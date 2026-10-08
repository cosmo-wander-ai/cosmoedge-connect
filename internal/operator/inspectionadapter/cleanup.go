package inspectionadapter

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

func (a *Adapter) Cleanup(ctx context.Context, request inspectionruntime.CleanupRequest) (inspectionruntime.CleanupResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	if request.RunID == "" || request.StepID == "" || request.TenantID == "" || request.SiteID == "" ||
		request.Attempt < 1 || len(request.Inputs) > 64 {
		return inspectionruntime.CleanupResult{}, inspectionruntime.ErrBindingStale
	}
	if err := requestDeadline(a.now().UTC(), request.Deadline); err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	requestSHA, err := canonicalDigest(struct {
		RunID    string                             `json:"runId"`
		StepID   string                             `json:"stepId"`
		TenantID string                             `json:"tenantId"`
		SiteID   string                             `json:"siteId"`
		Attempt  int                                `json:"attempt"`
		Inputs   []inspectionruntime.ValueReference `json:"inputs"`
		Deadline time.Time                          `json:"deadline"`
		Budget   inspection.StepBudget              `json:"budget"`
	}{request.RunID, request.StepID, request.TenantID, request.SiteID, request.Attempt,
		request.Inputs, request.Deadline.UTC(), request.Budget})
	if err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	resultRef := deterministicRef("cleanup", requestSHA)
	if len(request.Inputs) == 0 {
		return inspectionruntime.CleanupResult{
			RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			ResultRef: resultRef, Created: 0, Removed: 0, Pending: 0,
		}, nil
	}

	profileID, liveInputs, err := a.cleanupInputs(ctx, request)
	if err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	client, err := a.client(ctx, request.TenantID, request.SiteID, profileID)
	if err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	cleanupKey := operationKey("cleanup", requestSHA)
	pending := CleanupRecord{
		IdempotencyKey: cleanupKey, RequestSHA256: requestSHA, DeviceProfileID: profileID,
		State: CleanupRecordPending,
	}
	reserved, existed, err := a.records.ReserveCleanup(ctx, pending)
	if err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	if existed {
		if reserved.IdempotencyKey != cleanupKey || reserved.RequestSHA256 != requestSHA || reserved.DeviceProfileID != profileID {
			return inspectionruntime.CleanupResult{}, errors.New("durable live cleanup conflicts with replay")
		}
		switch reserved.State {
		case CleanupRecordCompleted:
			if err := validateCleanupResult(request, reserved.Result, resultRef); err != nil {
				return inspectionruntime.CleanupResult{}, err
			}
			return reserved.Result, nil
		case CleanupRecordPending:
			return inspectionruntime.CleanupResult{}, inspectionruntime.ErrOutcomeUnknown
		default:
			return inspectionruntime.CleanupResult{}, errors.New("durable live cleanup state is invalid")
		}
	}
	if !reflect.DeepEqual(reserved, pending) {
		return inspectionruntime.CleanupResult{}, errors.New("durable live cleanup reservation cannot be verified")
	}

	response, err := client.Cleanup(ctx, LiveCleanupRequest{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		IdempotencyKey: cleanupKey, DeviceProfileID: profileID, Inputs: liveInputs, Deadline: request.Deadline.UTC(),
	})
	if err != nil {
		return inspectionruntime.CleanupResult{}, mapClientError(err)
	}
	removed, pendingCount, err := cleanupAccounting(liveInputs, response.Items)
	if err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	result := inspectionruntime.CleanupResult{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: resultRef, Created: len(request.Inputs), Removed: removed, Pending: pendingCount,
	}
	completed := CleanupRecord{
		IdempotencyKey: cleanupKey, RequestSHA256: requestSHA, DeviceProfileID: profileID,
		State: CleanupRecordCompleted, Result: result,
	}
	if err := a.completeCleanup(ctx, completed); err != nil {
		return inspectionruntime.CleanupResult{}, errors.Join(inspectionruntime.ErrOutcomeUnknown, err)
	}
	return result, nil
}

func (a *Adapter) cleanupInputs(ctx context.Context, request inspectionruntime.CleanupRequest) (string, []LiveCleanupItem, error) {
	profileID := ""
	items := make([]LiveCleanupItem, 0, len(request.Inputs))
	seen := make(map[string]struct{}, len(request.Inputs))
	for _, input := range request.Inputs {
		if input.ValueRef == "" || input.ProducerStepID == "" || input.Attempt < 1 || !validDigest(input.SHA256) {
			return "", nil, inspectionruntime.ErrBindingStale
		}
		if _, duplicate := seen[input.ValueRef]; duplicate {
			return "", nil, inspectionruntime.ErrBindingStale
		}
		seen[input.ValueRef] = struct{}{}
		itemProfile := ""
		switch input.ProducerKind {
		case inspection.StepAcquireMedia:
			record, err := a.records.AcquisitionByMedia(ctx, input.ValueRef)
			if err != nil || record.Result.Descriptor.MediaRef != input.ValueRef ||
				record.Result.Descriptor.Integrity.SHA256 != input.SHA256 {
				return "", nil, inspectionruntime.ErrBindingStale
			}
			itemProfile = record.DeviceProfileID
		case inspection.StepAnalyze:
			record, err := a.records.Analysis(ctx, input.ValueRef)
			if err != nil || record.Result.ResultRef != input.ValueRef {
				return "", nil, inspectionruntime.ErrBindingStale
			}
			itemProfile = record.DeviceProfileID
		case inspection.StepOpenMedia, inspection.StepTransformMedia:
			return "", nil, inspectionruntime.ErrUnsupported
		default:
			return "", nil, inspectionruntime.ErrBindingStale
		}
		if itemProfile == "" {
			return "", nil, inspectionruntime.ErrBindingStale
		}
		if profileID == "" {
			profileID = itemProfile
		} else if profileID != itemProfile {
			// Avoid partially cleaning one device before discovering another.
			return "", nil, inspectionruntime.ErrUnsupported
		}
		items = append(items, LiveCleanupItem{ValueRef: input.ValueRef, ProducerKind: input.ProducerKind})
	}
	return profileID, items, nil
}

func cleanupAccounting(expected []LiveCleanupItem, actual []LiveCleanupItemResult) (int, int, error) {
	if len(actual) != len(expected) {
		return 0, 0, ErrInvalidResponse
	}
	wanted := make(map[string]struct{}, len(expected))
	for _, item := range expected {
		wanted[item.ValueRef] = struct{}{}
	}
	removed, pending := 0, 0
	for _, item := range actual {
		if _, ok := wanted[item.ValueRef]; !ok {
			return 0, 0, ErrInvalidResponse
		}
		delete(wanted, item.ValueRef)
		switch item.State {
		case CleanupRemoved:
			removed++
		case CleanupPending:
			pending++
		default:
			return 0, 0, ErrInvalidResponse
		}
	}
	if len(wanted) != 0 {
		return 0, 0, ErrInvalidResponse
	}
	return removed, pending, nil
}

func validateCleanupResult(request inspectionruntime.CleanupRequest, result inspectionruntime.CleanupResult, resultRef string) error {
	if result.RunID != request.RunID || result.StepID != request.StepID || result.Attempt != request.Attempt ||
		result.ResultRef != resultRef || result.Created != len(request.Inputs) || result.Removed < 0 || result.Pending < 0 ||
		result.Removed+result.Pending != result.Created {
		return errors.New("durable live cleanup result is invalid")
	}
	return nil
}
