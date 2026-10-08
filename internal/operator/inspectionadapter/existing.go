package inspectionadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

func (a *Adapter) readExisting(ctx context.Context, request inspectionruntime.ExistingEvidenceRequest) (inspectionruntime.ExistingEvidenceResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	if request.RunID == "" || request.StepID == "" || request.TenantID == "" || request.SiteID == "" ||
		request.TargetID == "" || request.ResolutionRef == "" || request.Attempt < 1 ||
		request.Source.Kind != inspection.SourceTaskEvidence || request.Source.Validate() != nil ||
		request.InstalledTask.Validate() != nil || !reflect.DeepEqual(request.CapabilityRefs, request.Source.CapabilityRefs) ||
		request.Budget.MaxBytes < 1 {
		return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrBindingStale
	}
	if err := requestDeadline(a.now().UTC(), request.Deadline); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	resolution, err := a.records.Resolution(ctx, request.ResolutionRef)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrBindingStale
		}
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	if !resolutionAuthorizesSource(resolution, request.RunID, request.TenantID, request.SiteID, request.TargetID, request.Source) ||
		!resolutionAuthorizesTask(resolution, request.InstalledTask) {
		return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrBindingStale
	}
	profileID, liveSources, liveTasks, err := a.liveBindings(ctx, request.TenantID, request.SiteID,
		[]inspection.SourceBinding{request.Source}, []inspection.InstalledTaskBinding{request.InstalledTask})
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	if profileID != resolution.DeviceProfileID || len(liveSources) != 1 || len(liveTasks) != 1 {
		return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrBindingStale
	}

	requestSHA, err := canonicalDigest(struct {
		RunID          string                          `json:"runId"`
		StepID         string                          `json:"stepId"`
		TenantID       string                          `json:"tenantId"`
		SiteID         string                          `json:"siteId"`
		TargetID       string                          `json:"targetId"`
		ResolutionRef  string                          `json:"resolutionRef"`
		Source         inspection.SourceBinding        `json:"source"`
		InstalledTask  inspection.InstalledTaskBinding `json:"installedTask"`
		CapabilityRefs []string                        `json:"capabilityRefs"`
		Attempt        int                             `json:"attempt"`
		Deadline       time.Time                       `json:"deadline"`
		Budget         inspection.StepBudget           `json:"budget"`
	}{request.RunID, request.StepID, request.TenantID, request.SiteID, request.TargetID, request.ResolutionRef,
		request.Source, request.InstalledTask, request.CapabilityRefs, request.Attempt, request.Deadline.UTC(), request.Budget})
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	evidenceRef := deterministicRef("evidence", requestSHA)
	if stored, storedErr := a.records.Existing(ctx, evidenceRef); storedErr == nil {
		if stored.RequestSHA256 != requestSHA || stored.DeviceProfileID != profileID {
			return inspectionruntime.ExistingEvidenceResult{}, errors.New("durable existing evidence conflicts with replay")
		}
		descriptor, describeErr := a.media.Describe(stored.Result.Descriptor.MediaRef)
		if describeErr != nil || !reflect.DeepEqual(descriptor, stored.Result.Descriptor) {
			return inspectionruntime.ExistingEvidenceResult{}, errors.New("durable existing evidence media cannot be verified")
		}
		return stored.Result, nil
	} else if !errors.Is(storedErr, ErrRecordNotFound) {
		return inspectionruntime.ExistingEvidenceResult{}, storedErr
	}

	client, err := a.client(ctx, request.TenantID, request.SiteID, profileID)
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	response, err := client.ReadExistingEvidence(ctx, ExistingEvidenceRequest{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		IdempotencyKey: operationKey("existing", requestSHA), DeviceProfileID: profileID,
		SourceHandle: request.Source.SourceHandle, SourceFingerprint: request.Source.SourceFingerprint,
		SourceLocator: liveSources[0].NativeLocator, TaskID: request.InstalledTask.TaskID,
		TaskFingerprint: request.InstalledTask.BindingFingerprint, TaskLocator: liveTasks[0].NativeLocator,
		CapabilityRefs: append([]string(nil), request.CapabilityRefs...), Deadline: request.Deadline.UTC(),
		MaxBytes: minInt64(request.Budget.MaxBytes, a.maxCaptureBytes),
	})
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, mapClientError(err)
	}
	if response.Content == nil || response.SourceFingerprint != request.Source.SourceFingerprint ||
		response.TaskFingerprint != request.InstalledTask.BindingFingerprint || response.MIMEType != "application/json" ||
		!existingKind(response.Kind) || !containsMediaKind(request.Source.MediaKinds, response.Kind) ||
		response.WindowStart.IsZero() || response.WindowEnd.Before(response.WindowStart) || response.WindowEnd.After(request.Deadline.UTC()) {
		if response.Content != nil {
			_ = response.Content.Close()
		}
		return inspectionruntime.ExistingEvidenceResult{}, ErrInvalidResponse
	}
	maxBytes := minInt64(request.Budget.MaxBytes, a.maxCaptureBytes)
	raw, readErr := io.ReadAll(io.LimitReader(response.Content, maxBytes+1))
	closeErr := response.Content.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) < 1 || int64(len(raw)) > maxBytes {
		return inspectionruntime.ExistingEvidenceResult{}, ErrInvalidResponse
	}
	var document map[string]json.RawMessage
	if err := strictjson.ValidateExactFields(raw, &document, 16); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, errors.Join(ErrInvalidResponse, err)
	}
	if err := json.Unmarshal(raw, &document); err != nil || document == nil {
		return inspectionruntime.ExistingEvidenceResult{}, ErrInvalidResponse
	}
	contentSHA := contentSHA256(raw)
	storedAt := a.now().UTC()
	descriptor, _, err := a.media.PutIdempotent(ctx, media.IdempotentPutRequest{
		IdempotencyKey: mediaPutKey(operationKey("existing", requestSHA)),
		Media: media.PutRequest{
			Kind: response.Kind,
			Binding: media.Binding{
				TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
				RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			},
			Encoding:       media.Encoding{MIMEType: "application/json", Container: "json", Codec: "json"},
			Temporal:       media.Temporal{WindowStart: timePointer(response.WindowStart), WindowEnd: timePointer(response.WindowEnd), SampleOrdinal: 1},
			Governance:     a.governance(storedAt, inspection.EvidencePolicy{RetentionSeconds: retentionSecondsFromDescriptorWindow(storedAt, request.Deadline)}),
			ExpectedSHA256: contentSHA,
		},
	}, bytes.NewReader(raw))
	if err != nil {
		if errors.Is(err, media.ErrIdempotencyConflict) {
			return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrOutcomeUnknown
		}
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	candidate, err := bindCandidate(response.Candidate, response.EvidenceOrdinals, []media.Descriptor{descriptor})
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	observedAt := a.now().UTC()
	if observedAt.After(request.Deadline.UTC()) {
		return inspectionruntime.ExistingEvidenceResult{}, context.DeadlineExceeded
	}
	result := inspectionruntime.ExistingEvidenceResult{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		EvidenceRef: evidenceRef, Descriptor: descriptor, Candidate: candidate,
		ObservedAt: observedAt, AdapterVersion: a.adapterVersion,
	}
	record := ExistingRecord{RequestSHA256: requestSHA, DeviceProfileID: profileID, Result: result}
	if err := a.persistExisting(ctx, record); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, errors.Join(inspectionruntime.ErrOutcomeUnknown, err)
	}
	return result, nil
}

func (a *Adapter) existingResult(ctx context.Context, ref string) (inspectionruntime.ExistingEvidenceResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	record, err := a.records.Existing(ctx, ref)
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	if record.Result.EvidenceRef != ref || record.Result.AdapterVersion != a.adapterVersion ||
		record.Result.Candidate.Validate() != nil {
		return inspectionruntime.ExistingEvidenceResult{}, errors.New("durable existing evidence is invalid")
	}
	descriptor, err := a.media.Describe(record.Result.Descriptor.MediaRef)
	if err != nil || !reflect.DeepEqual(descriptor, record.Result.Descriptor) {
		return inspectionruntime.ExistingEvidenceResult{}, errors.New("durable existing evidence media cannot be verified")
	}
	return record.Result, nil
}

func resolutionAuthorizesTask(record ResolutionRecord, task inspection.InstalledTaskBinding) bool {
	matches := 0
	for _, frozen := range record.InstalledTasks {
		if reflect.DeepEqual(frozen, task) {
			matches++
		}
	}
	return matches == 1
}

func existingKind(kind media.Kind) bool {
	return kind == media.KindMetric || kind == media.KindDetection || kind == media.KindEvent
}

// Existing evidence has no EvidencePolicy in the runtime port request. Keep it
// only through the frozen step deadline in this first slice; the runtime/domain
// contract should carry the plan evidence policy before this path is enabled in
// production.
func retentionSecondsFromDescriptorWindow(now, deadline time.Time) int {
	seconds := int(deadline.Sub(now).Seconds())
	if seconds < 1 {
		return 1
	}
	return seconds
}
