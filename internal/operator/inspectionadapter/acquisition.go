package inspectionadapter

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/jpeg"
	"io"
	"reflect"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

func (a *Adapter) Acquire(ctx context.Context, request inspectionruntime.MediaAcquireRequest) (inspectionruntime.MediaAcquireResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	now := a.now().UTC()
	if request.Operation != inspection.StepAcquireMedia || request.RunID == "" || request.StepID == "" ||
		request.TenantID == "" || request.SiteID == "" || request.TargetID == "" || request.ResolutionRef == "" ||
		request.Attempt < 1 || request.IdempotencyKey == "" || request.Source.Kind != inspection.SourceCamera ||
		request.Source.Validate() != nil {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
	}
	if request.Acquisition.Samples != 1 || request.Acquisition.IntervalMillis != 0 ||
		request.Acquisition.ClipDurationMillis != 0 || request.Acquisition.MaxExtractedFrames != 0 {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrUnsupported
	}
	if !containsMediaKind(request.Source.MediaKinds, inspection.MediaImage) || request.Budget.MaxBytes < 1 ||
		request.Evidence.RetentionSeconds < 1 {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrUnsupported
	}
	if err := requestDeadline(now, request.Deadline); err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}

	resolution, err := a.records.Resolution(ctx, request.ResolutionRef)
	if err != nil {
		if errors.Is(err, ErrRecordNotFound) {
			return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
		}
		return inspectionruntime.MediaAcquireResult{}, err
	}
	if !resolutionAuthorizesSource(resolution, request.RunID, request.TenantID, request.SiteID, request.TargetID, request.Source) {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
	}
	profileID, liveSources, _, err := a.liveBindings(ctx, request.TenantID, request.SiteID, []inspection.SourceBinding{request.Source}, nil)
	if err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	if profileID != resolution.DeviceProfileID || len(liveSources) != 1 || liveSources[0].NativeLocator.Empty() {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
	}
	if ok, err := a.hasSnapshotCapability(ctx, request.TenantID, request.SiteID, request.Source); err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	} else if !ok {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrUnsupported
	}

	requestSHA, err := canonicalDigest(struct {
		Operation      inspection.StepKind          `json:"operation"`
		RunID          string                       `json:"runId"`
		StepID         string                       `json:"stepId"`
		TenantID       string                       `json:"tenantId"`
		SiteID         string                       `json:"siteId"`
		TargetID       string                       `json:"targetId"`
		ResolutionRef  string                       `json:"resolutionRef"`
		Source         inspection.SourceBinding     `json:"source"`
		Acquisition    inspection.AcquisitionPolicy `json:"acquisition"`
		Evidence       inspection.EvidencePolicy    `json:"evidence"`
		Attempt        int                          `json:"attempt"`
		IdempotencyKey string                       `json:"idempotencyKey"`
		Deadline       time.Time                    `json:"deadline"`
		Budget         inspection.StepBudget        `json:"budget"`
	}{request.Operation, request.RunID, request.StepID, request.TenantID, request.SiteID, request.TargetID,
		request.ResolutionRef, request.Source, request.Acquisition, request.Evidence, request.Attempt,
		request.IdempotencyKey, request.Deadline.UTC(), request.Budget})
	if err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	recordKey := operationKey("capture", request.IdempotencyKey, requestSHA)
	if stored, storedErr := a.records.Acquisition(ctx, recordKey); storedErr == nil {
		if stored.RequestSHA256 != requestSHA || stored.DeviceProfileID != profileID ||
			stored.Result.AdapterVersion != a.adapterVersion {
			return inspectionruntime.MediaAcquireResult{}, errors.New("durable live acquisition conflicts with replay")
		}
		descriptor, describeErr := a.media.Describe(stored.Result.Descriptor.MediaRef)
		if describeErr != nil || !reflect.DeepEqual(descriptor, stored.Result.Descriptor) {
			return inspectionruntime.MediaAcquireResult{}, errors.New("durable live acquisition media cannot be verified")
		}
		return stored.Result, nil
	} else if !errors.Is(storedErr, ErrRecordNotFound) {
		return inspectionruntime.MediaAcquireResult{}, storedErr
	}

	maxBytes := minInt64(request.Budget.MaxBytes, a.maxCaptureBytes)
	client, err := a.client(ctx, request.TenantID, request.SiteID, profileID)
	if err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	callStarted := a.now().UTC()
	response, err := client.CaptureSnapshot(ctx, SnapshotRequest{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		IdempotencyKey: recordKey, DeviceProfileID: profileID,
		SourceHandle: request.Source.SourceHandle, SourceFingerprint: request.Source.SourceFingerprint,
		NativeLocator: liveSources[0].NativeLocator, ROIRef: request.Source.ROIRef,
		Deadline: request.Deadline.UTC(), MaxBytes: maxBytes,
	})
	if err != nil {
		return inspectionruntime.MediaAcquireResult{}, mapClientError(err)
	}
	if response.Content == nil || response.SourceFingerprint != request.Source.SourceFingerprint ||
		response.Freshness != SnapshotFresh || response.ObservedAt.IsZero() ||
		response.ObservedAt.Before(callStarted.Add(-time.Second)) || response.ObservedAt.After(request.Deadline.UTC()) {
		if response.Content != nil {
			_ = response.Content.Close()
		}
		if response.Freshness == SnapshotCached || response.Freshness == SnapshotUnverifiable {
			return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrOutcomeUnknown
		}
		return inspectionruntime.MediaAcquireResult{}, ErrInvalidResponse
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Content, maxBytes+1))
	closeErr := response.Content.Close()
	if readErr != nil || closeErr != nil {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrOutcomeUnknown
	}
	if int64(len(raw)) < 1 || int64(len(raw)) > maxBytes {
		return inspectionruntime.MediaAcquireResult{}, ErrInvalidResponse
	}
	decoded, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || format != "jpeg" || decoded.Width < 1 || decoded.Height < 1 {
		return inspectionruntime.MediaAcquireResult{}, ErrInvalidResponse
	}
	if a.now().UTC().After(request.Deadline.UTC()) {
		return inspectionruntime.MediaAcquireResult{}, context.DeadlineExceeded
	}
	contentSHA := contentSHA256(raw)
	observedAt := response.ObservedAt.UTC()
	descriptor, _, err := a.media.PutIdempotent(ctx, media.IdempotentPutRequest{
		IdempotencyKey: mediaPutKey(recordKey),
		Media: media.PutRequest{
			Kind: media.KindImage,
			Binding: media.Binding{
				TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
				RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			},
			Encoding:   media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: decoded.Width, HeightPixels: decoded.Height},
			Temporal:   media.Temporal{WindowStart: timePointer(observedAt), WindowEnd: timePointer(observedAt), SampleOrdinal: 1},
			Governance: a.governance(a.now().UTC(), request.Evidence), ExpectedSHA256: contentSHA,
		},
	}, bytes.NewReader(raw))
	if err != nil {
		if errors.Is(err, media.ErrIdempotencyConflict) {
			return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrOutcomeUnknown
		}
		return inspectionruntime.MediaAcquireResult{}, err
	}
	result := inspectionruntime.MediaAcquireResult{Descriptor: descriptor, AdapterVersion: a.adapterVersion}
	record := AcquisitionRecord{IdempotencyKey: recordKey, RequestSHA256: requestSHA, DeviceProfileID: profileID, Result: result}
	if err := a.persistAcquisition(ctx, record); err != nil {
		return inspectionruntime.MediaAcquireResult{}, errors.Join(inspectionruntime.ErrOutcomeUnknown, err)
	}
	return result, nil
}

func resolutionAuthorizesSource(record ResolutionRecord, runID, tenantID, siteID, targetID string, source inspection.SourceBinding) bool {
	if record.RunID != runID || record.TenantID != tenantID || record.SiteID != siteID || record.TargetID != targetID ||
		record.DeviceProfileID == "" {
		return false
	}
	matches := 0
	for _, frozen := range record.Sources {
		if reflect.DeepEqual(frozen, source) {
			matches++
		}
	}
	return matches == 1
}

func (a *Adapter) hasSnapshotCapability(ctx context.Context, tenantID, siteID string, frozen inspection.SourceBinding) (bool, error) {
	source, err := a.catalog.Get(ctx, tenantID, siteID, frozen.SourceHandle)
	if err != nil {
		return false, mapCatalogError(err)
	}
	for _, capability := range source.Capabilities {
		if !containsString(frozen.CapabilityRefs, capability.Ref) || capability.Kind != catalog.CapabilitySnapshot {
			continue
		}
		if containsMediaKind(capability.Constraints.MediaKinds, inspection.MediaImage) {
			return true, nil
		}
	}
	return false, nil
}

func (a *Adapter) governance(now time.Time, policy inspection.EvidencePolicy) media.Governance {
	return media.Governance{
		PrivacyClass: a.privacyClass, RedactionPolicyRef: policy.RedactionProfile,
		RetentionPolicyRef: a.retentionPolicyRef, Audience: append([]string(nil), a.audience...),
		ExpiresAt: now.UTC().Add(time.Duration(policy.RetentionSeconds) * time.Second),
	}
}
