package inspectionadapter

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

func (a *Adapter) Resolve(ctx context.Context, request inspectionruntime.ResolveSourceRequest) (inspectionruntime.ResolvedSourceSet, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	now := a.now().UTC()
	if request.RunID == "" || request.StepID == "" || request.TenantID == "" || request.SiteID == "" ||
		request.TargetID == "" || request.Attempt < 1 || len(request.Sources) == 0 || len(request.Sources) > 16 {
		return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
	}
	if err := requestDeadline(now, request.Deadline); err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	for _, source := range request.Sources {
		if err := source.Validate(); err != nil {
			return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
		}
	}
	for _, task := range request.InstalledTasks {
		if err := task.Validate(); err != nil {
			return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
		}
	}

	requestSHA, err := canonicalDigest(struct {
		RunID          string                            `json:"runId"`
		StepID         string                            `json:"stepId"`
		TenantID       string                            `json:"tenantId"`
		SiteID         string                            `json:"siteId"`
		TargetID       string                            `json:"targetId"`
		Sources        []inspection.SourceBinding        `json:"sources"`
		InstalledTasks []inspection.InstalledTaskBinding `json:"installedTasks"`
		Attempt        int                               `json:"attempt"`
		Deadline       time.Time                         `json:"deadline"`
		Budget         inspection.StepBudget             `json:"budget"`
	}{request.RunID, request.StepID, request.TenantID, request.SiteID, request.TargetID,
		request.Sources, request.InstalledTasks, request.Attempt, request.Deadline.UTC(), request.Budget})
	if err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	resolutionRef := deterministicRef("resolution", requestSHA)
	if stored, storedErr := a.records.Resolution(ctx, resolutionRef); storedErr == nil {
		if !resolutionMatchesRequest(stored, request, requestSHA, a.adapterVersion) {
			return inspectionruntime.ResolvedSourceSet{}, errors.New("durable live resolution conflicts with replay")
		}
		return inspectionruntime.ResolvedSourceSet{
			RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			ResolutionRef: stored.ResolutionRef, AdapterVersion: stored.AdapterVersion,
		}, nil
	} else if !errors.Is(storedErr, ErrRecordNotFound) {
		return inspectionruntime.ResolvedSourceSet{}, storedErr
	}

	profileID, liveSources, liveTasks, err := a.liveBindings(ctx, request.TenantID, request.SiteID, request.Sources, request.InstalledTasks)
	if err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	client, err := a.client(ctx, request.TenantID, request.SiteID, profileID)
	if err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	liveResult, err := client.Resolve(ctx, LiveResolveRequest{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		IdempotencyKey: operationKey("resolve", requestSHA), DeviceProfileID: profileID,
		Sources: liveSources, InstalledTasks: liveTasks, Deadline: request.Deadline.UTC(),
	})
	if err != nil {
		return inspectionruntime.ResolvedSourceSet{}, mapClientError(err)
	}
	if a.now().UTC().After(request.Deadline.UTC()) || !verifiedBindings(liveSources, liveTasks, liveResult) {
		return inspectionruntime.ResolvedSourceSet{}, ErrInvalidResponse
	}

	record := ResolutionRecord{
		ResolutionRef: resolutionRef, RequestSHA256: requestSHA,
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		TenantID: request.TenantID, SiteID: request.SiteID, TargetID: request.TargetID,
		DeviceProfileID: profileID, Sources: make([]inspection.SourceBinding, len(request.Sources)),
		InstalledTasks: make([]inspection.InstalledTaskBinding, len(request.InstalledTasks)),
		AdapterVersion: a.adapterVersion, ResolvedAt: a.now().UTC(),
	}
	for index := range request.Sources {
		record.Sources[index] = cloneSourceBinding(request.Sources[index])
	}
	for index := range request.InstalledTasks {
		record.InstalledTasks[index] = cloneTaskBinding(request.InstalledTasks[index])
	}
	if err := a.persistResolution(ctx, record); err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	return inspectionruntime.ResolvedSourceSet{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResolutionRef: resolutionRef, AdapterVersion: a.adapterVersion,
	}, nil
}

func resolutionMatchesRequest(record ResolutionRecord, request inspectionruntime.ResolveSourceRequest, requestSHA, adapterVersion string) bool {
	if record.ResolutionRef == "" || record.RequestSHA256 != requestSHA || record.RunID != request.RunID ||
		record.StepID != request.StepID || record.Attempt != request.Attempt || record.TenantID != request.TenantID ||
		record.SiteID != request.SiteID || record.TargetID != request.TargetID || record.DeviceProfileID == "" ||
		record.AdapterVersion != adapterVersion || record.ResolvedAt.IsZero() {
		return false
	}
	if len(record.Sources) != len(request.Sources) || len(record.InstalledTasks) != len(request.InstalledTasks) {
		return false
	}
	for index := range record.Sources {
		if !reflect.DeepEqual(record.Sources[index], request.Sources[index]) {
			return false
		}
	}
	for index := range record.InstalledTasks {
		if !reflect.DeepEqual(record.InstalledTasks[index], request.InstalledTasks[index]) {
			return false
		}
	}
	return true
}

func (a *Adapter) liveBindings(
	ctx context.Context,
	tenantID, siteID string,
	sources []inspection.SourceBinding,
	installedTasks []inspection.InstalledTaskBinding,
) (string, []LiveSource, []LiveTask, error) {
	profileID := ""
	liveTasks := make([]LiveTask, 0, len(installedTasks))
	for _, frozen := range installedTasks {
		if err := a.catalog.ValidateInstalledTask(ctx, tenantID, siteID, frozen); err != nil {
			return "", nil, nil, mapCatalogError(err)
		}
		task, err := a.catalog.GetTask(ctx, tenantID, siteID, frozen.TaskID)
		if err != nil {
			return "", nil, nil, mapCatalogError(err)
		}
		if task.NativeLocator == "" || task.IdentityFingerprint == "" || task.State != catalog.StateActive {
			return "", nil, nil, inspectionruntime.ErrBindingStale
		}
		if profileID == "" {
			profileID = task.DeviceProfileID
		} else if profileID != task.DeviceProfileID {
			return "", nil, nil, inspectionruntime.ErrUnsupported
		}
		capabilities := make([]string, len(frozen.Capabilities))
		for index, capability := range frozen.Capabilities {
			capabilities[index] = capability.Ref
		}
		liveTasks = append(liveTasks, LiveTask{
			TaskID: frozen.TaskID, BindingFingerprint: frozen.BindingFingerprint,
			CapabilityRefs: capabilities, NativeLocator: protectedLocator(task.NativeLocator),
		})
	}

	liveSources := make([]LiveSource, 0, len(sources))
	for _, frozen := range sources {
		source, err := a.catalog.Get(ctx, tenantID, siteID, frozen.SourceHandle)
		if err != nil {
			return "", nil, nil, mapCatalogError(err)
		}
		if source.NativeLocator == "" || source.State != catalog.StateActive || source.Revision != frozen.SourceRevision ||
			source.IdentityFingerprint != frozen.SourceFingerprint {
			return "", nil, nil, inspectionruntime.ErrBindingStale
		}
		if profileID == "" {
			profileID = source.DeviceProfileID
		} else if profileID != source.DeviceProfileID {
			return "", nil, nil, inspectionruntime.ErrUnsupported
		}
		switch frozen.Kind {
		case inspection.SourceCamera:
			current, bindErr := a.catalog.Binding(ctx, tenantID, siteID, frozen.SourceHandle, frozen.CapabilityRefs, frozen.ROIRef)
			if bindErr != nil || !reflect.DeepEqual(current, frozen) {
				return "", nil, nil, inspectionruntime.ErrBindingStale
			}
		case inspection.SourceTaskEvidence:
			matches := 0
			for _, task := range installedTasks {
				for _, taskSource := range task.TaskEvidenceSourceBindings() {
					if reflect.DeepEqual(taskSource, frozen) {
						matches++
					}
				}
			}
			if matches != 1 {
				return "", nil, nil, inspectionruntime.ErrBindingStale
			}
		default:
			return "", nil, nil, inspectionruntime.ErrUnsupported
		}
		liveSources = append(liveSources, LiveSource{
			SourceHandle: frozen.SourceHandle, Kind: frozen.Kind, IdentityFingerprint: frozen.SourceFingerprint,
			CapabilityRefs: append([]string(nil), frozen.CapabilityRefs...), ROIRef: frozen.ROIRef,
			NativeLocator: protectedLocator(source.NativeLocator),
		})
	}
	if profileID == "" || !validOpaque(profileID) {
		return "", nil, nil, inspectionruntime.ErrBindingStale
	}
	return profileID, liveSources, liveTasks, nil
}

func verifiedBindings(sources []LiveSource, tasks []LiveTask, result LiveResolveResult) bool {
	expectedSources := make([]VerifiedSource, len(sources))
	for index, source := range sources {
		expectedSources[index] = VerifiedSource{SourceHandle: source.SourceHandle, IdentityFingerprint: source.IdentityFingerprint}
	}
	expectedTasks := make([]VerifiedTask, len(tasks))
	for index, task := range tasks {
		expectedTasks[index] = VerifiedTask{TaskID: task.TaskID, BindingFingerprint: task.BindingFingerprint}
	}
	actualSources := append([]VerifiedSource(nil), result.Sources...)
	actualTasks := append([]VerifiedTask(nil), result.Tasks...)
	sort.Slice(expectedSources, func(i, j int) bool { return expectedSources[i].SourceHandle < expectedSources[j].SourceHandle })
	sort.Slice(actualSources, func(i, j int) bool { return actualSources[i].SourceHandle < actualSources[j].SourceHandle })
	sort.Slice(expectedTasks, func(i, j int) bool { return expectedTasks[i].TaskID < expectedTasks[j].TaskID })
	sort.Slice(actualTasks, func(i, j int) bool { return actualTasks[i].TaskID < actualTasks[j].TaskID })
	if len(expectedSources) != len(actualSources) || len(expectedTasks) != len(actualTasks) {
		return false
	}
	for index := range expectedSources {
		if expectedSources[index] != actualSources[index] {
			return false
		}
	}
	for index := range expectedTasks {
		if expectedTasks[index] != actualTasks[index] {
			return false
		}
	}
	return true
}

func mapCatalogError(err error) error {
	switch {
	case errors.Is(err, catalog.ErrNotFound), errors.Is(err, catalog.ErrInvalidSource),
		errors.Is(err, catalog.ErrIdentityDrift), errors.Is(err, catalog.ErrCapabilityMissing),
		errors.Is(err, catalog.ErrTaskNotFound), errors.Is(err, catalog.ErrInvalidTask),
		errors.Is(err, catalog.ErrTaskIdentityDrift), errors.Is(err, catalog.ErrTaskCapability),
		errors.Is(err, catalog.ErrTaskStale), errors.Is(err, catalog.ErrTaskAmbiguous):
		return inspectionruntime.ErrBindingStale
	default:
		return err
	}
}
