package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

// Resolver is a pure, concurrency-safe router. Its clock is injectable only
// to make freshness and expiry decisions deterministic in tests.
type Resolver struct {
	now func() time.Time
}

func New() *Resolver {
	return &Resolver{now: time.Now}
}

func NewWithClock(now func() time.Time) (*Resolver, error) {
	if now == nil {
		return nil, errors.New("inspection resolver clock is required")
	}
	return &Resolver{now: now}, nil
}

func (r *Resolver) Resolve(request Request) (Resolution, error) {
	if r == nil || r.now == nil {
		return Resolution{}, errors.New("inspection resolver is not initialized")
	}
	now := r.now().UTC()
	if now.IsZero() {
		return Resolution{}, errors.New("inspection resolver clock returned a zero time")
	}
	if err := request.validate(now); err != nil {
		return Resolution{}, err
	}

	switch request.Intent.Goal {
	case GoalConnect:
		return r.connectionResolution(request, request.Intent.Connection.Purpose, ReasonExplicitConnectionRequested, now)
	case GoalPersistentChange:
		return r.persistentProposalResolution(request, now)
	case GoalInspect:
		return r.inspectionResolution(request, now)
	default:
		return Resolution{}, invalidRequest("business goal is unsupported")
	}
}

func (r *Resolver) inspectionResolution(request Request, now time.Time) (Resolution, error) {
	intent := request.Intent.Inspection
	var temporarySpec *temporary.TemporaryObservationSpec
	var timeScope temporary.TimeScope
	if intent.Mode == InspectionModeTemporaryVisual {
		spec, err := temporary.NewSpec(*intent.TemporaryIntent)
		if err != nil {
			return finalize(Resolution{
				Schema: ResolutionSchemaVersion, Route: RouteUnsupported, Reason: ReasonUnsafeTemporaryIntent,
			})
		}
		temporarySpec = &spec
		timeScope = spec.TimeScope
	} else {
		timeScope = *intent.StandardTimeScope
	}

	source, sourceResolution, err := r.selectSource(request, now)
	if err != nil || sourceResolution != nil {
		if sourceResolution != nil {
			return finalize(*sourceResolution)
		}
		return Resolution{}, err
	}

	switch intent.Preference {
	case PreferenceExistingTask:
		return r.routeExistingTask(request, *source, temporarySpec, now)
	case PreferenceSnapshot:
		return r.routeVisual(request, *source, RouteSnapshotAnalysis, temporarySpec, now)
	case PreferenceClip:
		return r.routeVisual(request, *source, RouteClipAnalysis, temporarySpec, now)
	case PreferenceHybrid:
		return r.routeHybrid(request, *source, timeScope, temporarySpec, now)
	case PreferenceAuto:
		if intent.Mode == InspectionModeTemporaryVisual {
			return r.routeVisualForTime(request, *source, timeScope, temporarySpec, now)
		}
		task := selectTask(request, *source, intent.ObservableCode, now)
		if task.blockingReason != "" {
			return finalize(taskBlockedResolution(*source, task))
		}
		if task.fact != nil {
			if intent.VisualFollowup {
				return r.routeHybridWithTask(request, *source, *task.fact, task.capabilityRef, timeScope, temporarySpec, now)
			}
			return r.successOrAuthorityUnsupported(request, RouteExistingTaskRead, ReasonExistingTaskMatched,
				*source, task.fact, []string{task.capabilityRef}, []AuthorityClass{AuthorityDeviceRead}, nil, now)
		}
		return r.routeVisualForTime(request, *source, timeScope, temporarySpec, now)
	default:
		return Resolution{}, invalidRequest("inspection route preference is unsupported")
	}
}

func (r *Resolver) selectSource(request Request, now time.Time) (*SourceFact, *Resolution, error) {
	if len(request.Sources) == 0 {
		resolution, err := r.connectionResolution(request, ConnectionPurposeConnectDevice, ReasonSourceCatalogEmpty, now)
		return nil, &resolution, err
	}
	selector := request.Intent.Inspection.Source
	matches := make([]SourceFact, 0, 2)
	for _, fact := range request.Sources {
		if selector.SourceHandle != "" {
			if fact.Summary.SourceHandle == selector.SourceHandle {
				matches = append(matches, fact)
			}
			continue
		}
		if fact.Summary.Alias == selector.Alias && (selector.ZoneID == "" || fact.Summary.ZoneID == selector.ZoneID) {
			matches = append(matches, fact)
		}
	}
	if len(matches) == 0 {
		resolution := Resolution{Schema: ResolutionSchemaVersion, Route: RouteClarificationRequired, Reason: ReasonSourceNotFound}
		return nil, &resolution, nil
	}
	if len(matches) != 1 {
		resolution := Resolution{Schema: ResolutionSchemaVersion, Route: RouteClarificationRequired, Reason: ReasonSourceAmbiguous}
		return nil, &resolution, nil
	}
	fact := matches[0]
	resolution := Resolution{Schema: ResolutionSchemaVersion, Route: RouteClarificationRequired, SourceHandles: []string{fact.Summary.SourceHandle}}
	switch {
	case fact.Summary.State == catalog.StateIdentityDrift:
		resolution.Reason = ReasonSourceIdentityDrift
		return nil, &resolution, nil
	case !now.Before(fact.ExpiresAt):
		resolution.Reason = ReasonSourceStale
		return nil, &resolution, nil
	case selector.ExpectedRevision != 0 && selector.ExpectedRevision != fact.Summary.Revision:
		resolution.Reason = ReasonSourceRevisionChanged
		return nil, &resolution, nil
	case fact.Summary.State == catalog.StateDisabled:
		resolution.Reason = ReasonSourceDisabled
		return nil, &resolution, nil
	default:
		return &fact, nil, nil
	}
}

func (r *Resolver) routeExistingTask(request Request, source SourceFact, temporarySpec *temporary.TemporaryObservationSpec, now time.Time) (Resolution, error) {
	intent := request.Intent.Inspection
	task := selectTask(request, source, intent.ObservableCode, now)
	if task.blockingReason != "" || task.fact == nil {
		if task.blockingReason == "" {
			task.blockingReason = ReasonTaskNotFound
		}
		return finalize(taskBlockedResolution(source, task))
	}
	return r.successOrAuthorityUnsupported(request, RouteExistingTaskRead, ReasonExistingTaskMatched,
		source, task.fact, []string{task.capabilityRef}, []AuthorityClass{AuthorityDeviceRead}, temporarySpec, now)
}

func (r *Resolver) routeVisualForTime(request Request, source SourceFact, scope temporary.TimeScope, spec *temporary.TemporaryObservationSpec, now time.Time) (Resolution, error) {
	if scope.Kind == temporary.TimeScopeRecentWindow {
		return r.routeVisual(request, source, RouteClipAnalysis, spec, now)
	}
	return r.routeVisual(request, source, RouteSnapshotAnalysis, spec, now)
}

func (r *Resolver) routeVisual(request Request, source SourceFact, route Route, spec *temporary.TemporaryObservationSpec, now time.Time) (Resolution, error) {
	capabilityRef := visualCapability(source.Summary, route)
	if capabilityRef == "" {
		return finalize(Resolution{
			Schema: ResolutionSchemaVersion, Route: RouteUnsupported, Reason: ReasonCapabilityUnavailable,
			SourceHandles: []string{source.Summary.SourceHandle},
		})
	}
	reason := ReasonSnapshotCapabilityMatched
	if route == RouteClipAnalysis {
		reason = ReasonClipCapabilityMatched
	}
	return r.successOrAuthorityUnsupported(request, route, reason, source, nil, []string{capabilityRef},
		[]AuthorityClass{AuthorityInspectionExecution}, spec, now)
}

func (r *Resolver) routeHybrid(request Request, source SourceFact, scope temporary.TimeScope, spec *temporary.TemporaryObservationSpec, now time.Time) (Resolution, error) {
	intent := request.Intent.Inspection
	task := selectTask(request, source, intent.ObservableCode, now)
	if task.blockingReason != "" || task.fact == nil {
		if task.blockingReason == "" {
			task.blockingReason = ReasonTaskNotFound
		}
		return finalize(taskBlockedResolution(source, task))
	}
	return r.routeHybridWithTask(request, source, *task.fact, task.capabilityRef, scope, spec, now)
}

func (r *Resolver) routeHybridWithTask(request Request, source SourceFact, task InstalledTaskFact, taskCapabilityRef string,
	scope temporary.TimeScope, spec *temporary.TemporaryObservationSpec, now time.Time) (Resolution, error) {
	visualRoute := RouteSnapshotAnalysis
	if scope.Kind == temporary.TimeScopeRecentWindow {
		visualRoute = RouteClipAnalysis
	}
	visualRef := visualCapability(source.Summary, visualRoute)
	if visualRef == "" {
		return finalize(Resolution{
			Schema: ResolutionSchemaVersion, Route: RouteUnsupported, Reason: ReasonCapabilityUnavailable,
			SourceHandles: []string{source.Summary.SourceHandle}, TaskHandles: []string{task.TaskHandle},
			CapabilityRefs: normalizeRefs(taskCapabilityRef),
		})
	}
	return r.successOrAuthorityUnsupported(request, RouteHybridAnalysis, ReasonHybridCapabilitiesMatched,
		source, &task, normalizeRefs(taskCapabilityRef, visualRef),
		[]AuthorityClass{AuthorityDeviceRead, AuthorityInspectionExecution}, spec, now)
}

func (r *Resolver) successOrAuthorityUnsupported(request Request, route Route, reason ReasonCode, source SourceFact,
	task *InstalledTaskFact, capabilityRefs []string, required []AuthorityClass,
	spec *temporary.TemporaryObservationSpec, now time.Time) (Resolution, error) {
	required = normalizeAuthorities(required...)
	missing := missingAuthorities(request.Authorities, required, source.Summary.SourceHandle, now)
	resolution := Resolution{
		Schema: ResolutionSchemaVersion, Route: route, Reason: reason,
		SourceHandles: []string{source.Summary.SourceHandle}, CapabilityRefs: normalizeRefs(capabilityRefs...),
		RequiredAuthorities: required, MissingAuthorities: missing,
	}
	if task != nil {
		resolution.TaskHandles = []string{task.TaskHandle}
	}
	if len(missing) != 0 {
		resolution.Route = RouteUnsupported
		resolution.Reason = ReasonAuthorityUnavailable
		return finalize(resolution)
	}
	resolution.TemporaryObservationSpec = spec
	return finalize(resolution)
}

func (r *Resolver) connectionResolution(request Request, purpose ConnectionPurpose, reason ReasonCode, now time.Time) (Resolution, error) {
	required := []AuthorityClass{AuthorityConnectionProfileWrite}
	return finalize(Resolution{
		Schema: ResolutionSchemaVersion, Route: RouteConnectionWorkflow, Reason: reason,
		RequiredAuthorities: required,
		MissingAuthorities:  missingAuthorities(request.Authorities, required, "", now),
		ConnectionWorkflow: &ConnectionWorkflowHandoff{
			Purpose: purpose, RequiresSecureLocalInput: true, RequiredAuthority: AuthorityConnectionProfileWrite,
		},
	})
}

func (r *Resolver) persistentProposalResolution(request Request, now time.Time) (Resolution, error) {
	intent := *request.Intent.PersistentChange
	proposalID, err := persistentProposalID(request.Scope, intent)
	if err != nil {
		return Resolution{}, err
	}
	required := []AuthorityClass{AuthorityPersistentDeviceWrite}
	return finalize(Resolution{
		Schema: ResolutionSchemaVersion, Route: RoutePersistentChangeProposal, Reason: ReasonPersistentChangeNeedsProposal,
		RequiredAuthorities: required,
		MissingAuthorities:  missingAuthorities(request.Authorities, required, "", now),
		PersistentChangeProposal: &PersistentChangeProposal{
			ProposalID: proposalID, Kind: intent.Kind, SourceHandle: intent.SourceHandle, TaskHandle: intent.TaskHandle,
			ObservableCode: intent.ObservableCode, ExpectedSourceRevision: intent.ExpectedSourceRevision,
			ExpectedTaskRevision: intent.ExpectedTaskRevision, RequiredAuthority: AuthorityPersistentDeviceWrite,
			RequiresConfirmation: true, HandoffOnly: true,
		},
	})
}

type taskSelection struct {
	fact           *InstalledTaskFact
	capabilityRef  string
	blockingReason ReasonCode
}

func selectTask(request Request, source SourceFact, observable string, now time.Time) taskSelection {
	intent := request.Intent.Inspection
	candidates := make([]InstalledTaskFact, 0, 2)
	for _, fact := range request.Tasks {
		if intent.TaskHandle != "" {
			if fact.TaskHandle == intent.TaskHandle {
				candidates = append(candidates, fact)
			}
			continue
		}
		if fact.SourceHandle == source.Summary.SourceHandle && containsString(fact.ObservableCodes, observable) {
			candidates = append(candidates, fact)
		}
	}
	if len(candidates) == 0 {
		return taskSelection{}
	}
	if len(candidates) != 1 {
		return taskSelection{blockingReason: ReasonTaskAmbiguous}
	}
	fact := candidates[0]
	switch {
	case fact.SourceHandle != source.Summary.SourceHandle:
		return taskSelection{fact: &fact, blockingReason: ReasonTaskSourceDrift}
	case observable != "" && !containsString(fact.ObservableCodes, observable):
		return taskSelection{fact: &fact, blockingReason: ReasonTaskObservableUnavailable}
	case fact.State == catalog.StateIdentityDrift:
		return taskSelection{fact: &fact, blockingReason: ReasonTaskIdentityDrift}
	case fact.SourceRevision != source.Summary.Revision:
		return taskSelection{fact: &fact, blockingReason: ReasonTaskSourceDrift}
	case !now.Before(fact.ExpiresAt):
		return taskSelection{fact: &fact, blockingReason: ReasonTaskStale}
	case fact.State == catalog.StateDisabled:
		return taskSelection{fact: &fact, blockingReason: ReasonTaskDisabled}
	}
	capability := taskCapability(source.Summary, fact.CapabilityRef)
	if capability == nil || fact.ResultSchema != capability.ResultSchema {
		return taskSelection{fact: &fact, blockingReason: ReasonTaskSourceDrift}
	}
	return taskSelection{fact: &fact, capabilityRef: capability.Ref}
}

func taskBlockedResolution(source SourceFact, task taskSelection) Resolution {
	route := RouteClarificationRequired
	if task.blockingReason == ReasonTaskObservableUnavailable {
		route = RouteUnsupported
	}
	resolution := Resolution{
		Schema: ResolutionSchemaVersion, Route: route, Reason: task.blockingReason,
		SourceHandles: []string{source.Summary.SourceHandle},
	}
	if task.fact != nil {
		resolution.TaskHandles = []string{task.fact.TaskHandle}
	}
	return resolution
}

func taskCapability(summary catalog.BusinessSummary, ref string) *catalog.CapabilitySummary {
	for index := range summary.Capabilities {
		capability := &summary.Capabilities[index]
		if capability.Ref == ref && capability.Kind == catalog.CapabilityTaskEvidence {
			return capability
		}
	}
	return nil
}

func visualCapability(summary catalog.BusinessSummary, route Route) string {
	for _, capability := range summary.Capabilities {
		switch route {
		case RouteSnapshotAnalysis:
			switch summary.Kind {
			case inspection.SourceCamera:
				if capability.Kind == catalog.CapabilitySnapshot &&
					(containsMedia(capability.MediaKinds, inspection.MediaImage) || containsMedia(capability.MediaKinds, inspection.MediaFrameSet)) {
					return capability.Ref
				}
			case inspection.SourceUploadedImage:
				if capability.Kind == catalog.CapabilityUploadedMedia && containsMedia(capability.MediaKinds, inspection.MediaImage) {
					return capability.Ref
				}
			case inspection.SourceRetainedMedia:
				if capability.Kind == catalog.CapabilityRetainedMedia &&
					(containsMedia(capability.MediaKinds, inspection.MediaImage) || containsMedia(capability.MediaKinds, inspection.MediaFrameSet)) {
					return capability.Ref
				}
			}
		case RouteClipAnalysis:
			switch summary.Kind {
			case inspection.SourceCamera:
				if capability.Kind == catalog.CapabilityClip && containsMedia(capability.MediaKinds, inspection.MediaVideoClip) {
					return capability.Ref
				}
			case inspection.SourceUploadedVideo:
				if capability.Kind == catalog.CapabilityUploadedMedia && containsMedia(capability.MediaKinds, inspection.MediaVideoClip) {
					return capability.Ref
				}
			case inspection.SourceRetainedMedia:
				if capability.Kind == catalog.CapabilityRetainedMedia && containsMedia(capability.MediaKinds, inspection.MediaVideoClip) {
					return capability.Ref
				}
			}
		}
	}
	return ""
}

func missingAuthorities(available []AuthorityAvailability, required []AuthorityClass, sourceHandle string, now time.Time) []AuthorityClass {
	missing := make([]AuthorityClass, 0, len(required))
	for _, class := range required {
		found := false
		for _, candidate := range available {
			if candidate.Class != class || !now.Before(candidate.ExpiresAt) {
				continue
			}
			if sourceHandle != "" && len(candidate.SourceHandles) != 0 && !containsString(candidate.SourceHandles, sourceHandle) {
				continue
			}
			found = true
			break
		}
		if !found {
			missing = append(missing, class)
		}
	}
	return normalizeAuthorities(missing...)
}

func persistentProposalID(scope AuthenticatedScope, intent PersistentChangeIntent) (string, error) {
	payload := struct {
		Schema          string                 `json:"schema"`
		TenantID        string                 `json:"tenantId"`
		SiteID          string                 `json:"siteId"`
		PrincipalSHA256 string                 `json:"principalSha256"`
		Intent          PersistentChangeIntent `json:"intent"`
	}{
		Schema: RequestSchemaVersion, TenantID: scope.TenantID, SiteID: scope.SiteID,
		PrincipalSHA256: scope.PrincipalSHA256, Intent: intent,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "proposal-" + hex.EncodeToString(digest[:]), nil
}

func containsString(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}

func finalize(resolution Resolution) (Resolution, error) {
	if err := resolution.Validate(); err != nil {
		return Resolution{}, err
	}
	return resolution, nil
}
