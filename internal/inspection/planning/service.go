package planning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/inputguard"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/resolver"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

const (
	defaultCatalogFactTTL = 5 * time.Minute
	maximumCatalogFactTTL = 24 * time.Hour
	defaultRunTTL         = 5 * time.Minute
	maximumRunTTL         = 24 * time.Hour
	maximumCatalogItems   = 10_000
)

var (
	refPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	audienceRefPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern        = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reservedContextNames = map[string]struct{}{
		"tenant": {}, "tenantid": {}, "site": {}, "siteid": {}, "channel": {}, "principal": {},
		"principalsha256": {}, "source": {}, "sourcehandle": {}, "task": {}, "taskhandle": {},
		"native": {}, "nativelocator": {}, "authority": {}, "grant": {}, "credential": {},
		"capability": {}, "capabilityref": {}, "deviceid": {}, "cameraid": {}, "streamurl": {},
	}
)

func New(config Config) (*Service, error) {
	if config.Registry == nil || config.Catalog == nil || config.Authorities == nil || config.Interactions == nil || config.Interpreter == nil || config.MediaCompiler == nil {
		return nil, errors.New("complete inspection planning dependencies are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.CatalogFactTTL == 0 {
		config.CatalogFactTTL = defaultCatalogFactTTL
	}
	if config.DefaultRunTTL == 0 {
		config.DefaultRunTTL = defaultRunTTL
	}
	if config.CatalogFactTTL <= 0 || config.CatalogFactTTL > maximumCatalogFactTTL {
		return nil, errors.New("inspection planning catalog fact lifetime is invalid")
	}
	if config.DefaultRunTTL <= 0 || config.DefaultRunTTL > maximumRunTTL {
		return nil, errors.New("inspection planning run lifetime is invalid")
	}
	if config.Resolver == nil {
		technical, err := resolver.NewWithClock(config.Now)
		if err != nil {
			return nil, err
		}
		config.Resolver = technical
	}
	return &Service{
		registry: config.Registry, catalog: config.Catalog,
		authorities: config.Authorities, interactions: config.Interactions, interpreter: config.Interpreter,
		mediaCompiler: config.MediaCompiler, resolver: config.Resolver,
		now: config.Now, catalogFactTTL: config.CatalogFactTTL, defaultRunTTL: config.DefaultRunTTL,
	}, nil
}

type catalogSnapshot struct {
	templates   map[string]inspection.InspectionTemplate
	assignments []inspection.Assignment
	sources     []catalog.Source
	tasks       []catalog.DeviceTaskBinding
	fingerprint string
}

func (s *Service) Plan(ctx context.Context, input application.PlanningRequest) (application.PlanningDecision, error) {
	if s == nil || s.registry == nil || s.catalog == nil || s.authorities == nil || s.interactions == nil || s.interpreter == nil || s.mediaCompiler == nil || s.resolver == nil || s.now == nil {
		return application.PlanningDecision{}, errors.New("inspection planner is not initialized")
	}
	if err := validatePlanningInput(input); err != nil {
		return application.PlanningDecision{}, fmt.Errorf("%w: %v", httpapi.ErrInvalid, err)
	}
	snapshot, err := s.loadSnapshot(ctx, input.Session)
	if err != nil {
		return application.PlanningDecision{}, err
	}
	var preParsedTemporary *TemporaryObservationIntent
	if input.PreParsedTemporary != nil {
		preParsedTemporary = &TemporaryObservationIntent{
			Subject:            input.PreParsedTemporary.Subject,
			Region:             input.PreParsedTemporary.Region,
			Observable:         input.PreParsedTemporary.Observable,
			Locale:             "zh-CN",
			EvidenceTTLSeconds: 600,
		}
	}
	interpreted, err := s.interpreter.Interpret(ctx, InterpretationRequest{
		Instruction:     input.Request.Instruction,
		Context:         cloneInterpretationContext(input.Request.Context),
		Vocabulary:      vocabulary(snapshot),
		TemporaryIntent: preParsedTemporary,
	})
	if err != nil {
		return application.PlanningDecision{}, fmt.Errorf("%w: inspection intent could not be interpreted", httpapi.ErrInvalid)
	}
	if err := validateInterpretedIntent(interpreted); err != nil {
		return application.PlanningDecision{}, fmt.Errorf("%w: %v", httpapi.ErrInvalid, err)
	}
	scope, err := s.authenticatedScope(input.Session)
	if err != nil {
		return application.PlanningDecision{}, err
	}
	authorities, err := s.authorities.AvailableAuthorities(ctx, scope)
	if err != nil {
		return application.PlanningDecision{}, err
	}
	converted, err := convertIntent(interpreted, snapshot)
	if err != nil {
		return application.PlanningDecision{}, err
	}
	facts, err := s.resolverFacts(ctx, input.Session, snapshot, converted.observableCode)
	if err != nil {
		return application.PlanningDecision{}, err
	}
	resolution, err := s.resolver.Resolve(resolver.Request{
		Schema: resolver.RequestSchemaVersion, Scope: scope, Intent: converted.intent,
		Sources: facts.sources, Tasks: facts.tasks, Authorities: cloneAuthorities(authorities),
	})
	if err != nil {
		return application.PlanningDecision{}, errors.New("trusted inspection resolution failed")
	}
	if err := resolution.Validate(); err != nil {
		return application.PlanningDecision{}, errors.New("inspection resolver returned an invalid decision")
	}
	if len(resolution.MissingAuthorities) != 0 || resolution.Reason == resolver.ReasonAuthorityUnavailable {
		return application.PlanningDecision{}, fmt.Errorf("%w: required inspection authority is unavailable", httpapi.ErrForbidden)
	}

	switch resolution.Route {
	case resolver.RouteConnectionWorkflow:
		return s.registerInteraction(ctx, input, scope, LocalInteractionConnection, nil)
	case resolver.RoutePersistentChangeProposal:
		change, err := pendingChangeFromProposal(resolution.PersistentChangeProposal)
		if err != nil {
			return application.PlanningDecision{}, errors.New("inspection resolver returned an invalid local change intent")
		}
		return s.registerInteraction(ctx, input, scope, LocalInteractionPersistentChange, &change)
	case resolver.RouteUnsupported, resolver.RouteClarificationRequired:
		return application.PlanningDecision{}, fmt.Errorf("%w: inspection request is ambiguous, stale, or unsupported", httpapi.ErrConflict)
	case resolver.RouteExistingTaskRead, resolver.RouteSnapshotAnalysis, resolver.RouteClipAnalysis, resolver.RouteHybridAnalysis:
		if resolution.TemporaryObservationSpec != nil {
			decision, err := s.prepareTemporary(ctx, input, snapshot, resolution)
			if err != nil {
				return application.PlanningDecision{}, err
			}
			return application.PlanningDecision{Temporary: &decision}, nil
		}
		return s.planStandard(ctx, input, snapshot, converted.variables, converted.observableCode, resolution)
	default:
		return application.PlanningDecision{}, errors.New("inspection resolver returned an unknown route")
	}
}

// RequireConnection registers the same protected onboarding handoff used by
// the normal resolver connection route without requiring a device catalog
// snapshot. Product shells use this only when their trusted catalog refresh
// has already established that no live connection is available. Keeping the
// registration here prevents an outer shell from inventing an unregistered
// handoff reference or weakening the exact session binding.
func (s *Service) RequireConnection(ctx context.Context, input application.PlanningRequest) (application.PlanningDecision, error) {
	if s == nil || s.interactions == nil || s.now == nil {
		return application.PlanningDecision{}, errors.New("inspection planner is not initialized")
	}
	if err := validatePlanningInput(input); err != nil {
		return application.PlanningDecision{}, fmt.Errorf("%w: %v", httpapi.ErrInvalid, err)
	}
	scope, err := s.authenticatedScope(input.Session)
	if err != nil {
		return application.PlanningDecision{}, err
	}
	return s.registerInteraction(ctx, input, scope, LocalInteractionConnection, nil)
}

func (s *Service) prepareTemporary(ctx context.Context, input application.PlanningRequest, snapshot catalogSnapshot, resolution resolver.Resolution) (application.TemporaryDecision, error) {
	if resolution.TemporaryObservationSpec == nil || len(resolution.SourceHandles) != 1 {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary observation resolution is incomplete", httpapi.ErrConflict)
	}
	spec := *resolution.TemporaryObservationSpec
	if err := spec.Validate(); err != nil {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary observation specification is invalid", httpapi.ErrConflict)
	}
	capabilityRef, ok := temporaryVisualCapability(snapshot.sources, resolution)
	if !ok {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary visual capability is unavailable", httpapi.ErrConflict)
	}
	requestedAt := input.RequestedAt.UTC()
	evidenceExpiresAt := requestedAt.Add(time.Duration(spec.EvidenceTTLSeconds) * time.Second)
	audience, err := temporary.FreezeAudience(temporary.ChannelSession{
		TenantID: input.Session.TenantID, SiteID: input.Session.SiteID, Channel: input.Session.Channel,
		ConversationRef: input.Session.ConversationRef, RecipientRef: input.Session.RecipientRef,
		PrincipalSHA256: input.Session.PrincipalSHA256,
	})
	if err != nil {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary audience binding is invalid", httpapi.ErrConflict)
	}
	runID, err := temporary.RunIDForScope(input.Session.TenantID, input.Session.SiteID, input.RequestID)
	if err != nil {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary runtime identity is invalid", httpapi.ErrConflict)
	}
	stepID, err := temporary.MediaStepIDForRun(runID)
	if err != nil {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary media binding is invalid", httpapi.ErrConflict)
	}
	compilation := TemporaryMediaCompilation{
		TenantID: input.Session.TenantID, SiteID: input.Session.SiteID, RequestID: input.RequestID,
		RequestedAt: requestedAt, Spec: spec, SourceRef: resolution.SourceHandles[0], CapabilityRef: capabilityRef,
		RuntimeRunID: runID, RuntimeStepID: stepID, AudienceBindingRef: audience.Ref,
		AudienceSHA256: audience.SHA256, EvidenceExpiresAt: evidenceExpiresAt,
	}
	frozen, err := s.mediaCompiler.Compile(ctx, compilation)
	if err != nil {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary media request policy could not compile", httpapi.ErrConflict)
	}
	if err := validateCompiledTemporaryMedia(compilation, frozen); err != nil {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary media request policy returned an unbound request", httpapi.ErrConflict)
	}
	deadline := requestedAt.Add(temporary.MaxRunDuration)
	if evidenceExpiresAt.Before(deadline) {
		deadline = evidenceExpiresAt
	}
	if !deadline.After(requestedAt) {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary media lifetime is exhausted", httpapi.ErrConflict)
	}
	decision, err := application.NewTemporaryDecision(spec, frozen, deadline)
	if err != nil {
		return application.TemporaryDecision{}, fmt.Errorf("%w: temporary media decision could not be frozen", httpapi.ErrConflict)
	}
	return decision, nil
}

func validateCompiledTemporaryMedia(input TemporaryMediaCompilation, frozen mediaprep.FrozenRequest) error {
	if input.Spec.Validate() != nil || frozen.Schema != mediaprep.RequestSchema ||
		frozen.TenantID != input.TenantID || frozen.SiteID != input.SiteID || frozen.RequestID != input.RequestID ||
		frozen.SourceRef != input.SourceRef || frozen.CapabilityRef != input.CapabilityRef ||
		frozen.AudienceBindingRef != input.AudienceBindingRef || frozen.AudienceSHA256 != input.AudienceSHA256 ||
		!frozen.EvidenceExpiresAt.Equal(input.EvidenceExpiresAt) || frozen.Media.RunID != input.RuntimeRunID ||
		frozen.Media.StepID != input.RuntimeStepID || frozen.Media.Attempt != 1 || frozen.TimeScope.SampleOrdinal != 0 {
		return errors.New("compiled temporary media request changed a frozen identity")
	}
	expectedStart, expectedEnd := input.RequestedAt, input.RequestedAt
	expectedKind := media.KindImage
	if input.Spec.TimeScope.Kind == temporary.TimeScopeRecentWindow {
		expectedStart = expectedEnd.Add(-time.Duration(input.Spec.TimeScope.WindowSeconds) * time.Second)
		expectedKind = media.KindVideoClip
	}
	if frozen.Media.Kind != expectedKind || !frozen.TimeScope.WindowStart.Equal(expectedStart) ||
		!frozen.TimeScope.WindowEnd.Equal(expectedEnd) ||
		frozen.TimeScope.DurationMillis != expectedEnd.Sub(expectedStart).Milliseconds() {
		return errors.New("compiled temporary media request changed the frozen time scope")
	}
	return nil
}

func (s *Service) QueryCapabilities(ctx context.Context, session httpapi.SessionBinding) (httpapi.CapabilitySet, error) {
	if s == nil || s.registry == nil || s.catalog == nil {
		return httpapi.CapabilitySet{}, errors.New("inspection capability query is not initialized")
	}
	if !validSession(session) {
		return httpapi.CapabilitySet{}, httpapi.ErrForbidden
	}
	snapshot, err := s.loadSnapshot(ctx, session)
	if err != nil {
		return httpapi.CapabilitySet{}, err
	}
	views := make([]httpapi.CapabilityView, 0)
	for _, assignment := range snapshot.assignments {
		if assignment.SourceCatalogFingerprint != snapshot.fingerprint || s.validateAssignmentFresh(ctx, session, snapshot, assignment) != nil {
			continue
		}
		template, ok := snapshot.templates[assignment.TemplateID]
		if !ok || template.Revision != assignment.TemplateRevision {
			continue
		}
		criteria := criteriaByID(template)
		for _, target := range assignment.Targets {
			if len(views) == 100 {
				break
			}
			titleSubject := chineseOrFallback(target.FriendlyName, "现场")
			observable := "现场情况"
			if len(target.CriterionIDs) != 0 {
				if criterion, found := criteria[target.CriterionIDs[0]]; found {
					observable = chineseOrFallback(criterion.Name, observable)
				}
			}
			sourceName := businessSourceName(snapshot.sources, target)
			views = append(views, httpapi.CapabilityView{
				CapabilityRef: stableRef("cap", session.TenantID, session.SiteID, assignment.AssignmentID, fmt.Sprint(assignment.Revision), target.TargetID),
				Title:         titleSubject + "巡检",
				Description:   "可以按当前已配置的范围查看" + observable + "，并返回业务结论和可用的现场依据。",
				Examples:      []string{"帮我看看" + sourceName + "的" + observable},
			})
		}
	}
	if len(views) == 0 {
		views = append(views, httpapi.CapabilityView{
			CapabilityRef: stableRef("cap", session.TenantID, session.SiteID, "local-onboarding"),
			Title:         "现场接入引导",
			Description:   "可以引导你在本机管理页面完成现场接入和巡检准备。",
			Examples:      []string{"帮我准备现场接入"},
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].CapabilityRef < views[j].CapabilityRef })
	result := httpapi.CapabilitySet{ContextLabel: "当前现场", Capabilities: views}
	if err := validateChineseCapabilitySet(result); err != nil {
		return httpapi.CapabilitySet{}, err
	}
	return result, nil
}

func (s *Service) loadSnapshot(ctx context.Context, session httpapi.SessionBinding) (catalogSnapshot, error) {
	templates, err := s.registry.ListInspectionTemplates(ctx, session.TenantID)
	if err != nil {
		return catalogSnapshot{}, err
	}
	assignments, err := s.registry.ListAssignments(ctx, session.TenantID, session.SiteID)
	if err != nil {
		return catalogSnapshot{}, err
	}
	fingerprintBefore, err := s.catalog.Fingerprint(ctx, session.TenantID, session.SiteID)
	if err != nil {
		return catalogSnapshot{}, err
	}
	sources, err := s.catalog.ListSite(ctx, session.TenantID, session.SiteID)
	if err != nil {
		return catalogSnapshot{}, err
	}
	tasks, err := s.catalog.ListTasks(ctx, session.TenantID, session.SiteID)
	if err != nil {
		return catalogSnapshot{}, err
	}
	fingerprint, err := s.catalog.Fingerprint(ctx, session.TenantID, session.SiteID)
	if err != nil {
		return catalogSnapshot{}, err
	}
	if fingerprintBefore != fingerprint || len(templates) > maximumCatalogItems || len(assignments) > maximumCatalogItems || len(sources) > maximumCatalogItems || len(tasks) > maximumCatalogItems || !digestPattern.MatchString(fingerprint) {
		return catalogSnapshot{}, errors.New("inspection planning catalog is invalid or exceeds its bound")
	}

	latestTemplates := make(map[string]inspection.InspectionTemplate)
	for _, item := range templates {
		if err := item.Validate(); err != nil || item.TenantID != session.TenantID {
			return catalogSnapshot{}, errors.New("inspection template registry returned an invalid scoped item")
		}
		if current, ok := latestTemplates[item.TemplateID]; !ok || item.Revision > current.Revision {
			latestTemplates[item.TemplateID] = item
		}
	}
	for id, item := range latestTemplates {
		if item.State != inspection.TemplatePublished {
			delete(latestTemplates, id)
		}
	}

	latestAssignments := make(map[string]inspection.Assignment)
	for _, item := range assignments {
		if err := item.Validate(); err != nil || item.TenantID != session.TenantID || item.SiteID != session.SiteID {
			return catalogSnapshot{}, errors.New("inspection assignment registry returned an invalid scoped item")
		}
		if current, ok := latestAssignments[item.AssignmentID]; !ok || item.Revision > current.Revision {
			latestAssignments[item.AssignmentID] = item
		}
	}
	assignments = assignments[:0]
	for _, item := range latestAssignments {
		if item.Published {
			assignments = append(assignments, item)
		}
	}
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].AssignmentID < assignments[j].AssignmentID })
	for _, item := range sources {
		if err := item.Validate(); err != nil || item.TenantID != session.TenantID || item.SiteID != session.SiteID {
			return catalogSnapshot{}, errors.New("inspection source catalog returned an invalid scoped item")
		}
	}
	for _, item := range tasks {
		if err := item.Validate(); err != nil || item.TenantID != session.TenantID || item.SiteID != session.SiteID {
			return catalogSnapshot{}, errors.New("inspection task catalog returned an invalid scoped item")
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Handle < sources[j].Handle })
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].TaskHandle < tasks[j].TaskHandle })
	return catalogSnapshot{templates: latestTemplates, assignments: assignments, sources: sources, tasks: tasks, fingerprint: fingerprint}, nil
}

func (s *Service) authenticatedScope(session httpapi.SessionBinding) (resolver.AuthenticatedScope, error) {
	if !digestPattern.MatchString(session.PrincipalSHA256) {
		return resolver.AuthenticatedScope{}, httpapi.ErrForbidden
	}
	channel, err := resolverChannel(session.Channel)
	if err != nil {
		return resolver.AuthenticatedScope{}, httpapi.ErrForbidden
	}
	return resolver.AuthenticatedScope{TenantID: session.TenantID, SiteID: session.SiteID, Channel: channel, PrincipalSHA256: session.PrincipalSHA256}, nil
}

type convertedIntent struct {
	intent         resolver.BusinessIntent
	observableCode string
	variables      map[string]string
}

func convertIntent(value InterpretedIntent, snapshot catalogSnapshot) (convertedIntent, error) {
	switch value.Goal {
	case IntentConnect:
		purpose := resolver.ConnectionPurposeConnectDevice
		if *value.Connection == RefreshCurrent {
			purpose = resolver.ConnectionPurposeRefresh
		}
		return convertedIntent{intent: resolver.BusinessIntent{Goal: resolver.GoalConnect, Connection: &resolver.ConnectionIntent{Purpose: purpose}}}, nil
	case IntentPersistentChange:
		intent, err := convertPersistent(*value.PersistentChange, snapshot)
		if err != nil {
			return convertedIntent{}, err
		}
		return convertedIntent{intent: resolver.BusinessIntent{Goal: resolver.GoalPersistentChange, PersistentChange: &intent}}, nil
	case IntentInspect:
		business, observableCode, variables, err := convertInspection(*value.Inspection, snapshot)
		if err != nil {
			return convertedIntent{}, err
		}
		return convertedIntent{intent: resolver.BusinessIntent{Goal: resolver.GoalInspect, Inspection: &business}, observableCode: observableCode, variables: variables}, nil
	default:
		return convertedIntent{}, fmt.Errorf("%w: unsupported inspection goal", httpapi.ErrInvalid)
	}
}

func convertInspection(value InspectionIntent, snapshot catalogSnapshot) (resolver.InspectionIntent, string, map[string]string, error) {
	preference, err := resolverPreference(value.Preference)
	if err != nil {
		return resolver.InspectionIntent{}, "", nil, err
	}
	selector := resolver.SourceSelector{Alias: value.SourceName}
	taskHandle := ""
	if value.TaskName != "" {
		task, err := uniqueTaskByAlias(snapshot.tasks, value.TaskName)
		if err != nil {
			return resolver.InspectionIntent{}, "", nil, err
		}
		taskHandle = task.TaskHandle
	}
	if value.Mode == ModeTemporaryVisual {
		intent := temporary.Intent{
			Subject: value.Temporary.Subject, Region: value.Temporary.Region, Observable: value.Temporary.Observable,
			Locale: value.Temporary.Locale, TimeScope: value.TimeScope, EvidenceTTLSeconds: value.Temporary.EvidenceTTLSeconds,
		}
		return resolver.InspectionIntent{
			Mode: resolver.InspectionModeTemporaryVisual, Source: selector, TemporaryIntent: &intent,
			TaskHandle: taskHandle, Preference: preference,
		}, "", nil, nil
	}
	observable, err := uniqueObservableCode(snapshot.templates, value.ObservableName)
	if err != nil {
		return resolver.InspectionIntent{}, "", nil, err
	}
	variables, err := variableMap(value.VariableChoices)
	if err != nil {
		return resolver.InspectionIntent{}, "", nil, err
	}
	timeScope := value.TimeScope
	return resolver.InspectionIntent{
		Mode: resolver.InspectionModeStandard, Source: selector, ObservableCode: observable,
		StandardTimeScope: &timeScope, TaskHandle: taskHandle, Preference: preference, VisualFollowup: value.VisualFollowup,
	}, observable, variables, nil
}

func convertPersistent(value PersistentChangeIntent, snapshot catalogSnapshot) (resolver.PersistentChangeIntent, error) {
	result := resolver.PersistentChangeIntent{}
	switch value.Kind {
	case ChangeCreateSource:
		result.Kind = resolver.ChangeSourceCreate
	case ChangeUpdateSource, ChangeDeleteSource:
		source, err := uniqueSourceByAlias(snapshot.sources, value.SourceName)
		if err != nil {
			return result, err
		}
		if value.Kind == ChangeUpdateSource {
			result.Kind = resolver.ChangeSourceUpdate
		} else {
			result.Kind = resolver.ChangeSourceDelete
		}
		result.SourceHandle, result.ExpectedSourceRevision = source.Handle, source.Revision
	case ChangeDeployTask:
		source, err := uniqueSourceByAlias(snapshot.sources, value.SourceName)
		if err != nil {
			return result, err
		}
		observable, err := uniqueObservableCode(snapshot.templates, value.ObservableName)
		if err != nil {
			return result, err
		}
		result = resolver.PersistentChangeIntent{Kind: resolver.ChangeTaskDeploy, SourceHandle: source.Handle, ExpectedSourceRevision: source.Revision, ObservableCode: observable}
	case ChangeUpdateTask, ChangeEnableTask, ChangeDisableTask, ChangeUpdateSchedule:
		source, err := uniqueSourceByAlias(snapshot.sources, value.SourceName)
		if err != nil {
			return result, err
		}
		task, err := uniqueTaskByAlias(snapshot.tasks, value.TaskName)
		if err != nil || !containsString(task.SourceHandles, source.Handle) {
			return result, fmt.Errorf("%w: persistent task target is ambiguous or stale", httpapi.ErrConflict)
		}
		result.SourceHandle, result.ExpectedSourceRevision = source.Handle, source.Revision
		result.TaskHandle, result.ExpectedTaskRevision = task.TaskHandle, task.Revision
		switch value.Kind {
		case ChangeUpdateTask:
			observable, err := uniqueObservableCode(snapshot.templates, value.ObservableName)
			if err != nil {
				return result, err
			}
			result.Kind, result.ObservableCode = resolver.ChangeTaskUpdate, observable
		case ChangeEnableTask:
			result.Kind = resolver.ChangeTaskEnable
		case ChangeDisableTask:
			result.Kind = resolver.ChangeTaskDisable
		case ChangeUpdateSchedule:
			result.Kind = resolver.ChangeDeviceScheduleUpdate
		}
	default:
		return result, fmt.Errorf("%w: unsupported persistent change", httpapi.ErrInvalid)
	}
	return result, nil
}

type trustedFacts struct {
	sources []resolver.SourceFact
	tasks   []resolver.InstalledTaskFact
}

func (s *Service) resolverFacts(ctx context.Context, session httpapi.SessionBinding, snapshot catalogSnapshot, observableCode string) (trustedFacts, error) {
	facts := trustedFacts{sources: make([]resolver.SourceFact, 0, len(snapshot.sources))}
	for _, source := range snapshot.sources {
		summary, err := source.Summary()
		if err != nil {
			return trustedFacts{}, err
		}
		facts.sources = append(facts.sources, resolver.SourceFact{
			TenantID: session.TenantID, SiteID: session.SiteID, Summary: summary,
			ObservedAt: source.UpdatedAt.UTC(), ExpiresAt: source.UpdatedAt.UTC().Add(s.catalogFactTTL),
		})
	}

	type taskFactKey struct{ task, source, capability string }
	observables := make(map[taskFactKey]map[string]struct{})
	for _, assignment := range snapshot.assignments {
		if assignment.SourceCatalogFingerprint != snapshot.fingerprint {
			continue
		}
		template, ok := snapshot.templates[assignment.TemplateID]
		if !ok || assignment.TemplateRevision != template.Revision || s.validateAssignmentFresh(ctx, session, snapshot, assignment) != nil {
			continue
		}
		for _, target := range assignment.Targets {
			for _, installed := range target.InstalledTasks {
				if err := s.catalog.ValidateInstalledTask(ctx, session.TenantID, session.SiteID, installed); err != nil {
					continue
				}
				for _, source := range installed.Sources {
					for _, capability := range installed.Capabilities {
						key := taskFactKey{task: installed.TaskID, source: source.SourceHandle, capability: capability.Ref}
						if observables[key] == nil {
							observables[key] = make(map[string]struct{})
						}
						for _, criterionID := range target.CriterionIDs {
							if observableCode == "" || observableCode == criterionID {
								observables[key][criterionID] = struct{}{}
							}
						}
					}
				}
			}
		}
	}
	byTask := make(map[string]catalog.DeviceTaskBinding, len(snapshot.tasks))
	for _, task := range snapshot.tasks {
		byTask[task.TaskHandle] = task
	}
	keys := make([]taskFactKey, 0, len(observables))
	for key, values := range observables {
		if len(values) != 0 {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].task != keys[j].task {
			return keys[i].task < keys[j].task
		}
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].capability < keys[j].capability
	})
	for _, key := range keys {
		task, ok := byTask[key.task]
		if !ok {
			continue
		}
		capability, ok := taskCapability(task, key.capability)
		if !ok {
			continue
		}
		sourceRevision := uint64(0)
		for _, source := range snapshot.sources {
			if source.Handle == key.source {
				sourceRevision = source.Revision
				break
			}
		}
		codes := mapKeys(observables[key])
		facts.tasks = append(facts.tasks, resolver.InstalledTaskFact{
			TenantID: session.TenantID, SiteID: session.SiteID, TaskHandle: task.TaskHandle,
			SourceHandle: key.source, SourceRevision: sourceRevision, CapabilityRef: key.capability,
			Revision: task.Revision, State: task.State, ObservableCodes: codes, ResultSchema: capability.ResultSchema,
			ObservedAt: task.ObservedAt.UTC(), ExpiresAt: task.ObservedAt.UTC().Add(s.catalogFactTTL),
		})
	}
	return facts, nil
}

type standardCandidate struct {
	template   inspection.InspectionTemplate
	assignment inspection.Assignment
	targetID   string
	variables  map[string]string
}

func (s *Service) planStandard(ctx context.Context, input application.PlanningRequest, snapshot catalogSnapshot, requestedVariables map[string]string, observableCode string, resolution resolver.Resolution) (application.PlanningDecision, error) {
	strategy, ok := strategyForRoute(resolution.Route)
	if !ok {
		return application.PlanningDecision{}, errors.New("inspection route cannot produce a standard plan")
	}
	candidates := make([]standardCandidate, 0, 2)
	for _, assignment := range snapshot.assignments {
		if assignment.SourceCatalogFingerprint != snapshot.fingerprint || s.validateAssignmentFresh(ctx, input.Session, snapshot, assignment) != nil {
			continue
		}
		template, ok := snapshot.templates[assignment.TemplateID]
		if !ok || template.Revision != assignment.TemplateRevision {
			continue
		}
		for _, target := range assignment.Targets {
			if !targetMatchesResolution(target, strategy, observableCode, resolution) {
				continue
			}
			variables, err := bindVariables(template, target, requestedVariables)
			if err != nil {
				continue
			}
			candidates = append(candidates, standardCandidate{template: template, assignment: assignment, targetID: target.TargetID, variables: variables})
		}
	}
	if len(candidates) != 1 {
		return application.PlanningDecision{}, fmt.Errorf("%w: published inspection plan is missing, stale, or ambiguous", httpapi.ErrConflict)
	}
	candidate := candidates[0]
	duration := s.defaultRunTTL
	maximum := time.Duration(candidate.template.Budget.MaxDurationSeconds) * time.Second
	if maximum < duration {
		duration = maximum
	}
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: input.Session.TenantID, SiteID: input.Session.SiteID,
		TemplateID: candidate.template.TemplateID, TemplateRevision: candidate.template.Revision,
		AssignmentID: candidate.assignment.AssignmentID, AssignmentRevision: candidate.assignment.Revision,
		Origin: originForChannel(input.Session.Channel), RequestID: input.RequestID, TargetIDs: []string{candidate.targetID},
		Variables: candidate.variables, RequestedAt: input.RequestedAt.UTC(), Deadline: input.RequestedAt.UTC().Add(duration),
	}
	if _, err := inspection.CompilePlan(candidate.template, candidate.assignment, request); err != nil {
		return application.PlanningDecision{}, fmt.Errorf("%w: published inspection plan is not executable", httpapi.ErrConflict)
	}
	identity, err := inspectionauthority.ExecutionIdentityForOrigin(request.Origin, input.Session.PrincipalSHA256)
	if err != nil {
		return application.PlanningDecision{}, httpapi.ErrForbidden
	}
	submission, err := inspectionauthority.NewSubmission(request, identity)
	if err != nil {
		return application.PlanningDecision{}, err
	}
	return application.PlanningDecision{Template: candidate.template, Assignment: candidate.assignment, Submission: submission}, nil
}

func (s *Service) validateAssignmentFresh(ctx context.Context, session httpapi.SessionBinding, snapshot catalogSnapshot, assignment inspection.Assignment) error {
	if assignment.SourceCatalogFingerprint != snapshot.fingerprint {
		return errors.New("assignment catalog fingerprint is stale")
	}
	template, ok := snapshot.templates[assignment.TemplateID]
	if !ok || template.Revision != assignment.TemplateRevision {
		return errors.New("assignment template revision is stale")
	}
	bySource := make(map[string]catalog.Source, len(snapshot.sources))
	for _, source := range snapshot.sources {
		bySource[source.Handle] = source
	}
	for _, target := range assignment.Targets {
		expectedTaskSources := make(map[string]inspection.SourceBinding)
		for _, installed := range target.InstalledTasks {
			if err := s.catalog.ValidateInstalledTask(ctx, session.TenantID, session.SiteID, installed); err != nil {
				return err
			}
			for _, binding := range installed.TaskEvidenceSourceBindings() {
				expectedTaskSources[binding.SourceHandle] = binding
			}
		}
		for _, binding := range target.SourceBindings {
			if binding.Kind == inspection.SourceTaskEvidence {
				expected, ok := expectedTaskSources[binding.SourceHandle]
				if !ok || !reflect.DeepEqual(binding, expected) {
					return errors.New("assignment task-evidence binding is stale")
				}
				continue
			}
			source, ok := bySource[binding.SourceHandle]
			if !ok {
				return errors.New("assignment source is unavailable")
			}
			current, err := source.Binding(binding.CapabilityRefs, binding.ROIRef)
			if err != nil || !reflect.DeepEqual(binding, current) {
				return errors.New("assignment source binding is stale")
			}
		}
	}
	return nil
}

func targetMatchesResolution(target inspection.TargetBinding, strategy inspection.ExecutionStrategy, observableCode string, resolution resolver.Resolution) bool {
	if target.Strategy != strategy || !containsString(target.CriterionIDs, observableCode) {
		return false
	}
	sourceHandles := make(map[string]struct{})
	capabilities := make(map[string]struct{})
	taskEvidenceSources := 0
	for _, binding := range target.SourceBindings {
		sourceHandles[binding.SourceHandle] = struct{}{}
		if binding.Kind == inspection.SourceTaskEvidence {
			taskEvidenceSources++
		}
		for _, capability := range binding.CapabilityRefs {
			capabilities[capability] = struct{}{}
		}
	}
	switch strategy {
	case inspection.StrategyExistingTaskRead:
		if len(target.SourceBindings) != 1 || taskEvidenceSources != 1 {
			return false
		}
	case inspection.StrategySnapshotAnalysis, inspection.StrategyClipAnalysis:
		if len(target.SourceBindings) != 1 || taskEvidenceSources != 0 {
			return false
		}
	case inspection.StrategyHybridAnalysis:
		if len(target.SourceBindings) != 2 || taskEvidenceSources != 1 {
			return false
		}
	}
	if !sameSet(sourceHandles, resolution.SourceHandles) || !sameSet(capabilities, resolution.CapabilityRefs) {
		return false
	}
	tasks := make(map[string]struct{}, len(target.InstalledTasks))
	for _, task := range target.InstalledTasks {
		tasks[task.TaskID] = struct{}{}
	}
	return len(target.InstalledTasks) == len(resolution.TaskHandles) && sameSet(tasks, resolution.TaskHandles)
}

func bindVariables(template inspection.InspectionTemplate, target inspection.TargetBinding, requested map[string]string) (map[string]string, error) {
	criteria := criteriaByID(template)
	declared := make(map[string]inspection.PromptVariable)
	for _, criterionID := range target.CriterionIDs {
		criterion, ok := criteria[criterionID]
		if !ok {
			return nil, errors.New("target criterion is unavailable")
		}
		for _, variable := range criterion.Prompt.Variables {
			if existing, duplicate := declared[variable.Name]; duplicate && !reflect.DeepEqual(existing, variable) {
				return nil, errors.New("prompt variable contract is ambiguous")
			}
			declared[variable.Name] = variable
		}
	}
	for name := range requested {
		if _, ok := declared[name]; !ok {
			return nil, errors.New("interpreter selected an undeclared variable")
		}
	}
	result := make(map[string]string)
	for name, variable := range declared {
		value, supplied := requested[name]
		if !supplied && variable.Required && len(variable.AllowedValues) == 1 {
			value, supplied = variable.AllowedValues[0], true
		}
		if !supplied {
			if variable.Required {
				return nil, errors.New("required prompt variable was not selected")
			}
			continue
		}
		if utf8.RuneCountInString(value) > variable.MaxLength || len(variable.AllowedValues) != 0 && !containsString(variable.AllowedValues, value) || inputguard.ValidateText(value) != nil {
			return nil, errors.New("prompt variable selection is outside the published allowlist")
		}
		result[name] = value
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func validatePlanningInput(input application.PlanningRequest) error {
	if !validSession(input.Session) || !validRef(input.RequestID) || input.RequestedAt.IsZero() || input.RequestedAt.Location() != time.UTC ||
		!validBusinessText(input.Request.Instruction, 1, 2000) || len(input.Request.Context) > 16 {
		return errors.New("inspection planning request is invalid")
	}
	seen := make(map[string]struct{}, len(input.Request.Context))
	for _, item := range input.Request.Context {
		if !validBusinessText(item.Name, 1, 128) || !validBusinessText(item.Value, 1, 512) {
			return errors.New("inspection business context is invalid")
		}
		key := canonicalContextName(item.Name)
		if reservedContextName(key) {
			return errors.New("inspection business context attempts to supply a trusted fact")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("inspection business context is duplicated")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateInterpretedIntent(value InterpretedIntent) error {
	present := 0
	if value.Inspection != nil {
		present++
	}
	if value.Connection != nil {
		present++
	}
	if value.PersistentChange != nil {
		present++
	}
	if present != 1 {
		return errors.New("interpreted intent must contain exactly one typed payload")
	}
	switch value.Goal {
	case IntentConnect:
		if value.Connection == nil || (*value.Connection != ConnectNew && *value.Connection != RefreshCurrent) {
			return errors.New("connection intent is invalid")
		}
	case IntentPersistentChange:
		if value.PersistentChange == nil {
			return errors.New("persistent-change intent is missing")
		}
		change := *value.PersistentChange
		if change.SourceName != "" && !validBusinessText(change.SourceName, 1, 160) || change.TaskName != "" && !validBusinessText(change.TaskName, 1, 160) || change.ObservableName != "" && !validBusinessText(change.ObservableName, 1, 160) {
			return errors.New("persistent-change business selector is invalid")
		}
		if err := validatePersistentBusinessShape(change); err != nil {
			return err
		}
	case IntentInspect:
		if value.Inspection == nil {
			return errors.New("inspection intent is missing")
		}
		intent := *value.Inspection
		if !validBusinessText(intent.SourceName, 1, 160) || intent.TaskName != "" && !validBusinessText(intent.TaskName, 1, 160) {
			return errors.New("inspection business selector is invalid")
		}
		if _, err := resolverPreference(intent.Preference); err != nil {
			return err
		}
		switch intent.Mode {
		case ModeStandard:
			if !validBusinessText(intent.ObservableName, 1, 160) || intent.Temporary != nil {
				return errors.New("standard inspection intent is invalid")
			}
			if (intent.Preference == PreferSnapshot || intent.Preference == PreferClip) && intent.TaskName != "" ||
				(intent.Preference == PreferExistingTask || intent.Preference == PreferSnapshot || intent.Preference == PreferClip) && intent.VisualFollowup {
				return errors.New("standard inspection intent contains conflicting route selectors")
			}
		case ModeTemporaryVisual:
			if intent.ObservableName != "" || intent.Temporary == nil || len(intent.VariableChoices) != 0 || intent.VisualFollowup || intent.Preference == PreferExistingTask ||
				intent.Preference == PreferHybrid && intent.TaskName == "" || intent.Preference != PreferHybrid && intent.TaskName != "" {
				return errors.New("temporary observation intent is invalid")
			}
			temporaryIntent := intent.Temporary
			if !validBusinessText(temporaryIntent.Subject, 1, 160) || !validBusinessText(temporaryIntent.Region, 1, 160) || !validBusinessText(temporaryIntent.Observable, 1, 512) {
				return errors.New("temporary observation text is invalid")
			}
		default:
			return errors.New("inspection mode is invalid")
		}
		if _, err := variableMap(intent.VariableChoices); err != nil {
			return err
		}
	default:
		return errors.New("interpreted goal is invalid")
	}
	return nil
}

func validatePersistentBusinessShape(value PersistentChangeIntent) error {
	hasSource, hasTask, hasObservable := value.SourceName != "", value.TaskName != "", value.ObservableName != ""
	valid := false
	switch value.Kind {
	case ChangeCreateSource:
		valid = !hasSource && !hasTask && !hasObservable
	case ChangeUpdateSource, ChangeDeleteSource:
		valid = hasSource && !hasTask && !hasObservable
	case ChangeDeployTask:
		valid = hasSource && !hasTask && hasObservable
	case ChangeUpdateTask:
		valid = hasSource && hasTask && hasObservable
	case ChangeEnableTask, ChangeDisableTask, ChangeUpdateSchedule:
		valid = hasSource && hasTask && !hasObservable
	}
	if !valid {
		return errors.New("persistent-change intent shape is invalid")
	}
	return nil
}

func variableMap(values []VariableSelection) (map[string]string, error) {
	if len(values) > 64 {
		return nil, fmt.Errorf("%w: too many variable selections", httpapi.ErrInvalid)
	}
	result := make(map[string]string, len(values))
	for _, item := range values {
		if !validRef(item.Name) || !validBusinessText(item.Value, 1, 512) {
			return nil, fmt.Errorf("%w: invalid variable selection", httpapi.ErrInvalid)
		}
		if _, duplicate := result[item.Name]; duplicate {
			return nil, fmt.Errorf("%w: duplicate variable selection", httpapi.ErrInvalid)
		}
		result[item.Name] = item.Value
	}
	return result, nil
}

func vocabulary(snapshot catalogSnapshot) BusinessVocabulary {
	sources, tasks, observables := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
	variables := make(map[string]map[string]struct{})
	for _, source := range snapshot.sources {
		sources[source.Alias] = struct{}{}
	}
	for _, task := range snapshot.tasks {
		tasks[task.Alias] = struct{}{}
	}
	for _, template := range snapshot.templates {
		for _, criterion := range template.Criteria {
			observables[criterion.Name] = struct{}{}
			for _, variable := range criterion.Prompt.Variables {
				if variables[variable.Name] == nil {
					variables[variable.Name] = make(map[string]struct{})
				}
				for _, allowed := range variable.AllowedValues {
					variables[variable.Name][allowed] = struct{}{}
				}
			}
		}
	}
	variableOptions := make([]BusinessVariableOption, 0, len(variables))
	for name, allowed := range variables {
		variableOptions = append(variableOptions, BusinessVariableOption{Name: name, AllowedValues: mapKeys(allowed)})
	}
	sort.Slice(variableOptions, func(i, j int) bool { return variableOptions[i].Name < variableOptions[j].Name })
	return BusinessVocabulary{SourceNames: mapKeys(sources), TaskNames: mapKeys(tasks), ObservableNames: mapKeys(observables), VariableOptions: variableOptions}
}

func uniqueObservableCode(templates map[string]inspection.InspectionTemplate, name string) (string, error) {
	codes := make(map[string]struct{})
	for _, template := range templates {
		for _, criterion := range template.Criteria {
			if criterion.Name == name {
				codes[criterion.ID] = struct{}{}
			}
		}
	}
	if len(codes) != 1 {
		return "", fmt.Errorf("%w: inspection observable is missing or ambiguous", httpapi.ErrConflict)
	}
	for code := range codes {
		return code, nil
	}
	panic("unreachable")
}

func uniqueSourceByAlias(values []catalog.Source, alias string) (catalog.Source, error) {
	var result catalog.Source
	count := 0
	for _, item := range values {
		if item.Alias == alias {
			result, count = item, count+1
		}
	}
	if count != 1 {
		return catalog.Source{}, fmt.Errorf("%w: inspection source is missing or ambiguous", httpapi.ErrConflict)
	}
	return result, nil
}

func uniqueTaskByAlias(values []catalog.DeviceTaskBinding, alias string) (catalog.DeviceTaskBinding, error) {
	var result catalog.DeviceTaskBinding
	count := 0
	for _, item := range values {
		if item.Alias == alias {
			result, count = item, count+1
		}
	}
	if count != 1 {
		return catalog.DeviceTaskBinding{}, fmt.Errorf("%w: inspection task is missing or ambiguous", httpapi.ErrConflict)
	}
	return result, nil
}

func resolverPreference(value ExecutionPreference) (resolver.RoutePreference, error) {
	switch value {
	case PreferAuto:
		return resolver.PreferenceAuto, nil
	case PreferExistingTask:
		return resolver.PreferenceExistingTask, nil
	case PreferSnapshot:
		return resolver.PreferenceSnapshot, nil
	case PreferClip:
		return resolver.PreferenceClip, nil
	case PreferHybrid:
		return resolver.PreferenceHybrid, nil
	default:
		return "", fmt.Errorf("%w: inspection execution preference is invalid", httpapi.ErrInvalid)
	}
}

func strategyForRoute(route resolver.Route) (inspection.ExecutionStrategy, bool) {
	switch route {
	case resolver.RouteExistingTaskRead:
		return inspection.StrategyExistingTaskRead, true
	case resolver.RouteSnapshotAnalysis:
		return inspection.StrategySnapshotAnalysis, true
	case resolver.RouteClipAnalysis:
		return inspection.StrategyClipAnalysis, true
	case resolver.RouteHybridAnalysis:
		return inspection.StrategyHybridAnalysis, true
	default:
		return "", false
	}
}

func resolverChannel(value string) (resolver.Channel, error) {
	switch value {
	case string(resolver.ChannelWorkBuddyWeChat):
		return resolver.ChannelWorkBuddyWeChat, nil
	case string(resolver.ChannelLocalOperator):
		return resolver.ChannelLocalOperator, nil
	case string(resolver.ChannelAPI):
		return resolver.ChannelAPI, nil
	default:
		return "", errors.New("unsupported inspection channel")
	}
}

func originForChannel(value string) inspection.RunOrigin {
	if value == string(resolver.ChannelAPI) {
		return inspection.OriginAPI
	}
	return inspection.OriginUser
}

func (s *Service) registerInteraction(
	ctx context.Context,
	input application.PlanningRequest,
	scope resolver.AuthenticatedScope,
	kind LocalInteractionType,
	change *PendingChangeIntent,
) (application.PlanningDecision, error) {
	kindText := "connection"
	if kind == LocalInteractionPersistentChange {
		kindText = "persistent-change"
	}
	interaction := localInteraction(input, kindText)
	expiresAt := input.RequestedAt.UTC().Add(s.defaultRunTTL)
	registration := LocalInteractionRegistration{
		Type: kind, TenantID: scope.TenantID, SiteID: scope.SiteID, PrincipalSHA256: scope.PrincipalSHA256,
		HandoffRef: interaction.HandoffRef, ExpiresAt: expiresAt, Change: change,
	}
	if err := validateLocalInteractionRegistration(registration, s.now().UTC()); err != nil {
		return application.PlanningDecision{}, fmt.Errorf("%w: local interaction registration is invalid", httpapi.ErrConflict)
	}
	receipt, err := s.interactions.Register(ctx, registration)
	if err != nil {
		return application.PlanningDecision{}, fmt.Errorf("%w: local interaction could not be registered", httpapi.ErrConflict)
	}
	if receipt.Type != registration.Type || receipt.HandoffRef != registration.HandoffRef || receipt.ExpiresAt != registration.ExpiresAt {
		return application.PlanningDecision{}, fmt.Errorf("%w: local interaction registration was not acknowledged exactly", httpapi.ErrConflict)
	}
	return application.PlanningDecision{Interaction: interaction}, nil
}

func pendingChangeFromProposal(proposal *resolver.PersistentChangeProposal) (PendingChangeIntent, error) {
	if proposal == nil {
		return PendingChangeIntent{}, errors.New("persistent change proposal is missing")
	}
	operations := map[resolver.PersistentChangeKind]PendingChangeOperation{
		resolver.ChangeSourceCreate:         PendingSourceCreate,
		resolver.ChangeSourceUpdate:         PendingSourceUpdate,
		resolver.ChangeSourceDelete:         PendingSourceDelete,
		resolver.ChangeTaskDeploy:           PendingTaskDeploy,
		resolver.ChangeTaskUpdate:           PendingTaskUpdate,
		resolver.ChangeTaskEnable:           PendingTaskEnable,
		resolver.ChangeTaskDisable:          PendingTaskDisable,
		resolver.ChangeDeviceScheduleUpdate: PendingDeviceScheduleUpdate,
	}
	operation, ok := operations[proposal.Kind]
	if !ok {
		return PendingChangeIntent{}, errors.New("persistent change operation is unsupported")
	}
	change := PendingChangeIntent{
		Operation: operation, SourceRef: proposal.SourceHandle, TaskRef: proposal.TaskHandle,
		ObservableRef: proposal.ObservableCode, ExpectedSourceRevision: proposal.ExpectedSourceRevision,
		ExpectedTaskRevision: proposal.ExpectedTaskRevision,
	}
	if err := validatePendingChange(change); err != nil {
		return PendingChangeIntent{}, err
	}
	return change, nil
}

func validateLocalInteractionRegistration(value LocalInteractionRegistration, now time.Time) error {
	if !refPattern.MatchString(value.TenantID) || !refPattern.MatchString(value.SiteID) ||
		!digestPattern.MatchString(value.PrincipalSHA256) || !refPattern.MatchString(value.HandoffRef) ||
		value.ExpiresAt.IsZero() || value.ExpiresAt.Location() != time.UTC || !value.ExpiresAt.After(now) {
		return errors.New("local interaction scope or lifetime is invalid")
	}
	switch value.Type {
	case LocalInteractionConnection:
		if value.Change != nil {
			return errors.New("connection interaction contains a change intent")
		}
	case LocalInteractionPersistentChange:
		if value.Change == nil {
			return errors.New("persistent interaction is missing its closed intent")
		}
		return validatePendingChange(*value.Change)
	default:
		return errors.New("local interaction type is invalid")
	}
	return nil
}

func validatePendingChange(value PendingChangeIntent) error {
	for _, ref := range []string{value.SourceRef, value.TaskRef, value.ObservableRef} {
		if ref != "" && !refPattern.MatchString(ref) {
			return errors.New("pending change contains an invalid opaque reference")
		}
	}
	noSource := value.SourceRef == "" && value.ExpectedSourceRevision == 0
	noTask := value.TaskRef == "" && value.ExpectedTaskRevision == 0
	valid := false
	switch value.Operation {
	case PendingSourceCreate:
		valid = noSource && noTask && value.ObservableRef == ""
	case PendingSourceUpdate, PendingSourceDelete:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && noTask && value.ObservableRef == ""
	case PendingTaskDeploy:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && noTask && value.ObservableRef != ""
	case PendingTaskUpdate:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && value.TaskRef != "" && value.ExpectedTaskRevision > 0 && value.ObservableRef != ""
	case PendingTaskEnable, PendingTaskDisable, PendingDeviceScheduleUpdate:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && value.TaskRef != "" && value.ExpectedTaskRevision > 0 && value.ObservableRef == ""
	}
	if !valid {
		return errors.New("pending change shape is invalid")
	}
	return nil
}

func localInteraction(input application.PlanningRequest, kind string) *httpapi.InteractionRequired {
	interaction := &httpapi.InteractionRequired{ActionLabel: "打开本机管理页面"}
	if kind == "connection" {
		interaction.Capability = httpapi.InteractionCapabilityOnboarding
		interaction.Title = "需要在本机完成现场接入"
		interaction.Message = "请在本机管理页面填写连接信息并确认，完成后再发起巡检。"
	} else {
		interaction.Capability = httpapi.InteractionCapabilityPersistentChange
		interaction.Title = "需要在本机确认现场变更"
		interaction.Message = "该变更只会生成待确认事项，请在本机管理页面核对并确认后执行。"
	}
	interaction.HandoffRef = stableRef("handoff", input.Session.TenantID, input.Session.SiteID, input.Session.Channel, input.RequestID, kind)
	return interaction
}

func stableRef(prefix string, values ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(append([]string{prefix}, values...), "\x00")))
	return prefix + "_" + hex.EncodeToString(digest[:16])
}

func cloneInterpretationContext(values []httpapi.BusinessContext) []InterpretationContext {
	result := make([]InterpretationContext, len(values))
	for index, item := range values {
		result[index] = InterpretationContext{Name: item.Name, Value: item.Value}
	}
	return result
}

func cloneAuthorities(values []resolver.AuthorityAvailability) []resolver.AuthorityAvailability {
	result := append([]resolver.AuthorityAvailability(nil), values...)
	for index := range result {
		result[index].SourceHandles = append([]string(nil), result[index].SourceHandles...)
	}
	return result
}

func criteriaByID(template inspection.InspectionTemplate) map[string]inspection.Criterion {
	result := make(map[string]inspection.Criterion, len(template.Criteria))
	for _, criterion := range template.Criteria {
		result[criterion.ID] = criterion
	}
	return result
}

func taskCapability(task catalog.DeviceTaskBinding, ref string) (catalog.Capability, bool) {
	for _, capability := range task.Capabilities {
		if capability.Ref == ref {
			return capability, true
		}
	}
	return catalog.Capability{}, false
}

func temporaryVisualCapability(sources []catalog.Source, resolution resolver.Resolution) (string, bool) {
	wanted := catalog.CapabilitySnapshot
	switch resolution.Route {
	case resolver.RouteSnapshotAnalysis:
		wanted = catalog.CapabilitySnapshot
	case resolver.RouteClipAnalysis:
		wanted = catalog.CapabilityClip
	case resolver.RouteHybridAnalysis:
		if resolution.TemporaryObservationSpec != nil && resolution.TemporaryObservationSpec.TimeScope.Kind == temporary.TimeScopeRecentWindow {
			wanted = catalog.CapabilityClip
		}
	default:
		return "", false
	}
	for _, source := range sources {
		if len(resolution.SourceHandles) != 1 || source.Handle != resolution.SourceHandles[0] {
			continue
		}
		for _, capability := range source.Capabilities {
			if capability.Kind == wanted && containsString(resolution.CapabilityRefs, capability.Ref) {
				return capability.Ref, true
			}
		}
	}
	return "", false
}

func businessSourceName(sources []catalog.Source, target inspection.TargetBinding) string {
	for _, binding := range target.SourceBindings {
		if binding.Kind == inspection.SourceTaskEvidence {
			continue
		}
		for _, source := range sources {
			if source.Handle == binding.SourceHandle {
				return chineseOrFallback(source.Alias, "当前区域")
			}
		}
	}
	return "当前区域"
}

func chineseOrFallback(value, fallback string) string {
	value = strings.TrimSpace(value)
	hasHan := false
	for _, character := range value {
		if unicode.Is(unicode.Han, character) {
			hasHan = true
		}
		if character <= unicode.MaxASCII && unicode.IsLetter(character) {
			return fallback
		}
	}
	if !hasHan || inputguard.ValidateText(value) != nil {
		return fallback
	}
	return value
}

func validateChineseCapabilitySet(value httpapi.CapabilitySet) error {
	texts := []string{value.ContextLabel}
	for _, capability := range value.Capabilities {
		if !validRef(capability.CapabilityRef) || len(capability.Examples) == 0 {
			return errors.New("inspection capability projection is invalid")
		}
		texts = append(texts, capability.Title, capability.Description)
		texts = append(texts, capability.Examples...)
	}
	for _, item := range texts {
		if chineseOrFallback(item, "") == "" {
			return errors.New("inspection capability projection is not Chinese business text")
		}
	}
	return nil
}

func validSession(session httpapi.SessionBinding) bool {
	for _, value := range []string{session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef} {
		if value != strings.TrimSpace(value) || !audienceRefPattern.MatchString(value) {
			return false
		}
	}
	return digestPattern.MatchString(session.PrincipalSHA256)
}

func validRef(value string) bool {
	return value == strings.TrimSpace(value) && refPattern.MatchString(value)
}

func validBusinessText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || utf8.RuneCountInString(value) < minimum || utf8.RuneCountInString(value) > maximum || inputguard.ValidateText(value) != nil {
		return false
	}
	for _, character := range value {
		if character != '\n' && character != '\t' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
			return false
		}
	}
	return true
}

func canonicalContextName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(value)
}

func reservedContextName(value string) bool {
	if _, reserved := reservedContextNames[value]; reserved {
		return true
	}
	for _, fragment := range []string{
		"tenant", "principal", "sourcehandle", "taskhandle", "nativelocator", "authority", "credential",
		"capabilityref", "deviceid", "cameraid", "streamurl", "租户", "站点", "权限", "授权",
		"来源编号", "任务编号", "设备编号", "相机编号", "摄像头编号", "原生地址",
	} {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func mapKeys[T ~string](values map[T]struct{}) []T {
	result := make([]T, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func sameSet[T ~string](actual map[string]struct{}, expected []T) bool {
	if len(actual) != len(expected) {
		return false
	}
	for _, value := range expected {
		if _, ok := actual[string(value)]; !ok {
			return false
		}
	}
	return true
}
