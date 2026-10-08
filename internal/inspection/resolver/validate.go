package resolver

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

var (
	ErrInvalidRequest    = errors.New("inspection resolver request is invalid")
	ErrScopeMismatch     = errors.New("inspection resolver fact is outside the authenticated scope")
	ErrInvalidResolution = errors.New("inspection resolver produced an invalid resolution")
)

var (
	refPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	protectedPattern = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]{1,15}://|\bwww\.|password|passwd|token|credential|authorization|bearer|cookie|secret|api[_ -]?key|密码|口令|令牌|凭证|密钥)`)
)

const (
	maximumSources     = 128
	maximumTasks       = 512
	maximumAuthorities = 64
)

func (r Request) validate(now time.Time) error {
	if r.Schema != RequestSchemaVersion {
		return invalidRequest("schema is unsupported")
	}
	if err := r.Scope.validate(); err != nil {
		return err
	}
	if err := r.Intent.validate(); err != nil {
		return err
	}
	if len(r.Sources) > maximumSources || len(r.Tasks) > maximumTasks || len(r.Authorities) > maximumAuthorities {
		return invalidRequest("trusted fact set exceeds its bound")
	}
	for index, fact := range r.Sources {
		if err := fact.validate(now); err != nil {
			return fmt.Errorf("source fact %d: %w", index+1, err)
		}
		if fact.TenantID != r.Scope.TenantID || fact.SiteID != r.Scope.SiteID {
			return fmt.Errorf("source fact %d: %w", index+1, ErrScopeMismatch)
		}
	}
	for index, fact := range r.Tasks {
		if err := fact.validate(now); err != nil {
			return fmt.Errorf("installed task fact %d: %w", index+1, err)
		}
		if fact.TenantID != r.Scope.TenantID || fact.SiteID != r.Scope.SiteID {
			return fmt.Errorf("installed task fact %d: %w", index+1, ErrScopeMismatch)
		}
	}
	for index, availability := range r.Authorities {
		if err := availability.validate(now); err != nil {
			return fmt.Errorf("authority availability %d: %w", index+1, err)
		}
		if availability.TenantID != r.Scope.TenantID || availability.SiteID != r.Scope.SiteID ||
			availability.PrincipalSHA256 != r.Scope.PrincipalSHA256 {
			return fmt.Errorf("authority availability %d: %w", index+1, ErrScopeMismatch)
		}
	}
	return nil
}

func (s AuthenticatedScope) validate() error {
	if !validRef(s.TenantID) || !validRef(s.SiteID) || !digestPattern.MatchString(s.PrincipalSHA256) {
		return invalidRequest("authenticated scope is incomplete")
	}
	switch s.Channel {
	case ChannelWorkBuddyWeChat, ChannelLocalOperator, ChannelAPI:
		return nil
	default:
		return invalidRequest("authenticated channel is unsupported")
	}
}

func (i BusinessIntent) validate() error {
	present := 0
	if i.Inspection != nil {
		present++
	}
	if i.Connection != nil {
		present++
	}
	if i.PersistentChange != nil {
		present++
	}
	if present != 1 {
		return invalidRequest("business intent must contain exactly one typed payload")
	}
	switch i.Goal {
	case GoalInspect:
		if i.Inspection == nil {
			return invalidRequest("inspection goal requires inspection intent")
		}
		return i.Inspection.validate()
	case GoalConnect:
		if i.Connection == nil {
			return invalidRequest("connection goal requires connection intent")
		}
		return i.Connection.validate()
	case GoalPersistentChange:
		if i.PersistentChange == nil {
			return invalidRequest("persistent-change goal requires persistent-change intent")
		}
		return i.PersistentChange.validate()
	default:
		return invalidRequest("business goal is unsupported")
	}
}

func (i InspectionIntent) validate() error {
	if err := i.Source.validate(); err != nil {
		return err
	}
	if i.TaskHandle != "" && !validRef(i.TaskHandle) {
		return invalidRequest("task handle is invalid")
	}
	switch i.Preference {
	case PreferenceAuto, PreferenceExistingTask, PreferenceSnapshot, PreferenceClip, PreferenceHybrid:
	default:
		return invalidRequest("inspection route preference is unsupported")
	}

	switch i.Mode {
	case InspectionModeStandard:
		if !validRef(i.ObservableCode) || i.StandardTimeScope == nil || i.TemporaryIntent != nil {
			return invalidRequest("standard inspection intent is incomplete")
		}
		if err := validateTimeScope(*i.StandardTimeScope); err != nil {
			return err
		}
		if (i.Preference == PreferenceExistingTask || i.Preference == PreferenceSnapshot || i.Preference == PreferenceClip) && i.VisualFollowup {
			return invalidRequest("visual follow-up conflicts with the selected route preference")
		}
		if (i.Preference == PreferenceSnapshot || i.Preference == PreferenceClip) && i.TaskHandle != "" {
			return invalidRequest("visual-only inspection cannot select an installed task")
		}
	case InspectionModeTemporaryVisual:
		if i.TemporaryIntent == nil || i.StandardTimeScope != nil || i.ObservableCode != "" || i.VisualFollowup {
			return invalidRequest("temporary visual intent shape is invalid")
		}
		if i.Preference == PreferenceExistingTask {
			return invalidRequest("temporary visual intent cannot read an installed task without visual analysis")
		}
		if i.Preference == PreferenceHybrid && i.TaskHandle == "" {
			return invalidRequest("temporary hybrid intent requires one exact installed task")
		}
		if i.Preference != PreferenceHybrid && i.TaskHandle != "" {
			return invalidRequest("temporary visual intent can select a task only for hybrid analysis")
		}
	default:
		return invalidRequest("inspection mode is unsupported")
	}
	return nil
}

func (s SourceSelector) validate() error {
	hasHandle := s.SourceHandle != ""
	hasAlias := s.Alias != ""
	if hasHandle == hasAlias {
		return invalidRequest("source selector requires exactly one handle or alias")
	}
	if hasHandle {
		if !validRef(s.SourceHandle) || s.ZoneID != "" {
			return invalidRequest("source handle selector is invalid")
		}
		return nil
	}
	if err := validateBusinessText("source alias", s.Alias, 160); err != nil {
		return err
	}
	if s.ZoneID != "" && !validRef(s.ZoneID) {
		return invalidRequest("source zone is invalid")
	}
	return nil
}

func (i ConnectionIntent) validate() error {
	switch i.Purpose {
	case ConnectionPurposeConnectDevice, ConnectionPurposeRefresh:
		return nil
	default:
		return invalidRequest("connection purpose is unsupported")
	}
}

func (i PersistentChangeIntent) validate() error {
	for name, value := range map[string]string{
		"source handle":   i.SourceHandle,
		"task handle":     i.TaskHandle,
		"observable code": i.ObservableCode,
	} {
		if value != "" && !validRef(value) {
			return invalidRequest(name + " is invalid")
		}
	}
	noSource := i.SourceHandle == "" && i.ExpectedSourceRevision == 0
	noTask := i.TaskHandle == "" && i.ExpectedTaskRevision == 0
	switch i.Kind {
	case ChangeSourceCreate:
		if !noSource || !noTask || i.ObservableCode != "" {
			return invalidRequest("source-create intent contains an existing target")
		}
	case ChangeSourceUpdate, ChangeSourceDelete:
		if i.SourceHandle == "" || i.ExpectedSourceRevision == 0 || !noTask || i.ObservableCode != "" {
			return invalidRequest("source-change intent is incomplete")
		}
	case ChangeTaskDeploy:
		if i.SourceHandle == "" || i.ExpectedSourceRevision == 0 || !noTask || i.ObservableCode == "" {
			return invalidRequest("task-deploy intent is incomplete")
		}
	case ChangeTaskUpdate:
		if i.SourceHandle == "" || i.ExpectedSourceRevision == 0 || i.TaskHandle == "" || i.ExpectedTaskRevision == 0 || i.ObservableCode == "" {
			return invalidRequest("task-update intent is incomplete")
		}
	case ChangeTaskEnable, ChangeTaskDisable, ChangeDeviceScheduleUpdate:
		if i.SourceHandle == "" || i.ExpectedSourceRevision == 0 || i.TaskHandle == "" || i.ExpectedTaskRevision == 0 || i.ObservableCode != "" {
			return invalidRequest("task-state intent is incomplete")
		}
	default:
		return invalidRequest("persistent-change kind is unsupported")
	}
	return nil
}

func (f SourceFact) validate(now time.Time) error {
	if !validRef(f.TenantID) || !validRef(f.SiteID) || f.ObservedAt.IsZero() || f.ExpiresAt.IsZero() || !f.ExpiresAt.After(f.ObservedAt) || f.ObservedAt.After(now) {
		return invalidRequest("source fact binding or lifetime is invalid")
	}
	s := f.Summary
	if !validRef(s.SourceHandle) || !s.Kind.Valid() || s.Revision == 0 {
		return invalidRequest("source business summary identity is invalid")
	}
	if err := validateBusinessText("source alias", s.Alias, 160); err != nil {
		return err
	}
	if s.ZoneID != "" && !validRef(s.ZoneID) {
		return invalidRequest("source business summary zone is invalid")
	}
	if s.State != catalog.StateActive && s.State != catalog.StateDisabled && s.State != catalog.StateIdentityDrift {
		return invalidRequest("source business summary state is invalid")
	}
	if len(s.Capabilities) == 0 || len(s.Capabilities) > 32 {
		return invalidRequest("source business summary capabilities are invalid")
	}
	for index, capability := range s.Capabilities {
		if !validRef(capability.Ref) || !validCapabilityKind(capability.Kind) || len(capability.MediaKinds) == 0 || len(capability.MediaKinds) > 6 {
			return invalidRequest("source business capability is invalid")
		}
		if capability.ResultSchema != "" && !validRef(capability.ResultSchema) {
			return invalidRequest("source business capability result schema is invalid")
		}
		if index > 0 && s.Capabilities[index-1].Ref >= capability.Ref {
			return invalidRequest("source business capabilities are not canonical")
		}
		for mediaIndex, mediaKind := range capability.MediaKinds {
			if !mediaKind.Valid() || mediaIndex > 0 && capability.MediaKinds[mediaIndex-1] >= mediaKind {
				return invalidRequest("source business capability media kinds are not canonical")
			}
		}
	}
	return nil
}

func (f InstalledTaskFact) validate(now time.Time) error {
	if !validRef(f.TenantID) || !validRef(f.SiteID) || !validRef(f.TaskHandle) || !validRef(f.SourceHandle) ||
		f.SourceRevision == 0 || !validRef(f.CapabilityRef) || f.Revision == 0 ||
		f.ObservedAt.IsZero() || f.ExpiresAt.IsZero() || !f.ExpiresAt.After(f.ObservedAt) || f.ObservedAt.After(now) {
		return invalidRequest("installed task fact identity or lifetime is invalid")
	}
	if f.State != catalog.StateActive && f.State != catalog.StateDisabled && f.State != catalog.StateIdentityDrift {
		return invalidRequest("installed task fact state is invalid")
	}
	if len(f.ObservableCodes) == 0 || len(f.ObservableCodes) > 64 || !sortedUniqueRefs(f.ObservableCodes) {
		return invalidRequest("installed task observable codes are invalid")
	}
	if f.ResultSchema != "" && !validRef(f.ResultSchema) {
		return invalidRequest("installed task result schema is invalid")
	}
	return nil
}

func (a AuthorityAvailability) validate(now time.Time) error {
	if !a.Class.valid() || !validRef(a.TenantID) || !validRef(a.SiteID) || !digestPattern.MatchString(a.PrincipalSHA256) ||
		a.VerifiedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.VerifiedAt) || a.VerifiedAt.After(now) ||
		len(a.SourceHandles) > 128 || !sortedUniqueRefs(a.SourceHandles) {
		return invalidRequest("authority availability is invalid")
	}
	if (a.Class == AuthorityConnectionProfileWrite || a.Class == AuthorityPersistentDeviceWrite) && len(a.SourceHandles) != 0 {
		return invalidRequest("non-execution authority cannot carry source scope")
	}
	return nil
}

func (c AuthorityClass) valid() bool {
	switch c {
	case AuthorityConnectionProfileWrite, AuthorityDeviceRead, AuthorityInspectionExecution, AuthorityPersistentDeviceWrite, AuthorityServiceExecution:
		return true
	default:
		return false
	}
}

func validateTimeScope(scope temporary.TimeScope) error {
	switch scope.Kind {
	case temporary.TimeScopeCurrent:
		if scope.WindowSeconds != 0 {
			return invalidRequest("current inspection time scope must have a zero-second window")
		}
	case temporary.TimeScopeRecentWindow:
		if scope.WindowSeconds < 1 || scope.WindowSeconds > temporary.MaxRecentWindowSeconds {
			return invalidRequest("recent inspection time scope exceeds its bound")
		}
	default:
		return invalidRequest("inspection time scope is unsupported")
	}
	return nil
}

func validCapabilityKind(value catalog.CapabilityKind) bool {
	switch value {
	case catalog.CapabilitySnapshot, catalog.CapabilityClip, catalog.CapabilityTaskEvidence, catalog.CapabilityRetainedMedia, catalog.CapabilityUploadedMedia:
		return true
	default:
		return false
	}
}

func (r Resolution) Validate() error {
	if r.Schema != ResolutionSchemaVersion || !r.Route.valid() || !r.Reason.valid() {
		return ErrInvalidResolution
	}
	if !resolutionReasonCompatible(r.Route, r.Reason) {
		return ErrInvalidResolution
	}
	if !sortedUniqueRefs(r.SourceHandles) || !sortedUniqueRefs(r.TaskHandles) || !sortedUniqueRefs(r.CapabilityRefs) ||
		!sortedUniqueAuthorities(r.RequiredAuthorities) || !sortedUniqueAuthorities(r.MissingAuthorities) ||
		!authoritySubset(r.MissingAuthorities, r.RequiredAuthorities) {
		return ErrInvalidResolution
	}
	if r.TemporaryObservationSpec != nil {
		if err := r.TemporaryObservationSpec.Validate(); err != nil {
			return errors.Join(ErrInvalidResolution, err)
		}
	}

	switch r.Route {
	case RouteExistingTaskRead:
		if len(r.SourceHandles) != 1 || len(r.TaskHandles) != 1 || len(r.CapabilityRefs) != 1 ||
			!equalAuthorities(r.RequiredAuthorities, []AuthorityClass{AuthorityDeviceRead}) ||
			len(r.MissingAuthorities) != 0 || r.TemporaryObservationSpec != nil || r.ConnectionWorkflow != nil || r.PersistentChangeProposal != nil {
			return ErrInvalidResolution
		}
	case RouteSnapshotAnalysis, RouteClipAnalysis:
		if len(r.SourceHandles) != 1 || len(r.TaskHandles) != 0 || len(r.CapabilityRefs) != 1 ||
			!equalAuthorities(r.RequiredAuthorities, []AuthorityClass{AuthorityInspectionExecution}) ||
			len(r.MissingAuthorities) != 0 || r.ConnectionWorkflow != nil || r.PersistentChangeProposal != nil {
			return ErrInvalidResolution
		}
	case RouteHybridAnalysis:
		if len(r.SourceHandles) != 1 || len(r.TaskHandles) != 1 || len(r.CapabilityRefs) < 2 ||
			!equalAuthorities(r.RequiredAuthorities, []AuthorityClass{AuthorityDeviceRead, AuthorityInspectionExecution}) ||
			len(r.MissingAuthorities) != 0 || r.ConnectionWorkflow != nil || r.PersistentChangeProposal != nil {
			return ErrInvalidResolution
		}
	case RouteUnsupported, RouteClarificationRequired:
		if r.TemporaryObservationSpec != nil || r.ConnectionWorkflow != nil || r.PersistentChangeProposal != nil {
			return ErrInvalidResolution
		}
		if r.Route == RouteClarificationRequired && (len(r.RequiredAuthorities) != 0 || len(r.MissingAuthorities) != 0) {
			return ErrInvalidResolution
		}
		if r.Reason == ReasonAuthorityUnavailable && len(r.MissingAuthorities) == 0 {
			return ErrInvalidResolution
		}
	case RouteConnectionWorkflow:
		if len(r.SourceHandles) != 0 || len(r.TaskHandles) != 0 || len(r.CapabilityRefs) != 0 ||
			!equalAuthorities(r.RequiredAuthorities, []AuthorityClass{AuthorityConnectionProfileWrite}) ||
			r.TemporaryObservationSpec != nil || r.ConnectionWorkflow == nil || r.PersistentChangeProposal != nil ||
			r.ConnectionWorkflow.RequiredAuthority != AuthorityConnectionProfileWrite || !r.ConnectionWorkflow.RequiresSecureLocalInput {
			return ErrInvalidResolution
		}
	case RoutePersistentChangeProposal:
		if len(r.SourceHandles) != 0 || len(r.TaskHandles) != 0 || len(r.CapabilityRefs) != 0 ||
			!equalAuthorities(r.RequiredAuthorities, []AuthorityClass{AuthorityPersistentDeviceWrite}) ||
			r.TemporaryObservationSpec != nil || r.ConnectionWorkflow != nil || r.PersistentChangeProposal == nil ||
			r.PersistentChangeProposal.RequiredAuthority != AuthorityPersistentDeviceWrite ||
			!r.PersistentChangeProposal.RequiresConfirmation || !r.PersistentChangeProposal.HandoffOnly {
			return ErrInvalidResolution
		}
		proposal := r.PersistentChangeProposal
		if !validRef(proposal.ProposalID) || (PersistentChangeIntent{
			Kind: proposal.Kind, SourceHandle: proposal.SourceHandle, TaskHandle: proposal.TaskHandle,
			ObservableCode: proposal.ObservableCode, ExpectedSourceRevision: proposal.ExpectedSourceRevision,
			ExpectedTaskRevision: proposal.ExpectedTaskRevision,
		}).validate() != nil {
			return ErrInvalidResolution
		}
	}
	return nil
}

func resolutionReasonCompatible(route Route, reason ReasonCode) bool {
	switch route {
	case RouteExistingTaskRead:
		return reason == ReasonExistingTaskMatched
	case RouteSnapshotAnalysis:
		return reason == ReasonSnapshotCapabilityMatched
	case RouteClipAnalysis:
		return reason == ReasonClipCapabilityMatched
	case RouteHybridAnalysis:
		return reason == ReasonHybridCapabilitiesMatched
	case RouteUnsupported:
		return reason == ReasonCapabilityUnavailable || reason == ReasonAuthorityUnavailable ||
			reason == ReasonTaskObservableUnavailable || reason == ReasonUnsafeTemporaryIntent
	case RouteClarificationRequired:
		switch reason {
		case ReasonSourceAmbiguous, ReasonSourceNotFound, ReasonSourceStale, ReasonSourceRevisionChanged,
			ReasonSourceIdentityDrift, ReasonSourceDisabled, ReasonTaskAmbiguous, ReasonTaskNotFound,
			ReasonTaskStale, ReasonTaskSourceDrift, ReasonTaskIdentityDrift, ReasonTaskDisabled:
			return true
		default:
			return false
		}
	case RouteConnectionWorkflow:
		return reason == ReasonExplicitConnectionRequested || reason == ReasonSourceCatalogEmpty
	case RoutePersistentChangeProposal:
		return reason == ReasonPersistentChangeNeedsProposal
	default:
		return false
	}
}

func (r Route) valid() bool {
	switch r {
	case RouteExistingTaskRead, RouteSnapshotAnalysis, RouteClipAnalysis, RouteHybridAnalysis, RouteUnsupported,
		RouteClarificationRequired, RouteConnectionWorkflow, RoutePersistentChangeProposal:
		return true
	default:
		return false
	}
}

func (r ReasonCode) valid() bool {
	switch r {
	case ReasonExistingTaskMatched, ReasonSnapshotCapabilityMatched, ReasonClipCapabilityMatched,
		ReasonHybridCapabilitiesMatched, ReasonExplicitConnectionRequested, ReasonSourceCatalogEmpty,
		ReasonSourceAmbiguous, ReasonSourceNotFound, ReasonSourceStale, ReasonSourceRevisionChanged,
		ReasonSourceIdentityDrift, ReasonSourceDisabled, ReasonTaskAmbiguous, ReasonTaskNotFound,
		ReasonTaskStale, ReasonTaskSourceDrift, ReasonTaskIdentityDrift, ReasonTaskDisabled,
		ReasonTaskObservableUnavailable, ReasonCapabilityUnavailable, ReasonAuthorityUnavailable,
		ReasonUnsafeTemporaryIntent, ReasonPersistentChangeNeedsProposal:
		return true
	default:
		return false
	}
}

func validRef(value string) bool {
	return value == strings.TrimSpace(value) && refPattern.MatchString(value)
}

func validateBusinessText(name, value string, maximum int) error {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum || protectedPattern.MatchString(value) {
		return invalidRequest(name + " is invalid or contains protected material")
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return invalidRequest(name + " contains a control character")
		}
	}
	return nil
}

func sortedUniqueRefs(values []string) bool {
	for index, value := range values {
		if !validRef(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func sortedUniqueAuthorities(values []AuthorityClass) bool {
	for index, value := range values {
		if !value.valid() || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func authoritySubset(subset, set []AuthorityClass) bool {
	available := make(map[AuthorityClass]struct{}, len(set))
	for _, value := range set {
		available[value] = struct{}{}
	}
	for _, value := range subset {
		if _, ok := available[value]; !ok {
			return false
		}
	}
	return true
}

func equalAuthorities(left, right []AuthorityClass) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func normalizeRefs(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeAuthorities(values ...AuthorityClass) []AuthorityClass {
	seen := make(map[AuthorityClass]struct{}, len(values))
	result := make([]AuthorityClass, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func containsMedia(values []inspection.MediaKind, expected inspection.MediaKind) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func invalidRequest(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, message)
}
