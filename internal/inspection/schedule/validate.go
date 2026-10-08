package schedule

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

var (
	refPattern                   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	executionAuthorityRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

const frozenReferenceRequestID = "frozen-schedule-plan"

// FreezeRunSpec closes all mutable catalog inputs into one canonical snapshot.
// The request contributes target selection, normalized variables and TTL; its
// dynamic identity and times are deliberately replaced by a stable reference.
func FreezeRunSpec(template inspection.InspectionTemplate, assignment inspection.Assignment, request inspection.CreateRunRequest) (FrozenRunSpec, error) {
	if template.Validate() != nil || template.State != inspection.TemplatePublished || assignment.Validate() != nil || !assignment.Published || request.Validate() != nil {
		return FrozenRunSpec{}, errors.New("inspection frozen run input is invalid")
	}
	if request.Origin != inspection.OriginSchedule {
		return FrozenRunSpec{}, errors.New("inspection frozen run input requires schedule origin")
	}
	ttl := request.Deadline.Sub(request.RequestedAt)
	if ttl <= 0 || ttl%time.Second != 0 || ttl > 7*24*time.Hour {
		return FrozenRunSpec{}, errors.New("inspection frozen run TTL is invalid")
	}
	targetIDs := append([]string(nil), request.TargetIDs...)
	sort.Strings(targetIDs)
	if duplicateStrings(targetIDs) {
		return FrozenRunSpec{}, errors.New("inspection frozen target selection is not canonical")
	}
	variables := make([]VariableBinding, 0, len(request.Variables))
	for name, value := range request.Variables {
		variables = append(variables, VariableBinding{Name: name, Value: value})
	}
	sort.Slice(variables, func(i, j int) bool { return variables[i].Name < variables[j].Name })
	reference := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: request.TenantID, SiteID: request.SiteID,
		TemplateID: request.TemplateID, TemplateRevision: request.TemplateRevision,
		AssignmentID: request.AssignmentID, AssignmentRevision: request.AssignmentRevision,
		Origin: inspection.OriginSchedule, RequestID: frozenReferenceRequestID,
		TargetIDs: append([]string(nil), targetIDs...), Variables: variablesMap(variables),
		RequestedAt: time.Unix(0, 0).UTC(), Deadline: time.Unix(0, 0).UTC().Add(ttl),
	}
	plan, err := inspection.CompilePlan(template, assignment, reference)
	if err != nil {
		return FrozenRunSpec{}, fmt.Errorf("compile frozen inspection pipeline: %w", err)
	}
	requiredOperations := requiredOperationsForSteps(plan.Steps)
	selected, err := selectedAssignmentTargets(assignment, targetIDs)
	if err != nil {
		return FrozenRunSpec{}, err
	}
	if len(targetIDs) == 0 {
		targetIDs = make([]string, len(selected))
		for index := range selected {
			targetIDs[index] = selected[index].TargetID
		}
	}
	sources := sourceHandlesForTargets(selected)
	strategies, err := selectedStrategies(template, selected)
	if err != nil {
		return FrozenRunSpec{}, err
	}

	spec := FrozenRunSpec{
		Schema: FrozenRunSpecSchema, TenantID: request.TenantID, SiteID: request.SiteID,
		Template: cloneTemplate(template), Assignment: cloneAssignment(assignment),
		SelectedTargetIDs: targetIDs, SelectedTargets: cloneTargetBindings(selected),
		SourceHandles: sources, Strategies: cloneStrategies(strategies),
		Pipeline:  FrozenPipeline{Targets: clonePlannedTargets(plan.Targets), Steps: cloneExecutionSteps(plan.Steps)},
		Variables: variables, RunTTLSeconds: int(ttl / time.Second), ResourceCeiling: template.Budget,
		RetentionPolicy: template.Evidence, RequiredOperations: append([]string(nil), requiredOperations...),
	}
	if spec.TemplateSHA256, err = canonicalDigest(spec.Template); err != nil {
		return FrozenRunSpec{}, err
	}
	if spec.AssignmentSHA256, err = canonicalDigest(spec.Assignment); err != nil {
		return FrozenRunSpec{}, err
	}
	if spec.StrategySHA256, err = canonicalDigest(spec.Strategies); err != nil {
		return FrozenRunSpec{}, err
	}
	if spec.Pipeline.SHA256, err = pipelineDigest(spec.Pipeline); err != nil {
		return FrozenRunSpec{}, err
	}
	if spec.VariablesSHA256, err = canonicalDigest(spec.Variables); err != nil {
		return FrozenRunSpec{}, err
	}
	if spec.ResultContractSHA256, err = resultContractDigest(template); err != nil {
		return FrozenRunSpec{}, err
	}
	if spec.SHA256, err = frozenRunSpecDigest(spec); err != nil {
		return FrozenRunSpec{}, err
	}
	if err := spec.Validate(); err != nil {
		return FrozenRunSpec{}, err
	}
	return spec, nil
}

func NewDeliveryBinding(bindingRef string, revision uint64, audienceSHA256, principalSHA256 string) (DeliveryBinding, error) {
	value := DeliveryBinding{Schema: DeliveryBindingSchema, BindingRef: bindingRef, Revision: revision, AudienceSHA256: audienceSHA256, PrincipalSHA256: principalSHA256}
	digest, err := deliveryBindingDigest(value)
	if err != nil {
		return DeliveryBinding{}, err
	}
	value.SHA256 = digest
	if err := value.Validate(); err != nil {
		return DeliveryBinding{}, err
	}
	return value, nil
}

func (s FrozenRunSpec) Validate() error {
	if s.Schema != FrozenRunSpecSchema || !validExecutionAuthorityRef(s.TenantID) || !validExecutionAuthorityRef(s.SiteID) ||
		s.Template.Validate() != nil || s.Template.State != inspection.TemplatePublished || s.Assignment.Validate() != nil || !s.Assignment.Published {
		return errors.New("inspection frozen run spec identity is invalid")
	}
	if s.Template.TenantID != s.TenantID || s.Assignment.TenantID != s.TenantID || s.Assignment.SiteID != s.SiteID ||
		s.Assignment.TemplateID != s.Template.TemplateID || s.Assignment.TemplateRevision != s.Template.Revision {
		return errors.New("inspection frozen run spec bindings do not match")
	}
	if s.RunTTLSeconds < 1 || s.RunTTLSeconds > 7*24*60*60 || s.ResourceCeiling != s.Template.Budget ||
		!sortedUniqueOperations(s.RequiredOperations) || !sortedUniqueExecutionAuthorityRefs(s.SourceHandles) ||
		!validSHA256(s.TemplateSHA256) || !validSHA256(s.AssignmentSHA256) || !validSHA256(s.StrategySHA256) ||
		!validSHA256(s.Pipeline.SHA256) || !validSHA256(s.VariablesSHA256) || !validSHA256(s.ResultContractSHA256) || !validSHA256(s.SHA256) {
		return errors.New("inspection frozen run spec bounds or digests are invalid")
	}
	if len(s.SelectedTargetIDs) > 100 || duplicateStrings(s.SelectedTargetIDs) || !sort.StringsAreSorted(s.SelectedTargetIDs) ||
		len(s.Variables) > 256 || !sortedVariables(s.Variables) {
		return errors.New("inspection frozen run spec canonical collections are invalid")
	}
	selected, err := selectedAssignmentTargets(s.Assignment, s.SelectedTargetIDs)
	if err != nil || !canonicalEqual(selected, s.SelectedTargets) || !equalStrings(sourceHandlesForTargets(selected), s.SourceHandles) {
		return errors.New("inspection frozen target snapshot is invalid")
	}
	strategies, err := selectedStrategies(s.Template, selected)
	if err != nil || !canonicalEqual(strategies, s.Strategies) {
		return errors.New("inspection frozen strategy snapshot is invalid")
	}
	checks := []struct {
		got   string
		value any
	}{
		{s.TemplateSHA256, s.Template}, {s.AssignmentSHA256, s.Assignment}, {s.StrategySHA256, s.Strategies}, {s.VariablesSHA256, s.Variables},
	}
	for _, check := range checks {
		digest, digestErr := canonicalDigest(check.value)
		if digestErr != nil || digest != check.got {
			return errors.New("inspection frozen run spec digest mismatch")
		}
	}
	resultDigest, err := resultContractDigest(s.Template)
	if err != nil || resultDigest != s.ResultContractSHA256 || s.RetentionPolicy != s.Template.Evidence {
		return errors.New("inspection frozen result or retention contract is invalid")
	}
	reference := s.referenceRequest()
	plan, err := inspection.CompilePlan(s.Template, s.Assignment, reference)
	if err != nil || !canonicalEqual(plan.Targets, s.Pipeline.Targets) || !canonicalEqual(plan.Steps, s.Pipeline.Steps) {
		return errors.New("inspection frozen typed pipeline is invalid")
	}
	if !equalStrings(requiredOperationsForSteps(plan.Steps), s.RequiredOperations) {
		return errors.New("inspection frozen authority operations do not exactly match its typed pipeline")
	}
	pipelineSHA, err := pipelineDigest(s.Pipeline)
	if err != nil || pipelineSHA != s.Pipeline.SHA256 {
		return errors.New("inspection frozen pipeline digest mismatch")
	}
	self, err := frozenRunSpecDigest(s)
	if err != nil || self != s.SHA256 {
		return errors.New("inspection frozen run spec self digest mismatch")
	}
	return nil
}

func (s FrozenRunSpec) referenceRequest() inspection.CreateRunRequest {
	return inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: s.TenantID, SiteID: s.SiteID,
		TemplateID: s.Template.TemplateID, TemplateRevision: s.Template.Revision,
		AssignmentID: s.Assignment.AssignmentID, AssignmentRevision: s.Assignment.Revision,
		Origin: inspection.OriginSchedule, RequestID: frozenReferenceRequestID,
		TargetIDs: append([]string(nil), s.SelectedTargetIDs...), Variables: variablesMap(s.Variables),
		RequestedAt: time.Unix(0, 0).UTC(), Deadline: time.Unix(0, 0).UTC().Add(time.Duration(s.RunTTLSeconds) * time.Second),
	}
}

func (d DeliveryBinding) Validate() error {
	if d.Schema != DeliveryBindingSchema || validateRef("delivery binding", d.BindingRef) != nil || d.Revision == 0 ||
		!validSHA256(d.AudienceSHA256) || !validSHA256(d.PrincipalSHA256) || !validSHA256(d.SHA256) {
		return errors.New("inspection delivery binding is invalid")
	}
	digest, err := deliveryBindingDigest(d)
	if err != nil || digest != d.SHA256 {
		return errors.New("inspection delivery binding digest mismatch")
	}
	return nil
}

func (s Schedule) Validate() error { return s.ValidateWithZones(SystemZoneLoader{}) }

func (s Schedule) ValidateWithZones(zones ZoneLoader) error {
	if err := s.validateCore(zones); err != nil {
		return err
	}
	hasGrant := s.ServiceGrant.GrantID != "" || s.ServiceGrant.ProofSHA256 != "" || s.ScheduleScopeSHA256 != "" || s.AuthoritySHA256 != "" || s.AuthorizedAt != nil
	if hasGrant {
		if s.ServiceGrant.Validate() != nil || s.ServiceGrant.Class != authority.ServiceExecution || !validSHA256(s.ScheduleScopeSHA256) ||
			!validSHA256(s.AuthoritySHA256) || s.AuthorizedAt == nil || !s.ServiceGrant.ExpiresAt.After(s.ValidFrom) || !s.ValidUntil.After(s.ServiceGrant.IssuedAt) ||
			!s.AuthorizedAt.Before(s.ServiceGrant.ExpiresAt) || !s.AuthorizedAt.Before(s.ValidUntil) {
			return errors.New("inspection schedule grant validity is incomplete")
		}
		scope := scopeForUnchecked(s)
		digest, err := scopeDigest(scope)
		if err != nil || digest != s.ScheduleScopeSHA256 || validateGrantExactScope(s.ServiceGrant, scope) != nil {
			return errors.New("inspection schedule changed outside its authorized scope")
		}
		authorityDigest, err := grantDigest(s.ServiceGrant)
		if err != nil || authorityDigest != s.AuthoritySHA256 {
			return errors.New("inspection schedule authority digest is invalid")
		}
	}
	switch s.State {
	case StateDraft, StateAwaitingAuthorization:
		if hasGrant {
			return errors.New("unauthorized inspection schedule cannot retain a grant")
		}
	case StateActive:
		if !hasGrant || s.RevokedAt != nil || s.ExpiredAt != nil {
			return errors.New("active inspection schedule requires exact authority")
		}
	case StatePaused:
		if !hasGrant || s.PausedAt == nil || s.RevokedAt != nil || s.ExpiredAt != nil {
			return errors.New("paused inspection schedule is invalid")
		}
	case StateRevoked:
		if s.RevokedAt == nil || s.ExpiredAt != nil {
			return errors.New("revoked inspection schedule is invalid")
		}
	case StateExpired:
		if s.ExpiredAt == nil || s.RevokedAt != nil {
			return errors.New("expired inspection schedule is invalid")
		}
	default:
		return errors.New("inspection schedule state is invalid")
	}
	return nil
}

func (s Schedule) validateCore(zones ZoneLoader) error {
	if s.Schema != SchemaVersion || !validExecutionAuthorityRef(s.TenantID) || !validExecutionAuthorityRef(s.SiteID) ||
		!validExecutionAuthorityRef(s.ScheduleID) || s.Revision == 0 || s.Origin != inspection.OriginSchedule ||
		s.RunSpec.Validate() != nil || s.RunSpec.TenantID != s.TenantID || s.RunSpec.SiteID != s.SiteID ||
		s.RunSpecSHA256 != s.RunSpec.SHA256 || s.Delivery.Validate() != nil || s.DeliverySHA256 != s.Delivery.SHA256 ||
		!validSHA256(s.ServicePrincipalSHA256) {
		return errors.New("inspection schedule frozen scope is invalid")
	}
	if zones == nil || strings.TrimSpace(s.Timezone) != s.Timezone || s.Timezone == "" {
		return errors.New("inspection schedule timezone is invalid")
	}
	if _, err := zones.LoadLocation(s.Timezone); err != nil {
		return fmt.Errorf("load inspection schedule timezone: %w", err)
	}
	if _, _, err := parseLocalTime(s.LocalTime); err != nil {
		return err
	}
	if len(s.Weekdays) == 0 || len(s.Weekdays) > 7 {
		return errors.New("inspection schedule weekdays are invalid")
	}
	seen := map[Weekday]struct{}{}
	for _, weekday := range s.Weekdays {
		if _, ok := weekdayTimeValue(weekday); !ok {
			return fmt.Errorf("inspection schedule weekday %q is invalid", weekday)
		}
		if _, ok := seen[weekday]; ok {
			return fmt.Errorf("inspection schedule weekday %q is duplicated", weekday)
		}
		seen[weekday] = struct{}{}
	}
	if s.ValidFrom.IsZero() || s.ValidUntil.IsZero() || !s.ValidUntil.After(s.ValidFrom) || s.JitterPolicySeconds < 0 || s.JitterPolicySeconds > 6*60*60 ||
		(s.Misfire != MisfireSkip && s.Misfire != MisfireCatchUpOnce) || s.MisfireGraceSeconds < 1 || s.MisfireGraceSeconds > 24*60*60 ||
		s.Concurrency.MaxInFlight < 1 || s.Concurrency.MaxInFlight > 100 ||
		(s.Concurrency.OnLimit != ConcurrencyQueue && s.Concurrency.OnLimit != ConcurrencySkip) {
		return errors.New("inspection schedule timing or concurrency is invalid")
	}
	if s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) {
		return errors.New("inspection schedule lifecycle timestamps are invalid")
	}
	for name, value := range map[string]*time.Time{"authorization": s.AuthorizedAt, "pause": s.PausedAt, "revocation": s.RevokedAt, "expiry": s.ExpiredAt} {
		if value != nil && (value.IsZero() || value.Before(s.CreatedAt)) {
			return fmt.Errorf("inspection schedule %s timestamp is invalid", name)
		}
	}
	return nil
}

func (o Occurrence) Validate() error { return o.ValidateWithZones(SystemZoneLoader{}) }

func (o Occurrence) ValidateWithZones(zones ZoneLoader) error {
	if o.Schema != OccurrenceSchemaVersion || validateRef("occurrence", o.OccurrenceID) != nil || validateRef("idempotency", o.IdempotencyKey) != nil ||
		validateRef("operation", o.OperationRef) != nil || validateRef("request", o.RequestID) != nil || validateRef("request key", o.RequestKey) != nil ||
		validateRef("tenant", o.TenantID) != nil || validateRef("site", o.SiteID) != nil || validateRef("schedule", o.ScheduleID) != nil || o.ScheduleRevision == 0 ||
		o.Origin != inspection.OriginSchedule || o.RunSpec.Validate() != nil || o.RunSpecSHA256 != o.RunSpec.SHA256 || o.Delivery.Validate() != nil ||
		o.DeliverySHA256 != o.Delivery.SHA256 || !validSHA256(o.ServicePrincipalSHA256) || !validSHA256(o.ScheduleScopeSHA256) ||
		!validSHA256(o.AuthoritySHA256) || !validSHA256(o.RequestSHA256) || !validSHA256(o.PlanSHA256) || !validSHA256(o.SHA256) {
		return errors.New("inspection occurrence identity or frozen scope is invalid")
	}
	if o.RunSpec.TenantID != o.TenantID || o.RunSpec.SiteID != o.SiteID || o.Concurrency.MaxInFlight < 1 || o.Concurrency.MaxInFlight > 100 ||
		(o.Concurrency.OnLimit != ConcurrencyQueue && o.Concurrency.OnLimit != ConcurrencySkip) {
		return errors.New("inspection occurrence binding is invalid")
	}
	scopeSHA, err := scopeDigest(o.AuthorityScope)
	if err != nil || scopeSHA != o.ScheduleScopeSHA256 || validateScope(o.AuthorityScope) != nil ||
		o.AuthorityScope.TenantID != o.TenantID || o.AuthorityScope.SiteID != o.SiteID || o.AuthorityScope.ScheduleID != o.ScheduleID ||
		o.AuthorityScope.ScheduleRevision != o.ScheduleRevision || o.AuthorityScope.RunSpecSHA256 != o.RunSpecSHA256 ||
		o.AuthorityScope.DeliverySHA256 != o.DeliverySHA256 || o.AuthorityScope.ServicePrincipalSHA256 != o.ServicePrincipalSHA256 ||
		o.AuthorityScope.Origin != o.Origin || !equalStrings(o.AuthorityScope.SourceHandles, o.RunSpec.SourceHandles) ||
		o.AuthorityScope.ResourceCeiling != o.RunSpec.ResourceCeiling || !equalStrings(o.AuthorityScope.RequiredOperations, o.RunSpec.RequiredOperations) ||
		o.AuthorityScope.Timezone != o.Timezone || o.AuthorityScope.LocalTime != o.LocalTime || o.AuthorityScope.JitterPolicySeconds != o.JitterPolicySeconds ||
		o.AuthorityScope.Misfire != o.Misfire || o.AuthorityScope.MisfireGraceSeconds != o.MisfireGraceSeconds || o.AuthorityScope.Concurrency != o.Concurrency ||
		o.ScheduledAt.Before(o.AuthorityScope.ValidFrom) || !o.Deadline.Before(o.AuthorityScope.ValidUntil) {
		return errors.New("inspection occurrence authority scope is invalid")
	}
	if o.Misfire != MisfireSkip && o.Misfire != MisfireCatchUpOnce || o.MisfireGraceSeconds < 1 || o.MisfireGraceSeconds > 24*60*60 ||
		o.JitterPolicySeconds < 0 || o.JitterPolicySeconds > 6*60*60 || o.JitterOffsetSeconds < 0 || o.JitterOffsetSeconds > o.JitterPolicySeconds {
		return errors.New("inspection occurrence timing policy is invalid")
	}
	if o.ScheduledAt.IsZero() || o.DueAt.IsZero() || o.Deadline.IsZero() || o.GeneratedAt.IsZero() || o.DueAt.Before(o.ScheduledAt) ||
		!o.Deadline.Equal(o.DueAt.Add(time.Duration(o.RunSpec.RunTTLSeconds)*time.Second)) || o.GeneratedAt.Before(o.DueAt) ||
		o.DueAt.Sub(o.ScheduledAt) != time.Duration(o.JitterOffsetSeconds)*time.Second ||
		o.Misfired != (o.GeneratedAt.Sub(o.DueAt) > time.Duration(o.MisfireGraceSeconds)*time.Second) {
		return errors.New("inspection occurrence timestamps are invalid")
	}
	digest := occurrenceDigest(o.TenantID, o.SiteID, o.ScheduleID, o.ScheduleRevision, o.ScheduledAt)
	if o.OccurrenceID != "occ_"+digest || o.IdempotencyKey != "occurrence_"+digest || o.OperationRef != "submit_"+digest ||
		o.RequestID != o.OccurrenceID || o.RequestKey != inspection.RequestKey(o.TenantID, inspection.OriginSchedule, o.RequestID) {
		return errors.New("inspection occurrence stable identity is invalid")
	}
	if zones == nil || strings.TrimSpace(o.Timezone) != o.Timezone || o.Timezone == "" {
		return errors.New("inspection occurrence timezone is invalid")
	}
	location, err := zones.LoadLocation(o.Timezone)
	if err != nil {
		return fmt.Errorf("load inspection occurrence timezone: %w", err)
	}
	hour, minute, err := parseLocalTime(o.LocalTime)
	if err != nil {
		return err
	}
	local := o.ScheduledAt.In(location)
	date := civilDateFrom(local)
	resolved, ok := resolveLocalOnce(location, date, hour, minute)
	if !ok || o.LocalDate != date.String() || !resolved.Equal(o.ScheduledAt.UTC()) {
		return errors.New("inspection occurrence civil-time binding is invalid")
	}
	request := o.CreateRunRequest()
	requestSHA, err := canonicalDigest(request)
	if err != nil || requestSHA != o.RequestSHA256 {
		return errors.New("inspection occurrence request digest mismatch")
	}
	plan, err := inspection.CompilePlan(o.RunSpec.Template, o.RunSpec.Assignment, request)
	if err != nil || plan.PlanSHA256 != o.PlanSHA256 {
		return errors.New("inspection occurrence plan digest mismatch")
	}
	if pipelineSHAForPlan(plan) != o.RunSpec.Pipeline.SHA256 {
		return errors.New("inspection occurrence pipeline drifted from frozen semantics")
	}
	self, err := occurrenceSelfDigest(o)
	if err != nil || self != o.SHA256 {
		return errors.New("inspection occurrence self digest mismatch")
	}
	return nil
}

func (o Occurrence) CreateRunRequest() inspection.CreateRunRequest {
	return inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: o.TenantID, SiteID: o.SiteID,
		TemplateID: o.RunSpec.Template.TemplateID, TemplateRevision: o.RunSpec.Template.Revision,
		AssignmentID: o.RunSpec.Assignment.AssignmentID, AssignmentRevision: o.RunSpec.Assignment.Revision,
		Origin: inspection.OriginSchedule, RequestID: o.RequestID,
		TargetIDs: append([]string(nil), o.RunSpec.SelectedTargetIDs...), Variables: variablesMap(o.RunSpec.Variables),
		RequestedAt: o.DueAt.UTC(), Deadline: o.Deadline.UTC(),
	}
}

// ValidateSubmissionGrant rechecks the complete immutable grant binding at
// the adapter boundary, including its signature. This prevents an adapter
// from accepting a valid grant for a different schedule, principal, scope or
// lifetime even if a coordinator check is accidentally bypassed.
func (o Occurrence) ValidateSubmissionGrant(grant authority.Grant, verifier GrantVerifier, at time.Time) error {
	if o.Validate() != nil || grant.Validate() != nil || verifier == nil || at.IsZero() || grant.Class != authority.ServiceExecution ||
		grant.PrincipalSHA256 != o.ServicePrincipalSHA256 || at.UTC().Before(grant.IssuedAt) || !at.UTC().Before(grant.ExpiresAt) ||
		!o.Deadline.Before(grant.ExpiresAt) {
		return errors.New("inspection occurrence submission grant is invalid")
	}
	digest, err := grantDigest(grant)
	if err != nil || digest != o.AuthoritySHA256 || validateGrantExactScope(grant, o.AuthorityScope) != nil ||
		verifyServiceGrant(verifier, grant, o.AuthorityScope, at.UTC()) != nil {
		return errors.New("inspection occurrence submission grant does not match its frozen scope")
	}
	return nil
}

func ScopeFor(s Schedule) (AuthorizationScope, string, error) {
	return ScopeForWithZones(s, SystemZoneLoader{})
}

func ScopeForWithZones(s Schedule, zones ZoneLoader) (AuthorizationScope, string, error) {
	if err := s.validateCore(zones); err != nil {
		return AuthorizationScope{}, "", err
	}
	scope := scopeForUnchecked(s)
	digest, err := scopeDigest(scope)
	return scope, digest, err
}

func scopeForUnchecked(s Schedule) AuthorizationScope {
	weekdays := append([]Weekday(nil), s.Weekdays...)
	sort.Slice(weekdays, func(i, j int) bool {
		left, _ := weekdayTimeValue(weekdays[i])
		right, _ := weekdayTimeValue(weekdays[j])
		return left < right
	})
	return AuthorizationScope{
		Schema: SchemaVersion, TenantID: s.TenantID, SiteID: s.SiteID, ScheduleID: s.ScheduleID, ScheduleRevision: s.Revision,
		Origin: s.Origin, RunSpecSHA256: s.RunSpecSHA256, DeliverySHA256: s.DeliverySHA256,
		SourceHandles: append([]string(nil), s.RunSpec.SourceHandles...), ResourceCeiling: s.RunSpec.ResourceCeiling,
		ServicePrincipalSHA256: s.ServicePrincipalSHA256, RequiredOperations: append([]string(nil), s.RunSpec.RequiredOperations...),
		Timezone: s.Timezone, Weekdays: weekdays, LocalTime: s.LocalTime, ValidFrom: s.ValidFrom.UTC(), ValidUntil: s.ValidUntil.UTC(),
		JitterPolicySeconds: s.JitterPolicySeconds, Misfire: s.Misfire, MisfireGraceSeconds: s.MisfireGraceSeconds, Concurrency: s.Concurrency,
	}
}

func scopeDigest(scope AuthorizationScope) (string, error) { return canonicalDigest(scope) }

func parseLocalTime(value string) (int, int, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, 0, errors.New("inspection schedule local time must use HH:MM")
	}
	hour, errHour := strconv.Atoi(value[:2])
	minute, errMinute := strconv.Atoi(value[3:])
	if errHour != nil || errMinute != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, errors.New("inspection schedule local time is invalid")
	}
	return hour, minute, nil
}

func weekdayTimeValue(value Weekday) (time.Weekday, bool) {
	switch value {
	case Sunday:
		return time.Sunday, true
	case Monday:
		return time.Monday, true
	case Tuesday:
		return time.Tuesday, true
	case Wednesday:
		return time.Wednesday, true
	case Thursday:
		return time.Thursday, true
	case Friday:
		return time.Friday, true
	case Saturday:
		return time.Saturday, true
	default:
		return 0, false
	}
}

func containsWeekday(values []Weekday, target time.Weekday) bool {
	for _, value := range values {
		weekday, ok := weekdayTimeValue(value)
		if ok && weekday == target {
			return true
		}
	}
	return false
}
func validateRef(name, value string) error {
	if !refPattern.MatchString(value) {
		return fmt.Errorf("inspection schedule %s reference is invalid", name)
	}
	return nil
}
func validExecutionAuthorityRef(value string) bool {
	return executionAuthorityRefPattern.MatchString(value)
}
func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func canonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
func canonicalEqual(left, right any) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

type frozenRunSpecStorage FrozenRunSpec

func frozenRunSpecDigest(value FrozenRunSpec) (string, error) {
	value.SHA256 = ""
	return canonicalDigest(frozenRunSpecStorage(value))
}
func deliveryBindingDigest(value DeliveryBinding) (string, error) {
	value.SHA256 = ""
	return canonicalDigest(value)
}
func pipelineDigest(value FrozenPipeline) (string, error) {
	value.SHA256 = ""
	return canonicalDigest(value)
}

func resultContractDigest(template inspection.InspectionTemplate) (string, error) {
	type criterionOutput struct {
		ID     string                    `json:"id"`
		Output inspection.OutputContract `json:"output"`
	}
	value := struct {
		Schema  string            `json:"schema"`
		Outputs []criterionOutput `json:"outputs"`
	}{Schema: template.OutputSchemaVersion}
	for _, criterion := range template.Criteria {
		value.Outputs = append(value.Outputs, criterionOutput{ID: criterion.ID, Output: criterion.Output})
	}
	return canonicalDigest(value)
}

func pipelineSHAForPlan(plan inspection.ExecutionPlan) string {
	pipeline := FrozenPipeline{Targets: clonePlannedTargets(plan.Targets), Steps: cloneExecutionSteps(plan.Steps)}
	for index := range pipeline.Steps {
		pipeline.Steps[index].Deadline = time.Unix(0, 0).UTC().Add(plan.Deadline.Sub(plan.RequestedAt))
	}
	digest, _ := pipelineDigest(pipeline)
	return digest
}

func occurrenceSelfDigest(value Occurrence) (string, error) {
	value.SHA256 = ""
	raw, err := marshalOccurrenceStorage(value)
	if err != nil {
		return "", err
	}
	return bytesDigest(raw), nil
}

func variablesMap(values []VariableBinding) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value.Name] = value.Value
	}
	return result
}
func sortedVariables(values []VariableBinding) bool {
	for i, value := range values {
		if strings.TrimSpace(value.Name) != value.Name || value.Name == "" || i > 0 && values[i-1].Name >= value.Name {
			return false
		}
	}
	return true
}
func duplicateStrings(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] == values[i] {
			return true
		}
	}
	return false
}

func selectedAssignmentTargets(assignment inspection.Assignment, requested []string) ([]inspection.TargetBinding, error) {
	selectAll := len(requested) == 0
	wanted := map[string]struct{}{}
	for _, id := range requested {
		wanted[id] = struct{}{}
	}
	result := make([]inspection.TargetBinding, 0, len(assignment.Targets))
	for _, target := range assignment.Targets {
		if selectAll {
			result = append(result, target)
			continue
		}
		if _, ok := wanted[target.TargetID]; ok {
			result = append(result, target)
			delete(wanted, target.TargetID)
		}
	}
	if !selectAll && len(wanted) != 0 {
		return nil, errors.New("inspection frozen target is unavailable")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TargetID < result[j].TargetID })
	return cloneTargetBindings(result), nil
}

func selectedStrategies(template inspection.InspectionTemplate, targets []inspection.TargetBinding) ([]inspection.StrategyPolicy, error) {
	wanted := map[inspection.ExecutionStrategy]struct{}{}
	for _, target := range targets {
		wanted[target.Strategy] = struct{}{}
	}
	result := make([]inspection.StrategyPolicy, 0, len(wanted))
	for _, strategy := range template.Strategies {
		if _, ok := wanted[strategy.Strategy]; ok {
			result = append(result, strategy)
			delete(wanted, strategy.Strategy)
		}
	}
	if len(wanted) != 0 {
		return nil, errors.New("inspection frozen strategy is unavailable")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Strategy < result[j].Strategy })
	return cloneStrategies(result), nil
}

func sourceHandlesForTargets(targets []inspection.TargetBinding) []string {
	set := map[string]struct{}{}
	for _, target := range targets {
		for _, source := range target.SourceBindings {
			set[source.SourceHandle] = struct{}{}
		}
		for _, task := range target.InstalledTasks {
			for _, source := range task.Sources {
				set[source.SourceHandle] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func requiredOperationsForSteps(steps []inspection.ExecutionStep) []string {
	set := map[string]struct{}{authority.OpOccurrenceExecute: {}, authority.OpDeliver: {}}
	for _, step := range steps {
		switch step.Kind {
		case inspection.StepReadExisting:
			set[authority.OpReadExistingEvidence] = struct{}{}
		case inspection.StepAcquireMedia, inspection.StepOpenMedia:
			set[authority.OpSourceAcquire] = struct{}{}
		case inspection.StepTransformMedia:
			set[authority.OpMediaExtract] = struct{}{}
		case inspection.StepAnalyze:
			set[authority.OpAnalyze] = struct{}{}
		case inspection.StepCleanup:
			set[authority.OpCleanup] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for operation := range set {
		result = append(result, operation)
	}
	sort.Strings(result)
	return result
}

func cloneTemplate(value inspection.InspectionTemplate) inspection.InspectionTemplate {
	raw, _ := json.Marshal(value)
	var cloned inspection.InspectionTemplate
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}
func cloneAssignment(value inspection.Assignment) inspection.Assignment {
	raw, _ := json.Marshal(value)
	var cloned inspection.Assignment
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}
func cloneTargetBindings(value []inspection.TargetBinding) []inspection.TargetBinding {
	raw, _ := json.Marshal(value)
	var cloned []inspection.TargetBinding
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}
func cloneStrategies(value []inspection.StrategyPolicy) []inspection.StrategyPolicy {
	raw, _ := json.Marshal(value)
	var cloned []inspection.StrategyPolicy
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}
func clonePlannedTargets(value []inspection.PlannedTarget) []inspection.PlannedTarget {
	raw, _ := json.Marshal(value)
	var cloned []inspection.PlannedTarget
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}
func cloneExecutionSteps(value []inspection.ExecutionStep) []inspection.ExecutionStep {
	raw, _ := json.Marshal(value)
	var cloned []inspection.ExecutionStep
	_ = json.Unmarshal(raw, &cloned)
	return cloned
}

func cloneFrozenRunSpec(value FrozenRunSpec) FrozenRunSpec {
	raw, _ := json.Marshal(frozenRunSpecStorage(value))
	var cloned frozenRunSpecStorage
	_ = json.Unmarshal(raw, &cloned)
	return FrozenRunSpec(cloned)
}
func cloneSchedule(value Schedule) Schedule {
	value.RunSpec = cloneFrozenRunSpec(value.RunSpec)
	value.Weekdays = append([]Weekday(nil), value.Weekdays...)
	value.ServiceGrant.Scope.SourceHandles = append([]string(nil), value.ServiceGrant.Scope.SourceHandles...)
	value.ServiceGrant.Scope.OperationKinds = append([]string(nil), value.ServiceGrant.Scope.OperationKinds...)
	return value
}
