package schedule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

type GrantVerifier interface {
	Verify(authority.Grant, authority.Demand, time.Time) error
}

// AwaitAuthorization moves a draft or paused schedule to an ungranted state.
// Editing schedule scope must happen by creating a new draft revision first.
func AwaitAuthorization(s Schedule, at time.Time) (Schedule, error) {
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	if s.State != StateDraft && s.State != StatePaused {
		return Schedule{}, errors.New("inspection schedule cannot await authorization from its current state")
	}
	if err := validateTransitionTime(s, at); err != nil {
		return Schedule{}, err
	}
	if !at.Before(s.ValidUntil) {
		return Schedule{}, errors.New("inspection schedule validity ended before authorization request")
	}

	s.State = StateAwaitingAuthorization
	s.UpdatedAt = at.UTC()
	s.ScheduleScopeSHA256 = ""
	s.AuthoritySHA256 = ""
	s.ServiceGrant = authority.Grant{}
	s.AuthorizedAt = nil
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	return s, nil
}

// Activate binds one cryptographically verified ServiceExecution grant. The
// schedule package cannot mint service authority and does not accept an
// unsigned local grant shape.
func Activate(s Schedule, grant authority.Grant, verifier GrantVerifier, at time.Time) (Schedule, error) {
	return ActivateWithZones(s, grant, verifier, at, SystemZoneLoader{})
}

func ActivateWithZones(s Schedule, grant authority.Grant, verifier GrantVerifier, at time.Time, zones ZoneLoader) (Schedule, error) {
	if err := s.ValidateWithZones(zones); err != nil {
		return Schedule{}, err
	}
	if verifier == nil || grant.Validate() != nil || grant.Class != authority.ServiceExecution {
		return Schedule{}, errors.New("inspection schedule requires a signed ServiceExecution grant")
	}
	if s.State != StateAwaitingAuthorization && s.State != StatePaused {
		return Schedule{}, errors.New("inspection schedule cannot activate from its current state")
	}
	if err := validateTransitionTime(s, at); err != nil {
		return Schedule{}, err
	}
	scope, expectedDigest, err := ScopeForWithZones(s, zones)
	if err != nil {
		return Schedule{}, err
	}
	if err := validateGrantExactScope(grant, scope); err != nil {
		return Schedule{}, err
	}
	if at.Before(grant.IssuedAt) || !at.Before(grant.ExpiresAt) {
		return Schedule{}, errors.New("inspection authorization grant cannot be bound at activation time")
	}
	if !at.Before(s.ValidUntil) {
		return Schedule{}, errors.New("inspection schedule validity ended before activation")
	}

	if err := verifyServiceGrant(verifier, grant, scope, at.UTC()); err != nil {
		return Schedule{}, err
	}
	authorityDigest, err := grantDigest(grant)
	if err != nil {
		return Schedule{}, err
	}
	authorizedAt := at.UTC()
	s.State = StateActive
	s.ScheduleScopeSHA256 = expectedDigest
	s.AuthoritySHA256 = authorityDigest
	s.ServiceGrant = grant
	s.AuthorizedAt = &authorizedAt
	s.UpdatedAt = authorizedAt
	if err := s.ValidateWithZones(zones); err != nil {
		return Schedule{}, err
	}
	return s, nil
}

func Pause(s Schedule, at time.Time) (Schedule, error) {
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	if s.State != StateActive {
		return Schedule{}, errors.New("only an active inspection schedule can be paused")
	}
	if err := validateTransitionTime(s, at); err != nil {
		return Schedule{}, err
	}
	if !at.Before(effectiveEnd(s)) {
		return Schedule{}, errors.New("inspection schedule must expire rather than pause after its authority ends")
	}
	pausedAt := at.UTC()
	s.State = StatePaused
	s.PausedAt = &pausedAt
	s.UpdatedAt = pausedAt
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	return s, nil
}

// Revoke is irreversible for this schedule revision and is admitted from any
// nonterminal state so authorization can be withdrawn immediately.
func Revoke(s Schedule, at time.Time) (Schedule, error) {
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	if s.State == StateRevoked || s.State == StateExpired {
		return Schedule{}, errors.New("inspection schedule revision is already terminal")
	}
	if err := validateTransitionTime(s, at); err != nil {
		return Schedule{}, err
	}
	revokedAt := at.UTC()
	s.State = StateRevoked
	s.RevokedAt = &revokedAt
	s.UpdatedAt = revokedAt
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	return s, nil
}

// Expire closes a schedule only after its schedule or grant validity ended.
func Expire(s Schedule, at time.Time) (Schedule, error) {
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	if s.State == StateRevoked || s.State == StateExpired {
		return Schedule{}, errors.New("inspection schedule revision is already terminal")
	}
	if err := validateTransitionTime(s, at); err != nil {
		return Schedule{}, err
	}
	if at.Before(effectiveEnd(s)) {
		return Schedule{}, errors.New("inspection schedule validity has not ended")
	}
	expiredAt := at.UTC()
	s.State = StateExpired
	s.ExpiredAt = &expiredAt
	s.UpdatedAt = expiredAt
	if err := s.Validate(); err != nil {
		return Schedule{}, err
	}
	return s, nil
}

func effectiveStart(s Schedule) time.Time {
	start := s.ValidFrom
	if !s.ServiceGrant.IssuedAt.IsZero() && s.ServiceGrant.IssuedAt.After(start) {
		start = s.ServiceGrant.IssuedAt
	}
	return start.UTC()
}

func effectiveEnd(s Schedule) time.Time {
	end := s.ValidUntil
	if !s.ServiceGrant.ExpiresAt.IsZero() && s.ServiceGrant.ExpiresAt.Before(end) {
		end = s.ServiceGrant.ExpiresAt
	}
	return end.UTC()
}

func validateTransitionTime(s Schedule, at time.Time) error {
	if at.IsZero() {
		return errors.New("inspection schedule transition time is required")
	}
	if at.Before(s.UpdatedAt) {
		return errors.New("inspection schedule transition time moved backwards")
	}
	return nil
}

func validateScope(scope AuthorizationScope) error {
	if scope.Schema != SchemaVersion {
		return errors.New("inspection authorization scope schema is invalid")
	}
	for name, value := range map[string]string{
		"tenant": scope.TenantID, "site": scope.SiteID, "schedule": scope.ScheduleID,
	} {
		if !validExecutionAuthorityRef(value) {
			return fmt.Errorf("inspection authorization %s reference is invalid", name)
		}
	}
	if scope.ScheduleRevision == 0 || scope.Origin != inspection.OriginSchedule {
		return errors.New("inspection authorization scope revisions are required")
	}
	if !validSHA256(scope.RunSpecSHA256) || !validSHA256(scope.DeliverySHA256) ||
		!sortedUniqueExecutionAuthorityRefs(scope.SourceHandles) || !validSHA256(scope.ServicePrincipalSHA256) ||
		!sortedUniqueOperations(scope.RequiredOperations) || scope.ResourceCeiling.Validate() != nil {
		return errors.New("inspection authorization execution scope is invalid")
	}
	if scope.ValidFrom.IsZero() || scope.ValidUntil.IsZero() || !scope.ValidUntil.After(scope.ValidFrom) {
		return errors.New("inspection authorization scope validity is invalid")
	}
	if strings.TrimSpace(scope.Timezone) != scope.Timezone || scope.Timezone == "" {
		return errors.New("inspection authorization scope timezone is invalid")
	}
	if _, _, err := parseLocalTime(scope.LocalTime); err != nil {
		return err
	}
	if len(scope.Weekdays) == 0 || len(scope.Weekdays) > 7 {
		return errors.New("inspection authorization scope weekdays are invalid")
	}
	seen := map[Weekday]struct{}{}
	for _, weekday := range scope.Weekdays {
		if _, ok := weekdayTimeValue(weekday); !ok {
			return fmt.Errorf("inspection authorization scope weekday %q is invalid", weekday)
		}
		if _, ok := seen[weekday]; ok {
			return fmt.Errorf("inspection authorization scope weekday %q is duplicated", weekday)
		}
		seen[weekday] = struct{}{}
	}
	if scope.JitterPolicySeconds < 0 || scope.JitterPolicySeconds > 6*60*60 ||
		scope.MisfireGraceSeconds < 1 || scope.MisfireGraceSeconds > 24*60*60 {
		return errors.New("inspection authorization scope timing policy is invalid")
	}
	if scope.Misfire != MisfireSkip && scope.Misfire != MisfireCatchUpOnce {
		return errors.New("inspection authorization scope misfire policy is invalid")
	}
	if scope.Concurrency.MaxInFlight < 1 || scope.Concurrency.MaxInFlight > 100 ||
		(scope.Concurrency.OnLimit != ConcurrencyQueue && scope.Concurrency.OnLimit != ConcurrencySkip) {
		return errors.New("inspection authorization scope concurrency is invalid")
	}
	return nil
}

func validateGrantExactScope(grant authority.Grant, scope AuthorizationScope) error {
	policyDigest, err := scopeDigest(scope)
	if err != nil {
		return err
	}
	maxFrames := scope.ResourceCeiling.MaxTargets * scope.ResourceCeiling.MaxSamplesPerTarget
	if grant.Class != authority.ServiceExecution || grant.PrincipalSHA256 != scope.ServicePrincipalSHA256 ||
		grant.Scope.TenantID != scope.TenantID || grant.Scope.SiteID != scope.SiteID ||
		grant.Scope.ScheduleID != scope.ScheduleID || grant.Scope.PolicySHA256 != policyDigest || grant.Scope.DeviceProfileID != "" || grant.Scope.RunID != "" ||
		grant.Scope.MaxFrames != maxFrames || grant.Scope.MaxBytes != scope.ResourceCeiling.MaxMediaBytes ||
		grant.Scope.MaxDurationSeconds != scope.ResourceCeiling.MaxDurationSeconds ||
		!equalStrings(grant.Scope.SourceHandles, scope.SourceHandles) || !equalStrings(grant.Scope.OperationKinds, scope.RequiredOperations) {
		return errors.New("ServiceExecution grant does not exactly match the frozen schedule scope")
	}
	return nil
}

func verifyServiceGrant(verifier GrantVerifier, grant authority.Grant, scope AuthorizationScope, at time.Time) error {
	if verifier == nil {
		return errors.New("inspection schedule authority verifier is required")
	}
	policyDigest, err := scopeDigest(scope)
	if err != nil {
		return err
	}
	maxFrames := scope.ResourceCeiling.MaxTargets * scope.ResourceCeiling.MaxSamplesPerTarget
	for _, operation := range scope.RequiredOperations {
		demand := authority.Demand{
			Class: authority.ServiceExecution, OperationKind: operation,
			PrincipalSHA256: scope.ServicePrincipalSHA256, TenantID: scope.TenantID, SiteID: scope.SiteID,
			SourceHandles: append([]string(nil), scope.SourceHandles...), ScheduleID: scope.ScheduleID,
			PolicySHA256: policyDigest,
			MaxFrames:    maxFrames, MaxBytes: scope.ResourceCeiling.MaxMediaBytes,
			MaxDurationSeconds: scope.ResourceCeiling.MaxDurationSeconds,
		}
		if err := verifier.Verify(grant, demand, at.UTC()); err != nil {
			return errors.New("inspection schedule ServiceExecution grant verification failed")
		}
	}
	return nil
}

func grantDigest(grant authority.Grant) (string, error) {
	raw, err := json.Marshal(grant)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func sortedUniqueRefs(values []string, maximum int) bool {
	if len(values) == 0 || len(values) > maximum {
		return false
	}
	for index, value := range values {
		if validateRef("scope", value) != nil || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func sortedUniqueExecutionAuthorityRefs(values []string) bool {
	if len(values) == 0 || len(values) > 64 {
		return false
	}
	for index, value := range values {
		if !validExecutionAuthorityRef(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func sortedUniqueOperations(values []string) bool {
	if !sortedUniqueRefs(values, 16) || !containsString(values, authority.OpOccurrenceExecute) {
		return false
	}
	allowed := map[string]struct{}{
		authority.OpOccurrenceExecute: {}, authority.OpSourceAcquire: {}, authority.OpMediaExtract: {},
		authority.OpAnalyze: {}, authority.OpReadExistingEvidence: {}, authority.OpDeliver: {}, authority.OpCleanup: {},
	}
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func equalStrings(left, right []string) bool {
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
