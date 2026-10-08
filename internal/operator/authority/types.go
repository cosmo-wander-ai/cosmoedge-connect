package authority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "cosmoedge.operator.authority.v2"

type Class string

const (
	ConnectionProfileWrite Class = "connection_profile_write"
	DeviceRead             Class = "device_read"
	InspectionExecution    Class = "inspection_execution"
	PersistentDeviceWrite  Class = "persistent_device_write"
	ServiceExecution       Class = "service_execution"
)

const (
	OpProfileCreate    = "profile_create"
	OpProfileUpdate    = "profile_update"
	OpProfileForget    = "profile_forget"
	OpCredentialRotate = "credential_rotate"

	OpCatalogRead  = "catalog_read"
	OpStatusRead   = "status_read"
	OpEventsRead   = "events_read"
	OpEvidenceRead = "evidence_read"

	OpSourceAcquire        = "source_acquire"
	OpMediaExtract         = "media_extract"
	OpAnalyze              = "analyze"
	OpReadExistingEvidence = "read_existing_evidence"
	OpDeliver              = "deliver"
	OpCleanup              = "cleanup"
	OpOccurrenceExecute    = "occurrence_execute"

	OpSourceCreate         = "source_create"
	OpSourceUpdate         = "source_update"
	OpSourceDelete         = "source_delete"
	OpTaskDeploy           = "task_deploy"
	OpTaskUpdate           = "task_update"
	OpTaskEnable           = "task_enable"
	OpTaskDisable          = "task_disable"
	OpDeviceScheduleUpdate = "device_schedule_update"
)

type Scope struct {
	TenantID           string   `json:"tenantId"`
	SiteID             string   `json:"siteId"`
	DeviceProfileID    string   `json:"deviceProfileId,omitempty"`
	SourceHandles      []string `json:"sourceHandles,omitempty"`
	OperationKinds     []string `json:"operationKinds"`
	RunID              string   `json:"runId,omitempty"`
	ScheduleID         string   `json:"scheduleId,omitempty"`
	PolicySHA256       string   `json:"policySha256,omitempty"`
	MaxFrames          int      `json:"maxFrames,omitempty"`
	MaxBytes           int64    `json:"maxBytes,omitempty"`
	MaxDurationSeconds int      `json:"maxDurationSeconds,omitempty"`
}

type Grant struct {
	Schema          string    `json:"schema"`
	IssuerID        string    `json:"issuerId"`
	GrantID         string    `json:"grantId"`
	Class           Class     `json:"class"`
	PrincipalSHA256 string    `json:"principalSha256"`
	Scope           Scope     `json:"scope"`
	ScopeSHA256     string    `json:"scopeSha256"`
	IssuedAt        time.Time `json:"issuedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	ProofSHA256     string    `json:"proofSha256"`
}

var (
	refPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var operationsByClass = map[Class]map[string]struct{}{
	ConnectionProfileWrite: operationSet(OpProfileCreate, OpProfileUpdate, OpProfileForget, OpCredentialRotate),
	DeviceRead:             operationSet(OpCatalogRead, OpStatusRead, OpEventsRead, OpEvidenceRead),
	InspectionExecution: operationSet(
		OpSourceAcquire, OpMediaExtract, OpAnalyze, OpReadExistingEvidence, OpDeliver, OpCleanup,
	),
	PersistentDeviceWrite: operationSet(
		OpSourceCreate, OpSourceUpdate, OpSourceDelete, OpTaskDeploy, OpTaskUpdate,
		OpTaskEnable, OpTaskDisable, OpDeviceScheduleUpdate,
	),
	ServiceExecution: operationSet(
		OpOccurrenceExecute, OpSourceAcquire, OpMediaExtract, OpAnalyze,
		OpReadExistingEvidence, OpDeliver, OpCleanup,
	),
}

func newUnsignedGrant(issuerID, grantID string, class Class, principalSHA256 string, scope Scope, issuedAt, expiresAt time.Time) (Grant, error) {
	scope = normalizeScope(scope)
	grant := Grant{
		Schema: SchemaVersion, IssuerID: strings.TrimSpace(issuerID), GrantID: strings.TrimSpace(grantID), Class: class,
		PrincipalSHA256: strings.TrimSpace(principalSHA256), Scope: scope,
		IssuedAt: issuedAt.UTC(), ExpiresAt: expiresAt.UTC(),
	}
	digest, err := scopeDigest(scope)
	if err != nil {
		return Grant{}, err
	}
	grant.ScopeSHA256 = digest
	if err := grant.validateUnsigned(); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

func (g Grant) Validate() error {
	if err := g.validateUnsigned(); err != nil {
		return err
	}
	if !digestPattern.MatchString(g.ProofSHA256) {
		return errors.New("authority proof is invalid")
	}
	return nil
}

func (g Grant) validateUnsigned() error {
	if g.Schema != SchemaVersion {
		return errors.New("authority schema is unsupported")
	}
	if !validRef(g.IssuerID) || !validRef(g.GrantID) {
		return errors.New("authority issuer or grant id is invalid")
	}
	allowed, ok := operationsByClass[g.Class]
	if !ok {
		return errors.New("authority class is unsupported")
	}
	if !digestPattern.MatchString(g.PrincipalSHA256) {
		return errors.New("authority principal binding is invalid")
	}
	if g.IssuedAt.IsZero() || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) {
		return errors.New("authority lifetime is invalid")
	}
	if err := g.Scope.validate(g.Class, allowed); err != nil {
		return err
	}
	digest, err := scopeDigest(normalizeScope(g.Scope))
	if err != nil {
		return err
	}
	if !digestPattern.MatchString(g.ScopeSHA256) || g.ScopeSHA256 != digest {
		return errors.New("authority scope digest is invalid")
	}
	return nil
}

func (s Scope) validate(class Class, allowed map[string]struct{}) error {
	if !validRef(s.TenantID) || !validRef(s.SiteID) {
		return errors.New("authority tenant and site bindings are required")
	}
	if s.DeviceProfileID != "" && !validRef(s.DeviceProfileID) {
		return errors.New("authority device profile binding is invalid")
	}
	if len(s.OperationKinds) == 0 || len(s.OperationKinds) > 16 {
		return errors.New("authority operations are missing or exceed the bound")
	}
	if !strictlySortedUnique(s.OperationKinds) {
		return errors.New("authority operations must be sorted and unique")
	}
	for _, operation := range s.OperationKinds {
		if _, ok := allowed[operation]; !ok {
			return errors.New("authority operation is outside its class")
		}
	}
	if len(s.SourceHandles) > 64 || !strictlySortedUnique(s.SourceHandles) {
		return errors.New("authority source bindings are invalid")
	}
	for _, handle := range s.SourceHandles {
		if !validRef(handle) {
			return errors.New("authority source binding is invalid")
		}
	}
	for _, ref := range []string{s.RunID, s.ScheduleID} {
		if ref != "" && !validRef(ref) {
			return errors.New("authority execution binding is invalid")
		}
	}
	if s.PolicySHA256 != "" && !digestPattern.MatchString(s.PolicySHA256) {
		return errors.New("authority policy binding is invalid")
	}
	if s.MaxFrames < 0 || s.MaxFrames > 10000 || s.MaxBytes < 0 || s.MaxBytes > 1<<40 ||
		s.MaxDurationSeconds < 0 || s.MaxDurationSeconds > 7*24*60*60 {
		return errors.New("authority resource budget is invalid")
	}

	switch class {
	case ConnectionProfileWrite:
		if s.RunID != "" || s.ScheduleID != "" || s.PolicySHA256 != "" || len(s.SourceHandles) != 0 || hasBudget(s) {
			return errors.New("connection profile authority cannot carry execution scope")
		}
		for _, operation := range s.OperationKinds {
			if operation != OpProfileCreate && s.DeviceProfileID == "" {
				return errors.New("connection profile mutation authority requires an exact profile binding")
			}
		}
	case DeviceRead:
		if s.DeviceProfileID == "" || s.RunID != "" || s.ScheduleID != "" || s.PolicySHA256 != "" || hasBudget(s) {
			return errors.New("device read authority scope is invalid")
		}
	case InspectionExecution:
		if s.RunID == "" || s.ScheduleID != "" || !positiveBudget(s) {
			return errors.New("inspection execution authority requires one run and positive bounds")
		}
	case PersistentDeviceWrite:
		if s.DeviceProfileID == "" || s.RunID != "" || s.ScheduleID != "" || s.PolicySHA256 != "" || len(s.SourceHandles) != 0 || hasBudget(s) {
			return errors.New("persistent device write authority scope is invalid")
		}
	case ServiceExecution:
		if s.ScheduleID == "" || s.RunID != "" || !digestPattern.MatchString(s.PolicySHA256) || !positiveBudget(s) {
			return errors.New("service execution authority requires one schedule and positive bounds")
		}
	}
	return nil
}

func normalizeScope(scope Scope) Scope {
	scope.TenantID = strings.TrimSpace(scope.TenantID)
	scope.SiteID = strings.TrimSpace(scope.SiteID)
	scope.DeviceProfileID = strings.TrimSpace(scope.DeviceProfileID)
	scope.RunID = strings.TrimSpace(scope.RunID)
	scope.ScheduleID = strings.TrimSpace(scope.ScheduleID)
	scope.PolicySHA256 = strings.TrimSpace(scope.PolicySHA256)
	scope.SourceHandles = normalizeList(scope.SourceHandles)
	scope.OperationKinds = normalizeList(scope.OperationKinds)
	return scope
}

func scopeDigest(scope Scope) (string, error) {
	raw, err := json.Marshal(scope)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
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

func strictlySortedUnique(values []string) bool {
	for index, value := range values {
		if value == "" || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func operationSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func validRef(value string) bool { return refPattern.MatchString(value) }

func hasBudget(scope Scope) bool {
	return scope.MaxFrames != 0 || scope.MaxBytes != 0 || scope.MaxDurationSeconds != 0
}

func positiveBudget(scope Scope) bool {
	return scope.MaxFrames > 0 && scope.MaxBytes > 0 && scope.MaxDurationSeconds > 0
}
