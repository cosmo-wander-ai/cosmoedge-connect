package schedule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

const (
	SchemaVersion           = "cosmoedge.inspection.schedule.v4"
	OccurrenceSchemaVersion = "cosmoedge.inspection.occurrence.v4"
	FrozenRunSpecSchema     = "cosmoedge.inspection.frozen-run-spec.v1"
	DeliveryBindingSchema   = "cosmoedge.inspection.delivery-binding.v2"
)

type State string

const (
	StateDraft                 State = "draft"
	StateAwaitingAuthorization State = "awaiting_authorization"
	StateActive                State = "active"
	StatePaused                State = "paused"
	StateRevoked               State = "revoked"
	StateExpired               State = "expired"
)

type Weekday string

const (
	Monday    Weekday = "monday"
	Tuesday   Weekday = "tuesday"
	Wednesday Weekday = "wednesday"
	Thursday  Weekday = "thursday"
	Friday    Weekday = "friday"
	Saturday  Weekday = "saturday"
	Sunday    Weekday = "sunday"
)

type MisfirePolicy string

const (
	MisfireSkip        MisfirePolicy = "skip"
	MisfireCatchUpOnce MisfirePolicy = "catch_up_once"
)

type ConcurrencyAction string

const (
	ConcurrencyQueue ConcurrencyAction = "queue"
	ConcurrencySkip  ConcurrencyAction = "skip"
)

type ConcurrencyPolicy struct {
	MaxInFlight int               `json:"maxInFlight"`
	OnLimit     ConcurrencyAction `json:"onLimit"`
}

// VariableBinding is the canonical form of one prompt variable. Values are
// persisted in the protected schedule database but are intentionally omitted
// from public JSON projections.
type VariableBinding struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FrozenPipeline is the exact typed plan skeleton compiled from the immutable
// template and assignment. Dynamic request identity and deadlines are replaced
// by a canonical reference request before this value is produced.
type FrozenPipeline struct {
	Targets []inspection.PlannedTarget `json:"targets"`
	Steps   []inspection.ExecutionStep `json:"steps"`
	SHA256  string                     `json:"sha256"`
}

// FrozenRunSpec is the closed, immutable execution input. The full template,
// assignment, normalized variables and pipeline are protected persistence
// material. MarshalJSON deliberately emits only the non-sensitive projection.
type FrozenRunSpec struct {
	Schema               string                        `json:"schema"`
	TenantID             string                        `json:"tenantId"`
	SiteID               string                        `json:"siteId"`
	Template             inspection.InspectionTemplate `json:"template"`
	TemplateSHA256       string                        `json:"templateSha256"`
	Assignment           inspection.Assignment         `json:"assignment"`
	AssignmentSHA256     string                        `json:"assignmentSha256"`
	SelectedTargetIDs    []string                      `json:"selectedTargetIds"`
	SelectedTargets      []inspection.TargetBinding    `json:"selectedTargets"`
	SourceHandles        []string                      `json:"sourceHandles"`
	Strategies           []inspection.StrategyPolicy   `json:"strategies"`
	StrategySHA256       string                        `json:"strategySha256"`
	Pipeline             FrozenPipeline                `json:"pipeline"`
	Variables            []VariableBinding             `json:"variables"`
	VariablesSHA256      string                        `json:"variablesSha256"`
	RunTTLSeconds        int                           `json:"runTtlSeconds"`
	ResourceCeiling      inspection.ResourceBudget     `json:"resourceCeiling"`
	ResultContractSHA256 string                        `json:"resultContractSha256"`
	RetentionPolicy      inspection.EvidencePolicy     `json:"retentionPolicy"`
	RequiredOperations   []string                      `json:"requiredOperations"`
	SHA256               string                        `json:"sha256"`
}

type frozenRunSpecProjection struct {
	Schema               string                    `json:"schema"`
	TenantID             string                    `json:"tenantId"`
	SiteID               string                    `json:"siteId"`
	TemplateID           string                    `json:"templateId"`
	TemplateRevision     uint64                    `json:"templateRevision"`
	TemplateSHA256       string                    `json:"templateSha256"`
	AssignmentID         string                    `json:"assignmentId"`
	AssignmentRevision   uint64                    `json:"assignmentRevision"`
	AssignmentSHA256     string                    `json:"assignmentSha256"`
	SelectedTargetIDs    []string                  `json:"selectedTargetIds"`
	SourceCount          int                       `json:"sourceCount"`
	SourceSetSHA256      string                    `json:"sourceSetSha256"`
	StrategySHA256       string                    `json:"strategySha256"`
	PipelineSHA256       string                    `json:"pipelineSha256"`
	VariablesSHA256      string                    `json:"variablesSha256"`
	RunTTLSeconds        int                       `json:"runTtlSeconds"`
	ResourceCeiling      inspection.ResourceBudget `json:"resourceCeiling"`
	ResultContractSHA256 string                    `json:"resultContractSha256"`
	RetentionPolicy      inspection.EvidencePolicy `json:"retentionPolicy"`
	RequiredOperations   []string                  `json:"requiredOperations"`
	SHA256               string                    `json:"sha256"`
}

func (s FrozenRunSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(frozenRunSpecProjection{
		Schema: s.Schema, TenantID: s.TenantID, SiteID: s.SiteID,
		TemplateID: s.Template.TemplateID, TemplateRevision: s.Template.Revision, TemplateSHA256: s.TemplateSHA256,
		AssignmentID: s.Assignment.AssignmentID, AssignmentRevision: s.Assignment.Revision, AssignmentSHA256: s.AssignmentSHA256,
		SelectedTargetIDs: append([]string(nil), s.SelectedTargetIDs...), SourceCount: len(s.SourceHandles), SourceSetSHA256: digestProjectionSet(s.SourceHandles),
		StrategySHA256: s.StrategySHA256, PipelineSHA256: s.Pipeline.SHA256, VariablesSHA256: s.VariablesSHA256,
		RunTTLSeconds: s.RunTTLSeconds, ResourceCeiling: s.ResourceCeiling,
		ResultContractSHA256: s.ResultContractSHA256, RetentionPolicy: s.RetentionPolicy,
		RequiredOperations: append([]string(nil), s.RequiredOperations...), SHA256: s.SHA256,
	})
}

// DeliveryBinding is exactly one immutable recipient/audience binding. A
// schedule cannot silently pick the first member of a list.
type DeliveryBinding struct {
	Schema          string `json:"schema"`
	BindingRef      string `json:"bindingRef"`
	Revision        uint64 `json:"revision"`
	AudienceSHA256  string `json:"audienceSha256"`
	PrincipalSHA256 string `json:"principalSha256"`
	SHA256          string `json:"sha256"`
}

// Schedule is an immutable revision plus mutable lifecycle metadata. Any
// execution, delivery, timing or authority-scope edit creates a new revision.
type Schedule struct {
	Schema                 string               `json:"schema"`
	TenantID               string               `json:"tenantId"`
	SiteID                 string               `json:"siteId"`
	ScheduleID             string               `json:"scheduleId"`
	Revision               uint64               `json:"revision"`
	Origin                 inspection.RunOrigin `json:"origin"`
	RunSpec                FrozenRunSpec        `json:"runSpec"`
	RunSpecSHA256          string               `json:"runSpecSha256"`
	Delivery               DeliveryBinding      `json:"delivery"`
	DeliverySHA256         string               `json:"deliverySha256"`
	ServicePrincipalSHA256 string               `json:"servicePrincipalSha256"`
	Timezone               string               `json:"timezone"`
	Weekdays               []Weekday            `json:"weekdays"`
	LocalTime              string               `json:"localTime"`
	ValidFrom              time.Time            `json:"validFrom"`
	ValidUntil             time.Time            `json:"validUntil"`
	JitterPolicySeconds    int                  `json:"jitterPolicySeconds"`
	Misfire                MisfirePolicy        `json:"misfire"`
	MisfireGraceSeconds    int                  `json:"misfireGraceSeconds"`
	Concurrency            ConcurrencyPolicy    `json:"concurrency"`
	State                  State                `json:"state"`
	ScheduleScopeSHA256    string               `json:"scheduleScopeSha256,omitempty"`
	AuthoritySHA256        string               `json:"authoritySha256,omitempty"`
	ServiceGrant           authority.Grant      `json:"serviceGrant,omitempty"`
	CreatedAt              time.Time            `json:"createdAt"`
	UpdatedAt              time.Time            `json:"updatedAt"`
	AuthorizedAt           *time.Time           `json:"authorizedAt,omitempty"`
	PausedAt               *time.Time           `json:"pausedAt,omitempty"`
	RevokedAt              *time.Time           `json:"revokedAt,omitempty"`
	ExpiredAt              *time.Time           `json:"expiredAt,omitempty"`
}

// MarshalJSON is the protected schedule projection. The signed service grant
// is an execution capability and is therefore never emitted through ordinary
// JSON. The protected store uses an explicit storage wire type instead.
func (s Schedule) MarshalJSON() ([]byte, error) {
	type scheduleProjectionAlias Schedule
	raw, err := json.Marshal(scheduleProjectionAlias(s))
	if err != nil {
		return nil, err
	}
	var projection map[string]json.RawMessage
	if err := json.Unmarshal(raw, &projection); err != nil {
		return nil, err
	}
	delete(projection, "serviceGrant")
	return json.Marshal(projection)
}

// AuthorizationScope contains every expansion-sensitive field. Large frozen
// snapshots are represented by their verified self digests.
type AuthorizationScope struct {
	Schema                 string                    `json:"schema"`
	TenantID               string                    `json:"tenantId"`
	SiteID                 string                    `json:"siteId"`
	ScheduleID             string                    `json:"scheduleId"`
	ScheduleRevision       uint64                    `json:"scheduleRevision"`
	Origin                 inspection.RunOrigin      `json:"origin"`
	RunSpecSHA256          string                    `json:"runSpecSha256"`
	DeliverySHA256         string                    `json:"deliverySha256"`
	SourceHandles          []string                  `json:"sourceHandles"`
	ResourceCeiling        inspection.ResourceBudget `json:"resourceCeiling"`
	ServicePrincipalSHA256 string                    `json:"servicePrincipalSha256"`
	RequiredOperations     []string                  `json:"requiredOperations"`
	Timezone               string                    `json:"timezone"`
	Weekdays               []Weekday                 `json:"weekdays"`
	LocalTime              string                    `json:"localTime"`
	ValidFrom              time.Time                 `json:"validFrom"`
	ValidUntil             time.Time                 `json:"validUntil"`
	JitterPolicySeconds    int                       `json:"jitterPolicySeconds"`
	Misfire                MisfirePolicy             `json:"misfire"`
	MisfireGraceSeconds    int                       `json:"misfireGraceSeconds"`
	Concurrency            ConcurrencyPolicy         `json:"concurrency"`
}

// Occurrence is a complete immutable submission envelope. It carries the
// exact frozen input needed to rebuild the scheduled CreateRunRequest and plan.
type Occurrence struct {
	Schema                 string               `json:"schema"`
	OccurrenceID           string               `json:"occurrenceId"`
	IdempotencyKey         string               `json:"idempotencyKey"`
	OperationRef           string               `json:"operationRef"`
	RequestID              string               `json:"requestId"`
	RequestKey             string               `json:"requestKey"`
	RequestSHA256          string               `json:"requestSha256"`
	PlanSHA256             string               `json:"planSha256"`
	SHA256                 string               `json:"sha256"`
	TenantID               string               `json:"tenantId"`
	SiteID                 string               `json:"siteId"`
	ScheduleID             string               `json:"scheduleId"`
	ScheduleRevision       uint64               `json:"scheduleRevision"`
	Origin                 inspection.RunOrigin `json:"origin"`
	RunSpec                FrozenRunSpec        `json:"runSpec"`
	RunSpecSHA256          string               `json:"runSpecSha256"`
	Delivery               DeliveryBinding      `json:"delivery"`
	DeliverySHA256         string               `json:"deliverySha256"`
	ServicePrincipalSHA256 string               `json:"servicePrincipalSha256"`
	AuthorityScope         AuthorizationScope   `json:"authorityScope"`
	ScheduleScopeSHA256    string               `json:"scheduleScopeSha256"`
	AuthoritySHA256        string               `json:"authoritySha256"`
	Timezone               string               `json:"timezone"`
	LocalDate              string               `json:"localDate"`
	LocalTime              string               `json:"localTime"`
	ScheduledAt            time.Time            `json:"scheduledAt"`
	DueAt                  time.Time            `json:"dueAt"`
	Deadline               time.Time            `json:"deadline"`
	GeneratedAt            time.Time            `json:"generatedAt"`
	JitterPolicySeconds    int                  `json:"jitterPolicySeconds"`
	JitterOffsetSeconds    int                  `json:"jitterOffsetSeconds"`
	Misfire                MisfirePolicy        `json:"misfire"`
	MisfireGraceSeconds    int                  `json:"misfireGraceSeconds"`
	Misfired               bool                 `json:"misfired"`
	Concurrency            ConcurrencyPolicy    `json:"concurrency"`
}

// MarshalJSON removes the full authority scope because it contains protected
// source handles. ScheduleScopeSHA256 remains the public binding to that exact
// protected value; the storage wire persists the full scope.
func (o Occurrence) MarshalJSON() ([]byte, error) {
	type occurrenceProjectionAlias Occurrence
	raw, err := json.Marshal(occurrenceProjectionAlias(o))
	if err != nil {
		return nil, err
	}
	var projection map[string]json.RawMessage
	if err := json.Unmarshal(raw, &projection); err != nil {
		return nil, err
	}
	delete(projection, "authorityScope")
	return json.Marshal(projection)
}

func digestProjectionSet(values []string) string {
	raw, _ := json.Marshal(values)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

type Clock interface{ Now() time.Time }

type ZoneLoader interface {
	LoadLocation(name string) (*time.Location, error)
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

type SystemZoneLoader struct{}

func (SystemZoneLoader) LoadLocation(name string) (*time.Location, error) {
	return time.LoadLocation(name)
}
