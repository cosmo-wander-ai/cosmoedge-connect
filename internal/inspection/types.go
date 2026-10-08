package inspection

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "cosmoedge.inspection.v2"

type SourceKind string

const (
	SourceCamera        SourceKind = "camera"
	SourceUploadedImage SourceKind = "uploaded_image"
	SourceUploadedVideo SourceKind = "uploaded_video"
	SourceTaskEvidence  SourceKind = "task_evidence"
	SourceRetainedMedia SourceKind = "retained_media"
)

type MediaKind string

const (
	MediaImage     MediaKind = "image"
	MediaFrameSet  MediaKind = "frame_set"
	MediaVideoClip MediaKind = "video_clip"
	MediaMetric    MediaKind = "metric"
	MediaDetection MediaKind = "detection"
	MediaEvent     MediaKind = "event"
)

type TemplateState string

const (
	TemplateDraft      TemplateState = "draft"
	TemplatePublished  TemplateState = "published"
	TemplateDeprecated TemplateState = "deprecated"
)

type Method string

const (
	MethodCV     Method = "cv"
	MethodVLM    Method = "vlm"
	MethodHybrid Method = "hybrid"
	MethodEvent  Method = "event"
)

// ResultKind is the closed set of machine-readable values that an inspection
// criterion may produce. It is shared by the criterion output contract and by
// persisted results so adapters cannot smuggle an untyped JSON escape hatch
// across the analysis trust boundary.
type ResultKind string

const (
	ResultClassification ResultKind = "classification"
	ResultEnum           ResultKind = "enum"
	ResultStructured     ResultKind = "structured"
	ResultMetric         ResultKind = "metric"
	ResultDetection      ResultKind = "detection"
	ResultCount          ResultKind = "count"
	ResultEvent          ResultKind = "event"
)

type Assessment string

const (
	AssessmentMeetsRule      Assessment = "meets_rule"
	AssessmentNeedsAttention Assessment = "needs_attention"
	AssessmentUncertain      Assessment = "uncertain"
	AssessmentNotObservable  Assessment = "not_observable"
	AssessmentUnsupported    Assessment = "unsupported"
)

type RunOrigin string

const (
	OriginUser     RunOrigin = "user"
	OriginSchedule RunOrigin = "schedule"
	OriginAPI      RunOrigin = "api"
)

type RunState string

const (
	RunRequested              RunState = "requested"
	RunAdmitted               RunState = "admitted"
	RunQueued                 RunState = "queued"
	RunRunning                RunState = "running"
	RunReconciliationRequired RunState = "reconciliation_required"
	RunFinalizing             RunState = "finalizing"
	RunCompleted              RunState = "completed"
	RunPartial                RunState = "partial"
	RunBlocked                RunState = "blocked"
	RunUnknown                RunState = "unknown"
	RunFailed                 RunState = "failed"
	RunCancelled              RunState = "cancelled"
	RunExpired                RunState = "expired"
)

type RunPhase string

const (
	PhaseResolving  RunPhase = "resolving"
	PhaseCapturing  RunPhase = "capturing"
	PhaseAnalyzing  RunPhase = "analyzing"
	PhaseValidating RunPhase = "validating"
	PhaseComposing  RunPhase = "composing"
	PhaseCleaning   RunPhase = "cleaning"
)

type ExecutionStrategy string

const (
	StrategyExistingTaskRead ExecutionStrategy = "existing_task_read"
	StrategySnapshotAnalysis ExecutionStrategy = "snapshot_analysis"
	StrategyClipAnalysis     ExecutionStrategy = "clip_analysis"
	StrategyHybridAnalysis   ExecutionStrategy = "hybrid_analysis"
)

type TimeMode string

const (
	TimeCurrent      TimeMode = "current"
	TimeRecentWindow TimeMode = "recent_window"
)

type TimePolicy struct {
	Mode          TimeMode `json:"mode"`
	WindowSeconds int      `json:"windowSeconds"`
	MaxAgeSeconds int      `json:"maxAgeSeconds"`
}

// AcquisitionPolicy is a concrete, bounded source acquisition request. Fields
// that do not apply to the selected strategy must be zero rather than silently
// ignored.
type AcquisitionPolicy struct {
	Samples            int `json:"samples"`
	IntervalMillis     int `json:"intervalMillis"`
	ClipDurationMillis int `json:"clipDurationMillis"`
	MaxExtractedFrames int `json:"maxExtractedFrames"`
}

// StrategyPolicy is the template-owned upper bound for one closed execution
// strategy. It freezes admissible source kinds, capabilities, time scope,
// analysis policy, and maximum acquisition work.
type StrategyPolicy struct {
	Strategy               ExecutionStrategy `json:"strategy"`
	AllowedSourceKinds     []SourceKind      `json:"allowedSourceKinds"`
	RequiredCapabilityRefs []string          `json:"requiredCapabilityRefs"`
	MinimumSources         int               `json:"minimumSources"`
	MaximumSources         int               `json:"maximumSources"`
	Time                   TimePolicy        `json:"time"`
	AnalysisPolicyRef      string            `json:"analysisPolicyRef,omitempty"`
	MaximumAcquisition     AcquisitionPolicy `json:"maximumAcquisition"`
}

type ResourceBudget struct {
	MaxTargets          int   `json:"maxTargets"`
	MaxSamplesPerTarget int   `json:"maxSamplesPerTarget"`
	MaxAnalyses         int   `json:"maxAnalyses"`
	MaxDurationSeconds  int   `json:"maxDurationSeconds"`
	MaxMediaBytes       int64 `json:"maxMediaBytes"`
}

type EvidencePolicy struct {
	Required         bool   `json:"required"`
	RetentionSeconds int    `json:"retentionSeconds"`
	RedactionProfile string `json:"redactionProfile,omitempty"`
}

type PromptVariable struct {
	Name          string   `json:"name"`
	Required      bool     `json:"required"`
	MaxLength     int      `json:"maxLength"`
	AllowedValues []string `json:"allowedValues,omitempty"`
}

type PromptContract struct {
	Template  string           `json:"template"`
	Variables []PromptVariable `json:"variables"`
}

type OutputContract struct {
	Mode               ResultKind   `json:"mode"`
	AllowedAssessments []Assessment `json:"allowedAssessments"`
	SchemaVersion      string       `json:"schemaVersion"`
}

type Criterion struct {
	ID                  string         `json:"id"`
	Name                string         `json:"name"`
	Method              Method         `json:"method"`
	Required            bool           `json:"required"`
	RuleRef             string         `json:"ruleRef"`
	RuleVersion         uint64         `json:"ruleVersion"`
	MayAssertCompliance bool           `json:"mayAssertCompliance"`
	Prompt              PromptContract `json:"prompt"`
	Output              OutputContract `json:"output"`
}

type InspectionTemplate struct {
	Schema              string           `json:"schema"`
	TenantID            string           `json:"tenantId"`
	TemplateID          string           `json:"templateId"`
	Revision            uint64           `json:"revision"`
	Name                string           `json:"name"`
	BusinessPurpose     string           `json:"businessPurpose"`
	Criteria            []Criterion      `json:"criteria"`
	Strategies          []StrategyPolicy `json:"strategies"`
	Budget              ResourceBudget   `json:"budget"`
	Evidence            EvidencePolicy   `json:"evidence"`
	OutputSchemaVersion string           `json:"outputSchemaVersion"`
	State               TemplateState    `json:"state"`
	CreatedBy           string           `json:"createdBy"`
	CreatedAt           time.Time        `json:"createdAt"`
}

// SourceBinding freezes one opaque source identity and the capabilities that
// may be used with it. It never contains a device-native identifier, path,
// endpoint, credential, or media URL.
type SourceBinding struct {
	Kind              SourceKind  `json:"kind"`
	SourceHandle      string      `json:"sourceHandle"`
	SourceRevision    uint64      `json:"sourceRevision"`
	SourceFingerprint string      `json:"sourceFingerprint"`
	CapabilityRefs    []string    `json:"capabilityRefs"`
	MediaKinds        []MediaKind `json:"mediaKinds"`
	ROIRef            string      `json:"roiRef,omitempty"`
}

// InstalledTaskSourceBinding freezes one opaque source identity owned by an
// already installed catalog task. Native locators and device credentials are
// deliberately excluded from the inspection domain.
type InstalledTaskSourceBinding struct {
	SourceHandle      string `json:"sourceHandle"`
	SourceRevision    uint64 `json:"sourceRevision"`
	SourceFingerprint string `json:"sourceFingerprint"`
}

// InstalledTaskCapabilityBinding freezes the exact result and media contract
// selected from an installed catalog task.
type InstalledTaskCapabilityBinding struct {
	Ref          string      `json:"ref"`
	Revision     uint64      `json:"revision"`
	Digest       string      `json:"digest"`
	ResultSchema string      `json:"resultSchema"`
	MediaKinds   []MediaKind `json:"mediaKinds"`
}

// InstalledTaskBinding is the complete protected task snapshot carried by an
// assignment and copied byte-for-byte into its execution plan. TaskID is an
// opaque catalog identifier; BindingFingerprint is not a device-native ID.
type InstalledTaskBinding struct {
	TaskID             string                           `json:"taskId"`
	TaskRevision       uint64                           `json:"taskRevision"`
	BindingFingerprint string                           `json:"bindingFingerprint"`
	Sources            []InstalledTaskSourceBinding     `json:"sources"`
	Capabilities       []InstalledTaskCapabilityBinding `json:"capabilities"`
	ObservedAt         time.Time                        `json:"observedAt"`
}

type TargetBinding struct {
	TargetID       string                 `json:"targetId"`
	FriendlyName   string                 `json:"friendlyName"`
	SourceBindings []SourceBinding        `json:"sourceBindings"`
	InstalledTasks []InstalledTaskBinding `json:"installedTasks"`
	CriterionIDs   []string               `json:"criterionIds"`
	Strategy       ExecutionStrategy      `json:"strategy"`
	Acquisition    AcquisitionPolicy      `json:"acquisition"`
}

type Assignment struct {
	Schema                   string          `json:"schema"`
	TenantID                 string          `json:"tenantId"`
	AssignmentID             string          `json:"assignmentId"`
	Revision                 uint64          `json:"revision"`
	TemplateID               string          `json:"templateId"`
	TemplateRevision         uint64          `json:"templateRevision"`
	SiteID                   string          `json:"siteId"`
	ZoneID                   string          `json:"zoneId,omitempty"`
	Targets                  []TargetBinding `json:"targets"`
	SourceCatalogFingerprint string          `json:"sourceCatalogFingerprint"`
	Published                bool            `json:"published"`
}

type CreateRunRequest struct {
	Schema             string            `json:"schema"`
	TenantID           string            `json:"tenantId"`
	SiteID             string            `json:"siteId"`
	TemplateID         string            `json:"templateId"`
	TemplateRevision   uint64            `json:"templateRevision"`
	AssignmentID       string            `json:"assignmentId"`
	AssignmentRevision uint64            `json:"assignmentRevision"`
	Origin             RunOrigin         `json:"origin"`
	RequestID          string            `json:"requestId"`
	TargetIDs          []string          `json:"targetIds,omitempty"`
	Variables          map[string]string `json:"variables,omitempty"`
	RequestedAt        time.Time         `json:"requestedAt"`
	Deadline           time.Time         `json:"deadline"`
}

type PlannedCriterion struct {
	Criterion Criterion `json:"criterion"`
	Prompt    string    `json:"prompt,omitempty"`
	PromptSHA string    `json:"promptSha256,omitempty"`
}

type PlannedTarget struct {
	TargetID       string                 `json:"targetId"`
	FriendlyName   string                 `json:"friendlyName"`
	SourceBindings []SourceBinding        `json:"sourceBindings"`
	InstalledTasks []InstalledTaskBinding `json:"installedTasks"`
	StrategyPolicy StrategyPolicy         `json:"strategyPolicy"`
	Acquisition    AcquisitionPolicy      `json:"acquisition"`
	Criteria       []PlannedCriterion     `json:"criteria"`
}

type StepKind string

const (
	StepResolveSource  StepKind = "resolve_source"
	StepReadExisting   StepKind = "read_existing_evidence"
	StepAcquireMedia   StepKind = "acquire_media"
	StepOpenMedia      StepKind = "open_media"
	StepTransformMedia StepKind = "transform_media"
	StepAnalyze        StepKind = "analyze"
	StepValidateResult StepKind = "validate_result"
	StepAggregate      StepKind = "aggregate"
	StepCleanup        StepKind = "cleanup"
)

type StepAuthority string

const (
	StepAuthorityNone                StepAuthority = "none"
	StepAuthorityDeviceRead          StepAuthority = "device_read"
	StepAuthorityInspectionExecution StepAuthority = "inspection_execution"
)

// StepValueKind is the closed type of a frozen step output. A logical
// reference alone cannot distinguish media evidence from an analysis result
// or another opaque runtime value.
type StepValueKind string

const (
	StepValueResolvedSources  StepValueKind = "resolved_sources"
	StepValueExistingEvidence StepValueKind = "existing_evidence"
	StepValueMedia            StepValueKind = "media"
	StepValueAnalysis         StepValueKind = "analysis"
	StepValueResult           StepValueKind = "result"
	StepValueOutcome          StepValueKind = "outcome"
	StepValueCleanup          StepValueKind = "cleanup"
)

type StepOutputSlot struct {
	LogicalRef string        `json:"logicalRef"`
	Kind       StepValueKind `json:"kind"`
}

type ReconciliationPolicy string

const (
	ReconcilePureReplay       ReconciliationPolicy = "pure_replay"
	ReconcileIdempotencyKey   ReconciliationPolicy = "idempotency_key"
	ReconcileBeforeRetry      ReconciliationPolicy = "reconcile_before_retry"
	ReconcileNeverBlindReplay ReconciliationPolicy = "never_blind_replay"
)

type StepBudget struct {
	MaxFrames          int   `json:"maxFrames"`
	MaxBytes           int64 `json:"maxBytes"`
	MaxDurationSeconds int   `json:"maxDurationSeconds"`
	MaxAttempts        int   `json:"maxAttempts"`
}

// ExecutionStep is one frozen node in a closed, CosmoEdge Connect-owned pipeline. Its
// references are logical opaque slots; it contains no media bytes, prompt
// candidate, device locator, credential, or arbitrary tool name.
type ExecutionStep struct {
	Sequence       int                  `json:"sequence"`
	StepID         string               `json:"stepId"`
	Kind           StepKind             `json:"kind"`
	Authority      StepAuthority        `json:"authority"`
	TargetID       string               `json:"targetId,omitempty"`
	CriterionID    string               `json:"criterionId,omitempty"`
	SourceHandle   string               `json:"sourceHandle,omitempty"`
	TaskID         string               `json:"taskId,omitempty"`
	CapabilityRefs []string             `json:"capabilityRefs"`
	DependsOn      []string             `json:"dependsOn"`
	InputRefs      []string             `json:"inputRefs"`
	OutputSlots    []StepOutputSlot     `json:"outputSlots"`
	Budget         StepBudget           `json:"budget"`
	Deadline       time.Time            `json:"deadline"`
	Reconciliation ReconciliationPolicy `json:"reconciliation"`
	AlwaysRun      bool                 `json:"alwaysRun,omitempty"`
}

type ExecutionPlan struct {
	Schema                   string          `json:"schema"`
	TenantID                 string          `json:"tenantId"`
	SiteID                   string          `json:"siteId"`
	TemplateID               string          `json:"templateId"`
	TemplateRevision         uint64          `json:"templateRevision"`
	AssignmentID             string          `json:"assignmentId"`
	AssignmentRevision       uint64          `json:"assignmentRevision"`
	SourceCatalogFingerprint string          `json:"sourceCatalogFingerprint"`
	Origin                   RunOrigin       `json:"origin"`
	RequestID                string          `json:"requestId"`
	RequestKey               string          `json:"requestKey"`
	Targets                  []PlannedTarget `json:"targets"`
	Steps                    []ExecutionStep `json:"steps"`
	Budget                   ResourceBudget  `json:"budget"`
	Evidence                 EvidencePolicy  `json:"evidence"`
	OutputSchemaVersion      string          `json:"outputSchemaVersion"`
	RequestedAt              time.Time       `json:"requestedAt"`
	Deadline                 time.Time       `json:"deadline"`
	PlanSHA256               string          `json:"planSha256"`
}

type Run struct {
	RunID                  string    `json:"runId"`
	TenantID               string    `json:"tenantId"`
	SiteID                 string    `json:"siteId"`
	RequestKey             string    `json:"requestKey"`
	PlanSHA256             string    `json:"planSha256"`
	State                  RunState  `json:"state"`
	Conclusion             string    `json:"conclusion"`
	Reason                 string    `json:"reason"`
	PersistentConfigWrites int       `json:"persistentConfigWrites"`
	TemporaryResources     int       `json:"temporaryResources"`
	CleanupPending         int       `json:"cleanupPending"`
	CreatedAt              time.Time `json:"createdAt"`
	UpdatedAt              time.Time `json:"updatedAt"`
	Deadline               time.Time `json:"deadline"`
}

type RunEvent struct {
	Sequence   int64           `json:"sequence,omitempty"`
	RunID      string          `json:"runId"`
	Type       string          `json:"type"`
	From       RunState        `json:"from,omitempty"`
	To         RunState        `json:"to,omitempty"`
	Phase      RunPhase        `json:"phase,omitempty"`
	Reason     string          `json:"reason"`
	OccurredAt time.Time       `json:"occurredAt"`
	PublicJSON json.RawMessage `json:"publicJson,omitempty"`
}

// ResultUsage separates ordinary persisted inspection results from temporary
// observations. Only the latter may carry policy-bound display text.
type ResultUsage string

const (
	ResultUsageInspection           ResultUsage = "inspection"
	ResultUsageTemporaryObservation ResultUsage = "temporary_observation"
)

type ResultObservability string

const (
	ResultFullyVisible     ResultObservability = "fully_visible"
	ResultPartiallyVisible ResultObservability = "partially_visible"
	ResultNotVisible       ResultObservability = "not_visible"
	ResultUnusable         ResultObservability = "unusable"
)

// ResultTimeWindow is the exact scene-time interval represented by a result.
// It is distinct from analyzer execution time.
type ResultTimeWindow struct {
	StartAt time.Time `json:"startAt"`
	EndAt   time.Time `json:"endAt"`
}

// ResultSourceMedia binds one opaque media reference to the opaque source that
// produced it. Native camera identifiers, endpoints, credentials, and paths
// never enter this contract.
type ResultSourceMedia struct {
	SourceRef     string    `json:"sourceRef"`
	MediaRef      string    `json:"mediaRef"`
	SHA256        string    `json:"sha256"`
	CapturedAt    time.Time `json:"capturedAt"`
	FreshnessMS   int64     `json:"freshnessMs"`
	SampleOrdinal int       `json:"sampleOrdinal"`
}

// ResultBinding is entirely CosmoEdge Connect-owned. It binds a value to the frozen
// criterion, target, source/media set, scene-time window, and output schema.
type ResultBinding struct {
	ResultID            string              `json:"resultId"`
	RunID               string              `json:"runId"`
	StepID              string              `json:"stepId"`
	TargetID            string              `json:"targetId"`
	CriterionID         string              `json:"criterionId"`
	CriterionVersion    string              `json:"criterionVersion"`
	OutputKind          ResultKind          `json:"outputKind"`
	OutputSchemaVersion string              `json:"outputSchemaVersion"`
	Usage               ResultUsage         `json:"usage"`
	TimeWindow          ResultTimeWindow    `json:"timeWindow"`
	SourceMedia         []ResultSourceMedia `json:"sourceMedia"`
}

type ResultAnalyzerKind string

const (
	ResultAnalyzerCV      ResultAnalyzerKind = "cv"
	ResultAnalyzerVLM     ResultAnalyzerKind = "vlm"
	ResultAnalyzerHybrid  ResultAnalyzerKind = "hybrid"
	ResultAnalyzerEvent   ResultAnalyzerKind = "event"
	ResultAnalyzerFixture ResultAnalyzerKind = "fixture"
)

type ResultAnalyzer struct {
	Kind                  ResultAnalyzerKind `json:"kind"`
	AdapterVersion        string             `json:"adapterVersion"`
	ModelPolicy           string             `json:"modelPolicy"`
	ResolvedModelVersion  string             `json:"resolvedModelVersion,omitempty"`
	PromptTemplateID      string             `json:"promptTemplateId"`
	PromptTemplateVersion string             `json:"promptTemplateVersion"`
	PromptTemplateSHA256  string             `json:"promptTemplateSha256"`
}

// ResultExecution records trusted execution facts; model output cannot set or
// override these values.
type ResultExecution struct {
	Attempt                   int       `json:"attempt"`
	StartedAt                 time.Time `json:"startedAt"`
	CompletedAt               time.Time `json:"completedAt"`
	LatencyMS                 int64     `json:"latencyMs"`
	TemporaryResourcesCreated int       `json:"temporaryResourcesCreated"`
	TemporaryResourcesCleaned int       `json:"temporaryResourcesCleaned"`
	PersistentConfigWrites    int       `json:"persistentConfigWrites"`
}

type ResultIntegrity struct {
	RawOutputSHA256 string `json:"rawOutputSha256"`
	ContractSHA256  string `json:"contractSha256"`
}

type NormalizedRegion struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type ClassificationValue struct {
	Label string   `json:"label"`
	Score *float64 `json:"score,omitempty"`
}

type EnumValue struct {
	Value string `json:"value"`
}

type StructuredScalarKind string

const (
	StructuredEnum    StructuredScalarKind = "enum"
	StructuredNumber  StructuredScalarKind = "number"
	StructuredInteger StructuredScalarKind = "integer"
	StructuredBoolean StructuredScalarKind = "boolean"
)

// StructuredScalar is itself a strict union. Arbitrary text is deliberately
// excluded because it would become an unrestricted model-prose channel.
type StructuredScalar struct {
	Kind    StructuredScalarKind `json:"kind"`
	Enum    *string              `json:"enum,omitempty"`
	Number  *float64             `json:"number,omitempty"`
	Integer *int64               `json:"integer,omitempty"`
	Boolean *bool                `json:"boolean,omitempty"`
}

type StructuredField struct {
	Name  string           `json:"name"`
	Value StructuredScalar `json:"value"`
}

type StructuredValue struct {
	Fields []StructuredField `json:"fields"`
}

type MetricValue struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type DetectionObject struct {
	Label       string           `json:"label"`
	Score       *float64         `json:"score,omitempty"`
	Region      NormalizedRegion `json:"region"`
	EvidenceRef string           `json:"evidenceRef"`
}

type DetectionValue struct {
	Objects []DetectionObject `json:"objects"`
}

type CountValue struct {
	Value int64  `json:"value"`
	Label string `json:"label"`
	Unit  string `json:"unit"`
}

type EventState string

const (
	EventOccurred EventState = "occurred"
	EventStarted  EventState = "started"
	EventActive   EventState = "active"
	EventEnded    EventState = "ended"
)

type EventValue struct {
	Type        string     `json:"type"`
	State       EventState `json:"state"`
	OccurredAt  time.Time  `json:"occurredAt"`
	EvidenceRef string     `json:"evidenceRef"`
}

// ResultValue is a strict tagged union. Exactly one pointer must be non-nil and
// it must match Kind.
type ResultValue struct {
	Kind           ResultKind           `json:"kind"`
	Classification *ClassificationValue `json:"classification,omitempty"`
	Enum           *EnumValue           `json:"enum,omitempty"`
	Structured     *StructuredValue     `json:"structured,omitempty"`
	Metric         *MetricValue         `json:"metric,omitempty"`
	Detection      *DetectionValue      `json:"detection,omitempty"`
	Count          *CountValue          `json:"count,omitempty"`
	Event          *EventValue          `json:"event,omitempty"`
}

// PolicyBoundDisplay is allowed only for temporary observations and is never
// projected into a standard inspection report.
type PolicyBoundDisplay struct {
	PolicyRef string `json:"policyRef"`
	Locale    string `json:"locale"`
	Text      string `json:"text"`
}

// AnalysisResult is the durable typed result. Candidate-controlled fields are
// intentionally separated from CosmoEdge Connect-owned binding, analyzer, execution,
// and integrity facts.
type AnalysisResult struct {
	Binding       ResultBinding       `json:"binding"`
	Assessment    Assessment          `json:"assessment"`
	Observability ResultObservability `json:"observability"`
	Confidence    *float64            `json:"confidence,omitempty"`
	Value         *ResultValue        `json:"value,omitempty"`
	EvidenceRefs  []string            `json:"evidenceRefs"`
	ReasonCodes   []string            `json:"reasonCodes"`
	Limitations   []string            `json:"limitations"`
	Display       *PolicyBoundDisplay `json:"display,omitempty"`
	Analyzer      ResultAnalyzer      `json:"analyzer"`
	Execution     ResultExecution     `json:"execution"`
	Integrity     ResultIntegrity     `json:"integrity"`
}

type Observation struct {
	ObservationID string         `json:"observationId"`
	SampleID      string         `json:"sampleId"`
	Result        AnalysisResult `json:"result"`
}

type Finding struct {
	TargetID     string             `json:"targetId"`
	CriterionID  string             `json:"criterionId"`
	Assessment   Assessment         `json:"assessment"`
	SampleCount  int                `json:"sampleCount"`
	ReasonCodes  []string           `json:"reasonCodes"`
	EvidenceRefs []string           `json:"evidenceRefs"`
	Results      []ResultProjection `json:"results"`
	ObservedAt   time.Time          `json:"observedAt"`
	Limitations  []string           `json:"limitations"`
}

// ResultProjection is the Oracle-owned, prose-free projection retained for a
// standard report. Source identities, analyzer details, and temporary display
// text remain in the underlying observation only.
type ResultProjection struct {
	ResultID     string           `json:"resultId"`
	SampleID     string           `json:"sampleId"`
	OutputKind   ResultKind       `json:"outputKind"`
	Value        *ResultValue     `json:"value,omitempty"`
	EvidenceRefs []string         `json:"evidenceRefs"`
	TimeWindow   ResultTimeWindow `json:"timeWindow"`
}

type Coverage struct {
	Required     int     `json:"required"`
	Conclusive   int     `json:"conclusive"`
	Inconclusive int     `json:"inconclusive"`
	Missing      int     `json:"missing"`
	Ratio        float64 `json:"ratio"`
}

type Outcome struct {
	State             RunState   `json:"state"`
	OverallAssessment Assessment `json:"overallAssessment"`
	Coverage          Coverage   `json:"coverage"`
	Findings          []Finding  `json:"findings"`
	Conclusion        string     `json:"conclusion"`
	Reason            string     `json:"reason"`
}
