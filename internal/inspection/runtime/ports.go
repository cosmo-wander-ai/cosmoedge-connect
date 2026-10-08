package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

var (
	ErrWaitingForSite    = errors.New("inspection site execution session is unavailable")
	ErrBindingStale      = errors.New("inspection execution binding is stale")
	ErrResourceBusy      = errors.New("inspection execution resource is busy")
	ErrOutcomeUnknown    = errors.New("inspection execution outcome is unknown")
	ErrUnsupported       = errors.New("inspection execution operation is unsupported")
	ErrAuthorityRejected = errors.New("inspection execution authority was rejected")
)

type Repository interface {
	CreateQueuedRun(context.Context, inspection.ExecutionPlan, string, time.Time) (inspection.Run, bool, error)
	GetRun(context.Context, string) (inspection.Run, error)
	ClaimNext(context.Context, string, time.Time, time.Duration) (inspection.Run, inspection.ExecutionPlan, bool, error)
	RenewLease(context.Context, string, string, time.Time, time.Duration) error
	AppendPhase(context.Context, string, string, inspection.RunPhase, time.Time, string) error
	RecordObservation(context.Context, string, inspection.Observation, time.Time) error
	ListObservations(context.Context, string) ([]inspection.Observation, error)
	RecordResourceUsage(context.Context, string, string, int, int, time.Time) error
	BeginFinalization(context.Context, string, string, time.Time) error
	Finalize(context.Context, string, string, inspection.Outcome, time.Time) error
	Cancel(context.Context, string, time.Time, string) error
	ExpireQueued(context.Context, time.Time) (int, error)
	RecoverInterrupted(context.Context, time.Time) (int, error)
	RecoverExpiredStepAttempts(context.Context, time.Time) (int, error)
	ListPendingAuthorityReleases(context.Context, int) ([]string, error)
	MarkAuthorityReleased(context.Context, string, time.Time) error
	ListSteps(context.Context, string) ([]inspection.StepRecord, error)
	ClaimNextStep(context.Context, string, string, string, time.Time, time.Duration) (inspection.StepRecord, inspection.StepAttempt, bool, error)
	RenewStepAttemptLease(context.Context, string, string, string, string, time.Time, time.Duration) error
	CompleteStep(context.Context, string, string, string, string, inspection.StepState, []inspection.StepOutput, string, time.Time) error
}

// Ports is the closed runtime dependency set. There is intentionally no
// catch-all executor and no default implementation that can reach a device.
type Ports struct {
	Sources     SourceResolver
	Existing    ExistingEvidenceReader
	Acquisition MediaAcquirer
	Transform   MediaTransformer
	Analysis    Analyzer
	Cleanup     TemporaryResourceCleaner
}

func (p Ports) validate() error {
	if p.Sources == nil || p.Existing == nil || p.Acquisition == nil || p.Transform == nil || p.Analysis == nil || p.Cleanup == nil {
		return errors.New("all six inspection runtime ports are required")
	}
	return nil
}

type ResolveSourceRequest struct {
	RunID          string
	StepID         string
	TenantID       string
	SiteID         string
	TargetID       string
	Sources        []inspection.SourceBinding
	InstalledTasks []inspection.InstalledTaskBinding
	Attempt        int
	Deadline       time.Time
	Budget         inspection.StepBudget
}

type ResolvedSourceSet struct {
	RunID          string
	StepID         string
	Attempt        int
	ResolutionRef  string
	SHA256         string
	AdapterVersion string
}

type SourceResolver interface {
	Resolve(context.Context, ResolveSourceRequest) (ResolvedSourceSet, error)
}

// ExistingEvidenceRequest deliberately has no prompt or model field. Reading
// existing typed evidence is a device-read operation, not analysis authority.
type ExistingEvidenceRequest struct {
	RunID          string
	StepID         string
	TenantID       string
	SiteID         string
	TargetID       string
	ResolutionRef  string
	Source         inspection.SourceBinding
	InstalledTask  inspection.InstalledTaskBinding
	CapabilityRefs []string
	Attempt        int
	Deadline       time.Time
	Budget         inspection.StepBudget
}

type ExistingEvidenceResult struct {
	RunID          string
	StepID         string
	Attempt        int
	EvidenceRef    string
	SHA256         string
	Descriptor     media.Descriptor
	Candidate      analysiscontract.Candidate
	ObservedAt     time.Time
	AdapterVersion string
}

type ExistingEvidenceReader interface {
	Read(context.Context, ExistingEvidenceRequest) (ExistingEvidenceResult, error)
	Result(context.Context, string) (ExistingEvidenceResult, error)
}

type MediaAcquireRequest struct {
	Operation      inspection.StepKind
	RunID          string
	StepID         string
	TenantID       string
	SiteID         string
	TargetID       string
	ResolutionRef  string
	Source         inspection.SourceBinding
	Acquisition    inspection.AcquisitionPolicy
	Evidence       inspection.EvidencePolicy
	Attempt        int
	IdempotencyKey string
	Deadline       time.Time
	Budget         inspection.StepBudget
}

type MediaAcquireResult struct {
	Descriptor     media.Descriptor
	AdapterVersion string
}

type MediaAcquirer interface {
	Acquire(context.Context, MediaAcquireRequest) (MediaAcquireResult, error)
	Describe(context.Context, string) (media.Descriptor, error)
}

type MediaTransformRequest struct {
	RunID          string
	StepID         string
	TenantID       string
	SiteID         string
	TargetID       string
	SourceRef      string
	Input          media.Descriptor
	Acquisition    inspection.AcquisitionPolicy
	Evidence       inspection.EvidencePolicy
	Attempt        int
	IdempotencyKey string
	Deadline       time.Time
	Budget         inspection.StepBudget
}

type MediaTransformResult struct {
	Descriptor     media.Descriptor
	AdapterVersion string
}

type MediaTransformer interface {
	Transform(context.Context, MediaTransformRequest) (MediaTransformResult, error)
	Describe(context.Context, string) (media.Descriptor, error)
}

type AnalysisInput struct {
	ProducerStepID string
	ProducerKind   inspection.StepKind
	Attempt        int
	ValueRef       string
	SHA256         string
	Descriptor     *media.Descriptor
	Evidence       *ExistingEvidenceResult
}

// AnalyzeRequest contains only frozen analysis policy, prompt, and typed input
// references. It cannot carry a device connection, source binding, endpoint,
// credential, or resolution handle.
type AnalyzeRequest struct {
	RunID             string
	StepID            string
	TenantID          string
	SiteID            string
	TargetID          string
	CriterionID       string
	Attempt           int
	Method            inspection.Method
	AnalysisPolicyRef string
	Prompt            string
	PromptSHA256      string
	Output            inspection.OutputContract
	Inputs            []AnalysisInput
	IdempotencyKey    string
	Deadline          time.Time
	Budget            inspection.StepBudget
}

type AnalysisReference struct {
	RunID          string
	StepID         string
	Attempt        int
	ResultRef      string
	SHA256         string
	Candidate      analysiscontract.Candidate
	ModelVersion   string
	AdapterVersion string
	StartedAt      time.Time
	CompletedAt    time.Time
}

type Analyzer interface {
	Analyze(context.Context, AnalyzeRequest) (AnalysisReference, error)
	Result(context.Context, string) (AnalysisReference, error)
}

type ValueReference struct {
	LogicalRef     string
	ProducerStepID string
	Attempt        int
	ValueRef       string
	SHA256         string
	ProducerKind   inspection.StepKind
}

type CleanupRequest struct {
	RunID    string
	StepID   string
	TenantID string
	SiteID   string
	Attempt  int
	Inputs   []ValueReference
	Deadline time.Time
	Budget   inspection.StepBudget
}

type CleanupResult struct {
	RunID     string
	StepID    string
	Attempt   int
	ResultRef string
	SHA256    string
	Created   int
	Removed   int
	Pending   int
}

type TemporaryResourceCleaner interface {
	Cleanup(context.Context, CleanupRequest) (CleanupResult, error)
}
