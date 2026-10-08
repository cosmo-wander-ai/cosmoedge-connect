package temporary

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
)

const (
	RuntimeSchemaVersion  = "cosmoedge.inspection.temporary.runtime.v4"
	TerminalSchemaVersion = "cosmoedge.inspection.temporary.terminal.v4"

	MaxRunDuration = 30 * time.Minute
	MaxLeaseTTL    = 10 * time.Minute
	MaxMediaBytes  = 32 << 20
	MaxPrepPolls   = 1_000_000
)

var (
	ErrRuntimeInvalid           = errors.New("temporary observation runtime input is invalid")
	ErrRuntimeConflict          = errors.New("temporary observation runtime identity conflicts with stored state")
	ErrRuntimeNotFound          = errors.New("temporary observation runtime record was not found")
	ErrRuntimeLeaseLost         = errors.New("temporary observation runtime lease was lost")
	ErrRuntimeCorrupt           = errors.New("temporary observation runtime store integrity failure")
	ErrRuntimeSchema            = errors.New("temporary observation runtime store schema is unsupported")
	ErrAnalysisDefinitelyFailed = errors.New("temporary observation analysis definitely failed")
	ErrAnalysisOutcomeUnknown   = errors.New("temporary observation analysis outcome is unknown")

	runtimeRefPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	runtimeMediaRefPattern = regexp.MustCompile(`^media_[0-9a-f]{32}$`)
	runtimePrepRefPattern  = regexp.MustCompile(`^media_prep_[0-9a-f]{32}$`)
	runtimeDigestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// AuthenticatedBinding is supplied only after the channel adapter has
// authenticated and resolved the request. It deliberately contains no raw
// message, endpoint, credential, device identifier, or native camera handle.
type AuthenticatedBinding struct {
	TenantID        string `json:"tenantId"`
	SiteID          string `json:"siteId"`
	RequestKey      string `json:"requestKey"`
	PublicRunRef    string `json:"publicRunRef"`
	Channel         string `json:"channel"`
	ConversationRef string `json:"conversationRef"`
	RecipientRef    string `json:"recipientRef"`
	PrincipalSHA256 string `json:"principalSha256"`
}

// ChannelSession is the complete authenticated business-channel audience.
// It intentionally contains no request text, source, capability, endpoint, or
// device identity.
type ChannelSession struct {
	TenantID        string
	SiteID          string
	Channel         string
	ConversationRef string
	RecipientRef    string
	PrincipalSHA256 string
}

type AudienceBinding struct {
	Ref    string
	SHA256 string
}

// Submission freezes one already-resolved request onto one durable media
// preparation. No MediaRef exists yet: acquisition and publication happen in
// the independent mediaprep worker after the public request is accepted.
type Submission struct {
	Binding            AuthenticatedBinding
	Spec               TemporaryObservationSpec
	PreparationRef     string
	MediaKind          media.Kind
	AudienceBindingRef string
	AudienceSHA256     string
	EvidenceExpiresAt  time.Time
	SubmittedAt        time.Time
	DeadlineAt         time.Time
}

// Validate checks the complete frozen submission without exposing the stable
// identity derivation used by the runtime store.
func (s Submission) Validate() error { return s.validate() }

type State string

const (
	StateQueued           State = "queued"
	StateRunning          State = "running"
	StateSucceeded        State = "succeeded"
	StateInvalidCandidate State = "invalid_candidate"
	StateExpired          State = "expired"
	StateOutcomeUnknown   State = "outcome_unknown"
	StateFailed           State = "failed"
)

type Phase string

const (
	PhaseNone      Phase = "none"
	PhasePreparing Phase = "preparing"
	PhaseAnalyzing Phase = "analyzing"
)

type Reason string

const (
	ReasonSubmitted                Reason = "submitted"
	ReasonClaimed                  Reason = "claimed"
	ReasonPreparationPending       Reason = "preparation_pending"
	ReasonPreparationReady         Reason = "preparation_ready"
	ReasonPreparationFailed        Reason = "preparation_failed"
	ReasonPreparationExpired       Reason = "preparation_expired"
	ReasonRecoveredBeforeAnalysis  Reason = "recovered_before_analysis"
	ReasonCompleted                Reason = "completed"
	ReasonCandidateInvalid         Reason = "candidate_invalid"
	ReasonDeadlineExpired          Reason = "deadline_expired"
	ReasonAnalysisOutcomeUnknown   Reason = "analysis_outcome_unknown"
	ReasonAnalysisDefinitelyFailed Reason = "analysis_definitely_failed"
	ReasonMediaUnavailable         Reason = "media_unavailable"
	ReasonMediaInvalid             Reason = "media_invalid"
)

type MediaDescriptor struct {
	MediaRef           string         `json:"mediaRef"`
	Kind               media.Kind     `json:"kind"`
	TenantID           string         `json:"tenantId"`
	SiteID             string         `json:"siteId"`
	RunID              string         `json:"runId"`
	StepID             string         `json:"stepId"`
	Attempt            int            `json:"attempt"`
	AudienceBindingRef string         `json:"audienceBindingRef"`
	SHA256             string         `json:"sha256"`
	MIMEType           string         `json:"mimeType"`
	SizeBytes          int64          `json:"sizeBytes"`
	Temporal           media.Temporal `json:"temporal"`
	ExpiresAt          time.Time      `json:"expiresAt"`
}

// MediaReader can only resolve and read an opaque media reference. A device
// endpoint, credential, native identifier, or local path cannot be supplied
// through this port.
type MediaReader interface {
	Describe(context.Context, string) (MediaDescriptor, error)
	Open(context.Context, string) (io.ReadCloser, error)
}

// PreparationReader is the sole temporary-runtime view of media acquisition.
// The authoritative manager implements it directly; this port cannot create,
// mutate, or reacquire a preparation.
type PreparationReader interface {
	Get(context.Context, string) (mediaprep.Status, error)
}

type AnalysisEvidence struct {
	EvidenceRef string
	SHA256      string
	MIMEType    string
	CapturedAt  time.Time
	ExpiresAt   time.Time
	Content     []byte
}

type AnalysisRequest struct {
	RunID    string
	Prompt   CompiledPrompt
	Evidence AnalysisEvidence
}

// Analyzer returns bounded candidate JSON. Raw model output is never written
// by this package. Any error not explicitly wrapping
// ErrAnalysisDefinitelyFailed is conservatively treated as outcome_unknown
// once analysis has begun.
type Analyzer interface {
	Analyze(context.Context, AnalysisRequest) ([]byte, error)
}

type Lease struct {
	RunID          string
	Generation     uint64
	Owner          string
	StartedAt      time.Time
	LeaseExpiresAt time.Time
}

type Record struct {
	Schema             string                   `json:"schema"`
	RunID              string                   `json:"runId"`
	IdentitySHA256     string                   `json:"identitySha256"`
	Binding            AuthenticatedBinding     `json:"binding"`
	Spec               TemporaryObservationSpec `json:"spec"`
	PreparationRef     string                   `json:"preparationRef"`
	MediaKind          media.Kind               `json:"mediaKind"`
	AudienceBindingRef string                   `json:"audienceBindingRef"`
	AudienceSHA256     string                   `json:"audienceSha256"`
	EvidenceExpiresAt  time.Time                `json:"evidenceExpiresAt"`
	MediaRef           string                   `json:"mediaRef,omitempty"`
	State              State                    `json:"state"`
	Phase              Phase                    `json:"phase"`
	Reason             Reason                   `json:"reason"`
	Attempt            int                      `json:"attempt"`
	PreparationPolls   int                      `json:"preparationPolls"`
	Generation         uint64                   `json:"generation"`
	AvailableAt        time.Time                `json:"availableAt"`
	SubmittedAt        time.Time                `json:"submittedAt"`
	DeadlineAt         time.Time                `json:"deadlineAt"`
	UpdatedAt          time.Time                `json:"updatedAt"`
	CompletedAt        time.Time                `json:"completedAt,omitempty"`
	LeaseOwner         string                   `json:"leaseOwner,omitempty"`
	LeaseExpiresAt     time.Time                `json:"leaseExpiresAt,omitempty"`
	PromptSHA256       string                   `json:"promptSha256,omitempty"`
	Media              *MediaDescriptor         `json:"media,omitempty"`
	Candidate          *Candidate               `json:"candidate,omitempty"`
	Observation        *Observation             `json:"observation,omitempty"`
	ResultRef          string                   `json:"resultRef,omitempty"`
	ResultSHA256       string                   `json:"resultSha256,omitempty"`
}

func (r Record) String() string   { return "[temporary-observation-runtime-record]" }
func (r Record) GoString() string { return "temporary.Record([redacted])" }
func (r Record) LogValue() slog.Value {
	return slog.StringValue("[temporary-observation-runtime-record]")
}

// Validate verifies the full persisted runtime record and all trusted
// bindings. Application adapters should call it before publishing state.
func (r Record) Validate() error { return validateRecord(r) }

type TerminalEvent struct {
	Schema       string    `json:"schema"`
	EventID      string    `json:"eventId"`
	RunID        string    `json:"runId"`
	PublicRunRef string    `json:"publicRunRef"`
	ResultRef    string    `json:"resultRef"`
	State        State     `json:"state"`
	ResultSHA256 string    `json:"resultSha256,omitempty"`
	OccurredAt   time.Time `json:"occurredAt"`
}

type TerminalLease struct {
	Event          TerminalEvent
	Owner          string
	StartedAt      time.Time
	LeaseExpiresAt time.Time
}

func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateInvalidCandidate, StateExpired, StateOutcomeUnknown, StateFailed:
		return true
	default:
		return false
	}
}
