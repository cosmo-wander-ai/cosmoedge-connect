// Package inspectionadapter binds the Inspection v2 runtime to one live
// CosmoEdge device session. It deliberately owns no login/session lifecycle:
// callers provide an already-authorized client through ConnectionProvider.
package inspectionadapter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

var (
	// Client errors are intentionally transport-neutral. A concrete CosmoEdge
	// client must classify every ambiguous HTTP/decode/device outcome as
	// ErrOutcomeUnknown; the adapter will never turn it into a blind retry.
	ErrUnavailable       = errors.New("live CosmoEdge connection is unavailable")
	ErrBindingStale      = errors.New("live CosmoEdge binding is stale")
	ErrResourceBusy      = errors.New("live CosmoEdge resource is busy")
	ErrOutcomeUnknown    = errors.New("live CosmoEdge operation outcome is unknown")
	ErrUnsupported       = errors.New("live CosmoEdge operation is unsupported")
	ErrAuthorityRejected = errors.New("live CosmoEdge authority was rejected")
	ErrInvalidResponse   = errors.New("live CosmoEdge response is invalid")
	ErrRecordNotFound    = errors.New("inspection adapter record was not found")
	ErrRecordConflict    = errors.New("inspection adapter record conflicts with durable state")
	ErrProtectedValue    = errors.New("protected CosmoEdge value cannot be projected")
)

// ProtectedLocator is a catalog-owned native locator. It can be revealed only
// by the concrete live client; formatting and serialization always redact it.
// It must never be copied into a runtime result, log, error, or chat response.
type ProtectedLocator struct{ value string }

func protectedLocator(value string) ProtectedLocator  { return ProtectedLocator{value: value} }
func (v ProtectedLocator) Reveal() string             { return v.value }
func (v ProtectedLocator) Empty() bool                { return v.value == "" }
func (ProtectedLocator) MarshalJSON() ([]byte, error) { return nil, ErrProtectedValue }
func (ProtectedLocator) MarshalText() ([]byte, error) { return nil, ErrProtectedValue }
func (ProtectedLocator) String() string               { return "[protected-cosmoedge-locator]" }
func (ProtectedLocator) GoString() string             { return "inspectionadapter.ProtectedLocator([redacted])" }
func (ProtectedLocator) LogValue() slog.Value {
	return slog.StringValue("[protected-cosmoedge-locator]")
}

// ConnectionProvider resolves the current foreground live connection for one
// protected device profile. The first implementation may use the Operator's
// in-memory connection, but this seam intentionally does not expose session.Vault
// or any credential-bearing profile type to the inspection runtime.
type ConnectionProvider interface {
	LiveClient(context.Context, string, string, string) (LiveClient, error)
}

// LiveClient is the narrow real-device surface required by the first vertical
// Inspection v2 slice. Requests contain no endpoint, credential, stream URL,
// or arbitrary device method name.
type LiveClient interface {
	Resolve(context.Context, LiveResolveRequest) (LiveResolveResult, error)
	CaptureSnapshot(context.Context, SnapshotRequest) (SnapshotResponse, error)
	ReadExistingEvidence(context.Context, ExistingEvidenceRequest) (ExistingEvidenceResponse, error)
	Analyze(context.Context, AnalysisRequest) (AnalysisResponse, error)
	Cleanup(context.Context, LiveCleanupRequest) (LiveCleanupResponse, error)
}

type LiveSource struct {
	SourceHandle        string
	Kind                inspection.SourceKind
	IdentityFingerprint string
	CapabilityRefs      []string
	ROIRef              string
	NativeLocator       ProtectedLocator
}

type LiveTask struct {
	TaskID             string
	BindingFingerprint string
	CapabilityRefs     []string
	NativeLocator      ProtectedLocator
}

type LiveResolveRequest struct {
	RunID           string
	StepID          string
	Attempt         int
	IdempotencyKey  string
	DeviceProfileID string
	Sources         []LiveSource
	InstalledTasks  []LiveTask
	Deadline        time.Time
}

type VerifiedSource struct {
	SourceHandle        string
	IdentityFingerprint string
}

type VerifiedTask struct {
	TaskID             string
	BindingFingerprint string
}

type LiveResolveResult struct {
	Sources []VerifiedSource
	Tasks   []VerifiedTask
}

type SnapshotFreshness string

const (
	SnapshotFresh        SnapshotFreshness = "fresh_capture"
	SnapshotCached       SnapshotFreshness = "cached_fallback"
	SnapshotUnverifiable SnapshotFreshness = "unverifiable"
)

// SnapshotResponse contains bytes only. A concrete client may follow the
// device's GetPicture URL internally, but must require the same origin, a
// canonical /web/ path, a bounded JPEG response, and reject redirects outside
// that allowlist. The current device can silently fall back to /web/<channel>.jpg;
// that path must be reported as SnapshotCached, never as a fresh capture.
// ObservedAt is the local receive-completion time, not a device capture time.
type SnapshotResponse struct {
	Content           io.ReadCloser
	SourceFingerprint string
	Freshness         SnapshotFreshness
	ObservedAt        time.Time
}

type SnapshotRequest struct {
	RunID             string
	StepID            string
	Attempt           int
	IdempotencyKey    string
	DeviceProfileID   string
	SourceHandle      string
	SourceFingerprint string
	NativeLocator     ProtectedLocator
	ROIRef            string
	Deadline          time.Time
	MaxBytes          int64
}

// ExistingEvidenceResponse is a bounded typed device result and its JSON
// evidence document. Candidate.EvidenceRefs must be empty: only the adapter
// may bind model/device output to persisted media references.
type ExistingEvidenceResponse struct {
	Content           io.ReadCloser
	Kind              media.Kind
	MIMEType          string
	WindowStart       time.Time
	WindowEnd         time.Time
	Candidate         analysiscontract.Candidate
	EvidenceOrdinals  []int
	SourceFingerprint string
	TaskFingerprint   string
}

type ExistingEvidenceRequest struct {
	RunID             string
	StepID            string
	Attempt           int
	IdempotencyKey    string
	DeviceProfileID   string
	SourceHandle      string
	SourceFingerprint string
	SourceLocator     ProtectedLocator
	TaskID            string
	TaskFingerprint   string
	TaskLocator       ProtectedLocator
	CapabilityRefs    []string
	Deadline          time.Time
	MaxBytes          int64
}

// AnalysisMedia is valid only for the duration of LiveClient.Analyze. The
// client must consume Content synchronously and must not retain the reader.
type AnalysisMedia struct {
	Ordinal    int
	Descriptor media.Descriptor
	Content    io.Reader
}

type AnalysisRequest struct {
	RunID             string
	StepID            string
	Attempt           int
	IdempotencyKey    string
	DeviceProfileID   string
	CriterionID       string
	Method            inspection.Method
	AnalysisPolicyRef string
	Prompt            string
	PromptSHA256      string
	Output            inspection.OutputContract
	Inputs            []AnalysisMedia
	Deadline          time.Time
	MaxBytes          int64
	MaxFrames         int
}

// AnalysisResponse is the synchronous result of PTaskDetectPic or an
// equivalent real-device analyzer call. CosmoEdge currently has no result
// re-query endpoint, so a concrete client must return ErrOutcomeUnknown for an
// ambiguous transport/decode result. Candidate.EvidenceRefs must be empty;
// EvidenceOrdinals are one-based positions in AnalysisRequest.Inputs.
type AnalysisResponse struct {
	Candidate        analysiscontract.Candidate
	EvidenceOrdinals []int
	ModelVersion     string
}

type CleanupState string

const (
	CleanupRemoved CleanupState = "removed"
	CleanupPending CleanupState = "pending"
)

type LiveCleanupItem struct {
	ValueRef     string
	ProducerKind inspection.StepKind
}

type LiveCleanupRequest struct {
	RunID           string
	StepID          string
	Attempt         int
	IdempotencyKey  string
	DeviceProfileID string
	Inputs          []LiveCleanupItem
	Deadline        time.Time
}

type LiveCleanupItemResult struct {
	ValueRef string
	State    CleanupState
}

// Cleanup must reconcile every requested logical resource. PTaskCancle being
// successful for a missing task is not proof that a previously ambiguous
// create was cleaned; clients must report CleanupPending when absence cannot
// be proven.
type LiveCleanupResponse struct {
	Items []LiveCleanupItemResult
}

// ResolutionRecord and the result records contain no native locator. They are
// safe to keep in a durable local adapter ledger and are required for exact
// replay/result lookup across process restarts.
type ResolutionRecord struct {
	ResolutionRef   string                            `json:"resolutionRef"`
	RequestSHA256   string                            `json:"requestSha256"`
	RunID           string                            `json:"runId"`
	StepID          string                            `json:"stepId"`
	Attempt         int                               `json:"attempt"`
	TenantID        string                            `json:"tenantId"`
	SiteID          string                            `json:"siteId"`
	TargetID        string                            `json:"targetId"`
	DeviceProfileID string                            `json:"deviceProfileId"`
	Sources         []inspection.SourceBinding        `json:"sources"`
	InstalledTasks  []inspection.InstalledTaskBinding `json:"installedTasks"`
	AdapterVersion  string                            `json:"adapterVersion"`
	ResolvedAt      time.Time                         `json:"resolvedAt"`
}

type AcquisitionRecord struct {
	IdempotencyKey  string                               `json:"idempotencyKey"`
	RequestSHA256   string                               `json:"requestSha256"`
	DeviceProfileID string                               `json:"deviceProfileId"`
	Result          inspectionruntime.MediaAcquireResult `json:"result"`
}

type ExistingRecord struct {
	RequestSHA256   string                                   `json:"requestSha256"`
	DeviceProfileID string                                   `json:"deviceProfileId"`
	Result          inspectionruntime.ExistingEvidenceResult `json:"result"`
}

type AnalysisRecord struct {
	RequestSHA256   string                              `json:"requestSha256"`
	DeviceProfileID string                              `json:"deviceProfileId"`
	Result          inspectionruntime.AnalysisReference `json:"result"`
}

type CleanupRecordState string

const (
	CleanupRecordPending   CleanupRecordState = "pending"
	CleanupRecordCompleted CleanupRecordState = "completed"
)

type CleanupRecord struct {
	IdempotencyKey  string                          `json:"idempotencyKey"`
	RequestSHA256   string                          `json:"requestSha256"`
	DeviceProfileID string                          `json:"deviceProfileId"`
	State           CleanupRecordState              `json:"state"`
	Result          inspectionruntime.CleanupResult `json:"result"`
}

// RecordStore must be durable and exact-idempotent. Put methods must reject a
// conflicting value for an existing key/reference; Get methods return
// ErrRecordNotFound only when no value has ever been durably published.
// No in-memory fallback is supplied by this package.
type RecordStore interface {
	PutResolution(context.Context, ResolutionRecord) error
	Resolution(context.Context, string) (ResolutionRecord, error)
	PutAcquisition(context.Context, AcquisitionRecord) error
	Acquisition(context.Context, string) (AcquisitionRecord, error)
	AcquisitionByMedia(context.Context, string) (AcquisitionRecord, error)
	PutExisting(context.Context, ExistingRecord) error
	Existing(context.Context, string) (ExistingRecord, error)
	PutAnalysis(context.Context, AnalysisRecord) error
	Analysis(context.Context, string) (AnalysisRecord, error)
	// ReserveCleanup atomically inserts a pending record or returns the exact
	// existing record. CompleteCleanup is the only permitted pending->completed
	// transition. This prevents ReconcileNeverBlindReplay from issuing a second
	// device cleanup after a process crash with an unknown first outcome.
	ReserveCleanup(context.Context, CleanupRecord) (CleanupRecord, bool, error)
	CompleteCleanup(context.Context, CleanupRecord) error
	Cleanup(context.Context, string) (CleanupRecord, error)
}
