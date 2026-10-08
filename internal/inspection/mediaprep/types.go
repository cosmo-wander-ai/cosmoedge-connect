// Package mediaprep durably coordinates one-shot temporary media acquisition
// and idempotent publication. It stores only opaque source/capability
// references; credentials and native device locators are outside this package.
package mediaprep

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

const RequestSchema = "cosmoedge.inspection.temporary-media-preparation.v2"

var (
	ErrInvalid             = errors.New("temporary media preparation is invalid")
	ErrConflict            = errors.New("temporary media preparation conflicts with stored state")
	ErrNotFound            = errors.New("temporary media preparation was not found")
	ErrLeaseLost           = errors.New("temporary media preparation lease was lost")
	ErrOutcomeUnknown      = errors.New("temporary media acquisition outcome is unknown")
	ErrPublicationUnknown  = errors.New("temporary media publication outcome is unknown")
	ErrPublicationRejected = errors.New("temporary media publication was rejected")
	ErrAcquirerContract    = errors.New("temporary media acquirer returned an invalid result")
	ErrIncompatibleStore   = errors.New("temporary media preparation store schema is unsupported")
	ErrCorruptStore        = errors.New("temporary media preparation store content is corrupt")
	ErrClosed              = errors.New("temporary media preparation manager is closed")
	ErrProtected           = errors.New("temporary media preparation data is protected")
)

type State string

const (
	StatePrepared           State = "prepared"
	StateAcquiringUnknown   State = "acquiring_unknown"
	StatePublicationUnknown State = "publication_unknown"
	StateReady              State = "ready"
	StateFailed             State = "failed"
)

type Reason string

const (
	ReasonPrepared                         Reason = "prepared"
	ReasonAcquisitionStarted               Reason = "acquisition_started"
	ReasonAcquisitionPending               Reason = "acquisition_pending"
	ReasonAcquisitionUnknown               Reason = "acquisition_unknown"
	ReasonReconciliationStarted            Reason = "reconciliation_started"
	ReasonReconciliationPending            Reason = "reconciliation_pending"
	ReasonReconciliationUnknown            Reason = "reconciliation_unknown"
	ReasonWorkerInterrupted                Reason = "worker_interrupted"
	ReasonAcquisitionFailed                Reason = "acquisition_failed"
	ReasonEvidenceExpired                  Reason = "evidence_expired"
	ReasonContentInvalid                   Reason = "content_invalid"
	ReasonPublicationStarted               Reason = "publication_started"
	ReasonPublicationProbeStarted          Reason = "publication_probe_started"
	ReasonPublicationReconciliationStarted Reason = "publication_reconciliation_started"
	ReasonPublicationUnknown               Reason = "publication_unknown"
	ReasonPublicationRejected              Reason = "publication_rejected"
	ReasonReady                            Reason = "ready"
)

// TimeScope is the exact, immutable requested acquisition scope. For an image,
// the equal start/end point is the earliest acceptable capture time; the
// adapter returns the actual capture time separately. For a clip, the adapter
// must return this exact requested interval. Requested time is never published
// as if it were observed time.
type TimeScope struct {
	WindowStart    time.Time `json:"windowStart"`
	WindowEnd      time.Time `json:"windowEnd"`
	DurationMillis int64     `json:"durationMillis"`
	SampleOrdinal  int       `json:"sampleOrdinal"`
}

// MediaSpec is the immutable ownership and governance contract. Encoding and
// observed time are deliberately absent because only the trusted acquisition
// adapter can report those facts after acquisition.
type MediaSpec struct {
	Kind               media.Kind    `json:"kind"`
	RunID              string        `json:"runId"`
	StepID             string        `json:"stepId"`
	Attempt            int           `json:"attempt"`
	Lineage            media.Lineage `json:"lineage"`
	PrivacyClass       string        `json:"privacyClass"`
	RedactionPolicyRef string        `json:"redactionPolicyRef,omitempty"`
	RetentionPolicyRef string        `json:"retentionPolicyRef"`
}

// FrozenRequest contains only opaque local references and policy metadata. It
// deliberately has no field capable of carrying a stream URL, network address,
// credential, token, filesystem path, or native device identifier.
type FrozenRequest struct {
	Schema        string    `json:"schema"`
	TenantID      string    `json:"tenantId"`
	SiteID        string    `json:"siteId"`
	RequestID     string    `json:"requestId"`
	SourceRef     string    `json:"sourceRef"`
	CapabilityRef string    `json:"capabilityRef"`
	TimeScope     TimeScope `json:"timeScope"`
	// AudienceBindingRef is one exact upstream-owned delivery binding. Its
	// authoritative digest is frozen verbatim; this package never expands it
	// into a recipient list or applies first-recipient fallback behavior.
	AudienceBindingRef string    `json:"audienceBindingRef"`
	AudienceSHA256     string    `json:"audienceSha256"`
	EvidenceExpiresAt  time.Time `json:"evidenceExpiresAt"`
	Media              MediaSpec `json:"media"`
}

// Validate performs the complete request-contract check without writing state
// or allocating an acquisition/publication identity outside this process.
func (request FrozenRequest) Validate() error {
	_, _, _, _, err := canonicalRequest(request)
	return err
}

func (FrozenRequest) MarshalJSON() ([]byte, error) { return nil, ErrProtected }
func (FrozenRequest) MarshalText() ([]byte, error) { return nil, ErrProtected }
func (FrozenRequest) String() string               { return "[temporary-media-preparation-request]" }
func (FrozenRequest) GoString() string             { return "mediaprep.FrozenRequest([redacted])" }
func (FrozenRequest) LogValue() slog.Value {
	return slog.StringValue("[temporary-media-preparation-request]")
}

// AcquisitionRequest is delivered only to the trusted local adapter. The
// stable OperationKey is the adapter's sole idempotency identity.
type AcquisitionRequest struct {
	PreparationRef    string
	OperationKey      string
	TenantID          string
	SiteID            string
	SourceRef         string
	CapabilityRef     string
	Kind              media.Kind
	TimeScope         TimeScope
	AudienceSHA256    string
	EvidenceExpiresAt time.Time
}

func (AcquisitionRequest) MarshalJSON() ([]byte, error) { return nil, ErrProtected }
func (AcquisitionRequest) MarshalText() ([]byte, error) { return nil, ErrProtected }
func (AcquisitionRequest) String() string               { return "[temporary-media-acquisition-request]" }
func (AcquisitionRequest) GoString() string             { return "mediaprep.AcquisitionRequest([redacted])" }
func (AcquisitionRequest) LogValue() slog.Value {
	return slog.StringValue("[temporary-media-acquisition-request]")
}

// ReconciliationRequest can only inspect the already-started operation. It
// intentionally does not carry source information, preventing an adapter from
// interpreting reconciliation as a second acquisition request.
type ReconciliationRequest struct {
	PreparationRef string
	OperationKey   string
	TenantID       string
	SiteID         string
	AudienceSHA256 string
}

func (ReconciliationRequest) MarshalJSON() ([]byte, error) { return nil, ErrProtected }
func (ReconciliationRequest) MarshalText() ([]byte, error) { return nil, ErrProtected }
func (ReconciliationRequest) String() string               { return "[temporary-media-reconciliation-request]" }
func (ReconciliationRequest) GoString() string             { return "mediaprep.ReconciliationRequest([redacted])" }
func (ReconciliationRequest) LogValue() slog.Value {
	return slog.StringValue("[temporary-media-reconciliation-request]")
}

type AcquisitionOutcome string

const (
	AcquisitionPending AcquisitionOutcome = "pending"
	AcquisitionReady   AcquisitionOutcome = "ready"
	AcquisitionFailed  AcquisitionOutcome = "failed"
)

// AcquisitionResult is consumed synchronously. A ready result owns Content;
// the manager always closes it before returning. Content must be detached from
// the Acquire/Reconcile call context so it remains readable during the bounded
// publication call.
type AcquisitionResult struct {
	Outcome     AcquisitionOutcome
	Content     io.ReadCloser
	SHA256      string
	Encoding    media.Encoding
	Temporal    media.Temporal
	FailureCode string
}

func (AcquisitionResult) MarshalJSON() ([]byte, error) { return nil, ErrProtected }
func (AcquisitionResult) MarshalText() ([]byte, error) { return nil, ErrProtected }
func (AcquisitionResult) String() string               { return "[temporary-media-acquisition-result]" }
func (AcquisitionResult) GoString() string             { return "mediaprep.AcquisitionResult([redacted])" }
func (AcquisitionResult) LogValue() slog.Value {
	return slog.StringValue("[temporary-media-acquisition-result]")
}

// Acquirer is deliberately narrower than any device API. Implementations must
// honor context cancellation, make Acquire idempotent by OperationKey, and
// return the same ready bytes and digest from Reconcile until publication is
// complete or the evidence expires. Once Acquire may have begun, this package
// calls only Reconcile.
type Acquirer interface {
	Acquire(context.Context, AcquisitionRequest) (AcquisitionResult, error)
	Reconcile(context.Context, ReconciliationRequest) (AcquisitionResult, error)
}

// Publisher returns an exact committed replay without consuming source. When
// the stable key has no committed media and content is required, it must read
// source and preserve any source error in the errors.Is chain. Publication
// recovery relies on that distinction before consulting the acquirer.
// Publisher must consume the supplied reader when the stable publication key
// has not been published yet. If the reader cannot provide content, the
// returned error must preserve the reader error through errors.Is; recovery
// uses that distinction to decide whether acquisition reconciliation is
// required. A publisher must never allocate a second media identity for the
// same idempotency key and request.
type Publisher interface {
	PutIdempotent(context.Context, media.IdempotentPutRequest, io.Reader) (media.Descriptor, bool, error)
}

// Status is a protected local projection. Higher layers must explicitly map it
// into their own audience-bound business response.
type Status struct {
	PreparationRef string
	State          State
	Reason         Reason
	MediaRef       string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	AvailableAt    time.Time
}

// Validate verifies the complete protected projection returned for one exact
// preparation identity. It is pure and is safe for callers to use before they
// advance a downstream runtime.
func (status Status) Validate(expectedPreparationRef string) error {
	if status.PreparationRef != expectedPreparationRef || !preparationPattern.MatchString(status.PreparationRef) ||
		status.CreatedAt.IsZero() || status.UpdatedAt.IsZero() || status.AvailableAt.IsZero() ||
		status.CreatedAt.Location() != time.UTC || status.UpdatedAt.Location() != time.UTC || status.AvailableAt.Location() != time.UTC ||
		status.UpdatedAt.Before(status.CreatedAt) || status.AvailableAt.Before(status.CreatedAt) {
		return ErrInvalid
	}
	switch status.State {
	case StatePrepared:
		if status.Reason != ReasonPrepared || status.MediaRef != "" {
			return ErrInvalid
		}
	case StateAcquiringUnknown:
		if status.MediaRef != "" || status.Reason != ReasonAcquisitionStarted && status.Reason != ReasonAcquisitionPending &&
			status.Reason != ReasonAcquisitionUnknown && status.Reason != ReasonReconciliationStarted &&
			status.Reason != ReasonReconciliationPending && status.Reason != ReasonReconciliationUnknown &&
			status.Reason != ReasonWorkerInterrupted {
			return ErrInvalid
		}
	case StatePublicationUnknown:
		if status.MediaRef != "" || status.Reason != ReasonPublicationStarted && status.Reason != ReasonPublicationProbeStarted &&
			status.Reason != ReasonPublicationReconciliationStarted && status.Reason != ReasonPublicationUnknown &&
			status.Reason != ReasonWorkerInterrupted {
			return ErrInvalid
		}
	case StateReady:
		if status.Reason != ReasonReady || !mediaRefPattern.MatchString(status.MediaRef) {
			return ErrInvalid
		}
	case StateFailed:
		if status.MediaRef != "" || status.Reason != ReasonAcquisitionFailed && status.Reason != ReasonEvidenceExpired &&
			status.Reason != ReasonContentInvalid && status.Reason != ReasonPublicationRejected {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (Status) MarshalJSON() ([]byte, error) { return nil, ErrProtected }
func (Status) MarshalText() ([]byte, error) { return nil, ErrProtected }
func (Status) String() string               { return "[temporary-media-preparation-status]" }
func (Status) GoString() string             { return "mediaprep.Status([redacted])" }
func (Status) LogValue() slog.Value {
	return slog.StringValue("[temporary-media-preparation-status]")
}

type Recovery struct {
	AcquisitionLeasesRecovered    int
	ReconciliationLeasesRecovered int
	PublicationLeasesRecovered    int
}
