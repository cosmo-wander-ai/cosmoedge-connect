// Package onboarding coordinates durable ordinary-device connection setup
// across the protected profile and credential stores. It never grants device
// execution authority and never persists credential bytes.
package onboarding

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

const SagaSchemaVersion = "cosmoedge.operator.onboarding.v2"

var (
	ErrInvalidInput       = errors.New("onboarding input is invalid")
	ErrAuthorityDenied    = errors.New("onboarding authority was denied")
	ErrBindingMismatch    = errors.New("onboarding binding does not match the protected profile")
	ErrIdentityDrift      = errors.New("onboarding is blocked by device identity drift")
	ErrOperationConflict  = errors.New("onboarding operation conflicts with existing state")
	ErrRecoveryRequired   = errors.New("onboarding recovery is required")
	ErrOutcomeUnknown     = errors.New("onboarding operation outcome is unknown")
	ErrSagaNotFound       = errors.New("onboarding saga was not found")
	ErrSagaConflict       = errors.New("onboarding saga revision conflict")
	ErrInvalidSaga        = errors.New("onboarding saga is invalid")
	operationIDPattern    = regexp.MustCompile(`^onb_[0-9a-f]{32}$`)
	principalDigestRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Operation string

const (
	OperationCreate           Operation = "create"
	OperationUpdateEndpoint   Operation = "update_endpoint"
	OperationRotateCredential Operation = "rotate_credential"
	OperationForget           Operation = "forget"
)

type Status string

const (
	StatusCompleted      Status = "completed"
	StatusFailed         Status = "failed"
	StatusBlocked        Status = "blocked"
	StatusRecoverable    Status = "recoverable"
	StatusOutcomeUnknown Status = "outcome_unknown"
)

type Phase string

const (
	PhasePrepared          Phase = "prepared"
	PhaseProfileRotating   Phase = "profile_rotating"
	PhaseCredentialStored  Phase = "credential_stored"
	PhaseProfileSwitched   Phase = "profile_switched"
	PhaseProfileRevoking   Phase = "profile_revoking"
	PhaseCredentialDeleted Phase = "credential_deleted"
	PhaseProfileRevoked    Phase = "profile_revoked"
	PhaseCompensating      Phase = "compensating"
	PhaseCompleted         Phase = "completed"
	PhaseFailed            Phase = "failed"
	PhaseOutcomeUnknown    Phase = "outcome_unknown"
)

// Access is caller context only. Grant is an untrusted authorization artifact
// until the injected AuthorityVerifier accepts the complete Verification.
type Access struct {
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
	Grant           authority.Grant
}

func (Access) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Access) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Access) String() string               { return "[onboarding-access]" }
func (Access) GoString() string             { return "onboarding.Access([redacted])" }
func (Access) LogValue() slog.Value         { return slog.StringValue("[onboarding-access]") }

// AuthorityVerifier is the sole authorization truth for onboarding. A
// structural authority.Grant.Validate call is not sufficient.
type AuthorityVerifier interface {
	Verify(authority.Grant, authority.Demand, time.Time) error
}

type CreateRequest struct {
	OperationID  string
	Access       Access
	ProfileID    string
	Alias        string
	Endpoint     string
	Username     string
	Secret       []byte
	PinnedSerial string
	PinnedType   string
}

func (CreateRequest) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (CreateRequest) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (CreateRequest) String() string               { return "[onboarding-create-request]" }
func (CreateRequest) GoString() string             { return "onboarding.CreateRequest([redacted])" }
func (CreateRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-create-request]")
}

type UpdateEndpointRequest struct {
	OperationID        string
	Access             Access
	ProfileID          string
	ExpectedGeneration uint64
	Endpoint           string
	Username           string
}

func (UpdateEndpointRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (UpdateEndpointRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (UpdateEndpointRequest) String() string   { return "[onboarding-update-endpoint-request]" }
func (UpdateEndpointRequest) GoString() string { return "onboarding.UpdateEndpointRequest([redacted])" }
func (UpdateEndpointRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-update-endpoint-request]")
}

type RotateCredentialRequest struct {
	OperationID        string
	Access             Access
	ProfileID          string
	ExpectedGeneration uint64
	Secret             []byte
}

func (RotateCredentialRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (RotateCredentialRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (RotateCredentialRequest) String() string { return "[onboarding-rotate-credential-request]" }
func (RotateCredentialRequest) GoString() string {
	return "onboarding.RotateCredentialRequest([redacted])"
}
func (RotateCredentialRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-rotate-credential-request]")
}

type ForgetRequest struct {
	OperationID        string
	Access             Access
	ProfileID          string
	ExpectedGeneration uint64
}

func (ForgetRequest) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (ForgetRequest) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (ForgetRequest) String() string               { return "[onboarding-forget-request]" }
func (ForgetRequest) GoString() string             { return "onboarding.ForgetRequest([redacted])" }
func (ForgetRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-forget-request]")
}

// ResumeRequest resumes one durable saga. Secret is required only when a
// create or credential-rotation saga stopped before the new secret was stored.
// Ownership of Secret transfers to Resume and its bytes are cleared on return.
type ResumeRequest struct {
	OperationID string
	Access      Access
	Secret      []byte
}

func (ResumeRequest) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (ResumeRequest) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (ResumeRequest) String() string               { return "[onboarding-resume-request]" }
func (ResumeRequest) GoString() string             { return "onboarding.ResumeRequest([redacted])" }
func (ResumeRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-resume-request]")
}

type Result struct {
	OperationID string
	Operation   Operation
	Status      Status
	Phase       Phase
	Summary     *profile.BusinessSummary
}

// OperationCompletion is the narrow protected projection used by local
// handoff recovery. It carries only authoritative journal scope and whether
// the exact stable entry operation reached the durable completed phase.
// It contains no connection material, credential reference, grant, or device
// command.
type OperationCompletion struct {
	OperationID     string
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
	Found           bool
	Completed       bool
}

func (OperationCompletion) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (OperationCompletion) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (OperationCompletion) String() string { return "[onboarding-operation-completion]" }
func (OperationCompletion) GoString() string {
	return "onboarding.OperationCompletion([redacted])"
}
func (OperationCompletion) LogValue() slog.Value {
	return slog.StringValue("[onboarding-operation-completion]")
}

func (c OperationCompletion) validate() error {
	if !operationIDPattern.MatchString(c.OperationID) || c.Completed && !c.Found {
		return ErrOperationConflict
	}
	if !c.Found {
		if c.TenantID != "" || c.SiteID != "" || c.PrincipalSHA256 != "" {
			return ErrOperationConflict
		}
		return nil
	}
	if !handoffScopePattern.MatchString(c.TenantID) || !handoffScopePattern.MatchString(c.SiteID) ||
		!principalDigestRegexp.MatchString(c.PrincipalSHA256) {
		return ErrOperationConflict
	}
	return nil
}

// OperationCompletionReader is intentionally journal-only and read-only. It
// cannot resume an operation or touch current profile, credential, or device
// state.
type OperationCompletionReader interface {
	InspectOperationCompletion(context.Context, string) (OperationCompletion, error)
}

type OperationError struct {
	OperationID string
	Operation   Operation
	Status      Status
	Phase       Phase
	cause       error
}

func (e *OperationError) Error() string {
	return fmt.Sprintf("onboarding %s stopped in phase %s with status %s", e.Operation, e.Phase, e.Status)
}

func (e *OperationError) Unwrap() error { return e.cause }

func (*OperationError) GoString() string { return "onboarding.OperationError([redacted])" }

func (*OperationError) LogValue() slog.Value {
	return slog.StringValue("[onboarding-operation-error]")
}

func (*OperationError) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}

func (*OperationError) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}

// SagaRecord is protected orchestration state. It may contain connection and
// pinned-identity metadata plus opaque credential references, but never secret
// bytes, bearer material, or execution authority.
type SagaRecord struct {
	Schema                  string                    `json:"schema"`
	Version                 uint64                    `json:"version"`
	OperationID             string                    `json:"operationId"`
	Operation               Operation                 `json:"operation"`
	Phase                   Phase                     `json:"phase"`
	TenantID                string                    `json:"tenantId"`
	SiteID                  string                    `json:"siteId"`
	PrincipalSHA256         string                    `json:"principalSha256"`
	ProfileID               string                    `json:"profileId"`
	ExpectedGeneration      uint64                    `json:"expectedGeneration,omitempty"`
	Alias                   string                    `json:"alias,omitempty"`
	Endpoint                string                    `json:"endpoint,omitempty"`
	Username                string                    `json:"username,omitempty"`
	PinnedSerial            string                    `json:"pinnedSerial,omitempty"`
	PinnedType              string                    `json:"pinnedType,omitempty"`
	TransportFingerprint    string                    `json:"transportFingerprint,omitempty"`
	OldCredentialRef        credential.Ref            `json:"oldCredentialRef,omitempty"`
	NewCredentialRef        credential.Ref            `json:"newCredentialRef,omitempty"`
	CredentialPutID         credential.PutOperationID `json:"credentialPutId,omitempty"`
	CredentialPutPhase      credential.PutPhase       `json:"credentialPutPhase,omitempty"`
	CredentialRotationID    credential.RotationID     `json:"credentialRotationId,omitempty"`
	CredentialRotationPhase credential.RotationPhase  `json:"credentialRotationPhase,omitempty"`
	CreatedAt               time.Time                 `json:"createdAt"`
	UpdatedAt               time.Time                 `json:"updatedAt"`
}

// MarshalJSON fails closed because a saga contains protected connection and
// identity metadata even before it has a credential ref. Journal persistence
// must use the explicit protected DTO in journal.go.
func (SagaRecord) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}

func (SagaRecord) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}

func (SagaRecord) String() string   { return "[onboarding-saga]" }
func (SagaRecord) GoString() string { return "onboarding.SagaRecord([redacted])" }
func (SagaRecord) LogValue() slog.Value {
	return slog.StringValue("[onboarding-saga]")
}

type SagaJournal interface {
	Begin(context.Context, SagaRecord) (SagaRecord, error)
	Get(context.Context, string) (SagaRecord, error)
	Save(context.Context, SagaRecord) (SagaRecord, error)
}

func NewOperationID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "onb_" + hex.EncodeToString(buffer), nil
}

func (r SagaRecord) Validate() error {
	if r.Schema != SagaSchemaVersion || !operationIDPattern.MatchString(r.OperationID) ||
		!validOperation(r.Operation) || !validPhase(r.Phase) ||
		r.TenantID == "" || r.SiteID == "" || !principalDigestRegexp.MatchString(r.PrincipalSHA256) ||
		r.ProfileID == "" || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) {
		return ErrInvalidSaga
	}
	if r.Version == 0 {
		return ErrInvalidSaga
	}
	if !validPhaseForOperation(r.Operation, r.Phase) {
		return ErrInvalidSaga
	}
	if r.OldCredentialRef != "" && !r.OldCredentialRef.Valid() || r.NewCredentialRef != "" && !r.NewCredentialRef.Valid() {
		return ErrInvalidSaga
	}
	if r.CredentialRotationID != "" && !r.CredentialRotationID.Valid() || !validCredentialRotationPhase(r.CredentialRotationPhase) {
		return ErrInvalidSaga
	}
	if r.CredentialPutID != "" && !r.CredentialPutID.Valid() || !validCredentialPutPhase(r.CredentialPutPhase) {
		return ErrInvalidSaga
	}
	if r.Operation == OperationCreate {
		if r.Alias == "" || r.Endpoint == "" || r.Username == "" || r.PinnedSerial == "" || r.PinnedType == "" || r.ExpectedGeneration != 0 || r.OldCredentialRef != "" || !r.CredentialPutID.Valid() || r.CredentialRotationID != "" || r.CredentialRotationPhase != "" {
			return ErrInvalidSaga
		}
		if r.Phase == PhasePrepared && (r.NewCredentialRef != "" || r.CredentialPutPhase != "") {
			return ErrInvalidSaga
		}
		if r.Phase != PhasePrepared && r.Phase != PhaseOutcomeUnknown && (!r.NewCredentialRef.Valid() || r.CredentialPutPhase == "") {
			return ErrInvalidSaga
		}
	} else if r.ExpectedGeneration == 0 || !r.OldCredentialRef.Valid() {
		return ErrInvalidSaga
	}
	if r.Operation != OperationCreate && (r.CredentialPutID != "" || r.CredentialPutPhase != "") {
		return ErrInvalidSaga
	}
	if r.CredentialPutPhase != "" && (!r.CredentialPutID.Valid() || !r.NewCredentialRef.Valid()) {
		return ErrInvalidSaga
	}
	if r.Operation == OperationForget && (r.NewCredentialRef != "" || r.CredentialRotationID != "" || r.CredentialRotationPhase != "") {
		return ErrInvalidSaga
	}
	if r.CredentialRotationID == "" != (r.CredentialRotationPhase == "") {
		return ErrInvalidSaga
	}
	if r.CredentialRotationID != "" && (r.Operation != OperationUpdateEndpoint && r.Operation != OperationRotateCredential || !r.NewCredentialRef.Valid()) {
		return ErrInvalidSaga
	}
	if (r.Phase == PhaseCredentialStored || r.Phase == PhaseProfileSwitched || r.Phase == PhaseCompensating || r.Phase == PhaseCompleted) &&
		r.Operation != OperationForget && !r.NewCredentialRef.Valid() {
		return ErrInvalidSaga
	}
	if (r.Operation == OperationUpdateEndpoint || r.Operation == OperationRotateCredential) &&
		(r.Phase == PhaseCredentialStored || r.Phase == PhaseProfileSwitched || r.Phase == PhaseCompleted) && !r.CredentialRotationID.Valid() {
		if r.Phase != PhaseCompleted || r.NewCredentialRef != r.OldCredentialRef {
			return ErrInvalidSaga
		}
	}
	return nil
}

func validCredentialRotationPhase(value credential.RotationPhase) bool {
	switch value {
	case "", credential.RotationPrepared, credential.RotationCommitted, credential.RotationRolledBack, credential.RotationUnknown:
		return true
	default:
		return false
	}
}

func validCredentialPutPhase(value credential.PutPhase) bool {
	switch value {
	case "", credential.PutPrepared, credential.PutCommitted, credential.PutRolledBack, credential.PutUnknown:
		return true
	default:
		return false
	}
}

func validOperation(value Operation) bool {
	switch value {
	case OperationCreate, OperationUpdateEndpoint, OperationRotateCredential, OperationForget:
		return true
	default:
		return false
	}
}

func validPhase(value Phase) bool {
	switch value {
	case PhasePrepared, PhaseProfileRotating, PhaseCredentialStored, PhaseProfileSwitched,
		PhaseProfileRevoking, PhaseCredentialDeleted, PhaseProfileRevoked, PhaseCompensating,
		PhaseCompleted, PhaseFailed, PhaseOutcomeUnknown:
		return true
	default:
		return false
	}
}

func validPhaseForOperation(operation Operation, phase Phase) bool {
	switch operation {
	case OperationCreate:
		return phase == PhasePrepared || phase == PhaseCredentialStored || phase == PhaseProfileSwitched ||
			phase == PhaseCompensating || phase == PhaseCompleted || phase == PhaseFailed || phase == PhaseOutcomeUnknown
	case OperationUpdateEndpoint, OperationRotateCredential:
		return phase == PhasePrepared || phase == PhaseProfileRotating || phase == PhaseCredentialStored ||
			phase == PhaseProfileSwitched || phase == PhaseCompleted || phase == PhaseFailed || phase == PhaseOutcomeUnknown
	case OperationForget:
		return phase == PhasePrepared || phase == PhaseProfileRevoking || phase == PhaseCredentialDeleted ||
			phase == PhaseProfileRevoked || phase == PhaseCompleted || phase == PhaseFailed || phase == PhaseOutcomeUnknown
	default:
		return false
	}
}
