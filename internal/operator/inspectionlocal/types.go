// Package inspectionlocal is the protected local application boundary for
// Inspection v2 interactions. It accepts only an already-authenticated local
// browser session bound by bootstrap to one exact handoff.
package inspectionlocal

import (
	"errors"
	"log/slog"
	"regexp"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
)

var (
	ErrInvalidSession = errors.New("local inspection session is invalid")
	ErrInvalidRequest = errors.New("local inspection request is invalid")
	ErrNotFound       = errors.New("local inspection interaction was not found")
	ErrExpired        = errors.New("local inspection interaction has expired")
	ErrDenied         = errors.New("local inspection operation is not authorized")
	ErrAmbiguous      = errors.New("local inspection interaction is ambiguous")
	ErrWrongKind      = errors.New("local inspection interaction kind does not match the operation")
	ErrConflict       = errors.New("local inspection interaction conflicts with protected state")
	ErrIntegrity      = errors.New("local inspection interaction integrity check failed")
	ErrUnavailable    = errors.New("local inspection interaction service is unavailable")

	// Connection failures are a closed, user-actionable vocabulary. They
	// intentionally carry no device address, account, password, transport
	// detail, or native API response from the live connection layer.
	ErrConnectionRejected           = errors.New("local device credentials were rejected")
	ErrConnectionThrottled          = errors.New("local device login is temporarily throttled")
	ErrConnectionUnavailable        = errors.New("local device is currently unreachable")
	ErrConnectionReadUnavailable    = errors.New("local device information is unavailable after login")
	ErrConnectionPersistenceFailed  = errors.New("local verified connection could not be saved")
	ErrConnectionRequestUnavailable = errors.New("local device connection request is unavailable")

	scopeRefPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	opaqueRefPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	browserRefPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// LocalSession is an opaque per-request binding minted only by SessionBinder
// after the existing operator/session layer authenticates the browser. Its
// unexported handoff cannot be populated from query, form, or JSON fields.
type LocalSession struct {
	sessionID            string
	handoffRef           string
	browserBindingSHA256 string
	writeAuthorized      bool
}

func (s LocalSession) valid() bool {
	return browserRefPattern.MatchString(s.sessionID) && validHandoffRef(s.handoffRef) &&
		digestPattern.MatchString(s.browserBindingSHA256)
}

func (LocalSession) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (LocalSession) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (LocalSession) String() string               { return "[inspection-local-session]" }
func (LocalSession) GoString() string             { return "inspectionlocal.LocalSession([redacted])" }
func (LocalSession) LogValue() slog.Value {
	return slog.StringValue("[inspection-local-session]")
}

type InteractionKind string

const (
	KindConnection       InteractionKind = "connection"
	KindPersistentChange InteractionKind = "persistent_change"
)

type BusinessAction string

const (
	ActionCompleteConnection        BusinessAction = "complete_connection"
	ActionPreparePersistentTransfer BusinessAction = "prepare_persistent_transfer"
	ActionMarkPersistentTransferred BusinessAction = "mark_persistent_transferred"
	ActionNone                      BusinessAction = "none"
)

type ActionStatus string

const (
	StatusPending          ActionStatus = "pending"
	StatusCompleted        ActionStatus = "completed"
	StatusTransferPrepared ActionStatus = "transfer_prepared"
	StatusTransferred      ActionStatus = "transferred"
)

// Interaction is the complete local-page projection. It intentionally omits
// handoff, proposal, source, task, endpoint, credential, and native identities.
type Interaction struct {
	Kind   InteractionKind
	Action BusinessAction
	Status ActionStatus
}

func (Interaction) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Interaction) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Interaction) String() string               { return "[inspection-local-interaction]" }
func (Interaction) GoString() string             { return "inspectionlocal.Interaction([redacted])" }
func (Interaction) LogValue() slog.Value {
	return slog.StringValue("[inspection-local-interaction]")
}

// CompleteConnectionRequest is protected because it owns the password slice
// until CompleteConnection returns and carries a signed local grant.
type CompleteConnectionRequest struct {
	Connection onboarding.LocalConnectionInput
	Grant      authority.Grant
}

func (CompleteConnectionRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (CompleteConnectionRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (CompleteConnectionRequest) String() string { return "[inspection-local-connection-request]" }
func (CompleteConnectionRequest) GoString() string {
	return "inspectionlocal.CompleteConnectionRequest([redacted])"
}
func (CompleteConnectionRequest) LogValue() slog.Value {
	return slog.StringValue("[inspection-local-connection-request]")
}

// PersistentTransferRequest carries only one stable opaque correlation handle.
// It cannot carry a proposal body, desired value, confirmation, or grant.
type PersistentTransferRequest struct {
	ProposalRef string
}

func (PersistentTransferRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (PersistentTransferRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (PersistentTransferRequest) String() string { return "[inspection-local-transfer-request]" }
func (PersistentTransferRequest) GoString() string {
	return "inspectionlocal.PersistentTransferRequest([redacted])"
}
func (PersistentTransferRequest) LogValue() slog.Value {
	return slog.StringValue("[inspection-local-transfer-request]")
}

func validHandoffRef(value string) bool {
	return value == strings.TrimSpace(value) && scopeRefPattern.MatchString(value)
}

func validProposalRef(value string) bool {
	return value == strings.TrimSpace(value) && opaqueRefPattern.MatchString(value)
}
