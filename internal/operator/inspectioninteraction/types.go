// Package inspectioninteraction owns protected local interaction registration
// and durable local-transfer state for Inspection v2. It persists only opaque
// intent and correlation references; it never confirms, grants, proposes,
// dispatches, or executes a device operation.
package inspectioninteraction

import (
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
)

var (
	ErrInvalidRegistration = errors.New("inspection interaction registration is invalid")
	ErrNotFound            = errors.New("inspection interaction was not found")
	ErrExpired             = errors.New("inspection interaction has expired")
	ErrConflict            = errors.New("inspection interaction conflicts with existing state")
	ErrScopeMismatch       = errors.New("inspection interaction scope does not match")
	ErrIntegrity           = errors.New("inspection interaction integrity check failed")
	ErrUnsupportedSchema   = errors.New("inspection interaction store schema is unsupported")
	ErrTransferNotPrepared = errors.New("inspection interaction transfer was not prepared")
	ErrOnboardingMismatch  = errors.New("onboarding handoff acknowledgment does not match")
	scopeRefPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	opaqueRefPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Binding struct {
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
}

func (Binding) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Binding) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Binding) String() string               { return "[inspection-interaction-binding]" }
func (Binding) GoString() string {
	return "inspectioninteraction.Binding([redacted])"
}
func (Binding) LogValue() slog.Value {
	return slog.StringValue("[inspection-interaction-binding]")
}

type State string

const (
	StatePending          State = "pending"
	StateTransferPrepared State = "transfer_prepared"
	StateTransferred      State = "transferred"
)

// Record is the complete Operator-owned persistence shape. SourceRef, TaskRef,
// and ObservableRef are opaque catalog handles, never native device IDs.
// ProposalRef is only a stable, opaque correlation handle for the separately
// owned changeflow; no proposal body or desired value is stored here.
type Record struct {
	HandoffRef             string
	TenantID               string
	SiteID                 string
	PrincipalSHA256        string
	InteractionType        planning.LocalInteractionType
	Operation              planning.PendingChangeOperation
	SourceRef              string
	TaskRef                string
	ObservableRef          string
	ExpectedSourceRevision uint64
	ExpectedTaskRevision   uint64
	ExpiresAt              time.Time
	ProposalRef            string
	State                  State
	RecordSHA256           string
}

func (Record) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Record) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (Record) String() string               { return "[inspection-interaction-transfer]" }
func (Record) GoString() string {
	return "inspectioninteraction.Record([redacted])"
}
func (Record) LogValue() slog.Value {
	return slog.StringValue("[pending-inspection-interaction]")
}

// ProtectedLookup is the integrity-checked local application lookup. The
// protected record remains available after business expiry so exact prepared
// transfer replay and completion can preserve the store's monotonic semantics
// without accepting tenant, site, or principal fields from an HTTP request.
type ProtectedLookup struct {
	Record  Record
	Expired bool
}

func (ProtectedLookup) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (ProtectedLookup) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (ProtectedLookup) String() string { return "[inspection-interaction-protected-lookup]" }
func (ProtectedLookup) GoString() string {
	return "inspectioninteraction.ProtectedLookup([redacted])"
}
func (ProtectedLookup) LogValue() slog.Value {
	return slog.StringValue("[inspection-interaction-protected-lookup]")
}

func (r Record) validate() error {
	if !scopeRefPattern.MatchString(r.HandoffRef) || !scopeRefPattern.MatchString(r.TenantID) ||
		!scopeRefPattern.MatchString(r.SiteID) || !digestPattern.MatchString(r.PrincipalSHA256) ||
		r.InteractionType != planning.LocalInteractionPersistentChange || r.ExpiresAt.IsZero() ||
		!r.ExpiresAt.Equal(r.ExpiresAt.UTC()) || !validTransferState(r.State, r.ProposalRef) ||
		!digestPattern.MatchString(r.RecordSHA256) {
		return ErrInvalidRegistration
	}
	return validateChange(planning.PendingChangeIntent{
		Operation: r.Operation, SourceRef: r.SourceRef, TaskRef: r.TaskRef, ObservableRef: r.ObservableRef,
		ExpectedSourceRevision: r.ExpectedSourceRevision, ExpectedTaskRevision: r.ExpectedTaskRevision,
	})
}

func validTransferState(state State, proposalRef string) bool {
	switch state {
	case StatePending:
		return proposalRef == ""
	case StateTransferPrepared, StateTransferred:
		return opaqueRefPattern.MatchString(proposalRef)
	default:
		return false
	}
}

func validProposalRef(proposalRef string) bool {
	return proposalRef == strings.TrimSpace(proposalRef) && opaqueRefPattern.MatchString(proposalRef)
}

func validateChange(value planning.PendingChangeIntent) error {
	for _, ref := range []string{value.SourceRef, value.TaskRef, value.ObservableRef} {
		if ref != "" && !opaqueRefPattern.MatchString(ref) {
			return ErrInvalidRegistration
		}
	}
	noSource := value.SourceRef == "" && value.ExpectedSourceRevision == 0
	noTask := value.TaskRef == "" && value.ExpectedTaskRevision == 0
	valid := false
	switch value.Operation {
	case planning.PendingSourceCreate:
		valid = noSource && noTask && value.ObservableRef == ""
	case planning.PendingSourceUpdate, planning.PendingSourceDelete:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && noTask && value.ObservableRef == ""
	case planning.PendingTaskDeploy:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && noTask && value.ObservableRef != ""
	case planning.PendingTaskUpdate:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && value.TaskRef != "" && value.ExpectedTaskRevision > 0 && value.ObservableRef != ""
	case planning.PendingTaskEnable, planning.PendingTaskDisable, planning.PendingDeviceScheduleUpdate:
		valid = value.SourceRef != "" && value.ExpectedSourceRevision > 0 && value.TaskRef != "" && value.ExpectedTaskRevision > 0 && value.ObservableRef == ""
	}
	if !valid {
		return ErrInvalidRegistration
	}
	return nil
}

func validBinding(binding Binding) bool {
	return scopeRefPattern.MatchString(binding.TenantID) && scopeRefPattern.MatchString(binding.SiteID) &&
		digestPattern.MatchString(binding.PrincipalSHA256)
}
