// Package changeflow connects inspection-originated persistent-change intents
// to the ordinary Operator action boundary. It deliberately has no confirm or
// dispatch port: confirmation and device writes remain owned by the local
// Operator UI and Action Kernel.
package changeflow

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

const SchemaVersion = "cosmoedge.inspection.changeflow.v2"

var (
	ErrInvalid          = errors.New("persistent change workflow is invalid")
	ErrUnauthorized     = errors.New("persistent change workflow is not authorized")
	ErrConflict         = errors.New("persistent change workflow revision conflict")
	ErrNotFound         = errors.New("persistent change workflow was not found")
	ErrNotPublishable   = errors.New("persistent change workflow is not publishable")
	ErrProtectedRecord  = errors.New("protected persistent change workflow cannot be serialized")
	refPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	persistentOperation = map[string]struct{}{
		authority.OpSourceCreate: {}, authority.OpSourceUpdate: {}, authority.OpSourceDelete: {},
		authority.OpTaskDeploy: {}, authority.OpTaskUpdate: {}, authority.OpTaskEnable: {},
		authority.OpTaskDisable: {}, authority.OpDeviceScheduleUpdate: {},
	}
)

type State string

const (
	StateAwaitingLocalConfirmation State = "awaiting_local_confirmation"
	StateActionRunning             State = "action_running"
	StateOutcomeUnknown            State = "outcome_unknown"
	StateFailed                    State = "failed"
	StateCatalogRefreshRequired    State = "catalog_refresh_required"
	StateReadyToPublish            State = "ready_to_publish"
	StatePublished                 State = "published"
)

func (s State) valid() bool {
	switch s {
	case StateAwaitingLocalConfirmation, StateActionRunning, StateOutcomeUnknown, StateFailed,
		StateCatalogRefreshRequired, StateReadyToPublish, StatePublished:
		return true
	default:
		return false
	}
}

type Request struct {
	RequestID        string
	TenantID         string
	SiteID           string
	DeviceProfileID  string
	PrincipalSHA256  string
	OperationKind    string
	RequestedAt      time.Time
	RequestExpiresAt time.Time
}

func (r Request) validate() error {
	if !validRef(r.RequestID) || !validRef(r.TenantID) || !validRef(r.SiteID) || !validRef(r.DeviceProfileID) ||
		!digestPattern.MatchString(r.PrincipalSHA256) || r.RequestedAt.IsZero() ||
		!r.RequestExpiresAt.After(r.RequestedAt) || r.RequestExpiresAt.Sub(r.RequestedAt) > 30*time.Minute {
		return ErrInvalid
	}
	if _, ok := persistentOperation[r.OperationKind]; !ok {
		return ErrInvalid
	}
	return nil
}

// ProposalInput contains only protected, prevalidated references. Arbitrary
// device commands, credentials, endpoints and parameter values cannot enter
// this seam.
type ProposalInput struct {
	RequestID       string
	TenantID        string
	SiteID          string
	DeviceProfileID string
	OperationKind   string
	ExpiresAt       time.Time
}

type Proposal struct {
	ActionID        string
	LocalHandoffRef string
	ExpiresAt       time.Time
}

type ActionState string

const (
	ActionAwaitingConfirmation ActionState = "awaiting_confirmation"
	ActionRunning              ActionState = "running"
	ActionSucceeded            ActionState = "succeeded"
	ActionFailed               ActionState = "failed"
	ActionOutcomeUnknown       ActionState = "outcome_unknown"
)

type ActionStatus struct {
	ActionID       string
	State          ActionState
	EvidenceRef    string
	ReadbackSHA256 string
	DeviceWrites   int
	ObservedAt     time.Time
}

type RefreshRequest struct {
	WorkflowID      string
	TenantID        string
	SiteID          string
	DeviceProfileID string
	ActionID        string
	EvidenceRef     string
	ReadbackSHA256  string
}

type RefreshResult struct {
	ActionID           string
	CatalogFingerprint string
	RefreshedAt        time.Time
}

type PublicationRequest struct {
	WorkflowID         string
	TenantID           string
	SiteID             string
	AssignmentRef      string
	CatalogFingerprint string
}

// Record is protected correlation state. It includes the native Operator
// action reference and therefore must never be a channel projection.
type Record struct {
	Schema             string
	WorkflowID         string
	Revision           uint64
	Request            Request
	GrantID            string
	GrantScopeSHA256   string
	ActionID           string
	LocalHandoffRef    string
	ActionEvidenceRef  string
	ReadbackSHA256     string
	CatalogFingerprint string
	AssignmentRef      string
	State              State
	Reason             string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (Record) MarshalJSON() ([]byte, error) { return nil, ErrProtectedRecord }

type Summary struct {
	Schema              string    `json:"schema"`
	WorkflowRef         string    `json:"workflowRef"`
	State               State     `json:"state"`
	InteractionRequired bool      `json:"interactionRequired"`
	LocalHandoffRef     string    `json:"localHandoffRef,omitempty"`
	CatalogRefreshed    bool      `json:"catalogRefreshed"`
	Published           bool      `json:"published"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

func (r Record) Summary() (Summary, error) {
	if err := r.validate(); err != nil {
		return Summary{}, err
	}
	return Summary{
		Schema: SchemaVersion, WorkflowRef: r.WorkflowID, State: r.State,
		InteractionRequired: r.State == StateAwaitingLocalConfirmation,
		LocalHandoffRef: func() string {
			if r.State == StateAwaitingLocalConfirmation {
				return r.LocalHandoffRef
			}
			return ""
		}(),
		CatalogRefreshed: r.CatalogFingerprint != "",
		Published:        r.State == StatePublished, UpdatedAt: r.UpdatedAt.UTC(),
	}, nil
}

func (r Record) validate() error {
	if r.Schema != SchemaVersion || !validRef(r.WorkflowID) || r.Revision == 0 || r.Request.validate() != nil ||
		!validRef(r.GrantID) || !digestPattern.MatchString(r.GrantScopeSHA256) || !validRef(r.ActionID) ||
		!validRef(r.LocalHandoffRef) || !r.State.valid() || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) ||
		strings.TrimSpace(r.Reason) != r.Reason || r.Reason == "" || len(r.Reason) > 128 {
		return ErrInvalid
	}
	for _, digest := range []string{r.ReadbackSHA256, r.CatalogFingerprint} {
		if digest != "" && !digestPattern.MatchString(digest) {
			return ErrInvalid
		}
	}
	for _, ref := range []string{r.ActionEvidenceRef, r.AssignmentRef} {
		if ref != "" && !validRef(ref) {
			return ErrInvalid
		}
	}
	if (r.State == StateReadyToPublish || r.State == StatePublished) &&
		(r.ActionEvidenceRef == "" || r.ReadbackSHA256 == "" || r.CatalogFingerprint == "") {
		return ErrInvalid
	}
	if r.State == StatePublished && r.AssignmentRef == "" {
		return ErrInvalid
	}
	return nil
}

func validRef(value string) bool {
	return strings.TrimSpace(value) == value && refPattern.MatchString(value)
}

func canonicalSummary(summary Summary) ([]byte, error) { return json.Marshal(summary) }
