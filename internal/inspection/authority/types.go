// Package authority owns cryptographically protected execution authority for
// inspection runs. Public callers never construct or submit an authorization
// object; trusted admission explicitly freezes one authenticated identity and
// the broker binds it to one exact frozen run.
package authority

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const SchemaVersion = "cosmoedge.inspection.execution-authority.v3"

var (
	ErrUnauthorized                = errors.New("inspection execution authority rejected")
	ErrConflict                    = errors.New("inspection run authority already exists")
	ErrNotFound                    = errors.New("inspection run authority was not found")
	ErrClosed                      = errors.New("inspection authority broker is closed")
	ErrProtectedIdentityProjection = errors.New("inspection execution identity cannot be serialized")
)

type ExecutionIdentityKind string

const (
	IdentityActor   ExecutionIdentityKind = "actor"
	IdentityService ExecutionIdentityKind = "service"
)

type StepAuthority string

const (
	StepAuthorityNone                StepAuthority = "none"
	StepAuthorityDeviceRead          StepAuthority = "device_read"
	StepAuthorityInspectionExecution StepAuthority = "inspection_execution"
)

// ExecutionIdentity is the explicit authenticated identity frozen at
// admission. It is protected state: it may be compared and persisted by the
// authority implementation, but it cannot be projected as JSON, text, or a
// log value.
type ExecutionIdentity struct {
	Kind            ExecutionIdentityKind `json:"-"`
	PrincipalSHA256 string                `json:"-"`
}

func NewExecutionIdentity(kind ExecutionIdentityKind, principalSHA256 string) (ExecutionIdentity, error) {
	identity := ExecutionIdentity{Kind: kind, PrincipalSHA256: principalSHA256}
	if identity.Validate() != nil {
		return ExecutionIdentity{}, ErrUnauthorized
	}
	return identity, nil
}

func ExecutionIdentityForOrigin(origin inspection.RunOrigin, principalSHA256 string) (ExecutionIdentity, error) {
	kind := IdentityActor
	if origin == inspection.OriginSchedule {
		kind = IdentityService
	} else if origin != inspection.OriginUser && origin != inspection.OriginAPI {
		return ExecutionIdentity{}, ErrUnauthorized
	}
	return NewExecutionIdentity(kind, principalSHA256)
}

func (i ExecutionIdentity) Validate() error {
	if !validDigest(i.PrincipalSHA256) || i.Kind != IdentityActor && i.Kind != IdentityService {
		return ErrUnauthorized
	}
	return nil
}

func (ExecutionIdentity) MarshalJSON() ([]byte, error) { return nil, ErrProtectedIdentityProjection }
func (ExecutionIdentity) MarshalText() ([]byte, error) { return nil, ErrProtectedIdentityProjection }
func (ExecutionIdentity) String() string               { return "[inspection-execution-identity]" }
func (ExecutionIdentity) GoString() string {
	return "authority.ExecutionIdentity([redacted])"
}
func (ExecutionIdentity) LogValue() slog.Value {
	return slog.StringValue("[inspection-execution-identity]")
}

type StepScope struct {
	StepID    string        `json:"stepId"`
	Authority StepAuthority `json:"authority"`
}

type IssueDemand struct {
	Identity           ExecutionIdentity
	TenantID           string
	SiteID             string
	RunID              string
	PlanSHA256         string
	AssignmentID       string
	AssignmentRevision uint64
	RequestKey         string
	RuntimeID          string
	Steps              []StepScope
	Deadline           time.Time
}

// Authorization is an opaque broker result. It contains no raw actor or
// service identity and no signing material.
type Authorization struct {
	Schema             string            `json:"-"`
	IssuerID           string            `json:"-"`
	AuthorizationID    string            `json:"-"`
	Identity           ExecutionIdentity `json:"-"`
	TenantID           string            `json:"tenantId"`
	SiteID             string            `json:"siteId"`
	RunID              string            `json:"runId"`
	PlanSHA256         string            `json:"planSha256"`
	AssignmentID       string            `json:"assignmentId"`
	AssignmentRevision uint64            `json:"assignmentRevision"`
	RequestKey         string            `json:"requestKey"`
	RuntimeID          string            `json:"runtimeId"`
	Steps              []StepScope       `json:"steps"`
	IssuedAt           time.Time         `json:"issuedAt"`
	ExpiresAt          time.Time         `json:"expiresAt"`
	ProofSHA256        string            `json:"proofSha256"`
}

func (Authorization) MarshalJSON() ([]byte, error) { return nil, ErrProtectedIdentityProjection }
func (Authorization) MarshalText() ([]byte, error) { return nil, ErrProtectedIdentityProjection }
func (Authorization) String() string               { return "[inspection-execution-authorization]" }
func (Authorization) GoString() string {
	return "authority.Authorization([redacted])"
}
func (Authorization) LogValue() slog.Value {
	return slog.StringValue("[inspection-execution-authorization]")
}

type StepDemand struct {
	Identity           ExecutionIdentity
	Authority          StepAuthority
	TenantID           string
	SiteID             string
	RunID              string
	PlanSHA256         string
	AssignmentID       string
	AssignmentRevision uint64
	RequestKey         string
	RuntimeID          string
	StepID             string
	AttemptID          string
}

// Broker is the trusted execution-authority boundary. VerifyAndConsume is
// deliberately stateful: the same run/step/attempt authority cannot be replayed.
type Broker interface {
	// Issue returns created=false only when the exact same unexpired
	// authorization is already active. A caller may therefore replay one
	// authenticated admission after a process restart without widening or
	// replacing an in-process authorization.
	Issue(context.Context, IssueDemand) (authorization Authorization, created bool, err error)
	Lookup(context.Context, string) (Authorization, error)
	VerifyAndConsume(context.Context, Authorization, StepDemand) error
	// Revoke is an irreversible, idempotent terminal operation for a known
	// run. It must retain enough anti-replay state that neither a repeated
	// revoke nor a later exact Issue can reopen consumed work.
	Revoke(context.Context, string) error
}

// Submission is the only runtime admission shape. Its plan request is kept
// private so callers cannot mutate validated execution intent after admission.
// The broker provides all execution authority after the run ID and plan digest
// exist; authorization is deliberately absent from the business request and
// frozen plan shapes.
type Submission struct {
	request  inspection.CreateRunRequest
	identity ExecutionIdentity
}

func NewSubmission(request inspection.CreateRunRequest, identity ExecutionIdentity) (Submission, error) {
	request.TargetIDs = append([]string(nil), request.TargetIDs...)
	request.Variables = cloneVariables(request.Variables)
	if err := request.Validate(); err != nil {
		return Submission{}, err
	}
	if identity.Validate() != nil || !identityMatchesOrigin(identity, request.Origin) {
		return Submission{}, ErrUnauthorized
	}
	return Submission{request: request, identity: identity}, nil
}

func (s Submission) PlanRequest() (inspection.CreateRunRequest, error) {
	request := s.request
	request.TargetIDs = append([]string(nil), request.TargetIDs...)
	request.Variables = cloneVariables(request.Variables)
	if err := request.Validate(); err != nil || s.identity.Validate() != nil || !identityMatchesOrigin(s.identity, request.Origin) {
		return inspection.CreateRunRequest{}, ErrUnauthorized
	}
	return request, nil
}

func (s Submission) ExecutionIdentity() (ExecutionIdentity, error) {
	if _, err := s.PlanRequest(); err != nil {
		return ExecutionIdentity{}, ErrUnauthorized
	}
	return s.identity, nil
}

func StepAuthorityForPlan(value inspection.StepAuthority) (StepAuthority, error) {
	switch value {
	case inspection.StepAuthorityNone:
		return StepAuthorityNone, nil
	case inspection.StepAuthorityDeviceRead:
		return StepAuthorityDeviceRead, nil
	case inspection.StepAuthorityInspectionExecution:
		return StepAuthorityInspectionExecution, nil
	default:
		return "", ErrUnauthorized
	}
}

func ScopesForPlan(plan inspection.ExecutionPlan) ([]StepScope, error) {
	scopes := make([]StepScope, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		authority, err := StepAuthorityForPlan(step.Authority)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, StepScope{StepID: step.StepID, Authority: authority})
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].StepID < scopes[j].StepID })
	if !validStepScopes(scopes) {
		return nil, ErrUnauthorized
	}
	return scopes, nil
}

var (
	refPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requestPattern = regexp.MustCompile(`^req_[0-9a-f]{32}$`)
)

func (a Authorization) validate() error {
	if a.Schema != SchemaVersion || !validRef(a.IssuerID) || !validRef(a.AuthorizationID) ||
		!validRef(a.TenantID) || !validRef(a.SiteID) || !validRef(a.RunID) || !validDigest(a.PlanSHA256) ||
		!validRef(a.AssignmentID) || a.AssignmentRevision == 0 || !requestPattern.MatchString(a.RequestKey) ||
		!validRef(a.RuntimeID) || !validDigest(a.ProofSHA256) || !validStepScopes(a.Steps) ||
		a.IssuedAt.IsZero() || !a.ExpiresAt.After(a.IssuedAt) {
		return ErrUnauthorized
	}
	if a.Identity.Validate() != nil {
		return ErrUnauthorized
	}
	return nil
}

func validIssueDemand(d IssueDemand, at time.Time) bool {
	if !validRef(d.TenantID) || !validRef(d.SiteID) || !validRef(d.RunID) || !validDigest(d.PlanSHA256) ||
		!validRef(d.AssignmentID) || d.AssignmentRevision == 0 || !requestPattern.MatchString(d.RequestKey) ||
		!validRef(d.RuntimeID) || !validStepScopes(d.Steps) || at.IsZero() || !d.Deadline.After(at) {
		return false
	}
	return d.Identity.Validate() == nil
}

func validStepDemand(d StepDemand) bool {
	if !validRef(d.TenantID) || !validRef(d.SiteID) || !validRef(d.RunID) || !validDigest(d.PlanSHA256) ||
		!validRef(d.AssignmentID) || d.AssignmentRevision == 0 || !requestPattern.MatchString(d.RequestKey) ||
		!validRef(d.RuntimeID) || !validRef(d.StepID) || !validRef(d.AttemptID) {
		return false
	}
	if d.Identity.Validate() != nil {
		return false
	}
	return validStepAuthority(d.Authority)
}

func validStepScopes(values []StepScope) bool {
	if len(values) == 0 || len(values) > 10_000 {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validRef(value.StepID) || !validStepAuthority(value.Authority) || value.StepID <= previous {
			return false
		}
		previous = value.StepID
	}
	return true
}

func validStepAuthority(value StepAuthority) bool {
	return value == StepAuthorityNone || value == StepAuthorityDeviceRead || value == StepAuthorityInspectionExecution
}

func identityMatchesOrigin(identity ExecutionIdentity, origin inspection.RunOrigin) bool {
	return identity.Kind == IdentityActor && (origin == inspection.OriginUser || origin == inspection.OriginAPI) ||
		identity.Kind == IdentityService && origin == inspection.OriginSchedule
}

func validRef(value string) bool {
	return value == strings.TrimSpace(value) && refPattern.MatchString(value)
}

func validDigest(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func cloneVariables(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
