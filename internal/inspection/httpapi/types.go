package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const (
	MaxRequestBodyBytes int64 = 64 << 10
	MaxMediaBytes             = 8 << 20
)

var (
	ErrNotFound        = errors.New("inspection HTTP resource not found")
	ErrConflict        = errors.New("inspection HTTP resource conflict")
	ErrInvalid         = errors.New("inspection HTTP request invalid")
	ErrResultNotReady  = errors.New("inspection result not ready")
	ErrUnauthenticated = errors.New("inspection HTTP authentication unavailable")
	ErrForbidden       = errors.New("inspection HTTP authorization denied")
)

type Scope string

const (
	ScopeCapabilitiesRead Scope = "inspection:capabilities:read"
	ScopeRequestCreate    Scope = "inspection:requests:create"
	ScopeRunRead          Scope = "inspection:runs:read"
	ScopeResultRead       Scope = "inspection:results:read"
	ScopeMediaDeliver     Scope = "inspection:media:deliver"
	ScopeFeedbackCreate   Scope = "inspection:feedback:create"
)

// SessionBinding is established by the trusted channel authorizer. None of
// these values is accepted from an HTTP request or returned in a public body.
type SessionBinding struct {
	TenantID        string `json:"-"`
	SiteID          string `json:"-"`
	Channel         string `json:"-"`
	ConversationRef string `json:"-"`
	RecipientRef    string `json:"-"`
	PrincipalSHA256 string `json:"-"`
}

func (SessionBinding) String() string   { return "[inspection-session-binding]" }
func (SessionBinding) GoString() string { return "httpapi.SessionBinding([redacted])" }
func (SessionBinding) LogValue() slog.Value {
	return slog.StringValue("[inspection-session-binding]")
}

type AuthorizationRequest struct {
	Scope            Scope
	CredentialSHA256 string
}

type Authorization struct {
	Session SessionBinding
	Scope   Scope
}

// Authorizer resolves a previously bound tenant/site/channel conversation.
// There is deliberately no allow-all implementation in this package.
type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
}

// Backend is the complete public v2 inspection boundary. It is intentionally
// independent from application.Service so the product composition must make
// authority and projection choices explicitly.
type Backend interface {
	QueryCapabilities(context.Context, SessionBinding) (CapabilitySet, error)
	ResolveContinuation(context.Context, SessionBinding) (ContinuationResolution, error)
	RequestInspection(context.Context, SessionBinding, InspectionRequest, string) (RunView, bool, error)
	GetRun(context.Context, SessionBinding, string) (RunView, error)
	GetResult(context.Context, SessionBinding, string) (ResultView, error)
	GetMedia(context.Context, SessionBinding, string) (MediaPayload, error)
	SubmitFeedback(context.Context, SessionBinding, string, FeedbackRequest, string) (FeedbackReceipt, bool, error)
}

type ContinuationStatus string

const (
	ContinuationNone      ContinuationStatus = "none"
	ContinuationResolved  ContinuationStatus = "resolved"
	ContinuationAmbiguous ContinuationStatus = "ambiguous"
)

type ContinuationResolution struct {
	Status     ContinuationStatus      `json:"status"`
	Run        *RunView                `json:"run,omitempty"`
	Candidates []ContinuationCandidate `json:"candidates,omitempty"`
}

type ContinuationCandidate struct {
	RunRef    string    `json:"runRef"`
	Area      string    `json:"area"`
	Goal      string    `json:"goal"`
	StartedAt time.Time `json:"startedAt"`
}

// CapabilitySet contains only business-facing descriptions. Template IDs,
// source bindings, task IDs, prompts, model settings and device identifiers
// stay behind Backend.
type CapabilitySet struct {
	ContextLabel string           `json:"contextLabel"`
	Capabilities []CapabilityView `json:"capabilities"`
}

type CapabilityView struct {
	CapabilityRef string   `json:"capabilityRef"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Examples      []string `json:"examples"`
}

// TemporaryIntentRequest carries pre-parsed structured fields for a temporary
// visual observation. When provided, the interpreter will use these fields
// directly instead of applying hardcoded keyword matching to the instruction.
// Subject and Region each have a 160-character maximum; Observable has a
// 512-character maximum. All fields undergo normal business input validation.
type TemporaryIntentRequest struct {
	Subject    string `json:"subject"`
	Region     string `json:"region"`
	Observable string `json:"observable"`
}

// InspectionRequest is intentionally open-ended business language. The
// resolver may select an installed task, a composed workflow or temporary VLM
// analysis after the request crosses the trusted application boundary.
type InspectionRequest struct {
	Instruction     string                  `json:"instruction"`
	TemporaryIntent *TemporaryIntentRequest `json:"temporaryIntent,omitempty"`
	Context         []BusinessContext       `json:"context,omitempty"`
}

type BusinessContext struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RunStatus string

const (
	RunAccepted            RunStatus = "accepted"
	RunWorking             RunStatus = "working"
	RunReady               RunStatus = "ready"
	RunInteractionRequired RunStatus = "interaction_required"
	RunUnable              RunStatus = "unable"
	RunCancelled           RunStatus = "cancelled"
	RunExpired             RunStatus = "expired"
)

type RunView struct {
	RunRef      string    `json:"runRef"`
	Status      RunStatus `json:"status"`
	Message     string    `json:"message"`
	SubmittedAt time.Time `json:"submittedAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type ResultView struct {
	RunRef      string          `json:"runRef"`
	Summary     string          `json:"summary"`
	Answer      string          `json:"answer,omitempty"`
	Question    string          `json:"question,omitempty"`
	Sections    []ResultSection `json:"sections"`
	Limitations []string        `json:"limitations"`
	CompletedAt time.Time       `json:"completedAt"`
}

type ResultSection struct {
	Title      string            `json:"title"`
	Conclusion string            `json:"conclusion"`
	Details    []string          `json:"details"`
	Evidence   []MediaCapability `json:"evidence"`
}

// MediaCapability is the only media locator allowed in public JSON. It is a
// session-scoped opaque reference plus the operation the client may perform;
// it is never a filesystem path, URL, source reference or native device ID.
type MediaCapability struct {
	MediaRef   string `json:"mediaRef"`
	Capability string `json:"capability"`
	MediaType  string `json:"mediaType"`
	Title      string `json:"title"`
}

type MediaPayload struct {
	ContentType string
	SHA256      string
	Bytes       []byte
}

type FeedbackRequest struct {
	Helpful *bool  `json:"helpful"`
	Comment string `json:"comment,omitempty"`
}

type FeedbackReceipt struct {
	Accepted bool `json:"accepted"`
}

// InteractionRequired is a safe local handoff, not an arbitrary URL. The
// product shell resolves HandoffRef and asks the user to complete the action in
// the trusted Operator page.
type InteractionRequired struct {
	Title       string `json:"title"`
	Message     string `json:"message"`
	ActionLabel string `json:"actionLabel"`
	Capability  string `json:"capability"`
	HandoffRef  string `json:"handoffRef"`
}

const (
	InteractionCapabilityOnboarding       = "operator.onboarding"
	InteractionCapabilityPersistentChange = "operator.persistent_change"
)

func ValidInteractionCapability(value string) bool {
	return value == InteractionCapabilityOnboarding || value == InteractionCapabilityPersistentChange
}

type InteractionRequiredError struct {
	Interaction InteractionRequired
}

func (e *InteractionRequiredError) Error() string {
	return "inspection interaction is required"
}
