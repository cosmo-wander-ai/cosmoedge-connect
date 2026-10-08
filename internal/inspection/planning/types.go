// Package planning turns one authenticated, open-ended business request into
// exactly one trusted Inspection v2 decision. Open-ended text is interpreted
// through a narrow semantic port; protected catalog identities, authority
// facts, and published execution configuration are always loaded separately.
package planning

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/resolver"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

type PublishedRegistry interface {
	ListInspectionTemplates(context.Context, string) ([]inspection.InspectionTemplate, error)
	ListAssignments(context.Context, string, string) ([]inspection.Assignment, error)
}

// ProtectedCatalog is deliberately not a business-channel projection. The
// planner may compare protected facts with frozen assignments, but never
// returns a Source or DeviceTaskBinding to its caller or interpreter.
type ProtectedCatalog interface {
	ListSite(context.Context, string, string) ([]catalog.Source, error)
	ListTasks(context.Context, string, string) ([]catalog.DeviceTaskBinding, error)
	Fingerprint(context.Context, string, string) (string, error)
	ValidateInstalledTask(context.Context, string, string, inspection.InstalledTaskBinding) error
}

// AuthorityProvider returns already-verified, short-lived availability facts.
// It is the only source of authority used by Service.
type AuthorityProvider interface {
	AvailableAuthorities(context.Context, resolver.AuthenticatedScope) ([]resolver.AuthorityAvailability, error)
}

type TechnicalResolver interface {
	Resolve(resolver.Request) (resolver.Resolution, error)
}

var ErrProtectedInteractionProjection = errors.New("protected local interaction cannot be serialized")

type LocalInteractionType string

const (
	LocalInteractionConnection       LocalInteractionType = "connection"
	LocalInteractionPersistentChange LocalInteractionType = "persistent_change"
)

type PendingChangeOperation string

const (
	PendingSourceCreate         PendingChangeOperation = "source_create"
	PendingSourceUpdate         PendingChangeOperation = "source_update"
	PendingSourceDelete         PendingChangeOperation = "source_delete"
	PendingTaskDeploy           PendingChangeOperation = "task_deploy"
	PendingTaskUpdate           PendingChangeOperation = "task_update"
	PendingTaskEnable           PendingChangeOperation = "task_enable"
	PendingTaskDisable          PendingChangeOperation = "task_disable"
	PendingDeviceScheduleUpdate PendingChangeOperation = "device_schedule_update"
)

// PendingChangeIntent is a closed, parameter-free local todo. It carries only
// opaque catalog references and optimistic revisions; desired values and any
// device-write capability belong to the later trusted local flow.
type PendingChangeIntent struct {
	Operation              PendingChangeOperation
	SourceRef              string
	TaskRef                string
	ObservableRef          string
	ExpectedSourceRevision uint64
	ExpectedTaskRevision   uint64
}

func (PendingChangeIntent) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedInteractionProjection
}
func (PendingChangeIntent) MarshalText() ([]byte, error) {
	return nil, ErrProtectedInteractionProjection
}
func (PendingChangeIntent) String() string   { return "[pending-local-change]" }
func (PendingChangeIntent) GoString() string { return "planning.PendingChangeIntent([redacted])" }
func (PendingChangeIntent) LogValue() slog.Value {
	return slog.StringValue("[pending-local-change]")
}

// LocalInteractionRegistration is the only planning-to-Operator registration
// contract. It has no grant, secret, endpoint, native ID, command, desired
// parameter value, confirmation, proposal, or dispatch field.
type LocalInteractionRegistration struct {
	Type            LocalInteractionType
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
	HandoffRef      string
	ExpiresAt       time.Time
	Change          *PendingChangeIntent
}

func (LocalInteractionRegistration) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedInteractionProjection
}
func (LocalInteractionRegistration) MarshalText() ([]byte, error) {
	return nil, ErrProtectedInteractionProjection
}
func (LocalInteractionRegistration) String() string { return "[local-interaction-registration]" }
func (LocalInteractionRegistration) GoString() string {
	return "planning.LocalInteractionRegistration([redacted])"
}
func (LocalInteractionRegistration) LogValue() slog.Value {
	return slog.StringValue("[local-interaction-registration]")
}

type LocalInteractionReceipt struct {
	Type       LocalInteractionType
	HandoffRef string
	ExpiresAt  time.Time
}

type LocalInteractionRegistrar interface {
	Register(context.Context, LocalInteractionRegistration) (LocalInteractionReceipt, error)
}

// TemporaryMediaCompilation is a protected request-policy input. The compiler
// chooses device-neutral acquisition and publication metadata; the planner
// independently verifies every authority and identity field in its output.
type TemporaryMediaCompilation struct {
	TenantID           string
	SiteID             string
	RequestID          string
	RequestedAt        time.Time
	Spec               temporary.TemporaryObservationSpec
	SourceRef          string
	CapabilityRef      string
	RuntimeRunID       string
	RuntimeStepID      string
	AudienceBindingRef string
	AudienceSHA256     string
	EvidenceExpiresAt  time.Time
}

func (TemporaryMediaCompilation) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedInteractionProjection
}
func (TemporaryMediaCompilation) MarshalText() ([]byte, error) {
	return nil, ErrProtectedInteractionProjection
}
func (TemporaryMediaCompilation) String() string {
	return "[temporary-media-compilation]"
}
func (TemporaryMediaCompilation) GoString() string {
	return "planning.TemporaryMediaCompilation([redacted])"
}
func (TemporaryMediaCompilation) LogValue() slog.Value {
	return slog.StringValue("[temporary-media-compilation]")
}

type TemporaryMediaRequestCompiler interface {
	Compile(context.Context, TemporaryMediaCompilation) (mediaprep.FrozenRequest, error)
}

// BusinessVocabulary contains display-level choices only. It intentionally
// excludes tenant/site/principal values, native locators, opaque source/task
// handles, capability references, authority facts, prompts, and paths.
type BusinessVocabulary struct {
	SourceNames     []string
	TaskNames       []string
	ObservableNames []string
	VariableOptions []BusinessVariableOption
}

type BusinessVariableOption struct {
	Name          string
	AllowedValues []string
}

type InterpretationContext struct {
	Name  string
	Value string
}

type InterpretationRequest struct {
	Instruction     string
	Context         []InterpretationContext
	Vocabulary      BusinessVocabulary
	TemporaryIntent *TemporaryObservationIntent
}

// IntentInterpreter may use an LLM or another production semantic service,
// but it can return only this closed, business-level shape. A deterministic
// keyword interpreter is intentionally not provided in production code.
type IntentInterpreter interface {
	Interpret(context.Context, InterpretationRequest) (InterpretedIntent, error)
}

type IntentGoal string

const (
	IntentInspect          IntentGoal = "inspect"
	IntentConnect          IntentGoal = "connect"
	IntentPersistentChange IntentGoal = "persistent_change"
)

type InspectionMode string

const (
	ModeStandard        InspectionMode = "standard"
	ModeTemporaryVisual InspectionMode = "temporary_visual"
)

type ExecutionPreference string

const (
	PreferAuto         ExecutionPreference = "auto"
	PreferExistingTask ExecutionPreference = "existing_task"
	PreferSnapshot     ExecutionPreference = "snapshot"
	PreferClip         ExecutionPreference = "clip"
	PreferHybrid       ExecutionPreference = "hybrid"
)

type VariableSelection struct {
	Name  string
	Value string
}

type TemporaryObservationIntent struct {
	Subject            string
	Region             string
	Observable         string
	Locale             string
	EvidenceTTLSeconds int
}

type InspectionIntent struct {
	Mode            InspectionMode
	SourceName      string
	ObservableName  string
	TaskName        string
	Preference      ExecutionPreference
	VisualFollowup  bool
	TimeScope       temporary.TimeScope
	Temporary       *TemporaryObservationIntent
	VariableChoices []VariableSelection
}

type ConnectionPurpose string

const (
	ConnectNew     ConnectionPurpose = "connect"
	RefreshCurrent ConnectionPurpose = "refresh"
)

type ChangeKind string

const (
	ChangeCreateSource   ChangeKind = "create_source"
	ChangeUpdateSource   ChangeKind = "update_source"
	ChangeDeleteSource   ChangeKind = "delete_source"
	ChangeDeployTask     ChangeKind = "deploy_task"
	ChangeUpdateTask     ChangeKind = "update_task"
	ChangeEnableTask     ChangeKind = "enable_task"
	ChangeDisableTask    ChangeKind = "disable_task"
	ChangeUpdateSchedule ChangeKind = "update_schedule"
)

type PersistentChangeIntent struct {
	Kind           ChangeKind
	SourceName     string
	TaskName       string
	ObservableName string
}

type InterpretedIntent struct {
	Goal             IntentGoal
	Inspection       *InspectionIntent
	Connection       *ConnectionPurpose
	PersistentChange *PersistentChangeIntent
}

type Config struct {
	Registry       PublishedRegistry
	Catalog        ProtectedCatalog
	Authorities    AuthorityProvider
	Interactions   LocalInteractionRegistrar
	Interpreter    IntentInterpreter
	MediaCompiler  TemporaryMediaRequestCompiler
	Resolver       TechnicalResolver
	Now            func() time.Time
	CatalogFactTTL time.Duration
	DefaultRunTTL  time.Duration
}

type Service struct {
	registry       PublishedRegistry
	catalog        ProtectedCatalog
	authorities    AuthorityProvider
	interactions   LocalInteractionRegistrar
	interpreter    IntentInterpreter
	mediaCompiler  TemporaryMediaRequestCompiler
	resolver       TechnicalResolver
	now            func() time.Time
	catalogFactTTL time.Duration
	defaultRunTTL  time.Duration
}

var _ application.RequestPlanner = (*Service)(nil)
var _ application.CapabilityQuery = (*Service)(nil)
