package resolver

import (
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

const (
	RequestSchemaVersion    = "cosmoedge.inspection.resolver.request.v2"
	ResolutionSchemaVersion = "cosmoedge.inspection.resolver.resolution.v2"
)

type Channel string

const (
	ChannelWorkBuddyWeChat Channel = "workbuddy_wechat"
	ChannelLocalOperator   Channel = "local_operator"
	ChannelAPI             Channel = "api"
)

// AuthenticatedScope is supplied by the channel authentication boundary. The
// principal is a digest binding, never a username, account, or channel token.
type AuthenticatedScope struct {
	TenantID        string  `json:"tenantId"`
	SiteID          string  `json:"siteId"`
	Channel         Channel `json:"channel"`
	PrincipalSHA256 string  `json:"principalSha256"`
}

type Goal string

const (
	GoalInspect          Goal = "inspect"
	GoalConnect          Goal = "connect"
	GoalPersistentChange Goal = "persistent_change"
)

type BusinessIntent struct {
	Goal             Goal                    `json:"goal"`
	Inspection       *InspectionIntent       `json:"inspection,omitempty"`
	Connection       *ConnectionIntent       `json:"connection,omitempty"`
	PersistentChange *PersistentChangeIntent `json:"persistentChange,omitempty"`
}

type InspectionMode string

const (
	InspectionModeStandard        InspectionMode = "standard"
	InspectionModeTemporaryVisual InspectionMode = "temporary_visual"
)

type RoutePreference string

const (
	PreferenceAuto         RoutePreference = "auto"
	PreferenceExistingTask RoutePreference = "existing_task_read"
	PreferenceSnapshot     RoutePreference = "snapshot_analysis"
	PreferenceClip         RoutePreference = "clip_analysis"
	PreferenceHybrid       RoutePreference = "hybrid_analysis"
)

// SourceSelector accepts either one exact opaque source handle or one exact
// business alias. It never accepts a native device/channel identifier.
type SourceSelector struct {
	SourceHandle     string `json:"sourceHandle,omitempty"`
	Alias            string `json:"alias,omitempty"`
	ZoneID           string `json:"zoneId,omitempty"`
	ExpectedRevision uint64 `json:"expectedRevision,omitempty"`
}

// InspectionIntent is already structured by the channel layer. ObservableCode
// selects a published standard criterion. Temporary visual questions use only
// TemporaryIntent and are normalized again by temporary.NewSpec.
type InspectionIntent struct {
	Mode              InspectionMode       `json:"mode"`
	Source            SourceSelector       `json:"source"`
	ObservableCode    string               `json:"observableCode,omitempty"`
	StandardTimeScope *temporary.TimeScope `json:"standardTimeScope,omitempty"`
	TemporaryIntent   *temporary.Intent    `json:"temporaryIntent,omitempty"`
	TaskHandle        string               `json:"taskHandle,omitempty"`
	Preference        RoutePreference      `json:"preference"`
	VisualFollowup    bool                 `json:"visualFollowup,omitempty"`
}

type ConnectionPurpose string

const (
	ConnectionPurposeConnectDevice ConnectionPurpose = "connect_device"
	ConnectionPurposeRefresh       ConnectionPurpose = "refresh_connection"
)

type ConnectionIntent struct {
	Purpose ConnectionPurpose `json:"purpose"`
}

type PersistentChangeKind string

const (
	ChangeSourceCreate         PersistentChangeKind = "source_create"
	ChangeSourceUpdate         PersistentChangeKind = "source_update"
	ChangeSourceDelete         PersistentChangeKind = "source_delete"
	ChangeTaskDeploy           PersistentChangeKind = "task_deploy"
	ChangeTaskUpdate           PersistentChangeKind = "task_update"
	ChangeTaskEnable           PersistentChangeKind = "task_enable"
	ChangeTaskDisable          PersistentChangeKind = "task_disable"
	ChangeDeviceScheduleUpdate PersistentChangeKind = "device_schedule_update"
)

// PersistentChangeIntent contains only closed business identifiers and
// optimistic revisions. Parameters, desired values, commands, endpoints, and
// credentials must be collected and confirmed by the downstream local flow.
type PersistentChangeIntent struct {
	Kind                   PersistentChangeKind `json:"kind"`
	SourceHandle           string               `json:"sourceHandle,omitempty"`
	TaskHandle             string               `json:"taskHandle,omitempty"`
	ObservableCode         string               `json:"observableCode,omitempty"`
	ExpectedSourceRevision uint64               `json:"expectedSourceRevision,omitempty"`
	ExpectedTaskRevision   uint64               `json:"expectedTaskRevision,omitempty"`
}

// SourceFact adds authenticated scope and freshness to catalog.BusinessSummary,
// whose business projection intentionally contains neither tenant nor site.
type SourceFact struct {
	TenantID   string                  `json:"tenantId"`
	SiteID     string                  `json:"siteId"`
	Summary    catalog.BusinessSummary `json:"summary"`
	ObservedAt time.Time               `json:"observedAt"`
	ExpiresAt  time.Time               `json:"expiresAt"`
}

// InstalledTaskFact is a protected-catalog business fact. CapabilityRef must
// bind to a task_evidence capability in the referenced SourceFact.
type InstalledTaskFact struct {
	TenantID        string        `json:"tenantId"`
	SiteID          string        `json:"siteId"`
	TaskHandle      string        `json:"taskHandle"`
	SourceHandle    string        `json:"sourceHandle"`
	SourceRevision  uint64        `json:"sourceRevision"`
	CapabilityRef   string        `json:"capabilityRef"`
	Revision        uint64        `json:"revision"`
	State           catalog.State `json:"state"`
	ObservableCodes []string      `json:"observableCodes"`
	ResultSchema    string        `json:"resultSchema,omitempty"`
	ObservedAt      time.Time     `json:"observedAt"`
	ExpiresAt       time.Time     `json:"expiresAt"`
}

// AuthorityClass mirrors the stable business classes without importing an
// operator grant or any authority implementation into the inspection domain.
type AuthorityClass string

const (
	AuthorityConnectionProfileWrite AuthorityClass = "connection_profile_write"
	AuthorityDeviceRead             AuthorityClass = "device_read"
	AuthorityInspectionExecution    AuthorityClass = "inspection_execution"
	AuthorityPersistentDeviceWrite  AuthorityClass = "persistent_device_write"
	AuthorityServiceExecution       AuthorityClass = "service_execution"
)

// AuthorityAvailability is an already verified, short-lived availability
// fact. An empty SourceHandles list means site-wide availability; otherwise it
// covers only the listed opaque source handles.
type AuthorityAvailability struct {
	Class           AuthorityClass `json:"class"`
	TenantID        string         `json:"tenantId"`
	SiteID          string         `json:"siteId"`
	PrincipalSHA256 string         `json:"principalSha256"`
	SourceHandles   []string       `json:"sourceHandles,omitempty"`
	VerifiedAt      time.Time      `json:"verifiedAt"`
	ExpiresAt       time.Time      `json:"expiresAt"`
}

type Request struct {
	Schema      string                  `json:"schema"`
	Scope       AuthenticatedScope      `json:"scope"`
	Intent      BusinessIntent          `json:"intent"`
	Sources     []SourceFact            `json:"sources"`
	Tasks       []InstalledTaskFact     `json:"tasks"`
	Authorities []AuthorityAvailability `json:"authorities"`
}

type Route string

const (
	RouteExistingTaskRead         Route = "existing_task_read"
	RouteSnapshotAnalysis         Route = "snapshot_analysis"
	RouteClipAnalysis             Route = "clip_analysis"
	RouteHybridAnalysis           Route = "hybrid_analysis"
	RouteUnsupported              Route = "unsupported"
	RouteClarificationRequired    Route = "clarification_required"
	RouteConnectionWorkflow       Route = "connection_workflow"
	RoutePersistentChangeProposal Route = "persistent_change_proposal"
)

type ReasonCode string

const (
	ReasonExistingTaskMatched           ReasonCode = "existing_task_matched"
	ReasonSnapshotCapabilityMatched     ReasonCode = "snapshot_capability_matched"
	ReasonClipCapabilityMatched         ReasonCode = "clip_capability_matched"
	ReasonHybridCapabilitiesMatched     ReasonCode = "hybrid_capabilities_matched"
	ReasonExplicitConnectionRequested   ReasonCode = "explicit_connection_requested"
	ReasonSourceCatalogEmpty            ReasonCode = "source_catalog_empty"
	ReasonSourceAmbiguous               ReasonCode = "source_ambiguous"
	ReasonSourceNotFound                ReasonCode = "source_not_found"
	ReasonSourceStale                   ReasonCode = "source_stale"
	ReasonSourceRevisionChanged         ReasonCode = "source_revision_changed"
	ReasonSourceIdentityDrift           ReasonCode = "source_identity_drift"
	ReasonSourceDisabled                ReasonCode = "source_disabled"
	ReasonTaskAmbiguous                 ReasonCode = "task_ambiguous"
	ReasonTaskNotFound                  ReasonCode = "task_not_found"
	ReasonTaskStale                     ReasonCode = "task_stale"
	ReasonTaskSourceDrift               ReasonCode = "task_source_drift"
	ReasonTaskIdentityDrift             ReasonCode = "task_identity_drift"
	ReasonTaskDisabled                  ReasonCode = "task_disabled"
	ReasonTaskObservableUnavailable     ReasonCode = "task_observable_unavailable"
	ReasonCapabilityUnavailable         ReasonCode = "capability_unavailable"
	ReasonAuthorityUnavailable          ReasonCode = "authority_unavailable"
	ReasonUnsafeTemporaryIntent         ReasonCode = "unsafe_temporary_intent"
	ReasonPersistentChangeNeedsProposal ReasonCode = "persistent_change_requires_proposal"
)

type ConnectionWorkflowHandoff struct {
	Purpose                  ConnectionPurpose `json:"purpose"`
	RequiresSecureLocalInput bool              `json:"requiresSecureLocalInput"`
	RequiredAuthority        AuthorityClass    `json:"requiredAuthority"`
}

type PersistentChangeProposal struct {
	ProposalID             string               `json:"proposalId"`
	Kind                   PersistentChangeKind `json:"kind"`
	SourceHandle           string               `json:"sourceHandle,omitempty"`
	TaskHandle             string               `json:"taskHandle,omitempty"`
	ObservableCode         string               `json:"observableCode,omitempty"`
	ExpectedSourceRevision uint64               `json:"expectedSourceRevision,omitempty"`
	ExpectedTaskRevision   uint64               `json:"expectedTaskRevision,omitempty"`
	RequiredAuthority      AuthorityClass       `json:"requiredAuthority"`
	RequiresConfirmation   bool                 `json:"requiresConfirmation"`
	HandoffOnly            bool                 `json:"handoffOnly"`
}

type Resolution struct {
	Schema                   string                              `json:"schema"`
	Route                    Route                               `json:"route"`
	Reason                   ReasonCode                          `json:"reason"`
	SourceHandles            []string                            `json:"sourceHandles,omitempty"`
	TaskHandles              []string                            `json:"taskHandles,omitempty"`
	CapabilityRefs           []string                            `json:"capabilityRefs,omitempty"`
	RequiredAuthorities      []AuthorityClass                    `json:"requiredAuthorities,omitempty"`
	MissingAuthorities       []AuthorityClass                    `json:"missingAuthorities,omitempty"`
	TemporaryObservationSpec *temporary.TemporaryObservationSpec `json:"temporaryObservationSpec,omitempty"`
	ConnectionWorkflow       *ConnectionWorkflowHandoff          `json:"connectionWorkflow,omitempty"`
	PersistentChangeProposal *PersistentChangeProposal           `json:"persistentChangeProposal,omitempty"`
}
