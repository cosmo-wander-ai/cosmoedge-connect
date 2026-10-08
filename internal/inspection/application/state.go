package application

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/inputguard"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
	_ "modernc.org/sqlite"
)

const (
	applicationStateVersion = 7
	applicationStateID      = 0x43454137 // CEA7
	stateTimeLayout         = "2006-01-02T15:04:05.000000000Z07:00"
	minimumRequestRetention = 48 * time.Hour
	minimumStateRetention   = time.Hour
	maximumStateRetention   = 365 * 24 * time.Hour
)

type audienceRunOrigin string

const (
	audienceRunChannel  audienceRunOrigin = "channel"
	audienceRunSchedule audienceRunOrigin = "schedule"
)

const createAudienceRunsSQL = `CREATE TABLE audience_runs (
    public_run_ref TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    origin TEXT NOT NULL CHECK(origin IN ('channel','schedule')),
    run_kind TEXT NOT NULL CHECK(run_kind IN ('unresolved','standard','temporary')),
    binding_state TEXT NOT NULL CHECK(binding_state IN ('reserved','bound')),
    internal_run_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    purge_after TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    UNIQUE(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref),
    CHECK((binding_state='reserved' AND origin='channel' AND internal_run_id='') OR
          (binding_state='bound' AND run_kind<>'unresolved' AND internal_run_id<>''))
)`

const createAudienceRunInternalIndexSQL = `CREATE UNIQUE INDEX uq_audience_runs_internal_run
    ON audience_runs(internal_run_id) WHERE internal_run_id <> ''`

const createAudienceRunLookupIndexSQL = `CREATE INDEX idx_audience_runs_lookup
    ON audience_runs(tenant_id,site_id,channel,conversation_ref,recipient_ref,principal_sha256,public_run_ref)`

const createAudienceRunUpdateGuardSQL = `CREATE TRIGGER audience_runs_transition_guard
BEFORE UPDATE ON audience_runs
WHEN NOT (OLD.origin='channel' AND OLD.binding_state='reserved' AND NEW.binding_state='bound'
          AND OLD.run_kind='unresolved' AND NEW.run_kind IN ('standard','temporary'))
  OR OLD.public_run_ref <> NEW.public_run_ref
  OR OLD.tenant_id <> NEW.tenant_id
  OR OLD.site_id <> NEW.site_id
  OR OLD.channel <> NEW.channel
  OR OLD.conversation_ref <> NEW.conversation_ref
  OR OLD.recipient_ref <> NEW.recipient_ref
  OR OLD.principal_sha256 <> NEW.principal_sha256
  OR OLD.origin <> NEW.origin
  OR OLD.created_at <> NEW.created_at
  OR OLD.purge_after <> NEW.purge_after
BEGIN
    SELECT RAISE(ABORT, 'invalid audience run transition');
END`

var (
	ErrStateNotFound            = errors.New("inspection application state not found")
	ErrStateConflict            = errors.New("inspection application state conflict")
	ErrStateExpired             = errors.New("inspection media capability expired")
	ErrUnsupportedStateSchema   = errors.New("unsupported inspection application state schema")
	ErrCorruptState             = errors.New("inspection application state integrity failure")
	ErrProtectedStateProjection = errors.New("inspection protected state cannot be projected")
)

type requestResolution string

const (
	requestReserved         requestResolution = "reserved"
	requestStandardPending  requestResolution = "standard_pending"
	requestStandardBound    requestResolution = "standard_bound"
	requestInteraction      requestResolution = "interaction_required"
	requestTemporaryPending requestResolution = "temporary_pending"
	requestTemporaryBound   requestResolution = "temporary_bound"
)

const createRequestsSQL = `CREATE TABLE channel_requests (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
    request_json BLOB NOT NULL,
    public_run_ref TEXT NOT NULL UNIQUE,
    runtime_request_id TEXT NOT NULL UNIQUE,
    request_kind TEXT NOT NULL CHECK(request_kind IN ('unresolved', 'standard', 'temporary')),
    resolution TEXT NOT NULL CHECK(resolution IN ('reserved', 'standard_pending', 'standard_bound', 'interaction_required', 'temporary_pending', 'temporary_bound')),
    internal_run_id TEXT NOT NULL DEFAULT '',
    interaction_json BLOB NOT NULL DEFAULT X'',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    purge_after TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    PRIMARY KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, idempotency_key),
    UNIQUE(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref),
    FOREIGN KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        REFERENCES audience_runs(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK(
        (resolution = 'reserved' AND request_kind = 'unresolved' AND internal_run_id = '' AND length(interaction_json) = 0) OR
        (resolution = 'standard_pending' AND request_kind = 'standard' AND internal_run_id = '' AND length(interaction_json) = 0) OR
        (resolution = 'standard_bound' AND request_kind = 'standard' AND internal_run_id <> '' AND length(interaction_json) = 0) OR
        (resolution = 'interaction_required' AND request_kind = 'unresolved' AND internal_run_id = '' AND length(interaction_json) > 0) OR
        (resolution = 'temporary_pending' AND request_kind = 'temporary' AND internal_run_id = '' AND length(interaction_json) = 0) OR
        (resolution = 'temporary_bound' AND request_kind = 'temporary' AND internal_run_id <> '' AND length(interaction_json) = 0)
    )
)`

const createRequestRefIndexSQL = `CREATE INDEX idx_channel_requests_ref
    ON channel_requests(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)`

const createRequestRunIndexSQL = `CREATE UNIQUE INDEX uq_channel_requests_internal_run
    ON channel_requests(internal_run_id) WHERE internal_run_id <> ''`

const createDecisionsSQL = `CREATE TABLE standard_decisions (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    public_run_ref TEXT PRIMARY KEY,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256) = 64),
    template_json BLOB NOT NULL,
    assignment_json BLOB NOT NULL,
    run_request_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    FOREIGN KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        REFERENCES audience_runs(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)`

const createDecisionsUpdateGuardSQL = `CREATE TRIGGER standard_decisions_no_update
BEFORE UPDATE ON standard_decisions
BEGIN
    SELECT RAISE(ABORT, 'standard decisions are immutable');
END`

const createScheduledDecisionsSQL = `CREATE TABLE scheduled_decisions (
    public_run_ref TEXT PRIMARY KEY,
    occurrence_id TEXT NOT NULL UNIQUE,
    submission_ref TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    binding_ref TEXT NOT NULL,
    binding_revision INTEGER NOT NULL CHECK(binding_revision > 0),
    audience_sha256 TEXT NOT NULL CHECK(length(audience_sha256) = 64),
    delivery_sha256 TEXT NOT NULL CHECK(length(delivery_sha256) = 64),
    service_principal_sha256 TEXT NOT NULL CHECK(length(service_principal_sha256) = 64),
    occurrence_sha256 TEXT NOT NULL CHECK(length(occurrence_sha256) = 64),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256) = 64),
    internal_run_id TEXT NOT NULL UNIQUE,
    template_json BLOB NOT NULL,
    assignment_json BLOB NOT NULL,
    run_request_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    FOREIGN KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        REFERENCES audience_runs(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)`

const createScheduledDecisionsUpdateGuardSQL = `CREATE TRIGGER scheduled_decisions_no_update
BEFORE UPDATE ON scheduled_decisions
BEGIN
    SELECT RAISE(ABORT, 'scheduled decisions are immutable');
END`

const createTemporaryDecisionsSQL = `CREATE TABLE temporary_decisions (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    public_run_ref TEXT PRIMARY KEY,
    runtime_request_id TEXT NOT NULL UNIQUE,
    decision_json BLOB NOT NULL,
    decision_sha256 TEXT NOT NULL CHECK(length(decision_sha256) = 64),
    created_at TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    FOREIGN KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        REFERENCES audience_runs(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)`

const createTemporaryDecisionsUpdateGuardSQL = `CREATE TRIGGER temporary_decisions_no_update
BEFORE UPDATE ON temporary_decisions
BEGIN
    SELECT RAISE(ABORT, 'temporary decisions are immutable');
END`

const createMediaSQL = `CREATE TABLE media_capabilities (
    public_media_ref TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    public_run_ref TEXT NOT NULL,
    internal_run_id TEXT NOT NULL,
    media_binding_run_id TEXT NOT NULL,
    internal_media_ref TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
	content_type TEXT NOT NULL CHECK(content_type IN ('image/jpeg', 'image/png')),
    audience TEXT NOT NULL,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    FOREIGN KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        REFERENCES audience_runs(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)`

const createMediaLookupIndexSQL = `CREATE INDEX idx_media_capabilities_lookup
    ON media_capabilities(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, internal_media_ref, expires_at)`

const createFeedbackSQL = `CREATE TABLE channel_feedback (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    public_run_ref TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    feedback_sha256 TEXT NOT NULL CHECK(length(feedback_sha256) = 64),
    feedback_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    purge_after TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    PRIMARY KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, idempotency_key),
    FOREIGN KEY(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        REFERENCES audience_runs(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref)
        ON UPDATE RESTRICT ON DELETE RESTRICT
)`

const createRequestUpdateGuardSQL = `CREATE TRIGGER channel_requests_transition_guard
BEFORE UPDATE ON channel_requests
WHEN NOT (
       (OLD.resolution = 'reserved' AND NEW.resolution IN ('standard_pending', 'interaction_required', 'temporary_pending'))
    OR (OLD.resolution = 'standard_pending' AND NEW.resolution = 'standard_bound')
    OR (OLD.resolution = 'temporary_pending' AND NEW.resolution = 'temporary_bound')
  )
  OR OLD.tenant_id <> NEW.tenant_id
  OR OLD.site_id <> NEW.site_id
  OR OLD.channel <> NEW.channel
  OR OLD.conversation_ref <> NEW.conversation_ref
  OR OLD.recipient_ref <> NEW.recipient_ref
  OR OLD.principal_sha256 <> NEW.principal_sha256
  OR OLD.idempotency_key <> NEW.idempotency_key
  OR OLD.request_sha256 <> NEW.request_sha256
  OR OLD.request_json <> NEW.request_json
  OR OLD.public_run_ref <> NEW.public_run_ref
  OR OLD.runtime_request_id <> NEW.runtime_request_id
  OR OLD.created_at <> NEW.created_at
  OR OLD.purge_after <> NEW.purge_after
BEGIN
    SELECT RAISE(ABORT, 'invalid channel request transition');
END`

const createMediaUpdateGuardSQL = `CREATE TRIGGER media_capabilities_no_update
BEFORE UPDATE ON media_capabilities
BEGIN
    SELECT RAISE(ABORT, 'media capabilities are immutable');
END`

const createFeedbackUpdateGuardSQL = `CREATE TRIGGER channel_feedback_no_update
BEFORE UPDATE ON channel_feedback
BEGIN
    SELECT RAISE(ABORT, 'channel feedback is immutable');
END`

var applicationStateSchema = []string{
	createAudienceRunsSQL, createAudienceRunInternalIndexSQL, createAudienceRunLookupIndexSQL, createAudienceRunUpdateGuardSQL,
	createRequestsSQL, createRequestRefIndexSQL, createRequestRunIndexSQL,
	createDecisionsSQL, createDecisionsUpdateGuardSQL,
	createScheduledDecisionsSQL, createScheduledDecisionsUpdateGuardSQL,
	createTemporaryDecisionsSQL, createTemporaryDecisionsUpdateGuardSQL,
	createMediaSQL, createMediaLookupIndexSQL, createFeedbackSQL,
	createRequestUpdateGuardSQL, createMediaUpdateGuardSQL, createFeedbackUpdateGuardSQL,
}

type StateConfig struct {
	Path              string
	RequestRetention  time.Duration
	FeedbackRetention time.Duration
	Now               func() time.Time
}

type StateStore struct {
	db                *sql.DB
	path              string
	requestRetention  time.Duration
	feedbackRetention time.Duration
	now               func() time.Time
}

// AudienceRunRecord is the unified, protected binding between one public run,
// one internal run and one exact delivery audience. Channel and schedule
// origins share this row; only channel origin has a channel_requests record.
type AudienceRunRecord struct {
	Session       httpapi.SessionBinding
	PublicRunRef  string
	InternalRunID string
	Origin        string
	RunKind       string
	BindingState  string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	PurgeAfter    time.Time
	RecordSHA256  string
}

func (AudienceRunRecord) MarshalJSON() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (AudienceRunRecord) MarshalText() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (AudienceRunRecord) String() string               { return "[inspection-audience-run]" }
func (AudienceRunRecord) GoString() string             { return "application.AudienceRunRecord([redacted])" }
func (AudienceRunRecord) LogValue() slog.Value         { return slog.StringValue("[inspection-audience-run]") }

type ContinuationRecord struct {
	PublicRunRef string
	Request      httpapi.InspectionRequest
	CreatedAt    time.Time
}

func (ContinuationRecord) MarshalJSON() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (ContinuationRecord) MarshalText() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (ContinuationRecord) String() string               { return "[inspection-continuation-record]" }
func (ContinuationRecord) GoString() string {
	return "application.ContinuationRecord([redacted])"
}
func (ContinuationRecord) LogValue() slog.Value {
	return slog.StringValue("[inspection-continuation-record]")
}

type ScheduledDecisionRecord struct {
	Session                httpapi.SessionBinding
	PublicRunRef           string
	InternalRunID          string
	OccurrenceID           string
	SubmissionRef          string
	BindingRef             string
	BindingRevision        uint64
	AudienceSHA256         string
	DeliverySHA256         string
	ServicePrincipalSHA256 string
	OccurrenceSHA256       string
	RequestSHA256          string
	PlanSHA256             string
	Template               inspection.InspectionTemplate
	Assignment             inspection.Assignment
	RunRequest             inspection.CreateRunRequest
	CreatedAt              time.Time
	PurgeAfter             time.Time
	RecordSHA256           string
}

func (ScheduledDecisionRecord) MarshalJSON() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (ScheduledDecisionRecord) MarshalText() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (ScheduledDecisionRecord) String() string               { return "[inspection-scheduled-decision]" }
func (ScheduledDecisionRecord) GoString() string {
	return "application.ScheduledDecisionRecord([redacted])"
}
func (ScheduledDecisionRecord) LogValue() slog.Value {
	return slog.StringValue("[inspection-scheduled-decision]")
}

type RequestReservation struct {
	Session          httpapi.SessionBinding
	IdempotencyKey   string
	RequestJSON      []byte
	RequestSHA256    string
	PublicRunRef     string
	RuntimeRequestID string
	CreatedAt        time.Time
}

type RequestRecord struct {
	Session          httpapi.SessionBinding
	IdempotencyKey   string
	RequestJSON      []byte
	RequestSHA256    string
	PublicRunRef     string
	RuntimeRequestID string
	RequestKind      string
	Resolution       requestResolution
	InternalRunID    string
	InteractionJSON  []byte
	CreatedAt        time.Time
	UpdatedAt        time.Time
	PurgeAfter       time.Time
	RecordSHA256     string
}

type MediaCapabilityRecord struct {
	Session           httpapi.SessionBinding
	PublicRunRef      string
	PublicMediaRef    string
	InternalRunID     string
	MediaBindingRunID string
	InternalMediaRef  string
	SHA256            string
	SizeBytes         int64
	ContentType       string
	Audience          string
	Title             string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	RecordSHA256      string
}

type StandardDecisionRecord struct {
	Session      httpapi.SessionBinding
	PublicRunRef string
	PlanSHA256   string
	Template     inspection.InspectionTemplate
	Assignment   inspection.Assignment
	RunRequest   inspection.CreateRunRequest
	CreatedAt    time.Time
	RecordSHA256 string
}

type TemporaryDecisionRecord struct {
	Session          httpapi.SessionBinding
	PublicRunRef     string
	RuntimeRequestID string
	Decision         TemporaryDecision
	DecisionSHA256   string
	CreatedAt        time.Time
	RecordSHA256     string
}

type FeedbackRecord struct {
	Session        httpapi.SessionBinding
	PublicRunRef   string
	IdempotencyKey string
	FeedbackJSON   []byte
	FeedbackSHA256 string
	CreatedAt      time.Time
	PurgeAfter     time.Time
	RecordSHA256   string
}

// EvaluationFeedbackProjection is the only feedback shape available to the
// offline evaluator. It contains no comment, raw feedback JSON, idempotency
// key, principal, conversation, recipient, or channel-native identifier.
type EvaluationFeedbackProjection struct {
	PublicRunRef   string
	AudienceSHA256 string
	Helpful        bool
	ReceivedAt     time.Time
}

func (EvaluationFeedbackProjection) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedStateProjection
}
func (EvaluationFeedbackProjection) MarshalText() ([]byte, error) {
	return nil, ErrProtectedStateProjection
}
func (EvaluationFeedbackProjection) String() string { return "[inspection-evaluation-feedback]" }
func (EvaluationFeedbackProjection) GoString() string {
	return "application.EvaluationFeedbackProjection([redacted])"
}
func (EvaluationFeedbackProjection) LogValue() slog.Value {
	return slog.StringValue("[inspection-evaluation-feedback]")
}

type RunAudience struct {
	PublicRunRef    string
	PrincipalSHA256 string `json:"-"`
	Audience        delivery.Audience
}

func (RunAudience) String() string   { return "[inspection-run-audience]" }
func (RunAudience) GoString() string { return "application.RunAudience([redacted])" }
func (RunAudience) LogValue() slog.Value {
	return slog.StringValue("[inspection-run-audience]")
}

type PurgeReport struct {
	MediaCapabilities  int
	FeedbackRecords    int
	StandardDecisions  int
	ScheduledDecisions int
	TemporaryDecisions int
	RequestRecords     int
	AudienceRuns       int
}

// ScheduledPurgeCandidate is the exact protected cross-store identity Product
// must prove terminal before releasing. Application state deliberately cannot
// decide runtime, schedule-reservation or delivery truth by itself.
type ScheduledPurgeCandidate struct {
	PublicRunRef         string
	InternalRunID        string
	OccurrenceID         string
	AudienceSHA256       string
	PurgeAfter           time.Time
	DecisionRecordSHA256 string
	AudienceRecordSHA256 string
}

func (ScheduledPurgeCandidate) MarshalJSON() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (ScheduledPurgeCandidate) MarshalText() ([]byte, error) { return nil, ErrProtectedStateProjection }
func (ScheduledPurgeCandidate) String() string               { return "[inspection-scheduled-purge-candidate]" }
func (ScheduledPurgeCandidate) GoString() string {
	return "application.ScheduledPurgeCandidate([redacted])"
}
func (ScheduledPurgeCandidate) LogValue() slog.Value {
	return slog.StringValue("[inspection-scheduled-purge-candidate]")
}

func OpenState(config StateConfig) (*StateStore, error) {
	if strings.TrimSpace(config.Path) == "" || strings.ContainsAny(config.Path, "?#\x00") ||
		config.RequestRetention < minimumRequestRetention || config.RequestRetention > maximumStateRetention ||
		config.FeedbackRetention < minimumStateRetention || config.FeedbackRetention > maximumStateRetention {
		return nil, ErrUnsupportedStateSchema
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	absolute, err := filepath.Abs(config.Path)
	if err != nil {
		return nil, err
	}
	if err := localstate.PrepareStateRoot(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing inspection application state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, closeErr
		}
		if err := localstate.ProtectFile(absolute); err != nil {
			return nil, err
		}
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	fail := func(openErr error) (*StateStore, error) {
		_ = database.Close()
		return nil, openErr
	}
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF",
		"PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON",
	} {
		if _, err := database.Exec(pragma); err != nil {
			return fail(err)
		}
	}
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fail(err)
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return fail(err)
	}
	if version == 0 {
		var userObjects int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&userObjects); err != nil {
			return fail(err)
		}
		// SQLite DDL is transactional. A crash during first initialization can
		// therefore leave only an otherwise empty, protected version-zero file.
		// That exact state is safe to initialize again; any user object or
		// application marker still fails closed as an unknown schema.
		if applicationID != 0 || userObjects != 0 {
			return fail(ErrUnsupportedStateSchema)
		}
		transaction, err := database.Begin()
		if err != nil {
			return fail(err)
		}
		for _, statement := range applicationStateSchema {
			if _, err := transaction.Exec(statement); err != nil {
				_ = transaction.Rollback()
				return fail(err)
			}
		}
		for _, statement := range []string{
			fmt.Sprintf("PRAGMA application_id=%d", applicationStateID),
			fmt.Sprintf("PRAGMA user_version=%d", applicationStateVersion),
		} {
			if _, err := transaction.Exec(statement); err != nil {
				_ = transaction.Rollback()
				return fail(err)
			}
		}
		if err := transaction.Commit(); err != nil {
			return fail(err)
		}
	} else if version != applicationStateVersion || applicationID != applicationStateID {
		return fail(ErrUnsupportedStateSchema)
	}
	if err := validateStateShape(database); err != nil {
		return fail(err)
	}
	store := &StateStore{
		db: database, path: absolute, requestRetention: config.RequestRetention,
		feedbackRetention: config.FeedbackRetention, now: config.Now,
	}
	if err := store.validateStoredContent(context.Background()); err != nil {
		return fail(err)
	}
	if _, err := store.PurgeExpired(context.Background(), config.Now().UTC()); err != nil {
		return fail(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return fail(err)
	}
	return store, nil
}

func (s *StateStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// MatchRequest resolves an existing idempotency record before any new opaque
// identities are generated. A reused key with different canonical input fails
// closed.
func (s *StateStore) MatchRequest(ctx context.Context, session httpapi.SessionBinding, key string, requestJSON []byte, requestSHA256 string) (RequestRecord, error) {
	if s == nil || validateSession(session) != nil || !validRef(key) || !validDigest(requestSHA256) {
		return RequestRecord{}, ErrStateNotFound
	}
	record, err := getRequestByKey(ctx, s.db, session, key)
	if err != nil {
		return RequestRecord{}, err
	}
	if record.RequestSHA256 != requestSHA256 || string(record.RequestJSON) != string(requestJSON) {
		return RequestRecord{}, ErrStateConflict
	}
	if !record.PurgeAfter.After(s.now().UTC()) {
		return RequestRecord{}, ErrStateNotFound
	}
	return record, nil
}

// FreezeStandardDecision durably stores the exact catalog snapshots and run
// request before runtime submission. A restart therefore replays the same plan
// instead of resolving against a changed catalog.
func (s *StateStore) FreezeStandardDecision(ctx context.Context, value StandardDecisionRecord) (StandardDecisionRecord, bool, error) {
	templateJSON, assignmentJSON, runRequestJSON, err := validateAndMarshalStandardDecision(value)
	if s == nil || err != nil {
		return StandardDecisionRecord{}, false, ErrStateConflict
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.RecordSHA256 = standardDecisionDigest(value, templateJSON, assignmentJSON, runRequestJSON)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StandardDecisionRecord{}, false, err
	}
	defer tx.Rollback()
	request, err := getRequestByRef(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil || request.RuntimeRequestID != value.RunRequest.RequestID ||
		!request.CreatedAt.Equal(value.RunRequest.RequestedAt) || !value.CreatedAt.Equal(request.CreatedAt) ||
		!request.PurgeAfter.After(value.CreatedAt) {
		return StandardDecisionRecord{}, false, ErrStateConflict
	}
	if request.Resolution == requestStandardPending {
		stored, err := getStandardDecision(ctx, tx, value.Session, value.PublicRunRef)
		if err != nil || stored.RecordSHA256 != value.RecordSHA256 {
			return StandardDecisionRecord{}, false, ErrStateConflict
		}
		if err := tx.Commit(); err != nil {
			return StandardDecisionRecord{}, false, err
		}
		return stored, false, nil
	}
	if request.Resolution != requestReserved {
		return StandardDecisionRecord{}, false, ErrStateConflict
	}
	oldDigest := request.RecordSHA256
	request.RequestKind, request.Resolution, request.UpdatedAt = "standard", requestStandardPending, value.CreatedAt
	request.RecordSHA256 = requestRecordDigest(request)
	updated, err := tx.ExecContext(ctx, `UPDATE channel_requests SET request_kind=?, resolution=?, updated_at=?, record_sha256=?
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=? AND resolution='reserved' AND record_sha256=?`,
		request.RequestKind, request.Resolution, formatStateTime(request.UpdatedAt), request.RecordSHA256,
		value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef,
		value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, oldDigest)
	if err != nil {
		return StandardDecisionRecord{}, false, stateConstraint(err)
	}
	if rows, _ := updated.RowsAffected(); rows != 1 {
		return StandardDecisionRecord{}, false, ErrStateConflict
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO standard_decisions(
tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, plan_sha256,
template_json, assignment_json, run_request_json, created_at, record_sha256)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(public_run_ref) DO NOTHING`,
		value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef,
		value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, value.PlanSHA256, templateJSON, assignmentJSON,
		runRequestJSON, formatStateTime(value.CreatedAt), value.RecordSHA256)
	if err != nil {
		return StandardDecisionRecord{}, false, stateConstraint(err)
	}
	rows, _ := result.RowsAffected()
	stored, err := getStandardDecision(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil {
		return StandardDecisionRecord{}, false, err
	}
	if stored.RecordSHA256 != value.RecordSHA256 {
		return StandardDecisionRecord{}, false, ErrStateConflict
	}
	if err := tx.Commit(); err != nil {
		return StandardDecisionRecord{}, false, err
	}
	return stored, rows == 1, nil
}

func (s *StateStore) GetStandardDecision(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (StandardDecisionRecord, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) {
		return StandardDecisionRecord{}, ErrStateNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StandardDecisionRecord{}, err
	}
	defer tx.Rollback()
	request, err := getRequestByRef(ctx, tx, session, publicRunRef)
	if err != nil {
		return StandardDecisionRecord{}, err
	}
	if request.Resolution != requestStandardPending && request.Resolution != requestStandardBound {
		return StandardDecisionRecord{}, ErrStateNotFound
	}
	stored, err := getStandardDecision(ctx, tx, session, publicRunRef)
	if err != nil {
		return StandardDecisionRecord{}, ErrCorruptState
	}
	if err := tx.Commit(); err != nil {
		return StandardDecisionRecord{}, err
	}
	return stored, nil
}

// FreezeScheduledDecision atomically prebinds the exact audience, public run,
// deterministic internal run and frozen plan. Runtime submission must happen
// only after this transaction commits, so terminal outbox materialization can
// never outrun its audience binding.
func (s *StateStore) FreezeScheduledDecision(ctx context.Context, value ScheduledDecisionRecord) (ScheduledDecisionRecord, bool, error) {
	templateJSON, assignmentJSON, requestJSON, err := validateAndMarshalScheduledDecision(value)
	if s == nil || err != nil {
		return ScheduledDecisionRecord{}, false, ErrStateConflict
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.PurgeAfter = value.CreatedAt.Add(s.requestRetention)
	value.RecordSHA256 = scheduledDecisionDigest(value, templateJSON, assignmentJSON, requestJSON)
	audienceRun := AudienceRunRecord{
		Session: value.Session, PublicRunRef: value.PublicRunRef, InternalRunID: value.InternalRunID,
		Origin: string(audienceRunSchedule), RunKind: "standard", BindingState: "bound",
		CreatedAt: value.CreatedAt, UpdatedAt: value.CreatedAt, PurgeAfter: value.PurgeAfter,
	}
	audienceRun.RecordSHA256 = audienceRunDigest(audienceRun)
	if validateAudienceRun(audienceRun) != nil {
		return ScheduledDecisionRecord{}, false, ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ScheduledDecisionRecord{}, false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO audience_runs(public_run_ref,tenant_id,site_id,channel,conversation_ref,recipient_ref,
principal_sha256,origin,run_kind,binding_state,internal_run_id,created_at,updated_at,purge_after,record_sha256)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(public_run_ref) DO NOTHING`, audienceRun.PublicRunRef,
		audienceRun.Session.TenantID, audienceRun.Session.SiteID, audienceRun.Session.Channel, audienceRun.Session.ConversationRef,
		audienceRun.Session.RecipientRef, audienceRun.Session.PrincipalSHA256, audienceRun.Origin, audienceRun.RunKind, audienceRun.BindingState,
		audienceRun.InternalRunID, formatStateTime(audienceRun.CreatedAt), formatStateTime(audienceRun.UpdatedAt),
		formatStateTime(audienceRun.PurgeAfter), audienceRun.RecordSHA256)
	if err != nil {
		return ScheduledDecisionRecord{}, false, stateConstraint(err)
	}
	audienceRows, _ := result.RowsAffected()
	storedAudience, err := getAudienceRunByRef(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil || storedAudience.RecordSHA256 != audienceRun.RecordSHA256 {
		return ScheduledDecisionRecord{}, false, ErrStateConflict
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO scheduled_decisions(public_run_ref,occurrence_id,submission_ref,tenant_id,site_id,
channel,conversation_ref,recipient_ref,principal_sha256,binding_ref,binding_revision,audience_sha256,delivery_sha256,
service_principal_sha256,occurrence_sha256,request_sha256,plan_sha256,internal_run_id,template_json,assignment_json,
run_request_json,created_at,record_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(public_run_ref) DO NOTHING`, value.PublicRunRef, value.OccurrenceID, value.SubmissionRef,
		value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef, value.Session.RecipientRef,
		value.Session.PrincipalSHA256, value.BindingRef, value.BindingRevision, value.AudienceSHA256, value.DeliverySHA256,
		value.ServicePrincipalSHA256, value.OccurrenceSHA256, value.RequestSHA256, value.PlanSHA256, value.InternalRunID,
		templateJSON, assignmentJSON, requestJSON, formatStateTime(value.CreatedAt), value.RecordSHA256)
	if err != nil {
		return ScheduledDecisionRecord{}, false, stateConstraint(err)
	}
	decisionRows, _ := result.RowsAffected()
	stored, err := getScheduledDecisionByRef(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil || stored.RecordSHA256 != value.RecordSHA256 || audienceRows != decisionRows {
		return ScheduledDecisionRecord{}, false, ErrStateConflict
	}
	stored.PurgeAfter = value.PurgeAfter
	if err := tx.Commit(); err != nil {
		return ScheduledDecisionRecord{}, false, err
	}
	return stored, decisionRows == 1, nil
}

func (s *StateStore) GetScheduledDecision(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (ScheduledDecisionRecord, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) {
		return ScheduledDecisionRecord{}, ErrStateNotFound
	}
	audienceRun, err := getAudienceRunByRef(ctx, s.db, session, publicRunRef)
	if err != nil || audienceRun.Origin != string(audienceRunSchedule) || audienceRun.BindingState != "bound" {
		return ScheduledDecisionRecord{}, ErrStateNotFound
	}
	value, err := getScheduledDecisionByRef(ctx, s.db, session, publicRunRef)
	if err != nil {
		return ScheduledDecisionRecord{}, err
	}
	value.PurgeAfter = audienceRun.PurgeAfter
	if value.InternalRunID != audienceRun.InternalRunID {
		return ScheduledDecisionRecord{}, ErrCorruptState
	}
	return value, nil
}

func (s *StateStore) GetScheduledDecisionByRunID(ctx context.Context, internalRunID string) (ScheduledDecisionRecord, error) {
	if s == nil || !validRef(internalRunID) {
		return ScheduledDecisionRecord{}, ErrStateNotFound
	}
	audienceRun, err := getAudienceRunByInternal(ctx, s.db, internalRunID)
	if err != nil || audienceRun.Origin != string(audienceRunSchedule) {
		return ScheduledDecisionRecord{}, ErrStateNotFound
	}
	value, err := scanScheduledDecision(s.db.QueryRowContext(ctx, `SELECT `+scheduledDecisionColumns+` FROM scheduled_decisions WHERE internal_run_id=?`, internalRunID))
	if err != nil {
		return ScheduledDecisionRecord{}, err
	}
	value.PurgeAfter = audienceRun.PurgeAfter
	if value.PublicRunRef != audienceRun.PublicRunRef || value.Session != audienceRun.Session {
		return ScheduledDecisionRecord{}, ErrCorruptState
	}
	return value, nil
}

// AbandonScheduledDecision removes only an exact prebound schedule audience
// for which the authoritative runtime was proven absent. It is intentionally
// separate from retention cleanup: reconciliation may need to release this
// orphan immediately so the schedule reservation can converge without ever
// retrying Submit.
func (s *StateStore) AbandonScheduledDecision(ctx context.Context, expected ScheduledDecisionRecord) (bool, error) {
	if s == nil || s.db == nil || !validRef(expected.PublicRunRef) || !validRef(expected.InternalRunID) ||
		!validRef(expected.OccurrenceID) || !validDigest(expected.RecordSHA256) {
		return false, ErrStateConflict
	}
	templateJSON, assignmentJSON, requestJSON, err := validateAndMarshalScheduledDecision(expected)
	if err != nil || expected.RecordSHA256 != scheduledDecisionDigest(expected, templateJSON, assignmentJSON, requestJSON) {
		return false, ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	stored, err := scanScheduledDecision(tx.QueryRowContext(ctx, `SELECT `+scheduledDecisionColumns+` FROM scheduled_decisions WHERE internal_run_id=?`, expected.InternalRunID))
	if errors.Is(err, ErrStateNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	audience, err := getAudienceRunByInternal(ctx, tx, expected.InternalRunID)
	if err != nil {
		return false, err
	}
	if stored.PublicRunRef != expected.PublicRunRef || stored.OccurrenceID != expected.OccurrenceID ||
		stored.SubmissionRef != expected.SubmissionRef || stored.RecordSHA256 != expected.RecordSHA256 ||
		audience.PublicRunRef != expected.PublicRunRef || audience.Origin != string(audienceRunSchedule) {
		return false, ErrStateConflict
	}
	if err := deleteScheduledBindingTx(ctx, tx, stored.PublicRunRef, stored.RecordSHA256, audience.RecordSHA256, false, time.Time{}); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ListScheduledPurgeCandidates returns retention-expired bindings but never
// deletes them. Product must independently prove schedule reservation release,
// authoritative runtime terminal state and terminal delivery state.
func (s *StateStore) ListScheduledPurgeCandidates(ctx context.Context, now time.Time, limit int) ([]ScheduledPurgeCandidate, error) {
	if s == nil || s.db == nil || now.IsZero() || limit < 1 || limit > 256 {
		return nil, ErrStateConflict
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.public_run_ref,d.internal_run_id,d.occurrence_id,d.audience_sha256,
a.purge_after,d.record_sha256,a.record_sha256
FROM scheduled_decisions d JOIN audience_runs a ON a.public_run_ref=d.public_run_ref
WHERE a.origin='schedule' AND a.binding_state='bound' AND a.purge_after<=?
AND NOT EXISTS(SELECT 1 FROM media_capabilities m WHERE m.public_run_ref=d.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM channel_feedback f WHERE f.public_run_ref=d.public_run_ref)
ORDER BY a.purge_after,d.public_run_ref LIMIT ?`, formatStateTime(now.UTC()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ScheduledPurgeCandidate, 0)
	for rows.Next() {
		var value ScheduledPurgeCandidate
		var purgeAfter string
		if err := rows.Scan(&value.PublicRunRef, &value.InternalRunID, &value.OccurrenceID, &value.AudienceSHA256,
			&purgeAfter, &value.DecisionRecordSHA256, &value.AudienceRecordSHA256); err != nil {
			return nil, err
		}
		value.PurgeAfter, err = parseStateTime(purgeAfter)
		if err != nil || !validRef(value.PublicRunRef) || !validRef(value.InternalRunID) || !validRef(value.OccurrenceID) ||
			!validDigest(value.AudienceSHA256) || !validDigest(value.DecisionRecordSHA256) || !validDigest(value.AudienceRecordSHA256) ||
			value.PurgeAfter.After(now.UTC()) {
			return nil, ErrCorruptState
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

// PurgeScheduledCandidate consumes an exact candidate only after Product has
// established all external terminal proofs. A stale or substituted candidate
// fails closed and cannot delete a newer binding.
func (s *StateStore) PurgeScheduledCandidate(ctx context.Context, candidate ScheduledPurgeCandidate, now time.Time) (bool, error) {
	if s == nil || s.db == nil || now.IsZero() || !validRef(candidate.PublicRunRef) || !validRef(candidate.InternalRunID) ||
		!validRef(candidate.OccurrenceID) || !validDigest(candidate.AudienceSHA256) || !validDigest(candidate.DecisionRecordSHA256) ||
		!validDigest(candidate.AudienceRecordSHA256) || candidate.PurgeAfter.IsZero() || candidate.PurgeAfter.After(now.UTC()) {
		return false, ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	stored, err := scanScheduledDecision(tx.QueryRowContext(ctx, `SELECT `+scheduledDecisionColumns+` FROM scheduled_decisions WHERE internal_run_id=?`, candidate.InternalRunID))
	if errors.Is(err, ErrStateNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	audience, err := getAudienceRunByInternal(ctx, tx, candidate.InternalRunID)
	if err != nil {
		return false, err
	}
	if stored.PublicRunRef != candidate.PublicRunRef || stored.OccurrenceID != candidate.OccurrenceID ||
		stored.AudienceSHA256 != candidate.AudienceSHA256 || stored.RecordSHA256 != candidate.DecisionRecordSHA256 ||
		audience.PublicRunRef != candidate.PublicRunRef || audience.RecordSHA256 != candidate.AudienceRecordSHA256 ||
		!audience.PurgeAfter.Equal(candidate.PurgeAfter) || audience.Origin != string(audienceRunSchedule) {
		return false, ErrStateConflict
	}
	if err := deleteScheduledBindingTx(ctx, tx, candidate.PublicRunRef, candidate.DecisionRecordSHA256,
		candidate.AudienceRecordSHA256, true, now.UTC()); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func deleteScheduledBindingTx(ctx context.Context, tx *sql.Tx, publicRunRef, decisionDigest, audienceDigest string, enforceRetention bool, now time.Time) error {
	if enforceRetention {
		var eligible int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audience_runs a WHERE a.public_run_ref=? AND a.origin='schedule'
AND a.purge_after<=? AND NOT EXISTS(SELECT 1 FROM media_capabilities m WHERE m.public_run_ref=a.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM channel_feedback f WHERE f.public_run_ref=a.public_run_ref)`, publicRunRef, formatStateTime(now)).Scan(&eligible); err != nil {
			return err
		}
		if eligible != 1 {
			return ErrStateConflict
		}
	} else {
		var dependents int
		if err := tx.QueryRowContext(ctx, `SELECT
(SELECT COUNT(*) FROM media_capabilities WHERE public_run_ref=?)+(SELECT COUNT(*) FROM channel_feedback WHERE public_run_ref=?)`,
			publicRunRef, publicRunRef).Scan(&dependents); err != nil {
			return err
		}
		if dependents != 0 {
			return ErrStateConflict
		}
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM scheduled_decisions WHERE public_run_ref=? AND record_sha256=?`, publicRunRef, decisionDigest)
	if err != nil {
		return stateConstraint(err)
	}
	if rows, _ := deleted.RowsAffected(); rows != 1 {
		return ErrStateConflict
	}
	deleted, err = tx.ExecContext(ctx, `DELETE FROM audience_runs WHERE public_run_ref=? AND origin='schedule' AND record_sha256=?`, publicRunRef, audienceDigest)
	if err != nil {
		return stateConstraint(err)
	}
	if rows, _ := deleted.RowsAffected(); rows != 1 {
		return ErrStateConflict
	}
	return nil
}

// FreezeTemporaryDecision persists the complete bounded decision before the
// temporary runtime is called. A crash between runtime Submit and Bind can
// therefore replay the identical submission without invoking the planner or
// selecting media again.
func (s *StateStore) FreezeTemporaryDecision(ctx context.Context, value TemporaryDecisionRecord) (TemporaryDecisionRecord, bool, error) {
	decisionJSON, err := validateAndMarshalTemporaryDecision(value)
	if s == nil || err != nil {
		return TemporaryDecisionRecord{}, false, ErrStateConflict
	}
	value.CreatedAt = value.CreatedAt.UTC()
	digest := sha256.Sum256(decisionJSON)
	value.DecisionSHA256 = hex.EncodeToString(digest[:])
	value.RecordSHA256 = temporaryDecisionDigest(value, decisionJSON)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TemporaryDecisionRecord{}, false, err
	}
	defer tx.Rollback()
	request, err := getRequestByRef(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil || request.RuntimeRequestID != value.RuntimeRequestID || !request.CreatedAt.Equal(value.CreatedAt) ||
		!request.PurgeAfter.After(value.CreatedAt) {
		return TemporaryDecisionRecord{}, false, ErrStateConflict
	}
	if request.Resolution == requestTemporaryPending || request.Resolution == requestTemporaryBound {
		stored, err := getTemporaryDecision(ctx, tx, value.Session, value.PublicRunRef)
		if err != nil || stored.RecordSHA256 != value.RecordSHA256 {
			return TemporaryDecisionRecord{}, false, ErrStateConflict
		}
		if err := tx.Commit(); err != nil {
			return TemporaryDecisionRecord{}, false, err
		}
		return stored, false, nil
	}
	if request.Resolution != requestReserved {
		return TemporaryDecisionRecord{}, false, ErrStateConflict
	}
	oldDigest := request.RecordSHA256
	request.RequestKind, request.Resolution, request.UpdatedAt = "temporary", requestTemporaryPending, value.CreatedAt
	request.RecordSHA256 = requestRecordDigest(request)
	updated, err := tx.ExecContext(ctx, `UPDATE channel_requests SET request_kind=?,resolution=?,updated_at=?,record_sha256=?
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=? AND resolution='reserved' AND record_sha256=?`,
		request.RequestKind, request.Resolution, formatStateTime(request.UpdatedAt), request.RecordSHA256,
		value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef,
		value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, oldDigest)
	if err != nil {
		return TemporaryDecisionRecord{}, false, stateConstraint(err)
	}
	if rows, _ := updated.RowsAffected(); rows != 1 {
		return TemporaryDecisionRecord{}, false, ErrStateConflict
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO temporary_decisions(
tenant_id,site_id,channel,conversation_ref,recipient_ref,principal_sha256,public_run_ref,runtime_request_id,
decision_json,decision_sha256,created_at,record_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(public_run_ref) DO NOTHING`,
		value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef,
		value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, value.RuntimeRequestID, decisionJSON,
		value.DecisionSHA256, formatStateTime(value.CreatedAt), value.RecordSHA256)
	if err != nil {
		return TemporaryDecisionRecord{}, false, stateConstraint(err)
	}
	rows, _ := result.RowsAffected()
	stored, err := getTemporaryDecision(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil || stored.RecordSHA256 != value.RecordSHA256 {
		return TemporaryDecisionRecord{}, false, ErrStateConflict
	}
	if err := tx.Commit(); err != nil {
		return TemporaryDecisionRecord{}, false, err
	}
	return stored, rows == 1, nil
}

func (s *StateStore) GetTemporaryDecision(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (TemporaryDecisionRecord, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) {
		return TemporaryDecisionRecord{}, ErrStateNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TemporaryDecisionRecord{}, err
	}
	defer tx.Rollback()
	request, err := getRequestByRef(ctx, tx, session, publicRunRef)
	if err != nil {
		return TemporaryDecisionRecord{}, err
	}
	if request.Resolution != requestTemporaryPending && request.Resolution != requestTemporaryBound {
		return TemporaryDecisionRecord{}, ErrStateNotFound
	}
	stored, err := getTemporaryDecision(ctx, tx, session, publicRunRef)
	if err != nil {
		return TemporaryDecisionRecord{}, ErrCorruptState
	}
	if err := tx.Commit(); err != nil {
		return TemporaryDecisionRecord{}, err
	}
	return stored, nil
}

// ResolveRunAudience is the sole terminal-outbox bridge. It resolves one
// internal run to exactly one protected audience regardless of origin; the
// globally unique audience_runs index makes a first-recipient fallback
// impossible.
func (s *StateStore) ResolveRunAudience(ctx context.Context, internalRunID string) (RunAudience, error) {
	if s == nil || !validRef(internalRunID) {
		return RunAudience{}, ErrStateNotFound
	}
	record, err := getAudienceRunByInternal(ctx, s.db, internalRunID)
	if err != nil {
		return RunAudience{}, err
	}
	// Channel request retention is also its audience validity boundary. A
	// scheduled audience is different: PurgeAfter only makes it eligible for
	// Product-coordinated cleanup, and it must remain resolvable until terminal
	// delivery truth and reservation release are both proven.
	if record.BindingState != "bound" || record.InternalRunID != internalRunID ||
		(record.Origin == string(audienceRunChannel) && !record.PurgeAfter.After(s.now().UTC())) {
		return RunAudience{}, ErrCorruptState
	}
	return RunAudience{
		PublicRunRef: record.PublicRunRef, PrincipalSHA256: record.Session.PrincipalSHA256,
		Audience: delivery.Audience{
			TenantID: record.Session.TenantID, SiteID: record.Session.SiteID, Channel: record.Session.Channel,
			ConversationRef: record.Session.ConversationRef, RecipientRef: record.Session.RecipientRef,
		},
	}, nil
}

// PurgeExpired removes protected linkages in dependency order. Media rows are
// removed as soon as their capability expires; feedback and request mappings
// use their explicit configured retention windows.
func (s *StateStore) PurgeExpired(ctx context.Context, now time.Time) (PurgeReport, error) {
	if s == nil || s.db == nil || now.IsZero() {
		return PurgeReport{}, errors.New("inspection application purge time is required")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PurgeReport{}, err
	}
	defer tx.Rollback()
	report := PurgeReport{}
	for _, operation := range []struct {
		query string
		count *int
	}{
		{`DELETE FROM media_capabilities WHERE expires_at<=?`, &report.MediaCapabilities},
		{`DELETE FROM channel_feedback WHERE purge_after<=?`, &report.FeedbackRecords},
		{`DELETE FROM standard_decisions WHERE public_run_ref IN(SELECT public_run_ref FROM channel_requests r WHERE purge_after<=?
AND NOT EXISTS(SELECT 1 FROM media_capabilities m WHERE m.public_run_ref=r.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM channel_feedback f WHERE f.public_run_ref=r.public_run_ref))`, &report.StandardDecisions},
		{`DELETE FROM temporary_decisions WHERE public_run_ref IN(SELECT public_run_ref FROM channel_requests r WHERE purge_after<=?
AND NOT EXISTS(SELECT 1 FROM media_capabilities m WHERE m.public_run_ref=r.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM channel_feedback f WHERE f.public_run_ref=r.public_run_ref))`, &report.TemporaryDecisions},
		{`DELETE FROM channel_requests WHERE purge_after<=?
AND NOT EXISTS(SELECT 1 FROM media_capabilities m WHERE m.public_run_ref=channel_requests.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM channel_feedback f WHERE f.public_run_ref=channel_requests.public_run_ref)`, &report.RequestRecords},
		{`DELETE FROM audience_runs WHERE purge_after<=?
AND NOT EXISTS(SELECT 1 FROM channel_requests r WHERE r.public_run_ref=audience_runs.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM scheduled_decisions d WHERE d.public_run_ref=audience_runs.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM media_capabilities m WHERE m.public_run_ref=audience_runs.public_run_ref)
AND NOT EXISTS(SELECT 1 FROM channel_feedback f WHERE f.public_run_ref=audience_runs.public_run_ref)`, &report.AudienceRuns},
	} {
		result, err := tx.ExecContext(ctx, operation.query, formatStateTime(now))
		if err != nil {
			return PurgeReport{}, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return PurgeReport{}, err
		}
		*operation.count = int(rows)
	}
	if err := tx.Commit(); err != nil {
		return PurgeReport{}, err
	}
	return report, nil
}

func (s *StateStore) ReserveRequest(ctx context.Context, value RequestReservation) (RequestRecord, bool, error) {
	if s == nil || s.db == nil || validateReservation(value) != nil {
		return RequestRecord{}, false, ErrStateConflict
	}
	record := RequestRecord{
		Session: value.Session, IdempotencyKey: value.IdempotencyKey,
		RequestJSON: append([]byte(nil), value.RequestJSON...), RequestSHA256: value.RequestSHA256,
		PublicRunRef: value.PublicRunRef, RuntimeRequestID: value.RuntimeRequestID,
		RequestKind: "unresolved", Resolution: requestReserved, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.CreatedAt.UTC(),
		PurgeAfter: value.CreatedAt.UTC().Add(s.requestRetention),
	}
	record.RecordSHA256 = requestRecordDigest(record)
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return RequestRecord{}, false, err
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return RequestRecord{}, false, err
	}
	inTransaction := true
	defer func() {
		if inTransaction {
			_, _ = connection.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	stored, err := getRequestByKey(ctx, connection, value.Session, value.IdempotencyKey)
	if err == nil {
		if stored.RequestSHA256 != record.RequestSHA256 || string(stored.RequestJSON) != string(record.RequestJSON) {
			return RequestRecord{}, false, ErrStateConflict
		}
		if _, err := connection.ExecContext(ctx, `COMMIT`); err != nil {
			return RequestRecord{}, false, err
		}
		inTransaction = false
		return stored, false, nil
	}
	if !errors.Is(err, ErrStateNotFound) {
		return RequestRecord{}, false, err
	}
	audienceRun := AudienceRunRecord{
		Session: record.Session, PublicRunRef: record.PublicRunRef, Origin: string(audienceRunChannel),
		RunKind: "unresolved", BindingState: "reserved", CreatedAt: record.CreatedAt,
		UpdatedAt: record.CreatedAt, PurgeAfter: record.PurgeAfter,
	}
	audienceRun.RecordSHA256 = audienceRunDigest(audienceRun)
	if _, err := connection.ExecContext(ctx, `INSERT INTO audience_runs(public_run_ref,tenant_id,site_id,channel,conversation_ref,recipient_ref,
principal_sha256,origin,run_kind,binding_state,internal_run_id,created_at,updated_at,purge_after,record_sha256)
VALUES(?,?,?,?,?,?,?,?,?,?,'',?,?,?,?) ON CONFLICT(public_run_ref) DO NOTHING`, audienceRun.PublicRunRef,
		audienceRun.Session.TenantID, audienceRun.Session.SiteID, audienceRun.Session.Channel, audienceRun.Session.ConversationRef,
		audienceRun.Session.RecipientRef, audienceRun.Session.PrincipalSHA256, audienceRun.Origin, audienceRun.RunKind, audienceRun.BindingState,
		formatStateTime(audienceRun.CreatedAt), formatStateTime(audienceRun.UpdatedAt), formatStateTime(audienceRun.PurgeAfter), audienceRun.RecordSHA256); err != nil {
		return RequestRecord{}, false, stateConstraint(err)
	}
	storedAudience, err := getAudienceRunByRef(ctx, connection, record.Session, record.PublicRunRef)
	if err != nil || storedAudience.RecordSHA256 != audienceRun.RecordSHA256 {
		return RequestRecord{}, false, ErrStateConflict
	}
	result, err := connection.ExecContext(ctx, `INSERT INTO channel_requests(
tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, idempotency_key, request_sha256, request_json,
public_run_ref, runtime_request_id, request_kind, resolution, internal_run_id, interaction_json,
created_at, updated_at, purge_after, record_sha256) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', X'', ?, ?, ?, ?)
ON CONFLICT(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, idempotency_key) DO NOTHING`,
		record.Session.TenantID, record.Session.SiteID, record.Session.Channel,
		record.Session.ConversationRef, record.Session.RecipientRef, record.Session.PrincipalSHA256, record.IdempotencyKey,
		record.RequestSHA256, record.RequestJSON, record.PublicRunRef, record.RuntimeRequestID,
		record.RequestKind, record.Resolution, formatStateTime(record.CreatedAt), formatStateTime(record.UpdatedAt), formatStateTime(record.PurgeAfter), record.RecordSHA256)
	if err != nil {
		return RequestRecord{}, false, stateConstraint(err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		if _, err := connection.ExecContext(ctx, `ROLLBACK`); err != nil {
			return RequestRecord{}, false, err
		}
		inTransaction = false
		winner, err := getRequestByKey(ctx, connection, value.Session, value.IdempotencyKey)
		if err != nil {
			return RequestRecord{}, false, err
		}
		if winner.RequestSHA256 != record.RequestSHA256 || string(winner.RequestJSON) != string(record.RequestJSON) {
			return RequestRecord{}, false, ErrStateConflict
		}
		return winner, false, nil
	}
	stored, err = getRequestByKey(ctx, connection, value.Session, value.IdempotencyKey)
	if err != nil {
		return RequestRecord{}, false, err
	}
	if stored.RequestSHA256 != record.RequestSHA256 || string(stored.RequestJSON) != string(record.RequestJSON) {
		return RequestRecord{}, false, ErrStateConflict
	}
	if _, err := connection.ExecContext(ctx, `COMMIT`); err != nil {
		return RequestRecord{}, false, err
	}
	inTransaction = false
	return stored, rows == 1, nil
}

func (s *StateStore) BindRun(ctx context.Context, session httpapi.SessionBinding, publicRunRef, internalRunID string, at time.Time) (RequestRecord, bool, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) || !validRef(internalRunID) || at.IsZero() {
		return RequestRecord{}, false, ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RequestRecord{}, false, err
	}
	defer tx.Rollback()
	record, err := getRequestByRef(ctx, tx, session, publicRunRef)
	if err != nil {
		return RequestRecord{}, false, err
	}
	if record.Resolution == requestStandardBound {
		if record.InternalRunID != internalRunID {
			return RequestRecord{}, false, ErrStateConflict
		}
		if err := tx.Commit(); err != nil {
			return RequestRecord{}, false, err
		}
		return record, false, nil
	}
	if record.Resolution != requestStandardPending || at.UTC().Before(record.UpdatedAt) {
		return RequestRecord{}, false, ErrStateConflict
	}
	oldDigest := record.RecordSHA256
	record.RequestKind, record.Resolution, record.InternalRunID, record.UpdatedAt = "standard", requestStandardBound, internalRunID, at.UTC()
	record.RecordSHA256 = requestRecordDigest(record)
	if err := bindAudienceRunTx(ctx, tx, session, publicRunRef, internalRunID, "standard", at.UTC()); err != nil {
		return RequestRecord{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE channel_requests SET request_kind=?, resolution=?, internal_run_id=?, updated_at=?, record_sha256=?
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=? AND resolution='standard_pending' AND record_sha256=?`,
		record.RequestKind, record.Resolution, record.InternalRunID, formatStateTime(record.UpdatedAt), record.RecordSHA256,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, publicRunRef, oldDigest)
	if err != nil {
		return RequestRecord{}, false, stateConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return RequestRecord{}, false, ErrStateConflict
	}
	if err := tx.Commit(); err != nil {
		return RequestRecord{}, false, err
	}
	return record, true, nil
}

func (s *StateStore) BindTemporaryRun(ctx context.Context, session httpapi.SessionBinding, publicRunRef, internalRunID string, at time.Time) (RequestRecord, bool, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) || !validRef(internalRunID) || at.IsZero() {
		return RequestRecord{}, false, ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RequestRecord{}, false, err
	}
	defer tx.Rollback()
	record, err := getRequestByRef(ctx, tx, session, publicRunRef)
	if err != nil {
		return RequestRecord{}, false, err
	}
	if record.Resolution == requestTemporaryBound {
		if record.InternalRunID != internalRunID {
			return RequestRecord{}, false, ErrStateConflict
		}
		if err := tx.Commit(); err != nil {
			return RequestRecord{}, false, err
		}
		return record, false, nil
	}
	if record.Resolution != requestTemporaryPending || at.UTC().Before(record.UpdatedAt) {
		return RequestRecord{}, false, ErrStateConflict
	}
	if _, err := getTemporaryDecision(ctx, tx, session, publicRunRef); err != nil {
		return RequestRecord{}, false, ErrStateConflict
	}
	oldDigest := record.RecordSHA256
	record.RequestKind, record.Resolution, record.InternalRunID, record.UpdatedAt = "temporary", requestTemporaryBound, internalRunID, at.UTC()
	record.RecordSHA256 = requestRecordDigest(record)
	if err := bindAudienceRunTx(ctx, tx, session, publicRunRef, internalRunID, "temporary", at.UTC()); err != nil {
		return RequestRecord{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE channel_requests SET request_kind=?,resolution=?,internal_run_id=?,updated_at=?,record_sha256=?
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=? AND resolution='temporary_pending' AND record_sha256=?`,
		record.RequestKind, record.Resolution, record.InternalRunID, formatStateTime(record.UpdatedAt), record.RecordSHA256,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, publicRunRef, oldDigest)
	if err != nil {
		return RequestRecord{}, false, stateConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return RequestRecord{}, false, ErrStateConflict
	}
	if err := tx.Commit(); err != nil {
		return RequestRecord{}, false, err
	}
	return record, true, nil
}

func (s *StateStore) MarkInteraction(ctx context.Context, session httpapi.SessionBinding, publicRunRef string, interaction httpapi.InteractionRequired, at time.Time) (RequestRecord, bool, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) || validateInteraction(interaction) != nil || at.IsZero() {
		return RequestRecord{}, false, ErrStateConflict
	}
	raw, err := json.Marshal(interaction)
	if err != nil {
		return RequestRecord{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RequestRecord{}, false, err
	}
	defer tx.Rollback()
	record, err := getRequestByRef(ctx, tx, session, publicRunRef)
	if err != nil {
		return RequestRecord{}, false, err
	}
	if record.Resolution == requestInteraction {
		if string(record.InteractionJSON) != string(raw) {
			return RequestRecord{}, false, ErrStateConflict
		}
		if err := tx.Commit(); err != nil {
			return RequestRecord{}, false, err
		}
		return record, false, nil
	}
	if record.Resolution != requestReserved || at.UTC().Before(record.UpdatedAt) {
		return RequestRecord{}, false, ErrStateConflict
	}
	oldDigest := record.RecordSHA256
	record.RequestKind, record.Resolution, record.InteractionJSON, record.UpdatedAt = "unresolved", requestInteraction, raw, at.UTC()
	record.RecordSHA256 = requestRecordDigest(record)
	result, err := tx.ExecContext(ctx, `UPDATE channel_requests SET request_kind=?, resolution=?, interaction_json=?, updated_at=?, record_sha256=?
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=? AND resolution='reserved' AND record_sha256=?`,
		record.RequestKind, record.Resolution, record.InteractionJSON, formatStateTime(record.UpdatedAt), record.RecordSHA256,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, publicRunRef, oldDigest)
	if err != nil {
		return RequestRecord{}, false, stateConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return RequestRecord{}, false, ErrStateConflict
	}
	if err := tx.Commit(); err != nil {
		return RequestRecord{}, false, err
	}
	return record, true, nil
}

func (s *StateStore) GetRunMapping(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (RequestRecord, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) {
		return RequestRecord{}, ErrStateNotFound
	}
	record, err := getRequestByRef(ctx, s.db, session, publicRunRef)
	if err != nil {
		return RequestRecord{}, err
	}
	if record.Resolution != requestStandardBound && record.Resolution != requestTemporaryBound {
		return RequestRecord{}, ErrStateNotFound
	}
	audienceRun, err := getAudienceRunByRef(ctx, s.db, session, publicRunRef)
	if err != nil || audienceRun.Origin != string(audienceRunChannel) || audienceRun.BindingState != "bound" ||
		audienceRun.InternalRunID != record.InternalRunID || audienceRun.RunKind != record.RequestKind {
		return RequestRecord{}, ErrCorruptState
	}
	return record, nil
}

func (s *StateStore) ListContinuationCandidates(ctx context.Context, session httpapi.SessionBinding, after *ContinuationRecord, limit int) ([]ContinuationRecord, error) {
	if s == nil || validateSession(session) != nil || limit < 1 || limit > 5 {
		return nil, ErrStateConflict
	}
	var afterTime, afterRef string
	if after != nil {
		if after.CreatedAt.IsZero() || !validRef(after.PublicRunRef) {
			return nil, ErrStateConflict
		}
		afterTime, afterRef = formatStateTime(after.CreatedAt), after.PublicRunRef
	}
	rows, err := s.db.QueryContext(ctx, `SELECT r.public_run_ref,r.request_json,r.created_at
FROM channel_requests r JOIN audience_runs a
ON a.tenant_id=r.tenant_id AND a.site_id=r.site_id AND a.channel=r.channel AND
a.conversation_ref=r.conversation_ref AND a.recipient_ref=r.recipient_ref AND
a.principal_sha256=r.principal_sha256 AND a.public_run_ref=r.public_run_ref
WHERE r.tenant_id=? AND r.site_id=? AND r.channel=? AND r.conversation_ref=? AND
r.recipient_ref=? AND r.principal_sha256=? AND r.resolution IN ('standard_bound','temporary_bound') AND
a.origin='channel' AND a.binding_state='bound' AND
(r.created_at > ? OR (r.created_at = ? AND r.public_run_ref > ?))
ORDER BY r.created_at,r.public_run_ref LIMIT ?`, session.TenantID, session.SiteID, session.Channel,
		session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, afterTime, afterTime, afterRef, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ContinuationRecord, 0, limit)
	for rows.Next() {
		var value ContinuationRecord
		var raw []byte
		var createdAt string
		if err := rows.Scan(&value.PublicRunRef, &raw, &createdAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &value.Request); err != nil {
			return nil, ErrCorruptState
		}
		canonical, _, err := canonicalRequest(value.Request)
		if err != nil || string(canonical) != string(raw) {
			return nil, ErrCorruptState
		}
		value.CreatedAt, err = parseStateTime(createdAt)
		if err != nil {
			return nil, ErrCorruptState
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// GetAudienceRun is the scoped public projection used by application reads.
// It never searches by partial audience identity.
func (s *StateStore) GetAudienceRun(ctx context.Context, session httpapi.SessionBinding, publicRunRef string) (AudienceRunRecord, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicRunRef) {
		return AudienceRunRecord{}, ErrStateNotFound
	}
	value, err := getAudienceRunByRef(ctx, s.db, session, publicRunRef)
	if err != nil {
		return AudienceRunRecord{}, err
	}
	if value.BindingState != "bound" || !value.PurgeAfter.After(s.now().UTC()) {
		return AudienceRunRecord{}, ErrStateNotFound
	}
	return value, nil
}

func (s *StateStore) EnsureMediaCapability(ctx context.Context, value MediaCapabilityRecord, now time.Time) (MediaCapabilityRecord, error) {
	if s == nil || validateMediaCapabilityRecord(value) != nil || now.IsZero() {
		return MediaCapabilityRecord{}, ErrStateConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MediaCapabilityRecord{}, err
	}
	defer tx.Rollback()
	audienceRun, err := getAudienceRunByRef(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil || audienceRun.BindingState != "bound" ||
		audienceRun.InternalRunID != value.InternalRunID || audienceRun.InternalRunID != value.MediaBindingRunID {
		return MediaCapabilityRecord{}, ErrStateNotFound
	}
	row := tx.QueryRowContext(ctx, `SELECT `+mediaColumns+` FROM media_capabilities
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=? AND internal_media_ref=? AND expires_at>?
	ORDER BY expires_at DESC, public_media_ref LIMIT 1`, value.Session.TenantID, value.Session.SiteID, value.Session.Channel,
		value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, value.InternalMediaRef, formatStateTime(now.UTC()))
	existing, err := scanMedia(row)
	if err == nil {
		if existing.InternalRunID != value.InternalRunID || existing.MediaBindingRunID != value.MediaBindingRunID || existing.SHA256 != value.SHA256 || existing.SizeBytes != value.SizeBytes ||
			existing.ContentType != value.ContentType || existing.Audience != value.Audience || existing.Title != value.Title {
			return MediaCapabilityRecord{}, ErrStateConflict
		}
		if err := tx.Commit(); err != nil {
			return MediaCapabilityRecord{}, err
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return MediaCapabilityRecord{}, err
	}
	value.CreatedAt, value.ExpiresAt = value.CreatedAt.UTC(), value.ExpiresAt.UTC()
	value.RecordSHA256 = mediaRecordDigest(value)
	_, err = tx.ExecContext(ctx, `INSERT INTO media_capabilities(
public_media_ref, tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, internal_run_id,
media_binding_run_id, internal_media_ref, sha256, size_bytes, content_type, audience, title, created_at, expires_at, record_sha256)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, value.PublicMediaRef, value.Session.TenantID,
		value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, value.InternalRunID,
		value.MediaBindingRunID, value.InternalMediaRef, value.SHA256, value.SizeBytes, value.ContentType, value.Audience, value.Title,
		formatStateTime(value.CreatedAt), formatStateTime(value.ExpiresAt), value.RecordSHA256)
	if err != nil {
		return MediaCapabilityRecord{}, stateConstraint(err)
	}
	if err := tx.Commit(); err != nil {
		return MediaCapabilityRecord{}, err
	}
	return value, nil
}

func (s *StateStore) GetMediaCapability(ctx context.Context, session httpapi.SessionBinding, publicMediaRef string, now time.Time) (MediaCapabilityRecord, error) {
	if s == nil || validateSession(session) != nil || !validRef(publicMediaRef) || now.IsZero() {
		return MediaCapabilityRecord{}, ErrStateNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+mediaColumns+` FROM media_capabilities
WHERE public_media_ref=? AND tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=?`, publicMediaRef,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256)
	value, err := scanMedia(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MediaCapabilityRecord{}, ErrStateNotFound
	}
	if err != nil {
		return MediaCapabilityRecord{}, err
	}
	if !value.ExpiresAt.After(now.UTC()) {
		return MediaCapabilityRecord{}, ErrStateExpired
	}
	audienceRun, err := getAudienceRunByRef(ctx, s.db, session, value.PublicRunRef)
	if err != nil || audienceRun.BindingState != "bound" ||
		audienceRun.InternalRunID != value.InternalRunID || audienceRun.InternalRunID != value.MediaBindingRunID {
		return MediaCapabilityRecord{}, ErrCorruptState
	}
	return value, nil
}

func (s *StateStore) RecordFeedback(ctx context.Context, value FeedbackRecord) (bool, error) {
	if s == nil || s.db == nil {
		return false, ErrStateConflict
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.PurgeAfter = value.CreatedAt.Add(s.feedbackRetention)
	if validateFeedbackRecord(value) != nil {
		return false, ErrStateConflict
	}
	value.RecordSHA256 = feedbackRecordDigest(value)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	audienceRun, err := getAudienceRunByRef(ctx, tx, value.Session, value.PublicRunRef)
	if err != nil || audienceRun.BindingState != "bound" {
		return false, ErrStateNotFound
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO channel_feedback(
tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, idempotency_key, feedback_sha256,
feedback_json, created_at, purge_after, record_sha256) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, idempotency_key) DO NOTHING`,
		value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef, value.Session.RecipientRef,
		value.Session.PrincipalSHA256, value.PublicRunRef, value.IdempotencyKey, value.FeedbackSHA256, value.FeedbackJSON,
		formatStateTime(value.CreatedAt), formatStateTime(value.PurgeAfter), value.RecordSHA256)
	if err != nil {
		return false, stateConstraint(err)
	}
	rows, _ := result.RowsAffected()
	stored, err := getFeedback(ctx, tx, value.Session, value.PublicRunRef, value.IdempotencyKey)
	if err != nil {
		return false, err
	}
	if stored.FeedbackSHA256 != value.FeedbackSHA256 || string(stored.FeedbackJSON) != string(value.FeedbackJSON) {
		return false, ErrStateConflict
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return rows == 1, nil
}

// GetEvaluationFeedback returns one exact, comment-free feedback projection.
// The protected session is reconstructed from the unique public run before
// the caller-supplied full audience digest is checked. Zero records are not
// found; multiple or corrupt records fail closed.
func (s *StateStore) GetEvaluationFeedback(ctx context.Context, publicRunRef, audienceSHA256 string) (EvaluationFeedbackProjection, error) {
	if s == nil || s.db == nil || !validRef(publicRunRef) || !validDigest(audienceSHA256) {
		return EvaluationFeedbackProjection{}, ErrStateNotFound
	}
	audienceRun, err := getAudienceRunByPublic(ctx, s.db, publicRunRef)
	if err != nil {
		return EvaluationFeedbackProjection{}, err
	}
	if audienceRun.BindingState != "bound" {
		return EvaluationFeedbackProjection{}, ErrCorruptState
	}
	audience := delivery.Audience{
		TenantID: audienceRun.Session.TenantID, SiteID: audienceRun.Session.SiteID, Channel: audienceRun.Session.Channel,
		ConversationRef: audienceRun.Session.ConversationRef, RecipientRef: audienceRun.Session.RecipientRef,
	}
	storedAudienceSHA256, err := audience.SHA256()
	if err != nil {
		return EvaluationFeedbackProjection{}, ErrCorruptState
	}
	if storedAudienceSHA256 != audienceSHA256 {
		return EvaluationFeedbackProjection{}, ErrStateNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+feedbackColumns+` FROM channel_feedback
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=?
ORDER BY idempotency_key LIMIT 2`, audienceRun.Session.TenantID, audienceRun.Session.SiteID, audienceRun.Session.Channel,
		audienceRun.Session.ConversationRef, audienceRun.Session.RecipientRef, audienceRun.Session.PrincipalSHA256, publicRunRef)
	if err != nil {
		return EvaluationFeedbackProjection{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return EvaluationFeedbackProjection{}, err
		}
		return EvaluationFeedbackProjection{}, ErrStateNotFound
	}
	record, err := scanFeedback(rows)
	if err != nil {
		return EvaluationFeedbackProjection{}, err
	}
	if rows.Next() {
		return EvaluationFeedbackProjection{}, ErrCorruptState
	}
	if err := rows.Err(); err != nil {
		return EvaluationFeedbackProjection{}, err
	}
	if record.Session != audienceRun.Session || record.PublicRunRef != publicRunRef {
		return EvaluationFeedbackProjection{}, ErrCorruptState
	}
	var payload httpapi.FeedbackRequest
	if err := decodeCanonical(record.FeedbackJSON, &payload); err != nil || payload.Helpful == nil {
		return EvaluationFeedbackProjection{}, ErrCorruptState
	}
	return EvaluationFeedbackProjection{PublicRunRef: publicRunRef, AudienceSHA256: storedAudienceSHA256,
		Helpful: *payload.Helpful, ReceivedAt: record.CreatedAt}, nil
}

const requestColumns = `tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, idempotency_key, request_sha256, request_json, public_run_ref, runtime_request_id, request_kind, resolution, internal_run_id, interaction_json, created_at, updated_at, purge_after, record_sha256`
const audienceRunColumns = `public_run_ref,tenant_id,site_id,channel,conversation_ref,recipient_ref,principal_sha256,origin,run_kind,binding_state,internal_run_id,created_at,updated_at,purge_after,record_sha256`
const decisionColumns = `tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, plan_sha256, template_json, assignment_json, run_request_json, created_at, record_sha256`
const scheduledDecisionColumns = `public_run_ref,occurrence_id,submission_ref,tenant_id,site_id,channel,conversation_ref,recipient_ref,principal_sha256,binding_ref,binding_revision,audience_sha256,delivery_sha256,service_principal_sha256,occurrence_sha256,request_sha256,plan_sha256,internal_run_id,template_json,assignment_json,run_request_json,created_at,record_sha256`
const temporaryDecisionColumns = `tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, runtime_request_id, decision_json, decision_sha256, created_at, record_sha256`
const mediaColumns = `public_media_ref, tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, internal_run_id, media_binding_run_id, internal_media_ref, sha256, size_bytes, content_type, audience, title, created_at, expires_at, record_sha256`
const feedbackColumns = `tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, idempotency_key, feedback_sha256, feedback_json, created_at, purge_after, record_sha256`

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getAudienceRunByRef(ctx context.Context, query queryRower, session httpapi.SessionBinding, ref string) (AudienceRunRecord, error) {
	return scanAudienceRun(query.QueryRowContext(ctx, `SELECT `+audienceRunColumns+` FROM audience_runs
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=?`,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, ref))
}

func getAudienceRunByInternal(ctx context.Context, query queryRower, runID string) (AudienceRunRecord, error) {
	return scanAudienceRun(query.QueryRowContext(ctx, `SELECT `+audienceRunColumns+` FROM audience_runs WHERE internal_run_id=?`, runID))
}

func getAudienceRunByPublic(ctx context.Context, query queryRower, publicRunRef string) (AudienceRunRecord, error) {
	return scanAudienceRun(query.QueryRowContext(ctx, `SELECT `+audienceRunColumns+` FROM audience_runs WHERE public_run_ref=?`, publicRunRef))
}

func bindAudienceRunTx(ctx context.Context, tx *sql.Tx, session httpapi.SessionBinding, publicRunRef, internalRunID, runKind string, at time.Time) error {
	stored, err := getAudienceRunByRef(ctx, tx, session, publicRunRef)
	if err != nil {
		return err
	}
	if stored.Origin != string(audienceRunChannel) {
		return ErrStateConflict
	}
	if stored.BindingState == "bound" {
		if stored.InternalRunID != internalRunID || stored.RunKind != runKind {
			return ErrStateConflict
		}
		return nil
	}
	if stored.BindingState != "reserved" || stored.RunKind != "unresolved" || !validRef(internalRunID) ||
		runKind != "standard" && runKind != "temporary" || at.Before(stored.UpdatedAt) {
		return ErrStateConflict
	}
	oldDigest := stored.RecordSHA256
	stored.InternalRunID, stored.RunKind, stored.BindingState, stored.UpdatedAt = internalRunID, runKind, "bound", at.UTC()
	stored.RecordSHA256 = audienceRunDigest(stored)
	result, err := tx.ExecContext(ctx, `UPDATE audience_runs SET run_kind=?,binding_state='bound',internal_run_id=?,updated_at=?,record_sha256=?
WHERE public_run_ref=? AND origin='channel' AND binding_state='reserved' AND record_sha256=?`, stored.RunKind, stored.InternalRunID,
		formatStateTime(stored.UpdatedAt), stored.RecordSHA256, publicRunRef, oldDigest)
	if err != nil {
		return stateConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrStateConflict
	}
	return nil
}

func getRequestByKey(ctx context.Context, query queryRower, session httpapi.SessionBinding, key string) (RequestRecord, error) {
	return scanRequest(query.QueryRowContext(ctx, `SELECT `+requestColumns+` FROM channel_requests WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND idempotency_key=?`,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, key))
}

func getRequestByRef(ctx context.Context, query queryRower, session httpapi.SessionBinding, ref string) (RequestRecord, error) {
	return scanRequest(query.QueryRowContext(ctx, `SELECT `+requestColumns+` FROM channel_requests WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=?`,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, ref))
}

func getStandardDecision(ctx context.Context, query queryRower, session httpapi.SessionBinding, ref string) (StandardDecisionRecord, error) {
	return scanStandardDecision(query.QueryRowContext(ctx, `SELECT `+decisionColumns+` FROM standard_decisions
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=?`,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, ref))
}

func getScheduledDecisionByRef(ctx context.Context, query queryRower, session httpapi.SessionBinding, ref string) (ScheduledDecisionRecord, error) {
	return scanScheduledDecision(query.QueryRowContext(ctx, `SELECT `+scheduledDecisionColumns+` FROM scheduled_decisions
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=?`,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, ref))
}

func getTemporaryDecision(ctx context.Context, query queryRower, session httpapi.SessionBinding, ref string) (TemporaryDecisionRecord, error) {
	return scanTemporaryDecision(query.QueryRowContext(ctx, `SELECT `+temporaryDecisionColumns+` FROM temporary_decisions
WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=?`,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, ref))
}

type rowScanner interface{ Scan(...any) error }

func scanAudienceRun(row rowScanner) (AudienceRunRecord, error) {
	var value AudienceRunRecord
	var createdAt, updatedAt, purgeAfter string
	err := row.Scan(&value.PublicRunRef, &value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel,
		&value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256, &value.Origin,
		&value.RunKind, &value.BindingState, &value.InternalRunID, &createdAt, &updatedAt, &purgeAfter, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return AudienceRunRecord{}, ErrStateNotFound
	}
	if err != nil {
		return AudienceRunRecord{}, err
	}
	if value.CreatedAt, err = parseStateTime(createdAt); err == nil {
		value.UpdatedAt, err = parseStateTime(updatedAt)
	}
	if err == nil {
		value.PurgeAfter, err = parseStateTime(purgeAfter)
	}
	if err != nil || validateAudienceRun(value) != nil || value.RecordSHA256 != audienceRunDigest(value) {
		return AudienceRunRecord{}, ErrCorruptState
	}
	return value, nil
}

func scanRequest(row rowScanner) (RequestRecord, error) {
	var value RequestRecord
	var createdAt, updatedAt, purgeAfter string
	err := row.Scan(&value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel, &value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256, &value.IdempotencyKey,
		&value.RequestSHA256, &value.RequestJSON, &value.PublicRunRef, &value.RuntimeRequestID,
		&value.RequestKind, &value.Resolution, &value.InternalRunID, &value.InteractionJSON, &createdAt, &updatedAt, &purgeAfter, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestRecord{}, ErrStateNotFound
	}
	if err != nil {
		return RequestRecord{}, err
	}
	if value.CreatedAt, err = parseStateTime(createdAt); err != nil {
		return RequestRecord{}, ErrCorruptState
	}
	if value.UpdatedAt, err = parseStateTime(updatedAt); err != nil {
		return RequestRecord{}, ErrCorruptState
	}
	if value.PurgeAfter, err = parseStateTime(purgeAfter); err != nil {
		return RequestRecord{}, ErrCorruptState
	}
	if err := validateRequestRecord(value); err != nil {
		return RequestRecord{}, errors.Join(ErrCorruptState, err)
	}
	return value, nil
}

func scanStandardDecision(row rowScanner) (StandardDecisionRecord, error) {
	var value StandardDecisionRecord
	var templateJSON, assignmentJSON, runRequestJSON []byte
	var createdAt string
	err := row.Scan(&value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel,
		&value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256, &value.PublicRunRef, &value.PlanSHA256,
		&templateJSON, &assignmentJSON, &runRequestJSON, &createdAt, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return StandardDecisionRecord{}, ErrStateNotFound
	}
	if err != nil {
		return StandardDecisionRecord{}, err
	}
	if value.CreatedAt, err = parseStateTime(createdAt); err != nil {
		return StandardDecisionRecord{}, ErrCorruptState
	}
	if err := decodeCanonical(templateJSON, &value.Template); err != nil {
		return StandardDecisionRecord{}, ErrCorruptState
	}
	if err := decodeCanonical(assignmentJSON, &value.Assignment); err != nil {
		return StandardDecisionRecord{}, ErrCorruptState
	}
	if err := decodeCanonical(runRequestJSON, &value.RunRequest); err != nil {
		return StandardDecisionRecord{}, ErrCorruptState
	}
	canonicalTemplate, canonicalAssignment, canonicalRequest, err := validateAndMarshalStandardDecision(value)
	if err != nil || string(canonicalTemplate) != string(templateJSON) || string(canonicalAssignment) != string(assignmentJSON) ||
		string(canonicalRequest) != string(runRequestJSON) || value.RecordSHA256 != standardDecisionDigest(value, templateJSON, assignmentJSON, runRequestJSON) {
		return StandardDecisionRecord{}, ErrCorruptState
	}
	return value, nil
}

func scanScheduledDecision(row rowScanner) (ScheduledDecisionRecord, error) {
	var value ScheduledDecisionRecord
	var templateJSON, assignmentJSON, requestJSON []byte
	var createdAt string
	err := row.Scan(&value.PublicRunRef, &value.OccurrenceID, &value.SubmissionRef, &value.Session.TenantID, &value.Session.SiteID,
		&value.Session.Channel, &value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256,
		&value.BindingRef, &value.BindingRevision, &value.AudienceSHA256, &value.DeliverySHA256, &value.ServicePrincipalSHA256,
		&value.OccurrenceSHA256, &value.RequestSHA256, &value.PlanSHA256, &value.InternalRunID, &templateJSON, &assignmentJSON,
		&requestJSON, &createdAt, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return ScheduledDecisionRecord{}, ErrStateNotFound
	}
	if err != nil {
		return ScheduledDecisionRecord{}, err
	}
	if value.CreatedAt, err = parseStateTime(createdAt); err == nil {
		err = decodeCanonical(templateJSON, &value.Template)
	}
	if err == nil {
		err = decodeCanonical(assignmentJSON, &value.Assignment)
	}
	if err == nil {
		err = decodeCanonical(requestJSON, &value.RunRequest)
	}
	if err != nil {
		return ScheduledDecisionRecord{}, ErrCorruptState
	}
	canonicalTemplate, canonicalAssignment, canonicalRequest, err := validateAndMarshalScheduledDecision(value)
	if err != nil || string(canonicalTemplate) != string(templateJSON) || string(canonicalAssignment) != string(assignmentJSON) ||
		string(canonicalRequest) != string(requestJSON) || value.RecordSHA256 != scheduledDecisionDigest(value, templateJSON, assignmentJSON, requestJSON) {
		return ScheduledDecisionRecord{}, ErrCorruptState
	}
	return value, nil
}

func scanTemporaryDecision(row rowScanner) (TemporaryDecisionRecord, error) {
	var value TemporaryDecisionRecord
	var decisionJSON []byte
	var createdAt string
	err := row.Scan(&value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel,
		&value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256, &value.PublicRunRef, &value.RuntimeRequestID,
		&decisionJSON, &value.DecisionSHA256, &createdAt, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return TemporaryDecisionRecord{}, ErrStateNotFound
	}
	if err != nil {
		return TemporaryDecisionRecord{}, err
	}
	if value.CreatedAt, err = parseStateTime(createdAt); err != nil {
		return TemporaryDecisionRecord{}, ErrCorruptState
	}
	if value.Decision, err = unmarshalTemporaryDecisionStorage(decisionJSON); err != nil {
		return TemporaryDecisionRecord{}, ErrCorruptState
	}
	canonical, err := validateAndMarshalTemporaryDecision(value)
	digest := sha256.Sum256(decisionJSON)
	if err != nil || string(canonical) != string(decisionJSON) || value.DecisionSHA256 != hex.EncodeToString(digest[:]) ||
		value.RecordSHA256 != temporaryDecisionDigest(value, decisionJSON) {
		return TemporaryDecisionRecord{}, ErrCorruptState
	}
	return value, nil
}

func scanMedia(row rowScanner) (MediaCapabilityRecord, error) {
	var value MediaCapabilityRecord
	var createdAt, expiresAt string
	err := row.Scan(&value.PublicMediaRef, &value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel,
		&value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256,
		&value.PublicRunRef, &value.InternalRunID, &value.MediaBindingRunID, &value.InternalMediaRef, &value.SHA256, &value.SizeBytes,
		&value.ContentType, &value.Audience, &value.Title, &createdAt, &expiresAt, &value.RecordSHA256)
	if err != nil {
		return MediaCapabilityRecord{}, err
	}
	if value.CreatedAt, err = parseStateTime(createdAt); err != nil {
		return MediaCapabilityRecord{}, ErrCorruptState
	}
	if value.ExpiresAt, err = parseStateTime(expiresAt); err != nil {
		return MediaCapabilityRecord{}, ErrCorruptState
	}
	if err := validateMediaCapabilityRecord(value); err != nil || value.RecordSHA256 != mediaRecordDigest(value) {
		return MediaCapabilityRecord{}, ErrCorruptState
	}
	return value, nil
}

func getFeedback(ctx context.Context, query queryRower, session httpapi.SessionBinding, runRef, key string) (FeedbackRecord, error) {
	return scanFeedback(query.QueryRowContext(ctx, `SELECT `+feedbackColumns+` FROM channel_feedback WHERE tenant_id=? AND site_id=? AND channel=? AND conversation_ref=? AND recipient_ref=? AND principal_sha256=? AND public_run_ref=? AND idempotency_key=?`,
		session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef, session.PrincipalSHA256, runRef, key))
}

func scanFeedback(row rowScanner) (FeedbackRecord, error) {
	var value FeedbackRecord
	var createdAt, purgeAfter string
	err := row.Scan(&value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel, &value.Session.ConversationRef,
		&value.Session.RecipientRef, &value.Session.PrincipalSHA256, &value.PublicRunRef, &value.IdempotencyKey,
		&value.FeedbackSHA256, &value.FeedbackJSON, &createdAt, &purgeAfter, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return FeedbackRecord{}, ErrStateNotFound
	}
	if err != nil {
		return FeedbackRecord{}, err
	}
	if value.CreatedAt, err = parseStateTime(createdAt); err != nil {
		return FeedbackRecord{}, ErrCorruptState
	}
	if value.PurgeAfter, err = parseStateTime(purgeAfter); err != nil {
		return FeedbackRecord{}, ErrCorruptState
	}
	if err := validateFeedbackRecord(value); err != nil || value.RecordSHA256 != feedbackRecordDigest(value) {
		return FeedbackRecord{}, ErrCorruptState
	}
	return value, nil
}

func validateReservation(value RequestReservation) error {
	if validateSession(value.Session) != nil || !validRef(value.IdempotencyKey) || !validRef(value.PublicRunRef) ||
		!validRef(value.RuntimeRequestID) || value.CreatedAt.IsZero() || !validDigest(value.RequestSHA256) {
		return errors.New("invalid inspection request reservation")
	}
	var request httpapi.InspectionRequest
	if err := decodeCanonical(value.RequestJSON, &request); err != nil {
		return err
	}
	canonical, digest, err := canonicalRequest(request)
	if err != nil || string(canonical) != string(value.RequestJSON) || digest != value.RequestSHA256 {
		return errors.New("inspection request digest mismatch")
	}
	return nil
}

func validateRequestRecord(value RequestRecord) error {
	if validateReservation(RequestReservation{
		Session: value.Session, IdempotencyKey: value.IdempotencyKey, RequestJSON: value.RequestJSON,
		RequestSHA256: value.RequestSHA256, PublicRunRef: value.PublicRunRef,
		RuntimeRequestID: value.RuntimeRequestID, CreatedAt: value.CreatedAt,
	}) != nil || value.UpdatedAt.Before(value.CreatedAt) || !value.PurgeAfter.After(value.UpdatedAt) ||
		value.PurgeAfter.After(value.CreatedAt.Add(maximumStateRetention)) || !validDigest(value.RecordSHA256) {
		return errors.New("invalid channel request record")
	}
	switch value.Resolution {
	case requestReserved:
		if value.RequestKind != "unresolved" || value.InternalRunID != "" || len(value.InteractionJSON) != 0 || !value.UpdatedAt.Equal(value.CreatedAt) {
			return errors.New("invalid reserved request")
		}
	case requestStandardPending:
		if value.RequestKind != "standard" || value.InternalRunID != "" || len(value.InteractionJSON) != 0 {
			return errors.New("invalid standard-pending request")
		}
	case requestStandardBound:
		if value.RequestKind != "standard" || !validRef(value.InternalRunID) || len(value.InteractionJSON) != 0 {
			return errors.New("invalid bound request")
		}
	case requestInteraction:
		if value.RequestKind != "unresolved" || value.InternalRunID != "" {
			return errors.New("invalid interaction request")
		}
		if _, err := decodeInteraction(value.InteractionJSON); err != nil {
			return err
		}
	case requestTemporaryPending:
		if value.RequestKind != "temporary" || value.InternalRunID != "" || len(value.InteractionJSON) != 0 {
			return errors.New("invalid temporary request")
		}
	case requestTemporaryBound:
		if value.RequestKind != "temporary" || !validRef(value.InternalRunID) || len(value.InteractionJSON) != 0 {
			return errors.New("invalid bound temporary request")
		}
	default:
		return errors.New("invalid request resolution")
	}
	if value.RecordSHA256 != requestRecordDigest(value) {
		return errors.New("channel request record digest mismatch")
	}
	return nil
}

func validateAudienceRun(value AudienceRunRecord) error {
	if validateSession(value.Session) != nil || !validRef(value.PublicRunRef) || value.CreatedAt.IsZero() ||
		value.UpdatedAt.Before(value.CreatedAt) || !value.PurgeAfter.After(value.UpdatedAt) ||
		value.PurgeAfter.After(value.CreatedAt.Add(maximumStateRetention)) || !validDigest(value.RecordSHA256) {
		return errors.New("invalid audience run record")
	}
	switch audienceRunOrigin(value.Origin) {
	case audienceRunChannel:
		if value.BindingState == "reserved" {
			if value.RunKind != "unresolved" || value.InternalRunID != "" || !value.UpdatedAt.Equal(value.CreatedAt) {
				return errors.New("invalid reserved channel audience run")
			}
		} else if value.BindingState != "bound" || value.RunKind != "standard" && value.RunKind != "temporary" || !validRef(value.InternalRunID) {
			return errors.New("invalid bound channel audience run")
		}
	case audienceRunSchedule:
		if value.BindingState != "bound" || value.RunKind != "standard" || !validRef(value.InternalRunID) || !value.UpdatedAt.Equal(value.CreatedAt) {
			return errors.New("invalid scheduled audience run")
		}
	default:
		return errors.New("invalid audience run origin")
	}
	return nil
}

func validateMediaCapabilityRecord(value MediaCapabilityRecord) error {
	if validateSession(value.Session) != nil || !validRef(value.PublicRunRef) || !validRef(value.PublicMediaRef) ||
		!validRef(value.InternalRunID) || !validRef(value.MediaBindingRunID) || !validRef(value.InternalMediaRef) || !validDigest(value.SHA256) ||
		value.SizeBytes < 1 || value.SizeBytes > httpapi.MaxMediaBytes || !validImageContentType(value.ContentType) ||
		!validRef(value.Audience) || !validPublicText(value.Title, 1, 256) || value.CreatedAt.IsZero() || !value.ExpiresAt.After(value.CreatedAt) {
		return errors.New("invalid media capability record")
	}
	return nil
}

func validateFeedbackRecord(value FeedbackRecord) error {
	if validateSession(value.Session) != nil || !validRef(value.PublicRunRef) || !validRef(value.IdempotencyKey) ||
		!validDigest(value.FeedbackSHA256) || value.CreatedAt.IsZero() || !value.PurgeAfter.After(value.CreatedAt) ||
		value.PurgeAfter.After(value.CreatedAt.Add(maximumStateRetention)) {
		return errors.New("invalid feedback record")
	}
	var feedback httpapi.FeedbackRequest
	if err := decodeCanonical(value.FeedbackJSON, &feedback); err != nil || feedback.Helpful == nil ||
		!validInputText(feedback.Comment, 0, 1000) || inputguard.ValidateText(feedback.Comment) != nil {
		return errors.New("invalid feedback payload")
	}
	digest := sha256.Sum256(value.FeedbackJSON)
	if value.FeedbackSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("feedback digest mismatch")
	}
	return nil
}

func validateAndMarshalStandardDecision(value StandardDecisionRecord) ([]byte, []byte, []byte, error) {
	if validateSession(value.Session) != nil || !validRef(value.PublicRunRef) || !validDigest(value.PlanSHA256) || value.CreatedAt.IsZero() {
		return nil, nil, nil, errors.New("invalid standard decision metadata")
	}
	if err := value.Template.Validate(); err != nil || value.Template.State != inspection.TemplatePublished {
		return nil, nil, nil, errors.New("invalid standard decision template")
	}
	if err := value.Assignment.Validate(); err != nil || !value.Assignment.Published {
		return nil, nil, nil, errors.New("invalid standard decision assignment")
	}
	if err := value.RunRequest.Validate(); err != nil {
		return nil, nil, nil, errors.New("invalid standard decision run request")
	}
	if value.Template.TenantID != value.Session.TenantID || value.Assignment.TenantID != value.Session.TenantID ||
		value.Assignment.SiteID != value.Session.SiteID || value.RunRequest.TenantID != value.Session.TenantID ||
		value.RunRequest.SiteID != value.Session.SiteID || value.RunRequest.TemplateID != value.Template.TemplateID ||
		value.RunRequest.TemplateRevision != value.Template.Revision || value.RunRequest.AssignmentID != value.Assignment.AssignmentID ||
		value.RunRequest.AssignmentRevision != value.Assignment.Revision {
		return nil, nil, nil, errors.New("standard decision scope or catalog binding mismatch")
	}
	plan, err := inspection.CompilePlan(value.Template, value.Assignment, value.RunRequest)
	if err != nil || plan.PlanSHA256 != value.PlanSHA256 {
		return nil, nil, nil, errors.New("standard decision plan digest mismatch")
	}
	templateJSON, err := json.Marshal(value.Template)
	if err != nil {
		return nil, nil, nil, err
	}
	assignmentJSON, err := json.Marshal(value.Assignment)
	if err != nil {
		return nil, nil, nil, err
	}
	runRequestJSON, err := json.Marshal(value.RunRequest)
	if err != nil {
		return nil, nil, nil, err
	}
	return templateJSON, assignmentJSON, runRequestJSON, nil
}

func validateAndMarshalScheduledDecision(value ScheduledDecisionRecord) ([]byte, []byte, []byte, error) {
	if validateSession(value.Session) != nil || !validRef(value.PublicRunRef) || !validRef(value.InternalRunID) ||
		!validRef(value.OccurrenceID) || !validRef(value.SubmissionRef) || !validRef(value.BindingRef) || value.BindingRevision == 0 ||
		!validDigest(value.AudienceSHA256) || !validDigest(value.DeliverySHA256) || !validDigest(value.ServicePrincipalSHA256) ||
		!validDigest(value.OccurrenceSHA256) || !validDigest(value.RequestSHA256) || !validDigest(value.PlanSHA256) || value.CreatedAt.IsZero() ||
		value.RunRequest.Origin != inspection.OriginSchedule {
		return nil, nil, nil, errors.New("invalid scheduled decision metadata")
	}
	audience := delivery.Audience{
		TenantID: value.Session.TenantID, SiteID: value.Session.SiteID, Channel: value.Session.Channel,
		ConversationRef: value.Session.ConversationRef, RecipientRef: value.Session.RecipientRef,
	}
	audienceSHA, err := audience.SHA256()
	if err != nil || audienceSHA != value.AudienceSHA256 {
		return nil, nil, nil, errors.New("scheduled decision audience digest mismatch")
	}
	standard := StandardDecisionRecord{
		Session: value.Session, PublicRunRef: value.PublicRunRef, PlanSHA256: value.PlanSHA256,
		Template: value.Template, Assignment: value.Assignment, RunRequest: value.RunRequest, CreatedAt: value.CreatedAt,
	}
	templateJSON, assignmentJSON, requestJSON, err := validateAndMarshalStandardDecision(standard)
	if err != nil {
		return nil, nil, nil, err
	}
	digest := sha256.Sum256(requestJSON)
	if hex.EncodeToString(digest[:]) != value.RequestSHA256 {
		return nil, nil, nil, errors.New("scheduled decision request digest mismatch")
	}
	return templateJSON, assignmentJSON, requestJSON, nil
}

func validateAndMarshalTemporaryDecision(value TemporaryDecisionRecord) ([]byte, error) {
	if validateSession(value.Session) != nil || !validRef(value.PublicRunRef) || !validRef(value.RuntimeRequestID) ||
		value.CreatedAt.IsZero() || validateTemporaryDecision(value.Decision, value.CreatedAt) != nil {
		return nil, errors.New("invalid temporary decision")
	}
	if _, err := buildTemporarySubmission(RequestRecord{
		Session: value.Session, PublicRunRef: value.PublicRunRef, RuntimeRequestID: value.RuntimeRequestID,
		CreatedAt: value.CreatedAt,
	}, value.Decision); err != nil {
		return nil, errors.New("temporary decision is not bound to its authenticated request")
	}
	return marshalTemporaryDecisionStorage(value.Decision)
}

func requestRecordDigest(value RequestRecord) string {
	return digestFields(value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, value.IdempotencyKey,
		value.RequestSHA256, string(value.RequestJSON), value.PublicRunRef, value.RuntimeRequestID,
		value.RequestKind, string(value.Resolution), value.InternalRunID, string(value.InteractionJSON),
		formatStateTime(value.CreatedAt), formatStateTime(value.UpdatedAt), formatStateTime(value.PurgeAfter))
}

func audienceRunDigest(value AudienceRunRecord) string {
	return digestFields(value.PublicRunRef, value.Session.TenantID, value.Session.SiteID, value.Session.Channel,
		value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, value.Origin,
		value.RunKind, value.BindingState, value.InternalRunID, formatStateTime(value.CreatedAt),
		formatStateTime(value.UpdatedAt), formatStateTime(value.PurgeAfter))
}

func standardDecisionDigest(value StandardDecisionRecord, templateJSON, assignmentJSON, runRequestJSON []byte) string {
	return digestFields(value.Session.TenantID, value.Session.SiteID, value.Session.Channel,
		value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, value.PlanSHA256,
		string(templateJSON), string(assignmentJSON), string(runRequestJSON), formatStateTime(value.CreatedAt))
}

func scheduledDecisionDigest(value ScheduledDecisionRecord, templateJSON, assignmentJSON, runRequestJSON []byte) string {
	return digestFields(value.PublicRunRef, value.OccurrenceID, value.SubmissionRef, value.Session.TenantID, value.Session.SiteID,
		value.Session.Channel, value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256,
		value.BindingRef, strconv.FormatUint(value.BindingRevision, 10), value.AudienceSHA256, value.DeliverySHA256,
		value.ServicePrincipalSHA256, value.OccurrenceSHA256, value.RequestSHA256, value.PlanSHA256, value.InternalRunID,
		string(templateJSON), string(assignmentJSON), string(runRequestJSON), formatStateTime(value.CreatedAt))
}

func temporaryDecisionDigest(value TemporaryDecisionRecord, decisionJSON []byte) string {
	return digestFields(value.Session.TenantID, value.Session.SiteID, value.Session.Channel,
		value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef, value.RuntimeRequestID,
		string(decisionJSON), value.DecisionSHA256, formatStateTime(value.CreatedAt))
}

func mediaRecordDigest(value MediaCapabilityRecord) string {
	return digestFields(value.PublicMediaRef, value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256,
		value.PublicRunRef, value.InternalRunID, value.MediaBindingRunID, value.InternalMediaRef, value.SHA256,
		strconv.FormatInt(value.SizeBytes, 10), value.ContentType, value.Audience, value.Title,
		formatStateTime(value.CreatedAt), formatStateTime(value.ExpiresAt))
}

func feedbackRecordDigest(value FeedbackRecord) string {
	return digestFields(value.Session.TenantID, value.Session.SiteID, value.Session.Channel, value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, value.PublicRunRef,
		value.IdempotencyKey, value.FeedbackSHA256, string(value.FeedbackJSON), formatStateTime(value.CreatedAt), formatStateTime(value.PurgeAfter))
}

func digestFields(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = fmt.Fprintf(hash, "%d:", len(value))
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func decodeCanonical(raw []byte, output any) error {
	if len(raw) == 0 || !json.Valid(raw) {
		return errors.New("stored JSON is invalid")
	}
	if err := strictjson.ValidateExactFields(raw, output, 16); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, output); err != nil {
		return err
	}
	canonical, err := json.Marshal(output)
	if err != nil || string(canonical) != string(raw) {
		return errors.New("stored JSON is not canonical")
	}
	return nil
}

func formatStateTime(value time.Time) string { return value.UTC().Format(stateTimeLayout) }

func parseStateTime(value string) (time.Time, error) {
	parsed, err := time.Parse(stateTimeLayout, value)
	if err != nil || value != formatStateTime(parsed) {
		return time.Time{}, errors.New("invalid application state timestamp")
	}
	return parsed.UTC(), nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func stateConstraint(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "constraint") || strings.Contains(lower, "unique") || strings.Contains(lower, "invalid channel request transition") ||
		strings.Contains(lower, "invalid audience run transition") {
		return errors.Join(ErrStateConflict, err)
	}
	return err
}

func validateStateShape(database *sql.DB) error {
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != applicationStateVersion {
		return ErrUnsupportedStateSchema
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != applicationStateID {
		return ErrUnsupportedStateSchema
	}
	var integrity string
	if err := database.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrCorruptState
	}
	expected := map[string]string{
		"audience_runs": createAudienceRunsSQL, "uq_audience_runs_internal_run": createAudienceRunInternalIndexSQL,
		"idx_audience_runs_lookup": createAudienceRunLookupIndexSQL, "audience_runs_transition_guard": createAudienceRunUpdateGuardSQL,
		"channel_requests": createRequestsSQL, "idx_channel_requests_ref": createRequestRefIndexSQL,
		"uq_channel_requests_internal_run": createRequestRunIndexSQL,
		"standard_decisions":               createDecisionsSQL, "standard_decisions_no_update": createDecisionsUpdateGuardSQL,
		"scheduled_decisions": createScheduledDecisionsSQL, "scheduled_decisions_no_update": createScheduledDecisionsUpdateGuardSQL,
		"temporary_decisions": createTemporaryDecisionsSQL, "temporary_decisions_no_update": createTemporaryDecisionsUpdateGuardSQL,
		"media_capabilities": createMediaSQL, "idx_media_capabilities_lookup": createMediaLookupIndexSQL,
		"channel_feedback": createFeedbackSQL, "channel_requests_transition_guard": createRequestUpdateGuardSQL,
		"media_capabilities_no_update": createMediaUpdateGuardSQL, "channel_feedback_no_update": createFeedbackUpdateGuardSQL,
	}
	rows, err := database.Query(`SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	actual := map[string]string{}
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			return err
		}
		actual[name] = statement
	}
	if err := rows.Err(); err != nil || len(actual) != len(expected) {
		return ErrUnsupportedStateSchema
	}
	for name, statement := range expected {
		if normalizeStateSQL(actual[name]) != normalizeStateSQL(statement) {
			return fmt.Errorf("%w: unexpected object %s", ErrUnsupportedStateSchema, name)
		}
	}
	foreignKeys, err := database.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer foreignKeys.Close()
	if foreignKeys.Next() {
		return ErrCorruptState
	}
	return foreignKeys.Err()
}

func normalizeStateSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}

func (s *StateStore) validateStoredContent(ctx context.Context) error {
	audienceRows, err := s.db.QueryContext(ctx, `SELECT `+audienceRunColumns+` FROM audience_runs ORDER BY public_run_ref`)
	if err != nil {
		return err
	}
	for audienceRows.Next() {
		if _, err := scanAudienceRun(audienceRows); err != nil {
			audienceRows.Close()
			return err
		}
	}
	if err := audienceRows.Close(); err != nil {
		return err
	}
	requestRows, err := s.db.QueryContext(ctx, `SELECT `+requestColumns+` FROM channel_requests ORDER BY tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, idempotency_key`)
	if err != nil {
		return err
	}
	for requestRows.Next() {
		if _, err := scanRequest(requestRows); err != nil {
			requestRows.Close()
			return err
		}
	}
	if err := requestRows.Close(); err != nil {
		return err
	}
	decisionRows, err := s.db.QueryContext(ctx, `SELECT `+decisionColumns+` FROM standard_decisions ORDER BY public_run_ref`)
	if err != nil {
		return err
	}
	for decisionRows.Next() {
		if _, err := scanStandardDecision(decisionRows); err != nil {
			decisionRows.Close()
			return err
		}
	}
	if err := decisionRows.Close(); err != nil {
		return err
	}
	scheduledRows, err := s.db.QueryContext(ctx, `SELECT `+scheduledDecisionColumns+` FROM scheduled_decisions ORDER BY public_run_ref`)
	if err != nil {
		return err
	}
	for scheduledRows.Next() {
		if _, err := scanScheduledDecision(scheduledRows); err != nil {
			scheduledRows.Close()
			return err
		}
	}
	if err := scheduledRows.Close(); err != nil {
		return err
	}
	temporaryRows, err := s.db.QueryContext(ctx, `SELECT `+temporaryDecisionColumns+` FROM temporary_decisions ORDER BY public_run_ref`)
	if err != nil {
		return err
	}
	for temporaryRows.Next() {
		if _, err := scanTemporaryDecision(temporaryRows); err != nil {
			temporaryRows.Close()
			return err
		}
	}
	if err := temporaryRows.Close(); err != nil {
		return err
	}
	mediaRows, err := s.db.QueryContext(ctx, `SELECT `+mediaColumns+` FROM media_capabilities ORDER BY public_media_ref`)
	if err != nil {
		return err
	}
	for mediaRows.Next() {
		if _, err := scanMedia(mediaRows); err != nil {
			mediaRows.Close()
			return err
		}
	}
	if err := mediaRows.Close(); err != nil {
		return err
	}
	feedbackRows, err := s.db.QueryContext(ctx, `SELECT `+feedbackColumns+` FROM channel_feedback ORDER BY tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256, public_run_ref, idempotency_key`)
	if err != nil {
		return err
	}
	for feedbackRows.Next() {
		var value FeedbackRecord
		var createdAt, purgeAfter string
		if err := feedbackRows.Scan(&value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel,
			&value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256, &value.PublicRunRef, &value.IdempotencyKey,
			&value.FeedbackSHA256, &value.FeedbackJSON, &createdAt, &purgeAfter, &value.RecordSHA256); err != nil {
			feedbackRows.Close()
			return err
		}
		value.CreatedAt, err = parseStateTime(createdAt)
		if err == nil {
			value.PurgeAfter, err = parseStateTime(purgeAfter)
		}
		if err != nil || validateFeedbackRecord(value) != nil || value.RecordSHA256 != feedbackRecordDigest(value) {
			feedbackRows.Close()
			return ErrCorruptState
		}
	}
	if err := feedbackRows.Close(); err != nil {
		return err
	}
	checkBindings := func(label, query string) error {
		var brokenBindings int
		if err := s.db.QueryRowContext(ctx, query).Scan(&brokenBindings); err != nil {
			return fmt.Errorf("%w: %s query failed: %v", ErrCorruptState, label, err)
		}
		if brokenBindings != 0 {
			return fmt.Errorf("%w: %s (%d records)", ErrCorruptState, label, brokenBindings)
		}
		return nil
	}
	if err := checkBindings("media-to-run binding mismatch", `SELECT COUNT(*) FROM media_capabilities m
JOIN audience_runs r ON r.tenant_id=m.tenant_id AND r.site_id=m.site_id AND r.channel=m.channel AND r.public_run_ref=m.public_run_ref
	AND r.conversation_ref=m.conversation_ref AND r.recipient_ref=m.recipient_ref AND r.principal_sha256=m.principal_sha256
WHERE r.binding_state<>'bound' OR r.internal_run_id<>m.internal_run_id`); err != nil {
		return err
	}
	if err := checkBindings("media capability run mismatch", `SELECT COUNT(*) FROM media_capabilities m
JOIN audience_runs r ON r.tenant_id=m.tenant_id AND r.site_id=m.site_id AND r.channel=m.channel AND r.public_run_ref=m.public_run_ref
	AND r.conversation_ref=m.conversation_ref AND r.recipient_ref=m.recipient_ref AND r.principal_sha256=m.principal_sha256
WHERE m.media_binding_run_id<>r.internal_run_id OR r.run_kind NOT IN ('standard','temporary')`); err != nil {
		return err
	}
	if err := checkBindings("feedback-to-run binding mismatch", `SELECT COUNT(*) FROM channel_feedback f
JOIN audience_runs r ON r.tenant_id=f.tenant_id AND r.site_id=f.site_id AND r.channel=f.channel AND r.public_run_ref=f.public_run_ref
	AND r.conversation_ref=f.conversation_ref AND r.recipient_ref=f.recipient_ref AND r.principal_sha256=f.principal_sha256
WHERE r.binding_state<>'bound'`); err != nil {
		return err
	}
	if err := checkBindings("channel request audience mismatch", `SELECT COUNT(*) FROM channel_requests c
JOIN audience_runs r ON r.public_run_ref=c.public_run_ref
WHERE r.origin<>'channel' OR r.tenant_id<>c.tenant_id OR r.site_id<>c.site_id OR r.channel<>c.channel OR
r.conversation_ref<>c.conversation_ref OR r.recipient_ref<>c.recipient_ref OR r.principal_sha256<>c.principal_sha256 OR
(c.resolution IN ('standard_bound','temporary_bound') AND (r.binding_state<>'bound' OR r.internal_run_id<>c.internal_run_id OR r.run_kind<>c.request_kind)) OR
(c.resolution NOT IN ('standard_bound','temporary_bound') AND r.binding_state<>'reserved')`); err != nil {
		return err
	}
	if err := checkBindings("orphan channel audience", `SELECT COUNT(*) FROM audience_runs r WHERE r.origin='channel'
AND NOT EXISTS(SELECT 1 FROM channel_requests c WHERE c.public_run_ref=r.public_run_ref)`); err != nil {
		return err
	}
	if err := checkBindings("standard decision request mismatch", `SELECT COUNT(*) FROM standard_decisions d
JOIN channel_requests r ON r.tenant_id=d.tenant_id AND r.site_id=d.site_id AND r.channel=d.channel AND r.public_run_ref=d.public_run_ref
	AND r.conversation_ref=d.conversation_ref AND r.recipient_ref=d.recipient_ref AND r.principal_sha256=d.principal_sha256
WHERE r.resolution NOT IN ('standard_pending', 'standard_bound') OR r.request_kind<>'standard'`); err != nil {
		return err
	}
	if err := checkBindings("channel request missing standard decision", `SELECT COUNT(*) FROM channel_requests r
WHERE r.resolution IN ('standard_pending', 'standard_bound')
	AND NOT EXISTS(SELECT 1 FROM standard_decisions d WHERE d.tenant_id=r.tenant_id AND d.site_id=r.site_id AND d.channel=r.channel
		AND d.conversation_ref=r.conversation_ref AND d.recipient_ref=r.recipient_ref AND d.principal_sha256=r.principal_sha256 AND d.public_run_ref=r.public_run_ref)`); err != nil {
		return err
	}
	if err := checkBindings("scheduled decision audience mismatch", `SELECT COUNT(*) FROM scheduled_decisions d
JOIN audience_runs r ON r.public_run_ref=d.public_run_ref
WHERE r.origin<>'schedule' OR r.binding_state<>'bound' OR r.run_kind<>'standard' OR r.internal_run_id<>d.internal_run_id OR
r.tenant_id<>d.tenant_id OR r.site_id<>d.site_id OR r.channel<>d.channel OR r.conversation_ref<>d.conversation_ref OR
r.recipient_ref<>d.recipient_ref OR r.principal_sha256<>d.principal_sha256`); err != nil {
		return err
	}
	if err := checkBindings("orphan scheduled audience", `SELECT COUNT(*) FROM audience_runs r WHERE r.origin='schedule'
AND NOT EXISTS(SELECT 1 FROM scheduled_decisions d WHERE d.public_run_ref=r.public_run_ref)`); err != nil {
		return err
	}
	if err := checkBindings("temporary decision request mismatch", `SELECT COUNT(*) FROM temporary_decisions d
JOIN channel_requests r ON r.tenant_id=d.tenant_id AND r.site_id=d.site_id AND r.channel=d.channel AND r.public_run_ref=d.public_run_ref
	AND r.conversation_ref=d.conversation_ref AND r.recipient_ref=d.recipient_ref AND r.principal_sha256=d.principal_sha256
WHERE r.resolution NOT IN ('temporary_pending','temporary_bound') OR r.request_kind<>'temporary' OR r.runtime_request_id<>d.runtime_request_id`); err != nil {
		return err
	}
	if err := checkBindings("channel request missing temporary decision", `SELECT COUNT(*) FROM channel_requests r
WHERE r.resolution IN ('temporary_pending','temporary_bound')
	AND NOT EXISTS(SELECT 1 FROM temporary_decisions d WHERE d.tenant_id=r.tenant_id AND d.site_id=r.site_id AND d.channel=r.channel
		AND d.conversation_ref=r.conversation_ref AND d.recipient_ref=r.recipient_ref AND d.principal_sha256=r.principal_sha256 AND d.public_run_ref=r.public_run_ref)`); err != nil {
		return err
	}
	return nil
}

// objectNamesForTest returns a stable list without exposing the database.
func objectNamesForTest(database *sql.DB) ([]string, error) {
	rows, err := database.Query(`SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, rows.Err()
}
