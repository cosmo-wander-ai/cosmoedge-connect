package schedule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	_ "modernc.org/sqlite"
)

const (
	scheduleStoreVersion = 4
	scheduleStoreID      = 0x43455334 // CES4
	storeTimeLayout      = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	ErrNotFound     = errors.New("inspection schedule record not found")
	ErrConflict     = errors.New("inspection schedule state conflict")
	ErrSchema       = errors.New("unsupported inspection schedule state schema")
	ErrCorruptState = errors.New("inspection schedule state integrity failure")
)

type OccurrenceState string

const (
	OccurrencePending           OccurrenceState = "pending"
	OccurrenceClaimed           OccurrenceState = "claimed"
	OccurrenceSubmittingUnknown OccurrenceState = "submitting_unknown"
	OccurrenceSubmitted         OccurrenceState = "submitted"
	OccurrenceBlocked           OccurrenceState = "blocked"
	OccurrenceExpired           OccurrenceState = "expired"
	OccurrenceSkipped           OccurrenceState = "skipped"
	OccurrenceTerminal          OccurrenceState = "terminal"
)

type Key struct {
	TenantID   string
	SiteID     string
	ScheduleID string
	Revision   uint64
}

type StoreConfig struct {
	Path  string
	Now   func() time.Time
	Zones ZoneLoader
}

type Store struct {
	db    *sql.DB
	path  string
	now   func() time.Time
	zones ZoneLoader
}

type ScheduleRecord struct {
	Schedule      Schedule
	CursorAt      time.Time
	ReservedCount int
	PayloadSHA256 string
}

type OccurrenceRecord struct {
	Occurrence          Occurrence
	State               OccurrenceState
	RunRef              string
	SubmissionRef       string
	ReasonCode          string
	ClaimOwner          string
	LeaseExpiresAt      time.Time
	AvailableAt         time.Time
	Generation          uint64
	SubmitAttempts      int
	ReconcileAttempts   int
	ObserveAttempts     int
	SubmissionStartedAt time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	PayloadSHA256       string
}

type OccurrenceClaim struct {
	OccurrenceID string
	Owner        string
	Generation   uint64
}

type ReservationState string

const (
	ReservationHeld     ReservationState = "held"
	ReservationReleased ReservationState = "released"
)

type Reservation struct {
	OccurrenceID     string
	TenantID         string
	SiteID           string
	ScheduleID       string
	ScheduleRevision uint64
	State            ReservationState
	RunRef           string
	CreatedAt        time.Time
	ReleasedAt       time.Time
}

const createSchedulesSQL = `CREATE TABLE schedule_revisions (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    schedule_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    state TEXT NOT NULL CHECK(state IN ('draft','awaiting_authorization','active','paused','revoked','expired')),
    schedule_json BLOB NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    cursor_at TEXT NOT NULL,
    max_in_flight INTEGER NOT NULL CHECK(max_in_flight BETWEEN 1 AND 100),
    reserved_count INTEGER NOT NULL DEFAULT 0 CHECK(reserved_count BETWEEN 0 AND max_in_flight),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, site_id, schedule_id, revision)
)`

const createActiveScheduleIndexSQL = `CREATE UNIQUE INDEX uq_schedule_active_revision
    ON schedule_revisions(tenant_id, site_id, schedule_id) WHERE state = 'active'`

const createOccurrencesSQL = `CREATE TABLE occurrences (
    occurrence_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    operation_ref TEXT NOT NULL UNIQUE,
    request_key TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    schedule_id TEXT NOT NULL,
    schedule_revision INTEGER NOT NULL CHECK(schedule_revision > 0),
    due_at TEXT NOT NULL,
    deadline_at TEXT NOT NULL,
    available_at TEXT NOT NULL,
    occurrence_json BLOB NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    state TEXT NOT NULL CHECK(state IN ('pending','claimed','submitting_unknown','submitted','blocked','expired','skipped','terminal')),
    run_ref TEXT NOT NULL DEFAULT '',
    submission_ref TEXT NOT NULL DEFAULT '',
    reason_code TEXT NOT NULL DEFAULT '',
    claim_owner TEXT NOT NULL DEFAULT '',
    lease_expires_at TEXT NOT NULL DEFAULT '',
    generation INTEGER NOT NULL DEFAULT 0 CHECK(generation >= 0),
    submit_attempts INTEGER NOT NULL DEFAULT 0 CHECK(submit_attempts >= 0),
    reconcile_attempts INTEGER NOT NULL DEFAULT 0 CHECK(reconcile_attempts >= 0),
    observe_attempts INTEGER NOT NULL DEFAULT 0 CHECK(observe_attempts >= 0),
    submission_started_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(tenant_id, site_id, schedule_id, schedule_revision)
        REFERENCES schedule_revisions(tenant_id, site_id, schedule_id, revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK((claim_owner = '' AND lease_expires_at = '') OR (claim_owner <> '' AND lease_expires_at <> '')),
    CHECK((state = 'pending' AND claim_owner = '' AND submission_started_at = '' AND run_ref = '') OR
          (state = 'claimed' AND claim_owner <> '' AND submission_started_at = '' AND run_ref = '') OR
          (state = 'submitting_unknown' AND submission_started_at <> '' AND run_ref = '') OR
          (state = 'submitted' AND submission_started_at <> '' AND run_ref <> '') OR
          (state IN ('blocked','expired','skipped') AND claim_owner = '' AND run_ref = '') OR
          (state = 'terminal' AND claim_owner = '' AND run_ref <> ''))
)`

const createPendingIndexSQL = `CREATE INDEX idx_occurrence_pending
    ON occurrences(state, available_at, due_at, occurrence_id)`
const createReconcileIndexSQL = `CREATE INDEX idx_occurrence_reconcile
    ON occurrences(state, available_at, updated_at, occurrence_id)`
const createObserveIndexSQL = `CREATE INDEX idx_occurrence_observe
    ON occurrences(state, available_at, updated_at, occurrence_id)`

const createReservationsSQL = `CREATE TABLE schedule_reservations (
    occurrence_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    schedule_id TEXT NOT NULL,
    schedule_revision INTEGER NOT NULL CHECK(schedule_revision > 0),
    state TEXT NOT NULL CHECK(state IN ('held','released')),
    run_ref TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    released_at TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(occurrence_id) REFERENCES occurrences(occurrence_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY(tenant_id, site_id, schedule_id, schedule_revision)
        REFERENCES schedule_revisions(tenant_id, site_id, schedule_id, revision)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK((state = 'held' AND released_at = '') OR (state = 'released' AND released_at <> ''))
)`

const createHeldReservationsIndexSQL = `CREATE INDEX idx_reservation_scope
    ON schedule_reservations(tenant_id, site_id, schedule_id, schedule_revision, state, occurrence_id)`

var scheduleStoreSchema = []string{
	createSchedulesSQL, createActiveScheduleIndexSQL, createOccurrencesSQL, createPendingIndexSQL,
	createReconcileIndexSQL, createObserveIndexSQL, createReservationsSQL, createHeldReservationsIndexSQL,
}

// scheduleFileDSN accepts an absolute path with native separators converted by
// filepath.ToSlash. A Windows drive must be in the URL path, not its authority.
// net/url escapes filename characters independently from the SQLite options.
func scheduleFileDSN(slashPath string) string {
	if !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	dsnURL := &url.URL{Scheme: "file", Path: slashPath}
	query := dsnURL.Query()
	query.Set("_txlock", "immediate")
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(1)", "trusted_schema(0)", "synchronous(FULL)", "secure_delete(1)"} {
		query.Add("_pragma", pragma)
	}
	dsnURL.RawQuery = query.Encode()
	return dsnURL.String()
}

func OpenStore(config StoreConfig) (*Store, error) {
	if strings.TrimSpace(config.Path) == "" || strings.ContainsAny(config.Path, "?#\x00") {
		return nil, ErrSchema
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Zones == nil {
		config.Zones = SystemZoneLoader{}
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
			return nil, fmt.Errorf("reject existing inspection schedule state: %w", err)
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
	database, err := sql.Open("sqlite", scheduleFileDSN(filepath.ToSlash(absolute)))
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(8)
	database.SetMaxIdleConns(8)
	fail := func(openErr error) (*Store, error) { _ = database.Close(); return nil, openErr }
	if _, err := database.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fail(err)
	}
	var version, applicationID, userObjects int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fail(err)
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return fail(err)
	}
	if version == 0 {
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&userObjects); err != nil {
			return fail(err)
		}
		if applicationID != 0 || userObjects != 0 {
			return fail(ErrSchema)
		}
		tx, err := database.Begin()
		if err != nil {
			return fail(err)
		}
		for _, statement := range scheduleStoreSchema {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fail(err)
			}
		}
		for _, statement := range []string{fmt.Sprintf("PRAGMA application_id=%d", scheduleStoreID), fmt.Sprintf("PRAGMA user_version=%d", scheduleStoreVersion)} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fail(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != scheduleStoreVersion || applicationID != scheduleStoreID {
		return fail(ErrSchema)
	}
	if err := validateStoreShape(database); err != nil {
		return fail(err)
	}
	store := &Store{db: database, path: absolute, now: config.Now, zones: config.Zones}
	if err := store.validateStoredContent(context.Background()); err != nil {
		return fail(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return fail(err)
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Create(ctx context.Context, value Schedule) (ScheduleRecord, bool, error) {
	if s == nil || value.State != StateDraft || value.ValidateWithZones(s.zones) != nil {
		return ScheduleRecord{}, false, ErrConflict
	}
	raw, err := marshalScheduleStorage(value)
	if err != nil {
		return ScheduleRecord{}, false, err
	}
	record := ScheduleRecord{Schedule: cloneSchedule(value), CursorAt: value.ValidFrom.UTC().Add(-time.Nanosecond), PayloadSHA256: bytesDigest(raw)}
	result, err := s.db.ExecContext(ctx, `INSERT INTO schedule_revisions(
tenant_id, site_id, schedule_id, revision, state, schedule_json, payload_sha256, cursor_at, max_in_flight, reserved_count, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?) ON CONFLICT(tenant_id, site_id, schedule_id, revision) DO NOTHING`,
		value.TenantID, value.SiteID, value.ScheduleID, value.Revision, value.State, raw, record.PayloadSHA256,
		formatStoreTime(record.CursorAt), value.Concurrency.MaxInFlight, formatStoreTime(value.CreatedAt), formatStoreTime(value.UpdatedAt))
	if err != nil {
		return ScheduleRecord{}, false, storeConstraint(err)
	}
	rows, _ := result.RowsAffected()
	stored, err := s.Get(ctx, keyFor(value))
	if err != nil {
		return ScheduleRecord{}, false, err
	}
	if stored.PayloadSHA256 != record.PayloadSHA256 {
		return ScheduleRecord{}, false, ErrConflict
	}
	return stored, rows == 1, nil
}

func (s *Store) Get(ctx context.Context, key Key) (ScheduleRecord, error) {
	if s == nil || validateKey(key) != nil {
		return ScheduleRecord{}, ErrNotFound
	}
	return scanSchedule(s.zones, s.db.QueryRowContext(ctx, `SELECT `+scheduleColumns+` FROM schedule_revisions
WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=?`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision))
}

func (s *Store) List(ctx context.Context, tenantID, siteID string) ([]ScheduleRecord, error) {
	if s == nil || validateRef("tenant", tenantID) != nil || validateRef("site", siteID) != nil {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+scheduleColumns+` FROM schedule_revisions WHERE tenant_id=? AND site_id=? ORDER BY schedule_id, revision`, tenantID, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ScheduleRecord
	for rows.Next() {
		record, err := scanSchedule(s.zones, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *Store) DeleteDraft(ctx context.Context, key Key) (bool, error) {
	if s == nil || validateKey(key) != nil {
		return false, ErrNotFound
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM schedule_revisions WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=? AND state='draft' AND reserved_count=0`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision)
	if err != nil {
		return false, storeConstraint(err)
	}
	rows, _ := result.RowsAffected()
	return rows == 1, nil
}

func (s *Store) AwaitAuthorization(ctx context.Context, key Key, at time.Time) (ScheduleRecord, error) {
	return s.transition(ctx, key, at, func(value Schedule) (Schedule, error) { return AwaitAuthorization(value, at) }, false)
}
func (s *Store) Activate(ctx context.Context, key Key, grant authority.Grant, verifier GrantVerifier, at time.Time) (ScheduleRecord, error) {
	return s.transition(ctx, key, at, func(value Schedule) (Schedule, error) { return ActivateWithZones(value, grant, verifier, at, s.zones) }, true)
}
func (s *Store) Pause(ctx context.Context, key Key, at time.Time) (ScheduleRecord, error) {
	return s.transition(ctx, key, at, func(value Schedule) (Schedule, error) { return Pause(value, at) }, true)
}
func (s *Store) Revoke(ctx context.Context, key Key, at time.Time) (ScheduleRecord, error) {
	return s.transition(ctx, key, at, func(value Schedule) (Schedule, error) { return Revoke(value, at) }, true)
}
func (s *Store) Expire(ctx context.Context, key Key, at time.Time) (ScheduleRecord, error) {
	return s.transition(ctx, key, at, func(value Schedule) (Schedule, error) { return Expire(value, at) }, true)
}

func (s *Store) transition(ctx context.Context, key Key, at time.Time, apply func(Schedule) (Schedule, error), advanceCursor bool) (ScheduleRecord, error) {
	if s == nil || validateKey(key) != nil || at.IsZero() || apply == nil {
		return ScheduleRecord{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ScheduleRecord{}, err
	}
	defer tx.Rollback()
	record, err := scanSchedule(s.zones, tx.QueryRowContext(ctx, `SELECT `+scheduleColumns+` FROM schedule_revisions WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=?`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision))
	if err != nil {
		return ScheduleRecord{}, err
	}
	initialCursor := record.Schedule.ValidFrom.UTC().Add(-time.Nanosecond)
	cursorAdvanced := record.CursorAt.After(initialCursor)
	if advanceCursor && cursorAdvanced && at.UTC().Before(record.CursorAt) {
		return ScheduleRecord{}, ErrConflict
	}
	updated, err := apply(cloneSchedule(record.Schedule))
	if err != nil {
		return ScheduleRecord{}, err
	}
	if updated.ValidateWithZones(s.zones) != nil || updated.Concurrency.MaxInFlight != record.Schedule.Concurrency.MaxInFlight {
		return ScheduleRecord{}, ErrConflict
	}
	raw, err := marshalScheduleStorage(updated)
	if err != nil {
		return ScheduleRecord{}, err
	}
	oldSHA := record.PayloadSHA256
	record.Schedule = updated
	record.PayloadSHA256 = bytesDigest(raw)
	if advanceCursor && at.UTC().After(record.CursorAt) {
		record.CursorAt = at.UTC()
	}
	result, err := tx.ExecContext(ctx, `UPDATE schedule_revisions SET state=?, schedule_json=?, payload_sha256=?, cursor_at=?, updated_at=?
WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=? AND payload_sha256=?`, updated.State, raw, record.PayloadSHA256,
		formatStoreTime(record.CursorAt), formatStoreTime(updated.UpdatedAt), key.TenantID, key.SiteID, key.ScheduleID, key.Revision, oldSHA)
	if err != nil {
		return ScheduleRecord{}, storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ScheduleRecord{}, ErrConflict
	}
	if updated.State == StatePaused || updated.State == StateRevoked || updated.State == StateExpired {
		terminalState := OccurrenceBlocked
		if updated.State == StatePaused {
			terminalState = OccurrenceSkipped
		}
		if updated.State == StateExpired {
			terminalState = OccurrenceExpired
		}
		if err := terminalizePendingOccurrences(ctx, tx, key, terminalState, "schedule_"+string(updated.State), at.UTC()); err != nil {
			return ScheduleRecord{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ScheduleRecord{}, err
	}
	return record, nil
}

func keyFor(value Schedule) Key {
	return Key{TenantID: value.TenantID, SiteID: value.SiteID, ScheduleID: value.ScheduleID, Revision: value.Revision}
}
func validateKey(key Key) error {
	if validateRef("tenant", key.TenantID) != nil || validateRef("site", key.SiteID) != nil || validateRef("schedule", key.ScheduleID) != nil || key.Revision == 0 {
		return errors.New("invalid inspection schedule key")
	}
	return nil
}

const scheduleColumns = `tenant_id, site_id, schedule_id, revision, state, schedule_json, payload_sha256, cursor_at, max_in_flight, reserved_count, created_at, updated_at`
const occurrenceColumns = `occurrence_id, idempotency_key, operation_ref, request_key, tenant_id, site_id, schedule_id, schedule_revision, due_at, deadline_at, available_at, occurrence_json, payload_sha256, state,
run_ref, submission_ref, reason_code, claim_owner, lease_expires_at, generation, submit_attempts, reconcile_attempts, observe_attempts, submission_started_at, created_at, updated_at`

type rowScanner interface{ Scan(...any) error }

func scanSchedule(zones ZoneLoader, row rowScanner) (ScheduleRecord, error) {
	var value ScheduleRecord
	var raw []byte
	var tenantID, siteID, scheduleID, stateValue, cursorAt, createdAt, updatedAt string
	var revision uint64
	var max int
	err := row.Scan(&tenantID, &siteID, &scheduleID, &revision, &stateValue, &raw, &value.PayloadSHA256, &cursorAt, &max, &value.ReservedCount, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ScheduleRecord{}, ErrNotFound
	}
	if err != nil {
		return ScheduleRecord{}, err
	}
	value.Schedule, err = unmarshalScheduleStorage(raw)
	if err != nil || value.Schedule.ValidateWithZones(zones) != nil || value.Schedule.TenantID != tenantID || value.Schedule.SiteID != siteID ||
		value.Schedule.ScheduleID != scheduleID || value.Schedule.Revision != revision || string(value.Schedule.State) != stateValue ||
		value.Schedule.Concurrency.MaxInFlight != max || bytesDigest(raw) != value.PayloadSHA256 || value.ReservedCount < 0 || value.ReservedCount > max {
		return ScheduleRecord{}, ErrCorruptState
	}
	if value.CursorAt, err = parseStoreTime(cursorAt); err != nil {
		return ScheduleRecord{}, ErrCorruptState
	}
	if value.CursorAt.Before(value.Schedule.ValidFrom.UTC().Add(-time.Nanosecond)) {
		return ScheduleRecord{}, ErrCorruptState
	}
	parsedCreated, err := parseStoreTime(createdAt)
	if err != nil || !parsedCreated.Equal(value.Schedule.CreatedAt) {
		return ScheduleRecord{}, ErrCorruptState
	}
	parsedUpdated, err := parseStoreTime(updatedAt)
	if err != nil || !parsedUpdated.Equal(value.Schedule.UpdatedAt) {
		return ScheduleRecord{}, ErrCorruptState
	}
	return value, nil
}

func scanOccurrence(zones ZoneLoader, row rowScanner) (OccurrenceRecord, error) {
	var value OccurrenceRecord
	var raw []byte
	var occurrenceID, idempotencyKey, operationRef, requestKey, tenantID, siteID, scheduleID, dueAt, deadlineAt, availableAt, stateValue string
	var lease, started, created, updated string
	var revision uint64
	err := row.Scan(&occurrenceID, &idempotencyKey, &operationRef, &requestKey, &tenantID, &siteID, &scheduleID, &revision, &dueAt, &deadlineAt, &availableAt,
		&raw, &value.PayloadSHA256, &stateValue, &value.RunRef, &value.SubmissionRef, &value.ReasonCode, &value.ClaimOwner, &lease, &value.Generation,
		&value.SubmitAttempts, &value.ReconcileAttempts, &value.ObserveAttempts, &started, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return OccurrenceRecord{}, ErrNotFound
	}
	if err != nil {
		return OccurrenceRecord{}, err
	}
	value.Occurrence, err = unmarshalOccurrenceStorage(raw)
	if err != nil || value.Occurrence.ValidateWithZones(zones) != nil || value.Occurrence.OccurrenceID != occurrenceID || value.Occurrence.IdempotencyKey != idempotencyKey ||
		value.Occurrence.OperationRef != operationRef || value.Occurrence.RequestKey != requestKey || value.Occurrence.TenantID != tenantID || value.Occurrence.SiteID != siteID ||
		value.Occurrence.ScheduleID != scheduleID || value.Occurrence.ScheduleRevision != revision || formatStoreTime(value.Occurrence.DueAt) != dueAt ||
		formatStoreTime(value.Occurrence.Deadline) != deadlineAt || bytesDigest(raw) != value.PayloadSHA256 {
		return OccurrenceRecord{}, ErrCorruptState
	}
	value.State = OccurrenceState(stateValue)
	if value.AvailableAt, err = parseStoreTime(availableAt); err != nil {
		return OccurrenceRecord{}, ErrCorruptState
	}
	if lease != "" {
		value.LeaseExpiresAt, err = parseStoreTime(lease)
	}
	if err == nil && started != "" {
		value.SubmissionStartedAt, err = parseStoreTime(started)
	}
	if err == nil {
		value.CreatedAt, err = parseStoreTime(created)
	}
	if err == nil {
		value.UpdatedAt, err = parseStoreTime(updated)
	}
	if err != nil || validateOccurrenceRecord(value) != nil {
		return OccurrenceRecord{}, ErrCorruptState
	}
	return value, nil
}

func validateOccurrenceRecord(value OccurrenceRecord) error {
	if value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) || value.AvailableAt.IsZero() ||
		value.SubmitAttempts < 0 || value.ReconcileAttempts < 0 || value.ObserveAttempts < 0 || !validSHA256(value.PayloadSHA256) ||
		(value.RunRef != "" && validateRef("run", value.RunRef) != nil) || (value.SubmissionRef != "" && validateRef("submission", value.SubmissionRef) != nil) ||
		(value.ReasonCode != "" && validateRef("reason", value.ReasonCode) != nil) || (value.ClaimOwner != "" && validateRef("claim owner", value.ClaimOwner) != nil) {
		return errors.New("invalid inspection occurrence record")
	}
	claimed := value.ClaimOwner != "" && !value.LeaseExpiresAt.IsZero()
	if (value.ClaimOwner == "") != value.LeaseExpiresAt.IsZero() {
		return errors.New("invalid inspection occurrence claim")
	}
	switch value.State {
	case OccurrencePending:
		if claimed || !value.SubmissionStartedAt.IsZero() || value.RunRef != "" {
			return errors.New("invalid pending occurrence")
		}
	case OccurrenceClaimed:
		if !claimed || !value.SubmissionStartedAt.IsZero() || value.RunRef != "" {
			return errors.New("invalid claimed occurrence")
		}
	case OccurrenceSubmittingUnknown:
		if value.SubmissionStartedAt.IsZero() || value.RunRef != "" {
			return errors.New("invalid unknown occurrence")
		}
	case OccurrenceSubmitted:
		if value.SubmissionStartedAt.IsZero() || value.RunRef == "" {
			return errors.New("invalid submitted occurrence")
		}
	case OccurrenceBlocked, OccurrenceExpired, OccurrenceSkipped:
		if claimed || value.RunRef != "" {
			return errors.New("invalid terminal occurrence")
		}
	case OccurrenceTerminal:
		if claimed || value.RunRef == "" {
			return errors.New("invalid observed terminal occurrence")
		}
	default:
		return errors.New("invalid occurrence state")
	}
	return nil
}

type scheduleStorageAlias Schedule
type scheduleStorage struct {
	scheduleStorageAlias
	RunSpec frozenRunSpecStorage `json:"runSpec"`
}
type occurrenceStorageAlias Occurrence
type occurrenceStorage struct {
	occurrenceStorageAlias
	RunSpec frozenRunSpecStorage `json:"runSpec"`
}

func marshalScheduleStorage(value Schedule) ([]byte, error) {
	return json.Marshal(scheduleStorage{scheduleStorageAlias: scheduleStorageAlias(value), RunSpec: frozenRunSpecStorage(value.RunSpec)})
}
func unmarshalScheduleStorage(raw []byte) (Schedule, error) {
	var wire scheduleStorage
	if err := decodeCanonical(raw, &wire); err != nil {
		return Schedule{}, err
	}
	value := Schedule(wire.scheduleStorageAlias)
	value.RunSpec = FrozenRunSpec(wire.RunSpec)
	return value, nil
}
func marshalOccurrenceStorage(value Occurrence) ([]byte, error) {
	return json.Marshal(occurrenceStorage{occurrenceStorageAlias: occurrenceStorageAlias(value), RunSpec: frozenRunSpecStorage(value.RunSpec)})
}
func unmarshalOccurrenceStorage(raw []byte) (Occurrence, error) {
	var wire occurrenceStorage
	if err := decodeCanonical(raw, &wire); err != nil {
		return Occurrence{}, err
	}
	value := Occurrence(wire.occurrenceStorageAlias)
	value.RunSpec = FrozenRunSpec(wire.RunSpec)
	return value, nil
}

func decodeCanonical(raw []byte, output any) error {
	if !json.Valid(raw) || len(raw) == 0 || len(raw) > 8<<20 {
		return errors.New("stored schedule JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("stored schedule JSON contains trailing values")
	}
	canonical, err := json.Marshal(output)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("stored schedule JSON is not canonical")
	}
	return nil
}

func bytesDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func formatStoreTime(value time.Time) string { return value.UTC().Format(storeTimeLayout) }
func optionalStoreTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatStoreTime(value)
}
func parseStoreTime(value string) (time.Time, error) {
	parsed, err := time.Parse(storeTimeLayout, value)
	if err != nil || value != formatStoreTime(parsed) {
		return time.Time{}, errors.New("invalid inspection schedule timestamp")
	}
	return parsed.UTC(), nil
}

func storeConstraint(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "constraint") || strings.Contains(lower, "unique") || strings.Contains(lower, "locked") || strings.Contains(lower, "busy") {
		return errors.Join(ErrConflict, err)
	}
	return err
}

func validateStoreShape(database *sql.DB) error {
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != scheduleStoreVersion {
		return ErrSchema
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != scheduleStoreID {
		return ErrSchema
	}
	var integrity string
	if err := database.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrCorruptState
	}
	expected := map[string]string{"schedule_revisions": createSchedulesSQL, "uq_schedule_active_revision": createActiveScheduleIndexSQL, "occurrences": createOccurrencesSQL, "idx_occurrence_pending": createPendingIndexSQL, "idx_occurrence_reconcile": createReconcileIndexSQL, "idx_occurrence_observe": createObserveIndexSQL, "schedule_reservations": createReservationsSQL, "idx_reservation_scope": createHeldReservationsIndexSQL}
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
		return ErrSchema
	}
	for name, statement := range expected {
		if normalizeSQL(actual[name]) != normalizeSQL(statement) {
			return fmt.Errorf("%w: unexpected object %s", ErrSchema, name)
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

func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}

func (s *Store) validateStoredContent(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+scheduleColumns+` FROM schedule_revisions ORDER BY tenant_id, site_id, schedule_id, revision`)
	if err != nil {
		return err
	}
	schedules := map[string]ScheduleRecord{}
	for rows.Next() {
		record, err := scanSchedule(s.zones, rows)
		if err != nil {
			rows.Close()
			return err
		}
		schedules[scheduleMapKey(keyFor(record.Schedule))] = record
	}
	if err := rows.Close(); err != nil {
		return err
	}
	occurrences := map[string]OccurrenceRecord{}
	occurrenceRows, err := tx.QueryContext(ctx, `SELECT `+occurrenceColumns+` FROM occurrences ORDER BY occurrence_id`)
	if err != nil {
		return err
	}
	for occurrenceRows.Next() {
		record, err := scanOccurrence(s.zones, occurrenceRows)
		if err != nil {
			occurrenceRows.Close()
			return err
		}
		key := Key{record.Occurrence.TenantID, record.Occurrence.SiteID, record.Occurrence.ScheduleID, record.Occurrence.ScheduleRevision}
		bound, ok := schedules[scheduleMapKey(key)]
		if !ok || !occurrenceMatchesSchedule(record.Occurrence, bound.Schedule) {
			occurrenceRows.Close()
			return ErrCorruptState
		}
		occurrences[record.Occurrence.OccurrenceID] = record
	}
	if err := occurrenceRows.Close(); err != nil {
		return err
	}
	held := map[string]int{}
	heldByOccurrence := map[string]int{}
	reservationRows, err := tx.QueryContext(ctx, `SELECT occurrence_id, tenant_id, site_id, schedule_id, schedule_revision, state, run_ref, created_at, released_at FROM schedule_reservations ORDER BY occurrence_id`)
	if err != nil {
		return err
	}
	for reservationRows.Next() {
		reservation, err := scanReservation(reservationRows)
		if err != nil {
			reservationRows.Close()
			return err
		}
		occurrence, ok := occurrences[reservation.OccurrenceID]
		key := Key{reservation.TenantID, reservation.SiteID, reservation.ScheduleID, reservation.ScheduleRevision}
		if !ok || !occurrenceMatchesReservation(occurrence, reservation) {
			reservationRows.Close()
			return ErrCorruptState
		}
		if reservation.State == ReservationHeld {
			held[scheduleMapKey(key)]++
			heldByOccurrence[reservation.OccurrenceID]++
		}
	}
	if err := reservationRows.Close(); err != nil {
		return err
	}
	for key, record := range schedules {
		if record.ReservedCount != held[key] {
			return ErrCorruptState
		}
	}
	for occurrenceID, record := range occurrences {
		needsHeldReservation := record.State == OccurrenceSubmittingUnknown || record.State == OccurrenceSubmitted
		if needsHeldReservation != (heldByOccurrence[occurrenceID] == 1) {
			return ErrCorruptState
		}
	}
	return tx.Commit()
}

func scanReservation(row rowScanner) (Reservation, error) {
	var value Reservation
	var state, created, released string
	if err := row.Scan(&value.OccurrenceID, &value.TenantID, &value.SiteID, &value.ScheduleID, &value.ScheduleRevision, &state, &value.RunRef, &created, &released); err != nil {
		return Reservation{}, err
	}
	value.State = ReservationState(state)
	var err error
	value.CreatedAt, err = parseStoreTime(created)
	if err == nil && released != "" {
		value.ReleasedAt, err = parseStoreTime(released)
	}
	if err != nil || validateRef("occurrence", value.OccurrenceID) != nil || validateKey(Key{value.TenantID, value.SiteID, value.ScheduleID, value.ScheduleRevision}) != nil || (value.RunRef != "" && validateRef("run", value.RunRef) != nil) ||
		(value.State == ReservationHeld && !value.ReleasedAt.IsZero()) || (value.State == ReservationReleased && value.ReleasedAt.IsZero()) {
		return Reservation{}, ErrCorruptState
	}
	return value, nil
}

func occurrenceMatchesReservation(record OccurrenceRecord, reservation Reservation) bool {
	o := record.Occurrence
	if o.OccurrenceID != reservation.OccurrenceID || o.TenantID != reservation.TenantID || o.SiteID != reservation.SiteID || o.ScheduleID != reservation.ScheduleID || o.ScheduleRevision != reservation.ScheduleRevision {
		return false
	}
	if reservation.State == ReservationHeld {
		return (record.State == OccurrenceSubmittingUnknown && reservation.RunRef == "") || (record.State == OccurrenceSubmitted && reservation.RunRef == record.RunRef)
	}
	return record.State == OccurrenceBlocked || record.State == OccurrenceExpired || record.State == OccurrenceSkipped || record.State == OccurrenceTerminal
}

func terminalizePendingOccurrences(ctx context.Context, tx *sql.Tx, key Key, state OccurrenceState, reason string, at time.Time) error {
	if state != OccurrenceBlocked && state != OccurrenceExpired && state != OccurrenceSkipped {
		return ErrConflict
	}
	_, err := tx.ExecContext(ctx, `UPDATE occurrences SET state=?, reason_code=?, claim_owner='', lease_expires_at='', available_at=?, generation=generation+1, updated_at=?
WHERE tenant_id=? AND site_id=? AND schedule_id=? AND schedule_revision=? AND state IN ('pending','claimed')`, state, reason, formatStoreTime(at), formatStoreTime(at), key.TenantID, key.SiteID, key.ScheduleID, key.Revision)
	return storeConstraint(err)
}

func scheduleMapKey(key Key) string {
	return key.TenantID + "\x00" + key.SiteID + "\x00" + key.ScheduleID + "\x00" + strconv.FormatUint(key.Revision, 10)
}
func sortedObjectNames(database *sql.DB) ([]string, error) {
	rows, err := database.Query(`SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	sort.Strings(values)
	return values, rows.Err()
}
