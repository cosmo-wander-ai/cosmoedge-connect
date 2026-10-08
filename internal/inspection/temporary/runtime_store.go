package temporary

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

const (
	temporaryDatabaseVersion       = 4
	temporaryDatabaseApplicationID = 0x43455434 // CET4
	runtimeTimestampLayout         = "2006-01-02T15:04:05.000000000Z"
	outboxPending                  = "pending"
	outboxClaimed                  = "claimed"
	outboxDelivered                = "delivered"
	preparationRecoveryBackoff     = 2 * time.Second
)

const temporaryDatabaseSchema = `
CREATE TABLE temporary_runs (
    run_id TEXT PRIMARY KEY,
    identity_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    state TEXT NOT NULL,
    phase TEXT NOT NULL,
    available_at TEXT NOT NULL,
    deadline_at TEXT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json BLOB NOT NULL,
    record_sha256 TEXT NOT NULL,
    UNIQUE(tenant_id, site_id, request_key)
);
CREATE INDEX temporary_runs_claim_idx ON temporary_runs(state, available_at, deadline_at, run_id);
CREATE TABLE temporary_terminal_outbox (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    event_json BLOB NOT NULL,
    event_sha256 TEXT NOT NULL,
    delivery_state TEXT NOT NULL,
    available_at TEXT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES temporary_runs(run_id) ON DELETE RESTRICT
);
CREATE INDEX temporary_terminal_outbox_claim_idx ON temporary_terminal_outbox(delivery_state, available_at, event_id);`

var temporaryRunColumns = []string{
	"run_id", "identity_sha256", "tenant_id", "site_id", "request_key", "generation", "state", "phase",
	"available_at", "deadline_at", "lease_owner", "lease_expires_at", "updated_at", "record_json", "record_sha256",
}

var temporaryOutboxColumns = []string{
	"event_id", "run_id", "event_json", "event_sha256", "delivery_state", "available_at",
	"lease_owner", "lease_expires_at", "updated_at",
}

type SQLiteStore struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00?#") {
		return nil, ErrRuntimeInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing temporary observation runtime store: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		if closeErr := file.Close(); closeErr != nil {
			_ = os.Remove(absolute)
			return nil, closeErr
		}
		created = true
		if err := localstate.ProtectFile(absolute); err != nil {
			_ = os.Remove(absolute)
			return nil, err
		}
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	fail := func(openErr error) (*SQLiteStore, error) {
		_ = database.Close()
		if created {
			_ = os.Remove(absolute)
		}
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
		if !created || applicationID != 0 {
			return fail(ErrRuntimeSchema)
		}
		tx, err := database.Begin()
		if err != nil {
			return fail(err)
		}
		if _, err := tx.Exec(temporaryDatabaseSchema); err != nil {
			_ = tx.Rollback()
			return fail(err)
		}
		for _, statement := range []string{
			fmt.Sprintf("PRAGMA application_id=%d", temporaryDatabaseApplicationID),
			fmt.Sprintf("PRAGMA user_version=%d", temporaryDatabaseVersion),
		} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fail(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != temporaryDatabaseVersion || applicationID != temporaryDatabaseApplicationID {
		return fail(ErrRuntimeSchema)
	}
	store := &SQLiteStore{db: database}
	if err := store.validateShape(); err != nil {
		return fail(err)
	}
	if err := store.validateContent(context.Background()); err != nil {
		return fail(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return fail(err)
	}
	return store, nil
}

func (s *SQLiteStore) validateShape() error {
	rows, err := s.db.Query(`SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var name, kind string
		if err := rows.Scan(&name, &kind); err != nil {
			return err
		}
		key := kind + ":" + name
		switch key {
		case "table:temporary_runs", "table:temporary_terminal_outbox",
			"index:temporary_runs_claim_idx", "index:temporary_terminal_outbox_claim_idx":
			seen[key] = true
		default:
			return errors.Join(ErrRuntimeSchema, fmt.Errorf("unexpected temporary runtime database %s %q", kind, name))
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, key := range []string{
		"table:temporary_runs", "table:temporary_terminal_outbox",
		"index:temporary_runs_claim_idx", "index:temporary_terminal_outbox_claim_idx",
	} {
		if !seen[key] {
			return ErrRuntimeSchema
		}
	}
	for table, expected := range map[string][]string{
		"temporary_runs":            temporaryRunColumns,
		"temporary_terminal_outbox": temporaryOutboxColumns,
	} {
		columns, err := runtimeTableColumns(s.db, table)
		if err != nil {
			return err
		}
		if len(columns) != len(expected) {
			return ErrRuntimeSchema
		}
		for index := range columns {
			if columns[index] != expected[index] {
				return ErrRuntimeSchema
			}
		}
	}
	return nil
}

func runtimeTableColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := []string{}
	for rows.Next() {
		var ordinal, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&ordinal, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func (s *SQLiteStore) validateContent(ctx context.Context) error {
	runRows, err := s.db.QueryContext(ctx, `SELECT `+strings.Join(temporaryRunColumns, ",")+` FROM temporary_runs ORDER BY run_id`)
	if err != nil {
		return err
	}
	runs := map[string]Record{}
	for runRows.Next() {
		record, scanErr := scanRecord(runRows)
		if scanErr != nil {
			_ = runRows.Close()
			return scanErr
		}
		runs[record.RunID] = record
	}
	if err := runRows.Close(); err != nil {
		return err
	}
	outboxRows, err := s.db.QueryContext(ctx, `SELECT event_id,run_id,event_json,event_sha256,delivery_state,available_at,lease_owner,lease_expires_at,updated_at FROM temporary_terminal_outbox ORDER BY event_id`)
	if err != nil {
		return err
	}
	events := map[string]TerminalEvent{}
	for outboxRows.Next() {
		var eventID, runID, raw, digest, deliveryState, available, owner, leaseExpiry, updated string
		if err := outboxRows.Scan(&eventID, &runID, &raw, &digest, &deliveryState, &available, &owner, &leaseExpiry, &updated); err != nil {
			_ = outboxRows.Close()
			return err
		}
		event, err := unmarshalTerminalEvent(raw, digest)
		if err != nil || event.EventID != eventID || event.RunID != runID {
			_ = outboxRows.Close()
			return ErrRuntimeCorrupt
		}
		availableAt, err := parseRuntimeTime(available, false)
		if err != nil {
			_ = outboxRows.Close()
			return err
		}
		leaseExpiresAt, err := parseRuntimeTime(leaseExpiry, true)
		if err != nil {
			_ = outboxRows.Close()
			return err
		}
		updatedAt, err := parseRuntimeTime(updated, false)
		if err != nil || availableAt.Before(event.OccurredAt) || updatedAt.Before(event.OccurredAt) {
			_ = outboxRows.Close()
			return ErrRuntimeCorrupt
		}
		switch deliveryState {
		case outboxPending, outboxDelivered:
			if owner != "" || !leaseExpiresAt.IsZero() {
				_ = outboxRows.Close()
				return ErrRuntimeCorrupt
			}
		case outboxClaimed:
			if !validRuntimeRef(owner) || !leaseExpiresAt.After(updatedAt) {
				_ = outboxRows.Close()
				return ErrRuntimeCorrupt
			}
		default:
			_ = outboxRows.Close()
			return ErrRuntimeCorrupt
		}
		events[runID] = event
	}
	if err := outboxRows.Close(); err != nil {
		return err
	}
	for runID, record := range runs {
		event, exists := events[runID]
		if exists != record.State.Terminal() {
			return ErrRuntimeCorrupt
		}
		if exists {
			expected, err := terminalEventFor(record)
			if err != nil || expected != event {
				return ErrRuntimeCorrupt
			}
			delete(events, runID)
		}
	}
	if len(events) != 0 {
		return ErrRuntimeCorrupt
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) Submit(ctx context.Context, submission Submission, now time.Time) (Record, bool, error) {
	if s == nil || now.IsZero() || !isRuntimeUTC(now) || now.Before(submission.SubmittedAt) {
		return Record{}, false, ErrRuntimeInvalid
	}
	runID, identity, err := submissionIdentity(submission)
	if err != nil {
		return Record{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, false, err
	}
	defer tx.Rollback()
	existing, err := getRecordByScopeTx(ctx, tx, submission.Binding.TenantID, submission.Binding.SiteID, submission.Binding.RequestKey)
	if err == nil {
		if existing.RunID != runID || existing.IdentitySHA256 != identity {
			return Record{}, false, ErrRuntimeConflict
		}
		if err := tx.Commit(); err != nil {
			return Record{}, false, err
		}
		return cloneRecord(existing), false, nil
	}
	if !errors.Is(err, ErrRuntimeNotFound) {
		return Record{}, false, err
	}
	record := Record{
		Schema: RuntimeSchemaVersion, RunID: runID, IdentitySHA256: identity,
		Binding: submission.Binding, Spec: submission.Spec, PreparationRef: submission.PreparationRef, MediaKind: submission.MediaKind,
		AudienceBindingRef: submission.AudienceBindingRef, AudienceSHA256: submission.AudienceSHA256,
		EvidenceExpiresAt: submission.EvidenceExpiresAt, Generation: 1,
		State: StateQueued, Phase: PhaseNone, Reason: ReasonSubmitted,
		AvailableAt: now, SubmittedAt: submission.SubmittedAt, DeadlineAt: submission.DeadlineAt, UpdatedAt: now,
	}
	if !now.Before(record.DeadlineAt) {
		finishRecord(&record, StateExpired, ReasonDeadlineExpired, now)
	}
	if err := insertRecordTx(ctx, tx, record); err != nil {
		if isConstraint(err) {
			return Record{}, false, ErrRuntimeConflict
		}
		return Record{}, false, err
	}
	if record.State.Terminal() {
		if err := insertTerminalTx(ctx, tx, record); err != nil {
			return Record{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Record{}, false, err
	}
	return cloneRecord(record), true, nil
}

func (s *SQLiteStore) Get(ctx context.Context, runID string) (Record, error) {
	if s == nil || !validRuntimeRef(runID) {
		return Record{}, ErrRuntimeNotFound
	}
	return scanRecord(s.db.QueryRowContext(ctx, `SELECT `+strings.Join(temporaryRunColumns, ",")+` FROM temporary_runs WHERE run_id=?`, runID))
}

func (s *SQLiteStore) Claim(ctx context.Context, owner string, now time.Time, leaseTTL time.Duration) (Record, Lease, bool, error) {
	if s == nil || !validRuntimeRef(owner) || now.IsZero() || !isRuntimeUTC(now) || leaseTTL <= 0 || leaseTTL > MaxLeaseTTL {
		return Record{}, Lease{}, false, ErrRuntimeInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, Lease{}, false, err
	}
	defer tx.Rollback()
	var runID string
	err = tx.QueryRowContext(ctx, `SELECT run_id FROM temporary_runs WHERE state=? AND available_at<=? AND deadline_at>? AND record_json<>'' ORDER BY available_at,run_id LIMIT 1`,
		StateQueued, formatRuntimeTime(now), formatRuntimeTime(now)).Scan(&runID)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, Lease{}, false, nil
	}
	if err != nil {
		return Record{}, Lease{}, false, err
	}
	record, err := getRecordTx(ctx, tx, runID)
	if err != nil {
		return Record{}, Lease{}, false, err
	}
	leaseExpires := now.Add(leaseTTL)
	if record.DeadlineAt.Before(leaseExpires) {
		leaseExpires = record.DeadlineAt
	}
	record.State, record.Phase, record.Reason = StateRunning, PhasePreparing, ReasonClaimed
	record.Generation++
	record.LeaseOwner, record.LeaseExpiresAt, record.UpdatedAt = owner, leaseExpires, now
	if err := updateRecordTx(ctx, tx, record); err != nil {
		return Record{}, Lease{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, Lease{}, false, err
	}
	lease := Lease{RunID: runID, Generation: record.Generation, Owner: owner, StartedAt: now, LeaseExpiresAt: leaseExpires}
	return cloneRecord(record), lease, true, nil
}

func (s *SQLiteStore) BeginAnalysis(ctx context.Context, lease Lease, descriptor MediaDescriptor, promptSHA256 string, at time.Time) (Record, error) {
	if !runtimeDigestPattern.MatchString(promptSHA256) {
		return Record{}, ErrRuntimeInvalid
	}
	return s.mutateLease(ctx, lease, at, PhasePreparing, func(record *Record) error {
		if record.Attempt != 0 {
			return ErrRuntimeInvalid
		}
		record.MediaRef = descriptor.MediaRef
		if descriptor.validate(*record, at) != nil || !descriptor.ExpiresAt.After(at) {
			record.MediaRef = ""
			return ErrRuntimeInvalid
		}
		record.Phase, record.Reason = PhaseAnalyzing, ReasonPreparationReady
		record.Attempt++
		record.PromptSHA256 = promptSHA256
		value := descriptor
		record.Media = &value
		return nil
	})
}

// ReleasePreparationPending persists the polling backoff without consuming an
// analysis attempt. It is the only replay path before BeginAnalysis.
func (s *SQLiteStore) ReleasePreparationPending(ctx context.Context, lease Lease, availableAt, at time.Time) (Record, error) {
	if availableAt.IsZero() || !isRuntimeUTC(availableAt) || availableAt.Before(at) {
		return Record{}, ErrRuntimeInvalid
	}
	record, err := s.mutateLease(ctx, lease, at, PhasePreparing, func(record *Record) error {
		if record.PreparationPolls >= MaxPrepPolls {
			return ErrRuntimeInvalid
		}
		record.State, record.Phase, record.Reason = StateQueued, PhaseNone, ReasonPreparationPending
		record.PreparationPolls++
		record.AvailableAt = availableAt
		record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *SQLiteStore) CompletePreparationTerminal(ctx context.Context, lease Lease, state State, reason Reason, at time.Time) (Record, error) {
	if state == StateFailed && reason != ReasonPreparationFailed || state == StateExpired && reason != ReasonPreparationExpired ||
		state != StateFailed && state != StateExpired {
		return Record{}, ErrRuntimeInvalid
	}
	return s.finishLease(ctx, lease, at, PhasePreparing, state, reason, nil)
}

func (s *SQLiteStore) CompleteSuccess(ctx context.Context, lease Lease, candidate Candidate, observation Observation, at time.Time) (Record, error) {
	return s.finishLease(ctx, lease, at, PhaseAnalyzing, StateSucceeded, ReasonCompleted, func(record *Record) error {
		if candidate.Validate() != nil || observation.Validate() != nil || observation.IntentSHA256 != record.Spec.NormalizedIntentSHA256 ||
			len(observation.EvidenceRefs) != 1 || observation.EvidenceRefs[0] != record.MediaRef {
			return ErrRuntimeInvalid
		}
		digest, err := resultDigest(candidate, observation)
		if err != nil {
			return err
		}
		candidateCopy := candidate
		observationCopy := observation
		record.Candidate, record.Observation, record.ResultSHA256 = &candidateCopy, &observationCopy, digest
		return nil
	})
}

func (s *SQLiteStore) CompleteInvalidCandidate(ctx context.Context, lease Lease, at time.Time) (Record, error) {
	return s.finishLease(ctx, lease, at, PhaseAnalyzing, StateInvalidCandidate, ReasonCandidateInvalid, nil)
}

func (s *SQLiteStore) CompleteOutcomeUnknown(ctx context.Context, lease Lease, at time.Time) (Record, error) {
	return s.finishLease(ctx, lease, at, PhaseAnalyzing, StateOutcomeUnknown, ReasonAnalysisOutcomeUnknown, nil)
}

func (s *SQLiteStore) CompleteDefiniteFailure(ctx context.Context, lease Lease, reason Reason, at time.Time) (Record, error) {
	if reason != ReasonAnalysisDefinitelyFailed && reason != ReasonMediaUnavailable && reason != ReasonMediaInvalid {
		return Record{}, ErrRuntimeInvalid
	}
	expected := PhasePreparing
	if reason == ReasonAnalysisDefinitelyFailed {
		expected = PhaseAnalyzing
	}
	return s.finishLease(ctx, lease, at, expected, StateFailed, reason, nil)
}

func (s *SQLiteStore) Recover(ctx context.Context, now time.Time) (int, error) {
	if s == nil || now.IsZero() || !isRuntimeUTC(now) {
		return 0, ErrRuntimeInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+strings.Join(temporaryRunColumns, ",")+` FROM temporary_runs WHERE (state=? AND deadline_at<=?) OR (state=? AND (deadline_at<=? OR lease_expires_at<=?)) ORDER BY run_id`,
		StateQueued, formatRuntimeTime(now), StateRunning, formatRuntimeTime(now), formatRuntimeTime(now))
	if err != nil {
		return 0, err
	}
	records := []Record{}
	for rows.Next() {
		record, scanErr := scanRecord(rows)
		if scanErr != nil {
			_ = rows.Close()
			return 0, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for i := range records {
		record := &records[i]
		terminal := false
		switch {
		case record.State == StateQueued:
			finishRecord(record, StateExpired, ReasonDeadlineExpired, now)
			terminal = true
		case record.Phase == PhaseAnalyzing:
			finishRecord(record, StateOutcomeUnknown, ReasonAnalysisOutcomeUnknown, now)
			terminal = true
		case !now.Before(record.DeadlineAt):
			finishRecord(record, StateExpired, ReasonDeadlineExpired, now)
			terminal = true
		default:
			record.State, record.Phase, record.Reason = StateQueued, PhaseNone, ReasonRecoveredBeforeAnalysis
			record.AvailableAt, record.UpdatedAt = now.Add(preparationRecoveryBackoff), now
			record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
		}
		if err := updateRecordTx(ctx, tx, *record); err != nil {
			return 0, err
		}
		if terminal {
			if err := insertTerminalTx(ctx, tx, *record); err != nil {
				return 0, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(records), nil
}

func (s *SQLiteStore) TerminalEvent(ctx context.Context, runID string) (TerminalEvent, error) {
	if s == nil || !validRuntimeRef(runID) {
		return TerminalEvent{}, ErrRuntimeNotFound
	}
	return scanTerminalEvent(s.db.QueryRowContext(ctx, `SELECT event_id,run_id,event_json,event_sha256 FROM temporary_terminal_outbox WHERE run_id=?`, runID))
}

// ClaimTerminalEvent leases a terminal notification. Redelivery after a lease
// interruption is intentional: consumers must enqueue by EventID, which is
// stable for the run.
func (s *SQLiteStore) ClaimTerminalEvent(ctx context.Context, owner string, now time.Time, leaseTTL time.Duration) (TerminalLease, bool, error) {
	if s == nil || !validRuntimeRef(owner) || now.IsZero() || !isRuntimeUTC(now) || leaseTTL <= 0 || leaseTTL > MaxLeaseTTL {
		return TerminalLease{}, false, ErrRuntimeInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TerminalLease{}, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE temporary_terminal_outbox SET delivery_state=?,lease_owner='',lease_expires_at='',available_at=?,updated_at=? WHERE delivery_state=? AND lease_expires_at<=?`,
		outboxPending, formatRuntimeTime(now), formatRuntimeTime(now), outboxClaimed, formatRuntimeTime(now)); err != nil {
		return TerminalLease{}, false, err
	}
	var eventID string
	err = tx.QueryRowContext(ctx, `SELECT event_id FROM temporary_terminal_outbox WHERE delivery_state=? AND available_at<=? ORDER BY available_at,event_id LIMIT 1`,
		outboxPending, formatRuntimeTime(now)).Scan(&eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return TerminalLease{}, false, nil
	}
	if err != nil {
		return TerminalLease{}, false, err
	}
	event, err := scanTerminalEvent(tx.QueryRowContext(ctx, `SELECT event_id,run_id,event_json,event_sha256 FROM temporary_terminal_outbox WHERE event_id=?`, eventID))
	if err != nil {
		return TerminalLease{}, false, err
	}
	expires := now.Add(leaseTTL)
	result, err := tx.ExecContext(ctx, `UPDATE temporary_terminal_outbox SET delivery_state=?,lease_owner=?,lease_expires_at=?,updated_at=? WHERE event_id=? AND delivery_state=?`,
		outboxClaimed, owner, formatRuntimeTime(expires), formatRuntimeTime(now), eventID, outboxPending)
	if err != nil {
		return TerminalLease{}, false, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return TerminalLease{}, false, ErrRuntimeConflict
	}
	if err := tx.Commit(); err != nil {
		return TerminalLease{}, false, err
	}
	return TerminalLease{Event: event, Owner: owner, StartedAt: now, LeaseExpiresAt: expires}, true, nil
}

func (s *SQLiteStore) AcknowledgeTerminalEvent(ctx context.Context, lease TerminalLease, at time.Time) error {
	if s == nil || validateTerminalEvent(lease.Event) != nil || !validRuntimeRef(lease.Owner) ||
		lease.StartedAt.IsZero() || lease.LeaseExpiresAt.IsZero() || !isRuntimeUTC(lease.StartedAt) ||
		!isRuntimeUTC(lease.LeaseExpiresAt) || !lease.LeaseExpiresAt.After(lease.StartedAt) ||
		at.IsZero() || !isRuntimeUTC(at) || at.Before(lease.StartedAt) || at.After(lease.LeaseExpiresAt) {
		return ErrRuntimeInvalid
	}
	result, err := s.db.ExecContext(ctx, `UPDATE temporary_terminal_outbox SET delivery_state=?,lease_owner='',lease_expires_at='',updated_at=? WHERE event_id=? AND run_id=? AND delivery_state=? AND lease_owner=? AND lease_expires_at=?`,
		outboxDelivered, formatRuntimeTime(at), lease.Event.EventID, lease.Event.RunID, outboxClaimed, lease.Owner, formatRuntimeTime(lease.LeaseExpiresAt))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrRuntimeLeaseLost
	}
	return nil
}

func (s *SQLiteStore) mutateLease(ctx context.Context, lease Lease, at time.Time, expected Phase, mutate func(*Record) error) (Record, error) {
	if s == nil || !validLease(lease) || at.IsZero() || !isRuntimeUTC(at) || at.Before(lease.StartedAt) || at.After(lease.LeaseExpiresAt) {
		return Record{}, ErrRuntimeInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	record, err := getRecordTx(ctx, tx, lease.RunID)
	if err != nil {
		return Record{}, err
	}
	if !leaseMatches(record, lease, expected) || !at.Before(record.DeadlineAt) {
		return Record{}, ErrRuntimeLeaseLost
	}
	previousDigest, err := recordDigest(record)
	if err != nil {
		return Record{}, err
	}
	if err := mutate(&record); err != nil {
		return Record{}, err
	}
	record.UpdatedAt = at
	if err := updateRecordCASTx(ctx, tx, record, previousDigest); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func (s *SQLiteStore) finishLease(ctx context.Context, lease Lease, at time.Time, expected Phase, state State, reason Reason, decorate func(*Record) error) (Record, error) {
	if s == nil || !validLease(lease) || !state.Terminal() || at.IsZero() || !isRuntimeUTC(at) ||
		at.Before(lease.StartedAt) || at.After(lease.LeaseExpiresAt) {
		return Record{}, ErrRuntimeInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	record, err := getRecordTx(ctx, tx, lease.RunID)
	if err != nil {
		return Record{}, err
	}
	if !leaseMatches(record, lease, expected) || !at.Before(record.DeadlineAt) {
		return Record{}, ErrRuntimeLeaseLost
	}
	previousDigest, err := recordDigest(record)
	if err != nil {
		return Record{}, err
	}
	if decorate != nil {
		if err := decorate(&record); err != nil {
			return Record{}, err
		}
	}
	finishRecord(&record, state, reason, at)
	if err := updateRecordCASTx(ctx, tx, record, previousDigest); err != nil {
		return Record{}, err
	}
	if err := insertTerminalTx(ctx, tx, record); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return cloneRecord(record), nil
}

func finishRecord(record *Record, state State, reason Reason, at time.Time) {
	record.State, record.Phase, record.Reason = state, PhaseNone, reason
	record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
	record.UpdatedAt, record.CompletedAt = at, at
	record.ResultRef = resultRef(record.RunID)
}

func validLease(lease Lease) bool {
	return validRuntimeRef(lease.RunID) && validRuntimeRef(lease.Owner) && lease.Generation > 1 &&
		!lease.StartedAt.IsZero() && !lease.LeaseExpiresAt.IsZero() && isRuntimeUTC(lease.StartedAt) &&
		isRuntimeUTC(lease.LeaseExpiresAt) && lease.LeaseExpiresAt.After(lease.StartedAt) &&
		lease.LeaseExpiresAt.Sub(lease.StartedAt) <= MaxLeaseTTL
}

func leaseMatches(record Record, lease Lease, phase Phase) bool {
	return record.State == StateRunning && record.Phase == phase && record.RunID == lease.RunID &&
		record.Generation == lease.Generation && record.LeaseOwner == lease.Owner && record.LeaseExpiresAt.Equal(lease.LeaseExpiresAt)
}

func insertRecordTx(ctx context.Context, tx *sql.Tx, record Record) error {
	raw, digest, err := marshalRecord(record)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO temporary_runs(run_id,identity_sha256,tenant_id,site_id,request_key,generation,state,phase,available_at,deadline_at,lease_owner,lease_expires_at,updated_at,record_json,record_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		record.RunID, record.IdentitySHA256, record.Binding.TenantID, record.Binding.SiteID, record.Binding.RequestKey,
		record.Generation, record.State, record.Phase, formatRuntimeTime(record.AvailableAt), formatRuntimeTime(record.DeadlineAt),
		record.LeaseOwner, formatRuntimeTime(record.LeaseExpiresAt), formatRuntimeTime(record.UpdatedAt), raw, digest)
	return err
}

func updateRecordTx(ctx context.Context, tx *sql.Tx, record Record) error {
	current, err := getRecordTx(ctx, tx, record.RunID)
	if err != nil {
		return err
	}
	digest, err := recordDigest(current)
	if err != nil {
		return err
	}
	return updateRecordCASTx(ctx, tx, record, digest)
}

func updateRecordCASTx(ctx context.Context, tx *sql.Tx, record Record, previousDigest string) error {
	raw, digest, err := marshalRecord(record)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE temporary_runs SET generation=?,state=?,phase=?,available_at=?,deadline_at=?,lease_owner=?,lease_expires_at=?,updated_at=?,record_json=?,record_sha256=? WHERE run_id=? AND record_sha256=?`,
		record.Generation, record.State, record.Phase, formatRuntimeTime(record.AvailableAt), formatRuntimeTime(record.DeadlineAt),
		record.LeaseOwner, formatRuntimeTime(record.LeaseExpiresAt), formatRuntimeTime(record.UpdatedAt), raw, digest,
		record.RunID, previousDigest)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrRuntimeConflict
	}
	return nil
}

func getRecordTx(ctx context.Context, tx *sql.Tx, runID string) (Record, error) {
	return scanRecord(tx.QueryRowContext(ctx, `SELECT `+strings.Join(temporaryRunColumns, ",")+` FROM temporary_runs WHERE run_id=?`, runID))
}

func getRecordByScopeTx(ctx context.Context, tx *sql.Tx, tenantID, siteID, requestKey string) (Record, error) {
	return scanRecord(tx.QueryRowContext(ctx, `SELECT `+strings.Join(temporaryRunColumns, ",")+` FROM temporary_runs WHERE tenant_id=? AND site_id=? AND request_key=?`, tenantID, siteID, requestKey))
}

type rowScanner interface {
	Scan(...any) error
}

func scanRecord(row rowScanner) (Record, error) {
	var runID, identity, tenantID, siteID, requestKey, state, phase, available, deadline, leaseOwner, leaseExpiry, updated, raw, digest string
	var generation uint64
	if err := row.Scan(&runID, &identity, &tenantID, &siteID, &requestKey, &generation, &state, &phase, &available, &deadline, &leaseOwner, &leaseExpiry, &updated, &raw, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrRuntimeNotFound
		}
		return Record{}, err
	}
	record, err := unmarshalRecord(raw, digest)
	if err != nil || record.RunID != runID || record.IdentitySHA256 != identity || record.Binding.TenantID != tenantID ||
		record.Binding.SiteID != siteID || record.Binding.RequestKey != requestKey || record.Generation != generation || string(record.State) != state || string(record.Phase) != phase ||
		formatRuntimeTime(record.AvailableAt) != available || formatRuntimeTime(record.DeadlineAt) != deadline ||
		record.LeaseOwner != leaseOwner || formatRuntimeTime(record.LeaseExpiresAt) != leaseExpiry || formatRuntimeTime(record.UpdatedAt) != updated {
		return Record{}, ErrRuntimeCorrupt
	}
	return record, nil
}

func marshalRecord(record Record) (string, string, error) {
	if err := validateRecord(record); err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(raw)
	return string(raw), hex.EncodeToString(sum[:]), nil
}

func unmarshalRecord(raw, digest string) (Record, error) {
	if !runtimeDigestPattern.MatchString(digest) || len(raw) == 0 || len(raw) > 128<<10 {
		return Record{}, ErrRuntimeCorrupt
	}
	var record Record
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return Record{}, ErrRuntimeCorrupt
	}
	canonical, computed, err := marshalRecord(record)
	if err != nil || canonical != raw || computed != digest {
		return Record{}, ErrRuntimeCorrupt
	}
	return record, nil
}

func recordDigest(record Record) (string, error) {
	_, digest, err := marshalRecord(record)
	return digest, err
}

func insertTerminalTx(ctx context.Context, tx *sql.Tx, record Record) error {
	event, err := terminalEventFor(record)
	if err != nil {
		return err
	}
	raw, digest, err := marshalTerminalEvent(event)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO temporary_terminal_outbox(event_id,run_id,event_json,event_sha256,delivery_state,available_at,lease_owner,lease_expires_at,updated_at) VALUES(?,?,?,?,? ,?,'','',?)`,
		event.EventID, event.RunID, raw, digest, outboxPending, formatRuntimeTime(event.OccurredAt), formatRuntimeTime(event.OccurredAt))
	if isConstraint(err) {
		existing, getErr := scanTerminalEvent(tx.QueryRowContext(ctx, `SELECT event_id,run_id,event_json,event_sha256 FROM temporary_terminal_outbox WHERE run_id=?`, record.RunID))
		if getErr != nil || existing != event {
			return ErrRuntimeConflict
		}
		return nil
	}
	return err
}

func scanTerminalEvent(row rowScanner) (TerminalEvent, error) {
	var eventID, runID, raw, digest string
	if err := row.Scan(&eventID, &runID, &raw, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TerminalEvent{}, ErrRuntimeNotFound
		}
		return TerminalEvent{}, err
	}
	event, err := unmarshalTerminalEvent(raw, digest)
	if err != nil || event.EventID != eventID || event.RunID != runID {
		return TerminalEvent{}, ErrRuntimeCorrupt
	}
	return event, nil
}

func marshalTerminalEvent(event TerminalEvent) (string, string, error) {
	if err := validateTerminalEvent(event); err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(raw)
	return string(raw), hex.EncodeToString(sum[:]), nil
}

func unmarshalTerminalEvent(raw, digest string) (TerminalEvent, error) {
	if !runtimeDigestPattern.MatchString(digest) || len(raw) == 0 || len(raw) > 8<<10 {
		return TerminalEvent{}, ErrRuntimeCorrupt
	}
	var event TerminalEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return TerminalEvent{}, ErrRuntimeCorrupt
	}
	canonical, computed, err := marshalTerminalEvent(event)
	if err != nil || canonical != raw || computed != digest {
		return TerminalEvent{}, ErrRuntimeCorrupt
	}
	return event, nil
}

func formatRuntimeTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(runtimeTimestampLayout)
}

func parseRuntimeTime(value string, optional bool) (time.Time, error) {
	if value == "" && optional {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(runtimeTimestampLayout, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, ErrRuntimeCorrupt
	}
	return parsed.UTC(), nil
}

func isConstraint(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "constraint") || strings.Contains(message, "unique")
}
