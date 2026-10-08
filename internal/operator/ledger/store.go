package ledger

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
	_ "modernc.org/sqlite"
)

var (
	ErrConflict = errors.New("action state conflict")
	ErrNotFound = errors.New("action not found")
)

const schema = `
CREATE TABLE IF NOT EXISTS operator_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    result_class TEXT NOT NULL DEFAULT '',
    session_binding TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    public_json TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_queue ON actions(state, created_at);
CREATE TABLE IF NOT EXISTS dispatches (
    action_id TEXT PRIMARY KEY REFERENCES actions(id) ON DELETE RESTRICT,
    attempt_no INTEGER NOT NULL,
    state TEXT NOT NULL,
    outcome TEXT NOT NULL DEFAULT '',
    dispatch_count INTEGER NOT NULL DEFAULT 0,
    device_write_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS action_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_events_action ON action_events(action_id, sequence);
CREATE TABLE IF NOT EXISTS evidence (
    action_id TEXT PRIMARY KEY REFERENCES actions(id) ON DELETE RESTRICT,
    status TEXT NOT NULL,
    result_class TEXT NOT NULL,
    conclusion TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    sealed_at TEXT
);
CREATE TABLE IF NOT EXISTS worker_leases (
    name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);`

type Store struct {
	db *sql.DB
}

type Action struct {
	ID             string
	Kind           string
	State          string
	ResultClass    string
	SessionBinding string
	ResourceKey    string
	PublicJSON     string
	Reason         string
	ExpiresAt      time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type NewAction struct {
	ID             string
	Kind           string
	SessionBinding string
	ResourceKey    string
	PublicJSON     string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

type DispatchObservation struct {
	Outcome string
	// DeviceWriteCount retains the handler's write accounting; zero does not mean no HTTP request was sent.
	DeviceWriteCount int
	FinishedAt       time.Time
	Diagnostic       *safediagnostic.Diagnostic `json:"diagnostic,omitempty"`
}

type Record struct {
	Action
	Dispatches      int
	DeviceWrites    int
	DispatchOutcome string
	EvidenceStatus  string
	Conclusion      string
	Diagnostic      *safediagnostic.Diagnostic `json:"diagnostic,omitempty"`
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "?#\x00") {
		return nil, errors.New("ledger path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(absolute)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := localstate.PrepareStateRoot(root); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if err := localstate.ValidateStateRoot(root); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing Operator ledger: %w", err)
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
	// Reject unsafe files left by an earlier writer before SQLite can open them.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(absolute + suffix); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := localstate.ValidateFile(absolute + suffix); err != nil {
			return nil, fmt.Errorf("reject existing Operator ledger sidecar: %w", err)
		}
	}
	db, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL"} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO operator_schema_migrations(version, applied_at) VALUES(1, ?)`, formatTime(time.Now().UTC())); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrateDispatchDiagnostic(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// SQLite creates these files with inherited Windows ACLs. Give them the
	// same explicit, protected current-user ACL as the database before reuse.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(absolute + suffix); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			_ = db.Close()
			return nil, err
		}
		if err := localstate.ProtectFile(absolute + suffix); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("protect Operator ledger sidecar: %w", err)
		}
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrateDispatchDiagnostic only adds nullable metadata. Existing action, dispatch,
// evidence and event rows are never rewritten by this migration.
func migrateDispatchDiagnostic(db *sql.DB) error {
	transaction, err := db.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	rows, err := transaction.Query(`PRAGMA table_info(dispatches)`)
	if err != nil {
		return err
	}
	present := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "diagnostic_json" {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !present {
		if _, err := transaction.Exec(`ALTER TABLE dispatches ADD COLUMN diagnostic_json TEXT`); err != nil {
			return err
		}
	}
	if _, err := transaction.Exec(`INSERT OR IGNORE INTO operator_schema_migrations(version, applied_at) VALUES(2, ?)`, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Create(ctx context.Context, input NewAction) error {
	input.ID, input.Kind = strings.TrimSpace(input.ID), strings.TrimSpace(input.Kind)
	input.SessionBinding, input.ResourceKey = strings.TrimSpace(input.SessionBinding), strings.TrimSpace(input.ResourceKey)
	if input.ID == "" || input.Kind == "" || input.SessionBinding == "" || input.ResourceKey == "" || input.CreatedAt.IsZero() || !input.ExpiresAt.After(input.CreatedAt) {
		return errors.New("complete bounded action metadata is required")
	}
	if !isDigest(input.SessionBinding) || !isDigest(input.ResourceKey) {
		return errors.New("session binding and resource key must be SHA-256 digests")
	}
	if !json.Valid([]byte(input.PublicJSON)) {
		return errors.New("public action metadata must be valid JSON")
	}
	if err := rejectProtected(input.PublicJSON, input.SessionBinding, input.ResourceKey); err != nil {
		return err
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `INSERT INTO actions(id, kind, state, session_binding, resource_key, public_json, expires_at, created_at, updated_at) VALUES(?, ?, 'proposed', ?, ?, ?, ?, ?, ?)`,
		input.ID, input.Kind, input.SessionBinding, input.ResourceKey, input.PublicJSON,
		formatTime(input.ExpiresAt), formatTime(input.CreatedAt), formatTime(input.CreatedAt))
	if err != nil {
		return err
	}
	if err := appendEvent(ctx, transaction, input.ID, "proposed", "fresh_read_bound_proposal", input.CreatedAt); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) Confirm(ctx context.Context, id, sessionBinding string, now time.Time) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	expired, err := transaction.ExecContext(ctx, `UPDATE actions SET state='blocked', result_class='blocked', reason='proposal_expired', updated_at=? WHERE id=? AND state='proposed' AND expires_at<=?`, formatTime(now), id, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := expired.RowsAffected(); rows == 1 {
		if err := insertTerminalEvidence(ctx, transaction, id, result.Blocked, result.EvidencePending, "proposal_expired", "Proposal expired before confirmation.", now); err != nil {
			return err
		}
		if err := appendEvent(ctx, transaction, id, "blocked", "proposal_expired", now); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		return ErrConflict
	}
	resultSet, err := transaction.ExecContext(ctx, `UPDATE actions SET state='queued', reason='human_confirmed', updated_at=? WHERE id=? AND state='proposed' AND session_binding=? AND expires_at>?`, formatTime(now), id, sessionBinding, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := resultSet.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	if err := appendEvent(ctx, transaction, id, "queued", "human_confirmed", now); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) Cancel(ctx context.Context, id, sessionBinding string, now time.Time) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	resultSet, err := transaction.ExecContext(ctx, `UPDATE actions SET state='blocked', result_class='blocked', reason='cancelled_by_user', updated_at=? WHERE id=? AND state='proposed' AND session_binding=?`, formatTime(now), id, sessionBinding)
	if err != nil {
		return err
	}
	if rows, _ := resultSet.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	if err := insertTerminalEvidence(ctx, transaction, id, result.Blocked, result.EvidencePending, "cancelled_by_user", "Proposal cancelled before dispatch.", now); err != nil {
		return err
	}
	if err := appendEvent(ctx, transaction, id, "blocked", "cancelled_by_user", now); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) ClaimNext(ctx context.Context, now time.Time) (Action, bool, error) {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Action{}, false, err
	}
	defer transaction.Rollback()
	if err := expireQueued(ctx, transaction, now); err != nil {
		return Action{}, false, err
	}
	row := transaction.QueryRowContext(ctx, `UPDATE actions SET state='claimed', reason='worker_claimed', updated_at=? WHERE id=(SELECT id FROM actions WHERE state='queued' AND expires_at>? ORDER BY created_at, id LIMIT 1) AND state='queued' RETURNING id, kind, state, result_class, session_binding, resource_key, public_json, reason, expires_at, created_at, updated_at`, formatTime(now), formatTime(now))
	action, err := scanAction(row)
	if errors.Is(err, sql.ErrNoRows) {
		if err := transaction.Commit(); err != nil {
			return Action{}, false, err
		}
		return Action{}, false, nil
	}
	if err != nil {
		return Action{}, false, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO dispatches(action_id, attempt_no, state) VALUES(?, 1, 'claimed')`, action.ID); err != nil {
		return Action{}, false, err
	}
	if err := appendEvent(ctx, transaction, action.ID, "claimed", "worker_claimed", now); err != nil {
		return Action{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Action{}, false, err
	}
	return action, true, nil
}

func (s *Store) MarkDispatch(ctx context.Context, id string, now time.Time) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	resultSet, err := transaction.ExecContext(ctx, `UPDATE actions SET state='dispatching', reason='dispatch_marker_committed', updated_at=? WHERE id=? AND state='claimed'`, formatTime(now), id)
	if err != nil {
		return err
	}
	if rows, _ := resultSet.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	dispatchSet, err := transaction.ExecContext(ctx, `UPDATE dispatches SET state='dispatching', dispatch_count=1, started_at=? WHERE action_id=? AND state='claimed'`, formatTime(now), id)
	if err != nil {
		return err
	}
	if rows, _ := dispatchSet.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	if err := appendEvent(ctx, transaction, id, "dispatching", "dispatch_marker_committed", now); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) RecordDispatch(ctx context.Context, id string, observation DispatchObservation) error {
	if observation.Outcome != "accepted" && observation.Outcome != "known_failed" && observation.Outcome != "outcome_unknown" {
		return errors.New("dispatch outcome is invalid")
	}
	if observation.DeviceWriteCount < 0 || observation.FinishedAt.IsZero() {
		return errors.New("dispatch observation is incomplete")
	}
	var diagnosticJSON any
	if observation.Diagnostic != nil {
		if err := observation.Diagnostic.Validate(); err != nil {
			return err
		}
		encoded, err := json.Marshal(observation.Diagnostic)
		if err != nil {
			return err
		}
		diagnosticJSON = string(encoded)
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	resultSet, err := transaction.ExecContext(ctx, `UPDATE actions SET state='verifying', reason=?, updated_at=? WHERE id=? AND state='dispatching'`, observation.Outcome, formatTime(observation.FinishedAt), id)
	if err != nil {
		return err
	}
	if rows, _ := resultSet.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	dispatchSet, err := transaction.ExecContext(ctx, `UPDATE dispatches SET state='verifying', outcome=?, device_write_count=?, finished_at=?, diagnostic_json=? WHERE action_id=? AND state='dispatching'`, observation.Outcome, observation.DeviceWriteCount, formatTime(observation.FinishedAt), diagnosticJSON, id)
	if err != nil {
		return err
	}
	if rows, _ := dispatchSet.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	if err := appendEvent(ctx, transaction, id, "verifying", observation.Outcome, observation.FinishedAt); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) Finish(ctx context.Context, id string, trusted result.Trusted) error {
	if err := trusted.Validate(); err != nil {
		return err
	}
	if err := rejectProtected(trusted.Conclusion, trusted.Reason, trusted.EvidenceJSON); err != nil {
		return err
	}
	if !json.Valid([]byte(trusted.EvidenceJSON)) {
		return errors.New("trusted evidence payload must be valid JSON")
	}
	state := string(trusted.Class)
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	resultSet, err := transaction.ExecContext(ctx, `UPDATE actions SET state=?, result_class=?, reason=?, updated_at=? WHERE id=? AND state IN ('verifying','claimed')`, state, trusted.Class, trusted.Reason, formatTime(trusted.ObservedAt), id)
	if err != nil {
		return err
	}
	if rows, _ := resultSet.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	sealedAt := any(nil)
	if trusted.EvidenceStatus == result.EvidenceSealed {
		sealedAt = formatTime(trusted.ObservedAt)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO evidence(action_id, status, result_class, conclusion, reason, payload_json, observed_at, sealed_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, id, trusted.EvidenceStatus, trusted.Class, trusted.Conclusion, trusted.Reason, trusted.EvidenceJSON, formatTime(trusted.ObservedAt), sealedAt); err != nil {
		return err
	}
	if err := appendEvent(ctx, transaction, id, state, trusted.Reason, trusted.ObservedAt); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) Get(ctx context.Context, id string) (Action, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, kind, state, result_class, session_binding, resource_key, public_json, reason, expires_at, created_at, updated_at FROM actions WHERE id=?`, id)
	action, err := scanAction(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Action{}, ErrNotFound
	}
	return action, err
}

func (s *Store) Inspect(ctx context.Context, id string) (Record, error) {
	row := s.db.QueryRowContext(ctx, `SELECT a.id, a.kind, a.state, a.result_class, a.session_binding, a.resource_key, a.public_json, a.reason, a.expires_at, a.created_at, a.updated_at, COALESCE(d.dispatch_count, 0), COALESCE(d.device_write_count, 0), COALESCE(d.outcome, ''), COALESCE(e.status, ''), COALESCE(e.conclusion, ''), d.diagnostic_json FROM actions a LEFT JOIN dispatches d ON d.action_id=a.id LEFT JOIN evidence e ON e.action_id=a.id WHERE a.id=?`, id)
	var record Record
	var diagnosticJSON sql.NullString
	var expiresAt, createdAt, updatedAt string
	err := row.Scan(
		&record.ID, &record.Kind, &record.State, &record.ResultClass, &record.SessionBinding,
		&record.ResourceKey, &record.PublicJSON, &record.Reason, &expiresAt, &createdAt, &updatedAt,
		&record.Dispatches, &record.DeviceWrites, &record.DispatchOutcome, &record.EvidenceStatus, &record.Conclusion, &diagnosticJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	if diagnosticJSON.Valid {
		var diagnostic safediagnostic.Diagnostic
		decoder := json.NewDecoder(strings.NewReader(diagnosticJSON.String))
		decoder.DisallowUnknownFields()
		if !json.Valid([]byte(diagnosticJSON.String)) || decoder.Decode(&diagnostic) != nil || diagnostic.Validate() != nil {
			return Record{}, errors.New("stored dispatch diagnostic is invalid")
		}
		record.Diagnostic = &diagnostic
	}
	if record.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return Record{}, err
	}
	if record.CreatedAt, err = parseTime(createdAt); err != nil {
		return Record{}, err
	}
	if record.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return Record{}, err
	}
	return record, nil
}

// EvidenceRecord is an internal read of the existing evidence row. Callers must
// authorize the action owner and project a typed allowlist before public output.
// Raw evidence and storage timestamps are never serialized by this type.
type EvidenceRecord struct {
	Status      string `json:"-"`
	PayloadJSON string `json:"-"`
	ObservedAt  string `json:"-"`
	SealedAt    string `json:"-"`
}

func (s *Store) InspectEvidence(ctx context.Context, id string) (EvidenceRecord, error) {
	var evidence EvidenceRecord
	err := s.db.QueryRowContext(ctx, `SELECT status, payload_json, observed_at, COALESCE(sealed_at, '') FROM evidence WHERE action_id=?`, id).Scan(&evidence.Status, &evidence.PayloadJSON, &evidence.ObservedAt, &evidence.SealedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EvidenceRecord{}, ErrNotFound
	}
	return evidence, err
}

func (s *Store) AcquireWorker(ctx context.Context, name, owner string, now time.Time, ttl time.Duration) (bool, error) {
	if name == "" || owner == "" || ttl <= 0 {
		return false, errors.New("worker lease metadata is required")
	}
	expiresAt := now.Add(ttl)
	resultSet, err := s.db.ExecContext(ctx, `INSERT INTO worker_leases(name, owner_id, expires_at, updated_at) VALUES(?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET owner_id=excluded.owner_id, expires_at=excluded.expires_at, updated_at=excluded.updated_at WHERE worker_leases.owner_id=excluded.owner_id OR worker_leases.expires_at<=?`, name, owner, formatTime(expiresAt), formatTime(now), formatTime(now))
	if err != nil {
		return false, err
	}
	rows, err := resultSet.RowsAffected()
	return rows == 1, err
}

func (s *Store) ReleaseWorker(ctx context.Context, name, owner string) error {
	if name == "" || owner == "" {
		return errors.New("worker lease metadata is required")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM worker_leases WHERE name=? AND owner_id=?`, name, owner)
	return err
}

func (s *Store) RecoverInterrupted(ctx context.Context, now time.Time) error {
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `SELECT id, state FROM actions WHERE state IN ('proposed','queued','claimed','dispatching','verifying')`)
	if err != nil {
		return err
	}
	type interrupted struct{ id, state string }
	var actions []interrupted
	for rows.Next() {
		var item interrupted
		if err := rows.Scan(&item.id, &item.state); err != nil {
			rows.Close()
			return err
		}
		actions = append(actions, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, action := range actions {
		class, state, reason := "blocked", "blocked", "foreground_authority_lost_before_dispatch"
		if action.state == "dispatching" || action.state == "verifying" {
			class, state, reason = "unknown", "unknown", "process_restarted_after_dispatch"
		}
		if _, err := transaction.ExecContext(ctx, `UPDATE actions SET state=?, result_class=?, reason=?, updated_at=? WHERE id=?`, state, class, reason, formatTime(now), action.id); err != nil {
			return err
		}
		if _, err := transaction.ExecContext(ctx, `UPDATE dispatches SET state=?, outcome=?, finished_at=COALESCE(finished_at, ?) WHERE action_id=?`, state, reason, formatTime(now), action.id); err != nil {
			return err
		}
		conclusion := "Action stopped before device dispatch."
		if state == "unknown" {
			conclusion = "Dispatch may have reached the device; no replay is allowed."
		}
		if err := insertTerminalEvidence(ctx, transaction, action.id, result.Class(class), result.EvidencePending, reason, conclusion, now); err != nil {
			return err
		}
		if err := appendEvent(ctx, transaction, action.id, state, reason, now); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func expireQueued(ctx context.Context, transaction *sql.Tx, now time.Time) error {
	rows, err := transaction.QueryContext(ctx, `UPDATE actions SET state='blocked', result_class='blocked', reason='proposal_expired', updated_at=? WHERE state='queued' AND expires_at<=? RETURNING id`, formatTime(now), formatTime(now))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := insertTerminalEvidence(ctx, transaction, id, result.Blocked, result.EvidencePending, "proposal_expired", "Proposal expired before dispatch.", now); err != nil {
			return err
		}
		if err := appendEvent(ctx, transaction, id, "blocked", "proposal_expired", now); err != nil {
			return err
		}
	}
	return nil
}

func insertTerminalEvidence(ctx context.Context, transaction *sql.Tx, id string, class result.Class, status result.EvidenceStatus, reason, conclusion string, at time.Time) error {
	sealedAt := any(nil)
	if status == result.EvidenceSealed {
		sealedAt = formatTime(at)
	}
	_, err := transaction.ExecContext(ctx, `INSERT INTO evidence(action_id, status, result_class, conclusion, reason, payload_json, observed_at, sealed_at) VALUES(?, ?, ?, ?, ?, '{}', ?, ?)`, id, status, class, conclusion, reason, formatTime(at), sealedAt)
	return err
}

func appendEvent(ctx context.Context, transaction *sql.Tx, id, eventType, reason string, at time.Time) error {
	_, err := transaction.ExecContext(ctx, `INSERT INTO action_events(action_id, event_type, reason, occurred_at) VALUES(?, ?, ?, ?)`, id, eventType, reason, formatTime(at))
	return err
}

type rowScanner interface{ Scan(...any) error }

func scanAction(row rowScanner) (Action, error) {
	var action Action
	var expiresAt, createdAt, updatedAt string
	if err := row.Scan(&action.ID, &action.Kind, &action.State, &action.ResultClass, &action.SessionBinding, &action.ResourceKey, &action.PublicJSON, &action.Reason, &expiresAt, &createdAt, &updatedAt); err != nil {
		return Action{}, err
	}
	var err error
	if action.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return Action{}, err
	}
	if action.CreatedAt, err = parseTime(createdAt); err != nil {
		return Action{}, err
	}
	if action.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return Action{}, err
	}
	return action, nil
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }

var networkLiteral = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b`)

func rejectProtected(values ...string) error {
	for _, value := range values {
		lower := strings.ToLower(value)
		for _, marker := range []string{
			"password", "credential", "sourceurl", "source_url", "rtsp://", "rtsps://",
			"http://", "https://", "deviceaddress", "device_address", "endpoint",
			"confirmationtoken", "businessconfirmation", "cookie", "bearer", "\"mtk\"",
			"\"parameters\"", "\"params\"", "\"fields\"", "\"value\"",
		} {
			if strings.Contains(lower, marker) {
				return fmt.Errorf("protected material marker %q is not allowed in the ledger", marker)
			}
		}
		if networkLiteral.MatchString(lower) {
			return errors.New("network literals are not allowed in the ledger")
		}
	}
	return nil
}

func isDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
