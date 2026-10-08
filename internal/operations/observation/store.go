package observation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
	_ "modernc.org/sqlite"
)

const operationSchema = `
CREATE TABLE operations (
 operation_ref TEXT PRIMARY KEY, owner_hash TEXT NOT NULL, request_id TEXT NOT NULL,
 run_id TEXT NOT NULL UNIQUE, preparation_ref TEXT NOT NULL UNIQUE,
 stage TEXT NOT NULL, record_json BLOB NOT NULL, record_sha256 TEXT NOT NULL,
 UNIQUE(owner_hash,request_id)
);
CREATE TABLE chat_dispositions (
 operation_ref TEXT PRIMARY KEY REFERENCES operations(operation_ref),
 disposition TEXT NOT NULL CHECK(disposition='chat_only'), created_at TEXT NOT NULL
);
CREATE TABLE temporary_tasks (
 task_id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE REFERENCES operations(run_id),
 task_json BLOB NOT NULL, task_sha256 TEXT NOT NULL,
 disposition TEXT NOT NULL CHECK(disposition IN ('reserved','not_created','cancel_acknowledged','cleanup_unconfirmed')),
 cancel_attempts INTEGER NOT NULL CHECK(cancel_attempts>=0 AND cancel_attempts<=2)
);`

const diagnosticSchema = `CREATE TABLE failure_diagnostics (
 run_id TEXT NOT NULL REFERENCES operations(run_id), operation TEXT NOT NULL, phase TEXT NOT NULL,
 diagnostic_json BLOB NOT NULL, diagnostic_sha256 TEXT NOT NULL, recorded_at TEXT NOT NULL,
 PRIMARY KEY(run_id,operation,phase)
);`

type operation struct {
	Ref                string                             `json:"ref"`
	OwnerHash          string                             `json:"ownerHash"`
	Request            Request                            `json:"request"`
	InputSHA256        string                             `json:"inputSha256"`
	RequestKey         string                             `json:"requestKey"`
	RunID              string                             `json:"runId"`
	PreparationRef     string                             `json:"preparationRef"`
	Source             livevision.SourceBinding           `json:"source"`
	ResolvedSourceName string                             `json:"resolvedSourceName"`
	SourceKind         string                             `json:"sourceKind"`
	Spec               temporary.TemporaryObservationSpec `json:"spec"`
	CreatedAt          time.Time                          `json:"createdAt"`
	DeadlineAt         time.Time                          `json:"deadlineAt"`
	ExpiresAt          time.Time                          `json:"expiresAt"`
	Stage              string                             `json:"stage"`
	Failure            string                             `json:"failure,omitempty"`
	CaptureMedia       *media.Descriptor                  `json:"captureMedia,omitempty"`
}

type operationStore struct {
	db      *sql.DB
	maximum int
}

func openStore(path string, maximum int) (*operationStore, error) {
	if err := localstate.PrepareStateRoot(filepath.Dir(path)); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		if err := localstate.ProtectFile(path); err != nil {
			return nil, err
		}
		created = true
	} else if err != nil {
		return nil, err
	}
	if err := localstate.ValidateFile(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*operationStore, error) { _ = db.Close(); return nil, err }
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON"} {
		if _, err := db.Exec(pragma); err != nil {
			return fail(err)
		}
	}
	var version, appID int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if err := db.QueryRow("PRAGMA application_id").Scan(&appID); err != nil {
		return fail(err)
	}
	if created && version == 0 && appID == 0 {
		tx, err := db.Begin()
		if err != nil {
			return fail(err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(operationSchema); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec("PRAGMA user_version=1"); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec("PRAGMA application_id=1397703217"); err != nil {
			return fail(err)
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != 1 || appID != 1397703217 {
		return fail(errors.New("observation operation store is incompatible"))
	}
	if err := openDiagnosticExtension(db); err != nil {
		return fail(err)
	}
	if err := openUploadExtension(db); err != nil {
		return fail(err)
	}
	return &operationStore{db: db, maximum: maximum}, nil
}

func openDiagnosticExtension(db *sql.DB) error {
	// This additive extension has its own version. Core user_version stays 1
	// so a paired-package rollback can still read the original results/tasks.
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS observation_extensions (name TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version>0))`); err != nil {
		return err
	}
	var version int
	err = tx.QueryRow(`SELECT version FROM observation_extensions WHERE name='failure_diagnostics'`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.Exec(diagnosticSchema); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO observation_extensions(name,version) VALUES('failure_diagnostics',1)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if version != 1 {
		return errors.New("observation diagnostic extension is incompatible")
	}
	rows, err := tx.Query(`SELECT run_id,operation,phase,diagnostic_json,diagnostic_sha256,recorded_at FROM failure_diagnostics LIMIT 0`)
	if err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	return tx.Commit()
}

// putDiagnostic records only the first failure at each operation/phase. Cleanup
// acknowledgement and later cleanup failures never overwrite analysis evidence.
func (s *operationStore) putDiagnostic(ctx context.Context, runID string, diagnostic safediagnostic.Diagnostic) error {
	if diagnostic.Validate() != nil || diagnostic.Class == safediagnostic.ClassAccepted {
		return safediagnostic.ErrInvalidDiagnostic
	}
	if _, err := s.byRun(ctx, runID); err != nil {
		return err
	}
	raw, digest, err := canonical(diagnostic)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO failure_diagnostics(run_id,operation,phase,diagnostic_json,diagnostic_sha256,recorded_at) VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,operation,phase) DO NOTHING`, runID, diagnostic.Operation, diagnostic.Phase, raw, digest, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *operationStore) diagnostics(ctx context.Context, runID string) ([]safediagnostic.Diagnostic, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT operation,phase,diagnostic_json,diagnostic_sha256 FROM failure_diagnostics WHERE run_id=? ORDER BY rowid`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []safediagnostic.Diagnostic
	for rows.Next() {
		var operation, phase, digest string
		var raw []byte
		var diagnostic safediagnostic.Diagnostic
		if err := rows.Scan(&operation, &phase, &raw, &digest); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		if json.Unmarshal(raw, &diagnostic) != nil || hex.EncodeToString(sum[:]) != digest || diagnostic.Validate() != nil || diagnostic.Class == safediagnostic.ClassAccepted || diagnostic.Operation != operation || diagnostic.Phase != phase {
			return nil, safediagnostic.ErrInvalidDiagnostic
		}
		result = append(result, diagnostic)
	}
	return result, rows.Err()
}

func canonical(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}
func (s *operationStore) put(ctx context.Context, value operation) error {
	raw, digest, err := canonical(value)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations").Scan(&count); err != nil {
		return err
	}
	if count >= s.maximum {
		return ErrCapacity
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(operation_ref,owner_hash,request_id,run_id,preparation_ref,stage,record_json,record_sha256) VALUES(?,?,?,?,?,?,?,?)`, value.Ref, value.OwnerHash, value.Request.RequestID, value.RunID, value.PreparationRef, value.Stage, raw, digest); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO chat_dispositions(operation_ref,disposition,created_at) VALUES(?,'chat_only',?)`, value.Ref, value.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *operationStore) update(ctx context.Context, value operation) error {
	raw, digest, err := canonical(value)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE operations SET stage=?,record_json=?,record_sha256=? WHERE operation_ref=? AND owner_hash=? AND request_id=? AND run_id=? AND preparation_ref=?`, value.Stage, raw, digest, value.Ref, value.OwnerHash, value.Request.RequestID, value.RunID, value.PreparationRef)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

const selectColumns = "operation_ref,owner_hash,request_id,run_id,preparation_ref,stage,record_json,record_sha256"

type scanner interface{ Scan(...any) error }

func scanOperation(row scanner) (operation, error) {
	var ref, owner, request, run, prep, stage, digest string
	var raw []byte
	if err := row.Scan(&ref, &owner, &request, &run, &prep, &stage, &raw, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return operation{}, ErrNotFound
		}
		return operation{}, err
	}
	var value operation
	if len(raw) > 64<<10 || json.Unmarshal(raw, &value) != nil {
		return operation{}, ErrUnavailable
	}
	_, computed, err := canonical(value)
	if err != nil || computed != digest || value.Ref != ref || value.OwnerHash != owner || value.Request.RequestID != request || value.RunID != run || value.PreparationRef != prep || value.Stage != stage || !ownerPattern.MatchString(owner) {
		return operation{}, ErrUnavailable
	}
	if value.Request.Mode == CaptureOnly {
		if value.Spec != (temporary.TemporaryObservationSpec{}) {
			return operation{}, ErrUnavailable
		}
		if value.CaptureMedia != nil && (value.CaptureMedia.Validate() != nil || !matchesMedia(value, *value.CaptureMedia)) {
			return operation{}, ErrUnavailable
		}
	} else if value.Request.Mode != "" || value.Spec.Validate() != nil || value.CaptureMedia != nil {
		return operation{}, ErrUnavailable
	}
	return value, nil
}
func (s *operationStore) get(ctx context.Context, owner, ref string) (operation, error) {
	return scanOperation(s.db.QueryRowContext(ctx, "SELECT "+selectColumns+" FROM operations WHERE owner_hash=? AND operation_ref=?", owner, ref))
}
func (s *operationStore) byRequest(ctx context.Context, owner, id string) (operation, error) {
	return scanOperation(s.db.QueryRowContext(ctx, "SELECT "+selectColumns+" FROM operations WHERE owner_hash=? AND request_id=?", owner, id))
}
func (s *operationStore) byRun(ctx context.Context, run string) (operation, error) {
	return scanOperation(s.db.QueryRowContext(ctx, "SELECT "+selectColumns+" FROM operations WHERE run_id=?", run))
}
func (s *operationStore) byPreparation(ctx context.Context, ref string) (operation, error) {
	return scanOperation(s.db.QueryRowContext(ctx, "SELECT "+selectColumns+" FROM operations WHERE preparation_ref=?", ref))
}
func (s *operationStore) pending(ctx context.Context) ([]operation, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+selectColumns+" FROM operations WHERE stage!='terminal' ORDER BY rowid LIMIT 64")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []operation{}
	for rows.Next() {
		value, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
