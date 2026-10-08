package devlab

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
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

const evidenceSchema = `
CREATE TABLE IF NOT EXISTS lab_runs (
    run_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL,
    device_type TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    change_digest TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    finished_at TEXT,
    read_count INTEGER NOT NULL DEFAULT 1,
    device_writes INTEGER NOT NULL DEFAULT 0,
    probe_count INTEGER NOT NULL DEFAULT 0,
    assertion_count INTEGER NOT NULL DEFAULT 0,
    chain_head TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lab_probes (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES lab_runs(run_id) ON DELETE RESTRICT,
    probe_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    hypothesis_digest TEXT NOT NULL,
    public_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    read_count INTEGER NOT NULL,
    device_writes INTEGER NOT NULL CHECK(device_writes = 0),
    previous_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_lab_probes_run ON lab_probes(run_id, sequence);
CREATE TABLE IF NOT EXISTS lab_assertions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id TEXT NOT NULL REFERENCES lab_probes(probe_id) ON DELETE RESTRICT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL
);`

var privateAddress = regexp.MustCompile(`(?i)(?:https?|rtsps?)://|(?:^|[^0-9])(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)`)

type EvidenceStore struct {
	db   *sql.DB
	root string
	path string
}

func DefaultRoot() (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("device lab is supported only on Windows")
	}
	base := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if base == "" {
		return "", errors.New("LOCALAPPDATA is unavailable")
	}
	return filepath.Join(base, "CosmoEdge", "DevLab"), nil
}

func OpenEvidence(root string) (*EvidenceStore, error) {
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = DefaultRoot()
		if err != nil {
			return nil, err
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, "lab.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", evidenceSchema} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	store := &EvidenceStore{db: db, root: root, path: path}
	if err := store.protectFiles(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *EvidenceStore) Root() string { return s.root }
func (s *EvidenceStore) Path() string { return s.path }

func (s *EvidenceStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *EvidenceStore) StartRun(ctx context.Context, run EvidenceRun) error {
	if run.RunID == "" || run.Device == "" || run.DeviceType == "" || run.OpenedAt.IsZero() || !run.ExpiresAt.After(run.OpenedAt) {
		return errors.New("complete device lab run metadata is required")
	}
	if !validSourceMetadata(run.Commit, run.ChangeDigest) {
		return errors.New("device lab source metadata is invalid")
	}
	if privateAddress.MatchString(run.Device) || privateAddress.MatchString(run.DeviceType) || privateAddress.MatchString(run.Commit) || privateAddress.MatchString(run.ChangeDigest) {
		return errors.New("protected device data is not allowed in evidence")
	}
	genesis := hashRecord("", run.RunID, "run_started", run.OpenedAt.UTC().Format(time.RFC3339Nano))
	_, err := s.db.ExecContext(ctx, `INSERT INTO lab_runs(run_id,status,device,device_type,commit_sha,change_digest,opened_at,expires_at,chain_head) VALUES(?, 'active', ?, ?, ?, ?, ?, ?, ?)`,
		run.RunID, run.Device, run.DeviceType, run.Commit, run.ChangeDigest, formatEvidenceTime(run.OpenedAt), formatEvidenceTime(run.ExpiresAt), genesis)
	if err != nil {
		return err
	}
	return s.protectFiles()
}

func (s *EvidenceStore) RecordProbe(ctx context.Context, probe EvidenceProbe) error {
	if probe.RunID == "" || probe.ProbeID == "" || probe.Kind == "" || probe.ObservedAt.IsZero() || probe.ReadCount < 1 || probe.DeviceWrites != 0 {
		return errors.New("complete zero-write probe evidence is required")
	}
	if err := validatePublicEvidence(probe.PublicJSON); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT chain_head FROM lab_runs WHERE run_id=? AND status='active'`, probe.RunID).Scan(&previous); err != nil {
		return err
	}
	recordHash := hashRecord(previous, probe.ProbeID, probe.Kind, probe.HypothesisDigest, probe.PublicJSON, formatEvidenceTime(probe.ObservedAt), fmt.Sprint(probe.ReadCount), "0")
	if _, err := tx.ExecContext(ctx, `INSERT INTO lab_probes(run_id,probe_id,kind,hypothesis_digest,public_json,observed_at,read_count,device_writes,previous_hash,record_hash) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		probe.RunID, probe.ProbeID, probe.Kind, probe.HypothesisDigest, probe.PublicJSON, formatEvidenceTime(probe.ObservedAt), probe.ReadCount, 0, previous, recordHash); err != nil {
		return err
	}
	for _, assertion := range probe.Assertions {
		raw, err := json.Marshal(assertion)
		if err != nil {
			return err
		}
		if err := validatePublicEvidence(string(raw)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO lab_assertions(probe_id,kind,path,status,result_json) VALUES(?,?,?,?,?)`, probe.ProbeID, assertion.Kind, assertion.Path, assertion.Status, string(raw)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE lab_runs SET chain_head=?,read_count=?,probe_count=probe_count+1,assertion_count=assertion_count+? WHERE run_id=? AND status='active'`, recordHash, probe.ReadCount, len(probe.Assertions), probe.RunID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.protectFiles()
}

func (s *EvidenceStore) FinishRun(ctx context.Context, runID, result string, finishedAt time.Time, reads, probes, assertions int) error {
	if result != "passed" && result != "failed" {
		return errors.New("run result is invalid")
	}
	if reads < 1 || probes < 0 || assertions < 0 {
		return errors.New("run counters are invalid")
	}
	if err := s.VerifyRun(ctx, runID); err != nil {
		return err
	}
	updated, err := s.db.ExecContext(ctx, `UPDATE lab_runs SET status='finished',result=?,finished_at=?,read_count=?,device_writes=0,probe_count=?,assertion_count=? WHERE run_id=? AND status='active'`, result, formatEvidenceTime(finishedAt), reads, probes, assertions, runID)
	if err != nil {
		return err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return errors.New("active device lab run was not found")
	}
	return s.protectFiles()
}

func (s *EvidenceStore) VerifyRun(ctx context.Context, runID string) error {
	var openedRaw, head string
	if err := s.db.QueryRowContext(ctx, `SELECT opened_at,chain_head FROM lab_runs WHERE run_id=?`, runID).Scan(&openedRaw, &head); err != nil {
		return err
	}
	previous := hashRecord("", runID, "run_started", openedRaw)
	rows, err := s.db.QueryContext(ctx, `SELECT probe_id,kind,hypothesis_digest,public_json,observed_at,read_count,device_writes,previous_hash,record_hash FROM lab_probes WHERE run_id=? ORDER BY sequence`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var probeID, kind, hypothesis, publicJSON, observedAt, storedPrevious, storedHash string
		var reads, writes int
		if err := rows.Scan(&probeID, &kind, &hypothesis, &publicJSON, &observedAt, &reads, &writes, &storedPrevious, &storedHash); err != nil {
			return err
		}
		if writes != 0 || storedPrevious != previous || storedHash != hashRecord(previous, probeID, kind, hypothesis, publicJSON, observedAt, fmt.Sprint(reads), "0") {
			return errors.New("device lab evidence chain verification failed")
		}
		previous = storedHash
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if previous != head {
		return errors.New("device lab evidence chain head does not match")
	}
	return nil
}

func (s *EvidenceStore) protectFiles() error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := s.path + suffix
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("device lab evidence path is not a regular file")
		}
		if err := localstate.ProtectFile(path); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicEvidence(raw string) error {
	if len(raw) == 0 || len(raw) > 2<<20 || !json.Valid([]byte(raw)) {
		return errors.New("probe evidence must be bounded JSON")
	}
	if privateAddress.MatchString(raw) {
		return errors.New("probe evidence contains a protected address")
	}
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return err
	}
	return rejectProtectedKeys(value)
}

func rejectProtectedKeys(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
			switch normalized {
			case "endpoint", "password", "passwordbase64", "token", "username", "serial", "rawid", "deviceid", "channelid", "algorithmid":
				return fmt.Errorf("probe evidence contains protected field %q", key)
			}
			if err := rejectProtectedKeys(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := rejectProtectedKeys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func hashRecord(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func formatEvidenceTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
