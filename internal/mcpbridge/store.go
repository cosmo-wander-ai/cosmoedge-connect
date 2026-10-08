package mcpbridge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionowner"
	_ "modernc.org/sqlite"
)

type journal struct {
	db *sql.DB
}
type businessContext struct{ Ref, Session, CreatedAt string }
type operation struct {
	Ref        string         `json:"operationRef"`
	Context    string         `json:"-"`
	RequestKey string         `json:"requestKey"`
	RequestID  string         `json:"-"`
	Kind       string         `json:"kind"`
	Payload    string         `json:"-"`
	ServiceRef string         `json:"-"`
	State      string         `json:"state"`
	CreatedAt  string         `json:"createdAt"`
	Result     map[string]any `json:"-"`
	Revision   int            `json:"-"`
}
type artifact struct {
	Ref       string   `json:"artifactRef"`
	Context   string   `json:"-"`
	Operation string   `json:"operationRef,omitempty"`
	MIME      string   `json:"mimeType"`
	SHA256    string   `json:"sha256"`
	Size      int      `json:"sizeBytes"`
	CreatedAt string   `json:"createdAt"`
	Candidate Identity `json:"candidate"`
	Content   []byte   `json:"-"`
}

func randomRef(prefix string) (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
func (j *journal) close() error { return j.db.Close() }

func openJournal(root, binding string) (*journal, error) {
	if strings.ContainsAny(root, "?#\x00") || strings.TrimSpace(root) == "" {
		return nil, errors.New("private_state_root_required")
	}
	// The filesystem lease serializes schema admission only. Each stdio
	// process then uses SQLite transactions against the shared private journal.
	var lease *connectionowner.Lease
	var err error
	for attempts := 0; attempts < 60; attempts++ {
		lease, err = connectionowner.AcquireLease(root)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		return nil, errors.New("private_state_unavailable")
	}
	defer lease.Close()
	fail := func(e error) (*journal, error) { _ = lease.Close(); return nil, e }
	path := filepath.Join(root, "mcp-journal.db")
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		p := path + suffix
		if _, err := os.Lstat(p); err == nil {
			if localstate.ValidateFile(p) != nil {
				return fail(errors.New("private_journal_required"))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fail(errors.New("journal_unavailable"))
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	created := err == nil
	if created {
		_ = file.Close()
		if localstate.ProtectFile(path) != nil {
			return fail(errors.New("private_journal_required"))
		}
	} else if !errors.Is(err, os.ErrExist) {
		return fail(errors.New("journal_unavailable"))
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fail(errors.New("journal_unavailable"))
	}
	db.SetMaxOpenConns(1)
	failDB := func(e error) (*journal, error) { _ = db.Close(); return fail(e) }
	for _, q := range []string{"PRAGMA busy_timeout=3000", "PRAGMA trusted_schema=OFF", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err := db.Exec(q); err != nil {
			return failDB(errors.New("journal_unavailable"))
		}
	}
	var version, appID int
	if db.QueryRow("PRAGMA user_version").Scan(&version) != nil || db.QueryRow("PRAGMA application_id").Scan(&appID) != nil {
		return failDB(errors.New("journal_unavailable"))
	}
	if created {
		_, err = db.Exec(`PRAGMA application_id=1396919632; PRAGMA user_version=1;
CREATE TABLE metadata (binding TEXT NOT NULL);
CREATE TABLE contexts (ref TEXT PRIMARY KEY, session TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE operations (ref TEXT PRIMARY KEY, context_ref TEXT NOT NULL REFERENCES contexts(ref), request_key TEXT NOT NULL, request_id TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, service_ref TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, created_at TEXT NOT NULL, result TEXT NOT NULL DEFAULT '{}', revision INTEGER NOT NULL DEFAULT 0, UNIQUE(context_ref,request_key));
CREATE TABLE artifacts (ref TEXT PRIMARY KEY, context_ref TEXT NOT NULL REFERENCES contexts(ref), operation_ref TEXT NOT NULL, mime TEXT NOT NULL, sha TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL, candidate TEXT NOT NULL, content BLOB NOT NULL, UNIQUE(context_ref,operation_ref,sha));`)
		if err == nil {
			_, err = db.Exec("INSERT INTO metadata(binding) VALUES (?)", binding)
		}
		if err != nil {
			return failDB(errors.New("journal_creation_failed"))
		}
	} else if version != 1 || appID != 1396919632 {
		return failDB(errors.New("journal_schema_mismatch"))
	}
	var recorded string
	if db.QueryRow("SELECT binding FROM metadata").Scan(&recorded) != nil || recorded != binding {
		return failDB(errors.New("journal_service_binding_mismatch"))
	}
	return &journal{db}, nil
}

func (j *journal) addContext(session string) (businessContext, error) {
	var count int
	if j.db.QueryRow("SELECT count(*) FROM contexts").Scan(&count) != nil || count >= 4096 {
		return businessContext{}, errors.New("context_capacity_reached")
	}
	ref, err := randomRef("ctx_")
	if err != nil {
		return businessContext{}, err
	}
	c := businessContext{ref, session, time.Now().UTC().Format(time.RFC3339Nano)}
	_, err = j.db.Exec("INSERT INTO contexts(ref,session,created_at) VALUES (?,?,?)", c.Ref, c.Session, c.CreatedAt)
	if err != nil {
		return businessContext{}, errors.New("context_persistence_failed")
	}
	return c, nil
}
func (j *journal) context(ref string) (businessContext, error) {
	var c businessContext
	if !referencePattern.MatchString(ref) || j.db.QueryRow("SELECT ref,session,created_at FROM contexts WHERE ref=?", ref).Scan(&c.Ref, &c.Session, &c.CreatedAt) != nil {
		return c, errors.New("context_not_found")
	}
	if !sessionPattern.MatchString(c.Session) {
		return c, errors.New("invalid_context_record")
	}
	return c, nil
}
func (j *journal) prepare(contextRef, key, kind string, payload map[string]any) (operation, bool, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return operation{}, false, err
	}
	previous, err := j.operation(contextRef, "", key)
	if err == nil {
		if previous.Kind != kind || previous.Payload != string(raw) {
			return operation{}, false, errors.New("request_key_conflict")
		}
		return previous, false, nil
	}
	if err.Error() != "operation_not_found" {
		return operation{}, false, err
	}
	var count int
	if j.db.QueryRow("SELECT count(*) FROM operations").Scan(&count) != nil || count >= 32768 {
		return operation{}, false, errors.New("operation_capacity_reached")
	}
	ref, err := randomRef("op_")
	if err != nil {
		return operation{}, false, err
	}
	request, err := randomRef("req_")
	if err != nil {
		return operation{}, false, err
	}
	op := operation{Ref: ref, Context: contextRef, RequestKey: key, RequestID: request, Kind: kind, Payload: string(raw), State: "submission_unknown", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Result: map[string]any{}}
	_, err = j.db.Exec("INSERT INTO operations(ref,context_ref,request_key,request_id,kind,payload,state,created_at) VALUES (?,?,?,?,?,?,?,?)", op.Ref, op.Context, op.RequestKey, op.RequestID, op.Kind, op.Payload, op.State, op.CreatedAt)
	if err != nil {
		// Another adapter may have atomically claimed this intent after our
		// first read. Only the insert winner may send the original POST.
		if previous, e := j.operation(contextRef, "", key); e == nil {
			if previous.Kind != kind || previous.Payload != string(raw) {
				return operation{}, false, errors.New("request_key_conflict")
			}
			return previous, false, nil
		}
		return operation{}, false, errors.New("request_persistence_failed")
	}
	return op, true, nil
}

const operationColumns = "ref,context_ref,request_key,request_id,kind,payload,service_ref,state,created_at,result,revision"

func scanOperation(row interface{ Scan(...any) error }) (operation, error) {
	var op operation
	var raw string
	err := row.Scan(&op.Ref, &op.Context, &op.RequestKey, &op.RequestID, &op.Kind, &op.Payload, &op.ServiceRef, &op.State, &op.CreatedAt, &raw, &op.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return op, errors.New("operation_not_found")
	}
	if err != nil || decodeStrict([]byte(raw), &op.Result) != nil {
		return op, errors.New("operation_record_unavailable")
	}
	return op, nil
}
func (j *journal) operation(contextRef, ref, key string) (operation, error) {
	if (ref == "") == (key == "") {
		return operation{}, errors.New("one_operation_reference_required")
	}
	if ref != "" {
		return scanOperation(j.db.QueryRow("SELECT "+operationColumns+" FROM operations WHERE context_ref=? AND ref=?", contextRef, ref))
	}
	return scanOperation(j.db.QueryRow("SELECT "+operationColumns+" FROM operations WHERE context_ref=? AND request_key=?", contextRef, key))
}
func (j *journal) save(op *operation) error {
	raw, err := json.Marshal(op.Result)
	if err != nil || len(raw) > maxJSON {
		return errors.New("invalid_operation_record")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	updated, err := j.db.ExecContext(ctx, "UPDATE operations SET service_ref=?,state=?,result=?,revision=revision+1 WHERE ref=? AND context_ref=? AND revision=?", op.ServiceRef, op.State, string(raw), op.Ref, op.Context, op.Revision)
	if err != nil {
		return errors.New("operation_persistence_failed")
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return errors.New("operation_persistence_failed")
	}
	if count == 0 {
		latest, err := j.operation(op.Context, op.Ref, "")
		if err != nil {
			return err
		}
		*op = latest
		return nil
	}
	op.Revision++
	return nil
}
func (j *journal) pending(contextRef string) ([]operation, int, error) {
	tx, err := j.db.Begin()
	if err != nil {
		return nil, 0, errors.New("journal_unavailable")
	}
	defer tx.Rollback()
	const where = " FROM operations WHERE context_ref=? AND state IN ('submission_unknown','unknown','outcome_unknown','pending','proposed')"
	var total int
	if tx.QueryRow("SELECT count(*)"+where, contextRef).Scan(&total) != nil {
		return nil, 0, errors.New("journal_unavailable")
	}
	rows, err := tx.Query("SELECT "+operationColumns+where+" ORDER BY created_at,ref LIMIT 100", contextRef)
	if err != nil {
		return nil, 0, errors.New("journal_unavailable")
	}
	defer rows.Close()
	ops := []operation{}
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, 0, err
		}
		ops = append(ops, op)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, err
	}
	if err = rows.Close(); err != nil {
		return nil, 0, err
	}
	if err = tx.Commit(); err != nil {
		return nil, 0, errors.New("journal_unavailable")
	}
	return ops, total, nil
}
func (j *journal) addArtifact(contextRef, op, mime string, raw []byte, candidate Identity) (artifact, error) {
	digest := sha(raw)
	var ref string
	if j.db.QueryRow("SELECT ref FROM artifacts WHERE context_ref=? AND operation_ref=? AND sha=?", contextRef, op, digest).Scan(&ref) == nil {
		return j.artifact(contextRef, ref)
	}
	var size, count int
	if j.db.QueryRow("SELECT COALESCE(sum(size),0),count(*) FROM artifacts").Scan(&size, &count) != nil || size+len(raw) > 256<<20 || count >= 4096 {
		return artifact{}, errors.New("artifact_capacity_reached")
	}
	ref, err := randomRef("art_")
	if err != nil {
		return artifact{}, err
	}
	a := artifact{ref, contextRef, op, mime, digest, len(raw), time.Now().UTC().Format(time.RFC3339Nano), candidate, raw}
	meta, _ := json.Marshal(candidate)
	_, err = j.db.Exec("INSERT INTO artifacts(ref,context_ref,operation_ref,mime,sha,size,created_at,candidate,content) VALUES (?,?,?,?,?,?,?,?,?)", a.Ref, a.Context, a.Operation, a.MIME, a.SHA256, a.Size, a.CreatedAt, string(meta), raw)
	if err != nil {
		if j.db.QueryRow("SELECT ref FROM artifacts WHERE context_ref=? AND operation_ref=? AND sha=?", contextRef, op, digest).Scan(&ref) == nil {
			return j.artifact(contextRef, ref)
		}
		return artifact{}, errors.New("artifact_persistence_failed")
	}
	return a, nil
}

// Maintenance only expires whole old, settled contexts. Any uncertain,
// unconfirmed or pending operation pins its context and all of its evidence.
// Recent artifacts also pin the context. There is no "clear all" operation.
type Maintenance struct {
	Apply          bool   `json:"apply"`
	Before         string `json:"before"`
	Contexts       int    `json:"contexts"`
	Operations     int    `json:"operations"`
	Artifacts      int    `json:"artifacts"`
	ReclaimedBytes int    `json:"reclaimedBytes"`
}

func (j *journal) maintain(before time.Time, apply bool) (Maintenance, error) {
	r := Maintenance{Apply: apply, Before: before.UTC().Format(time.RFC3339Nano)}
	tx, err := j.db.Begin()
	if err != nil {
		return r, errors.New("maintenance_unavailable")
	}
	defer tx.Rollback()
	eligible := `SELECT c.ref FROM contexts c WHERE datetime(c.created_at)<datetime(?) AND NOT EXISTS (SELECT 1 FROM operations o WHERE o.context_ref=c.ref AND (o.state NOT IN ('completed','captured','blocked','rejected','failed') OR datetime(o.created_at)>=datetime(?))) AND NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.context_ref=c.ref AND datetime(a.created_at)>=datetime(?))`
	args := []any{r.Before, r.Before, r.Before}
	for _, v := range []struct {
		query string
		to    *int
	}{{"SELECT count(*) FROM contexts WHERE ref IN (" + eligible + ")", &r.Contexts}, {"SELECT count(*) FROM operations WHERE context_ref IN (" + eligible + ")", &r.Operations}, {"SELECT count(*) FROM artifacts WHERE context_ref IN (" + eligible + ")", &r.Artifacts}, {"SELECT COALESCE(sum(size),0) FROM artifacts WHERE context_ref IN (" + eligible + ")", &r.ReclaimedBytes}} {
		if tx.QueryRow(v.query, args...).Scan(v.to) != nil {
			return r, errors.New("maintenance_unavailable")
		}
	}
	if apply {
		// Capture the eligible set before deleting dependent rows.
		if _, err = tx.Exec("CREATE TEMP TABLE prune_contexts AS "+eligible, args...); err != nil {
			return r, errors.New("maintenance_unavailable")
		}
		for _, q := range []string{"DELETE FROM artifacts WHERE context_ref IN (SELECT ref FROM prune_contexts)", "DELETE FROM operations WHERE context_ref IN (SELECT ref FROM prune_contexts)", "DELETE FROM contexts WHERE ref IN (SELECT ref FROM prune_contexts)", "DROP TABLE prune_contexts"} {
			if _, err = tx.Exec(q); err != nil {
				return r, errors.New("maintenance_unavailable")
			}
		}
	}
	if tx.Commit() != nil {
		return r, errors.New("maintenance_unavailable")
	}
	return r, nil
}
func (j *journal) artifact(contextRef, ref string) (artifact, error) {
	var a artifact
	var candidate string
	err := j.db.QueryRow("SELECT ref,context_ref,operation_ref,mime,sha,size,created_at,candidate,content FROM artifacts WHERE context_ref=? AND ref=?", contextRef, ref).Scan(&a.Ref, &a.Context, &a.Operation, &a.MIME, &a.SHA256, &a.Size, &a.CreatedAt, &candidate, &a.Content)
	if err != nil {
		return a, errors.New("artifact_not_found")
	}
	if a.Size > maxImage || a.Size != len(a.Content) || sha(a.Content) != a.SHA256 || json.Unmarshal([]byte(candidate), &a.Candidate) != nil {
		return artifact{}, errors.New("artifact_integrity_failure")
	}
	return a, nil
}
