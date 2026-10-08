package ledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

func nativeRejectionDiagnostic() *safediagnostic.Diagnostic {
	code := 0
	return &safediagnostic.Diagnostic{Operation: safediagnostic.OperationTaskSwitch, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassNativeRejected, HTTPStatus: 200, ResCode: &code, MsgCode: "12314"}
}

func TestV1MigrationPreservesRowsAndHashesThenDiagnosticSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := protectedTestPath(t)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// schema is the deployed v1 schema, before the nullable diagnostic migration.
	if _, err = db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 7, 1, 0, 0, 0, time.UTC)
	if _, err = db.Exec(`INSERT INTO operator_schema_migrations VALUES(1, ?)`, formatTime(now)); err != nil {
		t.Fatal(err)
	}
	old := &Store{db: db}
	claimAction(t, old, "legacy", now)
	if err = old.MarkDispatch(ctx, "legacy", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE dispatches SET state='verifying',outcome='accepted',device_write_count=1,finished_at=? WHERE action_id='legacy'`, formatTime(now.Add(4*time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE actions SET state='verifying' WHERE id='legacy'`); err != nil {
		t.Fatal(err)
	}
	if err = old.Finish(ctx, "legacy", result.Trusted{Class: result.Completed, EvidenceStatus: result.EvidenceSealed, Conclusion: "Existing verified result.", Reason: "fresh_read_matches_target", EvidenceJSON: `{"configurationDigest":"` + resourceA + `"}`, ObservedAt: now.Add(5 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	before := legacyRowsHash(t, db)
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t, path)
	if after := legacyRowsHash(t, store.db); after != before {
		t.Fatal("migration rewrote existing rows, digests, counters or timestamps")
	}
	record, err := store.Inspect(ctx, "legacy")
	if err != nil || record.Diagnostic != nil || record.Dispatches != 1 || record.DeviceWrites != 1 || record.SessionBinding != bindingA || record.ResourceKey != resourceA {
		t.Fatalf("legacy record=%+v err=%v", record, err)
	}
	var migrations int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM operator_schema_migrations WHERE version IN (1,2)`).Scan(&migrations); err != nil || migrations != 2 {
		t.Fatalf("migration count=%d err=%v", migrations, err)
	}
	claimAction(t, store, "new-rejection", now.Add(time.Minute))
	if err = store.MarkDispatch(ctx, "new-rejection", now.Add(time.Minute+3*time.Second)); err != nil {
		t.Fatal(err)
	}
	diagnostic := nativeRejectionDiagnostic()
	if err = store.RecordDispatch(ctx, "new-rejection", DispatchObservation{Outcome: "known_failed", DeviceWriteCount: 0, FinishedAt: now.Add(time.Minute + 4*time.Second), Diagnostic: diagnostic}); err != nil {
		t.Fatal(err)
	}
	// Simulate restart between the atomic dispatch record and Verify.
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	record, err = store.Inspect(ctx, "new-rejection")
	if err != nil || record.State != "verifying" || record.DispatchOutcome != "known_failed" || record.Dispatches != 1 || record.DeviceWrites != 0 || !reflect.DeepEqual(record.Diagnostic, diagnostic) {
		t.Fatalf("reopened dispatch=%+v err=%v", record, err)
	}
	if err = store.RecoverInterrupted(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = store.RecoverInterrupted(ctx, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	record, err = store.Inspect(ctx, "new-rejection")
	if err != nil || record.State != "unknown" || record.Dispatches != 1 || record.DeviceWrites != 0 || !reflect.DeepEqual(record.Diagnostic, diagnostic) {
		t.Fatalf("recovery lost diagnostic or accounting: %+v err=%v", record, err)
	}
	if _, ok, err := store.ClaimNext(ctx, now.Add(4*time.Minute)); err != nil || ok {
		t.Fatalf("replayed recovered dispatch: ok=%v err=%v", ok, err)
	}
	var attempts, evidence int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM dispatches WHERE action_id='new-rejection'`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM evidence WHERE action_id='new-rejection'`).Scan(&evidence); err != nil || attempts != 1 || evidence != 1 {
		t.Fatalf("attempts=%d evidence=%d err=%v", attempts, evidence, err)
	}
}

// Hash logical legacy rows, not SQLite file bytes: adding a column necessarily changes the file.
func legacyRowsHash(t *testing.T, db *sql.DB) [32]byte {
	t.Helper()
	var all [][][]any
	for _, query := range []string{
		`SELECT * FROM actions ORDER BY id`,
		`SELECT action_id,attempt_no,state,outcome,dispatch_count,device_write_count,started_at,finished_at FROM dispatches ORDER BY action_id`,
		`SELECT * FROM action_events ORDER BY sequence`, `SELECT * FROM evidence ORDER BY action_id`,
		`SELECT * FROM worker_leases ORDER BY name`, `SELECT * FROM operator_schema_migrations WHERE version=1`,
	} {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var table [][]any
		for rows.Next() {
			values := make([]any, len(columns))
			targets := make([]any, len(columns))
			for i := range values {
				targets[i] = &values[i]
			}
			if err = rows.Scan(targets...); err != nil {
				t.Fatal(err)
			}
			table = append(table, values)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err = rows.Close(); err != nil {
			t.Fatal(err)
		}
		all = append(all, table)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(raw)
}

func TestInvalidDiagnosticCannotPartiallyRecordDispatch(t *testing.T) {
	store := openTestStore(t, protectedTestPath(t))
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	claimAction(t, store, "invalid-diagnostic", now)
	if err := store.MarkDispatch(ctx, "invalid-diagnostic", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	diagnostic := nativeRejectionDiagnostic()
	diagnostic.MsgCode = "rtsp://private.invalid/secret"
	err := store.RecordDispatch(ctx, "invalid-diagnostic", DispatchObservation{Outcome: "known_failed", FinishedAt: now.Add(4 * time.Second), Diagnostic: diagnostic})
	if !errors.Is(err, safediagnostic.ErrInvalidDiagnostic) {
		t.Fatalf("invalid diagnostic error=%v", err)
	}
	record, err := store.Inspect(ctx, "invalid-diagnostic")
	if err != nil || record.State != "dispatching" || record.DispatchOutcome != "" || record.Dispatches != 1 || record.Diagnostic != nil {
		t.Fatalf("partial record=%+v err=%v", record, err)
	}
	var updates int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM action_events WHERE action_id='invalid-diagnostic' AND event_type='verifying'`).Scan(&updates); err != nil || updates != 0 {
		t.Fatalf("partial events=%d err=%v", updates, err)
	}
}
