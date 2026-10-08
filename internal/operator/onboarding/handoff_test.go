package onboarding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

func TestHandoffStoreUsesExactProtectedSchemaAndSurvivesRestart(t *testing.T) {
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "protected", "handoffs.db")
	store := openTestHandoffStore(t, path, func() time.Time { return now })
	binding := testHandoffBinding()
	record := testHandoffRecord(binding, "skill_handoff_restart", now.Add(15*time.Minute))
	created, err := store.Begin(context.Background(), record)
	if err != nil || created.OperationID != stableHandoffOperationID(binding, record.HandoffRef) || created.State != HandoffPending {
		t.Fatalf("Begin()=(%+v, %v)", created, err)
	}
	completed, err := store.MarkCompleted(context.Background(), created)
	if err != nil || completed.State != HandoffCompleted {
		t.Fatalf("MarkCompleted()=(%+v, %v)", completed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestHandoffStore(t, path, func() time.Time { return now })
	defer reopened.Close()
	loaded, err := reopened.Resolve(context.Background(), binding, record.HandoffRef)
	if err != nil || loaded.State != HandoffCompleted || loaded.OperationID != created.OperationID || loaded.RecordSHA256 == created.RecordSHA256 {
		t.Fatalf("Resolve(restart)=(%+v, %v)", loaded, err)
	}
	var version, applicationID int
	if err := reopened.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := reopened.db.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		t.Fatal(err)
	}
	if version != handoffDatabaseVersion || applicationID != handoffDatabaseApplicationID {
		t.Fatalf("database identity=(%d, %d)", version, applicationID)
	}
	if err := localstate.ValidateFile(path); err != nil {
		t.Fatalf("handoff file permissions: %v", err)
	}
	columns := handoffColumnNames(t, reopened.db)
	wantColumns := "handoff_ref,tenant_id,site_id,principal_sha256,operation_id,expires_at,state,record_sha256"
	if strings.Join(columns, ",") != wantColumns {
		t.Fatalf("handoff columns=%v", columns)
	}
}

func TestHandoffStoreEnforcesExpiryBindingConflictAndCAS(t *testing.T) {
	now := time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	current := now
	store := openTestHandoffStore(t, filepath.Join(t.TempDir(), "protected", "handoffs.db"), func() time.Time { return current })
	defer store.Close()
	binding := testHandoffBinding()
	record := testHandoffRecord(binding, "skill_handoff_scope", now.Add(10*time.Minute))
	created, err := store.Begin(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	idempotent, err := store.Begin(context.Background(), record)
	if err != nil || idempotent.RecordSHA256 != created.RecordSHA256 {
		t.Fatalf("idempotent Begin()=(%+v, %v)", idempotent, err)
	}

	bindings := []HandoffBinding{
		{TenantID: "tenant-b", SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256},
		{TenantID: binding.TenantID, SiteID: "site-b", PrincipalSHA256: binding.PrincipalSHA256},
		{TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: strings.Repeat("b", 64)},
	}
	for _, wrong := range bindings {
		if _, err := store.Resolve(context.Background(), wrong, record.HandoffRef); !errors.Is(err, ErrBindingMismatch) {
			t.Fatalf("Resolve(cross binding) error=%v", err)
		}
	}
	current = record.ExpiresAt
	if _, err := store.Resolve(context.Background(), binding, record.HandoffRef); !errors.Is(err, ErrHandoffExpired) {
		t.Fatalf("Resolve(expired) error=%v", err)
	}
	current = now
	conflict := record
	conflict.ExpiresAt = conflict.ExpiresAt.Add(time.Minute)
	if _, err := store.Begin(context.Background(), conflict); !errors.Is(err, ErrHandoffConflict) {
		t.Fatalf("Begin(conflict) error=%v", err)
	}
	stale := created
	stale.RecordSHA256 = strings.Repeat("f", 64)
	if _, err := store.MarkCompleted(context.Background(), stale); !errors.Is(err, ErrHandoffConflict) {
		t.Fatalf("MarkCompleted(stale) error=%v", err)
	}
	completed, err := store.MarkCompleted(context.Background(), created)
	if err != nil || completed.State != HandoffCompleted {
		t.Fatalf("MarkCompleted()=(%+v, %v)", completed, err)
	}
	second, err := store.MarkCompleted(context.Background(), created)
	if err != nil || second.RecordSHA256 != completed.RecordSHA256 {
		t.Fatalf("MarkCompleted(idempotent)=(%+v, %v)", second, err)
	}
	if _, err := store.Resolve(context.Background(), binding, "missing_handoff"); !errors.Is(err, ErrHandoffNotFound) {
		t.Fatalf("Resolve(missing) error=%v", err)
	}
}

func TestProtectedHandoffLookupReturnsVerifiedExpiredRecordWithoutProjection(t *testing.T) {
	current := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
	store := openTestHandoffStore(t, filepath.Join(t.TempDir(), "protected", "handoffs.db"), func() time.Time { return current })
	defer store.Close()
	record := testHandoffRecord(testHandoffBinding(), "protected_lookup_expired", current.Add(time.Minute))
	created, err := store.Begin(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(time.Minute)
	lookup, err := store.ResolveProtected(context.Background(), record.HandoffRef)
	if err != nil || !lookup.Expired || lookup.Record.RecordSHA256 != created.RecordSHA256 {
		t.Fatalf("ResolveProtected() expired=%v same=%v err=%v", lookup.Expired, lookup.Record.RecordSHA256 == created.RecordSHA256, err)
	}
	if _, err := json.Marshal(lookup); !errors.Is(err, credential.ErrProtectedProjection) {
		t.Fatalf("Marshal(ProtectedHandoffLookup) error=%v", err)
	}
	if _, err := store.ResolveProtected(context.Background(), " protected_lookup_expired"); !errors.Is(err, ErrInvalidHandoff) {
		t.Fatalf("ResolveProtected(non-canonical) error=%v", err)
	}
}

func TestHandoffStoreRejectsUnknownSchemaAndTamperingWithoutMigration(t *testing.T) {
	t.Run("unprotected file", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "protected")
		if err := localstate.PrepareStateRoot(root); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "loose.db")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenHandoffStore(HandoffStoreConfig{Path: path}); err == nil {
			t.Fatal("unprotected handoff file was accepted")
		}
	})

	t.Run("unknown schema", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "protected")
		if err := localstate.PrepareStateRoot(root); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "legacy.db")
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`CREATE TABLE legacy_handoffs(value TEXT); PRAGMA user_version=1; PRAGMA application_id=1128613967`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if err := localstate.ProtectFile(path); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenHandoffStore(HandoffStoreConfig{Path: path}); !errors.Is(err, ErrUnsupportedHandoffStore) {
			t.Fatalf("OpenHandoffStore(legacy) error=%v", err)
		}
	})

	t.Run("schema change", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "protected", "changed.db")
		store := openTestHandoffStore(t, path, time.Now)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`ALTER TABLE onboarding_handoffs ADD COLUMN legacy_value TEXT`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenHandoffStore(HandoffStoreConfig{Path: path}); !errors.Is(err, ErrUnsupportedHandoffStore) {
			t.Fatalf("OpenHandoffStore(changed schema) error=%v", err)
		}
	})

	t.Run("record change", func(t *testing.T) {
		now := time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)
		path := filepath.Join(t.TempDir(), "protected", "tampered.db")
		store := openTestHandoffStore(t, path, func() time.Time { return now })
		binding := testHandoffBinding()
		if _, err := store.Begin(context.Background(), testHandoffRecord(binding, "skill_handoff_tamper", now.Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE onboarding_handoffs SET site_id='site-tampered'`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenHandoffStore(HandoffStoreConfig{Path: path, Now: func() time.Time { return now }}); !errors.Is(err, ErrHandoffIntegrity) {
			t.Fatalf("OpenHandoffStore(tampered record) error=%v", err)
		}
	})
}

func TestHandoffStoreConcurrentIdempotentBegin(t *testing.T) {
	now := time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)
	store := openTestHandoffStore(t, filepath.Join(t.TempDir(), "protected", "concurrent.db"), func() time.Time { return now })
	defer store.Close()
	record := testHandoffRecord(testHandoffBinding(), "skill_handoff_concurrent", now.Add(time.Hour))
	const workers = 24
	results := make(chan HandoffRecord, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			created, err := store.Begin(context.Background(), record)
			if err != nil {
				errorsFound <- err
				return
			}
			results <- created
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent Begin() error=%v", err)
	}
	wantOperation := stableHandoffOperationID(testHandoffBinding(), record.HandoffRef)
	count := 0
	for created := range results {
		count++
		if created.OperationID != wantOperation || created.State != HandoffPending {
			t.Fatalf("concurrent record=%+v", created)
		}
	}
	if count != workers {
		t.Fatalf("concurrent results=%d want=%d", count, workers)
	}
}

func TestHandoffStoreRecoveryReadIsProtectedBoundedKeysetOrderedAndIncludesExpired(t *testing.T) {
	now := time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC)
	current := now
	store := openTestHandoffStore(t, filepath.Join(t.TempDir(), "protected", "recovery.db"), func() time.Time { return current })
	defer store.Close()
	binding := testHandoffBinding()
	for _, ref := range []string{"skill_recovery_z", "skill_recovery_a", "skill_recovery_m"} {
		if _, err := store.Begin(context.Background(), testHandoffRecord(binding, ref, now.Add(time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	current = now.Add(2 * time.Minute)
	if _, err := store.Resolve(context.Background(), binding, "skill_recovery_a"); !errors.Is(err, ErrHandoffExpired) {
		t.Fatalf("Resolve(expired) error=%v", err)
	}
	first, err := store.PendingForRecovery(context.Background(), "", 2)
	if err != nil || len(first) != 2 || first[0].HandoffRef != "skill_recovery_a" || first[1].HandoffRef != "skill_recovery_m" {
		t.Fatalf("PendingForRecovery(first)=%+v err=%v", first, err)
	}
	for _, record := range first {
		if record.State != HandoffPending || record.ExpiresAt.After(current) || record.TenantID != binding.TenantID ||
			record.SiteID != binding.SiteID || record.PrincipalSHA256 != binding.PrincipalSHA256 {
			t.Fatalf("recovery record=%+v", record)
		}
	}
	second, err := store.PendingForRecovery(context.Background(), first[len(first)-1].HandoffRef, 2)
	if err != nil || len(second) != 1 || second[0].HandoffRef != "skill_recovery_z" {
		t.Fatalf("PendingForRecovery(second)=%+v err=%v", second, err)
	}
	if tail, err := store.PendingForRecovery(context.Background(), second[0].HandoffRef, 2); err != nil || len(tail) != 0 {
		t.Fatalf("PendingForRecovery(tail)=%+v err=%v", tail, err)
	}
	for _, request := range []struct {
		after string
		limit int
	}{{limit: 0}, {limit: -1}, {limit: MaximumHandoffRecoveryBatch + 1}, {after: "invalid cursor", limit: 1}} {
		if _, err := store.PendingForRecovery(context.Background(), request.after, request.limit); !errors.Is(err, ErrInvalidHandoff) {
			t.Fatalf("PendingForRecovery(%q, %d) error=%v", request.after, request.limit, err)
		}
	}
	if _, err := json.Marshal(first); !errors.Is(err, credential.ErrProtectedProjection) {
		t.Fatalf("recovery page projection error=%v", err)
	}
	if _, err := store.MarkCompleted(context.Background(), first[1]); err != nil {
		t.Fatal(err)
	}
	remaining, err := store.PendingForRecovery(context.Background(), "", MaximumHandoffRecoveryBatch)
	if err != nil || len(remaining) != 2 || remaining[0].HandoffRef != "skill_recovery_a" || remaining[1].HandoffRef != "skill_recovery_z" {
		t.Fatalf("PendingForRecovery(after completion)=%+v err=%v", remaining, err)
	}
}

func TestHandoffStoreRecoveryReadRejectsRecordTampering(t *testing.T) {
	now := time.Date(2026, 7, 20, 2, 30, 0, 0, time.UTC)
	store := openTestHandoffStore(t, filepath.Join(t.TempDir(), "protected", "recovery-tamper.db"), func() time.Time { return now })
	defer store.Close()
	if _, err := store.Begin(context.Background(), testHandoffRecord(testHandoffBinding(), "skill_recovery_tamper", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE onboarding_handoffs SET principal_sha256=? WHERE handoff_ref=?`, strings.Repeat("b", 64), "skill_recovery_tamper"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PendingForRecovery(context.Background(), "", 1); !errors.Is(err, ErrHandoffIntegrity) {
		t.Fatalf("PendingForRecovery(tampered) error=%v", err)
	}
}

func openTestHandoffStore(t *testing.T, path string, now func() time.Time) *HandoffStore {
	t.Helper()
	store, err := OpenHandoffStore(HandoffStoreConfig{Path: path, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testHandoffBinding() HandoffBinding {
	return HandoffBinding{TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("a", 64)}
}

func testHandoffRecord(binding HandoffBinding, ref string, expiresAt time.Time) HandoffRecord {
	return HandoffRecord{
		HandoffRef: ref, TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		OperationID: stableHandoffOperationID(binding, ref), ExpiresAt: expiresAt.UTC(), State: HandoffPending,
	}
}

func handoffColumnNames(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.Query(`PRAGMA table_info(onboarding_handoffs)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}
