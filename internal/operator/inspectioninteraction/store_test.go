package inspectioninteraction

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

const createV2PendingInteractionsSQL = `CREATE TABLE pending_inspection_interactions (
    handoff_ref TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL,
    interaction_type TEXT NOT NULL CHECK(interaction_type = 'persistent_change'),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN ('source_create', 'source_update', 'source_delete', 'task_deploy', 'task_update', 'task_enable', 'task_disable', 'device_schedule_update')),
    source_ref TEXT NOT NULL,
    task_ref TEXT NOT NULL,
    observable_ref TEXT NOT NULL,
    expected_source_revision INTEGER NOT NULL CHECK(expected_source_revision >= 0),
    expected_task_revision INTEGER NOT NULL CHECK(expected_task_revision >= 0),
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state = 'pending'),
    record_sha256 TEXT NOT NULL
) WITHOUT ROWID`

func TestStorePersistsExactV3TransferStateAndSurvivesRestart(t *testing.T) {
	now := time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "protected", "interactions.db")
	store := openTestStore(t, path, func() time.Time { return now })
	record := testRecord("handoff_restart", now.Add(15*time.Minute))
	created, err := store.Register(context.Background(), record)
	if err != nil || created.RecordSHA256 == "" || created.State != StatePending {
		t.Fatalf("Register() state=%q digest=%q err=%v", created.State, created.RecordSHA256, err)
	}
	idempotent, err := store.Register(context.Background(), record)
	if err != nil || !sameRecord(idempotent, created) {
		t.Fatalf("Register(replay) same=%t err=%v", sameRecord(idempotent, created), err)
	}
	prepared, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, "proposal_restart")
	if err != nil || prepared.State != StateTransferPrepared || prepared.ProposalRef != "proposal_restart" ||
		prepared.RecordSHA256 == created.RecordSHA256 {
		t.Fatalf("PrepareTransfer() state=%q proposal=%q digestChanged=%t err=%v",
			prepared.State, prepared.ProposalRef, prepared.RecordSHA256 != created.RecordSHA256, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, path, func() time.Time { return now })
	loaded, err := reopened.Resolve(context.Background(), testBinding(), record.HandoffRef)
	if err != nil || !sameRecord(loaded, prepared) {
		t.Fatalf("Resolve(restart) same=%t err=%v", sameRecord(loaded, prepared), err)
	}
	replayedRegistration, err := reopened.Register(context.Background(), record)
	if err != nil || !sameRecord(replayedRegistration, prepared) {
		t.Fatalf("Register(after preparation) same=%t err=%v", sameRecord(replayedRegistration, prepared), err)
	}
	transferred, err := reopened.MarkTransferred(context.Background(), testBinding(), record.HandoffRef, "proposal_restart")
	if err != nil || transferred.State != StateTransferred || transferred.ProposalRef != prepared.ProposalRef ||
		transferred.RecordSHA256 == prepared.RecordSHA256 {
		t.Fatalf("MarkTransferred() state=%q proposal=%q digestChanged=%t err=%v",
			transferred.State, transferred.ProposalRef, transferred.RecordSHA256 != prepared.RecordSHA256, err)
	}
	var version, applicationID int
	if err := reopened.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := reopened.db.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		t.Fatal(err)
	}
	if version != 3 || applicationID != storeApplicationID || !strings.Contains(recordDigestDomain, ".v3\x00") {
		t.Fatalf("store identity version=%d applicationID=%d domain=%q", version, applicationID, recordDigestDomain)
	}
	if err := localstate.ValidateFile(path); err != nil {
		t.Fatalf("store is not private: %v", err)
	}
	if err := localstate.ValidateStateRoot(filepath.Dir(path)); err != nil {
		t.Fatalf("store root is not private: %v", err)
	}
	columns := storeColumnNames(t, reopened.db)
	want := "handoff_ref,tenant_id,site_id,principal_sha256,interaction_type,operation_kind,source_ref,task_ref,observable_ref,expected_source_revision,expected_task_revision,expires_at,proposal_ref,state,record_sha256"
	if strings.Join(columns, ",") != want {
		t.Fatalf("store columns=%v", columns)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	final := openTestStore(t, path, func() time.Time { return now })
	defer final.Close()
	loaded, err = final.Resolve(context.Background(), testBinding(), record.HandoffRef)
	if err != nil || !sameRecord(loaded, transferred) {
		t.Fatalf("Resolve(transferred restart) same=%t err=%v", sameRecord(loaded, transferred), err)
	}
	replayedTerminal, err := final.MarkTransferred(context.Background(), testBinding(), record.HandoffRef, "proposal_restart")
	if err != nil || !sameRecord(replayedTerminal, transferred) {
		t.Fatalf("MarkTransferred(unknown outcome restart) same=%t err=%v", sameRecord(replayedTerminal, transferred), err)
	}
}

func TestProtectedLookupReturnsVerifiedExpiredRecordWithoutProjection(t *testing.T) {
	current := time.Date(2026, 7, 19, 20, 30, 0, 0, time.UTC)
	store := openTestStore(t, filepath.Join(t.TempDir(), "protected", "interactions.db"), func() time.Time { return current })
	defer store.Close()
	record := testRecord("protected_lookup_expired", current.Add(time.Minute))
	created, err := store.Register(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(time.Minute)
	lookup, err := store.ResolveProtected(context.Background(), record.HandoffRef)
	if err != nil || !lookup.Expired || lookup.Record.RecordSHA256 != created.RecordSHA256 {
		t.Fatalf("ResolveProtected() expired=%v same=%v err=%v", lookup.Expired, lookup.Record.RecordSHA256 == created.RecordSHA256, err)
	}
	if _, err := json.Marshal(lookup); !errors.Is(err, credential.ErrProtectedProjection) {
		t.Fatalf("Marshal(ProtectedLookup) error=%v", err)
	}
	if _, err := store.ResolveProtected(context.Background(), " protected_lookup_expired"); !errors.Is(err, ErrInvalidRegistration) {
		t.Fatalf("ResolveProtected(non-canonical) error=%v", err)
	}
}

func TestStoreAcceptsOnlyClosedNormalizedPendingChangeShapes(t *testing.T) {
	now := time.Date(2026, 7, 19, 20, 30, 0, 0, time.UTC)
	store := openTestStore(t, filepath.Join(t.TempDir(), "protected", "closed.db"), func() time.Time { return now })
	defer store.Close()
	cases := []planning.PendingChangeIntent{
		{Operation: planning.PendingSourceCreate},
		{Operation: planning.PendingSourceUpdate, SourceRef: "source-a", ExpectedSourceRevision: 2},
		{Operation: planning.PendingSourceDelete, SourceRef: "source-a", ExpectedSourceRevision: 2},
		{Operation: planning.PendingTaskDeploy, SourceRef: "source-a", ExpectedSourceRevision: 2, ObservableRef: "observable-a"},
		{Operation: planning.PendingTaskUpdate, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3, ObservableRef: "observable-a"},
		{Operation: planning.PendingTaskEnable, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3},
		{Operation: planning.PendingTaskDisable, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3},
		{Operation: planning.PendingDeviceScheduleUpdate, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3},
	}
	for index, change := range cases {
		record := recordForChange(fmt.Sprintf("handoff_closed_%d", index), now.Add(time.Hour), change)
		if _, err := store.Register(context.Background(), record); err != nil {
			t.Fatalf("Register(%s) error=%v", change.Operation, err)
		}
	}
	invalid := []planning.PendingChangeIntent{
		{},
		{Operation: planning.PendingSourceCreate, SourceRef: "source-a", ExpectedSourceRevision: 1},
		{Operation: planning.PendingSourceUpdate, SourceRef: "source-a"},
		{Operation: planning.PendingTaskDeploy, SourceRef: "source-a", ExpectedSourceRevision: 1},
		{Operation: planning.PendingTaskUpdate, SourceRef: "source-a", ExpectedSourceRevision: 1, TaskRef: "task-a", ExpectedTaskRevision: 1},
		{Operation: planning.PendingTaskEnable, SourceRef: "source-a", ExpectedSourceRevision: 1, TaskRef: "task-a", ExpectedTaskRevision: 1, ObservableRef: "forbidden"},
	}
	for index, change := range invalid {
		record := recordForChange(fmt.Sprintf("handoff_invalid_%d", index), now.Add(time.Hour), change)
		if _, err := store.Register(context.Background(), record); !errors.Is(err, ErrInvalidRegistration) {
			t.Fatalf("Register(invalid %d) error=%v", index, err)
		}
	}
}

func TestStoreEnforcesConflictExpiryScopeAndConcurrentReplay(t *testing.T) {
	now := time.Date(2026, 7, 19, 21, 0, 0, 0, time.UTC)
	current := now
	store := openTestStore(t, filepath.Join(t.TempDir(), "protected", "bindings.db"), func() time.Time { return current })
	defer store.Close()
	record := testRecord("handoff_bound", now.Add(10*time.Minute))
	if _, err := store.Register(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	for _, binding := range []Binding{
		{TenantID: "tenant-b", SiteID: "site-a", PrincipalSHA256: strings.Repeat("a", 64)},
		{TenantID: "tenant-a", SiteID: "site-b", PrincipalSHA256: strings.Repeat("a", 64)},
		{TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("b", 64)},
	} {
		if _, err := store.Resolve(context.Background(), binding, record.HandoffRef); !errors.Is(err, ErrScopeMismatch) {
			t.Fatalf("Resolve(cross scope) error=%v", err)
		}
	}
	conflict := record
	conflict.ExpectedTaskRevision++
	if _, err := store.Register(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("Register(conflict) error=%v", err)
	}

	const workers = 20
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := store.Register(context.Background(), record); err != nil {
				errorsFound <- err
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("Register(concurrent replay) error=%v", err)
	}
	current = record.ExpiresAt
	if _, err := store.Resolve(context.Background(), testBinding(), record.HandoffRef); !errors.Is(err, ErrExpired) {
		t.Fatalf("Resolve(expired) error=%v", err)
	}
	if _, err := store.Register(context.Background(), record); !errors.Is(err, ErrExpired) {
		t.Fatalf("Register(expired replay) error=%v", err)
	}
	if _, err := store.Resolve(context.Background(), testBinding(), "handoff_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Resolve(missing) error=%v", err)
	}
}

func TestTransferStateMachineRequiresExactProtectedBindingAndProposal(t *testing.T) {
	now := time.Date(2026, 7, 19, 21, 30, 0, 0, time.UTC)
	store := openTestStore(t, filepath.Join(t.TempDir(), "protected", "transfer.db"), func() time.Time { return now })
	defer store.Close()
	record := testRecord("handoff_transfer", now.Add(time.Hour))
	for _, illegal := range []Record{
		func() Record {
			value := record
			value.State = StateTransferPrepared
			value.ProposalRef = "proposal_injected"
			return value
		}(),
		func() Record {
			value := record
			value.State = StateTransferred
			value.ProposalRef = "proposal_injected"
			return value
		}(),
		func() Record { value := record; value.ProposalRef = "proposal_injected"; return value }(),
		func() Record { value := record; value.State = State("unknown"); return value }(),
	} {
		if _, err := store.Register(context.Background(), illegal); !errors.Is(err, ErrInvalidRegistration) {
			t.Fatalf("Register(illegal state=%q proposal=%q) error=%v", illegal.State, illegal.ProposalRef, err)
		}
	}
	if _, err := store.Register(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	if _, err := store.MarkTransferred(context.Background(), testBinding(), record.HandoffRef, "proposal_exact"); !errors.Is(err, ErrTransferNotPrepared) {
		t.Fatalf("MarkTransferred(pending) error=%v", err)
	}
	wrongBinding := testBinding()
	wrongBinding.SiteID = "site-b"
	if _, err := store.PrepareTransfer(context.Background(), wrongBinding, record.HandoffRef, "proposal_exact"); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("PrepareTransfer(wrong binding) error=%v", err)
	}
	for _, invalid := range []string{"", " proposal_exact", "proposal_exact ", "proposal/exact"} {
		if _, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, invalid); !errors.Is(err, ErrInvalidRegistration) {
			t.Fatalf("PrepareTransfer(invalid %q) error=%v", invalid, err)
		}
	}

	prepared, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, "proposal_exact")
	if err != nil || prepared.State != StateTransferPrepared || prepared.ProposalRef != "proposal_exact" {
		t.Fatalf("PrepareTransfer() state=%q proposal=%q err=%v", prepared.State, prepared.ProposalRef, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		replayed, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, "proposal_exact")
		if err != nil || !sameRecord(replayed, prepared) {
			t.Fatalf("PrepareTransfer(replay %d) same=%t err=%v", attempt, sameRecord(replayed, prepared), err)
		}
	}
	if _, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, "proposal_other"); !errors.Is(err, ErrConflict) {
		t.Fatalf("PrepareTransfer(other proposal) error=%v", err)
	}
	if _, err := store.MarkTransferred(context.Background(), testBinding(), record.HandoffRef, "proposal_other"); !errors.Is(err, ErrConflict) {
		t.Fatalf("MarkTransferred(other proposal) error=%v", err)
	}

	transferred, err := store.MarkTransferred(context.Background(), testBinding(), record.HandoffRef, "proposal_exact")
	if err != nil || transferred.State != StateTransferred || transferred.ProposalRef != "proposal_exact" {
		t.Fatalf("MarkTransferred() state=%q proposal=%q err=%v", transferred.State, transferred.ProposalRef, err)
	}
	for _, replay := range []func(context.Context, Binding, string, string) (Record, error){
		store.MarkTransferred,
		store.PrepareTransfer,
	} {
		got, err := replay(context.Background(), testBinding(), record.HandoffRef, "proposal_exact")
		if err != nil || !sameRecord(got, transferred) {
			t.Fatalf("terminal replay same=%t err=%v", sameRecord(got, transferred), err)
		}
	}
	for _, replay := range []func(context.Context, Binding, string, string) (Record, error){
		store.MarkTransferred,
		store.PrepareTransfer,
	} {
		if _, err := replay(context.Background(), testBinding(), record.HandoffRef, "proposal_other"); !errors.Is(err, ErrConflict) {
			t.Fatalf("terminal other proposal error=%v", err)
		}
	}
}

func TestTransferConvergesAcrossConcurrentReplayAndUnknownOutcomeRestart(t *testing.T) {
	now := time.Date(2026, 7, 19, 21, 45, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "protected", "replay.db")
	store := openTestStore(t, path, func() time.Time { return now })
	record := testRecord("handoff_replay", now.Add(time.Hour))
	if _, err := store.Register(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	const workers = 24
	type result struct {
		proposal string
		record   Record
		err      error
	}
	results := make(chan result, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		proposal := "proposal_alpha"
		if index%2 == 1 {
			proposal = "proposal_beta"
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, proposal)
			results <- result{proposal: proposal, record: got, err: err}
		}()
	}
	wait.Wait()
	close(results)
	prepared, err := store.Resolve(context.Background(), testBinding(), record.HandoffRef)
	if err != nil || prepared.State != StateTransferPrepared {
		t.Fatalf("Resolve(prepared) state=%q err=%v", prepared.State, err)
	}
	conflicts := 0
	for result := range results {
		if result.proposal == prepared.ProposalRef {
			if result.err != nil || !sameRecord(result.record, prepared) {
				t.Fatalf("winning replay proposal=%q same=%t err=%v", result.proposal, sameRecord(result.record, prepared), result.err)
			}
		} else if !errors.Is(result.err, ErrConflict) {
			t.Fatalf("losing replay proposal=%q error=%v", result.proposal, result.err)
		} else {
			conflicts++
		}
	}
	if conflicts == 0 {
		t.Fatal("competing proposal did not conflict")
	}

	// Simulate a lost response after preparation: close and reopen without
	// marking, then replay the exact proposal before completing the transfer.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path, func() time.Time { return now })
	defer reopened.Close()
	replayed, err := reopened.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, prepared.ProposalRef)
	if err != nil || !sameRecord(replayed, prepared) {
		t.Fatalf("PrepareTransfer(unknown outcome replay) same=%t err=%v", sameRecord(replayed, prepared), err)
	}

	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := reopened.MarkTransferred(context.Background(), testBinding(), record.HandoffRef, prepared.ProposalRef)
			if err != nil {
				errorsFound <- err
				return
			}
			if got.State != StateTransferred || got.ProposalRef != prepared.ProposalRef {
				errorsFound <- fmt.Errorf("unexpected terminal state %q proposal %q", got.State, got.ProposalRef)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("MarkTransferred(concurrent replay) error=%v", err)
	}
}

func TestTransferExpiryBoundaryAllowsOnlyPreparedProposalToConverge(t *testing.T) {
	now := time.Date(2026, 7, 19, 21, 55, 0, 0, time.UTC)
	current := now
	store := openTestStore(t, filepath.Join(t.TempDir(), "protected", "expiry.db"), func() time.Time { return current })
	defer store.Close()
	expiresAt := now.Add(time.Minute)
	preparedRecord := testRecord("handoff_expiry_prepared", expiresAt)
	pendingRecord := testRecord("handoff_expiry_pending", expiresAt)
	for _, record := range []Record{preparedRecord, pendingRecord} {
		if _, err := store.Register(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	current = expiresAt.Add(-time.Nanosecond)
	prepared, err := store.PrepareTransfer(context.Background(), testBinding(), preparedRecord.HandoffRef, "proposal_expiry")
	if err != nil || prepared.State != StateTransferPrepared {
		t.Fatalf("PrepareTransfer(before expiry) state=%q err=%v", prepared.State, err)
	}

	current = expiresAt
	if _, err := store.Resolve(context.Background(), testBinding(), preparedRecord.HandoffRef); !errors.Is(err, ErrExpired) {
		t.Fatalf("Resolve(at expiry) error=%v", err)
	}
	if _, err := store.PrepareTransfer(context.Background(), testBinding(), pendingRecord.HandoffRef, "proposal_late"); !errors.Is(err, ErrExpired) {
		t.Fatalf("PrepareTransfer(new at expiry) error=%v", err)
	}
	if _, err := store.PrepareTransfer(context.Background(), testBinding(), preparedRecord.HandoffRef, "proposal_other"); !errors.Is(err, ErrConflict) {
		t.Fatalf("PrepareTransfer(other after expiry) error=%v", err)
	}
	replayed, err := store.PrepareTransfer(context.Background(), testBinding(), preparedRecord.HandoffRef, "proposal_expiry")
	if err != nil || !sameRecord(replayed, prepared) {
		t.Fatalf("PrepareTransfer(exact after expiry) same=%t err=%v", sameRecord(replayed, prepared), err)
	}
	transferred, err := store.MarkTransferred(context.Background(), testBinding(), preparedRecord.HandoffRef, "proposal_expiry")
	if err != nil || transferred.State != StateTransferred {
		t.Fatalf("MarkTransferred(after expiry) state=%q err=%v", transferred.State, err)
	}
	for _, replay := range []func(context.Context, Binding, string, string) (Record, error){
		store.PrepareTransfer,
		store.MarkTransferred,
	} {
		got, err := replay(context.Background(), testBinding(), preparedRecord.HandoffRef, "proposal_expiry")
		if err != nil || !sameRecord(got, transferred) {
			t.Fatalf("terminal replay after expiry same=%t err=%v", sameRecord(got, transferred), err)
		}
	}
}

func TestStoreRejectsSchemaAndRecordTamperingWithoutCompatibility(t *testing.T) {
	t.Run("unprotected", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "protected")
		if err := localstate.PrepareStateRoot(root); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "loose.db")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(StoreConfig{Path: path}); err == nil {
			t.Fatal("unprotected store was accepted")
		}
	})

	t.Run("v2 exact shape", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "protected")
		if err := localstate.PrepareStateRoot(root); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "older.db")
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(createV2PendingInteractionsSQL + fmt.Sprintf(`; PRAGMA application_id=%d; PRAGMA user_version=2`, storeApplicationID)); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if err := localstate.ProtectFile(path); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(StoreConfig{Path: path}); !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("OpenStore(v2) error=%v", err)
		}
	})

	t.Run("altered schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "protected", "altered.db")
		store := openTestStore(t, path, time.Now)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`ALTER TABLE pending_inspection_interactions ADD COLUMN compatibility_value TEXT`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(StoreConfig{Path: path}); !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("OpenStore(altered) error=%v", err)
		}
	})

	t.Run("record digest", func(t *testing.T) {
		now := time.Date(2026, 7, 19, 22, 0, 0, 0, time.UTC)
		path := filepath.Join(t.TempDir(), "protected", "tampered.db")
		store := openTestStore(t, path, func() time.Time { return now })
		if _, err := store.Register(context.Background(), testRecord("handoff_tampered", now.Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE pending_inspection_interactions SET source_ref='source-tampered'`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(StoreConfig{Path: path, Now: func() time.Time { return now }}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("OpenStore(tampered) error=%v", err)
		}
	})

	t.Run("proposal digest", func(t *testing.T) {
		now := time.Date(2026, 7, 19, 22, 15, 0, 0, time.UTC)
		path := filepath.Join(t.TempDir(), "protected", "proposal-tampered.db")
		store := openTestStore(t, path, func() time.Time { return now })
		record := testRecord("handoff_proposal_tampered", now.Add(time.Hour))
		if _, err := store.Register(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, "proposal_original"); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE pending_inspection_interactions SET proposal_ref='proposal_tampered'`); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(StoreConfig{Path: path, Now: func() time.Time { return now }}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("OpenStore(proposal tampered) error=%v", err)
		}
	})

	t.Run("illegal state relationship", func(t *testing.T) {
		now := time.Date(2026, 7, 19, 22, 30, 0, 0, time.UTC)
		path := filepath.Join(t.TempDir(), "protected", "illegal-state.db")
		store := openTestStore(t, path, func() time.Time { return now })
		record := testRecord("handoff_illegal_state", now.Add(time.Hour))
		if _, err := store.Register(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		prepared, err := store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, "proposal_illegal")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		prepared.State = StatePending
		prepared.RecordSHA256 = recordDigest(prepared)
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`PRAGMA ignore_check_constraints=ON`); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE pending_inspection_interactions SET state=?, record_sha256=?`, prepared.State, prepared.RecordSHA256); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(StoreConfig{Path: path, Now: func() time.Time { return now }}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("OpenStore(illegal state) error=%v", err)
		}
	})
}

func TestTransferRecordHasNoGrantSecretNativeIdentityOrPublicProjection(t *testing.T) {
	recordType := reflect.TypeOf(Record{})
	for index := 0; index < recordType.NumField(); index++ {
		name := strings.ToLower(recordType.Field(index).Name)
		for _, forbidden := range []string{"grant", "authority", "secret", "password", "endpoint", "native", "command", "confirmation", "dispatch", "desired", "value"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Record contains forbidden field %q", recordType.Field(index).Name)
			}
		}
	}
	now := time.Date(2026, 7, 19, 23, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "protected", "projection.db")
	store := openTestStore(t, path, func() time.Time { return now })
	defer store.Close()
	record, err := store.Register(context.Background(), testRecord("handoff_projection", now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	record, err = store.PrepareTransfer(context.Background(), testBinding(), record.HandoffRef, "proposal_projection")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(record); !errors.Is(err, credential.ErrProtectedProjection) {
		t.Fatalf("Record projection error=%v", err)
	}
	projected := fmt.Sprintf("%+v %#v", record, record)
	var output bytes.Buffer
	slog.New(slog.NewJSONHandler(&output, nil)).Info("record", slog.Any("value", record))
	projected += output.String()
	for _, protected := range []string{"tenant-a", "source-opaque", "task-opaque", "observable-opaque", "proposal_projection"} {
		if strings.Contains(projected, protected) {
			t.Fatalf("projection leaked %q: %s", protected, projected)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-password-sentinel", "rtsp://native-camera", "native-device-id", "persistent-device-write-grant", "desired-enabled-value"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("store contains forbidden material %q", forbidden)
		}
	}
}

func openTestStore(t *testing.T, path string, now func() time.Time) *Store {
	t.Helper()
	store, err := OpenStore(StoreConfig{Path: path, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close test store: %v", err)
		}
	})
	return store
}

func testBinding() Binding {
	return Binding{TenantID: "tenant-a", SiteID: "site-a", PrincipalSHA256: strings.Repeat("a", 64)}
}

func testRecord(handoffRef string, expiresAt time.Time) Record {
	return recordForChange(handoffRef, expiresAt, planning.PendingChangeIntent{
		Operation: planning.PendingTaskUpdate, SourceRef: "source-opaque", ExpectedSourceRevision: 2,
		TaskRef: "task-opaque", ExpectedTaskRevision: 3, ObservableRef: "observable-opaque",
	})
}

func recordForChange(handoffRef string, expiresAt time.Time, change planning.PendingChangeIntent) Record {
	binding := testBinding()
	return Record{
		HandoffRef: handoffRef, TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		InteractionType: planning.LocalInteractionPersistentChange, Operation: change.Operation,
		SourceRef: change.SourceRef, TaskRef: change.TaskRef, ObservableRef: change.ObservableRef,
		ExpectedSourceRevision: change.ExpectedSourceRevision, ExpectedTaskRevision: change.ExpectedTaskRevision,
		ExpiresAt: expiresAt.UTC(), State: StatePending,
	}
}

func storeColumnNames(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.Query(`PRAGMA table_info(pending_inspection_interactions)`)
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
