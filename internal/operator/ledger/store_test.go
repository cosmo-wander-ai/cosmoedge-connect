package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	bindingA  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bindingB  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	resourceA = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestOpenProtectsSQLiteSidecarsAndRejectsUnsafeExistingFiles(t *testing.T) {
	path := protectedTestPath(t)
	store := openTestStore(t, path)
	defer store.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := localstate.ValidateFile(path + suffix); err != nil {
			t.Fatalf("ledger file %q is not protected: %v", suffix, err)
		}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		t.Run(suffix, func(t *testing.T) {
			path := protectedTestPath(t)
			sidecar := path + suffix
			if err := os.WriteFile(sidecar, []byte("existing untrusted file"), 0o644); err != nil {
				t.Fatal(err)
			}
			if store, err := Open(path); err == nil {
				store.Close()
				t.Fatal("unsafe existing sidecar was accepted")
			}
			if err := localstate.ValidateFile(sidecar); err == nil {
				t.Fatal("unsafe existing sidecar was silently hardened")
			}
		})
	}
}

func TestSchemaAndProtectedMaterialBoundary(t *testing.T) {
	path := protectedTestPath(t)
	store := openTestStore(t, path)

	rows, err := store.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"action_events", "actions", "dispatches", "evidence", "operator_schema_migrations", "worker_leases"}
	sort.Strings(want)
	if strings.Join(tables, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected schema tables: %v", tables)
	}

	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	secret := "VaultSecret-DoNotPersist"
	cases := []NewAction{
		{ID: "bad-digest", Kind: "task", SessionBinding: "browser-session", ResourceKey: resourceA, PublicJSON: `{}`, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
		{ID: "bad-json", Kind: "task", SessionBinding: bindingA, ResourceKey: resourceA, PublicJSON: `{`, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
		{ID: "bad-password", Kind: "task", SessionBinding: bindingA, ResourceKey: resourceA, PublicJSON: `{"password":"` + secret + `"}`, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
		{ID: "bad-source", Kind: "source", SessionBinding: bindingA, ResourceKey: resourceA, PublicJSON: `{"sourceUrl":"rtsp://user:pass@192.168.0.22/live"}`, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
		{ID: "bad-address", Kind: "task", SessionBinding: bindingA, ResourceKey: resourceA, PublicJSON: `{"summary":"192.168.0.22:8000"}`, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
		{ID: "bad-params", Kind: "parameters", SessionBinding: bindingA, ResourceKey: resourceA, PublicJSON: `{"fields":[{"value":"0.7"}]}`, CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
	}
	for _, item := range cases {
		if err := store.Create(context.Background(), item); err == nil {
			t.Fatalf("protected action %q was accepted", item.ID)
		}
	}
	valid := testAction("valid", now)
	valid.PublicJSON = `{"summary":"Enable selected task","changed":true}`
	if err := store.Create(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{secret, "rtsp://", "192.168.0.22", "browser-session"} {
			if strings.Contains(string(data), forbidden) {
				t.Fatalf("%s contains protected material %q", filepath.Base(file), forbidden)
			}
		}
	}
}

func TestConfirmationIsSessionBoundAndExactlyOnce(t *testing.T) {
	path := protectedTestPath(t)
	store := openTestStore(t, path)
	defer store.Close()
	other := openTestStore(t, path)
	defer other.Close()
	now := time.Date(2026, 7, 17, 11, 0, 0, 0, time.UTC)
	if err := store.Create(context.Background(), testAction("confirm-once", now)); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(context.Background(), "confirm-once", bindingB, now.Add(time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-session confirmation error = %v", err)
	}

	const contenders = 16
	start := make(chan struct{})
	results := make(chan error, contenders)
	var group sync.WaitGroup
	stores := []*Store{store, other}
	for index := range contenders {
		group.Add(1)
		go func(candidate *Store) {
			defer group.Done()
			<-start
			results <- candidate.Confirm(context.Background(), "confirm-once", bindingA, now.Add(2*time.Second))
		}(stores[index%len(stores)])
	}
	close(start)
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatalf("unexpected confirmation error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("confirmation successes = %d, want 1", successes)
	}
	action, err := store.Get(context.Background(), "confirm-once")
	if err != nil || action.State != "queued" {
		t.Fatalf("confirmed action = %+v, err = %v", action, err)
	}
}

func TestExpiredActionsBecomeTerminalWithoutDispatch(t *testing.T) {
	store := openTestStore(t, protectedTestPath(t))
	defer store.Close()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	proposed := testAction("expired-proposed", now)
	proposed.ExpiresAt = now.Add(time.Minute)
	if err := store.Create(context.Background(), proposed); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(context.Background(), proposed.ID, bindingA, proposed.ExpiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired confirmation error = %v", err)
	}
	assertTerminal(t, store, proposed.ID, "blocked", "proposal_expired")

	queued := testAction("expired-queued", now)
	queued.ExpiresAt = now.Add(2 * time.Minute)
	if err := store.Create(context.Background(), queued); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(context.Background(), queued.ID, bindingA, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.ClaimNext(context.Background(), queued.ExpiresAt); err != nil || ok {
		t.Fatalf("expired queue claim ok=%v err=%v", ok, err)
	}
	assertTerminal(t, store, queued.ID, "blocked", "proposal_expired")
}

func TestConcurrentClaimCreatesOneDispatchAttempt(t *testing.T) {
	path := protectedTestPath(t)
	first := openTestStore(t, path)
	defer first.Close()
	second := openTestStore(t, path)
	defer second.Close()
	now := time.Date(2026, 7, 17, 13, 0, 0, 0, time.UTC)
	if err := first.Create(context.Background(), testAction("claim-once", now)); err != nil {
		t.Fatal(err)
	}
	if err := first.Confirm(context.Background(), "claim-once", bindingA, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	type claimResult struct {
		ok  bool
		err error
	}
	results := make(chan claimResult, 2)
	for _, store := range []*Store{first, second} {
		go func(store *Store) {
			<-start
			_, ok, err := store.ClaimNext(context.Background(), now.Add(2*time.Second))
			results <- claimResult{ok: ok, err: err}
		}(store)
	}
	close(start)
	claimed := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("claim error: %v", result.err)
		}
		if result.ok {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("claim successes = %d, want 1", claimed)
	}
	var attempts int
	if err := first.db.QueryRow(`SELECT COUNT(*) FROM dispatches WHERE action_id='claim-once'`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("dispatch attempts = %d, want 1", attempts)
	}
}

func TestRestartRecoverySeparatesPreAndPostDispatch(t *testing.T) {
	store := openTestStore(t, protectedTestPath(t))
	defer store.Close()
	now := time.Date(2026, 7, 17, 14, 0, 0, 0, time.UTC)

	claimAction(t, store, "before-dispatch", now)
	if err := store.RecoverInterrupted(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertTerminal(t, store, "before-dispatch", "blocked", "foreground_authority_lost_before_dispatch")

	claimAction(t, store, "after-dispatch", now.Add(2*time.Minute))
	if err := store.MarkDispatch(context.Background(), "after-dispatch", now.Add(2*time.Minute+time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverInterrupted(context.Background(), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertTerminal(t, store, "after-dispatch", "unknown", "process_restarted_after_dispatch")

	if err := store.RecoverInterrupted(context.Background(), now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var evidenceCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM evidence`).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 2 {
		t.Fatalf("evidence rows after repeated recovery = %d, want 2", evidenceCount)
	}
	if _, ok, err := store.ClaimNext(context.Background(), now.Add(5*time.Minute)); err != nil || ok {
		t.Fatalf("terminal action was replayable: ok=%v err=%v", ok, err)
	}
}

func TestWorkerLeaseHasOneOwner(t *testing.T) {
	path := protectedTestPath(t)
	first := openTestStore(t, path)
	defer first.Close()
	second := openTestStore(t, path)
	defer second.Close()
	now := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	if acquired, err := first.AcquireWorker(context.Background(), "operator", "owner-a", now, time.Minute); err != nil || !acquired {
		t.Fatalf("first lease acquired=%v err=%v", acquired, err)
	}
	if acquired, err := second.AcquireWorker(context.Background(), "operator", "owner-b", now, time.Minute); err != nil || acquired {
		t.Fatalf("competing lease acquired=%v err=%v", acquired, err)
	}
	if err := second.ReleaseWorker(context.Background(), "operator", "owner-b"); err != nil {
		t.Fatal(err)
	}
	if acquired, err := second.AcquireWorker(context.Background(), "operator", "owner-b", now, time.Minute); err != nil || acquired {
		t.Fatalf("wrong-owner release changed lease: acquired=%v err=%v", acquired, err)
	}
	if err := first.ReleaseWorker(context.Background(), "operator", "owner-a"); err != nil {
		t.Fatal(err)
	}
	if acquired, err := second.AcquireWorker(context.Background(), "operator", "owner-b", now, time.Minute); err != nil || !acquired {
		t.Fatalf("lease handoff acquired=%v err=%v", acquired, err)
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func protectedTestPath(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "operator.db")
}

func testAction(id string, now time.Time) NewAction {
	return NewAction{
		ID: id, Kind: "task", SessionBinding: bindingA, ResourceKey: resourceA,
		PublicJSON: `{}`, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}
}

func claimAction(t *testing.T, store *Store, id string, now time.Time) {
	t.Helper()
	if err := store.Create(context.Background(), testAction(id, now)); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(context.Background(), id, bindingA, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	action, ok, err := store.ClaimNext(context.Background(), now.Add(2*time.Second))
	if err != nil || !ok || action.ID != id {
		t.Fatalf("claim = %+v, ok=%v, err=%v", action, ok, err)
	}
}

func assertTerminal(t *testing.T, store *Store, id, state, reason string) {
	t.Helper()
	action, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if action.State != state || action.ResultClass != state || action.Reason != reason {
		t.Fatalf("action %q = %+v", id, action)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM evidence WHERE action_id=?`, id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("evidence rows for %q = %d, want 1", id, count)
	}
}

func TestInspectEvidenceReadsExistingRowWithoutSerializingRawPayload(t *testing.T) {
	path := protectedTestPath(t)
	store := openTestStore(t, path)
	now := time.Now().UTC()
	ctx := context.Background()
	claimAction(t, store, "evidence-read", now)
	payload := `{"onlyInternal":"synthetic-private-evidence"}`
	sealedAt := now.Add(3 * time.Second)
	if err := store.Finish(ctx, "evidence-read", result.Trusted{Class: result.Completed, EvidenceStatus: result.EvidenceSealed, Conclusion: "Original conclusion", Reason: "verified", EvidenceJSON: payload, ObservedAt: sealedAt}); err != nil {
		t.Fatal(err)
	}
	evidence, err := store.InspectEvidence(ctx, "evidence-read")
	if err != nil || evidence.PayloadJSON != payload || evidence.ObservedAt != formatTime(sealedAt) || evidence.SealedAt != formatTime(sealedAt) {
		t.Fatalf("evidence metadata mismatch: %v", err)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("raw evidence serialized: %s %v", encoded, err)
	}
	if _, err := store.InspectEvidence(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	defer reopened.Close()
	later, err := reopened.InspectEvidence(ctx, "evidence-read")
	if err != nil || later != evidence {
		t.Fatal("sealed evidence changed after reopen")
	}
}
