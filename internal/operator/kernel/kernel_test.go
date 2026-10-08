package kernel

import (
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
)

const (
	testBinding  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testResource = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type testHandler struct {
	now             time.Time
	validateErr     error
	validatePanic   bool
	dispatchPanic   bool
	verifyPanic     bool
	invalidResult   bool
	protectedResult bool
	dispatches      atomic.Int32
	verifications   atomic.Int32
}

func (h *testHandler) Validate(context.Context, ledger.Action) error {
	if h.validatePanic {
		panic("validate")
	}
	return h.validateErr
}

func (h *testHandler) Dispatch(context.Context, ledger.Action) Dispatch {
	h.dispatches.Add(1)
	if h.dispatchPanic {
		panic("dispatch")
	}
	return Dispatch{Outcome: "accepted", DeviceWriteCount: 1}
}

func (h *testHandler) Verify(context.Context, ledger.Action, Dispatch) result.Trusted {
	h.verifications.Add(1)
	if h.verifyPanic {
		panic("verify")
	}
	if h.invalidResult {
		return result.Trusted{}
	}
	if h.protectedResult {
		return result.Trusted{
			Class: result.Completed, EvidenceStatus: result.EvidenceSealed,
			Conclusion: "Operation completed.", Reason: "fresh_read_matches_target", EvidenceJSON: `{"password":"must-not-persist"}`, ObservedAt: h.now,
		}
	}
	return result.Trusted{
		Class: result.Completed, EvidenceStatus: result.EvidenceSealed,
		Conclusion: "Operation completed.", Reason: "fresh_read_matches_target", EvidenceJSON: `{}`, ObservedAt: h.now,
	}
}

func TestKernelDispatchesOnceAndOwnsSingleWorker(t *testing.T) {
	now := time.Date(2026, 7, 17, 16, 0, 0, 0, time.UTC)
	store, err := ledger.Open(protectedLedgerPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := &testHandler{now: now.Add(time.Minute)}
	first, err := New(store, map[string]Handler{"task": handler})
	if err != nil {
		t.Fatal(err)
	}
	first.now = func() time.Time { return now }
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer first.Stop()

	second, err := New(store, map[string]Handler{"task": handler})
	if err != nil {
		t.Fatal(err)
	}
	second.now = func() time.Time { return now }
	if err := second.Start(context.Background()); !errors.Is(err, ErrWorkerUnavailable) {
		t.Fatalf("competing worker start error = %v", err)
	}

	action, err := first.Propose(context.Background(), ledger.NewAction{
		Kind: "task", SessionBinding: testBinding, ResourceKey: testResource,
		PublicJSON: `{}`, ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Confirm(context.Background(), action.ID, testBinding); err != nil {
		t.Fatal(err)
	}
	waitForState(t, store, action.ID, "completed")
	for range 8 {
		first.Wake()
	}
	time.Sleep(50 * time.Millisecond)
	if got := handler.dispatches.Load(); got != 1 {
		t.Fatalf("dispatch count = %d, want 1", got)
	}
	if got := handler.verifications.Load(); got != 1 {
		t.Fatalf("verification count = %d, want 1", got)
	}
}

func TestKernelContainsHandlerFailures(t *testing.T) {
	tests := []struct {
		name         string
		handler      func(time.Time) *testHandler
		wantState    string
		wantDispatch int32
		wantVerify   int32
	}{
		{name: "validation error", handler: func(now time.Time) *testHandler {
			return &testHandler{now: now, validateErr: errors.New("missing foreground material")}
		}, wantState: "blocked"},
		{name: "validation panic", handler: func(now time.Time) *testHandler { return &testHandler{now: now, validatePanic: true} }, wantState: "blocked"},
		{name: "dispatch panic", handler: func(now time.Time) *testHandler { return &testHandler{now: now, dispatchPanic: true} }, wantState: "unknown", wantDispatch: 1},
		{name: "verification panic", handler: func(now time.Time) *testHandler { return &testHandler{now: now, verifyPanic: true} }, wantState: "unknown", wantDispatch: 1, wantVerify: 1},
		{name: "invalid trusted result", handler: func(now time.Time) *testHandler { return &testHandler{now: now, invalidResult: true} }, wantState: "unknown", wantDispatch: 1, wantVerify: 1},
		{name: "protected trusted result", handler: func(now time.Time) *testHandler { return &testHandler{now: now, protectedResult: true} }, wantState: "unknown", wantDispatch: 1, wantVerify: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 7, 17, 17, 0, 0, 0, time.UTC)
			store, err := ledger.Open(protectedLedgerPath(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			handler := test.handler(now.Add(time.Minute))
			worker, err := New(store, map[string]Handler{"task": handler})
			if err != nil {
				t.Fatal(err)
			}
			worker.now = func() time.Time { return now }
			if err := worker.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer worker.Stop()

			action, err := worker.Propose(context.Background(), ledger.NewAction{
				Kind: "task", SessionBinding: testBinding, ResourceKey: testResource,
				PublicJSON: `{}`, ExpiresAt: now.Add(10 * time.Minute),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.Confirm(context.Background(), action.ID, testBinding); err != nil {
				t.Fatal(err)
			}
			waitForState(t, store, action.ID, test.wantState)
			if got := handler.dispatches.Load(); got != test.wantDispatch {
				t.Fatalf("dispatch count = %d, want %d", got, test.wantDispatch)
			}
			if got := handler.verifications.Load(); got != test.wantVerify {
				t.Fatalf("verification count = %d, want %d", got, test.wantVerify)
			}
			for range 4 {
				worker.Wake()
			}
			time.Sleep(25 * time.Millisecond)
			if got := handler.dispatches.Load(); got != test.wantDispatch {
				t.Fatalf("terminal action replayed, dispatch count = %d", got)
			}
		})
	}
}

func protectedLedgerPath(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "operator.db")
}

func waitForState(t *testing.T, store *ledger.Store, id, want string) ledger.Action {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		action, err := store.Get(context.Background(), id)
		if err == nil && action.State == want {
			return action
		}
		time.Sleep(10 * time.Millisecond)
	}
	action, err := store.Get(context.Background(), id)
	t.Fatalf("action state = %q, want %q (action=%+v err=%v)", action.State, want, action, err)
	return ledger.Action{}
}
