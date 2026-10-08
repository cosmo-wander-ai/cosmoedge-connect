package kernel

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

type diagnosticHandler struct {
	testHandler
	store      *ledger.Store
	t          *testing.T
	diagnostic *safediagnostic.Diagnostic
	want       *safediagnostic.Diagnostic
}

func (h *diagnosticHandler) Dispatch(context.Context, ledger.Action) Dispatch {
	h.dispatches.Add(1)
	return Dispatch{Outcome: "known_failed", DeviceWriteCount: 0, Diagnostic: h.diagnostic}
}
func (h *diagnosticHandler) Verify(ctx context.Context, action ledger.Action, dispatch Dispatch) result.Trusted {
	h.verifications.Add(1)
	record, err := h.store.Inspect(ctx, action.ID)
	if err != nil || record.State != "verifying" || record.DispatchOutcome != "known_failed" || !reflect.DeepEqual(record.Diagnostic, h.want) || !reflect.DeepEqual(dispatch.Diagnostic, h.want) {
		h.t.Fatalf("Verify did not see atomic safe diagnostic: record=%+v dispatch=%+v err=%v", record, dispatch, err)
	}
	return result.Trusted{Class: result.Blocked, EvidenceStatus: result.EvidenceSealed, Conclusion: "Device rejected the request.", Reason: "deployment_rejected", EvidenceJSON: `{}`, ObservedAt: h.now}
}
func TestKernelPersistsDiagnosticBeforeVerifyAndDoesNotReplay(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		name := "safe"
		if invalid {
			name = "invalid optional metadata"
		}
		t.Run(name, func(t *testing.T) {
			path := protectedLedgerPath(t)
			store, err := ledger.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Now().UTC()
			code := 0
			diagnostic := &safediagnostic.Diagnostic{Operation: safediagnostic.OperationTaskSwitch, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassNativeRejected, HTTPStatus: 200, ResCode: &code, MsgCode: "12314"}
			want := diagnostic.Clone()
			if invalid {
				diagnostic.MsgCode = "unsafe raw device text"
				want = nil
			}
			h := &diagnosticHandler{testHandler: testHandler{now: now.Add(time.Minute)}, store: store, t: t, diagnostic: diagnostic, want: want}
			worker, err := New(store, map[string]Handler{"task": h})
			if err != nil {
				t.Fatal(err)
			}
			worker.now = func() time.Time { return now }
			action, err := worker.Propose(context.Background(), ledger.NewAction{Kind: "task", SessionBinding: testBinding, ResourceKey: testResource, PublicJSON: `{}`, ExpiresAt: now.Add(10 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			if err = worker.Confirm(context.Background(), action.ID, testBinding); err != nil {
				t.Fatal(err)
			}
			claimed, ok, err := store.ClaimNext(context.Background(), now)
			if err != nil || !ok {
				t.Fatalf("claim ok=%v err=%v", ok, err)
			}
			worker.execute(context.Background(), claimed)
			worker.execute(context.Background(), claimed)
			record, err := store.Inspect(context.Background(), action.ID)
			if err != nil || record.State != "blocked" || record.DeviceWrites != 0 || record.Dispatches != 1 || h.dispatches.Load() != 1 || h.verifications.Load() != 1 || !reflect.DeepEqual(record.Diagnostic, want) {
				t.Fatalf("terminal diagnostic/counts=%+v err=%v", record, err)
			}
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := ledger.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			record, err = reopened.Inspect(context.Background(), action.ID)
			if err != nil || !reflect.DeepEqual(record.Diagnostic, want) || record.Reason != "deployment_rejected" {
				t.Fatalf("terminal diagnostic lost on reopen: %+v err=%v", record, err)
			}
		})
	}
}
