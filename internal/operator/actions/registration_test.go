package actions

import (
	"context"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/kernel"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
)

type additionalTestHandler struct{}

func (additionalTestHandler) Validate(context.Context, ledger.Action) error { return nil }
func (additionalTestHandler) Dispatch(context.Context, ledger.Action) kernel.Dispatch {
	return kernel.Dispatch{Outcome: "accepted"}
}
func (additionalTestHandler) Verify(context.Context, ledger.Action, kernel.Dispatch) result.Trusted {
	return result.Trusted{Class: result.Completed, EvidenceStatus: result.EvidenceSealed, Conclusion: "Additional operation verified.", Reason: "additional_verified", EvidenceJSON: `{}`, ObservedAt: time.Now().UTC()}
}

func TestAdditionalHandlerSharesWorkerWithOrdinaryActions(t *testing.T) {
	original, store, client, _ := newTestManager(t)
	original.Stop()
	manager, err := NewWithHandlers(store, fakeProvider{client: client}, map[string]kernel.Handler{"additional_operation": additionalTestHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)
	owner := bindingDigest("browser-a")
	proposal, err := manager.worker.Propose(context.Background(), ledger.NewAction{Kind: "additional_operation", SessionBinding: owner, ResourceKey: digest("additional-resource"), PublicJSON: `{}`, ExpiresAt: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.worker.Confirm(context.Background(), proposal.ID, owner); err != nil {
		t.Fatal(err)
	}
	if status := waitForTerminal(t, manager, proposal.ID); status.State != "completed" || status.Reason != "additional_verified" {
		t.Fatalf("additional handler not executed: %+v", status)
	}
	snapshot, err := client.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := manager.PrepareTaskSwitch(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", ordinary.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	if status := waitForTerminal(t, manager, ordinary.ActionID); status.State != "completed" || status.DeviceWrites != 1 {
		t.Fatalf("ordinary handler changed: %+v", status)
	}
}

func TestAdditionalHandlersCannotReplaceExistingBusinessHandlers(t *testing.T) {
	manager, store, client, _ := newTestManager(t)
	manager.Stop()
	for _, kind := range []string{KindTaskSwitch, KindTaskParameters, KindCameraSource, "", " padded "} {
		if _, err := NewWithHandlers(store, fakeProvider{client: client}, map[string]kernel.Handler{kind: additionalTestHandler{}}); err == nil {
			t.Fatalf("invalid replacement kind %q accepted", kind)
		}
	}
}
