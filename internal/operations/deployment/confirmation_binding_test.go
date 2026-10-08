package deployment

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

type changingDeploymentConnection struct {
	mu         sync.Mutex
	connection device.ActionConnection
}

func (p *changingDeploymentConnection) ActionConnection() (device.ActionConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connection, nil
}
func (p *changingDeploymentConnection) selectConnection(serial, epoch string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connection.Serial, p.connection.EndpointFingerprint = serial, epoch
}

func TestDeploymentConfirmationRejectsReturningDeviceSelectionEpochBeforeQueue(t *testing.T) {
	h := newHarness(t, true)
	provider := &changingDeploymentConnection{connection: device.ActionConnection{Client: h.client, Serial: "test-device", EndpointFingerprint: "selection-A-1"}}
	h.service.provider = provider
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range []struct{ serial, epoch string }{
		{"other-device", "selection-A-1"},
		{"other-device", "selection-B-2"},
		{"test-device", "selection-A-3"},
	} {
		provider.selectConnection(selection.serial, selection.epoch)
		if err := h.service.Confirm(context.Background(), "session-a", proposal.ActionRef, proposal.ConfirmationToken); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale confirmation=%v", err)
		}
		record, err := h.store.Inspect(context.Background(), proposal.ActionRef)
		if err != nil || record.State != "proposed" || record.Dispatches != 0 || record.DeviceWrites != 0 {
			t.Fatalf("stale proposal queued=%+v error=%v", record, err)
		}
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 0 {
		t.Fatal("stale proposal wrote a device")
	}
}

func TestConfirmedDeploymentAfterSelectionChangeReturnsOriginalRecord(t *testing.T) {
	h := newHarness(t, true)
	provider := &changingDeploymentConnection{connection: device.ActionConnection{Client: h.client, Serial: "test-device", EndpointFingerprint: "selection-A-1"}}
	h.service.provider = provider
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	if record := confirmAndWait(t, h, proposal); record.State != "completed" {
		t.Fatalf("original=%+v", record)
	}
	for _, selection := range []struct{ serial, epoch string }{{"other-device", "selection-B-2"}, {"test-device", "selection-A-3"}} {
		provider.selectConnection(selection.serial, selection.epoch)
		if err := h.service.Confirm(context.Background(), "session-a", proposal.ActionRef, proposal.ConfirmationToken); err != nil {
			t.Fatalf("repeat confirmation lost original record: %v", err)
		}
		status, err := h.service.GetByRequest(context.Background(), "session-a", "request-one")
		if err != nil || status.ActionRef != proposal.ActionRef || status.State != "completed" || status.Dispatches != 1 || status.DeviceWrites != 1 || status.Current != nil || status.Target.ConfirmationToken != "" {
			t.Fatalf("repeat/current attributed to new selection=%+v error=%v", status, err)
		}
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 1 {
		t.Fatalf("repeat dispatched %d writes", h.client.writes)
	}
}
