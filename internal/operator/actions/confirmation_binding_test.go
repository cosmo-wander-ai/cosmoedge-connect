package actions

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

type changingActionConnection struct {
	mu         sync.Mutex
	connection device.ActionConnection
}

func (p *changingActionConnection) ActionConnection() (device.ActionConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connection, nil
}
func (p *changingActionConnection) selectConnection(serial, epoch string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connection.Serial, p.connection.EndpointFingerprint = serial, epoch
}

func TestConfirmationRejectsChangedDeviceAndReturningSelectionEpochBeforeQueue(t *testing.T) {
	for _, kind := range []string{KindTaskSwitch, KindTaskParameters, KindCameraSource} {
		t.Run(kind, func(t *testing.T) {
			manager, store, client, _ := newTestManager(t)
			provider := &changingActionConnection{connection: device.ActionConnection{Client: client, Serial: client.serial, EndpointFingerprint: "selection-A-1"}}
			manager.provider = provider
			snapshot, _ := client.Read(context.Background())
			var proposal Proposal
			var err error
			switch kind {
			case KindTaskSwitch:
				proposal, err = manager.PrepareTaskSwitch(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], 0)
			case KindTaskParameters:
				proposal, err = manager.PrepareTaskParameters(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], []device.ParameterField{{Key: "param.threshold", Value: "7"}})
			case KindCameraSource:
				proposal, err = manager.PrepareCameraSource(context.Background(), "browser-a", "Test camera", []byte("rtsp://10.20.30.40/test-only"))
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, selection := range []struct{ serial, epoch string }{
				{"other-device", "selection-A-1"}, // Serial is independently required.
				{"other-device", "selection-B-2"},
				{client.serial, "selection-A-3"}, // Same device/address, new current-selection revision.
			} {
				provider.selectConnection(selection.serial, selection.epoch)
				if _, err := manager.ConfirmExpected(context.Background(), "browser-a", proposal.ConfirmationToken, proposal.ActionID); !errors.Is(err, ErrActionConflict) {
					t.Fatalf("changed selection accepted confirmation: %v", err)
				}
				record, err := store.Inspect(context.Background(), proposal.ActionID)
				if err != nil || record.State != "proposed" || record.Dispatches != 0 || record.DeviceWrites != 0 {
					t.Fatalf("confirmation entered queue: %+v error=%v", record, err)
				}
			}
			client.mu.Lock()
			defer client.mu.Unlock()
			if client.taskWrites+client.parameterWrites+client.sourceWrites != 0 {
				t.Fatal("stale proposal reached device write")
			}
		})
	}
}

func TestConsumedConfirmationAfterSelectionChangeDoesNotReplay(t *testing.T) {
	manager, store, client, _ := newTestManager(t)
	provider := &changingActionConnection{connection: device.ActionConnection{Client: client, Serial: client.serial, EndpointFingerprint: "selection-A-1"}}
	manager.provider = provider
	snapshot, _ := client.Read(context.Background())
	proposal, err := manager.PrepareTaskSwitch(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	if status := waitForTerminal(t, manager, proposal.ActionID); status.State != "completed" {
		t.Fatalf("status=%+v", status)
	}
	provider.selectConnection(client.serial, "selection-A-3")
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); !errors.Is(err, ErrActionConflict) {
		t.Fatalf("consumed token=%v", err)
	}
	record, err := store.Inspect(context.Background(), proposal.ActionID)
	if err != nil || record.State != "completed" || record.Dispatches != 1 || record.DeviceWrites != 1 {
		t.Fatalf("original record changed=%+v error=%v", record, err)
	}
}
