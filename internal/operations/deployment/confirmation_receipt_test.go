package deployment

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

// Synthetic native rejection: the receipt must not create another dispatch.
func TestConfirmationReceiptPreservesKnownRejectionWithoutNewDispatch(t *testing.T) {
	h := newHarness(t, true)
	h.client.writeErr = nativeRejectedError{}
	p, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	first, err := h.service.ConfirmWithReceipt(context.Background(), "session-a", p.ActionRef, p.ConfirmationToken)
	if err != nil || first.Disposition != "accepted" || !first.NewConfirmationAccepted {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	before := confirmAndWait(t, h, p)
	if before.State != "blocked" || before.Dispatches != 1 || before.DeviceWrites != 0 {
		t.Fatalf("before=%+v", before)
	}
	again, err := h.service.ConfirmWithReceipt(context.Background(), "session-a", p.ActionRef, p.ConfirmationToken)
	if err != nil || again.Disposition != "already_confirmed" || again.NewConfirmationAccepted {
		t.Fatalf("again=%+v err=%v", again, err)
	}
	after, err := h.store.Inspect(context.Background(), p.ActionRef)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("repeat changed original record: %+v, %v", after, err)
	}
	h.client.mu.Lock()
	writes := h.client.writes
	h.client.mu.Unlock()
	if writes != 1 {
		t.Fatalf("native attempts=%d, want 1", writes)
	}
	foreign, err := h.service.ConfirmWithReceipt(context.Background(), "session-b", p.ActionRef, p.ConfirmationToken)
	if !errors.Is(err, ErrConflict) || foreign != (ConfirmationReceipt{}) {
		t.Fatalf("foreign receipt leaked: %+v %v", foreign, err)
	}
}

type receiptGatedClient struct {
	*testClient
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
	attempts  atomic.Int32
}

func (c *receiptGatedClient) SwitchTask(ctx context.Context, task device.Task, enabled int) error {
	c.attempts.Add(1)
	c.enterOnce.Do(func() { close(c.entered) })
	select {
	case <-c.release:
		return c.testClient.SwitchTask(ctx, task, enabled)
	case <-ctx.Done():
		return ctx.Err()
	}
}

type receiptGatedProvider struct{ client *receiptGatedClient }

func (p receiptGatedProvider) ActionConnection() (device.ActionConnection, error) {
	return device.ActionConnection{Client: p.client, Serial: "test-device", EndpointFingerprint: "test-transport"}, nil
}

func TestConfirmationReceiptDuringDispatchDoesNotCreateOrCancelOperation(t *testing.T) {
	h := newHarness(t, true)
	gate := &receiptGatedClient{testClient: h.client, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	// No action exists yet. Keep the real service, worker and SQLite store,
	// replacing only the synthetic device boundary with a deterministic gate.
	h.service.mu.Lock()
	h.service.provider = receiptGatedProvider{client: gate}
	h.service.mu.Unlock()
	p, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	first, err := h.service.ConfirmWithReceipt(context.Background(), "session-a", p.ActionRef, p.ConfirmationToken)
	if err != nil || first.Disposition != "accepted" || !first.NewConfirmationAccepted {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	h.worker.Wake()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("synthetic dispatch was not entered")
	}
	before, err := h.store.Inspect(context.Background(), p.ActionRef)
	if err != nil || before.State != "dispatching" || before.Dispatches != 1 {
		t.Fatalf("not in flight: %+v, %v", before, err)
	}
	again, err := h.service.ConfirmWithReceipt(context.Background(), "session-a", p.ActionRef, p.ConfirmationToken)
	if err != nil || again.Disposition != "already_confirmed" || again.NewConfirmationAccepted {
		t.Fatalf("again=%+v err=%v", again, err)
	}
	after, err := h.store.Inspect(context.Background(), p.ActionRef)
	if err != nil || !reflect.DeepEqual(before, after) || gate.attempts.Load() != 1 {
		t.Fatalf("repeat changed in-flight operation: %+v, %v; attempts=%d", after, err, gate.attempts.Load())
	}
	release()
	completed := confirmAndWait(t, h, p)
	if completed.State != "completed" || completed.Dispatches != 1 || completed.DeviceWrites != 1 || gate.attempts.Load() != 1 {
		t.Fatalf("original did not complete exactly once: %+v attempts=%d", completed, gate.attempts.Load())
	}
}
