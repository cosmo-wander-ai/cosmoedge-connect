package delivery

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type transportFunc func(context.Context, SendRequest) (SendResult, error)

func (f transportFunc) Send(ctx context.Context, request SendRequest) (SendResult, error) {
	return f(ctx, request)
}

type reconcilerFunc func(context.Context, ReconciliationRequest) (Reconciliation, string, error)

func (f reconcilerFunc) Lookup(ctx context.Context, request ReconciliationRequest) (Reconciliation, string, error) {
	return f(ctx, request)
}

type failingMarkUnknownStore struct {
	Store
	err error
}

func (s failingMarkUnknownStore) MarkOutcomeUnknown(context.Context, Attempt, string, time.Time) error {
	return s.err
}

type blockingReconciler struct {
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	calls    int
	requests []ReconciliationRequest
}

func (r *blockingReconciler) Lookup(ctx context.Context, request ReconciliationRequest) (Reconciliation, string, error) {
	r.mu.Lock()
	r.calls++
	r.requests = append(r.requests, request)
	r.mu.Unlock()
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
		return ReconciliationDelivered, "receipt-reconciled", nil
	case <-ctx.Done():
		return ReconciliationUnknown, "lookup_cancelled", ctx.Err()
	}
}

func TestDispatcherRequiresCompleteExplicitConfiguration(t *testing.T) {
	now := fixtureTime()
	store := NewMemoryStore()
	transport := &scriptedTransport{}
	reconciler := &fixtureReconciler{}
	valid := DispatcherConfig{
		Store: store, Transport: transport, Reconciler: reconciler,
		Owner: "dispatcher-a", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return now },
	}
	if _, err := NewDispatcher(valid); err != nil {
		t.Fatal(err)
	}
	var typedNilStore *MemoryStore
	for name, mutate := range map[string]func(*DispatcherConfig){
		"store":                        func(config *DispatcherConfig) { config.Store = nil },
		"typed nil":                    func(config *DispatcherConfig) { config.Store = typedNilStore },
		"transport":                    func(config *DispatcherConfig) { config.Transport = nil },
		"reconciler":                   func(config *DispatcherConfig) { config.Reconciler = nil },
		"owner":                        func(config *DispatcherConfig) { config.Owner = "" },
		"lease":                        func(config *DispatcherConfig) { config.LeaseTTL = 0 },
		"oversized lease":              func(config *DispatcherConfig) { config.LeaseTTL = 11 * time.Minute },
		"send timeout":                 func(config *DispatcherConfig) { config.SendTimeout = 0 },
		"send exceeds lease reserve":   func(config *DispatcherConfig) { config.SendTimeout = 31 * time.Second },
		"lookup timeout":               func(config *DispatcherConfig) { config.LookupTimeout = 0 },
		"lookup exceeds lease reserve": func(config *DispatcherConfig) { config.LookupTimeout = 31 * time.Second },
		"clock":                        func(config *DispatcherConfig) { config.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewDispatcher(candidate); err == nil {
				t.Fatal("incomplete dispatcher configuration was accepted")
			}
		})
	}
}

func TestRecoverIsExplicitAndRoutesUnknownOnlyToReconciler(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	store := NewMemoryStore()
	message := fixtureMessage(t, base)
	if _, err := store.Enqueue(ctx, message); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.Claim(ctx, "crashed-worker", base.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	clock := base.Add(30 * time.Second)
	transport := &scriptedTransport{results: []SendResult{{Outcome: SendDelivered, ReceiptRef: "must-not-send"}}}
	reconciler := &fixtureReconciler{decision: ReconciliationDelivered, evidence: "receipt-reconciled"}
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Store: store, Transport: transport, Reconciler: reconciler,
		Owner: "recovery-worker", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := dispatcher.DeliverNext(ctx); err != nil || ok {
		t.Fatalf("active sending lease was delivered again: ok=%v err=%v", ok, err)
	}
	if ok, err := dispatcher.ReconcileNext(ctx); err != nil || ok {
		t.Fatalf("active sending lease was reconciled: ok=%v err=%v", ok, err)
	}
	if recovery, err := dispatcher.Recover(ctx); err != nil || recovery != (Recovery{}) {
		t.Fatalf("unexpired recovery=%#v err=%v", recovery, err)
	}
	clock = base.Add(2 * time.Minute)
	if ok, err := dispatcher.DeliverNext(ctx); err != nil || ok {
		t.Fatalf("expired send lease was implicitly recovered by delivery: ok=%v err=%v", ok, err)
	}
	if ok, err := dispatcher.ReconcileNext(ctx); err != nil || ok {
		t.Fatalf("expired send lease was implicitly recovered by reconciliation: ok=%v err=%v", ok, err)
	}
	if recovery, err := dispatcher.Recover(ctx); err != nil || recovery.SendingBecameUnknown != 1 || recovery.ReconciliationLeaseFreed != 0 {
		t.Fatalf("expired recovery=%#v err=%v", recovery, err)
	}
	if ok, err := dispatcher.DeliverNext(ctx); err != nil || ok {
		t.Fatalf("outcome-unknown delivery entered send queue: ok=%v err=%v", ok, err)
	}
	if ok, err := dispatcher.ReconcileNext(ctx); err != nil || !ok {
		t.Fatalf("unknown reconciliation ok=%v err=%v", ok, err)
	}
	if len(transport.requests) != 0 {
		t.Fatalf("transport was called during recovery/reconciliation: %#v", transport.requests)
	}
	record, err := store.Get(ctx, message.DeliveryID)
	if err != nil || record.State != StateDelivered || record.ReceiptRef != "receipt-reconciled" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	if reconciler.calls != 1 || len(reconciler.requests) != 1 || reconciler.requests[0] != (ReconciliationRequest{
		DeliveryID: message.DeliveryID, IdempotencyKey: message.IdempotencyKey, AudienceSHA256: message.AudienceSHA256,
	}) {
		t.Fatalf("reconciliation calls=%d requests=%#v", reconciler.calls, reconciler.requests)
	}
}

func TestSQLiteReconciliationClaimIsSingleOwnerAcrossInstances(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	path := filepath.Join(t.TempDir(), "delivery-state", "delivery.db")
	first, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	message := fixtureMessage(t, base)
	if _, err := first.Enqueue(ctx, message); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := first.Claim(ctx, "sender", base.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if recovery, err := first.RecoverExpired(ctx, base.Add(2*time.Minute)); err != nil || recovery.SendingBecameUnknown != 1 {
		t.Fatalf("recovery=%#v err=%v", recovery, err)
	}
	reconciler := &blockingReconciler{entered: make(chan struct{}), release: make(chan struct{})}
	transport := &scriptedTransport{}
	clock := func() time.Time { return base.Add(3 * time.Minute) }
	firstDispatcher, err := NewDispatcher(DispatcherConfig{
		Store: first, Transport: transport, Reconciler: reconciler,
		Owner: "dispatcher-first", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second, Now: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondDispatcher, err := NewDispatcher(DispatcherConfig{
		Store: second, Transport: transport, Reconciler: reconciler,
		Owner: "dispatcher-second", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second, Now: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		ok, reconcileErr := firstDispatcher.ReconcileNext(ctx)
		if !ok && reconcileErr == nil {
			reconcileErr = errors.New("first dispatcher did not claim reconciliation")
		}
		result <- reconcileErr
	}()
	<-reconciler.entered
	if ok, err := secondDispatcher.ReconcileNext(ctx); err != nil || ok {
		close(reconciler.release)
		t.Fatalf("second dispatcher claimed same unknown: ok=%v err=%v", ok, err)
	}
	close(reconciler.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	reconciler.mu.Lock()
	calls := reconciler.calls
	reconciler.mu.Unlock()
	if calls != 1 {
		t.Fatalf("reconciler calls=%d", calls)
	}
	record, err := second.Get(ctx, message.DeliveryID)
	if err != nil || record.State != StateDelivered || record.ReconciliationAttempts != 1 {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}

func TestExpiredReconciliationLeaseNeedsRecoveryAndRejectsStaleCAS(t *testing.T) {
	for _, fixture := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) Store {
			store, err := OpenSQLite(filepath.Join(t.TempDir(), "delivery-state", "delivery.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ctx := context.Background()
			base := fixtureTime()
			store := fixture.open(t)
			message := fixtureMessage(t, base)
			if _, err := store.Enqueue(ctx, message); err != nil {
				t.Fatal(err)
			}
			if _, _, ok, err := store.Claim(ctx, "sender", base.Add(time.Second), time.Minute); err != nil || !ok {
				t.Fatalf("send claim ok=%v err=%v", ok, err)
			}
			if _, err := store.RecoverExpired(ctx, base.Add(2*time.Minute)); err != nil {
				t.Fatal(err)
			}
			_, stale, ok, err := store.ClaimReconciliation(ctx, "reconciler-a", base.Add(3*time.Minute), time.Minute)
			if err != nil || !ok {
				t.Fatalf("reconciliation claim ok=%v err=%v", ok, err)
			}
			if recovery, err := store.RecoverExpired(ctx, base.Add(3*time.Minute+30*time.Second)); err != nil || recovery != (Recovery{}) {
				t.Fatalf("unexpired reconciliation recovery=%#v err=%v", recovery, err)
			}
			if _, _, ok, err := store.ClaimReconciliation(ctx, "reconciler-b", base.Add(3*time.Minute+30*time.Second), time.Minute); err != nil || ok {
				t.Fatalf("active reconciliation lease was stolen: ok=%v err=%v", ok, err)
			}
			if _, _, ok, err := store.ClaimReconciliation(ctx, "reconciler-b", base.Add(5*time.Minute), time.Minute); err != nil || ok {
				t.Fatalf("expired reconciliation lease was implicitly recovered: ok=%v err=%v", ok, err)
			}
			if recovery, err := store.RecoverExpired(ctx, base.Add(5*time.Minute)); err != nil || recovery.ReconciliationLeaseFreed != 1 || recovery.SendingBecameUnknown != 0 {
				t.Fatalf("expired reconciliation recovery=%#v err=%v", recovery, err)
			}
			if err := store.Reconcile(ctx, stale, ReconciliationDelivered, "stale-receipt", base.Add(5*time.Minute)); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("stale reconciliation error=%v", err)
			}
			_, current, ok, err := store.ClaimReconciliation(ctx, "reconciler-b", base.Add(5*time.Minute), time.Minute)
			if err != nil || !ok || current.Number != stale.Number+1 {
				t.Fatalf("new reconciliation attempt=%#v ok=%v err=%v", current, ok, err)
			}
			if err := store.Reconcile(ctx, current, ReconciliationDelivered, "current-receipt", base.Add(5*time.Minute)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLeaseExpiryBoundaryIsExclusive(t *testing.T) {
	for _, fixture := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) Store {
			store, err := OpenSQLite(filepath.Join(t.TempDir(), "delivery-state", "delivery.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ctx := context.Background()
			base := fixtureTime()
			store := fixture.open(t)
			message := fixtureMessage(t, base)
			if _, err := store.Enqueue(ctx, message); err != nil {
				t.Fatal(err)
			}
			_, sendAttempt, ok, err := store.Claim(ctx, "sender", base.Add(time.Second), time.Minute)
			if err != nil || !ok {
				t.Fatalf("send claim ok=%v err=%v", ok, err)
			}
			if err := store.MarkDelivered(ctx, sendAttempt, "receipt-at-boundary", sendAttempt.LeaseExpiresAt); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("send completion at lease boundary error=%v", err)
			}
			if recovery, err := store.RecoverExpired(ctx, sendAttempt.LeaseExpiresAt); err != nil || recovery.SendingBecameUnknown != 1 {
				t.Fatalf("send boundary recovery=%#v err=%v", recovery, err)
			}
			_, reconciliationAttempt, ok, err := store.ClaimReconciliation(ctx, "reconciler", sendAttempt.LeaseExpiresAt, time.Minute)
			if err != nil || !ok {
				t.Fatalf("reconciliation claim ok=%v err=%v", ok, err)
			}
			if err := store.Reconcile(ctx, reconciliationAttempt, ReconciliationDelivered, "receipt-at-boundary", reconciliationAttempt.LeaseExpiresAt); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("reconciliation at lease boundary error=%v", err)
			}
			if recovery, err := store.RecoverExpired(ctx, reconciliationAttempt.LeaseExpiresAt); err != nil || recovery.ReconciliationLeaseFreed != 1 {
				t.Fatalf("reconciliation boundary recovery=%#v err=%v", recovery, err)
			}
		})
	}
}

func TestStoreSubsecondTimeOrderingMatchesMemoryAndSQLite(t *testing.T) {
	for _, fixture := range []struct {
		name string
		open func(*testing.T, string) Store
	}{
		{name: "memory", open: func(*testing.T, string) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T, name string) Store {
			store, err := OpenSQLite(filepath.Join(t.TempDir(), "delivery-state", name+".db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	} {
		t.Run(fixture.name+"/availability", func(t *testing.T) {
			ctx := context.Background()
			base := fixtureTime()
			store := fixture.open(t, "availability")
			message := fixtureMessage(t, base.Add(100*time.Millisecond))
			if _, err := store.Enqueue(ctx, message); err != nil {
				t.Fatal(err)
			}
			if _, _, ok, err := store.Claim(ctx, "sender", base, time.Minute); err != nil || ok {
				t.Fatalf("future subsecond availability claimed early: ok=%v err=%v", ok, err)
			}
			if _, _, ok, err := store.Claim(ctx, "sender", base.Add(100*time.Millisecond), time.Minute); err != nil || !ok {
				t.Fatalf("available subsecond delivery not claimed: ok=%v err=%v", ok, err)
			}
		})
		t.Run(fixture.name+"/lease", func(t *testing.T) {
			ctx := context.Background()
			base := fixtureTime()
			store := fixture.open(t, "lease")
			message := fixtureMessage(t, base)
			if _, err := store.Enqueue(ctx, message); err != nil {
				t.Fatal(err)
			}
			_, attempt, ok, err := store.Claim(ctx, "sender", base, 900*time.Millisecond)
			if err != nil || !ok {
				t.Fatalf("claim ok=%v err=%v", ok, err)
			}
			if recovery, err := store.RecoverExpired(ctx, base); err != nil || recovery != (Recovery{}) {
				t.Fatalf("subsecond lease recovered early: recovery=%#v err=%v", recovery, err)
			}
			if err := store.MarkDelivered(ctx, attempt, "receipt-before-expiry", base.Add(100*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSendCompletionAfterLeaseExpiryConvergesThroughReconciliationWithoutResend(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	clock := base.Add(time.Second)
	store := NewMemoryStore()
	message := fixtureMessage(t, base)
	if _, err := store.Enqueue(ctx, message); err != nil {
		t.Fatal(err)
	}
	sends := 0
	transport := transportFunc(func(context.Context, SendRequest) (SendResult, error) {
		sends++
		clock = base.Add(2 * time.Minute)
		return SendResult{Outcome: SendDelivered, ReceiptRef: "receipt-before-crash"}, nil
	})
	reconciler := &fixtureReconciler{decision: ReconciliationDelivered, evidence: "receipt-before-crash"}
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Store: store, Transport: transport, Reconciler: reconciler,
		Owner: "dispatcher-a", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := dispatcher.DeliverNext(ctx); !ok || !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("late mark ok=%v err=%v", ok, err)
	}
	if recovery, err := dispatcher.Recover(ctx); err != nil || recovery.SendingBecameUnknown != 1 {
		t.Fatalf("recovery=%#v err=%v", recovery, err)
	}
	if ok, err := dispatcher.DeliverNext(ctx); err != nil || ok {
		t.Fatalf("unknown delivery was resent: ok=%v err=%v", ok, err)
	}
	if ok, err := dispatcher.ReconcileNext(ctx); err != nil || !ok {
		t.Fatalf("reconciliation ok=%v err=%v", ok, err)
	}
	if sends != 1 {
		t.Fatalf("send calls=%d", sends)
	}
	record, err := store.Get(ctx, message.DeliveryID)
	if err != nil || record.State != StateDelivered || record.ReceiptRef != "receipt-before-crash" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}

func TestCompletedSendIsNotChangedByLaterRecovery(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	clock := base.Add(time.Second)
	store := NewMemoryStore()
	message := fixtureMessage(t, base)
	if _, err := store.Enqueue(ctx, message); err != nil {
		t.Fatal(err)
	}
	transport := &scriptedTransport{results: []SendResult{{Outcome: SendDelivered, ReceiptRef: "receipt-recorded"}}}
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Store: store, Transport: transport, Reconciler: &fixtureReconciler{},
		Owner: "dispatcher-a", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := dispatcher.DeliverNext(ctx); err != nil || !ok {
		t.Fatalf("delivery ok=%v err=%v", ok, err)
	}
	clock = base.Add(10 * time.Minute)
	if recovery, err := dispatcher.Recover(ctx); err != nil || recovery != (Recovery{}) {
		t.Fatalf("recovery=%#v err=%v", recovery, err)
	}
	record, err := store.Get(ctx, message.DeliveryID)
	if err != nil || record.State != StateDelivered || record.Attempts != 1 || record.ReceiptRef != "receipt-recorded" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}

func TestLateReceiptWinsExactAudienceDuringReconciliation(t *testing.T) {
	for _, fixture := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) Store {
			store, err := OpenSQLite(filepath.Join(t.TempDir(), "delivery-state", "delivery.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ctx := context.Background()
			base := fixtureTime()
			store := fixture.open(t)
			message := fixtureMessage(t, base)
			if _, err := store.Enqueue(ctx, message); err != nil {
				t.Fatal(err)
			}
			if _, _, ok, err := store.Claim(ctx, "sender", base.Add(time.Second), time.Minute); err != nil || !ok {
				t.Fatalf("send claim ok=%v err=%v", ok, err)
			}
			if _, err := store.RecoverExpired(ctx, base.Add(2*time.Minute)); err != nil {
				t.Fatal(err)
			}
			_, attempt, ok, err := store.ClaimReconciliation(ctx, "reconciler", base.Add(3*time.Minute), time.Minute)
			if err != nil || !ok {
				t.Fatalf("reconciliation claim ok=%v err=%v", ok, err)
			}
			wrongAudience := fixtureAcknowledgement(message, "receipt-late", base.Add(3*time.Minute+time.Second))
			wrongAudience.AudienceSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			if err := store.Acknowledge(ctx, wrongAudience); !errors.Is(err, ErrConflict) {
				t.Fatalf("cross-audience acknowledgement error=%v", err)
			}
			if err := store.Acknowledge(ctx, fixtureAcknowledgement(message, "receipt-late", base.Add(3*time.Minute+time.Second))); err != nil {
				t.Fatal(err)
			}
			if err := store.Reconcile(ctx, attempt, ReconciliationDelivered, "receipt-late", base.Add(3*time.Minute+2*time.Second)); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("reconciliation after late receipt error=%v", err)
			}
			if err := store.Acknowledge(ctx, fixtureAcknowledgement(message, "receipt-late", base.Add(4*time.Minute))); err != nil {
				t.Fatalf("identical receipt replay error=%v", err)
			}
			if err := store.Acknowledge(ctx, fixtureAcknowledgement(message, "receipt-conflict", base.Add(4*time.Minute))); !errors.Is(err, ErrConflict) {
				t.Fatalf("conflicting receipt error=%v", err)
			}
		})
	}
}

func TestLateReceiptAfterNotDeliveredPreventsResend(t *testing.T) {
	for _, fixture := range []struct {
		name string
		open func(*testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemoryStore() }},
		{name: "sqlite", open: func(t *testing.T) Store {
			store, err := OpenSQLite(filepath.Join(t.TempDir(), "delivery-state", "delivery.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			return store
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ctx := context.Background()
			base := fixtureTime()
			store := fixture.open(t)
			message := fixtureMessage(t, base)
			if _, err := store.Enqueue(ctx, message); err != nil {
				t.Fatal(err)
			}
			if err := store.Acknowledge(ctx, fixtureAcknowledgement(message, "receipt-before-send", base.Add(time.Second))); !errors.Is(err, ErrConflict) {
				t.Fatalf("initial pending acknowledgement error=%v", err)
			}
			_, sendAttempt, ok, err := store.Claim(ctx, "sender", base.Add(time.Second), time.Minute)
			if err != nil || !ok {
				t.Fatalf("send claim ok=%v err=%v", ok, err)
			}
			if err := store.MarkOutcomeUnknown(ctx, sendAttempt, "channel_outcome_unknown", base.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			_, reconciliationAttempt, ok, err := store.ClaimReconciliation(ctx, "reconciler", base.Add(3*time.Second), time.Minute)
			if err != nil || !ok {
				t.Fatalf("reconciliation claim ok=%v err=%v", ok, err)
			}
			if err := store.Reconcile(ctx, reconciliationAttempt, ReconciliationNotDelivered, "channel_confirmed_not_delivered", base.Add(4*time.Second)); err != nil {
				t.Fatal(err)
			}
			record, err := store.Get(ctx, message.DeliveryID)
			if err != nil || record.State != StatePending || record.Attempts != 1 {
				t.Fatalf("retry-pending record=%#v err=%v", record, err)
			}
			if err := store.Acknowledge(ctx, fixtureAcknowledgement(message, "receipt-late", base.Add(5*time.Second))); err != nil {
				t.Fatal(err)
			}
			if _, _, ok, err := store.Claim(ctx, "second-sender", base.Add(6*time.Second), time.Minute); err != nil || ok {
				t.Fatalf("late receipt allowed resend: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestSQLiteConcurrentAcknowledgementConvergesAcrossReconciliationClaim(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	path := filepath.Join(t.TempDir(), "delivery-state", "delivery.db")
	first, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	type claimResult struct {
		attempt ReconciliationAttempt
		ok      bool
		err     error
	}
	for index := 0; index < 32; index++ {
		createdAt := base.Add(time.Duration(index) * time.Millisecond)
		message := fixtureMessageFor(t, createdAt, fmt.Sprintf("ack-reconcile-%d", index))
		if _, err := first.Enqueue(ctx, message); err != nil {
			t.Fatal(err)
		}
		_, sendAttempt, ok, err := first.Claim(ctx, fmt.Sprintf("sender-%d", index), createdAt, time.Minute)
		if err != nil || !ok {
			t.Fatalf("send claim index=%d ok=%v err=%v", index, ok, err)
		}
		if err := first.MarkOutcomeUnknown(ctx, sendAttempt, "channel_outcome_unknown", createdAt); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		acknowledged := make(chan error, 1)
		claimed := make(chan claimResult, 1)
		go func() {
			<-start
			acknowledged <- first.Acknowledge(ctx, fixtureAcknowledgement(message, "receipt-race", createdAt.Add(time.Second)))
		}()
		go func() {
			<-start
			_, attempt, claimedOK, claimErr := second.ClaimReconciliation(ctx, fmt.Sprintf("reconciler-%d", index), createdAt.Add(time.Second), time.Minute)
			claimed <- claimResult{attempt: attempt, ok: claimedOK, err: claimErr}
		}()
		close(start)
		if err := <-acknowledged; err != nil {
			t.Fatalf("acknowledgement index=%d err=%v", index, err)
		}
		claim := <-claimed
		if claim.err != nil {
			t.Fatalf("reconciliation claim index=%d err=%v", index, claim.err)
		}
		record, err := second.Get(ctx, message.DeliveryID)
		if err != nil || record.State != StateDelivered || record.ReceiptRef != "receipt-race" {
			t.Fatalf("record index=%d value=%#v err=%v", index, record, err)
		}
		if claim.ok {
			if err := second.Reconcile(ctx, claim.attempt, ReconciliationDelivered, "receipt-race", createdAt.Add(2*time.Second)); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("stale reconciliation index=%d err=%v", index, err)
			}
		}
	}
}

func TestSQLiteConcurrentAcknowledgementConvergesAcrossRetryClaim(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	path := filepath.Join(t.TempDir(), "delivery-state", "delivery.db")
	first, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	type claimResult struct {
		attempt Attempt
		ok      bool
		err     error
	}
	for index := 0; index < 32; index++ {
		createdAt := base.Add(time.Duration(index) * time.Millisecond)
		message := fixtureMessageFor(t, createdAt, fmt.Sprintf("ack-retry-%d", index))
		if _, err := first.Enqueue(ctx, message); err != nil {
			t.Fatal(err)
		}
		_, firstAttempt, ok, err := first.Claim(ctx, fmt.Sprintf("first-sender-%d", index), createdAt, time.Minute)
		if err != nil || !ok {
			t.Fatalf("first claim index=%d ok=%v err=%v", index, ok, err)
		}
		if err := first.MarkNotDelivered(ctx, firstAttempt, "channel_confirmed_not_delivered", createdAt, 0); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		acknowledged := make(chan error, 1)
		claimed := make(chan claimResult, 1)
		go func() {
			<-start
			acknowledged <- first.Acknowledge(ctx, fixtureAcknowledgement(message, "receipt-race", createdAt.Add(time.Second)))
		}()
		go func() {
			<-start
			_, attempt, claimedOK, claimErr := second.Claim(ctx, fmt.Sprintf("second-sender-%d", index), createdAt.Add(time.Second), time.Minute)
			claimed <- claimResult{attempt: attempt, ok: claimedOK, err: claimErr}
		}()
		close(start)
		if err := <-acknowledged; err != nil {
			t.Fatalf("acknowledgement index=%d err=%v", index, err)
		}
		claim := <-claimed
		if claim.err != nil {
			t.Fatalf("retry claim index=%d err=%v", index, claim.err)
		}
		record, err := second.Get(ctx, message.DeliveryID)
		if err != nil || record.State != StateDelivered || record.ReceiptRef != "receipt-race" {
			t.Fatalf("record index=%d value=%#v err=%v", index, record, err)
		}
		if claim.ok {
			if err := second.MarkDelivered(ctx, claim.attempt, "receipt-race", createdAt.Add(2*time.Second)); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("stale retry completion index=%d err=%v", index, err)
			}
		}
		if _, _, ok, err := first.Claim(ctx, "third-sender", createdAt.Add(3*time.Second), time.Minute); err != nil || ok {
			t.Fatalf("post-ack retry index=%d ok=%v err=%v", index, ok, err)
		}
	}
}

func TestSQLiteConcurrentAcknowledgementsAreIdempotentOrExactlyConflicting(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	path := filepath.Join(t.TempDir(), "delivery-state", "delivery.db")
	first, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for index, receipts := range [][2]string{
		{"receipt-same", "receipt-same"},
		{"receipt-first", "receipt-second"},
	} {
		createdAt := base.Add(time.Duration(index) * time.Second)
		message := fixtureMessageFor(t, createdAt, fmt.Sprintf("ack-pair-%d", index))
		if _, err := first.Enqueue(ctx, message); err != nil {
			t.Fatal(err)
		}
		_, sendAttempt, ok, err := first.Claim(ctx, fmt.Sprintf("sender-pair-%d", index), createdAt, time.Minute)
		if err != nil || !ok {
			t.Fatalf("send claim index=%d ok=%v err=%v", index, ok, err)
		}
		if err := first.MarkOutcomeUnknown(ctx, sendAttempt, "channel_outcome_unknown", createdAt); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for receiptIndex, candidate := range []*SQLiteStore{first, second} {
			receipt := receipts[receiptIndex]
			go func(store *SQLiteStore, receiptRef string) {
				<-start
				results <- store.Acknowledge(ctx, fixtureAcknowledgement(message, receiptRef, createdAt.Add(time.Second)))
			}(candidate, receipt)
		}
		close(start)
		firstErr, secondErr := <-results, <-results
		if receipts[0] == receipts[1] {
			if firstErr != nil || secondErr != nil {
				t.Fatalf("identical concurrent acknowledgements errors=(%v,%v)", firstErr, secondErr)
			}
		} else {
			successes, conflicts := 0, 0
			for _, candidate := range []error{firstErr, secondErr} {
				switch {
				case candidate == nil:
					successes++
				case errors.Is(candidate, ErrConflict):
					conflicts++
				default:
					t.Fatalf("unexpected acknowledgement error=%v", candidate)
				}
			}
			if successes != 1 || conflicts != 1 {
				t.Fatalf("different receipt successes=%d conflicts=%d", successes, conflicts)
			}
		}
		record, err := first.Get(ctx, message.DeliveryID)
		if err != nil || record.State != StateDelivered || record.ReceiptRef != receipts[0] && record.ReceiptRef != receipts[1] {
			t.Fatalf("record=%#v err=%v", record, err)
		}
	}
}

func TestReconcilerFailureReleasesUnknownWithoutSending(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	store := NewMemoryStore()
	message := fixtureMessage(t, base)
	if _, err := store.Enqueue(ctx, message); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.Claim(ctx, "sender", base.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if _, err := store.RecoverExpired(ctx, base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("channel lookup unavailable")
	reconciler := &fixtureReconciler{err: wantErr}
	transport := &scriptedTransport{}
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Store: store, Transport: transport, Reconciler: reconciler,
		Owner: "dispatcher-a", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return base.Add(3 * time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := dispatcher.ReconcileNext(ctx); !ok || !errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, wantErr) {
		t.Fatalf("reconciliation ok=%v err=%v", ok, err)
	}
	record, err := store.Get(ctx, message.DeliveryID)
	if err != nil || record.State != StateOutcomeUnknown || record.LeaseOwner != "" || record.Reason != "delivery_reconciliation_failed" ||
		record.AvailableAt != base.Add(3*time.Minute).Add(reconciliationRetryDelay) {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	if len(transport.requests) != 0 {
		t.Fatalf("transport requests=%#v", transport.requests)
	}
}

func TestUnknownPersistenceFailureIsNotReportedAsPersistedUnknown(t *testing.T) {
	ctx := context.Background()
	base := fixtureTime()
	persistent := NewMemoryStore()
	message := fixtureMessage(t, base)
	if _, err := persistent.Enqueue(ctx, message); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("unknown state persistence failed")
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Store:      failingMarkUnknownStore{Store: persistent, err: wantErr},
		Transport:  &scriptedTransport{results: []SendResult{{Outcome: SendUnknown, Reason: "channel_outcome_unknown"}}},
		Reconciler: &fixtureReconciler{}, Owner: "dispatcher-a", LeaseTTL: time.Minute,
		SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return base.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := dispatcher.DeliverNext(ctx); !ok || !errors.Is(err, wantErr) || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("delivery ok=%v err=%v", ok, err)
	}
	record, err := persistent.Get(ctx, message.DeliveryID)
	if err != nil || record.State != StateSending {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}

func TestExternalCallsTimeoutBeforeLeaseExpiryAndPersistUnknown(t *testing.T) {
	t.Run("send", func(t *testing.T) {
		ctx := context.Background()
		createdAt := time.Now().UTC().Add(-time.Second)
		store := NewMemoryStore()
		message := fixtureMessageFor(t, createdAt, "blocking-send")
		if _, err := store.Enqueue(ctx, message); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		transport := transportFunc(func(callContext context.Context, _ SendRequest) (SendResult, error) {
			close(entered)
			<-callContext.Done()
			return SendResult{}, callContext.Err()
		})
		dispatcher, err := NewDispatcher(DispatcherConfig{
			Store: store, Transport: transport, Reconciler: &fixtureReconciler{}, Owner: "dispatcher-a",
			LeaseTTL: 2 * time.Second, SendTimeout: 50 * time.Millisecond, LookupTimeout: 50 * time.Millisecond, Now: time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}
		type result struct {
			ok  bool
			err error
		}
		finished := make(chan result, 1)
		startedAt := time.Now()
		go func() {
			ok, deliverErr := dispatcher.DeliverNext(ctx)
			finished <- result{ok: ok, err: deliverErr}
		}()
		<-entered
		if recovery, err := dispatcher.Recover(ctx); err != nil || recovery != (Recovery{}) {
			t.Fatalf("active call recovery=%#v err=%v", recovery, err)
		}
		select {
		case completed := <-finished:
			if !completed.ok || !errors.Is(completed.err, ErrOutcomeUnknown) {
				t.Fatalf("delivery result=%#v", completed)
			}
		case <-time.After(time.Second):
			t.Fatal("transport did not honor dispatcher timeout")
		}
		if time.Since(startedAt) >= 2*time.Second {
			t.Fatal("transport call outlived its delivery lease")
		}
		record, err := store.Get(ctx, message.DeliveryID)
		if err != nil || record.State != StateOutcomeUnknown || record.LeaseOwner != "" {
			t.Fatalf("record=%#v err=%v", record, err)
		}
		if ok, err := dispatcher.DeliverNext(ctx); err != nil || ok {
			t.Fatalf("timed-out delivery was sent again: ok=%v err=%v", ok, err)
		}
	})

	t.Run("lookup", func(t *testing.T) {
		ctx := context.Background()
		createdAt := time.Now().UTC().Add(-time.Second)
		store := NewMemoryStore()
		message := fixtureMessageFor(t, createdAt, "blocking-lookup")
		if _, err := store.Enqueue(ctx, message); err != nil {
			t.Fatal(err)
		}
		_, sendAttempt, ok, err := store.Claim(ctx, "sender", createdAt, time.Minute)
		if err != nil || !ok {
			t.Fatalf("send claim ok=%v err=%v", ok, err)
		}
		if err := store.MarkOutcomeUnknown(ctx, sendAttempt, "channel_outcome_unknown", createdAt); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		reconciler := reconcilerFunc(func(callContext context.Context, _ ReconciliationRequest) (Reconciliation, string, error) {
			close(entered)
			<-callContext.Done()
			return ReconciliationUnknown, "lookup_cancelled", callContext.Err()
		})
		transport := &scriptedTransport{}
		dispatcher, err := NewDispatcher(DispatcherConfig{
			Store: store, Transport: transport, Reconciler: reconciler, Owner: "dispatcher-a",
			LeaseTTL: 2 * time.Second, SendTimeout: 50 * time.Millisecond, LookupTimeout: 50 * time.Millisecond, Now: time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}
		type result struct {
			ok  bool
			err error
		}
		finished := make(chan result, 1)
		go func() {
			claimed, reconcileErr := dispatcher.ReconcileNext(ctx)
			finished <- result{ok: claimed, err: reconcileErr}
		}()
		<-entered
		if recovery, err := dispatcher.Recover(ctx); err != nil || recovery != (Recovery{}) {
			t.Fatalf("active lookup recovery=%#v err=%v", recovery, err)
		}
		select {
		case completed := <-finished:
			if !completed.ok || !errors.Is(completed.err, ErrOutcomeUnknown) {
				t.Fatalf("reconciliation result=%#v", completed)
			}
		case <-time.After(time.Second):
			t.Fatal("reconciler did not honor dispatcher timeout")
		}
		record, err := store.Get(ctx, message.DeliveryID)
		if err != nil || record.State != StateOutcomeUnknown || record.LeaseOwner != "" || !record.AvailableAt.After(record.UpdatedAt) {
			t.Fatalf("record=%#v err=%v", record, err)
		}
		if ok, err := dispatcher.ReconcileNext(ctx); err != nil || ok {
			t.Fatalf("timed-out reconciliation was immediately retried: ok=%v err=%v", ok, err)
		}
		if len(transport.requests) != 0 {
			t.Fatalf("transport requests=%#v", transport.requests)
		}
	})
}

func TestClockFailureAfterExternalCallLeavesLeaseForExplicitRecovery(t *testing.T) {
	t.Run("send", func(t *testing.T) {
		ctx := context.Background()
		base := fixtureTime()
		store := NewMemoryStore()
		message := fixtureMessageFor(t, base, "clock-send")
		if _, err := store.Enqueue(ctx, message); err != nil {
			t.Fatal(err)
		}
		calls := 0
		clock := func() time.Time {
			calls++
			if calls == 1 {
				return base
			}
			return time.Time{}
		}
		dispatcher, err := NewDispatcher(DispatcherConfig{
			Store: store, Transport: &scriptedTransport{results: []SendResult{{Outcome: SendDelivered, ReceiptRef: "receipt-clock"}}},
			Reconciler: &fixtureReconciler{}, Owner: "dispatcher-a", LeaseTTL: time.Minute,
			SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second, Now: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := dispatcher.DeliverNext(ctx); !ok || !errors.Is(err, ErrInvalid) {
			t.Fatalf("delivery ok=%v err=%v", ok, err)
		}
		record, err := store.Get(ctx, message.DeliveryID)
		if err != nil || record.State != StateSending {
			t.Fatalf("record=%#v err=%v", record, err)
		}
		if recovery, err := store.RecoverExpired(ctx, base.Add(time.Minute)); err != nil || recovery.SendingBecameUnknown != 1 {
			t.Fatalf("recovery=%#v err=%v", recovery, err)
		}
	})

	t.Run("lookup", func(t *testing.T) {
		ctx := context.Background()
		base := fixtureTime()
		store := NewMemoryStore()
		message := fixtureMessageFor(t, base, "clock-lookup")
		if _, err := store.Enqueue(ctx, message); err != nil {
			t.Fatal(err)
		}
		_, sendAttempt, ok, err := store.Claim(ctx, "sender", base, time.Minute)
		if err != nil || !ok {
			t.Fatalf("send claim ok=%v err=%v", ok, err)
		}
		if err := store.MarkOutcomeUnknown(ctx, sendAttempt, "channel_outcome_unknown", base); err != nil {
			t.Fatal(err)
		}
		calls := 0
		claimAt := base.Add(time.Second)
		clock := func() time.Time {
			calls++
			if calls == 1 {
				return claimAt
			}
			return time.Time{}
		}
		dispatcher, err := NewDispatcher(DispatcherConfig{
			Store: store, Transport: &scriptedTransport{},
			Reconciler: &fixtureReconciler{decision: ReconciliationDelivered, evidence: "receipt-clock"},
			Owner:      "dispatcher-a", LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second, Now: clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := dispatcher.ReconcileNext(ctx); !ok || !errors.Is(err, ErrInvalid) {
			t.Fatalf("reconciliation ok=%v err=%v", ok, err)
		}
		record, err := store.Get(ctx, message.DeliveryID)
		if err != nil || record.State != StateOutcomeUnknown || record.LeaseOwner == "" {
			t.Fatalf("record=%#v err=%v", record, err)
		}
		if recovery, err := store.RecoverExpired(ctx, claimAt.Add(time.Minute)); err != nil || recovery.ReconciliationLeaseFreed != 1 {
			t.Fatalf("recovery=%#v err=%v", recovery, err)
		}
	})
}
