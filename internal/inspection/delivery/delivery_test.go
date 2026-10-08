package delivery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type scriptedTransport struct {
	mu       sync.Mutex
	results  []SendResult
	errors   []error
	requests []SendRequest
}

func (t *scriptedTransport) Send(_ context.Context, request SendRequest) (SendResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requests = append(t.requests, request)
	index := len(t.requests) - 1
	var result SendResult
	if index < len(t.results) {
		result = t.results[index]
	}
	var err error
	if index < len(t.errors) {
		err = t.errors[index]
	}
	return result, err
}

type fixtureReconciler struct {
	mu       sync.Mutex
	decision Reconciliation
	evidence string
	err      error
	calls    int
	requests []ReconciliationRequest
}

func (r *fixtureReconciler) Lookup(_ context.Context, request ReconciliationRequest) (Reconciliation, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.requests = append(r.requests, request)
	return r.decision, r.evidence, r.err
}

func TestDispatcherDeliversOnceWithStableIdempotencyAndAudience(t *testing.T) {
	now := fixtureTime()
	store := NewMemoryStore()
	message := fixtureMessage(t, now)
	first, err := store.Enqueue(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Enqueue(context.Background(), message)
	if err != nil || second.Message.DeliveryID != first.Message.DeliveryID {
		t.Fatalf("idempotent enqueue=%#v err=%v", second, err)
	}
	transport := &scriptedTransport{results: []SendResult{{Outcome: SendDelivered, ReceiptRef: "receipt-1"}}}
	reconciler := &fixtureReconciler{}
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Store: store, Transport: transport, Reconciler: reconciler, Owner: "dispatcher-a",
		LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := dispatcher.DeliverNext(context.Background()); err != nil || !ok {
		t.Fatalf("DeliverNext() ok=%v err=%v", ok, err)
	}
	if ok, err := dispatcher.DeliverNext(context.Background()); err != nil || ok {
		t.Fatalf("second DeliverNext() ok=%v err=%v", ok, err)
	}
	stored, err := store.Get(context.Background(), message.DeliveryID)
	if err != nil || stored.State != StateDelivered || stored.ReceiptRef != "receipt-1" || stored.Attempts != 1 {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	if len(transport.requests) != 1 || transport.requests[0].IdempotencyKey != message.DeliveryID ||
		transport.requests[0].AudienceSHA256 != message.AudienceSHA256 || transport.requests[0].Attachments[0].MediaRef != "media_0123456789abcdef0123456789abcdef" {
		t.Fatalf("request=%#v", transport.requests)
	}
}

func TestKnownNotDeliveredCanRetryButUnknownCannot(t *testing.T) {
	now := fixtureTime()
	store := NewMemoryStore()
	message := fixtureMessage(t, now)
	if _, err := store.Enqueue(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	transport := &scriptedTransport{results: []SendResult{
		{Outcome: SendNotDelivered, Reason: "channel_rejected_before_send", RetryAfter: time.Minute},
		{Outcome: SendUnknown, Reason: "channel_outcome_unknown"},
	}}
	reconciler := &fixtureReconciler{decision: ReconciliationUnknown, evidence: "lookup_inconclusive"}
	current := now.Add(time.Minute)
	dispatcher, _ := NewDispatcher(DispatcherConfig{
		Store: store, Transport: transport, Reconciler: reconciler, Owner: "dispatcher-a",
		LeaseTTL: time.Minute, SendTimeout: 10 * time.Second, LookupTimeout: 10 * time.Second,
		Now: func() time.Time { return current },
	})
	if ok, err := dispatcher.DeliverNext(context.Background()); err != nil || !ok {
		t.Fatalf("known failure ok=%v err=%v", ok, err)
	}
	if ok, _ := dispatcher.DeliverNext(context.Background()); ok {
		t.Fatal("known failure retried before its bounded availability time")
	}
	current = current.Add(time.Minute)
	if ok, err := dispatcher.DeliverNext(context.Background()); !ok || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unknown send ok=%v err=%v", ok, err)
	}
	if ok, _ := dispatcher.DeliverNext(context.Background()); ok {
		t.Fatal("unknown delivery was retried blindly")
	}
	if ok, err := dispatcher.ReconcileNext(context.Background()); err != nil || !ok {
		t.Fatalf("inconclusive reconciliation ok=%v err=%v", ok, err)
	}
	if ok, _ := dispatcher.DeliverNext(context.Background()); ok {
		t.Fatal("inconclusive reconciliation made unknown delivery retryable")
	}
	reconciler.decision, reconciler.evidence = ReconciliationNotDelivered, "channel_confirmed_not_delivered"
	if ok, err := dispatcher.ReconcileNext(context.Background()); err != nil || ok {
		t.Fatalf("inconclusive reconciliation was immediately reclaimed: ok=%v err=%v", ok, err)
	}
	current = current.Add(reconciliationRetryDelay)
	if ok, err := dispatcher.ReconcileNext(context.Background()); err != nil || !ok {
		t.Fatalf("definitive reconciliation ok=%v err=%v", ok, err)
	}
	transport.results = append(transport.results, SendResult{Outcome: SendDelivered, ReceiptRef: "receipt-after-reconcile"})
	if ok, err := dispatcher.DeliverNext(context.Background()); err != nil || !ok {
		t.Fatalf("post-reconciliation delivery ok=%v err=%v", ok, err)
	}
	if transport.requests[0].IdempotencyKey != transport.requests[1].IdempotencyKey ||
		transport.requests[1].IdempotencyKey != transport.requests[2].IdempotencyKey {
		t.Fatal("delivery retry changed its idempotency identity")
	}
}

func TestInterruptedLeaseBecomesUnknownAndLateAckIsScopeBound(t *testing.T) {
	now := fixtureTime()
	store := NewMemoryStore()
	message := fixtureMessage(t, now)
	if _, err := store.Enqueue(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	_, _, ok, err := store.Claim(context.Background(), "worker-a", now.Add(time.Second), time.Minute)
	if err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if recovery, err := store.RecoverExpired(context.Background(), now.Add(2*time.Minute)); err != nil || recovery.SendingBecameUnknown != 1 || recovery.ReconciliationLeaseFreed != 0 {
		t.Fatalf("recovery=%#v err=%v", recovery, err)
	}
	if _, _, ok, err := store.Claim(context.Background(), "worker-b", now.Add(3*time.Minute), time.Minute); err != nil || ok {
		t.Fatalf("unknown delivery reclaimed ok=%v err=%v", ok, err)
	}
	wrongAudience := fixtureAcknowledgement(message, "receipt-late", now.Add(4*time.Minute))
	wrongAudience.AudienceSHA256 = strings.Repeat("f", 64)
	if err := store.Acknowledge(context.Background(), wrongAudience); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong audience ack error=%v", err)
	}
	if err := store.Acknowledge(context.Background(), fixtureAcknowledgement(message, "receipt-late", now.Add(4*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := store.Acknowledge(context.Background(), fixtureAcknowledgement(message, "receipt-late", now.Add(5*time.Minute))); err != nil {
		t.Fatalf("duplicate identical ack error=%v", err)
	}
	if err := store.Acknowledge(context.Background(), fixtureAcknowledgement(message, "receipt-conflict", now.Add(5*time.Minute))); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting late ack error=%v", err)
	}
}

func TestConcurrentClaimHasOneSender(t *testing.T) {
	now := fixtureTime()
	store := NewMemoryStore()
	if _, err := store.Enqueue(context.Background(), fixtureMessage(t, now)); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan bool, 2)
	var group sync.WaitGroup
	for _, owner := range []string{"worker-a", "worker-b"} {
		group.Add(1)
		go func(owner string) {
			defer group.Done()
			<-start
			_, _, ok, _ := store.Claim(context.Background(), owner, now.Add(time.Second), time.Minute)
			results <- ok
		}(owner)
	}
	close(start)
	group.Wait()
	close(results)
	claimed := 0
	for ok := range results {
		if ok {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("claimed=%d", claimed)
	}
}

func TestMessageRejectsProtectedTextAndBrokenAttachmentBinding(t *testing.T) {
	now := fixtureTime()
	message := fixtureMessage(t, now)
	for name, mutate := range map[string]func(*Message){
		"url":         func(value *Message) { value.Presentation.Summary = "查看 rtsp://camera/private" },
		"prompt":      func(value *Message) { value.Presentation.Summary = "prompt 内容" },
		"audience":    func(value *Message) { value.Attachments[0].AudienceSHA256 = strings.Repeat("f", 64) },
		"hash":        func(value *Message) { value.Attachments[0].SHA256 = "bad" },
		"expiry":      func(value *Message) { value.Attachments[0].ExpiresAt = value.CreatedAt },
		"inline data": func(value *Message) { value.Attachments[0].MediaRef = "base64" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := message
			candidate.Attachments = append([]Attachment(nil), message.Attachments...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid delivery message was accepted")
			}
		})
	}
}

func TestSQLiteStoreReopensAndInterruptedSendStaysUnknownUntilAck(t *testing.T) {
	now := fixtureTime()
	path := sqliteTestPath(t, "delivery.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	message := fixtureMessage(t, now)
	if _, err := store.Enqueue(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	_, attempt, ok, err := store.Claim(context.Background(), "worker-a", now.Add(time.Second), time.Minute)
	if err != nil || !ok || attempt.Number != 1 {
		t.Fatalf("claim attempt=%#v ok=%v err=%v", attempt, ok, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if recovery, err := store.RecoverExpired(context.Background(), now.Add(2*time.Minute)); err != nil || recovery.SendingBecameUnknown != 1 || recovery.ReconciliationLeaseFreed != 0 {
		t.Fatalf("RecoverExpired recovery=%#v err=%v", recovery, err)
	}
	if _, _, ok, err := store.Claim(context.Background(), "worker-b", now.Add(3*time.Minute), time.Minute); err != nil || ok {
		t.Fatalf("unknown claim ok=%v err=%v", ok, err)
	}
	if err := store.Acknowledge(context.Background(), fixtureAcknowledgement(message, "receipt-after-restart", now.Add(4*time.Minute))); err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(context.Background(), message.DeliveryID)
	if err != nil || record.State != StateDelivered || record.ReceiptRef != "receipt-after-restart" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	byRun, err := store.GetRunDelivery(context.Background(), message.RunRef, message.AudienceSHA256)
	if err != nil || byRun.Message.DeliveryID != message.DeliveryID || byRun.State != StateDelivered {
		t.Fatalf("GetRunDelivery()=%#v err=%v", byRun, err)
	}
	if _, err := store.GetRunDelivery(context.Background(), message.RunRef, strings.Repeat("f", 64)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("substituted audience GetRunDelivery() err=%v", err)
	}
}

func TestSQLiteStoreConcurrentClaimHasOneAttempt(t *testing.T) {
	now := fixtureTime()
	path := sqliteTestPath(t, "concurrent.db")
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
	if _, err := first.Enqueue(context.Background(), fixtureMessage(t, now)); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type result struct {
		ok  bool
		err error
	}
	results := make(chan result, 2)
	var group sync.WaitGroup
	for index, candidate := range []*SQLiteStore{first, second} {
		group.Add(1)
		go func(index int, candidate *SQLiteStore) {
			defer group.Done()
			<-start
			_, _, ok, err := candidate.Claim(context.Background(), fmt.Sprintf("worker-%d", index), now.Add(time.Second), time.Minute)
			results <- result{ok: ok, err: err}
		}(index, candidate)
	}
	close(start)
	group.Wait()
	close(results)
	claimed := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.ok {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("claimed=%d", claimed)
	}
}

func TestSQLiteStoreRejectsTamperOldShapeAndUnsafePath(t *testing.T) {
	now := fixtureTime()
	path := sqliteTestPath(t, "tamper.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	message := fixtureMessage(t, now)
	if _, err := store.Enqueue(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE deliveries SET message_json='{}' WHERE delivery_id=?`, message.DeliveryID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), message.DeliveryID); err == nil {
		t.Fatal("tampered delivery message was accepted")
	}
	if _, err := store.db.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenSQLite(path); err == nil || !strings.Contains(err.Error(), "explicitly reset") {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("old schema error=%v", err)
	}
	if _, err := OpenSQLite(path + "?mode=ro"); err == nil {
		t.Fatal("delivery store accepted a query-bearing path")
	}

	shapePath := sqliteTestPath(t, "shape.db")
	shape, err := OpenSQLite(shapePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shape.db.Exec(`CREATE TABLE unexpected(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = shape.Close()
	if reopened, err := OpenSQLite(shapePath); err == nil {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("delivery store accepted an unexpected table")
	}

	alteredPath := sqliteTestPath(t, "altered.db")
	altered, err := OpenSQLite(alteredPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := altered.db.Exec(`DROP INDEX deliveries_reconcile_idx; CREATE INDEX deliveries_reconcile_idx ON deliveries(state, delivery_id)`); err != nil {
		t.Fatal(err)
	}
	if err := altered.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenSQLite(alteredPath); err == nil {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("delivery store accepted an altered current-version index")
	}

	alteredTablePath := sqliteTestPath(t, "altered-table.db")
	database, err := sql.Open("sqlite", alteredTablePath)
	if err != nil {
		t.Fatal(err)
	}
	alteredTableSQL := strings.Replace(createDeliveriesSQL,
		"attempts INTEGER NOT NULL CHECK(attempts >= 0 AND attempts <= 8)", "attempts INTEGER NOT NULL", 1)
	if _, err := database.Exec(alteredTableSQL + "\n" + createDeliveryClaimIndexSQL + "\n" + createDeliveryReconcileIndexSQL); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(fmt.Sprintf(`PRAGMA application_id=%d; PRAGMA user_version=%d;`, deliveryApplicationID, deliveryDatabaseVersion)); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(alteredTablePath); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenSQLite(alteredTablePath); err == nil {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("delivery store accepted an altered current-version table")
	}
}

func fixtureMessage(t *testing.T, now time.Time) Message {
	return fixtureMessageFor(t, now, "1")
}

func fixtureMessageFor(t *testing.T, now time.Time, identity string) Message {
	t.Helper()
	message, err := NewMessage("run-"+identity, "result-"+identity, Audience{
		TenantID: "tenant-a", SiteID: "site-a", Channel: "workbuddy",
		ConversationRef: "conversation-a", RecipientRef: "recipient-a",
	}, Presentation{Title: "巡检完成", Summary: "东侧就餐区需要关注。", DetailLabel: "查看现场快照"}, []Attachment{{
		MediaRef: "media_0123456789abcdef0123456789abcdef", SHA256: strings.Repeat("a", 64),
		Kind: "image", ExpiresAt: now.Add(time.Hour),
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func fixtureTime() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }

func fixtureAcknowledgement(message Message, receiptRef string, observedAt time.Time) Acknowledgement {
	return Acknowledgement{
		DeliveryID: message.DeliveryID, IdempotencyKey: message.IdempotencyKey,
		AudienceSHA256: message.AudienceSHA256, ReceiptRef: receiptRef, ObservedAt: observedAt,
	}
}

func sqliteTestPath(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "delivery-state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, name)
}
