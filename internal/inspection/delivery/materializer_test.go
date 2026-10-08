package delivery_test

import (
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"path/filepath"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectiontest"
)

type staticMessageBuilder struct {
	message delivery.Message
	calls   int
	err     error
}

func (b *staticMessageBuilder) BuildDeliveryMessage(_ context.Context, _ string) (delivery.Message, error) {
	b.calls++
	return b.message, b.err
}

type failingMarkOutbox struct {
	delivery.TerminalOutbox
	fail bool
}

func (o *failingMarkOutbox) MarkOutboxMaterialized(ctx context.Context, messageID, owner string, now time.Time) error {
	if o.fail {
		o.fail = false
		return errors.New("injected mark failure")
	}
	return o.TerminalOutbox.MarkOutboxMaterialized(ctx, messageID, owner, now)
}

func TestMaterializerPersistsDeliveryBeforeCompletingOutbox(t *testing.T) {
	ctx := context.Background()
	runs, terminalAt, internalRunID := terminalRunStore(t)
	deliveries, err := delivery.OpenSQLite(filepath.Join(privateTestDir(t), "delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer deliveries.Close()
	message := publicMessage(t, terminalAt)
	builder := &staticMessageBuilder{message: message}
	materializer, err := delivery.NewMaterializer(delivery.MaterializerConfig{
		Outbox: runs, Deliveries: deliveries, Builder: builder,
		Owner: "materializer-a", Now: func() time.Time { return terminalAt.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := materializer.MaterializeNext(ctx)
	if err != nil || !processed || builder.calls != 1 {
		t.Fatalf("MaterializeNext()=(%v,%v), calls=%d", processed, err, builder.calls)
	}
	record, err := deliveries.Get(ctx, message.DeliveryID)
	if err != nil || record.State != delivery.StatePending || record.Message.RunRef != message.RunRef {
		t.Fatalf("delivery record=%+v err=%v", record, err)
	}
	outbox, err := runs.ListOutbox(ctx, internalRunID)
	if err != nil || len(outbox) != 1 || outbox[0].State != inspectionstore.OutboxMaterialized {
		t.Fatalf("outbox=%+v err=%v", outbox, err)
	}
}

func TestMaterializerCrashAfterEnqueueReplaysWithoutDuplicateDelivery(t *testing.T) {
	ctx := context.Background()
	runs, terminalAt, internalRunID := terminalRunStore(t)
	deliveries, err := delivery.OpenSQLite(filepath.Join(privateTestDir(t), "delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer deliveries.Close()
	message := publicMessage(t, terminalAt)
	builder := &staticMessageBuilder{message: message}
	firstOutbox := &failingMarkOutbox{TerminalOutbox: runs, fail: true}
	first, err := delivery.NewMaterializer(delivery.MaterializerConfig{
		Outbox: firstOutbox, Deliveries: deliveries, Builder: builder, Owner: "materializer-first",
		LeaseTTL: time.Minute, Now: func() time.Time { return terminalAt.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := first.MaterializeNext(ctx); !processed || err == nil {
		t.Fatalf("first MaterializeNext()=(%v,%v)", processed, err)
	}
	if _, err := deliveries.Get(ctx, message.DeliveryID); err != nil {
		t.Fatalf("delivery was not committed before injected crash: %v", err)
	}

	retryAt := terminalAt.Add(2 * time.Minute)
	second, err := delivery.NewMaterializer(delivery.MaterializerConfig{
		Outbox: runs, Deliveries: deliveries, Builder: builder, Owner: "materializer-second",
		LeaseTTL: time.Minute, Now: func() time.Time { return retryAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := second.MaterializeNext(ctx); err != nil || !processed {
		t.Fatalf("replayed MaterializeNext()=(%v,%v)", processed, err)
	}
	if builder.calls != 2 {
		t.Fatalf("builder calls=%d want 2", builder.calls)
	}
	outbox, err := runs.ListOutbox(ctx, internalRunID)
	if err != nil || len(outbox) != 1 || outbox[0].State != inspectionstore.OutboxMaterialized || outbox[0].Attempts != 2 {
		t.Fatalf("replayed outbox=%+v err=%v", outbox, err)
	}
	record, err := deliveries.Get(ctx, message.DeliveryID)
	if err != nil || record.Attempts != 0 || record.State != delivery.StatePending {
		t.Fatalf("idempotent delivery=%+v err=%v", record, err)
	}
}

func TestMaterializerDoesNotCompleteOutboxWhenMessageBuildFails(t *testing.T) {
	ctx := context.Background()
	runs, terminalAt, internalRunID := terminalRunStore(t)
	deliveries, err := delivery.OpenSQLite(filepath.Join(privateTestDir(t), "delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer deliveries.Close()
	builder := &staticMessageBuilder{err: errors.New("projection unavailable")}
	materializer, err := delivery.NewMaterializer(delivery.MaterializerConfig{
		Outbox: runs, Deliveries: deliveries, Builder: builder,
		Owner: "materializer-failure", Now: func() time.Time { return terminalAt.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := materializer.MaterializeNext(ctx); !processed || err == nil {
		t.Fatalf("MaterializeNext()=(%v,%v)", processed, err)
	}
	outbox, err := runs.ListOutbox(ctx, internalRunID)
	if err != nil || len(outbox) != 1 || outbox[0].State != inspectionstore.OutboxMaterializing {
		t.Fatalf("failed outbox=%+v err=%v", outbox, err)
	}
}

func terminalRunStore(t *testing.T) (*inspectionstore.Store, time.Time, string) {
	t.Helper()
	store, err := inspectionstore.Open(filepath.Join(privateTestDir(t), "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	plan, err := inspectiontest.SceneExecutionPlan()
	if err != nil {
		t.Fatal(err)
	}
	runID := "run_materializer_fixture"
	if _, created, err := store.CreateQueuedRun(context.Background(), plan, runID, plan.RequestedAt); err != nil || !created {
		t.Fatalf("CreateQueuedRun() created=%v err=%v", created, err)
	}
	terminalAt := plan.RequestedAt.Add(time.Second)
	if err := store.Cancel(context.Background(), runID, terminalAt, "fixture_cancelled"); err != nil {
		t.Fatal(err)
	}
	return store, terminalAt, runID
}

func publicMessage(t *testing.T, createdAt time.Time) delivery.Message {
	t.Helper()
	message, err := delivery.NewMessage(
		"public-run-a", "public-result-a",
		delivery.Audience{
			TenantID: "tenant-fixture", SiteID: "site-fixture", Channel: "workbuddy-wechat",
			ConversationRef: "conversation-a", RecipientRef: "recipient-a",
		},
		delivery.Presentation{Title: "巡检结果", Summary: "本次巡检已完成。"}, nil, createdAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}
