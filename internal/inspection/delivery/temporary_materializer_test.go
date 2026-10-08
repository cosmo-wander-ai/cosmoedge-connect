package delivery

import (
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

type temporaryMessageBuilder struct {
	message       Message
	expectedRunID string
	calls         int
}

func (b *temporaryMessageBuilder) BuildDeliveryMessage(_ context.Context, runID string) (Message, error) {
	b.calls++
	if runID != b.expectedRunID {
		return Message{}, errors.New("unexpected run")
	}
	return b.message, nil
}

type acknowledgeFailingTemporaryOutbox struct {
	*temporary.SQLiteStore
	fail bool
}

func (s *acknowledgeFailingTemporaryOutbox) AcknowledgeTerminalEvent(ctx context.Context, lease temporary.TerminalLease, at time.Time) error {
	if s.fail {
		s.fail = false
		return errors.New("injected acknowledgement interruption")
	}
	return s.SQLiteStore.AcknowledgeTerminalEvent(ctx, lease, at)
}

func TestTemporaryMaterializerEnqueuesAndAcknowledgesOneTerminalEvent(t *testing.T) {
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	fixture := terminalTemporaryStore(t, now)
	deliveries := NewMemoryStore()
	message := terminalTemporaryMessage(t, now)
	builder := &temporaryMessageBuilder{message: message, expectedRunID: fixture.runID}
	materializer, err := NewTemporaryMaterializer(TemporaryMaterializerConfig{
		Outbox: fixture.store, Deliveries: deliveries, Builder: builder,
		Owner: "temporary-materializer", LeaseTTL: time.Minute, Now: func() time.Time { return now.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := materializer.MaterializeNext(context.Background())
	if err != nil || !processed || builder.calls != 1 {
		t.Fatalf("MaterializeNext()=(%v,%v), calls=%d", processed, err, builder.calls)
	}
	record, err := deliveries.Get(context.Background(), message.DeliveryID)
	if err != nil || record.Message.RunRef != "public-run" || record.State != StatePending {
		t.Fatalf("delivery=%+v err=%v", record, err)
	}
	if processed, err := materializer.MaterializeNext(context.Background()); err != nil || processed {
		t.Fatalf("second MaterializeNext()=(%v,%v)", processed, err)
	}
}

func TestTemporaryMaterializerCrashAfterEnqueueReplaysWithoutDuplicateDelivery(t *testing.T) {
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	fixture := terminalTemporaryStore(t, now)
	deliveries := NewMemoryStore()
	builder := &temporaryMessageBuilder{message: terminalTemporaryMessage(t, now), expectedRunID: fixture.runID}
	outbox := &acknowledgeFailingTemporaryOutbox{SQLiteStore: fixture.store, fail: true}
	first, err := NewTemporaryMaterializer(TemporaryMaterializerConfig{
		Outbox: outbox, Deliveries: deliveries, Builder: builder,
		Owner: "temporary-materializer-a", LeaseTTL: time.Second, Now: func() time.Time { return now.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := first.MaterializeNext(context.Background()); !processed || err == nil {
		t.Fatalf("interrupted MaterializeNext()=(%v,%v)", processed, err)
	}

	second, err := NewTemporaryMaterializer(TemporaryMaterializerConfig{
		Outbox: fixture.store, Deliveries: deliveries, Builder: builder,
		Owner: "temporary-materializer-b", LeaseTTL: time.Minute, Now: func() time.Time { return now.Add(3 * time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := second.MaterializeNext(context.Background()); err != nil || !processed {
		t.Fatalf("replayed MaterializeNext()=(%v,%v)", processed, err)
	}
	record, err := deliveries.Get(context.Background(), builder.message.DeliveryID)
	if err != nil || record.Attempts != 0 || builder.calls != 2 {
		t.Fatalf("replayed delivery=%+v calls=%d err=%v", record, builder.calls, err)
	}
	if processed, err := second.MaterializeNext(context.Background()); err != nil || processed {
		t.Fatalf("post-ack MaterializeNext()=(%v,%v)", processed, err)
	}
}

type scriptedProcessor struct {
	results []bool
	calls   int
}

func (p *scriptedProcessor) MaterializeNext(context.Context) (bool, error) {
	p.calls++
	if len(p.results) == 0 {
		return false, nil
	}
	result := p.results[0]
	p.results = p.results[1:]
	return result, nil
}

func TestMaterializerGroupFairlyDrainsStandardAndTemporarySources(t *testing.T) {
	standard := &scriptedProcessor{results: []bool{true, true}}
	temporarySource := &scriptedProcessor{results: []bool{true, true}}
	group, err := NewMaterializerGroup(standard, temporarySource)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		if processed, err := group.MaterializeNext(context.Background()); err != nil || !processed {
			t.Fatalf("pass %d=(%v,%v)", index, processed, err)
		}
	}
	if standard.calls != 2 || temporarySource.calls != 2 {
		t.Fatalf("unfair calls standard=%d temporary=%d", standard.calls, temporarySource.calls)
	}
	if processed, err := group.MaterializeNext(context.Background()); err != nil || processed {
		t.Fatalf("empty group=(%v,%v)", processed, err)
	}
}

type temporaryTerminalFixture struct {
	store *temporary.SQLiteStore
	runID string
}

func terminalTemporaryStore(t *testing.T, now time.Time) temporaryTerminalFixture {
	t.Helper()
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	store, err := temporary.OpenSQLite(filepath.Join(root, "temporary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	spec, err := temporary.NewSpec(temporary.Intent{
		Subject: "现场环境", Region: "可见区域", Observable: "说明画面中可见的整洁情况。",
		Locale: "zh-CN", TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
		EvidenceTTLSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := temporary.AuthenticatedBinding{
		TenantID: "tenant", SiteID: "site", RequestKey: "request-key", PublicRunRef: "public-run",
		Channel: "workbuddy", ConversationRef: "conversation", RecipientRef: "recipient",
		PrincipalSHA256: strings.Repeat("a", 64),
	}
	audience, err := temporary.FreezeAudience(temporary.ChannelSession{
		TenantID: binding.TenantID, SiteID: binding.SiteID, Channel: binding.Channel,
		ConversationRef: binding.ConversationRef, RecipientRef: binding.RecipientRef, PrincipalSHA256: binding.PrincipalSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	preparationRef, err := mediaprep.PreparationRefForScope(binding.TenantID, binding.SiteID, binding.RequestKey)
	if err != nil {
		t.Fatal(err)
	}
	submittedAt := now.Add(-time.Minute)
	record, created, err := store.Submit(context.Background(), temporary.Submission{
		Binding: binding, Spec: spec, PreparationRef: preparationRef, MediaKind: media.KindImage,
		AudienceBindingRef: audience.Ref, AudienceSHA256: audience.SHA256,
		EvidenceExpiresAt: submittedAt.Add(5 * time.Minute), SubmittedAt: submittedAt, DeadlineAt: now.Add(time.Minute),
	}, submittedAt)
	if err != nil || !created {
		t.Fatalf("Submit()=(%+v,%v,%v)", record, created, err)
	}
	_, lease, claimed, err := store.Claim(context.Background(), "runtime-owner", now.Add(-30*time.Second), time.Minute)
	if err != nil || !claimed {
		t.Fatalf("Claim()=(%+v,%v,%v)", lease, claimed, err)
	}
	terminal, err := store.CompleteDefiniteFailure(context.Background(), lease, temporary.ReasonMediaUnavailable, now)
	if err != nil || terminal.RunID == "" {
		t.Fatalf("CompleteDefiniteFailure()=(%+v,%v)", terminal, err)
	}
	return temporaryTerminalFixture{store: store, runID: terminal.RunID}
}

func terminalTemporaryMessage(t *testing.T, now time.Time) Message {
	t.Helper()
	message, err := NewMessage("public-run", "result_public-run", Audience{
		TenantID: "tenant", SiteID: "site", Channel: "workbuddy",
		ConversationRef: "conversation", RecipientRef: "recipient",
	}, Presentation{Title: "巡检结果", Summary: "本次临时查看已完成。"}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	return message
}
