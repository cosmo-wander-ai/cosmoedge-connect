package delivery

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

// TemporaryTerminalOutbox is the exact durable terminal-event boundary owned
// by the temporary observation runtime. The lease is acknowledged only after
// the audience-bound delivery message has been durably enqueued.
type TemporaryTerminalOutbox interface {
	ClaimTerminalEvent(context.Context, string, time.Time, time.Duration) (temporary.TerminalLease, bool, error)
	AcknowledgeTerminalEvent(context.Context, temporary.TerminalLease, time.Time) error
}

type TemporaryMaterializerConfig struct {
	Outbox     TemporaryTerminalOutbox
	Deliveries Store
	Builder    TerminalMessageBuilder
	Owner      string
	LeaseTTL   time.Duration
	Now        func() time.Time
}

// TemporaryMaterializer converges temporary-observation terminal events on
// the same delivery store and message contract as standard inspections. A
// crash after Enqueue and before AcknowledgeTerminalEvent safely replays the
// stable message identity instead of producing a second delivery.
type TemporaryMaterializer struct {
	outbox     TemporaryTerminalOutbox
	deliveries Store
	builder    TerminalMessageBuilder
	owner      string
	leaseTTL   time.Duration
	now        func() time.Time
}

func NewTemporaryMaterializer(config TemporaryMaterializerConfig) (*TemporaryMaterializer, error) {
	if config.Outbox == nil || config.Deliveries == nil || config.Builder == nil || !validRef(config.Owner) {
		return nil, errors.New("temporary inspection delivery materializer dependencies are required")
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = defaultMaterializationLease
	}
	if config.LeaseTTL <= 0 || config.LeaseTTL > temporary.MaxLeaseTTL {
		return nil, errors.New("temporary inspection delivery materializer lease is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &TemporaryMaterializer{
		outbox: config.Outbox, deliveries: config.Deliveries, builder: config.Builder,
		owner: config.Owner, leaseTTL: config.LeaseTTL, now: config.Now,
	}, nil
}

func (m *TemporaryMaterializer) MaterializeNext(ctx context.Context) (bool, error) {
	if m == nil {
		return false, errors.New("temporary inspection delivery materializer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := m.now().UTC()
	if now.IsZero() {
		return false, errors.New("temporary inspection delivery materializer clock returned zero")
	}
	lease, ok, err := m.outbox.ClaimTerminalEvent(ctx, m.owner, now, m.leaseTTL)
	if err != nil || !ok {
		return ok, err
	}
	if lease.Event.Schema != temporary.TerminalSchemaVersion || !lease.Event.State.Terminal() ||
		!validRef(lease.Event.EventID) || !validRef(lease.Event.RunID) || !validRef(lease.Event.PublicRunRef) ||
		lease.Event.OccurredAt.IsZero() || lease.Event.OccurredAt.After(now) {
		return true, errors.New("temporary inspection terminal event is invalid")
	}
	message, err := m.builder.BuildDeliveryMessage(ctx, lease.Event.RunID)
	if err != nil {
		return true, err
	}
	if message.Validate() != nil || message.RunRef != lease.Event.PublicRunRef {
		return true, errors.New("temporary inspection terminal delivery message is invalid")
	}
	if _, err := m.deliveries.Enqueue(ctx, message); err != nil {
		return true, err
	}
	acknowledgedAt := m.now().UTC()
	if acknowledgedAt.IsZero() {
		return true, errors.New("temporary inspection delivery materializer clock returned zero")
	}
	if err := m.outbox.AcknowledgeTerminalEvent(ctx, lease, acknowledgedAt); err != nil {
		return true, err
	}
	return true, nil
}

// OutboxProcessor is the common product pump boundary for every terminal
// event source. It is deliberately smaller than either runtime store.
type OutboxProcessor interface {
	MaterializeNext(context.Context) (bool, error)
}

// MaterializerGroup fairly drains multiple terminal-event sources into one
// delivery queue. It is safe for concurrent callers even though the product
// normally owns a single pump goroutine.
type MaterializerGroup struct {
	mu      sync.Mutex
	sources []OutboxProcessor
	next    int
}

func NewMaterializerGroup(sources ...OutboxProcessor) (*MaterializerGroup, error) {
	if len(sources) < 2 || len(sources) > 16 {
		return nil, errors.New("inspection delivery materializer group requires two to sixteen sources")
	}
	result := &MaterializerGroup{sources: append([]OutboxProcessor(nil), sources...)}
	for _, source := range result.sources {
		if source == nil {
			return nil, errors.New("inspection delivery materializer group contains a nil source")
		}
	}
	return result, nil
}

func (g *MaterializerGroup) MaterializeNext(ctx context.Context) (bool, error) {
	if g == nil {
		return false, errors.New("inspection delivery materializer group is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for offset := 0; offset < len(g.sources); offset++ {
		index := (g.next + offset) % len(g.sources)
		processed, err := g.sources[index].MaterializeNext(ctx)
		if err != nil {
			g.next = (index + 1) % len(g.sources)
			return processed, err
		}
		if processed {
			g.next = (index + 1) % len(g.sources)
			return true, nil
		}
	}
	g.next = (g.next + 1) % len(g.sources)
	return false, nil
}
