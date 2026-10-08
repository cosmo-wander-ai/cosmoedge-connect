package delivery

import (
	"context"
	"errors"
	"time"

	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
)

const defaultMaterializationLease = time.Minute

// TerminalOutbox is the exact durable seam between terminal inspection state
// and channel delivery. Materialization may be replayed; sending may not.
type TerminalOutbox interface {
	RecoverOutboxClaims(context.Context, time.Time) (int, error)
	ClaimOutbox(context.Context, string, time.Time, time.Duration) (inspectionstore.OutboxMessage, bool, error)
	MarkOutboxMaterialized(context.Context, string, string, time.Time) error
}

// TerminalMessageBuilder resolves one internal terminal run to exactly one
// audience-bound message containing public references only.
type TerminalMessageBuilder interface {
	BuildDeliveryMessage(context.Context, string) (Message, error)
}

type MaterializerConfig struct {
	Outbox     TerminalOutbox
	Deliveries Store
	Builder    TerminalMessageBuilder
	Owner      string
	LeaseTTL   time.Duration
	Now        func() time.Time
}

// Materializer atomically claims terminal notifications and idempotently
// enqueues delivery messages. A crash after Enqueue and before
// MarkOutboxMaterialized is safe: the stable delivery identity is verified by
// Store.Enqueue before the outbox record is marked complete.
type Materializer struct {
	outbox     TerminalOutbox
	deliveries Store
	builder    TerminalMessageBuilder
	owner      string
	leaseTTL   time.Duration
	now        func() time.Time
}

func NewMaterializer(config MaterializerConfig) (*Materializer, error) {
	if config.Outbox == nil || config.Deliveries == nil || config.Builder == nil || !validRef(config.Owner) {
		return nil, errors.New("inspection delivery materializer dependencies are required")
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = defaultMaterializationLease
	}
	if config.LeaseTTL <= 0 || config.LeaseTTL > 10*time.Minute {
		return nil, errors.New("inspection delivery materializer lease is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Materializer{
		outbox: config.Outbox, deliveries: config.Deliveries, builder: config.Builder,
		owner: config.Owner, leaseTTL: config.LeaseTTL, now: config.Now,
	}, nil
}

func (m *Materializer) MaterializeNext(ctx context.Context) (bool, error) {
	if m == nil {
		return false, errors.New("inspection delivery materializer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := m.now().UTC()
	if now.IsZero() {
		return false, errors.New("inspection delivery materializer clock returned zero")
	}
	if _, err := m.outbox.RecoverOutboxClaims(ctx, now); err != nil {
		return false, err
	}
	notification, ok, err := m.outbox.ClaimOutbox(ctx, m.owner, now, m.leaseTTL)
	if err != nil || !ok {
		return ok, err
	}
	if notification.Topic != "inspection.run.terminal" || notification.RunID == "" {
		return true, errors.New("inspection terminal outbox topic is invalid")
	}
	message, err := m.builder.BuildDeliveryMessage(ctx, notification.RunID)
	if err != nil {
		return true, err
	}
	if err := message.Validate(); err != nil {
		return true, errors.New("inspection terminal delivery message is invalid")
	}
	if _, err := m.deliveries.Enqueue(ctx, message); err != nil {
		return true, err
	}
	if err := m.outbox.MarkOutboxMaterialized(ctx, notification.MessageID, m.owner, m.now().UTC()); err != nil {
		return true, err
	}
	return true, nil
}
