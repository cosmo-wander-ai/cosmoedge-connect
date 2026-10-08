package delivery

import (
	"context"
	"errors"
	"reflect"
	"time"
)

type SendOutcome string

const (
	SendDelivered    SendOutcome = "delivered"
	SendNotDelivered SendOutcome = "not_delivered"
	SendUnknown      SendOutcome = "unknown"
)

type SendRequest struct {
	DeliveryID     string
	IdempotencyKey string
	Audience       Audience
	AudienceSHA256 string
	Presentation   Presentation
	Attachments    []Attachment
}

type SendResult struct {
	Outcome    SendOutcome
	ReceiptRef string
	Reason     string
	RetryAfter time.Duration
}

type Transport interface {
	// Send must stop on context cancellation and must not complete a channel
	// side effect after returning from the cancelled call.
	Send(context.Context, SendRequest) (SendResult, error)
}

type ReconciliationRequest struct {
	DeliveryID     string
	IdempotencyKey string
	AudienceSHA256 string
}

type Reconciler interface {
	// Lookup must stop on context cancellation. It is read-only and may be
	// repeated after a reconciliation lease is recovered.
	Lookup(context.Context, ReconciliationRequest) (Reconciliation, string, error)
}

type DispatcherConfig struct {
	Store         Store
	Transport     Transport
	Reconciler    Reconciler
	Owner         string
	LeaseTTL      time.Duration
	SendTimeout   time.Duration
	LookupTimeout time.Duration
	Now           func() time.Time
}

type Dispatcher struct {
	store         Store
	transport     Transport
	reconciler    Reconciler
	owner         string
	leaseTTL      time.Duration
	sendTimeout   time.Duration
	lookupTimeout time.Duration
	now           func() time.Time
}

func NewDispatcher(config DispatcherConfig) (*Dispatcher, error) {
	if nilDependency(config.Store) || nilDependency(config.Transport) || nilDependency(config.Reconciler) ||
		!validRef(config.Owner) || config.LeaseTTL <= 0 || config.LeaseTTL > 10*time.Minute ||
		!validCallTimeout(config.SendTimeout, config.LeaseTTL) || !validCallTimeout(config.LookupTimeout, config.LeaseTTL) ||
		config.Now == nil {
		return nil, errors.New("inspection delivery dispatcher dependencies are required")
	}
	return &Dispatcher{
		store: config.Store, transport: config.Transport, reconciler: config.Reconciler,
		owner: config.Owner, leaseTTL: config.LeaseTTL, sendTimeout: config.SendTimeout,
		lookupTimeout: config.LookupTimeout, now: config.Now,
	}, nil
}

// Recover advances only expired leases. It never sends or reconciles, and is
// deliberately separate from both worker queues so startup controls when
// interrupted state becomes eligible for channel lookup.
func (d *Dispatcher) Recover(ctx context.Context) (Recovery, error) {
	now, err := d.currentTime()
	if err != nil {
		return Recovery{}, err
	}
	return d.store.RecoverExpired(ctx, now)
}

func (d *Dispatcher) DeliverNext(ctx context.Context) (bool, error) {
	now, err := d.currentTime()
	if err != nil {
		return false, err
	}
	record, attempt, ok, err := d.store.Claim(ctx, d.owner, now, d.leaseTTL)
	if err != nil || !ok {
		return ok, err
	}
	message := record.Message
	sendContext, cancelSend := context.WithTimeout(ctx, d.sendTimeout)
	result, sendErr := d.transport.Send(sendContext, SendRequest{
		DeliveryID: message.DeliveryID, IdempotencyKey: message.IdempotencyKey,
		Audience: message.Audience, AudienceSHA256: message.AudienceSHA256,
		Presentation: message.Presentation, Attachments: append([]Attachment(nil), message.Attachments...),
	})
	cancelSend()
	finishedAt, clockErr := d.currentTime()
	if clockErr != nil {
		return true, clockErr
	}
	if sendErr != nil {
		return true, d.markUnknown(ctx, attempt, "transport_returned_error", finishedAt)
	}
	switch result.Outcome {
	case SendDelivered:
		if !validRef(result.ReceiptRef) {
			return true, d.markUnknown(ctx, attempt, "transport_receipt_invalid", finishedAt)
		}
		return true, d.store.MarkDelivered(ctx, attempt, result.ReceiptRef, finishedAt)
	case SendNotDelivered:
		if !safeReason(result.Reason) || result.RetryAfter < 0 || result.RetryAfter > 24*time.Hour {
			return true, d.markUnknown(ctx, attempt, "transport_failure_invalid", finishedAt)
		}
		return true, d.store.MarkNotDelivered(ctx, attempt, result.Reason, finishedAt, result.RetryAfter)
	case SendUnknown:
		reason := result.Reason
		if !safeReason(reason) {
			reason = "transport_outcome_unknown"
		}
		return true, d.markUnknown(ctx, attempt, reason, finishedAt)
	default:
		return true, d.markUnknown(ctx, attempt, "transport_outcome_invalid", finishedAt)
	}
}

func (d *Dispatcher) ReconcileNext(ctx context.Context) (bool, error) {
	now, err := d.currentTime()
	if err != nil {
		return false, err
	}
	record, attempt, ok, err := d.store.ClaimReconciliation(ctx, d.owner, now, d.leaseTTL)
	if err != nil || !ok {
		return ok, err
	}
	lookupContext, cancelLookup := context.WithTimeout(ctx, d.lookupTimeout)
	decision, evidence, lookupErr := d.reconciler.Lookup(lookupContext, ReconciliationRequest{
		DeliveryID: record.Message.DeliveryID, IdempotencyKey: record.Message.IdempotencyKey,
		AudienceSHA256: record.Message.AudienceSHA256,
	})
	cancelLookup()
	finishedAt, clockErr := d.currentTime()
	if clockErr != nil {
		return true, clockErr
	}
	if lookupErr != nil {
		finishErr := d.store.Reconcile(ctx, attempt, ReconciliationUnknown, "delivery_reconciliation_failed", finishedAt)
		if finishErr != nil {
			return true, finishErr
		}
		return true, ErrOutcomeUnknown
	}
	var invalidResult bool
	switch decision {
	case ReconciliationDelivered:
		if !validRef(evidence) {
			decision, evidence, invalidResult = ReconciliationUnknown, "delivery_reconciliation_invalid", true
		}
	case ReconciliationNotDelivered:
		if !safeReason(evidence) {
			decision, evidence, invalidResult = ReconciliationUnknown, "delivery_reconciliation_invalid", true
		}
	case ReconciliationUnknown:
		if !safeReason(evidence) {
			evidence = "delivery_reconciliation_inconclusive"
		}
	default:
		decision, evidence, invalidResult = ReconciliationUnknown, "delivery_reconciliation_invalid", true
	}
	finishErr := d.store.Reconcile(ctx, attempt, decision, evidence, finishedAt)
	if invalidResult {
		return true, errors.Join(ErrInvalid, finishErr)
	}
	return true, finishErr
}

func (d *Dispatcher) markUnknown(ctx context.Context, attempt Attempt, reason string, at time.Time) error {
	if err := d.store.MarkOutcomeUnknown(ctx, attempt, reason, at); err != nil {
		return err
	}
	return ErrOutcomeUnknown
}

func (d *Dispatcher) currentTime() (time.Time, error) {
	if d == nil || d.now == nil {
		return time.Time{}, ErrInvalid
	}
	now := d.now().UTC()
	if now.IsZero() {
		return time.Time{}, ErrInvalid
	}
	return now, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validCallTimeout(timeout, leaseTTL time.Duration) bool {
	return timeout > 0 && timeout <= leaseTTL/2
}
