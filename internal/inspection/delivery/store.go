package delivery

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	maxAttempts              = 8
	reconciliationRetryDelay = time.Minute
)

type Store interface {
	Enqueue(context.Context, Message) (Record, error)
	Get(context.Context, string) (Record, error)
	Claim(context.Context, string, time.Time, time.Duration) (Record, Attempt, bool, error)
	ClaimReconciliation(context.Context, string, time.Time, time.Duration) (Record, ReconciliationAttempt, bool, error)
	MarkDelivered(context.Context, Attempt, string, time.Time) error
	MarkNotDelivered(context.Context, Attempt, string, time.Time, time.Duration) error
	MarkOutcomeUnknown(context.Context, Attempt, string, time.Time) error
	Reconcile(context.Context, ReconciliationAttempt, Reconciliation, string, time.Time) error
	Acknowledge(context.Context, Acknowledgement) error
	RecoverExpired(context.Context, time.Time) (Recovery, error)
}

type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{records: make(map[string]Record)} }

func (s *MemoryStore) Enqueue(_ context.Context, message Message) (Record, error) {
	if s == nil || message.Validate() != nil {
		return Record{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.records[message.DeliveryID]; ok {
		left, _ := messageDigest(current.Message)
		right, _ := messageDigest(message)
		if left != right {
			return Record{}, ErrConflict
		}
		return cloneRecord(current), nil
	}
	record := Record{Message: message, State: StatePending, AvailableAt: message.CreatedAt, Reason: "delivery_enqueued", UpdatedAt: message.CreatedAt}
	s.records[message.DeliveryID] = record
	return cloneRecord(record), nil
}

func (s *MemoryStore) Get(_ context.Context, deliveryID string) (Record, error) {
	if s == nil || !validRef(deliveryID) {
		return Record{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[deliveryID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) Claim(_ context.Context, owner string, now time.Time, leaseTTL time.Duration) (Record, Attempt, bool, error) {
	if s == nil || !validRef(owner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 10*time.Minute {
		return Record{}, Attempt{}, false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		record := s.records[id]
		if record.State != StatePending || record.AvailableAt.After(now) {
			continue
		}
		if record.Attempts >= maxAttempts {
			record.State, record.Reason, record.UpdatedAt = StateFailed, "delivery_attempt_budget_exhausted", now.UTC()
			s.records[id] = record
			continue
		}
		record.State, record.Attempts = StateSending, record.Attempts+1
		record.LeaseOwner, record.LeaseExpiresAt = owner, now.UTC().Add(leaseTTL)
		record.Reason, record.UpdatedAt = "delivery_claimed", now.UTC()
		s.records[id] = record
		attempt := Attempt{
			AttemptID: attemptID(id, record.Attempts), DeliveryID: id, Number: record.Attempts,
			Owner: owner, LeaseExpiresAt: record.LeaseExpiresAt, StartedAt: now.UTC(),
		}
		return cloneRecord(record), attempt, true, nil
	}
	return Record{}, Attempt{}, false, nil
}

func (s *MemoryStore) ClaimReconciliation(_ context.Context, owner string, now time.Time, leaseTTL time.Duration) (Record, ReconciliationAttempt, bool, error) {
	if s == nil || !validRef(owner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 10*time.Minute {
		return Record{}, ReconciliationAttempt{}, false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		record := s.records[id]
		if record.State != StateOutcomeUnknown || record.LeaseOwner != "" || record.AvailableAt.After(now) {
			continue
		}
		record.ReconciliationAttempts++
		record.LeaseOwner, record.LeaseExpiresAt = owner, now.UTC().Add(leaseTTL)
		record.Reason, record.UpdatedAt = "delivery_reconciliation_claimed", now.UTC()
		s.records[id] = record
		attempt := ReconciliationAttempt{
			DeliveryID: id, IdempotencyKey: record.Message.IdempotencyKey,
			AudienceSHA256: record.Message.AudienceSHA256, Number: record.ReconciliationAttempts,
			Owner: owner, LeaseExpiresAt: record.LeaseExpiresAt, StartedAt: now.UTC(),
		}
		return cloneRecord(record), attempt, true, nil
	}
	return Record{}, ReconciliationAttempt{}, false, nil
}

func (s *MemoryStore) MarkDelivered(_ context.Context, attempt Attempt, receiptRef string, at time.Time) error {
	return s.finish(attempt, StateDelivered, receiptRef, "delivery_receipt_recorded", at, 0)
}

func (s *MemoryStore) MarkNotDelivered(_ context.Context, attempt Attempt, reason string, at time.Time, retryAfter time.Duration) error {
	if retryAfter < 0 || retryAfter > 24*time.Hour {
		return ErrInvalid
	}
	return s.finish(attempt, StatePending, "", reason, at, retryAfter)
}

func (s *MemoryStore) MarkOutcomeUnknown(_ context.Context, attempt Attempt, reason string, at time.Time) error {
	return s.finish(attempt, StateOutcomeUnknown, "", reason, at, 0)
}

func (s *MemoryStore) finish(attempt Attempt, state State, receiptRef, reason string, at time.Time, retryAfter time.Duration) error {
	if s == nil || !validAttempt(attempt) || at.IsZero() || !safeReason(reason) ||
		at.Before(attempt.StartedAt) ||
		(state == StateDelivered) != validRef(receiptRef) || state != StateDelivered && state != StatePending && state != StateOutcomeUnknown {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[attempt.DeliveryID]
	if !ok || record.State != StateSending || record.Attempts != attempt.Number || record.LeaseOwner != attempt.Owner ||
		!at.Before(record.LeaseExpiresAt) || record.LeaseExpiresAt != attempt.LeaseExpiresAt {
		return ErrLeaseLost
	}
	record.State, record.Reason, record.UpdatedAt = state, reason, at.UTC()
	record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
	if state == StateDelivered {
		record.ReceiptRef, record.DeliveredAt, record.AvailableAt = receiptRef, at.UTC(), at.UTC()
	} else if state == StatePending {
		record.AvailableAt = at.UTC().Add(retryAfter)
	} else {
		record.AvailableAt = at.UTC()
	}
	s.records[attempt.DeliveryID] = record
	return nil
}

func (s *MemoryStore) Reconcile(_ context.Context, attempt ReconciliationAttempt, decision Reconciliation, receiptOrReason string, at time.Time) error {
	if s == nil || !validReconciliationAttempt(attempt) || at.IsZero() || at.Before(attempt.StartedAt) ||
		(decision != ReconciliationDelivered && decision != ReconciliationNotDelivered && decision != ReconciliationUnknown) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[attempt.DeliveryID]
	if !ok {
		return ErrNotFound
	}
	if record.State != StateOutcomeUnknown || record.ReconciliationAttempts != attempt.Number ||
		record.LeaseOwner != attempt.Owner || record.LeaseExpiresAt != attempt.LeaseExpiresAt ||
		!at.Before(record.LeaseExpiresAt) || record.Message.IdempotencyKey != attempt.IdempotencyKey ||
		record.Message.AudienceSHA256 != attempt.AudienceSHA256 {
		return ErrLeaseLost
	}
	if at.Before(record.UpdatedAt) {
		return ErrInvalid
	}
	switch decision {
	case ReconciliationDelivered:
		if !validRef(receiptOrReason) {
			return ErrInvalid
		}
		record.State, record.ReceiptRef, record.DeliveredAt, record.Reason = StateDelivered, receiptOrReason, at.UTC(), "delivery_reconciled_delivered"
		record.AvailableAt = at.UTC()
	case ReconciliationNotDelivered:
		if !safeReason(receiptOrReason) {
			return ErrInvalid
		}
		record.State, record.AvailableAt, record.Reason = StatePending, at.UTC(), receiptOrReason
	case ReconciliationUnknown:
		if !safeReason(receiptOrReason) {
			return ErrInvalid
		}
		record.Reason = receiptOrReason
		record.AvailableAt = at.UTC().Add(reconciliationRetryDelay)
	}
	record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
	record.UpdatedAt = at.UTC()
	s.records[attempt.DeliveryID] = record
	return nil
}

func (s *MemoryStore) Acknowledge(_ context.Context, acknowledgement Acknowledgement) error {
	if s == nil || !validAcknowledgement(acknowledgement) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[acknowledgement.DeliveryID]
	if !ok {
		return ErrNotFound
	}
	if record.Message.IdempotencyKey != acknowledgement.IdempotencyKey || record.Message.AudienceSHA256 != acknowledgement.AudienceSHA256 {
		return ErrConflict
	}
	if acknowledgement.ObservedAt.Before(record.Message.CreatedAt) {
		return ErrInvalid
	}
	if record.State == StateDelivered {
		if record.ReceiptRef == acknowledgement.ReceiptRef {
			return nil
		}
		return ErrConflict
	}
	if !acknowledgeable(record) {
		return ErrConflict
	}
	committedAt := acknowledgement.ObservedAt.UTC()
	if committedAt.Before(record.UpdatedAt) {
		committedAt = record.UpdatedAt
	}
	record.State, record.ReceiptRef, record.DeliveredAt = StateDelivered, acknowledgement.ReceiptRef, committedAt
	record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
	record.Reason, record.UpdatedAt = "channel_acknowledged", committedAt
	s.records[acknowledgement.DeliveryID] = record
	return nil
}

func (s *MemoryStore) RecoverExpired(_ context.Context, now time.Time) (Recovery, error) {
	if s == nil || now.IsZero() {
		return Recovery{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recovery := Recovery{}
	for id, record := range s.records {
		if record.State == StateSending && !record.LeaseExpiresAt.After(now) {
			record.State, record.Reason, record.UpdatedAt, record.AvailableAt =
				StateOutcomeUnknown, "delivery_worker_interrupted", now.UTC(), now.UTC()
			record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
			s.records[id] = record
			recovery.SendingBecameUnknown++
			continue
		}
		if record.State == StateOutcomeUnknown && record.LeaseOwner != "" && !record.LeaseExpiresAt.After(now) {
			record.Reason, record.UpdatedAt, record.AvailableAt = "delivery_reconciliation_interrupted", now.UTC(), now.UTC()
			record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
			s.records[id] = record
			recovery.ReconciliationLeaseFreed++
		}
	}
	return recovery, nil
}

func attemptID(deliveryID string, number int) string {
	return deliveryID + "_attempt_" + strconv.Itoa(number)
}

func validAttempt(attempt Attempt) bool {
	return validRef(attempt.AttemptID) && validRef(attempt.DeliveryID) && attempt.Number > 0 && attempt.Number <= maxAttempts &&
		validRef(attempt.Owner) && !attempt.StartedAt.IsZero() && attempt.LeaseExpiresAt.After(attempt.StartedAt)
}

func validReconciliationAttempt(attempt ReconciliationAttempt) bool {
	return validRef(attempt.DeliveryID) && attempt.IdempotencyKey == attempt.DeliveryID &&
		digestPattern.MatchString(attempt.AudienceSHA256) && attempt.Number > 0 && validRef(attempt.Owner) &&
		!attempt.StartedAt.IsZero() && attempt.LeaseExpiresAt.After(attempt.StartedAt)
}

func validAcknowledgement(acknowledgement Acknowledgement) bool {
	return validRef(acknowledgement.DeliveryID) && acknowledgement.IdempotencyKey == acknowledgement.DeliveryID &&
		digestPattern.MatchString(acknowledgement.AudienceSHA256) && validRef(acknowledgement.ReceiptRef) &&
		!acknowledgement.ObservedAt.IsZero()
}

func acknowledgeable(record Record) bool {
	return record.State == StateSending || record.State == StateOutcomeUnknown ||
		record.Attempts > 0 && (record.State == StatePending || record.State == StateFailed)
}

func safeReason(value string) bool { return safeText(value, 1, 128) }

func cloneRecord(record Record) Record {
	record.Message.Attachments = append([]Attachment(nil), record.Message.Attachments...)
	return record
}

var _ Store = (*MemoryStore)(nil)
