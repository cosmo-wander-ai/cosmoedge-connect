package delivery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

const (
	deliveryDatabaseVersion = 3
	deliveryApplicationID   = 0x43454432 // CED2
)

const createDeliveriesSQL = `CREATE TABLE deliveries (
    delivery_id TEXT PRIMARY KEY,
    message_json BLOB NOT NULL,
    message_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK(attempts >= 0 AND attempts <= 8),
    reconciliation_attempts INTEGER NOT NULL CHECK(reconciliation_attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    receipt_ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    delivered_at TEXT NOT NULL
);`

const createDeliveryClaimIndexSQL = `CREATE INDEX deliveries_claim_idx ON deliveries(state, available_at, delivery_id);`

const createDeliveryReconcileIndexSQL = `CREATE INDEX deliveries_reconcile_idx ON deliveries(state, lease_owner, available_at, delivery_id);`

const deliverySchema = createDeliveriesSQL + "\n" + createDeliveryClaimIndexSQL + "\n" + createDeliveryReconcileIndexSQL

const deliveryColumnList = `delivery_id, message_json, message_sha256, state, attempts, reconciliation_attempts, available_at,
lease_owner, lease_expires_at, receipt_ref, reason, updated_at, delivered_at`

const deliverySelect = `SELECT ` + deliveryColumnList + ` FROM deliveries`

type SQLiteStore struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00?#") {
		return nil, errors.New("inspection delivery store path is invalid")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing inspection delivery store: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		if closeErr := file.Close(); closeErr != nil {
			_ = os.Remove(absolute)
			return nil, closeErr
		}
		created = true
		if err := localstate.ProtectFile(absolute); err != nil {
			_ = os.Remove(absolute)
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", absolute)
	if err != nil {
		if created {
			_ = os.Remove(absolute)
		}
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.initialize(); err != nil {
		_ = db.Close()
		if created {
			_ = os.Remove(absolute)
		}
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) initialize() error {
	if _, err := s.db.Exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		return err
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if _, err := s.db.Exec(deliverySchema); err != nil {
			return err
		}
		if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA application_id=%d; PRAGMA user_version=%d;`, deliveryApplicationID, deliveryDatabaseVersion)); err != nil {
			return err
		}
	}
	var applicationID, version int
	if err := s.db.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return err
	}
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if applicationID != deliveryApplicationID || version != deliveryDatabaseVersion {
		return errors.New("inspection delivery store schema is unsupported; explicitly reset this development delivery store")
	}
	return validateDeliveryShape(s.db)
}

func validateDeliveryShape(db *sql.DB) error {
	expected := map[string]string{
		"deliveries":               createDeliveriesSQL,
		"deliveries_claim_idx":     createDeliveryClaimIndexSQL,
		"deliveries_reconcile_idx": createDeliveryReconcileIndexSQL,
	}
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	actual := make(map[string]string, len(expected))
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			return err
		}
		actual[name] = statement
	}
	if err := rows.Err(); err != nil || len(actual) != len(expected) {
		return errors.New("inspection delivery store object shape is invalid")
	}
	for name, statement := range expected {
		if normalizeDeliverySQL(actual[name]) != normalizeDeliverySQL(statement) {
			return fmt.Errorf("inspection delivery store object shape is invalid: %s", name)
		}
	}
	return nil
}

func normalizeDeliverySQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}

func (s *SQLiteStore) Enqueue(ctx context.Context, message Message) (Record, error) {
	if s == nil || message.Validate() != nil {
		return Record{}, ErrInvalid
	}
	raw, digest, err := marshalMessage(message)
	if err != nil {
		return Record{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO deliveries(
delivery_id, message_json, message_sha256, state, attempts, reconciliation_attempts, available_at, lease_owner, lease_expires_at,
receipt_ref, reason, updated_at, delivered_at) VALUES(?, ?, ?, ?, 0, 0, ?, '', '', '', 'delivery_enqueued', ?, '')
ON CONFLICT(delivery_id) DO NOTHING`, message.DeliveryID, raw, digest, StatePending, formatDeliveryTime(message.CreatedAt), formatDeliveryTime(message.CreatedAt))
	if err != nil {
		return Record{}, err
	}
	record, err := s.Get(ctx, message.DeliveryID)
	if err != nil {
		return Record{}, err
	}
	existingRaw, existingDigest, err := marshalMessage(record.Message)
	if err != nil || existingRaw != raw || existingDigest != digest {
		return Record{}, ErrConflict
	}
	return record, nil
}

func (s *SQLiteStore) Get(ctx context.Context, deliveryID string) (Record, error) {
	if s == nil || !validRef(deliveryID) {
		return Record{}, ErrNotFound
	}
	record, err := scanDelivery(s.db.QueryRowContext(ctx, deliverySelect+` WHERE delivery_id=?`, deliveryID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	return record, err
}

// GetRunDelivery resolves the one exact delivery projection for a public run
// and frozen audience. It is the Product retention proof; callers cannot
// substitute a delivery from another recipient or run.
func (s *SQLiteStore) GetRunDelivery(ctx context.Context, runRef, audienceSHA256 string) (Record, error) {
	if s == nil || !validRef(runRef) || !digestPattern.MatchString(audienceSHA256) {
		return Record{}, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, deliverySelect+` WHERE json_extract(message_json,'$.runRef')=?
AND json_extract(message_json,'$.audienceSha256')=? ORDER BY delivery_id LIMIT 2`, runRef, audienceSHA256)
	if err != nil {
		return Record{}, err
	}
	defer rows.Close()
	var result Record
	count := 0
	for rows.Next() {
		value, err := scanDelivery(rows)
		if err != nil {
			return Record{}, err
		}
		if value.Message.RunRef != runRef || value.Message.AudienceSHA256 != audienceSHA256 {
			return Record{}, ErrConflict
		}
		result = value
		count++
	}
	if err := rows.Err(); err != nil {
		return Record{}, err
	}
	if count == 0 {
		return Record{}, ErrNotFound
	}
	if count != 1 {
		return Record{}, ErrConflict
	}
	return result, nil
}

func (s *SQLiteStore) Claim(ctx context.Context, owner string, now time.Time, leaseTTL time.Duration) (Record, Attempt, bool, error) {
	if s == nil || !validRef(owner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 10*time.Minute {
		return Record{}, Attempt{}, false, ErrInvalid
	}
	now = now.UTC()
	if _, err := s.db.ExecContext(ctx, `UPDATE deliveries SET state=?, reason='delivery_attempt_budget_exhausted', updated_at=?
WHERE state=? AND attempts>=? AND available_at<=?`, StateFailed, formatDeliveryTime(now), StatePending, maxAttempts, formatDeliveryTime(now)); err != nil {
		return Record{}, Attempt{}, false, err
	}
	leaseExpires := now.Add(leaseTTL)
	row := s.db.QueryRowContext(ctx, `UPDATE deliveries SET state=?, attempts=attempts+1, lease_owner=?, lease_expires_at=?, reason='delivery_claimed', updated_at=?
WHERE delivery_id=(SELECT delivery_id FROM deliveries WHERE state=? AND attempts<? AND available_at<=? ORDER BY available_at, delivery_id LIMIT 1)
AND state=? RETURNING `+deliveryColumnList,
		StateSending, owner, formatDeliveryTime(leaseExpires), formatDeliveryTime(now),
		StatePending, maxAttempts, formatDeliveryTime(now), StatePending)
	record, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, Attempt{}, false, nil
	}
	if err != nil {
		return Record{}, Attempt{}, false, err
	}
	attempt := Attempt{AttemptID: attemptID(record.Message.DeliveryID, record.Attempts), DeliveryID: record.Message.DeliveryID,
		Number: record.Attempts, Owner: owner, LeaseExpiresAt: leaseExpires, StartedAt: now}
	return record, attempt, true, nil
}

func (s *SQLiteStore) ClaimReconciliation(ctx context.Context, owner string, now time.Time, leaseTTL time.Duration) (Record, ReconciliationAttempt, bool, error) {
	if s == nil || !validRef(owner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 10*time.Minute {
		return Record{}, ReconciliationAttempt{}, false, ErrInvalid
	}
	now = now.UTC()
	leaseExpires := now.Add(leaseTTL)
	row := s.db.QueryRowContext(ctx, `UPDATE deliveries SET reconciliation_attempts=reconciliation_attempts+1,
lease_owner=?, lease_expires_at=?, reason='delivery_reconciliation_claimed', updated_at=?
WHERE delivery_id=(SELECT delivery_id FROM deliveries WHERE state=? AND lease_owner='' AND lease_expires_at='' AND available_at<=?
ORDER BY available_at, delivery_id LIMIT 1)
AND state=? AND lease_owner='' AND lease_expires_at='' RETURNING `+deliveryColumnList,
		owner, formatDeliveryTime(leaseExpires), formatDeliveryTime(now), StateOutcomeUnknown, formatDeliveryTime(now), StateOutcomeUnknown)
	record, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ReconciliationAttempt{}, false, nil
	}
	if err != nil {
		return Record{}, ReconciliationAttempt{}, false, err
	}
	attempt := ReconciliationAttempt{
		DeliveryID: record.Message.DeliveryID, IdempotencyKey: record.Message.IdempotencyKey,
		AudienceSHA256: record.Message.AudienceSHA256, Number: record.ReconciliationAttempts,
		Owner: owner, LeaseExpiresAt: leaseExpires, StartedAt: now,
	}
	return record, attempt, true, nil
}

func (s *SQLiteStore) MarkDelivered(ctx context.Context, attempt Attempt, receiptRef string, at time.Time) error {
	return s.finish(ctx, attempt, StateDelivered, receiptRef, "delivery_receipt_recorded", at, 0)
}

func (s *SQLiteStore) MarkNotDelivered(ctx context.Context, attempt Attempt, reason string, at time.Time, retryAfter time.Duration) error {
	if retryAfter < 0 || retryAfter > 24*time.Hour {
		return ErrInvalid
	}
	return s.finish(ctx, attempt, StatePending, "", reason, at, retryAfter)
}

func (s *SQLiteStore) MarkOutcomeUnknown(ctx context.Context, attempt Attempt, reason string, at time.Time) error {
	return s.finish(ctx, attempt, StateOutcomeUnknown, "", reason, at, 0)
}

func (s *SQLiteStore) finish(ctx context.Context, attempt Attempt, state State, receiptRef, reason string, at time.Time, retryAfter time.Duration) error {
	if s == nil || !validAttempt(attempt) || at.IsZero() || at.Before(attempt.StartedAt) || !safeReason(reason) ||
		(state == StateDelivered) != validRef(receiptRef) || state != StateDelivered && state != StatePending && state != StateOutcomeUnknown {
		return ErrInvalid
	}
	deliveredAt, availableAt := "", formatDeliveryTime(at.UTC())
	if state == StateDelivered {
		deliveredAt = formatDeliveryTime(at.UTC())
	} else if state == StatePending {
		availableAt = formatDeliveryTime(at.UTC().Add(retryAfter))
	}
	result, err := s.db.ExecContext(ctx, `UPDATE deliveries SET state=?, available_at=?, lease_owner='', lease_expires_at='', receipt_ref=?, reason=?, updated_at=?, delivered_at=?
WHERE delivery_id=? AND state=? AND attempts=? AND lease_owner=? AND lease_expires_at=? AND lease_expires_at>?`,
		state, availableAt, receiptRef, reason, formatDeliveryTime(at.UTC()), deliveredAt,
		attempt.DeliveryID, StateSending, attempt.Number, attempt.Owner, formatDeliveryTime(attempt.LeaseExpiresAt), formatDeliveryTime(at.UTC()))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (s *SQLiteStore) Reconcile(ctx context.Context, attempt ReconciliationAttempt, decision Reconciliation, evidence string, at time.Time) error {
	if s == nil || !validReconciliationAttempt(attempt) || at.IsZero() || at.Before(attempt.StartedAt) ||
		(decision != ReconciliationDelivered && decision != ReconciliationNotDelivered && decision != ReconciliationUnknown) {
		return ErrInvalid
	}
	record, err := s.Get(ctx, attempt.DeliveryID)
	if err != nil {
		return err
	}
	if record.State != StateOutcomeUnknown || record.ReconciliationAttempts != attempt.Number ||
		record.LeaseOwner != attempt.Owner || record.LeaseExpiresAt != attempt.LeaseExpiresAt ||
		record.Message.IdempotencyKey != attempt.IdempotencyKey || record.Message.AudienceSHA256 != attempt.AudienceSHA256 {
		return ErrLeaseLost
	}
	if at.Before(record.UpdatedAt) {
		return ErrInvalid
	}
	state, receipt, deliveredAt, availableAt, reason := StateOutcomeUnknown, "", "", formatDeliveryTime(at.UTC()), evidence
	switch decision {
	case ReconciliationDelivered:
		if !validRef(evidence) {
			return ErrInvalid
		}
		state, receipt, deliveredAt, reason = StateDelivered, evidence, formatDeliveryTime(at.UTC()), "delivery_reconciled_delivered"
	case ReconciliationNotDelivered:
		if !safeReason(evidence) {
			return ErrInvalid
		}
		state, availableAt = StatePending, formatDeliveryTime(at.UTC())
	case ReconciliationUnknown:
		if !safeReason(evidence) {
			return ErrInvalid
		}
		availableAt = formatDeliveryTime(at.UTC().Add(reconciliationRetryDelay))
	}
	result, err := s.db.ExecContext(ctx, `UPDATE deliveries SET state=?, available_at=?, lease_owner='', lease_expires_at='',
receipt_ref=?, reason=?, updated_at=?, delivered_at=? WHERE delivery_id=? AND state=? AND reconciliation_attempts=?
AND lease_owner=? AND lease_expires_at=? AND updated_at=? AND lease_expires_at>?`,
		state, availableAt, receipt, reason, formatDeliveryTime(at.UTC()), deliveredAt,
		attempt.DeliveryID, StateOutcomeUnknown, attempt.Number, attempt.Owner, formatDeliveryTime(attempt.LeaseExpiresAt),
		formatDeliveryTime(attempt.StartedAt), formatDeliveryTime(at.UTC()))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (s *SQLiteStore) Acknowledge(ctx context.Context, acknowledgement Acknowledgement) error {
	if s == nil || !validAcknowledgement(acknowledgement) {
		return ErrInvalid
	}
	for retry := 0; retry < 8; retry++ {
		record, err := s.Get(ctx, acknowledgement.DeliveryID)
		if err != nil {
			return err
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
		result, err := s.db.ExecContext(ctx, `UPDATE deliveries SET state=?, lease_owner='', lease_expires_at='', receipt_ref=?,
reason='channel_acknowledged', updated_at=?, delivered_at=? WHERE delivery_id=? AND state=? AND attempts=?
AND reconciliation_attempts=? AND lease_owner=? AND lease_expires_at=? AND updated_at=?`,
			StateDelivered, acknowledgement.ReceiptRef, formatDeliveryTime(committedAt), formatDeliveryTime(committedAt),
			acknowledgement.DeliveryID, record.State, record.Attempts, record.ReconciliationAttempts,
			record.LeaseOwner, formatDeliveryTime(record.LeaseExpiresAt), formatDeliveryTime(record.UpdatedAt))
		if err != nil {
			return err
		}
		if rows, _ := result.RowsAffected(); rows == 1 {
			return nil
		}
	}
	return ErrConflict
}

func (s *SQLiteStore) RecoverExpired(ctx context.Context, now time.Time) (Recovery, error) {
	if s == nil || now.IsZero() {
		return Recovery{}, ErrInvalid
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Recovery{}, err
	}
	defer func() { _ = tx.Rollback() }()
	sending, err := tx.ExecContext(ctx, `UPDATE deliveries SET state=?, available_at=?, lease_owner='', lease_expires_at='',
reason='delivery_worker_interrupted', updated_at=? WHERE state=? AND lease_expires_at<>'' AND lease_expires_at<=?`,
		StateOutcomeUnknown, formatDeliveryTime(now), formatDeliveryTime(now), StateSending, formatDeliveryTime(now))
	if err != nil {
		return Recovery{}, err
	}
	reconciling, err := tx.ExecContext(ctx, `UPDATE deliveries SET available_at=?, lease_owner='', lease_expires_at='',
reason='delivery_reconciliation_interrupted', updated_at=? WHERE state=? AND lease_owner<>'' AND lease_expires_at<>'' AND lease_expires_at<=?`,
		formatDeliveryTime(now), formatDeliveryTime(now), StateOutcomeUnknown, formatDeliveryTime(now))
	if err != nil {
		return Recovery{}, err
	}
	sendingRows, err := sending.RowsAffected()
	if err != nil {
		return Recovery{}, err
	}
	reconcilingRows, err := reconciling.RowsAffected()
	if err != nil {
		return Recovery{}, err
	}
	if err := tx.Commit(); err != nil {
		return Recovery{}, err
	}
	return Recovery{SendingBecameUnknown: int(sendingRows), ReconciliationLeaseFreed: int(reconcilingRows)}, nil
}

type deliveryScanner interface {
	Scan(...any) error
}

func scanDelivery(row deliveryScanner) (Record, error) {
	var id, raw, digest, state, available, leaseOwner, leaseExpires, receipt, reason, updated, delivered string
	var attempts, reconciliationAttempts int
	if err := row.Scan(&id, &raw, &digest, &state, &attempts, &reconciliationAttempts, &available, &leaseOwner, &leaseExpires, &receipt, &reason, &updated, &delivered); err != nil {
		return Record{}, err
	}
	message, err := unmarshalMessage(raw, digest)
	if err != nil || message.DeliveryID != id {
		return Record{}, errors.New("stored inspection delivery message failed integrity validation")
	}
	record := Record{Message: message, State: State(state), Attempts: attempts, ReconciliationAttempts: reconciliationAttempts,
		LeaseOwner: leaseOwner, ReceiptRef: receipt, Reason: reason}
	if record.AvailableAt, err = parseDeliveryTime(available, false); err != nil {
		return Record{}, err
	}
	if record.LeaseExpiresAt, err = parseDeliveryTime(leaseExpires, true); err != nil {
		return Record{}, err
	}
	if record.UpdatedAt, err = parseDeliveryTime(updated, false); err != nil {
		return Record{}, err
	}
	if record.DeliveredAt, err = parseDeliveryTime(delivered, true); err != nil {
		return Record{}, err
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecord(record Record) error {
	if record.Message.Validate() != nil || record.Attempts < 0 || record.Attempts > maxAttempts || record.ReconciliationAttempts < 0 || !safeReason(record.Reason) ||
		record.AvailableAt.IsZero() || record.UpdatedAt.Before(record.Message.CreatedAt) {
		return errors.New("stored inspection delivery state is invalid")
	}
	switch record.State {
	case StatePending:
		if record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() || record.ReceiptRef != "" || !record.DeliveredAt.IsZero() {
			return errors.New("stored pending delivery state is invalid")
		}
	case StateSending:
		if !validRef(record.LeaseOwner) || !record.LeaseExpiresAt.After(record.UpdatedAt) || record.ReceiptRef != "" || !record.DeliveredAt.IsZero() {
			return errors.New("stored sending delivery state is invalid")
		}
	case StateOutcomeUnknown:
		leaseEmpty := record.LeaseOwner == "" && record.LeaseExpiresAt.IsZero()
		leaseActive := validRef(record.LeaseOwner) && record.LeaseExpiresAt.After(record.UpdatedAt)
		if (!leaseEmpty && !leaseActive) || record.ReceiptRef != "" || !record.DeliveredAt.IsZero() {
			return errors.New("stored outcome-unknown delivery state is invalid")
		}
	case StateFailed:
		if record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() || record.ReceiptRef != "" || !record.DeliveredAt.IsZero() {
			return errors.New("stored terminal delivery state is invalid")
		}
	case StateDelivered:
		if record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() || !validRef(record.ReceiptRef) || record.DeliveredAt.IsZero() {
			return errors.New("stored delivered state is invalid")
		}
	default:
		return errors.New("stored inspection delivery state is invalid")
	}
	return nil
}

func marshalMessage(message Message) (string, string, error) {
	if err := message.Validate(); err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(message)
	if err != nil {
		return "", "", err
	}
	digest, err := messageDigest(message)
	return string(raw), digest, err
}

func unmarshalMessage(raw, digest string) (Message, error) {
	var message Message
	if err := json.Unmarshal([]byte(raw), &message); err != nil {
		return Message{}, err
	}
	canonical, computed, err := marshalMessage(message)
	if err != nil || canonical != raw || computed != digest {
		return Message{}, errors.New("stored inspection delivery message digest is invalid")
	}
	return message, nil
}

const deliveryTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatDeliveryTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(deliveryTimeLayout)
}

func parseDeliveryTime(value string, optional bool) (time.Time, error) {
	if value == "" && optional {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(deliveryTimeLayout, value)
	if err != nil || formatDeliveryTime(parsed) != value {
		return time.Time{}, errors.New("stored inspection delivery time is invalid")
	}
	return parsed.UTC(), nil
}

var _ Store = (*SQLiteStore)(nil)
