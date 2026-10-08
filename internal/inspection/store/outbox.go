package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

type OutboxState string

const (
	OutboxPending       OutboxState = "pending"
	OutboxMaterializing OutboxState = "materializing"
	OutboxMaterialized  OutboxState = "materialized"
)

// OutboxMessage is an atomic terminal-run notification. It is deliberately
// not a channel delivery attempt: the delivery package owns external send
// identities and unknown outcomes. A product worker materializes this record
// into one or more audience-bound delivery messages before any transport is
// called.
type OutboxMessage struct {
	MessageID      string          `json:"messageId"`
	RunID          string          `json:"runId"`
	Topic          string          `json:"topic"`
	Payload        json.RawMessage `json:"payload"`
	ContentSHA256  string          `json:"contentSha256"`
	State          OutboxState     `json:"state"`
	Attempts       int             `json:"attempts"`
	AvailableAt    time.Time       `json:"availableAt"`
	LeaseOwner     string          `json:"leaseOwner,omitempty"`
	LeaseExpiresAt time.Time       `json:"leaseExpiresAt,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	MaterializedAt time.Time       `json:"materializedAt,omitempty"`
}

func (s *Store) ListOutbox(ctx context.Context, runID string) ([]OutboxMessage, error) {
	if !validRef(runID) {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT o.message_id, o.run_id, o.topic, o.payload_json, o.content_sha256,
o.state, o.attempts, o.available_at, o.lease_owner, o.lease_expires_at, o.created_at, o.materialized_at,
r.tenant_id, r.site_id, r.state, r.reason
FROM inspection_outbox o JOIN inspection_runs r ON r.run_id=o.run_id
WHERE o.run_id=? ORDER BY o.created_at, o.message_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]OutboxMessage, 0)
	for rows.Next() {
		message, err := scanOutbox(rows, runID)
		if err != nil {
			return nil, err
		}
		result = append(result, message)
	}
	return result, rows.Err()
}

func (s *Store) ClaimOutbox(ctx context.Context, owner string, now time.Time, leaseTTL time.Duration) (OutboxMessage, bool, error) {
	if !validRef(owner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 10*time.Minute {
		return OutboxMessage{}, false, errors.New("inspection outbox claim metadata is invalid")
	}
	now = now.UTC()
	leaseExpires := now.Add(leaseTTL)
	row := s.db.QueryRowContext(ctx, `UPDATE inspection_outbox
SET state=?, attempts=attempts+1, lease_owner=?, lease_expires_at=?
WHERE message_id=(
    SELECT message_id FROM inspection_outbox
    WHERE state=? AND available_at<=?
    ORDER BY available_at, message_id LIMIT 1
)
AND state=?
RETURNING message_id, run_id, topic, payload_json, content_sha256, state, attempts,
available_at, lease_owner, lease_expires_at, created_at, materialized_at`,
		OutboxMaterializing, owner, formatTime(leaseExpires), OutboxPending, formatTime(now), OutboxPending)
	message, err := scanOutboxClaim(row)
	if errors.Is(err, sql.ErrNoRows) {
		return OutboxMessage{}, false, nil
	}
	if err != nil {
		return OutboxMessage{}, false, err
	}
	if message.LeaseOwner != owner || !message.LeaseExpiresAt.Equal(leaseExpires) {
		return OutboxMessage{}, false, errors.New("inspection outbox claim lost its lease binding")
	}
	var tenantID, siteID, runState, runReason string
	if err := s.db.QueryRowContext(ctx, `SELECT tenant_id, site_id, state, reason FROM inspection_runs WHERE run_id=?`, message.RunID).
		Scan(&tenantID, &siteID, &runState, &runReason); err != nil {
		return OutboxMessage{}, false, err
	}
	if err := validateOutbox(message, message.RunID, tenantID, siteID, runState, runReason); err != nil {
		return OutboxMessage{}, false, err
	}
	return message, true, nil
}

func (s *Store) MarkOutboxMaterialized(ctx context.Context, messageID, owner string, now time.Time) error {
	if !validRef(messageID) || !validRef(owner) || now.IsZero() {
		return errors.New("inspection outbox completion metadata is invalid")
	}
	now = now.UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE inspection_outbox
SET state=?, lease_owner='', lease_expires_at='', materialized_at=?
WHERE message_id=? AND state=? AND lease_owner=? AND lease_expires_at>=?`,
		OutboxMaterialized, formatTime(now), messageID, OutboxMaterializing, owner, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	return nil
}

// RecoverOutboxClaims is safe to replay because materialization only enqueues
// stable, idempotent delivery identities; it never sends to a transport.
func (s *Store) RecoverOutboxClaims(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		return 0, errors.New("inspection outbox recovery time is required")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE inspection_outbox
SET state=?, lease_owner='', lease_expires_at='', available_at=?
WHERE state=? AND lease_expires_at<>'' AND lease_expires_at<=?`,
		OutboxPending, formatTime(now.UTC()), OutboxMaterializing, formatTime(now.UTC()))
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	return int(rows), err
}

func enqueueTerminalTx(ctx context.Context, tx *sql.Tx, run inspection.Run, now time.Time) error {
	payload, err := json.Marshal(map[string]string{
		"runId": run.RunID, "tenantId": run.TenantID, "siteId": run.SiteID,
		"state": string(run.State), "reason": run.Reason,
	})
	if err != nil || protectedPayload.Match(payload) {
		return errors.New("inspection outbox payload is invalid")
	}
	digest := sha256Hex(payload)
	messageID := "terminal:" + run.RunID
	_, err = tx.ExecContext(ctx, `INSERT INTO inspection_outbox(
message_id, run_id, topic, payload_json, content_sha256, state, attempts, available_at,
lease_owner, lease_expires_at, created_at, materialized_at)
VALUES(?, ?, 'inspection.run.terminal', ?, ?, ?, 0, ?, '', '', ?, '')`,
		messageID, run.RunID, string(payload), digest, OutboxPending, formatTime(now), formatTime(now))
	return err
}

type outboxScanner interface{ Scan(...any) error }

func scanOutbox(row outboxScanner, expectedRunID string) (OutboxMessage, error) {
	var message OutboxMessage
	var payload, availableAt, leaseExpiresAt, createdAt, materializedAt string
	var tenantID, siteID, runState, runReason string
	if err := row.Scan(&message.MessageID, &message.RunID, &message.Topic, &payload, &message.ContentSHA256,
		&message.State, &message.Attempts, &availableAt, &message.LeaseOwner, &leaseExpiresAt, &createdAt,
		&materializedAt, &tenantID, &siteID, &runState, &runReason); err != nil {
		return OutboxMessage{}, err
	}
	message.Payload = json.RawMessage(payload)
	if err := parseOutboxTimes(&message, availableAt, leaseExpiresAt, createdAt, materializedAt); err != nil {
		return OutboxMessage{}, err
	}
	if err := validateOutbox(message, expectedRunID, tenantID, siteID, runState, runReason); err != nil {
		return OutboxMessage{}, err
	}
	return message, nil
}

func scanOutboxClaim(row outboxScanner) (OutboxMessage, error) {
	var message OutboxMessage
	var payload, availableAt, leaseExpiresAt, createdAt, materializedAt string
	if err := row.Scan(&message.MessageID, &message.RunID, &message.Topic, &payload, &message.ContentSHA256,
		&message.State, &message.Attempts, &availableAt, &message.LeaseOwner, &leaseExpiresAt, &createdAt,
		&materializedAt); err != nil {
		return OutboxMessage{}, err
	}
	message.Payload = json.RawMessage(payload)
	if err := parseOutboxTimes(&message, availableAt, leaseExpiresAt, createdAt, materializedAt); err != nil {
		return OutboxMessage{}, err
	}
	if err := validateOutboxShape(message); err != nil {
		return OutboxMessage{}, err
	}
	return message, nil
}

func parseOutboxTimes(message *OutboxMessage, availableAt, leaseExpiresAt, createdAt, materializedAt string) error {
	var err error
	if message.AvailableAt, err = parseTime(availableAt); err != nil {
		return err
	}
	if message.CreatedAt, err = parseTime(createdAt); err != nil {
		return err
	}
	if leaseExpiresAt != "" {
		if message.LeaseExpiresAt, err = parseTime(leaseExpiresAt); err != nil {
			return err
		}
	}
	if materializedAt != "" {
		if message.MaterializedAt, err = parseTime(materializedAt); err != nil {
			return err
		}
	}
	return nil
}

func validateOutbox(message OutboxMessage, expectedRunID, tenantID, siteID, runState, runReason string) error {
	if err := validateOutboxShape(message); err != nil {
		return err
	}
	var public map[string]string
	if err := json.Unmarshal(message.Payload, &public); err != nil {
		return fmt.Errorf("decode stored inspection outbox payload: %w", err)
	}
	canonical, err := json.Marshal(public)
	if err != nil {
		return err
	}
	if message.RunID != expectedRunID || len(public) != 5 || string(canonical) != string(message.Payload) ||
		public["runId"] != expectedRunID || public["tenantId"] != tenantID || public["siteId"] != siteID ||
		public["state"] != runState || public["reason"] != runReason {
		return errors.New("stored inspection outbox message failed its run integrity binding")
	}
	return nil
}

func validateOutboxShape(message OutboxMessage) error {
	if !validRef(message.MessageID) || !validRef(message.RunID) || message.MessageID != "terminal:"+message.RunID ||
		message.Topic != "inspection.run.terminal" || !digestPattern.MatchString(message.ContentSHA256) ||
		sha256Hex(message.Payload) != message.ContentSHA256 || message.Attempts < 0 || message.Attempts > 100 ||
		message.AvailableAt.IsZero() || message.CreatedAt.IsZero() || message.AvailableAt.Before(message.CreatedAt) ||
		protectedPayload.Match(message.Payload) {
		return errors.New("stored inspection outbox message is invalid")
	}
	switch message.State {
	case OutboxPending:
		if message.LeaseOwner != "" || !message.LeaseExpiresAt.IsZero() || !message.MaterializedAt.IsZero() {
			return errors.New("stored pending inspection outbox state is invalid")
		}
	case OutboxMaterializing:
		if !validRef(message.LeaseOwner) || !message.LeaseExpiresAt.After(message.AvailableAt) || !message.MaterializedAt.IsZero() {
			return errors.New("stored materializing inspection outbox state is invalid")
		}
	case OutboxMaterialized:
		if message.LeaseOwner != "" || !message.LeaseExpiresAt.IsZero() || message.MaterializedAt.Before(message.CreatedAt) {
			return errors.New("stored materialized inspection outbox state is invalid")
		}
	default:
		return errors.New("stored inspection outbox state is invalid")
	}
	return nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
