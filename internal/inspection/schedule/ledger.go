package schedule

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

type AdmissionStatus string

const (
	AdmissionReady   AdmissionStatus = "ready"
	AdmissionQueued  AdmissionStatus = "queued"
	AdmissionSkipped AdmissionStatus = "skipped"
	AdmissionBlocked AdmissionStatus = "blocked"
	AdmissionExpired AdmissionStatus = "expired"
)

func (s *Store) ListActive(ctx context.Context) ([]ScheduleRecord, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+scheduleColumns+` FROM schedule_revisions WHERE state='active' ORDER BY tenant_id, site_id, schedule_id, revision`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ScheduleRecord
	for rows.Next() {
		record, err := scanSchedule(s.zones, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

// RecordPlanning inserts deterministic occurrences and advances the exclusive
// schedule cursor in one transaction. No mutable catalog lookup occurs here.
func (s *Store) RecordPlanning(ctx context.Context, expected ScheduleRecord, now time.Time, occurrences []Occurrence) (int, error) {
	if s == nil || now.IsZero() || expected.Schedule.State != StateActive || expected.Schedule.ValidateWithZones(s.zones) != nil || expected.CursorAt.IsZero() || now.UTC().Before(expected.CursorAt) {
		return 0, ErrConflict
	}
	if expected.Schedule.Misfire == MisfireCatchUpOnce && len(occurrences) > 1 {
		return 0, ErrConflict
	}
	for index, occurrence := range occurrences {
		if occurrence.ValidateWithZones(s.zones) != nil || !occurrence.GeneratedAt.Equal(now.UTC()) || !occurrence.DueAt.After(expected.CursorAt) || occurrence.DueAt.After(now.UTC()) || !occurrenceMatchesSchedule(occurrence, expected.Schedule) {
			return 0, ErrConflict
		}
		if expected.Schedule.Misfire == MisfireSkip && now.UTC().Sub(occurrence.DueAt) > time.Duration(expected.Schedule.MisfireGraceSeconds)*time.Second {
			return 0, ErrConflict
		}
		if index > 0 && (!occurrences[index-1].DueAt.Before(occurrence.DueAt) && !(occurrences[index-1].DueAt.Equal(occurrence.DueAt) && occurrences[index-1].IdempotencyKey < occurrence.IdempotencyKey)) {
			return 0, ErrConflict
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	key := keyFor(expected.Schedule)
	stored, err := scanSchedule(s.zones, tx.QueryRowContext(ctx, `SELECT `+scheduleColumns+` FROM schedule_revisions WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=?`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision))
	if err != nil {
		return 0, err
	}
	if stored.PayloadSHA256 != expected.PayloadSHA256 || !stored.CursorAt.Equal(expected.CursorAt) || stored.Schedule.State != StateActive {
		return 0, ErrConflict
	}
	created := 0
	for _, occurrence := range occurrences {
		raw, err := marshalOccurrenceStorage(occurrence)
		if err != nil {
			return 0, err
		}
		payloadSHA := bytesDigest(raw)
		result, err := tx.ExecContext(ctx, `INSERT INTO occurrences(
occurrence_id, idempotency_key, operation_ref, request_key, tenant_id, site_id, schedule_id, schedule_revision, due_at, deadline_at, available_at,
occurrence_json, payload_sha256, state, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?) ON CONFLICT(occurrence_id) DO NOTHING`, occurrence.OccurrenceID,
			occurrence.IdempotencyKey, occurrence.OperationRef, occurrence.RequestKey, occurrence.TenantID, occurrence.SiteID, occurrence.ScheduleID,
			occurrence.ScheduleRevision, formatStoreTime(occurrence.DueAt), formatStoreTime(occurrence.Deadline), formatStoreTime(occurrence.DueAt), raw, payloadSHA,
			formatStoreTime(now.UTC()), formatStoreTime(now.UTC()))
		if err != nil {
			return 0, storeConstraint(err)
		}
		rows, _ := result.RowsAffected()
		if rows == 1 {
			created++
			continue
		}
		existing, err := scanOccurrence(s.zones, tx.QueryRowContext(ctx, `SELECT `+occurrenceColumns+` FROM occurrences WHERE occurrence_id=?`, occurrence.OccurrenceID))
		if err != nil || existing.PayloadSHA256 != payloadSHA || existing.Occurrence.IdempotencyKey != occurrence.IdempotencyKey {
			return 0, ErrConflict
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE schedule_revisions SET cursor_at=? WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=? AND state='active' AND payload_sha256=? AND cursor_at=?`,
		formatStoreTime(now.UTC()), key.TenantID, key.SiteID, key.ScheduleID, key.Revision, expected.PayloadSHA256, formatStoreTime(expected.CursorAt))
	if err != nil {
		return 0, storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return 0, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return created, nil
}

func (s *Store) GetOccurrence(ctx context.Context, occurrenceID string) (OccurrenceRecord, error) {
	if s == nil || validateRef("occurrence", occurrenceID) != nil {
		return OccurrenceRecord{}, ErrNotFound
	}
	return scanOccurrence(s.zones, s.db.QueryRowContext(ctx, `SELECT `+occurrenceColumns+` FROM occurrences WHERE occurrence_id=?`, occurrenceID))
}

func (s *Store) ListOccurrences(ctx context.Context, key Key) ([]OccurrenceRecord, error) {
	if s == nil || validateKey(key) != nil {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+occurrenceColumns+` FROM occurrences WHERE tenant_id=? AND site_id=? AND schedule_id=? AND schedule_revision=? ORDER BY due_at, occurrence_id`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OccurrenceRecord
	for rows.Next() {
		record, err := scanOccurrence(s.zones, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *Store) ExpirePending(ctx context.Context, now time.Time) (int, error) {
	if s == nil || now.IsZero() {
		return 0, ErrConflict
	}
	result, err := s.db.ExecContext(ctx, `UPDATE occurrences SET state='expired', reason_code='run_deadline_elapsed', claim_owner='', lease_expires_at='', available_at=?, generation=generation+1, updated_at=? WHERE state IN ('pending','claimed') AND deadline_at<=?`, formatStoreTime(now.UTC()), formatStoreTime(now.UTC()), formatStoreTime(now.UTC()))
	if err != nil {
		return 0, storeConstraint(err)
	}
	rows, _ := result.RowsAffected()
	return int(rows), nil
}

func (s *Store) ClaimPending(ctx context.Context, owner string, now time.Time, lease time.Duration) (OccurrenceRecord, OccurrenceClaim, bool, error) {
	if s == nil || validateClaimInput(owner, now, lease) != nil {
		return OccurrenceRecord{}, OccurrenceClaim{}, false, ErrConflict
	}
	record, err := scanOccurrence(s.zones, s.db.QueryRowContext(ctx, `UPDATE occurrences SET state='claimed', claim_owner=?, lease_expires_at=?, generation=generation+1, reason_code='', updated_at=?
WHERE occurrence_id=(SELECT o.occurrence_id FROM occurrences o WHERE o.due_at<=? AND o.deadline_at>? AND o.available_at<=?
 AND (o.state='pending' OR (o.state='claimed' AND o.lease_expires_at<=?))
 AND EXISTS(SELECT 1 FROM schedule_revisions s WHERE s.tenant_id=o.tenant_id AND s.site_id=o.site_id AND s.schedule_id=o.schedule_id AND s.revision=o.schedule_revision AND s.state='active')
 ORDER BY o.due_at,o.occurrence_id LIMIT 1)
RETURNING `+occurrenceColumns, owner, formatStoreTime(now.UTC().Add(lease)), formatStoreTime(now.UTC()), formatStoreTime(now.UTC()), formatStoreTime(now.UTC()), formatStoreTime(now.UTC()), formatStoreTime(now.UTC())))
	if errors.Is(err, ErrNotFound) {
		return OccurrenceRecord{}, OccurrenceClaim{}, false, nil
	}
	if err != nil {
		return OccurrenceRecord{}, OccurrenceClaim{}, false, storeConstraint(err)
	}
	claim := OccurrenceClaim{OccurrenceID: record.Occurrence.OccurrenceID, Owner: owner, Generation: record.Generation}
	return record, claim, true, nil
}

func (s *Store) ClaimUnknown(ctx context.Context, owner string, now time.Time, lease time.Duration) (OccurrenceRecord, OccurrenceClaim, bool, error) {
	return s.claimState(ctx, OccurrenceSubmittingUnknown, owner, now, lease)
}

func (s *Store) ClaimSubmitted(ctx context.Context, owner string, now time.Time, lease time.Duration) (OccurrenceRecord, OccurrenceClaim, bool, error) {
	return s.claimState(ctx, OccurrenceSubmitted, owner, now, lease)
}

// RenewClaim fences a long external Submit, Reconcile or Observe call. It does
// not change generation, so the original completion CAS remains valid. A stale
// owner cannot renew after its lease has expired or another manager has won.
func (s *Store) RenewClaim(ctx context.Context, claim OccurrenceClaim, now time.Time, lease time.Duration) (bool, error) {
	if s == nil || validateClaim(claim) != nil || validateClaimInput(claim.Owner, now, lease) != nil {
		return false, ErrConflict
	}
	expires := now.UTC().Add(lease)
	result, err := s.db.ExecContext(ctx, `UPDATE occurrences SET lease_expires_at=?,available_at=?,updated_at=?
WHERE occurrence_id=? AND state IN ('submitting_unknown','submitted') AND claim_owner=? AND generation=? AND lease_expires_at>?`,
		formatStoreTime(expires), formatStoreTime(expires), formatStoreTime(now.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation, formatStoreTime(now.UTC()))
	if err != nil {
		return false, storeConstraint(err)
	}
	rows, _ := result.RowsAffected()
	return rows == 1, nil
}

func (s *Store) claimState(ctx context.Context, state OccurrenceState, owner string, now time.Time, lease time.Duration) (OccurrenceRecord, OccurrenceClaim, bool, error) {
	if s == nil || (state != OccurrenceSubmittingUnknown && state != OccurrenceSubmitted) || validateClaimInput(owner, now, lease) != nil {
		return OccurrenceRecord{}, OccurrenceClaim{}, false, ErrConflict
	}
	attemptColumn := "reconcile_attempts"
	if state == OccurrenceSubmitted {
		attemptColumn = "observe_attempts"
	}
	query := `UPDATE occurrences SET claim_owner=?, lease_expires_at=?, generation=generation+1, ` + attemptColumn + `=` + attemptColumn + `+1, updated_at=?
WHERE occurrence_id=(SELECT occurrence_id FROM occurrences WHERE state=? AND available_at<=? AND (claim_owner='' OR lease_expires_at<=?) ORDER BY available_at,updated_at,occurrence_id LIMIT 1)
RETURNING ` + occurrenceColumns
	record, err := scanOccurrence(s.zones, s.db.QueryRowContext(ctx, query, owner, formatStoreTime(now.UTC().Add(lease)), formatStoreTime(now.UTC()), state, formatStoreTime(now.UTC()), formatStoreTime(now.UTC())))
	if errors.Is(err, ErrNotFound) {
		return OccurrenceRecord{}, OccurrenceClaim{}, false, nil
	}
	if err != nil {
		return OccurrenceRecord{}, OccurrenceClaim{}, false, storeConstraint(err)
	}
	return record, OccurrenceClaim{OccurrenceID: record.Occurrence.OccurrenceID, Owner: owner, Generation: record.Generation}, true, nil
}

// BeginSubmission acquires the exact schedule-revision capacity slot and
// commits submitting_unknown before any external call can occur.
func (s *Store) BeginSubmission(ctx context.Context, claim OccurrenceClaim, at time.Time, lease time.Duration) (OccurrenceRecord, AdmissionStatus, error) {
	if s == nil || validateClaim(claim) != nil || validateClaimInput(claim.Owner, at, lease) != nil {
		return OccurrenceRecord{}, "", ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OccurrenceRecord{}, "", err
	}
	defer tx.Rollback()
	record, err := scanOccurrence(s.zones, tx.QueryRowContext(ctx, `SELECT `+occurrenceColumns+` FROM occurrences WHERE occurrence_id=?`, claim.OccurrenceID))
	if err != nil {
		return OccurrenceRecord{}, "", err
	}
	if record.State != OccurrenceClaimed || !claimMatches(record, claim) || !record.LeaseExpiresAt.After(at.UTC()) {
		return OccurrenceRecord{}, "", ErrConflict
	}
	key := Key{record.Occurrence.TenantID, record.Occurrence.SiteID, record.Occurrence.ScheduleID, record.Occurrence.ScheduleRevision}
	scheduleRecord, err := scanSchedule(s.zones, tx.QueryRowContext(ctx, `SELECT `+scheduleColumns+` FROM schedule_revisions WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=?`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision))
	if err != nil {
		return OccurrenceRecord{}, "", err
	}
	if !at.UTC().Before(record.Occurrence.Deadline) {
		if err := updateClaimTerminal(ctx, tx, record, claim, OccurrenceExpired, "run_deadline_elapsed", at); err != nil {
			return OccurrenceRecord{}, "", err
		}
		if err := tx.Commit(); err != nil {
			return OccurrenceRecord{}, "", err
		}
		terminal, _ := s.GetOccurrence(ctx, claim.OccurrenceID)
		return terminal, AdmissionExpired, nil
	}
	if scheduleRecord.Schedule.State != StateActive || !occurrenceMatchesSchedule(record.Occurrence, scheduleRecord.Schedule) {
		if err := updateClaimTerminal(ctx, tx, record, claim, OccurrenceBlocked, "schedule_not_active", at); err != nil {
			return OccurrenceRecord{}, "", err
		}
		if err := tx.Commit(); err != nil {
			return OccurrenceRecord{}, "", err
		}
		terminal, _ := s.GetOccurrence(ctx, claim.OccurrenceID)
		return terminal, AdmissionBlocked, nil
	}
	capacity, err := tx.ExecContext(ctx, `UPDATE schedule_revisions SET reserved_count=reserved_count+1 WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=? AND state='active' AND reserved_count<max_in_flight`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision)
	if err != nil {
		return OccurrenceRecord{}, "", storeConstraint(err)
	}
	changed, _ := capacity.RowsAffected()
	if changed != 1 {
		if record.Occurrence.Concurrency.OnLimit == ConcurrencyQueue {
			available := retryAt(at.UTC(), int(record.Generation))
			result, err := tx.ExecContext(ctx, `UPDATE occurrences SET state='pending',reason_code='concurrency_queued',claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='claimed' AND claim_owner=? AND generation=?`, formatStoreTime(available), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
			if err != nil {
				return OccurrenceRecord{}, "", storeConstraint(err)
			}
			if rows, _ := result.RowsAffected(); rows != 1 {
				return OccurrenceRecord{}, "", ErrConflict
			}
			if err := tx.Commit(); err != nil {
				return OccurrenceRecord{}, "", err
			}
			queued, _ := s.GetOccurrence(ctx, claim.OccurrenceID)
			return queued, AdmissionQueued, nil
		}
		if err := updateClaimTerminal(ctx, tx, record, claim, OccurrenceSkipped, "concurrency_limit_reached", at); err != nil {
			return OccurrenceRecord{}, "", err
		}
		if err := tx.Commit(); err != nil {
			return OccurrenceRecord{}, "", err
		}
		skipped, _ := s.GetOccurrence(ctx, claim.OccurrenceID)
		return skipped, AdmissionSkipped, nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO schedule_reservations(occurrence_id,tenant_id,site_id,schedule_id,schedule_revision,state,created_at) VALUES(?,?,?,?,?,'held',?)`, claim.OccurrenceID, key.TenantID, key.SiteID, key.ScheduleID, key.Revision, formatStoreTime(at.UTC()))
	if err != nil {
		return OccurrenceRecord{}, "", storeConstraint(err)
	}
	newLeaseExpiry := at.UTC().Add(lease)
	result, err := tx.ExecContext(ctx, `UPDATE occurrences SET state='submitting_unknown',submission_started_at=?,submit_attempts=submit_attempts+1,lease_expires_at=?,available_at=?,updated_at=? WHERE occurrence_id=? AND state='claimed' AND claim_owner=? AND generation=? AND lease_expires_at>?`, formatStoreTime(at.UTC()), formatStoreTime(newLeaseExpiry), formatStoreTime(newLeaseExpiry), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation, formatStoreTime(at.UTC()))
	if err != nil {
		return OccurrenceRecord{}, "", storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return OccurrenceRecord{}, "", ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return OccurrenceRecord{}, "", err
	}
	ready, err := s.GetOccurrence(ctx, claim.OccurrenceID)
	return ready, AdmissionReady, err
}

func (s *Store) DeferClaim(ctx context.Context, claim OccurrenceClaim, reason string, at time.Time) (OccurrenceRecord, error) {
	if validateRef("reason", reason) != nil {
		return OccurrenceRecord{}, ErrConflict
	}
	available := retryAt(at.UTC(), int(claim.Generation))
	result, err := s.db.ExecContext(ctx, `UPDATE occurrences SET state='pending',reason_code=?,claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='claimed' AND claim_owner=? AND generation=?`, reason, formatStoreTime(available), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
	if err != nil {
		return OccurrenceRecord{}, storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return OccurrenceRecord{}, ErrConflict
	}
	return s.GetOccurrence(ctx, claim.OccurrenceID)
}

func (s *Store) MarkClaimedTerminal(ctx context.Context, claim OccurrenceClaim, state OccurrenceState, reason string, at time.Time) (OccurrenceRecord, error) {
	if state != OccurrenceBlocked && state != OccurrenceExpired && state != OccurrenceSkipped || validateRef("reason", reason) != nil {
		return OccurrenceRecord{}, ErrConflict
	}
	result, err := s.db.ExecContext(ctx, `UPDATE occurrences SET state=?,reason_code=?,claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='claimed' AND claim_owner=? AND generation=?`, state, reason, formatStoreTime(at.UTC()), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
	if err != nil {
		return OccurrenceRecord{}, storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return OccurrenceRecord{}, ErrConflict
	}
	return s.GetOccurrence(ctx, claim.OccurrenceID)
}

func (s *Store) ApplySubmission(ctx context.Context, claim OccurrenceClaim, result SubmissionResult, at time.Time) (OccurrenceRecord, error) {
	if s == nil || validateClaim(claim) != nil || result.Validate() != nil || at.IsZero() {
		return OccurrenceRecord{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OccurrenceRecord{}, err
	}
	defer tx.Rollback()
	record, err := scanOccurrence(s.zones, tx.QueryRowContext(ctx, `SELECT `+occurrenceColumns+` FROM occurrences WHERE occurrence_id=?`, claim.OccurrenceID))
	if err != nil {
		return OccurrenceRecord{}, err
	}
	if record.State != OccurrenceSubmittingUnknown || !claimMatches(record, claim) {
		return OccurrenceRecord{}, ErrConflict
	}
	state := OccurrenceSubmittingUnknown
	reason := ""
	runRef := ""
	available := retryAt(at.UTC(), record.ReconcileAttempts+1)
	switch result.Status {
	case SubmissionAccepted:
		state = OccurrenceSubmitted
		runRef = result.RunRef
		available = retryAt(at.UTC(), record.ObserveAttempts+1)
	case SubmissionNotSubmitted:
		state = OccurrenceBlocked
		reason = "abandoned_before_runtime"
	case SubmissionRejected:
		state = OccurrenceBlocked
		reason = "submission_rejected"
	case SubmissionUnknown:
		reason = "submission_outcome_unknown"
	}
	if state == OccurrenceSubmitted {
		res, err := tx.ExecContext(ctx, `UPDATE schedule_reservations SET run_ref=? WHERE occurrence_id=? AND state='held' AND run_ref=''`, runRef, claim.OccurrenceID)
		if err != nil {
			return OccurrenceRecord{}, storeConstraint(err)
		}
		if rows, _ := res.RowsAffected(); rows != 1 {
			return OccurrenceRecord{}, ErrConflict
		}
	}
	if state == OccurrenceBlocked {
		if err := releaseReservation(ctx, tx, record.Occurrence, at.UTC()); err != nil {
			return OccurrenceRecord{}, err
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE occurrences SET state=?,run_ref=?,submission_ref=?,reason_code=?,claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='submitting_unknown' AND claim_owner=? AND generation=?`, state, runRef, result.SubmissionRef, reason, formatStoreTime(available), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
	if err != nil {
		return OccurrenceRecord{}, storeConstraint(err)
	}
	if rows, _ := res.RowsAffected(); rows != 1 {
		return OccurrenceRecord{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return OccurrenceRecord{}, err
	}
	return s.GetOccurrence(ctx, claim.OccurrenceID)
}

func (s *Store) ReleaseUnknown(ctx context.Context, claim OccurrenceClaim, submissionRef string, at time.Time) (OccurrenceRecord, error) {
	if submissionRef != "" && validateRef("submission", submissionRef) != nil {
		return OccurrenceRecord{}, ErrConflict
	}
	available := retryAt(at.UTC(), int(claim.Generation))
	result, err := s.db.ExecContext(ctx, `UPDATE occurrences SET submission_ref=CASE WHEN ?='' THEN submission_ref ELSE ? END,reason_code='submission_outcome_unknown',claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='submitting_unknown' AND claim_owner=? AND generation=?`, submissionRef, submissionRef, formatStoreTime(available), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
	if err != nil {
		return OccurrenceRecord{}, storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return OccurrenceRecord{}, ErrConflict
	}
	return s.GetOccurrence(ctx, claim.OccurrenceID)
}

func (s *Store) ReleaseObservation(ctx context.Context, claim OccurrenceClaim, reason string, at time.Time) (OccurrenceRecord, error) {
	if validateRef("reason", reason) != nil {
		return OccurrenceRecord{}, ErrConflict
	}
	available := retryAt(at.UTC(), int(claim.Generation))
	result, err := s.db.ExecContext(ctx, `UPDATE occurrences SET reason_code=?,claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='submitted' AND claim_owner=? AND generation=?`, reason, formatStoreTime(available), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
	if err != nil {
		return OccurrenceRecord{}, storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return OccurrenceRecord{}, ErrConflict
	}
	return s.GetOccurrence(ctx, claim.OccurrenceID)
}

func (s *Store) markRunTerminal(ctx context.Context, claim OccurrenceClaim, runState inspection.RunState, at time.Time) (OccurrenceRecord, error) {
	if !inspection.Terminal(runState) {
		return OccurrenceRecord{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OccurrenceRecord{}, err
	}
	defer tx.Rollback()
	record, err := scanOccurrence(s.zones, tx.QueryRowContext(ctx, `SELECT `+occurrenceColumns+` FROM occurrences WHERE occurrence_id=?`, claim.OccurrenceID))
	if err != nil {
		return OccurrenceRecord{}, err
	}
	if record.State != OccurrenceSubmitted || !claimMatches(record, claim) {
		return OccurrenceRecord{}, ErrConflict
	}
	if err := releaseReservation(ctx, tx, record.Occurrence, at.UTC()); err != nil {
		return OccurrenceRecord{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE occurrences SET state='terminal',reason_code=?,claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='submitted' AND claim_owner=? AND generation=?`, "run_"+string(runState), formatStoreTime(at.UTC()), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
	if err != nil {
		return OccurrenceRecord{}, storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return OccurrenceRecord{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return OccurrenceRecord{}, err
	}
	return s.GetOccurrence(ctx, claim.OccurrenceID)
}

func (s *Store) ReservationCount(ctx context.Context, key Key) (int, error) {
	if s == nil || validateKey(key) != nil {
		return 0, ErrConflict
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT reserved_count FROM schedule_revisions WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=?`, key.TenantID, key.SiteID, key.ScheduleID, key.Revision).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return count, err
}

// IsOccurrenceReleasedTerminal is Product's narrow cross-store retention
// proof. Runtime terminal state alone is insufficient: application audience
// state must remain available until the occurrence has observed that terminal
// state and atomically released its concurrency reservation.
func (s *Store) IsOccurrenceReleasedTerminal(ctx context.Context, occurrenceID, runRef string) (bool, error) {
	if s == nil || s.db == nil || validateRef("occurrence", occurrenceID) != nil || validateRef("run", runRef) != nil {
		return false, ErrConflict
	}
	record, err := s.GetOccurrence(ctx, occurrenceID)
	if err != nil {
		return false, err
	}
	if record.State != OccurrenceTerminal || record.RunRef != runRef || record.ClaimOwner != "" || !record.LeaseExpiresAt.IsZero() {
		return false, nil
	}
	var released int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schedule_reservations
WHERE occurrence_id=? AND run_ref=? AND state='released' AND released_at<>''`, occurrenceID, runRef).Scan(&released); err != nil {
		return false, err
	}
	if released > 1 {
		return false, ErrConflict
	}
	return released == 1, nil
}

func releaseReservation(ctx context.Context, tx *sql.Tx, occurrence Occurrence, at time.Time) error {
	result, err := tx.ExecContext(ctx, `UPDATE schedule_reservations SET state='released',released_at=? WHERE occurrence_id=? AND state='held'`, formatStoreTime(at), occurrence.OccurrenceID)
	if err != nil {
		return storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	result, err = tx.ExecContext(ctx, `UPDATE schedule_revisions SET reserved_count=reserved_count-1 WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=? AND reserved_count>0`, occurrence.TenantID, occurrence.SiteID, occurrence.ScheduleID, occurrence.ScheduleRevision)
	if err != nil {
		return storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	return nil
}

func updateClaimTerminal(ctx context.Context, tx *sql.Tx, record OccurrenceRecord, claim OccurrenceClaim, state OccurrenceState, reason string, at time.Time) error {
	result, err := tx.ExecContext(ctx, `UPDATE occurrences SET state=?,reason_code=?,claim_owner='',lease_expires_at='',available_at=?,generation=generation+1,updated_at=? WHERE occurrence_id=? AND state='claimed' AND claim_owner=? AND generation=?`, state, reason, formatStoreTime(at.UTC()), formatStoreTime(at.UTC()), claim.OccurrenceID, claim.Owner, claim.Generation)
	if err != nil {
		return storeConstraint(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	return nil
}

func validateClaimInput(owner string, now time.Time, lease time.Duration) error {
	if validateRef("claim owner", owner) != nil || now.IsZero() || lease < time.Second || lease > time.Hour {
		return ErrConflict
	}
	return nil
}
func validateClaim(claim OccurrenceClaim) error {
	if validateRef("occurrence", claim.OccurrenceID) != nil || validateRef("claim owner", claim.Owner) != nil || claim.Generation == 0 {
		return ErrConflict
	}
	return nil
}
func claimMatches(record OccurrenceRecord, claim OccurrenceClaim) bool {
	return record.Occurrence.OccurrenceID == claim.OccurrenceID && record.ClaimOwner == claim.Owner && record.Generation == claim.Generation
}

func retryAt(at time.Time, attempt int) time.Time {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 9 {
		attempt = 9
	}
	delay := time.Second * time.Duration(1<<uint(attempt-1))
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return at.Add(delay)
}

func occurrenceMatchesSchedule(o Occurrence, s Schedule) bool {
	localDate, err := time.Parse("2006-01-02", o.LocalDate)
	if err != nil || !containsWeekday(s.Weekdays, localDate.Weekday()) {
		return false
	}
	jitter := deterministicJitter(s, o.ScheduledAt)
	if o.JitterPolicySeconds != s.JitterPolicySeconds || o.JitterOffsetSeconds != int(jitter/time.Second) || !o.DueAt.Equal(o.ScheduledAt.Add(jitter)) || o.ScheduledAt.Before(effectiveStart(s)) || !o.ScheduledAt.Before(effectiveEnd(s)) || o.DueAt.Before(effectiveStart(s)) || !o.DueAt.Before(effectiveEnd(s)) {
		return false
	}
	return o.TenantID == s.TenantID && o.SiteID == s.SiteID && o.ScheduleID == s.ScheduleID && o.ScheduleRevision == s.Revision && o.Origin == s.Origin &&
		o.RunSpecSHA256 == s.RunSpecSHA256 && o.RunSpec.SHA256 == s.RunSpec.SHA256 && canonicalEqual(o.RunSpec, s.RunSpec) && o.DeliverySHA256 == s.DeliverySHA256 && canonicalEqual(o.Delivery, s.Delivery) &&
		o.ServicePrincipalSHA256 == s.ServicePrincipalSHA256 && o.ScheduleScopeSHA256 == s.ScheduleScopeSHA256 && o.AuthoritySHA256 == s.AuthoritySHA256 &&
		o.Timezone == s.Timezone && o.LocalTime == s.LocalTime && o.Misfire == s.Misfire && o.MisfireGraceSeconds == s.MisfireGraceSeconds && o.Concurrency == s.Concurrency
}
