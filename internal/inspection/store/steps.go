package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const stepColumns = `run_id, step_id, sequence, kind, authority, state, attempt_count, output_json, output_sha256, reason, lease_owner, lease_expires_at, created_at, updated_at`

const (
	stepClaimBusyRetries = 64
	stepClaimBusyFloor   = 250 * time.Microsecond
	stepClaimBusyCeiling = 50 * time.Millisecond
)

type queryContext interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func insertPlanStepsTx(ctx context.Context, tx *sql.Tx, runID string, plan inspection.ExecutionPlan, now time.Time) error {
	emptyJSON, emptyDigest, err := marshalStepOutputs(nil)
	if err != nil {
		return err
	}
	for _, step := range plan.Steps {
		if _, err := tx.ExecContext(ctx, `INSERT INTO inspection_steps(
run_id, step_id, sequence, kind, authority, state, attempt_count, output_json, output_sha256, created_at, updated_at
) VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`, runID, step.StepID, step.Sequence, step.Kind, step.Authority,
			inspection.StepPending, emptyJSON, emptyDigest, formatTime(now), formatTime(now)); err != nil {
			return constraintConflict(err)
		}
	}
	return nil
}

func (s *Store) ListSteps(ctx context.Context, runID string) ([]inspection.StepRecord, error) {
	if !validRef(runID) {
		return nil, errors.New("inspection step run is invalid")
	}
	plan, err := s.GetPlan(ctx, runID)
	if err != nil {
		return nil, err
	}
	return listStepsQuery(ctx, s.db, runID, plan)
}

func listStepsTx(ctx context.Context, tx *sql.Tx, runID string, plan inspection.ExecutionPlan) ([]inspection.StepRecord, error) {
	return listStepsQuery(ctx, tx, runID, plan)
}

func listStepsQuery(ctx context.Context, query queryContext, runID string, plan inspection.ExecutionPlan) ([]inspection.StepRecord, error) {
	rows, err := query.QueryContext(ctx, `SELECT `+stepColumns+` FROM inspection_steps WHERE run_id=? ORDER BY sequence`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]inspection.StepRecord, 0, len(plan.Steps))
	for rows.Next() {
		record, err := scanStoredStep(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) != len(plan.Steps) {
		return nil, errors.New("stored inspection step ledger does not match the frozen plan")
	}
	for index, record := range result {
		step := plan.Steps[index]
		if record.RunID != runID || record.StepID != step.StepID || record.Sequence != step.Sequence ||
			record.Kind != step.Kind || record.Authority != step.Authority || record.AttemptCount > step.Budget.MaxAttempts {
			return nil, errors.New("stored inspection step failed its frozen plan binding")
		}
		if err := validateOutputsForState(step, record.State, record.Outputs); err != nil {
			return nil, fmt.Errorf("validate stored inspection step outputs: %w", err)
		}
	}
	return result, nil
}

// ClaimNextStep claims the first runnable frozen step. Dependencies that can
// no longer succeed are durably skipped. Cleanup remains runnable once all of
// its dependencies are terminal because it is the plan's sole AlwaysRun step.
func (s *Store) ClaimNextStep(ctx context.Context, runID, runOwner, attemptOwner string, now time.Time, leaseTTL time.Duration) (inspection.StepRecord, inspection.StepAttempt, bool, error) {
	var lastErr error
	for attempt := 0; attempt < stepClaimBusyRetries; attempt++ {
		record, claimedAttempt, ok, err := s.claimNextStepOnce(ctx, runID, runOwner, attemptOwner, now, leaseTTL)
		if err == nil || !sqliteBusy(err) {
			return record, claimedAttempt, ok, err
		}
		lastErr = err
		if attempt+1 == stepClaimBusyRetries {
			break
		}
		if err := waitStepClaimRetry(ctx, attempt); err != nil {
			return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
		}
	}
	return inspection.StepRecord{}, inspection.StepAttempt{}, false, lastErr
}

func waitStepClaimRetry(ctx context.Context, attempt int) error {
	shift := attempt
	if shift > 8 {
		shift = 8
	}
	delay := stepClaimBusyFloor << shift
	if delay > stepClaimBusyCeiling {
		delay = stepClaimBusyCeiling
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Store) claimNextStepOnce(ctx context.Context, runID, runOwner, attemptOwner string, now time.Time, leaseTTL time.Duration) (inspection.StepRecord, inspection.StepAttempt, bool, error) {
	if !validRef(runID) || !validRef(runOwner) || !validRef(attemptOwner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 24*time.Hour {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, errors.New("valid bounded inspection step lease metadata is required")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	defer tx.Rollback()
	if err := assertLeaseTx(ctx, tx, runID, runOwner, inspection.RunRunning, now); err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	var runLeaseRaw string
	if err := tx.QueryRowContext(ctx, `SELECT lease_expires_at FROM inspection_runs WHERE run_id=?`, runID).Scan(&runLeaseRaw); err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	runLease, err := parseTime(runLeaseRaw)
	if err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	_, plan, err := getRunPlanTx(ctx, tx, `run_id=?`, runID)
	if err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	records, err := listStepsTx(ctx, tx, runID, plan)
	if err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	states := make(map[string]inspection.StepState, len(records))
	for _, record := range records {
		states[record.StepID] = record.State
	}

	var selected inspection.StepRecord
	var selectedPlan inspection.ExecutionStep
	for index, record := range records {
		if record.State != inspection.StepPending {
			continue
		}
		step := plan.Steps[index]
		allTerminal, allSucceeded := true, true
		for _, dependency := range step.DependsOn {
			state := states[dependency]
			allTerminal = allTerminal && state.Terminal()
			allSucceeded = allSucceeded && state == inspection.StepSucceeded
		}
		if !allSucceeded && allTerminal && !step.AlwaysRun {
			if _, err := tx.ExecContext(ctx, `UPDATE inspection_steps SET state=?, reason='dependency_not_succeeded', updated_at=? WHERE run_id=? AND step_id=? AND state=?`,
				inspection.StepSkipped, formatTime(now), runID, step.StepID, inspection.StepPending); err != nil {
				return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
			}
			states[step.StepID] = inspection.StepSkipped
			continue
		}
		if !allSucceeded && !(step.AlwaysRun && allTerminal) {
			continue
		}
		if record.AttemptCount >= step.Budget.MaxAttempts || !now.Before(step.Deadline) {
			reason := "attempt_budget_exhausted"
			if !now.Before(step.Deadline) {
				reason = "step_deadline_exceeded"
			}
			if _, err := tx.ExecContext(ctx, `UPDATE inspection_steps SET state=?, reason=?, updated_at=? WHERE run_id=? AND step_id=? AND state=?`,
				inspection.StepFailed, reason, formatTime(now), runID, step.StepID, inspection.StepPending); err != nil {
				return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
			}
			states[step.StepID] = inspection.StepFailed
			continue
		}
		selected, selectedPlan = record, step
		break
	}
	if selected.StepID == "" {
		if err := tx.Commit(); err != nil {
			return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
		}
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, nil
	}

	leaseExpires := now.Add(leaseTTL)
	if leaseExpires.After(runLease) {
		leaseExpires = runLease
	}
	if leaseExpires.After(selectedPlan.Deadline) {
		leaseExpires = selectedPlan.Deadline
	}
	if !leaseExpires.After(now) {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, ErrLeaseLost
	}
	attemptNumber := selected.AttemptCount + 1
	attemptID := stepAttemptID(runID, selected.StepID, attemptNumber)
	emptyJSON, emptyDigest, err := marshalStepOutputs(nil)
	if err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE inspection_steps SET state=?, attempt_count=?, reason='step_claimed', lease_owner=?, lease_expires_at=?, updated_at=? WHERE run_id=? AND step_id=? AND state=? AND attempt_count=?`,
		inspection.StepRunning, attemptNumber, attemptOwner, formatTime(leaseExpires), formatTime(now),
		runID, selected.StepID, inspection.StepPending, selected.AttemptCount)
	if err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, ErrLeaseLost
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO inspection_step_attempts(
attempt_id, run_id, step_id, attempt_number, state, owner, lease_expires_at, output_json, output_sha256, reason, started_at, updated_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'step_claimed', ?, ?)`, attemptID, runID, selected.StepID, attemptNumber,
		inspection.AttemptRunning, attemptOwner, formatTime(leaseExpires), emptyJSON, emptyDigest, formatTime(now), formatTime(now)); err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, constraintConflict(err)
	}
	selected.State = inspection.StepRunning
	selected.AttemptCount = attemptNumber
	selected.Reason = "step_claimed"
	selected.UpdatedAt = now
	attempt := inspection.StepAttempt{
		AttemptID: attemptID, RunID: runID, StepID: selected.StepID, Number: attemptNumber,
		State: inspection.AttemptRunning, Owner: attemptOwner, LeaseExpires: leaseExpires,
		Outputs: []inspection.StepOutput{}, Reason: "step_claimed", StartedAt: now, UpdatedAt: now,
	}
	if err := tx.Commit(); err != nil {
		return inspection.StepRecord{}, inspection.StepAttempt{}, false, err
	}
	return selected, attempt, true, nil
}

func sqliteBusy(err error) bool {
	if err == nil {
		return false
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		// SQLite extended result codes retain the primary code in the low byte.
		// 5 is BUSY and 6 is LOCKED.
		if primary := coded.Code() & 0xff; primary == 5 || primary == 6 {
			return true
		}
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sqlite_busy") || strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database is busy")
}

// RenewStepAttemptLease extends one live attempt without allowing it to
// outlive either the run coordinator lease or the frozen step deadline.
func (s *Store) RenewStepAttemptLease(ctx context.Context, runID, runOwner, attemptID, attemptOwner string, now time.Time, leaseTTL time.Duration) error {
	if !validRef(runID) || !validRef(runOwner) || !validRef(attemptID) || !validRef(attemptOwner) || now.IsZero() ||
		leaseTTL <= 0 || leaseTTL > 24*time.Hour {
		return errors.New("valid bounded inspection step lease renewal metadata is required")
	}
	now = now.UTC()
	requestedExpiry := now.Add(leaseTTL)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Renewal is not a business event. A newer event can pass a heartbeat
	// waiting for database admission, so validate the owner at the latest
	// known logical time rather than requiring event timestamps to go backward.
	var runLeaseRaw, runUpdatedRaw, stepID string
	if err := tx.QueryRowContext(ctx, `SELECT lease_expires_at, updated_at FROM inspection_runs WHERE run_id=? AND state=? AND lease_owner=?`,
		runID, inspection.RunRunning, runOwner).Scan(&runLeaseRaw, &runUpdatedRaw); errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	} else if err != nil {
		return err
	}
	runUpdated, err := parseTime(runUpdatedRaw)
	if err != nil {
		return err
	}
	if runUpdated.After(now) {
		now = runUpdated
	}
	runLease, err := parseTime(runLeaseRaw)
	if err != nil {
		return err
	}
	_, plan, err := getRunPlanTx(ctx, tx, `run_id=?`, runID)
	if err != nil {
		return err
	}
	var attemptNumber int
	var attemptUpdatedRaw, attemptLeaseRaw string
	if err := tx.QueryRowContext(ctx, `SELECT step_id, attempt_number, updated_at, lease_expires_at FROM inspection_step_attempts WHERE attempt_id=? AND run_id=? AND state=? AND owner=?`,
		attemptID, runID, inspection.AttemptRunning, attemptOwner).Scan(&stepID, &attemptNumber, &attemptUpdatedRaw, &attemptLeaseRaw); errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	} else if err != nil {
		return err
	}
	attemptUpdated, err := parseTime(attemptUpdatedRaw)
	if err != nil {
		return err
	}
	if attemptUpdated.After(now) {
		now = attemptUpdated
	}
	attemptLease, err := parseTime(attemptLeaseRaw)
	if err != nil {
		return err
	}
	if !runLease.After(now) || !attemptLease.After(now) {
		return ErrLeaseLost
	}
	step, ok := planStep(plan, stepID)
	if !ok {
		return errors.New("inspection step attempt is outside its frozen plan")
	}
	if requestedExpiry.After(runLease) {
		requestedExpiry = runLease
	}
	if requestedExpiry.After(step.Deadline) {
		requestedExpiry = step.Deadline
	}
	// A superseded heartbeat may request an expiry already in the past. It
	// is harmless while the current attempt is live; the MAX updates below
	// retain the newer lease. The frozen execution deadline still fences it.
	if !step.Deadline.After(now) {
		return ErrLeaseLost
	}
	result, err := tx.ExecContext(ctx, `UPDATE inspection_step_attempts SET lease_expires_at=CASE WHEN lease_expires_at>=? THEN lease_expires_at ELSE ? END, updated_at=MAX(updated_at, ?) WHERE attempt_id=? AND run_id=? AND step_id=? AND attempt_number=? AND state=? AND owner=? AND lease_expires_at>?`,
		formatTime(requestedExpiry), formatTime(requestedExpiry), formatTime(now), attemptID, runID, stepID, attemptNumber,
		inspection.AttemptRunning, attemptOwner, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	result, err = tx.ExecContext(ctx, `UPDATE inspection_steps SET lease_expires_at=CASE WHEN lease_expires_at>=? THEN lease_expires_at ELSE ? END, updated_at=MAX(updated_at, ?) WHERE run_id=? AND step_id=? AND state=? AND attempt_count=? AND lease_owner=? AND lease_expires_at>?`,
		formatTime(requestedExpiry), formatTime(requestedExpiry), formatTime(now), runID, stepID, inspection.StepRunning,
		attemptNumber, attemptOwner, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	return tx.Commit()
}

// CompleteStep records a known attempt outcome exactly once. Unknown is a
// first-class outcome and is never converted into a retry here.
func (s *Store) CompleteStep(ctx context.Context, runID, runOwner, attemptID, attemptOwner string, state inspection.StepState, outputs []inspection.StepOutput, reason string, now time.Time) error {
	if !validRef(runID) || !validRef(runOwner) || !validRef(attemptID) || !validRef(attemptOwner) || now.IsZero() || !validReason(reason) ||
		(state != inspection.StepSucceeded && state != inspection.StepFailed && state != inspection.StepOutcomeUnknown) {
		return errors.New("complete inspection step outcome metadata is required")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := assertLeaseTx(ctx, tx, runID, runOwner, inspection.RunRunning, now); err != nil {
		return err
	}
	_, plan, err := getRunPlanTx(ctx, tx, `run_id=?`, runID)
	if err != nil {
		return err
	}
	var stepID string
	var attemptNumber int
	var storedOwner, attemptLeaseRaw string
	var attemptState inspection.AttemptState
	if err := tx.QueryRowContext(ctx, `SELECT step_id, attempt_number, state, owner, lease_expires_at FROM inspection_step_attempts WHERE attempt_id=? AND run_id=?`, attemptID, runID).
		Scan(&stepID, &attemptNumber, &attemptState, &storedOwner, &attemptLeaseRaw); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	step, ok := planStep(plan, stepID)
	if !ok || attemptState != inspection.AttemptRunning || storedOwner != attemptOwner {
		return ErrConflict
	}
	attemptLease, err := parseTime(attemptLeaseRaw)
	if err != nil {
		return err
	}
	if !attemptLease.After(now) {
		return ErrLeaseLost
	}
	if err := validateOutputsForState(step, state, outputs); err != nil {
		return err
	}
	outputJSON, outputDigest, err := marshalStepOutputs(outputs)
	if err != nil {
		return err
	}
	attemptTerminal := inspection.AttemptFailed
	switch state {
	case inspection.StepSucceeded:
		attemptTerminal = inspection.AttemptSucceeded
	case inspection.StepOutcomeUnknown:
		attemptTerminal = inspection.AttemptOutcomeUnknown
	}
	result, err := tx.ExecContext(ctx, `UPDATE inspection_step_attempts SET state=?, output_json=?, output_sha256=?, reason=?, updated_at=?, finished_at=? WHERE attempt_id=? AND run_id=? AND step_id=? AND attempt_number=? AND state=? AND owner=? AND lease_expires_at>?`,
		attemptTerminal, outputJSON, outputDigest, reason, formatTime(now), formatTime(now), attemptID, runID, stepID, attemptNumber,
		inspection.AttemptRunning, attemptOwner, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	result, err = tx.ExecContext(ctx, `UPDATE inspection_steps SET state=?, output_json=?, output_sha256=?, reason=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE run_id=? AND step_id=? AND state=? AND attempt_count=? AND lease_owner=? AND lease_expires_at>?`,
		state, outputJSON, outputDigest, reason, formatTime(now), runID, stepID, inspection.StepRunning, attemptNumber,
		attemptOwner, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	return tx.Commit()
}

func (s *Store) ListStepAttempts(ctx context.Context, runID, stepID string) ([]inspection.StepAttempt, error) {
	if !validRef(runID) || !validRef(stepID) {
		return nil, errors.New("inspection step attempt scope is invalid")
	}
	plan, err := s.GetPlan(ctx, runID)
	if err != nil {
		return nil, err
	}
	step, ok := planStep(plan, stepID)
	if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT attempt_id, run_id, step_id, attempt_number, state, owner, lease_expires_at, output_json, output_sha256, reason, started_at, updated_at, finished_at FROM inspection_step_attempts WHERE run_id=? AND step_id=? ORDER BY attempt_number`, runID, stepID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]inspection.StepAttempt, 0)
	for rows.Next() {
		attempt, err := scanStoredAttempt(rows, step)
		if err != nil {
			return nil, err
		}
		if attempt.Number != len(result)+1 || attempt.Number > step.Budget.MaxAttempts || attempt.AttemptID != stepAttemptID(runID, stepID, attempt.Number) {
			return nil, errors.New("stored inspection step attempt failed its identity binding")
		}
		result = append(result, attempt)
	}
	return result, rows.Err()
}

// RecoverExpiredStepAttempts makes replayability a per-step decision. Pure
// operations and idempotency-keyed analyzers return to pending while uncertain
// side effects become outcome_unknown and require reconciliation.
func (s *Store) RecoverExpiredStepAttempts(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		return 0, errors.New("inspection step recovery time is required")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT a.attempt_id, a.run_id, a.step_id, a.attempt_number
FROM inspection_step_attempts a
JOIN inspection_steps s ON s.run_id=a.run_id AND s.step_id=a.step_id
WHERE a.state=? AND a.lease_expires_at<=? AND s.state=?
ORDER BY a.run_id, s.sequence`, inspection.AttemptRunning, formatTime(now), inspection.StepRunning)
	if err != nil {
		return 0, err
	}
	type expired struct {
		attemptID string
		runID     string
		stepID    string
		number    int
	}
	items := make([]expired, 0)
	for rows.Next() {
		var item expired
		if err := rows.Scan(&item.attemptID, &item.runID, &item.stepID, &item.number); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, item := range items {
		_, plan, err := getRunPlanTx(ctx, tx, `run_id=?`, item.runID)
		if err != nil {
			return 0, err
		}
		step, ok := planStep(plan, item.stepID)
		if !ok || item.attemptID != stepAttemptID(item.runID, item.stepID, item.number) {
			return 0, errors.New("expired inspection step attempt failed its plan binding")
		}
		replayable := (step.Reconciliation == inspection.ReconcilePureReplay || step.Reconciliation == inspection.ReconcileIdempotencyKey) &&
			item.number < step.Budget.MaxAttempts && now.Before(step.Deadline)
		attemptState, stepState, reason := inspection.AttemptOutcomeUnknown, inspection.StepOutcomeUnknown, "step_lease_expired_outcome_unknown"
		if replayable {
			attemptState, stepState, reason = inspection.AttemptAbandoned, inspection.StepPending, "step_lease_expired_replayable"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inspection_step_attempts SET state=?, reason=?, updated_at=?, finished_at=? WHERE attempt_id=? AND state=? AND lease_expires_at<=?`,
			attemptState, reason, formatTime(now), formatTime(now), item.attemptID, inspection.AttemptRunning, formatTime(now)); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inspection_steps SET state=?, reason=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE run_id=? AND step_id=? AND state=?`,
			stepState, reason, formatTime(now), item.runID, item.stepID, inspection.StepRunning); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}

// ReconcileUnknownStep records an append-only reconciliation decision before
// changing an outcome-unknown step. Retry is available only to operations
// whose frozen policy explicitly requires reconciliation before retry; a
// never-blind-replay operation must be resolved as succeeded or failed.
func (s *Store) ReconcileUnknownStep(ctx context.Context, runID, runOwner, stepID, reconciler string, decision inspection.ReconciliationDecision, outputs []inspection.StepOutput, reason string, now time.Time) (inspection.StepReconciliation, error) {
	if !validRef(runID) || !validRef(runOwner) || !validRef(stepID) || !validRef(reconciler) || !validReason(reason) || now.IsZero() ||
		(decision != inspection.ReconciliationRetry && decision != inspection.ReconciliationSucceeded && decision != inspection.ReconciliationFailed) {
		return inspection.StepReconciliation{}, errors.New("complete inspection step reconciliation metadata is required")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inspection.StepReconciliation{}, err
	}
	defer tx.Rollback()
	var runState inspection.RunState
	var leaseOwner, leaseExpires sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT state, lease_owner, lease_expires_at FROM inspection_runs WHERE run_id=?`, runID).Scan(&runState, &leaseOwner, &leaseExpires); errors.Is(err, sql.ErrNoRows) {
		return inspection.StepReconciliation{}, ErrNotFound
	} else if err != nil {
		return inspection.StepReconciliation{}, err
	}
	if runState == inspection.RunRunning {
		if err := assertLeaseTx(ctx, tx, runID, runOwner, inspection.RunRunning, now); err != nil {
			return inspection.StepReconciliation{}, err
		}
	} else if runState != inspection.RunReconciliationRequired || leaseOwner.Valid || leaseExpires.Valid {
		return inspection.StepReconciliation{}, ErrConflict
	}
	_, plan, err := getRunPlanTx(ctx, tx, `run_id=?`, runID)
	if err != nil {
		return inspection.StepReconciliation{}, err
	}
	step, ok := planStep(plan, stepID)
	if !ok {
		return inspection.StepReconciliation{}, ErrNotFound
	}
	var state inspection.StepState
	var attemptCount int
	if err := tx.QueryRowContext(ctx, `SELECT state, attempt_count FROM inspection_steps WHERE run_id=? AND step_id=?`, runID, stepID).Scan(&state, &attemptCount); errors.Is(err, sql.ErrNoRows) {
		return inspection.StepReconciliation{}, ErrNotFound
	} else if err != nil {
		return inspection.StepReconciliation{}, err
	}
	if state != inspection.StepOutcomeUnknown {
		return inspection.StepReconciliation{}, ErrConflict
	}
	var attemptID string
	if err := tx.QueryRowContext(ctx, `SELECT attempt_id FROM inspection_step_attempts WHERE run_id=? AND step_id=? AND attempt_number=? AND state=?`,
		runID, stepID, attemptCount, inspection.AttemptOutcomeUnknown).Scan(&attemptID); errors.Is(err, sql.ErrNoRows) {
		return inspection.StepReconciliation{}, errors.New("outcome-unknown step has no matching attempt")
	} else if err != nil {
		return inspection.StepReconciliation{}, err
	}
	targetState := inspection.StepFailed
	switch decision {
	case inspection.ReconciliationRetry:
		if step.Reconciliation != inspection.ReconcileBeforeRetry || attemptCount >= step.Budget.MaxAttempts || !now.Before(step.Deadline) || len(outputs) != 0 {
			return inspection.StepReconciliation{}, errors.New("inspection step is not eligible for a reconciled retry")
		}
		targetState = inspection.StepPending
	case inspection.ReconciliationSucceeded:
		targetState = inspection.StepSucceeded
		if err := validateOutputsForState(step, targetState, outputs); err != nil {
			return inspection.StepReconciliation{}, err
		}
	case inspection.ReconciliationFailed:
		if len(outputs) != 0 {
			return inspection.StepReconciliation{}, errors.New("failed reconciliation cannot publish outputs")
		}
	default:
		return inspection.StepReconciliation{}, errors.New("inspection reconciliation decision is invalid")
	}
	outputJSON, outputDigest, err := marshalStepOutputs(outputs)
	if err != nil {
		return inspection.StepReconciliation{}, err
	}
	reconciliationID := stepReconciliationID(attemptID, decision)
	if _, err := tx.ExecContext(ctx, `INSERT INTO inspection_step_reconciliations(
reconciliation_id, run_id, step_id, attempt_id, decision, reconciled_by, output_json, output_sha256, reason, created_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, reconciliationID, runID, stepID, attemptID, decision, reconciler,
		outputJSON, outputDigest, reason, formatTime(now)); err != nil {
		return inspection.StepReconciliation{}, constraintConflict(err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE inspection_steps SET state=?, output_json=?, output_sha256=?, reason=?, updated_at=? WHERE run_id=? AND step_id=? AND state=? AND attempt_count=?`,
		targetState, outputJSON, outputDigest, reason, formatTime(now), runID, stepID, inspection.StepOutcomeUnknown, attemptCount)
	if err != nil {
		return inspection.StepReconciliation{}, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return inspection.StepReconciliation{}, ErrConflict
	}
	reconciliation := inspection.StepReconciliation{
		ReconciliationID: reconciliationID, RunID: runID, StepID: stepID, AttemptID: attemptID,
		Decision: decision, ReconciledBy: reconciler, Outputs: append([]inspection.StepOutput(nil), outputs...),
		Reason: reason, CreatedAt: now,
	}
	if err := tx.Commit(); err != nil {
		return inspection.StepReconciliation{}, err
	}
	return reconciliation, nil
}

func (s *Store) ListStepReconciliations(ctx context.Context, runID, stepID string) ([]inspection.StepReconciliation, error) {
	if !validRef(runID) || !validRef(stepID) {
		return nil, errors.New("inspection step reconciliation scope is invalid")
	}
	plan, err := s.GetPlan(ctx, runID)
	if err != nil {
		return nil, err
	}
	step, ok := planStep(plan, stepID)
	if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT reconciliation_id, run_id, step_id, attempt_id, decision, reconciled_by, output_json, output_sha256, reason, created_at FROM inspection_step_reconciliations WHERE run_id=? AND step_id=? ORDER BY created_at, reconciliation_id`, runID, stepID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]inspection.StepReconciliation, 0, 1)
	for rows.Next() {
		var value inspection.StepReconciliation
		var outputJSON, outputDigest, createdRaw string
		if err := rows.Scan(&value.ReconciliationID, &value.RunID, &value.StepID, &value.AttemptID, &value.Decision,
			&value.ReconciledBy, &outputJSON, &outputDigest, &value.Reason, &createdRaw); err != nil {
			return nil, err
		}
		if value.CreatedAt, err = parseTime(createdRaw); err != nil {
			return nil, err
		}
		if value.Outputs, err = decodeStepOutputs(outputJSON, outputDigest); err != nil {
			return nil, err
		}
		expectedState := inspection.StepFailed
		switch value.Decision {
		case inspection.ReconciliationRetry:
			expectedState = inspection.StepPending
		case inspection.ReconciliationSucceeded:
			expectedState = inspection.StepSucceeded
		case inspection.ReconciliationFailed:
		default:
			return nil, errors.New("stored inspection reconciliation decision is invalid")
		}
		if !validRef(value.ReconciliationID) || value.RunID != runID || value.StepID != stepID || !validRef(value.AttemptID) ||
			!validRef(value.ReconciledBy) || !validReason(value.Reason) || value.CreatedAt.IsZero() ||
			value.ReconciliationID != stepReconciliationID(value.AttemptID, value.Decision) ||
			validateOutputsForState(step, expectedState, value.Outputs) != nil {
			return nil, errors.New("stored inspection step reconciliation failed its integrity binding")
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func scanStoredStep(row rowScanner) (inspection.StepRecord, error) {
	var record inspection.StepRecord
	var outputJSON, outputDigest, createdRaw, updatedRaw string
	var leaseOwner, leaseExpires sql.NullString
	if err := row.Scan(&record.RunID, &record.StepID, &record.Sequence, &record.Kind, &record.Authority, &record.State,
		&record.AttemptCount, &outputJSON, &outputDigest, &record.Reason, &leaseOwner, &leaseExpires, &createdRaw, &updatedRaw); err != nil {
		return inspection.StepRecord{}, err
	}
	var err error
	if record.CreatedAt, err = parseTime(createdRaw); err != nil {
		return inspection.StepRecord{}, err
	}
	if record.UpdatedAt, err = parseTime(updatedRaw); err != nil {
		return inspection.StepRecord{}, err
	}
	if record.Outputs, err = decodeStepOutputs(outputJSON, outputDigest); err != nil {
		return inspection.StepRecord{}, err
	}
	validStoredReason := validReason(record.Reason) || record.State == inspection.StepPending && record.AttemptCount == 0 && record.Reason == ""
	if !validRef(record.RunID) || !validRef(record.StepID) || record.Sequence < 1 || !record.State.Valid() ||
		record.AttemptCount < 0 || !validStoredReason || record.CreatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) {
		return inspection.StepRecord{}, errors.New("stored inspection step metadata is invalid")
	}
	if record.State == inspection.StepRunning {
		if !leaseOwner.Valid || !validRef(leaseOwner.String) || !leaseExpires.Valid {
			return inspection.StepRecord{}, errors.New("running inspection step has no valid lease")
		}
		if _, err := parseTime(leaseExpires.String); err != nil {
			return inspection.StepRecord{}, err
		}
	} else if leaseOwner.Valid || leaseExpires.Valid {
		return inspection.StepRecord{}, errors.New("non-running inspection step retains a lease")
	}
	return record, nil
}

func scanStoredAttempt(row rowScanner, step inspection.ExecutionStep) (inspection.StepAttempt, error) {
	var attempt inspection.StepAttempt
	var leaseRaw, outputJSON, outputDigest, startedRaw, updatedRaw string
	var finishedRaw sql.NullString
	if err := row.Scan(&attempt.AttemptID, &attempt.RunID, &attempt.StepID, &attempt.Number, &attempt.State, &attempt.Owner,
		&leaseRaw, &outputJSON, &outputDigest, &attempt.Reason, &startedRaw, &updatedRaw, &finishedRaw); err != nil {
		return inspection.StepAttempt{}, err
	}
	var err error
	if attempt.LeaseExpires, err = parseTime(leaseRaw); err != nil {
		return inspection.StepAttempt{}, err
	}
	if attempt.StartedAt, err = parseTime(startedRaw); err != nil {
		return inspection.StepAttempt{}, err
	}
	if attempt.UpdatedAt, err = parseTime(updatedRaw); err != nil {
		return inspection.StepAttempt{}, err
	}
	if finishedRaw.Valid {
		if attempt.FinishedAt, err = parseTime(finishedRaw.String); err != nil {
			return inspection.StepAttempt{}, err
		}
	}
	if attempt.Outputs, err = decodeStepOutputs(outputJSON, outputDigest); err != nil {
		return inspection.StepAttempt{}, err
	}
	if !attempt.State.Valid() || !validRef(attempt.Owner) || !validReason(attempt.Reason) || attempt.Number < 1 ||
		attempt.StartedAt.IsZero() || attempt.UpdatedAt.Before(attempt.StartedAt) ||
		(attempt.State == inspection.AttemptRunning) != attempt.FinishedAt.IsZero() {
		return inspection.StepAttempt{}, errors.New("stored inspection step attempt metadata is invalid")
	}
	stepState := inspection.StepFailed
	switch attempt.State {
	case inspection.AttemptRunning, inspection.AttemptAbandoned:
		stepState = inspection.StepPending
	case inspection.AttemptSucceeded:
		stepState = inspection.StepSucceeded
	case inspection.AttemptOutcomeUnknown:
		stepState = inspection.StepOutcomeUnknown
	}
	if attempt.State == inspection.AttemptRunning {
		if len(attempt.Outputs) != 0 {
			return inspection.StepAttempt{}, errors.New("running inspection attempt has outputs")
		}
	} else if err := validateOutputsForState(step, stepState, attempt.Outputs); err != nil {
		return inspection.StepAttempt{}, err
	}
	return attempt, nil
}

func validateOutputsForState(step inspection.ExecutionStep, state inspection.StepState, outputs []inspection.StepOutput) error {
	if state != inspection.StepSucceeded {
		if len(outputs) != 0 {
			return errors.New("non-successful inspection step cannot publish outputs")
		}
		return nil
	}
	if len(outputs) != len(step.OutputSlots) {
		return errors.New("successful inspection step output set does not match its frozen plan")
	}
	for index, output := range outputs {
		slot := step.OutputSlots[index]
		if output.LogicalRef != slot.LogicalRef || output.Kind != slot.Kind || !validRef(output.ValueRef) || !digestPattern.MatchString(output.SHA256) ||
			index > 0 && outputs[index-1].LogicalRef >= output.LogicalRef {
			return errors.New("inspection step outputs are invalid or not canonical")
		}
	}
	return nil
}

func marshalStepOutputs(outputs []inspection.StepOutput) (string, string, error) {
	canonical := append([]inspection.StepOutput(nil), outputs...)
	if canonical == nil {
		canonical = []inspection.StepOutput{}
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].LogicalRef < canonical[j].LogicalRef })
	for index, output := range canonical {
		if !validRef(output.LogicalRef) || !validStoredStepValueKind(output.Kind) || !validRef(output.ValueRef) || !digestPattern.MatchString(output.SHA256) ||
			index > 0 && canonical[index-1].LogicalRef >= output.LogicalRef {
			return "", "", errors.New("inspection step outputs are invalid")
		}
	}
	raw, digest, err := marshalPublic(canonical)
	return string(raw), digest, err
}

func validStoredStepValueKind(kind inspection.StepValueKind) bool {
	switch kind {
	case inspection.StepValueResolvedSources, inspection.StepValueExistingEvidence, inspection.StepValueMedia,
		inspection.StepValueAnalysis, inspection.StepValueResult, inspection.StepValueOutcome, inspection.StepValueCleanup:
		return true
	default:
		return false
	}
}

func decodeStepOutputs(raw, digest string) ([]inspection.StepOutput, error) {
	var outputs []inspection.StepOutput
	if err := json.Unmarshal([]byte(raw), &outputs); err != nil {
		return nil, err
	}
	canonical, computed, err := marshalStepOutputs(outputs)
	if err != nil {
		return nil, err
	}
	if canonical != raw || computed != digest {
		return nil, errors.New("stored inspection step outputs failed their integrity digest")
	}
	return outputs, nil
}

func planStep(plan inspection.ExecutionPlan, stepID string) (inspection.ExecutionStep, bool) {
	for _, step := range plan.Steps {
		if step.StepID == stepID {
			return step, true
		}
	}
	return inspection.ExecutionStep{}, false
}

func stepAttemptID(runID, stepID string, number int) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{runID, stepID, fmt.Sprintf("%d", number)}, "\x00")))
	return "attempt_" + hex.EncodeToString(digest[:16])
}

func stepReconciliationID(attemptID string, decision inspection.ReconciliationDecision) string {
	digest := sha256.Sum256([]byte(attemptID + "\x00" + string(decision)))
	return "recon_" + hex.EncodeToString(digest[:16])
}
