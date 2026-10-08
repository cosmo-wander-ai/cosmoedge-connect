package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const runColumns = `run_id, tenant_id, site_id, request_key, plan_sha256, state, conclusion, reason, persistent_config_writes, temporary_resources, cleanup_pending, authority_release_state, authority_released_at, deadline, created_at, updated_at`

const storedResultColumns = `observation_id, result_id, run_id, target_id, criterion_id, sample_id, usage, output_kind, assessment, content_sha256, result_json, captured_at, observed_at, recorded_at`

const maxStoredTemporaryResources = 4096

const (
	authorityReleasePending  = "pending"
	authorityReleaseReleased = "released"
	maxAuthorityReleaseBatch = 1024
)

func (s *Store) CreateQueuedRun(ctx context.Context, plan inspection.ExecutionPlan, runID string, now time.Time) (inspection.Run, bool, error) {
	if !validRef(runID) || now.IsZero() {
		return inspection.Run{}, false, errors.New("complete inspection run creation metadata is required")
	}
	planJSON, err := validateAndMarshalPlan(plan)
	if err != nil {
		return inspection.Run{}, false, err
	}
	now = now.UTC()
	if now.Before(plan.RequestedAt) {
		return inspection.Run{}, false, fmt.Errorf("%w: inspection run cannot be queued before its requested time", ErrConflict)
	}
	run := inspection.Run{
		RunID: runID, TenantID: plan.TenantID, SiteID: plan.SiteID, RequestKey: plan.RequestKey,
		PlanSHA256: plan.PlanSHA256, State: inspection.RunQueued, Reason: "plan_admitted",
		CreatedAt: now, UpdatedAt: now, Deadline: plan.Deadline.UTC(),
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inspection.Run{}, false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO inspection_runs(run_id, tenant_id, site_id, request_key, plan_sha256, plan_json, state, reason, deadline, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, request_key) DO NOTHING`,
		run.RunID, run.TenantID, run.SiteID, run.RequestKey, run.PlanSHA256, string(planJSON), run.State, run.Reason,
		formatTime(run.Deadline), formatTime(run.CreatedAt), formatTime(run.UpdatedAt))
	if err != nil {
		return inspection.Run{}, false, constraintConflict(err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		existing, storedPlan, err := getRunPlanTx(ctx, tx, `tenant_id=? AND request_key=?`, plan.TenantID, plan.RequestKey)
		if err != nil {
			return inspection.Run{}, false, err
		}
		if existing.PlanSHA256 != plan.PlanSHA256 || storedPlan.PlanSHA256 != plan.PlanSHA256 {
			return inspection.Run{}, false, ErrConflict
		}
		if _, err := listStepsTx(ctx, tx, existing.RunID, storedPlan); err != nil {
			return inspection.Run{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return inspection.Run{}, false, err
		}
		return existing, false, nil
	}
	if err := insertPlanStepsTx(ctx, tx, runID, plan, now); err != nil {
		return inspection.Run{}, false, err
	}
	for _, event := range []inspection.RunEvent{
		{RunID: runID, Type: "run_created", To: inspection.RunRequested, Reason: "request_accepted", OccurredAt: now},
		{RunID: runID, Type: "state_changed", From: inspection.RunRequested, To: inspection.RunAdmitted, Reason: "plan_validated", OccurredAt: now},
		{RunID: runID, Type: "state_changed", From: inspection.RunAdmitted, To: inspection.RunQueued, Reason: "plan_admitted", OccurredAt: now},
	} {
		if err := appendEventTx(ctx, tx, event); err != nil {
			return inspection.Run{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return inspection.Run{}, false, err
	}
	return run, true, nil
}

func (s *Store) GetRun(ctx context.Context, runID string) (inspection.Run, error) {
	run, _, err := scanClaim(s.db.QueryRowContext(ctx, `SELECT `+runColumns+`, plan_json FROM inspection_runs WHERE run_id=?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return inspection.Run{}, ErrNotFound
	}
	return run, err
}

// ListPendingAuthorityReleases returns terminal runs whose execution authority
// has not yet been durably acknowledged as revoked. It intentionally returns
// only opaque run identities; authorization contents remain broker-private.
func (s *Store) ListPendingAuthorityReleases(ctx context.Context, limit int) ([]string, error) {
	if s == nil || limit < 1 || limit > maxAuthorityReleaseBatch {
		return nil, errors.New("inspection authority release batch is invalid")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+runColumns+` FROM inspection_runs
WHERE authority_release_state='pending' AND state IN ('completed','partial','blocked','unknown','failed','cancelled','expired')
ORDER BY run_id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]string, 0, limit)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, run.RunID)
	}
	return result, rows.Err()
}

// MarkAuthorityReleased is the second half of a revoke-then-ack protocol. The
// broker must be revoked first. Replaying this acknowledgement is idempotent;
// reopening a released row is forbidden by the schema trigger.
func (s *Store) MarkAuthorityReleased(ctx context.Context, runID string, at time.Time) error {
	if s == nil || !validRef(runID) || at.IsZero() {
		return errors.New("inspection authority release acknowledgement is invalid")
	}
	at = at.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state inspection.RunState
	var releaseState, releasedAtRaw, updatedAtRaw string
	if err := tx.QueryRowContext(ctx, `SELECT state,authority_release_state,authority_released_at,updated_at
FROM inspection_runs WHERE run_id=?`, runID).Scan(&state, &releaseState, &releasedAtRaw, &updatedAtRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	updatedAt, err := parseTime(updatedAtRaw)
	if err != nil || !inspection.Terminal(state) {
		return ErrConflict
	}
	if releaseState == authorityReleaseReleased {
		if releasedAt, parseErr := parseTime(releasedAtRaw); parseErr != nil || releasedAt.Before(updatedAt) {
			return errors.New("stored inspection authority release is invalid")
		}
		return tx.Commit()
	}
	if releaseState != authorityReleasePending || releasedAtRaw != "" {
		return errors.New("stored inspection authority release is invalid")
	}
	// The persisted terminal timestamp is the logical lower bound. A restarted
	// manager may observe an earlier wall clock; acknowledgement must still
	// converge after the broker has already been irreversibly revoked.
	if at.Before(updatedAt) {
		at = updatedAt
	}
	result, err := tx.ExecContext(ctx, `UPDATE inspection_runs
SET authority_release_state='released',authority_released_at=?,updated_at=?
WHERE run_id=? AND state=? AND authority_release_state='pending' AND authority_released_at='' AND updated_at=?`,
		formatTime(at), formatTime(at), runID, state, updatedAtRaw)
	if err != nil {
		return constraintConflict(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (s *Store) GetPlan(ctx context.Context, runID string) (inspection.ExecutionPlan, error) {
	_, plan, err := scanClaim(s.db.QueryRowContext(ctx, `SELECT `+runColumns+`, plan_json FROM inspection_runs WHERE run_id=?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return inspection.ExecutionPlan{}, ErrNotFound
	}
	if err != nil {
		return inspection.ExecutionPlan{}, err
	}
	return plan, nil
}

func (s *Store) GetOutcome(ctx context.Context, runID string) (inspection.Outcome, bool, error) {
	var raw sql.NullString
	var state inspection.RunState
	var conclusion, reason string
	err := s.db.QueryRowContext(ctx, `SELECT state, conclusion, reason, outcome_json FROM inspection_runs WHERE run_id=?`, runID).Scan(&state, &conclusion, &reason, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return inspection.Outcome{}, false, ErrNotFound
	}
	if err != nil {
		return inspection.Outcome{}, false, err
	}
	if !raw.Valid {
		return inspection.Outcome{}, false, nil
	}
	var outcome inspection.Outcome
	if err := json.Unmarshal([]byte(raw.String), &outcome); err != nil {
		return inspection.Outcome{}, false, fmt.Errorf("decode stored inspection outcome: %w", err)
	}
	if err := validateStoredOutcome(outcome); err != nil {
		return inspection.Outcome{}, false, fmt.Errorf("validate stored inspection outcome: %w", err)
	}
	canonical, _, err := marshalPublic(outcome)
	if err != nil {
		return inspection.Outcome{}, false, fmt.Errorf("canonicalize stored inspection outcome: %w", err)
	}
	if raw.String != string(canonical) || outcome.State != state || outcome.Conclusion != conclusion || outcome.Reason != reason {
		return inspection.Outcome{}, false, errors.New("stored inspection outcome failed its run integrity binding")
	}
	return outcome, true, nil
}

func (s *Store) ExpireQueued(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		return 0, errors.New("inspection queue expiry time is required")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+runColumns+`, plan_json FROM inspection_runs WHERE state=? AND deadline<=? ORDER BY run_id`, inspection.RunQueued, formatTime(now))
	if err != nil {
		return 0, err
	}
	type queuedPlan struct {
		run  inspection.Run
		plan inspection.ExecutionPlan
	}
	queued := make([]queuedPlan, 0)
	for rows.Next() {
		run, plan, err := scanClaim(rows)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("validate queued inspection plan: %w", err)
		}
		queued = append(queued, queuedPlan{run: run, plan: plan})
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	expired := 0
	for _, item := range queued {
		outcome := noObservationOutcome(item.plan, inspection.RunExpired, "queue_deadline_exceeded", "Inspection expired before execution began.")
		outcomeJSON, _, err := marshalPublic(outcome)
		if err != nil {
			return 0, err
		}
		row := tx.QueryRowContext(ctx, `UPDATE inspection_runs SET state=?, conclusion=?, reason=?, outcome_json=?, updated_at=? WHERE run_id=? AND state=? AND deadline<=? AND updated_at<=? RETURNING `+runColumns,
			inspection.RunExpired, outcome.Conclusion, outcome.Reason, string(outcomeJSON), formatTime(now), item.run.RunID,
			inspection.RunQueued, formatTime(now), formatTime(now))
		run, err := scanRun(row)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: item.run.RunID, Type: "state_changed", From: inspection.RunQueued, To: inspection.RunExpired, Reason: outcome.Reason, OccurredAt: now}); err != nil {
			return 0, err
		}
		if err := enqueueTerminalTx(ctx, tx, run, now); err != nil {
			return 0, err
		}
		expired++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return expired, nil
}

func (s *Store) ClaimNext(ctx context.Context, owner string, now time.Time, leaseTTL time.Duration) (inspection.Run, inspection.ExecutionPlan, bool, error) {
	if !validRef(owner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 24*time.Hour {
		return inspection.Run{}, inspection.ExecutionPlan{}, false, errors.New("valid bounded inspection lease metadata is required")
	}
	now, leaseExpires := now.UTC(), now.UTC().Add(leaseTTL)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, false, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `UPDATE inspection_runs
SET state=?, reason='worker_claimed', lease_owner=?,
    lease_expires_at=?,
    updated_at=?
WHERE run_id=(
    SELECT run_id FROM inspection_runs
    WHERE state=? AND deadline>?
    ORDER BY created_at, run_id LIMIT 1
) AND state=?
RETURNING `+runColumns+`, plan_json`,
		inspection.RunRunning, owner, formatTime(leaseExpires), formatTime(now),
		inspection.RunQueued, formatTime(now), inspection.RunQueued)
	run, plan, err := scanClaim(row)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return inspection.Run{}, inspection.ExecutionPlan{}, false, err
		}
		return inspection.Run{}, inspection.ExecutionPlan{}, false, nil
	}
	if err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, false, err
	}
	event := inspection.RunEvent{RunID: run.RunID, Type: "state_changed", From: inspection.RunQueued, To: inspection.RunRunning, Reason: "worker_claimed", OccurredAt: now}
	if err := appendEventTx(ctx, tx, event); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, false, err
	}
	return run, plan, true, nil
}

func (s *Store) RenewLease(ctx context.Context, runID, owner string, now time.Time, leaseTTL time.Duration) error {
	if !validRef(runID) || !validRef(owner) || now.IsZero() || leaseTTL <= 0 || leaseTTL > 24*time.Hour {
		return errors.New("valid bounded inspection lease renewal metadata is required")
	}
	// Heartbeats sample time before database admission. A newer business write
	// may already have committed; it does not fence out the same live owner.
	// Use the latest known logical time for expiry without changing event order.
	now, requestedExpiry := now.UTC(), now.UTC().Add(leaseTTL)
	result, err := s.db.ExecContext(ctx, `UPDATE inspection_runs
SET lease_expires_at=CASE
    WHEN lease_expires_at >= ? THEN lease_expires_at
    ELSE ?
END
WHERE run_id=? AND state=? AND lease_owner=? AND lease_expires_at>MAX(?, updated_at)`,
		formatTime(requestedExpiry), formatTime(requestedExpiry),
		runID, inspection.RunRunning, owner, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (s *Store) AppendPhase(ctx context.Context, runID, owner string, phase inspection.RunPhase, now time.Time, reason string) error {
	if !validRef(runID) || !validRef(owner) || now.IsZero() || !validReason(reason) {
		return errors.New("complete inspection phase metadata is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	run, err := getRunTx(ctx, tx, `run_id=?`, runID)
	if err != nil {
		return err
	}
	if err := assertLeaseTx(ctx, tx, runID, owner, inspection.RunRunning, now); err != nil {
		return err
	}
	event, err := inspection.PhaseEvent(run, phase, now, reason)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE inspection_runs SET updated_at=? WHERE run_id=? AND state=? AND lease_owner=? AND lease_expires_at>? AND updated_at<=?`,
		formatTime(now), runID, inspection.RunRunning, owner, formatTime(now), formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	if err := appendEventTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecordObservation(ctx context.Context, owner string, observation inspection.Observation, committedAt time.Time) error {
	binding := observation.Result.Binding
	runID, now := binding.RunID, committedAt.UTC()
	if !validRef(owner) || now.IsZero() || now.Before(observation.Result.Execution.CompletedAt) {
		return errors.New("complete inspection observation persistence metadata is required")
	}
	if err := observation.Validate(); err != nil {
		return err
	}
	raw, digest, err := marshalPublic(observation)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := assertLeaseTx(ctx, tx, runID, owner, inspection.RunRunning, now); err != nil {
		return err
	}
	if err := validateObservationAgainstPlanTx(ctx, tx, observation); err != nil {
		return err
	}
	capturedAt := earliestResultCapture(binding.SourceMedia)
	observedAt := binding.TimeWindow.EndAt.UTC()
	result, err := tx.ExecContext(ctx, `INSERT INTO inspection_results(observation_id, result_id, run_id, target_id, criterion_id, sample_id, usage, output_kind, assessment, content_sha256, result_json, captured_at, observed_at, recorded_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(observation_id) DO NOTHING`,
		observation.ObservationID, binding.ResultID, runID, binding.TargetID, binding.CriterionID, observation.SampleID,
		binding.Usage, binding.OutputKind, observation.Result.Assessment, digest, string(raw), formatTime(capturedAt), formatTime(observedAt), formatTime(now))
	if err != nil {
		return constraintConflict(err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		existing, err := scanStoredObservation(tx.QueryRowContext(ctx, `SELECT `+storedResultColumns+` FROM inspection_results WHERE observation_id=?`, observation.ObservationID), runID)
		if err != nil {
			return err
		}
		_, existingDigest, err := marshalPublic(existing)
		if err != nil {
			return err
		}
		if existingDigest != digest {
			return ErrConflict
		}
		if err := validateStoredResultMediaTx(ctx, tx, existing); err != nil {
			return err
		}
		return tx.Commit()
	}
	for _, source := range binding.SourceMedia {
		if _, err := tx.ExecContext(ctx, `INSERT INTO inspection_result_media(observation_id, ordinal, media_ref, content_sha256, source_ref, captured_at) VALUES(?, ?, ?, ?, ?, ?)`,
			observation.ObservationID, source.SampleOrdinal, source.MediaRef, source.SHA256, source.SourceRef, formatTime(source.CapturedAt)); err != nil {
			return constraintConflict(err)
		}
	}
	result, err = tx.ExecContext(ctx, `UPDATE inspection_runs SET updated_at=? WHERE run_id=? AND state=? AND lease_owner=? AND lease_expires_at>? AND updated_at<=?`,
		formatTime(now), runID, inspection.RunRunning, owner, formatTime(now), formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	public, _ := json.Marshal(map[string]string{"resultId": binding.ResultID, "targetId": binding.TargetID, "criterionId": binding.CriterionID, "assessment": string(observation.Result.Assessment), "outputKind": string(binding.OutputKind)})
	if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: runID, Type: "result_recorded", Reason: "typed_result_validated", OccurredAt: now, PublicJSON: public}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListObservations(ctx context.Context, runID string) ([]inspection.Observation, error) {
	plan, err := s.GetPlan(ctx, runID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+storedResultColumns+` FROM inspection_results WHERE run_id=? ORDER BY observed_at, observation_id`, runID)
	if err != nil {
		return nil, err
	}
	result := make([]inspection.Observation, 0)
	for rows.Next() {
		observation, err := scanStoredObservation(rows, runID)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if err := validateObservationAgainstPlan(plan, observation); err != nil {
			rows.Close()
			return nil, fmt.Errorf("validate stored inspection observation plan binding: %w", err)
		}
		result = append(result, observation)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, observation := range result {
		if err := validateStoredResultMediaDB(ctx, s.db, observation); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Store) RecordResourceUsage(ctx context.Context, runID, owner string, temporaryResources, cleanupPending int, now time.Time) error {
	if !validRef(runID) || !validRef(owner) || temporaryResources < 0 || temporaryResources > maxStoredTemporaryResources || cleanupPending < 0 || cleanupPending > temporaryResources || now.IsZero() {
		return errors.New("inspection resource usage is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := assertLeaseTx(ctx, tx, runID, owner, inspection.RunRunning, now); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE inspection_runs SET temporary_resources=?, cleanup_pending=?, updated_at=? WHERE run_id=? AND state=? AND lease_owner=? AND lease_expires_at>? AND updated_at<=?`,
		temporaryResources, cleanupPending, formatTime(now), runID, inspection.RunRunning, owner, formatTime(now), formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrLeaseLost
	}
	public, _ := json.Marshal(map[string]int{"temporaryResources": temporaryResources, "cleanupPending": cleanupPending, "persistentConfigWrites": 0})
	if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: runID, Type: "resource_usage_recorded", Reason: "bounded_temporary_resources_observed", OccurredAt: now, PublicJSON: public}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BeginFinalization(ctx context.Context, runID, owner string, now time.Time) error {
	if !validRef(runID) || !validRef(owner) || now.IsZero() {
		return errors.New("complete inspection finalization metadata is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `UPDATE inspection_runs SET state=?, reason='typed_results_complete', updated_at=? WHERE run_id=? AND state=? AND lease_owner=? AND lease_expires_at>? AND updated_at<=? RETURNING `+runColumns,
		inspection.RunFinalizing, formatTime(now), runID, inspection.RunRunning, owner, formatTime(now), formatTime(now))
	run, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: runID, Type: "state_changed", From: inspection.RunRunning, To: inspection.RunFinalizing, Reason: "typed_results_complete", OccurredAt: now}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = run
	return nil
}

func (s *Store) Finalize(ctx context.Context, runID, owner string, outcome inspection.Outcome, now time.Time) error {
	if !validRef(runID) || !validRef(owner) || now.IsZero() {
		return errors.New("complete inspection outcome persistence metadata is required")
	}
	if err := validateOutcome(outcome); err != nil {
		return err
	}
	raw, _, err := marshalPublic(outcome)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `UPDATE inspection_runs SET state=?, conclusion=?, reason=?, outcome_json=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE run_id=? AND state=? AND lease_owner=? AND lease_expires_at>? AND updated_at<=? RETURNING `+runColumns,
		outcome.State, outcome.Conclusion, outcome.Reason, string(raw), formatTime(now), runID, inspection.RunFinalizing, owner, formatTime(now), formatTime(now))
	run, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: runID, Type: "state_changed", From: inspection.RunFinalizing, To: outcome.State, Reason: outcome.Reason, OccurredAt: now}); err != nil {
		return err
	}
	if err := enqueueTerminalTx(ctx, tx, run, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) Cancel(ctx context.Context, runID string, now time.Time, reason string) error {
	if !validRef(runID) || now.IsZero() || !validReason(reason) {
		return errors.New("complete inspection cancellation metadata is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, plan, err := scanClaim(tx.QueryRowContext(ctx, `SELECT `+runColumns+`, plan_json FROM inspection_runs WHERE run_id=? AND state=?`, runID, inspection.RunQueued))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	} else if err != nil {
		return err
	}
	outcome := noObservationOutcome(plan, inspection.RunCancelled, reason, "Inspection was cancelled before execution.")
	outcomeJSON, _, err := marshalPublic(outcome)
	if err != nil {
		return err
	}
	row := tx.QueryRowContext(ctx, `UPDATE inspection_runs SET state=?, conclusion=?, reason=?, outcome_json=?, updated_at=? WHERE run_id=? AND state=? AND updated_at<=? RETURNING `+runColumns,
		inspection.RunCancelled, outcome.Conclusion, outcome.Reason, string(outcomeJSON), formatTime(now), runID, inspection.RunQueued, formatTime(now))
	run, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: runID, Type: "state_changed", From: inspection.RunQueued, To: inspection.RunCancelled, Reason: reason, OccurredAt: now}); err != nil {
		return err
	}
	if err := enqueueTerminalTx(ctx, tx, run, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) RecoverInterrupted(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		return 0, errors.New("inspection recovery time is required")
	}
	now = now.UTC()
	if _, err := s.RecoverExpiredStepAttempts(ctx, now); err != nil {
		return 0, fmt.Errorf("recover expired inspection steps: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+runColumns+`, plan_json FROM inspection_runs WHERE state IN (?, ?) AND (lease_expires_at IS NULL OR lease_expires_at<=?) ORDER BY run_id`, inspection.RunRunning, inspection.RunFinalizing, formatTime(now))
	if err != nil {
		return 0, err
	}
	type interrupted struct {
		run  inspection.Run
		plan inspection.ExecutionPlan
	}
	items := make([]interrupted, 0)
	for rows.Next() {
		run, plan, err := scanClaim(rows)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("validate interrupted inspection plan: %w", err)
		}
		items = append(items, interrupted{run: run, plan: plan})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	recovered := 0
	for _, item := range items {
		if item.run.State == inspection.RunRunning {
			steps, err := listStepsTx(ctx, tx, item.run.RunID, item.plan)
			if err != nil {
				return 0, err
			}
			requiresReconciliation := false
			for _, step := range steps {
				if step.State == inspection.StepRunning {
					return 0, errors.New("expired inspection run retains a live step lease")
				}
				if step.State == inspection.StepOutcomeUnknown {
					requiresReconciliation = true
				}
			}
			target, reason := inspection.RunQueued, "replayable_step_interrupted"
			if requiresReconciliation {
				target, reason = inspection.RunReconciliationRequired, "step_reconciliation_required"
			}
			row := tx.QueryRowContext(ctx, `UPDATE inspection_runs SET state=?, reason=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE run_id=? AND state=? AND (lease_expires_at IS NULL OR lease_expires_at<=?) RETURNING `+runColumns,
				target, reason, formatTime(now), item.run.RunID, inspection.RunRunning, formatTime(now))
			if _, err := scanRun(row); errors.Is(err, sql.ErrNoRows) {
				continue
			} else if err != nil {
				return 0, err
			}
			if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: item.run.RunID, Type: "state_changed", From: inspection.RunRunning, To: target, Reason: reason, OccurredAt: now}); err != nil {
				return 0, err
			}
			recovered++
			continue
		}

		const reason = "finalization_lease_expired"
		const conclusion = "Inspection finalization was interrupted; its delivery outcome is unknown."
		outcome, err := recoveredOutcomeTx(ctx, tx, item.run.RunID, item.plan, reason, conclusion)
		if err != nil {
			return 0, err
		}
		outcomeJSON, _, err := marshalPublic(outcome)
		if err != nil {
			return 0, err
		}
		row := tx.QueryRowContext(ctx, `UPDATE inspection_runs SET state=?, conclusion=?, reason=?, outcome_json=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE run_id=? AND state=? AND (lease_expires_at IS NULL OR lease_expires_at<=?) RETURNING `+runColumns,
			inspection.RunUnknown, conclusion, reason, string(outcomeJSON), formatTime(now), item.run.RunID, item.run.State, formatTime(now))
		run, err := scanRun(row)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: item.run.RunID, Type: "state_changed", From: item.run.State, To: inspection.RunUnknown, Reason: reason, OccurredAt: now}); err != nil {
			return 0, err
		}
		if err := enqueueTerminalTx(ctx, tx, run, now); err != nil {
			return 0, err
		}
		recovered++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return recovered, nil
}

// ResumeReconciledRun returns a run to the queue only after every uncertain
// step has an explicit reconciliation decision and no attempt remains live.
func (s *Store) ResumeReconciledRun(ctx context.Context, runID, reconciler string, now time.Time) error {
	if !validRef(runID) || !validRef(reconciler) || now.IsZero() {
		return errors.New("inspection reconciliation resume metadata is invalid")
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	run, plan, err := getRunPlanTx(ctx, tx, `run_id=? AND state=?`, runID, inspection.RunReconciliationRequired)
	if err != nil {
		return err
	}
	steps, err := listStepsTx(ctx, tx, runID, plan)
	if err != nil {
		return err
	}
	for _, step := range steps {
		if step.State == inspection.StepRunning || step.State == inspection.StepOutcomeUnknown {
			return errors.New("inspection run still has unreconciled steps")
		}
	}
	var decisions int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM inspection_step_reconciliations WHERE run_id=?`, runID).Scan(&decisions); err != nil {
		return err
	}
	if decisions == 0 {
		return errors.New("inspection run has no durable reconciliation decision")
	}
	const reason = "step_reconciliation_completed"
	result, err := tx.ExecContext(ctx, `UPDATE inspection_runs SET state=?, reason=?, updated_at=? WHERE run_id=? AND state=? AND updated_at<=?`,
		inspection.RunQueued, reason, formatTime(now), runID, inspection.RunReconciliationRequired, formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	if err := appendEventTx(ctx, tx, inspection.RunEvent{RunID: run.RunID, Type: "state_changed", From: inspection.RunReconciliationRequired, To: inspection.RunQueued, Reason: reason, OccurredAt: now}); err != nil {
		return err
	}
	return tx.Commit()
}

func recoveredOutcomeTx(ctx context.Context, tx *sql.Tx, runID string, plan inspection.ExecutionPlan, reason, conclusion string) (inspection.Outcome, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+storedResultColumns+` FROM inspection_results WHERE run_id=? ORDER BY observed_at, observation_id`, runID)
	if err != nil {
		return inspection.Outcome{}, err
	}
	observations := make([]inspection.Observation, 0)
	for rows.Next() {
		observation, err := scanStoredObservation(rows, runID)
		if err != nil {
			rows.Close()
			return inspection.Outcome{}, err
		}
		if err := validateObservationAgainstPlan(plan, observation); err != nil {
			rows.Close()
			return inspection.Outcome{}, fmt.Errorf("validate interrupted inspection observation plan binding: %w", err)
		}
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inspection.Outcome{}, err
	}
	if err := rows.Close(); err != nil {
		return inspection.Outcome{}, err
	}
	for _, observation := range observations {
		if err := validateStoredResultMediaTx(ctx, tx, observation); err != nil {
			return inspection.Outcome{}, err
		}
	}
	outcome, err := inspection.Evaluate(plan, observations)
	if err != nil {
		return inspection.Outcome{}, fmt.Errorf("evaluate interrupted inspection outcome: %w", err)
	}
	outcome.State = inspection.RunUnknown
	outcome.Reason = reason
	outcome.Conclusion = conclusion
	if err := validateOutcome(outcome); err != nil {
		return inspection.Outcome{}, err
	}
	return outcome, nil
}

func (s *Store) ListEvents(ctx context.Context, runID string) ([]inspection.RunEvent, error) {
	run, err := s.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT run_id, sequence, event_type, from_state, to_state, phase, reason, occurred_at, public_json FROM inspection_run_events WHERE run_id=? ORDER BY sequence`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]inspection.RunEvent, 0)
	var current inspection.RunState
	var previousSequence int64
	var previousTime time.Time
	for rows.Next() {
		var event inspection.RunEvent
		var storedRunID, occurredAt, publicJSON string
		if err := rows.Scan(&storedRunID, &event.Sequence, &event.Type, &event.From, &event.To, &event.Phase, &event.Reason, &occurredAt, &publicJSON); err != nil {
			return nil, err
		}
		event.RunID = storedRunID
		if event.OccurredAt, err = parseTime(occurredAt); err != nil {
			return nil, err
		}
		event.PublicJSON = json.RawMessage(publicJSON)
		if err := validateStoredEvent(event, runID, current, previousSequence, previousTime); err != nil {
			return nil, err
		}
		if event.Type == "run_created" || event.Type == "state_changed" {
			current = event.To
		}
		previousSequence = event.Sequence
		previousTime = event.OccurredAt
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 || current != run.State {
		return nil, errors.New("stored inspection events failed their run state binding")
	}
	return result, nil
}

func getRunTx(ctx context.Context, tx *sql.Tx, predicate string, args ...any) (inspection.Run, error) {
	run, _, err := scanClaim(tx.QueryRowContext(ctx, `SELECT `+runColumns+`, plan_json FROM inspection_runs WHERE `+predicate, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return inspection.Run{}, ErrNotFound
	}
	return run, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanRun(row rowScanner) (inspection.Run, error) {
	var run inspection.Run
	var authorityState, authorityReleasedAt, deadline, createdAt, updatedAt string
	err := row.Scan(&run.RunID, &run.TenantID, &run.SiteID, &run.RequestKey, &run.PlanSHA256, &run.State,
		&run.Conclusion, &run.Reason, &run.PersistentConfigWrites, &run.TemporaryResources, &run.CleanupPending,
		&authorityState, &authorityReleasedAt, &deadline, &createdAt, &updatedAt)
	if err != nil {
		return inspection.Run{}, err
	}
	if run.Deadline, err = parseTime(deadline); err != nil {
		return inspection.Run{}, err
	}
	if run.CreatedAt, err = parseTime(createdAt); err != nil {
		return inspection.Run{}, err
	}
	if run.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return inspection.Run{}, err
	}
	if err := validateStoredRun(run); err != nil {
		return inspection.Run{}, err
	}
	if err := validateStoredAuthorityRelease(run, authorityState, authorityReleasedAt); err != nil {
		return inspection.Run{}, err
	}
	return run, nil
}

func scanClaim(row rowScanner) (inspection.Run, inspection.ExecutionPlan, error) {
	var run inspection.Run
	var authorityState, authorityReleasedAt, deadline, createdAt, updatedAt, planJSON string
	err := row.Scan(&run.RunID, &run.TenantID, &run.SiteID, &run.RequestKey, &run.PlanSHA256, &run.State,
		&run.Conclusion, &run.Reason, &run.PersistentConfigWrites, &run.TemporaryResources, &run.CleanupPending,
		&authorityState, &authorityReleasedAt, &deadline, &createdAt, &updatedAt, &planJSON)
	if err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, err
	}
	if run.Deadline, err = parseTime(deadline); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, err
	}
	if run.CreatedAt, err = parseTime(createdAt); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, err
	}
	if run.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, err
	}
	if err := validateStoredRun(run); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, err
	}
	if err := validateStoredAuthorityRelease(run, authorityState, authorityReleasedAt); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, err
	}
	var plan inspection.ExecutionPlan
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, fmt.Errorf("decode stored inspection plan: %w", err)
	}
	canonical, err := validateAndMarshalPlan(plan)
	if err != nil {
		return inspection.Run{}, inspection.ExecutionPlan{}, fmt.Errorf("validate stored inspection plan: %w", err)
	}
	if planJSON != string(canonical) || run.PlanSHA256 != plan.PlanSHA256 || run.TenantID != plan.TenantID ||
		run.SiteID != plan.SiteID || run.RequestKey != plan.RequestKey || !run.Deadline.Equal(plan.Deadline) {
		return inspection.Run{}, inspection.ExecutionPlan{}, errors.New("stored inspection plan failed its run integrity binding")
	}
	return run, plan, nil
}

func validateStoredAuthorityRelease(run inspection.Run, state, releasedAtRaw string) error {
	switch state {
	case authorityReleasePending:
		if releasedAtRaw != "" {
			return errors.New("stored inspection authority release is incomplete")
		}
	case authorityReleaseReleased:
		if !inspection.Terminal(run.State) {
			return errors.New("non-terminal inspection run released its execution authority")
		}
		releasedAt, err := parseTime(releasedAtRaw)
		if err != nil || releasedAt.Before(run.CreatedAt) || releasedAt.After(run.UpdatedAt) {
			return errors.New("stored inspection authority release time is invalid")
		}
	default:
		return errors.New("stored inspection authority release state is invalid")
	}
	return nil
}

func validateStoredRun(run inspection.Run) error {
	if !validRef(run.RunID) || !validRef(run.TenantID) || !validRef(run.SiteID) ||
		!requestKeyPattern.MatchString(run.RequestKey) || !digestPattern.MatchString(run.PlanSHA256) ||
		!validRunState(run.State) || !validReason(run.Reason) {
		return errors.New("stored inspection run metadata is invalid")
	}
	if run.PersistentConfigWrites != 0 || run.TemporaryResources < 0 || run.TemporaryResources > maxStoredTemporaryResources ||
		run.CleanupPending < 0 || run.CleanupPending > run.TemporaryResources {
		return errors.New("stored inspection run resource usage is invalid")
	}
	if run.CreatedAt.IsZero() || run.UpdatedAt.IsZero() || run.Deadline.IsZero() || run.UpdatedAt.Before(run.CreatedAt) {
		return errors.New("stored inspection run timestamps are invalid")
	}
	conclusion := strings.TrimSpace(run.Conclusion)
	if inspection.Terminal(run.State) {
		if conclusion == "" || conclusion != run.Conclusion || len(conclusion) > 1000 ||
			strings.ContainsAny(conclusion, "\x00\r\n") || protectedPayload.MatchString(conclusion) {
			return errors.New("stored terminal inspection run conclusion is invalid")
		}
	} else if run.Conclusion != "" {
		return errors.New("stored non-terminal inspection run has a conclusion")
	}
	return nil
}

func validRunState(state inspection.RunState) bool {
	switch state {
	case inspection.RunRequested, inspection.RunAdmitted, inspection.RunQueued, inspection.RunRunning, inspection.RunReconciliationRequired,
		inspection.RunFinalizing, inspection.RunCompleted, inspection.RunPartial, inspection.RunBlocked,
		inspection.RunUnknown, inspection.RunFailed, inspection.RunCancelled, inspection.RunExpired:
		return true
	default:
		return false
	}
}

func validRunPhase(phase inspection.RunPhase) bool {
	switch phase {
	case inspection.PhaseResolving, inspection.PhaseCapturing, inspection.PhaseAnalyzing,
		inspection.PhaseValidating, inspection.PhaseComposing, inspection.PhaseCleaning:
		return true
	default:
		return false
	}
}

type resultEventPublic struct {
	Assessment  string `json:"assessment"`
	CriterionID string `json:"criterionId"`
	OutputKind  string `json:"outputKind"`
	ResultID    string `json:"resultId"`
	TargetID    string `json:"targetId"`
}

type resourceEventPublic struct {
	CleanupPending         int `json:"cleanupPending"`
	PersistentConfigWrites int `json:"persistentConfigWrites"`
	TemporaryResources     int `json:"temporaryResources"`
}

func validateStoredEvent(event inspection.RunEvent, expectedRunID string, current inspection.RunState, previousSequence int64, previousTime time.Time) error {
	if event.RunID != expectedRunID || !validRef(event.RunID) || event.Sequence <= previousSequence || event.Sequence <= 0 ||
		!validRef(event.Type) || !validReason(event.Reason) || event.OccurredAt.IsZero() ||
		(!previousTime.IsZero() && event.OccurredAt.Before(previousTime)) || !json.Valid(event.PublicJSON) ||
		protectedPayload.Match(event.PublicJSON) {
		return errors.New("stored inspection event failed its row integrity binding")
	}

	switch event.Type {
	case "run_created":
		if current != "" || event.From != "" || event.To != inspection.RunRequested || event.Phase != "" || string(event.PublicJSON) != "{}" {
			return errors.New("stored inspection creation event is invalid")
		}
	case "state_changed":
		if current == "" || event.From != current || !inspection.CanTransition(event.From, event.To) || event.Phase != "" || string(event.PublicJSON) != "{}" {
			return errors.New("stored inspection state event is invalid")
		}
	case "phase_observed":
		if current != inspection.RunRunning || event.From != "" || event.To != "" || !validRunPhase(event.Phase) || string(event.PublicJSON) != "{}" {
			return errors.New("stored inspection phase event is invalid")
		}
	case "result_recorded":
		var public resultEventPublic
		if current != inspection.RunRunning || event.From != "" || event.To != "" || event.Phase != "" ||
			event.Reason != "typed_result_validated" || decodeCanonicalEventPublic(event.PublicJSON, &public) != nil ||
			!validRef(public.ResultID) || !validRef(public.TargetID) || !validRef(public.CriterionID) ||
			!inspection.ResultKind(public.OutputKind).Valid() || !inspection.Assessment(public.Assessment).Valid() {
			return errors.New("stored inspection result event is invalid")
		}
	case "resource_usage_recorded":
		var public resourceEventPublic
		if current != inspection.RunRunning || event.From != "" || event.To != "" || event.Phase != "" ||
			event.Reason != "bounded_temporary_resources_observed" || decodeCanonicalEventPublic(event.PublicJSON, &public) != nil ||
			public.PersistentConfigWrites != 0 || public.TemporaryResources < 0 || public.TemporaryResources > maxStoredTemporaryResources ||
			public.CleanupPending < 0 || public.CleanupPending > public.TemporaryResources {
			return errors.New("stored inspection resource event is invalid")
		}
	default:
		return errors.New("stored inspection event type is unsupported")
	}
	return nil
}

func decodeCanonicalEventPublic(raw json.RawMessage, output any) error {
	if err := strictjson.ValidateExactFields(raw, output, 4); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, output); err != nil {
		return err
	}
	canonical, err := json.Marshal(output)
	if err != nil {
		return err
	}
	if string(canonical) != string(raw) {
		return errors.New("stored inspection event public data is not canonical")
	}
	return nil
}

func getRunPlanTx(ctx context.Context, tx *sql.Tx, predicate string, args ...any) (inspection.Run, inspection.ExecutionPlan, error) {
	run, plan, err := scanClaim(tx.QueryRowContext(ctx, `SELECT `+runColumns+`, plan_json FROM inspection_runs WHERE `+predicate, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return inspection.Run{}, inspection.ExecutionPlan{}, ErrNotFound
	}
	return run, plan, err
}

func scanStoredObservation(row rowScanner, expectedRunID string) (inspection.Observation, error) {
	var observationID, resultID, runID, targetID, criterionID, sampleID, usage, outputKind, assessment, digest, raw string
	var capturedAt, observedAt, recordedAt string
	if err := row.Scan(&observationID, &resultID, &runID, &targetID, &criterionID, &sampleID, &usage, &outputKind, &assessment, &digest, &raw, &capturedAt, &observedAt, &recordedAt); err != nil {
		return inspection.Observation{}, err
	}
	var observation inspection.Observation
	if err := json.Unmarshal([]byte(raw), &observation); err != nil {
		return inspection.Observation{}, fmt.Errorf("decode stored inspection observation: %w", err)
	}
	if err := observation.Validate(); err != nil {
		return inspection.Observation{}, fmt.Errorf("validate stored inspection observation: %w", err)
	}
	canonical, computedDigest, err := marshalPublic(observation)
	if err != nil {
		return inspection.Observation{}, fmt.Errorf("canonicalize stored inspection observation: %w", err)
	}
	storedCapturedAt, err := parseTime(capturedAt)
	if err != nil {
		return inspection.Observation{}, err
	}
	storedObservedAt, err := parseTime(observedAt)
	if err != nil {
		return inspection.Observation{}, err
	}
	if _, err := parseTime(recordedAt); err != nil {
		return inspection.Observation{}, err
	}
	binding := observation.Result.Binding
	if raw != string(canonical) || digest != computedDigest || runID != expectedRunID ||
		observation.ObservationID != observationID || binding.ResultID != resultID || binding.RunID != runID || binding.TargetID != targetID ||
		binding.CriterionID != criterionID || observation.SampleID != sampleID || string(binding.Usage) != usage ||
		string(binding.OutputKind) != outputKind || string(observation.Result.Assessment) != assessment ||
		!earliestResultCapture(binding.SourceMedia).Equal(storedCapturedAt) || !binding.TimeWindow.EndAt.Equal(storedObservedAt) {
		return inspection.Observation{}, errors.New("stored inspection observation failed its row integrity binding")
	}
	return observation, nil
}

type resultMediaQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func validateStoredResultMediaDB(ctx context.Context, db *sql.DB, observation inspection.Observation) error {
	return validateStoredResultMedia(ctx, db, observation)
}

func validateStoredResultMediaTx(ctx context.Context, tx *sql.Tx, observation inspection.Observation) error {
	return validateStoredResultMedia(ctx, tx, observation)
}

func validateStoredResultMedia(ctx context.Context, queryer resultMediaQueryer, observation inspection.Observation) error {
	rows, err := queryer.QueryContext(ctx, `SELECT ordinal, media_ref, content_sha256, source_ref, captured_at FROM inspection_result_media WHERE observation_id=? ORDER BY ordinal`, observation.ObservationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	expected := make(map[int]inspection.ResultSourceMedia, len(observation.Result.Binding.SourceMedia))
	for _, source := range observation.Result.Binding.SourceMedia {
		expected[source.SampleOrdinal] = source
	}
	seen := make(map[int]struct{}, len(expected))
	for rows.Next() {
		var ordinal int
		var mediaRef, digest, sourceRef, capturedAt string
		if err := rows.Scan(&ordinal, &mediaRef, &digest, &sourceRef, &capturedAt); err != nil {
			return err
		}
		captured, err := parseTime(capturedAt)
		if err != nil {
			return err
		}
		source, ok := expected[ordinal]
		if !ok || source.MediaRef != mediaRef || source.SHA256 != digest || source.SourceRef != sourceRef || !source.CapturedAt.Equal(captured) {
			return errors.New("stored inspection result media failed its binding")
		}
		if _, duplicate := seen[ordinal]; duplicate {
			return errors.New("stored inspection result media repeats an ordinal")
		}
		seen[ordinal] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("stored inspection result media set is incomplete")
	}
	return nil
}

func appendEventTx(ctx context.Context, tx *sql.Tx, event inspection.RunEvent) error {
	publicJSON := event.PublicJSON
	if len(publicJSON) == 0 {
		publicJSON = json.RawMessage(`{}`)
	}
	if !json.Valid(publicJSON) || protectedPayload.Match(publicJSON) || !validRef(event.RunID) || !validRef(event.Type) || !validReason(event.Reason) || event.OccurredAt.IsZero() {
		return errors.New("inspection run event is invalid or contains protected data")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO inspection_run_events(run_id, event_type, from_state, to_state, phase, reason, occurred_at, public_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		event.RunID, event.Type, event.From, event.To, event.Phase, event.Reason, formatTime(event.OccurredAt), string(publicJSON))
	return err
}

func assertLeaseTx(ctx context.Context, tx *sql.Tx, runID, owner string, state inspection.RunState, now time.Time) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM inspection_runs WHERE run_id=? AND state=? AND lease_owner=? AND lease_expires_at>? AND updated_at<=?`, runID, state, owner, formatTime(now), formatTime(now)).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrLeaseLost
	}
	return nil
}

func validateAndMarshalPlan(plan inspection.ExecutionPlan) ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	full, _, err := marshalPublic(plan)
	return full, err
}

func validateOutcome(outcome inspection.Outcome) error {
	if !inspection.CanTransition(inspection.RunFinalizing, outcome.State) {
		return errors.New("inspection outcome state is not terminal from finalizing")
	}
	return validateOutcomeContents(outcome)
}

func validateStoredOutcome(outcome inspection.Outcome) error {
	if !inspection.Terminal(outcome.State) {
		return errors.New("stored inspection outcome state is not terminal")
	}
	return validateOutcomeContents(outcome)
}

func validateOutcomeContents(outcome inspection.Outcome) error {
	conclusion := strings.TrimSpace(outcome.Conclusion)
	if !outcome.OverallAssessment.Valid() || conclusion == "" || conclusion != outcome.Conclusion || len(conclusion) > 1000 || strings.ContainsAny(conclusion, "\x00\r\n") || protectedPayload.MatchString(conclusion) || !validReason(outcome.Reason) {
		return errors.New("inspection outcome conclusion is incomplete")
	}
	if outcome.Coverage.Required < 0 || outcome.Coverage.Conclusive < 0 || outcome.Coverage.Inconclusive < 0 || outcome.Coverage.Missing < 0 || outcome.Coverage.Ratio < 0 || outcome.Coverage.Ratio > 1 {
		return errors.New("inspection outcome coverage is invalid")
	}
	if outcome.Coverage.Conclusive+outcome.Coverage.Inconclusive+outcome.Coverage.Missing != outcome.Coverage.Required {
		return errors.New("inspection outcome coverage totals do not match")
	}
	if len(outcome.Findings) > 10000 {
		return errors.New("inspection outcome has too many findings")
	}
	for _, finding := range outcome.Findings {
		if !validRef(finding.TargetID) || !validRef(finding.CriterionID) || !finding.Assessment.Valid() || finding.SampleCount < 0 || finding.SampleCount > 100 {
			return errors.New("inspection outcome finding is invalid")
		}
		if !validUniqueRefs(finding.ReasonCodes, 32) || !validUniqueRefs(finding.Limitations, 16) || !validUniqueRefs(finding.EvidenceRefs, 32) || len(finding.Results) != finding.SampleCount {
			return errors.New("inspection outcome finding references are invalid")
		}
		resultEvidence := make([]string, 0, len(finding.EvidenceRefs))
		for _, result := range finding.Results {
			if err := result.Validate(); err != nil {
				return fmt.Errorf("inspection outcome typed result is invalid: %w", err)
			}
			conclusive := finding.Assessment == inspection.AssessmentMeetsRule || finding.Assessment == inspection.AssessmentNeedsAttention
			if conclusive && result.Value == nil {
				return errors.New("conclusive inspection outcome typed result has no value")
			}
			if !conclusive && result.Value != nil {
				return errors.New("inconclusive inspection outcome typed result carries a value")
			}
			resultEvidence = append(resultEvidence, result.EvidenceRefs...)
		}
		if !sameRefSet(finding.EvidenceRefs, resultEvidence) {
			return errors.New("inspection outcome evidence does not match typed results")
		}
	}
	return nil
}

func validUniqueRefs(values []string, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRef(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func noObservationOutcome(plan inspection.ExecutionPlan, state inspection.RunState, reason, conclusion string) inspection.Outcome {
	coverage := inspection.Coverage{}
	for _, target := range plan.Targets {
		for _, criterion := range target.Criteria {
			if criterion.Criterion.Required {
				coverage.Required++
				coverage.Missing++
			}
		}
	}
	return inspection.Outcome{
		State: state, OverallAssessment: inspection.AssessmentUncertain,
		Coverage: coverage, Findings: []inspection.Finding{},
		Conclusion: conclusion, Reason: reason,
	}
}

func validateObservationAgainstPlanTx(ctx context.Context, tx *sql.Tx, observation inspection.Observation) error {
	_, plan, err := getRunPlanTx(ctx, tx, `run_id=?`, observation.Result.Binding.RunID)
	if err != nil {
		return err
	}
	if err := validateObservationAgainstPlan(plan, observation); err != nil {
		return err
	}
	return validateObservationMediaOutputsTx(ctx, tx, plan, observation)
}

// validateObservationMediaOutputsTx accepts evidence media only when it is an
// integrity-checked output of a successful media-producing step in the same
// frozen run. The step ledger is the authority for this binding; the removed
// artifact-metadata path is deliberately not a fallback.
func validateObservationMediaOutputsTx(ctx context.Context, tx *sql.Tx, plan inspection.ExecutionPlan, observation inspection.Observation) error {
	steps, err := listStepsTx(ctx, tx, observation.Result.Binding.RunID, plan)
	if err != nil {
		return err
	}
	type mediaOutput struct {
		sha256 string
		count  int
	}
	available := make(map[string]mediaOutput)
	for _, step := range steps {
		if step.State != inspection.StepSucceeded {
			continue
		}
		for _, output := range step.Outputs {
			if output.Kind != inspection.StepValueMedia {
				continue
			}
			if step.Kind != inspection.StepReadExisting && step.Kind != inspection.StepAcquireMedia &&
				step.Kind != inspection.StepOpenMedia && step.Kind != inspection.StepTransformMedia {
				return errors.New("inspection media output was published by a non-media step")
			}
			current := available[output.ValueRef]
			if current.count > 0 && current.sha256 != output.SHA256 {
				return errors.New("inspection media reference has conflicting step output digests")
			}
			current.sha256 = output.SHA256
			current.count++
			available[output.ValueRef] = current
		}
	}
	for _, source := range observation.Result.Binding.SourceMedia {
		output := available[source.MediaRef]
		if output.count != 1 || !digestPattern.MatchString(output.sha256) || output.sha256 != source.SHA256 {
			return errors.New("inspection observation references media outside successful run step outputs")
		}
	}
	return nil
}

func validateObservationAgainstPlan(plan inspection.ExecutionPlan, observation inspection.Observation) error {
	binding := observation.Result.Binding
	if binding.Usage != inspection.ResultUsageInspection || observation.Result.Display != nil {
		return errors.New("temporary observation cannot be persisted as a standard inspection result")
	}
	allowed := false
	for _, target := range plan.Targets {
		if target.TargetID != binding.TargetID {
			continue
		}
		for _, criterion := range target.Criteria {
			if criterion.Criterion.ID != binding.CriterionID {
				continue
			}
			if binding.CriterionVersion != strconv.FormatUint(criterion.Criterion.RuleVersion, 10) ||
				binding.OutputKind != criterion.Criterion.Output.Mode || binding.OutputSchemaVersion != criterion.Criterion.Output.SchemaVersion {
				return errors.New("inspection observation result contract does not match its frozen criterion")
			}
			for _, assessment := range criterion.Criterion.Output.AllowedAssessments {
				if assessment == observation.Result.Assessment {
					allowed = true
				}
			}
			knownSources := make(map[string]struct{}, len(target.SourceBindings))
			for _, source := range target.SourceBindings {
				knownSources[source.SourceHandle] = struct{}{}
			}
			for _, source := range binding.SourceMedia {
				if _, ok := knownSources[source.SourceRef]; !ok {
					return errors.New("inspection observation source is outside its frozen target binding")
				}
			}
			earliest := plan.RequestedAt.Add(-time.Duration(target.StrategyPolicy.Time.MaxAgeSeconds) * time.Second)
			if binding.TimeWindow.StartAt.Before(earliest) || binding.TimeWindow.EndAt.After(plan.Deadline) || observation.Result.Execution.CompletedAt.After(plan.Deadline) {
				return errors.New("inspection observation time is outside its frozen execution window")
			}
		}
	}
	if !allowed {
		return errors.New("inspection observation is outside its frozen execution plan")
	}
	stepFound := false
	for _, step := range plan.Steps {
		if step.StepID != binding.StepID {
			continue
		}
		stepFound = true
		if (step.TargetID != "" && step.TargetID != binding.TargetID) || (step.CriterionID != "" && step.CriterionID != binding.CriterionID) {
			return errors.New("inspection observation step binding contradicts its frozen plan")
		}
	}
	if !stepFound {
		return errors.New("inspection observation step is outside its frozen plan")
	}
	return nil
}

func earliestResultCapture(values []inspection.ResultSourceMedia) time.Time {
	var earliest time.Time
	for _, value := range values {
		if earliest.IsZero() || value.CapturedAt.Before(earliest) {
			earliest = value.CapturedAt.UTC()
		}
	}
	return earliest
}

func sameRefSet(left, right []string) bool {
	leftSet := make(map[string]struct{}, len(left))
	rightSet := make(map[string]struct{}, len(right))
	for _, value := range left {
		leftSet[value] = struct{}{}
	}
	for _, value := range right {
		rightSet[value] = struct{}{}
	}
	if len(leftSet) != len(rightSet) {
		return false
	}
	for value := range leftSet {
		if _, ok := rightSet[value]; !ok {
			return false
		}
	}
	return true
}

func validReason(reason string) bool {
	return reason != "" && strings.TrimSpace(reason) == reason && len(reason) <= 256 && !strings.ContainsAny(reason, "\x00\r\n") && !protectedPayload.MatchString(reason)
}
