package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

// A heartbeat samples its clock before waiting for database admission. A newer
// business event may commit first; that is not loss of the same owner's lease.
func TestRunRenewalAfterNewerBusinessEventPreservesFencing(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer s.Close()
	ctx, now := context.Background(), fixtureNow()
	plan := fixturePlan(t, now, "renew-order", 10*time.Minute)
	if _, _, err := s.CreateQueuedRun(ctx, plan, "run-renew-order", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := s.ClaimNext(ctx, "worker", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim=%v err=%v", ok, err)
	}
	captured := now.Add(9 * time.Second)
	committed := now.Add(10 * time.Second)
	if err := s.AppendPhase(ctx, "run-renew-order", "worker", inspection.PhaseAnalyzing, committed, "analysis_active"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewLease(ctx, "run-renew-order", "worker", captured, 2*time.Minute); err != nil {
		t.Fatalf("delayed live renewal: %v", err)
	}
	if err := s.RenewLease(ctx, "run-renew-order", "worker", captured.Add(-time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	var expiry string
	if err := s.db.QueryRowContext(ctx, `SELECT lease_expires_at FROM inspection_runs WHERE run_id=?`, "run-renew-order").Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	if expiry != formatTime(captured.Add(2*time.Minute)) {
		t.Fatalf("renewal shrank lease: %s", expiry)
	}
	run, err := s.GetRun(ctx, "run-renew-order")
	if err != nil || !run.UpdatedAt.Equal(committed) {
		t.Fatalf("business timestamp changed: %+v err=%v", run, err)
	}
	if err := s.AppendPhase(ctx, "run-renew-order", "worker", inspection.PhaseAnalyzing, captured, "older_business_event"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("out-of-order business event accepted: %v", err)
	}
	if err := s.RenewLease(ctx, "run-renew-order", "other-worker", captured, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("foreign renewal: %v", err)
	}
	if err := s.RenewLease(ctx, "run-renew-order", "worker", captured.Add(2*time.Minute), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("renewal at expiry: %v", err)
	}
	if err := s.BeginFinalization(ctx, "run-renew-order", "worker", committed.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewLease(ctx, "run-renew-order", "worker", captured, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("old timestamp revived finalizing run: %v", err)
	}
	outcome := noObservationOutcome(plan, inspection.RunFailed, "fixture_finished", "No trusted observation formed.")
	if err := s.Finalize(ctx, "run-renew-order", "worker", outcome, committed.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewLease(ctx, "run-renew-order", "worker", captured, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("old timestamp revived terminal run: %v", err)
	}
}

func TestStepRenewalAfterNewerBusinessEventPreservesBounds(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer s.Close()
	ctx, now := context.Background(), fixtureNow()
	plan := fixturePlan(t, now, "step-renew-order", 10*time.Minute)
	if _, _, err := s.CreateQueuedRun(ctx, plan, "run-step-order", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := s.ClaimNext(ctx, "worker", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim=%v err=%v", ok, err)
	}
	step, attempt, ok, err := s.ClaimNextStep(ctx, "run-step-order", "worker", "step-worker", now.Add(2*time.Second), 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim step=%v err=%v", ok, err)
	}
	captured, committed := now.Add(7*time.Second), now.Add(8*time.Second)
	if err := s.AppendPhase(ctx, "run-step-order", "worker", inspection.PhaseAnalyzing, committed, "analysis_active"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "worker", attempt.AttemptID, "step-worker", captured, 30*time.Second); err != nil {
		t.Fatalf("delayed live step renewal: %v", err)
	}
	// A newer heartbeat can also be admitted before an older one. The old
	// request is a no-op when its requested extension has already passed but
	// the newer renewal is still live.
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "worker", attempt.AttemptID, "step-worker", now.Add(20*time.Second), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "worker", attempt.AttemptID, "step-worker", captured, 5*time.Second); err != nil {
		t.Fatalf("superseded heartbeat rejected a live attempt: %v", err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "worker", attempt.AttemptID, "step-worker", captured.Add(-time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	attempts, err := s.ListStepAttempts(ctx, "run-step-order", step.StepID)
	if err != nil || len(attempts) != 1 {
		t.Fatalf("attempts=%+v err=%v", attempts, err)
	}
	if !attempts[0].LeaseExpires.Equal(now.Add(61*time.Second)) || !attempts[0].UpdatedAt.Equal(now.Add(20*time.Second)) {
		t.Fatalf("lost run cap or monotonic timestamp: %+v", attempts[0])
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "other-worker", attempt.AttemptID, "step-worker", captured, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("foreign run owner: %v", err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "worker", attempt.AttemptID, "other-worker", captured, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("foreign attempt owner: %v", err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "worker", attempt.AttemptID, "step-worker", now.Add(61*time.Second), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired coordinator revived: %v", err)
	}
	if err := s.CompleteStep(ctx, "run-step-order", "worker", attempt.AttemptID, "step-worker", inspection.StepSucceeded, successfulOutputs(plan.Steps[0]), "step_completed", now.Add(21*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-order", "worker", attempt.AttemptID, "step-worker", captured, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("completed attempt revived: %v", err)
	}
}

func TestDelayedStepRenewalCannotReviveKnownExpiredAttempt(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer s.Close()
	ctx, now := context.Background(), fixtureNow()
	plan := fixturePlan(t, now, "step-expired-order", 10*time.Minute)
	if _, _, err := s.CreateQueuedRun(ctx, plan, "run-step-expired-order", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := s.ClaimNext(ctx, "worker", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim=%v err=%v", ok, err)
	}
	_, attempt, ok, err := s.ClaimNextStep(ctx, "run-step-expired-order", "worker", "step-worker", now.Add(2*time.Second), 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim step=%v err=%v", ok, err)
	}
	// The heartbeat was sampled while live, but a later committed event proves
	// its attempt has expired. The older timestamp must not revive it.
	if err := s.AppendPhase(ctx, "run-step-expired-order", "worker", inspection.PhaseAnalyzing, now.Add(13*time.Second), "analysis_active"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-expired-order", "worker", attempt.AttemptID, "step-worker", now.Add(11*time.Second), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale timestamp revived known-expired attempt: %v", err)
	}
}

func TestDelayedStepRenewalRetainsFrozenDeadline(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer s.Close()
	ctx, now := context.Background(), fixtureNow()
	plan := fixturePlan(t, now, "step-deadline-order", 30*time.Second)
	if _, _, err := s.CreateQueuedRun(ctx, plan, "run-step-deadline-order", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := s.ClaimNext(ctx, "worker", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim=%v err=%v", ok, err)
	}
	step, attempt, ok, err := s.ClaimNextStep(ctx, "run-step-deadline-order", "worker", "step-worker", now.Add(2*time.Second), 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim step=%v err=%v", ok, err)
	}
	if err := s.AppendPhase(ctx, "run-step-deadline-order", "worker", inspection.PhaseAnalyzing, now.Add(8*time.Second), "analysis_active"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-deadline-order", "worker", attempt.AttemptID, "step-worker", now.Add(7*time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	attempts, err := s.ListStepAttempts(ctx, "run-step-deadline-order", step.StepID)
	if err != nil || len(attempts) != 1 || !attempts[0].LeaseExpires.Equal(plan.Steps[0].Deadline) {
		t.Fatalf("frozen deadline cap: attempts=%+v err=%v", attempts, err)
	}
	// The coordinator may still finalize after the execution deadline, but a
	// delayed heartbeat cannot revive the expired execution attempt.
	if err := s.AppendPhase(ctx, "run-step-deadline-order", "worker", inspection.PhaseAnalyzing, now.Add(31*time.Second), "analysis_active"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewStepAttemptLease(ctx, "run-step-deadline-order", "worker", attempt.AttemptID, "step-worker", now.Add(29*time.Second), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale timestamp bypassed deadline: %v", err)
	}
}
