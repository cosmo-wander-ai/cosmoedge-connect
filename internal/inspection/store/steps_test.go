package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

func TestStepLedgerPersistsPlanClaimsAndExactOutputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	store := openStore(t, path)
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "step-ledger", 10*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-step-ledger", now); err != nil {
		t.Fatal(err)
	}
	steps, err := store.ListSteps(ctx, "run-step-ledger")
	if err != nil || len(steps) != len(plan.Steps) {
		t.Fatalf("steps=%#v err=%v", steps, err)
	}
	for _, step := range steps {
		if step.State != inspection.StepPending || step.AttemptCount != 0 || len(step.Outputs) != 0 {
			t.Fatalf("new step=%#v", step)
		}
	}
	if _, _, ok, err := store.ClaimNext(ctx, "run-worker", now.Add(time.Second), 5*time.Minute); err != nil || !ok {
		t.Fatalf("claim run ok=%v err=%v", ok, err)
	}
	record, attempt, ok, err := store.ClaimNextStep(ctx, "run-step-ledger", "run-worker", "step-worker", now.Add(2*time.Second), time.Minute)
	if err != nil || !ok || record.StepID != plan.Steps[0].StepID || attempt.Number != 1 || attempt.State != inspection.AttemptRunning {
		t.Fatalf("record=%#v attempt=%#v ok=%v err=%v", record, attempt, ok, err)
	}
	bad := successfulOutputs(plan.Steps[0])
	bad[0].LogicalRef = "wrong-logical-ref"
	if err := store.CompleteStep(ctx, "run-step-ledger", "run-worker", attempt.AttemptID, "step-worker", inspection.StepSucceeded, bad, "step_completed", now.Add(3*time.Second)); err == nil {
		t.Fatal("step accepted outputs outside its frozen plan")
	}
	bad = successfulOutputs(plan.Steps[0])
	bad[0].Kind = inspection.StepValueMedia
	if err := store.CompleteStep(ctx, "run-step-ledger", "run-worker", attempt.AttemptID, "step-worker", inspection.StepSucceeded, bad, "step_completed", now.Add(3*time.Second)); err == nil {
		t.Fatal("step accepted an output with the wrong frozen type")
	}
	outputs := successfulOutputs(plan.Steps[0])
	if err := store.CompleteStep(ctx, "run-step-ledger", "run-worker", attempt.AttemptID, "step-worker", inspection.StepSucceeded, outputs, "step_completed", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	steps, err = store.ListSteps(ctx, "run-step-ledger")
	if err != nil || steps[0].State != inspection.StepSucceeded || len(steps[0].Outputs) != len(outputs) || steps[1].State != inspection.StepPending {
		t.Fatalf("steps=%#v err=%v", steps, err)
	}
	attempts, err := store.ListStepAttempts(ctx, "run-step-ledger", plan.Steps[0].StepID)
	if err != nil || len(attempts) != 1 || attempts[0].State != inspection.AttemptSucceeded || attempts[0].FinishedAt.IsZero() {
		t.Fatalf("attempts=%#v err=%v", attempts, err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openStore(t, path)
	defer reopened.Close()
	reopenedSteps, err := reopened.ListSteps(ctx, "run-step-ledger")
	if err != nil || reopenedSteps[0].State != inspection.StepSucceeded {
		t.Fatalf("reopened steps=%#v err=%v", reopenedSteps, err)
	}
}

func TestConcurrentStepClaimCreatesOneDeterministicAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	first := openStore(t, path)
	defer first.Close()
	second := openStore(t, path)
	defer second.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "step-claim-once", 10*time.Minute)
	if _, _, err := first.CreateQueuedRun(ctx, plan, "run-step-claim-once", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := first.ClaimNext(ctx, "run-worker", now.Add(time.Second), 5*time.Minute); err != nil || !ok {
		t.Fatalf("claim run ok=%v err=%v", ok, err)
	}
	type result struct {
		attempt inspection.StepAttempt
		ok      bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var group sync.WaitGroup
	for _, candidate := range []*Store{first, second} {
		group.Add(1)
		go func(store *Store) {
			defer group.Done()
			<-start
			_, attempt, ok, err := store.ClaimNextStep(ctx, "run-step-claim-once", "run-worker", "step-worker", now.Add(2*time.Second), time.Minute)
			results <- result{attempt: attempt, ok: ok, err: err}
		}(candidate)
	}
	close(start)
	group.Wait()
	close(results)
	claimed := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.ok {
			claimed++
			if result.attempt.AttemptID != stepAttemptID("run-step-claim-once", plan.Steps[0].StepID, 1) {
				t.Fatalf("attempt=%#v", result.attempt)
			}
		}
	}
	if claimed != 1 {
		t.Fatalf("claimed=%d", claimed)
	}
}

func TestStepAttemptLeaseRenewalIsOwnerBoundAndCappedByRun(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "step-renew", 10*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-step-renew", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(ctx, "run-worker", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim run ok=%v err=%v", ok, err)
	}
	_, attempt, ok, err := store.ClaimNextStep(ctx, "run-step-renew", "run-worker", "step-worker", now.Add(2*time.Second), 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim step ok=%v err=%v", ok, err)
	}
	if err := store.RenewStepAttemptLease(ctx, "run-step-renew", "run-worker", attempt.AttemptID, "wrong-worker", now.Add(5*time.Second), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong owner renewal error=%v", err)
	}
	if err := store.RenewLease(ctx, "run-step-renew", "run-worker", now.Add(5*time.Second), 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.RenewStepAttemptLease(ctx, "run-step-renew", "run-worker", attempt.AttemptID, "step-worker", now.Add(6*time.Second), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteStep(ctx, "run-step-renew", "run-worker", attempt.AttemptID, "step-worker", inspection.StepSucceeded,
		successfulOutputs(plan.Steps[0]), "step_completed", now.Add(100*time.Second)); err != nil {
		t.Fatalf("renewed attempt could not complete: %v", err)
	}
}

func TestExpiredStepRecoveryReplaysOnlyDeclaredSafeOperations(t *testing.T) {
	ctx := context.Background()
	now := fixtureNow()

	t.Run("pure replay", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "step-replay", 10*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-step-replay", now); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := store.ClaimNext(ctx, "run-worker", now.Add(time.Second), 5*time.Minute); err != nil || !ok {
			t.Fatalf("claim run ok=%v err=%v", ok, err)
		}
		_, firstAttempt, ok, err := store.ClaimNextStep(ctx, "run-step-replay", "run-worker", "step-worker", now.Add(2*time.Second), 10*time.Second)
		if err != nil || !ok {
			t.Fatalf("claim step ok=%v err=%v", ok, err)
		}
		if recovered, err := store.RecoverExpiredStepAttempts(ctx, now.Add(13*time.Second)); err != nil || recovered != 1 {
			t.Fatalf("recovered=%d err=%v", recovered, err)
		}
		_, secondAttempt, ok, err := store.ClaimNextStep(ctx, "run-step-replay", "run-worker", "step-worker", now.Add(14*time.Second), 10*time.Second)
		if err != nil || !ok || secondAttempt.Number != 2 || secondAttempt.AttemptID == firstAttempt.AttemptID {
			t.Fatalf("second=%#v ok=%v err=%v", secondAttempt, ok, err)
		}
		attempts, err := store.ListStepAttempts(ctx, "run-step-replay", plan.Steps[0].StepID)
		if err != nil || len(attempts) != 2 || attempts[0].State != inspection.AttemptAbandoned || attempts[1].State != inspection.AttemptRunning {
			t.Fatalf("attempts=%#v err=%v", attempts, err)
		}
	})

	t.Run("reconcile before retry", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "step-unknown", 10*time.Minute)
		if _, _, err := store.CreateQueuedRun(ctx, plan, "run-step-unknown", now); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := store.ClaimNext(ctx, "run-worker", now.Add(time.Second), 5*time.Minute); err != nil || !ok {
			t.Fatalf("claim run ok=%v err=%v", ok, err)
		}
		_, resolveAttempt, ok, err := store.ClaimNextStep(ctx, "run-step-unknown", "run-worker", "step-worker", now.Add(2*time.Second), time.Minute)
		if err != nil || !ok {
			t.Fatalf("resolve claim ok=%v err=%v", ok, err)
		}
		if err := store.CompleteStep(ctx, "run-step-unknown", "run-worker", resolveAttempt.AttemptID, "step-worker", inspection.StepSucceeded, successfulOutputs(plan.Steps[0]), "step_completed", now.Add(3*time.Second)); err != nil {
			t.Fatal(err)
		}
		claimed, acquireAttempt, ok, err := store.ClaimNextStep(ctx, "run-step-unknown", "run-worker", "step-worker", now.Add(4*time.Second), 10*time.Second)
		if err != nil || !ok || claimed.Kind != inspection.StepAcquireMedia {
			t.Fatalf("acquire=%#v attempt=%#v ok=%v err=%v", claimed, acquireAttempt, ok, err)
		}
		if recovered, err := store.RecoverExpiredStepAttempts(ctx, now.Add(15*time.Second)); err != nil || recovered != 1 {
			t.Fatalf("recovered=%d err=%v", recovered, err)
		}
		steps, err := store.ListSteps(ctx, "run-step-unknown")
		if err != nil || steps[1].State != inspection.StepOutcomeUnknown {
			t.Fatalf("steps=%#v err=%v", steps, err)
		}
		reconciliation, err := store.ReconcileUnknownStep(ctx, "run-step-unknown", "run-worker", plan.Steps[1].StepID,
			"reconciler", inspection.ReconciliationRetry, nil, "adapter_confirmed_no_effect", now.Add(16*time.Second))
		if err != nil || reconciliation.Decision != inspection.ReconciliationRetry || reconciliation.AttemptID != acquireAttempt.AttemptID {
			t.Fatalf("reconciliation=%#v err=%v", reconciliation, err)
		}
		reconciliations, err := store.ListStepReconciliations(ctx, "run-step-unknown", plan.Steps[1].StepID)
		if err != nil || len(reconciliations) != 1 || reconciliations[0].ReconciliationID != reconciliation.ReconciliationID {
			t.Fatalf("reconciliations=%#v err=%v", reconciliations, err)
		}
		next, retried, ok, err := store.ClaimNextStep(ctx, "run-step-unknown", "run-worker", "step-worker", now.Add(17*time.Second), time.Minute)
		if err != nil || !ok || next.Kind != inspection.StepAcquireMedia || retried.Number != 2 {
			t.Fatalf("reconciled retry=%#v attempt=%#v ok=%v err=%v", next, retried, ok, err)
		}
	})
}

func TestFailedStepSkipsDependentsButStillClaimsCleanup(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "step-cleanup", 10*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-step-cleanup", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(ctx, "run-worker", now.Add(time.Second), 5*time.Minute); err != nil || !ok {
		t.Fatalf("claim run ok=%v err=%v", ok, err)
	}
	clock := now.Add(2 * time.Second)
	_, resolve, ok, err := store.ClaimNextStep(ctx, "run-step-cleanup", "run-worker", "step-worker", clock, time.Minute)
	if err != nil || !ok {
		t.Fatalf("resolve ok=%v err=%v", ok, err)
	}
	if err := store.CompleteStep(ctx, "run-step-cleanup", "run-worker", resolve.AttemptID, "step-worker", inspection.StepSucceeded, successfulOutputs(plan.Steps[0]), "step_completed", clock.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Second)
	_, acquire, ok, err := store.ClaimNextStep(ctx, "run-step-cleanup", "run-worker", "step-worker", clock, time.Minute)
	if err != nil || !ok {
		t.Fatalf("acquire ok=%v err=%v", ok, err)
	}
	if err := store.CompleteStep(ctx, "run-step-cleanup", "run-worker", acquire.AttemptID, "step-worker", inspection.StepFailed, nil, "fixture_acquisition_failed", clock.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Second)
	cleanupRecord, cleanupAttempt, ok, err := store.ClaimNextStep(ctx, "run-step-cleanup", "run-worker", "step-worker", clock, time.Minute)
	if err != nil || !ok || cleanupRecord.Kind != inspection.StepCleanup {
		t.Fatalf("cleanup=%#v attempt=%#v ok=%v err=%v", cleanupRecord, cleanupAttempt, ok, err)
	}
	if err := store.CompleteStep(ctx, "run-step-cleanup", "run-worker", cleanupAttempt.AttemptID, "step-worker", inspection.StepSucceeded, successfulOutputs(plan.Steps[len(plan.Steps)-1]), "cleanup_completed", clock.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	steps, err := store.ListSteps(ctx, "run-step-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if steps[1].State != inspection.StepFailed || steps[len(steps)-1].State != inspection.StepSucceeded {
		t.Fatalf("steps=%#v", steps)
	}
	for _, step := range steps[2 : len(steps)-1] {
		if step.State != inspection.StepSkipped {
			t.Fatalf("dependent step was not skipped: %#v", step)
		}
	}
}

func TestInterruptedUncertainStepRequiresDurableReconciliationBeforeResume(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "run-reconciliation", 10*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-reconciliation", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(ctx, "run-worker", now.Add(time.Second), 20*time.Second); err != nil || !ok {
		t.Fatalf("claim run ok=%v err=%v", ok, err)
	}
	_, resolve, ok, err := store.ClaimNextStep(ctx, "run-reconciliation", "run-worker", "step-worker", now.Add(2*time.Second), 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim resolve ok=%v err=%v", ok, err)
	}
	if err := store.CompleteStep(ctx, "run-reconciliation", "run-worker", resolve.AttemptID, "step-worker", inspection.StepSucceeded, successfulOutputs(plan.Steps[0]), "step_completed", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	_, acquire, ok, err := store.ClaimNextStep(ctx, "run-reconciliation", "run-worker", "step-worker", now.Add(4*time.Second), 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("claim acquire ok=%v err=%v", ok, err)
	}
	if recovered, err := store.RecoverInterrupted(ctx, now.Add(22*time.Second)); err != nil || recovered != 1 {
		t.Fatalf("recover run=%d err=%v", recovered, err)
	}
	run, err := store.GetRun(ctx, "run-reconciliation")
	if err != nil || run.State != inspection.RunReconciliationRequired || run.Conclusion != "" {
		t.Fatalf("run=%#v err=%v", run, err)
	}
	if _, _, ok, err := store.ClaimNext(ctx, "other-worker", now.Add(23*time.Second), time.Minute); err != nil || ok {
		t.Fatalf("unreconciled run was claimable ok=%v err=%v", ok, err)
	}
	if err := store.ResumeReconciledRun(ctx, "run-reconciliation", "reconciler", now.Add(23*time.Second)); err == nil {
		t.Fatal("run resumed without a reconciliation decision")
	}
	if _, err := store.ReconcileUnknownStep(ctx, "run-reconciliation", "unused-run-owner", plan.Steps[1].StepID, "reconciler",
		inspection.ReconciliationRetry, nil, "adapter_confirmed_no_effect", now.Add(23*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.ResumeReconciledRun(ctx, "run-reconciliation", "reconciler", now.Add(24*time.Second)); err != nil {
		t.Fatal(err)
	}
	run, err = store.GetRun(ctx, "run-reconciliation")
	if err != nil || run.State != inspection.RunQueued || run.Reason != "step_reconciliation_completed" {
		t.Fatalf("resumed run=%#v err=%v acquire=%#v", run, err, acquire)
	}
}

func TestStepLedgerRejectsStoredTamperingAndOldInspectionSchema(t *testing.T) {
	ctx := context.Background()
	now := fixtureNow()
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	plan := fixturePlan(t, now, "step-tamper", 10*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-step-tamper", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_steps SET kind='shell' WHERE run_id=? AND step_id=?`, "run-step-tamper", plan.Steps[0].StepID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListSteps(ctx, "run-step-tamper"); err == nil {
		t.Fatal("stored step tampering was accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sqlOpenForTest(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE inspection_schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); INSERT INTO inspection_schema_migrations(version, applied_at) VALUES(1, 'legacy')`); err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()
	protectStoreTestPath(t, legacyPath, true)
	if opened, err := Open(legacyPath); err == nil || !strings.Contains(err.Error(), "explicitly reset") {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("legacy schema error=%v", err)
	}
}

func successfulOutputs(step inspection.ExecutionStep) []inspection.StepOutput {
	result := make([]inspection.StepOutput, len(step.OutputSlots))
	for index, slot := range step.OutputSlots {
		result[index] = inspection.StepOutput{LogicalRef: slot.LogicalRef, Kind: slot.Kind, ValueRef: "value_" + strings.TrimPrefix(slot.LogicalRef, "ref_"), SHA256: strings.Repeat("a", 64)}
	}
	return result
}

// sqlOpenForTest is kept local so this file does not expose a store helper in
// production code.
func sqlOpenForTest(path string) (*sql.DB, error) { return sql.Open("sqlite", path) }
