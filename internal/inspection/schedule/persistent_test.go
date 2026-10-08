package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectiontest"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	_ "modernc.org/sqlite"
)

func TestStoreCleanCreateRestartAndRejectsOldOrExtraSchema(t *testing.T) {
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "schedule.db")
	store, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	active, grant, signer := seedActiveStore(t, store, "schedule-restart", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
	_ = grant
	_ = signer
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	record, err := reopened.Get(context.Background(), keyFor(active))
	if err != nil || record.Schedule.RunSpec.SHA256 != active.RunSpec.SHA256 {
		t.Fatalf("restart Get err=%v", err)
	}
	if _, err := reopened.db.Exec(`CREATE TABLE unexpected_object(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(StoreConfig{Path: path}); !errors.Is(err, ErrSchema) {
		t.Fatalf("extra schema error=%v", err)
	}
	oldDirectory := t.TempDir()
	if err := teststate.ProtectDir(oldDirectory); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(oldDirectory, "old.db")
	db, err := sql.Open("sqlite", oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA application_id=1128616754; PRAGMA user_version=2; CREATE TABLE legacy(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	_ = localstate.ProtectFile(oldPath)
	if _, err := OpenStore(StoreConfig{Path: oldPath}); !errors.Is(err, ErrSchema) {
		t.Fatalf("old schema error=%v", err)
	}
}

func TestStoreActivatesScheduleBeforeFutureValidFromWithoutAdvancingCursor(t *testing.T) {
	store := testStore(t, "future-activation.db")
	draft := testDraftSchedule(t, "schedule-future", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	draft.ValidFrom = testBase.Add(7 * 24 * time.Hour)
	draft.ValidUntil = testBase.Add(14 * 24 * time.Hour)
	if err := draft.Validate(); err != nil {
		t.Fatalf("future draft: %v", err)
	}
	active, _, _ := activateDraftStore(t, store, draft)
	record, err := store.Get(context.Background(), keyFor(active))
	if err != nil {
		t.Fatal(err)
	}
	wantCursor := draft.ValidFrom.UTC().Add(-time.Nanosecond)
	if active.State != StateActive || !record.CursorAt.Equal(wantCursor) {
		t.Fatalf("future activation state=%s cursor=%s want=%s", active.State, record.CursorAt, wantCursor)
	}
}

func TestStoreRejectsInFlightOccurrenceWithoutReservationOnRestart(t *testing.T) {
	for _, submitted := range []bool{false, true} {
		name := "unknown"
		if submitted {
			name = "submitted"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := teststate.ProtectDir(directory); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "missing-reservation.db")
			store, err := OpenStore(StoreConfig{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			active, _, _ := seedActiveStore(t, store, "schedule-missing-reservation-"+name, ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
			due := testBase.Add(time.Hour)
			planOneOccurrence(t, store, active, due)
			_, claim, ok, err := store.ClaimPending(context.Background(), "manager-corrupt", due, time.Second)
			if err != nil || !ok {
				t.Fatalf("claim ok=%v err=%v", ok, err)
			}
			if _, status, err := store.BeginSubmission(context.Background(), claim, due, time.Second); err != nil || status != AdmissionReady {
				t.Fatalf("begin status=%s err=%v", status, err)
			}
			if submitted {
				if _, err := store.ApplySubmission(context.Background(), claim, SubmissionResult{Status: SubmissionAccepted, RunRef: "run-corrupt", SubmissionRef: "submission-corrupt"}, due); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.db.ExecContext(context.Background(), `DELETE FROM schedule_reservations WHERE occurrence_id=?`, claim.OccurrenceID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(context.Background(), `UPDATE schedule_revisions SET reserved_count=0 WHERE tenant_id=? AND site_id=? AND schedule_id=? AND revision=?`, active.TenantID, active.SiteID, active.ScheduleID, active.Revision); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenStore(StoreConfig{Path: path}); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("reopen missing %s reservation error=%v", name, err)
			}
		})
	}
}

func TestRecordPlanningEnforcesMisfirePolicyAtPersistenceBoundary(t *testing.T) {
	skipStore := testStore(t, "skip-policy.db")
	skip, _, _ := seedActiveStore(t, skipStore, "schedule-store-skip", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, func(s *Schedule) {
		s.Misfire = MisfireSkip
		s.MisfireGraceSeconds = 60
	})
	skipRecord, err := skipStore.Get(context.Background(), keyFor(skip))
	if err != nil {
		t.Fatal(err)
	}
	due := testBase.Add(time.Hour)
	forgedSkip, err := newOccurrence(skip, civilDateFrom(due), due, due, due)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := skipStore.RecordPlanning(context.Background(), skipRecord, due.Add(2*time.Minute), []Occurrence{forgedSkip}); !errors.Is(err, ErrConflict) {
		t.Fatalf("RecordPlanning accepted stale skip occurrence: %v", err)
	}
	afterSkip, err := skipStore.Get(context.Background(), keyFor(skip))
	if err != nil || !afterSkip.CursorAt.Equal(skipRecord.CursorAt) {
		t.Fatalf("rejected skip advanced cursor=%s err=%v", afterSkip.CursorAt, err)
	}
	if records, err := skipStore.ListOccurrences(context.Background(), keyFor(skip)); err != nil || len(records) != 0 {
		t.Fatalf("rejected skip persisted occurrences=%d err=%v", len(records), err)
	}

	catchStore := testStore(t, "catch-policy.db")
	catch, _, _ := seedActiveStore(t, catchStore, "schedule-store-catch", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, func(s *Schedule) {
		s.Weekdays = []Weekday{Monday, Tuesday}
	})
	catchRecord, err := catchStore.Get(context.Background(), keyFor(catch))
	if err != nil {
		t.Fatal(err)
	}
	latest := due.Add(24 * time.Hour)
	olderCatchUp, err := newOccurrence(catch, civilDateFrom(due), due, due, latest)
	if err != nil {
		t.Fatal(err)
	}
	latestCatchUp, err := newOccurrence(catch, civilDateFrom(latest), latest, latest, latest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catchStore.RecordPlanning(context.Background(), catchRecord, latest, []Occurrence{olderCatchUp, latestCatchUp}); !errors.Is(err, ErrConflict) {
		t.Fatalf("RecordPlanning accepted multiple catch-up occurrences: %v", err)
	}
}

func TestUnknownRecoveryNeverBlindlyResubmits(t *testing.T) {
	store := testStore(t, "unknown.db")
	active, grant, signer := seedActiveStore(t, store, "schedule-unknown", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
	clock := &mutableClock{at: testBase.Add(time.Hour)}
	submitter := &fixtureSubmitter{submitErr: errors.New("transport outcome unknown"), reconcileResult: SubmissionResult{Status: SubmissionAccepted, RunRef: "run-recovered", SubmissionRef: "submission-recovered"}}
	observer := fixtureObserver{result: RunObservation{Status: RunObservationNonTerminal, State: inspection.RunRunning}}
	coordinator := testCoordinator(t, store, active, grant, signer, clock, submitter, observer)
	report, err := coordinator.Tick(context.Background())
	if err == nil || report.SubmissionUnknown != 1 || submitter.submitCalls.Load() != 1 {
		t.Fatalf("first Tick report=%+v submit=%d err=%v", report, submitter.submitCalls.Load(), err)
	}
	count, err := store.ReservationCount(context.Background(), keyFor(active))
	if err != nil || count != 1 {
		t.Fatalf("unknown reservation=%d err=%v", count, err)
	}
	clock.at = clock.at.Add(3 * time.Second)
	submitter.submitErr = nil
	report, err = coordinator.Tick(context.Background())
	if err != nil || report.Reconciled != 1 || report.Submitted != 1 || submitter.submitCalls.Load() != 1 || submitter.reconcileCalls.Load() != 1 {
		t.Fatalf("recovery report=%+v submit=%d reconcile=%d err=%v", report, submitter.submitCalls.Load(), submitter.reconcileCalls.Load(), err)
	}
}

func TestBeforeCallCrashRecoversOnlyThroughReconcile(t *testing.T) {
	store := testStore(t, "before-call.db")
	active, _, _ := seedActiveStore(t, store, "schedule-before", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
	due := testBase.Add(time.Hour)
	planOneOccurrence(t, store, active, due)
	record, claim, ok, err := store.ClaimPending(context.Background(), "manager-a", due, time.Second)
	if err != nil || !ok {
		t.Fatal(err)
	}
	unknown, status, err := store.BeginSubmission(context.Background(), claim, due, time.Second)
	if err != nil || status != AdmissionReady || unknown.State != OccurrenceSubmittingUnknown {
		t.Fatalf("Begin=%s err=%v", status, err)
	}
	// Simulated process death: no Submit call and the reconciliation lease expires.
	_, claim2, ok, err := store.ClaimUnknown(context.Background(), "manager-b", due.Add(2*time.Second), time.Second)
	if err != nil || !ok {
		t.Fatalf("ClaimUnknown ok=%v err=%v", ok, err)
	}
	completed, err := store.ApplySubmission(context.Background(), claim2, SubmissionResult{Status: SubmissionNotSubmitted, SubmissionRef: "submission-missing"}, due.Add(2*time.Second))
	if err != nil || completed.State != OccurrenceBlocked || completed.ReasonCode != "abandoned_before_runtime" {
		t.Fatalf("reconcile not-submitted state=%s reason=%s err=%v", completed.State, completed.ReasonCode, err)
	}
	count, _ := store.ReservationCount(context.Background(), keyFor(active))
	if count != 0 {
		t.Fatalf("reservation leaked after proven not-submitted: %d", count)
	}
	_ = record
}

func TestUnknownReservationSurvivesRestartWithoutSlotLeak(t *testing.T) {
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "restart-unknown.db")
	first, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	active, _, _ := seedActiveStore(t, first, "schedule-restart-unknown", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
	due := testBase.Add(time.Hour)
	planOneOccurrence(t, first, active, due)
	_, claim, ok, err := first.ClaimPending(context.Background(), "manager-before-crash", due, time.Second)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, status, err := first.BeginSubmission(context.Background(), claim, due, time.Second); err != nil || status != AdmissionReady {
		t.Fatalf("Begin status=%s err=%v", status, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatalf("reopen unknown: %v", err)
	}
	defer reopened.Close()
	if count, err := reopened.ReservationCount(context.Background(), keyFor(active)); err != nil || count != 1 {
		t.Fatalf("restart reservation=%d err=%v", count, err)
	}
	_, reconcileClaim, ok, err := reopened.ClaimUnknown(context.Background(), "manager-after-crash", due.Add(2*time.Second), time.Second)
	if err != nil || !ok {
		t.Fatalf("ClaimUnknown ok=%v err=%v", ok, err)
	}
	if _, err := reopened.ApplySubmission(context.Background(), reconcileClaim, SubmissionResult{Status: SubmissionNotSubmitted, SubmissionRef: "submission-absent"}, due.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if count, _ := reopened.ReservationCount(context.Background(), keyFor(active)); count != 0 {
		t.Fatalf("restart reconciliation leaked reservation: %d", count)
	}
}

func TestSubmittedReservationSurvivesRestartUntilTerminalProof(t *testing.T) {
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "restart-submitted.db")
	first, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	active, _, _ := seedActiveStore(t, first, "schedule-restart-submitted", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
	due := testBase.Add(time.Hour)
	planOneOccurrence(t, first, active, due)
	_, claim, ok, err := first.ClaimPending(context.Background(), "manager-submit", due, time.Second)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, status, err := first.BeginSubmission(context.Background(), claim, due, time.Second); err != nil || status != AdmissionReady {
		t.Fatalf("Begin status=%s err=%v", status, err)
	}
	if _, err := first.ApplySubmission(context.Background(), claim, SubmissionResult{Status: SubmissionAccepted, RunRef: "run-persisted", SubmissionRef: "submission-persisted"}, due); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatalf("reopen submitted: %v", err)
	}
	defer reopened.Close()
	if count, _ := reopened.ReservationCount(context.Background(), keyFor(active)); count != 1 {
		t.Fatalf("submitted reservation after restart=%d", count)
	}
	if released, err := reopened.IsOccurrenceReleasedTerminal(context.Background(), claim.OccurrenceID, "run-persisted"); err != nil || released {
		t.Fatalf("submitted occurrence reported released terminal=%v err=%v", released, err)
	}
	record, observeClaim, ok, err := reopened.ClaimSubmitted(context.Background(), "manager-observe", due.Add(2*time.Second), time.Second)
	if err != nil || !ok || record.RunRef != "run-persisted" {
		t.Fatalf("ClaimSubmitted ok=%v run=%s err=%v", ok, record.RunRef, err)
	}
	if _, err := reopened.markRunTerminal(context.Background(), observeClaim, inspection.RunCompleted, due.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if count, _ := reopened.ReservationCount(context.Background(), keyFor(active)); count != 0 {
		t.Fatalf("terminal proof did not release restarted reservation: %d", count)
	}
	if released, err := reopened.IsOccurrenceReleasedTerminal(context.Background(), claim.OccurrenceID, "run-persisted"); err != nil || !released {
		t.Fatalf("terminal occurrence release proof=%v err=%v", released, err)
	}
}

func TestQueuedBackoffSurvivesRestart(t *testing.T) {
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "restart-queued.db")
	first, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	active, _, _ := seedActiveStore(t, first, "schedule-restart-queued", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, func(s *Schedule) {
		s.Weekdays = []Weekday{Monday, Tuesday}
		s.ValidUntil = testBase.Add(10 * 24 * time.Hour)
	})
	firstDue := testBase.Add(time.Hour)
	planOneOccurrence(t, first, active, firstDue)
	_, firstClaim, ok, err := first.ClaimPending(context.Background(), "manager-first", firstDue, time.Second)
	if err != nil || !ok {
		t.Fatalf("claim first ok=%v err=%v", ok, err)
	}
	if _, status, err := first.BeginSubmission(context.Background(), firstClaim, firstDue, time.Second); err != nil || status != AdmissionReady {
		t.Fatalf("begin first status=%s err=%v", status, err)
	}
	if _, err := first.ApplySubmission(context.Background(), firstClaim, SubmissionResult{Status: SubmissionAccepted, RunRef: "run-held", SubmissionRef: "submission-held"}, firstDue); err != nil {
		t.Fatal(err)
	}

	secondDue := firstDue.Add(24 * time.Hour)
	planOneOccurrence(t, first, active, secondDue)
	queuedBefore, secondClaim, ok, err := first.ClaimPending(context.Background(), "manager-second", secondDue, time.Second)
	if err != nil || !ok {
		t.Fatalf("claim second ok=%v err=%v", ok, err)
	}
	queuedBefore, status, err := first.BeginSubmission(context.Background(), secondClaim, secondDue, time.Second)
	if err != nil || status != AdmissionQueued || queuedBefore.State != OccurrencePending || queuedBefore.ReasonCode != "concurrency_queued" {
		t.Fatalf("queue status=%s state=%s reason=%s err=%v", status, queuedBefore.State, queuedBefore.ReasonCode, err)
	}
	availableAt := queuedBefore.AvailableAt
	if !availableAt.After(secondDue) {
		t.Fatalf("queued available_at=%s due=%s", availableAt, secondDue)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatalf("reopen queued: %v", err)
	}
	defer reopened.Close()
	queuedAfter, err := reopened.GetOccurrence(context.Background(), queuedBefore.Occurrence.OccurrenceID)
	if err != nil || queuedAfter.State != OccurrencePending || queuedAfter.ReasonCode != "concurrency_queued" || !queuedAfter.AvailableAt.Equal(availableAt) {
		t.Fatalf("reopened queue state=%s reason=%s available=%s err=%v", queuedAfter.State, queuedAfter.ReasonCode, queuedAfter.AvailableAt, err)
	}
	if count, err := reopened.ReservationCount(context.Background(), keyFor(active)); err != nil || count != 1 {
		t.Fatalf("reopened reserved_count=%d err=%v", count, err)
	}
	if _, _, claimed, err := reopened.ClaimPending(context.Background(), "manager-too-early", availableAt.Add(-time.Nanosecond), time.Second); err != nil || claimed {
		t.Fatalf("queued claim before backoff claimed=%v err=%v", claimed, err)
	}
	_, retryClaim, claimed, err := reopened.ClaimPending(context.Background(), "manager-retry", availableAt, time.Second)
	if err != nil || !claimed {
		t.Fatalf("queued claim after backoff claimed=%v err=%v", claimed, err)
	}
	requeued, status, err := reopened.BeginSubmission(context.Background(), retryClaim, availableAt, time.Second)
	if err != nil || status != AdmissionQueued || requeued.State != OccurrencePending || requeued.ReasonCode != "concurrency_queued" {
		t.Fatalf("requeue status=%s state=%s reason=%s err=%v", status, requeued.State, requeued.ReasonCode, err)
	}
	if count, err := reopened.ReservationCount(context.Background(), keyFor(active)); err != nil || count != 1 {
		t.Fatalf("requeue reserved_count=%d err=%v", count, err)
	}
}

func TestConcurrencyQueueAndTerminalProofRelease(t *testing.T) {
	store := testStore(t, "queue.db")
	active, grant, signer := seedActiveStore(t, store, "schedule-queue", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, func(s *Schedule) {
		s.Weekdays = []Weekday{Monday, Tuesday}
		s.ValidUntil = testBase.Add(10 * 24 * time.Hour)
	})
	clock := &mutableClock{at: testBase.Add(time.Hour)}
	submitter := &fixtureSubmitter{submitResult: SubmissionResult{Status: SubmissionAccepted, RunRef: "run-first", SubmissionRef: "submission-first"}}
	observer := &sequenceObserver{values: []RunObservation{{Status: RunObservationMissing}, {Status: RunObservationTerminal, State: inspection.RunCompleted}}}
	coordinator := testCoordinator(t, store, active, grant, signer, clock, submitter, observer)
	if _, err := coordinator.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count, _ := store.ReservationCount(context.Background(), keyFor(active)); count != 1 {
		t.Fatalf("first reservation=%d", count)
	}
	// Missing is not terminal and must retain the slot.
	clock.at = clock.at.Add(3 * time.Second)
	if _, _, err := coordinator.observeOne(context.Background(), clock.at); err != nil {
		t.Fatal(err)
	}
	if count, _ := store.ReservationCount(context.Background(), keyFor(active)); count != 1 {
		t.Fatalf("missing observation released slot: %d", count)
	}
	// Plan Tuesday while the first run still occupies the only slot.
	clock.at = testBase.Add(25 * time.Hour)
	if _, err := coordinator.plan(context.Background(), clock.at); err != nil {
		t.Fatal(err)
	}
	processed, state, admission, err := coordinator.processOne(context.Background(), clock.at)
	if err != nil || !processed || state != OccurrencePending || admission != AdmissionQueued {
		t.Fatalf("queued processed=%v state=%s admission=%s err=%v", processed, state, admission, err)
	}
	// Exact terminal proof releases atomically; the queued occurrence can then submit.
	clock.at = clock.at.Add(3 * time.Second)
	if _, _, err := coordinator.observeOne(context.Background(), clock.at); err != nil {
		t.Fatal(err)
	}
	if count, _ := store.ReservationCount(context.Background(), keyFor(active)); count != 0 {
		t.Fatalf("terminal proof did not release: %d", count)
	}
	submitter.submitResult = SubmissionResult{Status: SubmissionAccepted, RunRef: "run-second", SubmissionRef: "submission-second"}
	processed, state, admission, err = coordinator.processOne(context.Background(), clock.at)
	if err != nil || !processed || state != OccurrenceSubmitted || admission != AdmissionReady {
		t.Fatalf("post-release state=%s admission=%s err=%v", state, admission, err)
	}
}

func TestConcurrencySkipAndScheduleIsolation(t *testing.T) {
	store := testStore(t, "isolation.db")
	first, firstGrant, firstSigner := seedActiveStore(t, store, "schedule-skip-a", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencySkip}, func(s *Schedule) {
		s.Weekdays = []Weekday{Monday, Tuesday}
		s.ValidUntil = testBase.Add(10 * 24 * time.Hour)
	})
	clock := &mutableClock{at: testBase.Add(time.Hour)}
	submitter := &fixtureSubmitter{submitResult: SubmissionResult{Status: SubmissionAccepted, RunRef: "run-a1", SubmissionRef: "submission-a1"}}
	coordinator := testCoordinator(t, store, first, firstGrant, firstSigner, clock, submitter, fixtureObserver{result: RunObservation{Status: RunObservationNonTerminal, State: inspection.RunRunning}})
	if _, err := coordinator.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A reservation in schedule A never consumes schedule B capacity.
	second, _, _ := seedActiveStore(t, store, "schedule-skip-b", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencySkip}, nil)
	planOneOccurrence(t, store, second, testBase.Add(time.Hour))
	record, claim, ok, err := store.ClaimPending(context.Background(), "manager-b", testBase.Add(time.Hour), time.Second)
	if err != nil || !ok || record.Occurrence.ScheduleID != second.ScheduleID {
		t.Fatalf("schedule B claim=%s ok=%v err=%v", record.Occurrence.ScheduleID, ok, err)
	}
	unknown, status, err := store.BeginSubmission(context.Background(), claim, testBase.Add(time.Hour), time.Second)
	if err != nil || status != AdmissionReady {
		t.Fatalf("schedule B admission=%s state=%s err=%v", status, unknown.State, err)
	}
	if _, err := store.ApplySubmission(context.Background(), claim, SubmissionResult{Status: SubmissionAccepted, RunRef: "run-b1", SubmissionRef: "submission-b1"}, testBase.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Next A occurrence is skipped honestly while A remains occupied.
	clock.at = testBase.Add(25 * time.Hour)
	planOneOccurrence(t, store, first, clock.at)
	processed, state, admission, err := coordinator.processOne(context.Background(), clock.at)
	if err != nil || !processed || state != OccurrenceSkipped || admission != AdmissionSkipped {
		t.Fatalf("skip state=%s admission=%s err=%v", state, admission, err)
	}
}

func TestTwoStoresGenerationCASAndLeaseExpiry(t *testing.T) {
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "dual.db")
	first, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	active, _, _ := seedActiveStore(t, first, "schedule-dual", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
	planOneOccurrence(t, first, active, testBase.Add(time.Hour))
	second, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	start := make(chan struct{})
	var wins atomic.Int32
	var claim OccurrenceClaim
	var mu sync.Mutex
	var wg sync.WaitGroup
	for index, store := range []*Store{first, second} {
		wg.Add(1)
		go func(index int, store *Store) {
			defer wg.Done()
			<-start
			_, got, ok, _ := store.ClaimPending(context.Background(), "manager-"+string(rune('a'+index)), testBase.Add(time.Hour), time.Second)
			if ok {
				wins.Add(1)
				mu.Lock()
				claim = got
				mu.Unlock()
			}
		}(index, store)
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("claim winners=%d", wins.Load())
	}
	// The stale generation cannot mutate after another manager takes the expired lease.
	_, newClaim, ok, err := second.ClaimPending(context.Background(), "manager-c", testBase.Add(time.Hour+2*time.Second), time.Second)
	if err != nil || !ok {
		t.Fatalf("lease takeover ok=%v err=%v", ok, err)
	}
	if _, err := first.MarkClaimedTerminal(context.Background(), claim, OccurrenceBlocked, "stale_owner", testBase.Add(time.Hour+2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation error=%v", err)
	}
	if _, err := second.MarkClaimedTerminal(context.Background(), newClaim, OccurrenceBlocked, "valid_owner", testBase.Add(time.Hour+2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatPreventsReconciliationWhileSubmitIsStillRunning(t *testing.T) {
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "heartbeat.db")
	first, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	active, _, _ := seedActiveStore(t, first, "schedule-heartbeat", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
	due := testBase.Add(time.Hour)
	planOneOccurrence(t, first, active, due)
	_, claim, ok, err := first.ClaimPending(context.Background(), "manager-heartbeat", due, time.Second)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, status, err := first.BeginSubmission(context.Background(), claim, due, time.Second); err != nil || status != AdmissionReady {
		t.Fatalf("Begin status=%s err=%v", status, err)
	}
	second, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	wallStart := time.Now()
	clockNow := func() time.Time { return due.Add(time.Since(wallStart)) }
	coordinator := &Coordinator{store: first, lease: time.Second, now: clockNow}
	started := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- coordinator.withClaimHeartbeat(context.Background(), claim, func(context.Context) { close(started); time.Sleep(1500 * time.Millisecond) })
	}()
	<-started
	time.Sleep(1100 * time.Millisecond)
	if _, _, claimed, err := second.ClaimUnknown(context.Background(), "manager-reconcile", clockNow(), time.Second); err != nil || claimed {
		t.Fatalf("reconciliation overlapped live submit: claimed=%v err=%v", claimed, err)
	}
	if err := <-finished; err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	if _, err := first.ReleaseUnknown(context.Background(), claim, "", clockNow()); err != nil {
		t.Fatal(err)
	}
}

func TestTwoStoresConcurrentAdmissionKeepsExactlyOneReservation(t *testing.T) {
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "admission.db")
	first, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	template := inspectiontest.PublishedSceneTemplate()
	template.Budget.MaxDurationSeconds = 24 * 60 * 60
	request := inspectiontest.SceneRunRequest()
	request.Origin = inspection.OriginSchedule
	request.RequestedAt = testBase
	request.Deadline = testBase.Add(24 * time.Hour)
	spec, err := FreezeRunSpec(template, inspectiontest.PublishedSceneAssignment(), request)
	if err != nil {
		t.Fatal(err)
	}
	draft := testDraftSchedule(t, "schedule-admission", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	draft.RunSpec = spec
	draft.RunSpecSHA256 = spec.SHA256
	draft.Weekdays = []Weekday{Monday, Tuesday}
	draft.Misfire = MisfireSkip
	draft.JitterPolicySeconds = 300
	draft.ValidUntil = testBase.Add(10 * 24 * time.Hour)
	monday := testBase.Add(time.Hour)
	tuesday := monday.Add(24 * time.Hour)
	found := false
	for index := 0; index < 1000; index++ {
		draft.ScheduleID = fmt.Sprintf("schedule-admission-%d", index)
		if deterministicJitter(draft, monday) > deterministicJitter(draft, tuesday) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("could not find deterministic overlapping jitter")
	}
	active, _, signer := activateDraftStore(t, first, draft)
	record, err := first.Get(context.Background(), keyFor(active))
	if err != nil {
		t.Fatal(err)
	}
	now := tuesday.Add(deterministicJitter(active, tuesday))
	occurrences, err := NewPlanner(testClock{}, SystemZoneLoader{}, signer).Due(active, record.CursorAt, now)
	if err != nil || len(occurrences) != 2 {
		t.Fatalf("overlap Due=%d err=%v", len(occurrences), err)
	}
	if _, err := first.RecordPlanning(context.Background(), record, now, occurrences); err != nil {
		t.Fatal(err)
	}
	second, err := OpenStore(StoreConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_, claimA, ok, err := first.ClaimPending(context.Background(), "manager-admit-a", now, time.Minute)
	if err != nil || !ok {
		t.Fatal(err)
	}
	_, claimB, ok, err := second.ClaimPending(context.Background(), "manager-admit-b", now, time.Minute)
	if err != nil || !ok {
		t.Fatal(err)
	}
	type outcome struct {
		claim  OccurrenceClaim
		status AdmissionStatus
		err    error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	for _, item := range []struct {
		store *Store
		claim OccurrenceClaim
	}{{first, claimA}, {second, claimB}} {
		go func(item struct {
			store *Store
			claim OccurrenceClaim
		}) {
			<-start
			_, status, err := item.store.BeginSubmission(context.Background(), item.claim, now, time.Minute)
			results <- outcome{item.claim, status, err}
		}(item)
	}
	close(start)
	left, right := <-results, <-results
	if left.err != nil || right.err != nil {
		t.Fatalf("concurrent admission errors: %v / %v", left.err, right.err)
	}
	counts := map[AdmissionStatus]int{left.status: 1}
	counts[right.status]++
	if counts[AdmissionReady] != 1 || counts[AdmissionQueued] != 1 {
		t.Fatalf("admission statuses=%s,%s", left.status, right.status)
	}
	if count, err := first.ReservationCount(context.Background(), keyFor(active)); err != nil || count != 1 {
		t.Fatalf("reserved_count=%d err=%v", count, err)
	}
	winner := left
	if winner.status != AdmissionReady {
		winner = right
	}
	if _, err := first.ApplySubmission(context.Background(), winner.claim, SubmissionResult{Status: SubmissionNotSubmitted, SubmissionRef: "submission-concurrent-absent"}, now); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityMissingAndExpiredNeverSubmit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider fixtureProvider
		want     OccurrenceState
	}{{"missing", fixtureProvider{}, OccurrenceBlocked}, {"expired", fixtureProvider{found: true, grant: authority.Grant{GrantID: "expired", ExpiresAt: testBase}}, OccurrenceExpired}} {
		t.Run(tc.name, func(t *testing.T) {
			store := testStore(t, tc.name+".db")
			active, _, signer := seedActiveStore(t, store, "schedule-"+tc.name, ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue}, nil)
			planOneOccurrence(t, store, active, testBase.Add(time.Hour))
			submitter := &fixtureSubmitter{}
			coordinator, err := NewCoordinator(CoordinatorConfig{Store: store, Planner: NewPlanner(testClock{}, SystemZoneLoader{}, signer), AuthorityProvider: tc.provider, AuthorityVerifier: signer, Submitter: submitter, RunObserver: fixtureObserver{result: RunObservation{Status: RunObservationMissing}}, OwnerID: "manager-auth", Lease: time.Second, Now: func() time.Time { return testBase.Add(time.Hour) }})
			if err != nil {
				t.Fatal(err)
			}
			processed, state, _, err := coordinator.processOne(context.Background(), testBase.Add(time.Hour))
			if err != nil || !processed || state != tc.want || submitter.submitCalls.Load() != 0 {
				t.Fatalf("state=%s submit=%d err=%v", state, submitter.submitCalls.Load(), err)
			}
		})
	}
}

type mutableClock struct{ at time.Time }

func (c *mutableClock) Now() time.Time { return c.at }

type fixtureProvider struct {
	grant authority.Grant
	found bool
	err   error
}

func (p fixtureProvider) AuthorityFor(context.Context, Occurrence) (authority.Grant, bool, error) {
	return p.grant, p.found, p.err
}

type fixtureSubmitter struct {
	submitResult    SubmissionResult
	submitErr       error
	reconcileResult SubmissionResult
	reconcileErr    error
	submitCalls     atomic.Int32
	reconcileCalls  atomic.Int32
}

func (s *fixtureSubmitter) Submit(context.Context, Occurrence, authority.Grant) (SubmissionResult, error) {
	s.submitCalls.Add(1)
	return s.submitResult, s.submitErr
}
func (s *fixtureSubmitter) Reconcile(context.Context, Occurrence, string) (SubmissionResult, error) {
	s.reconcileCalls.Add(1)
	return s.reconcileResult, s.reconcileErr
}

type fixtureObserver struct {
	result RunObservation
	err    error
}

func (o fixtureObserver) Observe(context.Context, string) (RunObservation, error) {
	return o.result, o.err
}

type sequenceObserver struct {
	mu     sync.Mutex
	values []RunObservation
}

func (o *sequenceObserver) Observe(context.Context, string) (RunObservation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.values) == 0 {
		return RunObservation{Status: RunObservationNonTerminal, State: inspection.RunRunning}, nil
	}
	value := o.values[0]
	o.values = o.values[1:]
	return value, nil
}

func testStore(t *testing.T, name string) *Store {
	t.Helper()
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(StoreConfig{Path: filepath.Join(directory, name)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedActiveStore(t *testing.T, store *Store, id string, concurrency ConcurrencyPolicy, mutate func(*Schedule)) (Schedule, authority.Grant, *authority.Signer) {
	t.Helper()
	draft := testDraftSchedule(t, id, concurrency)
	if mutate != nil {
		mutate(&draft)
		if err := draft.Validate(); err != nil {
			t.Fatalf("mutated draft: %v", err)
		}
	}
	return activateDraftStore(t, store, draft)
}

func activateDraftStore(t *testing.T, store *Store, draft Schedule) (Schedule, authority.Grant, *authority.Signer) {
	t.Helper()
	id := draft.ScheduleID
	if _, created, err := store.Create(context.Background(), draft); err != nil || !created {
		t.Fatalf("Create created=%v err=%v", created, err)
	}
	awaiting, err := store.AwaitAuthorization(context.Background(), keyFor(draft), testBase.Add(-90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := authority.NewSigner("issuer-"+id, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	scope, digest, err := ScopeFor(awaiting.Schedule)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := signer.Issue("grant-"+id, authority.ServiceExecution, scope.ServicePrincipalSHA256, authority.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID, SourceHandles: scope.SourceHandles, OperationKinds: scope.RequiredOperations, ScheduleID: scope.ScheduleID, PolicySHA256: digest, MaxFrames: scope.ResourceCeiling.MaxTargets * scope.ResourceCeiling.MaxSamplesPerTarget, MaxBytes: scope.ResourceCeiling.MaxMediaBytes, MaxDurationSeconds: scope.ResourceCeiling.MaxDurationSeconds}, testBase.Add(-2*time.Hour), draft.ValidUntil)
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.Activate(context.Background(), keyFor(draft), grant, signer, testBase.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return active.Schedule, grant, signer
}

func planOneOccurrence(t *testing.T, store *Store, active Schedule, due time.Time) {
	t.Helper()
	record, err := store.Get(context.Background(), keyFor(active))
	if err != nil {
		t.Fatal(err)
	}
	date := civilDateFrom(due.In(time.UTC))
	occurrence, err := newOccurrence(active, date, due, due, due)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordPlanning(context.Background(), record, due, []Occurrence{occurrence}); err != nil {
		t.Fatalf("RecordPlanning: %v", err)
	}
}

func testCoordinator(t *testing.T, store *Store, active Schedule, grant authority.Grant, signer *authority.Signer, clock *mutableClock, submitter Submitter, observer RunObserver) *Coordinator {
	t.Helper()
	coordinator, err := NewCoordinator(CoordinatorConfig{Store: store, Planner: NewPlanner(clock, SystemZoneLoader{}, signer), AuthorityProvider: fixtureProvider{grant: grant, found: true}, AuthorityVerifier: signer, Submitter: submitter, RunObserver: observer, OwnerID: "manager-main", Lease: time.Second, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}
