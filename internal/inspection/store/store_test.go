package store

import (
	"context"
	"database/sql"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	_ "modernc.org/sqlite"
)

var _ inspectionruntime.Repository = (*Store)(nil)

func TestDirectUpgradeReopenAndVersionedConfigurationCoexistWithOtherTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	ordinary, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ordinary.Exec(`CREATE TABLE operator_fixture(id TEXT PRIMARY KEY); INSERT INTO operator_fixture(id) VALUES('preserved')`); err != nil {
		t.Fatal(err)
	}
	if err := ordinary.Close(); err != nil {
		t.Fatal(err)
	}
	protectStoreTestPath(t, path, true)

	now := fixtureNow()
	template, assignment := fixtureInspectionTemplate(now), fixtureAssignment()
	store := openStore(t, path)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("database mode=%v", info.Mode().Perm())
		}
	}
	if err := store.SaveInspectionTemplate(context.Background(), template); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAssignment(context.Background(), assignment, now); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInspectionTemplate(context.Background(), template); err != nil {
		t.Fatalf("idempotent template save: %v", err)
	}
	if err := store.SaveAssignment(context.Background(), assignment, now.Add(time.Second)); err != nil {
		t.Fatalf("idempotent assignment save: %v", err)
	}
	conflictingTemplate := template
	conflictingTemplate.Name = "Changed without a revision"
	if err := store.SaveInspectionTemplate(context.Background(), conflictingTemplate); !errors.Is(err, ErrConflict) {
		t.Fatalf("template conflict error=%v", err)
	}
	conflictingAssignment := assignment
	conflictingAssignment.ZoneID = "another-zone"
	if err := store.SaveAssignment(context.Background(), conflictingAssignment, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("assignment conflict error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openStore(t, path)
	defer reopened.Close()
	gotTemplate, err := reopened.GetInspectionTemplate(context.Background(), template.TenantID, template.TemplateID, template.Revision)
	if err != nil || !reflect.DeepEqual(gotTemplate, template) {
		t.Fatalf("template=%#v err=%v", gotTemplate, err)
	}
	templates, err := reopened.ListInspectionTemplates(context.Background(), template.TenantID)
	if err != nil || len(templates) != 1 || !reflect.DeepEqual(templates[0], template) {
		t.Fatalf("templates=%#v err=%v", templates, err)
	}
	gotAssignment, err := reopened.GetAssignment(context.Background(), assignment.TenantID, assignment.AssignmentID, assignment.Revision)
	if err != nil || !reflect.DeepEqual(gotAssignment, assignment) {
		t.Fatalf("assignment=%#v err=%v", gotAssignment, err)
	}
	var preserved string
	if err := reopened.db.QueryRow(`SELECT id FROM operator_fixture`).Scan(&preserved); err != nil || preserved != "preserved" {
		t.Fatalf("coexisting table value=%q err=%v", preserved, err)
	}
	var schema, digest string
	var version int
	if err := reopened.db.QueryRow(`SELECT schema, version, schema_sha256 FROM inspection_store_meta`).Scan(&schema, &version, &digest); err != nil || schema != storeSchemaID || version != schemaVersion || digest != storeSchemaSHA256 {
		t.Fatalf("store metadata schema=%q version=%d digest=%q err=%v", schema, version, digest, err)
	}
	rows, err := reopened.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'inspection_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	tables := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	want := []string{"inspection_assignments", "inspection_outbox", "inspection_result_media", "inspection_results", "inspection_run_events", "inspection_runs", "inspection_step_attempts", "inspection_step_reconciliations", "inspection_steps", "inspection_store_meta", "inspection_templates"}
	sort.Strings(want)
	if !reflect.DeepEqual(tables, want) {
		t.Fatalf("tables=%v want=%v", tables, want)
	}
}

func TestOpenRejectsNewerSchemaAndSymlinkDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE inspection_schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); INSERT INTO inspection_schema_migrations(version, applied_at) VALUES(4, 'future')`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	protectStoreTestPath(t, path, true)
	if store, err := Open(path); err == nil || !strings.Contains(err.Error(), "incomplete or unsupported") {
		if store != nil {
			store.Close()
		}
		t.Fatalf("newer schema error=%v", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(t.TempDir(), "target.db")
	if err := os.WriteFile(target, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	protectStoreTestPath(t, link, false)
	if store, err := Open(link); err == nil || !strings.Contains(err.Error(), "unexpected object type") {
		if store != nil {
			store.Close()
		}
		t.Fatalf("symlink database error=%v", err)
	}
}

func TestOpenRejectsPartialOrUnknownDirectUpgradeSchema(t *testing.T) {
	create := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "operator.db")
		store := openStore(t, path)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("missing table", func(t *testing.T) {
		path := create(t)
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`DROP TABLE inspection_step_reconciliations`); err != nil {
			t.Fatal(err)
		}
		_ = database.Close()
		if opened, err := Open(path); err == nil || !strings.Contains(err.Error(), "incomplete") {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatalf("partial schema error=%v", err)
		}
	})
	t.Run("unknown inspection table", func(t *testing.T) {
		path := create(t)
		database, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`CREATE TABLE inspection_legacy_payload(id TEXT)`); err != nil {
			t.Fatal(err)
		}
		_ = database.Close()
		if opened, err := Open(path); err == nil || !strings.Contains(err.Error(), "incomplete or unsupported") {
			if opened != nil {
				_ = opened.Close()
			}
			t.Fatalf("unknown schema error=%v", err)
		}
	})
}

func TestResetDevelopmentStateRequiresExactV2AndPreservesOtherTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE operator_fixture(id TEXT PRIMARY KEY); INSERT INTO operator_fixture(id) VALUES('preserved')`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	protectStoreTestPath(t, path, true)
	now := fixtureNow()
	template := fixtureInspectionTemplate(now)
	store := openStore(t, path)
	if err := store.SaveInspectionTemplate(context.Background(), template); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ResetDevelopmentState(context.Background(), path, "RESET"); err == nil {
		t.Fatal("development reset accepted an abbreviated confirmation")
	}
	reopened := openStore(t, path)
	if _, err := reopened.GetInspectionTemplate(context.Background(), template.TenantID, template.TemplateID, template.Revision); err != nil {
		t.Fatalf("rejected reset mutated inspection state: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ResetDevelopmentState(context.Background(), path, DevelopmentResetConfirmation); err != nil {
		t.Fatal(err)
	}
	fresh := openStore(t, path)
	defer fresh.Close()
	if _, err := fresh.GetInspectionTemplate(context.Background(), template.TenantID, template.TemplateID, template.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reset retained inspection template: %v", err)
	}
	var preserved string
	if err := fresh.db.QueryRow(`SELECT id FROM operator_fixture`).Scan(&preserved); err != nil || preserved != "preserved" {
		t.Fatalf("reset changed unrelated table value=%q err=%v", preserved, err)
	}
}

func TestCreateQueuedRunIsTenantRequestIdempotentAndPlanBound(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	now := fixtureNow()
	plan := fixturePlan(t, now, "request-1", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-future", now.Add(-time.Nanosecond)); !errors.Is(err, ErrConflict) {
		t.Fatalf("future request queue error=%v", err)
	}
	run, created, err := store.CreateQueuedRun(context.Background(), plan, "run-1", now)
	if err != nil || !created || run.State != inspection.RunQueued || run.RunID != "run-1" {
		t.Fatalf("create run=%#v created=%v err=%v", run, created, err)
	}
	replayed, created, err := store.CreateQueuedRun(context.Background(), plan, "run-retry", now.Add(time.Second))
	if err != nil || created || replayed.RunID != "run-1" {
		t.Fatalf("replay run=%#v created=%v err=%v", replayed, created, err)
	}
	changedPlan := fixturePlan(t, now, "request-1", 4*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), changedPlan, "run-conflict", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("same key changed plan error=%v", err)
	}
	otherPlan := fixturePlan(t, now, "request-2", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), otherPlan, "run-1", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("same run id changed request error=%v", err)
	}
	storedPlan, err := store.GetPlan(context.Background(), "run-1")
	if err != nil || storedPlan.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("plan=%#v err=%v", storedPlan, err)
	}
	events, err := store.ListEvents(context.Background(), "run-1")
	if err != nil || len(events) != 3 || events[0].To != inspection.RunRequested || events[2].To != inspection.RunQueued {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestConcurrentClaimHasExactlyOneLeaseOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	first := openStore(t, path)
	defer first.Close()
	second := openStore(t, path)
	defer second.Close()
	now := fixtureNow()
	plan := fixturePlan(t, now, "claim-once", 5*time.Minute)
	if _, _, err := first.CreateQueuedRun(context.Background(), plan, "run-claim", now); err != nil {
		t.Fatal(err)
	}
	type result struct {
		run   inspection.Run
		plan  inspection.ExecutionPlan
		ok    bool
		error error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var group sync.WaitGroup
	for index, candidate := range []*Store{first, second} {
		group.Add(1)
		go func(store *Store, owner string) {
			defer group.Done()
			<-start
			run, plan, ok, err := store.ClaimNext(context.Background(), owner, now.Add(time.Second), time.Minute)
			results <- result{run: run, plan: plan, ok: ok, error: err}
		}(candidate, []string{"worker-a", "worker-b"}[index])
	}
	close(start)
	group.Wait()
	close(results)
	claimed := 0
	for result := range results {
		if result.error != nil {
			t.Fatal(result.error)
		}
		if result.ok {
			claimed++
			if result.run.RunID != "run-claim" || result.run.State != inspection.RunRunning || result.plan.PlanSHA256 != plan.PlanSHA256 {
				t.Fatalf("claim=%#v plan=%#v", result.run, result.plan)
			}
		}
	}
	if claimed != 1 {
		t.Fatalf("claims=%d want=1", claimed)
	}
	events, err := first.ListEvents(context.Background(), "run-claim")
	if err != nil || len(events) != 4 || events[3].From != inspection.RunQueued || events[3].To != inspection.RunRunning {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestRenewLeaseRequiresCurrentOwnerAndUnexpiredRunningLease(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	now := fixtureNow()
	plan := fixturePlan(t, now, "renew", 10*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-renew", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(context.Background(), "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if err := store.RenewLease(context.Background(), "run-renew", "worker-b", now.Add(30*time.Second), 2*time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong-owner renewal error=%v", err)
	}
	if err := store.RenewLease(context.Background(), "run-renew", "worker-a", now.Add(30*time.Second), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	// The original lease ended at +61s; a successful renewal keeps the owner
	// valid until +150s.
	if err := store.AppendPhase(context.Background(), "run-renew", "worker-a", inspection.PhaseAnalyzing, now.Add(2*time.Minute), "long_analysis_active"); err != nil {
		t.Fatalf("renewed lease was not honored: %v", err)
	}
	if err := store.RenewLease(context.Background(), "run-renew", "worker-a", now.Add(3*time.Minute), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired lease renewal error=%v", err)
	}
}

func TestSubsecondLeaseBoundariesUseChronologicalTextOrdering(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	now := fixtureNow().Add(100 * time.Millisecond)
	plan := fixturePlan(t, now, "subsecond", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-subsecond", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(context.Background(), "worker-a", now.Add(100*time.Millisecond), 500*time.Millisecond); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if recovered, err := store.RecoverInterrupted(context.Background(), now.Add(599*time.Millisecond)); err != nil || recovered != 0 {
		t.Fatalf("early subsecond recovery=%d err=%v", recovered, err)
	}
	if recovered, err := store.RecoverInterrupted(context.Background(), now.Add(601*time.Millisecond)); err != nil || recovered != 1 {
		t.Fatalf("due subsecond recovery=%d err=%v", recovered, err)
	}
}

func TestExecutionDeadlineDoesNotPreventOwnedFinalization(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	now := fixtureNow()
	plan := fixturePlan(t, now, "deadline-finalize", 2*time.Second)
	if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-deadline-finalize", now); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimNext(context.Background(), "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if err := store.RenewLease(context.Background(), "run-deadline-finalize", "worker-a", now.Add(3*time.Second), time.Minute); err != nil {
		t.Fatalf("renew after execution deadline: %v", err)
	}
	if err := store.BeginFinalization(context.Background(), "run-deadline-finalize", "worker-a", now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	outcome := noObservationOutcome(plan, inspection.RunExpired, "run_deadline_exceeded", "Inspection expired before a trusted observation formed.")
	if err := store.Finalize(context.Background(), "run-deadline-finalize", "worker-a", outcome, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	run, err := store.GetRun(context.Background(), "run-deadline-finalize")
	if err != nil || run.State != inspection.RunExpired {
		t.Fatalf("run=%+v err=%v", run, err)
	}
}

func TestExpireQueuedIsAtomicTerminalAndNeverClaimed(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	now := fixtureNow()
	plan := fixturePlan(t, now, "queue-expiry", time.Second)
	if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-queue-expiry", now); err != nil {
		t.Fatal(err)
	}
	if count, err := store.ExpireQueued(context.Background(), now.Add(2*time.Second)); err != nil || count != 1 {
		t.Fatalf("ExpireQueued() count=%d err=%v", count, err)
	}
	run, err := store.GetRun(context.Background(), "run-queue-expiry")
	if err != nil || run.State != inspection.RunExpired || run.Reason != "queue_deadline_exceeded" {
		t.Fatalf("run=%+v err=%v", run, err)
	}
	outcome, present, err := store.GetOutcome(context.Background(), run.RunID)
	if err != nil || !present || outcome.State != inspection.RunExpired || outcome.Coverage.Missing != outcome.Coverage.Required {
		t.Fatalf("outcome=%+v present=%v err=%v", outcome, present, err)
	}
	if outbox, err := store.ListOutbox(context.Background(), run.RunID); err != nil || len(outbox) != 1 {
		t.Fatalf("outbox=%+v err=%v", outbox, err)
	}
	if _, _, ok, err := store.ClaimNext(context.Background(), "worker-a", now.Add(3*time.Second), time.Minute); err != nil || ok {
		t.Fatalf("expired run claim ok=%v err=%v", ok, err)
	}
	if count, err := store.ExpireQueued(context.Background(), now.Add(4*time.Second)); err != nil || count != 0 {
		t.Fatalf("second ExpireQueued() count=%d err=%v", count, err)
	}
}

func TestOutboxMaterializationLeaseRecoversWithoutSending(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "outbox-materialization", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-outbox", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Cancel(ctx, "run-outbox", now.Add(time.Second), "user_cancelled"); err != nil {
		t.Fatal(err)
	}
	message, ok, err := store.ClaimOutbox(ctx, "materializer-a", now.Add(2*time.Second), time.Minute)
	if err != nil || !ok || message.State != OutboxMaterializing || message.Attempts != 1 {
		t.Fatalf("first claim message=%+v ok=%v err=%v", message, ok, err)
	}
	if _, ok, err := store.ClaimOutbox(ctx, "materializer-b", now.Add(3*time.Second), time.Minute); err != nil || ok {
		t.Fatalf("concurrent claim ok=%v err=%v", ok, err)
	}
	if err := store.MarkOutboxMaterialized(ctx, message.MessageID, "materializer-b", now.Add(4*time.Second)); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong-owner materialization error=%v", err)
	}
	if recovered, err := store.RecoverOutboxClaims(ctx, now.Add(59*time.Second)); err != nil || recovered != 0 {
		t.Fatalf("early recovery=%d err=%v", recovered, err)
	}
	if recovered, err := store.RecoverOutboxClaims(ctx, now.Add(63*time.Second)); err != nil || recovered != 1 {
		t.Fatalf("expired recovery=%d err=%v", recovered, err)
	}
	message, ok, err = store.ClaimOutbox(ctx, "materializer-b", now.Add(64*time.Second), time.Minute)
	if err != nil || !ok || message.Attempts != 2 {
		t.Fatalf("reclaimed message=%+v ok=%v err=%v", message, ok, err)
	}
	if err := store.MarkOutboxMaterialized(ctx, message.MessageID, "materializer-b", now.Add(65*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := store.ListOutbox(ctx, "run-outbox")
	if err != nil || len(stored) != 1 || stored[0].State != OutboxMaterialized || stored[0].Attempts != 2 {
		t.Fatalf("stored outbox=%+v err=%v", stored, err)
	}
	if _, ok, err := store.ClaimOutbox(ctx, "materializer-c", now.Add(66*time.Second), time.Minute); err != nil || ok {
		t.Fatalf("materialized message reclaimed ok=%v err=%v", ok, err)
	}
}

func TestExecutionPersistsMediaBoundObservationsOutcomeAndOutbox(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	now := fixtureNow()
	plan := fixturePlan(t, now, "execute", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-execute", now); err != nil {
		t.Fatal(err)
	}
	run, claimedPlan, ok, err := store.ClaimNext(context.Background(), "worker-a", now.Add(time.Second), 2*time.Minute)
	if err != nil || !ok || run.State != inspection.RunRunning || claimedPlan.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("claim run=%#v ok=%v err=%v", run, ok, err)
	}
	phaseAt := now.Add(2 * time.Second)
	if err := store.AppendPhase(context.Background(), run.RunID, "worker-b", inspection.PhaseCapturing, phaseAt, "capture_started"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong-owner phase error=%v", err)
	}
	if err := store.AppendPhase(context.Background(), run.RunID, "worker-a", inspection.PhaseCapturing, phaseAt, "capture_started"); err != nil {
		t.Fatal(err)
	}
	mediaRef := "media_0123456789abcdef0123456789abcdef"
	completeStepsThroughFirstMedia(t, store, plan, run.RunID, "worker-a", phaseAt.Add(time.Second), mediaRef)
	observation := fixtureObservation(t, plan, run.RunID, mediaRef, phaseAt.Add(2*time.Second))
	committedAt := phaseAt.Add(3 * time.Second)
	if err := store.RecordObservation(context.Background(), "worker-a", observation, committedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordObservation(context.Background(), "worker-a", observation, committedAt); err != nil {
		t.Fatalf("idempotent observation: %v", err)
	}
	changed := observation
	changed.Result.Integrity.RawOutputSHA256 = strings.Repeat("b", 64)
	if err := store.RecordObservation(context.Background(), "worker-a", changed, committedAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("observation conflict error=%v", err)
	}
	observations, err := store.ListObservations(context.Background(), run.RunID)
	if err != nil || len(observations) != 1 || observations[0].ObservationID != observation.ObservationID {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
	usageAt := phaseAt.Add(3 * time.Second)
	if err := store.RecordResourceUsage(context.Background(), run.RunID, "worker-a", 2, 1, usageAt); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginFinalization(context.Background(), run.RunID, "worker-a", usageAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	outcome, err := inspection.Evaluate(plan, observations)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(context.Background(), run.RunID, "worker-b", outcome, usageAt.Add(2*time.Second)); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("wrong-owner finalize error=%v", err)
	}
	if err := store.Finalize(context.Background(), run.RunID, "worker-a", outcome, usageAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetRun(context.Background(), run.RunID)
	if err != nil || stored.State != outcome.State || stored.Conclusion != outcome.Conclusion || stored.TemporaryResources != 2 || stored.CleanupPending != 1 || stored.PersistentConfigWrites != 0 {
		t.Fatalf("stored run=%#v err=%v", stored, err)
	}
	storedOutcome, present, err := store.GetOutcome(context.Background(), run.RunID)
	if err != nil || !present || !reflect.DeepEqual(storedOutcome, outcome) {
		t.Fatalf("outcome=%#v present=%v err=%v", storedOutcome, present, err)
	}
	outbox, err := store.ListOutbox(context.Background(), run.RunID)
	if err != nil || len(outbox) != 1 || outbox[0].State != "pending" || strings.Contains(string(outbox[0].Payload), "artifact") {
		t.Fatalf("outbox=%#v err=%v", outbox, err)
	}
	if err := store.Finalize(context.Background(), run.RunID, "worker-a", outcome, usageAt.Add(3*time.Second)); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("second finalize error=%v", err)
	}
	assertResultMediaSchemaHasNoPayloadLocation(t, store)
	assertEventsAreAppendOnly(t, store, run.RunID)
}

func TestCancelOnlyQueuedRun(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	now := fixtureNow()
	queued := fixturePlan(t, now, "cancel-queued", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), queued, "run-cancel", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Cancel(context.Background(), "run-cancel", now.Add(time.Second), "user_cancelled"); err != nil {
		t.Fatal(err)
	}
	run, err := store.GetRun(context.Background(), "run-cancel")
	if err != nil || run.State != inspection.RunCancelled || run.Reason != "user_cancelled" {
		t.Fatalf("run=%#v err=%v", run, err)
	}
	outcome, present, err := store.GetOutcome(context.Background(), run.RunID)
	if err != nil || !present || outcome.State != inspection.RunCancelled || outcome.Coverage.Missing != outcome.Coverage.Required {
		t.Fatalf("cancel outcome=%#v present=%v err=%v", outcome, present, err)
	}
	if _, _, ok, err := store.ClaimNext(context.Background(), "worker-a", now.Add(2*time.Second), time.Minute); err != nil || ok {
		t.Fatalf("cancelled run claim ok=%v err=%v", ok, err)
	}
	if err := store.Cancel(context.Background(), "run-cancel", now.Add(3*time.Second), "again"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second cancel error=%v", err)
	}
}

func TestTerminalAuthorityReleaseIsDurableIrreversibleAndIdempotent(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
	defer store.Close()
	ctx := context.Background()
	now := fixtureNow()
	plan := fixturePlan(t, now, "authority-release", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(ctx, plan, "run-authority-release", now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAuthorityReleased(ctx, "run-authority-release", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-terminal release error=%v", err)
	}
	if err := store.Cancel(ctx, "run-authority-release", now.Add(time.Second), "user_cancelled"); err != nil {
		t.Fatal(err)
	}
	pending, err := store.ListPendingAuthorityReleases(ctx, 10)
	if err != nil || !reflect.DeepEqual(pending, []string{"run-authority-release"}) {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	releasedAt := now.Add(-time.Hour)
	if err := store.MarkAuthorityReleased(ctx, "run-authority-release", releasedAt); err != nil {
		t.Fatal(err)
	}
	var releasedAtRaw string
	if err := store.db.QueryRow(`SELECT authority_released_at FROM inspection_runs WHERE run_id='run-authority-release'`).Scan(&releasedAtRaw); err != nil {
		t.Fatal(err)
	}
	if storedRelease, err := parseTime(releasedAtRaw); err != nil || !storedRelease.Equal(now.Add(time.Second)) {
		t.Fatalf("monotonic release time=%v err=%v", storedRelease, err)
	}
	if err := store.MarkAuthorityReleased(ctx, "run-authority-release", releasedAt.Add(time.Second)); err != nil {
		t.Fatalf("idempotent release acknowledgement error=%v", err)
	}
	if pending, err := store.ListPendingAuthorityReleases(ctx, 10); err != nil || len(pending) != 0 {
		t.Fatalf("post-release pending=%v err=%v", pending, err)
	}
	if _, err := store.db.Exec(`UPDATE inspection_runs SET authority_release_state='pending',authority_released_at='' WHERE run_id='run-authority-release'`); err == nil {
		t.Fatal("released execution authority was reopened directly")
	}
	if run, err := store.GetRun(ctx, "run-authority-release"); err != nil || run.State != inspection.RunCancelled {
		t.Fatalf("released run=%+v err=%v", run, err)
	}
	for _, limit := range []int{-1, 0, maxAuthorityReleaseBatch + 1} {
		if _, err := store.ListPendingAuthorityReleases(ctx, limit); err == nil {
			t.Fatalf("invalid authority release limit %d was accepted", limit)
		}
	}
}

func TestRecoverInterruptedUsesPerStepReplayPolicyAndKeepsFinalizationUnknown(t *testing.T) {
	now := fixtureNow()

	t.Run("running replayable steps return to queue", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "recover-running", 10*time.Minute)
		if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-running", now); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := store.ClaimNext(context.Background(), "worker-a", now.Add(time.Second), time.Minute); err != nil || !ok {
			t.Fatalf("claim running ok=%v err=%v", ok, err)
		}
		if _, _, ok, err := store.ClaimNextStep(context.Background(), "run-running", "worker-a", "step-worker", now.Add(2*time.Second), 10*time.Second); err != nil || !ok {
			t.Fatalf("claim step ok=%v err=%v", ok, err)
		}
		if recovered, err := store.RecoverInterrupted(context.Background(), now.Add(30*time.Second)); err != nil || recovered != 0 {
			t.Fatalf("early run recovery count=%d err=%v", recovered, err)
		}
		if recovered, err := store.RecoverInterrupted(context.Background(), now.Add(61*time.Second)); err != nil || recovered != 1 {
			t.Fatalf("running recovery count=%d err=%v", recovered, err)
		}
		run, err := store.GetRun(context.Background(), "run-running")
		if err != nil || run.State != inspection.RunQueued || run.Reason != "replayable_step_interrupted" {
			t.Fatalf("run=%#v err=%v", run, err)
		}
		if _, _, ok, err := store.ClaimNext(context.Background(), "worker-b", now.Add(62*time.Second), time.Minute); err != nil || !ok {
			t.Fatalf("safe recovered run was not reclaimable ok=%v err=%v", ok, err)
		}
	})

	t.Run("finalization remains unknown", func(t *testing.T) {
		store := openStore(t, filepath.Join(t.TempDir(), "operator.db"))
		defer store.Close()
		plan := fixturePlan(t, now, "recover-finalizing", 10*time.Minute)
		if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-finalizing", now); err != nil {
			t.Fatal(err)
		}
		if _, _, ok, err := store.ClaimNext(context.Background(), "worker-b", now.Add(time.Second), time.Minute); err != nil || !ok {
			t.Fatalf("claim finalizing candidate ok=%v err=%v", ok, err)
		}
		if err := store.BeginFinalization(context.Background(), "run-finalizing", "worker-b", now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		if recovered, err := store.RecoverInterrupted(context.Background(), now.Add(61*time.Second)); err != nil || recovered != 1 {
			t.Fatalf("finalizing recovery count=%d err=%v", recovered, err)
		}
		run, err := store.GetRun(context.Background(), "run-finalizing")
		if err != nil || run.State != inspection.RunUnknown || run.Reason != "finalization_lease_expired" {
			t.Fatalf("run=%#v err=%v", run, err)
		}
		outcome, present, err := store.GetOutcome(context.Background(), "run-finalizing")
		if err != nil || !present || outcome.State != inspection.RunUnknown || outcome.Reason != run.Reason {
			t.Fatalf("outcome=%#v present=%v err=%v", outcome, present, err)
		}
		outbox, err := store.ListOutbox(context.Background(), "run-finalizing")
		if err != nil || len(outbox) != 1 || !strings.Contains(string(outbox[0].Payload), `"state":"unknown"`) {
			t.Fatalf("outbox=%#v err=%v", outbox, err)
		}
	})
}

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	protectStoreTestPath(t, path, false)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func protectStoreTestPath(t *testing.T, path string, protectFile bool) {
	t.Helper()
	if err := teststate.ProtectDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if protectFile {
		if err := localstate.ProtectFile(path); err != nil {
			t.Fatal(err)
		}
	}
}

func fixtureNow() time.Time {
	return time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
}

func fixtureInspectionTemplate(now time.Time) inspection.InspectionTemplate {
	return inspection.InspectionTemplate{
		Schema: inspection.SchemaVersion, TenantID: "tenant-local", TemplateID: "visible-hygiene", Revision: 1,
		Name: "Visible hygiene", BusinessPurpose: "Find visible residue without a regulatory claim.",
		Criteria: []inspection.Criterion{{
			ID: "visible-residue", Name: "Visible table residue", Method: inspection.MethodVLM, Required: true,
			RuleRef: "customer-visible-standard", RuleVersion: 1, MayAssertCompliance: true,
			Prompt: inspection.PromptContract{Template: "Inspect {{area}} for visible residue.", Variables: []inspection.PromptVariable{{Name: "area", Required: true, MaxLength: 32, AllowedValues: []string{"dining"}}}},
			Output: inspection.OutputContract{Mode: inspection.ResultStructured, AllowedAssessments: []inspection.Assessment{inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention, inspection.AssessmentUncertain, inspection.AssessmentNotObservable}, SchemaVersion: "finding.v2"},
		}},
		Strategies:          []inspection.StrategyPolicy{fixtureSnapshotStrategy(2)},
		Budget:              inspection.ResourceBudget{MaxTargets: 2, MaxSamplesPerTarget: 2, MaxAnalyses: 4, MaxDurationSeconds: 600, MaxMediaBytes: 1 << 20},
		Evidence:            inspection.EvidencePolicy{Required: true, RetentionSeconds: 3600, RedactionProfile: "faces-v1"},
		OutputSchemaVersion: "report.v2", State: inspection.TemplatePublished, CreatedBy: "fixture", CreatedAt: now,
	}
}

func fixtureAssignment() inspection.Assignment {
	return inspection.Assignment{
		Schema: inspection.SchemaVersion, TenantID: "tenant-local", AssignmentID: "store-a-hygiene", Revision: 1,
		TemplateID: "visible-hygiene", TemplateRevision: 1, SiteID: "site-a", ZoneID: "dining",
		Targets: []inspection.TargetBinding{{
			TargetID: "dining-east", FriendlyName: "Dining east",
			SourceBindings: []inspection.SourceBinding{{
				Kind: inspection.SourceCamera, SourceHandle: "source-east", SourceRevision: 1,
				SourceFingerprint: strings.Repeat("a", 64), CapabilityRefs: []string{"capture-capability"},
				MediaKinds: []inspection.MediaKind{inspection.MediaImage}, ROIRef: "roi-east",
			}},
			CriterionIDs: []string{"visible-residue"}, Strategy: inspection.StrategySnapshotAnalysis,
			Acquisition: inspection.AcquisitionPolicy{Samples: 1},
		}},
		SourceCatalogFingerprint: strings.Repeat("b", 64), Published: true,
	}
}

func fixtureSnapshotStrategy(maxSamples int) inspection.StrategyPolicy {
	return inspection.StrategyPolicy{
		Strategy:               inspection.StrategySnapshotAnalysis,
		AllowedSourceKinds:     []inspection.SourceKind{inspection.SourceCamera},
		RequiredCapabilityRefs: []string{"capture-capability"}, MinimumSources: 1, MaximumSources: 1,
		Time:               inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
		AnalysisPolicyRef:  "snapshot-vlm-v2",
		MaximumAcquisition: inspection.AcquisitionPolicy{Samples: maxSamples, IntervalMillis: 60_000},
	}
}

func fixturePlan(t *testing.T, now time.Time, requestID string, duration time.Duration) inspection.ExecutionPlan {
	t.Helper()
	template, assignment := fixtureInspectionTemplate(now.Add(-time.Hour)), fixtureAssignment()
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: template.TenantID, SiteID: assignment.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision,
		AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		Origin: inspection.OriginUser, RequestID: requestID, Variables: map[string]string{"area": "dining"},
		RequestedAt: now, Deadline: now.Add(duration),
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func fixtureObservation(t *testing.T, plan inspection.ExecutionPlan, runID, mediaRef string, observedAt time.Time) inspection.Observation {
	t.Helper()
	stepID := ""
	for _, step := range plan.Steps {
		if step.Kind == inspection.StepValidateResult && step.TargetID == "dining-east" && step.CriterionID == "visible-residue" {
			stepID = step.StepID
			break
		}
	}
	if stepID == "" {
		t.Fatal("fixture plan has no result validation step")
	}
	capturedAt := observedAt.Add(-time.Second)
	visible := true
	return inspection.Observation{
		ObservationID: "observation-1", SampleID: "sample-1",
		Result: inspection.AnalysisResult{
			Binding: inspection.ResultBinding{
				ResultID: "result-observation-1", RunID: runID, StepID: stepID, TargetID: "dining-east",
				CriterionID: "visible-residue", CriterionVersion: "1", OutputKind: inspection.ResultStructured,
				OutputSchemaVersion: "finding.v2", Usage: inspection.ResultUsageInspection,
				TimeWindow: inspection.ResultTimeWindow{StartAt: capturedAt, EndAt: capturedAt},
				SourceMedia: []inspection.ResultSourceMedia{{
					SourceRef: "source-east", MediaRef: mediaRef, SHA256: strings.Repeat("a", 64), CapturedAt: capturedAt,
					FreshnessMS: 1000, SampleOrdinal: 1,
				}},
			},
			Assessment: inspection.AssessmentNeedsAttention, Observability: inspection.ResultFullyVisible,
			Value: &inspection.ResultValue{Kind: inspection.ResultStructured, Structured: &inspection.StructuredValue{Fields: []inspection.StructuredField{{
				Name: "visible-residue", Value: inspection.StructuredScalar{Kind: inspection.StructuredBoolean, Boolean: &visible},
			}}}},
			EvidenceRefs: []string{mediaRef}, ReasonCodes: []string{"criterion_violated"}, Limitations: []string{},
			Analyzer: inspection.ResultAnalyzer{
				Kind: inspection.ResultAnalyzerFixture, AdapterVersion: "adapter.v2", ModelPolicy: "fixture-policy",
				ResolvedModelVersion: "fixture-v2", PromptTemplateID: "fixture-template",
				PromptTemplateVersion: "2", PromptTemplateSHA256: strings.Repeat("c", 64),
			},
			Execution: inspection.ResultExecution{
				Attempt: 1, StartedAt: observedAt, CompletedAt: observedAt.Add(500 * time.Millisecond), LatencyMS: 500,
			},
			Integrity: inspection.ResultIntegrity{RawOutputSHA256: strings.Repeat("d", 64), ContractSHA256: strings.Repeat("e", 64)},
		},
	}
}

func completeStepsThroughFirstMedia(t *testing.T, store *Store, plan inspection.ExecutionPlan, runID, runOwner string, at time.Time, mediaRef string) {
	t.Helper()
	ctx := context.Background()
	completedMedia := false
	for index := 0; index < len(plan.Steps) && !completedMedia; index++ {
		step := plan.Steps[index]
		if step.Kind != inspection.StepResolveSource && step.Kind != inspection.StepAcquireMedia && step.Kind != inspection.StepOpenMedia {
			continue
		}
		_, attempt, ok, err := store.ClaimNextStep(ctx, runID, runOwner, "media-step-worker", at.Add(time.Duration(index)*time.Millisecond), time.Minute)
		if err != nil || !ok || attempt.StepID != step.StepID {
			t.Fatalf("claim step %s ok=%v attempt=%#v err=%v", step.Kind, ok, attempt, err)
		}
		outputs := successfulOutputs(step)
		if step.Kind == inspection.StepAcquireMedia || step.Kind == inspection.StepOpenMedia {
			for outputIndex := range outputs {
				outputs[outputIndex].ValueRef = mediaRef
			}
			completedMedia = true
		}
		if err := store.CompleteStep(ctx, runID, runOwner, attempt.AttemptID, "media-step-worker", inspection.StepSucceeded, outputs, "step_completed", at.Add(time.Duration(index)*time.Millisecond+500*time.Microsecond)); err != nil {
			t.Fatalf("complete step %s: %v", step.Kind, err)
		}
	}
	if !completedMedia {
		t.Fatal("fixture plan has no media-producing step")
	}
}

func assertResultMediaSchemaHasNoPayloadLocation(t *testing.T, store *Store) {
	t.Helper()
	rows, err := store.db.Query(`PRAGMA table_info(inspection_result_media)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var position, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(name)
		for _, forbidden := range []string{"payload_bytes", "media_bytes", "base64", "path", "url", "endpoint", "address"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("result media schema persists forbidden payload/location column %q", name)
			}
		}
	}
}

func assertEventsAreAppendOnly(t *testing.T, store *Store, runID string) {
	t.Helper()
	if _, err := store.db.Exec(`UPDATE inspection_run_events SET reason='changed' WHERE run_id=?`, runID); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("event update error=%v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM inspection_run_events WHERE run_id=?`, runID); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("event delete error=%v", err)
	}
}

func TestDatabaseDoesNotPersistMediaBytesOrDeviceURLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.db")
	store := openStore(t, path)
	now := fixtureNow()
	plan := fixturePlan(t, now, "no-media", 5*time.Minute)
	if _, _, err := store.CreateQueuedRun(context.Background(), plan, "run-no-media", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"rtsp://", "rtsps://", "imageBase64", "data:image"} {
			if strings.Contains(string(content), forbidden) {
				t.Fatalf("%s contains forbidden data %q", filepath.Base(file), forbidden)
			}
		}
	}
}
