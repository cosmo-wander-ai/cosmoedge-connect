package runtime_test

import (
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectiontest"
)

type runtimeHarness struct {
	repository  *inspectionstore.Store
	manager     *inspectionruntime.Manager
	fixture     *inspectiontest.FixturePorts
	clock       *inspectiontest.MonotonicClock
	acquisition *recordingAcquirer
	analysis    *recordingAnalyzer
	authority   *inspectionauthority.EphemeralBroker
	authorized  *recordingAuthorityBroker
}

func TestRunIDForPlanIsStableAndRejectsInvalidPlans(t *testing.T) {
	request := inspectiontest.SceneRunRequest()
	plan, err := inspection.CompilePlan(inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), request)
	if err != nil {
		t.Fatal(err)
	}
	first, err := inspectionruntime.RunIDForPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := inspectionruntime.RunIDForPlan(plan)
	if err != nil || first != second || !strings.HasPrefix(first, "run_") {
		t.Fatalf("RunIDForPlan() first=%q second=%q err=%v", first, second, err)
	}
	changed := plan
	changed.RequestID = "request-changed"
	if _, err := inspectionruntime.RunIDForPlan(changed); err == nil {
		t.Fatal("RunIDForPlan accepted a plan with a stale self digest")
	}
	if value, err := inspectionruntime.RunIDForPlan(inspection.ExecutionPlan{}); err == nil || value != "" {
		t.Fatalf("invalid RunIDForPlan()=%q err=%v", value, err)
	}
}

func newRuntimeHarness(t *testing.T, scenario inspectiontest.FixtureScenario, request inspection.CreateRunRequest, options ...inspectionruntime.Option) *runtimeHarness {
	t.Helper()
	repository, err := inspectionstore.Open(filepath.Join(privateTestDir(t), "inspection.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	clock, err := inspectiontest.NewMonotonicClock(request.RequestedAt.Add(2*time.Second), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	mediaStore, err := media.New(media.Config{
		Root: filepath.Join(t.TempDir(), "media"), MaxObjectBytes: 1 << 20, MaxTotalBytes: 32 << 20,
		MaxDescriptors: 256, DefaultTTL: time.Hour, MaximumTTL: time.Hour, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := inspectiontest.RuntimeScriptForScenario(scenario)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := inspectiontest.NewFixturePorts(script, mediaStore, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	baseOptions := []inspectionruntime.Option{
		inspectionruntime.WithClock(clock.Now),
		inspectionruntime.WithRuntimeID("runtime-harness-v2"),
	}
	baseOptions = append(baseOptions, options...)
	ports := fixture.Ports()
	recorder := &recordingAcquirer{delegate: ports.Acquisition}
	ports.Acquisition = recorder
	analysisRecorder := &recordingAnalyzer{delegate: ports.Analysis}
	ports.Analysis = analysisRecorder
	broker := newActorBroker(t, 2*time.Minute, clock.Now)
	authorized := &recordingAuthorityBroker{Broker: broker}
	manager, err := inspectionruntime.New(repository, authorized, ports, baseOptions...)
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeHarness{
		repository: repository, manager: manager, fixture: fixture, clock: clock,
		acquisition: recorder, analysis: analysisRecorder, authority: broker, authorized: authorized,
	}
}

func TestRuntimeExecutesFrozenStepLedgerWithTypedReferences(t *testing.T) {
	request := runtimeRequest()
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioNormal, request)
	run, created, err := harness.manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil || !created {
		t.Fatalf("Submit()=(%+v,%v,%v)", run, created, err)
	}
	processed, err := harness.manager.ProcessOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("ProcessOne()=(%v,%v)", processed, err)
	}
	stored, err := harness.repository.GetRun(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != inspection.RunCompleted || stored.PersistentConfigWrites != 0 || stored.CleanupPending != 0 {
		failedSteps, _ := harness.repository.ListSteps(context.Background(), run.RunID)
		acquisitions := harness.acquisition.snapshot()
		validationErrors := make([]error, len(acquisitions))
		for index := range acquisitions {
			validationErrors[index] = acquisitions[index].Result.Descriptor.Validate()
		}
		t.Fatalf("run=%+v steps=%+v acquisitions=%+v descriptorValidation=%v analyses=%+v", stored, failedSteps, acquisitions, validationErrors, harness.analysis.snapshot())
	}
	steps, err := harness.repository.ListSteps(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) == 0 {
		t.Fatal("run has no durable step ledger")
	}
	for _, step := range steps {
		if step.State != inspection.StepSucceeded || len(step.Outputs) != 1 || step.Outputs[0].ValueRef == "" || step.Outputs[0].SHA256 == "" {
			t.Fatalf("step did not publish one typed reference: %+v", step)
		}
	}
	observations, err := harness.repository.ListObservations(context.Background(), run.RunID)
	if err != nil || len(observations) != 2 {
		t.Fatalf("observations=(%+v,%v)", observations, err)
	}
	for _, observation := range observations {
		if observation.Result.Binding.OutputSchemaVersion != "finding.v2" || len(observation.Result.EvidenceRefs) == 0 {
			t.Fatalf("observation is not v2 media-bound: %+v", observation)
		}
		for _, mediaRef := range observation.Result.EvidenceRefs {
			descriptor, err := harness.fixture.Ports().Acquisition.Describe(context.Background(), mediaRef)
			if err != nil || descriptor.Schema != media.Schema || descriptor.Binding.RunID != run.RunID {
				t.Fatalf("media descriptor=(%+v,%v)", descriptor, err)
			}
		}
	}
	stats := harness.fixture.Stats()
	if stats.ResolveCalls != 2 || stats.AcquireCalls != 3 || stats.AnalyzeCalls != 2 || stats.CleanupCalls != 1 {
		t.Fatalf("fixture stats=%+v", stats)
	}
	if _, err := harness.authority.Lookup(context.Background(), run.RunID); !errors.Is(err, inspectionauthority.ErrNotFound) {
		t.Fatalf("terminal run retained execution authority: %v", err)
	}
	if pending, err := harness.repository.ListPendingAuthorityReleases(context.Background(), 10); err != nil || len(pending) != 0 {
		t.Fatalf("terminal authority release pending=%v err=%v", pending, err)
	}
	plan, err := inspection.CompilePlan(inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustPlanRequest(t, request))
	if err != nil {
		t.Fatal(err)
	}
	verified := harness.authorized.snapshot()
	if len(verified) != len(plan.Steps) {
		t.Fatalf("verified steps=%d planned steps=%d", len(verified), len(plan.Steps))
	}
	seenAttempts := make(map[string]struct{}, len(verified))
	for _, demand := range verified {
		key := demand.StepID + "\x00" + demand.AttemptID
		if demand.Identity.Kind != inspectionauthority.IdentityActor || demand.Identity.PrincipalSHA256 != strings.Repeat("a", 64) ||
			demand.RunID != run.RunID || demand.PlanSHA256 != plan.PlanSHA256 ||
			demand.RuntimeID == "" || demand.AssignmentID != plan.AssignmentID || demand.RequestKey != plan.RequestKey {
			t.Fatalf("step authority demand=%+v", demand)
		}
		if _, repeated := seenAttempts[key]; repeated {
			t.Fatalf("replayed runtime authority demand=%q", key)
		}
		seenAttempts[key] = struct{}{}
	}
}

func TestRuntimeCancellationRevokesAuthorityBeforeAcknowledgingRelease(t *testing.T) {
	request := runtimeRequest()
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioNormal, request)
	run, created, err := harness.manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil || !created {
		t.Fatalf("Submit()=(%+v,%v,%v)", run, created, err)
	}
	if err := harness.manager.Cancel(context.Background(), run.RunID, "user_cancelled"); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.authority.Lookup(context.Background(), run.RunID); !errors.Is(err, inspectionauthority.ErrNotFound) {
		t.Fatalf("cancelled run retained execution authority: %v", err)
	}
	if pending, err := harness.repository.ListPendingAuthorityReleases(context.Background(), 10); err != nil || len(pending) != 0 {
		t.Fatalf("cancelled authority release pending=%v err=%v", pending, err)
	}
}

func TestRuntimeRecoversCrashBetweenAuthorityRevokeAndStoreAcknowledgement(t *testing.T) {
	request := runtimeRequest()
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioNormal, request)
	repository := &failOnceAuthorityAckRepository{Repository: harness.repository}
	manager, err := inspectionruntime.New(repository, harness.authority, harness.fixture.Ports(),
		inspectionruntime.WithClock(harness.clock.Now), inspectionruntime.WithRuntimeID("authority-release-recovery-v2"))
	if err != nil {
		t.Fatal(err)
	}
	run, _, err := manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Cancel(context.Background(), run.RunID, "user_cancelled"); err == nil || !strings.Contains(err.Error(), "acknowledge terminal") {
		t.Fatalf("injected authority acknowledgement error=%v", err)
	}
	if pending, err := harness.repository.ListPendingAuthorityReleases(context.Background(), 10); err != nil || len(pending) != 1 || pending[0] != run.RunID {
		t.Fatalf("pending after crash=%v err=%v", pending, err)
	}
	restarted, err := inspectionruntime.New(repository, harness.authority, harness.fixture.Ports(),
		inspectionruntime.WithClock(func() time.Time { return request.RequestedAt }),
		inspectionruntime.WithRuntimeID("authority-release-recovery-v2"))
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := restarted.ProcessOne(context.Background()); err != nil || processed {
		t.Fatalf("release recovery ProcessOne()=(%v,%v)", processed, err)
	}
	if pending, err := harness.repository.ListPendingAuthorityReleases(context.Background(), 10); err != nil || len(pending) != 0 {
		t.Fatalf("pending after recovery=%v err=%v", pending, err)
	}
}

func TestRuntimeRejectsExpiredAuthorityBeforeAnyExecutionPort(t *testing.T) {
	request := runtimeRequest()
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioNormal, request)
	run, created, err := harness.manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil || !created {
		t.Fatalf("Submit()=(%+v,%v,%v)", run, created, err)
	}
	if err := harness.clock.Advance(3 * time.Minute); err != nil {
		t.Fatal(err)
	}
	processed, err := harness.manager.ProcessOne(context.Background())
	if !processed || !errors.Is(err, inspectionruntime.ErrAuthorityRejected) {
		t.Fatalf("expired ProcessOne()=(%v,%v)", processed, err)
	}
	stats := harness.fixture.Stats()
	if stats.ResolveCalls != 0 || stats.AcquireCalls != 0 || stats.AnalyzeCalls != 0 || stats.CleanupCalls != 0 {
		t.Fatalf("expired authority reached execution ports: %+v", stats)
	}
	steps, err := harness.repository.ListSteps(context.Background(), run.RunID)
	if err != nil || len(steps) == 0 || steps[0].State != inspection.StepFailed || steps[0].Reason != "execution_authority_rejected" {
		t.Fatalf("authority rejection steps=%+v error=%v", steps, err)
	}
}

func TestRuntimeRejectsAuthorizationBoundToAnotherRuntime(t *testing.T) {
	request := runtimeRequest()
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioNormal, request)
	run, created, err := harness.manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil || !created {
		t.Fatalf("Submit()=(%+v,%v,%v)", run, created, err)
	}
	other, err := inspectionruntime.New(harness.repository, harness.authority, harness.fixture.Ports(),
		inspectionruntime.WithClock(harness.clock.Now), inspectionruntime.WithRuntimeID("other-runtime-v2"))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := other.ProcessOne(context.Background())
	if !processed || !errors.Is(err, inspectionruntime.ErrAuthorityRejected) {
		t.Fatalf("wrong runtime ProcessOne()=(%v,%v)", processed, err)
	}
	stats := harness.fixture.Stats()
	if stats.ResolveCalls != 0 || stats.AcquireCalls != 0 || stats.AnalyzeCalls != 0 || stats.CleanupCalls != 0 {
		t.Fatalf("wrong runtime reached execution ports: %+v", stats)
	}
}

func TestRuntimeScheduledExecutionRequiresServiceIdentity(t *testing.T) {
	request := runtimeRequest()
	request.Origin = inspection.OriginSchedule
	request.RequestID = "scheduled-runtime-request"
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioNormal, request)
	actorIdentity, err := inspectionauthority.NewExecutionIdentity(inspectionauthority.IdentityActor, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectionauthority.NewSubmission(request, actorIdentity); !errors.Is(err, inspectionauthority.ErrUnauthorized) {
		t.Fatalf("actor identity scheduled submission error=%v", err)
	}

	serviceBroker := newServiceBroker(t, 2*time.Minute, harness.clock.Now)
	manager, err := inspectionruntime.New(harness.repository, serviceBroker, harness.fixture.Ports(),
		inspectionruntime.WithClock(harness.clock.Now), inspectionruntime.WithRuntimeID("service-runtime-v2"))
	if err != nil {
		t.Fatal(err)
	}
	run, created, err := manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil || !created {
		t.Fatalf("service Submit()=(%+v,%v,%v)", run, created, err)
	}
	processed, err := manager.ProcessOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("service ProcessOne()=(%v,%v)", processed, err)
	}
	stored, err := harness.repository.GetRun(context.Background(), run.RunID)
	if err != nil || stored.State != inspection.RunCompleted {
		t.Fatalf("scheduled run=%+v error=%v", stored, err)
	}
}

func TestRuntimeKnownStaleBindingCompletesBlockedWithoutAnalysis(t *testing.T) {
	request := runtimeRequest()
	request.TargetIDs = []string{inspectiontest.SceneTargetBetaID}
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioCatalogMismatch, request)
	run, _, err := harness.manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || !processed {
		t.Fatalf("ProcessOne()=(%v,%v)", processed, err)
	}
	stored, err := harness.repository.GetRun(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != inspection.RunBlocked || stored.Reason != "execution_binding_stale" {
		t.Fatalf("blocked run=%+v", stored)
	}
	stats := harness.fixture.Stats()
	if stats.AcquireCalls != 0 || stats.AnalyzeCalls != 0 || stats.CleanupCalls != 1 {
		t.Fatalf("unexpected calls after stale binding: %+v", stats)
	}
}

func TestOutcomeUnknownRequiresExplicitReconciliation(t *testing.T) {
	request := runtimeRequest()
	request.TargetIDs = []string{inspectiontest.SceneTargetBetaID}
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioOutcomeUnknown, request)
	run, _, err := harness.manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || !processed {
		t.Fatalf("ProcessOne()=(%v,%v)", processed, err)
	}
	stored, _ := harness.repository.GetRun(context.Background(), run.RunID)
	if stored.State != inspection.RunRunning {
		t.Fatalf("unknown attempt finalized implicitly: %+v", stored)
	}
	steps, err := harness.repository.ListSteps(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	unknown := 0
	for _, step := range steps {
		if step.State == inspection.StepOutcomeUnknown {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatalf("outcome_unknown steps=%d, ledger=%+v", unknown, steps)
	}
	if err := harness.clock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || processed {
		t.Fatalf("recovery ProcessOne()=(%v,%v)", processed, err)
	}
	stored, _ = harness.repository.GetRun(context.Background(), run.RunID)
	if stored.State != inspection.RunReconciliationRequired {
		t.Fatalf("unknown run did not require reconciliation: %+v", stored)
	}
}

func TestInterruptedAcquisitionIsRecoveredPerStepWithoutBlindReplay(t *testing.T) {
	request := runtimeRequest()
	request.TargetIDs = []string{inspectiontest.SceneTargetBetaID}
	harness := newRuntimeHarness(t, inspectiontest.FixtureScenarioTimeout, request)
	harness.acquisition.entered = make(chan struct{})
	run, _, err := harness.manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	type processResult struct {
		processed bool
		err       error
	}
	done := make(chan processResult, 1)
	go func() {
		processed, processErr := harness.manager.ProcessOne(ctx)
		done <- processResult{processed: processed, err: processErr}
	}()
	select {
	case <-harness.acquisition.entered:
	case <-time.After(time.Second):
		t.Fatal("acquisition port was not entered")
	}
	cancel()
	select {
	case result := <-done:
		if !result.processed || !errors.Is(result.err, context.Canceled) {
			t.Fatalf("cancelled ProcessOne()=(%v,%v)", result.processed, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled ProcessOne did not return")
	}
	steps, err := harness.repository.ListSteps(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	running := 0
	for _, step := range steps {
		if step.State == inspection.StepRunning {
			running++
		}
	}
	if running != 1 {
		t.Fatalf("interrupted attempt was flattened instead of left recoverable: %+v", steps)
	}
	if err := harness.clock.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || processed {
		t.Fatalf("recovery ProcessOne()=(%v,%v)", processed, err)
	}
	stored, _ := harness.repository.GetRun(context.Background(), run.RunID)
	if stored.State != inspection.RunReconciliationRequired {
		t.Fatalf("interrupted side effect was blindly replayed: %+v", stored)
	}
}

func TestStepHeartbeatRenewsAttemptLeaseDuringLongPortCall(t *testing.T) {
	request := runtimeRequest()
	request.TargetIDs = []string{inspectiontest.SceneTargetBetaID}
	repository, err := inspectionstore.Open(filepath.Join(privateTestDir(t), "inspection.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	clock, _ := inspectiontest.NewMonotonicClock(request.RequestedAt.Add(2*time.Second), time.Millisecond)
	mediaStore, err := media.New(media.Config{
		Root: filepath.Join(t.TempDir(), "media"), MaxObjectBytes: 1 << 20, MaxTotalBytes: 8 << 20,
		MaxDescriptors: 64, DefaultTTL: time.Hour, MaximumTTL: time.Hour, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	script, _ := inspectiontest.RuntimeScriptForScenario(inspectiontest.FixtureScenarioNormal)
	fixture, _ := inspectiontest.NewFixturePorts(script, mediaStore, clock.Now)
	ports := fixture.Ports()
	blocker := &blockingAcquirer{delegate: ports.Acquisition, entered: make(chan struct{}), release: make(chan struct{})}
	ports.Acquisition = blocker
	counting := &renewalRepository{Repository: repository}
	broker := newActorBroker(t, 2*time.Minute, clock.Now)
	manager, err := inspectionruntime.New(counting, broker, ports, inspectionruntime.WithClock(clock.Now),
		inspectionruntime.WithRuntimeID("heartbeat-runtime-v2"), inspectionruntime.WithLease(60*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	run, _, err := manager.Submit(context.Background(), inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), mustSubmission(t, request))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, processErr := manager.ProcessOne(context.Background())
		done <- processErr
	}()
	select {
	case <-blocker.entered:
	case <-time.After(time.Second):
		t.Fatal("acquisition port was not entered")
	}
	steps, err := repository.ListSteps(context.Background(), run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	var running inspection.StepRecord
	for _, step := range steps {
		if step.State == inspection.StepRunning {
			running = step
			break
		}
	}
	if running.StepID == "" {
		t.Fatalf("blocked acquisition has no running step: %+v", steps)
	}
	attempts, err := repository.ListStepAttempts(context.Background(), run.RunID, running.StepID)
	if err != nil || len(attempts) != 1 {
		t.Fatalf("initial running attempt=(%+v,%v)", attempts, err)
	}
	initialExpiry := attempts[0].LeaseExpires
	renewalDeadline := time.NewTimer(2 * time.Second)
	renewalPoll := time.NewTicker(5 * time.Millisecond)
	defer renewalDeadline.Stop()
	defer renewalPoll.Stop()
	renewed := false
	for !renewed {
		select {
		case <-renewalPoll.C:
			attempts, err = repository.ListStepAttempts(context.Background(), run.RunID, running.StepID)
			if err != nil || len(attempts) != 1 {
				t.Fatalf("renewed running attempt=(%+v,%v)", attempts, err)
			}
			if attempts[0].LeaseExpires.After(initialExpiry) {
				renewed = true
			}
		case <-renewalDeadline.C:
			t.Fatalf("step attempt lease was not extended beyond %s", initialExpiry)
		}
	}
	close(blocker.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ProcessOne() after heartbeat: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not finish after releasing acquisition")
	}
	if counting.stepRenewals.Load() < 1 {
		t.Fatal("step attempt lease was never renewed")
	}
	stored, _ := repository.GetRun(context.Background(), run.RunID)
	if stored.State != inspection.RunCompleted {
		t.Fatalf("heartbeat run=%+v", stored)
	}
}

type renewalRepository struct {
	inspectionruntime.Repository
	stepRenewals atomic.Int64
}

type failOnceAuthorityAckRepository struct {
	inspectionruntime.Repository
	failed atomic.Bool
}

func (r *failOnceAuthorityAckRepository) MarkAuthorityReleased(ctx context.Context, runID string, at time.Time) error {
	if !r.failed.Swap(true) {
		return errors.New("injected authority release acknowledgement failure")
	}
	return r.Repository.MarkAuthorityReleased(ctx, runID, at)
}

func (r *renewalRepository) RenewStepAttemptLease(ctx context.Context, runID, runOwner, attemptID, attemptOwner string, now time.Time, ttl time.Duration) error {
	err := r.Repository.RenewStepAttemptLease(ctx, runID, runOwner, attemptID, attemptOwner, now, ttl)
	if err == nil {
		r.stepRenewals.Add(1)
	}
	return err
}

type blockingAcquirer struct {
	delegate inspectionruntime.MediaAcquirer
	once     sync.Once
	entered  chan struct{}
	release  chan struct{}
}

type recordedAcquisition struct {
	Result inspectionruntime.MediaAcquireResult
	Err    error
}

type recordingAcquirer struct {
	delegate inspectionruntime.MediaAcquirer
	mu       sync.Mutex
	values   []recordedAcquisition
	entered  chan struct{}
	once     sync.Once
}

type recordedAnalysis struct {
	Result inspectionruntime.AnalysisReference
	Err    error
}

type recordingAnalyzer struct {
	delegate inspectionruntime.Analyzer
	mu       sync.Mutex
	values   []recordedAnalysis
}

func (a *recordingAnalyzer) Analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	result, err := a.delegate.Analyze(ctx, request)
	a.mu.Lock()
	a.values = append(a.values, recordedAnalysis{Result: result, Err: err})
	a.mu.Unlock()
	return result, err
}

func (a *recordingAnalyzer) Result(ctx context.Context, resultRef string) (inspectionruntime.AnalysisReference, error) {
	return a.delegate.Result(ctx, resultRef)
}

func (a *recordingAnalyzer) snapshot() []recordedAnalysis {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recordedAnalysis(nil), a.values...)
}

func (a *recordingAcquirer) Acquire(ctx context.Context, request inspectionruntime.MediaAcquireRequest) (inspectionruntime.MediaAcquireResult, error) {
	if a.entered != nil {
		a.once.Do(func() { close(a.entered) })
	}
	result, err := a.delegate.Acquire(ctx, request)
	a.mu.Lock()
	a.values = append(a.values, recordedAcquisition{Result: result, Err: err})
	a.mu.Unlock()
	return result, err
}

func (a *recordingAcquirer) Describe(ctx context.Context, mediaRef string) (media.Descriptor, error) {
	return a.delegate.Describe(ctx, mediaRef)
}

func (a *recordingAcquirer) snapshot() []recordedAcquisition {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recordedAcquisition(nil), a.values...)
}

func (a *blockingAcquirer) Acquire(ctx context.Context, request inspectionruntime.MediaAcquireRequest) (inspectionruntime.MediaAcquireResult, error) {
	a.once.Do(func() {
		close(a.entered)
		select {
		case <-a.release:
		case <-ctx.Done():
		}
	})
	return a.delegate.Acquire(ctx, request)
}

func (a *blockingAcquirer) Describe(ctx context.Context, mediaRef string) (media.Descriptor, error) {
	return a.delegate.Describe(ctx, mediaRef)
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := teststate.ProtectDir(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

type recordingAuthorityBroker struct {
	inspectionauthority.Broker
	mu      sync.Mutex
	demands []inspectionauthority.StepDemand
}

func (b *recordingAuthorityBroker) VerifyAndConsume(ctx context.Context, authorization inspectionauthority.Authorization, demand inspectionauthority.StepDemand) error {
	if err := b.Broker.VerifyAndConsume(ctx, authorization, demand); err != nil {
		return err
	}
	b.mu.Lock()
	b.demands = append(b.demands, demand)
	b.mu.Unlock()
	return nil
}

func (b *recordingAuthorityBroker) snapshot() []inspectionauthority.StepDemand {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]inspectionauthority.StepDemand(nil), b.demands...)
}

func newActorBroker(t *testing.T, ttl time.Duration, now func() time.Time) *inspectionauthority.EphemeralBroker {
	t.Helper()
	broker, err := inspectionauthority.NewEphemeralBroker(
		"runtime-test-broker", []byte(strings.Repeat("k", 32)), ttl, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Close)
	return broker
}

func newServiceBroker(t *testing.T, ttl time.Duration, now func() time.Time) *inspectionauthority.EphemeralBroker {
	t.Helper()
	broker, err := inspectionauthority.NewEphemeralBroker(
		"runtime-service-test-broker", []byte(strings.Repeat("s", 32)), ttl, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Close)
	return broker
}

func mustSubmission(t *testing.T, request inspection.CreateRunRequest) inspectionauthority.Submission {
	t.Helper()
	principal := strings.Repeat("a", 64)
	if request.Origin == inspection.OriginSchedule {
		principal = strings.Repeat("b", 64)
	}
	identity, err := inspectionauthority.ExecutionIdentityForOrigin(request.Origin, principal)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := inspectionauthority.NewSubmission(request, identity)
	if err != nil {
		t.Fatal(err)
	}
	return submission
}

func mustPlanRequest(t *testing.T, request inspection.CreateRunRequest) inspection.CreateRunRequest {
	t.Helper()
	prepared, err := mustSubmission(t, request).PlanRequest()
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func runtimeRequest() inspection.CreateRunRequest {
	request := inspectiontest.SceneRunRequest()
	request.RequestedAt = time.Now().UTC().Add(-time.Second)
	request.Deadline = request.RequestedAt.Add(5 * time.Minute)
	return request
}
