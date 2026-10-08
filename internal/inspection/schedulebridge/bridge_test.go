package schedulebridge

import (
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/deliverybinding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/schedule"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectiontest"
	operatorauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

var bridgeTestTime = time.Date(2026, 7, 20, 10, 1, 0, 0, time.UTC)

func TestSubmitPrebindsExactDecisionBeforeRuntimeAndReplayIsIdempotent(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	fixture.runner.before = func(plan inspection.ExecutionPlan) {
		runID, err := runtime.RunIDForPlan(plan)
		if err != nil {
			t.Error(err)
			return
		}
		decision, err := fixture.state.GetScheduledDecisionByRunID(context.Background(), runID)
		if err != nil || decision.PlanSHA256 != plan.PlanSHA256 || decision.AudienceSHA256 != fixture.occurrence.Delivery.AudienceSHA256 {
			t.Errorf("decision was not prebound before Submit: %+v err=%v", decision, err)
		}
	}
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err != nil || result.Status != schedule.SubmissionAccepted || result.RunRef == "" || fixture.runner.calls != 1 {
		t.Fatalf("Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
	}
	replayed, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err != nil || replayed != result || fixture.runner.calls != 2 {
		t.Fatalf("replay=%+v calls=%d err=%v", replayed, fixture.runner.calls, err)
	}
	audience, err := fixture.state.ResolveRunAudience(context.Background(), result.RunRef)
	if err != nil || audience.PublicRunRef == result.RunRef || audience.Audience != fixture.binding.Audience || audience.PrincipalSHA256 != fixture.binding.PrincipalSHA256 {
		t.Fatalf("ResolveRunAudience()=%+v err=%v", audience, err)
	}
}

func TestRuntimeCreateReplyLossReconcileNeverSubmitsAgain(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	fixture.runner.replyLoss = true
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err == nil || result.Status != schedule.SubmissionUnknown || fixture.runner.calls != 1 {
		t.Fatalf("reply-loss Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
	}
	reconciled, err := fixture.bridge.Reconcile(context.Background(), fixture.occurrence, result.SubmissionRef)
	if err != nil || reconciled.Status != schedule.SubmissionAccepted || reconciled.RunRef == "" || fixture.runner.calls != 1 {
		t.Fatalf("Reconcile()=%+v calls=%d err=%v", reconciled, fixture.runner.calls, err)
	}
}

func TestFrozenDecisionWithoutRuntimeIsAbandonedAndNeverResubmitted(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	fixture.runner.failBeforeCreate = true
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err == nil || result.Status != schedule.SubmissionUnknown || fixture.runner.calls != 1 {
		t.Fatalf("Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
	}
	runID := mustRunID(t, fixture.occurrence)
	if _, err := fixture.state.GetScheduledDecisionByRunID(context.Background(), runID); err != nil {
		t.Fatalf("frozen decision missing before reconciliation: %v", err)
	}
	reconciled, err := fixture.bridge.Reconcile(context.Background(), fixture.occurrence, result.SubmissionRef)
	if err != nil || reconciled.Status != schedule.SubmissionNotSubmitted || fixture.runner.calls != 1 {
		t.Fatalf("Reconcile()=%+v calls=%d err=%v", reconciled, fixture.runner.calls, err)
	}
	if _, err := fixture.state.GetScheduledDecisionByRunID(context.Background(), runID); !errors.Is(err, application.ErrStateNotFound) {
		t.Fatalf("abandoned decision remained: %v", err)
	}
	if _, err := fixture.state.ResolveRunAudience(context.Background(), runID); !errors.Is(err, application.ErrStateNotFound) {
		t.Fatalf("abandoned audience remained: %v", err)
	}
	second, err := fixture.bridge.Reconcile(context.Background(), fixture.occurrence, result.SubmissionRef)
	if err != nil || second.Status != schedule.SubmissionNotSubmitted || fixture.runner.calls != 1 {
		t.Fatalf("replayed Reconcile()=%+v calls=%d err=%v", second, fixture.runner.calls, err)
	}
}

func TestEmptyBindingStateCanRegisterThenAdmit(t *testing.T) {
	fixture := newFixture(t, bindingMissing)
	if _, created, err := fixture.bindings.Register(context.Background(), fixture.binding); err != nil || !created {
		t.Fatalf("Register() created=%v err=%v", created, err)
	}
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err != nil || result.Status != schedule.SubmissionAccepted || fixture.runner.calls != 1 {
		t.Fatalf("Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
	}
}

func TestAdmittedRunKeepsFrozenAudienceIfBindingIsRevokedInFlight(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	fixture.runner.replyLoss = true
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err == nil || result.Status != schedule.SubmissionUnknown {
		t.Fatalf("Submit()=%+v err=%v", result, err)
	}
	if _, changed, err := fixture.bindings.Revoke(context.Background(), fixture.binding.TenantID, fixture.binding.SiteID,
		fixture.binding.BindingRef, fixture.binding.Revision, bridgeTestTime.Add(time.Second)); err != nil || !changed {
		t.Fatalf("Revoke() changed=%v err=%v", changed, err)
	}
	reconciled, err := fixture.bridge.Reconcile(context.Background(), fixture.occurrence, result.SubmissionRef)
	if err != nil || reconciled.Status != schedule.SubmissionAccepted || fixture.runner.calls != 1 {
		t.Fatalf("in-flight Reconcile()=%+v calls=%d err=%v", reconciled, fixture.runner.calls, err)
	}
}

func TestReconcileRejectsSubstitutedSubmissionReferenceWithoutSubmitting(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := fixture.bridge.Reconcile(context.Background(), fixture.occurrence, "submission_substituted")
	if err == nil || reconciled.Status != schedule.SubmissionUnknown || reconciled.SubmissionRef != result.SubmissionRef || fixture.runner.calls != 1 {
		t.Fatalf("Reconcile()=%+v calls=%d err=%v", reconciled, fixture.runner.calls, err)
	}
}

func TestBeforeSubmitPersistenceFailureAndMissingRunReconcileNotSubmitted(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	failing := &failureState{inner: fixture.state, failFreeze: true}
	bridge, err := New(Config{State: failing, Bindings: fixture.bindings, Runner: fixture.runner, Repository: fixture.repo, Verifier: fixture.verifier, Now: func() time.Time { return bridgeTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := bridge.Submit(context.Background(), fixture.occurrence, fixture.grant); err == nil || result.Status != schedule.SubmissionUnknown || fixture.runner.calls != 0 {
		t.Fatalf("failed prebind Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
	}
	reconciled, err := bridge.Reconcile(context.Background(), fixture.occurrence, "")
	if err != nil || reconciled.Status != schedule.SubmissionNotSubmitted || fixture.runner.calls != 0 {
		t.Fatalf("missing Reconcile()=%+v calls=%d err=%v", reconciled, fixture.runner.calls, err)
	}
}

func TestBindingStoreFailureIsUnknownAndNeverReachesRuntime(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	bridge, err := New(Config{State: fixture.state, Bindings: failingBindingResolver{}, Runner: fixture.runner,
		Repository: fixture.repo, Verifier: fixture.verifier, Now: func() time.Time { return bridgeTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err == nil || result.Status != schedule.SubmissionUnknown || result.SubmissionRef == "" || fixture.runner.calls != 0 {
		t.Fatalf("binding failure Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
	}
}

func TestSubmitIndependentlyRejectsAtAndAfterOccurrenceDeadline(t *testing.T) {
	for _, offset := range []time.Duration{0, time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			fixture := newFixture(t, bindingNormal)
			bridge, err := New(Config{
				State: fixture.state, Bindings: fixture.bindings, Runner: fixture.runner,
				Repository: fixture.repo, Verifier: fixture.verifier,
				Now: func() time.Time { return fixture.occurrence.Deadline.Add(offset) },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
			if err != nil || result.Status != schedule.SubmissionRejected || result.SubmissionRef != "" || fixture.runner.calls != 0 {
				t.Fatalf("deadline Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
			}
			if _, err := fixture.state.GetScheduledDecisionByRunID(context.Background(), mustRunID(t, fixture.occurrence)); !errors.Is(err, application.ErrStateNotFound) {
				t.Fatalf("deadline admission persisted a decision: %v", err)
			}
		})
	}
}

func mustRunID(t *testing.T, occurrence schedule.Occurrence) string {
	t.Helper()
	_, runID, err := exactPlan(occurrence)
	if err != nil {
		t.Fatal(err)
	}
	return runID
}

func TestBindingMissingRevokedExpiredOrSubstitutedFailsBeforeRuntime(t *testing.T) {
	for _, mode := range []bindingMode{bindingMissing, bindingRevoked, bindingExpired, bindingExpiresDuringRun, bindingPrincipalSubstituted, bindingAudienceSubstituted} {
		t.Run(string(mode), func(t *testing.T) {
			fixture := newFixture(t, mode)
			result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
			if err != nil || result.Status != schedule.SubmissionRejected || fixture.runner.calls != 0 {
				t.Fatalf("Submit()=%+v calls=%d err=%v", result, fixture.runner.calls, err)
			}
		})
	}
}

func TestReconcileAndObserveSurviveStateRestart(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.state.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := application.OpenState(application.StateConfig{Path: fixture.applicationPath, RequestRetention: 30 * 24 * time.Hour, FeedbackRetention: 90 * 24 * time.Hour, Now: func() time.Time { return bridgeTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	bridge, err := New(Config{State: reopened, Bindings: fixture.bindings, Runner: fixture.runner, Repository: fixture.repo, Verifier: fixture.verifier, Now: func() time.Time { return bridgeTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := bridge.Reconcile(context.Background(), fixture.occurrence, result.SubmissionRef)
	if err != nil || reconciled.Status != schedule.SubmissionAccepted || fixture.runner.calls != 1 {
		t.Fatalf("restart Reconcile()=%+v calls=%d err=%v", reconciled, fixture.runner.calls, err)
	}
	observed, err := bridge.Observe(context.Background(), result.RunRef)
	if err != nil || observed.Status != schedule.RunObservationNonTerminal || observed.State != inspection.RunQueued {
		t.Fatalf("Observe()=%+v err=%v", observed, err)
	}
}

func TestObserveRejectsUnknownOrTamperedRunBinding(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	missing, err := fixture.bridge.Observe(context.Background(), "run_missing")
	if err != nil || missing.Status != schedule.RunObservationMissing {
		t.Fatalf("missing Observe()=%+v err=%v", missing, err)
	}
	result, err := fixture.bridge.Submit(context.Background(), fixture.occurrence, fixture.grant)
	if err != nil {
		t.Fatal(err)
	}
	fixture.repo.mu.Lock()
	changed := fixture.repo.runs[result.RunRef]
	changed.PlanSHA256 = strings.Repeat("f", 64)
	fixture.repo.runs[result.RunRef] = changed
	fixture.repo.mu.Unlock()
	if _, err := fixture.bridge.Observe(context.Background(), result.RunRef); err == nil {
		t.Fatal("Observe accepted a substituted run plan")
	}

	planFixture := newFixture(t, bindingNormal)
	planResult, err := planFixture.bridge.Submit(context.Background(), planFixture.occurrence, planFixture.grant)
	if err != nil {
		t.Fatal(err)
	}
	planFixture.repo.mu.Lock()
	storedPlan := planFixture.repo.plans[planResult.RunRef]
	storedPlan.RequestID = "request-substituted"
	planFixture.repo.plans[planResult.RunRef] = storedPlan
	planFixture.repo.mu.Unlock()
	if _, err := planFixture.bridge.Observe(context.Background(), planResult.RunRef); err == nil {
		t.Fatal("Observe accepted a substituted authoritative plan")
	}
}

func TestNewRejectsTypedNilDependencies(t *testing.T) {
	fixture := newFixture(t, bindingNormal)
	var state *application.StateStore
	if bridge, err := New(Config{State: state, Bindings: fixture.bindings, Runner: fixture.runner, Repository: fixture.repo,
		Verifier: fixture.verifier}); err == nil || bridge != nil {
		t.Fatalf("New(typed nil)=%v err=%v", bridge, err)
	}
}

type bindingMode string

const (
	bindingNormal               bindingMode = "normal"
	bindingMissing              bindingMode = "missing"
	bindingRevoked              bindingMode = "revoked"
	bindingExpired              bindingMode = "expired"
	bindingExpiresDuringRun     bindingMode = "expires_during_run"
	bindingPrincipalSubstituted bindingMode = "principal_substituted"
	bindingAudienceSubstituted  bindingMode = "audience_substituted"
)

type fixture struct {
	applicationPath string
	state           *application.StateStore
	bindings        *deliverybinding.Store
	binding         deliverybinding.Binding
	occurrence      schedule.Occurrence
	grant           operatorauthority.Grant
	verifier        schedule.GrantVerifier
	repo            *fakeRepository
	runner          *fakeRunner
	bridge          *Bridge
}

func newFixture(t *testing.T, mode bindingMode) fixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	applicationPath := filepath.Join(root, "application.db")
	state, err := application.OpenState(application.StateConfig{Path: applicationPath, RequestRetention: 30 * 24 * time.Hour, FeedbackRetention: 90 * 24 * time.Hour, Now: func() time.Time { return bridgeTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	bindings, err := deliverybinding.Open(filepath.Join(root, "bindings.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bindings.Close() })
	audience := delivery.Audience{TenantID: inspectiontest.FixtureTenantID, SiteID: inspectiontest.FixtureSiteID,
		Channel: "wechat", ConversationRef: "conversation-main", RecipientRef: "recipient-main"}
	audienceSHA, err := audience.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	deliveryPrincipal := strings.Repeat("c", 64)
	occurrence, grant, verifier := testOccurrence(t, audienceSHA, deliveryPrincipal)
	binding := deliverybinding.Binding{
		TenantID: audience.TenantID, SiteID: audience.SiteID, BindingRef: occurrence.Delivery.BindingRef,
		Revision: occurrence.Delivery.Revision, Audience: audience, PrincipalSHA256: deliveryPrincipal,
		ValidFrom: bridgeTestTime.Add(-2 * time.Hour), ValidUntil: bridgeTestTime.Add(24 * time.Hour), CreatedAt: bridgeTestTime.Add(-3 * time.Hour),
	}
	switch mode {
	case bindingMissing:
	case bindingExpired:
		binding.ValidUntil = bridgeTestTime
	case bindingExpiresDuringRun:
		binding.ValidUntil = bridgeTestTime.Add(time.Minute)
	case bindingPrincipalSubstituted:
		binding.PrincipalSHA256 = strings.Repeat("d", 64)
	case bindingAudienceSubstituted:
		binding.Audience.RecipientRef = "recipient-other"
	default:
		if mode != bindingNormal && mode != bindingRevoked {
			t.Fatalf("unknown binding mode %q", mode)
		}
	}
	if mode != bindingMissing {
		binding, _, err = bindings.Register(context.Background(), binding)
		if err != nil {
			t.Fatal(err)
		}
		if mode == bindingRevoked {
			binding, _, err = bindings.Revoke(context.Background(), binding.TenantID, binding.SiteID, binding.BindingRef, binding.Revision, bridgeTestTime.Add(-time.Minute))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	repo := &fakeRepository{runs: map[string]inspection.Run{}, plans: map[string]inspection.ExecutionPlan{}}
	runner := &fakeRunner{repo: repo, now: bridgeTestTime}
	bridge, err := New(Config{State: state, Bindings: bindings, Runner: runner, Repository: repo, Verifier: verifier, Now: func() time.Time { return bridgeTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{applicationPath: applicationPath, state: state, bindings: bindings, binding: binding,
		occurrence: occurrence, grant: grant, verifier: verifier, repo: repo, runner: runner, bridge: bridge}
}

func testOccurrence(t *testing.T, audienceSHA, deliveryPrincipal string) (schedule.Occurrence, operatorauthority.Grant, schedule.GrantVerifier) {
	t.Helper()
	request := inspectiontest.SceneRunRequest()
	request.Origin = inspection.OriginSchedule
	request.RequestedAt = bridgeTestTime.Add(-time.Minute)
	request.Deadline = request.RequestedAt.Add(5 * time.Minute)
	spec, err := schedule.FreezeRunSpec(inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), request)
	if err != nil {
		t.Fatal(err)
	}
	deliveryBinding, err := schedule.NewDeliveryBinding("binding-main", 1, audienceSHA, deliveryPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	draft := schedule.Schedule{
		Schema: schedule.SchemaVersion, TenantID: inspectiontest.FixtureTenantID, SiteID: inspectiontest.FixtureSiteID,
		ScheduleID: "schedule-main", Revision: 1, Origin: inspection.OriginSchedule, RunSpec: spec, RunSpecSHA256: spec.SHA256,
		Delivery: deliveryBinding, DeliverySHA256: deliveryBinding.SHA256, ServicePrincipalSHA256: strings.Repeat("a", 64),
		Timezone: "UTC", Weekdays: []schedule.Weekday{schedule.Monday}, LocalTime: "10:00",
		ValidFrom: bridgeTestTime.Add(-2 * time.Hour), ValidUntil: bridgeTestTime.Add(48 * time.Hour), Misfire: schedule.MisfireCatchUpOnce,
		MisfireGraceSeconds: 24 * 60 * 60, Concurrency: schedule.ConcurrencyPolicy{MaxInFlight: 1, OnLimit: schedule.ConcurrencyQueue},
		State: schedule.StateDraft, CreatedAt: bridgeTestTime.Add(-3 * time.Hour), UpdatedAt: bridgeTestTime.Add(-3 * time.Hour),
	}
	awaiting, err := schedule.AwaitAuthorization(draft, bridgeTestTime.Add(-150*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauthority.NewSigner("issuer-test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	scope, scopeSHA, err := schedule.ScopeFor(awaiting)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := signer.Issue("grant-main", operatorauthority.ServiceExecution, scope.ServicePrincipalSHA256, operatorauthority.Scope{
		TenantID: scope.TenantID, SiteID: scope.SiteID, SourceHandles: append([]string(nil), scope.SourceHandles...),
		OperationKinds: append([]string(nil), scope.RequiredOperations...), ScheduleID: scope.ScheduleID, PolicySHA256: scopeSHA,
		MaxFrames: scope.ResourceCeiling.MaxTargets * scope.ResourceCeiling.MaxSamplesPerTarget, MaxBytes: scope.ResourceCeiling.MaxMediaBytes,
		MaxDurationSeconds: scope.ResourceCeiling.MaxDurationSeconds,
	}, bridgeTestTime.Add(-3*time.Hour), bridgeTestTime.Add(36*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	active, err := schedule.Activate(awaiting, grant, signer, bridgeTestTime.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	planner := schedule.NewPlanner(schedule.SystemClock{}, schedule.SystemZoneLoader{}, signer)
	occurrences, err := planner.Due(active, bridgeTestTime.Add(-time.Minute-time.Nanosecond), bridgeTestTime)
	if err != nil || len(occurrences) != 1 {
		t.Fatalf("Due() count=%d err=%v", len(occurrences), err)
	}
	return occurrences[0], grant, signer
}

type fakeRepository struct {
	mu    sync.Mutex
	runs  map[string]inspection.Run
	plans map[string]inspection.ExecutionPlan
}

func (r *fakeRepository) GetRun(_ context.Context, runID string) (inspection.Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.runs[runID]
	if !ok {
		return inspection.Run{}, inspectionstore.ErrNotFound
	}
	return run, nil
}

func (r *fakeRepository) GetPlan(_ context.Context, runID string) (inspection.ExecutionPlan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	plan, ok := r.plans[runID]
	if !ok {
		return inspection.ExecutionPlan{}, inspectionstore.ErrNotFound
	}
	return plan, nil
}

type fakeRunner struct {
	repo             *fakeRepository
	now              time.Time
	calls            int
	replyLoss        bool
	failBeforeCreate bool
	before           func(inspection.ExecutionPlan)
}

func (r *fakeRunner) Submit(_ context.Context, template inspection.InspectionTemplate, assignment inspection.Assignment, submission inspectionauthority.Submission) (inspection.Run, bool, error) {
	r.calls++
	request, err := submission.PlanRequest()
	if err != nil {
		return inspection.Run{}, false, err
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		return inspection.Run{}, false, err
	}
	if r.before != nil {
		r.before(plan)
	}
	if r.failBeforeCreate {
		return inspection.Run{}, false, errors.New("runtime unavailable before durable create")
	}
	runID, err := runtime.RunIDForPlan(plan)
	if err != nil {
		return inspection.Run{}, false, err
	}
	run := inspection.Run{TenantID: plan.TenantID, SiteID: plan.SiteID, RunID: runID,
		RequestKey: plan.RequestKey, PlanSHA256: plan.PlanSHA256, State: inspection.RunQueued, Reason: "plan_admitted",
		Deadline: plan.Deadline, CreatedAt: r.now, UpdatedAt: r.now}
	r.repo.mu.Lock()
	_, exists := r.repo.runs[runID]
	r.repo.runs[runID], r.repo.plans[runID] = run, plan
	r.repo.mu.Unlock()
	if r.replyLoss {
		return run, !exists, errors.New("transport reply lost")
	}
	return run, !exists, nil
}

type failureState struct {
	inner      *application.StateStore
	failFreeze bool
}

type failingBindingResolver struct{}

func (failingBindingResolver) Resolve(context.Context, deliverybinding.ResolveRequest) (deliverybinding.Binding, error) {
	return deliverybinding.Binding{}, errors.New("delivery binding store unavailable")
}

func (s *failureState) FreezeScheduledDecision(ctx context.Context, value application.ScheduledDecisionRecord) (application.ScheduledDecisionRecord, bool, error) {
	if s.failFreeze {
		return application.ScheduledDecisionRecord{}, false, errors.New("persistence unavailable")
	}
	return s.inner.FreezeScheduledDecision(ctx, value)
}

func (s *failureState) GetScheduledDecisionByRunID(ctx context.Context, runID string) (application.ScheduledDecisionRecord, error) {
	return s.inner.GetScheduledDecisionByRunID(ctx, runID)
}

func (s *failureState) AbandonScheduledDecision(ctx context.Context, value application.ScheduledDecisionRecord) (bool, error) {
	return s.inner.AbandonScheduledDecision(ctx, value)
}
