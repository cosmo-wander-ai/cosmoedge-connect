package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

type capabilityStub struct{}

func (capabilityStub) QueryCapabilities(context.Context, httpapi.SessionBinding) (httpapi.CapabilitySet, error) {
	return httpapi.CapabilitySet{
		ContextLabel: "当前场所",
		Capabilities: []httpapi.CapabilityView{{
			CapabilityRef: "general-observation", Title: "现场查看", Description: "按你的要求查看已接入区域。",
			Examples: []string{"看看入口现在的情况"},
		}},
	}, nil
}

type plannerStub struct {
	calls                 int
	temporaryCompileCalls int
	interaction           *httpapi.InteractionRequired
	temporary             *TemporaryDecision
	last                  PlanningRequest
	principal             string
}

func (p *plannerStub) Plan(_ context.Context, input PlanningRequest) (PlanningDecision, error) {
	p.calls++
	p.last = input
	if p.interaction != nil {
		copy := *p.interaction
		return PlanningDecision{Interaction: &copy}, nil
	}
	if p.temporary != nil {
		copy := *p.temporary
		if _, err := copy.PreparationRequest(); err != nil {
			p.temporaryCompileCalls++
			var freezeErr error
			copy, freezeErr = temporaryDecisionForTestInput(input, copy.Spec, copy.DeadlineAt)
			if freezeErr != nil {
				return PlanningDecision{}, freezeErr
			}
		}
		return PlanningDecision{Temporary: &copy}, nil
	}
	template, assignment := genericCatalogFixture(input.Session)
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: input.Session.TenantID, SiteID: input.Session.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision,
		AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		Origin: inspection.OriginUser, RequestID: input.RequestID,
		Variables: map[string]string{"focus": "entrance"}, RequestedAt: input.RequestedAt,
		Deadline: input.RequestedAt.Add(5 * time.Minute),
	}
	principal := input.Session.PrincipalSHA256
	if p.principal != "" {
		principal = p.principal
	}
	identity, err := inspectionauthority.ExecutionIdentityForOrigin(request.Origin, principal)
	if err != nil {
		return PlanningDecision{}, err
	}
	submission, err := inspectionauthority.NewSubmission(request, identity)
	if err != nil {
		return PlanningDecision{}, err
	}
	return PlanningDecision{Template: template, Assignment: assignment, Submission: submission}, nil
}

type repositoryStub struct {
	run          inspection.Run
	plan         inspection.ExecutionPlan
	outcome      inspection.Outcome
	present      bool
	observations []inspection.Observation
}

func (r *repositoryStub) GetRun(_ context.Context, runID string) (inspection.Run, error) {
	if r.run.RunID != runID {
		return inspection.Run{}, inspectionstore.ErrNotFound
	}
	return r.run, nil
}
func (r *repositoryStub) GetPlan(_ context.Context, runID string) (inspection.ExecutionPlan, error) {
	if r.run.RunID != runID {
		return inspection.ExecutionPlan{}, inspectionstore.ErrNotFound
	}
	return r.plan, nil
}
func (r *repositoryStub) GetOutcome(_ context.Context, runID string) (inspection.Outcome, bool, error) {
	if r.run.RunID != runID {
		return inspection.Outcome{}, false, inspectionstore.ErrNotFound
	}
	return r.outcome, r.present, nil
}
func (r *repositoryStub) ListObservations(_ context.Context, runID string) ([]inspection.Observation, error) {
	if r.run.RunID != runID {
		return nil, inspectionstore.ErrNotFound
	}
	return append([]inspection.Observation(nil), r.observations...), nil
}

type runnerStub struct {
	repository *repositoryStub
	calls      int
}

type temporaryRuntimeUnavailableStub struct{}

func (temporaryRuntimeUnavailableStub) Submit(context.Context, temporary.Submission) (temporary.Record, bool, error) {
	return temporary.Record{}, false, temporary.ErrRuntimeNotFound
}

func (temporaryRuntimeUnavailableStub) Get(context.Context, string) (temporary.Record, error) {
	return temporary.Record{}, temporary.ErrRuntimeNotFound
}

type panicAfterSubmitRunner struct{ delegate Runner }

func (r panicAfterSubmitRunner) Submit(ctx context.Context, template inspection.InspectionTemplate, assignment inspection.Assignment, submission inspectionauthority.Submission) (inspection.Run, bool, error) {
	run, created, err := r.delegate.Submit(ctx, template, assignment, submission)
	if err != nil {
		return inspection.Run{}, false, err
	}
	panic(struct {
		run     inspection.Run
		created bool
	}{run: run, created: created})
}

type panicAfterTemporarySubmitRunner struct {
	delegate  TemporaryRunner
	submitted temporary.Record
}

func (r *panicAfterTemporarySubmitRunner) Submit(ctx context.Context, submission temporary.Submission) (temporary.Record, bool, error) {
	run, created, err := r.delegate.Submit(ctx, submission)
	if err != nil {
		return temporary.Record{}, false, err
	}
	r.submitted = run
	panic(struct {
		run     temporary.Record
		created bool
	}{run: run, created: created})
}

type plannerFailureStub struct{ calls int }

func (p *plannerFailureStub) Plan(context.Context, PlanningRequest) (PlanningDecision, error) {
	p.calls++
	return PlanningDecision{}, errors.New("planner must not run after a frozen decision")
}

func (r *runnerStub) Submit(_ context.Context, template inspection.InspectionTemplate, assignment inspection.Assignment, submission inspectionauthority.Submission) (inspection.Run, bool, error) {
	r.calls++
	request, err := submission.PlanRequest()
	if err != nil {
		return inspection.Run{}, false, err
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		return inspection.Run{}, false, err
	}
	run := inspection.Run{
		RunID: "runtime-run-alpha", TenantID: request.TenantID, SiteID: request.SiteID,
		RequestKey: plan.RequestKey, PlanSHA256: plan.PlanSHA256, State: inspection.RunQueued,
		Reason: "plan_admitted", CreatedAt: request.RequestedAt, UpdatedAt: request.RequestedAt,
		Deadline: request.Deadline,
	}
	r.repository.run, r.repository.plan = run, plan
	return run, true, nil
}

type taskValidatorStub struct{ err error }

func (v taskValidatorStub) ValidateInstalledTask(context.Context, string, string, inspection.InstalledTaskBinding) error {
	return v.err
}

type mediaStub struct {
	descriptor media.Descriptor
	content    []byte
}

type temporaryMediaAdapter struct{ media *mediaStub }

func (a temporaryMediaAdapter) Describe(ctx context.Context, ref string) (temporary.MediaDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return temporary.MediaDescriptor{}, err
	}
	descriptor, err := a.media.Describe(ref)
	if err != nil {
		return temporary.MediaDescriptor{}, err
	}
	if len(descriptor.Governance.Audience) != 1 || descriptor.Temporal.WindowEnd == nil {
		return temporary.MediaDescriptor{}, temporary.ErrRuntimeInvalid
	}
	return temporary.MediaDescriptor{
		MediaRef: descriptor.MediaRef, Kind: descriptor.Kind, TenantID: descriptor.Binding.TenantID, SiteID: descriptor.Binding.SiteID,
		RunID: descriptor.Binding.RunID, StepID: descriptor.Binding.StepID, Attempt: descriptor.Binding.Attempt,
		AudienceBindingRef: descriptor.Governance.Audience[0], SHA256: descriptor.Integrity.SHA256,
		MIMEType: descriptor.Encoding.MIMEType, SizeBytes: descriptor.Integrity.SizeBytes,
		Temporal: cloneTestTemporal(descriptor.Temporal), ExpiresAt: descriptor.Governance.ExpiresAt.UTC(),
	}, nil
}

func cloneTestTemporal(value media.Temporal) media.Temporal {
	clone := value
	if value.WindowStart != nil {
		start := value.WindowStart.UTC()
		clone.WindowStart = &start
	}
	if value.WindowEnd != nil {
		end := value.WindowEnd.UTC()
		clone.WindowEnd = &end
	}
	return clone
}

func (a temporaryMediaAdapter) Open(ctx context.Context, ref string) (io.ReadCloser, error) {
	_, reader, err := a.media.Open(ctx, ref)
	return reader, err
}

type temporaryAnalyzerFunc func(context.Context, temporary.AnalysisRequest) ([]byte, error)

func (f temporaryAnalyzerFunc) Analyze(ctx context.Context, request temporary.AnalysisRequest) ([]byte, error) {
	return f(ctx, request)
}

type temporaryRuntimeHarness struct {
	path    string
	store   *temporary.SQLiteStore
	manager *temporary.Manager
}

type applicationPreparationFixture struct {
	mediaRef string
	now      time.Time
}

type applicationRegistrarFixture struct {
	mu                  sync.Mutex
	now                 time.Time
	requests            []mediaprep.FrozenRequest
	failAfterPersistOne bool
	mutateStatus        func(*mediaprep.Status)
}

type applicationPreparationAcquirer struct{}

func (applicationPreparationAcquirer) Acquire(context.Context, mediaprep.AcquisitionRequest) (mediaprep.AcquisitionResult, error) {
	return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionPending}, nil
}

func (applicationPreparationAcquirer) Reconcile(context.Context, mediaprep.ReconciliationRequest) (mediaprep.AcquisitionResult, error) {
	return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionPending}, nil
}

type applicationPreparationPublisher struct{}

func (applicationPreparationPublisher) PutIdempotent(context.Context, media.IdempotentPutRequest, io.Reader) (media.Descriptor, bool, error) {
	return media.Descriptor{}, false, errors.New("publisher is outside preparation registration tests")
}

type durableReplyLossRegistrar struct {
	manager  *mediaprep.Manager
	failOnce bool
	requests []mediaprep.FrozenRequest
	created  []bool
}

func (r *durableReplyLossRegistrar) Prepare(ctx context.Context, request mediaprep.FrozenRequest) (mediaprep.Status, bool, error) {
	status, created, err := r.manager.Prepare(ctx, request)
	if err != nil {
		return mediaprep.Status{}, false, err
	}
	r.requests = append(r.requests, request)
	r.created = append(r.created, created)
	if r.failOnce {
		r.failOnce = false
		return status, created, errors.New("simulated durable registration reply loss")
	}
	return status, created, nil
}

func (p *applicationRegistrarFixture) Prepare(_ context.Context, request mediaprep.FrozenRequest) (mediaprep.Status, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := request.Validate(); err != nil {
		return mediaprep.Status{}, false, err
	}
	preparationRef, err := mediaprep.PreparationRefForScope(request.TenantID, request.SiteID, request.RequestID)
	if err != nil {
		return mediaprep.Status{}, false, err
	}
	created := len(p.requests) == 0
	p.requests = append(p.requests, request)
	status := mediaprep.Status{
		PreparationRef: preparationRef, State: mediaprep.StatePrepared, Reason: mediaprep.ReasonPrepared,
		CreatedAt: p.now.UTC(), UpdatedAt: p.now.UTC(), AvailableAt: p.now.UTC(),
	}
	if p.mutateStatus != nil {
		p.mutateStatus(&status)
	}
	if p.failAfterPersistOne {
		p.failAfterPersistOne = false
		return status, created, errors.New("simulated registration reply loss")
	}
	return status, created, nil
}

func (p *applicationRegistrarFixture) Requests() []mediaprep.FrozenRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]mediaprep.FrozenRequest(nil), p.requests...)
}

func (p applicationPreparationFixture) Get(_ context.Context, ref string) (mediaprep.Status, error) {
	return mediaprep.Status{
		PreparationRef: ref, State: mediaprep.StateReady, Reason: mediaprep.ReasonReady, MediaRef: p.mediaRef,
		CreatedAt: p.now.UTC(), UpdatedAt: p.now.UTC(), AvailableAt: p.now.UTC(),
	}, nil
}

func temporaryDecisionForTestInput(input PlanningRequest, spec temporary.TemporaryObservationSpec, deadline time.Time) (TemporaryDecision, error) {
	audience, err := temporary.FreezeAudience(temporary.ChannelSession{
		TenantID: input.Session.TenantID, SiteID: input.Session.SiteID, Channel: input.Session.Channel,
		ConversationRef: input.Session.ConversationRef, RecipientRef: input.Session.RecipientRef,
		PrincipalSHA256: input.Session.PrincipalSHA256,
	})
	if err != nil {
		return TemporaryDecision{}, err
	}
	runID, err := temporary.RunIDForScope(input.Session.TenantID, input.Session.SiteID, input.RequestID)
	if err != nil {
		return TemporaryDecision{}, err
	}
	stepID, err := temporary.MediaStepIDForRun(runID)
	if err != nil {
		return TemporaryDecision{}, err
	}
	start, end := input.RequestedAt.UTC(), input.RequestedAt.UTC()
	kind, capability := media.KindImage, "snapshot-read"
	if spec.TimeScope.Kind == temporary.TimeScopeRecentWindow {
		start = end.Add(-time.Duration(spec.TimeScope.WindowSeconds) * time.Second)
		kind, capability = media.KindVideoClip, "clip-read"
	}
	request := mediaprep.FrozenRequest{
		Schema: mediaprep.RequestSchema, TenantID: input.Session.TenantID, SiteID: input.Session.SiteID, RequestID: input.RequestID,
		SourceRef: "opaque-temporary-source", CapabilityRef: capability,
		TimeScope:          mediaprep.TimeScope{WindowStart: start, WindowEnd: end, DurationMillis: end.Sub(start).Milliseconds()},
		AudienceBindingRef: audience.Ref, AudienceSHA256: audience.SHA256,
		EvidenceExpiresAt: end.Add(time.Duration(spec.EvidenceTTLSeconds) * time.Second),
		Media: mediaprep.MediaSpec{
			Kind: kind, RunID: runID, StepID: stepID, Attempt: 1, PrivacyClass: "internal",
			RetentionPolicyRef: "temporary-observation",
		},
	}
	return NewTemporaryDecision(spec, request, deadline)
}

func newTemporaryRuntimeHarness(t *testing.T, mediaReader *mediaStub, now time.Time, analyzer temporary.Analyzer) *temporaryRuntimeHarness {
	t.Helper()
	return newTemporaryRuntimeHarnessWithClock(t, mediaReader, func() time.Time { return now }, analyzer)
}

func newTemporaryRuntimeHarnessWithClock(t *testing.T, mediaReader *mediaStub, clock temporary.Clock, analyzer temporary.Analyzer) *temporaryRuntimeHarness {
	t.Helper()
	path := protectedStatePath(t, "temporary-runtime.db")
	store, err := temporary.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := temporary.NewManager(store, applicationPreparationFixture{mediaRef: mediaReader.descriptor.MediaRef, now: mediaReader.descriptor.CreatedAt}, temporaryMediaAdapter{media: mediaReader}, analyzer, clock)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	return &temporaryRuntimeHarness{path: path, store: store, manager: manager}
}

func (m *mediaStub) Describe(ref string) (media.Descriptor, error) {
	if m.descriptor.MediaRef != ref {
		return media.Descriptor{}, media.ErrNotFound
	}
	return m.descriptor, nil
}
func (m *mediaStub) Open(_ context.Context, ref string) (media.Descriptor, io.ReadCloser, error) {
	if m.descriptor.MediaRef != ref {
		return media.Descriptor{}, nil, media.ErrNotFound
	}
	return m.descriptor, io.NopCloser(bytes.NewReader(m.content)), nil
}

func temporarySpecFixture(t *testing.T) temporary.TemporaryObservationSpec {
	t.Helper()
	spec, err := temporary.NewSpec(temporary.Intent{
		Subject: "入口", Region: "主入口", Observable: "当前是否便于人员通行", Locale: "zh-CN",
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func temporaryMediaFixture(session httpapi.SessionBinding, mediaRef, runtimeRequestID string, now time.Time) *mediaStub {
	content := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01, 0x02}
	runID, _ := temporary.RunIDForScope(session.TenantID, session.SiteID, runtimeRequestID)
	stepID, _ := temporary.MediaStepIDForRun(runID)
	audience, _ := temporary.FreezeAudience(temporary.ChannelSession{
		TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef, PrincipalSHA256: session.PrincipalSHA256,
	})
	capturedAt := now.UTC()
	return &mediaStub{content: content, descriptor: media.Descriptor{
		Schema: media.Schema, MediaRef: mediaRef, Kind: media.KindImage,
		Binding: media.Binding{
			TenantID: session.TenantID, SiteID: session.SiteID, SourceRef: "opaque-temporary-source",
			RunID: runID, StepID: stepID, Attempt: 1,
		},
		Encoding: media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 2, HeightPixels: 2},
		Temporal: media.Temporal{WindowStart: &capturedAt, WindowEnd: &capturedAt, SampleOrdinal: 0}, Integrity: media.Integrity{SHA256: testDigest(string(content)), SizeBytes: int64(len(content))},
		Governance: media.Governance{
			PrivacyClass: "internal", RetentionPolicyRef: "temporary-observation", Audience: []string{audience.Ref},
			ExpiresAt: now.Add(10 * time.Minute),
		},
		FrameMembers: []media.FrameMember{}, Availability: media.AvailabilityAvailable, CreatedAt: now,
	}}
}

func TestBackendIdempotentlyPlansAndBindsAuthenticatedRequest(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "backend.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	repository := &repositoryStub{}
	planner := &plannerStub{}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixture(t, state, planner, runner, repository, &mediaStub{}, stateTestTime)
	session := testSession()
	request := httpapi.InspectionRequest{Instruction: "看看入口现在是否拥堵", Context: []httpapi.BusinessContext{{Name: "关注点", Value: "人员通行"}}}

	first, created, err := backend.RequestInspection(context.Background(), session, request, "message-one")
	if err != nil || !created || first.Status != httpapi.RunAccepted || first.RunRef == repository.run.RunID {
		t.Fatalf("first RequestInspection()=%+v created=%v err=%v", first, created, err)
	}
	backend.newID = func(string) (string, error) { return "", errors.New("identity source unavailable") }
	second, created, err := backend.RequestInspection(context.Background(), session, request, "message-one")
	if err != nil || created || second != first || planner.calls != 1 || runner.calls != 1 {
		t.Fatalf("duplicate RequestInspection()=%+v created=%v planner=%d runner=%d err=%v", second, created, planner.calls, runner.calls, err)
	}
	conflict := request
	conflict.Instruction = "看看出口现在是否拥堵"
	if _, _, err := backend.RequestInspection(context.Background(), session, conflict, "message-one"); !errors.Is(err, httpapi.ErrConflict) {
		t.Fatalf("conflicting request error=%v", err)
	}
	otherChannel := session
	otherChannel.ConversationRef = "conversation-two"
	if _, err := backend.GetRun(context.Background(), otherChannel, first.RunRef); !errors.Is(err, httpapi.ErrNotFound) {
		t.Fatalf("cross-channel GetRun() error=%v", err)
	}

	states := []struct {
		state inspection.RunState
		want  httpapi.RunStatus
	}{
		{inspection.RunRunning, httpapi.RunWorking}, {inspection.RunReconciliationRequired, httpapi.RunWorking},
		{inspection.RunFinalizing, httpapi.RunWorking}, {inspection.RunCompleted, httpapi.RunReady},
		{inspection.RunPartial, httpapi.RunReady}, {inspection.RunBlocked, httpapi.RunUnable},
		{inspection.RunUnknown, httpapi.RunUnable}, {inspection.RunFailed, httpapi.RunUnable},
		{inspection.RunCancelled, httpapi.RunCancelled}, {inspection.RunExpired, httpapi.RunExpired},
	}
	for index, test := range states {
		repository.run.State = test.state
		repository.run.UpdatedAt = stateTestTime.Add(time.Duration(index+1) * time.Second)
		view, err := backend.GetRun(context.Background(), session, first.RunRef)
		if err != nil || view.Status != test.want || view.Message == "" {
			t.Fatalf("state %s view=%+v err=%v", test.state, view, err)
		}
	}
}

func TestBackendRejectsPlannerExecutionIdentityFromAnotherPrincipal(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "principal-rebind.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	repository := &repositoryStub{}
	planner := &plannerStub{principal: testDigest("another-principal")}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixture(t, state, planner, runner, repository, &mediaStub{}, stateTestTime)
	if _, _, err := backend.RequestInspection(context.Background(), testSession(), httpapi.InspectionRequest{Instruction: "查看入口"}, "principal-rebind"); !errors.Is(err, httpapi.ErrConflict) {
		t.Fatalf("cross-principal planner admission error=%v", err)
	}
	if planner.calls != 1 || runner.calls != 0 {
		t.Fatalf("cross-principal planner reached runtime planner=%d runner=%d", planner.calls, runner.calls)
	}
}

func TestBackendRejectsProtectedInputBeforeAnyStateWrite(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "protected-input.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	repository := &repositoryStub{}
	planner := &plannerStub{}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixture(t, state, planner, runner, repository, &mediaStub{}, stateTestTime)
	protected := []string{
		"查看 rtsp://camera.example/live", "密码 password=abc123", "设备地址 192.168.1.20:554",
		"camera_id=12", "token: abc123", "密码是门店编号", "请填写设备口令", "把令牌保存下来",
		"请关闭摄像头", "启用巡检任务", "创建一个巡检任务", "删除二号任务", "修改视频源",
	}
	for index, instruction := range protected {
		if _, _, err := backend.RequestInspection(context.Background(), testSession(), httpapi.InspectionRequest{Instruction: instruction}, "protected-"+string(rune('a'+index))); !errors.Is(err, httpapi.ErrInvalid) {
			t.Fatalf("protected instruction %q error=%v", instruction, err)
		}
	}
	for _, table := range []string{"channel_requests", "standard_decisions", "temporary_decisions", "channel_feedback", "media_capabilities"} {
		var rows int
		if err := state.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("protected input persisted table=%s rows=%d err=%v", table, rows, err)
		}
	}
	rawState, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, instruction := range protected {
		if bytes.Contains(rawState, []byte(instruction)) {
			t.Fatalf("protected input %q appeared in durable state bytes", instruction)
		}
	}
	if planner.calls != 0 || runner.calls != 0 {
		t.Fatalf("protected input reached planner=%d runner=%d", planner.calls, runner.calls)
	}
}

func TestBackendPersistsOnlySafeLocalInteraction(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "interaction-backend.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	interaction := httpapi.InteractionRequired{
		Title: "需要先完成现场接入", Message: "请在本机管理页面完成接入。", ActionLabel: "前往本机管理页面",
		Capability: "operator.onboarding", HandoffRef: "handoff-local-one",
	}
	planner := &plannerStub{interaction: &interaction}
	repository := &repositoryStub{}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixture(t, state, planner, runner, repository, &mediaStub{}, stateTestTime)
	session := testSession()
	request := httpapi.InspectionRequest{Instruction: "看看入口"}
	for attempt := 0; attempt < 2; attempt++ {
		_, _, err := backend.RequestInspection(context.Background(), session, request, "interaction-one")
		var interactionErr *httpapi.InteractionRequiredError
		if !errors.As(err, &interactionErr) || interactionErr.Interaction != interaction {
			t.Fatalf("attempt %d interaction error=%v", attempt, err)
		}
	}
	if planner.calls != 1 || runner.calls != 0 {
		t.Fatalf("interaction replay planner=%d runner=%d", planner.calls, runner.calls)
	}
	unsafe := interaction
	unsafe.Message = "请打开 https://device.invalid 完成接入"
	unsafePlanner := &plannerStub{interaction: &unsafe}
	unsafeBackend := newBackendFixture(t, state, unsafePlanner, runner, repository, &mediaStub{}, stateTestTime.Add(time.Minute))
	if _, _, err := unsafeBackend.RequestInspection(context.Background(), session, request, "interaction-unsafe"); err == nil || errors.As(err, new(*httpapi.InteractionRequiredError)) {
		t.Fatalf("unsafe interaction error=%v", err)
	}
}

func TestBackendResumesReservedRequestAfterRestartWithStableIdentity(t *testing.T) {
	ctx := context.Background()
	path := protectedStatePath(t, "restart-backend.db")
	state, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	session := testSession()
	request := httpapi.InspectionRequest{Instruction: "查看入口是否便于通行"}
	raw, digest, _ := canonicalRequest(request)
	if _, _, err := state.ReserveRequest(ctx, RequestReservation{
		Session: session, IdempotencyKey: "restart-one", RequestJSON: raw, RequestSHA256: digest,
		PublicRunRef: "run-before-restart", RuntimeRequestID: "request-before-restart", CreatedAt: stateTestTime,
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	repository := &repositoryStub{}
	planner := &plannerStub{}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixture(t, state, planner, runner, repository, &mediaStub{}, stateTestTime.Add(time.Minute))
	backend.newID = func(string) (string, error) { return "", errors.New("must not generate replacement identity") }
	view, created, err := backend.RequestInspection(ctx, session, request, "restart-one")
	if err != nil || !created || view.RunRef != "run-before-restart" || planner.last.RequestID != "request-before-restart" || !planner.last.RequestedAt.Equal(stateTestTime) {
		t.Fatalf("resumed request view=%+v created=%v planning=%+v err=%v", view, created, planner.last, err)
	}
}

func TestBackendReplaysFrozenDecisionAfterCrashBetweenSubmitAndBind(t *testing.T) {
	ctx := context.Background()
	path := protectedStatePath(t, "submit-bind-crash.db")
	state, err := OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	session := testSession()
	request := httpapi.InspectionRequest{Instruction: "查看入口是否便于通行"}
	repository := &repositoryStub{}
	firstPlanner := &plannerStub{}
	firstRunner := &runnerStub{repository: repository}
	backend := newBackendFixture(t, state, firstPlanner, panicAfterSubmitRunner{delegate: firstRunner}, repository, &mediaStub{}, stateTestTime)

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected simulated process crash after runtime submission")
			}
		}()
		_, _, _ = backend.RequestInspection(ctx, session, request, "submit-bind-crash")
	}()
	if repository.run.RunID == "" {
		t.Fatal("runtime submission did not create the durable run before the simulated crash")
	}
	internalRunID := repository.run.RunID
	var resolution string
	if err := state.db.QueryRow(`SELECT resolution FROM channel_requests WHERE idempotency_key='submit-bind-crash'`).Scan(&resolution); err != nil || resolution != string(requestStandardPending) {
		t.Fatalf("post-crash resolution=%q err=%v", resolution, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenState(testStateConfig(path))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	restartedPlanner := &plannerFailureStub{}
	restartedRunner := &runnerStub{repository: repository}
	restarted := newBackendFixture(t, state, restartedPlanner, restartedRunner, repository, &mediaStub{}, stateTestTime.Add(time.Minute))
	restarted.newID = func(string) (string, error) { return "", errors.New("replay must use persisted identities") }
	view, bound, err := restarted.RequestInspection(ctx, session, request, "submit-bind-crash")
	if err != nil || !bound || view.RunRef == internalRunID || restartedPlanner.calls != 0 || restartedRunner.calls != 1 {
		t.Fatalf("crash replay view=%+v bound=%v planner=%d runner=%d err=%v", view, bound, restartedPlanner.calls, restartedRunner.calls, err)
	}
	mapping, err := state.GetRunMapping(ctx, session, view.RunRef)
	if err != nil || mapping.InternalRunID != internalRunID {
		t.Fatalf("crash replay mapping=%+v err=%v want internal run %s", mapping, err, internalRunID)
	}
	var decisions int
	if err := state.db.QueryRow(`SELECT COUNT(*) FROM standard_decisions`).Scan(&decisions); err != nil || decisions != 1 {
		t.Fatalf("frozen decision rows=%d err=%v", decisions, err)
	}
}

func TestBackendClosesTemporaryObservationRunResultMediaAndDelivery(t *testing.T) {
	ctx := context.Background()
	state, err := OpenState(testStateConfig(protectedStatePath(t, "temporary-backend.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	mediaRef := "media_0123456789abcdef0123456789abcdef"
	content := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01, 0x02}
	digest := testDigest(string(content))
	mediaReader := temporaryMediaFixture(testSession(), mediaRef, fmt.Sprintf("request_%032x", 2), stateTestTime)
	candidateRaw, err := json.Marshal(temporary.Candidate{
		Schema: temporary.CandidateSchemaVersion, Summary: "主入口当前可见人员通行空间",
		VisibleFacts: []string{}, Limitations: []string{"画面无法反映入口外侧情况"},
		EvidenceRefs: []string{mediaRef},
	})
	if err != nil {
		t.Fatal(err)
	}
	harness := newTemporaryRuntimeHarness(t, mediaReader, stateTestTime, temporaryAnalyzerFunc(func(_ context.Context, request temporary.AnalysisRequest) ([]byte, error) {
		if request.Evidence.EvidenceRef != mediaRef || request.Prompt.Text == "" || request.RunID == "" {
			t.Fatalf("temporary analysis request is not bound: %+v", request)
		}
		return append([]byte(nil), candidateRaw...), nil
	}))
	defer harness.store.Close()
	spec, err := temporary.NewSpec(temporary.Intent{
		Subject: "入口", Region: "主入口", Observable: "当前是否便于人员通行", Locale: "zh-CN",
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	planner := &plannerStub{temporary: &TemporaryDecision{Spec: spec, DeadlineAt: stateTestTime.Add(5 * time.Minute)}}
	repository := &repositoryStub{}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixtureWithTemporary(t, state, planner, runner, repository, harness.manager, harness.manager, mediaReader, stateTestTime)
	session := testSession()
	request := httpapi.InspectionRequest{Instruction: "临时帮我看看入口是否方便通行"}
	accepted, created, err := backend.RequestInspection(ctx, session, request, "temporary-one")
	if err != nil || !created || accepted.Status != httpapi.RunAccepted {
		t.Fatalf("temporary RequestInspection()=%+v created=%v err=%v", accepted, created, err)
	}
	duplicate, created, err := backend.RequestInspection(ctx, session, request, "temporary-one")
	if err != nil || created || duplicate != accepted || planner.calls != 1 || runner.calls != 0 {
		t.Fatalf("temporary replay=%+v created=%v planner=%d standard=%d err=%v", duplicate, created, planner.calls, runner.calls, err)
	}
	conflict := request
	conflict.Instruction = "临时帮我看看出口是否方便通行"
	if _, _, err := backend.RequestInspection(ctx, session, conflict, "temporary-one"); !errors.Is(err, httpapi.ErrConflict) {
		t.Fatalf("temporary request conflict error=%v", err)
	}
	if terminal, ran, err := harness.manager.RunOnce(ctx, "temporary-worker", time.Minute); err != nil || !ran || terminal.State != temporary.StateSucceeded {
		t.Fatalf("temporary runtime terminal=%+v ran=%v err=%v", terminal, ran, err)
	}
	ready, err := backend.GetRun(ctx, session, accepted.RunRef)
	if err != nil || ready.Status != httpapi.RunReady || !strings.Contains(ready.Message, "已完成") {
		t.Fatalf("temporary GetRun()=%+v err=%v", ready, err)
	}
	result, err := backend.GetResult(ctx, session, accepted.RunRef)
	if err != nil || result.Summary != "主入口当前可见人员通行空间" || len(result.Sections) != 1 ||
		result.Sections[0].Details == nil || len(result.Sections[0].Details) != 0 || len(result.Sections[0].Evidence) != 1 {
		t.Fatalf("temporary GetResult()=%+v err=%v", result, err)
	}
	publicMediaRef := result.Sections[0].Evidence[0].MediaRef
	payload, err := backend.GetMedia(ctx, session, publicMediaRef)
	if err != nil || !bytes.Equal(payload.Bytes, content) || payload.SHA256 != digest {
		t.Fatalf("temporary GetMedia()=%+v err=%v", payload, err)
	}
	unauthorized := []struct {
		name    string
		session httpapi.SessionBinding
	}{
		{name: "tenant", session: session}, {name: "site", session: session}, {name: "channel", session: session},
		{name: "conversation", session: session}, {name: "recipient", session: session}, {name: "principal", session: session},
	}
	unauthorized[0].session.TenantID = "tenant-beta"
	unauthorized[1].session.SiteID = "site-south"
	unauthorized[2].session.Channel = "another_channel"
	unauthorized[3].session.ConversationRef = "conversation-two"
	unauthorized[4].session.RecipientRef = "recipient-two"
	unauthorized[5].session.PrincipalSHA256 = testDigest("another-principal")
	for _, other := range unauthorized {
		if _, err := backend.GetRun(ctx, other.session, accepted.RunRef); !errors.Is(err, httpapi.ErrNotFound) {
			t.Fatalf("cross-%s temporary GetRun() error=%v", other.name, err)
		}
		if _, err := backend.GetResult(ctx, other.session, accepted.RunRef); !errors.Is(err, httpapi.ErrNotFound) {
			t.Fatalf("cross-%s temporary GetResult() error=%v", other.name, err)
		}
		if _, err := backend.GetMedia(ctx, other.session, publicMediaRef); !errors.Is(err, httpapi.ErrNotFound) {
			t.Fatalf("cross-%s temporary GetMedia() error=%v", other.name, err)
		}
	}
	record, err := getRequestByKey(ctx, state.db, session, "temporary-one")
	if err != nil || record.Resolution != requestTemporaryBound || record.InternalRunID == "" {
		t.Fatalf("temporary mapping=%+v err=%v", record, err)
	}
	firstMessage, err := backend.BuildDeliveryMessage(ctx, record.InternalRunID)
	if err != nil {
		t.Fatal(err)
	}
	secondMessage, err := backend.BuildDeliveryMessage(ctx, record.InternalRunID)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(firstMessage)
	secondJSON, _ := json.Marshal(secondMessage)
	if !bytes.Equal(firstJSON, secondJSON) || len(firstMessage.Attachments) != 1 || firstMessage.RunRef != accepted.RunRef {
		t.Fatalf("temporary delivery replay first=%+v second=%+v", firstMessage, secondMessage)
	}
	for _, private := range []string{record.InternalRunID, record.RuntimeRequestID, mediaRef, "opaque-temporary-source", session.PrincipalSHA256} {
		if bytes.Contains(firstJSON, []byte(private)) {
			t.Fatalf("temporary delivery disclosed %q: %s", private, firstJSON)
		}
	}
	runJSON, _ := json.Marshal(ready)
	resultJSON, _ := json.Marshal(result)
	for label, payload := range map[string][]byte{"run": runJSON, "result": resultJSON, "delivery": firstJSON} {
		for _, private := range []string{
			record.InternalRunID, record.RuntimeRequestID, mediaRef, "opaque-temporary-source",
			temporary.CandidateSchemaVersion, "outcome_unknown", "temporary-capture", "你是 CosmoEdge Connect 的一次性视觉观察器",
		} {
			if bytes.Contains(payload, []byte(private)) {
				t.Fatalf("temporary %s projection disclosed %q: %s", label, private, payload)
			}
		}
		if bytes.Contains(payload, candidateRaw) {
			t.Fatalf("temporary %s projection disclosed raw analyzer output: %s", label, payload)
		}
	}
	rawState, err := os.ReadFile(state.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("你是 CosmoEdge Connect 的一次性视觉观察器"),
		[]byte(temporary.CandidateSchemaVersion), candidateRaw, []byte("rtsp://"), []byte("password="), []byte("token="),
	} {
		if bytes.Contains(rawState, forbidden) {
			t.Fatalf("application state persisted forbidden temporary value %q", forbidden)
		}
	}
	if !bytes.Contains(rawState, []byte("opaque-temporary-source")) || !bytes.Contains(rawState, []byte("snapshot-read")) {
		t.Fatal("application state did not persist the complete replayable temporary preparation request")
	}
}

func TestBackendReplaysFrozenTemporaryDecisionAfterCrashBetweenSubmitAndBind(t *testing.T) {
	ctx := context.Background()
	applicationPath := protectedStatePath(t, "temporary-submit-bind-crash.db")
	runtimePath := protectedStatePath(t, "temporary-submit-bind-runtime.db")
	state, err := OpenState(testStateConfig(applicationPath))
	if err != nil {
		t.Fatal(err)
	}
	runtimeStore, err := temporary.OpenSQLite(runtimePath)
	if err != nil {
		state.Close()
		t.Fatal(err)
	}
	session := testSession()
	mediaRef := "media_1123456789abcdef0123456789abcdef"
	mediaReader := temporaryMediaFixture(session, mediaRef, fmt.Sprintf("request_%032x", 2), stateTestTime)
	analyzer := temporaryAnalyzerFunc(func(context.Context, temporary.AnalysisRequest) ([]byte, error) {
		return nil, errors.New("analyzer must not run during submit replay")
	})
	runtimeManager, err := temporary.NewManager(runtimeStore, applicationPreparationFixture{mediaRef: mediaRef, now: stateTestTime}, temporaryMediaAdapter{media: mediaReader}, analyzer, func() time.Time { return stateTestTime })
	if err != nil {
		runtimeStore.Close()
		state.Close()
		t.Fatal(err)
	}
	decision := TemporaryDecision{Spec: temporarySpecFixture(t), DeadlineAt: stateTestTime.Add(5 * time.Minute)}
	planner := &plannerStub{temporary: &decision}
	standardRepository := &repositoryStub{}
	standardRunner := &runnerStub{repository: standardRepository}
	crashingRunner := &panicAfterTemporarySubmitRunner{delegate: runtimeManager}
	backend := newBackendFixtureWithTemporary(t, state, planner, standardRunner, standardRepository, crashingRunner, runtimeManager, mediaReader, stateTestTime)
	request := httpapi.InspectionRequest{Instruction: "临时查看入口是否方便通行"}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected simulated process crash after temporary runtime submission")
			}
		}()
		_, _, _ = backend.RequestInspection(ctx, session, request, "temporary-submit-bind-crash")
	}()
	if crashingRunner.submitted.RunID == "" {
		t.Fatal("temporary runtime submission was not durable before simulated crash")
	}
	internalRunID := crashingRunner.submitted.RunID
	pending, err := getRequestByKey(ctx, state.db, session, "temporary-submit-bind-crash")
	if err != nil || pending.Resolution != requestTemporaryPending || pending.InternalRunID != "" {
		t.Fatalf("temporary post-crash request=%+v err=%v", pending, err)
	}
	var decisions int
	if err := state.db.QueryRow(`SELECT COUNT(*) FROM temporary_decisions`).Scan(&decisions); err != nil || decisions != 1 {
		t.Fatalf("temporary frozen decisions=%d err=%v", decisions, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtimeStore.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenState(testStateConfig(applicationPath))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	runtimeStore, err = temporary.OpenSQLite(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeStore.Close()
	runtimeManager, err = temporary.NewManager(runtimeStore, applicationPreparationFixture{mediaRef: mediaRef, now: stateTestTime}, temporaryMediaAdapter{media: mediaReader}, analyzer, func() time.Time {
		return stateTestTime.Add(time.Minute)
	})
	if err != nil {
		t.Fatal(err)
	}
	restartedPlanner := &plannerFailureStub{}
	restartedStandardRunner := &runnerStub{repository: standardRepository}
	restarted := newBackendFixtureWithTemporary(t, state, restartedPlanner, restartedStandardRunner, standardRepository, runtimeManager, runtimeManager, mediaReader, stateTestTime.Add(time.Minute))
	restarted.newID = func(string) (string, error) { return "", errors.New("replay must use persisted identities") }
	view, bound, err := restarted.RequestInspection(ctx, session, request, "temporary-submit-bind-crash")
	if err != nil || !bound || view.RunRef == internalRunID || restartedPlanner.calls != 0 || restartedStandardRunner.calls != 0 {
		t.Fatalf("temporary crash replay view=%+v bound=%v planner=%d standard=%d err=%v", view, bound, restartedPlanner.calls, restartedStandardRunner.calls, err)
	}
	mapping, err := state.GetRunMapping(ctx, session, view.RunRef)
	if err != nil || mapping.InternalRunID != internalRunID || mapping.Resolution != requestTemporaryBound {
		t.Fatalf("temporary replay mapping=%+v err=%v want run %s", mapping, err, internalRunID)
	}
	if err := state.db.QueryRow(`SELECT COUNT(*) FROM temporary_decisions`).Scan(&decisions); err != nil || decisions != 1 {
		t.Fatalf("temporary replay decision rows=%d err=%v", decisions, err)
	}
}

func TestBackendFreezesTemporaryDecisionBeforeRetryablePreparationRegistration(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	applicationPath := filepath.Join(root, "application.db")
	preparationPath := filepath.Join(root, "preparations.db")
	runtimePath := filepath.Join(root, "runtime.db")
	state, err := OpenState(testStateConfig(applicationPath))
	if err != nil {
		t.Fatal(err)
	}
	preparationManager, err := mediaprep.Open(mediaprep.Config{
		Path: preparationPath, Owner: "registration-worker", Acquirer: applicationPreparationAcquirer{},
		Publisher: applicationPreparationPublisher{}, Now: func() time.Time { return stateTestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeStore, err := temporary.OpenSQLite(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	session := testSession()
	mediaRef := "media_4123456789abcdef0123456789abcdef"
	mediaReader := temporaryMediaFixture(session, mediaRef, fmt.Sprintf("request_%032x", 2), stateTestTime)
	runtimeManager, err := temporary.NewManager(runtimeStore, preparationManager, temporaryMediaAdapter{media: mediaReader},
		temporaryAnalyzerFunc(func(context.Context, temporary.AnalysisRequest) ([]byte, error) {
			return nil, errors.New("analysis is outside registration replay")
		}), func() time.Time { return stateTestTime })
	if err != nil {
		t.Fatal(err)
	}
	planner := &plannerStub{temporary: &TemporaryDecision{Spec: temporarySpecFixture(t), DeadlineAt: stateTestTime.Add(5 * time.Minute)}}
	registrar := &durableReplyLossRegistrar{manager: preparationManager, failOnce: true}
	repository := &repositoryStub{}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixtureWithRegistrar(t, state, planner, runner, repository, runtimeManager, runtimeManager,
		registrar, mediaReader, stateTestTime)
	request := httpapi.InspectionRequest{Instruction: "临时查看入口"}
	if _, _, err := backend.RequestInspection(ctx, session, request, "temporary-prepare-reply-loss"); err == nil {
		t.Fatal("lost registration reply was reported as success")
	}
	pending, err := getRequestByKey(ctx, state.db, session, "temporary-prepare-reply-loss")
	if err != nil || pending.Resolution != requestTemporaryPending {
		t.Fatalf("post-registration pending request=%+v err=%v", pending, err)
	}
	if _, err := state.GetTemporaryDecision(ctx, session, pending.PublicRunRef); err != nil {
		t.Fatalf("complete frozen decision was not durable before registration: %v", err)
	}
	runID, err := temporary.RunIDForScope(session.TenantID, session.SiteID, pending.RuntimeRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeManager.Get(ctx, runID); !errors.Is(err, temporary.ErrRuntimeNotFound) {
		t.Fatalf("runtime was submitted after lost preparation reply: %v", err)
	}
	preparationBeforeRestart, err := preparationManager.GetByScope(ctx, session.TenantID, session.SiteID, pending.RuntimeRequestID)
	if err != nil || preparationBeforeRestart.State != mediaprep.StatePrepared || len(registrar.created) != 1 || !registrar.created[0] {
		t.Fatalf("durable preparation before restart=%+v created=%v err=%v", preparationBeforeRestart, registrar.created, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtimeStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := preparationManager.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenState(testStateConfig(applicationPath))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	preparationManager, err = mediaprep.Open(mediaprep.Config{
		Path: preparationPath, Owner: "registration-worker-restart", Acquirer: applicationPreparationAcquirer{},
		Publisher: applicationPreparationPublisher{}, Now: func() time.Time { return stateTestTime.Add(time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer preparationManager.Close()
	runtimeStore, err = temporary.OpenSQLite(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeStore.Close()
	runtimeManager, err = temporary.NewManager(runtimeStore, preparationManager, temporaryMediaAdapter{media: mediaReader},
		temporaryAnalyzerFunc(func(context.Context, temporary.AnalysisRequest) ([]byte, error) {
			return nil, errors.New("analysis is outside registration replay")
		}), func() time.Time { return stateTestTime.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	restartedPlanner := &plannerFailureStub{}
	restartedRegistrar := &durableReplyLossRegistrar{manager: preparationManager}
	restarted := newBackendFixtureWithRegistrar(t, state, restartedPlanner, runner, repository, runtimeManager, runtimeManager,
		restartedRegistrar, mediaReader, stateTestTime.Add(time.Second))
	restarted.newID = func(string) (string, error) { return "", errors.New("restart must reuse persisted request identities") }
	view, created, err := restarted.RequestInspection(ctx, session, request, "temporary-prepare-reply-loss")
	if err != nil || !created || restartedPlanner.calls != 0 || planner.calls != 1 || planner.temporaryCompileCalls != 1 {
		t.Fatalf("preparation replay view=%+v created=%v original-planner=%d compiler=%d restarted-planner=%d err=%v",
			view, created, planner.calls, planner.temporaryCompileCalls, restartedPlanner.calls, err)
	}
	if len(registrar.requests) != 1 || len(restartedRegistrar.requests) != 1 ||
		!reflect.DeepEqual(registrar.requests[0], restartedRegistrar.requests[0]) ||
		len(restartedRegistrar.created) != 1 || restartedRegistrar.created[0] {
		t.Fatalf("registration replay changed frozen request or recreated preparation: before=%#v after=%#v created=%v",
			registrar.requests, restartedRegistrar.requests, restartedRegistrar.created)
	}
	if run, err := runtimeManager.Get(ctx, runID); err != nil || run.RunID != runID {
		t.Fatalf("replayed registration did not continue to runtime submit: run=%+v err=%v", run, err)
	}
	preparationAfterRestart, err := preparationManager.GetByScope(ctx, session.TenantID, session.SiteID, pending.RuntimeRequestID)
	if err != nil || preparationAfterRestart.PreparationRef != preparationBeforeRestart.PreparationRef ||
		preparationAfterRestart.State != preparationBeforeRestart.State || !preparationAfterRestart.CreatedAt.Equal(preparationBeforeRestart.CreatedAt) {
		t.Fatalf("preparation changed across restart: before=%+v after=%+v err=%v", preparationBeforeRestart, preparationAfterRestart, err)
	}
}

func TestBackendRejectsMalformedPreparationReceiptBeforeRuntimeSubmit(t *testing.T) {
	ctx := context.Background()
	state, err := OpenState(testStateConfig(protectedStatePath(t, "temporary-malformed-registration.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	runtimeStore, err := temporary.OpenSQLite(protectedStatePath(t, "temporary-malformed-registration-runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer runtimeStore.Close()
	session := testSession()
	mediaRef := "media_5123456789abcdef0123456789abcdef"
	mediaReader := temporaryMediaFixture(session, mediaRef, fmt.Sprintf("request_%032x", 2), stateTestTime)
	runtimeManager, err := temporary.NewManager(runtimeStore,
		applicationPreparationFixture{mediaRef: mediaRef, now: stateTestTime}, temporaryMediaAdapter{media: mediaReader},
		temporaryAnalyzerFunc(func(context.Context, temporary.AnalysisRequest) ([]byte, error) {
			t.Fatal("malformed registration reached analysis")
			return nil, nil
		}), func() time.Time { return stateTestTime })
	if err != nil {
		t.Fatal(err)
	}
	planner := &plannerStub{temporary: &TemporaryDecision{Spec: temporarySpecFixture(t), DeadlineAt: stateTestTime.Add(5 * time.Minute)}}
	registrar := &applicationRegistrarFixture{now: stateTestTime, mutateStatus: func(status *mediaprep.Status) {
		status.AvailableAt = status.CreatedAt.Add(-time.Nanosecond)
	}}
	repository := &repositoryStub{}
	backend := newBackendFixtureWithRegistrar(t, state, planner, &runnerStub{repository: repository}, repository,
		runtimeManager, runtimeManager, registrar, mediaReader, stateTestTime)
	if _, _, err := backend.RequestInspection(ctx, session, httpapi.InspectionRequest{Instruction: "临时查看入口"}, "temporary-malformed-registration"); err == nil {
		t.Fatal("malformed durable registration receipt was accepted")
	}
	pending, err := getRequestByKey(ctx, state.db, session, "temporary-malformed-registration")
	if err != nil || pending.Resolution != requestTemporaryPending || planner.calls != 1 || planner.temporaryCompileCalls != 1 {
		t.Fatalf("pending=%+v planner=%d compiler=%d err=%v", pending, planner.calls, planner.temporaryCompileCalls, err)
	}
	runID, err := temporary.RunIDForScope(session.TenantID, session.SiteID, pending.RuntimeRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeManager.Get(ctx, runID); !errors.Is(err, temporary.ErrRuntimeNotFound) {
		t.Fatalf("malformed registration advanced runtime: %v", err)
	}
}

func TestBackendProjectsTemporaryOutcomeUnknownWithoutReplayOrTechnicalLeak(t *testing.T) {
	ctx := context.Background()
	state, err := OpenState(testStateConfig(protectedStatePath(t, "temporary-outcome-unknown.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	session := testSession()
	mediaRef := "media_2123456789abcdef0123456789abcdef"
	mediaReader := temporaryMediaFixture(session, mediaRef, fmt.Sprintf("request_%032x", 2), stateTestTime)
	analyzerCalls := 0
	harness := newTemporaryRuntimeHarness(t, mediaReader, stateTestTime, temporaryAnalyzerFunc(func(context.Context, temporary.AnalysisRequest) ([]byte, error) {
		analyzerCalls++
		return nil, errors.New("transport ended without a receipt")
	}))
	defer harness.store.Close()
	planner := &plannerStub{temporary: &TemporaryDecision{
		Spec: temporarySpecFixture(t), DeadlineAt: stateTestTime.Add(5 * time.Minute),
	}}
	standardRepository := &repositoryStub{}
	standardRunner := &runnerStub{repository: standardRepository}
	backend := newBackendFixtureWithTemporary(t, state, planner, standardRunner, standardRepository, harness.manager, harness.manager, mediaReader, stateTestTime)
	accepted, _, err := backend.RequestInspection(ctx, session, httpapi.InspectionRequest{Instruction: "临时查看入口"}, "temporary-unknown")
	if err != nil {
		t.Fatal(err)
	}
	terminal, ran, err := harness.manager.RunOnce(ctx, "temporary-worker", time.Minute)
	if err != nil || !ran || terminal.State != temporary.StateOutcomeUnknown || analyzerCalls != 1 {
		t.Fatalf("temporary unknown terminal=%+v ran=%v calls=%d err=%v", terminal, ran, analyzerCalls, err)
	}
	if _, ran, err := harness.manager.RunOnce(ctx, "temporary-worker", time.Minute); err != nil || ran || analyzerCalls != 1 {
		t.Fatalf("temporary unknown replayed ran=%v calls=%d err=%v", ran, analyzerCalls, err)
	}
	run, err := backend.GetRun(ctx, session, accepted.RunRef)
	if err != nil || run.Status != httpapi.RunUnable || run.Message != "现场查看的执行结果暂时无法确认" {
		t.Fatalf("temporary unknown run=%+v err=%v", run, err)
	}
	result, err := backend.GetResult(ctx, session, accepted.RunRef)
	if err != nil || result.Summary != "本次现场查看的执行结果暂时无法确认。" || len(result.Sections) != 0 || len(result.Limitations) != 1 {
		t.Fatalf("temporary unknown result=%+v err=%v", result, err)
	}
	message, err := backend.BuildDeliveryMessage(ctx, terminal.RunID)
	if err != nil || len(message.Attachments) != 0 {
		t.Fatalf("temporary unknown delivery=%+v err=%v", message, err)
	}
	publicJSON, _ := json.Marshal(struct {
		Run      httpapi.RunView
		Result   httpapi.ResultView
		Delivery delivery.Message
	}{run, result, message})
	for _, forbidden := range []string{"outcome_unknown", "analysis_outcome_unknown", "transport ended", terminal.RunID, mediaRef} {
		if bytes.Contains(publicJSON, []byte(forbidden)) {
			t.Fatalf("temporary unknown projection disclosed %q: %s", forbidden, publicJSON)
		}
	}
}

func TestBackendProjectsExpiredTemporaryObservationHonestly(t *testing.T) {
	ctx := context.Background()
	state, err := OpenState(testStateConfig(protectedStatePath(t, "temporary-expired.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	session := testSession()
	mediaRef := "media_3123456789abcdef0123456789abcdef"
	mediaReader := temporaryMediaFixture(session, mediaRef, fmt.Sprintf("request_%032x", 2), stateTestTime)
	current := stateTestTime
	harness := newTemporaryRuntimeHarnessWithClock(t, mediaReader, func() time.Time { return current }, temporaryAnalyzerFunc(func(context.Context, temporary.AnalysisRequest) ([]byte, error) {
		t.Fatal("expired temporary observation invoked the analyzer")
		return nil, nil
	}))
	defer harness.store.Close()
	deadline := stateTestTime.Add(time.Minute)
	planner := &plannerStub{temporary: &TemporaryDecision{
		Spec: temporarySpecFixture(t), DeadlineAt: deadline,
	}}
	standardRepository := &repositoryStub{}
	standardRunner := &runnerStub{repository: standardRepository}
	backend := newBackendFixtureWithTemporary(t, state, planner, standardRunner, standardRepository, harness.manager, harness.manager, mediaReader, current)
	backend.now = func() time.Time { return current }
	accepted, _, err := backend.RequestInspection(ctx, session, httpapi.InspectionRequest{Instruction: "临时查看入口"}, "temporary-expired")
	if err != nil {
		t.Fatal(err)
	}
	current = deadline
	if recovered, err := harness.manager.Recover(ctx); err != nil || recovered != 1 {
		t.Fatalf("temporary expiry recovery=%d err=%v", recovered, err)
	}
	run, err := backend.GetRun(ctx, session, accepted.RunRef)
	if err != nil || run.Status != httpapi.RunExpired || run.Message != "现场查看请求已过期" {
		t.Fatalf("temporary expired run=%+v err=%v", run, err)
	}
	result, err := backend.GetResult(ctx, session, accepted.RunRef)
	if err != nil || result.Summary != "本次现场查看已过期。" || len(result.Sections) != 0 || len(result.Limitations) != 1 {
		t.Fatalf("temporary expired result=%+v err=%v", result, err)
	}
	publicJSON, _ := json.Marshal(struct {
		Run    httpapi.RunView
		Result httpapi.ResultView
	}{run, result})
	for _, forbidden := range []string{"deadline_expired", mediaRef} {
		if bytes.Contains(publicJSON, []byte(forbidden)) {
			t.Fatalf("temporary expired projection disclosed %q: %s", forbidden, publicJSON)
		}
	}
}

func TestBackendFeedbackAndMediaRemainSessionBoundAndIntegrityChecked(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "media-backend.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	repository := &repositoryStub{}
	planner := &plannerStub{}
	runner := &runnerStub{repository: repository}
	content := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01, 0x02}
	mediaReader := &mediaStub{content: content}
	backend := newBackendFixture(t, state, planner, runner, repository, mediaReader, stateTestTime)
	session := testSession()
	runView, _, err := backend.RequestInspection(context.Background(), session, httpapi.InspectionRequest{Instruction: "查看入口"}, "media-run")
	if err != nil {
		t.Fatal(err)
	}
	digest := testDigest(string(content))
	mediaReader.descriptor = media.Descriptor{
		Schema: media.Schema, MediaRef: "internal-image-one", Kind: media.KindImage,
		Binding:  media.Binding{TenantID: session.TenantID, SiteID: session.SiteID, SourceRef: "opaque-source", RunID: repository.run.RunID, StepID: "opaque-step", Attempt: 1},
		Encoding: media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 2, HeightPixels: 2},
		Temporal: media.Temporal{SampleOrdinal: 1}, Integrity: media.Integrity{SHA256: digest, SizeBytes: int64(len(content))},
		Governance:   media.Governance{PrivacyClass: "internal", RetentionPolicyRef: "short-lived", Audience: []string{"run-owner"}, ExpiresAt: stateTestTime.Add(time.Hour)},
		FrameMembers: []media.FrameMember{}, Availability: media.AvailabilityAvailable, CreatedAt: stateTestTime,
	}
	capability, include, err := backend.issueMediaCapability(context.Background(), session, mustRunMapping(t, state, session, runView.RunRef).PublicRunRef, repository.run, ProjectionEvidence{
		InternalMediaRef: mediaReader.descriptor.MediaRef, ExpectedSHA256: digest, Title: "入口现场快照",
	})
	if err != nil || !include || capability.MediaRef == mediaReader.descriptor.MediaRef {
		t.Fatalf("issueMediaCapability()=%+v include=%v err=%v", capability, include, err)
	}
	payload, err := backend.GetMedia(context.Background(), session, capability.MediaRef)
	if err != nil || !bytes.Equal(payload.Bytes, content) || payload.SHA256 != digest {
		t.Fatalf("GetMedia() payload=%+v err=%v", payload, err)
	}
	other := session
	other.ConversationRef = "conversation-two"
	if _, err := backend.GetMedia(context.Background(), other, capability.MediaRef); !errors.Is(err, httpapi.ErrNotFound) {
		t.Fatalf("cross-session GetMedia() error=%v", err)
	}
	mediaReader.content = append([]byte(nil), content...)
	mediaReader.content[len(mediaReader.content)-1] ^= 0xff
	if _, err := backend.GetMedia(context.Background(), session, capability.MediaRef); err == nil {
		t.Fatal("GetMedia() accepted tampered media content")
	}

	helpful := true
	receipt, created, err := backend.SubmitFeedback(context.Background(), session, runView.RunRef, httpapi.FeedbackRequest{Helpful: &helpful, Comment: "有帮助"}, "feedback-one")
	if err != nil || !created || !receipt.Accepted {
		t.Fatalf("SubmitFeedback()=%+v created=%v err=%v", receipt, created, err)
	}
	if _, created, err := backend.SubmitFeedback(context.Background(), session, runView.RunRef, httpapi.FeedbackRequest{Helpful: &helpful, Comment: "有帮助"}, "feedback-one"); err != nil || created {
		t.Fatalf("duplicate feedback created=%v err=%v", created, err)
	}
	helpful = false
	if _, _, err := backend.SubmitFeedback(context.Background(), session, runView.RunRef, httpapi.FeedbackRequest{Helpful: &helpful, Comment: "没有帮助"}, "feedback-one"); !errors.Is(err, httpapi.ErrConflict) {
		t.Fatalf("conflicting feedback error=%v", err)
	}
}

func TestBackendBuildDeliveryMessageIsAudienceBoundStableAndPublicOnly(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "delivery-backend.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	repository := &repositoryStub{}
	planner := &plannerStub{}
	runner := &runnerStub{repository: repository}
	content := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01, 0x02}
	mediaReader := &mediaStub{content: content}
	backend := newBackendFixture(t, state, planner, runner, repository, mediaReader, stateTestTime)
	session := testSession()
	runView, _, err := backend.RequestInspection(context.Background(), session, httpapi.InspectionRequest{Instruction: "查看入口通行情况"}, "delivery-run")
	if err != nil {
		t.Fatal(err)
	}
	mediaRef := "internal-image-delivery"
	digest := testDigest(string(content))
	completeRepositoryWithImage(t, repository, mediaRef, digest)
	mediaReader.descriptor = media.Descriptor{
		Schema: media.Schema, MediaRef: mediaRef, Kind: media.KindImage,
		Binding: media.Binding{
			TenantID: session.TenantID, SiteID: session.SiteID, SourceRef: "opaque-entrance-source",
			RunID: repository.run.RunID, StepID: resultValidationStep(t, repository.plan).StepID, Attempt: 1,
		},
		Encoding: media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 2, HeightPixels: 2},
		Temporal: media.Temporal{SampleOrdinal: 1}, Integrity: media.Integrity{SHA256: digest, SizeBytes: int64(len(content))},
		Governance: media.Governance{
			PrivacyClass: "internal", RetentionPolicyRef: "short-lived", Audience: []string{"run-owner"}, ExpiresAt: stateTestTime.Add(time.Hour),
		},
		FrameMembers: []media.FrameMember{}, Availability: media.AvailabilityAvailable, CreatedAt: stateTestTime,
	}

	first, err := backend.BuildDeliveryMessage(context.Background(), repository.run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := backend.BuildDeliveryMessage(context.Background(), repository.run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) || first.Audience != (delivery.Audience{
		TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
	}) || first.RunRef != runView.RunRef || len(first.Attachments) != 1 {
		t.Fatalf("delivery messages first=%+v second=%+v", first, second)
	}
	for _, protected := range []string{repository.run.RunID, mediaRef, "opaque-entrance-source", session.PrincipalSHA256} {
		if bytes.Contains(firstJSON, []byte(protected)) {
			t.Fatalf("delivery payload disclosed protected reference %q: %s", protected, firstJSON)
		}
	}
	payload, err := backend.GetMedia(context.Background(), session, first.Attachments[0].MediaRef)
	if err != nil || !bytes.Equal(payload.Bytes, content) || payload.SHA256 != digest {
		t.Fatalf("delivered media payload=%+v err=%v", payload, err)
	}
	other := session
	other.RecipientRef = "recipient-two"
	if _, err := backend.GetMedia(context.Background(), other, first.Attachments[0].MediaRef); !errors.Is(err, httpapi.ErrNotFound) {
		t.Fatalf("cross-audience delivered media error=%v", err)
	}
	other = session
	other.PrincipalSHA256 = testDigest("another-delivery-principal")
	if _, err := backend.GetResult(context.Background(), other, runView.RunRef); !errors.Is(err, httpapi.ErrNotFound) {
		t.Fatalf("cross-principal delivered result error=%v", err)
	}
	if _, err := backend.GetMedia(context.Background(), other, first.Attachments[0].MediaRef); !errors.Is(err, httpapi.ErrNotFound) {
		t.Fatalf("cross-principal delivered media error=%v", err)
	}
}

func TestScheduledOriginUsesSameSafeProjectionAndExactOnceDeliveryIdentity(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "scheduled-delivery-backend.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	session := testSession()
	template, assignment := genericCatalogFixture(session)
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: session.TenantID, SiteID: session.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision,
		AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		Origin: inspection.OriginSchedule, RequestID: "scheduled-request-main", Variables: map[string]string{"focus": "entrance"},
		RequestedAt: stateTestTime, Deadline: stateTestTime.Add(5 * time.Minute),
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	audience := delivery.Audience{TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef}
	audienceSHA, err := audience.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	internalRunID := "runtime-scheduled-main"
	publicRunRef := "scheduled-public-main"
	decision, created, err := state.FreezeScheduledDecision(context.Background(), ScheduledDecisionRecord{
		Session: session, PublicRunRef: publicRunRef, InternalRunID: internalRunID,
		OccurrenceID: "occurrence-scheduled-main", SubmissionRef: "submission-scheduled-main",
		BindingRef: "binding-main", BindingRevision: 1, AudienceSHA256: audienceSHA,
		DeliverySHA256: testDigest("delivery-binding-main"), ServicePrincipalSHA256: testDigest("service-principal-main"),
		OccurrenceSHA256: testDigest("occurrence-main"), RequestSHA256: testDigest(string(requestJSON)), PlanSHA256: plan.PlanSHA256,
		Template: template, Assignment: assignment, RunRequest: request, CreatedAt: stateTestTime,
	})
	if err != nil || !created || decision.InternalRunID != internalRunID {
		t.Fatalf("FreezeScheduledDecision()=%+v created=%v err=%v", decision, created, err)
	}
	repository := &repositoryStub{plan: plan, run: inspection.Run{
		RunID: internalRunID, TenantID: session.TenantID, SiteID: session.SiteID, RequestKey: plan.RequestKey,
		PlanSHA256: plan.PlanSHA256, State: inspection.RunQueued, Reason: "plan_admitted", Deadline: plan.Deadline,
		CreatedAt: request.RequestedAt, UpdatedAt: request.RequestedAt,
	}}
	content := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01, 0x02}
	mediaReader := &mediaStub{content: content}
	backend := newBackendFixture(t, state, &plannerFailureStub{}, &runnerStub{repository: repository}, repository, mediaReader, stateTestTime)
	mediaRef := "internal-image-scheduled-delivery"
	digest := testDigest(string(content))
	completeRepositoryWithImage(t, repository, mediaRef, digest)
	mediaReader.descriptor = media.Descriptor{
		Schema: media.Schema, MediaRef: mediaRef, Kind: media.KindImage,
		Binding: media.Binding{TenantID: session.TenantID, SiteID: session.SiteID, SourceRef: "opaque-entrance-source",
			RunID: internalRunID, StepID: resultValidationStep(t, plan).StepID, Attempt: 1},
		Encoding: media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 2, HeightPixels: 2},
		Temporal: media.Temporal{SampleOrdinal: 1}, Integrity: media.Integrity{SHA256: digest, SizeBytes: int64(len(content))},
		Governance: media.Governance{PrivacyClass: "internal", RetentionPolicyRef: "short-lived", Audience: []string{"run-owner"},
			ExpiresAt: stateTestTime.Add(time.Hour)}, FrameMembers: []media.FrameMember{},
		Availability: media.AvailabilityAvailable, CreatedAt: stateTestTime,
	}
	view, err := backend.GetRun(context.Background(), session, publicRunRef)
	if err != nil || view.RunRef != publicRunRef || view.RunRef == internalRunID {
		t.Fatalf("GetRun()=%+v err=%v", view, err)
	}
	result, err := backend.GetResult(context.Background(), session, publicRunRef)
	if err != nil || result.RunRef != publicRunRef || len(result.Sections) == 0 {
		t.Fatalf("GetResult()=%+v err=%v", result, err)
	}
	first, err := backend.BuildDeliveryMessage(context.Background(), internalRunID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := backend.BuildDeliveryMessage(context.Background(), internalRunID)
	if err != nil {
		t.Fatal(err)
	}
	wantResultRef, _ := delivery.ResultRefForRun(publicRunRef)
	if !reflect.DeepEqual(first, second) || first.RunRef != publicRunRef || first.ResultRef != wantResultRef || first.Audience != audience {
		t.Fatalf("scheduled messages first=%+v second=%+v", first, second)
	}
	deliveries := delivery.NewMemoryStore()
	firstRecord, err := deliveries.Enqueue(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, err := deliveries.Enqueue(context.Background(), second)
	if err != nil || firstRecord.Message.DeliveryID != secondRecord.Message.DeliveryID || secondRecord.Attempts != 0 {
		t.Fatalf("exact-once enqueue first=%+v second=%+v err=%v", firstRecord, secondRecord, err)
	}
	other := session
	other.PrincipalSHA256 = testDigest("substituted-delivery-principal")
	if _, err := backend.GetResult(context.Background(), other, publicRunRef); !errors.Is(err, httpapi.ErrNotFound) {
		t.Fatalf("substituted principal GetResult err=%v", err)
	}
	messageJSON, _ := json.Marshal(first)
	for _, protected := range []string{internalRunID, mediaRef, session.PrincipalSHA256, "opaque-entrance-source"} {
		if bytes.Contains(messageJSON, []byte(protected)) {
			t.Fatalf("scheduled delivery disclosed protected value %q: %s", protected, messageJSON)
		}
	}
}

func TestBackendResultProjectionNeverUsesRuntimeConclusionOrReason(t *testing.T) {
	state, err := OpenState(testStateConfig(protectedStatePath(t, "result-backend.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	repository := &repositoryStub{}
	planner := &plannerStub{}
	runner := &runnerStub{repository: repository}
	backend := newBackendFixture(t, state, planner, runner, repository, &mediaStub{}, stateTestTime)
	session := testSession()
	runView, _, err := backend.RequestInspection(context.Background(), session, httpapi.InspectionRequest{Instruction: "查看入口"}, "result-run")
	if err != nil {
		t.Fatal(err)
	}
	repository.run.State = inspection.RunFailed
	repository.run.Conclusion = "raw model output token=https://secret.invalid"
	repository.run.Reason = "adapter_internal_failure"
	repository.run.UpdatedAt = stateTestTime.Add(time.Minute)
	repository.outcome = inspection.Outcome{
		State: inspection.RunFailed, OverallAssessment: inspection.AssessmentUncertain,
		Coverage:   inspection.Coverage{Required: 1, Missing: 1, Ratio: 0},
		Conclusion: repository.run.Conclusion, Reason: repository.run.Reason,
	}
	repository.present = true
	result, err := backend.GetResult(context.Background(), session, runView.RunRef)
	if err != nil {
		t.Fatal(err)
	}
	rendered := result.Summary + strings.Join(result.Limitations, " ")
	if strings.Contains(rendered, "secret.invalid") || strings.Contains(rendered, "adapter_internal_failure") || len(result.Sections) != 0 {
		t.Fatalf("unsafe terminal result projection=%+v", result)
	}
}

func TestBusinessResultProjectorRejectsProtectedTypedText(t *testing.T) {
	value := inspection.ResultValue{Kind: inspection.ResultClassification, Classification: &inspection.ClassificationValue{Label: "https://internal.invalid"}}
	if _, include := sanitizeProjectionValue(value); include {
		t.Fatal("sanitizeProjectionValue accepted protected typed text")
	}
	projection, err := NewBusinessResultProjector().Project(context.Background(), ProjectionInput{
		OverallAssessment: inspection.AssessmentMeetsRule, Coverage: inspection.Coverage{Required: 1, Conclusive: 1, Ratio: 1},
		CompletedAt: stateTestTime, Findings: []ProjectionFindingInput{{TargetTitle: "入口", CriterionTitle: "通行情况", Assessment: inspection.AssessmentMeetsRule}},
	})
	if err != nil || strings.Contains(strings.ToLower(projection.Summary), "completed") {
		t.Fatalf("business projection=%+v err=%v", projection, err)
	}
}

func newBackendFixture(t *testing.T, state *StateStore, planner RequestPlanner, runner Runner, repository Repository, mediaReader MediaReader, now time.Time) *Backend {
	return newBackendFixtureWithTemporary(t, state, planner, runner, repository, temporaryRuntimeUnavailableStub{}, temporaryRuntimeUnavailableStub{}, mediaReader, now)
}

func newBackendFixtureWithTemporary(t *testing.T, state *StateStore, planner RequestPlanner, runner Runner, repository Repository,
	temporaryRunner TemporaryRunner, temporaryRepository TemporaryRepository, mediaReader MediaReader, now time.Time) *Backend {
	return newBackendFixtureWithRegistrar(t, state, planner, runner, repository, temporaryRunner, temporaryRepository,
		&applicationRegistrarFixture{now: now}, mediaReader, now)
}

func newBackendFixtureWithRegistrar(t *testing.T, state *StateStore, planner RequestPlanner, runner Runner, repository Repository,
	temporaryRunner TemporaryRunner, temporaryRepository TemporaryRepository, registrar TemporaryMediaRegistrar,
	mediaReader MediaReader, now time.Time) *Backend {
	t.Helper()
	sequence := 0
	backend, err := New(Config{
		Capabilities: capabilityStub{}, Planner: planner, Runner: runner, Repository: repository,
		TemporaryRunner: temporaryRunner, TemporaryRepository: temporaryRepository, TemporaryMedia: registrar,
		InstalledTasks: taskValidatorStub{}, Projector: NewBusinessResultProjector(), Media: mediaReader, State: state,
		Now: func() time.Time { return now }, NewID: func(prefix string) (string, error) {
			sequence++
			return fmt.Sprintf("%s_%032x", prefix, sequence), nil
		}, MediaCapabilityTTL: 10 * time.Minute, MediaAudience: "run-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func completeRepositoryWithImage(t *testing.T, repository *repositoryStub, mediaRef, digest string) {
	t.Helper()
	step := resultValidationStep(t, repository.plan)
	capturedAt := repository.plan.RequestedAt.Add(30 * time.Second)
	result := inspection.AnalysisResult{
		Binding: inspection.ResultBinding{
			ResultID: "result-delivery", RunID: repository.run.RunID, StepID: step.StepID,
			TargetID: step.TargetID, CriterionID: step.CriterionID, CriterionVersion: "1",
			OutputKind: inspection.ResultClassification, OutputSchemaVersion: "classification.v2", Usage: inspection.ResultUsageInspection,
			TimeWindow: inspection.ResultTimeWindow{StartAt: capturedAt, EndAt: capturedAt},
			SourceMedia: []inspection.ResultSourceMedia{{
				SourceRef: "opaque-entrance-source", MediaRef: mediaRef, SHA256: digest,
				CapturedAt: capturedAt, FreshnessMS: 1000, SampleOrdinal: 1,
			}},
		},
		Assessment: inspection.AssessmentMeetsRule, Observability: inspection.ResultFullyVisible,
		Value:        &inspection.ResultValue{Kind: inspection.ResultClassification, Classification: &inspection.ClassificationValue{Label: "clear"}},
		EvidenceRefs: []string{mediaRef}, ReasonCodes: []string{"criterion_met"}, Limitations: []string{},
		Analyzer: inspection.ResultAnalyzer{
			Kind: inspection.ResultAnalyzerFixture, AdapterVersion: "adapter.v2", ModelPolicy: "fixture-policy",
			ResolvedModelVersion: "fixture-v2", PromptTemplateID: "fixture-template", PromptTemplateVersion: "2",
			PromptTemplateSHA256: testDigest("fixture-template"),
		},
		Execution: inspection.ResultExecution{
			Attempt: 1, StartedAt: capturedAt.Add(100 * time.Millisecond),
			CompletedAt: capturedAt.Add(500 * time.Millisecond), LatencyMS: 400,
		},
		Integrity: inspection.ResultIntegrity{RawOutputSHA256: testDigest("raw-delivery"), ContractSHA256: testDigest("contract-delivery")},
	}
	observation := inspection.Observation{ObservationID: "observation-delivery", SampleID: "sample-delivery", Result: result}
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
	outcome, err := inspection.Evaluate(repository.plan, []inspection.Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	repository.observations = []inspection.Observation{observation}
	repository.outcome, repository.present = outcome, true
	repository.run.State = outcome.State
	repository.run.UpdatedAt = capturedAt.Add(time.Second)
}

func resultValidationStep(t *testing.T, plan inspection.ExecutionPlan) inspection.ExecutionStep {
	t.Helper()
	for _, step := range plan.Steps {
		if step.Kind == inspection.StepValidateResult && step.TargetID == "main-entrance" && step.CriterionID == "passage-state" {
			return step
		}
	}
	t.Fatal("fixture plan has no result validation step")
	return inspection.ExecutionStep{}
}

func genericCatalogFixture(session httpapi.SessionBinding) (inspection.InspectionTemplate, inspection.Assignment) {
	template := inspection.InspectionTemplate{
		Schema: inspection.SchemaVersion, TenantID: session.TenantID, TemplateID: "general-entrance-observation", Revision: 1,
		Name: "入口通行情况", BusinessPurpose: "查看入口当前是否便于通行。",
		Criteria: []inspection.Criterion{{
			ID: "passage-state", Name: "通行情况", Method: inspection.MethodVLM, Required: true,
			RuleRef: "passage-policy", RuleVersion: 1, MayAssertCompliance: true,
			Prompt: inspection.PromptContract{Template: "Observe the {{focus}} area.", Variables: []inspection.PromptVariable{{Name: "focus", Required: true, MaxLength: 32, AllowedValues: []string{"entrance"}}}},
			Output: inspection.OutputContract{Mode: inspection.ResultClassification, SchemaVersion: "classification.v2", AllowedAssessments: []inspection.Assessment{
				inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention, inspection.AssessmentUncertain, inspection.AssessmentNotObservable,
			}},
		}},
		Strategies: []inspection.StrategyPolicy{{
			Strategy: inspection.StrategySnapshotAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera},
			RequiredCapabilityRefs: []string{"snapshot-read"}, MinimumSources: 1, MaximumSources: 1,
			Time: inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30}, AnalysisPolicyRef: "general-vlm-policy",
			MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1},
		}},
		Budget:              inspection.ResourceBudget{MaxTargets: 1, MaxSamplesPerTarget: 1, MaxAnalyses: 1, MaxDurationSeconds: 300, MaxMediaBytes: 2 << 20},
		Evidence:            inspection.EvidencePolicy{Required: true, RetentionSeconds: 3600, RedactionProfile: "default-redaction"},
		OutputSchemaVersion: "inspection-report.v2", State: inspection.TemplatePublished, CreatedBy: "generic-test", CreatedAt: stateTestTime.Add(-time.Hour),
	}
	assignment := inspection.Assignment{
		Schema: inspection.SchemaVersion, TenantID: session.TenantID, AssignmentID: "site-entrance-observation", Revision: 1,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision, SiteID: session.SiteID,
		SourceCatalogFingerprint: testDigest("generic-catalog"), Published: true,
		Targets: []inspection.TargetBinding{{
			TargetID: "main-entrance", FriendlyName: "主入口",
			SourceBindings: []inspection.SourceBinding{{
				Kind: inspection.SourceCamera, SourceHandle: "opaque-entrance-source", SourceRevision: 1,
				SourceFingerprint: testDigest("generic-source"), CapabilityRefs: []string{"snapshot-read"}, MediaKinds: []inspection.MediaKind{inspection.MediaImage},
			}},
			CriterionIDs: []string{"passage-state"}, Strategy: inspection.StrategySnapshotAnalysis,
			Acquisition: inspection.AcquisitionPolicy{Samples: 1},
		}},
	}
	return template, assignment
}

func mustRunMapping(t *testing.T, state *StateStore, session httpapi.SessionBinding, ref string) RequestRecord {
	t.Helper()
	record, err := state.GetRunMapping(context.Background(), session, ref)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestDeriveTemporaryAnswerMapsKnownSummaries(t *testing.T) {
	tests := []struct {
		summary    string
		wantAnswer string
	}{
		{"本次现场查看得到肯定结果", "yes"},
		{"本次现场查看暂未得到肯定结果", "no"},
		{"当前画面暂时无法判断", "unable"},
		{"未知摘要", ""},
	}
	for _, test := range tests {
		t.Run(test.summary, func(t *testing.T) {
			got := deriveTemporaryAnswer(test.summary)
			if got != test.wantAnswer {
				t.Fatalf("deriveTemporaryAnswer(%q) = %q, want %q", test.summary, got, test.wantAnswer)
			}
		})
	}
}
