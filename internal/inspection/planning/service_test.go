package planning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/resolver"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

type registryFixture struct {
	templates   []inspection.InspectionTemplate
	assignments []inspection.Assignment
}

func (r *registryFixture) ListInspectionTemplates(context.Context, string) ([]inspection.InspectionTemplate, error) {
	return append([]inspection.InspectionTemplate(nil), r.templates...), nil
}

func (r *registryFixture) ListAssignments(context.Context, string, string) ([]inspection.Assignment, error) {
	return append([]inspection.Assignment(nil), r.assignments...), nil
}

type catalogFixture struct {
	sources     []catalog.Source
	tasks       []catalog.DeviceTaskBinding
	fingerprint string
	invalidTask bool
}

func (c *catalogFixture) ListSite(context.Context, string, string) ([]catalog.Source, error) {
	return append([]catalog.Source(nil), c.sources...), nil
}

func (c *catalogFixture) ListTasks(context.Context, string, string) ([]catalog.DeviceTaskBinding, error) {
	return append([]catalog.DeviceTaskBinding(nil), c.tasks...), nil
}

func (c *catalogFixture) Fingerprint(context.Context, string, string) (string, error) {
	return c.fingerprint, nil
}

func (c *catalogFixture) ValidateInstalledTask(_ context.Context, tenantID, siteID string, frozen inspection.InstalledTaskBinding) error {
	if c.invalidTask || tenantID != testTenant || siteID != testSite || len(c.tasks) != 1 || frozen.TaskID != c.tasks[0].TaskHandle || frozen.TaskRevision != c.tasks[0].Revision {
		return catalog.ErrTaskStale
	}
	return nil
}

type authorityFixture struct {
	values []resolver.AuthorityAvailability
}

func (a authorityFixture) AvailableAuthorities(context.Context, resolver.AuthenticatedScope) ([]resolver.AuthorityAvailability, error) {
	return append([]resolver.AuthorityAvailability(nil), a.values...), nil
}

// scriptedInterpreter is deliberately test-only. Production planning has no
// keyword or deterministic interpreter that could bypass semantic review.
type scriptedInterpreter struct {
	values map[string]InterpretedIntent
	calls  int
	last   InterpretationRequest
}

func (i *scriptedInterpreter) Interpret(_ context.Context, request InterpretationRequest) (InterpretedIntent, error) {
	i.calls++
	i.last = request
	value, ok := i.values[request.Instruction]
	if !ok {
		return InterpretedIntent{}, errors.New("no scripted intent")
	}
	return value, nil
}

type mediaCompilerFixture struct {
	mutate func(*mediaprep.FrozenRequest)
	calls  int
	last   TemporaryMediaCompilation
}

func (c *mediaCompilerFixture) Compile(_ context.Context, input TemporaryMediaCompilation) (mediaprep.FrozenRequest, error) {
	c.calls++
	c.last = input
	start, end := input.RequestedAt, input.RequestedAt
	kind := media.KindImage
	if input.Spec.TimeScope.Kind == temporary.TimeScopeRecentWindow {
		start = end.Add(-time.Duration(input.Spec.TimeScope.WindowSeconds) * time.Second)
		kind = media.KindVideoClip
	}
	request := mediaprep.FrozenRequest{
		Schema: mediaprep.RequestSchema, TenantID: input.TenantID, SiteID: input.SiteID, RequestID: input.RequestID,
		SourceRef: input.SourceRef, CapabilityRef: input.CapabilityRef,
		TimeScope:          mediaprep.TimeScope{WindowStart: start, WindowEnd: end, DurationMillis: end.Sub(start).Milliseconds()},
		AudienceBindingRef: input.AudienceBindingRef, AudienceSHA256: input.AudienceSHA256,
		EvidenceExpiresAt: input.EvidenceExpiresAt,
		Media: mediaprep.MediaSpec{
			Kind: kind, RunID: input.RuntimeRunID, StepID: input.RuntimeStepID, Attempt: 1,
			PrivacyClass: "internal", RetentionPolicyRef: "temporary-observation",
		},
	}
	if c.mutate != nil {
		c.mutate(&request)
	}
	return request, nil
}

type interactionFixture struct {
	mu      sync.Mutex
	records map[string]LocalInteractionRegistration
	calls   []LocalInteractionRegistration
	fail    error
	mutate  func(*LocalInteractionReceipt)
}

func (r *interactionFixture) Register(_ context.Context, request LocalInteractionRegistration) (LocalInteractionReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, cloneLocalRegistration(request))
	if r.fail != nil {
		return LocalInteractionReceipt{}, r.fail
	}
	if existing, ok := r.records[request.HandoffRef]; ok {
		if !reflect.DeepEqual(existing, request) {
			return LocalInteractionReceipt{}, errors.New("interaction conflict")
		}
	} else {
		r.records[request.HandoffRef] = cloneLocalRegistration(request)
	}
	receipt := LocalInteractionReceipt{Type: request.Type, HandoffRef: request.HandoffRef, ExpiresAt: request.ExpiresAt}
	if r.mutate != nil {
		r.mutate(&receipt)
	}
	return receipt, nil
}

func cloneLocalRegistration(value LocalInteractionRegistration) LocalInteractionRegistration {
	if value.Change != nil {
		change := *value.Change
		value.Change = &change
	}
	return value
}

const (
	testTenant = "tenant-a"
	testSite   = "site-a"
)

var testNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

func TestServicePlansAllClosedStandardStrategiesAndStableReplay(t *testing.T) {
	fixture := newPlanningFixture(t)
	tests := []struct {
		instruction string
		preference  ExecutionPreference
		strategy    inspection.ExecutionStrategy
	}{
		{"读取已有巡检结果", PreferExistingTask, inspection.StrategyExistingTaskRead},
		{"查看当前画面", PreferSnapshot, inspection.StrategySnapshotAnalysis},
		{"查看最近一段情况", PreferClip, inspection.StrategyClipAnalysis},
		{"结合已有结果和当前画面", PreferHybrid, inspection.StrategyHybridAnalysis},
	}
	for _, test := range tests {
		t.Run(string(test.strategy), func(t *testing.T) {
			fixture.interpreter.values[test.instruction] = standardIntent(test.preference)
			input := planningRequest(test.instruction, "request-"+string(test.strategy))
			first, err := fixture.service.Plan(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			request, err := first.Submission.PlanRequest()
			if err != nil || first.Interaction != nil || first.Temporary != nil {
				t.Fatalf("standard decision=%#v request=%#v err=%v", first, request, err)
			}
			identity, err := first.Submission.ExecutionIdentity()
			if err != nil || identity != (inspectionauthority.ExecutionIdentity{
				Kind: inspectionauthority.IdentityActor, PrincipalSHA256: input.Session.PrincipalSHA256,
			}) {
				t.Fatalf("standard decision identity=%#v err=%v", identity, err)
			}
			plan, err := inspection.CompilePlan(first.Template, first.Assignment, request)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Targets) != 1 || plan.Targets[0].StrategyPolicy.Strategy != test.strategy || request.RequestID != input.RequestID || !request.RequestedAt.Equal(input.RequestedAt) {
				t.Fatalf("plan did not freeze requested strategy: %#v", plan)
			}
			if test.strategy == inspection.StrategySnapshotAnalysis && (len(plan.Targets[0].Criteria) != 1 || !strings.Contains(plan.Targets[0].Criteria[0].Prompt, "查看当前可见情况。") || strings.Contains(plan.Targets[0].Criteria[0].Prompt, input.Request.Instruction)) {
				t.Fatalf("open-ended request text reached the frozen prompt: %#v", plan.Targets[0].Criteria)
			}

			second, err := fixture.service.Plan(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			secondRequest, err := second.Submission.PlanRequest()
			if err != nil || !reflect.DeepEqual(request, secondRequest) {
				t.Fatalf("replay request changed: first=%#v second=%#v err=%v", request, secondRequest, err)
			}
			secondPlan, err := inspection.CompilePlan(second.Template, second.Assignment, secondRequest)
			if err != nil || secondPlan.PlanSHA256 != plan.PlanSHA256 {
				t.Fatalf("replay plan changed: first=%s second=%s err=%v", plan.PlanSHA256, secondPlan.PlanSHA256, err)
			}
		})
	}
}

func TestServiceRegistersTemporaryPreparationAndFreezesExactAudience(t *testing.T) {
	fixture := newPlanningFixture(t)
	fixture.interpreter.values["临时看看桌面情况"] = InterpretedIntent{Goal: IntentInspect, Inspection: &InspectionIntent{
		Mode: ModeTemporaryVisual, SourceName: "东侧就餐区", Preference: PreferSnapshot,
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
		Temporary: &TemporaryObservationIntent{
			Subject: "就餐区", Region: "东侧用餐区", Observable: "查看桌面是否有可见残留",
			Locale: "zh-CN", EvidenceTTLSeconds: 300,
		},
	}}
	input := planningRequest("临时看看桌面情况", "request-temporary")
	first, err := fixture.service.Plan(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Temporary == nil || first.Interaction != nil || first.Template.Schema != "" || first.Assignment.Schema != "" {
		t.Fatalf("temporary decision carried another decision kind: %#v", first)
	}
	if _, err := first.Submission.PlanRequest(); err == nil {
		t.Fatal("temporary decision carried a standard submission")
	}
	expectedAudience, err := temporary.FreezeAudience(temporary.ChannelSession{
		TenantID: testTenant, SiteID: testSite, Channel: input.Session.Channel,
		ConversationRef: input.Session.ConversationRef, RecipientRef: input.Session.RecipientRef,
		PrincipalSHA256: input.Session.PrincipalSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := first.Temporary.PreparationRequest()
	if err != nil {
		t.Fatal(err)
	}
	if !first.Temporary.DeadlineAt.Equal(testNow.Add(5*time.Minute)) || first.Temporary.Spec.EvidenceTTLSeconds != 300 ||
		prepared.Media.Kind != media.KindImage || prepared.AudienceBindingRef != expectedAudience.Ref ||
		prepared.AudienceSHA256 != expectedAudience.SHA256 {
		t.Fatalf("temporary decision=%#v", first.Temporary)
	}
	if fixture.compiler.calls != 1 || prepared.RequestID != input.RequestID ||
		prepared.SourceRef != "source-east" || prepared.CapabilityRef != "snapshot-read" ||
		!prepared.EvidenceExpiresAt.Equal(testNow.Add(5*time.Minute)) || prepared.Media.RunID == "" || prepared.Media.StepID == "" {
		t.Fatalf("trusted media preparation=%#v compiler-calls=%d", prepared, fixture.compiler.calls)
	}
	if _, err := json.Marshal(first.Temporary); !errors.Is(err, mediaprep.ErrProtected) {
		t.Fatalf("temporary decision allowed ordinary JSON: %v", err)
	}
	formatted := fmt.Sprintf("%s %v %+v %#v", first.Temporary, first.Temporary, first.Temporary, first.Temporary)
	for _, forbidden := range []string{"source-east", "snapshot-read", "native-private", "rtsp://", "/private/", "password"} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("temporary output leaked %q: %s", forbidden, formatted)
		}
	}
	second, err := fixture.service.Plan(context.Background(), input)
	if err != nil || second.Temporary == nil || !reflect.DeepEqual(*first.Temporary, *second.Temporary) {
		t.Fatalf("temporary replay changed: first=%#v second=%#v err=%v", first.Temporary, second.Temporary, err)
	}
}

func TestServiceRejectsUnboundCompilerOutput(t *testing.T) {
	compilerMutations := map[string]func(*mediaprep.FrozenRequest){
		"tenant":     func(value *mediaprep.FrozenRequest) { value.TenantID = "tenant-other" },
		"site":       func(value *mediaprep.FrozenRequest) { value.SiteID = "site-other" },
		"request":    func(value *mediaprep.FrozenRequest) { value.RequestID = "request-other" },
		"source":     func(value *mediaprep.FrozenRequest) { value.SourceRef = "source-other" },
		"capability": func(value *mediaprep.FrozenRequest) { value.CapabilityRef = "clip-read" },
		"audience":   func(value *mediaprep.FrozenRequest) { value.AudienceBindingRef = "audience_other" },
		"audience digest": func(value *mediaprep.FrozenRequest) {
			value.AudienceSHA256 = digest("other-audience")
		},
		"expiry": func(value *mediaprep.FrozenRequest) {
			value.EvidenceExpiresAt = value.EvidenceExpiresAt.Add(time.Second)
		},
		"run":     func(value *mediaprep.FrozenRequest) { value.Media.RunID = "temporary_other" },
		"step":    func(value *mediaprep.FrozenRequest) { value.Media.StepID = "tempmedia_other" },
		"attempt": func(value *mediaprep.FrozenRequest) { value.Media.Attempt = 2 },
		"media kind": func(value *mediaprep.FrozenRequest) {
			value.Media.Kind = media.KindVideoClip
		},
		"window start": func(value *mediaprep.FrozenRequest) {
			value.TimeScope.WindowStart = value.TimeScope.WindowStart.Add(-time.Second)
		},
		"window end": func(value *mediaprep.FrozenRequest) {
			value.TimeScope.WindowEnd = value.TimeScope.WindowEnd.Add(time.Second)
		},
		"duration": func(value *mediaprep.FrozenRequest) { value.TimeScope.DurationMillis = 1 },
		"sample ordinal": func(value *mediaprep.FrozenRequest) {
			value.TimeScope.SampleOrdinal = 1
		},
	}
	for name, mutate := range compilerMutations {
		t.Run("compiler "+name, func(t *testing.T) {
			fixture := newPlanningFixture(t)
			fixture.compiler.mutate = mutate
			fixture.interpreter.values["临时查看"] = InterpretedIntent{Goal: IntentInspect, Inspection: &InspectionIntent{
				Mode: ModeTemporaryVisual, SourceName: "东侧就餐区", Preference: PreferSnapshot,
				TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
				Temporary: &TemporaryObservationIntent{Subject: "就餐区", Region: "东侧", Observable: "查看可见情况", Locale: "zh-CN", EvidenceTTLSeconds: 300},
			}}
			decision, err := fixture.service.Plan(context.Background(), planningRequest("临时查看", "request-invalid-compiler"))
			if err == nil || decision.Temporary != nil {
				t.Fatalf("unbound compilation was accepted: decision=%#v err=%v", decision, err)
			}
		})
	}
}

func TestServiceFreezesRecentTemporaryObservationAsExactClip(t *testing.T) {
	newRecentFixture := func(t *testing.T) *planningFixture {
		t.Helper()
		fixture := newPlanningFixture(t)
		fixture.interpreter.values["查看最近一分钟"] = InterpretedIntent{Goal: IntentInspect, Inspection: &InspectionIntent{
			Mode: ModeTemporaryVisual, SourceName: "东侧就餐区", Preference: PreferClip,
			TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeRecentWindow, WindowSeconds: 60},
			Temporary: &TemporaryObservationIntent{
				Subject: "就餐区", Region: "东侧", Observable: "查看最近一分钟的可见情况", Locale: "zh-CN", EvidenceTTLSeconds: 300,
			},
		}}
		return fixture
	}

	fixture := newRecentFixture(t)
	decision, err := fixture.service.Plan(context.Background(), planningRequest("查看最近一分钟", "request-recent-clip"))
	if err != nil || decision.Temporary == nil {
		t.Fatalf("recent temporary plan=%#v err=%v", decision, err)
	}
	wantStart := testNow.Add(-time.Minute)
	prepared, err := decision.Temporary.PreparationRequest()
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Media.Kind != media.KindVideoClip || !prepared.TimeScope.WindowStart.Equal(wantStart) ||
		!prepared.TimeScope.WindowEnd.Equal(testNow) || prepared.TimeScope.DurationMillis != 60_000 || prepared.TimeScope.SampleOrdinal != 0 {
		t.Fatalf("recent frozen request=%#v decision=%#v", prepared, decision.Temporary)
	}

	downgrade := newRecentFixture(t)
	downgrade.compiler.mutate = func(value *mediaprep.FrozenRequest) {
		value.Media.Kind = media.KindImage
		value.TimeScope.WindowStart = value.TimeScope.WindowEnd
		value.TimeScope.DurationMillis = 0
	}
	if decision, err := downgrade.service.Plan(context.Background(), planningRequest("查看最近一分钟", "request-recent-downgrade")); err == nil || decision.Temporary != nil {
		t.Fatalf("recent clip downgrade was accepted: decision=%#v err=%v", decision, err)
	}
}

func TestServiceReturnsSafeLocalConnectionAndPersistentChangeInteractions(t *testing.T) {
	fixture := newPlanningFixture(t)
	connectPurpose := ConnectNew
	fixture.interpreter.values["准备现场接入"] = InterpretedIntent{Goal: IntentConnect, Connection: &connectPurpose}
	fixture.interpreter.values["调整巡检安排"] = InterpretedIntent{Goal: IntentPersistentChange, PersistentChange: &PersistentChangeIntent{
		Kind: ChangeUpdateSchedule, SourceName: "东侧就餐区", TaskName: "客流观察任务",
	}}

	for _, test := range []struct {
		instruction string
		capability  string
	}{
		{instruction: "准备现场接入", capability: httpapi.InteractionCapabilityOnboarding},
		{instruction: "调整巡检安排", capability: httpapi.InteractionCapabilityPersistentChange},
	} {
		instruction := test.instruction
		input := planningRequest(instruction, "request-"+fmt.Sprint(len(instruction)))
		first, err := fixture.service.Plan(context.Background(), input)
		if err != nil {
			t.Fatalf("%s: %v", instruction, err)
		}
		if first.Interaction == nil || first.Temporary != nil {
			t.Fatalf("%s returned a non-interaction decision: %#v", instruction, first)
		}
		if _, err := first.Submission.PlanRequest(); err == nil {
			t.Fatalf("%s interaction carried a standard submission", instruction)
		}
		if first.Interaction.Capability != test.capability || first.Interaction.ActionLabel != "打开本机管理页面" || strings.Contains(first.Interaction.Message, "task-") || strings.Contains(first.Interaction.Message, "source-") {
			t.Fatalf("unsafe interaction: %#v", first.Interaction)
		}
		second, err := fixture.service.Plan(context.Background(), input)
		if err != nil || second.Interaction == nil || second.Interaction.HandoffRef != first.Interaction.HandoffRef {
			t.Fatalf("interaction handoff is not stable: first=%#v second=%#v err=%v", first.Interaction, second.Interaction, err)
		}
		registered, ok := fixture.interactions.records[first.Interaction.HandoffRef]
		if !ok || registered.TenantID != testTenant || registered.SiteID != testSite || registered.PrincipalSHA256 != digest("principal") ||
			!registered.ExpiresAt.Equal(testNow.Add(5*time.Minute)) {
			t.Fatalf("interaction was not registered with exact authenticated scope: %#v", registered)
		}
		if test.capability == httpapi.InteractionCapabilityOnboarding {
			if registered.Type != LocalInteractionConnection || registered.Change != nil {
				t.Fatalf("connection registration=%#v", registered)
			}
		} else if registered.Type != LocalInteractionPersistentChange || registered.Change == nil ||
			registered.Change.Operation != PendingDeviceScheduleUpdate || registered.Change.SourceRef != "source-east" ||
			registered.Change.TaskRef != "task-dining" || registered.Change.ExpectedSourceRevision != 1 ||
			registered.Change.ExpectedTaskRevision != 1 || registered.Change.ObservableRef != "" {
			t.Fatalf("persistent registration=%#v", registered)
		}
	}
	if len(fixture.interactions.records) != 2 || len(fixture.interactions.calls) != 4 {
		t.Fatalf("interaction replay registrations records=%d calls=%d", len(fixture.interactions.records), len(fixture.interactions.calls))
	}
}

func TestRequireConnectionRegistersStableExactHandoffWithoutCatalogRead(t *testing.T) {
	fixture := newPlanningFixture(t)
	input := planningRequest("帮我查看当前现场情况", "request-connection-fallback")

	first, err := fixture.service.RequireConnection(context.Background(), input)
	if err != nil || first.Interaction == nil {
		t.Fatalf("first connection fallback=%#v err=%v", first, err)
	}
	second, err := fixture.service.RequireConnection(context.Background(), input)
	if err != nil || second.Interaction == nil || second.Interaction.HandoffRef != first.Interaction.HandoffRef {
		t.Fatalf("fallback replay first=%#v second=%#v err=%v", first.Interaction, second.Interaction, err)
	}
	if fixture.interpreter.calls != 0 {
		t.Fatalf("fallback unexpectedly interpreted against an unavailable catalog: calls=%d", fixture.interpreter.calls)
	}
	registered, ok := fixture.interactions.records[first.Interaction.HandoffRef]
	if !ok || registered.Type != LocalInteractionConnection || registered.Change != nil ||
		registered.TenantID != testTenant || registered.SiteID != testSite ||
		registered.PrincipalSHA256 != digest("principal") ||
		!registered.ExpiresAt.Equal(testNow.Add(5*time.Minute)) {
		t.Fatalf("fallback registration=%#v", registered)
	}

	other := input
	other.RequestID = "request-connection-fallback-other"
	different, err := fixture.service.RequireConnection(context.Background(), other)
	if err != nil || different.Interaction == nil || different.Interaction.HandoffRef == first.Interaction.HandoffRef {
		t.Fatalf("different request did not receive a distinct handoff: %#v err=%v", different, err)
	}

	fixture.interactions.mutate = func(receipt *LocalInteractionReceipt) { receipt.HandoffRef = "handoff_wrong" }
	rejected, err := fixture.service.RequireConnection(context.Background(), planningRequest("帮我查看当前现场情况", "request-connection-mismatch"))
	if !errors.Is(err, httpapi.ErrConflict) || rejected.Interaction != nil {
		t.Fatalf("mismatched fallback escaped: decision=%#v err=%v", rejected, err)
	}
}

func TestServiceNeverExposesAnUnregisteredOrMismatchedInteraction(t *testing.T) {
	connectPurpose := ConnectNew
	for _, test := range []struct {
		name   string
		mutate func(*interactionFixture)
	}{
		{name: "registration failure", mutate: func(value *interactionFixture) { value.fail = errors.New("injected registration failure") }},
		{name: "wrong handoff", mutate: func(value *interactionFixture) {
			value.mutate = func(receipt *LocalInteractionReceipt) { receipt.HandoffRef = "handoff_wrong" }
		}},
		{name: "wrong expiry", mutate: func(value *interactionFixture) {
			value.mutate = func(receipt *LocalInteractionReceipt) { receipt.ExpiresAt = receipt.ExpiresAt.Add(time.Second) }
		}},
		{name: "noncanonical expiry", mutate: func(value *interactionFixture) {
			value.mutate = func(receipt *LocalInteractionReceipt) {
				receipt.ExpiresAt = receipt.ExpiresAt.In(time.FixedZone("other", 3600))
			}
		}},
		{name: "wrong type", mutate: func(value *interactionFixture) {
			value.mutate = func(receipt *LocalInteractionReceipt) { receipt.Type = LocalInteractionPersistentChange }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPlanningFixture(t)
			fixture.interpreter.values["准备现场接入"] = InterpretedIntent{Goal: IntentConnect, Connection: &connectPurpose}
			test.mutate(fixture.interactions)
			decision, err := fixture.service.Plan(context.Background(), planningRequest("准备现场接入", "request-registration-failure"))
			if !errors.Is(err, httpapi.ErrConflict) || decision.Interaction != nil {
				t.Fatalf("unregistered interaction escaped: decision=%#v err=%v", decision, err)
			}
		})
	}
}

func TestPlanningRequiresRegistrarAndProtectsItsTypedBoundary(t *testing.T) {
	fixture := newPlanningFixture(t)
	if _, err := New(Config{
		Registry: fixture.registry, Catalog: fixture.catalog,
		Authorities: fixture.authorities, Interpreter: fixture.interpreter,
		MediaCompiler: fixture.compiler,
		Now:           func() time.Time { return testNow },
	}); err == nil {
		t.Fatal("planning accepted a missing LocalInteractionRegistrar")
	}

	registrationType := reflect.TypeOf(LocalInteractionRegistration{})
	for index := 0; index < registrationType.NumField(); index++ {
		name := strings.ToLower(registrationType.Field(index).Name)
		for _, forbidden := range []string{"grant", "authority", "secret", "password", "endpoint", "native", "command", "confirmation", "dispatch", "proposal"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("LocalInteractionRegistration contains forbidden field %q", registrationType.Field(index).Name)
			}
		}
	}
	change := PendingChangeIntent{
		Operation: PendingTaskDisable, SourceRef: "source-private", ExpectedSourceRevision: 1,
		TaskRef: "task-private", ExpectedTaskRevision: 1,
	}
	registration := LocalInteractionRegistration{
		Type: LocalInteractionPersistentChange, TenantID: "tenant-private", SiteID: "site-private",
		PrincipalSHA256: strings.Repeat("a", 64), HandoffRef: "handoff-private", ExpiresAt: testNow.Add(time.Minute), Change: &change,
	}
	if _, err := json.Marshal(registration); !errors.Is(err, ErrProtectedInteractionProjection) {
		t.Fatalf("registration projection error=%v", err)
	}
	if _, err := json.Marshal(change); !errors.Is(err, ErrProtectedInteractionProjection) {
		t.Fatalf("change projection error=%v", err)
	}
	projected := fmt.Sprintf("%+v %#v %+v %#v", registration, registration, change, change)
	for _, protected := range []string{"tenant-private", "source-private", "task-private"} {
		if strings.Contains(projected, protected) {
			t.Fatalf("typed boundary leaked %q: %s", protected, projected)
		}
	}
}

func TestPendingChangeMappingCoversOnlyTheClosedResolverOperations(t *testing.T) {
	cases := []struct {
		proposal resolver.PersistentChangeProposal
		want     PendingChangeIntent
	}{
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeSourceCreate}, want: PendingChangeIntent{Operation: PendingSourceCreate}},
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeSourceUpdate, SourceHandle: "source-a", ExpectedSourceRevision: 2}, want: PendingChangeIntent{Operation: PendingSourceUpdate, SourceRef: "source-a", ExpectedSourceRevision: 2}},
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeSourceDelete, SourceHandle: "source-a", ExpectedSourceRevision: 2}, want: PendingChangeIntent{Operation: PendingSourceDelete, SourceRef: "source-a", ExpectedSourceRevision: 2}},
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeTaskDeploy, SourceHandle: "source-a", ExpectedSourceRevision: 2, ObservableCode: "observable-a"}, want: PendingChangeIntent{Operation: PendingTaskDeploy, SourceRef: "source-a", ExpectedSourceRevision: 2, ObservableRef: "observable-a"}},
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeTaskUpdate, SourceHandle: "source-a", ExpectedSourceRevision: 2, TaskHandle: "task-a", ExpectedTaskRevision: 3, ObservableCode: "observable-a"}, want: PendingChangeIntent{Operation: PendingTaskUpdate, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3, ObservableRef: "observable-a"}},
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeTaskEnable, SourceHandle: "source-a", ExpectedSourceRevision: 2, TaskHandle: "task-a", ExpectedTaskRevision: 3}, want: PendingChangeIntent{Operation: PendingTaskEnable, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3}},
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeTaskDisable, SourceHandle: "source-a", ExpectedSourceRevision: 2, TaskHandle: "task-a", ExpectedTaskRevision: 3}, want: PendingChangeIntent{Operation: PendingTaskDisable, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3}},
		{proposal: resolver.PersistentChangeProposal{Kind: resolver.ChangeDeviceScheduleUpdate, SourceHandle: "source-a", ExpectedSourceRevision: 2, TaskHandle: "task-a", ExpectedTaskRevision: 3}, want: PendingChangeIntent{Operation: PendingDeviceScheduleUpdate, SourceRef: "source-a", ExpectedSourceRevision: 2, TaskRef: "task-a", ExpectedTaskRevision: 3}},
	}
	for _, test := range cases {
		got, err := pendingChangeFromProposal(&test.proposal)
		if err != nil || !reflect.DeepEqual(got, test.want) {
			t.Fatalf("pendingChangeFromProposal(%s)=(%#v, %v), want %#v", test.proposal.Kind, got, err, test.want)
		}
	}
	for _, proposal := range []*resolver.PersistentChangeProposal{
		nil,
		{Kind: resolver.PersistentChangeKind("future-operation")},
		{Kind: resolver.ChangeTaskEnable, SourceHandle: "source-a", ExpectedSourceRevision: 2},
	} {
		if _, err := pendingChangeFromProposal(proposal); err == nil {
			t.Fatalf("pendingChangeFromProposal(%#v) accepted an open or malformed operation", proposal)
		}
	}
}

func TestServiceFailsClosedForAmbiguousStaleAndMissingAuthority(t *testing.T) {
	t.Run("ambiguous source", func(t *testing.T) {
		fixture := newPlanningFixture(t)
		duplicate := fixture.catalog.sources[0]
		duplicate.Handle = "source-west"
		duplicate.IdentityFingerprint = digest("source-west")
		fixture.catalog.sources = append(fixture.catalog.sources, duplicate)
		fixture.interpreter.values["查看当前画面"] = standardIntent(PreferSnapshot)
		_, err := fixture.service.Plan(context.Background(), planningRequest("查看当前画面", "request-ambiguous"))
		if !errors.Is(err, httpapi.ErrConflict) {
			t.Fatalf("ambiguous source error=%v", err)
		}
	})

	t.Run("stale catalog fact", func(t *testing.T) {
		fixture := newPlanningFixture(t)
		fixture.catalog.sources[0].CreatedAt = testNow.Add(-10 * time.Minute)
		fixture.catalog.sources[0].UpdatedAt = testNow.Add(-10 * time.Minute)
		fixture.interpreter.values["查看当前画面"] = standardIntent(PreferSnapshot)
		_, err := fixture.service.Plan(context.Background(), planningRequest("查看当前画面", "request-stale-fact"))
		if !errors.Is(err, httpapi.ErrConflict) {
			t.Fatalf("stale source fact error=%v", err)
		}
	})

	t.Run("stale published assignment", func(t *testing.T) {
		fixture := newPlanningFixture(t)
		for index := range fixture.registry.assignments {
			fixture.registry.assignments[index].SourceCatalogFingerprint = digest("old-catalog")
		}
		fixture.interpreter.values["查看当前画面"] = standardIntent(PreferSnapshot)
		_, err := fixture.service.Plan(context.Background(), planningRequest("查看当前画面", "request-stale-assignment"))
		if !errors.Is(err, httpapi.ErrConflict) {
			t.Fatalf("stale assignment error=%v", err)
		}
	})

	t.Run("missing execution authority", func(t *testing.T) {
		fixture := newPlanningFixture(t)
		fixture.authorities.values = filterAuthorities(fixture.authorities.values, resolver.AuthorityInspectionExecution)
		fixture.interpreter.values["查看当前画面"] = standardIntent(PreferSnapshot)
		_, err := fixture.service.Plan(context.Background(), planningRequest("查看当前画面", "request-no-authority"))
		if !errors.Is(err, httpapi.ErrForbidden) {
			t.Fatalf("missing authority error=%v", err)
		}
	})
}

func TestServiceUsesOnlyThePrincipalFrozenInTrustedSession(t *testing.T) {
	fixture := newPlanningFixture(t)
	fixture.interpreter.values["查看东侧就餐区"] = standardIntent(PreferSnapshot)
	input := planningRequest("查看东侧就餐区", "request-cross-principal")
	input.Session.PrincipalSHA256 = digest("another-principal")
	if decision, err := fixture.service.Plan(context.Background(), input); err == nil {
		t.Fatalf("planner accepted authorities for another principal: decision=%#v err=%v", decision, err)
	}
	if _, exists := reflect.TypeOf(Config{}).FieldByName("Principal"); exists {
		t.Fatal("planning config retained an ambient Principal provider")
	}
}

func TestServiceRejectsSecretsDeviceCommandsAndTrustedContextImpersonationBeforeInterpretation(t *testing.T) {
	nonUTC := planningRequest("查看当前画面", "request-non-utc")
	nonUTC.RequestedAt = nonUTC.RequestedAt.In(time.FixedZone("offset", 8*60*60))
	tests := []struct {
		name    string
		request application.PlanningRequest
	}{
		{"secret", planningRequest("password=private", "request-secret")},
		{"device command", planningRequest("禁用摄像头", "request-device-command")},
		{"source handle context", requestWithContext("查看当前画面", "request-source-context", "source_handle", "source-east")},
		{"task handle context", requestWithContext("查看当前画面", "request-task-context", "task_handle", "task-dining")},
		{"native locator context", requestWithContext("查看当前画面", "request-native-context", "native_locator", "private-value")},
		{"authority context", requestWithContext("查看当前画面", "request-authority-context", "authority", "all")},
		{"tenant context", requestWithContext("查看当前画面", "request-tenant-context", "tenant-id", "tenant-b")},
		{"non UTC request time", nonUTC},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPlanningFixture(t)
			_, err := fixture.service.Plan(context.Background(), test.request)
			if !errors.Is(err, httpapi.ErrInvalid) || fixture.interpreter.calls != 0 {
				t.Fatalf("error=%v interpreter calls=%d", err, fixture.interpreter.calls)
			}
		})
	}
}

func TestInterpreterReceivesOnlyBusinessVocabulary(t *testing.T) {
	fixture := newPlanningFixture(t)
	fixture.interpreter.values["查看当前画面"] = standardIntent(PreferSnapshot)
	if _, err := fixture.service.Plan(context.Background(), planningRequest("查看当前画面", "request-vocabulary")); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fixture.interpreter.last.Vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"东侧就餐区", "客流观察任务", "用餐区域情况"} {
		if !strings.Contains(string(raw), expected) {
			t.Fatalf("business vocabulary omitted %q: %s", expected, raw)
		}
	}
	for _, forbidden := range []string{"source-east", "task-dining", "snapshot-read", "clip-read", "task-evidence", "tenant-a", "site-a", "native-private", "authority"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("interpreter vocabulary leaked %q: %s", forbidden, raw)
		}
	}
}

func TestCapabilityQueryContainsOnlyChineseBusinessDescriptions(t *testing.T) {
	fixture := newPlanningFixture(t)
	result, err := fixture.service.QueryCapabilities(context.Background(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	if result.ContextLabel != "当前现场" || len(result.Capabilities) != 4 {
		t.Fatalf("capabilities=%#v", result)
	}
	for _, capability := range result.Capabilities {
		for _, text := range append([]string{capability.Title, capability.Description}, capability.Examples...) {
			hasHan := false
			for _, character := range text {
				if unicode.Is(unicode.Han, character) {
					hasHan = true
				}
				if character <= unicode.MaxASCII && unicode.IsLetter(character) {
					t.Fatalf("capability text contains English: %q", text)
				}
			}
			if !hasHan {
				t.Fatalf("capability text is not Chinese business language: %q", text)
			}
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"source-east", "task-dining", "template-", "assignment-", "snapshot-read", "clip-read", "task-evidence",
		"existing_task_read", "snapshot_analysis", "clip_analysis", "hybrid_analysis", "查看当前可见情况。", "native-private",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("capability projection leaked %q: %s", forbidden, raw)
		}
	}
}

type planningFixture struct {
	service      *Service
	registry     *registryFixture
	catalog      *catalogFixture
	authorities  *authorityFixture
	interpreter  *scriptedInterpreter
	compiler     *mediaCompilerFixture
	interactions *interactionFixture
}

func newPlanningFixture(t *testing.T) *planningFixture {
	t.Helper()
	source := fixtureSource(t, testNow.Add(-time.Minute), "source-east", "东侧就餐区")
	task := fixtureTask(t, source, testNow.Add(-time.Minute))
	frozen := fixtureInstalledTask(t, source, task)
	fingerprint := digest("catalog-current")
	templates, assignments := fixturePublishedRegistry(t, source, frozen, fingerprint)
	registry := &registryFixture{templates: templates, assignments: assignments}
	catalogPort := &catalogFixture{sources: []catalog.Source{source}, tasks: []catalog.DeviceTaskBinding{task}, fingerprint: fingerprint}
	authorities := &authorityFixture{values: fixtureAuthorities()}
	interpreter := &scriptedInterpreter{values: make(map[string]InterpretedIntent)}
	compiler := &mediaCompilerFixture{}
	interactions := &interactionFixture{records: make(map[string]LocalInteractionRegistration)}
	service, err := New(Config{
		Registry: registry, Catalog: catalogPort,
		Authorities: authorities, Interactions: interactions, Interpreter: interpreter,
		MediaCompiler: compiler,
		Now:           func() time.Time { return testNow }, CatalogFactTTL: 5 * time.Minute, DefaultRunTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &planningFixture{service: service, registry: registry, catalog: catalogPort, authorities: authorities, interpreter: interpreter, compiler: compiler, interactions: interactions}
}

func standardIntent(preference ExecutionPreference) InterpretedIntent {
	timeScope := temporary.TimeScope{Kind: temporary.TimeScopeCurrent}
	if preference == PreferExistingTask || preference == PreferClip {
		timeScope = temporary.TimeScope{Kind: temporary.TimeScopeRecentWindow, WindowSeconds: 60}
	}
	return InterpretedIntent{Goal: IntentInspect, Inspection: &InspectionIntent{
		Mode: ModeStandard, SourceName: "东侧就餐区", ObservableName: "用餐区域情况",
		Preference: preference, TimeScope: timeScope,
	}}
}

func planningRequest(instruction, requestID string) application.PlanningRequest {
	return application.PlanningRequest{Session: testSession(), Request: httpapi.InspectionRequest{Instruction: instruction}, RequestID: requestID, RequestedAt: testNow}
}

func requestWithContext(instruction, requestID, name, value string) application.PlanningRequest {
	request := planningRequest(instruction, requestID)
	request.Request.Context = []httpapi.BusinessContext{{Name: name, Value: value}}
	return request
}

func testSession() httpapi.SessionBinding {
	return httpapi.SessionBinding{TenantID: testTenant, SiteID: testSite, Channel: "workbuddy_wechat", ConversationRef: "conversation-a", RecipientRef: "recipient-a", PrincipalSHA256: digest("principal")}
}

func fixtureSource(t *testing.T, observedAt time.Time, handle, alias string) catalog.Source {
	t.Helper()
	capabilities, err := catalog.NormalizeCapabilities([]catalog.Capability{
		{Ref: "clip-read", Kind: catalog.CapabilityClip, Revision: 1, Constraints: catalog.Constraints{MediaKinds: []inspection.MediaKind{inspection.MediaVideoClip}, MaxBytes: 8 << 20, MaxDurationSeconds: 60, MaxFreshnessSeconds: 120}},
		{Ref: "snapshot-read", Kind: catalog.CapabilitySnapshot, Revision: 1, Constraints: catalog.Constraints{MediaKinds: []inspection.MediaKind{inspection.MediaImage}, MaxBytes: 2 << 20, MaxFrames: 1, MaxFreshnessSeconds: 30}},
		{Ref: "task-evidence", Kind: catalog.CapabilityTaskEvidence, Revision: 1, ResultSchema: "event.v2", Constraints: catalog.Constraints{MediaKinds: []inspection.MediaKind{inspection.MediaEvent}, MaxBytes: 64 << 10, MaxFreshnessSeconds: 120}},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := catalog.Source{
		Schema: catalog.SchemaVersion, TenantID: testTenant, SiteID: testSite, DeviceProfileID: "profile-a",
		Handle: handle, Kind: inspection.SourceCamera, Revision: 1, IdentityFingerprint: digest(handle),
		NativeLocator: "native-private-" + handle, Alias: alias, ZoneID: "dining", State: catalog.StateActive,
		Capabilities: capabilities, CreatedAt: observedAt, UpdatedAt: observedAt,
	}
	if err := source.Validate(); err != nil {
		t.Fatal(err)
	}
	return source
}

func fixtureTask(t *testing.T, source catalog.Source, observedAt time.Time) catalog.DeviceTaskBinding {
	t.Helper()
	capabilities, err := catalog.NormalizeTaskCapabilities([]catalog.Capability{
		{Ref: "task-evidence", Kind: catalog.CapabilityTaskEvidence, Revision: 1, ResultSchema: "event.v2", Constraints: catalog.Constraints{MediaKinds: []inspection.MediaKind{inspection.MediaEvent}, MaxBytes: 64 << 10, MaxFreshnessSeconds: 120}},
	})
	if err != nil {
		t.Fatal(err)
	}
	task := catalog.DeviceTaskBinding{
		Schema: catalog.SchemaVersion, TenantID: testTenant, SiteID: testSite, DeviceProfileID: "profile-a",
		TaskHandle: "task-dining", Revision: 1, IdentityFingerprint: digest("task-dining"), NativeLocator: "native-private-task",
		Alias: "客流观察任务", SourceHandles: []string{source.Handle}, Capabilities: capabilities, State: catalog.StateActive,
		ObservedAt: observedAt, CreatedAt: observedAt, UpdatedAt: observedAt,
	}
	if err := task.Validate(); err != nil {
		t.Fatal(err)
	}
	return task
}

func fixtureInstalledTask(t *testing.T, source catalog.Source, task catalog.DeviceTaskBinding) inspection.InstalledTaskBinding {
	t.Helper()
	capability := task.Capabilities[0]
	result := inspection.InstalledTaskBinding{
		TaskID: task.TaskHandle, TaskRevision: task.Revision, BindingFingerprint: digest("binding-task-dining"),
		Sources: []inspection.InstalledTaskSourceBinding{{SourceHandle: source.Handle, SourceRevision: source.Revision, SourceFingerprint: source.IdentityFingerprint}},
		Capabilities: []inspection.InstalledTaskCapabilityBinding{{
			Ref: capability.Ref, Revision: capability.Revision, Digest: capability.Digest,
			ResultSchema: capability.ResultSchema, MediaKinds: append([]inspection.MediaKind(nil), capability.Constraints.MediaKinds...),
		}},
		ObservedAt: task.ObservedAt,
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	return result
}

func fixturePublishedRegistry(t *testing.T, source catalog.Source, task inspection.InstalledTaskBinding, fingerprint string) ([]inspection.InspectionTemplate, []inspection.Assignment) {
	t.Helper()
	regular := func(capability string) inspection.SourceBinding {
		binding, err := source.Binding([]string{capability}, "")
		if err != nil {
			t.Fatal(err)
		}
		return binding
	}
	taskSource := task.TaskEvidenceSourceBindings()[0]
	types := []struct {
		name        string
		method      inspection.Method
		strategy    inspection.StrategyPolicy
		acquisition inspection.AcquisitionPolicy
		sources     []inspection.SourceBinding
		tasks       []inspection.InstalledTaskBinding
	}{
		{
			name: "existing", method: inspection.MethodEvent,
			strategy:    inspection.StrategyPolicy{Strategy: inspection.StrategyExistingTaskRead, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceTaskEvidence}, RequiredCapabilityRefs: []string{"task-evidence"}, MinimumSources: 1, MaximumSources: 1, Time: inspection.TimePolicy{Mode: inspection.TimeRecentWindow, WindowSeconds: 60, MaxAgeSeconds: 120}, MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1}},
			acquisition: inspection.AcquisitionPolicy{Samples: 1}, sources: []inspection.SourceBinding{taskSource}, tasks: []inspection.InstalledTaskBinding{task},
		},
		{
			name: "snapshot", method: inspection.MethodVLM,
			strategy:    inspection.StrategyPolicy{Strategy: inspection.StrategySnapshotAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera}, RequiredCapabilityRefs: []string{"snapshot-read"}, MinimumSources: 1, MaximumSources: 1, Time: inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30}, AnalysisPolicyRef: "visual-policy", MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1}},
			acquisition: inspection.AcquisitionPolicy{Samples: 1}, sources: []inspection.SourceBinding{regular("snapshot-read")},
		},
		{
			name: "clip", method: inspection.MethodVLM,
			strategy:    inspection.StrategyPolicy{Strategy: inspection.StrategyClipAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera}, RequiredCapabilityRefs: []string{"clip-read"}, MinimumSources: 1, MaximumSources: 1, Time: inspection.TimePolicy{Mode: inspection.TimeRecentWindow, WindowSeconds: 60, MaxAgeSeconds: 120}, AnalysisPolicyRef: "clip-policy", MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1, ClipDurationMillis: 10_000, MaxExtractedFrames: 8}},
			acquisition: inspection.AcquisitionPolicy{Samples: 1, ClipDurationMillis: 10_000, MaxExtractedFrames: 8}, sources: []inspection.SourceBinding{regular("clip-read")},
		},
		{
			name: "hybrid", method: inspection.MethodHybrid,
			strategy:    inspection.StrategyPolicy{Strategy: inspection.StrategyHybridAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera, inspection.SourceTaskEvidence}, RequiredCapabilityRefs: []string{"snapshot-read", "task-evidence"}, MinimumSources: 2, MaximumSources: 2, Time: inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30}, AnalysisPolicyRef: "hybrid-policy", MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1}},
			acquisition: inspection.AcquisitionPolicy{Samples: 1}, sources: []inspection.SourceBinding{regular("snapshot-read"), taskSource}, tasks: []inspection.InstalledTaskBinding{task},
		},
	}
	templates := make([]inspection.InspectionTemplate, 0, len(types))
	assignments := make([]inspection.Assignment, 0, len(types))
	for _, item := range types {
		prompt := inspection.PromptContract{}
		if item.method == inspection.MethodVLM || item.method == inspection.MethodHybrid {
			prompt = inspection.PromptContract{Template: "查看当前可见情况。"}
		}
		template := inspection.InspectionTemplate{
			Schema: inspection.SchemaVersion, TenantID: testTenant, TemplateID: "template-" + item.name, Revision: 1,
			Name: "用餐区域巡检", BusinessPurpose: "查看当前区域的业务情况。",
			Criteria: []inspection.Criterion{{
				ID: "dining-state", Name: "用餐区域情况", Method: item.method, Required: true,
				RuleRef: "business-rule", RuleVersion: 1, Prompt: prompt,
				Output: inspection.OutputContract{Mode: inspection.ResultClassification, AllowedAssessments: []inspection.Assessment{inspection.AssessmentNeedsAttention, inspection.AssessmentUncertain, inspection.AssessmentNotObservable}, SchemaVersion: "finding.v2"},
			}},
			Strategies:          []inspection.StrategyPolicy{item.strategy},
			Budget:              inspection.ResourceBudget{MaxTargets: 1, MaxSamplesPerTarget: 1, MaxAnalyses: 1, MaxDurationSeconds: 600, MaxMediaBytes: 16 << 20},
			Evidence:            inspection.EvidencePolicy{Required: true, RetentionSeconds: 600, RedactionProfile: "default-redaction"},
			OutputSchemaVersion: "report.v2", State: inspection.TemplatePublished, CreatedBy: "fixture", CreatedAt: testNow.Add(-time.Hour),
		}
		assignment := inspection.Assignment{
			Schema: inspection.SchemaVersion, TenantID: testTenant, AssignmentID: "assignment-" + item.name, Revision: 1,
			TemplateID: template.TemplateID, TemplateRevision: 1, SiteID: testSite, ZoneID: "dining",
			Targets: []inspection.TargetBinding{{
				TargetID: "target-" + item.name, FriendlyName: "东侧用餐区", SourceBindings: item.sources,
				InstalledTasks: item.tasks, CriterionIDs: []string{"dining-state"}, Strategy: item.strategy.Strategy, Acquisition: item.acquisition,
			}},
			SourceCatalogFingerprint: fingerprint, Published: true,
		}
		if err := template.Validate(); err != nil {
			t.Fatalf("%s template: %v", item.name, err)
		}
		if err := assignment.Validate(); err != nil {
			t.Fatalf("%s assignment: %v", item.name, err)
		}
		templates, assignments = append(templates, template), append(assignments, assignment)
	}
	return templates, assignments
}

func fixtureAuthorities() []resolver.AuthorityAvailability {
	principal := digest("principal")
	result := make([]resolver.AuthorityAvailability, 0, 4)
	for _, class := range []resolver.AuthorityClass{
		resolver.AuthorityConnectionProfileWrite, resolver.AuthorityDeviceRead,
		resolver.AuthorityInspectionExecution, resolver.AuthorityPersistentDeviceWrite,
	} {
		result = append(result, resolver.AuthorityAvailability{
			Class: class, TenantID: testTenant, SiteID: testSite, PrincipalSHA256: principal,
			VerifiedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Minute),
		})
	}
	return result
}

func filterAuthorities(values []resolver.AuthorityAvailability, removed resolver.AuthorityClass) []resolver.AuthorityAvailability {
	result := make([]resolver.AuthorityAvailability, 0, len(values))
	for _, value := range values {
		if value.Class != removed {
			result = append(result, value)
		}
	}
	return result
}

func digest(value string) string {
	const hexadecimal = "0123456789abcdef"
	result := make([]byte, 64)
	for index := range result {
		result[index] = hexadecimal[(index+len(value))%len(hexadecimal)]
	}
	return string(result)
}
