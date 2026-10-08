package schedule

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectiontest"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

var testBase = time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

func TestProtectedStorageWireRoundTrip(t *testing.T) {
	value := testDraftSchedule(t, "schedule-wire", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	raw, err := marshalScheduleStorage(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalScheduleStorage(raw)
	if err != nil {
		t.Fatalf("unmarshal storage: %v\n%s", err, raw)
	}
	if !canonicalEqual(value, decoded) || decoded.RunSpec.Validate() != nil {
		t.Fatal("storage roundtrip changed schedule")
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := unmarshalScheduleStorage(unknown); err == nil {
		t.Fatal("storage accepted an unknown JSON field")
	}
}

func TestFrozenRunSpecIsClosedAndPublicProjectionIsProtected(t *testing.T) {
	spec := testFrozenRunSpec(t)
	if err := spec.Validate(); err != nil {
		t.Fatalf("Validate() error=%v", err)
	}
	if len(spec.SelectedTargets) != 2 || len(spec.Pipeline.Steps) == 0 || len(spec.SourceHandles) != 3 {
		t.Fatalf("incomplete frozen spec: %+v", spec)
	}
	wantOperations := []string{authority.OpAnalyze, authority.OpCleanup, authority.OpDeliver, authority.OpOccurrenceExecute, authority.OpSourceAcquire}
	if !equalStrings(spec.RequiredOperations, wantOperations) {
		t.Fatalf("derived operations=%v want=%v", spec.RequiredOperations, wantOperations)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	projection := string(raw)
	for _, forbidden := range []string{"Evaluate the", `"template":`, `"assignment":`, `"variables":`, `"steps":`, `"sourceHandles":`, `"sourceHandle":`, `"sourceBindings":`, `"authorityScope":`} {
		if strings.Contains(projection, forbidden) {
			t.Fatalf("protected projection leaked %q: %s", forbidden, projection)
		}
	}
	for _, required := range []string{spec.TemplateSHA256, spec.AssignmentSHA256, spec.Pipeline.SHA256, spec.SHA256} {
		if !strings.Contains(projection, required) {
			t.Fatalf("projection omitted digest %s", required)
		}
	}
}

func TestDeliveryPrincipalIsFrozenIntoBindingAndScheduleScopeDigests(t *testing.T) {
	first := testDraftSchedule(t, "schedule-delivery-principal", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	second := first
	changed, err := NewDeliveryBinding(first.Delivery.BindingRef, first.Delivery.Revision,
		first.Delivery.AudienceSHA256, strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	second.Delivery, second.DeliverySHA256 = changed, changed.SHA256
	firstScope, firstSHA, err := ScopeFor(first)
	if err != nil {
		t.Fatal(err)
	}
	secondScope, secondSHA, err := ScopeFor(second)
	if err != nil {
		t.Fatal(err)
	}
	if first.Delivery.SHA256 == second.Delivery.SHA256 || firstSHA == secondSHA || firstScope.DeliverySHA256 == secondScope.DeliverySHA256 {
		t.Fatalf("delivery principal did not change immutable digests: first=%s second=%s scope=%s/%s", first.Delivery.SHA256, second.Delivery.SHA256, firstSHA, secondSHA)
	}
}

func TestFrozenRunSpecSelectionCannotExpandPastRequestedTarget(t *testing.T) {
	template := inspectiontest.PublishedSceneTemplate()
	assignment := inspectiontest.PublishedSceneAssignment()
	request := inspectiontest.SceneRunRequest()
	request.Origin = inspection.OriginSchedule
	request.RequestedAt = testBase
	request.Deadline = testBase.Add(5 * time.Minute)
	request.TargetIDs = []string{inspectiontest.SceneTargetBetaID}

	spec, err := FreezeRunSpec(template, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.SelectedTargetIDs) != 1 || spec.SelectedTargetIDs[0] != inspectiontest.SceneTargetBetaID {
		t.Fatalf("selected target IDs expanded: %v", spec.SelectedTargetIDs)
	}
	if len(spec.SelectedTargets) != 1 || spec.SelectedTargets[0].TargetID != inspectiontest.SceneTargetBetaID {
		t.Fatalf("selected target snapshots expanded: %+v", spec.SelectedTargets)
	}
	if len(spec.SourceHandles) != 1 || spec.SourceHandles[0] != "source-beta" {
		t.Fatalf("source scope expanded: %v", spec.SourceHandles)
	}
	for _, target := range spec.Pipeline.Targets {
		if target.TargetID != inspectiontest.SceneTargetBetaID {
			t.Fatalf("pipeline target expanded: %s", target.TargetID)
		}
	}
	for _, step := range spec.Pipeline.Steps {
		if step.TargetID != "" && step.TargetID != inspectiontest.SceneTargetBetaID {
			t.Fatalf("pipeline step target expanded: %s", step.TargetID)
		}
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("single-target frozen spec invalid: %v", err)
	}
}

func TestScheduleRejectsAuthorityIncompatibleScopeBeforeAuthorization(t *testing.T) {
	draft := testDraftSchedule(t, "schedule-valid", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	draft.ScheduleID = "schedule:colon"
	if err := draft.Validate(); err == nil {
		t.Fatal("schedule accepted an identifier that ServiceExecution cannot sign")
	}

	template := inspectiontest.PublishedSceneTemplate()
	assignment := inspectiontest.PublishedSceneAssignment()
	assignment.Targets[0].SourceBindings[0].SourceHandle = "source:beta"
	request := inspectiontest.SceneRunRequest()
	request.Origin = inspection.OriginSchedule
	request.RequestedAt = testBase
	request.Deadline = testBase.Add(5 * time.Minute)
	request.TargetIDs = []string{inspectiontest.SceneTargetBetaID}
	if _, err := FreezeRunSpec(template, assignment, request); err == nil {
		t.Fatal("frozen run spec accepted a source handle that ServiceExecution cannot sign")
	}

	handles := make([]string, 65)
	for index := range handles {
		handles[index] = fmt.Sprintf("source-%03d", index)
	}
	if !sortedUniqueExecutionAuthorityRefs(handles[:64]) || sortedUniqueExecutionAuthorityRefs(handles) {
		t.Fatal("ServiceExecution source bound differs from the authority contract")
	}
}

func TestFrozenOccurrenceIgnoresMutableCatalogDriftAndRecompilesExactPlan(t *testing.T) {
	schedule, _, _ := testActiveSchedule(t, "schedule-frozen", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	planner := NewPlanner(testClock{testBase.Add(time.Hour)}, SystemZoneLoader{}, testVerifier{})
	occurrences, err := planner.Due(schedule, testBase.Add(30*time.Minute), testBase.Add(time.Hour))
	if err != nil || len(occurrences) != 1 {
		t.Fatalf("Due()=%d err=%v", len(occurrences), err)
	}
	occurrence := occurrences[0]
	// Simulate later catalog changes; the occurrence owns independent exact snapshots.
	template := inspectiontest.PublishedSceneTemplate()
	template.Criteria[0].Prompt.Template = "MUTATED {{scene}}"
	assignment := inspectiontest.PublishedSceneAssignment()
	assignment.Targets[0].SourceBindings[0].SourceFingerprint = strings.Repeat("f", 64)
	_ = template
	_ = assignment
	if err := occurrence.Validate(); err != nil {
		t.Fatalf("frozen occurrence rejected after ambient drift: %v", err)
	}
	request := occurrence.CreateRunRequest()
	plan, err := inspection.CompilePlan(occurrence.RunSpec.Template, occurrence.RunSpec.Assignment, request)
	if err != nil || plan.PlanSHA256 != occurrence.PlanSHA256 || request.RequestID != occurrence.RequestID {
		t.Fatalf("exact rebuild failed plan=%s err=%v", plan.PlanSHA256, err)
	}
	projection, err := json.Marshal(occurrence)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Evaluate the", `"template":`, `"assignment":`, `"variables":`, `"steps":`, `"sourceHandles":`, `"sourceHandle":`, `"sourceBindings":`, `"authorityScope":`} {
		if strings.Contains(string(projection), forbidden) {
			t.Fatalf("occurrence projection leaked %q", forbidden)
		}
	}
}

func TestFrozenDigestsRejectEverySemanticTamper(t *testing.T) {
	schedule, _, _ := testActiveSchedule(t, "schedule-tamper", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	planner := NewPlanner(testClock{testBase.Add(time.Hour)}, SystemZoneLoader{}, testVerifier{})
	occurrences, err := planner.Due(schedule, testBase.Add(30*time.Minute), testBase.Add(time.Hour))
	if err != nil || len(occurrences) != 1 {
		t.Fatalf("Due err=%v", err)
	}
	mutations := []func(*Occurrence){
		func(o *Occurrence) { o.RunSpec.Template.Criteria[0].Prompt.Template = "changed" },
		func(o *Occurrence) { o.RunSpec.Assignment.Targets[0].SourceBindings[0].SourceRevision++ },
		func(o *Occurrence) {
			o.RunSpec.SelectedTargets[0].SourceBindings[0].SourceFingerprint = strings.Repeat("e", 64)
		},
		func(o *Occurrence) { o.RunSpec.Variables[0].Value = "changed" },
		func(o *Occurrence) { o.Delivery.AudienceSHA256 = strings.Repeat("e", 64) },
		func(o *Occurrence) { o.Delivery.PrincipalSHA256 = strings.Repeat("e", 64) },
		func(o *Occurrence) { o.RequestSHA256 = strings.Repeat("c", 64) },
		func(o *Occurrence) { o.PlanSHA256 = strings.Repeat("b", 64) },
		func(o *Occurrence) { o.AuthorityScope.RunSpecSHA256 = strings.Repeat("a", 64) },
		func(o *Occurrence) {
			o.GeneratedAt = o.GeneratedAt.Add(time.Second)
			o.Misfired = o.GeneratedAt.Sub(o.DueAt) > time.Duration(o.MisfireGraceSeconds)*time.Second
		},
	}
	for index, mutate := range mutations {
		copy := occurrences[0]
		copy.RunSpec = cloneFrozenRunSpec(copy.RunSpec)
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Fatalf("tamper %d accepted", index)
		}
	}
}

func TestPlannerDSTGapAndFoldRemainDeterministic(t *testing.T) {
	schedule, _, _ := testActiveSchedule(t, "schedule-dst", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	schedule.Timezone = "America/New_York"
	schedule.LocalTime = "01:30"
	schedule.Weekdays = []Weekday{Sunday}
	schedule.ValidFrom = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	schedule.ValidUntil = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	// Re-authorize because timezone is part of the signed scope.
	schedule.State = StateAwaitingAuthorization
	schedule.ServiceGrant = authority.Grant{}
	schedule.ScheduleScopeSHA256 = ""
	schedule.AuthoritySHA256 = ""
	schedule.AuthorizedAt = nil
	schedule.UpdatedAt = schedule.ValidFrom
	schedule = testAuthorize(t, schedule, schedule.ValidFrom.Add(time.Minute))
	planner := NewPlanner(testClock{}, SystemZoneLoader{}, testVerifier{})
	now := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	values, err := planner.Due(schedule, time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), now)
	if err != nil || len(values) != 1 {
		t.Fatalf("fold Due=%d err=%v", len(values), err)
	}
	if values[0].ScheduledAt.Hour() != 5 {
		t.Fatalf("fall-back must select earliest instant, got %v", values[0].ScheduledAt)
	}
}

func TestNonZeroJitterSeparatesSignedPolicyFromOccurrenceOffset(t *testing.T) {
	draft := testDraftSchedule(t, "schedule-jitter", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	draft.JitterPolicySeconds = 300
	awaiting, err := AwaitAuthorization(draft, testBase.Add(-90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	active := testAuthorize(t, awaiting, testBase.Add(-time.Hour))
	planner := NewPlanner(testClock{}, SystemZoneLoader{}, testVerifier{})
	values, err := planner.Due(active, testBase.Add(30*time.Minute), testBase.Add(time.Hour+10*time.Minute))
	if err != nil || len(values) != 1 {
		t.Fatalf("Due=%d err=%v", len(values), err)
	}
	occurrence := values[0]
	if occurrence.JitterPolicySeconds != 300 || occurrence.JitterOffsetSeconds < 0 || occurrence.JitterOffsetSeconds > 300 {
		t.Fatalf("jitter policy=%d offset=%d", occurrence.JitterPolicySeconds, occurrence.JitterOffsetSeconds)
	}
	if err := occurrence.Validate(); err != nil {
		t.Fatalf("non-zero jitter occurrence invalid: %v", err)
	}
}

func TestAuthorityValidationUsesFrozenOccurrenceOnly(t *testing.T) {
	schedule, grant, signer := testActiveSchedule(t, "schedule-auth", ConcurrencyPolicy{MaxInFlight: 1, OnLimit: ConcurrencyQueue})
	planner := NewPlanner(testClock{testBase.Add(time.Hour)}, SystemZoneLoader{}, signer)
	occurrences, err := planner.Due(schedule, testBase.Add(30*time.Minute), testBase.Add(time.Hour))
	if err != nil || len(occurrences) != 1 {
		t.Fatal(err)
	}
	coordinator := &Coordinator{verifier: signer}
	scheduleProjection, err := json.Marshal(schedule)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{grant.ProofSHA256, grant.GrantID, `"serviceGrant"`, "Evaluate the", `"sourceHandles":`, `"sourceHandle":`, `"sourceBindings":`, `"authorityScope":`} {
		if strings.Contains(string(scheduleProjection), forbidden) {
			t.Fatalf("schedule projection leaked capability or prompt %q", forbidden)
		}
	}
	if err := coordinator.validateAuthority(occurrences[0], grant, testBase.Add(time.Hour)); err != nil {
		t.Fatalf("valid frozen authority rejected: %v", err)
	}
	wrong := grant
	wrong.PrincipalSHA256 = strings.Repeat("f", 64)
	if err := coordinator.validateAuthority(occurrences[0], wrong, testBase.Add(time.Hour)); err == nil {
		t.Fatal("mismatched authority accepted")
	}
}

type testClock struct{ value time.Time }

func (c testClock) Now() time.Time { return c.value }

type testVerifier struct{}

func (testVerifier) Verify(authority.Grant, authority.Demand, time.Time) error { return nil }

func testFrozenRunSpec(t *testing.T) FrozenRunSpec {
	t.Helper()
	request := inspectiontest.SceneRunRequest()
	request.Origin = inspection.OriginSchedule
	request.RequestedAt = testBase
	request.Deadline = testBase.Add(5 * time.Minute)
	spec, err := FreezeRunSpec(inspectiontest.PublishedSceneTemplate(), inspectiontest.PublishedSceneAssignment(), request)
	if err != nil {
		t.Fatalf("FreezeRunSpec: %v", err)
	}
	return spec
}

func testDraftSchedule(t *testing.T, id string, concurrency ConcurrencyPolicy) Schedule {
	t.Helper()
	spec := testFrozenRunSpec(t)
	delivery, err := NewDeliveryBinding("audience-main", 1, strings.Repeat("d", 64), strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	value := Schedule{Schema: SchemaVersion, TenantID: inspectiontest.FixtureTenantID, SiteID: inspectiontest.FixtureSiteID, ScheduleID: id, Revision: 1, Origin: inspection.OriginSchedule, RunSpec: spec, RunSpecSHA256: spec.SHA256, Delivery: delivery, DeliverySHA256: delivery.SHA256, ServicePrincipalSHA256: strings.Repeat("a", 64), Timezone: "UTC", Weekdays: []Weekday{Monday}, LocalTime: "10:00", ValidFrom: testBase.Add(-time.Hour), ValidUntil: testBase.Add(48 * time.Hour), Misfire: MisfireCatchUpOnce, MisfireGraceSeconds: 24 * 60 * 60, Concurrency: concurrency, State: StateDraft, CreatedAt: testBase.Add(-2 * time.Hour), UpdatedAt: testBase.Add(-2 * time.Hour)}
	if err := value.Validate(); err != nil {
		t.Fatalf("draft Validate: %v", err)
	}
	return value
}

func testActiveSchedule(t *testing.T, id string, concurrency ConcurrencyPolicy) (Schedule, authority.Grant, *authority.Signer) {
	t.Helper()
	draft := testDraftSchedule(t, id, concurrency)
	awaiting, err := AwaitAuthorization(draft, testBase.Add(-90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := authority.NewSigner("issuer-test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	scope, digest, err := ScopeFor(awaiting)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := signer.Issue("grant-"+id, authority.ServiceExecution, scope.ServicePrincipalSHA256, authority.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID, SourceHandles: append([]string(nil), scope.SourceHandles...), OperationKinds: append([]string(nil), scope.RequiredOperations...), ScheduleID: scope.ScheduleID, PolicySHA256: digest, MaxFrames: scope.ResourceCeiling.MaxTargets * scope.ResourceCeiling.MaxSamplesPerTarget, MaxBytes: scope.ResourceCeiling.MaxMediaBytes, MaxDurationSeconds: scope.ResourceCeiling.MaxDurationSeconds}, testBase.Add(-2*time.Hour), testBase.Add(36*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	active, err := Activate(awaiting, grant, signer, testBase.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return active, grant, signer
}

func testAuthorize(t *testing.T, s Schedule, at time.Time) Schedule {
	t.Helper()
	scope, digest, err := ScopeFor(s)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := authority.NewSigner("issuer-test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := signer.Issue("grant-"+s.ScheduleID, authority.ServiceExecution, scope.ServicePrincipalSHA256, authority.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID, SourceHandles: scope.SourceHandles, OperationKinds: scope.RequiredOperations, ScheduleID: scope.ScheduleID, PolicySHA256: digest, MaxFrames: scope.ResourceCeiling.MaxTargets * scope.ResourceCeiling.MaxSamplesPerTarget, MaxBytes: scope.ResourceCeiling.MaxMediaBytes, MaxDurationSeconds: scope.ResourceCeiling.MaxDurationSeconds}, at.Add(-time.Hour), s.ValidUntil)
	if err != nil {
		t.Fatal(err)
	}
	active, err := Activate(s, grant, signer, at)
	if err != nil {
		t.Fatal(err)
	}
	return active
}
