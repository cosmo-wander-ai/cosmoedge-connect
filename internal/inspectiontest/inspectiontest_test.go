package inspectiontest

import (
	"context"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

func TestAllFixtureScenariosAreClosedScripts(t *testing.T) {
	if len(AllFixtureScenarios) != 11 {
		t.Fatalf("scenario count=%d, want 11", len(AllFixtureScenarios))
	}
	for _, scenario := range AllFixtureScenarios {
		script, err := RuntimeScriptForScenario(scenario)
		if err != nil {
			t.Fatalf("RuntimeScriptForScenario(%q): %v", scenario, err)
		}
		if script.Name != scenario {
			t.Fatalf("RuntimeScriptForScenario(%q) name=%q", scenario, script.Name)
		}
	}
}

func TestFixturePortsExchangeDescriptorsAndTypedResults(t *testing.T) {
	now := FixtureBaseTime.Add(2 * time.Second)
	mediaStore, err := media.New(media.Config{
		Root: t.TempDir(), MaxObjectBytes: 1 << 20, MaxTotalBytes: 4 << 20, MaxDescriptors: 32,
		DefaultTTL: time.Hour, MaximumTTL: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	script, _ := RuntimeScriptForScenario(FixtureScenarioNormal)
	fixture, err := NewFixturePorts(script, mediaStore, func() time.Time {
		now = now.Add(time.Millisecond)
		return now
	})
	if err != nil {
		t.Fatal(err)
	}
	ports := fixture.Ports()
	target, _ := fixtureTarget(SceneTargetAlphaID)
	resolution, err := ports.Sources.Resolve(context.Background(), inspectionruntime.ResolveSourceRequest{
		RunID: "run_fixture_0001", StepID: "step_fixture_0001", TenantID: FixtureTenantID, SiteID: FixtureSiteID,
		TargetID: target.TargetID, Sources: target.SourceBindings, Attempt: 1, Deadline: FixtureBaseTime.Add(time.Minute),
	})
	if err != nil || resolution.ResolutionRef == "" {
		t.Fatalf("Resolve()=(%+v,%v)", resolution, err)
	}
	acquired, err := ports.Acquisition.Acquire(context.Background(), inspectionruntime.MediaAcquireRequest{
		Operation: inspection.StepAcquireMedia, RunID: resolution.RunID, StepID: "step_fixture_0002",
		TenantID: FixtureTenantID, SiteID: FixtureSiteID, TargetID: target.TargetID, ResolutionRef: resolution.ResolutionRef,
		Source: target.SourceBindings[0], Acquisition: inspection.AcquisitionPolicy{Samples: 1},
		Evidence: inspection.EvidencePolicy{Required: true, RetentionSeconds: 3600, RedactionProfile: "fixture-redaction-v1"},
		Attempt:  1, Deadline: FixtureBaseTime.Add(time.Minute), Budget: inspection.StepBudget{MaxBytes: 1 << 20},
	})
	if err != nil || acquired.Descriptor.MediaRef == "" || acquired.Descriptor.Schema != media.Schema {
		t.Fatalf("Acquire()=(%+v,%v)", acquired, err)
	}
	analysis, err := ports.Analysis.Analyze(context.Background(), inspectionruntime.AnalyzeRequest{
		RunID: resolution.RunID, StepID: "step_fixture_0003", TenantID: FixtureTenantID, SiteID: FixtureSiteID,
		TargetID: target.TargetID, CriterionID: BusinessCriterionID, Attempt: 1, Method: inspection.MethodVLM,
		AnalysisPolicyRef: "fixture-snapshot-vlm-v2", Prompt: "Evaluate the declared scene condition.", PromptSHA256: fixtureDigest("prompt"),
		Inputs: []inspectionruntime.AnalysisInput{{
			ProducerStepID: "step_fixture_0002", ProducerKind: inspection.StepAcquireMedia, Attempt: 1,
			ValueRef: acquired.Descriptor.MediaRef, SHA256: acquired.Descriptor.Integrity.SHA256, Descriptor: &acquired.Descriptor,
		}}, Deadline: FixtureBaseTime.Add(time.Minute),
	})
	if err != nil || analysis.Candidate.Assessment == "" {
		t.Fatalf("Analyze()=(%+v,%v)", analysis, err)
	}
	replayed, err := ports.Analysis.Result(context.Background(), analysis.ResultRef)
	if err != nil || replayed.ResultRef != analysis.ResultRef || replayed.Candidate.Assessment != analysis.Candidate.Assessment {
		t.Fatalf("Result()=(%+v,%v)", replayed, err)
	}
	cleanup, err := ports.Cleanup.Cleanup(context.Background(), inspectionruntime.CleanupRequest{
		RunID: resolution.RunID, StepID: "step_fixture_0004", TenantID: FixtureTenantID, SiteID: FixtureSiteID, Attempt: 1,
		Inputs: []inspectionruntime.ValueReference{{ValueRef: acquired.Descriptor.MediaRef}}, Deadline: FixtureBaseTime.Add(time.Minute),
	})
	if err != nil || cleanup.Created != 1 || cleanup.Removed != 1 || cleanup.Pending != 0 {
		t.Fatalf("Cleanup()=(%+v,%v)", cleanup, err)
	}
}

func TestFixtureFactoriesAndDeterminismRemainIndependent(t *testing.T) {
	first, err := SceneExecutionPlan()
	if err != nil {
		t.Fatal(err)
	}
	second, err := SceneExecutionPlan()
	if err != nil {
		t.Fatal(err)
	}
	first.Targets[0].SourceBindings[0].SourceHandle = "mutated"
	if second.Targets[0].SourceBindings[0].SourceHandle == "mutated" {
		t.Fatal("execution plan fixture shares mutable source bindings")
	}
	ids := NewDeterministicIDs()
	if value, _ := ids.Next("run"); value != "run-000001" {
		t.Fatalf("first deterministic id=%q", value)
	}
	clock, err := NewMonotonicClock(FixtureBaseTime, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if firstTick, secondTick := clock.Now(), clock.Now(); !secondTick.Equal(firstTick.Add(time.Millisecond)) {
		t.Fatalf("clock did not advance deterministically: %s -> %s", firstTick, secondTick)
	}
}
