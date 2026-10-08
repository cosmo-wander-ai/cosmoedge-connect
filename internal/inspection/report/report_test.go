package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

func TestComposeImmediateProjectsTypedResultsWithoutModelProse(t *testing.T) {
	run, plan := fixtureRunAndPlan(t, inspection.RunCompleted)
	outcome := fixtureOutcome(
		inspection.RunCompleted,
		inspection.AssessmentNeedsAttention,
		inspection.Coverage{Required: 2, Conclusive: 2, Ratio: 1},
		fixtureFinding("dining-east", "visible-residue", inspection.AssessmentNeedsAttention, "media_east_0001"),
		fixtureFinding("dining-west", "visible-residue", inspection.AssessmentMeetsRule, "media_west_0001"),
	)
	got, err := ComposeImmediate(run, plan, outcome, fixtureGeneratedAt())
	if err != nil {
		t.Fatalf("ComposeImmediate() error = %v", err)
	}
	if got.OverallAssessment != inspection.AssessmentNeedsAttention || len(got.Findings) != 2 {
		t.Fatalf("unexpected report: %#v", got)
	}
	for _, finding := range got.Findings {
		if len(finding.Results) != 1 || finding.Results[0].Kind != inspection.ResultDetection || finding.Results[0].Value == nil {
			t.Fatalf("typed result was not projected: %#v", finding)
		}
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"raw model prose", `"displayText":`, `"display":`, `"sourceRef":`, `"sourceHandle":`, `"analyzer":`,
		`"execution":`, `"integrity":`, `"promptTemplate`, `"modelPolicy":`, "rtsp://", "imageBase64",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("standard report leaked %q: %s", forbidden, raw)
		}
	}
}

func TestComposeImmediateFailsClosedOnTypedResultDrift(t *testing.T) {
	run, plan := fixtureRunAndPlan(t, inspection.RunCompleted)
	base := fixtureOutcome(
		inspection.RunCompleted,
		inspection.AssessmentMeetsRule,
		inspection.Coverage{Required: 2, Conclusive: 2, Ratio: 1},
		fixtureFinding("dining-east", "visible-residue", inspection.AssessmentMeetsRule, "media_east_0001"),
		fixtureFinding("dining-west", "visible-residue", inspection.AssessmentMeetsRule, "media_west_0001"),
	)
	tests := map[string]func(*inspection.Outcome){
		"sample count mismatch": func(o *inspection.Outcome) { o.Findings[0].SampleCount = 2 },
		"evidence mismatch":     func(o *inspection.Outcome) { o.Findings[0].EvidenceRefs = []string{"media_other_0001"} },
		"multiple union members": func(o *inspection.Outcome) {
			o.Findings[0].Results[0].Value.Enum = &inspection.EnumValue{Value: "extra"}
		},
		"kind mismatch": func(o *inspection.Outcome) { o.Findings[0].Results[0].OutputKind = inspection.ResultMetric },
		"future result": func(o *inspection.Outcome) {
			o.Findings[0].Results[0].TimeWindow.EndAt = fixtureGeneratedAt().Add(time.Second)
		},
		"unsafe evidence": func(o *inspection.Outcome) {
			o.Findings[0].EvidenceRefs = []string{"https://device/image.jpg"}
			o.Findings[0].Results[0].EvidenceRefs = []string{"https://device/image.jpg"}
		},
		"prose label": func(o *inspection.Outcome) {
			o.Findings[0].Results[0].Value.Detection.Objects = []inspection.DetectionObject{{
				Label: "raw model prose", Region: inspection.NormalizedRegion{X: .1, Y: .1, Width: .1, Height: .1}, EvidenceRef: "media_east_0001",
			}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			outcome := cloneOutcome(base)
			mutate(&outcome)
			if report, err := ComposeImmediate(run, plan, outcome, fixtureGeneratedAt()); err == nil || report.Schema != "" {
				t.Fatalf("ComposeImmediate(%s) report=%#v error=%v", name, report, err)
			}
		})
	}
}

func TestComposeImmediatePartialKeepsInconclusiveResultWithoutValue(t *testing.T) {
	run, plan := fixtureRunAndPlan(t, inspection.RunPartial)
	attention := fixtureFinding("dining-east", "visible-residue", inspection.AssessmentNeedsAttention, "media_east_0001")
	missing := inspection.Finding{
		TargetID: "dining-west", CriterionID: "visible-residue", Assessment: inspection.AssessmentNotObservable,
		ReasonCodes: []string{"observation_missing"}, EvidenceRefs: []string{}, Results: []inspection.ResultProjection{},
		Limitations: []string{"observation_missing"},
	}
	outcome := fixtureOutcome(
		inspection.RunPartial, inspection.AssessmentNeedsAttention,
		inspection.Coverage{Required: 2, Conclusive: 1, Missing: 1, Ratio: .5}, attention, missing,
	)
	report, err := ComposeImmediate(run, plan, outcome, fixtureGeneratedAt())
	if err != nil {
		t.Fatalf("ComposeImmediate() error = %v", err)
	}
	if report.ExecutionState != inspection.RunPartial || report.Coverage.Missing != 1 {
		t.Fatalf("unexpected partial report: %#v", report)
	}
}

func TestComposeDailyRetainsSafeTypedHighlights(t *testing.T) {
	run, plan := fixtureRunAndPlan(t, inspection.RunCompleted)
	outcome := fixtureOutcome(
		inspection.RunCompleted, inspection.AssessmentNeedsAttention,
		inspection.Coverage{Required: 2, Conclusive: 2, Ratio: 1},
		fixtureFinding("dining-east", "visible-residue", inspection.AssessmentNeedsAttention, "media_east_0001"),
		fixtureFinding("dining-west", "visible-residue", inspection.AssessmentMeetsRule, "media_west_0001"),
	)
	immediate, err := ComposeImmediate(run, plan, outcome, fixtureGeneratedAt())
	if err != nil {
		t.Fatal(err)
	}
	daily, err := ComposeDaily(plan.SiteID, fixtureGeneratedAt().In(time.FixedZone("CST", 8*3600)), []Immediate{immediate})
	if err != nil {
		t.Fatalf("ComposeDaily() error = %v", err)
	}
	if len(daily.Highlights) != 1 || len(daily.Highlights[0].Results) != 1 || daily.Highlights[0].Results[0].Value == nil {
		t.Fatalf("daily typed highlight is incomplete: %#v", daily.Highlights)
	}
}

func fixtureRunAndPlan(t *testing.T, state inspection.RunState) (inspection.Run, inspection.ExecutionPlan) {
	t.Helper()
	requestedAt := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	template := inspection.InspectionTemplate{
		Schema: inspection.SchemaVersion, TenantID: "tenant-local", TemplateID: "visible-hygiene", Revision: 1,
		Name: "Visible hygiene", BusinessPurpose: "Report visible residue without a compliance claim.",
		Criteria: []inspection.Criterion{{
			ID: "visible-residue", Name: "Visible table residue", Method: inspection.MethodVLM, Required: true,
			RuleRef: "visible-residue-rule", RuleVersion: 1, MayAssertCompliance: true,
			Prompt: inspection.PromptContract{Template: "Inspect only visible residue."},
			Output: inspection.OutputContract{
				Mode: inspection.ResultDetection, SchemaVersion: "finding.v2",
				AllowedAssessments: []inspection.Assessment{
					inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention, inspection.AssessmentUncertain,
					inspection.AssessmentNotObservable, inspection.AssessmentUnsupported,
				},
			},
		}},
		Strategies: []inspection.StrategyPolicy{{
			Strategy: inspection.StrategySnapshotAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera},
			RequiredCapabilityRefs: []string{"capture-capability"}, MinimumSources: 1, MaximumSources: 1,
			Time:              inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
			AnalysisPolicyRef: "snapshot-v2", MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1},
		}},
		Budget:   inspection.ResourceBudget{MaxTargets: 2, MaxSamplesPerTarget: 1, MaxAnalyses: 2, MaxDurationSeconds: 120, MaxMediaBytes: 1 << 20},
		Evidence: inspection.EvidencePolicy{Required: true, RetentionSeconds: 3600}, OutputSchemaVersion: "report.v2",
		State: inspection.TemplatePublished, CreatedBy: "fixture", CreatedAt: requestedAt.Add(-time.Hour),
	}
	assignment := inspection.Assignment{
		Schema: inspection.SchemaVersion, TenantID: template.TenantID, AssignmentID: "site-a-hygiene", Revision: 1,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision, SiteID: "site-a",
		SourceCatalogFingerprint: strings.Repeat("c", 64), Published: true,
		Targets: []inspection.TargetBinding{
			fixtureTarget("dining-east", "Dining east", "source-east", "d"),
			fixtureTarget("dining-west", "Dining west", "source-west", "e"),
		},
	}
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: template.TenantID, SiteID: assignment.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision,
		AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		Origin: inspection.OriginUser, RequestID: "request-report-1", RequestedAt: requestedAt, Deadline: requestedAt.Add(2 * time.Minute),
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		t.Fatalf("CompilePlan() error = %v", err)
	}
	updatedAt := requestedAt.Add(10 * time.Second)
	run := inspection.Run{
		RunID: "run-1", TenantID: plan.TenantID, SiteID: plan.SiteID, RequestKey: plan.RequestKey, PlanSHA256: plan.PlanSHA256,
		State: state, CreatedAt: requestedAt, UpdatedAt: updatedAt, Deadline: plan.Deadline,
	}
	return run, plan
}

func fixtureTarget(id, name, source, digestCharacter string) inspection.TargetBinding {
	return inspection.TargetBinding{
		TargetID: id, FriendlyName: name,
		SourceBindings: []inspection.SourceBinding{{
			Kind: inspection.SourceCamera, SourceHandle: source, SourceRevision: 1,
			SourceFingerprint: strings.Repeat(digestCharacter, 64), CapabilityRefs: []string{"capture-capability"},
			MediaKinds: []inspection.MediaKind{inspection.MediaImage},
		}},
		CriterionIDs: []string{"visible-residue"}, Strategy: inspection.StrategySnapshotAnalysis,
		Acquisition: inspection.AcquisitionPolicy{Samples: 1},
	}
}

func fixtureFinding(target, criterion string, assessment inspection.Assessment, evidence string) inspection.Finding {
	observedAt := fixtureObservedAt()
	objects := []inspection.DetectionObject{}
	if assessment == inspection.AssessmentNeedsAttention {
		objects = append(objects, inspection.DetectionObject{
			Label: "residue", Score: reportFloatPtr(.9), Region: inspection.NormalizedRegion{X: .2, Y: .2, Width: .2, Height: .2}, EvidenceRef: evidence,
		})
	}
	value := &inspection.ResultValue{Kind: inspection.ResultDetection, Detection: &inspection.DetectionValue{Objects: objects}}
	reason := "criterion_met"
	if assessment == inspection.AssessmentNeedsAttention {
		reason = "criterion_violated"
	}
	return inspection.Finding{
		TargetID: target, CriterionID: criterion, Assessment: assessment, SampleCount: 1,
		ReasonCodes: []string{reason}, EvidenceRefs: []string{evidence}, ObservedAt: observedAt, Limitations: []string{},
		Results: []inspection.ResultProjection{{
			ResultID: "result-" + target, SampleID: "sample-" + target, OutputKind: inspection.ResultDetection,
			Value: value, EvidenceRefs: []string{evidence}, TimeWindow: inspection.ResultTimeWindow{StartAt: observedAt, EndAt: observedAt},
		}},
	}
}

func fixtureOutcome(state inspection.RunState, assessment inspection.Assessment, coverage inspection.Coverage, findings ...inspection.Finding) inspection.Outcome {
	return inspection.Outcome{State: state, OverallAssessment: assessment, Coverage: coverage, Findings: findings}
}

func cloneOutcome(value inspection.Outcome) inspection.Outcome {
	raw, _ := json.Marshal(value)
	var clone inspection.Outcome
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func fixtureObservedAt() time.Time          { return time.Date(2026, 7, 18, 10, 0, 5, 0, time.UTC) }
func fixtureGeneratedAt() time.Time         { return time.Date(2026, 7, 18, 10, 0, 10, 0, time.UTC) }
func reportFloatPtr(value float64) *float64 { return &value }
