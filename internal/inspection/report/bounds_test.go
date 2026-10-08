package report

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

func TestComposeImmediateRejectsResourceLimitsWithoutPartialProjection(t *testing.T) {
	run, plan := fixtureRunAndPlan(t, inspection.RunCompleted)
	base := fixtureOutcome(
		inspection.RunCompleted, inspection.AssessmentMeetsRule,
		inspection.Coverage{Required: 2, Conclusive: 2, Ratio: 1},
		fixtureFinding("dining-east", "visible-residue", inspection.AssessmentMeetsRule, "media_east_0001"),
		fixtureFinding("dining-west", "visible-residue", inspection.AssessmentMeetsRule, "media_west_0001"),
	)
	tests := map[string]func(*inspection.Outcome){
		"findings": func(o *inspection.Outcome) { o.Findings = make([]inspection.Finding, maxPublicItems+1) },
		"evidence": func(o *inspection.Outcome) {
			o.Findings[0].EvidenceRefs = distinctRefs("media", maxFindingEvidenceRefs+1)
		},
		"typed results": func(o *inspection.Outcome) {
			o.Findings[0].Results = make([]inspection.ResultProjection, maxFindingResults+1)
		},
		"reason codes": func(o *inspection.Outcome) {
			o.Findings[0].ReasonCodes = distinctRefs("reason", maxFindingReasonCodes+1)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			outcome := cloneOutcome(base)
			mutate(&outcome)
			got, err := ComposeImmediate(run, plan, outcome, fixtureGeneratedAt())
			if !errors.Is(err, ErrResourceLimitExceeded) || got.Schema != "" || got.Findings != nil {
				t.Fatalf("report=%#v error=%v, want empty resource-limit rejection", got, err)
			}
		})
	}
}

func TestSafeEvidenceRefsRejectsRawCardinalityBeforeDeduplication(t *testing.T) {
	values := make([]string, maxFindingEvidenceRefs+1)
	for i := range values {
		values[i] = "media_duplicate_0001"
	}
	projected, err := safeEvidenceRefs(values)
	if !errors.Is(err, ErrResourceLimitExceeded) || projected != nil {
		t.Fatalf("safeEvidenceRefs() projected=%v error=%v", projected, err)
	}
}

func TestValidateImmediateRejectsDuplicateTypedEvidence(t *testing.T) {
	run, plan := fixtureRunAndPlan(t, inspection.RunCompleted)
	outcome := fixtureOutcome(
		inspection.RunCompleted, inspection.AssessmentMeetsRule,
		inspection.Coverage{Required: 2, Conclusive: 2, Ratio: 1},
		fixtureFinding("dining-east", "visible-residue", inspection.AssessmentMeetsRule, "media_east_0001"),
		fixtureFinding("dining-west", "visible-residue", inspection.AssessmentMeetsRule, "media_west_0001"),
	)
	report, err := ComposeImmediate(run, plan, outcome, fixtureGeneratedAt())
	if err != nil {
		t.Fatal(err)
	}
	report.Findings[0].Results[0].EvidenceRefs = []string{"media_east_0001", "media_east_0001"}
	if err := validateImmediatePublic(report); err == nil {
		t.Fatal("validateImmediatePublic accepted duplicate typed evidence")
	}
}

func distinctRefs(prefix string, count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = fmt.Sprintf("%s_%08d", prefix, i)
	}
	return values
}
