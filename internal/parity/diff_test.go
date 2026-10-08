package parity

import "testing"

func TestDiffNormalizedRejectsUnexplainedAndAcceptsExactCorrection(t *testing.T) {
	baseline := []NormalizedResult{{Scenario: "one", Class: "blocked", DeviceWrites: 1, Dispatches: 1}}
	candidate := []NormalizedResult{{Scenario: "one", Class: "blocked", DeviceWrites: 0, Dispatches: 1}}
	differences, err := DiffNormalized(baseline, candidate, nil)
	if err != nil || len(differences) != 1 || differences[0].Field != "deviceWrites" {
		t.Fatalf("unexplained differences=%#v err=%v", differences, err)
	}
	allowed := []AllowedDifference{{
		Difference: Difference{Scenario: "one", Field: "deviceWrites", Baseline: 1, Candidate: 0},
		Reason:     "S-02 separates rejected dispatches from writes",
	}}
	differences, err = DiffNormalized(baseline, candidate, allowed)
	if err != nil || len(differences) != 0 {
		t.Fatalf("allowed differences=%#v err=%v", differences, err)
	}
}

func TestDiffNormalizedRequiresSameScenarioSet(t *testing.T) {
	differences, err := DiffNormalized(
		[]NormalizedResult{{Scenario: "baseline-only"}},
		[]NormalizedResult{{Scenario: "candidate-only"}}, nil,
	)
	if err != nil || len(differences) != 2 {
		t.Fatalf("scenario differences=%#v err=%v", differences, err)
	}
}
