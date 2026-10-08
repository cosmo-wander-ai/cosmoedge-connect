package parity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	frozenResultsEnv    = "PARITY_FROZEN_RESULTS"
	candidateResultsEnv = "PARITY_CANDIDATE_RESULTS"
	frozenBaselineSHA   = "74b933a7d17cc69567f276bc1d1a06cbae207d0ea390e25ca55a1154a2327ca2"
)

func TestFrozenOrdinaryBaselineIntegrity(t *testing.T) {
	path := filepath.Join("testdata", "ordinary-baseline-normalized.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != frozenBaselineSHA {
		t.Fatalf("frozen ordinary baseline sha256=%s, want %s", got, frozenBaselineSHA)
	}
	results, err := ReadNormalizedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 39 {
		t.Fatalf("frozen ordinary baseline scenarios=%d, want 39", len(results))
	}
}

func TestPhase3DifferentialFiles(t *testing.T) {
	baselinePath, candidatePath := os.Getenv(frozenResultsEnv), os.Getenv(candidateResultsEnv)
	if baselinePath == "" || candidatePath == "" {
		t.Skip("phase 3 differential result files are not configured")
	}
	baseline, err := ReadNormalizedFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := ReadNormalizedFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []AllowedDifference{
		{Difference: Difference{Scenario: "G-ACT-02/cross-browser-confirm", Field: "class", Baseline: "completed", Candidate: "blocked"}, Reason: "confirmation is now browser-session bound"},
		{Difference: Difference{Scenario: "G-ACT-02/cross-browser-confirm", Field: "deviceWrites", Baseline: 1, Candidate: 0}, Reason: "cross-browser confirmation is rejected before dispatch"},
		{Difference: Difference{Scenario: "G-ACT-02/cross-browser-confirm", Field: "dispatches", Baseline: 1, Candidate: 0}, Reason: "cross-browser confirmation is rejected before dispatch"},
		{Difference: Difference{Scenario: "G-ACT-09/task-post-dispatch-drift", Field: "evidenceStatus", Baseline: "external_drift", Candidate: "sealed"}, Reason: "result class and evidence sealing are separate fields"},
	}
	differences, err := DiffNormalized(baseline, candidate, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if len(differences) != 0 {
		t.Fatalf("unapproved phase 3 differences: %+v", differences)
	}
	if len(baseline) != 39 || len(candidate) != 39 {
		t.Fatalf("normalized scenario count baseline=%d candidate=%d, want 39 each", len(baseline), len(candidate))
	}
}
