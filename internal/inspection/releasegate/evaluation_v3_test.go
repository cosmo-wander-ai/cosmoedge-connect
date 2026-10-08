package releasegate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type evaluationGateOutput struct {
	Schema string `json:"schema"`
	Status string `json:"status"`
	Gate   *struct {
		Schema       string   `json:"schema"`
		Passed       bool     `json:"passed"`
		Failures     []string `json:"failures"`
		ReportSHA256 string   `json:"reportSha256"`
	} `json:"gate"`
}

func TestOfflineEvaluationV3AdaptersStayOutsideWriteAuthoritiesAndProduct(t *testing.T) {
	forbidden := append([]string(nil), authorityDependencies...)
	forbidden = append(forbidden, modulePath+"/internal/operator/inspectionproduct")
	assertNoForbiddenDependencies(t, "./internal/inspectioneval", forbidden)
}

// TestOfflineEvaluationV3ReleaseGate makes the release gate execute, rather
// than merely compile, the frozen result-contract check and the checked-in v3
// golden/threshold/count gate. All inputs are synthetic metadata fixtures.
func TestOfflineEvaluationV3ReleaseGate(t *testing.T) {
	root := repositoryRoot(t)
	runReleaseGo(t, root, "test", "-buildvcs=false", "-count=1", "./internal/inspectioneval",
		"-run", "^TestAssembleRecordRejectsCallerDriftAcrossPlanAnnotationDeliveryAndFeedback$")

	fixtureRoot := filepath.Join("internal", "inspectioneval", "testdata")
	output := runReleaseGo(t, root, "run", "-buildvcs=false", "./tools/inspection-eval", "gate",
		"--manifest", filepath.Join(fixtureRoot, "synthetic.jsonl"),
		"--thresholds", filepath.Join(fixtureRoot, "golden-thresholds-v3.json"),
		"--golden-report", filepath.Join(fixtureRoot, "golden-report-v3.json"),
		"--golden-sha256", filepath.Join(fixtureRoot, "golden-report-v3.sha256"))
	var decoded evaluationGateOutput
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatalf("decode bounded evaluation gate output: %v", err)
	}
	if decoded.Schema != "cosmoedge.inspection.eval.cli.v3" || decoded.Status != "passed" || decoded.Gate == nil ||
		decoded.Gate.Schema != "cosmoedge.inspection.eval.gate-decision.v3" || !decoded.Gate.Passed || len(decoded.Gate.Failures) != 0 {
		t.Fatalf("offline evaluation v3 release gate did not pass")
	}
	declared, err := os.ReadFile(filepath.Join(root, fixtureRoot, "golden-report-v3.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Gate.ReportSHA256 != strings.TrimSpace(string(declared)) {
		t.Fatal("offline evaluation v3 report digest differs from the checked-in contract")
	}
}

func runReleaseGo(t *testing.T, root string, arguments ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", arguments...)
	command.Dir = root
	command.Env = environmentWithoutGoWork()
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("offline evaluation v3 release command timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("offline evaluation v3 release command failed: %v\n%s", err, bytes.TrimSpace(output))
	}
	return output
}
