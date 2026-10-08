package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectioneval"
)

func TestRunValidateV3FromStdinReturnsSafeSummary(t *testing.T) {
	raw := syntheticFixture(t)
	var output bytes.Buffer
	if err := run([]string{"validate", "--manifest", "-"}, bytes.NewReader(raw), &output); err != nil {
		t.Fatal(err)
	}
	var decoded commandOutput
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != cliSchema || decoded.Status != "validated" || decoded.Validation == nil ||
		decoded.Validation.Records != 11 || decoded.Validation.ResultKinds["classification"] != 4 || decoded.Validation.TemporaryObservations != 2 ||
		decoded.Validation.ThresholdFitTrain != 1 || decoded.Validation.ThresholdFitValidation != 1 || decoded.Validation.Sites != 2 {
		t.Fatalf("output=%#v", decoded)
	}
	for _, protected := range []string{"tenant_aaaaaaaaaaaaaaaa", "site_1111111111111111", "source_1111111111111111", "group_1111111111111111"} {
		if strings.Contains(output.String(), protected) {
			t.Fatalf("validation summary leaked %q: %s", protected, output.String())
		}
	}
}

func TestRunEvaluateV3FromFileUsesTestPrimary(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "evaluation-v3.jsonl")
	if err := os.WriteFile(path, syntheticFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"evaluate", "--manifest", path}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	var decoded commandOutput
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != cliSchema || decoded.Status != "evaluated" || decoded.Evaluation == nil ||
		decoded.Evaluation.Schema != inspectioneval.ReportSchema || decoded.Evaluation.PrimarySplit != inspectioneval.SplitTest ||
		decoded.Evaluation.Overall.Records != 9 || len(decoded.Evaluation.BySource) != 9 {
		t.Fatalf("output=%#v", decoded)
	}
}

func TestRunRejectsOldFlagManifestAndCommand(t *testing.T) {
	raw := syntheticFixture(t)
	if err := run([]string{"validate", "-input", "-"}, bytes.NewReader(raw), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "parse v3 command") {
		t.Fatalf("old flag error=%v", err)
	}
	old := `{"tenantPseudonym":"tenant-a","expectedLabel":"meets_rule"}`
	if err := run([]string{"validate", "--manifest", "-"}, strings.NewReader(old), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "v3") {
		t.Fatalf("old manifest error=%v", err)
	}
	if err := run([]string{"serve", "--manifest", "-"}, bytes.NewReader(raw), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unsupported v3 command") {
		t.Fatalf("command error=%v", err)
	}
}

func TestRunGatePassesCheckedInGoldenV3(t *testing.T) {
	manifest, thresholds, report, digest := goldenPaths()
	var output bytes.Buffer
	if err := run([]string{"gate", "--manifest", manifest, "--thresholds", thresholds, "--golden-report", report, "--golden-sha256", digest}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	var decoded commandOutput
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "passed" || decoded.Gate == nil || !decoded.Gate.Passed || len(decoded.Gate.Failures) != 0 || len(decoded.Gate.ReportSHA256) != 64 {
		t.Fatalf("gate=%#v", decoded)
	}
}

func TestGateCoverageCannotBePaddedByNonTestRecords(t *testing.T) {
	manifestPath, thresholdsPath, _, _ := goldenPaths()
	thresholds, err := loadThresholds(thresholdsPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		match func(inspectioneval.Record) bool
		want  string
	}{
		"result kind": {func(record inspectioneval.Record) bool { return record.Expected.Kind == inspectioneval.ResultEnum }, "missing_result_kind:enum"},
		"feedback":    {func(record inspectioneval.Record) bool { return record.Feedback != nil && record.Feedback.Helpful }, "minimum_helpful_feedback"},
		"delivery":    {func(record inspectioneval.Record) bool { return record.DeliveryStatus == inspectioneval.DeliveryFailed }, "minimum_failed_deliveries"},
	} {
		t.Run(name, func(t *testing.T) {
			manifest, loadErr := loadManifest(manifestPath, strings.NewReader(""))
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			moved := false
			for index := range manifest.Records {
				if test.match(manifest.Records[index]) {
					manifest.Records[index].Split, moved = inspectioneval.SplitValidation, true
				}
			}
			if !moved {
				t.Fatal("fixture did not contain target coverage")
			}
			report, evaluateErr := inspectioneval.Evaluate(manifest)
			if evaluateErr != nil {
				t.Fatal(evaluateErr)
			}
			decision := gateDecision{Failures: []string{}}
			applyThresholds(&decision, manifest, report, thresholds)
			if !containsString(decision.Failures, test.want) {
				t.Fatalf("failures=%v want=%s", decision.Failures, test.want)
			}
		})
	}
}

func TestRunGateReturnsFailureForThresholdAndGoldenRegression(t *testing.T) {
	manifest, thresholdsPath, report, digest := goldenPaths()
	raw, err := os.ReadFile(thresholdsPath)
	if err != nil {
		t.Fatal(err)
	}
	strictThreshold := bytes.Replace(raw, []byte(`"minimumTestRecords": 9`), []byte(`"minimumTestRecords": 10`), 1)
	thresholds := filepath.Join(t.TempDir(), "thresholds.json")
	if err := os.WriteFile(thresholds, strictThreshold, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = run([]string{"gate", "--manifest", manifest, "--thresholds", thresholds, "--golden-report", report, "--golden-sha256", digest}, strings.NewReader(""), &output)
	var gateErr *gateFailureError
	if !errors.As(err, &gateErr) {
		t.Fatalf("threshold gate err=%v output=%s", err, output.String())
	}
	var thresholdDecision commandOutput
	if json.Unmarshal(output.Bytes(), &thresholdDecision) != nil || thresholdDecision.Gate == nil ||
		len(thresholdDecision.Gate.Failures) != 1 || thresholdDecision.Gate.Failures[0] != "minimum_test_records" {
		t.Fatalf("threshold decision=%s", output.String())
	}

	tampered := filepath.Join(t.TempDir(), "golden.json")
	reportRaw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tampered, bytes.Replace(reportRaw, []byte(`"records": 9`), []byte(`"records": 8`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err = run([]string{"gate", "--manifest", manifest, "--thresholds", thresholdsPath, "--golden-report", tampered, "--golden-sha256", digest}, strings.NewReader(""), &output)
	var goldenDecision commandOutput
	if !errors.As(err, &gateErr) || json.Unmarshal(output.Bytes(), &goldenDecision) != nil || goldenDecision.Gate == nil ||
		len(goldenDecision.Gate.Failures) != 2 || goldenDecision.Gate.Failures[0] != "golden_report_digest_mismatch" ||
		goldenDecision.Gate.Failures[1] != "golden_report_regression" {
		t.Fatalf("golden gate err=%v output=%s", err, output.String())
	}
}

func TestRunGateRejectsUnknownThresholdFieldAndMissingGoldenFlags(t *testing.T) {
	manifest, thresholdsPath, _, _ := goldenPaths()
	raw, err := os.ReadFile(thresholdsPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`{`), []byte(`{"unknown":true,`), 1)
	path := filepath.Join(t.TempDir(), "thresholds.json")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"gate", "--manifest", manifest, "--thresholds", path, "--golden-report", "missing", "--golden-sha256", "missing"}, strings.NewReader(""), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "thresholds") {
		t.Fatalf("unknown thresholds err=%v", err)
	}
	if err := run([]string{"gate", "--manifest", manifest}, strings.NewReader(""), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("missing flags err=%v", err)
	}
}

func syntheticFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "internal", "inspectioneval", "testdata", "synthetic.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func goldenPaths() (string, string, string, string) {
	root := filepath.Join("..", "..", "internal", "inspectioneval", "testdata")
	return filepath.Join(root, "synthetic.jsonl"), filepath.Join(root, "golden-thresholds-v3.json"),
		filepath.Join(root, "golden-report-v3.json"), filepath.Join(root, "golden-report-v3.sha256")
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
