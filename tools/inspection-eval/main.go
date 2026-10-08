package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspectioneval"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const (
	cliSchema          = "cosmoedge.inspection.eval.cli.v3"
	cliErrorSchema     = "cosmoedge.inspection.eval.cli.error.v3"
	thresholdSchema    = "cosmoedge.inspection.eval.thresholds.v3"
	gateDecisionSchema = "cosmoedge.inspection.eval.gate-decision.v3"
	maximumConfigBytes = 1 << 20
	maximumReportBytes = 64 << 20
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type validationSummary struct {
	Records                int            `json:"records"`
	Splits                 map[string]int `json:"splits"`
	ResultKinds            map[string]int `json:"resultKinds"`
	Criteria               int            `json:"criteria"`
	Strategies             int            `json:"strategies"`
	Groups                 int            `json:"groups"`
	Sites                  int            `json:"sites"`
	TemporaryObservations  int            `json:"temporaryObservations"`
	ThresholdFitTrain      int            `json:"thresholdFitTrain"`
	ThresholdFitValidation int            `json:"thresholdFitValidation"`
}

type gateThresholds struct {
	Schema                     string                      `json:"schema"`
	MinimumTestRecords         int                         `json:"minimumTestRecords"`
	MinimumTestSites           int                         `json:"minimumTestSites"`
	RequiredStrategies         []inspectioneval.Strategy   `json:"requiredStrategies"`
	RequiredResultKinds        []inspectioneval.ResultKind `json:"requiredResultKinds"`
	MinimumDeliveryReliability float64                     `json:"minimumDeliveryReliability"`
	MaximumDeliveryUnknownRate float64                     `json:"maximumDeliveryUnknownRate"`
	MaximumFalseClearRate      float64                     `json:"maximumFalseClearRate"`
	MinimumHelpfulFeedback     int                         `json:"minimumHelpfulFeedback"`
	MinimumUnhelpfulFeedback   int                         `json:"minimumUnhelpfulFeedback"`
	MinimumMissingFeedback     int                         `json:"minimumMissingFeedback"`
	MinimumUnknownDeliveries   int                         `json:"minimumUnknownDeliveries"`
	MinimumFailedDeliveries    int                         `json:"minimumFailedDeliveries"`
	MinimumRetriedDeliveries   int                         `json:"minimumRetriedDeliveries"`
}

type gateDecision struct {
	Schema       string   `json:"schema"`
	Passed       bool     `json:"passed"`
	Failures     []string `json:"failures"`
	ReportSHA256 string   `json:"reportSha256"`
}

type commandOutput struct {
	Schema     string                           `json:"schema"`
	Status     string                           `json:"status"`
	Validation *validationSummary               `json:"validation,omitempty"`
	Evaluation *inspectioneval.EvaluationReport `json:"evaluation,omitempty"`
	Gate       *gateDecision                    `json:"gate,omitempty"`
}

type errorOutput struct {
	Schema     string `json:"schema"`
	Status     string `json:"status"`
	ReasonCode string `json:"reasonCode"`
	Message    string `json:"message"`
}

type gateFailureError struct{ failures int }

func (e *gateFailureError) Error() string {
	return fmt.Sprintf("v3 evaluation gate failed with %d decision(s)", e.failures)
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(errorOutput{
			Schema: cliErrorSchema, Status: "failed", ReasonCode: "invalid_v3_evaluation_or_gate_failure", Message: err.Error(),
		})
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("v3 command is required: validate, evaluate, or gate")
	}
	command := args[0]
	if command != "validate" && command != "evaluate" && command != "gate" {
		return fmt.Errorf("unsupported v3 command %q", command)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "v3 JSONL manifest path, or - for stdin")
	thresholdPath := flags.String("thresholds", "", "v3 gate threshold JSON")
	goldenReportPath := flags.String("golden-report", "", "checked-in v3 golden report JSON")
	goldenSHAPath := flags.String("golden-sha256", "", "checked-in canonical golden report digest")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("parse v3 command: %w", err)
	}
	if flags.NArg() != 0 || *manifestPath == "" {
		return errors.New("--manifest is required and positional arguments are not allowed")
	}
	if command == "gate" {
		if *thresholdPath == "" || *goldenReportPath == "" || *goldenSHAPath == "" {
			return errors.New("gate requires --thresholds, --golden-report, and --golden-sha256")
		}
	} else if *thresholdPath != "" || *goldenReportPath != "" || *goldenSHAPath != "" {
		return errors.New("golden and threshold flags are accepted only by gate")
	}
	manifest, err := loadManifest(*manifestPath, stdin)
	if err != nil {
		return err
	}
	output := commandOutput{Schema: cliSchema}
	switch command {
	case "validate":
		summary := summarize(manifest)
		output.Status = "validated"
		output.Validation = &summary
	case "evaluate":
		report, evaluateErr := inspectioneval.Evaluate(manifest)
		if evaluateErr != nil {
			return evaluateErr
		}
		output.Status = "evaluated"
		output.Evaluation = &report
	case "gate":
		thresholds, thresholdErr := loadThresholds(*thresholdPath)
		if thresholdErr != nil {
			return thresholdErr
		}
		report, evaluateErr := inspectioneval.Evaluate(manifest)
		if evaluateErr != nil {
			return evaluateErr
		}
		decision, decisionErr := decideGate(manifest, report, thresholds, *goldenReportPath, *goldenSHAPath)
		if decisionErr != nil {
			return decisionErr
		}
		output.Gate = &decision
		if decision.Passed {
			output.Status = "passed"
		} else {
			output.Status = "failed"
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return err
	}
	if output.Gate != nil && !output.Gate.Passed {
		return &gateFailureError{failures: len(output.Gate.Failures)}
	}
	return nil
}

func loadManifest(path string, stdin io.Reader) (inspectioneval.Manifest, error) {
	if path == "-" {
		return inspectioneval.Load(stdin)
	}
	file, err := os.Open(path)
	if err != nil {
		return inspectioneval.Manifest{}, errors.New("open v3 manifest: unavailable")
	}
	defer file.Close()
	return inspectioneval.Load(file)
}

func loadThresholds(path string) (gateThresholds, error) {
	raw, err := readBoundedFile(path, maximumConfigBytes)
	if err != nil {
		return gateThresholds{}, errors.New("open v3 thresholds: unavailable")
	}
	var value gateThresholds
	if strictjson.ValidateExactFields(raw, &value, 8) != nil || decodeStrict(raw, &value) != nil || validateThresholds(value) != nil {
		return gateThresholds{}, errors.New("v3 thresholds are invalid")
	}
	return value, nil
}

func validateThresholds(value gateThresholds) error {
	if value.Schema != thresholdSchema || value.MinimumTestRecords < 1 || value.MinimumTestRecords > inspectioneval.MaximumManifestRecords ||
		value.MinimumTestSites < 1 || value.MinimumTestSites > inspectioneval.MaximumManifestRecords ||
		value.MinimumHelpfulFeedback < 0 || value.MinimumUnhelpfulFeedback < 0 || value.MinimumMissingFeedback < 0 ||
		value.MinimumUnknownDeliveries < 0 || value.MinimumFailedDeliveries < 0 || value.MinimumRetriedDeliveries < 0 {
		return errors.New("threshold bounds are invalid")
	}
	for _, ratio := range []float64{value.MinimumDeliveryReliability, value.MaximumDeliveryUnknownRate, value.MaximumFalseClearRate} {
		if ratio < 0 || ratio > 1 {
			return errors.New("threshold ratio is invalid")
		}
	}
	strategies := append([]inspectioneval.Strategy(nil), value.RequiredStrategies...)
	resultKinds := append([]inspectioneval.ResultKind(nil), value.RequiredResultKinds...)
	if len(strategies) == 0 || len(strategies) > 4 || len(resultKinds) == 0 || len(resultKinds) > 7 ||
		!sort.SliceIsSorted(strategies, func(i, j int) bool { return strategies[i] < strategies[j] }) ||
		!sort.SliceIsSorted(resultKinds, func(i, j int) bool { return resultKinds[i] < resultKinds[j] }) {
		return errors.New("required enum lists are empty or not canonical")
	}
	for index, value := range strategies {
		if index > 0 && strategies[index-1] == value || !validStrategy(value) {
			return errors.New("required strategy is invalid or duplicated")
		}
	}
	for index, value := range resultKinds {
		if index > 0 && resultKinds[index-1] == value || !validResultKind(value) {
			return errors.New("required result kind is invalid or duplicated")
		}
	}
	return nil
}

func decideGate(manifest inspectioneval.Manifest, report inspectioneval.EvaluationReport, thresholds gateThresholds, goldenReportPath, goldenSHAPath string) (gateDecision, error) {
	currentRaw, err := json.Marshal(report)
	if err != nil {
		return gateDecision{}, err
	}
	currentDigest := sha256.Sum256(currentRaw)
	decision := gateDecision{Schema: gateDecisionSchema, Failures: []string{}, ReportSHA256: hex.EncodeToString(currentDigest[:])}
	goldenRaw, err := readBoundedFile(goldenReportPath, maximumReportBytes)
	if err != nil {
		return gateDecision{}, errors.New("open v3 golden report: unavailable")
	}
	var golden inspectioneval.EvaluationReport
	if err := decodeCanonicalReport(goldenRaw, &golden); err != nil {
		return gateDecision{}, fmt.Errorf("v3 golden report is invalid: %w", err)
	}
	canonicalGolden, err := json.Marshal(golden)
	if err != nil {
		return gateDecision{}, err
	}
	declaredSHA, err := readBoundedFile(goldenSHAPath, 128)
	if err != nil || !sha256Pattern.MatchString(strings.TrimSpace(string(declaredSHA))) {
		return gateDecision{}, errors.New("v3 golden report digest is invalid")
	}
	goldenDigest := sha256.Sum256(canonicalGolden)
	if hex.EncodeToString(goldenDigest[:]) != strings.TrimSpace(string(declaredSHA)) {
		decision.Failures = append(decision.Failures, "golden_report_digest_mismatch")
	}
	if !bytes.Equal(currentRaw, canonicalGolden) {
		decision.Failures = append(decision.Failures, "golden_report_regression")
	}
	applyThresholds(&decision, manifest, report, thresholds)
	decision.Passed = len(decision.Failures) == 0
	return decision, nil
}

func decodeCanonicalReport(raw []byte, target *inspectioneval.EvaluationReport) error {
	// The report contains one intentionally embedded metric struct. Validate
	// duplicate keys/depth generically, then use DisallowUnknownFields and an
	// exact canonical round trip to reject aliases and non-canonical fields.
	var generic any
	if err := strictjson.ValidateExactFields(raw, &generic, 64); err != nil {
		return err
	}
	if err := decodeStrict(raw, target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil || !bytes.Equal(compact.Bytes(), canonical) {
		return errors.New("golden report is not the canonical v3 projection")
	}
	return nil
}

func applyThresholds(decision *gateDecision, manifest inspectioneval.Manifest, report inspectioneval.EvaluationReport, thresholds gateThresholds) {
	if report.PrimarySplit != inspectioneval.SplitTest || report.Overall.Records < thresholds.MinimumTestRecords {
		decision.Failures = append(decision.Failures, "minimum_test_records")
	}
	if len(report.BySite) < thresholds.MinimumTestSites {
		decision.Failures = append(decision.Failures, "minimum_test_sites")
	}
	strategies := make(map[inspectioneval.Strategy]struct{})
	kinds := make(map[inspectioneval.ResultKind]struct{})
	deliveries := make(map[string]struct{})
	helpful, unhelpful, missing, unknown, failed, retried := 0, 0, 0, 0, 0, 0
	for _, record := range manifest.Records {
		if record.Split != inspectioneval.SplitTest {
			continue
		}
		kinds[record.Expected.Kind] = struct{}{}
		strategies[record.Strategy] = struct{}{}
		if _, counted := deliveries[record.DeliveryPseudonym]; counted {
			continue
		}
		deliveries[record.DeliveryPseudonym] = struct{}{}
		if record.Feedback == nil {
			missing++
		} else if record.Feedback.Helpful {
			helpful++
		} else {
			unhelpful++
		}
		switch record.DeliveryStatus {
		case inspectioneval.DeliveryUnknown:
			unknown++
		case inspectioneval.DeliveryFailed:
			failed++
		}
		if record.DeliveryAttempts > 1 || record.ReconciliationAttempts > 0 {
			retried++
		}
	}
	for _, required := range thresholds.RequiredStrategies {
		if _, ok := strategies[required]; !ok {
			decision.Failures = append(decision.Failures, "missing_strategy:"+string(required))
		}
	}
	for _, required := range thresholds.RequiredResultKinds {
		if _, ok := kinds[required]; !ok {
			decision.Failures = append(decision.Failures, "missing_result_kind:"+string(required))
		}
	}
	checkMinimumRatio(decision, "minimum_delivery_reliability", report.Overall.Delivery.Reliability.Value, thresholds.MinimumDeliveryReliability)
	checkMaximumRatio(decision, "maximum_delivery_unknown_rate", report.Overall.Delivery.UnknownRate.Value, thresholds.MaximumDeliveryUnknownRate)
	checkMaximumRatio(decision, "maximum_false_clear_rate", report.Overall.Classification.FalseClearRate.Value, thresholds.MaximumFalseClearRate)
	if helpful < thresholds.MinimumHelpfulFeedback {
		decision.Failures = append(decision.Failures, "minimum_helpful_feedback")
	}
	if unhelpful < thresholds.MinimumUnhelpfulFeedback {
		decision.Failures = append(decision.Failures, "minimum_unhelpful_feedback")
	}
	if missing < thresholds.MinimumMissingFeedback {
		decision.Failures = append(decision.Failures, "minimum_missing_feedback")
	}
	if unknown < thresholds.MinimumUnknownDeliveries {
		decision.Failures = append(decision.Failures, "minimum_unknown_deliveries")
	}
	if failed < thresholds.MinimumFailedDeliveries {
		decision.Failures = append(decision.Failures, "minimum_failed_deliveries")
	}
	if retried < thresholds.MinimumRetriedDeliveries {
		decision.Failures = append(decision.Failures, "minimum_retried_deliveries")
	}
	sort.Strings(decision.Failures)
}

func checkMinimumRatio(decision *gateDecision, code string, actual *float64, threshold float64) {
	if actual == nil || *actual < threshold {
		decision.Failures = append(decision.Failures, code)
	}
}

func checkMaximumRatio(decision *gateDecision, code string, actual *float64, threshold float64) {
	if actual == nil || *actual > threshold {
		decision.Failures = append(decision.Failures, code)
	}
}

func summarize(manifest inspectioneval.Manifest) validationSummary {
	result := validationSummary{Splits: make(map[string]int), ResultKinds: make(map[string]int)}
	criteria := make(map[string]struct{})
	strategies := make(map[inspectioneval.Strategy]struct{})
	groups := make(map[string]struct{})
	sites := make(map[string]struct{})
	for _, record := range manifest.Records {
		result.Records++
		result.Splits[string(record.Split)]++
		result.ResultKinds[string(record.Expected.Kind)]++
		criteria[record.CriterionID] = struct{}{}
		strategies[record.Strategy] = struct{}{}
		groups[record.GroupKey] = struct{}{}
		sites[record.SitePseudonym] = struct{}{}
		if record.ObservationMode == inspectioneval.ObservationTemporary {
			result.TemporaryObservations++
		}
		if record.CalibrationRole == inspectioneval.CalibrationThresholdFit {
			switch record.Split {
			case inspectioneval.SplitTrain:
				result.ThresholdFitTrain++
			case inspectioneval.SplitValidation:
				result.ThresholdFitValidation++
			}
		}
	}
	result.Criteria = len(criteria)
	result.Strategies = len(strategies)
	result.Groups = len(groups)
	result.Sites = len(sites)
	return result
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, errors.New("file is unavailable or outside its size bound")
	}
	return raw, nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func validStrategy(value inspectioneval.Strategy) bool {
	switch value {
	case inspectioneval.StrategyExistingTaskRead, inspectioneval.StrategySnapshotAnalysis, inspectioneval.StrategyClipAnalysis, inspectioneval.StrategyHybridAnalysis:
		return true
	default:
		return false
	}
}

func validResultKind(value inspectioneval.ResultKind) bool {
	switch value {
	case inspectioneval.ResultClassification, inspectioneval.ResultEnum, inspectioneval.ResultStructured, inspectioneval.ResultMetric,
		inspectioneval.ResultCount, inspectioneval.ResultDetection, inspectioneval.ResultEvent:
		return true
	default:
		return false
	}
}
