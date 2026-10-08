package inspectioneval

import (
	"math"
	"strings"
	"testing"
)

func TestEvaluateSyntheticV3UsesTestOnlyPrimaryMetricsAndAllRequiredStrata(t *testing.T) {
	report, err := Evaluate(loadSynthetic(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != ReportSchema || report.PrimarySplit != SplitTest || report.Overall.Records != 9 {
		t.Fatalf("report=%#v", report)
	}
	metrics := report.Overall
	assertRatio(t, "coverage", metrics.Coverage.Coverage, 7, 8, 7.0/8.0)
	classification := metrics.Classification
	if classification.EligibleExpectedDecisions != 1 || classification.Covered != 0 || classification.Abstained != 1 || classification.ExcludedExpectedAbstention != 1 ||
		classification.TruePositive != 0 || classification.FalseNegative != 1 || classification.TrueNegative != 0 || classification.FalseClear != 0 {
		t.Fatalf("classification=%#v", classification)
	}
	assertRatio(t, "false clear", classification.FalseClearRate, 0, 1, 0)
	assertRatio(t, "classification abstention", classification.AbstentionRate, 1, 1, 1)
	assertRatio(t, "enum accuracy", metrics.Enum.Accuracy, 1, 1, 1)
	assertRatio(t, "structured field agreement", metrics.Structured.FieldAgreement, 1, 2, 0.5)
	if math.Abs(value(metrics.Metric.MAE)-0.1) > 1e-12 || value(metrics.Count.MAE) != 2 {
		t.Fatalf("metric=%#v count=%#v", metrics.Metric, metrics.Count)
	}
	if metrics.Detection.TruePositive != 1 || metrics.Detection.FalsePositive != 1 || metrics.Detection.FalseNegative != 1 || math.Abs(value(metrics.Detection.MeanMatchedIoU)-1) > 1e-12 {
		t.Fatalf("detection=%#v", metrics.Detection)
	}
	assertRatio(t, "detection precision", metrics.Detection.Precision, 1, 2, 0.5)
	assertRatio(t, "detection recall", metrics.Detection.Recall, 1, 2, 0.5)
	if metrics.Event.TruePositive != 1 || metrics.Event.FalsePositive != 1 {
		t.Fatalf("event=%#v", metrics.Event)
	}
	assertRatio(t, "event precision", metrics.Event.Precision, 1, 2, 0.5)
	assertRatio(t, "delivery reliability", metrics.Delivery.Reliability, 6, 18, 1.0/3.0)
	assertRatio(t, "delivery unknown", metrics.Delivery.UnknownRate, 2, 18, 1.0/9.0)
	if metrics.Delivery.ReconciliationAttempts != 3 || metrics.Feedback.Responses != 2 || metrics.Feedback.Helpful != 1 || metrics.Feedback.Unhelpful != 1 {
		t.Fatalf("delivery=%#v feedback=%#v", metrics.Delivery, metrics.Feedback)
	}
	assertRatio(t, "temporary review agreement", metrics.Review.Agreement, 0, 1, 0)
	if metrics.Latency.EndToEnd.Samples != 9 || value(metrics.Latency.EndToEnd.Minimum) != 200 || value(metrics.Latency.EndToEnd.Maximum) != 1100 || math.Abs(value(metrics.Latency.EndToEnd.Mean)-5500.0/9.0) > 1e-12 || value(metrics.Latency.EndToEnd.P50) != 600 || value(metrics.Latency.EndToEnd.P95) != 1100 {
		t.Fatalf("latency=%#v", metrics.Latency.EndToEnd)
	}
	if len(report.ByStrategy) != 4 || len(report.ByCriterion) != 8 || len(report.BySourceKind) != 5 || len(report.ByMediaKind) != 4 ||
		len(report.BySite) != 2 || len(report.BySource) != 9 || len(report.BySceneStratum) != 4 || len(report.BySplit) != 3 {
		t.Fatalf("strata sizes: strategy=%d criterion=%d sourceKind=%d mediaKind=%d site=%d source=%d scene=%d split=%d", len(report.ByStrategy), len(report.ByCriterion), len(report.BySourceKind), len(report.ByMediaKind), len(report.BySite), len(report.BySource), len(report.BySceneStratum), len(report.BySplit))
	}
	assertSliceKeys(t, report.ByStrategy, []string{"clip_analysis", "existing_task_read", "hybrid_analysis", "snapshot_analysis"})
	assertSliceKeys(t, report.BySite, []string{"site_1111111111111111", "site_2222222222222222"})
	assertSliceKeys(t, report.BySceneStratum, []string{"dining-area", "high-activity", "low-activity", "transition"})
	assertSliceKeys(t, report.BySplit, []string{"test", "train", "validation"})
	if report.Calibration.TrainRecords != 1 || report.Calibration.ValidationRecords != 1 || report.Calibration.ThresholdFitTrain != 1 || report.Calibration.ThresholdFitValidation != 1 || report.Calibration.ThresholdFitTest != 0 {
		t.Fatalf("calibration=%#v", report.Calibration)
	}
}

func TestEvaluateUndefinedMetricsRemainNull(t *testing.T) {
	record := baseRecord(t, "undefined-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.Expected = ResultValue{Kind: ResultClassification, State: ValueUnsupported}
	record.Observed = ResultValue{Kind: ResultClassification, State: ValueUnsupported}
	report, err := Evaluate(Manifest{Records: []Record{record}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall.Classification.Precision.Value != nil || report.Overall.Count.MAE != nil || report.Overall.Detection.MeanMatchedIoU != nil {
		t.Fatalf("undefined metrics=%#v", report.Overall)
	}
}

func TestEvaluateCountsOneDeliveryAndFeedbackOnceAcrossMultipleCriteria(t *testing.T) {
	first := baseRecord(t, "delivery-group-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	second := baseRecord(t, "delivery-group-b", SplitTest, "source_2222222222222222", mustTime(t, "2026-07-01T09:00:00Z"))
	second.CriterionID, second.ResultSchemaRef = "another-criterion", "another-classification-v3"
	second.DeliveryPseudonym, second.DeliveryEvidenceSHA256 = first.DeliveryPseudonym, first.DeliveryEvidenceSHA256
	feedback := &FeedbackSummary{RecordSHA256: strings.Repeat("a", 64), Helpful: true, ReceivedAt: mustTime(t, "2026-07-01T10:00:00Z")}
	first.Feedback, second.Feedback = feedback, feedback
	report, err := Evaluate(Manifest{Records: []Record{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall.Records != 2 || report.Overall.Delivery.Delivered != 1 || report.Overall.Delivery.Attempts != 1 ||
		report.Overall.Feedback.Responses != 1 || report.Overall.Latency.Delivery.Samples != 1 {
		t.Fatalf("delivery=%#v feedback=%#v latency=%#v", report.Overall.Delivery, report.Overall.Feedback, report.Overall.Latency.Delivery)
	}
}

func TestEvaluateKeepsCriterionVersionsSeparate(t *testing.T) {
	first := baseRecord(t, "criterion-v1", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	second := baseRecord(t, "criterion-v2", SplitTest, "source_2222222222222222", mustTime(t, "2026-07-01T09:00:00Z"))
	second.CriterionVersion, second.ResultSchemaRef = 2, "classification-v4"
	report, err := Evaluate(Manifest{Records: []Record{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.ByCriterion) != 2 || report.ByCriterion[0].CriterionVersion != 1 || report.ByCriterion[1].CriterionVersion != 2 {
		t.Fatalf("criterion slices=%#v", report.ByCriterion)
	}
}

func TestDetectionIoUUsesDeterministicThreshold(t *testing.T) {
	left := NormalizedRegion{X: 0, Y: 0, Width: 0.5, Height: 0.5}
	if got := intersectionOverUnion(left, left); got != 1 {
		t.Fatalf("iou=%v", got)
	}
	right := NormalizedRegion{X: 0.25, Y: 0.25, Width: 0.5, Height: 0.5}
	if got := intersectionOverUnion(left, right); math.Abs(got-1.0/7.0) > 1e-12 {
		t.Fatalf("iou=%v", got)
	}
}

func TestDetectionMatchingMaximizesCardinalityBeforeTotalIoU(t *testing.T) {
	record := baseRecord(t, "matching-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.Strategy = StrategyExistingTaskRead
	record.SourceKind = SourceTaskEvidence
	record.MediaKind = MediaDetection
	record.Expected = ResultValue{Kind: ResultDetection, State: ValuePresent, Detection: &DetectionResult{Objects: []DetectionObject{
		{Label: "object", Region: NormalizedRegion{X: 0, Y: 0, Width: 0.6, Height: 1}},
		{Label: "object", Region: NormalizedRegion{X: 0.19, Y: 0, Width: 0.6, Height: 1}},
	}}}
	record.Observed = ResultValue{Kind: ResultDetection, State: ValuePresent, Detection: &DetectionResult{Objects: []DetectionObject{
		{Label: "object", Region: NormalizedRegion{X: 0, Y: 0, Width: 0.4, Height: 1}},
		{Label: "object", Region: NormalizedRegion{X: 0, Y: 0, Width: 0.6, Height: 1}},
	}}}
	report, err := Evaluate(Manifest{Records: []Record{record}})
	if err != nil {
		t.Fatal(err)
	}
	got := report.Overall.Detection
	if got.TruePositive != 2 || got.FalsePositive != 0 || got.FalseNegative != 0 ||
		got.MeanMatchedIoU == nil || math.Abs(*got.MeanMatchedIoU-(281.0/474.0)) > 1e-12 {
		t.Fatalf("optimal matching=%#v", got)
	}
}

func assertRatio(t *testing.T, name string, got Ratio, numerator, denominator int, want float64) {
	t.Helper()
	if got.Numerator != numerator || got.Denominator != denominator || got.Value == nil || math.Abs(*got.Value-want) > 1e-12 {
		t.Fatalf("%s=%#v want %d/%d", name, got, numerator, denominator)
	}
}

func value(pointer *float64) float64 {
	if pointer == nil {
		return math.NaN()
	}
	return *pointer
}

func assertSliceKeys(t *testing.T, values []SliceMetrics, expected []string) {
	t.Helper()
	if len(values) != len(expected) {
		t.Fatalf("slice keys=%v want=%v", values, expected)
	}
	for index := range values {
		if values[index].Key != expected[index] {
			t.Fatalf("slice key[%d]=%q want=%q", index, values[index].Key, expected[index])
		}
	}
}
