package inspectioneval

import (
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/dataset"
)

func TestResultValueFromAnalysisUsesCoreTypedShape(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	mediaRef := "media_0123456789abcdef0123456789abcdef"
	result := inspection.AnalysisResult{
		Binding: inspection.ResultBinding{
			ResultID: "result-1", RunID: "run-1", StepID: "step-1", TargetID: "target-1",
			CriterionID: "criterion-1", CriterionVersion: "1", OutputKind: inspection.ResultDetection,
			OutputSchemaVersion: "detection.v2", Usage: inspection.ResultUsageInspection,
			TimeWindow: inspection.ResultTimeWindow{StartAt: now, EndAt: now},
			SourceMedia: []inspection.ResultSourceMedia{{
				SourceRef: "source-1", MediaRef: mediaRef, SHA256: strings.Repeat("a", 64),
				CapturedAt: now, FreshnessMS: 1000, SampleOrdinal: 1,
			}},
		},
		Assessment: inspection.AssessmentNeedsAttention, Observability: inspection.ResultFullyVisible,
		Value: &inspection.ResultValue{Kind: inspection.ResultDetection, Detection: &inspection.DetectionValue{Objects: []inspection.DetectionObject{{
			Label: "spill", Region: inspection.NormalizedRegion{X: 0.1, Y: 0.2, Width: 0.3, Height: 0.4}, EvidenceRef: mediaRef,
		}}}},
		EvidenceRefs: []string{mediaRef}, ReasonCodes: []string{"criterion_violated"}, Limitations: []string{},
		Analyzer: inspection.ResultAnalyzer{
			Kind: inspection.ResultAnalyzerFixture, AdapterVersion: "adapter.v2", ModelPolicy: "fixture-policy",
			ResolvedModelVersion: "fixture-v2", PromptTemplateID: "prompt-template", PromptTemplateVersion: "2",
			PromptTemplateSHA256: strings.Repeat("b", 64),
		},
		Execution: inspection.ResultExecution{Attempt: 1, StartedAt: now.Add(time.Second), CompletedAt: now.Add(2 * time.Second), LatencyMS: 1000},
		Integrity: inspection.ResultIntegrity{RawOutputSHA256: strings.Repeat("c", 64), ContractSHA256: strings.Repeat("d", 64)},
	}
	projected, err := ResultValueFromAnalysis(result)
	if err != nil {
		t.Fatal(err)
	}
	if projected.Kind != ResultDetection || projected.State != ValuePresent || projected.Detection == nil ||
		len(projected.Detection.Objects) != 1 || projected.Detection.Objects[0].Label != "spill" || projected.Detection.Objects[0].Region.Width != 0.3 {
		t.Fatalf("projected=%+v", projected)
	}
}

func TestResultValueFromDatasetLabelUsesMetricAndAbstentionVocabulary(t *testing.T) {
	metric, err := ResultValueFromDatasetLabel(dataset.Label{Kind: dataset.LabelMetric, Metric: &dataset.MetricLabel{Value: 0.75, Unit: "ratio"}})
	if err != nil || metric.Kind != ResultMetric || metric.Metric == nil || metric.Metric.Unit != "ratio" {
		t.Fatalf("metric=%+v err=%v", metric, err)
	}
	uncertain, err := ResultValueFromDatasetLabel(dataset.Label{Kind: dataset.LabelClassification, Classification: &dataset.ClassificationLabel{Value: dataset.ClassificationUncertain}})
	if err != nil || uncertain.Kind != ResultClassification || uncertain.State != ValueUncertain || uncertain.Classification != nil {
		t.Fatalf("uncertain=%+v err=%v", uncertain, err)
	}
}

func TestResultValueFromDatasetLabelProjectsEnumAndStructuredValues(t *testing.T) {
	state := "open"
	count := int64(2)
	value, err := ResultValueFromDatasetLabel(dataset.Label{
		Kind: dataset.LabelStructured,
		Structured: &dataset.StructuredLabel{Fields: []dataset.StructuredField{
			{Name: "count", Value: dataset.StructuredScalar{Kind: dataset.StructuredInteger, Integer: &count}},
			{Name: "state", Value: dataset.StructuredScalar{Kind: dataset.StructuredEnum, Enum: &state}},
		}},
	})
	if err != nil || value.Kind != ResultStructured || value.Structured == nil || len(value.Structured.Fields) != 2 {
		t.Fatalf("structured=%+v err=%v", value, err)
	}
	enum, err := ResultValueFromDatasetLabel(dataset.Label{Kind: dataset.LabelEnum, Enum: &dataset.EnumLabel{Value: "open"}})
	if err != nil || enum.Kind != ResultEnum || enum.Enum == nil || enum.Enum.Value != "open" {
		t.Fatalf("enum=%+v err=%v", enum, err)
	}
}
