package analysiscontract

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const examplePath = "../../../docs/inspection/examples/analysis-result.example.json"

func TestDocumentationExampleSatisfiesTypedContract(t *testing.T) {
	envelope := readExample(t)
	if err := envelope.ValidateBindings(trustedFrom(envelope)); err != nil {
		t.Fatalf("ValidateBindings(documentation example) error = %v", err)
	}
	result, err := envelope.TypedResult()
	if err != nil {
		t.Fatalf("TypedResult() error = %v", err)
	}
	if result.Binding.OutputKind != inspection.ResultDetection || result.Value == nil || result.Value.Detection == nil {
		t.Fatalf("documentation example did not produce a detection union: %#v", result.Value)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"summary", "description", "displayText", "rtsp://", "imageBase64"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("standard typed result leaked unrestricted prose field %q: %s", forbidden, raw)
		}
	}
}

func TestAllTypedUnionMembersBuildAndRoundTrip(t *testing.T) {
	when := fixtureCapturedAt()
	zero := int64(0)
	truth := true
	values := map[inspection.ResultKind]*inspection.ResultValue{
		inspection.ResultClassification: {Kind: inspection.ResultClassification, Classification: &inspection.ClassificationValue{Label: "occupied", Score: floatPtr(.91)}},
		inspection.ResultEnum:           {Kind: inspection.ResultEnum, Enum: &inspection.EnumValue{Value: "aligned"}},
		inspection.ResultStructured: {Kind: inspection.ResultStructured, Structured: &inspection.StructuredValue{Fields: []inspection.StructuredField{
			{Name: "blocked", Value: inspection.StructuredScalar{Kind: inspection.StructuredBoolean, Boolean: &truth}},
			{Name: "severity", Value: inspection.StructuredScalar{Kind: inspection.StructuredEnum, Enum: stringPtr("low")}},
			{Name: "items", Value: inspection.StructuredScalar{Kind: inspection.StructuredInteger, Integer: &zero}},
		}}},
		inspection.ResultMetric:    {Kind: inspection.ResultMetric, Metric: &inspection.MetricValue{Value: 21.5, Unit: "celsius"}},
		inspection.ResultDetection: fixtureDetectionValue(),
		inspection.ResultCount:     {Kind: inspection.ResultCount, Count: &inspection.CountValue{Value: 3, Label: "person", Unit: "people"}},
		inspection.ResultEvent:     {Kind: inspection.ResultEvent, Event: &inspection.EventValue{Type: "queue.formed", State: inspection.EventOccurred, OccurredAt: when, EvidenceRef: fixtureMediaRef()}},
	}
	for kind, value := range values {
		t.Run(string(kind), func(t *testing.T) {
			envelope := fixtureEnvelope(kind, value)
			raw, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseEnvelope(raw)
			if err != nil {
				t.Fatalf("ParseEnvelope() error = %v", err)
			}
			result, err := parsed.TypedResult()
			if err != nil {
				t.Fatalf("TypedResult() error = %v", err)
			}
			if result.Value == nil || result.Value.Kind != kind || result.Binding.OutputKind != kind {
				t.Fatalf("typed result kind = %#v, want %q", result.Value, kind)
			}
		})
	}
}

func TestUnionAndEvidenceShapesFailClosed(t *testing.T) {
	tests := map[string]func(*Envelope){
		"multiple union members":     func(e *Envelope) { e.Candidate.Value.Enum = &inspection.EnumValue{Value: "extra"} },
		"tag mismatch":               func(e *Envelope) { e.Candidate.Value.Kind = inspection.ResultEnum },
		"contract kind mismatch":     func(e *Envelope) { e.Binding.OutputKind = inspection.ResultMetric },
		"foreign candidate evidence": func(e *Envelope) { e.Candidate.EvidenceRefs[0] = "media_foreign_0001" },
		"foreign detection evidence": func(e *Envelope) { e.Candidate.Value.Detection.Objects[0].EvidenceRef = "media_foreign_0001" },
		"capture outside window": func(e *Envelope) {
			e.Binding.SourceMedia[0].CapturedAt = e.Binding.TimeWindow.StartAt.Add(-time.Second)
		},
		"window after execution": func(e *Envelope) { e.Binding.TimeWindow.EndAt = e.Execution.CompletedAt.Add(time.Second) },
		"persistent write":       func(e *Envelope) { e.Execution.PersistentConfigWrites = 1 },
		"invalid region": func(e *Envelope) {
			e.Candidate.Value.Detection.Objects[0].Region.X = .9
			e.Candidate.Value.Detection.Objects[0].Region.Width = .2
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
			mutate(&envelope)
			if err := envelope.Validate(); err == nil {
				t.Fatalf("Envelope.Validate(%s) unexpectedly succeeded", name)
			}
		})
	}
}

func TestInconclusiveResultCannotSmuggleTypedValue(t *testing.T) {
	envelope := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
	envelope.Candidate.Assessment = inspection.AssessmentUncertain
	envelope.Candidate.Observability = inspection.ResultPartiallyVisible
	envelope.Candidate.ReasonCodes = []ReasonCode{ReasonInsufficientEvidence}
	envelope.Candidate.Limitations = []Limitation{LimitationInsufficientSamples}
	if err := envelope.Validate(); err == nil {
		t.Fatal("uncertain candidate retained a typed value")
	}
	envelope.Candidate.Value = nil
	envelope.Candidate.EvidenceRefs = []string{}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("valid uncertain candidate rejected: %v", err)
	}
}

func TestTemporaryDisplayRequiresExactTrustedPolicy(t *testing.T) {
	standard := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
	standard.Candidate.DisplayText = "画面中央可见一处待处理物体。"
	if err := standard.Validate(); err == nil {
		t.Fatal("standard inspection accepted model display text")
	}

	temporary := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
	temporary.Binding.Usage = inspection.ResultUsageTemporaryObservation
	temporary.Candidate.DisplayText = "画面中央可见一处待处理物体。"
	temporary.DisplayPolicy = &DisplayPolicy{PolicyRef: "temporary.zh", Locale: "zh-cn", MaxRunes: 64}
	result, err := temporary.TypedResult()
	if err != nil {
		t.Fatalf("TypedResult() error = %v", err)
	}
	if result.Display == nil || result.Display.PolicyRef != "temporary.zh" {
		t.Fatalf("temporary display policy was not preserved: %#v", result.Display)
	}

	temporary.Candidate.DisplayText = "inspect rtsp://camera.local/live"
	if err := temporary.Validate(); err == nil {
		t.Fatal("temporary display accepted a protected endpoint")
	}
}

func TestValidateBindingsRejectsTrustedFieldTampering(t *testing.T) {
	tests := map[string]func(*Envelope){
		"run":         func(e *Envelope) { e.Binding.RunID = "run_other_0001" },
		"criterion":   func(e *Envelope) { e.Binding.CriterionVersion = "2" },
		"source":      func(e *Envelope) { e.Binding.SourceMedia[0].SourceRef = "source_other_0001" },
		"media hash":  func(e *Envelope) { e.Binding.SourceMedia[0].SHA256 = strings.Repeat("a", 64) },
		"time window": func(e *Envelope) { e.Binding.TimeWindow.StartAt = e.Binding.TimeWindow.StartAt.Add(-time.Second) },
		"analyzer":    func(e *Envelope) { e.Analyzer.AdapterVersion = "2" },
		"execution":   func(e *Envelope) { e.Execution.Attempt = 2 },
		"integrity":   func(e *Envelope) { e.Integrity.ContractSHA256 = strings.Repeat("a", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
			trusted := trustedFrom(envelope)
			mutate(&envelope)
			if err := envelope.ValidateBindings(trusted); err == nil {
				t.Fatalf("ValidateBindings(%s) unexpectedly succeeded", name)
			}
		})
	}
}

func TestStrictCandidateParsingRejectsEnvelopeFieldsAndMalformedJSON(t *testing.T) {
	envelope := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
	raw, err := json.Marshal(envelope.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCandidate(raw); err != nil {
		t.Fatalf("ParseCandidate() error = %v", err)
	}

	unknown := append(raw[:len(raw)-1], []byte(`,"runId":"run_model_0001"}`)...)
	duplicate := bytes.Replace(raw, []byte(`"assessment":`), []byte(`"assessment":"meets_rule","assessment":`), 1)
	caseAlias := bytes.Replace(raw, []byte(`"assessment":`), []byte(`"Assessment":`), 1)
	nullValue := bytes.Replace(raw, []byte(`"value":{`), []byte(`"value":null,"ignored":{`), 1)
	multiple := append(append([]byte(nil), raw...), []byte(` {}`)...)
	oversized := append(raw[:len(raw)-1], []byte(`,"displayText":"`+strings.Repeat("x", MaxJSONBytes)+`"}`)...)
	for name, invalid := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "case alias": caseAlias, "null": nullValue,
		"multiple": multiple, "oversized": oversized, "array": []byte(`[]`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCandidate(invalid); err == nil {
				t.Fatalf("ParseCandidate(%s) unexpectedly succeeded", name)
			}
		})
	}
}

func TestBuildFromRawBindsDigestAndClonesInputs(t *testing.T) {
	example := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
	raw, err := json.Marshal(example.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	trusted := trustedFrom(example)
	trusted.Integrity.RawOutputSHA256 = ""
	envelope, err := BuildFromRaw(trusted, raw)
	if err != nil {
		t.Fatalf("BuildFromRaw() error = %v", err)
	}
	if envelope.Integrity.RawOutputSHA256 != Digest(raw) {
		t.Fatal("raw output digest was not bound")
	}

	trusted.Binding.SourceMedia[0].MediaRef = "media_mutated_0001"
	example.Candidate.Value.Detection.Objects[0].Label = "mutated"
	if envelope.Binding.SourceMedia[0].MediaRef != fixtureMediaRef() || envelope.Candidate.Value.Detection.Objects[0].Label != "residue" {
		t.Fatal("BuildFromRaw retained caller-owned aliases")
	}
}

func TestBuildPreservesRequiredEmptyCandidateCollections(t *testing.T) {
	envelope := fixtureEnvelope(inspection.ResultDetection, fixtureDetectionValue())
	envelope.Candidate.Assessment = inspection.AssessmentMeetsRule
	envelope.Candidate.Observability = inspection.ResultFullyVisible
	envelope.Candidate.Value = &inspection.ResultValue{Kind: inspection.ResultDetection, Detection: &inspection.DetectionValue{Objects: []inspection.DetectionObject{}}}
	envelope.Candidate.Limitations = []Limitation{}
	envelope.Candidate.ReasonCodes = []ReasonCode{ReasonCriterionMet}
	built, err := Build(trustedFrom(envelope), envelope.Candidate)
	if err != nil {
		t.Fatalf("Build() rejected required empty collections: %v", err)
	}
	if built.Candidate.Limitations == nil || built.Candidate.Value.Detection.Objects == nil {
		t.Fatal("Build() collapsed required empty collections to null")
	}
}

func TestDocumentationSchemaMatchesVersionAndUnionKinds(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/inspection/schema/analysis-result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("analysis-result.schema.json is not valid JSON")
	}
	if !bytes.Contains(raw, []byte(`"const": "inspection.analysis.v2"`)) {
		t.Fatal("schema does not freeze inspection.analysis.v2")
	}
	for _, kind := range []inspection.ResultKind{inspection.ResultClassification, inspection.ResultEnum, inspection.ResultStructured, inspection.ResultMetric, inspection.ResultDetection, inspection.ResultCount, inspection.ResultEvent} {
		if !bytes.Contains(raw, []byte(`"`+string(kind)+`"`)) {
			t.Fatalf("schema is missing union kind %q", kind)
		}
	}
}

func readExample(t *testing.T) Envelope {
	t.Helper()
	raw, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func fixtureEnvelope(kind inspection.ResultKind, value *inspection.ResultValue) Envelope {
	captured := fixtureCapturedAt()
	started := captured.Add(time.Second)
	completed := started.Add(3 * time.Second)
	return Envelope{
		SchemaVersion: SchemaVersion,
		Binding: inspection.ResultBinding{
			ResultID: "result_demo_0001", RunID: "run_demo_0001", StepID: "step_demo_0001",
			TargetID: "dining-east", CriterionID: "visible-table-cleanliness", CriterionVersion: "1",
			OutputKind: kind, OutputSchemaVersion: "finding.v2", Usage: inspection.ResultUsageInspection,
			TimeWindow: inspection.ResultTimeWindow{StartAt: captured, EndAt: captured},
			SourceMedia: []inspection.ResultSourceMedia{{
				SourceRef: "source_demo_0001", MediaRef: fixtureMediaRef(), SHA256: strings.Repeat("8", 64),
				CapturedAt: captured, FreshnessMS: 1000, SampleOrdinal: 1,
			}},
		},
		Analyzer: inspection.ResultAnalyzer{
			Kind: inspection.ResultAnalyzerFixture, AdapterVersion: "1.0.0", ModelPolicy: "fixture-visible-hygiene",
			ResolvedModelVersion: "fixture-v2", PromptTemplateID: "visible-hygiene-json",
			PromptTemplateVersion: "2.0.0", PromptTemplateSHA256: strings.Repeat("f", 64),
		},
		Candidate: Candidate{
			Assessment: inspection.AssessmentNeedsAttention, Observability: inspection.ResultPartiallyVisible,
			Confidence: floatPtr(.91), Value: cloneResultValue(value), EvidenceRefs: []string{fixtureMediaRef()},
			Limitations: []Limitation{LimitationOcclusion}, ReasonCodes: []ReasonCode{ReasonCriterionViolated},
		},
		Execution: inspection.ResultExecution{
			Attempt: 1, StartedAt: started, CompletedAt: completed, LatencyMS: 3000,
			TemporaryResourcesCreated: 1, TemporaryResourcesCleaned: 1, PersistentConfigWrites: 0,
		},
		Integrity: inspection.ResultIntegrity{RawOutputSHA256: strings.Repeat("d", 64), ContractSHA256: strings.Repeat("3", 64)},
	}
}

func fixtureDetectionValue() *inspection.ResultValue {
	return &inspection.ResultValue{Kind: inspection.ResultDetection, Detection: &inspection.DetectionValue{Objects: []inspection.DetectionObject{{
		Label: "residue", Score: floatPtr(.91), Region: inspection.NormalizedRegion{X: .38, Y: .44, Width: .24, Height: .18}, EvidenceRef: fixtureMediaRef(),
	}}}}
}

func trustedFrom(envelope Envelope) TrustedFields {
	return TrustedFields{
		Binding: cloneBinding(envelope.Binding), Analyzer: envelope.Analyzer, Execution: envelope.Execution,
		Integrity: envelope.Integrity, DisplayPolicy: cloneDisplayPolicy(envelope.DisplayPolicy),
	}
}

func fixtureCapturedAt() time.Time    { return time.Date(2026, 7, 18, 3, 0, 4, 0, time.UTC) }
func fixtureMediaRef() string         { return "media_demo_frame_0001" }
func floatPtr(value float64) *float64 { return &value }
func stringPtr(value string) *string  { return &value }
