package inspectioneval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadSyntheticV3Fixture(t *testing.T) {
	manifest := loadSynthetic(t)
	if len(manifest.Records) != 11 || manifest.Records[0].Schema != RecordSchema || manifest.Records[0].SourcePseudonym != "source_1111111111111111" {
		t.Fatalf("manifest=%#v", manifest)
	}
}

func TestLoadIsStrictAndRejectsV1OrPayloadFields(t *testing.T) {
	record := baseRecord(t, "strict-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string]func(string) string{
		"v2 schema": func(value string) string {
			return strings.Replace(value, RecordSchema, "cosmoedge.inspection.eval.record.v2", 1)
		},
		"stream url": func(value string) string { return strings.Replace(value, `{`, `{"streamUrl":"rtsp://secret",`, 1) },
		"base64":     func(value string) string { return strings.Replace(value, `{`, `{"base64":"AAAA",`, 1) },
		"duplicate": func(value string) string {
			return strings.Replace(value, `"recordId":"strict-a"`, `"recordId":"strict-a","recordId":"strict-b"`, 1)
		},
		"case alias": func(value string) string { return strings.Replace(value, `"recordId"`, `"RecordID"`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, loadErr := Load(strings.NewReader(mutation(string(raw)))); loadErr == nil {
				t.Fatal("incompatible or unsafe record was accepted")
			}
		})
	}
	old := `{"tenantPseudonym":"tenant-a","sitePseudonym":"site-a","camera":"camera-a","expectedLabel":"meets_rule"}`
	if _, err := Load(strings.NewReader(old)); err == nil {
		t.Fatal("old manifest shape was accepted")
	}
}

func TestValidateRejectsGroupAndAdjacentTimeLeakage(t *testing.T) {
	first := baseRecord(t, "leak-a", SplitTrain, "source_1111111111111111", mustTime(t, "2026-07-01T23:50:00Z"))
	second := baseRecord(t, "leak-b", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-02T00:10:00Z"))
	second.GroupKey = "group_2222222222222222"
	if err := Validate(Manifest{Records: []Record{first, second}}); err == nil || !strings.Contains(err.Error(), "within 24h") {
		t.Fatalf("temporal leakage error=%v", err)
	}
	second.SourcePseudonym = "source_2222222222222222"
	second.GroupKey = first.GroupKey
	if err := Validate(Manifest{Records: []Record{first, second}}); err == nil || !strings.Contains(err.Error(), "group crosses splits") {
		t.Fatalf("group leakage error=%v", err)
	}
}

func TestValidateRejectsTestCalibrationAndIncompleteTemporaryReview(t *testing.T) {
	record := baseRecord(t, "calibration-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.CalibrationRole = CalibrationThresholdFit
	if err := Validate(Manifest{Records: []Record{record}}); err == nil || !strings.Contains(err.Error(), "test records cannot") {
		t.Fatalf("calibration error=%v", err)
	}
	record.CalibrationRole = CalibrationNone
	record.ObservationMode = ObservationTemporary
	if err := Validate(Manifest{Records: []Record{record}}); err == nil || !strings.Contains(err.Error(), "complete v3 review") {
		t.Fatalf("temporary review error=%v", err)
	}
}

func TestValidateRejectsOpenOrConfusedResultUnion(t *testing.T) {
	record := baseRecord(t, "union-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.Observed.Count = &CountResult{Value: 1}
	if err := Validate(Manifest{Records: []Record{record}}); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("union error=%v", err)
	}
	record = baseRecord(t, "union-b", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.Observed = ResultValue{Kind: ResultClassification, State: ValueUncertain, Classification: &ClassificationResult{Value: ClassificationMeetsRule}}
	if err := Validate(Manifest{Records: []Record{record}}); err == nil || !strings.Contains(err.Error(), "abstention") {
		t.Fatalf("abstention union error=%v", err)
	}
}

func TestValidateBoundsCriteriaAndRejectsTimezoneDrift(t *testing.T) {
	records := make([]Record, 0, MaximumCriteria+1)
	for index := 0; index < MaximumCriteria+1; index++ {
		record := baseRecord(t, fmt.Sprintf("criterion-%03d", index), SplitTest, fmt.Sprintf("source_%016x", index+1), mustTime(t, "2026-07-01T09:00:00Z").Add(time.Duration(index)*48*time.Hour))
		record.CriterionID = fmt.Sprintf("criterion-%03d", index)
		record.GroupKey = fmt.Sprintf("group_%016x", index+1)
		records = append(records, record)
	}
	if err := Validate(Manifest{Records: records}); err == nil || !strings.Contains(err.Error(), "distinct criteria") {
		t.Fatalf("criteria error=%v", err)
	}
	first := baseRecord(t, "zone-a", SplitTrain, "source_aaaaaaaaaaaaaaaa", mustTime(t, "2026-07-01T09:00:00Z"))
	second := baseRecord(t, "zone-b", SplitTest, "source_bbbbbbbbbbbbbbbb", mustTime(t, "2026-07-03T09:00:00Z"))
	second.SiteTimezone = "Asia/Shanghai"
	if err := Validate(Manifest{Records: []Record{first, second}}); err == nil || !strings.Contains(err.Error(), "differs from line") {
		t.Fatalf("timezone error=%v", err)
	}
}

func TestValidateRejectsCriterionContractAndDeliveryEvidenceDrift(t *testing.T) {
	first := baseRecord(t, "contract-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	second := baseRecord(t, "contract-b", SplitTest, "source_2222222222222222", mustTime(t, "2026-07-01T09:00:00Z"))
	second.ResultSchemaRef = "drifted-classification-v3"
	if err := Validate(Manifest{Records: []Record{first, second}}); err == nil || !strings.Contains(err.Error(), "criterion contract differs") {
		t.Fatalf("criterion contract err=%v", err)
	}
	second = baseRecord(t, "delivery-b", SplitTest, "source_2222222222222222", mustTime(t, "2026-07-01T09:00:00Z"))
	second.CriterionID = "another-criterion"
	second.DeliveryPseudonym = first.DeliveryPseudonym
	if err := Validate(Manifest{Records: []Record{first, second}}); err == nil || !strings.Contains(err.Error(), "delivery evidence differs") {
		t.Fatalf("delivery evidence err=%v", err)
	}
}

func TestValidateRejectsFailedDeliveryWithoutExhaustedBudget(t *testing.T) {
	record := baseRecord(t, "failed-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.DeliveryStatus, record.DeliveryAttempts = DeliveryFailed, 7
	if err := Validate(Manifest{Records: []Record{record}}); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("failed delivery err=%v", err)
	}
}

func TestValidationErrorIsBounded(t *testing.T) {
	_, err := Load(strings.NewReader("{}"))
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Issues) < 8 || strings.Count(err.Error(), ";") > 8 {
		t.Fatalf("error=%v", err)
	}
}

func TestValidateRejectsV3ResourceLimitOverflow(t *testing.T) {
	record := baseRecord(t, "resource-a", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.SceneStrata = make([]string, 33)
	for index := range record.SceneStrata {
		record.SceneStrata[index] = fmt.Sprintf("scene-%03d", index)
	}
	if err := Validate(Manifest{Records: []Record{record}}); err == nil || !strings.Contains(err.Error(), "one to 32") {
		t.Fatalf("scene bound err=%v", err)
	}
	record = baseRecord(t, "resource-b", SplitTest, "source_1111111111111111", mustTime(t, "2026-07-01T09:00:00Z"))
	record.Expected = ResultValue{Kind: ResultDetection, State: ValuePresent, Detection: &DetectionResult{Objects: make([]DetectionObject, maximumDetections+1)}}
	record.Observed = record.Expected
	if err := Validate(Manifest{Records: []Record{record}}); err == nil || !strings.Contains(err.Error(), "detection result") {
		t.Fatalf("detection bound err=%v", err)
	}
}

func loadSynthetic(t *testing.T) Manifest {
	t.Helper()
	file, err := os.Open("testdata/synthetic.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	manifest, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func baseRecord(t *testing.T, id string, split Split, source string, captured time.Time) Record {
	t.Helper()
	deliveryEvidenceSHA256, err := digestValue("delivery-evidence-" + id)
	if err != nil {
		t.Fatal(err)
	}
	return Record{
		Schema: RecordSchema, RecordID: id,
		TenantPseudonym: "tenant_aaaaaaaaaaaaaaaa", SitePseudonym: "site_1111111111111111", SourcePseudonym: source,
		CapturedAt: captured, SiteTimezone: "UTC", SceneStrata: []string{"dining-busy"}, CriterionID: "visible-hygiene", CriterionVersion: 1, ResultSchemaRef: "classification-v3",
		Strategy: StrategySnapshotAnalysis, SourceKind: SourceCamera, MediaKind: MediaImage, Split: split,
		GroupKey: "group_1111111111111111", CalibrationRole: CalibrationNone, ObservationMode: ObservationStandard,
		Expected:          ResultValue{Kind: ResultClassification, State: ValuePresent, Classification: &ClassificationResult{Value: ClassificationNeedsAttention}},
		Observed:          ResultValue{Kind: ResultClassification, State: ValuePresent, Classification: &ClassificationResult{Value: ClassificationNeedsAttention}},
		Latencies:         Latencies{EndToEndMS: 100, AnalysisMS: 60, DeliveryMS: 20},
		DeliveryPseudonym: stableDeliveryPseudonym(id), DeliveryEvidenceSHA256: deliveryEvidenceSHA256,
		DeliveryStatus: DeliveryDelivered, DeliveryAttempts: 1,
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
