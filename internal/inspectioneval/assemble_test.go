package inspectioneval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/dataset"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

const assemblyMediaRef = "media_0123456789abcdef0123456789abcdef"

type assemblyDatasetRepository struct {
	value      dataset.Dataset
	receipt    dataset.CreateReceipt
	resolution dataset.CreateResolutionState
	err        error
}

func (r *assemblyDatasetRepository) ResolveCreate(_ context.Context, receipt dataset.CreateReceipt) (dataset.CreateResolution, error) {
	if receipt != r.receipt {
		return dataset.CreateResolution{State: dataset.CreateConflict}, r.err
	}
	return dataset.CreateResolution{State: r.resolution}, r.err
}
func (r *assemblyDatasetRepository) Get(context.Context, string, string, string, uint64) (dataset.Dataset, error) {
	return r.value, r.err
}

type assemblyDeliveryRepository struct {
	record delivery.Record
	err    error
}

func (r *assemblyDeliveryRepository) Get(_ context.Context, deliveryID string) (delivery.Record, error) {
	if r.err != nil || r.record.Message.DeliveryID != deliveryID {
		return delivery.Record{}, r.err
	}
	return r.record, nil
}

type assemblyRunBindingVerifier struct {
	want PublicRunBindingQuery
	err  error
}

type assemblyRuntimeEvidenceVerifier struct{ err error }

func (v assemblyRuntimeEvidenceVerifier) VerifyStandardEvidence(context.Context, StandardEvidence) error {
	return v.err
}
func (v assemblyRuntimeEvidenceVerifier) VerifyTemporaryEvidence(context.Context, temporary.Record) error {
	return v.err
}

type assemblyClock struct{ now time.Time }

func (c assemblyClock) Now() time.Time { return c.now }

func (v *assemblyRunBindingVerifier) VerifyPublicRunBinding(_ context.Context, query PublicRunBindingQuery) error {
	if v.err != nil {
		return v.err
	}
	if query != v.want {
		return errors.New("protected public run binding mismatch")
	}
	return nil
}

type assemblyFeedbackRepository struct {
	record FeedbackRecord
	found  bool
	err    error
}

func (r *assemblyFeedbackRepository) GetFeedback(_ context.Context, query FeedbackQuery) (FeedbackRecord, bool, error) {
	if r.err != nil || !r.found {
		return FeedbackRecord{}, false, r.err
	}
	return r.record, true, nil
}

type assemblyReviewRepository struct {
	observed    ResultValue
	adjudicated ResultValue
	reviewedAt  time.Time
	mutate      func(*TemporaryReviewRecord)
	duplicate   bool
	err         error
}

func (r *assemblyReviewRepository) ListTemporaryReviews(_ context.Context, query TemporaryReviewQuery) ([]TemporaryReviewRecord, error) {
	if r.err != nil {
		return nil, r.err
	}
	record := TemporaryReviewRecord{
		Schema: ReviewSchema, ReviewID: "review-one", DatasetID: query.DatasetID, DatasetRevision: query.DatasetRevision,
		DatasetItemID: query.DatasetItemID, AnnotationSHA256: query.AnnotationSHA256, RuntimeRunID: query.RuntimeRunID,
		RuntimeResultRef: query.RuntimeResultRef, RuntimeResultSHA256: query.RuntimeResultSHA256, MediaRef: query.MediaRef,
		MediaSHA256: query.MediaSHA256, SpecSHA256: query.SpecSHA256, ObservationSHA256: query.ObservationSHA256,
		Observed: r.observed, Adjudicated: r.adjudicated, PolicyRef: "temporary-review-v3",
		ReviewerPseudonym: "reviewer_aaaaaaaaaaaaaaaa", ReviewedAt: r.reviewedAt.UTC(),
	}
	if r.mutate != nil {
		r.mutate(&record)
	}
	record.RecordSHA256, _ = TemporaryReviewRecordSHA256(record)
	if r.duplicate {
		return []TemporaryReviewRecord{record, record}, nil
	}
	return []TemporaryReviewRecord{record}, nil
}

type assemblyReviewVerifier struct{ err error }

func (v assemblyReviewVerifier) VerifyTemporaryReview(context.Context, TemporaryReviewRecord) error {
	return v.err
}

func TestAssembleRecordUsesCommittedDatasetFrozenPlanActualDeliveryAttemptsAndTrustedFeedback(t *testing.T) {
	fixture := newStandardAssemblyFixture(t)
	deliveryRecord := fixture.repositories.Deliveries.(*assemblyDeliveryRepository).record
	feedback := FeedbackRecord{
		Schema: FeedbackSchema, FeedbackID: "feedback-one", PublicRunRef: fixture.input.Standard.PublicRunRef,
		ResultRef: deliveryRecord.Message.ResultRef, AudienceSHA256: deliveryRecord.Message.AudienceSHA256,
		Helpful: true, ReceivedAt: deliveryRecord.DeliveredAt.Add(time.Second),
	}
	feedback.RecordSHA256, _ = FeedbackProjectionSHA256(feedback)
	fixture.repositories.Feedback = &assemblyFeedbackRepository{record: feedback, found: true}

	record, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if record.Schema != RecordSchema || record.ObservationMode != ObservationStandard || record.Strategy != StrategySnapshotAnalysis ||
		record.SourceKind != SourceCamera || record.CriterionID != "surface-condition" || record.CriterionVersion != 1 ||
		record.ResultSchemaRef != "classification-v3" || len(record.SceneStrata) != 2 || record.SceneStrata[0] != "dining-area" ||
		record.DeliveryStatus != DeliveryDelivered || record.DeliveryAttempts != 3 || record.ReconciliationAttempts != 2 ||
		record.Feedback == nil || !record.Feedback.Helpful || record.Feedback.RecordSHA256 != feedback.RecordSHA256 {
		t.Fatalf("record=%+v", record)
	}
	replayed, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input)
	if err != nil || replayed.RecordID != record.RecordID {
		t.Fatalf("stable replay=%+v err=%v", replayed, err)
	}
	raw, _ := json.Marshal(record)
	for _, forbidden := range []string{assemblyMediaRef, "tenant-internal", "site-internal", "source-camera-one", "conversation-one", "recipient-one"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("evaluation projection leaked %q: %s", forbidden, raw)
		}
	}
}

func TestAssembleRecordRejectsUncommittedOrConflictingDatasetReceipt(t *testing.T) {
	fixture := newStandardAssemblyFixture(t)
	repository := fixture.repositories.Datasets.(*assemblyDatasetRepository)
	repository.resolution = dataset.CreateNotCommitted
	if _, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input); !errors.Is(err, ErrDatasetEvidenceUnavailable) {
		t.Fatalf("uncommitted err=%v", err)
	}
	repository.resolution = dataset.CreateCommitted
	fixture.input.DatasetReceipt.ContentSHA256 = strings.Repeat("f", 64)
	if _, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input); !errors.Is(err, ErrDatasetEvidenceUnavailable) {
		t.Fatalf("conflicting receipt err=%v", err)
	}
}

func TestAssembleRecordRejectsWrongPurposeOrExpiredDataset(t *testing.T) {
	fixture := newStandardAssemblyFixture(t)
	repository := fixture.repositories.Datasets.(*assemblyDatasetRepository)
	repository.value.PurposeRef = "purpose-unrelated"
	if _, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input); !errors.Is(err, ErrDatasetEvidenceUnavailable) {
		t.Fatalf("purpose err=%v", err)
	}
	fixture = newStandardAssemblyFixture(t)
	repository = fixture.repositories.Datasets.(*assemblyDatasetRepository)
	fixture.repositories.Clock = assemblyClock{now: repository.value.RetainUntil}
	if _, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input); !errors.Is(err, ErrDatasetEvidenceUnavailable) {
		t.Fatalf("retention err=%v", err)
	}
}

func TestAssembleRecordRejectsCallerDriftAcrossPlanAnnotationDeliveryAndFeedback(t *testing.T) {
	for name, test := range map[string]struct {
		mutate func(*standardAssemblyFixture)
		want   string
	}{
		"plan": {func(f *standardAssemblyFixture) { f.input.Standard.Run.PlanSHA256 = strings.Repeat("f", 64) }, "frozen plan"},
		"derived run id": {func(f *standardAssemblyFixture) {
			f.input.Standard.Run.RunID, f.input.Standard.Result.Binding.RunID = "run-forged", "run-forged"
		}, "frozen plan and result"},
		"output contract digest": {func(f *standardAssemblyFixture) {
			f.input.Standard.Result.Integrity.ContractSHA256 = strings.Repeat("f", 64)
		}, "frozen output contract"},
		"persistent write": {func(f *standardAssemblyFixture) {
			f.input.Standard.Run.PersistentConfigWrites = 1
		}, "frozen plan and result"},
		"source media": {func(f *standardAssemblyFixture) {
			f.input.Standard.Result.Binding.SourceMedia[0].MediaRef = "media_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			f.input.Standard.Result.EvidenceRefs[0] = "media_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "admitted media"},
		"source outside plan": {func(f *standardAssemblyFixture) {
			f.input.Standard.Result.Binding.SourceMedia[0].SourceRef = "source-outside-plan"
		}, "frozen target binding"},
		"annotation duplicate": {func(f *standardAssemblyFixture) {
			item := &f.repositories.Datasets.(*assemblyDatasetRepository).value.Items[0]
			item.Annotations = append(item.Annotations, item.Annotations[0])
			refreshAssemblyReceipt(f)
		}, "duplicated"},
		"delivery result": {func(f *standardAssemblyFixture) {
			f.repositories.Deliveries.(*assemblyDeliveryRepository).record.Message.ResultRef = "result_wrong"
		}, "run-and-result-bound"},
		"forged attempts": {func(f *standardAssemblyFixture) {
			f.repositories.Deliveries.(*assemblyDeliveryRepository).record.Attempts = 9
		}, "invalid"},
		"runtime provenance": {func(f *standardAssemblyFixture) {
			f.repositories.RuntimeEvidence = assemblyRuntimeEvidenceVerifier{err: errors.New("not persisted")}
		}, "runtime evidence is unavailable"},
		"public run binding": {func(f *standardAssemblyFixture) {
			f.repositories.RunBindings = &assemblyRunBindingVerifier{err: errors.New("mapping absent")}
		}, "public run binding is unavailable"},
		"feedback audience": {func(f *standardAssemblyFixture) {
			deliveryRecord := f.repositories.Deliveries.(*assemblyDeliveryRepository).record
			record := FeedbackRecord{Schema: FeedbackSchema, FeedbackID: "feedback-one", PublicRunRef: f.input.Standard.PublicRunRef,
				ResultRef: deliveryRecord.Message.ResultRef, AudienceSHA256: strings.Repeat("f", 64), Helpful: true,
				ReceivedAt: deliveryRecord.DeliveredAt.Add(time.Second)}
			record.RecordSHA256, _ = FeedbackProjectionSHA256(record)
			f.repositories.Feedback = &assemblyFeedbackRepository{record: record, found: true}
		}, "cross-bound"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newStandardAssemblyFixture(t)
			test.mutate(&fixture)
			if _, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want=%q", err, test.want)
			}
		})
	}
}

func TestTemporaryStrategyDerivesExactCurrentAndRecentWindows(t *testing.T) {
	end := time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC)
	start := end.Add(-30 * time.Second)
	record := temporary.Record{SubmittedAt: end, MediaKind: media.KindVideoClip,
		Spec:  temporary.TemporaryObservationSpec{TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeRecentWindow, WindowSeconds: 30}},
		Media: &temporary.MediaDescriptor{Kind: media.KindVideoClip, Temporal: media.Temporal{WindowStart: &start, WindowEnd: &end}}}
	if strategy, err := strategyForTemporary(record); err != nil || strategy != StrategyClipAnalysis {
		t.Fatalf("recent strategy=%q err=%v", strategy, err)
	}
	shifted := start.Add(time.Second)
	record.Media.Temporal.WindowStart = &shifted
	if _, err := strategyForTemporary(record); err == nil || !strings.Contains(err.Error(), "exact clip window") {
		t.Fatalf("shifted window err=%v", err)
	}
	record.MediaKind, record.Media.Kind = media.KindImage, media.KindImage
	record.Spec.TimeScope = temporary.TimeScope{Kind: temporary.TimeScopeCurrent}
	record.Media.Temporal.WindowStart, record.Media.Temporal.WindowEnd = &end, &end
	if strategy, err := strategyForTemporary(record); err != nil || strategy != StrategySnapshotAnalysis {
		t.Fatalf("current strategy=%q err=%v", strategy, err)
	}
}

func TestAssembleRecordTemporaryUsesExactRuntimeWindowAndTrustedReview(t *testing.T) {
	fixture := newTemporaryAssemblyFixture(t)
	record, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if record.ObservationMode != ObservationTemporary || record.Strategy != StrategySnapshotAnalysis ||
		record.SourceKind != SourcePreparedObservation || record.TemporaryReview == nil ||
		record.TemporaryReview.ReviewerPseudonym != "reviewer_aaaaaaaaaaaaaaaa" || record.Observed.Kind != ResultClassification {
		t.Fatalf("record=%+v", record)
	}
}

func TestAssembleRecordTemporaryFailsClosedWithoutOneVerifiedReview(t *testing.T) {
	for name, test := range map[string]struct {
		mutate func(*temporaryAssemblyFixture)
		want   string
	}{
		"missing": {func(f *temporaryAssemblyFixture) {
			f.repositories.Reviews = &assemblyReviewRepository{err: errors.New("offline")}
		}, "unavailable"},
		"duplicate": {func(f *temporaryAssemblyFixture) {
			r := f.repositories.Reviews.(*assemblyReviewRepository)
			r.duplicate = true
		}, "exactly one"},
		"cross media": {func(f *temporaryAssemblyFixture) {
			r := f.repositories.Reviews.(*assemblyReviewRepository)
			r.mutate = func(value *TemporaryReviewRecord) { value.MediaRef = "media_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
		}, "evidence-bound"},
		"early": {func(f *temporaryAssemblyFixture) {
			r := f.repositories.Reviews.(*assemblyReviewRepository)
			r.reviewedAt = f.input.Temporary.Record.CompletedAt.Add(-time.Second)
		}, "evidence-bound"},
		"unverified": {func(f *temporaryAssemblyFixture) {
			f.repositories.ReviewVerifier = assemblyReviewVerifier{err: errors.New("signature invalid")}
		}, "unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newTemporaryAssemblyFixture(t)
			test.mutate(&fixture)
			if _, err := AssembleRecord(context.Background(), fixture.repositories, fixture.input); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want=%q", err, test.want)
			}
		})
	}
}

type standardAssemblyFixture struct {
	repositories AssemblyRepositories
	input        AssemblyInput
}

func newStandardAssemblyFixture(t *testing.T) standardAssemblyFixture {
	t.Helper()
	requestedAt := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	capturedAt := requestedAt.Add(time.Second)
	plan := assemblyPlan(t, requestedAt)
	result := assemblyAnalysisResult(t, plan, capturedAt)
	run := inspection.Run{RunID: result.Binding.RunID, TenantID: plan.TenantID, SiteID: plan.SiteID, RequestKey: plan.RequestKey,
		PlanSHA256: plan.PlanSHA256, State: inspection.RunCompleted, CreatedAt: requestedAt, UpdatedAt: result.Execution.CompletedAt.Add(time.Second), Deadline: plan.Deadline}
	value := assemblyDataset(capturedAt, media.KindImage, dataset.ClassificationMeetsRule)
	repository, receipt := assemblyAdmittedRepository(t, value)
	publicRunRef := "run-public-one"
	deliveryRecord := assemblyDelivery(t, publicRunRef, result.Execution.CompletedAt, delivery.StateDelivered, 3, 2)
	deliveryRepository := &assemblyDeliveryRepository{record: deliveryRecord}
	bindingVerifier := &assemblyRunBindingVerifier{want: PublicRunBindingQuery{PublicRunRef: publicRunRef,
		InternalRunID: run.RunID, RunKind: ObservationStandard, TenantID: plan.TenantID, SiteID: plan.SiteID,
		PlanSHA256: plan.PlanSHA256, Audience: deliveryRecord.Message.Audience, AudienceSHA256: deliveryRecord.Message.AudienceSHA256}}
	return standardAssemblyFixture{
		repositories: AssemblyRepositories{Datasets: repository, Deliveries: deliveryRepository, Feedback: &assemblyFeedbackRepository{}, RunBindings: bindingVerifier, RuntimeEvidence: assemblyRuntimeEvidenceVerifier{}, Clock: assemblyClock{now: deliveryRecord.UpdatedAt}},
		input: AssemblyInput{DatasetReceipt: receipt, ItemID: "item-one", Context: AssemblyContext{SiteTimezone: "Asia/Shanghai", CalibrationRole: CalibrationNone},
			Standard: &StandardEvidence{PublicRunRef: publicRunRef, Run: run, Plan: plan, Result: result}, DeliveryID: deliveryRecord.Message.DeliveryID},
	}
}

func assemblyPlan(t *testing.T, requestedAt time.Time) inspection.ExecutionPlan {
	t.Helper()
	acquisition := inspection.AcquisitionPolicy{Samples: 1}
	strategy := inspection.StrategyPolicy{Strategy: inspection.StrategySnapshotAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera},
		RequiredCapabilityRefs: []string{"snapshot-read"}, MinimumSources: 1, MaximumSources: 1,
		Time: inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 60}, AnalysisPolicyRef: "analysis-policy-v3", MaximumAcquisition: acquisition}
	template := inspection.InspectionTemplate{Schema: inspection.SchemaVersion, TenantID: "tenant-internal", TemplateID: "template-one", Revision: 1,
		Name: "fixture", BusinessPurpose: "offline evaluation contract", Criteria: []inspection.Criterion{{ID: "surface-condition", Name: "surface condition",
			Method: inspection.MethodCV, Required: true, RuleRef: "rule-one", RuleVersion: 1, MayAssertCompliance: true,
			Output: inspection.OutputContract{Mode: inspection.ResultClassification, AllowedAssessments: []inspection.Assessment{inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention}, SchemaVersion: "classification-v3"}}},
		Strategies: []inspection.StrategyPolicy{strategy}, Budget: inspection.ResourceBudget{MaxTargets: 1, MaxSamplesPerTarget: 1, MaxAnalyses: 1, MaxDurationSeconds: 60, MaxMediaBytes: 1 << 20},
		Evidence: inspection.EvidencePolicy{Required: true, RetentionSeconds: 600}, OutputSchemaVersion: "report-v3", State: inspection.TemplatePublished,
		CreatedBy: "fixture-principal", CreatedAt: requestedAt.Add(-time.Hour)}
	assignment := inspection.Assignment{Schema: inspection.SchemaVersion, TenantID: template.TenantID, AssignmentID: "assignment-one", Revision: 1,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision, SiteID: "site-internal", Published: true,
		SourceCatalogFingerprint: strings.Repeat("a", 64), Targets: []inspection.TargetBinding{{TargetID: "target-one", FriendlyName: "Target one",
			SourceBindings: []inspection.SourceBinding{{Kind: inspection.SourceCamera, SourceHandle: "source-camera-one", SourceRevision: 1,
				SourceFingerprint: strings.Repeat("b", 64), CapabilityRefs: []string{"snapshot-read"}, MediaKinds: []inspection.MediaKind{inspection.MediaImage}}},
			CriterionIDs: []string{"surface-condition"}, Strategy: inspection.StrategySnapshotAnalysis, Acquisition: acquisition}}}
	request := inspection.CreateRunRequest{Schema: inspection.SchemaVersion, TenantID: template.TenantID, SiteID: assignment.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision, AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		Origin: inspection.OriginAPI, RequestID: "request-one", RequestedAt: requestedAt, Deadline: requestedAt.Add(time.Minute)}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func assemblyAnalysisResult(t *testing.T, plan inspection.ExecutionPlan, capturedAt time.Time) inspection.AnalysisResult {
	t.Helper()
	runID, err := inspectionruntime.RunIDForPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	stepID := ""
	for _, step := range plan.Steps {
		if step.Kind == inspection.StepValidateResult && step.TargetID == "target-one" && step.CriterionID == "surface-condition" {
			stepID = step.StepID
		}
	}
	contractSHA256, err := digestValue(struct {
		EnvelopeSchema string                    `json:"envelopeSchema"`
		Output         inspection.OutputContract `json:"output"`
	}{analysiscontract.SchemaVersion, plan.Targets[0].Criteria[0].Criterion.Output})
	if err != nil {
		t.Fatal(err)
	}
	result := inspection.AnalysisResult{
		Binding: inspection.ResultBinding{ResultID: "result-internal-one", RunID: runID, StepID: stepID, TargetID: "target-one",
			CriterionID: "surface-condition", CriterionVersion: "1", OutputKind: inspection.ResultClassification,
			OutputSchemaVersion: "classification-v3", Usage: inspection.ResultUsageInspection,
			TimeWindow:  inspection.ResultTimeWindow{StartAt: capturedAt, EndAt: capturedAt},
			SourceMedia: []inspection.ResultSourceMedia{{SourceRef: "source-camera-one", MediaRef: assemblyMediaRef, SHA256: strings.Repeat("c", 64), CapturedAt: capturedAt, FreshnessMS: 1000, SampleOrdinal: 1}}},
		Assessment: inspection.AssessmentMeetsRule, Observability: inspection.ResultFullyVisible,
		Value:        &inspection.ResultValue{Kind: inspection.ResultClassification, Classification: &inspection.ClassificationValue{Label: "clear"}},
		EvidenceRefs: []string{assemblyMediaRef}, ReasonCodes: []string{"criterion_met"}, Limitations: []string{},
		Analyzer: inspection.ResultAnalyzer{Kind: inspection.ResultAnalyzerFixture, AdapterVersion: "adapter-v3", ModelPolicy: "fixture-policy",
			ResolvedModelVersion: "fixture-v3", PromptTemplateID: "surface-condition", PromptTemplateVersion: "1", PromptTemplateSHA256: strings.Repeat("d", 64)},
		Execution: inspection.ResultExecution{Attempt: 1, StartedAt: capturedAt.Add(time.Second), CompletedAt: capturedAt.Add(2 * time.Second), LatencyMS: 1000},
		Integrity: inspection.ResultIntegrity{RawOutputSHA256: strings.Repeat("e", 64), ContractSHA256: contractSHA256},
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("result fixture: %v", err)
	}
	return result
}

type temporaryAssemblyFixture struct {
	repositories AssemblyRepositories
	input        AssemblyInput
}

func newTemporaryAssemblyFixture(t *testing.T) temporaryAssemblyFixture {
	t.Helper()
	submittedAt := time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC)
	capturedAt := submittedAt.Add(time.Second)
	evidenceExpiresAt := submittedAt.Add(10 * time.Minute)
	spec, err := temporary.NewSpec(temporary.Intent{Subject: "就餐区", Region: "入口", Observable: "查看地面可见情况", Locale: "zh-CN",
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	candidate := temporary.Candidate{Schema: temporary.CandidateSchemaVersion, Summary: "入口地面有可见残留。",
		VisibleFacts: []string{"地面可见少量残留。"}, Limitations: []string{}, EvidenceRefs: []string{assemblyMediaRef}}
	observation, err := temporary.BindCandidate(spec, candidate, []temporary.EvidenceBinding{{EvidenceRef: assemblyMediaRef, ExpiresAt: evidenceExpiresAt}}, capturedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	binding := temporary.AuthenticatedBinding{TenantID: "tenant-internal", SiteID: "site-internal", RequestKey: "request-temp-one",
		PublicRunRef: "run-public-temp", Channel: "workbuddy-wechat", ConversationRef: "conversation-one", RecipientRef: "recipient-one", PrincipalSHA256: strings.Repeat("a", 64)}
	audience, err := temporary.FreezeAudience(temporary.ChannelSession{TenantID: binding.TenantID, SiteID: binding.SiteID, Channel: binding.Channel,
		ConversationRef: binding.ConversationRef, RecipientRef: binding.RecipientRef, PrincipalSHA256: binding.PrincipalSHA256})
	if err != nil {
		t.Fatal(err)
	}
	preparationRef, _ := mediaprep.PreparationRefForScope(binding.TenantID, binding.SiteID, binding.RequestKey)
	runID, _ := temporary.RunIDForScope(binding.TenantID, binding.SiteID, binding.RequestKey)
	stepID, _ := temporary.MediaStepIDForRun(runID)
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	store, err := temporary.OpenSQLite(filepath.Join(root, "temporary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	_, created, err := store.Submit(context.Background(), temporary.Submission{Binding: binding, Spec: spec, PreparationRef: preparationRef,
		MediaKind: media.KindImage, AudienceBindingRef: audience.Ref, AudienceSHA256: audience.SHA256, EvidenceExpiresAt: evidenceExpiresAt,
		SubmittedAt: submittedAt, DeadlineAt: submittedAt.Add(5 * time.Minute)}, submittedAt)
	if err != nil || !created {
		t.Fatalf("submit created=%v err=%v", created, err)
	}
	_, lease, claimed, err := store.Claim(context.Background(), "evaluation-worker", capturedAt, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim=%v err=%v", claimed, err)
	}
	prompt, _ := temporary.CompilePrompt(spec)
	if _, err := store.BeginAnalysis(context.Background(), lease, temporary.MediaDescriptor{MediaRef: assemblyMediaRef, Kind: media.KindImage,
		TenantID: binding.TenantID, SiteID: binding.SiteID, RunID: runID, StepID: stepID, Attempt: 1, AudienceBindingRef: audience.Ref,
		SHA256: strings.Repeat("b", 64), MIMEType: "image/jpeg", SizeBytes: 128,
		Temporal: media.Temporal{WindowStart: &capturedAt, WindowEnd: &capturedAt}, ExpiresAt: evidenceExpiresAt}, prompt.SHA256, capturedAt); err != nil {
		t.Fatal(err)
	}
	runtimeRecord, err := store.CompleteSuccess(context.Background(), lease, candidate, observation, capturedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	value := assemblyDataset(capturedAt, media.KindImage, dataset.ClassificationNeedsAttention)
	repository, receipt := assemblyAdmittedRepository(t, value)
	observed := ResultValue{Kind: ResultClassification, State: ValuePresent, Classification: &ClassificationResult{Value: ClassificationNeedsAttention}}
	reviewRepo := &assemblyReviewRepository{observed: observed, adjudicated: observed, reviewedAt: runtimeRecord.CompletedAt.Add(time.Minute)}
	deliveryRecord := assemblyDelivery(t, binding.PublicRunRef, runtimeRecord.CompletedAt, delivery.StateDelivered, 1, 0)
	deliveryRepository := &assemblyDeliveryRepository{record: deliveryRecord}
	bindingVerifier := &assemblyRunBindingVerifier{want: PublicRunBindingQuery{PublicRunRef: binding.PublicRunRef,
		InternalRunID: runtimeRecord.RunID, RunKind: ObservationTemporary, TenantID: binding.TenantID, SiteID: binding.SiteID,
		Audience: deliveryRecord.Message.Audience, AudienceSHA256: deliveryRecord.Message.AudienceSHA256}}
	return temporaryAssemblyFixture{repositories: AssemblyRepositories{Datasets: repository, Deliveries: deliveryRepository, Feedback: &assemblyFeedbackRepository{}, Reviews: reviewRepo, ReviewVerifier: assemblyReviewVerifier{}, RunBindings: bindingVerifier, RuntimeEvidence: assemblyRuntimeEvidenceVerifier{}, Clock: assemblyClock{now: deliveryRecord.UpdatedAt}},
		input: AssemblyInput{DatasetReceipt: receipt, ItemID: "item-one", Context: AssemblyContext{SiteTimezone: "UTC", CalibrationRole: CalibrationNone},
			Temporary: &TemporaryEvidence{Record: runtimeRecord, Annotation: AnnotationSelector{CriterionID: "surface-condition", CriterionVersion: 1,
				ResultSchemaRef: "classification-v3", ResultKind: ResultClassification}},
			DeliveryID: deliveryRecord.Message.DeliveryID}}
}

func assemblyDataset(capturedAt time.Time, kind media.Kind, value dataset.ClassificationValue) dataset.Dataset {
	annotation := dataset.Annotation{AnnotationID: "annotation-one", CriterionID: "surface-condition", CriterionVersion: 1,
		SceneTaxonomy: []string{"dining-area", "indoor"}, ResultKind: dataset.LabelClassification, ResultSchemaRef: "classification-v3",
		Label:            dataset.Label{Kind: dataset.LabelClassification, Classification: &dataset.ClassificationLabel{Value: value}},
		AnnotationSHA256: strings.Repeat("a", 64), ApprovalCount: 2, LastReviewedAt: capturedAt.Add(-time.Minute)}
	return dataset.Dataset{Schema: dataset.Schema, DatasetID: "dataset-one", Revision: 1, PurposeRef: EvaluationDatasetPurposeRef,
		TenantStratum: "tenant_aaaaaaaaaaaaaaaa", SiteStratum: "site_bbbbbbbbbbbbbbbb", PolicySHA256: strings.Repeat("b", 64),
		RetainUntil: capturedAt.Add(24 * time.Hour), GovernanceState: dataset.GovernanceActive, CreatedAt: capturedAt.Add(-time.Hour),
		Items: []dataset.Item{{ItemID: "item-one", MediaRef: assemblyMediaRef, Kind: kind, Split: dataset.SplitTest, CapturedAt: capturedAt,
			SiteStratum: "site_bbbbbbbbbbbbbbbb", SourceStratum: "source_cccccccccccccccc", GroupStratum: "group_dddddddddddddddd", Annotations: []dataset.Annotation{annotation}}},
		Strata: []dataset.StratumSummary{{SiteStratum: "site_bbbbbbbbbbbbbbbb", SourceStratum: "source_cccccccccccccccc", Split: dataset.SplitTest,
			CriterionID: "surface-condition", CriterionVersion: 1, ResultKind: dataset.LabelClassification, Count: 1}},
		CountsBySplit: dataset.SplitCounts{Test: 1}, AnnotationCount: 1, ApprovalMinimum: 2}
}

func assemblyAdmittedRepository(t *testing.T, value dataset.Dataset) (*assemblyDatasetRepository, dataset.CreateReceipt) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	receipt := dataset.CreateReceipt{TenantStratum: value.TenantStratum, SiteStratum: value.SiteStratum, DatasetID: value.DatasetID,
		Revision: value.Revision, ContentSHA256: hex.EncodeToString(digest[:])}
	return &assemblyDatasetRepository{value: value, receipt: receipt, resolution: dataset.CreateCommitted}, receipt
}

func refreshAssemblyReceipt(fixture *standardAssemblyFixture) {
	value := fixture.repositories.Datasets.(*assemblyDatasetRepository).value
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	fixture.input.DatasetReceipt.ContentSHA256 = hex.EncodeToString(digest[:])
	fixture.repositories.Datasets.(*assemblyDatasetRepository).receipt = fixture.input.DatasetReceipt
}

func assemblyDelivery(t *testing.T, publicRunRef string, completedAt time.Time, state delivery.State, attempts, reconciliation int) delivery.Record {
	t.Helper()
	resultRef, err := delivery.ResultRefForRun(publicRunRef)
	if err != nil {
		t.Fatal(err)
	}
	message, err := delivery.NewMessage(publicRunRef, resultRef, delivery.Audience{TenantID: "tenant-internal", SiteID: "site-internal",
		Channel: "workbuddy-wechat", ConversationRef: "conversation-one", RecipientRef: "recipient-one"},
		delivery.Presentation{Title: "巡检结果", Summary: "巡检结果已生成。"}, nil, completedAt.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	terminalAt := message.CreatedAt.Add(500 * time.Millisecond)
	record := delivery.Record{Message: message, State: state, Attempts: attempts, ReconciliationAttempts: reconciliation,
		AvailableAt: terminalAt, Reason: "delivery_test_terminal", UpdatedAt: terminalAt}
	if state == delivery.StateDelivered {
		record.ReceiptRef, record.DeliveredAt = "receipt-test", terminalAt
	} else if state == delivery.StateOutcomeUnknown {
		record.AvailableAt = terminalAt.Add(time.Minute)
	} else if state == delivery.StateFailed {
		record.Attempts, record.Reason = 8, "delivery_attempt_budget_exhausted"
	}
	return record
}
