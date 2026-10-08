package inspectioneval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/dataset"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

var (
	ErrDatasetEvidenceUnavailable  = errors.New("evaluation dataset evidence is unavailable")
	ErrDeliveryEvidenceUnavailable = errors.New("evaluation delivery evidence is unavailable")
	ErrFeedbackUnavailable         = errors.New("evaluation feedback evidence is unavailable")
	ErrReviewUnavailable           = errors.New("evaluation temporary review evidence is unavailable")
	ErrRunBindingUnavailable       = errors.New("evaluation public run binding is unavailable")
	ErrRuntimeEvidenceUnavailable  = errors.New("evaluation runtime evidence is unavailable")
)

const EvaluationDatasetPurposeRef = "purpose-assistant-evaluation"

// DatasetRepository is intentionally narrower than the dataset writer. An
// evaluator can only reconcile one exact create receipt and read the active
// admitted projection that receipt names.
type DatasetRepository interface {
	ResolveCreate(context.Context, dataset.CreateReceipt) (dataset.CreateResolution, error)
	Get(context.Context, string, string, string, uint64) (dataset.Dataset, error)
}

type FeedbackQuery struct {
	PublicRunRef   string
	ResultRef      string
	AudienceSHA256 string
}

// FeedbackRecord is a trusted adapter projection. RecordSHA256 protects this
// projection; it is not the application store's private record digest.
// Comments and channel-native identities are intentionally absent.
type FeedbackRecord struct {
	Schema         string    `json:"schema"`
	FeedbackID     string    `json:"feedbackId"`
	PublicRunRef   string    `json:"publicRunRef"`
	ResultRef      string    `json:"resultRef"`
	AudienceSHA256 string    `json:"audienceSha256"`
	Helpful        bool      `json:"helpful"`
	ReceivedAt     time.Time `json:"receivedAt"`
	RecordSHA256   string    `json:"recordSha256"`
}

type FeedbackRepository interface {
	GetFeedback(context.Context, FeedbackQuery) (FeedbackRecord, bool, error)
}

type TemporaryReviewQuery struct {
	DatasetID           string
	DatasetRevision     uint64
	DatasetItemID       string
	AnnotationSHA256    string
	RuntimeRunID        string
	RuntimeResultRef    string
	RuntimeResultSHA256 string
	MediaRef            string
	MediaSHA256         string
	SpecSHA256          string
	ObservationSHA256   string
}

// TemporaryReviewRecord binds the typed interpretation and adjudication to
// both the admitted annotation and the complete successful temporary runtime
// result. RecordSHA256 covers every field except itself.
type TemporaryReviewRecord struct {
	Schema              string      `json:"schema"`
	ReviewID            string      `json:"reviewId"`
	DatasetID           string      `json:"datasetId"`
	DatasetRevision     uint64      `json:"datasetRevision"`
	DatasetItemID       string      `json:"datasetItemId"`
	AnnotationSHA256    string      `json:"annotationSha256"`
	RuntimeRunID        string      `json:"runtimeRunId"`
	RuntimeResultRef    string      `json:"runtimeResultRef"`
	RuntimeResultSHA256 string      `json:"runtimeResultSha256"`
	MediaRef            string      `json:"mediaRef"`
	MediaSHA256         string      `json:"mediaSha256"`
	SpecSHA256          string      `json:"specSha256"`
	ObservationSHA256   string      `json:"observationSha256"`
	Observed            ResultValue `json:"observed"`
	Adjudicated         ResultValue `json:"adjudicated"`
	PolicyRef           string      `json:"policyRef"`
	ReviewerPseudonym   string      `json:"reviewerPseudonym"`
	ReviewedAt          time.Time   `json:"reviewedAt"`
	RecordSHA256        string      `json:"recordSha256"`
}

type TemporaryReviewRepository interface {
	ListTemporaryReviews(context.Context, TemporaryReviewQuery) ([]TemporaryReviewRecord, error)
}

type TemporaryReviewVerifier interface {
	VerifyTemporaryReview(context.Context, TemporaryReviewRecord) error
}

// DeliveryRepository is a read-only view of the authoritative delivery store.
// Assembly accepts only a delivery identity; persisted state and attempt counts
// are loaded through this port rather than supplied by the caller.
type DeliveryRepository interface {
	Get(context.Context, string) (delivery.Record, error)
}

// PublicRunBindingQuery is the exact protected application binding that must
// exist before runtime, delivery, and feedback facts can be joined.
type PublicRunBindingQuery struct {
	PublicRunRef   string
	InternalRunID  string
	RunKind        ObservationMode
	TenantID       string
	SiteID         string
	PlanSHA256     string
	Audience       delivery.Audience
	AudienceSHA256 string
}

// PublicRunBindingVerifier is implemented by the protected application-state
// adapter. It must verify one exact public-to-internal run and audience binding;
// it must not create or repair a binding during evaluation.
type PublicRunBindingVerifier interface {
	VerifyPublicRunBinding(context.Context, PublicRunBindingQuery) error
}

// RuntimeEvidenceVerifier proves that the exact immutable evidence supplied to
// assembly was read from the authoritative runtime stores. Structural
// self-consistency alone is not accepted as persistence provenance.
type RuntimeEvidenceVerifier interface {
	VerifyStandardEvidence(context.Context, StandardEvidence) error
	VerifyTemporaryEvidence(context.Context, temporary.Record) error
}

type EvaluationClock interface {
	Now() time.Time
}

type AssemblyRepositories struct {
	Datasets        DatasetRepository
	Deliveries      DeliveryRepository
	Feedback        FeedbackRepository
	Reviews         TemporaryReviewRepository
	ReviewVerifier  TemporaryReviewVerifier
	RunBindings     PublicRunBindingVerifier
	RuntimeEvidence RuntimeEvidenceVerifier
	Clock           EvaluationClock
}

type AssemblyContext struct {
	SiteTimezone    string
	CalibrationRole CalibrationRole
}

type AnnotationSelector struct {
	CriterionID      string
	CriterionVersion uint64
	ResultSchemaRef  string
	ResultKind       ResultKind
}

type StandardEvidence struct {
	PublicRunRef string
	Run          inspection.Run
	Plan         inspection.ExecutionPlan
	Result       inspection.AnalysisResult
}

// TemporaryEvidence contains only authoritative runtime evidence plus the
// annotation contract to evaluate. Observed truth and review facts are loaded
// from the trusted review repository, never supplied here.
type TemporaryEvidence struct {
	Record     temporary.Record
	Annotation AnnotationSelector
}

type AssemblyInput struct {
	DatasetReceipt dataset.CreateReceipt
	ItemID         string
	Context        AssemblyContext
	Standard       *StandardEvidence
	Temporary      *TemporaryEvidence
	DeliveryID     string
}

// AssembleRecord joins one repository-admitted dataset item with authoritative
// runtime, delivery, feedback, and (for temporary observations) review facts.
// Exactly one standard or temporary evidence member is required.
func AssembleRecord(ctx context.Context, repositories AssemblyRepositories, input AssemblyInput) (Record, error) {
	if ctx == nil || repositories.Datasets == nil || repositories.Deliveries == nil || repositories.Feedback == nil || repositories.Clock == nil ||
		repositories.RunBindings == nil || repositories.RuntimeEvidence == nil || !validOpaqueRef(input.DeliveryID) ||
		(input.Standard == nil) == (input.Temporary == nil) {
		return Record{}, errors.New("evaluation assembly dependencies or observation mode are invalid")
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	evaluatedAt := repositories.Clock.Now().UTC()
	if evaluatedAt.IsZero() {
		return Record{}, errors.New("evaluation clock is invalid")
	}
	admitted, err := resolveAdmittedDataset(ctx, repositories.Datasets, input.DatasetReceipt, evaluatedAt)
	if err != nil {
		return Record{}, err
	}
	item, err := selectDatasetItem(admitted, input.ItemID)
	if err != nil {
		return Record{}, err
	}
	if !validAssemblyContext(input.Context) {
		return Record{}, errors.New("evaluation assembly context is invalid")
	}

	var (
		selector                 AnnotationSelector
		observed                 ResultValue
		review                   *TemporaryReview
		mode                     ObservationMode
		strategy                 Strategy
		sourceKind               SourceKind
		publicRunRef, resultID   string
		requestedAt, completedAt time.Time
		analysisMS               float64
		bindingQuery             PublicRunBindingQuery
	)
	if input.Standard != nil {
		standard := *input.Standard
		if err = repositories.RuntimeEvidence.VerifyStandardEvidence(ctx, standard); err != nil {
			return Record{}, errors.Join(ErrRuntimeEvidenceUnavailable, err)
		}
		selector, observed, strategy, sourceKind, requestedAt, completedAt, resultID, err = assembleStandard(item, standard)
		if err != nil {
			return Record{}, err
		}
		publicRunRef = standard.PublicRunRef
		analysisMS = float64(standard.Result.Execution.LatencyMS)
		mode = ObservationStandard
		bindingQuery = PublicRunBindingQuery{PublicRunRef: publicRunRef, InternalRunID: standard.Run.RunID,
			RunKind: mode, TenantID: standard.Plan.TenantID, SiteID: standard.Plan.SiteID, PlanSHA256: standard.Plan.PlanSHA256}
	} else {
		if repositories.Reviews == nil || repositories.ReviewVerifier == nil {
			return Record{}, errors.New("temporary evaluation requires trusted review dependencies")
		}
		temporaryEvidence := *input.Temporary
		if err = repositories.RuntimeEvidence.VerifyTemporaryEvidence(ctx, temporaryEvidence.Record); err != nil {
			return Record{}, errors.Join(ErrRuntimeEvidenceUnavailable, err)
		}
		selector = temporaryEvidence.Annotation
		annotation, selectErr := selectAnnotation(item, selector)
		if selectErr != nil {
			return Record{}, selectErr
		}
		observed, review, strategy, sourceKind, requestedAt, completedAt, resultID, err = assembleTemporary(
			ctx, repositories.Reviews, repositories.ReviewVerifier, admitted, item, annotation, temporaryEvidence.Record,
		)
		if err != nil {
			return Record{}, err
		}
		publicRunRef = temporaryEvidence.Record.Binding.PublicRunRef
		analysisMS = milliseconds(completedAt.Sub(requestedAt))
		mode = ObservationTemporary
		bindingQuery = PublicRunBindingQuery{PublicRunRef: publicRunRef, InternalRunID: temporaryEvidence.Record.RunID,
			RunKind: mode, TenantID: temporaryEvidence.Record.Binding.TenantID, SiteID: temporaryEvidence.Record.Binding.SiteID}
	}
	annotation, err := selectAnnotation(item, selector)
	if err != nil {
		return Record{}, err
	}
	expected, err := ResultValueFromDatasetLabel(annotation.Label)
	if err != nil {
		return Record{}, fmt.Errorf("project evaluation ground truth: %w", err)
	}
	if observed.Kind != expected.Kind || annotation.ResultKind != resultKindToDataset(expected.Kind) {
		return Record{}, errors.New("evaluated observation kind does not match the admitted annotation")
	}

	deliveryRecord, err := repositories.Deliveries.Get(ctx, input.DeliveryID)
	if err != nil {
		return Record{}, errors.Join(ErrDeliveryEvidenceUnavailable, err)
	}
	deliveryStatus, deliveryCompletedAt, deliveryMS, deliveryAttempts, reconciliationAttempts, resultRef, err :=
		terminalDelivery(deliveryRecord, input.DeliveryID, publicRunRef, completedAt)
	if err != nil {
		return Record{}, err
	}
	bindingQuery.Audience, bindingQuery.AudienceSHA256 = deliveryRecord.Message.Audience, deliveryRecord.Message.AudienceSHA256
	if deliveryRecord.Message.Audience.TenantID != bindingQuery.TenantID || deliveryRecord.Message.Audience.SiteID != bindingQuery.SiteID {
		return Record{}, errors.New("evaluation delivery audience does not match the bound runtime scope")
	}
	if input.Temporary != nil {
		binding := input.Temporary.Record.Binding
		if deliveryRecord.Message.Audience.Channel != binding.Channel ||
			deliveryRecord.Message.Audience.ConversationRef != binding.ConversationRef ||
			deliveryRecord.Message.Audience.RecipientRef != binding.RecipientRef {
			return Record{}, errors.New("temporary evaluation delivery audience does not match the authenticated runtime binding")
		}
	}
	if err := repositories.RunBindings.VerifyPublicRunBinding(ctx, bindingQuery); err != nil {
		return Record{}, errors.Join(ErrRunBindingUnavailable, err)
	}
	feedback, err := resolveFeedback(ctx, repositories.Feedback, FeedbackQuery{
		PublicRunRef: publicRunRef, ResultRef: resultRef, AudienceSHA256: deliveryRecord.Message.AudienceSHA256,
	}, deliveryCompletedAt)
	if err != nil {
		return Record{}, err
	}
	deliveryEvidenceSHA256, err := digestDeliveryEvidence(deliveryRecord)
	if err != nil {
		return Record{}, errors.Join(ErrDeliveryEvidenceUnavailable, err)
	}
	record := Record{
		Schema:          RecordSchema,
		RecordID:        stableEvaluationRecordID(admitted.DatasetID, admitted.Revision, item.ItemID, annotation.AnnotationSHA256, resultID),
		TenantPseudonym: admitted.TenantStratum, SitePseudonym: admitted.SiteStratum, SourcePseudonym: item.SourceStratum,
		CapturedAt: item.CapturedAt.UTC(), SiteTimezone: input.Context.SiteTimezone,
		SceneStrata: append([]string(nil), annotation.SceneTaxonomy...),
		CriterionID: annotation.CriterionID, CriterionVersion: annotation.CriterionVersion, ResultSchemaRef: annotation.ResultSchemaRef,
		Strategy: strategy, SourceKind: sourceKind, MediaKind: mediaKindForDataset(item.Kind),
		Split: Split(item.Split), GroupKey: item.GroupStratum, CalibrationRole: input.Context.CalibrationRole,
		ObservationMode: mode, Expected: expected, Observed: observed, TemporaryReview: review,
		Latencies:         Latencies{EndToEndMS: milliseconds(deliveryCompletedAt.Sub(requestedAt)), AnalysisMS: analysisMS, DeliveryMS: deliveryMS},
		DeliveryPseudonym: stableDeliveryPseudonym(deliveryRecord.Message.DeliveryID), DeliveryEvidenceSHA256: deliveryEvidenceSHA256,
		DeliveryStatus: deliveryStatus, DeliveryAttempts: deliveryAttempts, ReconciliationAttempts: reconciliationAttempts,
		Feedback: feedback,
	}
	if issues := validateRecord(record, 1); len(issues) != 0 {
		return Record{}, &ValidationError{Issues: issues}
	}
	return record, nil
}

func resolveAdmittedDataset(ctx context.Context, repository DatasetRepository, receipt dataset.CreateReceipt, evaluatedAt time.Time) (dataset.Dataset, error) {
	resolution, err := repository.ResolveCreate(ctx, receipt)
	if err != nil || resolution.State != dataset.CreateCommitted {
		return dataset.Dataset{}, errors.Join(ErrDatasetEvidenceUnavailable, err)
	}
	value, err := repository.Get(ctx, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision)
	if err != nil {
		return dataset.Dataset{}, errors.Join(ErrDatasetEvidenceUnavailable, err)
	}
	if value.Schema != dataset.Schema || value.GovernanceState != dataset.GovernanceActive ||
		value.TenantStratum != receipt.TenantStratum || value.SiteStratum != receipt.SiteStratum ||
		value.DatasetID != receipt.DatasetID || value.Revision != receipt.Revision || value.PurposeRef != EvaluationDatasetPurposeRef ||
		value.CreatedAt.After(evaluatedAt) || !value.RetainUntil.After(evaluatedAt) {
		return dataset.Dataset{}, ErrDatasetEvidenceUnavailable
	}
	return value, nil
}

func selectDatasetItem(value dataset.Dataset, itemID string) (dataset.Item, error) {
	if !validOpaqueRef(itemID) {
		return dataset.Item{}, errors.New("evaluation dataset item selector is invalid")
	}
	var selected dataset.Item
	found := 0
	for _, item := range value.Items {
		if item.ItemID == itemID {
			selected, found = item, found+1
		}
	}
	if found != 1 || selected.SiteStratum != value.SiteStratum || selected.CapturedAt.IsZero() ||
		!sourcePattern.MatchString(selected.SourceStratum) || !groupPattern.MatchString(selected.GroupStratum) || len(selected.Annotations) == 0 {
		return dataset.Item{}, errors.New("evaluation dataset item is missing, duplicated, or out of scope")
	}
	return selected, nil
}

func selectAnnotation(item dataset.Item, selector AnnotationSelector) (dataset.Annotation, error) {
	if !validOpaqueRef(selector.CriterionID) || selector.CriterionVersion == 0 ||
		!validOpaqueRef(selector.ResultSchemaRef) || !validResultKind(selector.ResultKind) {
		return dataset.Annotation{}, errors.New("evaluation annotation selector is invalid")
	}
	wantKind := resultKindToDataset(selector.ResultKind)
	var selected dataset.Annotation
	found := 0
	for _, annotation := range item.Annotations {
		if annotation.CriterionID == selector.CriterionID && annotation.CriterionVersion == selector.CriterionVersion &&
			annotation.ResultSchemaRef == selector.ResultSchemaRef && annotation.ResultKind == wantKind {
			selected, found = annotation, found+1
		}
	}
	if found != 1 || len(selected.SceneTaxonomy) == 0 || !digestPattern.MatchString(selected.AnnotationSHA256) {
		return dataset.Annotation{}, errors.New("evaluation annotation is missing, duplicated, or not exactly contract-bound")
	}
	previous := ""
	for _, stratum := range selected.SceneTaxonomy {
		if !validOpaqueRef(stratum) || stratum <= previous {
			return dataset.Annotation{}, errors.New("evaluation annotation scene taxonomy is not canonical")
		}
		previous = stratum
	}
	return selected, nil
}

func assembleStandard(item dataset.Item, evidence StandardEvidence) (AnnotationSelector, ResultValue, Strategy, SourceKind, time.Time, time.Time, string, error) {
	if !validOpaqueRef(evidence.PublicRunRef) || evidence.Plan.Validate() != nil || evidence.Result.Validate() != nil ||
		evidence.Result.Binding.Usage != inspection.ResultUsageInspection {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation evidence is invalid")
	}
	run, plan, result := evidence.Run, evidence.Plan, evidence.Result
	wantRunID, runIDErr := inspectionruntime.RunIDForPlan(plan)
	if runIDErr != nil || run.RunID != wantRunID || run.RunID != result.Binding.RunID || run.TenantID != plan.TenantID || run.SiteID != plan.SiteID ||
		run.RequestKey != plan.RequestKey || run.PlanSHA256 != plan.PlanSHA256 || !run.Deadline.Equal(plan.Deadline) ||
		(run.State != inspection.RunCompleted && run.State != inspection.RunPartial) || run.CreatedAt.IsZero() || run.UpdatedAt.Before(run.CreatedAt) ||
		run.PersistentConfigWrites != 0 || run.TemporaryResources < 0 || run.CleanupPending != 0 ||
		run.CreatedAt.Before(plan.RequestedAt) || run.CreatedAt.After(result.Execution.StartedAt) || run.UpdatedAt.Before(result.Execution.CompletedAt) ||
		result.Execution.StartedAt.Before(plan.RequestedAt) || result.Execution.CompletedAt.After(plan.Deadline) {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation run is not terminal or does not bind the frozen plan and result")
	}

	var target inspection.PlannedTarget
	targetCount := 0
	for _, candidate := range plan.Targets {
		if candidate.TargetID == result.Binding.TargetID {
			target, targetCount = candidate, targetCount+1
		}
	}
	if targetCount != 1 {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation result target is outside the frozen plan")
	}
	var criterion inspection.PlannedCriterion
	criterionCount := 0
	for _, candidate := range target.Criteria {
		if candidate.Criterion.ID == result.Binding.CriterionID {
			criterion, criterionCount = candidate, criterionCount+1
		}
	}
	wantVersion := strconv.FormatUint(criterion.Criterion.RuleVersion, 10)
	if criterionCount != 1 || result.Binding.CriterionVersion != wantVersion || result.Binding.OutputKind != criterion.Criterion.Output.Mode ||
		result.Binding.OutputSchemaVersion != criterion.Criterion.Output.SchemaVersion {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation result does not match its frozen criterion contract")
	}
	contractSHA256, contractErr := digestValue(struct {
		EnvelopeSchema string                    `json:"envelopeSchema"`
		Output         inspection.OutputContract `json:"output"`
	}{analysiscontract.SchemaVersion, criterion.Criterion.Output})
	if contractErr != nil || result.Integrity.ContractSHA256 != contractSHA256 {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation result integrity does not match the frozen output contract")
	}
	stepCount := 0
	for _, step := range plan.Steps {
		if step.StepID == result.Binding.StepID && step.Kind == inspection.StepValidateResult &&
			step.TargetID == result.Binding.TargetID && step.CriterionID == result.Binding.CriterionID {
			stepCount++
		}
	}
	if stepCount != 1 {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation result step is outside the frozen validation plan")
	}
	assessmentAllowed := false
	for _, allowed := range criterion.Criterion.Output.AllowedAssessments {
		if result.Assessment == allowed {
			assessmentAllowed = true
		}
	}
	earliest := plan.RequestedAt.Add(-time.Duration(target.StrategyPolicy.Time.MaxAgeSeconds) * time.Second)
	if !assessmentAllowed || result.Binding.TimeWindow.StartAt.Before(earliest) || result.Binding.TimeWindow.EndAt.After(plan.Deadline) {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation result assessment or scene time is outside the frozen plan")
	}
	for _, resultSource := range result.Binding.SourceMedia {
		bound := 0
		for _, plannedSource := range target.SourceBindings {
			if plannedSource.SourceHandle == resultSource.SourceRef {
				bound++
			}
		}
		if bound != 1 {
			return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation result contains source media outside the frozen target binding")
		}
	}

	var matched inspection.ResultSourceMedia
	mediaMatches := 0
	for _, source := range result.Binding.SourceMedia {
		if source.MediaRef == item.MediaRef && source.CapturedAt.Equal(item.CapturedAt) {
			matched, mediaMatches = source, mediaMatches+1
		}
	}
	if mediaMatches != 1 {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation result is not exactly bound to the admitted media and capture time")
	}
	var sourceBinding inspection.SourceBinding
	sourceMatches := 0
	for _, source := range target.SourceBindings {
		if source.SourceHandle == matched.SourceRef {
			sourceBinding, sourceMatches = source, sourceMatches+1
		}
	}
	if sourceMatches != 1 || !containsInspectionMediaKind(sourceBinding.MediaKinds, inspectionMediaKind(item.Kind)) {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", errors.New("standard evaluation media source is outside its frozen target binding")
	}
	projected, err := ResultValueFromAnalysis(result)
	if err != nil {
		return AnnotationSelector{}, ResultValue{}, "", "", time.Time{}, time.Time{}, "", err
	}
	selector := AnnotationSelector{CriterionID: result.Binding.CriterionID, CriterionVersion: criterion.Criterion.RuleVersion,
		ResultSchemaRef: result.Binding.OutputSchemaVersion, ResultKind: ResultKind(result.Binding.OutputKind)}
	return selector, projected, Strategy(target.StrategyPolicy.Strategy), SourceKind(sourceBinding.Kind), plan.RequestedAt.UTC(),
		result.Execution.CompletedAt.UTC(), result.Binding.ResultID, nil
}

func assembleTemporary(ctx context.Context, reviews TemporaryReviewRepository, verifier TemporaryReviewVerifier, admitted dataset.Dataset,
	item dataset.Item, annotation dataset.Annotation, record temporary.Record,
) (ResultValue, *TemporaryReview, Strategy, SourceKind, time.Time, time.Time, string, error) {
	if record.Validate() != nil || record.State != temporary.StateSucceeded || record.Media == nil || record.Observation == nil ||
		record.Candidate == nil || record.CompletedAt.IsZero() || record.MediaRef != item.MediaRef || record.Media.MediaRef != item.MediaRef ||
		record.ResultRef == "" || !digestPattern.MatchString(record.ResultSHA256) || record.CompletedAt.Before(record.SubmittedAt) {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", errors.New("temporary evaluation runtime evidence is incomplete or invalid")
	}
	strategy, err := strategyForTemporary(record)
	if err != nil {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", err
	}
	windowStart := record.Media.Temporal.WindowStart
	if windowStart == nil || !windowStart.Equal(item.CapturedAt) {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", errors.New("temporary evaluation capture window does not match the admitted media")
	}
	specDigest, err := digestValue(record.Spec)
	if err != nil {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", err
	}
	observationDigest, err := digestValue(*record.Observation)
	if err != nil {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", err
	}
	query := TemporaryReviewQuery{
		DatasetID: admitted.DatasetID, DatasetRevision: admitted.Revision, DatasetItemID: item.ItemID,
		AnnotationSHA256: annotation.AnnotationSHA256, RuntimeRunID: record.RunID, RuntimeResultRef: record.ResultRef,
		RuntimeResultSHA256: record.ResultSHA256, MediaRef: item.MediaRef, MediaSHA256: record.Media.SHA256,
		SpecSHA256: specDigest, ObservationSHA256: observationDigest,
	}
	values, err := reviews.ListTemporaryReviews(ctx, query)
	if err != nil {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", errors.Join(ErrReviewUnavailable, err)
	}
	if len(values) != 1 {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", errors.New("temporary evaluation requires exactly one trusted review")
	}
	trusted := values[0]
	if err := validateTemporaryReviewRecord(trusted, query, record.CompletedAt); err != nil {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", err
	}
	if err := verifier.VerifyTemporaryReview(ctx, trusted); err != nil {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", errors.Join(ErrReviewUnavailable, err)
	}
	if trusted.Observed.Kind != ResultKind(annotation.ResultKind) || trusted.Adjudicated.Kind != trusted.Observed.Kind {
		return ResultValue{}, nil, "", "", time.Time{}, time.Time{}, "", errors.New("temporary review kind does not match the admitted annotation")
	}
	publicReview := &TemporaryReview{Schema: ReviewSchema, ReviewID: trusted.ReviewID, RecordSHA256: trusted.RecordSHA256,
		ReviewerPseudonym: trusted.ReviewerPseudonym, ReviewedAt: trusted.ReviewedAt.UTC(), Adjudicated: trusted.Adjudicated,
		ReviewPolicyRef: trusted.PolicyRef}
	return trusted.Observed, publicReview, strategy, SourcePreparedObservation, record.SubmittedAt.UTC(), record.CompletedAt.UTC(), record.ResultRef, nil
}

func strategyForTemporary(record temporary.Record) (Strategy, error) {
	if record.Media == nil || record.Media.Temporal.WindowStart == nil || record.Media.Temporal.WindowEnd == nil {
		return "", errors.New("temporary evaluation media has no exact time window")
	}
	start, end := record.Media.Temporal.WindowStart.UTC(), record.Media.Temporal.WindowEnd.UTC()
	switch record.Spec.TimeScope.Kind {
	case temporary.TimeScopeCurrent:
		if record.MediaKind != media.KindImage || record.Media.Kind != media.KindImage || !start.Equal(end) {
			return "", errors.New("current temporary evaluation is not an exact snapshot")
		}
		return StrategySnapshotAnalysis, nil
	case temporary.TimeScopeRecentWindow:
		window := time.Duration(record.Spec.TimeScope.WindowSeconds) * time.Second
		if record.MediaKind != media.KindVideoClip || record.Media.Kind != media.KindVideoClip || !end.Equal(record.SubmittedAt) || !start.Equal(end.Add(-window)) {
			return "", errors.New("recent temporary evaluation is not bound to its exact clip window")
		}
		return StrategyClipAnalysis, nil
	default:
		return "", errors.New("temporary evaluation time scope is unsupported")
	}
}

func terminalDelivery(record delivery.Record, deliveryID, publicRunRef string, resultCompletedAt time.Time) (DeliveryStatus, time.Time, float64, int, int, string, error) {
	wantResultRef, err := delivery.ResultRefForRun(publicRunRef)
	if err != nil || record.Message.Validate() != nil || record.Message.DeliveryID != deliveryID || record.Message.RunRef != publicRunRef || record.Message.ResultRef != wantResultRef ||
		record.Message.CreatedAt.Before(resultCompletedAt) || record.Attempts < 1 || record.Attempts > 8 ||
		record.ReconciliationAttempts < 0 || record.ReconciliationAttempts > 1_000_000 || record.AvailableAt.IsZero() ||
		record.UpdatedAt.Before(record.Message.CreatedAt) || !validOpaqueRef(record.Reason) {
		return "", time.Time{}, 0, 0, 0, "", errors.New("evaluation delivery is invalid or not run-and-result-bound")
	}
	var status DeliveryStatus
	var completedAt time.Time
	switch record.State {
	case delivery.StateDelivered:
		if record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() || !validOpaqueRef(record.ReceiptRef) || record.DeliveredAt.IsZero() || !record.DeliveredAt.Equal(record.UpdatedAt) {
			return "", time.Time{}, 0, 0, 0, "", errors.New("evaluation delivered state is not a valid persisted terminal record")
		}
		status, completedAt = DeliveryDelivered, record.DeliveredAt.UTC()
	case delivery.StateOutcomeUnknown:
		if record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() || record.ReceiptRef != "" || !record.DeliveredAt.IsZero() {
			return "", time.Time{}, 0, 0, 0, "", errors.New("evaluation unknown state is still reconciling or is not a valid persisted record")
		}
		status, completedAt = DeliveryUnknown, record.UpdatedAt.UTC()
	case delivery.StateFailed:
		if record.Attempts != 8 || record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() || record.ReceiptRef != "" || !record.DeliveredAt.IsZero() {
			return "", time.Time{}, 0, 0, 0, "", errors.New("evaluation failed state is not an exhausted persisted terminal record")
		}
		status, completedAt = DeliveryFailed, record.UpdatedAt.UTC()
	default:
		return "", time.Time{}, 0, 0, 0, "", errors.New("evaluation delivery has not reached a terminal state")
	}
	if completedAt.IsZero() || completedAt.Before(record.Message.CreatedAt) {
		return "", time.Time{}, 0, 0, 0, "", errors.New("evaluation delivery terminal time is invalid")
	}
	return status, completedAt, milliseconds(completedAt.Sub(record.Message.CreatedAt)), record.Attempts, record.ReconciliationAttempts, wantResultRef, nil
}

func resolveFeedback(ctx context.Context, repository FeedbackRepository, query FeedbackQuery, deliveryCompletedAt time.Time) (*FeedbackSummary, error) {
	value, found, err := repository.GetFeedback(ctx, query)
	if err != nil {
		return nil, errors.Join(ErrFeedbackUnavailable, err)
	}
	if !found {
		return nil, nil
	}
	if value.Schema != FeedbackSchema || !validOpaqueRef(value.FeedbackID) || value.PublicRunRef != query.PublicRunRef ||
		value.ResultRef != query.ResultRef || value.AudienceSHA256 != query.AudienceSHA256 ||
		value.ReceivedAt.IsZero() || value.ReceivedAt.Before(deliveryCompletedAt) || !digestPattern.MatchString(value.RecordSHA256) {
		return nil, errors.New("evaluation feedback is invalid or cross-bound")
	}
	digest, err := feedbackRecordDigest(value)
	if err != nil || digest != value.RecordSHA256 {
		return nil, errors.New("evaluation feedback projection digest is invalid")
	}
	return &FeedbackSummary{RecordSHA256: value.RecordSHA256, Helpful: value.Helpful, ReceivedAt: value.ReceivedAt.UTC()}, nil
}

func validateTemporaryReviewRecord(value TemporaryReviewRecord, query TemporaryReviewQuery, completedAt time.Time) error {
	if value.Schema != ReviewSchema || !validOpaqueRef(value.ReviewID) || value.DatasetID != query.DatasetID ||
		value.DatasetRevision != query.DatasetRevision || value.DatasetItemID != query.DatasetItemID ||
		value.AnnotationSHA256 != query.AnnotationSHA256 || value.RuntimeRunID != query.RuntimeRunID ||
		value.RuntimeResultRef != query.RuntimeResultRef || value.RuntimeResultSHA256 != query.RuntimeResultSHA256 ||
		value.MediaRef != query.MediaRef || value.MediaSHA256 != query.MediaSHA256 || value.SpecSHA256 != query.SpecSHA256 ||
		value.ObservationSHA256 != query.ObservationSHA256 || !validOpaqueRef(value.PolicyRef) ||
		!reviewerPattern.MatchString(value.ReviewerPseudonym) || value.ReviewedAt.IsZero() || value.ReviewedAt.Before(completedAt) ||
		!digestPattern.MatchString(value.RecordSHA256) || validateResultValue(value.Observed) != nil || validateResultValue(value.Adjudicated) != nil {
		return errors.New("temporary evaluation review is invalid or not fully evidence-bound")
	}
	digest, err := temporaryReviewDigest(value)
	if err != nil || digest != value.RecordSHA256 {
		return errors.New("temporary evaluation review persistent digest is invalid")
	}
	return nil
}

func feedbackRecordDigest(value FeedbackRecord) (string, error) {
	value.RecordSHA256 = ""
	return digestValue(value)
}

func temporaryReviewDigest(value TemporaryReviewRecord) (string, error) {
	value.RecordSHA256 = ""
	return digestValue(value)
}

func digestDeliveryEvidence(value delivery.Record) (string, error) {
	return digestValue(struct {
		DeliveryID             string         `json:"deliveryId"`
		RunRef                 string         `json:"runRef"`
		ResultRef              string         `json:"resultRef"`
		AudienceSHA256         string         `json:"audienceSha256"`
		State                  delivery.State `json:"state"`
		Attempts               int            `json:"attempts"`
		ReconciliationAttempts int            `json:"reconciliationAttempts"`
		AvailableAt            time.Time      `json:"availableAt"`
		ReceiptRef             string         `json:"receiptRef"`
		Reason                 string         `json:"reason"`
		UpdatedAt              time.Time      `json:"updatedAt"`
		DeliveredAt            time.Time      `json:"deliveredAt"`
	}{value.Message.DeliveryID, value.Message.RunRef, value.Message.ResultRef, value.Message.AudienceSHA256,
		value.State, value.Attempts, value.ReconciliationAttempts, value.AvailableAt.UTC(), value.ReceiptRef,
		value.Reason, value.UpdatedAt.UTC(), value.DeliveredAt.UTC()})
}

// FeedbackProjectionSHA256 and TemporaryReviewRecordSHA256 are provided for
// trusted adapters and fixture repositories. They do not weaken verification:
// assembly always recomputes the digest and separately verifies review trust.
func FeedbackProjectionSHA256(value FeedbackRecord) (string, error) {
	return feedbackRecordDigest(value)
}
func TemporaryReviewRecordSHA256(value TemporaryReviewRecord) (string, error) {
	return temporaryReviewDigest(value)
}

func digestValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validAssemblyContext(value AssemblyContext) bool {
	_, err := loadSiteLocation(value.SiteTimezone)
	return err == nil && (value.CalibrationRole == CalibrationNone || value.CalibrationRole == CalibrationThresholdFit)
}

func mediaKindForDataset(kind media.Kind) MediaKind {
	switch kind {
	case media.KindImage:
		return MediaImage
	case media.KindFrameSet:
		return MediaFrameSet
	case media.KindVideoClip:
		return MediaVideoClip
	case media.KindMetric:
		return MediaMetric
	case media.KindDetection:
		return MediaDetection
	case media.KindEvent:
		return MediaEvent
	default:
		return ""
	}
}

func inspectionMediaKind(kind media.Kind) inspection.MediaKind { return inspection.MediaKind(kind) }

func containsInspectionMediaKind(values []inspection.MediaKind, wanted inspection.MediaKind) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func resultKindToDataset(kind ResultKind) dataset.LabelKind { return dataset.LabelKind(kind) }

func stableEvaluationRecordID(datasetID string, revision uint64, itemID, annotationDigest, resultIdentity string) string {
	value := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s", datasetID, revision, itemID, annotationDigest, resultIdentity)
	digest := sha256.Sum256([]byte(value))
	return "eval_" + hex.EncodeToString(digest[:16])
}

func stableDeliveryPseudonym(deliveryID string) string {
	digest := sha256.Sum256([]byte("inspection-evaluation-delivery\x00" + deliveryID))
	return "delivery_" + hex.EncodeToString(digest[:16])
}

func milliseconds(value time.Duration) float64 { return float64(value) / float64(time.Millisecond) }
