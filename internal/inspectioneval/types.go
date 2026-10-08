package inspectioneval

import "time"

const (
	RecordSchema   = "cosmoedge.inspection.eval.record.v3"
	ReviewSchema   = "cosmoedge.inspection.eval.review.v3"
	FeedbackSchema = "cosmoedge.inspection.eval.feedback.v3"
	ReportSchema   = "cosmoedge.inspection.eval.report.v3"

	MaximumManifestLineBytes = 8 << 20
	MaximumManifestRecords   = 1_000_000
	MaximumCriteria          = 128
)

type Split string

const (
	SplitTrain      Split = "train"
	SplitValidation Split = "validation"
	SplitTest       Split = "test"
)

type Strategy string

const (
	StrategyExistingTaskRead Strategy = "existing_task_read"
	StrategySnapshotAnalysis Strategy = "snapshot_analysis"
	StrategyClipAnalysis     Strategy = "clip_analysis"
	StrategyHybridAnalysis   Strategy = "hybrid_analysis"
)

type SourceKind string

const (
	SourceCamera        SourceKind = "camera"
	SourceUploadedImage SourceKind = "uploaded_image"
	SourceUploadedVideo SourceKind = "uploaded_video"
	SourceTaskEvidence  SourceKind = "task_evidence"
	SourceRetainedMedia SourceKind = "retained_media"
	// SourcePreparedObservation is the only source classification that can be
	// derived from a temporary runtime record. The runtime deliberately does
	// not expose a device or upload origin, so the evaluator must not guess one.
	SourcePreparedObservation SourceKind = "prepared_observation"
)

type MediaKind string

const (
	MediaImage     MediaKind = "image"
	MediaFrameSet  MediaKind = "frame_set"
	MediaVideoClip MediaKind = "video_clip"
	MediaMetric    MediaKind = "metric"
	MediaDetection MediaKind = "detection"
	MediaEvent     MediaKind = "event"
)

type ResultKind string

const (
	ResultClassification ResultKind = "classification"
	ResultEnum           ResultKind = "enum"
	ResultStructured     ResultKind = "structured"
	ResultMetric         ResultKind = "metric"
	ResultCount          ResultKind = "count"
	ResultDetection      ResultKind = "detection"
	ResultEvent          ResultKind = "event"
)

type ValueState string

const (
	ValuePresent       ValueState = "value"
	ValueUncertain     ValueState = "uncertain"
	ValueNotObservable ValueState = "not_observable"
	ValueUnsupported   ValueState = "unsupported"
)

type ClassificationValue string

const (
	ClassificationMeetsRule      ClassificationValue = "meets_rule"
	ClassificationNeedsAttention ClassificationValue = "needs_attention"
)

type ClassificationResult struct {
	Value ClassificationValue `json:"value"`
}

type EnumResult struct {
	Value string `json:"value"`
}

type StructuredFieldKind string

const (
	StructuredBoolean StructuredFieldKind = "boolean"
	StructuredEnum    StructuredFieldKind = "enum"
	StructuredNumber  StructuredFieldKind = "number"
	StructuredInteger StructuredFieldKind = "integer"
)

type MetricResult struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

type StructuredField struct {
	Name    string              `json:"name"`
	Kind    StructuredFieldKind `json:"kind"`
	Boolean *bool               `json:"boolean,omitempty"`
	Enum    *string             `json:"enum,omitempty"`
	Number  *float64            `json:"number,omitempty"`
	Integer *int64              `json:"integer,omitempty"`
}

type StructuredResult struct {
	Fields []StructuredField `json:"fields"`
}

type CountResult struct {
	Value int64 `json:"value"`
}

type NormalizedRegion struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type DetectionObject struct {
	Label  string           `json:"label"`
	Region NormalizedRegion `json:"region"`
}

type DetectionResult struct {
	Objects []DetectionObject `json:"objects"`
}

type EventResult struct {
	Type     string `json:"type"`
	Occurred bool   `json:"occurred"`
}

// ResultValue is a closed union. A present value has exactly one member that
// matches Kind; an abstention has no member. There is no RawMessage or map
// escape hatch.
type ResultValue struct {
	Kind           ResultKind            `json:"kind"`
	State          ValueState            `json:"state"`
	Classification *ClassificationResult `json:"classification,omitempty"`
	Enum           *EnumResult           `json:"enum,omitempty"`
	Structured     *StructuredResult     `json:"structured,omitempty"`
	Metric         *MetricResult         `json:"metric,omitempty"`
	Count          *CountResult          `json:"count,omitempty"`
	Detection      *DetectionResult      `json:"detection,omitempty"`
	Event          *EventResult          `json:"event,omitempty"`
}

type ObservationMode string

const (
	ObservationStandard  ObservationMode = "standard"
	ObservationTemporary ObservationMode = "temporary"
)

// TemporaryReview is required for every temporary observation. Adjudicated is
// independently reviewed truth used only for review-agreement metrics.
type TemporaryReview struct {
	Schema            string      `json:"schema"`
	ReviewID          string      `json:"reviewId"`
	RecordSHA256      string      `json:"recordSha256"`
	ReviewerPseudonym string      `json:"reviewerPseudonym"`
	ReviewedAt        time.Time   `json:"reviewedAt"`
	Adjudicated       ResultValue `json:"adjudicated"`
	ReviewPolicyRef   string      `json:"reviewPolicyRef"`
}

type DeliveryStatus string

const (
	DeliveryDelivered DeliveryStatus = "delivered"
	DeliveryUnknown   DeliveryStatus = "unknown"
	DeliveryFailed    DeliveryStatus = "failed"
)

// FeedbackSummary is the evaluation-safe projection of channel feedback. The
// free-form comment is deliberately excluded because it can contain personal,
// site, device, or credential information that is unnecessary for metrics.
type FeedbackSummary struct {
	RecordSHA256 string    `json:"recordSha256"`
	Helpful      bool      `json:"helpful"`
	ReceivedAt   time.Time `json:"receivedAt"`
}

type Latencies struct {
	EndToEndMS float64 `json:"endToEndMs"`
	AnalysisMS float64 `json:"analysisMs"`
	DeliveryMS float64 `json:"deliveryMs"`
}

type CalibrationRole string

const (
	CalibrationNone         CalibrationRole = "none"
	CalibrationThresholdFit CalibrationRole = "threshold_calibration"
)

// Record is one v3 evaluation projection. All location/source values are
// pseudonyms and the record contains no media locator, payload, or credential.
type Record struct {
	Schema                 string           `json:"schema"`
	RecordID               string           `json:"recordId"`
	TenantPseudonym        string           `json:"tenantPseudonym"`
	SitePseudonym          string           `json:"sitePseudonym"`
	SourcePseudonym        string           `json:"sourcePseudonym"`
	CapturedAt             time.Time        `json:"capturedAt"`
	SiteTimezone           string           `json:"siteTimezone"`
	SceneStrata            []string         `json:"sceneStrata"`
	CriterionID            string           `json:"criterionId"`
	CriterionVersion       uint64           `json:"criterionVersion"`
	ResultSchemaRef        string           `json:"resultSchemaRef"`
	Strategy               Strategy         `json:"strategy"`
	SourceKind             SourceKind       `json:"sourceKind"`
	MediaKind              MediaKind        `json:"mediaKind"`
	Split                  Split            `json:"split"`
	GroupKey               string           `json:"groupKey"`
	CalibrationRole        CalibrationRole  `json:"calibrationRole"`
	ObservationMode        ObservationMode  `json:"observationMode"`
	Expected               ResultValue      `json:"expected"`
	Observed               ResultValue      `json:"observed"`
	TemporaryReview        *TemporaryReview `json:"temporaryReview,omitempty"`
	Latencies              Latencies        `json:"latencies"`
	DeliveryPseudonym      string           `json:"deliveryPseudonym"`
	DeliveryEvidenceSHA256 string           `json:"deliveryEvidenceSha256"`
	DeliveryStatus         DeliveryStatus   `json:"deliveryStatus"`
	DeliveryAttempts       int              `json:"deliveryAttempts"`
	ReconciliationAttempts int              `json:"reconciliationAttempts"`
	Feedback               *FeedbackSummary `json:"feedback,omitempty"`

	sourceLine int
}

type Manifest struct {
	Records []Record
}

type Issue struct {
	Line    int    `json:"line,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

type ValidationError struct {
	Issues []Issue
}

type Ratio struct {
	Value       *float64 `json:"value"`
	Numerator   int      `json:"numerator"`
	Denominator int      `json:"denominator"`
}

type Distribution struct {
	Samples int      `json:"samples"`
	Minimum *float64 `json:"minimumMs"`
	Maximum *float64 `json:"maximumMs"`
	Mean    *float64 `json:"meanMs"`
	P50     *float64 `json:"p50Ms"`
	P95     *float64 `json:"p95Ms"`
	P99     *float64 `json:"p99Ms"`
}

type CoverageMetrics struct {
	Eligible  int   `json:"eligible"`
	Covered   int   `json:"covered"`
	Abstained int   `json:"abstained"`
	Coverage  Ratio `json:"coverage"`
}

type ClassificationMetrics struct {
	EligibleExpectedDecisions  int   `json:"eligibleExpectedDecisions"`
	Covered                    int   `json:"covered"`
	Abstained                  int   `json:"abstained"`
	ExcludedExpectedAbstention int   `json:"excludedExpectedAbstention"`
	TruePositive               int   `json:"truePositive"`
	FalsePositive              int   `json:"falsePositive"`
	FalseNegative              int   `json:"falseNegative"`
	TrueNegative               int   `json:"trueNegative"`
	FalseClear                 int   `json:"falseClear"`
	Precision                  Ratio `json:"precision"`
	Recall                     Ratio `json:"recall"`
	FalseClearRate             Ratio `json:"falseClearRate"`
	AbstentionRate             Ratio `json:"abstentionRate"`
	Coverage                   Ratio `json:"coverage"`
	Accuracy                   Ratio `json:"accuracy"`
	CoveredAccuracy            Ratio `json:"coveredAccuracy"`
}

type ExactMatchMetrics struct {
	Eligible        int   `json:"eligible"`
	Covered         int   `json:"covered"`
	Abstained       int   `json:"abstained"`
	Matches         int   `json:"matches"`
	Accuracy        Ratio `json:"accuracy"`
	CoveredAccuracy Ratio `json:"coveredAccuracy"`
}

type StructuredMetrics struct {
	ExactMatchMetrics
	ComparedFields int   `json:"comparedFields"`
	MatchingFields int   `json:"matchingFields"`
	FieldAgreement Ratio `json:"fieldAgreement"`
}

type ErrorMetrics struct {
	Eligible  int      `json:"eligible"`
	Covered   int      `json:"covered"`
	Abstained int      `json:"abstained"`
	MAE       *float64 `json:"mae"`
	RMSE      *float64 `json:"rmse"`
}

type DetectionMetrics struct {
	EligibleSamples  int      `json:"eligibleSamples"`
	CoveredSamples   int      `json:"coveredSamples"`
	AbstainedSamples int      `json:"abstainedSamples"`
	ExpectedObjects  int      `json:"expectedObjects"`
	ObservedObjects  int      `json:"observedObjects"`
	TruePositive     int      `json:"truePositive"`
	FalsePositive    int      `json:"falsePositive"`
	FalseNegative    int      `json:"falseNegative"`
	Precision        Ratio    `json:"precision"`
	Recall           Ratio    `json:"recall"`
	MeanMatchedIoU   *float64 `json:"meanMatchedIoU"`
	IoUThreshold     float64  `json:"iouThreshold"`
}

type EventMetrics struct {
	Eligible      int   `json:"eligible"`
	Covered       int   `json:"covered"`
	Abstained     int   `json:"abstained"`
	TruePositive  int   `json:"truePositive"`
	FalsePositive int   `json:"falsePositive"`
	FalseNegative int   `json:"falseNegative"`
	TrueNegative  int   `json:"trueNegative"`
	Precision     Ratio `json:"precision"`
	Recall        Ratio `json:"recall"`
}

type DeliveryMetrics struct {
	Attempts               int   `json:"attempts"`
	ReconciliationAttempts int   `json:"reconciliationAttempts"`
	Delivered              int   `json:"delivered"`
	Unknown                int   `json:"unknown"`
	Failed                 int   `json:"failed"`
	Reliability            Ratio `json:"reliability"`
	UnknownRate            Ratio `json:"unknownRate"`
	KnownSuccessRate       Ratio `json:"knownSuccessRate"`
}

type ReviewMetrics struct {
	TemporaryRecords int   `json:"temporaryRecords"`
	Reviewed         int   `json:"reviewed"`
	Agreements       int   `json:"agreements"`
	Disagreements    int   `json:"disagreements"`
	Agreement        Ratio `json:"agreement"`
}

type FeedbackMetrics struct {
	Responses   int   `json:"responses"`
	Helpful     int   `json:"helpful"`
	Unhelpful   int   `json:"unhelpful"`
	HelpfulRate Ratio `json:"helpfulRate"`
}

type LatencyMetrics struct {
	EndToEnd Distribution `json:"endToEnd"`
	Analysis Distribution `json:"analysis"`
	Delivery Distribution `json:"delivery"`
}

type Metrics struct {
	Records        int                   `json:"records"`
	Coverage       CoverageMetrics       `json:"coverage"`
	Classification ClassificationMetrics `json:"classification"`
	Enum           ExactMatchMetrics     `json:"enum"`
	Structured     StructuredMetrics     `json:"structured"`
	Metric         ErrorMetrics          `json:"metric"`
	Count          ErrorMetrics          `json:"count"`
	Detection      DetectionMetrics      `json:"detection"`
	Event          EventMetrics          `json:"event"`
	Delivery       DeliveryMetrics       `json:"delivery"`
	Review         ReviewMetrics         `json:"review"`
	Feedback       FeedbackMetrics       `json:"feedback"`
	Latency        LatencyMetrics        `json:"latency"`
}

type SliceMetrics struct {
	Key     string  `json:"key"`
	Metrics Metrics `json:"metrics"`
}

type CriterionSliceMetrics struct {
	CriterionID      string     `json:"criterionId"`
	CriterionVersion uint64     `json:"criterionVersion"`
	ResultSchemaRef  string     `json:"resultSchemaRef"`
	ResultKind       ResultKind `json:"resultKind"`
	Metrics          Metrics    `json:"metrics"`
}

type CalibrationSummary struct {
	TrainRecords           int `json:"trainRecords"`
	ValidationRecords      int `json:"validationRecords"`
	ThresholdFitTrain      int `json:"thresholdFitTrain"`
	ThresholdFitValidation int `json:"thresholdFitValidation"`
	ThresholdFitTest       int `json:"thresholdFitTest"`
}

type EvaluationReport struct {
	Schema         string                  `json:"schema"`
	PrimarySplit   Split                   `json:"primarySplit"`
	Overall        Metrics                 `json:"overall"`
	ByStrategy     []SliceMetrics          `json:"byStrategy"`
	ByCriterion    []CriterionSliceMetrics `json:"byCriterion"`
	BySourceKind   []SliceMetrics          `json:"bySourceKind"`
	ByMediaKind    []SliceMetrics          `json:"byMediaKind"`
	BySite         []SliceMetrics          `json:"bySite"`
	BySource       []SliceMetrics          `json:"bySource"`
	BySceneStratum []SliceMetrics          `json:"bySceneStratum"`
	BySplit        []SliceMetrics          `json:"bySplit"`
	Calibration    CalibrationSummary      `json:"calibration"`
}
