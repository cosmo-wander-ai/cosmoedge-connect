package dataset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

var (
	ErrInvalidSchema                 = errors.New("dataset schema is invalid")
	ErrInvalidRequest                = errors.New("dataset intake request is invalid")
	ErrUnauthorized                  = errors.New("dataset operation is unauthorized")
	ErrScopeMismatch                 = errors.New("media is outside dataset scope")
	ErrMediaUnavailable              = errors.New("media is unavailable")
	ErrRetention                     = errors.New("media retention is insufficient")
	ErrIntegrity                     = errors.New("media integrity does not match intake declaration")
	ErrProbe                         = errors.New("media probe facts are invalid")
	ErrReviewUnavailable             = errors.New("trusted review repository is unavailable")
	ErrReviewIncomplete              = errors.New("trusted review is incomplete")
	ErrReviewRejected                = errors.New("annotation was rejected by trusted review")
	ErrUnsupportedSemantics          = errors.New("annotation semantics are not registered")
	ErrLeakage                       = errors.New("dataset split leakage detected")
	ErrCapacity                      = errors.New("dataset storage capacity is exhausted")
	ErrConflict                      = errors.New("dataset revision already exists")
	ErrNotFound                      = errors.New("dataset revision not found")
	ErrTombstoned                    = errors.New("dataset revision is tombstoned")
	ErrGovernanceInProgress          = errors.New("dataset governance operation is in progress")
	ErrRetentionActive               = errors.New("dataset retention period is still active")
	ErrProtectedGovernanceProjection = errors.New("dataset governance request cannot be serialized")
)

var (
	opaqueRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	mediaRefPattern  = regexp.MustCompile(`^media_[a-f0-9]{32}$`)
	digestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	pseudonymPattern = regexp.MustCompile(`^(?:tenant|site|source|group)_[a-f0-9]{32}$`)
)

const (
	maximumReviewDecisions        = 16
	maximumDetectionObjects       = 2_000
	maximumStructuredFields       = 64
	maximumSceneTaxonomy          = 16
	maximumAdjacentWindow         = 7 * 24 * 60 * 60
	maximumMinimumRetention       = 365 * 24 * 60 * 60
	maximumIntakeJSONBytes        = 16 << 20
	maximumIntakeJSONDepth        = 32
	maximumLineageDepth           = 64
	maximumLineageDescriptors     = 100_000
	maximumPurposeLength          = 128
	maximumMetricAbsolute         = 1e15
	maximumGroundTruthCount       = int64(1_000_000_000)
	MaximumProtectedTaintPatterns = 250_000
	MaximumProtectedTaintBytes    = 32 << 20
)

func validOpaqueRef(value string) bool {
	if value != strings.TrimSpace(value) || !opaqueRefPattern.MatchString(value) || net.ParseIP(value) != nil {
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"http:", "https:", "rtsp:", "rtsps:", "file:", "data:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func validNamespacedRef(prefix, value string) bool {
	return strings.HasPrefix(value, prefix) && len(value) > len(prefix) && validOpaqueRef(value)
}

func validDigest(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validMediaRef(value string) bool { return mediaRefPattern.MatchString(value) }
func validPseudonym(domain, value string) bool {
	return strings.HasPrefix(value, domain+"_") && pseudonymPattern.MatchString(value)
}
func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() >= 0
}

func exactUnixNano(value time.Time) (int64, bool) {
	if !canonicalTime(value) {
		return 0, false
	}
	nanos := value.UnixNano()
	return nanos, time.Unix(0, nanos).UTC().Equal(value)
}

func validSplit(value Split) bool {
	switch value {
	case SplitTrain, SplitValidation, SplitTest:
		return true
	default:
		return false
	}
}

func validKind(kind media.Kind) bool {
	switch kind {
	case media.KindImage, media.KindFrameSet, media.KindVideoClip, media.KindMetric, media.KindDetection, media.KindEvent:
		return true
	default:
		return false
	}
}

func validPrivacyClass(value string) bool {
	switch value {
	case "public", "internal", "sensitive", "restricted":
		return true
	default:
		return false
	}
}

func validateLabel(label Label) error {
	present := 0
	for _, value := range []bool{label.Classification != nil, label.Enum != nil, label.Structured != nil, label.Count != nil, label.Metric != nil, label.Detection != nil, label.Event != nil} {
		if value {
			present++
		}
	}
	if present != 1 {
		return errors.New("label must contain exactly one union member")
	}
	switch label.Kind {
	case LabelClassification:
		if label.Classification == nil || !validClassification(label.Classification.Value) {
			return errors.New("classification label is invalid")
		}
	case LabelEnum:
		if label.Enum == nil || !validNamespacedRef("enum-", label.Enum.Value) {
			return errors.New("enum label is invalid")
		}
	case LabelStructured:
		if label.Structured == nil || len(label.Structured.Fields) < 1 || len(label.Structured.Fields) > maximumStructuredFields {
			return errors.New("structured label is invalid")
		}
		previous := ""
		for _, field := range label.Structured.Fields {
			if !validNamespacedRef("field-", field.Name) || field.Name <= previous || validateStructuredScalar(field.Value) != nil {
				return errors.New("structured label field is invalid")
			}
			previous = field.Name
		}
	case LabelCount:
		if label.Count == nil || label.Count.Value < 0 || label.Count.Value > maximumGroundTruthCount {
			return errors.New("count label is invalid")
		}
	case LabelMetric:
		if label.Metric == nil || !canonicalFinite(label.Metric.Value) || math.Abs(label.Metric.Value) > maximumMetricAbsolute || !validNamespacedRef("unit-", label.Metric.Unit) {
			return errors.New("metric label is invalid")
		}
	case LabelDetection:
		if label.Detection == nil || label.Detection.Objects == nil || len(label.Detection.Objects) > maximumDetectionObjects {
			return errors.New("detection label is invalid")
		}
		previous := ""
		for _, object := range label.Detection.Objects {
			if !validNamespacedRef("object-", object.Label) || !validRegion(object.Region) {
				return errors.New("detection object is invalid")
			}
			raw, err := json.Marshal(object)
			if err != nil || string(raw) <= previous {
				return errors.New("detection objects are not canonical")
			}
			previous = string(raw)
		}
	case LabelEvent:
		if label.Event == nil || !validNamespacedRef("event-", label.Event.Type) {
			return errors.New("event label is invalid")
		}
	default:
		return errors.New("label kind is unsupported")
	}
	return nil
}

func validateStructuredScalar(value StructuredScalar) error {
	present := 0
	for _, member := range []bool{value.Enum != nil, value.Number != nil, value.Integer != nil, value.Boolean != nil} {
		if member {
			present++
		}
	}
	if present != 1 {
		return errors.New("structured scalar must contain exactly one union member")
	}
	switch value.Kind {
	case StructuredEnum:
		if value.Enum == nil || !validNamespacedRef("enum-", *value.Enum) {
			return errors.New("structured enum is invalid")
		}
	case StructuredNumber:
		if value.Number == nil || !canonicalFinite(*value.Number) || math.Abs(*value.Number) > maximumMetricAbsolute {
			return errors.New("structured number is invalid")
		}
	case StructuredInteger:
		if value.Integer == nil {
			return errors.New("structured integer is invalid")
		}
	case StructuredBoolean:
		if value.Boolean == nil {
			return errors.New("structured boolean is invalid")
		}
	default:
		return errors.New("structured scalar kind is invalid")
	}
	return nil
}

func validClassification(value ClassificationValue) bool {
	switch value {
	case ClassificationMeetsRule, ClassificationNeedsAttention, ClassificationUncertain, ClassificationNotObservable, ClassificationUnsupported:
		return true
	default:
		return false
	}
}

func validRegion(region NormalizedRegion) bool {
	for _, value := range []float64{region.X, region.Y, region.Width, region.Height} {
		if !canonicalFinite(value) || value < 0 || value > 1 {
			return false
		}
	}
	return region.Width > 0 && region.Height > 0 && region.X+region.Width <= 1 && region.Y+region.Height <= 1
}
func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
func canonicalFinite(value float64) bool {
	return finite(value) && !(value == 0 && math.Signbit(value))
}

func validatePolicy(policy Policy, now time.Time) error {
	if policy.Schema != PolicySchema || !canonicalTime(policy.RetainUntil) || !policy.RetainUntil.After(now) ||
		policy.MinimumRemainingRetentionSeconds < 1 || policy.MinimumRemainingRetentionSeconds > maximumMinimumRetention ||
		!validOpaqueRef(policy.ReviewPolicyRef) || policy.MinimumApprovals < 1 || policy.MinimumApprovals > maximumReviewDecisions ||
		policy.AdjacentSourceWindowSeconds < 0 || policy.AdjacentSourceWindowSeconds > maximumAdjacentWindow {
		return ErrInvalidRequest
	}
	if len(policy.AllowedKinds) == 0 || len(policy.AllowedKinds) > 6 || !strictKinds(policy.AllowedKinds) {
		return ErrInvalidRequest
	}
	for _, kind := range policy.AllowedKinds {
		if !validKind(kind) {
			return ErrInvalidRequest
		}
	}
	if len(policy.AllowedPrivacyClasses) == 0 || len(policy.AllowedPrivacyClasses) > 4 || !strictStrings(policy.AllowedPrivacyClasses) {
		return ErrInvalidRequest
	}
	for _, value := range policy.AllowedPrivacyClasses {
		if !validPrivacyClass(value) {
			return ErrInvalidRequest
		}
	}
	if len(policy.RequiredRetentionPolicyRefs) == 0 || len(policy.RequiredRetentionPolicyRefs) > 16 || !strictStrings(policy.RequiredRetentionPolicyRefs) {
		return ErrInvalidRequest
	}
	for _, value := range policy.RequiredRetentionPolicyRefs {
		if !validOpaqueRef(value) {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validateAnnotation(value AnnotationCandidate) error {
	if value.Schema != AnnotationSchema || !validNamespacedRef("annotation-", value.AnnotationID) || !validNamespacedRef("criterion-", value.CriterionID) || value.CriterionVersion < 1 ||
		len(value.SceneTaxonomy) == 0 || len(value.SceneTaxonomy) > maximumSceneTaxonomy || !strictStrings(value.SceneTaxonomy) ||
		!validNamespacedRef("result-schema-", value.ResultSchemaRef) || value.ResultKind != value.Label.Kind || validateLabel(value.Label) != nil {
		return ErrInvalidRequest
	}
	for _, scene := range value.SceneTaxonomy {
		if !validNamespacedRef("scene-", scene) {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validateRequestShape(request IntakeRequest, now time.Time) error {
	if request.Schema != Schema {
		return ErrInvalidSchema
	}
	if !validOpaqueRef(request.TenantID) || !validOpaqueRef(request.SiteID) || !validNamespacedRef("dataset-", request.DatasetID) || request.Revision < 1 ||
		!validNamespacedRef("purpose-", request.PurposeRef) || len(request.PurposeRef) > maximumPurposeLength || !validOpaqueRef(request.AuthorityRef) ||
		!validDigest(request.PrincipalSHA256) || len(request.Items) < 3 || len(request.Items) > MaximumItems {
		return ErrInvalidRequest
	}
	if err := validatePolicy(request.Policy, now); err != nil {
		return err
	}
	previousItem := ""
	annotationCount := 0
	objectCount := 0
	for _, item := range request.Items {
		if item.Schema != ItemSchema || !validNamespacedRef("item-", item.ItemID) || item.ItemID <= previousItem || !validMediaRef(item.MediaRef) ||
			!validKind(item.ExpectedKind) || item.ExpectedMIME != strings.TrimSpace(item.ExpectedMIME) || strings.ToLower(item.ExpectedMIME) != item.ExpectedMIME ||
			(item.ExpectedKind != media.KindFrameSet && item.ExpectedMIME == "") || (item.ExpectedKind == media.KindFrameSet && item.ExpectedMIME != "") ||
			!validDigest(item.ExpectedSHA256) || !validOpaqueRef(item.GroupRef) || !validSplit(item.Split) ||
			len(item.Annotations) == 0 || len(item.Annotations) > MaximumAnnotationsPerItem {
			return ErrInvalidRequest
		}
		previousAnnotation := ""
		criterionKeys := make(map[string]struct{}, len(item.Annotations))
		for _, annotation := range item.Annotations {
			if annotation.AnnotationID <= previousAnnotation || validateAnnotation(annotation) != nil {
				return ErrInvalidRequest
			}
			key := fmt.Sprintf("%s\x00%020d\x00%s", annotation.CriterionID, annotation.CriterionVersion, annotation.ResultSchemaRef)
			if _, duplicate := criterionKeys[key]; duplicate {
				return ErrInvalidRequest
			}
			criterionKeys[key] = struct{}{}
			previousAnnotation = annotation.AnnotationID
			annotationCount++
			if annotation.Label.Detection != nil {
				objectCount += len(annotation.Label.Detection.Objects)
			}
		}
		previousItem = item.ItemID
	}
	if annotationCount > MaximumAnnotations || objectCount > MaximumObjectsPerDataset {
		return ErrInvalidRequest
	}
	canonical, err := json.Marshal(request)
	if err != nil || len(canonical) > maximumIntakeJSONBytes {
		return ErrInvalidRequest
	}
	return nil
}

func strictStrings(values []string) bool {
	if values == nil || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if value == "" || (index > 0 && values[index-1] == value) {
			return false
		}
	}
	return true
}

func strictKinds(values []media.Kind) bool {
	if values == nil {
		return false
	}
	for index, value := range values {
		if value == "" || (index > 0 && string(values[index-1]) >= string(value)) {
			return false
		}
	}
	return true
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}
func containsKind(values []media.Kind, wanted media.Kind) bool {
	index := sort.Search(len(values), func(index int) bool { return string(values[index]) >= string(wanted) })
	return index < len(values) && values[index] == wanted
}

func sha256JSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func PolicySHA256(policy Policy) (string, error) { return sha256JSON(policy) }

type canonicalIntakeSemantic struct {
	Schema     string      `json:"schema"`
	TenantID   string      `json:"tenantId"`
	SiteID     string      `json:"siteId"`
	DatasetID  string      `json:"datasetId"`
	Revision   uint64      `json:"revision"`
	PurposeRef string      `json:"purposeRef"`
	Policy     Policy      `json:"policy"`
	Items      []Candidate `json:"items"`
}

// IntakeSemanticSHA256 binds every business-semantic intake field while
// deliberately excluding transport authority and principal material.
func IntakeSemanticSHA256(request IntakeRequest) (string, error) {
	if request.Schema != Schema || !validOpaqueRef(request.TenantID) || !validOpaqueRef(request.SiteID) ||
		!validNamespacedRef("dataset-", request.DatasetID) || request.Revision < 1 || !validNamespacedRef("purpose-", request.PurposeRef) || request.Items == nil {
		return "", ErrInvalidRequest
	}
	items := make([]Candidate, len(request.Items))
	for index, item := range request.Items {
		items[index] = item
		items[index].Annotations = make([]AnnotationCandidate, len(item.Annotations))
		for annotationIndex, annotation := range item.Annotations {
			items[index].Annotations[annotationIndex] = cloneAnnotationCandidate(annotation)
		}
	}
	return sha256JSON(canonicalIntakeSemantic{Schema: request.Schema, TenantID: request.TenantID, SiteID: request.SiteID,
		DatasetID: request.DatasetID, Revision: request.Revision, PurposeRef: request.PurposeRef, Policy: request.Policy, Items: items})
}

func IntakeSHA256(request IntakeRequest) (string, error) { return IntakeSemanticSHA256(request) }

func DescriptorSHA256(descriptor media.Descriptor) (string, error) {
	if err := descriptor.Validate(); err != nil || !canonicalDescriptorTimes(descriptor) {
		return "", fmt.Errorf("%w: invalid descriptor", ErrIntegrity)
	}
	return sha256JSON(descriptor)
}

func canonicalDescriptorTimes(descriptor media.Descriptor) bool {
	if _, ok := exactUnixNano(descriptor.CreatedAt); !ok {
		return false
	}
	if _, ok := exactUnixNano(descriptor.Governance.ExpiresAt); !ok {
		return false
	}
	for _, value := range []*time.Time{descriptor.Temporal.WindowStart, descriptor.Temporal.WindowEnd, descriptor.DeletedAt} {
		if value != nil {
			if _, ok := exactUnixNano(*value); !ok {
				return false
			}
		}
	}
	return true
}

func LabelSHA256(label Label) (string, error) {
	if err := validateLabel(label); err != nil {
		return "", fmt.Errorf("%w: invalid label", ErrInvalidRequest)
	}
	return sha256JSON(label)
}

func BuildReviewSubject(request IntakeRequest, candidate Candidate, annotation AnnotationCandidate, descriptor media.Descriptor) (ReviewSubject, error) {
	if request.Schema != Schema || candidate.Schema != ItemSchema || validateAnnotation(annotation) != nil || descriptor.Validate() != nil ||
		descriptor.MediaRef != candidate.MediaRef || request.DatasetID == "" || request.Revision < 1 {
		return ReviewSubject{}, ErrInvalidRequest
	}
	descriptorDigest, err := DescriptorSHA256(descriptor)
	if err != nil {
		return ReviewSubject{}, err
	}
	intakeDigest, err := IntakeSemanticSHA256(request)
	if err != nil {
		return ReviewSubject{}, err
	}
	return buildReviewSubjectWithDigest(request, candidate, annotation, descriptor, descriptorDigest, intakeDigest)
}

func buildReviewSubjectWithDigest(request IntakeRequest, candidate Candidate, annotation AnnotationCandidate, descriptor media.Descriptor, descriptorDigest, intakeDigest string) (ReviewSubject, error) {
	if !validDigest(descriptorDigest) || !validDigest(intakeDigest) {
		return ReviewSubject{}, ErrInvalidRequest
	}
	return ReviewSubject{Schema: AnnotationSchema, DatasetID: request.DatasetID, Revision: request.Revision, ItemID: candidate.ItemID,
		MediaRef: candidate.MediaRef, DescriptorSHA256: descriptorDigest, IntakeSemanticSHA256: intakeDigest, Annotation: cloneAnnotationCandidate(annotation)}, nil
}

func AnnotationSHA256(subject ReviewSubject) (string, error) {
	if subject.Schema != AnnotationSchema || !validOpaqueRef(subject.DatasetID) || subject.Revision < 1 || !validOpaqueRef(subject.ItemID) ||
		!validMediaRef(subject.MediaRef) || !validDigest(subject.DescriptorSHA256) || !validDigest(subject.IntakeSemanticSHA256) || validateAnnotation(subject.Annotation) != nil {
		return "", ErrInvalidRequest
	}
	return sha256JSON(subject)
}

type canonicalReviewRecord struct {
	Schema           string         `json:"schema"`
	ReviewID         string         `json:"reviewId"`
	AnnotationSHA256 string         `json:"annotationSha256"`
	ReviewerSHA256   string         `json:"reviewerSha256"`
	ReviewerRole     string         `json:"reviewerRole"`
	Decision         ReviewDecision `json:"decision"`
	PolicyRef        string         `json:"policyRef"`
	ReviewedAt       time.Time      `json:"reviewedAt"`
}

func ReviewRecordSHA256(record ReviewRecord) (string, error) {
	if record.Schema != ReviewSchema || !validOpaqueRef(record.ReviewID) || !validDigest(record.AnnotationSHA256) || !validDigest(record.ReviewerSHA256) ||
		record.ReviewerRole != ReviewerRoleDataset || (record.Decision != ReviewApproved && record.Decision != ReviewRejected) || !validOpaqueRef(record.PolicyRef) || !canonicalTime(record.ReviewedAt) {
		return "", ErrReviewIncomplete
	}
	return sha256JSON(canonicalReviewRecord{record.Schema, record.ReviewID, record.AnnotationSHA256, record.ReviewerSHA256, record.ReviewerRole, record.Decision, record.PolicyRef, record.ReviewedAt})
}

func validateReviewRecord(record ReviewRecord) error {
	digest, err := ReviewRecordSHA256(record)
	if err != nil || record.RecordSHA256 != digest {
		return ErrReviewIncomplete
	}
	return nil
}

func validateSemanticsDemand(value SemanticsDemand) error {
	candidate := AnnotationCandidate{Schema: AnnotationSchema, AnnotationID: "annotation-semantics", CriterionID: value.CriterionID,
		CriterionVersion: value.CriterionVersion, SceneTaxonomy: value.SceneTaxonomy, ResultKind: value.ResultKind,
		ResultSchemaRef: value.ResultSchemaRef, Label: value.Label}
	if validateAnnotation(candidate) != nil {
		return ErrUnsupportedSemantics
	}
	return nil
}
