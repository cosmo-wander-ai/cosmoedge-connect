package dataset

import (
	"context"
	"log/slog"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

const (
	Schema                        = "cosmoedge.inspection.dataset.v3"
	PolicySchema                  = "cosmoedge.inspection.dataset.policy.v3"
	ItemSchema                    = "cosmoedge.inspection.dataset.media-item.v3"
	AnnotationSchema              = "cosmoedge.inspection.dataset.annotation.v3"
	ReviewSchema                  = "cosmoedge.inspection.dataset.review.v3"
	AuthorizationSchema           = "cosmoedge.inspection.dataset.authorization.v3"
	GovernanceRequestSchema       = "cosmoedge.inspection.dataset.governance-request.v3"
	GovernanceAuthorizationSchema = "cosmoedge.inspection.dataset.governance-authorization.v3"

	MaximumItems                  = 10_000
	MaximumAnnotationsPerItem     = 64
	MaximumAnnotations            = 100_000
	MaximumObjectsPerDataset      = 100_000
	MaximumFrameMembersPerDataset = 100_000
	MaximumClaimsPerItem          = 4_096
	MaximumClaimsPerDataset       = 200_000
	ReviewerRoleDataset           = "role-dataset-reviewer"
)

type Split string

const (
	SplitTrain      Split = "train"
	SplitValidation Split = "validation"
	SplitTest       Split = "test"
)

// LabelKind is a closed ground-truth union. There is deliberately no raw JSON
// escape hatch: every admitted result kind has one typed representation.
type LabelKind string

const (
	LabelClassification LabelKind = "classification"
	LabelEnum           LabelKind = "enum"
	LabelStructured     LabelKind = "structured"
	LabelCount          LabelKind = "count"
	LabelMetric         LabelKind = "metric"
	LabelDetection      LabelKind = "detection"
	LabelEvent          LabelKind = "event"
)

type ClassificationValue string

const (
	ClassificationMeetsRule      ClassificationValue = "meets_rule"
	ClassificationNeedsAttention ClassificationValue = "needs_attention"
	ClassificationUncertain      ClassificationValue = "uncertain"
	ClassificationNotObservable  ClassificationValue = "not_observable"
	ClassificationUnsupported    ClassificationValue = "unsupported"
)

type ClassificationLabel struct {
	Value ClassificationValue `json:"value"`
}
type EnumLabel struct {
	Value string `json:"value"`
}

type StructuredScalarKind string

const (
	StructuredEnum    StructuredScalarKind = "enum"
	StructuredNumber  StructuredScalarKind = "number"
	StructuredInteger StructuredScalarKind = "integer"
	StructuredBoolean StructuredScalarKind = "boolean"
)

type StructuredScalar struct {
	Kind    StructuredScalarKind `json:"kind"`
	Enum    *string              `json:"enum,omitempty"`
	Number  *float64             `json:"number,omitempty"`
	Integer *int64               `json:"integer,omitempty"`
	Boolean *bool                `json:"boolean,omitempty"`
}

type StructuredField struct {
	Name  string           `json:"name"`
	Value StructuredScalar `json:"value"`
}

type StructuredLabel struct {
	Fields []StructuredField `json:"fields"`
}
type CountLabel struct {
	Value int64 `json:"value"`
}
type MetricLabel struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
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

type DetectionLabel struct {
	Objects []DetectionObject `json:"objects"`
}
type EventLabel struct {
	Type     string `json:"type"`
	Occurred bool   `json:"occurred"`
}

type Label struct {
	Kind           LabelKind            `json:"kind"`
	Classification *ClassificationLabel `json:"classification,omitempty"`
	Enum           *EnumLabel           `json:"enum,omitempty"`
	Structured     *StructuredLabel     `json:"structured,omitempty"`
	Count          *CountLabel          `json:"count,omitempty"`
	Metric         *MetricLabel         `json:"metric,omitempty"`
	Detection      *DetectionLabel      `json:"detection,omitempty"`
	Event          *EventLabel          `json:"event,omitempty"`
}

type ReviewDecision string

const (
	ReviewApproved ReviewDecision = "approved"
	ReviewRejected ReviewDecision = "rejected"
)

// ReviewRecord is produced by a trusted review system, not by IntakeRequest.
// RecordSHA256 binds every decision field and is independently verified by a
// ReviewVerifier before it can count toward admission.
type ReviewRecord struct {
	Schema           string         `json:"schema"`
	ReviewID         string         `json:"reviewId"`
	AnnotationSHA256 string         `json:"annotationSha256"`
	ReviewerSHA256   string         `json:"reviewerSha256"`
	ReviewerRole     string         `json:"reviewerRole"`
	Decision         ReviewDecision `json:"decision"`
	PolicyRef        string         `json:"policyRef"`
	ReviewedAt       time.Time      `json:"reviewedAt"`
	RecordSHA256     string         `json:"recordSha256"`
}

type ReviewQuery struct {
	AnnotationSHA256 string
	PolicyRef        string
	NotAfter         time.Time
}

type ReviewRepository interface {
	ListReviews(context.Context, ReviewQuery) ([]ReviewRecord, error)
}

type ReviewVerifier interface {
	VerifyReview(context.Context, ReviewVerificationDemand) error
}

type ReviewVerificationDemand struct {
	Record                ReviewRecord
	IntakePrincipalSHA256 string
}

type Policy struct {
	Schema                           string       `json:"schema"`
	AllowedKinds                     []media.Kind `json:"allowedKinds"`
	AllowedPrivacyClasses            []string     `json:"allowedPrivacyClasses"`
	RequiredRetentionPolicyRefs      []string     `json:"requiredRetentionPolicyRefs"`
	RetainUntil                      time.Time    `json:"retainUntil"`
	MinimumRemainingRetentionSeconds int          `json:"minimumRemainingRetentionSeconds"`
	ReviewPolicyRef                  string       `json:"reviewPolicyRef"`
	MinimumApprovals                 int          `json:"minimumApprovals"`
	AdjacentSourceWindowSeconds      int          `json:"adjacentSourceWindowSeconds"`
}

// AnnotationCandidate is one independently reviewable ground-truth assertion.
// Multiple criteria and result schemas may annotate the same media item.
type AnnotationCandidate struct {
	Schema           string    `json:"schema"`
	AnnotationID     string    `json:"annotationId"`
	CriterionID      string    `json:"criterionId"`
	CriterionVersion uint64    `json:"criterionVersion"`
	SceneTaxonomy    []string  `json:"sceneTaxonomy"`
	ResultKind       LabelKind `json:"resultKind"`
	ResultSchemaRef  string    `json:"resultSchemaRef"`
	Label            Label     `json:"label"`
}

// Candidate declares only media identity/integrity plus annotations. Review
// decisions cannot be represented by the public intake contract.
type Candidate struct {
	Schema         string                `json:"schema"`
	ItemID         string                `json:"itemId"`
	MediaRef       string                `json:"mediaRef"`
	ExpectedKind   media.Kind            `json:"expectedKind"`
	ExpectedMIME   string                `json:"expectedMime"`
	ExpectedSHA256 string                `json:"expectedSha256"`
	GroupRef       string                `json:"groupRef"`
	Split          Split                 `json:"split"`
	Annotations    []AnnotationCandidate `json:"annotations"`
}

type IntakeRequest struct {
	Schema          string      `json:"schema"`
	TenantID        string      `json:"tenantId"`
	SiteID          string      `json:"siteId"`
	DatasetID       string      `json:"datasetId"`
	Revision        uint64      `json:"revision"`
	PurposeRef      string      `json:"purposeRef"`
	AuthorityRef    string      `json:"authorityRef"`
	PrincipalSHA256 string      `json:"principalSha256"`
	Policy          Policy      `json:"policy"`
	Items           []Candidate `json:"items"`
}

type ProbeFacts struct {
	Schema       string     `json:"schema"`
	MediaRef     string     `json:"mediaRef"`
	Kind         media.Kind `json:"kind"`
	MIMEType     string     `json:"mimeType"`
	SHA256       string     `json:"sha256"`
	SizeBytes    int64      `json:"sizeBytes"`
	WidthPixels  int        `json:"widthPixels"`
	HeightPixels int        `json:"heightPixels"`
	DurationMS   int64      `json:"durationMs"`
	ProbeRef     string     `json:"probeRef"`
	ProbedAt     time.Time  `json:"probedAt"`
}

type MediaCatalog interface {
	Describe(context.Context, string) (media.Descriptor, error)
	Probe(context.Context, string) (ProbeFacts, error)
}

const OperationIntake = "dataset_intake"

type PreflightAuthorizationDemand struct {
	AuthorityRef          string
	PrincipalSHA256       string
	TenantID              string
	SiteID                string
	DatasetID             string
	Revision              uint64
	Operation             string
	IntakeSHA256          string
	PolicySHA256          string
	RootMediaRefs         []string
	LineageDiscoveryLimit int
	ItemCount             int
	AnnotationCount       int
	At                    time.Time
}

type DescriptorAuthorizationFact struct {
	MediaRef         string
	SourceRef        string
	DescriptorSHA256 string
	ParentMediaRef   string
}

type FinalAuthorizationDemand struct {
	Preflight   PreflightAuthorizationDemand
	SourceRefs  []string
	Descriptors []DescriptorAuthorizationFact
}

type Authorizer interface {
	PreflightDataset(context.Context, PreflightAuthorizationDemand) error
	AuthorizeDataset(context.Context, FinalAuthorizationDemand) error
}

type AuthorizationGrant struct {
	Schema                string
	AuthorityRef          string
	PrincipalSHA256       string
	TenantID              string
	SiteID                string
	DatasetID             string
	Revision              uint64
	Operation             string
	IntakeSHA256          string
	PolicySHA256          string
	SourceRefs            []string
	RootMediaRefs         []string
	Descriptors           []DescriptorAuthorizationFact
	LineageDiscoveryLimit int
	ItemCount             int
	AnnotationCount       int
	IssuedAt              time.Time
	ExpiresAt             time.Time
}

type SemanticsDemand struct {
	CriterionID      string
	CriterionVersion uint64
	ResultKind       LabelKind
	ResultSchemaRef  string
	SceneTaxonomy    []string
	Label            Label
}

type SemanticsRegistry interface {
	VerifySemantics(context.Context, SemanticsDemand) error
}

type Pseudonymizer interface {
	Pseudonym(domain string, values ...string) (string, error)
}

type GovernanceState string

const (
	GovernanceActive          GovernanceState = "active"
	GovernancePurgeSubmitting GovernanceState = "purge_submitting"
	GovernanceTombstoned      GovernanceState = "tombstoned"
)

// Dataset is the safe admitted projection. Raw tenant/site/source/reviewer,
// descriptor integrity, authority material, and leakage identities are absent.
type Dataset struct {
	Schema          string           `json:"schema"`
	DatasetID       string           `json:"datasetId"`
	Revision        uint64           `json:"revision"`
	PurposeRef      string           `json:"purposeRef"`
	TenantStratum   string           `json:"tenantStratum"`
	SiteStratum     string           `json:"siteStratum"`
	PolicySHA256    string           `json:"policySha256"`
	RetainUntil     time.Time        `json:"retainUntil"`
	GovernanceState GovernanceState  `json:"governanceState"`
	CreatedAt       time.Time        `json:"createdAt"`
	Items           []Item           `json:"items"`
	Strata          []StratumSummary `json:"strata"`
	CountsBySplit   SplitCounts      `json:"countsBySplit"`
	AnnotationCount int              `json:"annotationCount"`
	ApprovalMinimum int              `json:"approvalMinimum"`

	claims          []identityClaim
	sourceIntervals []sourceIntervalClaim
	reviewBindings  []annotationReviewBinding
	admissionSHA256 string
}

// MarshalJSON emits only the business-safe projection; private leakage claims,
// source intervals, and exact review records are consumed transactionally by
// SQLiteRepository and never serialized.
func (d Dataset) MarshalJSON() ([]byte, error) { return marshalDatasetProjection(d) }

type Item struct {
	ItemID        string       `json:"itemId"`
	MediaRef      string       `json:"mediaRef"`
	Kind          media.Kind   `json:"kind"`
	Split         Split        `json:"split"`
	CapturedAt    time.Time    `json:"capturedAt"`
	SiteStratum   string       `json:"siteStratum"`
	SourceStratum string       `json:"sourceStratum"`
	GroupStratum  string       `json:"groupStratum"`
	Annotations   []Annotation `json:"annotations"`
}

type Annotation struct {
	AnnotationID     string    `json:"annotationId"`
	CriterionID      string    `json:"criterionId"`
	CriterionVersion uint64    `json:"criterionVersion"`
	SceneTaxonomy    []string  `json:"sceneTaxonomy"`
	ResultKind       LabelKind `json:"resultKind"`
	ResultSchemaRef  string    `json:"resultSchemaRef"`
	Label            Label     `json:"label"`
	AnnotationSHA256 string    `json:"annotationSha256"`
	ReviewSetSHA256  string    `json:"reviewSetSha256"`
	ApprovalCount    int       `json:"approvalCount"`
	LastReviewedAt   time.Time `json:"lastReviewedAt"`
}

type StratumSummary struct {
	SiteStratum         string    `json:"siteStratum"`
	SourceStratum       string    `json:"sourceStratum"`
	Split               Split     `json:"split"`
	CriterionID         string    `json:"criterionId"`
	CriterionVersion    uint64    `json:"criterionVersion"`
	ResultKind          LabelKind `json:"resultKind"`
	ResultSchemaRef     string    `json:"resultSchemaRef"`
	SceneTaxonomySHA256 string    `json:"sceneTaxonomySha256"`
	Count               int       `json:"count"`
}

type SplitCounts struct {
	Train      int `json:"train"`
	Validation int `json:"validation"`
	Test       int `json:"test"`
}

type ReviewSubject struct {
	Schema               string              `json:"schema"`
	DatasetID            string              `json:"datasetId"`
	Revision             uint64              `json:"revision"`
	ItemID               string              `json:"itemId"`
	MediaRef             string              `json:"mediaRef"`
	DescriptorSHA256     string              `json:"descriptorSha256"`
	IntakeSemanticSHA256 string              `json:"intakeSemanticSha256"`
	Annotation           AnnotationCandidate `json:"annotation"`
}

type Repository interface {
	Create(context.Context, Dataset) error
}

const OperationPurge = "dataset_purge"

type PurgeRequest struct {
	Schema          string `json:"schema"`
	OperationID     string `json:"operationId"`
	AuthorityRef    string `json:"authorityRef"`
	PrincipalSHA256 string `json:"principalSha256"`
	TenantStratum   string `json:"tenantStratum"`
	SiteStratum     string `json:"siteStratum"`
	DatasetID       string `json:"datasetId"`
	Revision        uint64 `json:"revision"`
}

type GovernancePreflightDemand struct {
	AuthorityRef    string    `json:"authorityRef"`
	PrincipalSHA256 string    `json:"principalSha256"`
	OperationID     string    `json:"operationId"`
	Operation       string    `json:"operation"`
	TenantStratum   string    `json:"tenantStratum"`
	SiteStratum     string    `json:"siteStratum"`
	DatasetID       string    `json:"datasetId"`
	Revision        uint64    `json:"revision"`
	At              time.Time `json:"at"`
}

type GovernanceDemand struct {
	Preflight     GovernancePreflightDemand `json:"preflight"`
	ContentSHA256 string                    `json:"contentSha256"`
	RetainUntil   time.Time                 `json:"retainUntil"`
}

type GovernanceAuthorizer interface {
	PreflightGovernance(context.Context, GovernancePreflightDemand) error
	AuthorizeGovernance(context.Context, GovernanceDemand) error
}

type GovernanceAuthorizationGrant struct {
	Schema          string
	AuthorityRef    string
	PrincipalSHA256 string
	OperationID     string
	Operation       string
	TenantStratum   string
	SiteStratum     string
	DatasetID       string
	Revision        uint64
	ContentSHA256   string
	RetainUntil     time.Time
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

type GovernanceRecord struct {
	TenantStratum string          `json:"tenantStratum"`
	SiteStratum   string          `json:"siteStratum"`
	DatasetID     string          `json:"datasetId"`
	Revision      uint64          `json:"revision"`
	ContentSHA256 string          `json:"contentSha256"`
	RetainUntil   time.Time       `json:"retainUntil"`
	State         GovernanceState `json:"state"`
	TombstonedAt  *time.Time      `json:"tombstonedAt,omitempty"`
}

type PurgeReceipt struct {
	OperationID   string `json:"operationId"`
	TenantStratum string `json:"tenantStratum"`
	SiteStratum   string `json:"siteStratum"`
	DatasetID     string `json:"datasetId"`
	Revision      uint64 `json:"revision"`
	ContentSHA256 string `json:"contentSha256"`
}

func (PurgeRequest) MarshalJSON() ([]byte, error) { return nil, ErrProtectedGovernanceProjection }
func (PurgeRequest) MarshalText() ([]byte, error) { return nil, ErrProtectedGovernanceProjection }
func (PurgeRequest) String() string               { return "[inspection-dataset-purge-request]" }
func (PurgeRequest) GoString() string             { return "dataset.PurgeRequest([redacted])" }
func (PurgeRequest) LogValue() slog.Value {
	return slog.StringValue("[inspection-dataset-purge-request]")
}
