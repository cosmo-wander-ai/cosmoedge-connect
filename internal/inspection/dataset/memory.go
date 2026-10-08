package dataset

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

type MemoryMediaCatalog struct {
	mu      sync.RWMutex
	entries map[string]memoryMediaEntry
}

type memoryMediaEntry struct {
	descriptor media.Descriptor
	probe      ProbeFacts
}

func NewMemoryMediaCatalog() *MemoryMediaCatalog {
	return &MemoryMediaCatalog{entries: make(map[string]memoryMediaEntry)}
}

func (m *MemoryMediaCatalog) Put(descriptor media.Descriptor, probe ProbeFacts) error {
	if m == nil || descriptor.Validate() != nil || validateProbe(probe, descriptor, probe.ProbedAt.UTC()) != nil {
		return ErrProbe
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[descriptor.MediaRef]; exists {
		return ErrConflict
	}
	m.entries[descriptor.MediaRef] = memoryMediaEntry{cloneDescriptor(descriptor), probe}
	return nil
}

func (m *MemoryMediaCatalog) Describe(ctx context.Context, mediaRef string) (media.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return media.Descriptor{}, err
	}
	if m == nil || !validMediaRef(mediaRef) {
		return media.Descriptor{}, ErrNotFound
	}
	m.mu.RLock()
	entry, exists := m.entries[mediaRef]
	m.mu.RUnlock()
	if !exists {
		return media.Descriptor{}, ErrNotFound
	}
	return cloneDescriptor(entry.descriptor), nil
}

func (m *MemoryMediaCatalog) Probe(ctx context.Context, mediaRef string) (ProbeFacts, error) {
	if err := ctx.Err(); err != nil {
		return ProbeFacts{}, err
	}
	if m == nil || !validMediaRef(mediaRef) {
		return ProbeFacts{}, ErrNotFound
	}
	m.mu.RLock()
	entry, exists := m.entries[mediaRef]
	m.mu.RUnlock()
	if !exists {
		return ProbeFacts{}, ErrNotFound
	}
	return entry.probe, nil
}

type MemoryAuthorizer struct {
	mu     sync.RWMutex
	grants map[string]AuthorizationGrant
}

func NewMemoryAuthorizer() *MemoryAuthorizer {
	return &MemoryAuthorizer{grants: make(map[string]AuthorizationGrant)}
}

func (m *MemoryAuthorizer) PutGrant(grant AuthorizationGrant) error {
	if m == nil || validateAuthorizationGrant(grant) != nil {
		return ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.grants[grant.AuthorityRef]; exists {
		return ErrConflict
	}
	grant.SourceRefs = append([]string(nil), grant.SourceRefs...)
	grant.RootMediaRefs = append([]string(nil), grant.RootMediaRefs...)
	grant.Descriptors = append([]DescriptorAuthorizationFact(nil), grant.Descriptors...)
	m.grants[grant.AuthorityRef] = grant
	return nil
}

func (m *MemoryAuthorizer) PreflightDataset(ctx context.Context, demand PreflightAuthorizationDemand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil {
		return ErrUnauthorized
	}
	m.mu.RLock()
	grant, exists := m.grants[demand.AuthorityRef]
	m.mu.RUnlock()
	if !exists || !authorizationGrantMatchesPreflight(grant, demand) {
		return ErrUnauthorized
	}
	return nil
}

func authorizationGrantMatchesPreflight(grant AuthorizationGrant, demand PreflightAuthorizationDemand) bool {
	return canonicalTime(demand.At) && !demand.At.Before(grant.IssuedAt) && demand.At.Before(grant.ExpiresAt) && grant.Schema == AuthorizationSchema &&
		grant.PrincipalSHA256 == demand.PrincipalSHA256 && grant.TenantID == demand.TenantID && grant.SiteID == demand.SiteID &&
		grant.DatasetID == demand.DatasetID && grant.Revision == demand.Revision && grant.Operation == demand.Operation && grant.IntakeSHA256 == demand.IntakeSHA256 &&
		grant.PolicySHA256 == demand.PolicySHA256 && grant.LineageDiscoveryLimit == demand.LineageDiscoveryLimit &&
		grant.ItemCount == demand.ItemCount && grant.AnnotationCount == demand.AnnotationCount && equalStrings(grant.RootMediaRefs, demand.RootMediaRefs)
}

func (m *MemoryAuthorizer) AuthorizeDataset(ctx context.Context, demand FinalAuthorizationDemand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.RLock()
	grant, exists := m.grants[demand.Preflight.AuthorityRef]
	m.mu.RUnlock()
	if !exists || !authorizationGrantMatchesPreflight(grant, demand.Preflight) || !equalStrings(grant.SourceRefs, demand.SourceRefs) || !equalDescriptorAuthorizationFacts(grant.Descriptors, demand.Descriptors) {
		return ErrUnauthorized
	}
	return nil
}

func validateAuthorizationGrant(grant AuthorizationGrant) error {
	if grant.Schema != AuthorizationSchema || !validOpaqueRef(grant.AuthorityRef) || !validDigest(grant.PrincipalSHA256) || !validOpaqueRef(grant.TenantID) ||
		!validOpaqueRef(grant.SiteID) || !validNamespacedRef("dataset-", grant.DatasetID) || grant.Revision < 1 || grant.Operation != OperationIntake || !validDigest(grant.IntakeSHA256) || !validDigest(grant.PolicySHA256) ||
		grant.ItemCount < 1 || grant.ItemCount > MaximumItems || grant.AnnotationCount < grant.ItemCount || grant.AnnotationCount > MaximumAnnotations ||
		!canonicalTime(grant.IssuedAt) || !canonicalTime(grant.ExpiresAt) || !grant.ExpiresAt.After(grant.IssuedAt) || len(grant.SourceRefs) == 0 ||
		!strictStrings(grant.SourceRefs) || len(grant.RootMediaRefs) != grant.ItemCount || !strictStrings(grant.RootMediaRefs) ||
		grant.LineageDiscoveryLimit != maximumLineageDepth || len(grant.Descriptors) < grant.ItemCount || len(grant.Descriptors) > grant.ItemCount*maximumLineageDepth {
		return ErrUnauthorized
	}
	for _, source := range grant.SourceRefs {
		if !validOpaqueRef(source) {
			return ErrUnauthorized
		}
	}
	for _, ref := range grant.RootMediaRefs {
		if !validMediaRef(ref) {
			return ErrUnauthorized
		}
	}
	for index, fact := range grant.Descriptors {
		if !validMediaRef(fact.MediaRef) || !validOpaqueRef(fact.SourceRef) || !validDigest(fact.DescriptorSHA256) ||
			(fact.ParentMediaRef != "" && !validMediaRef(fact.ParentMediaRef)) ||
			(index > 0 && grant.Descriptors[index-1].MediaRef >= fact.MediaRef) {
			return ErrUnauthorized
		}
	}
	return nil
}

func equalDescriptorAuthorizationFacts(left, right []DescriptorAuthorizationFact) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// MemoryReviewRepository and MemoryReviewVerifier model separate trusted
// boundaries: storing a well-formed record does not make it trusted.
type MemoryReviewRepository struct {
	mu      sync.RWMutex
	records map[string]map[string]ReviewRecord
}

func NewMemoryReviewRepository() *MemoryReviewRepository {
	return &MemoryReviewRepository{records: make(map[string]map[string]ReviewRecord)}
}
func (m *MemoryReviewRepository) Put(record ReviewRecord) error {
	if m == nil || validateReviewRecord(record) != nil {
		return ErrReviewIncomplete
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	byID := m.records[record.AnnotationSHA256]
	if byID == nil {
		byID = make(map[string]ReviewRecord)
		m.records[record.AnnotationSHA256] = byID
	}
	if _, exists := byID[record.ReviewID]; exists {
		return ErrConflict
	}
	byID[record.ReviewID] = record
	return nil
}
func (m *MemoryReviewRepository) ListReviews(ctx context.Context, query ReviewQuery) ([]ReviewRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m == nil || !validDigest(query.AnnotationSHA256) || !validOpaqueRef(query.PolicyRef) || !canonicalTime(query.NotAfter) {
		return nil, ErrReviewUnavailable
	}
	m.mu.RLock()
	source := m.records[query.AnnotationSHA256]
	result := make([]ReviewRecord, 0, len(source))
	for _, record := range source {
		if record.PolicyRef == query.PolicyRef && !record.ReviewedAt.After(query.NotAfter) {
			result = append(result, record)
		}
	}
	m.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].ReviewID < result[j].ReviewID })
	return result, nil
}

type MemoryReviewVerifier struct {
	mu      sync.RWMutex
	trusted map[string]ReviewRecord
}

func NewMemoryReviewVerifier() *MemoryReviewVerifier {
	return &MemoryReviewVerifier{trusted: make(map[string]ReviewRecord)}
}
func (m *MemoryReviewVerifier) Trust(record ReviewRecord) error {
	if m == nil || validateReviewRecord(record) != nil {
		return ErrReviewIncomplete
	}
	m.mu.Lock()
	m.trusted[record.RecordSHA256] = record
	m.mu.Unlock()
	return nil
}
func (m *MemoryReviewVerifier) VerifyReview(ctx context.Context, demand ReviewVerificationDemand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	record := demand.Record
	if m == nil || validateReviewRecord(record) != nil || record.ReviewerRole != ReviewerRoleDataset || record.ReviewerSHA256 == demand.IntakePrincipalSHA256 {
		return ErrReviewIncomplete
	}
	m.mu.RLock()
	trustedRecord, trusted := m.trusted[record.RecordSHA256]
	m.mu.RUnlock()
	if !trusted || trustedRecord != record {
		return ErrReviewIncomplete
	}
	return nil
}

// MemorySemanticsRegistry is an explicit trusted allow-list. Intake values do
// not extend it; callers must register the complete semantic tuple out of band.
type MemorySemanticsRegistry struct {
	mu      sync.RWMutex
	allowed map[string]map[string]struct{}
}

func NewMemorySemanticsRegistry() *MemorySemanticsRegistry {
	return &MemorySemanticsRegistry{allowed: make(map[string]map[string]struct{})}
}

func (m *MemorySemanticsRegistry) Put(demand SemanticsDemand) error {
	if m == nil || validateSemanticsDemand(demand) != nil {
		return ErrUnsupportedSemantics
	}
	tupleDigest, labelDigest, err := semanticsDigests(demand)
	if err != nil {
		return ErrUnsupportedSemantics
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	labels := m.allowed[tupleDigest]
	if labels == nil {
		labels = make(map[string]struct{})
		m.allowed[tupleDigest] = labels
	}
	if _, exists := labels[labelDigest]; exists {
		return ErrConflict
	}
	labels[labelDigest] = struct{}{}
	return nil
}

func (m *MemorySemanticsRegistry) VerifySemantics(ctx context.Context, demand SemanticsDemand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil || validateSemanticsDemand(demand) != nil {
		return ErrUnsupportedSemantics
	}
	tupleDigest, labelDigest, err := semanticsDigests(demand)
	if err != nil {
		return ErrUnsupportedSemantics
	}
	m.mu.RLock()
	labels := m.allowed[tupleDigest]
	_, exists := labels[labelDigest]
	m.mu.RUnlock()
	if !exists {
		return ErrUnsupportedSemantics
	}
	return nil
}

func semanticsDigests(demand SemanticsDemand) (string, string, error) {
	tupleDigest, err := sha256JSON(struct {
		CriterionID      string    `json:"criterionId"`
		CriterionVersion uint64    `json:"criterionVersion"`
		ResultKind       LabelKind `json:"resultKind"`
		ResultSchemaRef  string    `json:"resultSchemaRef"`
		SceneTaxonomy    []string  `json:"sceneTaxonomy"`
	}{demand.CriterionID, demand.CriterionVersion, demand.ResultKind, demand.ResultSchemaRef, demand.SceneTaxonomy})
	if err != nil {
		return "", "", err
	}
	labelDigest, err := LabelSHA256(demand.Label)
	return tupleDigest, labelDigest, err
}

type MemoryGovernanceAuthorizer struct {
	mu     sync.RWMutex
	grants map[string]GovernanceAuthorizationGrant
}

func NewMemoryGovernanceAuthorizer() *MemoryGovernanceAuthorizer {
	return &MemoryGovernanceAuthorizer{grants: make(map[string]GovernanceAuthorizationGrant)}
}
func (m *MemoryGovernanceAuthorizer) PutGrant(grant GovernanceAuthorizationGrant) error {
	if m == nil || validateGovernanceGrant(grant) != nil {
		return ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.grants[grant.AuthorityRef]; exists {
		return ErrConflict
	}
	m.grants[grant.AuthorityRef] = grant
	return nil
}
func (m *MemoryGovernanceAuthorizer) PreflightGovernance(ctx context.Context, demand GovernancePreflightDemand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil {
		return ErrUnauthorized
	}
	m.mu.RLock()
	grant, exists := m.grants[demand.AuthorityRef]
	m.mu.RUnlock()
	if !exists || !governanceGrantMatchesPreflight(grant, demand) {
		return ErrUnauthorized
	}
	return nil
}

func governanceGrantMatchesPreflight(grant GovernanceAuthorizationGrant, demand GovernancePreflightDemand) bool {
	return canonicalTime(demand.At) && !demand.At.Before(grant.IssuedAt) && demand.At.Before(grant.ExpiresAt) &&
		grant.Schema == GovernanceAuthorizationSchema && grant.PrincipalSHA256 == demand.PrincipalSHA256 && grant.OperationID == demand.OperationID &&
		grant.Operation == demand.Operation && grant.TenantStratum == demand.TenantStratum && grant.SiteStratum == demand.SiteStratum &&
		grant.DatasetID == demand.DatasetID && grant.Revision == demand.Revision
}

func (m *MemoryGovernanceAuthorizer) AuthorizeGovernance(ctx context.Context, demand GovernanceDemand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.RLock()
	grant, exists := m.grants[demand.Preflight.AuthorityRef]
	m.mu.RUnlock()
	if !exists || !governanceGrantMatchesPreflight(grant, demand.Preflight) || grant.ContentSHA256 != demand.ContentSHA256 ||
		!canonicalTime(demand.RetainUntil) || !grant.RetainUntil.Equal(demand.RetainUntil) {
		return ErrUnauthorized
	}
	return nil
}
func validateGovernanceGrant(grant GovernanceAuthorizationGrant) error {
	if grant.Schema != GovernanceAuthorizationSchema || !validOpaqueRef(grant.AuthorityRef) || !validDigest(grant.PrincipalSHA256) || !validOpaqueRef(grant.OperationID) ||
		grant.Operation != OperationPurge || !validPseudonym("tenant", grant.TenantStratum) || !validPseudonym("site", grant.SiteStratum) ||
		!validNamespacedRef("dataset-", grant.DatasetID) || grant.Revision < 1 || !validDigest(grant.ContentSHA256) || !canonicalTime(grant.RetainUntil) || !canonicalTime(grant.IssuedAt) ||
		!canonicalTime(grant.ExpiresAt) || !grant.ExpiresAt.After(grant.IssuedAt) {
		return ErrUnauthorized
	}
	return nil
}

func sourceIntervalsCrossSplits(existing, candidate sourceIntervalClaim) bool {
	if existing.SourceSHA256 != candidate.SourceSHA256 || existing.Split == candidate.Split {
		return false
	}
	return (existing.GuardStartUnixNano <= candidate.WindowEndUnixNano && existing.GuardEndUnixNano >= candidate.WindowStartUnixNano) ||
		(existing.WindowStartUnixNano <= candidate.GuardEndUnixNano && existing.WindowEndUnixNano >= candidate.GuardStartUnixNano)
}

type Service struct {
	validator  *Validator
	repository Repository
}

func NewService(validator *Validator, repository Repository) (*Service, error) {
	if validator == nil || repository == nil {
		return nil, errors.New("dataset service dependencies are required")
	}
	return &Service{validator, repository}, nil
}
func (s *Service) Intake(ctx context.Context, request IntakeRequest) (Dataset, error) {
	if s == nil || s.validator == nil || s.repository == nil {
		return Dataset{}, ErrUnauthorized
	}
	value, err := s.validator.Validate(ctx, request)
	if err != nil {
		return Dataset{}, err
	}
	if err := s.repository.Create(ctx, value); err != nil {
		return Dataset{}, err
	}
	return cloneDataset(value, false), nil
}

func validateProjection(value Dataset) error {
	if value.Schema != Schema || !validNamespacedRef("dataset-", value.DatasetID) || value.Revision < 1 || !validNamespacedRef("purpose-", value.PurposeRef) ||
		!validPseudonym("tenant", value.TenantStratum) || !validPseudonym("site", value.SiteStratum) || !validDigest(value.PolicySHA256) ||
		!canonicalTime(value.RetainUntil) || value.GovernanceState != GovernanceActive || !canonicalTime(value.CreatedAt) || !value.RetainUntil.After(value.CreatedAt) ||
		len(value.Items) < 3 || len(value.Items) > MaximumItems || value.ApprovalMinimum < 1 || value.ApprovalMinimum > maximumReviewDecisions || value.Strata == nil {
		return ErrInvalidRequest
	}
	projectionRaw, err := marshalDatasetProjection(value)
	if err != nil || len(projectionRaw) > maximumIntakeJSONBytes {
		return ErrInvalidRequest
	}
	counts := SplitCounts{}
	annotationCount := 0
	objectCount := 0
	previousItem := ""
	mediaSeen := make(map[string]struct{}, len(value.Items))
	strataCounts := make(map[string]int)
	for _, item := range value.Items {
		if !validNamespacedRef("item-", item.ItemID) || item.ItemID <= previousItem || !validMediaRef(item.MediaRef) || !validKind(item.Kind) || !validSplit(item.Split) ||
			!canonicalTime(item.CapturedAt) || item.CapturedAt.After(value.CreatedAt) || item.SiteStratum != value.SiteStratum || !validPseudonym("source", item.SourceStratum) ||
			!validPseudonym("group", item.GroupStratum) || len(item.Annotations) == 0 || len(item.Annotations) > MaximumAnnotationsPerItem {
			return ErrInvalidRequest
		}
		if _, duplicate := mediaSeen[item.MediaRef]; duplicate {
			return ErrInvalidRequest
		}
		mediaSeen[item.MediaRef] = struct{}{}
		previousAnnotation := ""
		for _, annotation := range item.Annotations {
			candidate := AnnotationCandidate{Schema: AnnotationSchema, AnnotationID: annotation.AnnotationID, CriterionID: annotation.CriterionID,
				CriterionVersion: annotation.CriterionVersion, SceneTaxonomy: annotation.SceneTaxonomy, ResultKind: annotation.ResultKind,
				ResultSchemaRef: annotation.ResultSchemaRef, Label: annotation.Label}
			if annotation.AnnotationID <= previousAnnotation || validateAnnotation(candidate) != nil || !validDigest(annotation.AnnotationSHA256) ||
				!validDigest(annotation.ReviewSetSHA256) ||
				annotation.ApprovalCount < value.ApprovalMinimum || annotation.ApprovalCount > maximumReviewDecisions || !canonicalTime(annotation.LastReviewedAt) ||
				annotation.LastReviewedAt.Before(item.CapturedAt) || annotation.LastReviewedAt.After(value.CreatedAt) {
				return ErrInvalidRequest
			}
			previousAnnotation = annotation.AnnotationID
			annotationCount++
			if annotation.Label.Detection != nil {
				objectCount += len(annotation.Label.Detection.Objects)
			}
			sceneDigest, digestErr := sha256JSON(annotation.SceneTaxonomy)
			if digestErr != nil {
				return ErrInvalidRequest
			}
			strataKey := stratumKey(value.SiteStratum, item.SourceStratum, item.Split, annotation.CriterionID, annotation.CriterionVersion, annotation.ResultKind, annotation.ResultSchemaRef, sceneDigest)
			strataCounts[strataKey]++
		}
		previousItem = item.ItemID
		switch item.Split {
		case SplitTrain:
			counts.Train++
		case SplitValidation:
			counts.Validation++
		case SplitTest:
			counts.Test++
		}
	}
	if counts != value.CountsBySplit || counts.Train == 0 || counts.Validation == 0 || counts.Test == 0 || annotationCount != value.AnnotationCount ||
		annotationCount > MaximumAnnotations || objectCount > MaximumObjectsPerDataset || len(strataCounts) != len(value.Strata) {
		return ErrInvalidRequest
	}
	previousStratum := ""
	for _, stratum := range value.Strata {
		key := stratumKey(stratum.SiteStratum, stratum.SourceStratum, stratum.Split, stratum.CriterionID, stratum.CriterionVersion, stratum.ResultKind, stratum.ResultSchemaRef, stratum.SceneTaxonomySHA256)
		if key <= previousStratum || stratum.SiteStratum != value.SiteStratum || !validPseudonym("source", stratum.SourceStratum) || !validSplit(stratum.Split) ||
			!validNamespacedRef("criterion-", stratum.CriterionID) || stratum.CriterionVersion < 1 || !validNamespacedRef("result-schema-", stratum.ResultSchemaRef) ||
			!validDigest(stratum.SceneTaxonomySHA256) || stratum.Count < 1 || strataCounts[key] != stratum.Count {
			return ErrInvalidRequest
		}
		delete(strataCounts, key)
		previousStratum = key
	}
	if len(strataCounts) != 0 {
		return ErrInvalidRequest
	}
	return nil
}

func validateAdmission(value Dataset) error {
	if validateProjection(value) != nil || len(value.claims) == 0 || len(value.sourceIntervals) != len(value.Items) ||
		len(value.claims) > MaximumClaimsPerDataset || len(value.sourceIntervals) > MaximumItems ||
		len(value.reviewBindings) != value.AnnotationCount || !validDigest(value.admissionSHA256) {
		return ErrInvalidRequest
	}
	reviewsRaw, err := json.Marshal(value.reviewBindings)
	if err != nil || len(reviewsRaw) > maximumIntakeJSONBytes {
		return ErrInvalidRequest
	}
	previous := ""
	splits := make(map[string]Split)
	for _, claim := range value.claims {
		if !validIdentityKind(claim.Kind) || !validDigest(claim.SHA256) || !validSplit(claim.Split) {
			return ErrInvalidRequest
		}
		key := claim.Kind + "\x00" + claim.SHA256
		if key <= previous {
			return ErrInvalidRequest
		}
		previous = key
		if existing, ok := splits[key]; ok && existing != claim.Split {
			return ErrLeakage
		}
		splits[key] = claim.Split
	}
	for index, interval := range value.sourceIntervals {
		if validateSourceIntervalClaim(interval) != nil {
			return ErrInvalidRequest
		}
		if index > 0 {
			previous := value.sourceIntervals[index-1]
			if interval.SourceSHA256 < previous.SourceSHA256 ||
				(interval.SourceSHA256 == previous.SourceSHA256 && interval.WindowStartUnixNano < previous.WindowStartUnixNano) ||
				(interval.SourceSHA256 == previous.SourceSHA256 && interval.WindowStartUnixNano == previous.WindowStartUnixNano && interval.IntervalSHA256 <= previous.IntervalSHA256) {
				return ErrInvalidRequest
			}
		}
	}
	previousBinding := ""
	reviewCount := 0
	for _, binding := range value.reviewBindings {
		reviewCount += len(binding.Reviews)
		if reviewCount > maximumStoredLedgerRows {
			return ErrCapacity
		}
		key := binding.ItemID + "\x00" + binding.AnnotationID
		if key <= previousBinding || !validNamespacedRef("item-", binding.ItemID) || !validNamespacedRef("annotation-", binding.AnnotationID) ||
			!validDigest(binding.AnnotationSHA256) || !validDigest(binding.ReviewSetSHA256) || len(binding.Reviews) == 0 || len(binding.Reviews) > maximumReviewDecisions {
			return ErrInvalidRequest
		}
		seenReviewers := make(map[string]struct{}, len(binding.Reviews))
		var latest time.Time
		var reviewerRole string
		for index, review := range binding.Reviews {
			if validateReviewRecord(review) != nil || review.AnnotationSHA256 != binding.AnnotationSHA256 ||
				review.Decision != ReviewApproved || (index > 0 && binding.Reviews[index-1].ReviewID >= review.ReviewID) {
				return ErrInvalidRequest
			}
			if _, duplicate := seenReviewers[review.ReviewerSHA256]; duplicate {
				return ErrInvalidRequest
			}
			seenReviewers[review.ReviewerSHA256] = struct{}{}
			if reviewerRole == "" {
				reviewerRole = review.ReviewerRole
			} else if reviewerRole != review.ReviewerRole {
				return ErrInvalidRequest
			}
			if review.ReviewedAt.After(latest) {
				latest = review.ReviewedAt
			}
		}
		reviewSetDigest, err := sha256JSON(binding.Reviews)
		if err != nil || reviewSetDigest != binding.ReviewSetSHA256 {
			return ErrInvalidRequest
		}
		annotation := findAnnotation(value, binding.ItemID, binding.AnnotationID)
		if annotation == nil || annotation.AnnotationSHA256 != binding.AnnotationSHA256 || annotation.ReviewSetSHA256 != binding.ReviewSetSHA256 ||
			annotation.ApprovalCount != len(binding.Reviews) || annotation.ApprovalCount < value.ApprovalMinimum || !annotation.LastReviewedAt.Equal(latest) {
			return ErrInvalidRequest
		}
		previousBinding = key
	}
	digest, err := admissionDigest(value)
	if err != nil || digest != value.admissionSHA256 {
		return ErrInvalidRequest
	}
	return nil
}

func admissionDigest(value Dataset) (string, error) {
	projectionDigest, err := sha256JSON(datasetProjection(value))
	if err != nil {
		return "", err
	}
	return sha256JSON(struct {
		ProjectionSHA256 string                    `json:"projectionSha256"`
		Claims           []identityClaim           `json:"claims"`
		SourceIntervals  []sourceIntervalClaim     `json:"sourceIntervals"`
		ReviewBindings   []annotationReviewBinding `json:"reviewBindings"`
	}{projectionDigest, value.claims, value.sourceIntervals, value.reviewBindings})
}

func findAnnotation(value Dataset, itemID, annotationID string) *Annotation {
	for itemIndex := range value.Items {
		if value.Items[itemIndex].ItemID != itemID {
			continue
		}
		for annotationIndex := range value.Items[itemIndex].Annotations {
			if value.Items[itemIndex].Annotations[annotationIndex].AnnotationID == annotationID {
				return &value.Items[itemIndex].Annotations[annotationIndex]
			}
		}
	}
	return nil
}

func validateSourceIntervalClaim(value sourceIntervalClaim) error {
	startNanos, startOK := exactUnixNano(value.WindowStart)
	endNanos, endOK := exactUnixNano(value.WindowEnd)
	if !validDigest(value.SourceSHA256) || !validDigest(value.IntervalSHA256) || !startOK || !endOK || endNanos < startNanos ||
		value.WindowStartUnixNano != startNanos || value.WindowEndUnixNano != endNanos || !validSplit(value.Split) ||
		value.AdjacencySeconds < 0 || value.AdjacencySeconds > maximumAdjacentWindow {
		return ErrInvalidRequest
	}
	adjacency := time.Duration(value.AdjacencySeconds) * time.Second
	guardStart, guardStartOK := exactUnixNano(value.WindowStart.Add(-adjacency))
	guardEnd, guardEndOK := exactUnixNano(value.WindowEnd.Add(adjacency))
	if !guardStartOK || !guardEndOK || value.GuardStartUnixNano != guardStart || value.GuardEndUnixNano != guardEnd {
		return ErrInvalidRequest
	}
	expected, err := sha256JSON(struct {
		SourceSHA256     string    `json:"sourceSha256"`
		WindowStart      time.Time `json:"windowStart"`
		WindowEnd        time.Time `json:"windowEnd"`
		AdjacencySeconds int       `json:"adjacencySeconds"`
	}{value.SourceSHA256, value.WindowStart, value.WindowEnd, value.AdjacencySeconds})
	if err != nil || expected != value.IntervalSHA256 {
		return ErrInvalidRequest
	}
	return nil
}
func validIdentityKind(value string) bool {
	switch value {
	case identityContent, identityMedia, identityLineage, identityGroup, identitySourceTime:
		return true
	default:
		return false
	}
}
func stratumKey(site, source string, split Split, criterion string, version uint64, kind LabelKind, resultSchemaRef, sceneTaxonomySHA256 string) string {
	return site + "\x00" + source + "\x00" + string(split) + "\x00" + criterion + "\x00" + fmtVersion(version) + "\x00" + string(kind) + "\x00" + resultSchemaRef + "\x00" + sceneTaxonomySHA256
}
func fmtVersion(value uint64) string {
	result := strconv.FormatUint(value, 10)
	return stringsRepeat("0", 20-len(result)) + result
}
func stringsRepeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}

func datasetKey(tenantStratum, siteStratum, datasetID string, revision uint64) string {
	return tenantStratum + "\x00" + siteStratum + "\x00" + datasetID + "\x00" + strconv.FormatUint(revision, 10)
}
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneDescriptor(value media.Descriptor) media.Descriptor {
	value.Governance.Audience = append([]string(nil), value.Governance.Audience...)
	if value.FrameMembers != nil {
		value.FrameMembers = append(make([]media.FrameMember, 0, len(value.FrameMembers)), value.FrameMembers...)
	}
	if value.Temporal.WindowStart != nil {
		copied := *value.Temporal.WindowStart
		value.Temporal.WindowStart = &copied
	}
	if value.Temporal.WindowEnd != nil {
		copied := *value.Temporal.WindowEnd
		value.Temporal.WindowEnd = &copied
	}
	if value.DeletedAt != nil {
		copied := *value.DeletedAt
		value.DeletedAt = &copied
	}
	return value
}

func cloneLabel(value Label) Label {
	result := value
	if value.Classification != nil {
		copied := *value.Classification
		result.Classification = &copied
	}
	if value.Enum != nil {
		copied := *value.Enum
		result.Enum = &copied
	}
	if value.Structured != nil {
		copied := *value.Structured
		copied.Fields = make([]StructuredField, len(value.Structured.Fields))
		for index, field := range value.Structured.Fields {
			copied.Fields[index] = cloneStructuredField(field)
		}
		result.Structured = &copied
	}
	if value.Count != nil {
		copied := *value.Count
		result.Count = &copied
	}
	if value.Metric != nil {
		copied := *value.Metric
		result.Metric = &copied
	}
	if value.Detection != nil {
		copied := *value.Detection
		copied.Objects = append([]DetectionObject(nil), value.Detection.Objects...)
		result.Detection = &copied
	}
	if value.Event != nil {
		copied := *value.Event
		result.Event = &copied
	}
	return result
}
func cloneStructuredField(value StructuredField) StructuredField {
	result := value
	if value.Value.Enum != nil {
		copied := *value.Value.Enum
		result.Value.Enum = &copied
	}
	if value.Value.Number != nil {
		copied := *value.Value.Number
		result.Value.Number = &copied
	}
	if value.Value.Integer != nil {
		copied := *value.Value.Integer
		result.Value.Integer = &copied
	}
	if value.Value.Boolean != nil {
		copied := *value.Value.Boolean
		result.Value.Boolean = &copied
	}
	return result
}
func cloneAnnotationCandidate(value AnnotationCandidate) AnnotationCandidate {
	value.SceneTaxonomy = append([]string(nil), value.SceneTaxonomy...)
	value.Label = cloneLabel(value.Label)
	return value
}
func cloneDataset(value Dataset, preserveAdmission bool) Dataset {
	result := value
	result.Items = make([]Item, len(value.Items))
	for index, item := range value.Items {
		result.Items[index] = item
		result.Items[index].Annotations = make([]Annotation, len(item.Annotations))
		for annotationIndex, annotation := range item.Annotations {
			result.Items[index].Annotations[annotationIndex] = annotation
			result.Items[index].Annotations[annotationIndex].SceneTaxonomy = append([]string(nil), annotation.SceneTaxonomy...)
			result.Items[index].Annotations[annotationIndex].Label = cloneLabel(annotation.Label)
		}
	}
	result.Strata = append([]StratumSummary(nil), value.Strata...)
	if preserveAdmission {
		result.claims = append([]identityClaim(nil), value.claims...)
		result.sourceIntervals = append([]sourceIntervalClaim(nil), value.sourceIntervals...)
		result.reviewBindings = cloneReviewBindings(value.reviewBindings)
	} else {
		result.claims = nil
		result.sourceIntervals = nil
		result.reviewBindings = nil
		result.admissionSHA256 = ""
	}
	return result
}

func cloneReviewBindings(values []annotationReviewBinding) []annotationReviewBinding {
	result := make([]annotationReviewBinding, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Reviews = append([]ReviewRecord(nil), value.Reviews...)
	}
	return result
}
