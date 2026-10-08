package dataset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

const (
	identityContent    = "content"
	identityMedia      = "media"
	identityLineage    = "lineage"
	identityGroup      = "group"
	identitySourceTime = "source_time"
)

type identityClaim struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Split  Split  `json:"split"`
}

type sourceIntervalClaim struct {
	SourceSHA256        string    `json:"sourceSha256"`
	IntervalSHA256      string    `json:"intervalSha256"`
	WindowStart         time.Time `json:"windowStart"`
	WindowEnd           time.Time `json:"windowEnd"`
	WindowStartUnixNano int64     `json:"windowStartUnixNano"`
	WindowEndUnixNano   int64     `json:"windowEndUnixNano"`
	GuardStartUnixNano  int64     `json:"guardStartUnixNano"`
	GuardEndUnixNano    int64     `json:"guardEndUnixNano"`
	Split               Split     `json:"split"`
	AdjacencySeconds    int       `json:"adjacencySeconds"`
}

type annotationReviewBinding struct {
	ItemID           string         `json:"itemId"`
	AnnotationID     string         `json:"annotationId"`
	AnnotationSHA256 string         `json:"annotationSha256"`
	ReviewSetSHA256  string         `json:"reviewSetSha256"`
	Reviews          []ReviewRecord `json:"reviews"`
}

type Validator struct {
	media          MediaCatalog
	authorizer     Authorizer
	pseudonymizer  Pseudonymizer
	reviews        ReviewRepository
	reviewVerifier ReviewVerifier
	semantics      SemanticsRegistry
	now            func() time.Time
}

func NewValidator(catalog MediaCatalog, authorizer Authorizer, pseudonymizer Pseudonymizer, reviews ReviewRepository, verifier ReviewVerifier, semantics SemanticsRegistry, now func() time.Time) (*Validator, error) {
	if catalog == nil || authorizer == nil || pseudonymizer == nil || reviews == nil || verifier == nil || semantics == nil || now == nil {
		return nil, errors.New("dataset validator dependencies are required")
	}
	return &Validator{media: catalog, authorizer: authorizer, pseudonymizer: pseudonymizer, reviews: reviews, reviewVerifier: verifier, semantics: semantics, now: now}, nil
}

type admittedAnnotation struct {
	candidate       AnnotationCandidate
	digest          string
	approvals       int
	approvalAt      time.Time
	reviewSetSHA256 string
	reviews         []ReviewRecord
}

type admittedItem struct {
	candidate   Candidate
	descriptor  media.Descriptor
	capturedAt  time.Time
	windowStart time.Time
	windowEnd   time.Time
	annotations []admittedAnnotation
	claims      []identityClaim
	interval    sourceIntervalClaim
}

// Validate performs all media, review, authorization, and intra-request checks.
// Its Dataset carries unexported identity claims, source intervals, and the
// exact trusted review set that SQLiteRepository commits atomically.
func (v *Validator) Validate(ctx context.Context, request IntakeRequest) (Dataset, error) {
	if v == nil || v.media == nil || v.authorizer == nil || v.pseudonymizer == nil || v.reviews == nil || v.reviewVerifier == nil || v.semantics == nil || v.now == nil {
		return Dataset{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return Dataset{}, err
	}
	now := v.now().UTC()
	if now.IsZero() {
		return Dataset{}, ErrInvalidRequest
	}
	if err := validateRequestShape(request, now); err != nil {
		return Dataset{}, err
	}
	policyDigest, err := PolicySHA256(request.Policy)
	if err != nil {
		return Dataset{}, ErrInvalidRequest
	}
	intakeDigest, err := IntakeSHA256(request)
	if err != nil {
		return Dataset{}, ErrInvalidRequest
	}

	rootMediaRefs := make([]string, 0, len(request.Items))
	annotationCount := 0
	for _, candidate := range request.Items {
		rootMediaRefs = append(rootMediaRefs, candidate.MediaRef)
		annotationCount += len(candidate.Annotations)
	}
	sort.Strings(rootMediaRefs)
	preflight := PreflightAuthorizationDemand{AuthorityRef: request.AuthorityRef, PrincipalSHA256: request.PrincipalSHA256,
		TenantID: request.TenantID, SiteID: request.SiteID, DatasetID: request.DatasetID, Revision: request.Revision,
		Operation: OperationIntake, IntakeSHA256: intakeDigest, PolicySHA256: policyDigest, RootMediaRefs: rootMediaRefs,
		LineageDiscoveryLimit: maximumLineageDepth, ItemCount: len(request.Items), AnnotationCount: annotationCount, At: now}
	if err := v.authorizer.PreflightDataset(ctx, preflight); err != nil {
		return Dataset{}, ErrUnauthorized
	}
	for _, candidate := range request.Items {
		for _, annotation := range candidate.Annotations {
			demand := SemanticsDemand{CriterionID: annotation.CriterionID, CriterionVersion: annotation.CriterionVersion,
				ResultKind: annotation.ResultKind, ResultSchemaRef: annotation.ResultSchemaRef, SceneTaxonomy: append([]string(nil), annotation.SceneTaxonomy...),
				Label: cloneLabel(annotation.Label)}
			if err := v.semantics.VerifySemantics(ctx, demand); err != nil {
				return Dataset{}, ErrUnsupportedSemantics
			}
		}
	}

	closure, descriptorFacts, sourceRefs, discoveryErr := v.discoverLineageClosure(ctx, request, now)
	if discoveryErr != nil {
		return Dataset{}, discoveryErr
	}
	finalDemand := FinalAuthorizationDemand{Preflight: preflight, SourceRefs: sourceRefs, Descriptors: descriptorFacts}
	if err := v.authorizer.AuthorizeDataset(ctx, finalDemand); err != nil {
		return Dataset{}, ErrUnauthorized
	}

	admitted := make([]admittedItem, 0, len(request.Items))
	claimSplits := make(map[string]Split)
	counts := SplitCounts{}
	claimCount := 0
	reviewBytes := 0
	for _, candidate := range request.Items {
		descriptor, exists := closure[candidate.MediaRef]
		if !exists {
			return Dataset{}, ErrIntegrity
		}
		probe, probeErr := v.media.Probe(ctx, candidate.MediaRef)
		if probeErr != nil || validateProbe(probe, descriptor, now) != nil {
			return Dataset{}, ErrProbe
		}

		windowStart, windowEnd := descriptorWindow(descriptor)
		annotations := make([]admittedAnnotation, 0, len(candidate.Annotations))
		for _, annotation := range candidate.Annotations {
			descriptorDigest, digestErr := DescriptorSHA256(descriptor)
			if digestErr != nil {
				return Dataset{}, digestErr
			}
			subject, subjectErr := buildReviewSubjectWithDigest(request, candidate, annotation, descriptor, descriptorDigest, intakeDigest)
			if subjectErr != nil {
				return Dataset{}, subjectErr
			}
			digest, digestErr := AnnotationSHA256(subject)
			if digestErr != nil {
				return Dataset{}, digestErr
			}
			reviewRecords, reviewedAt, reviewErr := v.resolveReviews(ctx, digest, request.Policy, request.PrincipalSHA256, descriptor, windowEnd, now)
			if reviewErr != nil {
				return Dataset{}, reviewErr
			}
			reviewSetDigest, digestErr := sha256JSON(reviewRecords)
			if digestErr != nil {
				return Dataset{}, ErrReviewIncomplete
			}
			reviewRaw, marshalErr := json.Marshal(reviewRecords)
			if marshalErr != nil {
				return Dataset{}, ErrReviewIncomplete
			}
			reviewBytes += len(reviewRaw)
			if reviewBytes > maximumIntakeJSONBytes {
				return Dataset{}, ErrCapacity
			}
			annotations = append(annotations, admittedAnnotation{candidate: annotation, digest: digest, approvals: len(reviewRecords), approvalAt: reviewedAt,
				reviewSetSHA256: reviewSetDigest, reviews: reviewRecords})
		}

		lineageKeys, lineageErr := lineageKeysFromClosure(candidate.MediaRef, closure)
		if lineageErr != nil {
			return Dataset{}, lineageErr
		}
		claims, claimErr := buildIdentityClaims(request, candidate, descriptor, lineageKeys, windowStart, windowEnd)
		if claimErr != nil {
			return Dataset{}, claimErr
		}
		if len(claims) > MaximumClaimsPerItem {
			return Dataset{}, ErrCapacity
		}
		claimCount += len(claims)
		if claimCount > MaximumClaimsPerDataset {
			return Dataset{}, ErrCapacity
		}
		interval, intervalErr := buildSourceIntervalClaim(request, candidate, descriptor, windowStart, windowEnd)
		if intervalErr != nil {
			return Dataset{}, intervalErr
		}
		for _, claim := range claims {
			key := claim.Kind + "\x00" + claim.SHA256
			if existing, ok := claimSplits[key]; ok {
				if existing != claim.Split {
					return Dataset{}, fmt.Errorf("%w: %s identity crosses splits", ErrLeakage, claim.Kind)
				}
				return Dataset{}, fmt.Errorf("%w: repeated %s identity", ErrLeakage, claim.Kind)
			}
			claimSplits[key] = claim.Split
		}

		admitted = append(admitted, admittedItem{candidate: candidate, descriptor: descriptor, capturedAt: windowStart,
			windowStart: windowStart, windowEnd: windowEnd, annotations: annotations, claims: claims, interval: interval})
		switch candidate.Split {
		case SplitTrain:
			counts.Train++
		case SplitValidation:
			counts.Validation++
		case SplitTest:
			counts.Test++
		}
	}
	if counts.Train == 0 || counts.Validation == 0 || counts.Test == 0 {
		return Dataset{}, fmt.Errorf("%w: train, validation, and test splits are all required", ErrInvalidRequest)
	}
	if err := validateTemporalIsolation(admitted, time.Duration(request.Policy.AdjacentSourceWindowSeconds)*time.Second); err != nil {
		return Dataset{}, err
	}

	return v.project(request, admitted, closure, policyDigest, counts, annotationCount, now)
}

func (v *Validator) resolveReviews(ctx context.Context, annotationDigest string, policy Policy, intakePrincipal string, descriptor media.Descriptor, capturedThrough, now time.Time) ([]ReviewRecord, time.Time, error) {
	records, err := v.reviews.ListReviews(ctx, ReviewQuery{AnnotationSHA256: annotationDigest, PolicyRef: policy.ReviewPolicyRef, NotAfter: now})
	if err != nil {
		return nil, time.Time{}, errors.Join(ErrReviewUnavailable, err)
	}
	if len(records) > maximumReviewDecisions {
		return nil, time.Time{}, ErrReviewIncomplete
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ReviewID < records[j].ReviewID })
	seenIDs := make(map[string]struct{}, len(records))
	seenReviewers := make(map[string]struct{}, len(records))
	var latest time.Time
	for _, record := range records {
		if err := validateReviewRecord(record); err != nil || record.AnnotationSHA256 != annotationDigest || record.PolicyRef != policy.ReviewPolicyRef ||
			record.ReviewerSHA256 == intakePrincipal || record.ReviewerRole != ReviewerRoleDataset ||
			record.ReviewedAt.Before(descriptor.CreatedAt.UTC()) || record.ReviewedAt.Before(capturedThrough) || record.ReviewedAt.After(now) ||
			!record.ReviewedAt.Before(descriptor.Governance.ExpiresAt.UTC()) {
			return nil, time.Time{}, ErrReviewIncomplete
		}
		if _, duplicate := seenIDs[record.ReviewID]; duplicate {
			return nil, time.Time{}, ErrReviewIncomplete
		}
		seenIDs[record.ReviewID] = struct{}{}
		if err := v.reviewVerifier.VerifyReview(ctx, ReviewVerificationDemand{Record: record, IntakePrincipalSHA256: intakePrincipal}); err != nil {
			return nil, time.Time{}, ErrReviewIncomplete
		}
		if record.Decision == ReviewRejected {
			return nil, time.Time{}, ErrReviewRejected
		}
		if _, duplicate := seenReviewers[record.ReviewerSHA256]; duplicate {
			return nil, time.Time{}, ErrReviewIncomplete
		}
		seenReviewers[record.ReviewerSHA256] = struct{}{}
		if record.ReviewedAt.After(latest) {
			latest = record.ReviewedAt
		}
	}
	if len(seenReviewers) < policy.MinimumApprovals {
		return nil, time.Time{}, ErrReviewIncomplete
	}
	return append([]ReviewRecord(nil), records...), latest.UTC(), nil
}

func validateDescriptorForIntake(descriptor media.Descriptor, candidate Candidate, request IntakeRequest, now time.Time) error {
	if err := descriptor.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if !canonicalDescriptorTimes(descriptor) || descriptor.Schema != media.Schema || descriptor.MediaRef != candidate.MediaRef {
		return ErrIntegrity
	}
	if descriptor.Binding.TenantID != request.TenantID || descriptor.Binding.SiteID != request.SiteID {
		return ErrScopeMismatch
	}
	if descriptor.Availability != media.AvailabilityAvailable || descriptor.DeletedAt != nil || !now.Before(descriptor.Governance.ExpiresAt) {
		return ErrMediaUnavailable
	}
	windowStart, windowEnd := descriptorWindow(descriptor)
	if windowStart.After(now) || windowEnd.After(now) {
		return ErrInvalidRequest
	}
	minimumExpiry := now.Add(time.Duration(request.Policy.MinimumRemainingRetentionSeconds) * time.Second)
	if descriptor.Governance.ExpiresAt.Before(minimumExpiry) || descriptor.Governance.ExpiresAt.Before(request.Policy.RetainUntil) ||
		!containsString(request.Policy.RequiredRetentionPolicyRefs, descriptor.Governance.RetentionPolicyRef) ||
		!containsString(request.Policy.AllowedPrivacyClasses, descriptor.Governance.PrivacyClass) {
		return ErrRetention
	}
	if !containsKind(request.Policy.AllowedKinds, descriptor.Kind) {
		return ErrInvalidRequest
	}
	if descriptor.Kind != candidate.ExpectedKind || descriptor.Encoding.MIMEType != candidate.ExpectedMIME || descriptor.Integrity.SHA256 != candidate.ExpectedSHA256 {
		return ErrIntegrity
	}
	return nil
}

func validateProbe(probe ProbeFacts, descriptor media.Descriptor, now time.Time) error {
	if probe.Schema != "cosmoedge.inspection.dataset.probe.v3" || probe.MediaRef != descriptor.MediaRef || probe.Kind != descriptor.Kind ||
		probe.MIMEType != descriptor.Encoding.MIMEType || probe.SHA256 != descriptor.Integrity.SHA256 || probe.SizeBytes != descriptor.Integrity.SizeBytes ||
		probe.WidthPixels != descriptor.Encoding.WidthPixels || probe.HeightPixels != descriptor.Encoding.HeightPixels || probe.DurationMS != descriptor.Temporal.DurationMillis ||
		!validDigest(probe.SHA256) || !validOpaqueRef(probe.ProbeRef) || !canonicalTime(probe.ProbedAt) || probe.ProbedAt.Before(descriptor.CreatedAt.UTC()) || probe.ProbedAt.After(now) {
		return ErrProbe
	}
	return nil
}

const ProbeSchema = "cosmoedge.inspection.dataset.probe.v3"

func descriptorWindow(descriptor media.Descriptor) (time.Time, time.Time) {
	start := descriptor.CreatedAt.UTC()
	end := start.Add(time.Duration(descriptor.Temporal.DurationMillis) * time.Millisecond)
	if descriptor.Temporal.WindowStart != nil && descriptor.Temporal.WindowEnd != nil {
		start = descriptor.Temporal.WindowStart.UTC()
		end = descriptor.Temporal.WindowEnd.UTC()
	}
	if end.Before(start) {
		end = start
	}
	return start, end
}

func (v *Validator) discoverLineageClosure(ctx context.Context, request IntakeRequest, now time.Time) (map[string]media.Descriptor, []DescriptorAuthorizationFact, []string, error) {
	closure := make(map[string]media.Descriptor, len(request.Items))
	frameMemberCount := 0
	for _, candidate := range request.Items {
		visited := make(map[string]struct{}, maximumLineageDepth)
		currentRef := candidate.MediaRef
		terminated := false
		for depth := 0; depth < maximumLineageDepth; depth++ {
			if err := ctx.Err(); err != nil {
				return nil, nil, nil, err
			}
			if _, cycle := visited[currentRef]; cycle {
				return nil, nil, nil, fmt.Errorf("%w: cyclic lineage", ErrLeakage)
			}
			visited[currentRef] = struct{}{}
			descriptor, exists := closure[currentRef]
			if !exists {
				var describeErr error
				descriptor, describeErr = v.media.Describe(ctx, currentRef)
				if describeErr != nil {
					return nil, nil, nil, fmt.Errorf("%w: bounded lineage descriptor lookup failed", ErrMediaUnavailable)
				}
				if err := validateLineageDescriptor(descriptor, currentRef, request.TenantID, request.SiteID, now); err != nil {
					return nil, nil, nil, err
				}
				frameMemberCount += len(descriptor.FrameMembers)
				if frameMemberCount > MaximumFrameMembersPerDataset {
					return nil, nil, nil, ErrInvalidRequest
				}
				closure[currentRef] = cloneDescriptor(descriptor)
				if len(closure) > maximumLineageDescriptors {
					return nil, nil, nil, ErrInvalidRequest
				}
			}
			if depth == 0 {
				if err := validateDescriptorForIntake(descriptor, candidate, request, now); err != nil {
					return nil, nil, nil, err
				}
			}
			parentRef := descriptor.Lineage.ParentMediaRef
			if parentRef == "" {
				terminated = true
				break
			}
			currentRef = parentRef
		}
		if !terminated {
			return nil, nil, nil, fmt.Errorf("%w: lineage depth exceeds the authorized bound", ErrLeakage)
		}
	}
	if len(closure) > len(request.Items)*maximumLineageDepth || len(closure) > maximumLineageDescriptors {
		return nil, nil, nil, ErrLeakage
	}
	facts := make([]DescriptorAuthorizationFact, 0, len(closure))
	sourceSet := make(map[string]struct{}, len(closure))
	for _, descriptor := range closure {
		digest, err := DescriptorSHA256(descriptor)
		if err != nil {
			return nil, nil, nil, err
		}
		facts = append(facts, DescriptorAuthorizationFact{MediaRef: descriptor.MediaRef, SourceRef: descriptor.Binding.SourceRef,
			DescriptorSHA256: digest, ParentMediaRef: descriptor.Lineage.ParentMediaRef})
		sourceSet[descriptor.Binding.SourceRef] = struct{}{}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].MediaRef < facts[j].MediaRef })
	return closure, facts, sortedKeys(sourceSet), nil
}

func validateLineageDescriptor(descriptor media.Descriptor, expectedRef, tenantID, siteID string, now time.Time) error {
	if descriptor.Validate() != nil || !canonicalDescriptorTimes(descriptor) || descriptor.Schema != media.Schema || descriptor.MediaRef != expectedRef {
		return ErrIntegrity
	}
	if descriptor.Binding.TenantID != tenantID || descriptor.Binding.SiteID != siteID {
		return ErrScopeMismatch
	}
	if descriptor.Availability != media.AvailabilityAvailable || descriptor.DeletedAt != nil || !now.Before(descriptor.Governance.ExpiresAt.UTC()) {
		return ErrMediaUnavailable
	}
	windowStart, windowEnd := descriptorWindow(descriptor)
	if windowStart.After(now) || windowEnd.After(now) {
		return ErrInvalidRequest
	}
	return nil
}

func lineageKeysFromClosure(rootRef string, closure map[string]media.Descriptor) ([]string, error) {
	keys := make(map[string]struct{})
	visited := make(map[string]struct{}, maximumLineageDepth)
	currentRef := rootRef
	for depth := 0; depth < maximumLineageDepth; depth++ {
		if _, cycle := visited[currentRef]; cycle {
			return nil, ErrLeakage
		}
		visited[currentRef] = struct{}{}
		descriptor, exists := closure[currentRef]
		if !exists {
			return nil, ErrUnauthorized
		}
		keys[descriptor.MediaRef] = struct{}{}
		for _, member := range descriptor.FrameMembers {
			keys[member.MediaRef] = struct{}{}
		}
		if descriptor.Lineage.ParentMediaRef == "" {
			return sortedKeys(keys), nil
		}
		currentRef = descriptor.Lineage.ParentMediaRef
	}
	return nil, ErrLeakage
}

type sourceTimeIdentity struct {
	TenantID    string    `json:"tenantId"`
	SiteID      string    `json:"siteId"`
	SourceRef   string    `json:"sourceRef"`
	WindowStart time.Time `json:"windowStart"`
	WindowEnd   time.Time `json:"windowEnd"`
}

func buildIdentityClaims(request IntakeRequest, candidate Candidate, descriptor media.Descriptor, lineage []string, windowStart, windowEnd time.Time) ([]identityClaim, error) {
	type rawClaim struct {
		kind  string
		value any
	}
	raw := []rawClaim{
		{identityContent, descriptor.Integrity.SHA256},
		{identityMedia, descriptor.MediaRef},
		{identityGroup, struct {
			TenantID string `json:"tenantId"`
			SiteID   string `json:"siteId"`
			GroupRef string `json:"groupRef"`
		}{request.TenantID, request.SiteID, candidate.GroupRef}},
		{identitySourceTime, sourceTimeIdentity{request.TenantID, request.SiteID, descriptor.Binding.SourceRef, windowStart.UTC(), windowEnd.UTC()}},
	}
	for _, ref := range lineage {
		raw = append(raw, rawClaim{identityLineage, ref})
	}
	claims := make([]identityClaim, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		digest, err := sha256JSON(struct {
			Kind  string `json:"kind"`
			Value any    `json:"value"`
		}{value.kind, value.value})
		if err != nil {
			return nil, ErrInvalidRequest
		}
		key := value.kind + "\x00" + digest
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		claims = append(claims, identityClaim{Kind: value.kind, SHA256: digest, Split: candidate.Split})
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].Kind != claims[j].Kind {
			return claims[i].Kind < claims[j].Kind
		}
		return claims[i].SHA256 < claims[j].SHA256
	})
	return claims, nil
}

func buildSourceIntervalClaim(request IntakeRequest, candidate Candidate, descriptor media.Descriptor, windowStart, windowEnd time.Time) (sourceIntervalClaim, error) {
	startNanos, startOK := exactUnixNano(windowStart.UTC())
	endNanos, endOK := exactUnixNano(windowEnd.UTC())
	if !startOK || !endOK || endNanos < startNanos || request.Policy.AdjacentSourceWindowSeconds < 0 || request.Policy.AdjacentSourceWindowSeconds > maximumAdjacentWindow {
		return sourceIntervalClaim{}, ErrInvalidRequest
	}
	adjacency := time.Duration(request.Policy.AdjacentSourceWindowSeconds) * time.Second
	guardStart, guardEnd := windowStart.UTC().Add(-adjacency), windowEnd.UTC().Add(adjacency)
	guardStartNanos, guardStartOK := exactUnixNano(guardStart)
	guardEndNanos, guardEndOK := exactUnixNano(guardEnd)
	if !guardStartOK || !guardEndOK {
		return sourceIntervalClaim{}, ErrInvalidRequest
	}
	sourceDigest, err := sha256JSON(struct {
		TenantID  string `json:"tenantId"`
		SiteID    string `json:"siteId"`
		SourceRef string `json:"sourceRef"`
	}{request.TenantID, request.SiteID, descriptor.Binding.SourceRef})
	if err != nil {
		return sourceIntervalClaim{}, ErrInvalidRequest
	}
	intervalDigest, err := sha256JSON(struct {
		SourceSHA256     string    `json:"sourceSha256"`
		WindowStart      time.Time `json:"windowStart"`
		WindowEnd        time.Time `json:"windowEnd"`
		AdjacencySeconds int       `json:"adjacencySeconds"`
	}{sourceDigest, windowStart.UTC(), windowEnd.UTC(), request.Policy.AdjacentSourceWindowSeconds})
	if err != nil {
		return sourceIntervalClaim{}, ErrInvalidRequest
	}
	return sourceIntervalClaim{SourceSHA256: sourceDigest, IntervalSHA256: intervalDigest, WindowStart: windowStart.UTC(), WindowEnd: windowEnd.UTC(),
		WindowStartUnixNano: startNanos, WindowEndUnixNano: endNanos, GuardStartUnixNano: guardStartNanos, GuardEndUnixNano: guardEndNanos,
		Split: candidate.Split, AdjacencySeconds: request.Policy.AdjacentSourceWindowSeconds}, nil
}

func validateTemporalIsolation(items []admittedItem, adjacency time.Duration) error {
	bySource := make(map[string][]admittedItem)
	for _, item := range items {
		bySource[item.descriptor.Binding.SourceRef] = append(bySource[item.descriptor.Binding.SourceRef], item)
	}
	for _, sourceItems := range bySource {
		sort.Slice(sourceItems, func(i, j int) bool {
			if !sourceItems[i].windowStart.Equal(sourceItems[j].windowStart) {
				return sourceItems[i].windowStart.Before(sourceItems[j].windowStart)
			}
			return sourceItems[i].candidate.ItemID < sourceItems[j].candidate.ItemID
		})
		latestEnd := make(map[Split]time.Time, 3)
		for _, item := range sourceItems {
			for _, other := range []Split{SplitTrain, SplitValidation, SplitTest} {
				if other == item.candidate.Split {
					continue
				}
				if end := latestEnd[other]; !end.IsZero() && !item.windowStart.After(end.Add(adjacency)) {
					return fmt.Errorf("%w: adjacent observations from one source cross splits", ErrLeakage)
				}
			}
			if item.windowEnd.After(latestEnd[item.candidate.Split]) {
				latestEnd[item.candidate.Split] = item.windowEnd
			}
		}
	}
	return nil
}

func (v *Validator) project(request IntakeRequest, admitted []admittedItem, closure map[string]media.Descriptor, policyDigest string, counts SplitCounts, annotationCount int, now time.Time) (Dataset, error) {
	tenantStratum, err := v.safePseudonym("tenant", []string{request.TenantID}, request.TenantID)
	if err != nil {
		return Dataset{}, err
	}
	siteStratum, err := v.safePseudonym("site", []string{request.TenantID, request.SiteID}, request.TenantID, request.SiteID)
	if err != nil {
		return Dataset{}, err
	}
	items := make([]Item, 0, len(admitted))
	claims := make([]identityClaim, 0, len(admitted)*5)
	intervals := make([]sourceIntervalClaim, 0, len(admitted))
	reviewBindings := make([]annotationReviewBinding, 0, annotationCount)
	strataCounts := make(map[string]StratumSummary)
	for _, value := range admitted {
		sourceStratum, pseudoErr := v.safePseudonym("source", []string{request.TenantID, request.SiteID, value.descriptor.Binding.SourceRef}, request.TenantID, request.SiteID, value.descriptor.Binding.SourceRef)
		if pseudoErr != nil {
			return Dataset{}, pseudoErr
		}
		groupStratum, pseudoErr := v.safePseudonym("group", []string{request.TenantID, request.SiteID, value.candidate.GroupRef}, request.TenantID, request.SiteID, value.candidate.GroupRef)
		if pseudoErr != nil {
			return Dataset{}, pseudoErr
		}
		annotations := make([]Annotation, 0, len(value.annotations))
		for _, admittedAnnotation := range value.annotations {
			candidate := admittedAnnotation.candidate
			annotation := Annotation{AnnotationID: candidate.AnnotationID, CriterionID: candidate.CriterionID, CriterionVersion: candidate.CriterionVersion,
				SceneTaxonomy: append([]string(nil), candidate.SceneTaxonomy...), ResultKind: candidate.ResultKind, ResultSchemaRef: candidate.ResultSchemaRef,
				Label: cloneLabel(candidate.Label), AnnotationSHA256: admittedAnnotation.digest, ReviewSetSHA256: admittedAnnotation.reviewSetSHA256,
				ApprovalCount: admittedAnnotation.approvals, LastReviewedAt: admittedAnnotation.approvalAt}
			annotations = append(annotations, annotation)
			sceneDigest, digestErr := sha256JSON(candidate.SceneTaxonomy)
			if digestErr != nil {
				return Dataset{}, ErrInvalidRequest
			}
			key := stratumKey(siteStratum, sourceStratum, value.candidate.Split, candidate.CriterionID, candidate.CriterionVersion, candidate.ResultKind, candidate.ResultSchemaRef, sceneDigest)
			summary := strataCounts[key]
			summary.SiteStratum, summary.SourceStratum, summary.Split = siteStratum, sourceStratum, value.candidate.Split
			summary.CriterionID, summary.CriterionVersion, summary.ResultKind = candidate.CriterionID, candidate.CriterionVersion, candidate.ResultKind
			summary.ResultSchemaRef, summary.SceneTaxonomySHA256 = candidate.ResultSchemaRef, sceneDigest
			summary.Count++
			strataCounts[key] = summary
			reviewBindings = append(reviewBindings, annotationReviewBinding{ItemID: value.candidate.ItemID, AnnotationID: candidate.AnnotationID,
				AnnotationSHA256: admittedAnnotation.digest, ReviewSetSHA256: admittedAnnotation.reviewSetSHA256, Reviews: append([]ReviewRecord(nil), admittedAnnotation.reviews...)})
		}
		items = append(items, Item{ItemID: value.candidate.ItemID, MediaRef: value.candidate.MediaRef, Kind: value.descriptor.Kind,
			Split: value.candidate.Split, CapturedAt: value.capturedAt.UTC(), SiteStratum: siteStratum, SourceStratum: sourceStratum,
			GroupStratum: groupStratum, Annotations: annotations})
		claims = append(claims, value.claims...)
		intervals = append(intervals, value.interval)
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].Kind != claims[j].Kind {
			return claims[i].Kind < claims[j].Kind
		}
		return claims[i].SHA256 < claims[j].SHA256
	})
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].SourceSHA256 != intervals[j].SourceSHA256 {
			return intervals[i].SourceSHA256 < intervals[j].SourceSHA256
		}
		if intervals[i].WindowStartUnixNano != intervals[j].WindowStartUnixNano {
			return intervals[i].WindowStartUnixNano < intervals[j].WindowStartUnixNano
		}
		return intervals[i].IntervalSHA256 < intervals[j].IntervalSHA256
	})
	strata := make([]StratumSummary, 0, len(strataCounts))
	for _, summary := range strataCounts {
		strata = append(strata, summary)
	}
	sort.Slice(strata, func(i, j int) bool {
		left := stratumKey(strata[i].SiteStratum, strata[i].SourceStratum, strata[i].Split, strata[i].CriterionID, strata[i].CriterionVersion, strata[i].ResultKind, strata[i].ResultSchemaRef, strata[i].SceneTaxonomySHA256)
		right := stratumKey(strata[j].SiteStratum, strata[j].SourceStratum, strata[j].Split, strata[j].CriterionID, strata[j].CriterionVersion, strata[j].ResultKind, strata[j].ResultSchemaRef, strata[j].SceneTaxonomySHA256)
		return left < right
	})
	sort.Slice(reviewBindings, func(i, j int) bool {
		if reviewBindings[i].ItemID != reviewBindings[j].ItemID {
			return reviewBindings[i].ItemID < reviewBindings[j].ItemID
		}
		return reviewBindings[i].AnnotationID < reviewBindings[j].AnnotationID
	})
	dataset := Dataset{Schema: Schema, DatasetID: request.DatasetID, Revision: request.Revision, PurposeRef: request.PurposeRef,
		TenantStratum: tenantStratum, SiteStratum: siteStratum, PolicySHA256: policyDigest, RetainUntil: request.Policy.RetainUntil.UTC(),
		GovernanceState: GovernanceActive, CreatedAt: now, Items: items, Strata: strata, CountsBySplit: counts,
		AnnotationCount: annotationCount, ApprovalMinimum: request.Policy.MinimumApprovals, claims: claims, sourceIntervals: intervals, reviewBindings: reviewBindings}
	if err := validateProtectedProjection(dataset, protectedRawValues(request, admitted, closure)); err != nil {
		return Dataset{}, err
	}
	dataset.admissionSHA256, err = admissionDigest(dataset)
	if err != nil {
		return Dataset{}, ErrInvalidRequest
	}
	return dataset, nil
}

func protectedRawValues(request IntakeRequest, admitted []admittedItem, closure map[string]media.Descriptor) []string {
	values := []string{request.TenantID, request.SiteID, request.AuthorityRef, request.PrincipalSHA256}
	for _, item := range admitted {
		values = append(values, item.candidate.GroupRef)
		for _, annotation := range item.annotations {
			for _, review := range annotation.reviews {
				values = append(values, review.ReviewID, review.ReviewerSHA256, review.ReviewerRole)
			}
		}
	}
	refs := make([]string, 0, len(closure))
	for ref := range closure {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		descriptor := closure[ref]
		values = append(values, descriptor.Binding.TenantID, descriptor.Binding.SiteID, descriptor.Binding.SourceRef,
			descriptor.Binding.RunID, descriptor.Binding.StepID, descriptor.Integrity.SHA256, descriptor.Lineage.ParentMediaRef,
			descriptor.Lineage.TransformPolicyRef, descriptor.RuntimeLease.SourceMediaRef, descriptor.RuntimeLease.SourceSHA256,
			descriptor.RuntimeLease.PolicyRef, descriptor.Governance.RedactionPolicyRef, descriptor.Governance.RetentionPolicyRef)
		values = append(values, descriptor.Governance.Audience...)
		for _, member := range descriptor.FrameMembers {
			values = append(values, member.MediaRef, member.SHA256, member.TransformPolicyRef)
		}
	}
	return values
}

func validateProtectedProjection(value Dataset, protected []string) error {
	exactOutputs, scanOutputs := projectionTaintValues(value)
	exactProtected := make(map[string]struct{}, len(protected))
	patterns := make(map[string]struct{}, len(protected))
	patternBytes := 0
	for _, raw := range protected {
		if raw == "" {
			continue
		}
		exactProtected[raw] = struct{}{}
		normalized := normalizeTaint(raw)
		if normalized != "" {
			if _, exists := patterns[normalized]; !exists {
				patternBytes += len(normalized)
				patterns[normalized] = struct{}{}
			}
		}
	}
	if len(patterns) > MaximumProtectedTaintPatterns || patternBytes > MaximumProtectedTaintBytes {
		return ErrInvalidRequest
	}
	for _, output := range exactOutputs {
		if _, collision := exactProtected[output]; collision {
			return ErrScopeMismatch
		}
	}
	matcher := newTaintMatcher(patterns)
	for _, output := range scanOutputs {
		if matcher.matches(normalizeTaint(output)) {
			return ErrScopeMismatch
		}
	}
	return nil
}

func projectionTaintValues(value Dataset) ([]string, []string) {
	exact := []string{value.DatasetID, value.PurposeRef, value.TenantStratum, value.SiteStratum, value.PolicySHA256}
	scan := []string{stripTaintNamespace(value.DatasetID, "dataset-"), stripTaintNamespace(value.PurposeRef, "purpose-")}
	for _, item := range value.Items {
		exact = append(exact, item.ItemID, item.SiteStratum, item.SourceStratum, item.GroupStratum)
		scan = append(scan, stripTaintNamespace(item.ItemID, "item-"))
		// MediaRef is an explicitly safe immutable content handle and is not a
		// projection of any protected source/device identifier.
		for _, annotation := range item.Annotations {
			exact = append(exact, annotation.AnnotationID, annotation.CriterionID, annotation.ResultSchemaRef,
				annotation.AnnotationSHA256, annotation.ReviewSetSHA256)
			scan = append(scan, stripTaintNamespace(annotation.AnnotationID, "annotation-"), stripTaintNamespace(annotation.CriterionID, "criterion-"),
				stripTaintNamespace(annotation.ResultSchemaRef, "result-schema-"))
			for _, scene := range annotation.SceneTaxonomy {
				exact = append(exact, scene)
				scan = append(scan, stripTaintNamespace(scene, "scene-"))
			}
			labelExact, labelScan := labelTaintValues(annotation.Label)
			exact, scan = append(exact, labelExact...), append(scan, labelScan...)
		}
	}
	for _, stratum := range value.Strata {
		exact = append(exact, stratum.SiteStratum, stratum.SourceStratum, stratum.CriterionID, stratum.ResultSchemaRef, stratum.SceneTaxonomySHA256)
		scan = append(scan, stripTaintNamespace(stratum.CriterionID, "criterion-"), stripTaintNamespace(stratum.ResultSchemaRef, "result-schema-"))
	}
	return exact, scan
}

func labelTaintValues(value Label) ([]string, []string) {
	exact, scan := make([]string, 0), make([]string, 0)
	if value.Enum != nil {
		exact = append(exact, value.Enum.Value)
		scan = append(scan, stripTaintNamespace(value.Enum.Value, "enum-"))
	}
	if value.Structured != nil {
		for _, field := range value.Structured.Fields {
			exact = append(exact, field.Name)
			scan = append(scan, stripTaintNamespace(field.Name, "field-"))
			if field.Value.Enum != nil {
				exact = append(exact, *field.Value.Enum)
				scan = append(scan, stripTaintNamespace(*field.Value.Enum, "enum-"))
			}
		}
	}
	if value.Metric != nil {
		exact = append(exact, value.Metric.Unit)
		scan = append(scan, stripTaintNamespace(value.Metric.Unit, "unit-"))
	}
	if value.Detection != nil {
		for _, object := range value.Detection.Objects {
			exact = append(exact, object.Label)
			scan = append(scan, stripTaintNamespace(object.Label, "object-"))
		}
	}
	if value.Event != nil {
		exact = append(exact, value.Event.Type)
		scan = append(scan, stripTaintNamespace(value.Event.Type, "event-"))
	}
	return exact, scan
}

func stripTaintNamespace(value, prefix string) string { return strings.TrimPrefix(value, prefix) }

type taintNode struct {
	next map[rune]int
	fail int
	out  bool
}

type taintMatcher struct{ nodes []taintNode }

func newTaintMatcher(patterns map[string]struct{}) taintMatcher {
	m := taintMatcher{nodes: []taintNode{{next: make(map[rune]int)}}}
	for pattern := range patterns {
		state := 0
		for _, value := range pattern {
			next, exists := m.nodes[state].next[value]
			if !exists {
				next = len(m.nodes)
				m.nodes[state].next[value] = next
				m.nodes = append(m.nodes, taintNode{next: make(map[rune]int)})
			}
			state = next
		}
		m.nodes[state].out = true
	}
	queue := make([]int, 0, len(m.nodes))
	for _, child := range m.nodes[0].next {
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for value, child := range m.nodes[state].next {
			fallback := m.nodes[state].fail
			for fallback != 0 {
				if _, exists := m.nodes[fallback].next[value]; exists {
					break
				}
				fallback = m.nodes[fallback].fail
			}
			if next, exists := m.nodes[fallback].next[value]; exists && next != child {
				m.nodes[child].fail = next
			}
			m.nodes[child].out = m.nodes[child].out || m.nodes[m.nodes[child].fail].out
			queue = append(queue, child)
		}
	}
	return m
}

func (m taintMatcher) matches(value string) bool {
	state := 0
	for _, current := range value {
		for state != 0 {
			if _, exists := m.nodes[state].next[current]; exists {
				break
			}
			state = m.nodes[state].fail
		}
		if next, exists := m.nodes[state].next[current]; exists {
			state = next
		}
		if m.nodes[state].out {
			return true
		}
	}
	return false
}

func normalizeTaint(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, value)
}

func (v *Validator) safePseudonym(domain string, values []string, forbidden ...string) (string, error) {
	value, err := v.pseudonymizer.Pseudonym(domain, values...)
	if err != nil || !validPseudonym(domain, value) {
		return "", errors.New("dataset pseudonymization failed")
	}
	for _, raw := range forbidden {
		if value == raw {
			return "", errors.New("dataset pseudonymization failed")
		}
	}
	return value, nil
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
