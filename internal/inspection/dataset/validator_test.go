package dataset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

const (
	fixtureTenant = "tenant-private-a"
	fixtureSite   = "site-private-a"
)

type fixture struct {
	now         time.Time
	request     IntakeRequest
	descriptors []media.Descriptor
	probes      []ProbeFacts
	catalog     *MemoryMediaCatalog
	authorizer  *MemoryAuthorizer
	reviews     *MemoryReviewRepository
	verifier    *MemoryReviewVerifier
	semantics   *MemorySemanticsRegistry
	validator   *Validator
	store       *memoryDatasetStore
	service     *Service
}

func newFixture(t *testing.T, mutate func([]media.Descriptor, *IntakeRequest)) *fixture {
	t.Helper()
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	classification := Label{Kind: LabelClassification, Classification: &ClassificationLabel{Value: ClassificationMeetsRule}}
	metric := Label{Kind: LabelMetric, Metric: &MetricLabel{Value: 0.42, Unit: "unit-occupancy-ratio"}}
	request := IntakeRequest{
		Schema: Schema, TenantID: fixtureTenant, SiteID: fixtureSite, DatasetID: "dataset-dining-evaluation-v3", Revision: 1,
		PurposeRef: "purpose-assistant-evaluation", AuthorityRef: "dataset-grant-a", PrincipalSHA256: strings.Repeat("9", 64),
		Policy: Policy{Schema: PolicySchema, AllowedKinds: []media.Kind{media.KindImage}, AllowedPrivacyClasses: []string{"internal"},
			RequiredRetentionPolicyRefs: []string{"dataset-retention-v3"}, RetainUntil: now.Add(48 * time.Hour),
			MinimumRemainingRetentionSeconds: 24 * 60 * 60, ReviewPolicyRef: "two-person-review-v3", MinimumApprovals: 2,
			AdjacentSourceWindowSeconds: 60 * 60},
		Items: []Candidate{
			{Schema: ItemSchema, ItemID: "item-01", GroupRef: "group-train", Split: SplitTrain, Annotations: []AnnotationCandidate{
				{Schema: AnnotationSchema, AnnotationID: "annotation-hygiene", CriterionID: "criterion-hygiene", CriterionVersion: 1, SceneTaxonomy: []string{"scene-dining-area", "scene-indoor"}, ResultKind: LabelClassification, ResultSchemaRef: "result-schema-classification-v1", Label: classification},
				{Schema: AnnotationSchema, AnnotationID: "annotation-occupancy", CriterionID: "criterion-occupancy", CriterionVersion: 2, SceneTaxonomy: []string{"scene-dining-area", "scene-indoor"}, ResultKind: LabelMetric, ResultSchemaRef: "result-schema-ratio-v2", Label: metric},
			}},
			{Schema: ItemSchema, ItemID: "item-02", GroupRef: "group-validation", Split: SplitValidation, Annotations: []AnnotationCandidate{{Schema: AnnotationSchema, AnnotationID: "annotation-hygiene", CriterionID: "criterion-hygiene", CriterionVersion: 1, SceneTaxonomy: []string{"scene-dining-area", "scene-indoor"}, ResultKind: LabelClassification, ResultSchemaRef: "result-schema-classification-v1", Label: classification}}},
			{Schema: ItemSchema, ItemID: "item-03", GroupRef: "group-test", Split: SplitTest, Annotations: []AnnotationCandidate{{Schema: AnnotationSchema, AnnotationID: "annotation-hygiene", CriterionID: "criterion-hygiene", CriterionVersion: 1, SceneTaxonomy: []string{"scene-dining-area", "scene-indoor"}, ResultKind: LabelClassification, ResultSchemaRef: "result-schema-classification-v1", Label: classification}}},
		},
	}
	descriptors := make([]media.Descriptor, len(request.Items))
	for index := range descriptors {
		descriptors[index] = fixtureDescriptor(index+1, fmt.Sprintf("source-private-%d", index+1), now.Add(-time.Duration(72-index*12)*time.Hour), now)
	}
	if mutate != nil {
		mutate(descriptors, &request)
	}
	probes := make([]ProbeFacts, len(descriptors))
	for index, descriptor := range descriptors {
		request.Items[index].MediaRef, request.Items[index].ExpectedKind = descriptor.MediaRef, descriptor.Kind
		request.Items[index].ExpectedMIME, request.Items[index].ExpectedSHA256 = descriptor.Encoding.MIMEType, descriptor.Integrity.SHA256
		probes[index] = fixtureProbe(descriptor, now.Add(-2*time.Hour))
	}
	catalog := NewMemoryMediaCatalog()
	for index := range descriptors {
		if err := catalog.Put(descriptors[index], probes[index]); err != nil {
			t.Fatalf("put media %d: %v", index, err)
		}
	}
	authorizer := NewMemoryAuthorizer()
	reviews := NewMemoryReviewRepository()
	verifier := NewMemoryReviewVerifier()
	semantics := NewMemorySemanticsRegistry()
	installSemantics(t, semantics, request)
	installReviews(t, reviews, verifier, request, descriptors, now)
	installIntakeGrant(t, authorizer, request, descriptors, now)
	pseudonymizer, err := NewHMACPseudonymizer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(catalog, authorizer, pseudonymizer, reviews, verifier, semantics, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryDatasetStore()
	service, err := NewService(validator, store)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{now, request, descriptors, probes, catalog, authorizer, reviews, verifier, semantics, validator, store, service}
}

func installSemantics(t *testing.T, registry *MemorySemanticsRegistry, request IntakeRequest) {
	t.Helper()
	seen := make(map[string]struct{})
	for _, item := range request.Items {
		for _, annotation := range item.Annotations {
			demand := SemanticsDemand{CriterionID: annotation.CriterionID, CriterionVersion: annotation.CriterionVersion,
				ResultKind: annotation.ResultKind, ResultSchemaRef: annotation.ResultSchemaRef, SceneTaxonomy: append([]string(nil), annotation.SceneTaxonomy...), Label: cloneLabel(annotation.Label)}
			digest, _ := sha256JSON(demand)
			if _, exists := seen[digest]; exists {
				continue
			}
			seen[digest] = struct{}{}
			if err := registry.Put(demand); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func installReviews(t *testing.T, repository *MemoryReviewRepository, verifier *MemoryReviewVerifier, request IntakeRequest, descriptors []media.Descriptor, now time.Time) {
	t.Helper()
	for itemIndex, item := range request.Items {
		for _, annotation := range item.Annotations {
			subject, err := BuildReviewSubject(request, item, annotation, descriptors[itemIndex])
			if err != nil {
				t.Fatal(err)
			}
			digest, err := AnnotationSHA256(subject)
			if err != nil {
				t.Fatal(err)
			}
			for reviewIndex, reviewer := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
				record := ReviewRecord{Schema: ReviewSchema, ReviewID: fmt.Sprintf("review-%02d", reviewIndex+1), AnnotationSHA256: digest,
					ReviewerSHA256: reviewer, ReviewerRole: ReviewerRoleDataset, Decision: ReviewApproved, PolicyRef: request.Policy.ReviewPolicyRef, ReviewedAt: now.Add(time.Duration(-90+reviewIndex*30) * time.Minute)}
				record.RecordSHA256, err = ReviewRecordSHA256(record)
				if err != nil {
					t.Fatal(err)
				}
				if err := repository.Put(record); err != nil {
					t.Fatal(err)
				}
				if err := verifier.Trust(record); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func installIntakeGrant(t *testing.T, authorizer *MemoryAuthorizer, request IntakeRequest, descriptors []media.Descriptor, now time.Time) {
	t.Helper()
	policyDigest, err := PolicySHA256(request.Policy)
	if err != nil {
		t.Fatal(err)
	}
	intakeDigest, err := IntakeSHA256(request)
	if err != nil {
		t.Fatal(err)
	}
	sources, refs, descriptorFacts, annotationCount := make([]string, 0, len(descriptors)), make([]string, 0, len(descriptors)), make([]DescriptorAuthorizationFact, 0, len(descriptors)), 0
	for index, descriptor := range descriptors {
		sources = append(sources, descriptor.Binding.SourceRef)
		refs = append(refs, descriptor.MediaRef)
		descriptorDigest, _ := DescriptorSHA256(descriptor)
		descriptorFacts = append(descriptorFacts, DescriptorAuthorizationFact{MediaRef: descriptor.MediaRef, SourceRef: descriptor.Binding.SourceRef,
			DescriptorSHA256: descriptorDigest, ParentMediaRef: descriptor.Lineage.ParentMediaRef})
		annotationCount += len(request.Items[index].Annotations)
	}
	sortStringsUnique(&sources)
	sortStringsUnique(&refs)
	sort.Slice(descriptorFacts, func(i, j int) bool { return descriptorFacts[i].MediaRef < descriptorFacts[j].MediaRef })
	if err := authorizer.PutGrant(AuthorizationGrant{Schema: AuthorizationSchema, AuthorityRef: request.AuthorityRef, PrincipalSHA256: request.PrincipalSHA256,
		TenantID: request.TenantID, SiteID: request.SiteID, DatasetID: request.DatasetID, Revision: request.Revision, Operation: OperationIntake,
		IntakeSHA256: intakeDigest, PolicySHA256: policyDigest, SourceRefs: sources, RootMediaRefs: refs, Descriptors: descriptorFacts,
		LineageDiscoveryLimit: maximumLineageDepth, ItemCount: len(request.Items), AnnotationCount: annotationCount,
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceIntakeProjectsMultipleAnnotationsAndGovernance(t *testing.T) {
	f := newFixture(t, nil)
	value, err := f.service.Intake(context.Background(), f.request)
	if err != nil {
		t.Fatalf("intake: %v", err)
	}
	if value.Schema != Schema || value.GovernanceState != GovernanceActive || !value.RetainUntil.Equal(f.request.Policy.RetainUntil) || value.AnnotationCount != 4 || len(value.Items[0].Annotations) != 2 || value.Items[0].Annotations[0].CriterionID != "criterion-hygiene" || value.Items[0].Annotations[1].CriterionID != "criterion-occupancy" {
		t.Fatalf("projection=%#v", value)
	}
	if value.CountsBySplit != (SplitCounts{1, 1, 1}) || len(value.Strata) != 4 {
		t.Fatalf("counts=%#v strata=%#v", value.CountsBySplit, value.Strata)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{fixtureTenant, fixtureSite, "source-private-1", f.request.AuthorityRef, f.request.PrincipalSHA256, f.request.Items[0].ExpectedSHA256, `"reviewerSha256"`, `"descriptorSha256"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("projection leaked %q: %s", forbidden, raw)
		}
	}
	stored, err := f.store.Get(context.Background(), value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision)
	if err != nil || stored.AnnotationCount != 4 {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
	stored.Items[0].Annotations[0].SceneTaxonomy[0] = "tampered"
	again, _ := f.store.Get(context.Background(), value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision)
	if again.Items[0].Annotations[0].SceneTaxonomy[0] == "tampered" {
		t.Fatal("mutable projection escaped")
	}
}

func TestIntakeContractCannotSelfReportReview(t *testing.T) {
	f := newFixture(t, nil)
	raw, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"reviews"`) {
		t.Fatalf("request carries reviews: %s", raw)
	}
	if _, err := DecodeIntake(strings.NewReader(string(raw))); err != nil {
		t.Fatalf("canonical decode: %v", err)
	}
	mutations := map[string]func(string) string{
		"whitespace": func(value string) string { return value + "\n" },
		"key order": func(value string) string {
			prefix := `{"schema":"` + Schema + `","tenantId":"` + fixtureTenant + `"`
			reordered := `{"tenantId":"` + fixtureTenant + `","schema":"` + Schema + `"`
			return strings.Replace(value, prefix, reordered, 1)
		},
		"noncanonical number": func(value string) string { return strings.Replace(value, `"value":0.42`, `"value":4.2e-1`, 1) },
		"negative zero":       func(value string) string { return strings.Replace(value, `"value":0.42`, `"value":-0`, 1) },
		"self review": func(value string) string {
			return strings.Replace(value, `"annotations":[`, `"reviews":[{"decision":"approved"}],"annotations":[`, 1)
		},
		"path": func(value string) string { return strings.Replace(value, `{`, `{"path":"/tmp/frame.jpg",`, 1) },
		"duplicate": func(value string) string {
			return strings.Replace(value, `"tenantId":"`+fixtureTenant+`"`, `"tenantId":"`+fixtureTenant+`","tenantId":"other"`, 1)
		},
		"v2": func(value string) string { return strings.Replace(value, Schema, "cosmoedge.inspection.dataset.v2", 1) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeIntake(strings.NewReader(mutate(string(raw)))); err == nil {
				t.Fatal("unsafe contract accepted")
			}
		})
	}
}

type countingCatalog struct {
	base              MediaCatalog
	describes, probes atomic.Int32
}

func (c *countingCatalog) Describe(ctx context.Context, ref string) (media.Descriptor, error) {
	c.describes.Add(1)
	return c.base.Describe(ctx, ref)
}
func (c *countingCatalog) Probe(ctx context.Context, ref string) (ProbeFacts, error) {
	c.probes.Add(1)
	return c.base.Probe(ctx, ref)
}

type countingReviews struct {
	base  ReviewRepository
	calls atomic.Int32
}

func (c *countingReviews) ListReviews(ctx context.Context, query ReviewQuery) ([]ReviewRecord, error) {
	c.calls.Add(1)
	return c.base.ListReviews(ctx, query)
}

type countingSemantics struct {
	base  SemanticsRegistry
	calls atomic.Int32
}

func (c *countingSemantics) VerifySemantics(ctx context.Context, demand SemanticsDemand) error {
	c.calls.Add(1)
	return c.base.VerifySemantics(ctx, demand)
}

type phaseDenyAuthorizer struct {
	denyPreflight bool
	denyFinal     bool
	preflights    atomic.Int32
	finals        atomic.Int32
}

func (a *phaseDenyAuthorizer) PreflightDataset(context.Context, PreflightAuthorizationDemand) error {
	a.preflights.Add(1)
	if a.denyPreflight {
		return ErrUnauthorized
	}
	return nil
}
func (a *phaseDenyAuthorizer) AuthorizeDataset(context.Context, FinalAuthorizationDemand) error {
	a.finals.Add(1)
	if a.denyFinal {
		return ErrUnauthorized
	}
	return nil
}

func TestAuthorizationDenialHasProvableDependencyOrder(t *testing.T) {
	for _, test := range []struct {
		name             string
		preflight, final bool
		wantDescribe     int32
		wantSemantics    int32
	}{{"preflight", true, false, 0, 0}, {"final", false, true, 3, 4}} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, nil)
			catalog := &countingCatalog{base: f.catalog}
			reviews := &countingReviews{base: f.reviews}
			semantics := &countingSemantics{base: f.semantics}
			authorizer := &phaseDenyAuthorizer{denyPreflight: test.preflight, denyFinal: test.final}
			pseudonymizer, _ := NewHMACPseudonymizer([]byte("0123456789abcdef0123456789abcdef"))
			validator, err := NewValidator(catalog, authorizer, pseudonymizer, reviews, f.verifier, semantics, func() time.Time { return f.now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validator.Validate(context.Background(), f.request); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("error=%v", err)
			}
			if catalog.describes.Load() != test.wantDescribe || catalog.probes.Load() != 0 || reviews.calls.Load() != 0 || semantics.calls.Load() != test.wantSemantics {
				t.Fatalf("describe=%d probe=%d reviews=%d semantics=%d", catalog.describes.Load(), catalog.probes.Load(), reviews.calls.Load(), semantics.calls.Load())
			}
			if authorizer.preflights.Load() != 1 || authorizer.finals.Load() != boolCount(!test.preflight) {
				t.Fatalf("preflight=%d final=%d", authorizer.preflights.Load(), authorizer.finals.Load())
			}
		})
	}
}

func boolCount(value bool) int32 {
	if value {
		return 1
	}
	return 0
}

func TestReviewerIdentityAndRoleAreIndependentFromIntake(t *testing.T) {
	for _, test := range []struct {
		name     string
		reviewer string
		role     string
	}{{"same principal", strings.Repeat("9", 64), ReviewerRoleDataset}, {"wrong role", strings.Repeat("c", 64), "role-site-operator"}} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, nil)
			item, annotation := f.request.Items[0], f.request.Items[0].Annotations[0]
			subject, _ := BuildReviewSubject(f.request, item, annotation, f.descriptors[0])
			digest, _ := AnnotationSHA256(subject)
			record := ReviewRecord{Schema: ReviewSchema, ReviewID: "review-00-adversarial", AnnotationSHA256: digest,
				ReviewerSHA256: test.reviewer, ReviewerRole: test.role, Decision: ReviewApproved, PolicyRef: f.request.Policy.ReviewPolicyRef,
				ReviewedAt: f.now.Add(-45 * time.Minute)}
			var digestErr error
			record.RecordSHA256, digestErr = ReviewRecordSHA256(record)
			if test.role != ReviewerRoleDataset {
				if !errors.Is(digestErr, ErrReviewIncomplete) {
					t.Fatalf("role digest error=%v", digestErr)
				}
				return
			}
			if err := f.reviews.Put(record); err != nil {
				t.Fatal(err)
			}
			if err := f.verifier.Trust(record); err != nil {
				t.Fatal(err)
			}
			if _, err := f.validator.Validate(context.Background(), f.request); !errors.Is(err, ErrReviewIncomplete) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTrustedSemanticsRegistryBindsExactTuple(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*AnnotationCandidate)
	}{
		{"result schema", func(annotation *AnnotationCandidate) { annotation.ResultSchemaRef = "result-schema-unregistered" }},
		{"actual label", func(annotation *AnnotationCandidate) {
			annotation.Label.Classification.Value = ClassificationNeedsAttention
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, nil)
			test.mutate(&f.request.Items[0].Annotations[0])
			pseudonymizer, _ := NewHMACPseudonymizer([]byte("0123456789abcdef0123456789abcdef"))
			validator, _ := NewValidator(f.catalog, &phaseDenyAuthorizer{}, pseudonymizer, f.reviews, f.verifier, f.semantics, func() time.Time { return f.now })
			if _, err := validator.Validate(context.Background(), f.request); !errors.Is(err, ErrUnsupportedSemantics) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProtectedProjectionCheckerboard(t *testing.T) {
	f := newFixture(t, nil)
	value, err := f.validator.Validate(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	raw := "protected-raw-value"
	mutations := map[string]func(*Dataset){
		"dataset id":    func(v *Dataset) { v.DatasetID = raw },
		"purpose":       func(v *Dataset) { v.PurposeRef = raw },
		"item id":       func(v *Dataset) { v.Items[0].ItemID = raw },
		"annotation id": func(v *Dataset) { v.Items[0].Annotations[0].AnnotationID = raw },
		"criterion":     func(v *Dataset) { v.Items[0].Annotations[0].CriterionID = raw },
		"taxonomy":      func(v *Dataset) { v.Items[0].Annotations[0].SceneTaxonomy[0] = raw },
		"result schema": func(v *Dataset) { v.Items[0].Annotations[0].ResultSchemaRef = raw },
		"enum": func(v *Dataset) {
			v.Items[0].Annotations[0].Label = Label{Kind: LabelEnum, Enum: &EnumLabel{Value: raw}}
		},
		"structured field": func(v *Dataset) {
			b := true
			v.Items[0].Annotations[0].Label = Label{Kind: LabelStructured, Structured: &StructuredLabel{Fields: []StructuredField{{Name: raw, Value: StructuredScalar{Kind: StructuredBoolean, Boolean: &b}}}}}
		},
		"structured enum": func(v *Dataset) {
			e := raw
			v.Items[0].Annotations[0].Label = Label{Kind: LabelStructured, Structured: &StructuredLabel{Fields: []StructuredField{{Name: "field-safe", Value: StructuredScalar{Kind: StructuredEnum, Enum: &e}}}}}
		},
		"metric unit": func(v *Dataset) {
			v.Items[0].Annotations[0].Label = Label{Kind: LabelMetric, Metric: &MetricLabel{Value: 1, Unit: raw}}
		},
		"detection label": func(v *Dataset) {
			v.Items[0].Annotations[0].Label = Label{Kind: LabelDetection, Detection: &DetectionLabel{Objects: []DetectionObject{{Label: raw}}}}
		},
		"event type": func(v *Dataset) {
			v.Items[0].Annotations[0].Label = Label{Kind: LabelEvent, Event: &EventLabel{Type: raw}}
		},
		"stratum schema": func(v *Dataset) { v.Strata[0].ResultSchemaRef = raw },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneDataset(value, true)
			mutate(&candidate)
			if err := validateProtectedProjection(candidate, []string{raw}); !errors.Is(err, ErrScopeMismatch) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestValidatorRejectsNamespacedRawDescriptorValueInProjection(t *testing.T) {
	f := newFixture(t, func(descriptors []media.Descriptor, request *IntakeRequest) {
		descriptors[0].Binding.SourceRef = "criterion-protected-source"
		request.Items[0].Annotations[0].CriterionID = descriptors[0].Binding.SourceRef
	})
	if _, err := f.validator.Validate(context.Background(), f.request); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("error=%v", err)
	}
}

func TestValidatorRequiresTrustedRepositoryReview(t *testing.T) {
	f := newFixture(t, nil)
	pseudonymizer, _ := NewHMACPseudonymizer([]byte("0123456789abcdef0123456789abcdef"))
	for name, dependencies := range map[string]struct {
		repository ReviewRepository
		verifier   ReviewVerifier
	}{
		"missing":   {NewMemoryReviewRepository(), f.verifier},
		"untrusted": {f.reviews, NewMemoryReviewVerifier()},
	} {
		t.Run(name, func(t *testing.T) {
			validator, _ := NewValidator(f.catalog, f.authorizer, pseudonymizer, dependencies.repository, dependencies.verifier, f.semantics, func() time.Time { return f.now })
			if _, err := validator.Validate(context.Background(), f.request); !errors.Is(err, ErrReviewIncomplete) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	item := f.request.Items[0]
	annotation := item.Annotations[0]
	subject, _ := BuildReviewSubject(f.request, item, annotation, f.descriptors[0])
	digest, _ := AnnotationSHA256(subject)
	rejected := ReviewRecord{Schema: ReviewSchema, ReviewID: "review-rejected", AnnotationSHA256: digest, ReviewerSHA256: strings.Repeat("c", 64), ReviewerRole: ReviewerRoleDataset, Decision: ReviewRejected, PolicyRef: f.request.Policy.ReviewPolicyRef, ReviewedAt: f.now.Add(-30 * time.Minute)}
	rejected.RecordSHA256, _ = ReviewRecordSHA256(rejected)
	_ = f.reviews.Put(rejected)
	_ = f.verifier.Trust(rejected)
	if _, err := f.validator.Validate(context.Background(), f.request); !errors.Is(err, ErrReviewRejected) {
		t.Fatalf("rejected review error=%v", err)
	}
}

func TestValidatorRejectsLineageAndTemporalLeakage(t *testing.T) {
	t.Run("lineage", func(t *testing.T) {
		f := newFixture(t, func(descriptors []media.Descriptor, _ *IntakeRequest) {
			descriptors[1].Lineage = media.Lineage{ParentMediaRef: descriptors[0].MediaRef, TransformPolicyRef: "crop-v3", Ordinal: 1, OffsetMillis: 100}
		})
		if _, err := f.validator.Validate(context.Background(), f.request); !errors.Is(err, ErrLeakage) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("source time", func(t *testing.T) {
		f := newFixture(t, func(descriptors []media.Descriptor, _ *IntakeRequest) {
			descriptors[1].Binding.SourceRef = descriptors[0].Binding.SourceRef
			start := *descriptors[0].Temporal.WindowStart
			adjacent := start.Add(30 * time.Minute)
			descriptors[1].Temporal.WindowStart, descriptors[1].Temporal.WindowEnd = &adjacent, &adjacent
		})
		if _, err := f.validator.Validate(context.Background(), f.request); !errors.Is(err, ErrLeakage) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestIdentityClaimsAreGlobalAndSourceTimeIsCanonical(t *testing.T) {
	f := newFixture(t, nil)
	descriptor := f.descriptors[0]
	start, end := descriptorWindow(descriptor)
	lineage := []string{descriptor.MediaRef}
	first, err := buildIdentityClaims(f.request, f.request.Items[0], descriptor, lineage, start, end)
	if err != nil {
		t.Fatal(err)
	}
	otherRevision := f.request
	otherRevision.DatasetID = "dataset-entirely-different"
	otherRevision.Revision = 99
	second, err := buildIdentityClaims(otherRevision, f.request.Items[0], descriptor, lineage, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identity changed with dataset scope: first=%#v second=%#v", first, second)
	}
	kinds := make(map[string]int)
	for _, claim := range first {
		kinds[claim.Kind]++
	}
	for _, kind := range []string{identityContent, identityMedia, identityLineage, identityGroup, identitySourceTime} {
		if kinds[kind] != 1 {
			t.Fatalf("identity kind %s count=%d claims=%#v", kind, kinds[kind], first)
		}
	}
	shifted, err := buildIdentityClaims(f.request, f.request.Items[0], descriptor, lineage, start.Add(time.Nanosecond), end)
	if err != nil {
		t.Fatal(err)
	}
	var originalSourceTime, shiftedSourceTime string
	for _, claim := range first {
		if claim.Kind == identitySourceTime {
			originalSourceTime = claim.SHA256
		}
	}
	for _, claim := range shifted {
		if claim.Kind == identitySourceTime {
			shiftedSourceTime = claim.SHA256
		}
	}
	if originalSourceTime == "" || shiftedSourceTime == "" || originalSourceTime == shiftedSourceTime {
		t.Fatalf("source-time identity is not exact: %q %q", originalSourceTime, shiftedSourceTime)
	}
	otherScope := f.request
	otherScope.TenantID = "tenant-private-b"
	otherScope.SiteID = "site-private-b"
	otherDescriptor := descriptor
	otherDescriptor.Binding.TenantID = otherScope.TenantID
	otherDescriptor.Binding.SiteID = otherScope.SiteID
	otherInterval, err := buildSourceIntervalClaim(otherScope, f.request.Items[0], otherDescriptor, start, end)
	if err != nil {
		t.Fatal(err)
	}
	originalInterval, err := buildSourceIntervalClaim(f.request, f.request.Items[0], descriptor, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if otherInterval.SourceSHA256 == originalInterval.SourceSHA256 {
		t.Fatal("source interval identity is not tenant/site scoped")
	}
	otherClaims, err := buildIdentityClaims(otherScope, f.request.Items[0], otherDescriptor, lineage, start, end)
	if err != nil {
		t.Fatal(err)
	}
	var originalContent, otherContent string
	for _, claim := range first {
		if claim.Kind == identityContent {
			originalContent = claim.SHA256
		}
	}
	for _, claim := range otherClaims {
		if claim.Kind == identityContent {
			otherContent = claim.SHA256
		}
	}
	if originalContent == "" || originalContent != otherContent {
		t.Fatalf("content identity must remain global: %q %q", originalContent, otherContent)
	}
}

func TestLabelCollectionsRequireCanonicalOrder(t *testing.T) {
	left := DetectionObject{Label: "object-chair", Region: NormalizedRegion{X: 0.1, Y: 0.1, Width: 0.2, Height: 0.2}}
	right := DetectionObject{Label: "object-table", Region: NormalizedRegion{X: 0.4, Y: 0.4, Width: 0.3, Height: 0.3}}
	canonical := Label{Kind: LabelDetection, Detection: &DetectionLabel{Objects: []DetectionObject{left, right}}}
	if err := validateLabel(canonical); err != nil {
		t.Fatalf("canonical detection: %v", err)
	}
	reversed := Label{Kind: LabelDetection, Detection: &DetectionLabel{Objects: []DetectionObject{right, left}}}
	if err := validateLabel(reversed); err == nil {
		t.Fatal("non-canonical detection order accepted")
	}
	duplicate := Label{Kind: LabelDetection, Detection: &DetectionLabel{Objects: []DetectionObject{left, left}}}
	if err := validateLabel(duplicate); err == nil {
		t.Fatal("duplicate detection accepted")
	}
}

func TestMemoryAdmissionAtomicAndRaceSafe(t *testing.T) {
	f := newFixture(t, nil)
	const workers = 24
	var success, conflict atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := f.service.Intake(context.Background(), f.request)
			if err == nil {
				success.Add(1)
			} else if errors.Is(err, ErrConflict) {
				conflict.Add(1)
			} else {
				t.Errorf("intake: %v", err)
			}
		}()
	}
	wait.Wait()
	if success.Load() != 1 || conflict.Load() != workers-1 {
		t.Fatalf("success=%d conflict=%d", success.Load(), conflict.Load())
	}
}

func fixtureDescriptor(index int, source string, capturedAt, now time.Time) media.Descriptor {
	start, end := capturedAt.UTC(), capturedAt.UTC()
	return media.Descriptor{Schema: media.Schema, MediaRef: fmt.Sprintf("media_%032x", index), Kind: media.KindImage,
		Binding:  media.Binding{TenantID: fixtureTenant, SiteID: fixtureSite, SourceRef: source, RunID: "dataset-fixture-run", StepID: "dataset-fixture-step", Attempt: 1},
		Encoding: media.Encoding{MIMEType: "image/png", Container: "png", Codec: "png", WidthPixels: 1280, HeightPixels: 720},
		Temporal: media.Temporal{WindowStart: &start, WindowEnd: &end, SampleOrdinal: index}, Integrity: media.Integrity{SHA256: fmt.Sprintf("%064x", index), SizeBytes: int64(1024 + index)},
		Lineage: media.Lineage{}, Governance: media.Governance{PrivacyClass: "internal", RetentionPolicyRef: "dataset-retention-v3", Audience: []string{"dataset-reviewer"}, ExpiresAt: now.Add(96 * time.Hour)},
		FrameMembers: []media.FrameMember{}, Availability: media.AvailabilityAvailable, CreatedAt: capturedAt.UTC()}
}
func fixtureProbe(descriptor media.Descriptor, probedAt time.Time) ProbeFacts {
	return ProbeFacts{Schema: ProbeSchema, MediaRef: descriptor.MediaRef, Kind: descriptor.Kind, MIMEType: descriptor.Encoding.MIMEType, SHA256: descriptor.Integrity.SHA256, SizeBytes: descriptor.Integrity.SizeBytes, WidthPixels: descriptor.Encoding.WidthPixels, HeightPixels: descriptor.Encoding.HeightPixels, DurationMS: descriptor.Temporal.DurationMillis, ProbeRef: "ffprobe-policy-v3", ProbedAt: probedAt.UTC()}
}
func sortStringsUnique(values *[]string) {
	sort.Strings(*values)
	result := (*values)[:0]
	for _, value := range *values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	*values = result
}
