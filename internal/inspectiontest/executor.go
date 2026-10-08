package inspectiontest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

var (
	ErrFixtureResolve = errors.New("fixture source resolution failed")
	ErrFixtureAcquire = errors.New("fixture media acquisition failed")
)

// RuntimeScript is a closed, fixture-only declaration. It contains no
// endpoint, credential, native device identity, prompt override, or media
// payload. Generated media is always persisted through media.Store.
type RuntimeScript struct {
	Name            FixtureScenario
	ResolveErr      error
	AcquireErr      error
	WaitForAcquire  bool
	AnalysisErr     error
	MalformedResult bool
	Assessments     map[string]inspection.Assessment
	CleanupErr      error
	CleanupPending  int
}

type RuntimePortStats struct {
	ResolveCalls int
	AcquireCalls int
	AnalyzeCalls int
	CleanupCalls int
}

// FixturePorts implements the six narrow v2 runtime ports. The same fixture
// object implements each interface, but the runtime receives six separately
// typed capabilities rather than one catch-all executor.
type FixturePorts struct {
	script RuntimeScript
	store  *media.Store
	now    func() time.Time

	mu       sync.Mutex
	stats    RuntimePortStats
	analysis map[string]inspectionruntime.AnalysisReference
}

func NewFixturePorts(script RuntimeScript, store *media.Store, now func() time.Time) (*FixturePorts, error) {
	if store == nil {
		return nil, errors.New("fixture media store is required")
	}
	if now == nil {
		now = time.Now
	}
	return &FixturePorts{
		script: cloneScript(script), store: store, now: now,
		analysis: make(map[string]inspectionruntime.AnalysisReference),
	}, nil
}

func (p *FixturePorts) Ports() inspectionruntime.Ports {
	return inspectionruntime.Ports{
		Sources: p, Existing: p, Acquisition: p, Transform: p, Analysis: analyzerPort{owner: p}, Cleanup: p,
	}
}

func (p *FixturePorts) Stats() RuntimePortStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

func (p *FixturePorts) Resolve(ctx context.Context, request inspectionruntime.ResolveSourceRequest) (inspectionruntime.ResolvedSourceSet, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	p.mu.Lock()
	p.stats.ResolveCalls++
	p.mu.Unlock()
	if p.script.ResolveErr != nil {
		return inspectionruntime.ResolvedSourceSet{}, p.script.ResolveErr
	}
	target, ok := fixtureTarget(request.TargetID)
	if !ok || request.TenantID != FixtureTenantID || request.SiteID != FixtureSiteID || !equalSourceBindings(request.Sources, target.SourceBindings) {
		return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
	}
	return inspectionruntime.ResolvedSourceSet{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResolutionRef:  deterministicFixtureRef("resolution", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		AdapterVersion: "fixture-resolver-v2",
	}, nil
}

func (p *FixturePorts) Read(context.Context, inspectionruntime.ExistingEvidenceRequest) (inspectionruntime.ExistingEvidenceResult, error) {
	return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrUnsupported
}

func (p *FixturePorts) Result(_ context.Context, evidenceRef string) (inspectionruntime.ExistingEvidenceResult, error) {
	return inspectionruntime.ExistingEvidenceResult{}, fmt.Errorf("%w: %s", inspectionruntime.ErrUnsupported, evidenceRef)
}

func (p *FixturePorts) Acquire(ctx context.Context, request inspectionruntime.MediaAcquireRequest) (inspectionruntime.MediaAcquireResult, error) {
	p.mu.Lock()
	p.stats.AcquireCalls++
	p.mu.Unlock()
	if p.script.WaitForAcquire {
		<-ctx.Done()
		return inspectionruntime.MediaAcquireResult{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	if p.script.AcquireErr != nil {
		return inspectionruntime.MediaAcquireResult{}, p.script.AcquireErr
	}
	target, ok := fixtureTarget(request.TargetID)
	if !ok || request.TenantID != FixtureTenantID || request.SiteID != FixtureSiteID || request.ResolutionRef == "" ||
		!containsSourceBinding(target.SourceBindings, request.Source) {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
	}
	expectedOperation := inspection.StepOpenMedia
	if request.Source.Kind == inspection.SourceCamera {
		expectedOperation = inspection.StepAcquireMedia
	}
	if request.Operation != expectedOperation {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
	}
	capturedAt := p.now().UTC()
	if capturedAt.After(request.Deadline) {
		return inspectionruntime.MediaAcquireResult{}, context.DeadlineExceeded
	}
	windowStart, windowEnd := capturedAt, capturedAt
	runBinding := media.Binding{
		TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
	}
	storedBinding := runBinding
	if request.Source.Kind != inspection.SourceCamera {
		storedBinding.RunID = deterministicFixtureRef("upload", request.Source.SourceHandle)
		storedBinding.StepID = "fixture-ingest"
		storedBinding.Attempt = 1
	}
	governance := media.Governance{
		PrivacyClass: "internal", RedactionPolicyRef: request.Evidence.RedactionProfile,
		RetentionPolicyRef: "fixture-retention-v2", Audience: []string{"inspection-fixture"},
		ExpiresAt: capturedAt.Add(time.Duration(request.Evidence.RetentionSeconds) * time.Second),
	}
	descriptor, err := p.store.Put(ctx, media.PutRequest{
		Kind:       media.KindImage,
		Binding:    storedBinding,
		Encoding:   media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 16, HeightPixels: 12},
		Temporal:   media.Temporal{WindowStart: &windowStart, WindowEnd: &windowEnd, SampleOrdinal: 1},
		Governance: governance,
	}, bytes.NewReader(NeutralSceneJPEG))
	if err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	if request.Source.Kind != inspection.SourceCamera {
		descriptor, err = p.store.LeaseForRun(ctx, media.RunLeaseRequest{
			SourceMediaRef: descriptor.MediaRef, Binding: runBinding, Governance: governance,
			PolicyRef: "inspection-run-lease-v2",
		})
		if err != nil {
			return inspectionruntime.MediaAcquireResult{}, err
		}
	}
	return inspectionruntime.MediaAcquireResult{Descriptor: descriptor, AdapterVersion: "fixture-media-v2"}, nil
}

func (p *FixturePorts) Describe(_ context.Context, mediaRef string) (media.Descriptor, error) {
	return p.store.Describe(mediaRef)
}

func (p *FixturePorts) Transform(context.Context, inspectionruntime.MediaTransformRequest) (inspectionruntime.MediaTransformResult, error) {
	return inspectionruntime.MediaTransformResult{}, inspectionruntime.ErrUnsupported
}

func (p *FixturePorts) Analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	p.mu.Lock()
	p.stats.AnalyzeCalls++
	p.mu.Unlock()
	if p.script.AnalysisErr != nil {
		return inspectionruntime.AnalysisReference{}, p.script.AnalysisErr
	}
	if _, ok := fixtureTarget(request.TargetID); !ok || request.TenantID != FixtureTenantID || request.SiteID != FixtureSiteID ||
		request.CriterionID != BusinessCriterionID || request.Prompt == "" || request.PromptSHA256 == "" || len(request.Inputs) == 0 {
		return inspectionruntime.AnalysisReference{}, inspectionruntime.ErrBindingStale
	}
	for _, input := range request.Inputs {
		if input.Descriptor == nil || input.ValueRef != input.Descriptor.MediaRef || input.SHA256 != input.Descriptor.Integrity.SHA256 {
			return inspectionruntime.AnalysisReference{}, errors.New("fixture analyzer received an untyped media input")
		}
	}
	assessment := p.script.Assessments[request.TargetID]
	if assessment == "" {
		assessment = inspection.AssessmentMeetsRule
	}
	candidate := fixtureCandidate(assessment, request.Inputs[0].ValueRef)
	if p.script.MalformedResult {
		candidate.Value = nil
	}
	startedAt := p.now().UTC()
	completedAt := p.now().UTC()
	if completedAt.After(request.Deadline) {
		return inspectionruntime.AnalysisReference{}, context.DeadlineExceeded
	}
	result := inspectionruntime.AnalysisReference{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: deterministicFixtureRef("analysis", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Candidate: candidate, ModelVersion: "fixture-model-v2", AdapterVersion: "fixture-analyzer-v2",
		StartedAt: startedAt, CompletedAt: completedAt,
	}
	p.mu.Lock()
	p.analysis[result.ResultRef] = cloneAnalysisReference(result)
	p.mu.Unlock()
	return result, nil
}

func (p *FixturePorts) analysisResult(ctx context.Context, resultRef string) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result, ok := p.analysis[resultRef]
	if !ok {
		return inspectionruntime.AnalysisReference{}, errors.New("fixture analysis result not found")
	}
	return cloneAnalysisReference(result), nil
}

func (p *FixturePorts) Cleanup(ctx context.Context, request inspectionruntime.CleanupRequest) (inspectionruntime.CleanupResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	p.mu.Lock()
	p.stats.CleanupCalls++
	p.mu.Unlock()
	if p.script.CleanupErr != nil {
		return inspectionruntime.CleanupResult{}, p.script.CleanupErr
	}
	pending := p.script.CleanupPending
	if pending < 0 || pending > len(request.Inputs) {
		pending = len(request.Inputs)
	}
	return inspectionruntime.CleanupResult{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: deterministicFixtureRef("cleanup", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Created:   len(request.Inputs), Removed: len(request.Inputs) - pending, Pending: pending,
	}, nil
}

// analyzerPort disambiguates Analyzer.Result from ExistingEvidenceReader.Result
// while preserving six narrow public runtime interfaces.
type analyzerPort struct{ owner *FixturePorts }

func (p analyzerPort) Analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	return p.owner.Analyze(ctx, request)
}

func (p analyzerPort) Result(ctx context.Context, resultRef string) (inspectionruntime.AnalysisReference, error) {
	return p.owner.analysisResult(ctx, resultRef)
}

func fixtureTarget(targetID string) (inspection.TargetBinding, bool) {
	for _, target := range PublishedSceneAssignment().Targets {
		if target.TargetID == targetID {
			return target, true
		}
	}
	return inspection.TargetBinding{}, false
}

func fixtureCandidate(assessment inspection.Assessment, mediaRef string) analysiscontract.Candidate {
	candidate := analysiscontract.Candidate{
		Assessment: assessment, Observability: inspection.ResultFullyVisible,
		Limitations: []analysiscontract.Limitation{},
	}
	switch assessment {
	case inspection.AssessmentMeetsRule:
		criterionSatisfied := true
		candidate.Value = structuredBusinessCriterionValue(&criterionSatisfied)
		candidate.EvidenceRefs = []string{mediaRef}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionMet}
	case inspection.AssessmentNeedsAttention:
		criterionSatisfied := false
		candidate.Value = structuredBusinessCriterionValue(&criterionSatisfied)
		candidate.EvidenceRefs = []string{mediaRef}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionViolated}
	case inspection.AssessmentNotObservable:
		candidate.Observability = inspection.ResultNotVisible
		candidate.Limitations = []analysiscontract.Limitation{analysiscontract.LimitationOcclusion}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonNotVisible}
	default:
		candidate.Assessment = inspection.AssessmentUncertain
		candidate.Observability = inspection.ResultPartiallyVisible
		candidate.Limitations = []analysiscontract.Limitation{analysiscontract.LimitationInsufficientSamples}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonInsufficientEvidence}
	}
	return candidate
}

func structuredBusinessCriterionValue(value *bool) *inspection.ResultValue {
	return &inspection.ResultValue{
		Kind: inspection.ResultStructured,
		Structured: &inspection.StructuredValue{Fields: []inspection.StructuredField{{
			Name:  "criterion_satisfied",
			Value: inspection.StructuredScalar{Kind: inspection.StructuredBoolean, Boolean: value},
		}}},
	}
}

func cloneScript(script RuntimeScript) RuntimeScript {
	clone := script
	clone.Assessments = make(map[string]inspection.Assessment, len(script.Assessments))
	for targetID, assessment := range script.Assessments {
		clone.Assessments[targetID] = assessment
	}
	return clone
}

func cloneAnalysisReference(result inspectionruntime.AnalysisReference) inspectionruntime.AnalysisReference {
	result.Candidate = fixtureCandidateCopy(result.Candidate)
	return result
}

func fixtureCandidateCopy(candidate analysiscontract.Candidate) analysiscontract.Candidate {
	cloned := candidate
	if candidate.Confidence != nil {
		confidence := *candidate.Confidence
		cloned.Confidence = &confidence
	}
	cloned.Value = cloneFixtureResultValue(candidate.Value)
	cloned.EvidenceRefs = append([]string(nil), candidate.EvidenceRefs...)
	cloned.Limitations = make([]analysiscontract.Limitation, len(candidate.Limitations))
	copy(cloned.Limitations, candidate.Limitations)
	cloned.ReasonCodes = append([]analysiscontract.ReasonCode(nil), candidate.ReasonCodes...)
	return cloned
}

func cloneFixtureResultValue(value *inspection.ResultValue) *inspection.ResultValue {
	if value == nil {
		return nil
	}
	clone := *value
	if value.Structured != nil {
		structured := *value.Structured
		structured.Fields = append([]inspection.StructuredField(nil), value.Structured.Fields...)
		for index := range structured.Fields {
			if scalar := structured.Fields[index].Value.Boolean; scalar != nil {
				boolean := *scalar
				structured.Fields[index].Value.Boolean = &boolean
			}
		}
		clone.Structured = &structured
	}
	return &clone
}

func equalSourceBindings(left, right []inspection.SourceBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !equalSourceBinding(left[index], right[index]) {
			return false
		}
	}
	return true
}

func containsSourceBinding(values []inspection.SourceBinding, expected inspection.SourceBinding) bool {
	for _, value := range values {
		if equalSourceBinding(value, expected) {
			return true
		}
	}
	return false
}

func equalSourceBinding(left, right inspection.SourceBinding) bool {
	if left.Kind != right.Kind || left.SourceHandle != right.SourceHandle || left.SourceRevision != right.SourceRevision ||
		left.SourceFingerprint != right.SourceFingerprint || left.ROIRef != right.ROIRef ||
		len(left.CapabilityRefs) != len(right.CapabilityRefs) || len(left.MediaKinds) != len(right.MediaKinds) {
		return false
	}
	for index := range left.CapabilityRefs {
		if left.CapabilityRefs[index] != right.CapabilityRefs[index] {
			return false
		}
	}
	for index := range left.MediaKinds {
		if left.MediaKinds[index] != right.MediaKinds[index] {
			return false
		}
	}
	return true
}

func deterministicFixtureRef(prefix string, values ...string) string {
	return prefix + "_" + fixtureDigest(fmt.Sprint(values))[:32]
}

var (
	_ inspectionruntime.SourceResolver           = (*FixturePorts)(nil)
	_ inspectionruntime.ExistingEvidenceReader   = (*FixturePorts)(nil)
	_ inspectionruntime.MediaAcquirer            = (*FixturePorts)(nil)
	_ inspectionruntime.MediaTransformer         = (*FixturePorts)(nil)
	_ inspectionruntime.Analyzer                 = analyzerPort{}
	_ inspectionruntime.TemporaryResourceCleaner = (*FixturePorts)(nil)
)
