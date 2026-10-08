package inspectiontest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

var gateMP4 = []byte{
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2',
	0x00, 0x00, 0x02, 0x00, 'm', 'p', '4', '2', 'i', 's', 'o', 'm',
}

type gateCatalogValidator interface {
	ValidateInstalledTask(context.Context, string, string, inspection.InstalledTaskBinding) error
}

type gatePortStats struct {
	ResolveCalls          int
	ExistingCalls         int
	AcquireCalls          int
	TransformCalls        int
	AnalyzeCalls          int
	CleanupCalls          int
	CVSelectionCalls      int
	VLMFollowupCalls      int
	AcquisitionOperations []inspection.StepKind
	AnalysisRequests      []inspectionruntime.AnalyzeRequest
	TransformResults      []media.Descriptor
	CVSelectedMedia       [][]string
}

type gatePorts struct {
	fixture gateFixture
	store   *media.Store
	now     func() time.Time
	catalog gateCatalogValidator

	invalidModel              bool
	cleanupFailure            bool
	wrongExistingMediaKind    bool
	swapEvidenceAfterAnalysis bool
	blockAcquire              bool
	acquireEntered            chan struct{}
	enterOnce                 sync.Once

	mu                sync.Mutex
	stats             gatePortStats
	evidence          map[string]inspectionruntime.ExistingEvidenceResult
	evidenceResults   map[string]int
	alternateEvidence map[string]media.Descriptor
	analysis          map[string]inspectionruntime.AnalysisReference
	uploadedSourceRef string
}

func (p *gatePorts) seedUploaded(ctx context.Context) error {
	if p.fixture.Mode != gateUploadedImage && p.fixture.Mode != gateClip {
		return nil
	}
	source := p.fixture.Assignment.Targets[0].SourceBindings[0]
	capturedAt := p.fixture.Request.RequestedAt.Add(-10 * time.Second)
	put := media.PutRequest{
		Binding: media.Binding{
			TenantID: gateTenantID, SiteID: gateSiteID, SourceRef: source.SourceHandle,
			RunID: gateOpaqueRef("upload", source.SourceHandle), StepID: "fixture-ingest", Attempt: 1,
		},
		Temporal: media.Temporal{WindowStart: &capturedAt, SampleOrdinal: 1}, Governance: p.governance(),
	}
	content := NeutralSceneJPEG
	if p.fixture.Mode == gateUploadedImage {
		put.Kind = media.KindImage
		put.Encoding = media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 16, HeightPixels: 12}
		put.Temporal.WindowEnd = &capturedAt
	} else {
		windowEnd := capturedAt.Add(1500 * time.Millisecond)
		put.Kind = media.KindVideoClip
		put.Encoding = media.Encoding{MIMEType: "video/mp4", Container: "mp4", Codec: "h264", WidthPixels: 64, HeightPixels: 48, FrameRate: 10}
		put.Temporal.DurationMillis = 1500
		put.Temporal.WindowEnd = &windowEnd
		content = gateMP4
	}
	descriptor, err := p.store.Put(ctx, put, bytes.NewReader(content))
	if err != nil {
		return err
	}
	p.uploadedSourceRef = descriptor.MediaRef
	return nil
}

func newGatePorts(fixture gateFixture, store *media.Store, now func() time.Time) *gatePorts {
	return &gatePorts{
		fixture: fixture, store: store, now: now,
		evidence:        make(map[string]inspectionruntime.ExistingEvidenceResult),
		evidenceResults: make(map[string]int), alternateEvidence: make(map[string]media.Descriptor),
		analysis: make(map[string]inspectionruntime.AnalysisReference),
	}
}

func (p *gatePorts) Ports() inspectionruntime.Ports {
	return inspectionruntime.Ports{
		Sources: p, Existing: gateExistingPort{owner: p}, Acquisition: p,
		Transform: p, Analysis: gateAnalyzerPort{owner: p}, Cleanup: p,
	}
}

func (p *gatePorts) Stats() gatePortStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := p.stats
	stats.AcquisitionOperations = append([]inspection.StepKind(nil), p.stats.AcquisitionOperations...)
	stats.AnalysisRequests = make([]inspectionruntime.AnalyzeRequest, len(p.stats.AnalysisRequests))
	for index, request := range p.stats.AnalysisRequests {
		stats.AnalysisRequests[index] = cloneGateAnalyzeRequest(request)
	}
	stats.TransformResults = append([]media.Descriptor(nil), p.stats.TransformResults...)
	stats.CVSelectedMedia = make([][]string, len(p.stats.CVSelectedMedia))
	for index := range p.stats.CVSelectedMedia {
		stats.CVSelectedMedia[index] = append([]string(nil), p.stats.CVSelectedMedia[index]...)
	}
	return stats
}

func (p *gatePorts) Resolve(ctx context.Context, request inspectionruntime.ResolveSourceRequest) (inspectionruntime.ResolvedSourceSet, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	p.mu.Lock()
	p.stats.ResolveCalls++
	p.mu.Unlock()
	target := p.fixture.Assignment.Targets[0]
	if request.TenantID != gateTenantID || request.SiteID != gateSiteID || request.TargetID != gateTargetID ||
		!gateEqualSources(request.Sources, target.SourceBindings) || !gateEqualInstalledTasks(request.InstalledTasks, target.InstalledTasks) {
		return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
	}
	if p.catalog != nil {
		for _, task := range request.InstalledTasks {
			if err := p.catalog.ValidateInstalledTask(ctx, request.TenantID, request.SiteID, task); err != nil {
				return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
			}
		}
	}
	return inspectionruntime.ResolvedSourceSet{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResolutionRef:  gateOpaqueRef("resolution", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		AdapterVersion: "gate-resolver-v2",
	}, nil
}

func (p *gatePorts) readExisting(ctx context.Context, request inspectionruntime.ExistingEvidenceRequest) (inspectionruntime.ExistingEvidenceResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	p.mu.Lock()
	p.stats.ExistingCalls++
	p.mu.Unlock()
	target := p.fixture.Assignment.Targets[0]
	if request.TenantID != gateTenantID || request.SiteID != gateSiteID || request.TargetID != gateTargetID ||
		len(target.InstalledTasks) != 1 || !reflect.DeepEqual(request.InstalledTask, target.InstalledTasks[0]) ||
		len(target.SourceBindings) == 0 || !gateContainsSource(target.SourceBindings, request.Source) ||
		!reflect.DeepEqual(request.CapabilityRefs, request.Source.CapabilityRefs) || request.ResolutionRef == "" {
		return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrBindingStale
	}
	observedAt := p.now().UTC()
	evidenceKind := media.KindEvent
	if p.wrongExistingMediaKind {
		evidenceKind = media.KindDetection
	}
	descriptor, err := p.store.Put(ctx, media.PutRequest{
		Kind: evidenceKind,
		Binding: media.Binding{
			TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
			RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		},
		Encoding:   media.Encoding{MIMEType: "application/json"},
		Temporal:   media.Temporal{WindowStart: &observedAt, WindowEnd: &observedAt, SampleOrdinal: 1},
		Governance: p.governance(),
	}, bytes.NewReader([]byte(`{"classification":"condition_met"}`)))
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	result := inspectionruntime.ExistingEvidenceResult{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		EvidenceRef: gateOpaqueRef("evidence", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Descriptor:  descriptor, Candidate: gateCandidate(descriptor.MediaRef), ObservedAt: observedAt,
		AdapterVersion: "gate-existing-v2",
	}
	var alternate media.Descriptor
	if p.swapEvidenceAfterAnalysis {
		alternate, err = p.store.Put(ctx, media.PutRequest{
			Kind: media.KindEvent,
			Binding: media.Binding{
				TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
				RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			},
			Encoding:   media.Encoding{MIMEType: "application/json"},
			Temporal:   media.Temporal{WindowStart: &observedAt, WindowEnd: &observedAt, SampleOrdinal: 1},
			Governance: p.governance(),
		}, bytes.NewReader([]byte(`{"classification":"substituted_after_analysis"}`)))
		if err != nil {
			return inspectionruntime.ExistingEvidenceResult{}, err
		}
	}
	p.mu.Lock()
	p.evidence[result.EvidenceRef] = cloneGateEvidence(result)
	if alternate.MediaRef != "" {
		p.alternateEvidence[result.EvidenceRef] = alternate
	}
	p.mu.Unlock()
	return result, nil
}

func (p *gatePorts) existingResult(ctx context.Context, evidenceRef string) (inspectionruntime.ExistingEvidenceResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result, ok := p.evidence[evidenceRef]
	if !ok {
		return inspectionruntime.ExistingEvidenceResult{}, errors.New("v2-12 evidence result not found")
	}
	p.evidenceResults[evidenceRef]++
	if p.swapEvidenceAfterAnalysis && p.evidenceResults[evidenceRef] > 1 {
		alternate, exists := p.alternateEvidence[evidenceRef]
		if !exists {
			return inspectionruntime.ExistingEvidenceResult{}, errors.New("v2-12 alternate evidence result not found")
		}
		result.Descriptor = alternate
	}
	return cloneGateEvidence(result), nil
}

func (p *gatePorts) Acquire(ctx context.Context, request inspectionruntime.MediaAcquireRequest) (inspectionruntime.MediaAcquireResult, error) {
	p.mu.Lock()
	p.stats.AcquireCalls++
	p.stats.AcquisitionOperations = append(p.stats.AcquisitionOperations, request.Operation)
	p.mu.Unlock()
	if p.blockAcquire {
		p.enterOnce.Do(func() {
			if p.acquireEntered != nil {
				close(p.acquireEntered)
			}
		})
		<-ctx.Done()
		return inspectionruntime.MediaAcquireResult{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	target := p.fixture.Assignment.Targets[0]
	expectedOperation := inspection.StepOpenMedia
	if request.Source.Kind == inspection.SourceCamera {
		expectedOperation = inspection.StepAcquireMedia
	}
	if request.TenantID != gateTenantID || request.SiteID != gateSiteID || request.TargetID != gateTargetID ||
		request.ResolutionRef == "" || request.Operation != expectedOperation || !gateContainsSource(target.SourceBindings, request.Source) {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
	}
	binding := media.Binding{
		TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
	}
	if request.Source.Kind != inspection.SourceCamera {
		if p.uploadedSourceRef == "" {
			return inspectionruntime.MediaAcquireResult{}, errors.New("v2-12 uploaded media was not seeded before execution")
		}
		descriptor, err := p.store.LeaseForRun(ctx, media.RunLeaseRequest{
			SourceMediaRef: p.uploadedSourceRef, Binding: binding, Governance: p.governance(),
			PolicyRef: "inspection-run-lease-v2",
		})
		if err != nil {
			return inspectionruntime.MediaAcquireResult{}, err
		}
		return inspectionruntime.MediaAcquireResult{Descriptor: descriptor, AdapterVersion: "gate-media-v2"}, nil
	}
	capturedAt := p.now().UTC()
	descriptor, err := p.store.Put(ctx, media.PutRequest{
		Kind: media.KindImage, Binding: binding,
		Encoding:   media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 16, HeightPixels: 12},
		Temporal:   media.Temporal{WindowStart: &capturedAt, WindowEnd: &capturedAt, SampleOrdinal: 1},
		Governance: p.governance(),
	}, bytes.NewReader(NeutralSceneJPEG))
	if err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	return inspectionruntime.MediaAcquireResult{Descriptor: descriptor, AdapterVersion: "gate-media-v2"}, nil
}

func (p *gatePorts) Describe(_ context.Context, mediaRef string) (media.Descriptor, error) {
	return p.store.Describe(mediaRef)
}

func (p *gatePorts) Transform(ctx context.Context, request inspectionruntime.MediaTransformRequest) (inspectionruntime.MediaTransformResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.MediaTransformResult{}, err
	}
	p.mu.Lock()
	p.stats.TransformCalls++
	p.mu.Unlock()
	if request.TenantID != gateTenantID || request.SiteID != gateSiteID || request.TargetID != gateTargetID ||
		request.Input.Kind != media.KindVideoClip || request.Input.Binding.SourceRef != request.SourceRef ||
		request.Acquisition.MaxExtractedFrames != 3 || request.Budget.MaxFrames != 3 {
		return inspectionruntime.MediaTransformResult{}, inspectionruntime.ErrBindingStale
	}
	windowStart := request.Input.Temporal.WindowStart
	if windowStart == nil {
		return inspectionruntime.MediaTransformResult{}, errors.New("v2-12 clip has no capture window")
	}
	members := make([]media.FrameMemberInput, 0, 3)
	for index, offset := range []int64{0, 500, 1000} {
		capturedAt := windowStart.Add(time.Duration(offset) * time.Millisecond)
		child, err := p.store.Put(ctx, media.PutRequest{
			Kind: media.KindImage,
			Binding: media.Binding{
				TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.SourceRef,
				RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			},
			Encoding:   media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: 16, HeightPixels: 12},
			Temporal:   media.Temporal{WindowStart: &capturedAt, WindowEnd: &capturedAt, SampleOrdinal: index + 1},
			Governance: p.governance(),
		}, bytes.NewReader(NeutralSceneJPEG))
		if err != nil {
			return inspectionruntime.MediaTransformResult{}, err
		}
		members = append(members, media.FrameMemberInput{
			MediaRef: child.MediaRef, Ordinal: index, OffsetMillis: offset, TransformPolicyRef: "bounded-frames-v2",
		})
	}
	frameSet, err := p.store.RegisterFrameSet(ctx, media.FrameSetRequest{
		Binding: media.Binding{
			TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.SourceRef,
			RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		},
		Temporal: request.Input.Temporal,
		Lineage: media.Lineage{
			ParentMediaRef: request.Input.MediaRef, TransformPolicyRef: "bounded-frames-v2",
		},
		Governance: p.governance(), Members: members,
	})
	if err != nil {
		return inspectionruntime.MediaTransformResult{}, err
	}
	p.mu.Lock()
	p.stats.TransformResults = append(p.stats.TransformResults, frameSet)
	p.mu.Unlock()
	return inspectionruntime.MediaTransformResult{Descriptor: frameSet, AdapterVersion: "gate-transform-v2"}, nil
}

func (p *gatePorts) analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	p.mu.Lock()
	p.stats.AnalyzeCalls++
	p.stats.AnalysisRequests = append(p.stats.AnalysisRequests, cloneGateAnalyzeRequest(request))
	p.mu.Unlock()
	if request.TenantID != gateTenantID || request.SiteID != gateSiteID || request.TargetID != gateTargetID ||
		request.CriterionID != gateCriterionID || request.Prompt == "" || request.PromptSHA256 == "" {
		return inspectionruntime.AnalysisReference{}, inspectionruntime.ErrBindingStale
	}
	selected := ""
	switch p.fixture.Mode {
	case gateSnapshot, gateUploadedImage:
		if len(request.Inputs) != 1 || request.Inputs[0].Descriptor == nil ||
			request.Inputs[0].Descriptor.Kind != media.KindImage || request.Inputs[0].Evidence != nil {
			return inspectionruntime.AnalysisReference{}, errors.New("snapshot analysis did not receive exactly one typed image")
		}
		selected = request.Inputs[0].Descriptor.MediaRef
	case gateClip:
		if len(request.Inputs) != 1 || request.Inputs[0].Descriptor == nil ||
			request.Inputs[0].Descriptor.Kind != media.KindFrameSet || request.Inputs[0].Evidence != nil {
			return inspectionruntime.AnalysisReference{}, errors.New("clip analysis did not receive exactly one bounded frame set")
		}
		selected = request.Inputs[0].Descriptor.MediaRef
	case gateHybrid:
		if len(request.Inputs) != 2 {
			return inspectionruntime.AnalysisReference{}, errors.New("hybrid analysis did not receive its two declared inputs")
		}
		declared := make(map[string]struct{}, len(request.Inputs))
		evidenceCount, imageCount := 0, 0
		for _, input := range request.Inputs {
			declared[input.ValueRef] = struct{}{}
			if input.Evidence != nil {
				evidenceCount++
			}
			if input.Descriptor != nil && input.Descriptor.Kind == media.KindImage {
				imageCount++
				selected = input.Descriptor.MediaRef
			}
		}
		if evidenceCount != 1 || imageCount != 1 {
			return inspectionruntime.AnalysisReference{}, errors.New("hybrid analysis inputs are not one typed evidence plus one image")
		}
		if _, ok := declared[selected]; !ok {
			return inspectionruntime.AnalysisReference{}, errors.New("hybrid CV selection escaped the declared media inputs")
		}
		p.mu.Lock()
		p.stats.CVSelectionCalls++
		p.stats.VLMFollowupCalls++
		p.stats.CVSelectedMedia = append(p.stats.CVSelectedMedia, []string{selected})
		p.mu.Unlock()
	default:
		return inspectionruntime.AnalysisReference{}, inspectionruntime.ErrUnsupported
	}
	startedAt := p.now().UTC()
	completedAt := p.now().UTC()
	modelVersion := "gate-model-v2"
	if p.invalidModel {
		modelVersion = "https://invalid"
	}
	result := inspectionruntime.AnalysisReference{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: gateOpaqueRef("analysis", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Candidate: gateCandidate(selected), ModelVersion: modelVersion, AdapterVersion: "gate-analyzer-v2",
		StartedAt: startedAt, CompletedAt: completedAt,
	}
	p.mu.Lock()
	p.analysis[result.ResultRef] = cloneGateAnalysis(result)
	p.mu.Unlock()
	return result, nil
}

func (p *gatePorts) analysisResult(ctx context.Context, resultRef string) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result, ok := p.analysis[resultRef]
	if !ok {
		return inspectionruntime.AnalysisReference{}, errors.New("v2-12 analysis result not found")
	}
	return cloneGateAnalysis(result), nil
}

func (p *gatePorts) Cleanup(ctx context.Context, request inspectionruntime.CleanupRequest) (inspectionruntime.CleanupResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	p.mu.Lock()
	p.stats.CleanupCalls++
	p.mu.Unlock()
	if p.cleanupFailure {
		return inspectionruntime.CleanupResult{}, errors.New("v2-12 cleanup fixture failure")
	}
	return inspectionruntime.CleanupResult{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: gateOpaqueRef("cleanup", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Created:   len(request.Inputs), Removed: len(request.Inputs), Pending: 0,
	}, nil
}

func (p *gatePorts) governance() media.Governance {
	return media.Governance{
		PrivacyClass: "internal", RedactionPolicyRef: "generic-redaction-v2",
		RetentionPolicyRef: "gate-retention-v2", Audience: []string{"inspection-gate"},
		ExpiresAt: p.fixture.Request.Deadline.Add(5 * time.Minute),
	}
}

type gateExistingPort struct{ owner *gatePorts }

func (p gateExistingPort) Read(ctx context.Context, request inspectionruntime.ExistingEvidenceRequest) (inspectionruntime.ExistingEvidenceResult, error) {
	return p.owner.readExisting(ctx, request)
}

func (p gateExistingPort) Result(ctx context.Context, ref string) (inspectionruntime.ExistingEvidenceResult, error) {
	return p.owner.existingResult(ctx, ref)
}

type gateAnalyzerPort struct{ owner *gatePorts }

func (p gateAnalyzerPort) Analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	return p.owner.analyze(ctx, request)
}

func (p gateAnalyzerPort) Result(ctx context.Context, ref string) (inspectionruntime.AnalysisReference, error) {
	return p.owner.analysisResult(ctx, ref)
}

func gateCandidate(mediaRef string) analysiscontract.Candidate {
	score := 0.95
	return analysiscontract.Candidate{
		Assessment: inspection.AssessmentMeetsRule, Observability: inspection.ResultFullyVisible,
		Confidence: &score,
		Value: &inspection.ResultValue{
			Kind:           inspection.ResultClassification,
			Classification: &inspection.ClassificationValue{Label: "condition_met", Score: &score},
		},
		EvidenceRefs: []string{mediaRef}, Limitations: []analysiscontract.Limitation{},
		ReasonCodes: []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionMet},
	}
}

func gateContainsSource(sources []inspection.SourceBinding, expected inspection.SourceBinding) bool {
	for _, source := range sources {
		if reflect.DeepEqual(source, expected) {
			return true
		}
	}
	return false
}

func cloneGateAnalyzeRequest(request inspectionruntime.AnalyzeRequest) inspectionruntime.AnalyzeRequest {
	clone := request
	clone.Output.AllowedAssessments = append([]inspection.Assessment(nil), request.Output.AllowedAssessments...)
	clone.Inputs = make([]inspectionruntime.AnalysisInput, len(request.Inputs))
	for index, input := range request.Inputs {
		clone.Inputs[index] = input
		if input.Descriptor != nil {
			descriptor := *input.Descriptor
			descriptor.Governance.Audience = append([]string(nil), input.Descriptor.Governance.Audience...)
			descriptor.FrameMembers = make([]media.FrameMember, len(input.Descriptor.FrameMembers))
			copy(descriptor.FrameMembers, input.Descriptor.FrameMembers)
			clone.Inputs[index].Descriptor = &descriptor
		}
		if input.Evidence != nil {
			evidence := cloneGateEvidence(*input.Evidence)
			clone.Inputs[index].Evidence = &evidence
		}
	}
	return clone
}

func cloneGateEvidence(result inspectionruntime.ExistingEvidenceResult) inspectionruntime.ExistingEvidenceResult {
	result.Candidate = fixtureCandidateCopy(result.Candidate)
	result.Descriptor.Governance.Audience = append([]string(nil), result.Descriptor.Governance.Audience...)
	members := make([]media.FrameMember, len(result.Descriptor.FrameMembers))
	copy(members, result.Descriptor.FrameMembers)
	result.Descriptor.FrameMembers = members
	return result
}

func gateEqualSources(left, right []inspection.SourceBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !reflect.DeepEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

func gateEqualInstalledTasks(left, right []inspection.InstalledTaskBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !reflect.DeepEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

func cloneGateAnalysis(result inspectionruntime.AnalysisReference) inspectionruntime.AnalysisReference {
	result.Candidate = fixtureCandidateCopy(result.Candidate)
	return result
}
