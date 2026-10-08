package inspectionfixture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

type RuntimeStats struct {
	ResolveCalls      int
	ExistingCalls     int
	AcquireCalls      int
	TransformCalls    int
	AnalyzeCalls      int
	CleanupCalls      int
	DeviceWriteCalls  int
	LastTransform     media.Descriptor
	LastAnalysisInput []media.Kind
	LastEvidenceMedia string
	LastAcquiredMedia string
	LastAcquiredKind  media.Kind
}

type fixturePorts struct {
	config  Config
	assets  assets
	store   *media.Store
	catalog *catalog.Store

	mu         sync.Mutex
	stats      RuntimeStats
	evidence   map[string]inspectionruntime.ExistingEvidenceResult
	analysis   map[string]inspectionruntime.AnalysisReference
	transforms map[string]media.Descriptor
}

func newFixturePorts(config Config, fixtureAssets assets, store *media.Store, catalogStore *catalog.Store) (*fixturePorts, error) {
	if store == nil || catalogStore == nil || fixtureAssets.validate() != nil {
		return nil, errors.New("complete fixture runtime dependencies are required")
	}
	return &fixturePorts{
		config: config, assets: fixtureAssets, store: store, catalog: catalogStore,
		evidence:   make(map[string]inspectionruntime.ExistingEvidenceResult),
		analysis:   make(map[string]inspectionruntime.AnalysisReference),
		transforms: make(map[string]media.Descriptor),
	}, nil
}

func (p *fixturePorts) Ports() inspectionruntime.Ports {
	return inspectionruntime.Ports{
		Sources: p, Existing: fixtureExistingPort{owner: p}, Acquisition: p,
		Transform: p, Analysis: fixtureAnalyzerPort{owner: p}, Cleanup: p,
	}
}

func (p *fixturePorts) Stats() RuntimeStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := p.stats
	result.LastTransform = cloneDescriptor(p.stats.LastTransform)
	result.LastAnalysisInput = append([]media.Kind(nil), p.stats.LastAnalysisInput...)
	return result
}

func (p *fixturePorts) Resolve(ctx context.Context, request inspectionruntime.ResolveSourceRequest) (inspectionruntime.ResolvedSourceSet, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ResolvedSourceSet{}, err
	}
	p.mu.Lock()
	p.stats.ResolveCalls++
	p.mu.Unlock()
	if request.TenantID != p.config.TenantID || request.SiteID != p.config.SiteID || request.TargetID == "" ||
		len(request.Sources) == 0 || len(request.Sources) > 2 {
		return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
	}
	for _, task := range request.InstalledTasks {
		if err := p.catalog.ValidateInstalledTask(ctx, request.TenantID, request.SiteID, task); err != nil {
			return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
		}
	}
	for _, source := range request.Sources {
		if source.SourceHandle != fixtureSourceID {
			return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
		}
		switch source.Kind {
		case inspection.SourceCamera:
			current, err := p.catalog.Binding(ctx, request.TenantID, request.SiteID, source.SourceHandle, source.CapabilityRefs, source.ROIRef)
			if err != nil || !reflect.DeepEqual(current, source) {
				return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
			}
		case inspection.SourceTaskEvidence:
			matched := false
			for _, task := range request.InstalledTasks {
				for _, frozen := range task.TaskEvidenceSourceBindings() {
					matched = matched || reflect.DeepEqual(frozen, source)
				}
			}
			if !matched {
				return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrBindingStale
			}
		default:
			return inspectionruntime.ResolvedSourceSet{}, inspectionruntime.ErrUnsupported
		}
	}
	return inspectionruntime.ResolvedSourceSet{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResolutionRef:  deterministicRef("resolution", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		AdapterVersion: "offline-fixture-resolver-v1",
	}, nil
}

func (p *fixturePorts) readExisting(ctx context.Context, request inspectionruntime.ExistingEvidenceRequest) (inspectionruntime.ExistingEvidenceResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	p.mu.Lock()
	p.stats.ExistingCalls++
	p.mu.Unlock()
	if request.TenantID != p.config.TenantID || request.SiteID != p.config.SiteID || request.Source.Kind != inspection.SourceTaskEvidence ||
		request.Source.SourceHandle != fixtureSourceID || request.ResolutionRef == "" ||
		!reflect.DeepEqual(request.CapabilityRefs, request.Source.CapabilityRefs) ||
		p.catalog.ValidateInstalledTask(ctx, request.TenantID, request.SiteID, request.InstalledTask) != nil {
		return inspectionruntime.ExistingEvidenceResult{}, inspectionruntime.ErrBindingStale
	}
	observedAt := time.Now().UTC()
	descriptor, err := p.store.Put(ctx, media.PutRequest{
		Kind: media.KindEvent,
		Binding: media.Binding{
			TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
			RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		},
		Encoding:   media.Encoding{MIMEType: "application/json", Container: "json", Codec: "json"},
		Temporal:   media.Temporal{WindowStart: timePointer(observedAt), WindowEnd: timePointer(observedAt), SampleOrdinal: 1},
		Governance: fixtureGovernance(observedAt, 3600),
	}, bytes.NewReader(p.assets.event))
	if err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	result := inspectionruntime.ExistingEvidenceResult{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		EvidenceRef: deterministicRef("evidence", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Descriptor:  descriptor, Candidate: fixtureCandidate(descriptor.MediaRef), ObservedAt: observedAt,
		AdapterVersion: "offline-fixture-existing-v1",
	}
	p.mu.Lock()
	p.evidence[result.EvidenceRef] = cloneEvidence(result)
	p.stats.LastEvidenceMedia = descriptor.MediaRef
	p.mu.Unlock()
	return result, nil
}

func (p *fixturePorts) existingResult(ctx context.Context, ref string) (inspectionruntime.ExistingEvidenceResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.ExistingEvidenceResult{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result, ok := p.evidence[ref]
	if !ok {
		return inspectionruntime.ExistingEvidenceResult{}, errors.New("fixture evidence reference was not found")
	}
	return cloneEvidence(result), nil
}

func (p *fixturePorts) Acquire(ctx context.Context, request inspectionruntime.MediaAcquireRequest) (inspectionruntime.MediaAcquireResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	p.mu.Lock()
	p.stats.AcquireCalls++
	p.mu.Unlock()
	if request.Operation != inspection.StepAcquireMedia || request.TenantID != p.config.TenantID || request.SiteID != p.config.SiteID ||
		request.Source.Kind != inspection.SourceCamera || request.Source.SourceHandle != fixtureSourceID || request.ResolutionRef == "" {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrBindingStale
	}
	kind := media.KindImage
	encoding := media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: p.assets.snapshotWidth, HeightPixels: p.assets.snapshotHeight}
	content := p.assets.snapshot
	capturedAt := time.Now().UTC()
	if capturedAt.After(request.Deadline) {
		return inspectionruntime.MediaAcquireResult{}, errors.New("fixture media acquisition exceeded its frozen deadline")
	}
	temporal := media.Temporal{WindowStart: timePointer(capturedAt), WindowEnd: timePointer(capturedAt), SampleOrdinal: 1}
	if containsString(request.Source.CapabilityRefs, capabilityClip) {
		kind = media.KindVideoClip
		encoding = media.Encoding{MIMEType: "video/mp4", Container: "mp4", Codec: "h264", WidthPixels: p.assets.clipWidth, HeightPixels: p.assets.clipHeight, FrameRate: p.assets.clipFrameRate}
		content = p.assets.clip
		if int64(request.Acquisition.ClipDurationMillis) != p.assets.clipDuration {
			return inspectionruntime.MediaAcquireResult{}, errors.New("fixture clip request does not match the prepared media duration")
		}
		windowStart := capturedAt.Add(-time.Duration(p.assets.clipDuration) * time.Millisecond)
		temporal = media.Temporal{
			WindowStart: timePointer(windowStart), WindowEnd: timePointer(capturedAt),
			DurationMillis: p.assets.clipDuration, SampleOrdinal: 1,
		}
	} else if !containsString(request.Source.CapabilityRefs, capabilitySnapshot) {
		return inspectionruntime.MediaAcquireResult{}, inspectionruntime.ErrUnsupported
	}
	contentSHA := digestBytes(content)
	descriptor, _, err := p.store.PutIdempotent(ctx, media.IdempotentPutRequest{
		IdempotencyKey: "media_put_" + digest(request.IdempotencyKey),
		Media: media.PutRequest{
			Kind: kind,
			Binding: media.Binding{
				TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.Source.SourceHandle,
				RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			},
			Encoding: encoding, Temporal: temporal,
			Governance:     fixtureGovernance(capturedAt, request.Evidence.RetentionSeconds),
			ExpectedSHA256: contentSHA,
		},
	}, bytes.NewReader(content))
	if err != nil {
		return inspectionruntime.MediaAcquireResult{}, err
	}
	p.mu.Lock()
	p.stats.LastAcquiredMedia = descriptor.MediaRef
	p.stats.LastAcquiredKind = descriptor.Kind
	p.mu.Unlock()
	return inspectionruntime.MediaAcquireResult{Descriptor: descriptor, AdapterVersion: "offline-fixture-media-v1"}, nil
}

func (p *fixturePorts) Describe(_ context.Context, mediaRef string) (media.Descriptor, error) {
	return p.store.Describe(mediaRef)
}

func (p *fixturePorts) Transform(ctx context.Context, request inspectionruntime.MediaTransformRequest) (inspectionruntime.MediaTransformResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.MediaTransformResult{}, err
	}
	p.mu.Lock()
	p.stats.TransformCalls++
	if existing, ok := p.transforms[request.IdempotencyKey]; ok {
		p.mu.Unlock()
		return inspectionruntime.MediaTransformResult{Descriptor: cloneDescriptor(existing), AdapterVersion: "offline-fixture-transform-v1"}, nil
	}
	p.mu.Unlock()
	if request.TenantID != p.config.TenantID || request.SiteID != p.config.SiteID || request.SourceRef != fixtureSourceID ||
		request.Input.Kind != media.KindVideoClip || request.Input.Binding.SourceRef != request.SourceRef ||
		request.Acquisition.MaxExtractedFrames < 1 || request.Acquisition.MaxExtractedFrames > 3 || request.Budget.MaxFrames < request.Acquisition.MaxExtractedFrames {
		return inspectionruntime.MediaTransformResult{}, inspectionruntime.ErrBindingStale
	}
	if request.Input.Temporal.WindowStart == nil || request.Input.Temporal.WindowEnd == nil {
		return inspectionruntime.MediaTransformResult{}, errors.New("fixture clip has no bounded capture window")
	}
	frameCount := request.Acquisition.MaxExtractedFrames
	if frameCount != 1 {
		return inspectionruntime.MediaTransformResult{}, errors.New("fixture clip has exactly one manifest-bound decoded frame")
	}
	members := make([]media.FrameMemberInput, 0, frameCount)
	for index := 0; index < frameCount; index++ {
		offset := p.assets.clipFrameOffset
		capturedAt := request.Input.Temporal.WindowStart.Add(time.Duration(offset) * time.Millisecond)
		put := media.PutRequest{
			Kind: media.KindImage,
			Binding: media.Binding{
				TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.SourceRef,
				RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
			},
			Encoding:   media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: p.assets.clipWidth, HeightPixels: p.assets.clipHeight},
			Temporal:   media.Temporal{WindowStart: timePointer(capturedAt), WindowEnd: timePointer(capturedAt), SampleOrdinal: index + 1},
			Governance: cloneGovernance(request.Input.Governance), ExpectedSHA256: digestBytes(p.assets.clipFrame),
		}
		// Frame-set registration transfers lifecycle ownership by rewriting the
		// child lineage. Such a child cannot be backed by an immutable
		// idempotent-put record, whose request digest deliberately freezes the
		// original descriptor. The transform operation itself owns replay.
		child, err := p.store.Put(ctx, put, bytes.NewReader(p.assets.clipFrame))
		if err != nil {
			return inspectionruntime.MediaTransformResult{}, err
		}
		members = append(members, media.FrameMemberInput{
			MediaRef: child.MediaRef, Ordinal: index, OffsetMillis: offset, TransformPolicyRef: "offline-bounded-frames-v1",
		})
	}
	frameSet, err := p.store.RegisterFrameSet(ctx, media.FrameSetRequest{
		Binding: media.Binding{
			TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.SourceRef,
			RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		},
		Temporal:   request.Input.Temporal,
		Lineage:    media.Lineage{ParentMediaRef: request.Input.MediaRef, TransformPolicyRef: "offline-bounded-frames-v1"},
		Governance: cloneGovernance(request.Input.Governance), Members: members,
	})
	if err != nil {
		return inspectionruntime.MediaTransformResult{}, err
	}
	p.mu.Lock()
	p.transforms[request.IdempotencyKey] = cloneDescriptor(frameSet)
	p.stats.LastTransform = cloneDescriptor(frameSet)
	p.mu.Unlock()
	return inspectionruntime.MediaTransformResult{Descriptor: frameSet, AdapterVersion: "offline-fixture-transform-v1"}, nil
}

func (p *fixturePorts) analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	if request.TenantID != p.config.TenantID || request.SiteID != p.config.SiteID || request.CriterionID != fixtureCriterionID ||
		request.Prompt == "" || request.PromptSHA256 == "" || len(request.Inputs) == 0 || len(request.Inputs) > 2 {
		return inspectionruntime.AnalysisReference{}, inspectionruntime.ErrBindingStale
	}
	kinds := make([]media.Kind, 0, len(request.Inputs))
	evidenceRef := ""
	evidenceCount := 0
	for _, input := range request.Inputs {
		if input.Descriptor != nil {
			if input.Descriptor.MediaRef != input.ValueRef || input.Descriptor.Integrity.SHA256 != input.SHA256 {
				return inspectionruntime.AnalysisReference{}, errors.New("fixture analyzer received an unbound media input")
			}
			kinds = append(kinds, input.Descriptor.Kind)
			if input.Descriptor.Kind == media.KindImage {
				evidenceRef = input.Descriptor.MediaRef
			} else if evidenceRef == "" {
				evidenceRef = input.Descriptor.MediaRef
			}
		}
		if input.Evidence != nil {
			evidenceCount++
			kinds = append(kinds, input.Evidence.Descriptor.Kind)
		}
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	validShape := len(kinds) == 1 && (kinds[0] == media.KindImage || kinds[0] == media.KindFrameSet) ||
		len(kinds) == 2 && evidenceCount == 1 && kinds[0] == media.KindEvent && kinds[1] == media.KindImage
	if !validShape || evidenceRef == "" {
		return inspectionruntime.AnalysisReference{}, errors.New("fixture analyzer received an unsupported typed input set")
	}
	startedAt := time.Now().UTC()
	result := inspectionruntime.AnalysisReference{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: deterministicRef("analysis", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Candidate: fixtureCandidate(evidenceRef), ModelVersion: "offline-fixture-model-v1",
		AdapterVersion: "offline-fixture-analyzer-v1", StartedAt: startedAt, CompletedAt: time.Now().UTC(),
	}
	p.mu.Lock()
	p.stats.AnalyzeCalls++
	p.stats.LastAnalysisInput = append([]media.Kind(nil), kinds...)
	p.analysis[result.ResultRef] = cloneAnalysis(result)
	p.mu.Unlock()
	return result, nil
}

func (p *fixturePorts) analysisResult(ctx context.Context, ref string) (inspectionruntime.AnalysisReference, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.AnalysisReference{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result, ok := p.analysis[ref]
	if !ok {
		return inspectionruntime.AnalysisReference{}, errors.New("fixture analysis reference was not found")
	}
	return cloneAnalysis(result), nil
}

func (p *fixturePorts) Cleanup(ctx context.Context, request inspectionruntime.CleanupRequest) (inspectionruntime.CleanupResult, error) {
	if err := ctx.Err(); err != nil {
		return inspectionruntime.CleanupResult{}, err
	}
	p.mu.Lock()
	p.stats.CleanupCalls++
	for ref, value := range p.evidence {
		if value.RunID == request.RunID {
			delete(p.evidence, ref)
		}
	}
	for ref, value := range p.analysis {
		if value.RunID == request.RunID {
			delete(p.analysis, ref)
		}
	}
	for key, value := range p.transforms {
		if value.Binding.RunID == request.RunID {
			delete(p.transforms, key)
		}
	}
	p.mu.Unlock()
	return inspectionruntime.CleanupResult{
		RunID: request.RunID, StepID: request.StepID, Attempt: request.Attempt,
		ResultRef: deterministicRef("cleanup", request.RunID, request.StepID, fmt.Sprint(request.Attempt)),
		Created:   len(request.Inputs), Removed: len(request.Inputs), Pending: 0,
	}, nil
}

type fixtureExistingPort struct{ owner *fixturePorts }

func (p fixtureExistingPort) Read(ctx context.Context, request inspectionruntime.ExistingEvidenceRequest) (inspectionruntime.ExistingEvidenceResult, error) {
	return p.owner.readExisting(ctx, request)
}
func (p fixtureExistingPort) Result(ctx context.Context, ref string) (inspectionruntime.ExistingEvidenceResult, error) {
	return p.owner.existingResult(ctx, ref)
}

type fixtureAnalyzerPort struct{ owner *fixturePorts }

func (p fixtureAnalyzerPort) Analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	return p.owner.analyze(ctx, request)
}
func (p fixtureAnalyzerPort) Result(ctx context.Context, ref string) (inspectionruntime.AnalysisReference, error) {
	return p.owner.analysisResult(ctx, ref)
}

func fixtureCandidate(evidenceRef string) analysiscontract.Candidate {
	score := 0.9
	return analysiscontract.Candidate{
		Assessment: inspection.AssessmentNeedsAttention, Observability: inspection.ResultFullyVisible,
		Confidence: &score,
		Value: &inspection.ResultValue{
			Kind:           inspection.ResultClassification,
			Classification: &inspection.ClassificationValue{Label: "attention", Score: &score},
		},
		EvidenceRefs: []string{evidenceRef}, Limitations: []analysiscontract.Limitation{},
		ReasonCodes: []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionViolated},
	}
}

func fixtureGovernance(observedAt time.Time, retentionSeconds int) media.Governance {
	if retentionSeconds < 60 {
		retentionSeconds = 60
	}
	return media.Governance{
		PrivacyClass: "internal", RedactionPolicyRef: "offline-default-redaction",
		RetentionPolicyRef: "offline-fixture-retention", Audience: []string{MediaAudience},
		ExpiresAt: observedAt.UTC().Add(time.Duration(retentionSeconds) * time.Second),
	}
}

func deterministicRef(prefix string, values ...string) string {
	joined := prefix
	for _, value := range values {
		joined += "\x00" + value
	}
	return prefix + "_" + digest(joined)[:32]
}

func digestBytes(value []byte) string { return digest(string(value)) }

func timePointer(value time.Time) *time.Time {
	canonical := value.UTC()
	return &canonical
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func cloneGovernance(value media.Governance) media.Governance {
	value.Audience = append([]string(nil), value.Audience...)
	return value
}

func cloneDescriptor(value media.Descriptor) media.Descriptor {
	value.Governance = cloneGovernance(value.Governance)
	if value.FrameMembers != nil {
		value.FrameMembers = append([]media.FrameMember{}, value.FrameMembers...)
	}
	return value
}

func cloneEvidence(value inspectionruntime.ExistingEvidenceResult) inspectionruntime.ExistingEvidenceResult {
	value.Descriptor = cloneDescriptor(value.Descriptor)
	value.Candidate = cloneCandidate(value.Candidate)
	return value
}

func cloneAnalysis(value inspectionruntime.AnalysisReference) inspectionruntime.AnalysisReference {
	value.Candidate = cloneCandidate(value.Candidate)
	return value
}

func cloneCandidate(value analysiscontract.Candidate) analysiscontract.Candidate {
	result := value
	if value.Confidence != nil {
		confidence := *value.Confidence
		result.Confidence = &confidence
	}
	if value.Value != nil {
		cloned := *value.Value
		if value.Value.Classification != nil {
			classification := *value.Value.Classification
			if classification.Score != nil {
				score := *classification.Score
				classification.Score = &score
			}
			cloned.Classification = &classification
		}
		result.Value = &cloned
	}
	if value.EvidenceRefs != nil {
		result.EvidenceRefs = append([]string{}, value.EvidenceRefs...)
	}
	if value.Limitations != nil {
		// The formal contract distinguishes an explicitly empty limitation
		// set from a missing model field, so preserve a non-nil empty slice
		// across the in-memory result-reference boundary.
		result.Limitations = append([]analysiscontract.Limitation{}, value.Limitations...)
	}
	if value.ReasonCodes != nil {
		result.ReasonCodes = append([]analysiscontract.ReasonCode{}, value.ReasonCodes...)
	}
	return result
}

var (
	_ inspectionruntime.SourceResolver           = (*fixturePorts)(nil)
	_ inspectionruntime.MediaAcquirer            = (*fixturePorts)(nil)
	_ inspectionruntime.MediaTransformer         = (*fixturePorts)(nil)
	_ inspectionruntime.TemporaryResourceCleaner = (*fixturePorts)(nil)
	_ inspectionruntime.ExistingEvidenceReader   = fixtureExistingPort{}
	_ inspectionruntime.Analyzer                 = fixtureAnalyzerPort{}
)
