package inspectionadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

const (
	testTenant  = "tenant-live"
	testSite    = "site-live"
	testProfile = "profile-live"
	testSource  = "camera-dining-east"
)

func TestLiveVerticalSliceReplaysDurableResultsAndKeepsCleanupPending(t *testing.T) {
	t.Parallel()
	adapter, client, source, now := newTestAdapter(t)
	ctx := context.Background()
	deadline := now.Add(10 * time.Minute)
	resolveRequest := inspectionruntime.ResolveSourceRequest{
		RunID: "run-live-1", StepID: "step-resolve", TenantID: testTenant, SiteID: testSite,
		TargetID: "target-east", Sources: []inspection.SourceBinding{source}, Attempt: 1,
		Deadline: deadline, Budget: inspection.StepBudget{MaxDurationSeconds: 60, MaxAttempts: 3},
	}
	resolved, err := adapter.Resolve(ctx, resolveRequest)
	if err != nil {
		t.Fatalf("resolve live source: %v", err)
	}
	if resolved.ResolutionRef == "" || client.resolveCalls != 1 {
		t.Fatalf("unexpected resolution: %#v calls=%d", resolved, client.resolveCalls)
	}
	if replay, err := adapter.Resolve(ctx, resolveRequest); err != nil || !reflect.DeepEqual(replay, resolved) || client.resolveCalls != 1 {
		t.Fatalf("resolution replay reached device or changed: %#v err=%v calls=%d", replay, err, client.resolveCalls)
	}

	acquireRequest := inspectionruntime.MediaAcquireRequest{
		Operation: inspection.StepAcquireMedia, RunID: resolveRequest.RunID, StepID: "step-capture",
		TenantID: testTenant, SiteID: testSite, TargetID: resolveRequest.TargetID,
		ResolutionRef: resolved.ResolutionRef, Source: source,
		Acquisition: inspection.AcquisitionPolicy{Samples: 1},
		Evidence:    inspection.EvidencePolicy{Required: true, RetentionSeconds: 600, RedactionProfile: "redaction-default"},
		Attempt:     1, IdempotencyKey: "attempt-capture-1", Deadline: deadline,
		Budget: inspection.StepBudget{MaxFrames: 1, MaxBytes: 1 << 20, MaxDurationSeconds: 60, MaxAttempts: 2},
	}
	acquired, err := adapter.Acquire(ctx, acquireRequest)
	if err != nil {
		t.Fatalf("capture live snapshot: %v", err)
	}
	if acquired.Descriptor.Kind != media.KindImage || acquired.Descriptor.Integrity.SHA256 != contentSHA256(client.snapshot) ||
		acquired.Descriptor.Encoding.WidthPixels != 12 || acquired.Descriptor.Encoding.HeightPixels != 8 || client.captureCalls != 1 {
		t.Fatalf("unexpected captured media: %#v calls=%d", acquired.Descriptor, client.captureCalls)
	}
	if replay, err := adapter.Acquire(ctx, acquireRequest); err != nil || !reflect.DeepEqual(replay, acquired) || client.captureCalls != 1 {
		t.Fatalf("capture replay reached device or changed: %#v err=%v calls=%d", replay, err, client.captureCalls)
	}

	prompt := "判断就餐区地面是否有需要处理的明显残留"
	analyzeRequest := inspectionruntime.AnalyzeRequest{
		RunID: resolveRequest.RunID, StepID: "step-analyze", TenantID: testTenant, SiteID: testSite,
		TargetID: resolveRequest.TargetID, CriterionID: "criterion-hygiene", Attempt: 1,
		Method: inspection.MethodVLM, AnalysisPolicyRef: "vlm-picture-policy-v1",
		Prompt: prompt, PromptSHA256: contentSHA256([]byte(prompt)),
		Output: inspection.OutputContract{
			Mode:               inspection.ResultClassification,
			AllowedAssessments: []inspection.Assessment{inspection.AssessmentNeedsAttention},
			SchemaVersion:      "finding-v1",
		},
		Inputs: []inspectionruntime.AnalysisInput{{
			ProducerStepID: acquireRequest.StepID, ProducerKind: inspection.StepAcquireMedia, Attempt: 1,
			ValueRef: acquired.Descriptor.MediaRef, SHA256: acquired.Descriptor.Integrity.SHA256,
			Descriptor: &acquired.Descriptor,
		}},
		IdempotencyKey: "attempt-analysis-1", Deadline: deadline,
		Budget: inspection.StepBudget{MaxFrames: 1, MaxBytes: 1 << 20, MaxDurationSeconds: 60, MaxAttempts: 2},
	}
	analysis, err := adapter.analyze(ctx, analyzeRequest)
	if err != nil {
		t.Fatalf("analyze live snapshot: %v", err)
	}
	if !reflect.DeepEqual(analysis.Candidate.EvidenceRefs, []string{acquired.Descriptor.MediaRef}) || client.analysisCalls != 1 {
		t.Fatalf("adapter did not bind analysis evidence: %#v calls=%d", analysis, client.analysisCalls)
	}
	if replay, err := adapter.analyze(ctx, analyzeRequest); err != nil || !reflect.DeepEqual(replay, analysis) || client.analysisCalls != 1 {
		t.Fatalf("analysis replay reached device or changed: %#v err=%v calls=%d", replay, err, client.analysisCalls)
	}
	if stored, err := adapter.analysisResult(ctx, analysis.ResultRef); err != nil || !reflect.DeepEqual(stored, analysis) {
		t.Fatalf("durable analysis lookup mismatch: %#v err=%v", stored, err)
	}

	cleanupRequest := inspectionruntime.CleanupRequest{
		RunID: resolveRequest.RunID, StepID: "step-cleanup", TenantID: testTenant, SiteID: testSite, Attempt: 1,
		Inputs: []inspectionruntime.ValueReference{
			{LogicalRef: "media", ProducerStepID: acquireRequest.StepID, Attempt: 1, ValueRef: acquired.Descriptor.MediaRef, SHA256: acquired.Descriptor.Integrity.SHA256, ProducerKind: inspection.StepAcquireMedia},
			{LogicalRef: "analysis", ProducerStepID: analyzeRequest.StepID, Attempt: 1, ValueRef: analysis.ResultRef, SHA256: strings.Repeat("c", 64), ProducerKind: inspection.StepAnalyze},
		},
		Deadline: deadline, Budget: inspection.StepBudget{MaxDurationSeconds: 60, MaxAttempts: 3},
	}
	cleaned, err := adapter.Cleanup(ctx, cleanupRequest)
	if err != nil {
		t.Fatalf("reconcile live cleanup: %v", err)
	}
	if cleaned.Created != 2 || cleaned.Removed != 0 || cleaned.Pending != 2 || client.cleanupCalls != 1 {
		t.Fatalf("cleanup overstated device proof: %#v calls=%d", cleaned, client.cleanupCalls)
	}
	if replay, err := adapter.Cleanup(ctx, cleanupRequest); err != nil || !reflect.DeepEqual(replay, cleaned) || client.cleanupCalls != 1 {
		t.Fatalf("cleanup replay reached device or changed: %#v err=%v calls=%d", replay, err, client.cleanupCalls)
	}
}

func TestUnfreshSnapshotsFailClosed(t *testing.T) {
	for _, freshness := range []SnapshotFreshness{SnapshotCached, SnapshotUnverifiable} {
		freshness := freshness
		t.Run(string(freshness), func(t *testing.T) {
			t.Parallel()
			adapter, client, source, now := newTestAdapter(t)
			client.freshness = freshness
			ctx := context.Background()
			resolved, err := adapter.Resolve(ctx, inspectionruntime.ResolveSourceRequest{
				RunID: "run-unfresh-" + string(freshness), StepID: "step-resolve", TenantID: testTenant, SiteID: testSite,
				TargetID: "target-east", Sources: []inspection.SourceBinding{source}, Attempt: 1,
				Deadline: now.Add(time.Minute), Budget: inspection.StepBudget{MaxAttempts: 3},
			})
			if err != nil {
				t.Fatalf("resolve source: %v", err)
			}
			_, err = adapter.Acquire(ctx, inspectionruntime.MediaAcquireRequest{
				Operation: inspection.StepAcquireMedia, RunID: "run-unfresh-" + string(freshness), StepID: "step-capture",
				TenantID: testTenant, SiteID: testSite, TargetID: "target-east", ResolutionRef: resolved.ResolutionRef,
				Source: source, Acquisition: inspection.AcquisitionPolicy{Samples: 1},
				Evidence: inspection.EvidencePolicy{Required: true, RetentionSeconds: 600}, Attempt: 1,
				IdempotencyKey: "attempt-" + string(freshness), Deadline: now.Add(time.Minute),
				Budget: inspection.StepBudget{MaxFrames: 1, MaxBytes: 1 << 20, MaxAttempts: 2},
			})
			if !errors.Is(err, inspectionruntime.ErrOutcomeUnknown) {
				t.Fatalf("%s snapshot must be outcome_unknown, got %v", freshness, err)
			}
		})
	}
}

func TestBindingDriftStopsBeforeCapture(t *testing.T) {
	t.Parallel()
	adapter, client, source, now := newTestAdapter(t)
	ctx := context.Background()
	resolved, err := adapter.Resolve(ctx, inspectionruntime.ResolveSourceRequest{
		RunID: "run-drift", StepID: "step-resolve", TenantID: testTenant, SiteID: testSite,
		TargetID: "target-east", Sources: []inspection.SourceBinding{source}, Attempt: 1,
		Deadline: now.Add(time.Minute), Budget: inspection.StepBudget{MaxAttempts: 3},
	})
	if err != nil {
		t.Fatalf("resolve source: %v", err)
	}
	current, err := adapter.catalog.Get(ctx, testTenant, testSite, testSource)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if _, err := adapter.catalog.Update(ctx, catalog.UpdateSource{
		TenantID: testTenant, SiteID: testSite, Handle: testSource, ExpectedRevision: current.Revision,
		IdentityFingerprint: strings.Repeat("d", 64),
	}); !errors.Is(err, catalog.ErrIdentityDrift) {
		t.Fatalf("record identity drift: %v", err)
	}
	_, err = adapter.Acquire(ctx, inspectionruntime.MediaAcquireRequest{
		Operation: inspection.StepAcquireMedia, RunID: "run-drift", StepID: "step-capture",
		TenantID: testTenant, SiteID: testSite, TargetID: "target-east", ResolutionRef: resolved.ResolutionRef,
		Source: source, Acquisition: inspection.AcquisitionPolicy{Samples: 1},
		Evidence: inspection.EvidencePolicy{Required: true, RetentionSeconds: 600}, Attempt: 1,
		IdempotencyKey: "attempt-drift", Deadline: now.Add(time.Minute),
		Budget: inspection.StepBudget{MaxFrames: 1, MaxBytes: 1 << 20, MaxAttempts: 2},
	})
	if !errors.Is(err, inspectionruntime.ErrBindingStale) || client.captureCalls != 0 {
		t.Fatalf("drifted source reached device: err=%v captureCalls=%d", err, client.captureCalls)
	}
}

func TestSynchronousAnalysisUnknownIsNotPublished(t *testing.T) {
	t.Parallel()
	adapter, client, source, now := newTestAdapter(t)
	ctx := context.Background()
	deadline := now.Add(time.Minute)
	resolved, err := adapter.Resolve(ctx, inspectionruntime.ResolveSourceRequest{
		RunID: "run-analysis-unknown", StepID: "step-resolve", TenantID: testTenant, SiteID: testSite,
		TargetID: "target-east", Sources: []inspection.SourceBinding{source}, Attempt: 1,
		Deadline: deadline, Budget: inspection.StepBudget{MaxAttempts: 3},
	})
	if err != nil {
		t.Fatalf("resolve source: %v", err)
	}
	acquired, err := adapter.Acquire(ctx, inspectionruntime.MediaAcquireRequest{
		Operation: inspection.StepAcquireMedia, RunID: "run-analysis-unknown", StepID: "step-capture",
		TenantID: testTenant, SiteID: testSite, TargetID: "target-east", ResolutionRef: resolved.ResolutionRef,
		Source: source, Acquisition: inspection.AcquisitionPolicy{Samples: 1},
		Evidence: inspection.EvidencePolicy{Required: true, RetentionSeconds: 600}, Attempt: 1,
		IdempotencyKey: "attempt-analysis-unknown-capture", Deadline: deadline,
		Budget: inspection.StepBudget{MaxFrames: 1, MaxBytes: 1 << 20, MaxAttempts: 2},
	})
	if err != nil {
		t.Fatalf("capture source: %v", err)
	}
	client.analysisErr = ErrOutcomeUnknown
	prompt := "判断现场是否需要关注"
	request := inspectionruntime.AnalyzeRequest{
		RunID: "run-analysis-unknown", StepID: "step-analyze", TenantID: testTenant, SiteID: testSite,
		TargetID: "target-east", CriterionID: "criterion-status", Attempt: 1,
		Method: inspection.MethodVLM, AnalysisPolicyRef: "vlm-picture-policy-v1",
		Prompt: prompt, PromptSHA256: contentSHA256([]byte(prompt)),
		Output: inspection.OutputContract{Mode: inspection.ResultClassification,
			AllowedAssessments: []inspection.Assessment{inspection.AssessmentNeedsAttention}, SchemaVersion: "finding-v1"},
		Inputs: []inspectionruntime.AnalysisInput{{
			ProducerStepID: "step-capture", ProducerKind: inspection.StepAcquireMedia, Attempt: 1,
			ValueRef: acquired.Descriptor.MediaRef, SHA256: acquired.Descriptor.Integrity.SHA256, Descriptor: &acquired.Descriptor,
		}},
		IdempotencyKey: "attempt-analysis-unknown", Deadline: deadline,
		Budget: inspection.StepBudget{MaxFrames: 1, MaxBytes: 1 << 20, MaxAttempts: 2},
	}
	_, err = adapter.analyze(ctx, request)
	if !errors.Is(err, inspectionruntime.ErrOutcomeUnknown) {
		t.Fatalf("ambiguous synchronous analysis must be outcome_unknown, got %v", err)
	}
	requestSHA, digestErr := analysisRequestDigest(request)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	if _, err := adapter.records.Analysis(ctx, deterministicRef("analysis", requestSHA)); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("ambiguous analysis was published: %v", err)
	}
}

func TestSQLiteRecordsSurviveRestartAndPreservePendingCleanup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "adapter-records.sqlite")
	store, err := OpenSQLiteRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	resolution := ResolutionRecord{
		ResolutionRef: "resolution_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RequestSHA256: strings.Repeat("a", 64),
		RunID: "run-store", StepID: "step-resolve", Attempt: 1, TenantID: testTenant, SiteID: testSite,
		TargetID: "target-east", DeviceProfileID: testProfile,
		Sources: []inspection.SourceBinding{{
			Kind: inspection.SourceCamera, SourceHandle: testSource, SourceRevision: 1,
			SourceFingerprint: strings.Repeat("b", 64), CapabilityRefs: []string{"snapshot-read"},
			MediaKinds: []inspection.MediaKind{inspection.MediaImage},
		}},
		InstalledTasks: []inspection.InstalledTaskBinding{}, AdapterVersion: DefaultAdapterVersion, ResolvedAt: now,
	}
	if err := store.PutResolution(context.Background(), resolution); err != nil {
		t.Fatalf("persist resolution: %v", err)
	}
	pending := CleanupRecord{
		IdempotencyKey: "cleanup_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RequestSHA256: strings.Repeat("c", 64),
		DeviceProfileID: testProfile, State: CleanupRecordPending,
	}
	if _, existed, err := store.ReserveCleanup(context.Background(), pending); err != nil || existed {
		t.Fatalf("reserve cleanup: existed=%v err=%v", existed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLiteRecords(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if actual, err := store.Resolution(context.Background(), resolution.ResolutionRef); err != nil || !reflect.DeepEqual(actual, resolution) {
		t.Fatalf("resolution did not survive restart: %#v err=%v", actual, err)
	}
	if actual, existed, err := store.ReserveCleanup(context.Background(), pending); err != nil || !existed || !reflect.DeepEqual(actual, pending) {
		t.Fatalf("pending cleanup was not preserved: %#v existed=%v err=%v", actual, existed, err)
	}
}

func TestAnalyzerCannotInjectEvidenceReference(t *testing.T) {
	t.Parallel()
	candidate := validCandidate()
	candidate.EvidenceRefs = []string{"media_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if _, err := bindCandidate(candidate, []int{1}, []media.Descriptor{{MediaRef: "media_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}); err == nil {
		t.Fatal("client-controlled evidence reference was accepted")
	}
}

func TestProtectedLocatorNeverFormatsOrSerializes(t *testing.T) {
	t.Parallel()
	locator := protectedLocator("video-channel-secret")
	for _, value := range []string{fmt.Sprint(locator), fmt.Sprintf("%#v", locator), locator.LogValue().String()} {
		if strings.Contains(value, "video-channel-secret") {
			t.Fatalf("protected locator leaked through formatting: %q", value)
		}
	}
	if _, err := json.Marshal(locator); !errors.Is(err, ErrProtectedValue) {
		t.Fatalf("protected locator JSON projection was not rejected: %v", err)
	}
}

func TestClientErrorMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		client  error
		runtime error
	}{
		{ErrUnavailable, inspectionruntime.ErrWaitingForSite},
		{ErrBindingStale, inspectionruntime.ErrBindingStale},
		{ErrResourceBusy, inspectionruntime.ErrResourceBusy},
		{ErrOutcomeUnknown, inspectionruntime.ErrOutcomeUnknown},
		{ErrUnsupported, inspectionruntime.ErrUnsupported},
		{ErrAuthorityRejected, inspectionruntime.ErrAuthorityRejected},
	}
	for _, test := range tests {
		if actual := mapClientError(test.client); !errors.Is(actual, test.runtime) {
			t.Fatalf("map %v: got %v want %v", test.client, actual, test.runtime)
		}
	}
}

func newTestAdapter(t *testing.T) (*Adapter, *recordingClient, inspection.SourceBinding, time.Time) {
	t.Helper()
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatalf("protect test state root: %v", err)
	}
	catalogStore, err := catalog.Open(filepath.Join(root, "catalog.sqlite"))
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	t.Cleanup(func() { _ = catalogStore.Close() })
	mediaStore, err := media.New(media.Config{Root: filepath.Join(root, "media")})
	if err != nil {
		t.Fatalf("open media store: %v", err)
	}
	records, err := OpenSQLiteRecords(filepath.Join(root, "adapter-records.sqlite"))
	if err != nil {
		t.Fatalf("open durable adapter records: %v", err)
	}
	t.Cleanup(func() { _ = records.Close() })
	fingerprint := strings.Repeat("a", 64)
	source, err := catalogStore.Create(context.Background(), catalog.NewSource{
		TenantID: testTenant, SiteID: testSite, DeviceProfileID: testProfile,
		Handle: testSource, Kind: inspection.SourceCamera, IdentityFingerprint: fingerprint,
		NativeLocator: "video-channel-17", Alias: "东侧就餐区",
		Capabilities: []catalog.Capability{{
			Ref: "snapshot-read", Kind: catalog.CapabilitySnapshot, Revision: 1,
			Constraints: catalog.Constraints{MediaKinds: []inspection.MediaKind{inspection.MediaImage}, MaxBytes: 1 << 20, MaxFrames: 1, MaxFreshnessSeconds: 30},
		}},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	binding, err := source.Binding([]string{"snapshot-read"}, "")
	if err != nil {
		t.Fatalf("freeze source: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	client := &recordingClient{snapshot: testJPEG(t), now: now, freshness: SnapshotFresh}
	adapter, err := New(Config{
		Catalog: catalogStore, Media: mediaStore, Connections: fixedProvider{client: client}, Records: records,
		PrivacyClass: "sensitive", RetentionPolicyRef: "inspection-evidence-v1", Audience: []string{"operator"},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	return adapter, client, binding, now
}

func testJPEG(t *testing.T) []byte {
	t.Helper()
	canvas := image.NewRGBA(image.Rect(0, 0, 12, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 12; x++ {
			canvas.Set(x, y, color.RGBA{R: uint8(20 + x), G: uint8(80 + y), B: 120, A: 255})
		}
	}
	var output bytes.Buffer
	if err := jpeg.Encode(&output, canvas, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return output.Bytes()
}

func validCandidate() analysiscontract.Candidate {
	score := 0.91
	return analysiscontract.Candidate{
		Assessment: inspection.AssessmentNeedsAttention, Observability: inspection.ResultFullyVisible,
		Confidence: &score,
		Value: &inspection.ResultValue{
			Kind:           inspection.ResultClassification,
			Classification: &inspection.ClassificationValue{Label: "attention", Score: &score},
		},
		EvidenceRefs: []string{}, Limitations: []analysiscontract.Limitation{},
		ReasonCodes: []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionViolated},
	}
}

type fixedProvider struct{ client LiveClient }

func (p fixedProvider) LiveClient(_ context.Context, tenantID, siteID, profileID string) (LiveClient, error) {
	if tenantID != testTenant || siteID != testSite || profileID != testProfile {
		return nil, ErrUnavailable
	}
	return p.client, nil
}

type recordingClient struct {
	snapshot    []byte
	now         time.Time
	freshness   SnapshotFreshness
	analysisErr error

	resolveCalls  int
	captureCalls  int
	analysisCalls int
	cleanupCalls  int
}

func (c *recordingClient) Resolve(_ context.Context, request LiveResolveRequest) (LiveResolveResult, error) {
	c.resolveCalls++
	result := LiveResolveResult{Sources: make([]VerifiedSource, len(request.Sources)), Tasks: make([]VerifiedTask, len(request.InstalledTasks))}
	for index, source := range request.Sources {
		if source.NativeLocator.Empty() {
			return LiveResolveResult{}, ErrBindingStale
		}
		result.Sources[index] = VerifiedSource{SourceHandle: source.SourceHandle, IdentityFingerprint: source.IdentityFingerprint}
	}
	for index, task := range request.InstalledTasks {
		result.Tasks[index] = VerifiedTask{TaskID: task.TaskID, BindingFingerprint: task.BindingFingerprint}
	}
	return result, nil
}

func (c *recordingClient) CaptureSnapshot(_ context.Context, request SnapshotRequest) (SnapshotResponse, error) {
	c.captureCalls++
	return SnapshotResponse{
		Content: io.NopCloser(bytes.NewReader(c.snapshot)), SourceFingerprint: request.SourceFingerprint,
		Freshness: c.freshness, ObservedAt: c.now,
	}, nil
}

func (c *recordingClient) ReadExistingEvidence(context.Context, ExistingEvidenceRequest) (ExistingEvidenceResponse, error) {
	return ExistingEvidenceResponse{}, ErrUnsupported
}

func (c *recordingClient) Analyze(_ context.Context, request AnalysisRequest) (AnalysisResponse, error) {
	c.analysisCalls++
	if c.analysisErr != nil {
		return AnalysisResponse{}, c.analysisErr
	}
	if len(request.Inputs) != 1 || request.Inputs[0].Ordinal != 1 {
		return AnalysisResponse{}, ErrInvalidResponse
	}
	content, err := io.ReadAll(request.Inputs[0].Content)
	if err != nil || !bytes.Equal(content, c.snapshot) {
		return AnalysisResponse{}, ErrInvalidResponse
	}
	return AnalysisResponse{Candidate: validCandidate(), EvidenceOrdinals: []int{1}, ModelVersion: "vlm-picture-v1"}, nil
}

func (c *recordingClient) Cleanup(_ context.Context, request LiveCleanupRequest) (LiveCleanupResponse, error) {
	c.cleanupCalls++
	items := make([]LiveCleanupItemResult, len(request.Inputs))
	for index, input := range request.Inputs {
		// Mirrors the current device limitation: PTaskCancle success cannot
		// prove that the temporary resource was actually removed.
		items[index] = LiveCleanupItemResult{ValueRef: input.ValueRef, State: CleanupPending}
	}
	return LiveCleanupResponse{Items: items}, nil
}
