package observation

import (
	"bytes"
	"context"
	"errors"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

// This device provides camera bytes but has no available picture algorithm.
// Even discovery is recorded, so a capture cannot hide a failed VLM attempt.
type captureDevice struct {
	*observationDevice
	algorithmQueries atomic.Int32
	downloadEntered  chan struct{}
	blockDownload    atomic.Bool
	downloadFails    atomic.Bool
}

func (d *captureDevice) QueryPictureAlgorithmsContext(context.Context, int, int) (adapter.PictureAlgorithmPage, error) {
	d.algorithmQueries.Add(1)
	return adapter.PictureAlgorithmPage{}, errors.New("no picture algorithms available")
}

func (d *captureDevice) DownloadFreshCameraPictureJPEG(ctx context.Context, picture adapter.CameraPicture, limit int64) (adapter.InspectionJPEG, error) {
	if d.blockDownload.Load() {
		select {
		case d.downloadEntered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return adapter.InspectionJPEG{}, ctx.Err()
	}
	if d.downloadFails.Load() {
		return adapter.InspectionJPEG{}, errors.New("camera image unavailable")
	}
	return d.observationDevice.DownloadFreshCameraPictureJPEG(ctx, picture, limit)
}

func newCaptureHarness(t *testing.T) (*Service, *captureDevice, string) {
	t.Helper()
	var capture *captureDevice
	service, _, root := newObservationHarness(t, func(base *observationDevice) device.Client {
		capture = &captureDevice{observationDevice: base, downloadEntered: make(chan struct{}, 1)}
		return capture
	})
	return service, capture, root
}

func assertNoCaptureAnalysis(t *testing.T, service *Service, fake *captureDevice, ref string, wantCaptures int) {
	t.Helper()
	fake.mu.Lock()
	counts := []int{int(fake.algorithmQueries.Load()), len(fake.creates), fake.detects, len(fake.cancels), len(fake.uploads), len(fake.uploadCancels)}
	actualCaptures := len(fake.captures)
	fake.mu.Unlock()
	if actualCaptures != wantCaptures {
		t.Fatalf("captures=%d, want %d", actualCaptures, wantCaptures)
	}
	for _, count := range counts {
		if count != 0 {
			t.Fatalf("capture invoked analysis discovery/create/detect/cancel/upload: %v", counts)
		}
	}
	value, err := service.resource.operations.get(context.Background(), testOwner, ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.resource.runner.Get(context.Background(), value.RunID); !errors.Is(err, temporary.ErrRuntimeNotFound) {
		t.Fatalf("capture created a temporary analysis run: %v", err)
	}
}

func TestCaptureWithoutVLMKeepsOriginalOwnershipAndRequestIdentity(t *testing.T) {
	service, fake, _ := newCaptureHarness(t)
	ctx := context.Background()
	request := Request{Mode: CaptureOnly, RequestID: "capture-first", SourceName: "室内"}
	first, err := service.Observe(ctx, testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	first = awaitTerminal(t, service, testOwner, first.OperationRef)
	if first.Kind != "capture" || first.AnalysisSource != "none" || first.Status != "captured" || first.Answer != "" || len(first.Facts) != 0 || first.CleanupStatus != "" || first.ObservedAt == nil || first.TimeMeaning != "image_retrieved_at" || first.FrameTimeKnown || len(first.Attachments) != 1 {
		t.Fatalf("capture invented analysis or lost evidence: %+v", first)
	}
	mediaRef := first.Attachments[0].MediaRef
	original, err := service.ReadMedia(ctx, testOwner, mediaRef)
	if err != nil || !bytes.Equal(original.Content, fake.images["camera-a"]) {
		t.Fatalf("capture original: %v", err)
	}
	for _, get := range []func() (Result, error){
		func() (Result, error) { return service.Observe(ctx, testOwner, request) },
		func() (Result, error) { return service.GetByRequest(ctx, testOwner, request.RequestID) },
	} {
		replay, err := get()
		if err != nil || replay.OperationRef != first.OperationRef || replay.Attachments[0].SHA256 != first.Attachments[0].SHA256 {
			t.Fatalf("capture replay changed original: %+v %v", replay, err)
		}
	}
	if _, err := service.Get(ctx, otherOwner, first.OperationRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner result: %v", err)
	}
	if _, err := service.GetByRequest(ctx, otherOwner, request.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner recovery: %v", err)
	}
	if _, err := service.ReadMedia(ctx, otherOwner, mediaRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner original: %v", err)
	}
	changed := request
	changed.SourceName = "走廊"
	if _, err := service.Observe(ctx, testOwner, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed capture reused request: %v", err)
	}
	edge := request
	edge.Mode, edge.Question = "", "画面中是否有人"
	if _, err := service.Observe(ctx, testOwner, edge); !errors.Is(err, ErrConflict) {
		t.Fatalf("capture changed into edge analysis: %v", err)
	}
	assertNoCaptureAnalysis(t, service, fake, first.OperationRef, 1)
}

func TestCaptureDarkImageAndRestartRetainBytesWithoutVisualAnswer(t *testing.T) {
	service, fake, root := newCaptureHarness(t)
	fake.mu.Lock()
	fake.images["camera-b"] = testJPEG(t, color.RGBA{0, 0, 0, 255})
	fake.mu.Unlock()
	ctx := context.Background()
	request := Request{Mode: CaptureOnly, RequestID: "dark-frame", SourceName: "走廊", Question: "描述一下画面，门在哪边？"}
	first, err := service.Observe(ctx, testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	first = awaitTerminal(t, service, testOwner, first.OperationRef)
	if first.Status != "captured" || first.Answer != "" || len(first.Facts) != 0 || first.Question != request.Question || first.SourceKind != "test_video" || !strings.Contains(strings.Join(first.Limitations, " "), "测试视频") {
		t.Fatalf("dark capture was treated as model analysis: %+v", first)
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.GetByRequest(ctx, testOwner, request.RequestID)
	if err != nil || recovered.Status != "captured" || recovered.ObservedAt == nil || !recovered.ObservedAt.Equal(*first.ObservedAt) || recovered.Attachments[0].SHA256 != first.Attachments[0].SHA256 {
		t.Fatalf("capture restart changed evidence: %+v %v", recovered, err)
	}
	ref := recovered.Attachments[0].MediaRef
	original, err := service.ReadMedia(ctx, testOwner, ref)
	if err != nil || !bytes.Equal(original.Content, fake.images["camera-b"]) {
		t.Fatalf("dark original: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "operations", "observation", "media", "descriptors", ref+".json")); err != nil {
		t.Fatal(err)
	}
	recovered, err = service.GetByRequest(ctx, testOwner, request.RequestID)
	if err != nil || recovered.Status != "captured" || recovered.Answer != "" || recovered.Attachments[0].Status != "unavailable" || recovered.Attachments[0].SHA256 != first.Attachments[0].SHA256 || recovered.ObservedAt == nil || !recovered.ObservedAt.Equal(*first.ObservedAt) {
		t.Fatalf("missing original erased capture metadata: %+v %v", recovered, err)
	}
	if _, err := service.ReadMedia(ctx, testOwner, ref); err == nil {
		t.Fatal("retained capture metadata authorized missing bytes")
	}
	assertNoCaptureAnalysis(t, service, fake, first.OperationRef, 1)
}

func TestCaptureFailureNeverInventsOriginalOrRetries(t *testing.T) {
	service, fake, _ := newCaptureHarness(t)
	fake.downloadFails.Store(true)
	ctx := context.Background()
	request := Request{Mode: CaptureOnly, RequestID: "missing-frame", SourceName: "室内"}
	first, err := service.Observe(ctx, testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	first = awaitTerminal(t, service, testOwner, first.OperationRef)
	if first.Status != "capture_failed" || first.AnalysisSource != "none" || first.Answer != "" || len(first.Attachments) != 0 || first.ObservedAt != nil {
		t.Fatalf("failed capture invented an image or answer: %+v", first)
	}
	fake.downloadFails.Store(false)
	if again, err := service.Observe(ctx, testOwner, request); err != nil || again.Status != first.Status || again.OperationRef != first.OperationRef {
		t.Fatalf("duplicate capture retried: %+v %v", again, err)
	}
	assertNoCaptureAnalysis(t, service, fake, first.OperationRef, 1)
}

func TestCaptureInterruptedDownloadDoesNotRecaptureAfterRestart(t *testing.T) {
	service, fake, _ := newCaptureHarness(t)
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	var clockOffset atomic.Int64
	service.config.Now = func() time.Time { return time.Now().Add(time.Duration(clockOffset.Load())) }
	service.config.RunTimeout, service.config.EvidenceTTL = 2*time.Minute, 5*time.Minute
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.blockDownload.Store(true)
	request := Request{Mode: CaptureOnly, RequestID: "interrupted-capture", SourceName: "室内"}
	first, err := service.Observe(context.Background(), testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-fake.downloadEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("capture download did not begin")
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	// Expire the interrupted acquisition lease, within the request and media
	// deadlines. Recovery must reconcile that attempt rather than recapture.
	clockOffset.Store(int64(62 * time.Second))
	fake.blockDownload.Store(false)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered := awaitTerminal(t, service, testOwner, first.OperationRef)
	if recovered.Status != "capture_failed" || recovered.Answer != "" || len(recovered.Attachments) != 0 {
		t.Fatalf("interrupted capture invented completion: %+v", recovered)
	}
	if replay, err := service.Observe(context.Background(), testOwner, request); err != nil || replay.OperationRef != first.OperationRef || replay.Status != recovered.Status {
		t.Fatalf("interrupted capture resubmitted: %+v %v", replay, err)
	}
	assertNoCaptureAnalysis(t, service, fake, first.OperationRef, 1)
}

func TestCaptureKeepsLegacyEdgeUnknownAfterRestart(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	ctx := context.Background()
	fake.mu.Lock()
	fake.blockDetect, fake.entered = true, make(chan struct{})
	entered := fake.entered
	fake.mu.Unlock()
	edge, err := service.Observe(ctx, testOwner, Request{RequestID: "legacy-edge", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("edge analysis did not begin")
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	edge = awaitTerminal(t, service, testOwner, edge.OperationRef)
	if edge.Status != "outcome_unknown" || edge.Answer != temporary.AnswerUnable || edge.Kind != "edge_observation" || edge.AnalysisSource != "edge" {
		t.Fatalf("legacy edge state changed: %+v", edge)
	}
	// Empty additions stay omitted in persisted edge JSON, preserving rc21's
	// canonical checksums and its existing temporary-runtime records.
	var raw []byte
	if err := service.resource.operations.db.QueryRow("SELECT record_json FROM operations WHERE operation_ref=?", edge.OperationRef).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"mode"`)) || bytes.Contains(raw, []byte(`"captureMedia"`)) {
		t.Fatal("legacy edge record gained capture fields")
	}
	capture, err := service.Observe(ctx, testOwner, Request{Mode: CaptureOnly, RequestID: "host-picture", SourceName: "室内"})
	if err != nil {
		t.Fatal(err)
	}
	capture = awaitTerminal(t, service, testOwner, capture.OperationRef)
	if capture.Status != "captured" || capture.Answer != "" || capture.Attachments[0].MediaRef == edge.Attachments[0].MediaRef {
		t.Fatalf("capture became the old edge operation: %+v", capture)
	}
	again, err := service.Get(ctx, testOwner, edge.OperationRef)
	if err != nil || again.Status != "outcome_unknown" || again.Answer != temporary.AnswerUnable || again.Attachments[0].MediaRef != edge.Attachments[0].MediaRef {
		t.Fatalf("new capture overwrote old edge unknown: %+v %v", again, err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.captures) != 2 || len(fake.creates) != 1 || fake.detects != 1 || len(fake.uploads) != 1 {
		t.Fatalf("capture resumed edge analysis: captures=%d creates=%d detects=%d uploads=%d", len(fake.captures), len(fake.creates), fake.detects, len(fake.uploads))
	}
}
