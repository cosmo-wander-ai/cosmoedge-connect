package httpapi

// This integration uses the real Python wrapper, HTTP handler, observation
// worker and SQLite stores. Only the typed device boundary is synthetic.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/observation"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

type observationIntegrationDevice struct {
	jpeg                                []byte
	captures, creates, detects, cancels atomic.Int32
	uploads, uploadCancels              atomic.Int32
	entered, release                    chan struct{}
}

func (*observationIntegrationDevice) Login(context.Context) error { return nil }
func (*observationIntegrationDevice) Read(context.Context) (device.Snapshot, error) {
	fingerprint := sha256.Sum256([]byte("integration-camera"))
	return device.Snapshot{Identity: device.Identity{Serial: "observation-integration-device", Type: "test-only"},
		Cameras:    []device.Camera{{ID: "integration-camera", Name: "测试入口", SourceKind: "test_video", SourceFingerprint: hex.EncodeToString(fingerprint[:])}},
		ObservedAt: time.Now().UTC()}, nil
}
func (*observationIntegrationDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{}
}
func (d *observationIntegrationDevice) GetCameraPictureContext(context.Context, string) (adapter.CameraPicture, error) {
	d.captures.Add(1)
	return adapter.CameraPicture{}, nil
}
func (d *observationIntegrationDevice) DownloadFreshCameraPictureJPEG(context.Context, adapter.CameraPicture, int64) (adapter.InspectionJPEG, error) {
	return adapter.InspectionJPEG{Content: append([]byte(nil), d.jpeg...), Width: 16, Height: 12}, nil
}
func (*observationIntegrationDevice) QueryPictureAlgorithmsContext(context.Context, int, int) (adapter.PictureAlgorithmPage, error) {
	return adapter.PictureAlgorithmPage{Total: 1, Rows: []adapter.PictureAlgorithm{{AlgorithmID: "picture-vlm", AlgorithmName: "视觉语言大模型", AlgorithmUsage: "2"}}}, nil
}
func (*observationIntegrationDevice) QueryAlgorithmLayoutDetailContext(context.Context, string) (adapter.AlgorithmLayoutDetail, error) {
	return adapter.AlgorithmLayoutDetail{AlgorithmCode: "89336", AlgorithmName: "视觉语言大模型", AlgorithmUsage: "2", ConfigVersionID: "active",
		Versions: []adapter.AlgorithmLayoutVersion{{ID: "active", AlgorithmCode: "89336", AlgorithmUpdateTime: "1752998400000"}}}, nil
}
func (d *observationIntegrationDevice) CreatePictureTaskContext(context.Context, adapter.PictureTaskCreateRequest) error {
	d.creates.Add(1)
	return nil
}
func (d *observationIntegrationDevice) DetectPictureTaskContext(ctx context.Context, request adapter.PictureTaskDetectRequest) (adapter.PictureTaskDetectResult, error) {
	if request.UploadID != "staged_integration" || len(request.JPEG) != 0 {
		return adapter.PictureTaskDetectResult{}, adapter.ErrInvalidInspectionRequest
	}
	d.detects.Add(1)
	select {
	case d.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return adapter.PictureTaskDetectResult{}, ctx.Err()
	case <-d.release:
	}
	return adapter.PictureTaskDetectResult{AlgorithmCode: request.AlgorithmCode, Areas: []adapter.PictureTaskArea{{Detected: true,
		Targets: []adapter.PictureTaskTarget{{Confidence: []adapter.PictureTaskConfidence{{Label: "是", Confidence: 1}}}}}}}, nil
}
func (d *observationIntegrationDevice) CancelPictureTaskContext(context.Context, adapter.PictureTaskCancelRequest) error {
	d.cancels.Add(1)
	return nil
}

func (*observationIntegrationDevice) QueryUploadCapabilitiesContext(context.Context) (adapter.UploadCapabilities, error) {
	return adapter.UploadCapabilities{MaxChunkSize: 8 << 20, IdleTimeoutMs: 1800000, AvailableForNewUploadsBytes: 64 << 20, MaxEncodedImageBytes: 16 << 20, MaxImagePixels: 33177600}, nil
}
func (d *observationIntegrationDevice) UploadPictureJPEGContext(_ context.Context, request adapter.StagedPictureUploadRequest) (adapter.StagedPictureUpload, error) {
	if !bytes.Equal(request.JPEG, d.jpeg) {
		return adapter.StagedPictureUpload{}, adapter.ErrInvalidInspectionRequest
	}
	d.uploads.Add(1)
	sum := sha256.Sum256(request.JPEG)
	return adapter.StagedPictureUpload{ClientRequestID: request.ClientRequestID, UploadID: "staged_integration", SHA256: hex.EncodeToString(sum[:]), SizeBytes: uint64(len(request.JPEG)), TotalChunks: 1, NextChunkIndex: 1, Complete: true}, nil
}
func (d *observationIntegrationDevice) CancelPictureUploadContext(ctx context.Context, upload adapter.StagedPictureUpload) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if upload.UploadID != "staged_integration" {
		return adapter.ErrInvalidInspectionRequest
	}
	d.uploadCancels.Add(1)
	return nil
}

type observationProcessEnvelope struct {
	OK               bool               `json:"ok"`
	Code             string             `json:"code"`
	Unknown          bool               `json:"unknown"`
	Retryable        bool               `json:"retryable"`
	RequestSubmitted bool               `json:"requestSubmitted"`
	Pending          bool               `json:"pending"`
	SessionRef       string             `json:"sessionRef"`
	RequestID        string             `json:"requestId"`
	OperationRef     string             `json:"operationRef"`
	Observation      observation.Result `json:"observation"`
	AttachmentFiles  []string           `json:"attachmentFiles"`
	Continuation     struct {
		Command    string `json:"command"`
		RequestID  string `json:"requestId"`
		SessionRef string `json:"sessionRef"`
	} `json:"continuation"`
}

func TestObservationPythonHTTPLostResponseResumesRealServiceWithoutRedispatch(t *testing.T) {
	pythonName := os.Getenv("COSMOEDGE_CONNECT_PYTHON")
	if pythonName == "" {
		pythonName = "python3"
	}
	python, err := exec.LookPath(pythonName)
	if err != nil {
		if os.Getenv("COSMOEDGE_CONNECT_PYTHON") != "" {
			t.Fatal("configured COSMOEDGE_CONNECT_PYTHON is unavailable:", err)
		}
		t.Skip("Python 3.9+ is required for the real client integration")
	}
	var encoded bytes.Buffer
	frame := image.NewGray(image.Rect(0, 0, 16, 12))
	for i := range frame.Pix {
		frame.Pix[i] = uint8(80 + i%120)
	}
	if err := jpeg.Encode(&encoded, frame, nil); err != nil {
		t.Fatal(err)
	}
	fake := &observationIntegrationDevice{jpeg: encoded.Bytes(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(fake.release) }) }
	defer release()
	vault := session.New(func(string, string, string) device.Client { return fake })
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", "synthetic-test-only")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, []byte("synthetic-test-only")); err != nil {
		t.Fatal(err)
	}
	service, err := observation.New(observation.Config{StateRoot: filepath.Join(t.TempDir(), "state"), Vault: vault,
		WorkerInterval: 5 * time.Millisecond, RunTimeout: 10 * time.Second, EvidenceTTL: time.Minute, MaxOperations: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Stop(); err != nil {
			t.Error(err)
		}
	})
	token := strings.Repeat("e", 64)
	digest := sha256.Sum256([]byte(token))
	handler, err := New(Config{TokenDigest: hex.EncodeToString(digest[:]), Connections: vault, Observations: service})
	if err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	var deniedReads atomic.Int32
	accepted := make(chan observationProcessEnvelope, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		if r.Method == http.MethodPost && r.URL.Path == Prefix+"observations" && posts.Add(1) == 1 {
			var original observationProcessEnvelope
			if err := json.Unmarshal(recorder.Body.Bytes(), &original); err != nil || recorder.Code != http.StatusOK || !original.OK {
				t.Errorf("observation was not accepted before injected loss: status=%d body=%s", recorder.Code, recorder.Body)
			}
			accepted <- original
			// Commit through the real handler, then close the actual TCP connection
			// without sending status, headers or body. The client never learns ref.
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		if r.Method == http.MethodGet && recorder.Code == http.StatusNotFound {
			deniedReads.Add(1)
		}
		for key, values := range recorder.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	tokenFile := filepath.Join(root, "access.token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(tokenFile); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../../integrations/workbuddy/skills/cosmoedge-operations/scripts/cosmoedge_operations.py")
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(command, sessionRef string, extra ...string) observationProcessEnvelope {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Explicit repository-only development bypass: this test joins transport
		// and execution, while the paired-package contract has separate tests.
		args := []string{script, command, "--allow-unpaired-development", "--base-url", server.URL,
			"--token-file", tokenFile, "--wait-seconds", "0", "--timeout", "3"}
		if sessionRef != "" {
			args = append(args, "--session-ref", sessionRef)
		}
		cmd := exec.CommandContext(ctx, python, append(args, extra...)...)
		cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "TMPDIR="+root)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil || stderr.Len() != 0 {
			t.Fatalf("client command %s: %v stdout=%s stderr=%s", command, err, &stdout, &stderr)
		}
		var result observationProcessEnvelope
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("client JSON: %v %s", err, &stdout)
		}
		return result
	}
	first, second := invoke("session", "").SessionRef, invoke("session", "").SessionRef
	if first == "" || second == "" || first == second {
		t.Fatal("two real client sessions were not independently issued")
	}
	requestFile := filepath.Join(root, "request.json")
	if err := os.WriteFile(requestFile, []byte(`{"sourceName":"测试入口","subject":"人员","question":"画面中有没有人员"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(requestFile); err != nil {
		t.Fatal(err)
	}
	lost := invoke("observe", first, "--request-file", requestFile)
	var original observationProcessEnvelope
	select {
	case original = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("fault injection did not record an accepted first request")
	}
	if !lost.Unknown || lost.Retryable || !lost.RequestSubmitted || lost.RequestID == "" || lost.OperationRef != "" || lost.RequestID != original.RequestID ||
		lost.Continuation.Command != "observation" || lost.Continuation.RequestID != lost.RequestID || lost.Continuation.SessionRef != first {
		t.Fatalf("lost response did not retain only its original request continuation: %+v original=%+v", lost, original)
	}
	select {
	case <-fake.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("real observation worker did not reach the typed detection boundary")
	}
	assertSingleDispatch := func() {
		t.Helper()
		if posts.Load() != 1 || fake.captures.Load() != 1 || fake.creates.Load() != 1 || fake.detects.Load() != 1 || fake.uploads.Load() != 1 {
			t.Fatalf("unexpected redispatch: posts=%d capture=%d create=%d detect=%d", posts.Load(), fake.captures.Load(), fake.creates.Load(), fake.detects.Load())
		}
	}
	for range 2 {
		resumed := invoke("observation", first, "--request-id", lost.RequestID)
		if !resumed.OK || !resumed.Pending || resumed.OperationRef != original.OperationRef || resumed.RequestID != lost.RequestID {
			t.Fatalf("by-request did not recover original pending operation: %+v", resumed)
		}
		assertSingleDispatch()
	}
	for _, refArgs := range [][]string{{"--request-id", lost.RequestID}, {"--operation-ref", original.OperationRef}} {
		foreign := invoke("observation", second, refArgs...)
		if foreign.OK || foreign.Code != "observation_not_found" || foreign.Observation.OperationRef != "" || len(foreign.AttachmentFiles) != 0 {
			t.Fatalf("other signed session could read observation: %+v", foreign)
		}
		assertSingleDispatch()
	}
	if deniedReads.Load() != 2 {
		t.Fatalf("expected HTTP 404 for both foreign read routes, got %d", deniedReads.Load())
	}
	release()
	completed := invoke("observation", first, "--request-id", lost.RequestID, "--wait-seconds", "2")
	if !completed.OK || completed.Pending || completed.OperationRef != original.OperationRef || completed.Observation.Status != "succeeded" ||
		completed.Observation.Answer != temporary.AnswerYes || completed.Observation.CleanupStatus != livevision.TaskCancelAcknowledged || len(completed.AttachmentFiles) != 1 {
		t.Fatalf("same operation did not finish through the real worker: %+v", completed)
	}
	content, err := os.ReadFile(completed.AttachmentFiles[0])
	if err != nil || !bytes.Equal(content, fake.jpeg) {
		t.Fatalf("client did not receive the original stored JPEG: %v", err)
	}
	assertSingleDispatch()
	if fake.cancels.Load() != 1 || fake.uploadCancels.Load() != 1 {
		t.Fatalf("temporary task cleanup count=%d", fake.cancels.Load())
	}
	repeated := invoke("observation", first, "--request-id", lost.RequestID)
	if repeated.Pending || repeated.OperationRef != original.OperationRef || repeated.Observation.Status != "succeeded" {
		t.Fatalf("terminal continuation changed the original operation: %+v", repeated)
	}
	assertSingleDispatch()
	if fake.cancels.Load() != 1 || fake.uploadCancels.Load() != 1 {
		t.Fatal("terminal continuation repeated device cleanup")
	}
}
