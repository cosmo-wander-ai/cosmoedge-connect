package observation

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionowner"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const testOwner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const otherOwner = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestObservationSelectedSourcesAnswersIdempotencyAndMediaOwnership(t *testing.T) {
	service, fake, root := newObservationHarness(t)
	request := Request{RequestID: "question-one", SourceName: "室内", Question: "画面中是否有人", Subject: "人员"}
	first, err := service.Observe(context.Background(), testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	first = awaitTerminal(t, service, testOwner, first.OperationRef)
	if first.Status != "succeeded" || first.Answer != temporary.AnswerYes || first.SourceName != "室内" || first.ObservedAt == nil || first.TimeMeaning != "image_retrieved_at" || len(first.Attachments) != 1 || first.CleanupStatus != livevision.TaskCancelAcknowledged {
		t.Fatalf("first observation: %+v", first)
	}
	imageA, err := service.ReadMedia(context.Background(), testOwner, first.Attachments[0].MediaRef)
	if err != nil || !bytes.Equal(imageA.Content, fake.images["camera-a"]) || imageA.SHA256 != first.Attachments[0].SHA256 {
		t.Fatalf("first media: %v", err)
	}
	if _, err := service.Get(context.Background(), otherOwner, first.OperationRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner result: %v", err)
	}
	if _, err := service.GetByRequest(context.Background(), otherOwner, request.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner request: %v", err)
	}
	if _, err := service.ReadMedia(context.Background(), otherOwner, first.Attachments[0].MediaRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner media: %v", err)
	}
	fake.mu.Lock()
	reads := fake.reads
	captures := len(fake.captures)
	fake.mu.Unlock()
	duplicate, err := service.Observe(context.Background(), testOwner, request)
	if err != nil || duplicate.OperationRef != first.OperationRef || duplicate.Attachments[0].SHA256 != first.Attachments[0].SHA256 {
		t.Fatalf("duplicate: %+v %v", duplicate, err)
	}
	lookedUp, err := service.GetByRequest(context.Background(), testOwner, request.RequestID)
	if err != nil || lookedUp.OperationRef != first.OperationRef {
		t.Fatalf("by request: %+v %v", lookedUp, err)
	}
	fake.mu.Lock()
	if fake.reads != reads || len(fake.captures) != captures {
		t.Error("repeated request reacquired device facts")
	}
	fake.mu.Unlock()
	changed := request
	changed.Question = "画面中是否有垃圾"
	if _, err := service.Observe(context.Background(), testOwner, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed duplicate: %v", err)
	}
	second, err := service.Observe(context.Background(), testOwner, Request{RequestID: "question-two", SourceName: "走廊", Question: "画面中是否有垃圾", Subject: "垃圾"})
	if err != nil {
		t.Fatal(err)
	}
	second = awaitTerminal(t, service, testOwner, second.OperationRef)
	if second.Status != "succeeded" || second.Answer != temporary.AnswerNo || second.Attachments[0].SHA256 == first.Attachments[0].SHA256 {
		t.Fatalf("second observation: %+v", second)
	}
	if second.SourceKind != "test_video" || !strings.Contains(strings.Join(second.Limitations, " "), "测试视频") {
		t.Fatal("test source was presented as current live scene")
	}
	fake.mu.Lock()
	fake.answer = "无法判断"
	fake.mu.Unlock()
	third, err := service.Observe(context.Background(), testOwner, Request{RequestID: "question-three", SourceName: "室内", Question: "画面中是否有人", Subject: "人员"})
	if err != nil {
		t.Fatal(err)
	}
	third = awaitTerminal(t, service, testOwner, third.OperationRef)
	if third.Status != "succeeded" || third.Answer != temporary.AnswerUnable {
		t.Fatalf("three-state unable: %+v", third)
	}
	fake.mu.Lock()
	if len(fake.captures) != 3 || fake.captures[0] != "camera-a" || fake.captures[1] != "camera-b" || fake.captures[2] != "camera-a" || len(fake.creates) != 3 || len(fake.cancels) != 3 {
		t.Errorf("device lifecycle capture=%v create=%d cancel=%d", fake.captures, len(fake.creates), len(fake.cancels))
	}
	fake.mu.Unlock()
	// Polling never acknowledges the runtime's outbox as delivered.
	db, err := sql.Open("sqlite", filepath.Join(root, "operations", "observation", "temporary-runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var pending, delivered int
	if err := db.QueryRow("SELECT count(*) FROM temporary_terminal_outbox WHERE delivery_state='pending'").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM temporary_terminal_outbox WHERE delivery_state='delivered'").Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if pending != 3 || delivered != 0 {
		t.Fatalf("chat outbox pending=%d delivered=%d", pending, delivered)
	}
	var dispositions int
	if err := service.resource.operations.db.QueryRow("SELECT count(*) FROM chat_dispositions WHERE disposition='chat_only'").Scan(&dispositions); err != nil || dispositions != 3 {
		t.Fatalf("chat dispositions=%d: %v", dispositions, err)
	}
}

func TestObservationSourceClarificationAndInvalidModelNeverInventSuccess(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	for _, name := range []string{"", "不存在"} {
		_, err := service.Observe(context.Background(), testOwner, Request{RequestID: "source-" + digestText(name)[:8], SourceName: name, Question: "画面中是否有人"})
		var selected *SourceSelectionError
		if !errors.As(err, &selected) || len(selected.Choices) != 2 {
			t.Fatalf("source %q: %v", name, err)
		}
	}
	fake.mu.Lock()
	fake.snapshot.Cameras = append(fake.snapshot.Cameras, device.Camera{ID: "ambiguous", Name: "室内", SourceFingerprint: digestText("ambiguous")})
	fake.mu.Unlock()
	_, err := service.Observe(context.Background(), testOwner, Request{RequestID: "ambiguous", SourceName: "室内", Question: "画面中是否有人"})
	var selected *SourceSelectionError
	if !errors.As(err, &selected) || selected.Code != "source_ambiguous" {
		t.Fatalf("ambiguous: %v", err)
	}
	fake.mu.Lock()
	fake.snapshot.Cameras = fake.snapshot.Cameras[:2]
	fake.answer = "看起来应该有人吧"
	fake.mu.Unlock()
	result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "invalid-answer", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	if result.Status == "succeeded" || result.Answer != temporary.AnswerUnable || len(result.Facts) != 0 || len(result.Attachments) != 1 {
		t.Fatalf("invented answer: %+v", result)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.captures) != 1 || len(fake.cancels) != 1 {
		t.Fatalf("clarification or invalid candidate leaked task: %v %v", fake.captures, fake.cancels)
	}
}

func TestObservationRestartKeepsUnknownAndNeverRedispatches(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	fake.mu.Lock()
	fake.blockDetect = true
	fake.entered = make(chan struct{})
	entered := fake.entered
	fake.mu.Unlock()
	request := Request{RequestID: "interrupted", SourceName: "室内", Question: "画面中是否有人"}
	first, err := service.Observe(context.Background(), testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("analysis did not start")
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := awaitTerminal(t, service, testOwner, first.OperationRef)
	if result.Status != "outcome_unknown" || result.Answer != temporary.AnswerUnable || len(result.Attachments) != 1 {
		t.Fatalf("restart result: %+v", result)
	}
	replay, err := service.Observe(context.Background(), testOwner, request)
	if err != nil || replay.OperationRef != result.OperationRef {
		t.Fatalf("restart replay: %+v %v", replay, err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.creates) != 1 || fake.detects != 1 || len(fake.captures) != 1 || len(fake.cancels) != 1 || len(fake.uploads) != 1 || len(fake.uploadCancels) != 1 {
		t.Fatalf("restart redispatched: creates=%d detects=%d captures=%d cancels=%d", len(fake.creates), fake.detects, len(fake.captures), len(fake.cancels))
	}
}

func TestObservationCleanupFailureRecoveryIsBoundedAndKeepsResultUnknown(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	fake.mu.Lock()
	fake.cancelErr = errors.New("simulated cancel unavailable")
	fake.mu.Unlock()
	first, err := service.Observe(context.Background(), testOwner, Request{RequestID: "cleanup-unknown", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result := awaitTerminal(t, service, testOwner, first.OperationRef)
	if result.Status != "outcome_unknown" || result.CleanupStatus != livevision.TaskCleanupUnconfirmed {
		t.Fatalf("cleanup failed: %+v", result)
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.cancelErr = nil
	fake.mu.Unlock()
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		result, err = service.Get(context.Background(), testOwner, first.OperationRef)
		if err != nil {
			t.Fatal(err)
		}
		if result.CleanupStatus == livevision.TaskCancelAcknowledged {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cleanup not reconciled: %+v", result)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if result.Status != "outcome_unknown" {
		t.Fatal("cleanup recovery invented analysis success")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.creates) != 1 || fake.detects != 1 || len(fake.cancels) != 2 || fake.cancels[0].TaskID != fake.cancels[1].TaskID {
		t.Fatalf("unexpected cleanup replay: create=%d detects=%d cancels=%v", len(fake.creates), fake.detects, fake.cancels)
	}
}

func TestObservationUnavailableMediaPreservesTextAndOwnership(t *testing.T) {
	service, _, _ := newObservationHarness(t)
	result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "media-fails", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	ref := result.Attachments[0].MediaRef
	if _, err := service.resource.media.Delete(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	unavailable, err := service.Get(context.Background(), testOwner, result.OperationRef)
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Answer != result.Answer || unavailable.Question != result.Question || unavailable.Attachments[0].Status != "unavailable" {
		t.Fatalf("media failure erased answer or reused image: %+v", unavailable)
	}
	if _, err := service.ReadMedia(context.Background(), testOwner, ref); !errors.Is(err, ErrMediaUnavailable) {
		t.Fatalf("deleted image: %v", err)
	}
	if _, err := service.ReadMedia(context.Background(), otherOwner, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted image leaked owner: %v", err)
	}
}

func TestObservationExactReferenceDisambiguatesAndMissingDescriptorPreservesText(t *testing.T) {
	service, fake, root := newObservationHarness(t)
	fake.mu.Lock()
	fake.snapshot.Cameras[1].Name = "室内"
	sourceRef := livevision.PublicSourceRef(fake.snapshot.Cameras[1])
	fake.mu.Unlock()
	request := Request{RequestID: "selected-reference", SourceRef: sourceRef, Question: "画面中是否有人"}
	result, err := service.Observe(context.Background(), testOwner, request)
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	if result.SourceName != "室内" || result.Answer != temporary.AnswerNo || len(result.Attachments) != 1 {
		t.Fatalf("reference selected wrong source: %+v", result)
	}
	fake.mu.Lock()
	if len(fake.captures) != 1 || fake.captures[0] != "camera-b" {
		t.Errorf("reference capture: %v", fake.captures)
	}
	fake.mu.Unlock()
	ref := result.Attachments[0].MediaRef
	// A Windows reader may briefly hold the descriptor open after the result
	// becomes terminal. Wait for that handle while keeping the service live.
	for deadline := time.Now().Add(time.Second); ; {
		err := os.Remove(filepath.Join(root, "operations", "observation", "media", "descriptors", ref+".json"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	retrieved, err := service.GetByRequest(context.Background(), testOwner, request.RequestID)
	if err != nil || retrieved.Answer != result.Answer || len(retrieved.Attachments) != 1 || retrieved.Attachments[0].Status != "unavailable" || retrieved.Attachments[0].SHA256 != result.Attachments[0].SHA256 || retrieved.ObservedAt == nil {
		t.Fatalf("missing descriptor erased retained evidence: %+v %v", retrieved, err)
	}
	if _, err := service.Get(context.Background(), otherOwner, result.OperationRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing descriptor result ownership: %v", err)
	}
	request.RequestID = "mismatched-source-name"
	request.SourceName = "不存在"
	if _, err := service.Observe(context.Background(), testOwner, request); err == nil {
		t.Fatal("reference accepted a mismatched supplied name")
	}
}

func TestObservationNeverAnalyzesOldImageAfterDeviceReplacement(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		returnToA bool
		dark      bool
	}{
		{name: "same-address new hardware"},
		{name: "A-to-B-to-A", returnToA: true},
		{name: "dark same-address new hardware", dark: true},
		{name: "dark A-to-B-to-A", returnToA: true, dark: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			service, fake, _ := newObservationHarness(t)
			if scenario.dark {
				fake.mu.Lock()
				fake.images["camera-a"] = testJPEG(t, color.RGBA{R: 2, G: 2, B: 2, A: 255})
				fake.mu.Unlock()
			}
			vault := service.config.Vault
			bootstrap, err := vault.IssueBootstrap()
			if err != nil {
				t.Fatal(err)
			}
			browser, err := vault.ConsumeBootstrap(bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			replace := func(serial string) error {
				fake.mu.Lock()
				fake.snapshot.Identity.Serial = serial
				fake.mu.Unlock()
				preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", "test-operator")
				if err != nil {
					return err
				}
				_, err = vault.ConnectConfirmed(context.Background(), browser.SessionID, preview.Token, []byte("synthetic-test-secret"), true)
				return err
			}
			replacementDone := make(chan error, 1)
			fake.mu.Lock()
			fake.afterDownload = func() {
				replaceErr := replace("replacement-test-box")
				if replaceErr == nil && scenario.returnToA {
					replaceErr = replace("observation-test-box")
				}
				replacementDone <- replaceErr
			}
			fake.mu.Unlock()
			result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "old-picture", SourceName: "室内", Question: "画面中是否有人"})
			if err != nil {
				t.Fatal(err)
			}
			result = awaitTerminal(t, service, testOwner, result.OperationRef)
			if replaceErr := <-replacementDone; replaceErr != nil {
				t.Fatal(replaceErr)
			}
			if result.Status == "succeeded" || result.Answer != temporary.AnswerUnable || len(result.Attachments) != 1 {
				t.Fatalf("old image reused across admission: %+v", result)
			}
			fake.mu.Lock()
			if len(fake.captures) != 1 || len(fake.creates) != 0 || fake.detects != 0 || len(fake.cancels) != 0 {
				t.Errorf("old operation dispatched after replacement capture=%d create=%d detect=%d cancel=%d", len(fake.captures), len(fake.creates), fake.detects, len(fake.cancels))
			}
			fake.mu.Unlock()
		})
	}
}

func TestObservationPendingWithoutAdmissionBindingFailsClosed(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "pre-epoch", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	value, err := service.resource.operations.get(context.Background(), testOwner, result.OperationRef)
	if err != nil {
		t.Fatal(err)
	}
	value.Source.DeviceIdentitySHA256 = ""
	value.Source.ConnectionEpoch = ""
	if err := service.resource.operations.update(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	before := len(fake.creates)
	fake.mu.Unlock()
	analyzer := deadlineAnalyzer{vault: service.config.Vault, journal: service.resource.journal, store: service.resource.operations}
	if _, err := analyzer.Analyze(context.Background(), temporary.AnalysisRequest{RunID: value.RunID}); !errors.Is(err, temporary.ErrAnalysisDefinitelyFailed) {
		t.Fatalf("pre-epoch analysis: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.creates) != before {
		t.Fatal("pre-epoch record redispatched")
	}
}

func newObservationHarness(t *testing.T, wrap ...func(*observationDevice) device.Client) (*Service, *observationDevice, string) {
	t.Helper()
	fake := &observationDevice{snapshot: device.Snapshot{Identity: device.Identity{Serial: "observation-test-box", Type: "edge"}, Cameras: []device.Camera{{ID: "camera-a", Name: "室内", SourceFingerprint: digestText("camera-a"), SourceKind: "network_camera"}, {ID: "camera-b", Name: "走廊", SourceFingerprint: digestText("camera-b"), SourceKind: "test_video"}}}, images: map[string][]byte{"camera-a": testJPEG(t, color.RGBA{255, 0, 0, 255}), "camera-b": testJPEG(t, color.RGBA{0, 255, 0, 255})}}
	var client device.Client = fake
	if len(wrap) != 0 {
		client = wrap[0](fake)
	}
	vault := session.New(func(_, _, _ string) device.Client { return client })
	base := t.TempDir()
	root := filepath.Join(base, "state")
	token := filepath.Join(base, "access.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	owner, err := connectionowner.New(connectionowner.Config{StateRoot: root, TokenFile: token, Vault: vault})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Stop(); err != nil {
			t.Error(err)
		}
	})
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", "test-operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, []byte("synthetic-test-secret")); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{StateRoot: root, Vault: vault, WorkerInterval: 5 * time.Millisecond, RunTimeout: 10 * time.Second, EvidenceTTL: time.Minute, MaxOperations: 100})
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
	return service, fake, root
}
func awaitTerminal(t *testing.T, s *Service, owner, ref string) Result {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for {
		result, err := s.Get(context.Background(), owner, ref)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Pending {
			return result
		}
		if time.Now().After(deadline) {
			t.Fatalf("observation did not finish: %+v worker=%v", result, s.workerErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func testJPEG(t *testing.T, shade color.RGBA) []byte {
	t.Helper()
	pic := image.NewRGBA(image.Rect(0, 0, 16, 12))
	for y := 0; y < 12; y++ {
		for x := 0; x < 16; x++ {
			pic.Set(x, y, shade)
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, pic, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

type observationDevice struct {
	mu              sync.Mutex
	snapshot        device.Snapshot
	images          map[string][]byte
	currentCamera   string
	captures        []string
	creates         []adapter.PictureTaskCreateRequest
	cancels         []adapter.PictureTaskCancelRequest
	detects         int
	detectRequests  []adapter.PictureTaskDetectRequest
	detectErr       error
	uploads         []adapter.StagedPictureUploadRequest
	uploadCancels   []adapter.StagedPictureUpload
	uploaded        map[string][]byte
	uploadErr       error
	uploadNoID      bool
	uploadCancelErr error
	reads           int
	answer          string
	blockDetect     bool
	entered         chan struct{}
	cancelErr       error
	afterDownload   func()
}

func (*observationDevice) Login(context.Context) error { return nil }
func (d *observationDevice) Read(context.Context) (device.Snapshot, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reads++
	snapshot := d.snapshot
	snapshot.Cameras = append([]device.Camera(nil), snapshot.Cameras...)
	snapshot.ObservedAt = time.Now().UTC()
	return snapshot, nil
}
func (*observationDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{}
}
func (d *observationDevice) GetCameraPictureContext(_ context.Context, id string) (adapter.CameraPicture, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.currentCamera = id
	d.captures = append(d.captures, id)
	return adapter.CameraPicture{}, nil
}
func (d *observationDevice) DownloadFreshCameraPictureJPEG(context.Context, adapter.CameraPicture, int64) (adapter.InspectionJPEG, error) {
	d.mu.Lock()
	value := adapter.InspectionJPEG{Content: append([]byte(nil), d.images[d.currentCamera]...), Width: 16, Height: 12}
	after := d.afterDownload
	d.afterDownload = nil
	d.mu.Unlock()
	if after != nil {
		after()
	}
	return value, nil
}
func (*observationDevice) QueryPictureAlgorithmsContext(context.Context, int, int) (adapter.PictureAlgorithmPage, error) {
	return adapter.PictureAlgorithmPage{Total: 1, Rows: []adapter.PictureAlgorithm{{AlgorithmID: "picture-vlm", AlgorithmName: "视觉语言大模型", AlgorithmUsage: "2"}}}, nil
}
func (*observationDevice) QueryAlgorithmLayoutDetailContext(context.Context, string) (adapter.AlgorithmLayoutDetail, error) {
	return adapter.AlgorithmLayoutDetail{AlgorithmCode: "89336", AlgorithmName: "视觉语言大模型", AlgorithmUsage: "2", ConfigVersionID: "active", Versions: []adapter.AlgorithmLayoutVersion{{ID: "active", AlgorithmCode: "89336", AlgorithmUpdateTime: "1752998400000"}}}, nil
}
func (d *observationDevice) CreatePictureTaskContext(_ context.Context, request adapter.PictureTaskCreateRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.creates = append(d.creates, request)
	return nil
}
func (d *observationDevice) DetectPictureTaskContext(ctx context.Context, request adapter.PictureTaskDetectRequest) (adapter.PictureTaskDetectResult, error) {
	d.mu.Lock()
	d.detects++
	d.detectRequests = append(d.detectRequests, request)
	content := request.JPEG
	if request.UploadID != "" {
		content = d.uploaded[request.UploadID]
	}
	detectErr := d.detectErr
	answer := d.answer
	block := d.blockDetect
	entered := d.entered
	if answer == "" {
		answer = "是"
		if bytes.Equal(content, d.images["camera-b"]) {
			answer = "否"
		}
	}
	d.mu.Unlock()
	if detectErr != nil {
		return adapter.PictureTaskDetectResult{}, detectErr
	}
	if block {
		close(entered)
		<-ctx.Done()
		return adapter.PictureTaskDetectResult{}, ctx.Err()
	}
	return adapter.PictureTaskDetectResult{AlgorithmCode: request.AlgorithmCode, Areas: []adapter.PictureTaskArea{{Detected: true, Targets: []adapter.PictureTaskTarget{{Confidence: []adapter.PictureTaskConfidence{{Label: answer, Confidence: 1}}}}}}}, nil
}
func (d *observationDevice) CancelPictureTaskContext(_ context.Context, request adapter.PictureTaskCancelRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancels = append(d.cancels, request)
	return d.cancelErr
}

var _ device.InspectionClient = (*observationDevice)(nil)
