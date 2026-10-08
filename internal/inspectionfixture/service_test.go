package inspectionfixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const fixtureToken = "9b4d7f2a13c86e50d1a4f7b29e6c0358af246bd0e9173c5d68a1f0b4ce729d83" // gitleaks:allow -- Synthetic credential for an isolated local test fixture.

type submissionResponse struct {
	Created bool            `json:"created"`
	Run     httpapi.RunView `json:"run"`
}

type feedbackResponse struct {
	Created  bool                    `json:"created"`
	Feedback httpapi.FeedbackReceipt `json:"feedback"`
}

func TestOfflineBusinessFixtureEndToEndAndRestart(t *testing.T) {
	stateRoot := protectedStateRoot(t)
	assetRoot := filepath.Join(stateRoot, "assets")
	if err := PrepareAssetRoot(filepath.Join("testdata", "assets"), assetRoot); err != nil {
		t.Fatalf("prepare realistic assets: %v", err)
	}
	assertProtectedAssetRoot(t, assetRoot)
	tokenFile := writeFixtureToken(t, stateRoot, fixtureToken)
	address := freeLoopbackAddress(t)
	config := Config{
		StateRoot: stateRoot, AssetRoot: assetRoot, TokenFile: tokenFile, Address: address,
		WorkerInterval: 10 * time.Millisecond,
	}

	service, err := New(config)
	if err != nil {
		t.Fatalf("construct fixture: %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	serviceRunning := true
	t.Cleanup(func() {
		if serviceRunning {
			_ = service.Stop()
		}
	})
	if readiness := service.Readiness(); !readiness.Ready || readiness.Address != address {
		t.Fatalf("fixture readiness=%+v", readiness)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + address
	var capabilities httpapi.CapabilitySet
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/capabilities", "", nil, http.StatusOK), &capabilities)
	if capabilities.ContextLabel == "" || len(capabilities.Capabilities) == 0 {
		t.Fatalf("business capabilities are incomplete: %+v", capabilities)
	}
	advertisedInstructions := make([]string, 0)
	seenAdvertisedInstructions := make(map[string]struct{})
	for _, capability := range capabilities.Capabilities {
		if len(capability.Examples) == 0 {
			t.Fatalf("business capability does not advertise an executable example: %+v", capability)
		}
		for _, instruction := range capability.Examples {
			if _, duplicate := seenAdvertisedInstructions[instruction]; duplicate {
				continue
			}
			seenAdvertisedInstructions[instruction] = struct{}{}
			advertisedInstructions = append(advertisedInstructions, instruction)
		}
	}

	instructions := []string{
		InstructionExisting, InstructionSnapshot, InstructionClip, InstructionHybrid,
		InstructionNatural,
	}
	instructions = append(instructions, advertisedInstructions...)
	runs := make(map[string]httpapi.RunView, len(instructions))
	results := make(map[string]httpapi.ResultView, len(instructions))
	resultPayloads := make(map[string][]byte, len(instructions))
	for index, instruction := range instructions {
		key := fmt.Sprintf("business-path-%d", index+1)
		body := []byte(`{"instruction":` + mustJSON(t, instruction) + `}`)
		var submitted submissionResponse
		decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, "/api/inspection/requests", key, body, http.StatusCreated), &submitted)
		if !submitted.Created || submitted.Run.RunRef == "" {
			t.Fatalf("%q did not create a public run: %+v", instruction, submitted)
		}
		var replay submissionResponse
		decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, "/api/inspection/requests", key, body, http.StatusOK), &replay)
		if replay.Created || replay.Run.RunRef != submitted.Run.RunRef {
			t.Fatalf("%q idempotency replay=%+v first=%+v", instruction, replay, submitted)
		}
		runs[instruction] = waitForReadyRun(t, client, baseURL, submitted.Run.RunRef)
		var result httpapi.ResultView
		resultResponse := doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/runs/"+submitted.Run.RunRef+"/result", "", nil, http.StatusOK)
		decodeResponse(t, resultResponse, &result)
		if result.RunRef != submitted.Run.RunRef || !strings.Contains(result.Summary, "整体判断") || len(result.Sections) != 1 {
			t.Fatalf("%q business result=%+v", instruction, result)
		}
		if !containsString(result.Limitations, simulatedMediaLimitation) {
			t.Fatalf("%q did not disclose the stable simulation boundary: %+v", instruction, result)
		}
		publicRaw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, technical := range []string{"needs_attention", "meets_rule", "synthetic_mock"} {
			if bytes.Contains(publicRaw, []byte(technical)) {
				t.Fatalf("%q leaked technical wording %q: %s", instruction, technical, publicRaw)
			}
		}
		results[instruction] = result
		resultPayloads[instruction] = append([]byte(nil), resultResponse.body...)
	}
	existingResult := results[InstructionExisting]
	if len(existingResult.Sections[0].Evidence) != 0 || bytes.Contains(resultPayloads[InstructionExisting], []byte(`"evidence":null`)) ||
		bytes.Contains(resultPayloads[InstructionExisting], []byte("application/json")) {
		t.Fatalf("existing-task event evidence escaped the private analysis boundary: %s", resultPayloads[InstructionExisting])
	}
	var existingPublic map[string]any
	if err := json.Unmarshal(resultPayloads[InstructionExisting], &existingPublic); err != nil {
		t.Fatal(err)
	}
	existingSections, ok := existingPublic["sections"].([]any)
	if !ok || len(existingSections) != 1 {
		t.Fatalf("existing-task public sections are not an array: %s", resultPayloads[InstructionExisting])
	}
	existingSection, ok := existingSections[0].(map[string]any)
	if !ok {
		t.Fatalf("existing-task public section is malformed: %s", resultPayloads[InstructionExisting])
	}
	if evidence, ok := existingSection["evidence"].([]any); !ok || len(evidence) != 0 {
		t.Fatalf("existing-task public evidence must be an explicit empty array: %s", resultPayloads[InstructionExisting])
	}

	standardStats := service.RuntimeStats()
	temporaryBody := []byte(`{"instruction":` + mustJSON(t, InstructionTemporary) + `}`)
	var temporarySubmission submissionResponse
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, "/api/inspection/requests", "business-temporary-1", temporaryBody, http.StatusCreated), &temporarySubmission)
	if !temporarySubmission.Created || temporarySubmission.Run.RunRef == "" {
		t.Fatalf("temporary observation did not create a public run: %+v", temporarySubmission)
	}
	var temporaryReplay submissionResponse
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, "/api/inspection/requests", "business-temporary-1", temporaryBody, http.StatusOK), &temporaryReplay)
	if temporaryReplay.Created || temporaryReplay.Run.RunRef != temporarySubmission.Run.RunRef {
		t.Fatalf("temporary observation idempotency replay=%+v first=%+v", temporaryReplay, temporarySubmission)
	}
	temporaryRun := waitForReadyRun(t, client, baseURL, temporarySubmission.Run.RunRef)
	var temporaryResult httpapi.ResultView
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/runs/"+temporaryRun.RunRef+"/result", "", nil, http.StatusOK), &temporaryResult)
	if temporaryResult.RunRef != temporaryRun.RunRef || temporaryResult.Summary == "" || len(temporaryResult.Sections) != 1 ||
		len(temporaryResult.Sections[0].Evidence) != 1 || !containsString(temporaryResult.Limitations, simulatedMediaLimitation) {
		t.Fatalf("temporary observation result=%+v", temporaryResult)
	}
	temporaryMedia := temporaryResult.Sections[0].Evidence[0]
	if temporaryMedia.Capability != "inspection.media.deliver" || temporaryMedia.MediaType != "image/jpeg" {
		t.Fatalf("temporary observation media capability=%+v", temporaryMedia)
	}
	temporaryMediaResponse := doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/media/"+temporaryMedia.MediaRef, "", nil, http.StatusOK)
	expectedTemporaryImage, err := os.ReadFile(filepath.Join(assetRoot, snapshotAssetName))
	if err != nil {
		t.Fatal(err)
	}
	if temporaryMediaResponse.header.Get("Content-Type") != "image/jpeg" || !bytes.Equal(temporaryMediaResponse.body, expectedTemporaryImage) {
		t.Fatal("temporary observation did not return the prepared realistic JPEG")
	}
	temporaryStats := service.RuntimeStats()
	if temporaryStats.DeviceWriteCalls != 0 || temporaryStats.CleanupCalls != standardStats.CleanupCalls {
		t.Fatalf("temporary observation crossed a persistent-write or cleanup port: before=%+v after=%+v", standardStats, temporaryStats)
	}

	for _, instruction := range []string{InstructionSnapshot, InstructionClip, InstructionHybrid} {
		if len(results[instruction].Sections[0].Evidence) != 1 {
			t.Fatalf("%q did not return one deliverable snapshot: %+v", instruction, results[instruction])
		}
	}
	snapshotMedia := results[InstructionSnapshot].Sections[0].Evidence[0]
	if snapshotMedia.Capability != "inspection.media.deliver" || snapshotMedia.MediaType != "image/jpeg" {
		t.Fatalf("snapshot media capability=%+v", snapshotMedia)
	}
	expectedImage, err := os.ReadFile(filepath.Join(assetRoot, snapshotAssetName))
	if err != nil {
		t.Fatal(err)
	}
	mediaResponse := doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/media/"+snapshotMedia.MediaRef, "", nil, http.StatusOK)
	if mediaResponse.header.Get("Content-Type") != "image/jpeg" || !bytes.Equal(mediaResponse.body, expectedImage) {
		t.Fatal("delivered snapshot did not preserve the prepared realistic JPEG")
	}
	digest := sha256.Sum256(expectedImage)
	if mediaResponse.header.Get("X-Content-SHA256") != hex.EncodeToString(digest[:]) {
		t.Fatal("delivered snapshot integrity header is incorrect")
	}
	clipMedia := results[InstructionClip].Sections[0].Evidence[0]
	if clipMedia.Capability != "inspection.media.deliver" || clipMedia.MediaType != "image/jpeg" {
		t.Fatalf("clip representative-frame capability=%+v", clipMedia)
	}
	expectedClipFrame, err := os.ReadFile(filepath.Join(assetRoot, clipFrameAssetName))
	if err != nil {
		t.Fatal(err)
	}
	clipMediaResponse := doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/media/"+clipMedia.MediaRef, "", nil, http.StatusOK)
	clipPublicJSON, err := json.Marshal(results[InstructionClip])
	if err != nil {
		t.Fatal(err)
	}
	if clipMediaResponse.header.Get("Content-Type") != "image/jpeg" || !bytes.Equal(clipMediaResponse.body, expectedClipFrame) ||
		bytes.Contains(clipPublicJSON, []byte("video/mp4")) {
		t.Fatal("clip result did not keep the MP4 private and return its manifest-bound representative frame")
	}

	feedbackPath := "/api/inspection/runs/" + runs[InstructionSnapshot].RunRef + "/feedback"
	feedbackBody := []byte(`{"helpful":true,"comment":"结果符合本次测试预期"}`)
	var feedback feedbackResponse
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, feedbackPath, "feedback-business-1", feedbackBody, http.StatusCreated), &feedback)
	if !feedback.Created || !feedback.Feedback.Accepted {
		t.Fatalf("feedback receipt=%+v", feedback)
	}
	var feedbackReplay feedbackResponse
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, feedbackPath, "feedback-business-1", feedbackBody, http.StatusOK), &feedbackReplay)
	if feedbackReplay.Created || !feedbackReplay.Feedback.Accepted {
		t.Fatalf("feedback replay=%+v", feedbackReplay)
	}

	stats := service.RuntimeStats()
	if stats.DeviceWriteCalls != 0 || stats.ResolveCalls < 4 || stats.ExistingCalls < 2 || stats.AcquireCalls < 3 ||
		stats.TransformCalls < 1 || stats.AnalyzeCalls < 3 || stats.LastTransform.Kind != media.KindFrameSet ||
		len(stats.LastTransform.FrameMembers) != 1 || stats.LastTransform.FrameMembers[0].OffsetMillis != service.assets.clipFrameOffset ||
		stats.LastTransform.Lineage.ParentMediaRef == "" {
		t.Fatalf("formal path coverage or zero-write invariant failed: %+v", stats)
	}
	assertFixtureReferencesReleased(t, service)
	if err := service.Stop(); err != nil {
		t.Fatalf("stop fixture: %v", err)
	}
	serviceRunning = false
	assertFrameLineage(t, stateRoot, stats.LastTransform)
	assertRawTokenNotPersisted(t, filepath.Join(stateRoot, "inspection-v2"), fixtureToken)

	restarted, err := New(config)
	if err != nil {
		t.Fatalf("reconstruct fixture: %v", err)
	}
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatalf("restart fixture: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Stop() })
	var priorResult httpapi.ResultView
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/runs/"+runs[InstructionSnapshot].RunRef+"/result", "", nil, http.StatusOK), &priorResult)
	if priorResult.RunRef != runs[InstructionSnapshot].RunRef || len(priorResult.Sections) != 1 || len(priorResult.Sections[0].Evidence) != 1 {
		t.Fatalf("persisted result after restart=%+v", priorResult)
	}
	if mediaAfterRestart := doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/media/"+snapshotMedia.MediaRef, "", nil, http.StatusOK); !bytes.Equal(mediaAfterRestart.body, expectedImage) {
		t.Fatal("persisted snapshot capability failed after restart")
	}
	replayBody := []byte(`{"instruction":` + mustJSON(t, InstructionSnapshot) + `}`)
	var restartReplay submissionResponse
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, "/api/inspection/requests", "business-path-2", replayBody, http.StatusOK), &restartReplay)
	if restartReplay.Created || restartReplay.Run.RunRef != runs[InstructionSnapshot].RunRef {
		t.Fatalf("request idempotency did not survive restart: %+v", restartReplay)
	}
	var restartFeedback feedbackResponse
	decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodPost, feedbackPath, "feedback-business-1", feedbackBody, http.StatusOK), &restartFeedback)
	if restartFeedback.Created || !restartFeedback.Feedback.Accepted {
		t.Fatalf("feedback idempotency did not survive restart: %+v", restartFeedback)
	}
}

func TestFixtureRejectsUnprotectedToken(t *testing.T) {
	stateRoot := protectedStateRoot(t)
	assetRoot := filepath.Join(stateRoot, "assets")
	if err := PrepareAssetRoot(filepath.Join("testdata", "assets"), assetRoot); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(stateRoot, "unsafe.token")
	if err := os.WriteFile(tokenPath, []byte(fixtureToken), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{StateRoot: stateRoot, AssetRoot: assetRoot, TokenFile: tokenPath, Address: freeLoopbackAddress(t)}); err == nil {
		t.Fatal("fixture accepted a token file that was not owner-only")
	}
}

type fixtureHTTPResponse struct {
	header http.Header
	body   []byte
}

func doFixtureRequest(t *testing.T, client *http.Client, baseURL, method, path, key string, body []byte, wantStatus int) fixtureHTTPResponse {
	t.Helper()
	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+fixtureToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, (9<<20)+1))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.StatusCode, wantStatus, payload)
	}
	return fixtureHTTPResponse{header: response.Header.Clone(), body: payload}
}

func decodeResponse(t *testing.T, response fixtureHTTPResponse, target any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(response.body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode response %s: %v", response.body, err)
	}
}

func waitForReadyRun(t *testing.T, client *http.Client, baseURL, runRef string) httpapi.RunView {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var run httpapi.RunView
		decodeResponse(t, doFixtureRequest(t, client, baseURL, http.MethodGet, "/api/inspection/runs/"+runRef, "", nil, http.StatusOK), &run)
		switch run.Status {
		case httpapi.RunReady:
			return run
		case httpapi.RunUnable, httpapi.RunCancelled, httpapi.RunExpired, httpapi.RunInteractionRequired:
			t.Fatalf("run %s ended as %s: %s", runRef, run.Status, run.Message)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run %s did not finish", runRef)
	return httpapi.RunView{}
}

func protectedStateRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeFixtureToken(t *testing.T, root, token string) string {
	t.Helper()
	path := filepath.Join(root, "channel.token")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(token)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errorsJoin(writeErr, syncErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func assertProtectedAssetRoot(t *testing.T, root string) {
	t.Helper()
	if err := localstate.ValidateStateRoot(root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{snapshotAssetName, clipAssetName, clipFrameAssetName, eventAssetName, manifestAssetName} {
		if err := localstate.ValidateFile(filepath.Join(root, name)); err != nil {
			t.Fatalf("asset %s is not protected: %v", name, err)
		}
	}
}

func assertFrameLineage(t *testing.T, stateRoot string, frameSet media.Descriptor) {
	t.Helper()
	store, err := media.New(media.Config{Root: filepath.Join(stateRoot, "inspection-v2", "media")})
	if err != nil {
		t.Fatal(err)
	}
	storedSet, err := store.Describe(frameSet.MediaRef)
	if err != nil || storedSet.Lineage.ParentMediaRef == "" || len(storedSet.FrameMembers) != 1 {
		t.Fatalf("stored frame set=%+v err=%v", storedSet, err)
	}
	for index, member := range storedSet.FrameMembers {
		child, err := store.Describe(member.MediaRef)
		if err != nil || child.Lineage.ParentMediaRef != storedSet.MediaRef || child.Lineage.Ordinal != index || child.Kind != media.KindImage {
			t.Fatalf("frame %d lineage=%+v err=%v", index, child, err)
		}
	}
}

func assertRawTokenNotPersisted(t *testing.T, root, token string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(payload, []byte(token)) {
			return fmt.Errorf("raw token was persisted in %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertFixtureReferencesReleased(t *testing.T, service *Service) {
	t.Helper()
	service.mu.RLock()
	ports := service.ports
	service.mu.RUnlock()
	if ports == nil {
		t.Fatal("fixture runtime ports are unavailable")
	}
	ports.mu.Lock()
	defer ports.mu.Unlock()
	if len(ports.evidence) != 0 || len(ports.analysis) != 0 || len(ports.transforms) != 0 {
		t.Fatalf("completed runs retained in-memory result references: evidence=%d analysis=%d transforms=%d",
			len(ports.evidence), len(ports.analysis), len(ports.transforms))
	}
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func errorsJoin(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
