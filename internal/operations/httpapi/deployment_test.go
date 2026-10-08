package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deployment"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deploymentlocal"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/kernel"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
	ordinaryweb "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/web"
)

// This client is injected into the real connection vault. No request can reach
// a device: every method used by the HTTP handler and action worker is local.
type deploymentHTTPDevice struct {
	device.InspectionClient
	mu            sync.Mutex
	state         device.DeploymentState
	cameras       []device.Camera
	algorithms    []device.Algorithm
	writes, reads int
	snapshotReads int
	count         uint64
	defaults      device.DeploymentConfiguration
	writeErr      error
}

func (*deploymentHTTPDevice) Login(context.Context) error { return nil }
func (c *deploymentHTTPDevice) Read(context.Context) (device.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshotReads++
	return device.Snapshot{Identity: device.Identity{Serial: "http-test-device", Type: "test-only"}, Cameras: append([]device.Camera(nil), c.cameras...),
		Tasks: []device.Task{{ID: c.state.TaskID, ChannelID: c.state.SourceID, AlgorithmID: c.state.AlgorithmID, Enabled: c.state.Enabled, SwitchVerified: true}}, ObservedAt: time.Now().UTC()}, nil
}
func (*deploymentHTTPDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{}
}
func (c *deploymentHTTPDevice) ReadAlgorithms(context.Context) ([]device.Algorithm, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]device.Algorithm(nil), c.algorithms...), nil
}
func (c *deploymentHTTPDevice) SwitchTask(_ context.Context, task device.Task, enabled int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if task.ID != c.state.TaskID || task.ChannelID != c.state.SourceID || task.AlgorithmID != c.state.AlgorithmID {
		return errors.New("unexpected target")
	}
	c.writes++
	if c.writeErr != nil {
		return c.writeErr
	}
	c.state.Enabled = enabled
	return nil
}
func (*deploymentHTTPDevice) ReadTaskParameters(context.Context, device.Task) ([]device.ParameterField, error) {
	return nil, errors.New("unused")
}
func (*deploymentHTTPDevice) UpdateTaskParameters(context.Context, device.Task, []device.ParameterField) error {
	return errors.New("unused")
}
func (*deploymentHTTPDevice) AddCameraSource(context.Context, string, []byte) error {
	return errors.New("unused")
}
func (c *deploymentHTTPDevice) ReadDeployment(_ context.Context, source, algorithm string) (device.DeploymentState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if source != c.state.SourceID || algorithm != c.state.AlgorithmID {
		return device.DeploymentState{}, errors.New("unexpected target")
	}
	state := c.state
	state.ObservedAt = time.Now().UTC()
	return state, nil
}
func (c *deploymentHTTPDevice) DefaultDeployment(context.Context, string, string) (device.DeploymentConfiguration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.defaults, nil
}
func (c *deploymentHTTPDevice) SaveDeployment(context.Context, device.DeploymentTarget) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return errors.New("unexpected create")
}
func (c *deploymentHTTPDevice) ReadDeploymentRuntime(_ context.Context, task device.Task) (device.DeploymentRuntime, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	return device.DeploymentRuntime{TaskID: task.ID, Known: true, Active: c.state.Enabled == 1, Stopped: c.state.Enabled == 0,
		Counters: map[string]uint64{"decode": c.count, "inference": c.count, "target-tracker": c.count}, ObservedAt: time.Now().UTC()}, nil
}

type deploymentHTTPHarness struct {
	handler   *Handler
	client    *deploymentHTTPDevice
	service   *deployment.Service
	store     *ledger.Store
	worker    *kernel.Kernel
	token     string
	vault     *session.Vault
	local     *ordinaryweb.Host
	gate      *deploymentlocal.Handler
	openedURL string
	now       func() time.Time
}

func newDeploymentHTTPHarness(t *testing.T) *deploymentHTTPHarness {
	t.Helper()
	client := &deploymentHTTPDevice{
		state: device.DeploymentState{SourceID: "private-camera-a", AlgorithmID: "private-algorithm-a", TaskID: "private-camera-a_private-algorithm-a", Exists: true, Enabled: 0,
			Configuration: device.DeploymentConfiguration{Ready: true, Shape: "native_task_config", Document: json.RawMessage(`{"scheduleId":"test-plan","taskConfig":{"params":[],"areas":[]}}`)}},
		cameras: []device.Camera{{ID: "private-camera-a", Name: "入口", SourceFingerprint: "test-source"}}, algorithms: []device.Algorithm{{ID: "private-algorithm-a", Name: "行人检测", Usage: "1"}},
	}
	vault := session.New(func(string, string, string) device.Client { return client })
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := vault.PrepareConnection(auth.SessionID, "10.20.30.77", "test-only")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = vault.Connect(context.Background(), auth.SessionID, preview.Token, []byte("test-only")); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(stateDir); err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(stateDir, "operator.db"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := deployment.New(store, vault)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := kernel.New(store, map[string]kernel.Handler{deployment.Kind: service})
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("d", 64)
	sum := sha256.Sum256([]byte(token))
	h := &deploymentHTTPHarness{client: client, service: service, store: store, worker: worker, token: token, vault: vault, now: time.Now}
	h.local = ordinaryweb.New("http://127.0.0.1:37790", "test-control", nil, vault, func(u string) error { h.openedURL = u; return nil })
	h.gate, err = deploymentlocal.New(deploymentlocal.Config{BaseURL: "http://127.0.0.1:37790", SessionCookie: ordinaryweb.SessionCookieName, Vault: vault, Deployments: service, Open: h.local.OpenDeploymentReview, Now: func() time.Time { return h.now() }})
	if err != nil {
		t.Fatal(err)
	}
	if err = h.local.MountDeploymentReview(h.gate); err != nil {
		t.Fatal(err)
	}
	handler, err := New(Config{TokenDigest: hex.EncodeToString(sum[:]), Connections: vault, Deployments: service, OpenDeploymentReview: h.gate.OpenReview})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Stop(); service.Close(); _ = store.Close() })
	h.handler = handler
	return h
}

func (h *deploymentHTTPHarness) browser(t *testing.T) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	h.local.ServeHTTP(w, httptest.NewRequest("GET", h.openedURL, nil))
	if w.Code != 303 || w.Header().Get("Location") != deploymentlocal.Path || len(w.Result().Cookies()) != 1 {
		t.Fatalf("bootstrap status=%d", w.Code)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unprotected browser cookie")
	}
	return cookie
}

func (h *deploymentHTTPHarness) localCall(t *testing.T, method string, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://127.0.0.1:37790"+deploymentlocal.Path, strings.NewReader(body))
	r.AddCookie(cookie)
	if method == "POST" {
		auth, err := h.vault.Authenticate(cookie.Value)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", "http://127.0.0.1:37790")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CosmoEdge-CSRF", auth.CSRF)
	}
	w := httptest.NewRecorder()
	h.local.ServeHTTP(w, r)
	return w
}

func (h *deploymentHTTPHarness) call(t *testing.T, method, path, sessionRef string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:37789"+Prefix+path, strings.NewReader(string(raw)))
	r.Header.Set("Authorization", "Bearer "+h.token)
	r.Header.Set("X-CosmoEdge-Session", sessionRef)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("response=%s error=%v", w.Body, err)
	}
	return w, result
}
func (h *deploymentHTTPHarness) session(t *testing.T) string {
	t.Helper()
	w, result := h.call(t, "POST", "session", "", map[string]any{})
	ref, _ := result["sessionRef"].(string)
	if w.Code != 200 || ref == "" {
		t.Fatalf("session=%s", w.Body)
	}
	return ref
}
func deploymentHTTPBody() map[string]any {
	return map[string]any{"requestId": "lost-response-request", "sourceName": "入口", "algorithmName": "行人检测", "enabled": true}
}

func TestDeploymentHTTPExplainsPictureOnlyAlgorithmBeforeTaskAccess(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	h.client.mu.Lock()
	h.client.algorithms[0].Usage = "2"
	h.client.mu.Unlock()
	w, response := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	if w.Code != 409 || response["code"] != "algorithm_usage_unsupported" || response["ok"] != false {
		t.Fatalf("picture-only rejection=%s", w.Body)
	}
	message, _ := response["userMessage"].(string)
	if !strings.Contains(message, "仅供图片分析") || response["operationRef"] != nil || response["confirmationToken"] != nil {
		t.Fatalf("rejection is not an actionable explanation before proposal: %s", w.Body)
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 0 || h.client.reads != 0 {
		t.Fatalf("unsupported algorithm accessed task: reads=%d writes=%d", h.client.reads, h.client.writes)
	}
}

func TestDeploymentHTTPLostFirstResponseResumesOriginalConfirmationOnce(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	w, prepared := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	if w.Code != 200 || prepared["interactionRequired"] != true || strings.Contains(w.Body.String(), "confirmationToken") || prepared["confirmationMode"] != "local_page" {
		t.Fatalf("prepare=%s", w.Body)
	}
	// The client lost that response, so its only available continuation is the
	// original request ID. This GET recovers the same proposal, never authority.
	w, recovered := h.call(t, "GET", "deployments/by-request/lost-response-request", owner, nil)
	if w.Code != 200 || recovered["interactionRequired"] != true || strings.Contains(w.Body.String(), "confirmationToken") || recovered["operationRef"] != prepared["operationRef"] {
		t.Fatalf("recovered=%s prepared=%v", w.Body, prepared)
	}
	h.client.mu.Lock()
	writes := h.client.writes
	h.client.mu.Unlock()
	if writes != 0 {
		t.Fatal("read-only recovery dispatched the proposal")
	}
	w, opened := h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": recovered["operationRef"]})
	if w.Code != 200 || opened["pageOpened"] != true || opened["confirmationReceipt"] != nil || strings.Contains(w.Body.String(), "bootstrap") {
		t.Fatalf("open=%s", w.Body)
	}
	cookie := h.browser(t)
	if w := h.localCall(t, "GET", cookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "入口") || !strings.Contains(w.Body.String(), "确认启用") {
		t.Fatalf("review=%s", w.Body)
	}
	before, _ := h.store.Inspect(context.Background(), recovered["operationRef"].(string))
	if before.State != "proposed" || before.Dispatches != 0 {
		t.Fatal("opening page confirmed")
	}
	for i := 0; i < 2; i++ {
		w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`)
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := "accepted"
		if i == 1 {
			want = "already_confirmed"
		}
		if result["status"] != want {
			t.Fatalf("receipt=%v", result)
		}
		if w.Code != 200 {
			t.Fatalf("confirm %d=%s", i, w.Body)
		}
	}
	h.worker.Wake()
	ref := recovered["operationRef"].(string)
	deadline := time.Now().Add(5 * time.Second)
	var record ledger.Record
	for time.Now().Before(deadline) {
		var err error
		record, err = h.store.Inspect(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if record.State == "completed" || record.State == "unknown" || record.State == "blocked" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if record.State != "completed" || record.Dispatches != 1 || record.DeviceWrites != 1 {
		t.Fatalf("record=%+v", record)
	}
	w, result := h.call(t, "GET", "deployments/by-request/lost-response-request", owner, nil)
	if w.Code != 200 || result["ok"] != true || result["interactionRequired"] == true || strings.Contains(w.Body.String(), "confirmationToken") {
		t.Fatalf("terminal=%s", w.Body)
	}
	w, result = h.call(t, "POST", "deployments/cancel", owner, map[string]any{"operationRef": ref})
	if w.Code != http.StatusConflict || result["cancelled"] != false || result["code"] != "deployment_not_cancellable" {
		t.Fatalf("completed operation reported cancelled: %s", w.Body)
	}
	state := result["deployment"].(map[string]any)
	if state["state"] != "completed" || state["dispatches"] != float64(1) || state["deviceWrites"] != float64(1) || strings.Contains(result["userMessage"].(string), "已取消") {
		t.Fatalf("cancel rewrote the completed outcome: %s", w.Body)
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 1 || h.client.state.Enabled != 1 {
		t.Fatalf("device writes=%d", h.client.writes)
	}
}

func TestDeploymentHTTPCrossSessionCannotReadOrConfirm(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner, stranger := h.session(t), h.session(t)
	w, prepared := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	if w.Code != 200 {
		t.Fatalf("prepare=%s", w.Body)
	}
	for _, request := range []struct {
		method, path string
		body         any
	}{
		{"GET", "deployments/by-request/lost-response-request", nil},
		{"GET", "deployments/" + prepared["operationRef"].(string), nil},
		{"POST", "deployments/review", map[string]any{"operationRef": prepared["operationRef"]}},
		{"POST", "deployments/cancel", map[string]any{"operationRef": prepared["operationRef"]}},
		{"POST", "deployments/confirm", map[string]any{"operationRef": prepared["operationRef"], "confirmationToken": "invented-token"}},
	} {
		w, _ := h.call(t, request.method, request.path, stranger, request.body)
		if w.Code != 409 || strings.Contains(w.Body.String(), "confirmationToken") {
			t.Fatalf("cross-session=%s", w.Body)
		}
	}
	record, err := h.store.Inspect(context.Background(), prepared["operationRef"].(string))
	if err != nil || record.State != "proposed" {
		t.Fatalf("cross-session request changed proposal: %+v %v", record, err)
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 0 {
		t.Fatal("cross-session request dispatched")
	}
}

func TestDeploymentHTTPUnmatchedOrAmbiguousTargetNeverPrepares(t *testing.T) {
	for _, variant := range []string{"unknown source", "unknown algorithm", "duplicate source", "duplicate algorithm", "missing explicit enable"} {
		t.Run(variant, func(t *testing.T) {
			h := newDeploymentHTTPHarness(t)
			body := deploymentHTTPBody()
			h.client.mu.Lock()
			switch variant {
			case "unknown source":
				body["sourceName"] = "不存在"
			case "unknown algorithm":
				body["algorithmName"] = "不存在"
			case "duplicate source":
				h.client.cameras = append(h.client.cameras, device.Camera{ID: "other-source", Name: "入口"})
			case "duplicate algorithm":
				h.client.algorithms = append(h.client.algorithms, device.Algorithm{ID: "other-algorithm", Name: "行人检测"})
			case "missing explicit enable":
				delete(body, "enabled")
			}
			h.client.mu.Unlock()
			w, _ := h.call(t, "POST", "deployments", h.session(t), body)
			if w.Code != 409 && w.Code != 400 {
				t.Fatalf("unmatched=%s", w.Body)
			}
			h.client.mu.Lock()
			defer h.client.mu.Unlock()
			if h.client.writes != 0 || h.client.reads != 0 {
				t.Fatalf("writes=%d preparation reads=%d", h.client.writes, h.client.reads)
			}
		})
	}
}

func TestDeploymentHTTPHistoricalOutcomeAndCurrentStateRemainSeparate(t *testing.T) {
	for _, tc := range []struct {
		name, state, class, runtime string
		enabled                     int
		match, ok                   bool
	}{
		{"completed and currently processing", "completed", "completed", "processing", 1, true, true},
		{"unknown write but currently processing", "unknown", "unknown", "processing", 1, true, false},
		{"completed but current progress unknown", "completed", "completed", "unknown", 1, true, true},
		{"completed but current configuration changed", "completed", "completed", "processing", 1, false, true},
		{"stopped verified", "completed", "completed", "stopped", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			w := httptest.NewRecorder()
			s := deployment.Status{ActionRef: "operation-ref", State: tc.state, Class: tc.class, Conclusion: "原始执行结论。", Target: deployment.Proposal{SourceID: "private-source", AlgorithmID: "private-algorithm", ConfirmationToken: "expired-confirmation"},
				Current: &deployment.Observation{SourceID: "private-source", AlgorithmID: "private-algorithm", TaskID: "private-task", Exists: true, Enabled: tc.enabled, Runtime: tc.runtime, ConfigurationMatch: tc.match}}
			h.replyDeploymentStatus(w, s)
			var result struct {
				OK          bool              `json:"ok"`
				Deployment  deployment.Status `json:"deployment"`
				UserMessage string            `json:"userMessage"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.OK != tc.ok || result.Deployment.State != tc.state || result.Deployment.Class != tc.class || result.Deployment.Current.Runtime != tc.runtime || result.Deployment.Conclusion != s.Conclusion {
				t.Fatalf("outcome rewritten=%s", w.Body)
			}
			if strings.Contains(result.UserMessage, "执行结果还未确认") != (tc.state == "unknown") {
				t.Fatalf("current state replaced original execution uncertainty: %s", w.Body)
			}
			claimedProgress := strings.Contains(result.UserMessage, "目前正在运行")
			if claimedProgress != (tc.runtime == "processing" && tc.enabled == 1 && tc.match) {
				t.Fatalf("current claim=%s", w.Body)
			}
			for _, private := range []string{"private-source", "private-algorithm", "private-task", "expired-confirmation"} {
				if strings.Contains(w.Body.String(), private) {
					t.Fatalf("private target or stale confirmation exposed: %s", w.Body)
				}
			}
		})
	}
}

func TestDeploymentHTTPSealedSnapshotAndCurrentReadbackHaveIndependentTimes(t *testing.T) {
	originalTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	currentTime := originalTime.Add(time.Minute)
	for _, class := range []string{"completed", "unknown", "blocked"} {
		t.Run(class, func(t *testing.T) {
			original := &deployment.VerificationSnapshot{Exists: true, Enabled: 1, ConfigurationMatch: true, Runtime: "processing", Progress: []deployment.Progress{{NodeID: "private-node", Before: 4, After: 9}}, ObservedAt: originalTime, SealedAt: originalTime.Add(time.Second)}
			current := &deployment.Observation{SourceID: "private-source", AlgorithmID: "private-algorithm", TaskID: "private-task", Exists: true, Enabled: 0, ConfigurationMatch: true, Runtime: "stopped", ObservedAt: currentTime}
			s := deployment.Status{ActionRef: "operation-ref", State: class, Class: class, Conclusion: "原结果保留。", Dispatches: 1, DeviceWrites: 1, Target: deployment.Proposal{SourceID: "private-source", AlgorithmID: "private-algorithm"}, OriginalVerificationAvailable: true, OriginalVerification: original, Current: current}
			w := httptest.NewRecorder()
			(&Handler{}).replyDeploymentStatus(w, s)
			var got struct {
				OK         bool              `json:"ok"`
				Deployment deployment.Status `json:"deployment"`
				Message    string            `json:"userMessage"`
				Evidence   map[string]string `json:"deploymentEvidence"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Deployment.State != class || got.OK != (class == "completed") || got.Deployment.OriginalVerification.Enabled != 1 || got.Deployment.Current.Enabled != 0 || !got.Deployment.OriginalVerification.ObservedAt.Equal(originalTime) || !got.Deployment.Current.ObservedAt.Equal(currentTime) {
				t.Fatalf("mixed original/current: %s", w.Body)
			}
			for _, text := range []string{"此前已确认运行", "目前处于停用状态", "状态变化的原因还未确认"} {
				if !strings.Contains(got.Message, text) {
					t.Fatalf("missing %q: %s", text, got.Message)
				}
			}
			if got.Evidence["counterScope"] != "operation_lifetime" || got.Evidence["resultScope"] != "original_operation" || got.Evidence["originalVerificationScope"] != "immutable_sealed_readback" || got.Evidence["targetScope"] != "original_proposal" {
				t.Fatalf("scopes=%+v", got.Evidence)
			}
			for _, secret := range []string{"private-node", "private-source", "private-algorithm", "private-task", "payload_json"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatalf("raw evidence leaked: %s", w.Body)
				}
			}
			if original.Progress[0].NodeID != "private-node" || current.SourceID != "private-source" {
				t.Fatal("formatter mutated caller's retained facts")
			}
		})
	}
}

func TestDeploymentHTTPMissingSnapshotDoesNotBorrowCurrentTime(t *testing.T) {
	w := httptest.NewRecorder()
	(&Handler{}).replyDeploymentStatus(w, deployment.Status{ActionRef: "old-op", State: "completed", Class: "completed", Conclusion: "原结果保留。", Current: &deployment.Observation{Exists: true, Enabled: 0, Runtime: "stopped", ObservedAt: time.Now().UTC()}})
	var result struct {
		Deployment deployment.Status `json:"deployment"`
		Message    string            `json:"userMessage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Deployment.OriginalVerificationAvailable || result.Deployment.OriginalVerification != nil || strings.Contains(result.Message, "此前已确认") || !strings.Contains(result.Message, "目前处于停用状态") {
		t.Fatalf("invented original=%s", w.Body)
	}
}

func assertProposalOnlyScope(t *testing.T, result map[string]any) {
	t.Helper()
	evidence, ok := result["deploymentEvidence"].(map[string]any)
	if !ok || len(evidence) != 4 || evidence["resultScope"] != "proposal_only" || evidence["targetScope"] != "original_proposal" || evidence["currentScope"] != "not_provided" || evidence["currentReadbackProvided"] != false {
		t.Fatalf("proposal scope=%+v", result)
	}
	if result["current"] != nil || result["deployment"] != nil || result["confirmationToken"] != nil || result["confirmationReceipt"] != nil {
		t.Fatalf("proposal response invented current/authority=%+v", result)
	}
	message, _ := result["userMessage"].(string)
	for _, unnecessary := range []string{"未提供当前设备状态回读", "不能据此认定", "关闭页面不等于取消"} {
		if strings.Contains(message, unnecessary) {
			t.Fatalf("routine proposal reply repeats technical precautions: %q", message)
		}
	}
}

func TestPendingProposalAndPageReceiptsDoNotImplyUnchangedDevice(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	h.client.state.Enabled = 1
	owner := h.session(t)
	body := deploymentHTTPBody()
	body["enabled"] = false
	w, proposal := h.call(t, "POST", "deployments", owner, body)
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	assertProposalOnlyScope(t, proposal)
	ref := proposal["operationRef"].(string)
	// The device changes independently after the proposal is prepared. Reading
	// or opening that proposal must neither claim a fresh state nor read/write it.
	h.client.mu.Lock()
	h.client.state.Enabled = 0
	reads, snapshots, runtimeSamples := h.client.reads, h.client.snapshotReads, h.client.count
	h.client.mu.Unlock()
	for _, route := range []struct{ method, path string }{
		{"GET", "deployments/" + ref},
		{"GET", "deployments/by-request/lost-response-request"},
		{"POST", "deployments/review"},
		{"POST", "deployments/review"},
	} {
		w, result := h.call(t, route.method, route.path, owner, map[string]any{"operationRef": ref})
		if w.Code != 200 {
			t.Fatal(w.Body)
		}
		assertProposalOnlyScope(t, result)
		if route.method == "POST" && (result["pageOpened"] != true || !strings.Contains(result["userMessage"].(string), "确认页已打开")) {
			t.Fatal("page receipt changed its real meaning")
		}
	}
	h.handler.config.OpenDeploymentReview = nil
	w, result := h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	if w.Code != 503 || result["code"] != "local_review_unavailable" || result["pageOpened"] != false || result["operationRef"] != ref {
		t.Fatal("page failure lost original facts")
	}
	assertProposalOnlyScope(t, result)
	h.service.Close()
	w, result = h.call(t, "GET", "deployments/"+ref, owner, nil)
	if w.Code != 200 || result["code"] != "local_confirmation_unavailable" || result["supportedInteraction"] != "none" {
		t.Fatal("expired local authority changed semantics")
	}
	assertProposalOnlyScope(t, result)
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.reads != reads || h.client.snapshotReads != snapshots || h.client.count != runtimeSamples || h.client.writes != 0 {
		t.Fatalf("proposal query accessed device: reads=%d snapshots=%d runtime=%d writes=%d", h.client.reads, h.client.snapshotReads, h.client.count, h.client.writes)
	}
	record, err := h.store.Inspect(context.Background(), ref)
	if err != nil || record.State != "proposed" || record.Dispatches != 0 || record.DeviceWrites != 0 {
		t.Fatal("proposal-only interaction changed dispatch accounting")
	}
}

func TestCancelledProposalStillReturnsActualCurrentReadback(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	h.client.state.Enabled = 1
	owner := h.session(t)
	body := deploymentHTTPBody()
	body["enabled"] = false
	_, proposal := h.call(t, "POST", "deployments", owner, body)
	ref := proposal["operationRef"].(string)
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	cookie := h.browser(t)
	if w := h.localCall(t, "GET", cookie, ""); w.Code != 200 {
		t.Fatal(w.Body)
	}
	// An independent stop is visible in the post-cancel readback. Cancelling
	// the proposal itself remains zero dispatch/write and is not its cause.
	h.client.mu.Lock()
	h.client.state.Enabled = 0
	h.client.mu.Unlock()
	if w := h.localCall(t, "POST", cookie, `{"decision":"cancel"}`); w.Code != 200 {
		t.Fatal(w.Body)
	}
	w, result := h.call(t, "GET", "deployments/"+ref, owner, nil)
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	status := result["deployment"].(map[string]any)
	current := status["current"].(map[string]any)
	evidence := result["deploymentEvidence"].(map[string]any)
	if status["state"] != "blocked" || status["reason"] != "cancelled_by_user" || status["dispatches"] != float64(0) || status["deviceWrites"] != float64(0) || current["enabled"] != float64(0) || current["runtime"] != "stopped" || current["observedAt"] == nil {
		t.Fatalf("cancel/current facts changed=%+v", result)
	}
	if evidence["resultScope"] != "original_operation" || evidence["currentScope"] != "readback_at_observed_at" || strings.Contains(result["userMessage"].(string), "本回执仅说明该提议尚未派发") {
		t.Fatal("actual current readback was replaced by proposal-only wording")
	}
}

func TestDeploymentHTTPWriteAccountingDoesNotInventZeroWriteReason(t *testing.T) {
	for _, tc := range []struct {
		name, outcome      string
		dispatches, writes int
	}{
		{"accepted noop", "accepted", 1, 0},
		{"accepted switch", "accepted", 1, 1},
		{"known failure", "known_failed", 1, 0},
		{"unknown before write", "outcome_unknown", 1, 0},
		{"unknown after write", "outcome_unknown", 1, 1},
		{"legacy missing outcome", "", 1, 0},
		{"no dispatch", "", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Handler{}).replyDeploymentStatus(w, deployment.Status{ActionRef: "op-one", State: "unknown", Class: "unknown", DispatchOutcome: tc.outcome, Dispatches: tc.dispatches, DeviceWrites: tc.writes})
			var got struct {
				Message    string            `json:"userMessage"`
				Evidence   map[string]string `json:"deploymentEvidence"`
				Deployment deployment.Status `json:"deployment"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got.Message, "执行结果还未确认") || !strings.Contains(got.Message, "暂时没取到最新状态") || strings.Contains(got.Message, "写入") || got.Evidence["deviceWriteScope"] != "configuration_and_enable_switch_accounting" || got.Evidence["counterScope"] != "operation_lifetime" || got.Deployment.DispatchOutcome != tc.outcome || got.Deployment.Class != "unknown" || got.Deployment.Dispatches != tc.dispatches || got.Deployment.DeviceWrites != tc.writes {
				t.Fatalf("accounting message promoted/mixed facts=%s", w.Body)
			}
		})
	}
}
