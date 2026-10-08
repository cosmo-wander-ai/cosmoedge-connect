package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deployment"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deploymentlocal"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

type deploymentHTTPRejected struct{}

func (deploymentHTTPRejected) Error() string {
	return "native response password=private-secret rtsp://private.invalid/feed"
}
func (deploymentHTTPRejected) KnownFailure() bool { return true }

func TestDeploymentHTTPRejectProjectsSafeCauseAndOneCurrentState(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	zero := 0
	h.client.writeErr = safediagnostic.Wrap(deploymentHTTPRejected{}, safediagnostic.Diagnostic{
		Operation: safediagnostic.OperationTaskSwitch, Phase: safediagnostic.PhaseNativeResponse,
		Class: safediagnostic.ClassNativeRejected, HTTPStatus: 200, ResCode: &zero, MsgCode: "8",
	})
	owner := h.session(t)
	_, proposal := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	ref := proposal["operationRef"].(string)
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	cookie := h.browser(t)
	h.localCall(t, "GET", cookie, "")
	if w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	h.worker.Wake()
	deadline := time.Now().Add(5 * time.Second)
	for {
		record, err := h.store.Inspect(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if record.State == "blocked" {
			if record.Dispatches != 1 || record.DeviceWrites != 0 || record.DispatchOutcome != "known_failed" {
				t.Fatalf("native rejection accounting changed: %+v", record)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native rejection did not settle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, path := range []string{"deployments/" + ref, "deployments/by-request/lost-response-request"} {
		w, response := h.call(t, "GET", path, owner, nil)
		status := response["deployment"].(map[string]any)
		target := status["target"].(map[string]any)
		diagnostic := status["diagnostic"].(map[string]any)
		if w.Code != http.StatusOK || status["state"] != "blocked" || target["state"] != nil || target["expiresAt"] == nil || target["enabled"] != true {
			t.Fatalf("target snapshot masquerades as current state: %s", w.Body)
		}
		if diagnostic["msgCode"] != "8" || diagnostic["resCode"] != float64(0) || diagnostic["operation"] != "task_switch" || len(diagnostic) != 6 || !strings.Contains(status["diagnosticMessage"].(string), "资源不足") || !strings.Contains(response["userMessage"].(string), "资源不足") {
			t.Fatalf("safe native reason missing: %s", w.Body)
		}
		for _, secret := range []string{"private-secret", "private.invalid", "password=", "msgText", "responseBody"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatalf("native response leaked: %s", secret)
			}
		}
	}
	record, _ := h.store.Inspect(context.Background(), ref)
	var original map[string]any
	if err := json.Unmarshal([]byte(record.PublicJSON), &original); err != nil || original["target"].(map[string]any)["state"] != "proposed" {
		t.Fatal("public projection rewrote the original ledger target")
	}
	h.client.mu.Lock()
	defer h.client.mu.Unlock()
	if h.client.writes != 1 || h.client.state.Enabled != 0 {
		t.Fatal("read-only status replayed the rejected write")
	}
}

func TestDeploymentHTTPUnknownDoesNotPublishOldProposedState(t *testing.T) {
	w := httptest.NewRecorder()
	s := deployment.Status{ActionRef: "original-op", State: "unknown", Class: "unknown", Dispatches: 1, DeviceWrites: 1, DispatchOutcome: "accepted",
		Target:  deployment.Proposal{State: "proposed", SourceName: "入口", AlgorithmName: "行人检测", Enabled: true, ExpiresAt: time.Now()},
		Current: &deployment.Observation{Exists: true, Enabled: 1, ConfigurationMatch: true, Runtime: "unknown"}}
	(&Handler{}).replyDeploymentStatus(w, s)
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	status := response["deployment"].(map[string]any)
	if response["ok"] != false || status["state"] != "unknown" || status["target"].(map[string]any)["state"] != nil || response["supportedInteraction"] != "none" || response["interactionRequired"] == true {
		t.Fatalf("unknown gained a stale confirmation state: %s", w.Body)
	}
	if s.Target.State != "proposed" {
		t.Fatal("formatter mutated its caller")
	}
}

func TestLocalDeploymentNewCookieRejectsOldPageWithoutDispatch(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	_, proposal := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	ref := proposal["operationRef"].(string)
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	oldCookie := h.browser(t)
	h.localCall(t, "GET", oldCookie, "")
	oldAuth, _ := h.vault.Authenticate(oldCookie.Value)
	// Opening another protected page overwrites this origin's browser cookie.
	// The old DOM still sends its own CSRF value; it must not confirm another gate.
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	newCookie := h.browser(t)
	h.localCall(t, "GET", newCookie, "")
	r := httptest.NewRequest("POST", "http://127.0.0.1:37790"+deploymentlocal.Path, strings.NewReader(`{"decision":"confirm"}`))
	r.AddCookie(newCookie)
	r.Header.Set("Origin", "http://127.0.0.1:37790")
	r.Header.Set("X-CosmoEdge-CSRF", oldAuth.CSRF)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.local.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("old page accepted a replaced cookie: %d", w.Code)
	}
	record, _ := h.store.Inspect(context.Background(), ref)
	if record.State != "proposed" || record.Dispatches != 0 || record.DeviceWrites != 0 {
		t.Fatal("rejected browser binding dispatched")
	}
	// The same operation can still be confirmed from its fresh, matching page.
	if w := h.localCall(t, "POST", newCookie, `{"decision":"confirm"}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "已确认，正在处理") {
		t.Fatalf("same operation could not recover its confirmation: %s", w.Body)
	}
}
