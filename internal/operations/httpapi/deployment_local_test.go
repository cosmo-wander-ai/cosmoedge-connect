package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deploymentlocal"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	ordinaryweb "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/web"
)

func TestDeploymentModelCannotConfirmEvenWithOriginalToken(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	w, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	sum := sha256.Sum256([]byte(owner))
	s, err := h.service.GetByRequest(context.Background(), hex.EncodeToString(sum[:]), "lost-response-request")
	if err != nil || s.Target.ConfirmationToken == "" {
		t.Fatal("test authority unavailable")
	}
	for _, token := range []string{"invented", s.Target.ConfirmationToken} {
		w, result := h.call(t, "POST", "deployments/confirm", owner, map[string]any{"operationRef": p["operationRef"], "confirmationToken": token})
		if w.Code != 409 || result["code"] != "local_confirmation_required" {
			t.Fatalf("legacy=%s", w.Body)
		}
	}
	record, _ := h.store.Inspect(context.Background(), s.ActionRef)
	if record.State != "proposed" || record.Dispatches != 0 || record.DeviceWrites != 0 {
		t.Fatalf("model confirmed=%+v", record)
	}
	for _, path := range []string{"deployments/" + s.ActionRef, "deployments/by-request/lost-response-request"} {
		w, _ := h.call(t, "GET", path, owner, nil)
		if strings.Contains(w.Body.String(), "confirmationToken") || strings.Contains(w.Body.String(), s.Target.ConfirmationToken) {
			t.Fatal("read leaked authority")
		}
	}
}

func TestLocalDeploymentRequiresRenderedBoundBrowserAndExactPost(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	_, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
	cookie := h.browser(t)
	if w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`); w.Code != 403 {
		t.Fatal("post without rendered review accepted")
	}
	if w := h.localCall(t, "GET", cookie, ""); w.Code != 200 {
		t.Fatal(w.Body)
	}
	auth, _ := h.vault.Authenticate(cookie.Value)
	for _, tc := range []struct{ name, origin, csrf, body, host, path string }{
		{"origin", "http://outside.invalid", auth.CSRF, `{"decision":"confirm"}`, "127.0.0.1:37790", deploymentlocal.Path},
		{"csrf", "http://127.0.0.1:37790", "bad", `{"decision":"confirm"}`, "127.0.0.1:37790", deploymentlocal.Path},
		{"owner injection", "http://127.0.0.1:37790", auth.CSRF, `{"decision":"confirm","owner":"other","operationRef":"other"}`, "127.0.0.1:37790", deploymentlocal.Path},
		{"trailing json", "http://127.0.0.1:37790", auth.CSRF, `{"decision":"confirm"}{}`, "127.0.0.1:37790", deploymentlocal.Path},
		{"host", "http://127.0.0.1:37790", auth.CSRF, `{"decision":"confirm"}`, "evil.invalid", deploymentlocal.Path},
		{"query", "http://127.0.0.1:37790", auth.CSRF, `{"decision":"confirm"}`, "127.0.0.1:37790", deploymentlocal.Path + "?operationRef=other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "http://"+tc.host+tc.path, strings.NewReader(tc.body))
			r.AddCookie(cookie)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-CosmoEdge-CSRF", tc.csrf)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.local.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatalf("accepted %s", tc.name)
			}
		})
	}
	bootstrap, _ := h.vault.IssueBootstrap()
	other, _ := h.vault.ConsumeBootstrap(bootstrap)
	if w := h.localCall(t, "GET", &http.Cookie{Name: ordinaryweb.SessionCookieName, Value: other.SessionID}, ""); w.Code != 403 {
		t.Fatal("ordinary browser entered proposal")
	}
	record, _ := h.store.Inspect(context.Background(), p["operationRef"].(string))
	if record.State != "proposed" || record.Dispatches != 0 {
		t.Fatal("invalid browser post queued")
	}
}

func TestLocalDeploymentCancelRevokesProposalWithoutDeviceWrite(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	_, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
	cookie := h.browser(t)
	h.localCall(t, "GET", cookie, "")
	for i := 0; i < 2; i++ {
		if w := h.localCall(t, "POST", cookie, `{"decision":"cancel"}`); w.Code != 200 {
			t.Fatal(w.Body)
		}
	}
	if w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`); w.Code != 409 {
		t.Fatal("cancelled grant accepted")
	}
	record, _ := h.store.Inspect(context.Background(), p["operationRef"].(string))
	if record.State != "blocked" || record.Reason != "cancelled_by_user" || record.Dispatches != 0 || record.DeviceWrites != 0 {
		t.Fatalf("cancel=%+v", record)
	}
	h.openedURL = ""
	_, result := h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
	if result["pageOpened"] != false || h.openedURL != "" {
		t.Fatal("cancelled proposal reopened authority")
	}
}

func TestDeploymentHTTPCancelNeedsNoReviewAndRevokesOldPage(t *testing.T) {
	for _, opened := range []bool{false, true} {
		name := "unopened enable"
		if opened {
			name = "opened stop"
		}
		t.Run(name, func(t *testing.T) {
			h := newDeploymentHTTPHarness(t)
			body := deploymentHTTPBody()
			if opened {
				h.client.state.Enabled = 1
				body["enabled"] = false
			}
			owner := h.session(t)
			_, p := h.call(t, "POST", "deployments", owner, body)
			ref := p["operationRef"].(string)
			var cookie *http.Cookie
			if opened {
				h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
				cookie = h.browser(t)
				if w := h.localCall(t, "GET", cookie, ""); w.Code != http.StatusOK {
					t.Fatal(w.Body)
				}
			}
			for _, invalid := range []map[string]any{{}, {"operationRef": ref, "enabled": false}, {"operationRef": ref, "owner": "other"}} {
				if w, _ := h.call(t, "POST", "deployments/cancel", owner, invalid); w.Code != http.StatusBadRequest {
					t.Fatalf("invalid cancellation accepted: %s", w.Body)
				}
			}
			for i := 0; i < 2; i++ {
				w, response := h.call(t, "POST", "deployments/cancel", owner, map[string]any{"operationRef": ref})
				if w.Code != http.StatusOK || response["ok"] != true || response["cancelled"] != true || response["operationRef"] != ref || response["interactionRequired"] == true || response["pageOpened"] != false {
					t.Fatalf("cancellation required another confirmation or lost original: %s", w.Body)
				}
				status := response["deployment"].(map[string]any)
				if status["state"] != "blocked" || status["reason"] != "cancelled_by_user" || strings.Contains(w.Body.String(), "confirmationToken") {
					t.Fatalf("cancellation receipt lost actual state: %s", w.Body)
				}
			}
			if cookie != nil {
				if w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`); w.Code != http.StatusConflict {
					t.Fatal("old rendered page confirmed a cancelled proposal")
				}
			}
			h.openedURL = ""
			_, response := h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
			if response["pageOpened"] != false || h.openedURL != "" {
				t.Fatal("cancelled proposal reopened confirmation")
			}
			record, err := h.store.Inspect(context.Background(), ref)
			if err != nil || record.State != "blocked" || record.Reason != "cancelled_by_user" || record.Dispatches != 0 || record.DeviceWrites != 0 {
				t.Fatalf("cancellation dispatched: %+v %v", record, err)
			}
			h.client.mu.Lock()
			defer h.client.mu.Unlock()
			if h.client.writes != 0 || (h.client.state.Enabled == 1) != opened {
				t.Fatal("cancelling a proposal changed the device enable state")
			}
		})
	}
}

func TestDeploymentHTTPCancelPreservesExpiredState(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	_, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	ref := p["operationRef"].(string)
	record, err := h.store.Inspect(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	// Advance the ledger confirmation clock, without executing or waiting for
	// the real proposal TTL; this records the existing expiry transition.
	if err := h.store.Confirm(context.Background(), ref, record.SessionBinding, record.ExpiresAt.Add(time.Second)); err == nil {
		t.Fatal("expired confirmation accepted")
	}
	w, response := h.call(t, "POST", "deployments/cancel", owner, map[string]any{"operationRef": ref})
	if w.Code != http.StatusConflict || response["cancelled"] != false || response["deployment"].(map[string]any)["reason"] != "proposal_expired" || !strings.Contains(response["userMessage"].(string), "已经过期") {
		t.Fatalf("expiry was replaced with cancellation: %s", w.Body)
	}
	record, err = h.store.Inspect(context.Background(), ref)
	if err != nil || record.State != "blocked" || record.Reason != "proposal_expired" || record.Dispatches != 0 || record.DeviceWrites != 0 {
		t.Fatalf("expired operation changed: %+v %v", record, err)
	}
}

func TestDeploymentHTTPCancelAndLocalConfirmHaveOneWinner(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	_, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	ref := p["operationRef"].(string)
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	cookie := h.browser(t)
	if w := h.localCall(t, "GET", cookie, ""); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	type outcome struct {
		cancel bool
		code   int
		result map[string]any
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	go func() {
		<-start
		w, result := h.call(t, "POST", "deployments/cancel", owner, map[string]any{"operationRef": ref})
		results <- outcome{cancel: true, code: w.Code, result: result}
	}()
	go func() {
		<-start
		w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`)
		results <- outcome{code: w.Code}
	}()
	close(start)
	var cancelled bool
	accepted := 0
	for i := 0; i < 2; i++ {
		result := <-results
		if result.code != http.StatusOK && result.code != http.StatusConflict {
			t.Fatalf("unexpected race response: %+v", result)
		}
		if result.code == http.StatusOK {
			accepted++
		}
		if result.cancel {
			cancelled = result.code == http.StatusOK
			if result.result["cancelled"] != cancelled {
				t.Fatalf("cancellation claimed the losing transition: %+v", result)
			}
		}
	}
	if accepted != 1 {
		t.Fatal("cancel and confirm did not have exactly one winner")
	}
	h.worker.Wake()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		record, err := h.store.Inspect(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if cancelled && record.State == "blocked" && record.Reason == "cancelled_by_user" && record.Dispatches == 0 && record.DeviceWrites == 0 {
			return
		}
		if !cancelled && record.State == "completed" && record.Dispatches == 1 && record.DeviceWrites == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("winning decision did not retain the expected single-operation outcome")
}

func TestLocalDeploymentLostAuthorityAndOpenFailurePreserveOriginal(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	_, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
	cookie := h.browser(t)
	h.localCall(t, "GET", cookie, "")
	h.service.Close()
	if w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`); w.Code != 409 {
		t.Fatal("lost process authority reused")
	}
	h.openedURL = ""
	_, result := h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
	if result["code"] != "local_confirmation_unavailable" || h.openedURL != "" {
		t.Fatal("lost authority recreated")
	}
	h2 := newDeploymentHTTPHarness(t)
	o2 := h2.session(t)
	_, p2 := h2.call(t, "POST", "deployments", o2, deploymentHTTPBody())
	h2.handler.config.OpenDeploymentReview = nil
	w, result := h2.call(t, "POST", "deployments/review", o2, map[string]any{"operationRef": p2["operationRef"]})
	if w.Code != 503 || result["operationRef"] != p2["operationRef"] || result["pageOpened"] != false {
		t.Fatal("open failure lost original")
	}
	record, _ := h2.store.Inspect(context.Background(), p2["operationRef"].(string))
	if record.State != "proposed" || record.Dispatches != 0 {
		t.Fatal("opening failure dispatched")
	}
}

func TestDeploymentMissingConfigurationIsNotAProposalOrAnROILink(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	h.client.state.Exists = false
	h.client.defaults = device.DeploymentConfiguration{Missing: []string{"检测区域或检测线"}}
	owner := h.session(t)
	w, result := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	if w.Code != 200 || result["ok"] != false || result["interactionRequired"] != false || result["proposalCreated"] != false || result["proposal"] != nil || result["configurationRequirement"] == nil || result["supportedInteraction"] != "none" || result["operationRef"] != nil {
		t.Fatalf("missing config=%s", w.Body)
	}
	h.handler.config.OpenConnection = func() error { return nil }
	w, result = h.call(t, "POST", "connection", owner, map[string]any{})
	if result["supportedInteraction"] != "connection_only" || !strings.Contains(result["userMessage"].(string), "不提供") {
		t.Fatalf("connection capability=%s", w.Body)
	}
}

func TestLocalDeploymentExpiryAndGenerationCloseNeverQueue(t *testing.T) {
	for _, mode := range []string{"expiry", "generation_close"} {
		t.Run(mode, func(t *testing.T) {
			h := newDeploymentHTTPHarness(t)
			owner := h.session(t)
			_, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
			h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
			cookie := h.browser(t)
			h.localCall(t, "GET", cookie, "")
			if mode == "expiry" {
				future := time.Now().Add(time.Hour)
				h.now = func() time.Time { return future }
			} else {
				h.gate.Close()
			}
			if w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`); w.Code != 410 {
				t.Fatal("expired page confirmed")
			}
			record, _ := h.store.Inspect(context.Background(), p["operationRef"].(string))
			if record.State != "proposed" || record.Dispatches != 0 || record.DeviceWrites != 0 {
				t.Fatal("revoked gate dispatched")
			}
		})
	}
}

func TestStopNeedsLocalClickAndReviewCannotReconfirmAcceptedAction(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	h.client.state.Enabled = 1
	owner := h.session(t)
	body := deploymentHTTPBody()
	body["enabled"] = false
	_, p := h.call(t, "POST", "deployments", owner, body)
	ref := p["operationRef"].(string)
	if w, result := h.call(t, "POST", "deployments/confirm", owner, map[string]any{"operationRef": ref}); w.Code != 409 || result["code"] != "local_confirmation_required" {
		t.Fatal("model stop confirmation allowed")
	}
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	cookie := h.browser(t)
	if w := h.localCall(t, "GET", cookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "确认停用") || !strings.Contains(w.Body.String(), "保留该绑定已保存的参数") {
		t.Fatal("stop target not shown")
	}
	before, _ := h.store.Inspect(context.Background(), ref)
	if before.State != "proposed" || before.Dispatches != 0 {
		t.Fatal("stop queued without click")
	}
	if w := h.localCall(t, "POST", cookie, `{"decision":"confirm"}`); w.Code != 200 {
		t.Fatal(w.Body)
	}
	h.openedURL = ""
	w, result := h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": ref})
	if w.Code != 200 || result["pageOpened"] != false || h.openedURL != "" || result["confirmationReceipt"] != nil {
		t.Fatal("accepted stop regained page authority")
	}
	h.worker.Wake()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := h.store.Inspect(context.Background(), ref)
		if r.State == "completed" {
			if r.Dispatches != 1 || r.DeviceWrites != 1 {
				t.Fatal("wrong stop counts")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("stop did not finish")
}

func TestLocalDeploymentPageEscapesNamesAndOnlyBindsButtonEvents(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	name := `入口</dd><script>decide('confirm')</script>`
	h.client.cameras[0].Name = name
	body := deploymentHTTPBody()
	body["sourceName"] = name
	owner := h.session(t)
	_, p := h.call(t, "POST", "deployments", owner, body)
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
	cookie := h.browser(t)
	w := h.localCall(t, "GET", cookie, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), name) || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("unescaped display name")
	}
	if !strings.Contains(w.Body.String(), "addEventListener('click',()=>decide('confirm'))") || strings.Contains(w.Body.String(), "confirmationToken") {
		t.Fatal("page is not button bound")
	}
	if !regexp.MustCompile(`(?s)<details><summary>配置详情</summary>.*?项参数.*?检测区域.*?</details>`).MatchString(w.Body.String()) || strings.Contains(w.Body.String(), "<details open") {
		t.Fatal("technical configuration counts are not in collapsed details")
	}
	record, _ := h.store.Inspect(context.Background(), p["operationRef"].(string))
	if record.State != "proposed" || record.Dispatches != 0 {
		t.Fatal("page display queued")
	}
	match := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("page script missing")
	}
	script, _ := json.Marshal(match[1])
	js := `const vm=require('node:vm');const assert=require('node:assert/strict');
async function click(decision,status,networkFailure=false){
 const listeners={};const nodes={confirm:{addEventListener:(e,f)=>listeners.confirm=f},cancel:{addEventListener:(e,f)=>listeners.cancel=f},message:{}};const calls=[];
 const context={document:{querySelectorAll:()=>[nodes.confirm,nodes.cancel],getElementById:id=>nodes[id]},fetch:async(path,options)=>{calls.push({path,body:JSON.parse(options.body)});if(networkFailure)throw new Error('offline');return {ok:status===200,status,json:async()=>({userMessage:'accepted'})}}};
 vm.runInNewContext(` + string(script) + `,context);assert.equal(calls.length,0);
 await listeners[decision]();assert.equal(calls.length,1);assert.equal(calls[0].path,'/deployment/review');assert.equal(calls[0].body.decision,decision);assert.deepEqual(Object.keys(calls[0].body),['decision']);assert.equal(nodes.confirm.disabled,true);assert.equal(nodes.cancel.disabled,true);
 return nodes.message.textContent;
}
(async()=>{
 assert.equal(await click('confirm',200),'accepted');
 assert.equal(await click('cancel',200),'accepted');
 for(const status of [401,403]){const m=await click('confirm',status);assert.match(m,/确认未被接受/);assert.match(m,/重新打开同一方案/);assert.doesNotMatch(m,/过期|未抵达/);}
 const conflict=await click('confirm',409);assert.match(conflict,/确认未被接受/);assert.match(conflict,/查询原方案状态/);assert.doesNotMatch(conflict,/过期|重新发起/);
 assert.match(await click('confirm',410),/已过期或失效/);
 assert.match(await click('cancel',403),/取消未被接受/);
 for(const m of [await click('confirm',500),await click('confirm',0,true)]){assert.match(m,/未取得确认结果/);assert.match(m,/查询原方案状态/);assert.doesNotMatch(m,/未被接受|重新发起/);}
})().catch(e=>{console.error(e);process.exitCode=1});`
	if out, err := exec.Command("node", "-e", js).CombinedOutput(); err != nil {
		t.Fatalf("review script event contract: %v %s", err, out)
	}
}

func TestLocalDeploymentConcurrentClicksAcceptOnce(t *testing.T) {
	h := newDeploymentHTTPHarness(t)
	owner := h.session(t)
	_, p := h.call(t, "POST", "deployments", owner, deploymentHTTPBody())
	h.call(t, "POST", "deployments/review", owner, map[string]any{"operationRef": p["operationRef"]})
	cookie := h.browser(t)
	h.localCall(t, "GET", cookie, "")
	auth, _ := h.vault.Authenticate(cookie.Value)
	results := make(chan string, 2)
	for i := 0; i < 2; i++ {
		go func() {
			r := httptest.NewRequest("POST", "http://127.0.0.1:37790"+deploymentlocal.Path, strings.NewReader(`{"decision":"confirm"}`))
			r.AddCookie(cookie)
			r.Header.Set("Origin", "http://127.0.0.1:37790")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CosmoEdge-CSRF", auth.CSRF)
			w := httptest.NewRecorder()
			h.local.ServeHTTP(w, r)
			var result map[string]string
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
				results <- "error"
				return
			}
			results <- result["status"]
		}()
	}
	seen := map[string]int{}
	seen[<-results]++
	seen[<-results]++
	if seen["accepted"] != 1 || seen["already_confirmed"] != 1 {
		t.Fatalf("concurrent receipts=%v", seen)
	}
	h.worker.Wake()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := h.store.Inspect(context.Background(), p["operationRef"].(string))
		if r.State == "completed" {
			if r.Dispatches != 1 || r.DeviceWrites != 1 {
				t.Fatal("duplicate dispatch")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("confirmation did not complete")
}
