package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)

var (
	testBearerToken  = strings.Repeat("a", 64)
	testBearerDigest = func() string {
		digest := sha256.Sum256([]byte(testBearerToken))
		return hex.EncodeToString(digest[:])
	}()
)

type fixtureAuthorizer struct {
	session SessionBinding
	err     error
	scopes  []Scope
	digests []string
}

func (a *fixtureAuthorizer) Authorize(_ context.Context, request AuthorizationRequest) (Authorization, error) {
	a.scopes = append(a.scopes, request.Scope)
	a.digests = append(a.digests, request.CredentialSHA256)
	if request.CredentialSHA256 != testBearerDigest {
		return Authorization{}, ErrUnauthenticated
	}
	if a.err != nil {
		return Authorization{}, a.err
	}
	return Authorization{Session: a.session, Scope: request.Scope}, nil
}

type backendCall struct {
	name        string
	session     SessionBinding
	ref         string
	idempotency string
	request     InspectionRequest
	feedback    FeedbackRequest
}

type fixtureBackend struct {
	capabilities CapabilitySet
	run          RunView
	result       ResultView
	media        MediaPayload
	receipt      FeedbackReceipt
	created      bool
	errByCall    map[string]error
	calls        []backendCall
}

func (b *fixtureBackend) callError(name string) error {
	if b.errByCall == nil {
		return nil
	}
	return b.errByCall[name]
}

func (b *fixtureBackend) QueryCapabilities(_ context.Context, session SessionBinding) (CapabilitySet, error) {
	b.calls = append(b.calls, backendCall{name: "capabilities", session: session})
	return b.capabilities, b.callError("capabilities")
}

func (b *fixtureBackend) ResolveContinuation(_ context.Context, session SessionBinding) (ContinuationResolution, error) {
	b.calls = append(b.calls, backendCall{name: "continuation", session: session})
	return ContinuationResolution{Status: ContinuationNone}, b.callError("continuation")
}

func (b *fixtureBackend) RequestInspection(_ context.Context, session SessionBinding, request InspectionRequest, key string) (RunView, bool, error) {
	b.calls = append(b.calls, backendCall{name: "request", session: session, request: request, idempotency: key})
	return b.run, b.created, b.callError("request")
}

func (b *fixtureBackend) GetRun(_ context.Context, session SessionBinding, ref string) (RunView, error) {
	b.calls = append(b.calls, backendCall{name: "run", session: session, ref: ref})
	return b.run, b.callError("run")
}

func (b *fixtureBackend) GetResult(_ context.Context, session SessionBinding, ref string) (ResultView, error) {
	b.calls = append(b.calls, backendCall{name: "result", session: session, ref: ref})
	return b.result, b.callError("result")
}

func (b *fixtureBackend) GetMedia(_ context.Context, session SessionBinding, ref string) (MediaPayload, error) {
	b.calls = append(b.calls, backendCall{name: "media", session: session, ref: ref})
	return b.media, b.callError("media")
}

func (b *fixtureBackend) SubmitFeedback(_ context.Context, session SessionBinding, ref string, request FeedbackRequest, key string) (FeedbackReceipt, bool, error) {
	b.calls = append(b.calls, backendCall{name: "feedback", session: session, ref: ref, feedback: request, idempotency: key})
	return b.receipt, b.created, b.callError("feedback")
}

func fixtureHandler(t *testing.T) (*Handler, *fixtureBackend, *fixtureAuthorizer) {
	t.Helper()
	png := append([]byte("\x89PNG\r\n\x1a\n"), []byte("fixture")...)
	digest := sha256.Sum256(png)
	backend := &fixtureBackend{
		capabilities: CapabilitySet{
			ContextLabel: "当前门店",
			Capabilities: []CapabilityView{{
				CapabilityRef: "inspection.scene", Title: "现场巡检", Description: "根据你的问题查看现场情况",
				Examples: []string{"看看入口现在是否拥堵", "检查指定区域的物品摆放"},
			}},
		},
		run: RunView{RunRef: "run-public-1", Status: RunWorking, Message: "正在查看现场情况", SubmittedAt: testNow, UpdatedAt: testNow},
		result: ResultView{
			RunRef: "run-public-1", Summary: "已完成现场查看。", CompletedAt: testNow.Add(time.Second),
			Sections: []ResultSection{{
				Title: "入口区域", Conclusion: "当前通行基本顺畅", Details: []string{"未发现明显排队"},
				Evidence: []MediaCapability{{MediaRef: "media-public-1", Capability: "inspection.media.deliver", MediaType: "image/png", Title: "入口现场图片"}},
			}},
			Limitations: []string{"画面外区域无法判断"},
		},
		media:   MediaPayload{ContentType: "image/png", SHA256: hex.EncodeToString(digest[:]), Bytes: png},
		receipt: FeedbackReceipt{Accepted: true},
		created: true,
	}
	authorizer := &fixtureAuthorizer{session: SessionBinding{
		TenantID: "tenant-a", SiteID: "site-a", Channel: "workbuddy_wechat",
		ConversationRef: "conversation-a", RecipientRef: "recipient-a", PrincipalSHA256: strings.Repeat("1", 64),
	}}
	handler, err := NewHandler(backend, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	return handler, backend, authorizer
}

func TestV2RoutesPropagateBoundSessionAndScopes(t *testing.T) {
	handler, backend, authorizer := fixtureHandler(t)

	requests := []*http.Request{
		request(http.MethodGet, capabilitiesPath, nil, ""),
		request(http.MethodPost, requestsPath, []byte(`{"instruction":"请查看一号入口现在是否拥堵","context":[{"name":"关注点","value":"人员排队"}]}`), "request-1"),
		request(http.MethodGet, runsPath+"/run-public-1", nil, ""),
		request(http.MethodGet, runsPath+"/run-public-1/result", nil, ""),
		request(http.MethodGet, mediaPath+"/media-public-1", nil, ""),
		request(http.MethodPost, runsPath+"/run-public-1/feedback", []byte(`{"helpful":true,"comment":"结果有帮助"}`), "feedback-1"),
	}
	wantStatuses := []int{http.StatusOK, http.StatusCreated, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusCreated}
	for i, input := range requests {
		response := serve(handler, input)
		if response.Code != wantStatuses[i] {
			t.Fatalf("request %d status=%d body=%s", i, response.Code, response.Body.String())
		}
		assertNoStore(t, response)
	}

	wantScopes := []Scope{ScopeCapabilitiesRead, ScopeRequestCreate, ScopeRunRead, ScopeResultRead, ScopeMediaDeliver, ScopeFeedbackCreate}
	if strings.Join(scopesToStrings(authorizer.scopes), ",") != strings.Join(scopesToStrings(wantScopes), ",") {
		t.Fatalf("scopes=%v want=%v", authorizer.scopes, wantScopes)
	}
	if len(backend.calls) != 6 {
		t.Fatalf("backend calls=%d", len(backend.calls))
	}
	for _, call := range backend.calls {
		if call.session != authorizer.session {
			t.Fatalf("%s received session %#v", call.name, call.session)
		}
	}
	if backend.calls[1].idempotency != "request-1" || backend.calls[1].request.Instruction != "请查看一号入口现在是否拥堵" {
		t.Fatalf("request call=%#v", backend.calls[1])
	}
	if backend.calls[5].idempotency != "feedback-1" || backend.calls[5].feedback.Helpful == nil || !*backend.calls[5].feedback.Helpful {
		t.Fatalf("feedback call=%#v", backend.calls[5])
	}
}

func TestPublicResponsesExcludeSessionAndPrivateRuntimeData(t *testing.T) {
	handler, _, _ := fixtureHandler(t)
	for _, path := range []string{capabilitiesPath, runsPath + "/run-public-1", runsPath + "/run-public-1/result"} {
		response := serve(handler, request(http.MethodGet, path, nil, ""))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		lower := strings.ToLower(response.Body.String())
		for _, forbidden := range []string{
			"tenant-a", "site-a", "wechat-session-a", "tenantid", "siteid", "channelid", "source", "camera", "device",
			"prompt", "modelversion", "adapterversion", "credential", "password", "token", "filepath", "http://", "rtsp://",
			strings.Repeat("1", 64),
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s leaked %q: %s", path, forbidden, response.Body.String())
			}
		}
	}
}

func TestResultContainsOnlyDeliverableMediaCapability(t *testing.T) {
	handler, _, _ := fixtureHandler(t)
	response := serve(handler, request(http.MethodGet, runsPath+"/run-public-1/result", nil, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result ResultView
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	evidence := result.Sections[0].Evidence[0]
	if evidence.MediaRef != "media-public-1" || evidence.Capability != "inspection.media.deliver" || evidence.MediaType != "image/png" {
		t.Fatalf("evidence=%#v", evidence)
	}
	if strings.Contains(response.Body.String(), "/api/") || strings.Contains(response.Body.String(), "sha256") {
		t.Fatalf("result exposed a route or integrity metadata: %s", response.Body.String())
	}
}

func TestWebPIsNotAnInspectionDeliveryFormat(t *testing.T) {
	webp := []byte("RIFF\x04\x00\x00\x00WEBP")
	digest := sha256.Sum256(webp)
	if validImageContentType("image/webp") || validImageMagic("image/webp", webp) ||
		validateMediaCapability(MediaCapability{
			MediaRef: "media-webp", Capability: "inspection.media.deliver", MediaType: "image/webp", Title: "现场图片",
		}) == nil || validateMediaPayload(MediaPayload{
		ContentType: "image/webp", SHA256: hex.EncodeToString(digest[:]), Bytes: webp,
	}) == nil {
		t.Fatal("inspection HTTP contract accepted unreachable WebP media")
	}
}

func TestMediaDeliveryIsBoundedAndIntegrityChecked(t *testing.T) {
	handler, backend, _ := fixtureHandler(t)
	response := serve(handler, request(http.MethodGet, mediaPath+"/media-public-1", nil, ""))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/png" || response.Header().Get("Content-Disposition") != "inline" {
		t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.Bytes())
	}
	if !bytes.Equal(response.Body.Bytes(), backend.media.Bytes) || response.Header().Get("X-Content-SHA256") != backend.media.SHA256 {
		t.Fatal("media response did not preserve verified bytes")
	}

	backend.media.SHA256 = strings.Repeat("0", 64)
	response = serve(handler, request(http.MethodGet, mediaPath+"/media-public-1", nil, ""))
	assertError(t, response, http.StatusInternalServerError, "internal_error")

	backend.media.Bytes = make([]byte, MaxMediaBytes+1)
	backend.media.SHA256 = strings.Repeat("0", 64)
	response = serve(handler, request(http.MethodGet, mediaPath+"/media-public-1", nil, ""))
	assertError(t, response, http.StatusInternalServerError, "internal_error")
}

func TestInteractionRequiredReturnsOnlyLocalHandoff(t *testing.T) {
	handler, backend, _ := fixtureHandler(t)
	backend.errByCall = map[string]error{
		"request": &InteractionRequiredError{Interaction: InteractionRequired{
			Title: "需要先完成现场接入", Message: "请在本机管理页面完成连接后再试。", ActionLabel: "打开本机管理页面",
			Capability: "operator.onboarding", HandoffRef: "handoff-public-1",
		}},
	}
	response := serve(handler, request(http.MethodPost, requestsPath, []byte(`{"instruction":"查看仓库通道是否畅通"}`), "request-2"))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{"interaction_required", "operator.onboarding", "handoff-public-1", "打开本机管理页面"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in %s", expected, body)
		}
	}
	for _, forbidden := range []string{"http://", "file://", "password", "deviceId", "sourceId"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("handoff leaked %q: %s", forbidden, body)
		}
	}
}

func TestPersistentChangeInteractionUsesOnlyTheClosedLocalCapability(t *testing.T) {
	handler, backend, _ := fixtureHandler(t)
	backend.errByCall = map[string]error{
		"request": &InteractionRequiredError{Interaction: InteractionRequired{
			Title: "需要在本机确认现场变更", Message: "请在本机管理页面核对后确认。", ActionLabel: "打开本机管理页面",
			Capability: InteractionCapabilityPersistentChange, HandoffRef: "handoff-change-1",
		}},
	}
	response := serve(handler, request(http.MethodPost, requestsPath, []byte(`{"instruction":"调整现场巡检任务"}`), "request-change"))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), InteractionCapabilityPersistentChange) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	backend.errByCall["request"] = &InteractionRequiredError{Interaction: InteractionRequired{
		Title: "需要本机操作", Message: "请在本机处理。", ActionLabel: "打开本机管理页面",
		Capability: "operator.arbitrary", HandoffRef: "handoff-change-2",
	}}
	response = serve(handler, request(http.MethodPost, requestsPath, []byte(`{"instruction":"调整现场巡检任务"}`), "request-change-invalid"))
	assertError(t, response, http.StatusInternalServerError, "internal_error")
}

func TestStrictJSONAndIdempotency(t *testing.T) {
	handler, backend, _ := fixtureHandler(t)
	tests := []struct {
		name string
		body string
		key  string
		ct   string
		code string
		want int
	}{
		{name: "unknown", body: `{"instruction":"查看入口","templateId":"private"}`, key: "key-1", ct: "application/json", want: 400, code: "invalid_json"},
		{name: "duplicate", body: `{"instruction":"查看入口","instruction":"查看出口"}`, key: "key-1", ct: "application/json", want: 400, code: "invalid_json"},
		{name: "trailing", body: `{"instruction":"查看入口"}{}`, key: "key-1", ct: "application/json", want: 400, code: "invalid_json"},
		{name: "blank", body: `{"instruction":" "}`, key: "key-1", ct: "application/json", want: 400, code: "invalid_request"},
		{name: "duplicate context", body: `{"instruction":"查看入口","context":[{"name":"区域","value":"一号"},{"name":"区域","value":"二号"}]}`, key: "key-1", ct: "application/json", want: 400, code: "invalid_request"},
		{name: "missing key", body: `{"instruction":"查看入口"}`, ct: "application/json", want: 400, code: "invalid_idempotency_key"},
		{name: "bad key", body: `{"instruction":"查看入口"}`, key: " bad ", ct: "application/json", want: 400, code: "invalid_idempotency_key"},
		{name: "content type", body: `{"instruction":"查看入口"}`, key: "key-1", ct: "text/plain", want: 415, code: "unsupported_media_type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := httptest.NewRequest(http.MethodPost, requestsPath, strings.NewReader(test.body))
			if test.ct != "" {
				input.Header.Set("Content-Type", test.ct)
			}
			if test.key != "" {
				input.Header.Set("Idempotency-Key", test.key)
			}
			response := serve(handler, input)
			assertError(t, response, test.want, test.code)
		})
	}
	if len(backend.calls) != 0 {
		t.Fatalf("invalid requests reached backend: %#v", backend.calls)
	}

	input := request(http.MethodPost, requestsPath, []byte(`{"instruction":"查看入口"}`), "key-1")
	input.Header.Add("Idempotency-Key", "key-2")
	assertError(t, serve(handler, input), http.StatusBadRequest, "invalid_idempotency_key")

	oversized := request(http.MethodPost, requestsPath, []byte(`{"instruction":"`+strings.Repeat("a", int(MaxRequestBodyBytes))+`"}`), "key-3")
	assertError(t, serve(handler, oversized), http.StatusRequestEntityTooLarge, "body_too_large")
}

func TestFeedbackRequiresExactBody(t *testing.T) {
	handler, backend, _ := fixtureHandler(t)
	for _, body := range []string{`{}`, `{"helpful":null}`, `{"helpful":true,"rating":"good"}`, `{"helpful":false,"comment":" "}`} {
		response := serve(handler, request(http.MethodPost, runsPath+"/run-public-1/feedback", []byte(body), "feedback-key"))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d response=%s", body, response.Code, response.Body.String())
		}
	}
	if len(backend.calls) != 0 {
		t.Fatalf("invalid feedback reached backend: %#v", backend.calls)
	}
}

func TestProtectedBusinessInputIsRejectedBeforeBackend(t *testing.T) {
	handler, backend, _ := fixtureHandler(t)
	for _, body := range []string{
		`{"instruction":"查看 rtsp://camera.example/live"}`,
		`{"instruction":"查看入口","context":[{"name":"地址","value":"192.168.1.20:554"}]}`,
		`{"instruction":"设备密码是 abc123"}`,
		`{"instruction":"请关闭摄像头"}`,
		`{"instruction":"启用巡检任务"}`,
		`{"instruction":"创建一个巡检任务"}`,
		`{"instruction":"删除二号任务"}`,
		`{"instruction":"修改视频源"}`,
	} {
		response := serve(handler, request(http.MethodPost, requestsPath, []byte(body), "protected-input"))
		assertError(t, response, http.StatusBadRequest, "invalid_request")
	}
	if len(backend.calls) != 0 {
		t.Fatalf("protected input reached backend: %#v", backend.calls)
	}
}

func TestAuthenticationAndBindingFailClosed(t *testing.T) {
	handler, backend, authorizer := fixtureHandler(t)
	authorizer.err = ErrUnauthenticated
	assertError(t, serve(handler, request(http.MethodGet, capabilitiesPath, nil, "")), http.StatusUnauthorized, "unauthenticated")
	authorizer.err = ErrForbidden
	assertError(t, serve(handler, request(http.MethodGet, capabilitiesPath, nil, "")), http.StatusForbidden, "forbidden")
	authorizer.err = nil
	authorizer.session.RecipientRef = ""
	assertError(t, serve(handler, request(http.MethodGet, capabilitiesPath, nil, "")), http.StatusForbidden, "forbidden")
	authorizer.session.RecipientRef = "recipient-a"
	authorizer.session.PrincipalSHA256 = ""
	assertError(t, serve(handler, request(http.MethodGet, capabilitiesPath, nil, "")), http.StatusForbidden, "forbidden")
	if len(backend.calls) != 0 {
		t.Fatalf("unauthorized request reached backend: %#v", backend.calls)
	}
}

func TestTrustedSessionBindingDoesNotProjectPrincipal(t *testing.T) {
	session := SessionBinding{
		TenantID: "tenant-a", SiteID: "site-a", Channel: "workbuddy_wechat",
		ConversationRef: "conversation-a", RecipientRef: "recipient-a", PrincipalSHA256: strings.Repeat("1", 64),
	}
	raw, err := json.Marshal(session)
	if err != nil || strings.Contains(string(raw), session.PrincipalSHA256) ||
		strings.Contains(fmt.Sprintf("%v %+v %#v", session, session, session), session.PrincipalSHA256) {
		t.Fatalf("trusted session projected principal raw=%s value=%+v err=%v", raw, session, err)
	}
}

func TestBearerCredentialIsRequiredAndOnlyItsDigestReachesAuthorizer(t *testing.T) {
	handler, backend, authorizer := fixtureHandler(t)
	missing := request(http.MethodGet, capabilitiesPath, nil, "")
	missing.Header.Del("Authorization")
	assertError(t, serve(handler, missing), http.StatusUnauthorized, "unauthenticated")
	for _, value := range []string{
		"", "Bearer short", "bearer " + testBearerToken, "Bearer " + strings.ToUpper(testBearerToken),
		"Bearer " + testBearerToken + " ", "Basic " + testBearerToken,
	} {
		input := request(http.MethodGet, capabilitiesPath, nil, "")
		input.Header["Authorization"] = []string{value}
		assertError(t, serve(handler, input), http.StatusUnauthorized, "unauthenticated")
	}
	duplicate := request(http.MethodGet, capabilitiesPath, nil, "")
	duplicate.Header.Add("Authorization", "Bearer "+testBearerToken)
	assertError(t, serve(handler, duplicate), http.StatusUnauthorized, "unauthenticated")
	if len(authorizer.scopes) != 0 || len(backend.calls) != 0 {
		t.Fatalf("invalid bearer reached authorization or backend: scopes=%v calls=%v", authorizer.scopes, backend.calls)
	}

	response := serve(handler, request(http.MethodGet, capabilitiesPath, nil, ""))
	if response.Code != http.StatusOK || len(authorizer.digests) != 1 || authorizer.digests[0] != testBearerDigest ||
		strings.Contains(authorizer.digests[0], testBearerToken) {
		t.Fatalf("valid bearer binding status=%d digests=%v", response.Code, authorizer.digests)
	}
}

func TestOldAndEncodedRoutesDoNotExist(t *testing.T) {
	handler, backend, _ := fixtureHandler(t)
	paths := []string{
		"/api/inspection-" + "runs", "/api/inspection-" + "templates", "/api/" + "mock-inspection-runs/run-1/media/media-1",
		"/api/inspection/v2/capabilities", "/api/inspection/v2/requests", "/api/inspection/v2/runs/run-1",
		basePath, basePath + "/runs", basePath + "/capabilities?tenantId=tenant-a", basePath + "/media/a/b",
	}
	for _, path := range paths {
		response := serve(handler, request(http.MethodGet, path, nil, ""))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	encoded := httptest.NewRequest(http.MethodGet, basePath+"/runs/run%2Fother", nil)
	if response := serve(handler, encoded); response.Code != http.StatusNotFound {
		t.Fatalf("encoded path status=%d body=%s", response.Code, response.Body.String())
	}
	emptyQuery := httptest.NewRequest(http.MethodGet, capabilitiesPath+"?", nil)
	if response := serve(handler, emptyQuery); response.Code != http.StatusNotFound {
		t.Fatalf("empty query status=%d body=%s", response.Code, response.Body.String())
	}
	if len(backend.calls) != 0 {
		t.Fatalf("retired routes reached backend: %#v", backend.calls)
	}
}

func TestBackendProjectionRejectsUnsafeOrMismatchedData(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		mutate func(*fixtureBackend)
	}{
		{name: "unsafe capability URL", path: capabilitiesPath, mutate: func(b *fixtureBackend) {
			b.capabilities.Capabilities[0].Description = "打开 http://device.local 查看"
		}},
		{name: "duplicate capability", path: capabilitiesPath, mutate: func(b *fixtureBackend) {
			b.capabilities.Capabilities = append(b.capabilities.Capabilities, b.capabilities.Capabilities[0])
		}},
		{name: "mismatched run", path: runsPath + "/run-public-1", mutate: func(b *fixtureBackend) { b.run.RunRef = "run-other" }},
		{name: "unsafe result URL", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) { b.result.Summary = "详情位于 file:///private/result" }},
		{name: "unsafe result IP", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) { b.result.Summary = "设备位于 192.168.1.20:554" }},
		{name: "unsafe result credential", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) { b.result.Summary = "设备密码是 abc123" }},
		{name: "unsafe result device command", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) { b.result.Summary = "请关闭摄像头" }},
		{name: "native media capability", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) { b.result.Sections[0].Evidence[0].Capability = "camera.snapshot" }},
		{name: "duplicate media", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) {
			b.result.Sections[0].Evidence = append(b.result.Sections[0].Evidence, b.result.Sections[0].Evidence[0])
		}},
		{name: "invalid answer value", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) {
			b.result.Answer = "maybe"
			b.result.Question = "测试问题"
		}},
		{name: "answer without question", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) {
			b.result.Answer = "yes"
			b.result.Question = ""
		}},
		{name: "question without answer", path: runsPath + "/run-public-1/result", mutate: func(b *fixtureBackend) {
			b.result.Answer = ""
			b.result.Question = "测试问题"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, backend, _ := fixtureHandler(t)
			test.mutate(backend)
			assertError(t, serve(handler, request(http.MethodGet, test.path, nil, "")), http.StatusInternalServerError, "internal_error")
		})
	}
}

func TestBackendErrorsAreMappedWithoutDetails(t *testing.T) {
	for _, test := range []struct {
		err  error
		want int
		code string
	}{
		{ErrNotFound, 404, "not_found"}, {ErrConflict, 409, "conflict"}, {ErrResultNotReady, 409, "result_not_ready"},
		{ErrInvalid, 400, "invalid_request"}, {ErrForbidden, 403, "forbidden"}, {errors.New("password=private"), 500, "internal_error"},
	} {
		handler, backend, _ := fixtureHandler(t)
		backend.errByCall = map[string]error{"run": test.err}
		response := serve(handler, request(http.MethodGet, runsPath+"/run-public-1", nil, ""))
		assertError(t, response, test.want, test.code)
		if strings.Contains(response.Body.String(), test.err.Error()) {
			t.Fatalf("backend error leaked: %s", response.Body.String())
		}
	}
}

func TestMethodsAndSecurityHeaders(t *testing.T) {
	handler, _, _ := fixtureHandler(t)
	for _, input := range []*http.Request{
		request(http.MethodPost, capabilitiesPath, []byte(`{}`), ""),
		request(http.MethodGet, requestsPath, nil, ""),
		request(http.MethodPost, runsPath+"/run-public-1", []byte(`{}`), ""),
		request(http.MethodPost, runsPath+"/run-public-1/result", []byte(`{}`), ""),
		request(http.MethodPost, mediaPath+"/media-public-1", []byte(`{}`), ""),
	} {
		response := serve(handler, input)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") == "" {
			t.Fatalf("%s %s status=%d headers=%v", input.Method, input.URL.Path, response.Code, response.Header())
		}
		assertNoStore(t, response)
	}
}

func TestGetBodyIsRejectedBeforeAuthorization(t *testing.T) {
	handler, backend, authorizer := fixtureHandler(t)
	response := serve(handler, request(http.MethodGet, capabilitiesPath, []byte(`{}`), ""))
	assertError(t, response, http.StatusBadRequest, "invalid_request")
	if len(authorizer.scopes) != 0 || len(backend.calls) != 0 {
		t.Fatalf("GET body reached authorization or backend: scopes=%v calls=%v", authorizer.scopes, backend.calls)
	}
}

func TestConstructorRejectsMissingDependencies(t *testing.T) {
	_, backend, authorizer := fixtureHandler(t)
	if _, err := NewHandler(nil, authorizer); err == nil {
		t.Fatal("missing backend accepted")
	}
	if _, err := NewHandler(backend, nil); err == nil {
		t.Fatal("missing authorizer accepted")
	}
}

func request(method, path string, body []byte, idempotency string) *http.Request {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	input := httptest.NewRequest(method, path, reader)
	if body != nil {
		input.Header.Set("Content-Type", "application/json")
	}
	if idempotency != "" {
		input.Header.Set("Idempotency-Key", idempotency)
	}
	input.Header.Set("Authorization", "Bearer "+testBearerToken)
	return input
}

func serve(handler http.Handler, input *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, input)
	return response
}

func assertError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("status=%d body=%s want status=%d code=%s", response.Code, response.Body.String(), status, code)
	}
	assertNoStore(t, response)
}

func assertNoStore(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers=%v", response.Header())
	}
}

func scopesToStrings(values []Scope) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}
