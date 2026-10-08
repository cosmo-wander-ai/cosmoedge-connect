package inspectionlocal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	operatorsession "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestHTTPHandlerUsesCookieSealedExactHandoffAndCompletesVerifiedConnection(t *testing.T) {
	vault := operatorsession.New(nil)
	bootstrap, err := vault.IssueBootstrapForIntent(operatorsession.OpenIntent{
		View: operatorsession.ViewInspectionInteraction, HandoffRef: "handoff_http_exact",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	binder, err := NewSessionBinder(SessionBinderConfig{Sessions: vaultBrowserSessions{vault: vault}})
	if err != nil {
		t.Fatal(err)
	}
	application := &httpApplicationFixture{wantHandoff: "handoff_http_exact"}
	probe := &httpProbeFixture{}
	handler, err := NewHTTPHandler(HTTPConfig{
		BaseURL: "http://127.0.0.1:38081", SessionCookie: "test_session", Sessions: binder,
		Application: application, Connections: probe,
	})
	if err != nil {
		t.Fatal(err)
	}

	get := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:38081"+InteractionPath, nil)
	get.AddCookie(&http.Cookie{Name: "test_session", Value: auth.SessionID})
	getResult := httptest.NewRecorder()
	handler.ServeHTTP(getResult, get)
	if getResult.Code != http.StatusOK || !strings.Contains(getResult.Body.String(), "完成现场接入") ||
		!strings.Contains(getResult.Body.String(), "password.value=''") ||
		!strings.Contains(getResult.Body.String(), "device_information_unavailable") ||
		strings.Contains(getResult.Body.String(), "handoff_http_exact") {
		t.Fatalf("GET status=%d body=%q", getResult.Code, getResult.Body.String())
	}

	retarget := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:38081"+InteractionPath+"?handoffRef=other", nil)
	retarget.AddCookie(&http.Cookie{Name: "test_session", Value: auth.SessionID})
	retargetResult := httptest.NewRecorder()
	handler.ServeHTTP(retargetResult, retarget)
	if retargetResult.Code != http.StatusNotFound {
		t.Fatalf("query retarget status=%d", retargetResult.Code)
	}

	form := url.Values{
		"ip": {"192.168.0.22"}, "port": {"8000"},
		"username": {"local-user"}, "password": {"local-private-password"},
	}
	post := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:38081"+InteractionPath, strings.NewReader(form.Encode()))
	post.Header.Set("Origin", "http://127.0.0.1:38081")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	post.Header.Set("X-CosmoEdge-CSRF", auth.CSRF)
	post.AddCookie(&http.Cookie{Name: "test_session", Value: auth.SessionID})
	postResult := httptest.NewRecorder()
	handler.ServeHTTP(postResult, post)
	if postResult.Code != http.StatusOK || application.completes != 1 || probe.connects != 1 {
		t.Fatalf("POST status=%d body=%q completes=%d connects=%d", postResult.Code, postResult.Body.String(), application.completes, probe.connects)
	}
	if !allZero(probe.passwordView) {
		t.Fatal("password bytes survived local completion")
	}

	bad := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:38081"+InteractionPath, strings.NewReader(form.Encode()))
	bad.Header.Set("Origin", "http://127.0.0.1:38081")
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	bad.Header.Set("X-CosmoEdge-CSRF", strings.Repeat("0", 64))
	bad.AddCookie(&http.Cookie{Name: "test_session", Value: auth.SessionID})
	badResult := httptest.NewRecorder()
	handler.ServeHTTP(badResult, bad)
	if badResult.Code != http.StatusForbidden || application.completes != 1 || probe.connects != 1 {
		t.Fatalf("bad CSRF status=%d completes=%d connects=%d", badResult.Code, application.completes, probe.connects)
	}
}

func TestHTTPConnectionFailuresReturnOnlyActionableChineseReasonAndClearPassword(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantReason string
		wantText   string
	}{
		{
			name: "credentials rejected", err: ErrConnectionRejected, wantStatus: http.StatusBadGateway,
			wantReason: "credentials_rejected", wantText: "设备未接受该账号或密码，请重新输入后重试。",
		},
		{
			name: "login throttled", err: ErrConnectionThrottled, wantStatus: http.StatusBadGateway,
			wantReason: "login_throttled", wantText: "设备暂时限制新的登录尝试，请稍后再试。",
		},
		{
			name: "device unreachable", err: ErrConnectionUnavailable, wantStatus: http.StatusBadGateway,
			wantReason: "device_unavailable", wantText: "暂时无法连接设备，请确认设备已开机且本机网络可达后重试。",
		},
		{
			name: "device information", err: ErrConnectionReadUnavailable, wantStatus: http.StatusBadGateway,
			wantReason: "device_information_unavailable", wantText: "已通过登录验证，但暂时无法读取设备信息，请确认该账号有查看权限后重试。",
		},
		{
			name: "secure save", err: ErrConnectionPersistenceFailed, wantStatus: http.StatusServiceUnavailable,
			wantReason: "secure_save_failed", wantText: "设备验证已通过，但连接信息未能安全保存，请检查本机可用空间和系统权限后重试。",
		},
		{
			name: "stale request", err: ErrConnectionRequestUnavailable, wantStatus: http.StatusConflict,
			wantReason: "connection_request_unavailable", wantText: "本次接入请求已失效，请刷新页面后重试。",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			vault := operatorsession.New(nil)
			bootstrap, err := vault.IssueBootstrapForIntent(operatorsession.OpenIntent{
				View: operatorsession.ViewInspectionInteraction, HandoffRef: "handoff_failure_exact",
			})
			if err != nil {
				t.Fatal(err)
			}
			auth, err := vault.ConsumeBootstrap(bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			binder, err := NewSessionBinder(SessionBinderConfig{Sessions: vaultBrowserSessions{vault: vault}})
			if err != nil {
				t.Fatal(err)
			}
			application := &httpApplicationFixture{wantHandoff: "handoff_failure_exact"}
			probe := &httpProbeFixture{connectErr: test.err}
			handler, err := NewHTTPHandler(HTTPConfig{
				BaseURL: "http://127.0.0.1:38082", SessionCookie: "test_session", Sessions: binder,
				Application: application, Connections: probe,
			})
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{
				"ip": {"192.168.0.22"}, "port": {"8000"},
				"username": {"private-local-user"}, "password": {"private-local-password"},
			}
			post := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:38082"+InteractionPath, strings.NewReader(form.Encode()))
			post.Header.Set("Origin", "http://127.0.0.1:38082")
			post.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
			post.Header.Set("X-CosmoEdge-CSRF", auth.CSRF)
			post.AddCookie(&http.Cookie{Name: "test_session", Value: auth.SessionID})
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, post)

			body := result.Body.String()
			if result.Code != test.wantStatus || !strings.HasPrefix(result.Header().Get("Content-Type"), "application/json") ||
				!strings.Contains(body, test.wantReason) || !strings.Contains(body, test.wantText) {
				t.Fatalf("POST status=%d type=%q body=%q", result.Code, result.Header().Get("Content-Type"), body)
			}
			for _, forbidden := range []string{"192.168.0.22", "private-local-user", "private-local-password", "v1 API"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("failure response leaked %q: %q", forbidden, body)
				}
			}
			if !allZero(probe.passwordView) {
				t.Fatal("failed HTTP connection retained password bytes")
			}
			if application.completes != 0 {
				t.Fatal("failed connection completed the protected handoff")
			}
		})
	}
}

type httpApplicationFixture struct {
	wantHandoff string
	completes   int
}

func (a *httpApplicationFixture) Resolve(_ context.Context, local LocalSession) (Interaction, error) {
	if local.handoffRef != a.wantHandoff {
		return Interaction{}, ErrNotFound
	}
	if a.completes != 0 {
		return Interaction{Kind: KindConnection, Action: ActionNone, Status: StatusCompleted}, nil
	}
	return Interaction{Kind: KindConnection, Action: ActionCompleteConnection, Status: StatusPending}, nil
}

func (a *httpApplicationFixture) CompleteConnection(_ context.Context, local LocalSession, _ CompleteConnectionRequest) (Interaction, error) {
	if local.handoffRef != a.wantHandoff || !local.writeAuthorized {
		return Interaction{}, ErrDenied
	}
	return Interaction{}, ErrWrongKind
}

func (a *httpApplicationFixture) CompleteVerifiedConnection(_ context.Context, local LocalSession) (Interaction, error) {
	if local.handoffRef != a.wantHandoff || !local.writeAuthorized {
		return Interaction{}, ErrDenied
	}
	a.completes++
	return Interaction{Kind: KindConnection, Action: ActionNone, Status: StatusCompleted}, nil
}

func (*httpApplicationFixture) PreparePersistentTransfer(context.Context, LocalSession, PersistentTransferRequest) (Interaction, error) {
	return Interaction{}, ErrWrongKind
}

func (*httpApplicationFixture) MarkPersistentTransferred(context.Context, LocalSession, PersistentTransferRequest) (Interaction, error) {
	return Interaction{}, ErrWrongKind
}

type httpProbeFixture struct {
	connects     int
	passwordView []byte
	connectErr   error
}

func (*httpProbeFixture) PrepareConnection(_, _, _ string) (string, error) {
	return "candidate", nil
}

func (p *httpProbeFixture) Connect(_ context.Context, _, _ string, password []byte) error {
	p.connects++
	p.passwordView = password
	return p.connectErr
}
