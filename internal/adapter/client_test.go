package adapter

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestImageBaseURLDefaultsToDeviceURLAndCanBeOverridden(t *testing.T) {
	c := NewClient("http://192.168.0.22:8000", "admin", "password")

	if got, want := c.ImageBaseURL(), "http://192.168.0.22:8000"; got != want {
		t.Fatalf("default ImageBaseURL() = %q, want %q", got, want)
	}

	c.SetImageBaseURL("http://192.168.0.22/")
	if got, want := c.ImageBaseURL(), "http://192.168.0.22"; got != want {
		t.Fatalf("overridden ImageBaseURL() = %q, want %q", got, want)
	}
}

func TestDefaultClientRejectsRedirectBeforeForwardingCredentials(t *testing.T) {
	var redirected int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirected, 1)
		t.Fatalf("redirect destination received credential-bearing request %s", r.URL.Path)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/captured", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	c := NewClient(source.URL, "admin", "private-password")
	if err := c.Login(); err == nil {
		t.Fatal("redirected login succeeded")
	}
	if got := atomic.LoadInt32(&redirected); got != 0 {
		t.Fatalf("redirect destination requests=%d, want 0", got)
	}
}

func TestV1ErrorMarksLoginThrottleAndCredentialFailures(t *testing.T) {
	throttled := &V1Error{MsgCode: "10009", Message: "登录太频繁"}
	if !throttled.LoginThrottled() {
		t.Fatal("device login throttle was not classified")
	}
	credential := v1ErrorFromResponse("/login/DoLogin", map[string]any{
		"resCode": float64(2),
		"resMsg":  []any{map[string]any{"msgText": "账号或密码错误"}},
	})
	if credential.LoginThrottled() || !credential.AuthenticationRejected() {
		t.Fatalf("credential classification=%#v", credential)
	}
}

func TestLoginAndQueryEventsUseV1Token(t *testing.T) {
	const password = "secret"
	const token = "mock-token"

	seenEventRequest := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/gtw/cwai/login/DoLogin":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode login body: %v", err)
			}
			if got, want := body["account"], "admin"; got != want {
				t.Fatalf("login account = %q, want %q", got, want)
			}
			wantPWD := fmt.Sprintf("%X", md5.Sum([]byte(password)))
			if got := body["pwd"]; got != wantPWD {
				t.Fatalf("login pwd = %q, want %q", got, wantPWD)
			}
			fmt.Fprintf(w, `{"resCode":1,"resData":{"mtk":%q}}`, token)
		case "/gtw/cwai/Event/Page":
			seenEventRequest = true
			if got := r.Header.Get("mtk"); got != token {
				t.Fatalf("mtk header = %q, want %q", got, token)
			}
			if got := r.Header.Get("token"); got != token {
				t.Fatalf("token header = %q, want %q", got, token)
			}
			fmt.Fprint(w, `{"resCode":1,"resData":{"rows":[{"id":"evt-1"}],"total":1}}`)
		default:
			t.Fatalf("unexpected v1 path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	c := NewClient(server.URL, "admin", password)
	if err := c.Login(); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	events, err := c.QueryEvents(1, 5)
	if err != nil {
		t.Fatalf("QueryEvents() error = %v", err)
	}
	if !seenEventRequest {
		t.Fatal("mock Event/Page endpoint was not called")
	}
	rows, ok := events["events"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("events rows = %#v, want one row", events["events"])
	}
	if got, want := events["total"], float64(1); got != want {
		t.Fatalf("events total = %#v, want %#v", got, want)
	}
}

func TestQueryDeviceInfoContextHonorsParentDeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.CloseClientConnections()
		server.Close()
	}()

	c := NewClient(server.URL, "admin", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()

	_, err := c.QueryDeviceInfoContext(ctx)
	if err == nil {
		t.Fatal("QueryDeviceInfoContext() error = nil, want deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("QueryDeviceInfoContext() error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("QueryDeviceInfoContext() took %s, want parent deadline to stop request promptly", elapsed)
	}
}

func TestReadAuthRejectedReloginsAndRetriesOnce(t *testing.T) {
	const password = "secret"
	const firstToken = "token-before-expiry"
	const secondToken = "token-after-relogin"
	var loginCalls int32
	var eventCalls int32
	eventTokens := make(chan string, 2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/gtw/cwai/login/DoLogin":
			call := atomic.AddInt32(&loginCalls, 1)
			if got := r.Header.Get("mtk"); got != "" {
				t.Fatalf("login mtk header = %q, want empty", got)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode login body: %v", err)
			}
			wantPWD := fmt.Sprintf("%X", md5.Sum([]byte(password)))
			if got := body["pwd"]; got != wantPWD {
				t.Fatalf("login pwd = %q, want %q", got, wantPWD)
			}
			token := firstToken
			if call == 2 {
				token = secondToken
			}
			fmt.Fprintf(w, `{"resCode":1,"resData":{"mtk":%q}}`, token)
		case "/gtw/cwai/Event/Page":
			call := atomic.AddInt32(&eventCalls, 1)
			eventTokens <- r.Header.Get("mtk")
			if call == 1 {
				fmt.Fprint(w, `{"resCode":401,"resMsg":[{"msgText":"token expired","msgCode":"TOKEN_EXPIRED"}]}`)
				return
			}
			if got := r.Header.Get("mtk"); got != secondToken {
				t.Fatalf("retry mtk header = %q, want %q", got, secondToken)
			}
			fmt.Fprint(w, `{"resCode":1,"resData":{"rows":[{"id":"evt-2"}],"total":1}}`)
		default:
			t.Fatalf("unexpected v1 path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	c := NewClient(server.URL, "admin", password)
	if err := c.Login(); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	events, err := c.QueryEvents(1, 5)
	if err != nil {
		t.Fatalf("QueryEvents() error = %v", err)
	}
	if got := atomic.LoadInt32(&loginCalls); got != 2 {
		t.Fatalf("login calls = %d, want initial login plus one auth retry", got)
	}
	if got := atomic.LoadInt32(&eventCalls); got != 2 {
		t.Fatalf("event calls = %d, want original read plus one retry", got)
	}
	if got := <-eventTokens; got != firstToken {
		t.Fatalf("first event token = %q, want %q", got, firstToken)
	}
	if got := <-eventTokens; got != secondToken {
		t.Fatalf("second event token = %q, want %q", got, secondToken)
	}
	rows, ok := events["events"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("events rows = %#v, want one row", events["events"])
	}
}

func TestWriteAuthRejectedDoesNotReloginOrRetry(t *testing.T) {
	const token = "write-token"
	var loginCalls int32
	var switchCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/gtw/cwai/login/DoLogin":
			atomic.AddInt32(&loginCalls, 1)
			fmt.Fprintf(w, `{"resCode":1,"resData":{"mtk":%q}}`, token)
		case "/gtw/cwai/Task/SwitchTask":
			atomic.AddInt32(&switchCalls, 1)
			if got := r.Header.Get("mtk"); got != token {
				t.Fatalf("switch mtk header = %q, want %q", got, token)
			}
			fmt.Fprint(w, `{"resCode":401,"resMsg":[{"msgText":"token expired","msgCode":"TOKEN_EXPIRED"}]}`)
		default:
			t.Fatalf("unexpected v1 path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	c := NewClient(server.URL, "admin", "secret")
	if err := c.Login(); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	_, err := c.SwitchTask(map[string]any{"id": "task-1", "channelId": "cam-1", "algorithmId": "alg-1", "switch": 1})
	if err == nil {
		t.Fatal("SwitchTask() error = nil, want auth rejection")
	}
	var v1Err *V1Error
	if !errors.As(err, &v1Err) {
		t.Fatalf("SwitchTask() error = %T %[1]v, want V1Error", err)
	}
	if !v1Err.AuthenticationRejected() || !v1Err.KnownFailure() {
		t.Fatalf("V1Error markers auth=%v known=%v, want both true", v1Err.AuthenticationRejected(), v1Err.KnownFailure())
	}
	var unknown *OutcomeUnknownError
	if errors.As(err, &unknown) {
		t.Fatalf("SwitchTask() error = %#v, should not be OutcomeUnknownError", unknown)
	}
	if got := atomic.LoadInt32(&loginCalls); got != 1 {
		t.Fatalf("login calls = %d, want no relogin for write", got)
	}
	if got := atomic.LoadInt32(&switchCalls); got != 1 {
		t.Fatalf("switch calls = %d, want no write retry", got)
	}
}
