package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/read"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestSavedConnectionRetryRequiresLocalBrowserAndCSRF(t *testing.T) {
	vault := session.New(nil)
	token, _ := vault.IssueBootstrap()
	auth, _ := vault.ConsumeBootstrap(token)
	backend := &retryBackend{available: true, result: session.RestoreNeedsAttention}
	host := New("http://127.0.0.1:12345", "control", backend, vault, nil)
	for _, test := range []struct {
		name, cookie, origin, csrf string
		want                       int
	}{
		{"no browser", "", host.baseURL, auth.CSRF, http.StatusForbidden},
		{"wrong csrf", auth.SessionID, host.baseURL, "wrong", http.StatusForbidden},
		{"wrong origin", auth.SessionID, "http://other.invalid", auth.CSRF, http.StatusForbidden},
		{"local retry", auth.SessionID, host.baseURL, auth.CSRF, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, host.baseURL+"/api/connection/retry", nil)
			request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: test.cookie})
			request.Header.Set("Origin", test.origin)
			request.Header.Set("X-CosmoEdge-CSRF", test.csrf)
			response := httptest.NewRecorder()
			host.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("retry HTTP status=%d", response.Code)
			}
		})
	}
	if backend.calls != 1 || backend.browser != auth.SessionID {
		t.Fatal("unbound request reached the saved connection retry")
	}
}

func TestJourneyOffersSavedRetryOnlyWhenDisconnectedAndAvailable(t *testing.T) {
	for _, test := range []struct {
		state     string
		available bool
		want      bool
	}{
		{"disconnected", true, true},
		{"disconnected", false, false},
		{"ready", true, false},
	} {
		t.Run(test.state+"-"+map[bool]string{true: "available", false: "unavailable"}[test.available], func(t *testing.T) {
			vault := session.New(nil)
			token, _ := vault.IssueBootstrap()
			auth, _ := vault.ConsumeBootstrap(token)
			backend := &retryBackend{available: test.available, state: test.state}
			host := New("http://127.0.0.1:12345", "control", backend, vault, nil)
			request := httptest.NewRequest(http.MethodGet, host.baseURL+"/api/journey", nil)
			request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: auth.SessionID})
			response := httptest.NewRecorder()
			host.ServeHTTP(response, request)
			var result struct {
				State                   string `json:"state"`
				CanRetrySavedConnection bool   `json:"canRetrySavedConnection"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != http.StatusOK || result.State != test.state || result.CanRetrySavedConnection != test.want {
				t.Fatal("journey exposed the wrong saved retry state")
			}
			if backend.calls != 0 {
				t.Fatal("rendering the page retried the device connection")
			}
		})
	}
}

type retryBackend struct {
	fakeBackend
	available bool
	state     string
	result    session.RestoreState
	calls     int
	browser   string
}

func (b *retryBackend) CanRetrySavedConnection() bool { return b.available }
func (b *retryBackend) RetrySavedConnection(_ context.Context, browser string) (session.RestoreResult, error) {
	b.calls++
	b.browser = browser
	return session.RestoreResult{State: b.result}, nil
}
func (b *retryBackend) Journey(context.Context, string, string, string) (read.Projection, error) {
	return read.Projection{State: b.state}, nil
}
