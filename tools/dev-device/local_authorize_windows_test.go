//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
)

type recordingAuthorizationIssuer struct {
	requests chan devauthority.AuthorizationRequest
}

func (r recordingAuthorizationIssuer) Authorize(_ context.Context, request devauthority.AuthorizationRequest) (devauthority.AuthorizationResult, error) {
	r.requests <- request
	return devauthority.AuthorizationResult{Status: "authorized"}, nil
}

func TestLocalAuthorizeIsOneTimeOriginBoundAndSecretFree(t *testing.T) {
	const username, password = "local-authorize-user", "local-authorize-private-password"
	const endpoint = "http://10.42.0.20:8000"
	issuer := recordingAuthorizationIssuer{requests: make(chan devauthority.AuthorizationRequest, 1)}
	handoffPath := filepath.Join(t.TempDir(), "DevAuthority", "enroll-url.json")
	done := make(chan error, 1)
	go func() { done <- serveLocalAuthorize(issuer, io.Discard, handoffPath) }()

	var handoff struct {
		URL string `json:"url"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, readErr := os.ReadFile(handoffPath)
		if readErr == nil && json.Unmarshal(raw, &handoff) == nil && handoff.URL != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if handoff.URL == "" {
		t.Fatal("local authorization handoff was not published")
	}
	parsed, err := url.Parse(handoff.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(handoff.URL) // #nosec G107 -- randomized loopback URL from this test server.
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Security-Policy"), "form-action 'self'") || response.Header.Get("Cache-Control") == "" {
		t.Fatalf("unexpected local authorization GET: status=%d headers=%v", response.StatusCode, response.Header)
	}
	if strings.Contains(string(body), username) || strings.Contains(string(body), password) {
		t.Fatal("local authorization GET echoed a credential")
	}

	form := url.Values{
		"endpoint": {endpoint}, "username": {username}, "password": {password},
		"validDays": {"1"}, "allowTaskSwitchRoundTrip": {"true"},
	}
	request, err := http.NewRequest(http.MethodPost, handoff.URL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "authorized") || strings.Contains(string(body), password) {
		t.Fatalf("unexpected local authorization POST: status=%d body=%q", response.StatusCode, body)
	}
	select {
	case serveErr := <-done:
		if serveErr != nil {
			t.Fatal(serveErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local authorization server did not stop after success")
	}
	if _, err := os.Stat(handoffPath); !os.IsNotExist(err) {
		t.Fatalf("one-time handoff remained after authorization: %v", err)
	}
	select {
	case request := <-issuer.requests:
		decoded, decodeErr := base64.StdEncoding.DecodeString(request.PasswordBase64)
		if decodeErr != nil || request.Endpoint != endpoint || request.Username != username || string(decoded) != password || request.ValidForHours != 24 || !request.AllowTaskSwitchRoundTrip {
			t.Fatalf("authorization request was not preserved over local POST")
		}
		for index := range decoded {
			decoded[index] = 0
		}
	default:
		t.Fatal("local authorization did not invoke the issuer")
	}
}
