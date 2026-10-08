package parity

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var normalizedRecorder struct {
	sync.Mutex
	results []NormalizedResult
}

func recordNormalized(t *testing.T, result NormalizedResult) {
	t.Helper()
	if result.Scenario == "" || result.Class == "" {
		t.Fatal("normalized observation requires scenario and class")
	}
	normalizedRecorder.Lock()
	normalizedRecorder.results = append(normalizedRecorder.results, result)
	normalizedRecorder.Unlock()
}

func recordedNormalizedResults() []NormalizedResult {
	normalizedRecorder.Lock()
	defer normalizedRecorder.Unlock()
	return append([]NormalizedResult(nil), normalizedRecorder.results...)
}

type baselineSession struct {
	Browser    *Browser
	Fixture    *DeviceFixture
	Run        *baselineRun
	Ready      map[string]any
	DeviceHost string
	Username   string
	Password   string
	FullSN     string
}

func newConnectedBaseline(t *testing.T, suffix string) *baselineSession {
	t.Helper()
	operatorPath := baselineOperatorPath(t)
	username := "parity-user-" + suffix
	password := "parity-password-" + suffix
	fullSN := "PARITY-FULL-SN-" + strings.ToUpper(suffix) + "-739184"
	fixture := NewDeviceFixture(username, password, fullSN)
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFixture() })
	parsedDevice, err := url.Parse(deviceURL)
	if err != nil {
		t.Fatal(err)
	}
	run := startBaselineOperator(t, operatorPath)
	t.Cleanup(run.Close)
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}

	status, raw, err := browser.Form("/api/connection/prepare", url.Values{
		"endpoint": {parsedDevice.Hostname()}, "username": {username},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("prepare baseline connection status=%d err=%v body=%s", status, err, raw)
	}
	preview := mustObject(t, raw)
	status, raw, err = browser.Form("/api/connection/connect", url.Values{
		"connectionToken": {StringField(preview, "connectionToken")}, "password": {password},
	})
	if err != nil || status != http.StatusOK || StringField(mustObject(t, raw), "state") != "connecting" {
		t.Fatalf("connect baseline status=%d err=%v body=%s", status, err, raw)
	}
	ready, err := browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "ready" && StringField(value, "read", "choiceSetId") != ""
	})
	if err != nil {
		t.Fatalf("wait baseline ready: %v last=%#v", err, ready)
	}
	return &baselineSession{
		Browser: browser, Fixture: fixture, Run: run, Ready: ready,
		DeviceHost: parsedDevice.Hostname(), Username: username, Password: password, FullSN: fullSN,
	}
}

func (s *baselineSession) selectOnlyTask(t *testing.T) map[string]any {
	t.Helper()
	status, raw, err := s.Browser.JSON(http.MethodPost, "/api/journey/select", map[string]any{
		"choiceIndex": 1, "choiceSetId": StringField(s.Ready, "read", "choiceSetId"),
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("select baseline task status=%d err=%v body=%s", status, err, raw)
	}
	selected := mustObject(t, raw)
	if StringField(selected, "selection", "selected", "displayName") != "Parity Algorithm + Parity Camera" || !BoolField(selected, "capabilities", "canPrepare") {
		t.Fatalf("unexpected selected baseline task: %#v", selected)
	}
	return selected
}

func totalRequests(snapshot FixtureSnapshot) int {
	total := 0
	for _, count := range snapshot.Requests {
		total += count
	}
	return total
}

func mustGetObject(t *testing.T, browser *Browser, path string) map[string]any {
	t.Helper()
	status, raw, err := browser.Get(path)
	if err != nil || status != http.StatusOK {
		t.Fatalf("GET %s status=%d err=%v body=%s", path, status, err, raw)
	}
	return mustObject(t, raw)
}

func mustPostObject(t *testing.T, browser *Browser, path string, input any) map[string]any {
	t.Helper()
	status, raw, err := browser.JSON(http.MethodPost, path, input)
	if err != nil || status != http.StatusOK {
		t.Fatalf("POST %s status=%d err=%v body=%s", path, status, err, raw)
	}
	return mustObject(t, raw)
}
