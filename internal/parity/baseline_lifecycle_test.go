package parity

import (
	"bytes"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBaselineDuplicateConnectGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)
	fixture := NewDeviceFixture("duplicate-user", "duplicate-password", "PARITY-DUPLICATE-739184") // gitleaks:allow -- Synthetic credential for an isolated local test fixture.
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	parsed, _ := url.Parse(deviceURL)
	run := startBaselineOperator(t, operatorPath)
	defer run.Close()
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	preview := mustPostConnectionPreview(t, browser, parsed.Hostname(), "duplicate-user")
	token := StringField(preview, "connectionToken")
	statuses := make(chan int, 8)
	var wait sync.WaitGroup
	for i := 0; i < cap(statuses); i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, _, requestErr := browser.Form("/api/connection/connect", url.Values{
				"connectionToken": {token}, "password": {"duplicate-password"},
			})
			if requestErr != nil {
				statuses <- 0
				return
			}
			statuses <- status
		}()
	}
	wait.Wait()
	close(statuses)
	accepted := 0
	for status := range statuses {
		if status == http.StatusOK {
			accepted++
		} else if status != http.StatusConflict && status != http.StatusTooManyRequests {
			t.Fatalf("duplicate connect status=%d", status)
		}
	}
	if accepted != 1 || fixture.Snapshot().Requests["/gtw/cwai/login/DoLogin"] != 1 {
		t.Fatalf("duplicate connects accepted=%d snapshot=%#v", accepted, fixture.Snapshot())
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-CONN-05/duplicate-connect", Class: "completed", Dispatches: 1})
}

func TestBaselineBootstrapAndConcurrentLaunchGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)
	run := startBaselineOperator(t, operatorPath)
	defer run.Close()
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	page, err := url.Parse(browser.PageURL())
	if err != nil || page.Path != "/" || page.RawQuery != "" || page.Fragment != "" || strings.Contains(browser.PageURL(), strings.TrimPrefix(run.BootstrapURL, browser.BaseURL())) {
		t.Fatalf("bootstrap did not clean page URL: bootstrap=%q page=%q err=%v", run.BootstrapURL, browser.PageURL(), err)
	}
	cookies := browser.BootstrapCookies()
	if len(cookies) != 1 || cookies[0].Name != "cosmoedge_operator_session" || cookies[0].Value == "" || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("bootstrap cookie=%#v", cookies)
	}
	reuseClient := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	reused, err := reuseClient.Get(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = reused.Body.Close()
	if reused.StatusCode == http.StatusOK || (reused.StatusCode >= 300 && reused.StatusCode < 400) {
		t.Fatalf("consumed bootstrap was reusable: status=%d", reused.StatusCode)
	}

	var secondOutput bytes.Buffer
	second := exec.Command(operatorPath, "open", "home")
	second.Env = append([]string(nil), run.Environment...)
	second.Stdout, second.Stderr = &secondOutput, &secondOutput
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- second.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("concurrent launcher failed: %v output=%s", err, secondOutput.String())
		}
	case <-time.After(10 * time.Second):
		_ = second.Process.Kill()
		<-done
		t.Fatal("concurrent open caller did not converge to the owned host")
	}
	urls, err := waitCapturedURLs(run.CapturePath, 2, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	secondBrowser, err := ConsumeBootstrap(urls[len(urls)-1])
	if err != nil {
		t.Fatal(err)
	}
	if secondBrowser.BaseURL() != browser.BaseURL() {
		t.Fatalf("concurrent launcher created another host: first=%s second=%s", browser.BaseURL(), secondBrowser.BaseURL())
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-LIFE-02/bootstrap-reopen", Class: "completed"})
}

func TestBaselineRestartDropsForegroundAuthorityGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)
	root := t.TempDir()
	fixture := NewDeviceFixture("restart-user", "restart-password-private", "PARITY-RESTART-739184")
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	parsed, _ := url.Parse(deviceURL)
	run := startBaselineOperatorAtRoot(t, operatorPath, root)
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	preview := mustPostConnectionPreview(t, browser, parsed.Hostname(), "restart-user")
	status, raw, err := browser.Form("/api/connection/connect", url.Values{
		"connectionToken": {StringField(preview, "connectionToken")}, "password": {"restart-password-private"},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("restart setup connect status=%d err=%v body=%s", status, err, raw)
	}
	ready, err := browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "ready" && StringField(value, "read", "choiceSetId") != ""
	})
	if err != nil {
		t.Fatal(err)
	}
	mustPostObject(t, browser, "/api/journey/select", map[string]any{
		"choiceIndex": 1, "choiceSetId": StringField(ready, "read", "choiceSetId"),
	})
	prepared := mustPostObject(t, browser, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
	if StringField(prepared, "businessConfirmationToken") == "" || fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("restart setup proposal=%#v snapshot=%#v", prepared, fixture.Snapshot())
	}
	run.Close()

	restarted := startBaselineOperatorAtRoot(t, operatorPath, root)
	defer restarted.Close()
	restartedBrowser, err := ConsumeBootstrap(restarted.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	current := mustGetObject(t, restartedBrowser, "/api/journey?intent=home&window=today")
	if StringField(current, "state") != "disconnected" || BoolField(current, "capabilities", "canConfirm") || StringField(current, "businessConfirmationToken") != "" || fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("restart inherited foreground authority: current=%#v snapshot=%#v", current, fixture.Snapshot())
	}
	restarted.Close()
	if err := ScanTreeProtected(filepath.Clean(root), "restart-password-private"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-ACT-10/restart-drops-authority", Class: "blocked"})
}

func TestBaselineRestartDropsConnectionGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)
	root := t.TempDir()
	fixture := NewDeviceFixture("restart-connection-user", "restart-connection-password-private", "PARITY-RESTART-CONNECTION-739184")
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	parsed, _ := url.Parse(deviceURL)
	run := startBaselineOperatorAtRoot(t, operatorPath, root)
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	preview := mustPostConnectionPreview(t, browser, parsed.Hostname(), "restart-connection-user")
	status, raw, err := browser.Form("/api/connection/connect", url.Values{
		"connectionToken": {StringField(preview, "connectionToken")}, "password": {"restart-connection-password-private"},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("restart connection setup status=%d err=%v body=%s", status, err, raw)
	}
	if _, err := browser.WaitJSON("/api/journey?intent=home&window=today", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "ready"
	}); err != nil {
		t.Fatal(err)
	}
	run.Close()

	restarted := startBaselineOperatorAtRoot(t, operatorPath, root)
	defer restarted.Close()
	restartedBrowser, err := ConsumeBootstrap(restarted.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	current := mustGetObject(t, restartedBrowser, "/api/journey?intent=home&window=today")
	if StringField(current, "state") != "disconnected" || fixture.Snapshot().TaskWrites != 0 || fixture.Snapshot().ParameterWrites != 0 || fixture.Snapshot().SourceWrites != 0 {
		t.Fatalf("restart inherited connection: current=%#v snapshot=%#v", current, fixture.Snapshot())
	}
	restarted.Close()
	if err := ScanTreeProtected(filepath.Clean(root), "restart-connection-password-private", "PARITY-RESTART-CONNECTION-739184"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-LIFE-03/restart-drops-connection", Class: "blocked"})
}

func TestBaselineCrossBrowserConfirmationGolden(t *testing.T) {
	session := newConnectedBaseline(t, "cross-browser")
	session.selectOnlyTask(t)
	prepared := mustPostObject(t, session.Browser, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
	token := StringField(prepared, "businessConfirmationToken")
	if token == "" || session.Fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("cross-browser preparation=%#v snapshot=%#v", prepared, session.Fixture.Snapshot())
	}

	var output bytes.Buffer
	command := exec.Command(baselineOperatorPath(t), "open", "tasks")
	command.Env = append([]string(nil), session.Run.Environment...)
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatalf("open second browser session: %v output=%s", err, output.String())
	}
	urls, err := waitCapturedURLs(session.Run.CapturePath, 2, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ConsumeBootstrap(urls[len(urls)-1])
	if err != nil {
		t.Fatal(err)
	}
	status, _, err := other.JSON(http.MethodPost, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": token})
	if baselineImplementation() {
		if err != nil || status != http.StatusOK || session.Fixture.Snapshot().TaskWrites != 1 {
			t.Fatalf("baseline cross-browser confirmation status=%d err=%v snapshot=%#v", status, err, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-02/cross-browser-confirm", Class: "completed", DeviceWrites: 1, Dispatches: 1})
		return
	}
	if err != nil || status != http.StatusConflict || session.Fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("candidate cross-browser confirmation status=%d err=%v snapshot=%#v", status, err, session.Fixture.Snapshot())
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-ACT-02/cross-browser-confirm", Class: "blocked"})
}
