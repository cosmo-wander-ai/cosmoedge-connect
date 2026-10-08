package parity

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	baselineOperatorEnv = "PARITY_BASELINE_OPERATOR"
	implementationEnv   = "PARITY_IMPLEMENTATION"
	resultPathEnv       = "PARITY_RESULTS_PATH"
	captureModeEnv      = "PARITY_BROWSER_CAPTURE_MODE"
	captureFileEnv      = "PARITY_BROWSER_CAPTURE_FILE"
)

func TestMain(m *testing.M) {
	if os.Getenv(captureModeEnv) == "1" {
		path := os.Getenv(captureFileEnv)
		if path == "" {
			os.Exit(2)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(2)
		}
		_, err = fmt.Fprintln(file, strings.Join(os.Args[1:], " "))
		_ = file.Close()
		if err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	code := m.Run()
	if path := strings.TrimSpace(os.Getenv(resultPathEnv)); path != "" {
		if err := WriteNormalizedFile(path, recordedNormalizedResults()); err != nil {
			fmt.Fprintln(os.Stderr, "write parity results:", err)
			if code == 0 {
				code = 2
			}
		}
	}
	os.Exit(code)
}

func TestBaselineTaskDisableGolden(t *testing.T) {
	operatorPath := baselineOperatorPath(t)

	password := "parity-private-password"
	username := "parity-field-user"
	fullSN := "PARITY-FULL-SN-739184"
	fixture := NewDeviceFixture(username, password, fullSN)
	deviceURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	parsedDevice, _ := url.Parse(deviceURL)

	run := startBaselineOperator(t, operatorPath)
	defer run.Close()
	browser, err := ConsumeBootstrap(run.BootstrapURL)
	if err != nil {
		t.Fatal(err)
	}

	status, raw, err := browser.Form("/api/connection/prepare", url.Values{
		"endpoint": {parsedDevice.Hostname()}, "username": {username},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("baseline destination prepare status=%d err=%v body=%s", status, err, raw)
	}
	preview, err := DecodeObject(raw)
	if err != nil || StringField(preview, "connectionToken") == "" {
		t.Fatal("baseline destination preview did not return a private token")
	}
	status, raw, err = browser.Form("/api/connection/connect", url.Values{
		"connectionToken": {StringField(preview, "connectionToken")}, "password": {password},
	})
	if err != nil || status != http.StatusOK || StringField(mustObject(t, raw), "state") != "connecting" {
		t.Fatalf("baseline connect status=%d err=%v body=%s", status, err, raw)
	}

	ready, err := browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "ready" && StringField(value, "read", "choiceSetId") != ""
	})
	if err != nil {
		t.Fatalf("baseline manage-tasks readiness: %v last=%#v", err, ready)
	}
	status, raw, err = browser.JSON(http.MethodPost, "/api/journey/select", map[string]any{
		"choiceIndex": 1, "choiceSetId": StringField(ready, "read", "choiceSetId"),
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("baseline selection status=%d err=%v body=%s", status, err, raw)
	}

	status, raw, err = browser.JSON(http.MethodPost, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
	prepared := mustObject(t, raw)
	if err != nil || status != http.StatusOK || StringField(prepared, "state") != "awaiting_confirmation" || StringField(prepared, "businessConfirmationToken") == "" || fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("baseline preparation status=%d err=%v body=%s snapshot=%#v", status, err, raw, fixture.Snapshot())
	}
	status, _, err = browser.JSON(http.MethodPost, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": "not-current"})
	if err != nil || status != http.StatusConflict || fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("baseline invalid confirmation status=%d err=%v snapshot=%#v", status, err, fixture.Snapshot())
	}

	token := StringField(prepared, "businessConfirmationToken")
	statuses := make(chan int, 8)
	var wait sync.WaitGroup
	for i := 0; i < cap(statuses); i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, _, err := browser.JSON(http.MethodPost, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": token})
			if err != nil {
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
		} else if status != http.StatusConflict {
			t.Fatalf("baseline concurrent confirmation status=%d", status)
		}
	}
	if accepted != 1 {
		t.Fatalf("baseline accepted confirmations=%d", accepted)
	}

	terminal, err := browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 45*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "complete" && StringField(value, "report", "evidenceStatus") == "sealed"
	})
	if err != nil {
		t.Fatalf("baseline terminal state: %v last=%#v", err, terminal)
	}
	snapshot := fixture.Snapshot()
	normalized, err := NormalizeTaskState("G-ACT-04/task-disable", terminal, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := NormalizedResult{
		Scenario: "G-ACT-04/task-disable", Class: "completed", State: "complete", View: "manage_tasks",
		Conclusion: "任务状态已持久变更并完成验证。", EvidenceStatus: "sealed",
		TaskName: "Parity Algorithm + Parity Camera", CameraName: "Parity Camera", AlgorithmName: "Parity Algorithm",
		CanUndo: true, DeviceWrites: 1, Dispatches: 1,
	}
	if normalized != want {
		t.Fatalf("baseline normalized result=%#v want=%#v", normalized, want)
	}
	recordNormalized(t, normalized)
	if snapshot.TaskEnabled != 0 || snapshot.TaskWrites != 1 {
		t.Fatalf("baseline target snapshot=%#v", snapshot)
	}
	if err := ScanProtected(browser.Bodies(), password, fullSN, username, parsedDevice.Hostname(), "parity-task-internal", "parity-camera-internal", "parity-algorithm-internal"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_, _, _ = browser.Get("/api/journey?intent=manage_tasks&window=today")
	}
	if fixture.Snapshot().TaskWrites != 1 {
		t.Fatal("baseline terminal refresh replayed the target write")
	}
}

type baselineRun struct {
	BootstrapURL string
	Root         string
	CapturePath  string
	Environment  []string
	command      *exec.Cmd
	output       *os.File
	once         sync.Once
}

func startBaselineOperator(t *testing.T, operatorPath string) *baselineRun {
	t.Helper()
	return startBaselineOperatorAtRoot(t, operatorPath, t.TempDir())
}

func startBaselineOperatorAtRoot(t *testing.T, operatorPath, root string) *baselineRun {
	t.Helper()
	capturePath := filepath.Join(root, "browser-capture.txt")
	if err := os.WriteFile(capturePath, nil, 0o600); err != nil {
		t.Fatal("create browser capture")
	}
	output, err := os.OpenFile(filepath.Join(root, "operator-output.txt"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal("create Operator output")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal("locate parity test executable")
	}
	localAppData := filepath.Join(root, "LocalAppData")
	userProfile := filepath.Join(root, "UserProfile")
	codexHome := filepath.Join(root, "CodexHome")
	for _, path := range []string{localAppData, userProfile, codexHome} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal("create isolated parity home")
		}
	}
	environment := isolatedEnvironment(localAppData, userProfile, codexHome, self, capturePath)
	command := exec.Command(operatorPath)
	command.Stdout, command.Stderr = output, output
	command.Env = environment
	if err := command.Start(); err != nil {
		_ = output.Close()
		t.Fatal("start baseline Operator")
	}
	bootstrap, err := waitCapturedURL(capturePath, 30*time.Second)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = output.Close()
		t.Fatal(err)
	}
	return &baselineRun{
		BootstrapURL: bootstrap, Root: root, CapturePath: capturePath,
		Environment: append([]string(nil), environment...), command: command, output: output,
	}
}

func (r *baselineRun) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		if r.command != nil && r.command.Process != nil {
			_ = r.command.Process.Kill()
			_ = r.command.Wait()
		}
		if r.output != nil {
			_ = r.output.Close()
		}
	})
}

func isolatedEnvironment(localAppData, userProfile, codexHome, browserPath, capturePath string) []string {
	keep := map[string]bool{"systemroot": true, "windir": true, "path": true, "pathext": true, "comspec": true, "temp": true, "tmp": true}
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok && keep[strings.ToLower(key)] {
			values[strings.ToUpper(key)] = value
		}
	}
	return []string{
		"SYSTEMROOT=" + firstNonEmpty(values["SYSTEMROOT"], values["WINDIR"]),
		"WINDIR=" + firstNonEmpty(values["WINDIR"], values["SYSTEMROOT"]),
		"COMSPEC=" + values["COMSPEC"], "PATHEXT=" + values["PATHEXT"],
		"PATH=" + values["PATH"], "TEMP=" + values["TEMP"], "TMP=" + values["TMP"],
		"LOCALAPPDATA=" + localAppData,
		"APPDATA=" + filepath.Join(userProfile, "AppData", "Roaming"),
		"USERPROFILE=" + userProfile, "HOME=" + userProfile, "CODEX_HOME=" + codexHome,
		"COSMOEDGE_OPERATOR_BROWSER=" + browserPath,
		captureModeEnv + "=1", captureFileEnv + "=" + capturePath,
	}
}

func waitCapturedURL(path string, timeout time.Duration) (string, error) {
	urls, err := waitCapturedURLs(path, 1, timeout)
	if err != nil {
		return "", err
	}
	return urls[0], nil
}

func waitCapturedURLs(path string, count int, timeout time.Duration) ([]string, error) {
	deadline := time.Now().Add(timeout)
	pattern := regexp.MustCompile(`https?://[^\s"']+`)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(path)
		var urls []string
		for _, line := range bytes.Split(raw, []byte("\n")) {
			if match := pattern.Find(line); len(match) > 0 {
				urls = append(urls, strings.TrimRight(string(match), "\r"))
			}
		}
		if len(urls) >= count {
			return urls, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("baseline Operator did not open %d private bootstrap page(s)", count)
}

func mustObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	object, err := DecodeObject(raw)
	if err != nil {
		t.Fatalf("decode parity response: %v body=%s", err, raw)
	}
	return object
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func baselineOperatorPath(t *testing.T) string {
	t.Helper()
	operatorPath := strings.TrimSpace(os.Getenv(baselineOperatorEnv))
	if operatorPath == "" {
		t.Skip(baselineOperatorEnv + " is set by the explicit parity baseline gate")
	}
	operatorPath, err := filepath.Abs(operatorPath)
	if err != nil {
		t.Fatal("resolve baseline Operator")
	}
	if info, err := os.Stat(operatorPath); err != nil || !info.Mode().IsRegular() {
		t.Fatal("baseline Operator is not a regular file")
	}
	return operatorPath
}

func baselineImplementation() bool {
	return strings.TrimSpace(os.Getenv(implementationEnv)) == "baseline"
}
