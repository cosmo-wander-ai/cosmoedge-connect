//go:build windows

package releasegate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/parity"
)

const (
	bundleRootEnv  = "OPERATOR_WINDOWS_BUNDLE_ROOT"
	helperModeEnv  = "OPERATOR_BROWSER_CAPTURE_HELPER"
	capturePathEnv = "OPERATOR_BROWSER_CAPTURE_PATH"
)

func TestMain(m *testing.M) {
	if os.Getenv(helperModeEnv) == "1" {
		path := os.Getenv(capturePathEnv)
		if path == "" || len(os.Args) != 2 {
			os.Exit(2)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			_, err = fmt.Fprintln(file, os.Args[1])
			_ = file.Close()
		}
		if err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestInstalledWindowsFreshHomeOrdinaryRelease(t *testing.T) {
	bundleRoot := strings.TrimSpace(os.Getenv(bundleRootEnv))
	if bundleRoot == "" {
		t.Skipf("%s is not configured", bundleRootEnv)
	}
	var err error
	bundleRoot, err = filepath.Abs(bundleRoot)
	if err != nil {
		t.Fatal(err)
	}
	assertReleaseBundle(t, bundleRoot)

	root := t.TempDir()
	localAppData := filepath.Join(root, "LocalAppData")
	operatorHome := filepath.Join(localAppData, "CosmoEdgeOperator")
	codexHome := filepath.Join(root, "CodexHome")
	userProfile := filepath.Join(root, "UserProfile")
	for _, path := range []string{localAppData, codexHome, userProfile} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	password := randomValue(t, "pw")
	username := randomValue(t, "user")
	fullSN := strings.ToUpper(randomValue(t, "fake-sn"))
	fixture := parity.NewDeviceFixture(username, password, fullSN)
	fixtureURL, closeFixture, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture()
	parsedFixture, _ := url.Parse(fixtureURL)
	endpoint := parsedFixture.Hostname()

	capturePath := filepath.Join(root, "browser-capture.txt")
	if err := os.WriteFile(capturePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childEnv := isolatedEnvironment(map[string]string{
		"LOCALAPPDATA":               localAppData,
		"CODEX_HOME":                 codexHome,
		"USERPROFILE":                userProfile,
		"HOME":                       userProfile,
		"COSMOEDGE_OPERATOR_BROWSER": self,
		helperModeEnv:                "1",
		capturePathEnv:               capturePath,
	})
	stateRoot := filepath.Join(localAppData, "CosmoEdge", "Operator")
	defer stopLocatedProcess(stateRoot)

	bootstrap := filepath.Join(bundleRoot, "cosmoedge-operator-bootstrap.ps1")
	unsafeSentinel := filepath.Join(localAppData, "keep-existing-user-data.txt")
	if err := os.WriteFile(unsafeSentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafeInstall := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", bootstrap, "-OperatorHome", localAppData, "-CodexHome", codexHome, "-NoSkill")
	unsafeInstall.Dir, unsafeInstall.Env = bundleRoot, childEnv
	unsafeOutput, unsafeErr := unsafeInstall.CombinedOutput()
	if unsafeErr == nil || !bytes.Contains(unsafeOutput, []byte("Refusing to install into a non-empty directory")) {
		t.Fatalf("unsafe install root was not rejected: %v\n%s", unsafeErr, unsafeOutput)
	}
	if raw, err := os.ReadFile(unsafeSentinel); err != nil || string(raw) != "keep" {
		t.Fatalf("unsafe install touched existing user data: %v %q", err, raw)
	}

	install := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", bootstrap, "-OperatorHome", operatorHome, "-CodexHome", codexHome)
	install.Dir, install.Env = bundleRoot, childEnv
	installOutput, err := install.CombinedOutput()
	if err != nil {
		t.Fatalf("release bootstrap failed: %v\n%s", err, installOutput)
	}
	assertNoSentinels(t, "bootstrap output", installOutput, password, fullSN, endpoint)
	assertInstalledLayout(t, operatorHome, codexHome)
	assertSameFile(t,
		filepath.Join(bundleRoot, "demo", "skill", "cosmoedge-operator", "SKILL.md"),
		filepath.Join(codexHome, "skills", "cosmoedge-operator", "SKILL.md"),
	)
	staleBinary := filepath.Join(operatorHome, "bin", "cosmoedge-v2.exe")
	staleSkill := filepath.Join(codexHome, "skills", "cosmoedge-operator", "stale-authority.md")
	for _, stale := range []string{staleBinary, staleSkill} {
		if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reinstall := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", bootstrap, "-OperatorHome", operatorHome, "-CodexHome", codexHome)
	reinstall.Dir, reinstall.Env = bundleRoot, childEnv
	reinstallOutput, err := reinstall.CombinedOutput()
	if err != nil {
		t.Fatalf("release reinstall failed: %v\n%s", err, reinstallOutput)
	}
	installOutput = bytes.Join([][]byte{installOutput, reinstallOutput}, nil)
	for _, stale := range []string{staleBinary, staleSkill} {
		if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("release reinstall retained stale authority: %s", stale)
		}
	}
	assertInstalledLayout(t, operatorHome, codexHome)
	assertSameFile(t,
		filepath.Join(bundleRoot, "demo", "skill", "cosmoedge-operator", "SKILL.md"),
		filepath.Join(codexHome, "skills", "cosmoedge-operator", "SKILL.md"),
	)

	launcher := filepath.Join(operatorHome, "bin", "cosmoedge-operator.ps1")
	launch := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", launcher)
	launch.Env = childEnv
	launchOutput, err := launch.CombinedOutput()
	if err != nil || !bytes.Contains(launchOutput, []byte(`"status":"started"`)) {
		t.Fatalf("installed launcher failed: %v\n%s", err, launchOutput)
	}
	firstBootstrap := waitCapturedURL(t, capturePath, 0, 30*time.Second)
	browser, err := parity.ConsumeBootstrap(firstBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if browser.PageURL() != browser.BaseURL()+"/" {
		t.Fatalf("bootstrap did not clean the private URL: %s", browser.PageURL())
	}
	if len(browser.BootstrapCookies()) != 1 || !browser.BootstrapCookies()[0].HttpOnly || browser.BootstrapCookies()[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("bootstrap cookie is not one strict HttpOnly foreground binding")
	}

	status, raw, err := browser.Form("/api/connection/prepare", url.Values{"endpoint": {endpoint}, "username": {username}})
	preview, decodeErr := parity.DecodeObject(raw)
	connectionToken := parity.StringField(preview, "connectionToken")
	if err != nil || decodeErr != nil || status != http.StatusOK || connectionToken == "" {
		t.Fatalf("connection admission status=%d err=%v body=%s", status, err, raw)
	}
	status, raw, err = browser.Form("/api/connection/connect", url.Values{"connectionToken": {connectionToken}, "password": {password}})
	if err != nil || status != http.StatusOK {
		t.Fatalf("connection status=%d err=%v body=%s", status, err, raw)
	}
	if fixture.Snapshot().TaskWrites != 0 {
		t.Fatal("read-only connection reached a device write")
	}

	journeyPath := "/api/journey?intent=manage_tasks&window=today"
	ready, err := browser.WaitJSON(journeyPath, 30*time.Second, func(value map[string]any) bool {
		return parity.StringField(value, "state") == "ready" && parity.StringField(value, "read", "choiceSetId") != ""
	})
	if err != nil {
		t.Fatalf("installed task catalog: %v, last=%#v", err, ready)
	}
	choiceSet := parity.StringField(ready, "read", "choiceSetId")
	status, raw, err = browser.JSON(http.MethodPost, "/api/journey/select", map[string]any{"choiceIndex": 1, "choiceSetId": choiceSet})
	selected, _ := parity.DecodeObject(raw)
	if err != nil || status != http.StatusOK || parity.StringField(selected, "state") != "target_selected" || fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("installed selection status=%d err=%v body=%s", status, err, raw)
	}
	status, raw, err = browser.JSON(http.MethodPost, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
	prepared, _ := parity.DecodeObject(raw)
	confirmation := parity.StringField(prepared, "businessConfirmationToken")
	if err != nil || status != http.StatusOK || confirmation == "" || fixture.Snapshot().TaskWrites != 0 {
		t.Fatalf("installed prepare status=%d err=%v body=%s", status, err, raw)
	}
	status, _, _ = browser.JSON(http.MethodPost, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": "not-current"})
	if status != http.StatusConflict || fixture.Snapshot().TaskWrites != 0 {
		t.Fatal("invalid installed confirmation was not zero-write fail-closed")
	}
	status, raw, err = browser.JSON(http.MethodPost, "/api/journey/confirm-business", map[string]any{"businessConfirmationToken": confirmation})
	if err != nil || status != http.StatusOK {
		t.Fatalf("installed confirmation status=%d err=%v body=%s", status, err, raw)
	}
	terminal, err := browser.WaitJSON(journeyPath, 45*time.Second, func(value map[string]any) bool {
		return parity.StringField(value, "state") == "complete"
	})
	if err != nil {
		t.Fatalf("installed action did not complete: %v, last=%#v", err, terminal)
	}
	if parity.StringField(terminal, "report", "evidenceStatus") != "sealed" {
		t.Fatalf("installed evidence is not sealed: %#v", terminal)
	}
	if snapshot := fixture.Snapshot(); snapshot.TaskWrites != 1 || snapshot.TaskEnabled != 0 {
		t.Fatalf("installed target writes=%d enabled=%d", snapshot.TaskWrites, snapshot.TaskEnabled)
	}
	for range 3 {
		_, _, _ = browser.Get(journeyPath)
	}
	if fixture.Snapshot().TaskWrites != 1 {
		t.Fatal("terminal refresh replayed the installed write")
	}

	statusEntry := filepath.Join(operatorHome, "bin", "cosmoedge-operator-status.ps1")
	statusCommand := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", statusEntry)
	statusCommand.Env = childEnv
	statusOutput, err := statusCommand.CombinedOutput()
	if err != nil || !bytes.Contains(statusOutput, []byte("连接状态：已连接")) {
		t.Fatalf("installed status failed: %v\n%s", err, statusOutput)
	}

	beforeDeepLink := countCapturedURLs(capturePath)
	operator := filepath.Join(operatorHome, "bin", "cosmoedge-operator.exe")
	queryOutput := runInstalledSkillQueries(t, operator, childEnv)
	deepLink := exec.Command(operator, "open", "task-index", "1", "parameters")
	deepLink.Env = childEnv
	deepOutput, err := deepLink.CombinedOutput()
	if err != nil {
		t.Fatalf("installed task-index open failed: %v\n%s", err, deepOutput)
	}
	deepBootstrap := waitCapturedURL(t, capturePath, beforeDeepLink, 30*time.Second)
	if strings.Contains(deepBootstrap, "Parity Algorithm") || strings.Contains(deepBootstrap, "parameters") {
		t.Fatal("task-index bootstrap URL exposed its friendly intent")
	}
	deepBrowser, err := parity.ConsumeBootstrap(deepBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	deepPage := deepBrowser.Bodies()
	if !bytes.Contains(deepPage, []byte("Parity Algorithm")) || !bytes.Contains(deepPage, []byte("parameters")) || fixture.Snapshot().TaskWrites != 1 {
		t.Fatal("installed task-index open did not remain a zero-write friendly page intent")
	}

	locatorBefore := readLocatorPID(t, stateRoot)
	beforeReopen := countCapturedURLs(capturePath)
	reopen := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", launcher)
	reopen.Env = childEnv
	reopenOutput, err := reopen.CombinedOutput()
	if err != nil || !bytes.Contains(reopenOutput, []byte(`"status":"opened"`)) {
		t.Fatalf("installed reopen failed: %v\n%s", err, reopenOutput)
	}
	_ = waitCapturedURL(t, capturePath, beforeReopen, 30*time.Second)
	if locatorAfter := readLocatorPID(t, stateRoot); locatorAfter != locatorBefore {
		t.Fatalf("dual launch replaced host pid %d with %d", locatorBefore, locatorAfter)
	}

	assertProtectedStateTree(t, stateRoot)
	assertNoSentinels(t, "status and launcher output", bytes.Join([][]byte{installOutput, launchOutput, statusOutput, queryOutput, deepOutput, reopenOutput}, nil), password, fullSN, endpoint)
	assertTreeNoSentinels(t, "state tree", stateRoot, password, fullSN, endpoint, confirmation, connectionToken)
	assertTreeNoSentinels(t, "installed Skill", filepath.Join(codexHome, "skills", "cosmoedge-operator"), password, fullSN)

	removeEntry := filepath.Join(operatorHome, "bin", "cosmoedge-operator-remove.ps1")
	remove := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", removeEntry)
	remove.Env = childEnv
	removeOutput, err := remove.CombinedOutput()
	if err != nil || !bytes.Contains(removeOutput, []byte(`"status":"removed"`)) {
		t.Fatalf("installed removal failed: %v\n%s", err, removeOutput)
	}
	for _, removed := range []string{operatorHome, stateRoot, filepath.Join(codexHome, "skills", "cosmoedge-operator")} {
		if _, err := os.Stat(removed); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("removed path remains: %s", removed)
		}
	}
	assertNoSentinels(t, "removal output", removeOutput, password, fullSN, endpoint)
	t.Log("installed release passed: fixture target writes=1, real-device writes=0, evidence=sealed, dual launch reused one host, removal left no Operator authority")
}

func assertReleaseBundle(t *testing.T, root string) {
	t.Helper()
	expected := map[string]bool{"cosmoedge-operator.exe": true, "cosmoedge-operator-bootstrap.ps1": true, "demo": true}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(expected) {
		t.Fatalf("release bundle root entries=%d, want %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			t.Fatalf("unexpected release bundle root asset %s", entry.Name())
		}
	}
	for _, required := range []string{
		"cosmoedge-operator.exe", "cosmoedge-operator-bootstrap.ps1",
		filepath.Join("demo", "skill", "cosmoedge-operator", "SKILL.md"),
	} {
		if info, err := os.Stat(filepath.Join(root, required)); err != nil || info.IsDir() {
			t.Fatalf("release bundle missing %s", required)
		}
	}
	bootstrap, _ := os.ReadFile(filepath.Join(root, "cosmoedge-operator-bootstrap.ps1"))
	for _, forbidden := range []string{"cosmoedge-v2", "cosmoedge-explore", "cosmoedge-dev-device", "cosmoedge-device-lab", "DevAuthority", "DevLab", "InstallEngineeringCompatibility", "go build", "go run"} {
		if bytes.Contains(bytes.ToLower(bootstrap), bytes.ToLower([]byte(forbidden))) {
			t.Fatalf("release bootstrap contains legacy/source dependency %q", forbidden)
		}
	}
}

func assertInstalledLayout(t *testing.T, operatorHome, codexHome string) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(operatorHome, ".cosmoedge-operator-root"),
		filepath.Join(operatorHome, "bin", "cosmoedge-operator.exe"),
		filepath.Join(operatorHome, "bin", "cosmoedge-operator.ps1"),
		filepath.Join(operatorHome, "bin", "cosmoedge-operator.cmd"),
		filepath.Join(operatorHome, "bin", "cosmoedge-operator-status.ps1"),
		filepath.Join(operatorHome, "bin", "cosmoedge-operator-remove.ps1"),
		filepath.Join(codexHome, "skills", "cosmoedge-operator", "SKILL.md"),
	} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Fatalf("installed asset missing: %s", path)
		}
	}
	for _, forbidden := range []string{"cosmoedge-v2.exe", "cosmoedge-explore.exe", "cosmoedge-explore-control.exe", "cosmoedge-dev-device.exe", "cosmoedge-device-lab.exe"} {
		if _, err := os.Stat(filepath.Join(operatorHome, "bin", forbidden)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("installed ordinary bundle contains %s", forbidden)
		}
	}
}

func assertSameFile(t *testing.T, first, second string) {
	t.Helper()
	firstRaw, firstErr := os.ReadFile(first)
	secondRaw, secondErr := os.ReadFile(second)
	if firstErr != nil || secondErr != nil || !bytes.Equal(firstRaw, secondRaw) {
		t.Fatalf("installed asset differs from bundle: %s -> %s, firstErr=%v secondErr=%v", first, second, firstErr, secondErr)
	}
}

func runInstalledSkillQueries(t *testing.T, operator string, environment []string) []byte {
	t.Helper()
	queries := []struct {
		args     []string
		expected string
	}{
		{args: []string{"query", "overview"}, expected: "设备概况"},
		{args: []string{"query", "cameras"}, expected: "Parity Camera"},
		{args: []string{"query", "tasks"}, expected: "Parity Algorithm + Parity Camera"},
		{args: []string{"query", "runtime"}, expected: "当前任务运行状态"},
		{args: []string{"query", "alarms", "today"}, expected: "今日告警"},
		{args: []string{"query", "alarms", "yesterday"}, expected: "昨天告警"},
		{args: []string{"query", "alarms", "last_1h"}, expected: "最近 1 小时告警"},
		{args: []string{"query", "alarms", "last_24h"}, expected: "最近 24 小时告警"},
		{args: []string{"query", "capabilities"}, expected: "当前可操作"},
	}
	var output bytes.Buffer
	for _, query := range queries {
		command := exec.Command(operator, query.args...)
		command.Env = environment
		raw, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(raw, []byte(query.expected)) {
			t.Fatalf("installed Skill query %q failed: %v\n%s", strings.Join(query.args, " "), err, raw)
		}
		output.Write(raw)
	}
	return output.Bytes()
}

func assertProtectedStateTree(t *testing.T, root string) {
	t.Helper()
	if err := localstate.ValidateStateRoot(root); err != nil {
		t.Fatalf("state root DACL: %v", err)
	}
	for _, name := range []string{"owner.lock", "locator.json", "operator.db", "operator.db-wal", "operator.db-shm"} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := localstate.ValidateFile(path); err != nil {
			t.Fatalf("state file %s DACL: %v", name, err)
		}
	}
}

func waitCapturedURL(t *testing.T, path string, index int, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		lines := capturedURLs(path)
		if len(lines) > index {
			parsed, err := url.Parse(lines[index])
			if err == nil && parsed.Scheme == "http" && parsed.Host != "" && parsed.Query().Get("bootstrap") != "" {
				return lines[index]
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("browser URL %d was not captured", index)
	return ""
}

func capturedURLs(path string) []string {
	raw, _ := os.ReadFile(path)
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func countCapturedURLs(path string) int { return len(capturedURLs(path)) }

func readLocatorPID(t *testing.T, root string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "locator.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		ProcessID int `json:"processId"`
	}
	if json.Unmarshal(raw, &value) != nil || value.ProcessID <= 0 {
		t.Fatal("locator process id is unavailable")
	}
	return value.ProcessID
}

func stopLocatedProcess(root string) {
	raw, err := os.ReadFile(filepath.Join(root, "locator.json"))
	if err != nil {
		return
	}
	var value struct {
		ProcessID int `json:"processId"`
	}
	if json.Unmarshal(raw, &value) != nil || value.ProcessID <= 0 {
		return
	}
	if process, err := os.FindProcess(value.ProcessID); err == nil {
		_ = process.Kill()
		_, _ = process.Wait()
	}
}

func isolatedEnvironment(overrides map[string]string) []string {
	values := map[string]string{}
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[strings.ToUpper(key)] = key + "=" + value
		}
	}
	for key, value := range overrides {
		values[strings.ToUpper(key)] = key + "=" + value
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func randomValue(t *testing.T, prefix string) string {
	t.Helper()
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatal(err)
	}
	return prefix + "-" + hex.EncodeToString(buffer)
}

func assertTreeNoSentinels(t *testing.T, label, root string, sentinels ...string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, sentinel := range sentinels {
			if sentinel != "" && bytes.Contains(raw, []byte(sentinel)) {
				return fmt.Errorf("%s contains a protected sentinel in %s", label, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertNoSentinels(t *testing.T, label string, raw []byte, sentinels ...string) {
	t.Helper()
	for _, sentinel := range sentinels {
		if sentinel != "" && bytes.Contains(raw, []byte(sentinel)) {
			t.Fatalf("%s exposed protected sentinel %s", label, strconv.Quote(sentinel))
		}
	}
}
