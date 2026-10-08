package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	ordinaryapp "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/app"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/read"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestBootstrapRendersFunctionalDeepLinkedWorkbench(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()
	vault := session.New(nil)
	host := New(baseURL, "control-private", fakeBackend{}, vault, func(string) error { return nil })
	server := &http.Server{Handler: host}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	bootstrap, err := host.BootstrapURL("manage_tasks")
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	response, err := client.Get(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)
	if response.Request.URL.String() != baseURL+"/" {
		t.Fatalf("page URL=%q", response.Request.URL)
	}
	for _, expected := range []string{
		"CosmoEdge Connect", "连接一台设备", "设备 IP", "分析任务",
		"const initialView='manage_tasks'", "function renderHome", "function renderTasks",
		"function renderParameterEditor", "function renderSourceEditor", "/api/journey/confirm-business",
		"[hidden]{display:none!important}",
		"确认设备地址", "确认连接", "替换保存设备并连接", "replaceSavedDevice",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("workbench missing %q", expected)
		}
	}
	for _, forbidden := range []string{"workflowId", "operationId", "confirmationText", "control-private"} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("workbench exposed %q", forbidden)
		}
	}
	if !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("CSP=%q", response.Header.Get("Content-Security-Policy"))
	}
	start, end := strings.Index(page, "<script>"), strings.LastIndex(page, "</script>")
	if start < 0 || end <= start {
		t.Fatal("workbench script is unavailable")
	}
	scriptPath := filepath.Join(t.TempDir(), "workbench.js")
	if err := os.WriteFile(scriptPath, []byte(page[start+len("<script>"):end]), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("node", "--check", scriptPath).CombinedOutput(); err != nil {
		t.Fatalf("workbench JavaScript syntax: %v\n%s", err, output)
	}
}

func TestControlOpenResolvesTaskIndexBeforeIssuingPrivateBootstrap(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()
	vault := session.New(nil)
	opened := make(chan string, 1)
	host := New(baseURL, "private-control", taskIntentBackend{fakeBackend{}}, vault, func(raw string) error {
		opened <- raw
		return nil
	})
	server := &http.Server{Handler: host}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	raw, _ := json.Marshal(map[string]any{"view": "manage_tasks", "taskIndex": 2, "taskAction": "parameters"})
	request, _ := http.NewRequest(http.MethodPost, baseURL+"/internal/open", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CosmoEdge-Control", "private-control")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("control open status=%d", response.StatusCode)
	}
	bootstrap := <-opened
	if strings.Contains(bootstrap, "Parity Algorithm") || strings.Contains(bootstrap, "parameters") {
		t.Fatalf("bootstrap URL exposed task intent: %s", bootstrap)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	pageResponse, err := client.Get(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(pageResponse.Body)
	pageResponse.Body.Close()
	for _, expected := range []string{
		"const initialView='manage_tasks'", "Parity Algorithm", "Parity Camera",
		"const launchAction='parameters'", "function continueLaunch",
	} {
		if !strings.Contains(string(page), expected) {
			t.Fatalf("task workbench missing %q", expected)
		}
	}
}

func TestInspectionInteractionOpenSealsExactHandoffInCookie(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + listener.Addr().String()
	vault := session.New(nil)
	opened := make(chan string, 1)
	host := New(baseURL, "private-control", fakeBackend{}, vault, func(raw string) error {
		opened <- raw
		return nil
	})
	resolved := make(chan error, 1)
	if err := host.MountInspectionLocal(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		cookie, cookieErr := request.Cookie(SessionCookieName)
		if cookieErr != nil {
			resolved <- cookieErr
			http.Error(response, "missing session", http.StatusUnauthorized)
			return
		}
		auth, authErr := vault.Authenticate(cookie.Value)
		if authErr != nil {
			resolved <- authErr
			http.Error(response, "bad session", http.StatusUnauthorized)
			return
		}
		handoff, handoffErr := vault.InspectionHandoff(auth)
		if handoffErr == nil && handoff != "handoff_cookie_exact" {
			handoffErr = errors.New("wrong sealed handoff")
		}
		resolved <- handoffErr
		response.WriteHeader(http.StatusNoContent)
	})); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: host}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	if err := host.OpenInspectionInteraction("handoff_cookie_exact"); err != nil {
		t.Fatal(err)
	}
	bootstrap := <-opened
	if strings.Contains(bootstrap, "handoff_cookie_exact") || strings.Contains(bootstrap, "handoff") {
		t.Fatalf("bootstrap URL exposed handoff: %s", bootstrap)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	response, err := client.Get(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.Request.URL.Path != "/inspection/interaction" || response.StatusCode != http.StatusNoContent {
		t.Fatalf("final page=%s status=%d", response.Request.URL, response.StatusCode)
	}
	if err := <-resolved; err != nil {
		t.Fatal(err)
	}
}

type taskIntentBackend struct{ fakeBackend }

func (taskIntentBackend) Journey(context.Context, string, string, string) (read.Projection, error) {
	return read.Projection{
		State: "ready",
		Read: read.ReadSurface{ChoiceSetID: "fresh-choice", Tasks: []read.Task{
			{Index: 1, DisplayName: "First Task"},
			{Index: 2, DisplayName: "Parity Algorithm + Parity Camera"},
		}},
	}, nil
}

type fakeBackend struct{}

func (fakeBackend) PrepareConnection(string, string, string) (session.ConnectionPreview, error) {
	return session.ConnectionPreview{}, nil
}

func (fakeBackend) Connect(context.Context, string, string, []byte) (session.ConnectionInfo, error) {
	return session.ConnectionInfo{}, nil
}

func (fakeBackend) CanRetrySavedConnection() bool { return false }

func (fakeBackend) RetrySavedConnection(context.Context, string) (session.RestoreResult, error) {
	return session.RestoreResult{}, session.ErrConflict
}

func (fakeBackend) Journey(context.Context, string, string, string) (read.Projection, error) {
	return read.Disconnected("home"), nil
}

func (fakeBackend) Select(context.Context, string, int, string) (read.Projection, error) {
	return read.Projection{}, nil
}

func (fakeBackend) PreparePersistent(context.Context, string, int) (read.Projection, error) {
	return read.Projection{}, nil
}

func (fakeBackend) ConfirmBusiness(context.Context, string, string) (read.Projection, error) {
	return read.Projection{}, nil
}

func (fakeBackend) CancelBusiness(context.Context, string) (read.Projection, error) {
	return read.Projection{}, nil
}

func (fakeBackend) TaskParameters(context.Context, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) PrepareTaskParameters(context.Context, string, []actions.ParameterField) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) ConfirmTaskParameters(context.Context, string, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) CancelTaskParameters(context.Context, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) ResetTaskParameters(context.Context, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) CameraSource(context.Context, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) PrepareCameraSource(context.Context, string, string, []byte) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) ConfirmCameraSource(context.Context, string, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) CancelCameraSource(context.Context, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) ResetCameraSource(context.Context, string) (ordinaryapp.ToolboxView, error) {
	return ordinaryapp.ToolboxView{}, nil
}

func (fakeBackend) Status(context.Context) string { return "status" }

func (fakeBackend) Query(context.Context, string, string) (string, error) { return "query", nil }
