package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	ordinaryapp "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/app"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionproduct"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
	ordinaryweb "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/web"
)

type locator struct {
	BaseURL      string `json:"baseUrl"`
	ControlToken string `json:"controlToken"`
	OwnerID      string `json:"ownerId"`
	ProcessID    int    `json:"processId"`
}

var errUnavailable = errors.New("ordinary operator is unavailable")

type invocation struct {
	mode           string
	view           string
	kind           string
	window         string
	taskIndex      int
	taskAction     string
	initialBrowser bool
}

func main() {
	if err := run(); err != nil {
		if errors.Is(err, errUnavailable) {
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "CosmoEdge Operator could not start")
		os.Exit(1)
	}
}

func run() error {
	invocation, err := parseInvocation(os.Args[1:])
	if err != nil {
		return err
	}
	root, err := stateRoot()
	if err != nil {
		return err
	}
	if err := localstate.PrepareStateRoot(root); err != nil {
		return err
	}
	if err := localstate.ValidateExistingStateFiles(root); err != nil {
		return err
	}
	switch invocation.mode {
	case "status":
		return printStatus(root, os.Stdout)
	case "query":
		return printQuery(root, invocation.kind, invocation.window, os.Stdout)
	case "open":
		opened, _ := openExisting(root, invocation)
		if opened {
			return nil
		}
		return errUnavailable
	}
	if available, _ := reuseExisting(root, invocation); available {
		return nil
	}
	lockPath := filepath.Join(root, "owner.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if available, _ := reuseExisting(root, invocation); available {
				return nil
			}
		}
		_ = os.Remove(filepath.Join(root, "locator.json"))
		_ = os.Remove(lockPath)
		lock, err = os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
	}
	defer lock.Close()
	if err := localstate.ProtectFile(lockPath); err != nil {
		return err
	}

	ownerID, err := randomHex(16)
	if err != nil {
		return err
	}
	_, _ = lock.WriteString(ownerID)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	baseURL := "http://" + listener.Addr().String()
	controlToken, err := randomHex(32)
	if err != nil {
		return err
	}
	vault := session.New(nil)
	databasePath := filepath.Join(root, "operator.db")
	store, err := ledger.Open(databasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := localstate.ValidateExistingStateFiles(root); err != nil {
		return err
	}
	actionManager, err := actions.New(store, vault)
	if err != nil {
		return err
	}
	if err := actionManager.Start(context.Background()); err != nil {
		return err
	}
	defer actionManager.Stop()
	if err := localstate.ValidateExistingStateFiles(root); err != nil {
		return err
	}
	inspectionV2, err := inspectionproduct.New(inspectionproduct.Config{
		Enabled:   false,
		StateRoot: root,
	}, inspectionproduct.Factories{})
	if err != nil {
		return err
	}
	if err := inspectionV2.Start(context.Background()); err != nil {
		return err
	}
	defer inspectionV2.Stop()
	service := ordinaryapp.New(vault, actionManager)
	opener := func(rawURL string) error { return openBrowser(rawURL) }
	host := ordinaryweb.New(baseURL, controlToken, service, vault, opener)
	server := &http.Server{Handler: host, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()

	loc := locator{BaseURL: baseURL, ControlToken: controlToken, OwnerID: ownerID, ProcessID: os.Getpid()}
	if err := writeLocator(root, loc); err != nil {
		_ = server.Close()
		return err
	}
	defer cleanupOwner(root, ownerID)
	if invocation.initialBrowser {
		bootstrap, err := host.BootstrapURL(invocation.view)
		if err != nil {
			_ = server.Close()
			return err
		}
		if err := openBrowser(bootstrap); err != nil {
			_ = server.Close()
			return err
		}
	}
	err = <-serveErrors
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func stateRoot() (string, error) {
	return localstate.DefaultStateRoot()
}

func parseInvocation(args []string) (invocation, error) {
	if len(args) == 0 {
		return invocation{mode: "launch", view: "home", initialBrowser: true}, nil
	}
	switch args[0] {
	case "--no-initial-browser":
		if len(args) != 1 {
			return invocation{}, errors.New("--no-initial-browser accepts no arguments")
		}
		return invocation{mode: "launch", view: "home", initialBrowser: false}, nil
	case "status":
		if len(args) != 1 {
			return invocation{}, errors.New("status accepts no arguments")
		}
		return invocation{mode: "status"}, nil
	case "open":
		if len(args) == 4 && args[1] == "task-index" {
			index, err := strconv.Atoi(args[2])
			if err != nil || index < 1 || index > 10000 {
				return invocation{}, errors.New("displayed task list number is unavailable")
			}
			if args[3] != "enable" && args[3] != "disable" && args[3] != "parameters" {
				return invocation{}, errors.New("task-index open requires enable, disable, or parameters")
			}
			return invocation{mode: "open", view: "manage_tasks", taskIndex: index, taskAction: args[3], initialBrowser: true}, nil
		}
		if len(args) != 2 {
			return invocation{}, errors.New("open requires one fixed view or task-index intent")
		}
		view := map[string]string{
			"home": "home", "tasks": "manage_tasks", "sources": "manage_sources",
			"runtime": "inspect_runtime", "alarms": "inspect_alerts",
		}[args[1]]
		if view == "" {
			return invocation{}, errors.New("unsupported open view")
		}
		return invocation{mode: "open", view: view, initialBrowser: true}, nil
	case "query":
		if len(args) < 2 || len(args) > 3 {
			return invocation{}, errors.New("query requires one fixed kind and optional alarm window")
		}
		kind := args[1]
		switch kind {
		case "overview", "cameras", "tasks", "runtime", "capabilities":
			if len(args) != 2 {
				return invocation{}, errors.New("query kind accepts no window")
			}
			return invocation{mode: "query", kind: kind, window: "today"}, nil
		case "alarms":
			window := "today"
			if len(args) == 3 {
				window = args[2]
			}
			if window != "today" && window != "yesterday" && window != "last_1h" && window != "last_24h" {
				return invocation{}, errors.New("unsupported alarm window")
			}
			return invocation{mode: "query", kind: kind, window: window}, nil
		default:
			return invocation{}, errors.New("unsupported query kind")
		}
	default:
		return invocation{}, errors.New("unsupported command")
	}
}

func reuseExisting(root string, input invocation) (bool, error) {
	if input.initialBrowser {
		return openExisting(root, input)
	}
	return probeExisting(root)
}

func probeExisting(root string) (bool, error) {
	loc, err := readLocator(root)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(loc.BaseURL, "/")+"/internal/health", nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("X-CosmoEdge-Control", loc.ControlToken)
	response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusNoContent, nil
}

func openExisting(root string, input invocation) (bool, error) {
	loc, err := readLocator(root)
	if err != nil {
		return false, err
	}
	body, _ := json.Marshal(map[string]any{
		"view": input.view, "taskIndex": input.taskIndex, "taskAction": input.taskAction,
	})
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(loc.BaseURL, "/")+"/internal/open", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CosmoEdge-Control", loc.ControlToken)
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusNoContent, nil
}

func printStatus(root string, out io.Writer) error {
	loc, err := readLocator(root)
	if err != nil {
		fmt.Fprintln(out, "本地设备运营当前未运行，或状态已经失效。")
		fmt.Fprintln(out, "下一步：打开 CosmoEdge 设备运营页面。")
		return errUnavailable
	}
	request, _ := http.NewRequest(http.MethodGet, strings.TrimRight(loc.BaseURL, "/")+"/internal/status", nil)
	request.Header.Set("X-CosmoEdge-Control", loc.ControlToken)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return errUnavailable
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_, _ = out.Write(raw)
	if response.StatusCode != http.StatusOK {
		return errUnavailable
	}
	return nil
}

func printQuery(root, kind, window string, out io.Writer) error {
	loc, err := readLocator(root)
	if err != nil {
		fmt.Fprintln(out, "本地设备运营当前未运行，或只读状态已经失效。")
		fmt.Fprintln(out, "下一步：打开 CosmoEdge 设备运营页面。")
		return errUnavailable
	}
	body, _ := json.Marshal(map[string]string{"kind": kind, "window": window})
	request, _ := http.NewRequest(http.MethodPost, strings.TrimRight(loc.BaseURL, "/")+"/internal/query", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CosmoEdge-Control", loc.ControlToken)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return errUnavailable
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	_, _ = out.Write(raw)
	if response.StatusCode != http.StatusOK {
		return errUnavailable
	}
	return nil
}

func readLocator(root string) (locator, error) {
	path := filepath.Join(root, "locator.json")
	if err := localstate.ValidateStateRoot(root); err != nil {
		return locator{}, err
	}
	if err := localstate.ValidateFile(path); err != nil {
		return locator{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return locator{}, err
	}
	var loc locator
	if json.Unmarshal(raw, &loc) != nil || loc.BaseURL == "" || loc.ControlToken == "" || loc.OwnerID == "" || loc.ProcessID <= 0 {
		return locator{}, errors.New("invalid locator")
	}
	return loc, nil
}

func writeLocator(root string, loc locator) error {
	raw, err := json.Marshal(loc)
	if err != nil {
		return err
	}
	temporary := filepath.Join(root, "locator.json.tmp")
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := localstate.ProtectFile(temporary); err != nil {
		return err
	}
	path := filepath.Join(root, "locator.json")
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return localstate.ProtectFile(path)
}

func cleanupOwner(root, ownerID string) {
	raw, err := os.ReadFile(filepath.Join(root, "locator.json"))
	if err == nil {
		var loc locator
		if json.Unmarshal(raw, &loc) == nil && loc.OwnerID == ownerID {
			_ = os.Remove(filepath.Join(root, "locator.json"))
			_ = os.Remove(filepath.Join(root, "owner.lock"))
		}
	}
}

func randomHex(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
