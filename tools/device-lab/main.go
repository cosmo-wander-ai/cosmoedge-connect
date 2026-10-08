package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devlab"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

type locator struct {
	BaseURL      string `json:"baseUrl"`
	ControlToken string `json:"controlToken"`
	OwnerID      string `json:"ownerId"`
	ProcessID    int    `json:"processId"`
}

type api struct {
	runtime  *devlab.Runtime
	token    string
	host     string
	shutdown func()
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"status": "failed", "reason": failureReason(err)})
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("exactly one device lab command is required")
	}
	root, err := devlab.DefaultRoot()
	if err != nil {
		return err
	}
	switch args[0] {
	case "serve":
		return serve(root)
	case "status":
		return invoke(root, http.MethodGet, "/v1/status", nil, out)
	case "begin":
		return invoke(root, http.MethodPost, "/v1/runs", in, out)
	case "probe":
		return invoke(root, http.MethodPost, "/v1/probes", in, out)
	case "finish":
		return invoke(root, http.MethodPost, "/v1/runs/finish", bytes.NewReader([]byte("{}")), out)
	case "stop":
		return invoke(root, http.MethodPost, "/v1/shutdown", bytes.NewReader([]byte("{}")), out)
	default:
		return errors.New("unsupported device lab command")
	}
}

func serve(root string) error {
	if err := localstate.PrepareStateRoot(root); err != nil {
		return err
	}
	lockPath := filepath.Join(root, "owner.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("device lab owner lock is already held")
	}
	defer lock.Close()
	if err := localstate.ProtectFile(lockPath); err != nil {
		return err
	}
	ownerID, err := randomHex(16)
	if err != nil {
		return err
	}
	if _, err := lock.WriteString(ownerID); err != nil {
		return err
	}

	evidence, err := devlab.OpenEvidence(root)
	if err != nil {
		return err
	}
	defer evidence.Close()
	authorityStore, err := devauthority.NewStore("")
	if err != nil {
		return err
	}
	authority, err := devauthority.New(authorityStore)
	if err != nil {
		return err
	}
	runtime, err := devlab.NewRuntime(devlab.AuthorityOpener(authority), evidence)
	if err != nil {
		return err
	}
	defer runtime.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	baseURL := "http://" + listener.Addr().String()
	token, err := randomHex(32)
	if err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	var shutdownOnce sync.Once
	server.Handler = newAPI(runtime, token, listener.Addr().String(), func() {
		shutdownOnce.Do(func() {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = server.Shutdown(ctx)
			}()
		})
	})
	loc := locator{BaseURL: baseURL, ControlToken: token, OwnerID: ownerID, ProcessID: os.Getpid()}
	if err := writeLocator(root, loc); err != nil {
		return err
	}
	defer cleanupOwner(root, ownerID)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func newAPI(runtime *devlab.Runtime, token, host string, shutdown func()) http.Handler {
	return &api{runtime: runtime, token: token, host: host, shutdown: shutdown}
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Host != a.host || !validBearer(r.Header.Get("Authorization"), a.token) {
		writeError(w, http.StatusForbidden, "control_boundary_rejected")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), MaximumRequestDuration)
	defer cancel()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
		writeJSON(w, http.StatusOK, a.runtime.Status())
	case r.Method == http.MethodPost && r.URL.Path == "/v1/runs":
		var request devlab.BeginRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		result, err := a.runtime.Begin(ctx, request)
		if err != nil {
			writeError(w, http.StatusConflict, failureReason(err))
			return
		}
		writeJSON(w, http.StatusCreated, result)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/probes":
		var request devlab.ProbeRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		result, err := a.runtime.Probe(ctx, request)
		request.Hypothesis = ""
		if err != nil {
			writeError(w, http.StatusConflict, failureReason(err))
			return
		}
		writeJSON(w, http.StatusOK, result)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/runs/finish":
		if !decodeJSON(w, r, &struct{}{}) {
			return
		}
		result, err := a.runtime.Finish(ctx)
		if err != nil {
			writeError(w, http.StatusConflict, failureReason(err))
			return
		}
		writeJSON(w, http.StatusOK, result)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/shutdown":
		if !decodeJSON(w, r, &struct{}{}) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
		a.shutdown()
	default:
		writeError(w, http.StatusNotFound, "route_not_found")
	}
}

func invoke(root, method, path string, input io.Reader, out io.Writer) error {
	loc, err := readLocator(root)
	if err != nil {
		return errors.New("device lab is unavailable")
	}
	var body io.Reader
	if input != nil {
		raw, err := io.ReadAll(io.LimitReader(input, (64<<10)+1))
		if err != nil || len(raw) > 64<<10 {
			return errors.New("device lab request is invalid")
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, strings.TrimRight(loc.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+loc.ControlToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: MaximumRequestDuration + time.Second}).Do(request)
	if err != nil {
		return errors.New("device lab is unavailable")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return errors.New("device lab response is invalid")
	}
	if _, err := out.Write(raw); err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("device lab request was rejected")
	}
	return nil
}

func readLocator(root string) (locator, error) {
	if err := localstate.ValidateStateRoot(root); err != nil {
		return locator{}, err
	}
	path := filepath.Join(root, "locator.json")
	if err := localstate.ValidateFile(path); err != nil {
		return locator{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return locator{}, err
	}
	var loc locator
	if json.Unmarshal(raw, &loc) != nil || !strings.HasPrefix(loc.BaseURL, "http://127.0.0.1:") || loc.ControlToken == "" || loc.OwnerID == "" || loc.ProcessID <= 0 {
		return locator{}, errors.New("device lab locator is invalid")
	}
	return loc, nil
}

func writeLocator(root string, loc locator) error {
	raw, err := json.Marshal(loc)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(root, "locator-*.tmp")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := localstate.ProtectFile(path); err != nil {
		return err
	}
	target := filepath.Join(root, "locator.json")
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(path, target); err != nil {
		return err
	}
	return localstate.ProtectFile(target)
}

func cleanupOwner(root, ownerID string) {
	lockPath := filepath.Join(root, "owner.lock")
	raw, err := os.ReadFile(lockPath)
	if err == nil && string(raw) == ownerID {
		_ = os.Remove(filepath.Join(root, "locator.json"))
		_ = os.Remove(lockPath)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func validBearer(header, token string) bool {
	provided := strings.TrimPrefix(header, "Bearer ")
	return len(provided) == len(token) && hmac.Equal([]byte(provided), []byte(token))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"status": "failed", "reason": reason})
}

func failureReason(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "already active"):
		return "run_already_active"
	case strings.Contains(message, "no device lab run"):
		return "run_not_active"
	case strings.Contains(message, "expired"):
		return "authority_or_run_expired"
	case strings.Contains(message, "login:"):
		return "device_login_failed"
	case strings.Contains(message, "identity"):
		return "device_identity_rejected"
	case strings.Contains(message, "stale") || strings.Contains(message, "catalog changed"):
		return "resource_handle_stale"
	case strings.Contains(message, "budget") || strings.Contains(message, "interval"):
		return "probe_budget_rejected"
	case strings.Contains(message, "assertion") || strings.Contains(message, "probe") || strings.Contains(message, "window"):
		return "probe_request_rejected"
	case strings.Contains(message, "unavailable") || strings.Contains(message, "not exist"):
		return "device_lab_unavailable"
	default:
		return "device_lab_failed"
	}
}

func randomHex(length int) (string, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

const MaximumRequestDuration = MaximumRunDuration + 10*time.Second

const MaximumRunDuration = devlab.MaximumRunDuration
