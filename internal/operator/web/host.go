package web

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	ordinaryapp "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/app"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/read"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const SessionCookieName = "cosmoedge_operator_session"

type Backend interface {
	PrepareConnection(browserID, endpoint, username string) (session.ConnectionPreview, error)
	Connect(context.Context, string, string, []byte) (session.ConnectionInfo, error)
	CanRetrySavedConnection() bool
	RetrySavedConnection(context.Context, string) (session.RestoreResult, error)
	Journey(context.Context, string, string, string) (read.Projection, error)
	Select(context.Context, string, int, string) (read.Projection, error)
	PreparePersistent(context.Context, string, int) (read.Projection, error)
	ConfirmBusiness(context.Context, string, string) (read.Projection, error)
	CancelBusiness(context.Context, string) (read.Projection, error)
	TaskParameters(context.Context, string) (ordinaryapp.ToolboxView, error)
	PrepareTaskParameters(context.Context, string, []actions.ParameterField) (ordinaryapp.ToolboxView, error)
	ConfirmTaskParameters(context.Context, string, string) (ordinaryapp.ToolboxView, error)
	CancelTaskParameters(context.Context, string) (ordinaryapp.ToolboxView, error)
	ResetTaskParameters(context.Context, string) (ordinaryapp.ToolboxView, error)
	CameraSource(context.Context, string) (ordinaryapp.ToolboxView, error)
	PrepareCameraSource(context.Context, string, string, []byte) (ordinaryapp.ToolboxView, error)
	ConfirmCameraSource(context.Context, string, string) (ordinaryapp.ToolboxView, error)
	CancelCameraSource(context.Context, string) (ordinaryapp.ToolboxView, error)
	ResetCameraSource(context.Context, string) (ordinaryapp.ToolboxView, error)
	Status(context.Context) string
	Query(context.Context, string, string) (string, error)
}

type BootstrapVault interface {
	IssueBootstrap() (string, error)
	IssueBootstrapForView(string) (string, error)
	IssueBootstrapForIntent(session.OpenIntent) (string, error)
	ConsumeBootstrap(string) (session.BrowserAuth, error)
	Authenticate(string) (session.BrowserAuth, error)
}

type Host struct {
	baseURL                 string
	controlToken            string
	backend                 Backend
	vault                   BootstrapVault
	openBrowser             func(string) error
	mux                     *http.ServeMux
	inspectionLocalMounted  bool
	deploymentReviewMounted bool
}

func New(baseURL, controlToken string, backend Backend, vault BootstrapVault, openBrowser func(string) error) *Host {
	host := &Host{baseURL: strings.TrimRight(baseURL, "/"), controlToken: controlToken, backend: backend, vault: vault, openBrowser: openBrowser, mux: http.NewServeMux()}
	host.routes()
	return host
}

func (h *Host) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.mux.ServeHTTP(w, r)
}

// MountInspectionLocal attaches the exact-handoff local application to this
// foreground Operator origin. It must be called before the HTTP server starts.
func (h *Host) MountInspectionLocal(handler http.Handler) error {
	if h == nil || h.mux == nil || handler == nil || h.inspectionLocalMounted {
		return errors.New("inspection local page is unavailable")
	}
	h.mux.Handle("GET /inspection/interaction", handler)
	h.mux.Handle("POST /inspection/interaction", handler)
	h.inspectionLocalMounted = true
	return nil
}

// OpenInspectionInteraction opens a one-time bootstrap whose handoff remains
// sealed in the foreground cookie rather than appearing in the browser URL.
func (h *Host) OpenInspectionInteraction(handoffRef string) error {
	if h == nil || h.openBrowser == nil || !h.inspectionLocalMounted {
		return errors.New("inspection local page is unavailable")
	}
	bootstrap, err := h.BootstrapURLForIntent(session.OpenIntent{
		View: session.ViewInspectionInteraction, HandoffRef: handoffRef,
	})
	if err != nil {
		return err
	}
	return h.openBrowser(bootstrap)
}

// MountDeploymentReview attaches the browser-only confirmation gate before serving.
func (h *Host) MountDeploymentReview(handler http.Handler) error {
	if h == nil || h.mux == nil || handler == nil || h.deploymentReviewMounted {
		return errors.New("deployment review page is unavailable")
	}
	h.mux.Handle("GET /deployment/review", handler)
	h.mux.Handle("POST /deployment/review", handler)
	h.deploymentReviewMounted = true
	return nil
}

func (h *Host) OpenDeploymentReview(handoffRef string) error {
	if h == nil || h.openBrowser == nil || !h.deploymentReviewMounted {
		return errors.New("deployment review page is unavailable")
	}
	bootstrap, err := h.BootstrapURLForIntent(session.OpenIntent{View: session.ViewDeploymentConfirmation, HandoffRef: handoffRef})
	if err != nil {
		return err
	}
	return h.openBrowser(bootstrap)
}

func (h *Host) routes() {
	h.mux.HandleFunc("GET /", h.home)
	h.mux.HandleFunc("POST /api/connection/prepare", h.prepareConnection)
	h.mux.HandleFunc("POST /api/connection/connect", h.connect)
	h.mux.HandleFunc("POST /api/connection/retry", h.retrySavedConnection)
	h.mux.HandleFunc("GET /api/journey", h.journey)
	h.mux.HandleFunc("POST /api/journey/select", h.selectTask)
	h.mux.HandleFunc("POST /api/journey/prepare-persistent", h.preparePersistent)
	h.mux.HandleFunc("POST /api/journey/confirm-business", h.confirmBusiness)
	h.mux.HandleFunc("POST /api/journey/cancel", h.cancelBusiness)
	h.mux.HandleFunc("GET /api/toolbox/task-parameters", h.taskParameters)
	h.mux.HandleFunc("POST /api/toolbox/task-parameters/prepare", h.prepareTaskParameters)
	h.mux.HandleFunc("POST /api/toolbox/task-parameters/confirm", h.confirmTaskParameters)
	h.mux.HandleFunc("POST /api/toolbox/task-parameters/cancel", h.cancelTaskParameters)
	h.mux.HandleFunc("POST /api/toolbox/task-parameters/reset", h.resetTaskParameters)
	h.mux.HandleFunc("GET /api/toolbox/camera-source", h.cameraSource)
	h.mux.HandleFunc("POST /api/toolbox/camera-source/prepare", h.prepareCameraSource)
	h.mux.HandleFunc("POST /api/toolbox/camera-source/confirm", h.confirmCameraSource)
	h.mux.HandleFunc("POST /api/toolbox/camera-source/cancel", h.cancelCameraSource)
	h.mux.HandleFunc("POST /api/toolbox/camera-source/reset", h.resetCameraSource)
	h.mux.HandleFunc("POST /internal/open", h.controlOpen)
	h.mux.HandleFunc("GET /internal/health", h.controlHealth)
	h.mux.HandleFunc("GET /internal/status", h.controlStatus)
	h.mux.HandleFunc("POST /internal/query", h.controlQuery)
}

func (h *Host) BootstrapURL(view string) (string, error) {
	return h.BootstrapURLForIntent(session.OpenIntent{View: view})
}

func (h *Host) BootstrapURLForIntent(intent session.OpenIntent) (string, error) {
	token, err := h.vault.IssueBootstrapForIntent(intent)
	if err != nil {
		return "", err
	}
	query := url.Values{"bootstrap": {token}}
	return h.baseURL + "/?" + query.Encode(), nil
}

func (h *Host) home(w http.ResponseWriter, r *http.Request) {
	if token := r.URL.Query().Get("bootstrap"); token != "" {
		auth, err := h.vault.ConsumeBootstrap(token)
		if err != nil {
			http.Error(w, "bootstrap unavailable", http.StatusGone)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: auth.SessionID, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		redirect := "/"
		if auth.View == session.ViewInspectionInteraction {
			redirect = "/inspection/interaction"
		} else if auth.View == session.ViewDeploymentConfirmation {
			redirect = "/deployment/review"
		}
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}
	auth, err := h.browserAuth(r)
	if err != nil {
		http.Error(w, "foreground session unavailable", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplate.Execute(w, map[string]any{
		"CSRF": auth.CSRF, "View": auth.View,
		"TaskName": auth.TaskName, "TaskAction": auth.TaskAction,
		// This is a local in-memory capability, never a device read or retry.
		"CanRetrySavedConnection": auth.View == session.ViewConnection && h.backend.CanRetrySavedConnection(),
	})
}

func (h *Host) prepareConnection(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	preview, err := h.backend.PrepareConnection(auth.SessionID, r.PostForm.Get("endpoint"), r.PostForm.Get("username"))
	if err != nil {
		http.Error(w, "device destination is not allowed", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connectionToken": preview.Token, "destination": preview.Destination, "expiresAt": preview.ExpiresAt, "currentDestination": preview.CurrentDestination, "replacementRequired": preview.ReplacementRequired, "replacementAvailable": preview.ReplacementAvailable})
}

func (h *Host) connect(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	password := []byte(r.PostForm.Get("password"))
	var result session.ConnectionInfo
	var err error
	if r.PostForm.Get("replaceSavedDevice") == "true" {
		if backend, ok := h.backend.(interface {
			ConnectConfirmed(context.Context, string, string, []byte, bool) (session.ConnectionInfo, error)
		}); ok {
			result, err = backend.ConnectConfirmed(r.Context(), auth.SessionID, r.PostForm.Get("connectionToken"), password, true)
		} else {
			clear(password)
			err = session.ErrConnectionReplacementRequired
		}
	} else {
		result, err = h.backend.Connect(r.Context(), auth.SessionID, r.PostForm.Get("connectionToken"), password)
	}
	if err != nil {
		status := statusFor(err)
		if status == http.StatusBadRequest {
			status = http.StatusBadGateway
		}
		http.Error(w, "device connection was not accepted", status)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) retrySavedConnection(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	result, err := h.backend.RetrySavedConnection(r.Context(), auth.SessionID)
	if err != nil {
		status := statusFor(err)
		if status == http.StatusBadRequest {
			status = http.StatusBadGateway
		}
		http.Error(w, "saved connection could not be restored", status)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": result.State, "canRetrySavedConnection": h.backend.CanRetrySavedConnection()})
}

func (h *Host) journey(w http.ResponseWriter, r *http.Request) {
	auth, err := h.browserAuth(r)
	if err != nil {
		http.Error(w, "foreground session unavailable", http.StatusUnauthorized)
		return
	}
	result, err := h.backend.Journey(r.Context(), auth.SessionID, r.URL.Query().Get("intent"), r.URL.Query().Get("window"))
	if err != nil {
		http.Error(w, "journey unavailable", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		read.Projection
		CanRetrySavedConnection bool `json:"canRetrySavedConnection,omitempty"`
	}{result, result.State == "disconnected" && h.backend.CanRetrySavedConnection()})
}

func (h *Host) selectTask(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct {
		ChoiceIndex int    `json:"choiceIndex"`
		ChoiceSetID string `json:"choiceSetId"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, "invalid selection", http.StatusBadRequest)
		return
	}
	result, err := h.backend.Select(r.Context(), auth.SessionID, input.ChoiceIndex, input.ChoiceSetID)
	if err != nil {
		http.Error(w, "selection unavailable", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) preparePersistent(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct {
		TargetEnabled int `json:"targetEnabled"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	result, err := h.backend.PreparePersistent(r.Context(), auth.SessionID, input.TargetEnabled)
	if err != nil {
		http.Error(w, "preparation unavailable", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) confirmBusiness(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct {
		Token string `json:"businessConfirmationToken"`
	}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "invalid confirmation", http.StatusBadRequest)
		return
	}
	result, err := h.backend.ConfirmBusiness(r.Context(), auth.SessionID, input.Token)
	if err != nil {
		http.Error(w, "confirmation unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) cancelBusiness(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct{}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "invalid cancellation", http.StatusBadRequest)
		return
	}
	result, err := h.backend.CancelBusiness(r.Context(), auth.SessionID)
	if err != nil {
		http.Error(w, "cancellation unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) taskParameters(w http.ResponseWriter, r *http.Request) {
	auth, err := h.browserAuth(r)
	if err != nil {
		http.Error(w, "foreground session unavailable", http.StatusUnauthorized)
		return
	}
	result, err := h.backend.TaskParameters(r.Context(), auth.SessionID)
	if err != nil {
		http.Error(w, "task parameters unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) prepareTaskParameters(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct {
		Fields []actions.ParameterField `json:"fields"`
	}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "invalid parameter proposal", http.StatusBadRequest)
		return
	}
	result, err := h.backend.PrepareTaskParameters(r.Context(), auth.SessionID, input.Fields)
	if err != nil {
		http.Error(w, "parameter preparation unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) confirmTaskParameters(w http.ResponseWriter, r *http.Request) {
	h.confirmToolbox(w, r, h.backend.ConfirmTaskParameters)
}

func (h *Host) cancelTaskParameters(w http.ResponseWriter, r *http.Request) {
	h.emptyToolboxPost(w, r, h.backend.CancelTaskParameters)
}

func (h *Host) resetTaskParameters(w http.ResponseWriter, r *http.Request) {
	h.emptyToolboxPost(w, r, h.backend.ResetTaskParameters)
}

func (h *Host) cameraSource(w http.ResponseWriter, r *http.Request) {
	auth, err := h.browserAuth(r)
	if err != nil {
		http.Error(w, "foreground session unavailable", http.StatusUnauthorized)
		return
	}
	result, err := h.backend.CameraSource(r.Context(), auth.SessionID)
	if err != nil {
		http.Error(w, "camera source unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) prepareCameraSource(w http.ResponseWriter, r *http.Request) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct {
		Name      string `json:"name"`
		SourceURL string `json:"sourceUrl"`
	}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "invalid camera source proposal", http.StatusBadRequest)
		return
	}
	secret := []byte(input.SourceURL)
	input.SourceURL = ""
	result, err := h.backend.PrepareCameraSource(r.Context(), auth.SessionID, input.Name, secret)
	clear(secret)
	if err != nil {
		http.Error(w, "camera source preparation unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) confirmCameraSource(w http.ResponseWriter, r *http.Request) {
	h.confirmToolbox(w, r, h.backend.ConfirmCameraSource)
}

func (h *Host) cancelCameraSource(w http.ResponseWriter, r *http.Request) {
	h.emptyToolboxPost(w, r, h.backend.CancelCameraSource)
}

func (h *Host) resetCameraSource(w http.ResponseWriter, r *http.Request) {
	h.emptyToolboxPost(w, r, h.backend.ResetCameraSource)
}

func (h *Host) confirmToolbox(w http.ResponseWriter, r *http.Request, confirm func(context.Context, string, string) (ordinaryapp.ToolboxView, error)) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct {
		Token string `json:"businessConfirmationToken"`
	}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "invalid confirmation", http.StatusBadRequest)
		return
	}
	result, err := confirm(r.Context(), auth.SessionID, input.Token)
	if err != nil {
		http.Error(w, "confirmation unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) emptyToolboxPost(w http.ResponseWriter, r *http.Request, command func(context.Context, string) (ordinaryapp.ToolboxView, error)) {
	auth, ok := h.authorizePost(w, r)
	if !ok {
		return
	}
	var input struct{}
	if decodeJSON(r, &input) != nil {
		http.Error(w, "invalid command", http.StatusBadRequest)
		return
	}
	result, err := command(r.Context(), auth.SessionID)
	if err != nil {
		http.Error(w, "command unavailable", statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Host) controlHealth(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeControl(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Host) controlStatus(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeControl(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, h.backend.Status(r.Context()))
}

func (h *Host) controlQuery(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeControl(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var input struct {
		Kind   string `json:"kind"`
		Window string `json:"window"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}
	text, err := h.backend.Query(r.Context(), input.Kind, input.Window)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusConflict)
	}
	_, _ = io.WriteString(w, text)
}

func (h *Host) controlOpen(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeControl(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var input struct {
		View       string `json:"view"`
		TaskIndex  int    `json:"taskIndex"`
		TaskAction string `json:"taskAction"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, "open unavailable", http.StatusBadRequest)
		return
	}
	intent := session.OpenIntent{View: input.View}
	if input.TaskIndex != 0 || input.TaskAction != "" {
		if input.View != "manage_tasks" || input.TaskIndex < 1 || (input.TaskAction != "enable" && input.TaskAction != "disable" && input.TaskAction != "parameters") {
			http.Error(w, "open unavailable", http.StatusBadRequest)
			return
		}
		projection, err := h.backend.Journey(r.Context(), "", "manage_tasks", "today")
		if err != nil {
			http.Error(w, "open unavailable", http.StatusConflict)
			return
		}
		var taskName string
		for _, task := range projection.Read.Tasks {
			if task.Index == input.TaskIndex {
				if taskName != "" {
					taskName = ""
					break
				}
				taskName = strings.TrimSpace(task.DisplayName)
			}
		}
		if taskName == "" {
			http.Error(w, "open unavailable", http.StatusConflict)
			return
		}
		for _, task := range projection.Read.Tasks {
			if task.Index != input.TaskIndex && strings.TrimSpace(task.DisplayName) == taskName {
				http.Error(w, "open unavailable", http.StatusConflict)
				return
			}
		}
		intent.TaskName, intent.TaskAction = taskName, input.TaskAction
	}
	bootstrap, err := h.BootstrapURLForIntent(intent)
	if err != nil || h.openBrowser == nil {
		http.Error(w, "open unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := h.openBrowser(bootstrap); err != nil {
		http.Error(w, "open unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Host) authorizePost(w http.ResponseWriter, r *http.Request) (session.BrowserAuth, bool) {
	auth, err := h.browserAuth(r)
	if err != nil || r.Header.Get("Origin") != h.baseURL || r.Header.Get("X-CosmoEdge-CSRF") != auth.CSRF {
		http.Error(w, "request binding unavailable", http.StatusForbidden)
		return session.BrowserAuth{}, false
	}
	return auth, true
}

func (h *Host) browserAuth(r *http.Request) (session.BrowserAuth, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return session.BrowserAuth{}, session.ErrUnauthorized
	}
	return h.vault.Authenticate(cookie.Value)
}

func (h *Host) authorizeControl(r *http.Request) bool {
	return h.controlToken != "" && r.Header.Get("X-CosmoEdge-Control") == h.controlToken
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, session.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, session.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, actions.ErrActionConflict), errors.Is(err, ledger.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, actions.ErrActionUnavailable):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

func decodeJSON(r *http.Request, output any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(output)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CosmoEdge Connect</title>
<style>
:root{color-scheme:light;--ink:#202522;--muted:#69716c;--line:#d8ddd9;--paper:#fff;--wash:#f3f5f2;--accent:#176b4d;--accent-dark:#10513a;--warn:#a45b12;--danger:#a6382e;--nav:#18201d}
*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;background:var(--wash);color:var(--ink);font:15px/1.5 system-ui,"Microsoft YaHei",sans-serif;letter-spacing:0}button,input,select{font:inherit;letter-spacing:0}button{cursor:pointer}button:disabled{cursor:not-allowed;opacity:.55}
.top{background:var(--nav);color:#f7faf8;border-bottom:3px solid #4f9b78}.top-inner{max-width:1120px;margin:auto;padding:18px 24px 0}.brand-row{display:flex;align-items:flex-end;justify-content:space-between;gap:20px}.brand h1{font-size:22px;line-height:1.2;margin:0 0 4px}.brand p{color:#b9c5bf;margin:0}.identity{min-height:24px;color:#d9e5df;text-align:right}.tabs{display:flex;gap:2px;margin-top:18px;overflow:auto}.tabs button{height:42px;padding:0 16px;color:#d7dfdb;background:transparent;border:0;border-bottom:3px solid transparent;white-space:nowrap}.tabs button.active{color:#fff;border-bottom-color:#70c49d}.tabs button:hover{background:#26322d}
main{max-width:1120px;margin:0 auto;padding:26px 24px 56px}.view-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:20px}.view-head h2{font-size:24px;line-height:1.2;margin:0}.view-head p{margin:5px 0 0;color:var(--muted)}.state{display:inline-flex;align-items:center;gap:7px;padding:5px 9px;border:1px solid #b8d5c7;border-radius:4px;background:#edf7f1;color:var(--accent-dark);font-size:13px}.state:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--accent)}
.band{background:var(--paper);border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:22px 0;margin:0 0 24px}.band-inner{padding:0 22px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid var(--line);background:var(--paper);margin:0 0 22px}.metric{min-width:0;padding:17px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span{display:block;color:var(--muted);font-size:13px}.metric strong{display:block;font-size:24px;line-height:1.25;margin-top:4px;font-weight:650;overflow-wrap:anywhere}
.summary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.summary{background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:17px;min-width:0}.summary header{display:flex;justify-content:space-between;gap:12px;align-items:baseline}.summary h3{font-size:16px;margin:0}.summary .count{font-size:22px;font-weight:650;color:var(--accent-dark)}.summary p{margin:8px 0 0;color:var(--muted)}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.segment{display:inline-flex;border:1px solid var(--line);background:var(--paper);border-radius:5px;overflow:hidden}.segment button{height:36px;border:0;border-right:1px solid var(--line);background:transparent;padding:0 12px}.segment button:last-child{border-right:0}.segment button.active{background:var(--nav);color:#fff}.filters{display:grid;grid-template-columns:minmax(220px,1fr) 180px;gap:10px;margin-bottom:14px}.field label{display:block;font-size:13px;color:var(--muted);margin-bottom:5px}.field input,.field select{width:100%;height:42px;border:1px solid #bac2bd;border-radius:4px;background:#fff;padding:0 11px;color:var(--ink)}.field input:focus,.field select:focus{outline:2px solid #9bcbb4;outline-offset:1px}
.task-list{display:grid;gap:9px}.task{display:grid;grid-template-columns:minmax(220px,1.4fr) minmax(130px,.8fr) 115px 115px auto;align-items:center;gap:12px;background:var(--paper);border:1px solid var(--line);border-radius:5px;padding:14px 16px}.task h3{font-size:15px;margin:0}.task small{display:block;color:var(--muted);margin-top:2px}.tag{display:inline-block;width:max-content;max-width:100%;padding:3px 7px;border-radius:3px;background:#edf1ee;color:#47514b;font-size:13px}.tag.good{background:#e9f5ef;color:var(--accent-dark)}.tag.warn{background:#fff3e6;color:var(--warn)}
.action-panel{background:var(--paper);border-top:2px solid var(--accent);border-bottom:1px solid var(--line);padding:17px 18px;margin:0 0 16px}.action-panel h3{font-size:16px;margin:0}.action-panel p{color:var(--muted);margin:5px 0 0}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}.secondary,.danger,.compact{height:38px;border:1px solid #aeb8b2;border-radius:4px;padding:0 13px;background:#fff;color:var(--ink)}.secondary:hover,.compact:hover{background:#f0f4f1}.danger{border-color:#d8aaa5;color:var(--danger)}.compact{height:34px;padding:0 11px}.parameter-grid{display:grid;grid-template-columns:minmax(180px,1fr) minmax(180px,1fr);gap:10px;margin-top:15px}.parameter-row{display:grid;grid-template-columns:minmax(150px,1fr) minmax(150px,1fr);gap:10px;align-items:end}.source-form{display:grid;grid-template-columns:minmax(180px,.8fr) minmax(260px,1.6fr);gap:12px;margin-top:15px}.inline-status{margin-top:12px;color:var(--muted)}
.alarm-list{margin:18px 0 0;border-top:1px solid var(--line)}.alarm{display:grid;grid-template-columns:180px 1fr 1fr;gap:15px;padding:12px 0;border-bottom:1px solid var(--line)}.alarm span{color:var(--muted)}
.connect{max-width:760px;margin:18px auto 0;background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:24px}.connect h2{font-size:22px;margin:0 0 5px}.connect>p{color:var(--muted);margin:0 0 22px}.connect-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:14px}.connect .password{grid-column:1/-1}.primary{height:42px;border:0;border-radius:4px;padding:0 18px;background:var(--accent);color:#fff;font-weight:650}.primary:hover{background:var(--accent-dark)}.message{min-height:24px;margin:14px 0 0;color:var(--muted)}.message.error{color:var(--danger)}.empty{padding:30px 0;color:var(--muted);text-align:center}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}
@media(max-width:760px){.top-inner,main{padding-left:16px;padding-right:16px}.brand-row,.view-head,.toolbar{align-items:flex-start;flex-direction:column}.identity{text-align:left}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.metric:nth-child(2){border-right:0}.metric:nth-child(-n+2){border-bottom:1px solid var(--line)}.summary-grid,.filters,.connect-grid,.parameter-grid,.parameter-row,.source-form{grid-template-columns:1fr}.connect .password{grid-column:auto}.task{grid-template-columns:1fr 1fr}.task h3{grid-column:1/-1}.alarm{grid-template-columns:1fr}.tabs button{padding:0 12px}}
</style></head><body>
<header class="top"><div class="top-inner"><div class="brand-row"><div class="brand"><h1>CosmoEdge Connect</h1><p>单设备事实、任务与告警</p></div><div id="identity" class="identity">本机安全会话</div></div><nav id="tabs" class="tabs" aria-label="运营视图"><button data-view="home">概况</button><button data-view="inspect_runtime">运行</button><button data-view="inspect_alerts">告警</button><button data-view="manage_tasks">任务</button><button data-view="manage_sources">视频源</button></nav></div></header>
<main><div id="content" aria-live="polite"></div></main>
<script>
const csrf='{{.CSRF}}';const initialView='{{.View}}';const launchTask='{{.TaskName}}';const launchAction='{{.TaskAction}}';
const initialCanRetrySavedConnection={{.CanRetrySavedConnection}};
const content=document.getElementById('content'),identity=document.getElementById('identity'),tabs=document.getElementById('tabs');
let activeView=initialView||'home',activeWindow='today',timer=0,latest=null,taskToken='',parameterToken='',sourceToken='',parameterMode=false,launchStage=launchTask?'select':'idle';
const viewNames={home:'设备概况',inspect_runtime:'运行情况',inspect_alerts:'结构化告警',manage_tasks:'分析任务',manage_sources:'视频源'};
function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
function button(text,fn,cls){const b=node('button',text,cls);b.type='button';b.onclick=fn;return b}
function clear(){content.replaceChildren()}
async function getJSON(path){const r=await fetch(path,{cache:'no-store'});if(!r.ok)throw new Error(await r.text());return r.json()}
async function postForm(path,body){const r=await fetch(path,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded;charset=UTF-8','X-CosmoEdge-CSRF':csrf},body:new URLSearchParams(body)});if(!r.ok){const e=new Error(await r.text());e.status=r.status;throw e}return r.json()}
async function postJSON(path,body){const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json','X-CosmoEdge-CSRF':csrf},body:JSON.stringify(body||{})});if(!r.ok){const e=new Error(await r.text());e.status=r.status;throw e}return r.json()}
function heading(title,subtitle){const wrap=node('div',undefined,'view-head'),copy=node('div');copy.append(node('h2',title),node('p',subtitle));wrap.append(copy,node('span','新鲜回读','state'));return wrap}
function metric(label,value){const e=node('div',undefined,'metric');e.append(node('span',label),node('strong',String(value)));return e}
function setTabs(enabled){tabs.hidden=!enabled;for(const b of tabs.querySelectorAll('button')){b.classList.toggle('active',b.dataset.view===activeView)}}
function renderDisconnected(j){
 clearTimeout(timer);setTabs(false);identity.textContent='设备接入';clear();
 const form=node('section',undefined,'connect');form.append(node('h2','连接一台设备'),node('p',j&&j.conclusion?j.conclusion:'连接成功后在本机安全保存，重新启动时自动恢复。'));
 const grid=node('div',undefined,'connect-grid'),endpoint=field('设备 IP','例如 192.168.0.22','text'),username=field('账号','设备账号','text'),password=field('密码','设备密码','password');password.wrap.classList.add('password');grid.append(endpoint.wrap,username.wrap,password.wrap);
 const action=button('确认设备地址',prepare,'primary'),message=node('p','','message'),confirmation=node('div',undefined,'actions');form.append(grid,action,message,confirmation);content.append(form);
 let retry;if(j&&j.canRetrySavedConnection){retry=button('重试已保存连接',retrySaved,'primary');form.insertBefore(retry,grid)}
 function reset(){confirmation.replaceChildren();action.disabled=false;endpoint.input.disabled=false;username.input.disabled=false;password.input.disabled=false;if(retry)retry.disabled=false}
 async function retrySaved(){if(retry.disabled||action.disabled)return;retry.disabled=true;action.disabled=true;endpoint.input.disabled=true;username.input.disabled=true;password.input.disabled=true;password.input.value='';message.className='message';message.textContent='正在连接已保存设备...';try{
  const result=await postJSON('/api/connection/retry',{});if(result.state==='connected'){taskToken='';parameterToken='';sourceToken='';activeView='home';await load();return}
  retry.hidden=!result.canRetrySavedConnection;message.textContent=result.canRetrySavedConnection?'暂时未连上，可重试或填写下方信息重新接入。':'保存的连接需要更新，请填写下方信息重新接入。';message.className='message error';
 }catch(e){message.textContent='连接未恢复，可重试或填写下方信息重新接入。';message.className='message error'}finally{reset()}}
 async function prepare(){if(action.disabled)return;action.disabled=true;if(retry)retry.disabled=true;endpoint.input.disabled=true;username.input.disabled=true;message.className='message';message.textContent='正在准备目标确认...';try{
  const preview=await postForm('/api/connection/prepare',{endpoint:endpoint.input.value,username:username.input.value});endpoint.input.disabled=true;username.input.disabled=true;
  message.textContent=preview.replacementRequired?'已保存设备 '+preview.currentDestination+'，本次目标 '+endpoint.input.value.trim()+'。替换后仅新设备作为当前设备；旧配置、证据和未完成清理记录保留。':'本次目标 '+endpoint.input.value.trim()+'。请核对后确认接入。';
  if(!preview.replacementRequired)confirmation.append(button('确认连接',()=>commit(preview,false),'primary'));
  if(preview.replacementAvailable)confirmation.append(button('替换保存设备并连接',()=>commit(preview,true),preview.replacementRequired?'primary':'danger'));
  if(preview.replacementRequired&&!preview.replacementAvailable)message.textContent='当前保存设备与目标不同，此服务版本不支持替换，请返回检查。';
  confirmation.append(button('返回修改',()=>{password.input.value='';message.textContent='';reset()},'secondary'));
 }catch(e){message.textContent='无法准备接入，请核对地址和账号。';message.className='message error';reset()}}
 async function commit(preview,replace){for(const b of confirmation.querySelectorAll('button'))b.disabled=true;let secret=password.input.value;password.input.value='';message.textContent=replace?'正在核对新设备并保存替换...':'正在识别设备...';try{
  await postForm('/api/connection/connect',{connectionToken:preview.connectionToken,password:secret,replaceSavedDevice:replace?'true':'false'});secret='';taskToken='';parameterToken='';sourceToken='';if(activeView==='connection')activeView='home';setTimeout(load,120);
 }catch(e){secret='';message.textContent=e.status===409?'确认已过期或当前设备已变化，请重新准备接入。':'接入未完成；已保存的记录保留。请检查设备、账号或重新明确确认替换。';message.className='message error';reset()}}
}
function field(label,placeholder,type){const wrap=node('div',undefined,'field'),l=node('label',label),input=document.createElement('input');input.placeholder=placeholder;input.type=type;input.autocomplete=type==='password'?'current-password':'off';l.append(input);wrap.append(l);return{wrap,input}}
function render(j){latest=j;if(j.state==='disconnected'){renderDisconnected(j);return}setTabs(true);identity.textContent=[j.device&&j.device.type,j.device&&j.device.maskedId].filter(Boolean).join(' · ')||'设备已连接';clear();content.append(heading(viewNames[activeView]||'设备概况',j.conclusion||'设备事实已刷新'));content.append(button('更换接入设备',()=>renderDisconnected({conclusion:'确认新目标后可替换当前设备，历史记录会保留。'}),'secondary'));if(activeView==='home')renderHome(j);else if(activeView==='manage_tasks')renderTasks(j);else if(activeView==='manage_sources')renderSources(j);else renderOperations(j);clearTimeout(timer);timer=setTimeout(load,5000)}
function renderHome(j){const summaries=j.operationsSummaries||[];if(!summaries.length){content.append(node('p','运营摘要仍在刷新。','empty'));return}const today=summaries[0],metrics=node('section',undefined,'metrics');metrics.append(metric('摄像头 / 视频通道',today.cameraCount),metric('分析任务',today.taskCount),metric('运行中',today.running),metric('今日告警',today.alarmText||'未知'));content.append(metrics);const grid=node('section',undefined,'summary-grid');for(const s of summaries)grid.append(summaryCard(s));content.append(grid)}
function summaryCard(s){const article=node('article',undefined,'summary'),head=node('header');head.append(node('h3',s.label||s.window),node('span',s.alarmText||'数量未知','count'));article.append(head,node('p','运行 '+s.running+' · 停止 '+s.stopped+' · 未知 '+s.unknown),node('p',(s.windowStart||'')+' 至 '+(s.windowEnd||'')));return article}
function windowControl(){const holder=node('div',undefined,'segment');for(const item of [['today','今日'],['yesterday','昨天'],['last_1h','最近 1 小时'],['last_24h','最近 24 小时']]){const b=button(item[1],()=>{activeWindow=item[0];load()});b.classList.toggle('active',activeWindow===item[0]);holder.append(b)}return holder}
function renderOperations(j){const bar=node('div',undefined,'toolbar');bar.append(node('span',activeView==='inspect_runtime'?'任务运行事实':'设备结构化告警'),windowControl());content.append(bar);const s=(j.operationsSummaries||[])[0];if(!s){content.append(node('p','当前窗口尚无可靠摘要。','empty'));return}const metrics=node('section',undefined,'metrics');metrics.append(metric('运行中',s.running),metric('已停止',s.stopped),metric('状态未知',s.unknown),metric('结构化告警',s.alarmText||'未知'));content.append(metrics);if(activeView==='inspect_alerts'){const list=node('section',undefined,'alarm-list');for(const a of s.recentAlarms||[]){const row=node('div',undefined,'alarm');row.append(node('span',a.occurredAt||'时间待确认'),node('strong',a.taskName||'任务待确认'),node('span',(a.cameraName||'摄像头待确认')+' · '+(a.algorithmName||'业务待确认')));list.append(row)}if(!list.childNodes.length)list.append(node('p','当前窗口没有读取到结构化告警。','empty'));content.append(list)}}
function renderTasks(j){const tasks=(j.read&&j.read.tasks)||[],selected=j.selection&&j.selection.selected;if(selected)content.append(taskActionPanel(j,selected));const filters=node('div',undefined,'filters'),search=field('搜索','按摄像头或业务名称搜索','search'),status=node('div',undefined,'field'),label=node('label','启停状态'),select=document.createElement('select');for(const value of [['','全部启停状态'],['已启用','已启用'],['已停用','已停用']]){const o=document.createElement('option');o.value=value[0];o.textContent=value[1];select.append(o)}status.append(label,select);filters.append(search.wrap,status);content.append(filters);const list=node('section',undefined,'task-list');content.append(list);function draw(){list.replaceChildren();const term=search.input.value.trim().toLowerCase();for(const t of tasks){if(term&&![t.displayName,t.cameraName,t.algorithmName].join(' ').toLowerCase().includes(term))continue;if(select.value&&t.enabledState!==select.value)continue;const row=node('article',undefined,'task'),title=node('div');title.append(node('h3',t.displayName),node('small',t.cameraName+' · '+t.algorithmName));row.append(title,node('span',t.enabledState,'tag '+(t.enabledState==='已启用'?'good':'warn')),node('span',t.runningState,'tag'),node('span','设备事实','tag'),button('管理',()=>selectTask(t),'compact'));list.append(row)}if(!list.childNodes.length)list.append(node('p','当前筛选条件下没有分析任务。','empty'))}search.input.oninput=draw;select.onchange=draw;if(launchStage==='select')search.input.value=launchTask;draw();if(parameterMode&&selected){const holder=node('section',undefined,'action-panel');content.append(holder);renderParameterEditor(holder)}continueLaunch(j,tasks)}
async function continueLaunch(j,tasks){if(activeView!=='manage_tasks'||launchStage!=='select')return;const matches=tasks.filter(t=>(t.displayName||'').trim()===launchTask);if(matches.length!==1){launchStage='done';content.prepend(node('p',matches.length?'存在同名任务，请在页面中重新选择。':'任务目录已经变化，请重新查询后发起操作。','message error'));return}launchStage='selecting';try{const selected=await postJSON('/api/journey/select',{choiceIndex:matches[0].index,choiceSetId:j.read.choiceSetId});if(launchAction==='parameters'){launchStage='done';parameterMode=true;render(selected);return}launchStage='preparing';const planned=await postJSON('/api/journey/prepare-persistent',{targetEnabled:launchAction==='enable'?1:0});taskToken=planned.businessConfirmationToken||'';launchStage='done';render(planned)}catch(e){launchStage='done';content.prepend(node('p','任务目录或状态已经变化，请重新查询后发起操作。','message error'))}}
function taskActionPanel(j,t){const panel=node('section',undefined,'action-panel'),title=node('h3',t.displayName),copy=node('p',j.conclusion||t.cameraName+' · '+t.algorithmName),actions=node('div',undefined,'actions');panel.append(title,copy,actions);if(j.state==='target_selected'||j.state==='ready'){if(t.enabledState!=='已启用')actions.append(button('启用任务',()=>prepareTask(1),'primary'));if(t.enabledState!=='已停用')actions.append(button('停用任务',()=>prepareTask(0),'danger'));actions.append(button('编辑参数',()=>{parameterMode=true;render(latest)},'secondary'))}else if(j.capabilities&&j.capabilities.canConfirm){if(taskToken)actions.append(button('确认执行',confirmTask,'primary'));actions.append(button('取消',cancelTask,'danger'))}else if(j.state==='complete'||j.state==='blocked'||j.state==='outcome_unknown'||j.state==='cancelled'||j.state==='expired'){actions.append(button('刷新设备事实',load,'secondary'));if(j.state!=='outcome_unknown')actions.append(button('编辑参数',()=>{parameterMode=true;render(latest)},'secondary'))}return panel}
async function selectTask(t){try{const j=await postJSON('/api/journey/select',{choiceIndex:t.index,choiceSetId:latest.read.choiceSetId});latest=j;render(j)}catch(e){load()}}
async function prepareTask(target){try{const j=await postJSON('/api/journey/prepare-persistent',{targetEnabled:target});taskToken=j.businessConfirmationToken||'';latest=j;render(j)}catch(e){load()}}
async function confirmTask(){if(!taskToken)return;try{const token=taskToken;taskToken='';const j=await postJSON('/api/journey/confirm-business',{businessConfirmationToken:token});latest=j;render(j)}catch(e){taskToken='';load()}}
async function cancelTask(){try{taskToken='';const j=await postJSON('/api/journey/cancel',{});latest=j;render(j)}catch(e){load()}}
async function renderParameterEditor(holder){try{const j=await getJSON('/api/toolbox/task-parameters');if(activeView!=='manage_tasks'||!holder.isConnected)return;holder.replaceChildren(node('h3','任务参数'),node('p',j.conclusion||'参数只在当前本机页面编辑。'));const rows=node('div',undefined,'parameter-grid'),inputs=[];for(const f of j.fields||[]){const item=field(f.key,'','text');item.input.value=f.value||'';item.input.disabled=j.state!=='editable';rows.append(item.wrap);inputs.push({key:f.key,input:item.input})}holder.append(rows);const actions=node('div',undefined,'actions');if(j.state==='editable')actions.append(button('准备变更',async()=>{try{const r=await postJSON('/api/toolbox/task-parameters/prepare',{fields:inputs.map(x=>({key:x.key,value:x.input.value}))});parameterToken=r.businessConfirmationToken||'';renderParameterEditor(holder)}catch(e){holder.append(node('p','参数方案未通过新鲜回读校验。','message error'))}},'primary'));else if(j.canConfirm){if(parameterToken)actions.append(button('确认写入',async()=>{const token=parameterToken;parameterToken='';await postJSON('/api/toolbox/task-parameters/confirm',{businessConfirmationToken:token});renderParameterEditor(holder)},'primary'));actions.append(button('取消',async()=>{parameterToken='';await postJSON('/api/toolbox/task-parameters/cancel',{});renderParameterEditor(holder)},'danger'))}if(j.canReset)actions.append(button('新建方案',async()=>{await postJSON('/api/toolbox/task-parameters/reset',{});renderParameterEditor(holder)},'secondary'));actions.append(button('关闭',()=>{parameterMode=false;render(latest)},'secondary'));holder.append(actions)}catch(e){holder.replaceChildren(node('h3','任务参数'),node('p','当前无法读取参数编辑面。','message error'))}}
function renderSources(j){const s=(j.operationsSummaries||[])[0],metrics=node('section',undefined,'metrics');metrics.append(metric('视频通道',s?s.cameraCount:'未知'),metric('关联任务',s?s.taskCount:'未知'),metric('运行任务',s?s.running:'未知'),metric('状态未知',s?s.unknown:'未知'));content.append(metrics);const holder=node('section',undefined,'action-panel');content.append(holder);renderSourceEditor(holder)}
async function renderSourceEditor(holder){try{const j=await getJSON('/api/toolbox/camera-source');if(activeView!=='manage_sources'||!holder.isConnected)return;holder.replaceChildren(node('h3','网络视频源'),node('p',j.conclusion||'创建前先在本机核对名称与 RTSP 地址。'));const actions=node('div',undefined,'actions');if(j.state==='editable'){const form=node('div',undefined,'source-form'),name=field('名称','例如 东门入口','text'),source=field('RTSP / RTSPS 地址','rtsp://...','password');form.append(name.wrap,source.wrap);holder.append(form);actions.append(button('准备创建',async()=>{let secret=source.input.value;source.input.value='';try{const r=await postJSON('/api/toolbox/camera-source/prepare',{name:name.input.value,sourceUrl:secret});secret='';sourceToken=r.businessConfirmationToken||'';renderSourceEditor(holder)}catch(e){secret='';holder.append(node('p','视频源方案未通过地址或目录校验。','message error'))}},'primary'))}else if(j.canConfirm){if(sourceToken)actions.append(button('确认创建',async()=>{const token=sourceToken;sourceToken='';await postJSON('/api/toolbox/camera-source/confirm',{businessConfirmationToken:token});renderSourceEditor(holder)},'primary'));actions.append(button('取消',async()=>{sourceToken='';await postJSON('/api/toolbox/camera-source/cancel',{});renderSourceEditor(holder)},'danger'))}if(j.canReset)actions.append(button('新建方案',async()=>{await postJSON('/api/toolbox/camera-source/reset',{});renderSourceEditor(holder)},'secondary'));holder.append(actions,node('p','状态：'+j.state+(j.evidence?' · 证据 '+j.evidence:''),'inline-status'))}catch(e){holder.replaceChildren(node('h3','网络视频源'),node('p','当前无法读取视频源工具。','message error'))}}
async function load(){try{const j=await getJSON('/api/journey?intent='+encodeURIComponent(activeView)+'&window='+encodeURIComponent(activeWindow));render(j)}catch(e){clearTimeout(timer);clear();content.append(node('p','当前无法读取本机运营状态。','empty'))}}
for(const b of tabs.querySelectorAll('button'))b.onclick=()=>{activeView=b.dataset.view;load()};
if(initialView==='connection')renderDisconnected({canRetrySavedConnection:initialCanRetrySavedConnection,conclusion:'请在本机填写设备地址和账号，核对目标后连接。更换已保存设备需要明确确认。'});else load();
</script></body></html>`))
