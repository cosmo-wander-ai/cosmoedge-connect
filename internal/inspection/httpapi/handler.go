package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

const (
	basePath         = "/api/inspection"
	capabilitiesPath = basePath + "/capabilities"
	continuationPath = basePath + "/continuation"
	requestsPath     = basePath + "/requests"
	runsPath         = basePath + "/runs"
	mediaPath        = basePath + "/media"
)

type Handler struct {
	backend    Backend
	authorizer Authorizer
}

func NewHandler(backend Backend, authorizer Authorizer) (*Handler, error) {
	if backend == nil {
		return nil, errors.New("inspection HTTP backend is required")
	}
	if authorizer == nil {
		return nil, errors.New("inspection HTTP authorizer is required")
	}
	return &Handler{backend: backend, authorizer: authorizer}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if r.Method == http.MethodGet && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not allowed")
		return
	}

	switch {
	case r.URL.Path == capabilitiesPath:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.queryCapabilities(w, r)
	case r.URL.Path == requestsPath:
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		h.requestInspection(w, r)
	case r.URL.Path == continuationPath:
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.resolveContinuation(w, r)
	case strings.HasPrefix(r.URL.Path, runsPath+"/"):
		h.serveRunPath(w, r)
	case strings.HasPrefix(r.URL.Path, mediaPath+"/"):
		h.serveMediaPath(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	}
}

func (h *Handler) resolveContinuation(w http.ResponseWriter, r *http.Request) {
	session, ok := h.authorize(w, r, ScopeRunRead)
	if !ok {
		return
	}
	resolution, err := h.backend.ResolveContinuation(r.Context(), session)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	if validateContinuationResolution(resolution) != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
		return
	}
	if err := writePublicJSON(w, http.StatusOK, resolution); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func (h *Handler) serveRunPath(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, runsPath+"/"), "/")
	if len(parts) == 0 || len(parts) > 2 || !validPublicRef(parts[0]) {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	runRef := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.getRun(w, r, runRef)
		return
	}
	switch parts[1] {
	case "result":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		h.getResult(w, r, runRef)
	case "feedback":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		h.submitFeedback(w, r, runRef)
	default:
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	}
}

func (h *Handler) serveMediaPath(w http.ResponseWriter, r *http.Request) {
	mediaRef := strings.TrimPrefix(r.URL.Path, mediaPath+"/")
	if strings.Contains(mediaRef, "/") || !validPublicRef(mediaRef) {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	h.getMedia(w, r, mediaRef)
}

func (h *Handler) queryCapabilities(w http.ResponseWriter, r *http.Request) {
	session, ok := h.authorize(w, r, ScopeCapabilitiesRead)
	if !ok {
		return
	}
	capabilities, err := h.backend.QueryCapabilities(r.Context(), session)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	if err := validateCapabilitySet(capabilities); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
		return
	}
	if err := writePublicJSON(w, http.StatusOK, capabilities); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func (h *Handler) requestInspection(w http.ResponseWriter, r *http.Request) {
	idempotencyKey, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var request InspectionRequest
	if err := decodeRequiredJSON(w, r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := validateInspectionRequest(request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		return
	}
	session, ok := h.authorize(w, r, ScopeRequestCreate)
	if !ok {
		return
	}
	run, created, err := h.backend.RequestInspection(r.Context(), session, request, idempotencyKey)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	if err := validateRunView(run); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		w.Header().Set("Location", runsPath+"/"+run.RunRef)
	}
	if err := writePublicJSON(w, status, struct {
		Created bool    `json:"created"`
		Run     RunView `json:"run"`
	}{Created: created, Run: run}); err != nil {
		w.Header().Del("Location")
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func (h *Handler) getRun(w http.ResponseWriter, r *http.Request, runRef string) {
	session, ok := h.authorize(w, r, ScopeRunRead)
	if !ok {
		return
	}
	run, err := h.backend.GetRun(r.Context(), session, runRef)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	if run.RunRef != runRef || validateRunView(run) != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
		return
	}
	if err := writePublicJSON(w, http.StatusOK, run); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func (h *Handler) getResult(w http.ResponseWriter, r *http.Request, runRef string) {
	session, ok := h.authorize(w, r, ScopeResultRead)
	if !ok {
		return
	}
	result, err := h.backend.GetResult(r.Context(), session, runRef)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	if result.RunRef != runRef || validateResultView(result) != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
		return
	}
	if err := writePublicJSON(w, http.StatusOK, result); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func (h *Handler) getMedia(w http.ResponseWriter, r *http.Request, mediaRef string) {
	session, ok := h.authorize(w, r, ScopeMediaDeliver)
	if !ok {
		return
	}
	payload, err := h.backend.GetMedia(r.Context(), session, mediaRef)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	if err := validateMediaPayload(payload); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
		return
	}
	digest := sha256.Sum256(payload.Bytes)
	w.Header().Set("Content-Type", payload.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(payload.Bytes)))
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(digest[:]))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload.Bytes)
}

func (h *Handler) submitFeedback(w http.ResponseWriter, r *http.Request, runRef string) {
	idempotencyKey, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var request FeedbackRequest
	if err := decodeRequiredJSON(w, r, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := validateFeedbackRequest(request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		return
	}
	session, ok := h.authorize(w, r, ScopeFeedbackCreate)
	if !ok {
		return
	}
	receipt, created, err := h.backend.SubmitFeedback(r.Context(), session, runRef, request, idempotencyKey)
	if err != nil {
		writeBackendError(w, err)
		return
	}
	if !receipt.Accepted {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	if err := writePublicJSON(w, status, struct {
		Created  bool            `json:"created"`
		Feedback FeedbackReceipt `json:"feedback"`
	}{Created: created, Feedback: receipt}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func (h *Handler) authorize(w http.ResponseWriter, request *http.Request, scope Scope) (SessionBinding, bool) {
	credentialSHA256, ok := bearerCredentialDigest(w, request)
	if !ok {
		return SessionBinding{}, false
	}
	authorization, err := h.authorizer.Authorize(request.Context(), AuthorizationRequest{Scope: scope, CredentialSHA256: credentialSHA256})
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required")
		} else {
			writeError(w, http.StatusForbidden, "forbidden", "request is not authorized")
		}
		return SessionBinding{}, false
	}
	if authorization.Scope != scope || validateSessionBinding(authorization.Session) != nil {
		writeError(w, http.StatusForbidden, "forbidden", "request is not authorized")
		return SessionBinding{}, false
	}
	return authorization.Session, true
}

func bearerCredentialDigest(w http.ResponseWriter, request *http.Request) (string, bool) {
	if request == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required")
		return "", false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) != len("Bearer ")+64 || !strings.HasPrefix(values[0], "Bearer ") {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required")
		return "", false
	}
	token := values[0][len("Bearer "):]
	if token != strings.ToLower(token) {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required")
		return "", false
	}
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required")
		return "", false
	}
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:]), true
}

func requireIdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || !validPublicRef(values[0]) {
		writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "a valid idempotency key is required")
		return "", false
	}
	return values[0], true
}

func writeBackendError(w http.ResponseWriter, err error) {
	var interaction *InteractionRequiredError
	switch {
	case errors.As(err, &interaction):
		if validateInteractionRequired(interaction.Interaction) != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
			return
		}
		writeInteractionRequired(w, interaction.Interaction)
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "request conflicts with current state")
	case errors.Is(err, ErrResultNotReady):
		writeError(w, http.StatusConflict, "result_not_ready", "inspection result is not ready")
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", "request is not authorized")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed")
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}
