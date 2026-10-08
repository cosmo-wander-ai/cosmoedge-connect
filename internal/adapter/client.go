package adapter

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

const (
	apiPrefix      = "/gtw/cwai"
	defaultTimeout = 20 * time.Second
	longTimeout    = 600 * time.Second
)

// longTimeoutRoutes are v1 endpoints that may take a long time.
var longTimeoutRoutes = map[string]bool{
	"/Camera/AddVideo":         true,
	"/aihost/PTaskCreate":      true,
	"/aihost/PTaskDetectPic":   true,
	"/aihost/PTaskCancle":      true,
	"/algorithm/layout/save":   true,
	"/atomic/model/uploadTemp": true,
}

// ── Client ───────────────────────────────────────────────────────────────────

// Client is an HTTP client for the CosmoEdge v1 API.
// Mirrors the logic verified in scenario-bench-py/cosmo_client.py.
type Client struct {
	base      string
	user      string
	password  string
	imageBase string
	lang      string
	mu        sync.RWMutex
	mtk       string
	client    *http.Client
}

// NewClient creates a new v1 API client.
func NewClient(base, user, password string) *Client {
	return &Client{
		base:     strings.TrimRight(base, "/"),
		user:     user,
		password: password,
		lang:     "zh-CN",
		// Device credentials and tokens must never follow an HTTP redirect to
		// another origin. Callers that need a specialized transport can still
		// supply one through NewClientWithHTTPClient, but the safe default is
		// fail-closed for every read and write route.
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

// NewClientWithHTTPClient creates a v1 API client with a caller-owned transport.
// The default NewClient behavior is unchanged; specialized read-only surfaces
// use this to disable redirects before sending credentials.
func NewClientWithHTTPClient(base, user, password string, httpClient *http.Client) *Client {
	c := NewClient(base, user, password)
	if httpClient != nil {
		c.client = httpClient
	}
	return c
}

// BaseURL returns the device base URL (e.g. http://192.168.0.22:8000).
func (c *Client) BaseURL() string {
	return c.base
}

// SetImageBaseURL overrides the base URL used for event images.
func (c *Client) SetImageBaseURL(base string) {
	c.imageBase = strings.TrimRight(base, "/")
}

// ImageBaseURL returns the base URL for accessing device images.
func (c *Client) ImageBaseURL() string {
	if c.imageBase != "" {
		return c.imageBase
	}
	return c.base
}

// ── Public API ───────────────────────────────────────────────────────────────

// Login authenticates with the device and stores the mtk token.
// Matches scenario-bench-py/cosmo_client.py:login().
func (c *Client) Login() error {
	return c.LoginContext(context.Background())
}

// LoginContext authenticates with the device using the caller's context.
func (c *Client) LoginContext(ctx context.Context) error {
	c.clearMTK()
	pwdMD5 := fmt.Sprintf("%X", md5.Sum([]byte(c.password)))
	data, err := c.postWithOptions(ctx, "/login/DoLogin", map[string]string{
		"account": c.user,
		"pwd":     pwdMD5,
	}, postOptions{})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	resData, ok := data["resData"].(map[string]any)
	if !ok {
		return fmt.Errorf("login: missing resData in response")
	}
	mtk, ok := resData["mtk"].(string)
	if !ok || mtk == "" {
		return fmt.Errorf("login: no mtk returned")
	}
	c.setMTK(mtk)
	return nil
}

// QueryDeviceInfo queries device information.
func (c *Client) QueryDeviceInfo() (map[string]any, error) {
	return c.QueryDeviceInfoContext(context.Background())
}

// QueryDeviceInfoContext queries device information using the caller's context.
func (c *Client) QueryDeviceInfoContext(ctx context.Context) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/System/QueryDeviceInfo", map[string]any{})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryHardwareResource queries hardware resource usage.
// Matches scenario-bench-py/metrics_sampler.py:_parse_hardware().
func (c *Client) QueryHardwareResource() (map[string]any, error) {
	return c.QueryHardwareResourceContext(context.Background())
}

// QueryHardwareResourceContext queries hardware resource usage with the caller's context.
func (c *Client) QueryHardwareResourceContext(ctx context.Context) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/System/QueryHardwareResource", map[string]any{})
	if err != nil {
		return nil, err
	}
	rd := c.resData(resp)
	itemList, _ := rd["itemList"].([]any)
	hw := map[string]any{"sampledAt": time.Now().UTC().Format(time.RFC3339)}
	byKey := map[string]map[string]any{}
	for _, it := range itemList {
		if m, ok := it.(map[string]any); ok {
			if key, ok := m["key"].(string); ok {
				byKey[key] = m
			}
		}
	}
	hwKeys := []string{
		"cpuUtilization", "generalMemoryUtilization", "npuUtilization",
		"modelMemoryUtilization", "pictureMemoryUtilization",
		"TPPMemoryUtilization", "eMMCUtilization", "packetDiscardUtilization",
	}
	for _, key := range hwKeys {
		if it, ok := byKey[key]; ok {
			hw[key] = map[string]any{
				"usedPercent": numVal(it["usedPercent"]),
				"usedSize":    it["usedSize"],
				"unusedSize":  it["unusedSize"],
			}
		}
	}
	if cs, ok := rd["customScore"]; ok {
		hw["customScore"] = cs
	}
	return hw, nil
}

// QueryEvents queries paginated event list.
func (c *Client) QueryEvents(pageNum, pageSize int) (map[string]any, error) {
	return c.QueryEventsContext(context.Background(), pageNum, pageSize)
}

// QueryEventsContext queries paginated event list using the caller's context.
func (c *Client) QueryEventsContext(ctx context.Context, pageNum, pageSize int) (map[string]any, error) {
	return c.QueryEventsWithBodyContext(ctx, map[string]any{
		"pageNum":  pageNum,
		"pageSize": pageSize,
	})
}

// QueryEventsWithBody queries Event/Page with the supplied v1-compatible body.
func (c *Client) QueryEventsWithBody(body map[string]any) (map[string]any, error) {
	return c.QueryEventsWithBodyContext(context.Background(), body)
}

// QueryEventsWithBodyContext queries Event/Page with the supplied v1-compatible body.
func (c *Client) QueryEventsWithBodyContext(ctx context.Context, body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.postWithContext(ctx, "/Event/Page", body)
	if err != nil {
		return nil, err
	}
	rd := c.resData(resp)
	rows, _ := rd["rows"].([]any)
	if rows == nil {
		rows, _ = rd["list"].([]any)
	}
	return map[string]any{
		"events":   rows,
		"total":    rd["total"],
		"pageNum":  body["pageNum"],
		"pageSize": body["pageSize"],
	}, nil
}

// ── Internals ────────────────────────────────────────────────────────────────

func (c *Client) post(path string, body any) (map[string]any, error) {
	return c.postWithContext(context.Background(), path, body)
}

func (c *Client) postWithContext(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.postWithOptions(ctx, path, body, postOptions{retryAuth: true})
}

func (c *Client) postWriteWithContext(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.postWithOptions(ctx, path, body, postOptions{write: true})
}

type postOptions struct {
	write     bool
	retryAuth bool
}

func (c *Client) postWithOptions(ctx context.Context, path string, body any, opts postOptions) (map[string]any, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, wrapRouteDiagnostic(err, path, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidRequest, 0)
	}

	timeout := defaultTimeout
	if longTimeoutRoutes[path] {
		timeout = longTimeout
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	data, err := c.doPostOnce(ctx, path, payload, opts.write)
	if err == nil || !opts.retryAuth || !isAuthRejectedError(err) {
		return data, err
	}
	c.clearMTK()
	if loginErr := c.LoginContext(ctx); loginErr != nil {
		return nil, wrapRouteDiagnostic(loginErr, path, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassAuthRejected, "", 0)
	}
	return c.doPostOnce(ctx, path, payload, opts.write)
}

func (c *Client) doPostOnce(ctx context.Context, path string, payload []byte, write bool) (map[string]any, error) {
	return c.doContentPostOnce(ctx, path, payload, "application/json", write)
}

func (c *Client) doContentPostOnce(ctx context.Context, path string, payload []byte, contentType string, write bool) (map[string]any, error) {
	url := c.base + apiPrefix + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, wrapRouteDiagnostic(err, path, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidRequest, 0)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept-Language", c.lang)
	if mtk := c.mtkToken(); mtk != "" {
		req.Header.Set("mtk", mtk)
		req.Header.Set("token", mtk)
	}

	httpClient := c.client
	if stagedPictureRoute(path) || path == detectPictureTaskPath {
		copyClient := *httpClient
		copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		httpClient = &copyClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if write {
			return nil, newOutcomeUnknownError(path, "transport", err)
		}
		return nil, wrapRouteDiagnostic(err, path, safediagnostic.PhaseTransport, safediagnostic.ClassTransportFailed, "", 0)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &V1Error{
			Path:             path,
			Message:          fmt.Sprintf("HTTP %d", resp.StatusCode),
			HTTPStatus:       resp.StatusCode,
			BusinessRejected: resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden,
			AuthRejected:     resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden,
		}
	}

	var responseBody io.Reader = resp.Body
	if stagedPictureRoute(path) {
		// Staged acknowledgements/capabilities are metadata, never media. Bound
		// this new protocol before decoding any untrusted response fields.
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxStagedPictureResponseBytes+1))
		if readErr != nil || int64(len(raw)) > maxStagedPictureResponseBytes {
			if readErr == nil {
				readErr = ErrInvalidInspectionResponse
			}
			if write {
				return nil, newOutcomeUnknownError(path, "decode_response", readErr)
			}
			return nil, wrapRouteDiagnostic(readErr, path, safediagnostic.PhaseDecodeJSON, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, resp.StatusCode)
		}
		responseBody = bytes.NewReader(raw)
	}
	var data map[string]any
	if err := json.NewDecoder(responseBody).Decode(&data); err != nil {
		if write {
			return nil, newOutcomeUnknownError(path, "decode_response", err)
		}
		return nil, wrapRouteDiagnostic(err, path, safediagnostic.PhaseDecodeJSON, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, resp.StatusCode)
	}

	rc, valid := nativeNumericCode(data["resCode"])
	if !valid {
		if write {
			return nil, newOutcomeUnknownError(path, "validate_typed_response", ErrInvalidInspectionResponse)
		}
		return nil, wrapRouteDiagnostic(ErrInvalidInspectionResponse, path, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, resp.StatusCode)
	}
	if rc != 1 {
		return nil, v1ErrorFromResponse(path, data)
	}

	return data, nil
}

func (c *Client) mtkToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mtk
}

func (c *Client) setMTK(mtk string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mtk = mtk
}

func (c *Client) clearMTK() {
	c.setMTK("")
}

func (c *Client) resData(resp map[string]any) map[string]any {
	if rd, ok := resp["resData"].(map[string]any); ok {
		return rd
	}
	return map[string]any{}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func numVal(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

// V1Error is an error returned by the v1 API.
type V1Error struct {
	Path    string `json:"path"`
	Message string `json:"message"`
	ResCode int    `json:"resCode"`
	// HTTPStatus is independent of the native business ResCode. In particular,
	// a business code above 500 in an HTTP 200 response is not an HTTP failure.
	HTTPStatus       int    `json:"httpStatus,omitempty"`
	MsgCode          string `json:"msgCode,omitempty"`
	BusinessRejected bool   `json:"-"`
	AuthRejected     bool   `json:"-"`
	resCodeKnown     bool
}

// SafeDiagnostic projects only bounded machine facts; legacy error text and
// route strings must never be persisted as diagnostic evidence.
func (e *V1Error) SafeDiagnostic() *safediagnostic.Diagnostic {
	if e == nil {
		return nil
	}
	operation := diagnosticOperation(e.Path)
	if operation == "" {
		return nil
	}
	d := safediagnostic.Diagnostic{Operation: operation, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassProtocolInvalid, HTTPStatus: e.HTTPStatus}
	if e.BusinessRejected {
		d.Class = safediagnostic.ClassNativeRejected
	}
	if e.AuthRejected {
		d.Class = safediagnostic.ClassAuthRejected
	}
	if e.HTTPStatus >= 500 {
		d.Class = safediagnostic.ClassOutcomeUnknown
	}
	if e.resCodeKnown || (e.HTTPStatus == 0 && e.ResCode != 0) {
		if value, ok := nativeNumericCode(e.ResCode); ok {
			d.ResCode = &value
		}
	}
	if safediagnostic.NumericCode(e.MsgCode) {
		d.MsgCode = e.MsgCode
	}
	if d.Validate() != nil {
		return nil
	}
	return d.Clone()
}

func (e *V1Error) Error() string {
	s := fmt.Sprintf("v1 API error on %s: %s", e.Path, e.Message)
	if e.MsgCode != "" {
		s += fmt.Sprintf(" (code %s)", e.MsgCode)
	}
	return s
}

func (e *V1Error) KnownFailure() bool {
	return e.BusinessRejected
}

func (e *V1Error) AuthenticationRejected() bool {
	return e.AuthRejected
}

// LoginThrottled marks the device's explicit anti-bruteforce response. Product
// surfaces may use it to stop immediate retries without exposing raw v1 data.
func (e *V1Error) LoginThrottled() bool {
	return e.MsgCode == "10009" || e.ResCode == 10009 || strings.Contains(e.Message, "登录太频繁") || strings.Contains(e.Message, "登陆太频繁")
}

// OutcomeUnknownError marks a write request whose response was ambiguous.
type OutcomeUnknownError struct {
	Path  string
	Phase string
	Cause error
}

func (e *OutcomeUnknownError) Error() string {
	return fmt.Sprintf("v1 write outcome unknown on %s during %s", e.Path, e.Phase)
}

func (e *OutcomeUnknownError) Unwrap() error {
	return e.Cause
}

func (e *OutcomeUnknownError) OutcomeUnknown() bool {
	return true
}

func (e *OutcomeUnknownError) SafeDiagnostic() *safediagnostic.Diagnostic {
	if e == nil {
		return nil
	}
	operation := diagnosticOperation(e.Path)
	if operation == "" {
		return nil
	}
	d := safediagnostic.Diagnostic{Operation: operation, Class: safediagnostic.ClassOutcomeUnknown}
	switch e.Phase {
	case "transport":
		d.Phase = safediagnostic.PhaseTransport
	case "decode_response":
		d.Phase, d.HTTPStatus = safediagnostic.PhaseDecodeJSON, http.StatusOK
	case "decode_typed_response":
		d.Phase, d.HTTPStatus = safediagnostic.PhaseDecodeTypedResponse, http.StatusOK
	case "validate_typed_response":
		d.Phase, d.HTTPStatus = safediagnostic.PhaseValidateTypedResponse, http.StatusOK
	case "http_status":
		d.Phase = safediagnostic.PhaseNativeResponse
	default:
		return nil
	}
	if cause := safediagnostic.FromError(e.Cause); cause != nil {
		d.HTTPStatus, d.ResCode, d.MsgCode = cause.HTTPStatus, cause.ResCode, cause.MsgCode
	}
	if errors.Is(e.Cause, context.DeadlineExceeded) {
		d.ValidationCode = safediagnostic.ValidationDeadlineExpired
	}
	if d.Phase == safediagnostic.PhaseDecodeJSON || d.Phase == safediagnostic.PhaseDecodeTypedResponse || d.Phase == safediagnostic.PhaseValidateTypedResponse {
		d.ValidationCode = safediagnostic.ValidationInvalidResponse
	}
	return d.Clone()
}

func newOutcomeUnknownError(path, phase string, cause error) *OutcomeUnknownError {
	return &OutcomeUnknownError{
		Path:  path,
		Phase: phase,
		Cause: cause,
	}
}

type authRejectedMarker interface {
	AuthenticationRejected() bool
}

func isAuthRejectedError(err error) bool {
	var marker authRejectedMarker
	return errors.As(err, &marker) && marker.AuthenticationRejected()
}

func v1ErrorFromResponse(path string, data map[string]any) *V1Error {
	msgs, _ := data["resMsg"].([]any)
	msgText := "unknown error"
	msgCode := ""
	if len(msgs) > 0 {
		if m, ok := msgs[0].(map[string]any); ok {
			if s, ok := m["msgText"].(string); ok && s != "" {
				msgText = s
			}
			if s, ok := m["msgCode"].(string); ok {
				msgCode = s
			} else if value, ok := nativeNumericCode(m["msgCode"]); ok {
				msgCode = strconv.Itoa(value)
			}
		}
	}
	resCode, known := nativeNumericCode(data["resCode"])
	return &V1Error{
		Path:             path,
		Message:          msgText,
		ResCode:          resCode,
		HTTPStatus:       http.StatusOK,
		resCodeKnown:     known,
		MsgCode:          msgCode,
		BusinessRejected: true,
		AuthRejected:     isAuthRejectedResponse(msgCode, msgText),
	}
}

func diagnosticOperation(route string) string {
	switch route {
	case getCameraPicturePath:
		return safediagnostic.OperationCameraPicture
	case createPictureTaskPath:
		return safediagnostic.OperationPictureCreate
	case detectPictureTaskPath:
		return safediagnostic.OperationPictureDetect
	case cancelPictureTaskPath:
		return safediagnostic.OperationPictureCancel
	case uploadCapabilitiesPath:
		return safediagnostic.OperationUploadCapabilities
	case uploadPicturePath:
		return safediagnostic.OperationPictureUpload
	case cancelPictureUploadPath:
		return safediagnostic.OperationPictureUploadCancel
	case "/Task/SwitchTask":
		return safediagnostic.OperationTaskSwitch
	case "/task/saveOrUpdate":
		return safediagnostic.OperationDeploymentSave
	case queryPictureAlgorithms, queryAlgorithmLayoutPath:
		return safediagnostic.OperationAnalysis
	default:
		return ""
	}
}

func wrapRouteDiagnostic(cause error, route, phase, class, validation string, httpStatus int) error {
	operation := diagnosticOperation(route)
	if operation == "" {
		return cause
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		validation = safediagnostic.ValidationDeadlineExpired
	}
	return safediagnostic.Wrap(cause, safediagnostic.Diagnostic{Operation: operation, Phase: phase, Class: class, ValidationCode: validation, HTTPStatus: httpStatus})
}

func nativeNumericCode(raw any) (int, bool) {
	var value float64
	switch v := raw.(type) {
	case float64:
		value = v
	case int:
		value = float64(v)
	case int64:
		value = float64(v)
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, false
		}
		value = parsed
	default:
		return 0, false
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > math.MaxUint32 || value != math.Trunc(value) {
		return 0, false
	}
	return int(value), true
}

func isAuthRejectedResponse(msgCode, msgText string) bool {
	joined := strings.ToLower(strings.TrimSpace(msgCode + " " + msgText))
	if joined == "" {
		return false
	}
	for _, needle := range []string{
		"auth", "unauthor", "forbid", "token", "mtk", "session", "login", "password", "credential",
		"未登录", "未登陆", "登录过期", "登陆过期", "认证", "鉴权", "授权", "过期", "失效", "账号", "账户", "密码",
	} {
		if strings.Contains(joined, needle) {
			return true
		}
	}
	return false
}
