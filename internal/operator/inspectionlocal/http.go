package inspectionlocal

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const InteractionPath = "/inspection/interaction"

type ConnectionProbe interface {
	PrepareConnection(string, string, string) (string, error)
	Connect(context.Context, string, string, []byte) error
}

type HTTPConfig struct {
	BaseURL       string
	SessionCookie string
	Sessions      *SessionBinder
	Application   Application
	Connections   ConnectionProbe
}

type HTTPHandler struct {
	baseURL       string
	sessionCookie string
	sessions      *SessionBinder
	application   Application
	connections   ConnectionProbe
}

func NewHTTPHandler(config HTTPConfig) (*HTTPHandler, error) {
	baseURL, err := normalizeLocalBaseURL(config.BaseURL)
	if err != nil || config.SessionCookie == "" || strings.ContainsAny(config.SessionCookie, "\r\n; ,") ||
		config.Sessions == nil || config.Application == nil || config.Connections == nil {
		return nil, ErrUnavailable
	}
	return &HTTPHandler{
		baseURL: baseURL, sessionCookie: config.SessionCookie, sessions: config.Sessions,
		application: config.Application, connections: config.Connections,
	}, nil
}

func (h *HTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setLocalHeaders(response.Header())
	if h == nil || request.URL.Path != InteractionPath || request.URL.EscapedPath() != request.URL.Path ||
		request.URL.RawQuery != "" || request.URL.ForceQuery {
		http.NotFound(response, request)
		return
	}
	switch request.Method {
	case http.MethodGet:
		h.get(response, request)
	case http.MethodPost:
		h.completeConnection(response, request)
	default:
		response.Header().Set("Allow", "GET, POST")
		http.Error(response, "method unavailable", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) get(response http.ResponseWriter, request *http.Request) {
	if request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		http.Error(response, "request unavailable", http.StatusBadRequest)
		return
	}
	sessionID, err := h.sessionID(request)
	if err != nil {
		http.Error(response, "local session unavailable", http.StatusUnauthorized)
		return
	}
	auth, local, err := h.sessions.Authenticate(sessionID)
	if err != nil {
		http.Error(response, "local session unavailable", http.StatusUnauthorized)
		return
	}
	interaction, err := h.application.Resolve(request.Context(), local)
	if err != nil {
		writeLocalApplicationError(response, err)
		return
	}
	view := localPageView{CSRF: auth.CSRF}
	switch interaction.Kind {
	case KindConnection:
		view.Connection = true
		view.Completed = interaction.Status == StatusCompleted || interaction.Action == ActionNone
		view.Title = "完成现场接入"
		view.Message = "请在本机填写设备连接信息。连接验证通过后会安全保存，聊天窗口不会接触这些内容。"
	case KindPersistentChange:
		view.Title = "核对现场变更"
		view.Message = "这项变更需要在本机页面继续核对。当前开发页面不会自动执行任何设备变更。"
		view.Completed = interaction.Status == StatusTransferred
	default:
		writeLocalApplicationError(response, ErrIntegrity)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := localPageTemplate.Execute(response, view); err != nil {
		return
	}
}

func (h *HTTPHandler) completeConnection(response http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Origin") != h.baseURL {
		http.Error(response, "request binding unavailable (origin)", http.StatusForbidden)
		return
	}
	if !isFormURLEncoded(request.Header.Get("Content-Type")) {
		http.Error(response, "request binding unavailable (content-type)", http.StatusForbidden)
		return
	}
	sessionID, err := h.sessionID(request)
	if err != nil {
		http.Error(response, "local session unavailable", http.StatusUnauthorized)
		return
	}
	auth, local, err := h.sessions.AuthorizePost(sessionID, request.Header.Get("X-CosmoEdge-CSRF"))
	if err != nil {
		http.Error(response, "request binding unavailable (csrf)", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 16<<10)
	if err := request.ParseForm(); err != nil {
		http.Error(response, "connection input unavailable", http.StatusBadRequest)
		return
	}
	if extraFormKeys(request.PostForm, "ip", "port", "username", "password") {
		http.Error(response, "connection input unavailable", http.StatusBadRequest)
		return
	}
	password := []byte(request.PostForm.Get("password"))
	defer clearBytes(password)
	if len(password) == 0 || len(password) > 4096 {
		http.Error(response, "connection input unavailable", http.StatusBadRequest)
		return
	}
	ip := net.ParseIP(strings.TrimSpace(request.PostForm.Get("ip")))
	port, portErr := strconv.Atoi(strings.TrimSpace(request.PostForm.Get("port")))
	username := strings.TrimSpace(request.PostForm.Get("username"))
	if ip == nil || portErr != nil || port <= 0 || port > 65535 || username == "" {
		http.Error(response, "connection input unavailable", http.StatusBadRequest)
		return
	}
	current, err := h.application.Resolve(request.Context(), local)
	if err != nil || current.Kind != KindConnection || current.Action != ActionCompleteConnection || current.Status != StatusPending {
		writeLocalApplicationError(response, errors.Join(ErrConflict, err))
		return
	}
	endpoint := (&url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(port))}).String()
	candidateToken, err := h.connections.PrepareConnection(auth.SessionID, endpoint, username)
	if err != nil {
		writeConnectionError(response, ErrConnectionRequestUnavailable)
		return
	}
	if err := h.connections.Connect(request.Context(), auth.SessionID, candidateToken, password); err != nil {
		writeConnectionError(response, err)
		return
	}
	result, err := h.application.CompleteVerifiedConnection(request.Context(), local)
	if err != nil || result.Kind != KindConnection || result.Action != ActionNone || result.Status != StatusCompleted {
		writeLocalApplicationError(response, errors.Join(ErrConflict, err))
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(response).Encode(map[string]string{"status": "completed", "message": "现场接入已完成，可以返回对话继续查看。"})
}

func (h *HTTPHandler) sessionID(request *http.Request) (string, error) {
	if h == nil || h.sessions == nil || h.application == nil {
		return "", ErrUnavailable
	}
	cookie, err := request.Cookie(h.sessionCookie)
	if err != nil || cookie.Value == "" {
		return "", ErrInvalidSession
	}
	return cookie.Value, nil
}

func normalizeLocalBaseURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrUnavailable
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() || parsed.Port() == "" {
		return "", ErrUnavailable
	}
	if _, err := strconv.ParseUint(parsed.Port(), 10, 16); err != nil {
		return "", ErrUnavailable
	}
	return raw, nil
}

func extraFormKeys(values url.Values, allowed ...string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		set[value] = struct{}{}
	}
	for key, items := range values {
		if _, ok := set[key]; !ok || len(items) != 1 {
			return true
		}
	}
	return false
}

func setLocalHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

func writeLocalApplicationError(response http.ResponseWriter, err error) {
	status := http.StatusConflict
	switch {
	case errors.Is(err, ErrInvalidSession):
		status = http.StatusUnauthorized
	case errors.Is(err, ErrDenied):
		status = http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrUnavailable):
		status = http.StatusServiceUnavailable
	}
	http.Error(response, "local interaction unavailable", status)
}

type connectionErrorView struct {
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func writeConnectionError(response http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	view := connectionErrorView{
		Status:  "failed",
		Reason:  "connection_request_unavailable",
		Message: "本次接入请求已失效，请刷新页面后重试。",
	}
	switch {
	case errors.Is(err, ErrConnectionRejected):
		view.Reason = "credentials_rejected"
		view.Message = "设备未接受该账号或密码，请重新输入后重试。"
	case errors.Is(err, ErrConnectionThrottled):
		view.Reason = "login_throttled"
		view.Message = "设备暂时限制新的登录尝试，请稍后再试。"
	case errors.Is(err, ErrConnectionUnavailable):
		view.Reason = "device_unavailable"
		view.Message = "暂时无法连接设备，请确认设备已开机且本机网络可达后重试。"
	case errors.Is(err, ErrConnectionReadUnavailable):
		view.Reason = "device_information_unavailable"
		view.Message = "已通过登录验证，但暂时无法读取设备信息，请确认该账号有查看权限后重试。"
	case errors.Is(err, ErrConnectionPersistenceFailed):
		status = http.StatusServiceUnavailable
		view.Reason = "secure_save_failed"
		view.Message = "设备验证已通过，但连接信息未能安全保存，请检查本机可用空间和系统权限后重试。"
	case errors.Is(err, ErrConnectionRequestUnavailable):
		status = http.StatusConflict
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(view)
}

type localPageView struct {
	CSRF       string
	Title      string
	Message    string
	Connection bool
	Completed  bool
}

// isFormURLEncoded validates Content-Type using proper MIME parsing.  It
// accepts any of the forms that compliant User-Agents may produce for a
// URLSearchParams body, including optional whitespace after the semicolon
// and any charset casing.
func isFormURLEncoded(value string) bool {
	mediatype, _, err := mime.ParseMediaType(value)
	return err == nil && mediatype == "application/x-www-form-urlencoded"
}

var localPageTemplate = template.Must(template.New("inspection-interaction").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CosmoEdge 本机接入</title><style>
body{margin:0;background:#f3f5f2;color:#202522;font:15px/1.5 system-ui,"Microsoft YaHei",sans-serif}main{max-width:720px;margin:48px auto;padding:0 20px}.card{background:#fff;border:1px solid #d8ddd9;border-radius:8px;padding:28px}h1{font-size:24px;margin:0 0 8px}p{color:#69716c}.grid{display:grid;grid-template-columns:1fr 140px;gap:12px}.wide{grid-column:1/-1}label{display:block;color:#69716c;font-size:13px;margin-bottom:4px}input{width:100%;height:42px;box-sizing:border-box;border:1px solid #bac2bd;border-radius:4px;padding:0 10px;font:inherit}button{height:42px;border:0;border-radius:4px;padding:0 18px;background:#176b4d;color:#fff;font:inherit;font-weight:650}button:disabled{opacity:.55}.message{min-height:24px}.error{color:#a6382e}@media(max-width:620px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}}
</style></head><body><main><section class="card"><h1>{{.Title}}</h1><p>{{.Message}}</p>
{{if .Completed}}<p>该事项已经完成，可以关闭此页面。</p>{{else if .Connection}}<div class="grid">
<div><label>设备 IP</label><input id="ip" placeholder="例如 192.168.0.22" autocomplete="off"></div><div><label>端口</label><input id="port" value="8000" inputmode="numeric"></div>
<div class="wide"><label>账号</label><input id="username" autocomplete="username"></div>
<div class="wide"><label>密码</label><input id="password" type="password" autocomplete="current-password"></div>
</div><p><button id="submit" type="button">验证并保存</button></p><p id="message" class="message"></p>
<script>const csrf={{printf "%q" .CSRF}},button=document.getElementById('submit'),message=document.getElementById('message'),failureMessages={credentials_rejected:'设备未接受该账号或密码，请重新输入后重试。',login_throttled:'设备暂时限制新的登录尝试，请稍后再试。',device_unavailable:'暂时无法连接设备，请确认设备已开机且本机网络可达后重试。',device_information_unavailable:'已通过登录验证，但暂时无法读取设备信息，请确认该账号有查看权限后重试。',secure_save_failed:'设备验证已通过，但连接信息未能安全保存，请检查本机可用空间和系统权限后重试。',connection_request_unavailable:'本次接入请求已失效，请刷新页面后重试。'};button.onclick=async()=>{if(button.disabled)return;button.disabled=true;message.className='message';message.textContent='正在验证设备并安全保存...';const password=document.getElementById('password'),body=new URLSearchParams({ip:document.getElementById('ip').value,port:document.getElementById('port').value,username:document.getElementById('username').value,password:password.value});password.value='';try{const response=await fetch('/inspection/interaction',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded;charset=UTF-8','X-CosmoEdge-CSRF':csrf},body}),result=await response.json();if(!response.ok)throw {safeMessage:failureMessages[result.reason]};message.textContent=result.message;button.hidden=true}catch(error){message.textContent=error&&error.safeMessage||'当前未能完成接入，请稍后重试。';message.className='message error';button.disabled=false}}</script>
{{else}}<p>请在本机运营页面继续完成此事项。</p>{{end}}</section></main></body></html>`))
