// Package deploymentlocal binds an original deployment proposal to a protected
// browser page. The operations bearer protocol has no confirmation authority.
package deploymentlocal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deployment"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const Path = "/deployment/review"

type Config struct {
	BaseURL       string
	SessionCookie string
	Vault         *session.Vault
	Deployments   *deployment.Service
	Open          func(string) error // Receives a server-only handoff, never returned to the model.
	Now           func() time.Time
}

type gate struct {
	owner, actionRef, token, browserID string
	expiresAt                          time.Time
	rendered, cancelled                bool
}

type Handler struct {
	config Config
	host   string
	mu     sync.Mutex
	gates  map[string]*gate
	closed bool
}

func New(c Config) (*Handler, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() == "" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || c.SessionCookie == "" || c.Vault == nil || c.Deployments == nil || c.Open == nil {
		return nil, errors.New("local deployment review unavailable")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Handler{config: c, host: u.Host, gates: make(map[string]*gate)}, nil
}

// OpenReview creates no action and consumes no confirmation. The opener gets
// an opaque bootstrap binding; the caller sees only success or failure.
func (h *Handler) OpenReview(ctx context.Context, owner, actionRef string) error {
	view, err := h.config.Deployments.LocalReview(ctx, owner, actionRef)
	if err != nil || !view.CanConfirm || view.Proposal.ConfirmationToken == "" {
		return deployment.ErrConflict
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	handoff := "deployment_" + hex.EncodeToString(raw)
	h.mu.Lock()
	h.sweepLocked()
	if h.closed || len(h.gates) >= 128 {
		h.mu.Unlock()
		return deployment.ErrUnavailable
	}
	h.gates[handoff] = &gate{owner: owner, actionRef: actionRef, token: view.Proposal.ConfirmationToken, expiresAt: view.Proposal.ExpiresAt}
	h.mu.Unlock()
	if err := h.config.Open(handoff); err != nil {
		h.mu.Lock()
		delete(h.gates, handoff)
		h.mu.Unlock()
		return err
	}
	return nil
}

// Close revokes every browser gate for this process generation.
func (h *Handler) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for key, g := range h.gates {
		g.token = ""
		delete(h.gates, key)
	}
}

func (h *Handler) sweepLocked() {
	for key, g := range h.gates {
		if !h.config.Now().Before(g.expiresAt) {
			g.token = ""
			delete(h.gates, key)
		}
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.Host != h.host || r.URL.Path != Path || r.URL.EscapedPath() != Path || r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method unavailable", 405)
		return
	}
	cookie, err := r.Cookie(h.config.SessionCookie)
	if err != nil {
		http.Error(w, "local browser required", 401)
		return
	}
	auth, err := h.config.Vault.Authenticate(cookie.Value)
	if err != nil {
		http.Error(w, "local browser required", 401)
		return
	}
	handoff, err := h.config.Vault.DeploymentHandoff(auth)
	if err != nil {
		http.Error(w, "bound review required", 403)
		return
	}
	if r.Method == http.MethodPost && (r.Header.Get("Origin") != h.config.BaseURL || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CosmoEdge-CSRF")), []byte(auth.CSRF)) != 1) {
		http.Error(w, "local confirmation binding required", 403)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked()
	g := h.gates[handoff]
	if h.closed || g == nil || (g.browserID != "" && g.browserID != auth.SessionID) {
		http.Error(w, "review expired or unavailable", 410)
		return
	}
	if r.Method == http.MethodGet {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			http.Error(w, "invalid review request", 400)
			return
		}
		view, err := h.config.Deployments.LocalReview(r.Context(), g.owner, g.actionRef)
		if err != nil {
			http.Error(w, "review unavailable", 409)
			return
		}
		data := pageView{CSRF: auth.CSRF, Source: view.Proposal.SourceName, Algorithm: view.Proposal.AlgorithmName, CanConfirm: view.CanConfirm && !g.cancelled, ParameterCount: view.ParameterCount, AreaPointCounts: view.AreaPointCounts}
		data.Action = "启用"
		if !view.Proposal.Enabled {
			data.Action = "停用"
		}
		data.Binding = "创建一个新绑定"
		data.Plan = "使用设备默认参数和区域，以及已核对的全天运行计划。"
		if view.Proposal.ExistingBinding {
			data.Binding = "复用原有绑定"
			data.Plan = "保留该绑定已保存的参数、完整区域和时间计划。"
		}
		if !data.CanConfirm {
			data.Notice = "这份提议已处理、取消或失去确认权限。请返回原对话查询；此页不能重新派发。"
		}
		var output bytes.Buffer
		if err := page.Execute(&output, data); err != nil {
			http.Error(w, "review unavailable", 500)
			return
		}
		g.browserID = auth.SessionID
		g.rendered = true
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(output.Bytes())
		return
	}
	if !g.rendered || g.browserID != auth.SessionID {
		http.Error(w, "review the bound proposal first", 403)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "invalid decision", 400)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var input struct {
		Decision string `json:"decision"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid decision", 400)
		return
	}
	var state, message string
	switch input.Decision {
	case "confirm":
		if g.cancelled {
			http.Error(w, "proposal cancelled", 409)
			return
		}
		receipt, err := h.config.Deployments.ConfirmWithReceipt(r.Context(), g.owner, g.actionRef, g.token)
		if err != nil {
			http.Error(w, "confirmation unavailable; return to the original conversation", 409)
			return
		}
		state = receipt.Disposition
		message = "已确认，正在处理。请返回原对话查看结果。"
		if state == "already_confirmed" {
			message = "这份方案已确认，请返回原对话查看结果。"
		}
	case "cancel":
		if !g.cancelled {
			view, err := h.config.Deployments.LocalReview(r.Context(), g.owner, g.actionRef)
			if err != nil || !view.CanConfirm {
				http.Error(w, "proposal can no longer be cancelled here", 409)
				return
			}
			if err := h.config.Deployments.Cancel(r.Context(), g.owner, g.actionRef); err != nil {
				http.Error(w, "cancellation unavailable", 409)
				return
			}
			g.cancelled = true
			g.token = ""
		}
		state = "cancelled"
		message = "已取消此方案。"
	default:
		http.Error(w, "invalid decision", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": state, "userMessage": message})
}

type pageView struct {
	CSRF, Source, Algorithm, Action, Binding, Plan, Notice string
	CanConfirm                                             bool
	ParameterCount                                         int
	AreaPointCounts                                        []int
}

var page = template.Must(template.New("deployment-review").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>核对设备变更</title><style>body{font:16px system-ui;max-width:720px;margin:48px auto;padding:0 24px;line-height:1.7}dt{font-weight:600}dd{margin:0 0 12px;white-space:pre-wrap}button{padding:10px 18px;margin:12px 12px 0 0;font:inherit}summary{cursor:pointer}#message{white-space:pre-wrap}</style></head><body><h1>核对设备变更</h1><dl><dt>机位</dt><dd>{{.Source}}</dd><dt>算法</dt><dd>{{.Algorithm}}</dd><dt>这次变更</dt><dd>{{.Action}}；{{.Binding}}</dd><dt>配置与计划</dt><dd>{{.Plan}}</dd></dl>{{if .CanConfirm}}<details><summary>配置详情</summary><p>原方案包含 {{.ParameterCount}} 项参数；{{len .AreaPointCounts}} 个检测区域{{range .AreaPointCounts}}（{{.}} 点）{{end}}。此处沿用原方案中的配置。</p></details><p>请核对机位、算法和变更后确认。</p><button id="confirm" type="button">确认{{.Action}}</button><button id="cancel" type="button">取消此方案</button>{{else}}<p>{{.Notice}}</p>{{end}}<p id="message" role="status"></p><script>
const csrf={{.CSRF}};
function decisionFailure(status,decision){
 const action=decision==='cancel'?'取消':'确认';
 if(status===401||status===403)return '本次'+action+'未被接受。请返回原对话重新打开同一方案。';
 if(status===410)return '这个核对页已过期或失效。请返回原对话查看原方案。';
 if(status===409)return '本次'+action+'未被接受。请返回原对话查询原方案状态。';
 return '暂时未取得'+action+'结果。请返回原对话查询原方案状态。';
}
async function decide(decision){
 for(const b of document.querySelectorAll('button'))b.disabled=true;
 const message=document.getElementById('message');
 message.textContent=decision==='cancel'?'正在取消…':'正在确认…';
 try{
  const r=await fetch('/deployment/review',{method:'POST',headers:{'Content-Type':'application/json','X-CosmoEdge-CSRF':csrf},body:JSON.stringify({decision})});
  if(!r.ok){message.textContent=decisionFailure(r.status,decision);return;}
  const result=await r.json();message.textContent=result.userMessage;
 }catch(e){message.textContent=decisionFailure(0,decision);}
}
const confirm=document.getElementById('confirm'),cancel=document.getElementById('cancel');
if(confirm)confirm.addEventListener('click',()=>decide('confirm'));
if(cancel)cancel.addEventListener('click',()=>decide('cancel'));
</script></body></html>`))
