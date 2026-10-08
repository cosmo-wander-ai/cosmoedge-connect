// Package httpapi is a small transport for distinct operations. It does not
// create inspection runs or load scheduling and delivery infrastructure.
package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deployment"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/observation"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const Prefix = "/operations/v1/"
const Protocol = "cosmoedge.operations.v1"

type Connections interface {
	InspectionConnection(context.Context) (session.InspectionConnection, error)
}
type Config struct {
	Deployments          *deployment.Service
	Observations         observation.API
	TokenDigest          string
	Connections          Connections
	OpenConnection       func() error
	OpenDeploymentReview func(context.Context, string, string) error
	Now                  func() time.Time
}
type Handler struct {
	config Config
	mux    *http.ServeMux
}
type Source struct {
	Ref  string `json:"sourceRef"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}
type Algorithm struct {
	Ref          string `json:"algorithmRef"`
	Name         string `json:"name"`
	Usage        string `json:"usage"`
	Verification string `json:"verification"`
}
type SummaryRequest struct {
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	TimeZone      string    `json:"timeZone"`
	SourceName    string    `json:"sourceName,omitempty"`
	SourceNames   []string  `json:"sourceNames,omitempty"`
	AlgorithmName string    `json:"algorithmName,omitempty"`

	sourceNameProvided  bool
	sourceNamesProvided bool
}

func New(c Config) (*Handler, error) {
	if len(c.TokenDigest) != 64 || c.Connections == nil {
		return nil, errors.New("operations token and connections required")
	}
	if _, err := hex.DecodeString(c.TokenDigest); err != nil {
		return nil, errors.New("invalid operations token")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	h := &Handler{config: c, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST "+Prefix+"session", h.newSession)
	h.mux.HandleFunc("GET "+Prefix+"version", func(w http.ResponseWriter, r *http.Request) {
		v := buildinfo.Current()
		h.reply(w, 200, map[string]any{"ok": true, "protocol": Protocol, "version": v, "candidateKey": v.PairingKey(), "serverTime": h.config.Now().UTC().Format(time.RFC3339)})
	})
	h.mux.HandleFunc("GET "+Prefix+"catalog", h.catalog)
	h.mux.HandleFunc("POST "+Prefix+"connection", h.openConnection)
	h.mux.HandleFunc("POST "+Prefix+"summary", h.summarize)
	h.registerDeployment()
	h.registerObservation()
	return h, nil
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || r.Header.Get("Origin") != "" {
		h.fail(w, 403, "forbidden", "当前入口不可用。")
		return
	}
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	digest := sha256.Sum256([]byte(raw))
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !hmac.Equal([]byte(hex.EncodeToString(digest[:])), []byte(h.config.TokenDigest)) {
		h.fail(w, 401, "unauthenticated", "请重新完成本机技能安装。")
		return
	}
	// Pin every MCP request, including media reads, to the candidate whose
	// protocol was checked. A service restart between preflight and submission
	// must reject an old adapter before it can read or mutate a device.
	if keys := r.Header.Values("X-CosmoEdge-Candidate"); len(keys) > 0 && (len(keys) != 1 || keys[0] != buildinfo.Current().PairingKey()) {
		h.fail(w, 409, "candidate_mismatch", "服务与客户端配套版本已变化，请使用同一安装包并重新启动客户端。")
		return
	}
	if r.URL.Path != Prefix+"session" && r.URL.Path != Prefix+"version" && !h.validSession(r.Header.Get("X-CosmoEdge-Session")) {
		h.fail(w, 403, "session_required", "请在本次对话重新开始查询，不能沿用其他对话的记录。")
		return
	}
	h.mux.ServeHTTP(w, r)
}
func (h *Handler) newSession(w http.ResponseWriter, r *http.Request) {
	if !h.decode(w, r, &struct{}{}) {
		return
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		h.fail(w, 500, "unavailable", "暂时无法开始新的查询。")
		return
	}
	now := h.config.Now()
	data := hex.EncodeToString(random) + "." + strconv.FormatInt(now.Unix(), 10)
	h.reply(w, 200, map[string]any{"ok": true, "sessionRef": data + "." + h.sign(data), "serverTime": now.UTC().Format(time.RFC3339), "binding": "desktop_conversation_capability", "protocol": Protocol, "version": buildinfo.Current(), "userMessage": "本次对话已就绪。"})
}
func (h *Handler) sign(data string) string {
	mac := hmac.New(sha256.New, []byte(h.config.TokenDigest))
	mac.Write([]byte("cosmoedge-connect-session-v1:" + data))
	return hex.EncodeToString(mac.Sum(nil))
}
func (h *Handler) validSession(ref string) bool {
	p := strings.Split(ref, ".")
	if len(p) != 3 || len(p[0]) != 32 {
		return false
	}
	if _, err := hex.DecodeString(p[0]); err != nil {
		return false
	}
	t, err := strconv.ParseInt(p[1], 10, 64)
	age := h.config.Now().Sub(time.Unix(t, 0))
	return err == nil && age >= -time.Minute && age <= 7*24*time.Hour && hmac.Equal([]byte(p[2]), []byte(h.sign(p[0]+"."+p[1])))
}
func SessionOwner(r *http.Request) string {
	d := sha256.Sum256([]byte(r.Header.Get("X-CosmoEdge-Session")))
	return hex.EncodeToString(d[:])
}
func sourceRef(c device.Camera) string { return publicRef("source", c.ID+":"+c.SourceFingerprint) }
func publicRef(kind, id string) string {
	d := sha256.Sum256([]byte(id))
	return kind + "_" + hex.EncodeToString(d[:12])
}
func (h *Handler) connection(w http.ResponseWriter, r *http.Request) (session.InspectionConnection, bool) {
	c, err := h.config.Connections.InspectionConnection(r.Context())
	if err != nil {
		h.fail(w, 409, "connection_required", "设备尚未接入或当前不可达，请在本机接入页面核对连接。")
		return c, false
	}
	return c, true
}
func (h *Handler) readAlgorithms(ctx context.Context, c session.InspectionConnection) ([]device.Algorithm, error) {
	reader, ok := c.Client().(device.AlgorithmReader)
	if !ok {
		return nil, errors.New("algorithm catalog unsupported")
	}
	return reader.ReadAlgorithms(ctx)
}
func (h *Handler) catalog(w http.ResponseWriter, r *http.Request) {
	c, ok := h.connection(w, r)
	if !ok {
		return
	}
	algorithms, err := h.readAlgorithms(r.Context(), c)
	if err != nil {
		h.fail(w, 502, "catalog_unavailable", "算法目录暂时无法完整读取，请稍后再查。")
		return
	}
	s := c.Snapshot()
	sources := []Source{}
	caps := []Algorithm{}
	tasks := []map[string]any{}
	for _, v := range s.Cameras {
		sources = append(sources, Source{sourceRef(v), v.Name, v.SourceKind})
	}
	for _, v := range algorithms {
		caps = append(caps, Algorithm{publicRef("algorithm", v.ID), v.Name, v.Usage, "registered_not_execution_verified"})
	}
	for _, v := range s.Tasks {
		tasks = append(tasks, map[string]any{"name": v.AlgorithmName, "sourceName": v.CameraName, "enabled": v.Enabled, "switchVerified": v.SwitchVerified, "runtime": v.Running})
	}
	h.reply(w, 200, map[string]any{"ok": true, "observedAt": s.ObservedAt, "sources": sources, "algorithms": caps, "tasks": tasks, "totals": summarizeCatalog(sources, caps, s.Tasks), "userMessage": "已读取当前机位、算法目录和配置，并核对分类数量。运行数量按当前状态统计，不代表已验证处理进度；算法出现在目录中，并不代表已验证能够运行。"})
}
func (h *Handler) openConnection(w http.ResponseWriter, r *http.Request) {
	if !h.decode(w, r, &struct{}{}) {
		return
	}
	if h.config.OpenConnection == nil || h.config.OpenConnection() != nil {
		h.fail(w, 503, "connection_page_unavailable", "本机接入页面暂时无法打开。")
		return
	}
	h.reply(w, 200, map[string]any{"ok": true, "pageState": "dispatched", "interactionRequired": true, "supportedInteraction": "connection_only", "userMessage": "已发起打开本机设备接入页面，请在页面中核对并连接设备。此入口不提供检测区域或检测线绘制。"})
}
func (h *Handler) summarize(w http.ResponseWriter, r *http.Request) {
	var q SummaryRequest
	if !h.decode(w, r, &q) {
		return
	}
	if !h.validateSummaryTime(w, q) {
		return
	}
	names, ok := h.summarySourceNames(w, q)
	if !ok {
		return
	}
	c, ok := h.connection(w, r)
	if !ok {
		return
	}
	snapshot := c.Snapshot()
	kinds := map[string]string{}
	for _, source := range snapshot.Cameras {
		kind := source.SourceKind
		switch kind {
		case "test_video", "network_camera", "usb_camera":
		default:
			kind = "unknown"
		}
		if previous, exists := kinds[source.ID]; exists && previous != kind {
			kind = "unknown"
		}
		kinds[source.ID] = kind
	}
	native := summary.Request{Start: q.Start, End: q.End, TimeZone: q.TimeZone, SourceKinds: kinds}
	sourceIDs, sourceName, ok := h.resolveSummarySources(w, names, snapshot.Cameras)
	if !ok {
		return
	}
	native.SourceIDs = sourceIDs
	algorithmName := ""
	if strings.TrimSpace(q.AlgorithmName) != "" {
		algorithms, err := h.readAlgorithms(r.Context(), c)
		if err != nil {
			h.fail(w, 502, "catalog_unavailable", "算法目录暂时无法完整读取。")
			return
		}
		matches := []string{}
		for _, a := range algorithms {
			if strings.EqualFold(strings.TrimSpace(q.AlgorithmName), a.Name) {
				matches = append(matches, a.ID)
				algorithmName = a.Name
			}
		}
		if len(matches) != 1 {
			h.fail(w, 409, "algorithm_ambiguous_or_missing", "没有找到唯一对应的算法，请明确算法名称。")
			return
		}
		native.AlgorithmIDs = matches
	}
	reader, ok := c.Client().(summary.EventReader)
	if !ok {
		h.fail(w, 503, "summary_unavailable", "当前设备不支持完整历史查询。")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	result, err := summary.New(reader).Summarize(ctx, native)
	if err != nil {
		h.fail(w, 400, "invalid_summary", "查询时段或筛选条件不完整，请重新确认。")
		return
	}
	sourceKinds := map[string]string{}
	for _, s := range result.BySource {
		kind := kinds[s.ID]
		if kind == "" {
			kind = "unknown"
		}
		if previous, exists := sourceKinds[s.Name]; exists && previous != kind {
			kind = "unknown"
		}
		sourceKinds[s.Name] = kind
	}
	// Native IDs stay within the device/summary boundary. Public result references
	// are stable across requests and cannot be sent directly to a device endpoint.
	for i := range result.SourceIDs {
		result.SourceIDs[i] = publicRef("source", result.SourceIDs[i])
	}
	for i := range result.AlgorithmIDs {
		result.AlgorithmIDs[i] = publicRef("algorithm", result.AlgorithmIDs[i])
	}
	for i := range result.BySource {
		result.BySource[i].ID = publicRef("source", result.BySource[i].ID)
	}
	for i := range result.ByDaySource {
		v := &result.ByDaySource[i]
		if v.SourceName == "" {
			for _, source := range snapshot.Cameras {
				if source.ID == v.SourceID {
					v.SourceName = source.Name
					break
				}
			}
		}
		v.SourceID = publicRef("source", v.SourceID)
	}
	for i := range result.ByAlgorithm {
		result.ByAlgorithm[i].ID = publicRef("algorithm", result.ByAlgorithm[i].ID)
	}
	for i := range result.BySourceAlgorithm {
		v := &result.BySourceAlgorithm[i]
		v.SourceID = publicRef("source", v.SourceID)
		v.AlgorithmID = publicRef("algorithm", v.AlgorithmID)
	}
	result.RepresentativeEvents = nil
	message := summaryUserMessage(result, sourceName, algorithmName)
	h.reply(w, 200, map[string]any{"ok": true, "partial": !result.Coverage.RetrievalComplete, "summary": result, "peak": summaryPeak(result), "sourceKinds": sourceKinds,
		"summaryEvidence": map[string]any{"dailyScope": "calendar_day", "sourceAlgorithmScope": "selected_window_retrieved_records", "daySourceScope": "selected_window_retrieved_records", "daySourceJointBreakdownProvided": true, "causalEvidenceProvided": false, "configurationHistoryProvided": false}, "userMessage": message,
		"summaryReport": newSummaryReport(result, message, sourceName, algorithmName)})
}
func (h *Handler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		h.fail(w, 400, "invalid_request", "请求内容不完整，请重新确认。")
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		h.fail(w, 400, "invalid_request", "请求内容不完整，请重新确认。")
		return false
	}
	return true
}
func (h *Handler) fail(w http.ResponseWriter, status int, code, message string) {
	h.reply(w, status, map[string]any{"ok": false, "code": code, "userMessage": message})
}
func (h *Handler) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
