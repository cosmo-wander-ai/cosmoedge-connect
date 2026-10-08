package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

// The real session vault and HTTP handler use this in-memory device. Only the
// event-page boundary is replaced; Summarize still reads and counts every page.
type summaryHTTPDevice struct {
	device.InspectionClient
	readPage       func(context.Context, device.EventPageRequest) (device.EventPage, error)
	cameras        []device.Camera
	tasks          []device.Task
	algorithms     []device.Algorithm
	algorithmReads int
}

func (*summaryHTTPDevice) Login(context.Context) error { return nil }
func (c *summaryHTTPDevice) Read(context.Context) (device.Snapshot, error) {
	return device.Snapshot{Identity: device.Identity{Serial: "summary-http-test", Type: "test-only"}, Cameras: c.cameras, Tasks: c.tasks}, nil
}
func (c *summaryHTTPDevice) ReadAlgorithms(context.Context) ([]device.Algorithm, error) {
	c.algorithmReads++
	return c.algorithms, nil
}
func (*summaryHTTPDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{}
}
func (c *summaryHTTPDevice) ReadEventPage(ctx context.Context, request device.EventPageRequest) (device.EventPage, error) {
	return c.readPage(ctx, request)
}

func newSummaryHTTPHandler(t *testing.T, client *summaryHTTPDevice, now time.Time) (*Handler, string) {
	t.Helper()
	vault := session.New(func(string, string, string) device.Client { return client })
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := vault.PrepareConnection(auth.SessionID, "10.20.30.77", "test-only")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Connect(context.Background(), auth.SessionID, preview.Token, []byte("test-only")); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("b", 64)
	digest := sha256.Sum256([]byte(token))
	handler, err := New(Config{TokenDigest: hex.EncodeToString(digest[:]), Connections: vault, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return handler, token
}

func callSummaryHTTP(handler *Handler, token, route, sessionRef, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:37789"+Prefix+route, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-CosmoEdge-Session", sessionRef)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestSummaryHTTPPaginationScopesPeakToRetrievedEvidence(t *testing.T) {
	start := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 7)
	event := func(id string, at time.Time) device.HistoricalEvent {
		return device.HistoricalEvent{ID: id, OccurredAt: at, SourceID: "historic-camera", SourceName: "历史机位", AlgorithmID: "historic-algorithm", AlgorithmName: "历史算法"}
	}
	firstPage := []device.HistoricalEvent{event("a", start), event("b", start.Add(time.Hour))}
	secondPage := []device.HistoricalEvent{event("c", start.AddDate(0, 0, 1)), event("d", start.AddDate(0, 0, 1).Add(time.Hour)), event("e", start.AddDate(0, 0, 1).Add(2*time.Hour))}
	for _, test := range []struct {
		name       string
		failSecond bool
		empty      bool
		wantCount  int
		wantDate   string
		wantPeak   int
	}{
		{name: "complete retained window", wantCount: 5, wantDate: "2026-09-01", wantPeak: 3},
		{name: "second page unavailable", failSecond: true, wantCount: 2, wantDate: "2026-08-31", wantPeak: 2},
		{name: "empty retained window", empty: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &summaryHTTPDevice{cameras: []device.Camera{{ID: "private-zero-grid-source", Name: "从未留存的机位", SourceKind: "test_video"}}, readPage: func(_ context.Context, request device.EventPageRequest) (device.EventPage, error) {
				calls++
				if request.Page != calls || request.PageSize != device.MaxEventPageSize || !request.Window.Start.Equal(start) || !request.Window.End.Equal(end) {
					t.Fatalf("summary changed pagination or the fixed window: %+v", request)
				}
				total := 5
				if test.empty {
					total = 0
					return device.EventPage{Total: &total}, nil
				}
				switch request.Page {
				case 1:
					return device.EventPage{Events: firstPage, Total: &total}, nil
				case 2:
					if test.failSecond {
						return device.EventPage{}, errors.New("private event endpoint detail")
					}
					return device.EventPage{Events: secondPage, Total: &total}, nil
				default:
					t.Fatalf("unexpected event page %d", request.Page)
					return device.EventPage{}, nil
				}
			}}
			handler, token := newSummaryHTTPHandler(t, client, end.Add(12*time.Hour))
			issued := callSummaryHTTP(handler, token, "session", "", "{}")
			var sessionResult struct {
				SessionRef string `json:"sessionRef"`
			}
			if err := json.Unmarshal(issued.Body.Bytes(), &sessionResult); err != nil || issued.Code != http.StatusOK || sessionResult.SessionRef == "" {
				t.Fatal("public session issuance failed", issued.Code, err)
			}
			request, err := json.Marshal(SummaryRequest{Start: start, End: end, TimeZone: "Asia/Shanghai"})
			if err != nil {
				t.Fatal(err)
			}
			w := callSummaryHTTP(handler, token, "summary", sessionResult.SessionRef, string(request))
			var response struct {
				OK              bool            `json:"ok"`
				Partial         bool            `json:"partial"`
				Summary         summary.Result  `json:"summary"`
				Peak            json.RawMessage `json:"peak"`
				UserMessage     string          `json:"userMessage"`
				Report          summaryReport   `json:"summaryReport"`
				SummaryEvidence struct {
					SourceAlgorithmScope            string
					DaySourceScope                  string
					DaySourceJointBreakdownProvided *bool
					CausalEvidenceProvided          *bool
					ConfigurationHistoryProvided    *bool
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || !response.OK {
				t.Fatalf("summary response status=%d body=%s error=%v", w.Code, w.Body, err)
			}
			digest := sha256.Sum256([]byte(response.UserMessage))
			if response.Report.SchemaVersion != 1 || response.Report.ContentType != "text/markdown; charset=utf-8" ||
				response.Report.SHA256 != hex.EncodeToString(digest[:]) || response.Report.SizeBytes != len([]byte(response.UserMessage)) ||
				response.Report.Candidate != buildinfo.Current() {
				t.Fatalf("report provenance did not describe this exact response: %+v", response.Report)
			}
			if strings.Contains(response.Report.Headline, "最多") == test.empty ||
				strings.Contains(response.Report.Headline, "完整时段的排名仍无法确定") != test.failSecond {
				t.Fatalf("report headline lost peak/partial boundary: %s", response.Report.Headline)
			}
			evidence := response.SummaryEvidence
			if evidence.SourceAlgorithmScope != "selected_window_retrieved_records" || evidence.DaySourceScope != "selected_window_retrieved_records" || evidence.DaySourceJointBreakdownProvided == nil || !*evidence.DaySourceJointBreakdownProvided || evidence.CausalEvidenceProvided == nil || *evidence.CausalEvidenceProvided || evidence.ConfigurationHistoryProvided == nil || *evidence.ConfigurationHistoryProvided {
				t.Fatalf("missing or inflated summary dimensions: %s", w.Body)
			}
			zeroCells, jointTotal := 0, 0
			for _, cell := range response.Summary.ByDaySource {
				jointTotal += cell.Count
				if cell.SourceID == publicRef("source", "private-zero-grid-source") {
					zeroCells++
					if cell.SourceName != "从未留存的机位" || cell.Count != 0 {
						t.Fatalf("known zero source lost its identity or count: %+v", cell)
					}
				}
			}
			if zeroCells != 7 || jointTotal != response.Summary.Count || strings.Contains(w.Body.String(), "private-zero-grid-source") ||
				!strings.Contains(response.UserMessage, "| 日期 | 机位 | 已读告警条数 |") ||
				strings.Contains(response.UserMessage, "表中 0 仅表示本次尚未读到") != test.failSecond {
				t.Fatalf("daily/source report lost zero rows, privacy or partial scope: %s", w.Body)
			}
			wantCalls, wantAccuracy := 2, "exact_retained"
			if test.empty {
				wantCalls = 1
			}
			if test.failSecond {
				wantAccuracy = "lower_bound"
			}
			if calls != wantCalls || response.Summary.Count != test.wantCount || response.Partial != test.failSecond || response.Summary.Coverage.RetrievalComplete == test.failSecond || response.Summary.Coverage.Accuracy != wantAccuracy {
				t.Fatalf("page evidence was lost or promoted: calls=%d response=%s", calls, w.Body)
			}
			gaps := map[string]bool{}
			for _, gap := range response.Summary.Coverage.Gaps {
				gaps[gap.Code] = true
			}
			if response.Summary.Coverage.HistoryCoverage != "unknown" || !gaps["history_coverage_unknown"] || gaps["event_page_unavailable"] != test.failSecond || strings.Contains(w.Body.String(), "private event endpoint detail") {
				t.Fatalf("coverage or error boundary lost: %s", w.Body)
			}
			if test.failSecond && (response.Summary.SourceKindScope != "retrieved_records" || len(response.Summary.BySourceKind) != 1 || response.Summary.BySourceKind[0].RetainedRecordCount != test.wantCount || !strings.Contains(response.UserMessage, "已读取记录中：")) {
				t.Fatalf("partial kind totals exceeded the retrieved records: %s", w.Body)
			}
			if test.empty {
				if string(response.Peak) != "null" {
					t.Fatalf("zero retained events must have explicit peak=null: %s", w.Body)
				}
				return
			}
			var peak struct {
				Date                string `json:"date"`
				Count               int    `json:"count"`
				Scope               string `json:"scope"`
				RetainedWindowKnown *bool  `json:"retainedWindowKnown"`
			}
			if err := json.Unmarshal(response.Peak, &peak); err != nil {
				t.Fatalf("missing or invalid structured peak: %s error=%v", w.Body, err)
			}
			wantScope := "retained_window"
			if test.failSecond {
				wantScope = "retrieved_records"
			}
			if peak.Date != test.wantDate || peak.Count != test.wantPeak || peak.Scope != wantScope || peak.RetainedWindowKnown == nil || *peak.RetainedWindowKnown == test.failSecond {
				t.Fatalf("peak exceeded its evidence scope: %s", w.Body)
			}
			if test.failSecond {
				if !strings.Contains(response.UserMessage, "已读取记录中") || !strings.Contains(response.UserMessage, "完整时段哪天最多尚无法确定") {
					t.Fatalf("partial summary omitted its peak limitation: %s", response.UserMessage)
				}
				// A date immediately after a sentence boundary must not be presented
				// as the complete window's peak when the next page was unavailable.
				for _, sentence := range strings.FieldsFunc(response.UserMessage, func(r rune) bool { return r == '。' || r == '！' || r == '；' }) {
					if strings.HasPrefix(strings.TrimSpace(sentence), test.wantDate+" 最多") {
						t.Fatalf("unscoped peak claim after pagination failure: %s", response.UserMessage)
					}
				}
			}
		})
	}
}

func TestSummaryHTTPResolvesFiltersDirectlyAndDoesNotInferHistoryFromCurrentTasks(t *testing.T) {
	start := time.Date(2026, 4, 6, 0, 0, 0, 0, time.UTC)
	var messages []string
	for _, enabled := range []int{0, 1} {
		calls := 0
		client := &summaryHTTPDevice{
			cameras:    []device.Camera{{ID: "selected-source", Name: "Atrium", SourceKind: "network_camera"}},
			algorithms: []device.Algorithm{{ID: "selected-algorithm", Name: "Detector"}},
			tasks:      []device.Task{{ID: "current-task", ChannelID: "selected-source", AlgorithmID: "selected-algorithm", Enabled: enabled, Running: []string{"stopped", "processing"}[enabled]}},
			readPage: func(_ context.Context, request device.EventPageRequest) (device.EventPage, error) {
				calls++
				if calls != 1 || request.Page != 1 || !request.Window.Start.Equal(start) || !request.Window.End.Equal(start.Add(24*time.Hour)) || len(request.AlgorithmIDs) != 1 || request.AlgorithmIDs[0] != "selected-algorithm" {
					t.Fatalf("summary changed the explicit query or added a read: %+v", request)
				}
				total := 2
				return device.EventPage{Total: &total, Events: []device.HistoricalEvent{
					{ID: "selected-event", OccurredAt: start, SourceID: "selected-source", SourceName: "Atrium", AlgorithmID: "selected-algorithm", AlgorithmName: "Detector"},
					{ID: "other-event", OccurredAt: start, SourceID: "other-source", SourceName: "Elsewhere", AlgorithmID: "selected-algorithm", AlgorithmName: "Detector"},
				}}, nil
			},
		}
		handler, token := newSummaryHTTPHandler(t, client, start.Add(48*time.Hour))
		issued := callSummaryHTTP(handler, token, "session", "", "{}")
		var session struct{ SessionRef string }
		if err := json.Unmarshal(issued.Body.Bytes(), &session); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(SummaryRequest{Start: start, End: start.Add(24 * time.Hour), TimeZone: "Asia/Shanghai", SourceName: " atrium ", AlgorithmName: " detector "})
		// There is no public catalog call between session and summary.
		w := callSummaryHTTP(handler, token, "summary", session.SessionRef, string(body))
		var response struct {
			Summary       summary.Result
			UserMessage   string
			SummaryReport summaryReport
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || calls != 1 || client.algorithmReads != 1 || response.Summary.Count != 1 {
			t.Fatalf("direct filtered summary failed: status=%d reads=%d algorithms=%d err=%v body=%s", w.Code, calls, client.algorithmReads, err, w.Body)
		}
		requireSummaryText(t, response.UserMessage, `筛选：机位\"Atrium\"；算法\"Detector\"`, "共 1 条（已去重）", "2026-04-06 08:00:00 +08:00", "本次未提供历史启停")
		if response.SummaryReport.Filters["sourceName"] != "Atrium" || response.SummaryReport.Filters["algorithmName"] != "Detector" {
			t.Fatalf("report lost uniquely matched canonical filters: %+v", response.SummaryReport.Filters)
		}
		if strings.Contains(response.UserMessage, "Elsewhere") || strings.Contains(response.UserMessage, "selected-") {
			t.Fatal("filtered-out source or native identity leaked into the message")
		}
		messages = append(messages, response.UserMessage)
	}
	if messages[0] != messages[1] {
		t.Fatal("current task state changed the historical fact message")
	}
}
