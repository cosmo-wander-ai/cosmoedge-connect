package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

// The whole-window leader differs from the peak day's leader. The public
// response must preserve that distinction using the actual daily/source joint breakdown.
func TestSummaryHTTPWindowLeaderDoesNotEstablishPeakDayComposition(t *testing.T) {
	zone := time.FixedZone("test-east-eight", 8*60*60)
	start := time.Date(2026, 4, 6, 0, 0, 0, 0, zone)
	var events []device.HistoricalEvent
	for source, counts := range map[string][]int{"alpha": {1, 4, 3}, "beta": {5, 0, 0}} {
		for day, count := range counts {
			for i := 0; i < count; i++ {
				events = append(events, device.HistoricalEvent{ID: fmt.Sprintf("%s-%d-%d", source, day, i),
					OccurredAt: start.AddDate(0, 0, day).Add(time.Hour), SourceID: source,
					SourceName: source, AlgorithmID: "synthetic-algorithm"})
			}
		}
	}
	for _, tc := range []struct {
		name        string
		from, to    time.Time
		counts      map[string]int
		count, peak int
	}{
		{"three-day window", start, start.AddDate(0, 0, 3), map[string]int{"alpha": 8, "beta": 5}, 13, 6},
		{"explicit peak-day query", start, start.AddDate(0, 0, 1), map[string]int{"alpha": 1, "beta": 5}, 6, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &summaryHTTPDevice{readPage: func(_ context.Context, request device.EventPageRequest) (device.EventPage, error) {
				calls++
				if request.Page != 1 || !request.Window.Start.Equal(tc.from) || !request.Window.End.Equal(tc.to) {
					t.Fatalf("changed fixed query window: %+v", request)
				}
				var selected []device.HistoricalEvent
				for _, event := range events {
					if !event.OccurredAt.Before(tc.from) && event.OccurredAt.Before(tc.to) {
						selected = append(selected, event)
					}
				}
				total := len(selected)
				return device.EventPage{Events: selected, Total: &total}, nil
			}}
			handler, token := newSummaryHTTPHandler(t, client, start.AddDate(0, 0, 4))
			issued := callSummaryHTTP(handler, token, "session", "", "{}")
			var session struct{ SessionRef string }
			if err := json.Unmarshal(issued.Body.Bytes(), &session); err != nil || issued.Code != http.StatusOK || session.SessionRef == "" {
				t.Fatalf("session issuance failed: %v", err)
			}
			request, err := json.Marshal(SummaryRequest{Start: tc.from, End: tc.to, TimeZone: "Asia/Shanghai"})
			if err != nil {
				t.Fatal(err)
			}
			w := callSummaryHTTP(handler, token, "summary", session.SessionRef, string(request))
			var response struct {
				Summary     summary.Result
				UserMessage string
				Peak        struct {
					Date  string
					Count int
					Scope string
				}
				SummaryEvidence struct {
					SourceAlgorithmScope            string
					DaySourceJointBreakdownProvided *bool
					CausalEvidenceProvided          *bool
					ConfigurationHistoryProvided    *bool
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || calls != 1 {
				t.Fatalf("query failed: status=%d calls=%d err=%v", w.Code, calls, err)
			}
			counts := map[string]int{}
			for _, group := range response.Summary.BySource {
				counts[group.Name] = group.Count
			}
			if !reflect.DeepEqual(counts, tc.counts) || response.Summary.Count != tc.count || response.Peak.Count != tc.peak || response.Peak.Date != "2026-04-06" || response.Peak.Scope != "retained_window" {
				t.Fatalf("whole-window and daily facts were mixed: %s", w.Body)
			}
			e := response.SummaryEvidence
			if e.SourceAlgorithmScope != "selected_window_retrieved_records" || e.DaySourceJointBreakdownProvided == nil || !*e.DaySourceJointBreakdownProvided || e.CausalEvidenceProvided == nil || *e.CausalEvidenceProvided || e.ConfigurationHistoryProvided == nil || *e.ConfigurationHistoryProvided {
				t.Fatalf("response invented joint or causal evidence: %s", w.Body)
			}
			for source, count := range tc.counts {
				if !strings.Contains(response.UserMessage, fmt.Sprintf("机位\\\"%s\\\"／算法名称未提供 %d 条", source, count)) {
					t.Fatalf("message mixed full-window and explicit-day counts: %s", response.UserMessage)
				}
			}
			requireSummaryText(t, response.UserMessage, "本次窗口内已读取记录", fmt.Sprintf("列出项合计 %d 条；其余 0 组共 0 条", tc.count), "不能将整个窗口的算法分布当作某日构成")
		})
	}
}
