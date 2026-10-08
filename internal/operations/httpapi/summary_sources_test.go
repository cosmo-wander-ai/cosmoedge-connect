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

func TestSummaryHTTPMultipleSourcesKeepAllAlgorithmsAndOneCombinedWindow(t *testing.T) {
	start := time.Date(2026, 4, 6, 0, 0, 0, 0, time.FixedZone("east-eight", 8*60*60))
	for _, emptySecond := range []bool{false, true} {
		t.Run(fmt.Sprintf("second source empty=%t", emptySecond), func(t *testing.T) {
			var events []device.HistoricalEvent
			add := func(source, algorithm string, day int) {
				events = append(events, device.HistoricalEvent{ID: fmt.Sprint(len(events)),
					OccurredAt: start.AddDate(0, 0, day).Add(time.Hour), SourceID: source,
					SourceName: strings.ToUpper(source), AlgorithmID: algorithm, AlgorithmName: algorithm})
			}
			add("a", "one", 0)
			add("a", "two", 0) // An unrequested algorithm filter would lose this record.
			add("a", "one", 2)
			if !emptySecond {
				add("b", "two", 2)
				add("b", "two", 2)
			}
			for i := 0; i < 9; i++ {
				add("c", "one", 1) // The unselected source must not establish the peak.
			}
			calls := 0
			client := &summaryHTTPDevice{
				cameras: []device.Camera{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}, {ID: "c", Name: "C"}},
				readPage: func(_ context.Context, request device.EventPageRequest) (device.EventPage, error) {
					calls++
					if calls != 1 || request.Page != 1 || len(request.AlgorithmIDs) != 0 || !request.Window.Start.Equal(start) || !request.Window.End.Equal(start.AddDate(0, 0, 7)) {
						t.Fatalf("source query changed its window, inferred algorithms, or repeated retrieval: %+v", request)
					}
					total := len(events)
					return device.EventPage{Events: events, Total: &total}, nil
				},
			}
			handler, token := newSummaryHTTPHandler(t, client, start.AddDate(0, 0, 8))
			issued := callSummaryHTTP(handler, token, "session", "", "{}")
			var auth struct{ SessionRef string }
			if err := json.Unmarshal(issued.Body.Bytes(), &auth); err != nil {
				t.Fatal(err)
			}
			request, err := json.Marshal(SummaryRequest{Start: start, End: start.AddDate(0, 0, 7), TimeZone: "Asia/Shanghai", SourceNames: []string{" a ", "B", "A"}})
			if err != nil {
				t.Fatal(err)
			}
			w := callSummaryHTTP(handler, token, "summary", auth.SessionRef, string(request))
			var response struct {
				Summary       summary.Result
				SummaryReport summaryReport
				Peak          struct {
					Date  string
					Count int
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || calls != 1 || client.algorithmReads != 0 {
				t.Fatalf("multi-source summary failed: status=%d calls=%d algorithms=%d err=%v body=%s", w.Code, calls, client.algorithmReads, err, w.Body)
			}
			wantCount, wantPeak, wantDate, wantB := 5, 3, "2026-04-08", 2
			if emptySecond {
				wantCount, wantPeak, wantDate, wantB = 3, 2, "2026-04-06", 0
			}
			result := response.Summary
			if result.Count != wantCount || response.Peak.Count != wantPeak || response.Peak.Date != wantDate || len(result.AlgorithmIDs) != 0 || len(result.ByAlgorithm) != 2 || !result.Coverage.RetrievalComplete {
				t.Fatalf("lost cross-algorithm records or mixed the third source into the total/peak: %s", w.Body)
			}
			if !reflect.DeepEqual(result.SourceIDs, []string{publicRef("source", "a"), publicRef("source", "b")}) || response.SummaryReport.Filters["sourceName"] != "A、B" || response.SummaryReport.Filters["algorithmName"] != "" {
				t.Fatalf("source set or canonical report filter changed: %+v / %+v", result.SourceIDs, response.SummaryReport.Filters)
			}
			if len(result.ByDaySource) != 14 || result.ShareBasis.Denominator != wantCount {
				t.Fatalf("lost the seven-day two-source grid or changed the share denominator: %+v", result)
			}
			counts := map[string]int{}
			for _, cell := range result.ByDaySource {
				if cell.SourceName != "A" && cell.SourceName != "B" {
					t.Fatalf("third source appeared in selected zero cells: %+v", cell)
				}
				counts[cell.SourceName] += cell.Count
			}
			if counts["A"] != 3 || counts["B"] != wantB || counts["A"]+counts["B"] != result.Count {
				t.Fatalf("joint grid does not reconcile to the selected total: %+v", counts)
			}
		})
	}
}

func TestSummaryHTTPInvalidSourceSetsNeverReadPartialSelections(t *testing.T) {
	start := time.Date(2026, 4, 6, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, selectors, code string
		status                int
	}{
		{"empty array", `"sourceNames":[]`, "source_names_invalid", http.StatusBadRequest},
		{"null array", `"sourceNames":null`, "source_names_invalid", http.StatusBadRequest},
		{"case-insensitive null array", `"SourceNames":null`, "source_names_invalid", http.StatusBadRequest},
		{"blank item", `"sourceNames":["A"," "]`, "source_names_invalid", http.StatusBadRequest},
		{"null item", `"sourceNames":["A",null]`, "source_names_invalid", http.StatusBadRequest},
		{"unknown after valid", `"sourceNames":["A","missing"]`, "source_ambiguous_or_missing", http.StatusConflict},
		{"ambiguous after valid", `"sourceNames":["A","Shared"]`, "source_ambiguous_or_missing", http.StatusConflict},
		{"both selectors", `"sourceName":"A","sourceNames":["B"]`, "source_filters_conflict", http.StatusBadRequest},
		{"empty single still conflicts", `"sourceName":"","sourceNames":["B"]`, "source_filters_conflict", http.StatusBadRequest},
		{"null single still conflicts", `"sourceName":null,"sourceNames":["B"]`, "source_filters_conflict", http.StatusBadRequest},
		{"wrong array type", `"sourceNames":"A"`, "invalid_request", http.StatusBadRequest},
		{"unknown field remains rejected", `"sourceNames":["A"],"sourceIds":["native"]`, "invalid_request", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &summaryHTTPDevice{
				cameras: []device.Camera{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}, {ID: "shared-one", Name: "Shared"}, {ID: "shared-two", Name: "Shared"}},
				readPage: func(context.Context, device.EventPageRequest) (device.EventPage, error) {
					t.Fatal("invalid source set reached the event reader")
					return device.EventPage{}, nil
				},
			}
			handler, token := newSummaryHTTPHandler(t, client, start.Add(48*time.Hour))
			issued := callSummaryHTTP(handler, token, "session", "", "{}")
			var auth struct{ SessionRef string }
			if err := json.Unmarshal(issued.Body.Bytes(), &auth); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"start":%q,"end":%q,"timeZone":"UTC",%s}`, start.Format(time.RFC3339), start.Add(24*time.Hour).Format(time.RFC3339), tc.selectors)
			w := callSummaryHTTP(handler, token, "summary", auth.SessionRef, body)
			var response struct{ Code string }
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != tc.status || response.Code != tc.code || client.algorithmReads != 0 {
				t.Fatalf("invalid filter was widened or partly executed: status=%d algorithms=%d err=%v body=%s", w.Code, client.algorithmReads, err, w.Body)
			}
		})
	}
}

func TestSummaryHTTPLegacyEmptySourceNameKeepsUnfilteredQuery(t *testing.T) {
	start := time.Date(2026, 4, 6, 0, 0, 0, 0, time.UTC)
	for _, value := range []string{`""`, `" "`, `null`} {
		t.Run(value, func(t *testing.T) {
			calls := 0
			client := &summaryHTTPDevice{
				cameras: []device.Camera{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}},
				readPage: func(_ context.Context, request device.EventPageRequest) (device.EventPage, error) {
					calls++
					total := 2
					return device.EventPage{Total: &total, Events: []device.HistoricalEvent{
						{ID: "a-event", SourceID: "a", SourceName: "A", AlgorithmID: "one", OccurredAt: start},
						{ID: "b-event", SourceID: "b", SourceName: "B", AlgorithmID: "two", OccurredAt: start},
					}}, nil
				},
			}
			handler, token := newSummaryHTTPHandler(t, client, start.Add(48*time.Hour))
			issued := callSummaryHTTP(handler, token, "session", "", "{}")
			var auth struct{ SessionRef string }
			if err := json.Unmarshal(issued.Body.Bytes(), &auth); err != nil {
				t.Fatal(err)
			}
			// Legacy clients always send the scalar field, including when unfiltered.
			body := fmt.Sprintf(`{"start":%q,"end":%q,"timeZone":"UTC","sourceName":%s,"algorithmName":""}`, start.Format(time.RFC3339), start.Add(24*time.Hour).Format(time.RFC3339), value)
			w := callSummaryHTTP(handler, token, "summary", auth.SessionRef, body)
			var response struct {
				Summary       summary.Result
				SummaryReport summaryReport
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || calls != 1 || response.Summary.Count != 2 || len(response.Summary.BySource) != 2 || len(response.Summary.SourceIDs) != 0 || response.SummaryReport.Filters["sourceName"] != "" {
				t.Fatalf("legacy unfiltered request changed scope: status=%d calls=%d err=%v body=%s", w.Code, calls, err, w.Body)
			}
		})
	}
}
