package summary

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

type readerFunc func(context.Context, device.EventPageRequest) (device.EventPage, error)

func (f readerFunc) ReadEventPage(ctx context.Context, request device.EventPageRequest) (device.EventPage, error) {
	return f(ctx, request)
}

func testRequest() Request {
	return Request{
		Start: time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 9, 7, 16, 0, 0, 0, time.UTC), TimeZone: "Asia/Shanghai",
	}
}

func testEvent(id string, at time.Time) device.HistoricalEvent {
	return device.HistoricalEvent{
		ID: id, OccurredAt: at, SourceID: "deleted-camera", SourceName: "入口",
		AlgorithmID: "old-algorithm", AlgorithmName: "历史分析",
	}
}

func intPointer(value int) *int { return &value }

func floatPointer(value float64) *float64 { return &value }

func hasGap(result Result, code string) bool {
	for _, gap := range result.Coverage.Gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func TestSummaryReadsBeyondOnePageAndKeepsHistoricalSourcesSeparate(t *testing.T) {
	request := testRequest()
	eventCount := defaultPageSize + 1
	events := make([]device.HistoricalEvent, 0, eventCount+2)
	for i := 0; i < eventCount; i++ {
		event := testEvent(fmt.Sprintf("event-%04d", i), request.Start.Add(time.Duration(i)*time.Second))
		if i%2 == 0 {
			event.SourceID = "other-deleted-camera" // Same name, distinct historic source.
		}
		events = append(events, event)
	}
	events = append(events, events[0], events[500])
	calls := 0
	service := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
		calls++
		if !page.Window.Start.Equal(request.Start) || !page.Window.End.Equal(request.End) {
			t.Fatal("time window moved between pages")
		}
		start, end := (page.Page-1)*page.PageSize, page.Page*page.PageSize
		if end > len(events) {
			end = len(events)
		}
		return device.EventPage{Events: events[start:end], Total: intPointer(len(events))}, nil
	}))
	result, err := service.Summarize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != eventCount || calls != 2 || result.Coverage.RowsRead != eventCount+2 || result.Coverage.Duplicates != 2 {
		t.Fatalf("count/pagination/dedup = count %d, calls %d, coverage %+v", result.Count, calls, result.Coverage)
	}
	if !result.Coverage.RetrievalComplete || result.Coverage.Accuracy != "exact_retained" || result.Coverage.HistoryCoverage != "unknown" {
		t.Fatalf("coverage = %+v", result.Coverage)
	}
	if len(result.BySource) != 2 || result.BySource[0].Count != (eventCount+1)/2 || result.BySource[1].Count != eventCount/2 || result.BySource[0].Name != result.BySource[1].Name {
		t.Fatalf("same-name source grouping = %+v", result.BySource)
	}
	if len(result.ByDay) != 7 || result.ByDay[0].Date != "2026-09-01" || result.ByDay[0].Count != eventCount || result.ByDay[6].Count != 0 {
		t.Fatalf("local-day distribution = %+v", result.ByDay)
	}
	if len(result.RepresentativeEvents) != representativeLimit || result.RepresentativeEvents[0].ID != fmt.Sprintf("event-%04d", eventCount-1) {
		t.Fatalf("representatives = %+v", result.RepresentativeEvents)
	}
	if len(result.Coverage.Gaps) != 1 || !hasGap(result, "history_coverage_unknown") {
		t.Fatalf("history must remain unknown after exact pagination: %+v", result.Coverage)
	}
}

func TestSummaryFiltersStableIDsAndHalfOpenTimeLocally(t *testing.T) {
	request := testRequest()
	request.SourceIDs = []string{"deleted-camera"}
	request.AlgorithmIDs = []string{"old-algorithm", "old-algorithm"}
	before := testEvent("before", request.Start.Add(-time.Millisecond))
	start := testEvent("start", request.Start)
	last := testEvent("last", request.End.Add(-time.Millisecond))
	end := testEvent("end", request.End)
	wrongSource := testEvent("wrong-source", request.Start)
	wrongSource.SourceID = "same-display-name"
	wrongAlgorithm := testEvent("wrong-algorithm", request.Start)
	wrongAlgorithm.AlgorithmID = "other-algorithm"
	rows := []device.HistoricalEvent{end, wrongSource, before, start, wrongAlgorithm, last}
	service := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
		if !reflect.DeepEqual(page.AlgorithmIDs, []string{"old-algorithm"}) {
			t.Fatalf("algorithm query filter = %#v", page.AlgorithmIDs)
		}
		// Deliberately ignore the device query filters to verify local matching.
		return device.EventPage{Events: rows, Total: intPointer(len(rows))}, nil
	}))
	result, err := service.Summarize(context.Background(), request)
	if err != nil || result.Count != 2 || result.Coverage.ExcludedRows != 4 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if result.ByDay[0].Count != 1 || result.ByDay[6].Count != 1 || result.BySourceAlgorithm[0].Count != 2 {
		t.Fatalf("distribution = %+v", result)
	}
	if result.RepresentativeEvents[0].ID != "last" || result.RepresentativeEvents[1].ID != "start" {
		t.Fatalf("wrong event evidence = %+v", result.RepresentativeEvents)
	}
}

func TestSummaryUsesCalendarDaysAcrossDST(t *testing.T) {
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Start: time.Date(2026, 3, 7, 0, 0, 0, 0, zone), End: time.Date(2026, 3, 10, 0, 0, 0, 0, zone), TimeZone: "America/New_York"}
	rows := []device.HistoricalEvent{
		testEvent("a", time.Date(2026, 3, 8, 0, 30, 0, 0, zone)),
		testEvent("b", time.Date(2026, 3, 8, 23, 30, 0, 0, zone)),
		testEvent("c", time.Date(2026, 3, 9, 0, 0, 0, 0, zone)),
	}
	result, err := New(readerFunc(func(context.Context, device.EventPageRequest) (device.EventPage, error) {
		return device.EventPage{Events: rows}, nil
	})).Summarize(context.Background(), request)
	want := []DailyCount{{Date: "2026-03-07", SharePercent: floatPointer(0)}, {Date: "2026-03-08", Count: 2, SharePercent: floatPointer(66.67)}, {Date: "2026-03-09", Count: 1, SharePercent: floatPointer(33.33)}}
	if err != nil || !reflect.DeepEqual(result.ByDay, want) {
		t.Fatalf("calendar day counts = %+v, error=%v", result.ByDay, err)
	}
}

func TestSummaryEmptyIsExactRetainedButCoverageUnknown(t *testing.T) {
	request := testRequest()
	result, err := New(readerFunc(func(context.Context, device.EventPageRequest) (device.EventPage, error) {
		return device.EventPage{Total: intPointer(0)}, nil
	})).Summarize(context.Background(), request)
	if err != nil || result.Count != 0 || !result.Coverage.RetrievalComplete || result.Coverage.Accuracy != "exact_retained" || !hasGap(result, "history_coverage_unknown") {
		t.Fatalf("empty result=%+v error=%v", result, err)
	}
	if !strings.Contains(strings.Join(result.Notes, ""), "零条记录不证明") {
		t.Fatal("empty result lacks the no-safety/no-uptime interpretation boundary")
	}
}

func TestSummaryUnknownTotalReadsThroughTerminalPage(t *testing.T) {
	request := testRequest()
	calls := 0
	service := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
		calls++
		if page.Page == 4 {
			return device.EventPage{}, nil
		}
		rows := make([]device.HistoricalEvent, page.PageSize)
		for i := range rows {
			rows[i] = testEvent(fmt.Sprintf("%d-%d", page.Page, i), request.Start)
		}
		return device.EventPage{Events: rows}, nil
	}))
	result, err := service.Summarize(context.Background(), request)
	if err != nil || calls != 4 || result.Count != 3*defaultPageSize || !result.Coverage.RetrievalComplete || result.Coverage.ReportedTotal != nil {
		t.Fatalf("unknown-total pagination=%+v calls=%d error=%v", result.Coverage, calls, err)
	}
}

func TestSummaryFailureRetainsPartialFactsAndNeverProjectsDeviceError(t *testing.T) {
	request := testRequest()
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(failFirst), func(t *testing.T) {
			service := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
				if failFirst || page.Page == 2 {
					return device.EventPage{}, errors.New("private endpoint and authentication value")
				}
				return device.EventPage{Events: []device.HistoricalEvent{testEvent("a", request.Start)}, Total: intPointer(3)}, nil
			}))
			result, err := service.Summarize(context.Background(), request)
			if err != nil || result.Coverage.RetrievalComplete || !hasGap(result, "event_page_unavailable") {
				t.Fatalf("partial result=%+v error=%v", result, err)
			}
			wantCount, wantAccuracy := 1, "lower_bound"
			if failFirst {
				wantCount, wantAccuracy = 0, "unknown"
			}
			if result.Count != wantCount || result.Coverage.Accuracy != wantAccuracy || strings.Contains(fmt.Sprint(result), "authentication value") {
				t.Fatalf("partial count/error projection=%+v", result)
			}
		})
	}
}

func TestSummaryIncompletePagesAndMalformedFacts(t *testing.T) {
	request := testRequest()
	a, b := testEvent("a", request.Start), testEvent("b", request.Start)
	conflict := a
	conflict.SourceID = "another-camera"
	for _, test := range []struct {
		name      string
		pages     []device.EventPage
		maxPages  int
		wantCount int
		gap       string
	}{
		{name: "early terminal", pages: []device.EventPage{{Events: []device.HistoricalEvent{a}, Total: intPointer(3)}, {Total: intPointer(3)}}, wantCount: 1, gap: "page_ended_early"},
		{name: "total drift", pages: []device.EventPage{{Events: []device.HistoricalEvent{a}, Total: intPointer(2)}, {Events: []device.HistoricalEvent{b}, Total: intPointer(3)}, {Total: intPointer(3)}}, wantCount: 2, gap: "total_changed"},
		{name: "repeated page", pages: []device.EventPage{{Events: []device.HistoricalEvent{a}, Total: intPointer(2)}, {Events: []device.HistoricalEvent{a}, Total: intPointer(2)}}, wantCount: 1, gap: "page_repeated"},
		{name: "invalid row", pages: []device.EventPage{{Events: []device.HistoricalEvent{a, {}}, Total: intPointer(2)}}, wantCount: 1, gap: "invalid_event_rows"},
		{name: "ID conflict", pages: []device.EventPage{{Events: []device.HistoricalEvent{a, b, conflict}, Total: intPointer(3)}}, wantCount: 1, gap: "conflicting_event_ids"},
		{name: "page limit", pages: []device.EventPage{{Events: []device.HistoricalEvent{a}, Total: intPointer(2)}}, maxPages: 1, wantCount: 1, gap: "page_limit_reached"},
		{name: "inconsistent total", pages: []device.EventPage{{Events: []device.HistoricalEvent{a, b}, Total: intPointer(1)}}, wantCount: 2, gap: "total_inconsistent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
				if page.Page > len(test.pages) {
					t.Fatalf("unexpected page %d", page.Page)
				}
				return test.pages[page.Page-1], nil
			}))
			if test.maxPages > 0 {
				service.maxPages = test.maxPages
			}
			result, err := service.Summarize(context.Background(), request)
			if err != nil || result.Count != test.wantCount || result.Coverage.RetrievalComplete || !hasGap(result, test.gap) {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if result.Coverage.Accuracy != "lower_bound" {
				t.Fatalf("partial count must be a lower bound: %+v", result.Coverage)
			}
		})
	}
}

func TestSummaryCancelledBeforeReadReturnsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := New(readerFunc(func(context.Context, device.EventPageRequest) (device.EventPage, error) {
		t.Fatal("cancelled query reached the device")
		return device.EventPage{}, nil
	})).Summarize(ctx, testRequest())
	if err != nil || result.Coverage.Accuracy != "unknown" || !hasGap(result, "read_interrupted") || result.Coverage.PagesRead != 0 {
		t.Fatalf("cancelled result=%+v error=%v", result, err)
	}
}

func TestSummaryRejectsUnboundedAmbiguousOrInvalidRequests(t *testing.T) {
	valid := testRequest()
	requests := []Request{{}, {Start: valid.End, End: valid.Start}, {Start: valid.Start, End: valid.Start.Add(MaxWindow + time.Second)}}
	for _, zone := range []string{"Local", "not-a-zone"} {
		request := valid
		request.TimeZone = zone
		requests = append(requests, request)
	}
	for _, id := range []string{"", " imprecise ", "a\nb"} {
		request := valid
		request.SourceIDs = []string{id}
		requests = append(requests, request)
	}
	service := New(readerFunc(func(context.Context, device.EventPageRequest) (device.EventPage, error) {
		t.Fatal("invalid request reached device")
		return device.EventPage{}, nil
	}))
	for i, request := range requests {
		if _, err := service.Summarize(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("request %d error=%v, want ErrInvalidRequest", i, err)
		}
	}
}
