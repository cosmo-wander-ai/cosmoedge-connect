package summary

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestSummarySourceKindsCountRetainedRecordsAndDistinctSourcesSeparately(t *testing.T) {
	base := testRequest()
	base.SourceKinds = map[string]string{"network": "network_camera", "unrecognized": "future_kind", "no-events": "test_video"}
	var first, second []device.HistoricalEvent
	appendEvents := func(target *[]device.HistoricalEvent, source string, count int) {
		for i := 0; i < count; i++ {
			event := testEvent(fmt.Sprintf("%s-%d", source, i), base.Start.Add(time.Minute))
			event.SourceID, event.SourceName = source, "相同显示名称"
			*target = append(*target, event)
		}
	}
	for i := 0; i < 5; i++ {
		source := fmt.Sprintf("test-%d", i)
		base.SourceKinds[source] = "test_video"
		appendEvents(&first, source, 2)
	}
	appendEvents(&second, "network", 40)
	appendEvents(&second, "deleted", 3) // No current catalog entry, still historical evidence.
	appendEvents(&second, "unrecognized", 1)
	second = append(second, first[0]) // A repeated record is not another event or source.
	outOfWindow := first[1]
	outOfWindow.ID, outOfWindow.OccurredAt = "outside-window", base.End
	second = append(second, outOfWindow)

	for _, test := range []struct {
		name    string
		filter  bool
		partial bool
		kinds   []SourceKindCount
		count   int
	}{
		{name: "complete history", count: 54, kinds: []SourceKindCount{
			{SourceKind: "network_camera", RetainedRecordCount: 40, SourceCount: 1, SharePercent: floatPointer(74.07)},
			{SourceKind: "test_video", RetainedRecordCount: 10, SourceCount: 5, SharePercent: floatPointer(18.52)},
			{SourceKind: "unknown", RetainedRecordCount: 4, SourceCount: 2, SharePercent: floatPointer(7.41)},
		}},
		{name: "filtered history", filter: true, count: 40, kinds: []SourceKindCount{{SourceKind: "network_camera", RetainedRecordCount: 40, SourceCount: 1, SharePercent: floatPointer(100)}}},
		{name: "only first page read", partial: true, count: 10, kinds: []SourceKindCount{{SourceKind: "test_video", RetainedRecordCount: 10, SourceCount: 5, SharePercent: floatPointer(100)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := base
			if test.filter {
				request.SourceIDs = []string{"network"}
			}
			calls := 0
			service := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
				calls++
				if page.Page != calls || calls > 2 {
					t.Fatalf("unexpected page %d", page.Page)
				}
				if page.Page == 1 {
					return device.EventPage{Events: first, Total: intPointer(len(first) + len(second))}, nil
				}
				if test.partial {
					return device.EventPage{}, errors.New("page unavailable")
				}
				return device.EventPage{Events: second, Total: intPointer(len(first) + len(second))}, nil
			}))
			result, err := service.Summarize(context.Background(), request)
			if err != nil || calls != 2 || result.Count != test.count || !reflect.DeepEqual(result.BySourceKind, test.kinds) {
				t.Fatalf("kind counts changed evidence dimensions: count=%d kinds=%+v calls=%d err=%v", result.Count, result.BySourceKind, calls, err)
			}
			records, sources := 0, 0
			for _, kind := range result.BySourceKind {
				records += kind.RetainedRecordCount
				sources += kind.SourceCount
			}
			if records != result.Count || sources != len(result.BySource) || result.SourceKindBasis != "current_source_catalog" {
				t.Fatal("classification dropped history or counted inactive catalog entries")
			}
			wantScope := "retained_window"
			if test.partial {
				wantScope = "retrieved_records"
				if result.Coverage.Accuracy != "lower_bound" || result.Coverage.RetrievalComplete {
					t.Fatal("partial source distribution was promoted to full-window evidence")
				}
			} else if result.Coverage.Duplicates != 1 {
				t.Fatal("fixture did not exercise event deduplication")
			}
			if result.SourceKindScope != wantScope {
				t.Fatalf("kind scope %q, want %q", result.SourceKindScope, wantScope)
			}
		})
	}
}

func TestSummaryWithoutSourceCatalogRetainsUnknownClassification(t *testing.T) {
	request := testRequest()
	service := New(readerFunc(func(context.Context, device.EventPageRequest) (device.EventPage, error) {
		return device.EventPage{Events: []device.HistoricalEvent{testEvent("event", request.Start)}, Total: intPointer(1)}, nil
	}))
	result, err := service.Summarize(context.Background(), request)
	if err != nil || result.Count != 1 || result.SourceKindBasis != "unavailable" || !reflect.DeepEqual(result.BySourceKind, []SourceKindCount{{SourceKind: "unknown", RetainedRecordCount: 1, SourceCount: 1, SharePercent: floatPointer(100)}}) {
		t.Fatalf("missing catalog lost retained history: %+v, %v", result, err)
	}
}
