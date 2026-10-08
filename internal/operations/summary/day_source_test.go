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

func TestDaySourceGridPreservesZeroCellsAndPartialScope(t *testing.T) {
	request := testRequest()
	request.End = request.Start.AddDate(0, 0, 3)
	request.SourceKinds = map[string]string{"one": "test_video", "two": "network_camera"}
	var first, second []device.HistoricalEvent
	for source, daily := range map[string][]int{"one": {1, 0, 2}, "two": {0, 4, 0}} {
		for day, count := range daily {
			for i := 0; i < count; i++ {
				e := testEvent(fmt.Sprintf("%s-%d-%d", source, day, i), request.Start.AddDate(0, 0, day))
				e.SourceID, e.SourceName = source, "same name"
				if source == "one" {
					first = append(first, e)
				} else {
					second = append(second, e)
				}
			}
		}
	}
	outside := first[0]
	outside.ID, outside.OccurredAt = "outside", request.End
	second = append(second, first[0], outside)
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			calls := 0
			result, err := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
				calls++
				if page.PageSize != device.MaxEventPageSize || page.Page != calls || calls > 2 {
					t.Fatalf("unexpected page: %+v", page)
				}
				if calls == 1 {
					return device.EventPage{Events: first, Total: intPointer(9)}, nil
				}
				if partial {
					return device.EventPage{}, errors.New("page unavailable")
				}
				return device.EventPage{Events: second, Total: intPointer(9)}, nil
			})).Summarize(context.Background(), request)
			if err != nil || calls != 2 || len(result.ByDaySource) != 6 || result.Coverage.RetrievalComplete == partial {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			want := map[string][]int{"one": {1, 0, 2}, "two": {0, 4, 0}}
			if partial {
				want["two"] = []int{0, 0, 0}
			}
			got := map[string][]int{"one": {}, "two": {}}
			daySums := map[string]int{}
			total := 0
			for _, cell := range result.ByDaySource {
				got[cell.SourceID] = append(got[cell.SourceID], cell.Count)
				daySums[cell.Date] += cell.Count
				total += cell.Count
			}
			if !reflect.DeepEqual(got, want) || total != result.Count || result.ShareBasis.Scope != "selected_window_retrieved_records" {
				t.Fatalf("incorrect daily/source counts: %+v", result)
			}
			for _, day := range result.ByDay {
				if daySums[day.Date] != day.Count {
					t.Fatal("day totals diverged")
				}
			}
			for _, source := range result.BySource {
				sum := 0
				for _, n := range got[source.ID] {
					sum += n
				}
				if sum != source.Count {
					t.Fatal("source totals diverged")
				}
			}
			if partial && (!hasGap(result, "event_page_unavailable") || result.Coverage.Accuracy != "lower_bound") {
				t.Fatal("zero cells concealed incomplete retrieval")
			}
		})
	}
}

func TestDaySourceGridForExplicitZeroSourceExcludesOtherCatalogSources(t *testing.T) {
	request := testRequest()
	request.End = request.Start.Add(24 * time.Hour)
	request.SourceIDs = []string{"selected-empty"}
	request.SourceKinds = map[string]string{"selected-empty": "test_video", "unselected": "network_camera"}
	row := testEvent("unselected-event", request.Start)
	row.SourceID = "unselected"
	result, err := New(readerFunc(func(context.Context, device.EventPageRequest) (device.EventPage, error) {
		return device.EventPage{Events: []device.HistoricalEvent{row}, Total: intPointer(1)}, nil
	})).Summarize(context.Background(), request)
	if err != nil || result.Count != 0 || len(result.ByDaySource) != 1 || result.ByDaySource[0].SourceID != "selected-empty" || result.ByDaySource[0].Count != 0 || result.ByDaySource[0].SharePercent != nil || len(result.BySourceKind) != 0 || len(result.BySource) != 0 {
		t.Fatalf("zero grid changed count scope: %+v, %v", result, err)
	}
}
