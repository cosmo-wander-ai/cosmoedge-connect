package summary

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestSummarySharesUseFilteredDeduplicatedRetrievedRecords(t *testing.T) {
	request := testRequest()
	request.SourceIDs = []string{"one", "two"}
	request.SourceKinds = map[string]string{"one": "network_camera", "two": "test_video"}
	a, b, c := testEvent("a", request.Start), testEvent("b", request.Start.Add(24*time.Hour)), testEvent("c", request.Start.Add(25*time.Hour))
	a.SourceID, b.SourceID, c.SourceID = "one", "one", "two"
	a.AlgorithmID, b.AlgorithmID, c.AlgorithmID = "first", "second", "second"
	excluded, outside := a, a
	excluded.ID, excluded.SourceID = "excluded", "not-selected"
	outside.ID, outside.OccurredAt = "outside", request.End

	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[partial], func(t *testing.T) {
			service := New(readerFunc(func(_ context.Context, page device.EventPageRequest) (device.EventPage, error) {
				if page.Page == 1 {
					return device.EventPage{Events: []device.HistoricalEvent{a, b}, Total: intPointer(6)}, nil
				}
				if partial {
					return device.EventPage{}, errors.New("unavailable")
				}
				return device.EventPage{Events: []device.HistoricalEvent{c, a, excluded, outside}, Total: intPointer(6)}, nil
			}))
			result, err := service.Summarize(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			wantCount := 3
			if partial {
				wantCount = 2
			}
			wantBasis := ShareBasis{Scope: "selected_window_retrieved_records", Denominator: wantCount, NumeratorFields: map[string]string{
				"byDay": "count", "byDaySource": "count", "bySource": "count", "byAlgorithm": "count", "bySourceAlgorithm": "count", "bySourceKind": "retainedRecordCount",
			}}
			if result.Count != wantCount || !reflect.DeepEqual(result.ShareBasis, wantBasis) || result.Coverage.RetrievalComplete == partial {
				t.Fatalf("share basis included unselected, duplicate or unread rows: %+v", result)
			}
			// Hand-calculated expectations across all five independent dimensions.
			wantByCount := map[int]float64{0: 0, 1: 33.33, 2: 66.67, 3: 100}
			if partial {
				wantByCount = map[int]float64{0: 0, 1: 50, 2: 100}
			}
			check := func(count int, percent *float64) {
				t.Helper()
				if percent == nil || *percent != wantByCount[count] {
					t.Fatalf("count %d / %d has share %v, want %.2f", count, wantCount, percent, wantByCount[count])
				}
			}
			for _, v := range result.ByDay {
				check(v.Count, v.SharePercent)
			}
			for _, v := range result.ByDaySource {
				check(v.Count, v.SharePercent)
			}
			for _, v := range result.BySource {
				check(v.Count, v.SharePercent)
			}
			for _, v := range result.ByAlgorithm {
				check(v.Count, v.SharePercent)
			}
			for _, v := range result.BySourceAlgorithm {
				check(v.Count, v.SharePercent)
			}
			for _, v := range result.BySourceKind {
				check(v.RetainedRecordCount, v.SharePercent)
			}
		})
	}
}

func TestSummaryZeroDenominatorSerializesUndefinedShares(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "no retained rows", true: "no readable rows"}[partial], func(t *testing.T) {
			result, err := New(readerFunc(func(context.Context, device.EventPageRequest) (device.EventPage, error) {
				if partial {
					return device.EventPage{}, errors.New("unavailable")
				}
				return device.EventPage{Total: intPointer(0)}, nil
			})).Summarize(context.Background(), testRequest())
			if err != nil || result.ShareBasis.Denominator != 0 || result.Coverage.RetrievalComplete == partial {
				t.Fatalf("zero-row result: %+v, %v", result, err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var response map[string]any
			if err := json.Unmarshal(encoded, &response); err != nil {
				t.Fatal(err)
			}
			for _, day := range response["byDay"].([]any) {
				value, exists := day.(map[string]any)["sharePercent"]
				if !exists || value != nil {
					t.Fatalf("zero denominator must explicitly be null: %s", encoded)
				}
			}
		})
	}
}
