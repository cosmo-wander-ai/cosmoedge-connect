package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func issueSummaryTestSession(t *testing.T, handler *Handler, token string) string {
	t.Helper()
	w := callSummaryHTTP(handler, token, "session", "", "{}")
	var response struct {
		SessionRef string `json:"sessionRef"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || response.SessionRef == "" {
		t.Fatalf("session issuance failed: %d %s", w.Code, w.Body)
	}
	return response.SessionRef
}

func TestSummaryHTTPDistinguishesTimeErrorsBeforeDeviceReads(t *testing.T) {
	zone, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 23, 0, 0, 123456789, zone)
	start := time.Date(2026, 9, 9, 0, 0, 0, 0, zone)
	for _, tc := range []struct {
		name       string
		start, end time.Time
		zone, code string
	}{
		{name: "missing start", end: now, code: "time_range_missing"},
		{name: "missing end", start: start, code: "time_range_missing"},
		{name: "equal bounds", start: start, end: start, code: "time_range_invalid_order"},
		{name: "reversed bounds", start: now, end: start, code: "time_range_invalid_order"},
		{name: "duration exceeds limit", start: now.Add(-summary.MaxWindow - time.Nanosecond), end: now, code: "time_range_too_long"},
		{name: "tomorrow midnight", start: start, end: time.Date(2026, 9, 11, 0, 0, 0, 0, zone), zone: "Asia/Shanghai", code: "time_range_future_end"},
		{name: "future within old minute tolerance", start: start, end: now.Add(time.Second), zone: "Asia/Shanghai", code: "time_range_future_end"},
		{name: "whole window in future", start: now.Add(time.Second), end: now.Add(time.Hour), zone: "Asia/Shanghai", code: "time_range_future_end"},
		{name: "invalid zone", start: start, end: now, zone: "not-a-zone", code: "time_zone_invalid"},
		{name: "ambient local zone", start: start, end: now, zone: "Local", code: "time_zone_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &summaryHTTPDevice{readPage: func(context.Context, device.EventPageRequest) (device.EventPage, error) {
				t.Fatal("invalid time range reached event reader")
				return device.EventPage{}, nil
			}}
			handler, token := newSummaryHTTPHandler(t, client, now)
			ref := issueSummaryTestSession(t, handler, token)
			body, _ := json.Marshal(SummaryRequest{Start: tc.start, End: tc.end, TimeZone: tc.zone, AlgorithmName: "must not resolve"})
			w := callSummaryHTTP(handler, token, "summary", ref, string(body))
			var response struct {
				OK                       bool `json:"ok"`
				Code, UserMessage        string
				RequestedWindow          SummaryRequest `json:"requestedWindow"`
				ServerTime, AvailableEnd *time.Time
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusBadRequest || response.OK || response.Code != tc.code || response.UserMessage == "" || client.algorithmReads != 0 {
				t.Fatalf("wrong time diagnosis or unnecessary catalog read: %d %s", w.Code, w.Body)
			}
			wantZone := tc.zone
			if wantZone == "" {
				wantZone = "UTC"
			}
			if !response.RequestedWindow.Start.Equal(tc.start) || !response.RequestedWindow.End.Equal(tc.end) || response.RequestedWindow.TimeZone != wantZone {
				t.Fatalf("request was silently changed: %s", w.Body)
			}
			if tc.code == "time_range_future_end" {
				if response.ServerTime == nil || !response.ServerTime.Equal(now) || response.AvailableEnd == nil || !response.AvailableEnd.Equal(now) {
					t.Fatalf("future error lacks actual clock and usable end: %s", w.Body)
				}
				if !tc.start.Before(now) && strings.Contains(response.UserMessage, "可将结束时间设为") {
					t.Fatal("an entirely future window cannot be fixed by changing only the end")
				}
			} else if response.ServerTime != nil || response.AvailableEnd != nil {
				t.Fatalf("unrelated time error invented a replacement end: %s", w.Body)
			}
			if strings.Contains(response.UserMessage, "过去 31 天以内") {
				t.Fatal("duration limit was described as a historical cutoff")
			}
		})
	}
}

func TestSummaryHTTPKeepsExactRequestedWindowAndAcceptsUsableEnd(t *testing.T) {
	zone, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 10, 23, 0, 0, 123456789, zone)
	yesterday := time.Date(2026, 9, 9, 0, 0, 0, 0, zone)
	for _, tc := range []struct {
		name        string
		start, end  time.Time
		futureRetry bool
	}{
		{name: "yesterday through now with explicit offset", start: yesterday, end: now},
		{name: "equivalent UTC input", start: yesterday.UTC(), end: now.UTC()},
		{name: "exactly 31 day span", start: now.Add(-summary.MaxWindow), end: now},
		{name: "old retained history", start: yesterday.AddDate(-1, 0, 0), end: yesterday.AddDate(-1, 0, 1)},
		{name: "caller explicitly retries suggested end", start: yesterday, end: now, futureRetry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &summaryHTTPDevice{readPage: func(_ context.Context, request device.EventPageRequest) (device.EventPage, error) {
				calls++
				if !request.Window.Start.Equal(tc.start) || !request.Window.End.Equal(tc.end) {
					t.Fatalf("time window shifted: %+v", request.Window)
				}
				zero := 0
				return device.EventPage{Total: &zero}, nil
			}}
			handler, token := newSummaryHTTPHandler(t, client, now)
			ref := issueSummaryTestSession(t, handler, token)
			request := SummaryRequest{Start: tc.start, End: tc.end, TimeZone: "Asia/Shanghai"}
			if tc.futureRetry {
				request.End = time.Date(2026, 9, 11, 0, 0, 0, 0, zone)
				body, _ := json.Marshal(request)
				w := callSummaryHTTP(handler, token, "summary", ref, string(body))
				var response struct {
					AvailableEnd time.Time `json:"availableEnd"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusBadRequest || calls != 0 || !response.AvailableEnd.Equal(now) {
					t.Fatalf("future request executed or lacked retry fact: %d %s", w.Code, w.Body)
				}
				request.End = response.AvailableEnd
			}
			body, _ := json.Marshal(request)
			w := callSummaryHTTP(handler, token, "summary", ref, string(body))
			var response struct {
				Summary summary.Result `json:"summary"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || calls != 1 {
				t.Fatalf("valid range rejected: %d %s", w.Code, w.Body)
			}
			if !response.Summary.Window.Start.Equal(tc.start) || !response.Summary.Window.End.Equal(tc.end) || response.Summary.TimeZone != "Asia/Shanghai" || response.Summary.ByDay[0].Date != tc.start.In(zone).Format("2006-01-02") {
				t.Fatalf("response lost the requested local-day range: %s", w.Body)
			}
		})
	}
}
