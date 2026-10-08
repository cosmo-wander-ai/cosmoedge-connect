package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func eventTestClient(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *v1Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/gtw/cwai/login/DoLogin":
			fmt.Fprint(w, `{"resCode":1,"resData":{"mtk":"event-test-session"}}`)
		case "/gtw/cwai/Event/Page":
			handler(w, r)
		default:
			t.Errorf("unexpected device endpoint: %s", r.URL.Path)
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := NewV1Client(server.URL, "test-operator", "test-only").(*v1Client)
	if err := client.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

func eventPageRequest() EventPageRequest {
	return EventPageRequest{Window: EventWindow{Start: time.UnixMilli(1788220800000).UTC(), End: time.UnixMilli(1788307200000).UTC()}, Page: 2, PageSize: 200, AlgorithmIDs: []string{"5"}}
}

func TestReadEventPageUsesStableTimeAndActualV1Fields(t *testing.T) {
	request := eventPageRequest()
	request.PageSize = 5000
	client := eventTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{
			"pageNum": float64(2), "pageSize": float64(5000),
			"timeBegin": float64(request.Window.Start.UnixMilli()), "timeEnd": float64(request.Window.End.UnixMilli()),
			"algorithmCodes": []any{"5"},
		}
		if !reflect.DeepEqual(body, want) {
			t.Errorf("event query=%#v, want %#v", body, want)
		}
		fmt.Fprint(w, `{"resCode":1,"resData":{"total":11167,"rows":[{"id":"event-1","timestamp":1788239318472,"videoChannelId":"historical-camera","channelName":"历史测试视频","algorithmCode":"5","algorithmName":"烟火检测","fullPicture":"/private/not-exposed.jpg"}]}}`)
	})
	page, err := client.ReadEventPage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total == nil || *page.Total != 11167 || len(page.Events) != 1 {
		t.Fatalf("page=%+v", page)
	}
	want := HistoricalEvent{ID: "event-1", OccurredAt: time.UnixMilli(1788239318472).UTC(), SourceID: "historical-camera", SourceName: "历史测试视频", AlgorithmID: "5", AlgorithmName: "烟火检测"}
	if !reflect.DeepEqual(page.Events[0], want) {
		t.Fatalf("historical event=%+v, want %+v", page.Events[0], want)
	}
}

func TestReadEventPagePreservesMalformedRowsAndNumericStringTimestamp(t *testing.T) {
	client := eventTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resCode":1,"resData":{"total":"3","rows":[{"id":"event-1","timestamp":"1788239318472","videoChannelId":"camera","algorithmCode":"5"},{"id":"event-2","timestamp":1788239318472.5,"videoChannelId":{"secret":"not-an-id"},"algorithmCode":"5"},false]}}`)
	})
	page, err := client.ReadEventPage(context.Background(), eventPageRequest())
	if err != nil || len(page.Events) != 3 || page.Total == nil || *page.Total != 3 {
		t.Fatalf("page=%+v error=%v", page, err)
	}
	if page.Events[0].OccurredAt.UnixMilli() != 1788239318472 || !page.Events[1].OccurredAt.IsZero() || page.Events[1].SourceID != "" || page.Events[2].ID != "" {
		t.Fatalf("malformed values were promoted into event evidence: %+v", page.Events)
	}
}

func TestReadEventPageRejectsUnknownRowsAndInvalidTotals(t *testing.T) {
	for name, payload := range map[string]string{
		"missing rows":           `{"total":3}`,
		"unknown total and rows": `{}`,
		"wrong rows type":        `{"total":3,"rows":"not-a-page"}`,
		"negative total":         `{"total":-1,"rows":[]}`,
		"fraction total":         `{"total":0.5,"rows":[]}`,
		"wrong total type":       `{"total":{},"rows":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := eventTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"resCode":1,"resData":%s}`, payload)
			})
			if page, err := client.ReadEventPage(context.Background(), eventPageRequest()); err == nil {
				t.Fatalf("malformed response accepted as %+v", page)
			}
		})
	}
}

func TestReadEventPageAllowsExplicitEmptyTotalOrEmptyRowsWithoutTotal(t *testing.T) {
	for _, payload := range []string{`{"total":0,"rows":null}`, `{"rows":[]}`} {
		client := eventTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"resCode":1,"resData":%s}`, payload)
		})
		page, err := client.ReadEventPage(context.Background(), eventPageRequest())
		if err != nil || len(page.Events) != 0 {
			t.Fatalf("empty page=%+v error=%v", page, err)
		}
	}
}

func TestReadEventPageRoundsQueryEndOutwards(t *testing.T) {
	request := eventPageRequest()
	request.Window.End = request.Window.End.Add(time.Microsecond)
	client := eventTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["timeEnd"] != float64(request.Window.End.UnixMilli()+1) {
			t.Errorf("query excluded events in last partial millisecond: %#v", body)
		}
		fmt.Fprint(w, `{"resCode":1,"resData":{"total":0,"rows":[]}}`)
	})
	if _, err := client.ReadEventPage(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestReadEventPageRejectsInvalidBoundsBeforeRequest(t *testing.T) {
	client := eventTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("invalid request reached Event/Page")
	})
	for _, request := range []EventPageRequest{
		{},
		{Window: eventPageRequest().Window, Page: 0, PageSize: 200},
		{Window: eventPageRequest().Window, Page: 1, PageSize: 5001},
		{Window: eventPageRequest().Window, Page: 1, PageSize: 200, AlgorithmIDs: []string{""}},
	} {
		if _, err := client.ReadEventPage(context.Background(), request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
}

func TestReadEventPageRejectsResponseLargerThanRequested(t *testing.T) {
	client := eventTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"resCode": 1, "resData": map[string]any{"total": 5001, "rows": make([]any, 5001)},
		})
	})
	request := eventPageRequest()
	request.PageSize = 5000
	if _, err := client.ReadEventPage(context.Background(), request); err == nil {
		t.Fatal("response exceeding the requested page size was accepted")
	}
}
