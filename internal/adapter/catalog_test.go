package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestCatalogAdapterMethodsUseExpectedV1PathsAndBodies(t *testing.T) {
	wantBodies := map[string]map[string]any{
		"/gtw/cwai/Camera/Page":                    {"pageNum": float64(2), "pageSize": float64(3)},
		"/gtw/cwai/Camera/Add":                     {"channelName": "Front Door", "channelType": float64(0), "url": "rtsp://camera/live"},
		"/gtw/cwai/Algorithm/Page":                 {"pageNum": float64(4), "pageSize": float64(5)},
		"/gtw/cwai/atomic/Model/Page":              {"pageNum": float64(6), "pageSize": float64(7)},
		"/gtw/cwai/atomic/model/list":              {},
		"/gtw/cwai/algorithm/layout/list":          {},
		"/gtw/cwai/algorithm/layout/save":          {"algorithmId": "alg-1", "filePath": "/opt/models/helmet.zip"},
		"/gtw/cwai/Algorithm/PassFlowList":         {},
		"/gtw/cwai/Event/QueryPassengerFlowNumber": {"algorithmCode": "alg-1", "channelId": "cam-1", "type": float64(1)},
		"/gtw/cwai/Event/ExportAlarm":              {"algorithmId": "alg-1"},
		"/gtw/cwai/Task/RunningDetail":             {"tasks": []any{"task-1", "task-2"}},
		"/gtw/cwai/Task/SwitchTask":                {"algorithmId": "alg-1", "channelId": "cam-1", "id": "task-1", "switch": float64(1)},
		"/gtw/cwai/Task/QuerySwitch":               {"algorithmId": "alg-1", "channelId": "cam-1", "id": "task-1"},
		"/gtw/cwai/Task/QueryParam":                {"algorithmId": "alg-1", "channelId": "cam-1"},
		"/gtw/cwai/Task/ModifyParam":               {"algorithmId": "alg-1", "channelId": "cam-1", "id": "task-1", "taskConfig": map[string]any{"params": []any{map[string]any{"key": "param.sensitivity", "value": "6"}}}},
		"/gtw/cwai/task/selectConfigByAlgorithmId": {"algorithmId": "alg-1", "channelId": "cam-1"},
	}
	seen := map[string]bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		want, ok := wantBodies[r.URL.Path]
		if !ok {
			t.Errorf("unexpected v1 path %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}

		var got map[string]any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode %s body: %v", r.URL.Path, err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s body = %#v, want %#v", r.URL.Path, got, want)
			http.Error(w, "unexpected body", http.StatusBadRequest)
			return
		}
		seen[r.URL.Path] = true
		fmt.Fprint(w, `{"resCode":1,"resData":{"ok":true}}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "admin", "secret")

	calls := []struct {
		name string
		run  func() (map[string]any, error)
	}{
		{"camera page", func() (map[string]any, error) { return c.QueryCameraPage(2, 3) }},
		{"camera add", func() (map[string]any, error) {
			return c.AddCameraSource(map[string]any{"channelName": "Front Door", "channelType": 0, "url": "rtsp://camera/live"})
		}},
		{"algorithm page", func() (map[string]any, error) { return c.QueryAlgorithmPage(4, 5) }},
		{"atomic model page", func() (map[string]any, error) { return c.QueryAtomicModelPage(6, 7) }},
		{"atomic model list", c.QueryAtomicModelList},
		{"algorithm layout list", c.QueryAlgorithmLayoutList},
		{"algorithm layout save", func() (map[string]any, error) {
			return c.SaveAlgorithmLayout(map[string]any{"algorithmId": "alg-1", "filePath": "/opt/models/helmet.zip"})
		}},
		{"pass flow list", c.QueryPassFlowList},
		{"passenger flow number", func() (map[string]any, error) {
			return c.QueryPassengerFlowNumber(map[string]any{
				"channelId":     "cam-1",
				"algorithmCode": "alg-1",
				"type":          1,
			})
		}},
		{"export alarm", func() (map[string]any, error) {
			return c.ExportAlarm(map[string]any{"algorithmId": "alg-1"})
		}},
		{"task running detail", func() (map[string]any, error) {
			return c.QueryTaskRunningDetail([]string{"task-1", "task-2"})
		}},
		{"task switch", func() (map[string]any, error) {
			return c.SwitchTask(map[string]any{"id": "task-1", "channelId": "cam-1", "algorithmId": "alg-1", "switch": 1})
		}},
		{"task query switch", func() (map[string]any, error) {
			return c.QueryTaskSwitch(map[string]any{"id": "task-1", "channelId": "cam-1", "algorithmId": "alg-1"})
		}},
		{"task param", func() (map[string]any, error) {
			return c.QueryTaskParam("cam-1", "alg-1")
		}},
		{"task modify param", func() (map[string]any, error) {
			return c.UpdateTaskParameters(map[string]any{"id": "task-1", "channelId": "cam-1", "algorithmId": "alg-1", "taskConfig": map[string]any{"params": []any{map[string]any{"key": "param.sensitivity", "value": "6"}}}})
		}},
		{"task config", func() (map[string]any, error) {
			return c.QueryTaskConfig("cam-1", "alg-1")
		}},
	}

	for _, call := range calls {
		resp, err := call.run()
		if err != nil {
			t.Fatalf("%s error = %v", call.name, err)
		}
		if ok, _ := resp["ok"].(bool); !ok {
			t.Fatalf("%s response = %#v, want ok=true", call.name, resp)
		}
	}

	for path := range wantBodies {
		if !seen[path] {
			t.Fatalf("expected path %s was not called", path)
		}
	}
}

func TestWriteMethodsClassifyDecodeFailureAsOutcomeUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{not-json`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "admin", "secret")
	cases := []struct {
		name string
		path string
		run  func() (map[string]any, error)
	}{
		{
			name: "algorithm layout save",
			path: "/algorithm/layout/save",
			run:  func() (map[string]any, error) { return c.SaveAlgorithmLayout(map[string]any{"algorithmId": "alg-1"}) },
		},
		{
			name: "task switch",
			path: "/Task/SwitchTask",
			run:  func() (map[string]any, error) { return c.SwitchTask(map[string]any{"id": "task-1", "switch": 1}) },
		},
		{
			name: "task param modify",
			path: "/Task/ModifyParam",
			run: func() (map[string]any, error) {
				return c.UpdateTaskParameters(map[string]any{"channelId": "cam-1", "algorithmId": "alg-1", "taskConfig": map[string]any{"params": []any{}}})
			},
		},
		{
			name: "camera source add",
			path: "/Camera/Add",
			run: func() (map[string]any, error) {
				return c.AddCameraSource(map[string]any{"channelName": "Front Door", "channelType": 0, "url": "rtsp://camera/live"})
			},
		},
	}
	for _, tc := range cases {
		_, err := tc.run()
		if err == nil {
			t.Fatalf("%s error = nil, want OutcomeUnknownError", tc.name)
		}
		var unknown *OutcomeUnknownError
		if !errors.As(err, &unknown) {
			t.Fatalf("%s error = %T %v, want OutcomeUnknownError", tc.name, err, err)
		}
		if unknown.Path != tc.path || unknown.Phase != "decode_response" {
			t.Fatalf("%s unknown = %#v, want path %q phase decode_response", tc.name, unknown, tc.path)
		}
	}
}

func TestReadDecodeFailureIsNotOutcomeUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{not-json`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "admin", "secret")
	_, err := c.QueryTaskSwitch(map[string]any{"id": "task-1"})
	if err == nil {
		t.Fatal("QueryTaskSwitch() error = nil, want decode error")
	}
	var unknown *OutcomeUnknownError
	if errors.As(err, &unknown) {
		t.Fatalf("QueryTaskSwitch() error = %#v, should not be OutcomeUnknownError", unknown)
	}
}

func TestWriteBusinessRejectionIsV1ErrorNotOutcomeUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"resCode":123,"resMsg":[{"msgText":"business rejected","msgCode":"TASK_REJECTED"}]}`)
	}))
	defer server.Close()

	c := NewClient(server.URL, "admin", "secret")
	_, err := c.SwitchTask(map[string]any{"id": "task-1", "switch": 1})
	if err == nil {
		t.Fatal("SwitchTask() error = nil, want V1Error")
	}
	var unknown *OutcomeUnknownError
	if errors.As(err, &unknown) {
		t.Fatalf("SwitchTask() error = %#v, should not be OutcomeUnknownError", unknown)
	}
	var v1Err *V1Error
	if !errors.As(err, &v1Err) {
		t.Fatalf("SwitchTask() error = %T %[1]v, want V1Error", err)
	}
	if v1Err.ResCode != 123 || v1Err.MsgCode != "TASK_REJECTED" {
		t.Fatalf("V1Error = %#v, want resCode=123 msgCode=TASK_REJECTED", v1Err)
	}
	if !v1Err.KnownFailure() {
		t.Fatalf("V1Error.KnownFailure() = false, want true for business rejection")
	}
}

func TestWriteDeadlineIsOutcomeUnknownAndNotRetried(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.CloseClientConnections()
		server.Close()
	}()

	c := NewClient(server.URL, "admin", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.SwitchTaskContext(ctx, map[string]any{"id": "task-1", "switch": 1})
	if err == nil {
		t.Fatal("SwitchTaskContext() error = nil, want OutcomeUnknownError")
	}
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("SwitchTaskContext() error = %T %[1]v, want OutcomeUnknownError", err)
	}
	if unknown.Path != "/Task/SwitchTask" || unknown.Phase != "transport" {
		t.Fatalf("unknown = %#v, want Task/SwitchTask transport", unknown)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SwitchTaskContext() error = %v, want context deadline exceeded", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("SwitchTaskContext() calls = %d, want no retry", got)
	}
}
