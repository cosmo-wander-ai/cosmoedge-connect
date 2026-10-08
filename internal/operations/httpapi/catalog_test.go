package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestCatalogTotalsMatchReturnedEntriesWithoutInferringUnknownFacts(t *testing.T) {
	longCatalog := []device.Camera{{ID: "network", Name: "Camera", SourceKind: "network_camera"}}
	for i := 0; i < 18; i++ {
		longCatalog = append(longCatalog, device.Camera{ID: fmt.Sprintf("video-%d", i), Name: "Video", SourceKind: "test_video"})
	}
	for _, tc := range []struct {
		name       string
		cameras    []device.Camera
		algorithms []device.Algorithm
		tasks      []device.Task
		want       CatalogTotals
	}{
		{
			name: "long repeated-name directory", cameras: longCatalog,
			algorithms: []device.Algorithm{{ID: "a", Name: "Detection"}, {ID: "b", Name: "Detection"}},
			tasks:      []device.Task{{Enabled: 1, Running: "running"}, {Enabled: 0, Running: "stopped"}},
			want: CatalogTotals{SourceCount: 19, SourcesByKind: map[string]int{"network_camera": 1, "test_video": 18, "usb_camera": 0, "unknown": 0},
				AlgorithmCount: 2, TaskCount: 2, RunningTaskCount: 1, StoppedTaskCount: 1},
		},
		{
			name: "unknown types and runtime remain unknown",
			cameras: []device.Camera{
				{ID: "a", SourceKind: "network_camera"}, {ID: "b", SourceKind: "test_video"},
				{ID: "c", SourceKind: "usb_camera"}, {ID: "d", SourceKind: "unknown"},
				{ID: "e", SourceKind: ""}, {ID: "f", SourceKind: "future_source"},
			},
			// Totals follow runtime, never the enabled switch or an unfamiliar
			// state that happens to sound like progress.
			tasks: []device.Task{
				{Enabled: 0, Running: "running"}, {Enabled: 1, Running: "stopped"},
				{Enabled: 1, Running: "unknown"}, {Enabled: 0, Running: ""},
				{Enabled: 1, Running: "processing"},
			},
			want: CatalogTotals{SourceCount: 6, SourcesByKind: map[string]int{"network_camera": 1, "test_video": 1, "usb_camera": 1, "unknown": 3},
				TaskCount: 5, RunningTaskCount: 1, StoppedTaskCount: 1, UnknownRuntimeTaskCount: 3},
		},
		{
			name: "empty directory reports explicit zeros",
			want: CatalogTotals{SourcesByKind: map[string]int{"network_camera": 0, "test_video": 0, "usb_camera": 0, "unknown": 0}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &summaryHTTPDevice{cameras: tc.cameras, algorithms: tc.algorithms, tasks: tc.tasks}
			handler, token := newSummaryHTTPHandler(t, client, time.Now().UTC())
			issued := callSummaryHTTP(handler, token, "session", "", "{}")
			var session struct{ SessionRef string }
			if err := json.Unmarshal(issued.Body.Bytes(), &session); err != nil || issued.Code != http.StatusOK || session.SessionRef == "" {
				t.Fatal("session issuance failed", issued.Code, err)
			}
			r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:37789"+Prefix+"catalog", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("X-CosmoEdge-Session", session.SessionRef)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			var got struct {
				OK         bool
				Sources    []Source
				Algorithms []Algorithm
				Tasks      []struct {
					Enabled int
					Runtime string
				}
				Totals *CatalogTotals
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK || !got.OK || got.Totals == nil {
				t.Fatalf("catalog response: status=%d body=%s error=%v", w.Code, w.Body, err)
			}
			if !reflect.DeepEqual(*got.Totals, tc.want) {
				t.Fatalf("totals=%+v want=%+v", *got.Totals, tc.want)
			}
			if got.Totals.SourceCount != len(got.Sources) || got.Totals.AlgorithmCount != len(got.Algorithms) || got.Totals.TaskCount != len(got.Tasks) {
				t.Fatal("totals do not match the returned directory")
			}
			for i, source := range got.Sources {
				if source.Kind != tc.cameras[i].SourceKind || source.Name != tc.cameras[i].Name {
					t.Fatal("counting changed a source entry", source)
				}
			}
			for i, task := range got.Tasks {
				if task.Runtime != tc.tasks[i].Running || task.Enabled != tc.tasks[i].Enabled {
					t.Fatal("counting changed a task entry", task)
				}
			}
			if client.algorithmReads != 1 {
				t.Fatal("totals made an additional catalog read")
			}
		})
	}
}
