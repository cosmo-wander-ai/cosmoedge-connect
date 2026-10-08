package read

import (
	"context"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestPresentProjectsNotConnectedAsForegroundConnectionState(t *testing.T) {
	t.Parallel()
	service := New(notConnectedSource{})
	projection, _, err := service.Present(context.Background(), "manage_tasks", "today")
	if err != session.ErrNotConnected {
		t.Fatalf("not-connected error=%v", err)
	}
	if projection.State != "disconnected" || projection.Conclusion != "尚未连接设备。" || projection.Read.State != "disconnected" {
		t.Fatalf("not-connected projection=%#v", projection)
	}
}

func TestPresentUsesFixedProductWindowsAndFriendlyFacts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.Local)
	source := &fakeSource{snapshot: device.Snapshot{
		Identity: device.Identity{Serial: "FULL-DEVICE-SN-739184", Type: "edge-gateway"},
		Cameras:  []device.Camera{{ID: "camera-private", Name: "East Gate"}},
		Tasks: []device.Task{{
			ID: "task-private", ChannelID: "camera-private", AlgorithmID: "algorithm-private",
			DisplayName: "Helmet + East Gate", CameraName: "East Gate", AlgorithmName: "Helmet",
			Enabled: 1, Running: "running",
		}},
		ObservedAt: now.UTC(),
	}}
	service := New(source)
	service.now = func() time.Time { return now }
	projection, _, err := service.Present(context.Background(), "home", "today")
	if err != nil {
		t.Fatal(err)
	}
	if projection.Device.MaskedID != "***9184" || len(projection.Read.Tasks) != 0 || len(projection.OperationsSummaries) != 4 {
		t.Fatalf("home projection=%#v", projection)
	}
	if len(source.windows) != 4 {
		t.Fatalf("event windows=%d", len(source.windows))
	}
	windows := map[string]time.Duration{}
	for _, window := range source.windows {
		windows[windowKey(window, now)] = window.End.Sub(window.Start)
	}
	if windows["today"] != 9*time.Hour+30*time.Minute || windows["yesterday"] != 24*time.Hour || windows["last_1h"] != time.Hour || windows["last_24h"] != 24*time.Hour {
		t.Fatalf("resolved windows=%#v", windows)
	}
	for _, summary := range projection.OperationsSummaries {
		if summary.AlarmAccuracy != "exact" || summary.AlarmCount != 0 || summary.AlarmText != "0 条告警" || len(summary.Tasks) != 1 {
			t.Fatalf("summary=%#v", summary)
		}
	}
}

func TestOperationsSummaryPreservesLowerBound(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 17, 9, 30, 0, 0, time.Local)
	source := &fakeSource{
		snapshot: device.Snapshot{
			Identity: device.Identity{Serial: "SN-739184", Type: "edge"},
			Cameras:  []device.Camera{{ID: "camera-private", Name: "East Gate"}},
			Tasks: []device.Task{{
				ID: "task-private", ChannelID: "camera-private", AlgorithmID: "algorithm-private",
				DisplayName: "Helmet + East Gate", CameraName: "East Gate", AlgorithmName: "Helmet",
				Enabled: 1, Running: "unknown",
			}},
			ObservedAt: now.UTC(),
		},
		events: device.EventObservation{ByTask: map[string]device.TaskEventObservation{
			"task-private": {
				Count: 31, Accuracy: "lower_bound",
				Events: []device.Alarm{{OccurredAt: now.Add(-time.Minute).UTC().Format(time.RFC3339), CameraName: "East Gate", TaskName: "Helmet + East Gate", AlgorithmName: "Helmet"}},
			},
		}},
	}
	service := New(source)
	service.now = func() time.Time { return now }
	projection, _, err := service.Present(context.Background(), "inspect_alerts", "last_1h")
	if err != nil {
		t.Fatal(err)
	}
	summary := projection.OperationsSummaries[0]
	if summary.AlarmCount != 31 || summary.AlarmAccuracy != "lower_bound" || summary.AlarmText != "至少 31 条告警" || summary.Unknown != 1 || len(summary.RecentAlarms) != 1 {
		t.Fatalf("lower-bound summary=%#v", summary)
	}
}

type fakeSource struct {
	snapshot device.Snapshot
	events   device.EventObservation
	windows  []device.EventWindow
}

type notConnectedSource struct{}

func (notConnectedSource) Read(context.Context) (device.Snapshot, error) {
	return device.Snapshot{}, session.ErrNotConnected
}

func (notConnectedSource) ObserveEvents(context.Context, []device.Task, device.EventWindow) (device.EventObservation, error) {
	return device.EventObservation{}, session.ErrNotConnected
}

func (notConnectedSource) ConnectedIdentity() (string, string, bool) { return "", "", false }

func (f *fakeSource) Read(context.Context) (device.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeSource) ObserveEvents(_ context.Context, tasks []device.Task, window device.EventWindow) (device.EventObservation, error) {
	f.windows = append(f.windows, window)
	if f.events.ByTask != nil {
		return f.events, nil
	}
	byTask := map[string]device.TaskEventObservation{}
	for _, task := range tasks {
		byTask[task.ID] = device.TaskEventObservation{Accuracy: "exact", Complete: true, Events: []device.Alarm{}}
	}
	return device.EventObservation{ByTask: byTask}, nil
}

func (f *fakeSource) ConnectedIdentity() (string, string, bool) {
	return "***9184", f.snapshot.Identity.Type, true
}

func windowKey(window device.EventWindow, now time.Time) string {
	if window.End.Equal(now) && window.End.Sub(window.Start) == time.Hour {
		return "last_1h"
	}
	if window.End.Equal(now) && window.End.Sub(window.Start) == 24*time.Hour {
		return "last_24h"
	}
	if window.End.Equal(now) {
		return "today"
	}
	return "yesterday"
}
