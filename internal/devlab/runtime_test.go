package devlab

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

type fakeLease struct {
	mu          sync.Mutex
	snapshot    device.Snapshot
	readCalls   int
	activeReads atomic.Int32
	concurrent  atomic.Bool
	closed      bool
}

func (f *fakeLease) Read(context.Context) (device.Snapshot, error) {
	if f.activeReads.Add(1) != 1 {
		f.concurrent.Store(true)
	}
	defer f.activeReads.Add(-1)
	time.Sleep(time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return device.Snapshot{}, errors.New("closed")
	}
	f.readCalls++
	result := f.snapshot
	result.ObservedAt = time.Now().UTC()
	return result, nil
}

func (f *fakeLease) ObserveTaskEvents(context.Context, device.Task, device.EventWindow) (device.Snapshot, device.TaskEventObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readCalls++
	return f.snapshot, device.TaskEventObservation{Count: 2, Accuracy: "exact", Complete: true}, nil
}

func (f *fakeLease) Close() error { f.mu.Lock(); defer f.mu.Unlock(); f.closed = true; return nil }

type memoryRecorder struct{ runs, probes, finishes int }

func (m *memoryRecorder) StartRun(context.Context, EvidenceRun) error      { m.runs++; return nil }
func (m *memoryRecorder) RecordProbe(context.Context, EvidenceProbe) error { m.probes++; return nil }
func (m *memoryRecorder) FinishRun(context.Context, string, string, time.Time, int, int, int) error {
	m.finishes++
	return nil
}

func TestRuntimeUsesOneLeaseAndSerializesDynamicProbes(t *testing.T) {
	lease := &fakeLease{snapshot: fixtureSnapshot(1, "running")}
	opened := 0
	opener := func(context.Context, time.Duration) (Lease, device.Snapshot, devauthority.ReadLeaseInfo, error) {
		opened++
		now := time.Now().UTC()
		return lease, lease.snapshot, devauthority.ReadLeaseInfo{Device: "***0002", DeviceType: "fixture", OpenedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
	}
	recorder := &memoryRecorder{}
	runtime, err := NewRuntime(opener, recorder)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runtime.Begin(context.Background(), BeginRequest{DurationSeconds: 60, Commit: "abc1234"})
	if err != nil {
		t.Fatal(err)
	}
	if opened != 1 || run.ReadCount != 1 || run.DeviceWrites != 0 {
		t.Fatalf("opened=%d run=%#v", opened, run)
	}

	request := ProbeRequest{Kind: "task_catalog", Assertions: []AssertionSpec{{Kind: "equals", Path: "count", Expected: 1.0}}}
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := runtime.Probe(context.Background(), request); results <- err }()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if lease.concurrent.Load() {
		t.Fatal("device reads overlapped")
	}
	if opened != 1 || recorder.probes != 2 {
		t.Fatalf("opened=%d probes=%d", opened, recorder.probes)
	}
	status := runtime.Status()
	if status.ReadCount != 3 || status.DeviceWrites != 0 {
		t.Fatalf("status=%#v", status)
	}
	if _, err := runtime.Finish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if recorder.finishes != 1 || !lease.closed {
		t.Fatal("run did not close its lease and evidence")
	}
}

func TestRuntimeInvalidatesHandleOnlyOnStructuralDrift(t *testing.T) {
	lease := &fakeLease{snapshot: fixtureSnapshot(1, "running")}
	runtime, _ := NewRuntime(func(context.Context, time.Duration) (Lease, device.Snapshot, devauthority.ReadLeaseInfo, error) {
		now := time.Now().UTC()
		return lease, lease.snapshot, devauthority.ReadLeaseInfo{Device: "***0002", DeviceType: "fixture", OpenedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
	}, &memoryRecorder{})
	if _, err := runtime.Begin(context.Background(), BeginRequest{DurationSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	catalog, err := runtime.Probe(context.Background(), ProbeRequest{Kind: "task_catalog"})
	if err != nil {
		t.Fatal(err)
	}
	handle := catalog.Samples[0]["tasks"].([]any)[0].(map[string]any)["handle"].(string)

	lease.mu.Lock()
	lease.snapshot.Tasks[0].Enabled = 0
	lease.snapshot.Tasks[0].Running = "stopped"
	lease.mu.Unlock()
	state, err := runtime.Probe(context.Background(), ProbeRequest{Kind: "task_state", Handle: handle})
	if err != nil {
		t.Fatalf("dynamic state invalidated handle: %v", err)
	}
	if state.Samples[0]["enabledState"] != "disabled" {
		t.Fatalf("state=%#v", state)
	}

	lease.mu.Lock()
	lease.snapshot.Tasks[0].ID = "different-private-id"
	lease.mu.Unlock()
	if _, err := runtime.Probe(context.Background(), ProbeRequest{Kind: "task_state", Handle: handle}); err == nil {
		t.Fatal("structural drift retained an old handle")
	}
}

func TestProbeAndOracleBudgetsFailClosed(t *testing.T) {
	if err := validateProbe(ProbeRequest{Kind: "snapshot", Repeat: MaximumRepeat + 1, IntervalMS: 250}); err == nil {
		t.Fatal("repeat budget accepted")
	}
	if err := validateProbe(ProbeRequest{Kind: "snapshot", Repeat: 2, IntervalMS: 249}); err == nil {
		t.Fatal("interval budget accepted")
	}
	results := EvaluateAssertions([]map[string]any{{"state": "unknown", "count": 1.0}, {"state": "running", "count": 2.0}}, []AssertionSpec{
		{Kind: "known", Path: "state"}, {Kind: "stable", Path: "count"},
	})
	if results[0].Status != "failed" || results[1].Status != "failed" {
		t.Fatalf("results=%#v", results)
	}
}

func TestRuntimeFinishIsOwnedByOracleFailures(t *testing.T) {
	lease := &fakeLease{snapshot: fixtureSnapshot(1, "unknown")}
	runtime, _ := NewRuntime(func(context.Context, time.Duration) (Lease, device.Snapshot, devauthority.ReadLeaseInfo, error) {
		now := time.Now().UTC()
		return lease, lease.snapshot, devauthority.ReadLeaseInfo{Device: "***0002", DeviceType: "fixture", OpenedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
	}, &memoryRecorder{})
	if _, err := runtime.Begin(context.Background(), BeginRequest{DurationSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	probe, err := runtime.Probe(context.Background(), ProbeRequest{Kind: "task_catalog", Assertions: []AssertionSpec{{Kind: "known", Path: "tasks.0.runtimeState"}}})
	if err != nil {
		t.Fatal(err)
	}
	if probe.Status != "assertion_failed" {
		t.Fatalf("probe=%#v", probe)
	}
	finished, err := runtime.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if finished.Result != "failed" {
		t.Fatalf("finish=%#v", finished)
	}
}

func TestStructuralFingerprintExcludesDynamicState(t *testing.T) {
	first := fixtureSnapshot(1, "running")
	second := fixtureSnapshot(0, "stopped")
	if structuralFingerprint(first) != structuralFingerprint(second) {
		t.Fatal("dynamic task state changed the structural fingerprint")
	}
}

func fixtureSnapshot(enabled int, running string) device.Snapshot {
	now := time.Now().UTC()
	cpu := 12.5
	return device.Snapshot{
		Identity: device.Identity{Serial: "PRIVATE-SERIAL", Type: "fixture"},
		Health:   device.Health{CPUPercent: &cpu, ObservedAt: now}, ObservedAt: now,
		Cameras: []device.Camera{{ID: "camera-private-id", Name: "Front Door"}},
		Tasks:   []device.Task{{ID: "task-private-id", ChannelID: "camera-private-id", AlgorithmID: "algo-private-id", DisplayName: "Person + Front Door", CameraName: "Front Door", AlgorithmName: "Person", Enabled: enabled, Running: running}},
	}
}
