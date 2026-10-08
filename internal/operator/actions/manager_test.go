package actions

import (
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
)

type fakeProvider struct {
	client *fakeActionClient
}

func (p fakeProvider) ActionConnection() (device.ActionConnection, error) {
	return device.ActionConnection{Client: p.client, Serial: p.client.serial, EndpointFingerprint: "endpoint-fingerprint"}, nil
}

type fakeActionClient struct {
	mu              sync.Mutex
	serial          string
	snapshot        device.Snapshot
	parameters      []device.ParameterField
	taskWrites      int
	parameterWrites int
	sourceWrites    int
	writeErr        error
	mutateOnError   bool
}

func newFakeActionClient() *fakeActionClient {
	task := device.Task{
		ID: "private-task-id", ChannelID: "private-camera-id", AlgorithmID: "private-algorithm-id",
		DisplayName: "Parity Algorithm + Parity Camera", CameraName: "Parity Camera", AlgorithmName: "Parity Algorithm",
		Enabled: 1, Running: "running", SwitchVerified: true,
	}
	return &fakeActionClient{
		serial: "PRIVATE-DEVICE-SERIAL-739184",
		snapshot: device.Snapshot{
			Identity: device.Identity{Serial: "PRIVATE-DEVICE-SERIAL-739184", Type: "edge"},
			Cameras:  []device.Camera{{ID: task.ChannelID, Name: task.CameraName}}, Tasks: []device.Task{task}, ObservedAt: time.Now().UTC(),
		},
		parameters: []device.ParameterField{{Key: "param.threshold", Value: "5"}},
	}
}

func (f *fakeActionClient) Login(context.Context) error { return nil }

func (f *fakeActionClient) Read(context.Context) (device.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	snapshot := f.snapshot
	snapshot.Tasks = append([]device.Task(nil), f.snapshot.Tasks...)
	snapshot.Cameras = append([]device.Camera(nil), f.snapshot.Cameras...)
	return snapshot, nil
}

func (f *fakeActionClient) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{ByTask: map[string]device.TaskEventObservation{}}
}

func (f *fakeActionClient) SwitchTask(_ context.Context, _ device.Task, target int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr == nil || f.mutateOnError {
		f.snapshot.Tasks[0].Enabled = target
		f.taskWrites++
	}
	return f.writeErr
}

func (f *fakeActionClient) ReadTaskParameters(context.Context, device.Task) ([]device.ParameterField, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]device.ParameterField(nil), f.parameters...), nil
}

func (f *fakeActionClient) UpdateTaskParameters(_ context.Context, _ device.Task, fields []device.ParameterField) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr == nil || f.mutateOnError {
		f.parameters = append([]device.ParameterField(nil), fields...)
		f.parameterWrites++
	}
	return f.writeErr
}

func (f *fakeActionClient) AddCameraSource(_ context.Context, name string, sourceURL []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr == nil || f.mutateOnError {
		f.snapshot.Cameras = append(f.snapshot.Cameras, device.Camera{
			ID: "private-created-camera-id", Name: name, SourceFingerprint: rawDigest(sourceURL),
		})
		f.sourceWrites++
	}
	return f.writeErr
}

type knownRejection struct{}

func (knownRejection) Error() string      { return "explicit rejection" }
func (knownRejection) KnownFailure() bool { return true }

func TestTaskSwitchConfirmationIsBrowserBoundAndDispatchesOnce(t *testing.T) {
	manager, store, client, path := newTestManager(t)
	snapshot, _ := client.Read(context.Background())
	proposal, err := manager.PrepareTaskSwitch(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if client.taskWrites != 0 {
		t.Fatal("prepare wrote to the device")
	}
	if _, err := manager.Confirm(context.Background(), "browser-b", proposal.ConfirmationToken); !errors.Is(err, ErrActionConflict) {
		t.Fatalf("cross-browser confirmation error = %v", err)
	}
	if client.taskWrites != 0 {
		t.Fatal("cross-browser confirmation wrote to the device")
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	status := waitForTerminal(t, manager, proposal.ActionID)
	if status.State != "completed" || status.Evidence != "sealed" || status.Dispatches != 1 || status.DeviceWrites != 1 || client.taskWrites != 1 {
		t.Fatalf("terminal status=%+v writes=%d", status, client.taskWrites)
	}
	for range 6 {
		manager.worker.Wake()
	}
	time.Sleep(40 * time.Millisecond)
	if client.taskWrites != 1 {
		t.Fatalf("terminal task replayed, writes=%d", client.taskWrites)
	}
	if _, err := manager.vault.get(proposal.ActionID); !errors.Is(err, ErrActionUnavailable) {
		t.Fatal("terminal task material was retained")
	}
	assertFilesExclude(t, path, proposal.ConfirmationToken, client.serial, "private-task-id", "private-camera-id", "private-algorithm-id")
	_ = store
}

func TestTaskSwitchRejectsUnverifiedCompatibleTaskID(t *testing.T) {
	manager, _, client, _ := newTestManager(t)
	snapshot, _ := client.Read(context.Background())
	task := snapshot.Tasks[0]
	task.SwitchVerified = false
	snapshot.Tasks[0] = task
	if _, err := manager.PrepareTaskSwitch(context.Background(), "browser-a", snapshot, task, 0); err == nil {
		t.Fatal("task switch accepted an ID without fresh QuerySwitch verification")
	}
	if client.taskWrites != 0 {
		t.Fatalf("unverified task binding wrote to device: %d", client.taskWrites)
	}
}

func TestAmbiguousTaskSwitchStaysUnknownEvenWhenTargetIsObserved(t *testing.T) {
	manager, _, client, _ := newTestManager(t)
	client.writeErr = errors.New("response lost")
	client.mutateOnError = true
	snapshot, _ := client.Read(context.Background())
	proposal, err := manager.PrepareTaskSwitch(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	status := waitForTerminal(t, manager, proposal.ActionID)
	if status.State != "unknown" || status.Evidence != "sealed" || status.DeviceWrites != 1 || client.taskWrites != 1 {
		t.Fatalf("ambiguous task status=%+v writes=%d", status, client.taskWrites)
	}
}

func TestParameterResponseLossCompletesFromFreshReadAndDoesNotPersistValues(t *testing.T) {
	manager, _, client, path := newTestManager(t)
	client.writeErr = errors.New("response lost")
	client.mutateOnError = true
	snapshot, _ := client.Read(context.Background())
	targetValue := "parameter-secret-739184"
	proposal, err := manager.PrepareTaskParameters(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], []device.ParameterField{{Key: "param.threshold", Value: targetValue}})
	if err != nil {
		t.Fatal(err)
	}
	if client.parameterWrites != 0 {
		t.Fatal("parameter prepare wrote to the device")
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	status := waitForTerminal(t, manager, proposal.ActionID)
	if status.State != "completed" || status.Evidence != "sealed" || status.DeviceWrites != 1 || client.parameterWrites != 1 {
		t.Fatalf("parameter status=%+v writes=%d", status, client.parameterWrites)
	}
	assertFilesExclude(t, path, targetValue, proposal.ConfirmationToken)
}

func TestKnownParameterRejectionRecordsDispatchButZeroWrites(t *testing.T) {
	manager, _, client, _ := newTestManager(t)
	client.writeErr = knownRejection{}
	snapshot, _ := client.Read(context.Background())
	proposal, err := manager.PrepareTaskParameters(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], []device.ParameterField{{Key: "param.threshold", Value: "17"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	status := waitForTerminal(t, manager, proposal.ActionID)
	if status.State != "blocked" || status.Evidence != "sealed" || status.Dispatches != 1 || status.DeviceWrites != 0 || client.parameterWrites != 0 {
		t.Fatalf("known rejection status=%+v writes=%d", status, client.parameterWrites)
	}
}

func TestCameraSourceResponseLossCompletesFromFreshCatalogAndClearsInput(t *testing.T) {
	manager, _, client, path := newTestManager(t)
	client.writeErr = errors.New("response lost")
	client.mutateOnError = true
	source := []byte("rtsp://private-user:private-password@10.42.0.9/live")
	secret := string(source)
	proposal, err := manager.PrepareCameraSource(context.Background(), "browser-a", "Parity Entrance", source)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range source {
		if value != 0 {
			t.Fatal("source input buffer was not cleared after preparation")
		}
	}
	if client.sourceWrites != 0 {
		t.Fatal("camera source prepare wrote to the device")
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	status := waitForTerminal(t, manager, proposal.ActionID)
	if status.State != "completed" || status.Evidence != "sealed" || status.DeviceWrites != 1 || client.sourceWrites != 1 {
		t.Fatalf("source status=%+v writes=%d", status, client.sourceWrites)
	}
	assertFilesExclude(t, path, secret, "private-user", "private-password", proposal.ConfirmationToken)
}

func TestCancelInvalidatesConfirmationWithoutDispatch(t *testing.T) {
	manager, _, client, _ := newTestManager(t)
	snapshot, _ := client.Read(context.Background())
	proposal, err := manager.PrepareTaskSwitch(context.Background(), "browser-a", snapshot, snapshot.Tasks[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Cancel(context.Background(), "browser-a", proposal.ActionID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Confirm(context.Background(), "browser-a", proposal.ConfirmationToken); !errors.Is(err, ErrActionConflict) {
		t.Fatalf("cancelled confirmation error=%v", err)
	}
	status, err := manager.Status(context.Background(), proposal.ActionID)
	if err != nil || status.State != "cancelled" || status.DeviceWrites != 0 || client.taskWrites != 0 {
		t.Fatalf("cancelled status=%+v err=%v writes=%d", status, err, client.taskWrites)
	}
}

func newTestManager(t *testing.T) (*Manager, *ledger.Store, *fakeActionClient, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "operator.db")
	store, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	client := newFakeActionClient()
	manager, err := New(store, fakeProvider{client: client})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		store.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		manager.Stop()
		_ = store.Close()
	})
	return manager, store, client, path
}

func waitForTerminal(t *testing.T, manager *Manager, id string) Status {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		status, err := manager.Status(context.Background(), id)
		if err == nil && (status.State == "completed" || status.State == "blocked" || status.State == "unknown") {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	status, err := manager.Status(context.Background(), id)
	t.Fatalf("action did not become terminal: status=%+v err=%v", status, err)
	return Status{}
}

func assertFilesExclude(t *testing.T, databasePath string, values ...string) {
	t.Helper()
	files, err := filepath.Glob(databasePath + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			if value != "" && strings.Contains(string(raw), value) {
				t.Fatalf("%s persisted protected value %q", filepath.Base(file), value)
			}
		}
	}
}
