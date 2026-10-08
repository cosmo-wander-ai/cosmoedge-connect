package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/kernel"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
)

type testProvider struct{ client *testClient }

func (p testProvider) ActionConnection() (device.ActionConnection, error) {
	return device.ActionConnection{Client: p.client, Serial: "test-device", EndpointFingerprint: "test-transport"}, nil
}

type testClient struct {
	mu                      sync.Mutex
	state                   State
	defaults                Configuration
	fingerprint             string
	writeErr                error
	deploymentReadErr       error
	mutateOnError           bool
	stalled                 bool
	writes, saves, switches int
	count                   uint64
	readCalls               int
}

func nativeConfig() Configuration {
	return Configuration{Ready: true, Shape: "native_task_config", Document: json.RawMessage(`{"scheduleId":"schedule-all-day","taskConfig":{"params":[{"key":"model.threshold","value":"CONFIDENTIAL-PARAMETER-0.7"}],"areas":[{"areaId":"area-1","points":[{"xRatio":0,"yRatio":0},{"xRatio":1,"yRatio":0},{"xRatio":1,"yRatio":1}]}]}}`)}
}

func (c *testClient) Login(context.Context) error { return nil }
func (c *testClient) Read(context.Context) (device.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCalls++
	snapshot := device.Snapshot{Identity: device.Identity{Serial: "test-device"}, Cameras: []device.Camera{{ID: "camera-a", Name: "入口", SourceFingerprint: c.fingerprint}}, ObservedAt: time.Now().UTC()}
	if c.state.Exists {
		snapshot.Tasks = []device.Task{taskFor(c.state)}
	}
	return snapshot, nil
}
func (*testClient) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{}
}
func (c *testClient) ReadAlgorithms(context.Context) ([]device.Algorithm, error) {
	return []device.Algorithm{{ID: "algorithm-a", Name: "已安装分析", Usage: "1"}}, nil
}
func (c *testClient) SwitchTask(_ context.Context, task device.Task, enabled int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.switches++
	if task.ID != c.state.TaskID || task.ChannelID != c.state.SourceID || task.AlgorithmID != c.state.AlgorithmID {
		return errors.New("wrong target")
	}
	if c.writeErr == nil || c.mutateOnError {
		c.state.Enabled = enabled
	}
	return c.writeErr
}
func (*testClient) ReadTaskParameters(context.Context, device.Task) ([]device.ParameterField, error) {
	return nil, errors.New("unused")
}
func (*testClient) UpdateTaskParameters(context.Context, device.Task, []device.ParameterField) error {
	return errors.New("unused")
}
func (*testClient) AddCameraSource(context.Context, string, []byte) error {
	return errors.New("unused")
}
func (c *testClient) ReadDeployment(_ context.Context, source, algorithm string) (State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deploymentReadErr != nil {
		return State{}, c.deploymentReadErr
	}
	if source != c.state.SourceID || algorithm != c.state.AlgorithmID {
		return State{}, errors.New("wrong target")
	}
	state := cloneState(c.state)
	state.ObservedAt = time.Now().UTC()
	return state, nil
}
func (c *testClient) DefaultDeployment(context.Context, string, string) (Configuration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneConfiguration(c.defaults), nil
}
func (c *testClient) SaveDeployment(_ context.Context, target Target) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.saves++
	if target.SourceID != c.state.SourceID || target.AlgorithmID != c.state.AlgorithmID {
		return errors.New("wrong target")
	}
	if c.writeErr == nil || c.mutateOnError {
		c.state.Exists, c.state.Enabled, c.state.TaskID, c.state.Configuration = true, 1, "camera-a_algorithm-a", cloneConfiguration(target.Configuration)
	}
	return c.writeErr
}
func (c *testClient) ReadDeploymentRuntime(_ context.Context, task device.Task) (Runtime, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stalled && c.state.Enabled == 1 {
		c.count++
	}
	return Runtime{TaskID: task.ID, Known: true, Active: c.state.Enabled == 1, Stopped: c.state.Enabled == 0, Counters: map[string]uint64{"decode": c.count, "inference": c.count}, ObservedAt: time.Now().UTC()}, nil
}

type harness struct {
	service *Service
	store   *ledger.Store
	client  *testClient
	worker  *kernel.Kernel
	dbPath  string
}

func newHarness(t *testing.T, existing bool) *harness {
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
	client := &testClient{state: State{SourceID: "camera-a", AlgorithmID: "algorithm-a", Exists: existing, Enabled: 0, ObservedAt: time.Now().UTC()}, defaults: nativeConfig(), fingerprint: "source-a"}
	if existing {
		client.state.TaskID, client.state.Configuration = "camera-a_algorithm-a", nativeConfig()
	}
	service, err := New(store, testProvider{client})
	if err != nil {
		t.Fatal(err)
	}
	service.verifyDuration, service.verifyInterval = 30*time.Millisecond, time.Millisecond
	worker, err := kernel.New(store, map[string]kernel.Handler{Kind: service})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := &harness{service: service, store: store, client: client, worker: worker, dbPath: path}
	t.Cleanup(func() { worker.Stop(); service.Close(); _ = store.Close() })
	return h
}

func request(enabled bool) Request {
	return Request{RequestID: "request-one", SourceID: "camera-a", AlgorithmID: "algorithm-a", Enabled: enabled}
}

func confirmAndWait(t *testing.T, h *harness, proposal Proposal) ledger.Record {
	t.Helper()
	if err := h.service.Confirm(context.Background(), "session-a", proposal.ActionRef, proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	h.worker.Wake()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, err := h.store.Inspect(context.Background(), proposal.ActionRef)
		if err != nil {
			t.Fatal(err)
		}
		if record.State == "completed" || record.State == "unknown" || record.State == "blocked" {
			return record
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("deployment did not reach a terminal ledger state")
	return ledger.Record{}
}

func TestNewBindingUsesOneSaveAndVerifiesProcessing(t *testing.T) {
	h := newHarness(t, false)
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	if proposal.State != "proposed" || proposal.ExistingBinding || proposal.ConfirmationToken == "" {
		t.Fatalf("proposal=%+v", proposal)
	}
	record := confirmAndWait(t, h, proposal)
	if record.State != "completed" || record.DeviceWrites != 1 || record.Dispatches != 1 || record.Reason != "deployment_processing_verified" {
		t.Fatalf("record=%+v", record)
	}
	if h.client.saves != 1 || h.client.switches != 0 {
		t.Fatalf("save=%d switch=%d; save already enables", h.client.saves, h.client.switches)
	}
	status, err := h.service.GetByRequest(context.Background(), "session-a", "request-one")
	if err != nil || status.Current == nil || status.Current.Runtime != "processing" || !status.Current.ConfigurationMatch || len(status.Current.Progress) != 2 {
		t.Fatalf("current=%+v error=%v", status, err)
	}
	assertNotDurable(t, h.dbPath, proposal.ConfirmationToken, "CONFIDENTIAL-PARAMETER-0.7")
}

func TestExistingBindingSwitchAndStopPreserveNativeConfig(t *testing.T) {
	h := newHarness(t, true)
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	if record := confirmAndWait(t, h, proposal); record.State != "completed" {
		t.Fatalf("enable=%+v", record)
	}
	stop := request(false)
	stop.RequestID = "request-stop"
	proposal, err = h.service.Prepare(context.Background(), "session-a", stop)
	if err != nil {
		t.Fatal(err)
	}
	if record := confirmAndWait(t, h, proposal); record.State != "completed" || record.Reason != "deployment_stopped_verified" {
		t.Fatalf("stop=%+v", record)
	}
	if h.client.saves != 0 || h.client.switches != 2 || string(h.client.state.Configuration.Document) != string(nativeConfig().Document) {
		t.Fatal("switch/stop altered the original native configuration")
	}
}

func TestDuplicateRequestAndConfirmationNeverDispatchAgain(t *testing.T) {
	h := newHarness(t, true)
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil || duplicate.ActionRef != proposal.ActionRef || duplicate.ConfirmationToken != proposal.ConfirmationToken {
		t.Fatalf("duplicate=%+v error=%v", duplicate, err)
	}
	recovered, err := h.service.GetByRequest(context.Background(), "session-a", "request-one")
	if err != nil || recovered.Target.ConfirmationToken != proposal.ConfirmationToken || recovered.State != "proposed" {
		t.Fatalf("lost-response recovery=%+v error=%v", recovered, err)
	}
	confirmAndWait(t, h, proposal)
	if err := h.service.Confirm(context.Background(), "session-a", proposal.ActionRef, proposal.ConfirmationToken); err != nil {
		t.Fatal(err)
	}
	duplicate, err = h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil || duplicate.ActionRef != proposal.ActionRef || duplicate.State != "completed" || duplicate.ConfirmationToken != "" || h.client.writes != 1 {
		t.Fatalf("repeat=%+v writes=%d error=%v", duplicate, h.client.writes, err)
	}
	// A new phrase/request for the already enabled binding verifies current
	// processing but does not create another binding or issue another switch.
	again := request(true)
	again.RequestID = "different-phrase"
	proposal, err = h.service.Prepare(context.Background(), "session-a", again)
	if err != nil {
		t.Fatal(err)
	}
	if record := confirmAndWait(t, h, proposal); record.DeviceWrites != 0 || record.State != "completed" || h.client.writes != 1 {
		t.Fatalf("already-enabled=%+v writes=%d", record, h.client.writes)
	}
}

func TestSessionOwnershipAndRequestTargetConflict(t *testing.T) {
	h := newHarness(t, true)
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.service.Confirm(context.Background(), "session-b", proposal.ActionRef, proposal.ConfirmationToken); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-session confirmation=%v", err)
	}
	if _, err := h.service.Status(context.Background(), "session-b", proposal.ActionRef); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-session status=%v", err)
	}
	if _, err := h.service.GetByRequest(context.Background(), "session-b", "request-one"); !errors.Is(err, ledger.ErrNotFound) {
		t.Fatalf("cross-session request lookup=%v", err)
	}
	if _, err := h.service.Prepare(context.Background(), "session-a", request(false)); !errors.Is(err, ErrConflict) {
		t.Fatalf("request ID target reuse=%v", err)
	}
	if h.client.writes != 0 {
		t.Fatal("ownership validation wrote the device")
	}
}

func TestMissingROIRequiresInputWithoutDurableAction(t *testing.T) {
	h := newHarness(t, false)
	h.client.defaults.Ready, h.client.defaults.Missing = false, []string{"检测区域或检测线"}
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil || proposal.State != "needs_input" || proposal.ActionRef != "" || proposal.ConfirmationToken != "" || len(proposal.Missing) == 0 {
		t.Fatalf("proposal=%+v error=%v", proposal, err)
	}
	if _, err := h.service.GetByRequest(context.Background(), "session-a", "request-one"); !errors.Is(err, ledger.ErrNotFound) {
		t.Fatalf("unprepared action was durably queued: %v", err)
	}
}

func TestEnabledWithoutProcessingRemainsUnknown(t *testing.T) {
	h := newHarness(t, true)
	h.client.stalled = true
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	record := confirmAndWait(t, h, proposal)
	if record.State != "unknown" || record.Reason != "deployment_not_fully_verified" || h.client.writes != 1 {
		t.Fatalf("stalled=%+v", record)
	}
}

func TestAmbiguousWriteNeverBecomesCompletedOrReplays(t *testing.T) {
	h := newHarness(t, true)
	// This assertion needs two fresh runtime samples. A 1 ms fixture interval
	// gives Status only 2 ms, making scheduler timing part of the contract.
	h.service.verifyInterval, h.service.verifyDuration = 25*time.Millisecond, 100*time.Millisecond
	h.client.writeErr, h.client.mutateOnError = errors.New("lost response"), true
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	record := confirmAndWait(t, h, proposal)
	if record.State != "unknown" || record.Reason != "ambiguous_dispatch_no_replay" {
		t.Fatalf("ambiguous=%+v", record)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		status, err := h.service.GetByRequest(ctx, "session-a", "request-one")
		if err != nil || status.State != "unknown" || status.Class != "unknown" ||
			status.Reason != "ambiguous_dispatch_no_replay" || status.Dispatches != 1 ||
			status.DeviceWrites != 1 || h.client.writes != 1 {
			t.Fatalf("continued lookup=%+v current=%+v error=%v", status, status.Current, err)
		}
		if status.Current != nil && status.Current.Runtime == "processing" {
			break
		}
		// A bounded current read may lack its second sample under scheduling
		// pressure. Continue only this same read; never confirm or submit again.
		if status.Current == nil || status.Current.Runtime != "processing_unconfirmed" || ctx.Err() != nil {
			t.Fatalf("fresh processing was not observed: current=%+v error=%v", status.Current, ctx.Err())
		}
	}
}

func TestSourceChangeAfterProposalPreventsDispatch(t *testing.T) {
	h := newHarness(t, true)
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	h.client.fingerprint = "changed-video"
	record := confirmAndWait(t, h, proposal)
	if record.State != "blocked" || record.Dispatches != 0 || h.client.writes != 0 {
		t.Fatalf("source drift=%+v", record)
	}
}

func TestRestartKeepsRequestLookupAndNeverRestoresWriteAuthority(t *testing.T) {
	h := newHarness(t, true)
	proposal, err := h.service.Prepare(context.Background(), "session-a", request(true))
	if err != nil {
		t.Fatal(err)
	}
	h.worker.Stop()
	h.service.Close()
	if err := h.store.RecoverInterrupted(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(h.store, testProvider{h.client})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	status, err := restarted.GetByRequest(context.Background(), "session-a", "request-one")
	if err != nil || status.State != "blocked" || status.Reason != "foreground_authority_lost_before_dispatch" {
		t.Fatalf("restart lookup=%+v error=%v", status, err)
	}
	if err := restarted.Confirm(context.Background(), "session-a", proposal.ActionRef, proposal.ConfirmationToken); !errors.Is(err, ErrConflict) {
		t.Fatalf("restart reused authority: %v", err)
	}
	duplicate, err := restarted.Prepare(context.Background(), "session-a", request(true))
	if err != nil || duplicate.State != "blocked" || duplicate.ConfirmationToken != "" || h.client.writes != 0 {
		t.Fatalf("restart duplicate=%+v error=%v", duplicate, err)
	}
}

func assertNotDurable(t *testing.T, path string, protected ...string) {
	t.Helper()
	files, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range protected {
			if strings.Contains(string(raw), value) {
				t.Fatalf("protected deployment material persisted in %s", filepath.Base(file))
			}
		}
	}
}

func TestStopWriteAccountingDistinguishesRequiredSwitchNoopAndRejectedRequest(t *testing.T) {
	for _, tc := range []struct {
		name             string
		before           int
		writeErr         error
		outcome, state   string
		accounted, calls int
	}{
		{"required switch", 1, nil, "accepted", "completed", 1, 1},
		{"already stopped", 0, nil, "accepted", "completed", 0, 0},
		{"native rejected switch", 1, nativeRejectedError{}, "known_failed", "blocked", 0, 1},
		{"uncertain switch", 1, errors.New("transport outcome unknown"), "outcome_unknown", "unknown", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, true)
			h.client.state.Enabled, h.client.writeErr = tc.before, tc.writeErr
			proposal, err := h.service.Prepare(context.Background(), "session-a", request(false))
			if err != nil {
				t.Fatal(err)
			}
			record := confirmAndWait(t, h, proposal)
			if record.State != tc.state || record.Dispatches != 1 || record.DeviceWrites != tc.accounted || record.DispatchOutcome != tc.outcome {
				t.Fatalf("ledger accounting=%+v", record)
			}
			status, err := h.service.Status(context.Background(), "session-a", proposal.ActionRef)
			if err != nil || status.DispatchOutcome != tc.outcome || status.DeviceWrites != tc.accounted || status.State != tc.state {
				t.Fatalf("status=%+v error=%v", status, err)
			}
			_, err = h.service.GetByRequest(context.Background(), "session-a", "request-one")
			if err != nil {
				t.Fatal(err)
			}
			h.client.mu.Lock()
			defer h.client.mu.Unlock()
			if h.client.switches != tc.calls || h.client.writes != tc.calls || h.client.saves != 0 {
				t.Fatalf("actual calls: switches=%d writes=%d saves=%d", h.client.switches, h.client.writes, h.client.saves)
			}
		})
	}
}
