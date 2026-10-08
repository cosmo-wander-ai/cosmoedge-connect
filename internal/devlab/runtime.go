package devlab

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

var (
	commitDigest = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	changeDigest = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

type Runtime struct {
	mu       sync.Mutex
	open     OpenLeaseFunc
	recorder Recorder
	now      func() time.Time
	run      *activeRun
}

type activeRun struct {
	info               RunInfo
	lease              Lease
	catalogFingerprint string
	tasks              map[string]device.Task
	cameras            map[string]device.Camera
	assertionFailed    bool
}

func NewRuntime(open OpenLeaseFunc, recorder Recorder) (*Runtime, error) {
	if open == nil || recorder == nil {
		return nil, errors.New("device lab lease opener and recorder are required")
	}
	return &Runtime{open: open, recorder: recorder, now: time.Now}, nil
}

func (r *Runtime) Begin(ctx context.Context, request BeginRequest) (RunInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run != nil {
		return RunInfo{}, errors.New("a device lab run is already active")
	}
	duration := time.Duration(request.DurationSeconds) * time.Second
	if duration <= 0 {
		duration = MaximumRunDuration
	}
	if duration > MaximumRunDuration {
		return RunInfo{}, errors.New("run duration exceeds the read lease budget")
	}
	request.Commit = strings.TrimSpace(request.Commit)
	request.ChangeDigest = strings.TrimSpace(request.ChangeDigest)
	if !validSourceMetadata(request.Commit, request.ChangeDigest) {
		return RunInfo{}, errors.New("run source metadata is invalid")
	}
	lease, initial, leaseInfo, err := r.open(ctx, duration)
	if err != nil {
		return RunInfo{}, err
	}
	runID, err := opaqueID("run")
	if err != nil {
		lease.Close()
		return RunInfo{}, err
	}
	run := &activeRun{lease: lease, tasks: map[string]device.Task{}, cameras: map[string]device.Camera{}}
	run.info = RunInfo{
		RunID: runID, Status: "active", Device: leaseInfo.Device, DeviceType: leaseInfo.DeviceType,
		OpenedAt: leaseInfo.OpenedAt, ExpiresAt: leaseInfo.ExpiresAt, ReadCount: 1, DeviceWrites: 0,
	}
	run.bindCatalog(initial)
	if err := r.recorder.StartRun(ctx, EvidenceRun{
		RunID: runID, Device: leaseInfo.Device, DeviceType: leaseInfo.DeviceType,
		Commit: request.Commit, ChangeDigest: request.ChangeDigest,
		OpenedAt: leaseInfo.OpenedAt, ExpiresAt: leaseInfo.ExpiresAt,
	}); err != nil {
		lease.Close()
		return RunInfo{}, err
	}
	r.run = run
	return run.info, nil
}

func (r *Runtime) Status() RunInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run == nil {
		return RunInfo{Status: "idle", DeviceWrites: 0}
	}
	return r.run.info
}

func (r *Runtime) Probe(ctx context.Context, request ProbeRequest) (ProbeResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run == nil {
		return ProbeResult{}, errors.New("no device lab run is active")
	}
	if !r.now().UTC().Before(r.run.info.ExpiresAt) {
		return ProbeResult{}, errors.New("device lab run has expired")
	}
	if err := validateProbe(request); err != nil {
		return ProbeResult{}, err
	}
	repeat := request.Repeat
	if repeat == 0 {
		repeat = 1
	}
	if r.run.info.ReadCount+repeat > MaximumReads {
		return ProbeResult{}, errors.New("probe exceeds the read budget")
	}
	interval := time.Duration(request.IntervalMS) * time.Millisecond
	probeID, err := opaqueID("probe")
	if err != nil {
		return ProbeResult{}, err
	}
	result := ProbeResult{
		RunID: r.run.info.RunID, ProbeID: probeID, Kind: request.Kind, Status: "observed",
		Samples: []map[string]any{}, Assertions: []AssertionResult{}, DeviceWrites: 0,
	}
	for index := 0; index < repeat; index++ {
		if index > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ProbeResult{}, ctx.Err()
			case <-timer.C:
			}
		}
		sample, err := r.sample(ctx, request)
		if err != nil {
			return ProbeResult{}, err
		}
		result.Samples = append(result.Samples, sample)
		r.run.info.ReadCount++
	}
	result.Assertions = EvaluateAssertions(result.Samples, request.Assertions)
	for _, assertion := range result.Assertions {
		if assertion.Status != "passed" {
			result.Status = "assertion_failed"
			r.run.assertionFailed = true
		}
	}
	r.run.info.ProbeCount++
	r.run.info.AssertionCount += len(result.Assertions)
	result.ReadCount = r.run.info.ReadCount
	result.RemainingReads = MaximumReads - result.ReadCount
	result.ObservedAt = r.now().UTC()
	publicJSON, err := json.Marshal(result)
	if err != nil {
		return ProbeResult{}, err
	}
	if err := r.recorder.RecordProbe(ctx, EvidenceProbe{
		RunID: result.RunID, ProbeID: result.ProbeID, Kind: result.Kind,
		HypothesisDigest: digestText(request.Hypothesis), PublicJSON: string(publicJSON),
		Assertions: result.Assertions, ObservedAt: result.ObservedAt,
		ReadCount: result.ReadCount, DeviceWrites: 0,
	}); err != nil {
		return ProbeResult{}, err
	}
	return result, nil
}

func (r *Runtime) Finish(ctx context.Context) (FinishResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run == nil {
		return FinishResult{}, errors.New("no device lab run is active")
	}
	run := r.run
	run.info.Status = "finished"
	finishedAt := r.now().UTC()
	result := "passed"
	if run.assertionFailed {
		result = "failed"
	}
	if err := r.recorder.FinishRun(ctx, run.info.RunID, result, finishedAt, run.info.ReadCount, run.info.ProbeCount, run.info.AssertionCount); err != nil {
		return FinishResult{}, err
	}
	err := run.lease.Close()
	r.run = nil
	return FinishResult{RunInfo: run.info, Result: result}, err
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.run == nil {
		return nil
	}
	err := r.run.lease.Close()
	r.run = nil
	return err
}

func (r *Runtime) sample(ctx context.Context, request ProbeRequest) (map[string]any, error) {
	if request.Kind == "event_window" {
		task, ok := r.run.tasks[request.Handle]
		if !ok {
			return nil, errors.New("task handle is unavailable or stale")
		}
		window, err := eventWindow(r.now().UTC(), request.Window)
		if err != nil {
			return nil, err
		}
		snapshot, observed, err := r.run.lease.ObserveTaskEvents(ctx, task, window)
		if err != nil {
			return nil, err
		}
		if structuralFingerprint(snapshot) != r.run.catalogFingerprint {
			r.run.bindCatalog(snapshot)
			return nil, errors.New("catalog changed; the supplied handle is stale")
		}
		return map[string]any{
			"observedAt": r.now().UTC(), "taskHandle": request.Handle, "count": observed.Count,
			"accuracy": observed.Accuracy, "complete": observed.Complete, "reason": observed.Reason,
		}, nil
	}
	snapshot, err := r.run.lease.Read(ctx)
	if err != nil {
		return nil, err
	}
	fingerprint := structuralFingerprint(snapshot)
	if fingerprint != r.run.catalogFingerprint {
		r.run.bindCatalog(snapshot)
		if request.Handle != "" {
			return nil, errors.New("catalog changed; the supplied handle is stale")
		}
	}
	switch request.Kind {
	case "identity":
		return map[string]any{"observedAt": snapshot.ObservedAt, "device": r.run.info.Device, "deviceType": r.run.info.DeviceType}, nil
	case "health":
		cpu := any("unknown")
		if snapshot.Health.CPUPercent != nil {
			cpu = *snapshot.Health.CPUPercent
		}
		return map[string]any{"observedAt": snapshot.Health.ObservedAt, "cpuPercent": cpu}, nil
	case "camera_catalog":
		return map[string]any{"observedAt": snapshot.ObservedAt, "catalogFingerprint": r.run.catalogFingerprint, "count": len(snapshot.Cameras), "cameras": r.cameraProjection(snapshot)}, nil
	case "task_catalog":
		return map[string]any{"observedAt": snapshot.ObservedAt, "catalogFingerprint": r.run.catalogFingerprint, "count": len(snapshot.Tasks), "tasks": r.taskProjection(snapshot)}, nil
	case "task_state":
		target, ok := r.run.tasks[request.Handle]
		if !ok {
			return nil, errors.New("task handle is unavailable or stale")
		}
		for _, task := range snapshot.Tasks {
			if sameTask(task, target) {
				return projectedTask(request.Handle, task), nil
			}
		}
		return nil, errors.New("task handle binding disappeared")
	case "snapshot":
		return map[string]any{
			"observedAt": snapshot.ObservedAt, "device": r.run.info.Device, "deviceType": r.run.info.DeviceType,
			"catalogFingerprint": r.run.catalogFingerprint, "cameraCount": len(snapshot.Cameras), "taskCount": len(snapshot.Tasks),
			"cameras": r.cameraProjection(snapshot), "tasks": r.taskProjection(snapshot),
		}, nil
	default:
		return nil, errors.New("unsupported probe kind")
	}
}

func (run *activeRun) bindCatalog(snapshot device.Snapshot) {
	run.catalogFingerprint = structuralFingerprint(snapshot)
	run.tasks = make(map[string]device.Task, len(snapshot.Tasks))
	run.cameras = make(map[string]device.Camera, len(snapshot.Cameras))
	prefix := run.info.RunID
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	for index, task := range snapshot.Tasks {
		run.tasks[fmt.Sprintf("task:%s:%d", prefix, index+1)] = task
	}
	for index, camera := range snapshot.Cameras {
		run.cameras[fmt.Sprintf("camera:%s:%d", prefix, index+1)] = camera
	}
}

func (r *Runtime) taskProjection(snapshot device.Snapshot) []any {
	byKey := make(map[string]string, len(r.run.tasks))
	for handle, task := range r.run.tasks {
		byKey[taskKey(task)] = handle
	}
	result := make([]any, 0, len(snapshot.Tasks))
	for _, task := range snapshot.Tasks {
		result = append(result, projectedTask(byKey[taskKey(task)], task))
	}
	return result
}

func (r *Runtime) cameraProjection(snapshot device.Snapshot) []any {
	byID := make(map[string]string, len(r.run.cameras))
	for handle, camera := range r.run.cameras {
		byID[camera.ID] = handle
	}
	result := make([]any, 0, len(snapshot.Cameras))
	for _, camera := range snapshot.Cameras {
		result = append(result, map[string]any{"handle": byID[camera.ID], "name": camera.Name})
	}
	return result
}

func projectedTask(handle string, task device.Task) map[string]any {
	return map[string]any{
		"handle": handle, "name": task.DisplayName, "camera": task.CameraName, "algorithm": task.AlgorithmName,
		"enabledState": enabledState(task.Enabled), "runtimeState": normalizedRuntime(task.Running),
	}
}

func structuralFingerprint(snapshot device.Snapshot) string {
	parts := make([]string, 0, len(snapshot.Cameras)+len(snapshot.Tasks))
	for _, camera := range snapshot.Cameras {
		parts = append(parts, "c\x00"+camera.ID+"\x00"+camera.Name)
	}
	for _, task := range snapshot.Tasks {
		parts = append(parts, "t\x00"+taskKey(task)+"\x00"+task.DisplayName)
	}
	sort.Strings(parts)
	return digestText(strings.Join(parts, "\x01"))
}

func validateProbe(request ProbeRequest) error {
	switch request.Kind {
	case "identity", "health", "camera_catalog", "task_catalog", "snapshot":
		if request.Handle != "" {
			return errors.New("probe kind does not accept a handle")
		}
	case "task_state", "event_window":
		if !strings.HasPrefix(request.Handle, "task:") {
			return errors.New("probe requires an opaque task handle")
		}
	default:
		return errors.New("unsupported probe kind")
	}
	repeat := request.Repeat
	if repeat == 0 {
		repeat = 1
	}
	if repeat < 1 || repeat > MaximumRepeat {
		return errors.New("probe repeat exceeds the sampling budget")
	}
	if repeat > 1 && time.Duration(request.IntervalMS)*time.Millisecond < MinimumInterval {
		return errors.New("probe interval is below the sampling budget")
	}
	if len(request.Hypothesis) > 4096 {
		return errors.New("probe hypothesis is too long")
	}
	return validateAssertions(request.Assertions)
}

func eventWindow(now time.Time, name string) (device.EventWindow, error) {
	switch name {
	case "last_1h":
		return device.EventWindow{Start: now.Add(-time.Hour), End: now}, nil
	case "last_24h", "":
		return device.EventWindow{Start: now.Add(-24 * time.Hour), End: now}, nil
	default:
		return device.EventWindow{}, errors.New("unsupported event window")
	}
}

func taskKey(task device.Task) string {
	return task.ID + "\x00" + task.ChannelID + "\x00" + task.AlgorithmID
}
func sameTask(left, right device.Task) bool { return taskKey(left) == taskKey(right) }

func enabledState(value int) string {
	if value == 0 {
		return "disabled"
	}
	if value == 1 {
		return "enabled"
	}
	return "unknown"
}

func normalizedRuntime(value string) string {
	if value == "running" || value == "stopped" {
		return value
	}
	return "unknown"
}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func opaqueID(prefix string) (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(raw), nil
}

func validSourceMetadata(commit, change string) bool {
	return (commit == "" || commitDigest.MatchString(commit)) && (change == "" || changeDigest.MatchString(change))
}
