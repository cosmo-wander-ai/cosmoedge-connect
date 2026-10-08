// Package parity provides implementation-independent fixtures and result
// normalization for old/new ordinary Operator comparison.
package parity

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const StandardDevicePort = 8000

type FaultMode string

const (
	FaultNone            FaultMode = ""
	FaultReject          FaultMode = "reject"
	FaultMalformed       FaultMode = "malformed"
	FaultCloseBefore     FaultMode = "close_before"
	FaultCloseAfterWrite FaultMode = "close_after_write"
)

type Source struct {
	ID   string
	Name string
	URL  string
}

type FixtureEvent struct {
	ID             string
	AlgorithmCode  string
	AlgorithmName  string
	VideoChannelID string
	ChannelName    string
	Timestamp      int64
}

type FixtureSnapshot struct {
	Requests        map[string]int
	Logins          int
	Identities      int
	TaskEnabled     int
	TaskWrites      int
	ParameterValue  string
	ParameterWrites int
	Sources         []Source
	SourceWrites    int
	EventCount      int
}

type DeviceFixture struct {
	mu sync.Mutex

	username            string
	passwordDigest      string
	fullSN              string
	taskEnabled         int
	taskDriftAfterWrite *int
	parameterValue      string
	sources             []Source
	events              []FixtureEvent
	faults              map[string]FaultMode
	nextFaults          map[string]scheduledFault
	nextMutations       map[string]scheduledMutation
	redirects           map[string]string
	requests            map[string]int
	logins              int
	identities          int
	taskWrites          int
	parameterWrites     int
	sourceWrites        int
}

type scheduledFault struct {
	request int
	mode    FaultMode
}

type scheduledMutation struct {
	request        int
	taskEnabled    *int
	parameterValue *string
	clearSources   bool
}

func NewDeviceFixture(username, password, fullSN string) *DeviceFixture {
	digest := fmt.Sprintf("%X", md5.Sum([]byte(password)))
	return &DeviceFixture{
		username: username, passwordDigest: digest, fullSN: fullSN,
		taskEnabled: 1, parameterValue: "5",
		faults: make(map[string]FaultMode), nextFaults: make(map[string]scheduledFault), nextMutations: make(map[string]scheduledMutation), redirects: make(map[string]string), requests: make(map[string]int),
	}
}

func (f *DeviceFixture) SetFault(path string, mode FaultMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if mode == FaultNone {
		delete(f.faults, path)
		return
	}
	f.faults[path] = mode
}

func (f *DeviceFixture) SetFaultOnNext(path string, mode FaultMode) {
	f.SetFaultAfter(path, 1, mode)
}

func (f *DeviceFixture) SetFaultAfter(path string, requestOffset int, mode FaultMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if mode == FaultNone {
		delete(f.nextFaults, path)
		return
	}
	if requestOffset < 1 {
		requestOffset = 1
	}
	f.nextFaults[path] = scheduledFault{request: f.requests[path] + requestOffset, mode: mode}
}

func (f *DeviceFixture) SetTaskEnabledAfter(path string, requestOffset, enabled int) {
	f.scheduleMutation(path, requestOffset, scheduledMutation{taskEnabled: &enabled})
}

func (f *DeviceFixture) SetParameterValueAfter(path string, requestOffset int, value string) {
	f.scheduleMutation(path, requestOffset, scheduledMutation{parameterValue: &value})
}

func (f *DeviceFixture) ClearSourcesAfter(path string, requestOffset int) {
	f.scheduleMutation(path, requestOffset, scheduledMutation{clearSources: true})
}

func (f *DeviceFixture) scheduleMutation(path string, requestOffset int, mutation scheduledMutation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if requestOffset < 1 {
		requestOffset = 1
	}
	mutation.request = f.requests[path] + requestOffset
	f.nextMutations[path] = mutation
}

func (f *DeviceFixture) SetRedirect(path, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.TrimSpace(target) == "" {
		delete(f.redirects, path)
		return
	}
	f.redirects[path] = target
}

func (f *DeviceFixture) SetFullSN(fullSN string) {
	f.mu.Lock()
	f.fullSN = fullSN
	f.mu.Unlock()
}

func (f *DeviceFixture) SetTaskEnabled(enabled int) {
	f.mu.Lock()
	f.taskEnabled = enabled
	f.mu.Unlock()
}

func (f *DeviceFixture) SetTaskEnabledAfterWrite(enabled int) {
	f.mu.Lock()
	f.taskDriftAfterWrite = &enabled
	f.mu.Unlock()
}

func (f *DeviceFixture) InjectSource(source Source) {
	f.mu.Lock()
	f.sources = append(f.sources, source)
	f.mu.Unlock()
}

func (f *DeviceFixture) SetEvents(events ...FixtureEvent) {
	f.mu.Lock()
	f.events = append([]FixtureEvent(nil), events...)
	f.mu.Unlock()
}

func (f *DeviceFixture) Snapshot() FixtureSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := make(map[string]int, len(f.requests))
	for path, count := range f.requests {
		requests[path] = count
	}
	sources := append([]Source(nil), f.sources...)
	return FixtureSnapshot{
		Requests: requests, Logins: f.logins, Identities: f.identities,
		TaskEnabled: f.taskEnabled, TaskWrites: f.taskWrites,
		ParameterValue: f.parameterValue, ParameterWrites: f.parameterWrites,
		Sources: sources, SourceWrites: f.sourceWrites, EventCount: len(f.events),
	}
}

func (f *DeviceFixture) Start() (string, func() error, error) {
	addresses, err := privateIPv4Candidates()
	if err != nil {
		return "", nil, err
	}
	var listener net.Listener
	var listenErrors []error
	for _, ip := range addresses {
		listener, err = net.Listen("tcp4", net.JoinHostPort(ip.String(), fmt.Sprint(StandardDevicePort)))
		if err == nil {
			break
		}
		listenErrors = append(listenErrors, fmt.Errorf("%s: %w", ip, err))
	}
	if listener == nil {
		return "", nil, fmt.Errorf("listen on a private standard device port: %w", errors.Join(listenErrors...))
	}
	stop := serveFixture(listener, http.HandlerFunc(f.handle))
	return "http://" + listener.Addr().String(), stop, nil
}

func serveFixture(listener net.Listener, handler http.Handler) func() error {
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	var once sync.Once
	var stopErr error
	return func() error {
		once.Do(func() {
			// Close may run before Serve has registered this listener. Close
			// the owned listener directly as well, then join the Serve goroutine.
			for _, err := range []error{server.Close(), listener.Close()} {
				if err != nil && !errors.Is(err, net.ErrClosed) {
					stopErr = errors.Join(stopErr, err)
				}
			}
			<-done
		})
		return stopErr
	}
}

func privateIPv4Candidates() ([]net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate network interfaces: %w", err)
	}
	var candidates []net.IP
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil || !ip.IsPrivate() || ip.IsLoopback() {
				continue
			}
			candidates = append(candidates, ip.To4())
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("no private non-loopback IPv4 is available for the parity fixture")
	}
	return candidates, nil
}

func (f *DeviceFixture) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	if body == nil {
		body = map[string]any{}
	}

	f.mu.Lock()
	f.requests[r.URL.Path]++
	fault := f.faults[r.URL.Path]
	if scheduled, ok := f.nextFaults[r.URL.Path]; ok && scheduled.request == f.requests[r.URL.Path] {
		fault = scheduled.mode
		delete(f.nextFaults, r.URL.Path)
	}
	if mutation, ok := f.nextMutations[r.URL.Path]; ok && mutation.request == f.requests[r.URL.Path] {
		if mutation.taskEnabled != nil {
			f.taskEnabled = *mutation.taskEnabled
		}
		if mutation.parameterValue != nil {
			f.parameterValue = *mutation.parameterValue
		}
		if mutation.clearSources {
			f.sources = nil
		}
		delete(f.nextMutations, r.URL.Path)
	}
	redirect := f.redirects[r.URL.Path]
	f.mu.Unlock()
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
		return
	}

	switch fault {
	case FaultReject:
		f.fail(w, "fixture rejected request")
		return
	case FaultMalformed:
		_, _ = io.WriteString(w, "{")
		return
	case FaultCloseBefore:
		closeConnection(w)
		return
	}

	if r.URL.Path != "/gtw/cwai/login/DoLogin" && r.Header.Get("mtk") != "parity-session-token" {
		f.fail(w, "not authenticated")
		return
	}

	switch r.URL.Path {
	case "/gtw/cwai/login/DoLogin":
		f.mu.Lock()
		f.logins++
		valid := body["account"] == f.username && body["pwd"] == f.passwordDigest
		f.mu.Unlock()
		if !valid {
			f.fail(w, "invalid credential")
			return
		}
		f.ok(w, map[string]any{"mtk": "parity-session-token"})
	case "/gtw/cwai/System/QueryDeviceInfo":
		f.mu.Lock()
		f.identities++
		fullSN := f.fullSN
		f.mu.Unlock()
		f.ok(w, map[string]any{"devInfoList": []any{
			map[string]any{"key": "deviceSn", "value": fullSN},
			map[string]any{"key": "deviceType", "value": "parity-edge-gateway"},
		}})
	case "/gtw/cwai/System/QueryHardwareResource":
		f.ok(w, map[string]any{"itemList": []any{map[string]any{"key": "cpuUtilization", "usedPercent": 12.0}}, "customScore": 98.0})
	case "/gtw/cwai/Camera/Page":
		f.mu.Lock()
		taskEnabled := f.taskEnabled
		sources := append([]Source(nil), f.sources...)
		f.mu.Unlock()
		rows := []any{map[string]any{
			"videoChannelId": "parity-camera-internal", "channelName": "Parity Camera", "channelType": 0.0,
			"url": "rtsp://redacted.invalid/existing",
			"taskList": []any{map[string]any{
				"id": "parity-task-internal", "algorithmId": "parity-algorithm-internal",
				"algorithmName": "Parity Algorithm", "enableStatus": float64(taskEnabled),
				"status": 1.0, "scheduleId": "always",
			}},
		}}
		for _, source := range sources {
			rows = append(rows, map[string]any{
				"videoChannelId": source.ID, "channelName": source.Name,
				"channelType": 0.0, "url": source.URL, "taskList": []any{},
			})
		}
		f.ok(w, map[string]any{"rows": rows, "total": len(rows)})
	case "/gtw/cwai/Camera/Add":
		name, nameOK := body["channelName"].(string)
		sourceURL, sourceOK := body["url"].(string)
		channelType, typeOK := numberAsInt(body["channelType"])
		if !nameOK || strings.TrimSpace(name) == "" || !sourceOK || !strings.HasPrefix(strings.ToLower(sourceURL), "rtsp") || !typeOK || channelType != 0 {
			f.fail(w, "invalid camera source")
			return
		}
		f.mu.Lock()
		f.sourceWrites++
		f.sources = append(f.sources, Source{ID: fmt.Sprintf("parity-source-%d", f.sourceWrites), Name: name, URL: sourceURL})
		f.mu.Unlock()
		if fault == FaultCloseAfterWrite {
			closeConnection(w)
			return
		}
		f.ok(w, map[string]any{"created": true})
	case "/gtw/cwai/Algorithm/Page":
		f.ok(w, map[string]any{"rows": []any{map[string]any{
			"algorithmId": "parity-algorithm-internal", "algorithmName": "Parity Algorithm",
			"algorithmUsage": "video", "algorithmCategory": "safety", "categoryName": "Safety",
			"supplier": "Parity", "models": []any{map[string]any{"modelCode": "parity-model-internal"}},
		}}, "total": 1})
	case "/gtw/cwai/atomic/Model/Page":
		f.ok(w, map[string]any{"rows": []any{map[string]any{"modelCode": "parity-model-internal", "modelName": "Parity Model"}}, "total": 1})
	case "/gtw/cwai/algorithm/layout/list":
		f.ok(w, map[string]any{"list": []any{map[string]any{"layoutId": "parity-layout-internal", "algorithmCode": "parity-algorithm-internal"}}})
	case "/gtw/cwai/Task/QuerySwitch":
		f.mu.Lock()
		current := f.taskEnabled
		f.mu.Unlock()
		f.ok(w, map[string]any{"enable": float64(current), "switch": float64(current)})
	case "/gtw/cwai/Task/SwitchTask":
		value, ok := numberAsInt(body["switch"])
		if !ok || value < 0 || value > 1 {
			f.fail(w, "invalid task switch")
			return
		}
		f.mu.Lock()
		f.taskEnabled = value
		f.taskWrites++
		if f.taskDriftAfterWrite != nil {
			f.taskEnabled = *f.taskDriftAfterWrite
			f.taskDriftAfterWrite = nil
		}
		f.mu.Unlock()
		if fault == FaultCloseAfterWrite {
			closeConnection(w)
			return
		}
		f.ok(w, map[string]any{"switched": true})
	case "/gtw/cwai/Task/QueryParam":
		f.mu.Lock()
		value := f.parameterValue
		f.mu.Unlock()
		f.ok(w, map[string]any{"params": []any{map[string]any{"key": "param.threshold", "value": value}}})
	case "/gtw/cwai/task/selectConfigByAlgorithmId":
		f.mu.Lock()
		value := f.parameterValue
		f.mu.Unlock()
		f.ok(w, map[string]any{"taskConfig": map[string]any{"params": []any{map[string]any{"key": "param.threshold", "value": value}}}})
	case "/gtw/cwai/Task/ModifyParam":
		value, ok := taskParameterValue(body)
		if !ok {
			f.fail(w, "invalid task parameters")
			return
		}
		f.mu.Lock()
		f.parameterValue = value
		f.parameterWrites++
		f.mu.Unlock()
		if fault == FaultCloseAfterWrite {
			closeConnection(w)
			return
		}
		f.ok(w, map[string]any{"updated": true})
	case "/gtw/cwai/Task/RunningDetail":
		f.ok(w, map[string]any{"list": []any{map[string]any{"id": "parity-task-internal", "status": "running"}}})
	case "/gtw/cwai/Event/Page":
		f.mu.Lock()
		events := append([]FixtureEvent(nil), f.events...)
		f.mu.Unlock()
		rows := fixtureEventPage(events, body)
		pageNum, _ := numberAsInt(body["pageNum"])
		pageSize, _ := numberAsInt(body["pageSize"])
		if pageNum < 1 {
			pageNum = 1
		}
		if pageSize < 1 {
			pageSize = 100
		}
		start := (pageNum - 1) * pageSize
		end := start + pageSize
		if start > len(rows) {
			start = len(rows)
		}
		if end > len(rows) {
			end = len(rows)
		}
		f.ok(w, map[string]any{"rows": rows[start:end], "total": len(rows)})
	default:
		w.WriteHeader(http.StatusNotFound)
		f.fail(w, "unknown fixture route")
	}
}

func fixtureEventPage(events []FixtureEvent, body map[string]any) []any {
	timeBegin, hasBegin := numberAsInt64(body["timeBegin"])
	timeEnd, hasEnd := numberAsInt64(body["timeEnd"])
	algorithms := stringSet(body["algorithmCodes"])
	cameraName, _ := body["videoChannelName"].(string)
	rows := []any{}
	for _, event := range events {
		if hasBegin && event.Timestamp < timeBegin {
			continue
		}
		if hasEnd && event.Timestamp >= timeEnd {
			continue
		}
		if len(algorithms) > 0 && !algorithms[event.AlgorithmCode] {
			continue
		}
		if cameraName != "" && event.ChannelName != cameraName {
			continue
		}
		rows = append(rows, map[string]any{
			"id": event.ID, "algorithmCode": event.AlgorithmCode, "algorithmName": event.AlgorithmName,
			"videoChannelId": event.VideoChannelID, "channelName": event.ChannelName, "timestamp": event.Timestamp,
		})
	}
	return rows
}

func stringSet(value any) map[string]bool {
	set := map[string]bool{}
	switch values := value.(type) {
	case []any:
		for _, item := range values {
			if text, ok := item.(string); ok {
				set[text] = true
			}
		}
	case []string:
		for _, item := range values {
			set[item] = true
		}
	}
	return set
}

func numberAsInt64(value any) (int64, bool) {
	switch number := value.(type) {
	case float64:
		if number != float64(int64(number)) {
			return 0, false
		}
		return int64(number), true
	case int64:
		return number, true
	case int:
		return int64(number), true
	default:
		return 0, false
	}
}

func taskParameterValue(body map[string]any) (string, bool) {
	config, ok := body["taskConfig"].(map[string]any)
	if !ok {
		return "", false
	}
	rows, ok := config["params"].([]any)
	if !ok || len(rows) != 1 {
		return "", false
	}
	row, ok := rows[0].(map[string]any)
	if !ok || row["key"] != "param.threshold" {
		return "", false
	}
	value, ok := row["value"].(string)
	return value, ok
}

func numberAsInt(value any) (int, bool) {
	switch number := value.(type) {
	case float64:
		if number != float64(int(number)) {
			return 0, false
		}
		return int(number), true
	case int:
		return number, true
	default:
		return 0, false
	}
}

func (f *DeviceFixture) ok(w http.ResponseWriter, value map[string]any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"resCode": 1, "resData": value})
}

func (f *DeviceFixture) fail(w http.ResponseWriter, message string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resCode": 0,
		"resMsg":  []any{map[string]any{"msgCode": "PARITY", "msgText": message}},
	})
}

func closeConnection(w http.ResponseWriter) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	connection, _, err := hijacker.Hijack()
	if err == nil {
		_ = connection.Close()
	}
}
