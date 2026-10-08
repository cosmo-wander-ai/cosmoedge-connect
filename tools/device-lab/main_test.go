package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devlab"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

type apiLease struct{ snapshot device.Snapshot }

func (l *apiLease) Read(context.Context) (device.Snapshot, error) { return l.snapshot, nil }
func (l *apiLease) ObserveTaskEvents(context.Context, device.Task, device.EventWindow) (device.Snapshot, device.TaskEventObservation, error) {
	return l.snapshot, device.TaskEventObservation{}, nil
}
func (l *apiLease) Close() error { return nil }

type apiRecorder struct{}

func (*apiRecorder) StartRun(context.Context, devlab.EvidenceRun) error      { return nil }
func (*apiRecorder) RecordProbe(context.Context, devlab.EvidenceProbe) error { return nil }
func (*apiRecorder) FinishRun(context.Context, string, string, time.Time, int, int, int) error {
	return nil
}

func TestAPIRequiresHostAndTokenAndReturnsOnlyProjection(t *testing.T) {
	now := time.Now().UTC()
	lease := &apiLease{snapshot: device.Snapshot{
		Identity: device.Identity{Serial: "PRIVATE-SERIAL-0002", Type: "fixture"}, ObservedAt: now,
		Cameras: []device.Camera{{ID: "private-camera-id", Name: "Front Door"}},
		Tasks:   []device.Task{{ID: "private-task-id", ChannelID: "private-camera-id", AlgorithmID: "private-algorithm-id", DisplayName: "Person + Front Door", CameraName: "Front Door", AlgorithmName: "Person", Enabled: 1, Running: "running"}},
	}}
	runtime, err := devlab.NewRuntime(func(context.Context, time.Duration) (devlab.Lease, device.Snapshot, devauthority.ReadLeaseInfo, error) {
		return lease, lease.snapshot, devauthority.ReadLeaseInfo{Device: "***0002", DeviceType: "fixture", OpenedAt: now, ExpiresAt: now.Add(time.Minute)}, nil
	}, &apiRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	handler := newAPI(runtime, "secret-token", "127.0.0.1:4567", func() {})

	unauthorized := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:4567/v1/status", nil)
	unauthorized.Host = "127.0.0.1:4567"
	unauthorizedResult := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResult, unauthorized)
	if unauthorizedResult.Code != http.StatusForbidden {
		t.Fatalf("status=%d", unauthorizedResult.Code)
	}

	begin := authenticatedRequest(http.MethodPost, "/v1/runs", `{"durationSeconds":60,"commit":"abc1234"}`)
	beginResult := httptest.NewRecorder()
	handler.ServeHTTP(beginResult, begin)
	if beginResult.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", beginResult.Code, beginResult.Body.String())
	}

	probe := authenticatedRequest(http.MethodPost, "/v1/probes", `{"kind":"snapshot","hypothesis":"raw model thought","assertions":[{"kind":"equals","path":"taskCount","expected":1}]}`)
	probeResult := httptest.NewRecorder()
	handler.ServeHTTP(probeResult, probe)
	if probeResult.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", probeResult.Code, probeResult.Body.String())
	}
	body := probeResult.Body.String()
	for _, protected := range []string{"PRIVATE-SERIAL-0002", "private-camera-id", "private-task-id", "private-algorithm-id", "raw model thought", "secret-token"} {
		if strings.Contains(body, protected) {
			t.Fatalf("protected value %q returned: %s", protected, body)
		}
	}
	var decoded devlab.ProbeResult
	if err := json.NewDecoder(bytes.NewBufferString(body)).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != "observed" || decoded.Assertions[0].Status != "passed" || decoded.DeviceWrites != 0 {
		t.Fatalf("result=%#v", decoded)
	}
}

func authenticatedRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, "http://127.0.0.1:4567"+path, strings.NewReader(body))
	request.Host = "127.0.0.1:4567"
	request.Header.Set("Authorization", "Bearer secret-token")
	request.Header.Set("Content-Type", "application/json")
	return request
}
