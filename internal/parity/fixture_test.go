package parity

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeviceFixtureTracksWritesAndFaults(t *testing.T) {
	fixture := NewDeviceFixture("field-user", "private-password", "FULL-SN-001")
	server := httptest.NewServer(http.HandlerFunc(fixture.handle))
	defer server.Close()

	loginBody, _ := json.Marshal(map[string]any{"account": "field-user", "pwd": fixture.passwordDigest})
	response, err := http.Post(server.URL+"/gtw/cwai/login/DoLogin", "application/json", bytes.NewReader(loginBody))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("fixture login failed: status=%v err=%v", response, err)
	}
	_ = response.Body.Close()

	requestBody, _ := json.Marshal(map[string]any{"switch": 0})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/gtw/cwai/Task/SwitchTask", bytes.NewReader(requestBody))
	request.Header.Set("mtk", "parity-session-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("fixture write failed: status=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	snapshot := fixture.Snapshot()
	if snapshot.TaskEnabled != 0 || snapshot.TaskWrites != 1 {
		t.Fatalf("fixture snapshot=%#v", snapshot)
	}

	fixture.SetFault("/gtw/cwai/Task/SwitchTask", FaultReject)
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/gtw/cwai/Task/SwitchTask", bytes.NewReader(requestBody))
	request.Header.Set("mtk", "parity-session-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("fixture rejection transport failed: status=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	if fixture.Snapshot().TaskWrites != 1 {
		t.Fatal("known rejection changed the target")
	}
}

func TestNormalizeTaskStateRejectsUnknownStateAndProtectedFields(t *testing.T) {
	if _, err := NormalizeTaskState("unknown", map[string]any{"state": "invented"}, FixtureSnapshot{}); err == nil {
		t.Fatal("unknown implementation state was normalized")
	}
	if err := ScanProtected([]byte(`{"operationId":"internal"}`)); err == nil {
		t.Fatal("internal authority field passed the secret scanner")
	}
}

func TestFaultOnNext(t *testing.T) {
	fixture := NewDeviceFixture("user", "password", "sn")
	fixture.SetFaultOnNext("/one", FaultMalformed)
	fixture.mu.Lock()
	scheduled := fixture.nextFaults["/one"]
	fixture.mu.Unlock()
	if scheduled.request != 1 || scheduled.mode != FaultMalformed {
		t.Fatalf("scheduled fault=%#v", scheduled)
	}
}
