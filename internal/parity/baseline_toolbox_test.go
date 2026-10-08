package parity

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestBaselineTaskParametersGolden(t *testing.T) {
	session := newConnectedBaseline(t, "parameters")
	targetValue := "param-secret-739184"
	session.selectOnlyTask(t)
	initial := mustGetObject(t, session.Browser, "/api/toolbox/task-parameters")
	fields := ArrayField(initial, "fields")
	if StringField(initial, "state") != "editable" || !BoolField(initial, "canEdit") || BoolField(initial, "canConfirm") || len(fields) != 1 {
		t.Fatalf("initial task parameters=%#v", initial)
	}
	field, _ := fields[0].(map[string]any)
	if StringField(field, "key") != "param.threshold" || StringField(field, "value") != "5" {
		t.Fatalf("initial task parameter field=%#v", field)
	}

	prepared := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
		"fields": []map[string]any{{"key": "param.threshold", "value": targetValue}},
	})
	if StringField(prepared, "state") != "awaiting_approval" || !BoolField(prepared, "canConfirm") || StringField(prepared, "businessConfirmationToken") == "" || IntField(prepared, "deviceWrites") != 0 || session.Fixture.Snapshot().ParameterWrites != 0 {
		t.Fatalf("prepared task parameters=%#v snapshot=%#v", prepared, session.Fixture.Snapshot())
	}
	preparedField, _ := ArrayField(prepared, "fields")[0].(map[string]any)
	if StringField(preparedField, "before") != "5" || StringField(preparedField, "value") != targetValue || !BoolField(preparedField, "changed") {
		t.Fatalf("prepared task parameter diff=%#v", preparedField)
	}
	status, _, err := session.Browser.JSON(http.MethodPost, "/api/toolbox/task-parameters/confirm", map[string]any{"businessConfirmationToken": "not-current"})
	if err != nil || status != http.StatusConflict || session.Fixture.Snapshot().ParameterWrites != 0 {
		t.Fatalf("invalid parameter confirmation status=%d err=%v snapshot=%#v", status, err, session.Fixture.Snapshot())
	}
	cancelled := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/cancel", map[string]any{})
	if StringField(cancelled, "state") != "cancelled" || IntField(cancelled, "deviceWrites") != 0 || session.Fixture.Snapshot().ParameterWrites != 0 {
		t.Fatalf("cancelled task parameters=%#v snapshot=%#v", cancelled, session.Fixture.Snapshot())
	}

	mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/reset", map[string]any{})
	prepared = mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
		"fields": []map[string]any{{"key": "param.threshold", "value": targetValue}},
	})
	mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/confirm", map[string]any{
		"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
	})
	terminal, err := session.Browser.WaitJSON("/api/toolbox/task-parameters", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "succeeded" && StringField(value, "evidence") == "sealed"
	})
	if err != nil {
		t.Fatalf("task parameter terminal: %v last=%#v", err, terminal)
	}
	snapshot := session.Fixture.Snapshot()
	if snapshot.ParameterValue != targetValue || snapshot.ParameterWrites != 1 || IntField(terminal, "deviceWrites") != 1 || !BoolField(terminal, "canEdit") {
		t.Fatalf("task parameter terminal=%#v snapshot=%#v", terminal, snapshot)
	}
	for i := 0; i < 4; i++ {
		mustGetObject(t, session.Browser, "/api/toolbox/task-parameters")
	}
	if session.Fixture.Snapshot().ParameterWrites != 1 {
		t.Fatalf("task parameter refresh replayed write: %#v", session.Fixture.Snapshot())
	}
	if err := ScanProtected(session.Browser.Bodies(), session.Password, session.FullSN, "parity-task-internal", "parity-camera-internal", "parity-algorithm-internal"); err != nil {
		t.Fatal(err)
	}
	session.Run.Close()
	if err := ScanTreeProtected(session.Run.Root, targetValue); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{
		Scenario: "G-ACT-04/parameters-success", Class: "completed", EvidenceStatus: "sealed",
		TaskName: "Parity Algorithm + Parity Camera", CameraName: "Parity Camera", AlgorithmName: "Parity Algorithm",
		DeviceWrites: 1, Dispatches: 1,
	})
}

func TestBaselineCameraSourceGolden(t *testing.T) {
	session := newConnectedBaseline(t, "source")
	streamURL := "rtsp://private-source-user:private-source-password@10.42.0.9/live"
	initial := mustGetObject(t, session.Browser, "/api/toolbox/camera-source")
	if StringField(initial, "state") != "editable" || !BoolField(initial, "canCreate") || BoolField(initial, "canConfirm") || IntField(initial, "deviceWrites") != 0 {
		t.Fatalf("initial camera source=%#v", initial)
	}
	prepared := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
		"name": "Parity Entrance", "sourceUrl": streamURL,
	})
	if StringField(prepared, "state") != "awaiting_approval" || !BoolField(prepared, "canConfirm") || !BoolField(prepared, "canCancel") || StringField(prepared, "businessConfirmationToken") == "" || StringField(prepared, "name") != "Parity Entrance" || IntField(prepared, "catalogCountBefore") != 1 || IntField(prepared, "catalogCountTarget") != 2 || session.Fixture.Snapshot().SourceWrites != 0 {
		t.Fatalf("prepared camera source=%#v snapshot=%#v", prepared, session.Fixture.Snapshot())
	}
	status, _, err := session.Browser.JSON(http.MethodPost, "/api/toolbox/camera-source/confirm", map[string]any{"businessConfirmationToken": "not-current"})
	if err != nil || status != http.StatusConflict || session.Fixture.Snapshot().SourceWrites != 0 {
		t.Fatalf("invalid source confirmation status=%d err=%v snapshot=%#v", status, err, session.Fixture.Snapshot())
	}
	cancelled := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/cancel", map[string]any{})
	if StringField(cancelled, "state") != "cancelled" || !BoolField(cancelled, "canReset") || IntField(cancelled, "deviceWrites") != 0 || session.Fixture.Snapshot().SourceWrites != 0 {
		t.Fatalf("cancelled camera source=%#v snapshot=%#v", cancelled, session.Fixture.Snapshot())
	}
	status, _, err = session.Browser.JSON(http.MethodPost, "/api/toolbox/camera-source/confirm", map[string]any{
		"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
	})
	if err != nil || status != http.StatusConflict || session.Fixture.Snapshot().SourceWrites != 0 {
		t.Fatalf("cancelled source confirmation status=%d err=%v snapshot=%#v", status, err, session.Fixture.Snapshot())
	}

	mustPostObject(t, session.Browser, "/api/toolbox/camera-source/reset", map[string]any{})
	prepared = mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
		"name": "Parity Entrance", "sourceUrl": streamURL,
	})
	mustPostObject(t, session.Browser, "/api/toolbox/camera-source/confirm", map[string]any{
		"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
	})
	terminal, err := session.Browser.WaitJSON("/api/toolbox/camera-source", 30*time.Second, func(value map[string]any) bool {
		return StringField(value, "state") == "succeeded" && StringField(value, "evidence") == "sealed"
	})
	if err != nil {
		t.Fatalf("camera source terminal: %v last=%#v", err, terminal)
	}
	snapshot := session.Fixture.Snapshot()
	if snapshot.SourceWrites != 1 || len(snapshot.Sources) != 1 || snapshot.Sources[0].Name != "Parity Entrance" || snapshot.Sources[0].URL != streamURL || IntField(terminal, "deviceWrites") != 1 || !BoolField(terminal, "canReset") {
		t.Fatalf("camera source terminal=%#v snapshot=%#v", terminal, snapshot)
	}
	for i := 0; i < 4; i++ {
		mustGetObject(t, session.Browser, "/api/toolbox/camera-source")
	}
	if session.Fixture.Snapshot().SourceWrites != 1 {
		t.Fatalf("camera source refresh replayed write: %#v", session.Fixture.Snapshot())
	}
	if err := ScanProtected(session.Browser.Bodies(), session.Password, session.FullSN, streamURL, "private-source-user", "private-source-password", "parity-task-internal", "parity-camera-internal", "parity-algorithm-internal"); err != nil {
		t.Fatal(err)
	}
	session.Run.Close()
	if err := ScanTreeProtected(session.Run.Root, streamURL, "private-source-user", "private-source-password"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{Scenario: "G-ACT-04/source-success", Class: "completed", EvidenceStatus: "sealed", DeviceWrites: 1, Dispatches: 1})
}

func TestBaselineToolboxAmbiguousWritesGolden(t *testing.T) {
	t.Run("parameters verified after response loss", func(t *testing.T) {
		session := newConnectedBaseline(t, "param-verified")
		session.selectOnlyTask(t)
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
			"fields": []map[string]any{{"key": "param.threshold", "value": "11"}},
		})
		session.Fixture.SetFault("/gtw/cwai/Task/ModifyParam", FaultCloseAfterWrite)
		mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/task-parameters", 30*time.Second, func(value map[string]any) bool {
			return StringField(value, "state") == "succeeded" && StringField(value, "evidence") == "sealed"
		})
		if err != nil || session.Fixture.Snapshot().ParameterWrites != 1 || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("parameter response loss terminal=%#v err=%v snapshot=%#v", terminal, err, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-07/parameters-response-lost-verified", Class: "completed", EvidenceStatus: "sealed", DeviceWrites: 1, Dispatches: 1})
	})

	t.Run("parameters unknown when verification fails", func(t *testing.T) {
		session := newConnectedBaseline(t, "param-unknown")
		session.selectOnlyTask(t)
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
			"fields": []map[string]any{{"key": "param.threshold", "value": "13"}},
		})
		session.Fixture.SetFault("/gtw/cwai/Task/ModifyParam", FaultCloseAfterWrite)
		session.Fixture.SetFaultOnNext("/gtw/cwai/Task/QueryParam", FaultMalformed)
		mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/task-parameters", 30*time.Second, func(value map[string]any) bool {
			return StringField(value, "state") == "outcome_unknown"
		})
		if err != nil || session.Fixture.Snapshot().ParameterWrites != 1 || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("parameter unknown terminal=%#v err=%v snapshot=%#v", terminal, err, session.Fixture.Snapshot())
		}
		for i := 0; i < 4; i++ {
			mustGetObject(t, session.Browser, "/api/toolbox/task-parameters")
		}
		if session.Fixture.Snapshot().ParameterWrites != 1 {
			t.Fatalf("parameter unknown refresh replayed: %#v", session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-07/parameters-verification-unavailable", Class: "unknown", DeviceWrites: 1, Dispatches: 1})
	})

	t.Run("source verified after response loss", func(t *testing.T) {
		session := newConnectedBaseline(t, "source-verified")
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
			"name": "Verified Source", "sourceUrl": "rtsp://private:verified@10.42.0.10/live",
		})
		session.Fixture.SetFault("/gtw/cwai/Camera/Add", FaultCloseAfterWrite)
		mustPostObject(t, session.Browser, "/api/toolbox/camera-source/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/camera-source", 30*time.Second, func(value map[string]any) bool {
			return StringField(value, "state") == "succeeded" && StringField(value, "evidence") == "sealed"
		})
		if err != nil || session.Fixture.Snapshot().SourceWrites != 1 || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("source response loss terminal=%#v err=%v snapshot=%#v", terminal, err, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-07/source-response-lost-verified", Class: "completed", EvidenceStatus: "sealed", DeviceWrites: 1, Dispatches: 1})
	})

	t.Run("source unknown when verification fails", func(t *testing.T) {
		session := newConnectedBaseline(t, "source-unknown")
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
			"name": "Unknown Source", "sourceUrl": "rtsp://private:unknown@10.42.0.11/live",
		})
		session.Fixture.SetFault("/gtw/cwai/Camera/Add", FaultCloseAfterWrite)
		session.Fixture.SetFaultAfter("/gtw/cwai/Camera/Page", 2, FaultMalformed)
		mustPostObject(t, session.Browser, "/api/toolbox/camera-source/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/camera-source", 30*time.Second, func(value map[string]any) bool {
			return StringField(value, "state") == "outcome_unknown"
		})
		if err != nil || session.Fixture.Snapshot().SourceWrites != 1 || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("source unknown terminal=%#v err=%v snapshot=%#v", terminal, err, session.Fixture.Snapshot())
		}
		for i := 0; i < 4; i++ {
			mustGetObject(t, session.Browser, "/api/toolbox/camera-source")
		}
		if session.Fixture.Snapshot().SourceWrites != 1 {
			t.Fatalf("source unknown refresh replayed: %#v", session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-07/source-verification-unavailable", Class: "unknown", DeviceWrites: 1, Dispatches: 1})
	})
}

func TestBaselineToolboxKnownRejectionsGolden(t *testing.T) {
	t.Run("parameters", func(t *testing.T) {
		session := newConnectedBaseline(t, "param-reject")
		session.selectOnlyTask(t)
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
			"fields": []map[string]any{{"key": "param.threshold", "value": "17"}},
		})
		session.Fixture.SetFault("/gtw/cwai/Task/ModifyParam", FaultReject)
		mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/task-parameters", 30*time.Second, func(value map[string]any) bool {
			return toolboxBlockedTerminal(value)
		})
		wantWrites := 1
		if !baselineImplementation() {
			wantWrites = 0
		}
		if err != nil || session.Fixture.Snapshot().ParameterWrites != 0 || IntField(terminal, "deviceWrites") != wantWrites || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/ModifyParam"] != 1 {
			t.Fatalf("parameter rejection terminal=%#v err=%v snapshot=%#v", terminal, err, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-06/parameters-known-rejection", Class: "blocked", EvidenceStatus: "sealed", Dispatches: 1})
	})

	t.Run("source", func(t *testing.T) {
		session := newConnectedBaseline(t, "source-reject")
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
			"name": "Rejected Source", "sourceUrl": "rtsp://private:rejected@10.42.0.12/live",
		})
		session.Fixture.SetFault("/gtw/cwai/Camera/Add", FaultReject)
		mustPostObject(t, session.Browser, "/api/toolbox/camera-source/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/camera-source", 30*time.Second, func(value map[string]any) bool {
			return toolboxBlockedTerminal(value)
		})
		wantWrites := 1
		if !baselineImplementation() {
			wantWrites = 0
		}
		if err != nil || session.Fixture.Snapshot().SourceWrites != 0 || IntField(terminal, "deviceWrites") != wantWrites || session.Fixture.Snapshot().Requests["/gtw/cwai/Camera/Add"] != 1 {
			t.Fatalf("source rejection terminal=%#v err=%v snapshot=%#v", terminal, err, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-06/source-known-rejection", Class: "blocked", EvidenceStatus: "sealed", Dispatches: 1})
	})
}

func toolboxBlockedTerminal(value map[string]any) bool {
	state := StringField(value, "state")
	if baselineImplementation() {
		return state == "recovery_required" && StringField(value, "evidence") == "sealed"
	}
	return state == "blocked" && StringField(value, "evidence") == "sealed"
}

func TestBaselineToolboxConcurrentConfirmGolden(t *testing.T) {
	t.Run("parameters", func(t *testing.T) {
		session := newConnectedBaseline(t, "param-concurrent")
		session.selectOnlyTask(t)
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
			"fields": []map[string]any{{"key": "param.threshold", "value": "19"}},
		})
		accepted := concurrentConfirm(t, session.Browser, "/api/toolbox/task-parameters/confirm", StringField(prepared, "businessConfirmationToken"))
		terminal, err := session.Browser.WaitJSON("/api/toolbox/task-parameters", 30*time.Second, func(value map[string]any) bool {
			return StringField(value, "state") == "succeeded" && StringField(value, "evidence") == "sealed"
		})
		if accepted != 1 || err != nil || session.Fixture.Snapshot().ParameterWrites != 1 || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("concurrent parameter accepted=%d terminal=%#v err=%v snapshot=%#v", accepted, terminal, err, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-05/parameters-concurrent-confirm", Class: "completed", EvidenceStatus: "sealed", DeviceWrites: 1, Dispatches: 1})
	})

	t.Run("source", func(t *testing.T) {
		session := newConnectedBaseline(t, "source-concurrent")
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
			"name": "Concurrent Source", "sourceUrl": "rtsp://private:concurrent@10.42.0.13/live",
		})
		accepted := concurrentConfirm(t, session.Browser, "/api/toolbox/camera-source/confirm", StringField(prepared, "businessConfirmationToken"))
		terminal, err := session.Browser.WaitJSON("/api/toolbox/camera-source", 30*time.Second, func(value map[string]any) bool {
			return StringField(value, "state") == "succeeded" && StringField(value, "evidence") == "sealed"
		})
		if accepted != 1 || err != nil || session.Fixture.Snapshot().SourceWrites != 1 || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("concurrent source accepted=%d terminal=%#v err=%v snapshot=%#v", accepted, terminal, err, session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-05/source-concurrent-confirm", Class: "completed", EvidenceStatus: "sealed", DeviceWrites: 1, Dispatches: 1})
	})
}

func concurrentConfirm(t *testing.T, browser *Browser, path, token string) int {
	t.Helper()
	statuses := make(chan int, 8)
	var wait sync.WaitGroup
	for i := 0; i < cap(statuses); i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, _, err := browser.JSON(http.MethodPost, path, map[string]any{"businessConfirmationToken": token})
			if err != nil {
				statuses <- 0
				return
			}
			statuses <- status
		}()
	}
	wait.Wait()
	close(statuses)
	accepted := 0
	for status := range statuses {
		if status == http.StatusOK {
			accepted++
		} else if status != http.StatusConflict {
			t.Fatalf("concurrent confirmation status=%d", status)
		}
	}
	return accepted
}
