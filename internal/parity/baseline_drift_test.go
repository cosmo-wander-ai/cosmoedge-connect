package parity

import (
	"testing"
	"time"
)

func TestBaselinePostDispatchDriftGolden(t *testing.T) {
	t.Run("task state", func(t *testing.T) {
		session := newConnectedBaseline(t, "task-post-drift")
		session.selectOnlyTask(t)
		prepared := mustPostObject(t, session.Browser, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
		session.Fixture.SetTaskEnabledAfterWrite(1)
		mustPostObject(t, session.Browser, "/api/journey/confirm-business", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 30*time.Second, func(value map[string]any) bool {
			if baselineImplementation() {
				return StringField(value, "state") == "external_drift" && StringField(value, "report", "evidenceStatus") == "external_drift"
			}
			return StringField(value, "state") == "outcome_unknown" && StringField(value, "report", "evidenceStatus") == "sealed"
		})
		snapshot := session.Fixture.Snapshot()
		if err != nil || snapshot.TaskWrites != 1 || snapshot.TaskEnabled != 1 || snapshot.Requests["/gtw/cwai/Task/SwitchTask"] != 1 {
			t.Fatalf("task post-dispatch drift terminal=%#v err=%v snapshot=%#v", terminal, err, snapshot)
		}
		for i := 0; i < 4; i++ {
			mustGetObject(t, session.Browser, "/api/journey?intent=manage_tasks&window=today")
		}
		if session.Fixture.Snapshot().TaskWrites != 1 {
			t.Fatalf("task drift replayed: %#v", session.Fixture.Snapshot())
		}
		evidenceStatus := "external_drift"
		if !baselineImplementation() {
			evidenceStatus = "sealed"
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-09/task-post-dispatch-drift", Class: "unknown", EvidenceStatus: evidenceStatus, DeviceWrites: 1, Dispatches: 1})
	})

	t.Run("parameters", func(t *testing.T) {
		session := newConnectedBaseline(t, "param-post-drift")
		session.selectOnlyTask(t)
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
			"fields": []map[string]any{{"key": "param.threshold", "value": "29"}},
		})
		session.Fixture.SetParameterValueAfter("/gtw/cwai/Task/QueryParam", 1, "external-31")
		mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/task-parameters", 30*time.Second, func(value map[string]any) bool {
			return toolboxBlockedTerminal(value)
		})
		snapshot := session.Fixture.Snapshot()
		if err != nil || snapshot.ParameterWrites != 1 || snapshot.ParameterValue != "external-31" || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("parameter post-dispatch drift terminal=%#v err=%v snapshot=%#v", terminal, err, snapshot)
		}
		for i := 0; i < 4; i++ {
			mustGetObject(t, session.Browser, "/api/toolbox/task-parameters")
		}
		if session.Fixture.Snapshot().ParameterWrites != 1 {
			t.Fatalf("parameter drift replayed: %#v", session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-09/parameters-post-dispatch-drift", Class: "blocked", EvidenceStatus: "sealed", DeviceWrites: 1, Dispatches: 1})
	})

	t.Run("source", func(t *testing.T) {
		session := newConnectedBaseline(t, "source-post-drift")
		prepared := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
			"name": "Drifted Source", "sourceUrl": "rtsp://private:drift@10.42.0.15/live",
		})
		session.Fixture.ClearSourcesAfter("/gtw/cwai/Camera/Page", 2)
		mustPostObject(t, session.Browser, "/api/toolbox/camera-source/confirm", map[string]any{
			"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
		})
		terminal, err := session.Browser.WaitJSON("/api/toolbox/camera-source", 30*time.Second, func(value map[string]any) bool {
			return toolboxBlockedTerminal(value)
		})
		snapshot := session.Fixture.Snapshot()
		if err != nil || snapshot.SourceWrites != 1 || len(snapshot.Sources) != 0 || IntField(terminal, "deviceWrites") != 1 {
			t.Fatalf("source post-dispatch drift terminal=%#v err=%v snapshot=%#v", terminal, err, snapshot)
		}
		for i := 0; i < 4; i++ {
			mustGetObject(t, session.Browser, "/api/toolbox/camera-source")
		}
		if session.Fixture.Snapshot().SourceWrites != 1 {
			t.Fatalf("source drift replayed: %#v", session.Fixture.Snapshot())
		}
		recordNormalized(t, NormalizedResult{Scenario: "G-ACT-09/source-post-dispatch-drift", Class: "blocked", EvidenceStatus: "sealed", DeviceWrites: 1, Dispatches: 1})
	})
}
