package parity

import (
	"testing"
	"time"
)

func TestBaselineFaultBeforeMutationGolden(t *testing.T) {
	for _, fault := range []FaultMode{FaultCloseBefore, FaultMalformed} {
		fault := fault
		t.Run("task_state/"+string(fault), func(t *testing.T) {
			session := newConnectedBaseline(t, "task-before-"+string(fault))
			session.selectOnlyTask(t)
			prepared := mustPostObject(t, session.Browser, "/api/journey/prepare-persistent", map[string]any{"targetEnabled": 0})
			session.Fixture.SetFault("/gtw/cwai/Task/SwitchTask", fault)
			mustPostObject(t, session.Browser, "/api/journey/confirm-business", map[string]any{
				"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
			})
			terminal, err := session.Browser.WaitJSON("/api/journey?intent=manage_tasks&window=today", 30*time.Second, func(value map[string]any) bool {
				return StringField(value, "state") == "outcome_unknown"
			})
			if err != nil || session.Fixture.Snapshot().TaskWrites != 0 || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/SwitchTask"] != 1 {
				t.Fatalf("task pre-mutation fault=%s terminal=%#v err=%v snapshot=%#v", fault, terminal, err, session.Fixture.Snapshot())
			}
			assertNoTaskReplay(t, session)
			recordNormalized(t, NormalizedResult{Scenario: "G-ACT-08/task-" + string(fault), Class: "unknown", Dispatches: 1})
		})

		t.Run("parameters/"+string(fault), func(t *testing.T) {
			session := newConnectedBaseline(t, "param-before-"+string(fault))
			session.selectOnlyTask(t)
			prepared := mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/prepare", map[string]any{
				"fields": []map[string]any{{"key": "param.threshold", "value": "23"}},
			})
			session.Fixture.SetFault("/gtw/cwai/Task/ModifyParam", fault)
			mustPostObject(t, session.Browser, "/api/toolbox/task-parameters/confirm", map[string]any{
				"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
			})
			terminal, err := session.Browser.WaitJSON("/api/toolbox/task-parameters", 30*time.Second, func(value map[string]any) bool {
				return toolboxBlockedTerminal(value)
			})
			if err != nil || session.Fixture.Snapshot().ParameterWrites != 0 || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/ModifyParam"] != 1 || IntField(terminal, "deviceWrites") != 1 {
				t.Fatalf("parameter pre-mutation fault=%s terminal=%#v err=%v snapshot=%#v", fault, terminal, err, session.Fixture.Snapshot())
			}
			for i := 0; i < 4; i++ {
				mustGetObject(t, session.Browser, "/api/toolbox/task-parameters")
			}
			if session.Fixture.Snapshot().ParameterWrites != 0 || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/ModifyParam"] != 1 {
				t.Fatalf("parameter fault replayed: %#v", session.Fixture.Snapshot())
			}
			recordNormalized(t, NormalizedResult{Scenario: "G-ACT-08/parameters-" + string(fault), Class: "blocked", EvidenceStatus: "sealed", Dispatches: 1})
		})

		t.Run("source/"+string(fault), func(t *testing.T) {
			session := newConnectedBaseline(t, "source-before-"+string(fault))
			prepared := mustPostObject(t, session.Browser, "/api/toolbox/camera-source/prepare", map[string]any{
				"name": "Pre-mutation Source", "sourceUrl": "rtsp://private:before@10.42.0.14/live",
			})
			session.Fixture.SetFault("/gtw/cwai/Camera/Add", fault)
			mustPostObject(t, session.Browser, "/api/toolbox/camera-source/confirm", map[string]any{
				"businessConfirmationToken": StringField(prepared, "businessConfirmationToken"),
			})
			terminal, err := session.Browser.WaitJSON("/api/toolbox/camera-source", 30*time.Second, func(value map[string]any) bool {
				return toolboxBlockedTerminal(value)
			})
			if err != nil || session.Fixture.Snapshot().SourceWrites != 0 || session.Fixture.Snapshot().Requests["/gtw/cwai/Camera/Add"] != 1 || IntField(terminal, "deviceWrites") != 1 {
				t.Fatalf("source pre-mutation fault=%s terminal=%#v err=%v snapshot=%#v", fault, terminal, err, session.Fixture.Snapshot())
			}
			for i := 0; i < 4; i++ {
				mustGetObject(t, session.Browser, "/api/toolbox/camera-source")
			}
			if session.Fixture.Snapshot().SourceWrites != 0 || session.Fixture.Snapshot().Requests["/gtw/cwai/Camera/Add"] != 1 {
				t.Fatalf("source fault replayed: %#v", session.Fixture.Snapshot())
			}
			recordNormalized(t, NormalizedResult{Scenario: "G-ACT-08/source-" + string(fault), Class: "blocked", EvidenceStatus: "sealed", Dispatches: 1})
		})
	}
}

func assertNoTaskReplay(t *testing.T, session *baselineSession) {
	t.Helper()
	for i := 0; i < 4; i++ {
		mustGetObject(t, session.Browser, "/api/journey?intent=manage_tasks&window=today")
	}
	if session.Fixture.Snapshot().TaskWrites != 0 || session.Fixture.Snapshot().Requests["/gtw/cwai/Task/SwitchTask"] != 1 {
		t.Fatalf("task fault replayed: %#v", session.Fixture.Snapshot())
	}
}
