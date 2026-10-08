package inspection

import (
	"errors"
	"strings"
	"time"
)

var transitions = map[RunState]map[RunState]struct{}{
	RunRequested: {
		RunAdmitted: {}, RunBlocked: {}, RunCancelled: {}, RunExpired: {},
	},
	RunAdmitted: {
		RunQueued: {}, RunBlocked: {}, RunCancelled: {}, RunExpired: {},
	},
	RunQueued: {
		RunRunning: {}, RunBlocked: {}, RunCancelled: {}, RunExpired: {},
	},
	RunRunning: {
		RunQueued: {}, RunReconciliationRequired: {}, RunFinalizing: {}, RunPartial: {}, RunBlocked: {}, RunFailed: {}, RunUnknown: {}, RunCancelled: {}, RunExpired: {},
	},
	RunReconciliationRequired: {
		RunQueued: {}, RunFailed: {}, RunUnknown: {}, RunCancelled: {}, RunExpired: {},
	},
	RunFinalizing: {
		RunCompleted: {}, RunPartial: {}, RunBlocked: {}, RunFailed: {}, RunUnknown: {}, RunExpired: {},
	},
}

func CanTransition(from, to RunState) bool {
	_, ok := transitions[from][to]
	return ok
}

func Terminal(state RunState) bool {
	switch state {
	case RunCompleted, RunPartial, RunBlocked, RunUnknown, RunFailed, RunCancelled, RunExpired:
		return true
	default:
		return false
	}
}

func Transition(run Run, target RunState, at time.Time, reason string) (Run, RunEvent, error) {
	if run.RunID == "" || run.State == "" || at.IsZero() || strings.TrimSpace(reason) == "" {
		return Run{}, RunEvent{}, errors.New("complete inspection transition metadata is required")
	}
	if !CanTransition(run.State, target) {
		return Run{}, RunEvent{}, errors.New("inspection run state transition is invalid")
	}
	if at.Before(run.UpdatedAt) {
		return Run{}, RunEvent{}, errors.New("inspection transition time moved backwards")
	}
	previous := run.State
	run.State = target
	run.Reason = reason
	run.UpdatedAt = at.UTC()
	event := RunEvent{
		RunID: run.RunID, Type: "state_changed", From: previous, To: target,
		Reason: reason, OccurredAt: at.UTC(),
	}
	return run, event, nil
}

func PhaseEvent(run Run, phase RunPhase, at time.Time, reason string) (RunEvent, error) {
	if run.RunID == "" || run.State != RunRunning || at.IsZero() || strings.TrimSpace(reason) == "" {
		return RunEvent{}, errors.New("inspection phase event requires a running run")
	}
	switch phase {
	case PhaseResolving, PhaseCapturing, PhaseAnalyzing, PhaseValidating, PhaseComposing, PhaseCleaning:
	default:
		return RunEvent{}, errors.New("inspection run phase is invalid")
	}
	return RunEvent{RunID: run.RunID, Type: "phase_observed", Phase: phase, Reason: reason, OccurredAt: at.UTC()}, nil
}
