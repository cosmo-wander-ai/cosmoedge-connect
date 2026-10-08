package devwrite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const actionTimeout = 90 * time.Second

type Validator struct{ authority *devauthority.Authority }

type Result struct {
	Status           string `json:"status"`
	RunID            string `json:"runId"`
	Device           string `json:"device"`
	TaskIndex        int    `json:"taskIndex"`
	TaskName         string `json:"taskName"`
	OriginalState    string `json:"originalState"`
	TemporaryState   string `json:"temporaryState"`
	FinalState       string `json:"finalState"`
	ForwardResult    string `json:"forwardResult"`
	RestoreResult    string `json:"restoreResult"`
	Dispatches       int    `json:"dispatches"`
	DeviceWrites     int    `json:"deviceWrites"`
	EvidenceSealed   bool   `json:"evidenceSealed"`
	Restored         bool   `json:"restored"`
	RecoveryRequired bool   `json:"recoveryRequired"`
}

func New(authority *devauthority.Authority) (*Validator, error) {
	if authority == nil {
		return nil, errors.New("development write authority is required")
	}
	return &Validator{authority: authority}, nil
}

func (v *Validator) VerifyTaskRoundTrip(ctx context.Context, taskIndex int) (Result, error) {
	authorized, err := v.authority.OpenTaskRoundTripSession(ctx)
	if err != nil {
		return Result{}, err
	}
	if taskIndex < 1 || taskIndex > len(authorized.Snapshot.Tasks) {
		return Result{}, errors.New("displayed task list number is unavailable")
	}
	task := authorized.Snapshot.Tasks[taskIndex-1]
	if task.Enabled != 0 && task.Enabled != 1 || !task.SwitchVerified {
		return Result{}, errors.New("selected task state is not safely reversible")
	}
	target := 1 - task.Enabled
	runID, err := randomID(12)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Status: "failed", RunID: runID, Device: authorized.Device, TaskIndex: taskIndex,
		TaskName: task.DisplayName, OriginalState: switchState(task.Enabled), TemporaryState: switchState(target),
		FinalState: "unknown", RecoveryRequired: true,
	}
	runRoot := filepath.Join(authorized.EvidenceRoot, "runs", runID)
	if err := localstate.PrepareStateRoot(runRoot); err != nil {
		return result, err
	}
	store, err := ledger.Open(filepath.Join(runRoot, "operator.db"))
	if err != nil {
		return result, err
	}
	defer store.Close()
	if err := localstate.ValidateExistingStateFiles(runRoot); err != nil {
		return result, err
	}
	manager, err := actions.New(store, authorized.Vault)
	if err != nil {
		return result, err
	}
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := manager.Start(workerContext); err != nil {
		return result, err
	}
	defer manager.Stop()

	forward, err := executeTaskSwitch(ctx, manager, authorized.BrowserID, authorized.Snapshot, task, target)
	result.ForwardResult = forward.State
	result.Dispatches += forward.Dispatches
	result.DeviceWrites += forward.DeviceWrites
	result.EvidenceSealed = forward.Evidence == "sealed"
	if err != nil {
		return recoverTask(ctx, manager, authorized.Vault, authorized.BrowserID, task, task.Enabled, result, err)
	}
	return recoverTask(ctx, manager, authorized.Vault, authorized.BrowserID, task, task.Enabled, result, nil)
}

func recoverTask(ctx context.Context, manager *actions.Manager, vault *session.Vault, browserID string, original device.Task, originalState int, result Result, forwardErr error) (Result, error) {
	fresh, err := vault.Read(ctx)
	if err != nil {
		result.RecoveryRequired = true
		if forwardErr != nil {
			return result, errors.Join(forwardErr, err)
		}
		return result, err
	}
	current, ok := findTask(fresh, original)
	if !ok || (current.Enabled != 0 && current.Enabled != 1) {
		result.RecoveryRequired = true
		return result, errors.New("selected task identity or state changed during validation")
	}
	if current.Enabled != originalState {
		restore, restoreErr := executeTaskSwitch(ctx, manager, browserID, fresh, current, originalState)
		result.RestoreResult = restore.State
		result.Dispatches += restore.Dispatches
		result.DeviceWrites += restore.DeviceWrites
		result.EvidenceSealed = result.EvidenceSealed && restore.Evidence == "sealed"
		if restoreErr != nil {
			result.RecoveryRequired = true
			return result, restoreErr
		}
	} else {
		result.RestoreResult = "not_required"
	}
	finalSnapshot, err := vault.Read(ctx)
	if err != nil {
		return result, err
	}
	finalTask, ok := findTask(finalSnapshot, original)
	if !ok || finalTask.Enabled != originalState {
		return result, errors.New("task restoration could not be verified")
	}
	result.FinalState = switchState(finalTask.Enabled)
	result.Restored = true
	result.RecoveryRequired = false
	if result.DeviceWrites > 2 || result.Dispatches > 2 {
		return result, errors.New("development validation exceeded its two-write budget")
	}
	if forwardErr != nil {
		return result, forwardErr
	}
	if result.ForwardResult != "completed" || result.RestoreResult != "completed" {
		return result, errors.New("task round-trip did not complete both trusted actions")
	}
	result.Status = "passed"
	return result, nil
}

func executeTaskSwitch(ctx context.Context, manager *actions.Manager, browserID string, snapshot device.Snapshot, task device.Task, target int) (actions.Status, error) {
	proposal, err := manager.PrepareTaskSwitch(ctx, browserID, snapshot, task, target)
	if err != nil {
		return actions.Status{}, err
	}
	if _, err := manager.ConfirmExpected(ctx, browserID, proposal.ConfirmationToken, proposal.ActionID); err != nil {
		return actions.Status{}, err
	}
	deadline := time.Now().Add(actionTimeout)
	for {
		status, err := manager.Status(ctx, proposal.ActionID)
		if err != nil {
			return actions.Status{}, err
		}
		switch status.State {
		case "completed":
			return status, nil
		case "blocked", "unknown", "cancelled", "expired":
			return status, fmt.Errorf("task action ended in %s", status.State)
		}
		if time.Now().After(deadline) {
			return status, errors.New("task action timed out")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return status, ctx.Err()
		case <-timer.C:
		}
	}
}

func findTask(snapshot device.Snapshot, target device.Task) (device.Task, bool) {
	for _, candidate := range snapshot.Tasks {
		if candidate.ID == target.ID && candidate.ChannelID == target.ChannelID && candidate.AlgorithmID == target.AlgorithmID {
			return candidate, true
		}
	}
	return device.Task{}, false
}

func switchState(value int) string {
	if value == 1 {
		return "enabled"
	}
	if value == 0 {
		return "disabled"
	}
	return "unknown"
}

func randomID(length int) (string, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
