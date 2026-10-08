package app

import (
	"context"
	"errors"
	"sync"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/read"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

type Service struct {
	vault   *session.Vault
	reader  *read.Service
	actions *actions.Manager

	mu         sync.Mutex
	selections map[string]selection
	active     map[string]map[string]*activeAction
}

type selection struct {
	choiceSetID string
	index       int
}

type activeAction struct {
	id            string
	kind          string
	selected      read.Task
	beforeFields  []actions.ParameterField
	targetFields  []actions.ParameterField
	sourceName    string
	catalogBefore int
}

func New(vault *session.Vault, managers ...*actions.Manager) *Service {
	var manager *actions.Manager
	if len(managers) > 0 {
		manager = managers[0]
	}
	return &Service{
		vault: vault, reader: read.New(vault), actions: manager,
		selections: map[string]selection{}, active: map[string]map[string]*activeAction{},
	}
}

func (s *Service) PrepareConnection(browserID, endpoint, username string) (session.ConnectionPreview, error) {
	return s.vault.PrepareConnection(browserID, endpoint, username)
}

func (s *Service) Connect(ctx context.Context, browserID, token string, password []byte) (session.ConnectionInfo, error) {
	return s.vault.Connect(ctx, browserID, token, password)
}

func (s *Service) ConnectConfirmed(ctx context.Context, browserID, token string, password []byte, replace bool) (session.ConnectionInfo, error) {
	return s.vault.ConnectConfirmed(ctx, browserID, token, password, replace)
}

func (s *Service) CanRetrySavedConnection() bool {
	return s.vault.CanRetrySavedConnection()
}

func (s *Service) RetrySavedConnection(ctx context.Context, browserID string) (session.RestoreResult, error) {
	return s.vault.RetrySavedConnection(ctx, browserID)
}

func (s *Service) Journey(ctx context.Context, browserID, intent, window string) (read.Projection, error) {
	projection, _, err := s.reader.Present(ctx, intent, window)
	if errors.Is(err, session.ErrNotConnected) || err != nil {
		return projection, nil
	}
	if projection.View != "manage_tasks" {
		return projection, nil
	}
	if active := s.activeFor(browserID, actions.KindTaskSwitch); active != nil && s.actions != nil {
		projection.Selection = &read.Selection{Status: "selected", Selected: &active.selected}
		status, statusErr := s.actions.Status(ctx, active.id)
		if statusErr == nil {
			applyTaskStatus(&projection, status)
		}
		return projection, nil
	}
	selected, ok := s.selectionFor(browserID)
	if ok && selected.choiceSetID == projection.Read.ChoiceSetID && selected.index > 0 && selected.index <= len(projection.Read.Tasks) {
		return read.Selected(projection, projection.Read.Tasks[selected.index-1]), nil
	}
	return projection, nil
}

func (s *Service) Select(ctx context.Context, browserID string, index int, choiceSetID string) (read.Projection, error) {
	projection, _, err := s.reader.Present(ctx, "manage_tasks", "today")
	if err != nil {
		return projection, nil
	}
	if choiceSetID == "" || choiceSetID != projection.Read.ChoiceSetID || index <= 0 || index > len(projection.Read.Tasks) {
		return read.Stale(projection), nil
	}
	selected := projection.Read.Tasks[index-1]
	s.mu.Lock()
	s.selections[browserID] = selection{choiceSetID: choiceSetID, index: index}
	s.mu.Unlock()
	return read.Selected(projection, selected), nil
}

func (s *Service) PreparePersistent(ctx context.Context, browserID string, target int) (read.Projection, error) {
	projection, snapshot, rawTask, selected, ok := s.selectedTask(ctx, browserID)
	if !ok {
		return read.Stale(projection), nil
	}
	projection = read.Selected(projection, selected)
	if s.actions == nil {
		projection.State = "action_unavailable"
		projection.Conclusion = "确定性控制内核当前不可用。"
		projection.Capabilities = read.Capabilities{}
		return projection, nil
	}
	proposal, err := s.actions.PrepareTaskSwitch(ctx, browserID, snapshot, rawTask, target)
	if err != nil {
		projection.State = "blocked"
		projection.Conclusion = "任务状态或设备身份已经变化，请刷新后重新选择。"
		projection.Capabilities = read.Capabilities{}
		return projection, nil
	}
	s.setActive(browserID, &activeAction{id: proposal.ActionID, kind: actions.KindTaskSwitch, selected: selected})
	projection.State = "awaiting_confirmation"
	projection.Conclusion = "方案已完成新鲜回读，等待本机人员确认。"
	projection.BusinessConfirmationToken = proposal.ConfirmationToken
	projection.Capabilities = read.Capabilities{CanConfirm: true, CanCancel: true}
	return projection, nil
}

func (s *Service) ConfirmBusiness(ctx context.Context, browserID, token string) (read.Projection, error) {
	active := s.activeFor(browserID, actions.KindTaskSwitch)
	if active == nil || s.actions == nil {
		return read.Projection{}, actions.ErrActionConflict
	}
	if _, err := s.actions.ConfirmExpected(ctx, browserID, token, active.id); err != nil {
		return read.Projection{}, err
	}
	return s.Journey(ctx, browserID, "manage_tasks", "today")
}

func (s *Service) CancelBusiness(ctx context.Context, browserID string) (read.Projection, error) {
	active := s.activeFor(browserID, actions.KindTaskSwitch)
	if active == nil || s.actions == nil {
		return read.Projection{}, actions.ErrActionConflict
	}
	if err := s.actions.Cancel(ctx, browserID, active.id); err != nil {
		return read.Projection{}, err
	}
	return s.Journey(ctx, browserID, "manage_tasks", "today")
}

func (s *Service) selectedTask(ctx context.Context, browserID string) (read.Projection, device.Snapshot, device.Task, read.Task, bool) {
	projection, snapshot, err := s.reader.Present(ctx, "manage_tasks", "today")
	if err != nil {
		return projection, snapshot, device.Task{}, read.Task{}, false
	}
	selected, ok := s.selectionFor(browserID)
	if !ok || selected.choiceSetID != projection.Read.ChoiceSetID || selected.index <= 0 || selected.index > len(snapshot.Tasks) || selected.index > len(projection.Read.Tasks) {
		return projection, snapshot, device.Task{}, read.Task{}, false
	}
	return projection, snapshot, snapshot.Tasks[selected.index-1], projection.Read.Tasks[selected.index-1], true
}

func (s *Service) selectionFor(browserID string) (selection, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	selected, ok := s.selections[browserID]
	return selected, ok
}

func (s *Service) activeFor(browserID, kind string) *activeAction {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.active[browserID][kind]
	if active == nil {
		return nil
	}
	copy := *active
	copy.beforeFields = append([]actions.ParameterField(nil), active.beforeFields...)
	copy.targetFields = append([]actions.ParameterField(nil), active.targetFields...)
	return &copy
}

func (s *Service) setActive(browserID string, active *activeAction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[browserID] == nil {
		s.active[browserID] = map[string]*activeAction{}
	}
	s.active[browserID][active.kind] = active
}

func (s *Service) clearActive(browserID, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active[browserID], kind)
}

func applyTaskStatus(projection *read.Projection, status actions.Status) {
	projection.BusinessConfirmationToken = ""
	projection.Capabilities = read.Capabilities{}
	switch status.State {
	case "proposed":
		projection.State = "awaiting_confirmation"
		projection.Capabilities = read.Capabilities{CanConfirm: true, CanCancel: true}
	case "queued", "claimed":
		projection.State = "queued"
		projection.Conclusion = "授权已接受，等待本机工作线程处理。"
	case "dispatching":
		projection.State = "switching"
		projection.Conclusion = "目标写入已经派发，系统不会重复发送。"
	case "verifying":
		projection.State = "observing"
		projection.Conclusion = "正在执行新鲜回读验证。"
	case "completed":
		projection.State = "complete"
		projection.Conclusion = "任务状态已持久变更并完成验证。"
		projection.Capabilities.CanUndo = true
	case "blocked", "cancelled", "expired":
		projection.State = status.State
		projection.Conclusion = status.Conclusion
	case "unknown":
		projection.State = "outcome_unknown"
		projection.Conclusion = status.Conclusion
	default:
		projection.State = status.State
	}
	if status.Evidence != "" {
		projection.Report = &read.ActionReport{
			BusinessConclusion: status.Conclusion, EvidenceStatus: status.Evidence,
			Dispatches: status.Dispatches, DeviceWrites: status.DeviceWrites,
		}
	}
}
