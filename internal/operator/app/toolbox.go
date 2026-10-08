package app

import (
	"context"
	"errors"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/actions"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

type ToolboxView struct {
	State                     string                   `json:"state"`
	Conclusion                string                   `json:"conclusion,omitempty"`
	Evidence                  string                   `json:"evidence,omitempty"`
	BusinessConfirmationToken string                   `json:"businessConfirmationToken,omitempty"`
	CanEdit                   bool                     `json:"canEdit,omitempty"`
	CanCreate                 bool                     `json:"canCreate,omitempty"`
	CanConfirm                bool                     `json:"canConfirm,omitempty"`
	CanCancel                 bool                     `json:"canCancel,omitempty"`
	CanReset                  bool                     `json:"canReset,omitempty"`
	DeviceWrites              int                      `json:"deviceWrites"`
	Dispatches                int                      `json:"dispatches"`
	Fields                    []actions.ParameterField `json:"fields,omitempty"`
	TaskName                  string                   `json:"taskName,omitempty"`
	CameraName                string                   `json:"cameraName,omitempty"`
	AlgorithmName             string                   `json:"algorithmName,omitempty"`
	Name                      string                   `json:"name,omitempty"`
	CatalogCountBefore        int                      `json:"catalogCountBefore,omitempty"`
	CatalogCountTarget        int                      `json:"catalogCountTarget,omitempty"`
}

func (s *Service) TaskParameters(ctx context.Context, browserID string) (ToolboxView, error) {
	active := s.activeFor(browserID, actions.KindTaskParameters)
	if active != nil && s.actions != nil {
		status, err := s.actions.Status(ctx, active.id)
		if err == nil && !toolboxTerminal(status.State) {
			view := ToolboxView{
				TaskName: active.selected.DisplayName, CameraName: active.selected.CameraName,
				AlgorithmName: active.selected.AlgorithmName,
			}
			if status.State == "proposed" {
				view.Fields = parameterDiff(active.beforeFields, active.targetFields)
			}
			applyToolboxStatus(&view, status, true)
			return view, nil
		}
	}
	_, snapshot, rawTask, selected, ok := s.selectedTask(ctx, browserID)
	if !ok || s.actions == nil {
		return ToolboxView{State: "blocked", Conclusion: "请刷新任务目录并重新选择任务。"}, nil
	}
	fields, err := s.actions.CurrentTaskParameters(ctx, snapshot, rawTask)
	if err != nil {
		return ToolboxView{State: "blocked", Conclusion: "任务参数新鲜回读不可用。"}, nil
	}
	view := ToolboxView{
		State: "editable", CanEdit: true, Fields: fields,
		TaskName: selected.DisplayName, CameraName: selected.CameraName, AlgorithmName: selected.AlgorithmName,
	}
	if active == nil {
		return view, nil
	}
	status, err := s.actions.Status(ctx, active.id)
	if err != nil {
		return view, nil
	}
	if status.State == "proposed" && len(active.targetFields) > 0 {
		view.Fields = parameterDiff(active.beforeFields, active.targetFields)
	}
	applyToolboxStatus(&view, status, true)
	return view, nil
}

func (s *Service) PrepareTaskParameters(ctx context.Context, browserID string, target []actions.ParameterField) (ToolboxView, error) {
	_, snapshot, rawTask, selected, ok := s.selectedTask(ctx, browserID)
	if !ok || s.actions == nil {
		return ToolboxView{}, actions.ErrActionUnavailable
	}
	before, err := s.actions.CurrentTaskParameters(ctx, snapshot, rawTask)
	if err != nil {
		return ToolboxView{}, err
	}
	deviceTarget := make([]device.ParameterField, 0, len(target))
	for _, field := range target {
		deviceTarget = append(deviceTarget, device.ParameterField{Key: field.Key, Value: field.Value})
	}
	proposal, err := s.actions.PrepareTaskParameters(ctx, browserID, snapshot, rawTask, deviceTarget)
	if err != nil {
		return ToolboxView{}, err
	}
	active := &activeAction{
		id: proposal.ActionID, kind: actions.KindTaskParameters, selected: selected,
		beforeFields: append([]actions.ParameterField(nil), before...), targetFields: append([]actions.ParameterField(nil), target...),
	}
	s.setActive(browserID, active)
	return ToolboxView{
		State: "awaiting_approval", Conclusion: "参数变更方案已准备，尚未写入设备。",
		BusinessConfirmationToken: proposal.ConfirmationToken, CanConfirm: true, CanCancel: true,
		Fields: parameterDiff(before, target), TaskName: selected.DisplayName, CameraName: selected.CameraName, AlgorithmName: selected.AlgorithmName,
	}, nil
}

func (s *Service) ConfirmTaskParameters(ctx context.Context, browserID, token string) (ToolboxView, error) {
	active := s.activeFor(browserID, actions.KindTaskParameters)
	if active == nil || s.actions == nil {
		return ToolboxView{}, actions.ErrActionConflict
	}
	if _, err := s.actions.ConfirmExpected(ctx, browserID, token, active.id); err != nil {
		return ToolboxView{}, err
	}
	s.clearActiveFields(browserID, actions.KindTaskParameters)
	return s.localToolboxStatus(ctx, active, true)
}

func (s *Service) CancelTaskParameters(ctx context.Context, browserID string) (ToolboxView, error) {
	active := s.activeFor(browserID, actions.KindTaskParameters)
	if active == nil || s.actions == nil {
		return ToolboxView{}, actions.ErrActionConflict
	}
	if err := s.actions.Cancel(ctx, browserID, active.id); err != nil {
		return ToolboxView{}, err
	}
	s.clearActiveFields(browserID, actions.KindTaskParameters)
	return s.TaskParameters(ctx, browserID)
}

func (s *Service) ResetTaskParameters(ctx context.Context, browserID string) (ToolboxView, error) {
	if err := s.resetActive(ctx, browserID, actions.KindTaskParameters); err != nil {
		return ToolboxView{}, err
	}
	return s.TaskParameters(ctx, browserID)
}

func (s *Service) CameraSource(ctx context.Context, browserID string) (ToolboxView, error) {
	active := s.activeFor(browserID, actions.KindCameraSource)
	if active != nil && s.actions != nil {
		return s.localToolboxStatus(ctx, active, false)
	}
	projection, _, err := s.reader.Present(ctx, "manage_sources", "today")
	if err != nil || projection.State == "disconnected" || s.actions == nil {
		return ToolboxView{State: "blocked", Conclusion: "视频源目录新鲜回读不可用。"}, nil
	}
	view := ToolboxView{State: "editable", CanCreate: true}
	return view, nil
}

func (s *Service) PrepareCameraSource(ctx context.Context, browserID, name string, sourceURL []byte) (ToolboxView, error) {
	if s.actions == nil {
		clear(sourceURL)
		return ToolboxView{}, actions.ErrActionUnavailable
	}
	proposal, err := s.actions.PrepareCameraSource(ctx, browserID, name, sourceURL)
	if err != nil {
		return ToolboxView{}, err
	}
	s.setActive(browserID, &activeAction{
		id: proposal.ActionID, kind: actions.KindCameraSource, sourceName: name, catalogBefore: proposal.CatalogCountBefore,
	})
	return ToolboxView{
		State: "awaiting_approval", Conclusion: "视频源创建方案已准备，地址仅保留在当前本机进程。",
		BusinessConfirmationToken: proposal.ConfirmationToken, CanConfirm: true, CanCancel: true,
		Name: name, CatalogCountBefore: proposal.CatalogCountBefore, CatalogCountTarget: proposal.CatalogCountTarget,
	}, nil
}

func (s *Service) ConfirmCameraSource(ctx context.Context, browserID, token string) (ToolboxView, error) {
	active := s.activeFor(browserID, actions.KindCameraSource)
	if active == nil || s.actions == nil {
		return ToolboxView{}, actions.ErrActionConflict
	}
	if _, err := s.actions.ConfirmExpected(ctx, browserID, token, active.id); err != nil {
		return ToolboxView{}, err
	}
	return s.localToolboxStatus(ctx, active, false)
}

func (s *Service) CancelCameraSource(ctx context.Context, browserID string) (ToolboxView, error) {
	active := s.activeFor(browserID, actions.KindCameraSource)
	if active == nil || s.actions == nil {
		return ToolboxView{}, actions.ErrActionConflict
	}
	if err := s.actions.Cancel(ctx, browserID, active.id); err != nil {
		return ToolboxView{}, err
	}
	return s.CameraSource(ctx, browserID)
}

func (s *Service) ResetCameraSource(ctx context.Context, browserID string) (ToolboxView, error) {
	if err := s.resetActive(ctx, browserID, actions.KindCameraSource); err != nil {
		return ToolboxView{}, err
	}
	return s.CameraSource(ctx, browserID)
}

func (s *Service) resetActive(ctx context.Context, browserID, kind string) error {
	active := s.activeFor(browserID, kind)
	if active == nil {
		return nil
	}
	if s.actions == nil {
		return actions.ErrActionUnavailable
	}
	status, err := s.actions.Status(ctx, active.id)
	if err != nil {
		return err
	}
	if status.State != "completed" && status.State != "blocked" && status.State != "unknown" && status.State != "cancelled" && status.State != "expired" {
		return errors.New("active action is not terminal")
	}
	s.clearActive(browserID, kind)
	return nil
}

func (s *Service) clearActiveFields(browserID, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.active[browserID][kind]
	if active == nil {
		return
	}
	for index := range active.beforeFields {
		active.beforeFields[index].Value = ""
	}
	for index := range active.targetFields {
		active.targetFields[index].Value = ""
	}
	active.beforeFields, active.targetFields = nil, nil
}

func parameterDiff(before, target []actions.ParameterField) []actions.ParameterField {
	byKey := map[string]string{}
	for _, field := range before {
		byKey[field.Key] = field.Value
	}
	result := make([]actions.ParameterField, 0, len(target))
	for _, field := range target {
		result = append(result, actions.ParameterField{
			Key: field.Key, Value: field.Value, Before: byKey[field.Key], Changed: byKey[field.Key] != field.Value,
		})
	}
	return result
}

func applyToolboxStatus(view *ToolboxView, status actions.Status, parameters bool) {
	view.BusinessConfirmationToken = ""
	view.CanEdit, view.CanCreate, view.CanConfirm, view.CanCancel, view.CanReset = false, false, false, false, false
	view.DeviceWrites, view.Dispatches = status.DeviceWrites, status.Dispatches
	view.Evidence, view.Conclusion = status.Evidence, status.Conclusion
	switch status.State {
	case "proposed":
		view.State, view.CanConfirm, view.CanCancel = "awaiting_approval", true, true
	case "queued", "claimed", "dispatching":
		view.State = "executing"
	case "verifying":
		view.State = "verifying"
	case "completed":
		view.State, view.CanEdit, view.CanReset = "succeeded", parameters, true
	case "blocked":
		view.State, view.CanEdit, view.CanReset = "blocked", parameters, true
	case "unknown":
		view.State, view.CanReset = "outcome_unknown", true
	case "cancelled", "expired":
		view.State, view.CanReset = status.State, true
	default:
		view.State = status.State
	}
}

func (s *Service) localToolboxStatus(ctx context.Context, active *activeAction, parameters bool) (ToolboxView, error) {
	status, err := s.actions.Status(ctx, active.id)
	if err != nil {
		return ToolboxView{}, err
	}
	view := ToolboxView{
		TaskName: active.selected.DisplayName, CameraName: active.selected.CameraName,
		AlgorithmName: active.selected.AlgorithmName, Name: active.sourceName,
		CatalogCountBefore: active.catalogBefore, CatalogCountTarget: active.catalogBefore + 1,
	}
	applyToolboxStatus(&view, status, parameters)
	return view, nil
}

func toolboxTerminal(state string) bool {
	switch state {
	case "completed", "blocked", "unknown", "cancelled", "expired":
		return true
	default:
		return false
	}
}
