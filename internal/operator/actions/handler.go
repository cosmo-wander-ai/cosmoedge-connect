package actions

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/kernel"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
)

func (m *Manager) Validate(ctx context.Context, action ledger.Action) error {
	err := m.validate(ctx, action)
	if err != nil {
		m.vault.delete(action.ID)
	}
	return err
}

func (m *Manager) validate(ctx context.Context, action ledger.Action) error {
	item, err := m.vault.get(action.ID)
	if err != nil {
		return err
	}
	if item.kind != action.Kind || item.sessionBinding != action.SessionBinding || item.resourceKey != action.ResourceKey {
		return ErrActionConflict
	}
	connection, err := m.provider.ActionConnection()
	if err != nil || connection.Client == nil || connection.Serial != item.serial || connection.EndpointFingerprint != item.endpointFingerprint {
		return ErrActionUnavailable
	}
	snapshot, err := connection.Client.Read(ctx)
	if err != nil || snapshot.Identity.Serial != item.serial {
		return ErrActionUnavailable
	}
	switch item.kind {
	case KindTaskSwitch:
		current, ok := findTask(snapshot, item.task)
		if !ok || current.Enabled != item.originalSwitch {
			return errors.New("task switch precondition changed")
		}
	case KindTaskParameters:
		current, ok := findTask(snapshot, item.task)
		if !ok || current.Enabled != item.task.Enabled {
			return errors.New("task parameter binding changed")
		}
	case KindCameraSource:
		if cameraNameExists(snapshot.Cameras, item.sourceName) || len(snapshot.Cameras) != item.catalogCountBefore || cameraCatalogFingerprint(snapshot.Cameras) != item.catalogFingerprint {
			return errors.New("camera source catalog changed")
		}
	default:
		return errors.New("unsupported action kind")
	}
	return nil
}

func (m *Manager) Dispatch(ctx context.Context, action ledger.Action) kernel.Dispatch {
	item, err := m.vault.get(action.ID)
	if err != nil {
		return kernel.Dispatch{Outcome: "outcome_unknown"}
	}
	connection, err := m.provider.ActionConnection()
	if err != nil || connection.Client == nil || connection.Serial != item.serial || connection.EndpointFingerprint != item.endpointFingerprint {
		return kernel.Dispatch{Outcome: "outcome_unknown"}
	}
	switch item.kind {
	case KindTaskSwitch:
		err = connection.Client.SwitchTask(ctx, item.task, item.targetSwitch)
	case KindTaskParameters:
		err = connection.Client.UpdateTaskParameters(ctx, item.task, cloneFields(item.targetParameters))
	case KindCameraSource:
		source := append([]byte(nil), item.sourceURL...)
		err = connection.Client.AddCameraSource(ctx, item.sourceName, source)
		clear(source)
	default:
		return kernel.Dispatch{Outcome: "outcome_unknown"}
	}
	return classifyDispatch(err)
}

func (m *Manager) Verify(ctx context.Context, action ledger.Action, dispatch kernel.Dispatch) result.Trusted {
	item, err := m.vault.get(action.ID)
	if err != nil {
		return m.unverified("foreground_action_material_unavailable")
	}
	defer func() {
		clear(item.sourceURL)
		m.vault.delete(action.ID)
	}()
	connection, err := m.provider.ActionConnection()
	if err != nil || connection.Client == nil || connection.Serial != item.serial || connection.EndpointFingerprint != item.endpointFingerprint {
		return m.unverified("connection_binding_unavailable")
	}
	switch item.kind {
	case KindTaskSwitch:
		return m.verifyTaskSwitch(ctx, connection.Client, item, dispatch)
	case KindTaskParameters:
		return m.verifyTaskParameters(ctx, connection.Client, item, dispatch)
	case KindCameraSource:
		return m.verifyCameraSource(ctx, connection.Client, item, dispatch)
	default:
		return m.unverified("unsupported_action_kind")
	}
}

func (m *Manager) verifyTaskSwitch(ctx context.Context, client device.ActionClient, item *material, dispatch kernel.Dispatch) result.Trusted {
	snapshot, err := client.Read(ctx)
	if err != nil || snapshot.Identity.Serial != item.serial {
		return m.unverified("fresh_task_read_unavailable")
	}
	current, ok := findTask(snapshot, item.task)
	if !ok {
		return m.unverified("task_binding_unavailable")
	}
	if dispatch.Outcome == "outcome_unknown" {
		return m.trusted(result.Unknown, result.EvidenceSealed, "写入结果尚不明确；系统不会重发目标写入。", "ambiguous_dispatch_no_replay", map[string]any{"verification": switchObservation(current.Enabled, item)})
	}
	if dispatch.Outcome == "known_failed" && current.Enabled == item.originalSwitch {
		return m.trusted(result.Blocked, result.EvidenceSealed, "设备明确拒绝或尚未开始本次写入。", "device_rejected_without_write", map[string]any{"verification": "original"})
	}
	if dispatch.Outcome == "accepted" && current.Enabled == item.targetSwitch {
		return m.trusted(result.Completed, result.EvidenceSealed, "设备已达到授权目标。", "fresh_read_matches_target", map[string]any{"verification": "target"})
	}
	return m.trusted(result.Unknown, result.EvidenceSealed, "设备状态与本次授权结果不一致；系统不会重发。", "post_dispatch_external_drift", map[string]any{"verification": switchObservation(current.Enabled, item)})
}

func (m *Manager) verifyTaskParameters(ctx context.Context, client device.ActionClient, item *material, _ kernel.Dispatch) result.Trusted {
	fields, err := client.ReadTaskParameters(ctx, item.task)
	if err != nil {
		return m.unverified("fresh_parameter_read_unavailable")
	}
	fields, err = normalizeFields(fields)
	if err != nil {
		return m.unverified("fresh_parameter_read_invalid")
	}
	if sameFields(fields, item.targetParameters) {
		return m.trusted(result.Completed, result.EvidenceSealed, "任务参数已达到授权目标。", "fresh_read_matches_target", map[string]any{"verification": "target", "changedCount": changedFieldCount(item.beforeParameters, item.targetParameters)})
	}
	reason := "parameter_target_not_observed"
	if !sameFields(fields, item.beforeParameters) {
		reason = "post_dispatch_external_drift"
	}
	return m.trusted(result.Blocked, result.EvidenceSealed, "任务参数未达到授权目标，已停止后续写入。", reason, map[string]any{"verification": "not_target"})
}

func (m *Manager) verifyCameraSource(ctx context.Context, client device.ActionClient, item *material, _ kernel.Dispatch) result.Trusted {
	snapshot, err := client.Read(ctx)
	if err != nil || snapshot.Identity.Serial != item.serial {
		return m.unverified("fresh_camera_catalog_unavailable")
	}
	matches := 0
	for _, camera := range snapshot.Cameras {
		if camera.Name == item.sourceName && camera.SourceFingerprint == item.sourceFingerprint {
			matches++
		}
	}
	if matches == 1 && len(snapshot.Cameras) == item.catalogCountBefore+1 {
		return m.trusted(result.Completed, result.EvidenceSealed, "网络视频源已创建并完成新鲜回读。", "fresh_read_matches_target", map[string]any{"verification": "target", "catalogCount": len(snapshot.Cameras)})
	}
	return m.trusted(result.Blocked, result.EvidenceSealed, "网络视频源未达到授权目标，已停止后续写入。", "camera_source_target_not_observed", map[string]any{"verification": "not_target", "catalogCount": len(snapshot.Cameras)})
}

func classifyDispatch(err error) kernel.Dispatch {
	if err == nil {
		return kernel.Dispatch{Outcome: "accepted", DeviceWriteCount: 1}
	}
	var known interface{ KnownFailure() bool }
	if errors.As(err, &known) && known.KnownFailure() {
		return kernel.Dispatch{Outcome: "known_failed", DeviceWriteCount: 0}
	}
	return kernel.Dispatch{Outcome: "outcome_unknown", DeviceWriteCount: 1}
}

func (m *Manager) unverified(reason string) result.Trusted {
	return m.trusted(result.Unknown, result.EvidencePending, "结果缺少新鲜回读，系统不会重发。", reason, map[string]any{"verification": "unavailable"})
}

func (m *Manager) trusted(class result.Class, evidence result.EvidenceStatus, conclusion, reason string, payload map[string]any) result.Trusted {
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{}`)
	}
	return result.Trusted{
		Class: class, EvidenceStatus: evidence, Conclusion: conclusion, Reason: reason,
		EvidenceJSON: string(raw), ObservedAt: m.now().UTC(),
	}
}

func switchObservation(current int, item *material) string {
	if current == item.targetSwitch {
		return "target"
	}
	if current == item.originalSwitch {
		return "original"
	}
	return "other"
}

var _ kernel.Handler = (*Manager)(nil)
