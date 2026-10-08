package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/kernel"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/result"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

var _ kernel.Handler = (*Service)(nil)

func (s *Service) Validate(ctx context.Context, action ledger.Action) error {
	item, err := s.material(action.ID)
	if err != nil || action.Kind != Kind || item.session != action.SessionBinding || !item.confirmed ||
		action.ResourceKey != digest(item.serial, "deployment-binding", item.meta.Target.SourceID, item.meta.Target.AlgorithmID) {
		return ErrConflict
	}
	connection, client, err := s.connection()
	if err != nil || connection.Serial != item.serial || connection.EndpointFingerprint != item.transport {
		return ErrUnavailable
	}
	snapshot, err := connection.Client.Read(ctx)
	if err != nil || snapshot.Identity.Serial != item.serial {
		return ErrUnavailable
	}
	matched := 0
	for _, source := range snapshot.Cameras {
		if source.ID == item.meta.Target.SourceID && source.SourceFingerprint == item.sourceFingerprint {
			matched++
		}
	}
	if matched != 1 {
		return ErrConflict
	}
	current, err := client.ReadDeployment(ctx, item.meta.Target.SourceID, item.meta.Target.AlgorithmID)
	if err != nil || current.SourceID != item.before.SourceID || current.AlgorithmID != item.before.AlgorithmID || current.Exists != item.before.Exists {
		return ErrConflict
	}
	if current.Exists {
		beforeDigest, beforeErr := configurationDigest(item.before.Configuration)
		currentDigest, currentErr := configurationDigest(current.Configuration)
		if beforeErr != nil || currentErr != nil || beforeDigest != currentDigest || current.TaskID != item.before.TaskID || current.Enabled != item.before.Enabled {
			return ErrConflict
		}
	} else {
		currentDefault, err := client.DefaultDeployment(ctx, item.meta.Target.SourceID, item.meta.Target.AlgorithmID)
		currentDigest, digestErr := configurationDigest(currentDefault)
		if err != nil || digestErr != nil || !currentDefault.Ready || currentDigest != item.meta.ConfigurationDigest {
			return ErrConflict
		}
	}
	return nil
}

func (s *Service) Dispatch(ctx context.Context, action ledger.Action) kernel.Dispatch {
	item, err := s.material(action.ID)
	if err != nil {
		return kernel.Dispatch{Outcome: "outcome_unknown"}
	}
	connection, client, err := s.connection()
	if err != nil || connection.Serial != item.serial || connection.EndpointFingerprint != item.transport {
		return kernel.Dispatch{Outcome: "outcome_unknown"}
	}
	targetEnabled := 0
	if item.meta.Target.Enabled {
		targetEnabled = 1
	}
	if item.before.Exists {
		if item.before.Enabled == targetEnabled {
			return kernel.Dispatch{Outcome: "accepted"} // Repeated business intent needs no write.
		}
		err = connection.Client.SwitchTask(ctx, taskFor(item.before), targetEnabled)
	} else {
		// CosmoEdge SaveOrUpdateTask persists and enables a new binding itself.
		// It must not be followed by a second speculative SwitchTask call.
		err = client.SaveDeployment(ctx, Target{SourceID: item.before.SourceID, AlgorithmID: item.before.AlgorithmID, Configuration: cloneConfiguration(item.target)})
	}
	if err == nil {
		return kernel.Dispatch{Outcome: "accepted", DeviceWriteCount: 1}
	}
	var known interface{ KnownFailure() bool }
	if errors.As(err, &known) && known.KnownFailure() {
		// A native rejection can follow a sent HTTP request; zero here is write accounting, not a network-attempt count.
		return kernel.Dispatch{Outcome: "known_failed", Diagnostic: safediagnostic.FromError(err)}
	}
	return kernel.Dispatch{Outcome: "outcome_unknown", DeviceWriteCount: 1, Diagnostic: safediagnostic.FromError(err)}
}

func (s *Service) Verify(ctx context.Context, action ledger.Action, dispatch kernel.Dispatch) result.Trusted {
	item, err := s.material(action.ID)
	if err != nil {
		return s.trusted(result.Unknown, result.EvidencePending, "部署结果缺少新鲜回读；不会自动重发。", "deployment_authority_unavailable", Observation{})
	}
	connection, client, err := s.connection()
	if err != nil || connection.Serial != item.serial || connection.EndpointFingerprint != item.transport {
		return s.trusted(result.Unknown, result.EvidencePending, "设备连接已变化，部署结果待核对；不会自动重发。", "deployment_connection_changed", Observation{})
	}
	observation := s.observe(ctx, client, item.meta, true)
	if dispatch.Outcome == "outcome_unknown" {
		return s.trusted(result.Unknown, result.EvidenceSealed, "本次设备写入结果不明确；已保留当前回读事实，不会自动重发。", "ambiguous_dispatch_no_replay", observation)
	}
	if dispatch.Outcome == "known_failed" {
		return s.trusted(result.Blocked, result.EvidenceSealed, "设备未接受本次部署操作，当前状态见回读结果。", "deployment_rejected", observation)
	}
	if observation.Exists && observation.ConfigurationMatch && observation.Enabled == 1 && item.meta.Target.Enabled && observation.Runtime == "processing" {
		return s.trusted(result.Completed, result.EvidenceSealed, "指定机位的算法配置和启用状态已回读，处理链路计数持续增长。", "deployment_processing_verified", observation)
	}
	if observation.Exists && observation.ConfigurationMatch && observation.Enabled == 0 && !item.meta.Target.Enabled && observation.Runtime == "stopped" {
		return s.trusted(result.Completed, result.EvidenceSealed, "指定机位的算法已停用，配置保留，运行状态已回读。", "deployment_stopped_verified", observation)
	}
	return s.trusted(result.Unknown, result.EvidenceSealed, "已记录设备响应，但配置、启用状态或处理进度尚未全部验证，可继续查询当前状态。", "deployment_not_fully_verified", observation)
}

func (s *Service) observe(ctx context.Context, client Client, meta metadata, wait bool) Observation {
	duration := s.verifyInterval * 2
	if wait {
		duration = s.verifyDuration
	}
	bounded, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	// A failed read has no observation time. Do not turn default values into
	// fresh evidence that the binding is absent or its configuration changed.
	observation := Observation{SourceID: meta.Target.SourceID, AlgorithmID: meta.Target.AlgorithmID, Enabled: -1, Runtime: "unknown"}
	state, err := client.ReadDeployment(bounded, meta.Target.SourceID, meta.Target.AlgorithmID)
	if err != nil || state.SourceID != meta.Target.SourceID || state.AlgorithmID != meta.Target.AlgorithmID || state.ObservedAt.IsZero() {
		return observation
	}
	observation.TaskID, observation.Exists, observation.Enabled, observation.ObservedAt = state.TaskID, state.Exists, state.Enabled, state.ObservedAt
	currentDigest, err := configurationDigest(state.Configuration)
	observation.ConfigurationMatch = err == nil && currentDigest == meta.ConfigurationDigest
	if !state.Exists || state.TaskID == "" {
		return observation
	}
	var before Runtime
	for {
		after, readErr := client.ReadDeploymentRuntime(bounded, taskFor(state))
		if readErr == nil && after.TaskID == state.TaskID && after.Known {
			if state.Enabled == 0 && after.Stopped {
				observation.Runtime, observation.ObservedAt = "stopped", after.ObservedAt
				break
			}
			if progress, ok := progressBetween(before, after, state.TaskID); ok {
				observation.Runtime, observation.Progress, observation.ObservedAt = "processing", progress, after.ObservedAt
				break
			}
			before = after
			observation.Runtime = "processing_unconfirmed"
		}
		timer := time.NewTimer(s.verifyInterval)
		select {
		case <-bounded.Done():
			timer.Stop()
			return observation
		case <-timer.C:
		}
	}
	// Processing evidence is only attached to the configuration/enable state
	// that still exists after the two runtime samples.
	final, err := client.ReadDeployment(bounded, meta.Target.SourceID, meta.Target.AlgorithmID)
	finalDigest, digestErr := configurationDigest(final.Configuration)
	if err != nil || digestErr != nil || final.TaskID != state.TaskID || !final.Exists || final.Enabled != state.Enabled || finalDigest != currentDigest {
		observation.Runtime, observation.ConfigurationMatch = "unknown", false
		observation.Progress = nil
	}
	return observation
}

func (s *Service) trusted(class result.Class, evidence result.EvidenceStatus, conclusion, reason string, observation Observation) result.Trusted {
	raw, err := json.Marshal(observation)
	if err != nil {
		raw = []byte(`{}`)
	}
	return result.Trusted{Class: class, EvidenceStatus: evidence, Conclusion: conclusion, Reason: reason, EvidenceJSON: string(raw), ObservedAt: s.now().UTC()}
}

func taskFor(state State) device.Task {
	return device.Task{ID: state.TaskID, ChannelID: state.SourceID, AlgorithmID: state.AlgorithmID, Enabled: state.Enabled, SwitchVerified: state.Enabled == 0 || state.Enabled == 1}
}
