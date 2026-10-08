package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var _ DeploymentClient = (*v1Client)(nil)

func (c *v1Client) ReadDeployment(ctx context.Context, sourceID, algorithmID string) (DeploymentState, error) {
	state := DeploymentState{SourceID: sourceID, AlgorithmID: algorithmID, Enabled: -1, ObservedAt: time.Now().UTC()}
	if !validDeploymentID(sourceID) || !validDeploymentID(algorithmID) {
		return state, errors.New("invalid deployment target")
	}
	rows, err := c.readCameraRows(ctx)
	if err != nil {
		return state, err
	}
	sources, bindings := 0, 0
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return state, errors.New("invalid deployment source row")
		}
		if stringValue(row, "videoChannelId", "channelId", "id") != sourceID {
			continue
		}
		sources++
		tasks, ok := arrayValue(row, "taskList", "tasks")
		if !ok {
			return state, errors.New("deployment bindings are unavailable")
		}
		for _, rawTask := range tasks {
			task, ok := rawTask.(map[string]any)
			if !ok {
				return state, errors.New("invalid deployment binding row")
			}
			if stringValue(task, "algorithmId", "algorithmCode") == algorithmID {
				bindings++
				state.TaskID = canonicalTaskID(sourceID, algorithmID, stringValue(task, "id", "taskId"))
			}
		}
	}
	if sources != 1 || bindings > 1 {
		return state, errors.New("deployment target is missing or ambiguous")
	}
	if bindings == 0 {
		return state, nil
	}
	state.Exists = true
	// selectConfigByAlgorithmId masks some missing-binding errors, therefore
	// existence above comes from the catalog and switch is independently read.
	response, err := c.client.QueryTaskConfigContext(ctx, sourceID, algorithmID)
	if err != nil {
		return state, err
	}
	state.Configuration, err = retainedConfiguration(response)
	if err != nil {
		return state, err
	}
	schedules, err := c.deploymentSchedules(ctx)
	if err != nil {
		return state, err
	}
	plan, ok := schedules[eventString(response, "scheduleId")]
	if !ok {
		return state, errors.New("configured deployment schedule is unavailable")
	}
	state.Configuration.ScheduleDigest = plan.digest
	switchResponse, err := c.client.QueryTaskSwitchContext(ctx, map[string]any{"channelId": sourceID, "algorithmId": algorithmID})
	if err != nil {
		return state, err
	}
	enabled, enabledOK := firstInt(switchResponse, "enable", "switch")
	configEnabled, configOK := firstInt(response, "taskEnableStatus")
	if !enabledOK || !configOK || (enabled != 0 && enabled != 1) || enabled != configEnabled {
		return state, errors.New("deployment switch reads do not agree")
	}
	state.Enabled, state.ObservedAt = enabled, time.Now().UTC()
	return state, nil
}

func retainedConfiguration(response map[string]any) (DeploymentConfiguration, error) {
	config, ok := response["taskConfig"].(map[string]any)
	if !ok {
		return DeploymentConfiguration{}, errors.New("native task configuration is unavailable")
	}
	if _, ok := config["params"].([]any); !ok {
		return DeploymentConfiguration{}, errors.New("native task parameters are unavailable")
	}
	scheduleID := eventString(response, "scheduleId")
	if scheduleID == "" {
		return DeploymentConfiguration{}, errors.New("native task schedule is unavailable")
	}
	raw, err := json.Marshal(map[string]any{"taskConfig": config, "scheduleId": scheduleID})
	if err != nil {
		return DeploymentConfiguration{}, err
	}
	return DeploymentConfiguration{Document: raw, Shape: "native_task_config", Ready: true}, nil
}

func (c *v1Client) DefaultDeployment(ctx context.Context, sourceID, algorithmID string) (DeploymentConfiguration, error) {
	if !validDeploymentID(sourceID) || !validDeploymentID(algorithmID) {
		return DeploymentConfiguration{}, errors.New("invalid deployment target")
	}
	response, err := c.client.QueryTaskConfigContext(ctx, sourceID, algorithmID)
	if err != nil {
		return DeploymentConfiguration{}, err
	}
	var metadata map[string]any
	switch raw := response["algorithmMetadata"].(type) {
	case string:
		if json.Unmarshal([]byte(raw), &metadata) != nil {
			return DeploymentConfiguration{}, errors.New("algorithm defaults are invalid")
		}
	case map[string]any:
		metadata = raw
	default:
		return DeploymentConfiguration{}, errors.New("algorithm defaults are unavailable")
	}
	schedules, err := c.deploymentSchedules(ctx)
	if err != nil {
		return DeploymentConfiguration{}, err
	}
	var candidates []string
	for id, plan := range schedules {
		if plan.continuous {
			candidates = append(candidates, id)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return DeploymentConfiguration{Missing: []string{"设备上已有的全天运行计划"}}, nil
	}
	configuration, err := defaultDeploymentConfiguration(sourceID, algorithmID, candidates[0], metadata)
	configuration.ScheduleDigest = schedules[candidates[0]].digest
	return configuration, err
}

func defaultDeploymentConfiguration(sourceID, algorithmID, scheduleID string, metadata map[string]any) (DeploymentConfiguration, error) {
	configuration := DeploymentConfiguration{Shape: "native_task_config", Missing: []string{}}
	rows, ok := metadata["params"].([]any)
	if !ok {
		return configuration, errors.New("algorithm parameter defaults are unavailable")
	}
	params := make([]any, 0, len(rows))
	seen := map[string]bool{}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return configuration, errors.New("invalid algorithm parameter default")
		}
		key := eventString(row, "key")
		if key == "" || seen[key] {
			return configuration, errors.New("algorithm default keys are incomplete or duplicated")
		}
		seen[key] = true
		param := map[string]any{"key": key}
		value, exists := row["defaultValue"]
		if exists && value != nil && value != "" {
			switch typed := value.(type) {
			case string:
				param["value"] = typed
			case float64:
				param["value"] = fmt.Sprint(typed)
			case bool:
				if typed {
					param["value"] = "1"
				} else {
					param["value"] = "0"
				}
			case []any:
				parts := make([]string, 0, len(typed))
				for _, part := range typed {
					text, ok := part.(string)
					if !ok {
						return configuration, errors.New("algorithm option defaults require local input")
					}
					parts = append(parts, text)
				}
				param["value"] = strings.Join(parts, ",")
			default:
				return configuration, errors.New("unsupported algorithm default structure")
			}
		} else if eventString(row, "regexpr") != "" {
			configuration.Missing = append(configuration.Missing, "参数："+firstNonEmpty(eventString(row, "name"), key))
		}
		params = append(params, param)
	}
	areas := []any{}
	regionType := eventString(metadata, "regionType")
	fullFrame, _ := metadata["defaultFullScreen"].(bool)
	if regionType != "" && regionType != "none" {
		if !fullFrame || regionType == "cordon" || regionType == "oneWayCordon" {
			configuration.Missing = append(configuration.Missing, "检测区域或检测线")
		} else {
			sum := sha256.Sum256([]byte(sourceID + "\x00" + algorithmID + "\x00default-full-frame"))
			areas = append(areas, map[string]any{"areaId": "cosmoedge-connect-" + hex.EncodeToString(sum[:12]), "name": "全画面",
				"points":          []any{map[string]any{"xRatio": 0, "yRatio": 0}, map[string]any{"xRatio": 1, "yRatio": 0}, map[string]any{"xRatio": 1, "yRatio": 1}, map[string]any{"xRatio": 0, "yRatio": 1}},
				"associatedAreas": []any{}, "linePoints": []any{}, "params": []any{map[string]any{"key": "name", "value": "全画面"}}})
		}
	}
	if required, _ := metadata["enableShieldedRegion"].(bool); required {
		configuration.Missing = append(configuration.Missing, "屏蔽区域")
	}
	raw, err := json.Marshal(map[string]any{"scheduleId": scheduleID, "taskConfig": map[string]any{"params": params, "areas": areas, "shieldedAreas": []any{}, "facesetConfig": []any{}}})
	if err != nil {
		return configuration, err
	}
	configuration.Document, configuration.Ready = raw, len(configuration.Missing) == 0
	return configuration, nil
}

func (c *v1Client) SaveDeployment(ctx context.Context, target DeploymentTarget) error {
	if !validDeploymentID(target.SourceID) || !validDeploymentID(target.AlgorithmID) || !target.Configuration.Ready || len(target.Configuration.Document) == 0 || len(target.Configuration.Document) > 1<<20 {
		return errors.New("invalid deployment target or configuration")
	}
	var configuration map[string]any
	if json.Unmarshal(target.Configuration.Document, &configuration) != nil || len(configuration) != 2 {
		return errors.New("invalid native deployment configuration")
	}
	config, ok := configuration["taskConfig"].(map[string]any)
	scheduleID := eventString(configuration, "scheduleId")
	if !ok || scheduleID == "" {
		return errors.New("deployment config and schedule are required")
	}
	return c.client.SaveTaskConfigurationContext(ctx, map[string]any{"channelId": target.SourceID, "algorithmId": target.AlgorithmID, "taskConfig": config, "scheduleId": scheduleID})
}

func (c *v1Client) ReadDeploymentRuntime(ctx context.Context, task Task) (DeploymentRuntime, error) {
	result := DeploymentRuntime{TaskID: task.ID, Counters: map[string]uint64{}, ObservedAt: time.Now().UTC()}
	if !validDeploymentID(task.ID) || !validDeploymentID(task.ChannelID) || !validDeploymentID(task.AlgorithmID) {
		return result, errors.New("invalid runtime target")
	}
	response, err := c.client.QueryTaskRunningDetailContext(ctx, []string{task.ID})
	if err != nil {
		return result, err
	}
	rows, ok := arrayValue(response, "status")
	if !ok {
		return result, errors.New("runtime rows are unavailable")
	}
	if len(rows) == 0 {
		result.Known, result.Stopped = true, true
		return result, nil
	}
	matches, healthy, stopped, inferenceNodes, decoderNodes := 0, true, true, 0, 0
	localCounters := map[string]map[string]uint64{"AA_00003": {}, "BA_00005": {}}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok || eventString(row, "taskId") != task.ID || eventString(row, "channelId") != task.ChannelID || eventString(row, "algorithmId") != task.AlgorithmID {
			return result, errors.New("runtime response changed target")
		}
		matches++
		actions, ok := arrayValue(row, "actionStatus")
		if !ok {
			return result, errors.New("runtime processing nodes are unavailable")
		}
		for _, rawAction := range actions {
			action, ok := rawAction.(map[string]any)
			if !ok {
				return result, errors.New("invalid runtime node")
			}
			id := eventString(action, "actionId")
			status, statusOK := eventInteger(action["statusCode"])
			if !statusOK {
				return result, errors.New("runtime node status is invalid")
			}
			// Ready/started nodes may legitimately have no target input. Known
			// initialization, model, source or processing failures must still
			// prevent a healthy-runtime result even if other counters increase.
			if status != 0 && status != 12288 && status != 12289 && status != 12300 && status != 16777217 {
				healthy = false
			}
			// These frame-inference actions are verified against the V1 runtime
			// source. Target-dependent classifiers, alarms and decoders do not
			// establish primary inference progress when no target is present.
			primary := id == "AA_00001" || id == "DA_00003"
			decoder := id == "BA_00001 DECODE"
			// V1 attaches shared AiDetector queue counts to every bound task.
			// AlgActionBase instead names each task-local queue taskId-name-flowId.
			// AiTracker and AreaAlarm consume frames even without targets/alarms;
			// their own queue proves this task received downstream inference data.
			if counters, supported := localCounters[id]; supported && strings.HasPrefix(eventString(action, "name"), task.ID+"-") {
				count, countOK := eventInteger(action["processCount"])
				key := eventString(row, "algorithmVersion") + ":" + id + ":" + eventString(action, "name")
				if _, duplicate := counters[key]; duplicate || !countOK || count < 0 {
					return result, errors.New("task-local runtime counter or identity is invalid")
				}
				counters[key] = uint64(count)
			}
			if !primary && !decoder {
				continue
			}
			if primary {
				inferenceNodes++
			}
			if decoder {
				decoderNodes++
			}
			count, countOK := eventInteger(action["processCount"])
			key := eventString(row, "algorithmVersion") + ":" + id + ":" + eventString(action, "name")
			if _, duplicate := result.Counters[key]; duplicate || !countOK || count < 0 || !statusOK {
				return result, errors.New("runtime counter or node identity is invalid")
			}
			result.Counters[key] = uint64(count)
			if status != 0 {
				healthy = false
			}
			if primary && status != 4 && status != 12288 && status != 12290 {
				stopped = false
			}
		}
	}
	// Prefer the tracker, which consumes every detection frame. Requiring a
	// later alarm branch too could conflate target-gated routing with a stall.
	local := localCounters["AA_00003"]
	if len(local) == 0 {
		local = localCounters["BA_00005"]
	}
	for id, count := range local {
		result.Counters[id] = count
	}
	result.Known = matches == 1 && inferenceNodes > 0 && decoderNodes == 1 && len(local) > 0
	result.Active, result.Stopped, result.ObservedAt = result.Known && healthy, result.Known && stopped, time.Now().UTC()
	return result, nil
}

func validDeploymentID(id string) bool {
	return id != "" && strings.TrimSpace(id) == id && len(id) <= 256 && !strings.ContainsAny(id, "\x00\r\n")
}

type deploymentSchedule struct {
	digest     string
	continuous bool
}

func (c *v1Client) deploymentSchedules(ctx context.Context) (map[string]deploymentSchedule, error) {
	response, err := c.client.QueryDeploymentSchedulesContext(ctx)
	if err != nil {
		return nil, err
	}
	rows, ok := arrayValue(response, "rows")
	total, totalOK := eventInteger(response["total"])
	if !ok || !totalOK || total != int64(len(rows)) || len(rows) > 1000 {
		return nil, errors.New("deployment schedule catalog is incomplete")
	}
	result := map[string]deploymentSchedule{}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid deployment schedule")
		}
		id := eventString(row, "scheduleId")
		if _, duplicate := result[id]; id == "" || duplicate {
			return nil, errors.New("deployment schedules are ambiguous")
		}
		configuration, ok := row["scheduleConfig"].([]any)
		if !ok {
			return nil, errors.New("deployment schedule configuration is unavailable")
		}
		encoded, err := json.Marshal(configuration)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(encoded)
		days := map[int64]bool{}
		for _, rawDay := range configuration {
			day, ok := rawDay.(map[string]any)
			if !ok {
				return nil, errors.New("invalid deployment schedule day")
			}
			weekday, ok := eventInteger(day["weekDay"])
			if !ok || weekday < 0 || weekday > 6 {
				return nil, errors.New("invalid deployment schedule weekday")
			}
			periods, ok := day["runTime"].([]any)
			if !ok {
				return nil, errors.New("invalid deployment schedule periods")
			}
			for _, rawPeriod := range periods {
				period, ok := rawPeriod.(map[string]any)
				if !ok {
					return nil, errors.New("invalid deployment schedule period")
				}
				if eventString(period, "timeBegin") == "00:00:00" && eventString(period, "timeEnd") == "23:59:59" {
					days[weekday] = true
				}
			}
		}
		result[id] = deploymentSchedule{digest: hex.EncodeToString(sum[:]), continuous: len(days) == 7}
	}
	return result, nil
}
