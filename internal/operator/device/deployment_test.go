package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func deploymentTestClient(t *testing.T, handler func(string, map[string]any) any) *v1Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/gtw/cwai/login/DoLogin" {
			fmt.Fprint(w, `{"resCode":1,"resData":{"mtk":"deployment-test-token"}}`)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "invalid body", 400)
			return
		}
		data := handler(r.URL.Path, body)
		if err := json.NewEncoder(w).Encode(map[string]any{"resCode": 1, "resData": data}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	client := NewV1Client(server.URL, "test-operator", "test-only").(*v1Client)
	if err := client.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

func scheduleRows() map[string]any {
	days := []any{}
	for day := 0; day < 7; day++ {
		days = append(days, map[string]any{"weekDay": day, "runTime": []any{map[string]any{"timeBegin": "00:00:00", "timeEnd": "23:59:59"}}})
	}
	return map[string]any{"total": 1, "rows": []any{map[string]any{"scheduleId": "device-specific-all-day", "scheduleName": "全天候", "scheduleConfig": days}}}
}

func nativeMetadata(fullFrame bool) map[string]any {
	return map[string]any{"params": []any{
		map[string]any{"key": "aiParam.pedestrian.confidence", "defaultValue": "", "regexpr": ""},
		map[string]any{"key": "param.targetAlarmInterval", "defaultValue": "60", "regexpr": "integer"},
	}, "regionType": "hexagon", "defaultFullScreen": fullFrame, "enableShieldedRegion": false}
}

func TestDeploymentReadPreservesFullNativeDocumentAndChecksBindingAndSchedule(t *testing.T) {
	native := map[string]any{"params": []any{map[string]any{"key": "aiParam.pedestrian.confidence"}, map[string]any{"key": "algorithm.nested", "value": map[string]any{"choice": []any{"a", "b"}}}}, "areas": []any{map[string]any{"areaId": "original-area", "points": []any{map[string]any{"xRatio": 0.15, "yRatio": 0.25}}}}, "facesetConfig": []any{}, "shieldedAreas": []any{}}
	client := deploymentTestClient(t, func(path string, body map[string]any) any {
		switch path {
		case "/gtw/cwai/Camera/Page":
			return map[string]any{"total": 1, "rows": []any{map[string]any{"videoChannelId": "cam-a", "taskList": []any{map[string]any{"algorithmId": "15", "id": "native-task"}}}}}
		case "/gtw/cwai/task/selectConfigByAlgorithmId":
			return map[string]any{"taskConfig": native, "scheduleId": "device-specific-all-day", "taskEnableStatus": 0, "taskStatus": 0}
		case "/gtw/cwai/schedule/SelectScheduleInfo":
			return scheduleRows()
		case "/gtw/cwai/Task/QuerySwitch":
			return map[string]any{"enable": 0}
		default:
			t.Errorf("unexpected endpoint %s", path)
			return nil
		}
	})
	state, err := client.ReadDeployment(context.Background(), "cam-a", "15")
	if err != nil || !state.Exists || state.TaskID != "native-task" || state.Enabled != 0 || !state.Configuration.Ready || state.Configuration.ScheduleDigest == "" {
		t.Fatalf("state=%+v error=%v", state, err)
	}
	var document map[string]any
	if err := json.Unmarshal(state.Configuration.Document, &document); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(document["taskConfig"], native) {
		t.Fatalf("native structure was flattened: %#v", document)
	}
}

func TestDeploymentDoesNotInferExistenceFromSuccessfulConfigEnvelope(t *testing.T) {
	client := deploymentTestClient(t, func(path string, body map[string]any) any {
		if path != "/gtw/cwai/Camera/Page" {
			t.Errorf("absent binding must not be inferred from %s", path)
		}
		return map[string]any{"total": 1, "rows": []any{map[string]any{"videoChannelId": "cam-a", "taskList": []any{}}}}
	})
	state, err := client.ReadDeployment(context.Background(), "cam-a", "15")
	if err != nil || state.Exists || state.TaskID != "" || state.Enabled != -1 {
		t.Fatalf("missing binding=%+v error=%v", state, err)
	}
}

func TestDefaultDeploymentUsesActualContinuousScheduleAndOptionalEmptyDefaults(t *testing.T) {
	metadata := nativeMetadata(true)
	client := deploymentTestClient(t, func(path string, body map[string]any) any {
		switch path {
		case "/gtw/cwai/task/selectConfigByAlgorithmId":
			raw, _ := json.Marshal(metadata)
			return map[string]any{"algorithmMetadata": string(raw), "taskConfig": map[string]any{"params": []any{}}}
		case "/gtw/cwai/schedule/SelectScheduleInfo":
			return scheduleRows()
		default:
			t.Errorf("unexpected endpoint %s", path)
			return nil
		}
	})
	configuration, err := client.DefaultDeployment(context.Background(), "new-camera", "15")
	if err != nil || !configuration.Ready || len(configuration.Missing) != 0 || configuration.ScheduleDigest == "" {
		t.Fatalf("defaults=%+v error=%v", configuration, err)
	}
	var document map[string]any
	if err := json.Unmarshal(configuration.Document, &document); err != nil {
		t.Fatal(err)
	}
	if document["scheduleId"] != "device-specific-all-day" {
		t.Fatal("used a hardcoded or unverified schedule")
	}
	config := document["taskConfig"].(map[string]any)
	params := config["params"].([]any)
	if _, exists := params[0].(map[string]any)["value"]; exists {
		t.Fatal("optional empty confidence was silently populated")
	}
	if params[1].(map[string]any)["value"] != "60" || len(config["areas"].([]any)) != 1 {
		t.Fatalf("manufacturer defaults/full frame not preserved: %#v", config)
	}
	second, err := client.DefaultDeployment(context.Background(), "new-camera", "15")
	if err != nil || string(second.Document) != string(configuration.Document) {
		t.Fatal("default preparation changed its own precondition")
	}
}

func TestDefaultDeploymentMissingROIOrRequiredParameterDoesNotBecomeReady(t *testing.T) {
	metadata := nativeMetadata(false)
	configuration, err := defaultDeploymentConfiguration("camera", "algorithm", "actual-plan", metadata)
	if err != nil || configuration.Ready || len(configuration.Missing) != 1 {
		t.Fatalf("missing ROI=%+v error=%v", configuration, err)
	}
	metadata = nativeMetadata(true)
	metadata["params"].([]any)[0].(map[string]any)["regexpr"] = "nonempty"
	configuration, err = defaultDeploymentConfiguration("camera", "algorithm", "actual-plan", metadata)
	if err != nil || configuration.Ready || len(configuration.Missing) != 1 {
		t.Fatalf("required parameter=%+v error=%v", configuration, err)
	}
}

func TestSaveDeploymentUsesNativeSingleEnablingWrite(t *testing.T) {
	configuration, err := defaultDeploymentConfiguration("cam-a", "15", "actual-device-plan", nativeMetadata(true))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client := deploymentTestClient(t, func(path string, body map[string]any) any {
		calls++
		if path != "/gtw/cwai/task/saveOrUpdate" || body["channelId"] != "cam-a" || body["algorithmId"] != "15" || body["scheduleId"] != "actual-device-plan" {
			t.Errorf("unexpected write %s %#v", path, body)
		}
		if len(body) != 4 {
			t.Errorf("save contained unverified extra fields: %#v", body)
		}
		return map[string]any{}
	})
	if err := client.SaveDeployment(context.Background(), DeploymentTarget{SourceID: "cam-a", AlgorithmID: "15", Configuration: configuration}); err != nil || calls != 1 {
		t.Fatalf("writes=%d error=%v", calls, err)
	}
}

func runtimeRows(detectorStatus string, detectorCount, decoderCount int) map[string]any {
	return map[string]any{"status": []any{map[string]any{"taskId": "cam-a_15", "channelId": "cam-a", "algorithmId": "15", "algorithmVersion": "version-1", "actionStatus": []any{
		map[string]any{"actionId": "BA_00001 DEMUX", "name": "", "statusCode": "12300", "processCount": decoderCount + 100},
		map[string]any{"actionId": "BA_00001 DECODE", "name": "cam-a Decode", "statusCode": "0", "processCount": decoderCount},
		map[string]any{"actionId": "AA_00001", "name": "1001003 AiDetector", "statusCode": detectorStatus, "processCount": detectorCount},
		map[string]any{"actionId": "AA_00002", "name": "cam-a_15 Classifier", "statusCode": "12288", "processCount": 0},
		map[string]any{"actionId": "AA_00003", "name": "cam-a_15-追踪算法-node-a", "statusCode": "0", "processCount": detectorCount},
	}}}}
}

func TestRuntimeNeedsTargetDecodeAndInferenceAndDoesNotRequireAnAlarm(t *testing.T) {
	client := deploymentTestClient(t, func(path string, body map[string]any) any {
		if path != "/gtw/cwai/Task/RunningDetail" || !reflect.DeepEqual(body["tasks"], []any{"cam-a_15"}) {
			t.Errorf("runtime target request=%s %#v", path, body)
		}
		return runtimeRows("0", 30, 40)
	})
	runtime, err := client.ReadDeploymentRuntime(context.Background(), Task{ID: "cam-a_15", ChannelID: "cam-a", AlgorithmID: "15"})
	if err != nil || !runtime.Known || !runtime.Active || runtime.Stopped || len(runtime.Counters) != 3 || runtime.Counters["version-1:AA_00001:1001003 AiDetector"] != 30 {
		t.Fatalf("runtime=%+v error=%v", runtime, err)
	}
}

func TestRuntimeRequiresSupportedTaskLocalDownstreamEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, id, queue, status string
		known                   bool
	}{
		{"tracker without targets", "AA_00003", "cam-a_15-追踪算法-node-a", "0", true},
		{"area without alarms", "BA_00005", "cam-a_15-区域告警判断-node-b", "12288", true},
		{"different task queue", "AA_00003", "cam-b_15-追踪算法-node-a", "0", false},
		{"task prefix collision", "AA_00003", "cam-a_150-追踪算法-node-a", "0", false},
		{"shared inference only", "AA_00001", "another-model AiDetector", "0", false},
		{"alarm report is conditional", "BA_00004", "cam-a_15-告警上报-node-a", "0", false},
		{"classifier is conditional", "AA_00002", "cam-a_15-分类-node-a", "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := runtimeRows("0", 30, 40)
			local := rows["status"].([]any)[0].(map[string]any)["actionStatus"].([]any)[4].(map[string]any)
			local["actionId"], local["name"], local["statusCode"] = tc.id, tc.queue, tc.status
			client := deploymentTestClient(t, func(string, map[string]any) any { return rows })
			runtime, err := client.ReadDeploymentRuntime(context.Background(), Task{ID: "cam-a_15", ChannelID: "cam-a", AlgorithmID: "15"})
			if err != nil || runtime.Known != tc.known || runtime.Active != tc.known {
				t.Fatalf("runtime=%+v error=%v", runtime, err)
			}
		})
	}
}

func TestRuntimePrefersTrackerOverTargetGatedAlarmBranch(t *testing.T) {
	rows := runtimeRows("0", 30, 40)
	row := rows["status"].([]any)[0].(map[string]any)
	row["actionStatus"] = append(row["actionStatus"].([]any), map[string]any{"actionId": "BA_00005", "name": "cam-a_15-区域告警判断-node-b", "statusCode": "12288", "processCount": 0})
	client := deploymentTestClient(t, func(string, map[string]any) any { return rows })
	runtime, err := client.ReadDeploymentRuntime(context.Background(), Task{ID: "cam-a_15", ChannelID: "cam-a", AlgorithmID: "15"})
	if err != nil || !runtime.Known || !runtime.Active || len(runtime.Counters) != 3 {
		t.Fatalf("runtime=%+v error=%v", runtime, err)
	}
}

func TestRuntimeFailureOrWrongTaskNeverBecomesHealthyOrStopped(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(map[string]any)
	}{
		{name: "model failure", modify: func(row map[string]any) { row["actionStatus"].([]any)[2].(map[string]any)["statusCode"] = "16777218" }},
		{name: "classifier failure", modify: func(row map[string]any) { row["actionStatus"].([]any)[3].(map[string]any)["statusCode"] = "16777222" }},
		{name: "wrong channel", modify: func(row map[string]any) { row["channelId"] = "cam-b" }},
		{name: "no inference counter", modify: func(row map[string]any) { delete(row["actionStatus"].([]any)[2].(map[string]any), "processCount") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := runtimeRows("0", 30, 40)
			test.modify(rows["status"].([]any)[0].(map[string]any))
			client := deploymentTestClient(t, func(string, map[string]any) any { return rows })
			runtime, err := client.ReadDeploymentRuntime(context.Background(), Task{ID: "cam-a_15", ChannelID: "cam-a", AlgorithmID: "15"})
			if err == nil && (runtime.Active || runtime.Stopped) {
				t.Fatalf("invalid runtime=%+v", runtime)
			}
		})
	}
}

func TestNoContinuousScheduleRequiresInput(t *testing.T) {
	schedules := scheduleRows()
	schedules["rows"].([]any)[0].(map[string]any)["scheduleConfig"] = []any{}
	client := deploymentTestClient(t, func(path string, body map[string]any) any {
		if path == "/gtw/cwai/task/selectConfigByAlgorithmId" {
			return map[string]any{"algorithmMetadata": nativeMetadata(true)}
		}
		if path == "/gtw/cwai/schedule/SelectScheduleInfo" {
			return schedules
		}
		t.Errorf("unexpected endpoint %s", path)
		return nil
	})
	configuration, err := client.DefaultDeployment(context.Background(), "camera", "algorithm")
	if err != nil || configuration.Ready || len(configuration.Missing) == 0 {
		t.Fatalf("unverified schedule defaults=%+v error=%v", configuration, err)
	}
}
