package deployment

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNativeConfigurationDigestPreservesValuesAndPolygonOrder(t *testing.T) {
	config := Configuration{Document: json.RawMessage(`{"taskConfig":{"params":[{"key":"b","value":{"nested":[1,2]}},{"key":"a","value":"1"}],"areas":[{"points":[{"x":0},{"x":1}]}]},"scheduleId":"schedule-one"}`)}
	reordered := Configuration{Document: json.RawMessage(`{"scheduleId":"schedule-one","taskConfig":{"areas":[{"points":[{"x":0},{"x":1}]}],"params":[{"key":"a","value":"1"},{"key":"b","value":{"nested":[1,2]}}]}}`)}
	a, err := configurationDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	b, err := configurationDigest(reordered)
	if err != nil || a != b {
		t.Fatalf("keyed params changed digest: %v", err)
	}
	for _, document := range []string{
		`{"taskConfig":{"params":[{"key":"a","value":"2"},{"key":"b","value":{"nested":[1,2]}}],"areas":[{"points":[{"x":0},{"x":1}]}]},"scheduleId":"schedule-one"}`,
		`{"taskConfig":{"params":[{"key":"b","value":{"nested":[1,2]}},{"key":"a","value":"1"}],"areas":[{"points":[{"x":1},{"x":0}]}]},"scheduleId":"schedule-one"}`,
		`{"taskConfig":{"params":[{"key":"b","value":{"nested":[1,2]}},{"key":"a","value":"1"}],"areas":[{"points":[{"x":0},{"x":1}]}]},"scheduleId":"schedule-two"}`,
	} {
		changed, err := configurationDigest(Configuration{Document: json.RawMessage(document)})
		if err != nil || changed == a {
			t.Fatalf("native config change was hidden: %v", err)
		}
	}
}

func TestProgressRequiresSameTaskFreshSamplesAndAllRequiredCounters(t *testing.T) {
	now := time.Now().UTC()
	before := Runtime{TaskID: "task-a", Known: true, Active: true, Counters: map[string]uint64{"decode": 10, "inference": 8}, ObservedAt: now}
	valid := Runtime{TaskID: "task-a", Known: true, Active: true, Counters: map[string]uint64{"decode": 15, "inference": 13}, ObservedAt: now.Add(time.Second)}
	if progress, ok := progressBetween(before, valid, "task-a"); !ok || len(progress) != 2 {
		t.Fatalf("valid progress=%+v ok=%t", progress, ok)
	}
	for _, mutate := range []func(*Runtime){
		func(r *Runtime) { r.TaskID = "task-b" },
		func(r *Runtime) { r.Known = false },
		func(r *Runtime) { r.Active = false },
		func(r *Runtime) { r.ObservedAt = now },
		func(r *Runtime) { r.Counters = map[string]uint64{"decode": 15, "inference": 8} },
		func(r *Runtime) { r.Counters = map[string]uint64{"decode": 3, "inference": 2} },
		func(r *Runtime) { r.Counters = map[string]uint64{"other-node": 30} },
	} {
		after := valid
		mutate(&after)
		if _, ok := progressBetween(before, after, "task-a"); ok {
			t.Fatalf("unverified progress accepted: %+v", after)
		}
	}
}

func TestSharedInferenceAndTargetDecodeCannotMaskStalledTaskBranch(t *testing.T) {
	now := time.Now().UTC()
	before := Runtime{TaskID: "task-a", Known: true, Active: true, Counters: map[string]uint64{"decode": 10, "shared-inference": 100, "task-local-tracker": 8}, ObservedAt: now}
	after := Runtime{TaskID: "task-a", Known: true, Active: true, Counters: map[string]uint64{"decode": 15, "shared-inference": 200, "task-local-tracker": 8}, ObservedAt: now.Add(time.Second)}
	if _, ok := progressBetween(before, after, "task-a"); ok {
		t.Fatal("another camera's shared inference growth masked a stalled target task")
	}
	after.Counters["task-local-tracker"] = 9
	if progress, ok := progressBetween(before, after, "task-a"); !ok || len(progress) != 3 {
		t.Fatalf("task-local progress=%+v verified=%t", progress, ok)
	}
}
