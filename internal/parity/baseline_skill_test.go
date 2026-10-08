package parity

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestBaselineThinSkillFixedQueriesGolden(t *testing.T) {
	session := newConnectedBaseline(t, "thin-skill")
	_ = mustGetObject(t, session.Browser, "/api/journey?intent=home&window=today")
	commands := []struct {
		args     []string
		contains []string
	}{
		{args: []string{"status"}, contains: []string{"已连接", "***9184"}},
		{args: []string{"query", "overview"}, contains: []string{"1 路摄像头", "1 个分析任务", "0 条告警"}},
		{args: []string{"query", "cameras"}, contains: []string{"1 路摄像头", "Parity Camera"}},
		{args: []string{"query", "tasks"}, contains: []string{"Parity Algorithm + Parity Camera", "已启用"}},
		{args: []string{"query", "runtime"}, contains: []string{"运行 1 个", "Parity Algorithm + Parity Camera"}},
		{args: []string{"query", "alarms", "today"}, contains: []string{"今日告警", "0 条"}},
		{args: []string{"query", "alarms", "yesterday"}, contains: []string{"昨天告警", "0 条"}},
		{args: []string{"query", "alarms", "last_1h"}, contains: []string{"最近 1 小时", "0 条"}},
		{args: []string{"query", "alarms", "last_24h"}, contains: []string{"最近 24 小时", "0 条"}},
		{args: []string{"query", "capabilities"}, contains: []string{"当前可查询", "本地页面"}},
	}
	var bodies [][]byte
	for _, item := range commands {
		output := waitFixedQuery(t, session, item.args, item.contains)
		bodies = append(bodies, append([]byte(nil), output.Bytes()...))
	}
	if snapshot := session.Fixture.Snapshot(); snapshot.TaskWrites != 0 || snapshot.ParameterWrites != 0 || snapshot.SourceWrites != 0 {
		t.Fatalf("fixed Skill queries wrote device: %#v", snapshot)
	}
	if err := ScanProtected(bytes.Join(bodies, []byte("\n")), session.Password, session.FullSN, session.Username, session.DeviceHost, "parity-task-internal", "parity-camera-internal", "parity-algorithm-internal"); err != nil {
		t.Fatal(err)
	}
	recordNormalized(t, NormalizedResult{
		Scenario: "G-READ-07/thin-skill-fixed-queries", Class: "completed",
		TaskName: "Parity Algorithm + Parity Camera", CameraName: "Parity Camera", AlgorithmName: "Parity Algorithm",
	})
}

func waitFixedQuery(t *testing.T, session *baselineSession, args, expected []string) bytes.Buffer {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var output bytes.Buffer
	var commandErr error
	for time.Now().Before(deadline) {
		output.Reset()
		command := exec.Command(baselineOperatorPath(t), args...)
		command.Env = append([]string(nil), session.Run.Environment...)
		command.Stdout, command.Stderr = &output, &output
		commandErr = command.Run()
		complete := commandErr == nil
		for _, text := range expected {
			complete = complete && strings.Contains(output.String(), text)
		}
		if complete {
			return output
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("fixed query %v did not converge: err=%v output=%s", args, commandErr, output.String())
	return output
}
