package main

import "testing"

func TestParseInvocationAllowsOnlyFixedSkillCommands(t *testing.T) {
	t.Parallel()
	tests := []struct {
		args       []string
		mode, view string
		kind       string
		window     string
		taskIndex  int
		taskAction string
	}{
		{mode: "launch", view: "home"},
		{args: []string{"--no-initial-browser"}, mode: "launch", view: "home"},
		{args: []string{"status"}, mode: "status"},
		{args: []string{"open", "tasks"}, mode: "open", view: "manage_tasks"},
		{args: []string{"open", "task-index", "2", "disable"}, mode: "open", view: "manage_tasks", taskIndex: 2, taskAction: "disable"},
		{args: []string{"query", "overview"}, mode: "query", kind: "overview", window: "today"},
		{args: []string{"query", "alarms", "last_1h"}, mode: "query", kind: "alarms", window: "last_1h"},
	}
	for _, test := range tests {
		got, err := parseInvocation(test.args)
		if err != nil {
			t.Fatalf("parse %v: %v", test.args, err)
		}
		if got.mode != test.mode || got.view != test.view || got.kind != test.kind || got.window != test.window || got.taskIndex != test.taskIndex || got.taskAction != test.taskAction {
			t.Fatalf("parse %v=%#v", test.args, got)
		}
	}
}

func TestParseInvocationRejectsFreeFormAuthority(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"journey"}, {"query", "raw"}, {"query", "alarms", "custom"},
		{"open", "http://device.internal"}, {"open", "task-index", "0", "disable"},
		{"open", "task-index", "1", "delete"}, {"open", "task", "friendly", "enable"},
		{"--no-initial-browser", "extra"},
		{"status", "--json"},
	} {
		if _, err := parseInvocation(args); err == nil {
			t.Fatalf("unsafe invocation %v accepted", args)
		}
	}
}
