package main

import (
	"path/filepath"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionlive"
)

func TestParseConfigMatchesLaunchAgentArguments(t *testing.T) {
	root := t.TempDir()
	got, err := parseConfig([]string{
		"--state-root", filepath.Join(root, "state"),
		"--token-file", filepath.Join(root, "access.token"),
		"--listen", "127.0.0.1:37789",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.listen != inspectionlive.DefaultAddress || !got.openOperator || !filepath.IsAbs(got.stateRoot) || !filepath.IsAbs(got.tokenFile) {
		t.Fatalf("unexpected config: %#v", got)
	}
}

func TestRestoredConnectionDoesNotOpenOperatorPage(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		requested bool
		restore   connectionregistry.RestoreState
		want      bool
	}{
		{name: "restored", requested: true, restore: connectionregistry.RestoreConnected, want: false},
		{name: "first_run", requested: true, restore: connectionregistry.RestoreNotConfigured, want: true},
		{name: "attention", requested: true, restore: connectionregistry.RestoreNeedsAttention, want: true},
		{name: "disabled", requested: false, restore: connectionregistry.RestoreNotConfigured, want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := shouldOpenOperator(testCase.requested, testCase.restore); got != testCase.want {
				t.Fatalf("shouldOpenOperator(%t, %q) = %t, want %t", testCase.requested, testCase.restore, got, testCase.want)
			}
		})
	}
}

func TestParseConfigRejectsIncompleteOrPositionalInput(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--state-root", "/tmp/state"},
		{"--state-root", "/tmp/state", "--token-file", "/tmp/token", "--listen", "127.0.0.1:37789", "extra"},
	} {
		if _, err := parseConfig(args); err == nil {
			t.Fatalf("accepted invalid args: %v", args)
		}
	}
}
