package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestMinimalProviderExclusiveRestartWithoutInspectionStores(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "private-state")
	token := filepath.Join(parent, "access.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	cfg := config{stateRoot: root, tokenFile: token}
	makeProvider := func() *provider {
		return &provider{config: cfg, vault: session.New(nil), opener: func(string) error { return nil }}
	}
	first, second := makeProvider(), makeProvider()
	if err := first.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer first.Stop()
	if err := second.Start(context.Background()); err == nil {
		second.Stop()
		t.Fatal("second state writer accepted")
	}
	for _, name := range []string{"application.db", "runs.db", "temporary-runs.db", "delivery.db", "schedules.db", "changeflow.json"} {
		if _, err := os.Stat(filepath.Join(root, "inspection-v2", name)); !os.IsNotExist(err) {
			t.Fatal("minimal provider opened unrelated state", name)
		}
	}
	if _, err := first.Handler(); err != nil {
		t.Fatal(err)
	}
	if err := first.Stop(); err != nil {
		t.Fatal(err)
	}
	third := makeProvider()
	if err := third.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := third.Stop(); err != nil {
		t.Fatal(err)
	}
}
