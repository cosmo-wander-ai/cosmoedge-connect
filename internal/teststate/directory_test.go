package teststate

import (
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePrivateFixturePermissions(t *testing.T) {
	root := t.TempDir()
	if err := ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ValidateStateRoot(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "fixture.db")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ValidateFile(path); err != nil {
		t.Fatal(err)
	}
}
