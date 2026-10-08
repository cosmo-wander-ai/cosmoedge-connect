package credential

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestCredentialNamespaceIsPersistentAndRejectsCorruption(t *testing.T) {
	root := newCredentialStateRoot(t)
	prepared, err := prepareSystemRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := namespaceForRoot(prepared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := namespaceForRoot(prepared)
	if err != nil || second != first {
		t.Fatalf("persistent namespace changed: %q / %q, %v", first, second, err)
	}
	marker := filepath.Join(root, namespaceMarkerName)
	if err := os.WriteFile(marker, []byte("v2:corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := namespaceForRoot(prepared); err == nil {
		t.Fatal("corrupt credential namespace marker was accepted")
	}
}

func TestCredentialRootRejectsUnknownPermissionsWithoutChangingThem(t *testing.T) {
	root := filepath.Join(t.TempDir(), "unsafe-root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := localstate.ValidateStateRoot(root); err == nil {
		t.Fatal("test requires an unprotected existing root")
	}
	if _, err := prepareSystemRoot(root); err == nil {
		t.Fatal("unprotected existing credential root was silently hardened")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("unknown credential root permissions changed: %v to %v", before.Mode().Perm(), info.Mode().Perm())
	}
	if err := localstate.ValidateStateRoot(root); err == nil {
		t.Fatal("unprotected existing credential root is no longer rejected")
	}
}
