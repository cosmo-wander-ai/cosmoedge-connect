//go:build !windows

package localstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareStateRootCreatesProtectedAndRejectsExistingWeakRoot(t *testing.T) {
	created := filepath.Join(t.TempDir(), "created")
	if err := PrepareStateRoot(created); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(created)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("created root mode=%v err=%v", info.Mode().Perm(), err)
	}

	weak := filepath.Join(t.TempDir(), "weak")
	if err := os.Mkdir(weak, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := PrepareStateRoot(weak); err == nil {
		t.Fatal("existing weak state root was silently repaired")
	}
	info, err = os.Stat(weak)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("weak root was mutated mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestStateValidationRejectsSymlinksAndWeakExistingFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "operator.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(link); err == nil {
		t.Fatal("state file symlink was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("db"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExistingStateFiles(root); err == nil {
		t.Fatal("weak existing Operator file was accepted")
	}
	if err := ProtectFile(link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExistingStateFiles(root); err != nil {
		t.Fatalf("protected existing Operator file rejected: %v", err)
	}
}
