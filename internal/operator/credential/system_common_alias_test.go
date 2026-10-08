//go:build !windows

package credential

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialNamespaceDoesNotDependOnTextualPathAlias(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	prepared, err := prepareSystemRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := namespaceForRoot(prepared)
	if err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(parent, aliasParent); err != nil {
		t.Fatal(err)
	}
	aliased, err := prepareSystemRoot(filepath.Join(aliasParent, "state"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := namespaceForRoot(aliased)
	if err != nil || first != second {
		t.Fatalf("path alias changed credential namespace: %q / %q, %v", first, second, err)
	}
}
