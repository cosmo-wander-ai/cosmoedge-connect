//go:build !windows

package credential

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedFileStoreRejectsWeakParentAndFilePermissions(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	weakParent := filepath.Join(t.TempDir(), "weak-parent")
	if err := os.Mkdir(weakParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEncryptedFileStore(filepath.Join(weakParent, "credentials.bin"), key); !errors.Is(err, ErrEncryptedFileStoreUnavailable) {
		t.Fatalf("weak parent error = %v", err)
	}
	if info, err := os.Stat(weakParent); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("weak parent was silently repaired: %v, %v", info.Mode().Perm(), err)
	}

	protectedParent := filepath.Join(t.TempDir(), "protected")
	path := filepath.Join(protectedParent, "credentials.bin")
	store, err := OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEncryptedFileStore(path, key); !errors.Is(err, ErrEncryptedFileStoreUnavailable) {
		t.Fatalf("weak file error = %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("weak file was silently repaired: %v, %v", info.Mode().Perm(), err)
	}
}
