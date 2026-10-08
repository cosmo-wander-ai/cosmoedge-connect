//go:build !windows

package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func PrepareStateRoot(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return ValidateStateRoot(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return ValidateStateRoot(path)
}

func ValidateStateRoot(path string) error {
	return validatePath(path, true, 0o700)
}

func ProtectFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return ValidateFile(path)
}

func ValidateFile(path string) error {
	return validatePath(path, false, 0o600)
}

func ValidateExistingStateFiles(root string) error {
	for _, name := range []string{"owner.lock", "locator.json", "operator.db", "operator.db-wal", "operator.db-shm"} {
		path := filepath.Join(root, name)
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := ValidateFile(path); err != nil {
			return fmt.Errorf("reject existing Operator state file %s: %w", name, err)
		}
	}
	return nil
}

func validatePath(path string, directory bool, permission os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory {
		return errors.New("Operator state path has an unexpected object type")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("Operator state must be owned by the current user")
	}
	if info.Mode().Perm() != permission {
		return fmt.Errorf("Operator state permissions are %o, want %o", info.Mode().Perm(), permission)
	}
	return nil
}
