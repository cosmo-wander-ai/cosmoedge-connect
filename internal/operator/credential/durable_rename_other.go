//go:build !windows

package credential

import (
	"os"
	"path/filepath"
)

func durableRename(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	if err := syncContainingDirectory(newPath); err != nil {
		return err
	}
	if filepath.Dir(oldPath) != filepath.Dir(newPath) {
		return syncContainingDirectory(oldPath)
	}
	return nil
}

func durableReplace(oldPath, newPath string) error {
	return durableRename(oldPath, newPath)
}

func syncContainingDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
