//go:build !windows

package changeflow

import "os"

func replaceStoreFile(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

func syncStoreDirectory(root string) error {
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
