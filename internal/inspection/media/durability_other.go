//go:build !windows

package media

import (
	"os"
	"path/filepath"
)

func syncMediaDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
