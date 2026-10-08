//go:build windows

package changeflow

import "golang.org/x/sys/windows"

func replaceStoreFile(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldName, newName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// File.Sync plus the write-through replacement provide the Windows durability
// boundary. Windows does not support the POSIX directory fsync used elsewhere.
func syncStoreDirectory(string) error { return nil }
