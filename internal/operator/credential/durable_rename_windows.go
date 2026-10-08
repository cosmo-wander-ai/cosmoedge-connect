//go:build windows

package credential

import "golang.org/x/sys/windows"

func durableRename(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldName, newName, windows.MOVEFILE_WRITE_THROUGH)
}

func durableReplace(oldPath, newPath string) error {
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

// File.Sync plus MOVEFILE_WRITE_THROUGH cover the Windows paths that call
// this helper. Windows does not expose a portable directory fsync equivalent.
func syncContainingDirectory(string) error { return nil }
