//go:build windows

package media

// Windows does not support fsync on a directory handle through os.File. The
// durable replacement itself is provided by the platform rename operation.
func syncMediaDirectory(string) error { return nil }
