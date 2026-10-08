//go:build !darwin && !windows

package credential

import (
	"errors"
	"testing"
)

func TestSystemStoreUnsupportedPlatformFailsClosed(t *testing.T) {
	if _, err := OpenSystemStore(t.TempDir()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported platform error=%v", err)
	}
}
