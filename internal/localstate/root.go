package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultStateRoot returns a per-user state directory without accepting a
// caller-controlled network or device path.
func DefaultStateRoot() (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if base == "" {
			return "", errors.New("LOCALAPPDATA is unavailable")
		}
		return filepath.Join(base, "CosmoEdge", "Operator"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return "", errors.New("home directory is unavailable")
		}
		return filepath.Join(home, "Library", "Application Support", "CosmoEdge", "Operator"), nil
	default:
		if base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); base != "" {
			return filepath.Join(base, "cosmoedge", "operator"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return "", errors.New("home directory is unavailable")
		}
		return filepath.Join(home, ".local", "state", "cosmoedge", "operator"), nil
	}
}
