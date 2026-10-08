//go:build !windows

package teststate

import (
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"os"
)

// ProtectDir makes an existing, test-owned fixture directory private.
func ProtectDir(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return localstate.ValidateStateRoot(path)
}
