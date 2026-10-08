package inspectionfixture

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const channelTokenBytes = 32

// ProvisionToken creates the fixture channel token exactly once. It never
// returns the raw token to its caller.
func ProvisionToken(path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return errors.New("fixture token path is invalid")
	}
	absolute, err := filepath.Abs(trimmed)
	if err != nil || absolute == string(os.PathSeparator) {
		return errors.New("fixture token path is invalid")
	}
	parent := filepath.Dir(absolute)
	if parent == absolute {
		return errors.New("fixture token parent is invalid")
	}
	if err := localstate.PrepareStateRoot(parent); err != nil {
		return errors.Join(errors.New("fixture token parent must be owner-only"), err)
	}

	random := make([]byte, channelTokenBytes)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		clear(random)
		return errors.Join(errors.New("generate fixture token"), err)
	}
	encoded := make([]byte, hex.EncodedLen(len(random)))
	hex.Encode(encoded, random)
	clear(random)
	defer clear(encoded)

	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.Join(errors.New("create fixture token without replacement"), err)
	}
	created := true
	defer func() {
		if created {
			_ = os.Remove(absolute)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return errors.Join(errors.New("write fixture token"), err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.Join(errors.New("sync fixture token"), err)
	}
	if err := file.Close(); err != nil {
		return errors.Join(errors.New("close fixture token"), err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return errors.Join(errors.New("protect fixture token"), err)
	}
	created = false
	return nil
}

func validateTokenEntropy(raw []byte) error {
	for period := 1; period <= 16; period++ {
		if len(raw)%period != 0 {
			continue
		}
		repeated := true
		for index := period; index < len(raw); index++ {
			if raw[index] != raw[index%period] {
				repeated = false
				break
			}
		}
		if repeated {
			return errors.New("fixture token file contains an obvious low-entropy repeated pattern")
		}
	}
	return nil
}
