package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const namespaceMarkerName = "credential.namespace"

func prepareSystemRoot(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("credential state root is required")
	}
	root, err := filepath.Abs(raw)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	if root == filepath.Dir(root) {
		return "", errors.New("credential state root must be a dedicated directory")
	}
	if _, err := os.Lstat(root); err == nil {
		if err := localstate.ValidateStateRoot(root); err != nil {
			return "", fmt.Errorf("reject existing credential state root: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("credential state root is unavailable")
	} else if err := localstate.PrepareStateRoot(root); err != nil {
		return "", errors.New("credential state root creation failed")
	}
	return root, nil
}

func namespaceForRoot(root string) (string, error) {
	marker := filepath.Join(root, namespaceMarkerName)
	value, err := readNamespaceMarker(marker)
	if errors.Is(err, os.ErrNotExist) {
		value = make([]byte, 32)
		if _, randomErr := rand.Read(value); randomErr != nil {
			return "", errors.New("credential namespace generation failed")
		}
		encoded := []byte("v2:" + hex.EncodeToString(value) + "\n")
		file, createErr := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			clear(value)
			if errors.Is(createErr, os.ErrExist) {
				value, err = readNamespaceMarker(marker)
			} else {
				return "", errors.New("credential namespace creation failed")
			}
		} else {
			ok := false
			defer func() {
				_ = file.Close()
				if !ok {
					_ = os.Remove(marker)
				}
			}()
			if _, err = file.Write(encoded); err == nil {
				err = file.Sync()
			}
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
			clear(encoded)
			if err == nil {
				err = localstate.ProtectFile(marker)
			}
			if err == nil {
				err = syncContainingDirectory(marker)
			}
			if err != nil {
				clear(value)
				return "", errors.New("credential namespace creation failed")
			}
			ok = true
		}
	}
	if err != nil {
		return "", err
	}
	defer clear(value)
	sum := sha256.Sum256(append([]byte("CosmoEdge/ordinary-credential-namespace/v2\x00"), value...))
	return "com.cosmoedge.operator.credentials." + hex.EncodeToString(sum[:12]), nil
}

func readNamespaceMarker(path string) ([]byte, error) {
	if err := localstate.ValidateFile(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("credential namespace marker is invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("credential namespace marker is unavailable")
	}
	defer clear(raw)
	text := strings.TrimSuffix(string(raw), "\n")
	if !strings.HasPrefix(text, "v2:") || len(text) != 67 {
		return nil, errors.New("credential namespace marker is invalid")
	}
	value, err := hex.DecodeString(strings.TrimPrefix(text, "v2:"))
	if err != nil || len(value) != 32 {
		clear(value)
		return nil, errors.New("credential namespace marker is invalid")
	}
	return value, nil
}
