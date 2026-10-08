package connectionowner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type TokenMaterial struct {
	mu            sync.Mutex
	digest        string
	credentialKey []byte
	signerKey     []byte
}

func ReadTokenMaterial(path string) (*TokenMaterial, error) {
	if err := localstate.ValidateFile(path); err != nil {
		return nil, errors.New("inspection access token is unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 64 || info.Size() > 65 {
		return nil, errors.New("inspection access token is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("inspection access token is unavailable")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 66))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		clear(raw)
		return nil, errors.New("inspection access token is unavailable")
	}
	if len(raw) == 65 && raw[64] == '\n' {
		raw = raw[:64]
	}
	if len(raw) != 64 || !tokenPattern.Match(raw) {
		clear(raw)
		return nil, errors.New("inspection access token is invalid")
	}
	digest := sha256.Sum256(raw)
	credentialInput := make([]byte, 0, len("cosmoedge.inspectionlive.credentials.v1\x00")+len(raw))
	credentialInput = append(credentialInput, []byte("cosmoedge.inspectionlive.credentials.v1\x00")...)
	credentialInput = append(credentialInput, raw...)
	credentialKey := sha256.Sum256(credentialInput)
	clear(credentialInput)
	signerInput := make([]byte, 0, len("cosmoedge.inspectionlive.authority-signer.v1\x00")+len(raw))
	signerInput = append(signerInput, []byte("cosmoedge.inspectionlive.authority-signer.v1\x00")...)
	signerInput = append(signerInput, raw...)
	signerKey := sha256.Sum256(signerInput)
	clear(signerInput)
	clear(raw)
	return &TokenMaterial{
		digest: hex.EncodeToString(digest[:]), credentialKey: append([]byte(nil), credentialKey[:]...),
		signerKey: append([]byte(nil), signerKey[:]...),
	}, nil
}

// Digest is the bearer digest; keys and raw token bytes never leave this owner.
func (m *TokenMaterial) Digest() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.digest
}
func (m *TokenMaterial) NewSigner(issuerID string) (*authority.Signer, error) {
	if m == nil {
		return nil, errors.New("local token material is unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.signerKey) != 32 {
		return nil, errors.New("local token material is closed")
	}
	return authority.NewSigner(issuerID, m.signerKey)
}
func (m *TokenMaterial) OpenCredentials(ctx context.Context, root string) (*credential.EncryptedFileStore, error) {
	if ctx == nil {
		return nil, credential.ErrEncryptedFileStoreUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, credential.ErrEncryptedFileStoreUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.credentialKey) != 32 {
		return nil, credential.ErrEncryptedFileStoreUnavailable
	}
	return credential.OpenEncryptedFileStore(filepath.Join(root, "inspection-authority-secrets.bin"), m.credentialKey)
}
func (m *TokenMaterial) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.credentialKey)
	clear(m.signerKey)
	m.credentialKey = nil
	m.signerKey = nil
	m.digest = ""
}
func (*TokenMaterial) String() string               { return "[local-token-material]" }
func (*TokenMaterial) GoString() string             { return "connectionowner.TokenMaterial([redacted])" }
func (*TokenMaterial) LogValue() slog.Value         { return slog.StringValue("[local-token-material]") }
func (*TokenMaterial) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
