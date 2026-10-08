package connectionowner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestTokenMaterialUsesDomainSeparatedCredentialKey(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "access.token")
	raw := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(token, append(append([]byte(nil), raw...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	material, err := ReadTokenMaterial(token)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.credentialKey)
	defer clear(material.signerKey)
	digest := sha256.Sum256(raw)
	if material.digest != hex.EncodeToString(digest[:]) {
		t.Fatal("channel digest does not match the access token")
	}
	input := append([]byte("cosmoedge.inspectionlive.credentials.v1\x00"), raw...)
	wantedKey := sha256.Sum256(input)
	clear(input)
	if !bytes.Equal(material.credentialKey, wantedKey[:]) {
		t.Fatal("credential key does not use the inspectionlive KDF domain")
	}
	if bytes.Equal(material.credentialKey, digest[:]) {
		t.Fatal("credential key reused the channel authorization digest")
	}
	signerInput := append([]byte("cosmoedge.inspectionlive.authority-signer.v1\x00"), raw...)
	wantedSignerKey := sha256.Sum256(signerInput)
	clear(signerInput)
	if !bytes.Equal(material.signerKey, wantedSignerKey[:]) {
		t.Fatal("signer key does not use its inspectionlive KDF domain")
	}
	if bytes.Equal(material.signerKey, material.credentialKey) || bytes.Equal(material.signerKey, digest[:]) {
		t.Fatal("signer key was not separated from credential and channel authorization keys")
	}
}
