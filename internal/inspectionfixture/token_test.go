package inspectionfixture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestProvisionTokenCreatesProtectedRandomMaterialExactlyOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixture-state")
	path := filepath.Join(root, "channel.token")
	if err := ProvisionToken(path); err != nil {
		t.Fatalf("provision token: %v", err)
	}
	if err := localstate.ValidateStateRoot(root); err != nil {
		t.Fatalf("token parent is not protected: %v", err)
	}
	if err := localstate.ValidateFile(path); err != nil {
		t.Fatalf("token file is not protected: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || !lowercaseToken.Match(first) {
		t.Fatalf("provisioned token format is invalid: length=%d", len(first))
	}
	if err := validateTokenEntropy(first); err != nil {
		t.Fatalf("provisioned token failed entropy policy: %v", err)
	}
	if _, err := readTokenMaterial(path); err != nil {
		t.Fatalf("provisioned token cannot be consumed: %v", err)
	}
	if err := ProvisionToken(path); err == nil {
		t.Fatal("existing token was silently replaced")
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("failed reprovisioning changed the existing token")
	}
}

func TestReadTokenMaterialRejectsLowEntropyPatterns(t *testing.T) {
	cases := map[string]string{
		"all-zero":           strings.Repeat("0", 64),
		"one-character":      strings.Repeat("a", 64),
		"two-character":      strings.Repeat("01", 32),
		"repeated-hex-block": strings.Repeat("0123456789abcdef", 4),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			if err := localstate.PrepareStateRoot(root); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "channel.token")
			if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := localstate.ProtectFile(path); err != nil {
				t.Fatal(err)
			}
			if _, err := readTokenMaterial(path); err == nil {
				t.Fatalf("accepted low-entropy token pattern %q", name)
			}
		})
	}
}

func TestProvisionTokenRejectsWeakExistingParent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "weak-state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "channel.token")
	if err := ProvisionToken(path); err == nil {
		t.Fatal("provisioning accepted a weak existing parent")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("provisioning created a token under a weak parent: %v", err)
	}
}
