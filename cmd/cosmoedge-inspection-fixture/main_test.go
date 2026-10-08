package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestProvisionTokenCommandCreatesOnceWithoutDisclosingToken(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixture-state")
	var output bytes.Buffer
	if err := run(context.Background(), []string{"provision-token", "--state-root", root}, &output); err != nil {
		t.Fatalf("provision-token: %v", err)
	}
	if output.String() != "巡检测试访问令牌已安全创建。\n" {
		t.Fatalf("unexpected success output %q", output.String())
	}
	path := filepath.Join(root, "channel.token")
	token, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 || strings.Contains(output.String(), string(token)) {
		t.Fatal("command disclosed or malformed the provisioned token")
	}
	if err := localstate.ValidateStateRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ValidateFile(path); err != nil {
		t.Fatal(err)
	}

	var replayOutput bytes.Buffer
	if err := run(context.Background(), []string{"provision-token", "--state-root", root}, &replayOutput); err == nil {
		t.Fatal("provision-token replaced an existing token")
	}
	if replayOutput.Len() != 0 {
		t.Fatalf("failed provisioning printed output %q", replayOutput.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(token, after) {
		t.Fatal("failed provisioning changed the existing token")
	}
}

func TestNormalStartDoesNotCreateMissingToken(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixture-state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	assetSource := filepath.Join("..", "..", "internal", "inspectionfixture", "testdata", "assets")
	tokenPath := filepath.Join(root, "missing.token")
	var output bytes.Buffer
	err := run(context.Background(), []string{
		"--state-root", root,
		"--asset-source", assetSource,
		"--token-file", tokenPath,
	}, &output)
	if err == nil {
		t.Fatal("normal start accepted a missing token")
	}
	if _, statErr := os.Lstat(tokenPath); !os.IsNotExist(statErr) {
		t.Fatalf("normal start created or changed the missing token: %v", statErr)
	}
	if output.Len() != 0 {
		t.Fatalf("failed normal start printed output %q", output.String())
	}
}
