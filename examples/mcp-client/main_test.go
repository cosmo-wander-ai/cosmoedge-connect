package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestActualStdioNoSkillSmokeWithTwoProcesses(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "cosmoedge-mcp")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command("go", "build", "-buildvcs=false", "-ldflags", "-X github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo.Version=mcp-smoke -X github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo.SourceRevision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -X github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo.SourceModified=false", "-o", binary, "../../cmd/cosmoedge-mcp")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	if err := run([]string{"--server", binary, "--mock"}); err != nil {
		t.Fatal(err)
	}
}
