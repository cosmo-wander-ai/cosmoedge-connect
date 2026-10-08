package parity

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRetiredProductPathsStayAbsent(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	for _, relative := range []string{
		"cmd/cosmoedge-v2",
		"cmd/cosmoedge-explore",
		"cmd/cosmoedge-explore-control",
		"internal/app",
		"internal/control",
		"internal/db",
		"internal/explore",
		"internal/maintenance",
		"internal/operatorhost",
		"internal/operatorprovision",
		"internal/operatorruntime",
		"internal/operatorstate",
		"internal/readmodel",
		"internal/server",
		"internal/workflow",
		"demo/fixtures",
		"demo/skill/cosmoedge-explore",
		"schemas",
		"scripts/cosmoedge-explore-bootstrap.ps1",
		"scripts/cosmoedge-explore.ps1",
		"scripts/powershell-inventory.json",
		"scripts/protect-e3-control-descriptor.ps1",
		".github/workflows/e3-windows-dacl.yml",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retired product path returned: %s, err=%v", relative, err)
		}
	}
}

func TestRetainedProductAndEvidencePathsExist(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	for _, relative := range []string{
		"cmd/cosmoedge-connect",
		"cmd/cosmoedge-mcp",
		"skills/cosmoedge-operations/SKILL.md",
		"examples/mcp-client",
		"cmd/cosmoedge-operator",
		"internal/adapter",
		"internal/devauthority",
		"internal/operator",
		"internal/parity/testdata/ordinary-baseline-normalized.json",
		"demo/skill/cosmoedge-operator/SKILL.md",
		"scripts/parity/ordinary-differential.ps1",
		"scripts/build-operator-bundles.ps1",
		"scripts/cosmoedge-dev-device.ps1",
		"tools/dev-device/main.go",
		"internal/inspection/releasegate",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("retained product or evidence path missing: %s, err=%v", relative, err)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("repository source path is unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}
