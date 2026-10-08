package releasegate

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

const modulePath = "github.com/cosmo-wander-ai/cosmoedge-connect"

var authorityDependencies = []string{
	modulePath + "/internal/operator/actions",
	modulePath + "/internal/operator/app",
	modulePath + "/internal/operator/credential",
	modulePath + "/internal/operator/device",
	modulePath + "/internal/operator/kernel",
	modulePath + "/internal/operator/ledger",
	modulePath + "/internal/operator/onboarding",
	modulePath + "/internal/operator/profile",
	modulePath + "/internal/operator/read",
	modulePath + "/internal/operator/result",
	modulePath + "/internal/operator/session",
	modulePath + "/internal/operator/web",
	modulePath + "/internal/devwrite",
	modulePath + "/internal/devauthority",
	modulePath + "/internal/devlab",
	modulePath + "/internal/adapter",
}

func TestOrdinaryOperatorUsesOnlyTheDefaultOffInspectionCompositionSeam(t *testing.T) {
	direct := listDirectDependencies(t, "./cmd/cosmoedge-operator")
	composition := modulePath + "/internal/operator/inspectionproduct"
	foundComposition := false
	for _, dependency := range direct {
		if dependency == composition {
			foundComposition = true
		}
		if dependency == modulePath+"/internal/inspection" || strings.HasPrefix(dependency, modulePath+"/internal/inspection/") {
			t.Fatalf("ordinary Operator imports inspection implementation directly instead of the product composition: %s", dependency)
		}
	}
	if !foundComposition {
		t.Fatal("ordinary Operator does not own the Inspection v2 product lifecycle")
	}

	mainPath := filepath.Join(repositoryRoot(t), "cmd", "cosmoedge-operator", "main.go")
	contents, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	defaultOff := regexp.MustCompile(`(?s)inspectionproduct\.Config\s*\{\s*Enabled:\s*false,.*?\}\s*,\s*inspectionproduct\.Factories\{\}\s*\)`)
	if !defaultOff.Match(contents) {
		t.Fatal("ordinary Operator must construct Inspection v2 with an explicit disabled config and no enabled factories")
	}

	assertNoForbiddenDependencies(t, "./internal/operator/inspectionproduct", []string{
		modulePath + "/internal/operator/actions",
		modulePath + "/internal/operator/app",
		modulePath + "/internal/operator/device",
		modulePath + "/internal/operator/kernel",
		modulePath + "/internal/operator/ledger",
		modulePath + "/internal/operator/read",
		modulePath + "/internal/operator/result",
		modulePath + "/internal/operator/session",
		modulePath + "/internal/operator/web",
		modulePath + "/internal/devwrite",
		modulePath + "/internal/devauthority",
		modulePath + "/internal/devlab",
		modulePath + "/internal/adapter",
		modulePath + "/internal/inspectiontest",
		modulePath + "/internal/inspectioneval",
	})
}

func TestProductionInspectionPackagesStayOutsideWriteAuthoritiesAndTestTools(t *testing.T) {
	productionRoots := listPackages(t, "./internal/inspection/...")
	forbidden := append([]string(nil), authorityDependencies...)
	forbidden = append(forbidden,
		modulePath+"/internal/inspectiontest",
		modulePath+"/internal/inspectioneval",
	)

	for _, root := range productionRoots {
		root := root
		t.Run(strings.TrimPrefix(root, "./"), func(t *testing.T) {
			assertNoForbiddenDependencies(t, root, forbidden)
		})
	}
}

func TestInspectionMayDependOnlyOnTypedOperatorAuthorityBoundary(t *testing.T) {
	productionRoots := listPackages(t, "./internal/inspection/...")
	for _, root := range productionRoots {
		dependencies := listDependencies(t, root)
		for _, dependency := range dependencies {
			if dependency == modulePath+"/internal/operator/authority" {
				continue
			}
			if strings.HasPrefix(dependency, modulePath+"/internal/operator/") {
				t.Fatalf("%s reaches Operator implementation package %s; only the typed authority boundary is allowed", root, dependency)
			}
		}
	}
}

func listPackages(t *testing.T, pattern string) []string {
	t.Helper()
	root := repositoryRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "list", "-mod=readonly", pattern)
	command.Dir = root
	command.Env = environmentWithoutGoWork()
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("go list packages for %s: %v", pattern, ctx.Err())
	}
	if err != nil {
		t.Fatalf("go list packages for %s: %v\n%s", pattern, err, bytes.TrimSpace(output))
	}
	packages := strings.Fields(string(output))
	if len(packages) == 0 {
		t.Fatalf("go list packages for %s returned no packages", pattern)
	}
	return packages
}

func TestInspectionFixturesStayOutsideWriteAuthorities(t *testing.T) {
	assertNoForbiddenDependencies(t, "./internal/inspectiontest", authorityDependencies)
}

func assertNoForbiddenDependencies(t *testing.T, packageRoot string, forbidden []string) {
	t.Helper()
	dependencies := listDependencies(t, packageRoot)
	var violations []string
	for _, dependency := range dependencies {
		for _, prefix := range forbidden {
			if dependency == prefix || strings.HasPrefix(dependency, prefix+"/") {
				violations = append(violations, dependency)
				break
			}
		}
	}
	if len(violations) == 0 {
		return
	}
	sort.Strings(violations)
	t.Fatalf("%s reaches forbidden dependencies:\n  %s", packageRoot, strings.Join(violations, "\n  "))
}

func listDependencies(t *testing.T, packageRoot string) []string {
	t.Helper()
	root := repositoryRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "list", "-deps", "-mod=readonly", packageRoot)
	command.Dir = root
	command.Env = environmentWithoutGoWork()
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("go list dependencies for %s: %v", packageRoot, ctx.Err())
	}
	if err != nil {
		t.Fatalf("go list dependencies for %s: %v\n%s", packageRoot, err, bytes.TrimSpace(output))
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	dependencies := make([]string, 0, len(lines))
	for _, line := range lines {
		if dependency := strings.TrimSpace(line); dependency != "" {
			dependencies = append(dependencies, dependency)
		}
	}
	return dependencies
}

func listDirectDependencies(t *testing.T, packageRoot string) []string {
	t.Helper()
	root := repositoryRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-f", `{{join .Imports "\n"}}`, packageRoot)
	command.Dir = root
	command.Env = environmentWithoutGoWork()
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("go list direct dependencies for %s: %v", packageRoot, ctx.Err())
	}
	if err != nil {
		t.Fatalf("go list direct dependencies for %s: %v\n%s", packageRoot, err, bytes.TrimSpace(output))
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	dependencies := make([]string, 0, len(lines))
	for _, line := range lines {
		if dependency := strings.TrimSpace(line); dependency != "" {
			dependencies = append(dependencies, dependency)
		}
	}
	return dependencies
}

func environmentWithoutGoWork() []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "GOWORK=") {
			environment = append(environment, item)
		}
	}
	return append(environment, "GOWORK=off")
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(workingDirectory); resolveErr == nil {
		workingDirectory = resolved
	}
	for candidate := workingDirectory; ; candidate = filepath.Dir(candidate) {
		contents, readErr := os.ReadFile(filepath.Join(candidate, "go.mod"))
		if readErr == nil && hasModuleDeclaration(contents, modulePath) {
			return candidate
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			t.Fatalf("repository root with module %s was not found above %s", modulePath, workingDirectory)
		}
	}
}

func hasModuleDeclaration(contents []byte, expected string) bool {
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		return line == "module "+expected
	}
	return false
}

var syntheticDataLeaks = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:https?|rtsps?|file)://`),
	regexp.MustCompile(`(?i)data:(?:image|video)/[a-z0-9.+-]+;base64,`),
	regexp.MustCompile(`(?i)"(?:password|credential|authorization|cookie|token|endpoint|deviceUrl|cameraHandle|sourceBindings?|sourceHandle|sourceRevision|sourceFingerprint|sourceCatalogFingerprint|capabilityRefs|imageBase64|videoBase64)"\s*:`),
	regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
}

func TestSyntheticEvaluationDataContainsNoEndpointOrCredentialMaterial(t *testing.T) {
	dataRoot := filepath.Join(repositoryRoot(t), "internal", "inspectioneval", "testdata")
	files := 0
	err := filepath.WalkDir(dataRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
			return nil
		}
		files++
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, pattern := range syntheticDataLeaks {
			if match := pattern.Find(contents); match != nil {
				return fmt.Errorf("%s contains protected material matching %q", filepath.Base(path), match)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatalf("no synthetic JSONL datasets found under %s", dataRoot)
	}
}
