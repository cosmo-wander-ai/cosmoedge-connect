package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalSkillExplicitCapabilitiesIntentUsesInstalledCLIOnly(t *testing.T) {
	skillRoot := filepath.Join("..", "..", "integrations", "agent", "cosmoedge-site-inspection")
	raw, err := os.ReadFile(filepath.Join(skillRoot, "SKILL.md"))
	if err != nil {
		t.Fatalf("read canonical Skill: %v", err)
	}
	document := string(raw)
	for _, required := range []string{
		"name: cosmoedge-site-inspection",
		"physical-site",
		"`cosmoedge-inspection capabilities`",
		"empty standard input",
		"exactly one JSON envelope",
	} {
		if !strings.Contains(document, required) {
			t.Fatalf("canonical Skill is missing explicit capabilities behavior %q", required)
		}
	}
	for _, forbidden := range []string{
		"python", "go run", "/api/inspection", "Authorization", "token", "<skill-root>", "output-dir",
	} {
		if strings.Contains(strings.ToLower(document), strings.ToLower(forbidden)) {
			t.Fatalf("canonical Skill exposes implementation choreography %q", forbidden)
		}
	}
	metadata, err := os.ReadFile(filepath.Join(skillRoot, "agents", "openai.yaml"))
	if err != nil {
		t.Fatalf("read canonical Skill metadata: %v", err)
	}
	if !strings.Contains(string(metadata), `allow_implicit_invocation: true`) {
		t.Fatal("canonical Skill metadata does not permit the specified future implicit routing")
	}
}

func TestCanonicalSkillInspectIntentForwardsOnlyBusinessInput(t *testing.T) {
	path := filepath.Join("..", "..", "integrations", "agent", "cosmoedge-site-inspection", "SKILL.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	for _, required := range []string{
		"`cosmoedge-inspection inspect`", "`instruction`", "`context`", "working", "ready", "Result Projection",
	} {
		if !strings.Contains(document, required) {
			t.Fatalf("canonical Skill is missing inspect forwarding behavior %q", required)
		}
	}
	for _, forbidden := range []string{"subject", "region", "observable", "run reference", "poll"} {
		if strings.Contains(strings.ToLower(document), forbidden) {
			t.Fatalf("canonical Skill asks the model to manage inspect internals %q", forbidden)
		}
	}
}

func TestCanonicalSkillFollowupUsesContinueWithoutUserManagedReference(t *testing.T) {
	path := filepath.Join("..", "..", "integrations", "agent", "cosmoedge-site-inspection", "SKILL.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	for _, required := range []string{"`cosmoedge-inspection continue`", "clarification", "area", "goal", "startedAt", "never display", "user clearly selects", `{"runRef":`} {
		if !strings.Contains(document, required) {
			t.Fatalf("canonical Skill is missing follow-up behavior %q", required)
		}
	}
	for _, forbidden := range []string{"remember a run", "manual reference", "newest"} {
		if strings.Contains(strings.ToLower(document), forbidden) {
			t.Fatalf("canonical Skill exposes continuation policy %q", forbidden)
		}
	}
}
