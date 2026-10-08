package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type skillIntentCase struct {
	ID                     string     `json:"id"`
	Category               string     `json:"category"`
	Utterance              string     `json:"utterance"`
	Disposition            string     `json:"disposition"`
	Commands               [][]string `json:"commands"`
	Authority              string     `json:"authority"`
	NeedsFinalConfirmation bool       `json:"needsFinalConfirmation"`
}

func TestThinSkillIntentContract(t *testing.T) {
	t.Parallel()
	cases := readSkillIntentCases(t)
	if len(cases) != 30 {
		t.Fatalf("intent cases=%d, want 30", len(cases))
	}

	wantCategories := map[string]int{"query": 9, "open": 5, "action": 4, "boundary": 12}
	gotCategories := make(map[string]int)
	seenIDs := make(map[string]bool)
	coveredCommands := make(map[string]bool)
	for _, item := range cases {
		if item.ID == "" || item.Utterance == "" || seenIDs[item.ID] {
			t.Fatalf("invalid or duplicate intent id %q", item.ID)
		}
		seenIDs[item.ID] = true
		gotCategories[item.Category]++
		if item.Authority != "zero_write" {
			t.Fatalf("intent %s grants Skill write authority: %q", item.ID, item.Authority)
		}
		if !containsString([]string{"invoke", "local_page", "clarify", "refuse", "preserve_unknown"}, item.Disposition) {
			t.Fatalf("intent %s has invalid disposition %q", item.ID, item.Disposition)
		}
		if item.Disposition == "refuse" && len(item.Commands) != 0 {
			t.Fatalf("refused intent %s invokes commands", item.ID)
		}

		queriedTasks := false
		for _, args := range item.Commands {
			invocation, err := parseInvocation(args)
			if err != nil {
				t.Fatalf("intent %s command %q is outside the CLI whitelist: %v", item.ID, strings.Join(args, " "), err)
			}
			if invocation.mode != "query" && invocation.mode != "status" && invocation.mode != "open" {
				t.Fatalf("intent %s reached non-Skill mode %q", item.ID, invocation.mode)
			}
			joined := strings.ToLower(strings.Join(args, " "))
			for _, forbidden := range []string{"password", "credential", "confirmation", "journey", "worker", "recovery", "http://", "https://", "rtsp://", "rtsps://", " raw"} {
				if strings.Contains(" "+joined, forbidden) {
					t.Fatalf("intent %s command carries forbidden authority or data: %q", item.ID, joined)
				}
			}
			if joined == "query tasks" {
				queriedTasks = true
			}
			if len(args) > 1 && args[0] == "open" && args[1] == "task-index" && !queriedTasks {
				t.Fatalf("intent %s opens a task without a fresh friendly task query", item.ID)
			}
			coveredCommands[normalizeSkillCommand(args)] = true
		}
		if item.NeedsFinalConfirmation && item.Disposition != "local_page" {
			t.Fatalf("intent %s needs confirmation without a local-page handoff", item.ID)
		}
		if item.Disposition == "clarify" {
			for _, args := range item.Commands {
				if len(args) > 1 && args[0] == "open" && args[1] == "task-index" {
					t.Fatalf("ambiguous intent %s selected a task", item.ID)
				}
			}
		}
	}
	if !reflect.DeepEqual(gotCategories, wantCategories) {
		t.Fatalf("intent categories=%v, want %v", gotCategories, wantCategories)
	}

	wantCommands := []string{
		"open alarms", "open home", "open runtime", "open sources", "open task-index NUMBER disable",
		"open task-index NUMBER enable", "open task-index NUMBER parameters", "open tasks",
		"query alarms last_1h", "query alarms last_24h", "query alarms today", "query alarms yesterday",
		"query cameras", "query capabilities", "query overview", "query runtime", "query tasks", "status",
	}
	var gotCommands []string
	for command := range coveredCommands {
		gotCommands = append(gotCommands, command)
	}
	sort.Strings(gotCommands)
	if !reflect.DeepEqual(gotCommands, wantCommands) {
		t.Fatalf("corpus command coverage=%v, want %v", gotCommands, wantCommands)
	}
}

func TestThinSkillDocumentMatchesIntentContract(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "demo", "skill", "cosmoedge-operator", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	document := strings.Join(strings.Fields(string(raw)), " ")
	for _, required := range []string{
		"`query overview`", "`query cameras`", "`query tasks`", "`query runtime`", "`query capabilities`",
		"`query alarms today`", "`query alarms yesterday`", "`query alarms last_1h`", "`query alarms last_24h`",
		"`open home`", "`open tasks`", "`open sources`", "`open runtime`", "`open alarms`",
		"`open task-index NUMBER enable`", "`open task-index NUMBER disable`", "`open task-index NUMBER parameters`",
		"Never click or simulate the final business-confirmation button",
		"Never retry a write",
		"Never pass the user's text to the shell",
		"Do not accept a stream address in chat",
		"Preserve unavailable, incomplete, expired, cancelled, drift,",
	} {
		if !strings.Contains(document, strings.Join(strings.Fields(required), " ")) {
			t.Fatalf("Skill document is missing contract clause %q", required)
		}
	}
}

func readSkillIntentCases(t *testing.T) []skillIntentCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "skill-intents.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []skillIntentCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func normalizeSkillCommand(args []string) string {
	normalized := append([]string(nil), args...)
	if len(normalized) > 2 && normalized[0] == "open" && normalized[1] == "task-index" {
		normalized[2] = "NUMBER"
	}
	return strings.Join(normalized, " ")
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func TestThinSkillCorpusIsUserFacing(t *testing.T) {
	t.Parallel()
	for _, item := range readSkillIntentCases(t) {
		for _, internal := range []string{"choiceSetId", "selectorFingerprint", "businessConfirmationToken", "deviceWriteCount", "Journey", "Operation", "POC", "E3", "E4"} {
			if strings.Contains(item.Utterance, internal) {
				t.Fatalf("intent %s exposes internal term %s", item.ID, fmt.Sprintf("%q", internal))
			}
		}
	}
}
