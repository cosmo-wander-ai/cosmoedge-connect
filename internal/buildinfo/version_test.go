package buildinfo

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
)

func TestSourceIdentityUsesPairedInjectionOrVCSFallback(t *testing.T) {
	originalRevision, originalModified := SourceRevision, SourceModified
	t.Cleanup(func() { SourceRevision, SourceModified = originalRevision, originalModified })
	vcsRevision, pairedRevision := strings.Repeat("a", 40), strings.Repeat("b", 40)
	settings := []debug.BuildSetting{{Key: "vcs.revision", Value: vcsRevision}, {Key: "vcs.modified", Value: "true"}}
	for _, test := range []struct {
		name, revision, modified, wantRevision string
		settings                               []debug.BuildSetting
		wantModified                           bool
	}{
		{name: "ordinary VCS build", settings: settings, wantRevision: vcsRevision, wantModified: true},
		{name: "worktree paired clean", revision: pairedRevision, modified: "false", wantRevision: pairedRevision},
		{name: "worktree paired dirty", revision: pairedRevision, modified: "true", wantRevision: pairedRevision, wantModified: true},
		{name: "paired identity overrides VCS", settings: settings, revision: pairedRevision, modified: "false", wantRevision: pairedRevision},
		{name: "missing paired value retains VCS", settings: settings, revision: pairedRevision, wantRevision: vcsRevision, wantModified: true},
		{name: "invalid paired boolean retains VCS", settings: settings, revision: pairedRevision, modified: "invalid", wantRevision: vcsRevision, wantModified: true},
		{name: "no identity is not invented"},
	} {
		t.Run(test.name, func(t *testing.T) {
			SourceRevision, SourceModified = test.revision, test.modified
			got := currentWithSettings(test.settings)
			if got.Revision != test.wantRevision || got.Modified != test.wantModified || got.Version != Version || got.Product != "cosmoedge-connect" {
				t.Fatalf("source identity: %+v", got)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			if _, ok := wire["modified"].(bool); !ok {
				t.Fatalf("modified is not a JSON boolean: %s", encoded)
			}
			if _, ok := wire["revision"].(string); !ok {
				t.Fatalf("revision is not a JSON string: %s", encoded)
			}
		})
	}
}
