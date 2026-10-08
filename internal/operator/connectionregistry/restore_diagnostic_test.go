package connectionregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectiondiagnostic"
)

func TestRestoreDiagnosticSeparatesSelectionFromMissingCredential(t *testing.T) {
	t.Parallel()
	h := openHarness(t, t.TempDir())
	defer h.close(t)
	var output bytes.Buffer
	ctx := connectiondiagnostic.WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&output, nil)))
	if _, err := h.registry.LoadCurrent(ctx); !errors.Is(err, ErrNoSavedConnection) {
		t.Fatal("empty profile was not distinguished")
	}
	assertRestoreStages(t, output.String(), []string{"selection:not_configured"})
	output.Reset()
	if err := h.registry.CommitVerified(ctx, testVerified("private-diagnostic-serial", "test-box"), []byte("private-diagnostic-secret")); err != nil {
		t.Fatal(err)
	}
	item, err := h.profiles.Get(ctx, testTenant, testSite, testProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.credentials.Delete(ctx, item.CredentialRef); err != nil {
		t.Fatal(err)
	}
	if _, err = h.registry.LoadCurrent(ctx); !errors.Is(err, ErrSavedConnectionAttention) {
		t.Fatal("missing credential did not retain attention state")
	}
	assertRestoreStages(t, output.String(), []string{"selection:ok", "credential_read:credential_missing"})
	output.Reset()
	if _, err = h.registry.LoadCurrent(ctx); !errors.Is(err, ErrSavedConnectionAttention) {
		t.Fatal("saved credential attention was not retained")
	}
	assertRestoreStages(t, output.String(), []string{"selection:needs_attention"})
}

func assertRestoreStages(t *testing.T, output string, want []string) {
	t.Helper()
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		got = append(got, event["stage"].(string)+":"+event["class"].(string))
	}
	if !reflect.DeepEqual(got, want) || strings.Contains(output, "private-diagnostic") || strings.Contains(output, "credential_ref") {
		t.Fatalf("unexpected stages or protected projection: %v", got)
	}
}
