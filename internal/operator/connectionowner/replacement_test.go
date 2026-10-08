package connectionowner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestExplicitReplacementPreservesOldProfileAndChangesAdmissionEpoch(t *testing.T) {
	root := t.TempDir()
	serials := map[string]string{"http://10.20.30.40:8000": "device-A", "http://10.20.30.41:8000": "device-B"}
	factoryCalls := 0
	vault := session.New(func(endpoint, _, secret string) device.Client {
		factoryCalls++
		client := &ownerDevice{snapshot: device.Snapshot{Identity: device.Identity{Serial: serials[endpoint], Type: "edge"}}}
		if secret != "synthetic-owner-secret" {
			client.login = func(context.Context) error { return errors.New("synthetic login failure") }
		}
		return client
	})
	owner, err := New(Config{StateRoot: filepath.Join(root, "state"), TokenFile: writeTestToken(t, root), Vault: vault})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Stop()
	if _, err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	connectOwnerVault(t, vault)
	initial, err := owner.current.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	old, err := owner.profiles.Get(context.Background(), owner.config.Binding.TenantID, owner.config.Binding.SiteID, initial.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	epochA, err := owner.registry.ConnectionEpoch(context.Background())
	if err != nil || epochA == "" {
		t.Fatal("initial epoch absent")
	}
	browser := replacementBrowser(t, vault)
	prepare := func(endpoint string) session.ConnectionPreview {
		t.Helper()
		p, err := vault.PrepareConnection(browser, endpoint, "operator")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	preview := prepare("10.20.30.41")
	if !preview.ReplacementRequired || !preview.ReplacementAvailable || preview.CurrentDestination == "" {
		t.Fatalf("replacement preview unavailable: required=%t available=%t", preview.ReplacementRequired, preview.ReplacementAvailable)
	}
	before := factoryCalls
	if _, err := vault.Connect(context.Background(), browser, preview.Token, []byte("synthetic-owner-secret")); !errors.Is(err, session.ErrConnectionReplacementRequired) {
		t.Fatalf("implicit replacement: %v", err)
	}
	if factoryCalls != before {
		t.Fatal("unconfirmed replacement contacted target")
	}
	stale := prepare("10.20.30.40")
	preview = prepare("10.20.30.41")
	if _, err := vault.ConnectConfirmed(context.Background(), browser, preview.Token, []byte("wrong-synthetic-secret"), true); err == nil {
		t.Fatal("wrong credentials replaced profile")
	}
	if selected, _ := owner.current.Current(context.Background()); selected != initial {
		t.Fatal("failed login changed selection")
	}
	preview = prepare("10.20.30.41")
	if _, err := vault.ConnectConfirmed(context.Background(), browser, preview.Token, []byte("synthetic-owner-secret"), true); err != nil {
		t.Fatal(err)
	}
	selectedB, _ := owner.current.Current(context.Background())
	epochB, _ := owner.registry.ConnectionEpoch(context.Background())
	if selectedB.ProfileID == initial.ProfileID || selectedB.Revision != initial.Revision+1 || epochA == epochB {
		t.Fatal("replacement reused old profile or epoch")
	}
	retained, err := owner.profiles.Get(context.Background(), old.TenantID, old.SiteID, old.ProfileID)
	if err != nil || retained != old {
		t.Fatal("replacement modified old protected profile")
	}
	secret, err := owner.credentials.Get(context.Background(), old.CredentialRef)
	if err != nil || string(secret) != "synthetic-owner-secret" {
		t.Fatal("replacement lost old credential")
	}
	clear(secret)
	before = factoryCalls
	if _, err := vault.ConnectConfirmed(context.Background(), browser, stale.Token, []byte("synthetic-owner-secret"), true); !errors.Is(err, session.ErrConflict) {
		t.Fatal("stale selection confirmation succeeded")
	}
	if factoryCalls != before {
		t.Fatal("stale confirmation contacted old target")
	}
	if _, _, connected := vault.ConnectedIdentity(); !connected {
		t.Fatal("stale confirmation disconnected current B")
	}
	if selected, _ := owner.current.Current(context.Background()); selected != selectedB {
		t.Fatal("stale selection changed current")
	}
	if err := owner.Stop(); err != nil {
		t.Fatal(err)
	}
	if state, err := owner.Start(context.Background()); err != nil || state != connectionregistry.RestoreConnected {
		t.Fatalf("restart: %s %v", state, err)
	}
	if current, err := owner.registry.ConnectionEpoch(context.Background()); err != nil || current != epochB {
		t.Fatal("restart changed admitted epoch")
	}
	// Same endpoint, different physical hardware is automatic identity drift,
	// never permission to repin the saved B profile.
	if err := owner.Stop(); err != nil {
		t.Fatal(err)
	}
	serials["http://10.20.30.41:8000"] = "device-C"
	if state, err := owner.Start(context.Background()); err != nil || state != connectionregistry.RestoreNeedsAttention {
		t.Fatalf("same endpoint drift: %s %v", state, err)
	}
	bProfile, err := owner.profiles.Get(context.Background(), old.TenantID, old.SiteID, selectedB.ProfileID)
	if err != nil || bProfile.PinnedSerial != "device-B" || bProfile.State != profile.StateIdentityDrift {
		t.Fatal("automatic restore repinned hardware")
	}
	browser = replacementBrowser(t, vault)
	preview = prepare("10.20.30.41")
	if !preview.ReplacementRequired {
		t.Fatal("drifted same-address profile not explicit replacement")
	}
	if _, err := vault.ConnectConfirmed(context.Background(), browser, preview.Token, []byte("synthetic-owner-secret"), true); err != nil {
		t.Fatal(err)
	}
	// Returning to A is a new selection, so old A action confirmations cannot
	// regain their endpoint fingerprint merely because hardware/address match.
	preview = prepare("10.20.30.40")
	if _, err := vault.ConnectConfirmed(context.Background(), browser, preview.Token, []byte("synthetic-owner-secret"), true); err != nil {
		t.Fatal(err)
	}
	epochAgain, _ := owner.registry.ConnectionEpoch(context.Background())
	if epochAgain == epochA || epochAgain == epochB {
		t.Fatal("A-to-B-to-A revived old admission")
	}
	profiles, err := owner.profiles.ListSite(context.Background(), old.TenantID, old.SiteID)
	if err != nil || len(profiles) != 4 {
		t.Fatalf("retained profiles=%d error=%v", len(profiles), err)
	}
	if err := owner.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "state", "inspection-v2", "current-connection.db")); err != nil {
		t.Fatal(err)
	}
	before = factoryCalls
	if _, err := owner.Start(context.Background()); !errors.Is(err, connectionregistry.ErrSavedConnectionAttention) {
		t.Fatalf("lost selector fell back to old A: %v", err)
	}
	if factoryCalls != before {
		t.Fatal("lost selector guessed a device to restore")
	}
}

func replacementBrowser(t *testing.T, vault *session.Vault) string {
	t.Helper()
	token, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := vault.ConsumeBootstrap(token)
	if err != nil {
		t.Fatal(err)
	}
	return browser.SessionID
}
