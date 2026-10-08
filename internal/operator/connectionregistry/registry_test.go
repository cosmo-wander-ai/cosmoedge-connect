package connectionregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestRegistryPersistsOnceAndRestoresThroughANewVaultAndProcessState(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first := openHarness(t, root)
	verified := testVerified("SN-REGISTRY-001", "edge-box")
	secret := []byte("restart-only-device-secret")
	if err := first.registry.CommitVerified(context.Background(), verified, secret); err != nil {
		t.Fatal(err)
	}
	if !allZero(secret) {
		t.Fatal("registry did not clear committed secret")
	}
	first.close(t)
	assertFilesDoNotContain(t, root, "restart-only-device-secret")

	second := openHarness(t, root)
	defer second.close(t)
	vault := session.New(func(endpoint, username, password string) device.Client {
		if endpoint != verified.Endpoint || username != verified.Username || password != "restart-only-device-secret" {
			t.Fatal("restart restore changed protected connection material")
		}
		return &registryDevice{snapshot: snapshot(verified.PinnedSerial, verified.PinnedType)}
	})
	if _, err := vault.BindConnectionPersistence(testPersistenceAdapter{registry: second.registry}); err != nil {
		t.Fatal(err)
	}
	result, err := vault.Restore(context.Background())
	if err != nil || result.State != session.RestoreConnected {
		t.Fatalf("Restore()=(%#v, %v)", result, err)
	}
	if _, _, connected := vault.ConnectedIdentity(); !connected {
		t.Fatal("restart restore did not publish a live connection")
	}
}

func TestRegistryRotatesChangedCredentialAndRestoresOnlyNewSecret(t *testing.T) {
	t.Parallel()
	h := openHarness(t, t.TempDir())
	defer h.close(t)
	verified := testVerified("SN-REGISTRY-ROTATE", "edge-box")
	oldSecret := []byte("old-device-secret")
	if err := h.registry.CommitVerified(context.Background(), verified, oldSecret); err != nil {
		t.Fatal(err)
	}
	newSecret := []byte("new-device-secret")
	if err := h.registry.CommitVerified(context.Background(), verified, newSecret); err != nil {
		t.Fatal(err)
	}
	if !allZero(newSecret) {
		t.Fatal("rotated caller secret was not cleared")
	}
	vault := session.New(func(_, _, password string) device.Client {
		if password != "new-device-secret" {
			t.Fatalf("restored stale password %q", password)
		}
		return &registryDevice{snapshot: snapshot(verified.PinnedSerial, verified.PinnedType)}
	})
	if _, err := vault.BindConnectionPersistence(testPersistenceAdapter{registry: h.registry}); err != nil {
		t.Fatal(err)
	}
	if result, err := vault.Restore(context.Background()); err != nil || result.State != session.RestoreConnected {
		t.Fatalf("Restore()=(%#v, %v)", result, err)
	}
}

func TestRegistryWrongSavedCredentialFailsClosedAndPersistsAttentionState(t *testing.T) {
	t.Parallel()
	h := openHarness(t, t.TempDir())
	defer h.close(t)
	verified := testVerified("SN-REGISTRY-WRONG", "edge-box")
	if err := h.registry.CommitVerified(context.Background(), verified, []byte("saved-but-now-wrong")); err != nil {
		t.Fatal(err)
	}
	vault := session.New(func(_, _, _ string) device.Client {
		return &registryDevice{loginErr: registryAuthenticationRejected{}}
	})
	if _, err := vault.BindConnectionPersistence(testPersistenceAdapter{registry: h.registry}); err != nil {
		t.Fatal(err)
	}
	result, err := vault.Restore(context.Background())
	if err != nil || result.State != session.RestoreNeedsAttention {
		t.Fatalf("Restore()=(%#v, %v)", result, err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("wrong credential restored a live connection")
	}
	item, err := h.profiles.Get(context.Background(), testTenant, testSite, testProfileID)
	if err != nil || item.CredentialState != profile.CredentialUnavailable {
		t.Fatalf("profile credential state=%q err=%v", item.CredentialState, err)
	}
}

func TestRegistryIdentityDriftFailsClosedAndMarksExactProfile(t *testing.T) {
	t.Parallel()
	h := openHarness(t, t.TempDir())
	defer h.close(t)
	verified := testVerified("SN-REGISTRY-PINNED", "edge-box")
	if err := h.registry.CommitVerified(context.Background(), verified, []byte("device-secret")); err != nil {
		t.Fatal(err)
	}
	vault := session.New(func(_, _, _ string) device.Client {
		return &registryDevice{snapshot: snapshot("SN-REGISTRY-DRIFTED", "edge-box")}
	})
	if _, err := vault.BindConnectionPersistence(testPersistenceAdapter{registry: h.registry}); err != nil {
		t.Fatal(err)
	}
	result, err := vault.Restore(context.Background())
	if err != nil || result.State != session.RestoreNeedsAttention {
		t.Fatalf("Restore()=(%#v, %v)", result, err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("identity drift restored a live connection")
	}
	item, err := h.profiles.Get(context.Background(), testTenant, testSite, testProfileID)
	if err != nil || item.State != profile.StateIdentityDrift {
		t.Fatalf("profile state=%q err=%v", item.State, err)
	}
}

func TestRegistryErrorsAndProtectedInputsDoNotLeakConnectionMaterial(t *testing.T) {
	t.Parallel()
	h := openHarness(t, t.TempDir())
	defer h.close(t)
	verified := testVerified("PRIVATE-REGISTRY-SERIAL", "private-device-type")
	secret := []byte("private-registry-password")
	if err := h.registry.CommitVerified(context.Background(), verified, secret); err != nil {
		t.Fatal(err)
	}
	conflict := verified
	conflict.PinnedSerial = "OTHER-PRIVATE-SERIAL"
	err := h.registry.CommitVerified(context.Background(), conflict, []byte("private-registry-password-2"))
	if !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("conflict error=%v", err)
	}
	var output bytes.Buffer
	slog.New(slog.NewJSONHandler(&output, nil)).Error("registry", "error", err, "verified", verified)
	projection := fmt.Sprintf("%v %s", err, output.String())
	for _, forbidden := range []string{verified.Endpoint, verified.Username, verified.PinnedSerial, verified.PinnedType, "private-registry-password"} {
		if strings.Contains(projection, forbidden) {
			t.Fatalf("registry projection leaked %q", forbidden)
		}
	}
}

const (
	testTenant     = "tenant-registry"
	testSite       = "site-registry"
	testPrincipal  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testProfileID  = "dpf_0123456789abcdef0123456789abcdef"
	testCreateOpID = "onb_0123456789abcdef0123456789abcdef"
)

type registryHarness struct {
	registry    *Registry
	profiles    *profile.Store
	credentials *credential.EncryptedFileStore
	journal     *onboarding.Journal
	signer      *authority.Signer
}

func openHarness(t *testing.T, root string) *registryHarness {
	t.Helper()
	root = filepath.Join(root, "state")
	profiles, err := profile.Open(filepath.Join(root, "device-profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := credential.OpenEncryptedFileStore(filepath.Join(root, "credentials.bin"), bytes.Repeat([]byte{0x4d}, 32))
	if err != nil {
		_ = profiles.Close()
		t.Fatal(err)
	}
	journal, err := onboarding.OpenJournal(filepath.Join(root, "onboarding.db"))
	if err != nil {
		_ = credentials.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	signer, err := authority.NewSigner("connection-registry-test", bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		_ = journal.Close()
		_ = credentials.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	core, err := onboarding.NewService(profiles, credentials, journal, signer)
	if err != nil {
		signer.Close()
		_ = journal.Close()
		_ = credentials.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	registry, err := New(Config{
		Profiles: profiles, Credentials: credentials, Onboarding: core, Issuer: signer,
		TenantID: testTenant, SiteID: testSite, PrincipalSHA256: testPrincipal,
		ProfileID: testProfileID, CreateOperationID: testCreateOpID, Alias: "当前设备",
	})
	if err != nil {
		signer.Close()
		_ = journal.Close()
		_ = credentials.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	return &registryHarness{registry: registry, profiles: profiles, credentials: credentials, journal: journal, signer: signer}
}

func (h *registryHarness) close(t *testing.T) {
	t.Helper()
	h.signer.Close()
	if err := errors.Join(h.journal.Close(), h.credentials.Close(), h.profiles.Close()); err != nil {
		t.Fatal(err)
	}
}

func testVerified(serial, deviceType string) VerifiedConnection {
	endpoint := "http://10.40.50.60:8000"
	username := "registry-admin"
	sum := sha256.Sum256([]byte(endpoint + "\x00" + username))
	return VerifiedConnection{
		Endpoint: endpoint, Username: username, PinnedSerial: serial, PinnedType: deviceType,
		TransportFingerprint: hex.EncodeToString(sum[:]),
	}
}

type testPersistenceAdapter struct{ registry *Registry }

func (a testPersistenceAdapter) CommitVerified(ctx context.Context, value session.VerifiedConnection, secret []byte) error {
	return a.registry.CommitVerified(ctx, VerifiedConnection{
		Endpoint: value.Endpoint, Username: value.Username, PinnedSerial: value.PinnedSerial,
		PinnedType: value.PinnedType, TransportFingerprint: value.TransportFingerprint,
	}, secret)
}

func (a testPersistenceAdapter) LoadCurrent(ctx context.Context) (session.RestoreCandidate, error) {
	candidate, err := a.registry.LoadCurrent(ctx)
	if errors.Is(err, ErrNoSavedConnection) {
		return session.RestoreCandidate{}, session.ErrNoSavedConnection
	}
	if errors.Is(err, ErrSavedConnectionAttention) {
		return session.RestoreCandidate{}, session.ErrSavedConnectionAttention
	}
	if err != nil {
		return session.RestoreCandidate{}, err
	}
	var result session.RestoreCandidate
	err = candidate.Consume(func(binding PersistentBinding, secret []byte) error {
		created, createErr := session.NewRestoreCandidate(session.PersistentBinding{
			ProfileID: binding.ProfileID, Generation: binding.Generation, Endpoint: binding.Endpoint,
			Username: binding.Username, PinnedSerial: binding.PinnedSerial, PinnedType: binding.PinnedType,
			TransportFingerprint: binding.TransportFingerprint,
		}, secret)
		result = created
		return createErr
	})
	return result, err
}

func (a testPersistenceAdapter) MarkIdentityDrift(ctx context.Context, binding session.PersistentBinding) error {
	return a.registry.MarkIdentityDrift(ctx, testRegistryBinding(binding))
}

func (a testPersistenceAdapter) MarkCredentialUnavailable(ctx context.Context, binding session.PersistentBinding) error {
	return a.registry.MarkCredentialUnavailable(ctx, testRegistryBinding(binding))
}

func testRegistryBinding(binding session.PersistentBinding) PersistentBinding {
	return PersistentBinding{
		ProfileID: binding.ProfileID, Generation: binding.Generation, Endpoint: binding.Endpoint,
		Username: binding.Username, PinnedSerial: binding.PinnedSerial, PinnedType: binding.PinnedType,
		TransportFingerprint: binding.TransportFingerprint,
	}
}

func snapshot(serial, deviceType string) device.Snapshot {
	return device.Snapshot{Identity: device.Identity{Serial: serial, Type: deviceType}}
}

type registryDevice struct {
	loginErr error
	snapshot device.Snapshot
}

type registryAuthenticationRejected struct{}

func (registryAuthenticationRejected) Error() string                { return "authentication rejected" }
func (registryAuthenticationRejected) AuthenticationRejected() bool { return true }

func (d *registryDevice) Login(context.Context) error { return d.loginErr }
func (d *registryDevice) Read(context.Context) (device.Snapshot, error) {
	return d.snapshot, nil
}
func (*registryDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{ByTask: map[string]device.TaskEventObservation{}}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func assertFilesDoNotContain(t *testing.T, root, forbidden string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte(forbidden)) {
			return fmt.Errorf("protected secret found in %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
