package connectionbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectiondiagnostic"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestLifecycleBindsExactVaultUntilStopped(t *testing.T) {
	registry := openTestRegistry(t)
	vault := session.New(nil)
	lifecycle, err := New(vault, registry)
	if err != nil {
		t.Fatal(err)
	}

	state, err := lifecycle.Start(context.Background())
	if err != nil || state != connectionregistry.RestoreNotConfigured {
		t.Fatalf("Start() state=%q err=%v", state, err)
	}
	if _, err := lifecycle.Start(context.Background()); !errors.Is(err, session.ErrConflict) {
		t.Fatalf("second Start() error=%v, want conflict", err)
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}

	state, err = lifecycle.Start(context.Background())
	if err != nil || state != connectionregistry.RestoreNotConfigured {
		t.Fatalf("Start(after Stop) state=%q err=%v", state, err)
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatalf("idempotent Stop() error=%v", err)
	}
}

func TestLifecycleRestoreFailureReleasesVaultBinding(t *testing.T) {
	registry := openTestRegistry(t)
	vault := session.New(nil)
	lifecycle, err := New(vault, registry)
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lifecycle.Start(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(cancelled) error=%v", err)
	}

	state, err := lifecycle.Start(context.Background())
	if err != nil || state != connectionregistry.RestoreNotConfigured {
		t.Fatalf("Start(after failed restore) state=%q err=%v", state, err)
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestLifecyclePersistsRestoresExactIdentityAndStopsEveryGeneration(t *testing.T) {
	registry := openTestRegistry(t)
	const (
		endpoint = "http://10.20.30.40:8000"
		username = "operator"
		password = "device-secret"
		serial   = "SN-BRIDGE-001"
	)
	factoryCalls := 0
	vault := session.New(func(gotEndpoint, gotUsername, gotPassword string) device.Client {
		factoryCalls++
		if gotEndpoint != endpoint || gotUsername != username || gotPassword != password {
			t.Fatalf("factory binding=(%q, %q, %q)", gotEndpoint, gotUsername, gotPassword)
		}
		observedSerial := serial
		if factoryCalls == 3 {
			observedSerial = "SN-BRIDGE-DRIFTED"
		}
		return &bridgeDevice{snapshot: device.Snapshot{Identity: device.Identity{Serial: observedSerial, Type: "edge"}}}
	})
	lifecycle, err := New(vault, registry)
	if err != nil {
		t.Fatal(err)
	}
	state, err := lifecycle.Start(context.Background())
	if err != nil || state != connectionregistry.RestoreNotConfigured {
		t.Fatalf("first Start() state=%q err=%v", state, err)
	}
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", username)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(password)
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, secret); err != nil {
		t.Fatal(err)
	}
	if !zeroed(secret) {
		t.Fatal("caller secret was not cleared")
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("stopped lifecycle retained the first live connection")
	}

	state, err = lifecycle.Start(context.Background())
	if err != nil || state != connectionregistry.RestoreConnected {
		t.Fatalf("restored Start() state=%q err=%v", state, err)
	}
	if masked, kind, connected := vault.ConnectedIdentity(); !connected || masked != "***-001" || kind != "edge" {
		t.Fatalf("restored identity masked=%q type=%q connected=%t", masked, kind, connected)
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}

	state, err = lifecycle.Start(context.Background())
	if err != nil || state != connectionregistry.RestoreNeedsAttention {
		t.Fatalf("drifted Start() state=%q err=%v", state, err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("identity drift published a live connection")
	}
	if err := lifecycle.Stop(); err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 3 {
		t.Fatalf("factory calls=%d, want initial connection plus two fresh restores", factoryCalls)
	}
}

func TestNewRejectsMissingLifecycleOwners(t *testing.T) {
	registry := openTestRegistry(t)
	if _, err := New(nil, registry); err == nil {
		t.Fatal("New(nil Vault) succeeded")
	}
	if _, err := New(session.New(nil), nil); err == nil {
		t.Fatal("New(nil Registry) succeeded")
	}
}

func TestBoundedRestorePreservesPersistenceOnlyOnOwnTimeout(t *testing.T) {
	for _, scenario := range []struct{ name, stage, parent string }{
		{"login timeout", "login", ""},
		{"read timeout", "read", ""},
		{"partial read after timeout", "partial_read", ""},
		{"parent cancellation", "login", "cancel"},
		{"parent deadline", "read", "deadline"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			registry := openTestRegistry(t)
			blocking := false
			ctx := context.Background()
			cancelParent := func() {}
			wait := func(callCtx context.Context) error {
				if !blocking {
					return nil
				}
				if scenario.parent == "cancel" {
					cancelParent()
				}
				<-callCtx.Done()
				return callCtx.Err()
			}
			client := &bridgeDevice{snapshot: device.Snapshot{Identity: device.Identity{Serial: "SN-BOUNDED", Type: "edge"}}}
			if scenario.stage == "login" {
				client.login = wait
			} else if scenario.stage == "partial_read" {
				client.read = func(ctx context.Context) error { _ = wait(ctx); return nil }
			} else {
				client.read = wait
			}
			vault := session.New(func(_, _, _ string) device.Client { return client })
			lifecycle, err := New(vault, registry)
			if err != nil {
				t.Fatal(err)
			}
			defer lifecycle.Stop()
			if _, err := lifecycle.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			connectBridgeVault(t, vault)
			if err := lifecycle.Stop(); err != nil {
				t.Fatal(err)
			}
			blocking = true
			limit := 20 * time.Millisecond
			if scenario.parent != "" {
				limit = time.Second
			}
			// Start the parent's real deadline only after the initial connection,
			// SQLite persistence and shutdown have finished. Those fixture writes
			// can exceed 50 ms under -race before the restore under test starts.
			if scenario.parent == "cancel" {
				ctx, cancelParent = context.WithCancel(ctx)
			} else if scenario.parent == "deadline" {
				ctx, cancelParent = context.WithTimeout(ctx, 50*time.Millisecond)
			}
			defer cancelParent()
			var diagnostic bytes.Buffer
			ctx = connectiondiagnostic.WithLogger(ctx, slog.New(slog.NewJSONHandler(&diagnostic, nil)))
			started := time.Now()
			state, err := lifecycle.StartWithRestoreTimeout(ctx, limit)
			if time.Since(started) > time.Second {
				t.Fatal("restore exceeded bounded test allowance")
			}
			var last map[string]any
			phaseFound := false
			phase := "device_read"
			if scenario.stage == "login" {
				phase = "login"
			}
			phaseClass, totalClass := "deadline_exceeded", "budget_expired"
			if scenario.parent == "cancel" {
				phaseClass, totalClass = "canceled", "canceled"
			} else if scenario.parent == "deadline" {
				totalClass = "deadline_exceeded"
			}
			for _, line := range strings.Split(strings.TrimSpace(diagnostic.String()), "\n") {
				if err := json.Unmarshal([]byte(line), &last); err != nil {
					t.Fatal(err)
				}
				if last["stage"] == phase && last["class"] == phaseClass {
					phaseFound = true
				}
			}
			if !phaseFound || last["stage"] != "total" || last["class"] != totalClass {
				t.Fatalf("restore deadline phase diagnostic missing: %s", diagnostic.String())
			}
			if scenario.parent == "" {
				if err != nil || state != connectionregistry.RestoreNeedsAttention {
					t.Fatalf("own budget: %s %v", state, err)
				}
				if _, err := vault.BindConnectionPersistence(persistenceAdapter{registry: registry}); !errors.Is(err, session.ErrConflict) {
					t.Fatalf("timeout released durable owner: %v", err)
				}
			} else {
				if !errors.Is(err, ctx.Err()) || state != "" {
					t.Fatalf("parent failure swallowed: %s %v", state, err)
				}
				lease, err := vault.BindConnectionPersistence(persistenceAdapter{registry: registry})
				if err != nil {
					t.Fatalf("parent failure retained owner: %v", err)
				}
				if err := lease.Release(); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, connected := vault.ConnectedIdentity(); connected {
				t.Fatal("timed-out restore published a connection")
			}
			if err := registry.VerifyCurrent(context.Background()); err != nil {
				t.Fatalf("timeout changed saved credential/profile: %v", err)
			}
			blocking = false
			if scenario.parent == "" {
				connectBridgeVault(t, vault)
				if err := registry.VerifyCurrent(context.Background()); err != nil {
					t.Fatalf("local reconnect unavailable after budget: %v", err)
				}
			}
			if err := lifecycle.Stop(); err != nil {
				t.Fatal(err)
			}
			if state, err := lifecycle.Start(context.Background()); err != nil || state != connectionregistry.RestoreConnected {
				t.Fatalf("saved connection could not recover: %s %v", state, err)
			}
		})
	}
}

func TestBoundedRestoreRejectsExpiredParentInvalidBudgetAndOwnershipConflict(t *testing.T) {
	registry := openTestRegistry(t)
	vault := session.New(nil)
	lifecycle, err := New(vault, registry)
	if err != nil {
		t.Fatal(err)
	}
	// An already-cancelled parent must never become needs_attention, even if
	// its deadline would be indistinguishable from a local budget by error text.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if state, err := lifecycle.StartWithRestoreTimeout(ctx, time.Second); state != "" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline: %s %v", state, err)
	}
	if _, err := lifecycle.StartWithRestoreTimeout(context.Background(), 0); err == nil {
		t.Fatal("zero timeout accepted")
	}
	lease, err := vault.BindConnectionPersistence(persistenceAdapter{registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if state, err := lifecycle.StartWithRestoreTimeout(context.Background(), time.Second); state != "" || !errors.Is(err, session.ErrConflict) {
		t.Fatalf("ownership error swallowed: %s %v", state, err)
	}
}

func connectBridgeVault(t *testing.T, vault *session.Vault) {
	t.Helper()
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, []byte("synthetic-bounded-secret")); err != nil {
		t.Fatal(err)
	}
}

func openTestRegistry(t *testing.T) *connectionregistry.Registry {
	t.Helper()
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	profiles, err := profile.Open(filepath.Join(root, "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	credentials := credential.NewMemoryStore()
	journal, err := onboarding.OpenJournal(filepath.Join(root, "onboarding.db"))
	if err != nil {
		_ = profiles.Close()
		t.Fatal(err)
	}
	signer, err := authority.NewSigner("connection-bridge-test", []byte(strings.Repeat("s", 32)))
	if err != nil {
		_ = journal.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	core, err := onboarding.NewService(profiles, credentials, journal, signer)
	if err != nil {
		signer.Close()
		_ = journal.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	registry, err := connectionregistry.New(connectionregistry.Config{
		Profiles: profiles, Credentials: credentials, Onboarding: core, Issuer: signer,
		TenantID: "tenant-bridge", SiteID: "site-bridge", PrincipalSHA256: strings.Repeat("a", 64),
		ProfileID: "dpf_0123456789abcdef0123456789abcdef", CreateOperationID: "onb_0123456789abcdef0123456789abcdef",
		Alias: "当前设备",
	})
	if err != nil {
		signer.Close()
		_ = journal.Close()
		_ = profiles.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		signer.Close()
		if err := errors.Join(journal.Close(), profiles.Close()); err != nil {
			t.Error(err)
		}
	})
	return registry
}

type bridgeDevice struct {
	snapshot device.Snapshot
	login    func(context.Context) error
	read     func(context.Context) error
}

func (d *bridgeDevice) Login(ctx context.Context) error {
	if d.login != nil {
		return d.login(ctx)
	}
	return nil
}

func (d *bridgeDevice) Read(ctx context.Context) (device.Snapshot, error) {
	if d.read != nil {
		if err := d.read(ctx); err != nil {
			return device.Snapshot{}, err
		}
	}
	return d.snapshot, nil
}

func (*bridgeDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{ByTask: map[string]device.TaskEventObservation{}}
}

func zeroed(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
