package connectionowner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestOwnerPersistsRestoresAndRejectsDriftWithoutProductState(t *testing.T) {
	root := t.TempDir()
	token := writeTestToken(t, root)
	serial := "owner-test-device"
	calls := 0
	vault := session.New(func(endpoint, username, password string) device.Client {
		calls++
		if endpoint != "http://10.20.30.40:8000" || username != "operator" || password != "synthetic-owner-secret" {
			t.Fatal("unexpected restored connection binding")
		}
		return &ownerDevice{snapshot: device.Snapshot{Identity: device.Identity{Serial: serial, Type: "edge"}}}
	})
	owner, err := New(Config{StateRoot: filepath.Join(root, "state"), TokenFile: token, Vault: vault})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Stop()
	if state, err := owner.Start(context.Background()); err != nil || state != connectionregistry.RestoreNotConfigured {
		t.Fatalf("first start: %s %v", state, err)
	}
	connectOwnerVault(t, vault)
	if err := owner.VerifyCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	if digest, err := owner.TokenDigest(); err != nil || len(digest) != 64 {
		t.Fatalf("digest unavailable: %v", err)
	}
	if err := owner.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("stopped owner retained live connection")
	}
	if _, err := owner.TokenDigest(); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("closed digest: %v", err)
	}
	if state, err := owner.Start(context.Background()); err != nil || state != connectionregistry.RestoreConnected {
		t.Fatalf("restore: %s %v", state, err)
	}
	if err := owner.Stop(); err != nil {
		t.Fatal(err)
	}
	serial = "drifted-owner-test-device"
	if state, err := owner.Start(context.Background()); err != nil || state != connectionregistry.RestoreNeedsAttention {
		t.Fatalf("drift: %s %v", state, err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("drifted connection published")
	}
	if calls != 3 {
		t.Fatalf("factory calls %d, want initial connection and two restores", calls)
	}
	entries, err := os.ReadDir(filepath.Join(root, "state", "inspection-v2"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if strings.Join(names, ",") != "credentials,current-connection.db,device-profiles.db,onboarding-journal.db" {
		t.Fatalf("connection started unrelated product state: %v", names)
	}
}

func TestOwnerStartupRollbackReleasesRootAndVault(t *testing.T) {
	root := t.TempDir()
	token := writeTestToken(t, root)
	stateRoot := filepath.Join(root, "state")
	vault := session.New(nil)
	bad, _ := New(Config{StateRoot: stateRoot, TokenFile: token, Vault: vault, Binding: Binding{TenantID: "invalid-partial"}})
	if _, err := bad.Start(context.Background()); err == nil {
		t.Fatal("invalid binding accepted")
	}
	good, _ := New(Config{StateRoot: stateRoot, TokenFile: token, Vault: vault})
	defer good.Stop()
	if _, err := good.Start(context.Background()); err != nil {
		t.Fatalf("rollback retained owner: %v", err)
	}
	other, _ := New(Config{StateRoot: stateRoot, TokenFile: token, Vault: session.New(nil)})
	if _, err := other.Start(context.Background()); !errors.Is(err, ErrAlreadyOwned) {
		t.Fatalf("second owner: %v", err)
	}
	if err := good.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Start(context.Background()); err != nil {
		t.Fatalf("released root unavailable: %v", err)
	}
	if err := other.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerRestoreAlwaysSuppliesTenSecondBudget(t *testing.T) {
	root := t.TempDir()
	client := &ownerDevice{snapshot: device.Snapshot{Identity: device.Identity{Serial: "budget-owner-device", Type: "edge"}}}
	vault := session.New(func(_, _, _ string) device.Client { return client })
	owner, err := New(Config{StateRoot: filepath.Join(root, "state"), TokenFile: writeTestToken(t, root), Vault: vault})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Stop()
	if _, err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	connectOwnerVault(t, vault)
	if err := owner.Stop(); err != nil {
		t.Fatal(err)
	}
	checked := false
	client.login = func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining > 10*time.Second || remaining < 9*time.Second {
			t.Fatalf("startup restoration budget is not ten seconds: %s", remaining)
		}
		checked = true
		return errors.New("simulated offline device")
	}
	if state, err := owner.Start(context.Background()); err != nil || state != connectionregistry.RestoreNeedsAttention || !checked {
		t.Fatalf("offline owner: %s %v checked=%t", state, err, checked)
	}
	if err := owner.VerifyCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.login = nil
	connectOwnerVault(t, vault)
	if _, _, connected := vault.ConnectedIdentity(); !connected {
		t.Fatal("local repair unavailable after offline restore")
	}
}

func TestRootLeaseRejectsSameAndOtherProcessAndAllowsReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireLease(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := AcquireLease(root); !errors.Is(err, ErrAlreadyOwned) {
		t.Fatalf("same process: %v", err)
	}
	child := func(want int) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestStateLeaseProcessHelper$")
		cmd.Env = append(os.Environ(), "COSMOEDGE_CONNECT_TEST_LEASE_ROOT="+root)
		output, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != want {
			t.Fatalf("child lease exit %d, want %d: %s", code, want, output)
		}
	}
	child(23)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	child(0)
	reopened, err := AcquireLease(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLeaseProcessHelper(t *testing.T) {
	root := os.Getenv("COSMOEDGE_CONNECT_TEST_LEASE_ROOT")
	if root == "" {
		return
	}
	lease, err := AcquireLease(root)
	if errors.Is(err, ErrAlreadyOwned) {
		os.Exit(23)
	}
	if err != nil {
		os.Exit(24)
	}
	if err := lease.Close(); err != nil {
		os.Exit(25)
	}
	os.Exit(0)
}

func writeTestToken(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "access.token")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	return path
}
func connectOwnerVault(t *testing.T, vault *session.Vault) {
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
	secret := []byte("synthetic-owner-secret")
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, secret); err != nil {
		t.Fatal(err)
	}
	for _, b := range secret {
		if b != 0 {
			t.Fatal("connection secret retained")
		}
	}
}

type ownerDevice struct {
	snapshot device.Snapshot
	login    func(context.Context) error
}

func (d *ownerDevice) Login(ctx context.Context) error {
	if d.login != nil {
		return d.login(ctx)
	}
	return nil
}
func (d *ownerDevice) Read(context.Context) (device.Snapshot, error) { return d.snapshot, nil }
func (*ownerDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{}
}
