package inspectionproduct

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	operatorauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionbridge"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestPersistentConnectionRestoresAcrossProductGenerationAndReleasesOnStop(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	key := []byte(strings.Repeat("k", 32))
	signer, err := operatorauthority.NewSigner("product-connection-test", []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)

	var logins atomic.Uint64
	vault := session.New(func(_, _, password string) device.Client {
		return &persistentConnectionDevice{password: password, logins: &logins}
	})
	factories := PersistentFactories(signer, idleMediaPreparationAcquirer{}, validTestBuilders())
	factories.ConnectionAuthorityIssuer = signer
	factories.BuildConnectionLifecycle = func(registry *connectionregistry.Registry) (ConnectionLifecycle, error) {
		return connectionbridge.New(vault, registry)
	}
	factories.OpenCredentials = func(ctx context.Context, root string) (Opened[credential.SecretStore], error) {
		if err := ctx.Err(); err != nil {
			return Opened[credential.SecretStore]{}, err
		}
		store, err := credential.OpenEncryptedFileStore(filepath.Join(root, "product-secrets.bin"), key)
		if err != nil {
			return Opened[credential.SecretStore]{}, err
		}
		return Opened[credential.SecretStore]{Value: store, Close: store.Close}, nil
	}
	product, err := New(Config{
		Enabled: true, StateRoot: root, TemporaryWorkerOwner: "persistent-connection-test",
		PersistentConnection: &PersistentConnectionConfig{
			TenantID: "tenant-live", SiteID: "site-live",
			PrincipalSHA256:   strings.Repeat("a", 64),
			ProfileID:         "dpf_0123456789abcdef0123456789abcdef",
			CreateOperationID: "onb_0123456789abcdef0123456789abcdef",
			Alias:             "当前设备",
		},
	}, factories)
	if err != nil {
		t.Fatal(err)
	}

	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, err := product.ConnectionRestoreState(); err != nil || state != connectionregistry.RestoreNotConfigured {
		t.Fatalf("first restore state=%q err=%v", state, err)
	}
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	browser, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := vault.PrepareConnection(browser.SessionID, "192.168.0.20", "operator")
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("fresh-device-secret")
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, password); err != nil {
		t.Fatal(err)
	}
	if !allZero(password) {
		t.Fatal("caller password was not cleared")
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("stopped Product left a live device session")
	}

	if err := product.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, err := product.ConnectionRestoreState(); err != nil || state != connectionregistry.RestoreConnected {
		t.Fatalf("restart restore state=%q err=%v", state, err)
	}
	if masked, deviceType, connected := vault.ConnectedIdentity(); !connected || masked != "***7890" || deviceType != "edge-test" {
		t.Fatalf("restored identity masked=%q type=%q connected=%t", masked, deviceType, connected)
	}
	if logins.Load() != 2 {
		t.Fatalf("device login count=%d, want initial plus fresh restore", logins.Load())
	}
	if err := product.Stop(); err != nil {
		t.Fatal(err)
	}
}

type persistentConnectionDevice struct {
	password string
	logins   *atomic.Uint64
}

func (d *persistentConnectionDevice) Login(context.Context) error {
	d.logins.Add(1)
	if d.password != "fresh-device-secret" {
		return errors.New("invalid credential")
	}
	return nil
}

func (*persistentConnectionDevice) Read(context.Context) (device.Snapshot, error) {
	return device.Snapshot{Identity: device.Identity{Serial: "device-1234567890", Type: "edge-test"}}, nil
}

func (*persistentConnectionDevice) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
