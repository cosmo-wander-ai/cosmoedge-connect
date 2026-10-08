package inspectionlive

import (
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionowner"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestCompatibilityServiceAndConnectionOwnerExcludeEachOther(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "access.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	vault := session.New(nil)
	state := filepath.Join(root, "state")
	owner, err := connectionowner.New(connectionowner.Config{StateRoot: state, TokenFile: token, Vault: vault})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Stop()
	legacy, err := New(Config{
		StateRoot: state, TokenFile: token, Address: availableInspectionAddress(t), Sessions: vault,
		Snapshots: snapshotReaderStub{err: session.ErrNotConnected}, Connections: connectionProviderStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Stop()
	if _, err := owner.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Start(context.Background()); !errors.Is(err, connectionowner.ErrAlreadyOwned) {
		t.Fatalf("compatibility overlapped new owner: %v", err)
	}
	if err := owner.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, connectionowner.ErrAlreadyOwned) {
		t.Fatalf("new owner overlapped compatibility: %v", err)
	}
	if err := legacy.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Start(context.Background()); err != nil {
		t.Fatalf("new owner after compatibility shutdown: %v", err)
	}
}
