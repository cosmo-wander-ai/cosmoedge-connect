//go:build windows

package devwrite

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/parity"
)

func TestTaskRoundTripUsesActionKernelAndRestoresFixture(t *testing.T) {
	const (
		username = "development-write-user"
		password = "development-write-password-private"
		serial   = "DEV-WRITE-SERIAL-739184"
	)
	fixture := parity.NewDeviceFixture(username, password, serial)
	endpoint, stop, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	store, err := devauthority.NewStore(filepath.Join(t.TempDir(), "authority"))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := devauthority.New(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Authorize(context.Background(), devauthority.AuthorizationRequest{
		Endpoint: endpoint, Username: username, PasswordBase64: base64.StdEncoding.EncodeToString([]byte(password)),
		ValidForHours: 1, AllowTaskSwitchRoundTrip: true,
	}); err != nil {
		t.Fatal(err)
	}
	validator, err := New(authority)
	if err != nil {
		t.Fatal(err)
	}
	result, err := validator.VerifyTaskRoundTrip(context.Background(), 1)
	if err != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if result.Status != "passed" || !result.Restored || result.RecoveryRequired || result.DeviceWrites != 2 || result.Dispatches != 2 || !result.EvidenceSealed {
		t.Fatalf("result=%#v", result)
	}
	if snapshot := fixture.Snapshot(); snapshot.TaskEnabled != 1 || snapshot.TaskWrites != 2 {
		t.Fatalf("fixture=%#v", snapshot)
	}
}
