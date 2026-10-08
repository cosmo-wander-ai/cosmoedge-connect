package devauthority

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/parity"
)

func TestAuthorizedReadUsesProductSafetyPath(t *testing.T) {
	const (
		username = "development-user"
		password = "development-password-private"
		serial   = "DEV-AUTHORITY-SERIAL-739184"
	)
	fixture := parity.NewDeviceFixture(username, password, serial)
	endpoint, stop, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	authority := testAuthority(t, device.NewV1Client)
	result, err := authority.Authorize(context.Background(), AuthorizationRequest{
		Endpoint: endpoint, Username: username, PasswordBase64: base64.StdEncoding.EncodeToString([]byte(password)),
		ValidForHours: 24, AllowTaskSwitchRoundTrip: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "authorized" || result.Device != "***9184" || len(result.AllowedActions) != 2 {
		t.Fatalf("authorization=%#v", result)
	}
	read, err := authority.VerifyRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if read.Status != "passed" || read.Device != "***9184" || read.TaskCount != 1 || read.CameraCount != 1 || read.Enabled != 1 || len(read.Tasks) != 1 || read.Tasks[0].Index != 1 || read.Tasks[0].Name == "" {
		t.Fatalf("read=%#v", read)
	}
	if _, err := authority.Authorize(context.Background(), AuthorizationRequest{
		Endpoint: endpoint, Username: username, PasswordBase64: base64.StdEncoding.EncodeToString([]byte(password)), ValidForHours: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.OpenTaskRoundTripSession(context.Background()); err == nil {
		t.Fatal("read-only authority opened a task write session")
	}
	if snapshot := fixture.Snapshot(); snapshot.TaskWrites != 0 {
		t.Fatalf("read-only authority wrote to fixture: %#v", snapshot)
	}
	profileRaw, err := os.ReadFile(authority.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range []string{password, username, serial, endpoint} {
		if contains(profileRaw, []byte(protected)) && protected != username && protected != endpoint {
			t.Fatalf("protected value persisted in clear text: %q", protected)
		}
	}
}

func TestExpiredAndRevokedAuthorityFailClosed(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	authority := testAuthority(t, device.NewV1Client)
	profile := Profile{
		Version: profileVersion, Endpoint: "http://10.42.0.20:8000", Username: "user",
		DeviceFingerprint: deviceFingerprint("serial"), DeviceHint: "***rial", DeviceType: "fixture",
		AllowedActions: []string{ActionRead}, EncryptedPassword: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}
	if err := authority.store.Save(profile); err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return now }
	if status := authority.Status(); status.Status != "invalid_or_expired" {
		t.Fatalf("status=%#v", status)
	}
	if _, err := authority.VerifyRead(context.Background()); err == nil {
		t.Fatal("expired authority was accepted")
	}
	if err := authority.Revoke(); err != nil {
		t.Fatal(err)
	}
	if status := authority.Status(); status.Status != "not_authorized" {
		t.Fatalf("status after revoke=%#v", status)
	}
}

func TestReadLeaseReusesOneLoginAndRejectsIdentityDrift(t *testing.T) {
	const username, password = "lease-user", "lease-password-private"
	fixture := parity.NewDeviceFixture(username, password, "LEASE-SERIAL-739184") // gitleaks:allow -- Synthetic credential for an isolated local test fixture.
	endpoint, stop, err := fixture.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	authority := testAuthority(t, device.NewV1Client)
	if _, err := authority.Authorize(context.Background(), AuthorizationRequest{
		Endpoint: endpoint, Username: username, PasswordBase64: base64.StdEncoding.EncodeToString([]byte(password)), ValidForHours: 1,
	}); err != nil {
		t.Fatal(err)
	}
	before := fixture.Snapshot().Logins
	lease, initial, info, err := authority.OpenReadLease(context.Background(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Identity.Serial == "" || info.Device != "***9184" || !info.ExpiresAt.After(info.OpenedAt) {
		t.Fatalf("initial=%#v info=%#v", initial, info)
	}
	for range 3 {
		if _, err := lease.Read(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := fixture.Snapshot().Logins; got != before+1 {
		t.Fatalf("read lease logins=%d, want %d", got, before+1)
	}
	fixture.SetFullSN("LEASE-DRIFT-0001")
	if _, err := lease.Read(context.Background()); err == nil {
		t.Fatal("read lease accepted identity drift")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Read(context.Background()); err == nil {
		t.Fatal("closed read lease remained usable")
	}
}

func testAuthority(t *testing.T, factory device.Factory) *Authority {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "private-state"))
	if err != nil {
		t.Fatal(err)
	}
	return &Authority{
		store: store, factory: factory, now: time.Now,
		protect: func(value []byte) ([]byte, error) {
			result := append([]byte("test-envelope:"), value...)
			for index := len("test-envelope:"); index < len(result); index++ {
				result[index] ^= 0x5a
			}
			return result, nil
		},
		unprotect: func(value []byte) ([]byte, error) {
			const prefix = "test-envelope:"
			if len(value) < len(prefix) || string(value[:len(prefix)]) != prefix {
				return nil, errors.New("invalid test envelope")
			}
			result := append([]byte(nil), value[len(prefix):]...)
			for index := range result {
				result[index] ^= 0x5a
			}
			return result, nil
		},
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for offset := 0; offset+len(needle) <= len(haystack); offset++ {
		match := true
		for index := range needle {
			if haystack[offset+index] != needle[index] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
