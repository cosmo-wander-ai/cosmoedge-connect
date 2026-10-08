package profile

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

func TestStoreCreateReopenUpdateAndCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator-state", "device-profiles.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return clock }
	ref := testCredentialRef(t, []byte("profile-db-must-never-see-this-password"))
	created, err := store.Create(context.Background(), NewDeviceProfile{
		ProfileID: "dpf_00112233445566778899aabbccddeeff",
		TenantID:  "tenant-a", SiteID: "site-shanghai-01", Alias: "餐厅主设备", Endpoint: "192.168.8.20",
		Username: "operator", CredentialRef: ref, PinnedSerial: "SERIAL-PRIVATE-001", PinnedType: "edge-box",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Endpoint != "http://192.168.8.20:8000" || created.Generation != 1 || created.State != StateActive || created.CredentialState != CredentialReady {
		t.Fatalf("unexpected created profile: %#v", created)
	}
	if err := created.Validate(); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	updated, err := store.Update(context.Background(), updateFrom(created, func(input *UpdateDeviceProfile) {
		input.Alias = "餐厅边缘主机"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Generation != 2 || updated.Alias != "餐厅边缘主机" || !updated.UpdatedAt.Equal(clock) {
		t.Fatalf("unexpected update: %#v", updated)
	}
	if _, err := store.Update(context.Background(), updateFrom(created, nil)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation was accepted: %v", err)
	}
	events, err := store.Events(context.Background(), created.TenantID, created.SiteID, created.ProfileID)
	if err != nil || len(events) != 2 || events[0].EventType != "created" || events[1].EventType != "updated" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Get(context.Background(), created.TenantID, created.SiteID, created.ProfileID)
	if err != nil || loaded.Generation != updated.Generation || loaded.Alias != updated.Alias {
		t.Fatalf("reopened profile=%#v err=%v", loaded, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("profile-db-must-never-see-this-password")) {
		t.Fatal("password bytes entered the device profile database")
	}
}

func TestCredentialRotationIdentityDriftAndForget(t *testing.T) {
	store := openTestStore(t)
	secretStore := credential.NewMemoryStore()
	t.Cleanup(secretStore.Purge)
	putID, err := credential.NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	putReceipt, err := secretStore.Put(context.Background(), putID, []byte("old-private-password"))
	if err != nil {
		t.Fatal(err)
	}
	oldRef := putReceipt.Ref
	item, err := store.Create(context.Background(), NewDeviceProfile{
		ProfileID: "dpf_11112222333344445555666677778888",
		TenantID:  "tenant-a", SiteID: "site-a", Alias: "后厨设备", Endpoint: "10.20.30.40:9000", Username: "admin",
		CredentialRef: oldRef, PinnedSerial: "PINNED-SERIAL-A", PinnedType: "gateway-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := secretStore.AcknowledgePut(context.Background(), putID); err != nil {
		t.Fatal(err)
	}
	item, err = store.SetCredentialState(context.Background(), item.TenantID, item.SiteID, item.ProfileID, item.Generation, CredentialRotating)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := secretStore.Rotate(context.Background(), oldRef, []byte("new-private-password"))
	if err != nil {
		t.Fatal(err)
	}
	newRef := rotation.NewRef
	item, err = store.Update(context.Background(), updateFrom(item, func(input *UpdateDeviceProfile) {
		input.Endpoint = "https://10.20.30.41"
		input.CredentialRef = newRef
		input.TransportFingerprint = ""
		input.CredentialState = CredentialReady
	}))
	if err != nil {
		t.Fatal(err)
	}
	if item.Endpoint != "https://10.20.30.41:443" || item.CredentialRef != newRef || item.Generation != 3 {
		t.Fatalf("rotation was not bound to profile generation: %#v", item)
	}
	if err := secretStore.AcknowledgeRotation(context.Background(), rotation.OperationID); err != nil {
		t.Fatal(err)
	}
	item, err = store.MarkIdentityDrift(context.Background(), item.TenantID, item.SiteID, item.ProfileID, item.Generation)
	if err != nil || item.State != StateIdentityDrift {
		t.Fatalf("identity drift item=%#v err=%v", item, err)
	}
	item, err = store.Update(context.Background(), updateFrom(item, func(input *UpdateDeviceProfile) {
		input.PinnedSerial = "PINNED-SERIAL-B"
		input.PinnedType = "gateway-b"
		input.State = StateActive
	}))
	if err != nil {
		t.Fatalf("explicit identity repin failed: %v", err)
	}
	if err := store.Forget(context.Background(), item.TenantID, item.SiteID, item.ProfileID, item.Generation); !errors.Is(err, ErrCredentialNotRevoked) {
		t.Fatalf("profile forgot a live credential: %v", err)
	}
	item, err = store.SetCredentialState(context.Background(), item.TenantID, item.SiteID, item.ProfileID, item.Generation, CredentialRevoking)
	if err != nil || item.State != StateDisabled {
		t.Fatalf("revoking did not disable the profile: %#v err=%v", item, err)
	}
	if err := secretStore.Delete(context.Background(), item.CredentialRef); err != nil {
		t.Fatal(err)
	}
	item, err = store.SetCredentialState(context.Background(), item.TenantID, item.SiteID, item.ProfileID, item.Generation, CredentialRevoked)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Forget(context.Background(), item.TenantID, item.SiteID, item.ProfileID, item.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), item.TenantID, item.SiteID, item.ProfileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forgotten profile still exists: %v", err)
	}
	events, err := store.Events(context.Background(), item.TenantID, item.SiteID, item.ProfileID)
	if err != nil || len(events) < 7 || events[len(events)-1].State != StateForgotten || events[len(events)-1].EventType != "forgotten" {
		t.Fatalf("forget audit event missing: %#v err=%v", events, err)
	}
}

func TestStoreRejectsUnsafeProfilesAndAliasConflicts(t *testing.T) {
	store := openTestStore(t)
	ref := testCredentialRef(t, []byte("not-persisted"))
	base := NewDeviceProfile{
		ProfileID: "dpf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TenantID: "tenant-a", SiteID: "site-a", Alias: "主设备",
		Endpoint: "172.16.1.10", Username: "admin", CredentialRef: ref,
		PinnedSerial: "serial-a", PinnedType: "edge",
	}
	if _, err := store.Create(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	duplicate := base
	duplicate.ProfileID = "dpf_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	duplicate.Alias = "主设备"
	if _, err := store.Create(context.Background(), duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate site alias error=%v", err)
	}
	unsafe := base
	unsafe.ProfileID = "dpf_cccccccccccccccccccccccccccccccc"
	unsafe.Alias = "公网设备"
	unsafe.Endpoint = "8.8.8.8"
	if _, err := store.Create(context.Background(), unsafe); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("public endpoint error=%v", err)
	}
	unsafe = base
	unsafe.ProfileID = "dpf_dddddddddddddddddddddddddddddddd"
	unsafe.Alias = "错误凭证引用"
	unsafe.CredentialRef = credential.Ref("plaintext-password")
	if _, err := store.Create(context.Background(), unsafe); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("plaintext credential reference error=%v", err)
	}
	listed, err := store.ListSite(context.Background(), "tenant-a", "site-a")
	if err != nil || len(listed) != 1 || listed[0].ProfileID != base.ProfileID {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
}

func TestStoreScopesEveryLookupAndMutationByTenant(t *testing.T) {
	store := openTestStore(t)
	ref := testCredentialRef(t, []byte("tenant-scoped-secret"))
	created, err := store.Create(context.Background(), NewDeviceProfile{
		ProfileID: "dpf_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", TenantID: "tenant-a", SiteID: "site-a", Alias: "主设备",
		Endpoint: "10.10.10.20", Username: "admin", CredentialRef: ref,
		PinnedSerial: "serial-a", PinnedType: "edge",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "tenant-b", created.SiteID, created.ProfileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant lookup was not hidden: %v", err)
	}
	if listed, err := store.ListSite(context.Background(), "tenant-b", created.SiteID); err != nil || len(listed) != 0 {
		t.Fatalf("cross-tenant list leaked profiles: %#v, %v", listed, err)
	}
	if _, err := store.MarkIdentityDrift(context.Background(), "tenant-b", created.SiteID, created.ProfileID, created.Generation); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant mutation was not hidden: %v", err)
	}
	if events, err := store.Events(context.Background(), "tenant-b", created.SiteID, created.ProfileID); err != nil || len(events) != 0 {
		t.Fatalf("cross-tenant events leaked profile history: %#v, %v", events, err)
	}
	if _, err := store.Get(context.Background(), created.TenantID, "site-b", created.ProfileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-site lookup was not hidden: %v", err)
	}
	if _, err := store.MarkIdentityDrift(context.Background(), created.TenantID, "site-b", created.ProfileID, created.Generation); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-site mutation was not hidden: %v", err)
	}
	if events, err := store.Events(context.Background(), created.TenantID, "site-b", created.ProfileID); err != nil || len(events) != 0 {
		t.Fatalf("cross-site events leaked profile history: %#v, %v", events, err)
	}
	otherRef := testCredentialRef(t, []byte("other-tenant-secret"))
	other, err := store.Create(context.Background(), NewDeviceProfile{
		ProfileID: created.ProfileID, TenantID: "tenant-b", SiteID: "site-a", Alias: "其他租户设备",
		Endpoint: "10.10.10.21", Username: "admin", CredentialRef: otherRef,
		PinnedSerial: "serial-b", PinnedType: "edge",
	})
	if err != nil {
		t.Fatalf("composite tenant/profile identity rejected: %v", err)
	}
	if other.TenantID == created.TenantID || other.ProfileID != created.ProfileID {
		t.Fatalf("tenant-scoped duplicate profile id was not isolated: %v", other)
	}
	duplicateCapability := NewDeviceProfile{
		ProfileID: "dpf_ffffffffffffffffffffffffffffffff", TenantID: "tenant-c", SiteID: "site-a", Alias: "错误复用",
		Endpoint: "10.10.10.22", Username: "admin", CredentialRef: ref,
		PinnedSerial: "serial-c", PinnedType: "edge",
	}
	if _, err := store.Create(context.Background(), duplicateCapability); !errors.Is(err, ErrConflict) {
		t.Fatalf("credential capability could be rebound to another profile: %v", err)
	}
}

func TestStoreRejectsUnprotectedFileAndUnknownSchema(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operator-state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	unprotected := filepath.Join(root, "unprotected.db")
	if err := os.WriteFile(unprotected, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(unprotected); err == nil {
		t.Fatal("unprotected existing profile database was accepted")
	}
	unknown := filepath.Join(root, "unknown.db")
	database, err := sql.Open("sqlite", unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`PRAGMA user_version=99`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(unknown); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(unknown); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("unknown schema error=%v", err)
	}
	unrecognized := filepath.Join(root, "unrecognized.db")
	database, err = sql.Open("sqlite", unrecognized)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE unrelated_state(value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(unrecognized); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(unrecognized); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("unrecognized existing database error=%v", err)
	}
	impostor := filepath.Join(root, "impostor.db")
	database, err = sql.Open("sqlite", impostor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE device_profiles(fake TEXT); PRAGMA user_version=1; PRAGMA application_id=` + fmt.Sprint(schemaApplicationID)); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(impostor); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(impostor); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("schema impostor error=%v", err)
	}
}

func TestStoreRejectsDSNCharactersAndDoesNotHardenUnknownDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "unsafe-root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(root, "profile.db")); err == nil {
		t.Fatal("unprotected existing root was silently hardened")
	}
	if err := localstate.ValidateStateRoot(root); err == nil {
		t.Fatal("unknown root was unexpectedly hardened")
	}
	protectedRoot := filepath.Join(t.TempDir(), "operator-state")
	if err := localstate.PrepareStateRoot(protectedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(protectedRoot, "profile?.db")); err == nil {
		t.Fatal("DSN-like profile path was accepted")
	}
	if entries, err := os.ReadDir(protectedRoot); err != nil || len(entries) != 0 {
		t.Fatalf("rejected DSN path created state: %#v, %v", entries, err)
	}
}

func TestTransportFingerprintIsCanonical(t *testing.T) {
	normalized, err := NormalizeEndpoint("192.168.1.5")
	if err != nil || normalized != "http://192.168.1.5:8000" {
		t.Fatalf("normalized=%q err=%v", normalized, err)
	}
	first, err := ComputeTransportFingerprint("192.168.1.5", "operator")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ComputeTransportFingerprint("http://192.168.1.5:8000", "operator")
	if err != nil || first != second {
		t.Fatalf("fingerprints differ: %q %q err=%v", first, second, err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "operator-state", "device-profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testCredentialRef(t *testing.T, secret []byte) credential.Ref {
	t.Helper()
	store := credential.NewMemoryStore()
	t.Cleanup(store.Purge)
	operationID, err := credential.NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Put(context.Background(), operationID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgePut(context.Background(), operationID); err != nil {
		t.Fatal(err)
	}
	return receipt.Ref
}

func updateFrom(item DeviceProfile, mutate func(*UpdateDeviceProfile)) UpdateDeviceProfile {
	input := UpdateDeviceProfile{
		ProfileID: item.ProfileID, ExpectedGeneration: item.Generation,
		TenantID: item.TenantID, SiteID: item.SiteID, Alias: item.Alias, Endpoint: item.Endpoint, Username: item.Username,
		CredentialRef: item.CredentialRef, PinnedSerial: item.PinnedSerial, PinnedType: item.PinnedType,
		TransportFingerprint: item.TransportFingerprint, State: item.State, CredentialState: item.CredentialState,
	}
	if mutate != nil {
		mutate(&input)
	}
	return input
}
