package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

func TestStorePersistsCanonicalSourceAndBuildsFrozenBinding(t *testing.T) {
	path := filepath.Join(protectedCatalogTestRoot(t), "source-catalog.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	created, err := store.Create(context.Background(), fixtureSource("source-east"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.Capabilities[0].Ref != "cap-clip" || created.Capabilities[1].Ref != "cap-snapshot" ||
		created.Capabilities[0].Constraints.MediaKinds[0] != MediaFrameSet || len(created.Capabilities[0].Digest) != 64 {
		t.Fatalf("source was not canonicalized: %#v", created)
	}
	binding, err := store.Binding(context.Background(), "tenant-a", "site-a", created.Handle,
		[]string{"cap-snapshot", "cap-clip", "cap-snapshot"}, "roi-dining-east")
	if err != nil {
		t.Fatal(err)
	}
	if binding.Kind != inspection.SourceCamera || binding.SourceHandle != created.Handle || binding.SourceRevision != 1 ||
		len(binding.CapabilityRefs) != 2 || binding.CapabilityRefs[0] != "cap-clip" || binding.SourceFingerprint != created.IdentityFingerprint {
		t.Fatalf("binding=%#v", binding)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Get(context.Background(), "tenant-a", "site-a", created.Handle)
	if err != nil || loaded.NativeLocator != "native-camera-id-private-east" || loaded.Revision != created.Revision {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}

	if _, err := json.Marshal(loaded); !errors.Is(err, ErrProtectedProjection) {
		t.Fatalf("protected source serialized: %v", err)
	}
	summary, err := loaded.Summary()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"native-camera-id", "deviceProfile", "endpoint", "credential", "fingerprint", "tenant-a", "site-a"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("business summary leaked %q: %s", forbidden, raw)
		}
	}
}

func TestStoreScopesAllReadsAndCASByTenantAndSite(t *testing.T) {
	store := openTestStore(t)
	created, err := store.Create(context.Background(), fixtureSource("source-east"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range [][2]string{{"tenant-b", "site-a"}, {"tenant-a", "site-b"}} {
		if _, err := store.Get(context.Background(), scope[0], scope[1], created.Handle); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-scope get (%v) error=%v", scope, err)
		}
		if values, err := store.ListSite(context.Background(), scope[0], scope[1]); err != nil || len(values) != 0 {
			t.Fatalf("cross-scope list (%v)=%#v err=%v", scope, values, err)
		}
	}
	wrong := updateFrom(created)
	wrong.TenantID = "tenant-b"
	if _, err := store.Update(context.Background(), wrong); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant update error=%v", err)
	}
	wrong = updateFrom(created)
	wrong.SiteID = "site-b"
	if _, err := store.Update(context.Background(), wrong); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-site update error=%v", err)
	}

	updated, err := store.Update(context.Background(), updateFrom(created))
	if err != nil || updated.Revision != created.Revision+1 {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	if _, err := store.Update(context.Background(), updateFrom(created)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision was accepted: %v", err)
	}
}

func TestIdentityDriftBlocksBindingUntilExplicitRepin(t *testing.T) {
	store := openTestStore(t)
	created, err := store.Create(context.Background(), fixtureSource("source-east"))
	if err != nil {
		t.Fatal(err)
	}
	drift := updateFrom(created)
	drift.IdentityFingerprint = strings.Repeat("b", 64)
	drift.NativeLocator = "untrusted-new-native-id"
	drift.Capabilities = nil
	drifted, err := store.Update(context.Background(), drift)
	if !errors.Is(err, ErrIdentityDrift) || drifted.State != StateIdentityDrift ||
		drifted.NativeLocator != created.NativeLocator || drifted.IdentityFingerprint != created.IdentityFingerprint {
		t.Fatalf("drifted=%#v err=%v", drifted, err)
	}
	if _, err := store.Binding(context.Background(), created.TenantID, created.SiteID, created.Handle, []string{"cap-snapshot"}, ""); !errors.Is(err, ErrIdentityDrift) {
		t.Fatalf("drifted source produced a binding: %v", err)
	}
	repin := updateFrom(drifted)
	repin.IdentityFingerprint = strings.Repeat("b", 64)
	repin.NativeLocator = "new-native-id-after-local-confirmation"
	repin.Capabilities = fixtureCapabilities()
	repinned, err := store.Repin(context.Background(), repin)
	if err != nil || repinned.State != StateActive || repinned.IdentityFingerprint != strings.Repeat("b", 64) {
		t.Fatalf("repinned=%#v err=%v", repinned, err)
	}
	if _, err := store.Binding(context.Background(), repinned.TenantID, repinned.SiteID, repinned.Handle, []string{"cap-snapshot"}, ""); err != nil {
		t.Fatalf("repinned source did not bind: %v", err)
	}
}

func TestCapabilitiesAreBoundedCanonicalAndRequired(t *testing.T) {
	base := fixtureSource("source-east")
	duplicate := base
	duplicate.Capabilities = append(duplicate.Capabilities, duplicate.Capabilities[0])
	if _, err := NormalizeCapabilities(duplicate.Capabilities); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("duplicate capability error=%v", err)
	}
	badMedia := cloneCapabilities(base.Capabilities)
	badMedia[0].Constraints.MediaKinds = []MediaKind{"shell_output"}
	if _, err := NormalizeCapabilities(badMedia); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("invalid media capability error=%v", err)
	}
	store := openTestStore(t)
	created, err := store.Create(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.Binding([]string{"cap-unknown"}, ""); !errors.Is(err, ErrCapabilityMissing) {
		t.Fatalf("unknown capability produced a binding: %v", err)
	}
	disabled := updateFrom(created)
	disabled.State = StateDisabled
	disabledSource, err := store.Update(context.Background(), disabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabledSource.Binding([]string{"cap-snapshot"}, ""); !errors.Is(err, ErrCapabilityMissing) {
		t.Fatalf("disabled source produced a binding: %v", err)
	}
}

func TestCatalogFingerprintIsDeterministicAndChangesOnCASRefresh(t *testing.T) {
	store := openTestStore(t)
	firstInput := fixtureSource("source-west")
	firstInput.Alias = "西侧"
	secondInput := fixtureSource("source-east")
	secondInput.Alias = "东侧"
	first, err := store.Create(context.Background(), firstInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(context.Background(), secondInput); err != nil {
		t.Fatal(err)
	}
	before, err := store.Fingerprint(context.Background(), "tenant-a", "site-a")
	if err != nil || len(before) != 64 {
		t.Fatalf("fingerprint=%q err=%v", before, err)
	}
	// A refresh increments the frozen revision even when only the business
	// alias changes, so an assignment cannot silently reuse stale catalog state.
	update := updateFrom(first)
	update.Alias = "西侧主机位"
	if _, err := store.Update(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	after, err := store.Fingerprint(context.Background(), "tenant-a", "site-a")
	if err != nil || before == after {
		t.Fatalf("catalog fingerprint did not change: %q %q err=%v", before, after, err)
	}
}

func TestConcurrentCASAllowsOneRefresh(t *testing.T) {
	store := openTestStore(t)
	created, err := store.Create(context.Background(), fixtureSource("source-east"))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			update := updateFrom(created)
			update.Alias = []string{"东侧 A", "东侧 B"}[index]
			_, err := store.Update(context.Background(), update)
			errorsSeen <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	var success, conflict int
	for err := range errorsSeen {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflict++
		} else {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}

func TestStoreRejectsUnprotectedUnknownAndUnrelatedDatabases(t *testing.T) {
	root := protectedCatalogTestRoot(t)
	unprotected := filepath.Join(root, "unprotected.db")
	if err := os.WriteFile(unprotected, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(unprotected); err == nil {
		t.Fatal("unprotected database was accepted")
	}

	for name, initialize := range map[string]func(*sql.DB) error{
		"unknown-version": func(db *sql.DB) error { _, err := db.Exec(`PRAGMA user_version=99`); return err },
		"unrelated-table": func(db *sql.DB) error { _, err := db.Exec(`CREATE TABLE unrelated(value TEXT)`); return err },
		"wrong-app-id": func(db *sql.DB) error {
			_, err := db.Exec(`PRAGMA user_version=2; PRAGMA application_id=1234`)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".db")
			database, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if err := initialize(database); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			if err := localstate.ProtectFile(path); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); !errors.Is(err, ErrUnsupportedSchema) {
				t.Fatalf("unsupported database error=%v", err)
			}
		})
	}
}

func fixtureSource(handle string) NewSource {
	fingerprint := sha256.Sum256([]byte(handle))
	return NewSource{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "dpf_00112233445566778899aabbccddeeff",
		Handle: handle, Kind: inspection.SourceCamera, IdentityFingerprint: fmt.Sprintf("%x", fingerprint[:]),
		NativeLocator: "native-camera-id-private-" + strings.TrimPrefix(handle, "source-"),
		Alias:         "东侧就餐区", ZoneID: "zone-dining-east", Capabilities: fixtureCapabilities(),
	}
}

func fixtureCapabilities() []Capability {
	return []Capability{
		{
			Ref: "cap-snapshot", Kind: CapabilitySnapshot, Revision: 2,
			Constraints: Constraints{MediaKinds: []MediaKind{MediaImage}, MaxBytes: 4 << 20, MaxFrames: 1, MaxFreshnessSeconds: 30},
		},
		{
			Ref: "cap-clip", Kind: CapabilityClip, Revision: 1,
			Constraints: Constraints{MediaKinds: []MediaKind{MediaVideoClip, MediaFrameSet}, MaxBytes: 32 << 20, MaxFrames: 16, MaxDurationSeconds: 30, MaxFreshnessSeconds: 60},
		},
	}
}

func updateFrom(source Source) UpdateSource {
	return UpdateSource{
		TenantID: source.TenantID, SiteID: source.SiteID, Handle: source.Handle, ExpectedRevision: source.Revision,
		DeviceProfileID: source.DeviceProfileID, IdentityFingerprint: source.IdentityFingerprint,
		NativeLocator: source.NativeLocator, Alias: source.Alias, ZoneID: source.ZoneID,
		State: source.State, Capabilities: cloneCapabilities(source.Capabilities),
	}
}

func cloneCapabilities(values []Capability) []Capability {
	result := append([]Capability(nil), values...)
	for index := range result {
		result[index].Constraints.MediaKinds = append([]MediaKind(nil), result[index].Constraints.MediaKinds...)
	}
	return result
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(protectedCatalogTestRoot(t), "source-catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func protectedCatalogTestRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "protected-state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return root
}
