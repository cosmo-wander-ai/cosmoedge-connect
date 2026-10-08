package deliverybinding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	_ "modernc.org/sqlite"
)

var bindingTestTime = time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)

func TestStoreResolvesOnlyExactActiveRevisionAndRejectsSubstitution(t *testing.T) {
	store := openTestStore(t)
	binding := testBinding()
	stored, created, err := store.Register(context.Background(), binding)
	if err != nil || !created || stored.RecordSHA256 == "" {
		t.Fatalf("Register() created=%v value=%+v err=%v", created, stored, err)
	}
	request := ResolveRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, BindingRef: binding.BindingRef, Revision: binding.Revision,
		AudienceSHA256: stored.AudienceSHA256, PrincipalSHA256: stored.PrincipalSHA256, At: bindingTestTime.Add(time.Hour),
	}
	resolved, err := store.Resolve(context.Background(), request)
	if err != nil || resolved.RecordSHA256 != stored.RecordSHA256 || resolved.Audience != binding.Audience {
		t.Fatalf("Resolve()=%+v err=%v", resolved, err)
	}
	for name, mutate := range map[string]func(*ResolveRequest){
		"tenant":    func(v *ResolveRequest) { v.TenantID = "tenant-other" },
		"site":      func(v *ResolveRequest) { v.SiteID = "site-other" },
		"revision":  func(v *ResolveRequest) { v.Revision++ },
		"audience":  func(v *ResolveRequest) { v.AudienceSHA256 = strings.Repeat("a", 64) },
		"principal": func(v *ResolveRequest) { v.PrincipalSHA256 = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if _, err := store.Resolve(context.Background(), changed); err == nil {
				t.Fatal("substituted binding resolved")
			}
		})
	}
}

func TestStoreDuplicateIsIdempotentButCannotRewriteRevision(t *testing.T) {
	store := openTestStore(t)
	binding := testBinding()
	first, created, err := store.Register(context.Background(), binding)
	if err != nil || !created {
		t.Fatal(err)
	}
	second, created, err := store.Register(context.Background(), binding)
	if err != nil || created || second.RecordSHA256 != first.RecordSHA256 {
		t.Fatalf("exact duplicate created=%v err=%v", created, err)
	}
	binding.Audience.RecipientRef = "recipient-other"
	if _, _, err := store.Register(context.Background(), binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("revision rewrite err=%v", err)
	}
}

func TestStoreRevocationIsOneWayAndSurvivesRestart(t *testing.T) {
	path := protectedTestPath(t, "bindings.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	stored, _, err := store.Register(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	revoked, changed, err := store.Revoke(context.Background(), binding.TenantID, binding.SiteID, binding.BindingRef, binding.Revision, bindingTestTime.Add(2*time.Hour))
	if err != nil || !changed || revoked.RevokedAt.IsZero() || revoked.RecordSHA256 == stored.RecordSHA256 {
		t.Fatalf("Revoke() changed=%v value=%+v err=%v", changed, revoked, err)
	}
	if _, changed, err := store.Revoke(context.Background(), binding.TenantID, binding.SiteID, binding.BindingRef, binding.Revision, bindingTestTime.Add(3*time.Hour)); err != nil || changed {
		t.Fatalf("repeat Revoke() changed=%v err=%v", changed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if _, err := reopened.Resolve(context.Background(), ResolveRequest{
		TenantID: binding.TenantID, SiteID: binding.SiteID, BindingRef: binding.BindingRef, Revision: binding.Revision,
		AudienceSHA256: stored.AudienceSHA256, PrincipalSHA256: stored.PrincipalSHA256, At: bindingTestTime.Add(4 * time.Hour),
	}); !errors.Is(err, ErrInactive) {
		t.Fatalf("revoked binding resolve err=%v", err)
	}
}

func TestStoreRejectsExpiredAndFutureBindings(t *testing.T) {
	store := openTestStore(t)
	stored, _, err := store.Register(context.Background(), testBinding())
	if err != nil {
		t.Fatal(err)
	}
	request := ResolveRequest{TenantID: stored.TenantID, SiteID: stored.SiteID, BindingRef: stored.BindingRef, Revision: stored.Revision,
		AudienceSHA256: stored.AudienceSHA256, PrincipalSHA256: stored.PrincipalSHA256}
	for _, at := range []time.Time{bindingTestTime.Add(-time.Nanosecond), bindingTestTime.Add(24 * time.Hour)} {
		request.At = at
		if _, err := store.Resolve(context.Background(), request); !errors.Is(err, ErrInactive) {
			t.Fatalf("Resolve(%v) err=%v", at, err)
		}
	}
	timeTravel := testBinding()
	timeTravel.BindingRef = "binding-time-travel"
	timeTravel.CreatedAt = timeTravel.ValidFrom.Add(time.Second)
	if _, _, err := store.Register(context.Background(), timeTravel); !errors.Is(err, ErrConflict) {
		t.Fatalf("Register(time travel) err=%v", err)
	}
}

func TestStoreRejectsOldSchemaAndShapeTampering(t *testing.T) {
	path := protectedTestPath(t, "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE old_bindings(id TEXT); PRAGMA application_id=1128612912; PRAGMA user_version=0`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("old schema err=%v", err)
	}

	path = protectedTestPath(t, "tampered.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Register(context.Background(), testBinding()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DROP TRIGGER delivery_recipient_binding_update_guard`); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if _, err := Open(path); !errors.Is(err, ErrSchema) {
		t.Fatalf("tampered shape err=%v", err)
	}
}

func TestBindingRejectsPublicProjection(t *testing.T) {
	if raw, err := json.Marshal(testBinding()); !errors.Is(err, ErrProtectedProjection) || raw != nil {
		t.Fatalf("json.Marshal(binding)=%q err=%v", raw, err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(protectedTestPath(t, "bindings.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func protectedTestPath(t *testing.T, name string) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := localstate.PrepareStateRoot(directory); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, name)
}

func testBinding() Binding {
	return Binding{
		TenantID: "tenant-main", SiteID: "site-main", BindingRef: "binding-main", Revision: 1,
		Audience: delivery.Audience{TenantID: "tenant-main", SiteID: "site-main", Channel: "wechat",
			ConversationRef: "conversation-main", RecipientRef: "recipient-main"},
		PrincipalSHA256: strings.Repeat("c", 64), ValidFrom: bindingTestTime,
		ValidUntil: bindingTestTime.Add(24 * time.Hour), CreatedAt: bindingTestTime,
	}
}
