package channelauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	_ "modernc.org/sqlite"
)

var channelTestTime = time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)

func TestBindingIsPersistentIdempotentAndScopeBound(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateDir(t), "channel.db")
	now := channelTestTime
	store, err := Open(Config{Path: path, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	value := fixtureBinding(strings.Repeat("a", 64), []httpapi.Scope{
		httpapi.ScopeRequestCreate, httpapi.ScopeCapabilitiesRead,
	})
	stored, created, err := store.Bind(ctx, value)
	if err != nil || !created || stored.Scopes[0] != httpapi.ScopeCapabilitiesRead {
		t.Fatalf("Bind()=(%+v,%v,%v)", stored, created, err)
	}
	replayed, created, err := store.Bind(ctx, value)
	if err != nil || created || !sameBinding(replayed, stored) {
		t.Fatalf("replayed Bind()=(%+v,%v,%v)", replayed, created, err)
	}
	changed := value
	changed.Session.RecipientRef = "recipient-b"
	if _, _, err := store.Bind(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Bind() error=%v", err)
	}
	changed = value
	changed.Session.PrincipalSHA256 = strings.Repeat("2", 64)
	if _, _, err := store.Bind(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("principal rebound Bind() error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(Config{Path: path, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authorization, err := store.Authorize(ctx, httpapi.AuthorizationRequest{
		Scope: httpapi.ScopeRequestCreate, CredentialSHA256: value.CredentialSHA256,
	})
	if err != nil || authorization.Session != value.Session || authorization.Scope != httpapi.ScopeRequestCreate {
		t.Fatalf("Authorize()=(%+v,%v)", authorization, err)
	}
	if _, err := store.Authorize(ctx, httpapi.AuthorizationRequest{
		Scope: httpapi.ScopeResultRead, CredentialSHA256: value.CredentialSHA256,
	}); !errors.Is(err, httpapi.ErrForbidden) {
		t.Fatalf("ungranted scope error=%v", err)
	}
	if _, err := store.Authorize(ctx, httpapi.AuthorizationRequest{
		Scope: httpapi.ScopeRequestCreate, CredentialSHA256: strings.Repeat("b", 64),
	}); !errors.Is(err, httpapi.ErrUnauthenticated) {
		t.Fatalf("unknown credential error=%v", err)
	}
}

func TestBindingRevocationAndExpiryFailClosed(t *testing.T) {
	ctx := context.Background()
	now := channelTestTime
	store, err := Open(Config{Path: filepath.Join(privateDir(t), "channel.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := fixtureBinding(strings.Repeat("a", 64), []httpapi.Scope{httpapi.ScopeCapabilitiesRead})
	if _, _, err := store.Bind(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, first.CredentialSHA256, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, first.CredentialSHA256, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if _, err := store.Authorize(ctx, httpapi.AuthorizationRequest{
		Scope: httpapi.ScopeCapabilitiesRead, CredentialSHA256: first.CredentialSHA256,
	}); !errors.Is(err, httpapi.ErrUnauthenticated) {
		t.Fatalf("revoked credential error=%v", err)
	}
	second := fixtureBinding(strings.Repeat("b", 64), []httpapi.Scope{httpapi.ScopeCapabilitiesRead})
	second.ExpiresAt = now.Add(2 * time.Minute)
	if _, _, err := store.Bind(ctx, second); err != nil {
		t.Fatal(err)
	}
	now = second.ExpiresAt
	if _, err := store.Authorize(ctx, httpapi.AuthorizationRequest{
		Scope: httpapi.ScopeCapabilitiesRead, CredentialSHA256: second.CredentialSHA256,
	}); !errors.Is(err, httpapi.ErrUnauthenticated) {
		t.Fatalf("expired credential error=%v", err)
	}
}

func TestProvisionWritesOwnerOnlyTokenAndStoresOnlyItsDigest(t *testing.T) {
	ctx := context.Background()
	root := privateDir(t)
	databasePath := filepath.Join(root, "channel.db")
	store, err := Open(Config{Path: databasePath, Now: func() time.Time { return channelTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tokenPath := filepath.Join(root, "binding", "access.token")
	binding, err := store.Provision(ctx, ProvisionRequest{
		TokenPath: tokenPath, Session: fixtureSession(), Scopes: []httpapi.Scope{
			httpapi.ScopeCapabilitiesRead, httpapi.ScopeRequestCreate, httpapi.ScopeRunRead,
			httpapi.ScopeResultRead, httpapi.ScopeMediaDeliver, httpapi.ScopeFeedbackCreate,
		},
		CreatedAt: channelTestTime, ExpiresAt: channelTestTime.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := localstate.ValidateFile(tokenPath); err != nil {
		t.Fatalf("token permissions: %v", err)
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.TrimSpace(raw)
	if len(token) != 64 {
		t.Fatalf("token length=%d", len(token))
	}
	digest := sha256.Sum256(token)
	if binding.CredentialSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("stored binding does not match token digest")
	}
	databaseRaw, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(databaseRaw, token) {
		t.Fatal("raw bearer token was persisted in channel database")
	}
	if _, err := store.Authorize(ctx, httpapi.AuthorizationRequest{
		Scope: httpapi.ScopeMediaDeliver, CredentialSHA256: binding.CredentialSHA256,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Provision(ctx, ProvisionRequest{
		TokenPath: tokenPath, Session: fixtureSession(), Scopes: []httpapi.Scope{httpapi.ScopeCapabilitiesRead},
		CreatedAt: channelTestTime, ExpiresAt: channelTestTime.Add(time.Hour),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing token path error=%v", err)
	}
}

func TestOpenRejectsTamperedOrUnknownStateWithoutAdoptingIt(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(privateDir(t), "channel.db")
	store, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Bind(ctx, fixtureBinding(strings.Repeat("a", 64), []httpapi.Scope{httpapi.ScopeCapabilitiesRead})); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DROP TRIGGER channel_bindings_insert_only`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE channel_bindings SET recipient_ref='tampered'`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Path: path}); err == nil {
		t.Fatal("tampered channel state reopened")
	}

	unknownPath := filepath.Join(privateDir(t), "unknown.db")
	db, err := sql.Open("sqlite", unknownPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE foreign_state(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(unknownPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Path: unknownPath}); err == nil {
		t.Fatal("unknown version-zero state was adopted")
	}
	db, err = sql.Open("sqlite", unknownPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='channel_bindings'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed open mutated unknown state count=%d err=%v", count, err)
	}
}

func TestOpenRejectsCurrentVersionSchemaMissingPrincipal(t *testing.T) {
	path := filepath.Join(privateDir(t), "missing-principal.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacyTable := strings.Replace(createBindingsSQL,
		"    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256)=64),\n", "", 1)
	legacyTrigger := strings.Replace(createInsertOnlyTriggerSQL,
		"\n     NEW.principal_sha256<>OLD.principal_sha256 OR", "", 1)
	for _, statement := range []string{
		legacyTable, createActiveIndexSQL, legacyTrigger,
		fmt.Sprintf("PRAGMA application_id=%d", applicationID),
		fmt.Sprintf("PRAGMA user_version=%d", databaseVersion),
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Path: path}); err == nil {
		t.Fatal("current-version channel state without principal was adopted")
	}
}

func fixtureBinding(digest string, scopes []httpapi.Scope) Binding {
	return Binding{
		CredentialSHA256: digest, Session: fixtureSession(), Scopes: scopes,
		CreatedAt: channelTestTime, ExpiresAt: channelTestTime.Add(time.Hour),
	}
}

func fixtureSession() httpapi.SessionBinding {
	return httpapi.SessionBinding{
		TenantID: "tenant-a", SiteID: "site-a", Channel: "workbuddy-wechat",
		ConversationRef: "conversation-a", RecipientRef: "recipient-a",
		PrincipalSHA256: strings.Repeat("1", 64),
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	return root
}
