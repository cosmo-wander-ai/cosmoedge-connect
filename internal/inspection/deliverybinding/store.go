// Package deliverybinding persists immutable, pseudonymous delivery audience
// revisions. It contains no transport credential, native channel identifier or
// device locator.
package deliverybinding

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

const (
	SchemaVersion = "cosmoedge.inspection.delivery-recipient-binding.v1"
	storeVersion  = 1
	storeID       = 0x43454431 // CED1
	timeLayout    = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	ErrNotFound            = errors.New("inspection delivery binding was not found")
	ErrConflict            = errors.New("inspection delivery binding conflicts with stored state")
	ErrInactive            = errors.New("inspection delivery binding is inactive")
	ErrSchema              = errors.New("unsupported inspection delivery binding schema")
	ErrCorrupt             = errors.New("inspection delivery binding integrity failure")
	ErrProtectedProjection = errors.New("inspection delivery binding cannot be projected")
	refPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestRegex            = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Binding struct {
	Schema          string
	TenantID        string
	SiteID          string
	BindingRef      string
	Revision        uint64
	Audience        delivery.Audience
	AudienceSHA256  string
	PrincipalSHA256 string
	ValidFrom       time.Time
	ValidUntil      time.Time
	CreatedAt       time.Time
	RevokedAt       time.Time
	RecordSHA256    string
}

func (Binding) String() string               { return "[inspection-delivery-binding]" }
func (Binding) GoString() string             { return "deliverybinding.Binding([redacted])" }
func (Binding) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (Binding) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
func (Binding) LogValue() slog.Value         { return slog.StringValue("[inspection-delivery-binding]") }

type ResolveRequest struct {
	TenantID        string
	SiteID          string
	BindingRef      string
	Revision        uint64
	AudienceSHA256  string
	PrincipalSHA256 string
	At              time.Time
}

type Store struct {
	db   *sql.DB
	path string
}

const createBindingsSQL = `CREATE TABLE delivery_recipient_bindings (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    binding_ref TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    audience_sha256 TEXT NOT NULL CHECK(length(audience_sha256) = 64),
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256) = 64),
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT '',
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64),
    PRIMARY KEY(tenant_id, site_id, binding_ref, revision)
)`

const createActiveIndexSQL = `CREATE INDEX idx_delivery_recipient_binding_active
    ON delivery_recipient_bindings(tenant_id, site_id, binding_ref, revision, valid_from, valid_until, revoked_at)`

const createUpdateGuardSQL = `CREATE TRIGGER delivery_recipient_binding_update_guard
BEFORE UPDATE ON delivery_recipient_bindings
WHEN OLD.tenant_id <> NEW.tenant_id
  OR OLD.site_id <> NEW.site_id
  OR OLD.binding_ref <> NEW.binding_ref
  OR OLD.revision <> NEW.revision
  OR OLD.channel <> NEW.channel
  OR OLD.conversation_ref <> NEW.conversation_ref
  OR OLD.recipient_ref <> NEW.recipient_ref
  OR OLD.audience_sha256 <> NEW.audience_sha256
  OR OLD.principal_sha256 <> NEW.principal_sha256
  OR OLD.valid_from <> NEW.valid_from
  OR OLD.valid_until <> NEW.valid_until
  OR OLD.created_at <> NEW.created_at
  OR OLD.revoked_at <> ''
  OR NEW.revoked_at = ''
BEGIN
    SELECT RAISE(ABORT, 'invalid delivery binding transition');
END`

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "?#\x00") {
		return nil, ErrSchema
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := localstate.PrepareStateRoot(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	exists := true
	if _, err := os.Lstat(absolute); errors.Is(err, os.ErrNotExist) {
		exists = false
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, closeErr
		}
		if err := localstate.ProtectFile(absolute); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if err := localstate.ValidateFile(absolute); err != nil {
		return nil, fmt.Errorf("reject existing inspection delivery binding state: %w", err)
	}
	db, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(openErr error) (*Store, error) { _ = db.Close(); return nil, openErr }
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON"} {
		if _, err := db.Exec(pragma); err != nil {
			return fail(err)
		}
	}
	if !exists {
		tx, err := db.Begin()
		if err != nil {
			return fail(err)
		}
		for _, statement := range []string{createBindingsSQL, createActiveIndexSQL, createUpdateGuardSQL,
			fmt.Sprintf("PRAGMA application_id=%d", storeID), fmt.Sprintf("PRAGMA user_version=%d", storeVersion)} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fail(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	}
	store := &Store{db: db, path: absolute}
	if err := store.validateState(context.Background()); err != nil {
		return fail(err)
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Register(ctx context.Context, value Binding) (Binding, bool, error) {
	if s == nil || s.db == nil {
		return Binding{}, false, ErrConflict
	}
	value.Schema = SchemaVersion
	value.ValidFrom, value.ValidUntil, value.CreatedAt = value.ValidFrom.UTC(), value.ValidUntil.UTC(), value.CreatedAt.UTC()
	value.RevokedAt = time.Time{}
	digest, err := value.Audience.SHA256()
	if err != nil {
		return Binding{}, false, ErrConflict
	}
	value.AudienceSHA256 = digest
	value.RecordSHA256 = recordDigest(value)
	if validateBinding(value) != nil {
		return Binding{}, false, ErrConflict
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO delivery_recipient_bindings(
tenant_id,site_id,binding_ref,revision,channel,conversation_ref,recipient_ref,audience_sha256,principal_sha256,
valid_from,valid_until,created_at,revoked_at,record_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(tenant_id,site_id,binding_ref,revision) DO NOTHING`, value.TenantID, value.SiteID, value.BindingRef, value.Revision,
		value.Audience.Channel, value.Audience.ConversationRef, value.Audience.RecipientRef, value.AudienceSHA256, value.PrincipalSHA256,
		formatTime(value.ValidFrom), formatTime(value.ValidUntil), formatTime(value.CreatedAt), "", value.RecordSHA256)
	if err != nil {
		return Binding{}, false, constraint(err)
	}
	rows, _ := result.RowsAffected()
	stored, err := s.Get(ctx, value.TenantID, value.SiteID, value.BindingRef, value.Revision)
	if err != nil {
		return Binding{}, false, err
	}
	if stored.RecordSHA256 != value.RecordSHA256 {
		return Binding{}, false, ErrConflict
	}
	return stored, rows == 1, nil
}

func (s *Store) Get(ctx context.Context, tenantID, siteID, bindingRef string, revision uint64) (Binding, error) {
	if s == nil || s.db == nil || !validRef(tenantID) || !validRef(siteID) || !validRef(bindingRef) || revision == 0 {
		return Binding{}, ErrNotFound
	}
	return scanBinding(s.db.QueryRowContext(ctx, `SELECT tenant_id,site_id,binding_ref,revision,channel,conversation_ref,recipient_ref,
audience_sha256,principal_sha256,valid_from,valid_until,created_at,revoked_at,record_sha256
FROM delivery_recipient_bindings WHERE tenant_id=? AND site_id=? AND binding_ref=? AND revision=?`, tenantID, siteID, bindingRef, revision))
}

func (s *Store) Resolve(ctx context.Context, request ResolveRequest) (Binding, error) {
	if !validRef(request.TenantID) || !validRef(request.SiteID) || !validRef(request.BindingRef) || request.Revision == 0 ||
		!validDigest(request.AudienceSHA256) || !validDigest(request.PrincipalSHA256) || request.At.IsZero() {
		return Binding{}, ErrNotFound
	}
	value, err := s.Get(ctx, request.TenantID, request.SiteID, request.BindingRef, request.Revision)
	if err != nil {
		return Binding{}, err
	}
	if value.AudienceSHA256 != request.AudienceSHA256 || value.PrincipalSHA256 != request.PrincipalSHA256 {
		return Binding{}, ErrConflict
	}
	at := request.At.UTC()
	if at.Before(value.CreatedAt) || at.Before(value.ValidFrom) || !at.Before(value.ValidUntil) || !value.RevokedAt.IsZero() {
		return Binding{}, ErrInactive
	}
	return value, nil
}

func (s *Store) Revoke(ctx context.Context, tenantID, siteID, bindingRef string, revision uint64, at time.Time) (Binding, bool, error) {
	value, err := s.Get(ctx, tenantID, siteID, bindingRef, revision)
	if err != nil {
		return Binding{}, false, err
	}
	if at.IsZero() {
		return Binding{}, false, ErrConflict
	}
	if !value.RevokedAt.IsZero() {
		return value, false, nil
	}
	if at.UTC().Before(value.CreatedAt) {
		return Binding{}, false, ErrConflict
	}
	oldDigest := value.RecordSHA256
	value.RevokedAt = at.UTC()
	value.RecordSHA256 = recordDigest(value)
	result, err := s.db.ExecContext(ctx, `UPDATE delivery_recipient_bindings SET revoked_at=?,record_sha256=?
WHERE tenant_id=? AND site_id=? AND binding_ref=? AND revision=? AND revoked_at='' AND record_sha256=?`,
		formatTime(value.RevokedAt), value.RecordSHA256, tenantID, siteID, bindingRef, revision, oldDigest)
	if err != nil {
		return Binding{}, false, constraint(err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return Binding{}, false, ErrConflict
	}
	return value, true, nil
}

type rowScanner interface{ Scan(...any) error }

func scanBinding(row rowScanner) (Binding, error) {
	var value Binding
	var validFrom, validUntil, createdAt, revokedAt string
	err := row.Scan(&value.TenantID, &value.SiteID, &value.BindingRef, &value.Revision,
		&value.Audience.Channel, &value.Audience.ConversationRef, &value.Audience.RecipientRef,
		&value.AudienceSHA256, &value.PrincipalSHA256, &validFrom, &validUntil, &createdAt, &revokedAt, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, ErrNotFound
	}
	if err != nil {
		return Binding{}, err
	}
	value.Schema = SchemaVersion
	value.Audience.TenantID, value.Audience.SiteID = value.TenantID, value.SiteID
	if value.ValidFrom, err = parseTime(validFrom); err == nil {
		value.ValidUntil, err = parseTime(validUntil)
	}
	if err == nil {
		value.CreatedAt, err = parseTime(createdAt)
	}
	if err == nil && revokedAt != "" {
		value.RevokedAt, err = parseTime(revokedAt)
	}
	if err != nil || validateBinding(value) != nil || value.RecordSHA256 != recordDigest(value) {
		return Binding{}, ErrCorrupt
	}
	return value, nil
}

func validateBinding(value Binding) error {
	audienceSHA, err := value.Audience.SHA256()
	if value.Schema != SchemaVersion || !validRef(value.TenantID) || !validRef(value.SiteID) || !validRef(value.BindingRef) || value.Revision == 0 ||
		value.Audience.TenantID != value.TenantID || value.Audience.SiteID != value.SiteID || err != nil || audienceSHA != value.AudienceSHA256 ||
		!validDigest(value.PrincipalSHA256) || value.ValidFrom.IsZero() || !value.ValidUntil.After(value.ValidFrom) || value.CreatedAt.IsZero() ||
		value.ValidFrom.Before(value.CreatedAt) ||
		!value.ValidUntil.After(value.CreatedAt) || (!value.RevokedAt.IsZero() && value.RevokedAt.Before(value.CreatedAt)) || !validDigest(value.RecordSHA256) {
		return ErrCorrupt
	}
	return nil
}

func recordDigest(value Binding) string {
	payload := struct {
		Schema, TenantID, SiteID, BindingRef, AudienceSHA256, PrincipalSHA256, ValidFrom, ValidUntil, CreatedAt, RevokedAt string
		Revision                                                                                                           uint64
		Audience                                                                                                           delivery.Audience
	}{value.Schema, value.TenantID, value.SiteID, value.BindingRef, value.AudienceSHA256, value.PrincipalSHA256,
		formatTime(value.ValidFrom), formatTime(value.ValidUntil), formatTime(value.CreatedAt), optionalTime(value.RevokedAt), value.Revision, value.Audience}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Store) validateState(ctx context.Context) error {
	var version, applicationID int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != storeVersion {
		return ErrSchema
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != storeID {
		return ErrSchema
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrCorrupt
	}
	expected := map[string]string{"delivery_recipient_bindings": createBindingsSQL, "idx_delivery_recipient_binding_active": createActiveIndexSQL, "delivery_recipient_binding_update_guard": createUpdateGuardSQL}
	rows, err := s.db.QueryContext(ctx, `SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	actual := map[string]string{}
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			return err
		}
		actual[name] = statement
	}
	if err := rows.Err(); err != nil || len(actual) != len(expected) {
		return ErrSchema
	}
	for name, statement := range expected {
		if normalizeSQL(actual[name]) != normalizeSQL(statement) {
			return ErrSchema
		}
	}
	content, err := s.db.QueryContext(ctx, `SELECT tenant_id,site_id,binding_ref,revision,channel,conversation_ref,recipient_ref,
audience_sha256,principal_sha256,valid_from,valid_until,created_at,revoked_at,record_sha256 FROM delivery_recipient_bindings`)
	if err != nil {
		return err
	}
	defer content.Close()
	for content.Next() {
		if _, err := scanBinding(content); err != nil {
			return err
		}
	}
	return content.Err()
}

func validRef(value string) bool {
	return strings.TrimSpace(value) == value && refPattern.MatchString(value)
}
func validDigest(value string) bool     { return digestRegex.MatchString(value) }
func formatTime(value time.Time) string { return value.UTC().Format(timeLayout) }
func optionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatTime(value)
}
func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timeLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, ErrCorrupt
	}
	return parsed.UTC(), nil
}
func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}
func constraint(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "constraint") || strings.Contains(lower, "invalid delivery binding transition") {
		return errors.Join(ErrConflict, err)
	}
	return err
}
