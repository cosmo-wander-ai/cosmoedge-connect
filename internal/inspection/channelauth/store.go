// Package channelauth owns the persistent mapping from a high-entropy local
// bearer credential digest to one exact inspection channel session. Raw
// bearer credentials exist only in an owner-readable local token file and are
// never stored in SQLite or returned through the HTTP API.
package channelauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

const (
	databaseVersion = 3
	applicationID   = 0x43484333 // CHC3
	timeLayout      = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	ErrInvalid  = errors.New("inspection channel binding is invalid")
	ErrConflict = errors.New("inspection channel binding conflicts with stored state")
	refPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestRegex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var allScopes = map[httpapi.Scope]struct{}{
	httpapi.ScopeCapabilitiesRead: {}, httpapi.ScopeRequestCreate: {}, httpapi.ScopeRunRead: {},
	httpapi.ScopeResultRead: {}, httpapi.ScopeMediaDeliver: {}, httpapi.ScopeFeedbackCreate: {},
}

const createBindingsSQL = `CREATE TABLE channel_bindings (
    credential_sha256 TEXT PRIMARY KEY CHECK(length(credential_sha256)=64),
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    conversation_ref TEXT NOT NULL,
    recipient_ref TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256)=64),
    scopes_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK(length(record_sha256)=64)
)`

const createActiveIndexSQL = `CREATE INDEX channel_bindings_active_idx ON channel_bindings(expires_at, revoked_at, credential_sha256)`

const createInsertOnlyTriggerSQL = `CREATE TRIGGER channel_bindings_insert_only
BEFORE UPDATE ON channel_bindings
WHEN NEW.credential_sha256<>OLD.credential_sha256 OR NEW.tenant_id<>OLD.tenant_id OR
     NEW.site_id<>OLD.site_id OR NEW.channel<>OLD.channel OR
     NEW.conversation_ref<>OLD.conversation_ref OR NEW.recipient_ref<>OLD.recipient_ref OR
     NEW.principal_sha256<>OLD.principal_sha256 OR
     NEW.scopes_json<>OLD.scopes_json OR NEW.created_at<>OLD.created_at OR NEW.expires_at<>OLD.expires_at OR
     OLD.revoked_at<>'' OR NEW.revoked_at='' OR NEW.record_sha256=OLD.record_sha256
BEGIN
    SELECT RAISE(ABORT, 'channel binding is immutable except for one revocation');
END`

const schema = createBindingsSQL + ";\n" + createActiveIndexSQL + ";\n" + createInsertOnlyTriggerSQL + ";"

type Config struct {
	Path string
	Now  func() time.Time
}

type Binding struct {
	CredentialSHA256 string
	Session          httpapi.SessionBinding
	Scopes           []httpapi.Scope
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        time.Time
	RecordSHA256     string
}

type ProvisionRequest struct {
	TokenPath string
	Session   httpapi.SessionBinding
	Scopes    []httpapi.Scope
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Store struct {
	db  *sql.DB
	now func() time.Time
}

func Open(config Config) (*Store, error) {
	if strings.TrimSpace(config.Path) == "" || strings.ContainsAny(config.Path, "\x00?#") {
		return nil, ErrInvalid
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	absolute, err := filepath.Abs(config.Path)
	if err != nil {
		return nil, err
	}
	if err := localstate.PrepareStateRoot(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(absolute); errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		if closeErr := file.Close(); closeErr != nil {
			_ = os.Remove(absolute)
			return nil, closeErr
		}
		created = true
		if err := localstate.ProtectFile(absolute); err != nil {
			_ = os.Remove(absolute)
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		if created {
			_ = os.Remove(absolute)
		}
		return nil, err
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	store := &Store{db: database, now: config.Now}
	if err := store.initialize(); err != nil {
		_ = database.Close()
		if created {
			_ = os.Remove(absolute)
		}
		return nil, err
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		_ = database.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Bind(ctx context.Context, value Binding) (Binding, bool, error) {
	value, scopesJSON, err := normalizeBinding(value)
	if s == nil || err != nil || !value.RevokedAt.IsZero() {
		return Binding{}, false, ErrInvalid
	}
	value.RecordSHA256 = bindingDigest(value, scopesJSON)
	result, err := s.db.ExecContext(ctx, `INSERT INTO channel_bindings(
credential_sha256, tenant_id, site_id, channel, conversation_ref, recipient_ref, principal_sha256,
scopes_json, created_at, expires_at, revoked_at, record_sha256)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?) ON CONFLICT(credential_sha256) DO NOTHING`,
		value.CredentialSHA256, value.Session.TenantID, value.Session.SiteID, value.Session.Channel,
		value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256, scopesJSON,
		formatTime(value.CreatedAt), formatTime(value.ExpiresAt), value.RecordSHA256)
	if err != nil {
		return Binding{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Binding{}, false, err
	}
	stored, err := s.get(ctx, value.CredentialSHA256)
	if err != nil {
		return Binding{}, false, err
	}
	if !sameBinding(stored, value) {
		return Binding{}, false, ErrConflict
	}
	return stored, rows == 1, nil
}

// Provision creates an owner-readable token file and binds only its SHA-256
// digest. It never returns or persists the raw token anywhere else.
func (s *Store) Provision(ctx context.Context, request ProvisionRequest) (Binding, error) {
	if s == nil || strings.TrimSpace(request.TokenPath) == "" || strings.ContainsRune(request.TokenPath, '\x00') {
		return Binding{}, ErrInvalid
	}
	absolute, err := filepath.Abs(request.TokenPath)
	if err != nil || absolute == string(os.PathSeparator) {
		return Binding{}, ErrInvalid
	}
	if err := localstate.PrepareStateRoot(filepath.Dir(absolute)); err != nil {
		return Binding{}, err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return Binding{}, err
	}
	token := make([]byte, hex.EncodedLen(len(random)))
	hex.Encode(token, random)
	clear(random)
	defer clear(token)
	digest := sha256.Sum256(token)
	binding := Binding{
		CredentialSHA256: hex.EncodeToString(digest[:]), Session: request.Session,
		Scopes:    append([]httpapi.Scope(nil), request.Scopes...),
		CreatedAt: request.CreatedAt, ExpiresAt: request.ExpiresAt,
	}
	if _, _, err := normalizeBinding(binding); err != nil {
		return Binding{}, ErrInvalid
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Binding{}, ErrConflict
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(absolute)
		}
	}()
	if err := localstate.ProtectFile(absolute); err != nil {
		return Binding{}, err
	}
	if _, err := file.Write(token); err != nil {
		return Binding{}, err
	}
	if _, err := file.Write([]byte{'\n'}); err != nil {
		return Binding{}, err
	}
	if err := file.Sync(); err != nil {
		return Binding{}, err
	}
	if err := file.Close(); err != nil {
		return Binding{}, err
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		return Binding{}, err
	}
	stored, _, err := s.Bind(ctx, binding)
	if err != nil {
		return Binding{}, err
	}
	committed = true
	return stored, nil
}

func (s *Store) Revoke(ctx context.Context, credentialSHA256 string, at time.Time) error {
	if s == nil || !digestRegex.MatchString(credentialSHA256) || at.IsZero() {
		return ErrInvalid
	}
	current, err := s.get(ctx, credentialSHA256)
	if err != nil {
		return httpapi.ErrUnauthenticated
	}
	if !current.RevokedAt.IsZero() {
		return nil
	}
	at = at.UTC()
	if at.Before(current.CreatedAt) {
		return ErrInvalid
	}
	current.RevokedAt = at
	scopesJSON, _ := json.Marshal(current.Scopes)
	current.RecordSHA256 = bindingDigest(current, scopesJSON)
	result, err := s.db.ExecContext(ctx, `UPDATE channel_bindings SET revoked_at=?, record_sha256=?
WHERE credential_sha256=? AND revoked_at=''`, formatTime(at), current.RecordSHA256, credentialSHA256)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) Authorize(ctx context.Context, request httpapi.AuthorizationRequest) (httpapi.Authorization, error) {
	if s == nil || !validScope(request.Scope) || !digestRegex.MatchString(request.CredentialSHA256) {
		return httpapi.Authorization{}, httpapi.ErrUnauthenticated
	}
	binding, err := s.get(ctx, request.CredentialSHA256)
	if err != nil || !binding.RevokedAt.IsZero() || !s.now().UTC().Before(binding.ExpiresAt) {
		return httpapi.Authorization{}, httpapi.ErrUnauthenticated
	}
	index := sort.Search(len(binding.Scopes), func(index int) bool { return binding.Scopes[index] >= request.Scope })
	if index >= len(binding.Scopes) || binding.Scopes[index] != request.Scope {
		return httpapi.Authorization{}, httpapi.ErrForbidden
	}
	return httpapi.Authorization{Session: binding.Session, Scope: request.Scope}, nil
}

func (s *Store) initialize() error {
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF",
		"PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON",
	} {
		if _, err := s.db.Exec(pragma); err != nil {
			return err
		}
	}
	var version, appID int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if err := s.db.QueryRow(`PRAGMA application_id`).Scan(&appID); err != nil {
		return err
	}
	if version == 0 && appID == 0 {
		var userObjects int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&userObjects); err != nil {
			return err
		}
		if userObjects != 0 {
			return errors.New("unsupported inspection channel binding schema; explicitly reset this development store")
		}
		if _, err := s.db.Exec(schema); err != nil {
			return err
		}
		if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA application_id=%d; PRAGMA user_version=%d;`, applicationID, databaseVersion)); err != nil {
			return err
		}
	} else if version != databaseVersion || appID != applicationID {
		return errors.New("unsupported inspection channel binding schema; explicitly reset this development store")
	}
	if err := validateShape(s.db); err != nil {
		return err
	}
	rows, err := s.db.Query(`SELECT credential_sha256 FROM channel_bindings ORDER BY credential_sha256`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var digests []string
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return err
		}
		digests = append(digests, digest)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, digest := range digests {
		if _, err := s.get(context.Background(), digest); err != nil {
			return fmt.Errorf("validate stored inspection channel binding: %w", err)
		}
	}
	return nil
}

func (s *Store) get(ctx context.Context, digest string) (Binding, error) {
	var value Binding
	var scopesJSON []byte
	var createdAt, expiresAt, revokedAt string
	err := s.db.QueryRowContext(ctx, `SELECT credential_sha256, tenant_id, site_id, channel,
conversation_ref, recipient_ref, principal_sha256, scopes_json, created_at, expires_at, revoked_at, record_sha256
FROM channel_bindings WHERE credential_sha256=?`, digest).Scan(
		&value.CredentialSHA256, &value.Session.TenantID, &value.Session.SiteID, &value.Session.Channel,
		&value.Session.ConversationRef, &value.Session.RecipientRef, &value.Session.PrincipalSHA256, &scopesJSON,
		&createdAt, &expiresAt, &revokedAt, &value.RecordSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, httpapi.ErrUnauthenticated
	}
	if err != nil {
		return Binding{}, err
	}
	if value.CreatedAt, err = parseTime(createdAt); err != nil {
		return Binding{}, ErrInvalid
	}
	if value.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return Binding{}, ErrInvalid
	}
	if revokedAt != "" {
		if value.RevokedAt, err = parseTime(revokedAt); err != nil {
			return Binding{}, ErrInvalid
		}
	}
	if err := json.Unmarshal(scopesJSON, &value.Scopes); err != nil {
		return Binding{}, ErrInvalid
	}
	normalized, canonicalScopes, err := normalizeBinding(value)
	if err != nil || string(canonicalScopes) != string(scopesJSON) || normalized.RecordSHA256 != value.RecordSHA256 ||
		bindingDigest(normalized, canonicalScopes) != value.RecordSHA256 {
		return Binding{}, ErrInvalid
	}
	return normalized, nil
}

func normalizeBinding(value Binding) (Binding, []byte, error) {
	value.CreatedAt, value.ExpiresAt, value.RevokedAt = value.CreatedAt.UTC(), value.ExpiresAt.UTC(), value.RevokedAt.UTC()
	if !digestRegex.MatchString(value.CredentialSHA256) || !validSession(value.Session) || value.CreatedAt.IsZero() ||
		!value.ExpiresAt.After(value.CreatedAt) || value.ExpiresAt.Sub(value.CreatedAt) > 366*24*time.Hour ||
		!value.RevokedAt.IsZero() && value.RevokedAt.Before(value.CreatedAt) || len(value.Scopes) == 0 || len(value.Scopes) > len(allScopes) {
		return Binding{}, nil, ErrInvalid
	}
	value.Scopes = append([]httpapi.Scope(nil), value.Scopes...)
	sort.Slice(value.Scopes, func(i, j int) bool { return value.Scopes[i] < value.Scopes[j] })
	for index, scope := range value.Scopes {
		if !validScope(scope) || index > 0 && value.Scopes[index-1] == scope {
			return Binding{}, nil, ErrInvalid
		}
	}
	scopesJSON, err := json.Marshal(value.Scopes)
	if err != nil {
		return Binding{}, nil, err
	}
	return value, scopesJSON, nil
}

func bindingDigest(value Binding, scopesJSON []byte) string {
	canonical := struct {
		CredentialSHA256 string          `json:"credentialSha256"`
		TenantID         string          `json:"tenantId"`
		SiteID           string          `json:"siteId"`
		Channel          string          `json:"channel"`
		ConversationRef  string          `json:"conversationRef"`
		RecipientRef     string          `json:"recipientRef"`
		PrincipalSHA256  string          `json:"principalSha256"`
		Scopes           json.RawMessage `json:"scopes"`
		CreatedAt        time.Time       `json:"createdAt"`
		ExpiresAt        time.Time       `json:"expiresAt"`
		RevokedAt        time.Time       `json:"revokedAt,omitempty"`
	}{
		value.CredentialSHA256, value.Session.TenantID, value.Session.SiteID, value.Session.Channel,
		value.Session.ConversationRef, value.Session.RecipientRef, value.Session.PrincipalSHA256,
		scopesJSON, value.CreatedAt, value.ExpiresAt, value.RevokedAt,
	}
	raw, _ := json.Marshal(canonical)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func sameBinding(left, right Binding) bool {
	if left.CredentialSHA256 != right.CredentialSHA256 || left.Session != right.Session ||
		!left.CreatedAt.Equal(right.CreatedAt) || !left.ExpiresAt.Equal(right.ExpiresAt) ||
		!left.RevokedAt.Equal(right.RevokedAt) || left.RecordSHA256 != right.RecordSHA256 || len(left.Scopes) != len(right.Scopes) {
		return false
	}
	for index := range left.Scopes {
		if left.Scopes[index] != right.Scopes[index] {
			return false
		}
	}
	return true
}

func validSession(value httpapi.SessionBinding) bool {
	for _, field := range []string{value.TenantID, value.SiteID, value.Channel, value.ConversationRef, value.RecipientRef} {
		if strings.TrimSpace(field) != field || !refPattern.MatchString(field) {
			return false
		}
	}
	return digestRegex.MatchString(value.PrincipalSHA256)
}

func validScope(scope httpapi.Scope) bool {
	_, ok := allScopes[scope]
	return ok
}

func formatTime(value time.Time) string { return value.UTC().Format(timeLayout) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timeLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed.UTC(), nil
}

func validateShape(db *sql.DB) error {
	expected := map[string]string{
		"channel_bindings":             createBindingsSQL,
		"channel_bindings_active_idx":  createActiveIndexSQL,
		"channel_bindings_insert_only": createInsertOnlyTriggerSQL,
	}
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	actual := make(map[string]string, len(expected))
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			return err
		}
		actual[name] = statement
	}
	if err := rows.Err(); err != nil || len(actual) != len(expected) {
		return errors.New("inspection channel binding state shape is invalid")
	}
	for name, statement := range expected {
		if normalizeSQL(actual[name]) != normalizeSQL(statement) {
			return fmt.Errorf("inspection channel binding state shape is invalid: %s", name)
		}
	}
	return nil
}

func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}
