package onboarding

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

const (
	handoffDatabaseVersion       = 2
	handoffDatabaseApplicationID = 0x4345484f // "CEHO"
	handoffOperationDomain       = "cosmoedge.onboarding.handoff.operation.v2\x00"
	handoffRecordDomain          = "cosmoedge.onboarding.handoff.record.v2\x00"
	// MaximumHandoffRecoveryBatch bounds one local reconciliation page. Recovery
	// callers advance the exclusive keyset cursor, then start a fresh sweep.
	MaximumHandoffRecoveryBatch = 100
)

const createHandoffsSQL = `CREATE TABLE onboarding_handoffs (
    handoff_ref TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending', 'completed')),
    record_sha256 TEXT NOT NULL
) WITHOUT ROWID`

var (
	ErrInvalidHandoff          = errors.New("onboarding handoff is invalid")
	ErrHandoffNotFound         = errors.New("onboarding handoff was not found")
	ErrHandoffExpired          = errors.New("onboarding handoff has expired")
	ErrHandoffConflict         = errors.New("onboarding handoff conflicts with existing state")
	ErrHandoffIntegrity        = errors.New("onboarding handoff integrity check failed")
	ErrUnsupportedHandoffStore = errors.New("onboarding handoff store schema is unsupported")
	ErrHandoffCommit           = errors.New("onboarding completed but handoff was not marked complete")
	handoffRefPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	handoffScopePattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	handoffDigestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type HandoffState string

const (
	HandoffPending   HandoffState = "pending"
	HandoffCompleted HandoffState = "completed"
)

// HandoffBinding contains only the authenticated channel scope. It never
// carries connection coordinates, credentials, or device-native identity.
type HandoffBinding struct {
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
}

func (HandoffBinding) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (HandoffBinding) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (HandoffBinding) String() string               { return "[onboarding-handoff-binding]" }
func (HandoffBinding) GoString() string             { return "onboarding.HandoffBinding([redacted])" }
func (HandoffBinding) LogValue() slog.Value {
	return slog.StringValue("[onboarding-handoff-binding]")
}

// HandoffRecord is the complete protected persistence shape. Its deliberately
// small field set is the boundary between a Skill request and local setup.
type HandoffRecord struct {
	HandoffRef      string
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
	OperationID     string
	ExpiresAt       time.Time
	State           HandoffState
	RecordSHA256    string
}

func (HandoffRecord) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (HandoffRecord) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (HandoffRecord) String() string               { return "[onboarding-handoff]" }
func (HandoffRecord) GoString() string             { return "onboarding.HandoffRecord([redacted])" }
func (HandoffRecord) LogValue() slog.Value {
	return slog.StringValue("[onboarding-handoff]")
}

// ProtectedHandoffLookup is the integrity-checked local application lookup.
// It intentionally returns the protected record even after business expiry so
// a handoff-bound browser can perform exact idempotent reconciliation without
// accepting tenant, site, or principal fields from an HTTP request.
type ProtectedHandoffLookup struct {
	Record  HandoffRecord
	Expired bool
}

func (ProtectedHandoffLookup) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (ProtectedHandoffLookup) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (ProtectedHandoffLookup) String() string { return "[onboarding-protected-handoff-lookup]" }
func (ProtectedHandoffLookup) GoString() string {
	return "onboarding.ProtectedHandoffLookup([redacted])"
}
func (ProtectedHandoffLookup) LogValue() slog.Value {
	return slog.StringValue("[onboarding-protected-handoff-lookup]")
}

func (r HandoffRecord) validate() error {
	if !handoffRefPattern.MatchString(r.HandoffRef) || !handoffScopePattern.MatchString(r.TenantID) ||
		!handoffScopePattern.MatchString(r.SiteID) || !principalDigestRegexp.MatchString(r.PrincipalSHA256) ||
		!operationIDPattern.MatchString(r.OperationID) || r.OperationID != stableHandoffOperationID(
		HandoffBinding{TenantID: r.TenantID, SiteID: r.SiteID, PrincipalSHA256: r.PrincipalSHA256}, r.HandoffRef,
	) || r.ExpiresAt.IsZero() || r.ExpiresAt != r.ExpiresAt.UTC() ||
		(r.State != HandoffPending && r.State != HandoffCompleted) || !handoffDigestPattern.MatchString(r.RecordSHA256) {
		return ErrInvalidHandoff
	}
	return nil
}

type HandoffRepository interface {
	Begin(context.Context, HandoffRecord) (HandoffRecord, error)
	Resolve(context.Context, HandoffBinding, string) (HandoffRecord, error)
	PendingForRecovery(context.Context, string, int) ([]HandoffRecord, error)
	MarkCompleted(context.Context, HandoffRecord) (HandoffRecord, error)
}

type HandoffStoreConfig struct {
	Path string
	Now  func() time.Time
}

// HandoffStore owns an exact-schema protected SQLite file. Existing unknown,
// older, or altered schemas are rejected; this store has no migration path.
type HandoffStore struct {
	db  *sql.DB
	now func() time.Time
}

func OpenHandoffStore(config HandoffStoreConfig) (*HandoffStore, error) {
	if strings.TrimSpace(config.Path) == "" || strings.ContainsAny(config.Path, "?#\x00") {
		return nil, ErrInvalidHandoff
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	absolute, err := filepath.Abs(config.Path)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(absolute, "?#\x00") {
		return nil, ErrInvalidHandoff
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing onboarding handoff state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
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
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	fail := func(openErr error) (*HandoffStore, error) {
		_ = database.Close()
		return nil, openErr
	}
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF",
		"PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON",
	} {
		if _, err := database.Exec(pragma); err != nil {
			return fail(err)
		}
	}
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fail(err)
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return fail(err)
	}
	if version == 0 {
		var objects int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&objects); err != nil {
			return fail(err)
		}
		if applicationID != 0 || objects != 0 {
			return fail(ErrUnsupportedHandoffStore)
		}
		tx, err := database.Begin()
		if err != nil {
			return fail(err)
		}
		for _, statement := range []string{
			createHandoffsSQL,
			fmt.Sprintf("PRAGMA application_id=%d", handoffDatabaseApplicationID),
			fmt.Sprintf("PRAGMA user_version=%d", handoffDatabaseVersion),
		} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fail(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != handoffDatabaseVersion || applicationID != handoffDatabaseApplicationID {
		return fail(ErrUnsupportedHandoffStore)
	}
	if err := verifyHandoffStore(database); err != nil {
		return fail(err)
	}
	store := &HandoffStore{db: database, now: config.Now}
	if err := store.validateContent(context.Background()); err != nil {
		return fail(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return fail(err)
	}
	return store, nil
}

func (s *HandoffStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *HandoffStore) Begin(ctx context.Context, record HandoffRecord) (HandoffRecord, error) {
	if s == nil || s.db == nil {
		return HandoffRecord{}, ErrInvalidHandoff
	}
	record = canonicalHandoff(record)
	if record.State != HandoffPending {
		return HandoffRecord{}, ErrInvalidHandoff
	}
	record.RecordSHA256 = handoffRecordDigest(record)
	if err := record.validate(); err != nil {
		return HandoffRecord{}, err
	}
	if !record.ExpiresAt.After(s.now().UTC()) {
		return HandoffRecord{}, ErrHandoffExpired
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO onboarding_handoffs(
handoff_ref, tenant_id, site_id, principal_sha256, operation_id, expires_at, state, record_sha256
) VALUES(?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, handoffValues(record)...)
	if err != nil {
		return HandoffRecord{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 1 {
		return record, nil
	}
	existing, err := s.load(ctx, record.HandoffRef)
	if err != nil {
		return HandoffRecord{}, errors.Join(ErrHandoffConflict, err)
	}
	if !sameHandoffIntent(existing, record) {
		return HandoffRecord{}, ErrHandoffConflict
	}
	if !existing.ExpiresAt.After(s.now().UTC()) {
		return HandoffRecord{}, ErrHandoffExpired
	}
	return existing, nil
}

func (s *HandoffStore) Resolve(ctx context.Context, binding HandoffBinding, ref string) (HandoffRecord, error) {
	if s == nil || s.db == nil {
		return HandoffRecord{}, ErrInvalidHandoff
	}
	binding = canonicalHandoffBinding(binding)
	ref = strings.TrimSpace(ref)
	if !validHandoffBinding(binding) || !handoffRefPattern.MatchString(ref) {
		return HandoffRecord{}, ErrInvalidHandoff
	}
	record, err := s.load(ctx, ref)
	if err != nil {
		return HandoffRecord{}, err
	}
	if record.TenantID != binding.TenantID || record.SiteID != binding.SiteID || record.PrincipalSHA256 != binding.PrincipalSHA256 {
		return HandoffRecord{}, ErrBindingMismatch
	}
	if !s.now().UTC().Before(record.ExpiresAt) {
		return HandoffRecord{}, ErrHandoffExpired
	}
	return record, nil
}

// ResolveProtected performs an integrity-checked lookup by the opaque handoff
// already sealed into an authenticated local browser session. Callers must not
// expose this method as a request-field lookup; its result is non-projectable.
func (s *HandoffStore) ResolveProtected(ctx context.Context, ref string) (ProtectedHandoffLookup, error) {
	if s == nil || s.db == nil || ref != strings.TrimSpace(ref) || !handoffRefPattern.MatchString(ref) {
		return ProtectedHandoffLookup{}, ErrInvalidHandoff
	}
	record, err := s.load(ctx, ref)
	if err != nil {
		return ProtectedHandoffLookup{}, err
	}
	return ProtectedHandoffLookup{Record: record, Expired: !s.now().UTC().Before(record.ExpiresAt)}, nil
}

// PendingForRecovery is a protected local maintenance read. Unlike Resolve it
// deliberately includes expired pending records so a crash after the core
// commit cannot strand the handoff forever. afterRef is an exclusive keyset
// cursor, preventing an unfinished first page from starving later records.
// HandoffRecord blocks business, JSON, text, and log projection of the returned
// scope and operation identity.
func (s *HandoffStore) PendingForRecovery(ctx context.Context, afterRef string, limit int) ([]HandoffRecord, error) {
	afterRef = strings.TrimSpace(afterRef)
	if s == nil || s.db == nil || (afterRef != "" && !handoffRefPattern.MatchString(afterRef)) ||
		limit <= 0 || limit > MaximumHandoffRecoveryBatch {
		return nil, ErrInvalidHandoff
	}
	rows, err := s.db.QueryContext(ctx, `SELECT handoff_ref, tenant_id, site_id, principal_sha256,
operation_id, expires_at, state, record_sha256 FROM onboarding_handoffs
WHERE state=? AND handoff_ref>? ORDER BY handoff_ref ASC LIMIT ?`, HandoffPending, afterRef, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]HandoffRecord, 0, limit)
	for rows.Next() {
		record, err := scanHandoff(rows)
		if err != nil {
			return nil, err
		}
		if record.State != HandoffPending {
			return nil, ErrHandoffIntegrity
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *HandoffStore) MarkCompleted(ctx context.Context, expected HandoffRecord) (HandoffRecord, error) {
	if s == nil || s.db == nil {
		return HandoffRecord{}, ErrInvalidHandoff
	}
	if err := expected.validate(); err != nil {
		return HandoffRecord{}, err
	}
	current, err := s.load(ctx, expected.HandoffRef)
	if err != nil {
		return HandoffRecord{}, err
	}
	if !sameHandoffIntent(current, expected) {
		return HandoffRecord{}, ErrHandoffConflict
	}
	if current.State == HandoffCompleted {
		return current, nil
	}
	if current.RecordSHA256 != expected.RecordSHA256 || expected.State != HandoffPending {
		return HandoffRecord{}, ErrHandoffConflict
	}
	completed := current
	completed.State = HandoffCompleted
	completed.RecordSHA256 = handoffRecordDigest(completed)
	result, err := s.db.ExecContext(ctx, `UPDATE onboarding_handoffs SET state=?, record_sha256=?
WHERE handoff_ref=? AND state=? AND record_sha256=?`, completed.State, completed.RecordSHA256,
		current.HandoffRef, HandoffPending, current.RecordSHA256)
	if err != nil {
		return HandoffRecord{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 1 {
		return completed, nil
	}
	latest, err := s.load(ctx, current.HandoffRef)
	if err == nil && sameHandoffIntent(latest, current) && latest.State == HandoffCompleted {
		return latest, nil
	}
	return HandoffRecord{}, errors.Join(ErrHandoffConflict, err)
}

func (s *HandoffStore) load(ctx context.Context, ref string) (HandoffRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT handoff_ref, tenant_id, site_id, principal_sha256,
operation_id, expires_at, state, record_sha256 FROM onboarding_handoffs WHERE handoff_ref=?`, ref)
	record, err := scanHandoff(row)
	if errors.Is(err, sql.ErrNoRows) {
		return HandoffRecord{}, ErrHandoffNotFound
	}
	return record, err
}

func (s *HandoffStore) validateContent(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT handoff_ref, tenant_id, site_id, principal_sha256,
operation_id, expires_at, state, record_sha256 FROM onboarding_handoffs ORDER BY handoff_ref`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if _, err := scanHandoff(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

type handoffScanner interface {
	Scan(...any) error
}

func scanHandoff(scanner handoffScanner) (HandoffRecord, error) {
	var record HandoffRecord
	var expiresAt string
	if err := scanner.Scan(&record.HandoffRef, &record.TenantID, &record.SiteID, &record.PrincipalSHA256,
		&record.OperationID, &expiresAt, &record.State, &record.RecordSHA256); err != nil {
		return HandoffRecord{}, errors.Join(ErrHandoffIntegrity, err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != expiresAt {
		return HandoffRecord{}, ErrHandoffIntegrity
	}
	record.ExpiresAt = parsed.UTC()
	if err := record.validate(); err != nil {
		return HandoffRecord{}, errors.Join(ErrHandoffIntegrity, err)
	}
	want := handoffRecordDigest(record)
	if subtle.ConstantTimeCompare([]byte(record.RecordSHA256), []byte(want)) != 1 {
		return HandoffRecord{}, ErrHandoffIntegrity
	}
	return record, nil
}

func verifyHandoffStore(database *sql.DB) error {
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != handoffDatabaseVersion {
		return ErrUnsupportedHandoffStore
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != handoffDatabaseApplicationID {
		return ErrUnsupportedHandoffStore
	}
	var integrity string
	if err := database.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrHandoffIntegrity
	}
	rows, err := database.Query(`SELECT name, sql FROM sqlite_master
WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name`)
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
	if err := rows.Err(); err != nil || len(actual) != 1 || normalizeHandoffSQL(actual["onboarding_handoffs"]) != normalizeHandoffSQL(createHandoffsSQL) {
		return ErrUnsupportedHandoffStore
	}
	return nil
}

func canonicalHandoff(record HandoffRecord) HandoffRecord {
	record.HandoffRef = strings.TrimSpace(record.HandoffRef)
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.SiteID = strings.TrimSpace(record.SiteID)
	record.PrincipalSHA256 = strings.TrimSpace(record.PrincipalSHA256)
	record.OperationID = strings.TrimSpace(record.OperationID)
	record.ExpiresAt = record.ExpiresAt.UTC()
	return record
}

func canonicalHandoffBinding(binding HandoffBinding) HandoffBinding {
	binding.TenantID = strings.TrimSpace(binding.TenantID)
	binding.SiteID = strings.TrimSpace(binding.SiteID)
	binding.PrincipalSHA256 = strings.TrimSpace(binding.PrincipalSHA256)
	return binding
}

func validHandoffBinding(binding HandoffBinding) bool {
	return handoffScopePattern.MatchString(binding.TenantID) && handoffScopePattern.MatchString(binding.SiteID) &&
		principalDigestRegexp.MatchString(binding.PrincipalSHA256)
}

func stableHandoffOperationID(binding HandoffBinding, ref string) string {
	binding = canonicalHandoffBinding(binding)
	sum := sha256.Sum256([]byte(handoffOperationDomain + binding.TenantID + "\x00" +
		binding.SiteID + "\x00" + binding.PrincipalSHA256 + "\x00" + strings.TrimSpace(ref)))
	return "onb_" + hex.EncodeToString(sum[:16])
}

func handoffRecordDigest(record HandoffRecord) string {
	sum := sha256.Sum256([]byte(handoffRecordDomain + record.HandoffRef + "\x00" +
		record.TenantID + "\x00" + record.SiteID + "\x00" + record.PrincipalSHA256 + "\x00" + record.OperationID + "\x00" +
		record.ExpiresAt.UTC().Format(time.RFC3339Nano) + "\x00" + string(record.State)))
	return hex.EncodeToString(sum[:])
}

func handoffValues(record HandoffRecord) []any {
	return []any{record.HandoffRef, record.TenantID, record.SiteID, record.PrincipalSHA256, record.OperationID,
		record.ExpiresAt.UTC().Format(time.RFC3339Nano), record.State, record.RecordSHA256}
}

func sameHandoffIntent(left, right HandoffRecord) bool {
	return left.HandoffRef == right.HandoffRef && left.TenantID == right.TenantID && left.SiteID == right.SiteID &&
		left.PrincipalSHA256 == right.PrincipalSHA256 && left.OperationID == right.OperationID && left.ExpiresAt.Equal(right.ExpiresAt)
}

func normalizeHandoffSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}

var _ HandoffRepository = (*HandoffStore)(nil)
