package inspectioninteraction

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

const (
	storeVersion       = 3
	storeApplicationID = 0x43454949 // "CEII"
	recordDigestDomain = "cosmoedge.operator.inspection-interaction.record.v3\x00"
)

const createPendingInteractionsSQL = `CREATE TABLE pending_inspection_interactions (
    handoff_ref TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    principal_sha256 TEXT NOT NULL,
    interaction_type TEXT NOT NULL CHECK(interaction_type = 'persistent_change'),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN ('source_create', 'source_update', 'source_delete', 'task_deploy', 'task_update', 'task_enable', 'task_disable', 'device_schedule_update')),
    source_ref TEXT NOT NULL,
    task_ref TEXT NOT NULL,
    observable_ref TEXT NOT NULL,
    expected_source_revision INTEGER NOT NULL CHECK(expected_source_revision >= 0),
    expected_task_revision INTEGER NOT NULL CHECK(expected_task_revision >= 0),
    expires_at TEXT NOT NULL,
    proposal_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending', 'transfer_prepared', 'transferred')),
    record_sha256 TEXT NOT NULL,
    CHECK((state = 'pending' AND proposal_ref = '') OR (state IN ('transfer_prepared', 'transferred') AND length(proposal_ref) > 0))
) WITHOUT ROWID`

type StoreConfig struct {
	Path string
	Now  func() time.Time
}

type RegistrationStore interface {
	Register(context.Context, Record) (Record, error)
}

type PendingStore interface {
	RegistrationStore
	Resolve(context.Context, Binding, string) (Record, error)
	PrepareTransfer(context.Context, Binding, string, string) (Record, error)
	MarkTransferred(context.Context, Binding, string, string) (Record, error)
}

// Store persists the pending-change handoff and its durable transfer boundary.
// ProposalRef is an opaque correlation handle only. The store deliberately has
// no desired values, confirmation, grant, secret, device endpoint, dispatch, or
// execution API.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

func OpenStore(config StoreConfig) (*Store, error) {
	if strings.TrimSpace(config.Path) == "" || strings.ContainsAny(config.Path, "?#\x00") {
		return nil, ErrInvalidRegistration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	absolute, err := filepath.Abs(config.Path)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(absolute, "?#\x00") {
		return nil, ErrInvalidRegistration
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing inspection interaction state: %w", err)
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
	fail := func(openErr error) (*Store, error) {
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
			return fail(ErrUnsupportedSchema)
		}
		tx, err := database.Begin()
		if err != nil {
			return fail(err)
		}
		for _, statement := range []string{
			createPendingInteractionsSQL,
			fmt.Sprintf("PRAGMA application_id=%d", storeApplicationID),
			fmt.Sprintf("PRAGMA user_version=%d", storeVersion),
		} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fail(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != storeVersion || applicationID != storeApplicationID {
		return fail(ErrUnsupportedSchema)
	}
	if err := verifyStore(database); err != nil {
		return fail(err)
	}
	store := &Store{db: database, now: config.Now}
	if err := store.validateContent(context.Background()); err != nil {
		return fail(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
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

func (s *Store) Register(ctx context.Context, record Record) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, ErrInvalidRegistration
	}
	record = canonicalRecord(record)
	if record.State == "" {
		record.State = StatePending
	}
	if record.State != StatePending || record.ProposalRef != "" {
		return Record{}, ErrInvalidRegistration
	}
	record.RecordSHA256 = recordDigest(record)
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	if !record.ExpiresAt.After(s.now().UTC()) {
		return Record{}, ErrExpired
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO pending_inspection_interactions(
handoff_ref, tenant_id, site_id, principal_sha256, interaction_type, operation_kind,
source_ref, task_ref, observable_ref, expected_source_revision, expected_task_revision,
expires_at, proposal_ref, state, record_sha256
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, recordValues(record)...)
	if err != nil {
		return Record{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 1 {
		return record, nil
	}
	existing, err := s.load(ctx, record.HandoffRef)
	if err != nil {
		return Record{}, errors.Join(ErrConflict, err)
	}
	if !sameRegistration(existing, record) {
		return Record{}, ErrConflict
	}
	if !existing.ExpiresAt.After(s.now().UTC()) {
		return Record{}, ErrExpired
	}
	return existing, nil
}

// PrepareTransfer atomically binds one stable proposal reference to a pending
// handoff. Replaying the exact proposal is idempotent, including after expiry
// once preparation has durably succeeded. A different proposal always
// conflicts.
func (s *Store) PrepareTransfer(ctx context.Context, binding Binding, handoffRef, proposalRef string) (Record, error) {
	return s.transitionTransfer(ctx, binding, handoffRef, proposalRef, StateTransferPrepared)
}

// MarkTransferred durably closes a previously prepared transfer. It never
// invokes changeflow or any device operation; callers may mark only after the
// separately owned changeflow has confirmed durable success for the same
// proposal reference.
func (s *Store) MarkTransferred(ctx context.Context, binding Binding, handoffRef, proposalRef string) (Record, error) {
	return s.transitionTransfer(ctx, binding, handoffRef, proposalRef, StateTransferred)
}

func (s *Store) transitionTransfer(
	ctx context.Context,
	binding Binding,
	handoffRef string,
	proposalRef string,
	target State,
) (Record, error) {
	if s == nil || s.db == nil || (target != StateTransferPrepared && target != StateTransferred) {
		return Record{}, ErrInvalidRegistration
	}
	binding = canonicalBinding(binding)
	handoffRef = strings.TrimSpace(handoffRef)
	if !validBinding(binding) || !scopeRefPattern.MatchString(handoffRef) || !validProposalRef(proposalRef) {
		return Record{}, ErrInvalidRegistration
	}

	// At most two monotonic transitions can race with this call. Retrying the
	// exact compare-and-swap is bounded and needs no broad recovery query.
	for attempt := 0; attempt < 3; attempt++ {
		record, err := s.load(ctx, handoffRef)
		if err != nil {
			return Record{}, err
		}
		if record.TenantID != binding.TenantID || record.SiteID != binding.SiteID || record.PrincipalSHA256 != binding.PrincipalSHA256 {
			return Record{}, ErrScopeMismatch
		}

		switch target {
		case StateTransferPrepared:
			switch record.State {
			case StatePending:
				if !s.now().UTC().Before(record.ExpiresAt) {
					return Record{}, ErrExpired
				}
			case StateTransferPrepared, StateTransferred:
				if record.ProposalRef != proposalRef {
					return Record{}, ErrConflict
				}
				return record, nil
			}
		case StateTransferred:
			switch record.State {
			case StatePending:
				return Record{}, ErrTransferNotPrepared
			case StateTransferPrepared:
				if record.ProposalRef != proposalRef {
					return Record{}, ErrConflict
				}
			case StateTransferred:
				if record.ProposalRef != proposalRef {
					return Record{}, ErrConflict
				}
				return record, nil
			}
		}

		next := record
		next.State = target
		next.ProposalRef = proposalRef
		next.RecordSHA256 = recordDigest(next)
		result, err := s.db.ExecContext(ctx, `UPDATE pending_inspection_interactions
SET proposal_ref=?, state=?, record_sha256=?
WHERE handoff_ref=? AND tenant_id=? AND site_id=? AND principal_sha256=?
AND proposal_ref=? AND state=? AND record_sha256=?`,
			next.ProposalRef, next.State, next.RecordSHA256,
			record.HandoffRef, binding.TenantID, binding.SiteID, binding.PrincipalSHA256,
			record.ProposalRef, record.State, record.RecordSHA256,
		)
		if err != nil {
			return Record{}, err
		}
		if changed, _ := result.RowsAffected(); changed == 1 {
			return next, nil
		}
	}
	return Record{}, ErrConflict
}

func (s *Store) Resolve(ctx context.Context, binding Binding, handoffRef string) (Record, error) {
	if s == nil || s.db == nil {
		return Record{}, ErrInvalidRegistration
	}
	binding = canonicalBinding(binding)
	handoffRef = strings.TrimSpace(handoffRef)
	if !validBinding(binding) || !scopeRefPattern.MatchString(handoffRef) {
		return Record{}, ErrInvalidRegistration
	}
	record, err := s.load(ctx, handoffRef)
	if err != nil {
		return Record{}, err
	}
	if record.TenantID != binding.TenantID || record.SiteID != binding.SiteID || record.PrincipalSHA256 != binding.PrincipalSHA256 {
		return Record{}, ErrScopeMismatch
	}
	if !s.now().UTC().Before(record.ExpiresAt) {
		return Record{}, ErrExpired
	}
	return record, nil
}

// ResolveProtected performs an integrity-checked lookup by the opaque handoff
// already sealed into an authenticated local browser session. Callers must not
// expose this as a request-field lookup; its result is non-projectable.
func (s *Store) ResolveProtected(ctx context.Context, handoffRef string) (ProtectedLookup, error) {
	if s == nil || s.db == nil || handoffRef != strings.TrimSpace(handoffRef) || !scopeRefPattern.MatchString(handoffRef) {
		return ProtectedLookup{}, ErrInvalidRegistration
	}
	record, err := s.load(ctx, handoffRef)
	if err != nil {
		return ProtectedLookup{}, err
	}
	return ProtectedLookup{Record: record, Expired: !s.now().UTC().Before(record.ExpiresAt)}, nil
}

func (s *Store) load(ctx context.Context, handoffRef string) (Record, error) {
	row := s.db.QueryRowContext(ctx, `SELECT handoff_ref, tenant_id, site_id, principal_sha256,
interaction_type, operation_kind, source_ref, task_ref, observable_ref, expected_source_revision,
expected_task_revision, expires_at, proposal_ref, state, record_sha256
FROM pending_inspection_interactions WHERE handoff_ref=?`, handoffRef)
	record, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	return record, err
}

func (s *Store) validateContent(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT handoff_ref, tenant_id, site_id, principal_sha256,
interaction_type, operation_kind, source_ref, task_ref, observable_ref, expected_source_revision,
expected_task_revision, expires_at, proposal_ref, state, record_sha256
FROM pending_inspection_interactions ORDER BY handoff_ref`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if _, err := scanRecord(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

type recordScanner interface {
	Scan(...any) error
}

func scanRecord(scanner recordScanner) (Record, error) {
	var record Record
	var expiresAt string
	if err := scanner.Scan(
		&record.HandoffRef, &record.TenantID, &record.SiteID, &record.PrincipalSHA256,
		&record.InteractionType, &record.Operation, &record.SourceRef, &record.TaskRef, &record.ObservableRef,
		&record.ExpectedSourceRevision, &record.ExpectedTaskRevision, &expiresAt, &record.ProposalRef,
		&record.State, &record.RecordSHA256,
	); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return Record{}, errors.Join(ErrIntegrity, err)
		}
		return Record{}, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != expiresAt {
		return Record{}, ErrIntegrity
	}
	record.ExpiresAt = parsed.UTC()
	if err := record.validate(); err != nil {
		return Record{}, errors.Join(ErrIntegrity, err)
	}
	want := recordDigest(record)
	if subtle.ConstantTimeCompare([]byte(record.RecordSHA256), []byte(want)) != 1 {
		return Record{}, ErrIntegrity
	}
	return record, nil
}

func verifyStore(database *sql.DB) error {
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != storeVersion {
		return ErrUnsupportedSchema
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != storeApplicationID {
		return ErrUnsupportedSchema
	}
	var integrity string
	if err := database.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrIntegrity
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
	if err := rows.Err(); err != nil || len(actual) != 1 ||
		normalizeSQL(actual["pending_inspection_interactions"]) != normalizeSQL(createPendingInteractionsSQL) {
		return ErrUnsupportedSchema
	}
	return nil
}

func canonicalRecord(record Record) Record {
	record.HandoffRef = strings.TrimSpace(record.HandoffRef)
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.SiteID = strings.TrimSpace(record.SiteID)
	record.PrincipalSHA256 = strings.TrimSpace(record.PrincipalSHA256)
	record.SourceRef = strings.TrimSpace(record.SourceRef)
	record.TaskRef = strings.TrimSpace(record.TaskRef)
	record.ObservableRef = strings.TrimSpace(record.ObservableRef)
	record.ProposalRef = strings.TrimSpace(record.ProposalRef)
	record.ExpiresAt = record.ExpiresAt.UTC()
	return record
}

func canonicalBinding(binding Binding) Binding {
	binding.TenantID = strings.TrimSpace(binding.TenantID)
	binding.SiteID = strings.TrimSpace(binding.SiteID)
	binding.PrincipalSHA256 = strings.TrimSpace(binding.PrincipalSHA256)
	return binding
}

func sameRecord(left, right Record) bool {
	return left.HandoffRef == right.HandoffRef && left.TenantID == right.TenantID && left.SiteID == right.SiteID &&
		left.PrincipalSHA256 == right.PrincipalSHA256 && left.InteractionType == right.InteractionType &&
		left.Operation == right.Operation && left.SourceRef == right.SourceRef && left.TaskRef == right.TaskRef &&
		left.ObservableRef == right.ObservableRef && left.ExpectedSourceRevision == right.ExpectedSourceRevision &&
		left.ExpectedTaskRevision == right.ExpectedTaskRevision && left.ExpiresAt == right.ExpiresAt &&
		left.ProposalRef == right.ProposalRef && left.State == right.State && left.RecordSHA256 == right.RecordSHA256
}

func sameRegistration(left, right Record) bool {
	return left.HandoffRef == right.HandoffRef && left.TenantID == right.TenantID && left.SiteID == right.SiteID &&
		left.PrincipalSHA256 == right.PrincipalSHA256 && left.InteractionType == right.InteractionType &&
		left.Operation == right.Operation && left.SourceRef == right.SourceRef && left.TaskRef == right.TaskRef &&
		left.ObservableRef == right.ObservableRef && left.ExpectedSourceRevision == right.ExpectedSourceRevision &&
		left.ExpectedTaskRevision == right.ExpectedTaskRevision && left.ExpiresAt == right.ExpiresAt
}

func recordDigest(record Record) string {
	sum := sha256.Sum256([]byte(recordDigestDomain + record.HandoffRef + "\x00" + record.TenantID + "\x00" +
		record.SiteID + "\x00" + record.PrincipalSHA256 + "\x00" + string(record.InteractionType) + "\x00" +
		string(record.Operation) + "\x00" + record.SourceRef + "\x00" + record.TaskRef + "\x00" + record.ObservableRef + "\x00" +
		strconv.FormatUint(record.ExpectedSourceRevision, 10) + "\x00" + strconv.FormatUint(record.ExpectedTaskRevision, 10) + "\x00" +
		record.ExpiresAt.UTC().Format(time.RFC3339Nano) + "\x00" + record.ProposalRef + "\x00" + string(record.State)))
	return hex.EncodeToString(sum[:])
}

func recordValues(record Record) []any {
	return []any{
		record.HandoffRef, record.TenantID, record.SiteID, record.PrincipalSHA256, record.InteractionType,
		record.Operation, record.SourceRef, record.TaskRef, record.ObservableRef, record.ExpectedSourceRevision,
		record.ExpectedTaskRevision, record.ExpiresAt.UTC().Format(time.RFC3339Nano), record.ProposalRef,
		record.State, record.RecordSHA256,
	}
}

func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}

var _ PendingStore = (*Store)(nil)
var _ RegistrationStore = (*Store)(nil)
