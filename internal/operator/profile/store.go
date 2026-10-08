package profile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

const (
	schemaVersion       = 1
	schemaApplicationID = 0x43455052 // "CEPR"
)

const schema = `
CREATE TABLE IF NOT EXISTS device_profiles (
    profile_id TEXT NOT NULL,
	 tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    username TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    pinned_serial TEXT NOT NULL,
    pinned_type TEXT NOT NULL,
    transport_fingerprint TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    state TEXT NOT NULL,
    credential_state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
	 PRIMARY KEY(tenant_id, profile_id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_profiles_site_alias
    ON device_profiles(tenant_id, site_id, alias COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_profiles_credential_ref
    ON device_profiles(credential_ref);
CREATE TABLE IF NOT EXISTS device_profile_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id TEXT NOT NULL,
	 tenant_id TEXT NOT NULL,
	 site_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    credential_state TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_profile_events_profile
    ON device_profile_events(tenant_id, profile_id, sequence);`

// Store owns a dedicated protected SQLite file. It intentionally does not
// share or migrate the Action Kernel ledger schema.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("device profile database path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(absolute, "?#\x00") {
		return nil, errors.New("device profile database path contains a reserved character")
	}
	root := filepath.Dir(absolute)
	if _, err := os.Lstat(root); err == nil {
		if err := localstate.ValidateStateRoot(root); err != nil {
			return nil, fmt.Errorf("reject existing device profile state root: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("device profile state root is unavailable")
	} else if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, errors.New("device profile state root creation failed")
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing device profile database: %w", err)
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
		created = true
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	closeOnError := func(openErr error) (*Store, error) {
		_ = database.Close()
		return nil, openErr
	}
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA trusted_schema=OFF",
		"PRAGMA journal_mode=DELETE",
		"PRAGMA synchronous=FULL",
		"PRAGMA secure_delete=ON",
	} {
		if _, err := database.Exec(pragma); err != nil {
			return closeOnError(err)
		}
	}
	var version int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return closeOnError(err)
	}
	if version != 0 && version != schemaVersion {
		return closeOnError(ErrUnsupportedSchema)
	}
	var applicationID int
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return closeOnError(err)
	}
	if version == schemaVersion && applicationID != schemaApplicationID {
		return closeOnError(ErrUnsupportedSchema)
	}
	if version == 0 && applicationID != 0 {
		return closeOnError(ErrUnsupportedSchema)
	}
	if version == 0 && !created {
		var existingTables int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&existingTables); err != nil {
			return closeOnError(err)
		}
		if existingTables != 0 {
			return closeOnError(ErrUnsupportedSchema)
		}
	}
	if version == 0 {
		transaction, err := database.Begin()
		if err != nil {
			return closeOnError(err)
		}
		if _, err := transaction.Exec(schema); err != nil {
			_ = transaction.Rollback()
			return closeOnError(err)
		}
		if _, err := transaction.Exec(fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
			_ = transaction.Rollback()
			return closeOnError(err)
		}
		if _, err := transaction.Exec(fmt.Sprintf("PRAGMA application_id=%d", schemaApplicationID)); err != nil {
			_ = transaction.Rollback()
			return closeOnError(err)
		}
		if err := transaction.Commit(); err != nil {
			return closeOnError(err)
		}
	}
	if err := verifySchema(database); err != nil {
		return closeOnError(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return closeOnError(err)
	}
	return &Store{db: database, now: time.Now}, nil
}

type schemaColumn struct {
	name    string
	kind    string
	notNull int
	primary int
}

var profileColumns = []schemaColumn{
	{"profile_id", "TEXT", 1, 2}, {"tenant_id", "TEXT", 1, 1},
	{"site_id", "TEXT", 1, 0}, {"alias", "TEXT", 1, 0},
	{"endpoint", "TEXT", 1, 0}, {"username", "TEXT", 1, 0},
	{"credential_ref", "TEXT", 1, 0}, {"pinned_serial", "TEXT", 1, 0},
	{"pinned_type", "TEXT", 1, 0}, {"transport_fingerprint", "TEXT", 1, 0},
	{"generation", "INTEGER", 1, 0}, {"state", "TEXT", 1, 0},
	{"credential_state", "TEXT", 1, 0}, {"created_at", "TEXT", 1, 0},
	{"updated_at", "TEXT", 1, 0},
}

var eventColumns = []schemaColumn{
	{"sequence", "INTEGER", 0, 1}, {"profile_id", "TEXT", 1, 0},
	{"tenant_id", "TEXT", 1, 0}, {"site_id", "TEXT", 1, 0},
	{"event_type", "TEXT", 1, 0}, {"generation", "INTEGER", 1, 0},
	{"state", "TEXT", 1, 0}, {"credential_state", "TEXT", 1, 0},
	{"occurred_at", "TEXT", 1, 0},
}

func verifySchema(database *sql.DB) error {
	for table, expected := range map[string][]schemaColumn{
		"device_profiles": profileColumns, "device_profile_events": eventColumns,
	} {
		rows, err := database.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			return errors.Join(ErrUnsupportedSchema, err)
		}
		actual := make([]schemaColumn, 0, len(expected))
		for rows.Next() {
			var cid int
			var column schemaColumn
			var defaultValue any
			if err := rows.Scan(&cid, &column.name, &column.kind, &column.notNull, &defaultValue, &column.primary); err != nil {
				_ = rows.Close()
				return errors.Join(ErrUnsupportedSchema, err)
			}
			actual = append(actual, column)
		}
		if err := rows.Close(); err != nil {
			return errors.Join(ErrUnsupportedSchema, err)
		}
		if len(actual) != len(expected) {
			return ErrUnsupportedSchema
		}
		for index := range expected {
			if actual[index] != expected[index] {
				return ErrUnsupportedSchema
			}
		}
	}
	var unexpected int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE (type='table' AND name NOT IN ('device_profiles','device_profile_events','sqlite_sequence'))
		   OR type IN ('trigger','view')`).Scan(&unexpected); err != nil {
		return errors.Join(ErrUnsupportedSchema, err)
	}
	if unexpected != 0 {
		return ErrUnsupportedSchema
	}
	indices := []struct {
		table   string
		name    string
		unique  int
		columns []string
	}{
		{"device_profiles", "idx_device_profiles_site_alias", 1, []string{"tenant_id", "site_id", "alias"}},
		{"device_profiles", "idx_device_profiles_credential_ref", 1, []string{"credential_ref"}},
		{"device_profile_events", "idx_device_profile_events_profile", 0, []string{"tenant_id", "profile_id", "sequence"}},
	}
	for _, index := range indices {
		if err := verifyIndex(database, index.table, index.name, index.unique, index.columns); err != nil {
			return err
		}
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND sql IS NOT NULL
		AND name NOT IN ('idx_device_profiles_site_alias','idx_device_profiles_credential_ref','idx_device_profile_events_profile')`).Scan(&unexpected); err != nil {
		return errors.Join(ErrUnsupportedSchema, err)
	}
	if unexpected != 0 {
		return ErrUnsupportedSchema
	}
	var aliasIndexSQL string
	if err := database.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_device_profiles_site_alias'`).Scan(&aliasIndexSQL); err != nil || !strings.Contains(strings.ToUpper(aliasIndexSQL), "ALIAS COLLATE NOCASE") {
		return ErrUnsupportedSchema
	}
	return nil
}

func verifyIndex(database *sql.DB, table, name string, expectedUnique int, expectedColumns []string) error {
	rows, err := database.Query(`PRAGMA index_list(` + table + `)`)
	if err != nil {
		return errors.Join(ErrUnsupportedSchema, err)
	}
	found := false
	for rows.Next() {
		var sequence, unique, partial int
		var indexName, origin string
		if err := rows.Scan(&sequence, &indexName, &unique, &origin, &partial); err != nil {
			_ = rows.Close()
			return errors.Join(ErrUnsupportedSchema, err)
		}
		if indexName == name {
			found = unique == expectedUnique && partial == 0 && origin == "c"
		}
	}
	if err := rows.Close(); err != nil || !found {
		return ErrUnsupportedSchema
	}
	rows, err = database.Query(`PRAGMA index_info(` + name + `)`)
	if err != nil {
		return errors.Join(ErrUnsupportedSchema, err)
	}
	columns := make([]string, 0, len(expectedColumns))
	for rows.Next() {
		var sequence, columnID int
		var columnName string
		if err := rows.Scan(&sequence, &columnID, &columnName); err != nil {
			_ = rows.Close()
			return errors.Join(ErrUnsupportedSchema, err)
		}
		columns = append(columns, columnName)
	}
	if err := rows.Close(); err != nil || len(columns) != len(expectedColumns) {
		return ErrUnsupportedSchema
	}
	for index := range expectedColumns {
		if columns[index] != expectedColumns[index] {
			return ErrUnsupportedSchema
		}
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Create(ctx context.Context, input NewDeviceProfile) (DeviceProfile, error) {
	if input.ProfileID == "" {
		generated, err := NewProfileID()
		if err != nil {
			return DeviceProfile{}, err
		}
		input.ProfileID = generated
	}
	endpoint, fingerprint, err := normalizeTransport(input.Endpoint, input.Username, input.TransportFingerprint)
	if err != nil {
		return DeviceProfile{}, err
	}
	state := input.State
	if state == "" {
		state = StateActive
	}
	credentialState := input.CredentialState
	if credentialState == "" {
		credentialState = CredentialReady
	}
	now := s.now().UTC()
	item := DeviceProfile{
		ProfileID: input.ProfileID, TenantID: strings.TrimSpace(input.TenantID), SiteID: strings.TrimSpace(input.SiteID), Alias: strings.TrimSpace(input.Alias),
		Endpoint: endpoint, Username: strings.TrimSpace(input.Username), CredentialRef: input.CredentialRef,
		PinnedSerial: strings.TrimSpace(input.PinnedSerial), PinnedType: strings.TrimSpace(input.PinnedType),
		TransportFingerprint: fingerprint, Generation: 1, State: state, CredentialState: credentialState,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := item.Validate(); err != nil {
		return DeviceProfile{}, err
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceProfile{}, err
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `INSERT INTO device_profiles(
		profile_id, tenant_id, site_id, alias, endpoint, username, credential_ref,
		pinned_serial, pinned_type, transport_fingerprint, generation, state,
		credential_state, created_at, updated_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, profileValues(item)...)
	if err != nil {
		return DeviceProfile{}, classifyConstraint(err)
	}
	if err := appendEvent(ctx, transaction, item, "created"); err != nil {
		return DeviceProfile{}, err
	}
	if err := transaction.Commit(); err != nil {
		return DeviceProfile{}, err
	}
	return item, nil
}

func (s *Store) Get(ctx context.Context, tenantID, siteID, profileID string) (DeviceProfile, error) {
	if !validScope(tenantID, siteID) {
		return DeviceProfile{}, ErrInvalidProfile
	}
	return scanProfile(s.db.QueryRowContext(ctx, selectProfile+` WHERE tenant_id=? AND site_id=? AND profile_id=?`, strings.TrimSpace(tenantID), strings.TrimSpace(siteID), strings.TrimSpace(profileID)))
}

func (s *Store) ListSite(ctx context.Context, tenantID, siteID string) ([]DeviceProfile, error) {
	if !siteIDPattern.MatchString(strings.TrimSpace(tenantID)) || !siteIDPattern.MatchString(strings.TrimSpace(siteID)) {
		return nil, ErrInvalidProfile
	}
	rows, err := s.db.QueryContext(ctx, selectProfile+` WHERE tenant_id=? AND site_id=? ORDER BY alias COLLATE NOCASE, profile_id`, strings.TrimSpace(tenantID), strings.TrimSpace(siteID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []DeviceProfile{}
	for rows.Next() {
		item, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) Update(ctx context.Context, input UpdateDeviceProfile) (DeviceProfile, error) {
	if input.ExpectedGeneration == 0 || input.ExpectedGeneration >= math.MaxInt64 || !validScope(input.TenantID, input.SiteID) {
		return DeviceProfile{}, ErrInvalidProfile
	}
	endpoint, fingerprint, err := normalizeTransport(input.Endpoint, input.Username, input.TransportFingerprint)
	if err != nil {
		return DeviceProfile{}, err
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceProfile{}, err
	}
	defer transaction.Rollback()
	current, err := scanProfile(transaction.QueryRowContext(ctx, selectProfile+` WHERE tenant_id=? AND site_id=? AND profile_id=?`, strings.TrimSpace(input.TenantID), strings.TrimSpace(input.SiteID), strings.TrimSpace(input.ProfileID)))
	if err != nil {
		return DeviceProfile{}, err
	}
	if current.Generation != input.ExpectedGeneration {
		return DeviceProfile{}, ErrConflict
	}
	next := DeviceProfile{
		ProfileID: current.ProfileID, TenantID: current.TenantID, SiteID: strings.TrimSpace(input.SiteID), Alias: strings.TrimSpace(input.Alias),
		Endpoint: endpoint, Username: strings.TrimSpace(input.Username), CredentialRef: input.CredentialRef,
		PinnedSerial: strings.TrimSpace(input.PinnedSerial), PinnedType: strings.TrimSpace(input.PinnedType),
		TransportFingerprint: fingerprint, Generation: current.Generation + 1,
		State: input.State, CredentialState: input.CredentialState,
		CreatedAt: current.CreatedAt, UpdatedAt: s.now().UTC(),
	}
	if next.UpdatedAt.Before(current.UpdatedAt) || next.Validate() != nil || !allowedProfileTransition(current.State, next.State) || !allowedCredentialTransition(current.CredentialState, next.CredentialState) {
		return DeviceProfile{}, ErrInvalidProfile
	}
	transportChanged := current.Endpoint != next.Endpoint || current.Username != next.Username
	credentialChanged := current.CredentialRef != next.CredentialRef
	if transportChanged && !credentialChanged || credentialChanged && (current.CredentialState != CredentialRotating || next.CredentialState != CredentialReady) {
		return DeviceProfile{}, errors.Join(ErrInvalidProfile, errors.New("transport and credential rotation are not coherently bound"))
	}
	identityChanged := current.PinnedSerial != next.PinnedSerial || current.PinnedType != next.PinnedType
	if identityChanged && !((current.State == StateIdentityDrift || current.State == StateDisabled) && next.State == StateActive && next.CredentialState == CredentialReady) {
		return DeviceProfile{}, errors.Join(ErrInvalidProfile, errors.New("identity repinning requires an explicit disabled or drifted profile"))
	}
	result, err := transaction.ExecContext(ctx, `UPDATE device_profiles SET
        site_id=?, alias=?, endpoint=?, username=?, credential_ref=?,
        pinned_serial=?, pinned_type=?, transport_fingerprint=?, generation=?,
        state=?, credential_state=?, updated_at=?
		WHERE tenant_id=? AND profile_id=? AND generation=?`,
		next.SiteID, next.Alias, next.Endpoint, next.Username, next.CredentialRef.ProtectedValue(),
		next.PinnedSerial, next.PinnedType, next.TransportFingerprint, next.Generation,
		next.State, next.CredentialState, formatTime(next.UpdatedAt), next.TenantID, next.ProfileID, current.Generation)
	if err != nil {
		return DeviceProfile{}, classifyConstraint(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return DeviceProfile{}, ErrConflict
	}
	if err := appendEvent(ctx, transaction, next, "updated"); err != nil {
		return DeviceProfile{}, err
	}
	if err := transaction.Commit(); err != nil {
		return DeviceProfile{}, err
	}
	return next, nil
}

func (s *Store) MarkIdentityDrift(ctx context.Context, tenantID, siteID, profileID string, expectedGeneration uint64) (DeviceProfile, error) {
	return s.updateStatus(ctx, tenantID, siteID, profileID, expectedGeneration, StateIdentityDrift, "", "identity_drift")
}

func (s *Store) SetCredentialState(ctx context.Context, tenantID, siteID, profileID string, expectedGeneration uint64, state CredentialState) (DeviceProfile, error) {
	return s.updateStatus(ctx, tenantID, siteID, profileID, expectedGeneration, "", state, "credential_state_changed")
}

func (s *Store) Forget(ctx context.Context, tenantID, siteID, profileID string, expectedGeneration uint64) error {
	if !validScope(tenantID, siteID) {
		return ErrInvalidProfile
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	current, err := scanProfile(transaction.QueryRowContext(ctx, selectProfile+` WHERE tenant_id=? AND site_id=? AND profile_id=?`, strings.TrimSpace(tenantID), strings.TrimSpace(siteID), strings.TrimSpace(profileID)))
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration {
		return ErrConflict
	}
	if current.CredentialState != CredentialRevoked {
		return ErrCredentialNotRevoked
	}
	result, err := transaction.ExecContext(ctx, `DELETE FROM device_profiles WHERE tenant_id=? AND site_id=? AND profile_id=? AND generation=?`, current.TenantID, current.SiteID, current.ProfileID, current.Generation)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrConflict
	}
	current.Generation++
	current.State = StateForgotten
	current.UpdatedAt = s.now().UTC()
	if err := appendEvent(ctx, transaction, current, "forgotten"); err != nil {
		return err
	}
	return transaction.Commit()
}

func (s *Store) Events(ctx context.Context, tenantID, siteID, profileID string) ([]Event, error) {
	if !validScope(tenantID, siteID) {
		return nil, ErrInvalidProfile
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence, profile_id, tenant_id, site_id, event_type, generation, state, credential_state, occurred_at
		FROM device_profile_events WHERE tenant_id=? AND site_id=? AND profile_id=? ORDER BY sequence`, strings.TrimSpace(tenantID), strings.TrimSpace(siteID), strings.TrimSpace(profileID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Event{}
	for rows.Next() {
		var item Event
		var generation int64
		var occurredAt string
		if err := rows.Scan(&item.Sequence, &item.ProfileID, &item.TenantID, &item.SiteID, &item.EventType, &generation, &item.State, &item.CredentialState, &occurredAt); err != nil {
			return nil, err
		}
		item.Generation = uint64(generation)
		if item.OccurredAt, err = parseTime(occurredAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) updateStatus(ctx context.Context, tenantID, siteID, profileID string, expectedGeneration uint64, profileState State, credentialState CredentialState, eventType string) (DeviceProfile, error) {
	if expectedGeneration == 0 || expectedGeneration >= math.MaxInt64 || !validScope(tenantID, siteID) {
		return DeviceProfile{}, ErrInvalidProfile
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceProfile{}, err
	}
	defer transaction.Rollback()
	current, err := scanProfile(transaction.QueryRowContext(ctx, selectProfile+` WHERE tenant_id=? AND site_id=? AND profile_id=?`, strings.TrimSpace(tenantID), strings.TrimSpace(siteID), strings.TrimSpace(profileID)))
	if err != nil {
		return DeviceProfile{}, err
	}
	if current.Generation != expectedGeneration {
		return DeviceProfile{}, ErrConflict
	}
	next := current
	next.Generation++
	next.UpdatedAt = s.now().UTC()
	if profileState != "" {
		if !allowedProfileTransition(current.State, profileState) {
			return DeviceProfile{}, ErrInvalidProfile
		}
		next.State = profileState
	}
	if credentialState != "" {
		if !allowedCredentialTransition(current.CredentialState, credentialState) {
			return DeviceProfile{}, ErrInvalidProfile
		}
		next.CredentialState = credentialState
		if credentialState == CredentialRevoking || credentialState == CredentialRevoked {
			next.State = StateDisabled
		}
	}
	if next.UpdatedAt.Before(current.UpdatedAt) || next.Validate() != nil {
		return DeviceProfile{}, ErrInvalidProfile
	}
	result, err := transaction.ExecContext(ctx, `UPDATE device_profiles SET generation=?, state=?, credential_state=?, updated_at=? WHERE tenant_id=? AND site_id=? AND profile_id=? AND generation=?`,
		next.Generation, next.State, next.CredentialState, formatTime(next.UpdatedAt), next.TenantID, next.SiteID, next.ProfileID, current.Generation)
	if err != nil {
		return DeviceProfile{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return DeviceProfile{}, ErrConflict
	}
	if err := appendEvent(ctx, transaction, next, eventType); err != nil {
		return DeviceProfile{}, err
	}
	if err := transaction.Commit(); err != nil {
		return DeviceProfile{}, err
	}
	return next, nil
}

const selectProfile = `SELECT profile_id, tenant_id, site_id, alias, endpoint, username, credential_ref,
    pinned_serial, pinned_type, transport_fingerprint, generation, state,
    credential_state, created_at, updated_at FROM device_profiles`

type scanner interface{ Scan(...any) error }

func scanProfile(row scanner) (DeviceProfile, error) {
	var item DeviceProfile
	var ref string
	var generation int64
	var createdAt, updatedAt string
	err := row.Scan(
		&item.ProfileID, &item.TenantID, &item.SiteID, &item.Alias, &item.Endpoint, &item.Username, &ref,
		&item.PinnedSerial, &item.PinnedType, &item.TransportFingerprint, &generation,
		&item.State, &item.CredentialState, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceProfile{}, ErrNotFound
	}
	if err != nil || generation < 1 {
		return DeviceProfile{}, firstError(err, ErrInvalidProfile)
	}
	item.Generation = uint64(generation)
	if item.CredentialRef, err = credential.ParseRef(ref); err != nil {
		return DeviceProfile{}, ErrInvalidProfile
	}
	if item.CreatedAt, err = parseTime(createdAt); err != nil {
		return DeviceProfile{}, ErrInvalidProfile
	}
	if item.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return DeviceProfile{}, ErrInvalidProfile
	}
	if err := item.Validate(); err != nil {
		return DeviceProfile{}, err
	}
	return item, nil
}

func appendEvent(ctx context.Context, transaction *sql.Tx, item DeviceProfile, eventType string) error {
	_, err := transaction.ExecContext(ctx, `INSERT INTO device_profile_events(profile_id, tenant_id, site_id, event_type, generation, state, credential_state, occurred_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ProfileID, item.TenantID, item.SiteID, eventType, item.Generation, item.State, item.CredentialState, formatTime(item.UpdatedAt))
	return err
}

func normalizeTransport(endpoint, username, supplied string) (string, string, error) {
	normalized, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return "", "", errors.Join(ErrInvalidProfile, err)
	}
	fingerprint, err := ComputeTransportFingerprint(normalized, username)
	if err != nil {
		return "", "", errors.Join(ErrInvalidProfile, err)
	}
	if supplied != "" && supplied != fingerprint {
		return "", "", errors.Join(ErrInvalidProfile, errors.New("supplied transport fingerprint does not match"))
	}
	return normalized, fingerprint, nil
}

func profileValues(item DeviceProfile) []any {
	return []any{
		item.ProfileID, item.TenantID, item.SiteID, item.Alias, item.Endpoint, item.Username, item.CredentialRef.ProtectedValue(),
		item.PinnedSerial, item.PinnedType, item.TransportFingerprint, item.Generation, item.State,
		item.CredentialState, formatTime(item.CreatedAt), formatTime(item.UpdatedAt),
	}
}

func allowedProfileTransition(from, to State) bool {
	if from == to {
		return true
	}
	switch from {
	case StateActive:
		return to == StateIdentityDrift || to == StateDisabled
	case StateIdentityDrift:
		return to == StateActive || to == StateDisabled
	case StateDisabled:
		return to == StateActive || to == StateIdentityDrift
	default:
		return false
	}
}

func allowedCredentialTransition(from, to CredentialState) bool {
	if from == to {
		return true
	}
	switch from {
	case CredentialReady:
		return to == CredentialRotating || to == CredentialInvalid || to == CredentialUnavailable || to == CredentialRevoking
	case CredentialRotating:
		return to == CredentialReady || to == CredentialInvalid || to == CredentialUnavailable || to == CredentialRevoking
	case CredentialInvalid, CredentialUnavailable:
		return to == CredentialReady || to == CredentialRotating || to == CredentialRevoking
	case CredentialRevoking:
		return to == CredentialRevoked
	default:
		return false
	}
}

func classifyConstraint(err error) error {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "constraint") {
		return ErrConflict
	}
	return err
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }

func firstError(first, fallback error) error {
	if first != nil {
		return first
	}
	return fallback
}

func validScope(tenantID, siteID string) bool {
	return siteIDPattern.MatchString(strings.TrimSpace(tenantID)) && siteIDPattern.MatchString(strings.TrimSpace(siteID))
}
