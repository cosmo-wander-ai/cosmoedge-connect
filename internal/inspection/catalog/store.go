package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
	_ "modernc.org/sqlite"
)

const (
	databaseSchemaVersion = 3
	databaseApplicationID = 0x43454332 // CEC2
	maxCapabilityJSON     = 128 << 10
)

const databaseSchema = `
CREATE TABLE source_catalog (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    source_handle TEXT NOT NULL,
    device_profile_id TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    identity_fingerprint TEXT NOT NULL,
    native_locator TEXT NOT NULL,
    alias TEXT NOT NULL,
    zone_id TEXT NOT NULL,
    state TEXT NOT NULL,
    capabilities_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, site_id, source_handle),
    UNIQUE(tenant_id, site_id, device_profile_id, source_kind, identity_fingerprint)
);
CREATE INDEX idx_source_catalog_site_alias
    ON source_catalog(tenant_id, site_id, alias COLLATE NOCASE, source_handle);
CREATE TABLE source_catalog_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    source_handle TEXT NOT NULL,
    event_type TEXT NOT NULL,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX idx_source_catalog_events_source
    ON source_catalog_events(tenant_id, site_id, source_handle, sequence);
CREATE TABLE device_task_bindings (
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    task_handle TEXT NOT NULL,
    device_profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    identity_fingerprint TEXT NOT NULL,
    native_locator TEXT NOT NULL,
    alias TEXT NOT NULL,
    source_handles_json BLOB NOT NULL,
    capabilities_json BLOB NOT NULL,
    state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, site_id, task_handle)
);
CREATE INDEX idx_device_task_bindings_site_alias
    ON device_task_bindings(tenant_id, site_id, alias COLLATE NOCASE, task_handle);
CREATE UNIQUE INDEX idx_device_task_bindings_identity
    ON device_task_bindings(tenant_id, site_id, device_profile_id, identity_fingerprint);
CREATE TABLE device_task_binding_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    task_handle TEXT NOT NULL,
    event_type TEXT NOT NULL,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX idx_device_task_binding_events_task
    ON device_task_binding_events(tenant_id, site_id, task_handle, sequence);`

type Store struct {
	db  *sql.DB
	now func() time.Time
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("inspection source catalog path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(absolute, "?#\x00") {
		return nil, errors.New("inspection source catalog path contains a reserved character")
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing inspection source catalog: %w", err)
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
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return closeOnError(err)
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return closeOnError(err)
	}
	if version == 0 {
		if applicationID != 0 {
			return closeOnError(ErrUnsupportedSchema)
		}
	} else if version != databaseSchemaVersion || applicationID != databaseApplicationID {
		return closeOnError(ErrUnsupportedSchema)
	}
	if version == 0 && !created {
		var tables int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&tables); err != nil {
			return closeOnError(err)
		}
		if tables != 0 {
			return closeOnError(ErrUnsupportedSchema)
		}
	}
	if version == 0 {
		transaction, err := database.Begin()
		if err != nil {
			return closeOnError(err)
		}
		if _, err := transaction.Exec(databaseSchema); err != nil {
			_ = transaction.Rollback()
			return closeOnError(err)
		}
		for _, statement := range []string{
			fmt.Sprintf("PRAGMA application_id=%d", databaseApplicationID),
			fmt.Sprintf("PRAGMA user_version=%d", databaseSchemaVersion),
		} {
			if _, err := transaction.Exec(statement); err != nil {
				_ = transaction.Rollback()
				return closeOnError(err)
			}
		}
		if err := transaction.Commit(); err != nil {
			return closeOnError(err)
		}
	}
	if err := validateDatabaseShape(database); err != nil {
		return closeOnError(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return closeOnError(err)
	}
	return &Store{db: database, now: time.Now}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Create(ctx context.Context, input NewSource) (Source, error) {
	capabilities, err := NormalizeCapabilities(input.Capabilities)
	if err != nil {
		return Source{}, err
	}
	now := s.now().UTC()
	item := Source{
		Schema: SchemaVersion, TenantID: strings.TrimSpace(input.TenantID), SiteID: strings.TrimSpace(input.SiteID),
		DeviceProfileID: strings.TrimSpace(input.DeviceProfileID), Handle: strings.TrimSpace(input.Handle), Kind: input.Kind,
		Revision: 1, IdentityFingerprint: strings.TrimSpace(input.IdentityFingerprint),
		NativeLocator: strings.TrimSpace(input.NativeLocator), Alias: strings.TrimSpace(input.Alias), ZoneID: strings.TrimSpace(input.ZoneID),
		State: StateActive, Capabilities: capabilities, CreatedAt: now, UpdatedAt: now,
	}
	if err := item.Validate(); err != nil {
		return Source{}, err
	}
	raw, err := marshalCapabilities(capabilities)
	if err != nil {
		return Source{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO source_catalog(
        tenant_id, site_id, source_handle, device_profile_id, source_kind, revision,
        identity_fingerprint, native_locator, alias, zone_id, state, capabilities_json,
        created_at, updated_at
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.TenantID, item.SiteID, item.Handle, item.DeviceProfileID, item.Kind, item.Revision,
		item.IdentityFingerprint, item.NativeLocator, item.Alias, item.ZoneID, item.State, raw,
		formatTime(item.CreatedAt), formatTime(item.UpdatedAt))
	if err != nil {
		return Source{}, classifyConstraint(err)
	}
	if err := appendEvent(ctx, tx, item, "created"); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(); err != nil {
		return Source{}, err
	}
	return cloneSource(item), nil
}

func (s *Store) Get(ctx context.Context, tenantID, siteID, handle string) (Source, error) {
	if !validRef(tenantID) || !validRef(siteID) || !validRef(handle) {
		return Source{}, ErrInvalidSource
	}
	return scanSource(s.db.QueryRowContext(ctx, selectSource+` WHERE tenant_id=? AND site_id=? AND source_handle=?`,
		strings.TrimSpace(tenantID), strings.TrimSpace(siteID), strings.TrimSpace(handle)))
}

func (s *Store) ListSite(ctx context.Context, tenantID, siteID string) ([]Source, error) {
	if !validRef(tenantID) || !validRef(siteID) {
		return nil, ErrInvalidSource
	}
	rows, err := s.db.QueryContext(ctx, selectSource+` WHERE tenant_id=? AND site_id=? ORDER BY alias COLLATE NOCASE, source_handle`,
		strings.TrimSpace(tenantID), strings.TrimSpace(siteID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Source{}
	for rows.Next() {
		item, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// Update refreshes a source only when its pinned identity is unchanged. A
// different fingerprint records identity_drift while retaining the trusted
// locator and capabilities, then returns ErrIdentityDrift.
func (s *Store) Update(ctx context.Context, input UpdateSource) (Source, error) {
	if input.ExpectedRevision == 0 {
		return Source{}, ErrInvalidSource
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, err
	}
	defer tx.Rollback()
	current, err := scanSource(tx.QueryRowContext(ctx, selectSource+` WHERE tenant_id=? AND site_id=? AND source_handle=?`,
		strings.TrimSpace(input.TenantID), strings.TrimSpace(input.SiteID), strings.TrimSpace(input.Handle)))
	if err != nil {
		return Source{}, err
	}
	if current.Revision != input.ExpectedRevision {
		return Source{}, ErrConflict
	}
	if strings.TrimSpace(input.IdentityFingerprint) != current.IdentityFingerprint {
		drifted := current
		drifted.Revision++
		drifted.State = StateIdentityDrift
		drifted.UpdatedAt = s.now().UTC()
		if err := updateRow(ctx, tx, current.Revision, drifted); err != nil {
			return Source{}, err
		}
		if err := appendEvent(ctx, tx, drifted, "identity_drift"); err != nil {
			return Source{}, err
		}
		if err := tx.Commit(); err != nil {
			return Source{}, err
		}
		return cloneSource(drifted), ErrIdentityDrift
	}
	capabilities, err := NormalizeCapabilities(input.Capabilities)
	if err != nil {
		return Source{}, err
	}
	next := current
	next.Revision++
	next.DeviceProfileID = strings.TrimSpace(input.DeviceProfileID)
	next.NativeLocator = strings.TrimSpace(input.NativeLocator)
	next.Alias = strings.TrimSpace(input.Alias)
	next.ZoneID = strings.TrimSpace(input.ZoneID)
	next.State = input.State
	next.Capabilities = capabilities
	next.UpdatedAt = s.now().UTC()
	if next.DeviceProfileID != current.DeviceProfileID || next.State == StateIdentityDrift || next.Validate() != nil {
		return Source{}, ErrInvalidSource
	}
	if err := updateRow(ctx, tx, current.Revision, next); err != nil {
		return Source{}, err
	}
	if err := appendEvent(ctx, tx, next, "refreshed"); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(); err != nil {
		return Source{}, err
	}
	return cloneSource(next), nil
}

func (s *Store) Repin(ctx context.Context, input UpdateSource) (Source, error) {
	if input.ExpectedRevision == 0 {
		return Source{}, ErrInvalidSource
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, err
	}
	defer tx.Rollback()
	current, err := scanSource(tx.QueryRowContext(ctx, selectSource+` WHERE tenant_id=? AND site_id=? AND source_handle=?`,
		strings.TrimSpace(input.TenantID), strings.TrimSpace(input.SiteID), strings.TrimSpace(input.Handle)))
	if err != nil {
		return Source{}, err
	}
	if current.Revision != input.ExpectedRevision {
		return Source{}, ErrConflict
	}
	if current.State != StateIdentityDrift || strings.TrimSpace(input.IdentityFingerprint) == current.IdentityFingerprint {
		return Source{}, ErrInvalidSource
	}
	capabilities, err := NormalizeCapabilities(input.Capabilities)
	if err != nil {
		return Source{}, err
	}
	next := current
	next.Revision++
	next.IdentityFingerprint = strings.TrimSpace(input.IdentityFingerprint)
	next.NativeLocator = strings.TrimSpace(input.NativeLocator)
	next.Alias = strings.TrimSpace(input.Alias)
	next.ZoneID = strings.TrimSpace(input.ZoneID)
	next.State = StateActive
	next.Capabilities = capabilities
	next.UpdatedAt = s.now().UTC()
	if strings.TrimSpace(input.DeviceProfileID) != current.DeviceProfileID || next.Validate() != nil {
		return Source{}, ErrInvalidSource
	}
	if err := updateRow(ctx, tx, current.Revision, next); err != nil {
		return Source{}, err
	}
	if err := appendEvent(ctx, tx, next, "identity_repinned"); err != nil {
		return Source{}, err
	}
	if err := tx.Commit(); err != nil {
		return Source{}, err
	}
	return cloneSource(next), nil
}

func (s *Store) Binding(ctx context.Context, tenantID, siteID, handle string, capabilities []string, roiRef string) (inspection.SourceBinding, error) {
	source, err := s.Get(ctx, tenantID, siteID, handle)
	if err != nil {
		return inspection.SourceBinding{}, err
	}
	return source.Binding(capabilities, roiRef)
}

func (s *Store) Fingerprint(ctx context.Context, tenantID, siteID string) (string, error) {
	values, err := s.ListSite(ctx, tenantID, siteID)
	if err != nil {
		return "", err
	}
	projection := make([]struct {
		Handle       string   `json:"handle"`
		Kind         string   `json:"kind"`
		Revision     uint64   `json:"revision"`
		Identity     string   `json:"identity"`
		State        State    `json:"state"`
		Capabilities []string `json:"capabilities"`
	}, 0, len(values))
	for _, value := range values {
		capabilities := make([]string, 0, len(value.Capabilities))
		for _, capability := range value.Capabilities {
			capabilities = append(capabilities, capability.Ref+":"+capability.Digest)
		}
		projection = append(projection, struct {
			Handle       string   `json:"handle"`
			Kind         string   `json:"kind"`
			Revision     uint64   `json:"revision"`
			Identity     string   `json:"identity"`
			State        State    `json:"state"`
			Capabilities []string `json:"capabilities"`
		}{value.Handle, string(value.Kind), value.Revision, value.IdentityFingerprint, value.State, capabilities})
	}
	tasks, err := s.ListTasks(ctx, tenantID, siteID)
	if err != nil {
		return "", err
	}
	taskProjection := make([]struct {
		Handle       string   `json:"handle"`
		Revision     uint64   `json:"revision"`
		Identity     string   `json:"identity"`
		State        State    `json:"state"`
		Sources      []string `json:"sources"`
		Capabilities []string `json:"capabilities"`
	}, 0, len(tasks))
	for _, task := range tasks {
		capabilities := make([]string, 0, len(task.Capabilities))
		for _, capability := range task.Capabilities {
			capabilities = append(capabilities, capability.Ref+":"+capability.Digest)
		}
		taskProjection = append(taskProjection, struct {
			Handle       string   `json:"handle"`
			Revision     uint64   `json:"revision"`
			Identity     string   `json:"identity"`
			State        State    `json:"state"`
			Sources      []string `json:"sources"`
			Capabilities []string `json:"capabilities"`
		}{task.TaskHandle, task.Revision, task.IdentityFingerprint, task.State,
			append([]string(nil), task.SourceHandles...), capabilities})
	}
	raw, err := json.Marshal(struct {
		Sources any `json:"sources"`
		Tasks   any `json:"tasks"`
	}{Sources: projection, Tasks: taskProjection})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

const selectSource = `SELECT tenant_id, site_id, source_handle, device_profile_id, source_kind,
    revision, identity_fingerprint, native_locator, alias, zone_id, state,
    capabilities_json, created_at, updated_at FROM source_catalog`

type rowScanner interface{ Scan(...any) error }

func scanSource(row rowScanner) (Source, error) {
	var item Source
	var revision int64
	var raw []byte
	var createdAt, updatedAt string
	if err := row.Scan(&item.TenantID, &item.SiteID, &item.Handle, &item.DeviceProfileID, &item.Kind,
		&revision, &item.IdentityFingerprint, &item.NativeLocator, &item.Alias, &item.ZoneID,
		&item.State, &raw, &createdAt, &updatedAt); errors.Is(err, sql.ErrNoRows) {
		return Source{}, ErrNotFound
	} else if err != nil || revision < 1 {
		return Source{}, firstError(err, ErrInvalidSource)
	}
	item.Schema = SchemaVersion
	item.Revision = uint64(revision)
	var err error
	if item.Capabilities, err = parseCapabilities(raw); err != nil {
		return Source{}, err
	}
	if item.CreatedAt, err = parseTime(createdAt); err != nil {
		return Source{}, ErrInvalidSource
	}
	if item.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return Source{}, ErrInvalidSource
	}
	if err := item.Validate(); err != nil {
		return Source{}, err
	}
	return cloneSource(item), nil
}

func updateRow(ctx context.Context, tx *sql.Tx, expectedRevision uint64, item Source) error {
	raw, err := marshalCapabilities(item.Capabilities)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE source_catalog SET device_profile_id=?, revision=?,
        identity_fingerprint=?, native_locator=?, alias=?, zone_id=?, state=?, capabilities_json=?, updated_at=?
        WHERE tenant_id=? AND site_id=? AND source_handle=? AND revision=?`,
		item.DeviceProfileID, item.Revision, item.IdentityFingerprint, item.NativeLocator, item.Alias,
		item.ZoneID, item.State, raw, formatTime(item.UpdatedAt), item.TenantID, item.SiteID, item.Handle, expectedRevision)
	if err != nil {
		return classifyConstraint(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrConflict
	}
	return nil
}

func appendEvent(ctx context.Context, tx *sql.Tx, item Source, eventType string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO source_catalog_events(
        tenant_id, site_id, source_handle, event_type, revision, state, occurred_at
    ) VALUES(?, ?, ?, ?, ?, ?, ?)`, item.TenantID, item.SiteID, item.Handle, eventType,
		item.Revision, item.State, formatTime(item.UpdatedAt))
	return err
}

func marshalCapabilities(values []Capability) ([]byte, error) {
	raw, err := json.Marshal(values)
	if err != nil || len(raw) == 0 || len(raw) > maxCapabilityJSON {
		return nil, ErrInvalidSource
	}
	return raw, nil
}

func parseCapabilities(raw []byte) ([]Capability, error) {
	if len(raw) == 0 || len(raw) > maxCapabilityJSON {
		return nil, ErrInvalidSource
	}
	var values []Capability
	if err := strictjson.ValidateExactFields(raw, &values, 8); err != nil {
		return nil, ErrInvalidSource
	}
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, ErrInvalidSource
	}
	for index, value := range values {
		if err := validateCapability(value, true); err != nil || index > 0 && values[index-1].Ref >= value.Ref {
			return nil, ErrInvalidSource
		}
	}
	return values, nil
}

func validateDatabaseShape(database *sql.DB) error {
	var integrity string
	if err := database.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrUnsupportedSchema
	}
	required := map[string]bool{
		"source_catalog": false, "source_catalog_events": false,
		"device_task_bindings": false, "device_task_binding_events": false,
	}
	rows, err := database.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		if _, ok := required[name]; !ok {
			_ = rows.Close()
			return ErrUnsupportedSchema
		}
		required[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, present := range required {
		if !present {
			return ErrUnsupportedSchema
		}
	}
	var unexpected int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')`).Scan(&unexpected); err != nil {
		return err
	}
	if unexpected != 0 {
		return ErrUnsupportedSchema
	}
	for table, expected := range map[string][]catalogSchemaColumn{
		"source_catalog":             sourceCatalogColumns,
		"source_catalog_events":      sourceCatalogEventColumns,
		"device_task_bindings":       deviceTaskBindingColumns,
		"device_task_binding_events": deviceTaskBindingEventColumns,
	} {
		if err := verifyCatalogTable(database, table, expected); err != nil {
			return err
		}
	}
	indices := []catalogSchemaIndex{
		{"source_catalog", "idx_source_catalog_site_alias", 0, []string{"tenant_id", "site_id", "alias", "source_handle"}},
		{"source_catalog_events", "idx_source_catalog_events_source", 0, []string{"tenant_id", "site_id", "source_handle", "sequence"}},
		{"device_task_bindings", "idx_device_task_bindings_site_alias", 0, []string{"tenant_id", "site_id", "alias", "task_handle"}},
		{"device_task_bindings", "idx_device_task_bindings_identity", 1, []string{"tenant_id", "site_id", "device_profile_id", "identity_fingerprint"}},
		{"device_task_binding_events", "idx_device_task_binding_events_task", 0, []string{"tenant_id", "site_id", "task_handle", "sequence"}},
	}
	for _, index := range indices {
		if err := verifyCatalogIndex(database, index); err != nil {
			return err
		}
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND sql IS NOT NULL
        AND name NOT IN ('idx_source_catalog_site_alias','idx_source_catalog_events_source',
                         'idx_device_task_bindings_site_alias','idx_device_task_bindings_identity',
                         'idx_device_task_binding_events_task')`).Scan(&unexpected); err != nil {
		return err
	}
	if unexpected != 0 {
		return ErrUnsupportedSchema
	}
	return nil
}

type catalogSchemaColumn struct {
	name    string
	kind    string
	notNull int
	primary int
}

var sourceCatalogColumns = []catalogSchemaColumn{
	{"tenant_id", "TEXT", 1, 1}, {"site_id", "TEXT", 1, 2}, {"source_handle", "TEXT", 1, 3},
	{"device_profile_id", "TEXT", 1, 0}, {"source_kind", "TEXT", 1, 0}, {"revision", "INTEGER", 1, 0},
	{"identity_fingerprint", "TEXT", 1, 0}, {"native_locator", "TEXT", 1, 0}, {"alias", "TEXT", 1, 0},
	{"zone_id", "TEXT", 1, 0}, {"state", "TEXT", 1, 0}, {"capabilities_json", "BLOB", 1, 0},
	{"created_at", "TEXT", 1, 0}, {"updated_at", "TEXT", 1, 0},
}

var sourceCatalogEventColumns = []catalogSchemaColumn{
	{"sequence", "INTEGER", 0, 1}, {"tenant_id", "TEXT", 1, 0}, {"site_id", "TEXT", 1, 0},
	{"source_handle", "TEXT", 1, 0}, {"event_type", "TEXT", 1, 0}, {"revision", "INTEGER", 1, 0},
	{"state", "TEXT", 1, 0}, {"occurred_at", "TEXT", 1, 0},
}

var deviceTaskBindingColumns = []catalogSchemaColumn{
	{"tenant_id", "TEXT", 1, 1}, {"site_id", "TEXT", 1, 2}, {"task_handle", "TEXT", 1, 3},
	{"device_profile_id", "TEXT", 1, 0}, {"revision", "INTEGER", 1, 0},
	{"identity_fingerprint", "TEXT", 1, 0}, {"native_locator", "TEXT", 1, 0}, {"alias", "TEXT", 1, 0},
	{"source_handles_json", "BLOB", 1, 0}, {"capabilities_json", "BLOB", 1, 0}, {"state", "TEXT", 1, 0},
	{"observed_at", "TEXT", 1, 0}, {"created_at", "TEXT", 1, 0}, {"updated_at", "TEXT", 1, 0},
}

var deviceTaskBindingEventColumns = []catalogSchemaColumn{
	{"sequence", "INTEGER", 0, 1}, {"tenant_id", "TEXT", 1, 0}, {"site_id", "TEXT", 1, 0},
	{"task_handle", "TEXT", 1, 0}, {"event_type", "TEXT", 1, 0}, {"revision", "INTEGER", 1, 0},
	{"state", "TEXT", 1, 0}, {"observed_at", "TEXT", 1, 0}, {"occurred_at", "TEXT", 1, 0},
}

func verifyCatalogTable(database *sql.DB, table string, expected []catalogSchemaColumn) error {
	rows, err := database.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return ErrUnsupportedSchema
	}
	actual := make([]catalogSchemaColumn, 0, len(expected))
	for rows.Next() {
		var cid int
		var column catalogSchemaColumn
		var defaultValue any
		if err := rows.Scan(&cid, &column.name, &column.kind, &column.notNull, &defaultValue, &column.primary); err != nil {
			_ = rows.Close()
			return ErrUnsupportedSchema
		}
		actual = append(actual, column)
	}
	if err := rows.Close(); err != nil || len(actual) != len(expected) {
		return ErrUnsupportedSchema
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return ErrUnsupportedSchema
		}
	}
	return nil
}

type catalogSchemaIndex struct {
	table   string
	name    string
	unique  int
	columns []string
}

func verifyCatalogIndex(database *sql.DB, expected catalogSchemaIndex) error {
	rows, err := database.Query(`PRAGMA index_list(` + expected.table + `)`)
	if err != nil {
		return ErrUnsupportedSchema
	}
	found := false
	for rows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			_ = rows.Close()
			return ErrUnsupportedSchema
		}
		if name == expected.name {
			found = unique == expected.unique && partial == 0 && origin == "c"
		}
	}
	if err := rows.Close(); err != nil || !found {
		return ErrUnsupportedSchema
	}
	rows, err = database.Query(`PRAGMA index_info(` + expected.name + `)`)
	if err != nil {
		return ErrUnsupportedSchema
	}
	columns := make([]string, 0, len(expected.columns))
	for rows.Next() {
		var sequence, columnID int
		var name string
		if err := rows.Scan(&sequence, &columnID, &name); err != nil {
			_ = rows.Close()
			return ErrUnsupportedSchema
		}
		columns = append(columns, name)
	}
	if err := rows.Close(); err != nil || len(columns) != len(expected.columns) {
		return ErrUnsupportedSchema
	}
	for index := range expected.columns {
		if columns[index] != expected.columns[index] {
			return ErrUnsupportedSchema
		}
	}
	return nil
}

func classifyConstraint(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "constraint") {
		return errors.Join(ErrConflict, err)
	}
	return err
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed.UTC(), err
}

func firstError(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func cloneSource(value Source) Source {
	value.Capabilities = append([]Capability(nil), value.Capabilities...)
	for index := range value.Capabilities {
		value.Capabilities[index].Constraints.MediaKinds = append([]MediaKind(nil), value.Capabilities[index].Constraints.MediaKinds...)
	}
	return value
}
