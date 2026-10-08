package store

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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound  = errors.New("inspection record not found")
	ErrConflict  = errors.New("inspection state conflict")
	ErrLeaseLost = errors.New("inspection execution lease is unavailable or expired")
)

var (
	publicRefPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	requestKeyPattern = regexp.MustCompile(`^req_[a-f0-9]{32}$`)
	digestPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	protectedPayload  = regexp.MustCompile(`(?i)(?:https?|rtsps?|data):|"(?:password|token|cookie|authorization|endpoint|deviceId|cameraId|imageBase64|bytes)"\s*:`)
)

type Store struct {
	db *sql.DB
}

const maxStoredCatalogItems = 10_000

const timestampLayout = "2006-01-02T15:04:05.000000000Z07:00"

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "?#\x00") {
		return nil, errors.New("inspection store path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(absolute)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := localstate.PrepareStateRoot(root); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if err := localstate.ValidateStateRoot(root); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing inspection database: %w", err)
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
	db, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL"} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("configure inspection store: %w", err)
		}
	}
	store := &Store{db: db}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		_ = db.Close()
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

func (s *Store) initialize(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master
WHERE name LIKE 'inspection_%' AND type IN ('table','index','trigger','view')`).Scan(&existing); err != nil {
		return fmt.Errorf("inspect existing inspection schema: %w", err)
	}
	if existing == 0 {
		if _, err := tx.ExecContext(ctx, schemaV5); err != nil {
			return fmt.Errorf("create direct-upgrade inspection schema: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO inspection_store_meta(schema, version, schema_sha256, created_at) VALUES(?, ?, ?, ?)`,
			storeSchemaID, schemaVersion, storeSchemaSHA256, formatTime(time.Now().UTC())); err != nil {
			return fmt.Errorf("record direct-upgrade inspection schema: %w", err)
		}
	}
	if err := validateSchemaShapeTx(ctx, tx); err != nil {
		return fmt.Errorf("inspection database is not the exact direct-upgrade schema; explicitly reset only the validated development inspection state: %w", err)
	}
	return tx.Commit()
}

func validateSchemaShapeTx(ctx context.Context, tx *sql.Tx) error {
	expectedObjects, err := exactSchemaObjects()
	if err != nil {
		return err
	}
	objectRows, err := tx.QueryContext(ctx, `SELECT type, name, sql FROM sqlite_master
WHERE name LIKE 'inspection_%' AND type IN ('table','index','trigger','view') AND sql IS NOT NULL
ORDER BY type, name`)
	if err != nil {
		return err
	}
	actualObjects := make(map[string]string, len(expectedObjects))
	for objectRows.Next() {
		var kind, name, statement string
		if err := objectRows.Scan(&kind, &name, &statement); err != nil {
			objectRows.Close()
			return err
		}
		actualObjects[kind+":"+name] = strings.TrimSpace(statement)
	}
	if err := objectRows.Close(); err != nil {
		return err
	}
	if len(actualObjects) != len(expectedObjects) {
		return errors.New("inspection database object set is incomplete or unsupported")
	}
	for key, expected := range expectedObjects {
		if actualObjects[key] != expected {
			return fmt.Errorf("inspection database object %q does not match the exact v2 definition", key)
		}
	}

	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'inspection_%' ORDER BY name`)
	if err != nil {
		return err
	}
	found := make(map[string]struct{}, len(expectedInspectionTables))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		if _, expected := expectedInspectionTables[name]; !expected {
			rows.Close()
			return fmt.Errorf("inspection database contains unsupported table %q; explicitly reset only validated development inspection state", name)
		}
		found[name] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(found) != len(expectedInspectionTables) {
		return errors.New("inspection database table set is incomplete or unsupported")
	}
	for table, expectedColumns := range expectedInspectionTables {
		columnRows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
		if err != nil {
			return err
		}
		actual := make([]string, 0, len(expectedColumns))
		for columnRows.Next() {
			var position, notNull, primaryKey int
			var name, kind string
			var defaultValue any
			if err := columnRows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
				columnRows.Close()
				return err
			}
			actual = append(actual, name)
		}
		if err := columnRows.Close(); err != nil {
			return err
		}
		if len(actual) != len(expectedColumns) {
			return fmt.Errorf("inspection table %q has an unsupported shape", table)
		}
		for index := range actual {
			if actual[index] != expectedColumns[index] {
				return fmt.Errorf("inspection table %q has an unsupported shape", table)
			}
		}
	}
	triggerRows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'inspection_%' ORDER BY name`)
	if err != nil {
		return err
	}
	triggers := make([]string, 0, len(expectedInspectionTriggers))
	for triggerRows.Next() {
		var name string
		if err := triggerRows.Scan(&name); err != nil {
			triggerRows.Close()
			return err
		}
		triggers = append(triggers, name)
	}
	if err := triggerRows.Close(); err != nil {
		return err
	}
	if len(triggers) != len(expectedInspectionTriggers) {
		return errors.New("inspection database trigger set is incomplete or unsupported")
	}
	for index := range triggers {
		if triggers[index] != expectedInspectionTriggers[index] {
			return errors.New("inspection database trigger set is incomplete or unsupported")
		}
	}
	indexRows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master
WHERE type='index' AND name LIKE 'inspection_%' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		return err
	}
	indexes := make([]string, 0, len(expectedInspectionIndexes))
	for indexRows.Next() {
		var name string
		if err := indexRows.Scan(&name); err != nil {
			indexRows.Close()
			return err
		}
		indexes = append(indexes, name)
	}
	if err := indexRows.Close(); err != nil {
		return err
	}
	if len(indexes) != len(expectedInspectionIndexes) {
		return errors.New("inspection database index set is incomplete or unsupported")
	}
	for _, name := range indexes {
		expected, ok := expectedInspectionIndexes[name]
		if !ok {
			return fmt.Errorf("inspection database contains unsupported index %q", name)
		}
		rows, err := tx.QueryContext(ctx, `PRAGMA index_info(`+name+`)`)
		if err != nil {
			return err
		}
		actual := make([]string, 0, len(expected))
		for rows.Next() {
			var sequence, columnID int
			var column string
			if err := rows.Scan(&sequence, &columnID, &column); err != nil {
				rows.Close()
				return err
			}
			actual = append(actual, column)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(actual) != len(expected) {
			return fmt.Errorf("inspection index %q has an unsupported shape", name)
		}
		for index := range expected {
			if actual[index] != expected[index] {
				return fmt.Errorf("inspection index %q has an unsupported shape", name)
			}
		}
	}
	var views int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name LIKE 'inspection_%'`).Scan(&views); err != nil {
		return err
	}
	if views != 0 {
		return errors.New("inspection database contains unsupported views")
	}
	var rowsCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM inspection_store_meta`).Scan(&rowsCount); err != nil {
		return err
	}
	if rowsCount != 1 {
		return errors.New("inspection store metadata must contain exactly one row")
	}
	var schema string
	var version int
	var digest, createdAt string
	if err := tx.QueryRowContext(ctx, `SELECT schema, version, schema_sha256, created_at FROM inspection_store_meta`).
		Scan(&schema, &version, &digest, &createdAt); err != nil {
		return err
	}
	if schema != storeSchemaID || version != schemaVersion || digest != storeSchemaSHA256 {
		return errors.New("inspection store metadata does not identify the exact direct-upgrade schema")
	}
	if _, err := parseTime(createdAt); err != nil {
		return errors.New("inspection store metadata creation time is invalid")
	}
	return nil
}

var (
	referenceSchemaOnce    sync.Once
	referenceSchemaObjects map[string]string
	referenceSchemaErr     error
)

func exactSchemaObjects() (map[string]string, error) {
	referenceSchemaOnce.Do(func() {
		database, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			referenceSchemaErr = err
			return
		}
		defer database.Close()
		if _, err := database.Exec(schemaV5); err != nil {
			referenceSchemaErr = fmt.Errorf("construct inspection v2 schema reference: %w", err)
			return
		}
		rows, err := database.Query(`SELECT type, name, sql FROM sqlite_master
WHERE name LIKE 'inspection_%' AND type IN ('table','index','trigger','view') AND sql IS NOT NULL
ORDER BY type, name`)
		if err != nil {
			referenceSchemaErr = err
			return
		}
		defer rows.Close()
		objects := make(map[string]string)
		for rows.Next() {
			var kind, name, statement string
			if err := rows.Scan(&kind, &name, &statement); err != nil {
				referenceSchemaErr = err
				return
			}
			objects[kind+":"+name] = strings.TrimSpace(statement)
		}
		if err := rows.Err(); err != nil {
			referenceSchemaErr = err
			return
		}
		referenceSchemaObjects = objects
	})
	if referenceSchemaErr != nil {
		return nil, referenceSchemaErr
	}
	return referenceSchemaObjects, nil
}

func (s *Store) SaveInspectionTemplate(ctx context.Context, template inspection.InspectionTemplate) error {
	if err := template.Validate(); err != nil {
		return err
	}
	raw, digest, err := marshalPublic(template)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO inspection_templates(tenant_id, template_id, revision, state, content_sha256, template_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, template_id, revision) DO NOTHING`,
		template.TenantID, template.TemplateID, template.Revision, template.State, digest, string(raw), formatTime(template.CreatedAt))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 1 {
		return nil
	}
	existing, err := s.GetInspectionTemplate(ctx, template.TenantID, template.TemplateID, template.Revision)
	if err != nil {
		return err
	}
	_, existingDigest, err := marshalPublic(existing)
	if err != nil {
		return err
	}
	if existingDigest != digest {
		return ErrConflict
	}
	return nil
}

func (s *Store) GetInspectionTemplate(ctx context.Context, tenantID, templateID string, revision uint64) (inspection.InspectionTemplate, error) {
	var storedTenantID, storedTemplateID, digest, raw string
	var storedRevision uint64
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id, template_id, revision, content_sha256, template_json FROM inspection_templates WHERE tenant_id=? AND template_id=? AND revision=?`, tenantID, templateID, revision).
		Scan(&storedTenantID, &storedTemplateID, &storedRevision, &digest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return inspection.InspectionTemplate{}, ErrNotFound
	}
	if err != nil {
		return inspection.InspectionTemplate{}, err
	}
	return decodeStoredInspectionTemplate(raw, digest, storedTenantID, storedTemplateID, storedRevision, tenantID, templateID, revision)
}

func (s *Store) ListInspectionTemplates(ctx context.Context, tenantID string) ([]inspection.InspectionTemplate, error) {
	if !validRef(tenantID) {
		return nil, errors.New("inspection template tenant is invalid")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id, template_id, revision, content_sha256, template_json FROM inspection_templates WHERE tenant_id=? ORDER BY template_id, revision LIMIT ?`, tenantID, maxStoredCatalogItems+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	templates := make([]inspection.InspectionTemplate, 0)
	publicItems := 0
	for rows.Next() {
		var storedTenantID, templateID, digest, raw string
		var revision uint64
		if err := rows.Scan(&storedTenantID, &templateID, &revision, &digest, &raw); err != nil {
			return nil, err
		}
		template, err := decodeStoredInspectionTemplate(raw, digest, storedTenantID, templateID, revision, tenantID, templateID, revision)
		if err != nil {
			return nil, err
		}
		if publicItems > maxStoredCatalogItems-1-len(template.Criteria) {
			return nil, errors.New("inspection template catalog exceeds its bounded projection")
		}
		publicItems += 1 + len(template.Criteria)
		templates = append(templates, template)
	}
	return templates, rows.Err()
}

func (s *Store) SaveAssignment(ctx context.Context, assignment inspection.Assignment, now time.Time) error {
	if err := assignment.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("inspection assignment save time is required")
	}
	raw, digest, err := marshalPublic(assignment)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO inspection_assignments(tenant_id, assignment_id, revision, template_id, template_revision, site_id, published, content_sha256, assignment_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(tenant_id, assignment_id, revision) DO NOTHING`,
		assignment.TenantID, assignment.AssignmentID, assignment.Revision, assignment.TemplateID, assignment.TemplateRevision,
		assignment.SiteID, assignment.Published, digest, string(raw), formatTime(now))
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 1 {
		return nil
	}
	existing, err := s.GetAssignment(ctx, assignment.TenantID, assignment.AssignmentID, assignment.Revision)
	if err != nil {
		return err
	}
	_, existingDigest, err := marshalPublic(existing)
	if err != nil {
		return err
	}
	if existingDigest != digest {
		return ErrConflict
	}
	return nil
}

func (s *Store) GetAssignment(ctx context.Context, tenantID, assignmentID string, revision uint64) (inspection.Assignment, error) {
	var storedTenantID, storedAssignmentID, templateID, siteID, digest, raw string
	var storedRevision, templateRevision uint64
	var published bool
	err := s.db.QueryRowContext(ctx, `SELECT tenant_id, assignment_id, revision, template_id, template_revision, site_id, published, content_sha256, assignment_json FROM inspection_assignments WHERE tenant_id=? AND assignment_id=? AND revision=?`, tenantID, assignmentID, revision).
		Scan(&storedTenantID, &storedAssignmentID, &storedRevision, &templateID, &templateRevision, &siteID, &published, &digest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return inspection.Assignment{}, ErrNotFound
	}
	if err != nil {
		return inspection.Assignment{}, err
	}
	return decodeStoredAssignment(raw, digest, storedTenantID, storedAssignmentID, storedRevision, templateID, templateRevision, siteID, published, tenantID, assignmentID, revision)
}

// ListAssignments returns the integrity-checked assignment catalog for one
// exact tenant and site. The ordering is part of the contract so request
// planning remains deterministic across process restarts.
func (s *Store) ListAssignments(ctx context.Context, tenantID, siteID string) ([]inspection.Assignment, error) {
	if !validRef(tenantID) || !validRef(siteID) {
		return nil, errors.New("inspection assignment scope is invalid")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT tenant_id, assignment_id, revision, template_id, template_revision, site_id, published, content_sha256, assignment_json FROM inspection_assignments WHERE tenant_id=? AND site_id=? ORDER BY assignment_id, revision LIMIT ?`, tenantID, siteID, maxStoredCatalogItems+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	assignments := make([]inspection.Assignment, 0)
	publicItems := 0
	for rows.Next() {
		var storedTenantID, assignmentID, templateID, storedSiteID, digest, raw string
		var revision, templateRevision uint64
		var published bool
		if err := rows.Scan(&storedTenantID, &assignmentID, &revision, &templateID, &templateRevision, &storedSiteID, &published, &digest, &raw); err != nil {
			return nil, err
		}
		assignment, err := decodeStoredAssignment(raw, digest, storedTenantID, assignmentID, revision, templateID, templateRevision, storedSiteID, published, tenantID, assignmentID, revision)
		if err != nil {
			return nil, err
		}
		items := 1
		for _, target := range assignment.Targets {
			items += 1 + len(target.SourceBindings) + len(target.InstalledTasks) + len(target.CriterionIDs)
			for _, source := range target.SourceBindings {
				items += len(source.CapabilityRefs) + len(source.MediaKinds)
			}
			for _, task := range target.InstalledTasks {
				items += len(task.Sources) + len(task.Capabilities)
				for _, capability := range task.Capabilities {
					items += len(capability.MediaKinds)
				}
			}
		}
		if items > maxStoredCatalogItems || publicItems > maxStoredCatalogItems-items {
			return nil, errors.New("inspection assignment catalog exceeds its bounded projection")
		}
		publicItems += items
		assignments = append(assignments, assignment)
	}
	return assignments, rows.Err()
}

func decodeStoredInspectionTemplate(raw, digest, storedTenantID, storedTemplateID string, storedRevision uint64, tenantID, templateID string, revision uint64) (inspection.InspectionTemplate, error) {
	var template inspection.InspectionTemplate
	if err := json.Unmarshal([]byte(raw), &template); err != nil {
		return inspection.InspectionTemplate{}, fmt.Errorf("decode stored inspection template: %w", err)
	}
	if err := template.Validate(); err != nil {
		return inspection.InspectionTemplate{}, fmt.Errorf("validate stored inspection template: %w", err)
	}
	canonical, computedDigest, err := marshalPublic(template)
	if err != nil {
		return inspection.InspectionTemplate{}, fmt.Errorf("canonicalize stored inspection template: %w", err)
	}
	if digest != computedDigest || raw != string(canonical) ||
		storedTenantID != tenantID || storedTemplateID != templateID || storedRevision != revision ||
		template.TenantID != storedTenantID || template.TemplateID != storedTemplateID || template.Revision != storedRevision {
		return inspection.InspectionTemplate{}, errors.New("stored inspection template failed its integrity binding")
	}
	return template, nil
}

func decodeStoredAssignment(raw, digest, storedTenantID, storedAssignmentID string, storedRevision uint64, templateID string, templateRevision uint64, siteID string, published bool, tenantID, assignmentID string, revision uint64) (inspection.Assignment, error) {
	var assignment inspection.Assignment
	if err := json.Unmarshal([]byte(raw), &assignment); err != nil {
		return inspection.Assignment{}, fmt.Errorf("decode stored inspection assignment: %w", err)
	}
	if err := assignment.Validate(); err != nil {
		return inspection.Assignment{}, fmt.Errorf("validate stored inspection assignment: %w", err)
	}
	canonical, computedDigest, err := marshalPublic(assignment)
	if err != nil {
		return inspection.Assignment{}, fmt.Errorf("canonicalize stored inspection assignment: %w", err)
	}
	if digest != computedDigest || raw != string(canonical) ||
		storedTenantID != tenantID || storedAssignmentID != assignmentID || storedRevision != revision ||
		assignment.TenantID != storedTenantID || assignment.AssignmentID != storedAssignmentID || assignment.Revision != storedRevision ||
		assignment.TemplateID != templateID || assignment.TemplateRevision != templateRevision || assignment.SiteID != siteID || assignment.Published != published {
		return inspection.Assignment{}, errors.New("stored inspection assignment failed its integrity binding")
	}
	return assignment, nil
}

func marshalPublic(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	if protectedPayload.Match(raw) {
		return nil, "", errors.New("inspection persistence payload contains protected device data")
	}
	digest := sha256.Sum256(raw)
	return raw, hex.EncodeToString(digest[:]), nil
}

func formatTime(value time.Time) string {
	// Fixed-width UTC timestamps preserve chronological ordering under SQLite's
	// TEXT comparison, including sub-second lease boundaries.
	return value.UTC().Format(timestampLayout)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse inspection store time: %w", err)
	}
	return parsed.UTC(), nil
}

func validRef(value string) bool {
	return strings.TrimSpace(value) == value && publicRefPattern.MatchString(value)
}

func constraintConflict(err error) error {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "constraint") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}
