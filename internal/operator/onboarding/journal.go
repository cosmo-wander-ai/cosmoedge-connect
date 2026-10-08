package onboarding

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
	_ "modernc.org/sqlite"
)

const journalSchemaVersion = 2

const journalSchema = `
CREATE TABLE IF NOT EXISTS onboarding_sagas (
    operation_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK(version >= 1),
	tenant_id TEXT NOT NULL,
	site_id TEXT NOT NULL,
	profile_id TEXT NOT NULL,
	active INTEGER NOT NULL CHECK(active IN (0, 1)),
    record_json BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_onboarding_active_profile
ON onboarding_sagas(tenant_id, site_id, profile_id) WHERE active = 1;`

// protectedSagaDTO is deliberately separate from SagaRecord. credential.Ref
// fails generic serialization; this DTO is the one audited opt-in point that
// may persist ProtectedValue inside the owner-only journal.
type protectedSagaDTO struct {
	Schema                  string                   `json:"schema"`
	Version                 uint64                   `json:"version"`
	OperationID             string                   `json:"operationId"`
	Operation               Operation                `json:"operation"`
	Phase                   Phase                    `json:"phase"`
	TenantID                string                   `json:"tenantId"`
	SiteID                  string                   `json:"siteId"`
	PrincipalSHA256         string                   `json:"principalSha256"`
	ProfileID               string                   `json:"profileId"`
	ExpectedGeneration      uint64                   `json:"expectedGeneration,omitempty"`
	Alias                   string                   `json:"alias,omitempty"`
	Endpoint                string                   `json:"endpoint,omitempty"`
	Username                string                   `json:"username,omitempty"`
	PinnedSerial            string                   `json:"pinnedSerial,omitempty"`
	PinnedType              string                   `json:"pinnedType,omitempty"`
	TransportFingerprint    string                   `json:"transportFingerprint,omitempty"`
	OldCredentialRef        string                   `json:"oldCredentialRef,omitempty"`
	NewCredentialRef        string                   `json:"newCredentialRef,omitempty"`
	CredentialPutID         string                   `json:"credentialPutId,omitempty"`
	CredentialPutPhase      credential.PutPhase      `json:"credentialPutPhase,omitempty"`
	CredentialRotationID    string                   `json:"credentialRotationId,omitempty"`
	CredentialRotationPhase credential.RotationPhase `json:"credentialRotationPhase,omitempty"`
	CreatedAt               time.Time                `json:"createdAt"`
	UpdatedAt               time.Time                `json:"updatedAt"`
}

// Journal is a protected durable saga journal. Its JSON records may contain
// protected connection metadata and opaque credential refs, so the database
// has the same local ownership boundary as the profile store.
type Journal struct {
	db  *sql.DB
	now func() time.Time
}

func OpenJournal(path string) (*Journal, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.Join(ErrInvalidInput, errors.New("onboarding journal path is required"))
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(absolute, "?#\x00") {
		return nil, errors.Join(ErrInvalidInput, errors.New("onboarding journal path contains a reserved character"))
	}
	root := filepath.Dir(absolute)
	if _, err := os.Lstat(root); err == nil {
		if err := localstate.ValidateStateRoot(root); err != nil {
			return nil, fmt.Errorf("reject existing onboarding state root: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("onboarding state root is unavailable")
	} else if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, errors.New("onboarding state root creation failed")
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing onboarding journal: %w", err)
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
	closeOnError := func(openErr error) (*Journal, error) {
		_ = database.Close()
		return nil, openErr
	}
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000",
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
	if version != 0 && version != journalSchemaVersion {
		return closeOnError(ErrInvalidSaga)
	}
	if version == 0 && !created {
		var existingTables int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&existingTables); err != nil {
			return closeOnError(err)
		}
		if existingTables != 0 {
			return closeOnError(ErrInvalidSaga)
		}
	}
	transaction, err := database.Begin()
	if err != nil {
		return closeOnError(err)
	}
	if _, err := transaction.Exec(journalSchema); err != nil {
		_ = transaction.Rollback()
		return closeOnError(err)
	}
	if _, err := transaction.Exec(fmt.Sprintf("PRAGMA user_version=%d", journalSchemaVersion)); err != nil {
		_ = transaction.Rollback()
		return closeOnError(err)
	}
	if err := transaction.Commit(); err != nil {
		return closeOnError(err)
	}
	if err := verifyJournalSchema(database); err != nil {
		return closeOnError(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return closeOnError(err)
	}
	return &Journal{db: database, now: time.Now}, nil
}

type journalColumn struct {
	name    string
	kind    string
	notNull int
	primary int
}

func verifyJournalSchema(database *sql.DB) error {
	rows, err := database.Query(`PRAGMA table_info(onboarding_sagas)`)
	if err != nil {
		return errors.Join(ErrInvalidSaga, err)
	}
	defer rows.Close()
	actual := []journalColumn{}
	for rows.Next() {
		var cid int
		var column journalColumn
		var defaultValue any
		if err := rows.Scan(&cid, &column.name, &column.kind, &column.notNull, &defaultValue, &column.primary); err != nil {
			return errors.Join(ErrInvalidSaga, err)
		}
		actual = append(actual, column)
	}
	if err := rows.Err(); err != nil {
		return errors.Join(ErrInvalidSaga, err)
	}
	expected := []journalColumn{
		{name: "operation_id", kind: "TEXT", notNull: 0, primary: 1},
		{name: "version", kind: "INTEGER", notNull: 1, primary: 0},
		{name: "tenant_id", kind: "TEXT", notNull: 1, primary: 0},
		{name: "site_id", kind: "TEXT", notNull: 1, primary: 0},
		{name: "profile_id", kind: "TEXT", notNull: 1, primary: 0},
		{name: "active", kind: "INTEGER", notNull: 1, primary: 0},
		{name: "record_json", kind: "BLOB", notNull: 1, primary: 0},
	}
	if len(actual) != len(expected) {
		return ErrInvalidSaga
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return ErrInvalidSaga
		}
	}
	var unexpected int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE (type='table' AND name NOT IN ('onboarding_sagas')) OR type IN ('trigger','view') OR
		(type='index' AND name NOT LIKE 'sqlite_autoindex_%' AND name != 'uq_onboarding_active_profile')`).Scan(&unexpected); err != nil {
		return errors.Join(ErrInvalidSaga, err)
	}
	if unexpected != 0 {
		return ErrInvalidSaga
	}
	return verifyActiveProfileIndex(database)
}

func verifyActiveProfileIndex(database *sql.DB) error {
	rows, err := database.Query(`PRAGMA index_list(onboarding_sagas)`)
	if err != nil {
		return errors.Join(ErrInvalidSaga, err)
	}
	found := false
	for rows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			_ = rows.Close()
			return errors.Join(ErrInvalidSaga, err)
		}
		if name == "uq_onboarding_active_profile" {
			found = unique == 1 && partial == 1 && origin == "c"
		}
	}
	if err := rows.Close(); err != nil || !found {
		return ErrInvalidSaga
	}
	rows, err = database.Query(`PRAGMA index_info(uq_onboarding_active_profile)`)
	if err != nil {
		return errors.Join(ErrInvalidSaga, err)
	}
	columns := []string{}
	for rows.Next() {
		var sequence, columnID int
		var name string
		if err := rows.Scan(&sequence, &columnID, &name); err != nil {
			_ = rows.Close()
			return errors.Join(ErrInvalidSaga, err)
		}
		columns = append(columns, name)
	}
	if err := rows.Close(); err != nil || len(columns) != 3 || columns[0] != "tenant_id" || columns[1] != "site_id" || columns[2] != "profile_id" {
		return ErrInvalidSaga
	}
	return nil
}

func (j *Journal) Close() error {
	if j == nil || j.db == nil {
		return nil
	}
	return j.db.Close()
}

func (j *Journal) Begin(ctx context.Context, record SagaRecord) (SagaRecord, error) {
	if record.Version != 0 {
		return SagaRecord{}, ErrInvalidSaga
	}
	now := j.now().UTC()
	record.Version = 1
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	if err := record.Validate(); err != nil {
		return SagaRecord{}, err
	}
	raw, err := encodeSagaRecord(record)
	if err != nil {
		return SagaRecord{}, err
	}
	if _, err := j.db.ExecContext(ctx, `INSERT INTO onboarding_sagas(operation_id, version, tenant_id, site_id, profile_id, active, record_json) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		record.OperationID, record.Version, record.TenantID, record.SiteID, record.ProfileID, sagaActive(record.Phase), raw); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "constraint") {
			var existing int
			if lookupErr := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM onboarding_sagas WHERE operation_id=?`, record.OperationID).Scan(&existing); lookupErr != nil {
				return SagaRecord{}, errors.Join(ErrOperationConflict, err, lookupErr)
			}
			if existing == 1 {
				return SagaRecord{}, errors.Join(ErrSagaConflict, err)
			}
			return SagaRecord{}, errors.Join(ErrOperationConflict, err)
		}
		return SagaRecord{}, err
	}
	return record, nil
}

func (j *Journal) Get(ctx context.Context, operationID string) (SagaRecord, error) {
	if !operationIDPattern.MatchString(operationID) {
		return SagaRecord{}, ErrInvalidSaga
	}
	var raw []byte
	var tenantID, siteID, profileID string
	var active int
	if err := j.db.QueryRowContext(ctx, `SELECT tenant_id, site_id, profile_id, active, record_json FROM onboarding_sagas WHERE operation_id=?`, operationID).
		Scan(&tenantID, &siteID, &profileID, &active, &raw); errors.Is(err, sql.ErrNoRows) {
		return SagaRecord{}, ErrSagaNotFound
	} else if err != nil {
		return SagaRecord{}, err
	}
	record, err := decodeSagaRecord(raw)
	if err != nil {
		return SagaRecord{}, err
	}
	if err := record.Validate(); err != nil {
		return SagaRecord{}, err
	}
	if record.TenantID != tenantID || record.SiteID != siteID || record.ProfileID != profileID || sagaActive(record.Phase) != active {
		return SagaRecord{}, ErrInvalidSaga
	}
	return record, nil
}

func (j *Journal) Save(ctx context.Context, record SagaRecord) (SagaRecord, error) {
	if record.Version == 0 {
		return SagaRecord{}, ErrInvalidSaga
	}
	previousVersion := record.Version
	record.Version++
	record.UpdatedAt = j.now().UTC()
	if err := record.Validate(); err != nil {
		return SagaRecord{}, err
	}
	raw, err := encodeSagaRecord(record)
	if err != nil {
		return SagaRecord{}, err
	}
	result, err := j.db.ExecContext(ctx, `UPDATE onboarding_sagas SET version=?, active=?, record_json=?
		WHERE operation_id=? AND version=? AND tenant_id=? AND site_id=? AND profile_id=?`,
		record.Version, sagaActive(record.Phase), raw, record.OperationID, previousVersion, record.TenantID, record.SiteID, record.ProfileID)
	if err != nil {
		return SagaRecord{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return SagaRecord{}, ErrSagaConflict
	}
	return record, nil
}

// MemoryJournal is a deterministic ephemeral journal for tests. It is not a
// durable fallback for production onboarding.
type MemoryJournal struct {
	mu      sync.Mutex
	now     func() time.Time
	records map[string]SagaRecord
}

func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{now: time.Now, records: make(map[string]SagaRecord)}
}

func (j *MemoryJournal) Begin(ctx context.Context, record SagaRecord) (SagaRecord, error) {
	if err := contextErr(ctx); err != nil {
		return SagaRecord{}, err
	}
	if record.Version != 0 {
		return SagaRecord{}, ErrInvalidSaga
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, exists := j.records[record.OperationID]; exists {
		return SagaRecord{}, ErrSagaConflict
	}
	for _, existing := range j.records {
		if sagaActive(existing.Phase) == 1 && existing.TenantID == record.TenantID && existing.SiteID == record.SiteID && existing.ProfileID == record.ProfileID {
			return SagaRecord{}, ErrOperationConflict
		}
	}
	now := j.now().UTC()
	record.Version = 1
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	if err := record.Validate(); err != nil {
		return SagaRecord{}, err
	}
	j.records[record.OperationID] = record
	return record, nil
}

func (j *MemoryJournal) Get(ctx context.Context, operationID string) (SagaRecord, error) {
	if err := contextErr(ctx); err != nil {
		return SagaRecord{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	record, exists := j.records[operationID]
	if !exists {
		return SagaRecord{}, ErrSagaNotFound
	}
	return record, nil
}

func (j *MemoryJournal) Save(ctx context.Context, record SagaRecord) (SagaRecord, error) {
	if err := contextErr(ctx); err != nil {
		return SagaRecord{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	current, exists := j.records[record.OperationID]
	if !exists {
		return SagaRecord{}, ErrSagaNotFound
	}
	if current.Version != record.Version {
		return SagaRecord{}, ErrSagaConflict
	}
	record.Version++
	record.UpdatedAt = j.now().UTC()
	if err := record.Validate(); err != nil {
		return SagaRecord{}, err
	}
	j.records[record.OperationID] = record
	return record, nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func sagaActive(phase Phase) int {
	if phase == PhaseCompleted || phase == PhaseFailed {
		return 0
	}
	return 1
}

func encodeSagaRecord(record SagaRecord) ([]byte, error) {
	dto := protectedSagaDTO{
		Schema: record.Schema, Version: record.Version, OperationID: record.OperationID,
		Operation: record.Operation, Phase: record.Phase, TenantID: record.TenantID, SiteID: record.SiteID,
		PrincipalSHA256: record.PrincipalSHA256, ProfileID: record.ProfileID, ExpectedGeneration: record.ExpectedGeneration,
		Alias: record.Alias, Endpoint: record.Endpoint, Username: record.Username,
		PinnedSerial: record.PinnedSerial, PinnedType: record.PinnedType, TransportFingerprint: record.TransportFingerprint,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
	if record.OldCredentialRef != "" {
		dto.OldCredentialRef = record.OldCredentialRef.ProtectedValue()
	}
	if record.NewCredentialRef != "" {
		dto.NewCredentialRef = record.NewCredentialRef.ProtectedValue()
	}
	if record.CredentialPutID != "" {
		dto.CredentialPutID = record.CredentialPutID.ProtectedValue()
		dto.CredentialPutPhase = record.CredentialPutPhase
	}
	if record.CredentialRotationID != "" {
		dto.CredentialRotationID = record.CredentialRotationID.ProtectedValue()
		dto.CredentialRotationPhase = record.CredentialRotationPhase
	}
	return json.Marshal(dto)
}

func decodeSagaRecord(raw []byte) (SagaRecord, error) {
	var dto protectedSagaDTO
	if err := strictjson.ValidateExactFields(raw, &dto, 4); err != nil {
		return SagaRecord{}, ErrInvalidSaga
	}
	if err := json.Unmarshal(raw, &dto); err != nil {
		return SagaRecord{}, ErrInvalidSaga
	}
	record := SagaRecord{
		Schema: dto.Schema, Version: dto.Version, OperationID: dto.OperationID,
		Operation: dto.Operation, Phase: dto.Phase, TenantID: dto.TenantID, SiteID: dto.SiteID,
		PrincipalSHA256: dto.PrincipalSHA256, ProfileID: dto.ProfileID, ExpectedGeneration: dto.ExpectedGeneration,
		Alias: dto.Alias, Endpoint: dto.Endpoint, Username: dto.Username,
		PinnedSerial: dto.PinnedSerial, PinnedType: dto.PinnedType, TransportFingerprint: dto.TransportFingerprint,
		CreatedAt: dto.CreatedAt, UpdatedAt: dto.UpdatedAt,
	}
	var err error
	if dto.OldCredentialRef != "" {
		record.OldCredentialRef, err = credential.ParseRef(dto.OldCredentialRef)
		if err != nil {
			return SagaRecord{}, ErrInvalidSaga
		}
	}
	if dto.NewCredentialRef != "" {
		record.NewCredentialRef, err = credential.ParseRef(dto.NewCredentialRef)
		if err != nil {
			return SagaRecord{}, ErrInvalidSaga
		}
	}
	if dto.CredentialPutID != "" {
		record.CredentialPutID, err = credential.ParsePutOperationID(dto.CredentialPutID)
		if err != nil {
			return SagaRecord{}, ErrInvalidSaga
		}
		record.CredentialPutPhase = dto.CredentialPutPhase
	}
	if dto.CredentialRotationID != "" {
		record.CredentialRotationID, err = credential.ParseRotationID(dto.CredentialRotationID)
		if err != nil {
			return SagaRecord{}, ErrInvalidSaga
		}
		record.CredentialRotationPhase = dto.CredentialRotationPhase
	}
	return record, nil
}

var _ SagaJournal = (*Journal)(nil)
var _ SagaJournal = (*MemoryJournal)(nil)
