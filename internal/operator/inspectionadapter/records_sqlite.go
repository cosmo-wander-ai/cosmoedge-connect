package inspectionadapter

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
	_ "modernc.org/sqlite"
)

const (
	recordDatabaseVersion       = 1
	recordDatabaseApplicationID = 0x43495232 // CIR2: CosmoEdge Inspection Records v2.
	maximumRecordBytes          = 2 << 20

	recordKindResolution  = "resolution"
	recordKindAcquisition = "acquisition"
	recordKindExisting    = "existing"
	recordKindAnalysis    = "analysis"
	recordKindCleanup     = "cleanup"
)

const recordDatabaseSchema = `
CREATE TABLE adapter_records (
    kind TEXT NOT NULL,
    record_key TEXT NOT NULL,
    secondary_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    device_profile_id TEXT NOT NULL,
    state TEXT NOT NULL,
    payload_json BLOB NOT NULL CHECK(length(payload_json) > 0 AND length(payload_json) <= 2097152),
    PRIMARY KEY(kind, record_key),
    UNIQUE(kind, secondary_key)
);
CREATE INDEX idx_adapter_records_profile
    ON adapter_records(device_profile_id, kind, record_key);`

// SQLiteRecords is the deployment-ready durable RecordStore for the live
// adapter. It persists only opaque bindings, hashes, typed results, and media
// descriptors; native locators, endpoints, and credentials never enter it.
type SQLiteRecords struct{ db *sql.DB }

func OpenSQLiteRecords(path string) (*SQLiteRecords, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("inspection adapter record path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(absolute, "?#\x00") {
		return nil, errors.New("inspection adapter record path contains a reserved character")
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing inspection adapter records: %w", err)
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
	closeOnError := func(openErr error) (*SQLiteRecords, error) {
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
			return closeOnError(errors.New("inspection adapter record schema is unsupported"))
		}
	} else if version != recordDatabaseVersion || applicationID != recordDatabaseApplicationID {
		return closeOnError(errors.New("inspection adapter record schema is unsupported"))
	}
	if version == 0 && !created {
		var tables int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&tables); err != nil {
			return closeOnError(err)
		}
		if tables != 0 {
			return closeOnError(errors.New("inspection adapter record schema is unsupported"))
		}
	}
	if version == 0 {
		transaction, err := database.Begin()
		if err != nil {
			return closeOnError(err)
		}
		if _, err := transaction.Exec(recordDatabaseSchema); err != nil {
			_ = transaction.Rollback()
			return closeOnError(err)
		}
		for _, statement := range []string{
			fmt.Sprintf("PRAGMA application_id=%d", recordDatabaseApplicationID),
			fmt.Sprintf("PRAGMA user_version=%d", recordDatabaseVersion),
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
	if err := validateRecordDatabaseShape(database); err != nil {
		return closeOnError(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return closeOnError(err)
	}
	return &SQLiteRecords{db: database}, nil
}

func (s *SQLiteRecords) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func validateRecordDatabaseShape(database *sql.DB) error {
	rows, err := database.Query(`PRAGMA table_info(adapter_records)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns := make(map[string]struct{})
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, name := range []string{"kind", "record_key", "secondary_key", "request_sha256", "device_profile_id", "state", "payload_json"} {
		if _, ok := columns[name]; !ok {
			return errors.New("inspection adapter record table is incomplete")
		}
	}
	return nil
}

func (s *SQLiteRecords) PutResolution(ctx context.Context, record ResolutionRecord) error {
	if err := validateResolutionRecord(record); err != nil {
		return err
	}
	payload, err := encodeRecord(record)
	if err != nil {
		return err
	}
	return s.putExact(ctx, recordKindResolution, record.ResolutionRef, record.ResolutionRef,
		record.RequestSHA256, record.DeviceProfileID, "published", payload)
}

func (s *SQLiteRecords) Resolution(ctx context.Context, ref string) (ResolutionRecord, error) {
	payload, err := s.getPayload(ctx, recordKindResolution, "record_key", ref)
	if err != nil {
		return ResolutionRecord{}, err
	}
	record, err := decodeRecord[ResolutionRecord](payload)
	if err != nil || validateResolutionRecord(record) != nil || record.ResolutionRef != ref {
		return ResolutionRecord{}, errors.New("durable live resolution record is corrupt")
	}
	return record, nil
}

func (s *SQLiteRecords) PutAcquisition(ctx context.Context, record AcquisitionRecord) error {
	if err := validateAcquisitionRecord(record); err != nil {
		return err
	}
	payload, err := encodeRecord(record)
	if err != nil {
		return err
	}
	return s.putExact(ctx, recordKindAcquisition, record.IdempotencyKey, record.Result.Descriptor.MediaRef,
		record.RequestSHA256, record.DeviceProfileID, "published", payload)
}

func (s *SQLiteRecords) Acquisition(ctx context.Context, key string) (AcquisitionRecord, error) {
	return s.acquisitionBy(ctx, "record_key", key)
}

func (s *SQLiteRecords) AcquisitionByMedia(ctx context.Context, mediaRef string) (AcquisitionRecord, error) {
	return s.acquisitionBy(ctx, "secondary_key", mediaRef)
}

func (s *SQLiteRecords) acquisitionBy(ctx context.Context, column, value string) (AcquisitionRecord, error) {
	payload, err := s.getPayload(ctx, recordKindAcquisition, column, value)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	record, err := decodeRecord[AcquisitionRecord](payload)
	if err != nil || validateAcquisitionRecord(record) != nil ||
		column == "record_key" && record.IdempotencyKey != value ||
		column == "secondary_key" && record.Result.Descriptor.MediaRef != value {
		return AcquisitionRecord{}, errors.New("durable live acquisition record is corrupt")
	}
	return record, nil
}

func (s *SQLiteRecords) PutExisting(ctx context.Context, record ExistingRecord) error {
	if err := validateExistingRecord(record); err != nil {
		return err
	}
	payload, err := encodeRecord(record)
	if err != nil {
		return err
	}
	return s.putExact(ctx, recordKindExisting, record.Result.EvidenceRef, record.Result.EvidenceRef,
		record.RequestSHA256, record.DeviceProfileID, "published", payload)
}

func (s *SQLiteRecords) Existing(ctx context.Context, ref string) (ExistingRecord, error) {
	payload, err := s.getPayload(ctx, recordKindExisting, "record_key", ref)
	if err != nil {
		return ExistingRecord{}, err
	}
	record, err := decodeRecord[ExistingRecord](payload)
	if err != nil || validateExistingRecord(record) != nil || record.Result.EvidenceRef != ref {
		return ExistingRecord{}, errors.New("durable live existing evidence record is corrupt")
	}
	return record, nil
}

func (s *SQLiteRecords) PutAnalysis(ctx context.Context, record AnalysisRecord) error {
	if err := validateAnalysisRecord(record); err != nil {
		return err
	}
	payload, err := encodeRecord(record)
	if err != nil {
		return err
	}
	return s.putExact(ctx, recordKindAnalysis, record.Result.ResultRef, record.Result.ResultRef,
		record.RequestSHA256, record.DeviceProfileID, "published", payload)
}

func (s *SQLiteRecords) Analysis(ctx context.Context, ref string) (AnalysisRecord, error) {
	payload, err := s.getPayload(ctx, recordKindAnalysis, "record_key", ref)
	if err != nil {
		return AnalysisRecord{}, err
	}
	record, err := decodeRecord[AnalysisRecord](payload)
	if err != nil || validateAnalysisRecord(record) != nil || record.Result.ResultRef != ref {
		return AnalysisRecord{}, errors.New("durable live analysis record is corrupt")
	}
	return record, nil
}

func (s *SQLiteRecords) ReserveCleanup(ctx context.Context, pending CleanupRecord) (CleanupRecord, bool, error) {
	if err := validateCleanupRecord(pending); err != nil || pending.State != CleanupRecordPending {
		return CleanupRecord{}, false, errors.Join(ErrRecordConflict, err)
	}
	payload, err := encodeRecord(pending)
	if err != nil {
		return CleanupRecord{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CleanupRecord{}, false, err
	}
	defer tx.Rollback()
	var existingPayload []byte
	err = tx.QueryRowContext(ctx, `SELECT payload_json FROM adapter_records WHERE kind=? AND record_key=?`,
		recordKindCleanup, pending.IdempotencyKey).Scan(&existingPayload)
	if err == nil {
		existing, decodeErr := decodeRecord[CleanupRecord](existingPayload)
		if decodeErr != nil || validateCleanupRecord(existing) != nil {
			return CleanupRecord{}, false, errors.New("durable live cleanup record is corrupt")
		}
		if err := tx.Commit(); err != nil {
			return CleanupRecord{}, false, err
		}
		return existing, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CleanupRecord{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO adapter_records(
        kind, record_key, secondary_key, request_sha256, device_profile_id, state, payload_json
    ) VALUES(?, ?, ?, ?, ?, ?, ?)`, recordKindCleanup, pending.IdempotencyKey, pending.IdempotencyKey,
		pending.RequestSHA256, pending.DeviceProfileID, string(pending.State), payload)
	if err != nil {
		return CleanupRecord{}, false, ErrRecordConflict
	}
	if err := tx.Commit(); err != nil {
		return CleanupRecord{}, false, err
	}
	return pending, false, nil
}

func (s *SQLiteRecords) CompleteCleanup(ctx context.Context, completed CleanupRecord) error {
	if err := validateCleanupRecord(completed); err != nil || completed.State != CleanupRecordCompleted {
		return errors.Join(ErrRecordConflict, err)
	}
	payload, err := encodeRecord(completed)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var requestSHA, profileID, state string
	var currentPayload []byte
	err = tx.QueryRowContext(ctx, `SELECT request_sha256, device_profile_id, state, payload_json
        FROM adapter_records WHERE kind=? AND record_key=?`, recordKindCleanup, completed.IdempotencyKey).
		Scan(&requestSHA, &profileID, &state, &currentPayload)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRecordNotFound
	}
	if err != nil {
		return err
	}
	if requestSHA != completed.RequestSHA256 || profileID != completed.DeviceProfileID {
		return ErrRecordConflict
	}
	if state == string(CleanupRecordCompleted) {
		if !bytes.Equal(currentPayload, payload) {
			return ErrRecordConflict
		}
		return tx.Commit()
	}
	if state != string(CleanupRecordPending) {
		return ErrRecordConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE adapter_records SET state=?, payload_json=?
        WHERE kind=? AND record_key=? AND state=?`, string(CleanupRecordCompleted), payload,
		recordKindCleanup, completed.IdempotencyKey, string(CleanupRecordPending))
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return ErrRecordConflict
	}
	return tx.Commit()
}

func (s *SQLiteRecords) Cleanup(ctx context.Context, key string) (CleanupRecord, error) {
	payload, err := s.getPayload(ctx, recordKindCleanup, "record_key", key)
	if err != nil {
		return CleanupRecord{}, err
	}
	record, err := decodeRecord[CleanupRecord](payload)
	if err != nil || validateCleanupRecord(record) != nil || record.IdempotencyKey != key {
		return CleanupRecord{}, errors.New("durable live cleanup record is corrupt")
	}
	return record, nil
}

func (s *SQLiteRecords) putExact(ctx context.Context, kind, key, secondary, requestSHA, profileID, state string, payload []byte) error {
	if s == nil || s.db == nil {
		return ErrRecordNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO adapter_records(
        kind, record_key, secondary_key, request_sha256, device_profile_id, state, payload_json
    ) VALUES(?, ?, ?, ?, ?, ?, ?)`, kind, key, secondary, requestSHA, profileID, state, payload)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	var storedSecondary, storedRequestSHA, storedProfile, storedState string
	var storedPayload []byte
	err = tx.QueryRowContext(ctx, `SELECT secondary_key, request_sha256, device_profile_id, state, payload_json
        FROM adapter_records WHERE kind=? AND record_key=?`, kind, key).
		Scan(&storedSecondary, &storedRequestSHA, &storedProfile, &storedState, &storedPayload)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) && inserted == 0 {
			return ErrRecordConflict
		}
		return err
	}
	if storedSecondary != secondary || storedRequestSHA != requestSHA || storedProfile != profileID ||
		storedState != state || !bytes.Equal(storedPayload, payload) {
		return ErrRecordConflict
	}
	return tx.Commit()
}

func (s *SQLiteRecords) getPayload(ctx context.Context, kind, column, value string) ([]byte, error) {
	if s == nil || s.db == nil {
		return nil, ErrRecordNotFound
	}
	if column != "record_key" && column != "secondary_key" {
		return nil, ErrRecordConflict
	}
	query := `SELECT payload_json FROM adapter_records WHERE kind=? AND ` + column + `=?`
	var payload []byte
	if err := s.db.QueryRowContext(ctx, query, kind, value).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}
	return payload, nil
}

func encodeRecord(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(payload) < 1 || len(payload) > maximumRecordBytes {
		return nil, errors.New("inspection adapter record is outside the bounded size")
	}
	return payload, nil
}

func decodeRecord[T any](payload []byte) (T, error) {
	var result T
	if len(payload) < 1 || len(payload) > maximumRecordBytes {
		return result, errors.New("inspection adapter record is outside the bounded size")
	}
	if err := strictjson.ValidateExactFields(payload, &result, 32); err != nil {
		return result, err
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return result, err
	}
	return result, nil
}

func validateResolutionRecord(record ResolutionRecord) error {
	if !validOpaque(record.ResolutionRef) || !validDigest(record.RequestSHA256) || !validOpaque(record.RunID) ||
		!validOpaque(record.StepID) || record.Attempt < 1 || !validOpaque(record.TenantID) || !validOpaque(record.SiteID) ||
		!validOpaque(record.TargetID) || !validOpaque(record.DeviceProfileID) || !validOpaque(record.AdapterVersion) ||
		record.ResolvedAt.IsZero() || len(record.Sources) == 0 || len(record.Sources) > 16 || len(record.InstalledTasks) > 16 {
		return ErrRecordConflict
	}
	for _, source := range record.Sources {
		if source.Validate() != nil {
			return ErrRecordConflict
		}
	}
	for _, task := range record.InstalledTasks {
		if task.Validate() != nil {
			return ErrRecordConflict
		}
	}
	return nil
}

func validateAcquisitionRecord(record AcquisitionRecord) error {
	if !validOpaque(record.IdempotencyKey) || !validDigest(record.RequestSHA256) || !validOpaque(record.DeviceProfileID) ||
		record.Result.Descriptor.Validate() != nil || !validOpaque(record.Result.AdapterVersion) {
		return ErrRecordConflict
	}
	return nil
}

func validateExistingRecord(record ExistingRecord) error {
	result := record.Result
	if !validDigest(record.RequestSHA256) || !validOpaque(record.DeviceProfileID) || !validOpaque(result.RunID) ||
		!validOpaque(result.StepID) || result.Attempt < 1 || !validOpaque(result.EvidenceRef) || result.Descriptor.Validate() != nil ||
		result.Candidate.Validate() != nil || result.ObservedAt.IsZero() || !validOpaque(result.AdapterVersion) {
		return ErrRecordConflict
	}
	return nil
}

func validateAnalysisRecord(record AnalysisRecord) error {
	result := record.Result
	if !validDigest(record.RequestSHA256) || !validOpaque(record.DeviceProfileID) || !validOpaque(result.RunID) ||
		!validOpaque(result.StepID) || result.Attempt < 1 || !validOpaque(result.ResultRef) || result.Candidate.Validate() != nil ||
		!validOpaque(result.ModelVersion) || !validOpaque(result.AdapterVersion) || result.StartedAt.IsZero() ||
		result.CompletedAt.Before(result.StartedAt) {
		return ErrRecordConflict
	}
	return nil
}

func validateCleanupRecord(record CleanupRecord) error {
	if !validOpaque(record.IdempotencyKey) || !validDigest(record.RequestSHA256) || !validOpaque(record.DeviceProfileID) {
		return ErrRecordConflict
	}
	switch record.State {
	case CleanupRecordPending:
		if record.Result != (inspectionruntime.CleanupResult{}) {
			return ErrRecordConflict
		}
	case CleanupRecordCompleted:
		result := record.Result
		if !validOpaque(result.RunID) || !validOpaque(result.StepID) || result.Attempt < 1 || !validOpaque(result.ResultRef) ||
			result.Created < 0 || result.Removed < 0 || result.Pending < 0 || result.Removed+result.Pending != result.Created {
			return ErrRecordConflict
		}
	default:
		return ErrRecordConflict
	}
	return nil
}
