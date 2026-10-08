package mediaprep

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

const (
	databaseVersion       = 2
	databaseApplicationID = 0x434D5032 // CMP2
	timestampLayout       = "2006-01-02T15:04:05.000000000Z"
)

const createPreparationsSQL = `CREATE TABLE temporary_media_preparations (
    preparation_ref TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    capability_ref TEXT NOT NULL,
    audience_binding_ref TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    audience_sha256 TEXT NOT NULL,
    evidence_expires_at TEXT NOT NULL,
    request_json BLOB NOT NULL,
    request_sha256 TEXT NOT NULL,
    operation_key TEXT NOT NULL UNIQUE,
    media_put_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('prepared','acquiring_unknown','publication_unknown','ready','failed')),
    content_sha256 TEXT NOT NULL,
    content_metadata_json BLOB NOT NULL,
    media_ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 0),
    reconciliation_attempts INTEGER NOT NULL CHECK(reconciliation_attempts >= 0),
    publication_attempts INTEGER NOT NULL CHECK(publication_attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    UNIQUE(tenant_id, site_id, request_id)
);`

const createClaimIndexSQL = `CREATE INDEX temporary_media_preparations_claim_idx
ON temporary_media_preparations(state, available_at, lease_owner, evidence_expires_at, preparation_ref);`

const preparationColumns = `preparation_ref,tenant_id,site_id,request_id,source_ref,capability_ref,audience_binding_ref,window_start,window_end,
audience_sha256,evidence_expires_at,request_json,request_sha256,operation_key,media_put_key,state,content_sha256,
content_metadata_json,media_ref,reason,generation,reconciliation_attempts,publication_attempts,available_at,lease_owner,lease_expires_at,created_at,updated_at,record_sha256`

type sqliteStore struct {
	db *sql.DB
}

type storedRecord struct {
	PreparationRef         string
	Request                persistedRequest
	RequestRaw             string
	RequestSHA256          string
	OperationKey           string
	MediaPutKey            string
	State                  State
	ContentSHA256          string
	ActualMedia            persistedActualMedia
	ActualMediaRaw         string
	MediaRef               string
	Reason                 Reason
	Generation             int
	ReconciliationAttempts int
	PublicationAttempts    int
	AvailableAt            time.Time
	LeaseOwner             string
	LeaseExpiresAt         time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
	RecordSHA256           string
}

type claimKind uint8

const (
	claimAcquire claimKind = iota + 1
	claimReconcile
	claimPublication
)

type workClaim struct {
	Record         storedRecord
	Kind           claimKind
	Owner          string
	Generation     int
	StartedAt      time.Time
	LeaseExpiresAt time.Time
}

func openSQLite(path string) (*sqliteStore, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00?#") {
		return nil, ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalid
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, errors.Join(ErrIncompatibleStore, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
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
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		if created {
			_ = os.Remove(absolute)
		}
		return nil, err
	}
	database.SetMaxOpenConns(1)
	fail := func(openErr error) (*sqliteStore, error) {
		_ = database.Close()
		if created {
			_ = os.Remove(absolute)
		}
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
	var version, applicationID, objectCount int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fail(err)
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return fail(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&objectCount); err != nil {
		return fail(err)
	}
	if version == 0 {
		if !created || applicationID != 0 || objectCount != 0 {
			return fail(ErrIncompatibleStore)
		}
		tx, err := database.Begin()
		if err != nil {
			return fail(err)
		}
		if _, err := tx.Exec(createPreparationsSQL + "\n" + createClaimIndexSQL); err != nil {
			_ = tx.Rollback()
			return fail(err)
		}
		for _, statement := range []string{
			fmt.Sprintf("PRAGMA application_id=%d", databaseApplicationID),
			fmt.Sprintf("PRAGMA user_version=%d", databaseVersion),
		} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fail(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != databaseVersion || applicationID != databaseApplicationID {
		return fail(ErrIncompatibleStore)
	}
	store := &sqliteStore{db: database}
	if err := store.validateShape(); err != nil {
		return fail(err)
	}
	if err := store.validateContent(context.Background()); err != nil {
		return fail(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return fail(err)
	}
	return store, nil
}

func (s *sqliteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *sqliteStore) validateShape() error {
	expected := map[string]string{
		"temporary_media_preparations":           createPreparationsSQL,
		"temporary_media_preparations_claim_idx": createClaimIndexSQL,
	}
	rows, err := s.db.Query(`SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name`)
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
		return ErrIncompatibleStore
	}
	for name, statement := range expected {
		if normalizeSQL(actual[name]) != normalizeSQL(statement) {
			return ErrIncompatibleStore
		}
	}
	return nil
}

func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ";"))), " ")
}

func (s *sqliteStore) validateContent(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT `+preparationColumns+` FROM temporary_media_preparations ORDER BY preparation_ref`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if _, err := scanStoredRecord(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *sqliteStore) prepare(ctx context.Context, request FrozenRequest, now time.Time) (storedRecord, bool, error) {
	value, requestDigest, operationKey, putKey, err := canonicalRequest(request)
	if err != nil || now.IsZero() {
		return storedRecord{}, false, ErrInvalid
	}
	now = now.UTC()
	raw, computedDigest, err := marshalPersistedRequest(value)
	if err != nil || computedDigest != requestDigest {
		return storedRecord{}, false, ErrInvalid
	}
	preparationRef, err := PreparationRefForScope(value.TenantID, value.SiteID, value.RequestID)
	if err != nil {
		return storedRecord{}, false, err
	}
	if existing, existingErr := s.getByScope(ctx, value.TenantID, value.SiteID, value.RequestID); existingErr == nil {
		if existing.PreparationRef != preparationRef || existing.RequestSHA256 != requestDigest ||
			existing.OperationKey != operationKey || existing.MediaPutKey != putKey || existing.RequestRaw != raw {
			return storedRecord{}, false, ErrConflict
		}
		return existing, false, nil
	} else if !errors.Is(existingErr, ErrNotFound) {
		return storedRecord{}, false, existingErr
	}
	if !value.EvidenceExpiresAt.After(now) || value.EvidenceExpiresAt.Sub(now) > maximumEvidenceTTL {
		return storedRecord{}, false, ErrInvalid
	}
	record := storedRecord{
		PreparationRef: preparationRef, Request: value, RequestRaw: raw, RequestSHA256: requestDigest,
		OperationKey: operationKey, MediaPutKey: putKey, State: StatePrepared, Reason: ReasonPrepared,
		AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	record.RecordSHA256 = digestRecord(record)
	result, err := s.db.ExecContext(ctx, `INSERT INTO temporary_media_preparations(`+preparationColumns+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,site_id,request_id) DO NOTHING`,
		recordSQLValues(record)...)
	if err != nil {
		return storedRecord{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return storedRecord{}, false, err
	}
	stored, err := s.getByScope(ctx, value.TenantID, value.SiteID, value.RequestID)
	if err != nil {
		return storedRecord{}, false, err
	}
	if stored.PreparationRef != preparationRef || stored.RequestSHA256 != requestDigest ||
		stored.OperationKey != operationKey || stored.MediaPutKey != putKey || stored.RequestRaw != raw {
		return storedRecord{}, false, ErrConflict
	}
	return stored, rows == 1, nil
}

func (s *sqliteStore) getByScope(ctx context.Context, tenantID, siteID, requestID string) (storedRecord, error) {
	if s == nil || !validRef(tenantID) || !validRef(siteID) || !validRef(requestID) {
		return storedRecord{}, ErrNotFound
	}
	record, err := scanStoredRecord(s.db.QueryRowContext(ctx, `SELECT `+preparationColumns+` FROM temporary_media_preparations WHERE tenant_id=? AND site_id=? AND request_id=?`, tenantID, siteID, requestID))
	if errors.Is(err, sql.ErrNoRows) {
		return storedRecord{}, ErrNotFound
	}
	return record, err
}

func (s *sqliteStore) get(ctx context.Context, preparationRef string) (storedRecord, error) {
	if s == nil || !preparationPattern.MatchString(preparationRef) {
		return storedRecord{}, ErrNotFound
	}
	record, err := scanStoredRecord(s.db.QueryRowContext(ctx, `SELECT `+preparationColumns+` FROM temporary_media_preparations WHERE preparation_ref=?`, preparationRef))
	if errors.Is(err, sql.ErrNoRows) {
		return storedRecord{}, ErrNotFound
	}
	return record, err
}

func (s *sqliteStore) claim(ctx context.Context, owner string, now time.Time, leaseTTL time.Duration) (workClaim, bool, error) {
	if s == nil || !validRef(owner) || now.IsZero() || leaseTTL <= 0 {
		return workClaim{}, false, ErrInvalid
	}
	now = now.UTC()
	for attempts := 0; attempts < 32; attempts++ {
		record, err := scanStoredRecord(s.db.QueryRowContext(ctx, `SELECT `+preparationColumns+` FROM temporary_media_preparations
WHERE state IN (?,?,?) AND lease_owner='' AND available_at<=? ORDER BY available_at,preparation_ref LIMIT 1`,
			StatePrepared, StateAcquiringUnknown, StatePublicationUnknown, formatTime(now)))
		if errors.Is(err, sql.ErrNoRows) {
			return workClaim{}, false, nil
		}
		if err != nil {
			return workClaim{}, false, err
		}
		previousRecordSHA := record.RecordSHA256
		if !record.Request.EvidenceExpiresAt.After(now) {
			record.State, record.Reason = StateFailed, ReasonEvidenceExpired
			record.Generation++
			record.AvailableAt, record.UpdatedAt = now, now
			record.LeaseOwner, record.LeaseExpiresAt = "", time.Time{}
			if changed, err := s.casUpdate(ctx, &record, record.Generation-1, "", time.Time{}, previousRecordSHA); err != nil {
				return workClaim{}, false, err
			} else if !changed {
				continue
			}
			continue
		}
		kind := claimAcquire
		previousGeneration := record.Generation
		switch record.State {
		case StateAcquiringUnknown:
			kind = claimReconcile
			record.ReconciliationAttempts++
			record.Reason = ReasonReconciliationStarted
		case StatePublicationUnknown:
			kind = claimPublication
			record.PublicationAttempts++
			record.Reason = ReasonPublicationProbeStarted
		case StatePrepared:
			record.State = StateAcquiringUnknown
			record.Reason = ReasonAcquisitionStarted
		default:
			return workClaim{}, false, ErrCorruptStore
		}
		record.Generation++
		record.LeaseOwner = owner
		record.LeaseExpiresAt = now.Add(leaseTTL)
		if record.Request.EvidenceExpiresAt.Before(record.LeaseExpiresAt) {
			record.LeaseExpiresAt = record.Request.EvidenceExpiresAt
		}
		record.AvailableAt, record.UpdatedAt = now, now
		changed, err := s.casUpdate(ctx, &record, previousGeneration, "", time.Time{}, previousRecordSHA)
		if err != nil {
			return workClaim{}, false, err
		}
		if !changed {
			continue
		}
		return workClaim{Record: record, Kind: kind, Owner: owner, Generation: record.Generation,
			StartedAt: now, LeaseExpiresAt: record.LeaseExpiresAt}, true, nil
	}
	return workClaim{}, false, ErrLeaseLost
}

func (s *sqliteStore) bindContent(ctx context.Context, claim workClaim, contentSHA string, actual persistedActualMedia, actualRaw string, now time.Time, leaseTTL time.Duration) (workClaim, error) {
	if (claim.Kind != claimAcquire && claim.Kind != claimReconcile) || !digestPattern.MatchString(contentSHA) ||
		actualRaw == "" || now.IsZero() || leaseTTL <= 0 {
		return workClaim{}, ErrInvalid
	}
	if !now.UTC().Before(claim.LeaseExpiresAt) {
		return workClaim{}, ErrLeaseLost
	}
	record, err := s.get(ctx, claim.Record.PreparationRef)
	if err != nil {
		return workClaim{}, err
	}
	if !claimMatches(record, claim) {
		return workClaim{}, ErrLeaseLost
	}
	canonical, raw, err := canonicalActualMedia(record.Request, actual.Encoding, actual.Temporal, now)
	if err != nil || raw != actualRaw {
		return workClaim{}, ErrInvalid
	}
	if record.ContentSHA256 != "" && (record.ContentSHA256 != contentSHA || record.ActualMediaRaw != actualRaw) {
		return workClaim{}, ErrConflict
	}
	previousExpiry := record.LeaseExpiresAt
	previousRecordSHA := record.RecordSHA256
	record.ContentSHA256 = contentSHA
	record.ActualMedia, record.ActualMediaRaw = canonical, actualRaw
	record.State = StatePublicationUnknown
	record.Reason = ReasonPublicationStarted
	record.PublicationAttempts++
	record.LeaseExpiresAt = now.UTC().Add(leaseTTL)
	if record.Request.EvidenceExpiresAt.Before(record.LeaseExpiresAt) {
		record.LeaseExpiresAt = record.Request.EvidenceExpiresAt
	}
	if !record.LeaseExpiresAt.After(now.UTC()) {
		return workClaim{}, ErrLeaseLost
	}
	record.UpdatedAt = now.UTC()
	changed, err := s.casUpdate(ctx, &record, record.Generation, claim.Owner, previousExpiry, previousRecordSHA)
	if err != nil {
		return workClaim{}, err
	}
	if !changed {
		return workClaim{}, ErrLeaseLost
	}
	claim.Record = record
	claim.Kind = claimPublication
	claim.LeaseExpiresAt = record.LeaseExpiresAt
	return claim, nil
}

func (s *sqliteStore) markPublicationReconciliation(ctx context.Context, claim workClaim, now time.Time, leaseTTL time.Duration) (workClaim, error) {
	if claim.Kind != claimPublication || now.IsZero() || leaseTTL <= 0 || !now.UTC().Before(claim.LeaseExpiresAt) {
		return workClaim{}, ErrLeaseLost
	}
	record, err := s.get(ctx, claim.Record.PreparationRef)
	if err != nil {
		return workClaim{}, err
	}
	if !claimMatches(record, claim) {
		return workClaim{}, ErrLeaseLost
	}
	previousExpiry := record.LeaseExpiresAt
	previousRecordSHA := record.RecordSHA256
	record.ReconciliationAttempts++
	record.Reason = ReasonPublicationReconciliationStarted
	record.LeaseExpiresAt = now.UTC().Add(leaseTTL)
	if record.Request.EvidenceExpiresAt.Before(record.LeaseExpiresAt) {
		record.LeaseExpiresAt = record.Request.EvidenceExpiresAt
	}
	if !record.LeaseExpiresAt.After(now.UTC()) {
		return workClaim{}, ErrLeaseLost
	}
	record.UpdatedAt = now.UTC()
	changed, err := s.casUpdate(ctx, &record, record.Generation, claim.Owner, previousExpiry, previousRecordSHA)
	if err != nil {
		return workClaim{}, err
	}
	if !changed {
		return workClaim{}, ErrLeaseLost
	}
	claim.Record = record
	claim.LeaseExpiresAt = record.LeaseExpiresAt
	return claim, nil
}

func (s *sqliteStore) markPublicationStarted(ctx context.Context, claim workClaim, contentSHA string, now time.Time, leaseTTL time.Duration) (workClaim, error) {
	if claim.Kind != claimPublication || !digestPattern.MatchString(contentSHA) || now.IsZero() || leaseTTL <= 0 || !now.UTC().Before(claim.LeaseExpiresAt) {
		return workClaim{}, ErrLeaseLost
	}
	record, err := s.get(ctx, claim.Record.PreparationRef)
	if err != nil {
		return workClaim{}, err
	}
	if !claimMatches(record, claim) || record.ContentSHA256 != contentSHA {
		return workClaim{}, ErrLeaseLost
	}
	previousExpiry := record.LeaseExpiresAt
	previousRecordSHA := record.RecordSHA256
	record.Reason = ReasonPublicationStarted
	record.LeaseExpiresAt = now.UTC().Add(leaseTTL)
	if record.Request.EvidenceExpiresAt.Before(record.LeaseExpiresAt) {
		record.LeaseExpiresAt = record.Request.EvidenceExpiresAt
	}
	if !record.LeaseExpiresAt.After(now.UTC()) {
		return workClaim{}, ErrLeaseLost
	}
	record.UpdatedAt = now.UTC()
	changed, err := s.casUpdate(ctx, &record, record.Generation, claim.Owner, previousExpiry, previousRecordSHA)
	if err != nil {
		return workClaim{}, err
	}
	if !changed {
		return workClaim{}, ErrLeaseLost
	}
	claim.Record = record
	claim.LeaseExpiresAt = record.LeaseExpiresAt
	return claim, nil
}

func (s *sqliteStore) completeUnknown(ctx context.Context, claim workClaim, reason Reason, at time.Time, backoff time.Duration, contentSHA string) (storedRecord, error) {
	if reason != ReasonAcquisitionPending && reason != ReasonAcquisitionUnknown && reason != ReasonReconciliationPending &&
		reason != ReasonReconciliationUnknown || at.IsZero() || backoff <= 0 || contentSHA != "" {
		return storedRecord{}, ErrInvalid
	}
	return s.finishClaim(ctx, claim, at.UTC(), func(record *storedRecord) error {
		record.State, record.Reason = StateAcquiringUnknown, reason
		record.ContentSHA256 = contentSHA
		record.ActualMedia, record.ActualMediaRaw = persistedActualMedia{}, ""
		record.AvailableAt = at.UTC().Add(backoff)
		return nil
	})
}

func (s *sqliteStore) completePublicationUnknown(ctx context.Context, claim workClaim, at time.Time, backoff time.Duration) (storedRecord, error) {
	if claim.Kind != claimPublication || at.IsZero() || backoff <= 0 {
		return storedRecord{}, ErrInvalid
	}
	return s.finishClaim(ctx, claim, at.UTC(), func(record *storedRecord) error {
		if !digestPattern.MatchString(record.ContentSHA256) {
			return ErrCorruptStore
		}
		if record.ActualMediaRaw == "" {
			return ErrCorruptStore
		}
		record.State, record.Reason = StatePublicationUnknown, ReasonPublicationUnknown
		record.AvailableAt = at.UTC().Add(backoff)
		return nil
	})
}

func (s *sqliteStore) completeFailed(ctx context.Context, claim workClaim, reason Reason, at time.Time, contentSHA string) (storedRecord, error) {
	if reason != ReasonAcquisitionFailed && reason != ReasonContentInvalid && reason != ReasonPublicationRejected ||
		at.IsZero() || contentSHA != "" && !digestPattern.MatchString(contentSHA) {
		return storedRecord{}, ErrInvalid
	}
	return s.finishClaim(ctx, claim, at.UTC(), func(record *storedRecord) error {
		record.State, record.Reason = StateFailed, reason
		record.ContentSHA256 = contentSHA
		if contentSHA == "" {
			record.ActualMedia, record.ActualMediaRaw = persistedActualMedia{}, ""
		}
		record.AvailableAt = at.UTC()
		return nil
	})
}

func (s *sqliteStore) completeReady(ctx context.Context, claim workClaim, mediaRef, contentSHA string, at time.Time) (storedRecord, error) {
	if !mediaRefPattern.MatchString(mediaRef) || !digestPattern.MatchString(contentSHA) || at.IsZero() {
		return storedRecord{}, ErrInvalid
	}
	return s.finishClaim(ctx, claim, at.UTC(), func(record *storedRecord) error {
		record.State, record.Reason = StateReady, ReasonReady
		record.MediaRef, record.ContentSHA256 = mediaRef, contentSHA
		record.AvailableAt = at.UTC()
		return nil
	})
}

func (s *sqliteStore) finishClaim(ctx context.Context, claim workClaim, at time.Time, mutate func(*storedRecord) error) (storedRecord, error) {
	record, err := s.get(ctx, claim.Record.PreparationRef)
	if err != nil {
		return storedRecord{}, err
	}
	if !claimMatches(record, claim) || !at.Before(record.LeaseExpiresAt) || at.Before(record.UpdatedAt) {
		return storedRecord{}, ErrLeaseLost
	}
	previousExpiry := record.LeaseExpiresAt
	previousRecordSHA := record.RecordSHA256
	if err := mutate(&record); err != nil {
		return storedRecord{}, err
	}
	record.LeaseOwner, record.LeaseExpiresAt, record.UpdatedAt = "", time.Time{}, at
	changed, err := s.casUpdate(ctx, &record, record.Generation, claim.Owner, previousExpiry, previousRecordSHA)
	if err != nil {
		return storedRecord{}, err
	}
	if !changed {
		return storedRecord{}, ErrLeaseLost
	}
	return record, nil
}

func claimMatches(record storedRecord, claim workClaim) bool {
	expected := StateAcquiringUnknown
	if claim.Kind == claimPublication {
		expected = StatePublicationUnknown
	}
	return record.State == expected && record.PreparationRef == claim.Record.PreparationRef &&
		record.Generation == claim.Generation && record.LeaseOwner == claim.Owner &&
		record.LeaseExpiresAt.Equal(claim.LeaseExpiresAt)
}

func (s *sqliteStore) recover(ctx context.Context, now time.Time, backoff func(int) time.Duration) (Recovery, error) {
	if s == nil || now.IsZero() {
		return Recovery{}, ErrInvalid
	}
	now = now.UTC()
	rows, err := s.db.QueryContext(ctx, `SELECT `+preparationColumns+` FROM temporary_media_preparations
WHERE state IN (?,?,?) AND (evidence_expires_at<=? OR (lease_owner<>'' AND lease_expires_at<=?)) ORDER BY preparation_ref`,
		StatePrepared, StateAcquiringUnknown, StatePublicationUnknown, formatTime(now), formatTime(now))
	if err != nil {
		return Recovery{}, err
	}
	var records []storedRecord
	for rows.Next() {
		record, scanErr := scanStoredRecord(rows)
		if scanErr != nil {
			_ = rows.Close()
			return Recovery{}, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return Recovery{}, err
	}
	result := Recovery{}
	for _, record := range records {
		previousOwner, previousExpiry, previousGeneration := record.LeaseOwner, record.LeaseExpiresAt, record.Generation
		previousRecordSHA := record.RecordSHA256
		recoveryKind := claimKind(0)
		if !record.Request.EvidenceExpiresAt.After(now) {
			record.State, record.Reason = StateFailed, ReasonEvidenceExpired
			record.AvailableAt = now
		} else {
			switch record.State {
			case StateAcquiringUnknown:
				if record.Reason == ReasonAcquisitionStarted {
					recoveryKind = claimAcquire
					result.AcquisitionLeasesRecovered++
				} else {
					recoveryKind = claimReconcile
					result.ReconciliationLeasesRecovered++
				}
			case StatePublicationUnknown:
				recoveryKind = claimPublication
				result.PublicationLeasesRecovered++
			default:
				return Recovery{}, ErrCorruptStore
			}
			record.Reason = ReasonWorkerInterrupted
			attempt := record.ReconciliationAttempts + 1
			if recoveryKind == claimPublication {
				attempt = record.PublicationAttempts
			}
			record.AvailableAt = now.Add(backoff(attempt))
		}
		record.Generation++
		record.LeaseOwner, record.LeaseExpiresAt, record.UpdatedAt = "", time.Time{}, now
		changed, err := s.casUpdate(ctx, &record, previousGeneration, previousOwner, previousExpiry, previousRecordSHA)
		if err != nil {
			return Recovery{}, err
		}
		if !changed {
			if record.Reason != ReasonEvidenceExpired {
				switch recoveryKind {
				case claimAcquire:
					result.AcquisitionLeasesRecovered--
				case claimReconcile:
					result.ReconciliationLeasesRecovered--
				case claimPublication:
					result.PublicationLeasesRecovered--
				}
			}
		}
	}
	return result, nil
}

func (s *sqliteStore) casUpdate(ctx context.Context, record *storedRecord, previousGeneration int, previousOwner string, previousExpiry time.Time, previousRecordSHA string) (bool, error) {
	if record == nil {
		return false, ErrInvalid
	}
	record.RecordSHA256 = digestRecord(*record)
	result, err := s.db.ExecContext(ctx, `UPDATE temporary_media_preparations SET
	state=?,content_sha256=?,content_metadata_json=?,media_ref=?,reason=?,generation=?,reconciliation_attempts=?,publication_attempts=?,available_at=?,lease_owner=?,lease_expires_at=?,updated_at=?,record_sha256=?
WHERE preparation_ref=? AND generation=? AND lease_owner=? AND lease_expires_at=? AND record_sha256=?`,
		record.State, record.ContentSHA256, record.ActualMediaRaw, record.MediaRef, record.Reason, record.Generation, record.ReconciliationAttempts,
		record.PublicationAttempts,
		formatTime(record.AvailableAt), record.LeaseOwner, formatTime(record.LeaseExpiresAt), formatTime(record.UpdatedAt), record.RecordSHA256,
		record.PreparationRef, previousGeneration, previousOwner, formatTime(previousExpiry), previousRecordSHA)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func recordSQLValues(record storedRecord) []any {
	request := record.Request
	return []any{
		record.PreparationRef, request.TenantID, request.SiteID, request.RequestID, request.SourceRef, request.CapabilityRef,
		request.AudienceBindingRef, formatTime(request.TimeScope.WindowStart), formatTime(request.TimeScope.WindowEnd), request.AudienceSHA256,
		formatTime(request.EvidenceExpiresAt), record.RequestRaw, record.RequestSHA256, record.OperationKey, record.MediaPutKey,
		record.State, record.ContentSHA256, record.ActualMediaRaw, record.MediaRef, record.Reason, record.Generation, record.ReconciliationAttempts,
		record.PublicationAttempts,
		formatTime(record.AvailableAt), record.LeaseOwner, formatTime(record.LeaseExpiresAt), formatTime(record.CreatedAt),
		formatTime(record.UpdatedAt), record.RecordSHA256,
	}
}

type rowScanner interface{ Scan(...any) error }

func scanStoredRecord(row rowScanner) (storedRecord, error) {
	var record storedRecord
	var tenantID, siteID, requestID, sourceRef, capabilityRef, audienceBindingRef, windowStart, windowEnd, audienceDigest, expires string
	var state, reason, available, leaseExpiry, created, updated string
	if err := row.Scan(
		&record.PreparationRef, &tenantID, &siteID, &requestID, &sourceRef, &capabilityRef, &audienceBindingRef, &windowStart, &windowEnd,
		&audienceDigest, &expires, &record.RequestRaw, &record.RequestSHA256, &record.OperationKey, &record.MediaPutKey,
		&state, &record.ContentSHA256, &record.ActualMediaRaw, &record.MediaRef, &reason, &record.Generation, &record.ReconciliationAttempts, &record.PublicationAttempts,
		&available, &record.LeaseOwner, &leaseExpiry, &created, &updated, &record.RecordSHA256,
	); err != nil {
		return storedRecord{}, err
	}
	request, err := unmarshalPersistedRequest(record.RequestRaw, record.RequestSHA256)
	if err != nil {
		return storedRecord{}, err
	}
	record.Request = request
	if record.ActualMediaRaw != "" {
		if record.ActualMedia, err = unmarshalActualMedia(record.ActualMediaRaw, request); err != nil {
			return storedRecord{}, err
		}
	}
	record.State, record.Reason = State(state), Reason(reason)
	if request.TenantID != tenantID || request.SiteID != siteID || request.RequestID != requestID ||
		request.SourceRef != sourceRef || request.CapabilityRef != capabilityRef || request.AudienceBindingRef != audienceBindingRef ||
		request.AudienceSHA256 != audienceDigest ||
		formatTime(request.TimeScope.WindowStart) != windowStart || formatTime(request.TimeScope.WindowEnd) != windowEnd ||
		formatTime(request.EvidenceExpiresAt) != expires {
		return storedRecord{}, ErrCorruptStore
	}
	if record.AvailableAt, err = parseTime(available, false); err != nil {
		return storedRecord{}, err
	}
	if record.LeaseExpiresAt, err = parseTime(leaseExpiry, true); err != nil {
		return storedRecord{}, err
	}
	if record.CreatedAt, err = parseTime(created, false); err != nil {
		return storedRecord{}, err
	}
	if record.UpdatedAt, err = parseTime(updated, false); err != nil {
		return storedRecord{}, err
	}
	if err := validateStoredRecord(record); err != nil {
		return storedRecord{}, err
	}
	return record, nil
}

func validateStoredRecord(record storedRecord) error {
	value := record.Request
	expectedRef, refErr := PreparationRefForScope(value.TenantID, value.SiteID, value.RequestID)
	expectedOperation := "media_acquire_" + shaHex([]byte("acquisition\x00"+record.RequestSHA256))
	expectedPut := "media_put_" + shaHex([]byte("publication\x00"+expectedRef))
	if refErr != nil || record.PreparationRef != expectedRef || !preparationPattern.MatchString(record.PreparationRef) ||
		record.OperationKey != expectedOperation || !operationPattern.MatchString(record.OperationKey) ||
		record.MediaPutKey != expectedPut || !putKeyPattern.MatchString(record.MediaPutKey) ||
		record.Generation < 0 || record.ReconciliationAttempts < 0 || record.PublicationAttempts < 0 || !safeStoredReason(record.Reason) ||
		record.CreatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) || record.AvailableAt.IsZero() ||
		!record.Request.EvidenceExpiresAt.After(record.CreatedAt) || record.Request.EvidenceExpiresAt.Sub(record.CreatedAt) > maximumEvidenceTTL ||
		digestRecord(record) != record.RecordSHA256 {
		return ErrCorruptStore
	}
	leaseEmpty := record.LeaseOwner == "" && record.LeaseExpiresAt.IsZero()
	leaseActive := validRef(record.LeaseOwner) && record.LeaseExpiresAt.After(record.UpdatedAt)
	if !leaseEmpty && !leaseActive {
		return ErrCorruptStore
	}
	switch record.State {
	case StatePrepared:
		if record.Reason != ReasonPrepared || record.Generation != 0 || record.ReconciliationAttempts != 0 || record.PublicationAttempts != 0 ||
			!leaseEmpty || record.ContentSHA256 != "" || record.ActualMediaRaw != "" || record.MediaRef != "" {
			return ErrCorruptStore
		}
	case StateAcquiringUnknown:
		if record.Generation < 1 || record.PublicationAttempts != 0 || record.MediaRef != "" || record.ContentSHA256 != "" || record.ActualMediaRaw != "" ||
			(record.Reason != ReasonAcquisitionStarted && record.Reason != ReasonAcquisitionPending && record.Reason != ReasonAcquisitionUnknown &&
				record.Reason != ReasonReconciliationStarted && record.Reason != ReasonReconciliationPending && record.Reason != ReasonReconciliationUnknown &&
				record.Reason != ReasonWorkerInterrupted) ||
			(record.Reason == ReasonAcquisitionStarted || record.Reason == ReasonReconciliationStarted) != leaseActive ||
			(record.Reason != ReasonAcquisitionStarted && record.Reason != ReasonReconciliationStarted) != leaseEmpty {
			return ErrCorruptStore
		}
	case StatePublicationUnknown:
		activeReason := record.Reason == ReasonPublicationStarted || record.Reason == ReasonPublicationProbeStarted ||
			record.Reason == ReasonPublicationReconciliationStarted
		if record.Generation < 1 || record.PublicationAttempts < 1 || record.MediaRef != "" || !digestPattern.MatchString(record.ContentSHA256) || record.ActualMediaRaw == "" ||
			(!activeReason && record.Reason != ReasonPublicationUnknown && record.Reason != ReasonWorkerInterrupted) ||
			activeReason != leaseActive || !activeReason != leaseEmpty {
			return ErrCorruptStore
		}
	case StateReady:
		if record.Generation < 1 || record.PublicationAttempts < 1 || record.Reason != ReasonReady || !leaseEmpty || !digestPattern.MatchString(record.ContentSHA256) || record.ActualMediaRaw == "" ||
			!mediaRefPattern.MatchString(record.MediaRef) {
			return ErrCorruptStore
		}
	case StateFailed:
		if record.Generation < 1 || !leaseEmpty || record.MediaRef != "" || record.ContentSHA256 != "" && (!digestPattern.MatchString(record.ContentSHA256) || record.ActualMediaRaw == "") ||
			record.ContentSHA256 == "" && record.ActualMediaRaw != "" ||
			(record.Reason != ReasonAcquisitionFailed && record.Reason != ReasonEvidenceExpired &&
				record.Reason != ReasonContentInvalid && record.Reason != ReasonPublicationRejected) {
			return ErrCorruptStore
		}
	default:
		return ErrCorruptStore
	}
	return nil
}

type recordDigestValue struct {
	PreparationRef         string `json:"preparationRef"`
	RequestSHA256          string `json:"requestSha256"`
	OperationKey           string `json:"operationKey"`
	MediaPutKey            string `json:"mediaPutKey"`
	State                  State  `json:"state"`
	ContentSHA256          string `json:"contentSha256"`
	ActualMediaRaw         string `json:"actualMedia"`
	MediaRef               string `json:"mediaRef"`
	Reason                 Reason `json:"reason"`
	Generation             int    `json:"generation"`
	ReconciliationAttempts int    `json:"reconciliationAttempts"`
	PublicationAttempts    int    `json:"publicationAttempts"`
	AvailableAt            string `json:"availableAt"`
	LeaseOwner             string `json:"leaseOwner"`
	LeaseExpiresAt         string `json:"leaseExpiresAt"`
	CreatedAt              string `json:"createdAt"`
	UpdatedAt              string `json:"updatedAt"`
}

func digestRecord(record storedRecord) string {
	raw, _ := json.Marshal(recordDigestValue{
		PreparationRef: record.PreparationRef, RequestSHA256: record.RequestSHA256,
		OperationKey: record.OperationKey, MediaPutKey: record.MediaPutKey, State: record.State,
		ContentSHA256: record.ContentSHA256, ActualMediaRaw: record.ActualMediaRaw, MediaRef: record.MediaRef, Reason: record.Reason,
		Generation: record.Generation, ReconciliationAttempts: record.ReconciliationAttempts,
		PublicationAttempts: record.PublicationAttempts,
		AvailableAt:         formatTime(record.AvailableAt), LeaseOwner: record.LeaseOwner,
		LeaseExpiresAt: formatTime(record.LeaseExpiresAt), CreatedAt: formatTime(record.CreatedAt), UpdatedAt: formatTime(record.UpdatedAt),
	})
	return shaHex(raw)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timestampLayout)
}

func parseTime(value string, optional bool) (time.Time, error) {
	if value == "" && optional {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, ErrCorruptStore
	}
	return parsed.UTC(), nil
}
