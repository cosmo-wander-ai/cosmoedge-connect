package inspectionauthority

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	coreauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

const (
	databaseVersion       = 3
	databaseApplicationID = 0x43454133 // "CEA3"
	keyAttached           = "attached"
	keyPrepared           = "prepared"
	keyBindingDomain      = "cosmoedge.operator.inspection-authority.key-binding.v1\x00"
)

const createKeySQL = `CREATE TABLE authority_key (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    put_operation_id TEXT NOT NULL UNIQUE,
    issuer_id TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    anchor_generation INTEGER NOT NULL CHECK(anchor_generation>=0),
    anchor_sha256 TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('prepared','attached')),
    record_hmac TEXT NOT NULL,
    CHECK((phase='prepared' AND credential_ref='' AND anchor_generation=0 AND anchor_sha256='' AND record_hmac='') OR
          (phase='attached' AND length(credential_ref)=69 AND length(anchor_sha256)=64 AND length(record_hmac)=64))
) WITHOUT ROWID`

const createAuthorizationsSQL = `CREATE TABLE execution_authorizations (
    run_id TEXT PRIMARY KEY,
    schema_name TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL UNIQUE,
    identity_kind TEXT NOT NULL CHECK(identity_kind IN ('actor','service')),
    principal_sha256 TEXT NOT NULL CHECK(length(principal_sha256)=64),
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64),
    assignment_id TEXT NOT NULL,
    assignment_revision INTEGER NOT NULL CHECK(assignment_revision>0),
    request_key TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    steps_json BLOB NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    proof_sha256 TEXT NOT NULL CHECK(length(proof_sha256)=64),
    revoked_at TEXT NOT NULL,
    record_hmac TEXT NOT NULL CHECK(length(record_hmac)=64)
) WITHOUT ROWID`

const createConsumptionsSQL = `CREATE TABLE execution_consumptions (
    authorization_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority IN ('none','device_read','inspection_execution')),
    operation_sha256 TEXT NOT NULL CHECK(length(operation_sha256)=64),
    consumed_at TEXT NOT NULL,
    anchor_generation INTEGER NOT NULL CHECK(anchor_generation>0),
    previous_anchor_sha256 TEXT NOT NULL CHECK(length(previous_anchor_sha256)=64),
    anchor_sha256 TEXT NOT NULL CHECK(length(anchor_sha256)=64),
    record_hmac TEXT NOT NULL CHECK(length(record_hmac)=64),
    PRIMARY KEY(authorization_id,step_id,attempt_id),
    FOREIGN KEY(authorization_id) REFERENCES execution_authorizations(authorization_id) ON DELETE RESTRICT
) WITHOUT ROWID`

const createRevocationsSQL = `CREATE TABLE execution_revocations (
    authorization_id TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    previous_authorization_hmac TEXT NOT NULL CHECK(length(previous_authorization_hmac)=64),
    new_authorization_hmac TEXT NOT NULL CHECK(length(new_authorization_hmac)=64),
    anchor_generation INTEGER NOT NULL UNIQUE CHECK(anchor_generation>0),
    previous_anchor_sha256 TEXT NOT NULL CHECK(length(previous_anchor_sha256)=64),
    anchor_sha256 TEXT NOT NULL CHECK(length(anchor_sha256)=64),
    record_hmac TEXT NOT NULL CHECK(length(record_hmac)=64),
    FOREIGN KEY(authorization_id) REFERENCES execution_authorizations(authorization_id) ON DELETE RESTRICT
) WITHOUT ROWID`

const createConsumptionPendingSQL = `CREATE TABLE execution_consumption_pending (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    event_kind TEXT NOT NULL CHECK(event_kind IN ('consume','revoke')),
    authorization_id TEXT NOT NULL,
    authorization_hmac TEXT NOT NULL CHECK(length(authorization_hmac)=64),
    step_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    authority TEXT NOT NULL CHECK(authority IN ('none','device_read','inspection_execution')),
    operation_sha256 TEXT NOT NULL CHECK(length(operation_sha256)=64),
    consumed_at TEXT NOT NULL,
    anchor_generation INTEGER NOT NULL CHECK(anchor_generation>0),
    previous_anchor_sha256 TEXT NOT NULL CHECK(length(previous_anchor_sha256)=64),
    anchor_sha256 TEXT NOT NULL CHECK(length(anchor_sha256)=64),
    record_hmac TEXT NOT NULL CHECK(length(record_hmac)=64),
    revoked_at TEXT NOT NULL,
    new_authorization_hmac TEXT NOT NULL,
    old_credential_ref TEXT NOT NULL CHECK(length(old_credential_ref)=69),
    new_credential_ref TEXT NOT NULL,
    rotation_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('prepared','applied')),
    transition_hmac TEXT NOT NULL CHECK(length(transition_hmac)=64),
    CHECK((phase='prepared' AND new_credential_ref='' AND rotation_id='') OR
          (phase='applied' AND length(new_credential_ref)=69 AND length(rotation_id)=36)),
    CHECK((event_kind='consume' AND revoked_at='' AND new_authorization_hmac='') OR
          (event_kind='revoke' AND revoked_at<>'' AND length(new_authorization_hmac)=64)),
    FOREIGN KEY(authorization_id) REFERENCES execution_authorizations(authorization_id) ON DELETE RESTRICT
) WITHOUT ROWID`

const insertAuthorizationSQL = `INSERT OR IGNORE INTO execution_authorizations (
run_id,schema_name,issuer_id,authorization_id,identity_kind,principal_sha256,tenant_id,site_id,
plan_sha256,assignment_id,assignment_revision,request_key,runtime_id,steps_json,issued_at,expires_at,
proof_sha256,revoked_at,record_hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const insertConsumptionSQL = `INSERT OR IGNORE INTO execution_consumptions (
authorization_id,step_id,attempt_id,authority,operation_sha256,consumed_at,anchor_generation,
previous_anchor_sha256,anchor_sha256,record_hmac)
SELECT ?,?,?,?,?,?,?,?,?,? FROM execution_authorizations
WHERE authorization_id=? AND revoked_at='' AND record_hmac=?`

type keyRecord struct {
	operationID credential.PutOperationID
	issuerID    string
	ref         credential.Ref
	generation  uint64
	anchorSHA   string
	phase       string
	recordHMAC  string
}

func openDatabase(path string) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || strings.ContainsAny(absolute, "\x00?#") {
		return nil, ErrInvalidConfig
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
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
	} else if err := localstate.ValidateFile(absolute); err != nil {
		return nil, fmt.Errorf("reject existing inspection authority state: %w", err)
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	fail := func(openErr error) (*sql.DB, error) {
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
		if !created || applicationID != 0 || objects != 0 {
			return fail(ErrSchema)
		}
		transaction, err := database.Begin()
		if err != nil {
			return fail(err)
		}
		for _, statement := range []string{
			createKeySQL, createAuthorizationsSQL, createConsumptionsSQL, createRevocationsSQL, createConsumptionPendingSQL,
			fmt.Sprintf("PRAGMA application_id=%d", databaseApplicationID),
			fmt.Sprintf("PRAGMA user_version=%d", databaseVersion),
		} {
			if _, err := transaction.Exec(statement); err != nil {
				_ = transaction.Rollback()
				return fail(err)
			}
		}
		if err := transaction.Commit(); err != nil {
			return fail(err)
		}
	} else if version != databaseVersion || applicationID != databaseApplicationID {
		return fail(ErrSchema)
	}
	if err := verifyDatabaseShape(database); err != nil {
		return fail(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return fail(err)
	}
	return database, nil
}

func establishKey(ctx context.Context, database *sql.DB, secrets credential.SecretStore, issuerID string) ([]byte, error) {
	for attempt := 0; attempt < 4; attempt++ {
		record, found, err := readKeyRecord(ctx, database)
		if err != nil {
			return nil, err
		}
		if !found {
			empty, err := businessStateEmpty(ctx, database)
			if err != nil {
				return nil, err
			}
			if !empty {
				return nil, ErrIntegrity
			}
			operationID, err := credential.NewPutOperationID()
			if err != nil {
				return nil, err
			}
			result, err := database.ExecContext(ctx, `INSERT OR IGNORE INTO authority_key
				(singleton,put_operation_id,issuer_id,credential_ref,anchor_generation,anchor_sha256,phase,record_hmac)
				VALUES (1,?,?,'',0,'','prepared','')`,
				operationID.ProtectedValue(), issuerID)
			if err != nil {
				return nil, err
			}
			if _, err := result.RowsAffected(); err != nil {
				return nil, err
			}
			continue
		}
		if record.issuerID != issuerID {
			return nil, ErrIntegrity
		}
		switch record.phase {
		case keyAttached:
			return loadAttachedKey(ctx, database, secrets, record)
		case keyPrepared:
			key, retry, err := finishPreparedKey(ctx, database, secrets, record)
			if err != nil {
				return nil, err
			}
			if retry {
				continue
			}
			return key, nil
		default:
			return nil, ErrIntegrity
		}
	}
	return nil, ErrKeyUnavailable
}

func finishPreparedKey(ctx context.Context, database *sql.DB, secrets credential.SecretStore, record keyRecord) ([]byte, bool, error) {
	receipt, err := secrets.PutByOperationID(ctx, record.operationID)
	if errors.Is(err, credential.ErrNotFound) {
		entropy := make([]byte, macKeyEntropyBytes)
		if _, err := rand.Read(entropy); err != nil {
			clearBytes(entropy)
			return nil, false, err
		}
		key := make([]byte, macKeyBytes)
		hex.Encode(key, entropy)
		clearBytes(entropy)
		envelope, encodeErr := encodeSecretEnvelope(key, 0, genesisAnchor(key))
		if encodeErr != nil {
			clearBytes(key)
			return nil, false, encodeErr
		}
		receipt, err = secrets.Put(ctx, record.operationID, envelope)
		clearBytes(envelope)
		clearBytes(key)
		if err != nil {
			recovered, recoverErr := secrets.RecoverPut(ctx, record.operationID)
			if recoverErr != nil {
				return nil, false, err
			}
			receipt = recovered
		}
	} else if err != nil {
		return nil, false, err
	}
	if !receipt.Valid() || receipt.OperationID != record.operationID {
		return nil, false, ErrKeyUnavailable
	}
	if receipt.Phase != credential.PutCommitted {
		receipt, err = secrets.RecoverPut(ctx, record.operationID)
		if err != nil && receipt.Phase != credential.PutRolledBack {
			return nil, false, err
		}
	}
	if receipt.Phase != credential.PutCommitted {
		return resetPreparedKey(ctx, database, secrets, record)
	}
	raw, err := secrets.Get(ctx, receipt.Ref)
	if err != nil {
		clearBytes(raw)
		return nil, false, errors.Join(ErrKeyUnavailable, err)
	}
	key, generation, anchorSHA, decodeErr := decodeSecretEnvelope(raw)
	clearBytes(raw)
	if decodeErr != nil || generation != 0 || anchorSHA != genesisAnchor(key) {
		clearBytes(key)
		return nil, false, errors.Join(ErrKeyUnavailable, decodeErr)
	}
	attached := keyRecord{operationID: record.operationID, issuerID: record.issuerID, ref: receipt.Ref,
		generation: generation, anchorSHA: anchorSHA, phase: keyAttached}
	attached.recordHMAC = keyRecordHMAC(key, attached)
	result, err := database.ExecContext(ctx, `UPDATE authority_key SET credential_ref=?,anchor_generation=?,anchor_sha256=?,phase='attached',record_hmac=?
		WHERE singleton=1 AND put_operation_id=? AND issuer_id=? AND credential_ref='' AND phase='prepared' AND record_hmac=''`,
		receipt.Ref.ProtectedValue(), attached.generation, attached.anchorSHA, attached.recordHMAC,
		record.operationID.ProtectedValue(), record.issuerID)
	if err != nil {
		clearBytes(key)
		return nil, false, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		clearBytes(key)
		return nil, false, err
	}
	if updated != 1 {
		clearBytes(key)
		// A concurrent opener may have attached the same operation. Re-read it;
		// never compensate a key whose database commit may already be durable.
		return nil, true, nil
	}
	if err := secrets.AcknowledgePut(ctx, record.operationID); err != nil {
		clearBytes(key)
		return nil, false, err
	}
	return key, false, nil
}

func resetPreparedKey(ctx context.Context, database *sql.DB, secrets credential.SecretStore, record keyRecord) ([]byte, bool, error) {
	receipt, err := secrets.CompensatePut(ctx, record.operationID)
	if err != nil || !receipt.Valid() || receipt.OperationID != record.operationID || receipt.Phase != credential.PutRolledBack {
		return nil, false, errors.Join(ErrKeyUnavailable, err)
	}
	if err := secrets.AcknowledgePut(ctx, record.operationID); err != nil {
		return nil, false, err
	}
	empty, err := businessStateEmpty(ctx, database)
	if err != nil {
		return nil, false, err
	}
	if !empty {
		return nil, false, ErrIntegrity
	}
	result, err := database.ExecContext(ctx, `DELETE FROM authority_key WHERE singleton=1 AND put_operation_id=? AND issuer_id=?
		AND credential_ref='' AND phase='prepared' AND record_hmac=''`, record.operationID.ProtectedValue(), record.issuerID)
	if err != nil {
		return nil, false, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if deleted != 1 {
		return nil, false, ErrIntegrity
	}
	return nil, true, nil
}

func loadAttachedKey(ctx context.Context, database *sql.DB, secrets credential.SecretStore, record keyRecord) ([]byte, error) {
	raw, err := secrets.Get(ctx, record.ref)
	if err != nil {
		clearBytes(raw)
		if recovered, recoverErr := keyFromPreparedRotation(ctx, database, secrets, record); recoverErr == nil {
			return recovered, nil
		}
		return nil, errors.Join(ErrKeyUnavailable, ErrIntegrity, err)
	}
	key, generation, anchorSHA, decodeErr := decodeSecretEnvelope(raw)
	clearBytes(raw)
	if decodeErr != nil || generation != record.generation || anchorSHA != record.anchorSHA {
		clearBytes(key)
		return nil, errors.Join(ErrKeyUnavailable, ErrIntegrity, decodeErr)
	}
	want := keyRecordHMAC(key, record)
	if subtle.ConstantTimeCompare([]byte(want), []byte(record.recordHMAC)) != 1 {
		clearBytes(key)
		return nil, ErrIntegrity
	}
	receipt, err := secrets.PutByOperationID(ctx, record.operationID)
	if err == nil {
		receipt, err = secrets.RecoverPut(ctx, record.operationID)
		if err != nil || !receipt.Valid() || receipt.OperationID != record.operationID || receipt.Ref != record.ref || receipt.Phase != credential.PutCommitted {
			clearBytes(key)
			return nil, errors.Join(ErrKeyUnavailable, err)
		}
		if err := secrets.AcknowledgePut(ctx, record.operationID); err != nil {
			clearBytes(key)
			return nil, err
		}
	} else if !errors.Is(err, credential.ErrNotFound) {
		clearBytes(key)
		return nil, err
	}
	return key, nil
}

func keyFromPreparedRotation(ctx context.Context, database *sql.DB, secrets credential.SecretStore, record keyRecord) ([]byte, error) {
	var oldRef, phase string
	if err := database.QueryRowContext(ctx, `SELECT old_credential_ref,phase FROM execution_consumption_pending
		WHERE singleton=1`).Scan(&oldRef, &phase); err != nil || phase != transitionPrepared || oldRef != record.ref.ProtectedValue() {
		return nil, errors.Join(ErrIntegrity, err)
	}
	receipt, err := secrets.RotationByOldRef(ctx, record.ref)
	if err != nil {
		return nil, err
	}
	if receipt.Phase != credential.RotationCommitted {
		receipt, err = secrets.RecoverRotation(ctx, receipt.OperationID)
	}
	if err != nil || !receipt.Valid() || receipt.OldRef != record.ref || receipt.Phase != credential.RotationCommitted {
		return nil, errors.Join(ErrKeyUnavailable, err)
	}
	raw, err := secrets.Get(ctx, receipt.NewRef)
	if err != nil {
		clearBytes(raw)
		return nil, err
	}
	key, generation, anchorSHA, decodeErr := decodeSecretEnvelope(raw)
	clearBytes(raw)
	if decodeErr != nil || subtle.ConstantTimeCompare([]byte(keyRecordHMAC(key, record)), []byte(record.recordHMAC)) != 1 {
		clearBytes(key)
		return nil, errors.Join(ErrIntegrity, decodeErr)
	}
	transition, found, transitionErr := loadPendingTransition(ctx, database, key)
	if transitionErr != nil || !found || transition.phase != transitionPrepared || transition.oldRef != record.ref ||
		transition.generation() != generation || transition.anchor() != anchorSHA {
		clearBytes(key)
		return nil, errors.Join(ErrIntegrity, transitionErr)
	}
	return key, nil
}

func readKeyRecord(ctx context.Context, database *sql.DB) (keyRecord, bool, error) {
	var operationValue, issuerID, refValue, anchorSHA, phase, recordHMAC string
	var generation uint64
	err := database.QueryRowContext(ctx, `SELECT put_operation_id,issuer_id,credential_ref,anchor_generation,anchor_sha256,phase,record_hmac
		FROM authority_key WHERE singleton=1`).Scan(&operationValue, &issuerID, &refValue, &generation, &anchorSHA, &phase, &recordHMAC)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if countErr := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM authority_key`).Scan(&count); countErr != nil {
			return keyRecord{}, false, countErr
		}
		if count != 0 {
			return keyRecord{}, false, ErrIntegrity
		}
		return keyRecord{}, false, nil
	}
	if err != nil {
		return keyRecord{}, false, err
	}
	operationID, err := credential.ParsePutOperationID(operationValue)
	if err != nil {
		return keyRecord{}, false, ErrIntegrity
	}
	if !validProtectedRef(issuerID) {
		return keyRecord{}, false, ErrIntegrity
	}
	record := keyRecord{operationID: operationID, issuerID: issuerID, generation: generation,
		anchorSHA: anchorSHA, phase: phase, recordHMAC: recordHMAC}
	switch phase {
	case keyPrepared:
		if refValue != "" || generation != 0 || anchorSHA != "" || recordHMAC != "" {
			return keyRecord{}, false, ErrIntegrity
		}
	case keyAttached:
		ref, err := credential.ParseRef(refValue)
		if err != nil || !validDigest(anchorSHA) || !validDigest(recordHMAC) {
			return keyRecord{}, false, ErrIntegrity
		}
		record.ref = ref
	default:
		return keyRecord{}, false, ErrIntegrity
	}
	return record, true, nil
}

func businessStateEmpty(ctx context.Context, database *sql.DB) (bool, error) {
	var authorizations, consumptions, revocations, pending int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_authorizations`).Scan(&authorizations); err != nil {
		return false, err
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_consumptions`).Scan(&consumptions); err != nil {
		return false, err
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_consumption_pending`).Scan(&pending); err != nil {
		return false, err
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_revocations`).Scan(&revocations); err != nil {
		return false, err
	}
	return authorizations == 0 && consumptions == 0 && revocations == 0 && pending == 0, nil
}

func keyRecordHMAC(key []byte, record keyRecord) string {
	raw := []byte(record.operationID.ProtectedValue() + "\x00" + record.issuerID + "\x00" +
		record.ref.ProtectedValue() + "\x00" + fmt.Sprint(record.generation) + "\x00" + record.anchorSHA + "\x00" + record.phase)
	return keyedDigest(key, keyBindingDomain, raw)
}

func validateDatabaseContent(ctx context.Context, database *sql.DB, key []byte, issuerID string) error {
	keyState, found, err := readKeyRecord(ctx, database)
	if err != nil || !found || keyState.phase != keyAttached || keyState.issuerID != issuerID ||
		subtle.ConstantTimeCompare([]byte(keyRecordHMAC(key, keyState)), []byte(keyState.recordHMAC)) != 1 {
		return errors.Join(ErrIntegrity, err)
	}
	if _, pending, err := loadPendingTransition(ctx, database, key); err != nil || pending {
		return errors.Join(ErrIntegrity, err)
	}
	rows, err := database.QueryContext(ctx, `SELECT run_id FROM execution_authorizations ORDER BY run_id`)
	if err != nil {
		return err
	}
	var runIDs []string
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			_ = rows.Close()
			return err
		}
		runIDs = append(runIDs, runID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	authorizations := make(map[string]authorizationRecord, len(runIDs))
	for _, runID := range runIDs {
		record, err := loadAuthorization(ctx, database, key, runID)
		if err != nil || record.authorization.IssuerID != issuerID {
			return errors.Join(ErrIntegrity, err)
		}
		authorizations[record.authorization.AuthorizationID] = record
	}
	return validateConsumptionChainWithAuthorizations(ctx, database, key, keyState, authorizations)
}

func validateConsumptionChain(ctx context.Context, database *sql.DB, key []byte, keyState keyRecord) error {
	rows, err := database.QueryContext(ctx, `SELECT run_id FROM execution_authorizations ORDER BY run_id`)
	if err != nil {
		return err
	}
	var runIDs []string
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			_ = rows.Close()
			return err
		}
		runIDs = append(runIDs, runID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	authorizations := make(map[string]authorizationRecord, len(runIDs))
	for _, runID := range runIDs {
		record, err := loadAuthorization(ctx, database, key, runID)
		if err != nil {
			return err
		}
		authorizations[record.authorization.AuthorizationID] = record
	}
	return validateConsumptionChainWithAuthorizations(ctx, database, key, keyState, authorizations)
}

func validateConsumptionChainWithAuthorizations(ctx context.Context, database *sql.DB, key []byte, keyState keyRecord,
	authorizations map[string]authorizationRecord) error {
	type chainEvent struct {
		generation  uint64
		previous    string
		anchor      string
		consumption *consumptionRecord
		revocation  *revocationRecord
	}
	var events []chainEvent
	rows, err := database.QueryContext(ctx, `SELECT authorization_id,step_id,attempt_id,authority,
		operation_sha256,consumed_at,anchor_generation,previous_anchor_sha256,anchor_sha256,record_hmac
		FROM execution_consumptions ORDER BY anchor_generation`)
	if err != nil {
		return err
	}
	for rows.Next() {
		record, err := scanConsumption(rows)
		if err != nil {
			_ = rows.Close()
			return errors.Join(ErrIntegrity, err)
		}
		copyOfRecord := record
		events = append(events, chainEvent{generation: record.anchorGeneration, previous: record.previousAnchorSHA,
			anchor: record.anchorSHA, consumption: &copyOfRecord})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = database.QueryContext(ctx, `SELECT authorization_id,revoked_at,previous_authorization_hmac,
		new_authorization_hmac,anchor_generation,previous_anchor_sha256,anchor_sha256,record_hmac
		FROM execution_revocations ORDER BY anchor_generation`)
	if err != nil {
		return err
	}
	for rows.Next() {
		record, err := scanRevocation(rows)
		if err != nil {
			_ = rows.Close()
			return errors.Join(ErrIntegrity, err)
		}
		copyOfRecord := record
		events = append(events, chainEvent{generation: record.anchorGeneration, previous: record.previousAnchorSHA,
			anchor: record.anchorSHA, revocation: &copyOfRecord})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	sort.Slice(events, func(left, right int) bool { return events[left].generation < events[right].generation })
	generation := uint64(0)
	anchorSHA := genesisAnchor(key)
	for _, event := range events {
		generation++
		if event.generation != generation || event.previous != anchorSHA {
			return errors.Join(ErrIntegrity, errors.New("authority anchor sequence is invalid"))
		}
		if event.consumption != nil {
			authorization, found := authorizations[event.consumption.authorizationID]
			if !found || validateConsumptionRecord(key, *event.consumption, authorization.authorization) != nil {
				return errors.Join(ErrIntegrity, errors.New("consumption record is invalid"))
			}
		} else if event.revocation != nil {
			authorization, found := authorizations[event.revocation.authorizationID]
			if !found || validateRevocationRecord(key, *event.revocation, authorization) != nil {
				return errors.Join(ErrIntegrity, errors.New("revocation record is invalid"))
			}
		} else {
			return ErrIntegrity
		}
		anchorSHA = event.anchor
	}
	if keyState.generation != generation || keyState.anchorSHA != anchorSHA {
		return errors.Join(ErrIntegrity, errors.New("authority anchor head is invalid"))
	}
	return nil
}

func loadAuthorization(ctx context.Context, database *sql.DB, key []byte, runID string) (authorizationRecord, error) {
	row := database.QueryRowContext(ctx, `SELECT run_id,schema_name,issuer_id,authorization_id,identity_kind,
		principal_sha256,tenant_id,site_id,plan_sha256,assignment_id,assignment_revision,request_key,runtime_id,
		steps_json,issued_at,expires_at,proof_sha256,revoked_at,record_hmac
		FROM execution_authorizations WHERE run_id=?`, runID)
	record, err := scanAuthorization(row)
	if errors.Is(err, sql.ErrNoRows) {
		return authorizationRecord{}, coreauthority.ErrNotFound
	}
	if err != nil {
		return authorizationRecord{}, errors.Join(ErrIntegrity, err)
	}
	if err := validateAuthorizationRecord(key, record); err != nil {
		return authorizationRecord{}, err
	}
	return record, nil
}

type scanner interface{ Scan(...any) error }

func scanAuthorization(row scanner) (authorizationRecord, error) {
	var record authorizationRecord
	var identityKind, issuedAt, expiresAt, revokedAt string
	value := &record.authorization
	if err := row.Scan(&value.RunID, &value.Schema, &value.IssuerID, &value.AuthorizationID, &identityKind,
		&value.Identity.PrincipalSHA256, &value.TenantID, &value.SiteID, &value.PlanSHA256, &value.AssignmentID,
		&value.AssignmentRevision, &value.RequestKey, &value.RuntimeID, &record.stepsJSON, &issuedAt, &expiresAt,
		&value.ProofSHA256, &revokedAt, &record.recordHMAC); err != nil {
		return authorizationRecord{}, err
	}
	value.Identity.Kind = coreauthority.ExecutionIdentityKind(identityKind)
	var err error
	if value.Steps, err = decodeScopes(record.stepsJSON); err != nil {
		return authorizationRecord{}, err
	}
	if value.IssuedAt, err = parseTime(issuedAt); err != nil {
		return authorizationRecord{}, err
	}
	if value.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return authorizationRecord{}, err
	}
	if revokedAt != "" {
		if record.revokedAt, err = parseTime(revokedAt); err != nil {
			return authorizationRecord{}, err
		}
	}
	record.previousRecordHMAC = record.recordHMAC
	return record, nil
}

func validateAuthorizationRecord(key []byte, record authorizationRecord) error {
	if !validAuthorization(record.authorization) || !validDigest(record.recordHMAC) ||
		(!record.revokedAt.IsZero() && record.revokedAt.Before(record.authorization.IssuedAt)) {
		return ErrIntegrity
	}
	proof, err := proofFor(key, record.authorization)
	if err != nil || subtle.ConstantTimeCompare([]byte(proof), []byte(record.authorization.ProofSHA256)) != 1 {
		return ErrIntegrity
	}
	want, err := authorizationRecordHMAC(key, record)
	if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(record.recordHMAC)) != 1 {
		return ErrIntegrity
	}
	return nil
}

func scanConsumption(row scanner) (consumptionRecord, error) {
	var record consumptionRecord
	var authority, consumedAt string
	if err := row.Scan(&record.authorizationID, &record.stepID, &record.attemptID, &authority,
		&record.operationSHA256, &consumedAt, &record.anchorGeneration, &record.previousAnchorSHA,
		&record.anchorSHA, &record.recordHMAC); err != nil {
		return consumptionRecord{}, err
	}
	record.authority = coreauthority.StepAuthority(authority)
	var err error
	record.consumedAt, err = parseTime(consumedAt)
	return record, err
}

func scanRevocation(row scanner) (revocationRecord, error) {
	var record revocationRecord
	var revokedAt string
	if err := row.Scan(&record.authorizationID, &revokedAt, &record.previousAuthorizationHMAC,
		&record.newAuthorizationHMAC, &record.anchorGeneration, &record.previousAnchorSHA,
		&record.anchorSHA, &record.recordHMAC); err != nil {
		return revocationRecord{}, err
	}
	var err error
	record.revokedAt, err = parseTime(revokedAt)
	return record, err
}

func validateRevocationRecord(key []byte, record revocationRecord, authorization authorizationRecord) error {
	if !validProtectedRef(record.authorizationID) || !validDigest(record.previousAuthorizationHMAC) ||
		!validDigest(record.newAuthorizationHMAC) || record.anchorGeneration == 0 ||
		!validDigest(record.previousAnchorSHA) || !validDigest(record.anchorSHA) || !validDigest(record.recordHMAC) ||
		record.authorizationID != authorization.authorization.AuthorizationID || authorization.revokedAt.IsZero() ||
		!record.revokedAt.Equal(authorization.revokedAt) || record.newAuthorizationHMAC != authorization.recordHMAC {
		return ErrIntegrity
	}
	anchor, anchorErr := revocationAnchor(key, record)
	want, hmacErr := revocationRecordHMAC(key, record)
	if anchorErr != nil || hmacErr != nil ||
		subtle.ConstantTimeCompare([]byte(anchor), []byte(record.anchorSHA)) != 1 ||
		subtle.ConstantTimeCompare([]byte(want), []byte(record.recordHMAC)) != 1 {
		return ErrIntegrity
	}
	return nil
}

func validateConsumptionRecord(key []byte, record consumptionRecord, authorization coreauthority.Authorization) error {
	if !validProtectedRef(record.authorizationID) || !validProtectedRef(record.stepID) ||
		!validProtectedRef(record.attemptID) || !validStepAuthority(record.authority) ||
		!validDigest(record.operationSHA256) || record.consumedAt.IsZero() ||
		record.consumedAt.Before(authorization.IssuedAt) || !record.consumedAt.Before(authorization.ExpiresAt) ||
		record.anchorGeneration == 0 || !validDigest(record.previousAnchorSHA) || !validDigest(record.anchorSHA) ||
		!validDigest(record.recordHMAC) {
		return ErrIntegrity
	}
	demand := coreauthority.StepDemand{
		Identity: authorization.Identity, Authority: record.authority, TenantID: authorization.TenantID,
		SiteID: authorization.SiteID, RunID: authorization.RunID, PlanSHA256: authorization.PlanSHA256,
		AssignmentID: authorization.AssignmentID, AssignmentRevision: authorization.AssignmentRevision,
		RequestKey: authorization.RequestKey, RuntimeID: authorization.RuntimeID,
		StepID: record.stepID, AttemptID: record.attemptID,
	}
	operation, err := consumptionOperationDigest(demand)
	anchor, anchorErr := consumptionAnchor(key, record)
	if err != nil || !authorizationAllows(authorization, demand) ||
		anchorErr != nil || subtle.ConstantTimeCompare([]byte(operation), []byte(record.operationSHA256)) != 1 ||
		subtle.ConstantTimeCompare([]byte(anchor), []byte(record.anchorSHA)) != 1 {
		return ErrIntegrity
	}
	want, err := consumptionRecordHMAC(key, record)
	if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(record.recordHMAC)) != 1 {
		return ErrIntegrity
	}
	return nil
}

func authorizationRecordValues(record authorizationRecord) []any {
	value := record.authorization
	return []any{
		value.RunID, value.Schema, value.IssuerID, value.AuthorizationID, string(value.Identity.Kind),
		value.Identity.PrincipalSHA256, value.TenantID, value.SiteID, value.PlanSHA256, value.AssignmentID,
		value.AssignmentRevision, value.RequestKey, value.RuntimeID, record.stepsJSON, formatTime(value.IssuedAt),
		formatTime(value.ExpiresAt), value.ProofSHA256, formatOptionalTime(record.revokedAt), record.recordHMAC,
	}
}

func consumptionRecordValues(record consumptionRecord, authorizationHMAC string) []any {
	return []any{
		record.authorizationID, record.stepID, record.attemptID, string(record.authority), record.operationSHA256,
		formatTime(record.consumedAt), record.anchorGeneration, record.previousAnchorSHA, record.anchorSHA,
		record.recordHMAC, record.authorizationID, authorizationHMAC,
	}
}

func pendingValues(transition consumptionTransition) []any {
	if transition.eventKind == eventRevoke {
		record := transition.revocation
		return []any{
			transition.eventKind, record.authorizationID, transition.authorizationHMAC, "terminal-revoke", "terminal",
			string(coreauthority.StepAuthorityNone), record.newAuthorizationHMAC, formatTime(record.revokedAt),
			record.anchorGeneration, record.previousAnchorSHA, record.anchorSHA, record.recordHMAC,
			formatTime(record.revokedAt), record.newAuthorizationHMAC, transition.oldRef.ProtectedValue(),
			transition.transitionHMAC,
		}
	}
	record := transition.record
	return []any{
		transition.eventKind, record.authorizationID, transition.authorizationHMAC, record.stepID, record.attemptID, string(record.authority),
		record.operationSHA256, formatTime(record.consumedAt), record.anchorGeneration, record.previousAnchorSHA,
		record.anchorSHA, record.recordHMAC, "", "", transition.oldRef.ProtectedValue(), transition.transitionHMAC,
	}
}

func loadPendingTransition(ctx context.Context, database *sql.DB, key []byte) (consumptionTransition, bool, error) {
	row := database.QueryRowContext(ctx, `SELECT event_kind,authorization_id,authorization_hmac,step_id,attempt_id,authority,
		operation_sha256,consumed_at,anchor_generation,previous_anchor_sha256,anchor_sha256,record_hmac,
		revoked_at,new_authorization_hmac,old_credential_ref,new_credential_ref,rotation_id,phase,transition_hmac
		FROM execution_consumption_pending WHERE singleton=1`)
	var transition consumptionTransition
	var authority, consumedAt, revokedAt, newAuthorizationHMAC, oldRef, newRef, rotationID string
	err := row.Scan(&transition.eventKind, &transition.record.authorizationID, &transition.authorizationHMAC, &transition.record.stepID,
		&transition.record.attemptID, &authority, &transition.record.operationSHA256, &consumedAt,
		&transition.record.anchorGeneration, &transition.record.previousAnchorSHA, &transition.record.anchorSHA,
		&transition.record.recordHMAC, &revokedAt, &newAuthorizationHMAC, &oldRef, &newRef, &rotationID,
		&transition.phase, &transition.transitionHMAC)
	if errors.Is(err, sql.ErrNoRows) {
		return consumptionTransition{}, false, nil
	}
	if err != nil {
		return consumptionTransition{}, false, errors.Join(ErrIntegrity, err)
	}
	transition.record.authority = coreauthority.StepAuthority(authority)
	transition.record.consumedAt, err = parseTime(consumedAt)
	if err != nil {
		return consumptionTransition{}, false, err
	}
	transition.oldRef, err = credential.ParseRef(oldRef)
	if err != nil {
		return consumptionTransition{}, false, ErrIntegrity
	}
	if transition.phase == transitionApplied {
		transition.newRef, err = credential.ParseRef(newRef)
		if err != nil {
			return consumptionTransition{}, false, ErrIntegrity
		}
		transition.rotationID, err = credential.ParseRotationID(rotationID)
		if err != nil {
			return consumptionTransition{}, false, ErrIntegrity
		}
	} else if transition.phase != transitionPrepared || newRef != "" || rotationID != "" {
		return consumptionTransition{}, false, ErrIntegrity
	}
	if !validDigest(transition.authorizationHMAC) || !validDigest(transition.record.recordHMAC) ||
		!validDigest(transition.transitionHMAC) || !validDigest(transition.record.previousAnchorSHA) ||
		!validDigest(transition.record.anchorSHA) || transition.record.anchorGeneration == 0 ||
		!validProtectedRef(transition.record.authorizationID) {
		return consumptionTransition{}, false, ErrIntegrity
	}
	var wantRecord string
	var hmacErr error
	if transition.eventKind == eventConsume {
		if revokedAt != "" || newAuthorizationHMAC != "" || !validProtectedRef(transition.record.stepID) ||
			!validProtectedRef(transition.record.attemptID) || !validStepAuthority(transition.record.authority) ||
			!validDigest(transition.record.operationSHA256) {
			return consumptionTransition{}, false, ErrIntegrity
		}
		wantRecord, hmacErr = consumptionRecordHMAC(key, transition.record)
	} else if transition.eventKind == eventRevoke {
		parsedRevokedAt, parseErr := parseTime(revokedAt)
		if parseErr != nil || !validDigest(newAuthorizationHMAC) || transition.record.operationSHA256 != newAuthorizationHMAC {
			return consumptionTransition{}, false, ErrIntegrity
		}
		transition.revocation = revocationRecord{
			authorizationID: transition.record.authorizationID, revokedAt: parsedRevokedAt,
			previousAuthorizationHMAC: transition.authorizationHMAC, newAuthorizationHMAC: newAuthorizationHMAC,
			anchorGeneration: transition.record.anchorGeneration, previousAnchorSHA: transition.record.previousAnchorSHA,
			anchorSHA: transition.record.anchorSHA, recordHMAC: transition.record.recordHMAC,
		}
		wantRecord, hmacErr = revocationRecordHMAC(key, transition.revocation)
	} else {
		return consumptionTransition{}, false, ErrIntegrity
	}
	wantTransition, transitionErr := transitionHMAC(key, transition)
	if hmacErr != nil || transitionErr != nil ||
		subtle.ConstantTimeCompare([]byte(wantRecord), []byte(transition.record.recordHMAC)) != 1 ||
		subtle.ConstantTimeCompare([]byte(wantTransition), []byte(transition.transitionHMAC)) != 1 {
		return consumptionTransition{}, false, ErrIntegrity
	}
	return transition, true, nil
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || formatTime(parsed) != value {
		return time.Time{}, ErrIntegrity
	}
	return parsed, nil
}

func verifyDatabaseShape(database *sql.DB) error {
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != databaseVersion {
		return ErrSchema
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != databaseApplicationID {
		return ErrSchema
	}
	var integrity string
	if err := database.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrIntegrity
	}
	rows, err := database.Query(`SELECT name,sql FROM sqlite_master
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
		actual[name] = normalizeSQL(statement)
	}
	if err := rows.Err(); err != nil || len(actual) != 5 ||
		actual["authority_key"] != normalizeSQL(createKeySQL) ||
		actual["execution_authorizations"] != normalizeSQL(createAuthorizationsSQL) ||
		actual["execution_consumptions"] != normalizeSQL(createConsumptionsSQL) ||
		actual["execution_revocations"] != normalizeSQL(createRevocationsSQL) ||
		actual["execution_consumption_pending"] != normalizeSQL(createConsumptionPendingSQL) {
		return ErrSchema
	}
	return nil
}

func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}
