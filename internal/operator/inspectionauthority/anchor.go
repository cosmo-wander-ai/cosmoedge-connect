package inspectionauthority

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	coreauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
)

const (
	eventConsume       = "consume"
	eventRevoke        = "revoke"
	transitionPrepared = "prepared"
	transitionApplied  = "applied"
)

type consumptionTransition struct {
	eventKind         string
	record            consumptionRecord
	revocation        revocationRecord
	authorizationHMAC string
	oldRef            credential.Ref
	newRef            credential.Ref
	rotationID        credential.RotationID
	phase             string
	transitionHMAC    string
}

type revocationRecord struct {
	authorizationID           string
	revokedAt                 time.Time
	previousAuthorizationHMAC string
	newAuthorizationHMAC      string
	anchorGeneration          uint64
	previousAnchorSHA         string
	anchorSHA                 string
	recordHMAC                string
}

func (b *DurableBroker) validateAnchoredState(ctx context.Context) error {
	state, found, err := readKeyRecord(ctx, b.db)
	if err != nil || !found || state.phase != keyAttached ||
		subtle.ConstantTimeCompare([]byte(keyStateHMAC(b.key, state)), []byte(state.recordHMAC)) != 1 {
		return errors.Join(ErrIntegrity, err)
	}
	return validateConsumptionChain(ctx, b.db, b.key, state)
}

func (transition consumptionTransition) generation() uint64 {
	if transition.eventKind == eventRevoke {
		return transition.revocation.anchorGeneration
	}
	return transition.record.anchorGeneration
}

func (transition consumptionTransition) previousAnchor() string {
	if transition.eventKind == eventRevoke {
		return transition.revocation.previousAnchorSHA
	}
	return transition.record.previousAnchorSHA
}

func (transition consumptionTransition) anchor() string {
	if transition.eventKind == eventRevoke {
		return transition.revocation.anchorSHA
	}
	return transition.record.anchorSHA
}

func (transition consumptionTransition) eventRecordHMAC() string {
	if transition.eventKind == eventRevoke {
		return transition.revocation.recordHMAC
	}
	return transition.record.recordHMAC
}

func (b *DurableBroker) consumeAnchored(ctx context.Context, supplied coreauthority.Authorization, demand coreauthority.StepDemand, at time.Time) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	lock, err := acquireSagaLock(b.path)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := recoverPendingConsumption(ctx, b.db, b.secrets, b.key); err != nil {
		return err
	}
	authorization, err := loadAuthorization(ctx, b.db, b.key, demand.RunID)
	if err != nil || !sameAuthorization(authorization.authorization, supplied) || !authorization.revokedAt.IsZero() {
		return coreauthority.ErrUnauthorized
	}
	keyState, found, err := readKeyRecord(ctx, b.db)
	if err != nil || !found || keyState.phase != keyAttached ||
		subtle.ConstantTimeCompare([]byte(keyStateHMAC(b.key, keyState)), []byte(keyState.recordHMAC)) != 1 {
		return errors.Join(coreauthority.ErrUnauthorized, ErrIntegrity, err)
	}
	if err := validateConsumptionChain(ctx, b.db, b.key, keyState); err != nil {
		return errors.Join(coreauthority.ErrUnauthorized, err)
	}
	var alreadyConsumed int
	if err := b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_consumptions
		WHERE authorization_id=? AND step_id=? AND attempt_id=?`, supplied.AuthorizationID, demand.StepID,
		demand.AttemptID).Scan(&alreadyConsumed); err != nil {
		return err
	}
	if alreadyConsumed != 0 {
		return coreauthority.ErrUnauthorized
	}
	record, err := newAnchoredConsumptionRecord(b.key, supplied.AuthorizationID, demand, at, keyState)
	if err != nil {
		return coreauthority.ErrUnauthorized
	}
	transition := consumptionTransition{eventKind: eventConsume, record: record, authorizationHMAC: authorization.recordHMAC,
		oldRef: keyState.ref, phase: transitionPrepared}
	transition.transitionHMAC, err = transitionHMAC(b.key, transition)
	if err != nil {
		return err
	}
	result, err := b.db.ExecContext(ctx, `INSERT OR IGNORE INTO execution_consumption_pending (
		singleton,event_kind,authorization_id,authorization_hmac,step_id,attempt_id,authority,operation_sha256,consumed_at,anchor_generation,
		previous_anchor_sha256,anchor_sha256,record_hmac,revoked_at,new_authorization_hmac,
		old_credential_ref,new_credential_ref,rotation_id,phase,transition_hmac)
		VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,? ,?,'','','prepared',?)`, pendingValues(transition)...)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted != 1 {
		// A committed replay has no pending row; a live pending row must be
		// recovered before a new demand is considered.
		if err := recoverPendingConsumption(ctx, b.db, b.secrets, b.key); err != nil {
			return err
		}
		return coreauthority.ErrUnauthorized
	}
	if err := recoverPendingConsumption(ctx, b.db, b.secrets, b.key); err != nil {
		return err
	}
	return nil
}

func (b *DurableBroker) revokeAnchoredLocked(ctx context.Context, authorization authorizationRecord, revokedAt time.Time) error {
	keyState, found, err := readKeyRecord(ctx, b.db)
	if err != nil || !found || keyState.phase != keyAttached ||
		subtle.ConstantTimeCompare([]byte(keyStateHMAC(b.key, keyState)), []byte(keyState.recordHMAC)) != 1 {
		return errors.Join(ErrIntegrity, err)
	}
	if err := validateConsumptionChain(ctx, b.db, b.key, keyState); err != nil {
		return err
	}
	revocation, newAuthorization, err := newRevocationRecord(b.key, authorization, revokedAt, keyState)
	if err != nil {
		return err
	}
	transition := consumptionTransition{
		eventKind: eventRevoke, revocation: revocation, authorizationHMAC: authorization.recordHMAC,
		oldRef: keyState.ref, phase: transitionPrepared,
	}
	// The proposed authorization HMAC is persisted in the protected pending
	// transition and applied atomically with the anchor promotion.
	transition.revocation.newAuthorizationHMAC = newAuthorization.recordHMAC
	transition.transitionHMAC, err = transitionHMAC(b.key, transition)
	if err != nil {
		return err
	}
	result, err := b.db.ExecContext(ctx, `INSERT OR IGNORE INTO execution_consumption_pending (
		singleton,event_kind,authorization_id,authorization_hmac,step_id,attempt_id,authority,operation_sha256,consumed_at,anchor_generation,
		previous_anchor_sha256,anchor_sha256,record_hmac,revoked_at,new_authorization_hmac,
		old_credential_ref,new_credential_ref,rotation_id,phase,transition_hmac)
		VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'','','prepared',?)`, pendingValues(transition)...)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted != 1 {
		return ErrIntegrity
	}
	return recoverPendingConsumption(ctx, b.db, b.secrets, b.key)
}

func newRevocationRecord(key []byte, authorization authorizationRecord, revokedAt time.Time, state keyRecord) (revocationRecord, authorizationRecord, error) {
	updated := authorization
	updated.revokedAt = revokedAt.UTC()
	var err error
	updated.recordHMAC, err = authorizationRecordHMAC(key, updated)
	if err != nil {
		return revocationRecord{}, authorizationRecord{}, err
	}
	record := revocationRecord{
		authorizationID: authorization.authorization.AuthorizationID, revokedAt: updated.revokedAt,
		previousAuthorizationHMAC: authorization.recordHMAC, newAuthorizationHMAC: updated.recordHMAC,
		anchorGeneration: state.generation + 1, previousAnchorSHA: state.anchorSHA,
	}
	record.anchorSHA, err = revocationAnchor(key, record)
	if err != nil {
		return revocationRecord{}, authorizationRecord{}, err
	}
	record.recordHMAC, err = revocationRecordHMAC(key, record)
	return record, updated, err
}

func revocationAnchor(key []byte, record revocationRecord) (string, error) {
	raw := []byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s\x00%s", record.anchorGeneration,
		record.previousAnchorSHA, record.authorizationID, formatTime(record.revokedAt),
		record.previousAuthorizationHMAC, record.newAuthorizationHMAC))
	return keyedDigest(key, revocationAnchorDomain, raw), nil
}

func revocationRecordHMAC(key []byte, record revocationRecord) (string, error) {
	raw := []byte(record.authorizationID + "\x00" + formatTime(record.revokedAt) + "\x00" +
		record.previousAuthorizationHMAC + "\x00" + record.newAuthorizationHMAC + "\x00" +
		fmt.Sprint(record.anchorGeneration) + "\x00" + record.previousAnchorSHA + "\x00" + record.anchorSHA)
	return keyedDigest(key, revocationRecordDomain, raw), nil
}

func recoverPendingConsumption(ctx context.Context, database *sql.DB, secrets credential.SecretStore, key []byte) error {
	transition, found, err := loadPendingTransition(ctx, database, key)
	if err != nil || !found {
		return err
	}
	keyState, keyFound, err := readKeyRecord(ctx, database)
	if err != nil || !keyFound || keyState.phase != keyAttached {
		return errors.Join(ErrIntegrity, err)
	}
	switch transition.phase {
	case transitionApplied:
		if keyState.ref != transition.newRef || keyState.generation != transition.generation() ||
			keyState.anchorSHA != transition.anchor() {
			return ErrIntegrity
		}
		if err := acknowledgeRotation(ctx, secrets, transition); err != nil {
			return err
		}
		_, err := database.ExecContext(ctx, `DELETE FROM execution_consumption_pending
			WHERE singleton=1 AND transition_hmac=?`, transition.transitionHMAC)
		return err
	case transitionPrepared:
		if keyState.ref != transition.oldRef || keyState.generation+1 != transition.generation() ||
			keyState.anchorSHA != transition.previousAnchor() {
			return ErrIntegrity
		}
	default:
		return ErrIntegrity
	}
	receipt, err := rotateAnchor(ctx, secrets, key, transition)
	if err != nil {
		return err
	}
	raw, err := secrets.Get(ctx, receipt.NewRef)
	if err != nil {
		clearBytes(raw)
		return errors.Join(ErrKeyUnavailable, err)
	}
	rotatedKey, generation, anchorSHA, decodeErr := decodeSecretEnvelope(raw)
	clearBytes(raw)
	if decodeErr != nil || subtle.ConstantTimeCompare(rotatedKey, key) != 1 ||
		generation != transition.generation() || anchorSHA != transition.anchor() {
		clearBytes(rotatedKey)
		return errors.Join(ErrIntegrity, decodeErr)
	}
	clearBytes(rotatedKey)
	transition.newRef = receipt.NewRef
	transition.rotationID = receipt.OperationID
	transition.phase = transitionApplied
	transition.transitionHMAC, err = transitionHMAC(key, transition)
	if err != nil {
		return err
	}
	newKeyState := keyState
	newKeyState.ref = receipt.NewRef
	newKeyState.generation = transition.generation()
	newKeyState.anchorSHA = transition.anchor()
	newKeyState.recordHMAC = keyStateHMAC(key, newKeyState)
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	fail := func(applyErr error) error {
		_ = transaction.Rollback()
		return applyErr
	}
	var result sql.Result
	if transition.eventKind == eventConsume {
		result, err = transaction.ExecContext(ctx, insertConsumptionSQL,
			consumptionRecordValues(transition.record, transition.authorizationHMAC)...)
		if err != nil {
			return fail(err)
		}
		inserted, rowsErr := result.RowsAffected()
		if rowsErr != nil || inserted != 1 {
			return fail(errors.Join(ErrIntegrity, rowsErr))
		}
	} else if transition.eventKind == eventRevoke {
		result, err = transaction.ExecContext(ctx, `UPDATE execution_authorizations SET revoked_at=?,record_hmac=?
			WHERE authorization_id=? AND record_hmac=? AND revoked_at=''`, formatTime(transition.revocation.revokedAt),
			transition.revocation.newAuthorizationHMAC, transition.revocation.authorizationID,
			transition.revocation.previousAuthorizationHMAC)
		if err != nil {
			return fail(err)
		}
		updated, rowsErr := result.RowsAffected()
		if rowsErr != nil || updated != 1 {
			return fail(errors.Join(ErrIntegrity, rowsErr))
		}
		result, err = transaction.ExecContext(ctx, `INSERT INTO execution_revocations (
			authorization_id,revoked_at,previous_authorization_hmac,new_authorization_hmac,anchor_generation,
			previous_anchor_sha256,anchor_sha256,record_hmac) VALUES (?,?,?,?,?,?,?,?)`,
			transition.revocation.authorizationID, formatTime(transition.revocation.revokedAt),
			transition.revocation.previousAuthorizationHMAC, transition.revocation.newAuthorizationHMAC,
			transition.revocation.anchorGeneration, transition.revocation.previousAnchorSHA,
			transition.revocation.anchorSHA, transition.revocation.recordHMAC)
		if err != nil {
			return fail(err)
		}
	} else {
		return fail(ErrIntegrity)
	}
	result, err = transaction.ExecContext(ctx, `UPDATE authority_key SET credential_ref=?,anchor_generation=?,
		anchor_sha256=?,record_hmac=? WHERE singleton=1 AND credential_ref=? AND anchor_generation=? AND
		anchor_sha256=? AND record_hmac=?`, newKeyState.ref.ProtectedValue(), newKeyState.generation,
		newKeyState.anchorSHA, newKeyState.recordHMAC, keyState.ref.ProtectedValue(), keyState.generation,
		keyState.anchorSHA, keyState.recordHMAC)
	if err != nil {
		return fail(err)
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return fail(errors.Join(ErrIntegrity, err))
	}
	result, err = transaction.ExecContext(ctx, `UPDATE execution_consumption_pending SET
		new_credential_ref=?,rotation_id=?,phase='applied',transition_hmac=?
		WHERE singleton=1 AND phase='prepared'`, transition.newRef.ProtectedValue(),
		transition.rotationID.ProtectedValue(), transition.transitionHMAC)
	if err != nil {
		return fail(err)
	}
	updated, err = result.RowsAffected()
	if err != nil || updated != 1 {
		return fail(errors.Join(ErrIntegrity, err))
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	if err := acknowledgeRotation(ctx, secrets, transition); err != nil {
		// The current secret and consumption are already atomically attached.
		// Leave the applied transition for deterministic startup cleanup.
		return nil
	}
	_, err = database.ExecContext(ctx, `DELETE FROM execution_consumption_pending
		WHERE singleton=1 AND transition_hmac=?`, transition.transitionHMAC)
	return err
}

func rotateAnchor(ctx context.Context, secrets credential.SecretStore, key []byte, transition consumptionTransition) (credential.RotationReceipt, error) {
	receipt, err := secrets.RotationByOldRef(ctx, transition.oldRef)
	if errors.Is(err, credential.ErrNotFound) {
		envelope, encodeErr := encodeSecretEnvelope(key, transition.generation(), transition.anchor())
		if encodeErr != nil {
			return credential.RotationReceipt{}, encodeErr
		}
		receipt, err = secrets.Rotate(ctx, transition.oldRef, envelope)
		clearBytes(envelope)
	} else if err != nil {
		return credential.RotationReceipt{}, err
	}
	if !receipt.Valid() || receipt.OldRef != transition.oldRef {
		return credential.RotationReceipt{}, ErrKeyUnavailable
	}
	if receipt.Phase != credential.RotationCommitted {
		receipt, err = secrets.RecoverRotation(ctx, receipt.OperationID)
	}
	if receipt.Phase == credential.RotationRolledBack {
		if ackErr := secrets.AcknowledgeRotation(ctx, receipt.OperationID); ackErr != nil {
			return credential.RotationReceipt{}, ackErr
		}
		envelope, encodeErr := encodeSecretEnvelope(key, transition.generation(), transition.anchor())
		if encodeErr != nil {
			return credential.RotationReceipt{}, encodeErr
		}
		receipt, err = secrets.Rotate(ctx, transition.oldRef, envelope)
		clearBytes(envelope)
	}
	if err != nil || !receipt.Valid() || receipt.OldRef != transition.oldRef || receipt.Phase != credential.RotationCommitted {
		return credential.RotationReceipt{}, errors.Join(ErrKeyUnavailable, err)
	}
	return receipt, nil
}

func acknowledgeRotation(ctx context.Context, secrets credential.SecretStore, transition consumptionTransition) error {
	receipt, err := secrets.RecoverRotation(ctx, transition.rotationID)
	if errors.Is(err, credential.ErrNotFound) {
		return nil
	}
	if err != nil || !receipt.Valid() || receipt.OperationID != transition.rotationID ||
		receipt.OldRef != transition.oldRef || receipt.NewRef != transition.newRef || receipt.Phase != credential.RotationCommitted {
		return errors.Join(ErrKeyUnavailable, err)
	}
	return secrets.AcknowledgeRotation(ctx, transition.rotationID)
}

func newAnchoredConsumptionRecord(key []byte, authorizationID string, demand coreauthority.StepDemand, at time.Time, state keyRecord) (consumptionRecord, error) {
	record, err := newConsumptionRecord(authorizationID, demand, at)
	if err != nil {
		return consumptionRecord{}, err
	}
	record.anchorGeneration = state.generation + 1
	record.previousAnchorSHA = state.anchorSHA
	record.anchorSHA, err = consumptionAnchor(key, record)
	if err != nil {
		return consumptionRecord{}, err
	}
	record.recordHMAC, err = consumptionRecordHMAC(key, record)
	return record, err
}

func consumptionAnchor(key []byte, record consumptionRecord) (string, error) {
	raw := []byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		record.anchorGeneration, record.previousAnchorSHA, record.authorizationID, record.stepID,
		record.attemptID, record.operationSHA256, formatTime(record.consumedAt)))
	return keyedDigest(key, consumptionAnchorDomain, raw), nil
}

func transitionHMAC(key []byte, transition consumptionTransition) (string, error) {
	raw := []byte(transition.eventKind + "\x00" + transition.eventRecordHMAC() + "\x00" + transition.authorizationHMAC + "\x00" + transition.oldRef.ProtectedValue() + "\x00" +
		transition.newRef.ProtectedValue() + "\x00" + transition.rotationID.ProtectedValue() + "\x00" + transition.phase)
	return keyedDigest(key, consumptionTransitionDomain, raw), nil
}

func keyStateHMAC(key []byte, record keyRecord) string { return keyRecordHMAC(key, record) }
