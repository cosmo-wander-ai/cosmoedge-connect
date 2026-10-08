package inspectionfixture

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	_ "modernc.org/sqlite"
)

const (
	fixtureCredentialApplicationID = 0x46435331 // FCS1
	fixtureCredentialVersion       = 1
	fixtureMaximumSecretBytes      = 4096
)

type fixtureCredentialStore struct {
	mu  sync.Mutex
	db  *sql.DB
	key []byte
}

// openFixtureCredentialStore is an offline-fixture credential backend, not a
// device credential backend. It durably preserves only the execution
// authority envelope, encrypted by key material derived from the protected
// channel token. The raw channel token itself never reaches this store.
func openFixtureCredentialStore(path string, key []byte) (*fixtureCredentialStore, error) {
	if len(key) != 32 {
		return nil, errors.New("fixture credential key is invalid")
	}
	absolute, err := filepath.Abs(path)
	if err != nil || absolute == string(os.PathSeparator) {
		return nil, errors.New("fixture credential path is invalid")
	}
	if err := localstate.PrepareStateRoot(filepath.Dir(absolute)); err != nil {
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
		if err := localstate.ProtectFile(absolute); err != nil {
			_ = os.Remove(absolute)
			return nil, err
		}
		created = true
	} else if err != nil {
		return nil, err
	} else if err := localstate.ValidateFile(absolute); err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		if created {
			_ = os.Remove(absolute)
		}
		return nil, err
	}
	database.SetMaxOpenConns(1)
	store := &fixtureCredentialStore{db: database, key: append([]byte(nil), key...)}
	if err := store.initialize(created); err != nil {
		_ = store.Close()
		if created {
			_ = os.Remove(absolute)
		}
		return nil, err
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (s *fixtureCredentialStore) initialize(created bool) error {
	if _, err := s.db.Exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000`); err != nil {
		return err
	}
	var applicationID, version int
	if err := s.db.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return err
	}
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if created {
		if applicationID != 0 || version != 0 {
			return errors.New("new fixture credential state was not empty")
		}
		transaction, err := s.db.Begin()
		if err != nil {
			return err
		}
		fail := func(cause error) error {
			return errors.Join(cause, transaction.Rollback())
		}
		statements := []string{
			`CREATE TABLE secrets(ref TEXT PRIMARY KEY, encrypted BLOB NOT NULL CHECK(length(encrypted)>0))`,
			`CREATE TABLE puts(operation_id TEXT PRIMARY KEY, ref TEXT NOT NULL UNIQUE, phase TEXT NOT NULL CHECK(phase IN ('committed','rolled_back')))`,
			`CREATE TABLE rotations(operation_id TEXT PRIMARY KEY, old_ref TEXT NOT NULL UNIQUE, new_ref TEXT NOT NULL UNIQUE, phase TEXT NOT NULL CHECK(phase IN ('committed','rolled_back')))`,
			`PRAGMA application_id=1178817329`,
			`PRAGMA user_version=1`,
		}
		for _, statement := range statements {
			if _, err := transaction.Exec(statement); err != nil {
				return fail(err)
			}
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		applicationID, version = fixtureCredentialApplicationID, fixtureCredentialVersion
	}
	if applicationID != fixtureCredentialApplicationID || version != fixtureCredentialVersion {
		return errors.New("fixture credential state schema is unsupported")
	}
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	sort.Strings(names)
	if len(names) != 3 || names[0] != "puts" || names[1] != "rotations" || names[2] != "secrets" {
		return errors.New("fixture credential state shape is unsupported")
	}
	return nil
}

func (s *fixtureCredentialStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.key = nil
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *fixtureCredentialStore) Put(ctx context.Context, operationID credential.PutOperationID, secret []byte) (credential.PutReceipt, error) {
	if err := fixtureCredentialContext(ctx); err != nil {
		return credential.PutReceipt{}, err
	}
	if !operationID.Valid() {
		return credential.PutReceipt{}, credential.ErrInvalidPutOperationID
	}
	if len(secret) < 1 || len(secret) > fixtureMaximumSecretBytes {
		return credential.PutReceipt{}, credential.ErrInvalidSecret
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if receipt, err := s.putReceiptLocked(ctx, operationID); err == nil {
		return receipt, nil
	} else if !errors.Is(err, credential.ErrNotFound) {
		return credential.PutReceipt{}, err
	}
	ref, err := newFixtureCredentialRef()
	if err != nil {
		return credential.PutReceipt{}, err
	}
	encrypted, err := s.encrypt(ref, secret)
	if err != nil {
		return credential.PutReceipt{}, err
	}
	defer clear(encrypted)
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return credential.PutReceipt{}, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO secrets(ref,encrypted) VALUES(?,?)`, ref.ProtectedValue(), encrypted); err != nil {
		_ = transaction.Rollback()
		return credential.PutReceipt{}, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO puts(operation_id,ref,phase) VALUES(?,?,'committed')`, operationID.ProtectedValue(), ref.ProtectedValue()); err != nil {
		_ = transaction.Rollback()
		return credential.PutReceipt{}, err
	}
	if err := transaction.Commit(); err != nil {
		return credential.PutReceipt{}, err
	}
	return credential.PutReceipt{OperationID: operationID, Ref: ref, Phase: credential.PutCommitted}, nil
}

func (s *fixtureCredentialStore) PutByOperationID(ctx context.Context, operationID credential.PutOperationID) (credential.PutReceipt, error) {
	if err := fixtureCredentialContext(ctx); err != nil {
		return credential.PutReceipt{}, err
	}
	if !operationID.Valid() {
		return credential.PutReceipt{}, credential.ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putReceiptLocked(ctx, operationID)
}

func (s *fixtureCredentialStore) RecoverPut(ctx context.Context, operationID credential.PutOperationID) (credential.PutReceipt, error) {
	return s.PutByOperationID(ctx, operationID)
}

func (s *fixtureCredentialStore) CompensatePut(ctx context.Context, operationID credential.PutOperationID) (credential.PutReceipt, error) {
	if err := fixtureCredentialContext(ctx); err != nil {
		return credential.PutReceipt{}, err
	}
	if !operationID.Valid() {
		return credential.PutReceipt{}, credential.ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.putReceiptLocked(ctx, operationID)
	if err != nil || receipt.Phase == credential.PutRolledBack {
		return receipt, err
	}
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return credential.PutReceipt{}, err
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM secrets WHERE ref=?`, receipt.Ref.ProtectedValue()); err != nil {
		_ = transaction.Rollback()
		return credential.PutReceipt{}, err
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE puts SET phase='rolled_back' WHERE operation_id=?`, operationID.ProtectedValue()); err != nil {
		_ = transaction.Rollback()
		return credential.PutReceipt{}, err
	}
	if err := transaction.Commit(); err != nil {
		return credential.PutReceipt{}, err
	}
	receipt.Phase = credential.PutRolledBack
	return receipt, nil
}

func (s *fixtureCredentialStore) AcknowledgePut(ctx context.Context, operationID credential.PutOperationID) error {
	if err := fixtureCredentialContext(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return credential.ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.ExecContext(ctx, `DELETE FROM puts WHERE operation_id=? AND phase IN ('committed','rolled_back')`, operationID.ProtectedValue())
	if err != nil {
		return err
	}
	_, err = result.RowsAffected()
	return err
}

func (s *fixtureCredentialStore) Get(ctx context.Context, ref credential.Ref) ([]byte, error) {
	if err := fixtureCredentialContext(ctx); err != nil {
		return nil, err
	}
	if !ref.Valid() {
		return nil, credential.ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var encrypted []byte
	if err := s.db.QueryRowContext(ctx, `SELECT encrypted FROM secrets WHERE ref=?`, ref.ProtectedValue()).Scan(&encrypted); errors.Is(err, sql.ErrNoRows) {
		return nil, credential.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	defer clear(encrypted)
	return s.decrypt(ref, encrypted)
}

func (s *fixtureCredentialStore) Delete(ctx context.Context, ref credential.Ref) error {
	if err := fixtureCredentialContext(ctx); err != nil {
		return err
	}
	if !ref.Valid() {
		return credential.ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE ref=?`, ref.ProtectedValue())
	return err
}

func (s *fixtureCredentialStore) Rotate(ctx context.Context, old credential.Ref, secret []byte) (credential.RotationReceipt, error) {
	if err := fixtureCredentialContext(ctx); err != nil {
		return credential.RotationReceipt{}, err
	}
	if !old.Valid() {
		return credential.RotationReceipt{}, credential.ErrInvalidRef
	}
	if len(secret) < 1 || len(secret) > fixtureMaximumSecretBytes {
		return credential.RotationReceipt{}, credential.ErrInvalidSecret
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if receipt, err := s.rotationByOldLocked(ctx, old); err == nil {
		return receipt, nil
	} else if !errors.Is(err, credential.ErrNotFound) {
		return credential.RotationReceipt{}, err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE ref=?`, old.ProtectedValue()).Scan(&exists); err != nil {
		return credential.RotationReceipt{}, err
	}
	if exists != 1 {
		return credential.RotationReceipt{}, credential.ErrNotFound
	}
	newRef, err := newFixtureCredentialRef()
	if err != nil {
		return credential.RotationReceipt{}, err
	}
	rotationID, err := newFixtureRotationID()
	if err != nil {
		return credential.RotationReceipt{}, err
	}
	encrypted, err := s.encrypt(newRef, secret)
	if err != nil {
		return credential.RotationReceipt{}, err
	}
	defer clear(encrypted)
	transaction, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return credential.RotationReceipt{}, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO secrets(ref,encrypted) VALUES(?,?)`, newRef.ProtectedValue(), encrypted); err != nil {
		_ = transaction.Rollback()
		return credential.RotationReceipt{}, err
	}
	if result, err := transaction.ExecContext(ctx, `DELETE FROM secrets WHERE ref=?`, old.ProtectedValue()); err != nil {
		_ = transaction.Rollback()
		return credential.RotationReceipt{}, err
	} else if changed, countErr := result.RowsAffected(); countErr != nil || changed != 1 {
		_ = transaction.Rollback()
		return credential.RotationReceipt{}, errors.Join(credential.ErrNotFound, countErr)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO rotations(operation_id,old_ref,new_ref,phase) VALUES(?,?,?,'committed')`, rotationID.ProtectedValue(), old.ProtectedValue(), newRef.ProtectedValue()); err != nil {
		_ = transaction.Rollback()
		return credential.RotationReceipt{}, err
	}
	if err := transaction.Commit(); err != nil {
		return credential.RotationReceipt{}, err
	}
	return credential.RotationReceipt{OperationID: rotationID, OldRef: old, NewRef: newRef, Phase: credential.RotationCommitted}, nil
}

func (s *fixtureCredentialStore) RotationByOldRef(ctx context.Context, old credential.Ref) (credential.RotationReceipt, error) {
	if err := fixtureCredentialContext(ctx); err != nil {
		return credential.RotationReceipt{}, err
	}
	if !old.Valid() {
		return credential.RotationReceipt{}, credential.ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotationByOldLocked(ctx, old)
}

func (s *fixtureCredentialStore) RecoverRotation(ctx context.Context, operationID credential.RotationID) (credential.RotationReceipt, error) {
	if err := fixtureCredentialContext(ctx); err != nil {
		return credential.RotationReceipt{}, err
	}
	if !operationID.Valid() {
		return credential.RotationReceipt{}, credential.ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotationReceiptLocked(ctx, operationID)
}

func (s *fixtureCredentialStore) AcknowledgeRotation(ctx context.Context, operationID credential.RotationID) error {
	if err := fixtureCredentialContext(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return credential.ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `DELETE FROM rotations WHERE operation_id=? AND phase IN ('committed','rolled_back')`, operationID.ProtectedValue())
	return err
}

func (s *fixtureCredentialStore) putReceiptLocked(ctx context.Context, operationID credential.PutOperationID) (credential.PutReceipt, error) {
	var refValue, phaseValue string
	if err := s.db.QueryRowContext(ctx, `SELECT ref,phase FROM puts WHERE operation_id=?`, operationID.ProtectedValue()).Scan(&refValue, &phaseValue); errors.Is(err, sql.ErrNoRows) {
		return credential.PutReceipt{}, credential.ErrNotFound
	} else if err != nil {
		return credential.PutReceipt{}, err
	}
	ref, err := credential.ParseRef(refValue)
	if err != nil {
		return credential.PutReceipt{}, errors.New("fixture credential put receipt is invalid")
	}
	phase, err := parseFixturePutPhase(phaseValue)
	if err != nil {
		return credential.PutReceipt{}, err
	}
	return credential.PutReceipt{OperationID: operationID, Ref: ref, Phase: phase}, nil
}

func (s *fixtureCredentialStore) rotationByOldLocked(ctx context.Context, old credential.Ref) (credential.RotationReceipt, error) {
	var operationValue string
	if err := s.db.QueryRowContext(ctx, `SELECT operation_id FROM rotations WHERE old_ref=?`, old.ProtectedValue()).Scan(&operationValue); errors.Is(err, sql.ErrNoRows) {
		return credential.RotationReceipt{}, credential.ErrNotFound
	} else if err != nil {
		return credential.RotationReceipt{}, err
	}
	operationID, err := credential.ParseRotationID(operationValue)
	if err != nil {
		return credential.RotationReceipt{}, errors.New("fixture credential rotation receipt is invalid")
	}
	return s.rotationReceiptLocked(ctx, operationID)
}

func (s *fixtureCredentialStore) rotationReceiptLocked(ctx context.Context, operationID credential.RotationID) (credential.RotationReceipt, error) {
	var oldValue, newValue, phaseValue string
	if err := s.db.QueryRowContext(ctx, `SELECT old_ref,new_ref,phase FROM rotations WHERE operation_id=?`, operationID.ProtectedValue()).Scan(&oldValue, &newValue, &phaseValue); errors.Is(err, sql.ErrNoRows) {
		return credential.RotationReceipt{}, credential.ErrNotFound
	} else if err != nil {
		return credential.RotationReceipt{}, err
	}
	oldRef, oldErr := credential.ParseRef(oldValue)
	newRef, newErr := credential.ParseRef(newValue)
	phase, phaseErr := parseFixtureRotationPhase(phaseValue)
	if err := errors.Join(oldErr, newErr, phaseErr); err != nil || oldRef == newRef {
		return credential.RotationReceipt{}, errors.Join(errors.New("fixture credential rotation receipt is invalid"), err)
	}
	return credential.RotationReceipt{OperationID: operationID, OldRef: oldRef, NewRef: newRef, Phase: phase}, nil
}

func (s *fixtureCredentialStore) encrypt(ref credential.Ref, secret []byte) ([]byte, error) {
	aead, err := fixtureAEAD(s.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, secret, []byte(ref.ProtectedValue())), nil
}

func (s *fixtureCredentialStore) decrypt(ref credential.Ref, encrypted []byte) ([]byte, error) {
	aead, err := fixtureAEAD(s.key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) <= aead.NonceSize() {
		return nil, errors.New("fixture credential ciphertext is invalid")
	}
	plain, err := aead.Open(nil, encrypted[:aead.NonceSize()], encrypted[aead.NonceSize():], []byte(ref.ProtectedValue()))
	if err != nil || len(plain) < 1 || len(plain) > fixtureMaximumSecretBytes {
		clear(plain)
		return nil, errors.New("fixture credential ciphertext failed authentication")
	}
	return plain, nil
}

func fixtureAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newFixtureCredentialRef() (credential.Ref, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	value := "cred_" + hex.EncodeToString(random)
	clear(random)
	return credential.ParseRef(value)
}

func newFixtureRotationID() (credential.RotationID, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	value := "cro_" + hex.EncodeToString(random)
	clear(random)
	return credential.ParseRotationID(value)
}

func parseFixturePutPhase(value string) (credential.PutPhase, error) {
	switch credential.PutPhase(value) {
	case credential.PutCommitted:
		return credential.PutCommitted, nil
	case credential.PutRolledBack:
		return credential.PutRolledBack, nil
	default:
		return "", errors.New("fixture credential put phase is invalid")
	}
}

func parseFixtureRotationPhase(value string) (credential.RotationPhase, error) {
	switch credential.RotationPhase(value) {
	case credential.RotationCommitted:
		return credential.RotationCommitted, nil
	case credential.RotationRolledBack:
		return credential.RotationRolledBack, nil
	default:
		return "", errors.New("fixture credential rotation phase is invalid")
	}
}

func fixtureCredentialContext(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ credential.SecretStore = (*fixtureCredentialStore)(nil)
