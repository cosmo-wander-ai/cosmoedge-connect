package credential

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const (
	encryptedFileStoreVersion    = 1
	encryptedFileStoreMaxBytes   = 32 << 20
	encryptedFileStoreMaxRecords = 4096
	encryptedFileStoreMagic      = "CECRD001"
)

var (
	// ErrEncryptedFileStoreUnavailable deliberately omits the backing path and
	// underlying operating-system error. The store may be opened from a local
	// channel boundary whose errors are projected to an untrusted client.
	ErrEncryptedFileStoreUnavailable = errors.New("encrypted credential store is unavailable")
	// ErrEncryptedFileStoreIntegrity reports an authenticated state failure
	// without exposing a credential reference, ciphertext, key, or path.
	ErrEncryptedFileStoreIntegrity = errors.New("encrypted credential store integrity check failed")
)

type encryptedFilePut struct {
	Ref   string        `json:"ref"`
	Phase RotationPhase `json:"phase"`
}

type encryptedFileRotation struct {
	OldRef string        `json:"oldRef"`
	NewRef string        `json:"newRef"`
	Phase  RotationPhase `json:"phase"`
}

type encryptedFileState struct {
	Version   int                              `json:"version"`
	Secrets   map[string][]byte                `json:"secrets"`
	Puts      map[string]encryptedFilePut      `json:"puts"`
	Rotations map[string]encryptedFileRotation `json:"rotations"`
}

// EncryptedFileStore is a small, durable SecretStore intended for unattended
// local services that already own high-entropy key material. Every state
// transition rewrites one authenticated AES-GCM envelope through an owner-only
// temporary file and an atomic same-directory replacement.
//
// The caller owns key and may clear it as soon as OpenEncryptedFileStore
// returns. The store retains an independent copy until Close.
type EncryptedFileStore struct {
	mu     sync.Mutex
	path   string
	key    []byte
	state  encryptedFileState
	closed bool
}

// OpenEncryptedFileStore opens or creates an owner-only encrypted credential
// file. key must contain exactly 32 bytes of caller-derived, high-entropy key
// material. No raw credential or key material is persisted outside the AEAD
// envelope.
func OpenEncryptedFileStore(path string, key []byte) (*EncryptedFileStore, error) {
	if len(key) != 32 {
		return nil, ErrEncryptedFileStoreUnavailable
	}
	absolute, err := filepath.Abs(path)
	if err != nil || absolute == string(os.PathSeparator) || filepath.Dir(absolute) == absolute {
		return nil, ErrEncryptedFileStoreUnavailable
	}
	parent := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(parent); err != nil {
		return nil, ErrEncryptedFileStoreUnavailable
	}
	store := &EncryptedFileStore{path: absolute, key: append([]byte(nil), key...)}
	lock, err := acquireEncryptedFileLock(absolute)
	if err != nil {
		_ = store.Close()
		return nil, ErrEncryptedFileStoreUnavailable
	}
	defer lock.Close()
	if _, err := os.Lstat(absolute); errors.Is(err, os.ErrNotExist) {
		store.state = newEncryptedFileState()
		if err := store.writeStateLocked(store.state); err != nil {
			_ = store.Close()
			return nil, ErrEncryptedFileStoreUnavailable
		}
		return store, nil
	} else if err != nil {
		_ = store.Close()
		return nil, ErrEncryptedFileStoreUnavailable
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		_ = store.Close()
		return nil, ErrEncryptedFileStoreUnavailable
	}
	state, err := readEncryptedFileState(absolute, store.key)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	store.state = state
	return store, nil
}

func (s *EncryptedFileStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	clear(s.key)
	s.key = nil
	clearEncryptedFileState(&s.state)
	s.state = encryptedFileState{}
	return nil
}

func (s *EncryptedFileStore) Put(ctx context.Context, operationID PutOperationID, secret []byte) (PutReceipt, error) {
	if err := encryptedFileContext(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	if err := validateSecret(secret); err != nil {
		return PutReceipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return PutReceipt{}, err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return PutReceipt{}, err
	}
	defer lock.Close()
	if record, ok := s.state.Puts[operationID.ProtectedValue()]; ok {
		return putReceiptFromEncrypted(operationID, record)
	}
	ref, err := newRef()
	if err != nil {
		return PutReceipt{}, ErrEncryptedFileStoreUnavailable
	}
	candidate := cloneEncryptedFileState(s.state)
	candidate.Secrets[ref.ProtectedValue()] = append([]byte(nil), secret...)
	candidate.Puts[operationID.ProtectedValue()] = encryptedFilePut{Ref: ref.ProtectedValue(), Phase: PutCommitted}
	receipt := PutReceipt{OperationID: operationID, Ref: ref, Phase: PutCommitted}
	status := s.commitLocked(candidate)
	switch status {
	case encryptedCommitApplied:
		return receipt, nil
	case encryptedCommitNotApplied:
		return PutReceipt{}, ErrEncryptedFileStoreUnavailable
	default:
		return receipt, &OutcomeUnknownError{Operation: "put", NewRef: ref}
	}
}

func (s *EncryptedFileStore) PutByOperationID(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := encryptedFileContext(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return PutReceipt{}, err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return PutReceipt{}, err
	}
	defer lock.Close()
	record, ok := s.state.Puts[operationID.ProtectedValue()]
	if !ok {
		return PutReceipt{}, ErrNotFound
	}
	return putReceiptFromEncrypted(operationID, record)
}

func (s *EncryptedFileStore) RecoverPut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	return s.PutByOperationID(ctx, operationID)
}

func (s *EncryptedFileStore) CompensatePut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := encryptedFileContext(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return PutReceipt{}, err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return PutReceipt{}, err
	}
	defer lock.Close()
	record, ok := s.state.Puts[operationID.ProtectedValue()]
	if !ok {
		return PutReceipt{}, ErrNotFound
	}
	receipt, err := putReceiptFromEncrypted(operationID, record)
	if err != nil || receipt.Phase == PutRolledBack {
		return receipt, err
	}
	candidate := cloneEncryptedFileState(s.state)
	delete(candidate.Secrets, receipt.Ref.ProtectedValue())
	record.Phase = PutRolledBack
	candidate.Puts[operationID.ProtectedValue()] = record
	receipt.Phase = PutRolledBack
	switch s.commitLocked(candidate) {
	case encryptedCommitApplied:
		return receipt, nil
	case encryptedCommitNotApplied:
		return PutReceipt{}, ErrEncryptedFileStoreUnavailable
	default:
		return receipt, &OutcomeUnknownError{Operation: "delete", NewRef: receipt.Ref}
	}
}

func (s *EncryptedFileStore) AcknowledgePut(ctx context.Context, operationID PutOperationID) error {
	if err := encryptedFileContext(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, ok := s.state.Puts[operationID.ProtectedValue()]; !ok {
		return nil
	}
	candidate := cloneEncryptedFileState(s.state)
	delete(candidate.Puts, operationID.ProtectedValue())
	switch s.commitLocked(candidate) {
	case encryptedCommitApplied:
		return nil
	case encryptedCommitNotApplied:
		return ErrEncryptedFileStoreUnavailable
	default:
		return &OutcomeUnknownError{Operation: "delete"}
	}
}

func (s *EncryptedFileStore) Get(ctx context.Context, ref Ref) ([]byte, error) {
	if err := encryptedFileContext(ctx); err != nil {
		return nil, err
	}
	if !ref.Valid() {
		return nil, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return nil, err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	secret, ok := s.state.Secrets[ref.ProtectedValue()]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), secret...), nil
}

func (s *EncryptedFileStore) Delete(ctx context.Context, ref Ref) error {
	if err := encryptedFileContext(ctx); err != nil {
		return err
	}
	if !ref.Valid() {
		return ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, ok := s.state.Secrets[ref.ProtectedValue()]; !ok {
		return nil
	}
	candidate := cloneEncryptedFileState(s.state)
	delete(candidate.Secrets, ref.ProtectedValue())
	switch s.commitLocked(candidate) {
	case encryptedCommitApplied:
		return nil
	case encryptedCommitNotApplied:
		return ErrEncryptedFileStoreUnavailable
	default:
		return &OutcomeUnknownError{Operation: "delete", OldRef: ref}
	}
}

func (s *EncryptedFileStore) Rotate(ctx context.Context, old Ref, secret []byte) (RotationReceipt, error) {
	if err := encryptedFileContext(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !old.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	if err := validateSecret(secret); err != nil {
		return RotationReceipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return RotationReceipt{}, err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return RotationReceipt{}, err
	}
	defer lock.Close()
	if receipt, ok, err := s.rotationByOldLocked(old); ok || err != nil {
		return receipt, err
	}
	if _, ok := s.state.Secrets[old.ProtectedValue()]; !ok {
		return RotationReceipt{}, ErrNotFound
	}
	newReference, err := newRef()
	if err != nil {
		return RotationReceipt{}, ErrEncryptedFileStoreUnavailable
	}
	operationID, err := newRotationID()
	if err != nil {
		return RotationReceipt{}, ErrEncryptedFileStoreUnavailable
	}
	receipt := RotationReceipt{OperationID: operationID, OldRef: old, NewRef: newReference, Phase: RotationCommitted}
	candidate := cloneEncryptedFileState(s.state)
	delete(candidate.Secrets, old.ProtectedValue())
	candidate.Secrets[newReference.ProtectedValue()] = append([]byte(nil), secret...)
	candidate.Rotations[operationID.ProtectedValue()] = encryptedFileRotation{
		OldRef: old.ProtectedValue(), NewRef: newReference.ProtectedValue(), Phase: RotationCommitted,
	}
	switch s.commitLocked(candidate) {
	case encryptedCommitApplied:
		return receipt, nil
	case encryptedCommitNotApplied:
		return RotationReceipt{}, ErrEncryptedFileStoreUnavailable
	default:
		receipt.Phase = RotationUnknown
		return receipt, &OutcomeUnknownError{Operation: "rotate", OldRef: old, NewRef: newReference}
	}
}

func (s *EncryptedFileStore) RotationByOldRef(ctx context.Context, old Ref) (RotationReceipt, error) {
	if err := encryptedFileContext(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !old.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return RotationReceipt{}, err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return RotationReceipt{}, err
	}
	defer lock.Close()
	receipt, ok, err := s.rotationByOldLocked(old)
	if !ok && err == nil {
		return RotationReceipt{}, ErrNotFound
	}
	return receipt, err
}

func (s *EncryptedFileStore) RecoverRotation(ctx context.Context, operationID RotationID) (RotationReceipt, error) {
	if err := encryptedFileContext(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !operationID.Valid() {
		return RotationReceipt{}, ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return RotationReceipt{}, err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return RotationReceipt{}, err
	}
	defer lock.Close()
	record, ok := s.state.Rotations[operationID.ProtectedValue()]
	if !ok {
		return RotationReceipt{}, ErrNotFound
	}
	return rotationReceiptFromEncrypted(operationID, record)
}

func (s *EncryptedFileStore) AcknowledgeRotation(ctx context.Context, operationID RotationID) error {
	if err := encryptedFileContext(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.availableLocked(); err != nil {
		return err
	}
	lock, err := s.lockAndRefreshLocked()
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, ok := s.state.Rotations[operationID.ProtectedValue()]; !ok {
		return nil
	}
	candidate := cloneEncryptedFileState(s.state)
	delete(candidate.Rotations, operationID.ProtectedValue())
	switch s.commitLocked(candidate) {
	case encryptedCommitApplied:
		return nil
	case encryptedCommitNotApplied:
		return ErrEncryptedFileStoreUnavailable
	default:
		return &OutcomeUnknownError{Operation: "rotate"}
	}
}

func (s *EncryptedFileStore) rotationByOldLocked(old Ref) (RotationReceipt, bool, error) {
	for operationValue, record := range s.state.Rotations {
		if record.OldRef != old.ProtectedValue() {
			continue
		}
		operationID, err := ParseRotationID(operationValue)
		if err != nil {
			return RotationReceipt{}, true, ErrEncryptedFileStoreIntegrity
		}
		receipt, err := rotationReceiptFromEncrypted(operationID, record)
		return receipt, true, err
	}
	return RotationReceipt{}, false, nil
}

type encryptedCommitStatus uint8

const (
	encryptedCommitUnknown encryptedCommitStatus = iota
	encryptedCommitApplied
	encryptedCommitNotApplied
)

func (s *EncryptedFileStore) commitLocked(candidate encryptedFileState) encryptedCommitStatus {
	previous := s.state
	if err := s.writeStateLocked(candidate); err == nil {
		clearEncryptedFileState(&s.state)
		s.state = candidate
		return encryptedCommitApplied
	}
	reloaded, err := readEncryptedFileState(s.path, s.key)
	if err != nil {
		clearEncryptedFileState(&candidate)
		return encryptedCommitUnknown
	}
	switch {
	case reflect.DeepEqual(reloaded, candidate):
		clearEncryptedFileState(&s.state)
		s.state = reloaded
		clearEncryptedFileState(&candidate)
		return encryptedCommitApplied
	case reflect.DeepEqual(reloaded, previous):
		clearEncryptedFileState(&reloaded)
		clearEncryptedFileState(&candidate)
		return encryptedCommitNotApplied
	default:
		clearEncryptedFileState(&s.state)
		s.state = reloaded
		clearEncryptedFileState(&candidate)
		return encryptedCommitUnknown
	}
}

func (s *EncryptedFileStore) writeStateLocked(state encryptedFileState) error {
	payload, err := marshalEncryptedFileState(state, s.key)
	if err != nil {
		return err
	}
	defer clear(payload)
	parent := filepath.Dir(s.path)
	if err := localstate.ValidateStateRoot(parent); err != nil {
		return ErrEncryptedFileStoreUnavailable
	}
	if _, err := os.Lstat(s.path); err == nil {
		if err := localstate.ValidateFile(s.path); err != nil {
			return ErrEncryptedFileStoreUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrEncryptedFileStoreUnavailable
	}
	temporary, err := os.CreateTemp(parent, ".credential-state-*")
	if err != nil {
		return ErrEncryptedFileStoreUnavailable
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	fail := func() error {
		_ = temporary.Close()
		return ErrEncryptedFileStoreUnavailable
	}
	if err := localstate.ProtectFile(temporaryPath); err != nil {
		return fail()
	}
	if _, err := temporary.Write(payload); err != nil {
		return fail()
	}
	if err := temporary.Sync(); err != nil {
		return fail()
	}
	if err := temporary.Close(); err != nil {
		return ErrEncryptedFileStoreUnavailable
	}
	if err := localstate.ValidateFile(temporaryPath); err != nil {
		return ErrEncryptedFileStoreUnavailable
	}
	if err := durableReplace(temporaryPath, s.path); err != nil {
		return ErrEncryptedFileStoreUnavailable
	}
	removeTemporary = false
	if err := localstate.ValidateFile(s.path); err != nil {
		return ErrEncryptedFileStoreUnavailable
	}
	return nil
}

func readEncryptedFileState(path string, key []byte) (encryptedFileState, error) {
	if len(key) != 32 {
		return encryptedFileState{}, ErrEncryptedFileStoreUnavailable
	}
	if err := localstate.ValidateFile(path); err != nil {
		return encryptedFileState{}, ErrEncryptedFileStoreUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return encryptedFileState{}, ErrEncryptedFileStoreUnavailable
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, encryptedFileStoreMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(payload) > encryptedFileStoreMaxBytes {
		clear(payload)
		return encryptedFileState{}, ErrEncryptedFileStoreUnavailable
	}
	defer clear(payload)
	return unmarshalEncryptedFileState(payload, key)
}

func marshalEncryptedFileState(state encryptedFileState, key []byte) ([]byte, error) {
	if err := validateEncryptedFileState(state); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return nil, ErrEncryptedFileStoreIntegrity
	}
	defer clear(plain)
	aead, err := encryptedFileAEAD(key)
	if err != nil {
		return nil, ErrEncryptedFileStoreUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		clear(nonce)
		return nil, ErrEncryptedFileStoreUnavailable
	}
	payload := make([]byte, 0, len(encryptedFileStoreMagic)+len(nonce)+len(plain)+aead.Overhead())
	payload = append(payload, encryptedFileStoreMagic...)
	payload = append(payload, nonce...)
	payload = aead.Seal(payload, nonce, plain, []byte(encryptedFileStoreMagic))
	clear(nonce)
	return payload, nil
}

func unmarshalEncryptedFileState(payload, key []byte) (encryptedFileState, error) {
	aead, err := encryptedFileAEAD(key)
	if err != nil {
		return encryptedFileState{}, ErrEncryptedFileStoreUnavailable
	}
	headerLength := len(encryptedFileStoreMagic) + aead.NonceSize()
	if len(payload) <= headerLength+aead.Overhead() || !bytes.Equal(payload[:len(encryptedFileStoreMagic)], []byte(encryptedFileStoreMagic)) {
		return encryptedFileState{}, ErrEncryptedFileStoreIntegrity
	}
	nonce := payload[len(encryptedFileStoreMagic):headerLength]
	plain, err := aead.Open(nil, nonce, payload[headerLength:], []byte(encryptedFileStoreMagic))
	if err != nil {
		clear(plain)
		return encryptedFileState{}, ErrEncryptedFileStoreIntegrity
	}
	defer clear(plain)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var state encryptedFileState
	if err := decoder.Decode(&state); err != nil {
		clearEncryptedFileState(&state)
		return encryptedFileState{}, ErrEncryptedFileStoreIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		clearEncryptedFileState(&state)
		return encryptedFileState{}, ErrEncryptedFileStoreIntegrity
	}
	if err := validateEncryptedFileState(state); err != nil {
		clearEncryptedFileState(&state)
		return encryptedFileState{}, err
	}
	return state, nil
}

func encryptedFileAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrEncryptedFileStoreUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEncryptedFileStoreUnavailable
	}
	return cipher.NewGCM(block)
}

func validateEncryptedFileState(state encryptedFileState) error {
	if state.Version != encryptedFileStoreVersion || state.Secrets == nil || state.Puts == nil || state.Rotations == nil ||
		len(state.Secrets) > encryptedFileStoreMaxRecords || len(state.Puts) > encryptedFileStoreMaxRecords || len(state.Rotations) > encryptedFileStoreMaxRecords {
		return ErrEncryptedFileStoreIntegrity
	}
	for value, secret := range state.Secrets {
		ref, err := ParseRef(value)
		if err != nil || !ref.Valid() || validateSecret(secret) != nil {
			return ErrEncryptedFileStoreIntegrity
		}
	}
	seenPutRefs := make(map[string]struct{}, len(state.Puts))
	for operationValue, record := range state.Puts {
		operationID, operationErr := ParsePutOperationID(operationValue)
		ref, refErr := ParseRef(record.Ref)
		if operationErr != nil || refErr != nil || !operationID.Valid() || !ref.Valid() ||
			(record.Phase != PutCommitted && record.Phase != PutRolledBack) {
			return ErrEncryptedFileStoreIntegrity
		}
		if _, duplicate := seenPutRefs[record.Ref]; duplicate {
			return ErrEncryptedFileStoreIntegrity
		}
		seenPutRefs[record.Ref] = struct{}{}
	}
	seenOldRefs := make(map[string]struct{}, len(state.Rotations))
	seenNewRefs := make(map[string]struct{}, len(state.Rotations))
	for operationValue, record := range state.Rotations {
		operationID, operationErr := ParseRotationID(operationValue)
		oldRef, oldErr := ParseRef(record.OldRef)
		newRef, newErr := ParseRef(record.NewRef)
		if operationErr != nil || oldErr != nil || newErr != nil || !operationID.Valid() || !oldRef.Valid() || !newRef.Valid() ||
			oldRef == newRef || (record.Phase != RotationCommitted && record.Phase != RotationRolledBack) {
			return ErrEncryptedFileStoreIntegrity
		}
		if _, duplicate := seenOldRefs[record.OldRef]; duplicate {
			return ErrEncryptedFileStoreIntegrity
		}
		if _, duplicate := seenNewRefs[record.NewRef]; duplicate {
			return ErrEncryptedFileStoreIntegrity
		}
		seenOldRefs[record.OldRef] = struct{}{}
		seenNewRefs[record.NewRef] = struct{}{}
	}
	return nil
}

func newEncryptedFileState() encryptedFileState {
	return encryptedFileState{
		Version: encryptedFileStoreVersion, Secrets: map[string][]byte{},
		Puts: map[string]encryptedFilePut{}, Rotations: map[string]encryptedFileRotation{},
	}
}

func cloneEncryptedFileState(source encryptedFileState) encryptedFileState {
	clone := newEncryptedFileState()
	for ref, secret := range source.Secrets {
		clone.Secrets[ref] = append([]byte(nil), secret...)
	}
	for operationID, record := range source.Puts {
		clone.Puts[operationID] = record
	}
	for operationID, record := range source.Rotations {
		clone.Rotations[operationID] = record
	}
	return clone
}

func clearEncryptedFileState(state *encryptedFileState) {
	if state == nil {
		return
	}
	for ref, secret := range state.Secrets {
		clear(secret)
		delete(state.Secrets, ref)
	}
	for operationID := range state.Puts {
		delete(state.Puts, operationID)
	}
	for operationID := range state.Rotations {
		delete(state.Rotations, operationID)
	}
}

func putReceiptFromEncrypted(operationID PutOperationID, record encryptedFilePut) (PutReceipt, error) {
	ref, err := ParseRef(record.Ref)
	if err != nil || (record.Phase != PutCommitted && record.Phase != PutRolledBack) {
		return PutReceipt{}, ErrEncryptedFileStoreIntegrity
	}
	return PutReceipt{OperationID: operationID, Ref: ref, Phase: record.Phase}, nil
}

func rotationReceiptFromEncrypted(operationID RotationID, record encryptedFileRotation) (RotationReceipt, error) {
	oldRef, oldErr := ParseRef(record.OldRef)
	newRef, newErr := ParseRef(record.NewRef)
	if oldErr != nil || newErr != nil || oldRef == newRef || (record.Phase != RotationCommitted && record.Phase != RotationRolledBack) {
		return RotationReceipt{}, ErrEncryptedFileStoreIntegrity
	}
	return RotationReceipt{OperationID: operationID, OldRef: oldRef, NewRef: newRef, Phase: record.Phase}, nil
}

func (s *EncryptedFileStore) availableLocked() error {
	if s == nil || s.closed || len(s.key) != 32 {
		return ErrEncryptedFileStoreUnavailable
	}
	return nil
}

func (s *EncryptedFileStore) lockAndRefreshLocked() (*encryptedFileLock, error) {
	lock, err := acquireEncryptedFileLock(s.path)
	if err != nil {
		return nil, ErrEncryptedFileStoreUnavailable
	}
	state, err := readEncryptedFileState(s.path, s.key)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	clearEncryptedFileState(&s.state)
	s.state = state
	return lock, nil
}

func encryptedFileContext(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ SecretStore = (*EncryptedFileStore)(nil)
