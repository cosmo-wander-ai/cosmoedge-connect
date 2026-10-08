package credential

import (
	"context"
	"errors"
	"sync"
)

// MemoryStore is a strict ephemeral implementation for tests and foreground
// sessions. It is deliberately not a durable fallback for a missing native
// credential backend.
type MemoryStore struct {
	mu        sync.Mutex
	secrets   map[Ref][]byte
	puts      map[PutOperationID]PutReceipt
	rotations map[RotationID]RotationReceipt
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{secrets: map[Ref][]byte{}, puts: map[PutOperationID]PutReceipt{}, rotations: map[RotationID]RotationReceipt{}}
}

func (s *MemoryStore) Put(ctx context.Context, operationID PutOperationID, secret []byte) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	if err := validateSecret(secret); err != nil {
		return PutReceipt{}, err
	}
	copyOfSecret := append([]byte(nil), secret...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found := s.puts[operationID]; found {
		clear(copyOfSecret)
		return s.recoverPutLocked(existing)
	}
	for {
		ref, err := newRef()
		if err != nil {
			clear(copyOfSecret)
			return PutReceipt{}, err
		}
		if _, exists := s.secrets[ref]; exists {
			continue
		}
		receipt := PutReceipt{OperationID: operationID, Ref: ref, Phase: PutPrepared}
		s.puts[operationID] = receipt
		s.secrets[ref] = copyOfSecret
		receipt.Phase = PutCommitted
		s.puts[operationID] = receipt
		return receipt, nil
	}
}

func (s *MemoryStore) PutByOperationID(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.puts[operationID]
	if !found {
		return PutReceipt{}, ErrNotFound
	}
	return receipt, nil
}

func (s *MemoryStore) RecoverPut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.puts[operationID]
	if !found {
		return PutReceipt{}, ErrNotFound
	}
	return s.recoverPutLocked(receipt)
}

func (s *MemoryStore) CompensatePut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.puts[operationID]
	if !found {
		return PutReceipt{}, ErrNotFound
	}
	if secret, exists := s.secrets[receipt.Ref]; exists {
		clear(secret)
		delete(s.secrets, receipt.Ref)
	}
	receipt.Phase = PutRolledBack
	s.puts[operationID] = receipt
	return receipt, nil
}

func (s *MemoryStore) AcknowledgePut(ctx context.Context, operationID PutOperationID) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.puts[operationID]
	if !found {
		return nil
	}
	if !receipt.Phase.terminal() {
		return &OutcomeUnknownError{Operation: "put", NewRef: receipt.Ref}
	}
	delete(s.puts, operationID)
	return nil
}

func (s *MemoryStore) recoverPutLocked(receipt PutReceipt) (PutReceipt, error) {
	if secret, exists := s.secrets[receipt.Ref]; exists && receipt.Phase == PutRolledBack {
		clear(secret)
		delete(s.secrets, receipt.Ref)
		receipt.Phase = PutRolledBack
	} else if exists {
		receipt.Phase = PutCommitted
	} else {
		receipt.Phase = PutRolledBack
	}
	s.puts[receipt.OperationID] = receipt
	return receipt, nil
}

func (s *MemoryStore) Get(ctx context.Context, ref Ref) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !ref.Valid() {
		return nil, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, exists := s.secrets[ref]
	if !exists {
		return nil, ErrNotFound
	}
	return append([]byte(nil), secret...), nil
}

func (s *MemoryStore) Delete(ctx context.Context, ref Ref) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !ref.Valid() {
		return ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if secret, exists := s.secrets[ref]; exists {
		clear(secret)
		delete(s.secrets, ref)
	}
	return nil
}

func (s *MemoryStore) Rotate(ctx context.Context, old Ref, secret []byte) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !old.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	if err := validateSecret(secret); err != nil {
		return RotationReceipt{}, err
	}
	copyOfSecret := append([]byte(nil), secret...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found := s.rotationByOldRefLocked(old); found {
		clear(copyOfSecret)
		return s.recoverRotationLocked(existing)
	}
	previous, exists := s.secrets[old]
	if !exists {
		clear(copyOfSecret)
		return RotationReceipt{}, ErrNotFound
	}
	for {
		ref, err := newRef()
		if err != nil {
			clear(copyOfSecret)
			return RotationReceipt{}, err
		}
		if _, collision := s.secrets[ref]; collision {
			continue
		}
		operationID, err := newRotationID()
		if err != nil {
			clear(copyOfSecret)
			return RotationReceipt{}, err
		}
		receipt := RotationReceipt{OperationID: operationID, OldRef: old, NewRef: ref, Phase: RotationPrepared}
		s.rotations[operationID] = receipt
		s.secrets[ref] = copyOfSecret
		clear(previous)
		delete(s.secrets, old)
		receipt.Phase = RotationCommitted
		s.rotations[operationID] = receipt
		return receipt, nil
	}
}

func (s *MemoryStore) RotationByOldRef(ctx context.Context, old Ref) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !old.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.rotationByOldRefLocked(old)
	if !found {
		return RotationReceipt{}, ErrNotFound
	}
	return receipt, nil
}

func (s *MemoryStore) RecoverRotation(ctx context.Context, operationID RotationID) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !operationID.Valid() {
		return RotationReceipt{}, ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.rotations[operationID]
	if !found {
		return RotationReceipt{}, ErrNotFound
	}
	return s.recoverRotationLocked(receipt)
}

func (s *MemoryStore) AcknowledgeRotation(ctx context.Context, operationID RotationID) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, found := s.rotations[operationID]
	if !found {
		return nil
	}
	if !receipt.Phase.terminal() {
		return &OutcomeUnknownError{Operation: "rotate", OldRef: receipt.OldRef, NewRef: receipt.NewRef}
	}
	delete(s.rotations, operationID)
	return nil
}

func (s *MemoryStore) rotationByOldRefLocked(old Ref) (RotationReceipt, bool) {
	for _, receipt := range s.rotations {
		if receipt.OldRef == old {
			return receipt, true
		}
	}
	return RotationReceipt{}, false
}

func (s *MemoryStore) recoverRotationLocked(receipt RotationReceipt) (RotationReceipt, error) {
	if receipt.Phase.terminal() {
		return receipt, nil
	}
	_, oldExists := s.secrets[receipt.OldRef]
	newSecret, newExists := s.secrets[receipt.NewRef]
	switch {
	case oldExists && !newExists:
		receipt.Phase = RotationRolledBack
	case !oldExists && newExists:
		receipt.Phase = RotationCommitted
	case oldExists && newExists:
		clear(newSecret)
		delete(s.secrets, receipt.NewRef)
		receipt.Phase = RotationRolledBack
	default:
		receipt.Phase = RotationUnknown
		s.rotations[receipt.OperationID] = receipt
		return receipt, &OutcomeUnknownError{Operation: "rotate", OldRef: receipt.OldRef, NewRef: receipt.NewRef}
	}
	s.rotations[receipt.OperationID] = receipt
	return receipt, nil
}

// Purge clears all in-memory copies. It is not part of SecretStore because a
// production backend must use explicit, auditable reference deletion.
func (s *MemoryStore) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref, secret := range s.secrets {
		clear(secret)
		delete(s.secrets, ref)
	}
	for operationID := range s.rotations {
		delete(s.rotations, operationID)
	}
	for operationID := range s.puts {
		delete(s.puts, operationID)
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("credential context is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

var _ SecretStore = (*MemoryStore)(nil)
