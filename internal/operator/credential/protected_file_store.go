package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const (
	maxProtectedSecretBytes = 64 << 10
	rotationManifestVersion = 1
	rotationActiveName      = ".credential-rotation.active.json"
	rotationCommittedName   = ".credential-rotation.committed.json"
)

type rotationManifest struct {
	Version     int    `json:"version"`
	OperationID string `json:"operationId"`
	OldRef      string `json:"oldRef"`
	NewRef      string `json:"newRef"`
}

type parsedRotationManifest struct {
	OperationID RotationID
	OldRef      Ref
	NewRef      Ref
	committed   bool
}

type secretProtector interface {
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

// protectedFileStore is used only by a native protector such as Windows
// DPAPI. It is intentionally unexported so it cannot become a plaintext file
// fallback.
type protectedFileStore struct {
	mu        sync.Mutex
	root      string
	protector secretProtector
	puts      *putJournal
	journal   *rotationJournal
}

func newProtectedFileStore(stateRoot string, protector secretProtector) (*protectedFileStore, error) {
	if protector == nil {
		return nil, errors.New("native credential protector is required")
	}
	root, err := prepareSystemRoot(stateRoot)
	if err != nil {
		return nil, err
	}
	root = filepath.Join(root, "credential-blobs")
	if _, err := os.Lstat(root); err == nil {
		if err := localstate.ValidateStateRoot(root); err != nil {
			return nil, errors.New("reject existing credential blob directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("credential blob directory is unavailable")
	} else if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, errors.New("credential blob directory creation failed")
	}
	journal, err := openRotationJournal(root)
	if err != nil {
		return nil, err
	}
	puts, err := openPutJournal(root)
	if err != nil {
		return nil, err
	}
	store := &protectedFileStore{root: root, protector: protector, puts: puts, journal: journal}
	if err := store.recoverInterruptedRotationLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *protectedFileStore) Put(ctx context.Context, operationID PutOperationID, secret []byte) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
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
	if existing, err := s.puts.Get(operationID); err == nil {
		return s.recoverPutReceiptLocked(existing)
	} else if !errors.Is(err, ErrNotFound) {
		return PutReceipt{}, err
	}
	ref, err := s.unusedRefLocked()
	if err != nil {
		return PutReceipt{}, err
	}
	receipt, err := s.puts.Create(operationID, ref)
	if err != nil {
		return PutReceipt{}, err
	}
	protected, err := s.protector.Protect(secret)
	if err != nil {
		return s.rollbackPutReceiptAfterKnownFailureLocked(receipt, errors.New("native credential protection failed"))
	}
	defer clear(protected)
	if err := validateProtected(protected); err != nil {
		return s.rollbackPutReceiptAfterKnownFailureLocked(receipt, err)
	}
	if err := s.writeNewLocked(ref, protected); err != nil {
		if errors.Is(err, ErrOutcomeUnknown) {
			return s.markPutReceiptUnknownLocked(receipt)
		}
		return s.rollbackPutReceiptAfterKnownFailureLocked(receipt, err)
	}
	committed, err := s.puts.Update(receipt, PutCommitted)
	if err != nil {
		return s.markPutReceiptUnknownLocked(receipt)
	}
	return committed, nil
}

func (s *protectedFileStore) PutByOperationID(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts.Get(operationID)
}

func (s *protectedFileStore) RecoverPut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.puts.Get(operationID)
	if err != nil {
		return PutReceipt{}, err
	}
	return s.recoverPutReceiptLocked(receipt)
}

func (s *protectedFileStore) CompensatePut(ctx context.Context, operationID PutOperationID) (PutReceipt, error) {
	if err := contextError(ctx); err != nil {
		return PutReceipt{}, err
	}
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.puts.Get(operationID)
	if err != nil {
		return PutReceipt{}, err
	}
	if receipt.Phase == PutRolledBack {
		return receipt, nil
	}
	if err := s.deleteLocked(receipt.Ref); err != nil {
		return s.markPutReceiptUnknownLocked(receipt)
	}
	rolledBack, err := s.puts.Update(receipt, PutRolledBack)
	if err != nil {
		return s.markPutReceiptUnknownLocked(receipt)
	}
	return rolledBack, nil
}

func (s *protectedFileStore) AcknowledgePut(ctx context.Context, operationID PutOperationID) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidPutOperationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.puts.Get(operationID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !receipt.Phase.terminal() {
		return &OutcomeUnknownError{Operation: "put", NewRef: receipt.Ref}
	}
	return s.puts.Delete(operationID)
}

func (s *protectedFileStore) recoverPutReceiptLocked(receipt PutReceipt) (PutReceipt, error) {
	if receipt.Phase == PutRolledBack {
		if err := s.deleteLocked(receipt.Ref); err != nil {
			return s.markPutReceiptUnknownLocked(receipt)
		}
		updated, err := s.puts.Update(receipt, PutRolledBack)
		if err != nil {
			return s.markPutReceiptUnknownLocked(receipt)
		}
		return updated, nil
	}
	secret, err := s.readLocked(receipt.Ref)
	clear(secret)
	phase := PutCommitted
	if errors.Is(err, ErrNotFound) {
		phase = PutRolledBack
	} else if err != nil {
		return s.markPutReceiptUnknownLocked(receipt)
	}
	updated, err := s.puts.Update(receipt, phase)
	if err != nil {
		return s.markPutReceiptUnknownLocked(receipt)
	}
	return updated, nil
}

func (s *protectedFileStore) rollbackPutReceiptAfterKnownFailureLocked(receipt PutReceipt, cause error) (PutReceipt, error) {
	updated, err := s.puts.Update(receipt, PutRolledBack)
	if err != nil {
		return s.markPutReceiptUnknownLocked(receipt)
	}
	return updated, cause
}

func (s *protectedFileStore) markPutReceiptUnknownLocked(receipt PutReceipt) (PutReceipt, error) {
	updated, err := s.puts.Update(receipt, PutUnknown)
	if err == nil {
		receipt = updated
	}
	return receipt, &OutcomeUnknownError{Operation: "put", NewRef: receipt.Ref}
}

func (s *protectedFileStore) Get(ctx context.Context, ref Ref) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !ref.Valid() {
		return nil, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked(ref)
}

func (s *protectedFileStore) Delete(ctx context.Context, ref Ref) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !ref.Valid() {
		return ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(ref)
}

func (s *protectedFileStore) deleteLocked(ref Ref) error {
	path := s.path(ref)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return storageOperationError("delete")
	}
	if err := localstate.ValidateFile(path); err != nil {
		return storageOperationError("delete")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return storageOperationError("delete")
	}
	// Delete is an authority transition used by the durable forget saga. Run
	// the platform's containing-directory durability barrier before reporting
	// success (Windows has no portable directory-fsync equivalent).
	if err := syncContainingDirectory(path); err != nil {
		return storageOperationError("delete")
	}
	return nil
}

func (s *protectedFileStore) Rotate(ctx context.Context, old Ref, secret []byte) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
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
	if existing, err := s.journal.ByOldRef(old); err == nil {
		return s.recoverRotationReceiptLocked(existing)
	} else if !errors.Is(err, ErrNotFound) {
		return RotationReceipt{}, err
	}
	previous, err := s.readLocked(old)
	clear(previous)
	if err != nil {
		return RotationReceipt{}, err
	}
	newReference, err := s.unusedRefLocked()
	if err != nil {
		return RotationReceipt{}, err
	}
	receipt, err := s.journal.Create(old, newReference)
	if err != nil {
		return RotationReceipt{}, err
	}
	// A second process can win the durable receipt creation between the
	// ByOldRef lookup above and Create. Resume that operation instead of
	// installing data under the losing process's reference.
	if receipt.NewRef != newReference {
		return s.recoverRotationReceiptLocked(receipt)
	}
	protected, err := s.protector.Protect(secret)
	if err != nil {
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, errors.New("native credential protection failed"))
	}
	defer clear(protected)
	if err := validateProtected(protected); err != nil {
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, err)
	}
	manifest := rotationManifest{
		Version: rotationManifestVersion, OperationID: receipt.OperationID.ProtectedValue(),
		OldRef: old.ProtectedValue(), NewRef: newReference.ProtectedValue(),
	}
	staged := s.rotationStagePath(newReference)
	backup := s.rotationBackupPath(old, newReference)
	if err := s.writeProtectedPathLocked(staged, protected); err != nil {
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, err)
	}
	defer func() { _ = os.Remove(staged) }()
	if err := s.writeRotationManifestLocked(s.rotationActivePath(), manifest); err != nil {
		_ = os.Remove(staged)
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, err)
	}
	oldPath, newPath := s.path(old), s.path(newReference)
	if err := durableRename(oldPath, backup); err != nil {
		if recoverErr := s.rollbackRotationLocked(old, newReference); recoverErr != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, storageOperationError("rotate"))
	}
	if err := durableRename(staged, newPath); err != nil {
		if recoverErr := s.rollbackRotationLocked(old, newReference); recoverErr != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, storageOperationError("rotate"))
	}
	if err := localstate.ProtectFile(newPath); err != nil {
		if rollbackErr := s.rollbackRotationLocked(old, newReference); rollbackErr != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, storageOperationError("rotate"))
	}
	if err := localstate.ValidateFile(newPath); err != nil {
		if rollbackErr := s.rollbackRotationLocked(old, newReference); rollbackErr != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, storageOperationError("rotate"))
	}
	opened, err := s.readLocked(newReference)
	clear(opened)
	if err != nil {
		if rollbackErr := s.rollbackRotationLocked(old, newReference); rollbackErr != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, storageOperationError("rotate"))
	}
	// The manifest rename is the durable commit point. Recovery rolls an active
	// manifest back to old and finalizes a committed manifest to new.
	if err := durableRename(s.rotationActivePath(), s.rotationCommittedPath()); err != nil {
		if rollbackErr := s.rollbackRotationLocked(old, newReference); rollbackErr != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		return s.rollbackReceiptAfterKnownFailureLocked(receipt, storageOperationError("rotate"))
	}
	if err := localstate.ProtectFile(s.rotationCommittedPath()); err != nil {
		return s.markReceiptUnknownLocked(receipt)
	}
	committed, err := s.journal.Update(receipt, RotationCommitted)
	if err != nil {
		return s.markReceiptUnknownLocked(receipt)
	}
	// A cleanup failure leaves the committed manifest as a durable
	// cleanup-pending record. The new reference is nevertheless authoritative.
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return committed, nil
	}
	if err := os.Remove(s.rotationCommittedPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return committed, nil
	}
	return committed, nil
}

func (s *protectedFileStore) RotationByOldRef(ctx context.Context, old Ref) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !old.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.journal.ByOldRef(old)
}

func (s *protectedFileStore) RecoverRotation(ctx context.Context, operationID RotationID) (RotationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return RotationReceipt{}, err
	}
	if !operationID.Valid() {
		return RotationReceipt{}, ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.journal.Get(operationID)
	if err != nil {
		return RotationReceipt{}, err
	}
	return s.recoverRotationReceiptLocked(receipt)
}

func (s *protectedFileStore) AcknowledgeRotation(ctx context.Context, operationID RotationID) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if !operationID.Valid() {
		return ErrInvalidRotationID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.journal.Get(operationID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	receipt, err = s.recoverRotationReceiptLocked(receipt)
	if err != nil {
		return err
	}
	if !receipt.Phase.terminal() {
		return unknownFileRotation(receipt.OldRef, receipt.NewRef)
	}
	return s.journal.Delete(operationID)
}

func (s *protectedFileStore) rollbackReceiptAfterKnownFailureLocked(receipt RotationReceipt, cause error) (RotationReceipt, error) {
	updated, err := s.journal.Update(receipt, RotationRolledBack)
	if err != nil {
		return s.markReceiptUnknownLocked(receipt)
	}
	return updated, cause
}

func (s *protectedFileStore) markReceiptUnknownLocked(receipt RotationReceipt) (RotationReceipt, error) {
	updated, err := s.journal.Update(receipt, RotationUnknown)
	if err == nil {
		receipt = updated
	}
	return receipt, unknownFileRotation(receipt.OldRef, receipt.NewRef)
}

func (s *protectedFileStore) recoverRotationReceiptLocked(receipt RotationReceipt) (RotationReceipt, error) {
	manifest, found, manifestErr := s.readAnyRotationManifestLocked()
	if manifestErr != nil {
		return s.markReceiptUnknownLocked(receipt)
	}
	if found {
		if manifest.OperationID != receipt.OperationID || manifest.OldRef != receipt.OldRef || manifest.NewRef != receipt.NewRef {
			return s.markReceiptUnknownLocked(receipt)
		}
		phase := RotationRolledBack
		var err error
		if manifest.committed {
			phase = RotationCommitted
			err = s.finalizeRotationLocked(receipt.OldRef, receipt.NewRef)
		} else {
			err = s.rollbackRotationLocked(receipt.OldRef, receipt.NewRef)
		}
		if err != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		updated, updateErr := s.journal.Update(receipt, phase)
		if updateErr != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		return updated, nil
	}
	if receipt.Phase.terminal() {
		return receipt, nil
	}
	oldExists, oldErr := s.validFileExistsLocked(s.path(receipt.OldRef))
	newExists, newErr := s.validFileExistsLocked(s.path(receipt.NewRef))
	backup := s.rotationBackupPath(receipt.OldRef, receipt.NewRef)
	staged := s.rotationStagePath(receipt.NewRef)
	backupExists, backupErr := s.validFileExistsLocked(backup)
	if oldErr != nil || newErr != nil || backupErr != nil {
		return s.markReceiptUnknownLocked(receipt)
	}
	phase := RotationUnknown
	switch {
	case oldExists && !newExists:
		phase = RotationRolledBack
		if err := s.removeRotationArtifactLocked(backup); err != nil || s.removeRotationArtifactLocked(staged) != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
	case !oldExists && newExists:
		phase = RotationCommitted
		if err := s.removeRotationArtifactLocked(backup); err != nil || s.removeRotationArtifactLocked(staged) != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
	case oldExists && newExists:
		if err := os.Remove(s.path(receipt.NewRef)); err == nil || errors.Is(err, os.ErrNotExist) {
			phase = RotationRolledBack
		}
		if phase == RotationRolledBack {
			if err := s.removeRotationArtifactLocked(backup); err != nil || s.removeRotationArtifactLocked(staged) != nil {
				return s.markReceiptUnknownLocked(receipt)
			}
		}
	case !oldExists && !newExists && backupExists:
		if err := durableRename(backup, s.path(receipt.OldRef)); err != nil || localstate.ProtectFile(s.path(receipt.OldRef)) != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		if err := s.removeRotationArtifactLocked(staged); err != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
		phase = RotationRolledBack
	}
	if phase == RotationCommitted || phase == RotationRolledBack {
		verifyRef := receipt.OldRef
		if phase == RotationCommitted {
			verifyRef = receipt.NewRef
		}
		secret, err := s.readLocked(verifyRef)
		clear(secret)
		if err != nil {
			return s.markReceiptUnknownLocked(receipt)
		}
	}
	updated, err := s.journal.Update(receipt, phase)
	if err != nil {
		return s.markReceiptUnknownLocked(receipt)
	}
	if phase == RotationUnknown {
		return updated, unknownFileRotation(receipt.OldRef, receipt.NewRef)
	}
	return updated, nil
}

func (s *protectedFileStore) readLocked(ref Ref) ([]byte, error) {
	path := s.path(ref)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, storageOperationError("get")
	}
	if info.Size() <= 0 || info.Size() > maxProtectedSecretBytes {
		return nil, errors.New("protected credential payload is invalid")
	}
	if err := localstate.ValidateFile(path); err != nil {
		return nil, storageOperationError("get")
	}
	protected, err := os.ReadFile(path)
	if err != nil {
		return nil, storageOperationError("get")
	}
	defer clear(protected)
	secret, err := s.protector.Unprotect(protected)
	if err != nil {
		clear(secret)
		return nil, errors.New("native credential opening failed")
	}
	if err := validateSecret(secret); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

func (s *protectedFileStore) writeNewLocked(ref Ref, protected []byte) error {
	staged, err := s.writeStagedLocked(protected, ".credential-new-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	target := s.path(ref)
	if _, err := os.Lstat(target); err == nil {
		return errors.New("credential reference collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return storageOperationError("put")
	}
	if err := durableRename(staged, target); err != nil {
		return storageOperationError("put")
	}
	if err := localstate.ProtectFile(target); err != nil {
		if removeErr := os.Remove(target); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return &OutcomeUnknownError{Operation: "put", NewRef: ref}
		}
		return storageOperationError("put")
	}
	return nil
}

func (s *protectedFileStore) writeStagedLocked(protected []byte, pattern string) (string, error) {
	temporary, err := os.CreateTemp(s.root, pattern)
	if err != nil {
		return "", storageOperationError("write")
	}
	path := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", storageOperationError("write")
	}
	if _, err := temporary.Write(protected); err != nil {
		return "", storageOperationError("write")
	}
	if err := temporary.Sync(); err != nil {
		return "", storageOperationError("write")
	}
	if err := temporary.Close(); err != nil {
		return "", storageOperationError("write")
	}
	if err := localstate.ProtectFile(path); err != nil {
		return "", storageOperationError("write")
	}
	ok = true
	return path, nil
}

func (s *protectedFileStore) writeProtectedPathLocked(path string, protected []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return storageOperationError("write")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(protected); err != nil {
		return storageOperationError("write")
	}
	if err := file.Sync(); err != nil {
		return storageOperationError("write")
	}
	if err := file.Close(); err != nil {
		return storageOperationError("write")
	}
	if err := localstate.ProtectFile(path); err != nil {
		return storageOperationError("write")
	}
	if err := syncContainingDirectory(path); err != nil {
		return storageOperationError("write")
	}
	ok = true
	return nil
}

func (s *protectedFileStore) writeRotationManifestLocked(path string, manifest rotationManifest) error {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return storageOperationError("rotate")
	}
	defer clear(raw)
	return s.writeProtectedPathLocked(path, raw)
}

func (s *protectedFileStore) readAnyRotationManifestLocked() (parsedRotationManifest, bool, error) {
	active, activeFound, activeErr := s.readRotationManifestLocked(s.rotationActivePath(), false)
	committed, committedFound, committedErr := s.readRotationManifestLocked(s.rotationCommittedPath(), true)
	if activeErr != nil || committedErr != nil || activeFound && committedFound {
		return parsedRotationManifest{}, false, unknownFileRotation("", "")
	}
	if activeFound {
		return active, true, nil
	}
	if committedFound {
		return committed, true, nil
	}
	return parsedRotationManifest{}, false, nil
}

func (s *protectedFileStore) readRotationManifestLocked(path string, committed bool) (parsedRotationManifest, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return parsedRotationManifest{}, false, nil
	}
	if err != nil || info.Size() <= 0 || info.Size() > 1024 || localstate.ValidateFile(path) != nil {
		return parsedRotationManifest{}, false, storageOperationError("rotate")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return parsedRotationManifest{}, false, storageOperationError("rotate")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest rotationManifest
	if err := decoder.Decode(&manifest); err != nil {
		return parsedRotationManifest{}, false, storageOperationError("rotate")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return parsedRotationManifest{}, false, storageOperationError("rotate")
	}
	oldRef, oldErr := ParseRef(manifest.OldRef)
	newRef, newErr := ParseRef(manifest.NewRef)
	operationID, operationErr := ParseRotationID(manifest.OperationID)
	if manifest.Version != rotationManifestVersion || operationErr != nil || oldErr != nil || newErr != nil || oldRef == newRef {
		return parsedRotationManifest{}, false, storageOperationError("rotate")
	}
	return parsedRotationManifest{OperationID: operationID, OldRef: oldRef, NewRef: newRef, committed: committed}, true, nil
}

func (s *protectedFileStore) recoverInterruptedRotationLocked() error {
	manifest, found, err := s.readAnyRotationManifestLocked()
	if err != nil || !found {
		return err
	}
	receipt, receiptErr := s.journal.Get(manifest.OperationID)
	if receiptErr != nil || receipt.OldRef != manifest.OldRef || receipt.NewRef != manifest.NewRef {
		return unknownFileRotation(manifest.OldRef, manifest.NewRef)
	}
	phase := RotationRolledBack
	if manifest.committed {
		phase = RotationCommitted
		err = s.finalizeRotationLocked(manifest.OldRef, manifest.NewRef)
	} else {
		err = s.rollbackRotationLocked(manifest.OldRef, manifest.NewRef)
	}
	if err != nil {
		_, _ = s.journal.Update(receipt, RotationUnknown)
		return unknownFileRotation(manifest.OldRef, manifest.NewRef)
	}
	if _, err := s.journal.Update(receipt, phase); err != nil {
		return unknownFileRotation(manifest.OldRef, manifest.NewRef)
	}
	return nil
}

func (s *protectedFileStore) rollbackRotationLocked(old, new Ref) error {
	oldPath, newPath := s.path(old), s.path(new)
	backup, staged := s.rotationBackupPath(old, new), s.rotationStagePath(new)
	oldExists, err := s.validFileExistsLocked(oldPath)
	if err != nil {
		return unknownFileRotation(old, new)
	}
	newExists, err := s.validFileExistsLocked(newPath)
	if err != nil {
		return unknownFileRotation(old, new)
	}
	backupExists, err := s.validFileExistsLocked(backup)
	if err != nil {
		return unknownFileRotation(old, new)
	}
	if newExists {
		if err := os.Remove(newPath); err != nil {
			return unknownFileRotation(old, new)
		}
	}
	if backupExists {
		if oldExists {
			if err := os.Remove(backup); err != nil {
				return unknownFileRotation(old, new)
			}
		} else if err := durableRename(backup, oldPath); err != nil {
			return unknownFileRotation(old, new)
		} else {
			oldExists = true
		}
	}
	if !oldExists {
		return unknownFileRotation(old, new)
	}
	if err := s.removeRotationArtifactLocked(staged); err != nil {
		return unknownFileRotation(old, new)
	}
	if err := localstate.ProtectFile(oldPath); err != nil {
		return unknownFileRotation(old, new)
	}
	secret, err := s.readLocked(old)
	clear(secret)
	if err != nil {
		return unknownFileRotation(old, new)
	}
	if err := s.removeRotationArtifactLocked(s.rotationActivePath()); err != nil {
		return unknownFileRotation(old, new)
	}
	return nil
}

func (s *protectedFileStore) finalizeRotationLocked(old, new Ref) error {
	newPath := s.path(new)
	newExists, err := s.validFileExistsLocked(newPath)
	if err != nil || !newExists {
		return unknownFileRotation(old, new)
	}
	secret, err := s.readLocked(new)
	clear(secret)
	if err != nil {
		return unknownFileRotation(old, new)
	}
	for _, artifact := range []string{s.path(old), s.rotationBackupPath(old, new), s.rotationStagePath(new)} {
		if err := s.removeRotationArtifactLocked(artifact); err != nil {
			return unknownFileRotation(old, new)
		}
	}
	if err := s.removeRotationArtifactLocked(s.rotationCommittedPath()); err != nil {
		return unknownFileRotation(old, new)
	}
	return nil
}

func (s *protectedFileStore) validFileExistsLocked(path string) (bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, storageOperationError("rotate")
	}
	if err := localstate.ValidateFile(path); err != nil {
		return false, storageOperationError("rotate")
	}
	return true, nil
}

func (s *protectedFileStore) removeRotationArtifactLocked(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return storageOperationError("rotate")
	}
	return nil
}

func (s *protectedFileStore) rotationActivePath() string {
	return filepath.Join(s.root, rotationActiveName)
}

func (s *protectedFileStore) rotationCommittedPath() string {
	return filepath.Join(s.root, rotationCommittedName)
}

func (s *protectedFileStore) rotationStagePath(new Ref) string {
	return filepath.Join(s.root, ".rotate-"+new.ProtectedValue()+".new")
}

func (s *protectedFileStore) rotationBackupPath(old, new Ref) string {
	return filepath.Join(s.root, ".rotate-"+old.ProtectedValue()+"-"+new.ProtectedValue()+".bak")
}

func (s *protectedFileStore) unusedRefLocked() (Ref, error) {
	for attempts := 0; attempts < 16; attempts++ {
		ref, err := newRef()
		if err != nil {
			return "", err
		}
		if _, err := os.Lstat(s.path(ref)); errors.Is(err, os.ErrNotExist) {
			return ref, nil
		} else if err != nil {
			return "", storageOperationError("put")
		}
	}
	return "", errors.New("could not allocate an opaque credential reference")
}

func (s *protectedFileStore) path(ref Ref) string {
	return filepath.Join(s.root, ref.ProtectedValue()+".bin")
}

func validateProtected(value []byte) error {
	if len(value) == 0 || len(value) > maxProtectedSecretBytes {
		return errors.New("protected credential payload is invalid")
	}
	return nil
}

func unknownFileRotation(old, new Ref) error {
	return &OutcomeUnknownError{Operation: "rotate", OldRef: old, NewRef: new}
}

func storageOperationError(operation string) error {
	return errors.New("credential storage " + operation + " failed")
}

var _ SecretStore = (*protectedFileStore)(nil)
