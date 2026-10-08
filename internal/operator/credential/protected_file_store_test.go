package credential

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

func TestProtectedFileStorePersistsOnlyProtectedBytesAndRotatesReferences(t *testing.T) {
	root := newCredentialStateRoot(t)
	store, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("windows-dpapi-plaintext-sentinel")
	old := putTestSecretAndAcknowledge(t, store, secret)
	oldPath := filepath.Join(root, "credential-blobs", old.ProtectedValue()+".bin")
	raw, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) || bytes.Equal(raw, secret) {
		t.Fatal("protected file store persisted plaintext bytes")
	}
	if err := localstate.ValidateFile(oldPath); err != nil {
		t.Fatalf("credential blob is not private: %v", err)
	}
	opened, err := store.Get(context.Background(), old)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	clear(opened)
	rotation, err := store.Rotate(context.Background(), old, []byte("rotated-dpapi-secret"))
	newReference := rotation.NewRef
	if err != nil || newReference == old || rotation.Phase != RotationCommitted {
		t.Fatalf("rotation receipt=%v err=%v", rotation, err)
	}
	if _, err := store.Get(context.Background(), old); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old protected-file reference survived: %v", err)
	}
	opened, err = store.Get(context.Background(), newReference)
	if err != nil || string(opened) != "rotated-dpapi-secret" {
		t.Fatalf("rotated secret=%q err=%v", opened, err)
	}
	clear(opened)
	entries, err := os.ReadDir(filepath.Join(root, "credential-blobs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() == ".credential-rotations" {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".rotate-") || strings.Contains(entry.Name(), "rotation") {
			t.Fatalf("successful rotation left transaction artifact: %s", entry.Name())
		}
	}
	if err := store.AcknowledgeRotation(context.Background(), rotation.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), newReference); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), newReference); err != nil {
		t.Fatalf("Delete is not idempotent: %v", err)
	}
}

func TestProtectedFileStoreRejectsInvalidReferenceAndCorruption(t *testing.T) {
	root := newCredentialStateRoot(t)
	store, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), Ref("../../escape")); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("path-like reference error=%v", err)
	}
	ref := putTestSecretAndAcknowledge(t, store, []byte("valid-secret"))
	path := filepath.Join(root, "credential-blobs", ref.ProtectedValue()+".bin")
	if err := os.WriteFile(path, []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), ref); err == nil {
		t.Fatal("corrupted protected credential was accepted")
	} else if strings.Contains(err.Error(), ref.ProtectedValue()) {
		t.Fatalf("storage error exposed credential capability: %v", err)
	}
}

func TestProtectedFileStoreRecoversActiveRotationToOldReference(t *testing.T) {
	root := newCredentialStateRoot(t)
	store, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	old := putTestSecretAndAcknowledge(t, store, []byte("old-secret-survives"))
	receipt := stageInterruptedRotation(t, store, old, []byte("uncommitted-new-secret"), false)
	newReference := receipt.NewRef
	reopened, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := reopened.Get(context.Background(), old)
	if err != nil || string(opened) != "old-secret-survives" {
		t.Fatalf("active rotation did not roll back to old: %q, %v", opened, err)
	}
	clear(opened)
	if _, err := reopened.Get(context.Background(), newReference); !errors.Is(err, ErrNotFound) {
		t.Fatalf("uncommitted new reference survived recovery: %v", err)
	}
	if recovered, err := reopened.RotationByOldRef(context.Background(), old); err != nil || recovered.Phase != RotationRolledBack || recovered.OperationID != receipt.OperationID {
		t.Fatalf("rollback receipt was not durable: %v, %v", recovered, err)
	}
}

func TestProtectedFileStoreRecoversCommittedRotationToNewReference(t *testing.T) {
	root := newCredentialStateRoot(t)
	store, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	old := putTestSecretAndAcknowledge(t, store, []byte("old-secret-is-retired"))
	receipt := stageInterruptedRotation(t, store, old, []byte("committed-new-secret"), true)
	newReference := receipt.NewRef
	reopened, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Get(context.Background(), old); !errors.Is(err, ErrNotFound) {
		t.Fatalf("committed recovery restored old reference: %v", err)
	}
	opened, err := reopened.Get(context.Background(), newReference)
	if err != nil || string(opened) != "committed-new-secret" {
		t.Fatalf("committed rotation did not retain new: %q, %v", opened, err)
	}
	clear(opened)
	if recovered, err := reopened.RotationByOldRef(context.Background(), old); err != nil || recovered.Phase != RotationCommitted || recovered.OperationID != receipt.OperationID {
		t.Fatalf("commit receipt was not durable: %v, %v", recovered, err)
	}
}

func TestProtectedFileStoreRecoversPreparedRotationBeforeManifest(t *testing.T) {
	root := newCredentialStateRoot(t)
	store, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	old := putTestSecretAndAcknowledge(t, store, []byte("old-before-manifest"))
	newReference, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.journal.Create(old, newReference)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := store.protector.Protect([]byte("staged-before-manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.writeProtectedPathLocked(store.rotationStagePath(newReference), protected); err != nil {
		clear(protected)
		t.Fatal(err)
	}
	clear(protected)
	reopened, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.RecoverRotation(context.Background(), receipt.OperationID)
	if err != nil || recovered.Phase != RotationRolledBack {
		t.Fatalf("pre-manifest rotation recovery=%v err=%v", recovered, err)
	}
	if _, err := os.Lstat(reopened.rotationStagePath(newReference)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-manifest staged blob survived recovery: %v", err)
	}
}

func TestProtectedFileStoreRejectsCorruptRotationManifestAsOutcomeUnknown(t *testing.T) {
	root := newCredentialStateRoot(t)
	store, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.rotationActivePath(), []byte(`{"version":1,"oldRef":"cred_private"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newProtectedFileStore(root, xorProtector{}); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("corrupt rotation manifest was not fail-closed: %v", err)
	}
}

func TestProtectedFileStoreRecoversAndCompensatesDurablePutReceipts(t *testing.T) {
	root := newCredentialStateRoot(t)
	store, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Put(context.Background(), operationID, []byte("persisted-put-secret"))
	if err != nil || receipt.Phase != PutCommitted {
		t.Fatalf("Put receipt=%v err=%v", receipt, err)
	}
	reopened, err := newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := reopened.PutByOperationID(context.Background(), operationID); err != nil || recovered != receipt {
		t.Fatalf("reopened Put receipt=%v err=%v", recovered, err)
	}
	if err := reopened.AcknowledgePut(context.Background(), operationID); err != nil {
		t.Fatal(err)
	}
	opened, err := reopened.Get(context.Background(), receipt.Ref)
	if err != nil || string(opened) != "persisted-put-secret" {
		t.Fatalf("acknowledging Put removed secret: %q, %v", opened, err)
	}
	clear(opened)

	preparedID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	preparedRef, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := reopened.puts.Create(preparedID, preparedRef)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err = newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.RecoverPut(context.Background(), prepared.OperationID)
	if err != nil || recovered.Phase != PutRolledBack {
		t.Fatalf("prepared Put without blob did not roll back: %v, %v", recovered, err)
	}
	if err := reopened.AcknowledgePut(context.Background(), prepared.OperationID); err != nil {
		t.Fatal(err)
	}
	crashID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	crashRef, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	crashReceipt, err := reopened.puts.Create(crashID, crashRef)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := reopened.protector.Protect([]byte("installed-before-receipt-update"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.writeNewLocked(crashRef, protected); err != nil {
		clear(protected)
		t.Fatal(err)
	}
	clear(protected)
	reopened, err = newProtectedFileStore(root, xorProtector{})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err = reopened.RecoverPut(context.Background(), crashReceipt.OperationID)
	if err != nil || recovered.Phase != PutCommitted || recovered.Ref != crashRef {
		t.Fatalf("installed Put was not recovered as committed: %v, %v", recovered, err)
	}
	compensated, err := reopened.CompensatePut(context.Background(), crashReceipt.OperationID)
	if err != nil || compensated.Phase != PutRolledBack {
		t.Fatalf("recovered Put compensation=%v err=%v", compensated, err)
	}
	if _, err := reopened.Get(context.Background(), crashRef); !errors.Is(err, ErrNotFound) {
		t.Fatalf("compensated recovered Put survived: %v", err)
	}
	if err := reopened.AcknowledgePut(context.Background(), crashReceipt.OperationID); err != nil {
		t.Fatal(err)
	}

	compensated, err = reopened.CompensatePut(context.Background(), operationID)
	if !errors.Is(err, ErrNotFound) || compensated.Valid() {
		t.Fatalf("acknowledged Put receipt was still compensatable: %v, %v", compensated, err)
	}
}

func stageInterruptedRotation(t *testing.T, store *protectedFileStore, old Ref, secret []byte, committed bool) RotationReceipt {
	t.Helper()
	newReference, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	protected, err := store.protector.Protect(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	if err := store.writeProtectedPathLocked(store.rotationStagePath(newReference), protected); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.journal.Create(old, newReference)
	if err != nil {
		t.Fatal(err)
	}
	manifest := rotationManifest{
		Version: rotationManifestVersion, OperationID: receipt.OperationID.ProtectedValue(),
		OldRef: old.ProtectedValue(), NewRef: newReference.ProtectedValue(),
	}
	if err := store.writeRotationManifestLocked(store.rotationActivePath(), manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(store.path(old), store.rotationBackupPath(old, newReference)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(store.rotationStagePath(newReference), store.path(newReference)); err != nil {
		t.Fatal(err)
	}
	if committed {
		if err := os.Rename(store.rotationActivePath(), store.rotationCommittedPath()); err != nil {
			t.Fatal(err)
		}
	}
	return receipt
}

type xorProtector struct{}

func (xorProtector) Protect(secret []byte) ([]byte, error) {
	result := make([]byte, len(secret)+4)
	copy(result, []byte{0x43, 0x45, 0x01, 0xa5})
	for index := range secret {
		result[index+4] = secret[index] ^ 0xa5
	}
	return result, nil
}

func (xorProtector) Unprotect(protected []byte) ([]byte, error) {
	if len(protected) <= 4 || !bytes.Equal(protected[:4], []byte{0x43, 0x45, 0x01, 0xa5}) {
		return nil, errors.New("invalid fake envelope")
	}
	result := make([]byte, len(protected)-4)
	for index := range result {
		result[index] = protected[index+4] ^ 0xa5
	}
	return result, nil
}

var _ secretProtector = xorProtector{}

func newCredentialStateRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "operator-state")
}
