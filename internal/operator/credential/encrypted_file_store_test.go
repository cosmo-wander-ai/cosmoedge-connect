package credential

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedFileStoreRoundTripRestartAndExactIdempotency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected", "credentials.bin")
	key := bytes.Repeat([]byte{0x42}, 32)
	store, err := OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("authority-envelope-private-value")
	put, err := store.Put(context.Background(), putID, secret)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.Put(context.Background(), putID, []byte("must-not-replace-first-value"))
	if err != nil || replayed != put {
		t.Fatalf("idempotent Put receipt mismatch: %#v, %v", replayed, err)
	}
	opened, err := store.Get(context.Background(), put.Ref)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("opened secret mismatch: %v", err)
	}
	clear(opened)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	recovered, err := store.RecoverPut(context.Background(), putID)
	if err != nil || recovered != put {
		t.Fatalf("restart Put receipt mismatch: %#v, %v", recovered, err)
	}
	rotation, err := store.Rotate(context.Background(), put.Ref, []byte("rotated-private-value"))
	if err != nil {
		t.Fatal(err)
	}
	replayedRotation, err := store.Rotate(context.Background(), put.Ref, []byte("must-not-start-second-rotation"))
	if err != nil || replayedRotation != rotation {
		t.Fatalf("idempotent rotation mismatch: %#v, %v", replayedRotation, err)
	}
	if _, err := store.Get(context.Background(), put.Ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old reference survived rotation: %v", err)
	}
	rotated, err := store.Get(context.Background(), rotation.NewRef)
	if err != nil || string(rotated) != "rotated-private-value" {
		t.Fatalf("rotated secret mismatch: %v", err)
	}
	clear(rotated)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredRotation, err := store.RecoverRotation(context.Background(), rotation.OperationID); err != nil || recoveredRotation != rotation {
		t.Fatalf("restart rotation mismatch: %#v, %v", recoveredRotation, err)
	}
	if err := store.AcknowledgePut(context.Background(), putID); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeRotation(context.Background(), rotation.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgePut(context.Background(), putID); err != nil {
		t.Fatalf("Put acknowledgement is not idempotent: %v", err)
	}
	if err := store.AcknowledgeRotation(context.Background(), rotation.OperationID); err != nil {
		t.Fatalf("rotation acknowledgement is not idempotent: %v", err)
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{string(secret), "rotated-private-value", put.Ref.ProtectedValue(), putID.ProtectedValue()} {
		if bytes.Contains(persisted, []byte(forbidden)) {
			t.Fatalf("encrypted file exposed protected material")
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 2 || entries[0].Name() != filepath.Base(path) || entries[1].Name() != filepath.Base(path)+".lock" {
		t.Fatalf("atomic replacement left artifacts: %#v, %v", entries, err)
	}
}

func TestEncryptedFileStoreSerializesMultipleOpenInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected", "credentials.bin")
	key := bytes.Repeat([]byte{0x31}, 32)
	first, err := OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	firstID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	firstReceipt, err := first.Put(context.Background(), firstID, []byte("first-private-value"))
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err := second.Put(context.Background(), secondID, []byte("second-private-value"))
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := second.RecoverPut(context.Background(), firstID); err != nil || recovered != firstReceipt {
		t.Fatalf("second instance lost first receipt: %#v, %v", recovered, err)
	}
	if recovered, err := first.RecoverPut(context.Background(), secondID); err != nil || recovered != secondReceipt {
		t.Fatalf("first instance lost second receipt: %#v, %v", recovered, err)
	}
	for store, target := range map[*EncryptedFileStore]Ref{first: secondReceipt.Ref, second: firstReceipt.Ref} {
		opened, err := store.Get(context.Background(), target)
		if err != nil {
			t.Fatalf("cross-instance secret unavailable: %v", err)
		}
		clear(opened)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if recovered, err := reopened.RecoverPut(context.Background(), firstID); err != nil || recovered != firstReceipt {
		t.Fatalf("restart lost first receipt: %#v, %v", recovered, err)
	}
	if recovered, err := reopened.RecoverPut(context.Background(), secondID); err != nil || recovered != secondReceipt {
		t.Fatalf("restart lost second receipt: %#v, %v", recovered, err)
	}
}

func TestEncryptedFileStoreCompensatesDurably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected", "credentials.bin")
	key := bytes.Repeat([]byte{0x27}, 32)
	store, err := OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	put, err := store.Put(context.Background(), putID, []byte("temporary-private-value"))
	if err != nil {
		t.Fatal(err)
	}
	compensated, err := store.CompensatePut(context.Background(), putID)
	if err != nil || compensated.Ref != put.Ref || compensated.Phase != PutRolledBack {
		t.Fatalf("compensation mismatch: %#v, %v", compensated, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	recovered, err := store.RecoverPut(context.Background(), putID)
	if err != nil || recovered != compensated {
		t.Fatalf("durable compensation mismatch: %#v, %v", recovered, err)
	}
	if _, err := store.Get(context.Background(), put.Ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("compensated secret still resolves: %v", err)
	}
}

func TestEncryptedFileStoreRejectsTamperAndWrongKeyWithoutLeaks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected", "credentials.bin")
	key := bytes.Repeat([]byte{0x19}, 32)
	store, err := OpenEncryptedFileStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	secret := "never-project-this-secret"
	put, err := store.Put(context.Background(), putID, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEncryptedFileStore(path, bytes.Repeat([]byte{0x20}, 32)); !errors.Is(err, ErrEncryptedFileStoreIntegrity) {
		t.Fatalf("wrong key error = %v", err)
	} else {
		assertEncryptedStoreErrorRedacted(t, err, path, secret, put.Ref.ProtectedValue())
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted[len(persisted)-1] ^= 0xff
	if err := os.WriteFile(path, persisted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEncryptedFileStore(path, key); !errors.Is(err, ErrEncryptedFileStoreIntegrity) {
		t.Fatalf("tamper error = %v", err)
	} else {
		assertEncryptedStoreErrorRedacted(t, err, path, secret, put.Ref.ProtectedValue())
	}
}

func assertEncryptedStoreErrorRedacted(t *testing.T, err error, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("error exposed protected material: %v", err)
		}
	}
}
