//go:build windows

package credential

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestWindowsDPAPIAndProtectedStoreRoundTrip(t *testing.T) {
	root := newCredentialStateRoot(t)
	prepared, err := prepareSystemRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := namespaceForRoot(prepared)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := newWindowsProtector(namespace)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("windows-private-device-secret")
	protected, err := protector.Protect(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected, secret) || bytes.Equal(protected, secret) {
		t.Fatal("DPAPI output contains plaintext")
	}
	opened, err := protector.Unprotect(protected)
	clear(protected)
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("DPAPI opened=%q err=%v", opened, err)
	}
	clear(opened)

	store, err := OpenSystemStore(root)
	if err != nil {
		t.Fatal(err)
	}
	ref := putTestSecretAndAcknowledge(t, store, secret)
	rotation, err := store.Rotate(context.Background(), ref, []byte("rotated-secret"))
	if err != nil {
		t.Fatal(err)
	}
	rotated := rotation.NewRef
	reopened, err := OpenSystemStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := reopened.RotationByOldRef(context.Background(), ref); err != nil || recovered != rotation {
		t.Fatalf("DPAPI rotation receipt=%v err=%v", recovered, err)
	}
	if err := reopened.AcknowledgeRotation(context.Background(), rotation.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old DPAPI reference survived rotation: %v", err)
	}
	opened, err = store.Get(context.Background(), rotated)
	if err != nil || string(opened) != "rotated-secret" {
		t.Fatalf("rotated secret=%q err=%v", opened, err)
	}
	clear(opened)
	if err := store.Delete(context.Background(), rotated); err != nil {
		t.Fatal(err)
	}
}
