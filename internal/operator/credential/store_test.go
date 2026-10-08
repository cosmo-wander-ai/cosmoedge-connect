package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestRefAndOutcomeUnknownRejectGenericJSONProjection(t *testing.T) {
	ref, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := json.Marshal(ref); err == nil || len(raw) != 0 {
		t.Fatalf("credential capability serialized: %s, %v", raw, err)
	}
	outcome := &OutcomeUnknownError{Operation: "rotate", OldRef: ref, NewRef: ref}
	if raw, err := json.Marshal(outcome); err == nil || len(raw) != 0 {
		t.Fatalf("outcome binding serialized: %s, %v", raw, err)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", outcome), fmt.Sprintf("%+v", outcome), fmt.Sprintf("%#v", outcome)} {
		if strings.Contains(formatted, ref.ProtectedValue()) {
			t.Fatalf("outcome formatting leaked capability: %s", formatted)
		}
	}
	var log bytes.Buffer
	slog.New(slog.NewTextHandler(&log, nil)).Info("outcome", "value", outcome)
	if strings.Contains(log.String(), ref.ProtectedValue()) {
		t.Fatalf("outcome structured log leaked capability: %s", log.String())
	}
	outcome.Operation = "secret-value"
	if strings.Contains(outcome.Error(), outcome.Operation) {
		t.Fatalf("untrusted operation entered sanitized error: %v", outcome)
	}
}

func TestMemoryStoreConformance(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(store.Purge)
	ctx := context.Background()
	first := []byte("first-private-device-secret")
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	putReceipt, err := store.Put(ctx, putID, first)
	if err != nil {
		t.Fatal(err)
	}
	ref := putReceipt.Ref
	if putReceipt.Phase != PutCommitted || putReceipt.OperationID != putID {
		t.Fatalf("Put did not return a durable committed receipt: %v", putReceipt)
	}
	if recovered, err := store.PutByOperationID(ctx, putID); err != nil || recovered != putReceipt {
		t.Fatalf("Put receipt was not recoverable: %v, %v", recovered, err)
	}
	retried, err := store.Put(ctx, putID, []byte("must-not-replace-first-secret"))
	if err != nil || retried != putReceipt {
		t.Fatalf("same Put operation was not idempotent: %v, %v", retried, err)
	}
	if !ref.Valid() || strings.Contains(ref.ProtectedValue(), string(first)) {
		t.Fatalf("reference is not opaque: %q", ref)
	}
	if strings.Contains(ref.String(), "cred_") || strings.Contains(ref.GoString(), "cred_") {
		t.Fatalf("reference formatting exposed bearer capability: %s / %#v", ref, ref)
	}
	first[0] = 'X'
	opened, err := store.Get(ctx, ref)
	if err != nil || string(opened) != "first-private-device-secret" {
		t.Fatalf("stored secret did not own its input: %q, %v", opened, err)
	}
	opened[0] = 'Y'
	again, err := store.Get(ctx, ref)
	if err != nil || string(again) != "first-private-device-secret" {
		t.Fatalf("Get leaked its backing buffer: %q, %v", again, err)
	}
	clear(opened)
	clear(again)
	if err := store.AcknowledgePut(ctx, putID); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgePut(ctx, putID); err != nil {
		t.Fatalf("Put acknowledgement is not idempotent: %v", err)
	}

	second := []byte("rotated-private-device-secret")
	rotation, err := store.Rotate(ctx, ref, second)
	if err != nil {
		t.Fatal(err)
	}
	rotated := rotation.NewRef
	if rotated == ref || !rotated.Valid() || !rotation.OperationID.Valid() || rotation.Phase != RotationCommitted {
		t.Fatalf("rotation did not issue a durable committed receipt: %v", rotation)
	}
	if raw, err := json.Marshal(rotation); err == nil || len(raw) != 0 {
		t.Fatalf("rotation receipt serialized: %s, %v", raw, err)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", rotation), fmt.Sprintf("%#v", rotation)} {
		if strings.Contains(formatted, "cred_") || strings.Contains(formatted, "cro_") {
			t.Fatalf("rotation receipt formatting leaked capabilities: %s", formatted)
		}
	}
	if _, err := store.Get(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old reference remained valid after rotation: %v", err)
	}
	opened, err = store.Get(ctx, rotated)
	if err != nil || !bytes.Equal(opened, second) {
		t.Fatalf("rotated reference mismatch: %q, %v", opened, err)
	}
	clear(opened)
	recovered, err := store.RotationByOldRef(ctx, ref)
	if err != nil || recovered != rotation {
		t.Fatalf("rotation receipt was not recoverable by old ref: %v, %v", recovered, err)
	}
	if err := store.AcknowledgeRotation(ctx, rotation.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeRotation(ctx, rotation.OperationID); err != nil {
		t.Fatalf("rotation acknowledgement is not idempotent: %v", err)
	}
	if _, err := store.RotationByOldRef(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acknowledged rotation receipt survived: %v", err)
	}
	if err := store.Delete(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, rotated); err != nil {
		t.Fatalf("Delete is not idempotent: %v", err)
	}
	if _, err := store.Get(ctx, rotated); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted reference still resolves: %v", err)
	}
}

func TestMemoryStoreCompensatesDurablePutReceipt(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(store.Purge)
	operationID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Put(context.Background(), operationID, []byte("orphan-candidate"))
	if err != nil || receipt.Phase != PutCommitted {
		t.Fatalf("Put receipt=%v err=%v", receipt, err)
	}
	if raw, err := json.Marshal(receipt); err == nil || len(raw) != 0 {
		t.Fatalf("Put receipt serialized: %s, %v", raw, err)
	}
	compensated, err := store.CompensatePut(context.Background(), operationID)
	if err != nil || compensated.Phase != PutRolledBack {
		t.Fatalf("Put compensation=%v err=%v", compensated, err)
	}
	if _, err := store.Get(context.Background(), receipt.Ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("compensated Put secret survived: %v", err)
	}
	if err := store.AcknowledgePut(context.Background(), operationID); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgePut(context.Background(), operationID); err != nil {
		t.Fatalf("Put acknowledgement is not idempotent: %v", err)
	}
}

func TestMemoryStoreRecoversDeleteBeforePutReceiptPhaseUpdate(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(store.Purge)
	operationID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Put(context.Background(), operationID, []byte("delete-before-phase-update"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), receipt.Ref); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.RecoverPut(context.Background(), operationID)
	if err != nil || recovered.Phase != PutRolledBack {
		t.Fatalf("deleted Put did not recover as rolled back: %v, %v", recovered, err)
	}
}

func TestMemoryStoreDoesNotAcknowledgeUnknownRotation(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(store.Purge)
	old := putTestSecretAndAcknowledge(t, store, []byte("old-secret"))
	receipt, err := store.Rotate(context.Background(), old, []byte("new-secret"))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	receipt.Phase = RotationUnknown
	store.rotations[receipt.OperationID] = receipt
	store.mu.Unlock()
	if err := store.AcknowledgeRotation(context.Background(), receipt.OperationID); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unknown rotation was acknowledged: %v", err)
	}
	recovered, err := store.RecoverRotation(context.Background(), receipt.OperationID)
	if err != nil || recovered.Phase != RotationCommitted {
		t.Fatalf("unknown memory rotation was not reconciled: %v, %v", recovered, err)
	}
	if err := store.AcknowledgeRotation(context.Background(), receipt.OperationID); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryStoreRejectsInvalidInputsAndCancellation(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(store.Purge)
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), putID, nil); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("empty secret error=%v", err)
	}
	if _, err := store.Put(context.Background(), putID, make([]byte, maxSecretBytes+1)); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("oversized secret error=%v", err)
	}
	if _, err := store.Get(context.Background(), Ref("not-a-reference")); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("invalid reference error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Put(cancelled, putID, []byte("must-not-be-retained")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Put error=%v", err)
	}
}

func TestCredentialStoreRejectsNilContext(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(store.Purge)
	operationID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(nil, operationID, []byte("must-not-be-retained")); err == nil {
		t.Fatal("nil context was accepted")
	}
	ref := Ref("cred_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := store.Get(nil, ref); err == nil {
		t.Fatal("nil context was accepted by Get")
	}
}

func TestMemoryStoreConcurrentReferencesRemainIsolated(t *testing.T) {
	store := NewMemoryStore()
	t.Cleanup(store.Purge)
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			secret := bytes.Repeat([]byte{value}, 32)
			operationID, err := NewPutOperationID()
			if err != nil {
				errorsSeen <- err
				return
			}
			receipt, err := store.Put(context.Background(), operationID, secret)
			if err != nil {
				errorsSeen <- err
				return
			}
			opened, err := store.Get(context.Background(), receipt.Ref)
			if err != nil || !bytes.Equal(opened, secret) {
				errorsSeen <- errors.New("concurrent secret mismatch")
			}
			clear(opened)
		}(byte(index + 1))
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
}

func TestUnsupportedStoreFailsClosed(t *testing.T) {
	store := UnsupportedStore{}
	valid, err := newRef()
	if err != nil {
		t.Fatal(err)
	}
	putID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), putID, []byte("private")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Put error=%v", err)
	}
	if _, err := store.Get(context.Background(), valid); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Get error=%v", err)
	}
	if err := store.Delete(context.Background(), valid); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Delete error=%v", err)
	}
	if _, err := store.Rotate(context.Background(), valid, []byte("private")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Rotate error=%v", err)
	}
}
