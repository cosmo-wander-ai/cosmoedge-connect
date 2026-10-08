package credential

import (
	"context"
	"testing"
)

func putTestSecretAndAcknowledge(t *testing.T, store SecretStore, secret []byte) Ref {
	t.Helper()
	operationID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Put(context.Background(), operationID, secret)
	if err != nil || receipt.Phase != PutCommitted {
		t.Fatalf("test Put receipt=%v err=%v", receipt, err)
	}
	if err := store.AcknowledgePut(context.Background(), operationID); err != nil {
		t.Fatal(err)
	}
	return receipt.Ref
}
