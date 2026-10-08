package credential

import (
	"os"
	"testing"
)

func TestPutJournalRejectsStoredOperationIDFilenameMismatch(t *testing.T) {
	journal, err := openPutJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	firstID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := journal.Create(firstID, newRotationJournalTestRef(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(journal.path(firstID), journal.path(secondID)); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Get(secondID); err == nil {
		t.Fatal("receipt stored under another operation ID was accepted")
	}
	if receipt.OperationID != firstID {
		t.Fatal("test receipt binding changed unexpectedly")
	}
}

func TestPutJournalDoesNotResurrectRolledBackReceipt(t *testing.T) {
	journal, err := openPutJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := journal.Create(operationID, newRotationJournalTestRef(t))
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := journal.Update(prepared, PutRolledBack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Update(prepared, PutCommitted); err == nil {
		t.Fatal("rolled-back Put receipt resurrected as committed")
	}
	if current, err := journal.Get(operationID); err != nil || current != rolledBack {
		t.Fatalf("rolled-back receipt changed: got %#v err=%v want %#v", current, err, rolledBack)
	}
}
