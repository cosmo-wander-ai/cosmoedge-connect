package credential

import (
	"errors"
	"os"
	"sync"
	"testing"
)

func TestRotationJournalEnforcesOneUnacknowledgedReceiptPerOldRefAcrossInstances(t *testing.T) {
	root := t.TempDir()
	first, err := openRotationJournal(root)
	if err != nil {
		t.Fatalf("open first journal: %v", err)
	}
	second, err := openRotationJournal(root)
	if err != nil {
		t.Fatalf("open second journal: %v", err)
	}

	oldRef := newRotationJournalTestRef(t)
	firstNewRef := newRotationJournalTestRef(t)
	secondNewRef := newRotationJournalTestRef(t)
	winner, err := first.Create(oldRef, firstNewRef)
	if err != nil {
		t.Fatalf("create winning receipt: %v", err)
	}
	observed, err := second.Create(oldRef, secondNewRef)
	if err != nil {
		t.Fatalf("create competing receipt: %v", err)
	}
	if observed != winner {
		t.Fatalf("competing create returned a different receipt: got %#v want %#v", observed, winner)
	}
	if observed.NewRef == secondNewRef {
		t.Fatal("competing create retained its losing reference")
	}
}

func TestRotationJournalRejectsTerminalPhaseRegressionAndMisindexedReceipt(t *testing.T) {
	journal, err := openRotationJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldRef := newRotationJournalTestRef(t)
	receipt, err := journal.Create(oldRef, newRotationJournalTestRef(t))
	if err != nil {
		t.Fatal(err)
	}
	committed, err := journal.Update(receipt, RotationCommitted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Update(receipt, RotationUnknown); err == nil {
		t.Fatal("terminal committed receipt regressed to unknown")
	}
	if current, err := journal.Get(receipt.OperationID); err != nil || current != committed {
		t.Fatalf("terminal receipt changed: got %#v err=%v want %#v", current, err, committed)
	}

	wrongIndex := journal.pathForOldRef(newRotationJournalTestRef(t))
	if err := os.Rename(journal.pathForOldRef(oldRef), wrongIndex); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Get(receipt.OperationID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("misindexed receipt was not rejected: %v", err)
	}
}

func TestRotationJournalAtomicallyCreatesOldRefIndex(t *testing.T) {
	root := t.TempDir()
	first, err := openRotationJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := openRotationJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	oldRef := newRotationJournalTestRef(t)
	firstID, err := newRotationID()
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := newRotationID()
	if err != nil {
		t.Fatal(err)
	}
	receipts := []RotationReceipt{
		{OperationID: firstID, OldRef: oldRef, NewRef: newRotationJournalTestRef(t), Phase: RotationPrepared},
		{OperationID: secondID, OldRef: oldRef, NewRef: newRotationJournalTestRef(t), Phase: RotationPrepared},
	}
	type result struct {
		receipt RotationReceipt
		err     error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, journal := range []*rotationJournal{first, second} {
		wait.Add(1)
		go func(journal *rotationJournal, receipt RotationReceipt) {
			defer wait.Done()
			<-start
			results <- result{receipt: receipt, err: journal.writeNew(receipt)}
		}(journal, receipts[index])
	}
	close(start)
	wait.Wait()
	close(results)
	var winner RotationReceipt
	created, rejected := 0, 0
	for outcome := range results {
		switch {
		case outcome.err == nil:
			winner = outcome.receipt
			created++
		case errors.Is(outcome.err, errRotationReceiptExists):
			rejected++
		default:
			t.Fatalf("unexpected atomic-create error: %v", outcome.err)
		}
	}
	if created != 1 || rejected != 1 {
		t.Fatalf("atomic receipt creation created=%d rejected=%d", created, rejected)
	}
	if stored, err := first.ByOldRef(oldRef); err != nil || stored != winner {
		t.Fatalf("stored atomic winner=%#v err=%v want=%#v", stored, err, winner)
	}
}

func newRotationJournalTestRef(t *testing.T) Ref {
	t.Helper()
	ref, err := newRef()
	if err != nil {
		t.Fatalf("allocate reference: %v", err)
	}
	return ref
}
