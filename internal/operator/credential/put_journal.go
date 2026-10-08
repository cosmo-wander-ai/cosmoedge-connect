package credential

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const maxPutReceiptBytes = 1536

type putJournal struct {
	root string
}

type putReceiptDisk struct {
	Version     int    `json:"version"`
	OperationID string `json:"operationId"`
	Ref         string `json:"ref"`
	Phase       string `json:"phase"`
}

func openPutJournal(parent string) (*putJournal, error) {
	root := filepath.Join(parent, ".credential-puts")
	if _, err := os.Lstat(root); err == nil {
		if err := localstate.ValidateStateRoot(root); err != nil {
			return nil, errors.New("reject existing credential put journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("credential put journal is unavailable")
	} else if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, errors.New("credential put journal creation failed")
	}
	journal := &putJournal{root: root}
	if err := journal.cleanupInterruptedUpdates(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *putJournal) cleanupInterruptedUpdates() error {
	entries, err := os.ReadDir(journal.root)
	if err != nil {
		return errors.New("credential put journal is unavailable")
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".receipt-") && strings.HasSuffix(name, ".tmp") && !entry.IsDir() {
			path := filepath.Join(journal.root, name)
			if localstate.ValidateFile(path) != nil || os.Remove(path) != nil {
				return errors.New("credential put journal recovery failed")
			}
		}
	}
	return nil
}

func (journal *putJournal) Create(operationID PutOperationID, ref Ref) (PutReceipt, error) {
	receipt := PutReceipt{OperationID: operationID, Ref: ref, Phase: PutPrepared}
	if !receipt.Valid() {
		return PutReceipt{}, errors.New("credential put receipt is invalid")
	}
	if _, err := journal.Get(operationID); err == nil {
		return PutReceipt{}, errors.New("credential put operation already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return PutReceipt{}, err
	}
	if err := journal.writeNew(receipt); err != nil {
		return PutReceipt{}, err
	}
	return receipt, nil
}

func (journal *putJournal) Update(receipt PutReceipt, phase PutPhase) (PutReceipt, error) {
	if !receipt.Valid() || !phase.valid() {
		return PutReceipt{}, errors.New("credential put receipt is invalid")
	}
	current, err := journal.Get(receipt.OperationID)
	if err != nil || current.Ref != receipt.Ref {
		return PutReceipt{}, errors.New("credential put receipt binding changed")
	}
	if !allowedPutReceiptTransition(current.Phase, phase) {
		return PutReceipt{}, errors.New("credential put receipt transition is invalid")
	}
	current.Phase = phase
	if err := journal.replace(current); err != nil {
		return PutReceipt{}, err
	}
	return current, nil
}

func (journal *putJournal) Get(operationID PutOperationID) (PutReceipt, error) {
	if !operationID.Valid() {
		return PutReceipt{}, ErrInvalidPutOperationID
	}
	path := journal.path(operationID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return PutReceipt{}, ErrNotFound
	}
	if err != nil || info.Size() <= 0 || info.Size() > maxPutReceiptBytes || localstate.ValidateFile(path) != nil {
		return PutReceipt{}, errors.New("credential put receipt is invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return PutReceipt{}, errors.New("credential put receipt is unavailable")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var stored putReceiptDisk
	if err := decoder.Decode(&stored); err != nil {
		return PutReceipt{}, errors.New("credential put receipt is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PutReceipt{}, errors.New("credential put receipt is invalid")
	}
	id, idErr := ParsePutOperationID(stored.OperationID)
	ref, refErr := ParseRef(stored.Ref)
	receipt := PutReceipt{OperationID: id, Ref: ref, Phase: PutPhase(stored.Phase)}
	if stored.Version != 1 || idErr != nil || refErr != nil || id != operationID || !receipt.Valid() {
		return PutReceipt{}, errors.New("credential put receipt is invalid")
	}
	return receipt, nil
}

func allowedPutReceiptTransition(from, to PutPhase) bool {
	if from == to {
		return true
	}
	switch from {
	case PutPrepared:
		return to == PutCommitted || to == PutRolledBack || to == PutUnknown
	case PutCommitted:
		// A committed unattached Put may be compensated after a business-store
		// conflict. If deletion cannot be proven, it becomes unknown.
		return to == PutRolledBack || to == PutUnknown
	case PutRolledBack:
		// Reconciliation can discover that removal of a stale backend object is
		// ambiguous, but a rolled-back receipt must never resurrect as committed.
		return to == PutUnknown
	case PutUnknown:
		return to == PutCommitted || to == PutRolledBack
	default:
		return false
	}
}

func (journal *putJournal) Delete(operationID PutOperationID) error {
	if !operationID.Valid() {
		return ErrInvalidPutOperationID
	}
	path := journal.path(operationID)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil || localstate.ValidateFile(path) != nil {
		return errors.New("credential put acknowledgement failed")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("credential put acknowledgement failed")
	}
	if err := syncContainingDirectory(path); err != nil {
		return errors.New("credential put acknowledgement failed")
	}
	return nil
}

func (journal *putJournal) writeNew(receipt PutReceipt) error {
	raw, err := encodePutReceipt(receipt)
	if err != nil {
		return err
	}
	defer clear(raw)
	path := journal.path(receipt.OperationID)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("credential put receipt creation failed")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return errors.New("credential put receipt creation failed")
	}
	if err := file.Sync(); err != nil {
		return errors.New("credential put receipt creation failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("credential put receipt creation failed")
	}
	if err := localstate.ProtectFile(path); err != nil {
		return errors.New("credential put receipt creation failed")
	}
	if err := syncContainingDirectory(path); err != nil {
		return errors.New("credential put receipt creation failed")
	}
	ok = true
	return nil
}

func (journal *putJournal) replace(receipt PutReceipt) error {
	raw, err := encodePutReceipt(receipt)
	if err != nil {
		return err
	}
	defer clear(raw)
	temporary, err := os.CreateTemp(journal.root, ".receipt-*.tmp")
	if err != nil {
		return errors.New("credential put receipt update failed")
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("credential put receipt update failed")
	}
	if _, err := temporary.Write(raw); err != nil {
		return errors.New("credential put receipt update failed")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("credential put receipt update failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("credential put receipt update failed")
	}
	if err := localstate.ProtectFile(temporaryPath); err != nil {
		return errors.New("credential put receipt update failed")
	}
	if err := durableReplace(temporaryPath, journal.path(receipt.OperationID)); err != nil {
		return errors.New("credential put receipt update failed")
	}
	ok = true
	return nil
}

func (journal *putJournal) path(operationID PutOperationID) string {
	return filepath.Join(journal.root, operationID.ProtectedValue()+".json")
}

func encodePutReceipt(receipt PutReceipt) ([]byte, error) {
	if !receipt.Valid() {
		return nil, errors.New("credential put receipt is invalid")
	}
	return json.Marshal(putReceiptDisk{
		Version: 1, OperationID: receipt.OperationID.ProtectedValue(), Ref: receipt.Ref.ProtectedValue(), Phase: string(receipt.Phase),
	})
}
