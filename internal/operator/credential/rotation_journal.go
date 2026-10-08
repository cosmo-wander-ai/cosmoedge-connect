package credential

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const maxRotationReceiptBytes = 2048

var errRotationReceiptExists = errors.New("credential rotation receipt already exists")

type rotationJournal struct {
	root string
}

type rotationReceiptDisk struct {
	Version     int    `json:"version"`
	OperationID string `json:"operationId"`
	OldRef      string `json:"oldRef"`
	NewRef      string `json:"newRef"`
	Phase       string `json:"phase"`
}

func openRotationJournal(parent string) (*rotationJournal, error) {
	root := filepath.Join(parent, ".credential-rotations")
	if _, err := os.Lstat(root); err == nil {
		if err := localstate.ValidateStateRoot(root); err != nil {
			return nil, errors.New("reject existing credential rotation journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("credential rotation journal is unavailable")
	} else if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, errors.New("credential rotation journal creation failed")
	}
	journal := &rotationJournal{root: root}
	if err := journal.cleanupInterruptedUpdates(); err != nil {
		return nil, err
	}
	return journal, nil
}

func (journal *rotationJournal) cleanupInterruptedUpdates() error {
	entries, err := os.ReadDir(journal.root)
	if err != nil {
		return errors.New("credential rotation journal is unavailable")
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".receipt-") && strings.HasSuffix(name, ".tmp") && !entry.IsDir() {
			path := filepath.Join(journal.root, name)
			if localstate.ValidateFile(path) != nil {
				return errors.New("credential rotation journal contains an invalid update")
			}
			if err := os.Remove(path); err != nil {
				return errors.New("credential rotation journal recovery failed")
			}
		}
	}
	return nil
}

func (journal *rotationJournal) Create(oldRef, newRef Ref) (RotationReceipt, error) {
	if existing, err := journal.ByOldRef(oldRef); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return RotationReceipt{}, err
	}
	operationID, err := newRotationID()
	if err != nil {
		return RotationReceipt{}, errors.New("credential rotation operation allocation failed")
	}
	receipt := RotationReceipt{OperationID: operationID, OldRef: oldRef, NewRef: newRef, Phase: RotationPrepared}
	if err := journal.writeNew(receipt); err != nil {
		if errors.Is(err, errRotationReceiptExists) {
			return journal.ByOldRef(oldRef)
		}
		return RotationReceipt{}, err
	}
	return receipt, nil
}

func (journal *rotationJournal) Update(receipt RotationReceipt, phase RotationPhase) (RotationReceipt, error) {
	if !receipt.Valid() || !phase.valid() {
		return RotationReceipt{}, errors.New("credential rotation receipt is invalid")
	}
	current, err := journal.Get(receipt.OperationID)
	if err != nil || current.OldRef != receipt.OldRef || current.NewRef != receipt.NewRef {
		return RotationReceipt{}, errors.New("credential rotation receipt binding changed")
	}
	if !allowedRotationReceiptTransition(current.Phase, phase) {
		return RotationReceipt{}, errors.New("credential rotation receipt transition is invalid")
	}
	current.Phase = phase
	if err := journal.replace(current); err != nil {
		return RotationReceipt{}, err
	}
	return current, nil
}

func (journal *rotationJournal) Get(operationID RotationID) (RotationReceipt, error) {
	if !operationID.Valid() {
		return RotationReceipt{}, ErrInvalidRotationID
	}
	entries, err := os.ReadDir(journal.root)
	if err != nil {
		return RotationReceipt{}, errors.New("credential rotation journal lookup failed")
	}
	for _, entry := range entries {
		if entry.IsDir() || !validRotationReceiptFilename(entry.Name()) {
			if strings.HasPrefix(entry.Name(), ".receipt-") && strings.HasSuffix(entry.Name(), ".tmp") && !entry.IsDir() {
				continue
			}
			return RotationReceipt{}, errors.New("credential rotation journal contains an unexpected object")
		}
		receipt, err := journal.read(filepath.Join(journal.root, entry.Name()))
		if err != nil {
			return RotationReceipt{}, err
		}
		if entry.Name() != filepath.Base(journal.pathForOldRef(receipt.OldRef)) {
			return RotationReceipt{}, errors.New("credential rotation receipt index is invalid")
		}
		if receipt.OperationID == operationID {
			return receipt, nil
		}
	}
	return RotationReceipt{}, ErrNotFound
}

func allowedRotationReceiptTransition(from, to RotationPhase) bool {
	if from == to {
		return true
	}
	return (from == RotationPrepared || from == RotationUnknown) && to != RotationPrepared
}

func (journal *rotationJournal) ByOldRef(oldRef Ref) (RotationReceipt, error) {
	if !oldRef.Valid() {
		return RotationReceipt{}, ErrInvalidRef
	}
	path := journal.pathForOldRef(oldRef)
	receipt, err := journal.read(path)
	if err != nil {
		return RotationReceipt{}, err
	}
	if receipt.OldRef != oldRef {
		return RotationReceipt{}, &OutcomeUnknownError{Operation: "rotate", OldRef: oldRef}
	}
	return receipt, nil
}

func (journal *rotationJournal) Delete(operationID RotationID) error {
	if !operationID.Valid() {
		return ErrInvalidRotationID
	}
	receipt, err := journal.Get(operationID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	path := journal.pathForOldRef(receipt.OldRef)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil || localstate.ValidateFile(path) != nil {
		return errors.New("credential rotation acknowledgement failed")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("credential rotation acknowledgement failed")
	}
	if err := syncContainingDirectory(path); err != nil {
		return errors.New("credential rotation acknowledgement failed")
	}
	return nil
}

func (journal *rotationJournal) writeNew(receipt RotationReceipt) error {
	if !receipt.Valid() {
		return errors.New("credential rotation receipt is invalid")
	}
	raw, err := encodeRotationReceipt(receipt)
	if err != nil {
		return err
	}
	defer clear(raw)
	path := journal.pathForOldRef(receipt.OldRef)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errRotationReceiptExists
		}
		return errors.New("credential rotation receipt creation failed")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return errors.New("credential rotation receipt creation failed")
	}
	if err := file.Sync(); err != nil {
		return errors.New("credential rotation receipt creation failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("credential rotation receipt creation failed")
	}
	if err := localstate.ProtectFile(path); err != nil {
		return errors.New("credential rotation receipt creation failed")
	}
	if err := syncContainingDirectory(path); err != nil {
		return errors.New("credential rotation receipt creation failed")
	}
	ok = true
	return nil
}

func (journal *rotationJournal) replace(receipt RotationReceipt) error {
	raw, err := encodeRotationReceipt(receipt)
	if err != nil {
		return err
	}
	defer clear(raw)
	temporary, err := os.CreateTemp(journal.root, ".receipt-*.tmp")
	if err != nil {
		return errors.New("credential rotation receipt update failed")
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
		return errors.New("credential rotation receipt update failed")
	}
	if _, err := temporary.Write(raw); err != nil {
		return errors.New("credential rotation receipt update failed")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("credential rotation receipt update failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("credential rotation receipt update failed")
	}
	if err := localstate.ProtectFile(temporaryPath); err != nil {
		return errors.New("credential rotation receipt update failed")
	}
	if err := durableReplace(temporaryPath, journal.pathForOldRef(receipt.OldRef)); err != nil {
		return errors.New("credential rotation receipt update failed")
	}
	ok = true
	return nil
}

func (journal *rotationJournal) read(path string) (RotationReceipt, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return RotationReceipt{}, ErrNotFound
	}
	if err != nil || info.Size() <= 0 || info.Size() > maxRotationReceiptBytes || localstate.ValidateFile(path) != nil {
		return RotationReceipt{}, errors.New("credential rotation receipt is invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return RotationReceipt{}, errors.New("credential rotation receipt is unavailable")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var stored rotationReceiptDisk
	if err := decoder.Decode(&stored); err != nil {
		return RotationReceipt{}, errors.New("credential rotation receipt is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RotationReceipt{}, errors.New("credential rotation receipt is invalid")
	}
	operationID, operationErr := ParseRotationID(stored.OperationID)
	oldRef, oldErr := ParseRef(stored.OldRef)
	newRef, newErr := ParseRef(stored.NewRef)
	receipt := RotationReceipt{OperationID: operationID, OldRef: oldRef, NewRef: newRef, Phase: RotationPhase(stored.Phase)}
	if stored.Version != 1 || operationErr != nil || oldErr != nil || newErr != nil || !receipt.Valid() {
		return RotationReceipt{}, errors.New("credential rotation receipt is invalid")
	}
	return receipt, nil
}

func (journal *rotationJournal) pathForOldRef(oldRef Ref) string {
	sum := sha256.Sum256([]byte("CosmoEdge/credential-rotation-old-index/v2\x00" + oldRef.ProtectedValue()))
	return filepath.Join(journal.root, "old_"+hex.EncodeToString(sum[:])+".json")
}

func validRotationReceiptFilename(name string) bool {
	if len(name) != len("old_")+64+len(".json") || !strings.HasPrefix(name, "old_") || !strings.HasSuffix(name, ".json") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(name, "old_"), ".json"))
	return err == nil
}

func encodeRotationReceipt(receipt RotationReceipt) ([]byte, error) {
	if !receipt.Valid() {
		return nil, errors.New("credential rotation receipt is invalid")
	}
	return json.Marshal(rotationReceiptDisk{
		Version: 1, OperationID: receipt.OperationID.ProtectedValue(), OldRef: receipt.OldRef.ProtectedValue(),
		NewRef: receipt.NewRef.ProtectedValue(), Phase: string(receipt.Phase),
	})
}
