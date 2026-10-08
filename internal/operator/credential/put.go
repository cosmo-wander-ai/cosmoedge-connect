package credential

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
)

var ErrInvalidPutOperationID = errors.New("credential put operation id is invalid")

type PutOperationID string

var putOperationIDPattern = regexp.MustCompile(`^cpo_[0-9a-f]{32}$`)

func NewPutOperationID() (PutOperationID, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return PutOperationID("cpo_" + hex.EncodeToString(buffer)), nil
}

func ParsePutOperationID(value string) (PutOperationID, error) {
	id := PutOperationID(value)
	if !id.Valid() {
		return "", ErrInvalidPutOperationID
	}
	return id, nil
}

func (id PutOperationID) Valid() bool { return putOperationIDPattern.MatchString(string(id)) }

func (id PutOperationID) ProtectedValue() string { return string(id) }

func (PutOperationID) String() string   { return "[credential-put-operation-id]" }
func (PutOperationID) GoString() string { return "credential.PutOperationID([redacted])" }
func (PutOperationID) LogValue() slog.Value {
	return slog.StringValue("[credential-put-operation-id]")
}
func (PutOperationID) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (PutOperationID) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }

type PutPhase = RotationPhase

const (
	PutPrepared   PutPhase = RotationPrepared
	PutCommitted  PutPhase = RotationCommitted
	PutRolledBack PutPhase = RotationRolledBack
	PutUnknown    PutPhase = RotationUnknown
)

// PutReceipt remains in the credential backend until the caller has durably
// attached Ref to its protected business saga and acknowledges the receipt.
type PutReceipt struct {
	OperationID PutOperationID
	Ref         Ref
	Phase       PutPhase
}

func (receipt PutReceipt) Valid() bool {
	return receipt.OperationID.Valid() && receipt.Ref.Valid() && receipt.Phase.valid()
}

func (PutReceipt) String() string   { return "[credential-put-receipt]" }
func (PutReceipt) GoString() string { return "credential.PutReceipt([redacted])" }
func (PutReceipt) LogValue() slog.Value {
	return slog.StringValue("[credential-put-receipt]")
}
func (PutReceipt) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (PutReceipt) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
