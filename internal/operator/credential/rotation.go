package credential

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
)

var ErrInvalidRotationID = errors.New("credential rotation operation id is invalid")

type RotationID string

var rotationIDPattern = regexp.MustCompile(`^cro_[0-9a-f]{32}$`)

func ParseRotationID(value string) (RotationID, error) {
	id := RotationID(value)
	if !id.Valid() {
		return "", ErrInvalidRotationID
	}
	return id, nil
}

func newRotationID() (RotationID, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return RotationID("cro_" + hex.EncodeToString(buffer)), nil
}

func (id RotationID) Valid() bool { return rotationIDPattern.MatchString(string(id)) }

func (id RotationID) ProtectedValue() string { return string(id) }

func (RotationID) String() string   { return "[credential-rotation-id]" }
func (RotationID) GoString() string { return "credential.RotationID([redacted])" }
func (RotationID) LogValue() slog.Value {
	return slog.StringValue("[credential-rotation-id]")
}
func (RotationID) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (RotationID) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }

type RotationPhase string

const (
	RotationPrepared   RotationPhase = "prepared"
	RotationCommitted  RotationPhase = "committed"
	RotationRolledBack RotationPhase = "rolled_back"
	RotationUnknown    RotationPhase = "unknown"
)

func (phase RotationPhase) valid() bool {
	return phase == RotationPrepared || phase == RotationCommitted || phase == RotationRolledBack || phase == RotationUnknown
}

func (phase RotationPhase) terminal() bool {
	return phase == RotationCommitted || phase == RotationRolledBack
}

// RotationReceipt is protected coordination state. It intentionally remains
// in the credential backend after Rotate returns so a caller that crashes
// before saving its business saga can recover the new reference by OldRef.
type RotationReceipt struct {
	OperationID RotationID
	OldRef      Ref
	NewRef      Ref
	Phase       RotationPhase
}

func (receipt RotationReceipt) Valid() bool {
	return receipt.OperationID.Valid() && receipt.OldRef.Valid() && receipt.NewRef.Valid() &&
		receipt.OldRef != receipt.NewRef && receipt.Phase.valid()
}

func (RotationReceipt) String() string   { return "[credential-rotation-receipt]" }
func (RotationReceipt) GoString() string { return "credential.RotationReceipt([redacted])" }
func (RotationReceipt) LogValue() slog.Value {
	return slog.StringValue("[credential-rotation-receipt]")
}
func (RotationReceipt) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (RotationReceipt) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
