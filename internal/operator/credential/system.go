package credential

import (
	"context"
	"errors"
	"log/slog"
)

var ErrOutcomeUnknown = errors.New("credential operation outcome is unknown")

// OutcomeUnknownError means a backend could not prove whether every reference
// transition completed. OldRef and NewRef are opaque and allow a later local
// reconciliation without exposing secret material.
type OutcomeUnknownError struct {
	Operation string
	OldRef    Ref
	NewRef    Ref
}

func (e *OutcomeUnknownError) Error() string {
	operation := "operation"
	switch e.Operation {
	case "put", "get", "delete", "rotate":
		operation = e.Operation
	}
	return "credential " + operation + " outcome is unknown; local reconciliation is required"
}

func (e *OutcomeUnknownError) Unwrap() error { return ErrOutcomeUnknown }

func (*OutcomeUnknownError) GoString() string {
	return "credential.OutcomeUnknownError([redacted])"
}

func (*OutcomeUnknownError) LogValue() slog.Value {
	return slog.StringValue("[credential-outcome-unknown]")
}

// MarshalJSON prevents the old and new capability references from entering a
// generic error response or telemetry envelope.
func (e *OutcomeUnknownError) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedProjection
}

func (e *OutcomeUnknownError) MarshalText() ([]byte, error) {
	return nil, ErrProtectedProjection
}

// UnsupportedStore is useful at composition boundaries that require a
// non-nil dependency. Every operation fails without retaining its inputs.
type UnsupportedStore struct{}

func (UnsupportedStore) Put(context.Context, PutOperationID, []byte) (PutReceipt, error) {
	return PutReceipt{}, ErrUnsupported
}

func (UnsupportedStore) PutByOperationID(context.Context, PutOperationID) (PutReceipt, error) {
	return PutReceipt{}, ErrUnsupported
}

func (UnsupportedStore) RecoverPut(context.Context, PutOperationID) (PutReceipt, error) {
	return PutReceipt{}, ErrUnsupported
}

func (UnsupportedStore) CompensatePut(context.Context, PutOperationID) (PutReceipt, error) {
	return PutReceipt{}, ErrUnsupported
}

func (UnsupportedStore) AcknowledgePut(context.Context, PutOperationID) error {
	return ErrUnsupported
}

func (UnsupportedStore) Get(context.Context, Ref) ([]byte, error) {
	return nil, ErrUnsupported
}

func (UnsupportedStore) Delete(context.Context, Ref) error {
	return ErrUnsupported
}

func (UnsupportedStore) Rotate(context.Context, Ref, []byte) (RotationReceipt, error) {
	return RotationReceipt{}, ErrUnsupported
}

func (UnsupportedStore) RotationByOldRef(context.Context, Ref) (RotationReceipt, error) {
	return RotationReceipt{}, ErrUnsupported
}

func (UnsupportedStore) RecoverRotation(context.Context, RotationID) (RotationReceipt, error) {
	return RotationReceipt{}, ErrUnsupported
}

func (UnsupportedStore) AcknowledgeRotation(context.Context, RotationID) error {
	return ErrUnsupported
}

var _ SecretStore = UnsupportedStore{}
