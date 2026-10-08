// Package credential defines the ordinary Operator boundary for durable
// secrets. Device profiles may persist only the opaque Ref returned here; they
// must never persist the secret bytes themselves.
package credential

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
)

const maxSecretBytes = 4096

var (
	ErrInvalidSecret = errors.New("credential secret is invalid")
	ErrInvalidRef    = errors.New("credential reference is invalid")
	ErrNotFound      = errors.New("credential reference was not found")
	ErrUnsupported   = errors.New("durable credential storage is unsupported")
	// ErrProtectedProjection prevents opaque credential capabilities from being
	// serialized into a Skill, CLI, log, or other business projection by
	// accident. Trusted persistence must opt in with Ref.ProtectedValue().
	ErrProtectedProjection = errors.New("credential reference cannot be serialized")
)

// Ref is an opaque lookup capability. It contains no account, endpoint, or
// secret material and is safe to persist in the protected profile database.
type Ref string

var refPattern = regexp.MustCompile(`^cred_[0-9a-f]{64}$`)

func ParseRef(value string) (Ref, error) {
	ref := Ref(value)
	if !ref.Valid() {
		return "", ErrInvalidRef
	}
	return ref, nil
}

// String and GoString deliberately redact because a Ref is a bearer
// capability. Internal trusted persistence must use ProtectedValue explicitly.
func (r Ref) String() string   { return "[credential-ref]" }
func (r Ref) GoString() string { return "credential.Ref([redacted])" }

func (r Ref) LogValue() slog.Value { return slog.StringValue("[credential-ref]") }

// ProtectedValue exposes the opaque capability only for trusted local
// persistence and backend lookup. It must never be sent to a business channel.
func (r Ref) ProtectedValue() string { return string(r) }

func (r Ref) Valid() bool { return refPattern.MatchString(string(r)) }

// MarshalJSON fails closed. A Ref is an authorization capability, not a
// business identifier; trusted persistence must call ProtectedValue explicitly.
func (r Ref) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedProjection
}

func (r Ref) MarshalText() ([]byte, error) {
	return nil, ErrProtectedProjection
}

// SecretStore owns secret bytes behind opaque references. Put and Rotate copy
// their input; callers remain responsible for clearing their own buffers.
//
// Before Put, the caller must generate and durably save a PutOperationID in its
// business saga. Put records the operation/ref binding before installing the
// secret and retains a receipt until AcknowledgePut. RecoverPut reconciles an
// interrupted install; CompensatePut deletes an unattached secret. Ack is
// idempotent and removes only a committed or rolled-back receipt.
//
// Rotate similarly records old/new references before changing authority. A
// committed receipt means the old reference no longer resolves.
// RotationByOldRef lets a caller recover even if it crashed before saving the
// returned operation ID. RecoverRotation reconciles backend state, and Ack
// removes only a committed or rolled-back receipt after the business saga is
// safe. Delete is idempotent.
type SecretStore interface {
	Put(context.Context, PutOperationID, []byte) (PutReceipt, error)
	PutByOperationID(context.Context, PutOperationID) (PutReceipt, error)
	RecoverPut(context.Context, PutOperationID) (PutReceipt, error)
	CompensatePut(context.Context, PutOperationID) (PutReceipt, error)
	AcknowledgePut(context.Context, PutOperationID) error
	Get(context.Context, Ref) ([]byte, error)
	Delete(context.Context, Ref) error
	Rotate(context.Context, Ref, []byte) (RotationReceipt, error)
	RotationByOldRef(context.Context, Ref) (RotationReceipt, error)
	RecoverRotation(context.Context, RotationID) (RotationReceipt, error)
	AcknowledgeRotation(context.Context, RotationID) error
}

func validateSecret(secret []byte) error {
	if len(secret) == 0 || len(secret) > maxSecretBytes {
		return ErrInvalidSecret
	}
	return nil
}

func newRef() (Ref, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return Ref("cred_" + hex.EncodeToString(buffer)), nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
