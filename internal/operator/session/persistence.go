package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

var (
	// ErrNoSavedConnection is the ordinary first-run state. It is not a
	// connectivity failure and callers may open the local connection page.
	ErrNoSavedConnection = errors.New("saved device connection is not configured")
	// ErrSavedConnectionAttention means protected connection state exists but
	// cannot currently be admitted to the live Vault. The underlying endpoint,
	// account, credential reference, and device identity are never projected.
	ErrSavedConnectionAttention = errors.New("saved device connection needs local attention")
)

type RestoreState string

const (
	RestoreNotConfigured  RestoreState = "not_configured"
	RestoreConnected      RestoreState = "connected"
	RestoreNeedsAttention RestoreState = "needs_attention"
)

// RestoreResult is the only startup projection. It deliberately carries no
// protected connection material or failure cause.
type RestoreResult struct {
	State RestoreState
}

// CanRetrySavedConnection projects only whether a known saved binding can be
// retried. Rendering a page never loads credentials or contacts the device.
func (v *Vault) CanRetrySavedConnection() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.persistence != nil && v.connected == nil && !v.connecting && v.retrySavedConnection
}

// RetrySavedConnection is an explicit local-browser action against the saved
// identity. It accepts no replacement target or secret and performs one bounded
// login and identity check using the same Restore path as startup.
func (v *Vault) RetrySavedConnection(ctx context.Context, browserID string) (RestoreResult, error) {
	if _, err := v.Authenticate(browserID); err != nil {
		return RestoreResult{}, err
	}
	if !v.CanRetrySavedConnection() {
		return RestoreResult{}, ErrConflict
	}
	restoreCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := v.Restore(restoreCtx)
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return RestoreResult{State: RestoreNeedsAttention}, nil
	}
	return result, err
}

// VerifiedConnection is produced only after the Vault has authenticated to a
// device and completed a fresh identity read. It is protected local input to
// the Product-owned connection registry, never a business or log shape.
type VerifiedConnection struct {
	Endpoint             string
	Username             string
	PinnedSerial         string
	PinnedType           string
	TransportFingerprint string
}

func (VerifiedConnection) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (VerifiedConnection) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (VerifiedConnection) String() string   { return "[verified-device-connection]" }
func (VerifiedConnection) GoString() string { return "session.VerifiedConnection([redacted])" }
func (VerifiedConnection) LogValue() slog.Value {
	return slog.StringValue("[verified-device-connection]")
}

func (c VerifiedConnection) valid() bool {
	endpoint, err := NormalizeDeviceAddress(c.Endpoint)
	return err == nil && endpoint.URL == c.Endpoint && strings.TrimSpace(c.Username) != "" &&
		strings.TrimSpace(c.PinnedSerial) != "" && strings.TrimSpace(c.PinnedType) != "" &&
		c.TransportFingerprint == endpointFingerprint(endpoint, c.Username)
}

// PersistentBinding is protected profile state without secret bytes. It is
// used only for exact CAS status changes after a failed restore.
type PersistentBinding struct {
	ProfileID            string
	Generation           uint64
	Endpoint             string
	Username             string
	PinnedSerial         string
	PinnedType           string
	TransportFingerprint string
}

func (PersistentBinding) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (PersistentBinding) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (PersistentBinding) String() string               { return "[persistent-device-binding]" }
func (PersistentBinding) GoString() string             { return "session.PersistentBinding([redacted])" }
func (PersistentBinding) LogValue() slog.Value {
	return slog.StringValue("[persistent-device-binding]")
}

func (b PersistentBinding) valid() bool {
	return strings.TrimSpace(b.ProfileID) != "" && b.Generation > 0 && VerifiedConnection{
		Endpoint: b.Endpoint, Username: b.Username, PinnedSerial: b.PinnedSerial,
		PinnedType: b.PinnedType, TransportFingerprint: b.TransportFingerprint,
	}.valid()
}

// RestoreCandidate owns a copied secret until Vault.Restore returns. Generic
// formatting and serialization fail closed. NewRestoreCandidate is the only
// constructor so malformed persisted state cannot reach the device factory.
type RestoreCandidate struct {
	binding PersistentBinding
	secret  []byte
}

func NewRestoreCandidate(binding PersistentBinding, secret []byte) (RestoreCandidate, error) {
	if !binding.valid() || len(secret) == 0 {
		return RestoreCandidate{}, ErrSavedConnectionAttention
	}
	return RestoreCandidate{binding: binding, secret: append([]byte(nil), secret...)}, nil
}

func (RestoreCandidate) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (RestoreCandidate) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (RestoreCandidate) String() string               { return "[saved-device-connection]" }
func (RestoreCandidate) GoString() string             { return "session.RestoreCandidate([redacted])" }
func (RestoreCandidate) LogValue() slog.Value {
	return slog.StringValue("[saved-device-connection]")
}

// ConnectionPersistence is implemented by the one Product-owned registry.
// CommitVerified must make the profile and secret durable before returning;
// Vault will not publish the live connection until it succeeds. LoadCurrent
// returns an independent secret copy whose lifetime ends with Restore.
type ConnectionPersistence interface {
	CommitVerified(context.Context, VerifiedConnection, []byte) error
	LoadCurrent(context.Context) (RestoreCandidate, error)
	MarkIdentityDrift(context.Context, PersistentBinding) error
	MarkCredentialUnavailable(context.Context, PersistentBinding) error
}

// PreparedConnection is an opaque exact local-page confirmation. Implementors
// hold the frozen current selection and target; callers cannot replace either
// with request fields at commit time.
type PreparedConnection interface {
	Validate(context.Context) error
	CurrentDestination() string
	ReplacementRequired() bool
	ReplacementAvailable() bool
	Commit(context.Context, VerifiedConnection, []byte, string, bool) error
}
type ConnectionPreparer interface {
	PrepareConnection(context.Context, string, string) (PreparedConnection, error)
	ConnectionEpoch(context.Context) (string, error)
}

// PersistenceLease binds one Product generation to the Vault. Releasing the
// exact unforgeable lease disconnects the generation before its profile and
// credential resources are closed; a stale generation cannot detach a newer
// registry.
type PersistenceLease struct {
	vault      *Vault
	generation uint64
	seal       [32]byte
}

func (PersistenceLease) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (PersistenceLease) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (PersistenceLease) String() string               { return "[connection-persistence-lease]" }
func (PersistenceLease) GoString() string             { return "session.PersistenceLease([redacted])" }
func (PersistenceLease) LogValue() slog.Value {
	return slog.StringValue("[connection-persistence-lease]")
}

func (lease PersistenceLease) Release() error {
	if lease.vault == nil || lease.generation == 0 {
		return ErrConflict
	}
	vault := lease.vault
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.connecting || vault.persistenceGeneration != lease.generation ||
		subtle.ConstantTimeCompare(vault.persistenceSeal[:], lease.seal[:]) != 1 {
		return ErrConflict
	}
	vault.persistence = nil
	vault.persistenceSeal = [32]byte{}
	vault.connected = nil
	vault.retrySavedConnection = false
	return nil
}

func verifiedConnection(endpoint Endpoint, username string, identity device.Identity) VerifiedConnection {
	return VerifiedConnection{
		Endpoint: endpoint.URL, Username: strings.TrimSpace(username),
		PinnedSerial: strings.TrimSpace(identity.Serial), PinnedType: strings.TrimSpace(identity.Type),
		TransportFingerprint: endpointFingerprint(endpoint, username),
	}
}

func clearRestoreCandidate(candidate *RestoreCandidate) {
	if candidate == nil {
		return
	}
	clearBytes(candidate.secret)
	candidate.secret = nil
}
