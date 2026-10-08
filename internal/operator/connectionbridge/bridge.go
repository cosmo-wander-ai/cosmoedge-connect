// Package connectionbridge is the live-layer adapter between the ordinary
// session Vault and the clean Product-owned persistent connection registry.
// Keeping it outside inspectionproduct preserves the inspection dependency
// boundary while retaining one durable profile and credential owner.
package connectionbridge

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectiondiagnostic"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

type Lifecycle struct {
	mu       sync.Mutex
	vault    *session.Vault
	registry *connectionregistry.Registry
	lease    *session.PersistenceLease
}

func New(vault *session.Vault, registry *connectionregistry.Registry) (*Lifecycle, error) {
	if vault == nil || registry == nil {
		return nil, errors.New("connection lifecycle dependencies are required")
	}
	return &Lifecycle{vault: vault, registry: registry}, nil
}

func (l *Lifecycle) Start(ctx context.Context) (connectionregistry.RestoreState, error) {
	return l.start(ctx, 0)
}

// StartWithRestoreTimeout bounds startup device restoration while retaining
// the registered persistence owner when only that budget expires. A local
// connection flow can then repair/reconnect the saved profile. Parent context
// cancellation and all other restore errors still fail and release ownership.
func (l *Lifecycle) StartWithRestoreTimeout(ctx context.Context, limit time.Duration) (connectionregistry.RestoreState, error) {
	if limit <= 0 {
		return "", errors.New("connection restore timeout must be positive")
	}
	return l.start(ctx, limit)
}

var errRestoreBudget = errors.New("connection restore startup budget exhausted")

func (l *Lifecycle) start(ctx context.Context, limit time.Duration) (connectionregistry.RestoreState, error) {
	started, outcome := time.Now(), connectiondiagnostic.Unavailable
	defer func() { connectiondiagnostic.Record(ctx, connectiondiagnostic.Total, outcome, started) }()
	if l == nil || ctx == nil {
		outcome = connectiondiagnostic.InvalidState
		return "", errors.New("connection lifecycle is unavailable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lease != nil {
		outcome = connectiondiagnostic.Conflict
		return "", session.ErrConflict
	}
	lease, err := l.vault.BindConnectionPersistence(persistenceAdapter{registry: l.registry})
	if err != nil {
		if errors.Is(err, session.ErrConflict) {
			outcome = connectiondiagnostic.Conflict
		}
		return "", err
	}
	l.lease = &lease
	restoreCtx := ctx
	if limit > 0 {
		var cancel context.CancelFunc
		restoreCtx, cancel = context.WithTimeoutCause(ctx, limit, errRestoreBudget)
		defer cancel()
	}
	restored, err := l.vault.Restore(restoreCtx)
	if parentErr := ctx.Err(); parentErr != nil {
		outcome = connectiondiagnostic.Failure(ctx, parentErr)
		return "", errors.Join(parentErr, err, l.releaseLocked())
	}
	if err == context.DeadlineExceeded && context.Cause(restoreCtx) == errRestoreBudget {
		outcome = connectiondiagnostic.BudgetExpired
		return connectionregistry.RestoreNeedsAttention, nil
	}
	if err != nil {
		outcome = connectiondiagnostic.Failure(restoreCtx, err)
		releaseErr := l.releaseLocked()
		return "", errors.Join(err, releaseErr)
	}
	switch restored.State {
	case session.RestoreNotConfigured:
		outcome = connectiondiagnostic.NotConfigured
		return connectionregistry.RestoreNotConfigured, nil
	case session.RestoreConnected:
		outcome = connectiondiagnostic.OK
		return connectionregistry.RestoreConnected, nil
	case session.RestoreNeedsAttention:
		outcome = connectiondiagnostic.NeedsAttention
		return connectionregistry.RestoreNeedsAttention, nil
	default:
		outcome = connectiondiagnostic.InvalidState
		releaseErr := l.releaseLocked()
		return "", errors.Join(errors.New("connection restore returned an invalid state"), releaseErr)
	}
}

func (l *Lifecycle) Stop() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.releaseLocked()
}

func (l *Lifecycle) releaseLocked() error {
	if l.lease == nil {
		return nil
	}
	if err := l.lease.Release(); err != nil {
		return err
	}
	l.lease = nil
	return nil
}

type persistenceAdapter struct {
	registry *connectionregistry.Registry
}

func (a persistenceAdapter) PrepareConnection(ctx context.Context, endpoint, username string) (session.PreparedConnection, error) {
	plan, err := a.registry.PrepareConnection(ctx, endpoint, username)
	if err != nil {
		return nil, mapRegistryError(err)
	}
	return preparedConnection{registry: a.registry, plan: plan}, nil
}
func (a persistenceAdapter) ConnectionEpoch(ctx context.Context) (string, error) {
	return a.registry.ConnectionEpoch(ctx)
}

type preparedConnection struct {
	registry *connectionregistry.Registry
	plan     connectionregistry.ConnectionPlan
}

func (p preparedConnection) MarshalJSON() ([]byte, error) { return p.plan.MarshalJSON() }
func (p preparedConnection) MarshalText() ([]byte, error) { return p.plan.MarshalText() }
func (preparedConnection) String() string                 { return "[protected-prepared-connection]" }
func (preparedConnection) GoString() string               { return "connectionbridge.preparedConnection([redacted])" }
func (preparedConnection) LogValue() slog.Value {
	return slog.StringValue("[protected-prepared-connection]")
}

func (p preparedConnection) Validate(ctx context.Context) error {
	return p.registry.ValidatePlan(ctx, p.plan)
}

func (p preparedConnection) CurrentDestination() string {
	endpoint, err := session.NormalizeDeviceAddress(p.plan.CurrentEndpoint)
	if err != nil {
		return ""
	}
	return endpoint.Masked()
}
func (p preparedConnection) ReplacementRequired() bool  { return p.plan.ReplacementRequired }
func (p preparedConnection) ReplacementAvailable() bool { return p.plan.ReplacementAvailable }
func (p preparedConnection) Commit(ctx context.Context, value session.VerifiedConnection, secret []byte, confirmationID string, replace bool) error {
	return mapRegistryError(p.registry.CommitPrepared(ctx, p.plan, confirmationID, replace, connectionregistry.VerifiedConnection{Endpoint: value.Endpoint, Username: value.Username, PinnedSerial: value.PinnedSerial, PinnedType: value.PinnedType, TransportFingerprint: value.TransportFingerprint}, secret))
}

func (a persistenceAdapter) CommitVerified(ctx context.Context, verified session.VerifiedConnection, secret []byte) error {
	return mapRegistryError(a.registry.CommitVerified(ctx, connectionregistry.VerifiedConnection{
		Endpoint: verified.Endpoint, Username: verified.Username,
		PinnedSerial: verified.PinnedSerial, PinnedType: verified.PinnedType,
		TransportFingerprint: verified.TransportFingerprint,
	}, secret))
}

func (a persistenceAdapter) LoadCurrent(ctx context.Context) (session.RestoreCandidate, error) {
	candidate, err := a.registry.LoadCurrent(ctx)
	if err != nil {
		return session.RestoreCandidate{}, mapRegistryError(err)
	}
	var result session.RestoreCandidate
	err = candidate.Consume(func(binding connectionregistry.PersistentBinding, secret []byte) error {
		created, createErr := session.NewRestoreCandidate(session.PersistentBinding{
			ProfileID: binding.ProfileID, Generation: binding.Generation,
			Endpoint: binding.Endpoint, Username: binding.Username,
			PinnedSerial: binding.PinnedSerial, PinnedType: binding.PinnedType,
			TransportFingerprint: binding.TransportFingerprint,
		}, secret)
		if createErr == nil {
			result = created
		}
		return createErr
	})
	return result, mapRegistryError(err)
}

func (a persistenceAdapter) MarkIdentityDrift(ctx context.Context, binding session.PersistentBinding) error {
	return mapRegistryError(a.registry.MarkIdentityDrift(ctx, registryBinding(binding)))
}

func (a persistenceAdapter) MarkCredentialUnavailable(ctx context.Context, binding session.PersistentBinding) error {
	return mapRegistryError(a.registry.MarkCredentialUnavailable(ctx, registryBinding(binding)))
}

func registryBinding(binding session.PersistentBinding) connectionregistry.PersistentBinding {
	return connectionregistry.PersistentBinding{
		ProfileID: binding.ProfileID, Generation: binding.Generation,
		Endpoint: binding.Endpoint, Username: binding.Username,
		PinnedSerial: binding.PinnedSerial, PinnedType: binding.PinnedType,
		TransportFingerprint: binding.TransportFingerprint,
	}
}

func mapRegistryError(err error) error {
	switch {
	case errors.Is(err, connectionregistry.ErrNoSavedConnection):
		return errors.Join(session.ErrNoSavedConnection, err)
	case errors.Is(err, connectionregistry.ErrSavedConnectionAttention):
		return errors.Join(session.ErrSavedConnectionAttention, err)
	default:
		return err
	}
}

var _ session.ConnectionPersistence = persistenceAdapter{}
