package devauthority

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const maximumReadLeaseDuration = 10 * time.Minute

type ReadLeaseInfo struct {
	Device     string    `json:"device"`
	DeviceType string    `json:"deviceType"`
	OpenedAt   time.Time `json:"openedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// ReadLease is a development-only, read-only view of one authenticated device
// session. It intentionally exposes neither credentials nor ActionConnection.
type ReadLease struct {
	mu        sync.Mutex
	authority *Authority
	profile   Profile
	vault     *session.Vault
	openedAt  time.Time
	expiresAt time.Time
	closed    bool
}

func (a *Authority) OpenReadLease(ctx context.Context, requested time.Duration) (*ReadLease, device.Snapshot, ReadLeaseInfo, error) {
	if requested <= 0 || requested > maximumReadLeaseDuration {
		requested = maximumReadLeaseDuration
	}
	profile, vault, snapshot, _, err := a.open(ctx, ActionRead)
	if err != nil {
		return nil, device.Snapshot{}, ReadLeaseInfo{}, err
	}
	now := a.now().UTC()
	expiresAt := now.Add(requested)
	if profile.ExpiresAt.Before(expiresAt) {
		expiresAt = profile.ExpiresAt
	}
	lease := &ReadLease{
		authority: a, profile: profile, vault: vault,
		openedAt: now, expiresAt: expiresAt,
	}
	return lease, snapshot, ReadLeaseInfo{
		Device: profile.DeviceHint, DeviceType: profile.DeviceType,
		OpenedAt: now, ExpiresAt: expiresAt,
	}, nil
}

func (l *ReadLease) Read(ctx context.Context) (device.Snapshot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.readLocked(ctx)
}

func (l *ReadLease) ObserveTaskEvents(ctx context.Context, target device.Task, window device.EventWindow) (device.Snapshot, device.TaskEventObservation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	snapshot, err := l.readLocked(ctx)
	if err != nil {
		return device.Snapshot{}, device.TaskEventObservation{}, err
	}
	fresh, ok := leaseTask(snapshot, target)
	if !ok {
		return snapshot, device.TaskEventObservation{}, errors.New("development read lease rejected task binding drift")
	}
	observation, err := l.vault.ObserveEvents(ctx, []device.Task{fresh}, window)
	if err != nil {
		return snapshot, device.TaskEventObservation{}, err
	}
	result, ok := observation.ByTask[fresh.ID]
	if !ok {
		return snapshot, device.TaskEventObservation{}, errors.New("development read lease event observation is unavailable")
	}
	return snapshot, result, nil
}

func (l *ReadLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.vault = nil
	return nil
}

func (l *ReadLease) readLocked(ctx context.Context) (device.Snapshot, error) {
	if l == nil || l.closed || l.vault == nil || l.authority == nil {
		return device.Snapshot{}, errors.New("development read lease is closed")
	}
	now := l.authority.now().UTC()
	if !now.Before(l.expiresAt) {
		return device.Snapshot{}, errors.New("development read lease has expired")
	}
	current, err := l.authority.store.Load(now)
	if err != nil {
		return device.Snapshot{}, err
	}
	if !current.Allows(ActionRead) || current.DeviceFingerprint != l.profile.DeviceFingerprint || current.DeviceType != l.profile.DeviceType || current.Endpoint != l.profile.Endpoint || current.Username != l.profile.Username {
		return device.Snapshot{}, errors.New("development read lease authority changed")
	}
	snapshot, err := l.vault.Read(ctx)
	if err != nil {
		return device.Snapshot{}, err
	}
	if deviceFingerprint(snapshot.Identity.Serial) != l.profile.DeviceFingerprint || snapshot.Identity.Type != l.profile.DeviceType {
		return device.Snapshot{}, errors.New("development read lease rejected device identity drift")
	}
	return snapshot, nil
}

func leaseTask(snapshot device.Snapshot, target device.Task) (device.Task, bool) {
	for _, candidate := range snapshot.Tasks {
		if candidate.ID == target.ID && candidate.ChannelID == target.ChannelID && candidate.AlgorithmID == target.AlgorithmID {
			return candidate, true
		}
	}
	return device.Task{}, false
}
