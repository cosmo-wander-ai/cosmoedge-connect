package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestSavedConnectionRetryUsesStoredIdentityAndBrowserSession(t *testing.T) {
	binding := testPersistentBinding("saved-retry-device", "edge")
	persistence := &retryConnectionPersistence{binding: binding}
	calls := 0
	vault := New(func(endpoint, username, password string) device.Client {
		calls++
		if endpoint != binding.Endpoint || username != binding.Username || password != "saved-retry-secret" {
			t.Fatal("retry changed the stored connection inputs")
		}
		if calls == 1 {
			return &loginFailClient{err: errors.New("temporarily unreachable")}
		}
		return &fakeClient{snapshots: []device.Snapshot{testSnapshot(binding.PinnedSerial)}}
	})
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Restore(context.Background()); err != nil || !vault.CanRetrySavedConnection() || calls != 1 {
		t.Fatal("failed startup did not retain an explicit retry")
	}
	if _, err := vault.RetrySavedConnection(context.Background(), "invalid-browser"); !errors.Is(err, ErrUnauthorized) || calls != 1 {
		t.Fatal("unauthenticated retry reached the device")
	}
	browser := newBrowser(t, vault)
	result, err := vault.RetrySavedConnection(context.Background(), browser.SessionID)
	if err != nil || result.State != RestoreConnected || calls != 2 || vault.CanRetrySavedConnection() {
		t.Fatalf("saved retry state=%s error=%v calls=%d", result.State, err, calls)
	}
	if _, err := vault.RetrySavedConnection(context.Background(), browser.SessionID); !errors.Is(err, ErrConflict) || calls != 2 {
		t.Fatal("already connected retry started another login")
	}
	if persistence.credentialMarks != 0 || persistence.identityMarks != 0 || len(persistence.committedSecret) != 0 {
		t.Fatal("retry changed the saved profile or credential")
	}
}

func TestSavedConnectionRetryUnavailableWithoutUsableSavedBinding(t *testing.T) {
	for _, loadErr := range []error{ErrNoSavedConnection, ErrSavedConnectionAttention} {
		t.Run(loadErr.Error(), func(t *testing.T) {
			vault := New(func(_, _, _ string) device.Client {
				t.Fatal("unavailable saved binding reached the device")
				return nil
			})
			if vault.CanRetrySavedConnection() {
				t.Fatal("first-run Vault offered saved retry")
			}
			persistence := &fakeConnectionPersistence{loadErr: loadErr}
			if _, err := vault.BindConnectionPersistence(persistence); err != nil {
				t.Fatal(err)
			}
			if _, err := vault.Restore(context.Background()); err != nil {
				t.Fatal(err)
			}
			if vault.CanRetrySavedConnection() {
				t.Fatal("unavailable saved binding offered retry")
			}
			browser := newBrowser(t, vault)
			if _, err := vault.RetrySavedConnection(context.Background(), browser.SessionID); !errors.Is(err, ErrConflict) {
				t.Fatalf("unavailable retry error=%v", err)
			}
		})
	}
}

func TestSavedConnectionRetryIsBoundedAndExclusive(t *testing.T) {
	persistence := &retryConnectionPersistence{binding: testPersistentBinding("saved-retry-device", "edge")}
	started := make(chan time.Time, 1)
	calls := 0
	vault := New(func(_, _, _ string) device.Client {
		calls++
		if calls == 1 {
			return &loginFailClient{err: errors.New("temporarily unreachable")}
		}
		return &boundedRetryClient{started: started}
	})
	lease, err := vault.BindConnectionPersistence(persistence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	browser := newBrowser(t, vault)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := vault.RetrySavedConnection(ctx, browser.SessionID)
		done <- err
	}()
	deadline := <-started
	if remaining := time.Until(deadline); remaining <= 0 || remaining > 10*time.Second {
		t.Fatal("local retry did not carry the bounded restore deadline")
	}
	if vault.CanRetrySavedConnection() {
		t.Fatal("in-flight retry remained available")
	}
	if _, err := vault.RetrySavedConnection(context.Background(), browser.SessionID); !errors.Is(err, ErrConflict) {
		t.Fatal("concurrent retry was admitted")
	}
	if err := lease.Release(); !errors.Is(err, ErrConflict) {
		t.Fatal("in-flight retry lost its persistence owner")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || calls != 2 || !vault.CanRetrySavedConnection() {
		t.Fatalf("cancelled retry error=%v calls=%d", err, calls)
	}
	if err := lease.Release(); err != nil || vault.CanRetrySavedConnection() {
		t.Fatal("released persistence retained saved retry availability")
	}
}

func TestSavedConnectionRetryRechecksIdentity(t *testing.T) {
	persistence := &retryConnectionPersistence{binding: testPersistentBinding("saved-retry-device", "edge")}
	calls := 0
	vault := New(func(_, _, _ string) device.Client {
		calls++
		if calls == 1 {
			return &loginFailClient{err: errors.New("temporarily unreachable")}
		}
		return &fakeClient{snapshots: []device.Snapshot{testSnapshot("different-device")}}
	})
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	browser := newBrowser(t, vault)
	result, err := vault.RetrySavedConnection(context.Background(), browser.SessionID)
	if err != nil || result.State != RestoreNeedsAttention || vault.CanRetrySavedConnection() || persistence.identityMarks != 1 {
		t.Fatal("identity drift remained retryable")
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("retry admitted a different device")
	}
}

type retryConnectionPersistence struct {
	fakeConnectionPersistence
	binding PersistentBinding
}

func (p *retryConnectionPersistence) LoadCurrent(context.Context) (RestoreCandidate, error) {
	return NewRestoreCandidate(p.binding, []byte("saved-retry-secret"))
}

type boundedRetryClient struct {
	loginFailClient
	started chan<- time.Time
}

func (c *boundedRetryClient) Login(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	c.started <- deadline
	<-ctx.Done()
	return ctx.Err()
}
