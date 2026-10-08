package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestPersistentConnectCommitsBeforePublishingLiveConnection(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{snapshots: []device.Snapshot{testSnapshot("SN-PERSIST-001")}}
	vault := New(func(_, _, password string) device.Client {
		if password != "device-secret" {
			t.Fatalf("factory password mismatch")
		}
		return fake
	})
	persistence := &fakeConnectionPersistence{}
	persistence.commit = func(_ context.Context, verified VerifiedConnection, secret []byte) error {
		if _, _, connected := vault.ConnectedIdentity(); connected {
			t.Fatal("Vault published connection before durable commit")
		}
		persistence.verified = verified
		persistence.committedSecret = append([]byte(nil), secret...)
		return nil
	}
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	browser := newBrowser(t, vault)
	preview, err := vault.PrepareConnection(browser.SessionID, "10.20.30.40", "admin")
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("device-secret")
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, password); err != nil {
		t.Fatal(err)
	}
	if !allZeroBytes(password) {
		t.Fatal("caller password was not cleared")
	}
	if string(persistence.committedSecret) != "device-secret" || persistence.verified.PinnedSerial != "SN-PERSIST-001" ||
		persistence.verified.Endpoint != "http://10.20.30.40:8000" || !persistence.verified.valid() {
		t.Fatal("registry did not receive the exact verified connection")
	}
	if _, _, connected := vault.ConnectedIdentity(); !connected {
		t.Fatal("Vault did not publish connection after durable commit")
	}
}

func TestPersistentConnectFailureNeverPublishesLiveConnection(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{snapshots: []device.Snapshot{testSnapshot("SN-PERSIST-002")}}
	vault := New(func(_, _, _ string) device.Client { return fake })
	persistence := &fakeConnectionPersistence{commitErr: errors.New("durable commit failed")}
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	browser := newBrowser(t, vault)
	preview, _ := vault.PrepareConnection(browser.SessionID, "10.20.30.41", "admin")
	password := []byte("device-secret")
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, password); err == nil {
		t.Fatal("durable commit failure was accepted")
	}
	if !allZeroBytes(password) {
		t.Fatal("failed commit password was not cleared")
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("failed durable commit published a live connection")
	}
}

func TestPersistenceLeaseDisconnectsOldGenerationAndRejectsStaleRelease(t *testing.T) {
	t.Parallel()
	fake := &fakeClient{snapshots: []device.Snapshot{testSnapshot("SN-LEASE-001")}}
	vault := New(func(_, _, _ string) device.Client { return fake })
	first := &fakeConnectionPersistence{}
	firstLease, err := vault.BindConnectionPersistence(first)
	if err != nil {
		t.Fatal(err)
	}
	browser := newBrowser(t, vault)
	preview, _ := vault.PrepareConnection(browser.SessionID, "10.20.30.42", "admin")
	if _, err := vault.Connect(context.Background(), browser.SessionID, preview.Token, []byte("device-secret")); err != nil {
		t.Fatal(err)
	}
	if err := firstLease.Release(); err != nil {
		t.Fatal(err)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("released Product generation left live connection admitted")
	}
	secondLease, err := vault.BindConnectionPersistence(&fakeConnectionPersistence{})
	if err != nil {
		t.Fatal(err)
	}
	if err := firstLease.Release(); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation release error=%v", err)
	}
	if err := secondLease.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreAuthenticatesAndRechecksExactPersistentIdentity(t *testing.T) {
	t.Parallel()
	binding := testPersistentBinding("SN-RESTORE-001", "edge")
	candidate, err := NewRestoreCandidate(binding, []byte("saved-secret"))
	if err != nil {
		t.Fatal(err)
	}
	persistence := &fakeConnectionPersistence{candidate: candidate}
	vault := New(func(endpoint, username, password string) device.Client {
		if endpoint != binding.Endpoint || username != binding.Username || password != "saved-secret" {
			t.Fatal("restore factory received a changed protected binding")
		}
		return &fakeClient{snapshots: []device.Snapshot{testSnapshot(binding.PinnedSerial)}}
	})
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	result, err := vault.Restore(context.Background())
	if err != nil || result.State != RestoreConnected {
		t.Fatalf("Restore()=(%#v, %v)", result, err)
	}
	if _, _, connected := vault.ConnectedIdentity(); !connected {
		t.Fatal("verified restore did not publish live connection")
	}
	if !allZeroBytes(persistence.candidate.secret) {
		t.Fatal("restore candidate secret copy was not cleared")
	}
}

func TestRestoreWrongSecretMarksCredentialUnavailableAndStaysDisconnected(t *testing.T) {
	t.Parallel()
	binding := testPersistentBinding("SN-RESTORE-002", "edge")
	candidate, _ := NewRestoreCandidate(binding, []byte("wrong-secret"))
	persistence := &fakeConnectionPersistence{candidate: candidate}
	vault := New(func(_, _, _ string) device.Client {
		return &loginFailClient{err: stagedLoginFailure{
			raw: "authentication rejected", rejected: true,
		}}
	})
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	result, err := vault.Restore(context.Background())
	if err != nil || result.State != RestoreNeedsAttention {
		t.Fatalf("Restore()=(%#v, %v)", result, err)
	}
	if persistence.credentialMarks != 1 || persistence.identityMarks != 0 {
		t.Fatalf("marks credential=%d identity=%d", persistence.credentialMarks, persistence.identityMarks)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("wrong saved secret published a live connection")
	}
	if vault.CanRetrySavedConnection() {
		t.Fatal("rejected saved credential was offered for retry")
	}
}

func TestRestoreTransientLoginFailuresPreserveCredentialForRetry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		loginErr error
	}{
		{
			name: "throttled even when device also labels rejection",
			loginErr: stagedLoginFailure{
				raw: "rate limited", rejected: true, throttled: true,
			},
		},
		{name: "device unreachable", loginErr: errors.New("device unreachable")},
		{name: "transport timeout", loginErr: context.DeadlineExceeded},
		{name: "rejection text without typed evidence", loginErr: errors.New("authentication rejected")},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding := testPersistentBinding("SN-RESTORE-TRANSIENT", "edge")
			candidate, err := NewRestoreCandidate(binding, []byte("saved-secret"))
			if err != nil {
				t.Fatal(err)
			}
			persistence := &fakeConnectionPersistence{candidate: candidate}
			vault := New(func(_, _, _ string) device.Client {
				return &loginFailClient{err: test.loginErr}
			})
			if _, err := vault.BindConnectionPersistence(persistence); err != nil {
				t.Fatal(err)
			}

			result, err := vault.Restore(context.Background())
			if err != nil || result.State != RestoreNeedsAttention {
				t.Fatalf("Restore()=(%#v, %v)", result, err)
			}
			if persistence.credentialMarks != 0 || persistence.identityMarks != 0 {
				t.Fatalf("transient login failure changed durable profile: credential=%d identity=%d",
					persistence.credentialMarks, persistence.identityMarks)
			}
			if _, _, connected := vault.ConnectedIdentity(); connected {
				t.Fatal("transient login failure published a live connection")
			}
			if !vault.CanRetrySavedConnection() {
				t.Fatal("transient login failure hid the saved connection retry")
			}
			if !allZeroBytes(persistence.candidate.secret) {
				t.Fatal("transient restore retained candidate secret bytes")
			}
		})
	}
}

func TestRestoreCancelledLoginPreservesCredentialAndReturnsContextError(t *testing.T) {
	t.Parallel()
	binding := testPersistentBinding("SN-RESTORE-CANCELLED", "edge")
	candidate, err := NewRestoreCandidate(binding, []byte("saved-secret"))
	if err != nil {
		t.Fatal(err)
	}
	persistence := &fakeConnectionPersistence{candidate: candidate}
	ctx, cancel := context.WithCancel(context.Background())
	vault := New(func(_, _, _ string) device.Client {
		return &cancelingLoginClient{cancel: cancel}
	})
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}

	result, err := vault.Restore(ctx)
	if !errors.Is(err, context.Canceled) || result.State != "" {
		t.Fatalf("Restore()=(%#v, %v), want context cancellation", result, err)
	}
	if persistence.credentialMarks != 0 || persistence.identityMarks != 0 {
		t.Fatalf("cancelled login changed durable profile: credential=%d identity=%d",
			persistence.credentialMarks, persistence.identityMarks)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("cancelled login published a live connection")
	}
}

func TestRestoreIdentityDriftMarksProfileAndStaysDisconnected(t *testing.T) {
	t.Parallel()
	binding := testPersistentBinding("SN-RESTORE-003", "edge")
	candidate, _ := NewRestoreCandidate(binding, []byte("saved-secret"))
	persistence := &fakeConnectionPersistence{candidate: candidate}
	vault := New(func(_, _, _ string) device.Client {
		return &fakeClient{snapshots: []device.Snapshot{testSnapshot("SN-DIFFERENT-999")}}
	})
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	result, err := vault.Restore(context.Background())
	if err != nil || result.State != RestoreNeedsAttention {
		t.Fatalf("Restore()=(%#v, %v)", result, err)
	}
	if persistence.identityMarks != 1 || persistence.credentialMarks != 0 {
		t.Fatalf("marks identity=%d credential=%d", persistence.identityMarks, persistence.credentialMarks)
	}
	if _, _, connected := vault.ConnectedIdentity(); connected {
		t.Fatal("identity drift published a live connection")
	}
}

func TestProtectedPersistenceTypesDoNotLeakThroughJSONFormattingOrLogs(t *testing.T) {
	t.Parallel()
	binding := testPersistentBinding("PRIVATE-SERIAL-RESTORE", "private-device-type")
	candidate, err := NewRestoreCandidate(binding, []byte("private-device-secret"))
	if err != nil {
		t.Fatal(err)
	}
	verified := VerifiedConnection{
		Endpoint: binding.Endpoint, Username: binding.Username, PinnedSerial: binding.PinnedSerial,
		PinnedType: binding.PinnedType, TransportFingerprint: binding.TransportFingerprint,
	}
	for _, value := range []any{binding, candidate, verified} {
		if _, err := json.Marshal(value); !errors.Is(err, credential.ErrProtectedProjection) {
			t.Fatalf("Marshal(%T) error=%v", value, err)
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("protected", slog.Any("value", value))
		projection := fmt.Sprintf("%v %+v %#v %s", value, value, value, output.String())
		for _, forbidden := range []string{binding.Endpoint, binding.Username, binding.PinnedSerial, binding.PinnedType, "private-device-secret"} {
			if strings.Contains(projection, forbidden) {
				t.Fatalf("%T leaked %q", value, forbidden)
			}
		}
	}
	clearRestoreCandidate(&candidate)
}

func testPersistentBinding(serial, deviceType string) PersistentBinding {
	endpoint, _ := NormalizeDeviceAddress("10.20.30.50")
	return PersistentBinding{
		ProfileID: "dpf_0123456789abcdef0123456789abcdef", Generation: 1,
		Endpoint: endpoint.URL, Username: "private-admin", PinnedSerial: serial, PinnedType: deviceType,
		TransportFingerprint: endpointFingerprint(endpoint, "private-admin"),
	}
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

type fakeConnectionPersistence struct {
	mu sync.Mutex

	commit          func(context.Context, VerifiedConnection, []byte) error
	commitErr       error
	loadErr         error
	candidate       RestoreCandidate
	verified        VerifiedConnection
	committedSecret []byte
	identityMarks   int
	credentialMarks int
}

func (p *fakeConnectionPersistence) CommitVerified(ctx context.Context, verified VerifiedConnection, secret []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commit != nil {
		return p.commit(ctx, verified, secret)
	}
	p.verified = verified
	p.committedSecret = append([]byte(nil), secret...)
	return p.commitErr
}

func (p *fakeConnectionPersistence) LoadCurrent(context.Context) (RestoreCandidate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.candidate, p.loadErr
}

func (p *fakeConnectionPersistence) MarkIdentityDrift(_ context.Context, binding PersistentBinding) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if binding.ProfileID == "" {
		return errors.New("missing binding")
	}
	p.identityMarks++
	return nil
}

func (p *fakeConnectionPersistence) MarkCredentialUnavailable(_ context.Context, binding PersistentBinding) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if binding.ProfileID == "" {
		return errors.New("missing binding")
	}
	p.credentialMarks++
	return nil
}

type loginFailClient struct{ err error }

func (c *loginFailClient) Login(context.Context) error { return c.err }
func (*loginFailClient) Read(context.Context) (device.Snapshot, error) {
	return device.Snapshot{}, errors.New("read should not be called")
}
func (*loginFailClient) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{ByTask: map[string]device.TaskEventObservation{}}
}

type cancelingLoginClient struct{ cancel context.CancelFunc }

func (c *cancelingLoginClient) Login(ctx context.Context) error {
	c.cancel()
	return ctx.Err()
}
func (*cancelingLoginClient) Read(context.Context) (device.Snapshot, error) {
	return device.Snapshot{}, errors.New("read should not be called")
}
func (*cancelingLoginClient) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{ByTask: map[string]device.TaskEventObservation{}}
}
