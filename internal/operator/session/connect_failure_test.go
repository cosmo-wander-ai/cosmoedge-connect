package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestConnectClassifiesFailureStageWithoutProjectingProtectedDetail(t *testing.T) {
	t.Parallel()
	const (
		rawEndpoint = "10.20.30.77"
		rawUsername = "private-operator"
		rawPassword = "private-device-password"
	)
	tests := []struct {
		name       string
		loginErr   error
		readErr    error
		commitErr  error
		want       error
		wantReads  int
		wantCommit int
	}{
		{
			name: "credentials rejected",
			loginErr: stagedLoginFailure{
				raw: "v1 rejected private-operator at 10.20.30.77", rejected: true,
			},
			want: ErrConnectionLoginRejected,
		},
		{
			name: "login throttled takes precedence over rejection",
			loginErr: stagedLoginFailure{
				raw: "v1 10009 login private-device-password", rejected: true, throttled: true,
			},
			want: ErrConnectionLoginThrottled,
		},
		{
			name:     "login unreachable",
			loginErr: errors.New("dial tcp 10.20.30.77:8000 with private-operator failed"),
			want:     ErrConnectionLoginUnavailable,
		},
		{
			name:      "post-login device read",
			readErr:   errors.New("raw v1 device-info response exposed private-operator"),
			want:      ErrConnectionReadUnavailable,
			wantReads: 1,
		},
		{
			name:       "durable save",
			commitErr:  errors.New("keychain write included private-device-password"),
			want:       ErrConnectionPersistenceFailure,
			wantReads:  1,
			wantCommit: 1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &stagedConnectionClient{
				loginErr: test.loginErr,
				readErr:  test.readErr,
				snapshot: testSnapshot("SN-STAGED-001"),
			}
			persistence := &stagedConnectionPersistence{commitErr: test.commitErr}
			vault := New(func(endpoint, username, password string) device.Client {
				if endpoint != "http://10.20.30.77:8000" || username != rawUsername || password != rawPassword {
					t.Fatalf("factory received changed connection input")
				}
				return client
			})
			if _, err := vault.BindConnectionPersistence(persistence); err != nil {
				t.Fatal(err)
			}
			browser := newBrowser(t, vault)
			preview, err := vault.PrepareConnection(browser.SessionID, rawEndpoint, rawUsername)
			if err != nil {
				t.Fatal(err)
			}
			password := []byte(rawPassword)
			_, got := vault.Connect(context.Background(), browser.SessionID, preview.Token, password)
			if !errors.Is(got, test.want) || got == nil || got.Error() != test.want.Error() {
				t.Fatalf("Connect() error=%T %v, want exact safe category %v", got, got, test.want)
			}
			if !allZeroBytes(password) {
				t.Fatal("failed connection retained caller password bytes")
			}
			if client.reads != test.wantReads || persistence.commits != test.wantCommit {
				t.Fatalf("stages reads=%d commits=%d, want %d/%d", client.reads, persistence.commits, test.wantReads, test.wantCommit)
			}
			projection := fmt.Sprintf("%v %+v %#v", got, got, got)
			for _, forbidden := range []string{
				rawEndpoint, rawUsername, rawPassword, "10009", "v1", "keychain", "dial tcp",
			} {
				if strings.Contains(projection, forbidden) {
					t.Fatalf("classified error leaked protected/raw detail %q", forbidden)
				}
			}
			if _, _, connected := vault.ConnectedIdentity(); connected {
				t.Fatal("failed stage published a live connection")
			}
		})
	}
}

type stagedLoginFailure struct {
	raw       string
	rejected  bool
	throttled bool
}

func (e stagedLoginFailure) Error() string                { return e.raw }
func (e stagedLoginFailure) AuthenticationRejected() bool { return e.rejected }
func (e stagedLoginFailure) LoginThrottled() bool         { return e.throttled }

type stagedConnectionClient struct {
	loginErr error
	readErr  error
	snapshot device.Snapshot
	reads    int
}

func (c *stagedConnectionClient) Login(context.Context) error { return c.loginErr }
func (c *stagedConnectionClient) Read(context.Context) (device.Snapshot, error) {
	c.reads++
	return c.snapshot, c.readErr
}
func (*stagedConnectionClient) ObserveEvents(context.Context, []device.Task, device.EventWindow) device.EventObservation {
	return device.EventObservation{ByTask: map[string]device.TaskEventObservation{}}
}

type stagedConnectionPersistence struct {
	commitErr error
	commits   int
}

func (p *stagedConnectionPersistence) CommitVerified(context.Context, VerifiedConnection, []byte) error {
	p.commits++
	return p.commitErr
}
func (*stagedConnectionPersistence) LoadCurrent(context.Context) (RestoreCandidate, error) {
	return RestoreCandidate{}, ErrNoSavedConnection
}
func (*stagedConnectionPersistence) MarkIdentityDrift(context.Context, PersistentBinding) error {
	return nil
}
func (*stagedConnectionPersistence) MarkCredentialUnavailable(context.Context, PersistentBinding) error {
	return nil
}
