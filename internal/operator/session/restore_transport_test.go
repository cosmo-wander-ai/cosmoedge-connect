package session

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectiondiagnostic"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestRestoreRetainsTypedTransportCauseWithoutRetryOrCredentialMutation(t *testing.T) {
	binding := testPersistentBinding("private-restore-serial", "private-device-type")
	candidate, err := NewRestoreCandidate(binding, []byte("private-saved-secret"))
	if err != nil {
		t.Fatal(err)
	}
	persistence := &fakeConnectionPersistence{candidate: candidate}
	factoryCalls := 0
	vault := New(func(endpoint, username, _ string) device.Client {
		factoryCalls++
		if endpoint != binding.Endpoint || username != binding.Username {
			t.Fatal("restore changed the saved factory endpoint or account binding")
		}
		return &loginFailClient{err: &url.Error{Op: "private-request", URL: "http://private-user:private-secret@private-device/",
			Err: &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.EINVAL}}}}
	})
	if _, err := vault.BindConnectionPersistence(persistence); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	ctx := connectiondiagnostic.WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&output, nil)))
	result, err := vault.Restore(ctx)
	if err != nil || result.State != RestoreNeedsAttention || factoryCalls != 1 || persistence.credentialMarks != 0 || persistence.identityMarks != 0 {
		t.Fatal("transport diagnostics changed restoration policy or durable credentials")
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event["stage"] != "login" || event["class"] != "transport_error" || event["transport_cause"] != "EINVAL" {
		t.Fatalf("restore lost the closed transport cause: %v", event)
	}
	if strings.Contains(output.String(), "private") || strings.Contains(output.String(), binding.Endpoint) {
		t.Fatal("restore projected protected input or original transport error")
	}
	if _, _, connected := vault.ConnectedIdentity(); connected || !allZeroBytes(persistence.candidate.secret) {
		t.Fatal("failed restore published connection authority or retained candidate secret")
	}
}
