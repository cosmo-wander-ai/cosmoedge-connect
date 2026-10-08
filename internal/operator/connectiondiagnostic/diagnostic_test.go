package connectiondiagnostic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type unprintableError struct{}

func (unprintableError) Error() string { panic("a protected error must never be formatted") }

type deviceFailure struct {
	unprintableError
	throttled, rejected, known bool
}

func (e deviceFailure) LoginThrottled() bool         { return e.throttled }
func (e deviceFailure) AuthenticationRejected() bool { return e.rejected }
func (e deviceFailure) KnownFailure() bool           { return e.known }

func TestFailureDoesNotFormatOrProjectProtectedErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want Outcome
	}{
		{unprintableError{}, Unavailable},
		{&url.Error{Op: "POST", URL: "https://private:secret@device/?token=private-token", Err: unprintableError{}}, TransportError},
		{deviceFailure{throttled: true, rejected: true}, Throttled},
		{deviceFailure{rejected: true}, Rejected},
		{deviceFailure{known: true}, DeviceRejected},
		{io.ErrUnexpectedEOF, ResponseInvalid},
		{&json.UnmarshalTypeError{Value: "private-secret", Type: nil}, ResponseInvalid},
		{context.Canceled, Canceled},
		{context.DeadlineExceeded, DeadlineExceeded},
	} {
		if got := Failure(context.Background(), test.err); got != test.want {
			t.Fatalf("failure class=%d want=%d", got, test.want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if Failure(ctx, errors.New("unclassified private error")) != Canceled {
		t.Fatal("parent cancellation lost to device error")
	}
}

func TestDiagnosticHasOnlyClosedLabelsAndElapsedTime(t *testing.T) {
	var output bytes.Buffer
	ctx := WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&output, nil)))
	Record(ctx, Login, Failure(ctx, &url.Error{URL: "http://private/secret", Err: unprintableError{}}), time.Now().Add(-20*time.Millisecond))
	Record(ctx, Stage(255), Outcome(255), time.Now().Add(time.Hour))
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("diagnostic count=%d", len(lines))
	}
	for i, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if len(event) != 6 || event["msg"] != "connection_restore" || event["level"] != "INFO" || event["time"] == nil {
			t.Fatal("unexpected diagnostic schema")
		}
		if i == 0 && (event["stage"] != "login" || event["class"] != "transport_error" || event["elapsed_ms"].(float64) < 20) {
			t.Fatal("typed failure or elapsed time was lost")
		}
		if i == 1 && (event["stage"] != "unknown" || event["class"] != "unknown" || event["elapsed_ms"] != float64(0)) {
			t.Fatal("unknown labels or negative duration were not normalized")
		}
	}
	if strings.Contains(output.String(), "private") || strings.Contains(output.String(), "secret") {
		t.Fatal("protected error escaped into diagnostic")
	}
}

func TestTransportCauseUnwrapsTypedErrnoWithoutProtectedText(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{syscall.EINVAL, "EINVAL"}, {syscall.ECONNREFUSED, "ECONNREFUSED"},
		{syscall.EACCES, "EACCES"}, {syscall.EPERM, "EPERM"},
		{syscall.EHOSTUNREACH, "EHOSTUNREACH"}, {syscall.ENETUNREACH, "ENETUNREACH"},
		{syscall.EADDRNOTAVAIL, "EADDRNOTAVAIL"}, {syscall.ECONNRESET, "ECONNRESET"},
		{syscall.EPIPE, "EPIPE"}, {syscall.ETIMEDOUT, "ETIMEDOUT"},
		{syscall.EMFILE, "EMFILE"}, {syscall.ENFILE, "ENFILE"}, {syscall.ENOENT, "other_errno"},
		{&net.DNSError{Name: "private-secret", Err: "private-secret"}, "dns_failure"},
		{net.InvalidAddrError("private-secret"), "invalid_address"},
		{net.ErrClosed, "connection_closed"}, {io.ErrUnexpectedEOF, "connection_eof"},
		{unprintableError{}, "unknown"},
	} {
		wrapped := &url.Error{Op: "private-operation", URL: "http://private-user:private-secret@private-host/",
			Err: &net.OpError{Op: "private-dial", Net: "private-net",
				Addr: &net.TCPAddr{IP: net.ParseIP("10.20.30.40"), Port: 8000},
				Err:  &os.SyscallError{Syscall: "private-syscall", Err: test.err}}}
		var output bytes.Buffer
		ctx := WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&output, nil)))
		RecordFailure(ctx, Login, wrapped, time.Now())
		var event map[string]any
		if err := json.Unmarshal(output.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if len(event) != 7 || event["stage"] != "login" || event["class"] != "transport_error" || event["transport_cause"] != test.want {
			t.Fatalf("closed transport cause=%v want=%s", event, test.want)
		}
		for _, protected := range []string{"private", "10.20.30.40"} {
			if strings.Contains(output.String(), protected) {
				t.Fatal("transport diagnostic leaked a protected error field")
			}
		}
	}
}

func TestCanceledContextStillTakesPrecedenceOverTransportErrno(t *testing.T) {
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&output, nil))))
	cancel()
	RecordFailure(ctx, Login, &url.Error{Err: syscall.EINVAL}, time.Now())
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event["class"] != "canceled" || event["transport_cause"] != nil {
		t.Fatal("transport cause hid a canceled startup context")
	}
}
