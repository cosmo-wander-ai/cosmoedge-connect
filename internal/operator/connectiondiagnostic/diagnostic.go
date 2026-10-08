// Package connectiondiagnostic emits only closed startup phase/outcome labels
// and elapsed time. Protected inputs and original errors are never log fields.
package connectiondiagnostic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"syscall"
	"time"
)

type Stage uint8

const (
	Selection Stage = iota + 1
	CredentialRead
	Login
	DeviceRead
	Commit
	Total
)

func (s Stage) label() string {
	switch s {
	case Selection:
		return "selection"
	case CredentialRead:
		return "credential_read"
	case Login:
		return "login"
	case DeviceRead:
		return "device_read"
	case Commit:
		return "commit"
	case Total:
		return "total"
	default:
		return "unknown"
	}
}

type Outcome uint8

const (
	OK Outcome = iota + 1
	NotConfigured
	NeedsAttention
	CredentialMissing
	InvalidState
	IdentityMismatch
	Rejected
	Throttled
	TransportError
	ResponseInvalid
	DeviceRejected
	Unavailable
	Canceled
	DeadlineExceeded
	BudgetExpired
	Conflict
)

func (o Outcome) label() string {
	switch o {
	case OK:
		return "ok"
	case NotConfigured:
		return "not_configured"
	case NeedsAttention:
		return "needs_attention"
	case CredentialMissing:
		return "credential_missing"
	case InvalidState:
		return "invalid_state"
	case IdentityMismatch:
		return "identity_mismatch"
	case Rejected:
		return "authentication_rejected"
	case Throttled:
		return "login_throttled"
	case TransportError:
		return "transport_error"
	case ResponseInvalid:
		return "response_invalid"
	case DeviceRejected:
		return "device_rejected"
	case Unavailable:
		return "unavailable"
	case Canceled:
		return "canceled"
	case DeadlineExceeded:
		return "deadline_exceeded"
	case BudgetExpired:
		return "budget_expired"
	case Conflict:
		return "conflict"
	default:
		return "unknown"
	}
}

type loggerKey struct{}

// WithLogger permits a caller-owned structured sink without global mutation.
// Production startup defaults to slog's service stderr logger.
func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

func Record(ctx context.Context, stage Stage, outcome Outcome, started time.Time) {
	record(ctx, stage, outcome, started)
}

// RecordFailure preserves a closed transport cause before a caller discards
// the protected error. No error text, syscall arguments or peer address escape.
func RecordFailure(ctx context.Context, stage Stage, err error, started time.Time) {
	outcome := Failure(ctx, err)
	if outcome == TransportError {
		record(ctx, stage, outcome, started, slog.String("transport_cause", transportCause(err)))
		return
	}
	Record(ctx, stage, outcome, started)
}

func transportCause(err error) string {
	var number syscall.Errno
	if errors.As(err, &number) {
		switch number {
		case syscall.EINVAL:
			return "EINVAL"
		case syscall.ECONNREFUSED:
			return "ECONNREFUSED"
		case syscall.EACCES:
			return "EACCES"
		case syscall.EPERM:
			return "EPERM"
		case syscall.EHOSTUNREACH:
			return "EHOSTUNREACH"
		case syscall.ENETUNREACH:
			return "ENETUNREACH"
		case syscall.EADDRNOTAVAIL:
			return "EADDRNOTAVAIL"
		case syscall.ECONNRESET:
			return "ECONNRESET"
		case syscall.EPIPE:
			return "EPIPE"
		case syscall.ETIMEDOUT:
			return "ETIMEDOUT"
		case syscall.EMFILE:
			return "EMFILE"
		case syscall.ENFILE:
			return "ENFILE"
		default:
			return "other_errno"
		}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_failure"
	}
	var address net.InvalidAddrError
	if errors.As(err, &address) {
		return "invalid_address"
	}
	if errors.Is(err, net.ErrClosed) {
		return "connection_closed"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "connection_eof"
	}
	return "unknown"
}

func record(ctx context.Context, stage Stage, outcome Outcome, started time.Time, details ...slog.Attr) {
	logger := slog.Default()
	if ctx != nil {
		if configured, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && configured != nil {
			logger = configured
		}
	}
	elapsed := time.Since(started).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	// Deliberately do not attach context values, error objects, or arbitrary
	// strings. Even unknown enum values produce only fixed labels.
	attributes := []slog.Attr{
		slog.String("stage", stage.label()), slog.String("class", outcome.label()),
		slog.Int64("elapsed_ms", elapsed)}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "connection_restore", append(attributes, details...)...)
}

// Failure classifies by typed markers only. It never formats an error, parses
// its text, or emits a device-provided status/message/URL.
func Failure(ctx context.Context, err error) Outcome {
	if ctx != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return DeadlineExceeded
	}
	var throttled interface{ LoginThrottled() bool }
	if errors.As(err, &throttled) && throttled.LoginThrottled() {
		return Throttled
	}
	var rejected interface{ AuthenticationRejected() bool }
	if errors.As(err, &rejected) && rejected.AuthenticationRejected() {
		return Rejected
	}
	var transport net.Error
	if errors.As(err, &transport) {
		return TransportError
	}
	var syntax *json.SyntaxError
	var shape *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &shape) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ResponseInvalid
	}
	var business interface{ KnownFailure() bool }
	if errors.As(err, &business) && business.KnownFailure() {
		return DeviceRejected
	}
	return Unavailable
}
