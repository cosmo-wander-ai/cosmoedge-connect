// Package profile persists ordinary-product device connection metadata. It
// deliberately stores only credential references; password bytes belong to a
// credential.SecretStore implementation.
package profile

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
)

const defaultDevicePort = 8000

var (
	ErrNotFound             = errors.New("device profile was not found")
	ErrConflict             = errors.New("device profile generation conflict")
	ErrInvalidProfile       = errors.New("device profile is invalid")
	ErrCredentialNotRevoked = errors.New("device credential must be revoked before forgetting the profile")
	ErrUnsupportedSchema    = errors.New("device profile schema is unsupported")
	ErrProtectedProjection  = errors.New("protected device profile cannot be serialized")
)

type State string

const (
	StateActive        State = "active"
	StateIdentityDrift State = "identity_drift"
	StateDisabled      State = "disabled"
	StateForgotten     State = "forgotten"
)

type CredentialState string

const (
	CredentialReady       CredentialState = "ready"
	CredentialRotating    CredentialState = "rotating"
	CredentialInvalid     CredentialState = "invalid"
	CredentialUnavailable CredentialState = "unavailable"
	CredentialRevoking    CredentialState = "revoking"
	CredentialRevoked     CredentialState = "revoked"
)

// DeviceProfile is protected local configuration. Endpoint, username, and the
// pinned serial are never suitable for Skill, CLI, log, or public projections.
type DeviceProfile struct {
	ProfileID            string
	TenantID             string
	SiteID               string
	Alias                string
	Endpoint             string
	Username             string
	CredentialRef        credential.Ref
	PinnedSerial         string
	PinnedType           string
	TransportFingerprint string
	Generation           uint64
	State                State
	CredentialState      CredentialState
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// MarshalJSON fails closed because DeviceProfile is protected configuration,
// not a wire shape. Use BusinessSummary for an explicitly redacted projection.
func (DeviceProfile) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedProjection
}

func (DeviceProfile) MarshalText() ([]byte, error) {
	return nil, ErrProtectedProjection
}

func (DeviceProfile) String() string   { return "[protected-device-profile]" }
func (DeviceProfile) GoString() string { return "profile.DeviceProfile([redacted])" }

func (DeviceProfile) LogValue() slog.Value {
	return slog.StringValue("[protected-device-profile]")
}

type NewDeviceProfile struct {
	ProfileID            string
	TenantID             string
	SiteID               string
	Alias                string
	Endpoint             string
	Username             string
	CredentialRef        credential.Ref
	PinnedSerial         string
	PinnedType           string
	TransportFingerprint string
	State                State
	CredentialState      CredentialState
}

// NewDeviceProfile is protected input because it contains connection and
// credential-capability material. Generic diagnostics must not project it.
func (NewDeviceProfile) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (NewDeviceProfile) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
func (NewDeviceProfile) String() string               { return "[protected-new-device-profile]" }
func (NewDeviceProfile) GoString() string {
	return "profile.NewDeviceProfile([redacted])"
}
func (NewDeviceProfile) LogValue() slog.Value {
	return slog.StringValue("[protected-new-device-profile]")
}

// UpdateDeviceProfile is a complete replacement protected by
// ExpectedGeneration. Store.Update increments the generation exactly once.
type UpdateDeviceProfile struct {
	ProfileID            string
	ExpectedGeneration   uint64
	TenantID             string
	SiteID               string
	Alias                string
	Endpoint             string
	Username             string
	CredentialRef        credential.Ref
	PinnedSerial         string
	PinnedType           string
	TransportFingerprint string
	State                State
	CredentialState      CredentialState
}

// UpdateDeviceProfile is a protected complete replacement, not a wire shape.
func (UpdateDeviceProfile) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (UpdateDeviceProfile) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
func (UpdateDeviceProfile) String() string               { return "[protected-update-device-profile]" }
func (UpdateDeviceProfile) GoString() string {
	return "profile.UpdateDeviceProfile([redacted])"
}
func (UpdateDeviceProfile) LogValue() slog.Value {
	return slog.StringValue("[protected-update-device-profile]")
}

type Event struct {
	Sequence        int64
	ProfileID       string
	TenantID        string
	SiteID          string
	EventType       string
	Generation      uint64
	State           State
	CredentialState CredentialState
	OccurredAt      time.Time
}

// Event is protected audit metadata. Business callers should consume an
// explicit projection rather than tenant/site identifiers from the ledger.
func (Event) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (Event) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
func (Event) String() string               { return "[protected-device-profile-event]" }
func (Event) GoString() string             { return "profile.Event([redacted])" }
func (Event) LogValue() slog.Value {
	return slog.StringValue("[protected-device-profile-event]")
}

var (
	profileIDPattern = regexp.MustCompile(`^dpf_[0-9a-f]{32}$`)
	siteIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func NewProfileID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "dpf_" + hex.EncodeToString(buffer), nil
}

// NormalizeEndpoint keeps the existing ordinary-product admission rule: a
// literal private/site-local IP with an explicit normalized HTTP(S) port.
func NormalizeEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("device endpoint is required")
	}
	if ip := net.ParseIP(raw); ip != nil {
		raw = (&url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(defaultDevicePort))}).String()
	} else if !strings.Contains(raw, "://") {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || net.ParseIP(host) == nil {
			return "", errors.New("device endpoint must use a literal IP")
		}
		raw = (&url.URL{Scheme: "http", Host: net.JoinHostPort(net.ParseIP(host).String(), port)}).String()
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("device endpoint scheme must be http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Trim(parsed.EscapedPath(), "/") != "" {
		return "", errors.New("device endpoint contains unsupported components")
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || !privateSiteLocal(ip) {
		return "", errors.New("device endpoint must be private or site-local")
	}
	port := defaultDevicePort
	if text := parsed.Port(); text != "" {
		port, err = strconv.Atoi(text)
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("device endpoint port is invalid")
		}
	} else if parsed.Scheme == "https" {
		port = 443
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: net.JoinHostPort(ip.String(), strconv.Itoa(port))}).String(), nil
}

func ComputeTransportFingerprint(endpoint, username string) (string, error) {
	normalized, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	username = strings.TrimSpace(username)
	if err := validateText("username", username, 256); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(normalized + "\x00" + username))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (p DeviceProfile) Validate() error {
	if !profileIDPattern.MatchString(p.ProfileID) || !siteIDPattern.MatchString(p.TenantID) || !siteIDPattern.MatchString(p.SiteID) {
		return ErrInvalidProfile
	}
	if err := validateText("alias", p.Alias, 128); err != nil {
		return errors.Join(ErrInvalidProfile, err)
	}
	normalized, err := NormalizeEndpoint(p.Endpoint)
	if err != nil || normalized != p.Endpoint {
		return errors.Join(ErrInvalidProfile, errors.New("endpoint is not normalized"))
	}
	if err := validateText("username", p.Username, 256); err != nil {
		return errors.Join(ErrInvalidProfile, err)
	}
	if !p.CredentialRef.Valid() {
		return errors.Join(ErrInvalidProfile, credential.ErrInvalidRef)
	}
	if err := validateText("pinned serial", p.PinnedSerial, 256); err != nil {
		return errors.Join(ErrInvalidProfile, err)
	}
	if err := validateText("pinned type", p.PinnedType, 256); err != nil {
		return errors.Join(ErrInvalidProfile, err)
	}
	fingerprint, err := ComputeTransportFingerprint(p.Endpoint, p.Username)
	if err != nil || !digestPattern.MatchString(p.TransportFingerprint) || p.TransportFingerprint != fingerprint {
		return errors.Join(ErrInvalidProfile, errors.New("transport fingerprint does not match endpoint and username"))
	}
	if p.Generation == 0 || !validState(p.State) || !validCredentialState(p.CredentialState) {
		return ErrInvalidProfile
	}
	if (p.CredentialState == CredentialRevoking || p.CredentialState == CredentialRevoked) && p.State != StateDisabled {
		return errors.Join(ErrInvalidProfile, errors.New("revoking or revoked credentials require a disabled profile"))
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() || p.UpdatedAt.Before(p.CreatedAt) {
		return ErrInvalidProfile
	}
	return nil
}

func validateText(field, value string, maximum int) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maximum || !utf8.ValidString(value) {
		return errors.New(field + " is invalid")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New(field + " contains a control character")
		}
	}
	return nil
}

func validState(value State) bool {
	return value == StateActive || value == StateIdentityDrift || value == StateDisabled
}

func validCredentialState(value CredentialState) bool {
	switch value {
	case CredentialReady, CredentialRotating, CredentialInvalid, CredentialUnavailable, CredentialRevoking, CredentialRevoked:
		return true
	default:
		return false
	}
}

func privateSiteLocal(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	ip = ip.To16()
	return ip != nil && ip[0]&0xfe == 0xfc
}
