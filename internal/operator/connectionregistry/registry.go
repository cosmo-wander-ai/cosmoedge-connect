// Package connectionregistry binds one ordinary persistent device profile to
// the live session Vault. The registry is constructed only by Inspection
// Product from its already-open profile, credential, and onboarding owners;
// it never opens a second store or exposes those stores to the page or Skill.
package connectionregistry

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectiondiagnostic"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

const rotationOperationDomain = "cosmoedge.connection-registry.credential-rotation.v1\x00"

var (
	ErrInvalidConfig            = errors.New("connection registry configuration is invalid")
	ErrBindingConflict          = errors.New("saved device connection conflicts with the verified device")
	ErrNoSavedConnection        = errors.New("saved device connection is not configured")
	ErrSavedConnectionAttention = errors.New("saved device connection needs local attention")

	profileIDPattern   = regexp.MustCompile(`^dpf_[0-9a-f]{32}$`)
	operationIDPattern = regexp.MustCompile(`^onb_[0-9a-f]{32}$`)
	localRefPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RestoreState string

const (
	RestoreNotConfigured  RestoreState = "not_configured"
	RestoreConnected      RestoreState = "connected"
	RestoreNeedsAttention RestoreState = "needs_attention"
)

// VerifiedConnection is the clean protected input produced by the live-layer
// session adapter after device authentication and a fresh identity read.
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
func (VerifiedConnection) String() string { return "[verified-device-connection]" }
func (VerifiedConnection) GoString() string {
	return "connectionregistry.VerifiedConnection([redacted])"
}
func (VerifiedConnection) LogValue() slog.Value {
	return slog.StringValue("[verified-device-connection]")
}

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
func (PersistentBinding) GoString() string             { return "connectionregistry.PersistentBinding([redacted])" }
func (PersistentBinding) LogValue() slog.Value {
	return slog.StringValue("[persistent-device-binding]")
}

type RestoreCandidate struct {
	binding PersistentBinding
	secret  []byte
}

func (RestoreCandidate) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (RestoreCandidate) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (RestoreCandidate) String() string               { return "[saved-device-connection]" }
func (RestoreCandidate) GoString() string             { return "connectionregistry.RestoreCandidate([redacted])" }
func (RestoreCandidate) LogValue() slog.Value         { return slog.StringValue("[saved-device-connection]") }

// Consume transfers a temporary secret copy to the live-layer adapter and
// clears both copies on return. Generic projection remains fail-closed.
func (c *RestoreCandidate) Consume(use func(PersistentBinding, []byte) error) error {
	if c == nil || use == nil || !validBinding(c.binding) || len(c.secret) == 0 {
		return ErrSavedConnectionAttention
	}
	secret := append([]byte(nil), c.secret...)
	clear(c.secret)
	c.secret = nil
	defer clear(secret)
	return use(c.binding, secret)
}

type ProfileStore interface {
	Get(context.Context, string, string, string) (profile.DeviceProfile, error)
	MarkIdentityDrift(context.Context, string, string, string, uint64) (profile.DeviceProfile, error)
	SetCredentialState(context.Context, string, string, string, uint64, profile.CredentialState) (profile.DeviceProfile, error)
}

type AuthorityIssuer interface {
	Issue(string, authority.Class, string, authority.Scope, time.Time, time.Time) (authority.Grant, error)
}

type Config struct {
	Current     *CurrentStore // Optional: legacy composition keeps its fixed profile.
	Profiles    ProfileStore
	Credentials credential.SecretStore
	Onboarding  *onboarding.Service
	Issuer      AuthorityIssuer

	TenantID          string
	SiteID            string
	PrincipalSHA256   string
	ProfileID         string
	CreateOperationID string
	Alias             string
	Now               func() time.Time
}

type Registry struct {
	current     *CurrentStore
	profiles    ProfileStore
	credentials credential.SecretStore
	onboarding  *onboarding.Service
	issuer      AuthorityIssuer

	tenantID          string
	siteID            string
	principalSHA256   string
	profileID         string
	createOperationID string
	alias             string
	now               func() time.Time
}

func New(config Config) (*Registry, error) {
	config.TenantID = strings.TrimSpace(config.TenantID)
	config.SiteID = strings.TrimSpace(config.SiteID)
	config.PrincipalSHA256 = strings.TrimSpace(config.PrincipalSHA256)
	config.ProfileID = strings.TrimSpace(config.ProfileID)
	config.CreateOperationID = strings.TrimSpace(config.CreateOperationID)
	config.Alias = strings.TrimSpace(config.Alias)
	if config.Now == nil {
		config.Now = time.Now
	}
	if isNil(config.Profiles) || isNil(config.Credentials) || config.Onboarding == nil || isNil(config.Issuer) ||
		!localRefPattern.MatchString(config.TenantID) || !localRefPattern.MatchString(config.SiteID) ||
		!digestPattern.MatchString(config.PrincipalSHA256) || !profileIDPattern.MatchString(config.ProfileID) ||
		!operationIDPattern.MatchString(config.CreateOperationID) || config.Alias == "" || len(config.Alias) > 128 {
		return nil, ErrInvalidConfig
	}
	return &Registry{
		current:  config.Current,
		profiles: config.Profiles, credentials: config.Credentials, onboarding: config.Onboarding, issuer: config.Issuer,
		tenantID: config.TenantID, siteID: config.SiteID, principalSHA256: config.PrincipalSHA256,
		profileID: config.ProfileID, createOperationID: config.CreateOperationID, alias: config.Alias, now: config.Now,
	}, nil
}

func (r *Registry) CommitVerified(ctx context.Context, verified VerifiedConnection, secret []byte) error {
	defer clear(secret)
	if r == nil || ctx == nil || ctx.Err() != nil || !r.validVerified(verified) || len(secret) == 0 {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrBindingConflict
	}
	current, err := r.currentProfile(ctx)
	if errors.Is(err, profile.ErrNotFound) {
		return r.create(ctx, verified, secret)
	}
	if err != nil {
		return err
	}
	if !r.matches(current, verified) || current.State != profile.StateActive {
		return ErrBindingConflict
	}

	stored, getErr := r.credentials.Get(ctx, current.CredentialRef)
	sameSecret := getErr == nil && len(stored) == len(secret) && subtle.ConstantTimeCompare(stored, secret) == 1
	clear(stored)
	if sameSecret && current.CredentialState == profile.CredentialReady {
		return nil
	}
	if getErr != nil && !errors.Is(getErr, credential.ErrNotFound) {
		return getErr
	}
	if errors.Is(getErr, credential.ErrNotFound) {
		if current.CredentialState == profile.CredentialReady {
			if _, markErr := r.profiles.SetCredentialState(ctx, r.tenantID, r.siteID, current.ProfileID, current.Generation, profile.CredentialUnavailable); markErr != nil {
				return markErr
			}
		}
		return ErrSavedConnectionAttention
	}
	return r.rotate(ctx, current, secret)
}

func (r *Registry) LoadCurrent(ctx context.Context) (RestoreCandidate, error) {
	started := time.Now()
	if r == nil || ctx == nil {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.Selection, connectiondiagnostic.InvalidState, started)
		return RestoreCandidate{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.Selection, connectiondiagnostic.Failure(ctx, err), started)
		return RestoreCandidate{}, err
	}
	current, err := r.currentProfile(ctx)
	if errors.Is(err, profile.ErrNotFound) {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.Selection, connectiondiagnostic.NotConfigured, started)
		return RestoreCandidate{}, ErrNoSavedConnection
	}
	if err != nil {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.Selection, connectiondiagnostic.Failure(ctx, err), started)
		return RestoreCandidate{}, err
	}
	if current.Validate() != nil || current.TenantID != r.tenantID || current.SiteID != r.siteID {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.Selection, connectiondiagnostic.InvalidState, started)
		return RestoreCandidate{}, ErrBindingConflict
	}
	if current.State != profile.StateActive || current.CredentialState != profile.CredentialReady {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.Selection, connectiondiagnostic.NeedsAttention, started)
		return RestoreCandidate{}, ErrSavedConnectionAttention
	}
	connectiondiagnostic.Record(ctx, connectiondiagnostic.Selection, connectiondiagnostic.OK, started)
	started = time.Now()
	secret, err := r.credentials.Get(ctx, current.CredentialRef)
	if err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			connectiondiagnostic.Record(ctx, connectiondiagnostic.CredentialRead, connectiondiagnostic.CredentialMissing, started)
			if _, markErr := r.profiles.SetCredentialState(ctx, r.tenantID, r.siteID, current.ProfileID, current.Generation, profile.CredentialUnavailable); markErr != nil {
				return RestoreCandidate{}, markErr
			}
			return RestoreCandidate{}, ErrSavedConnectionAttention
		}
		connectiondiagnostic.Record(ctx, connectiondiagnostic.CredentialRead, connectiondiagnostic.Failure(ctx, err), started)
		return RestoreCandidate{}, err
	}
	defer clear(secret)
	binding := bindingFor(current)
	if !validBinding(binding) || len(secret) == 0 {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.CredentialRead, connectiondiagnostic.InvalidState, started)
		return RestoreCandidate{}, ErrSavedConnectionAttention
	}
	connectiondiagnostic.Record(ctx, connectiondiagnostic.CredentialRead, connectiondiagnostic.OK, started)
	return RestoreCandidate{binding: binding, secret: append([]byte(nil), secret...)}, nil
}

// VerifyCurrent proves that the one Product-owned current device profile is
// still active and has an available encrypted credential. It intentionally
// returns no profile or secret material; local interaction completion uses it
// only as a fresh prerequisite before acknowledging an exact handoff.
func (r *Registry) VerifyCurrent(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := r.currentProfile(ctx)
	if err != nil {
		return err
	}
	if current.Validate() != nil || current.TenantID != r.tenantID ||
		current.SiteID != r.siteID || current.State != profile.StateActive ||
		current.CredentialState != profile.CredentialReady {
		return ErrBindingConflict
	}
	secret, err := r.credentials.Get(ctx, current.CredentialRef)
	if err != nil {
		return err
	}
	defer clear(secret)
	if len(secret) == 0 {
		return ErrSavedConnectionAttention
	}
	return nil
}

func (r *Registry) MarkIdentityDrift(ctx context.Context, binding PersistentBinding) error {
	current, err := r.exactCurrent(ctx, binding)
	if err != nil {
		return err
	}
	_, err = r.profiles.MarkIdentityDrift(ctx, r.tenantID, r.siteID, current.ProfileID, current.Generation)
	return err
}

func (r *Registry) MarkCredentialUnavailable(ctx context.Context, binding PersistentBinding) error {
	current, err := r.exactCurrent(ctx, binding)
	if err != nil {
		return err
	}
	if current.CredentialState == profile.CredentialUnavailable {
		return nil
	}
	_, err = r.profiles.SetCredentialState(ctx, r.tenantID, r.siteID, current.ProfileID, current.Generation, profile.CredentialUnavailable)
	return err
}

func (r *Registry) create(ctx context.Context, verified VerifiedConnection, secret []byte) error {
	selected, err := r.selection(ctx)
	if err != nil {
		return err
	}
	if selected.ProfileID != r.profileID {
		return ErrBindingConflict
	}
	access, err := r.access([]string{authority.OpProfileCreate}, "connection-registry-create", "")
	if err != nil {
		return err
	}
	result, err := r.onboarding.Create(ctx, onboarding.CreateRequest{
		OperationID: r.createOperationID, Access: access, ProfileID: r.profileID, Alias: r.alias,
		Endpoint: verified.Endpoint, Username: verified.Username, Secret: secret,
		PinnedSerial: verified.PinnedSerial, PinnedType: verified.PinnedType,
	})
	if err != nil {
		return err
	}
	if result.Status != onboarding.StatusCompleted || result.Phase != onboarding.PhaseCompleted || result.Summary == nil ||
		result.Summary.ProfileID != r.profileID || result.Summary.State != "ready" {
		return ErrBindingConflict
	}
	return nil
}

func (r *Registry) rotate(ctx context.Context, current profile.DeviceProfile, secret []byte) error {
	if current.CredentialState == profile.CredentialInvalid || current.CredentialState == profile.CredentialUnavailable {
		updated, err := r.profiles.SetCredentialState(ctx, r.tenantID, r.siteID, current.ProfileID, current.Generation, profile.CredentialReady)
		if err != nil {
			return err
		}
		current = updated
	}
	if current.CredentialState != profile.CredentialReady && current.CredentialState != profile.CredentialRotating {
		return ErrSavedConnectionAttention
	}
	operationID := rotationOperationID(current.ProfileID, current.CredentialRef)
	access, err := r.access([]string{authority.OpCredentialRotate, authority.OpProfileUpdate}, "connection-registry-rotate", current.ProfileID)
	if err != nil {
		return err
	}
	var result onboarding.Result
	if current.CredentialState == profile.CredentialRotating {
		result, err = r.onboarding.Resume(ctx, onboarding.ResumeRequest{OperationID: operationID, Access: access, Secret: secret})
	} else {
		result, err = r.onboarding.RotateCredential(ctx, onboarding.RotateCredentialRequest{
			OperationID: operationID, Access: access, ProfileID: current.ProfileID,
			ExpectedGeneration: current.Generation, Secret: secret,
		})
	}
	if err != nil {
		return err
	}
	if result.Status != onboarding.StatusCompleted || result.Phase != onboarding.PhaseCompleted || result.Summary == nil ||
		result.Summary.ProfileID != current.ProfileID || result.Summary.State != "ready" {
		return ErrBindingConflict
	}
	return nil
}

func (r *Registry) access(operations []string, grantID, profileID string) (onboarding.Access, error) {
	now := r.now().UTC()
	scope := authority.Scope{
		TenantID: r.tenantID, SiteID: r.siteID, DeviceProfileID: profileID,
		OperationKinds: operations,
	}
	grant, err := r.issuer.Issue(grantID, authority.ConnectionProfileWrite, r.principalSHA256, scope, now.Add(-time.Minute), now.Add(5*time.Minute))
	if err != nil {
		return onboarding.Access{}, err
	}
	return onboarding.Access{TenantID: r.tenantID, SiteID: r.siteID, PrincipalSHA256: r.principalSHA256, Grant: grant}, nil
}

func (r *Registry) exactCurrent(ctx context.Context, binding PersistentBinding) (profile.DeviceProfile, error) {
	if r == nil || ctx == nil {
		return profile.DeviceProfile{}, ErrBindingConflict
	}
	current, err := r.currentProfile(ctx)
	if err != nil {
		return profile.DeviceProfile{}, err
	}
	want := bindingFor(current)
	if binding != want {
		return profile.DeviceProfile{}, ErrBindingConflict
	}
	return current, nil
}

func (r *Registry) validVerified(value VerifiedConnection) bool {
	endpoint, err := profile.NormalizeEndpoint(value.Endpoint)
	if err != nil || endpoint != value.Endpoint || strings.TrimSpace(value.Username) == "" ||
		strings.TrimSpace(value.PinnedSerial) == "" || strings.TrimSpace(value.PinnedType) == "" {
		return false
	}
	fingerprint, err := profile.ComputeTransportFingerprint(endpoint, value.Username)
	return err == nil && fingerprint == "sha256:"+value.TransportFingerprint
}

func (r *Registry) matches(current profile.DeviceProfile, verified VerifiedConnection) bool {
	if current.Validate() != nil {
		return false
	}
	return current.TenantID == r.tenantID && current.SiteID == r.siteID &&
		current.Endpoint == verified.Endpoint && current.Username == strings.TrimSpace(verified.Username) &&
		current.PinnedSerial == strings.TrimSpace(verified.PinnedSerial) && current.PinnedType == strings.TrimSpace(verified.PinnedType) &&
		current.TransportFingerprint == "sha256:"+verified.TransportFingerprint
}

func bindingFor(current profile.DeviceProfile) PersistentBinding {
	return PersistentBinding{
		ProfileID: current.ProfileID, Generation: current.Generation, Endpoint: current.Endpoint, Username: current.Username,
		PinnedSerial: current.PinnedSerial, PinnedType: current.PinnedType,
		TransportFingerprint: strings.TrimPrefix(current.TransportFingerprint, "sha256:"),
	}
}

func validBinding(binding PersistentBinding) bool {
	if !profileIDPattern.MatchString(strings.TrimSpace(binding.ProfileID)) || binding.Generation == 0 {
		return false
	}
	endpoint, err := profile.NormalizeEndpoint(binding.Endpoint)
	if err != nil || endpoint != binding.Endpoint || strings.TrimSpace(binding.Username) == "" ||
		strings.TrimSpace(binding.PinnedSerial) == "" || strings.TrimSpace(binding.PinnedType) == "" {
		return false
	}
	fingerprint, err := profile.ComputeTransportFingerprint(endpoint, binding.Username)
	return err == nil && fingerprint == "sha256:"+binding.TransportFingerprint
}

func rotationOperationID(profileID string, ref credential.Ref) string {
	sum := sha256.Sum256([]byte(rotationOperationDomain + profileID + "\x00" + ref.ProtectedValue()))
	return "onb_" + hex.EncodeToString(sum[:16])
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
