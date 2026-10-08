package onboarding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const (
	onboardingProfileDomain    = "cosmoedge.onboarding.profile.v2\x00"
	onboardingLocalEntryDomain = "cosmoedge.onboarding.local.handoff.v2\x00"
)

// SkillHandoffRequest is intentionally incapable of carrying a device
// endpoint, username, credential, pinned identity, or device-native ID.
type SkillHandoffRequest struct {
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
	HandoffRef      string
	ExpiresAt       time.Time
}

type skillHandoffRequestDTO struct {
	TenantID        string    `json:"tenantId"`
	SiteID          string    `json:"siteId"`
	PrincipalSHA256 string    `json:"principalSha256"`
	HandoffRef      string    `json:"handoffRef"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

func (r *SkillHandoffRequest) UnmarshalJSON(raw []byte) error {
	var dto skillHandoffRequestDTO
	if err := strictjson.ValidateExactFields(raw, &dto, 2); err != nil {
		return errors.Join(ErrInvalidHandoff, err)
	}
	if err := json.Unmarshal(raw, &dto); err != nil {
		return errors.Join(ErrInvalidHandoff, err)
	}
	*r = SkillHandoffRequest{
		TenantID: dto.TenantID, SiteID: dto.SiteID, PrincipalSHA256: dto.PrincipalSHA256,
		HandoffRef: dto.HandoffRef, ExpiresAt: dto.ExpiresAt,
	}
	return nil
}

func (SkillHandoffRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (SkillHandoffRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (SkillHandoffRequest) String() string { return "[onboarding-skill-handoff-request]" }
func (SkillHandoffRequest) GoString() string {
	return "onboarding.SkillHandoffRequest([redacted])"
}
func (SkillHandoffRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-skill-handoff-request]")
}

// SkillHandoff is the only projection returned to a channel. Internal
// operation identity and authenticated scope remain in protected local state.
type SkillHandoff struct {
	HandoffRef string    `json:"handoffRef"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// PersistedConnectionVerifier proves that the single Product-owned current
// connection profile is durably usable. It carries no profile, credential, or
// device identity into the handoff service.
type PersistedConnectionVerifier interface {
	VerifyCurrent(context.Context) error
}

type LocalConnectionInput struct {
	Alias        string
	IP           string
	Port         uint16
	Username     string
	Password     []byte
	PinnedSerial string
	PinnedType   string
}

func (LocalConnectionInput) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (LocalConnectionInput) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (LocalConnectionInput) String() string   { return "[onboarding-local-connection]" }
func (LocalConnectionInput) GoString() string { return "onboarding.LocalConnectionInput([redacted])" }
func (LocalConnectionInput) LogValue() slog.Value {
	return slog.StringValue("[onboarding-local-connection]")
}

// CompleteSkillRequest is accepted only by the local completion surface. Its
// Grant must authorize ConnectionProfileWrite/profile_create for the exact
// tenant, site, and principal bound to the handoff.
type CompleteSkillRequest struct {
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
	HandoffRef      string
	Connection      LocalConnectionInput
	Grant           authority.Grant
}

func (CompleteSkillRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (CompleteSkillRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (CompleteSkillRequest) String() string   { return "[onboarding-complete-skill-request]" }
func (CompleteSkillRequest) GoString() string { return "onboarding.CompleteSkillRequest([redacted])" }
func (CompleteSkillRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-complete-skill-request]")
}

// DirectConnectRequest is the local-page-only entry. RequestRef and ExpiresAt
// are the caller's stable idempotency boundary; connection material is never
// copied into the handoff store.
type DirectConnectRequest struct {
	TenantID        string
	SiteID          string
	PrincipalSHA256 string
	RequestRef      string
	ExpiresAt       time.Time
	Connection      LocalConnectionInput
	Grant           authority.Grant
}

func (DirectConnectRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (DirectConnectRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (DirectConnectRequest) String() string   { return "[onboarding-direct-connect-request]" }
func (DirectConnectRequest) GoString() string { return "onboarding.DirectConnectRequest([redacted])" }
func (DirectConnectRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-direct-connect-request]")
}

type EntryServiceConfig struct {
	Core     *Service
	Handoffs HandoffRepository
}

// EntryService converges Skill-initiated and local-direct onboarding onto the
// same handoff repository and the existing onboarding Service.
type EntryService struct {
	core        *Service
	handoffs    HandoffRepository
	completions OperationCompletionReader
	now         func() time.Time
}

func NewEntryService(config EntryServiceConfig) (*EntryService, error) {
	if config.Core == nil || config.Handoffs == nil {
		return nil, errors.Join(ErrInvalidInput, errors.New("onboarding entry dependencies are required"))
	}
	return &EntryService{core: config.Core, handoffs: config.Handoffs, completions: config.Core, now: config.Core.now}, nil
}

func (s *EntryService) BeginSkill(ctx context.Context, request SkillHandoffRequest) (SkillHandoff, error) {
	if strings.HasPrefix(strings.TrimSpace(request.HandoffRef), "local_") {
		return SkillHandoff{}, ErrInvalidHandoff
	}
	binding := canonicalHandoffBinding(HandoffBinding{
		TenantID: request.TenantID, SiteID: request.SiteID, PrincipalSHA256: request.PrincipalSHA256,
	})
	record, err := s.begin(ctx, binding, request.HandoffRef, request.ExpiresAt)
	if err != nil {
		return SkillHandoff{}, err
	}
	return SkillHandoff{HandoffRef: record.HandoffRef, ExpiresAt: record.ExpiresAt}, nil
}

// HandoffReconcileRequest is local maintenance input. AfterRef is an exclusive
// keyset cursor returned by the previous successful page.
type HandoffReconcileRequest struct {
	AfterRef string
	Limit    int
}

func (HandoffReconcileRequest) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (HandoffReconcileRequest) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (HandoffReconcileRequest) String() string { return "[onboarding-handoff-reconcile-request]" }
func (HandoffReconcileRequest) GoString() string {
	return "onboarding.HandoffReconcileRequest([redacted])"
}
func (HandoffReconcileRequest) LogValue() slog.Value {
	return slog.StringValue("[onboarding-handoff-reconcile-request]")
}

// HandoffReconcileResult returns only bounded progress and the next protected
// cursor. It never returns a handoff record or core completion evidence.
type HandoffReconcileResult struct {
	Examined           int
	ConfirmedCompleted int
	NextAfterRef       string
}

func (HandoffReconcileResult) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (HandoffReconcileResult) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (HandoffReconcileResult) String() string { return "[onboarding-handoff-reconcile-result]" }
func (HandoffReconcileResult) GoString() string {
	return "onboarding.HandoffReconcileResult([redacted])"
}
func (HandoffReconcileResult) LogValue() slog.Value {
	return slog.StringValue("[onboarding-handoff-reconcile-result]")
}

// ReconcileCompletedHandoffs closes only the post-commit handoff gap. It reads
// pending handoffs (including expired ones), checks the stable OperationID
// against the core's authoritative completed state, and performs the existing
// CAS completion mark. It never resumes onboarding, accepts connection input,
// verifies or issues a grant, reads credentials, or performs a device action.
// A caller advances with NextAfterRef until an empty page, then starts the next
// sweep with an empty cursor so previously incomplete operations are revisited.
func (s *EntryService) ReconcileCompletedHandoffs(ctx context.Context, request HandoffReconcileRequest) (HandoffReconcileResult, error) {
	result := HandoffReconcileResult{}
	afterRef := strings.TrimSpace(request.AfterRef)
	if s == nil || s.handoffs == nil || s.completions == nil ||
		(afterRef != "" && !handoffRefPattern.MatchString(afterRef)) ||
		request.Limit <= 0 || request.Limit > MaximumHandoffRecoveryBatch {
		return result, ErrInvalidHandoff
	}
	records, err := s.handoffs.PendingForRecovery(ctx, afterRef, request.Limit)
	if err != nil {
		return result, err
	}
	if len(records) > request.Limit {
		return result, ErrHandoffIntegrity
	}
	previousRef := afterRef
	for _, record := range records {
		if err := validateResolvedHandoff(record); err != nil || record.State != HandoffPending || record.HandoffRef <= previousRef {
			return result, errors.Join(ErrHandoffIntegrity, err)
		}
		previousRef = record.HandoffRef
		completion, err := s.completions.InspectOperationCompletion(ctx, record.OperationID)
		if err != nil {
			return result, err
		}
		if err := completion.validate(); err != nil || completion.OperationID != record.OperationID {
			return result, errors.Join(ErrHandoffIntegrity, err)
		}
		if completion.Found {
			if completion.TenantID != record.TenantID || completion.SiteID != record.SiteID ||
				completion.PrincipalSHA256 != record.PrincipalSHA256 {
				return result, ErrBindingMismatch
			}
			if completion.Completed {
				marked, err := s.handoffs.MarkCompleted(ctx, record)
				if err != nil {
					return result, errors.Join(ErrHandoffCommit, err)
				}
				if err := validateResolvedHandoff(marked); err != nil || marked.State != HandoffCompleted || !sameHandoffIntent(marked, record) {
					return result, errors.Join(ErrHandoffIntegrity, err)
				}
				// MarkCompleted is idempotent, so this counts authoritative completed
				// confirmations rather than physical SQLite rows changed.
				result.ConfirmedCompleted++
			}
		}
		result.Examined++
		result.NextAfterRef = record.HandoffRef
	}
	return result, nil
}

func (s *EntryService) CompleteSkill(ctx context.Context, request CompleteSkillRequest) (Result, error) {
	defer clearBytes(request.Connection.Password)
	binding := canonicalHandoffBinding(HandoffBinding{
		TenantID: request.TenantID, SiteID: request.SiteID, PrincipalSHA256: request.PrincipalSHA256,
	})
	record, err := s.handoffs.Resolve(ctx, binding, strings.TrimSpace(request.HandoffRef))
	if err != nil {
		return Result{}, err
	}
	if err := validateResolvedHandoff(record); err != nil {
		return Result{}, err
	}
	return s.complete(ctx, record, request.Connection, request.Grant)
}

// AcknowledgeSkillPersisted closes an exact Skill handoff after the shared
// connection registry has durably committed and re-verified the one current
// profile. It intentionally does not create another handoff-derived profile or
// accept connection material, credentials, grants, or device identity.
func (s *EntryService) AcknowledgeSkillPersisted(ctx context.Context, request SkillHandoffRequest, verifier PersistedConnectionVerifier) (SkillHandoff, error) {
	if s == nil || s.handoffs == nil || verifier == nil {
		return SkillHandoff{}, ErrInvalidHandoff
	}
	binding := canonicalHandoffBinding(HandoffBinding{
		TenantID: request.TenantID, SiteID: request.SiteID, PrincipalSHA256: request.PrincipalSHA256,
	})
	record, err := s.handoffs.Resolve(ctx, binding, strings.TrimSpace(request.HandoffRef))
	if err != nil {
		return SkillHandoff{}, err
	}
	if err := validateResolvedHandoff(record); err != nil || !record.ExpiresAt.Equal(request.ExpiresAt.UTC()) {
		return SkillHandoff{}, errors.Join(ErrHandoffIntegrity, err)
	}
	if record.State == HandoffCompleted {
		return SkillHandoff{HandoffRef: record.HandoffRef, ExpiresAt: record.ExpiresAt}, nil
	}
	if record.State != HandoffPending {
		return SkillHandoff{}, ErrHandoffIntegrity
	}
	if err := verifier.VerifyCurrent(ctx); err != nil {
		return SkillHandoff{}, errors.Join(ErrHandoffCommit, err)
	}
	completed, err := s.handoffs.MarkCompleted(ctx, record)
	if err != nil {
		return SkillHandoff{}, errors.Join(ErrHandoffCommit, err)
	}
	if err := validateResolvedHandoff(completed); err != nil || completed.State != HandoffCompleted || !sameHandoffIntent(completed, record) {
		return SkillHandoff{}, errors.Join(ErrHandoffIntegrity, err)
	}
	return SkillHandoff{HandoffRef: completed.HandoffRef, ExpiresAt: completed.ExpiresAt}, nil
}

func (s *EntryService) ConnectLocal(ctx context.Context, request DirectConnectRequest) (Result, error) {
	defer clearBytes(request.Connection.Password)
	binding := canonicalHandoffBinding(HandoffBinding{
		TenantID: request.TenantID, SiteID: request.SiteID, PrincipalSHA256: request.PrincipalSHA256,
	})
	if !handoffRefPattern.MatchString(strings.TrimSpace(request.RequestRef)) {
		return Result{}, ErrInvalidInput
	}
	ref := stableDirectHandoffRef(binding, request.RequestRef)
	record, err := s.begin(ctx, binding, ref, request.ExpiresAt)
	if err != nil {
		return Result{}, err
	}
	return s.complete(ctx, record, request.Connection, request.Grant)
}

func (s *EntryService) begin(ctx context.Context, binding HandoffBinding, ref string, expiresAt time.Time) (HandoffRecord, error) {
	ref = strings.TrimSpace(ref)
	expiresAt = expiresAt.UTC()
	if !validHandoffBinding(binding) || !handoffRefPattern.MatchString(ref) || expiresAt.IsZero() || !expiresAt.After(s.now().UTC()) {
		return HandoffRecord{}, ErrInvalidHandoff
	}
	record := HandoffRecord{
		HandoffRef: ref, TenantID: binding.TenantID, SiteID: binding.SiteID, PrincipalSHA256: binding.PrincipalSHA256,
		OperationID: stableHandoffOperationID(binding, ref), ExpiresAt: expiresAt, State: HandoffPending,
	}
	stored, err := s.handoffs.Begin(ctx, record)
	if err != nil {
		return HandoffRecord{}, err
	}
	if !sameHandoffIntent(stored, record) {
		return HandoffRecord{}, ErrHandoffConflict
	}
	if err := validateResolvedHandoff(stored); err != nil {
		return HandoffRecord{}, err
	}
	return stored, nil
}

func (s *EntryService) complete(ctx context.Context, record HandoffRecord, connection LocalConnectionInput, grant authority.Grant) (Result, error) {
	endpoint, err := localEndpoint(connection.IP, connection.Port)
	if err != nil {
		return Result{}, err
	}
	access := Access{
		TenantID: record.TenantID, SiteID: record.SiteID, PrincipalSHA256: record.PrincipalSHA256, Grant: grant,
	}
	result, err := s.core.Create(ctx, CreateRequest{
		OperationID:  record.OperationID,
		Access:       access,
		ProfileID:    stableProfileID(record.OperationID),
		Alias:        connection.Alias,
		Endpoint:     endpoint,
		Username:     connection.Username,
		Secret:       connection.Password,
		PinnedSerial: connection.PinnedSerial,
		PinnedType:   connection.PinnedType,
	})
	if err != nil {
		return result, err
	}
	if result.Status != StatusCompleted || result.Phase != PhaseCompleted {
		return result, ErrOperationConflict
	}
	if _, markErr := s.handoffs.MarkCompleted(ctx, record); markErr != nil {
		return result, errors.Join(ErrHandoffCommit, markErr)
	}
	return result, nil
}

func localEndpoint(rawIP string, port uint16) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil || port == 0 {
		return "", ErrInvalidInput
	}
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))}).String(), nil
}

func stableProfileID(operationID string) string {
	sum := sha256.Sum256([]byte(onboardingProfileDomain + operationID))
	return "dpf_" + hex.EncodeToString(sum[:16])
}

func stableDirectHandoffRef(binding HandoffBinding, requestRef string) string {
	binding = canonicalHandoffBinding(binding)
	sum := sha256.Sum256([]byte(onboardingLocalEntryDomain + binding.TenantID + "\x00" +
		binding.SiteID + "\x00" + binding.PrincipalSHA256 + "\x00" + strings.TrimSpace(requestRef)))
	return "local_" + hex.EncodeToString(sum[:16])
}

func validateResolvedHandoff(record HandoffRecord) error {
	if err := record.validate(); err != nil {
		return errors.Join(ErrHandoffIntegrity, err)
	}
	if record.RecordSHA256 != handoffRecordDigest(record) {
		return ErrHandoffIntegrity
	}
	return nil
}
