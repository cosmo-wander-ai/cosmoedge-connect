package inspectioninteraction

import (
	"context"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
)

type OnboardingEntry interface {
	BeginSkill(context.Context, onboarding.SkillHandoffRequest) (onboarding.SkillHandoff, error)
}

type RegistrarConfig struct {
	Onboarding OnboardingEntry
	Changes    RegistrationStore
	Now        func() time.Time
}

// Registrar routes connection handoffs to the existing onboarding EntryService
// and persistent changes to a registration-only store capability. It has no
// transfer, authority issuer, grant, Action Kernel, confirmation, or device
// dependency.
type Registrar struct {
	onboarding OnboardingEntry
	changes    RegistrationStore
	now        func() time.Time
}

func NewRegistrar(config RegistrarConfig) (*Registrar, error) {
	if config.Onboarding == nil || config.Changes == nil {
		return nil, ErrInvalidRegistration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Registrar{onboarding: config.Onboarding, changes: config.Changes, now: config.Now}, nil
}

func (r *Registrar) Register(ctx context.Context, request planning.LocalInteractionRegistration) (planning.LocalInteractionReceipt, error) {
	if r == nil || r.onboarding == nil || r.changes == nil || r.now == nil {
		return planning.LocalInteractionReceipt{}, ErrInvalidRegistration
	}
	request = canonicalRegistration(request)
	if err := validateRegistration(request, r.now().UTC()); err != nil {
		return planning.LocalInteractionReceipt{}, err
	}
	switch request.Type {
	case planning.LocalInteractionConnection:
		ticket, err := r.onboarding.BeginSkill(ctx, onboarding.SkillHandoffRequest{
			TenantID: request.TenantID, SiteID: request.SiteID, PrincipalSHA256: request.PrincipalSHA256,
			HandoffRef: request.HandoffRef, ExpiresAt: request.ExpiresAt,
		})
		if err != nil {
			return planning.LocalInteractionReceipt{}, err
		}
		if ticket.HandoffRef != request.HandoffRef || ticket.ExpiresAt != request.ExpiresAt {
			return planning.LocalInteractionReceipt{}, ErrOnboardingMismatch
		}
	case planning.LocalInteractionPersistentChange:
		change := *request.Change
		record, err := r.changes.Register(ctx, Record{
			HandoffRef: request.HandoffRef, TenantID: request.TenantID, SiteID: request.SiteID,
			PrincipalSHA256: request.PrincipalSHA256, InteractionType: request.Type,
			Operation: change.Operation, SourceRef: change.SourceRef, TaskRef: change.TaskRef,
			ObservableRef: change.ObservableRef, ExpectedSourceRevision: change.ExpectedSourceRevision,
			ExpectedTaskRevision: change.ExpectedTaskRevision, ExpiresAt: request.ExpiresAt, State: StatePending,
		})
		if err != nil {
			return planning.LocalInteractionReceipt{}, err
		}
		if record.HandoffRef != request.HandoffRef || record.InteractionType != request.Type || record.ExpiresAt != request.ExpiresAt {
			return planning.LocalInteractionReceipt{}, ErrIntegrity
		}
	default:
		return planning.LocalInteractionReceipt{}, ErrInvalidRegistration
	}
	return planning.LocalInteractionReceipt{Type: request.Type, HandoffRef: request.HandoffRef, ExpiresAt: request.ExpiresAt}, nil
}

func canonicalRegistration(request planning.LocalInteractionRegistration) planning.LocalInteractionRegistration {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.SiteID = strings.TrimSpace(request.SiteID)
	request.PrincipalSHA256 = strings.TrimSpace(request.PrincipalSHA256)
	request.HandoffRef = strings.TrimSpace(request.HandoffRef)
	request.ExpiresAt = request.ExpiresAt.UTC()
	if request.Change != nil {
		change := *request.Change
		change.SourceRef = strings.TrimSpace(change.SourceRef)
		change.TaskRef = strings.TrimSpace(change.TaskRef)
		change.ObservableRef = strings.TrimSpace(change.ObservableRef)
		request.Change = &change
	}
	return request
}

func validateRegistration(request planning.LocalInteractionRegistration, now time.Time) error {
	if !scopeRefPattern.MatchString(request.TenantID) || !scopeRefPattern.MatchString(request.SiteID) ||
		!digestPattern.MatchString(request.PrincipalSHA256) || !scopeRefPattern.MatchString(request.HandoffRef) ||
		request.ExpiresAt.IsZero() || !request.ExpiresAt.Equal(request.ExpiresAt.UTC()) || !request.ExpiresAt.After(now) {
		return ErrInvalidRegistration
	}
	switch request.Type {
	case planning.LocalInteractionConnection:
		if request.Change != nil {
			return ErrInvalidRegistration
		}
	case planning.LocalInteractionPersistentChange:
		if request.Change == nil {
			return ErrInvalidRegistration
		}
		if err := validateChange(*request.Change); err != nil {
			return err
		}
	default:
		return ErrInvalidRegistration
	}
	return nil
}

var _ planning.LocalInteractionRegistrar = (*Registrar)(nil)
