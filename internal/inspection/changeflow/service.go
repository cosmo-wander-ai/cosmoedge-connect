package changeflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

type GrantVerifier interface {
	Verify(authority.Grant, authority.Demand, time.Time) error
}

// ProposalCreator can create only an ordinary Operator proposal. Deliberately
// absent are Confirm, Dispatch, raw device client and credential methods.
type ProposalCreator interface {
	ProposePersistentChange(context.Context, ProposalInput) (Proposal, error)
}

type ActionReader interface {
	ReadAction(context.Context, string) (ActionStatus, error)
}

type CatalogRefresher interface {
	RefreshAfterAction(context.Context, RefreshRequest) (RefreshResult, error)
}

type AssignmentPublisher interface {
	PublishAfterRefresh(context.Context, PublicationRequest) error
}

type Store interface {
	Create(context.Context, Record) (Record, error)
	Get(context.Context, string) (Record, error)
	CompareAndSwap(context.Context, Record, uint64) (Record, error)
}

type Service struct {
	verifier  GrantVerifier
	proposals ProposalCreator
	actions   ActionReader
	catalog   CatalogRefresher
	publisher AssignmentPublisher
	store     Store
	now       func() time.Time
}

func New(verifier GrantVerifier, proposals ProposalCreator, actions ActionReader, catalog CatalogRefresher, publisher AssignmentPublisher, store Store) (*Service, error) {
	if verifier == nil || proposals == nil || actions == nil || catalog == nil || publisher == nil || store == nil {
		return nil, errors.New("persistent change workflow dependencies are required")
	}
	return &Service{verifier: verifier, proposals: proposals, actions: actions, catalog: catalog, publisher: publisher, store: store, now: time.Now}, nil
}

func (s *Service) Propose(ctx context.Context, request Request, grant authority.Grant) (Summary, error) {
	request.RequestID = strings.TrimSpace(request.RequestID)
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.SiteID = strings.TrimSpace(request.SiteID)
	request.DeviceProfileID = strings.TrimSpace(request.DeviceProfileID)
	request.PrincipalSHA256 = strings.TrimSpace(request.PrincipalSHA256)
	request.OperationKind = strings.TrimSpace(request.OperationKind)
	request.RequestedAt = request.RequestedAt.UTC()
	request.RequestExpiresAt = request.RequestExpiresAt.UTC()
	if request.validate() != nil {
		return Summary{}, ErrInvalid
	}
	now := s.now().UTC()
	if now.Before(request.RequestedAt) || !now.Before(request.RequestExpiresAt) {
		return Summary{}, ErrInvalid
	}
	demand := authority.Demand{
		Class: authority.PersistentDeviceWrite, OperationKind: request.OperationKind,
		PrincipalSHA256: request.PrincipalSHA256, TenantID: request.TenantID, SiteID: request.SiteID,
		DeviceProfileID: request.DeviceProfileID,
	}
	if err := s.verifier.Verify(grant, demand, now); err != nil {
		return Summary{}, ErrUnauthorized
	}
	proposal, err := s.proposals.ProposePersistentChange(ctx, ProposalInput{
		RequestID: request.RequestID, TenantID: request.TenantID, SiteID: request.SiteID,
		DeviceProfileID: request.DeviceProfileID, OperationKind: request.OperationKind,
		ExpiresAt: request.RequestExpiresAt,
	})
	if err != nil {
		return Summary{}, err
	}
	if !validRef(proposal.ActionID) || !validRef(proposal.LocalHandoffRef) || proposal.ExpiresAt.IsZero() ||
		proposal.ExpiresAt.After(request.RequestExpiresAt) || !proposal.ExpiresAt.After(now) {
		return Summary{}, errors.New("operator returned an invalid persistent change proposal")
	}
	record := Record{
		Schema: SchemaVersion, WorkflowID: workflowID(request), Revision: 1, Request: request,
		GrantID: grant.GrantID, GrantScopeSHA256: grant.ScopeSHA256, ActionID: proposal.ActionID,
		LocalHandoffRef: proposal.LocalHandoffRef, State: StateAwaitingLocalConfirmation,
		Reason: "operator_proposal_created", CreatedAt: now, UpdatedAt: now,
	}
	created, err := s.store.Create(ctx, record)
	if err != nil {
		return Summary{}, err
	}
	return created.Summary()
}

// Advance observes the ordinary Action Kernel and refreshes the protected
// catalog only after a confirmed, read-back-backed success. It never confirms
// or dispatches the action itself.
func (s *Service) Advance(ctx context.Context, workflowID string) (Summary, error) {
	record, err := s.store.Get(ctx, strings.TrimSpace(workflowID))
	if err != nil {
		return Summary{}, err
	}
	now := s.now().UTC()
	switch record.State {
	case StateAwaitingLocalConfirmation, StateActionRunning:
		status, err := s.actions.ReadAction(ctx, record.ActionID)
		if err != nil {
			return Summary{}, err
		}
		if status.ActionID != record.ActionID || status.ObservedAt.IsZero() || status.ObservedAt.After(now.Add(time.Minute)) || status.DeviceWrites < 0 {
			return Summary{}, errors.New("operator action status is invalid")
		}
		switch status.State {
		case ActionAwaitingConfirmation:
			record.State, record.Reason = StateAwaitingLocalConfirmation, "local_confirmation_required"
		case ActionRunning:
			record.State, record.Reason = StateActionRunning, "operator_action_running"
		case ActionOutcomeUnknown:
			record.State, record.Reason = StateOutcomeUnknown, "operator_action_outcome_unknown"
		case ActionFailed:
			record.State, record.Reason = StateFailed, "operator_action_failed"
		case ActionSucceeded:
			if status.DeviceWrites < 1 || !validRef(status.EvidenceRef) || !digestPattern.MatchString(status.ReadbackSHA256) {
				return Summary{}, errors.New("successful operator action lacks trusted readback evidence")
			}
			record.State, record.Reason = StateCatalogRefreshRequired, "trusted_readback_received"
			record.ActionEvidenceRef, record.ReadbackSHA256 = status.EvidenceRef, status.ReadbackSHA256
		default:
			return Summary{}, errors.New("operator action state is unsupported")
		}
		record.UpdatedAt = now
		record, err = s.store.CompareAndSwap(ctx, record, record.Revision)
		if err != nil {
			return Summary{}, err
		}
		if record.State != StateCatalogRefreshRequired {
			return record.Summary()
		}
		fallthrough
	case StateCatalogRefreshRequired:
		refresh, err := s.catalog.RefreshAfterAction(ctx, RefreshRequest{
			WorkflowID: record.WorkflowID, TenantID: record.Request.TenantID, SiteID: record.Request.SiteID,
			DeviceProfileID: record.Request.DeviceProfileID, ActionID: record.ActionID,
			EvidenceRef: record.ActionEvidenceRef, ReadbackSHA256: record.ReadbackSHA256,
		})
		if err != nil {
			return Summary{}, err
		}
		if refresh.ActionID != record.ActionID || !digestPattern.MatchString(refresh.CatalogFingerprint) ||
			refresh.RefreshedAt.IsZero() || refresh.RefreshedAt.Before(record.UpdatedAt) || refresh.RefreshedAt.After(now.Add(time.Minute)) {
			return Summary{}, errors.New("catalog refresh result is not bound to the confirmed action")
		}
		record.CatalogFingerprint = refresh.CatalogFingerprint
		record.State, record.Reason, record.UpdatedAt = StateReadyToPublish, "catalog_refreshed_after_readback", now
		record, err = s.store.CompareAndSwap(ctx, record, record.Revision)
		if err != nil {
			return Summary{}, err
		}
		return record.Summary()
	default:
		return record.Summary()
	}
}

func (s *Service) Publish(ctx context.Context, workflowID, assignmentRef, catalogFingerprint string) (Summary, error) {
	record, err := s.store.Get(ctx, strings.TrimSpace(workflowID))
	if err != nil {
		return Summary{}, err
	}
	if record.State != StateReadyToPublish || !validRef(assignmentRef) ||
		!digestPattern.MatchString(catalogFingerprint) || catalogFingerprint != record.CatalogFingerprint {
		return Summary{}, ErrNotPublishable
	}
	request := PublicationRequest{
		WorkflowID: record.WorkflowID, TenantID: record.Request.TenantID, SiteID: record.Request.SiteID,
		AssignmentRef: assignmentRef, CatalogFingerprint: catalogFingerprint,
	}
	if err := s.publisher.PublishAfterRefresh(ctx, request); err != nil {
		return Summary{}, err
	}
	record.AssignmentRef, record.State, record.Reason = assignmentRef, StatePublished, "assignment_published_after_catalog_refresh"
	record.UpdatedAt = s.now().UTC()
	record, err = s.store.CompareAndSwap(ctx, record, record.Revision)
	if err != nil {
		return Summary{}, err
	}
	return record.Summary()
}

func workflowID(request Request) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{request.TenantID, request.SiteID, request.DeviceProfileID, request.RequestID}, "\x00")))
	return "change_" + hex.EncodeToString(sum[:16])
}
