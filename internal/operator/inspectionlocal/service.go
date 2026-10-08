package inspectionlocal

import (
	"context"
	"errors"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectioninteraction"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
)

type Config struct {
	Sessions             *SessionBinder
	Onboarding           *onboarding.EntryService
	Connections          *onboarding.HandoffStore
	Changes              *inspectioninteraction.Store
	PersistentConnection onboarding.PersistedConnectionVerifier
}

// Service owns no authority issuer, proposal creator, device adapter,
// dispatcher, or persistence. It is only the local application boundary over
// the one configured onboarding entry and the two authoritative handoff stores.
type Service struct {
	sessions             *SessionBinder
	onboarding           *onboarding.EntryService
	connections          *onboarding.HandoffStore
	changes              *inspectioninteraction.Store
	persistentConnection onboarding.PersistedConnectionVerifier
}

func NewService(config Config) (*Service, error) {
	if config.Sessions == nil || config.Onboarding == nil || config.Connections == nil || config.Changes == nil {
		return nil, ErrUnavailable
	}
	return &Service{
		sessions: config.Sessions, onboarding: config.Onboarding,
		connections: config.Connections, changes: config.Changes,
		persistentConnection: config.PersistentConnection,
	}, nil
}

type presence uint8

const (
	presenceMissing presence = iota
	presenceAccessible
	presenceExpired
)

type resolvedInteraction struct {
	kind       InteractionKind
	presence   presence
	connection onboarding.HandoffRecord
	change     inspectioninteraction.Record
}

// Resolve returns only a closed local action state. Both stores are always
// checked before a result is selected, so a duplicated handoff fails closed.
func (s *Service) Resolve(ctx context.Context, local LocalSession) (Interaction, error) {
	if !serviceReady(s) {
		return Interaction{}, ErrUnavailable
	}
	local, err := s.sessions.validate(local, false)
	if err != nil {
		return Interaction{}, err
	}
	resolved, err := s.lookup(ctx, local.handoffRef)
	if err != nil {
		return Interaction{}, err
	}
	switch resolved.presence {
	case presenceExpired:
		return Interaction{}, ErrExpired
	case presenceAccessible:
		if resolved.kind == KindConnection {
			return connectionInteraction(local.handoffRef, resolved.connection)
		}
		return persistentInteraction(local.handoffRef, resolved.change)
	default:
		return Interaction{}, ErrIntegrity
	}
}

// CompleteConnection delegates the exact protected input and grant to the one
// configured EntryService. Password ownership remains with this call and its
// bytes are cleared on every return path, including validation and lookup
// failure.
func (s *Service) CompleteConnection(ctx context.Context, local LocalSession, request CompleteConnectionRequest) (Interaction, error) {
	defer clearBytes(request.Connection.Password)
	if !serviceReady(s) {
		return Interaction{}, ErrUnavailable
	}
	local, err := s.sessions.validate(local, true)
	if err != nil {
		return Interaction{}, err
	}
	resolved, err := s.lookup(ctx, local.handoffRef)
	if err != nil {
		return Interaction{}, err
	}
	if resolved.kind != KindConnection {
		return Interaction{}, ErrWrongKind
	}
	if resolved.presence == presenceExpired {
		return Interaction{}, ErrExpired
	}
	if resolved.presence != presenceAccessible {
		return Interaction{}, ErrIntegrity
	}
	result, err := s.onboarding.CompleteSkill(ctx, onboarding.CompleteSkillRequest{
		TenantID: resolved.connection.TenantID, SiteID: resolved.connection.SiteID,
		PrincipalSHA256: resolved.connection.PrincipalSHA256, HandoffRef: local.handoffRef,
		Connection: request.Connection, Grant: request.Grant,
	})
	if err != nil {
		return Interaction{}, mapOnboardingActionError(err)
	}
	if result.OperationID != resolved.connection.OperationID || result.Operation != onboarding.OperationCreate ||
		result.Status != onboarding.StatusCompleted || result.Phase != onboarding.PhaseCompleted {
		return Interaction{}, ErrIntegrity
	}
	return Interaction{Kind: KindConnection, Action: ActionNone, Status: StatusCompleted}, nil
}

// CompleteVerifiedConnection closes the exact onboarding handoff only after
// the shared Product registry confirms that the one current profile was
// durably committed. It cannot create a second profile and carries no password
// or authority grant.
func (s *Service) CompleteVerifiedConnection(ctx context.Context, local LocalSession) (Interaction, error) {
	if !serviceReady(s) || s.persistentConnection == nil {
		return Interaction{}, ErrUnavailable
	}
	local, err := s.sessions.validate(local, true)
	if err != nil {
		return Interaction{}, err
	}
	resolved, err := s.lookup(ctx, local.handoffRef)
	if err != nil {
		return Interaction{}, err
	}
	if resolved.kind != KindConnection {
		return Interaction{}, ErrWrongKind
	}
	if resolved.presence == presenceExpired {
		return Interaction{}, ErrExpired
	}
	if resolved.presence != presenceAccessible || resolved.connection.State != onboarding.HandoffPending {
		return Interaction{}, ErrConflict
	}
	receipt, err := s.onboarding.AcknowledgeSkillPersisted(ctx, onboarding.SkillHandoffRequest{
		TenantID: resolved.connection.TenantID, SiteID: resolved.connection.SiteID,
		PrincipalSHA256: resolved.connection.PrincipalSHA256, HandoffRef: local.handoffRef,
		ExpiresAt: resolved.connection.ExpiresAt,
	}, s.persistentConnection)
	if err != nil {
		return Interaction{}, mapOnboardingActionError(err)
	}
	if receipt.HandoffRef != local.handoffRef || !receipt.ExpiresAt.Equal(resolved.connection.ExpiresAt) {
		return Interaction{}, ErrIntegrity
	}
	return Interaction{Kind: KindConnection, Action: ActionNone, Status: StatusCompleted}, nil
}

// PreparePersistentTransfer durably binds the separately-created stable
// proposal reference. This service neither creates nor confirms that proposal.
func (s *Service) PreparePersistentTransfer(ctx context.Context, local LocalSession, request PersistentTransferRequest) (Interaction, error) {
	return s.transfer(ctx, local, request, false)
}

// MarkPersistentTransferred closes the transfer only after the external
// changeflow owner has durably accepted the same stable proposal reference.
func (s *Service) MarkPersistentTransferred(ctx context.Context, local LocalSession, request PersistentTransferRequest) (Interaction, error) {
	return s.transfer(ctx, local, request, true)
}

func (s *Service) transfer(ctx context.Context, local LocalSession, request PersistentTransferRequest, mark bool) (Interaction, error) {
	if !serviceReady(s) {
		return Interaction{}, ErrUnavailable
	}
	local, err := s.sessions.validate(local, true)
	if err != nil {
		return Interaction{}, err
	}
	if !validProposalRef(request.ProposalRef) {
		return Interaction{}, ErrInvalidRequest
	}
	resolved, err := s.lookup(ctx, local.handoffRef)
	if err != nil {
		return Interaction{}, err
	}
	if resolved.kind != KindPersistentChange {
		return Interaction{}, ErrWrongKind
	}
	if resolved.presence != presenceAccessible && resolved.presence != presenceExpired {
		return Interaction{}, ErrIntegrity
	}
	binding := inspectioninteraction.Binding{
		TenantID: resolved.change.TenantID, SiteID: resolved.change.SiteID,
		PrincipalSHA256: resolved.change.PrincipalSHA256,
	}
	var record inspectioninteraction.Record
	if mark {
		record, err = s.changes.MarkTransferred(ctx, binding, local.handoffRef, request.ProposalRef)
	} else {
		record, err = s.changes.PrepareTransfer(ctx, binding, local.handoffRef, request.ProposalRef)
	}
	if err != nil {
		return Interaction{}, mapChangeActionError(err)
	}
	if record.HandoffRef != local.handoffRef || record.TenantID != resolved.change.TenantID || record.SiteID != resolved.change.SiteID ||
		record.PrincipalSHA256 != resolved.change.PrincipalSHA256 || record.InteractionType != planning.LocalInteractionPersistentChange ||
		record.ProposalRef != request.ProposalRef {
		return Interaction{}, ErrIntegrity
	}
	if mark && record.State != inspectioninteraction.StateTransferred {
		return Interaction{}, ErrIntegrity
	}
	if !mark && record.State != inspectioninteraction.StateTransferPrepared && record.State != inspectioninteraction.StateTransferred {
		return Interaction{}, ErrIntegrity
	}
	return persistentInteraction(local.handoffRef, record)
}

func (s *Service) lookup(ctx context.Context, handoffRef string) (resolvedInteraction, error) {
	connection, connectionPresence, connectionErr := s.lookupConnection(ctx, handoffRef)
	change, changePresence, changeErr := s.lookupChange(ctx, handoffRef)
	if connectionErr != nil {
		return resolvedInteraction{}, connectionErr
	}
	if changeErr != nil {
		return resolvedInteraction{}, changeErr
	}
	connectionExists := connectionPresence != presenceMissing
	changeExists := changePresence != presenceMissing
	if connectionExists && changeExists {
		return resolvedInteraction{}, ErrAmbiguous
	}
	if !connectionExists && !changeExists {
		return resolvedInteraction{}, ErrNotFound
	}
	if connectionExists {
		return resolvedInteraction{kind: KindConnection, presence: connectionPresence, connection: connection}, nil
	}
	return resolvedInteraction{kind: KindPersistentChange, presence: changePresence, change: change}, nil
}

func (s *Service) lookupConnection(ctx context.Context, handoffRef string) (onboarding.HandoffRecord, presence, error) {
	result, err := s.connections.ResolveProtected(ctx, handoffRef)
	switch {
	case err == nil:
		if result.Expired {
			return result.Record, presenceExpired, nil
		}
		return result.Record, presenceAccessible, nil
	case errors.Is(err, onboarding.ErrHandoffNotFound):
		return onboarding.HandoffRecord{}, presenceMissing, nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return onboarding.HandoffRecord{}, presenceMissing, err
	case errors.Is(err, onboarding.ErrHandoffIntegrity), errors.Is(err, onboarding.ErrInvalidHandoff):
		return onboarding.HandoffRecord{}, presenceMissing, ErrIntegrity
	default:
		return onboarding.HandoffRecord{}, presenceMissing, ErrUnavailable
	}
}

func (s *Service) lookupChange(ctx context.Context, handoffRef string) (inspectioninteraction.Record, presence, error) {
	result, err := s.changes.ResolveProtected(ctx, handoffRef)
	switch {
	case err == nil:
		if result.Expired {
			return result.Record, presenceExpired, nil
		}
		return result.Record, presenceAccessible, nil
	case errors.Is(err, inspectioninteraction.ErrNotFound):
		return inspectioninteraction.Record{}, presenceMissing, nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return inspectioninteraction.Record{}, presenceMissing, err
	case errors.Is(err, inspectioninteraction.ErrIntegrity), errors.Is(err, inspectioninteraction.ErrInvalidRegistration):
		return inspectioninteraction.Record{}, presenceMissing, ErrIntegrity
	default:
		return inspectioninteraction.Record{}, presenceMissing, ErrUnavailable
	}
}

func connectionInteraction(handoffRef string, record onboarding.HandoffRecord) (Interaction, error) {
	if record.HandoffRef != handoffRef {
		return Interaction{}, ErrIntegrity
	}
	switch record.State {
	case onboarding.HandoffPending:
		return Interaction{Kind: KindConnection, Action: ActionCompleteConnection, Status: StatusPending}, nil
	case onboarding.HandoffCompleted:
		return Interaction{Kind: KindConnection, Action: ActionNone, Status: StatusCompleted}, nil
	default:
		return Interaction{}, ErrIntegrity
	}
}

func persistentInteraction(handoffRef string, record inspectioninteraction.Record) (Interaction, error) {
	if record.HandoffRef != handoffRef || record.InteractionType != planning.LocalInteractionPersistentChange {
		return Interaction{}, ErrIntegrity
	}
	switch record.State {
	case inspectioninteraction.StatePending:
		if record.ProposalRef != "" {
			return Interaction{}, ErrIntegrity
		}
		return Interaction{Kind: KindPersistentChange, Action: ActionPreparePersistentTransfer, Status: StatusPending}, nil
	case inspectioninteraction.StateTransferPrepared:
		if !validProposalRef(record.ProposalRef) {
			return Interaction{}, ErrIntegrity
		}
		return Interaction{Kind: KindPersistentChange, Action: ActionMarkPersistentTransferred, Status: StatusTransferPrepared}, nil
	case inspectioninteraction.StateTransferred:
		if !validProposalRef(record.ProposalRef) {
			return Interaction{}, ErrIntegrity
		}
		return Interaction{Kind: KindPersistentChange, Action: ActionNone, Status: StatusTransferred}, nil
	default:
		return Interaction{}, ErrIntegrity
	}
}

func mapOnboardingActionError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, onboarding.ErrHandoffExpired):
		return ErrExpired
	case errors.Is(err, onboarding.ErrBindingMismatch):
		return ErrIntegrity
	case errors.Is(err, onboarding.ErrAuthorityDenied):
		return ErrDenied
	case errors.Is(err, onboarding.ErrInvalidInput):
		return ErrInvalidRequest
	case errors.Is(err, onboarding.ErrHandoffIntegrity), errors.Is(err, onboarding.ErrInvalidHandoff):
		return ErrIntegrity
	case errors.Is(err, onboarding.ErrHandoffNotFound):
		return ErrNotFound
	case errors.Is(err, onboarding.ErrHandoffConflict), errors.Is(err, onboarding.ErrOperationConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

func mapChangeActionError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, inspectioninteraction.ErrExpired):
		return ErrExpired
	case errors.Is(err, inspectioninteraction.ErrScopeMismatch):
		return ErrIntegrity
	case errors.Is(err, inspectioninteraction.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, inspectioninteraction.ErrIntegrity), errors.Is(err, inspectioninteraction.ErrInvalidRegistration):
		return ErrIntegrity
	case errors.Is(err, inspectioninteraction.ErrConflict), errors.Is(err, inspectioninteraction.ErrTransferNotPrepared):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

func serviceReady(service *Service) bool {
	return service != nil && service.sessions != nil && service.onboarding != nil &&
		service.connections != nil && service.changes != nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
