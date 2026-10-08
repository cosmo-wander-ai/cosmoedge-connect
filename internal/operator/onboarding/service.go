package onboarding

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

type ProfileStore interface {
	Create(context.Context, profile.NewDeviceProfile) (profile.DeviceProfile, error)
	Get(context.Context, string, string, string) (profile.DeviceProfile, error)
	Update(context.Context, profile.UpdateDeviceProfile) (profile.DeviceProfile, error)
	SetCredentialState(context.Context, string, string, string, uint64, profile.CredentialState) (profile.DeviceProfile, error)
	Forget(context.Context, string, string, string, uint64) error
}

type Service struct {
	profiles    ProfileStore
	credentials credential.SecretStore
	journal     SagaJournal
	authority   AuthorityVerifier
	now         func() time.Time
}

type Option func(*Service) error

func WithClock(now func() time.Time) Option {
	return func(service *Service) error {
		if now == nil {
			return ErrInvalidInput
		}
		service.now = now
		return nil
	}
}

func NewService(profiles ProfileStore, credentials credential.SecretStore, journal SagaJournal, verifier AuthorityVerifier, options ...Option) (*Service, error) {
	if profiles == nil || credentials == nil || journal == nil || verifier == nil {
		return nil, errors.Join(ErrInvalidInput, errors.New("all onboarding dependencies are required"))
	}
	service := &Service{profiles: profiles, credentials: credentials, journal: journal, authority: verifier, now: time.Now}
	for _, option := range options {
		if option == nil {
			return nil, ErrInvalidInput
		}
		if err := option(service); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// InspectOperationCompletion is a pure protected-state read for local handoff
// reconciliation. It never verifies or issues a grant, reads a credential or
// current profile, resumes a saga, mutates state, or performs a device action.
func (s *Service) InspectOperationCompletion(ctx context.Context, operationID string) (OperationCompletion, error) {
	completion := OperationCompletion{OperationID: operationID}
	if s == nil || s.journal == nil || !operationIDPattern.MatchString(operationID) {
		return OperationCompletion{}, ErrInvalidInput
	}
	record, err := s.journal.Get(ctx, operationID)
	if errors.Is(err, ErrSagaNotFound) {
		return completion, nil
	}
	if err != nil {
		return OperationCompletion{}, err
	}
	if err := record.Validate(); err != nil || record.OperationID != operationID || record.Operation != OperationCreate ||
		record.ProfileID != stableProfileID(operationID) {
		return OperationCompletion{}, errors.Join(ErrOperationConflict, err)
	}
	completion.TenantID = record.TenantID
	completion.SiteID = record.SiteID
	completion.PrincipalSHA256 = record.PrincipalSHA256
	completion.Found = true
	if record.Phase != PhaseCompleted {
		if err := completion.validate(); err != nil {
			return OperationCompletion{}, err
		}
		return completion, nil
	}
	completion.Completed = true
	if err := completion.validate(); err != nil {
		return OperationCompletion{}, err
	}
	return completion, nil
}

func (s *Service) Create(ctx context.Context, request CreateRequest) (Result, error) {
	defer clearBytes(request.Secret)
	operationID, err := ensureOperationID(request.OperationID)
	if err != nil {
		return Result{}, err
	}
	profileID := strings.TrimSpace(request.ProfileID)
	if profileID == "" {
		profileID, err = profile.NewProfileID()
		if err != nil {
			return Result{OperationID: operationID, Operation: OperationCreate, Status: StatusFailed, Phase: PhasePrepared}, err
		}
	}
	if err := s.verify(request.Access, "", authority.OpProfileCreate); err != nil {
		return stoppedResult(operationID, OperationCreate, PhasePrepared, StatusFailed, err)
	}
	candidate, err := s.prepareCreateProfile(request, profileID)
	if err != nil {
		return stoppedResult(operationID, OperationCreate, PhasePrepared, StatusFailed, err)
	}
	putOperationID, err := credential.NewPutOperationID()
	if err != nil {
		return stoppedResult(operationID, OperationCreate, PhasePrepared, StatusFailed, err)
	}
	record := SagaRecord{
		Schema: SagaSchemaVersion, OperationID: operationID, Operation: OperationCreate, Phase: PhasePrepared,
		TenantID: candidate.TenantID, SiteID: candidate.SiteID, PrincipalSHA256: request.Access.PrincipalSHA256,
		ProfileID: candidate.ProfileID, Alias: candidate.Alias, Endpoint: candidate.Endpoint, Username: candidate.Username,
		PinnedSerial: candidate.PinnedSerial, PinnedType: candidate.PinnedType, TransportFingerprint: candidate.TransportFingerprint,
		CredentialPutID: putOperationID,
	}
	record, err = s.begin(ctx, record)
	if err != nil {
		return stoppedResult(operationID, OperationCreate, PhasePrepared, StatusFailed, err)
	}
	if !sameCreateIntent(record, candidate) {
		return stoppedResult(operationID, OperationCreate, record.Phase, StatusFailed, ErrOperationConflict)
	}
	return s.resumeCreate(ctx, record, request.Secret)
}

var _ OperationCompletionReader = (*Service)(nil)

func (s *Service) UpdateEndpoint(ctx context.Context, request UpdateEndpointRequest) (Result, error) {
	operationID, err := ensureOperationID(request.OperationID)
	if err != nil {
		return Result{}, err
	}
	if request.ExpectedGeneration == 0 {
		return stoppedResult(operationID, OperationUpdateEndpoint, PhasePrepared, StatusFailed, ErrInvalidInput)
	}
	if err := s.verify(request.Access, request.ProfileID, authority.OpCredentialRotate, authority.OpProfileUpdate); err != nil {
		return stoppedResult(operationID, OperationUpdateEndpoint, PhasePrepared, StatusFailed, err)
	}
	current, err := s.loadBoundProfile(ctx, request.Access, request.ProfileID)
	if err != nil {
		return stoppedResult(operationID, OperationUpdateEndpoint, PhasePrepared, StatusFailed, err)
	}
	if current.Generation != request.ExpectedGeneration {
		return stoppedResult(operationID, OperationUpdateEndpoint, PhasePrepared, StatusFailed, profile.ErrConflict)
	}
	if err := requireStableIdentity(current, current.PinnedSerial, current.PinnedType); err != nil {
		return stoppedResult(operationID, OperationUpdateEndpoint, PhasePrepared, StatusBlocked, err)
	}
	desired, err := desiredTransport(current, request.Endpoint, request.Username)
	if err != nil {
		return stoppedResult(operationID, OperationUpdateEndpoint, PhasePrepared, StatusFailed, err)
	}
	record := changeRecord(operationID, OperationUpdateEndpoint, request.Access, current, desired.Endpoint, desired.Username, desired.TransportFingerprint)
	if desired.Endpoint == current.Endpoint && desired.Username == current.Username {
		record.Phase = PhaseCompleted
		record.NewCredentialRef = current.CredentialRef
		record, err = s.begin(ctx, record)
		if err != nil {
			return stoppedResult(operationID, OperationUpdateEndpoint, PhaseCompleted, StatusFailed, err)
		}
		if !sameChangeIntent(record, OperationUpdateEndpoint, request.ProfileID, desired.Endpoint, desired.Username) {
			return stoppedResult(operationID, OperationUpdateEndpoint, record.Phase, StatusFailed, ErrOperationConflict)
		}
		if record.Phase != PhaseCompleted {
			return s.resumeChange(ctx, request.Access, record, nil)
		}
		return completedResult(record, &current), nil
	}
	record, err = s.begin(ctx, record)
	if err != nil {
		return stoppedResult(operationID, OperationUpdateEndpoint, PhasePrepared, StatusFailed, err)
	}
	if !sameChangeIntent(record, OperationUpdateEndpoint, request.ProfileID, desired.Endpoint, desired.Username) {
		return stoppedResult(operationID, OperationUpdateEndpoint, record.Phase, StatusFailed, ErrOperationConflict)
	}
	return s.resumeChange(ctx, request.Access, record, nil)
}

func (s *Service) RotateCredential(ctx context.Context, request RotateCredentialRequest) (Result, error) {
	defer clearBytes(request.Secret)
	operationID, err := ensureOperationID(request.OperationID)
	if err != nil {
		return Result{}, err
	}
	if request.ExpectedGeneration == 0 {
		return stoppedResult(operationID, OperationRotateCredential, PhasePrepared, StatusFailed, ErrInvalidInput)
	}
	if err := s.verify(request.Access, request.ProfileID, authority.OpCredentialRotate, authority.OpProfileUpdate); err != nil {
		return stoppedResult(operationID, OperationRotateCredential, PhasePrepared, StatusFailed, err)
	}
	current, err := s.loadBoundProfile(ctx, request.Access, request.ProfileID)
	if err != nil {
		return stoppedResult(operationID, OperationRotateCredential, PhasePrepared, StatusFailed, err)
	}
	if current.Generation != request.ExpectedGeneration {
		return stoppedResult(operationID, OperationRotateCredential, PhasePrepared, StatusFailed, profile.ErrConflict)
	}
	if err := requireStableIdentity(current, current.PinnedSerial, current.PinnedType); err != nil {
		return stoppedResult(operationID, OperationRotateCredential, PhasePrepared, StatusBlocked, err)
	}
	record := changeRecord(operationID, OperationRotateCredential, request.Access, current, current.Endpoint, current.Username, current.TransportFingerprint)
	record, err = s.begin(ctx, record)
	if err != nil {
		return stoppedResult(operationID, OperationRotateCredential, PhasePrepared, StatusFailed, err)
	}
	if !sameChangeIntent(record, OperationRotateCredential, request.ProfileID, current.Endpoint, current.Username) {
		return stoppedResult(operationID, OperationRotateCredential, record.Phase, StatusFailed, ErrOperationConflict)
	}
	return s.resumeChange(ctx, request.Access, record, request.Secret)
}

func (s *Service) Forget(ctx context.Context, request ForgetRequest) (Result, error) {
	operationID, err := ensureOperationID(request.OperationID)
	if err != nil {
		return Result{}, err
	}
	if request.ExpectedGeneration == 0 {
		return stoppedResult(operationID, OperationForget, PhasePrepared, StatusFailed, ErrInvalidInput)
	}
	if err := s.verify(request.Access, request.ProfileID, authority.OpProfileForget); err != nil {
		return stoppedResult(operationID, OperationForget, PhasePrepared, StatusFailed, err)
	}
	current, err := s.loadBoundProfile(ctx, request.Access, request.ProfileID)
	if err != nil {
		return stoppedResult(operationID, OperationForget, PhasePrepared, StatusFailed, err)
	}
	if current.Generation != request.ExpectedGeneration {
		return stoppedResult(operationID, OperationForget, PhasePrepared, StatusFailed, profile.ErrConflict)
	}
	record := SagaRecord{
		Schema: SagaSchemaVersion, OperationID: operationID, Operation: OperationForget, Phase: PhasePrepared,
		TenantID: current.TenantID, SiteID: current.SiteID, PrincipalSHA256: request.Access.PrincipalSHA256,
		ProfileID: current.ProfileID, ExpectedGeneration: current.Generation, OldCredentialRef: current.CredentialRef,
	}
	record, err = s.begin(ctx, record)
	if err != nil {
		return stoppedResult(operationID, OperationForget, PhasePrepared, StatusFailed, err)
	}
	if record.Operation != OperationForget || record.ProfileID != current.ProfileID {
		return stoppedResult(operationID, OperationForget, record.Phase, StatusFailed, ErrOperationConflict)
	}
	return s.resumeForget(ctx, request.Access, record)
}

func (s *Service) Resume(ctx context.Context, request ResumeRequest) (Result, error) {
	defer clearBytes(request.Secret)
	if !operationIDPattern.MatchString(request.OperationID) {
		return Result{}, ErrInvalidInput
	}
	record, err := s.journal.Get(ctx, request.OperationID)
	if err != nil {
		return stoppedResult(request.OperationID, "", PhasePrepared, StatusFailed, err)
	}
	if record.TenantID != request.Access.TenantID || record.SiteID != request.Access.SiteID || record.PrincipalSHA256 != request.Access.PrincipalSHA256 {
		return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusFailed, ErrBindingMismatch)
	}
	if err := s.verifyForRecord(request.Access, record); err != nil {
		return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusFailed, err)
	}
	switch record.Operation {
	case OperationCreate:
		return s.resumeCreate(ctx, record, request.Secret)
	case OperationUpdateEndpoint, OperationRotateCredential:
		return s.resumeChange(ctx, request.Access, record, request.Secret)
	case OperationForget:
		return s.resumeForget(ctx, request.Access, record)
	default:
		return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusFailed, ErrInvalidSaga)
	}
}

func (s *Service) resumeCreate(ctx context.Context, record SagaRecord, secret []byte) (Result, error) {
	for {
		switch record.Phase {
		case PhaseCompleted:
			item, err := s.profiles.Get(ctx, record.TenantID, record.SiteID, record.ProfileID)
			if err != nil || !profileMatchesCreate(item, record) {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(err, ErrOperationConflict))
			}
			return completedResult(record, &item), nil
		case PhaseFailed:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusFailed, ErrOperationConflict)
		case PhaseOutcomeUnknown:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrOutcomeUnknown)
		case PhasePrepared:
			receipt, putErr := s.findOrPutCredential(ctx, record, secret)
			if !putReceiptMatches(record, receipt) {
				status := StatusRecoverable
				if errors.Is(putErr, credential.ErrOutcomeUnknown) {
					status = StatusOutcomeUnknown
				}
				return stoppedResult(record.OperationID, record.Operation, record.Phase, status, firstNonNil(putErr, ErrOperationConflict))
			}
			record.NewCredentialRef = receipt.Ref
			record.CredentialPutPhase = receipt.Phase
			record.Phase = PhaseCredentialStored
			saved, saveErr := s.journal.Save(ctx, record)
			if saveErr != nil {
				status := StatusRecoverable
				if receipt.Phase == credential.PutUnknown || errors.Is(putErr, credential.ErrOutcomeUnknown) {
					status = StatusOutcomeUnknown
				}
				return stoppedResult(record.OperationID, record.Operation, PhasePrepared, status, errors.Join(putErr, saveErr))
			}
			record = saved
		case PhaseCredentialStored:
			if record.CredentialPutPhase == credential.PutRolledBack {
				record.Phase = PhaseCompensating
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, PhaseCredentialStored, StatusRecoverable, saveErr)
				}
				record = saved
				continue
			}
			if record.CredentialPutPhase != credential.PutCommitted {
				receipt, recoverErr := s.credentials.RecoverPut(ctx, record.CredentialPutID)
				if !putReceiptMatches(record, receipt) {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, errors.Join(recoverErr, ErrOperationConflict))
				}
				record.NewCredentialRef = receipt.Ref
				record.CredentialPutPhase = receipt.Phase
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, errors.Join(recoverErr, saveErr))
				}
				record = saved
				switch receipt.Phase {
				case credential.PutCommitted:
					// Continue below and create the profile with the durable ref.
				case credential.PutRolledBack:
					record.Phase = PhaseCompensating
					continue
				default:
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(recoverErr, credential.ErrOutcomeUnknown))
				}
			}
			item, createErr := s.profiles.Create(ctx, profile.NewDeviceProfile{
				ProfileID: record.ProfileID, TenantID: record.TenantID, SiteID: record.SiteID,
				Alias: record.Alias, Endpoint: record.Endpoint, Username: record.Username,
				CredentialRef: record.NewCredentialRef, PinnedSerial: record.PinnedSerial, PinnedType: record.PinnedType,
				TransportFingerprint: record.TransportFingerprint,
			})
			if createErr == nil {
				return s.saveCreatedProfile(ctx, record, item)
			}
			current, getErr := s.profiles.Get(ctx, record.TenantID, record.SiteID, record.ProfileID)
			if getErr == nil && profileMatchesCreate(current, record) {
				return s.saveCreatedProfile(ctx, record, current)
			}
			if errors.Is(createErr, profile.ErrConflict) || errors.Is(createErr, profile.ErrInvalidProfile) || getErr == nil {
				record.Phase = PhaseCompensating
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, PhaseCredentialStored, StatusRecoverable, errors.Join(createErr, saveErr))
				}
				record = saved
				continue
			}
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, errors.Join(createErr, getErr))
		case PhaseProfileSwitched:
			item, err := s.profiles.Get(ctx, record.TenantID, record.SiteID, record.ProfileID)
			if err != nil || !profileMatchesCreate(item, record) {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(err, ErrOperationConflict))
			}
			if err := s.acknowledgeCommittedPut(ctx, &record); err != nil {
				status := StatusRecoverable
				if errors.Is(err, credential.ErrOutcomeUnknown) {
					status = StatusOutcomeUnknown
				}
				return stoppedResult(record.OperationID, record.Operation, record.Phase, status, err)
			}
			return s.finish(ctx, record, &item)
		case PhaseCompensating:
			if record.CredentialPutPhase != credential.PutRolledBack {
				receipt, compensateErr := s.credentials.CompensatePut(ctx, record.CredentialPutID)
				if !putReceiptMatches(record, receipt) {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, errors.Join(compensateErr, ErrOperationConflict))
				}
				record.NewCredentialRef = receipt.Ref
				record.CredentialPutPhase = receipt.Phase
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, errors.Join(compensateErr, saveErr))
				}
				record = saved
				if receipt.Phase != credential.PutRolledBack {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(compensateErr, credential.ErrOutcomeUnknown))
				}
			}
			if err := s.credentials.AcknowledgePut(ctx, record.CredentialPutID); err != nil {
				status := StatusRecoverable
				if errors.Is(err, credential.ErrOutcomeUnknown) {
					status = StatusOutcomeUnknown
				}
				return stoppedResult(record.OperationID, record.Operation, record.Phase, status, err)
			}
			record.Phase = PhaseFailed
			saved, err := s.journal.Save(ctx, record)
			if err != nil {
				return stoppedResult(record.OperationID, record.Operation, PhaseCompensating, StatusRecoverable, err)
			}
			record = saved
		default:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrInvalidSaga)
		}
	}
}

func (s *Service) findOrPutCredential(ctx context.Context, record SagaRecord, secret []byte) (credential.PutReceipt, error) {
	receipt, err := s.credentials.PutByOperationID(ctx, record.CredentialPutID)
	if err == nil || !errors.Is(err, credential.ErrNotFound) {
		return receipt, err
	}
	if len(secret) == 0 {
		return credential.PutReceipt{}, ErrInvalidInput
	}
	return s.credentials.Put(ctx, record.CredentialPutID, secret)
}

func putReceiptMatches(record SagaRecord, receipt credential.PutReceipt) bool {
	if !receipt.Valid() || receipt.OperationID != record.CredentialPutID {
		return false
	}
	return record.NewCredentialRef == "" || receipt.Ref == record.NewCredentialRef
}

func (s *Service) saveCreatedProfile(ctx context.Context, record SagaRecord, item profile.DeviceProfile) (Result, error) {
	record.Phase = PhaseProfileSwitched
	saved, err := s.journal.Save(ctx, record)
	if err != nil {
		result, operationErr := stoppedResult(record.OperationID, record.Operation, PhaseCredentialStored, StatusRecoverable, err)
		summary := item.BusinessSummary()
		result.Summary = &summary
		return result, operationErr
	}
	return s.resumeCreate(ctx, saved, nil)
}

func (s *Service) acknowledgeCommittedPut(ctx context.Context, record *SagaRecord) error {
	err := s.credentials.AcknowledgePut(ctx, record.CredentialPutID)
	if !errors.Is(err, credential.ErrOutcomeUnknown) {
		return err
	}
	receipt, recoverErr := s.credentials.RecoverPut(ctx, record.CredentialPutID)
	if recoverErr != nil || !putReceiptMatches(*record, receipt) || receipt.Phase != credential.PutCommitted {
		return errors.Join(err, recoverErr, ErrOperationConflict)
	}
	if record.CredentialPutPhase != receipt.Phase {
		record.CredentialPutPhase = receipt.Phase
		saved, saveErr := s.journal.Save(ctx, *record)
		if saveErr != nil {
			return errors.Join(err, saveErr)
		}
		*record = saved
	}
	return s.credentials.AcknowledgePut(ctx, record.CredentialPutID)
}

func (s *Service) resumeChange(ctx context.Context, access Access, record SagaRecord, suppliedSecret []byte) (Result, error) {
	for {
		switch record.Phase {
		case PhaseCompleted:
			item, err := s.loadBoundProfile(ctx, access, record.ProfileID)
			if err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, err)
			}
			return completedResult(record, &item), nil
		case PhaseFailed:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusFailed, ErrOperationConflict)
		case PhaseOutcomeUnknown:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrOutcomeUnknown)
		case PhasePrepared:
			current, err := s.loadBoundProfile(ctx, access, record.ProfileID)
			if err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
			}
			if err := requireStableIdentity(current, record.PinnedSerial, record.PinnedType); err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusBlocked, err)
			}
			if record.NewCredentialRef.Valid() && current.CredentialRef == record.NewCredentialRef && current.CredentialState == profile.CredentialReady {
				record.ExpectedGeneration = current.Generation
				record.Phase = PhaseProfileSwitched
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, PhasePrepared, StatusRecoverable, saveErr)
				}
				record = saved
				continue
			}
			if current.CredentialRef != record.OldCredentialRef {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, ErrOperationConflict)
			}
			switch current.CredentialState {
			case profile.CredentialReady:
				if current.Generation != record.ExpectedGeneration {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, profile.ErrConflict)
				}
				current, err = s.profiles.SetCredentialState(ctx, record.TenantID, record.SiteID, record.ProfileID, current.Generation, profile.CredentialRotating)
				if err != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
				}
			case profile.CredentialRotating:
			default:
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusBlocked, ErrOperationConflict)
			}
			record.ExpectedGeneration = current.Generation
			record.Phase = PhaseProfileRotating
			saved, saveErr := s.journal.Save(ctx, record)
			if saveErr != nil {
				return stoppedResult(record.OperationID, record.Operation, PhasePrepared, StatusRecoverable, saveErr)
			}
			record = saved
		case PhaseProfileRotating:
			current, err := s.loadBoundProfile(ctx, access, record.ProfileID)
			if err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
			}
			if current.CredentialRef == record.NewCredentialRef && current.CredentialState == profile.CredentialReady &&
				current.Endpoint == record.Endpoint && current.Username == record.Username {
				record.ExpectedGeneration = current.Generation
				record.Phase = PhaseProfileSwitched
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, PhaseProfileRotating, StatusRecoverable, saveErr)
				}
				record = saved
				continue
			}
			if err := requireStableIdentity(current, record.PinnedSerial, record.PinnedType); err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusBlocked, err)
			}
			if current.CredentialRef != record.OldCredentialRef {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, ErrOperationConflict)
			}
			if current.CredentialState == profile.CredentialReady {
				current, err = s.profiles.SetCredentialState(ctx, record.TenantID, record.SiteID, record.ProfileID, current.Generation, profile.CredentialRotating)
				if err != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
				}
				record.ExpectedGeneration = current.Generation
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, saveErr)
				}
				record = saved
				continue
			}
			if current.CredentialState != profile.CredentialRotating {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusBlocked, ErrOperationConflict)
			}
			receipt, rotationErr := s.findOrRotateCredential(ctx, record, suppliedSecret)
			if !receipt.Valid() {
				if errors.Is(rotationErr, credential.ErrOutcomeUnknown) {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, rotationErr)
				}
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, rotationErr)
			}
			if !rotationReceiptMatches(record, receipt) {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrOperationConflict)
			}
			record.CredentialRotationID = receipt.OperationID
			record.CredentialRotationPhase = receipt.Phase
			record.NewCredentialRef = receipt.NewRef
			record.Phase = PhaseCredentialStored
			saved, saveErr := s.journal.Save(ctx, record)
			if saveErr != nil {
				status := StatusRecoverable
				if receipt.Phase == credential.RotationUnknown || errors.Is(rotationErr, credential.ErrOutcomeUnknown) {
					status = StatusOutcomeUnknown
				}
				return stoppedResult(record.OperationID, record.Operation, PhaseProfileRotating, status, errors.Join(rotationErr, saveErr))
			}
			record = saved
		case PhaseCredentialStored:
			current, err := s.loadBoundProfile(ctx, access, record.ProfileID)
			if err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
			}
			if current.CredentialRef == record.NewCredentialRef && current.CredentialState == profile.CredentialReady &&
				current.Endpoint == record.Endpoint && current.Username == record.Username {
				record.ExpectedGeneration = current.Generation
				record.Phase = PhaseProfileSwitched
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, PhaseCredentialStored, StatusRecoverable, saveErr)
				}
				record = saved
				continue
			}
			if record.CredentialRotationPhase == credential.RotationRolledBack {
				return s.finishRolledBackRotation(ctx, access, record)
			}
			if record.CredentialRotationPhase != credential.RotationCommitted {
				receipt, recoverErr := s.credentials.RecoverRotation(ctx, record.CredentialRotationID)
				if !receipt.Valid() || !rotationReceiptMatches(record, receipt) {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, errors.Join(recoverErr, ErrOperationConflict))
				}
				record.CredentialRotationPhase = receipt.Phase
				saved, saveErr := s.journal.Save(ctx, record)
				if saveErr != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, errors.Join(recoverErr, saveErr))
				}
				record = saved
				switch receipt.Phase {
				case credential.RotationCommitted:
					// Continue below and switch the profile to the durable new ref.
				case credential.RotationRolledBack:
					return s.finishRolledBackRotation(ctx, access, record)
				default:
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(recoverErr, credential.ErrOutcomeUnknown))
				}
			}
			if err := requireStableIdentity(current, record.PinnedSerial, record.PinnedType); err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusBlocked, err)
			}
			if current.CredentialRef != record.OldCredentialRef || current.CredentialState != profile.CredentialRotating || current.Generation != record.ExpectedGeneration {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, ErrOperationConflict)
			}
			next, updateErr := s.profiles.Update(ctx, updateProfile(current, record))
			if updateErr != nil {
				reconciled, getErr := s.loadBoundProfile(ctx, access, record.ProfileID)
				if getErr != nil || reconciled.CredentialRef != record.NewCredentialRef || reconciled.CredentialState != profile.CredentialReady {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, errors.Join(updateErr, getErr))
				}
				next = reconciled
			}
			record.ExpectedGeneration = next.Generation
			record.Phase = PhaseProfileSwitched
			saved, saveErr := s.journal.Save(ctx, record)
			if saveErr != nil {
				return stoppedResult(record.OperationID, record.Operation, PhaseCredentialStored, StatusRecoverable, saveErr)
			}
			record = saved
		case PhaseProfileSwitched:
			item, err := s.loadBoundProfile(ctx, access, record.ProfileID)
			if err != nil || item.CredentialRef != record.NewCredentialRef || item.CredentialState != profile.CredentialReady ||
				item.Endpoint != record.Endpoint || item.Username != record.Username {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(err, ErrOperationConflict))
			}
			ackErr := s.credentials.AcknowledgeRotation(ctx, record.CredentialRotationID)
			if errors.Is(ackErr, credential.ErrOutcomeUnknown) {
				receipt, recoverErr := s.credentials.RecoverRotation(ctx, record.CredentialRotationID)
				if recoverErr != nil || !rotationReceiptMatches(record, receipt) || receipt.Phase != credential.RotationCommitted {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, errors.Join(ackErr, recoverErr, ErrOperationConflict))
				}
				if record.CredentialRotationPhase != receipt.Phase {
					record.CredentialRotationPhase = receipt.Phase
					saved, saveErr := s.journal.Save(ctx, record)
					if saveErr != nil {
						return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, errors.Join(ackErr, saveErr))
					}
					record = saved
				}
				ackErr = s.credentials.AcknowledgeRotation(ctx, record.CredentialRotationID)
			}
			if ackErr != nil {
				status := StatusRecoverable
				if errors.Is(ackErr, credential.ErrOutcomeUnknown) {
					status = StatusOutcomeUnknown
				}
				return stoppedResult(record.OperationID, record.Operation, record.Phase, status, ackErr)
			}
			return s.finish(ctx, record, &item)
		default:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrInvalidSaga)
		}
	}
}

func (s *Service) findOrRotateCredential(ctx context.Context, record SagaRecord, suppliedSecret []byte) (credential.RotationReceipt, error) {
	receipt, err := s.credentials.RotationByOldRef(ctx, record.OldCredentialRef)
	if err == nil || !errors.Is(err, credential.ErrNotFound) {
		return receipt, err
	}
	if record.Operation == OperationUpdateEndpoint {
		secret, getErr := s.credentials.Get(ctx, record.OldCredentialRef)
		if getErr != nil {
			return credential.RotationReceipt{}, getErr
		}
		defer clearBytes(secret)
		return s.credentials.Rotate(ctx, record.OldCredentialRef, secret)
	}
	if len(suppliedSecret) == 0 {
		return credential.RotationReceipt{}, ErrInvalidInput
	}
	return s.credentials.Rotate(ctx, record.OldCredentialRef, suppliedSecret)
}

func rotationReceiptMatches(record SagaRecord, receipt credential.RotationReceipt) bool {
	if !receipt.Valid() || receipt.OldRef != record.OldCredentialRef {
		return false
	}
	if record.CredentialRotationID != "" && receipt.OperationID != record.CredentialRotationID {
		return false
	}
	return record.NewCredentialRef == "" || receipt.NewRef == record.NewCredentialRef
}

func (s *Service) finishRolledBackRotation(ctx context.Context, access Access, record SagaRecord) (Result, error) {
	current, err := s.loadBoundProfile(ctx, access, record.ProfileID)
	if err != nil || current.CredentialRef != record.OldCredentialRef {
		return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(err, ErrOperationConflict))
	}
	if current.CredentialState == profile.CredentialRotating {
		current, err = s.profiles.SetCredentialState(ctx, record.TenantID, record.SiteID, record.ProfileID, current.Generation, profile.CredentialReady)
		if err != nil {
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
		}
	} else if current.CredentialState != profile.CredentialReady {
		return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrOperationConflict)
	}
	if err := s.credentials.AcknowledgeRotation(ctx, record.CredentialRotationID); err != nil {
		status := StatusRecoverable
		if errors.Is(err, credential.ErrOutcomeUnknown) {
			status = StatusOutcomeUnknown
		}
		return stoppedResult(record.OperationID, record.Operation, record.Phase, status, err)
	}
	record.ExpectedGeneration = current.Generation
	record.Phase = PhaseFailed
	if _, err := s.journal.Save(ctx, record); err != nil {
		return stoppedResult(record.OperationID, record.Operation, PhaseCredentialStored, StatusRecoverable, err)
	}
	return stoppedResult(record.OperationID, record.Operation, PhaseFailed, StatusFailed, ErrOperationConflict)
}

func (s *Service) resumeForget(ctx context.Context, access Access, record SagaRecord) (Result, error) {
	for {
		switch record.Phase {
		case PhaseCompleted:
			if _, err := s.profiles.Get(ctx, record.TenantID, record.SiteID, record.ProfileID); !errors.Is(err, profile.ErrNotFound) {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, firstNonNil(err, ErrOperationConflict))
			}
			return completedResult(record, nil), nil
		case PhaseFailed:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusFailed, ErrOperationConflict)
		case PhaseOutcomeUnknown:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrOutcomeUnknown)
		case PhasePrepared:
			current, err := s.profiles.Get(ctx, record.TenantID, record.SiteID, record.ProfileID)
			if errors.Is(err, profile.ErrNotFound) {
				return s.finish(ctx, record, nil)
			}
			if err != nil || current.SiteID != access.SiteID || current.CredentialRef != record.OldCredentialRef {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, firstNonNil(err, ErrBindingMismatch))
			}
			switch current.CredentialState {
			case profile.CredentialRevoked:
				record.ExpectedGeneration = current.Generation
				record.Phase = PhaseProfileRevoked
			case profile.CredentialRevoking:
				record.ExpectedGeneration = current.Generation
				record.Phase = PhaseProfileRevoking
			default:
				if current.Generation != record.ExpectedGeneration {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, profile.ErrConflict)
				}
				current, err = s.profiles.SetCredentialState(ctx, record.TenantID, record.SiteID, record.ProfileID, current.Generation, profile.CredentialRevoking)
				if err != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
				}
				record.ExpectedGeneration = current.Generation
				record.Phase = PhaseProfileRevoking
			}
			saved, saveErr := s.journal.Save(ctx, record)
			if saveErr != nil {
				return stoppedResult(record.OperationID, record.Operation, PhasePrepared, StatusRecoverable, saveErr)
			}
			record = saved
		case PhaseProfileRevoking:
			if err := s.credentials.Delete(ctx, record.OldCredentialRef); err != nil {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
			}
			record.Phase = PhaseCredentialDeleted
			saved, saveErr := s.journal.Save(ctx, record)
			if saveErr != nil {
				return stoppedResult(record.OperationID, record.Operation, PhaseProfileRevoking, StatusRecoverable, saveErr)
			}
			record = saved
		case PhaseCredentialDeleted:
			current, err := s.profiles.Get(ctx, record.TenantID, record.SiteID, record.ProfileID)
			if errors.Is(err, profile.ErrNotFound) {
				return s.finish(ctx, record, nil)
			}
			if err != nil || current.SiteID != access.SiteID || current.CredentialRef != record.OldCredentialRef {
				return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, firstNonNil(err, ErrBindingMismatch))
			}
			if current.CredentialState != profile.CredentialRevoked {
				if current.CredentialState != profile.CredentialRevoking {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, ErrOperationConflict)
				}
				current, err = s.profiles.SetCredentialState(ctx, record.TenantID, record.SiteID, record.ProfileID, current.Generation, profile.CredentialRevoked)
				if err != nil {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, err)
				}
			}
			record.ExpectedGeneration = current.Generation
			record.Phase = PhaseProfileRevoked
			saved, saveErr := s.journal.Save(ctx, record)
			if saveErr != nil {
				return stoppedResult(record.OperationID, record.Operation, PhaseCredentialDeleted, StatusRecoverable, saveErr)
			}
			record = saved
		case PhaseProfileRevoked:
			err := s.profiles.Forget(ctx, record.TenantID, record.SiteID, record.ProfileID, record.ExpectedGeneration)
			if err != nil {
				if _, getErr := s.profiles.Get(ctx, record.TenantID, record.SiteID, record.ProfileID); !errors.Is(getErr, profile.ErrNotFound) {
					return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusRecoverable, errors.Join(err, getErr))
				}
			}
			return s.finish(ctx, record, nil)
		default:
			return stoppedResult(record.OperationID, record.Operation, record.Phase, StatusOutcomeUnknown, ErrInvalidSaga)
		}
	}
}

func (s *Service) finish(ctx context.Context, record SagaRecord, item *profile.DeviceProfile) (Result, error) {
	previousPhase := record.Phase
	record.Phase = PhaseCompleted
	saved, err := s.journal.Save(ctx, record)
	if err != nil {
		result, operationErr := stoppedResult(record.OperationID, record.Operation, previousPhase, StatusRecoverable, err)
		if item != nil {
			summary := item.BusinessSummary()
			result.Summary = &summary
		}
		return result, operationErr
	}
	return completedResult(saved, item), nil
}

func (s *Service) begin(ctx context.Context, record SagaRecord) (SagaRecord, error) {
	record.CreatedAt = s.now().UTC()
	created, err := s.journal.Begin(ctx, record)
	if !errors.Is(err, ErrSagaConflict) {
		return created, err
	}
	existing, getErr := s.journal.Get(ctx, record.OperationID)
	if getErr != nil {
		return SagaRecord{}, errors.Join(err, getErr)
	}
	if existing.TenantID != record.TenantID || existing.SiteID != record.SiteID || existing.PrincipalSHA256 != record.PrincipalSHA256 || existing.Operation != record.Operation {
		return SagaRecord{}, ErrOperationConflict
	}
	return existing, nil
}

func (s *Service) verify(access Access, profileID string, operations ...string) error {
	for _, operation := range operations {
		demand := authority.Demand{
			Class: authority.ConnectionProfileWrite, OperationKind: operation,
			PrincipalSHA256: access.PrincipalSHA256, TenantID: access.TenantID, SiteID: access.SiteID,
		}
		if operation != authority.OpProfileCreate {
			demand.DeviceProfileID = strings.TrimSpace(profileID)
		}
		if err := s.authority.Verify(access.Grant, demand, s.now().UTC()); err != nil {
			return errors.Join(ErrAuthorityDenied, err)
		}
	}
	return nil
}

func (s *Service) verifyForRecord(access Access, record SagaRecord) error {
	switch record.Operation {
	case OperationCreate:
		return s.verify(access, "", authority.OpProfileCreate)
	case OperationUpdateEndpoint, OperationRotateCredential:
		return s.verify(access, record.ProfileID, authority.OpCredentialRotate, authority.OpProfileUpdate)
	case OperationForget:
		return s.verify(access, record.ProfileID, authority.OpProfileForget)
	default:
		return ErrInvalidSaga
	}
}

func (s *Service) loadBoundProfile(ctx context.Context, access Access, profileID string) (profile.DeviceProfile, error) {
	item, err := s.profiles.Get(ctx, strings.TrimSpace(access.TenantID), strings.TrimSpace(access.SiteID), strings.TrimSpace(profileID))
	if err != nil {
		return profile.DeviceProfile{}, err
	}
	if item.TenantID != access.TenantID || item.SiteID != access.SiteID {
		return profile.DeviceProfile{}, ErrBindingMismatch
	}
	return item, nil
}

func (s *Service) prepareCreateProfile(request CreateRequest, profileID string) (profile.DeviceProfile, error) {
	endpoint, err := profile.NormalizeEndpoint(request.Endpoint)
	if err != nil {
		return profile.DeviceProfile{}, errors.Join(ErrInvalidInput, err)
	}
	username := strings.TrimSpace(request.Username)
	fingerprint, err := profile.ComputeTransportFingerprint(endpoint, username)
	if err != nil {
		return profile.DeviceProfile{}, errors.Join(ErrInvalidInput, err)
	}
	placeholder, _ := credential.ParseRef("cred_" + strings.Repeat("0", 64))
	now := s.now().UTC()
	item := profile.DeviceProfile{
		ProfileID: profileID, TenantID: strings.TrimSpace(request.Access.TenantID), SiteID: strings.TrimSpace(request.Access.SiteID),
		Alias: strings.TrimSpace(request.Alias), Endpoint: endpoint, Username: username, CredentialRef: placeholder,
		PinnedSerial: strings.TrimSpace(request.PinnedSerial), PinnedType: strings.TrimSpace(request.PinnedType),
		TransportFingerprint: fingerprint, Generation: 1, State: profile.StateActive, CredentialState: profile.CredentialReady,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := item.Validate(); err != nil {
		return profile.DeviceProfile{}, errors.Join(ErrInvalidInput, err)
	}
	return item, nil
}

func desiredTransport(current profile.DeviceProfile, endpoint, username string) (profile.DeviceProfile, error) {
	endpoint, err := profile.NormalizeEndpoint(endpoint)
	if err != nil {
		return profile.DeviceProfile{}, errors.Join(ErrInvalidInput, err)
	}
	username = strings.TrimSpace(username)
	fingerprint, err := profile.ComputeTransportFingerprint(endpoint, username)
	if err != nil {
		return profile.DeviceProfile{}, errors.Join(ErrInvalidInput, err)
	}
	desired := current
	desired.Endpoint = endpoint
	desired.Username = username
	desired.TransportFingerprint = fingerprint
	if err := desired.Validate(); err != nil {
		return profile.DeviceProfile{}, errors.Join(ErrInvalidInput, err)
	}
	return desired, nil
}

func changeRecord(operationID string, operation Operation, access Access, current profile.DeviceProfile, endpoint, username, fingerprint string) SagaRecord {
	return SagaRecord{
		Schema: SagaSchemaVersion, OperationID: operationID, Operation: operation, Phase: PhasePrepared,
		TenantID: current.TenantID, SiteID: current.SiteID, PrincipalSHA256: access.PrincipalSHA256,
		ProfileID: current.ProfileID, ExpectedGeneration: current.Generation,
		Alias: current.Alias, Endpoint: endpoint, Username: username,
		PinnedSerial: current.PinnedSerial, PinnedType: current.PinnedType, TransportFingerprint: fingerprint,
		OldCredentialRef: current.CredentialRef,
	}
}

func updateProfile(current profile.DeviceProfile, record SagaRecord) profile.UpdateDeviceProfile {
	return profile.UpdateDeviceProfile{
		ProfileID: current.ProfileID, ExpectedGeneration: current.Generation,
		TenantID: current.TenantID, SiteID: current.SiteID, Alias: record.Alias,
		Endpoint: record.Endpoint, Username: record.Username, CredentialRef: record.NewCredentialRef,
		PinnedSerial: record.PinnedSerial, PinnedType: record.PinnedType, TransportFingerprint: record.TransportFingerprint,
		State: current.State, CredentialState: profile.CredentialReady,
	}
}

func requireStableIdentity(current profile.DeviceProfile, serial, deviceType string) error {
	if current.State == profile.StateIdentityDrift || current.PinnedSerial != serial || current.PinnedType != deviceType {
		return ErrIdentityDrift
	}
	if current.State != profile.StateActive {
		return ErrOperationConflict
	}
	return nil
}

func sameCreateIntent(record SagaRecord, item profile.DeviceProfile) bool {
	return record.Operation == OperationCreate && record.ProfileID == item.ProfileID && record.TenantID == item.TenantID &&
		record.SiteID == item.SiteID && record.Alias == item.Alias && record.Endpoint == item.Endpoint && record.Username == item.Username &&
		record.PinnedSerial == item.PinnedSerial && record.PinnedType == item.PinnedType && record.TransportFingerprint == item.TransportFingerprint
}

func sameChangeIntent(record SagaRecord, operation Operation, profileID, endpoint, username string) bool {
	return record.Operation == operation && record.ProfileID == strings.TrimSpace(profileID) && record.Endpoint == endpoint && record.Username == username
}

func profileMatchesCreate(item profile.DeviceProfile, record SagaRecord) bool {
	return item.ProfileID == record.ProfileID && item.TenantID == record.TenantID && item.SiteID == record.SiteID &&
		item.Alias == record.Alias && item.Endpoint == record.Endpoint && item.Username == record.Username &&
		item.CredentialRef == record.NewCredentialRef && item.PinnedSerial == record.PinnedSerial && item.PinnedType == record.PinnedType &&
		item.TransportFingerprint == record.TransportFingerprint
}

func ensureOperationID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return NewOperationID()
	}
	if !operationIDPattern.MatchString(value) {
		return "", ErrInvalidInput
	}
	return value, nil
}

func stoppedResult(operationID string, operation Operation, phase Phase, status Status, cause error) (Result, error) {
	if cause == nil {
		cause = ErrOperationConflict
	}
	switch status {
	case StatusRecoverable:
		cause = errors.Join(ErrRecoveryRequired, cause)
	case StatusOutcomeUnknown:
		cause = errors.Join(ErrOutcomeUnknown, cause)
	case StatusBlocked:
		cause = errors.Join(ErrIdentityDrift, cause)
	}
	result := Result{OperationID: operationID, Operation: operation, Status: status, Phase: phase}
	return result, &OperationError{OperationID: operationID, Operation: operation, Status: status, Phase: phase, cause: cause}
}

func completedResult(record SagaRecord, item *profile.DeviceProfile) Result {
	result := Result{OperationID: record.OperationID, Operation: record.Operation, Status: StatusCompleted, Phase: PhaseCompleted}
	if item != nil {
		summary := item.BusinessSummary()
		result.Summary = &summary
	}
	return result
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func firstNonNil(value, fallback error) error {
	if value != nil {
		return value
	}
	return fallback
}

var _ ProfileStore = (*profile.Store)(nil)
