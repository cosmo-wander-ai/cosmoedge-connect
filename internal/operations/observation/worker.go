package observation

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

// One worker serializes all acquisition, analysis and cleanup device calls.
func (s *Service) worker(ctx context.Context, r *resources, done chan struct{}, wake <-chan struct{}) {
	defer close(done)
	timer := time.NewTimer(0)
	defer timer.Stop()
	lastGC := time.Time{}
	lastCleanup := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-wake:
		}
		if err := s.cycle(ctx, r, &lastGC, &lastCleanup); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.mu.Lock()
			s.workerErr = err
			s.mu.Unlock()
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(s.config.WorkerInterval)
	}
}
func (s *Service) cycle(ctx context.Context, r *resources, lastGC, lastCleanup *time.Time) error {
	now := s.config.Now().UTC()
	if lastCleanup.IsZero() || now.Sub(*lastCleanup) >= 30*time.Second {
		epoch, _ := livevision.CurrentTemporaryConnectionEpoch(s.config.Vault)
		tasks, err := r.journal.pending(ctx, epoch)
		if err != nil {
			return err
		}
		for _, task := range tasks {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			_ = livevision.CancelRecordedTemporaryTask(ctx, s.config.Vault, task, r.journal)
			if err := r.journal.diagnosticFailure(); err != nil {
				return err
			}
		}
		uploads, err := r.journal.pendingUploads(ctx, epoch)
		if err != nil {
			return err
		}
		for _, upload := range uploads {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			_ = livevision.CancelRecordedTemporaryUpload(ctx, s.config.Vault, upload, r.journal)
			if err := r.journal.diagnosticFailure(); err != nil {
				return err
			}
		}
		*lastCleanup = now
	}
	values, err := r.operations.pending(ctx)
	if err != nil {
		return err
	}
	for _, value := range values {
		if value.Stage == "accepted" {
			if !now.Before(value.DeadlineAt) {
				value.Stage = "terminal"
				value.Failure = "expired"
				if err := r.operations.update(ctx, value); err != nil {
					return err
				}
				continue
			}
			if err := ensureSubmitted(ctx, r, value); err != nil {
				return err
			}
		}
	}
	if _, _, err := r.preparations.ProcessNext(ctx); err != nil && !persistedPreparationError(err) {
		return err
	}
	if _, _, err := r.runner.RunOnce(ctx, "observation-worker", s.config.RunTimeout); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !errors.Is(err, temporary.ErrDependencyFatal) && !errors.Is(err, temporary.ErrDependencyRetryable) && !errors.Is(err, temporary.ErrRuntimeLeaseLost) {
			return err
		}
	}
	values, err = r.operations.pending(ctx)
	if err != nil {
		return err
	}
	for _, value := range values {
		if value.Stage != "submitted" {
			continue
		}
		if value.Request.Mode == CaptureOnly {
			status, pending, mediaRef, err := captureProgress(ctx, r, value, s.config.Now().UTC())
			if err != nil {
				return err
			}
			if !pending {
				value.Stage = "terminal"
				if status != "captured" {
					value.Failure = status
				}
				if mediaRef != "" {
					descriptor, err := r.media.Describe(mediaRef)
					if err == nil {
						if descriptor.Validate() != nil || !matchesMedia(value, descriptor) {
							return ErrUnavailable
						}
						value.CaptureMedia = &descriptor
					}
				}
				if err := r.operations.update(ctx, value); err != nil {
					return err
				}
				r.acquirer.forget(value.PreparationRef)
			}
			continue
		}
		record, err := r.runner.Get(ctx, value.RunID)
		if err != nil {
			return err
		}
		if record.State.Terminal() {
			value.Stage = "terminal"
			if err := r.operations.update(ctx, value); err != nil {
				return err
			}
			r.acquirer.forget(value.PreparationRef)
		}
	}
	// Managers first commit their existing non-replayable terminal, then the
	// worker reports diagnostic storage failure instead of dispatching again.
	if err := r.journal.diagnosticFailure(); err != nil {
		return err
	}
	if lastGC.IsZero() || now.Sub(*lastGC) >= time.Minute {
		if _, err := r.media.GC(ctx); err != nil {
			return err
		}
		*lastGC = now
	}
	return nil
}
func persistedPreparationError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, mediaprep.ErrOutcomeUnknown) || errors.Is(err, mediaprep.ErrPublicationUnknown) || errors.Is(err, mediaprep.ErrPublicationRejected) || errors.Is(err, mediaprep.ErrAcquirerContract) || errors.Is(err, mediaprep.ErrLeaseLost)
}

func channelBinding(value operation) temporary.AuthenticatedBinding {
	return temporary.AuthenticatedBinding{TenantID: livevision.TenantID, SiteID: livevision.SiteID, RequestKey: value.RequestKey, PublicRunRef: value.Ref, Channel: "desktop_conversation", ConversationRef: "conversation_" + value.OwnerHash[:32], RecipientRef: "owner_" + value.OwnerHash[:32], PrincipalSHA256: value.OwnerHash}
}
func audienceFor(value operation) (temporary.AudienceBinding, error) {
	binding := channelBinding(value)
	return temporary.FreezeAudience(temporary.ChannelSession{TenantID: binding.TenantID, SiteID: binding.SiteID, Channel: binding.Channel, ConversationRef: binding.ConversationRef, RecipientRef: binding.RecipientRef, PrincipalSHA256: binding.PrincipalSHA256})
}
func ensureSubmitted(ctx context.Context, r *resources, value operation) error {
	audience, err := audienceFor(value)
	if err != nil {
		return err
	}
	step, err := temporary.MediaStepIDForRun(value.RunID)
	if err != nil {
		return err
	}
	frozen := mediaprep.FrozenRequest{
		Schema: mediaprep.RequestSchema, TenantID: livevision.TenantID, SiteID: livevision.SiteID, RequestID: value.RequestKey,
		SourceRef: value.Source.SourceRef, CapabilityRef: livevision.SnapshotCapability,
		TimeScope:          mediaprep.TimeScope{WindowStart: value.CreatedAt, WindowEnd: value.CreatedAt},
		AudienceBindingRef: audience.Ref, AudienceSHA256: audience.SHA256, EvidenceExpiresAt: value.ExpiresAt,
		Media: mediaprep.MediaSpec{Kind: media.KindImage, RunID: value.RunID, StepID: step, Attempt: 1, PrivacyClass: "internal", RetentionPolicyRef: "observation-chat-retention"},
	}
	status, _, err := r.preparations.Prepare(ctx, frozen)
	if err != nil {
		return err
	}
	if status.PreparationRef != value.PreparationRef {
		return ErrUnavailable
	}
	if value.Request.Mode != CaptureOnly {
		_, _, err = r.runner.Submit(ctx, temporary.Submission{
			Binding: channelBinding(value), Spec: value.Spec, PreparationRef: value.PreparationRef, MediaKind: media.KindImage,
			AudienceBindingRef: audience.Ref, AudienceSHA256: audience.SHA256, EvidenceExpiresAt: value.ExpiresAt,
			SubmittedAt: value.CreatedAt, DeadlineAt: value.DeadlineAt,
		})
		if err != nil {
			return err
		}
	}
	value.Stage = "submitted"
	return r.operations.update(ctx, value)
}

type sourceAcquirer struct {
	vault   *session.Vault
	store   *operationStore
	journal *taskJournal
	now     func() time.Time
	mu      sync.Mutex
	cache   map[string]mediaprep.Acquirer
}

func (a *sourceAcquirer) Acquire(ctx context.Context, request mediaprep.AcquisitionRequest) (mediaprep.AcquisitionResult, error) {
	value, err := a.store.byPreparation(ctx, request.PreparationRef)
	if err != nil {
		return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionFailed, FailureCode: "source-binding-unavailable"}, nil
	}
	audience, audienceErr := audienceFor(value)
	if err != nil || audienceErr != nil || value.Source.DeviceIdentitySHA256 == "" || value.Source.ConnectionEpoch == "" || request.SourceRef != value.Source.SourceRef || request.AudienceSHA256 != audience.SHA256 || !a.now().Before(value.DeadlineAt) || value.Stage == "terminal" {
		_ = a.journal.RecordFailure(ctx, value.RunID, safediagnostic.Diagnostic{Operation: safediagnostic.OperationCameraPicture, Phase: safediagnostic.PhaseSourceBinding, Class: safediagnostic.ClassLocalContractRejected, ValidationCode: safediagnostic.ValidationBindingInvalid})
		return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionFailed, FailureCode: "source-binding-unavailable"}, nil
	}
	a.mu.Lock()
	cached := a.cache[request.PreparationRef]
	a.mu.Unlock()
	if cached == nil {
		connection, err := livevision.NewVaultConnectionsForSource(a.vault, value.Source, livevision.WithTemporaryDiagnostics(value.RunID, a.journal))
		if err != nil {
			_ = a.journal.RecordFailure(ctx, value.RunID, safediagnostic.Diagnostic{Operation: safediagnostic.OperationCameraPicture, Phase: safediagnostic.PhaseSourceBinding, Class: safediagnostic.ClassLocalContractRejected, ValidationCode: safediagnostic.ValidationBindingInvalid})
			return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionFailed, FailureCode: "source-binding-unavailable"}, nil
		}
		cached = livevision.NewTemporaryAcquirer(connection)
		a.mu.Lock()
		a.cache[request.PreparationRef] = cached
		a.mu.Unlock()
	}
	return cached.Acquire(ctx, request)
}
func (a *sourceAcquirer) Reconcile(ctx context.Context, request mediaprep.ReconciliationRequest) (mediaprep.AcquisitionResult, error) {
	a.mu.Lock()
	cached := a.cache[request.PreparationRef]
	a.mu.Unlock()
	if cached == nil {
		return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionFailed, FailureCode: "snapshot-not-recoverable"}, nil
	}
	return cached.Reconcile(ctx, request)
}
func (a *sourceAcquirer) forget(ref string) { a.mu.Lock(); delete(a.cache, ref); a.mu.Unlock() }

type deadlineAnalyzer struct {
	vault   *session.Vault
	journal *taskJournal
	store   *operationStore
}

func (a deadlineAnalyzer) Analyze(ctx context.Context, request temporary.AnalysisRequest) (candidate []byte, analysisErr error) {
	defer func() {
		if analysisErr == nil || errors.Is(analysisErr, livevision.ErrDiagnosticPersistence) {
			return
		}
		diagnostic := safediagnostic.FromError(analysisErr)
		if diagnostic == nil {
			diagnostic = &safediagnostic.Diagnostic{Operation: safediagnostic.OperationAnalysis, Phase: safediagnostic.PhaseSourceBinding, Class: safediagnostic.ClassLocalContractRejected, ValidationCode: safediagnostic.ValidationBindingInvalid}
		}
		if err := a.journal.RecordFailure(ctx, request.RunID, *diagnostic); err != nil {
			analysisErr = errors.Join(analysisErr, livevision.ErrDiagnosticPersistence)
		}
	}()
	value, err := a.store.byRun(ctx, request.RunID)
	if err != nil {
		return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, err)
	}
	if value.Request.Mode == CaptureOnly || value.Source.DeviceIdentitySHA256 == "" || value.Source.ConnectionEpoch == "" {
		return nil, temporary.ErrAnalysisDefinitelyFailed
	}
	connections, err := livevision.NewVaultConnectionsForSource(a.vault, value.Source, livevision.WithTemporaryTaskJournal(a.journal), livevision.WithTemporaryUploadJournal(value.OwnerHash, a.journal), livevision.WithTemporaryDiagnostics(value.RunID, a.journal))
	if err != nil {
		return nil, temporary.ErrAnalysisDefinitelyFailed
	}
	bounded, cancel := context.WithDeadline(ctx, value.DeadlineAt)
	defer cancel()
	return livevision.NewTemporaryAnalyzer(connections).Analyze(bounded, request)
}
