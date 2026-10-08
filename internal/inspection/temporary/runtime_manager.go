package temporary

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	inspectionmedia "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
)

type Clock func() time.Time

var (
	// ErrDependencyRetryable is the only dependency error that may be
	// durably rescheduled without surfacing an error to Product. Adapters must
	// wrap it explicitly; unclassified I/O is fail-closed.
	ErrDependencyRetryable = errors.New("temporary observation dependency is retryable")
	// ErrDependencyFatal is the bounded Product-facing error for dependency
	// corruption, invalid data, definitive absence, and unclassified I/O.
	ErrDependencyFatal = errors.New("temporary observation dependency failed")
)

type Manager struct {
	store        *SQLiteStore
	preparations PreparationReader
	media        MediaReader
	analyzer     Analyzer
	clock        Clock
}

func NewManager(store *SQLiteStore, preparations PreparationReader, media MediaReader, analyzer Analyzer, clock Clock) (*Manager, error) {
	if store == nil || store.db == nil || preparations == nil || media == nil || analyzer == nil {
		return nil, ErrRuntimeInvalid
	}
	if clock == nil {
		clock = time.Now
	}
	return &Manager{store: store, preparations: preparations, media: media, analyzer: analyzer, clock: clock}, nil
}

func (m *Manager) Submit(ctx context.Context, submission Submission) (Record, bool, error) {
	if m == nil {
		return Record{}, false, ErrRuntimeInvalid
	}
	now, err := m.now()
	if err != nil {
		return Record{}, false, err
	}
	return m.store.Submit(ctx, submission, now)
}

func (m *Manager) Get(ctx context.Context, runID string) (Record, error) {
	if m == nil {
		return Record{}, ErrRuntimeInvalid
	}
	return m.store.Get(ctx, runID)
}

func (m *Manager) Recover(ctx context.Context) (int, error) {
	if m == nil {
		return 0, ErrRuntimeInvalid
	}
	now, err := m.now()
	if err != nil {
		return 0, err
	}
	return m.store.Recover(ctx, now)
}

// RunOnce performs at most one bounded preparation poll or observation. A
// pending preparation is durably rescheduled without consuming Attempt. The
// only non-replayable boundary is BeginAnalysis; interruption after it becomes
// outcome_unknown.
func (m *Manager) RunOnce(ctx context.Context, owner string, leaseTTL time.Duration) (Record, bool, error) {
	if m == nil {
		return Record{}, false, ErrRuntimeInvalid
	}
	now, err := m.now()
	if err != nil {
		return Record{}, false, err
	}
	if _, err := m.store.Recover(ctx, now); err != nil {
		return Record{}, false, err
	}
	record, lease, claimed, err := m.store.Claim(ctx, owner, now, leaseTTL)
	if err != nil || !claimed {
		return Record{}, claimed, err
	}
	status, statusErr := m.preparations.Get(ctx, record.PreparationRef)
	at, clockErr := m.now()
	if clockErr != nil {
		return Record{}, true, clockErr
	}
	if authoritative, crossed, boundaryErr := m.recoverIfLeaseBoundary(ctx, record, lease, at); crossed {
		return authoritative, true, boundaryErr
	}
	if statusErr != nil {
		if ctx.Err() != nil {
			pending, _, releaseErr := m.releaseDependencyRetry(context.WithoutCancel(ctx), record, lease, at, time.Time{})
			if releaseErr != nil {
				return Record{}, true, releaseErr
			}
			return pending, true, ctx.Err()
		}
		if !errors.Is(statusErr, ErrDependencyRetryable) {
			return m.returnDependencyFatal(ctx, record.RunID)
		}
		return m.releaseDependencyRetry(ctx, record, lease, at, time.Time{})
	}
	if err := validatePreparationStatus(status, record.PreparationRef); err != nil {
		return m.returnDependencyFatal(ctx, record.RunID)
	}
	if !at.Before(record.EvidenceExpiresAt) {
		terminal, finishErr := m.store.CompletePreparationTerminal(context.WithoutCancel(ctx), lease, StateExpired, ReasonPreparationExpired, at)
		if leaseMutationBoundaryError(finishErr) {
			return m.recoverAfterLeaseBoundary(ctx, record.RunID, at, finishErr)
		}
		return terminal, true, finishErr
	}
	switch status.State {
	case mediaprep.StatePrepared, mediaprep.StateAcquiringUnknown, mediaprep.StatePublicationUnknown:
		return m.releaseDependencyRetry(ctx, record, lease, at, status.AvailableAt)
	case mediaprep.StateFailed:
		state, reason := StateFailed, ReasonPreparationFailed
		if status.Reason == mediaprep.ReasonEvidenceExpired {
			state, reason = StateExpired, ReasonPreparationExpired
		}
		terminal, finishErr := m.store.CompletePreparationTerminal(context.WithoutCancel(ctx), lease, state, reason, at)
		if leaseMutationBoundaryError(finishErr) {
			return m.recoverAfterLeaseBoundary(ctx, record.RunID, at, finishErr)
		}
		return terminal, true, finishErr
	case mediaprep.StateReady:
	default:
		return m.returnDependencyFatal(ctx, record.RunID)
	}
	prompt, err := CompilePrompt(record.Spec)
	if err != nil {
		terminal, finishErr := m.store.CompleteDefiniteFailure(context.WithoutCancel(ctx), lease, ReasonMediaInvalid, at)
		if leaseMutationBoundaryError(finishErr) {
			return m.recoverAfterLeaseBoundary(ctx, record.RunID, at, finishErr)
		}
		if finishErr != nil {
			return Record{}, true, finishErr
		}
		return terminal, true, err
	}
	descriptor, content, err := m.loadMedia(ctx, record, status.MediaRef)
	if err != nil {
		at, clockErr := m.now()
		if clockErr != nil {
			return Record{}, true, clockErr
		}
		if authoritative, crossed, boundaryErr := m.recoverIfLeaseBoundary(ctx, record, lease, at); crossed {
			return authoritative, true, boundaryErr
		}
		if ctx.Err() != nil {
			pending, _, releaseErr := m.releaseDependencyRetry(context.WithoutCancel(ctx), record, lease, at, status.AvailableAt)
			if releaseErr != nil {
				return Record{}, true, releaseErr
			}
			return pending, true, ctx.Err()
		}
		switch classifyMediaReadError(err) {
		case dependencyFatalUnavailable:
			return m.completeMediaReadFailure(ctx, record.RunID, lease, ReasonMediaUnavailable, at)
		case dependencyRetry:
			return m.releaseDependencyRetry(ctx, record, lease, at, status.AvailableAt)
		default:
			return m.returnDependencyFatal(ctx, record.RunID)
		}
	}
	defer zeroBytes(content)
	at, err = m.now()
	if err != nil {
		return Record{}, true, err
	}
	if authoritative, crossed, boundaryErr := m.recoverIfLeaseBoundary(ctx, record, lease, at); crossed {
		return authoritative, true, boundaryErr
	}
	if !descriptor.ExpiresAt.After(at) {
		return m.completeMediaFailure(ctx, record.RunID, lease, ReasonMediaUnavailable, at)
	}
	if _, err := m.store.BeginAnalysis(ctx, lease, descriptor, prompt.SHA256, at); err != nil {
		if errors.Is(err, ErrRuntimeLeaseLost) {
			return m.recoverAfterLeaseBoundary(ctx, record.RunID, at, err)
		}
		if errors.Is(err, ErrRuntimeInvalid) {
			return m.returnDependencyFatal(ctx, record.RunID)
		}
		return Record{}, true, err
	}
	rawCandidate, analyzeErr := m.analyzer.Analyze(ctx, AnalysisRequest{
		RunID: record.RunID, Prompt: prompt,
		Evidence: AnalysisEvidence{
			EvidenceRef: descriptor.MediaRef, SHA256: descriptor.SHA256, MIMEType: descriptor.MIMEType,
			CapturedAt: descriptor.Temporal.WindowEnd.UTC(), ExpiresAt: descriptor.ExpiresAt, Content: content,
		},
	})
	at, clockErr = m.now()
	if clockErr != nil {
		return Record{}, true, clockErr
	}
	if authoritative, crossed, boundaryErr := m.recoverIfLeaseBoundary(ctx, record, lease, at); crossed {
		return authoritative, true, boundaryErr
	}
	if analyzeErr != nil {
		var terminal Record
		if errors.Is(analyzeErr, ErrAnalysisDefinitelyFailed) {
			terminal, err = m.store.CompleteDefiniteFailure(context.WithoutCancel(ctx), lease, ReasonAnalysisDefinitelyFailed, at)
		} else {
			terminal, err = m.store.CompleteOutcomeUnknown(context.WithoutCancel(ctx), lease, at)
		}
		if errors.Is(err, ErrRuntimeLeaseLost) {
			_, recoverErr := m.store.Recover(context.WithoutCancel(ctx), at)
			if recoverErr != nil {
				return Record{}, true, recoverErr
			}
			terminal, err = m.store.Get(context.WithoutCancel(ctx), record.RunID)
		}
		return terminal, true, err
	}
	observation, bindErr := ParseAndBindCandidate(rawCandidate, record.Spec, []EvidenceBinding{{
		EvidenceRef: descriptor.MediaRef, ExpiresAt: descriptor.ExpiresAt,
	}}, at)
	if bindErr != nil {
		terminal, finishErr := m.store.CompleteInvalidCandidate(context.WithoutCancel(ctx), lease, at)
		if errors.Is(finishErr, ErrRuntimeLeaseLost) {
			return m.recoverAfterLeaseBoundary(ctx, record.RunID, at, finishErr)
		}
		return terminal, true, finishErr
	}
	candidate, err := ParseCandidate(rawCandidate)
	if err != nil {
		terminal, finishErr := m.store.CompleteInvalidCandidate(context.WithoutCancel(ctx), lease, at)
		if errors.Is(finishErr, ErrRuntimeLeaseLost) {
			return m.recoverAfterLeaseBoundary(ctx, record.RunID, at, finishErr)
		}
		return terminal, true, finishErr
	}
	terminal, err := m.store.CompleteSuccess(context.WithoutCancel(ctx), lease, candidate, observation, at)
	if errors.Is(err, ErrRuntimeLeaseLost) {
		_, recoverErr := m.store.Recover(context.WithoutCancel(ctx), at)
		if recoverErr != nil {
			return Record{}, true, recoverErr
		}
		terminal, err = m.store.Get(context.WithoutCancel(ctx), record.RunID)
	}
	return terminal, true, err
}

func (m *Manager) releasePreparation(ctx context.Context, record Record, lease Lease, at, notBefore time.Time) (Record, error) {
	delay := preparationBackoff(record.PreparationPolls + 1)
	availableAt := at.Add(delay)
	if !notBefore.IsZero() && notBefore.After(availableAt) {
		availableAt = notBefore.UTC()
	}
	if availableAt.After(record.DeadlineAt) {
		availableAt = record.DeadlineAt
	}
	return m.store.ReleasePreparationPending(context.WithoutCancel(ctx), lease, availableAt.UTC(), at.UTC())
}

type dependencyFailure uint8

const (
	dependencyRetry dependencyFailure = iota
	dependencyFatalUnavailable
	dependencyFatalRead
)

// Media readers use the same explicit-retry boundary as preparation readers.
// Typed absence is definitively unavailable. Invalid metadata, corruption,
// integrity failures and unclassified I/O fail closed without inventing a
// terminal business result; lease recovery may safely requeue after repair.
func classifyMediaReadError(err error) dependencyFailure {
	if errorIsAny(err,
		inspectionmedia.ErrNotFound,
		inspectionmedia.ErrDeleted,
		inspectionmedia.ErrExpired,
		inspectionmedia.ErrNoContent,
	) {
		return dependencyFatalUnavailable
	}
	if errorIsAny(err,
		ErrRuntimeInvalid,
		inspectionmedia.ErrInvalidMediaRef,
		inspectionmedia.ErrInvalidDescriptor,
		inspectionmedia.ErrUnsupportedKind,
		inspectionmedia.ErrUnsupportedMIME,
		inspectionmedia.ErrMIMEMismatch,
		inspectionmedia.ErrHashMismatch,
		inspectionmedia.ErrTooLarge,
		inspectionmedia.ErrUnsafePath,
		inspectionmedia.ErrCorruptDescriptor,
		inspectionmedia.ErrIntegrityMismatch,
		inspectionmedia.ErrIncompatibleStore,
		inspectionmedia.ErrInvalidRetention,
		inspectionmedia.ErrLineageConflict,
		inspectionmedia.ErrCorruptIdempotency,
	) {
		return dependencyFatalRead
	}
	if errors.Is(err, ErrDependencyRetryable) {
		return dependencyRetry
	}
	return dependencyFatalRead
}

func errorIsAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func leaseMutationBoundaryError(err error) bool {
	return errors.Is(err, ErrRuntimeLeaseLost)
}

func (m *Manager) releaseDependencyRetry(ctx context.Context, record Record, lease Lease, at, notBefore time.Time) (Record, bool, error) {
	pending, err := m.releasePreparation(ctx, record, lease, at, notBefore)
	if leaseMutationBoundaryError(err) {
		return m.recoverAfterLeaseBoundary(ctx, record.RunID, at, err)
	}
	if err != nil {
		return Record{}, true, err
	}
	if err := ctx.Err(); err != nil {
		return pending, true, err
	}
	return pending, true, nil
}

func (m *Manager) returnDependencyFatal(ctx context.Context, runID string) (Record, bool, error) {
	// A failed Status is the only business preparation failure. Read-side
	// corruption, invalid projections, and unclassified I/O must not invent a
	// terminal business result. Keep the authoritative claimed record intact;
	// lease recovery can safely requeue it after the dependency is repaired.
	authoritative, err := m.store.Get(context.WithoutCancel(ctx), runID)
	if err != nil {
		return Record{}, true, err
	}
	return authoritative, true, ErrDependencyFatal
}

func (m *Manager) completeMediaFailure(ctx context.Context, runID string, lease Lease, reason Reason, at time.Time) (Record, bool, error) {
	terminal, err := m.store.CompleteDefiniteFailure(context.WithoutCancel(ctx), lease, reason, at)
	if leaseMutationBoundaryError(err) {
		return m.recoverAfterLeaseBoundary(ctx, runID, at, err)
	}
	return terminal, true, err
}

func (m *Manager) completeMediaReadFailure(ctx context.Context, runID string, lease Lease, reason Reason, at time.Time) (Record, bool, error) {
	terminal, err := m.store.CompleteDefiniteFailure(context.WithoutCancel(ctx), lease, reason, at)
	if leaseMutationBoundaryError(err) {
		return m.recoverAfterLeaseBoundary(ctx, runID, at, err)
	}
	if err != nil {
		return Record{}, true, err
	}
	return terminal, true, ErrDependencyFatal
}

func preparationBackoff(polls int) time.Duration {
	if polls < 1 {
		polls = 1
	}
	delay := time.Second
	for index := 1; index < polls && delay < time.Minute; index++ {
		delay *= 2
		if delay > time.Minute {
			return time.Minute
		}
	}
	return delay
}

func validatePreparationStatus(status mediaprep.Status, expectedRef string) error {
	if !runtimePrepRefPattern.MatchString(expectedRef) || status.Validate(expectedRef) != nil {
		return ErrRuntimeInvalid
	}
	return nil
}

// recoverIfLeaseBoundary is called immediately after every external operation.
// At the exact deadline or lease expiry the store already considers the run
// recoverable, so callers must read that authoritative transition instead of
// issuing a lease mutation that is guaranteed to lose.
func (m *Manager) recoverIfLeaseBoundary(ctx context.Context, record Record, lease Lease, at time.Time) (Record, bool, error) {
	if at.Before(record.DeadlineAt) && at.Before(lease.LeaseExpiresAt) {
		return Record{}, false, nil
	}
	withoutCancel := context.WithoutCancel(ctx)
	if _, err := m.store.Recover(withoutCancel, at); err != nil {
		return Record{}, true, err
	}
	authoritative, err := m.store.Get(withoutCancel, record.RunID)
	return authoritative, true, err
}

func (m *Manager) recoverAfterLeaseBoundary(ctx context.Context, runID string, at time.Time, original error) (Record, bool, error) {
	if !errors.Is(original, ErrRuntimeLeaseLost) {
		return Record{}, true, original
	}
	withoutCancel := context.WithoutCancel(ctx)
	if _, err := m.store.Recover(withoutCancel, at); err != nil {
		return Record{}, true, err
	}
	record, err := m.store.Get(withoutCancel, runID)
	if err != nil {
		return Record{}, true, err
	}
	return record, true, nil
}

func (m *Manager) loadMedia(ctx context.Context, record Record, mediaRef string) (MediaDescriptor, []byte, error) {
	descriptor, err := m.media.Describe(ctx, mediaRef)
	if err != nil {
		return MediaDescriptor{}, nil, fmt.Errorf("describe temporary observation media: %w", err)
	}
	bound := record
	bound.MediaRef = mediaRef
	if err := descriptor.validate(bound, time.Time{}); err != nil {
		return MediaDescriptor{}, nil, err
	}
	reader, err := m.media.Open(ctx, mediaRef)
	if err != nil {
		return MediaDescriptor{}, nil, fmt.Errorf("open temporary observation media: %w", err)
	}
	if reader == nil {
		return MediaDescriptor{}, nil, ErrRuntimeInvalid
	}
	content, readErr := io.ReadAll(io.LimitReader(reader, descriptor.SizeBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		return MediaDescriptor{}, nil, fmt.Errorf("read temporary observation media: %w", readErr)
	}
	if closeErr != nil {
		zeroBytes(content)
		return MediaDescriptor{}, nil, fmt.Errorf("close temporary observation media: %w", closeErr)
	}
	if int64(len(content)) != descriptor.SizeBytes || int64(len(content)) > MaxMediaBytes {
		zeroBytes(content)
		return MediaDescriptor{}, nil, ErrRuntimeInvalid
	}
	digest := sha256.Sum256(content)
	if !bytes.Equal([]byte(hex.EncodeToString(digest[:])), []byte(descriptor.SHA256)) {
		zeroBytes(content)
		return MediaDescriptor{}, nil, ErrRuntimeInvalid
	}
	return descriptor, content, nil
}

func (m *Manager) now() (time.Time, error) {
	value := m.clock()
	if value.IsZero() {
		return time.Time{}, ErrRuntimeInvalid
	}
	return value.UTC(), nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
