package schedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

type AuthorityProvider interface {
	AuthorityFor(context.Context, Occurrence) (authority.Grant, bool, error)
}

type SubmissionStatus string

const (
	SubmissionAccepted     SubmissionStatus = "accepted"
	SubmissionNotSubmitted SubmissionStatus = "not_submitted"
	SubmissionRejected     SubmissionStatus = "rejected"
	SubmissionUnknown      SubmissionStatus = "unknown"
)

type SubmissionResult struct {
	Status        SubmissionStatus
	RunRef        string
	SubmissionRef string
}

func (r SubmissionResult) Validate() error {
	if r.SubmissionRef != "" && validateRef("submission", r.SubmissionRef) != nil {
		return errors.New("inspection occurrence submission reference is invalid")
	}
	switch r.Status {
	case SubmissionAccepted:
		if validateRef("run", r.RunRef) != nil {
			return errors.New("accepted inspection occurrence requires a run reference")
		}
	case SubmissionNotSubmitted, SubmissionRejected, SubmissionUnknown:
		if r.RunRef != "" {
			return errors.New("non-accepted inspection occurrence cannot carry a run reference")
		}
	default:
		return errors.New("inspection occurrence submission status is invalid")
	}
	return nil
}

// Submitter receives an already self-validated immutable occurrence. The
// stable OperationRef and RequestKey are part of that envelope. Once Submit is
// possible, the store is already in submitting_unknown; recovery uses only
// Reconcile and never blindly calls Submit again.
type Submitter interface {
	Submit(context.Context, Occurrence, authority.Grant) (SubmissionResult, error)
	Reconcile(context.Context, Occurrence, string) (SubmissionResult, error)
}

type RunObservationStatus string

const (
	RunObservationMissing     RunObservationStatus = "missing"
	RunObservationNonTerminal RunObservationStatus = "non_terminal"
	RunObservationTerminal    RunObservationStatus = "terminal"
)

type RunObservation struct {
	Status RunObservationStatus
	State  inspection.RunState
}

func (o RunObservation) Validate() error {
	switch o.Status {
	case RunObservationMissing:
		if o.State != "" {
			return errors.New("missing run observation cannot carry state")
		}
	case RunObservationNonTerminal:
		if o.State == "" || inspection.Terminal(o.State) {
			return errors.New("nonterminal run observation is invalid")
		}
	case RunObservationTerminal:
		if !inspection.Terminal(o.State) {
			return errors.New("terminal run observation requires terminal proof")
		}
	default:
		return errors.New("run observation status is invalid")
	}
	return nil
}

type RunObserver interface {
	Observe(context.Context, string) (RunObservation, error)
}

type CoordinatorConfig struct {
	Store             *Store
	Planner           Planner
	AuthorityProvider AuthorityProvider
	AuthorityVerifier GrantVerifier
	Submitter         Submitter
	RunObserver       RunObserver
	OwnerID           string
	Lease             time.Duration
	Now               func() time.Time
}

type Coordinator struct {
	store     *Store
	planner   Planner
	provider  AuthorityProvider
	verifier  GrantVerifier
	submitter Submitter
	observer  RunObserver
	ownerID   string
	lease     time.Duration
	now       func() time.Time
}

type TickReport struct {
	SchedulesScanned   int
	SchedulesExpired   int
	OccurrencesCreated int
	OccurrencesExpired int
	Submitted          int
	Blocked            int
	Expired            int
	Queued             int
	Skipped            int
	SubmissionUnknown  int
	Reconciled         int
	ObservedTerminal   int
	ObservedMissing    int
}

func NewCoordinator(config CoordinatorConfig) (*Coordinator, error) {
	if config.Store == nil || config.Planner.zones == nil || config.Planner.verifier == nil || config.AuthorityProvider == nil ||
		config.AuthorityVerifier == nil || config.Submitter == nil || config.RunObserver == nil || validateRef("coordinator owner", config.OwnerID) != nil {
		return nil, errors.New("complete inspection schedule coordinator dependencies are required")
	}
	if config.Lease == 0 {
		config.Lease = 30 * time.Second
	}
	if config.Lease < time.Second || config.Lease > time.Hour {
		return nil, errors.New("inspection schedule coordinator lease must be between one second and one hour")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Coordinator{store: config.Store, planner: config.Planner, provider: config.AuthorityProvider, verifier: config.AuthorityVerifier,
		submitter: config.Submitter, observer: config.RunObserver, ownerID: config.OwnerID, lease: config.Lease, now: config.Now}, nil
}

func (c *Coordinator) Tick(ctx context.Context) (TickReport, error) {
	now := c.now().UTC()
	if now.IsZero() {
		return TickReport{}, errors.New("inspection schedule coordinator clock returned zero")
	}
	report, err := c.plan(ctx, now)
	if err != nil {
		return report, err
	}
	report.OccurrencesExpired, err = c.store.ExpirePending(ctx, now)
	if err != nil {
		return report, err
	}
	observed, observation, err := c.observeOne(ctx, now)
	if observed {
		if observation.Status == RunObservationTerminal {
			report.ObservedTerminal++
		}
		if observation.Status == RunObservationMissing {
			report.ObservedMissing++
		}
	}
	if err != nil {
		return report, err
	}
	reconciled, reconciliationState, err := c.reconcileOne(ctx, now)
	if reconciled {
		report.Reconciled++
		countOccurrenceState(&report, reconciliationState)
	}
	if err != nil {
		return report, err
	}
	processed, state, admission, err := c.processOne(ctx, now)
	if processed {
		countOccurrenceState(&report, state)
		if admission == AdmissionQueued {
			report.Queued++
		}
		if admission == AdmissionSkipped {
			report.Skipped++
		}
	}
	return report, err
}

func countOccurrenceState(report *TickReport, state OccurrenceState) {
	if report == nil {
		return
	}
	switch state {
	case OccurrenceSubmitted:
		report.Submitted++
	case OccurrenceBlocked:
		report.Blocked++
	case OccurrenceExpired:
		report.Expired++
	case OccurrenceSubmittingUnknown:
		report.SubmissionUnknown++
	}
}

func (c *Coordinator) plan(ctx context.Context, now time.Time) (TickReport, error) {
	records, err := c.store.ListActive(ctx)
	if err != nil {
		return TickReport{}, err
	}
	report := TickReport{SchedulesScanned: len(records)}
	for _, record := range records {
		if !now.Before(effectiveEnd(record.Schedule)) {
			if _, err := c.store.Expire(ctx, keyFor(record.Schedule), now); err != nil && !errors.Is(err, ErrConflict) {
				return report, err
			}
			report.SchedulesExpired++
			continue
		}
		occurrences, err := c.planner.Due(record.Schedule, record.CursorAt, now)
		if err != nil {
			return report, err
		}
		created, err := c.store.RecordPlanning(ctx, record, now, occurrences)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return report, err
		}
		report.OccurrencesCreated += created
	}
	return report, nil
}

func (c *Coordinator) processOne(ctx context.Context, now time.Time) (bool, OccurrenceState, AdmissionStatus, error) {
	record, claim, claimed, err := c.store.ClaimPending(ctx, c.ownerID, now, c.lease)
	if err != nil || !claimed {
		return false, "", "", err
	}
	if err := record.Occurrence.ValidateWithZones(c.store.zones); err != nil {
		terminal, markErr := c.store.MarkClaimedTerminal(ctx, claim, OccurrenceBlocked, "frozen_run_invalid", now)
		return true, terminal.State, AdmissionBlocked, markErr
	}
	if !now.Before(record.Occurrence.Deadline) {
		terminal, markErr := c.store.MarkClaimedTerminal(ctx, claim, OccurrenceExpired, "run_deadline_elapsed", now)
		return true, terminal.State, AdmissionExpired, markErr
	}
	grant, found, err := c.provider.AuthorityFor(ctx, record.Occurrence)
	if err != nil {
		_, deferErr := c.store.DeferClaim(context.Background(), claim, "authority_lookup_failed", c.now().UTC())
		return true, OccurrencePending, "", errors.Join(err, deferErr)
	}
	if !found || grant.GrantID == "" {
		terminal, markErr := c.store.MarkClaimedTerminal(ctx, claim, OccurrenceBlocked, "authority_missing", now)
		return true, terminal.State, AdmissionBlocked, markErr
	}
	admissionAt := c.now().UTC()
	if !admissionAt.Before(record.Occurrence.Deadline) {
		terminal, markErr := c.store.MarkClaimedTerminal(ctx, claim, OccurrenceExpired, "run_deadline_elapsed", admissionAt)
		return true, terminal.State, AdmissionExpired, markErr
	}
	if !admissionAt.Before(grant.ExpiresAt) {
		terminal, markErr := c.store.MarkClaimedTerminal(ctx, claim, OccurrenceExpired, "authority_expired", admissionAt)
		return true, terminal.State, AdmissionExpired, markErr
	}
	if err := c.validateAuthority(record.Occurrence, grant, admissionAt); err != nil {
		terminal, markErr := c.store.MarkClaimedTerminal(ctx, claim, OccurrenceBlocked, "authority_scope_invalid", admissionAt)
		if markErr != nil {
			return true, terminal.State, AdmissionBlocked, markErr
		}
		return true, terminal.State, AdmissionBlocked, nil
	}
	unknown, admission, err := c.store.BeginSubmission(ctx, claim, admissionAt, c.lease)
	if err != nil || admission != AdmissionReady {
		return true, unknown.State, admission, err
	}
	var result SubmissionResult
	var submitErr error
	heartbeatErr := c.withClaimHeartbeat(ctx, claim, func(callCtx context.Context) {
		result, submitErr = c.submitter.Submit(callCtx, unknown.Occurrence, grant)
	})
	submitErr = errors.Join(submitErr, heartbeatErr)
	if submitErr != nil {
		_, releaseErr := c.store.ReleaseUnknown(context.Background(), claim, "", c.now().UTC())
		return true, OccurrenceSubmittingUnknown, admission, errors.Join(submitErr, releaseErr)
	}
	if err := result.Validate(); err != nil {
		_, releaseErr := c.store.ReleaseUnknown(context.Background(), claim, "", c.now().UTC())
		return true, OccurrenceSubmittingUnknown, admission, errors.Join(err, releaseErr)
	}
	completed, err := c.store.ApplySubmission(ctx, claim, result, c.now().UTC())
	return true, completed.State, admission, err
}

func (c *Coordinator) reconcileOne(ctx context.Context, now time.Time) (bool, OccurrenceState, error) {
	record, claim, claimed, err := c.store.ClaimUnknown(ctx, c.ownerID, now, c.lease)
	if err != nil || !claimed {
		return false, "", err
	}
	var result SubmissionResult
	var reconcileErr error
	heartbeatErr := c.withClaimHeartbeat(ctx, claim, func(callCtx context.Context) {
		result, reconcileErr = c.submitter.Reconcile(callCtx, record.Occurrence, record.SubmissionRef)
	})
	reconcileErr = errors.Join(reconcileErr, heartbeatErr)
	if reconcileErr != nil {
		_, releaseErr := c.store.ReleaseUnknown(context.Background(), claim, record.SubmissionRef, c.now().UTC())
		return true, OccurrenceSubmittingUnknown, errors.Join(reconcileErr, releaseErr)
	}
	if err := result.Validate(); err != nil {
		_, releaseErr := c.store.ReleaseUnknown(context.Background(), claim, record.SubmissionRef, c.now().UTC())
		return true, OccurrenceSubmittingUnknown, errors.Join(err, releaseErr)
	}
	completed, err := c.store.ApplySubmission(ctx, claim, result, c.now().UTC())
	return true, completed.State, err
}

func (c *Coordinator) observeOne(ctx context.Context, now time.Time) (bool, RunObservation, error) {
	record, claim, claimed, err := c.store.ClaimSubmitted(ctx, c.ownerID, now, c.lease)
	if err != nil || !claimed {
		return false, RunObservation{}, err
	}
	var observation RunObservation
	var observeErr error
	heartbeatErr := c.withClaimHeartbeat(ctx, claim, func(callCtx context.Context) {
		observation, observeErr = c.observer.Observe(callCtx, record.RunRef)
	})
	observeErr = errors.Join(observeErr, heartbeatErr)
	if observeErr != nil {
		_, releaseErr := c.store.ReleaseObservation(context.Background(), claim, "run_observer_failed", c.now().UTC())
		return true, RunObservation{}, errors.Join(observeErr, releaseErr)
	}
	if err := observation.Validate(); err != nil {
		_, releaseErr := c.store.ReleaseObservation(context.Background(), claim, "run_observation_invalid", c.now().UTC())
		return true, observation, errors.Join(err, releaseErr)
	}
	switch observation.Status {
	case RunObservationMissing:
		_, err = c.store.ReleaseObservation(ctx, claim, "run_not_found", c.now().UTC())
	case RunObservationNonTerminal:
		_, err = c.store.ReleaseObservation(ctx, claim, "run_non_terminal", c.now().UTC())
	case RunObservationTerminal:
		_, err = c.store.markRunTerminal(ctx, claim, observation.State, c.now().UTC())
	}
	return true, observation, err
}

func (c *Coordinator) validateAuthority(occurrence Occurrence, grant authority.Grant, now time.Time) error {
	if grant.Validate() != nil || grant.Class != authority.ServiceExecution || grant.PrincipalSHA256 != occurrence.ServicePrincipalSHA256 || now.Before(grant.IssuedAt) || !now.Before(grant.ExpiresAt) || !occurrence.Deadline.Before(grant.ExpiresAt) {
		return errors.New("inspection occurrence authority is invalid")
	}
	digest, err := grantDigest(grant)
	if err != nil || digest != occurrence.AuthoritySHA256 {
		return errors.New("inspection occurrence authority digest is invalid")
	}
	scope := occurrence.AuthorityScope
	scopeDigestValue, err := scopeDigest(scope)
	if err != nil || scopeDigestValue != occurrence.ScheduleScopeSHA256 || validateGrantExactScope(grant, scope) != nil || verifyServiceGrant(c.verifier, grant, scope, now) != nil {
		return fmt.Errorf("inspection occurrence authority scope verification failed")
	}
	return nil
}

// withClaimHeartbeat keeps the durable fence alive for the complete external
// call. A failed renewal cancels the call context and forces the result back to
// the durable unknown/reconciliation path; it is never applied under a stale
// generation.
func (c *Coordinator) withClaimHeartbeat(ctx context.Context, claim OccurrenceClaim, call func(context.Context)) error {
	if call == nil {
		return errors.New("inspection schedule external call is required")
	}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan struct{})
	done := make(chan error, 1)
	interval := c.lease / 3
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	renewCtx, renewCancel := context.WithTimeout(context.Background(), interval)
	renewed, renewErr := c.store.RenewClaim(renewCtx, claim, c.now().UTC(), c.lease)
	renewCancel()
	if renewErr != nil || !renewed {
		if renewErr == nil {
			renewErr = ErrConflict
		}
		return fmt.Errorf("establish inspection schedule external-call lease: %w", renewErr)
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(context.Background(), interval)
				renewed, err := c.store.RenewClaim(renewCtx, claim, c.now().UTC(), c.lease)
				renewCancel()
				if err != nil || !renewed {
					cancel()
					if err == nil {
						err = ErrConflict
					}
					done <- fmt.Errorf("renew inspection schedule external-call lease: %w", err)
					return
				}
			}
		}
	}()
	call(callCtx)
	close(stop)
	return <-done
}
