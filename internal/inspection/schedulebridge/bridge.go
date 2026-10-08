// Package schedulebridge is the durable adapter between frozen schedule
// occurrences, the standard inspection runtime and application delivery.
package schedulebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/deliverybinding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/schedule"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	operatorauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

type Runner interface {
	Submit(context.Context, inspection.InspectionTemplate, inspection.Assignment, inspectionauthority.Submission) (inspection.Run, bool, error)
}

type Repository interface {
	GetRun(context.Context, string) (inspection.Run, error)
	GetPlan(context.Context, string) (inspection.ExecutionPlan, error)
}

type ApplicationState interface {
	FreezeScheduledDecision(context.Context, application.ScheduledDecisionRecord) (application.ScheduledDecisionRecord, bool, error)
	GetScheduledDecisionByRunID(context.Context, string) (application.ScheduledDecisionRecord, error)
	AbandonScheduledDecision(context.Context, application.ScheduledDecisionRecord) (bool, error)
}

type BindingResolver interface {
	Resolve(context.Context, deliverybinding.ResolveRequest) (deliverybinding.Binding, error)
}

type Config struct {
	State      ApplicationState
	Bindings   BindingResolver
	Runner     Runner
	Repository Repository
	Verifier   schedule.GrantVerifier
	Now        func() time.Time
}

// Bridge is intentionally the only object passed to the schedule coordinator.
// It exposes no raw runtime submission object or mutable recipient registry.
// Admission requires a recipient binding valid beyond the run deadline. Once
// runtime submission begins, that exact audience is frozen: later revocation
// prevents new admissions but does not rewrite or orphan the in-flight run.
type Bridge struct {
	state      ApplicationState
	bindings   BindingResolver
	runner     Runner
	repository Repository
	verifier   schedule.GrantVerifier
	now        func() time.Time
}

func New(config Config) (*Bridge, error) {
	if nilDependency(config.State) || nilDependency(config.Bindings) || nilDependency(config.Runner) || nilDependency(config.Repository) || nilDependency(config.Verifier) {
		return nil, errors.New("complete inspection schedule bridge dependencies are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Bridge{state: config.State, bindings: config.Bindings, runner: config.Runner, repository: config.Repository, verifier: config.Verifier, now: config.Now}, nil
}

func nilDependency(value any) bool {
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

func (b *Bridge) Submit(ctx context.Context, occurrence schedule.Occurrence, grant operatorauthority.Grant) (schedule.SubmissionResult, error) {
	now := b.now().UTC()
	// The coordinator checks the deadline before it hands off, but this adapter
	// is also an admission boundary and must not trust caller timing. Equality
	// is expired: no recipient lookup, decision freeze or runtime call may begin
	// once the frozen occurrence deadline has been reached.
	if occurrence.Deadline.IsZero() || !now.Before(occurrence.Deadline.UTC()) {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected}, nil
	}
	if err := occurrence.ValidateSubmissionGrant(grant, b.verifier, now); err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected}, nil
	}
	plan, runID, err := exactPlan(occurrence)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected}, nil
	}
	binding, err := b.bindings.Resolve(ctx, deliverybinding.ResolveRequest{
		TenantID: occurrence.TenantID, SiteID: occurrence.SiteID, BindingRef: occurrence.Delivery.BindingRef,
		Revision: occurrence.Delivery.Revision, AudienceSHA256: occurrence.Delivery.AudienceSHA256,
		PrincipalSHA256: occurrence.Delivery.PrincipalSHA256, At: now,
	})
	if err != nil {
		if errors.Is(err, deliverybinding.ErrNotFound) || errors.Is(err, deliverybinding.ErrConflict) || errors.Is(err, deliverybinding.ErrInactive) {
			return schedule.SubmissionResult{Status: schedule.SubmissionRejected}, nil
		}
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRefFor(occurrence)}, err
	}
	decision, err := decisionFor(occurrence, binding, plan, runID)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected}, nil
	}
	stored, _, err := b.state.FreezeScheduledDecision(ctx, decision)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: decision.SubmissionRef}, err
	}
	if !sameDecision(stored, decision) {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected, SubmissionRef: decision.SubmissionRef}, nil
	}
	identity, err := inspectionauthority.ExecutionIdentityForOrigin(inspection.OriginSchedule, occurrence.ServicePrincipalSHA256)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected, SubmissionRef: decision.SubmissionRef}, nil
	}
	submission, err := inspectionauthority.NewSubmission(occurrence.CreateRunRequest(), identity)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected, SubmissionRef: decision.SubmissionRef}, nil
	}
	run, _, err := b.runner.Submit(ctx, occurrence.RunSpec.Template, occurrence.RunSpec.Assignment, submission)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: decision.SubmissionRef}, err
	}
	if err := validateRun(run, plan, runID); err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: decision.SubmissionRef}, err
	}
	if err := b.validateAuthoritative(ctx, runID, plan); err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: decision.SubmissionRef}, err
	}
	return schedule.SubmissionResult{Status: schedule.SubmissionAccepted, RunRef: runID, SubmissionRef: decision.SubmissionRef}, nil
}

// Reconcile never calls Submit. The deterministic run ID is derived with the
// runtime package's sole algorithm and looked up in authoritative state.
func (b *Bridge) Reconcile(ctx context.Context, occurrence schedule.Occurrence, persistedSubmissionRef string) (schedule.SubmissionResult, error) {
	plan, runID, err := exactPlan(occurrence)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionRejected}, err
	}
	submissionRef := submissionRefFor(occurrence)
	if persistedSubmissionRef != "" && persistedSubmissionRef != submissionRef {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, errors.New("inspection scheduled reconciliation submission reference mismatch")
	}
	run, err := b.repository.GetRun(ctx, runID)
	if errors.Is(err, inspectionstore.ErrNotFound) {
		decision, decisionErr := b.state.GetScheduledDecisionByRunID(ctx, runID)
		if errors.Is(decisionErr, application.ErrStateNotFound) {
			return schedule.SubmissionResult{Status: schedule.SubmissionNotSubmitted, SubmissionRef: submissionRef}, nil
		}
		if decisionErr != nil {
			return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, decisionErr
		}
		if !sameOccurrenceDecision(decision, occurrence, runID) {
			return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, errors.New("inspection scheduled abandoned decision binding mismatch")
		}
		if _, abandonErr := b.state.AbandonScheduledDecision(ctx, decision); abandonErr != nil {
			return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, abandonErr
		}
		return schedule.SubmissionResult{Status: schedule.SubmissionNotSubmitted, SubmissionRef: submissionRef}, nil
	}
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, err
	}
	decision, err := b.state.GetScheduledDecisionByRunID(ctx, runID)
	if err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, err
	}
	if !sameOccurrenceDecision(decision, occurrence, runID) {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, errors.New("inspection scheduled reconciliation decision binding mismatch")
	}
	if err := validateRun(run, plan, runID); err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, err
	}
	if err := b.validateAuthoritative(ctx, runID, plan); err != nil {
		return schedule.SubmissionResult{Status: schedule.SubmissionUnknown, SubmissionRef: submissionRef}, err
	}
	return schedule.SubmissionResult{Status: schedule.SubmissionAccepted, RunRef: runID, SubmissionRef: submissionRef}, nil
}

func (b *Bridge) Observe(ctx context.Context, runID string) (schedule.RunObservation, error) {
	decision, err := b.state.GetScheduledDecisionByRunID(ctx, runID)
	if errors.Is(err, application.ErrStateNotFound) {
		return schedule.RunObservation{Status: schedule.RunObservationMissing}, nil
	}
	if err != nil {
		return schedule.RunObservation{}, err
	}
	run, err := b.repository.GetRun(ctx, runID)
	if errors.Is(err, inspectionstore.ErrNotFound) {
		return schedule.RunObservation{Status: schedule.RunObservationMissing}, nil
	}
	if err != nil {
		return schedule.RunObservation{}, err
	}
	plan, err := inspection.CompilePlan(decision.Template, decision.Assignment, decision.RunRequest)
	if err != nil || plan.PlanSHA256 != decision.PlanSHA256 || validateRun(run, plan, runID) != nil {
		return schedule.RunObservation{}, errors.New("inspection scheduled observation binding mismatch")
	}
	if err := b.validateAuthoritative(ctx, runID, plan); err != nil {
		return schedule.RunObservation{}, errors.New("inspection scheduled observation authoritative state mismatch")
	}
	if inspection.Terminal(run.State) {
		return schedule.RunObservation{Status: schedule.RunObservationTerminal, State: run.State}, nil
	}
	return schedule.RunObservation{Status: schedule.RunObservationNonTerminal, State: run.State}, nil
}

func (b *Bridge) validateAuthoritative(ctx context.Context, runID string, expected inspection.ExecutionPlan) error {
	run, err := b.repository.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if err := validateRun(run, expected, runID); err != nil {
		return err
	}
	storedPlan, err := b.repository.GetPlan(ctx, runID)
	if err != nil {
		return err
	}
	if storedPlan.Validate() != nil || storedPlan.PlanSHA256 != expected.PlanSHA256 || storedPlan.RequestKey != expected.RequestKey ||
		storedPlan.TenantID != expected.TenantID || storedPlan.SiteID != expected.SiteID || storedPlan.RequestID != expected.RequestID ||
		!storedPlan.RequestedAt.Equal(expected.RequestedAt) || !storedPlan.Deadline.Equal(expected.Deadline) {
		return errors.New("inspection scheduled authoritative plan binding mismatch")
	}
	return nil
}

func exactPlan(occurrence schedule.Occurrence) (inspection.ExecutionPlan, string, error) {
	if err := occurrence.Validate(); err != nil {
		return inspection.ExecutionPlan{}, "", err
	}
	plan, err := inspection.CompilePlan(occurrence.RunSpec.Template, occurrence.RunSpec.Assignment, occurrence.CreateRunRequest())
	if err != nil || plan.PlanSHA256 != occurrence.PlanSHA256 {
		return inspection.ExecutionPlan{}, "", errors.New("inspection occurrence exact plan binding mismatch")
	}
	runID, err := runtime.RunIDForPlan(plan)
	return plan, runID, err
}

func decisionFor(occurrence schedule.Occurrence, binding deliverybinding.Binding, plan inspection.ExecutionPlan, runID string) (application.ScheduledDecisionRecord, error) {
	if binding.TenantID != occurrence.TenantID || binding.SiteID != occurrence.SiteID || binding.BindingRef != occurrence.Delivery.BindingRef ||
		binding.Revision != occurrence.Delivery.Revision || binding.AudienceSHA256 != occurrence.Delivery.AudienceSHA256 ||
		binding.PrincipalSHA256 != occurrence.Delivery.PrincipalSHA256 || !occurrence.Deadline.Before(binding.ValidUntil) {
		return application.ScheduledDecisionRecord{}, errors.New("inspection scheduled recipient binding mismatch")
	}
	return application.ScheduledDecisionRecord{
		Session: httpapi.SessionBinding{
			TenantID: binding.TenantID, SiteID: binding.SiteID, Channel: binding.Audience.Channel,
			ConversationRef: binding.Audience.ConversationRef, RecipientRef: binding.Audience.RecipientRef,
			PrincipalSHA256: binding.PrincipalSHA256,
		},
		PublicRunRef: publicRunRefFor(occurrence), InternalRunID: runID, OccurrenceID: occurrence.OccurrenceID,
		SubmissionRef: submissionRefFor(occurrence), BindingRef: binding.BindingRef, BindingRevision: binding.Revision,
		AudienceSHA256: binding.AudienceSHA256, DeliverySHA256: occurrence.DeliverySHA256,
		ServicePrincipalSHA256: occurrence.ServicePrincipalSHA256, OccurrenceSHA256: occurrence.SHA256,
		RequestSHA256: occurrence.RequestSHA256, PlanSHA256: plan.PlanSHA256, Template: occurrence.RunSpec.Template,
		Assignment: occurrence.RunSpec.Assignment, RunRequest: occurrence.CreateRunRequest(), CreatedAt: occurrence.GeneratedAt.UTC(),
	}, nil
}

func validateRun(run inspection.Run, plan inspection.ExecutionPlan, runID string) error {
	if run.RunID != runID || run.TenantID != plan.TenantID || run.SiteID != plan.SiteID || run.RequestKey != plan.RequestKey ||
		run.PlanSHA256 != plan.PlanSHA256 || !run.Deadline.Equal(plan.Deadline) || run.CreatedAt.IsZero() || run.UpdatedAt.Before(run.CreatedAt) ||
		run.CreatedAt.Before(plan.RequestedAt) {
		return errors.New("inspection scheduled runtime returned an unbound run")
	}
	return nil
}

func sameDecision(left, right application.ScheduledDecisionRecord) bool {
	return left.Session == right.Session && left.PublicRunRef == right.PublicRunRef && left.InternalRunID == right.InternalRunID &&
		left.OccurrenceID == right.OccurrenceID && left.SubmissionRef == right.SubmissionRef && left.BindingRef == right.BindingRef &&
		left.BindingRevision == right.BindingRevision && left.AudienceSHA256 == right.AudienceSHA256 && left.DeliverySHA256 == right.DeliverySHA256 &&
		left.ServicePrincipalSHA256 == right.ServicePrincipalSHA256 && left.OccurrenceSHA256 == right.OccurrenceSHA256 &&
		left.RequestSHA256 == right.RequestSHA256 && left.PlanSHA256 == right.PlanSHA256 && left.CreatedAt.Equal(right.CreatedAt)
}

func sameOccurrenceDecision(value application.ScheduledDecisionRecord, occurrence schedule.Occurrence, runID string) bool {
	audience := delivery.Audience{
		TenantID: value.Session.TenantID, SiteID: value.Session.SiteID, Channel: value.Session.Channel,
		ConversationRef: value.Session.ConversationRef, RecipientRef: value.Session.RecipientRef,
	}
	audienceSHA, err := audience.SHA256()
	return err == nil && value.Session.TenantID == occurrence.TenantID && value.Session.SiteID == occurrence.SiteID &&
		value.Session.PrincipalSHA256 == occurrence.Delivery.PrincipalSHA256 && audienceSHA == occurrence.Delivery.AudienceSHA256 &&
		value.PublicRunRef == publicRunRefFor(occurrence) && value.InternalRunID == runID && value.OccurrenceID == occurrence.OccurrenceID &&
		value.SubmissionRef == submissionRefFor(occurrence) && value.BindingRef == occurrence.Delivery.BindingRef &&
		value.BindingRevision == occurrence.Delivery.Revision && value.AudienceSHA256 == occurrence.Delivery.AudienceSHA256 &&
		value.DeliverySHA256 == occurrence.DeliverySHA256 && value.ServicePrincipalSHA256 == occurrence.ServicePrincipalSHA256 &&
		value.OccurrenceSHA256 == occurrence.SHA256 && value.RequestSHA256 == occurrence.RequestSHA256 &&
		value.PlanSHA256 == occurrence.PlanSHA256 && value.CreatedAt.Equal(occurrence.GeneratedAt)
}

func publicRunRefFor(occurrence schedule.Occurrence) string {
	sum := sha256.Sum256([]byte("cosmoedge.inspection.scheduled-public-run.v1\x00" + occurrence.OccurrenceID + "\x00" + occurrence.SHA256))
	return "scheduled_" + hex.EncodeToString(sum[:16])
}

func submissionRefFor(occurrence schedule.Occurrence) string {
	sum := sha256.Sum256([]byte("cosmoedge.inspection.scheduled-submission.v1\x00" + occurrence.OccurrenceID + "\x00" + occurrence.SHA256))
	return "submission_" + hex.EncodeToString(sum[:16])
}
