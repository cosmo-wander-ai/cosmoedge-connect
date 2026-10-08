package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
)

const (
	defaultLease              = 30 * time.Second
	defaultWorkerTick         = 2 * time.Second
	defaultCleanupTimeout     = 5 * time.Second
	defaultPersistenceTTL     = 5 * time.Second
	defaultAuthorityBatch     = 256
	executionContextCancelled = "execution_context_cancelled"
)

type Manager struct {
	repository Repository
	authority  inspectionauthority.Broker
	ports      Ports
	now        func() time.Time
	ownerID    string
	lease      time.Duration
	workerTick time.Duration
	cleanupTTL time.Duration
	wake       chan struct{}

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

type Option func(*Manager) error

func WithClock(now func() time.Time) Option {
	return func(manager *Manager) error {
		if now == nil {
			return errors.New("inspection clock is required")
		}
		manager.now = now
		return nil
	}
}

// WithRuntimeID binds the manager to a stable, deployment-owned runtime
// identity. Recreating a manager after a process-local repository restart must
// not silently change the identity already frozen into execution authority.
func WithRuntimeID(runtimeID string) Option {
	return func(manager *Manager) error {
		if !validOpaqueRuntimeRef(runtimeID) || len(runtimeID) > 64 {
			return errors.New("inspection runtime identity is invalid")
		}
		manager.ownerID = runtimeID
		return nil
	}
}

func WithLease(lease time.Duration) Option {
	return func(manager *Manager) error {
		if lease < 30*time.Millisecond || lease > 24*time.Hour {
			return errors.New("inspection lease must be between 30ms and 24h")
		}
		manager.lease = lease
		return nil
	}
}

func WithWorkerTick(tick time.Duration) Option {
	return func(manager *Manager) error {
		if tick <= 0 || tick > 24*time.Hour {
			return errors.New("inspection worker tick must be between zero and 24h")
		}
		manager.workerTick = tick
		return nil
	}
}

func WithCleanupTimeout(timeout time.Duration) Option {
	return func(manager *Manager) error {
		if timeout <= 0 || timeout > 5*time.Minute {
			return errors.New("inspection cleanup timeout must be between zero and five minutes")
		}
		manager.cleanupTTL = timeout
		return nil
	}
}

func New(repository Repository, broker inspectionauthority.Broker, ports Ports, options ...Option) (*Manager, error) {
	if repository == nil || broker == nil {
		return nil, errors.New("inspection repository and execution authority broker are required")
	}
	if err := ports.validate(); err != nil {
		return nil, err
	}
	ownerID, err := randomID("worker")
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		repository: repository, authority: broker, ports: ports, now: time.Now,
		ownerID: ownerID, lease: defaultLease, workerTick: defaultWorkerTick,
		cleanupTTL: defaultCleanupTimeout, wake: make(chan struct{}, 1),
	}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("inspection runtime option is nil")
		}
		if err := option(manager); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (m *Manager) Submit(ctx context.Context, template inspection.InspectionTemplate, assignment inspection.Assignment, submission inspectionauthority.Submission) (inspection.Run, bool, error) {
	request, err := submission.PlanRequest()
	if err != nil {
		return inspection.Run{}, false, inspectionauthority.ErrUnauthorized
	}
	plan, err := inspection.CompilePlan(template, assignment, request)
	if err != nil {
		return inspection.Run{}, false, err
	}
	runID, err := RunIDForPlan(plan)
	if err != nil {
		return inspection.Run{}, false, err
	}
	identity, err := submission.ExecutionIdentity()
	if err != nil {
		return inspection.Run{}, false, err
	}
	wantIdentity, err := inspectionauthority.ExecutionIdentityForOrigin(plan.Origin, identity.PrincipalSHA256)
	if err != nil || wantIdentity != identity {
		return inspection.Run{}, false, inspectionauthority.ErrUnauthorized
	}
	stepScopes, err := inspectionauthority.ScopesForPlan(plan)
	if err != nil {
		return inspection.Run{}, false, err
	}
	_, authorityCreated, err := m.authority.Issue(ctx, inspectionauthority.IssueDemand{
		Identity: identity, TenantID: plan.TenantID, SiteID: plan.SiteID, RunID: runID,
		PlanSHA256: plan.PlanSHA256, AssignmentID: plan.AssignmentID, AssignmentRevision: plan.AssignmentRevision,
		RequestKey: plan.RequestKey, RuntimeID: m.ownerID, Steps: stepScopes, Deadline: plan.Deadline,
	})
	if err != nil {
		return inspection.Run{}, false, err
	}
	run, created, err := m.repository.CreateQueuedRun(ctx, plan, runID, m.now().UTC())
	if err != nil && authorityCreated {
		_ = m.authority.Revoke(context.Background(), runID)
	}
	if err != nil {
		return inspection.Run{}, false, err
	}
	if run.RunID != runID {
		if authorityCreated {
			_ = m.authority.Revoke(context.Background(), runID)
		}
		return inspection.Run{}, false, errors.New("inspection request replay resolved to a different run identity")
	}
	if inspection.Terminal(run.State) {
		releaseContext, cancelRelease := context.WithTimeout(context.Background(), defaultPersistenceTTL)
		releaseErr := m.releaseAuthorityForRun(releaseContext, runID, m.now().UTC())
		cancelRelease()
		if releaseErr != nil {
			return run, created, releaseErr
		}
	} else {
		m.Wake()
	}
	return run, created, nil
}

// RunIDForPlan is the sole stable standard-runtime identity algorithm. Callers
// that must persist an admission decision before Submit use this function and
// must still present the exact plan to Manager.Submit.
func RunIDForPlan(plan inspection.ExecutionPlan) (string, error) {
	if err := plan.Validate(); err != nil {
		return "", errors.New("inspection run identity requires a valid frozen plan")
	}
	digest := sha256.Sum256([]byte("cosmoedge.inspection.run.v2\x00" + plan.RequestKey + "\x00" + plan.PlanSHA256))
	return "run_" + hex.EncodeToString(digest[:16]), nil
}

func (m *Manager) Get(ctx context.Context, runID string) (inspection.Run, error) {
	return m.repository.GetRun(ctx, runID)
}

func (m *Manager) Cancel(ctx context.Context, runID, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("inspection cancellation reason is required")
	}
	at := m.now().UTC()
	if err := m.repository.Cancel(ctx, runID, at, reason); err != nil {
		return err
	}
	releaseContext, cancelRelease := context.WithTimeout(context.Background(), defaultPersistenceTTL)
	defer cancelRelease()
	return m.releaseAuthorityForRun(releaseContext, runID, at)
}

func (m *Manager) Start(parent context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		return errors.New("inspection runtime is already running")
	}
	now := m.now().UTC()
	if _, err := m.repository.RecoverExpiredStepAttempts(parent, now); err != nil {
		return err
	}
	if _, err := m.repository.RecoverInterrupted(parent, now); err != nil {
		return err
	}
	if _, err := m.repository.ExpireQueued(parent, now); err != nil {
		return err
	}
	if err := m.releaseTerminalAuthorities(parent, now); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	m.cancel, m.done = cancel, done
	go m.run(ctx, done)
	m.Wake()
	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.cancel, m.done = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) ProcessOne(ctx context.Context) (bool, error) {
	now := m.now().UTC()
	if _, err := m.repository.RecoverExpiredStepAttempts(ctx, now); err != nil {
		return false, err
	}
	if _, err := m.repository.RecoverInterrupted(ctx, now); err != nil {
		return false, err
	}
	if _, err := m.repository.ExpireQueued(ctx, now); err != nil {
		return false, err
	}
	if err := m.releaseTerminalAuthorities(ctx, now); err != nil {
		return false, err
	}
	run, plan, ok, err := m.repository.ClaimNext(ctx, m.ownerID, now, m.lease)
	if err != nil || !ok {
		return ok, err
	}
	return true, m.execute(ctx, run, plan)
}

func (m *Manager) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(m.workerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			m.drain(ctx)
		case <-ticker.C:
			m.drain(ctx)
		}
	}
}

func (m *Manager) drain(ctx context.Context) {
	for {
		processed, err := m.ProcessOne(ctx)
		if err != nil || !processed {
			return
		}
	}
}

func (m *Manager) execute(parent context.Context, run inspection.Run, plan inspection.ExecutionPlan) error {
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("inspection repository returned an invalid execution plan: %w", err)
	}
	if run.State != inspection.RunRunning || run.TenantID != plan.TenantID || run.SiteID != plan.SiteID ||
		run.RequestKey != plan.RequestKey || run.PlanSHA256 != plan.PlanSHA256 || !run.Deadline.Equal(plan.Deadline) {
		return errors.New("inspection repository returned a run outside its frozen execution plan")
	}
	ctx, cancel := context.WithDeadline(parent, plan.Deadline)
	runHeartbeat := m.startRunHeartbeat(run.RunID, cancel)
	defer func() {
		cancel()
		runHeartbeat.stop()
	}()

	for {
		if ctx.Err() != nil {
			return runHeartbeatOrContext(runHeartbeat, ctx)
		}
		record, attempt, ok, err := m.repository.ClaimNextStep(ctx, run.RunID, m.ownerID, m.ownerID, m.now().UTC(), m.lease)
		if err != nil {
			return err
		}
		if !ok {
			steps, err := m.repository.ListSteps(ctx, run.RunID)
			if err != nil {
				return err
			}
			if allStepsTerminal(steps) {
				if containsUnknownStep(steps) {
					// Keep the run recoverable. RecoverInterrupted will move it to
					// reconciliation_required after its lease expires.
					return nil
				}
				return m.finalizeRun(run, plan, steps, parent, ctx, runHeartbeat)
			}
			return errors.New("inspection step ledger has no runnable or terminal step")
		}
		step, found := planStep(plan, record.StepID)
		if !found || step.Sequence != record.Sequence || step.Kind != record.Kind || step.Authority != record.Authority {
			return errors.New("claimed inspection step is outside the frozen plan")
		}
		stepAuthority, authorityErr := inspectionauthority.StepAuthorityForPlan(step.Authority)
		authorization, lookupErr := m.authority.Lookup(ctx, run.RunID)
		identity := authorization.Identity
		wantIdentity, identityErr := inspectionauthority.ExecutionIdentityForOrigin(plan.Origin, identity.PrincipalSHA256)
		if authorityErr != nil || lookupErr != nil || identityErr != nil || wantIdentity != identity {
			m.failUnauthorizedStep(run.RunID, attempt.AttemptID)
			return ErrAuthorityRejected
		}
		if m.authority.VerifyAndConsume(ctx, authorization, inspectionauthority.StepDemand{
			Identity: identity, Authority: stepAuthority,
			TenantID: plan.TenantID, SiteID: plan.SiteID, RunID: run.RunID, PlanSHA256: plan.PlanSHA256,
			AssignmentID: plan.AssignmentID, AssignmentRevision: plan.AssignmentRevision,
			RequestKey: plan.RequestKey, RuntimeID: m.ownerID,
			StepID: step.StepID, AttemptID: attempt.AttemptID,
		}) != nil {
			m.failUnauthorizedStep(run.RunID, attempt.AttemptID)
			return ErrAuthorityRejected
		}
		if phase, ok := phaseForStep(step.Kind); ok {
			if err := m.repository.AppendPhase(ctx, run.RunID, m.ownerID, phase, m.now().UTC(), "step_"+string(step.Kind)); err != nil {
				return err
			}
		}
		stepCtx, stepCancel := context.WithDeadline(ctx, step.Deadline)
		if step.Kind == inspection.StepCleanup {
			var cleanupCancel context.CancelFunc
			stepCtx, cleanupCancel = context.WithTimeout(stepCtx, m.cleanupTTL)
			defer cleanupCancel()
		}
		stepHeartbeat := m.startStepHeartbeat(stepCtx, run.RunID, attempt.AttemptID, stepCancel)
		result := m.executeStep(stepCtx, run, plan, step, attempt)
		stepHeartbeat.stop()
		stepCancel()
		if heartbeatErr := stepHeartbeat.err(); heartbeatErr != nil {
			return heartbeatErr
		}
		if result.interrupted {
			return runHeartbeatOrContext(runHeartbeat, ctx)
		}
		completeContext, completeCancel := context.WithTimeout(context.Background(), defaultPersistenceTTL)
		err = m.repository.CompleteStep(completeContext, run.RunID, m.ownerID, attempt.AttemptID, m.ownerID,
			result.state, result.outputs, result.reason, m.now().UTC())
		completeCancel()
		if err != nil {
			return err
		}
	}
}

func (m *Manager) failUnauthorizedStep(runID, attemptID string) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultPersistenceTTL)
	defer cancel()
	_ = m.repository.CompleteStep(ctx, runID, m.ownerID, attemptID, m.ownerID,
		inspection.StepFailed, nil, "execution_authority_rejected", m.now().UTC())
}

func (m *Manager) finalizeRun(run inspection.Run, plan inspection.ExecutionPlan, steps []inspection.StepRecord, parent, execution context.Context, heartbeat *leaseHeartbeat) error {
	finalContext, cancel := context.WithTimeout(context.Background(), defaultPersistenceTTL)
	defer cancel()
	observations, err := m.repository.ListObservations(finalContext, run.RunID)
	if err != nil {
		return err
	}
	outcome, err := inspection.Evaluate(plan, observations)
	if err != nil {
		outcome = unknownOutcome(plan, "oracle_contract_invalid", "巡检结果无法完成确定性校验。")
	}
	for _, record := range steps {
		if record.State != inspection.StepFailed && record.State != inspection.StepSkipped {
			continue
		}
		if record.Kind == inspection.StepCleanup {
			outcome = unknownOutcome(plan, "cleanup_failed", "临时资源清理未能形成可信结果。")
			break
		}
		if record.Kind == inspection.StepResolveSource && len(observations) == 0 &&
			(record.Reason == "site_session_unavailable" || record.Reason == "execution_binding_stale" || record.Reason == "execution_resource_busy") {
			outcome.State = inspection.RunBlocked
			outcome.Reason = record.Reason
			outcome.Conclusion = "巡检没有进入有效设备执行。"
			continue
		}
		applyIncompleteOutcome(&outcome, len(observations), "execution_step_failed",
			"巡检仅形成部分可信观察，至少一个类型化执行步骤失败。",
			"巡检未形成可信观察，至少一个类型化执行步骤失败。")
	}
	if interruption, interrupted := classifyExecutionInterruption(parent, execution); interrupted {
		applyExecutionInterruption(&outcome, interruption, len(observations))
	}
	current, err := m.repository.GetRun(finalContext, run.RunID)
	if err != nil {
		return err
	}
	if current.CleanupPending > 0 {
		applyIncompleteOutcome(&outcome, len(observations), "cleanup_pending",
			"巡检形成了观察，但仍有已知临时资源待清理。",
			"巡检未形成可信观察，且仍有临时资源待核查。")
	}
	heartbeat.stop()
	if err := heartbeat.err(); err != nil {
		return err
	}
	finalizedAt := m.now().UTC()
	if err := m.repository.BeginFinalization(finalContext, run.RunID, m.ownerID, finalizedAt); err != nil {
		return err
	}
	if err := m.repository.Finalize(finalContext, run.RunID, m.ownerID, outcome, finalizedAt); err != nil {
		return err
	}
	return m.releaseAuthorityForRun(finalContext, run.RunID, finalizedAt)
}

func (m *Manager) releaseTerminalAuthorities(ctx context.Context, at time.Time) error {
	if at.IsZero() {
		return errors.New("inspection authority release time is required")
	}
	for {
		runIDs, err := m.repository.ListPendingAuthorityReleases(ctx, defaultAuthorityBatch)
		if err != nil {
			return err
		}
		if len(runIDs) == 0 {
			return nil
		}
		for _, runID := range runIDs {
			if err := m.releaseAuthorityForRun(ctx, runID, at); err != nil {
				return err
			}
		}
		if len(runIDs) < defaultAuthorityBatch {
			return nil
		}
	}
}

func (m *Manager) releaseAuthorityForRun(ctx context.Context, runID string, at time.Time) error {
	if err := m.authority.Revoke(ctx, runID); err != nil {
		return fmt.Errorf("revoke terminal inspection execution authority: %w", err)
	}
	if err := m.repository.MarkAuthorityReleased(ctx, runID, at); err != nil {
		return fmt.Errorf("acknowledge terminal inspection execution authority release: %w", err)
	}
	return nil
}

func unknownOutcome(plan inspection.ExecutionPlan, reason, conclusion string) inspection.Outcome {
	return inspection.Outcome{
		State: inspection.RunUnknown, OverallAssessment: inspection.AssessmentUncertain,
		Coverage: missingCoverage(plan), Findings: []inspection.Finding{}, Reason: reason, Conclusion: conclusion,
	}
}

func allStepsTerminal(records []inspection.StepRecord) bool {
	if len(records) == 0 {
		return false
	}
	for _, record := range records {
		if !record.State.Terminal() {
			return false
		}
	}
	return true
}

func containsUnknownStep(records []inspection.StepRecord) bool {
	for _, record := range records {
		if record.State == inspection.StepOutcomeUnknown {
			return true
		}
	}
	return false
}

type executionInterruption struct {
	state      inspection.RunState
	reason     string
	conclusion string
	empty      string
	limitation string
}

func classifyExecutionInterruption(parent, execution context.Context) (executionInterruption, bool) {
	if execution == nil || execution.Err() == nil {
		return executionInterruption{}, false
	}
	if parent != nil && parent.Err() != nil {
		return executionInterruption{state: inspection.RunUnknown, reason: executionContextCancelled,
			conclusion: "巡检执行上下文提前结束，已形成的观察不足以确认完整结果。",
			empty:      "巡检执行上下文提前结束，未形成可确认的可信观察。", limitation: executionContextCancelled}, true
	}
	if errors.Is(execution.Err(), context.DeadlineExceeded) {
		return executionInterruption{state: inspection.RunExpired, reason: "run_deadline_exceeded",
			conclusion: "巡检未能在截止时间前完成全部可信步骤。", empty: "巡检在截止时间前没有形成可信观察。"}, true
	}
	return executionInterruption{state: inspection.RunUnknown, reason: executionContextCancelled,
		conclusion: "巡检执行上下文提前结束，已形成的观察不足以确认完整结果。",
		empty:      "巡检执行上下文提前结束，未形成可确认的可信观察。", limitation: executionContextCancelled}, true
}

func applyExecutionInterruption(outcome *inspection.Outcome, interruption executionInterruption, observationCount int) {
	if outcome == nil {
		return
	}
	outcome.State, outcome.Reason, outcome.Conclusion = interruption.state, interruption.reason, interruption.conclusion
	if observationCount == 0 {
		outcome.Conclusion = interruption.empty
	}
	if interruption.limitation == "" {
		return
	}
	for index := range outcome.Findings {
		if containsString(outcome.Findings[index].Limitations, interruption.limitation) || len(outcome.Findings[index].Limitations) >= 16 {
			continue
		}
		outcome.Findings[index].Limitations = append(outcome.Findings[index].Limitations, interruption.limitation)
		sort.Strings(outcome.Findings[index].Limitations)
	}
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func applyIncompleteOutcome(outcome *inspection.Outcome, observationCount int, reason, partialConclusion, unknownConclusion string) {
	if outcome == nil || (outcome.State != inspection.RunCompleted && outcome.State != inspection.RunPartial) {
		return
	}
	outcome.State, outcome.Reason, outcome.Conclusion = inspection.RunPartial, reason, partialConclusion
	if observationCount == 0 {
		outcome.State, outcome.Conclusion = inspection.RunUnknown, unknownConclusion
	}
}

func missingCoverage(plan inspection.ExecutionPlan) inspection.Coverage {
	coverage := inspection.Coverage{}
	for _, target := range plan.Targets {
		coverage.Required += len(target.Criteria)
	}
	coverage.Missing = coverage.Required
	return coverage
}

type leaseHeartbeat struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	errVal error
}

func (m *Manager) startRunHeartbeat(runID string, cancelExecution context.CancelFunc) *leaseHeartbeat {
	ctx, cancel := context.WithCancel(context.Background())
	heartbeat := &leaseHeartbeat{cancel: cancel, done: make(chan struct{})}
	interval := m.lease / 3
	if interval <= 0 {
		interval = time.Millisecond
	}
	go func() {
		defer close(heartbeat.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.repository.RenewLease(ctx, runID, m.ownerID, m.now().UTC(), m.lease); err != nil {
					if ctx.Err() != nil {
						return
					}
					heartbeat.setErr(err)
					cancelExecution()
					return
				}
			}
		}
	}()
	return heartbeat
}

func (m *Manager) startStepHeartbeat(parent context.Context, runID, attemptID string, cancelExecution context.CancelFunc) *leaseHeartbeat {
	ctx, cancel := context.WithCancel(parent)
	heartbeat := &leaseHeartbeat{cancel: cancel, done: make(chan struct{})}
	interval := m.lease / 4
	if interval <= 0 {
		interval = time.Millisecond
	}
	go func() {
		defer close(heartbeat.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := m.now().UTC()
				if err := m.repository.RenewStepAttemptLease(ctx, runID, m.ownerID, attemptID, m.ownerID, now, m.lease); err != nil {
					if ctx.Err() != nil {
						return
					}
					heartbeat.setErr(err)
					cancelExecution()
					return
				}
			}
		}
	}()
	return heartbeat
}

func (h *leaseHeartbeat) setErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.errVal == nil {
		h.errVal = err
	}
}

func (h *leaseHeartbeat) stop() {
	if h == nil {
		return
	}
	h.cancel()
	<-h.done
}

func (h *leaseHeartbeat) err() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.errVal
}

func runHeartbeatOrContext(heartbeat *leaseHeartbeat, ctx context.Context) error {
	if err := heartbeat.err(); err != nil {
		return err
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return context.Canceled
}

func planStep(plan inspection.ExecutionPlan, stepID string) (inspection.ExecutionStep, bool) {
	for _, step := range plan.Steps {
		if step.StepID == stepID {
			return step, true
		}
	}
	return inspection.ExecutionStep{}, false
}

func phaseForStep(kind inspection.StepKind) (inspection.RunPhase, bool) {
	switch kind {
	case inspection.StepResolveSource, inspection.StepReadExisting:
		return inspection.PhaseResolving, true
	case inspection.StepAcquireMedia, inspection.StepOpenMedia, inspection.StepTransformMedia:
		return inspection.PhaseCapturing, true
	case inspection.StepAnalyze:
		return inspection.PhaseAnalyzing, true
	case inspection.StepValidateResult:
		return inspection.PhaseValidating, true
	case inspection.StepAggregate:
		return inspection.PhaseComposing, true
	case inspection.StepCleanup:
		return inspection.PhaseCleaning, true
	default:
		return "", false
	}
}

func randomID(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate inspection id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(buffer), nil
}
