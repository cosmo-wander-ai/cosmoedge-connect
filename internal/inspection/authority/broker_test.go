package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

func TestSubmissionPrivatelyFreezesValidatedRequest(t *testing.T) {
	request := validSubmissionRequest()
	request.Origin = inspection.OriginSchedule
	identity, err := NewExecutionIdentity(IdentityService, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	submission, err := NewSubmission(request, identity)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := submission.PlanRequest()
	if err != nil {
		t.Fatal(err)
	}
	prepared.TargetIDs[0] = "mutated"
	prepared.Variables["area"] = "mutated"
	again, err := submission.PlanRequest()
	if err != nil || again.TargetIDs[0] != "target-a" || again.Variables["area"] != "dining" {
		t.Fatalf("submission was mutable: %#v, %v", again, err)
	}
	if _, err := (Submission{}).PlanRequest(); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("zero submission error=%v", err)
	}
}

func TestSubmissionRejectsActorServiceOriginConfusion(t *testing.T) {
	actor, err := NewExecutionIdentity(IdentityActor, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewExecutionIdentity(IdentityService, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	user := validSubmissionRequest()
	scheduled := validSubmissionRequest()
	scheduled.Origin = inspection.OriginSchedule
	for name, test := range map[string]struct {
		request  inspection.CreateRunRequest
		identity ExecutionIdentity
	}{
		"service as user":  {request: user, identity: service},
		"actor as service": {request: scheduled, identity: actor},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSubmission(test.request, test.identity); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("identity/origin confusion error=%v", err)
			}
		})
	}
}

func TestEphemeralBrokerBindsAndConsumesExactStepAuthority(t *testing.T) {
	at := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &authorityTestClock{now: at}
	broker := newTestBroker(t, 2*time.Minute, clock.Now)
	authorization, created, err := broker.Issue(context.Background(), fixtureIssueDemand(IdentityActor, "run-a", at))
	if err != nil || !created {
		t.Fatal(err)
	}
	if authorization.Identity.Kind != IdentityActor || authorization.Identity.PrincipalSHA256 == "" || authorization.ExpiresAt.Sub(at) != 2*time.Minute {
		t.Fatalf("actor authorization=%+v", authorization)
	}
	lookedUp, err := broker.Lookup(context.Background(), authorization.RunID)
	if err != nil || lookedUp.AuthorizationID != authorization.AuthorizationID {
		t.Fatalf("lookup=%+v error=%v", lookedUp, err)
	}
	lookedUp.Steps[0].Authority = StepAuthorityInspectionExecution
	again, _ := broker.Lookup(context.Background(), authorization.RunID)
	if again.Steps[0].Authority == lookedUp.Steps[0].Authority {
		t.Fatal("lookup returned broker-owned step storage")
	}

	clock.now = at.Add(time.Second)
	demand := fixtureStepDemand(authorization, "step-a", StepAuthorityDeviceRead)
	for name, mutate := range map[string]func(*StepDemand){
		"identity":   func(value *StepDemand) { value.Identity.Kind = IdentityService },
		"principal":  func(value *StepDemand) { value.Identity.PrincipalSHA256 = strings.Repeat("d", 64) },
		"authority":  func(value *StepDemand) { value.Authority = StepAuthorityInspectionExecution },
		"tenant":     func(value *StepDemand) { value.TenantID = "tenant-b" },
		"site":       func(value *StepDemand) { value.SiteID = "site-b" },
		"run":        func(value *StepDemand) { value.RunID = "run-b" },
		"plan":       func(value *StepDemand) { value.PlanSHA256 = strings.Repeat("e", 64) },
		"assignment": func(value *StepDemand) { value.AssignmentID = "assignment-b" },
		"revision":   func(value *StepDemand) { value.AssignmentRevision++ },
		"request":    func(value *StepDemand) { value.RequestKey = "req_" + strings.Repeat("f", 32) },
		"runtime":    func(value *StepDemand) { value.RuntimeID = "worker-b" },
		"step":       func(value *StepDemand) { value.StepID = "step-b" },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := demand
			mutate(&wrong)
			if err := broker.VerifyAndConsume(context.Background(), authorization, wrong); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("wrong binding error=%v", err)
			}
		})
	}
	forged := authorization
	forged.PlanSHA256 = strings.Repeat("e", 64)
	if err := broker.VerifyAndConsume(context.Background(), forged, demand); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("forged authorization error=%v", err)
	}
	if err := broker.VerifyAndConsume(context.Background(), authorization, demand); err != nil {
		t.Fatalf("first exact consume error=%v", err)
	}
	if err := broker.VerifyAndConsume(context.Background(), authorization, demand); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestEphemeralBrokerRejectsExpiryWrongPrincipalAndRevocation(t *testing.T) {
	at := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &authorityTestClock{now: at}
	actor := newTestBroker(t, time.Second, clock.Now)
	authorization, _, err := actor.Issue(context.Background(), fixtureIssueDemand(IdentityActor, "run-expiry", at))
	if err != nil {
		t.Fatal(err)
	}
	clock.now = authorization.ExpiresAt
	expired := fixtureStepDemand(authorization, "step-a", StepAuthorityDeviceRead)
	if err := actor.VerifyAndConsume(context.Background(), authorization, expired); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expiry error=%v", err)
	}
	if err := actor.Revoke(context.Background(), authorization.RunID); err != nil {
		t.Fatal(err)
	}
	if err := actor.Revoke(context.Background(), authorization.RunID); err != nil {
		t.Fatalf("idempotent revocation error=%v", err)
	}
	clock.now = at.Add(time.Millisecond)
	fresh := fixtureStepDemand(authorization, "step-a", StepAuthorityDeviceRead)
	if err := actor.VerifyAndConsume(context.Background(), authorization, fresh); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked authorization error=%v", err)
	}
	if _, _, err := actor.Issue(context.Background(), fixtureIssueDemand(IdentityActor, authorization.RunID, at)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked run reissue error=%v", err)
	}

	service := newTestBroker(t, time.Minute, clock.Now)
	issued, _, err := service.Issue(context.Background(), fixtureIssueDemand(IdentityService, "run-service", at))
	if err != nil || issued.Identity.Kind != IdentityService || issued.Identity.PrincipalSHA256 == "" {
		t.Fatalf("service authorization=%+v error=%v", issued, err)
	}
}

func TestEphemeralBrokerConsumesOneConcurrentReplay(t *testing.T) {
	at := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &authorityTestClock{now: at}
	broker := newTestBroker(t, time.Minute, clock.Now)
	authorization, _, err := broker.Issue(context.Background(), fixtureIssueDemand(IdentityActor, "run-concurrent", at))
	if err != nil {
		t.Fatal(err)
	}
	clock.now = at.Add(time.Second)
	demand := fixtureStepDemand(authorization, "step-a", StepAuthorityDeviceRead)
	const workers = 32
	start := make(chan struct{})
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- broker.VerifyAndConsume(context.Background(), authorization, demand)
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, replays := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrUnauthorized) {
			replays++
		} else {
			t.Fatalf("unexpected consume error=%v", err)
		}
	}
	if successes != 1 || replays != workers-1 {
		t.Fatalf("successes=%d replays=%d", successes, replays)
	}
}

func TestEphemeralBrokerIssueIsExactIdempotentAndNeverWidens(t *testing.T) {
	at := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &authorityTestClock{now: at}
	broker := newTestBroker(t, time.Minute, clock.Now)
	demand := fixtureIssueDemand(IdentityActor, "run-idempotent", at)
	first, created, err := broker.Issue(context.Background(), demand)
	if err != nil || !created {
		t.Fatalf("first Issue()=(%+v,%v,%v)", first, created, err)
	}
	clock.now = at.Add(time.Second)
	replayed, created, err := broker.Issue(context.Background(), demand)
	if err != nil || created || replayed.AuthorizationID != first.AuthorizationID || replayed.ProofSHA256 != first.ProofSHA256 {
		t.Fatalf("replayed Issue()=(%+v,%v,%v), first=%+v", replayed, created, err, first)
	}

	for name, mutate := range map[string]func(*IssueDemand){
		"runtime":  func(value *IssueDemand) { value.RuntimeID = "worker-b" },
		"plan":     func(value *IssueDemand) { value.PlanSHA256 = strings.Repeat("e", 64) },
		"scope":    func(value *IssueDemand) { value.Steps[0].Authority = StepAuthorityNone },
		"identity": func(value *IssueDemand) { value.Identity.PrincipalSHA256 = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := demand
			changed.Steps = cloneStepScopes(demand.Steps)
			mutate(&changed)
			if _, _, err := broker.Issue(context.Background(), changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("changed Issue() error=%v", err)
			}
		})
	}
	stored, err := broker.Lookup(context.Background(), demand.RunID)
	if err != nil || stored.AuthorizationID != first.AuthorizationID {
		t.Fatalf("conflict replaced active authorization: %+v, %v", stored, err)
	}
}

func TestEphemeralBrokerExpiredExactAuthorityCanBeReissued(t *testing.T) {
	at := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &authorityTestClock{now: at}
	broker := newTestBroker(t, time.Second, clock.Now)
	demand := fixtureIssueDemand(IdentityActor, "run-reissue", at)
	first, _, err := broker.Issue(context.Background(), demand)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = at.Add(2 * time.Second)
	second, created, err := broker.Issue(context.Background(), demand)
	if err != nil || !created || second.AuthorizationID == first.AuthorizationID || !second.IssuedAt.Equal(clock.now) {
		t.Fatalf("reissued Issue()=(%+v,%v,%v), first=%+v", second, created, err, first)
	}
	if err := broker.VerifyAndConsume(context.Background(), first, fixtureStepDemand(first, "step-a", StepAuthorityDeviceRead)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired authorization survived reissue: %v", err)
	}
}

func TestEphemeralBrokerReissueDoesNotForgetConsumedRunAttempt(t *testing.T) {
	at := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &authorityTestClock{now: at}
	broker := newTestBroker(t, time.Second, clock.Now)
	demand := fixtureIssueDemand(IdentityActor, "run-consumption-tombstone", at)
	first, _, err := broker.Issue(context.Background(), demand)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = at.Add(500 * time.Millisecond)
	consumed := fixtureStepDemand(first, "step-a", StepAuthorityDeviceRead)
	if err := broker.VerifyAndConsume(context.Background(), first, consumed); err != nil {
		t.Fatal(err)
	}
	clock.now = at.Add(2 * time.Second)
	second, created, err := broker.Issue(context.Background(), demand)
	if err != nil || !created || second.AuthorizationID == first.AuthorizationID {
		t.Fatalf("reissue=(%+v,%v,%v)", second, created, err)
	}
	replayed := fixtureStepDemand(second, "step-a", StepAuthorityDeviceRead)
	if err := broker.VerifyAndConsume(context.Background(), second, replayed); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("consumed attempt replay after reissue error=%v", err)
	}
	fresh := replayed
	fresh.AttemptID = "attempt-step-a-2"
	if err := broker.VerifyAndConsume(context.Background(), second, fresh); err != nil {
		t.Fatalf("fresh attempt after reissue error=%v", err)
	}
}

func TestEphemeralBrokerAuthorityLifetimeIsBoundedByRunDeadlineNotFiveMinutes(t *testing.T) {
	at := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &authorityTestClock{now: at}
	broker := newTestBroker(t, 30*time.Minute, clock.Now)
	demand := fixtureIssueDemand(IdentityActor, "run-long", at)
	demand.Deadline = at.Add(2 * time.Hour)
	authorization, _, err := broker.Issue(context.Background(), demand)
	if err != nil || !authorization.ExpiresAt.Equal(at.Add(30*time.Minute)) {
		t.Fatalf("long authority expiry=%s err=%v", authorization.ExpiresAt, err)
	}

	deadlineBound := fixtureIssueDemand(IdentityActor, "run-deadline-bound", at)
	deadlineBound.Deadline = at.Add(12 * time.Minute)
	authorization, _, err = broker.Issue(context.Background(), deadlineBound)
	if err != nil || !authorization.ExpiresAt.Equal(deadlineBound.Deadline) {
		t.Fatalf("deadline-bounded authority expiry=%s err=%v", authorization.ExpiresAt, err)
	}
}

func newTestBroker(t *testing.T, ttl time.Duration, now func() time.Time) *EphemeralBroker {
	t.Helper()
	broker, err := NewEphemeralBroker("test-broker", []byte(strings.Repeat("k", 32)), ttl, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Close)
	return broker
}

func validSubmissionRequest() inspection.CreateRunRequest {
	requestedAt := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	return inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: "tenant-a", SiteID: "site-a",
		TemplateID: "template-a", TemplateRevision: 1, AssignmentID: "assignment-a", AssignmentRevision: 1,
		Origin: inspection.OriginUser, RequestID: "request-a", TargetIDs: []string{"target-a"},
		Variables: map[string]string{"area": "dining"}, RequestedAt: requestedAt, Deadline: requestedAt.Add(5 * time.Minute),
	}
}

func fixtureIssueDemand(kind ExecutionIdentityKind, runID string, at time.Time) IssueDemand {
	return IssueDemand{
		Identity: ExecutionIdentity{Kind: kind, PrincipalSHA256: strings.Repeat("a", 64)},
		TenantID: "tenant-a", SiteID: "site-a", RunID: runID,
		PlanSHA256: strings.Repeat("b", 64), AssignmentID: "assignment-a", AssignmentRevision: 1,
		RequestKey: "req_" + strings.Repeat("c", 32), RuntimeID: "worker-a",
		Steps: []StepScope{
			{StepID: "step-b", Authority: StepAuthorityInspectionExecution},
			{StepID: "step-a", Authority: StepAuthorityDeviceRead},
		},
		Deadline: at.Add(5 * time.Minute),
	}
}

func fixtureStepDemand(authorization Authorization, stepID string, stepAuthority StepAuthority) StepDemand {
	return StepDemand{
		Identity: authorization.Identity, Authority: stepAuthority,
		TenantID: authorization.TenantID, SiteID: authorization.SiteID, RunID: authorization.RunID,
		PlanSHA256: authorization.PlanSHA256, AssignmentID: authorization.AssignmentID,
		AssignmentRevision: authorization.AssignmentRevision, RequestKey: authorization.RequestKey,
		RuntimeID: authorization.RuntimeID, StepID: stepID, AttemptID: "attempt-a",
	}
}

func TestExecutionIdentityAndAuthorizationAreNotProjectable(t *testing.T) {
	identity := ExecutionIdentity{Kind: IdentityActor, PrincipalSHA256: strings.Repeat("a", 64)}
	for _, value := range []any{identity, Authorization{Identity: identity}} {
		if raw, err := json.Marshal(value); !errors.Is(err, ErrProtectedIdentityProjection) || len(raw) != 0 {
			t.Fatalf("protected authority projection raw=%q err=%v", raw, err)
		}
		projected := fmt.Sprintf("%v %+v %#v", value, value, value)
		if strings.Contains(projected, identity.PrincipalSHA256) {
			t.Fatalf("protected identity leaked through formatting: %s", projected)
		}
	}
}

type authorityTestClock struct {
	now time.Time
}

func (c *authorityTestClock) Now() time.Time { return c.now }
