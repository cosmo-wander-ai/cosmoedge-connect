package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
)

func newContinuationBackend(t *testing.T, statuses []inspection.RunState, request httpapi.InspectionRequest) (*Backend, []string) {
	t.Helper()
	ctx := context.Background()
	state, err := OpenState(testStateConfig(protectedStatePath(t, "continuation-state.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	repository, err := inspectionstore.Open(protectedStatePath(t, "continuation-runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	refs := make([]string, 0, len(statuses))
	for index, status := range statuses {
		// Equal timestamps exercise the public-reference tie-break across pages.
		createdAt := stateTestTime
		ref := fmt.Sprintf("continuation-public-%02d", index)
		runtimeID := fmt.Sprintf("continuation-runtime-%02d", index)
		raw, digest, err := canonicalRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		record, created, err := state.ReserveRequest(ctx, RequestReservation{
			Session: testSession(), IdempotencyKey: fmt.Sprintf("continuation-key-%d", index),
			RequestJSON: raw, RequestSHA256: digest, PublicRunRef: ref,
			RuntimeRequestID: fmt.Sprintf("continuation-request-%d", index), CreatedAt: createdAt,
		})
		if err != nil || !created {
			t.Fatalf("reserve %d: created=%v err=%v", index, created, err)
		}
		decision := freezeStateTestDecision(t, state, record, createdAt)
		plan, err := inspection.CompilePlan(decision.Template, decision.Assignment, decision.RunRequest)
		if err != nil {
			t.Fatal(err)
		}
		if _, created, err := repository.CreateQueuedRun(ctx, plan, runtimeID, createdAt); err != nil || !created {
			t.Fatalf("create runtime %d: created=%v err=%v", index, created, err)
		}
		if _, changed, err := state.BindRun(ctx, testSession(), ref, runtimeID, createdAt); err != nil || !changed {
			t.Fatalf("bind %d: changed=%v err=%v", index, changed, err)
		}
		switch status {
		case inspection.RunCancelled:
			if err := repository.Cancel(ctx, runtimeID, createdAt, "user_cancelled"); err != nil {
				t.Fatal(err)
			}
		case inspection.RunRunning:
			run, _, claimed, err := repository.ClaimNext(ctx, "continuation-worker", createdAt, time.Minute)
			if err != nil || !claimed || run.RunID != runtimeID {
				t.Fatalf("claim %d: run=%+v claimed=%v err=%v", index, run, claimed, err)
			}
		default:
			t.Fatalf("unsupported fixture status %s", status)
		}
		refs = append(refs, ref)
	}
	backend := newBackendFixture(t, state, &plannerStub{}, &runnerStub{}, repository, &mediaStub{}, stateTestTime.Add(time.Minute))
	return backend, refs
}

func TestBackendContinuationFindsWorkingRunAfterTerminalHistory(t *testing.T) {
	backend, refs := newContinuationBackend(t, []inspection.RunState{
		inspection.RunCancelled, inspection.RunCancelled, inspection.RunCancelled,
		inspection.RunCancelled, inspection.RunCancelled, inspection.RunRunning,
	}, httpapi.InspectionRequest{Instruction: "查看入口通行情况"})
	view, err := backend.GetRun(context.Background(), testSession(), refs[5])
	if err != nil || view.Status != httpapi.RunWorking {
		t.Fatalf("sixth run precondition: status=%s err=%v", view.Status, err)
	}
	resolution, err := backend.ResolveContinuation(context.Background(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Status != httpapi.ContinuationResolved || resolution.Run == nil || resolution.Run.RunRef != refs[5] {
		t.Fatalf("expected sixth working run %q after terminal history; got status=%s run=%+v", refs[5], resolution.Status, resolution.Run)
	}
}

func TestBackendContinuationKeepsAmbiguityPastTerminalHistory(t *testing.T) {
	backend, _ := newContinuationBackend(t, []inspection.RunState{
		inspection.RunRunning, inspection.RunCancelled, inspection.RunCancelled,
		inspection.RunCancelled, inspection.RunCancelled, inspection.RunRunning,
	}, httpapi.InspectionRequest{Instruction: "查看入口通行情况"})
	resolution, err := backend.ResolveContinuation(context.Background(), testSession())
	if err != nil || resolution.Status != httpapi.ContinuationAmbiguous || len(resolution.Candidates) != 2 {
		t.Fatalf("expected two eligible candidates; got status=%s candidates=%d err=%v", resolution.Status, len(resolution.Candidates), err)
	}
	for _, change := range []func(*httpapi.SessionBinding){
		func(s *httpapi.SessionBinding) { s.TenantID = "other-tenant" },
		func(s *httpapi.SessionBinding) { s.SiteID = "other-site" },
		func(s *httpapi.SessionBinding) { s.Channel = "codex" },
		func(s *httpapi.SessionBinding) { s.ConversationRef = "other-conversation" },
		func(s *httpapi.SessionBinding) { s.RecipientRef = "other-recipient" },
		func(s *httpapi.SessionBinding) { s.PrincipalSHA256 = testDigest("other-principal") },
	} {
		other := testSession()
		change(&other)
		resolution, err := backend.ResolveContinuation(context.Background(), other)
		if err != nil || resolution.Status != httpapi.ContinuationNone || len(resolution.Candidates) != 0 || resolution.Run != nil {
			t.Fatalf("another Session Binding received candidates: %+v err=%v", resolution, err)
		}
	}
}

type continuationRunReadAuthorizer struct{}

func (continuationRunReadAuthorizer) Authorize(_ context.Context, request httpapi.AuthorizationRequest) (httpapi.Authorization, error) {
	if request.Scope != httpapi.ScopeRunRead || request.CredentialSHA256 != testDigest(strings.Repeat("a", 64)) {
		return httpapi.Authorization{}, httpapi.ErrForbidden
	}
	return httpapi.Authorization{Session: testSession(), Scope: httpapi.ScopeRunRead}, nil
}

func TestBackendContinuationBoundsLongBusinessDescriptions(t *testing.T) {
	backend, _ := newContinuationBackend(t, []inspection.RunState{inspection.RunRunning, inspection.RunRunning}, httpapi.InspectionRequest{
		Instruction: "查看\t" + strings.Repeat("观察", 100),
		Context:     []httpapi.BusinessContext{{Name: "区域", Value: "区域\t" + strings.Repeat("入口", 50)}},
	})
	handler, err := httpapi.NewHandler(backend, continuationRunReadAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/inspection/continuation", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid long business input must yield clarification, got HTTP %d: %s", response.Code, response.Body.String())
	}
	var resolution httpapi.ContinuationResolution
	if err := json.Unmarshal(response.Body.Bytes(), &resolution); err != nil {
		t.Fatal(err)
	}
	if resolution.Status != httpapi.ContinuationAmbiguous || len(resolution.Candidates) != 2 {
		t.Fatalf("expected two clarification candidates: %+v", resolution)
	}
	for _, candidate := range resolution.Candidates {
		if len(candidate.Area) == 0 || len(candidate.Area) > 256 || !utf8.ValidString(candidate.Area) ||
			len(candidate.Goal) == 0 || len(candidate.Goal) > 512 || !utf8.ValidString(candidate.Goal) ||
			strings.Contains(candidate.Area+candidate.Goal, "\t") {
			t.Fatalf("candidate descriptions must be bounded UTF-8: %+v", candidate)
		}
	}
}

func TestBackendContinuationCandidatesCarryExactSessionRunReferences(t *testing.T) {
	backend, refs := newContinuationBackend(t, []inspection.RunState{inspection.RunRunning, inspection.RunRunning}, httpapi.InspectionRequest{Instruction: "查看入口通行情况"})
	handler, err := httpapi.NewHandler(backend, continuationRunReadAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/inspection/continuation", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("candidate response HTTP %d: %s", response.Code, response.Body.String())
	}
	var resolution struct {
		Status     httpapi.ContinuationStatus `json:"status"`
		Candidates []struct {
			RunRef string `json:"runRef"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &resolution); err != nil {
		t.Fatal(err)
	}
	if resolution.Status != httpapi.ContinuationAmbiguous || len(resolution.Candidates) != len(refs) {
		t.Fatalf("expected ambiguous candidates: %+v", resolution)
	}
	for index, candidate := range resolution.Candidates {
		if candidate.RunRef != refs[index] {
			t.Fatalf("candidate %d must carry its selectable opaque reference %q; got %q", index, refs[index], candidate.RunRef)
		}
		view, err := backend.GetRun(context.Background(), testSession(), candidate.RunRef)
		if err != nil || view.RunRef != refs[index] || view.Status != httpapi.RunWorking {
			t.Fatalf("explicit candidate read: %+v err=%v", view, err)
		}
		other := testSession()
		other.ConversationRef = "another-conversation"
		if _, err := backend.GetRun(context.Background(), other, candidate.RunRef); !errors.Is(err, httpapi.ErrNotFound) {
			t.Fatalf("cross-conversation candidate read must be not found: %v", err)
		}
	}
}

func TestBackendContinuationLimitsAmbiguityToFourEligibleCandidates(t *testing.T) {
	backend, refs := newContinuationBackend(t, []inspection.RunState{
		inspection.RunRunning, inspection.RunRunning, inspection.RunRunning,
		inspection.RunRunning, inspection.RunRunning, inspection.RunRunning,
	}, httpapi.InspectionRequest{Instruction: "查看入口通行情况"})
	resolution, err := backend.ResolveContinuation(context.Background(), testSession())
	if err != nil || resolution.Status != httpapi.ContinuationAmbiguous || len(resolution.Candidates) != 4 {
		t.Fatalf("expected four bounded candidates: %+v err=%v", resolution, err)
	}
	for index, candidate := range resolution.Candidates {
		if candidate.RunRef != refs[index] {
			t.Fatalf("candidate %d reference=%q, want %q", index, candidate.RunRef, refs[index])
		}
	}
}
