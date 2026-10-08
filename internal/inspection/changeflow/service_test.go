package changeflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

type fixturePorts struct {
	mu            sync.Mutex
	proposal      Proposal
	status        ActionStatus
	refresh       RefreshResult
	proposalCalls int
	refreshCalls  int
	publishCalls  int
	lastPublish   PublicationRequest
}

func (p *fixturePorts) ProposePersistentChange(_ context.Context, _ ProposalInput) (Proposal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proposalCalls++
	return p.proposal, nil
}

func (p *fixturePorts) ReadAction(_ context.Context, actionID string) (ActionStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := p.status
	result.ActionID = actionID
	return result, nil
}

func (p *fixturePorts) RefreshAfterAction(_ context.Context, _ RefreshRequest) (RefreshResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refreshCalls++
	return p.refresh, nil
}

func (p *fixturePorts) PublishAfterRefresh(_ context.Context, request PublicationRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.publishCalls++
	p.lastPublish = request
	return nil
}

func TestConfirmedReadbackRefreshesCatalogBeforeAssignmentPublication(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer, grant := persistentGrant(t, now)
	defer signer.Close()
	ports := &fixturePorts{
		proposal: Proposal{ActionID: "action_deploy_1", LocalHandoffRef: "handoff_local_1", ExpiresAt: now.Add(10 * time.Minute)},
		status:   ActionStatus{State: ActionSucceeded, EvidenceRef: "evidence_readback_1", ReadbackSHA256: strings.Repeat("b", 64), DeviceWrites: 1, ObservedAt: now.Add(time.Minute)},
		refresh:  RefreshResult{ActionID: "action_deploy_1", CatalogFingerprint: strings.Repeat("c", 64), RefreshedAt: now.Add(3 * time.Minute)},
	}
	service, err := New(signer, ports, ports, ports, ports, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	current := now
	service.now = func() time.Time { return current }
	request := fixtureRequest(now)
	summary, err := service.Propose(context.Background(), request, grant)
	if err != nil || summary.State != StateAwaitingLocalConfirmation || !summary.InteractionRequired || summary.LocalHandoffRef == "" {
		t.Fatalf("proposal summary=%#v err=%v", summary, err)
	}
	current = now.Add(3 * time.Minute)
	summary, err = service.Advance(context.Background(), summary.WorkflowRef)
	if err != nil || summary.State != StateReadyToPublish || !summary.CatalogRefreshed || summary.Published {
		t.Fatalf("advanced summary=%#v err=%v", summary, err)
	}
	if _, err := service.Publish(context.Background(), summary.WorkflowRef, "assignment_dining_v2", strings.Repeat("d", 64)); !errors.Is(err, ErrNotPublishable) {
		t.Fatalf("publication with stale catalog error=%v", err)
	}
	summary, err = service.Publish(context.Background(), summary.WorkflowRef, "assignment_dining_v2", strings.Repeat("c", 64))
	if err != nil || summary.State != StatePublished || !summary.Published {
		t.Fatalf("published summary=%#v err=%v", summary, err)
	}
	if ports.proposalCalls != 1 || ports.refreshCalls != 1 || ports.publishCalls != 1 ||
		ports.lastPublish.CatalogFingerprint != strings.Repeat("c", 64) {
		t.Fatalf("ports=%#v", ports)
	}
}

func TestInspectionExecutionCannotProposePersistentWrite(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer, err := authority.NewSigner("cosmoedge-connect-authority", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	principal := digest("principal-a")
	grant, err := signer.Issue("grant-inspection", authority.InspectionExecution, principal, authority.Scope{
		TenantID: "tenant-a", SiteID: "site-a", RunID: "run-a", SourceHandles: []string{"source-a"},
		OperationKinds: []string{authority.OpSourceAcquire}, MaxFrames: 10, MaxBytes: 1 << 20, MaxDurationSeconds: 60,
	}, now.Add(-time.Minute), now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	ports := &fixturePorts{proposal: Proposal{ActionID: "action-1", LocalHandoffRef: "handoff-1", ExpiresAt: now.Add(5 * time.Minute)}}
	service, err := New(signer, ports, ports, ports, ports, NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	request := fixtureRequest(now)
	request.PrincipalSHA256 = principal
	if _, err := service.Propose(context.Background(), request, grant); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("inspection grant error=%v", err)
	}
	if ports.proposalCalls != 0 {
		t.Fatal("unauthorized inspection grant reached the Operator proposal port")
	}
}

func TestUnknownActionNeverRefreshesOrPublishes(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer, grant := persistentGrant(t, now)
	defer signer.Close()
	ports := &fixturePorts{
		proposal: Proposal{ActionID: "action-unknown", LocalHandoffRef: "handoff-unknown", ExpiresAt: now.Add(5 * time.Minute)},
		status:   ActionStatus{State: ActionOutcomeUnknown, DeviceWrites: 0, ObservedAt: now.Add(time.Minute)},
	}
	service, _ := New(signer, ports, ports, ports, ports, NewMemoryStore())
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	summary, err := service.Propose(context.Background(), fixtureRequest(now), grant)
	if err != nil {
		t.Fatal(err)
	}
	summary, err = service.Advance(context.Background(), summary.WorkflowRef)
	if err != nil || summary.State != StateOutcomeUnknown {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
	if ports.refreshCalls != 0 || ports.publishCalls != 0 {
		t.Fatal("unknown action crossed the catalog or publication boundary")
	}
	if _, err := service.Publish(context.Background(), summary.WorkflowRef, "assignment-a", strings.Repeat("c", 64)); !errors.Is(err, ErrNotPublishable) {
		t.Fatalf("unknown publication error=%v", err)
	}
}

func TestSuccessfulActionWithoutReadbackFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer, grant := persistentGrant(t, now)
	defer signer.Close()
	ports := &fixturePorts{
		proposal: Proposal{ActionID: "action-no-proof", LocalHandoffRef: "handoff-no-proof", ExpiresAt: now.Add(5 * time.Minute)},
		status:   ActionStatus{State: ActionSucceeded, DeviceWrites: 1, ObservedAt: now.Add(time.Minute)},
	}
	service, _ := New(signer, ports, ports, ports, ports, NewMemoryStore())
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	summary, err := service.Propose(context.Background(), fixtureRequest(now), grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Advance(context.Background(), summary.WorkflowRef); err == nil {
		t.Fatal("successful action without trusted readback was accepted")
	}
	if ports.refreshCalls != 0 {
		t.Fatal("unproven action refreshed the catalog")
	}
}

func TestProtectedRecordCannotLeakThroughJSONProjection(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer, grant := persistentGrant(t, now)
	defer signer.Close()
	store := NewMemoryStore()
	ports := &fixturePorts{proposal: Proposal{ActionID: "private-action", LocalHandoffRef: "handoff-public", ExpiresAt: now.Add(5 * time.Minute)}}
	service, _ := New(signer, ports, ports, ports, ports, store)
	service.now = func() time.Time { return now }
	summary, err := service.Propose(context.Background(), fixtureRequest(now), grant)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(context.Background(), summary.WorkflowRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(record); !errors.Is(err, ErrProtectedRecord) {
		t.Fatalf("protected record marshal error=%v", err)
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-action", "tenant-a", "profile-a", "readback", "grant-write"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("summary leaked %q: %s", forbidden, raw)
		}
	}
}

func TestFileStoreSurvivesRestartAcrossProposalRefreshAndPublication(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	path := changeflowStorePath(t, "workflows.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	signer, grant := persistentGrant(t, now)
	defer signer.Close()
	ports := &fixturePorts{
		proposal: Proposal{ActionID: "action_restart", LocalHandoffRef: "handoff_restart", ExpiresAt: now.Add(10 * time.Minute)},
		status:   ActionStatus{State: ActionSucceeded, EvidenceRef: "evidence_restart", ReadbackSHA256: strings.Repeat("b", 64), DeviceWrites: 1, ObservedAt: now.Add(time.Minute)},
		refresh:  RefreshResult{ActionID: "action_restart", CatalogFingerprint: strings.Repeat("c", 64), RefreshedAt: now.Add(3 * time.Minute)},
	}
	service, _ := New(signer, ports, ports, ports, ports, store)
	current := now
	service.now = func() time.Time { return current }
	summary, err := service.Propose(context.Background(), fixtureRequest(now), grant)
	if err != nil {
		t.Fatal(err)
	}
	store, err = OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service, _ = New(signer, ports, ports, ports, ports, store)
	current = now.Add(3 * time.Minute)
	service.now = func() time.Time { return current }
	summary, err = service.Advance(context.Background(), summary.WorkflowRef)
	if err != nil || summary.State != StateReadyToPublish {
		t.Fatalf("advance after restart summary=%#v err=%v", summary, err)
	}
	store, err = OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service, _ = New(signer, ports, ports, ports, ports, store)
	current = now.Add(4 * time.Minute)
	service.now = func() time.Time { return current }
	summary, err = service.Publish(context.Background(), summary.WorkflowRef, "assignment_restart", strings.Repeat("c", 64))
	if err != nil || summary.State != StatePublished {
		t.Fatalf("publish after restart summary=%#v err=%v", summary, err)
	}
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := reopened.Get(context.Background(), summary.WorkflowRef)
	if err != nil || record.State != StatePublished || record.Revision != 4 {
		t.Fatalf("reopened record=%#v err=%v", record, err)
	}
}

func TestFileStoreRejectsDigestTamperUnsafePathAndWeakPermissions(t *testing.T) {
	path := changeflowStorePath(t, "tamper.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	signer, grant := persistentGrant(t, now)
	defer signer.Close()
	ports := &fixturePorts{proposal: Proposal{ActionID: "action_tamper", LocalHandoffRef: "handoff_tamper", ExpiresAt: now.Add(5 * time.Minute)}}
	service, _ := New(signer, ports, ports, ports, ports, store)
	service.now = func() time.Time { return now }
	if _, err := service.Propose(context.Background(), fixtureRequest(now), grant); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), "operator_proposal_created", "operator_proposal_changed", 1)
	if tampered == string(raw) {
		t.Fatal("fixture store did not contain the expected record")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered store error=%v", err)
	}
	if _, err := OpenFileStore(path + "?unsafe=1"); err == nil {
		t.Fatal("changeflow store accepted a query-bearing path")
	}
	if runtime.GOOS != "windows" {
		permissionPath := changeflowStorePath(t, "permissions.json")
		if _, err := OpenFileStore(permissionPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(permissionPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(permissionPath); err == nil {
			t.Fatal("changeflow store silently repaired a weak existing file")
		}
	}
}

func persistentGrant(t *testing.T, now time.Time) (*authority.Signer, authority.Grant) {
	t.Helper()
	signer, err := authority.NewSigner("cosmoedge-connect-authority", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := signer.Issue("grant-write", authority.PersistentDeviceWrite, digest("principal-a"), authority.Scope{
		TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "profile-a",
		OperationKinds: []string{authority.OpTaskDeploy},
	}, now.Add(-time.Minute), now.Add(15*time.Minute))
	if err != nil {
		signer.Close()
		t.Fatal(err)
	}
	return signer, grant
}

func fixtureRequest(now time.Time) Request {
	return Request{
		RequestID: "request-deploy-1", TenantID: "tenant-a", SiteID: "site-a", DeviceProfileID: "profile-a",
		PrincipalSHA256: digest("principal-a"), OperationKind: authority.OpTaskDeploy,
		RequestedAt: now.Add(-time.Minute), RequestExpiresAt: now.Add(10 * time.Minute),
	}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func changeflowStorePath(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "changeflow-state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, name)
}
