package inspectiontest

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/changeflow"
	operatorauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

type gateChangePorts struct {
	mu        sync.Mutex
	sequence  []string
	proposals []changeflow.ProposalInput
	publishes []changeflow.PublicationRequest
}

func (p *gateChangePorts) ProposePersistentChange(_ context.Context, input changeflow.ProposalInput) (changeflow.Proposal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence = append(p.sequence, "proposal:"+input.RequestID)
	p.proposals = append(p.proposals, input)
	return changeflow.Proposal{
		ActionID: "action-" + input.RequestID, LocalHandoffRef: "handoff-" + input.RequestID,
		ExpiresAt: time.Now().UTC().Add(2 * time.Minute),
	}, nil
}

func (p *gateChangePorts) ReadAction(_ context.Context, actionID string) (changeflow.ActionStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence = append(p.sequence, "readback:"+actionID)
	return changeflow.ActionStatus{
		ActionID: actionID, State: changeflow.ActionSucceeded,
		EvidenceRef: "evidence-" + actionID, ReadbackSHA256: gateDigest("readback:" + actionID),
		DeviceWrites: 1, ObservedAt: time.Now().UTC(),
	}, nil
}

func (p *gateChangePorts) RefreshAfterAction(_ context.Context, request changeflow.RefreshRequest) (changeflow.RefreshResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence = append(p.sequence, "catalog:"+request.WorkflowID)
	return changeflow.RefreshResult{
		ActionID: request.ActionID, CatalogFingerprint: gateDigest("catalog:" + request.WorkflowID),
		RefreshedAt: time.Now().UTC(),
	}, nil
}

func (p *gateChangePorts) PublishAfterRefresh(_ context.Context, request changeflow.PublicationRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence = append(p.sequence, "publish:"+request.WorkflowID)
	p.publishes = append(p.publishes, request)
	return nil
}

func (p *gateChangePorts) snapshot() ([]string, []changeflow.ProposalInput, []changeflow.PublicationRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.sequence...), append([]changeflow.ProposalInput(nil), p.proposals...),
		append([]changeflow.PublicationRequest(nil), p.publishes...)
}

func TestV212PersistentChangeEntriesConvergeOnOneProfileBoundary(t *testing.T) {
	now := time.Now().UTC()
	principal := gateDigest("change-principal")
	signer, err := operatorauthority.NewSigner("gate-change-authority", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	grant, err := signer.Issue(
		"gate-change-grant", operatorauthority.PersistentDeviceWrite, principal,
		operatorauthority.Scope{
			TenantID: gateTenantID, SiteID: gateSiteID, DeviceProfileID: "profile-gate",
			OperationKinds: []string{operatorauthority.OpTaskDeploy},
		},
		now.Add(-time.Minute), now.Add(10*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	ports := &gateChangePorts{}
	service, err := changeflow.New(signer, ports, ports, ports, ports, changeflow.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"skill-entry", "onsite-entry"} {
		request := changeflow.Request{
			RequestID: entry, TenantID: gateTenantID, SiteID: gateSiteID,
			DeviceProfileID: "profile-gate", PrincipalSHA256: principal,
			OperationKind: operatorauthority.OpTaskDeploy,
			RequestedAt:   now.Add(-time.Second), RequestExpiresAt: now.Add(5 * time.Minute),
		}
		summary, err := service.Propose(context.Background(), request, grant)
		if err != nil || summary.State != changeflow.StateAwaitingLocalConfirmation || !summary.InteractionRequired {
			t.Fatalf("%s proposal=%+v err=%v", entry, summary, err)
		}
		summary, err = service.Advance(context.Background(), summary.WorkflowRef)
		if err != nil || summary.State != changeflow.StateReadyToPublish || !summary.CatalogRefreshed {
			t.Fatalf("%s advance=%+v err=%v", entry, summary, err)
		}
		fingerprint := gateDigest("catalog:" + summary.WorkflowRef)
		summary, err = service.Publish(context.Background(), summary.WorkflowRef, "assignment-"+entry, fingerprint)
		if err != nil || summary.State != changeflow.StatePublished || !summary.Published {
			t.Fatalf("%s publish=%+v err=%v", entry, summary, err)
		}
	}
	sequence, proposals, publishes := ports.snapshot()
	if len(proposals) != 2 || len(publishes) != 2 ||
		proposals[0].DeviceProfileID != "profile-gate" || proposals[1].DeviceProfileID != "profile-gate" {
		t.Fatalf("changeflow did not converge on one device profile: proposals=%+v publishes=%+v", proposals, publishes)
	}
	wantPrefixes := []string{
		"proposal:skill-entry", "readback:action-skill-entry", "catalog:", "publish:",
		"proposal:onsite-entry", "readback:action-onsite-entry", "catalog:", "publish:",
	}
	if len(sequence) != len(wantPrefixes) {
		t.Fatalf("changeflow sequence=%v", sequence)
	}
	for index, prefix := range wantPrefixes {
		if len(sequence[index]) < len(prefix) || sequence[index][:len(prefix)] != prefix {
			t.Fatalf("changeflow sequence[%d]=%q want prefix %q; all=%v", index, sequence[index], prefix, sequence)
		}
	}
	for index := range proposals {
		if proposals[index].TenantID != gateTenantID || proposals[index].SiteID != gateSiteID ||
			proposals[index].OperationKind != operatorauthority.OpTaskDeploy ||
			publishes[index].TenantID != gateTenantID || publishes[index].SiteID != gateSiteID {
			t.Fatalf("persistent change escaped its protected profile boundary: proposal=%+v publish=%+v", proposals[index], publishes[index])
		}
	}
	implemented := []any{
		changeflow.ProposalCreator(ports), changeflow.ActionReader(ports),
		changeflow.CatalogRefresher(ports), changeflow.AssignmentPublisher(ports),
	}
	if len(implemented) != 4 || reflect.TypeOf(ports).NumMethod() != 4 {
		t.Fatalf("test boundary unexpectedly exposes a confirmation/dispatch method: %s", fmt.Sprint(reflect.TypeOf(ports)))
	}
}
