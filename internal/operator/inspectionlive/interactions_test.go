package inspectionlive

import (
	"context"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
)

func TestOpeningRegistrarOpensOnlyExactlyAcknowledgedDurableHandoff(t *testing.T) {
	expires := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	request := planning.LocalInteractionRegistration{
		Type: planning.LocalInteractionConnection, TenantID: "tenant-a", SiteID: "site-a",
		PrincipalSHA256: digestText("principal-a"), HandoffRef: "handoff_exact", ExpiresAt: expires,
	}
	inner := &openingRegistrarFixture{}
	var capability, handoff string
	registrar := openingRegistrar{inner: inner, open: func(gotCapability, gotHandoff string) error {
		capability, handoff = gotCapability, gotHandoff
		return nil
	}}
	receipt, err := registrar.Register(context.Background(), request)
	if err != nil || receipt.HandoffRef != request.HandoffRef || inner.calls != 1 ||
		capability != httpapi.InteractionCapabilityOnboarding || handoff != request.HandoffRef {
		t.Fatalf("receipt=%#v err=%v calls=%d opened=(%q,%q)", receipt, err, inner.calls, capability, handoff)
	}

	capability, handoff = "", ""
	inner.mutate = func(receipt *planning.LocalInteractionReceipt) { receipt.HandoffRef = "handoff_mismatch" }
	if _, err := registrar.Register(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if capability != "" || handoff != "" {
		t.Fatalf("mismatched acknowledgment opened (%q,%q)", capability, handoff)
	}
}

type openingRegistrarFixture struct {
	calls  int
	mutate func(*planning.LocalInteractionReceipt)
}

func (f *openingRegistrarFixture) Register(_ context.Context, request planning.LocalInteractionRegistration) (planning.LocalInteractionReceipt, error) {
	f.calls++
	receipt := planning.LocalInteractionReceipt{Type: request.Type, HandoffRef: request.HandoffRef, ExpiresAt: request.ExpiresAt}
	if f.mutate != nil {
		f.mutate(&receipt)
	}
	return receipt, nil
}
