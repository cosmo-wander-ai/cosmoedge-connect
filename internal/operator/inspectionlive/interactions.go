package inspectionlive

import (
	"context"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
)

type openingRegistrar struct {
	inner planning.LocalInteractionRegistrar
	open  func(capability, handoffRef string) error
}

func (r openingRegistrar) Register(ctx context.Context, request planning.LocalInteractionRegistration) (planning.LocalInteractionReceipt, error) {
	receipt, err := r.inner.Register(ctx, request)
	if err != nil {
		return planning.LocalInteractionReceipt{}, err
	}
	// Never open a page until the protected registrar has acknowledged every
	// exact field that the planner will subsequently verify.
	if receipt.Type != request.Type || receipt.HandoffRef != request.HandoffRef || receipt.ExpiresAt != request.ExpiresAt || r.open == nil {
		return receipt, nil
	}
	capability := ""
	switch request.Type {
	case planning.LocalInteractionConnection:
		capability = httpapi.InteractionCapabilityOnboarding
	case planning.LocalInteractionPersistentChange:
		capability = httpapi.InteractionCapabilityPersistentChange
	}
	if capability != "" {
		// Opening is a foreground convenience after durable registration. An
		// unavailable browser must not erase the recoverable handoff returned to
		// the channel.
		_ = r.open(capability, receipt.HandoffRef)
	}
	return receipt, nil
}

var _ planning.LocalInteractionRegistrar = openingRegistrar{}
