package inspectionfixture

import (
	"context"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/schedule"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
)

type fixtureDeliveryTransport struct{}

func (fixtureDeliveryTransport) Send(ctx context.Context, request delivery.SendRequest) (delivery.SendResult, error) {
	if err := ctx.Err(); err != nil {
		return delivery.SendResult{}, err
	}
	return delivery.SendResult{Outcome: delivery.SendDelivered, ReceiptRef: deterministicRef("receipt", request.DeliveryID)}, nil
}

func (fixtureDeliveryTransport) Lookup(ctx context.Context, request delivery.ReconciliationRequest) (delivery.Reconciliation, string, error) {
	if err := ctx.Err(); err != nil {
		return delivery.ReconciliationUnknown, "delivery_lookup_cancelled", err
	}
	return delivery.ReconciliationDelivered, deterministicRef("receipt", request.DeliveryID), nil
}

type noScheduleAuthority struct{}

func (noScheduleAuthority) AuthorityFor(context.Context, schedule.Occurrence) (authority.Grant, bool, error) {
	return authority.Grant{}, false, nil
}

var (
	_ delivery.Transport         = fixtureDeliveryTransport{}
	_ delivery.Reconciler        = fixtureDeliveryTransport{}
	_ schedule.AuthorityProvider = noScheduleAuthority{}
)
