package inspectionlocal

import "context"

// Application is the narrow generation-bound local-page surface. Product may
// wrap Service with lifecycle admission without exposing its private
// onboarding or interaction stores.
type Application interface {
	Resolve(context.Context, LocalSession) (Interaction, error)
	CompleteConnection(context.Context, LocalSession, CompleteConnectionRequest) (Interaction, error)
	CompleteVerifiedConnection(context.Context, LocalSession) (Interaction, error)
	PreparePersistentTransfer(context.Context, LocalSession, PersistentTransferRequest) (Interaction, error)
	MarkPersistentTransferred(context.Context, LocalSession, PersistentTransferRequest) (Interaction, error)
}

var _ Application = (*Service)(nil)
