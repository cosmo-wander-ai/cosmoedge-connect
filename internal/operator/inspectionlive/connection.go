package inspectionlive

import (
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

var (
	ErrPictureAlgorithmUnavailable = livevision.ErrPictureAlgorithmUnavailable
	ErrPictureVersionUnavailable   = livevision.ErrPictureVersionUnavailable
)

// NewVaultConnections retains the legacy default camera behavior. New business
// composition can bind a specific source through livevision.NewVaultConnectionsForSource.
func NewVaultConnections(vault *session.Vault) (inspectionadapter.ConnectionProvider, error) {
	return livevision.NewVaultConnections(vault)
}
