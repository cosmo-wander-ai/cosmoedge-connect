package device

import (
	"context"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
)

// StagedPictureClient is the explicit exact-byte upload seam. Older clients
// remain usable for other operations, but cannot silently fall back to base64
// when a journaled observation requires staging.
type StagedPictureClient interface {
	QueryUploadCapabilitiesContext(context.Context) (adapter.UploadCapabilities, error)
	UploadPictureJPEGContext(context.Context, adapter.StagedPictureUploadRequest) (adapter.StagedPictureUpload, error)
	CancelPictureUploadContext(context.Context, adapter.StagedPictureUpload) error
}

func (c *v1Client) QueryUploadCapabilitiesContext(ctx context.Context) (adapter.UploadCapabilities, error) {
	return c.client.QueryUploadCapabilitiesContext(ctx)
}

func (c *v1Client) UploadPictureJPEGContext(ctx context.Context, request adapter.StagedPictureUploadRequest) (adapter.StagedPictureUpload, error) {
	return c.client.UploadPictureJPEGContext(ctx, request)
}

func (c *v1Client) CancelPictureUploadContext(ctx context.Context, upload adapter.StagedPictureUpload) error {
	return c.client.CancelPictureUploadContext(ctx, upload)
}

var _ StagedPictureClient = (*v1Client)(nil)
