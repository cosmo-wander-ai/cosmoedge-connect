// Package inspectionlive assembles the snapshot-first Inspection v2 service
// against the foreground CosmoEdge Operator connection. It contains no
// fixture or synthetic fallback.
package inspectionlive

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const (
	DefaultAddress = "127.0.0.1:37789"

	TenantID          = "tenant-cosmoedge-live"
	SiteID            = "site-current-device"
	DeviceProfileID   = "dpf_86ada3d536c17b313c52b04502050804"
	CreateOperationID = "onb_146a8abd7de77406fe13d82ee1849618"
	SourceHandle      = "source-current-camera"

	SourceAlias    = "当前现场"
	ObservableName = "现场情况"
	MediaAudience  = "workbuddy-wechat-live"

	channel         = "workbuddy_wechat"
	conversationRef = "workbuddy-wechat-local"
	recipientRef    = "local-user"
)

var (
	ErrConnectionRequired = errors.New("local CosmoEdge connection is required")
	ErrCameraUnavailable  = errors.New("connected CosmoEdge device has no usable camera")
)

// SnapshotReader is the read-only foreground device view needed to refresh
// the protected source catalog. session.Vault implements it directly.
type SnapshotReader interface {
	Read(context.Context) (device.Snapshot, error)
}

type Config struct {
	StateRoot       string
	TokenFile       string
	Address         string
	Snapshots       SnapshotReader
	Connections     inspectionadapter.ConnectionProvider
	Sessions        *session.Vault
	OpenInteraction func(capability, handoffRef string) error

	WorkerInterval time.Duration
}

func (c Config) normalized() (Config, error) {
	c.StateRoot = strings.TrimSpace(c.StateRoot)
	c.TokenFile = strings.TrimSpace(c.TokenFile)
	c.Address = strings.TrimSpace(c.Address)
	if c.Address == "" {
		c.Address = DefaultAddress
	}
	if c.WorkerInterval == 0 {
		c.WorkerInterval = 100 * time.Millisecond
	}
	if c.StateRoot == "" || c.TokenFile == "" || c.Snapshots == nil || c.Connections == nil || c.Sessions == nil {
		return Config{}, errors.New("live inspection state, token, session Vault, snapshot reader, and connection provider are required")
	}
	if c.WorkerInterval <= 0 || c.WorkerInterval > time.Minute {
		return Config{}, errors.New("live inspection worker interval is invalid")
	}
	return c, nil
}

func sessionBinding() httpapi.SessionBinding {
	return httpapi.SessionBinding{
		TenantID: TenantID, SiteID: SiteID, Channel: channel,
		ConversationRef: conversationRef, RecipientRef: recipientRef,
		PrincipalSHA256: digestText("workbuddy-wechat-local-principal-v1"),
	}
}
