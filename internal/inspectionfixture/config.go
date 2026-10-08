package inspectionfixture

import (
	"errors"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
)

const (
	DefaultAddress = "127.0.0.1:37790"

	TenantID       = "tenant-offline-fixture"
	SiteID         = "site-offline-fixture"
	SourceAlias    = "公共区域"
	TaskAlias      = "现场状态任务"
	ObservableName = "现场状态"
	MediaAudience  = "offline-fixture-audience"

	InstructionExisting = "使用现有任务查看公共区域状态"
	InstructionSnapshot = "拍摄快照查看公共区域状态"
	InstructionClip     = "截取视频查看公共区域状态"
	InstructionHybrid   = "结合现有任务和快照查看公共区域状态"
	InstructionNatural  = "帮我查看公共区域的现场状态"
)

type Config struct {
	StateRoot string
	AssetRoot string
	TokenFile string
	Address   string

	TenantID        string
	SiteID          string
	ConversationRef string
	RecipientRef    string
	PrincipalSHA256 string
	ChannelScopes   []httpapi.Scope

	WorkerInterval time.Duration
}

func (c Config) normalized() (Config, error) {
	c.StateRoot = strings.TrimSpace(c.StateRoot)
	c.AssetRoot = strings.TrimSpace(c.AssetRoot)
	c.TokenFile = strings.TrimSpace(c.TokenFile)
	c.Address = strings.TrimSpace(c.Address)
	if c.Address == "" {
		c.Address = DefaultAddress
	}
	if c.TenantID == "" {
		c.TenantID = TenantID
	}
	if c.SiteID == "" {
		c.SiteID = SiteID
	}
	if c.ConversationRef == "" {
		c.ConversationRef = "offline-fixture-conversation"
	}
	if c.RecipientRef == "" {
		c.RecipientRef = "offline-fixture-recipient"
	}
	if c.PrincipalSHA256 == "" {
		c.PrincipalSHA256 = digest("offline-fixture-principal")
	}
	if len(c.ChannelScopes) == 0 {
		c.ChannelScopes = []httpapi.Scope{
			httpapi.ScopeCapabilitiesRead, httpapi.ScopeFeedbackCreate, httpapi.ScopeMediaDeliver,
			httpapi.ScopeRequestCreate, httpapi.ScopeResultRead, httpapi.ScopeRunRead,
		}
	} else {
		c.ChannelScopes = append([]httpapi.Scope(nil), c.ChannelScopes...)
	}
	if c.WorkerInterval == 0 {
		c.WorkerInterval = 20 * time.Millisecond
	}
	if c.StateRoot == "" || c.AssetRoot == "" || c.TokenFile == "" {
		return Config{}, errors.New("fixture state root, asset root, and token file are required")
	}
	if c.WorkerInterval <= 0 || c.WorkerInterval > time.Minute {
		return Config{}, errors.New("fixture worker interval is invalid")
	}
	return c, nil
}

func (c Config) session() httpapi.SessionBinding {
	return httpapi.SessionBinding{
		TenantID: c.TenantID, SiteID: c.SiteID, Channel: "workbuddy_wechat",
		ConversationRef: c.ConversationRef, RecipientRef: c.RecipientRef,
		PrincipalSHA256: c.PrincipalSHA256,
	}
}
