// Package connectionowner composes one persistent connection generation without
// inspection Product, scheduling, planning, media or delivery dependencies.
package connectionowner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionbridge"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

var ErrNotStarted = errors.New("shared connection owner is not started")

type Binding struct {
	TenantID          string
	SiteID            string
	PrincipalSHA256   string
	ProfileID         string
	CreateOperationID string
	Alias             string
}

// DefaultBinding preserves the existing local device profile and principal.
func DefaultBinding() Binding {
	principal := sha256.Sum256([]byte("workbuddy-wechat-local-principal-v1"))
	return Binding{
		TenantID: "tenant-cosmoedge-live", SiteID: "site-current-device",
		PrincipalSHA256:   hex.EncodeToString(principal[:]),
		ProfileID:         "dpf_86ada3d536c17b313c52b04502050804",
		CreateOperationID: "onb_146a8abd7de77406fe13d82ee1849618", Alias: "当前现场",
	}
}

type Config struct {
	StateRoot string
	TokenFile string
	Vault     *session.Vault
	Binding   Binding // Zero selects DefaultBinding.
}

// Owner owns only the credential, profile, current selection and onboarding journal handles. The
// injected Vault is shared with business services; Stop releases its persistence
// generation and disconnects it before closing any durable resource.
type Owner struct {
	mu           sync.RWMutex
	config       Config
	lease        *Lease
	material     *TokenMaterial
	signer       *authority.Signer
	credentials  *credential.EncryptedFileStore
	profiles     *profile.Store
	current      *connectionregistry.CurrentStore
	journal      *onboarding.Journal
	registry     *connectionregistry.Registry
	bridge       *connectionbridge.Lifecycle
	restoreState connectionregistry.RestoreState
}

func New(config Config) (*Owner, error) {
	if strings.TrimSpace(config.StateRoot) == "" || strings.TrimSpace(config.TokenFile) == "" || config.Vault == nil {
		return nil, errors.New("shared connection state, token file and Vault are required")
	}
	if config.Binding == (Binding{}) {
		config.Binding = DefaultBinding()
	}
	return &Owner{config: config}, nil
}

func (o *Owner) Start(ctx context.Context) (connectionregistry.RestoreState, error) {
	if o == nil || ctx == nil {
		return "", ErrNotStarted
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lease != nil {
		return "", ErrAlreadyOwned
	}
	var err error
	if o.lease, err = AcquireLease(o.config.StateRoot); err != nil {
		return "", err
	}
	fail := func(err error) (connectionregistry.RestoreState, error) { return "", errors.Join(err, o.closeLocked()) }
	if o.material, err = ReadTokenMaterial(o.config.TokenFile); err != nil {
		return fail(err)
	}
	if o.signer, err = o.material.NewSigner("inspection-live-local-authority"); err != nil {
		return fail(err)
	}
	root := filepath.Join(o.config.StateRoot, "inspection-v2")
	if err = localstate.PrepareStateRoot(root); err != nil {
		return fail(err)
	}
	if o.credentials, err = o.material.OpenCredentials(ctx, filepath.Join(root, "credentials")); err != nil {
		return fail(err)
	}
	if o.profiles, err = profile.Open(filepath.Join(root, "device-profiles.db")); err != nil {
		return fail(err)
	}
	currentPath := filepath.Join(root, "current-connection.db")
	if _, statErr := os.Lstat(currentPath); errors.Is(statErr, os.ErrNotExist) {
		retained, listErr := o.profiles.ListSite(ctx, o.config.Binding.TenantID, o.config.Binding.SiteID)
		if listErr != nil {
			return fail(listErr)
		}
		// Only first-run/single-profile migration may seed the historical
		// default. Losing the selector after replacement cannot revive A/epoch1.
		if len(retained) > 1 || len(retained) == 1 && retained[0].ProfileID != o.config.Binding.ProfileID {
			return fail(connectionregistry.ErrSavedConnectionAttention)
		}
	}
	if o.current, err = connectionregistry.OpenCurrentStore(currentPath, o.config.Binding.ProfileID); err != nil {
		return fail(err)
	}
	if o.journal, err = onboarding.OpenJournal(filepath.Join(root, "onboarding-journal.db")); err != nil {
		return fail(err)
	}
	core, err := onboarding.NewService(o.profiles, o.credentials, o.journal, o.signer)
	if err != nil {
		return fail(err)
	}
	b := o.config.Binding
	o.registry, err = connectionregistry.New(connectionregistry.Config{
		Current:  o.current,
		Profiles: o.profiles, Credentials: o.credentials, Onboarding: core, Issuer: o.signer,
		TenantID: b.TenantID, SiteID: b.SiteID, PrincipalSHA256: b.PrincipalSHA256,
		ProfileID: b.ProfileID, CreateOperationID: b.CreateOperationID, Alias: b.Alias,
	})
	if err != nil {
		return fail(err)
	}
	if o.bridge, err = connectionbridge.New(o.config.Vault, o.registry); err != nil {
		return fail(err)
	}
	if o.restoreState, err = o.bridge.StartWithRestoreTimeout(ctx, 10*time.Second); err != nil {
		return fail(err)
	}
	return o.restoreState, nil
}

func (o *Owner) RestoreState() (connectionregistry.RestoreState, error) {
	if o == nil {
		return "", ErrNotStarted
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.restoreState == "" {
		return "", ErrNotStarted
	}
	return o.restoreState, nil
}

func (o *Owner) TokenDigest() (string, error) {
	if o == nil {
		return "", ErrNotStarted
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.restoreState == "" || o.material == nil {
		return "", ErrNotStarted
	}
	return o.material.Digest(), nil
}

func (o *Owner) VerifyCurrent(ctx context.Context) error {
	if o == nil {
		return ErrNotStarted
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.restoreState == "" || o.registry == nil {
		return ErrNotStarted
	}
	return o.registry.VerifyCurrent(ctx)
}

// Stop must follow business worker shutdown. A still-connecting Vault prevents
// release; keep all resources and the root lease intact so Stop can be retried.
func (o *Owner) Stop() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closeLocked()
}

func (o *Owner) closeLocked() error {
	if o.bridge != nil {
		if err := o.bridge.Stop(); err != nil {
			return err
		}
		o.bridge = nil
	}
	o.restoreState = ""
	o.registry = nil
	var err error
	if o.journal != nil {
		err = errors.Join(err, o.journal.Close())
		o.journal = nil
	}
	if o.profiles != nil {
		err = errors.Join(err, o.profiles.Close())
		o.profiles = nil
	}
	if o.current != nil {
		err = errors.Join(err, o.current.Close())
		o.current = nil
	}
	if o.credentials != nil {
		err = errors.Join(err, o.credentials.Close())
		o.credentials = nil
	}
	if o.signer != nil {
		o.signer.Close()
		o.signer = nil
	}
	if o.material != nil {
		o.material.Close()
		o.material = nil
	}
	if o.lease != nil {
		err = errors.Join(err, o.lease.Close())
		o.lease = nil
	}
	return err
}
