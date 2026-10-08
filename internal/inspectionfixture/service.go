package inspectionfixture

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/channelauth"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/schedule"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionhost"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionproduct"
)

type Service struct {
	config  Config
	assets  assets
	digest  string
	product *inspectionproduct.Product
	host    *inspectionhost.Host

	mu    sync.RWMutex
	ports *fixturePorts
}

func New(config Config) (*Service, error) {
	normalized, err := config.normalized()
	if err != nil {
		return nil, err
	}
	fixtureAssets, err := loadAssets(normalized.AssetRoot)
	if err != nil {
		return nil, err
	}
	material, err := readTokenMaterial(normalized.TokenFile)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte("cosmoedge-offline-fixture-authority-v1"))
	signer, err := authority.NewSigner("offline-fixture-authority", key[:])
	if err != nil {
		return nil, err
	}
	service := &Service{config: normalized, assets: fixtureAssets, digest: material.digest}
	acquirer := replayingTemporaryAcquirer{inner: newTemporaryAcquirer(fixtureAssets)}
	builders := inspectionproduct.Builders{
		StandardRuntime: func(ctx context.Context, resources inspectionproduct.Resources, execution inspectionproduct.ExecutionBinding) (inspectionproduct.StandardRuntime, error) {
			if _, err := seedCatalog(ctx, normalized, fixtureAssets, resources.Catalog, resources.Runs); err != nil {
				return nil, err
			}
			ports, err := newFixturePorts(normalized, fixtureAssets, resources.Media, resources.Catalog)
			if err != nil {
				return nil, err
			}
			manager, err := inspectionruntime.New(resources.Runs, execution.Authority(), ports.Ports(),
				inspectionruntime.WithRuntimeID(execution.RuntimeID()),
				inspectionruntime.WithWorkerTick(normalized.WorkerInterval),
			)
			if err != nil {
				return nil, err
			}
			service.mu.Lock()
			service.ports = ports
			service.mu.Unlock()
			return manager, nil
		},
		TemporaryRuntime: func(_ context.Context, resources inspectionproduct.Resources, preparations inspectionproduct.MediaPreparationReader) (inspectionproduct.TemporaryRuntime, error) {
			return temporary.NewManager(resources.Temporary, preparations, temporaryMediaReader{store: resources.Media}, temporaryAnalyzer{}, time.Now)
		},
		ApplicationBackend: func(ctx context.Context, resources inspectionproduct.Resources, operator inspectionproduct.OperatorServices,
			standard inspectionproduct.StandardRuntime, temporaryRuntime inspectionproduct.TemporaryRuntime,
			registrar inspectionproduct.MediaPreparationRegistrar) (inspectionproduct.ApplicationBackend, error) {
			if err := ensureChannelBinding(ctx, resources.ChannelAuth, material.digest, normalized); err != nil {
				return nil, err
			}
			planner, err := planning.New(planning.Config{
				Registry: resources.Runs, Catalog: resources.Catalog,
				Authorities: staticAuthorities{config: normalized}, Interactions: operator.InteractionRegistrar(),
				Interpreter: closedInterpreter{clipWindowSeconds: int(fixtureAssets.clipDuration / 1000)}, MediaCompiler: temporaryCompiler{},
				Now: time.Now, CatalogFactTTL: 24 * time.Hour, DefaultRunTTL: 5 * time.Minute,
			})
			if err != nil {
				return nil, err
			}
			return application.New(application.Config{
				Capabilities: planner, Planner: planner, Runner: standard, Repository: resources.Runs,
				TemporaryRunner: temporaryRuntime, TemporaryRepository: temporaryRuntime, TemporaryMedia: registrar,
				InstalledTasks: resources.Catalog, Projector: fixtureProjector{
					inner: application.NewBusinessResultProjector(), store: resources.Media,
					clipFrameSHA256: digestBytes(fixtureAssets.clipFrame),
					clipFrameOffset: fixtureAssets.clipFrameOffset,
				},
				Media: resources.Media, State: resources.Application, Now: time.Now,
				MediaCapabilityTTL: 10 * time.Minute, MediaAudience: MediaAudience,
			})
		},
		OutboxMaterializer: func(_ context.Context, resources inspectionproduct.Resources, builder delivery.TerminalMessageBuilder) (inspectionproduct.OutboxMaterializer, error) {
			materializer, err := delivery.NewMaterializer(delivery.MaterializerConfig{
				Outbox: resources.Runs, Deliveries: resources.Delivery, Builder: builder,
				Owner: "offline-fixture-materializer", LeaseTTL: time.Second, Now: time.Now,
			})
			if err != nil {
				return nil, err
			}
			return materializer, nil
		},
		DeliveryDispatcher: func(_ context.Context, resources inspectionproduct.Resources) (inspectionproduct.DeliveryDispatcher, error) {
			transport := fixtureDeliveryTransport{}
			return delivery.NewDispatcher(delivery.DispatcherConfig{
				Store: resources.Delivery, Transport: transport, Reconciler: transport,
				Owner: "offline-fixture-delivery", LeaseTTL: time.Second,
				SendTimeout: 250 * time.Millisecond, LookupTimeout: 250 * time.Millisecond, Now: time.Now,
			})
		},
		ScheduleCoordinator: func(_ context.Context, schedules *schedule.Store, bridge inspectionproduct.ScheduleBridge) (inspectionproduct.ScheduleCoordinator, error) {
			return schedule.NewCoordinator(schedule.CoordinatorConfig{
				Store: schedules, Planner: schedule.NewPlanner(schedule.SystemClock{}, schedule.SystemZoneLoader{}, signer),
				AuthorityProvider: noScheduleAuthority{}, AuthorityVerifier: signer,
				Submitter: bridge, RunObserver: bridge, OwnerID: "offline-fixture-scheduler",
				Lease: time.Second, Now: time.Now,
			})
		},
	}
	factories := inspectionproduct.PersistentFactories(signer, acquirer, builders)
	factories.OpenCredentials = func(ctx context.Context, root string) (inspectionproduct.Opened[credential.SecretStore], error) {
		if err := ctx.Err(); err != nil {
			return inspectionproduct.Opened[credential.SecretStore]{}, err
		}
		store, err := openFixtureCredentialStore(filepath.Join(root, "fixture-authority-secrets.db"), material.credentialKey)
		if err != nil {
			return inspectionproduct.Opened[credential.SecretStore]{}, err
		}
		return inspectionproduct.Opened[credential.SecretStore]{Value: store, Close: store.Close}, nil
	}
	product, err := inspectionproduct.New(inspectionproduct.Config{
		Enabled: true, StateRoot: normalized.StateRoot,
		WorkerInterval:  normalized.WorkerInterval,
		MediaGCInterval: time.Hour, HandoffRecoveryInterval: time.Hour,
		TemporaryWorkerInterval:        normalized.WorkerInterval,
		TemporaryWorkerOwner:           "offline-fixture-temporary",
		TemporaryLeaseTTL:              time.Second,
		MediaPreparationWorkerInterval: normalized.WorkerInterval,
		MediaPreparationWorkerOwner:    "offline-fixture-media-preparation",
		ExecutionAuthorityIssuerID:     "offline-fixture-execution-authority",
		ExecutionRuntimeID:             "offline-fixture-runtime",
	}, factories)
	if err != nil {
		return nil, err
	}
	host, err := inspectionhost.New(inspectionhost.Config{Enabled: true, Address: normalized.Address}, product)
	if err != nil {
		return nil, err
	}
	service.product, service.host = product, host
	return service, nil
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || s.host == nil {
		return errors.New("fixture service is unavailable")
	}
	return s.host.Start(ctx)
}

func (s *Service) Stop() error {
	if s == nil || s.host == nil {
		return nil
	}
	return s.host.Stop()
}

func (s *Service) Readiness() inspectionhost.Readiness {
	if s == nil || s.host == nil {
		return inspectionhost.Readiness{State: inspectionhost.StateFailed, Failure: "fixture_unavailable"}
	}
	return s.host.Readiness()
}

func (s *Service) RuntimeStats() RuntimeStats {
	if s == nil {
		return RuntimeStats{}
	}
	s.mu.RLock()
	ports := s.ports
	s.mu.RUnlock()
	if ports == nil {
		return RuntimeStats{}
	}
	return ports.Stats()
}

func ensureChannelBinding(ctx context.Context, store *channelauth.Store, credentialDigest string, config Config) error {
	scopes := append([]httpapi.Scope(nil), config.ChannelScopes...)
	session := config.session()
	bound := true
	for _, scope := range scopes {
		authorization, err := store.Authorize(ctx, httpapi.AuthorizationRequest{Scope: scope, CredentialSHA256: credentialDigest})
		if errors.Is(err, httpapi.ErrUnauthenticated) {
			bound = false
			break
		}
		if err != nil {
			return err
		}
		if authorization.Session != session || authorization.Scope != scope {
			return errors.New("fixture token is already bound to another session")
		}
	}
	if bound {
		return nil
	}
	now := time.Now().UTC()
	_, _, err := store.Bind(ctx, channelauth.Binding{
		CredentialSHA256: credentialDigest, Session: session, Scopes: scopes,
		CreatedAt: now, ExpiresAt: now.Add(365 * 24 * time.Hour),
	})
	return err
}
