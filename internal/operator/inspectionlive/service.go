package inspectionlive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionbridge"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionowner"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionhost"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionproduct"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
)

type Service struct {
	config  Config
	product *inspectionproduct.Product
	host    *inspectionhost.Host
	signer  *authority.Signer

	stopped bool

	material    *connectionowner.TokenMaterial
	lifecycleMu sync.Mutex
	stateLease  *connectionowner.Lease
}

func New(config Config) (*Service, error) {
	normalized, err := config.normalized()
	if err != nil {
		return nil, err
	}
	material, err := connectionowner.ReadTokenMaterial(normalized.TokenFile)
	if err != nil {
		return nil, err
	}
	signer, err := material.NewSigner("inspection-live-local-authority")
	if err != nil {
		material.Close()
		return nil, err
	}
	service := &Service{config: normalized, signer: signer, material: material}
	temporaryAcquirer := livevision.NewTemporaryAcquirer(normalized.Connections)
	builders := inspectionproduct.Builders{
		StandardRuntime: func(_ context.Context, resources inspectionproduct.Resources, execution inspectionproduct.ExecutionBinding) (inspectionproduct.StandardRuntime, error) {
			records, err := inspectionadapter.OpenSQLiteRecords(filepath.Join(normalized.StateRoot, "adapter-records.db"))
			if err != nil {
				return nil, err
			}
			adapter, err := inspectionadapter.New(inspectionadapter.Config{
				Catalog: resources.Catalog, Media: resources.Media, Connections: normalized.Connections, Records: records,
				PrivacyClass: "internal", RetentionPolicyRef: "live-retention", Audience: []string{MediaAudience},
			})
			if err != nil {
				_ = records.Close()
				return nil, err
			}
			manager, err := inspectionruntime.New(resources.Runs, execution.Authority(), adapter.Ports(),
				inspectionruntime.WithRuntimeID(execution.RuntimeID()), inspectionruntime.WithWorkerTick(normalized.WorkerInterval),
			)
			if err != nil {
				_ = records.Close()
				return nil, err
			}
			return &standardRuntime{Manager: manager, records: records}, nil
		},
		TemporaryRuntime: func(_ context.Context, resources inspectionproduct.Resources, preparations inspectionproduct.MediaPreparationReader) (inspectionproduct.TemporaryRuntime, error) {
			return temporary.NewManager(resources.Temporary, preparations, livevision.NewTemporaryMediaReader(resources.Media), livevision.NewTemporaryAnalyzer(normalized.Connections), time.Now)
		},
		ApplicationBackend: func(ctx context.Context, resources inspectionproduct.Resources, operator inspectionproduct.OperatorServices,
			standard inspectionproduct.StandardRuntime, temporaryRuntime inspectionproduct.TemporaryRuntime,
			registrar inspectionproduct.MediaPreparationRegistrar,
		) (inspectionproduct.ApplicationBackend, error) {
			if err := ensureChannelBinding(ctx, resources.ChannelAuth, material.Digest()); err != nil {
				return nil, err
			}
			synchronizer := newCatalogSynchronizer(normalized.Snapshots, resources.Catalog, resources.Runs)
			interactions := operator.InteractionRegistrar()
			if normalized.OpenInteraction != nil {
				interactions = openingRegistrar{inner: interactions, open: normalized.OpenInteraction}
			}
			planner, err := planning.New(planning.Config{
				Registry: resources.Runs, Catalog: resources.Catalog,
				Authorities: liveAuthorities{sync: synchronizer}, Interactions: interactions,
				Interpreter: naturalInterpreter{}, MediaCompiler: liveTemporaryCompiler{},
				Now: time.Now, CatalogFactTTL: 5 * time.Minute, DefaultRunTTL: 5 * time.Minute,
			})
			if err != nil {
				return nil, err
			}
			dynamic := synchronizedPlanner{sync: synchronizer, inner: planner}
			return application.New(application.Config{
				Capabilities: dynamic, Planner: dynamic, Runner: standard, Repository: resources.Runs,
				TemporaryRunner: temporaryRuntime, TemporaryRepository: temporaryRuntime, TemporaryMedia: registrar,
				InstalledTasks: resources.Catalog,
				Projector:      liveProjector{inner: application.NewBusinessResultProjector()},
				Media:          resources.Media, State: resources.Application, Now: time.Now,
				MediaCapabilityTTL: 10 * time.Minute, MediaAudience: MediaAudience,
			})
		},
		OutboxMaterializer: func(_ context.Context, resources inspectionproduct.Resources, builder delivery.TerminalMessageBuilder) (inspectionproduct.OutboxMaterializer, error) {
			standard, err := delivery.NewMaterializer(delivery.MaterializerConfig{
				Outbox: resources.Runs, Deliveries: resources.Delivery, Builder: builder,
				Owner: "inspection-live-materializer", LeaseTTL: time.Second, Now: time.Now,
			})
			if err != nil {
				return nil, err
			}
			temporaryMaterializer, err := delivery.NewTemporaryMaterializer(delivery.TemporaryMaterializerConfig{
				Outbox: resources.Temporary, Deliveries: resources.Delivery, Builder: builder,
				Owner: "inspection-live-temporary-materializer", LeaseTTL: time.Second, Now: time.Now,
			})
			if err != nil {
				return nil, err
			}
			return delivery.NewMaterializerGroup(standard, temporaryMaterializer)
		},
		DeliveryDispatcher: func(_ context.Context, resources inspectionproduct.Resources) (inspectionproduct.DeliveryDispatcher, error) {
			transport := localTerminalTransport{}
			return delivery.NewDispatcher(delivery.DispatcherConfig{
				Store: resources.Delivery, Transport: transport, Reconciler: transport,
				Owner: "inspection-live-delivery", LeaseTTL: time.Second,
				SendTimeout: 250 * time.Millisecond, LookupTimeout: 250 * time.Millisecond, Now: time.Now,
			})
		},
		ScheduleCoordinator: func(_ context.Context, schedules *schedule.Store, bridge inspectionproduct.ScheduleBridge) (inspectionproduct.ScheduleCoordinator, error) {
			return schedule.NewCoordinator(schedule.CoordinatorConfig{
				Store: schedules, Planner: schedule.NewPlanner(schedule.SystemClock{}, schedule.SystemZoneLoader{}, signer),
				AuthorityProvider: noScheduleAuthority{}, AuthorityVerifier: signer,
				Submitter: bridge, RunObserver: bridge, OwnerID: "inspection-live-scheduler",
				Lease: time.Second, Now: time.Now,
			})
		},
	}
	factories := inspectionproduct.PersistentFactories(signer, temporaryAcquirer, builders)
	factories.OpenCredentials = service.openCredentialStore
	factories.ConnectionAuthorityIssuer = signer
	factories.BuildConnectionLifecycle = func(registry *connectionregistry.Registry) (inspectionproduct.ConnectionLifecycle, error) {
		return connectionbridge.New(normalized.Sessions, registry)
	}
	binding := sessionBinding()
	product, err := inspectionproduct.New(inspectionproduct.Config{
		Enabled: true, StateRoot: normalized.StateRoot,
		WorkerInterval: normalized.WorkerInterval, MediaGCInterval: time.Hour,
		HandoffRecoveryInterval: time.Hour, TemporaryWorkerInterval: normalized.WorkerInterval,
		// A real picture-VLM cycle includes task creation, inference and bounded
		// cancellation. Keep the durable lease wider than that full device round
		// trip so a successful response is not reclassified as outcome_unknown.
		TemporaryWorkerOwner: "inspection-live-temporary", TemporaryLeaseTTL: 5 * time.Minute,
		MediaPreparationWorkerInterval: normalized.WorkerInterval,
		MediaPreparationWorkerOwner:    "inspection-live-media-preparation",
		ExecutionAuthorityIssuerID:     "inspection-live-execution-authority",
		ExecutionRuntimeID:             "inspection-live-runtime",
		PersistentConnection: &inspectionproduct.PersistentConnectionConfig{
			TenantID: TenantID, SiteID: SiteID,
			PrincipalSHA256: binding.PrincipalSHA256, ProfileID: DeviceProfileID,
			CreateOperationID: CreateOperationID, Alias: SourceAlias,
		},
	}, factories)
	if err != nil {
		service.clearCredentialKey()
		signer.Close()
		return nil, err
	}
	host, err := inspectionhost.New(inspectionhost.Config{Enabled: true, Address: normalized.Address}, product)
	if err != nil {
		service.clearCredentialKey()
		signer.Close()
		return nil, err
	}
	service.product, service.host = product, host
	return service, nil
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || s.host == nil {
		return errors.New("live inspection service is unavailable")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.stopped {
		return errors.New("live inspection service is stopped")
	}
	if s.stateLease != nil {
		return connectionowner.ErrAlreadyOwned
	}
	lease, err := connectionowner.AcquireLease(s.config.StateRoot)
	if err != nil {
		return err
	}
	if err := s.host.Start(ctx); err != nil {
		return errors.Join(err, lease.Close())
	}
	s.stateLease = lease
	return nil
}

func (s *Service) Stop() error {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.stopped {
		return nil
	}
	if s.host != nil {
		if err := s.host.Stop(); err != nil {
			return err
		}
	}
	if s.signer != nil {
		s.signer.Close()
	}
	s.clearCredentialKey()
	err := s.stateLease.Close()
	s.stateLease = nil
	s.stopped = true
	return err
}

func (s *Service) openCredentialStore(ctx context.Context, root string) (inspectionproduct.Opened[credential.SecretStore], error) {
	if err := ctx.Err(); err != nil {
		return inspectionproduct.Opened[credential.SecretStore]{}, err
	}
	store, err := s.material.OpenCredentials(ctx, root)
	if err != nil {
		return inspectionproduct.Opened[credential.SecretStore]{}, err
	}
	return inspectionproduct.Opened[credential.SecretStore]{Value: store, Close: store.Close}, nil
}

func (s *Service) clearCredentialKey() {
	if s == nil {
		return
	}
	s.material.Close()
}

func (s *Service) Readiness() inspectionhost.Readiness {
	if s == nil || s.host == nil {
		return inspectionhost.Readiness{State: inspectionhost.StateFailed, Failure: "live_service_unavailable"}
	}
	return s.host.Readiness()
}

func (s *Service) ConnectionRestoreState() (connectionregistry.RestoreState, error) {
	if s == nil || s.product == nil {
		return "", inspectionproduct.ErrConnectionRestoreUnavailable
	}
	return s.product.ConnectionRestoreState()
}

type standardRuntime struct {
	*inspectionruntime.Manager
	records *inspectionadapter.SQLiteRecords
	once    sync.Once
}

func (r *standardRuntime) Stop() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		if r.Manager != nil {
			r.Manager.Stop()
		}
		if r.records != nil {
			_ = r.records.Close()
		}
	})
}

func ensureChannelBinding(ctx context.Context, store *channelauth.Store, credentialDigest string) error {
	scopes := []httpapi.Scope{
		httpapi.ScopeCapabilitiesRead, httpapi.ScopeFeedbackCreate, httpapi.ScopeMediaDeliver,
		httpapi.ScopeRequestCreate, httpapi.ScopeResultRead, httpapi.ScopeRunRead,
	}
	session := sessionBinding()
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
			return errors.New("inspection access token is already bound to another local session")
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

type localTerminalTransport struct{}

func (localTerminalTransport) Send(ctx context.Context, request delivery.SendRequest) (delivery.SendResult, error) {
	if err := ctx.Err(); err != nil {
		return delivery.SendResult{}, err
	}
	return delivery.SendResult{Outcome: delivery.SendDelivered, ReceiptRef: localReceipt(request.DeliveryID)}, nil
}

func (localTerminalTransport) Lookup(ctx context.Context, request delivery.ReconciliationRequest) (delivery.Reconciliation, string, error) {
	if err := ctx.Err(); err != nil {
		return delivery.ReconciliationUnknown, "", err
	}
	return delivery.ReconciliationDelivered, localReceipt(request.DeliveryID), nil
}

func localReceipt(deliveryID string) string {
	digest := sha256.Sum256([]byte("inspection-live-local-terminal\x00" + deliveryID))
	return "receipt_" + hex.EncodeToString(digest[:16])
}

type noScheduleAuthority struct{}

func (noScheduleAuthority) AuthorityFor(context.Context, schedule.Occurrence) (authority.Grant, bool, error) {
	return authority.Grant{}, false, nil
}

var (
	_ inspectionproduct.StandardRuntime = (*standardRuntime)(nil)
	_ delivery.Transport                = localTerminalTransport{}
	_ delivery.Reconciler               = localTerminalTransport{}
	_ schedule.AuthorityProvider        = noScheduleAuthority{}
)
