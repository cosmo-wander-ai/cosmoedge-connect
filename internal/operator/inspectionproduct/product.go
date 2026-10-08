package inspectionproduct

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	inspection "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionapplication "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	inspectioncatalog "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	inspectionchangeflow "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/changeflow"
	inspectionchannelauth "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/channelauth"
	inspectiondelivery "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/delivery"
	inspectiondeliverybinding "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/deliverybinding"
	inspectionhttpapi "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	inspectionmedia "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionmediaprep "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	inspectionplanning "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	inspectionschedule "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/schedule"
	inspectionschedulebridge "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/schedulebridge"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	inspectiontemporary "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionregistry"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	operatorinspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectioninteraction"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionlocal"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/onboarding"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/profile"
)

const (
	defaultWorkerInterval           = 250 * time.Millisecond
	defaultMediaGCInterval          = 5 * time.Minute
	defaultHandoffRecoveryInterval  = 5 * time.Minute
	defaultTemporaryLease           = time.Minute
	defaultMediaPreparationOwner    = "cosmoedge-connect-local-media-preparation"
	defaultExecutionAuthorityIssuer = "cosmoedge-connect-local-inspection-authority"
	defaultExecutionRuntimeID       = "cosmoedge-connect-local-inspection-runtime"
	requestStateRetention           = 30 * 24 * time.Hour
	feedbackStateRetention          = 90 * 24 * time.Hour
	productWorkerCount              = 8
)

var (
	temporaryWorkerOwnerPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	handoffRecoveryCursorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	principalDigestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	connectionProfileIDPattern   = regexp.MustCompile(`^dpf_[0-9a-f]{32}$`)
	connectionOperationPattern   = regexp.MustCompile(`^onb_[0-9a-f]{32}$`)
)

// ErrHTTPSurfaceUnavailable is returned unless the current product generation
// has completed startup and remains ready.
var ErrHTTPSurfaceUnavailable = errors.New("inspection HTTP surface is unavailable")

var (
	ErrDeliveryBindingUnavailable   = errors.New("inspection delivery binding management is unavailable")
	ErrDeliveryBindingScope         = errors.New("inspection delivery binding scope mismatch")
	ErrLocalInteractionUnavailable  = errors.New("inspection local interaction surface is unavailable")
	ErrConnectionRestoreUnavailable = errors.New("persistent connection restore state is unavailable")
)

type State string

const (
	StateDisabled State = "disabled"
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateReady    State = "ready"
	StateStopping State = "stopping"
	StateFailed   State = "failed"
)

type Config struct {
	Enabled                        bool
	StateRoot                      string
	WorkerInterval                 time.Duration
	MediaGCInterval                time.Duration
	HandoffRecoveryInterval        time.Duration
	TemporaryWorkerInterval        time.Duration
	TemporaryWorkerOwner           string
	TemporaryLeaseTTL              time.Duration
	MediaPreparationWorkerInterval time.Duration
	MediaPreparationWorkerOwner    string
	ExecutionAuthorityIssuerID     string
	ExecutionRuntimeID             string
	PersistentConnection           *PersistentConnectionConfig
}

// PersistentConnectionConfig binds the ordinary foreground Vault to the same
// Product-owned profile, encrypted credential, and onboarding state used by
// the inspection product. It never opens or names a second profile store.
type PersistentConnectionConfig struct {
	TenantID          string
	SiteID            string
	PrincipalSHA256   string
	ProfileID         string
	CreateOperationID string
	Alias             string
}

// ConnectionLifecycle is implemented only by the live-layer Vault adapter.
// Product sees a safe restore classification and a release boundary, never a
// device client, session, endpoint, or secret.
type ConnectionLifecycle interface {
	Start(context.Context) (connectionregistry.RestoreState, error)
	Stop() error
}

type StatePaths struct {
	CredentialRoot             string
	ExecutionAuthorityDatabase string
	ProfileDatabase            string
	OnboardingJournalDatabase  string
	OnboardingHandoffDatabase  string
	PendingInteractionDatabase string
	SourceCatalog              string
	ApplicationState           string
	ChannelBindings            string
	ChangeflowJournal          string
	RunDatabase                string
	TemporaryDatabase          string
	ScheduleDatabase           string
	MediaRoot                  string
	MediaPreparationDatabase   string
	DeliveryDatabase           string
	DeliveryBindingDatabase    string
}

// Opened binds one typed resource to its lifecycle owner. Close must release
// process-local handles only; persistent product state is never deleted by
// startup rollback or normal shutdown.
type Opened[T any] struct {
	Value T
	Close func() error
}

// Resources is the least-privilege inspection-domain state set available to
// ordinary builders. Operator onboarding, credentials, device profiles,
// pending interactions and changeflow state remain Product-private.
type Resources struct {
	Catalog     *inspectioncatalog.Store
	Application *inspectionapplication.StateStore
	ChannelAuth *inspectionchannelauth.Store
	Runs        *inspectionstore.Store
	Temporary   *inspectiontemporary.SQLiteStore
	Schedules   *inspectionschedule.Store
	Media       *inspectionmedia.Store
	Delivery    *inspectiondelivery.SQLiteStore
}

// ExecutionBinding is given only to the standard runtime builder. Delivery,
// scheduling, application and other passive builders never receive authority
// issuance or consumption capability merely because they share state stores.
// Its fields remain private so a builder cannot splice a different authority
// or runtime identity into the generation.
type ExecutionBinding struct {
	authority inspectionauthority.Broker
	runtimeID string
}

func (b ExecutionBinding) Authority() inspectionauthority.Broker { return b.authority }
func (b ExecutionBinding) RuntimeID() string                     { return b.runtimeID }

func (b ExecutionBinding) valid() bool {
	return !isNil(b.authority) && temporaryWorkerOwnerPattern.MatchString(b.runtimeID) && len(b.runtimeID) <= 64
}

// OperatorServices is constructed only by Product from its owned state. Its
// fields are deliberately private, so builders can consume the exact service
// identities but cannot replace either service in the generation.
type OperatorServices struct {
	onboardingEntry      *onboarding.EntryService
	interactionRegistrar *inspectioninteraction.Registrar
}

func (s OperatorServices) InteractionRegistrar() inspectionplanning.LocalInteractionRegistrar {
	return s.interactionRegistrar
}

func (s OperatorServices) valid() bool {
	return s.onboardingEntry != nil && s.interactionRegistrar != nil
}

type Runtime interface {
	// Start is the only point at which the runtime may create goroutines.
	// Stop must be idempotent and safe after a partially failed Start.
	Start(context.Context) error
	Stop()
}

// StandardRuntime is one object that owns both the worker lifecycle and the
// application submission port for a product generation. The embedded
// interface prevents builders from splicing independently replaceable fields.
type StandardRuntime interface {
	Runtime
	inspectionapplication.Runner
}

type OutboxMaterializer interface {
	MaterializeNext(context.Context) (bool, error)
}

type DeliveryDispatcher interface {
	Recover(context.Context) (inspectiondelivery.Recovery, error)
	DeliverNext(context.Context) (bool, error)
	ReconcileNext(context.Context) (bool, error)
}

type ScheduleCoordinator interface {
	Tick(context.Context) (inspectionschedule.TickReport, error)
}

type ScheduleBridge interface {
	inspectionschedule.Submitter
	inspectionschedule.RunObserver
}

// DeliveryBindingManager is a generation-bound, exact-session management
// entry. Product never exposes the underlying store to ordinary builders or
// callers.
type DeliveryBindingManager interface {
	Register(context.Context, inspectiondeliverybinding.Binding) (inspectiondeliverybinding.Binding, bool, error)
	Revoke(context.Context, string, uint64, time.Time) (inspectiondeliverybinding.Binding, bool, error)
}

type scopedDeliveryBindingManager struct {
	product              *Product
	generation           uint64
	session              inspectionhttpapi.SessionBinding
	authorizationRequest inspectionhttpapi.AuthorizationRequest
}

type handoffReconciler interface {
	ReconcileCompletedHandoffs(context.Context, onboarding.HandoffReconcileRequest) (onboarding.HandoffReconcileResult, error)
}

// TemporaryProcessor is the product-owned lifecycle boundary around the
// temporary observation manager. The manager intentionally has no Start/Stop
// methods: Product owns its polling cadence, lease identity and failure domain.
type TemporaryProcessor interface {
	RunOnce(context.Context, string, time.Duration) (inspectiontemporary.Record, bool, error)
}

// TemporaryRuntime is one object exposing submission, lookup and product-owned
// processing. The same instance is passed to the application and worker.
type TemporaryRuntime interface {
	TemporaryProcessor
	inspectionapplication.TemporaryRunner
	inspectionapplication.TemporaryRepository
}

// MediaPreparationRegistrar is the application/planning-side registration
// port. Product supplies a private forwarding object rather than the manager,
// so a builder cannot recover or process work by asserting a wider interface.
type MediaPreparationRegistrar interface {
	Prepare(context.Context, inspectionmediaprep.FrozenRequest) (inspectionmediaprep.Status, bool, error)
}

// MediaPreparationReader is the temporary-runtime-side lookup port. It cannot
// register, recover, process or close media-preparation state.
type MediaPreparationReader interface {
	Get(context.Context, string) (inspectionmediaprep.Status, error)
}

type mediaPreparationRegistrar struct {
	prepare func(context.Context, inspectionmediaprep.FrozenRequest) (inspectionmediaprep.Status, bool, error)
}

func (r mediaPreparationRegistrar) Prepare(ctx context.Context, request inspectionmediaprep.FrozenRequest) (inspectionmediaprep.Status, bool, error) {
	return r.prepare(ctx, request)
}

type mediaPreparationReader struct {
	get func(context.Context, string) (inspectionmediaprep.Status, error)
}

func (r mediaPreparationReader) Get(ctx context.Context, preparationRef string) (inspectionmediaprep.Status, error) {
	return r.get(ctx, preparationRef)
}

type mediaPreparationProcessor interface {
	Recover(context.Context) (inspectionmediaprep.Recovery, error)
	ProcessNext(context.Context) (inspectionmediaprep.Status, bool, error)
}

// ApplicationBackend is the single trusted application object for one product
// generation. Product constructs the HTTP handler itself with its owned
// ChannelAuth store, so builders cannot splice a different HTTP backend into
// the terminal delivery projection.
type ApplicationBackend interface {
	inspectionhttpapi.Backend
	inspectiondelivery.TerminalMessageBuilder
}

type applicationSurface struct {
	handler *inspectionhttpapi.Handler
	backend ApplicationBackend
}

func (s *applicationSurface) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	s.handler.ServeHTTP(response, request)
}

func (s *applicationSurface) BuildDeliveryMessage(ctx context.Context, runID string) (inspectiondelivery.Message, error) {
	return s.backend.BuildDeliveryMessage(ctx, runID)
}

// Builders only assemble passive components. They must not start goroutines,
// open network listeners, contact a device, or transfer lifecycle ownership;
// Product.Start remains the single start boundary.
type Builders struct {
	StandardRuntime     func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error)
	TemporaryRuntime    func(context.Context, Resources, MediaPreparationReader) (TemporaryRuntime, error)
	ApplicationBackend  func(context.Context, Resources, OperatorServices, StandardRuntime, TemporaryRuntime, MediaPreparationRegistrar) (ApplicationBackend, error)
	OutboxMaterializer  func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error)
	DeliveryDispatcher  func(context.Context, Resources) (DeliveryDispatcher, error)
	ScheduleCoordinator func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error)
}

// Factories are mandatory in enabled mode. Keeping every constructor explicit
// prevents an ordinary Operator launch from acquiring implicit device, fixture,
// delivery, or credential authority.
type Factories struct {
	AuthorityVerifier         onboarding.AuthorityVerifier
	ConnectionAuthorityIssuer connectionregistry.AuthorityIssuer
	BuildConnectionLifecycle  func(*connectionregistry.Registry) (ConnectionLifecycle, error)
	OpenCredentials           func(context.Context, string) (Opened[credential.SecretStore], error)
	OpenExecutionAuthority    func(context.Context, string, string, credential.SecretStore) (Opened[inspectionauthority.Broker], error)
	OpenProfiles              func(context.Context, string) (Opened[*profile.Store], error)
	OpenOnboardingJournal     func(context.Context, string) (Opened[*onboarding.Journal], error)
	OpenOnboardingHandoffs    func(context.Context, string) (Opened[*onboarding.HandoffStore], error)
	OpenPendingInteractions   func(context.Context, string) (Opened[*inspectioninteraction.Store], error)
	OpenCatalog               func(context.Context, string) (Opened[*inspectioncatalog.Store], error)
	OpenApplication           func(context.Context, string) (Opened[*inspectionapplication.StateStore], error)
	OpenChannelAuth           func(context.Context, string) (Opened[*inspectionchannelauth.Store], error)
	OpenChangeflow            func(context.Context, string) (Opened[inspectionchangeflow.Store], error)
	OpenRuns                  func(context.Context, string) (Opened[*inspectionstore.Store], error)
	OpenTemporary             func(context.Context, string) (Opened[*inspectiontemporary.SQLiteStore], error)
	OpenSchedules             func(context.Context, string) (Opened[*inspectionschedule.Store], error)
	OpenMedia                 func(context.Context, inspectionmedia.Config) (Opened[*inspectionmedia.Store], error)
	MediaPreparationAcquirer  inspectionmediaprep.Acquirer
	OpenMediaPreparations     func(context.Context, inspectionmediaprep.Config) (Opened[*inspectionmediaprep.Manager], error)
	OpenDelivery              func(context.Context, string) (Opened[*inspectiondelivery.SQLiteStore], error)
	OpenDeliveryBindings      func(context.Context, string) (Opened[*inspectiondeliverybinding.Store], error)

	BuildStandardRuntime     func(context.Context, Resources, ExecutionBinding) (StandardRuntime, error)
	BuildTemporaryRuntime    func(context.Context, Resources, MediaPreparationReader) (TemporaryRuntime, error)
	BuildApplicationBackend  func(context.Context, Resources, OperatorServices, StandardRuntime, TemporaryRuntime, MediaPreparationRegistrar) (ApplicationBackend, error)
	BuildOutboxMaterializer  func(context.Context, Resources, inspectiondelivery.TerminalMessageBuilder) (OutboxMaterializer, error)
	BuildDeliveryDispatcher  func(context.Context, Resources) (DeliveryDispatcher, error)
	BuildScheduleCoordinator func(context.Context, *inspectionschedule.Store, ScheduleBridge) (ScheduleCoordinator, error)
}

// PersistentFactories selects the final v2 state owners. Execution ports,
// channel delivery and outbox projection remain mandatory injected builders;
// there is intentionally no fixture or device-reaching default.
func PersistentFactories(verifier onboarding.AuthorityVerifier, acquirer inspectionmediaprep.Acquirer, builders Builders) Factories {
	return Factories{
		AuthorityVerifier:        verifier,
		MediaPreparationAcquirer: acquirer,
		OpenCredentials: func(ctx context.Context, root string) (Opened[credential.SecretStore], error) {
			if err := ctx.Err(); err != nil {
				return Opened[credential.SecretStore]{}, err
			}
			store, err := credential.OpenSystemStore(root)
			return Opened[credential.SecretStore]{Value: store, Close: noClose}, err
		},
		OpenExecutionAuthority: func(ctx context.Context, path, issuerID string, secrets credential.SecretStore) (Opened[inspectionauthority.Broker], error) {
			if err := ctx.Err(); err != nil {
				return Opened[inspectionauthority.Broker]{}, err
			}
			broker, err := operatorinspectionauthority.Open(operatorinspectionauthority.Config{
				Path: path, IssuerID: issuerID, Secrets: secrets,
			})
			if err != nil {
				return Opened[inspectionauthority.Broker]{}, err
			}
			return Opened[inspectionauthority.Broker]{Value: broker, Close: broker.Close}, nil
		},
		OpenProfiles: func(ctx context.Context, path string) (Opened[*profile.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*profile.Store]{}, err
			}
			store, err := profile.Open(path)
			if err != nil {
				return Opened[*profile.Store]{}, err
			}
			return Opened[*profile.Store]{Value: store, Close: store.Close}, nil
		},
		OpenOnboardingJournal: func(ctx context.Context, path string) (Opened[*onboarding.Journal], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*onboarding.Journal]{}, err
			}
			journal, err := onboarding.OpenJournal(path)
			if err != nil {
				return Opened[*onboarding.Journal]{}, err
			}
			return Opened[*onboarding.Journal]{Value: journal, Close: journal.Close}, nil
		},
		OpenOnboardingHandoffs: func(ctx context.Context, path string) (Opened[*onboarding.HandoffStore], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*onboarding.HandoffStore]{}, err
			}
			store, err := onboarding.OpenHandoffStore(onboarding.HandoffStoreConfig{Path: path})
			if err != nil {
				return Opened[*onboarding.HandoffStore]{}, err
			}
			return Opened[*onboarding.HandoffStore]{Value: store, Close: store.Close}, nil
		},
		OpenPendingInteractions: func(ctx context.Context, path string) (Opened[*inspectioninteraction.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectioninteraction.Store]{}, err
			}
			store, err := inspectioninteraction.OpenStore(inspectioninteraction.StoreConfig{Path: path})
			if err != nil {
				return Opened[*inspectioninteraction.Store]{}, err
			}
			return Opened[*inspectioninteraction.Store]{Value: store, Close: store.Close}, nil
		},
		OpenCatalog: func(ctx context.Context, path string) (Opened[*inspectioncatalog.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectioncatalog.Store]{}, err
			}
			store, err := inspectioncatalog.Open(path)
			if err != nil {
				return Opened[*inspectioncatalog.Store]{}, err
			}
			return Opened[*inspectioncatalog.Store]{Value: store, Close: store.Close}, nil
		},
		OpenApplication: func(ctx context.Context, path string) (Opened[*inspectionapplication.StateStore], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectionapplication.StateStore]{}, err
			}
			store, err := inspectionapplication.OpenState(inspectionapplication.StateConfig{
				Path: path, RequestRetention: requestStateRetention, FeedbackRetention: feedbackStateRetention,
			})
			if err != nil {
				return Opened[*inspectionapplication.StateStore]{}, err
			}
			return Opened[*inspectionapplication.StateStore]{Value: store, Close: store.Close}, nil
		},
		OpenChannelAuth: func(ctx context.Context, path string) (Opened[*inspectionchannelauth.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectionchannelauth.Store]{}, err
			}
			store, err := inspectionchannelauth.Open(inspectionchannelauth.Config{Path: path})
			if err != nil {
				return Opened[*inspectionchannelauth.Store]{}, err
			}
			return Opened[*inspectionchannelauth.Store]{Value: store, Close: store.Close}, nil
		},
		OpenChangeflow: func(ctx context.Context, path string) (Opened[inspectionchangeflow.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[inspectionchangeflow.Store]{}, err
			}
			store, err := inspectionchangeflow.OpenFileStore(path)
			if err != nil {
				return Opened[inspectionchangeflow.Store]{}, err
			}
			return Opened[inspectionchangeflow.Store]{Value: store, Close: noClose}, nil
		},
		OpenRuns: func(ctx context.Context, path string) (Opened[*inspectionstore.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectionstore.Store]{}, err
			}
			store, err := inspectionstore.Open(path)
			if err != nil {
				return Opened[*inspectionstore.Store]{}, err
			}
			return Opened[*inspectionstore.Store]{Value: store, Close: store.Close}, nil
		},
		OpenTemporary: func(ctx context.Context, path string) (Opened[*inspectiontemporary.SQLiteStore], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectiontemporary.SQLiteStore]{}, err
			}
			store, err := inspectiontemporary.OpenSQLite(path)
			if err != nil {
				return Opened[*inspectiontemporary.SQLiteStore]{}, err
			}
			return Opened[*inspectiontemporary.SQLiteStore]{Value: store, Close: store.Close}, nil
		},
		OpenSchedules: func(ctx context.Context, path string) (Opened[*inspectionschedule.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectionschedule.Store]{}, err
			}
			store, err := inspectionschedule.OpenStore(inspectionschedule.StoreConfig{Path: path})
			if err != nil {
				return Opened[*inspectionschedule.Store]{}, err
			}
			return Opened[*inspectionschedule.Store]{Value: store, Close: store.Close}, nil
		},
		OpenMedia: func(ctx context.Context, config inspectionmedia.Config) (Opened[*inspectionmedia.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectionmedia.Store]{}, err
			}
			store, err := inspectionmedia.New(config)
			return Opened[*inspectionmedia.Store]{Value: store, Close: noClose}, err
		},
		OpenMediaPreparations: func(ctx context.Context, config inspectionmediaprep.Config) (Opened[*inspectionmediaprep.Manager], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectionmediaprep.Manager]{}, err
			}
			manager, err := inspectionmediaprep.Open(config)
			if err != nil {
				return Opened[*inspectionmediaprep.Manager]{}, err
			}
			return Opened[*inspectionmediaprep.Manager]{Value: manager, Close: manager.Close}, nil
		},
		OpenDelivery: func(ctx context.Context, path string) (Opened[*inspectiondelivery.SQLiteStore], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectiondelivery.SQLiteStore]{}, err
			}
			store, err := inspectiondelivery.OpenSQLite(path)
			if err != nil {
				return Opened[*inspectiondelivery.SQLiteStore]{}, err
			}
			return Opened[*inspectiondelivery.SQLiteStore]{Value: store, Close: store.Close}, nil
		},
		OpenDeliveryBindings: func(ctx context.Context, path string) (Opened[*inspectiondeliverybinding.Store], error) {
			if err := ctx.Err(); err != nil {
				return Opened[*inspectiondeliverybinding.Store]{}, err
			}
			store, err := inspectiondeliverybinding.Open(path)
			if err != nil {
				return Opened[*inspectiondeliverybinding.Store]{}, err
			}
			return Opened[*inspectiondeliverybinding.Store]{Value: store, Close: store.Close}, nil
		},
		BuildStandardRuntime:     builders.StandardRuntime,
		BuildTemporaryRuntime:    builders.TemporaryRuntime,
		BuildApplicationBackend:  builders.ApplicationBackend,
		BuildOutboxMaterializer:  builders.OutboxMaterializer,
		BuildDeliveryDispatcher:  builders.DeliveryDispatcher,
		BuildScheduleCoordinator: builders.ScheduleCoordinator,
	}
}

type Readiness struct {
	Enabled    bool
	Ready      bool
	State      State
	Generation uint64
	Failure    string
}

type Metrics struct {
	Starts                                uint64
	Stops                                 uint64
	StartupFailures                       uint64
	WorkerFailures                        uint64
	LifecycleInterruptions                uint64
	OutboxPasses                          uint64
	OutboxMessages                        uint64
	DeliveryPasses                        uint64
	Deliveries                            uint64
	DeliveryUnknownOutcomes               uint64
	DeliveryRecoveryPasses                uint64
	DeliverySendingRecovered              uint64
	DeliveryReconciliationLeasesRecovered uint64
	DeliveryReconciliationPasses          uint64
	DeliveriesReconciled                  uint64
	SchedulePasses                        uint64
	ScheduleOccurrences                   uint64
	ScheduleSubmissions                   uint64
	ScheduleBlocked                       uint64
	ScheduleUnknownOutcomes               uint64
	TemporaryPasses                       uint64
	TemporaryClaims                       uint64
	MediaPreparationRecoveryPasses        uint64
	MediaPreparationAcquisitionRecovered  uint64
	MediaPreparationReconcileRecovered    uint64
	MediaPreparationPublicationRecovered  uint64
	MediaPreparationPasses                uint64
	MediaPreparationsProcessed            uint64
	MediaPreparationPersistedOutcomes     uint64
	MediaPreparationLeaseConflicts        uint64
	MediaGCPasses                         uint64
	MediaDescriptorsPurged                uint64
	HandoffRecoveryPasses                 uint64
	HandoffsExamined                      uint64
	HandoffsCompleted                     uint64
	HandoffRecoverySweeps                 uint64
}

type Product struct {
	config    Config
	paths     StatePaths
	factories Factories

	lifecycle  sync.Mutex
	mu         sync.RWMutex
	state      State
	generation uint64
	failure    string
	metrics    Metrics
	active     bool
	cancel     context.CancelFunc
	workers    sync.WaitGroup
	surfaceMu  sync.RWMutex

	opened              openedResources
	standard            StandardRuntime
	temporary           TemporaryRuntime
	mediaPreparations   *inspectionmediaprep.Manager
	materializer        OutboxMaterializer
	dispatcher          DeliveryDispatcher
	scheduler           ScheduleCoordinator
	application         *applicationSurface
	services            OperatorServices
	connectionRegistry  *connectionregistry.Registry
	connectionLifecycle ConnectionLifecycle
	connectionRestore   connectionregistry.RestoreState
}

// LocalInteractions returns a lifecycle-gated local application over the
// current Product-owned onboarding and interaction stores. The caller supplies
// only the existing foreground-session binder; no private store or onboarding
// service escapes the Product generation.
func (p *Product) LocalInteractions(sessions *inspectionlocal.SessionBinder) (inspectionlocal.Application, error) {
	if p == nil || sessions == nil || !p.config.Enabled {
		return nil, ErrLocalInteractionUnavailable
	}
	p.surfaceMu.RLock()
	defer p.surfaceMu.RUnlock()
	p.mu.RLock()
	ready := p.active && p.state == StateReady && p.generation > 0 &&
		p.services.onboardingEntry != nil && p.opened.onboardingHandoffs.Value != nil &&
		p.opened.pendingInteractions.Value != nil && p.connectionRegistry != nil
	generation := p.generation
	connectionRegistry := p.connectionRegistry
	p.mu.RUnlock()
	if !ready {
		return nil, ErrLocalInteractionUnavailable
	}
	target, err := inspectionlocal.NewService(inspectionlocal.Config{
		Sessions: sessions, Onboarding: p.services.onboardingEntry,
		Connections: p.opened.onboardingHandoffs.Value, Changes: p.opened.pendingInteractions.Value,
		PersistentConnection: connectionRegistry,
	})
	if err != nil {
		return nil, errors.Join(ErrLocalInteractionUnavailable, err)
	}
	return &localInteractionGate{product: p, generation: generation, target: target}, nil
}

type localInteractionGate struct {
	product    *Product
	generation uint64
	target     *inspectionlocal.Service
}

func (g *localInteractionGate) admit() (func(), error) {
	if g == nil || g.product == nil || g.target == nil || g.generation == 0 {
		return nil, ErrLocalInteractionUnavailable
	}
	g.product.surfaceMu.RLock()
	g.product.mu.RLock()
	ready := g.product.config.Enabled && g.product.active && g.product.state == StateReady &&
		g.product.generation == g.generation && g.product.services.onboardingEntry != nil
	g.product.mu.RUnlock()
	if !ready {
		g.product.surfaceMu.RUnlock()
		return nil, ErrLocalInteractionUnavailable
	}
	return g.product.surfaceMu.RUnlock, nil
}

func (g *localInteractionGate) Resolve(ctx context.Context, local inspectionlocal.LocalSession) (inspectionlocal.Interaction, error) {
	release, err := g.admit()
	if err != nil {
		return inspectionlocal.Interaction{}, err
	}
	defer release()
	return g.target.Resolve(ctx, local)
}

func (g *localInteractionGate) CompleteConnection(ctx context.Context, local inspectionlocal.LocalSession, request inspectionlocal.CompleteConnectionRequest) (inspectionlocal.Interaction, error) {
	release, err := g.admit()
	if err != nil {
		clear(request.Connection.Password)
		return inspectionlocal.Interaction{}, err
	}
	defer release()
	return g.target.CompleteConnection(ctx, local, request)
}

func (g *localInteractionGate) CompleteVerifiedConnection(ctx context.Context, local inspectionlocal.LocalSession) (inspectionlocal.Interaction, error) {
	release, err := g.admit()
	if err != nil {
		return inspectionlocal.Interaction{}, err
	}
	defer release()
	return g.target.CompleteVerifiedConnection(ctx, local)
}

func (g *localInteractionGate) PreparePersistentTransfer(ctx context.Context, local inspectionlocal.LocalSession, request inspectionlocal.PersistentTransferRequest) (inspectionlocal.Interaction, error) {
	release, err := g.admit()
	if err != nil {
		return inspectionlocal.Interaction{}, err
	}
	defer release()
	return g.target.PreparePersistentTransfer(ctx, local, request)
}

func (g *localInteractionGate) MarkPersistentTransferred(ctx context.Context, local inspectionlocal.LocalSession, request inspectionlocal.PersistentTransferRequest) (inspectionlocal.Interaction, error) {
	release, err := g.admit()
	if err != nil {
		return inspectionlocal.Interaction{}, err
	}
	defer release()
	return g.target.MarkPersistentTransferred(ctx, local, request)
}

var _ inspectionlocal.Application = (*localInteractionGate)(nil)

type composition struct {
	opened              openedResources
	resources           Resources
	standard            StandardRuntime
	temporary           TemporaryRuntime
	mediaPreparations   *inspectionmediaprep.Manager
	materializer        OutboxMaterializer
	dispatcher          DeliveryDispatcher
	scheduler           ScheduleCoordinator
	application         *applicationSurface
	services            OperatorServices
	connectionRegistry  *connectionregistry.Registry
	connectionLifecycle ConnectionLifecycle
	connectionRestore   connectionregistry.RestoreState
}

// close releases the exact Vault binding before any profile or credential
// owner is closed. If a foreground connection is still being committed, the
// lease cannot be detached and the persistent resources deliberately remain
// open so a caller can retry Stop without racing closed state.
func (c *composition) close() error {
	if c == nil {
		return nil
	}
	if !isNil(c.connectionLifecycle) {
		if err := c.connectionLifecycle.Stop(); err != nil {
			return fmt.Errorf("release connection persistence before closing product state: %w", err)
		}
		c.connectionLifecycle = nil
	}
	return c.opened.close()
}

type openedResources struct {
	credentials         Opened[credential.SecretStore]
	executionAuthority  Opened[inspectionauthority.Broker]
	profiles            Opened[*profile.Store]
	onboardingJournal   Opened[*onboarding.Journal]
	onboardingHandoffs  Opened[*onboarding.HandoffStore]
	pendingInteractions Opened[*inspectioninteraction.Store]
	catalog             Opened[*inspectioncatalog.Store]
	application         Opened[*inspectionapplication.StateStore]
	channelAuth         Opened[*inspectionchannelauth.Store]
	changeflow          Opened[inspectionchangeflow.Store]
	runs                Opened[*inspectionstore.Store]
	temporary           Opened[*inspectiontemporary.SQLiteStore]
	schedules           Opened[*inspectionschedule.Store]
	media               Opened[*inspectionmedia.Store]
	mediaPreparations   Opened[*inspectionmediaprep.Manager]
	delivery            Opened[*inspectiondelivery.SQLiteStore]
	deliveryBindings    Opened[*inspectiondeliverybinding.Store]
}

func New(config Config, factories Factories) (*Product, error) {
	product := &Product{config: config, factories: factories, state: StateDisabled}
	if !config.Enabled {
		return product, nil
	}
	normalized, paths, err := normalizeEnabledConfig(config)
	if err != nil {
		return nil, err
	}
	if err := validateFactories(factories, normalized.PersistentConnection != nil); err != nil {
		return nil, err
	}
	product.config = normalized
	product.paths = paths
	product.state = StateStopped
	return product, nil
}

func (p *Product) Start(parent context.Context) error {
	if p == nil {
		return errors.New("inspection product is required")
	}
	if !p.config.Enabled {
		return nil
	}
	if parent == nil {
		return errors.New("inspection product parent context is required")
	}
	if err := parent.Err(); err != nil {
		return fmt.Errorf("inspection product parent context is unavailable: %w", err)
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()

	p.mu.Lock()
	if p.active || p.state == StateStarting || p.state == StateStopping {
		p.mu.Unlock()
		return errors.New("inspection product lifecycle is already active")
	}
	p.state = StateStarting
	p.failure = ""
	p.mu.Unlock()

	assembled, err := p.build(parent)
	if err != nil {
		p.recordStartupFailure()
		return err
	}
	if assembled.connectionRegistry != nil {
		restore, restoreErr := assembled.connectionLifecycle.Start(parent)
		if restoreErr != nil {
			assembled.standard.Stop()
			closeErr := assembled.close()
			p.recordStartupFailure()
			return errors.Join(fmt.Errorf("restore persistent device connection before startup: %w", restoreErr), closeErr)
		}
		assembled.connectionRestore = restore
	}
	if err := p.reconcileAllHandoffs(parent, assembled.services.onboardingEntry); err != nil {
		assembled.standard.Stop()
		closeErr := assembled.close()
		p.recordStartupFailure()
		return errors.Join(fmt.Errorf("reconcile onboarding handoffs before startup: %w", err), closeErr)
	}
	if recovery, err := assembled.mediaPreparations.Recover(parent); err != nil || !validMediaPreparationRecovery(recovery) {
		if err == nil {
			err = errors.New("temporary media preparation recovery returned invalid counters")
		}
		assembled.standard.Stop()
		closeErr := assembled.close()
		p.recordStartupFailure()
		return errors.Join(fmt.Errorf("recover temporary media preparations before startup: %w", err), closeErr)
	} else {
		p.recordMediaPreparationRecovery(recovery)
	}
	if recovery, err := assembled.dispatcher.Recover(parent); err != nil || !validDeliveryRecovery(recovery) {
		if err == nil {
			err = errors.New("inspection delivery recovery returned invalid counters")
		}
		assembled.standard.Stop()
		closeErr := assembled.close()
		p.recordStartupFailure()
		return errors.Join(fmt.Errorf("recover inspection deliveries before startup: %w", err), closeErr)
	} else {
		p.recordDeliveryRecovery(recovery)
	}
	workerContext, cancel := context.WithCancel(parent)
	if err := assembled.standard.Start(workerContext); err != nil {
		cancel()
		assembled.standard.Stop()
		closeErr := assembled.close()
		p.recordStartupFailure()
		return errors.Join(fmt.Errorf("start inspection runtime: %w", err), closeErr)
	}

	// Construct every worker goroutine before publishing readiness. Each worker
	// waits behind the same release gate, so no initial pass can fail or mutate
	// state before the product has atomically published one complete generation.
	workerStarted := make(chan struct{}, productWorkerCount)
	workerRelease := make(chan struct{})
	p.workers.Add(productWorkerCount)
	go p.gateWorker(workerStarted, workerRelease, func() { p.watchLifecycleContext(workerContext) })
	go p.gateWorker(workerStarted, workerRelease, func() {
		p.runMediaPreparations(workerContext, p.config.MediaPreparationWorkerInterval, assembled.mediaPreparations)
	})
	go p.gateWorker(workerStarted, workerRelease, func() {
		p.runTemporary(workerContext, p.config.TemporaryWorkerInterval, assembled.temporary)
	})
	go p.gateWorker(workerStarted, workerRelease, func() {
		p.runPump(workerContext, "outbox", p.config.WorkerInterval, assembled.materializer.MaterializeNext)
	})
	go p.gateWorker(workerStarted, workerRelease, func() {
		p.runDelivery(workerContext, p.config.WorkerInterval, assembled.dispatcher)
	})
	go p.gateWorker(workerStarted, workerRelease, func() {
		p.runSchedule(workerContext, p.config.WorkerInterval, assembled.scheduler, assembled.resources)
	})
	go p.gateWorker(workerStarted, workerRelease, func() {
		p.runMediaGC(workerContext, p.config.MediaGCInterval, assembled.resources.Media)
	})
	go p.gateWorker(workerStarted, workerRelease, func() {
		p.runHandoffRecovery(workerContext, p.config.HandoffRecoveryInterval, assembled.services.onboardingEntry)
	})
	for range productWorkerCount {
		<-workerStarted
	}
	if err := workerContext.Err(); err != nil {
		close(workerRelease)
		cancel()
		p.workers.Wait()
		assembled.standard.Stop()
		closeErr := assembled.close()
		p.recordStartupFailure()
		return errors.Join(fmt.Errorf("start inspection workers: %w", err), closeErr)
	}

	p.opened = assembled.opened
	p.standard = assembled.standard
	p.temporary = assembled.temporary
	p.mediaPreparations = assembled.mediaPreparations
	p.materializer = assembled.materializer
	p.dispatcher = assembled.dispatcher
	p.scheduler = assembled.scheduler
	p.services = assembled.services
	p.connectionRegistry = assembled.connectionRegistry
	p.connectionLifecycle = assembled.connectionLifecycle
	p.connectionRestore = assembled.connectionRestore
	p.cancel = cancel
	p.surfaceMu.Lock()
	p.application = assembled.application
	p.surfaceMu.Unlock()
	p.mu.Lock()
	p.active = true
	p.generation++
	p.metrics.Starts++
	p.state = StateReady
	p.mu.Unlock()
	close(workerRelease)
	return nil
}

func (p *Product) gateWorker(started chan<- struct{}, release <-chan struct{}, run func()) {
	started <- struct{}{}
	<-release
	run()
}

func (p *Product) watchLifecycleContext(ctx context.Context) {
	defer p.workers.Done()
	<-ctx.Done()
	p.mu.Lock()
	if p.active && p.state == StateReady {
		p.state = StateFailed
		p.failure = "lifecycle_context_closed"
		p.metrics.LifecycleInterruptions++
	}
	p.mu.Unlock()
}

func (p *Product) Stop() error {
	if p == nil || !p.config.Enabled {
		return nil
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()

	p.mu.Lock()
	if !p.active {
		p.mu.Unlock()
		return nil
	}
	failed := p.state == StateFailed
	p.state = StateStopping
	cancel, standard := p.cancel, p.standard
	assembled := composition{opened: p.opened, connectionLifecycle: p.connectionLifecycle}
	p.mu.Unlock()

	// Marking the product stopping rejects new requests. Taking the exclusive
	// surface lock then drains every request already admitted before any shared
	// resource or runtime is closed.
	p.surfaceMu.Lock()
	p.application = nil
	p.surfaceMu.Unlock()
	if cancel != nil {
		cancel()
	}
	p.workers.Wait()
	if !isNil(standard) {
		standard.Stop()
	}
	closeErr := assembled.close()
	if closeErr != nil && !isNil(assembled.connectionLifecycle) {
		p.mu.Lock()
		p.state = StateFailed
		p.failure = "connection_persistence_release_failed"
		p.mu.Unlock()
		return closeErr
	}

	p.opened = openedResources{}
	p.standard = nil
	p.temporary = nil
	p.mediaPreparations = nil
	p.materializer = nil
	p.dispatcher = nil
	p.scheduler = nil
	p.services = OperatorServices{}
	p.connectionRegistry = nil
	p.connectionLifecycle = nil
	p.connectionRestore = ""
	p.cancel = nil
	p.mu.Lock()
	p.active = false
	p.metrics.Stops++
	if closeErr != nil {
		p.state = StateFailed
		p.failure = "state_close_failed"
	} else if failed {
		p.state = StateFailed
	} else {
		p.state = StateStopped
	}
	p.mu.Unlock()
	return closeErr
}

func (p *Product) Readiness() Readiness {
	if p == nil {
		return Readiness{State: StateFailed, Failure: "product_unavailable"}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Readiness{
		Enabled: p.config.Enabled, Ready: p.state == StateReady,
		State: p.state, Generation: p.generation, Failure: p.failure,
	}
}

// ConnectionRestoreState reports only the safe startup classification. It
// never projects endpoint, account, credential, or device identity details.
func (p *Product) ConnectionRestoreState() (connectionregistry.RestoreState, error) {
	if p == nil {
		return "", ErrConnectionRestoreUnavailable
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.config.Enabled || !p.active || p.state != StateReady || isNil(p.connectionLifecycle) ||
		p.connectionRestore == "" {
		return "", ErrConnectionRestoreUnavailable
	}
	return p.connectionRestore, nil
}

func (p *Product) Metrics() Metrics {
	if p == nil {
		return Metrics{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.metrics
}

// Handler returns one generation-bound gate to the canonical Inspection v2
// HTTP surface. Callers cannot acquire it before successful startup. A cached
// gate rejects every new request after failure, shutdown or restart, so no
// stale generation can reach closed state resources.
func (p *Product) Handler() (http.Handler, error) {
	if p == nil {
		return nil, ErrHTTPSurfaceUnavailable
	}
	p.surfaceMu.RLock()
	defer p.surfaceMu.RUnlock()
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.config.Enabled || !p.active || p.state != StateReady || p.application == nil {
		return nil, ErrHTTPSurfaceUnavailable
	}
	return productHTTPGate{product: p, generation: p.generation, target: p.application}, nil
}

// DeliveryBindings returns a narrow manager only after Product's private
// channel authorizer resolves an active request-creation credential to one
// exact session. A caller cannot self-assert tenant, site or recipient scope,
// and a manager becomes unusable on stop or restart.
func (p *Product) DeliveryBindings(ctx context.Context, request inspectionhttpapi.AuthorizationRequest) (DeliveryBindingManager, error) {
	if p == nil || request.Scope != inspectionhttpapi.ScopeRequestCreate {
		return nil, ErrDeliveryBindingUnavailable
	}
	p.surfaceMu.RLock()
	defer p.surfaceMu.RUnlock()
	p.mu.RLock()
	available := p.config.Enabled && p.active && p.state == StateReady && p.opened.deliveryBindings.Value != nil &&
		p.opened.channelAuth.Value != nil
	authorizer := p.opened.channelAuth.Value
	generation := p.generation
	p.mu.RUnlock()
	if !available {
		return nil, ErrDeliveryBindingUnavailable
	}
	authorization, err := authorizer.Authorize(ctx, request)
	if err != nil || authorization.Scope != inspectionhttpapi.ScopeRequestCreate || !validDeliveryBindingSession(authorization.Session) {
		return nil, ErrDeliveryBindingUnavailable
	}
	return &scopedDeliveryBindingManager{
		product: p, generation: generation, session: authorization.Session, authorizationRequest: request,
	}, nil
}

func (m *scopedDeliveryBindingManager) Register(ctx context.Context, value inspectiondeliverybinding.Binding) (inspectiondeliverybinding.Binding, bool, error) {
	if m == nil || !bindingMatchesSession(value, m.session) {
		return inspectiondeliverybinding.Binding{}, false, ErrDeliveryBindingScope
	}
	store, release, err := m.acquire(ctx)
	if err != nil {
		return inspectiondeliverybinding.Binding{}, false, err
	}
	defer release()
	return store.Register(ctx, value)
}

func (m *scopedDeliveryBindingManager) Revoke(ctx context.Context, bindingRef string, revision uint64, at time.Time) (inspectiondeliverybinding.Binding, bool, error) {
	if m == nil {
		return inspectiondeliverybinding.Binding{}, false, ErrDeliveryBindingUnavailable
	}
	store, release, err := m.acquire(ctx)
	if err != nil {
		return inspectiondeliverybinding.Binding{}, false, err
	}
	defer release()
	stored, err := store.Get(ctx, m.session.TenantID, m.session.SiteID, bindingRef, revision)
	if err != nil {
		return inspectiondeliverybinding.Binding{}, false, err
	}
	if !bindingMatchesSession(stored, m.session) {
		return inspectiondeliverybinding.Binding{}, false, ErrDeliveryBindingScope
	}
	return store.Revoke(ctx, m.session.TenantID, m.session.SiteID, bindingRef, revision, at)
}

func (m *scopedDeliveryBindingManager) acquire(ctx context.Context) (*inspectiondeliverybinding.Store, func(), error) {
	if m == nil || m.product == nil {
		return nil, nil, ErrDeliveryBindingUnavailable
	}
	p := m.product
	p.surfaceMu.RLock()
	p.mu.RLock()
	available := p.config.Enabled && p.active && p.state == StateReady && p.generation == m.generation &&
		p.opened.deliveryBindings.Value != nil && p.opened.channelAuth.Value != nil
	store := p.opened.deliveryBindings.Value
	authorizer := p.opened.channelAuth.Value
	p.mu.RUnlock()
	if !available {
		p.surfaceMu.RUnlock()
		return nil, nil, ErrDeliveryBindingUnavailable
	}
	authorization, err := authorizer.Authorize(ctx, m.authorizationRequest)
	if err != nil || authorization.Scope != inspectionhttpapi.ScopeRequestCreate || authorization.Session != m.session {
		p.surfaceMu.RUnlock()
		return nil, nil, ErrDeliveryBindingUnavailable
	}
	return store, p.surfaceMu.RUnlock, nil
}

func validDeliveryBindingSession(session inspectionhttpapi.SessionBinding) bool {
	audience := inspectiondelivery.Audience{
		TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
	}
	return audience.Validate() == nil && principalDigestPattern.MatchString(session.PrincipalSHA256)
}

func bindingMatchesSession(value inspectiondeliverybinding.Binding, session inspectionhttpapi.SessionBinding) bool {
	wantAudience := inspectiondelivery.Audience{
		TenantID: session.TenantID, SiteID: session.SiteID, Channel: session.Channel,
		ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
	}
	return validDeliveryBindingSession(session) && value.TenantID == session.TenantID && value.SiteID == session.SiteID &&
		value.PrincipalSHA256 == session.PrincipalSHA256 && value.Audience == wantAudience
}

type productHTTPGate struct {
	product    *Product
	generation uint64
	target     http.Handler
}

func (g productHTTPGate) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if g.product == nil || isNil(g.target) {
		writeSurfaceUnavailable(response)
		return
	}
	p := g.product
	p.surfaceMu.RLock()
	p.mu.RLock()
	available := p.config.Enabled && p.active && p.state == StateReady &&
		p.generation == g.generation && p.application != nil
	p.mu.RUnlock()
	if !available {
		p.surfaceMu.RUnlock()
		writeSurfaceUnavailable(response)
		return
	}
	// Keep the surface read lock until the admitted request completes. Stop
	// takes the exclusive lock before closing resources, which safely drains
	// in-flight requests without permitting a new generation through this gate.
	defer p.surfaceMu.RUnlock()
	g.target.ServeHTTP(response, request)
}

func writeSurfaceUnavailable(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusServiceUnavailable)
	_, _ = response.Write([]byte(`{"error":"inspection_unavailable"}`))
}

func (p *Product) build(ctx context.Context) (composition, error) {
	var assembled composition
	opened := &assembled.opened
	fail := func(stage string, err error) (composition, error) {
		if !isNil(assembled.standard) {
			assembled.standard.Stop()
		}
		return composition{}, errors.Join(
			fmt.Errorf("open inspection product %s: %w", stage, err),
			assembled.opened.close(),
		)
	}
	var err error
	if opened.credentials, err = p.factories.OpenCredentials(ctx, p.paths.CredentialRoot); err != nil || opened.credentials.Value == nil || opened.credentials.Close == nil {
		if err == nil {
			err = errors.New("credential factory returned an incomplete resource")
		}
		return fail("credentials", err)
	}
	if opened.executionAuthority, err = p.factories.OpenExecutionAuthority(
		ctx,
		p.paths.ExecutionAuthorityDatabase,
		p.config.ExecutionAuthorityIssuerID,
		opened.credentials.Value,
	); err != nil || isNil(opened.executionAuthority.Value) || opened.executionAuthority.Close == nil {
		if err == nil {
			err = errors.New("execution authority factory returned an incomplete resource")
		}
		return fail("execution authority", err)
	}
	if opened.profiles, err = p.factories.OpenProfiles(ctx, p.paths.ProfileDatabase); err != nil || opened.profiles.Value == nil || opened.profiles.Close == nil {
		if err == nil {
			err = errors.New("profile factory returned an incomplete resource")
		}
		return fail("profiles", err)
	}
	if opened.onboardingJournal, err = p.factories.OpenOnboardingJournal(ctx, p.paths.OnboardingJournalDatabase); err != nil || opened.onboardingJournal.Value == nil || opened.onboardingJournal.Close == nil {
		if err == nil {
			err = errors.New("onboarding journal factory returned an incomplete resource")
		}
		return fail("onboarding journal", err)
	}
	if opened.onboardingHandoffs, err = p.factories.OpenOnboardingHandoffs(ctx, p.paths.OnboardingHandoffDatabase); err != nil || opened.onboardingHandoffs.Value == nil || opened.onboardingHandoffs.Close == nil {
		if err == nil {
			err = errors.New("onboarding handoff factory returned an incomplete resource")
		}
		return fail("onboarding handoffs", err)
	}
	if opened.pendingInteractions, err = p.factories.OpenPendingInteractions(ctx, p.paths.PendingInteractionDatabase); err != nil || opened.pendingInteractions.Value == nil || opened.pendingInteractions.Close == nil {
		if err == nil {
			err = errors.New("pending interaction factory returned an incomplete resource")
		}
		return fail("pending interactions", err)
	}
	if opened.catalog, err = p.factories.OpenCatalog(ctx, p.paths.SourceCatalog); err != nil || opened.catalog.Value == nil || opened.catalog.Close == nil {
		if err == nil {
			err = errors.New("catalog factory returned an incomplete resource")
		}
		return fail("catalog", err)
	}
	if opened.application, err = p.factories.OpenApplication(ctx, p.paths.ApplicationState); err != nil || opened.application.Value == nil || opened.application.Close == nil {
		if err == nil {
			err = errors.New("application state factory returned an incomplete resource")
		}
		return fail("application state", err)
	}
	if opened.channelAuth, err = p.factories.OpenChannelAuth(ctx, p.paths.ChannelBindings); err != nil || opened.channelAuth.Value == nil || opened.channelAuth.Close == nil {
		if err == nil {
			err = errors.New("channel authorization factory returned an incomplete resource")
		}
		return fail("channel authorization", err)
	}
	if opened.changeflow, err = p.factories.OpenChangeflow(ctx, p.paths.ChangeflowJournal); err != nil || opened.changeflow.Value == nil || opened.changeflow.Close == nil {
		if err == nil {
			err = errors.New("changeflow factory returned an incomplete resource")
		}
		return fail("changeflow", err)
	}
	if opened.runs, err = p.factories.OpenRuns(ctx, p.paths.RunDatabase); err != nil || opened.runs.Value == nil || opened.runs.Close == nil {
		if err == nil {
			err = errors.New("run factory returned an incomplete resource")
		}
		return fail("runs", err)
	}
	if opened.temporary, err = p.factories.OpenTemporary(ctx, p.paths.TemporaryDatabase); err != nil || opened.temporary.Value == nil || opened.temporary.Close == nil {
		if err == nil {
			err = errors.New("temporary runtime factory returned an incomplete resource")
		}
		return fail("temporary runtime", err)
	}
	if opened.schedules, err = p.factories.OpenSchedules(ctx, p.paths.ScheduleDatabase); err != nil || opened.schedules.Value == nil || opened.schedules.Close == nil {
		if err == nil {
			err = errors.New("schedule factory returned an incomplete resource")
		}
		return fail("schedules", err)
	}
	if opened.media, err = p.factories.OpenMedia(ctx, inspectionmedia.Config{Root: p.paths.MediaRoot}); err != nil || opened.media.Value == nil || opened.media.Close == nil {
		if err == nil {
			err = errors.New("media factory returned an incomplete resource")
		}
		return fail("media", err)
	}
	if opened.mediaPreparations, err = p.factories.OpenMediaPreparations(ctx, inspectionmediaprep.Config{
		Path:      p.paths.MediaPreparationDatabase,
		Owner:     p.config.MediaPreparationWorkerOwner,
		Acquirer:  p.factories.MediaPreparationAcquirer,
		Publisher: opened.media.Value,
	}); err != nil || opened.mediaPreparations.Value == nil || opened.mediaPreparations.Close == nil {
		if err == nil {
			err = errors.New("temporary media preparation factory returned an incomplete resource")
		}
		return fail("temporary media preparations", err)
	}
	assembled.mediaPreparations = opened.mediaPreparations.Value
	if opened.delivery, err = p.factories.OpenDelivery(ctx, p.paths.DeliveryDatabase); err != nil || opened.delivery.Value == nil || opened.delivery.Close == nil {
		if err == nil {
			err = errors.New("delivery factory returned an incomplete resource")
		}
		return fail("delivery", err)
	}
	if opened.deliveryBindings, err = p.factories.OpenDeliveryBindings(ctx, p.paths.DeliveryBindingDatabase); err != nil || opened.deliveryBindings.Value == nil || opened.deliveryBindings.Close == nil {
		if err == nil {
			err = errors.New("delivery binding factory returned an incomplete resource")
		}
		return fail("delivery bindings", err)
	}

	assembled.resources = Resources{
		Catalog:     opened.catalog.Value,
		Application: opened.application.Value, ChannelAuth: opened.channelAuth.Value,
		Runs: opened.runs.Value, Temporary: opened.temporary.Value, Schedules: opened.schedules.Value,
		Media: opened.media.Value, Delivery: opened.delivery.Value,
	}
	onboardingCore, err := onboarding.NewService(
		opened.profiles.Value,
		opened.credentials.Value,
		opened.onboardingJournal.Value,
		p.factories.AuthorityVerifier,
	)
	if err != nil {
		return fail("onboarding service", err)
	}
	if persistent := p.config.PersistentConnection; persistent != nil {
		assembled.connectionRegistry, err = connectionregistry.New(connectionregistry.Config{
			Profiles: opened.profiles.Value, Credentials: opened.credentials.Value,
			Onboarding: onboardingCore, Issuer: p.factories.ConnectionAuthorityIssuer,
			TenantID: persistent.TenantID, SiteID: persistent.SiteID,
			PrincipalSHA256: persistent.PrincipalSHA256, ProfileID: persistent.ProfileID,
			CreateOperationID: persistent.CreateOperationID, Alias: persistent.Alias,
		})
		if err != nil {
			return fail("persistent connection registry", err)
		}
		assembled.connectionLifecycle, err = p.factories.BuildConnectionLifecycle(assembled.connectionRegistry)
		if err != nil || isNil(assembled.connectionLifecycle) {
			if err == nil {
				err = errors.New("persistent connection lifecycle builder returned nil")
			}
			return fail("persistent connection lifecycle", err)
		}
	}
	onboardingEntry, err := onboarding.NewEntryService(onboarding.EntryServiceConfig{
		Core: onboardingCore, Handoffs: opened.onboardingHandoffs.Value,
	})
	if err != nil {
		return fail("onboarding entry service", err)
	}
	interactionRegistrar, err := inspectioninteraction.NewRegistrar(inspectioninteraction.RegistrarConfig{
		Onboarding: onboardingEntry, Changes: opened.pendingInteractions.Value,
	})
	if err != nil {
		return fail("inspection interaction registrar", err)
	}
	assembled.services = OperatorServices{
		onboardingEntry: onboardingEntry, interactionRegistrar: interactionRegistrar,
	}
	if !assembled.services.valid() {
		return fail("operator services", errors.New("operator services are incomplete"))
	}
	execution := ExecutionBinding{
		authority: opened.executionAuthority.Value,
		runtimeID: p.config.ExecutionRuntimeID,
	}
	if !execution.valid() {
		return fail("execution binding", errors.New("execution binding is incomplete"))
	}
	standard, err := p.factories.BuildStandardRuntime(ctx, assembled.resources, execution)
	if err != nil || isNil(standard) {
		if err == nil {
			err = errors.New("standard runtime builder returned nil")
		}
		return fail("standard runtime", err)
	}
	assembled.standard = standard
	preparationReader := mediaPreparationReader{get: assembled.mediaPreparations.Get}
	temporaryRuntime, err := p.factories.BuildTemporaryRuntime(ctx, assembled.resources, preparationReader)
	if err != nil || isNil(temporaryRuntime) {
		if err == nil {
			err = errors.New("temporary runtime builder returned nil")
		}
		return fail("temporary runtime", err)
	}
	assembled.temporary = temporaryRuntime
	preparationRegistrar := mediaPreparationRegistrar{prepare: assembled.mediaPreparations.Prepare}
	applicationBackend, err := p.factories.BuildApplicationBackend(ctx, assembled.resources, assembled.services, standard, temporaryRuntime, preparationRegistrar)
	if err != nil || isNil(applicationBackend) {
		if err == nil {
			err = errors.New("application backend builder returned nil")
		}
		return fail("application backend", err)
	}
	handler, err := inspectionhttpapi.NewHandler(applicationBackend, assembled.resources.ChannelAuth)
	if err != nil {
		return fail("application HTTP surface", err)
	}
	assembled.application = &applicationSurface{handler: handler, backend: applicationBackend}
	assembled.materializer, err = p.factories.BuildOutboxMaterializer(ctx, assembled.resources, assembled.application)
	if err != nil || isNil(assembled.materializer) {
		if err == nil {
			err = errors.New("outbox materializer builder returned nil")
		}
		return fail("outbox materializer", err)
	}
	assembled.dispatcher, err = p.factories.BuildDeliveryDispatcher(ctx, assembled.resources)
	if err != nil || isNil(assembled.dispatcher) {
		if err == nil {
			err = errors.New("delivery dispatcher builder returned nil")
		}
		return fail("delivery dispatcher", err)
	}
	scheduleBridge, err := inspectionschedulebridge.New(inspectionschedulebridge.Config{
		State: opened.application.Value, Bindings: opened.deliveryBindings.Value,
		Runner: standard, Repository: opened.runs.Value, Verifier: p.factories.AuthorityVerifier,
	})
	if err != nil {
		return fail("schedule bridge", err)
	}
	assembled.scheduler, err = p.factories.BuildScheduleCoordinator(ctx, opened.schedules.Value, scheduleBridge)
	if err != nil || isNil(assembled.scheduler) {
		if err == nil {
			err = errors.New("schedule coordinator builder returned nil")
		}
		return fail("schedule coordinator", err)
	}
	return assembled, nil
}

func (p *Product) reconcileAllHandoffs(ctx context.Context, entry handoffReconciler) error {
	afterRef := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, complete, err := p.reconcileHandoffPage(ctx, entry, afterRef)
		if err != nil {
			return err
		}
		if complete {
			if err := ctx.Err(); err != nil {
				return err
			}
			return nil
		}
		afterRef = result.NextAfterRef
	}
}

func (p *Product) reconcileHandoffPage(
	ctx context.Context,
	entry handoffReconciler,
	afterRef string,
) (onboarding.HandoffReconcileResult, bool, error) {
	if isNil(entry) {
		p.recordHandoffRecovery(onboarding.HandoffReconcileResult{}, false)
		return onboarding.HandoffReconcileResult{}, false, errors.New("onboarding entry service is unavailable")
	}
	result, err := entry.ReconcileCompletedHandoffs(ctx, onboarding.HandoffReconcileRequest{
		AfterRef: afterRef,
		Limit:    onboarding.MaximumHandoffRecoveryBatch,
	})
	if err != nil {
		if validationErr := validateHandoffReconcileProgress(afterRef, result); validationErr != nil {
			p.recordHandoffRecovery(onboarding.HandoffReconcileResult{}, false)
			return onboarding.HandoffReconcileResult{}, false, errors.Join(err, validationErr)
		}
		p.recordHandoffRecovery(result, false)
		return result, false, err
	}
	complete, err := validateHandoffReconcileResult(afterRef, result)
	if err != nil {
		p.recordHandoffRecovery(onboarding.HandoffReconcileResult{}, false)
		return onboarding.HandoffReconcileResult{}, false, err
	}
	p.recordHandoffRecovery(result, complete)
	return result, complete, nil
}

func validateHandoffReconcileResult(afterRef string, result onboarding.HandoffReconcileResult) (bool, error) {
	if err := validateHandoffReconcileProgress(afterRef, result); err != nil {
		return false, err
	}
	return result.Examined == 0, nil
}

func validateHandoffReconcileProgress(afterRef string, result onboarding.HandoffReconcileResult) error {
	next := result.NextAfterRef
	if result.Examined < 0 || result.Examined > onboarding.MaximumHandoffRecoveryBatch ||
		result.ConfirmedCompleted < 0 || result.ConfirmedCompleted > result.Examined ||
		next != strings.TrimSpace(next) {
		return errors.New("onboarding handoff recovery returned invalid counters or cursor")
	}
	if result.Examined == 0 {
		if next != "" {
			return errors.New("empty onboarding handoff recovery page returned a cursor")
		}
		return nil
	}
	if !handoffRecoveryCursorPattern.MatchString(next) || next <= afterRef {
		return errors.New("onboarding handoff recovery cursor did not advance")
	}
	return nil
}

func (p *Product) recordHandoffRecovery(result onboarding.HandoffReconcileResult, complete bool) {
	p.mu.Lock()
	p.metrics.HandoffRecoveryPasses++
	p.metrics.HandoffsExamined += uint64(result.Examined)
	p.metrics.HandoffsCompleted += uint64(result.ConfirmedCompleted)
	if complete {
		p.metrics.HandoffRecoverySweeps++
	}
	p.mu.Unlock()
}

func (p *Product) runHandoffRecovery(ctx context.Context, interval time.Duration, entry handoffReconciler) {
	defer p.workers.Done()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		err := p.reconcileAllHandoffs(ctx, entry)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				p.failWorker("onboarding_recovery")
			}
			return
		}
		timer.Reset(interval)
	}
}

// runMediaPreparations is the sole owner of recovery and processing authority
// for temporary media acquisition. Errors that name an already-persisted
// business outcome do not make the Product unavailable; corruption, I/O and
// contract failures outside those terminal transitions fail closed.
func (p *Product) runMediaPreparations(ctx context.Context, interval time.Duration, processor mediaPreparationProcessor) {
	defer p.workers.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		recovery, err := processor.Recover(ctx)
		if err == nil && !validMediaPreparationRecovery(recovery) {
			err = errors.New("temporary media preparation recovery returned invalid counters")
		}
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				p.failWorker("media_preparation_recovery")
			}
			return
		}
		p.recordMediaPreparationRecovery(recovery)

		for {
			_, processed, processErr := processor.ProcessNext(ctx)
			persistedOutcome := isPersistedMediaPreparationOutcome(processErr)
			leaseConflict := errors.Is(processErr, inspectionmediaprep.ErrLeaseLost)
			p.recordMediaPreparationPass(processed, persistedOutcome, leaseConflict)
			if processErr != nil {
				if persistedOutcome || leaseConflict {
					if !processed {
						break
					}
					continue
				}
				if !errors.Is(processErr, context.Canceled) && !errors.Is(processErr, context.DeadlineExceeded) {
					p.failWorker("media_preparation")
				}
				return
			}
			if !processed {
				break
			}
		}
		timer.Reset(interval)
	}
}

func isPersistedMediaPreparationOutcome(err error) bool {
	return errors.Is(err, inspectionmediaprep.ErrOutcomeUnknown) ||
		errors.Is(err, inspectionmediaprep.ErrPublicationUnknown) ||
		errors.Is(err, inspectionmediaprep.ErrPublicationRejected) ||
		errors.Is(err, inspectionmediaprep.ErrAcquirerContract)
}

func validMediaPreparationRecovery(recovery inspectionmediaprep.Recovery) bool {
	return recovery.AcquisitionLeasesRecovered >= 0 &&
		recovery.ReconciliationLeasesRecovered >= 0 &&
		recovery.PublicationLeasesRecovered >= 0
}

func (p *Product) recordMediaPreparationRecovery(recovery inspectionmediaprep.Recovery) {
	p.mu.Lock()
	p.metrics.MediaPreparationRecoveryPasses++
	p.metrics.MediaPreparationAcquisitionRecovered += uint64(recovery.AcquisitionLeasesRecovered)
	p.metrics.MediaPreparationReconcileRecovered += uint64(recovery.ReconciliationLeasesRecovered)
	p.metrics.MediaPreparationPublicationRecovered += uint64(recovery.PublicationLeasesRecovered)
	p.mu.Unlock()
}

func (p *Product) recordMediaPreparationPass(processed, persistedOutcome, leaseConflict bool) {
	p.mu.Lock()
	p.metrics.MediaPreparationPasses++
	if processed {
		p.metrics.MediaPreparationsProcessed++
	}
	if persistedOutcome {
		p.metrics.MediaPreparationPersistedOutcomes++
	}
	if leaseConflict {
		p.metrics.MediaPreparationLeaseConflicts++
	}
	p.mu.Unlock()
}

func (p *Product) runTemporary(ctx context.Context, interval time.Duration, processor TemporaryProcessor) {
	defer p.workers.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		for {
			record, processed, err := processor.RunOnce(ctx, p.config.TemporaryWorkerOwner, p.config.TemporaryLeaseTTL)
			if err == nil && processed {
				if validationErr := record.Validate(); validationErr != nil {
					err = errors.New("temporary processor returned an invalid persisted record")
				}
			}
			p.mu.Lock()
			p.metrics.TemporaryPasses++
			if processed {
				p.metrics.TemporaryClaims++
			}
			p.mu.Unlock()
			if err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					p.failWorker("temporary")
				}
				return
			}
			if !processed {
				break
			}
		}
		timer.Reset(interval)
	}
}

func (p *Product) runPump(ctx context.Context, name string, interval time.Duration, process func(context.Context) (bool, error)) {
	defer p.workers.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		for {
			processed, err := process(ctx)
			p.recordPumpPass(name, processed, err)
			if err != nil {
				if name == "delivery" && errors.Is(err, inspectiondelivery.ErrOutcomeUnknown) {
					// Outcome-unknown is a durable delivery state, not a worker
					// failure. The dispatcher has already stopped blind replay;
					// continue so unrelated recipients are not starved while
					// reconciliation is pending.
					continue
				}
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					p.failWorker(name)
				}
				return
			}
			if !processed {
				break
			}
		}
		timer.Reset(interval)
	}
}

// runDelivery owns all three durable delivery paths. Recovery advances only
// expired leases, reconciliation resolves outcome-unknown sends, and delivery
// handles only records that are proven eligible for a new send. Keeping the
// paths in this order prevents a restart from blindly resending an interrupted
// channel operation.
func (p *Product) runDelivery(ctx context.Context, interval time.Duration, dispatcher DeliveryDispatcher) {
	defer p.workers.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		recovery, err := dispatcher.Recover(ctx)
		if err == nil && !validDeliveryRecovery(recovery) {
			err = errors.New("inspection delivery recovery returned invalid counters")
		}
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				p.failWorker("delivery_recovery")
			}
			return
		}
		p.recordDeliveryRecovery(recovery)

		for {
			processed, reconcileErr := dispatcher.ReconcileNext(ctx)
			p.recordDeliveryReconciliation(processed, reconcileErr)
			if reconcileErr != nil && !errors.Is(reconcileErr, inspectiondelivery.ErrOutcomeUnknown) {
				if !errors.Is(reconcileErr, context.Canceled) && !errors.Is(reconcileErr, context.DeadlineExceeded) {
					p.failWorker("delivery_reconciliation")
				}
				return
			}
			if !processed {
				break
			}
		}

		for {
			processed, deliveryErr := dispatcher.DeliverNext(ctx)
			p.recordPumpPass("delivery", processed, deliveryErr)
			if deliveryErr != nil && !errors.Is(deliveryErr, inspectiondelivery.ErrOutcomeUnknown) {
				if !errors.Is(deliveryErr, context.Canceled) && !errors.Is(deliveryErr, context.DeadlineExceeded) {
					p.failWorker("delivery")
				}
				return
			}
			if !processed {
				break
			}
		}
		timer.Reset(interval)
	}
}

func (p *Product) runMediaGC(ctx context.Context, interval time.Duration, store *inspectionmedia.Store) {
	defer p.workers.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		purged, err := store.GC(ctx)
		p.mu.Lock()
		p.metrics.MediaGCPasses++
		if purged > 0 {
			p.metrics.MediaDescriptorsPurged += uint64(purged)
		}
		p.mu.Unlock()
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				p.failWorker("media_gc")
			}
			return
		}
		timer.Reset(interval)
	}
}

func (p *Product) runSchedule(ctx context.Context, interval time.Duration, coordinator ScheduleCoordinator, resources Resources) {
	defer p.workers.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		report, err := coordinator.Tick(ctx)
		if err == nil {
			_, purgeErr := purgeScheduledApplicationState(ctx, resources.Application, resources.Runs, resources.Schedules, resources.Delivery, time.Now().UTC())
			err = errors.Join(err, purgeErr)
		}
		if !validScheduleReport(report) {
			err = errors.Join(err, errors.New("inspection schedule coordinator returned invalid counters"))
			report = inspectionschedule.TickReport{}
		}
		p.mu.Lock()
		p.metrics.SchedulePasses++
		p.metrics.ScheduleOccurrences += uint64(report.OccurrencesCreated)
		p.metrics.ScheduleSubmissions += uint64(report.Submitted)
		p.metrics.ScheduleBlocked += uint64(report.Blocked + report.Expired)
		p.metrics.ScheduleUnknownOutcomes += uint64(report.SubmissionUnknown)
		p.mu.Unlock()
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				p.failWorker("schedule")
			}
			return
		}
		timer.Reset(interval)
	}
}

type scheduledRetentionState interface {
	ListScheduledPurgeCandidates(context.Context, time.Time, int) ([]inspectionapplication.ScheduledPurgeCandidate, error)
	PurgeScheduledCandidate(context.Context, inspectionapplication.ScheduledPurgeCandidate, time.Time) (bool, error)
}

type scheduledRunReader interface {
	GetRun(context.Context, string) (inspection.Run, error)
}

type scheduledOccurrenceReleaseReader interface {
	IsOccurrenceReleasedTerminal(context.Context, string, string) (bool, error)
}

type scheduledDeliveryReader interface {
	GetRunDelivery(context.Context, string, string) (inspectiondelivery.Record, error)
}

func purgeScheduledApplicationState(
	ctx context.Context,
	application scheduledRetentionState,
	runs scheduledRunReader,
	schedules scheduledOccurrenceReleaseReader,
	deliveries scheduledDeliveryReader,
	now time.Time,
) (int, error) {
	if isNil(application) || isNil(runs) || isNil(schedules) || isNil(deliveries) || now.IsZero() {
		return 0, errors.New("inspection scheduled retention dependencies are incomplete")
	}
	candidates, err := application.ListScheduledPurgeCandidates(ctx, now.UTC(), 64)
	if err != nil {
		return 0, err
	}
	purged := 0
	for _, candidate := range candidates {
		run, err := runs.GetRun(ctx, candidate.InternalRunID)
		if errors.Is(err, inspectionstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return purged, err
		}
		if !inspection.Terminal(run.State) || run.RunID != candidate.InternalRunID {
			continue
		}
		released, err := schedules.IsOccurrenceReleasedTerminal(ctx, candidate.OccurrenceID, candidate.InternalRunID)
		if errors.Is(err, inspectionschedule.ErrNotFound) {
			continue
		}
		if err != nil {
			return purged, err
		}
		if !released {
			continue
		}
		deliveryRecord, err := deliveries.GetRunDelivery(ctx, candidate.PublicRunRef, candidate.AudienceSHA256)
		if errors.Is(err, inspectiondelivery.ErrNotFound) {
			continue
		}
		if err != nil {
			return purged, err
		}
		if deliveryRecord.State != inspectiondelivery.StateDelivered && deliveryRecord.State != inspectiondelivery.StateFailed {
			continue
		}
		changed, err := application.PurgeScheduledCandidate(ctx, candidate, now.UTC())
		if err != nil {
			return purged, err
		}
		if changed {
			purged++
		}
	}
	return purged, nil
}

func validScheduleReport(report inspectionschedule.TickReport) bool {
	return report.SchedulesScanned >= 0 && report.SchedulesExpired >= 0 && report.OccurrencesCreated >= 0 &&
		report.Submitted >= 0 && report.Blocked >= 0 && report.Expired >= 0 &&
		report.SubmissionUnknown >= 0 && report.Reconciled >= 0
}

func (p *Product) recordPumpPass(name string, processed bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch name {
	case "outbox":
		p.metrics.OutboxPasses++
		if processed {
			p.metrics.OutboxMessages++
		}
	case "delivery":
		p.metrics.DeliveryPasses++
		if processed {
			p.metrics.Deliveries++
		}
		if errors.Is(err, inspectiondelivery.ErrOutcomeUnknown) {
			p.metrics.DeliveryUnknownOutcomes++
		}
	}
}

func (p *Product) recordDeliveryRecovery(recovery inspectiondelivery.Recovery) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.DeliveryRecoveryPasses++
	if recovery.SendingBecameUnknown > 0 {
		p.metrics.DeliverySendingRecovered += uint64(recovery.SendingBecameUnknown)
	}
	if recovery.ReconciliationLeaseFreed > 0 {
		p.metrics.DeliveryReconciliationLeasesRecovered += uint64(recovery.ReconciliationLeaseFreed)
	}
}

func validDeliveryRecovery(recovery inspectiondelivery.Recovery) bool {
	return recovery.SendingBecameUnknown >= 0 && recovery.ReconciliationLeaseFreed >= 0
}

func (p *Product) recordDeliveryReconciliation(processed bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.DeliveryReconciliationPasses++
	if processed {
		p.metrics.DeliveriesReconciled++
	}
	if errors.Is(err, inspectiondelivery.ErrOutcomeUnknown) {
		p.metrics.DeliveryUnknownOutcomes++
	}
}

func (p *Product) failWorker(name string) {
	p.mu.Lock()
	if p.active && p.state != StateStopping && p.state != StateFailed {
		p.state = StateFailed
		p.failure = name + "_worker_failed"
		p.metrics.WorkerFailures++
		if p.cancel != nil {
			p.cancel()
		}
	}
	p.mu.Unlock()
}

func (p *Product) recordStartupFailure() {
	p.mu.Lock()
	p.state = StateFailed
	p.failure = "startup_failed"
	p.metrics.StartupFailures++
	p.mu.Unlock()
}

func (o openedResources) close() error {
	var result error
	for _, closeResource := range []func() error{
		o.deliveryBindings.Close, o.delivery.Close, o.mediaPreparations.Close, o.media.Close, o.schedules.Close, o.temporary.Close, o.runs.Close,
		o.changeflow.Close, o.channelAuth.Close, o.application.Close, o.catalog.Close,
		o.pendingInteractions.Close, o.onboardingHandoffs.Close, o.onboardingJournal.Close,
		o.profiles.Close, o.executionAuthority.Close, o.credentials.Close,
	} {
		if closeResource != nil {
			result = errors.Join(result, closeResource())
		}
	}
	return result
}

func normalizeEnabledConfig(config Config) (Config, StatePaths, error) {
	if strings.TrimSpace(config.StateRoot) == "" || strings.ContainsAny(config.StateRoot, "\x00?#") {
		return Config{}, StatePaths{}, errors.New("enabled inspection product requires a protected state root")
	}
	root, err := filepath.Abs(config.StateRoot)
	if err != nil {
		return Config{}, StatePaths{}, err
	}
	root = filepath.Clean(root)
	if root == string(os.PathSeparator) || root == filepath.Dir(root) {
		return Config{}, StatePaths{}, errors.New("inspection product state root must be a dedicated directory")
	}
	if config.WorkerInterval == 0 {
		config.WorkerInterval = defaultWorkerInterval
	}
	if config.MediaGCInterval == 0 {
		config.MediaGCInterval = defaultMediaGCInterval
	}
	if config.HandoffRecoveryInterval == 0 {
		config.HandoffRecoveryInterval = defaultHandoffRecoveryInterval
	}
	if config.TemporaryWorkerInterval == 0 {
		config.TemporaryWorkerInterval = config.WorkerInterval
	}
	if config.MediaPreparationWorkerInterval == 0 {
		config.MediaPreparationWorkerInterval = config.WorkerInterval
	}
	if config.MediaPreparationWorkerOwner == "" {
		config.MediaPreparationWorkerOwner = defaultMediaPreparationOwner
	}
	if config.TemporaryLeaseTTL == 0 {
		config.TemporaryLeaseTTL = defaultTemporaryLease
	}
	if config.ExecutionAuthorityIssuerID == "" {
		config.ExecutionAuthorityIssuerID = defaultExecutionAuthorityIssuer
	}
	if config.ExecutionRuntimeID == "" {
		config.ExecutionRuntimeID = defaultExecutionRuntimeID
	}
	if config.WorkerInterval <= 0 || config.WorkerInterval > 24*time.Hour ||
		config.MediaGCInterval <= 0 || config.MediaGCInterval > 24*time.Hour ||
		config.HandoffRecoveryInterval <= 0 || config.HandoffRecoveryInterval > 24*time.Hour ||
		config.TemporaryWorkerInterval <= 0 || config.TemporaryWorkerInterval > 24*time.Hour ||
		config.MediaPreparationWorkerInterval <= 0 || config.MediaPreparationWorkerInterval > 24*time.Hour {
		return Config{}, StatePaths{}, errors.New("inspection product worker intervals must be positive and bounded")
	}
	if !temporaryWorkerOwnerPattern.MatchString(config.TemporaryWorkerOwner) {
		return Config{}, StatePaths{}, errors.New("enabled inspection product requires a bounded temporary worker owner")
	}
	if !temporaryWorkerOwnerPattern.MatchString(config.MediaPreparationWorkerOwner) || len(config.MediaPreparationWorkerOwner) > 64 {
		return Config{}, StatePaths{}, errors.New("inspection product media preparation owner is invalid")
	}
	if !temporaryWorkerOwnerPattern.MatchString(config.ExecutionAuthorityIssuerID) ||
		len(config.ExecutionAuthorityIssuerID) > 64 ||
		!temporaryWorkerOwnerPattern.MatchString(config.ExecutionRuntimeID) || len(config.ExecutionRuntimeID) > 64 {
		return Config{}, StatePaths{}, errors.New("inspection product execution identities are invalid")
	}
	if config.TemporaryLeaseTTL <= 0 || config.TemporaryLeaseTTL > inspectiontemporary.MaxLeaseTTL {
		return Config{}, StatePaths{}, errors.New("inspection product temporary worker lease is invalid")
	}
	if config.PersistentConnection != nil {
		persistent := *config.PersistentConnection
		persistent.TenantID = strings.TrimSpace(persistent.TenantID)
		persistent.SiteID = strings.TrimSpace(persistent.SiteID)
		persistent.PrincipalSHA256 = strings.TrimSpace(persistent.PrincipalSHA256)
		persistent.ProfileID = strings.TrimSpace(persistent.ProfileID)
		persistent.CreateOperationID = strings.TrimSpace(persistent.CreateOperationID)
		persistent.Alias = strings.TrimSpace(persistent.Alias)
		if !temporaryWorkerOwnerPattern.MatchString(persistent.TenantID) ||
			!temporaryWorkerOwnerPattern.MatchString(persistent.SiteID) ||
			!principalDigestPattern.MatchString(persistent.PrincipalSHA256) ||
			!connectionProfileIDPattern.MatchString(persistent.ProfileID) ||
			!connectionOperationPattern.MatchString(persistent.CreateOperationID) ||
			persistent.Alias == "" || len(persistent.Alias) > 128 {
			return Config{}, StatePaths{}, errors.New("inspection product persistent connection binding is invalid")
		}
		config.PersistentConnection = &persistent
	}
	config.StateRoot = root
	productRoot := filepath.Join(root, "inspection-v2")
	paths := StatePaths{
		CredentialRoot:             filepath.Join(productRoot, "credentials"),
		ExecutionAuthorityDatabase: filepath.Join(productRoot, operatorinspectionauthority.DatabaseFilename),
		ProfileDatabase:            filepath.Join(productRoot, "device-profiles.db"),
		OnboardingJournalDatabase:  filepath.Join(productRoot, "onboarding-journal.db"),
		OnboardingHandoffDatabase:  filepath.Join(productRoot, "onboarding-handoffs.db"),
		PendingInteractionDatabase: filepath.Join(productRoot, "pending-interactions.db"),
		SourceCatalog:              filepath.Join(productRoot, "source-catalog.db"),
		ApplicationState:           filepath.Join(productRoot, "application.db"),
		ChannelBindings:            filepath.Join(productRoot, "channel-bindings.db"),
		ChangeflowJournal:          filepath.Join(productRoot, "changeflow.json"),
		RunDatabase:                filepath.Join(productRoot, "runs.db"),
		TemporaryDatabase:          filepath.Join(productRoot, "temporary-runs.db"),
		ScheduleDatabase:           filepath.Join(productRoot, "schedules.db"),
		MediaRoot:                  filepath.Join(productRoot, "media"),
		MediaPreparationDatabase:   filepath.Join(productRoot, "media-preparations.db"),
		DeliveryDatabase:           filepath.Join(productRoot, "delivery.db"),
		DeliveryBindingDatabase:    filepath.Join(productRoot, "delivery-bindings.db"),
	}
	return config, paths, nil
}

func validateFactories(factories Factories, persistentConnection bool) error {
	if isNil(factories.AuthorityVerifier) || factories.OpenCredentials == nil || factories.OpenExecutionAuthority == nil || factories.OpenProfiles == nil ||
		factories.OpenOnboardingJournal == nil || factories.OpenOnboardingHandoffs == nil || factories.OpenPendingInteractions == nil ||
		factories.OpenCatalog == nil || factories.OpenApplication == nil || factories.OpenChannelAuth == nil || factories.OpenChangeflow == nil ||
		factories.OpenRuns == nil || factories.OpenMedia == nil || isNil(factories.MediaPreparationAcquirer) ||
		factories.OpenMediaPreparations == nil || factories.OpenDelivery == nil || factories.OpenDeliveryBindings == nil ||
		factories.OpenTemporary == nil || factories.OpenSchedules == nil ||
		factories.BuildStandardRuntime == nil || factories.BuildTemporaryRuntime == nil || factories.BuildApplicationBackend == nil ||
		factories.BuildOutboxMaterializer == nil || factories.BuildDeliveryDispatcher == nil || factories.BuildScheduleCoordinator == nil {
		return errors.New("enabled inspection product requires every state and worker factory")
	}
	if persistentConnection && (isNil(factories.ConnectionAuthorityIssuer) || factories.BuildConnectionLifecycle == nil) {
		return errors.New("persistent connection requires an authority issuer and lifecycle builder")
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func noClose() error { return nil }
