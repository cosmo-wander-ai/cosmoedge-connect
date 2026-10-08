package mediaprep

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

const (
	defaultLeaseTTL       = 30 * time.Second
	defaultCallTimeout    = 10 * time.Second
	defaultBaseBackoff    = 2 * time.Second
	defaultMaximumBackoff = 5 * time.Minute
	maximumLeaseTTL       = 10 * time.Minute
)

var errPublicationContentRequired = errors.New("temporary media publication content is required")

type publicationProbeReader struct{}

func (publicationProbeReader) Read([]byte) (int, error) {
	return 0, errPublicationContentRequired
}

type Config struct {
	Path             string
	Owner            string
	Acquirer         Acquirer
	Publisher        Publisher
	LeaseTTL         time.Duration
	AcquireTimeout   time.Duration
	ReconcileTimeout time.Duration
	PublishTimeout   time.Duration
	BaseBackoff      time.Duration
	MaximumBackoff   time.Duration
	Now              func() time.Time
}

type Manager struct {
	store            *sqliteStore
	owner            string
	acquirer         Acquirer
	publisher        Publisher
	leaseTTL         time.Duration
	acquireTimeout   time.Duration
	reconcileTimeout time.Duration
	publishTimeout   time.Duration
	baseBackoff      time.Duration
	maximumBackoff   time.Duration
	now              func() time.Time
	closeMu          sync.RWMutex
	closed           bool
}

func Open(config Config) (*Manager, error) {
	if err := normalizeConfig(&config); err != nil {
		return nil, err
	}
	store, err := openSQLite(config.Path)
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		store: store, owner: config.Owner, acquirer: config.Acquirer, publisher: config.Publisher,
		leaseTTL: config.LeaseTTL, acquireTimeout: config.AcquireTimeout,
		reconcileTimeout: config.ReconcileTimeout, publishTimeout: config.PublishTimeout,
		baseBackoff: config.BaseBackoff, maximumBackoff: config.MaximumBackoff, now: config.Now,
	}
	if _, err := manager.recover(context.Background()); err != nil {
		_ = store.Close()
		return nil, err
	}
	return manager, nil
}

func normalizeConfig(config *Config) error {
	if config == nil || strings.TrimSpace(config.Path) == "" || !validRef(config.Owner) ||
		config.Acquirer == nil || config.Publisher == nil {
		return ErrInvalid
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = defaultLeaseTTL
	}
	if config.AcquireTimeout == 0 {
		config.AcquireTimeout = defaultCallTimeout
	}
	if config.ReconcileTimeout == 0 {
		config.ReconcileTimeout = defaultCallTimeout
	}
	if config.PublishTimeout == 0 {
		config.PublishTimeout = defaultCallTimeout
	}
	if config.BaseBackoff == 0 {
		config.BaseBackoff = defaultBaseBackoff
	}
	if config.MaximumBackoff == 0 {
		config.MaximumBackoff = defaultMaximumBackoff
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.LeaseTTL < 2*time.Second || config.LeaseTTL > maximumLeaseTTL ||
		config.AcquireTimeout <= 0 || config.AcquireTimeout > config.LeaseTTL/2 ||
		config.ReconcileTimeout <= 0 || config.ReconcileTimeout > config.LeaseTTL/2 ||
		config.PublishTimeout <= 0 || config.PublishTimeout > config.LeaseTTL/2 ||
		config.BaseBackoff <= 0 || config.MaximumBackoff < config.BaseBackoff || config.MaximumBackoff > 24*time.Hour {
		return ErrInvalid
	}
	return nil
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	return m.store.Close()
}

func (m *Manager) Prepare(ctx context.Context, request FrozenRequest) (Status, bool, error) {
	if err := m.enter(); err != nil {
		return Status{}, false, err
	}
	defer m.leave()
	now := m.now().UTC()
	if _, err := m.store.recover(ctx, now, m.backoff); err != nil {
		return Status{}, false, err
	}
	record, created, err := m.store.prepare(ctx, request, now)
	if err != nil {
		return Status{}, false, err
	}
	return projectStatus(record), created, nil
}

func (m *Manager) Get(ctx context.Context, preparationRef string) (Status, error) {
	if err := m.enter(); err != nil {
		return Status{}, err
	}
	defer m.leave()
	record, err := m.store.get(ctx, preparationRef)
	if err != nil {
		return Status{}, err
	}
	return projectStatus(record), nil
}

func (m *Manager) GetByScope(ctx context.Context, tenantID, siteID, requestID string) (Status, error) {
	if err := m.enter(); err != nil {
		return Status{}, err
	}
	defer m.leave()
	record, err := m.store.getByScope(ctx, tenantID, siteID, requestID)
	if err != nil {
		return Status{}, err
	}
	return projectStatus(record), nil
}

// ProcessNext claims at most one preparation. The prepared-to-unknown CAS is
// committed before Acquire is called. Every later acquisition attempt uses
// only Reconcile. Once content is bound, publication recovery probes the stable
// media key before consulting the acquirer, so a lost publication reply cannot
// regress an already-published preparation into acquisition failure.
func (m *Manager) ProcessNext(ctx context.Context) (Status, bool, error) {
	if err := m.enter(); err != nil {
		return Status{}, false, err
	}
	defer m.leave()
	if _, err := m.store.recover(ctx, m.now().UTC(), m.backoff); err != nil {
		return Status{}, false, err
	}
	claim, found, err := m.store.claim(ctx, m.owner, m.now().UTC(), m.leaseTTL)
	if err != nil || !found {
		return Status{}, false, err
	}
	if claim.Kind == claimPublication {
		return m.reconcilePublication(ctx, claim)
	}
	result, callErr := m.acquire(ctx, claim)
	if result.Content != nil {
		defer result.Content.Close()
	}
	return m.handleAcquisition(ctx, claim, result, callErr)
}

func (m *Manager) handleAcquisition(ctx context.Context, claim workClaim, result AcquisitionResult, callErr error) (Status, bool, error) {
	now := m.now().UTC()
	if callErr != nil {
		reason := ReasonAcquisitionUnknown
		if claim.Kind == claimReconcile {
			reason = ReasonReconciliationUnknown
		}
		record, finishErr := m.store.completeUnknown(ctx, claim, reason, now,
			m.backoff(claim.Record.ReconciliationAttempts+1), "")
		if finishErr != nil {
			return Status{}, true, finishErr
		}
		return projectStatus(record), true, ErrOutcomeUnknown
	}
	actual, actualRaw, validationErr := validateAcquisitionResult(result, claim.Record.Request, now)
	if validationErr != nil {
		record, finishErr := m.store.completeFailed(ctx, claim, ReasonContentInvalid, now, "")
		if finishErr != nil {
			return Status{}, true, finishErr
		}
		return projectStatus(record), true, ErrAcquirerContract
	}
	switch result.Outcome {
	case AcquisitionPending:
		reason := ReasonAcquisitionPending
		if claim.Kind == claimReconcile {
			reason = ReasonReconciliationPending
		}
		record, err := m.store.completeUnknown(ctx, claim, reason, now,
			m.backoff(claim.Record.ReconciliationAttempts+1), "")
		if err != nil {
			return Status{}, true, err
		}
		return projectStatus(record), true, nil
	case AcquisitionFailed:
		record, err := m.store.completeFailed(ctx, claim, ReasonAcquisitionFailed, now, "")
		if err != nil {
			return Status{}, true, err
		}
		return projectStatus(record), true, nil
	case AcquisitionReady:
		return m.publish(ctx, claim, result, actual, actualRaw, now)
	default:
		return Status{}, true, ErrAcquirerContract
	}
}

func (m *Manager) acquire(parent context.Context, claim workClaim) (AcquisitionResult, error) {
	timeout := m.acquireTimeout
	if claim.Kind != claimAcquire {
		timeout = m.reconcileTimeout
	}
	remaining := claim.LeaseExpiresAt.Sub(m.now().UTC())
	if remaining <= 0 {
		return AcquisitionResult{}, context.DeadlineExceeded
	}
	if remaining < timeout {
		timeout = remaining
	}
	ctx, cancel := boundedContext(parent, timeout)
	defer cancel()
	request := claim.Record.Request
	if claim.Kind == claimAcquire {
		return m.acquirer.Acquire(ctx, AcquisitionRequest{
			PreparationRef: claim.Record.PreparationRef, OperationKey: claim.Record.OperationKey,
			TenantID: request.TenantID, SiteID: request.SiteID, SourceRef: request.SourceRef,
			CapabilityRef: request.CapabilityRef, Kind: request.Media.Kind, TimeScope: request.TimeScope,
			AudienceSHA256: request.AudienceSHA256, EvidenceExpiresAt: request.EvidenceExpiresAt,
		})
	}
	return m.acquirer.Reconcile(ctx, ReconciliationRequest{
		PreparationRef: claim.Record.PreparationRef, OperationKey: claim.Record.OperationKey,
		TenantID: request.TenantID, SiteID: request.SiteID, AudienceSHA256: request.AudienceSHA256,
	})
}

func (m *Manager) publish(ctx context.Context, claim workClaim, result AcquisitionResult, actual persistedActualMedia, actualRaw string, at time.Time) (Status, bool, error) {
	digest := result.SHA256
	renewed, err := m.store.bindContent(ctx, claim, digest, actual, actualRaw, at, m.leaseTTL)
	if err != nil {
		return Status{}, true, err
	}
	claim = renewed
	publication := claim.Record.Request.publication(digest, claim.Record.ActualMedia)
	descriptor, publishErr := m.callPublisher(ctx, claim, publication, result.Content)
	return m.finishPublication(ctx, claim, publication, descriptor, publishErr)
}

func (m *Manager) reconcilePublication(ctx context.Context, claim workClaim) (Status, bool, error) {
	digest := claim.Record.ContentSHA256
	publication := claim.Record.Request.publication(digest, claim.Record.ActualMedia)
	descriptor, probeErr := m.callPublisher(ctx, claim, publication, publicationProbeReader{})
	if probeErr == nil {
		return m.finishPublication(ctx, claim, publication, descriptor, nil)
	}
	if !errors.Is(probeErr, errPublicationContentRequired) {
		return m.finishPublication(ctx, claim, publication, media.Descriptor{}, probeErr)
	}

	marked, err := m.store.markPublicationReconciliation(ctx, claim, m.now().UTC(), m.leaseTTL)
	if err != nil {
		return Status{}, true, err
	}
	claim = marked
	result, callErr := m.acquire(ctx, claim)
	if result.Content != nil {
		defer result.Content.Close()
	}
	if callErr != nil {
		return m.finishPublicationUnknown(ctx, claim, ErrOutcomeUnknown)
	}
	actual, actualRaw, validationErr := validateAcquisitionResult(result, claim.Record.Request, m.now().UTC())
	if validationErr != nil || result.Outcome != AcquisitionReady || result.SHA256 != digest ||
		actualRaw != claim.Record.ActualMediaRaw || !sameActualMedia(actual, claim.Record.ActualMedia) {
		return m.finishPublicationUnknown(ctx, claim, ErrAcquirerContract)
	}
	claim, err = m.store.markPublicationStarted(ctx, claim, digest, m.now().UTC(), m.leaseTTL)
	if err != nil {
		return Status{}, true, err
	}
	descriptor, publishErr := m.callPublisher(ctx, claim, publication, result.Content)
	return m.finishPublication(ctx, claim, publication, descriptor, publishErr)
}

func (m *Manager) callPublisher(ctx context.Context, claim workClaim, publication media.PutRequest, content interface{ Read([]byte) (int, error) }) (media.Descriptor, error) {
	publishTimeout := m.publishTimeout
	if remaining := claim.LeaseExpiresAt.Sub(m.now().UTC()); remaining <= 0 {
		return media.Descriptor{}, ErrLeaseLost
	} else if remaining < publishTimeout {
		publishTimeout = remaining
	}
	publishContext, cancel := boundedContext(ctx, publishTimeout)
	descriptor, _, publishErr := m.publisher.PutIdempotent(publishContext, media.IdempotentPutRequest{
		IdempotencyKey: claim.Record.MediaPutKey,
		Media:          publication,
	}, content)
	cancel()
	return descriptor, publishErr
}

func (m *Manager) finishPublication(ctx context.Context, claim workClaim, publication media.PutRequest, descriptor media.Descriptor, publishErr error) (Status, bool, error) {
	now := m.now().UTC()
	if publishErr != nil {
		if definitePublicationError(publishErr) {
			reason := ReasonPublicationRejected
			terminalErr := ErrPublicationRejected
			if errors.Is(publishErr, media.ErrHashMismatch) || errors.Is(publishErr, media.ErrMIMEMismatch) || errors.Is(publishErr, media.ErrTooLarge) {
				reason = ReasonContentInvalid
				terminalErr = ErrAcquirerContract
			}
			record, finishErr := m.store.completeFailed(ctx, claim, reason, now, claim.Record.ContentSHA256)
			if finishErr != nil {
				return Status{}, true, finishErr
			}
			return projectStatus(record), true, terminalErr
		}
		return m.finishPublicationUnknown(ctx, claim, ErrPublicationUnknown)
	}
	if !descriptorMatchesPublication(descriptor, publication) {
		return m.finishPublicationUnknown(ctx, claim, ErrPublicationUnknown)
	}
	record, err := m.store.completeReady(ctx, claim, descriptor.MediaRef, claim.Record.ContentSHA256, now)
	if err != nil {
		return Status{}, true, err
	}
	return projectStatus(record), true, nil
}

func (m *Manager) finishPublicationUnknown(ctx context.Context, claim workClaim, resultErr error) (Status, bool, error) {
	record, err := m.store.completePublicationUnknown(ctx, claim, m.now().UTC(), m.backoff(claim.Record.PublicationAttempts))
	if err != nil {
		return Status{}, true, err
	}
	return projectStatus(record), true, resultErr
}

func (m *Manager) Recover(ctx context.Context) (Recovery, error) {
	if err := m.enter(); err != nil {
		return Recovery{}, err
	}
	defer m.leave()
	return m.recover(ctx)
}

func (m *Manager) recover(ctx context.Context) (Recovery, error) {
	return m.store.recover(ctx, m.now().UTC(), m.backoff)
}

func (m *Manager) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := m.baseBackoff
	for index := 1; index < attempt && delay < m.maximumBackoff; index++ {
		if delay > m.maximumBackoff/2 {
			return m.maximumBackoff
		}
		delay *= 2
	}
	if delay > m.maximumBackoff {
		return m.maximumBackoff
	}
	return delay
}

func (m *Manager) enter() error {
	if m == nil {
		return ErrClosed
	}
	m.closeMu.RLock()
	if m.closed {
		m.closeMu.RUnlock()
		return ErrClosed
	}
	return nil
}

func (m *Manager) leave() { m.closeMu.RUnlock() }

func projectStatus(record storedRecord) Status {
	return Status{
		PreparationRef: record.PreparationRef, State: record.State, Reason: record.Reason,
		MediaRef: record.MediaRef, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		AvailableAt: record.AvailableAt,
	}
}

func boundedContext(parent context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, maximum)
}
