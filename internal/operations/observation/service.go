package observation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectionowner"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
)

var ownerPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var requestPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var sourceRefPattern = regexp.MustCompile(`^source_[0-9a-f]{24}$`)

const maxImageBytes = int64(8 << 20)

type resources struct {
	operations     *operationStore
	media          *media.Store
	preparations   *mediaprep.Manager
	temporaryStore *temporary.SQLiteStore
	runner         *temporary.Manager
	acquirer       *sourceAcquirer
	journal        *taskJournal
	lease          *connectionowner.Lease
}

type Service struct {
	config    Config
	mu        sync.RWMutex
	submitMu  sync.Mutex
	resource  *resources
	cancel    context.CancelFunc
	done      chan struct{}
	wake      chan struct{}
	stopping  bool
	workerErr error
}

func New(config Config) (*Service, error) {
	if strings.TrimSpace(config.StateRoot) == "" || config.Vault == nil {
		return nil, ErrInvalidRequest
	}
	if config.WorkerInterval == 0 {
		config.WorkerInterval = 100 * time.Millisecond
	}
	if config.RunTimeout == 0 {
		config.RunTimeout = 3 * time.Minute
	}
	if config.EvidenceTTL == 0 {
		config.EvidenceTTL = time.Hour
	}
	if config.MaxOperations == 0 {
		config.MaxOperations = 10000
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.WorkerInterval < time.Millisecond || config.WorkerInterval > time.Second || config.RunTimeout < 2*time.Second || config.RunTimeout > 5*time.Minute || config.EvidenceTTL < time.Minute || config.EvidenceTTL > 24*time.Hour || config.EvidenceTTL < config.RunTimeout || config.EvidenceTTL%time.Second != 0 || config.MaxOperations < 1 || config.MaxOperations > 100000 {
		return nil, ErrInvalidRequest
	}
	return &Service{config: config}, nil
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resource != nil || s.stopping {
		return ErrUnavailable
	}
	root := filepath.Join(s.config.StateRoot, "operations", "observation")
	r := &resources{}
	var err error
	fail := func(err error) error { return errors.Join(err, r.close()) }
	if r.lease, err = connectionowner.AcquireLease(root); err != nil {
		return err
	}
	if r.operations, err = openStore(filepath.Join(root, "operations.db"), s.config.MaxOperations); err != nil {
		return fail(err)
	}
	if r.temporaryStore, err = temporary.OpenSQLite(filepath.Join(root, "temporary-runs.db")); err != nil {
		return fail(err)
	}
	if r.media, err = media.New(media.Config{Root: filepath.Join(root, "media"), MaxObjectBytes: maxImageBytes, MaxTotalBytes: 256 << 20, MaxDescriptors: s.config.MaxOperations, DefaultTTL: s.config.EvidenceTTL, MaximumTTL: 24 * time.Hour, Now: s.config.Now}); err != nil {
		return fail(err)
	}
	r.journal = &taskJournal{store: r.operations}
	r.acquirer = &sourceAcquirer{vault: s.config.Vault, store: r.operations, journal: r.journal, now: s.config.Now, cache: make(map[string]mediaprep.Acquirer)}
	if r.preparations, err = mediaprep.Open(mediaprep.Config{Path: filepath.Join(root, "media-preparations.db"), Owner: "observation-media", Acquirer: r.acquirer, Publisher: r.media, LeaseTTL: time.Minute, AcquireTimeout: 20 * time.Second, ReconcileTimeout: 10 * time.Second, PublishTimeout: 10 * time.Second, Now: s.config.Now}); err != nil {
		return fail(err)
	}
	analyzer := deadlineAnalyzer{vault: s.config.Vault, journal: r.journal, store: r.operations}
	if r.runner, err = temporary.NewManager(r.temporaryStore, r.preparations, livevision.NewTemporaryMediaReader(r.media), analyzer, s.config.Now); err != nil {
		return fail(err)
	}
	if _, err := r.runner.Recover(ctx); err != nil {
		return fail(err)
	}
	child, cancel := context.WithCancel(ctx)
	s.resource = r
	s.cancel = cancel
	s.done = make(chan struct{})
	s.wake = make(chan struct{}, 1)
	s.workerErr = nil
	go s.worker(child, r, s.done, s.wake)
	return nil
}

func (s *Service) Stop() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.resource == nil {
		s.mu.Unlock()
		return nil
	}
	s.stopping = true
	s.cancel()
	done := s.done
	s.mu.Unlock()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.resource.close()
	s.resource = nil
	s.cancel = nil
	s.done = nil
	s.stopping = false
	return err
}
func (r *resources) close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.preparations != nil {
		err = errors.Join(err, r.preparations.Close())
	}
	if r.temporaryStore != nil {
		err = errors.Join(err, r.temporaryStore.Close())
	}
	if r.operations != nil {
		err = errors.Join(err, r.operations.db.Close())
	}
	if r.lease != nil {
		err = errors.Join(err, r.lease.Close())
	}
	return err
}

func (s *Service) Observe(ctx context.Context, owner string, request Request) (Result, error) {
	if s == nil || !ownerPattern.MatchString(owner) {
		return Result{}, ErrInvalidRequest
	}
	request, err := normalizeRequest(request)
	if err != nil {
		return Result{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.resource != nil && s.resource.journal.diagnosticFailure() != nil {
		return Result{}, errors.Join(ErrUnavailable, livevision.ErrDiagnosticPersistence)
	}
	if s.resource == nil || s.stopping || s.workerErr != nil {
		return Result{}, ErrUnavailable
	}
	select {
	case <-s.done:
		return Result{}, ErrUnavailable
	default:
	}
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	_, inputHash, err := canonical(request)
	if err != nil {
		return Result{}, ErrInvalidRequest
	}
	if existing, err := s.resource.operations.byRequest(ctx, owner, request.RequestID); err == nil {
		if existing.InputSHA256 != inputHash {
			return Result{}, ErrConflict
		}
		return s.result(ctx, s.resource, existing)
	} else if !errors.Is(err, ErrNotFound) {
		return Result{}, err
	}
	connection, err := s.config.Vault.InspectionConnection(ctx)
	if err != nil {
		return Result{}, ErrConnectionRequired
	}
	snapshot := connection.Snapshot()
	selected, err := selectSource(snapshot, request.SourceName, request.SourceRef)
	if err != nil {
		return Result{}, err
	}
	var spec temporary.TemporaryObservationSpec
	if request.Mode != CaptureOnly {
		spec, err = temporary.NewSpec(temporary.Intent{Subject: request.Subject, Region: "所选机位画面", Observable: request.Question, Locale: "zh-CN", TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: int(s.config.EvidenceTTL / time.Second)})
		if err != nil {
			return Result{}, ErrInvalidRequest
		}
	}
	identity := digestText("cosmoedge-connect.observation.v1\x00" + owner + "\x00" + request.RequestID)
	ref := "observation_" + identity[:32]
	key := "obsreq_" + identity
	binding, err := livevision.BindConnectionSource(connection, selected, "obs_source_"+identity[:32])
	if err != nil {
		return Result{}, ErrConnectionRequired
	}
	run, err := temporary.RunIDForScope(livevision.TenantID, livevision.SiteID, key)
	if err != nil {
		return Result{}, ErrInvalidRequest
	}
	prep, err := mediaprep.PreparationRefForScope(livevision.TenantID, livevision.SiteID, key)
	if err != nil {
		return Result{}, ErrInvalidRequest
	}
	at := s.config.Now().UTC()
	value := operation{Ref: ref, OwnerHash: owner, Request: request, InputSHA256: inputHash, RequestKey: key, RunID: run, PreparationRef: prep, Source: binding, ResolvedSourceName: selected.Name, SourceKind: selected.SourceKind, Spec: spec, CreatedAt: at, DeadlineAt: at.Add(s.config.RunTimeout), ExpiresAt: at.Add(s.config.EvidenceTTL), Stage: "accepted"}
	if err := s.resource.operations.put(ctx, value); err != nil {
		return Result{}, err
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return s.result(ctx, s.resource, value)
}

func (s *Service) Get(ctx context.Context, owner, ref string) (Result, error) {
	if s == nil || !ownerPattern.MatchString(owner) {
		return Result{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.resource == nil || s.stopping {
		return Result{}, ErrUnavailable
	}
	value, err := s.resource.operations.get(ctx, owner, ref)
	if err != nil {
		return Result{}, err
	}
	return s.result(ctx, s.resource, value)
}
func (s *Service) GetByRequest(ctx context.Context, owner, requestID string) (Result, error) {
	if s == nil || !ownerPattern.MatchString(owner) || !requestPattern.MatchString(requestID) {
		return Result{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.resource == nil || s.stopping {
		return Result{}, ErrUnavailable
	}
	value, err := s.resource.operations.byRequest(ctx, owner, requestID)
	if err != nil {
		return Result{}, err
	}
	return s.result(ctx, s.resource, value)
}

func (s *Service) ReadMedia(ctx context.Context, owner, ref string) (Media, error) {
	if s == nil || !ownerPattern.MatchString(owner) {
		return Media{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.resource == nil || s.stopping {
		return Media{}, ErrUnavailable
	}
	descriptor, describeErr := s.resource.media.Describe(ref)
	value, err := s.resource.operations.byRun(ctx, descriptor.Binding.RunID)
	if err != nil || value.OwnerHash != owner || !matchesMedia(value, descriptor) {
		return Media{}, ErrNotFound
	}
	if describeErr != nil {
		return Media{}, ErrMediaUnavailable
	}
	actual, reader, err := s.resource.media.Open(ctx, ref)
	if err != nil {
		return Media{}, ErrMediaUnavailable
	}
	defer reader.Close()
	if !matchesMedia(value, actual) || actual.Integrity.SHA256 != descriptor.Integrity.SHA256 {
		return Media{}, ErrMediaUnavailable
	}
	content, err := io.ReadAll(io.LimitReader(reader, maxImageBytes+1))
	if err != nil || len(content) == 0 || int64(len(content)) != descriptor.Integrity.SizeBytes || int64(len(content)) > maxImageBytes {
		clear(content)
		return Media{}, ErrMediaUnavailable
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != descriptor.Integrity.SHA256 {
		clear(content)
		return Media{}, ErrMediaUnavailable
	}
	return Media{Content: content, MIMEType: descriptor.Encoding.MIMEType, SHA256: descriptor.Integrity.SHA256}, nil
}

func normalizeRequest(value Request) (Request, error) {
	value.RequestID = strings.TrimSpace(value.RequestID)
	value.SourceName = strings.TrimSpace(value.SourceName)
	value.SourceRef = strings.TrimSpace(value.SourceRef)
	value.Question = strings.Join(strings.Fields(value.Question), " ")
	value.Subject = strings.Join(strings.Fields(value.Subject), " ")
	if value.SourceRef != "" && !sourceRefPattern.MatchString(value.SourceRef) {
		return Request{}, ErrInvalidRequest
	}
	if !requestPattern.MatchString(value.RequestID) || !utf8.ValidString(value.SourceName) || utf8.RuneCountInString(value.SourceName) > 256 {
		return Request{}, ErrInvalidRequest
	}
	for _, r := range value.SourceName {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return Request{}, ErrInvalidRequest
		}
	}
	if value.Mode == CaptureOnly {
		// The optional question is context for the host, never a box-side prompt.
		if value.Subject != "" || !utf8.ValidString(value.Question) || utf8.RuneCountInString(value.Question) > 2048 {
			return Request{}, ErrInvalidRequest
		}
		return value, nil
	}
	if value.Mode != "" || value.Question == "" {
		return Request{}, ErrInvalidRequest
	}
	if value.Subject == "" {
		value.Subject = "画面中的可见事物"
	}
	return value, nil
}
func selectSource(snapshot device.Snapshot, name, ref string) (device.Camera, error) {
	choices := []SourceChoice{}
	matches := []device.Camera{}
	for _, camera := range snapshot.Cameras {
		if camera.ID == "" {
			continue
		}
		publicRef := livevision.PublicSourceRef(camera)
		choices = append(choices, SourceChoice{Name: camera.Name, SourceRef: publicRef})
		if ref != "" {
			if publicRef == ref && (name == "" || camera.Name == name) {
				matches = append(matches, camera)
			}
		} else if camera.Name == name {
			matches = append(matches, camera)
		}
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].Name != choices[j].Name {
			return choices[i].Name < choices[j].Name
		}
		return choices[i].SourceRef < choices[j].SourceRef
	})
	if len(matches) == 1 {
		return matches[0], nil
	}
	code := "source_not_found"
	if name == "" && ref == "" {
		code = "source_required"
	} else if len(matches) > 1 {
		code = "source_ambiguous"
	}
	return device.Camera{}, &SourceSelectionError{Code: code, Choices: choices}
}
func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

var _ API = (*Service)(nil)
