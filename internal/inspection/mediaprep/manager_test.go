package mediaprep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	_ "modernc.org/sqlite"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

type scriptedAcquirer struct {
	mu                sync.Mutex
	acquireCalls      int
	reconcileCalls    int
	acquireRequests   []AcquisitionRequest
	reconcileRequests []ReconciliationRequest
	acquire           func(context.Context, AcquisitionRequest) (AcquisitionResult, error)
	reconcile         func(context.Context, ReconciliationRequest) (AcquisitionResult, error)
}

func (a *scriptedAcquirer) Acquire(ctx context.Context, request AcquisitionRequest) (AcquisitionResult, error) {
	a.mu.Lock()
	a.acquireCalls++
	a.acquireRequests = append(a.acquireRequests, request)
	fn := a.acquire
	a.mu.Unlock()
	if fn == nil {
		return AcquisitionResult{Outcome: AcquisitionPending}, nil
	}
	return fn(ctx, request)
}

func (a *scriptedAcquirer) Reconcile(ctx context.Context, request ReconciliationRequest) (AcquisitionResult, error) {
	a.mu.Lock()
	a.reconcileCalls++
	a.reconcileRequests = append(a.reconcileRequests, request)
	fn := a.reconcile
	a.mu.Unlock()
	if fn == nil {
		return AcquisitionResult{Outcome: AcquisitionPending}, nil
	}
	return fn(ctx, request)
}

func (a *scriptedAcquirer) counts() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.acquireCalls, a.reconcileCalls
}

type managerFixture struct {
	manager   *Manager
	media     *media.Store
	database  string
	mediaRoot string
	clock     *fakeClock
}

func newManagerFixture(t *testing.T, clock *fakeClock, acquirer Acquirer, publisher Publisher) managerFixture {
	t.Helper()
	root := t.TempDir()
	mediaRoot := filepath.Join(root, "media")
	mediaStore, err := media.New(media.Config{Root: mediaRoot, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if publisher == nil {
		publisher = mediaStore
	}
	database := filepath.Join(root, "private", "temporary-media.db")
	manager, err := Open(Config{
		Path: database, Owner: "worker-test", Acquirer: acquirer, Publisher: publisher, Now: clock.Now,
		LeaseTTL: 4 * time.Second, AcquireTimeout: time.Second, ReconcileTimeout: time.Second,
		PublishTimeout: time.Second, BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return managerFixture{manager: manager, media: mediaStore, database: database, mediaRoot: mediaRoot, clock: clock}
}

func testRequest(t *testing.T, now time.Time, requestID string) FrozenRequest {
	t.Helper()
	point := now.Add(-time.Minute).UTC()
	return FrozenRequest{
		Schema: RequestSchema, TenantID: "tenant-test", SiteID: "site-test", RequestID: requestID,
		SourceRef: "source-zone-a", CapabilityRef: "capability-snapshot-read",
		TimeScope:          TimeScope{WindowStart: point, WindowEnd: point, SampleOrdinal: 0},
		AudienceBindingRef: "delivery-binding-test", AudienceSHA256: shaHex([]byte("protected-delivery-binding-test")),
		EvidenceExpiresAt: now.Add(time.Hour).UTC(),
		Media: MediaSpec{
			Kind: media.KindImage, RunID: "run-test", StepID: "step-snapshot", Attempt: 1,
			PrivacyClass: "sensitive", RetentionPolicyRef: "retention-hour",
		},
	}
}

func pngBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	value := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			value.Set(x, y, color.RGBA{R: uint8(x * 7), G: uint8(y * 11), B: 93, A: 255})
		}
	}
	var output bytes.Buffer
	if err := png.Encode(&output, value); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func contentDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func readyResult(content []byte, capturedAt time.Time) AcquisitionResult {
	capturedAt = capturedAt.UTC()
	return AcquisitionResult{
		Outcome: AcquisitionReady, Content: io.NopCloser(bytes.NewReader(content)), SHA256: contentDigest(content),
		Encoding: media.Encoding{MIMEType: "image/png", Container: "png", Codec: "png", WidthPixels: 1, HeightPixels: 1},
		Temporal: media.Temporal{WindowStart: &capturedAt, WindowEnd: &capturedAt},
	}
}

func TestPrepareExactReplayConflictAndFrozenScope(t *testing.T) {
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	fixture := newManagerFixture(t, clock, &scriptedAcquirer{}, nil)
	request := testRequest(t, now, "request-exact")

	first, created, err := fixture.manager.Prepare(context.Background(), request)
	if err != nil || !created || first.State != StatePrepared {
		t.Fatalf("first Prepare state=%q created=%v err=%v", first.State, created, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(fixture.database); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private database info=%v err=%v", info, err)
		}
		if info, err := os.Stat(filepath.Dir(fixture.database)); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("private database root info=%v err=%v", info, err)
		}
	}
	replay, created, err := fixture.manager.Prepare(context.Background(), request)
	if err != nil || created || replay.PreparationRef != first.PreparationRef {
		t.Fatalf("replay ref=%q created=%v err=%v", replay.PreparationRef, created, err)
	}
	changed := request
	changed.CapabilityRef = "capability-video-read"
	if _, _, err := fixture.manager.Prepare(context.Background(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed request error=%v", err)
	}

	clock.Advance(2 * time.Hour)
	if expiredReplay, created, err := fixture.manager.Prepare(context.Background(), request); err != nil || created ||
		expiredReplay.PreparationRef != first.PreparationRef || expiredReplay.State != StateFailed || expiredReplay.Reason != ReasonEvidenceExpired {
		t.Fatalf("expired exact replay ref=%q created=%v err=%v", expiredReplay.PreparationRef, created, err)
	}
	newExpired := testRequest(t, now, "request-expired-new")
	if _, _, err := fixture.manager.Prepare(context.Background(), newExpired); !errors.Is(err, ErrInvalid) {
		t.Fatalf("new expired request error=%v", err)
	}

	var count int
	if err := fixture.manager.store.db.QueryRow(`SELECT COUNT(*) FROM temporary_media_preparations`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("persisted preparations=%d err=%v", count, err)
	}
	var source, capability, audienceBinding, windowStart, windowEnd, audienceDigest, expires string
	if err := fixture.manager.store.db.QueryRow(`SELECT source_ref,capability_ref,audience_binding_ref,window_start,window_end,audience_sha256,evidence_expires_at FROM temporary_media_preparations`).
		Scan(&source, &capability, &audienceBinding, &windowStart, &windowEnd, &audienceDigest, &expires); err != nil {
		t.Fatal(err)
	}
	if source != "source-zone-a" || capability != "capability-snapshot-read" || audienceBinding != request.AudienceBindingRef || windowStart != windowEnd ||
		audienceDigest != request.AudienceSHA256 || expires != formatTime(request.EvidenceExpiresAt) {
		t.Fatalf("frozen scope mismatch source=%q capability=%q window=%q..%q audience=%q expires=%q", source, capability, windowStart, windowEnd, audienceDigest, expires)
	}
}

func TestConcurrentPrepareCreatesOneFrozenIdentity(t *testing.T) {
	now := time.Date(2026, 7, 19, 8, 30, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	fixture := newManagerFixture(t, clock, &scriptedAcquirer{}, nil)
	request := testRequest(t, now, "request-concurrent-prepare")
	const workers = 24
	var wait sync.WaitGroup
	var created atomic.Int32
	refs := make(chan string, workers)
	errs := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, wasCreated, err := fixture.manager.Prepare(context.Background(), request)
			if err != nil {
				errs <- err
				return
			}
			if wasCreated {
				created.Add(1)
			}
			refs <- status.PreparationRef
		}()
	}
	wait.Wait()
	close(refs)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if created.Load() != 1 {
		t.Fatalf("created identities=%d", created.Load())
	}
	var exact string
	for ref := range refs {
		if exact == "" {
			exact = ref
		}
		if ref != exact {
			t.Fatalf("concurrent identities=%q and %q", exact, ref)
		}
	}
}

func TestReadyAcquisitionPublishesVerifiedMediaOnce(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	content := pngBytes(t, 18, 12)
	var observedManager *Manager
	acquirer := &scriptedAcquirer{acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
		record, err := observedManager.store.getByScope(context.Background(), "tenant-test", "site-test", "request-ready")
		if err != nil || record.State != StateAcquiringUnknown || record.Reason != ReasonAcquisitionStarted || record.LeaseOwner == "" {
			return AcquisitionResult{}, fmt.Errorf("acquisition was called before durable unknown transition")
		}
		result := readyResult(content, now)
		result.Encoding.WidthPixels, result.Encoding.HeightPixels = 18, 12
		return result, nil
	}}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	observedManager = fixture.manager
	prepared, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, "request-ready"))
	if err != nil {
		t.Fatal(err)
	}
	status, found, err := fixture.manager.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateReady || !mediaRefPattern.MatchString(status.MediaRef) {
		t.Fatalf("ProcessNext status=%#v found=%v err=%v", status, found, err)
	}
	if status.PreparationRef != prepared.PreparationRef {
		t.Fatalf("ready preparation=%q want=%q", status.PreparationRef, prepared.PreparationRef)
	}
	descriptor, reader, err := fixture.media.Open(context.Background(), status.MediaRef)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, content) || descriptor.Integrity.SHA256 != contentDigest(content) {
		t.Fatalf("published media bytes=%d descriptor=%+v read=%v close=%v", len(got), descriptor, readErr, closeErr)
	}
	requestedPoint := testRequest(t, now, "request-ready").TimeScope.WindowEnd
	if descriptor.Temporal.WindowStart == nil || descriptor.Temporal.WindowEnd == nil ||
		!descriptor.Temporal.WindowStart.Equal(now) || !descriptor.Temporal.WindowEnd.Equal(now) ||
		descriptor.Temporal.WindowEnd.Equal(requestedPoint) || descriptor.Encoding != (media.Encoding{
		MIMEType: "image/png", Container: "png", Codec: "png", WidthPixels: 18, HeightPixels: 12,
	}) {
		t.Fatalf("published requested time or guessed encoding instead of adapter facts: temporal=%+v encoding=%+v", descriptor.Temporal, descriptor.Encoding)
	}
	acquirer.mu.Lock()
	if len(acquirer.acquireRequests) != 1 || acquirer.acquireRequests[0].Kind != media.KindImage {
		t.Fatalf("adapter request kind=%q", acquirer.acquireRequests[0].Kind)
	}
	acquirer.mu.Unlock()
	if acquire, reconcile := acquirer.counts(); acquire != 1 || reconcile != 0 {
		t.Fatalf("external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
	if _, found, err := fixture.manager.ProcessNext(context.Background()); err != nil || found {
		t.Fatalf("terminal replay found=%v err=%v", found, err)
	}
}

func TestReadyClipPublishesOnlyExactObservedWindow(t *testing.T) {
	now := time.Date(2026, 7, 19, 9, 30, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	content := []byte{0, 0, 0, 12, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'}
	request := testRequest(t, now, "request-ready-clip")
	request.TimeScope.WindowStart = now.Add(-2 * time.Minute)
	request.TimeScope.WindowEnd = now.Add(-time.Minute)
	request.TimeScope.DurationMillis = int64(time.Minute / time.Millisecond)
	request.Media.Kind = media.KindVideoClip
	acquirer := &scriptedAcquirer{acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
		start, end := request.TimeScope.WindowStart, request.TimeScope.WindowEnd
		return AcquisitionResult{
			Outcome: AcquisitionReady, Content: io.NopCloser(bytes.NewReader(content)), SHA256: contentDigest(content),
			Encoding: media.Encoding{MIMEType: "video/mp4", Container: "mp4", Codec: "h264", WidthPixels: 1920, HeightPixels: 1080, FrameRate: 25},
			Temporal: media.Temporal{WindowStart: &start, WindowEnd: &end, DurationMillis: request.TimeScope.DurationMillis},
		}, nil
	}}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	if _, _, err := fixture.manager.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	status, found, err := fixture.manager.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateReady {
		t.Fatalf("clip status=%#v found=%v err=%v", status, found, err)
	}
	descriptor, reader, err := fixture.media.Open(context.Background(), status.MediaRef)
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	if descriptor.Kind != media.KindVideoClip || descriptor.Encoding.Codec != "h264" ||
		descriptor.Temporal.WindowStart == nil || descriptor.Temporal.WindowEnd == nil ||
		!descriptor.Temporal.WindowStart.Equal(request.TimeScope.WindowStart) || !descriptor.Temporal.WindowEnd.Equal(request.TimeScope.WindowEnd) ||
		descriptor.Temporal.DurationMillis != request.TimeScope.DurationMillis {
		t.Fatalf("clip descriptor=%+v", descriptor)
	}
}

func TestAcquireErrorUsesReconcileOnlyAfterPersistedBackoff(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	content := pngBytes(t, 10, 8)
	acquirer := &scriptedAcquirer{
		acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
			return AcquisitionResult{}, errors.New("native adapter outcome unavailable")
		},
		reconcile: func(context.Context, ReconciliationRequest) (AcquisitionResult, error) {
			result := readyResult(content, now)
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 10, 8
			return result, nil
		},
	}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	if _, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, "request-reconcile")); err != nil {
		t.Fatal(err)
	}
	status, found, err := fixture.manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrOutcomeUnknown) || status.State != StateAcquiringUnknown || status.Reason != ReasonAcquisitionUnknown {
		t.Fatalf("first status=%#v found=%v err=%v", status, found, err)
	}
	if _, found, err := fixture.manager.ProcessNext(context.Background()); err != nil || found {
		t.Fatalf("backoff hot-looped found=%v err=%v", found, err)
	}
	clock.Advance(2 * time.Second)
	status, found, err = fixture.manager.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateReady {
		t.Fatalf("reconcile status=%#v found=%v err=%v", status, found, err)
	}
	acquire, reconcile := acquirer.counts()
	if acquire != 1 || reconcile != 1 {
		t.Fatalf("external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
	acquirer.mu.Lock()
	if acquirer.acquireRequests[0].OperationKey != acquirer.reconcileRequests[0].OperationKey ||
		acquirer.acquireRequests[0].PreparationRef != acquirer.reconcileRequests[0].PreparationRef {
		t.Fatalf("stable operation binding changed acquire=%#v reconcile=%#v", acquirer.acquireRequests[0], acquirer.reconcileRequests[0])
	}
	acquirer.mu.Unlock()
}

type failAfterPublish struct {
	inner      Publisher
	before     func() error
	mu         sync.Mutex
	calls      int
	created    []bool
	references []string
}

func (p *failAfterPublish) PutIdempotent(ctx context.Context, request media.IdempotentPutRequest, reader io.Reader) (media.Descriptor, bool, error) {
	if p.before != nil {
		if err := p.before(); err != nil {
			return media.Descriptor{}, false, err
		}
	}
	descriptor, created, err := p.inner.PutIdempotent(ctx, request, reader)
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.created = append(p.created, created)
	p.references = append(p.references, descriptor.MediaRef)
	p.mu.Unlock()
	if err != nil {
		return descriptor, created, err
	}
	if call == 1 {
		return media.Descriptor{}, false, errors.New("worker disappeared after publication commit")
	}
	return descriptor, created, nil
}

func TestPublicationCrashWindowReplaysSameMediaIdentity(t *testing.T) {
	now := time.Date(2026, 7, 19, 11, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	root := t.TempDir()
	mediaStore, err := media.New(media.Config{Root: filepath.Join(root, "media"), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &failAfterPublish{inner: mediaStore}
	content := pngBytes(t, 11, 9)
	acquirer := &scriptedAcquirer{
		acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
			result := readyResult(content, now)
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 11, 9
			return result, nil
		},
		reconcile: func(context.Context, ReconciliationRequest) (AcquisitionResult, error) {
			return AcquisitionResult{Outcome: AcquisitionFailed, FailureCode: "adapter-result-expired"}, nil
		},
	}
	manager, err := Open(Config{
		Path: filepath.Join(root, "private", "preparations.db"), Owner: "worker-crash", Acquirer: acquirer,
		Publisher: wrapper, Now: clock.Now, LeaseTTL: 4 * time.Second, AcquireTimeout: time.Second,
		ReconcileTimeout: time.Second, PublishTimeout: time.Second, BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	wrapper.before = func() error {
		record, err := manager.store.getByScope(context.Background(), "tenant-test", "site-test", "request-publish-crash")
		if err != nil {
			return err
		}
		if record.State != StatePublicationUnknown || record.ContentSHA256 != contentDigest(content) || record.LeaseOwner == "" {
			return errors.New("verified content digest was not durably bound before publication")
		}
		return nil
	}
	if _, _, err := manager.Prepare(context.Background(), testRequest(t, now, "request-publish-crash")); err != nil {
		t.Fatal(err)
	}
	status, found, err := manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrPublicationUnknown) || status.State != StatePublicationUnknown {
		t.Fatalf("first publication status=%#v found=%v err=%v", status, found, err)
	}
	clock.Advance(2 * time.Second)
	status, found, err = manager.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateReady {
		t.Fatalf("publication reconciliation status=%#v found=%v err=%v", status, found, err)
	}
	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if wrapper.calls != 2 || len(wrapper.created) != 2 || !wrapper.created[0] || wrapper.created[1] ||
		wrapper.references[0] == "" || wrapper.references[0] != wrapper.references[1] || status.MediaRef != wrapper.references[0] {
		t.Fatalf("publication calls=%d created=%v refs=%v status=%q", wrapper.calls, wrapper.created, wrapper.references, status.MediaRef)
	}
	if acquire, reconcile := acquirer.counts(); acquire != 1 || reconcile != 0 {
		t.Fatalf("external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
	for directory, want := range map[string]int{"objects": 1, "descriptors": 1, "idempotency": 1, "tmp": 0} {
		entries, err := os.ReadDir(filepath.Join(root, "media", directory))
		if err != nil || len(entries) != want {
			t.Fatalf("media %s entries=%d want=%d err=%v", directory, len(entries), want, err)
		}
	}
}

type failBeforePublishOnce struct {
	inner Publisher
	mu    sync.Mutex
	calls int
}

type leaseWindowPublisher struct {
	inner Publisher
	clock *fakeClock
	mu    sync.Mutex
	calls int
}

func (p *leaseWindowPublisher) PutIdempotent(ctx context.Context, request media.IdempotentPutRequest, reader io.Reader) (media.Descriptor, bool, error) {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.mu.Unlock()
	switch call {
	case 1:
		return media.Descriptor{}, false, errors.New("publisher unavailable before commit")
	case 2:
		p.clock.Advance(1900 * time.Millisecond)
	case 3:
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return media.Descriptor{}, false, ctx.Err()
		case <-timer.C:
		}
	}
	return p.inner.PutIdempotent(ctx, request, reader)
}

func (p *failBeforePublishOnce) PutIdempotent(ctx context.Context, request media.IdempotentPutRequest, reader io.Reader) (media.Descriptor, bool, error) {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.mu.Unlock()
	if call == 1 {
		return media.Descriptor{}, false, errors.New("publisher unavailable before commit")
	}
	return p.inner.PutIdempotent(ctx, request, reader)
}

func TestPublicationProbeMissDoesNotRegressReadyAcquisition(t *testing.T) {
	now := time.Date(2026, 7, 19, 11, 30, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	root := t.TempDir()
	mediaStore, err := media.New(media.Config{Root: filepath.Join(root, "media"), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	publisher := &failBeforePublishOnce{inner: mediaStore}
	content := pngBytes(t, 13, 10)
	var reconciliationAttempt atomic.Int32
	acquirer := &scriptedAcquirer{
		acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
			result := readyResult(content, now)
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 13, 10
			return result, nil
		},
		reconcile: func(context.Context, ReconciliationRequest) (AcquisitionResult, error) {
			if reconciliationAttempt.Add(1) == 1 {
				return AcquisitionResult{Outcome: AcquisitionFailed, FailureCode: "adapter-result-regressed"}, nil
			}
			result := readyResult(content, now)
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 13, 10
			return result, nil
		},
	}
	manager, err := Open(Config{
		Path: filepath.Join(root, "private", "preparations.db"), Owner: "worker-probe-miss", Acquirer: acquirer,
		Publisher: publisher, Now: clock.Now, LeaseTTL: 4 * time.Second, AcquireTimeout: time.Second,
		ReconcileTimeout: time.Second, PublishTimeout: time.Second, BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, _, err := manager.Prepare(context.Background(), testRequest(t, now, "request-publish-probe-miss")); err != nil {
		t.Fatal(err)
	}
	status, found, err := manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrPublicationUnknown) || status.State != StatePublicationUnknown {
		t.Fatalf("first publication status=%#v found=%v err=%v", status, found, err)
	}
	clock.Advance(2 * time.Second)
	status, found, err = manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrAcquirerContract) || status.State != StatePublicationUnknown {
		t.Fatalf("regressing reconciliation status=%#v found=%v err=%v", status, found, err)
	}
	if _, found, err := manager.ProcessNext(context.Background()); err != nil || found {
		t.Fatalf("publication recovery hot-looped found=%v err=%v", found, err)
	}
	clock.Advance(4 * time.Second)
	status, found, err = manager.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateReady {
		t.Fatalf("recovered publication status=%#v found=%v err=%v", status, found, err)
	}
	if acquire, reconcile := acquirer.counts(); acquire != 1 || reconcile != 2 {
		t.Fatalf("external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
	publisher.mu.Lock()
	publicationCalls := publisher.calls
	publisher.mu.Unlock()
	if publicationCalls != 4 {
		t.Fatalf("publication calls=%d want=4", publicationCalls)
	}
	for directory, want := range map[string]int{"objects": 1, "descriptors": 1, "idempotency": 1, "tmp": 0} {
		entries, err := os.ReadDir(filepath.Join(root, "media", directory))
		if err != nil || len(entries) != want {
			t.Fatalf("media %s entries=%d want=%d err=%v", directory, len(entries), want, err)
		}
	}
}

func TestPublicationRecoveryRejectsChangedActualMetadata(t *testing.T) {
	now := time.Date(2026, 7, 19, 11, 40, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	root := t.TempDir()
	mediaStore, err := media.New(media.Config{Root: filepath.Join(root, "media"), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	publisher := &failBeforePublishOnce{inner: mediaStore}
	content := pngBytes(t, 15, 9)
	acquirer := &scriptedAcquirer{
		acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
			result := readyResult(content, now)
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 15, 9
			return result, nil
		},
		reconcile: func(context.Context, ReconciliationRequest) (AcquisitionResult, error) {
			result := readyResult(content, now.Add(time.Second))
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 15, 9
			return result, nil
		},
	}
	manager, err := Open(Config{
		Path: filepath.Join(root, "private", "preparations.db"), Owner: "worker-metadata-change", Acquirer: acquirer,
		Publisher: publisher, Now: clock.Now, LeaseTTL: 4 * time.Second, AcquireTimeout: time.Second,
		ReconcileTimeout: time.Second, PublishTimeout: time.Second, BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, _, err := manager.Prepare(context.Background(), testRequest(t, now, "request-metadata-change")); err != nil {
		t.Fatal(err)
	}
	status, found, err := manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrPublicationUnknown) || status.State != StatePublicationUnknown {
		t.Fatalf("initial publication status=%#v found=%v err=%v", status, found, err)
	}
	clock.Advance(2 * time.Second)
	status, found, err = manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrAcquirerContract) || status.State != StatePublicationUnknown || status.MediaRef != "" {
		t.Fatalf("changed metadata status=%#v found=%v err=%v", status, found, err)
	}
	if acquire, reconcile := acquirer.counts(); acquire != 1 || reconcile != 1 {
		t.Fatalf("external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
	objects, readErr := os.ReadDir(filepath.Join(root, "media", "objects"))
	if readErr != nil || len(objects) != 0 {
		t.Fatalf("changed metadata published objects=%d err=%v", len(objects), readErr)
	}
}

func TestPublicationRecoveryRenewsEveryPhaseLease(t *testing.T) {
	now := time.Date(2026, 7, 19, 11, 45, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	root := t.TempDir()
	mediaStore, err := media.New(media.Config{Root: filepath.Join(root, "media"), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	publisher := &leaseWindowPublisher{inner: mediaStore, clock: clock}
	content := pngBytes(t, 14, 11)
	var manager *Manager
	acquirer := &scriptedAcquirer{
		acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
			result := readyResult(content, now)
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 14, 11
			return result, nil
		},
		reconcile: func(context.Context, ReconciliationRequest) (AcquisitionResult, error) {
			record, err := manager.store.getByScope(context.Background(), "tenant-test", "site-test", "request-publish-lease")
			if err != nil {
				return AcquisitionResult{}, err
			}
			if remaining := record.LeaseExpiresAt.Sub(clock.Now()); remaining < 3*time.Second {
				return AcquisitionResult{}, fmt.Errorf("reconciliation lease was not renewed: %s", remaining)
			}
			clock.Advance(1900 * time.Millisecond)
			result := readyResult(content, now)
			result.Encoding.WidthPixels, result.Encoding.HeightPixels = 14, 11
			return result, nil
		},
	}
	manager, err = Open(Config{
		Path: filepath.Join(root, "private", "preparations.db"), Owner: "worker-publication-lease", Acquirer: acquirer,
		Publisher: publisher, Now: clock.Now, LeaseTTL: 4 * time.Second, AcquireTimeout: 2 * time.Second,
		ReconcileTimeout: 2 * time.Second, PublishTimeout: 2 * time.Second, BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, _, err := manager.Prepare(context.Background(), testRequest(t, now, "request-publish-lease")); err != nil {
		t.Fatal(err)
	}
	status, found, err := manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrPublicationUnknown) || status.State != StatePublicationUnknown {
		t.Fatalf("initial publication status=%#v found=%v err=%v", status, found, err)
	}
	clock.Advance(2 * time.Second)
	status, found, err = manager.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateReady {
		t.Fatalf("lease-renewed publication status=%#v found=%v err=%v", status, found, err)
	}
	if acquire, reconcile := acquirer.counts(); acquire != 1 || reconcile != 1 {
		t.Fatalf("external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
	publisher.mu.Lock()
	publicationCalls := publisher.calls
	publisher.mu.Unlock()
	if publicationCalls != 3 {
		t.Fatalf("publication calls=%d want=3", publicationCalls)
	}
}

func TestRestartRecoversExpiredLeaseWithoutSecondAcquire(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	content := pngBytes(t, 9, 7)
	acquirer := &scriptedAcquirer{reconcile: func(context.Context, ReconciliationRequest) (AcquisitionResult, error) {
		result := readyResult(content, clock.Now())
		result.Encoding.WidthPixels, result.Encoding.HeightPixels = 9, 7
		return result, nil
	}}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	prepared, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, "request-restart"))
	if err != nil {
		t.Fatal(err)
	}
	claim, found, err := fixture.manager.store.claim(context.Background(), "crashed-worker", now, 4*time.Second)
	if err != nil || !found || claim.Kind != claimAcquire || claim.Record.State != StateAcquiringUnknown {
		t.Fatalf("durable pre-acquire claim=%#v found=%v err=%v", claim, found, err)
	}
	if err := fixture.manager.Close(); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Second)
	reopened, err := Open(Config{
		Path: fixture.database, Owner: "worker-restarted", Acquirer: acquirer, Publisher: fixture.media, Now: clock.Now,
		LeaseTTL: 4 * time.Second, AcquireTimeout: time.Second, ReconcileTimeout: time.Second,
		PublishTimeout: time.Second, BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	status, err := reopened.Get(context.Background(), prepared.PreparationRef)
	if err != nil || status.State != StateAcquiringUnknown || status.Reason != ReasonWorkerInterrupted || !status.AvailableAt.Equal(clock.Now().Add(2*time.Second)) {
		t.Fatalf("recovered status=%#v err=%v", status, err)
	}
	if _, found, err := reopened.ProcessNext(context.Background()); err != nil || found {
		t.Fatalf("recovery backoff hot-looped found=%v err=%v", found, err)
	}
	clock.Advance(2 * time.Second)
	status, found, err = reopened.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateReady {
		t.Fatalf("recovered reconciliation status=%#v found=%v err=%v", status, found, err)
	}
	if acquire, reconcile := acquirer.counts(); acquire != 0 || reconcile != 1 {
		t.Fatalf("restart external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
}

func TestRecoveredGenerationRejectsStaleWorkerCompletion(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 30, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	fixture := newManagerFixture(t, clock, &scriptedAcquirer{}, nil)
	if _, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, "request-stale-generation")); err != nil {
		t.Fatal(err)
	}
	stale, found, err := fixture.manager.store.claim(context.Background(), "worker-stale", now, 4*time.Second)
	if err != nil || !found {
		t.Fatalf("initial claim found=%v err=%v", found, err)
	}
	clock.Advance(5 * time.Second)
	recovery, err := fixture.manager.Recover(context.Background())
	if err != nil || recovery.AcquisitionLeasesRecovered != 1 || recovery.ReconciliationLeasesRecovered != 0 {
		t.Fatalf("recovery=%+v err=%v", recovery, err)
	}
	clock.Advance(2 * time.Second)
	fresh, found, err := fixture.manager.store.claim(context.Background(), "worker-fresh", clock.Now(), 4*time.Second)
	if err != nil || !found || fresh.Kind != claimReconcile || fresh.Generation <= stale.Generation {
		t.Fatalf("fresh claim=%#v found=%v err=%v", fresh, found, err)
	}
	if _, err := fixture.manager.store.completeFailed(context.Background(), stale, ReasonAcquisitionFailed, now.Add(time.Second), ""); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale completion error=%v", err)
	}
	record, err := fixture.manager.store.completeUnknown(context.Background(), fresh, ReasonReconciliationPending, clock.Now(), 2*time.Second, "")
	if err != nil || record.Generation != fresh.Generation || record.Reason != ReasonReconciliationPending {
		t.Fatalf("fresh completion record=%#v err=%v", record, err)
	}
}

func TestConcurrentWorkersNeverOverlapExternalAcquisition(t *testing.T) {
	now := time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	started := make(chan struct{})
	release := make(chan struct{})
	var active, maximum atomic.Int32
	acquirer := &scriptedAcquirer{acquire: func(ctx context.Context, _ AcquisitionRequest) (AcquisitionResult, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		close(started)
		select {
		case <-release:
			return AcquisitionResult{Outcome: AcquisitionPending}, nil
		case <-ctx.Done():
			return AcquisitionResult{}, ctx.Err()
		}
	}}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	if _, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, "request-concurrent")); err != nil {
		t.Fatal(err)
	}
	secondManager, err := Open(Config{
		Path: fixture.database, Owner: "worker-test-second", Acquirer: acquirer, Publisher: fixture.media, Now: clock.Now,
		LeaseTTL: 4 * time.Second, AcquireTimeout: time.Second, ReconcileTimeout: time.Second,
		PublishTimeout: time.Second, BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secondManager.Close()
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := fixture.manager.ProcessNext(context.Background())
		firstDone <- err
	}()
	<-started
	if _, found, err := secondManager.ProcessNext(context.Background()); err != nil || found {
		t.Fatalf("second worker found=%v err=%v", found, err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if acquire, reconcile := acquirer.counts(); acquire != 1 || reconcile != 0 || maximum.Load() != 1 {
		t.Fatalf("calls acquire=%d reconcile=%d maximum-concurrent=%d", acquire, reconcile, maximum.Load())
	}
}

func TestDigestMismatchFailsWithoutPublishingOrRetryingAcquire(t *testing.T) {
	now := time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	content := pngBytes(t, 8, 8)
	acquirer := &scriptedAcquirer{acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
		return AcquisitionResult{Outcome: AcquisitionReady, Content: io.NopCloser(bytes.NewReader(content)), SHA256: strings.Repeat("0", 64)}, nil
	}}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	if _, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, "request-bad-digest")); err != nil {
		t.Fatal(err)
	}
	status, found, err := fixture.manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrAcquirerContract) || status.State != StateFailed || status.Reason != ReasonContentInvalid {
		t.Fatalf("digest mismatch status=%#v found=%v err=%v", status, found, err)
	}
	objects, readErr := os.ReadDir(filepath.Join(fixture.mediaRoot, "objects"))
	if readErr != nil || len(objects) != 0 {
		t.Fatalf("digest mismatch published objects=%d err=%v", len(objects), readErr)
	}
	if _, found, err := fixture.manager.ProcessNext(context.Background()); err != nil || found {
		t.Fatalf("failed preparation retried found=%v err=%v", found, err)
	}
}

func TestReadyResultRequiresAuthoritativeEncodingAndCaptureTime(t *testing.T) {
	now := time.Date(2026, 7, 19, 14, 15, 0, 0, time.UTC)
	content := pngBytes(t, 8, 6)
	for name, mutate := range map[string]func(*AcquisitionResult){
		"missing encoding": func(result *AcquisitionResult) { result.Encoding = media.Encoding{} },
		"before request": func(result *AcquisitionResult) {
			capturedAt := now.Add(-2 * time.Minute)
			result.Temporal.WindowStart, result.Temporal.WindowEnd = &capturedAt, &capturedAt
		},
		"after expiry": func(result *AcquisitionResult) {
			capturedAt := now.Add(2 * time.Hour)
			result.Temporal.WindowStart, result.Temporal.WindowEnd = &capturedAt, &capturedAt
		},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{now: now}
			acquirer := &scriptedAcquirer{acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
				result := readyResult(content, now)
				result.Encoding.WidthPixels, result.Encoding.HeightPixels = 8, 6
				mutate(&result)
				return result, nil
			}}
			fixture := newManagerFixture(t, clock, acquirer, nil)
			requestID := "request-actual-" + strings.ReplaceAll(name, " ", "-")
			if _, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, requestID)); err != nil {
				t.Fatal(err)
			}
			status, found, err := fixture.manager.ProcessNext(context.Background())
			if !found || !errors.Is(err, ErrAcquirerContract) || status.State != StateFailed || status.Reason != ReasonContentInvalid {
				t.Fatalf("status=%#v found=%v err=%v", status, found, err)
			}
			objects, readErr := os.ReadDir(filepath.Join(fixture.mediaRoot, "objects"))
			if readErr != nil || len(objects) != 0 {
				t.Fatalf("invalid actual metadata published objects=%d err=%v", len(objects), readErr)
			}
		})
	}
}

func TestDefiniteAcquisitionFailureIsTerminalAndGeneric(t *testing.T) {
	now := time.Date(2026, 7, 19, 14, 30, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	acquirer := &scriptedAcquirer{acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
		return AcquisitionResult{Outcome: AcquisitionFailed, FailureCode: "adapter-source-unavailable"}, nil
	}}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	if _, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, now, "request-definite-failure")); err != nil {
		t.Fatal(err)
	}
	status, found, err := fixture.manager.ProcessNext(context.Background())
	if err != nil || !found || status.State != StateFailed || status.Reason != ReasonAcquisitionFailed {
		t.Fatalf("definite failure state=%q reason=%q found=%v err=%v", status.State, status.Reason, found, err)
	}
	if acquire, reconcile := acquirer.counts(); acquire != 1 || reconcile != 0 {
		t.Fatalf("terminal external calls acquire=%d reconcile=%d", acquire, reconcile)
	}
}

func TestSchemaOldShapeAndPersistedTamperAreRejected(t *testing.T) {
	root := t.TempDir()
	privateRoot := filepath.Join(root, "private-old")
	if err := localstate.PrepareStateRoot(privateRoot); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(privateRoot, "old.db")
	database, err := sql.Open("sqlite", oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE old_preparations(value TEXT); PRAGMA application_id=1129140273; PRAGMA user_version=1`); err != nil { // CMP1
		t.Fatal(err)
	}
	_ = database.Close()
	if err := localstate.ProtectFile(oldPath); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)}
	mediaStore, err := media.New(media.Config{Root: filepath.Join(root, "media"), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Path: oldPath, Owner: "worker-schema", Acquirer: &scriptedAcquirer{}, Publisher: mediaStore, Now: clock.Now}
	if _, err := Open(config); !errors.Is(err, ErrIncompatibleStore) {
		t.Fatalf("old schema error=%v", err)
	}
	alteredPath := filepath.Join(privateRoot, "altered.db")
	database, err = sql.Open("sqlite", alteredPath)
	if err != nil {
		t.Fatal(err)
	}
	alteredSchema := strings.Replace(createPreparationsSQL, "record_sha256 TEXT NOT NULL", "record_sha256 BLOB NOT NULL", 1)
	if _, err := database.Exec(alteredSchema + "\n" + createClaimIndexSQL + fmt.Sprintf("; PRAGMA application_id=%d; PRAGMA user_version=%d", databaseApplicationID, databaseVersion)); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if err := localstate.ProtectFile(alteredPath); err != nil {
		t.Fatal(err)
	}
	config.Path = alteredPath
	if _, err := Open(config); !errors.Is(err, ErrIncompatibleStore) {
		t.Fatalf("altered schema error=%v", err)
	}

	fixture := newManagerFixture(t, clock, &scriptedAcquirer{}, nil)
	if _, _, err := fixture.manager.Prepare(context.Background(), testRequest(t, clock.Now(), "request-tamper")); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.Close(); err != nil {
		t.Fatal(err)
	}
	tamperDB, err := sql.Open("sqlite", fixture.database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tamperDB.Exec(`UPDATE temporary_media_preparations SET source_ref='source-other'`); err != nil {
		t.Fatal(err)
	}
	_ = tamperDB.Close()
	if _, err := Open(Config{
		Path: fixture.database, Owner: "worker-schema", Acquirer: &scriptedAcquirer{}, Publisher: fixture.media, Now: clock.Now,
	}); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("persisted tamper error=%v", err)
	}
	tamperDB, err = sql.Open("sqlite", fixture.database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tamperDB.Exec(`UPDATE temporary_media_preparations SET source_ref='source-zone-a',record_sha256=?`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	_ = tamperDB.Close()
	if _, err := Open(Config{
		Path: fixture.database, Owner: "worker-schema", Acquirer: &scriptedAcquirer{}, Publisher: fixture.media, Now: clock.Now,
	}); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("record digest tamper error=%v", err)
	}
}

func TestProtectedProjectionsCloseAndLeakSafeErrors(t *testing.T) {
	now := time.Date(2026, 7, 19, 16, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	secret := "rtsp://admin:secret@10.0.0.9/live"
	acquirer := &scriptedAcquirer{acquire: func(context.Context, AcquisitionRequest) (AcquisitionResult, error) {
		return AcquisitionResult{}, errors.New(secret)
	}}
	fixture := newManagerFixture(t, clock, acquirer, nil)
	request := testRequest(t, now, "request-protected")
	if err := request.Validate(); err != nil {
		t.Fatalf("pure request validation: %v", err)
	}
	status, _, err := fixture.manager.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(request); !errors.Is(err, ErrProtected) {
		t.Fatalf("request marshal error=%v", err)
	}
	if _, err := json.Marshal(status); !errors.Is(err, ErrProtected) {
		t.Fatalf("status marshal error=%v", err)
	}
	acquisition := AcquisitionRequest{SourceRef: request.SourceRef, OperationKey: strings.Repeat("a", 64)}
	if _, err := json.Marshal(acquisition); !errors.Is(err, ErrProtected) {
		t.Fatalf("acquisition marshal error=%v", err)
	}
	reconciliation := ReconciliationRequest{OperationKey: strings.Repeat("b", 64), AudienceSHA256: request.AudienceSHA256}
	if _, err := json.Marshal(reconciliation); !errors.Is(err, ErrProtected) {
		t.Fatalf("reconciliation marshal error=%v", err)
	}
	result := AcquisitionResult{Outcome: AcquisitionReady, SHA256: strings.Repeat("c", 64)}
	if _, err := json.Marshal(result); !errors.Is(err, ErrProtected) {
		t.Fatalf("result marshal error=%v", err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("protected", slog.Any("request", request), slog.Any("status", status),
		slog.Any("acquisition", acquisition), slog.Any("reconciliation", reconciliation), slog.Any("result", result))
	projection := fmt.Sprintf("%s %+v %#v %+v %#v %+v %#v %+v %#v %+v %#v", logs.String(), request, request, status, status,
		acquisition, acquisition, reconciliation, reconciliation, result, result)
	for _, forbidden := range []string{request.SourceRef, request.CapabilityRef, request.AudienceBindingRef, request.AudienceSHA256, request.Media.RunID} {
		if strings.Contains(projection, forbidden) {
			t.Fatalf("protected projection leaked %q: %s", forbidden, projection)
		}
	}
	if strings.Contains(projection, result.SHA256) || strings.Contains(projection, reconciliation.OperationKey) {
		t.Fatalf("protected operation result leaked: %s", projection)
	}
	_, _, processErr := fixture.manager.ProcessNext(context.Background())
	if !errors.Is(processErr, ErrOutcomeUnknown) || strings.Contains(processErr.Error(), secret) || strings.Contains(processErr.Error(), "10.0.0.9") {
		t.Fatalf("external error leaked: %v", processErr)
	}
	if err := fixture.manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.Close(); err != nil {
		t.Fatalf("second Close error=%v", err)
	}
	if _, err := fixture.manager.Get(context.Background(), status.PreparationRef); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after close error=%v", err)
	}
	if _, _, err := fixture.manager.Prepare(context.Background(), request); !errors.Is(err, ErrClosed) {
		t.Fatalf("Prepare after close error=%v", err)
	}
}

func TestRequestRejectsNativeLocatorsAndMalformedAudienceBinding(t *testing.T) {
	now := time.Date(2026, 7, 19, 17, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	fixture := newManagerFixture(t, clock, &scriptedAcquirer{}, nil)
	for name, source := range map[string]string{
		"rtsp":      "rtsp://camera/live",
		"ip":        "192.168.1.20",
		"host-port": "10.0.0.9:554",
		"path":      "/var/run/camera",
	} {
		t.Run(name, func(t *testing.T) {
			request := testRequest(t, now, "request-locator-"+name)
			request.SourceRef = source
			if _, _, err := fixture.manager.Prepare(context.Background(), request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("native source %q error=%v", source, err)
			}
		})
	}
	request := testRequest(t, now, "request-audience-malformed")
	request.AudienceSHA256 = "not-a-digest"
	if _, _, err := fixture.manager.Prepare(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed audience digest error=%v", err)
	}
	request = testRequest(t, now, "request-audience-ref-malformed")
	request.AudienceBindingRef = "https://channel.example/conversation"
	if _, _, err := fixture.manager.Prepare(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("native audience binding error=%v", err)
	}
}

func TestFrozenRequestRejectsNonUTCTimesBeforeCanonicalization(t *testing.T) {
	now := time.Date(2026, 7, 19, 17, 30, 0, 0, time.UTC)
	offset := time.FixedZone("offset", 8*60*60)
	for name, mutate := range map[string]func(*FrozenRequest){
		"window start": func(value *FrozenRequest) { value.TimeScope.WindowStart = value.TimeScope.WindowStart.In(offset) },
		"window end":   func(value *FrozenRequest) { value.TimeScope.WindowEnd = value.TimeScope.WindowEnd.In(offset) },
		"expiry":       func(value *FrozenRequest) { value.EvidenceExpiresAt = value.EvidenceExpiresAt.In(offset) },
	} {
		t.Run(name, func(t *testing.T) {
			request := testRequest(t, now, "request-non-utc-"+strings.ReplaceAll(name, " ", "-"))
			mutate(&request)
			if err := request.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("non-UTC request accepted: %v", err)
			}
		})
	}
}

func TestAcquireTimeoutBecomesUnknownAndDoesNotRetryImmediately(t *testing.T) {
	now := time.Date(2026, 7, 19, 18, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: now}
	acquirer := &scriptedAcquirer{acquire: func(ctx context.Context, _ AcquisitionRequest) (AcquisitionResult, error) {
		<-ctx.Done()
		return AcquisitionResult{}, ctx.Err()
	}}
	root := t.TempDir()
	mediaStore, err := media.New(media.Config{Root: filepath.Join(root, "media"), Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := Open(Config{
		Path: filepath.Join(root, "private", "preparations.db"), Owner: "worker-timeout", Acquirer: acquirer,
		Publisher: mediaStore, Now: clock.Now, LeaseTTL: 2 * time.Second, AcquireTimeout: 20 * time.Millisecond,
		ReconcileTimeout: 20 * time.Millisecond, PublishTimeout: 20 * time.Millisecond,
		BaseBackoff: 2 * time.Second, MaximumBackoff: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, _, err := manager.Prepare(context.Background(), testRequest(t, now, "request-timeout")); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	status, found, err := manager.ProcessNext(context.Background())
	if !found || !errors.Is(err, ErrOutcomeUnknown) || status.State != StateAcquiringUnknown || time.Since(started) > time.Second {
		t.Fatalf("timeout status=%#v found=%v elapsed=%s err=%v", status, found, time.Since(started), err)
	}
	if _, found, err := manager.ProcessNext(context.Background()); err != nil || found {
		t.Fatalf("timeout hot-looped found=%v err=%v", found, err)
	}
}

func TestStatusValidateRejectsMalformedRegistrationReceipts(t *testing.T) {
	now := time.Date(2026, 7, 19, 19, 0, 0, 0, time.UTC)
	ref := "media_prep_0123456789abcdef0123456789abcdef"
	base := Status{
		PreparationRef: ref, State: StatePrepared, Reason: ReasonPrepared,
		CreatedAt: now, UpdatedAt: now, AvailableAt: now,
	}
	valid := []Status{
		base,
		{PreparationRef: ref, State: StateAcquiringUnknown, Reason: ReasonAcquisitionPending, CreatedAt: now, UpdatedAt: now, AvailableAt: now},
		{PreparationRef: ref, State: StatePublicationUnknown, Reason: ReasonPublicationUnknown, CreatedAt: now, UpdatedAt: now, AvailableAt: now},
		{PreparationRef: ref, State: StateReady, Reason: ReasonReady, MediaRef: "media_0123456789abcdef0123456789abcdef", CreatedAt: now, UpdatedAt: now, AvailableAt: now},
		{PreparationRef: ref, State: StateFailed, Reason: ReasonContentInvalid, CreatedAt: now, UpdatedAt: now, AvailableAt: now},
	}
	for index, status := range valid {
		if err := status.Validate(ref); err != nil {
			t.Fatalf("valid status %d rejected: %v", index, err)
		}
	}
	for name, mutate := range map[string]func(*Status){
		"wrong ref":        func(value *Status) { value.PreparationRef = "media_prep_ffffffffffffffffffffffffffffffff" },
		"non UTC":          func(value *Status) { value.UpdatedAt = value.UpdatedAt.In(time.FixedZone("offset", 3600)) },
		"updated backward": func(value *Status) { value.UpdatedAt = value.CreatedAt.Add(-time.Nanosecond) },
		"available backward": func(value *Status) {
			value.AvailableAt = value.CreatedAt.Add(-time.Nanosecond)
		},
		"bad state":        func(value *Status) { value.State = State("other") },
		"bad reason":       func(value *Status) { value.Reason = ReasonReady },
		"unexpected media": func(value *Status) { value.MediaRef = "media_0123456789abcdef0123456789abcdef" },
	} {
		t.Run(name, func(t *testing.T) {
			status := base
			mutate(&status)
			if err := status.Validate(ref); !errors.Is(err, ErrInvalid) {
				t.Fatalf("malformed status accepted: %#v err=%v", status, err)
			}
		})
	}
}
