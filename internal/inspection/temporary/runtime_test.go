package temporary

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
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	_ "modernc.org/sqlite"
)

var runtimeTestNow = time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)

const runtimeTestMediaRef = "media_0123456789abcdef0123456789abcdef"

type runtimeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *runtimeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *runtimeClock) Set(value time.Time) {
	c.mu.Lock()
	c.now = value.UTC()
	c.mu.Unlock()
}

type preparationFixture struct {
	mu     sync.Mutex
	status mediaprep.Status
	err    error
	calls  int
}

func (p *preparationFixture) Get(_ context.Context, ref string) (mediaprep.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.status.PreparationRef != ref {
		return mediaprep.Status{}, mediaprep.ErrNotFound
	}
	return p.status, p.err
}

func (p *preparationFixture) Set(status mediaprep.Status) {
	p.mu.Lock()
	p.status = status
	p.mu.Unlock()
}

func (p *preparationFixture) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type runtimeMediaFixture struct {
	descriptor MediaDescriptor
	content    []byte
	describes  atomic.Int32
	opens      atomic.Int32
}

func (m *runtimeMediaFixture) Describe(_ context.Context, ref string) (MediaDescriptor, error) {
	m.describes.Add(1)
	if ref != m.descriptor.MediaRef {
		return MediaDescriptor{}, errors.New("media not found")
	}
	return m.descriptor, nil
}

func (m *runtimeMediaFixture) Open(_ context.Context, ref string) (io.ReadCloser, error) {
	m.opens.Add(1)
	if ref != m.descriptor.MediaRef {
		return nil, errors.New("media not found")
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), m.content...))), nil
}

type runtimeAnalyzerFunc func(context.Context, AnalysisRequest) ([]byte, error)

func (f runtimeAnalyzerFunc) Analyze(ctx context.Context, request AnalysisRequest) ([]byte, error) {
	return f(ctx, request)
}

func TestSubmissionBindsMediaKindToObservationTimeScope(t *testing.T) {
	current := runtimeSubmission(t, runtimeTestNow, "request-current-kind")
	changed := current
	changed.MediaKind = media.KindVideoClip
	if err := changed.Validate(); !errors.Is(err, ErrRuntimeInvalid) {
		t.Fatalf("current observation accepted video media: %v", err)
	}

	recent := runtimeSubmission(t, runtimeTestNow, "request-recent-kind")
	var err error
	recent.Spec, err = NewSpec(Intent{
		Subject: "装卸区域", Region: "入口附近", Observable: "最近一分钟是否存在可见临时堆放物", Locale: "zh-CN",
		TimeScope: TimeScope{Kind: TimeScopeRecentWindow, WindowSeconds: 60}, EvidenceTTLSeconds: 10 * 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	recent.MediaKind = media.KindVideoClip
	if err := recent.Validate(); err != nil {
		t.Fatalf("valid recent clip submission: %v", err)
	}
	recent.MediaKind = media.KindImage
	if err := recent.Validate(); !errors.Is(err, ErrRuntimeInvalid) {
		t.Fatalf("recent observation accepted snapshot downgrade: %v", err)
	}
}

func TestRuntimeRejectsNonUTCTimesAcrossPublicContracts(t *testing.T) {
	offset := time.FixedZone("offset", 8*60*60)
	for name, mutate := range map[string]func(*Submission){
		"submitted": func(value *Submission) { value.SubmittedAt = value.SubmittedAt.In(offset) },
		"evidence expiry": func(value *Submission) {
			value.EvidenceExpiresAt = value.EvidenceExpiresAt.In(offset)
		},
		"deadline": func(value *Submission) { value.DeadlineAt = value.DeadlineAt.In(offset) },
	} {
		t.Run("submission "+name, func(t *testing.T) {
			submission := runtimeSubmission(t, runtimeTestNow, "request-non-utc-submission-"+strings.ReplaceAll(name, " ", "-"))
			mutate(&submission)
			if err := submission.Validate(); !errors.Is(err, ErrRuntimeInvalid) {
				t.Fatalf("non-UTC submission accepted: %v", err)
			}
		})
	}

	store := openRuntimeTestStore(t)
	defer store.Close()
	submission := runtimeSubmission(t, runtimeTestNow, "request-non-utc-store")
	if _, _, err := store.Submit(context.Background(), submission, runtimeTestNow.In(offset)); !errors.Is(err, ErrRuntimeInvalid) {
		t.Fatalf("non-UTC store time accepted: %v", err)
	}
	record, _, err := store.Submit(context.Background(), submission, runtimeTestNow)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Record){
		"submitted":       func(value *Record) { value.SubmittedAt = value.SubmittedAt.In(offset) },
		"deadline":        func(value *Record) { value.DeadlineAt = value.DeadlineAt.In(offset) },
		"available":       func(value *Record) { value.AvailableAt = value.AvailableAt.In(offset) },
		"updated":         func(value *Record) { value.UpdatedAt = value.UpdatedAt.In(offset) },
		"evidence expiry": func(value *Record) { value.EvidenceExpiresAt = value.EvidenceExpiresAt.In(offset) },
	} {
		t.Run("record "+name, func(t *testing.T) {
			changed := cloneRecord(record)
			mutate(&changed)
			if err := changed.Validate(); !errors.Is(err, ErrRuntimeCorrupt) {
				t.Fatalf("non-UTC record accepted: %v", err)
			}
		})
	}
	lease := Lease{
		RunID: record.RunID, Generation: record.Generation + 1, Owner: "worker-utc",
		StartedAt: runtimeTestNow, LeaseExpiresAt: runtimeTestNow.Add(time.Minute),
	}
	for name, mutate := range map[string]func(*Lease){
		"started": func(value *Lease) { value.StartedAt = value.StartedAt.In(offset) },
		"expires": func(value *Lease) { value.LeaseExpiresAt = value.LeaseExpiresAt.In(offset) },
	} {
		t.Run("lease "+name, func(t *testing.T) {
			changed := lease
			mutate(&changed)
			if validLease(changed) {
				t.Fatal("non-UTC lease accepted")
			}
		})
	}
	event := TerminalEvent{
		Schema: TerminalSchemaVersion, EventID: "tempevent_0123456789abcdef0123456789abcdef",
		RunID: record.RunID, PublicRunRef: record.Binding.PublicRunRef, ResultRef: "tempresult_0123456789abcdef0123456789abcdef",
		State: StateFailed, OccurredAt: runtimeTestNow,
	}
	event.OccurredAt = event.OccurredAt.In(offset)
	if err := validateTerminalEvent(event); !errors.Is(err, ErrRuntimeCorrupt) {
		t.Fatalf("non-UTC terminal event accepted: %v", err)
	}
}

func TestRuntimeRejectsInvalidPreparationProjectionAndMediaShape(t *testing.T) {
	submission := runtimeSubmission(t, runtimeTestNow, "request-invalid-projection")
	for name, status := range map[string]mediaprep.Status{
		"prepared with ready reason":         preparationStatus(submission, mediaprep.StatePrepared, mediaprep.ReasonReady, ""),
		"acquiring with publication reason":  preparationStatus(submission, mediaprep.StateAcquiringUnknown, mediaprep.ReasonPublicationUnknown, ""),
		"publishing with acquisition reason": preparationStatus(submission, mediaprep.StatePublicationUnknown, mediaprep.ReasonAcquisitionPending, ""),
		"failed with ready reason":           preparationStatus(submission, mediaprep.StateFailed, mediaprep.ReasonReady, ""),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePreparationStatus(status, submission.PreparationRef); !errors.Is(err, ErrRuntimeInvalid) {
				t.Fatalf("invalid preparation projection accepted: %v", err)
			}
		})
	}

	store := openRuntimeTestStore(t)
	defer store.Close()
	record, _, err := store.Submit(context.Background(), submission, runtimeTestNow)
	if err != nil {
		t.Fatal(err)
	}
	record.MediaRef = runtimeTestMediaRef
	for name, mutate := range map[string]func(*MediaDescriptor){
		"unsupported webp":        func(value *MediaDescriptor) { value.MIMEType = "image/webp" },
		"unfrozen sample ordinal": func(value *MediaDescriptor) { value.Temporal.SampleOrdinal = 1 },
		"point before request": func(value *MediaDescriptor) {
			point := submission.SubmittedAt.Add(-time.Second)
			value.Temporal.WindowStart, value.Temporal.WindowEnd = &point, &point
		},
		"snapshot downgrade": func(value *MediaDescriptor) {
			value.Kind, value.MIMEType = media.KindVideoClip, "video/mp4"
		},
		"capture beyond future bound": func(value *MediaDescriptor) {
			point := runtimeTestNow.Add(2*time.Minute + time.Nanosecond)
			value.Temporal.WindowStart, value.Temporal.WindowEnd = &point, &point
		},
	} {
		t.Run(name, func(t *testing.T) {
			descriptor := runtimeMedia(t, submission).descriptor
			mutate(&descriptor)
			if err := descriptor.validate(record, runtimeTestNow); !errors.Is(err, ErrRuntimeInvalid) {
				t.Fatalf("invalid media descriptor accepted: %v", err)
			}
		})
	}
}

func TestRecentWindowRejectsReaderWindowMismatchAndSnapshotDowngrade(t *testing.T) {
	submission := runtimeSubmission(t, runtimeTestNow, "request-recent-reader")
	var err error
	submission.Spec, err = NewSpec(Intent{
		Subject: "装卸区域", Region: "入口附近", Observable: "最近一分钟是否存在可见临时堆放物", Locale: "zh-CN",
		TimeScope: TimeScope{Kind: TimeScopeRecentWindow, WindowSeconds: 60}, EvidenceTTLSeconds: 10 * 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	submission.MediaKind = media.KindVideoClip
	store := openRuntimeTestStore(t)
	defer store.Close()
	record, _, err := store.Submit(context.Background(), submission, runtimeTestNow)
	if err != nil {
		t.Fatal(err)
	}
	record.MediaRef = runtimeTestMediaRef
	end := submission.SubmittedAt
	start := end.Add(-time.Minute)
	valid := runtimeMedia(t, submission).descriptor
	valid.Kind, valid.MIMEType = media.KindVideoClip, "video/mp4"
	valid.Temporal = media.Temporal{WindowStart: &start, WindowEnd: &end, DurationMillis: 60_000}
	if err := valid.validate(record, runtimeTestNow); err != nil {
		t.Fatalf("valid recent descriptor: %v", err)
	}

	wrongWindow := valid
	wrongStart := start.Add(time.Second)
	wrongWindow.Temporal.WindowStart = &wrongStart
	if err := wrongWindow.validate(record, runtimeTestNow); !errors.Is(err, ErrRuntimeInvalid) {
		t.Fatalf("recent window mismatch accepted: %v", err)
	}
	downgrade := valid
	downgrade.Kind, downgrade.MIMEType = media.KindImage, "image/jpeg"
	downgrade.Temporal = media.Temporal{WindowStart: &end, WindowEnd: &end}
	if err := downgrade.validate(record, runtimeTestNow); !errors.Is(err, ErrRuntimeInvalid) {
		t.Fatalf("recent snapshot downgrade accepted: %v", err)
	}
}

func TestRuntimePendingThenReadyPersistsBackoffWithoutAttempt(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	clock := &runtimeClock{now: runtimeTestNow}
	submission := runtimeSubmission(t, runtimeTestNow, "request-pending-ready")
	preparations := &preparationFixture{status: preparationStatus(submission, mediaprep.StatePrepared, mediaprep.ReasonPrepared, "")}
	media := runtimeMedia(t, submission)
	capturedAt := submission.SubmittedAt.Add(time.Second)
	media.descriptor.Temporal.WindowStart, media.descriptor.Temporal.WindowEnd = timePointer(capturedAt), timePointer(capturedAt)
	var analyzerCalls atomic.Int32
	manager, err := NewManager(store, preparations, media, runtimeAnalyzerFunc(func(_ context.Context, request AnalysisRequest) ([]byte, error) {
		analyzerCalls.Add(1)
		if request.Evidence.EvidenceRef != runtimeTestMediaRef || !request.Evidence.CapturedAt.Equal(capturedAt) {
			t.Fatalf("unexpected evidence binding %+v", request.Evidence)
		}
		return runtimeCandidateJSON(t, runtimeTestMediaRef), nil
	}), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	first, created, err := manager.Submit(context.Background(), submission)
	if err != nil || !created {
		t.Fatalf("Submit() record=%+v created=%v err=%v", first, created, err)
	}
	pending, ran, err := manager.RunOnce(context.Background(), "worker-alpha", time.Minute)
	if err != nil || !ran || pending.State != StateQueued || pending.Reason != ReasonPreparationPending ||
		pending.Attempt != 0 || pending.PreparationPolls != 1 || !pending.AvailableAt.Equal(runtimeTestNow.Add(time.Second)) {
		t.Fatalf("pending RunOnce() record=%+v ran=%v err=%v", pending, ran, err)
	}
	if analyzerCalls.Load() != 0 || media.describes.Load() != 0 || media.opens.Load() != 0 {
		t.Fatal("pending preparation reached media or analyzer")
	}
	if _, ran, err := manager.RunOnce(context.Background(), "worker-alpha", time.Minute); err != nil || ran {
		t.Fatalf("backoff was not honored ran=%v err=%v", ran, err)
	}
	preparations.Set(preparationStatus(submission, mediaprep.StateReady, mediaprep.ReasonReady, runtimeTestMediaRef))
	clock.Set(runtimeTestNow.Add(time.Second))
	terminal, ran, err := manager.RunOnce(context.Background(), "worker-alpha", time.Minute)
	if err != nil || !ran || terminal.State != StateSucceeded || terminal.Attempt != 1 || terminal.MediaRef != runtimeTestMediaRef ||
		terminal.Candidate == nil || terminal.Observation == nil || analyzerCalls.Load() != 1 || preparations.Calls() != 2 {
		t.Fatalf("ready RunOnce() record=%+v ran=%v err=%v analyzer=%d prep=%d", terminal, ran, err, analyzerCalls.Load(), preparations.Calls())
	}
	if err := terminal.Validate(); err != nil {
		t.Fatalf("returned terminal record failed validation: %v", err)
	}
	event, err := store.TerminalEvent(context.Background(), terminal.RunID)
	if err != nil || event.State != StateSucceeded || event.ResultSHA256 != terminal.ResultSHA256 {
		t.Fatalf("TerminalEvent() event=%+v err=%v", event, err)
	}
}

func TestRuntimePreparationFailureAndExpiryAreHonestTerminalStates(t *testing.T) {
	for _, test := range []struct {
		name       string
		prepReason mediaprep.Reason
		wantState  State
		wantReason Reason
	}{
		{name: "failed", prepReason: mediaprep.ReasonAcquisitionFailed, wantState: StateFailed, wantReason: ReasonPreparationFailed},
		{name: "expired", prepReason: mediaprep.ReasonEvidenceExpired, wantState: StateExpired, wantReason: ReasonPreparationExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := openRuntimeTestStore(t)
			defer store.Close()
			submission := runtimeSubmission(t, runtimeTestNow, "request-prep-"+test.name)
			preparations := &preparationFixture{status: preparationStatus(submission, mediaprep.StateFailed, test.prepReason, "")}
			media := runtimeMedia(t, submission)
			var analyzerCalls atomic.Int32
			manager, err := NewManager(store, preparations, media, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
				analyzerCalls.Add(1)
				return nil, nil
			}), func() time.Time { return runtimeTestNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Submit(context.Background(), submission); err != nil {
				t.Fatal(err)
			}
			terminal, ran, err := manager.RunOnce(context.Background(), "worker-terminal", time.Minute)
			if err != nil || !ran || terminal.State != test.wantState || terminal.Reason != test.wantReason || terminal.Attempt != 0 ||
				analyzerCalls.Load() != 0 || media.describes.Load() != 0 {
				t.Fatalf("terminal=%+v ran=%v err=%v", terminal, ran, err)
			}
		})
	}
}

func TestRuntimeRestartRecoveryKeepsPreparationReplayable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "temporary.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	submission := runtimeSubmission(t, runtimeTestNow, "request-restart")
	created, _, err := store.Submit(context.Background(), submission, runtimeTestNow)
	if err != nil {
		t.Fatal(err)
	}
	_, lease, claimed, err := store.Claim(context.Background(), "worker-restart", runtimeTestNow, time.Second)
	if err != nil || !claimed {
		t.Fatalf("Claim() claimed=%v err=%v", claimed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recoverAt := lease.LeaseExpiresAt.Add(time.Nanosecond)
	if count, err := store.Recover(context.Background(), recoverAt); err != nil || count != 1 {
		t.Fatalf("Recover() count=%d err=%v", count, err)
	}
	recovered, err := store.Get(context.Background(), created.RunID)
	if err != nil || recovered.State != StateQueued || recovered.Reason != ReasonRecoveredBeforeAnalysis || recovered.Attempt != 0 ||
		!recovered.AvailableAt.Equal(recoverAt.Add(preparationRecoveryBackoff)) {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
}

func TestRuntimeAnalysisInterruptionBecomesOutcomeUnknown(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	submission := runtimeSubmission(t, runtimeTestNow, "request-analysis-crash")
	record, _, err := store.Submit(context.Background(), submission, runtimeTestNow)
	if err != nil {
		t.Fatal(err)
	}
	_, lease, claimed, err := store.Claim(context.Background(), "worker-analysis", runtimeTestNow, time.Second)
	if err != nil || !claimed {
		t.Fatalf("Claim() claimed=%v err=%v", claimed, err)
	}
	prompt, err := CompilePrompt(record.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginAnalysis(context.Background(), lease, runtimeMedia(t, submission).descriptor, prompt.SHA256, runtimeTestNow); err != nil {
		t.Fatal(err)
	}
	if count, err := store.Recover(context.Background(), lease.LeaseExpiresAt.Add(time.Nanosecond)); err != nil || count != 1 {
		t.Fatalf("Recover() count=%d err=%v", count, err)
	}
	unknown, err := store.Get(context.Background(), record.RunID)
	if err != nil || unknown.State != StateOutcomeUnknown || unknown.Reason != ReasonAnalysisOutcomeUnknown || unknown.Attempt != 1 {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
}

func TestRuntimeConcurrentDuplicateSubmitHasOneFrozenRun(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	submission := runtimeSubmission(t, runtimeTestNow, "request-concurrent")
	var created atomic.Int32
	var runID atomic.Value
	errorsSeen := make(chan error, 16)
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, wasCreated, err := store.Submit(context.Background(), submission, runtimeTestNow)
			if err != nil {
				errorsSeen <- err
				return
			}
			if wasCreated {
				created.Add(1)
			}
			if first := runID.Load(); first == nil {
				runID.Store(record.RunID)
			} else if first.(string) != record.RunID {
				errorsSeen <- fmt.Errorf("run identity changed")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if created.Load() != 1 {
		t.Fatalf("created=%d, want 1", created.Load())
	}
	conflict := submission
	conflict.Spec = runtimeSpec(t, "是否存在其他物品")
	if _, _, err := store.Submit(context.Background(), conflict, runtimeTestNow); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("changed duplicate error=%v", err)
	}
}

func TestRuntimeRejectsAudiencePreparationMediaTamperingAndOldSchema(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	base := runtimeSubmission(t, runtimeTestNow, "request-tamper-input")
	for name, mutate := range map[string]func(*Submission){
		"audience digest":   func(value *Submission) { value.AudienceSHA256 = stringsOf("f", 64) },
		"first recipient":   func(value *Submission) { value.Binding.RecipientRef = "recipient-other" },
		"preparation ref":   func(value *Submission) { value.PreparationRef = "media_prep_ffffffffffffffffffffffffffffffff" },
		"credential":        func(value *Submission) { value.Binding.RequestKey = "token_secret" },
		"endpoint":          func(value *Submission) { value.Binding.ConversationRef = "rtsp.endpoint" },
		"native identifier": func(value *Submission) { value.Binding.RecipientRef = "camera_id" },
		"IP":                func(value *Submission) { value.Binding.SiteID = "192.168.1.2" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, _, err := store.Submit(context.Background(), value, runtimeTestNow); !errors.Is(err, ErrRuntimeInvalid) {
				t.Fatalf("unsafe submission error=%v", err)
			}
		})
	}

	oldRoot := filepath.Join(t.TempDir(), "old-state")
	if err := localstate.PrepareStateRoot(oldRoot); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(oldRoot, "old.db")
	db, err := sql.Open("sqlite", oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA application_id=1128617010; PRAGMA user_version=2; CREATE TABLE legacy(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(oldPath); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenSQLite(oldPath); !errors.Is(err, ErrRuntimeSchema) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("old schema error=%v", err)
	}
}

func TestRuntimeStoreRejectsTamperedRecordOnReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "temporary.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Submit(context.Background(), runtimeSubmission(t, runtimeTestNow, "request-db-tamper"), runtimeTestNow); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE temporary_runs SET generation=generation+1`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenSQLite(path); !errors.Is(err, ErrRuntimeCorrupt) {
		if reopened != nil {
			reopened.Close()
		}
		t.Fatalf("tampered store error=%v", err)
	}
}

func TestRuntimeInvalidCandidateDoesNotPersistRawModelOutputOrPrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "temporary.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	submission := runtimeSubmission(t, runtimeTestNow, "request-raw-output")
	preparations := &preparationFixture{status: preparationStatus(submission, mediaprep.StateReady, mediaprep.ReasonReady, runtimeTestMediaRef)}
	rawSecret := `{"schema":"cosmoedge.inspection.temporary.candidate.v2","summary":"可见目标","visibleFacts":[],"limitations":[],"evidenceRefs":["media_0123456789abcdef0123456789abcdef"],"modelProse":"rtsp://user:password@192.168.1.9/live"}`
	manager, err := NewManager(store, preparations, runtimeMedia(t, submission), runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
		return []byte(rawSecret), nil
	}), func() time.Time { return runtimeTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Submit(context.Background(), submission); err != nil {
		t.Fatal(err)
	}
	terminal, ran, err := manager.RunOnce(context.Background(), "worker-invalid", time.Minute)
	if err != nil || !ran || terminal.State != StateInvalidCandidate {
		t.Fatalf("terminal=%+v ran=%v err=%v", terminal, ran, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	databaseBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(rawSecret), []byte("rtsp://user:password"), []byte("192.168.1.9/live"), []byte("你是 CosmoEdge Connect 的一次性视觉观察器")} {
		if bytes.Contains(databaseBytes, forbidden) {
			t.Fatalf("runtime database persisted forbidden raw content %q", forbidden)
		}
	}
}

func openRuntimeTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "state", "temporary.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func runtimeSubmission(t *testing.T, now time.Time, requestKey string) Submission {
	t.Helper()
	binding := AuthenticatedBinding{
		TenantID: "tenant-alpha", SiteID: "site-alpha", RequestKey: requestKey,
		PublicRunRef: "run-public-alpha", Channel: "wechat", ConversationRef: "conversation-alpha",
		RecipientRef: "recipient-alpha", PrincipalSHA256: digestText("principal-alpha"),
	}
	audience, err := FreezeAudience(ChannelSession{
		TenantID: binding.TenantID, SiteID: binding.SiteID, Channel: binding.Channel,
		ConversationRef: binding.ConversationRef, RecipientRef: binding.RecipientRef,
		PrincipalSHA256: binding.PrincipalSHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	preparationRef, err := mediaprep.PreparationRefForScope(binding.TenantID, binding.SiteID, binding.RequestKey)
	if err != nil {
		t.Fatal(err)
	}
	spec := runtimeSpec(t, "是否存在可见临时堆放物")
	expiresAt := now.UTC().Add(time.Duration(spec.EvidenceTTLSeconds) * time.Second)
	return Submission{
		Binding: binding, Spec: spec, PreparationRef: preparationRef, MediaKind: media.KindImage,
		AudienceBindingRef: audience.Ref, AudienceSHA256: audience.SHA256,
		EvidenceExpiresAt: expiresAt, SubmittedAt: now.UTC(), DeadlineAt: now.UTC().Add(5 * time.Minute),
	}
}

func runtimeSpec(t *testing.T, observable string) TemporaryObservationSpec {
	t.Helper()
	spec, err := NewSpec(Intent{
		Subject: "装卸区域", Region: "入口附近", Observable: observable, Locale: "zh-CN",
		TimeScope: TimeScope{Kind: TimeScopeCurrent}, EvidenceTTLSeconds: 10 * 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func preparationStatus(submission Submission, state mediaprep.State, reason mediaprep.Reason, mediaRef string) mediaprep.Status {
	return mediaprep.Status{
		PreparationRef: submission.PreparationRef, State: state, Reason: reason, MediaRef: mediaRef,
		CreatedAt: submission.SubmittedAt, UpdatedAt: submission.SubmittedAt, AvailableAt: submission.SubmittedAt,
	}
}

func runtimeMedia(t *testing.T, submission Submission) *runtimeMediaFixture {
	t.Helper()
	content := []byte("device-free-visual-fixture")
	digest := sha256.Sum256(content)
	runID, err := RunIDForScope(submission.Binding.TenantID, submission.Binding.SiteID, submission.Binding.RequestKey)
	if err != nil {
		t.Fatal(err)
	}
	stepID, err := MediaStepIDForRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	return &runtimeMediaFixture{
		content: content,
		descriptor: MediaDescriptor{
			MediaRef: runtimeTestMediaRef, Kind: submission.MediaKind, TenantID: submission.Binding.TenantID, SiteID: submission.Binding.SiteID,
			RunID: runID, StepID: stepID, Attempt: 1, AudienceBindingRef: submission.AudienceBindingRef,
			SHA256: hex.EncodeToString(digest[:]), MIMEType: "image/jpeg", SizeBytes: int64(len(content)),
			Temporal:  media.Temporal{WindowStart: timePointer(submission.SubmittedAt), WindowEnd: timePointer(submission.SubmittedAt)},
			ExpiresAt: submission.EvidenceExpiresAt,
		},
	}
}

func timePointer(value time.Time) *time.Time {
	canonical := value.UTC()
	return &canonical
}

func runtimeCandidateJSON(t *testing.T, evidenceRef string) []byte {
	t.Helper()
	raw, err := json.Marshal(Candidate{
		Schema: CandidateSchemaVersion, Summary: "入口附近可见一个临时放置的纸箱",
		VisibleFacts: []string{"纸箱位于画面中央"}, Limitations: []string{}, EvidenceRefs: []string{evidenceRef},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func stringsOf(value string, count int) string {
	buffer := bytes.Buffer{}
	for index := 0; index < count; index++ {
		buffer.WriteString(value)
	}
	return buffer.String()
}
