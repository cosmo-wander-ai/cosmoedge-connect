package temporary

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
)

type boundaryPreparationReader struct {
	status mediaprep.Status
	err    error
	onGet  func()
	calls  int
}

func (r *boundaryPreparationReader) Get(_ context.Context, _ string) (mediaprep.Status, error) {
	r.calls++
	if r.onGet != nil {
		r.onGet()
	}
	return r.status, r.err
}

type boundaryMediaReader struct {
	descriptor  MediaDescriptor
	content     []byte
	describeErr error
	openErr     error
	onDescribe  func()
	onOpen      func()
	describes   int
	opens       int
}

func (r *boundaryMediaReader) Describe(_ context.Context, _ string) (MediaDescriptor, error) {
	r.describes++
	if r.onDescribe != nil {
		r.onDescribe()
	}
	return r.descriptor, r.describeErr
}

func (r *boundaryMediaReader) Open(_ context.Context, _ string) (io.ReadCloser, error) {
	r.opens++
	if r.onOpen != nil {
		r.onOpen()
	}
	if r.openErr != nil {
		return nil, r.openErr
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), r.content...))), nil
}

func TestRuntimePreparationTransientPersistsPendingWithoutProductError(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	submission := runtimeSubmission(t, runtimeTestNow, "request-prep-transient-boundary")
	preparations := &boundaryPreparationReader{
		status: preparationStatus(submission, mediaprep.StatePrepared, mediaprep.ReasonPrepared, ""),
		err:    fmt.Errorf("preparation service timeout: %w", ErrDependencyRetryable),
	}
	mediaReader := runtimeMedia(t, submission)
	var analyzerCalls int
	manager, err := NewManager(store, preparations, mediaReader, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
		analyzerCalls++
		return nil, nil
	}), func() time.Time { return runtimeTestNow })
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := manager.Submit(context.Background(), submission)
	if err != nil {
		t.Fatal(err)
	}

	pending, ran, err := manager.RunOnce(context.Background(), "worker-prep-transient", time.Minute)
	if err != nil || !ran || pending.State != StateQueued || pending.Reason != ReasonPreparationPending ||
		pending.PreparationPolls != 1 || pending.Attempt != 0 || !pending.AvailableAt.Equal(runtimeTestNow.Add(time.Second)) {
		t.Fatalf("pending=%+v ran=%v err=%v", pending, ran, err)
	}
	authoritative, err := store.Get(context.Background(), created.RunID)
	if err != nil || authoritative.State != StateQueued || authoritative.PreparationPolls != 1 ||
		authoritative.Attempt != 0 || analyzerCalls != 0 || mediaReader.describes.Load() != 0 || mediaReader.opens.Load() != 0 {
		t.Fatalf("authoritative=%+v err=%v analyzer=%d describe=%d open=%d", authoritative, err, analyzerCalls, mediaReader.describes.Load(), mediaReader.opens.Load())
	}
}

func TestRuntimePreparationFatalReadFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		key  string
		err  error
	}{
		{name: "corrupt store", key: "corrupt-store", err: mediaprep.ErrCorruptStore},
		{name: "invalid projection", key: "invalid-projection", err: mediaprep.ErrInvalid},
		{name: "missing preparation", key: "not-found", err: mediaprep.ErrNotFound},
		{name: "unclassified IO", key: "unclassified-io", err: errors.New("local sqlite read failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := openRuntimeTestStore(t)
			defer store.Close()
			submission := runtimeSubmission(t, runtimeTestNow, "request-prep-fatal-"+test.key)
			preparations := &boundaryPreparationReader{
				status: preparationStatus(submission, mediaprep.StatePrepared, mediaprep.ReasonPrepared, ""),
				err:    fmt.Errorf("preparation read: %w", test.err),
			}
			mediaReader := runtimeMedia(t, submission)
			var analyzerCalls int
			manager, err := NewManager(store, preparations, mediaReader, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
				analyzerCalls++
				return nil, nil
			}), func() time.Time { return runtimeTestNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Submit(context.Background(), submission); err != nil {
				t.Fatal(err)
			}

			running, ran, err := manager.RunOnce(context.Background(), "worker-prep-fatal", time.Second)
			if !errors.Is(err, ErrDependencyFatal) || !ran || running.State != StateRunning || running.Phase != PhasePreparing ||
				running.Reason != ReasonClaimed || running.Attempt != 0 || running.PreparationPolls != 0 || analyzerCalls != 0 ||
				mediaReader.describes.Load() != 0 || mediaReader.opens.Load() != 0 {
				t.Fatalf("running=%+v ran=%v err=%v analyzer=%d describe=%d open=%d", running, ran, err, analyzerCalls, mediaReader.describes.Load(), mediaReader.opens.Load())
			}
			if _, err := store.TerminalEvent(context.Background(), running.RunID); !errors.Is(err, ErrRuntimeNotFound) {
				t.Fatalf("unexpected terminal event: %v", err)
			}
			recoverAt := runtimeTestNow.Add(time.Second)
			if count, err := store.Recover(context.Background(), recoverAt); err != nil || count != 1 {
				t.Fatalf("Recover() count=%d err=%v", count, err)
			}
			recovered, err := store.Get(context.Background(), running.RunID)
			if err != nil || recovered.State != StateQueued || recovered.Reason != ReasonRecoveredBeforeAnalysis ||
				recovered.PreparationPolls != 0 || recovered.Attempt != 0 {
				t.Fatalf("recovered=%+v err=%v", recovered, err)
			}
		})
	}
}

func TestRuntimeMediaTransientPersistsPendingWithoutProductError(t *testing.T) {
	for _, stage := range []string{"describe", "open"} {
		t.Run(stage, func(t *testing.T) {
			store := openRuntimeTestStore(t)
			defer store.Close()
			submission := runtimeSubmission(t, runtimeTestNow, "request-media-transient-"+stage)
			fixture := runtimeMedia(t, submission)
			reader := &boundaryMediaReader{descriptor: fixture.descriptor, content: fixture.content}
			transient := fmt.Errorf("media backend timeout: %w", ErrDependencyRetryable)
			if stage == "describe" {
				reader.describeErr = transient
			} else {
				reader.openErr = transient
			}
			preparations := &boundaryPreparationReader{
				status: preparationStatus(submission, mediaprep.StateReady, mediaprep.ReasonReady, runtimeTestMediaRef),
			}
			var analyzerCalls int
			manager, err := NewManager(store, preparations, reader, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
				analyzerCalls++
				return nil, nil
			}), func() time.Time { return runtimeTestNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Submit(context.Background(), submission); err != nil {
				t.Fatal(err)
			}

			pending, ran, err := manager.RunOnce(context.Background(), "worker-media-transient", time.Minute)
			if err != nil || !ran || pending.State != StateQueued || pending.Reason != ReasonPreparationPending ||
				pending.PreparationPolls != 1 || pending.Attempt != 0 || analyzerCalls != 0 || reader.describes != 1 {
				t.Fatalf("pending=%+v ran=%v err=%v analyzer=%d describe=%d open=%d", pending, ran, err, analyzerCalls, reader.describes, reader.opens)
			}
			if stage == "describe" && reader.opens != 0 || stage == "open" && reader.opens != 1 {
				t.Fatalf("stage=%s opens=%d", stage, reader.opens)
			}
		})
	}
}

func TestRuntimeMediaFatalReadsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name              string
		key               string
		describe          error
		open              error
		mutate            func(*MediaDescriptor)
		definitiveAbsence bool
		wantOpens         int
	}{
		{name: "corrupt descriptor store", key: "corrupt-descriptor", describe: fmt.Errorf("describe: %w", media.ErrCorruptDescriptor)},
		{name: "invalid bound descriptor", key: "invalid-bound", mutate: func(value *MediaDescriptor) { value.AudienceBindingRef = "audience-other" }},
		{name: "non UTC temporal", key: "non-utc-temporal", mutate: func(value *MediaDescriptor) {
			offset := time.FixedZone("offset", 8*60*60)
			start, end := value.Temporal.WindowStart.In(offset), value.Temporal.WindowEnd.In(offset)
			value.Temporal.WindowStart, value.Temporal.WindowEnd, value.ExpiresAt = &start, &end, value.ExpiresAt.In(offset)
		}},
		{name: "future capture", key: "future-capture", mutate: func(value *MediaDescriptor) {
			point := runtimeTestNow.Add(2*time.Minute + time.Nanosecond)
			value.Temporal.WindowStart, value.Temporal.WindowEnd = &point, &point
		}, wantOpens: 1},
		{name: "definitively absent media", key: "absent", describe: fmt.Errorf("describe: %w", media.ErrNotFound), definitiveAbsence: true},
		{name: "unclassified IO", key: "unclassified-io", describe: errors.New("local media read failed")},
		{name: "unclassified open IO", key: "unclassified-open-io", open: errors.New("local media open failed"), wantOpens: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := openRuntimeTestStore(t)
			defer store.Close()
			submission := runtimeSubmission(t, runtimeTestNow, "request-media-fatal-"+test.key)
			fixture := runtimeMedia(t, submission)
			descriptor := fixture.descriptor
			if test.mutate != nil {
				test.mutate(&descriptor)
			}
			reader := &boundaryMediaReader{descriptor: descriptor, content: fixture.content, describeErr: test.describe, openErr: test.open}
			preparations := &boundaryPreparationReader{
				status: preparationStatus(submission, mediaprep.StateReady, mediaprep.ReasonReady, runtimeTestMediaRef),
			}
			var analyzerCalls int
			manager, err := NewManager(store, preparations, reader, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
				analyzerCalls++
				return nil, nil
			}), func() time.Time { return runtimeTestNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Submit(context.Background(), submission); err != nil {
				t.Fatal(err)
			}

			result, ran, err := manager.RunOnce(context.Background(), "worker-media-fatal", time.Minute)
			if !errors.Is(err, ErrDependencyFatal) || !ran || result.Attempt != 0 || result.PreparationPolls != 0 ||
				analyzerCalls != 0 || reader.opens != test.wantOpens {
				t.Fatalf("result=%+v ran=%v err=%v analyzer=%d describe=%d open=%d", result, ran, err, analyzerCalls, reader.describes, reader.opens)
			}
			if test.definitiveAbsence {
				if result.State != StateFailed || result.Reason != ReasonMediaUnavailable {
					t.Fatalf("definitive absence result=%+v", result)
				}
				return
			}
			if result.State != StateRunning || result.Phase != PhasePreparing || result.Reason != ReasonClaimed {
				t.Fatalf("dependency failure forged terminal result=%+v", result)
			}
			if _, err := store.TerminalEvent(context.Background(), result.RunID); !errors.Is(err, ErrRuntimeNotFound) {
				t.Fatalf("dependency failure emitted a terminal event: %v", err)
			}
			recoverAt := runtimeTestNow.Add(time.Minute)
			if count, err := store.Recover(context.Background(), recoverAt); err != nil || count != 1 {
				t.Fatalf("Recover() count=%d err=%v", count, err)
			}
			recovered, err := store.Get(context.Background(), result.RunID)
			if err != nil || recovered.State != StateQueued || recovered.Reason != ReasonRecoveredBeforeAnalysis || recovered.Attempt != 0 {
				t.Fatalf("recovered=%+v err=%v", recovered, err)
			}
		})
	}
}

func TestRuntimeRecentReaderWindowMismatchFailsClosedBeforeAnalysis(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	submission := runtimeSubmission(t, runtimeTestNow, "request-recent-reader-boundary")
	var err error
	submission.Spec, err = NewSpec(Intent{
		Subject: "装卸区域", Region: "入口附近", Observable: "最近一分钟是否存在可见临时堆放物", Locale: "zh-CN",
		TimeScope: TimeScope{Kind: TimeScopeRecentWindow, WindowSeconds: 60}, EvidenceTTLSeconds: 10 * 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	submission.MediaKind = media.KindVideoClip
	fixture := runtimeMedia(t, submission)
	end := submission.SubmittedAt
	wrongStart := end.Add(-59 * time.Second)
	reader := &boundaryMediaReader{descriptor: fixture.descriptor, content: fixture.content}
	reader.descriptor.Kind, reader.descriptor.MIMEType = media.KindVideoClip, "video/mp4"
	reader.descriptor.Temporal = media.Temporal{WindowStart: &wrongStart, WindowEnd: &end, DurationMillis: 59_000}
	preparations := &boundaryPreparationReader{
		status: preparationStatus(submission, mediaprep.StateReady, mediaprep.ReasonReady, runtimeTestMediaRef),
	}
	var analyzerCalls int
	manager, err := NewManager(store, preparations, reader, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
		analyzerCalls++
		return nil, nil
	}), func() time.Time { return runtimeTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Submit(context.Background(), submission); err != nil {
		t.Fatal(err)
	}
	running, ran, err := manager.RunOnce(context.Background(), "worker-recent-mismatch", time.Minute)
	if !errors.Is(err, ErrDependencyFatal) || !ran || running.State != StateRunning || running.Phase != PhasePreparing ||
		running.Reason != ReasonClaimed || running.Attempt != 0 || reader.opens != 0 || analyzerCalls != 0 {
		t.Fatalf("running=%+v ran=%v opens=%d analyzer=%d err=%v", running, ran, reader.opens, analyzerCalls, err)
	}
	if _, err := store.TerminalEvent(context.Background(), running.RunID); !errors.Is(err, ErrRuntimeNotFound) {
		t.Fatalf("malicious recent reader emitted a terminal event: %v", err)
	}
}

func TestRuntimeDeadlineDuringPreparationReadReturnsAuthoritativeExpiry(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	clock := &runtimeClock{now: runtimeTestNow}
	submission := runtimeSubmission(t, runtimeTestNow, "request-prep-deadline-boundary")
	preparations := &boundaryPreparationReader{
		status: preparationStatus(submission, mediaprep.StatePrepared, mediaprep.ReasonPrepared, ""),
		err:    mediaprep.ErrCorruptStore,
		onGet:  func() { clock.Set(submission.DeadlineAt) },
	}
	manager, err := NewManager(store, preparations, runtimeMedia(t, submission), runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
		t.Fatal("analyzer called after deadline")
		return nil, nil
	}), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Submit(context.Background(), submission); err != nil {
		t.Fatal(err)
	}

	terminal, ran, err := manager.RunOnce(context.Background(), "worker-prep-deadline", MaxLeaseTTL)
	if err != nil || !ran || terminal.State != StateExpired || terminal.Reason != ReasonDeadlineExpired ||
		terminal.PreparationPolls != 0 || terminal.Attempt != 0 || !terminal.CompletedAt.Equal(submission.DeadlineAt) {
		t.Fatalf("terminal=%+v ran=%v err=%v", terminal, ran, err)
	}
}

func TestRuntimeLeaseExpiryDuringMediaOpenReturnsRecoveredAuthority(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	clock := &runtimeClock{now: runtimeTestNow}
	submission := runtimeSubmission(t, runtimeTestNow, "request-media-lease-boundary")
	fixture := runtimeMedia(t, submission)
	leaseExpiry := runtimeTestNow.Add(time.Second)
	reader := &boundaryMediaReader{
		descriptor: fixture.descriptor,
		content:    fixture.content,
		onOpen:     func() { clock.Set(leaseExpiry) },
	}
	preparations := &boundaryPreparationReader{
		status: preparationStatus(submission, mediaprep.StateReady, mediaprep.ReasonReady, runtimeTestMediaRef),
	}
	manager, err := NewManager(store, preparations, reader, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
		t.Fatal("analyzer called after lease expiry")
		return nil, nil
	}), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Submit(context.Background(), submission); err != nil {
		t.Fatal(err)
	}

	recovered, ran, err := manager.RunOnce(context.Background(), "worker-media-lease", time.Second)
	if err != nil || !ran || recovered.State != StateQueued || recovered.Reason != ReasonRecoveredBeforeAnalysis ||
		recovered.PreparationPolls != 0 || recovered.Attempt != 0 || !recovered.AvailableAt.Equal(leaseExpiry.Add(preparationRecoveryBackoff)) {
		t.Fatalf("recovered=%+v ran=%v err=%v", recovered, ran, err)
	}
}

func TestRuntimeLostLeaseReturnsConcurrentAuthoritativeOwnerWithoutError(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	submission := runtimeSubmission(t, runtimeTestNow, "request-concurrent-lease-boundary")
	var takeover Record
	preparations := &boundaryPreparationReader{
		status: preparationStatus(submission, mediaprep.StatePrepared, mediaprep.ReasonPrepared, ""),
		onGet: func() {
			expiredAt := runtimeTestNow.Add(time.Second)
			if count, err := store.Recover(context.Background(), expiredAt); err != nil || count != 1 {
				t.Fatalf("takeover Recover() count=%d err=%v", count, err)
			}
			claimAt := expiredAt.Add(preparationRecoveryBackoff)
			var claimed bool
			var err error
			takeover, _, claimed, err = store.Claim(context.Background(), "worker-takeover", claimAt, time.Second)
			if err != nil || !claimed {
				t.Fatalf("takeover Claim() claimed=%v err=%v", claimed, err)
			}
		},
	}
	mediaReader := runtimeMedia(t, submission)
	manager, err := NewManager(store, preparations, mediaReader, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
		t.Fatal("analyzer called for stale lease")
		return nil, nil
	}), func() time.Time { return runtimeTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Submit(context.Background(), submission); err != nil {
		t.Fatal(err)
	}

	authoritative, ran, err := manager.RunOnce(context.Background(), "worker-stale", time.Second)
	if err != nil || !ran || authoritative.State != StateRunning || authoritative.Phase != PhasePreparing ||
		authoritative.LeaseOwner != "worker-takeover" || authoritative.Generation != takeover.Generation ||
		authoritative.PreparationPolls != 0 || authoritative.Attempt != 0 ||
		mediaReader.describes.Load() != 0 || mediaReader.opens.Load() != 0 {
		t.Fatalf("authoritative=%+v takeover=%+v ran=%v err=%v", authoritative, takeover, ran, err)
	}
}

func TestRuntimeAnalysisLeaseExpiryReturnsOutcomeUnknownAuthority(t *testing.T) {
	store := openRuntimeTestStore(t)
	defer store.Close()
	clock := &runtimeClock{now: runtimeTestNow}
	submission := runtimeSubmission(t, runtimeTestNow, "request-analysis-lease-boundary")
	fixture := runtimeMedia(t, submission)
	preparations := &boundaryPreparationReader{
		status: preparationStatus(submission, mediaprep.StateReady, mediaprep.ReasonReady, runtimeTestMediaRef),
	}
	manager, err := NewManager(store, preparations, fixture, runtimeAnalyzerFunc(func(context.Context, AnalysisRequest) ([]byte, error) {
		clock.Set(runtimeTestNow.Add(time.Second))
		return runtimeCandidateJSON(t, runtimeTestMediaRef), nil
	}), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Submit(context.Background(), submission); err != nil {
		t.Fatal(err)
	}

	unknown, ran, err := manager.RunOnce(context.Background(), "worker-analysis-lease", time.Second)
	if err != nil || !ran || unknown.State != StateOutcomeUnknown || unknown.Reason != ReasonAnalysisOutcomeUnknown ||
		unknown.Attempt != 1 || unknown.Media == nil {
		t.Fatalf("unknown=%+v ran=%v err=%v", unknown, ran, err)
	}
}
