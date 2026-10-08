package inspectionfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

type temporaryAcquirer struct {
	assets assets
	mu     sync.Mutex
	ready  map[string]mediaprep.AcquisitionResult
}

func newTemporaryAcquirer(fixtureAssets assets) *temporaryAcquirer {
	return &temporaryAcquirer{assets: fixtureAssets, ready: make(map[string]mediaprep.AcquisitionResult)}
}

func (a *temporaryAcquirer) Acquire(ctx context.Context, request mediaprep.AcquisitionRequest) (mediaprep.AcquisitionResult, error) {
	if err := ctx.Err(); err != nil {
		return mediaprep.AcquisitionResult{}, err
	}
	result, err := a.resultFor(request.Kind, request.TimeScope)
	if err != nil {
		return mediaprep.AcquisitionResult{}, err
	}
	a.mu.Lock()
	a.ready[request.OperationKey] = cloneAcquisitionResult(result)
	a.mu.Unlock()
	return result, nil
}

func (a *temporaryAcquirer) Reconcile(ctx context.Context, request mediaprep.ReconciliationRequest) (mediaprep.AcquisitionResult, error) {
	if err := ctx.Err(); err != nil {
		return mediaprep.AcquisitionResult{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	result, ok := a.ready[request.OperationKey]
	if !ok {
		return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionPending}, nil
	}
	return cloneAcquisitionResult(result), nil
}

func (a *temporaryAcquirer) resultFor(kind media.Kind, scope mediaprep.TimeScope) (mediaprep.AcquisitionResult, error) {
	var payload []byte
	var encoding media.Encoding
	switch kind {
	case media.KindImage:
		payload = a.assets.snapshot
		encoding = media.Encoding{MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg", WidthPixels: a.assets.snapshotWidth, HeightPixels: a.assets.snapshotHeight}
		capture := time.Now().UTC()
		if capture.Before(scope.WindowStart) {
			capture = scope.WindowStart.UTC()
		}
		scope = mediaprep.TimeScope{WindowStart: capture, WindowEnd: capture}
	case media.KindVideoClip:
		payload = a.assets.clip
		encoding = media.Encoding{MIMEType: "video/mp4", Container: "mp4", Codec: "h264", WidthPixels: a.assets.clipWidth, HeightPixels: a.assets.clipHeight, FrameRate: a.assets.clipFrameRate}
		if scope.DurationMillis != a.assets.clipDuration {
			return mediaprep.AcquisitionResult{}, errors.New("fixture temporary clip request does not match the prepared media duration")
		}
	default:
		return mediaprep.AcquisitionResult{}, errors.New("fixture temporary media kind is unsupported")
	}
	return mediaprep.AcquisitionResult{
		Outcome: mediaprep.AcquisitionReady, Content: io.NopCloser(bytes.NewReader(payload)),
		SHA256: digestBytes(payload), Encoding: encoding,
		Temporal: media.Temporal{
			WindowStart: timePointer(scope.WindowStart), WindowEnd: timePointer(scope.WindowEnd),
			DurationMillis: scope.DurationMillis,
		},
	}, nil
}

func cloneAcquisitionResult(value mediaprep.AcquisitionResult) mediaprep.AcquisitionResult {
	result := value
	result.Content = nil
	return result
}

// Reconciliation must return bytes again. Keep a private immutable value
// instead of attempting to rewind a reader previously owned by mediaprep.
type replayingTemporaryAcquirer struct {
	inner *temporaryAcquirer
}

func (a replayingTemporaryAcquirer) Acquire(ctx context.Context, request mediaprep.AcquisitionRequest) (mediaprep.AcquisitionResult, error) {
	return a.inner.Acquire(ctx, request)
}

func (a replayingTemporaryAcquirer) Reconcile(ctx context.Context, request mediaprep.ReconciliationRequest) (mediaprep.AcquisitionResult, error) {
	if err := ctx.Err(); err != nil {
		return mediaprep.AcquisitionResult{}, err
	}
	a.inner.mu.Lock()
	stored, ok := a.inner.ready[request.OperationKey]
	a.inner.mu.Unlock()
	if !ok {
		return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionPending}, nil
	}
	payload := a.inner.assets.snapshot
	if stored.Encoding.MIMEType == "video/mp4" {
		payload = a.inner.assets.clip
	}
	stored.Content = io.NopCloser(bytes.NewReader(payload))
	return stored, nil
}

type temporaryMediaReader struct{ store *media.Store }

func (r temporaryMediaReader) Describe(ctx context.Context, ref string) (temporary.MediaDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return temporary.MediaDescriptor{}, err
	}
	descriptor, err := r.store.Describe(ref)
	if err != nil {
		return temporary.MediaDescriptor{}, err
	}
	audience := ""
	if len(descriptor.Governance.Audience) == 1 {
		audience = descriptor.Governance.Audience[0]
	}
	return temporary.MediaDescriptor{
		MediaRef: descriptor.MediaRef, Kind: descriptor.Kind,
		TenantID: descriptor.Binding.TenantID, SiteID: descriptor.Binding.SiteID,
		RunID: descriptor.Binding.RunID, StepID: descriptor.Binding.StepID, Attempt: descriptor.Binding.Attempt,
		AudienceBindingRef: audience, SHA256: descriptor.Integrity.SHA256,
		MIMEType: descriptor.Encoding.MIMEType, SizeBytes: descriptor.Integrity.SizeBytes,
		Temporal: descriptor.Temporal, ExpiresAt: descriptor.Governance.ExpiresAt,
	}, nil
}

func (r temporaryMediaReader) Open(ctx context.Context, ref string) (io.ReadCloser, error) {
	_, reader, err := r.store.Open(ctx, ref)
	return reader, err
}

type temporaryAnalyzer struct{}

func (temporaryAnalyzer) Analyze(ctx context.Context, request temporary.AnalysisRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.Evidence.EvidenceRef == "" || request.Evidence.SHA256 == "" || len(request.Evidence.Content) == 0 {
		return nil, temporary.ErrAnalysisDefinitelyFailed
	}
	return json.Marshal(temporary.Candidate{
		Schema:       temporary.CandidateSchemaVersion,
		Summary:      "当前画面中可见需要进一步人工确认的现场情况。",
		VisibleFacts: []string{"画面内容已成功获取并完成限定范围内的观察。"},
		Limitations:  []string{simulatedMediaLimitation},
		EvidenceRefs: []string{request.Evidence.EvidenceRef},
	})
}

var (
	_ mediaprep.Acquirer    = replayingTemporaryAcquirer{}
	_ temporary.MediaReader = temporaryMediaReader{}
	_ temporary.Analyzer    = temporaryAnalyzer{}
)
