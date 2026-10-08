package livevision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	"io"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

const maxTemporaryAcquisitions = 128

type temporaryCapture struct {
	content  []byte
	encoding media.Encoding
	temporal media.Temporal
}

type temporaryVisionAnalysis struct {
	runID        string
	prompt       string
	promptSHA256 string
	evidenceRef  string
	evidenceSHA  string
	jpeg         []byte
}

type temporaryVisionResult struct {
	modelText []byte
	quality   temporaryImageQuality
}

// temporaryVision is deliberately private to the ordinary Operator process.
// The inspection service receives only the generic ConnectionProvider, while
// the real Vault-backed provider additionally implements this exact snapshot
// and picture-VLM seam. A fixture provider cannot silently become a fallback.
type temporaryVision interface {
	captureTemporarySnapshot(context.Context, mediaprep.AcquisitionRequest) (temporaryCapture, error)
	analyzeTemporarySnapshot(context.Context, temporaryVisionAnalysis) (temporaryVisionResult, error)
}

type temporaryAcquisition struct {
	identity       string
	preparationRef string
	audienceSHA256 string
	expiresAt      time.Time
	pending        bool
	capture        temporaryCapture
}

type liveTemporaryAcquirer struct {
	connections inspectionadapter.ConnectionProvider

	mu         sync.Mutex
	operations map[string]temporaryAcquisition
}

func newLiveTemporaryAcquirer(connections inspectionadapter.ConnectionProvider) *liveTemporaryAcquirer {
	return &liveTemporaryAcquirer{
		connections: connections,
		operations:  make(map[string]temporaryAcquisition),
	}
}

func (a *liveTemporaryAcquirer) Acquire(ctx context.Context, request mediaprep.AcquisitionRequest) (mediaprep.AcquisitionResult, error) {
	if err := ctx.Err(); err != nil {
		return mediaprep.AcquisitionResult{}, err
	}
	if a == nil || !validTemporaryAcquisitionRequest(request) {
		return failedTemporaryAcquisition("snapshot-request-invalid"), nil
	}
	vision, ok := a.connections.(temporaryVision)
	if !ok || vision == nil {
		return failedTemporaryAcquisition("live-connection-unavailable"), nil
	}
	identity := temporaryAcquisitionIdentity(request)
	now := time.Now().UTC()
	a.mu.Lock()
	a.pruneExpiredLocked(now)
	if stored, exists := a.operations[request.OperationKey]; exists {
		a.mu.Unlock()
		if stored.identity != identity {
			return failedTemporaryAcquisition("snapshot-request-conflict"), nil
		}
		if stored.pending {
			return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionPending}, nil
		}
		return readyTemporaryAcquisition(stored.capture), nil
	}
	if len(a.operations) >= maxTemporaryAcquisitions {
		a.mu.Unlock()
		return failedTemporaryAcquisition("snapshot-capacity-exhausted"), nil
	}
	a.operations[request.OperationKey] = temporaryAcquisition{
		identity: identity, preparationRef: request.PreparationRef, audienceSHA256: request.AudienceSHA256,
		expiresAt: request.EvidenceExpiresAt.UTC(), pending: true,
	}
	a.mu.Unlock()

	capture, err := vision.captureTemporarySnapshot(ctx, request)
	if err != nil {
		a.mu.Lock()
		delete(a.operations, request.OperationKey)
		a.mu.Unlock()
		if ctx.Err() != nil {
			return mediaprep.AcquisitionResult{}, ctx.Err()
		}
		return failedTemporaryAcquisition("snapshot-unavailable"), nil
	}
	a.mu.Lock()
	a.operations[request.OperationKey] = temporaryAcquisition{
		identity: identity, preparationRef: request.PreparationRef, audienceSHA256: request.AudienceSHA256,
		expiresAt: request.EvidenceExpiresAt.UTC(), capture: cloneTemporaryCapture(capture),
	}
	a.mu.Unlock()
	return readyTemporaryAcquisition(capture), nil
}

func (a *liveTemporaryAcquirer) Reconcile(ctx context.Context, request mediaprep.ReconciliationRequest) (mediaprep.AcquisitionResult, error) {
	if err := ctx.Err(); err != nil {
		return mediaprep.AcquisitionResult{}, err
	}
	if a == nil || request.OperationKey == "" || request.TenantID != TenantID || request.SiteID != SiteID {
		return failedTemporaryAcquisition("snapshot-reconciliation-invalid"), nil
	}
	now := time.Now().UTC()
	a.mu.Lock()
	a.pruneExpiredLocked(now)
	stored, exists := a.operations[request.OperationKey]
	a.mu.Unlock()
	if !exists {
		// Reconciliation is intentionally read-only. After a process restart we
		// cannot prove which bytes a possibly-started capture returned, so a new
		// camera read is never substituted for the original operation.
		return failedTemporaryAcquisition("snapshot-not-recoverable"), nil
	}
	if stored.preparationRef != request.PreparationRef || stored.audienceSHA256 != request.AudienceSHA256 {
		return failedTemporaryAcquisition("snapshot-reconciliation-conflict"), nil
	}
	if stored.pending {
		return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionPending}, nil
	}
	return readyTemporaryAcquisition(stored.capture), nil
}

func (a *liveTemporaryAcquirer) pruneExpiredLocked(now time.Time) {
	for key, operation := range a.operations {
		if !operation.expiresAt.After(now) {
			delete(a.operations, key)
		}
	}
}

func validTemporaryAcquisitionRequest(request mediaprep.AcquisitionRequest) bool {
	return request.PreparationRef != "" && request.OperationKey != "" &&
		request.TenantID == TenantID && request.SiteID == SiteID && request.SourceRef != "" &&
		request.CapabilityRef == snapshotCapability && request.Kind == media.KindImage &&
		request.TimeScope.DurationMillis == 0 && request.TimeScope.SampleOrdinal == 0 &&
		request.TimeScope.WindowStart.Location() == time.UTC && request.TimeScope.WindowEnd.Location() == time.UTC &&
		request.TimeScope.WindowStart.Equal(request.TimeScope.WindowEnd) &&
		request.EvidenceExpiresAt.Location() == time.UTC && request.EvidenceExpiresAt.After(request.TimeScope.WindowEnd)
}

func temporaryAcquisitionIdentity(request mediaprep.AcquisitionRequest) string {
	value := strings.Join([]string{
		"cosmoedge.inspection.live-temporary-acquisition.v1", request.PreparationRef,
		request.TenantID, request.SiteID, request.SourceRef, request.CapabilityRef, string(request.Kind),
		request.TimeScope.WindowStart.Format(time.RFC3339Nano), request.TimeScope.WindowEnd.Format(time.RFC3339Nano),
		fmt.Sprint(request.TimeScope.SampleOrdinal), request.AudienceSHA256, request.EvidenceExpiresAt.Format(time.RFC3339Nano),
	}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func failedTemporaryAcquisition(code string) mediaprep.AcquisitionResult {
	return mediaprep.AcquisitionResult{Outcome: mediaprep.AcquisitionFailed, FailureCode: code}
}

func readyTemporaryAcquisition(capture temporaryCapture) mediaprep.AcquisitionResult {
	copyCapture := cloneTemporaryCapture(capture)
	digest := sha256.Sum256(copyCapture.content)
	return mediaprep.AcquisitionResult{
		Outcome: mediaprep.AcquisitionReady, Content: io.NopCloser(bytes.NewReader(copyCapture.content)),
		SHA256: hex.EncodeToString(digest[:]), Encoding: copyCapture.encoding, Temporal: copyCapture.temporal,
	}
}

func cloneTemporaryCapture(capture temporaryCapture) temporaryCapture {
	result := capture
	result.content = append([]byte(nil), capture.content...)
	if capture.temporal.WindowStart != nil {
		value := *capture.temporal.WindowStart
		result.temporal.WindowStart = &value
	}
	if capture.temporal.WindowEnd != nil {
		value := *capture.temporal.WindowEnd
		result.temporal.WindowEnd = &value
	}
	return result
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

type liveTemporaryAnalyzer struct {
	connections inspectionadapter.ConnectionProvider
}

func (a liveTemporaryAnalyzer) Analyze(ctx context.Context, request temporary.AnalysisRequest) (candidate []byte, analysisErr error) {
	defer func() {
		if p, ok := a.connections.(*vaultConnections); ok && analysisErr != nil {
			analysisErr = p.recordFailure(ctx, analysisErr, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseInputValidation, safediagnostic.ValidationInvalidRequest))
		}
	}()
	if err := ctx.Err(); err != nil {
		diagnostic := safediagnostic.Diagnostic{Operation: safediagnostic.OperationAnalysis, Phase: safediagnostic.PhaseBeforeDispatch, Class: safediagnostic.ClassUnavailable}
		if errors.Is(err, context.DeadlineExceeded) {
			diagnostic.ValidationCode = safediagnostic.ValidationDeadlineExpired
		}
		return nil, safediagnostic.Wrap(err, diagnostic)
	}
	if request.RunID == "" || request.Prompt.Version != temporary.PromptVersion || request.Prompt.Text == "" ||
		request.Prompt.SHA256 == "" || request.Prompt.Observable() == "" || request.Evidence.EvidenceRef == "" || request.Evidence.MIMEType != "image/jpeg" ||
		len(request.Evidence.Content) < 1 || len(request.Evidence.Content) > int(maxLiveJPEGBytes) ||
		request.Evidence.CapturedAt.IsZero() || !request.Evidence.ExpiresAt.After(request.Evidence.CapturedAt) {
		return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, errors.New("temporary visual analysis input is invalid"))
	}
	promptDigest := sha256.Sum256([]byte(request.Prompt.Text))
	contentDigest := sha256.Sum256(request.Evidence.Content)
	if hex.EncodeToString(promptDigest[:]) != request.Prompt.SHA256 || hex.EncodeToString(contentDigest[:]) != request.Evidence.SHA256 {
		return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, errors.New("temporary visual analysis binding is invalid"))
	}
	decoded, format, err := image.DecodeConfig(bytes.NewReader(request.Evidence.Content))
	if err != nil || format != "jpeg" || decoded.Width < 1 || decoded.Height < 1 {
		return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, errors.New("temporary visual evidence is not a JPEG"))
	}
	vision, ok := a.connections.(temporaryVision)
	if !ok || vision == nil {
		return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, errors.New("live temporary visual connection is unavailable"))
	}
	modelPrompt := request.Prompt.Text
	if len(modelPrompt) > 2056 {
		return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, errors.New("temporary visual prompt exceeds the live model bound"))
	}
	result, err := vision.analyzeTemporarySnapshot(ctx, temporaryVisionAnalysis{
		runID: request.RunID, prompt: modelPrompt, promptSHA256: request.Prompt.SHA256,
		evidenceRef: request.Evidence.EvidenceRef, evidenceSHA: request.Evidence.SHA256,
		jpeg: append([]byte(nil), request.Evidence.Content...),
	})
	if err == nil {
		var candidateJSON []byte
		var candidateErr error
		if result.quality != "" {
			candidateJSON, candidateErr = temporaryQualityCandidateJSON(result.quality, request.Evidence.EvidenceRef)
		} else {
			candidateJSON, candidateErr = temporaryCandidateJSON(result.modelText, request.Evidence.EvidenceRef, request.Prompt.Observable())
		}
		if candidateErr != nil {
			return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, candidateErr)
		}
		return candidateJSON, nil
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), err)
	}
	if errors.Is(err, inspectionadapter.ErrOutcomeUnknown) {
		return nil, errors.Join(temporary.ErrAnalysisOutcomeUnknown, err)
	}
	return nil, errors.Join(temporary.ErrAnalysisDefinitelyFailed, err)
}

func (p *vaultConnections) captureTemporarySnapshot(ctx context.Context, request mediaprep.AcquisitionRequest) (capture temporaryCapture, captureErr error) {
	defer func() {
		captureErr = p.recordFailure(ctx, captureErr, localDiagnostic(safediagnostic.OperationCameraPicture, safediagnostic.PhaseSourceBinding, safediagnostic.ValidationBindingInvalid))
	}()
	if !validTemporaryAcquisitionRequest(request) || request.SourceRef != p.sourceRef() {
		return temporaryCapture{}, inspectionadapter.ErrBindingStale
	}
	connection, err := p.connection(ctx)
	if err != nil {
		return temporaryCapture{}, err
	}
	snapshot := connection.Snapshot()
	camera, ok := p.selectCamera(snapshot)
	if !ok || SourceFingerprint(snapshot, camera) == "" {
		return temporaryCapture{}, inspectionadapter.ErrBindingStale
	}
	picture, err := connection.Client().GetCameraPictureContext(ctx, camera.ID)
	if err != nil {
		return temporaryCapture{}, p.recordFailure(ctx, sanitizeDeviceError(err), safediagnostic.Diagnostic{Operation: safediagnostic.OperationCameraPicture, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassUnavailable})
	}
	jpeg, err := connection.Client().DownloadFreshCameraPictureJPEG(ctx, picture, minInt64(8<<20, maxLiveJPEGBytes))
	if err != nil {
		return temporaryCapture{}, p.recordFailure(ctx, sanitizeDeviceError(err), safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureDownload, Phase: safediagnostic.PhaseDownload, Class: safediagnostic.ClassUnavailable})
	}
	if len(jpeg.Content) < 1 || jpeg.Width < 1 || jpeg.Height < 1 {
		return temporaryCapture{}, safediagnostic.Wrap(inspectionadapter.ErrInvalidResponse, localDiagnostic(safediagnostic.OperationPictureDownload, safediagnostic.PhaseValidateJPEG, safediagnostic.ValidationInvalidJPEG))
	}
	observedAt := p.now().UTC()
	if observedAt.Before(request.TimeScope.WindowEnd) || !request.EvidenceExpiresAt.After(observedAt) {
		return temporaryCapture{}, safediagnostic.Wrap(inspectionadapter.ErrOutcomeUnknown, localDiagnostic(safediagnostic.OperationCameraPicture, safediagnostic.PhaseInputValidation, safediagnostic.ValidationDeadlineExpired))
	}
	return temporaryCapture{
		content: append([]byte(nil), jpeg.Content...),
		encoding: media.Encoding{
			MIMEType: "image/jpeg", Container: "jpeg", Codec: "jpeg",
			WidthPixels: jpeg.Width, HeightPixels: jpeg.Height,
		},
		temporal: media.Temporal{WindowStart: timePointer(observedAt), WindowEnd: timePointer(observedAt), SampleOrdinal: 0},
	}, nil
}

func (p *vaultConnections) analyzeTemporarySnapshot(ctx context.Context, request temporaryVisionAnalysis) (result temporaryVisionResult, analysisErr error) {
	defer func() {
		analysisErr = p.recordFailure(ctx, analysisErr, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseSourceBinding, safediagnostic.ValidationBindingInvalid))
	}()
	if request.runID == "" || p.diagnosticRunID != "" && p.diagnosticRunID != request.runID || request.prompt == "" || len(request.prompt) > 2056 ||
		!digestPattern.MatchString(request.promptSHA256) || !digestPattern.MatchString(request.evidenceSHA) ||
		request.evidenceRef == "" || len(request.jpeg) < 1 || len(request.jpeg) > int(maxLiveJPEGBytes) {
		return temporaryVisionResult{}, inspectionadapter.ErrBindingStale
	}
	connection, err := p.connection(ctx)
	if err != nil {
		return temporaryVisionResult{}, err
	}
	quality, err := assessTemporaryImage(ctx, request.jpeg)
	if err != nil {
		return temporaryVisionResult{}, safediagnostic.Wrap(err, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseValidateJPEG, safediagnostic.ValidationInvalidJPEG))
	}
	if quality != "" {
		return temporaryVisionResult{quality: quality}, nil
	}
	selected, err := selectPictureAlgorithm(ctx, connection.Client(), connection.Snapshot())
	if err != nil {
		return temporaryVisionResult{}, p.recordFailure(ctx, err, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseAlgorithmSelection, safediagnostic.ValidationAlgorithmUnavailable))
	}
	keyDigest := sha256.Sum256([]byte(strings.Join([]string{
		"cosmoedge.inspection.live-temporary-analysis.v1", request.runID,
		request.promptSHA256, request.evidenceSHA, request.evidenceRef,
	}, "\x00")))
	key := hex.EncodeToString(keyDigest[:])
	task := temporaryPictureTask{
		key: key, runID: request.runID, taskID: runScopedTaskID(key),
		algorithmCode: selected.algorithmCode, updateTime: selected.updateTime, phase: temporaryTaskCreating,
	}
	if !p.reserveTask(task) {
		return temporaryVisionResult{}, inspectionadapter.ErrOutcomeUnknown
	}
	journalTask := TemporaryTask{RunID: request.runID, TaskID: task.taskID, AlgorithmCode: selected.algorithmCode, DeviceIdentitySHA256: deviceIdentityDigest(connection.Snapshot()), ConnectionEpoch: connectionEpoch(connection)}
	if p.taskJournal != nil {
		if err := p.taskJournal.BeforeCreate(ctx, journalTask); err != nil {
			p.forgetTask(key)
			return temporaryVisionResult{}, p.recordFailure(ctx, errors.Join(inspectionadapter.ErrOutcomeUnknown, ErrTemporaryCleanupUnconfirmed), journalPersistenceDiagnostic(safediagnostic.OperationPictureCreate))
		}
	}
	createErr := connection.Client().CreatePictureTaskContext(ctx, adapter.PictureTaskCreateRequest{
		TaskID: task.taskID, AlgorithmCode: task.algorithmCode, AlgorithmUpdateTime: task.updateTime,
	})
	if createErr != nil {
		mapped := p.recordFailure(ctx, sanitizeDeviceError(createErr), safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureCreate, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassUnavailable})
		if errors.Is(mapped, inspectionadapter.ErrOutcomeUnknown) || errors.Is(createErr, context.Canceled) || errors.Is(createErr, context.DeadlineExceeded) {
			p.markTask(key, temporaryTaskCreationUnknown)
			cleanupErr := cancelJournaledTask(context.WithoutCancel(ctx), connection, journalTask, p.taskJournal)
			if cleanupErr == nil {
				p.forgetTask(key)
			}
			return temporaryVisionResult{}, errors.Join(mapped, inspectionadapter.ErrOutcomeUnknown, cleanupErr)
		} else {
			p.forgetTask(key)
			if p.taskJournal != nil {
				writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), failedTaskCleanupLimit)
				err := p.taskJournal.FinishTask(writeCtx, journalTask, TaskNotCreated)
				cancel()
				if err != nil {
					journalErr := p.recordFailure(ctx, ErrTemporaryCleanupUnconfirmed, journalPersistenceDiagnostic(safediagnostic.OperationPictureCreate))
					return temporaryVisionResult{}, errors.Join(mapped, journalErr)
				}
			}
		}
		return temporaryVisionResult{}, mapped
	}
	p.markTask(key, temporaryTaskCreated)
	detectRequest := adapter.PictureTaskDetectRequest{
		TaskID: task.taskID, AlgorithmCode: task.algorithmCode, JPEG: request.jpeg,
		TaskConfig: adapter.PictureTaskConfig{Params: []adapter.PictureTaskParameter{
			{Key: "advanced_mode", Value: "1"},
			{Key: "generationStyle", Value: "strict"},
			{Key: "keywords", Value: request.prompt},
		}},
	}
	var detected adapter.PictureTaskDetectResult
	var detectErr error
	if p.uploadJournal != nil {
		detected, detectErr = p.detectStagedTemporaryPicture(ctx, connection, request, detectRequest)
	} else {
		// The separate legacy inspection service retains its original contract.
		// Ordinary observations always install the owned upload journal.
		detected, detectErr = connection.Client().DetectPictureTaskContext(ctx, detectRequest)
	}
	if detectErr == nil {
		p.markTask(key, temporaryTaskDetected)
	} else {
		// Save the analysis failure before cleanup; a later successful cancel
		// cannot turn it into success or replace its diagnostic.
		detectErr = p.recordFailure(ctx, sanitizeDeviceError(detectErr), safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureDetect, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassUnavailable})
	}
	cancelErr := cancelJournaledTask(context.WithoutCancel(ctx), connection, journalTask, p.taskJournal)
	if cancelErr == nil {
		p.forgetTask(key)
	}
	if detectErr != nil {
		return temporaryVisionResult{}, errors.Join(detectErr, cancelErr)
	}
	if cancelErr != nil {
		return temporaryVisionResult{}, errors.Join(inspectionadapter.ErrOutcomeUnknown, cancelErr)
	}
	text, err := temporaryDetectionText(detected)
	return temporaryVisionResult{modelText: text}, err
}

func temporaryDetectionText(result adapter.PictureTaskDetectResult) ([]byte, error) {
	labels := make(map[string]struct{})
	for _, area := range result.Areas {
		if !area.Detected {
			continue
		}
		for _, target := range area.Targets {
			for _, confidence := range target.Confidence {
				if math.IsNaN(confidence.Confidence) || math.IsInf(confidence.Confidence, 0) ||
					confidence.Confidence < 0 || confidence.Confidence > 1 {
					return nil, safediagnostic.Wrap(inspectionadapter.ErrInvalidResponse, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseExtractLabel, safediagnostic.ValidationConfidenceInvalid))
				}
				// Preserve the model label byte-for-byte. Normalizing here would
				// silently repair a non-contract response before the strict local
				// wrapper gets a chance to reject it.
				label := confidence.Label
				if label != "" {
					labels[label] = struct{}{}
				}
			}
		}
	}
	if len(labels) != 1 {
		return nil, safediagnostic.Wrap(inspectionadapter.ErrInvalidResponse, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseExtractLabel, safediagnostic.ValidationLabelCountInvalid))
	}
	for label := range labels {
		if len(label) < 2 || len(label) > temporary.MaxJSONBytes {
			return nil, safediagnostic.Wrap(inspectionadapter.ErrInvalidResponse, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseExtractLabel, safediagnostic.ValidationEncodingInvalid))
		}
		return []byte(label), nil
	}
	return nil, inspectionadapter.ErrInvalidResponse
}

const (
	temporaryUnableToJudge = "无法判断"
	temporaryAnswerYes     = "是"
	temporaryAnswerNo      = "否"
)

// temporaryCandidateJSON is the only bridge from model-owned text into the
// strict temporary Candidate contract. The model never supplies schema,
// evidence references, or JSON structure; those are constructed from trusted
// runtime values after the closed-vocabulary answer is projected through the
// existing Candidate text safety validation.
func temporaryCandidateJSON(raw []byte, evidenceRef, observable string) ([]byte, error) {
	answer, err := validateTemporaryModelAnswer(raw)
	if err != nil {
		return nil, errors.Join(inspectionadapter.ErrInvalidResponse, err)
	}
	candidate := temporary.Candidate{
		Schema:       temporary.CandidateSchemaVersion,
		VisibleFacts: []string{}, Limitations: []string{}, EvidenceRefs: []string{evidenceRef},
	}
	switch answer {
	case temporaryAnswerYes:
		candidate.Answer = temporary.AnswerYes
		candidate.Summary = "本次现场查看得到肯定结果"
		candidate.VisibleFacts = []string{temporaryPositiveFact(observable)}
	case temporaryAnswerNo:
		candidate.Answer = temporary.AnswerNo
		candidate.Summary = "本次现场查看暂未得到肯定结果"
		candidate.VisibleFacts = []string{temporaryNegativeFact(observable)}
	case temporaryUnableToJudge:
		candidate.Answer = temporary.AnswerUnable
		candidate.Summary = "当前画面暂时无法判断"
		candidate.Limitations = []string{"当前画面信息不足，暂时无法作出可靠判断"}
	}
	if err := candidate.Validate(); err != nil {
		return nil, safediagnostic.Wrap(errors.Join(inspectionadapter.ErrInvalidResponse, err), localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseBindCandidate, safediagnostic.ValidationInvalidResponse))
	}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return nil, safediagnostic.Wrap(errors.Join(inspectionadapter.ErrInvalidResponse, err), localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseBindCandidate, safediagnostic.ValidationEncodingInvalid))
	}
	return encoded, nil
}

func validateTemporaryModelAnswer(raw []byte) (string, error) {
	if len(raw) < 1 || len(raw) > len(temporaryUnableToJudge) || !utf8.Valid(raw) {
		return "", safediagnostic.Wrap(inspectionadapter.ErrInvalidResponse, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseValidateClosedVocabulary, safediagnostic.ValidationEncodingInvalid))
	}
	answer := string(raw)
	if strings.TrimSpace(answer) != answer || strings.ContainsAny(answer, "\r\n") {
		return "", safediagnostic.Wrap(inspectionadapter.ErrInvalidResponse, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseValidateClosedVocabulary, safediagnostic.ValidationNormalizationInvalid))
	}
	switch answer {
	case temporaryAnswerYes, temporaryAnswerNo, temporaryUnableToJudge:
		return answer, nil
	default:
		return "", safediagnostic.Wrap(inspectionadapter.ErrInvalidResponse, localDiagnostic(safediagnostic.OperationAnalysis, safediagnostic.PhaseValidateClosedVocabulary, safediagnostic.ValidationVocabularyInvalid))
	}
}

func temporaryPositiveFact(observable string) string {
	detailed := "针对“" + observable + "”，本次查看得到肯定结果"
	if utf8.RuneCountInString(detailed) <= temporary.MaxCandidateVisibleFactRunes {
		return detailed
	}
	return "本次查看得到肯定结果"
}

func temporaryNegativeFact(observable string) string {
	detailed := "针对“" + observable + "”，本次查看得到否定结果"
	if utf8.RuneCountInString(detailed) <= temporary.MaxCandidateVisibleFactRunes {
		return detailed
	}
	return "本次查看得到否定结果"
}

func timePointer(value time.Time) *time.Time {
	copyValue := value.UTC()
	return &copyValue
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

var (
	_ mediaprep.Acquirer    = (*liveTemporaryAcquirer)(nil)
	_ temporary.MediaReader = temporaryMediaReader{}
	_ temporary.Analyzer    = liveTemporaryAnalyzer{}
	_ temporaryVision       = (*vaultConnections)(nil)
)
