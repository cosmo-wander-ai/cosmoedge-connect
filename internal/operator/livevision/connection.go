package livevision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

const (
	maxLiveJPEGBytes       = int64(16 << 20)
	maxPictureAlgorithms   = 64
	pictureAlgorithmPage   = 100
	maxPicturePages        = 10
	liveAnalysisPolicyRef  = "current-scene-vlm"
	pictureAlgorithmUsage  = "2"
	temporaryTaskMapLimit  = 256
	failedTaskCleanupLimit = 5 * time.Second
	classificationV2Schema = "classification.v2"
)

var (
	ErrPictureAlgorithmUnavailable = errors.New("live picture VLM algorithm is unavailable or ambiguous")
	ErrPictureVersionUnavailable   = errors.New("live picture VLM algorithm version is unavailable or ambiguous")
	updateTimePattern              = regexp.MustCompile(`^[0-9]{13}$`)
)

// NewVaultConnections exposes the already-authenticated foreground Vault as
// the exact ConnectionProvider required by the live inspection adapter. The
// returned provider keeps no endpoint, username, password, token, serial, or
// native locator. Every operation reacquires an identity-checked typed client
// from the Vault.
func NewVaultConnections(vault *session.Vault, options ...ConnectionOption) (inspectionadapter.ConnectionProvider, error) {
	if vault == nil {
		return nil, errors.New("live inspection connection vault is required")
	}
	p := &vaultConnections{vault: vault, now: time.Now, tasks: make(map[string]*temporaryPictureTask)}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("live vision option is invalid")
		}
		if err := option(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

type vaultConnections struct {
	vault           *session.Vault
	now             func() time.Time
	source          *SourceBinding
	taskJournal     TemporaryTaskJournal
	uploadJournal   TemporaryUploadJournal
	uploadOwnerHash string
	diagnosticRunID string
	diagnostics     TemporaryFailureRecorder

	mu    sync.Mutex
	tasks map[string]*temporaryPictureTask
}

func (*vaultConnections) String() string   { return "[live-inspection-connections]" }
func (*vaultConnections) GoString() string { return "inspectionlive.vaultConnections([redacted])" }
func (*vaultConnections) LogValue() slog.Value {
	return slog.StringValue("[live-inspection-connections]")
}

func (p *vaultConnections) LiveClient(ctx context.Context, tenantID, siteID, profileID string) (inspectionadapter.LiveClient, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if p == nil || p.vault == nil {
		return nil, inspectionadapter.ErrUnavailable
	}
	if tenantID != TenantID || siteID != SiteID || profileID != DeviceProfileID {
		return nil, inspectionadapter.ErrAuthorityRejected
	}
	if _, err := p.connection(ctx); err != nil {
		return nil, err
	}
	return &vaultLiveClient{owner: p, profileID: profileID}, nil
}

func (p *vaultConnections) connection(ctx context.Context) (session.InspectionConnection, error) {
	connection, err := p.vault.InspectionConnection(ctx)
	if err == nil && connection.Client() == nil {
		return session.InspectionConnection{}, inspectionadapter.ErrUnavailable
	}
	if err != nil {
		return session.InspectionConnection{}, sanitizeSessionError(err)
	}
	if p.source != nil && (p.source.DeviceIdentitySHA256 != "" && p.source.DeviceIdentitySHA256 != deviceIdentityDigest(connection.Snapshot()) || p.source.ConnectionEpoch != "" && p.source.ConnectionEpoch != connectionEpoch(connection)) {
		return session.InspectionConnection{}, inspectionadapter.ErrBindingStale
	}
	return connection, nil
}

type vaultLiveClient struct {
	owner     *vaultConnections
	profileID string
}

var _ inspectionadapter.LiveClient = (*vaultLiveClient)(nil)

func (*vaultLiveClient) String() string   { return "[live-inspection-client]" }
func (*vaultLiveClient) GoString() string { return "inspectionlive.vaultLiveClient([redacted])" }
func (*vaultLiveClient) LogValue() slog.Value {
	return slog.StringValue("[live-inspection-client]")
}

func (c *vaultLiveClient) Resolve(ctx context.Context, request inspectionadapter.LiveResolveRequest) (inspectionadapter.LiveResolveResult, error) {
	if err := c.validateRequest(ctx, request.RunID, request.StepID, request.DeviceProfileID, request.IdempotencyKey, request.Attempt, request.Deadline); err != nil {
		return inspectionadapter.LiveResolveResult{}, err
	}
	if len(request.Sources) != 1 || len(request.InstalledTasks) > 16 || request.Sources[0].SourceHandle != c.owner.sourceRef() {
		return inspectionadapter.LiveResolveResult{}, inspectionadapter.ErrBindingStale
	}
	connection, err := c.owner.connection(ctx)
	if err != nil {
		return inspectionadapter.LiveResolveResult{}, err
	}
	snapshot := connection.Snapshot()
	source := request.Sources[0]
	camera, locator, ok := verifiedCamera(snapshot, source)
	if !ok || !c.owner.matchesSource(camera, source.IdentityFingerprint) {
		return inspectionadapter.LiveResolveResult{}, inspectionadapter.ErrBindingStale
	}
	verifiedTasks := make([]inspectionadapter.VerifiedTask, 0, len(request.InstalledTasks))
	seenTasks := make(map[string]struct{}, len(request.InstalledTasks))
	for _, frozen := range request.InstalledTasks {
		if frozen.TaskID == "" || frozen.BindingFingerprint == "" || frozen.NativeLocator.Empty() {
			return inspectionadapter.LiveResolveResult{}, inspectionadapter.ErrBindingStale
		}
		if _, duplicate := seenTasks[frozen.TaskID]; duplicate {
			return inspectionadapter.LiveResolveResult{}, inspectionadapter.ErrBindingStale
		}
		seenTasks[frozen.TaskID] = struct{}{}
		if !currentTaskBinding(snapshot.Tasks, frozen.NativeLocator.Reveal(), camera.ID) {
			return inspectionadapter.LiveResolveResult{}, inspectionadapter.ErrBindingStale
		}
		verifiedTasks = append(verifiedTasks, inspectionadapter.VerifiedTask{
			TaskID: frozen.TaskID, BindingFingerprint: frozen.BindingFingerprint,
		})
	}
	_ = locator // The native locator is intentionally not retained or returned.
	return inspectionadapter.LiveResolveResult{
		Sources: []inspectionadapter.VerifiedSource{{
			SourceHandle: source.SourceHandle, IdentityFingerprint: source.IdentityFingerprint,
		}},
		Tasks: verifiedTasks,
	}, nil
}

func (c *vaultLiveClient) CaptureSnapshot(ctx context.Context, request inspectionadapter.SnapshotRequest) (inspectionadapter.SnapshotResponse, error) {
	if err := c.validateRequest(ctx, request.RunID, request.StepID, request.DeviceProfileID, request.IdempotencyKey, request.Attempt, request.Deadline); err != nil {
		return inspectionadapter.SnapshotResponse{}, err
	}
	if request.SourceHandle != c.owner.sourceRef() || request.NativeLocator.Empty() || request.SourceFingerprint == "" ||
		request.ROIRef != fullFrameROI || request.MaxBytes < 1 || request.MaxBytes > maxLiveJPEGBytes {
		return inspectionadapter.SnapshotResponse{}, inspectionadapter.ErrBindingStale
	}
	connection, err := c.owner.connection(ctx)
	if err != nil {
		return inspectionadapter.SnapshotResponse{}, err
	}
	snapshot := connection.Snapshot()
	camera, _, ok := currentCamera(snapshot, request.NativeLocator.Reveal(), request.SourceFingerprint)
	if !ok || !c.owner.matchesSource(camera, request.SourceFingerprint) {
		return inspectionadapter.SnapshotResponse{}, inspectionadapter.ErrBindingStale
	}
	picture, err := connection.Client().GetCameraPictureContext(ctx, camera.ID)
	if err != nil {
		return inspectionadapter.SnapshotResponse{}, sanitizeDeviceError(err)
	}
	jpeg, err := connection.Client().DownloadFreshCameraPictureJPEG(ctx, picture, request.MaxBytes)
	if errors.Is(err, adapter.ErrCachedPicture) {
		return inspectionadapter.SnapshotResponse{
			SourceFingerprint: request.SourceFingerprint,
			Freshness:         inspectionadapter.SnapshotCached,
			ObservedAt:        c.owner.now().UTC(),
		}, nil
	}
	if err != nil {
		return inspectionadapter.SnapshotResponse{}, sanitizeDeviceError(err)
	}
	if len(jpeg.Content) == 0 || int64(len(jpeg.Content)) > request.MaxBytes || jpeg.Width < 1 || jpeg.Height < 1 {
		return inspectionadapter.SnapshotResponse{}, inspectionadapter.ErrInvalidResponse
	}
	content := append([]byte(nil), jpeg.Content...)
	return inspectionadapter.SnapshotResponse{
		Content:           io.NopCloser(bytes.NewReader(content)),
		SourceFingerprint: request.SourceFingerprint,
		Freshness:         inspectionadapter.SnapshotFresh,
		ObservedAt:        c.owner.now().UTC(),
	}, nil
}

func (c *vaultLiveClient) ReadExistingEvidence(context.Context, inspectionadapter.ExistingEvidenceRequest) (inspectionadapter.ExistingEvidenceResponse, error) {
	return inspectionadapter.ExistingEvidenceResponse{}, inspectionadapter.ErrUnsupported
}

func (c *vaultLiveClient) Analyze(ctx context.Context, request inspectionadapter.AnalysisRequest) (inspectionadapter.AnalysisResponse, error) {
	if err := c.validateRequest(ctx, request.RunID, request.StepID, request.DeviceProfileID, request.IdempotencyKey, request.Attempt, request.Deadline); err != nil {
		return inspectionadapter.AnalysisResponse{}, err
	}
	if request.Method != inspection.MethodVLM || request.AnalysisPolicyRef != liveAnalysisPolicyRef ||
		request.Output.Mode != inspection.ResultClassification || request.Output.SchemaVersion != classificationV2Schema ||
		request.Output.Validate() != nil || len(request.Inputs) != 1 || request.MaxFrames < 1 ||
		request.MaxBytes < 1 || request.MaxBytes > maxLiveJPEGBytes || len(request.Prompt) < 1 || len(request.Prompt) > 2056 {
		return inspectionadapter.AnalysisResponse{}, inspectionadapter.ErrUnsupported
	}
	jpeg, ordinal, err := analysisJPEG(request)
	if err != nil {
		return inspectionadapter.AnalysisResponse{}, err
	}
	connection, err := c.owner.connection(ctx)
	if err != nil {
		return inspectionadapter.AnalysisResponse{}, err
	}
	selected, err := selectPictureAlgorithm(ctx, connection.Client(), connection.Snapshot())
	if err != nil {
		return inspectionadapter.AnalysisResponse{}, err
	}
	key := temporaryTaskKey(request)
	task := temporaryPictureTask{
		key: key, runID: request.RunID, taskID: runScopedTaskID(key),
		algorithmCode: selected.algorithmCode, updateTime: selected.updateTime,
		phase: temporaryTaskCreating,
	}
	if !c.owner.reserveTask(task) {
		return inspectionadapter.AnalysisResponse{}, inspectionadapter.ErrOutcomeUnknown
	}
	createErr := connection.Client().CreatePictureTaskContext(ctx, adapter.PictureTaskCreateRequest{
		TaskID: task.taskID, AlgorithmCode: task.algorithmCode, AlgorithmUpdateTime: task.updateTime,
	})
	if createErr != nil {
		mapped := sanitizeDeviceError(createErr)
		if errors.Is(mapped, inspectionadapter.ErrOutcomeUnknown) {
			c.owner.markTask(key, temporaryTaskCreationUnknown)
		} else {
			c.owner.forgetTask(key)
		}
		return inspectionadapter.AnalysisResponse{}, mapped
	}
	c.owner.markTask(key, temporaryTaskCreated)
	detected, detectErr := connection.Client().DetectPictureTaskContext(ctx, adapter.PictureTaskDetectRequest{
		TaskID: task.taskID, AlgorithmCode: task.algorithmCode, JPEG: jpeg,
		TaskConfig: adapter.PictureTaskConfig{Params: []adapter.PictureTaskParameter{
			{Key: "advanced_mode", Value: "1"},
			{Key: "generationStyle", Value: "strict"},
			{Key: "keywords", Value: request.Prompt},
		}},
	})
	if detectErr != nil {
		mapped := sanitizeDeviceError(detectErr)
		if cleanupErr := c.cancelFailedAnalysisTask(connection, task); cleanupErr != nil {
			return inspectionadapter.AnalysisResponse{}, errors.Join(mapped, cleanupErr, inspectionadapter.ErrOutcomeUnknown)
		}
		return inspectionadapter.AnalysisResponse{}, mapped
	}
	c.owner.markTask(key, temporaryTaskDetected)
	candidate, err := classificationCandidate(detected, request.Output)
	if err != nil {
		if cleanupErr := c.cancelFailedAnalysisTask(connection, task); cleanupErr != nil {
			return inspectionadapter.AnalysisResponse{}, errors.Join(err, cleanupErr, inspectionadapter.ErrOutcomeUnknown)
		}
		return inspectionadapter.AnalysisResponse{}, err
	}
	return inspectionadapter.AnalysisResponse{
		Candidate: candidate, EvidenceOrdinals: []int{ordinal}, ModelVersion: selected.modelVersion,
	}, nil
}

func (c *vaultLiveClient) cancelFailedAnalysisTask(connection session.InspectionConnection, task temporaryPictureTask) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), failedTaskCleanupLimit)
	defer cancel()
	if err := connection.Client().CancelPictureTaskContext(cleanupCtx, adapter.PictureTaskCancelRequest{
		TaskID: task.taskID, AlgorithmCode: task.algorithmCode,
	}); err != nil {
		return sanitizeDeviceError(err)
	}
	c.owner.forgetTask(task.key)
	return nil
}

func (c *vaultLiveClient) Cleanup(ctx context.Context, request inspectionadapter.LiveCleanupRequest) (inspectionadapter.LiveCleanupResponse, error) {
	if err := c.validateRequest(ctx, request.RunID, request.StepID, request.DeviceProfileID, request.IdempotencyKey, request.Attempt, request.Deadline); err != nil {
		return inspectionadapter.LiveCleanupResponse{}, err
	}
	items := make([]inspectionadapter.LiveCleanupItemResult, len(request.Inputs))
	analysisInputs := 0
	for index, input := range request.Inputs {
		if input.ValueRef == "" || (input.ProducerKind != inspection.StepAcquireMedia && input.ProducerKind != inspection.StepAnalyze) {
			return inspectionadapter.LiveCleanupResponse{}, inspectionadapter.ErrBindingStale
		}
		state := inspectionadapter.CleanupRemoved
		if input.ProducerKind == inspection.StepAnalyze {
			state = inspectionadapter.CleanupPending
			analysisInputs++
		}
		items[index] = inspectionadapter.LiveCleanupItemResult{ValueRef: input.ValueRef, State: state}
	}
	if analysisInputs == 0 {
		// Development assumption: snapshot acquisition retains no live device
		// handle in this bridge after its bounded response body is consumed.
		return inspectionadapter.LiveCleanupResponse{Items: items}, nil
	}
	tasks := c.owner.claimCleanup(request.RunID)
	if len(tasks) == 0 {
		return inspectionadapter.LiveCleanupResponse{Items: items}, nil
	}
	connection, err := c.owner.connection(ctx)
	if err != nil {
		// No cleanup can be proven without the exact live connection. Pending is
		// the truthful terminal report for this bridge, not an invented removal.
		return inspectionadapter.LiveCleanupResponse{Items: items}, nil
	}
	removedTasks := 0
	for _, task := range tasks {
		if err := contextError(ctx); err != nil {
			return inspectionadapter.LiveCleanupResponse{}, err
		}
		cancelErr := connection.Client().CancelPictureTaskContext(ctx, adapter.PictureTaskCancelRequest{
			TaskID: task.taskID, AlgorithmCode: task.algorithmCode,
		})
		if cancelErr == nil {
			removedTasks++
			c.owner.forgetTask(task.key)
		}
	}
	if removedTasks == analysisInputs && len(tasks) == analysisInputs {
		for index := range items {
			if request.Inputs[index].ProducerKind == inspection.StepAnalyze {
				items[index].State = inspectionadapter.CleanupRemoved
			}
		}
	}
	// Development assumption: a nil PTaskCancle business response is admitted
	// as removal so the first vertical slice can terminate. Authentication,
	// transport, decode, timeout, and device rejection remain pending and are
	// never replayed. Replace this with a typed task-status/absence query or a
	// trusted resource baseline before production hardening.
	return inspectionadapter.LiveCleanupResponse{Items: items}, nil
}

func (c *vaultLiveClient) validateRequest(
	ctx context.Context,
	runID, stepID, profileID, idempotencyKey string,
	attempt int,
	deadline time.Time,
) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if c == nil || c.owner == nil || c.owner.vault == nil || profileID != c.profileID || profileID != DeviceProfileID {
		return inspectionadapter.ErrAuthorityRejected
	}
	if runID == "" || stepID == "" || idempotencyKey == "" || attempt < 1 {
		return inspectionadapter.ErrBindingStale
	}
	if deadline.IsZero() || !c.owner.now().UTC().Before(deadline.UTC()) {
		return context.DeadlineExceeded
	}
	return nil
}

func verifiedCamera(snapshot device.Snapshot, source inspectionadapter.LiveSource) (device.Camera, string, bool) {
	if source.SourceHandle == "" || source.Kind != inspection.SourceCamera || source.NativeLocator.Empty() ||
		source.IdentityFingerprint == "" || len(source.CapabilityRefs) == 0 {
		return device.Camera{}, "", false
	}
	locator := source.NativeLocator.Reveal()
	camera, _, ok := currentCamera(snapshot, locator, source.IdentityFingerprint)
	return camera, locator, ok
}

func currentCamera(snapshot device.Snapshot, locator, fingerprint string) (device.Camera, string, bool) {
	if snapshot.Identity.Serial == "" || locator == "" || !digestPattern.MatchString(fingerprint) {
		return device.Camera{}, "", false
	}
	matches := 0
	var selected device.Camera
	for _, camera := range snapshot.Cameras {
		if camera.ID == locator {
			matches++
			selected = camera
		}
	}
	if matches != 1 || SourceFingerprint(snapshot, selected) != fingerprint {
		return device.Camera{}, "", false
	}
	return selected, locator, true
}

func currentTaskBinding(tasks []device.Task, locator, channelID string) bool {
	if locator == "" || channelID == "" {
		return false
	}
	matches := 0
	for _, task := range tasks {
		if task.ID == locator && task.ChannelID == channelID && task.AlgorithmID != "" {
			matches++
		}
	}
	return matches == 1
}

type selectedPictureAlgorithm struct {
	algorithmCode string
	updateTime    string
	modelVersion  string
	vlmNamed      bool
}

func selectPictureAlgorithm(ctx context.Context, client device.InspectionClient, snapshot device.Snapshot) (selectedPictureAlgorithm, error) {
	rows, err := pictureAlgorithms(ctx, client)
	if err != nil {
		return selectedPictureAlgorithm{}, err
	}
	bindings := make([]selectedPictureAlgorithm, 0, len(rows))
	for _, row := range rows {
		detail, detailErr := client.QueryAlgorithmLayoutDetailContext(ctx, row.AlgorithmID)
		if detailErr != nil {
			return selectedPictureAlgorithm{}, sanitizeDeviceError(detailErr)
		}
		binding, bindingErr := exactPictureVersion(row, detail)
		if bindingErr != nil {
			return selectedPictureAlgorithm{}, bindingErr
		}
		bindings = append(bindings, binding)
	}
	currentAlgorithms := make(map[string]struct{}, len(snapshot.Tasks))
	for _, task := range snapshot.Tasks {
		name := task.AlgorithmName + " " + task.DisplayName
		if task.AlgorithmID != "" && isVLMName(name) {
			currentAlgorithms[task.AlgorithmID] = struct{}{}
		}
	}
	current := make([]selectedPictureAlgorithm, 0, 1)
	for _, binding := range bindings {
		if _, ok := currentAlgorithms[binding.algorithmCode]; ok {
			current = append(current, binding)
		}
	}
	if len(current) == 1 {
		return current[0], nil
	}
	if len(current) > 1 {
		return selectedPictureAlgorithm{}, unsupportedAlgorithm(ErrPictureAlgorithmUnavailable)
	}
	named := make([]selectedPictureAlgorithm, 0, 1)
	for _, binding := range bindings {
		if binding.vlmNamed {
			named = append(named, binding)
		}
	}
	if len(named) != 1 {
		if len(named) == 0 && len(bindings) == 1 {
			// Some deployed devices expose a single valid picture algorithm with
			// an opaque display name such as "1". A sole usage=picture binding
			// with an exact active version is deterministic; multiple opaque
			// candidates remain ambiguous and fail closed.
			return bindings[0], nil
		}
		return selectedPictureAlgorithm{}, unsupportedAlgorithm(ErrPictureAlgorithmUnavailable)
	}
	return named[0], nil
}

func pictureAlgorithms(ctx context.Context, client device.InspectionClient) ([]adapter.PictureAlgorithm, error) {
	rows := make([]adapter.PictureAlgorithm, 0)
	seen := make(map[string]struct{})
	expectedTotal := -1
	for page := 1; page <= maxPicturePages; page++ {
		result, err := client.QueryPictureAlgorithmsContext(ctx, page, pictureAlgorithmPage)
		if err != nil {
			return nil, sanitizeDeviceError(err)
		}
		if expectedTotal < 0 {
			expectedTotal = result.Total
		} else if expectedTotal != result.Total {
			return nil, inspectionadapter.ErrInvalidResponse
		}
		for _, row := range result.Rows {
			if row.AlgorithmID == "" || row.AlgorithmUsage != pictureAlgorithmUsage {
				return nil, inspectionadapter.ErrInvalidResponse
			}
			if _, duplicate := seen[row.AlgorithmID]; duplicate {
				return nil, inspectionadapter.ErrInvalidResponse
			}
			seen[row.AlgorithmID] = struct{}{}
			rows = append(rows, row)
			if len(rows) > maxPictureAlgorithms {
				return nil, unsupportedAlgorithm(ErrPictureAlgorithmUnavailable)
			}
		}
		if len(rows) == expectedTotal {
			break
		}
		if len(result.Rows) == 0 || len(rows) > expectedTotal {
			return nil, inspectionadapter.ErrInvalidResponse
		}
	}
	if expectedTotal <= 0 || len(rows) != expectedTotal {
		return nil, unsupportedAlgorithm(ErrPictureAlgorithmUnavailable)
	}
	return rows, nil
}

func exactPictureVersion(row adapter.PictureAlgorithm, detail adapter.AlgorithmLayoutDetail) (selectedPictureAlgorithm, error) {
	if detail.AlgorithmCode == "" || detail.AlgorithmUsage != pictureAlgorithmUsage || detail.ConfigVersionID == "" {
		return selectedPictureAlgorithm{}, unsupportedAlgorithm(ErrPictureVersionUnavailable)
	}
	matches := 0
	var selected adapter.AlgorithmLayoutVersion
	for _, version := range detail.Versions {
		if version.ID == detail.ConfigVersionID {
			matches++
			selected = version
		}
	}
	if matches != 1 || selected.AlgorithmCode != detail.AlgorithmCode || !updateTimePattern.MatchString(selected.AlgorithmUpdateTime) {
		return selectedPictureAlgorithm{}, unsupportedAlgorithm(ErrPictureVersionUnavailable)
	}
	modelDigest := sha256.Sum256([]byte("cosmoedge.inspection.picture-model.v1\x00" + detail.AlgorithmCode + "\x00" + selected.AlgorithmUpdateTime))
	name := strings.ToLower(strings.Join([]string{
		row.AlgorithmName, row.AlgorithmCategory, row.CategoryName, detail.AlgorithmName,
	}, " "))
	return selectedPictureAlgorithm{
		algorithmCode: detail.AlgorithmCode,
		updateTime:    selected.AlgorithmUpdateTime,
		modelVersion:  "picture-vlm-" + hex.EncodeToString(modelDigest[:])[:16],
		vlmNamed:      isVLMName(name),
	}, nil
}

func isVLMName(value string) bool {
	normalized := strings.ToLower(value)
	for _, marker := range []string{"vlm", "视觉语言", "语言视觉", "vision language"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func analysisJPEG(request inspectionadapter.AnalysisRequest) ([]byte, int, error) {
	input := request.Inputs[0]
	descriptor := input.Descriptor
	if input.Ordinal != 1 || input.Content == nil || descriptor.Kind != media.KindImage ||
		descriptor.Encoding.MIMEType != "image/jpeg" || descriptor.Encoding.Container != "jpeg" ||
		descriptor.Encoding.Codec != "jpeg" || descriptor.Integrity.SizeBytes < 1 ||
		descriptor.Integrity.SizeBytes > request.MaxBytes || !digestPattern.MatchString(descriptor.Integrity.SHA256) {
		return nil, 0, inspectionadapter.ErrBindingStale
	}
	content, err := io.ReadAll(io.LimitReader(input.Content, request.MaxBytes+1))
	if err != nil {
		return nil, 0, inspectionadapter.ErrInvalidResponse
	}
	if int64(len(content)) != descriptor.Integrity.SizeBytes || int64(len(content)) > request.MaxBytes {
		return nil, 0, inspectionadapter.ErrInvalidResponse
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != descriptor.Integrity.SHA256 {
		return nil, 0, inspectionadapter.ErrInvalidResponse
	}
	return content, input.Ordinal, nil
}

func classificationCandidate(result adapter.PictureTaskDetectResult, output inspection.OutputContract) (analysiscontract.Candidate, error) {
	assessment, score, err := classifyPictureResult(result, output.AllowedAssessments)
	if err != nil {
		return analysiscontract.Candidate{}, err
	}
	candidate := analysiscontract.Candidate{
		Assessment: assessment, Confidence: score, EvidenceRefs: []string{},
		Limitations: []analysiscontract.Limitation{},
	}
	switch assessment {
	case inspection.AssessmentNeedsAttention:
		candidate.Observability = inspection.ResultFullyVisible
		candidate.Value = &inspection.ResultValue{
			Kind:           inspection.ResultClassification,
			Classification: &inspection.ClassificationValue{Label: "attention", Score: score},
		}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionViolated}
	case inspection.AssessmentMeetsRule:
		candidate.Observability = inspection.ResultFullyVisible
		candidate.Value = &inspection.ResultValue{
			Kind:           inspection.ResultClassification,
			Classification: &inspection.ClassificationValue{Label: "condition_met", Score: score},
		}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionMet}
	case inspection.AssessmentUncertain:
		candidate.Observability = inspection.ResultPartiallyVisible
		candidate.Limitations = []analysiscontract.Limitation{analysiscontract.LimitationAnalyzerLimit}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonInsufficientEvidence}
	case inspection.AssessmentNotObservable:
		candidate.Observability = inspection.ResultNotVisible
		candidate.Limitations = []analysiscontract.Limitation{analysiscontract.LimitationOutOfFrame}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonNotVisible}
	case inspection.AssessmentUnsupported:
		candidate.Observability = inspection.ResultUnusable
		candidate.Limitations = []analysiscontract.Limitation{analysiscontract.LimitationAnalyzerLimit}
		candidate.ReasonCodes = []analysiscontract.ReasonCode{analysiscontract.ReasonUnsupportedCriterion}
	default:
		return analysiscontract.Candidate{}, inspectionadapter.ErrInvalidResponse
	}
	return candidate, nil
}

func classifyPictureResult(
	result adapter.PictureTaskDetectResult,
	allowed []inspection.Assessment,
) (inspection.Assessment, *float64, error) {
	if len(result.Areas) == 0 {
		return "", nil, inspectionadapter.ErrInvalidResponse
	}
	decisions := make(map[inspection.Assessment]struct{})
	var minimumScore *float64
	allObservable := true
	for _, area := range result.Areas {
		if !area.Detected {
			allObservable = false
			continue
		}
		for _, target := range area.Targets {
			for _, classification := range target.Confidence {
				if math.IsNaN(classification.Confidence) || math.IsInf(classification.Confidence, 0) ||
					classification.Confidence < 0 || classification.Confidence > 1 {
					return "", nil, inspectionadapter.ErrInvalidResponse
				}
				if strings.TrimSpace(classification.Label) == "" {
					continue
				}
				assessment, mapErr := assessmentForLabel(classification.Label, allowed)
				if mapErr != nil {
					decisions[inspection.AssessmentUncertain] = struct{}{}
				} else {
					decisions[assessment] = struct{}{}
				}
				if minimumScore == nil || classification.Confidence < *minimumScore {
					score := classification.Confidence
					minimumScore = &score
				}
			}
		}
	}
	if !allObservable {
		if containsAssessment(allowed, inspection.AssessmentNotObservable) {
			decisions[inspection.AssessmentNotObservable] = struct{}{}
		} else {
			decisions[inspection.AssessmentUncertain] = struct{}{}
		}
	}
	if len(decisions) == 1 {
		for decision := range decisions {
			if containsAssessment(allowed, decision) {
				return decision, minimumScore, nil
			}
		}
	}
	if containsAssessment(allowed, inspection.AssessmentUncertain) {
		return inspection.AssessmentUncertain, minimumScore, nil
	}
	return "", nil, inspectionadapter.ErrInvalidResponse
}

func assessmentForLabel(label string, allowed []inspection.Assessment) (inspection.Assessment, error) {
	normalized := strings.ToLower(strings.TrimSpace(label))
	var assessment inspection.Assessment
	switch normalized {
	case "是", "有", "yes", "true", "attention", "needs_attention":
		assessment = inspection.AssessmentNeedsAttention
	case "否", "没有", "无", "no", "false", "clear", "meets_rule":
		if containsAssessment(allowed, inspection.AssessmentMeetsRule) {
			assessment = inspection.AssessmentMeetsRule
		} else {
			// A negative answer is not upgraded into an all-clear when the frozen
			// output policy intentionally disallows meets_rule.
			assessment = inspection.AssessmentUncertain
		}
	case "不确定", "无法判断", "uncertain", "unknown":
		assessment = inspection.AssessmentUncertain
	case "不可见", "无法观察", "not_observable":
		assessment = inspection.AssessmentNotObservable
	case "不支持", "unsupported":
		assessment = inspection.AssessmentUnsupported
	default:
		return "", inspectionadapter.ErrInvalidResponse
	}
	if !containsAssessment(allowed, assessment) {
		return "", inspectionadapter.ErrInvalidResponse
	}
	return assessment, nil
}

func containsAssessment(values []inspection.Assessment, wanted inspection.Assessment) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type temporaryTaskPhase uint8

const (
	temporaryTaskCreating temporaryTaskPhase = iota + 1
	temporaryTaskCreationUnknown
	temporaryTaskCreated
	temporaryTaskDetected
)

type temporaryPictureTask struct {
	key           string
	runID         string
	taskID        string
	algorithmCode string
	updateTime    string
	phase         temporaryTaskPhase
	cancelClaimed bool
}

func (p *vaultConnections) reserveTask(task temporaryPictureTask) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.tasks) >= temporaryTaskMapLimit {
		return false
	}
	if _, exists := p.tasks[task.key]; exists {
		return false
	}
	copyTask := task
	p.tasks[task.key] = &copyTask
	return true
}

func (p *vaultConnections) markTask(key string, phase temporaryTaskPhase) {
	p.mu.Lock()
	if task := p.tasks[key]; task != nil {
		task.phase = phase
	}
	p.mu.Unlock()
}

func (p *vaultConnections) forgetTask(key string) {
	p.mu.Lock()
	delete(p.tasks, key)
	p.mu.Unlock()
}

func (p *vaultConnections) claimCleanup(runID string) []temporaryPictureTask {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]temporaryPictureTask, 0)
	for _, task := range p.tasks {
		if task.runID != runID || task.cancelClaimed || task.phase == temporaryTaskCreating {
			continue
		}
		task.cancelClaimed = true
		result = append(result, *task)
	}
	return result
}

func temporaryTaskKey(request inspectionadapter.AnalysisRequest) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		"cosmoedge.inspection.temporary-picture.v1", request.RunID, request.StepID,
		fmt.Sprint(request.Attempt), request.IdempotencyKey,
	}, "\x00")))
	return hex.EncodeToString(digest[:])
}

func runScopedTaskID(key string) string {
	digest := sha256.Sum256([]byte("cosmoedge.inspection.picture-task-id.v1\x00" + key))
	return "inspection-" + hex.EncodeToString(digest[:])[:32]
}

func unsupportedAlgorithm(gap error) error {
	return errors.Join(inspectionadapter.ErrUnsupported, gap)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return inspectionadapter.ErrUnavailable
	}
	return ctx.Err()
}

func sanitizeSessionError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, session.ErrIdentityDrift):
		return inspectionadapter.ErrBindingStale
	case errors.Is(err, session.ErrInspectionUnsupported):
		return inspectionadapter.ErrUnsupported
	default:
		return inspectionadapter.ErrUnavailable
	}
}

func sanitizeDeviceError(err error) (sanitized error) {
	defer func() {
		if diagnostic := safediagnostic.FromError(err); diagnostic != nil {
			sanitized = safediagnostic.Wrap(sanitized, *diagnostic)
		}
	}()
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var unknown interface{ OutcomeUnknown() bool }
	if errors.As(err, &unknown) && unknown.OutcomeUnknown() {
		return inspectionadapter.ErrOutcomeUnknown
	}
	var rejected interface{ AuthenticationRejected() bool }
	if errors.As(err, &rejected) && rejected.AuthenticationRejected() {
		return inspectionadapter.ErrAuthorityRejected
	}
	switch {
	case errors.Is(err, adapter.ErrInvalidInspectionRequest):
		return inspectionadapter.ErrBindingStale
	case errors.Is(err, adapter.ErrInvalidInspectionResponse), errors.Is(err, adapter.ErrUnsafePictureReference),
		errors.Is(err, adapter.ErrPictureRedirect), errors.Is(err, adapter.ErrPictureTooLarge),
		errors.Is(err, adapter.ErrInvalidPictureJPEG):
		return inspectionadapter.ErrInvalidResponse
	}
	var known interface{ KnownFailure() bool }
	if errors.As(err, &known) && known.KnownFailure() {
		return inspectionadapter.ErrUnsupported
	}
	return inspectionadapter.ErrUnavailable
}
