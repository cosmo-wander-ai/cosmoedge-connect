package inspectionadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
)

const (
	DefaultAdapterVersion = "cosmoedge-live-v1"
	defaultCaptureBytes   = int64(16 << 20)
)

var (
	opaquePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Config struct {
	Catalog            *catalog.Store
	Media              *media.Store
	Connections        ConnectionProvider
	Records            RecordStore
	AdapterVersion     string
	PrivacyClass       string
	RetentionPolicyRef string
	Audience           []string
	MaxCaptureBytes    int64
	Now                func() time.Time
}

type Adapter struct {
	catalog            *catalog.Store
	media              *media.Store
	connections        ConnectionProvider
	records            RecordStore
	adapterVersion     string
	privacyClass       string
	retentionPolicyRef string
	audience           []string
	maxCaptureBytes    int64
	now                func() time.Time
}

func New(config Config) (*Adapter, error) {
	if config.Catalog == nil || config.Media == nil || config.Connections == nil || config.Records == nil {
		return nil, errors.New("catalog, media store, live connection provider, and durable record store are required")
	}
	if config.AdapterVersion == "" {
		config.AdapterVersion = DefaultAdapterVersion
	}
	if !validOpaque(config.AdapterVersion) {
		return nil, errors.New("inspection adapter version is invalid")
	}
	switch config.PrivacyClass {
	case "public", "internal", "sensitive", "restricted":
	default:
		return nil, errors.New("inspection adapter privacy class is invalid")
	}
	if !validOpaque(config.RetentionPolicyRef) {
		return nil, errors.New("inspection adapter retention policy is invalid")
	}
	audience := append([]string(nil), config.Audience...)
	sort.Strings(audience)
	if len(audience) == 0 || len(audience) > 16 {
		return nil, errors.New("inspection adapter audience is required and bounded")
	}
	for index, value := range audience {
		if !validOpaque(value) || index > 0 && audience[index-1] == value {
			return nil, errors.New("inspection adapter audience is invalid")
		}
	}
	if config.MaxCaptureBytes == 0 {
		config.MaxCaptureBytes = defaultCaptureBytes
	}
	if config.MaxCaptureBytes < 1 {
		return nil, errors.New("inspection adapter capture limit must be positive")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Adapter{
		catalog: config.Catalog, media: config.Media, connections: config.Connections, records: config.Records,
		adapterVersion: config.AdapterVersion, privacyClass: config.PrivacyClass,
		retentionPolicyRef: config.RetentionPolicyRef, audience: audience,
		maxCaptureBytes: config.MaxCaptureBytes, now: config.Now,
	}, nil
}

func (a *Adapter) Ports() inspectionruntime.Ports {
	return inspectionruntime.Ports{
		Sources: a, Existing: existingPort{adapter: a}, Acquisition: a,
		Transform: a, Analysis: analysisPort{adapter: a}, Cleanup: a,
	}
}

type existingPort struct{ adapter *Adapter }

func (p existingPort) Read(ctx context.Context, request inspectionruntime.ExistingEvidenceRequest) (inspectionruntime.ExistingEvidenceResult, error) {
	return p.adapter.readExisting(ctx, request)
}

func (p existingPort) Result(ctx context.Context, ref string) (inspectionruntime.ExistingEvidenceResult, error) {
	return p.adapter.existingResult(ctx, ref)
}

type analysisPort struct{ adapter *Adapter }

func (p analysisPort) Analyze(ctx context.Context, request inspectionruntime.AnalyzeRequest) (inspectionruntime.AnalysisReference, error) {
	return p.adapter.analyze(ctx, request)
}

func (p analysisPort) Result(ctx context.Context, ref string) (inspectionruntime.AnalysisReference, error) {
	return p.adapter.analysisResult(ctx, ref)
}

// Transform is deliberately not implemented by the snapshot-first vertical
// slice. Clip/frame extraction must be added as a real bounded implementation;
// it may never fall back to fixtures or silently analyze an untransformed clip.
func (a *Adapter) Transform(context.Context, inspectionruntime.MediaTransformRequest) (inspectionruntime.MediaTransformResult, error) {
	return inspectionruntime.MediaTransformResult{}, inspectionruntime.ErrUnsupported
}

func (a *Adapter) Describe(ctx context.Context, mediaRef string) (media.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return media.Descriptor{}, err
	}
	return a.media.Describe(mediaRef)
}

func (a *Adapter) client(ctx context.Context, tenantID, siteID, deviceProfileID string) (LiveClient, error) {
	client, err := a.connections.LiveClient(ctx, tenantID, siteID, deviceProfileID)
	if err != nil {
		return nil, mapClientError(err)
	}
	if client == nil {
		return nil, inspectionruntime.ErrWaitingForSite
	}
	return client, nil
}

func mapClientError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrUnavailable):
		return inspectionruntime.ErrWaitingForSite
	case errors.Is(err, ErrBindingStale):
		return inspectionruntime.ErrBindingStale
	case errors.Is(err, ErrResourceBusy):
		return inspectionruntime.ErrResourceBusy
	case errors.Is(err, ErrOutcomeUnknown):
		return inspectionruntime.ErrOutcomeUnknown
	case errors.Is(err, ErrUnsupported):
		return inspectionruntime.ErrUnsupported
	case errors.Is(err, ErrAuthorityRejected):
		return inspectionruntime.ErrAuthorityRejected
	default:
		return err
	}
}

func validOpaque(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !opaquePattern.MatchString(value) || net.ParseIP(value) != nil {
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"http:", "https:", "rtsp:", "rtsps:", "file:", "data:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func canonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func deterministicRef(prefix string, values ...string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("cosmoedge.inspection.adapter.v1\x00" + prefix))
	for _, value := range values {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(value))
	}
	return prefix + "_" + hex.EncodeToString(digest.Sum(nil))[:32]
}

func operationKey(prefix string, values ...string) string {
	return deterministicRef(prefix, values...)
}

func mediaPutKey(value string) string {
	digest := sha256.Sum256([]byte("cosmoedge.inspection.adapter.media.v1\x00" + value))
	return "media_put_" + hex.EncodeToString(digest[:])
}

func contentSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func requestDeadline(now time.Time, deadline time.Time) error {
	if deadline.IsZero() || !now.UTC().Before(deadline.UTC()) {
		return context.DeadlineExceeded
	}
	return nil
}

func sameResolution(left, right ResolutionRecord) bool {
	return reflect.DeepEqual(left, right)
}

func sameAcquisition(left, right AcquisitionRecord) bool {
	return reflect.DeepEqual(left, right)
}

func sameExisting(left, right ExistingRecord) bool {
	return reflect.DeepEqual(left, right)
}

func sameAnalysis(left, right AnalysisRecord) bool {
	return reflect.DeepEqual(left, right)
}

func (a *Adapter) persistResolution(ctx context.Context, record ResolutionRecord) error {
	if err := a.records.PutResolution(ctx, record); err != nil {
		return fmt.Errorf("persist live resolution: %w", err)
	}
	stored, err := a.records.Resolution(ctx, record.ResolutionRef)
	if err != nil || !sameResolution(stored, record) {
		return errors.New("durable live resolution cannot be verified")
	}
	return nil
}

func (a *Adapter) persistAcquisition(ctx context.Context, record AcquisitionRecord) error {
	if err := a.records.PutAcquisition(ctx, record); err != nil {
		return fmt.Errorf("persist live acquisition: %w", err)
	}
	stored, err := a.records.Acquisition(ctx, record.IdempotencyKey)
	if err != nil || !sameAcquisition(stored, record) {
		return errors.New("durable live acquisition cannot be verified")
	}
	return nil
}

func (a *Adapter) persistExisting(ctx context.Context, record ExistingRecord) error {
	if err := a.records.PutExisting(ctx, record); err != nil {
		return fmt.Errorf("persist live existing evidence: %w", err)
	}
	stored, err := a.records.Existing(ctx, record.Result.EvidenceRef)
	if err != nil || !sameExisting(stored, record) {
		return errors.New("durable live existing evidence cannot be verified")
	}
	return nil
}

func (a *Adapter) persistAnalysis(ctx context.Context, record AnalysisRecord) error {
	if err := a.records.PutAnalysis(ctx, record); err != nil {
		return fmt.Errorf("persist live analysis: %w", err)
	}
	stored, err := a.records.Analysis(ctx, record.Result.ResultRef)
	if err != nil || !sameAnalysis(stored, record) {
		return errors.New("durable live analysis cannot be verified")
	}
	return nil
}

func (a *Adapter) completeCleanup(ctx context.Context, record CleanupRecord) error {
	if err := a.records.CompleteCleanup(ctx, record); err != nil {
		return fmt.Errorf("complete durable live cleanup: %w", err)
	}
	stored, err := a.records.Cleanup(ctx, record.IdempotencyKey)
	if err != nil || !reflect.DeepEqual(stored, record) {
		return errors.New("durable live cleanup cannot be verified")
	}
	return nil
}

func cloneSourceBinding(value inspection.SourceBinding) inspection.SourceBinding {
	value.CapabilityRefs = append([]string(nil), value.CapabilityRefs...)
	value.MediaKinds = append([]inspection.MediaKind(nil), value.MediaKinds...)
	return value
}

func cloneTaskBinding(value inspection.InstalledTaskBinding) inspection.InstalledTaskBinding {
	value.Sources = append([]inspection.InstalledTaskSourceBinding(nil), value.Sources...)
	value.Capabilities = append([]inspection.InstalledTaskCapabilityBinding(nil), value.Capabilities...)
	for index := range value.Capabilities {
		value.Capabilities[index].MediaKinds = append([]inspection.MediaKind(nil), value.Capabilities[index].MediaKinds...)
	}
	return value
}

func cloneCandidate(value analysiscontract.Candidate) analysiscontract.Candidate {
	if value.Confidence != nil {
		confidence := *value.Confidence
		value.Confidence = &confidence
	}
	if value.Value != nil {
		raw, err := json.Marshal(value.Value)
		if err == nil {
			var copied inspection.ResultValue
			if json.Unmarshal(raw, &copied) == nil {
				value.Value = &copied
			}
		}
	}
	if value.EvidenceRefs != nil {
		value.EvidenceRefs = append([]string{}, value.EvidenceRefs...)
	}
	if value.Limitations != nil {
		value.Limitations = append([]analysiscontract.Limitation{}, value.Limitations...)
	}
	if value.ReasonCodes != nil {
		value.ReasonCodes = append([]analysiscontract.ReasonCode{}, value.ReasonCodes...)
	}
	return value
}

func bindCandidate(candidate analysiscontract.Candidate, ordinals []int, descriptors []media.Descriptor) (analysiscontract.Candidate, error) {
	if len(candidate.EvidenceRefs) != 0 {
		return analysiscontract.Candidate{}, errors.New("live result attempted to supply trusted evidence references")
	}
	if len(ordinals) > len(descriptors) || len(ordinals) > 16 {
		return analysiscontract.Candidate{}, ErrInvalidResponse
	}
	refs := make([]string, 0, len(ordinals))
	seen := make(map[int]struct{}, len(ordinals))
	for _, ordinal := range ordinals {
		if ordinal < 1 || ordinal > len(descriptors) {
			return analysiscontract.Candidate{}, ErrInvalidResponse
		}
		if _, duplicate := seen[ordinal]; duplicate {
			return analysiscontract.Candidate{}, ErrInvalidResponse
		}
		seen[ordinal] = struct{}{}
		refs = append(refs, descriptors[ordinal-1].MediaRef)
	}
	candidate = cloneCandidate(candidate)
	candidate.EvidenceRefs = refs
	if err := candidate.Validate(); err != nil {
		return analysiscontract.Candidate{}, errors.Join(ErrInvalidResponse, err)
	}
	return candidate, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsMediaKind(values []inspection.MediaKind, expected inspection.MediaKind) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }
