package inspectioneval

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const (
	maximumManifestJSONDepth = 32
	maximumLatencyMS         = 24 * 60 * 60 * 1000
	temporalIsolationWindow  = 24 * time.Hour
)

var (
	opaqueRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	timezonePattern  = regexp.MustCompile(`^(?:UTC|[A-Za-z_]+(?:/[A-Za-z0-9_+.-]+)+)$`)
	tenantPattern    = regexp.MustCompile(`^tenant_[a-f0-9]{16,64}$`)
	sitePattern      = regexp.MustCompile(`^site_[a-f0-9]{16,64}$`)
	sourcePattern    = regexp.MustCompile(`^source_[a-f0-9]{16,64}$`)
	groupPattern     = regexp.MustCompile(`^group_[a-f0-9]{16,64}$`)
	reviewerPattern  = regexp.MustCompile(`^reviewer_[a-f0-9]{16,64}$`)
	deliveryPattern  = regexp.MustCompile(`^delivery_[a-f0-9]{32}$`)
	digestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func (e *ValidationError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "v3 manifest validation failed"
	}
	const maximumRenderedIssues = 8
	limit := len(e.Issues)
	if limit > maximumRenderedIssues {
		limit = maximumRenderedIssues
	}
	parts := make([]string, 0, limit+1)
	for _, issue := range e.Issues[:limit] {
		location := "manifest"
		if issue.Line > 0 {
			location = fmt.Sprintf("line %d", issue.Line)
		}
		if issue.Field != "" {
			location += " field " + issue.Field
		}
		parts = append(parts, location+": "+issue.Message)
	}
	if len(e.Issues) > limit {
		parts = append(parts, fmt.Sprintf("%d more issue(s)", len(e.Issues)-limit))
	}
	return "v3 manifest validation failed: " + strings.Join(parts, "; ")
}

// Load strictly decodes a v3 JSONL projection. It rejects unknown fields,
// duplicate keys, case aliases, blank lines, oversized input, and trailing
// JSON values before metrics are calculated.
func Load(reader io.Reader) (Manifest, error) {
	if reader == nil {
		return Manifest{}, errors.New("v3 manifest reader is required")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), MaximumManifestLineBytes)
	records := make([]Record, 0)
	line := 0
	for scanner.Scan() {
		line++
		if len(records) >= MaximumManifestRecords {
			return Manifest{}, fmt.Errorf("v3 manifest exceeds %d records", MaximumManifestRecords)
		}
		raw := append([]byte(nil), scanner.Bytes()...)
		if len(strings.TrimSpace(string(raw))) == 0 {
			return Manifest{}, fmt.Errorf("line %d: blank lines are not allowed", line)
		}
		var record Record
		if err := strictjson.ValidateExactFields(raw, &record, maximumManifestJSONDepth); err != nil {
			return Manifest{}, fmt.Errorf("line %d: validate exact v3 JSON: %w", line, err)
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return Manifest{}, fmt.Errorf("line %d: decode v3 record: %w", line, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return Manifest{}, fmt.Errorf("line %d: multiple JSON values are not allowed", line)
		}
		record.sourceLine = line
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return Manifest{}, fmt.Errorf("read v3 manifest: %w", err)
	}
	manifest := Manifest{Records: records}
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Validate(manifest Manifest) error {
	issues := make([]Issue, 0)
	if len(manifest.Records) == 0 {
		issues = append(issues, Issue{Message: "at least one v3 record is required"})
	}
	if len(manifest.Records) > MaximumManifestRecords {
		issues = append(issues, Issue{Message: fmt.Sprintf("record count exceeds %d", MaximumManifestRecords)})
	}
	type origin struct {
		split       Split
		calibration CalibrationRole
		line        int
	}
	type criterionContract struct {
		schema string
		kind   ResultKind
		line   int
	}
	type deliveryOrigin struct {
		evidenceSHA256     string
		status             DeliveryStatus
		attempts           int
		reconciliation     int
		deliveryMS         float64
		feedbackSHA256     string
		feedbackHelpful    bool
		feedbackReceivedAt time.Time
		line               int
	}
	groups := make(map[string]origin)
	recordIDs := make(map[string]int)
	criteria := make(map[string]criterionContract)
	deliveries := make(map[string]deliveryOrigin)
	deliveryEvidence := make(map[string]struct {
		pseudonym string
		line      int
	})
	feedbackEvidence := make(map[string]struct {
		deliveryPseudonym string
		helpful           bool
		receivedAt        time.Time
		line              int
	})
	reviewIDs := make(map[string]int)
	reviewEvidence := make(map[string]int)
	siteZones := make(map[string]struct {
		zone string
		line int
	})
	temporal := make(map[string][]temporalRecord)
	for index, record := range manifest.Records {
		line := record.sourceLine
		if line == 0 {
			line = index + 1
		}
		issues = append(issues, validateRecord(record, line)...)
		if validOpaqueRef(record.RecordID) {
			if first, duplicate := recordIDs[record.RecordID]; duplicate {
				issues = append(issues, Issue{Line: line, Field: "recordId", Message: fmt.Sprintf("duplicates line %d", first)})
			} else {
				recordIDs[record.RecordID] = line
			}
		}
		if validOpaqueRef(record.CriterionID) && record.CriterionVersion > 0 && validOpaqueRef(record.ResultSchemaRef) && validResultKind(record.Expected.Kind) {
			key := fmt.Sprintf("%s\x00%d", record.CriterionID, record.CriterionVersion)
			if existing, ok := criteria[key]; ok {
				if existing.schema != record.ResultSchemaRef || existing.kind != record.Expected.Kind {
					issues = append(issues, Issue{Line: line, Field: "resultSchemaRef", Message: fmt.Sprintf("criterion contract differs from line %d", existing.line)})
				}
			} else {
				criteria[key] = criterionContract{schema: record.ResultSchemaRef, kind: record.Expected.Kind, line: line}
			}
		}
		if deliveryPattern.MatchString(record.DeliveryPseudonym) && digestPattern.MatchString(record.DeliveryEvidenceSHA256) {
			feedbackSHA256 := ""
			feedbackHelpful := false
			feedbackReceivedAt := time.Time{}
			if record.Feedback != nil {
				feedbackSHA256, feedbackHelpful, feedbackReceivedAt = record.Feedback.RecordSHA256, record.Feedback.Helpful, record.Feedback.ReceivedAt
			}
			candidate := deliveryOrigin{evidenceSHA256: record.DeliveryEvidenceSHA256, status: record.DeliveryStatus,
				attempts: record.DeliveryAttempts, reconciliation: record.ReconciliationAttempts, deliveryMS: record.Latencies.DeliveryMS,
				feedbackSHA256: feedbackSHA256, feedbackHelpful: feedbackHelpful, feedbackReceivedAt: feedbackReceivedAt, line: line}
			if existing, ok := deliveries[record.DeliveryPseudonym]; ok {
				if existing.evidenceSHA256 != candidate.evidenceSHA256 || existing.status != candidate.status ||
					existing.attempts != candidate.attempts || existing.reconciliation != candidate.reconciliation ||
					existing.deliveryMS != candidate.deliveryMS || existing.feedbackSHA256 != candidate.feedbackSHA256 ||
					existing.feedbackHelpful != candidate.feedbackHelpful || !existing.feedbackReceivedAt.Equal(candidate.feedbackReceivedAt) {
					issues = append(issues, Issue{Line: line, Field: "deliveryPseudonym", Message: fmt.Sprintf("delivery evidence differs from line %d", existing.line)})
				}
			} else {
				deliveries[record.DeliveryPseudonym] = candidate
			}
			if existing, ok := deliveryEvidence[record.DeliveryEvidenceSHA256]; ok && existing.pseudonym != record.DeliveryPseudonym {
				issues = append(issues, Issue{Line: line, Field: "deliveryEvidenceSha256", Message: fmt.Sprintf("is already bound to another delivery on line %d", existing.line)})
			} else if !ok {
				deliveryEvidence[record.DeliveryEvidenceSHA256] = struct {
					pseudonym string
					line      int
				}{record.DeliveryPseudonym, line}
			}
		}
		if record.Feedback != nil && digestPattern.MatchString(record.Feedback.RecordSHA256) {
			if existing, ok := feedbackEvidence[record.Feedback.RecordSHA256]; ok {
				if existing.deliveryPseudonym != record.DeliveryPseudonym || existing.helpful != record.Feedback.Helpful || !existing.receivedAt.Equal(record.Feedback.ReceivedAt) {
					issues = append(issues, Issue{Line: line, Field: "feedback", Message: fmt.Sprintf("feedback evidence differs from line %d", existing.line)})
				}
			} else {
				feedbackEvidence[record.Feedback.RecordSHA256] = struct {
					deliveryPseudonym string
					helpful           bool
					receivedAt        time.Time
					line              int
				}{record.DeliveryPseudonym, record.Feedback.Helpful, record.Feedback.ReceivedAt, line}
			}
		}
		if record.TemporaryReview != nil {
			if first, duplicate := reviewIDs[record.TemporaryReview.ReviewID]; duplicate {
				issues = append(issues, Issue{Line: line, Field: "temporaryReview.reviewId", Message: fmt.Sprintf("duplicates line %d", first)})
			} else {
				reviewIDs[record.TemporaryReview.ReviewID] = line
			}
			if first, duplicate := reviewEvidence[record.TemporaryReview.RecordSHA256]; duplicate {
				issues = append(issues, Issue{Line: line, Field: "temporaryReview.recordSha256", Message: fmt.Sprintf("duplicates line %d", first)})
			} else {
				reviewEvidence[record.TemporaryReview.RecordSHA256] = line
			}
		}
		if sitePattern.MatchString(record.SitePseudonym) && tenantPattern.MatchString(record.TenantPseudonym) {
			key := record.TenantPseudonym + "\x00" + record.SitePseudonym
			if existing, ok := siteZones[key]; ok && existing.zone != record.SiteTimezone {
				issues = append(issues, Issue{Line: line, Field: "siteTimezone", Message: fmt.Sprintf("differs from line %d", existing.line)})
			} else if !ok {
				siteZones[key] = struct {
					zone string
					line int
				}{zone: record.SiteTimezone, line: line}
			}
		}
		if groupPattern.MatchString(record.GroupKey) && validSplit(record.Split) {
			key := record.TenantPseudonym + "\x00" + record.SitePseudonym + "\x00" + record.GroupKey
			if existing, ok := groups[key]; ok {
				if existing.split != record.Split {
					issues = append(issues, Issue{Line: line, Field: "groupKey", Message: fmt.Sprintf("group crosses splits from line %d", existing.line)})
				}
				if existing.calibration != record.CalibrationRole {
					issues = append(issues, Issue{Line: line, Field: "calibrationRole", Message: fmt.Sprintf("group calibration role differs from line %d", existing.line)})
				}
			} else {
				groups[key] = origin{split: record.Split, calibration: record.CalibrationRole, line: line}
			}
		}
		if sourcePattern.MatchString(record.SourcePseudonym) && validSplit(record.Split) && !record.CapturedAt.IsZero() {
			key := record.TenantPseudonym + "\x00" + record.SitePseudonym + "\x00" + record.SourcePseudonym
			temporal[key] = append(temporal[key], temporalRecord{at: record.CapturedAt.UTC(), split: record.Split, line: line})
		}
	}
	if len(criteria) > MaximumCriteria {
		issues = append(issues, Issue{Field: "criterionId", Message: fmt.Sprintf("manifest exceeds %d distinct criteria", MaximumCriteria)})
	}
	issues = append(issues, validateTemporalIsolation(temporal)...)
	if len(issues) == 0 {
		return nil
	}
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Line != issues[j].Line {
			return issues[i].Line < issues[j].Line
		}
		return issues[i].Field < issues[j].Field
	})
	return &ValidationError{Issues: issues}
}

type temporalRecord struct {
	at    time.Time
	split Split
	line  int
}

func validateTemporalIsolation(groups map[string][]temporalRecord) []Issue {
	issues := make([]Issue, 0)
	for _, records := range groups {
		sort.Slice(records, func(i, j int) bool { return records[i].at.Before(records[j].at) })
		latest := make(map[Split]temporalRecord, 3)
		for _, record := range records {
			for _, split := range []Split{SplitTrain, SplitValidation, SplitTest} {
				if split == record.split {
					continue
				}
				if previous, ok := latest[split]; ok && record.at.Sub(previous.at) < temporalIsolationWindow {
					issues = append(issues, Issue{Line: record.line, Field: "capturedAt", Message: fmt.Sprintf("same-source observations within 24h cross splits from line %d", previous.line)})
				}
			}
			latest[record.split] = record
		}
	}
	return issues
}

func validateRecord(record Record, line int) []Issue {
	issues := make([]Issue, 0)
	add := func(field, message string) {
		issues = append(issues, Issue{Line: line, Field: field, Message: message})
	}
	if record.Schema != RecordSchema {
		add("schema", "must equal the v3 record schema")
	}
	if !validOpaqueRef(record.RecordID) {
		add("recordId", "must be an opaque identifier")
	}
	if !tenantPattern.MatchString(record.TenantPseudonym) {
		add("tenantPseudonym", "must be a keyed tenant pseudonym")
	}
	if !sitePattern.MatchString(record.SitePseudonym) {
		add("sitePseudonym", "must be a keyed site pseudonym")
	}
	if !sourcePattern.MatchString(record.SourcePseudonym) {
		add("sourcePseudonym", "must be a keyed source pseudonym")
	}
	if record.CapturedAt.IsZero() {
		add("capturedAt", "must be an RFC3339 timestamp")
	}
	if _, err := loadSiteLocation(record.SiteTimezone); err != nil {
		add("siteTimezone", err.Error())
	}
	if len(record.SceneStrata) == 0 || len(record.SceneStrata) > 32 {
		add("sceneStrata", "must contain one to 32 taxonomy strata")
	}
	previousScene := ""
	for _, value := range record.SceneStrata {
		if !validOpaqueRef(value) || value <= previousScene {
			add("sceneStrata", "must be canonical, unique opaque taxonomy strata")
			break
		}
		previousScene = value
	}
	if !validOpaqueRef(record.CriterionID) {
		add("criterionId", "must be an opaque criterion reference")
	}
	if record.CriterionVersion == 0 {
		add("criterionVersion", "must be positive")
	}
	if !validOpaqueRef(record.ResultSchemaRef) {
		add("resultSchemaRef", "must be an opaque schema reference")
	}
	if !validStrategy(record.Strategy) {
		add("strategy", "is unsupported")
	}
	if !validSourceKind(record.SourceKind) {
		add("sourceKind", "is unsupported")
	}
	if !validMediaKind(record.MediaKind) {
		add("mediaKind", "is unsupported")
	}
	if validStrategy(record.Strategy) && validSourceKind(record.SourceKind) && validMediaKind(record.MediaKind) &&
		!validStrategySourceMedia(record.Strategy, record.SourceKind, record.MediaKind, record.ObservationMode) {
		add("mediaKind", "does not match the strategy and source contract")
	}
	if !validSplit(record.Split) {
		add("split", "must be train, validation, or test")
	}
	if !groupPattern.MatchString(record.GroupKey) {
		add("groupKey", "must be a keyed group pseudonym")
	}
	if record.CalibrationRole != CalibrationNone && record.CalibrationRole != CalibrationThresholdFit {
		add("calibrationRole", "is unsupported")
	}
	if record.Split == SplitTest && record.CalibrationRole != CalibrationNone {
		add("calibrationRole", "test records cannot participate in threshold calibration")
	}
	if err := validateResultValue(record.Expected); err != nil {
		add("expected", err.Error())
	}
	if err := validateResultValue(record.Observed); err != nil {
		add("observed", err.Error())
	}
	if record.Expected.Kind != record.Observed.Kind {
		add("observed", "kind must equal expected kind")
	}
	if record.Expected.State == ValuePresent && record.Observed.State == ValuePresent {
		if record.Expected.Kind == ResultMetric && record.Expected.Metric != nil && record.Observed.Metric != nil && record.Expected.Metric.Unit != record.Observed.Metric.Unit {
			add("observed.metric.unit", "must equal expected unit")
		}
		if record.Expected.Kind == ResultEvent && record.Expected.Event != nil && record.Observed.Event != nil && record.Expected.Event.Type != record.Observed.Event.Type {
			add("observed.event.type", "must equal expected event type")
		}
	}
	switch record.ObservationMode {
	case ObservationStandard:
		if record.TemporaryReview != nil {
			add("temporaryReview", "standard observations must not contain temporary review")
		}
		if record.SourceKind == SourcePreparedObservation {
			add("sourceKind", "standard observations cannot use the temporary prepared source")
		}
	case ObservationTemporary:
		if err := validateTemporaryReview(record); err != nil {
			add("temporaryReview", err.Error())
		}
		if record.SourceKind != SourcePreparedObservation ||
			(record.Strategy != StrategySnapshotAnalysis && record.Strategy != StrategyClipAnalysis) {
			add("sourceKind", "temporary observations must use their derived prepared source and snapshot or clip strategy")
		}
	default:
		add("observationMode", "is unsupported")
	}
	if !validLatencies(record.Latencies) {
		add("latencies", "must be finite, bounded, and no component may exceed end-to-end latency")
	}
	if !deliveryPattern.MatchString(record.DeliveryPseudonym) {
		add("deliveryPseudonym", "must be a keyed delivery pseudonym")
	}
	if !digestPattern.MatchString(record.DeliveryEvidenceSHA256) {
		add("deliveryEvidenceSha256", "must be a canonical evidence digest")
	}
	if !validDeliveryStatus(record.DeliveryStatus) {
		add("deliveryStatus", "is unsupported")
	}
	if record.DeliveryAttempts < 1 || record.DeliveryAttempts > 8 ||
		record.ReconciliationAttempts < 0 || record.ReconciliationAttempts > 1_000_000 {
		add("deliveryAttempts", "delivery and reconciliation attempts must be bounded persisted counts")
	}
	if record.DeliveryStatus == DeliveryFailed && record.DeliveryAttempts != 8 {
		add("deliveryAttempts", "failed delivery must have exhausted the persisted attempt budget")
	}
	if record.Feedback != nil {
		if !digestPattern.MatchString(record.Feedback.RecordSHA256) || record.Feedback.ReceivedAt.IsZero() || record.Feedback.ReceivedAt.Before(record.CapturedAt) {
			add("feedback", "must contain a receipt time at or after capture")
		}
	}
	return issues
}

func validateTemporaryReview(record Record) error {
	review := record.TemporaryReview
	if review == nil || review.Schema != ReviewSchema || !validOpaqueRef(review.ReviewID) || !digestPattern.MatchString(review.RecordSHA256) || !reviewerPattern.MatchString(review.ReviewerPseudonym) ||
		review.ReviewedAt.IsZero() || review.ReviewedAt.Before(record.CapturedAt) || !validOpaqueRef(review.ReviewPolicyRef) {
		return errors.New("temporary observation requires a complete v3 review")
	}
	if validateResultValue(review.Adjudicated) != nil || review.Adjudicated.Kind != record.Observed.Kind {
		return errors.New("review adjudication must be a valid result of the observed kind")
	}
	if record.Expected.State == ValuePresent && review.Adjudicated.State == ValuePresent {
		if record.Expected.Kind == ResultMetric && record.Expected.Metric != nil && review.Adjudicated.Metric != nil && record.Expected.Metric.Unit != review.Adjudicated.Metric.Unit {
			return errors.New("review metric unit must equal expected unit")
		}
		if record.Expected.Kind == ResultEvent && record.Expected.Event != nil && review.Adjudicated.Event != nil && record.Expected.Event.Type != review.Adjudicated.Event.Type {
			return errors.New("review event type must equal expected event type")
		}
	}
	return nil
}

func validLatencies(value Latencies) bool {
	values := []float64{value.EndToEndMS, value.AnalysisMS, value.DeliveryMS}
	for _, sample := range values {
		if !finite(sample) || sample < 0 || sample > maximumLatencyMS {
			return false
		}
	}
	return value.AnalysisMS <= value.EndToEndMS && value.DeliveryMS <= value.EndToEndMS
}

func validOpaqueRef(value string) bool {
	if value != strings.TrimSpace(value) || !opaqueRefPattern.MatchString(value) || net.ParseIP(value) != nil {
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

func loadSiteLocation(value string) (*time.Location, error) {
	if value != strings.TrimSpace(value) || len(value) == 0 || len(value) > 64 || !timezonePattern.MatchString(value) || strings.Contains(value, "..") {
		return nil, errors.New("must be a canonical IANA timezone")
	}
	location, err := time.LoadLocation(value)
	if err != nil {
		return nil, errors.New("must name an available IANA timezone")
	}
	return location, nil
}

func validSplit(value Split) bool {
	return value == SplitTrain || value == SplitValidation || value == SplitTest
}

func validStrategy(value Strategy) bool {
	return value == StrategyExistingTaskRead || value == StrategySnapshotAnalysis || value == StrategyClipAnalysis || value == StrategyHybridAnalysis
}

func validSourceKind(value SourceKind) bool {
	switch value {
	case SourceCamera, SourceUploadedImage, SourceUploadedVideo, SourceTaskEvidence, SourceRetainedMedia, SourcePreparedObservation:
		return true
	default:
		return false
	}
}

func validMediaKind(value MediaKind) bool {
	switch value {
	case MediaImage, MediaFrameSet, MediaVideoClip, MediaMetric, MediaDetection, MediaEvent:
		return true
	default:
		return false
	}
}

func validDeliveryStatus(value DeliveryStatus) bool {
	return value == DeliveryDelivered || value == DeliveryUnknown || value == DeliveryFailed
}

func validStrategySourceMedia(strategy Strategy, source SourceKind, media MediaKind, mode ObservationMode) bool {
	if mode == ObservationTemporary {
		return source == SourcePreparedObservation &&
			(strategy == StrategySnapshotAnalysis && media == MediaImage || strategy == StrategyClipAnalysis && media == MediaVideoClip)
	}
	if source == SourcePreparedObservation {
		return false
	}
	sourceSupportsMedia := false
	switch source {
	case SourceCamera:
		sourceSupportsMedia = media == MediaImage || media == MediaFrameSet || media == MediaVideoClip
	case SourceUploadedImage:
		sourceSupportsMedia = media == MediaImage
	case SourceUploadedVideo:
		sourceSupportsMedia = media == MediaVideoClip
	case SourceTaskEvidence:
		sourceSupportsMedia = media == MediaImage || media == MediaMetric || media == MediaDetection || media == MediaEvent
	case SourceRetainedMedia:
		sourceSupportsMedia = media == MediaImage || media == MediaFrameSet || media == MediaVideoClip
	}
	if !sourceSupportsMedia {
		return false
	}
	switch strategy {
	case StrategyExistingTaskRead:
		return source == SourceTaskEvidence
	case StrategySnapshotAnalysis:
		return source == SourceCamera || source == SourceUploadedImage || source == SourceRetainedMedia
	case StrategyClipAnalysis:
		return source == SourceCamera || source == SourceUploadedVideo || source == SourceRetainedMedia
	case StrategyHybridAnalysis:
		return source != SourcePreparedObservation
	default:
		return false
	}
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
