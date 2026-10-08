package mediaprep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const (
	maximumEvidenceTTL      = 30 * 24 * time.Hour
	maximumWindow           = 24 * time.Hour
	maximumCaptureClockSkew = 2 * time.Minute
)

var (
	refPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	mediaRefPattern    = regexp.MustCompile(`^media_[a-f0-9]{32}$`)
	preparationPattern = regexp.MustCompile(`^media_prep_[a-f0-9]{32}$`)
	operationPattern   = regexp.MustCompile(`^media_acquire_[a-f0-9]{64}$`)
	putKeyPattern      = regexp.MustCompile(`^media_put_[a-f0-9]{64}$`)
	unsafeLocator      = regexp.MustCompile(`(?i)(?:https?|rtsps?|file)://|(?:password|passwd|token|secret|credential|authorization)=`)
)

// persistedRequest exists so the protected public request never needs a
// serialization escape hatch.
type persistedRequest struct {
	Schema             string    `json:"schema"`
	TenantID           string    `json:"tenantId"`
	SiteID             string    `json:"siteId"`
	RequestID          string    `json:"requestId"`
	SourceRef          string    `json:"sourceRef"`
	CapabilityRef      string    `json:"capabilityRef"`
	TimeScope          TimeScope `json:"timeScope"`
	AudienceBindingRef string    `json:"audienceBindingRef"`
	AudienceSHA256     string    `json:"audienceSha256"`
	EvidenceExpiresAt  time.Time `json:"evidenceExpiresAt"`
	Media              MediaSpec `json:"media"`
}

type persistedActualMedia struct {
	Encoding media.Encoding `json:"encoding"`
	Temporal media.Temporal `json:"temporal"`
}

// PreparationRefForScope returns the sole durable preparation identity for an
// authenticated request scope. Higher layers use this helper instead of
// duplicating the identity algorithm.
func PreparationRefForScope(tenantID, siteID, requestID string) (string, error) {
	if !validRef(tenantID) || !validRef(siteID) || !validRef(requestID) {
		return "", ErrInvalid
	}
	identity := strings.Join([]string{tenantID, siteID, requestID}, "\x00")
	return "media_prep_" + shaHex([]byte("preparation\x00" + identity))[:32], nil
}

func canonicalRequest(request FrozenRequest) (persistedRequest, string, string, string, error) {
	if request.TimeScope.WindowStart.Location() != time.UTC || request.TimeScope.WindowEnd.Location() != time.UTC ||
		request.EvidenceExpiresAt.Location() != time.UTC {
		return persistedRequest{}, "", "", "", ErrInvalid
	}
	value := persistedRequest{
		Schema: request.Schema, TenantID: request.TenantID, SiteID: request.SiteID,
		RequestID: request.RequestID, SourceRef: request.SourceRef, CapabilityRef: request.CapabilityRef,
		TimeScope: request.TimeScope, AudienceBindingRef: request.AudienceBindingRef,
		AudienceSHA256: request.AudienceSHA256, EvidenceExpiresAt: request.EvidenceExpiresAt, Media: request.Media,
	}
	value.TimeScope.WindowStart = value.TimeScope.WindowStart.UTC()
	value.TimeScope.WindowEnd = value.TimeScope.WindowEnd.UTC()
	value.EvidenceExpiresAt = value.EvidenceExpiresAt.UTC()
	if err := validatePersistedRequest(value); err != nil {
		return persistedRequest{}, "", "", "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return persistedRequest{}, "", "", "", ErrInvalid
	}
	digest := shaHex(raw)
	preparationRef, err := PreparationRefForScope(value.TenantID, value.SiteID, value.RequestID)
	if err != nil {
		return persistedRequest{}, "", "", "", err
	}
	operationKey := "media_acquire_" + shaHex([]byte("acquisition\x00"+digest))
	putKey := "media_put_" + shaHex([]byte("publication\x00"+preparationRef))
	return value, digest, operationKey, putKey, nil
}

func validatePersistedRequest(value persistedRequest) error {
	if value.Schema != RequestSchema || !validRef(value.TenantID) || !validRef(value.SiteID) ||
		!validRef(value.RequestID) || !validSourceRef(value.SourceRef) || !validRef(value.CapabilityRef) ||
		value.TimeScope.WindowStart.IsZero() || value.TimeScope.WindowEnd.IsZero() ||
		value.TimeScope.WindowStart.Location() != time.UTC ||
		value.TimeScope.WindowEnd.Location() != time.UTC ||
		value.TimeScope.WindowEnd.Before(value.TimeScope.WindowStart) ||
		value.TimeScope.WindowEnd.Sub(value.TimeScope.WindowStart) > maximumWindow ||
		value.TimeScope.DurationMillis < 0 || value.TimeScope.DurationMillis > int64(maximumWindow/time.Millisecond) ||
		value.TimeScope.WindowEnd.Sub(value.TimeScope.WindowStart) != time.Duration(value.TimeScope.DurationMillis)*time.Millisecond ||
		value.TimeScope.SampleOrdinal < 0 || value.TimeScope.SampleOrdinal > 1_000_000 || !validRef(value.AudienceBindingRef) ||
		value.EvidenceExpiresAt.IsZero() || value.EvidenceExpiresAt.Location() != time.UTC ||
		!value.EvidenceExpiresAt.After(value.TimeScope.WindowEnd) || !digestPattern.MatchString(value.AudienceSHA256) {
		return ErrInvalid
	}
	if err := validateMediaSpec(value.Media, value.TimeScope); err != nil {
		return err
	}
	return nil
}

func validateMediaSpec(spec MediaSpec, scope TimeScope) error {
	if !validRef(spec.RunID) || !validRef(spec.StepID) || spec.Attempt < 1 || spec.Attempt > 1_000_000 ||
		!validRef(spec.RetentionPolicyRef) || spec.RedactionPolicyRef != "" && !validRef(spec.RedactionPolicyRef) {
		return ErrInvalid
	}
	switch spec.Kind {
	case media.KindImage:
		if scope.DurationMillis != 0 || !scope.WindowStart.Equal(scope.WindowEnd) {
			return ErrInvalid
		}
	case media.KindVideoClip:
		if scope.DurationMillis <= 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	switch spec.PrivacyClass {
	case "public", "internal", "sensitive", "restricted":
	default:
		return ErrInvalid
	}
	if spec.Lineage.ParentMediaRef == "" {
		if spec.Lineage.TransformPolicyRef != "" || spec.Lineage.Ordinal != 0 || spec.Lineage.OffsetMillis != 0 {
			return ErrInvalid
		}
	} else if !mediaRefPattern.MatchString(spec.Lineage.ParentMediaRef) || !validRef(spec.Lineage.TransformPolicyRef) ||
		spec.Lineage.Ordinal < 0 || spec.Lineage.Ordinal > 1_000_000 || spec.Lineage.OffsetMillis < 0 {
		return ErrInvalid
	}
	return nil
}

func marshalPersistedRequest(value persistedRequest) (string, string, error) {
	if err := validatePersistedRequest(value); err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", "", ErrInvalid
	}
	return string(raw), shaHex(raw), nil
}

func unmarshalPersistedRequest(raw, digest string) (persistedRequest, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !digestPattern.MatchString(digest) {
		return persistedRequest{}, ErrCorruptStore
	}
	var value persistedRequest
	if err := strictjson.ValidateExactFields([]byte(raw), &value, 8); err != nil {
		return persistedRequest{}, ErrCorruptStore
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return persistedRequest{}, ErrCorruptStore
	}
	canonical, computed, err := marshalPersistedRequest(value)
	if err != nil || canonical != raw || computed != digest {
		return persistedRequest{}, ErrCorruptStore
	}
	return value, nil
}

func (value persistedRequest) publication(expectedSHA256 string, actual persistedActualMedia) media.PutRequest {
	return media.PutRequest{
		Kind: value.Media.Kind,
		Binding: media.Binding{
			TenantID: value.TenantID, SiteID: value.SiteID, SourceRef: value.SourceRef,
			RunID: value.Media.RunID, StepID: value.Media.StepID, Attempt: value.Media.Attempt,
		},
		Encoding: actual.Encoding,
		Temporal: cloneTemporal(actual.Temporal),
		Lineage:  value.Media.Lineage,
		Governance: media.Governance{
			PrivacyClass: value.Media.PrivacyClass, RedactionPolicyRef: value.Media.RedactionPolicyRef,
			RetentionPolicyRef: value.Media.RetentionPolicyRef, Audience: []string{value.AudienceBindingRef},
			ExpiresAt: value.EvidenceExpiresAt,
		},
		ExpectedSHA256: expectedSHA256,
	}
}

func validateAcquisitionResult(result AcquisitionResult, request persistedRequest, now time.Time) (persistedActualMedia, string, error) {
	digest := result.SHA256
	switch result.Outcome {
	case AcquisitionPending:
		if result.Content != nil || digest != "" || result.FailureCode != "" || result.Encoding != (media.Encoding{}) || !emptyTemporal(result.Temporal) {
			return persistedActualMedia{}, "", ErrAcquirerContract
		}
	case AcquisitionReady:
		if result.Content == nil || !digestPattern.MatchString(digest) || result.FailureCode != "" {
			return persistedActualMedia{}, "", ErrAcquirerContract
		}
		actual, raw, err := canonicalActualMedia(request, result.Encoding, result.Temporal, now)
		if err != nil {
			return persistedActualMedia{}, "", ErrAcquirerContract
		}
		return actual, raw, nil
	case AcquisitionFailed:
		if result.Content != nil || digest != "" || !validRef(result.FailureCode) || result.Encoding != (media.Encoding{}) || !emptyTemporal(result.Temporal) {
			return persistedActualMedia{}, "", ErrAcquirerContract
		}
	default:
		return persistedActualMedia{}, "", ErrAcquirerContract
	}
	return persistedActualMedia{}, "", nil
}

func canonicalActualMedia(request persistedRequest, encoding media.Encoding, temporal media.Temporal, now time.Time) (persistedActualMedia, string, error) {
	if temporal.WindowStart != nil && temporal.WindowStart.Location() != time.UTC ||
		temporal.WindowEnd != nil && temporal.WindowEnd.Location() != time.UTC {
		return persistedActualMedia{}, "", ErrAcquirerContract
	}
	actual := persistedActualMedia{Encoding: encoding, Temporal: cloneTemporal(temporal)}
	if actual.Temporal.WindowStart != nil {
		start := actual.Temporal.WindowStart.UTC()
		actual.Temporal.WindowStart = &start
	}
	if actual.Temporal.WindowEnd != nil {
		end := actual.Temporal.WindowEnd.UTC()
		actual.Temporal.WindowEnd = &end
	}
	if err := validateActualMedia(request, actual, now); err != nil {
		return persistedActualMedia{}, "", err
	}
	raw, err := json.Marshal(actual)
	if err != nil {
		return persistedActualMedia{}, "", ErrAcquirerContract
	}
	return actual, string(raw), nil
}

func unmarshalActualMedia(raw string, request persistedRequest) (persistedActualMedia, error) {
	if len(raw) == 0 || len(raw) > 8<<10 {
		return persistedActualMedia{}, ErrCorruptStore
	}
	var actual persistedActualMedia
	if err := strictjson.ValidateExactFields([]byte(raw), &actual, 6); err != nil {
		return persistedActualMedia{}, ErrCorruptStore
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&actual); err != nil {
		return persistedActualMedia{}, ErrCorruptStore
	}
	canonical, computed, err := canonicalActualMedia(request, actual.Encoding, actual.Temporal, time.Time{})
	if err != nil || computed != raw {
		return persistedActualMedia{}, ErrCorruptStore
	}
	return canonical, nil
}

func validateActualMedia(request persistedRequest, actual persistedActualMedia, now time.Time) error {
	encoding, temporal := actual.Encoding, actual.Temporal
	if math.IsNaN(encoding.FrameRate) || math.IsInf(encoding.FrameRate, 0) || encoding.WidthPixels < 0 || encoding.HeightPixels < 0 || encoding.FrameRate < 0 ||
		temporal.WindowStart == nil || temporal.WindowEnd == nil || temporal.DurationMillis < 0 ||
		temporal.DurationMillis > int64(maximumWindow/time.Millisecond) || temporal.SampleOrdinal != request.TimeScope.SampleOrdinal ||
		temporal.WindowEnd.Before(*temporal.WindowStart) || temporal.WindowEnd.Sub(*temporal.WindowStart) != time.Duration(temporal.DurationMillis)*time.Millisecond ||
		!temporal.WindowEnd.Before(request.EvidenceExpiresAt) {
		return ErrAcquirerContract
	}
	if !now.IsZero() && temporal.WindowEnd.After(now.UTC().Add(maximumCaptureClockSkew)) {
		return ErrAcquirerContract
	}
	switch request.Media.Kind {
	case media.KindImage:
		expected := strings.TrimPrefix(encoding.MIMEType, "image/")
		if encoding.MIMEType != "image/jpeg" && encoding.MIMEType != "image/png" ||
			encoding.Container != expected || encoding.Codec != expected || encoding.WidthPixels < 1 || encoding.HeightPixels < 1 || encoding.FrameRate != 0 ||
			temporal.DurationMillis != 0 || !temporal.WindowStart.Equal(*temporal.WindowEnd) || temporal.WindowEnd.Before(request.TimeScope.WindowEnd) {
			return ErrAcquirerContract
		}
	case media.KindVideoClip:
		if encoding.MIMEType != "video/mp4" || encoding.Container != "mp4" || !validRef(encoding.Codec) ||
			encoding.WidthPixels < 1 || encoding.HeightPixels < 1 || encoding.FrameRate <= 0 || encoding.FrameRate > 1000 ||
			temporal.DurationMillis <= 0 || !temporal.WindowStart.Equal(request.TimeScope.WindowStart) ||
			!temporal.WindowEnd.Equal(request.TimeScope.WindowEnd) || temporal.DurationMillis != request.TimeScope.DurationMillis {
			return ErrAcquirerContract
		}
	default:
		return ErrAcquirerContract
	}
	return nil
}

func emptyTemporal(value media.Temporal) bool {
	return value.DurationMillis == 0 && value.WindowStart == nil && value.WindowEnd == nil && value.SampleOrdinal == 0
}

func cloneTemporal(value media.Temporal) media.Temporal {
	if value.WindowStart != nil {
		start := *value.WindowStart
		value.WindowStart = &start
	}
	if value.WindowEnd != nil {
		end := *value.WindowEnd
		value.WindowEnd = &end
	}
	return value
}

func sameActualMedia(left, right persistedActualMedia) bool {
	return left.Encoding == right.Encoding && left.Temporal.DurationMillis == right.Temporal.DurationMillis &&
		left.Temporal.SampleOrdinal == right.Temporal.SampleOrdinal &&
		sameOptionalTime(left.Temporal.WindowStart, right.Temporal.WindowStart) &&
		sameOptionalTime(left.Temporal.WindowEnd, right.Temporal.WindowEnd)
}

func validRef(value string) bool {
	return strings.TrimSpace(value) == value && refPattern.MatchString(value) && !unsafeLocator.MatchString(value)
}

func validSourceRef(value string) bool {
	if !validRef(value) || net.ParseIP(value) != nil || strings.ContainsAny(value, `:/\\@`) {
		return false
	}
	return true
}

func shaHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func safeStoredReason(reason Reason) bool {
	switch reason {
	case ReasonPrepared, ReasonAcquisitionStarted, ReasonAcquisitionPending, ReasonAcquisitionUnknown,
		ReasonReconciliationStarted, ReasonReconciliationPending, ReasonReconciliationUnknown, ReasonWorkerInterrupted, ReasonAcquisitionFailed,
		ReasonEvidenceExpired, ReasonContentInvalid, ReasonPublicationStarted, ReasonPublicationProbeStarted,
		ReasonPublicationReconciliationStarted, ReasonPublicationUnknown, ReasonPublicationRejected, ReasonReady:
		return true
	default:
		return false
	}
}

func definitePublicationError(err error) bool {
	return errors.Is(err, media.ErrHashMismatch) || errors.Is(err, media.ErrMIMEMismatch) ||
		errors.Is(err, media.ErrTooLarge) || errors.Is(err, media.ErrUnsupportedKind) || errors.Is(err, media.ErrUnsupportedMIME) ||
		errors.Is(err, media.ErrInvalidRetention) || errors.Is(err, media.ErrLineageConflict) ||
		errors.Is(err, media.ErrIdempotencyConflict) || errors.Is(err, media.ErrDeleted)
}

func descriptorMatchesPublication(descriptor media.Descriptor, request media.PutRequest) bool {
	if descriptor.Validate() != nil || descriptor.Kind != request.Kind || descriptor.Binding != request.Binding ||
		descriptor.Integrity.SHA256 != request.ExpectedSHA256 || descriptor.Lineage != request.Lineage ||
		descriptor.RuntimeLease != (media.RuntimeLease{}) || len(descriptor.FrameMembers) != 0 ||
		descriptor.Availability != media.AvailabilityAvailable ||
		descriptor.Temporal.DurationMillis != request.Temporal.DurationMillis ||
		descriptor.Temporal.SampleOrdinal != request.Temporal.SampleOrdinal ||
		!sameOptionalTime(descriptor.Temporal.WindowStart, request.Temporal.WindowStart) ||
		!sameOptionalTime(descriptor.Temporal.WindowEnd, request.Temporal.WindowEnd) {
		return false
	}
	if descriptor.Governance.PrivacyClass != request.Governance.PrivacyClass ||
		descriptor.Governance.RedactionPolicyRef != request.Governance.RedactionPolicyRef ||
		descriptor.Governance.RetentionPolicyRef != request.Governance.RetentionPolicyRef ||
		!descriptor.Governance.ExpiresAt.Equal(request.Governance.ExpiresAt) ||
		len(descriptor.Governance.Audience) != 1 || len(request.Governance.Audience) != 1 ||
		descriptor.Governance.Audience[0] != request.Governance.Audience[0] {
		return false
	}
	actual, expected := descriptor.Encoding, request.Encoding
	return actual.MIMEType == expected.MIMEType &&
		(expected.Container == "" || actual.Container == expected.Container) &&
		(expected.Codec == "" || actual.Codec == expected.Codec) &&
		(expected.WidthPixels == 0 || actual.WidthPixels == expected.WidthPixels) &&
		(expected.HeightPixels == 0 || actual.HeightPixels == expected.HeightPixels) &&
		(expected.FrameRate == 0 || actual.FrameRate == expected.FrameRate)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}
