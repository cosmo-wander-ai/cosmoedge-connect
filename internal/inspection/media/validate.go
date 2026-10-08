package media

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"mime"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidMediaRef        = errors.New("invalid media reference")
	ErrInvalidDescriptor      = errors.New("invalid media descriptor")
	ErrUnsupportedKind        = errors.New("unsupported media kind")
	ErrUnsupportedMIME        = errors.New("unsupported media MIME type")
	ErrMIMEMismatch           = errors.New("declared media MIME type does not match content")
	ErrHashMismatch           = errors.New("media content hash does not match the expected digest")
	ErrTooLarge               = errors.New("media content exceeds the per-object limit")
	ErrQuotaExceeded          = errors.New("media store quota exceeded")
	ErrNotFound               = errors.New("media reference not found")
	ErrDeleted                = errors.New("media was deleted")
	ErrExpired                = errors.New("media retention expired")
	ErrNoContent              = errors.New("media descriptor has no content stream")
	ErrUnsafePath             = errors.New("unsafe media store path")
	ErrCorruptDescriptor      = errors.New("corrupt media descriptor")
	ErrIntegrityMismatch      = errors.New("stored media integrity mismatch")
	ErrIncompatibleStore      = errors.New("incompatible media store schema")
	ErrInvalidRetention       = errors.New("invalid media retention")
	ErrLineageConflict        = errors.New("media lineage conflict")
	ErrInvalidIdempotencyKey  = errors.New("invalid media idempotency key")
	ErrIdempotencyConflict    = errors.New("media idempotency request conflict")
	ErrCorruptIdempotency     = errors.New("corrupt media idempotency state")
	ErrProtectedPutProjection = errors.New("protected media put request cannot be serialized")
)

var (
	mediaRefPattern  = regexp.MustCompile(`^media_[a-f0-9]{32}$`)
	opaqueRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	digestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func validateDescriptor(d Descriptor) error {
	if d.Schema != Schema || validateMediaRef(d.MediaRef) != nil || !validKind(d.Kind) {
		return ErrCorruptDescriptor
	}
	if err := validateBinding(d.Binding); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptDescriptor, err)
	}
	if err := validateEncoding(d.Kind, d.Encoding); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptDescriptor, err)
	}
	if err := validateTemporal(d.Temporal); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptDescriptor, err)
	}
	if !digestPattern.MatchString(d.Integrity.SHA256) || d.Integrity.SizeBytes < 0 {
		return ErrCorruptDescriptor
	}
	if err := validateLineage(d.Lineage); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptDescriptor, err)
	}
	if err := validateRuntimeLease(d.RuntimeLease, d.Lineage); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptDescriptor, err)
	}
	if err := validateGovernance(d.Governance, d.CreatedAt); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptDescriptor, err)
	}
	if err := validateFrameMembers(d.Kind, d.FrameMembers); err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptDescriptor, err)
	}
	if d.CreatedAt.IsZero() {
		return ErrCorruptDescriptor
	}
	switch d.Availability {
	case AvailabilityAvailable:
		if d.DeletedAt != nil || d.DeletionReason != "" {
			return ErrCorruptDescriptor
		}
	case AvailabilityDeleted:
		if d.DeletedAt == nil || d.DeletedAt.Before(d.CreatedAt) || !validReason(d.DeletionReason) {
			return ErrCorruptDescriptor
		}
	default:
		return ErrCorruptDescriptor
	}
	if d.Kind == KindFrameSet {
		if d.Integrity.SizeBytes != 0 {
			return ErrCorruptDescriptor
		}
	} else if d.Integrity.SizeBytes <= 0 {
		return ErrCorruptDescriptor
	}
	return nil
}

func validateBinding(b Binding) error {
	for name, value := range map[string]string{
		"tenant": b.TenantID, "site": b.SiteID, "source": b.SourceRef,
		"run": b.RunID, "step": b.StepID,
	} {
		if !validOpaqueRef(value) {
			return fmt.Errorf("%s binding is not opaque", name)
		}
	}
	if b.Attempt < 1 || b.Attempt > 1_000_000 {
		return errors.New("attempt is outside the bounded range")
	}
	return nil
}

func validateEncoding(kind Kind, e Encoding) error {
	if math.IsNaN(e.FrameRate) || math.IsInf(e.FrameRate, 0) || e.WidthPixels < 0 || e.HeightPixels < 0 || e.FrameRate < 0 {
		return errors.New("encoding dimensions or frame rate are invalid")
	}
	switch kind {
	case KindImage:
		if e.MIMEType != "image/jpeg" && e.MIMEType != "image/png" {
			return ErrUnsupportedMIME
		}
		expected := strings.TrimPrefix(e.MIMEType, "image/")
		if e.Container != expected || e.Codec != expected || e.WidthPixels < 1 || e.HeightPixels < 1 || e.FrameRate != 0 {
			return errors.New("image encoding is incomplete")
		}
	case KindVideoClip:
		if e.MIMEType != "video/mp4" {
			return ErrUnsupportedMIME
		}
		if e.Container != "mp4" || !validOpaqueRef(e.Codec) || e.WidthPixels < 1 || e.HeightPixels < 1 || e.FrameRate <= 0 || e.FrameRate > 1000 {
			return errors.New("video encoding is incomplete")
		}
	case KindMetric, KindDetection, KindEvent:
		if e.MIMEType != "application/json" || e.Container != "json" || e.Codec != "json" || e.WidthPixels != 0 || e.HeightPixels != 0 || e.FrameRate != 0 {
			return errors.New("structured observation encoding is invalid")
		}
	case KindFrameSet:
		if e != (Encoding{}) {
			return errors.New("frame set must not claim a content encoding")
		}
	default:
		return ErrUnsupportedKind
	}
	return nil
}

func validateTemporal(t Temporal) error {
	if t.DurationMillis < 0 || t.DurationMillis > int64((24*time.Hour)/time.Millisecond) || t.SampleOrdinal < 0 || t.SampleOrdinal > 1_000_000 {
		return errors.New("media temporal bounds are invalid")
	}
	if (t.WindowStart == nil) != (t.WindowEnd == nil) {
		return errors.New("media time window is incomplete")
	}
	if t.WindowStart != nil && t.WindowEnd.Before(*t.WindowStart) {
		return errors.New("media time window is reversed")
	}
	return nil
}

func validateLineage(l Lineage) error {
	if l.ParentMediaRef == "" {
		if l.TransformPolicyRef != "" || l.Ordinal != 0 || l.OffsetMillis != 0 {
			return errors.New("lineage fields require a parent")
		}
		return nil
	}
	if validateMediaRef(l.ParentMediaRef) != nil || !validOpaqueRef(l.TransformPolicyRef) || l.Ordinal < 0 || l.Ordinal > 1_000_000 || l.OffsetMillis < 0 {
		return errors.New("lineage is invalid")
	}
	return nil
}

func validateRuntimeLease(lease RuntimeLease, lineage Lineage) error {
	empty := lease.SourceMediaRef == "" && lease.SourceSHA256 == "" && lease.PolicyRef == ""
	if empty {
		return nil
	}
	if validateMediaRef(lease.SourceMediaRef) != nil || !validDigest(lease.SourceSHA256) ||
		!validOpaqueRef(lease.PolicyRef) || lineage.ParentMediaRef != "" {
		return errors.New("runtime media lease is invalid")
	}
	return nil
}

func validateGovernance(g Governance, createdAt time.Time) error {
	switch g.PrivacyClass {
	case "public", "internal", "sensitive", "restricted":
	default:
		return errors.New("privacy class is invalid")
	}
	if g.RedactionPolicyRef != "" && !validOpaqueRef(g.RedactionPolicyRef) {
		return errors.New("redaction policy is invalid")
	}
	if !validOpaqueRef(g.RetentionPolicyRef) || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(createdAt) {
		return ErrInvalidRetention
	}
	if len(g.Audience) < 1 || len(g.Audience) > 16 || !sort.StringsAreSorted(g.Audience) {
		return errors.New("audience is not canonical")
	}
	for index, value := range g.Audience {
		if !validOpaqueRef(value) || index > 0 && value == g.Audience[index-1] {
			return errors.New("audience is invalid")
		}
	}
	return nil
}

func validateFrameMembers(kind Kind, members []FrameMember) error {
	if members == nil {
		return errors.New("frame member collection must be explicit")
	}
	if kind != KindFrameSet {
		if len(members) != 0 {
			return errors.New("only a frame set may contain frame members")
		}
		return nil
	}
	if len(members) < 1 || len(members) > maxFrameMembers {
		return errors.New("frame set member count is outside the bounded range")
	}
	seen := make(map[string]struct{}, len(members))
	var previousOffset int64
	for index, member := range members {
		if validateMediaRef(member.MediaRef) != nil || !digestPattern.MatchString(member.SHA256) ||
			member.Ordinal != index || member.OffsetMillis < 0 || !validOpaqueRef(member.TransformPolicyRef) ||
			(index > 0 && member.OffsetMillis < previousOffset) {
			return errors.New("frame set member order or identity is invalid")
		}
		if _, exists := seen[member.MediaRef]; exists {
			return errors.New("frame set repeats a media reference")
		}
		seen[member.MediaRef] = struct{}{}
		previousOffset = member.OffsetMillis
	}
	return nil
}

func validKind(kind Kind) bool {
	switch kind {
	case KindImage, KindFrameSet, KindVideoClip, KindMetric, KindDetection, KindEvent:
		return true
	default:
		return false
	}
}

func validateMediaRef(ref string) error {
	if !mediaRefPattern.MatchString(ref) {
		return ErrInvalidMediaRef
	}
	return nil
}

func validOpaqueRef(value string) bool {
	if strings.TrimSpace(value) != value || !opaqueRefPattern.MatchString(value) || net.ParseIP(value) != nil {
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

func validDigest(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func normalizedMIME(raw string) (string, error) {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil {
		return "", ErrUnsupportedMIME
	}
	return strings.ToLower(mediaType), nil
}

func validReason(value string) bool {
	return validOpaqueRef(value) && len(value) <= 64
}
