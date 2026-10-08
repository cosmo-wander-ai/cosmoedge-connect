// Package catalog owns protected, device-independent facts for inspection
// sources and already-installed device tasks. Native locators are deliberately
// excluded from every business projection and frozen assignment reference.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const SchemaVersion = "cosmoedge.inspection.catalog.v2"

var (
	ErrNotFound            = errors.New("inspection source was not found")
	ErrConflict            = errors.New("inspection source revision conflict")
	ErrInvalidSource       = errors.New("inspection source is invalid")
	ErrIdentityDrift       = errors.New("inspection source identity drifted")
	ErrCapabilityMissing   = errors.New("inspection source capability is unavailable")
	ErrUnsupportedSchema   = errors.New("inspection source catalog schema is unsupported")
	ErrProtectedProjection = errors.New("protected inspection source cannot be serialized")
)

type State string

const (
	StateActive        State = "active"
	StateDisabled      State = "disabled"
	StateIdentityDrift State = "identity_drift"
)

type CapabilityKind string

const (
	CapabilitySnapshot      CapabilityKind = "snapshot"
	CapabilityClip          CapabilityKind = "clip"
	CapabilityTaskEvidence  CapabilityKind = "task_evidence"
	CapabilityRetainedMedia CapabilityKind = "retained_media"
	CapabilityUploadedMedia CapabilityKind = "uploaded_media"
)

// MediaKind is owned by the inspection domain. The catalog records which of
// those closed media types each verified capability can produce.
type MediaKind = inspection.MediaKind

const (
	MediaImage     = inspection.MediaImage
	MediaFrameSet  = inspection.MediaFrameSet
	MediaVideoClip = inspection.MediaVideoClip
	MediaMetric    = inspection.MediaMetric
	MediaDetection = inspection.MediaDetection
	MediaEvent     = inspection.MediaEvent
)

type Constraints struct {
	MediaKinds          []MediaKind `json:"mediaKinds"`
	MaxBytes            int64       `json:"maxBytes"`
	MaxFrames           int         `json:"maxFrames"`
	MaxDurationSeconds  int         `json:"maxDurationSeconds"`
	MaxFreshnessSeconds int         `json:"maxFreshnessSeconds"`
}

type Capability struct {
	Ref          string         `json:"ref"`
	Kind         CapabilityKind `json:"kind"`
	Revision     uint64         `json:"revision"`
	ResultSchema string         `json:"resultSchema,omitempty"`
	Constraints  Constraints    `json:"constraints"`
	Digest       string         `json:"digest"`
}

// Source is protected local catalog state. NativeLocator is required by a
// future adapter but may never cross the catalog/application boundary.
type Source struct {
	Schema              string
	TenantID            string
	SiteID              string
	DeviceProfileID     string
	Handle              string
	Kind                inspection.SourceKind
	Revision            uint64
	IdentityFingerprint string
	NativeLocator       string
	Alias               string
	ZoneID              string
	State               State
	Capabilities        []Capability
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (Source) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }

type NewSource struct {
	TenantID            string
	SiteID              string
	DeviceProfileID     string
	Handle              string
	Kind                inspection.SourceKind
	IdentityFingerprint string
	NativeLocator       string
	Alias               string
	ZoneID              string
	Capabilities        []Capability
}

type UpdateSource struct {
	TenantID            string
	SiteID              string
	Handle              string
	ExpectedRevision    uint64
	DeviceProfileID     string
	IdentityFingerprint string
	NativeLocator       string
	Alias               string
	ZoneID              string
	State               State
	Capabilities        []Capability
}

type CapabilitySummary struct {
	Ref          string         `json:"ref"`
	Kind         CapabilityKind `json:"kind"`
	MediaKinds   []MediaKind    `json:"mediaKinds"`
	ResultSchema string         `json:"resultSchema,omitempty"`
}

type BusinessSummary struct {
	SourceHandle string                `json:"sourceHandle"`
	Kind         inspection.SourceKind `json:"kind"`
	Alias        string                `json:"alias"`
	ZoneID       string                `json:"zoneId,omitempty"`
	State        State                 `json:"state"`
	Revision     uint64                `json:"revision"`
	Capabilities []CapabilitySummary   `json:"capabilities"`
}

var (
	refPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func NormalizeCapabilities(values []Capability) ([]Capability, error) {
	if len(values) == 0 || len(values) > 32 {
		return nil, ErrInvalidSource
	}
	result := make([]Capability, len(values))
	for index, value := range values {
		value.ResultSchema = strings.TrimSpace(value.ResultSchema)
		value.Constraints.MediaKinds = append([]MediaKind(nil), value.Constraints.MediaKinds...)
		sort.Slice(value.Constraints.MediaKinds, func(i, j int) bool {
			return value.Constraints.MediaKinds[i] < value.Constraints.MediaKinds[j]
		})
		value.Digest = ""
		if err := validateCapability(value, false); err != nil {
			return nil, err
		}
		digest, err := capabilityDigest(value)
		if err != nil {
			return nil, err
		}
		value.Digest = digest
		result[index] = value
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Ref < result[j].Ref })
	for index := 1; index < len(result); index++ {
		if result[index-1].Ref == result[index].Ref {
			return nil, ErrInvalidSource
		}
	}
	return result, nil
}

func (s Source) Validate() error {
	if s.Schema != SchemaVersion || !validRef(s.TenantID) || !validRef(s.SiteID) ||
		!validRef(s.DeviceProfileID) || !validRef(s.Handle) || !s.Kind.Valid() ||
		s.Revision == 0 || !digestPattern.MatchString(s.IdentityFingerprint) ||
		!validState(s.State) || s.CreatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) {
		return ErrInvalidSource
	}
	if err := validateProtectedText("native locator", s.NativeLocator, 512); err != nil {
		return errors.Join(ErrInvalidSource, err)
	}
	if err := validateBusinessText("alias", s.Alias, 160); err != nil {
		return errors.Join(ErrInvalidSource, err)
	}
	if s.ZoneID != "" && !validRef(s.ZoneID) {
		return ErrInvalidSource
	}
	if len(s.Capabilities) == 0 || len(s.Capabilities) > 32 {
		return ErrInvalidSource
	}
	for index, capability := range s.Capabilities {
		if err := validateCapability(capability, true); err != nil {
			return err
		}
		if index > 0 && s.Capabilities[index-1].Ref >= capability.Ref {
			return ErrInvalidSource
		}
	}
	return nil
}

func (s Source) Summary() (BusinessSummary, error) {
	if err := s.Validate(); err != nil {
		return BusinessSummary{}, err
	}
	summary := BusinessSummary{
		SourceHandle: s.Handle, Kind: s.Kind, Alias: s.Alias, ZoneID: s.ZoneID,
		State: s.State, Revision: s.Revision, Capabilities: make([]CapabilitySummary, 0, len(s.Capabilities)),
	}
	for _, capability := range s.Capabilities {
		summary.Capabilities = append(summary.Capabilities, CapabilitySummary{
			Ref: capability.Ref, Kind: capability.Kind,
			MediaKinds:   append([]MediaKind(nil), capability.Constraints.MediaKinds...),
			ResultSchema: capability.ResultSchema,
		})
	}
	return summary, nil
}

func (s Source) Binding(requiredCapabilities []string, roiRef string) (inspection.SourceBinding, error) {
	if err := s.Validate(); err != nil {
		return inspection.SourceBinding{}, err
	}
	if s.State == StateIdentityDrift {
		return inspection.SourceBinding{}, ErrIdentityDrift
	}
	if s.State != StateActive {
		return inspection.SourceBinding{}, ErrCapabilityMissing
	}
	required := normalizeRefs(requiredCapabilities)
	if len(required) == 0 || len(required) > 16 {
		return inspection.SourceBinding{}, ErrCapabilityMissing
	}
	available := make(map[string]Capability, len(s.Capabilities))
	for _, capability := range s.Capabilities {
		available[capability.Ref] = capability
	}
	mediaSet := make(map[inspection.MediaKind]struct{})
	for _, ref := range required {
		capability, ok := available[ref]
		if !ok {
			return inspection.SourceBinding{}, ErrCapabilityMissing
		}
		for _, kind := range capability.Constraints.MediaKinds {
			mediaSet[kind] = struct{}{}
		}
	}
	mediaKinds := make([]inspection.MediaKind, 0, len(mediaSet))
	for kind := range mediaSet {
		mediaKinds = append(mediaKinds, kind)
	}
	sort.Slice(mediaKinds, func(i, j int) bool { return mediaKinds[i] < mediaKinds[j] })
	binding := inspection.SourceBinding{
		Kind: s.Kind, SourceHandle: s.Handle, SourceRevision: s.Revision,
		SourceFingerprint: s.IdentityFingerprint, CapabilityRefs: required,
		MediaKinds: mediaKinds, ROIRef: strings.TrimSpace(roiRef),
	}
	if err := binding.Validate(); err != nil {
		return inspection.SourceBinding{}, err
	}
	return binding, nil
}

func capabilityDigest(value Capability) (string, error) {
	canonical := struct {
		Ref          string         `json:"ref"`
		Kind         CapabilityKind `json:"kind"`
		Revision     uint64         `json:"revision"`
		ResultSchema string         `json:"resultSchema,omitempty"`
		Constraints  Constraints    `json:"constraints"`
	}{value.Ref, value.Kind, value.Revision, value.ResultSchema, value.Constraints}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validateCapability(value Capability, requireDigest bool) error {
	if !validRef(value.Ref) || value.Revision == 0 || !validCapabilityKind(value.Kind) {
		return ErrInvalidSource
	}
	if value.ResultSchema != "" && !validRef(value.ResultSchema) {
		return ErrInvalidSource
	}
	if len(value.Constraints.MediaKinds) == 0 || len(value.Constraints.MediaKinds) > 8 ||
		value.Constraints.MaxBytes < 0 || value.Constraints.MaxBytes > 1<<40 ||
		value.Constraints.MaxFrames < 0 || value.Constraints.MaxFrames > 10_000 ||
		value.Constraints.MaxDurationSeconds < 0 || value.Constraints.MaxDurationSeconds > 24*60*60 ||
		value.Constraints.MaxFreshnessSeconds < 0 || value.Constraints.MaxFreshnessSeconds > 30*24*60*60 {
		return ErrInvalidSource
	}
	for index, kind := range value.Constraints.MediaKinds {
		if !validMediaKind(kind) || index > 0 && value.Constraints.MediaKinds[index-1] >= kind {
			return ErrInvalidSource
		}
	}
	if requireDigest {
		digest, err := capabilityDigest(Capability{
			Ref: value.Ref, Kind: value.Kind, Revision: value.Revision,
			ResultSchema: value.ResultSchema, Constraints: value.Constraints,
		})
		if err != nil || value.Digest != digest {
			return ErrInvalidSource
		}
	}
	return nil
}

func normalizeRefs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validCapabilityKind(value CapabilityKind) bool {
	switch value {
	case CapabilitySnapshot, CapabilityClip, CapabilityTaskEvidence, CapabilityRetainedMedia, CapabilityUploadedMedia:
		return true
	default:
		return false
	}
}

func validMediaKind(value MediaKind) bool {
	return value.Valid()
}

func validState(value State) bool {
	return value == StateActive || value == StateDisabled || value == StateIdentityDrift
}

func validRef(value string) bool { return refPattern.MatchString(strings.TrimSpace(value)) }

func validateBusinessText(name, value string, maximum int) error {
	if err := validateProtectedText(name, value, maximum); err != nil {
		return err
	}
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"http://", "https://", "rtsp://", "rtsps://", "password", "token", "credential"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("%s contains protected data", name)
		}
	}
	return nil
}

func validateProtectedText(name, value string, maximum int) error {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}
