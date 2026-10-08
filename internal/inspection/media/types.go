package media

import (
	"log/slog"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const Schema = "cosmoedge.inspection.media.v3"

type Kind = inspection.MediaKind

const (
	KindImage     = inspection.MediaImage
	KindFrameSet  = inspection.MediaFrameSet
	KindVideoClip = inspection.MediaVideoClip
	KindMetric    = inspection.MediaMetric
	KindDetection = inspection.MediaDetection
	KindEvent     = inspection.MediaEvent
)

type Availability string

const (
	AvailabilityAvailable Availability = "available"
	AvailabilityDeleted   Availability = "deleted"
)

type Binding struct {
	TenantID  string `json:"tenantId"`
	SiteID    string `json:"siteId"`
	SourceRef string `json:"sourceRef"`
	RunID     string `json:"runId"`
	StepID    string `json:"stepId"`
	Attempt   int    `json:"attempt"`
}

type Encoding struct {
	MIMEType     string  `json:"mimeType,omitempty"`
	Container    string  `json:"container,omitempty"`
	Codec        string  `json:"codec,omitempty"`
	WidthPixels  int     `json:"widthPixels,omitempty"`
	HeightPixels int     `json:"heightPixels,omitempty"`
	FrameRate    float64 `json:"frameRate,omitempty"`
}

type Temporal struct {
	DurationMillis int64      `json:"durationMillis,omitempty"`
	WindowStart    *time.Time `json:"windowStart,omitempty"`
	WindowEnd      *time.Time `json:"windowEnd,omitempty"`
	SampleOrdinal  int        `json:"sampleOrdinal"`
}

type Integrity struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

type Lineage struct {
	ParentMediaRef     string `json:"parentMediaRef,omitempty"`
	TransformPolicyRef string `json:"transformPolicyRef,omitempty"`
	Ordinal            int    `json:"ordinal,omitempty"`
	OffsetMillis       int64  `json:"offsetMillis,omitempty"`
}

// RuntimeLease binds immutable pre-existing media to one execution without
// rewriting the source descriptor's ingestion ownership. The leased descriptor
// is a bounded, run-owned copy; transformations may therefore use it as their
// ordinary same-run lineage parent.
type RuntimeLease struct {
	SourceMediaRef string `json:"sourceMediaRef,omitempty"`
	SourceSHA256   string `json:"sourceSha256,omitempty"`
	PolicyRef      string `json:"policyRef,omitempty"`
}

type Governance struct {
	PrivacyClass       string    `json:"privacyClass"`
	RedactionPolicyRef string    `json:"redactionPolicyRef,omitempty"`
	RetentionPolicyRef string    `json:"retentionPolicyRef"`
	Audience           []string  `json:"audience"`
	ExpiresAt          time.Time `json:"expiresAt"`
}

// FrameMember is an ordered, integrity-bound child of a frame_set. Registering
// a frame set transfers lifecycle ownership of each member to the set.
type FrameMember struct {
	MediaRef           string `json:"mediaRef"`
	SHA256             string `json:"sha256"`
	Ordinal            int    `json:"ordinal"`
	OffsetMillis       int64  `json:"offsetMillis"`
	TransformPolicyRef string `json:"transformPolicyRef"`
}

// Descriptor is the sole persisted media contract. It contains opaque
// references and bounded metadata only: never a filesystem path, stream URL,
// credential, or encoded payload.
type Descriptor struct {
	Schema         string        `json:"schema"`
	MediaRef       string        `json:"mediaRef"`
	Kind           Kind          `json:"kind"`
	Binding        Binding       `json:"binding"`
	Encoding       Encoding      `json:"encoding"`
	Temporal       Temporal      `json:"temporal"`
	Integrity      Integrity     `json:"integrity"`
	Lineage        Lineage       `json:"lineage"`
	RuntimeLease   RuntimeLease  `json:"runtimeLease"`
	Governance     Governance    `json:"governance"`
	FrameMembers   []FrameMember `json:"frameMembers"`
	Availability   Availability  `json:"availability"`
	CreatedAt      time.Time     `json:"createdAt"`
	DeletedAt      *time.Time    `json:"deletedAt,omitempty"`
	DeletionReason string        `json:"deletionReason,omitempty"`
}

type PutRequest struct {
	Kind           Kind
	Binding        Binding
	Encoding       Encoding
	Temporal       Temporal
	Lineage        Lineage
	Governance     Governance
	ExpectedSHA256 string
}

// IdempotentPutRequest binds one exact immutable media publication to a
// caller-owned operation key. The store reserves the resulting MediaRef before
// content publication, so an interrupted retry can never allocate a second
// object identity.
type IdempotentPutRequest struct {
	IdempotencyKey string
	Media          PutRequest
}

func (IdempotentPutRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedPutProjection
}
func (IdempotentPutRequest) MarshalText() ([]byte, error) {
	return nil, ErrProtectedPutProjection
}
func (IdempotentPutRequest) String() string   { return "[inspection-media-idempotent-put]" }
func (IdempotentPutRequest) GoString() string { return "media.IdempotentPutRequest([redacted])" }
func (IdempotentPutRequest) LogValue() slog.Value {
	return slog.StringValue("[inspection-media-idempotent-put]")
}

type FrameMemberInput struct {
	MediaRef           string
	Ordinal            int
	OffsetMillis       int64
	TransformPolicyRef string
}

type FrameSetRequest struct {
	Binding    Binding
	Temporal   Temporal
	Lineage    Lineage
	Governance Governance
	Members    []FrameMemberInput
}

type RunLeaseRequest struct {
	SourceMediaRef string
	Binding        Binding
	Governance     Governance
	PolicyRef      string
}

// BusinessDescriptor is safe for chat/UI projections. It deliberately omits
// storage locations, source identifiers, execution identifiers, hashes, and
// any way to retrieve content.
type BusinessDescriptor struct {
	MediaRef       string       `json:"mediaRef"`
	Kind           Kind         `json:"kind"`
	MIMEType       string       `json:"mimeType,omitempty"`
	WidthPixels    int          `json:"widthPixels,omitempty"`
	HeightPixels   int          `json:"heightPixels,omitempty"`
	DurationMillis int64        `json:"durationMillis,omitempty"`
	SampleOrdinal  int          `json:"sampleOrdinal"`
	Availability   Availability `json:"availability"`
	CreatedAt      time.Time    `json:"createdAt"`
	ExpiresAt      time.Time    `json:"expiresAt"`
}

func (d Descriptor) Business() BusinessDescriptor {
	return BusinessDescriptor{
		MediaRef: d.MediaRef, Kind: d.Kind, MIMEType: d.Encoding.MIMEType,
		WidthPixels: d.Encoding.WidthPixels, HeightPixels: d.Encoding.HeightPixels,
		DurationMillis: d.Temporal.DurationMillis, SampleOrdinal: d.Temporal.SampleOrdinal,
		Availability: d.Availability, CreatedAt: d.CreatedAt.UTC(), ExpiresAt: d.Governance.ExpiresAt.UTC(),
	}
}

// Validate verifies the complete persisted v2 descriptor contract without
// exposing any storage location or content bytes.
func (d Descriptor) Validate() error {
	return validateDescriptor(d)
}
