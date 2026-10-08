package application

import (
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

const temporaryDecisionStorageSchema = "cosmoedge.inspection.application.temporary-decision.v1"

// TemporaryDecision is the complete replay authority for one temporary
// observation. The protected preparation request is deliberately unexported;
// ordinary JSON, text and structured logging are denied. StateStore uses the
// dedicated canonical storage wire below.
type TemporaryDecision struct {
	Spec       temporary.TemporaryObservationSpec
	DeadlineAt time.Time
	request    mediaprep.FrozenRequest
}

func NewTemporaryDecision(spec temporary.TemporaryObservationSpec, request mediaprep.FrozenRequest, deadlineAt time.Time) (TemporaryDecision, error) {
	decision := TemporaryDecision{Spec: spec, DeadlineAt: deadlineAt, request: request}
	if err := validateTemporaryDecision(decision, request.TimeScope.WindowEnd); err != nil {
		return TemporaryDecision{}, err
	}
	return decision, nil
}

// PreparationRequest returns a value copy of the already-frozen protected
// request. Callers may register it verbatim but cannot serialize or log it.
func (decision TemporaryDecision) PreparationRequest() (mediaprep.FrozenRequest, error) {
	if err := validateTemporaryDecision(decision, decision.request.TimeScope.WindowEnd); err != nil {
		return mediaprep.FrozenRequest{}, err
	}
	return decision.request, nil
}

func (TemporaryDecision) MarshalJSON() ([]byte, error) { return nil, mediaprep.ErrProtected }
func (TemporaryDecision) MarshalText() ([]byte, error) { return nil, mediaprep.ErrProtected }
func (TemporaryDecision) String() string               { return "[temporary-observation-decision]" }
func (TemporaryDecision) GoString() string {
	return "application.TemporaryDecision([redacted])"
}
func (TemporaryDecision) LogValue() slog.Value {
	return slog.StringValue("[temporary-observation-decision]")
}

type temporaryDecisionStorageWire struct {
	Schema      string                             `json:"schema"`
	Spec        temporary.TemporaryObservationSpec `json:"spec"`
	DeadlineAt  time.Time                          `json:"deadlineAt"`
	Preparation temporaryPreparationStorageWire    `json:"preparation"`
}

type temporaryPreparationStorageWire struct {
	Schema             string              `json:"schema"`
	TenantID           string              `json:"tenantId"`
	SiteID             string              `json:"siteId"`
	RequestID          string              `json:"requestId"`
	SourceRef          string              `json:"sourceRef"`
	CapabilityRef      string              `json:"capabilityRef"`
	TimeScope          mediaprep.TimeScope `json:"timeScope"`
	AudienceBindingRef string              `json:"audienceBindingRef"`
	AudienceSHA256     string              `json:"audienceSha256"`
	EvidenceExpiresAt  time.Time           `json:"evidenceExpiresAt"`
	Media              mediaprep.MediaSpec `json:"media"`
}

func marshalTemporaryDecisionStorage(decision TemporaryDecision) ([]byte, error) {
	request, err := decision.PreparationRequest()
	if err != nil {
		return nil, err
	}
	wire := temporaryDecisionStorageWire{
		Schema: temporaryDecisionStorageSchema, Spec: decision.Spec, DeadlineAt: decision.DeadlineAt,
		Preparation: temporaryPreparationStorageWire{
			Schema: request.Schema, TenantID: request.TenantID, SiteID: request.SiteID, RequestID: request.RequestID,
			SourceRef: request.SourceRef, CapabilityRef: request.CapabilityRef, TimeScope: request.TimeScope,
			AudienceBindingRef: request.AudienceBindingRef, AudienceSHA256: request.AudienceSHA256,
			EvidenceExpiresAt: request.EvidenceExpiresAt, Media: request.Media,
		},
	}
	return json.Marshal(wire)
}

func unmarshalTemporaryDecisionStorage(raw []byte) (TemporaryDecision, error) {
	var wire temporaryDecisionStorageWire
	if err := decodeCanonical(raw, &wire); err != nil || wire.Schema != temporaryDecisionStorageSchema {
		return TemporaryDecision{}, errors.New("stored temporary decision wire is invalid")
	}
	request := mediaprep.FrozenRequest{
		Schema: wire.Preparation.Schema, TenantID: wire.Preparation.TenantID, SiteID: wire.Preparation.SiteID,
		RequestID: wire.Preparation.RequestID, SourceRef: wire.Preparation.SourceRef,
		CapabilityRef: wire.Preparation.CapabilityRef, TimeScope: wire.Preparation.TimeScope,
		AudienceBindingRef: wire.Preparation.AudienceBindingRef, AudienceSHA256: wire.Preparation.AudienceSHA256,
		EvidenceExpiresAt: wire.Preparation.EvidenceExpiresAt, Media: wire.Preparation.Media,
	}
	return NewTemporaryDecision(wire.Spec, request, wire.DeadlineAt)
}

func validateTemporaryDecision(decision TemporaryDecision, requestedAt time.Time) error {
	request := decision.request
	if decision.Spec.Validate() != nil || request.Validate() != nil || requestedAt.IsZero() || requestedAt.Location() != time.UTC ||
		!request.TimeScope.WindowEnd.Equal(requestedAt) || decision.DeadlineAt.IsZero() ||
		decision.DeadlineAt.Location() != time.UTC || !decision.DeadlineAt.After(requestedAt) ||
		decision.DeadlineAt.Sub(requestedAt) > temporary.MaxRunDuration ||
		!request.EvidenceExpiresAt.Equal(requestedAt.Add(time.Duration(decision.Spec.EvidenceTTLSeconds)*time.Second)) ||
		decision.DeadlineAt.After(request.EvidenceExpiresAt) || request.TimeScope.SampleOrdinal != 0 {
		return errors.New("invalid bounded temporary observation decision")
	}
	expectedStart := requestedAt
	expectedKind := media.KindImage
	if decision.Spec.TimeScope.Kind == temporary.TimeScopeRecentWindow {
		expectedStart = requestedAt.Add(-time.Duration(decision.Spec.TimeScope.WindowSeconds) * time.Second)
		expectedKind = media.KindVideoClip
	}
	if request.Media.Kind != expectedKind || !request.TimeScope.WindowStart.Equal(expectedStart) ||
		request.TimeScope.DurationMillis != requestedAt.Sub(expectedStart).Milliseconds() {
		return errors.New("temporary observation media request does not match its frozen time scope")
	}
	return nil
}
