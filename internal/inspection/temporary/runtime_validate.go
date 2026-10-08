package temporary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
)

type frozenIdentity struct {
	Schema             string                   `json:"schema"`
	Binding            AuthenticatedBinding     `json:"binding"`
	Spec               TemporaryObservationSpec `json:"spec"`
	PreparationRef     string                   `json:"preparationRef"`
	MediaKind          media.Kind               `json:"mediaKind"`
	AudienceBindingRef string                   `json:"audienceBindingRef"`
	AudienceSHA256     string                   `json:"audienceSha256"`
	EvidenceExpiresAt  time.Time                `json:"evidenceExpiresAt"`
	DeadlineAt         time.Time                `json:"deadlineAt"`
}

type audienceIdentity struct {
	Schema          string `json:"schema"`
	TenantID        string `json:"tenantId"`
	SiteID          string `json:"siteId"`
	Channel         string `json:"channel"`
	ConversationRef string `json:"conversationRef"`
	RecipientRef    string `json:"recipientRef"`
	PrincipalSHA256 string `json:"principalSha256"`
}

func (b AuthenticatedBinding) validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"tenantId", b.TenantID}, {"siteId", b.SiteID}, {"requestKey", b.RequestKey},
		{"publicRunRef", b.PublicRunRef}, {"channel", b.Channel},
		{"conversationRef", b.ConversationRef}, {"recipientRef", b.RecipientRef},
	} {
		if !validRuntimeRef(field.value) {
			return fmt.Errorf("%w: authenticated %s is invalid", ErrRuntimeInvalid, field.name)
		}
	}
	if !runtimeDigestPattern.MatchString(b.PrincipalSHA256) {
		return fmt.Errorf("%w: authenticated principalSha256 is invalid", ErrRuntimeInvalid)
	}
	return nil
}

// FreezeAudience derives one immutable binding from the complete authenticated
// channel session. There is deliberately no recipient-list or first-recipient
// fallback contract.
func FreezeAudience(session ChannelSession) (AudienceBinding, error) {
	for _, value := range []string{session.TenantID, session.SiteID, session.Channel, session.ConversationRef, session.RecipientRef} {
		if !validRuntimeRef(value) {
			return AudienceBinding{}, ErrRuntimeInvalid
		}
	}
	if !runtimeDigestPattern.MatchString(session.PrincipalSHA256) {
		return AudienceBinding{}, ErrRuntimeInvalid
	}
	raw, err := json.Marshal(audienceIdentity{
		Schema: "cosmoedge.inspection.channel-audience.v1", TenantID: session.TenantID, SiteID: session.SiteID,
		Channel: session.Channel, ConversationRef: session.ConversationRef, RecipientRef: session.RecipientRef,
		PrincipalSHA256: session.PrincipalSHA256,
	})
	if err != nil {
		return AudienceBinding{}, ErrRuntimeInvalid
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	return AudienceBinding{Ref: "audience_" + digest[:32], SHA256: digest}, nil
}

// RunIDForScope is the one pre-publication runtime identity. It lets
// mediaprep bind the future media descriptor to the exact runtime request
// before the temporary runtime record exists.
func RunIDForScope(tenantID, siteID, requestKey string) (string, error) {
	for _, value := range []string{tenantID, siteID, requestKey} {
		if !validRuntimeRef(value) {
			return "", ErrRuntimeInvalid
		}
	}
	sum := sha256.Sum256([]byte("temporary-runtime\x00" + tenantID + "\x00" + siteID + "\x00" + requestKey))
	return "temporary_" + hex.EncodeToString(sum[:16]), nil
}

// MediaStepIDForRun is the immutable publication step bound into the media
// descriptor. It is public only so the planner and read adapter can agree on
// the same protected contract.
func MediaStepIDForRun(runID string) (string, error) {
	if !validRuntimeRef(runID) {
		return "", ErrRuntimeInvalid
	}
	sum := sha256.Sum256([]byte("temporary-media-step\x00" + runID))
	return "tempmedia_" + hex.EncodeToString(sum[:16]), nil
}

func (s Submission) validate() error {
	if err := s.Binding.validate(); err != nil {
		return err
	}
	if err := s.Spec.Validate(); err != nil {
		return errors.Join(ErrRuntimeInvalid, err)
	}
	audience, err := FreezeAudience(ChannelSession{
		TenantID: s.Binding.TenantID, SiteID: s.Binding.SiteID, Channel: s.Binding.Channel,
		ConversationRef: s.Binding.ConversationRef, RecipientRef: s.Binding.RecipientRef,
		PrincipalSHA256: s.Binding.PrincipalSHA256,
	})
	preparationRef, preparationErr := mediaprep.PreparationRefForScope(s.Binding.TenantID, s.Binding.SiteID, s.Binding.RequestKey)
	if err != nil || audience.Ref != s.AudienceBindingRef || audience.SHA256 != s.AudienceSHA256 ||
		preparationErr != nil || preparationRef != s.PreparationRef || !runtimePrepRefPattern.MatchString(s.PreparationRef) ||
		!validRuntimeMediaKind(s.MediaKind) ||
		!isRuntimeUTC(s.SubmittedAt) || !isRuntimeUTC(s.EvidenceExpiresAt) || !isRuntimeUTC(s.DeadlineAt) ||
		s.SubmittedAt.IsZero() || s.DeadlineAt.IsZero() ||
		s.EvidenceExpiresAt.IsZero() || !s.EvidenceExpiresAt.After(s.SubmittedAt) ||
		!s.DeadlineAt.After(s.SubmittedAt) || s.DeadlineAt.Sub(s.SubmittedAt) > MaxRunDuration ||
		!s.EvidenceExpiresAt.Equal(s.SubmittedAt.Add(time.Duration(s.Spec.EvidenceTTLSeconds)*time.Second)) ||
		s.DeadlineAt.After(s.EvidenceExpiresAt) {
		return ErrRuntimeInvalid
	}
	if s.Spec.TimeScope.Kind == TimeScopeCurrent && s.MediaKind != media.KindImage ||
		s.Spec.TimeScope.Kind == TimeScopeRecentWindow && s.MediaKind != media.KindVideoClip {
		return ErrRuntimeInvalid
	}
	return nil
}

func submissionIdentity(s Submission) (string, string, error) {
	if err := s.validate(); err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(frozenIdentity{
		Schema: RuntimeSchemaVersion, Binding: s.Binding, Spec: s.Spec,
		PreparationRef: s.PreparationRef, MediaKind: s.MediaKind, AudienceBindingRef: s.AudienceBindingRef,
		AudienceSHA256: s.AudienceSHA256, EvidenceExpiresAt: s.EvidenceExpiresAt,
		DeadlineAt: s.DeadlineAt,
	})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	runID, err := RunIDForScope(s.Binding.TenantID, s.Binding.SiteID, s.Binding.RequestKey)
	if err != nil {
		return "", "", err
	}
	return runID, digest, nil
}

func (d MediaDescriptor) validate(record Record, at time.Time) error {
	stepID, err := MediaStepIDForRun(record.RunID)
	if err != nil {
		return ErrRuntimeInvalid
	}
	if d.Temporal.WindowStart == nil || d.Temporal.WindowEnd == nil {
		return ErrRuntimeInvalid
	}
	if d.Temporal.WindowStart.Location() != time.UTC || d.Temporal.WindowEnd.Location() != time.UTC || d.ExpiresAt.Location() != time.UTC {
		return ErrRuntimeInvalid
	}
	windowStart, windowEnd := d.Temporal.WindowStart.UTC(), d.Temporal.WindowEnd.UTC()
	if !runtimeMediaRefPattern.MatchString(d.MediaRef) || d.MediaRef != record.MediaRef || d.Kind != record.MediaKind ||
		d.TenantID != record.Binding.TenantID || d.SiteID != record.Binding.SiteID || d.RunID != record.RunID ||
		d.StepID != stepID || d.Attempt != 1 || d.AudienceBindingRef != record.AudienceBindingRef ||
		!runtimeDigestPattern.MatchString(d.SHA256) || !validMIMEType(d.MIMEType) ||
		d.SizeBytes < 1 || d.SizeBytes > MaxMediaBytes || d.Temporal.SampleOrdinal != 0 || d.Temporal.DurationMillis < 0 ||
		windowStart.IsZero() || windowEnd.IsZero() || windowEnd.Before(windowStart) ||
		windowEnd.Sub(windowStart) != time.Duration(d.Temporal.DurationMillis)*time.Millisecond || d.ExpiresAt.IsZero() ||
		!d.ExpiresAt.After(windowEnd) ||
		!d.ExpiresAt.Equal(record.EvidenceExpiresAt) || d.ExpiresAt.Sub(windowEnd) > 30*24*time.Hour {
		return ErrRuntimeInvalid
	}
	if !at.IsZero() && windowEnd.After(at.UTC().Add(2*time.Minute)) {
		return ErrRuntimeInvalid
	}
	switch record.Spec.TimeScope.Kind {
	case TimeScopeCurrent:
		if d.Kind != media.KindImage || d.MIMEType != "image/jpeg" && d.MIMEType != "image/png" ||
			d.Temporal.DurationMillis != 0 || !windowStart.Equal(windowEnd) || windowEnd.Before(record.SubmittedAt) {
			return ErrRuntimeInvalid
		}
	case TimeScopeRecentWindow:
		expectedStart := record.SubmittedAt.Add(-time.Duration(record.Spec.TimeScope.WindowSeconds) * time.Second)
		if d.Kind != media.KindVideoClip || d.MIMEType != "video/mp4" || !windowStart.Equal(expectedStart) ||
			!windowEnd.Equal(record.SubmittedAt) || d.Temporal.DurationMillis != int64(record.Spec.TimeScope.WindowSeconds)*1000 {
			return ErrRuntimeInvalid
		}
	default:
		return ErrRuntimeInvalid
	}
	return nil
}

func validRuntimeMediaKind(kind media.Kind) bool {
	return kind == media.KindImage || kind == media.KindVideoClip
}

func validMIMEType(value string) bool {
	switch value {
	case "image/jpeg", "image/png", "video/mp4":
		return true
	default:
		return false
	}
}

func validRuntimeRef(value string) bool {
	return strings.TrimSpace(value) == value && runtimeRefPattern.MatchString(value) &&
		!urlPattern.MatchString(value) && !credentialPattern.MatchString(value) &&
		!nativeIdentifierPattern.MatchString(value) && !ipv4Pattern.MatchString(value) &&
		!base64Pattern.MatchString(value)
}

func validReason(reason Reason) bool {
	switch reason {
	case ReasonSubmitted, ReasonClaimed, ReasonPreparationPending, ReasonPreparationReady,
		ReasonPreparationFailed, ReasonPreparationExpired, ReasonRecoveredBeforeAnalysis, ReasonCompleted,
		ReasonCandidateInvalid, ReasonDeadlineExpired, ReasonAnalysisOutcomeUnknown,
		ReasonAnalysisDefinitelyFailed, ReasonMediaUnavailable, ReasonMediaInvalid:
		return true
	default:
		return false
	}
}

func validateRecord(record Record) error {
	if record.Schema != RuntimeSchemaVersion || !validRuntimeRef(record.RunID) ||
		!runtimeDigestPattern.MatchString(record.IdentitySHA256) || record.Binding.validate() != nil ||
		record.Spec.Validate() != nil || !runtimePrepRefPattern.MatchString(record.PreparationRef) || !validRuntimeMediaKind(record.MediaKind) ||
		!validRuntimeRef(record.AudienceBindingRef) || !runtimeDigestPattern.MatchString(record.AudienceSHA256) ||
		record.EvidenceExpiresAt.IsZero() || !isRuntimeUTC(record.EvidenceExpiresAt) ||
		record.MediaRef != "" && !runtimeMediaRefPattern.MatchString(record.MediaRef) ||
		!validReason(record.Reason) || record.Attempt < 0 || record.Attempt > 1 ||
		record.PreparationPolls < 0 || record.PreparationPolls > MaxPrepPolls || record.Generation == 0 ||
		record.SubmittedAt.IsZero() || record.DeadlineAt.IsZero() || record.AvailableAt.IsZero() || record.UpdatedAt.IsZero() ||
		!isRuntimeUTC(record.SubmittedAt) || !isRuntimeUTC(record.DeadlineAt) ||
		!isRuntimeUTC(record.AvailableAt) || !isRuntimeUTC(record.UpdatedAt) ||
		record.DeadlineAt.Sub(record.SubmittedAt) <= 0 || record.DeadlineAt.Sub(record.SubmittedAt) > MaxRunDuration ||
		record.UpdatedAt.Before(record.SubmittedAt) {
		return ErrRuntimeCorrupt
	}
	identityRunID, identityDigest, err := submissionIdentity(Submission{
		Binding: record.Binding, Spec: record.Spec, PreparationRef: record.PreparationRef, MediaKind: record.MediaKind,
		AudienceBindingRef: record.AudienceBindingRef, AudienceSHA256: record.AudienceSHA256,
		EvidenceExpiresAt: record.EvidenceExpiresAt,
		SubmittedAt:       record.SubmittedAt, DeadlineAt: record.DeadlineAt,
	})
	if err != nil || identityRunID != record.RunID || identityDigest != record.IdentitySHA256 {
		return ErrRuntimeCorrupt
	}
	if record.PromptSHA256 != "" && !runtimeDigestPattern.MatchString(record.PromptSHA256) {
		return ErrRuntimeCorrupt
	}
	if record.Media != nil && record.Media.validate(record, time.Time{}) != nil {
		return ErrRuntimeCorrupt
	}
	if record.Candidate != nil && record.Candidate.Validate() != nil {
		return ErrRuntimeCorrupt
	}
	if record.Observation != nil && record.Observation.Validate() != nil {
		return ErrRuntimeCorrupt
	}
	if record.ResultRef != "" && !validRuntimeRef(record.ResultRef) {
		return ErrRuntimeCorrupt
	}
	if record.ResultSHA256 != "" && !runtimeDigestPattern.MatchString(record.ResultSHA256) {
		return ErrRuntimeCorrupt
	}
	if record.CompletedAt.IsZero() != !record.State.Terminal() ||
		!record.CompletedAt.IsZero() && (!isRuntimeUTC(record.CompletedAt) || record.CompletedAt.Before(record.SubmittedAt)) {
		return ErrRuntimeCorrupt
	}

	switch record.State {
	case StateQueued:
		if record.Phase != PhaseNone || record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() ||
			record.PromptSHA256 != "" || record.Media != nil || record.Candidate != nil || record.Observation != nil ||
			record.ResultRef != "" || record.ResultSHA256 != "" || record.CompletedAt.IsZero() == false {
			return ErrRuntimeCorrupt
		}
		if record.MediaRef != "" || record.Media != nil {
			return ErrRuntimeCorrupt
		}
		if record.Attempt != 0 || record.Reason != ReasonSubmitted && record.Reason != ReasonPreparationPending && record.Reason != ReasonRecoveredBeforeAnalysis ||
			record.Reason == ReasonSubmitted && record.PreparationPolls != 0 || record.Reason == ReasonPreparationPending && record.PreparationPolls < 1 {
			return ErrRuntimeCorrupt
		}
	case StateRunning:
		if record.Phase != PhasePreparing && record.Phase != PhaseAnalyzing || !validRuntimeRef(record.LeaseOwner) ||
			!isRuntimeUTC(record.LeaseExpiresAt) || !record.LeaseExpiresAt.After(record.UpdatedAt) ||
			record.Candidate != nil || record.Observation != nil || record.ResultRef != "" || record.ResultSHA256 != "" {
			return ErrRuntimeCorrupt
		}
		if record.Phase == PhasePreparing && (record.PromptSHA256 != "" || record.Media != nil || record.MediaRef != "") ||
			record.Phase == PhaseAnalyzing && (record.PromptSHA256 == "" || record.Media == nil || record.MediaRef == "" || record.Attempt < 1) {
			return ErrRuntimeCorrupt
		}
		if record.Phase == PhasePreparing && (record.Reason != ReasonClaimed || record.Attempt != 0) ||
			record.Phase == PhaseAnalyzing && record.Reason != ReasonPreparationReady {
			return ErrRuntimeCorrupt
		}
	case StateSucceeded:
		if record.Phase != PhaseNone || record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() ||
			record.Media == nil || record.Candidate == nil || record.Observation == nil || record.PromptSHA256 == "" ||
			record.ResultRef == "" || record.ResultSHA256 == "" {
			return ErrRuntimeCorrupt
		}
		if record.MediaRef == "" || record.Observation.IntentSHA256 != record.Spec.NormalizedIntentSHA256 ||
			len(record.Observation.EvidenceRefs) != 1 || record.Observation.EvidenceRefs[0] != record.MediaRef {
			return ErrRuntimeCorrupt
		}
		if record.Reason != ReasonCompleted || record.Attempt < 1 {
			return ErrRuntimeCorrupt
		}
		if record.Candidate.Answer != record.Observation.Answer || record.Candidate.Summary != record.Observation.Summary ||
			!equalRuntimeStrings(record.Candidate.VisibleFacts, record.Observation.VisibleFacts) ||
			!equalRuntimeStrings(record.Candidate.Limitations, record.Observation.Limitations) ||
			len(record.Candidate.EvidenceRefs) != 1 || record.Candidate.EvidenceRefs[0] != record.MediaRef {
			return ErrRuntimeCorrupt
		}
		digest, err := resultDigest(*record.Candidate, *record.Observation)
		if err != nil || digest != record.ResultSHA256 {
			return ErrRuntimeCorrupt
		}
	case StateInvalidCandidate:
		if record.Phase != PhaseNone || record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() ||
			record.Media == nil || record.PromptSHA256 == "" || record.Candidate != nil || record.Observation != nil ||
			record.MediaRef == "" || record.ResultRef == "" || record.ResultSHA256 != "" {
			return ErrRuntimeCorrupt
		}
		if record.Reason != ReasonCandidateInvalid || record.Attempt < 1 {
			return ErrRuntimeCorrupt
		}
	case StateOutcomeUnknown:
		if record.Phase != PhaseNone || record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() ||
			record.Media == nil || record.PromptSHA256 == "" || record.Candidate != nil || record.Observation != nil ||
			record.MediaRef == "" || record.ResultRef == "" || record.ResultSHA256 != "" {
			return ErrRuntimeCorrupt
		}
		if record.Reason != ReasonAnalysisOutcomeUnknown || record.Attempt < 1 {
			return ErrRuntimeCorrupt
		}
	case StateExpired:
		if record.Phase != PhaseNone || record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() ||
			record.Candidate != nil || record.Observation != nil || record.ResultRef == "" || record.ResultSHA256 != "" {
			return ErrRuntimeCorrupt
		}
		if record.Reason != ReasonDeadlineExpired && record.Reason != ReasonPreparationExpired || record.Attempt != 0 ||
			record.MediaRef != "" || record.Media != nil || record.PromptSHA256 != "" {
			return ErrRuntimeCorrupt
		}
	case StateFailed:
		if record.Phase != PhaseNone || record.LeaseOwner != "" || !record.LeaseExpiresAt.IsZero() ||
			record.Candidate != nil || record.Observation != nil || record.ResultRef == "" || record.ResultSHA256 != "" {
			return ErrRuntimeCorrupt
		}
		switch record.Reason {
		case ReasonAnalysisDefinitelyFailed:
			if record.Attempt < 1 || record.MediaRef == "" || record.Media == nil || record.PromptSHA256 == "" {
				return ErrRuntimeCorrupt
			}
		case ReasonPreparationFailed, ReasonMediaUnavailable, ReasonMediaInvalid:
			if record.Attempt != 0 || record.MediaRef != "" || record.Media != nil || record.PromptSHA256 != "" {
				return ErrRuntimeCorrupt
			}
		default:
			return ErrRuntimeCorrupt
		}
	default:
		return ErrRuntimeCorrupt
	}
	if record.Attempt == 0 && (record.MediaRef != "" || record.Media != nil || record.PromptSHA256 != "") {
		return ErrRuntimeCorrupt
	}
	if record.MediaRef == "" && record.Media != nil {
		return ErrRuntimeCorrupt
	}
	return nil
}

func equalRuntimeStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func resultDigest(candidate Candidate, observation Observation) (string, error) {
	raw, err := json.Marshal(struct {
		Candidate   Candidate   `json:"candidate"`
		Observation Observation `json:"observation"`
	}{candidate, observation})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func resultRef(runID string) string {
	sum := sha256.Sum256([]byte("temporary-result\x00" + runID))
	return "tempresult_" + hex.EncodeToString(sum[:16])
}

func terminalEventFor(record Record) (TerminalEvent, error) {
	if err := validateRecord(record); err != nil || !record.State.Terminal() {
		return TerminalEvent{}, ErrRuntimeCorrupt
	}
	sum := sha256.Sum256([]byte("temporary-terminal\x00" + record.RunID))
	event := TerminalEvent{
		Schema: TerminalSchemaVersion, EventID: "tempevent_" + hex.EncodeToString(sum[:16]),
		RunID: record.RunID, PublicRunRef: record.Binding.PublicRunRef,
		ResultRef: record.ResultRef, State: record.State, ResultSHA256: record.ResultSHA256,
		OccurredAt: record.CompletedAt,
	}
	if err := validateTerminalEvent(event); err != nil {
		return TerminalEvent{}, err
	}
	return event, nil
}

func validateTerminalEvent(event TerminalEvent) error {
	if event.Schema != TerminalSchemaVersion || !validRuntimeRef(event.EventID) || !validRuntimeRef(event.RunID) ||
		!validRuntimeRef(event.PublicRunRef) || !validRuntimeRef(event.ResultRef) || !event.State.Terminal() ||
		event.OccurredAt.IsZero() || !isRuntimeUTC(event.OccurredAt) ||
		(event.State == StateSucceeded) != runtimeDigestPattern.MatchString(event.ResultSHA256) {
		return ErrRuntimeCorrupt
	}
	return nil
}

func isRuntimeUTC(value time.Time) bool { return value.Location() == time.UTC }

func cloneRecord(record Record) Record {
	clone := record
	if record.Media != nil {
		value := *record.Media
		value.Temporal = cloneRuntimeTemporal(record.Media.Temporal)
		clone.Media = &value
	}
	if record.Candidate != nil {
		value := *record.Candidate
		value.VisibleFacts = cloneRuntimeStrings(record.Candidate.VisibleFacts)
		value.Limitations = cloneRuntimeStrings(record.Candidate.Limitations)
		value.EvidenceRefs = cloneRuntimeStrings(record.Candidate.EvidenceRefs)
		clone.Candidate = &value
	}
	if record.Observation != nil {
		value := *record.Observation
		value.VisibleFacts = cloneRuntimeStrings(record.Observation.VisibleFacts)
		value.Limitations = cloneRuntimeStrings(record.Observation.Limitations)
		value.EvidenceRefs = cloneRuntimeStrings(record.Observation.EvidenceRefs)
		clone.Observation = &value
	}
	return clone
}

func cloneRuntimeTemporal(value media.Temporal) media.Temporal {
	clone := value
	if value.WindowStart != nil {
		start := value.WindowStart.UTC()
		clone.WindowStart = &start
	}
	if value.WindowEnd != nil {
		end := value.WindowEnd.UTC()
		clone.WindowEnd = &end
	}
	return clone
}

func cloneRuntimeStrings(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}
