package analysiscontract

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

var (
	opaqueIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{8,96}$`)
	stableIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
	urlPattern       = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]{1,15}://|\bwww\.)`)
	dataURLPattern   = regexp.MustCompile(`(?i)data:[^,\s]{0,128};base64,`)
	base64Pattern    = regexp.MustCompile(`(?:^|[^A-Za-z0-9_+/.-])(?:[A-Za-z0-9_+/-]{128,}={0,2})(?:$|[^A-Za-z0-9_+/=-])`)
	protectedPattern = regexp.MustCompile(`(?i)(?:password|passwd|authorization|bearer|cookie|access[_-]?token|refresh[_-]?token|device[_-]?id|camera[_-]?id|image[_-]?base64|rtsp[_-]?url)`)
	ipv4Pattern      = regexp.MustCompile(`(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|[^0-9])`)
	macPattern       = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?:$|[^0-9a-f])`)
)

func (e Envelope) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must equal %q", SchemaVersion)
	}
	trusted := TrustedFields{
		Binding: e.Binding, Analyzer: e.Analyzer, Execution: e.Execution,
		Integrity: e.Integrity, DisplayPolicy: e.DisplayPolicy,
	}
	if err := trusted.Validate(); err != nil {
		return err
	}
	if err := e.Candidate.Validate(); err != nil {
		return err
	}
	if e.Candidate.DisplayText != "" {
		if e.DisplayPolicy == nil {
			return errors.New("candidate displayText has no trusted display policy")
		}
		if utf8.RuneCountInString(e.Candidate.DisplayText) > e.DisplayPolicy.MaxRunes {
			return errors.New("candidate displayText exceeds its trusted policy")
		}
	} else if e.DisplayPolicy != nil {
		return errors.New("unused display policy is not allowed")
	}
	result := e.typedResultUnchecked()
	if err := result.Validate(); err != nil {
		return fmt.Errorf("validate typed analysis result: %w", err)
	}
	return nil
}

func (c Candidate) Validate() error {
	if !c.Assessment.Valid() {
		return errors.New("candidate assessment is invalid")
	}
	if !c.Observability.Valid() {
		return errors.New("candidate observability is invalid")
	}
	if c.Confidence != nil && (math.IsNaN(*c.Confidence) || math.IsInf(*c.Confidence, 0) || *c.Confidence < 0 || *c.Confidence > 1) {
		return errors.New("candidate confidence must be between 0 and 1")
	}
	if len(c.EvidenceRefs) > 16 {
		return errors.New("candidate evidenceRefs contains more than 16 entries")
	}
	evidence := make(map[string]struct{}, len(c.EvidenceRefs))
	for _, ref := range c.EvidenceRefs {
		if err := validateOpaqueID("evidenceRef", ref); err != nil {
			return err
		}
		if _, duplicate := evidence[ref]; duplicate {
			return errors.New("candidate evidenceRefs repeats an entry")
		}
		evidence[ref] = struct{}{}
	}
	if c.Limitations == nil || len(c.Limitations) > 16 {
		return errors.New("candidate limitations must be present and bounded")
	}
	limitations := make(map[Limitation]struct{}, len(c.Limitations))
	for _, limitation := range c.Limitations {
		if !limitation.valid() {
			return fmt.Errorf("candidate limitation %q is invalid", limitation)
		}
		if _, duplicate := limitations[limitation]; duplicate {
			return fmt.Errorf("candidate limitation %q is repeated", limitation)
		}
		limitations[limitation] = struct{}{}
	}
	if len(c.ReasonCodes) < 1 || len(c.ReasonCodes) > 16 {
		return errors.New("candidate reasonCodes must contain 1 to 16 entries")
	}
	reasons := make(map[ReasonCode]struct{}, len(c.ReasonCodes))
	for _, reason := range c.ReasonCodes {
		if !reason.valid() {
			return fmt.Errorf("candidate reason code %q is invalid", reason)
		}
		if _, duplicate := reasons[reason]; duplicate {
			return fmt.Errorf("candidate reason code %q is repeated", reason)
		}
		reasons[reason] = struct{}{}
	}
	if c.DisplayText != "" {
		if err := validateUntrustedText("candidate displayText", c.DisplayText, 1, 1024); err != nil {
			return err
		}
	}
	if err := validateCandidateSemantics(c, limitations, reasons); err != nil {
		return err
	}
	if c.Value != nil {
		window := inspection.ResultTimeWindow{StartAt: time.Unix(1, 0).UTC(), EndAt: time.Unix(1, 0).UTC()}
		if c.Value.Event != nil {
			window.StartAt = c.Value.Event.OccurredAt
			window.EndAt = c.Value.Event.OccurredAt
		}
		if err := c.Value.Validate(c.EvidenceRefs, window); err != nil {
			return err
		}
	}
	return nil
}

func validateCandidateSemantics(c Candidate, limitations map[Limitation]struct{}, reasons map[ReasonCode]struct{}) error {
	hasReason := func(values ...ReasonCode) bool {
		for _, value := range values {
			if _, ok := reasons[value]; ok {
				return true
			}
		}
		return false
	}
	hasLimitation := func(values ...Limitation) bool {
		for _, value := range values {
			if _, ok := limitations[value]; ok {
				return true
			}
		}
		return false
	}
	if c.Observability == inspection.ResultFullyVisible && hasLimitation(LimitationOcclusion, LimitationOutOfFrame) {
		return errors.New("fully_visible is incompatible with occlusion or out_of_frame")
	}
	conclusive := c.Assessment == inspection.AssessmentMeetsRule || c.Assessment == inspection.AssessmentNeedsAttention
	if conclusive {
		if c.Value == nil || len(c.EvidenceRefs) == 0 {
			return errors.New("conclusive candidate requires a typed value and evidence")
		}
	} else if c.Value != nil {
		return errors.New("inconclusive candidate cannot carry a typed value")
	}
	switch c.Assessment {
	case inspection.AssessmentMeetsRule:
		if !hasReason(ReasonCriterionMet) || hasReason(ReasonCriterionViolated, ReasonInsufficientEvidence, ReasonInvalidModelOutput, ReasonAnalyzerTimeout, ReasonUnsupportedCriterion, ReasonInconsistentSamples) {
			return errors.New("meets_rule requires criterion_met without a contradictory reason")
		}
		if c.Observability == inspection.ResultNotVisible || c.Observability == inspection.ResultUnusable ||
			hasLimitation(LimitationOcclusion, LimitationOutOfFrame, LimitationStaleCapture, LimitationInsufficientSamples, LimitationConflictingSamples, LimitationCriterionNotVisual, LimitationAnalyzerLimit) {
			return errors.New("meets_rule is incompatible with a conclusion-limiting condition")
		}
	case inspection.AssessmentNeedsAttention:
		if !hasReason(ReasonCriterionViolated) || hasReason(ReasonCriterionMet, ReasonInsufficientEvidence, ReasonInvalidModelOutput, ReasonAnalyzerTimeout, ReasonUnsupportedCriterion, ReasonInconsistentSamples) {
			return errors.New("needs_attention requires criterion_violated without a contradictory reason")
		}
		if c.Observability == inspection.ResultNotVisible || c.Observability == inspection.ResultUnusable ||
			hasLimitation(LimitationStaleCapture, LimitationInsufficientSamples, LimitationConflictingSamples, LimitationCriterionNotVisual, LimitationAnalyzerLimit) {
			return errors.New("needs_attention is incompatible with a conclusion-limiting condition")
		}
	case inspection.AssessmentUncertain:
		if !hasReason(ReasonInsufficientEvidence, ReasonInvalidModelOutput, ReasonAnalyzerTimeout, ReasonInconsistentSamples) || hasReason(ReasonCriterionMet, ReasonCriterionViolated, ReasonUnsupportedCriterion) {
			return errors.New("uncertain requires an uncertainty reason without a conclusion")
		}
	case inspection.AssessmentNotObservable:
		if c.Observability != inspection.ResultNotVisible && c.Observability != inspection.ResultUnusable {
			return errors.New("not_observable requires not_visible or unusable observability")
		}
		if !hasReason(ReasonNotVisible, ReasonUnusableMedia) || hasReason(ReasonCriterionMet, ReasonCriterionViolated, ReasonUnsupportedCriterion) {
			return errors.New("not_observable requires a visibility reason without a conclusion")
		}
	case inspection.AssessmentUnsupported:
		if !hasReason(ReasonUnsupportedCriterion) || hasReason(ReasonCriterionMet, ReasonCriterionViolated) {
			return errors.New("unsupported requires unsupported_criterion without a conclusion")
		}
		if !hasLimitation(LimitationCriterionNotVisual, LimitationAnalyzerLimit) {
			return errors.New("unsupported requires criterion_not_visual or analyzer_limit")
		}
	}
	return nil
}

func (p DisplayPolicy) validate() error {
	if err := validateStableID("display policy", p.PolicyRef); err != nil {
		return err
	}
	if err := validateStableID("display locale", p.Locale); err != nil {
		return err
	}
	if p.MaxRunes < 1 || p.MaxRunes > 1024 {
		return errors.New("display policy maxRunes is outside the contract")
	}
	return nil
}

func (l Limitation) valid() bool {
	switch l {
	case LimitationOcclusion, LimitationLowLight, LimitationGlare, LimitationMotionBlur, LimitationLowResolution,
		LimitationOutOfFrame, LimitationStaleCapture, LimitationInsufficientSamples, LimitationConflictingSamples,
		LimitationCriterionNotVisual, LimitationAnalyzerLimit:
		return true
	default:
		return false
	}
}

func (r ReasonCode) valid() bool {
	switch r {
	case ReasonCriterionMet, ReasonCriterionViolated, ReasonInsufficientEvidence, ReasonNotVisible, ReasonUnusableMedia,
		ReasonInvalidModelOutput, ReasonAnalyzerTimeout, ReasonUnsupportedCriterion, ReasonInconsistentSamples:
		return true
	default:
		return false
	}
}

func validateOpaqueID(name, value string) error {
	if !opaqueIDPattern.MatchString(value) {
		return fmt.Errorf("%s is not a valid opaque identifier", name)
	}
	return nil
}

func validateStableID(name, value string) error {
	if !stableIDPattern.MatchString(value) {
		return fmt.Errorf("%s is not a valid stable identifier", name)
	}
	return nil
}

func validateUntrustedText(name, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum || strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s length is outside the contract", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	if urlPattern.MatchString(value) || dataURLPattern.MatchString(value) || base64Pattern.MatchString(value) || protectedPattern.MatchString(value) || ipv4Pattern.MatchString(value) || macPattern.MatchString(value) {
		return fmt.Errorf("%s contains protected data, a URL, or encoded media", name)
	}
	return nil
}
