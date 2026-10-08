// Package analysiscontract defines the trust boundary between untrusted
// analyzer output and CosmoEdge Connect-owned inspection result bindings.
package analysiscontract

import (
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const (
	SchemaVersion = "inspection.analysis.v2"
	MaxJSONBytes  = 64 << 10
	MaxJSONDepth  = 16
)

type Limitation string

const (
	LimitationOcclusion           Limitation = "occlusion"
	LimitationLowLight            Limitation = "low_light"
	LimitationGlare               Limitation = "glare"
	LimitationMotionBlur          Limitation = "motion_blur"
	LimitationLowResolution       Limitation = "low_resolution"
	LimitationOutOfFrame          Limitation = "out_of_frame"
	LimitationStaleCapture        Limitation = "stale_capture"
	LimitationInsufficientSamples Limitation = "insufficient_samples"
	LimitationConflictingSamples  Limitation = "conflicting_samples"
	LimitationCriterionNotVisual  Limitation = "criterion_not_visual"
	LimitationAnalyzerLimit       Limitation = "analyzer_limit"
)

type ReasonCode string

const (
	ReasonCriterionMet         ReasonCode = "criterion_met"
	ReasonCriterionViolated    ReasonCode = "criterion_violated"
	ReasonInsufficientEvidence ReasonCode = "insufficient_evidence"
	ReasonNotVisible           ReasonCode = "not_visible"
	ReasonUnusableMedia        ReasonCode = "unusable_media"
	ReasonInvalidModelOutput   ReasonCode = "invalid_model_output"
	ReasonAnalyzerTimeout      ReasonCode = "analyzer_timeout"
	ReasonUnsupportedCriterion ReasonCode = "unsupported_criterion"
	ReasonInconsistentSamples  ReasonCode = "inconsistent_samples"
)

// Candidate is the only model-controlled part of an analysis envelope. Its
// typed value is domain-owned; there is no free-form facts object or summary.
type Candidate struct {
	Assessment    inspection.Assessment          `json:"assessment"`
	Observability inspection.ResultObservability `json:"observability"`
	Confidence    *float64                       `json:"confidence,omitempty"`
	Value         *inspection.ResultValue        `json:"value,omitempty"`
	EvidenceRefs  []string                       `json:"evidenceRefs"`
	Limitations   []Limitation                   `json:"limitations"`
	ReasonCodes   []ReasonCode                   `json:"reasonCodes"`
	DisplayText   string                         `json:"displayText,omitempty"`
}

// DisplayPolicy is a trusted admission policy. It may be present only for a
// temporary observation; the model never chooses its policy, locale, or cap.
type DisplayPolicy struct {
	PolicyRef string `json:"policyRef"`
	Locale    string `json:"locale"`
	MaxRunes  int    `json:"maxRunes"`
}

// Envelope keeps untrusted Candidate separate from every CosmoEdge Connect-owned fact.
type Envelope struct {
	SchemaVersion string                     `json:"schemaVersion"`
	Binding       inspection.ResultBinding   `json:"binding"`
	Analyzer      inspection.ResultAnalyzer  `json:"analyzer"`
	Candidate     Candidate                  `json:"candidate"`
	Execution     inspection.ResultExecution `json:"execution"`
	Integrity     inspection.ResultIntegrity `json:"integrity"`
	DisplayPolicy *DisplayPolicy             `json:"displayPolicy,omitempty"`
}

// TrustedFields intentionally excludes Candidate.
type TrustedFields struct {
	Binding       inspection.ResultBinding
	Analyzer      inspection.ResultAnalyzer
	Execution     inspection.ResultExecution
	Integrity     inspection.ResultIntegrity
	DisplayPolicy *DisplayPolicy
}
