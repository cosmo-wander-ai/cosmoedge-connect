// Package temporary defines the device-independent contract for one bounded,
// temporary visual observation. It deliberately contains no raw chat, device
// connection, native identifier, persistent-task, or tool-execution field.
package temporary

import "time"

const (
	SpecSchemaVersion        = "cosmoedge.inspection.temporary.spec.v2"
	CandidateSchemaVersion   = "cosmoedge.inspection.temporary.candidate.v2"
	ObservationSchemaVersion = "cosmoedge.inspection.temporary.observation.v2"
	PromptVersion            = "temporary-observation.v4"

	MaxRecentWindowSeconds = 10 * 60
	MinEvidenceTTLSeconds  = 60
	MaxEvidenceTTLSeconds  = 24 * 60 * 60
	MaxJSONBytes           = 32 << 10
	MaxJSONDepth           = 8

	// Candidate bounds deliberately keep the complete picture-VLM response
	// small enough for constrained edge models. The temporary runtime analyzes
	// one snapshot at a time, so one fact, one limitation, and one evidence
	// reference are sufficient for its complete, evidence-bound result.
	MaxCandidateJSONBytes        = 2 << 10
	MaxCandidateSummaryRunes     = 32
	MaxCandidateVisibleFacts     = 1
	MaxCandidateVisibleFactRunes = 48
	MaxCandidateLimitations      = 1
	MaxCandidateLimitationRunes  = 48
	MaxCandidateEvidenceRefs     = 1
)

type TimeScopeKind string

const (
	TimeScopeCurrent      TimeScopeKind = "current"
	TimeScopeRecentWindow TimeScopeKind = "recent_window"
)

// TimeScope is explicit even for a current observation. WindowSeconds must be
// zero for current and bounded for recent_window.
type TimeScope struct {
	Kind          TimeScopeKind `json:"kind"`
	WindowSeconds int           `json:"windowSeconds"`
}

// Intent contains normalized semantic fields only. Callers must extract these
// fields from a channel request before constructing a Spec; raw chat is not a
// member of this contract.
type Intent struct {
	Subject            string
	Region             string
	Observable         string
	Locale             string
	TimeScope          TimeScope
	EvidenceTTLSeconds int
}

// TemporaryObservationSpec is the only durable request contract for a
// temporary visual observation. NormalizedIntentSHA256 binds its complete
// normalized semantic content and retention policy.
type TemporaryObservationSpec struct {
	Schema                 string    `json:"schema"`
	Subject                string    `json:"subject"`
	Region                 string    `json:"region"`
	Observable             string    `json:"observable"`
	Locale                 string    `json:"locale"`
	TimeScope              TimeScope `json:"timeScope"`
	EvidenceTTLSeconds     int       `json:"evidenceTtlSeconds"`
	NormalizedIntentSHA256 string    `json:"normalizedIntentSha256"`
}

type CompiledPrompt struct {
	Version string
	Text    string
	SHA256  string

	// observable is copied from a validated Spec by CompilePrompt. Keeping it
	// private prevents adapters from accepting a second model- or caller-owned
	// description when they project a constrained model answer locally.
	observable string
}

// Observable returns the validated observation question bound into Text.
func (p CompiledPrompt) Observable() string { return p.observable }

// Candidate is the complete analyzer-owned JSON object. A live edge adapter
// may project a closed-vocabulary model answer into this strict shape, but the
// model never owns its schema or evidence references. It has no assessment,
// compliance, task, command, tool, or retention field. Trusted evidence and
// expiry are bound separately by BindCandidate.
type Candidate struct {
	Schema string `json:"schema"`
	// Answer is optional only for compatibility with earlier durable records.
	// New visual adapters preserve this closed value from model response onward.
	Answer       Answer   `json:"answer,omitempty"`
	Summary      string   `json:"summary"`
	VisibleFacts []string `json:"visibleFacts"`
	Limitations  []string `json:"limitations"`
	EvidenceRefs []string `json:"evidenceRefs"`
}

// EvidenceBinding is supplied by trusted runtime code, never by the model.
type EvidenceBinding struct {
	EvidenceRef string
	ExpiresAt   time.Time
}

// Observation is the bounded persistable projection. Candidate JSON bytes are
// intentionally absent; only validated text and trusted evidence bindings
// cross this boundary.
type Observation struct {
	Schema       string    `json:"schema"`
	IntentSHA256 string    `json:"intentSha256"`
	Answer       Answer    `json:"answer,omitempty"`
	Summary      string    `json:"summary"`
	VisibleFacts []string  `json:"visibleFacts"`
	Limitations  []string  `json:"limitations"`
	EvidenceRefs []string  `json:"evidenceRefs"`
	GeneratedAt  time.Time `json:"generatedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type Answer string

const (
	AnswerYes    Answer = "yes"
	AnswerNo     Answer = "no"
	AnswerUnable Answer = "unable"
)

func (a Answer) Valid() bool { return a == AnswerYes || a == AnswerNo || a == AnswerUnable }
