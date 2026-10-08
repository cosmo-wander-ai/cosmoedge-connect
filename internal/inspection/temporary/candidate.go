package temporary

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

func (c Candidate) Validate() error {
	if c.Answer != "" && !c.Answer.Valid() {
		return errors.New("temporary observation answer is invalid")
	}
	if c.Schema != CandidateSchemaVersion {
		return fmt.Errorf("temporary observation candidate schema must equal %q", CandidateSchemaVersion)
	}
	summary, err := normalizeApprovedText("candidate summary", c.Summary, MaxCandidateSummaryRunes)
	if err != nil {
		return err
	}
	if summary != c.Summary {
		return errors.New("temporary observation candidate summary is not normalized")
	}
	if err := validateUniqueTextList("visible facts", c.VisibleFacts, MaxCandidateVisibleFacts, MaxCandidateVisibleFactRunes, false); err != nil {
		return err
	}
	if err := validateUniqueTextList("limitations", c.Limitations, MaxCandidateLimitations, MaxCandidateLimitationRunes, false); err != nil {
		return err
	}
	if len(c.VisibleFacts) == 0 && len(c.Limitations) == 0 {
		return errors.New("temporary observation candidate requires a visible fact or limitation")
	}
	if c.EvidenceRefs == nil || len(c.EvidenceRefs) != MaxCandidateEvidenceRefs {
		return errors.New("temporary observation candidate evidenceRefs must contain exactly one entry")
	}
	seen := make(map[string]struct{}, len(c.EvidenceRefs))
	for _, ref := range c.EvidenceRefs {
		if err := validateEvidenceRef(ref); err != nil {
			return err
		}
		if _, duplicate := seen[ref]; duplicate {
			return fmt.Errorf("temporary observation candidate repeats evidence reference %q", ref)
		}
		seen[ref] = struct{}{}
	}
	return nil
}

// BindCandidate combines validated model-owned content with trusted intent,
// evidence, and retention facts. The resulting expiry is the earliest of the
// requested TTL and every referenced evidence object's expiry.
func BindCandidate(spec TemporaryObservationSpec, candidate Candidate, available []EvidenceBinding, generatedAt time.Time) (Observation, error) {
	if err := spec.Validate(); err != nil {
		return Observation{}, fmt.Errorf("bind temporary observation spec: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return Observation{}, fmt.Errorf("bind temporary observation candidate: %w", err)
	}
	if generatedAt.IsZero() {
		return Observation{}, errors.New("temporary observation generation time is required")
	}
	generatedAt = generatedAt.UTC()
	if len(available) < 1 || len(available) > 32 {
		return Observation{}, errors.New("temporary observation available evidence count is invalid")
	}
	evidence := make(map[string]time.Time, len(available))
	for _, binding := range available {
		if err := validateEvidenceRef(binding.EvidenceRef); err != nil {
			return Observation{}, err
		}
		if binding.ExpiresAt.IsZero() || !binding.ExpiresAt.After(generatedAt) {
			return Observation{}, fmt.Errorf("temporary observation evidence %q is unavailable or expired", binding.EvidenceRef)
		}
		if _, duplicate := evidence[binding.EvidenceRef]; duplicate {
			return Observation{}, fmt.Errorf("temporary observation available evidence repeats %q", binding.EvidenceRef)
		}
		evidence[binding.EvidenceRef] = binding.ExpiresAt.UTC()
	}

	expiresAt := generatedAt.Add(time.Duration(spec.EvidenceTTLSeconds) * time.Second)
	refs := append([]string(nil), candidate.EvidenceRefs...)
	for _, ref := range refs {
		evidenceExpiry, ok := evidence[ref]
		if !ok {
			return Observation{}, fmt.Errorf("temporary observation candidate references unbound evidence %q", ref)
		}
		if evidenceExpiry.Before(expiresAt) {
			expiresAt = evidenceExpiry
		}
	}
	sort.Strings(refs)
	observation := Observation{
		Schema: ObservationSchemaVersion, IntentSHA256: spec.NormalizedIntentSHA256,
		Answer:  candidate.Answer,
		Summary: candidate.Summary, VisibleFacts: clonePresentStrings(candidate.VisibleFacts),
		Limitations: clonePresentStrings(candidate.Limitations), EvidenceRefs: refs,
		GeneratedAt: generatedAt, ExpiresAt: expiresAt,
	}
	if err := observation.Validate(); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func (o Observation) Validate() error {
	if o.Schema != ObservationSchemaVersion {
		return errors.New("temporary observation result schema is invalid")
	}
	if !sha256Pattern.MatchString(o.IntentSHA256) {
		return errors.New("temporary observation result intent digest is invalid")
	}
	candidate := Candidate{
		Schema: CandidateSchemaVersion, Summary: o.Summary, Answer: o.Answer,
		VisibleFacts: o.VisibleFacts, Limitations: o.Limitations, EvidenceRefs: o.EvidenceRefs,
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("temporary observation result content: %w", err)
	}
	if o.GeneratedAt.IsZero() || o.ExpiresAt.IsZero() || !o.ExpiresAt.After(o.GeneratedAt) ||
		o.ExpiresAt.After(o.GeneratedAt.Add(MaxEvidenceTTLSeconds*time.Second)) {
		return errors.New("temporary observation result retention window is invalid")
	}
	for index := 1; index < len(o.EvidenceRefs); index++ {
		if o.EvidenceRefs[index-1] >= o.EvidenceRefs[index] {
			return errors.New("temporary observation result evidence references are not uniquely sorted")
		}
	}
	return nil
}

func clonePresentStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}
