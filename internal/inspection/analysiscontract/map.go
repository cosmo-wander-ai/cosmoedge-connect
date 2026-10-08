package analysiscontract

import "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"

// TypedResult is the only conversion across the analyzer boundary. It retains
// exact trusted bindings and a strict domain union while dropping no execution
// facts. Standard report composition deliberately ignores Display.
func (e Envelope) TypedResult() (inspection.AnalysisResult, error) {
	if err := e.Validate(); err != nil {
		return inspection.AnalysisResult{}, err
	}
	return cloneAnalysisResult(e.typedResultUnchecked()), nil
}

func (e Envelope) typedResultUnchecked() inspection.AnalysisResult {
	result := inspection.AnalysisResult{
		Binding:       cloneBinding(e.Binding),
		Assessment:    e.Candidate.Assessment,
		Observability: e.Candidate.Observability,
		Confidence:    cloneFloat(e.Candidate.Confidence),
		Value:         cloneResultValue(e.Candidate.Value),
		EvidenceRefs:  append([]string(nil), e.Candidate.EvidenceRefs...),
		ReasonCodes:   reasonStrings(e.Candidate.ReasonCodes),
		Limitations:   limitationStrings(e.Candidate.Limitations),
		Analyzer:      e.Analyzer,
		Execution:     e.Execution,
		Integrity:     e.Integrity,
	}
	if e.Candidate.DisplayText != "" && e.DisplayPolicy != nil {
		result.Display = &inspection.PolicyBoundDisplay{
			PolicyRef: e.DisplayPolicy.PolicyRef,
			Locale:    e.DisplayPolicy.Locale,
			Text:      e.Candidate.DisplayText,
		}
	}
	return result
}

func cloneAnalysisResult(value inspection.AnalysisResult) inspection.AnalysisResult {
	clone := value
	clone.Binding = cloneBinding(value.Binding)
	clone.Confidence = cloneFloat(value.Confidence)
	clone.Value = cloneResultValue(value.Value)
	clone.EvidenceRefs = append([]string(nil), value.EvidenceRefs...)
	clone.ReasonCodes = append([]string(nil), value.ReasonCodes...)
	clone.Limitations = append([]string(nil), value.Limitations...)
	if value.Display != nil {
		display := *value.Display
		clone.Display = &display
	}
	return clone
}

func reasonStrings(values []ReasonCode) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func limitationStrings(values []Limitation) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}
