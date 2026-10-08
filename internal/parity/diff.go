package parity

import (
	"errors"
	"fmt"
	"sort"
)

type Difference struct {
	Scenario  string `json:"scenario"`
	Field     string `json:"field"`
	Baseline  any    `json:"baseline,omitempty"`
	Candidate any    `json:"candidate,omitempty"`
}

type AllowedDifference struct {
	Difference
	Reason string `json:"reason"`
}

func DiffNormalized(baseline, candidate []NormalizedResult, allowed []AllowedDifference) ([]Difference, error) {
	baselineIndex, err := indexNormalized(baseline)
	if err != nil {
		return nil, fmt.Errorf("baseline results: %w", err)
	}
	candidateIndex, err := indexNormalized(candidate)
	if err != nil {
		return nil, fmt.Errorf("candidate results: %w", err)
	}
	allowedIndex := make(map[string]AllowedDifference, len(allowed))
	for _, item := range allowed {
		if item.Scenario == "" || item.Field == "" || item.Reason == "" {
			return nil, errors.New("allowed difference requires scenario, field, and reason")
		}
		key := differenceKey(item.Scenario, item.Field)
		if _, exists := allowedIndex[key]; exists {
			return nil, fmt.Errorf("duplicate allowed difference %s", key)
		}
		allowedIndex[key] = item
	}

	var differences []Difference
	for scenario, before := range baselineIndex {
		after, exists := candidateIndex[scenario]
		if !exists {
			differences = append(differences, Difference{Scenario: scenario, Field: "scenario", Baseline: "present", Candidate: "missing"})
			continue
		}
		delete(candidateIndex, scenario)
		beforeFields, afterFields := normalizedFields(before), normalizedFields(after)
		for field, baselineValue := range beforeFields {
			candidateValue := afterFields[field]
			if baselineValue == candidateValue {
				continue
			}
			difference := Difference{Scenario: scenario, Field: field, Baseline: baselineValue, Candidate: candidateValue}
			if correction, ok := allowedIndex[differenceKey(scenario, field)]; ok && correction.Baseline == baselineValue && correction.Candidate == candidateValue {
				continue
			}
			differences = append(differences, difference)
		}
	}
	for scenario := range candidateIndex {
		differences = append(differences, Difference{Scenario: scenario, Field: "scenario", Baseline: "missing", Candidate: "present"})
	}
	sort.Slice(differences, func(i, j int) bool {
		if differences[i].Scenario == differences[j].Scenario {
			return differences[i].Field < differences[j].Field
		}
		return differences[i].Scenario < differences[j].Scenario
	})
	return differences, nil
}

func indexNormalized(results []NormalizedResult) (map[string]NormalizedResult, error) {
	index := make(map[string]NormalizedResult, len(results))
	for _, result := range results {
		if result.Scenario == "" {
			return nil, errors.New("scenario is required")
		}
		if _, exists := index[result.Scenario]; exists {
			return nil, fmt.Errorf("duplicate scenario %q", result.Scenario)
		}
		index[result.Scenario] = result
	}
	return index, nil
}

func normalizedFields(result NormalizedResult) map[string]any {
	return map[string]any{
		"class": result.Class, "conclusion": result.Conclusion,
		"evidenceStatus": result.EvidenceStatus,
		"taskName":       result.TaskName, "cameraName": result.CameraName, "algorithmName": result.AlgorithmName,
		"canPrepare": result.CanPrepare, "canConfirm": result.CanConfirm, "canCancel": result.CanCancel, "canUndo": result.CanUndo,
		"deviceWrites": result.DeviceWrites, "dispatches": result.Dispatches,
	}
}

func differenceKey(scenario, field string) string {
	return scenario + "\x00" + field
}
