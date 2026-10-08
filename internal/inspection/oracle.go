package inspection

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
)

type findingKey struct {
	targetID    string
	criterionID string
}

func Evaluate(plan ExecutionPlan, observations []Observation) (Outcome, error) {
	if err := plan.Validate(); err != nil {
		return Outcome{}, fmt.Errorf("validate inspection execution plan: %w", err)
	}
	known := map[findingKey]PlannedCriterion{}
	targets := map[findingKey]PlannedTarget{}
	expectedSamples := map[findingKey]int{}
	for _, target := range plan.Targets {
		for _, criterion := range target.Criteria {
			key := findingKey{targetID: target.TargetID, criterionID: criterion.Criterion.ID}
			known[key] = criterion
			targets[key] = target
			expectedSamples[key] = target.Acquisition.Samples
		}
	}
	byKey := map[findingKey][]Observation{}
	samplesByKey := map[findingKey]map[string]struct{}{}
	boundRunID := ""
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return Outcome{}, err
		}
		binding := observation.Result.Binding
		if binding.Usage != ResultUsageInspection || observation.Result.Display != nil {
			return Outcome{}, errors.New("temporary observation cannot enter the standard inspection Oracle")
		}
		if boundRunID == "" {
			boundRunID = binding.RunID
		} else if boundRunID != binding.RunID {
			return Outcome{}, errors.New("inspection observations span multiple runs")
		}
		key := findingKey{targetID: binding.TargetID, criterionID: binding.CriterionID}
		criterion, ok := known[key]
		if !ok {
			return Outcome{}, fmt.Errorf("inspection observation target or criterion is outside the frozen plan")
		}
		if err := validateObservationPlanBinding(plan, targets[key], criterion, observation); err != nil {
			return Outcome{}, err
		}
		if !contains(criterion.Criterion.Output.AllowedAssessments, observation.Result.Assessment) {
			return Outcome{}, fmt.Errorf("inspection observation assessment is outside the frozen criterion contract")
		}
		if samplesByKey[key] == nil {
			samplesByKey[key] = map[string]struct{}{}
		}
		if _, duplicate := samplesByKey[key][observation.SampleID]; duplicate {
			return Outcome{}, fmt.Errorf("inspection observations repeat sample %q for one target criterion", observation.SampleID)
		}
		samplesByKey[key][observation.SampleID] = struct{}{}
		if len(samplesByKey[key]) > expectedSamples[key] {
			return Outcome{}, fmt.Errorf("inspection observations exceed the frozen sample count")
		}
		byKey[key] = append(byKey[key], observation)
	}

	outcome := Outcome{State: RunCompleted, OverallAssessment: AssessmentUncertain, Findings: []Finding{}}
	attention := false
	for _, target := range plan.Targets {
		for _, plannedCriterion := range target.Criteria {
			criterion := plannedCriterion.Criterion
			key := findingKey{targetID: target.TargetID, criterionID: criterion.ID}
			finding := aggregateFinding(target.TargetID, criterion.ID, byKey[key])
			samplesComplete := finding.SampleCount == expectedSamples[key]
			if !samplesComplete && finding.SampleCount > 0 {
				finding.Limitations = uniqueSorted(append(finding.Limitations, "required_samples_incomplete"))
			}
			outcome.Findings = append(outcome.Findings, finding)
			if finding.Assessment == AssessmentNeedsAttention {
				attention = true
			}
			if !criterion.Required {
				continue
			}
			outcome.Coverage.Required++
			if finding.SampleCount == 0 {
				outcome.Coverage.Missing++
				continue
			}
			if !samplesComplete {
				outcome.Coverage.Inconclusive++
				continue
			}
			switch finding.Assessment {
			case AssessmentMeetsRule, AssessmentNeedsAttention:
				outcome.Coverage.Conclusive++
			case AssessmentUncertain, AssessmentNotObservable, AssessmentUnsupported:
				outcome.Coverage.Inconclusive++
			}
		}
	}
	if outcome.Coverage.Required == 0 {
		return Outcome{}, errors.New("inspection plan has no required criterion bindings")
	}
	outcome.Coverage.Ratio = float64(outcome.Coverage.Conclusive) / float64(outcome.Coverage.Required)
	if attention {
		outcome.OverallAssessment = AssessmentNeedsAttention
	} else if outcome.Coverage.Conclusive == outcome.Coverage.Required {
		outcome.OverallAssessment = AssessmentMeetsRule
	}
	if outcome.Coverage.Conclusive != outcome.Coverage.Required {
		outcome.State = RunPartial
		outcome.Conclusion = "巡检仅形成部分可信观察，不能汇总为全部达标。"
		outcome.Reason = "required_criteria_incomplete"
	} else if attention {
		outcome.Conclusion = "巡检证据完整，至少一项需要关注。"
		outcome.Reason = "required_criterion_needs_attention"
	} else {
		outcome.Conclusion = "巡检证据完整，所有允许判定的必选项符合当前规则。"
		outcome.Reason = "all_required_criteria_conclusive"
	}
	return outcome, nil
}

func aggregateFinding(targetID, criterionID string, observations []Observation) Finding {
	finding := Finding{TargetID: targetID, CriterionID: criterionID, Assessment: AssessmentNotObservable, ReasonCodes: []string{}, EvidenceRefs: []string{}, Results: []ResultProjection{}, Limitations: []string{}}
	if len(observations) == 0 {
		finding.ReasonCodes = []string{"observation_missing"}
		finding.Limitations = []string{"observation_missing"}
		return finding
	}
	sort.SliceStable(observations, func(i, j int) bool {
		left := observations[i].Result.Binding.TimeWindow.EndAt
		right := observations[j].Result.Binding.TimeWindow.EndAt
		if left.Equal(right) {
			return observations[i].ObservationID < observations[j].ObservationID
		}
		return left.Before(right)
	})
	finding.SampleCount = len(observations)
	finding.ObservedAt = observations[len(observations)-1].Result.Binding.TimeWindow.EndAt
	allMeet := true
	hasAttention, hasUncertain, hasNotObservable := false, false, false
	for _, observation := range observations {
		result := observation.Result
		switch result.Assessment {
		case AssessmentNeedsAttention:
			hasAttention = true
			allMeet = false
		case AssessmentMeetsRule:
		case AssessmentUncertain:
			hasUncertain = true
			allMeet = false
		case AssessmentNotObservable:
			hasNotObservable = true
			allMeet = false
		case AssessmentUnsupported:
			allMeet = false
		}
		finding.ReasonCodes = append(finding.ReasonCodes, result.ReasonCodes...)
		finding.EvidenceRefs = append(finding.EvidenceRefs, result.EvidenceRefs...)
		finding.Limitations = append(finding.Limitations, result.Limitations...)
		finding.Results = append(finding.Results, ResultProjection{
			ResultID: result.Binding.ResultID, SampleID: observation.SampleID,
			OutputKind: result.Binding.OutputKind, Value: cloneOracleResultValue(result.Value),
			EvidenceRefs: append([]string(nil), result.EvidenceRefs...), TimeWindow: result.Binding.TimeWindow,
		})
	}
	switch {
	case hasAttention:
		finding.Assessment = AssessmentNeedsAttention
	case allMeet:
		finding.Assessment = AssessmentMeetsRule
	case hasUncertain:
		finding.Assessment = AssessmentUncertain
	case hasNotObservable:
		finding.Assessment = AssessmentNotObservable
	default:
		finding.Assessment = AssessmentUnsupported
	}
	finding.ReasonCodes = uniqueSorted(finding.ReasonCodes)
	finding.EvidenceRefs = uniqueSorted(finding.EvidenceRefs)
	finding.Limitations = uniqueSorted(finding.Limitations)
	return finding
}

func validateObservationPlanBinding(plan ExecutionPlan, target PlannedTarget, criterion PlannedCriterion, observation Observation) error {
	binding := observation.Result.Binding
	if binding.CriterionVersion != strconv.FormatUint(criterion.Criterion.RuleVersion, 10) ||
		binding.OutputKind != criterion.Criterion.Output.Mode || binding.OutputSchemaVersion != criterion.Criterion.Output.SchemaVersion {
		return errors.New("inspection observation result contract does not match the frozen criterion")
	}
	knownSources := make(map[string]struct{}, len(target.SourceBindings))
	for _, source := range target.SourceBindings {
		knownSources[source.SourceHandle] = struct{}{}
	}
	for _, source := range binding.SourceMedia {
		if _, ok := knownSources[source.SourceRef]; !ok {
			return errors.New("inspection observation source is outside the frozen target binding")
		}
	}
	earliest := plan.RequestedAt.Add(-time.Duration(target.StrategyPolicy.Time.MaxAgeSeconds) * time.Second)
	if binding.TimeWindow.StartAt.Before(earliest) || binding.TimeWindow.EndAt.After(plan.Deadline) || observation.Result.Execution.CompletedAt.After(plan.Deadline) {
		return errors.New("inspection observation time is outside the frozen plan")
	}
	stepFound := false
	for _, step := range plan.Steps {
		if step.StepID != binding.StepID {
			continue
		}
		stepFound = true
		if (step.TargetID != "" && step.TargetID != binding.TargetID) || (step.CriterionID != "" && step.CriterionID != binding.CriterionID) {
			return errors.New("inspection observation step binding contradicts the frozen plan")
		}
		break
	}
	if !stepFound {
		return errors.New("inspection observation step is outside the frozen plan")
	}
	return nil
}

func cloneOracleResultValue(value *ResultValue) *ResultValue {
	if value == nil {
		return nil
	}
	clone := *value
	if value.Classification != nil {
		member := *value.Classification
		member.Score = cloneOracleFloat(member.Score)
		clone.Classification = &member
	}
	if value.Enum != nil {
		member := *value.Enum
		clone.Enum = &member
	}
	if value.Structured != nil {
		member := *value.Structured
		member.Fields = make([]StructuredField, len(value.Structured.Fields))
		for i, field := range value.Structured.Fields {
			member.Fields[i] = field
			member.Fields[i].Value.Enum = cloneOracleString(field.Value.Enum)
			member.Fields[i].Value.Number = cloneOracleFloat(field.Value.Number)
			member.Fields[i].Value.Integer = cloneOracleInt64(field.Value.Integer)
			member.Fields[i].Value.Boolean = cloneOracleBool(field.Value.Boolean)
		}
		clone.Structured = &member
	}
	if value.Metric != nil {
		member := *value.Metric
		clone.Metric = &member
	}
	if value.Detection != nil {
		member := *value.Detection
		if value.Detection.Objects != nil {
			member.Objects = make([]DetectionObject, len(value.Detection.Objects))
			copy(member.Objects, value.Detection.Objects)
		}
		for i := range member.Objects {
			member.Objects[i].Score = cloneOracleFloat(member.Objects[i].Score)
		}
		clone.Detection = &member
	}
	if value.Count != nil {
		member := *value.Count
		clone.Count = &member
	}
	if value.Event != nil {
		member := *value.Event
		clone.Event = &member
	}
	return &clone
}

func cloneOracleFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
func cloneOracleString(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
func cloneOracleInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
func cloneOracleBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
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

func latestTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value.After(latest) {
			latest = value
		}
	}
	return latest
}
