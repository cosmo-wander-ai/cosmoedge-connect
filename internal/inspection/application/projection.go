package application

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

// BusinessResultProjector is the default deterministic Chinese projection. It
// never uses PolicyBoundDisplay, reason codes, limitations, prompts, model
// metadata or native identities.
type BusinessResultProjector struct{}

func NewBusinessResultProjector() ResultProjector { return BusinessResultProjector{} }

func (BusinessResultProjector) Project(_ context.Context, input ProjectionInput) (Projection, error) {
	if !input.OverallAssessment.Valid() || input.CompletedAt.IsZero() {
		return Projection{}, errors.New("invalid safe projection input")
	}
	result := Projection{
		Summary:  fmt.Sprintf("整体判断：%s。已确认 %d 项，共 %d 项。", assessmentLabel(input.OverallAssessment), input.Coverage.Conclusive, input.Coverage.Required),
		Sections: make([]ProjectedSection, 0, len(input.Findings)),
	}
	if input.Coverage.Missing > 0 || input.Coverage.Inconclusive > 0 {
		result.Limitations = append(result.Limitations, "部分巡检内容没有形成有效结论。")
	}
	for _, finding := range input.Findings {
		section := ProjectedSection{
			Title:      finding.TargetTitle + " · " + finding.CriterionTitle,
			Conclusion: assessmentLabel(finding.Assessment),
			Evidence:   append([]ProjectionEvidence(nil), finding.Evidence...),
		}
		for _, value := range finding.Values {
			section.Details = append(section.Details, displayValue(value)...)
		}
		result.Sections = append(result.Sections, section)
	}
	return result, nil
}

func assessmentLabel(value inspection.Assessment) string {
	switch value {
	case inspection.AssessmentMeetsRule:
		return "符合要求"
	case inspection.AssessmentNeedsAttention:
		return "需要关注"
	case inspection.AssessmentUncertain:
		return "暂时无法确认"
	case inspection.AssessmentNotObservable:
		return "当前画面无法判断"
	case inspection.AssessmentUnsupported:
		return "当前能力不支持"
	default:
		return "无法判断"
	}
}

func displayValue(value ProjectionValue) []string {
	switch value.Kind {
	case inspection.ResultClassification:
		if value.Label != "" {
			return []string{"识别结果：" + value.Label}
		}
	case inspection.ResultEnum:
		if value.Label != "" {
			return []string{"结果：" + value.Label}
		}
	case inspection.ResultMetric:
		return []string{"测量结果：" + strconv.FormatFloat(value.Number, 'f', -1, 64) + value.Unit}
	case inspection.ResultCount:
		return []string{"数量：" + strconv.FormatInt(value.Integer, 10) + value.Unit}
	case inspection.ResultDetection:
		return []string{"识别到的目标数量：" + strconv.Itoa(value.ObjectCount)}
	case inspection.ResultEvent:
		switch value.EventState {
		case inspection.EventOccurred:
			return []string{"事件状态：已发生"}
		case inspection.EventStarted:
			return []string{"事件状态：已开始"}
		case inspection.EventActive:
			return []string{"事件状态：进行中"}
		case inspection.EventEnded:
			return []string{"事件状态：已结束"}
		}
	case inspection.ResultStructured:
		result := make([]string, 0, len(value.Fields))
		for _, field := range value.Fields {
			detail := field.Name + "："
			switch field.Kind {
			case inspection.StructuredEnum:
				detail += field.Text
			case inspection.StructuredNumber:
				detail += strconv.FormatFloat(field.Number, 'f', -1, 64)
			case inspection.StructuredInteger:
				detail += strconv.FormatInt(field.Integer, 10)
			case inspection.StructuredBoolean:
				if field.Boolean != nil && *field.Boolean {
					detail += "是"
				} else {
					detail += "否"
				}
			}
			result = append(result, detail)
		}
		return result
	}
	return nil
}

func sanitizedProjectionInput(run inspection.Run, plan inspection.ExecutionPlan, outcome inspection.Outcome, observations []inspection.Observation) (ProjectionInput, error) {
	if err := plan.Validate(); err != nil || !outcome.OverallAssessment.Valid() || outcome.State != run.State || !validCoverage(outcome.Coverage) {
		return ProjectionInput{}, errors.New("inspection outcome is not safe to project")
	}
	if len(plan.Targets) > maximumProjectionItems || len(outcome.Findings) > maximumProjectionItems || len(observations) > maximumProjectionItems {
		return ProjectionInput{}, errors.New("inspection result exceeds its bounded projection")
	}
	targetTitles := make(map[string]string, len(plan.Targets))
	criterionTitles := make(map[string]map[string]string, len(plan.Targets))
	for _, target := range plan.Targets {
		if !validPublicText(target.FriendlyName, 1, 160) {
			return ProjectionInput{}, errors.New("inspection target title is unsafe")
		}
		targetTitles[target.TargetID] = target.FriendlyName
		criteria := make(map[string]string, len(target.Criteria))
		for _, criterion := range target.Criteria {
			if !validPublicText(criterion.Criterion.Name, 1, 160) {
				return ProjectionInput{}, errors.New("inspection criterion title is unsafe")
			}
			criteria[criterion.Criterion.ID] = criterion.Criterion.Name
		}
		criterionTitles[target.TargetID] = criteria
	}

	type observationBinding struct {
		observation inspection.Observation
		media       map[string]string
	}
	byResult := make(map[string]observationBinding, len(observations))
	for _, observation := range observations {
		if err := observation.Validate(); err != nil || observation.Result.Binding.RunID != run.RunID || observation.Result.Binding.Usage != inspection.ResultUsageInspection {
			return ProjectionInput{}, errors.New("inspection observation failed its run or usage binding")
		}
		if _, ok := targetTitles[observation.Result.Binding.TargetID]; !ok {
			return ProjectionInput{}, errors.New("inspection observation references an unknown target")
		}
		if _, ok := criterionTitles[observation.Result.Binding.TargetID][observation.Result.Binding.CriterionID]; !ok {
			return ProjectionInput{}, errors.New("inspection observation references an unknown criterion")
		}
		mediaByRef := make(map[string]string, len(observation.Result.Binding.SourceMedia))
		for _, sourceMedia := range observation.Result.Binding.SourceMedia {
			mediaByRef[sourceMedia.MediaRef] = sourceMedia.SHA256
		}
		for _, evidenceRef := range observation.Result.EvidenceRefs {
			if _, ok := mediaByRef[evidenceRef]; !ok {
				return ProjectionInput{}, errors.New("inspection evidence is not bound to source media")
			}
		}
		if _, duplicate := byResult[observation.Result.Binding.ResultID]; duplicate {
			return ProjectionInput{}, errors.New("inspection result identity is duplicated")
		}
		byResult[observation.Result.Binding.ResultID] = observationBinding{observation: observation, media: mediaByRef}
	}

	input := ProjectionInput{
		OverallAssessment: outcome.OverallAssessment, Coverage: outcome.Coverage,
		CompletedAt: run.UpdatedAt.UTC(), Findings: make([]ProjectionFindingInput, 0, len(outcome.Findings)),
	}
	seenFinding := map[string]struct{}{}
	for _, finding := range outcome.Findings {
		criterionTitle, ok := criterionTitles[finding.TargetID][finding.CriterionID]
		if !ok || !finding.Assessment.Valid() || finding.SampleCount != len(finding.Results) || finding.SampleCount < 1 {
			return ProjectionInput{}, errors.New("inspection finding failed its frozen plan binding")
		}
		findingKey := finding.TargetID + "\x00" + finding.CriterionID
		if _, duplicate := seenFinding[findingKey]; duplicate {
			return ProjectionInput{}, errors.New("inspection finding is duplicated")
		}
		seenFinding[findingKey] = struct{}{}
		projected := ProjectionFindingInput{
			TargetTitle: targetTitles[finding.TargetID], CriterionTitle: criterionTitle,
			Assessment: finding.Assessment, Values: make([]ProjectionValue, 0, len(finding.Results)),
		}
		evidenceSHA := map[string]string{}
		for _, result := range finding.Results {
			bound, ok := byResult[result.ResultID]
			if !ok || bound.observation.SampleID != result.SampleID || bound.observation.Result.Binding.TargetID != finding.TargetID ||
				bound.observation.Result.Binding.CriterionID != finding.CriterionID || bound.observation.Result.Binding.OutputKind != result.OutputKind ||
				!reflect.DeepEqual(bound.observation.Result.Value, result.Value) || !reflect.DeepEqual(bound.observation.Result.EvidenceRefs, result.EvidenceRefs) ||
				!bound.observation.Result.Binding.TimeWindow.StartAt.Equal(result.TimeWindow.StartAt) || !bound.observation.Result.Binding.TimeWindow.EndAt.Equal(result.TimeWindow.EndAt) {
				return ProjectionInput{}, errors.New("inspection finding result failed its typed observation binding")
			}
			if result.Value != nil {
				if value, include := sanitizeProjectionValue(*result.Value); include {
					projected.Values = append(projected.Values, value)
				}
			}
			for _, evidenceRef := range result.EvidenceRefs {
				digest, ok := bound.media[evidenceRef]
				if !ok {
					return ProjectionInput{}, errors.New("inspection finding evidence failed its observation binding")
				}
				evidenceSHA[evidenceRef] = digest
			}
		}
		for _, evidenceRef := range finding.EvidenceRefs {
			if _, ok := evidenceSHA[evidenceRef]; !ok {
				return ProjectionInput{}, errors.New("inspection finding evidence failed its result binding")
			}
		}
		for _, evidenceRef := range sortedUnique(finding.EvidenceRefs) {
			projected.Evidence = append(projected.Evidence, ProjectionEvidence{
				InternalMediaRef: evidenceRef, ExpectedSHA256: evidenceSHA[evidenceRef],
				Title: targetTitles[finding.TargetID] + "现场快照",
			})
		}
		input.Findings = append(input.Findings, projected)
	}
	return input, nil
}

func sanitizeProjectionValue(value inspection.ResultValue) (ProjectionValue, bool) {
	result := ProjectionValue{Kind: value.Kind}
	switch value.Kind {
	case inspection.ResultClassification:
		if value.Classification == nil || !validPublicText(value.Classification.Label, 1, 256) {
			return ProjectionValue{}, false
		}
		result.Label = value.Classification.Label
	case inspection.ResultEnum:
		if value.Enum == nil || !validPublicText(value.Enum.Value, 1, 256) {
			return ProjectionValue{}, false
		}
		result.Label = value.Enum.Value
	case inspection.ResultMetric:
		if value.Metric == nil || !validPublicText(value.Metric.Unit, 1, 64) {
			return ProjectionValue{}, false
		}
		result.Number, result.Unit = value.Metric.Value, value.Metric.Unit
	case inspection.ResultCount:
		if value.Count == nil || !validPublicText(value.Count.Unit, 1, 64) {
			return ProjectionValue{}, false
		}
		result.Integer, result.Unit = value.Count.Value, value.Count.Unit
	case inspection.ResultDetection:
		if value.Detection == nil {
			return ProjectionValue{}, false
		}
		result.ObjectCount = len(value.Detection.Objects)
	case inspection.ResultEvent:
		if value.Event == nil {
			return ProjectionValue{}, false
		}
		result.EventState = value.Event.State
	case inspection.ResultStructured:
		if value.Structured == nil {
			return ProjectionValue{}, false
		}
		result.Fields = make([]ProjectionField, 0, len(value.Structured.Fields))
		for _, field := range value.Structured.Fields {
			if !validPublicText(field.Name, 1, 128) {
				continue
			}
			output := ProjectionField{Name: field.Name, Kind: field.Value.Kind}
			switch field.Value.Kind {
			case inspection.StructuredEnum:
				if field.Value.Enum == nil || !validPublicText(*field.Value.Enum, 1, 256) {
					continue
				}
				output.Text = *field.Value.Enum
			case inspection.StructuredNumber:
				if field.Value.Number == nil {
					continue
				}
				output.Number = *field.Value.Number
			case inspection.StructuredInteger:
				if field.Value.Integer == nil {
					continue
				}
				output.Integer = *field.Value.Integer
			case inspection.StructuredBoolean:
				if field.Value.Boolean == nil {
					continue
				}
				boolean := *field.Value.Boolean
				output.Boolean = &boolean
			default:
				continue
			}
			result.Fields = append(result.Fields, output)
		}
	default:
		return ProjectionValue{}, false
	}
	return result, true
}

func validateProjection(value Projection, input ProjectionInput) error {
	if !validPublicText(value.Summary, 1, 4<<10) || len(value.Sections) > 100 || len(value.Limitations) > 32 {
		return errors.New("invalid result projection")
	}
	internalRefs := make([]string, 0)
	allowedEvidence := map[string]ProjectionEvidence{}
	for _, finding := range input.Findings {
		for _, evidence := range finding.Evidence {
			allowedEvidence[evidence.InternalMediaRef] = evidence
			internalRefs = append(internalRefs, evidence.InternalMediaRef)
		}
	}
	checkText := func(text string, minimum, maximum int) bool {
		if !validPublicText(text, minimum, maximum) {
			return false
		}
		for _, internalRef := range internalRefs {
			if strings.Contains(text, internalRef) {
				return false
			}
		}
		return true
	}
	if !checkText(value.Summary, 1, 4<<10) {
		return errors.New("unsafe result summary")
	}
	for _, limitation := range value.Limitations {
		if !checkText(limitation, 1, 1024) {
			return errors.New("unsafe result limitation")
		}
	}
	seenEvidence := map[string]struct{}{}
	for _, section := range value.Sections {
		if !checkText(section.Title, 1, 256) || !checkText(section.Conclusion, 1, 4<<10) || len(section.Details) > 100 || len(section.Evidence) > 32 {
			return errors.New("unsafe result section")
		}
		for _, detail := range section.Details {
			if !checkText(detail, 1, 1024) {
				return errors.New("unsafe result detail")
			}
		}
		for _, evidence := range section.Evidence {
			allowed, ok := allowedEvidence[evidence.InternalMediaRef]
			if !ok || evidence.ExpectedSHA256 != allowed.ExpectedSHA256 || !checkText(evidence.Title, 1, 256) {
				return errors.New("result projection invented evidence")
			}
			if _, duplicate := seenEvidence[evidence.InternalMediaRef]; duplicate {
				return errors.New("result projection duplicated evidence")
			}
			seenEvidence[evidence.InternalMediaRef] = struct{}{}
		}
	}
	return nil
}

func validCoverage(value inspection.Coverage) bool {
	if value.Required < 0 || value.Conclusive < 0 || value.Inconclusive < 0 || value.Missing < 0 ||
		value.Conclusive+value.Inconclusive+value.Missing != value.Required || value.Ratio < 0 || value.Ratio > 1 {
		return false
	}
	expected := 0.0
	if value.Required > 0 {
		expected = float64(value.Conclusive) / float64(value.Required)
	}
	return value.Ratio == expected
}

func sortProjectionFindings(values []ProjectionFindingInput) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].TargetTitle != values[j].TargetTitle {
			return values[i].TargetTitle < values[j].TargetTitle
		}
		return values[i].CriterionTitle < values[j].CriterionTitle
	})
}
