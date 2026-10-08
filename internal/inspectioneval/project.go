package inspectioneval

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/dataset"
)

// ResultValueFromAnalysis produces the evaluation-only projection of one
// validated durable result. It drops model, authority, source, and media
// identity while preserving the closed value shape used for scoring.
func ResultValueFromAnalysis(result inspection.AnalysisResult) (ResultValue, error) {
	if err := result.Validate(); err != nil {
		return ResultValue{}, fmt.Errorf("project validated inspection result: %w", err)
	}
	kind, err := projectKind(result.Binding.OutputKind)
	if err != nil {
		return ResultValue{}, err
	}
	projected := ResultValue{Kind: kind, State: stateFromAssessment(result.Assessment)}
	if projected.State != ValuePresent {
		if err := validateResultValue(projected); err != nil {
			return ResultValue{}, err
		}
		return projected, nil
	}
	if result.Value == nil {
		return ResultValue{}, errors.New("conclusive inspection result has no typed value")
	}
	switch result.Binding.OutputKind {
	case inspection.ResultClassification:
		projected.Classification = &ClassificationResult{Value: classificationFromAssessment(result.Assessment)}
	case inspection.ResultEnum:
		projected.Enum = &EnumResult{Value: result.Value.Enum.Value}
	case inspection.ResultStructured:
		fields := make([]StructuredField, 0, len(result.Value.Structured.Fields))
		for _, field := range result.Value.Structured.Fields {
			item := StructuredField{Name: field.Name, Kind: StructuredFieldKind(field.Value.Kind)}
			switch field.Value.Kind {
			case inspection.StructuredBoolean:
				value := *field.Value.Boolean
				item.Boolean = &value
			case inspection.StructuredEnum:
				value := *field.Value.Enum
				item.Enum = &value
			case inspection.StructuredNumber:
				value := *field.Value.Number
				item.Number = &value
			case inspection.StructuredInteger:
				value := *field.Value.Integer
				item.Integer = &value
			default:
				return ResultValue{}, errors.New("inspection structured value kind cannot be evaluated")
			}
			fields = append(fields, item)
		}
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		projected.Structured = &StructuredResult{Fields: fields}
	case inspection.ResultMetric:
		projected.Metric = &MetricResult{Value: result.Value.Metric.Value, Unit: result.Value.Metric.Unit}
	case inspection.ResultCount:
		projected.Count = &CountResult{Value: result.Value.Count.Value}
	case inspection.ResultDetection:
		objects := make([]DetectionObject, 0, len(result.Value.Detection.Objects))
		for _, object := range result.Value.Detection.Objects {
			objects = append(objects, DetectionObject{Label: object.Label, Region: NormalizedRegion{
				X: object.Region.X, Y: object.Region.Y, Width: object.Region.Width, Height: object.Region.Height,
			}})
		}
		sort.Slice(objects, func(i, j int) bool { return detectionSortKey(objects[i]) < detectionSortKey(objects[j]) })
		projected.Detection = &DetectionResult{Objects: objects}
	case inspection.ResultEvent:
		projected.Event = &EventResult{Type: result.Value.Event.Type, Occurred: true}
	default:
		return ResultValue{}, errors.New("inspection result kind cannot be evaluated")
	}
	if err := validateResultValue(projected); err != nil {
		return ResultValue{}, fmt.Errorf("validate projected inspection result: %w", err)
	}
	return projected, nil
}

// ResultValueFromDatasetLabel projects an accepted, reviewed dataset label
// into the same closed evaluation value used for runtime results.
func ResultValueFromDatasetLabel(label dataset.Label) (ResultValue, error) {
	var projected ResultValue
	switch label.Kind {
	case dataset.LabelClassification:
		if label.Classification == nil {
			return ResultValue{}, errors.New("dataset classification label is missing")
		}
		projected.Kind = ResultClassification
		switch label.Classification.Value {
		case dataset.ClassificationMeetsRule:
			projected.State = ValuePresent
			projected.Classification = &ClassificationResult{Value: ClassificationMeetsRule}
		case dataset.ClassificationNeedsAttention:
			projected.State = ValuePresent
			projected.Classification = &ClassificationResult{Value: ClassificationNeedsAttention}
		case dataset.ClassificationUncertain:
			projected.State = ValueUncertain
		case dataset.ClassificationNotObservable:
			projected.State = ValueNotObservable
		case dataset.ClassificationUnsupported:
			projected.State = ValueUnsupported
		default:
			return ResultValue{}, errors.New("dataset classification label is invalid")
		}
	case dataset.LabelEnum:
		if label.Enum == nil {
			return ResultValue{}, errors.New("dataset enum label is missing")
		}
		projected = ResultValue{Kind: ResultEnum, State: ValuePresent, Enum: &EnumResult{Value: label.Enum.Value}}
	case dataset.LabelStructured:
		if label.Structured == nil {
			return ResultValue{}, errors.New("dataset structured label is missing")
		}
		fields := make([]StructuredField, 0, len(label.Structured.Fields))
		for _, field := range label.Structured.Fields {
			item := StructuredField{Name: field.Name, Kind: StructuredFieldKind(field.Value.Kind)}
			switch field.Value.Kind {
			case dataset.StructuredBoolean:
				value := *field.Value.Boolean
				item.Boolean = &value
			case dataset.StructuredEnum:
				value := *field.Value.Enum
				item.Enum = &value
			case dataset.StructuredNumber:
				value := *field.Value.Number
				item.Number = &value
			case dataset.StructuredInteger:
				value := *field.Value.Integer
				item.Integer = &value
			default:
				return ResultValue{}, errors.New("dataset structured value kind cannot be evaluated")
			}
			fields = append(fields, item)
		}
		sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
		projected = ResultValue{Kind: ResultStructured, State: ValuePresent, Structured: &StructuredResult{Fields: fields}}
	case dataset.LabelMetric:
		if label.Metric == nil {
			return ResultValue{}, errors.New("dataset metric label is missing")
		}
		projected = ResultValue{Kind: ResultMetric, State: ValuePresent, Metric: &MetricResult{Value: label.Metric.Value, Unit: label.Metric.Unit}}
	case dataset.LabelCount:
		if label.Count == nil {
			return ResultValue{}, errors.New("dataset count label is missing")
		}
		projected = ResultValue{Kind: ResultCount, State: ValuePresent, Count: &CountResult{Value: label.Count.Value}}
	case dataset.LabelDetection:
		if label.Detection == nil {
			return ResultValue{}, errors.New("dataset detection label is missing")
		}
		objects := make([]DetectionObject, 0, len(label.Detection.Objects))
		for _, object := range label.Detection.Objects {
			objects = append(objects, DetectionObject{Label: object.Label, Region: NormalizedRegion{
				X: object.Region.X, Y: object.Region.Y, Width: object.Region.Width, Height: object.Region.Height,
			}})
		}
		sort.Slice(objects, func(i, j int) bool { return detectionSortKey(objects[i]) < detectionSortKey(objects[j]) })
		projected = ResultValue{Kind: ResultDetection, State: ValuePresent, Detection: &DetectionResult{Objects: objects}}
	case dataset.LabelEvent:
		if label.Event == nil {
			return ResultValue{}, errors.New("dataset event label is missing")
		}
		projected = ResultValue{Kind: ResultEvent, State: ValuePresent, Event: &EventResult{Type: label.Event.Type, Occurred: label.Event.Occurred}}
	default:
		return ResultValue{}, errors.New("dataset label kind cannot be evaluated")
	}
	if err := validateResultValue(projected); err != nil {
		return ResultValue{}, fmt.Errorf("validate projected dataset label: %w", err)
	}
	return projected, nil
}

func projectKind(kind inspection.ResultKind) (ResultKind, error) {
	switch kind {
	case inspection.ResultClassification:
		return ResultClassification, nil
	case inspection.ResultEnum:
		return ResultEnum, nil
	case inspection.ResultStructured:
		return ResultStructured, nil
	case inspection.ResultMetric:
		return ResultMetric, nil
	case inspection.ResultCount:
		return ResultCount, nil
	case inspection.ResultDetection:
		return ResultDetection, nil
	case inspection.ResultEvent:
		return ResultEvent, nil
	default:
		return "", errors.New("inspection result kind cannot be evaluated")
	}
}

func stateFromAssessment(assessment inspection.Assessment) ValueState {
	switch assessment {
	case inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention:
		return ValuePresent
	case inspection.AssessmentNotObservable:
		return ValueNotObservable
	case inspection.AssessmentUnsupported:
		return ValueUnsupported
	default:
		return ValueUncertain
	}
}

func classificationFromAssessment(assessment inspection.Assessment) ClassificationValue {
	if assessment == inspection.AssessmentNeedsAttention {
		return ClassificationNeedsAttention
	}
	return ClassificationMeetsRule
}
