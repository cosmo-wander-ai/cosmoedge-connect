package inspectioneval

import (
	"encoding/json"
	"errors"
	"math"
)

const (
	maximumCountValue       = int64(1_000_000_000)
	maximumMetricAbsolute   = 1e15
	maximumStructuredFields = 256
	// V3 uses cubic-time deterministic optimal matching, so each side is
	// bounded before allocation or scoring.
	maximumDetections = 256
)

func validateResultValue(value ResultValue) error {
	if !validResultKind(value.Kind) || !validValueState(value.State) {
		return errors.New("result kind or state is unsupported")
	}
	present := 0
	for _, member := range []bool{
		value.Classification != nil, value.Enum != nil, value.Structured != nil,
		value.Metric != nil, value.Count != nil, value.Detection != nil, value.Event != nil,
	} {
		if member {
			present++
		}
	}
	if value.State != ValuePresent {
		if present != 0 {
			return errors.New("abstention must not contain a value member")
		}
		return nil
	}
	if present != 1 {
		return errors.New("present result must contain exactly one value member")
	}
	switch value.Kind {
	case ResultClassification:
		if value.Classification == nil || !validClassification(value.Classification.Value) {
			return errors.New("classification result is invalid")
		}
	case ResultEnum:
		if value.Enum == nil || !validOpaqueRef(value.Enum.Value) {
			return errors.New("enum result is invalid")
		}
	case ResultStructured:
		if value.Structured == nil || value.Structured.Fields == nil || len(value.Structured.Fields) > maximumStructuredFields {
			return errors.New("structured result is invalid")
		}
		previous := ""
		for _, field := range value.Structured.Fields {
			if !validOpaqueRef(field.Name) || field.Name <= previous || validateStructuredField(field) != nil {
				return errors.New("structured field is invalid or not canonical")
			}
			previous = field.Name
		}
	case ResultMetric:
		if value.Metric == nil || validateMetric(*value.Metric) != nil {
			return errors.New("metric result is invalid")
		}
	case ResultCount:
		if value.Count == nil || value.Count.Value < 0 || value.Count.Value > maximumCountValue {
			return errors.New("count result is invalid")
		}
	case ResultDetection:
		if value.Detection == nil || value.Detection.Objects == nil || len(value.Detection.Objects) > maximumDetections {
			return errors.New("detection result is invalid")
		}
		previous := ""
		for _, object := range value.Detection.Objects {
			key := detectionSortKey(object)
			if !validOpaqueRef(object.Label) || !validRegion(object.Region) || key <= previous {
				return errors.New("detection objects are invalid or not canonical")
			}
			previous = key
		}
	case ResultEvent:
		if value.Event == nil || !validOpaqueRef(value.Event.Type) {
			return errors.New("event result is invalid")
		}
	default:
		return errors.New("result kind is unsupported")
	}
	return nil
}

func validateStructuredField(field StructuredField) error {
	present := 0
	for _, member := range []bool{field.Boolean != nil, field.Enum != nil, field.Number != nil, field.Integer != nil} {
		if member {
			present++
		}
	}
	if present != 1 {
		return errors.New("structured field must contain exactly one value")
	}
	switch field.Kind {
	case StructuredBoolean:
		if field.Boolean == nil {
			return errors.New("boolean field is missing")
		}
	case StructuredEnum:
		if field.Enum == nil || !validOpaqueRef(*field.Enum) {
			return errors.New("enum field is invalid")
		}
	case StructuredNumber:
		if field.Number == nil || !finite(*field.Number) || math.Abs(*field.Number) > maximumMetricAbsolute {
			return errors.New("number field is invalid")
		}
	case StructuredInteger:
		if field.Integer == nil || *field.Integer < -maximumCountValue || *field.Integer > maximumCountValue {
			return errors.New("integer field is invalid")
		}
	default:
		return errors.New("structured field kind is unsupported")
	}
	return nil
}

func validateMetric(value MetricResult) error {
	if !finite(value.Value) || math.Abs(value.Value) > maximumMetricAbsolute || !validOpaqueRef(value.Unit) {
		return errors.New("metric is outside the bounded domain")
	}
	return nil
}

func validRegion(region NormalizedRegion) bool {
	for _, value := range []float64{region.X, region.Y, region.Width, region.Height} {
		if !finite(value) || value < 0 || value > 1 {
			return false
		}
	}
	return region.Width > 0 && region.Height > 0 && region.X+region.Width <= 1 && region.Y+region.Height <= 1
}

func detectionSortKey(object DetectionObject) string {
	raw, _ := json.Marshal(object)
	return string(raw)
}

func validResultKind(kind ResultKind) bool {
	switch kind {
	case ResultClassification, ResultEnum, ResultStructured, ResultMetric, ResultCount, ResultDetection, ResultEvent:
		return true
	default:
		return false
	}
}

func validValueState(state ValueState) bool {
	switch state {
	case ValuePresent, ValueUncertain, ValueNotObservable, ValueUnsupported:
		return true
	default:
		return false
	}
}

func validClassification(value ClassificationValue) bool {
	return value == ClassificationMeetsRule || value == ClassificationNeedsAttention
}

func equivalent(left, right ResultValue) bool {
	if left.Kind != right.Kind || left.State != right.State {
		return false
	}
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}
