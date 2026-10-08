package inspectioneval

import (
	"encoding/json"
	"math"
	"sort"
)

const detectionIoUThreshold = 0.50

// Evaluate validates the immutable v3 projection and computes deterministic
// metrics. It never selects or tunes thresholds; test records are rejected at
// validation time if marked for threshold calibration.
func Evaluate(manifest Manifest) (EvaluationReport, error) {
	if err := Validate(manifest); err != nil {
		return EvaluationReport{}, err
	}
	testRecords := selectRecords(manifest.Records, func(record Record) bool { return record.Split == SplitTest })
	report := EvaluationReport{
		Schema:         ReportSchema,
		PrimarySplit:   SplitTest,
		Overall:        calculateMetrics(testRecords),
		ByStrategy:     stratify(testRecords, func(record Record) string { return string(record.Strategy) }),
		ByCriterion:    stratifyCriteria(testRecords),
		BySourceKind:   stratify(testRecords, func(record Record) string { return string(record.SourceKind) }),
		ByMediaKind:    stratify(testRecords, func(record Record) string { return string(record.MediaKind) }),
		BySite:         stratify(testRecords, func(record Record) string { return record.SitePseudonym }),
		BySource:       stratify(testRecords, func(record Record) string { return record.SourcePseudonym }),
		BySceneStratum: stratifyMany(testRecords, func(record Record) []string { return record.SceneStrata }),
		BySplit:        stratify(manifest.Records, func(record Record) string { return string(record.Split) }),
	}
	for _, record := range manifest.Records {
		switch record.Split {
		case SplitTrain:
			report.Calibration.TrainRecords++
		case SplitValidation:
			report.Calibration.ValidationRecords++
		}
		if record.CalibrationRole != CalibrationThresholdFit {
			continue
		}
		switch record.Split {
		case SplitTrain:
			report.Calibration.ThresholdFitTrain++
		case SplitValidation:
			report.Calibration.ThresholdFitValidation++
		case SplitTest:
			report.Calibration.ThresholdFitTest++
		}
	}
	return report, nil
}

type criterionSliceKey struct {
	id      string
	version uint64
	schema  string
	kind    ResultKind
}

func stratifyCriteria(records []Record) []CriterionSliceMetrics {
	groups := make(map[criterionSliceKey][]Record)
	for _, record := range records {
		key := criterionSliceKey{record.CriterionID, record.CriterionVersion, record.ResultSchemaRef, record.Expected.Kind}
		groups[key] = append(groups[key], record)
	}
	keys := make([]criterionSliceKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].id != keys[j].id {
			return keys[i].id < keys[j].id
		}
		if keys[i].version != keys[j].version {
			return keys[i].version < keys[j].version
		}
		if keys[i].schema != keys[j].schema {
			return keys[i].schema < keys[j].schema
		}
		return keys[i].kind < keys[j].kind
	})
	result := make([]CriterionSliceMetrics, 0, len(keys))
	for _, key := range keys {
		result = append(result, CriterionSliceMetrics{CriterionID: key.id, CriterionVersion: key.version,
			ResultSchemaRef: key.schema, ResultKind: key.kind, Metrics: calculateMetrics(groups[key])})
	}
	return result
}

func selectRecords(records []Record, keep func(Record) bool) []Record {
	selected := make([]Record, 0, len(records))
	for _, record := range records {
		if keep(record) {
			selected = append(selected, record)
		}
	}
	return selected
}

func stratify(records []Record, key func(Record) string) []SliceMetrics {
	groups := make(map[string][]Record)
	for _, record := range records {
		value := key(record)
		groups[value] = append(groups[value], record)
	}
	keys := make([]string, 0, len(groups))
	for value := range groups {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	result := make([]SliceMetrics, 0, len(keys))
	for _, value := range keys {
		result = append(result, SliceMetrics{Key: value, Metrics: calculateMetrics(groups[value])})
	}
	return result
}

func stratifyMany(records []Record, keys func(Record) []string) []SliceMetrics {
	groups := make(map[string][]Record)
	for _, record := range records {
		for _, key := range keys(record) {
			groups[key] = append(groups[key], record)
		}
	}
	ordered := make([]string, 0, len(groups))
	for key := range groups {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	result := make([]SliceMetrics, 0, len(ordered))
	for _, key := range ordered {
		result = append(result, SliceMetrics{Key: key, Metrics: calculateMetrics(groups[key])})
	}
	return result
}

func calculateMetrics(records []Record) Metrics {
	metrics := Metrics{Records: len(records)}
	metrics.Detection.IoUThreshold = detectionIoUThreshold
	endToEnd := make([]float64, 0, len(records))
	analysis := make([]float64, 0, len(records))
	deliveryLatency := make([]float64, 0, len(records))
	metricAbsolute := 0.0
	metricSquared := 0.0
	countAbsolute := 0.0
	countSquared := 0.0
	detectionIoUSum := 0.0
	detectionMatches := 0
	seenDeliveries := make(map[string]struct{})

	for _, record := range records {
		if record.Expected.State == ValuePresent {
			metrics.Coverage.Eligible++
			if record.Observed.State == ValuePresent {
				metrics.Coverage.Covered++
			} else {
				metrics.Coverage.Abstained++
			}
		}
		switch record.Expected.Kind {
		case ResultClassification:
			accumulateClassification(&metrics.Classification, record)
		case ResultEnum:
			accumulateExact(&metrics.Enum, record)
		case ResultStructured:
			accumulateStructured(&metrics.Structured, record)
		case ResultMetric:
			accumulateError(&metrics.Metric, record, &metricAbsolute, &metricSquared)
		case ResultCount:
			accumulateError(&metrics.Count, record, &countAbsolute, &countSquared)
		case ResultDetection:
			matchedSum, matched := accumulateDetection(&metrics.Detection, record)
			detectionIoUSum += matchedSum
			detectionMatches += matched
		case ResultEvent:
			accumulateEvent(&metrics.Event, record)
		}

		_, deliveryAlreadyCounted := seenDeliveries[record.DeliveryPseudonym]
		if !deliveryAlreadyCounted {
			seenDeliveries[record.DeliveryPseudonym] = struct{}{}
			metrics.Delivery.Attempts += record.DeliveryAttempts
			metrics.Delivery.ReconciliationAttempts += record.ReconciliationAttempts
			switch record.DeliveryStatus {
			case DeliveryDelivered:
				metrics.Delivery.Delivered++
			case DeliveryUnknown:
				metrics.Delivery.Unknown++
			case DeliveryFailed:
				metrics.Delivery.Failed++
			}
			if record.Feedback != nil {
				metrics.Feedback.Responses++
				if record.Feedback.Helpful {
					metrics.Feedback.Helpful++
				} else {
					metrics.Feedback.Unhelpful++
				}
			}
			deliveryLatency = append(deliveryLatency, record.Latencies.DeliveryMS)
		}
		if record.ObservationMode == ObservationTemporary {
			metrics.Review.TemporaryRecords++
			if record.TemporaryReview != nil {
				metrics.Review.Reviewed++
				if equivalent(record.Observed, record.TemporaryReview.Adjudicated) {
					metrics.Review.Agreements++
				} else {
					metrics.Review.Disagreements++
				}
			}
		}
		endToEnd = append(endToEnd, record.Latencies.EndToEndMS)
		analysis = append(analysis, record.Latencies.AnalysisMS)
	}

	finalizeClassification(&metrics.Classification)
	finalizeExact(&metrics.Enum)
	finalizeExact(&metrics.Structured.ExactMatchMetrics)
	metrics.Structured.FieldAgreement = ratio(metrics.Structured.MatchingFields, metrics.Structured.ComparedFields)
	finalizeError(&metrics.Metric, metricAbsolute, metricSquared)
	finalizeError(&metrics.Count, countAbsolute, countSquared)
	metrics.Coverage.Coverage = ratio(metrics.Coverage.Covered, metrics.Coverage.Eligible)
	metrics.Detection.Precision = ratio(metrics.Detection.TruePositive, metrics.Detection.TruePositive+metrics.Detection.FalsePositive)
	metrics.Detection.Recall = ratio(metrics.Detection.TruePositive, metrics.Detection.TruePositive+metrics.Detection.FalseNegative)
	if detectionMatches > 0 {
		metrics.Detection.MeanMatchedIoU = floatPointer(detectionIoUSum / float64(detectionMatches))
	}
	metrics.Event.Precision = ratio(metrics.Event.TruePositive, metrics.Event.TruePositive+metrics.Event.FalsePositive)
	metrics.Event.Recall = ratio(metrics.Event.TruePositive, metrics.Event.TruePositive+metrics.Event.FalseNegative)
	metrics.Delivery.Reliability = ratio(metrics.Delivery.Delivered, metrics.Delivery.Attempts)
	metrics.Delivery.UnknownRate = ratio(metrics.Delivery.Unknown, metrics.Delivery.Attempts)
	metrics.Delivery.KnownSuccessRate = ratio(metrics.Delivery.Delivered, metrics.Delivery.Delivered+metrics.Delivery.Failed)
	metrics.Review.Agreement = ratio(metrics.Review.Agreements, metrics.Review.Reviewed)
	metrics.Feedback.HelpfulRate = ratio(metrics.Feedback.Helpful, metrics.Feedback.Responses)
	metrics.Latency = LatencyMetrics{
		EndToEnd: distribution(endToEnd), Analysis: distribution(analysis), Delivery: distribution(deliveryLatency),
	}
	return metrics
}

func accumulateClassification(metrics *ClassificationMetrics, record Record) {
	if record.Expected.State != ValuePresent || record.Expected.Classification == nil {
		metrics.ExcludedExpectedAbstention++
		return
	}
	metrics.EligibleExpectedDecisions++
	if record.Observed.State == ValuePresent && record.Observed.Classification != nil {
		metrics.Covered++
	} else {
		metrics.Abstained++
	}
	expected := record.Expected.Classification.Value
	if expected == ClassificationNeedsAttention {
		if record.Observed.State == ValuePresent && record.Observed.Classification != nil && record.Observed.Classification.Value == ClassificationNeedsAttention {
			metrics.TruePositive++
		} else {
			metrics.FalseNegative++
			if record.Observed.State == ValuePresent && record.Observed.Classification != nil && record.Observed.Classification.Value == ClassificationMeetsRule {
				metrics.FalseClear++
			}
		}
		return
	}
	if record.Observed.State != ValuePresent || record.Observed.Classification == nil {
		return
	}
	if record.Observed.Classification.Value == ClassificationNeedsAttention {
		metrics.FalsePositive++
	} else {
		metrics.TrueNegative++
	}
}

func finalizeClassification(metrics *ClassificationMetrics) {
	metrics.Precision = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalsePositive)
	metrics.Recall = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalseNegative)
	metrics.FalseClearRate = ratio(metrics.FalseClear, metrics.TruePositive+metrics.FalseNegative)
	metrics.AbstentionRate = ratio(metrics.Abstained, metrics.EligibleExpectedDecisions)
	metrics.Coverage = ratio(metrics.Covered, metrics.EligibleExpectedDecisions)
	correct := metrics.TruePositive + metrics.TrueNegative
	metrics.Accuracy = ratio(correct, metrics.EligibleExpectedDecisions)
	metrics.CoveredAccuracy = ratio(correct, metrics.Covered)
}

func accumulateExact(metrics *ExactMatchMetrics, record Record) {
	if record.Expected.State != ValuePresent {
		return
	}
	metrics.Eligible++
	if record.Observed.State != ValuePresent {
		metrics.Abstained++
		return
	}
	metrics.Covered++
	if equivalent(record.Expected, record.Observed) {
		metrics.Matches++
	}
}

func finalizeExact(metrics *ExactMatchMetrics) {
	metrics.Accuracy = ratio(metrics.Matches, metrics.Eligible)
	metrics.CoveredAccuracy = ratio(metrics.Matches, metrics.Covered)
}

func accumulateStructured(metrics *StructuredMetrics, record Record) {
	accumulateExact(&metrics.ExactMatchMetrics, record)
	if record.Expected.State != ValuePresent || record.Expected.Structured == nil {
		return
	}
	expected := fieldsByName(record.Expected.Structured.Fields)
	if record.Observed.State != ValuePresent || record.Observed.Structured == nil {
		metrics.ComparedFields += len(expected)
		return
	}
	observed := fieldsByName(record.Observed.Structured.Fields)
	union := make(map[string]struct{}, len(expected)+len(observed))
	for name := range expected {
		union[name] = struct{}{}
	}
	for name := range observed {
		union[name] = struct{}{}
	}
	metrics.ComparedFields += len(union)
	for name, expectedField := range expected {
		if observedField, exists := observed[name]; exists && equivalentStructuredField(expectedField, observedField) {
			metrics.MatchingFields++
		}
	}
}

func fieldsByName(fields []StructuredField) map[string]StructuredField {
	result := make(map[string]StructuredField, len(fields))
	for _, field := range fields {
		result[field.Name] = field
	}
	return result
}

func equivalentStructuredField(left, right StructuredField) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func accumulateError(metrics *ErrorMetrics, record Record, absolute, squared *float64) {
	if record.Expected.State != ValuePresent {
		return
	}
	metrics.Eligible++
	if record.Observed.State != ValuePresent {
		metrics.Abstained++
		return
	}
	var difference float64
	switch record.Expected.Kind {
	case ResultMetric:
		if record.Expected.Metric == nil || record.Observed.Metric == nil {
			return
		}
		difference = record.Observed.Metric.Value - record.Expected.Metric.Value
	case ResultCount:
		if record.Expected.Count == nil || record.Observed.Count == nil {
			return
		}
		difference = float64(record.Observed.Count.Value - record.Expected.Count.Value)
	default:
		return
	}
	metrics.Covered++
	*absolute += math.Abs(difference)
	*squared += difference * difference
}

func finalizeError(metrics *ErrorMetrics, absolute, squared float64) {
	if metrics.Covered == 0 {
		return
	}
	metrics.MAE = floatPointer(absolute / float64(metrics.Covered))
	metrics.RMSE = floatPointer(math.Sqrt(squared / float64(metrics.Covered)))
}

func accumulateDetection(metrics *DetectionMetrics, record Record) (float64, int) {
	if record.Expected.State != ValuePresent || record.Expected.Detection == nil {
		return 0, 0
	}
	metrics.EligibleSamples++
	expected := record.Expected.Detection.Objects
	metrics.ExpectedObjects += len(expected)
	if record.Observed.State != ValuePresent || record.Observed.Detection == nil {
		metrics.AbstainedSamples++
		metrics.FalseNegative += len(expected)
		return 0, 0
	}
	metrics.CoveredSamples++
	observed := record.Observed.Detection.Objects
	metrics.ObservedObjects += len(observed)
	weights := make([][]float64, maxInt(len(expected), len(observed)))
	valid := make([][]bool, len(weights))
	for index := range weights {
		weights[index] = make([]float64, len(weights))
		valid[index] = make([]bool, len(weights))
	}
	bonus := float64(len(weights) + 1)
	for expectedIndex, expectedObject := range expected {
		for observedIndex, observedObject := range observed {
			if expectedObject.Label != observedObject.Label {
				continue
			}
			iou := intersectionOverUnion(expectedObject.Region, observedObject.Region)
			if iou >= detectionIoUThreshold {
				valid[expectedIndex][observedIndex] = true
				weights[expectedIndex][observedIndex] = bonus + iou
			}
		}
	}
	assignment := maximumWeightAssignment(weights)
	iouSum := 0.0
	matches := 0
	for expectedIndex, observedIndex := range assignment {
		if expectedIndex >= len(expected) || observedIndex < 0 || observedIndex >= len(observed) || !valid[expectedIndex][observedIndex] {
			continue
		}
		matches++
		iouSum += weights[expectedIndex][observedIndex] - bonus
	}
	metrics.TruePositive += matches
	metrics.FalseNegative += len(expected) - matches
	metrics.FalsePositive += len(observed) - matches
	return iouSum, matches
}

// maximumWeightAssignment uses a deterministic Hungarian assignment. Every
// admissible detection edge receives a cardinality bonus larger than the
// maximum possible total IoU, so it first maximizes true-positive count and
// only then maximizes total matched IoU.
func maximumWeightAssignment(weights [][]float64) []int {
	n := len(weights)
	if n == 0 {
		return nil
	}
	u := make([]float64, n+1)
	v := make([]float64, n+1)
	p := make([]int, n+1)
	way := make([]int, n+1)
	for row := 1; row <= n; row++ {
		p[0] = row
		minv := make([]float64, n+1)
		used := make([]bool, n+1)
		for column := 1; column <= n; column++ {
			minv[column] = math.Inf(1)
		}
		column0 := 0
		for {
			used[column0] = true
			row0 := p[column0]
			delta := math.Inf(1)
			column1 := 0
			for column := 1; column <= n; column++ {
				if used[column] {
					continue
				}
				cost := -weights[row0-1][column-1] - u[row0] - v[column]
				if cost < minv[column] {
					minv[column] = cost
					way[column] = column0
				}
				if minv[column] < delta || (minv[column] == delta && column < column1) {
					delta = minv[column]
					column1 = column
				}
			}
			for column := 0; column <= n; column++ {
				if used[column] {
					u[p[column]] += delta
					v[column] -= delta
				} else {
					minv[column] -= delta
				}
			}
			column0 = column1
			if p[column0] == 0 {
				break
			}
		}
		for {
			column1 := way[column0]
			p[column0] = p[column1]
			column0 = column1
			if column0 == 0 {
				break
			}
		}
	}
	assignment := make([]int, n)
	for index := range assignment {
		assignment[index] = -1
	}
	for column := 1; column <= n; column++ {
		if p[column] > 0 {
			assignment[p[column]-1] = column - 1
		}
	}
	return assignment
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func intersectionOverUnion(left, right NormalizedRegion) float64 {
	leftXMax, leftYMax := left.X+left.Width, left.Y+left.Height
	rightXMax, rightYMax := right.X+right.Width, right.Y+right.Height
	intersectionWidth := math.Max(0, math.Min(leftXMax, rightXMax)-math.Max(left.X, right.X))
	intersectionHeight := math.Max(0, math.Min(leftYMax, rightYMax)-math.Max(left.Y, right.Y))
	intersection := intersectionWidth * intersectionHeight
	leftArea := left.Width * left.Height
	rightArea := right.Width * right.Height
	union := leftArea + rightArea - intersection
	if union <= 0 {
		return 0
	}
	return intersection / union
}

func accumulateEvent(metrics *EventMetrics, record Record) {
	if record.Expected.State != ValuePresent || record.Expected.Event == nil {
		return
	}
	metrics.Eligible++
	if record.Observed.State != ValuePresent || record.Observed.Event == nil {
		metrics.Abstained++
		if record.Expected.Event.Occurred {
			metrics.FalseNegative++
		}
		return
	}
	metrics.Covered++
	switch {
	case record.Expected.Event.Occurred && record.Observed.Event.Occurred:
		metrics.TruePositive++
	case !record.Expected.Event.Occurred && record.Observed.Event.Occurred:
		metrics.FalsePositive++
	case record.Expected.Event.Occurred && !record.Observed.Event.Occurred:
		metrics.FalseNegative++
	default:
		metrics.TrueNegative++
	}
}

func distribution(values []float64) Distribution {
	result := Distribution{Samples: len(values)}
	if len(values) == 0 {
		return result
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	sum := 0.0
	for _, value := range sorted {
		sum += value
	}
	result.Minimum = floatPointer(sorted[0])
	result.Maximum = floatPointer(sorted[len(sorted)-1])
	result.Mean = floatPointer(sum / float64(len(sorted)))
	result.P50 = floatPointer(nearestRank(sorted, 0.50))
	result.P95 = floatPointer(nearestRank(sorted, 0.95))
	result.P99 = floatPointer(nearestRank(sorted, 0.99))
	return result
}

func nearestRank(sorted []float64, percentile float64) float64 {
	rank := int(math.Ceil(percentile * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func ratio(numerator, denominator int) Ratio {
	result := Ratio{Numerator: numerator, Denominator: denominator}
	if denominator > 0 {
		result.Value = floatPointer(float64(numerator) / float64(denominator))
	}
	return result
}

func floatPointer(value float64) *float64 { return &value }
