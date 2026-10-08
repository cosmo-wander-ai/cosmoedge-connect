// Package report composes deterministic, presentation-safe inspection reports
// from the typed inspection plan and Oracle outcome. It intentionally does not
// expose camera handles, compiled prompts, raw analyzer text, device addresses,
// or internal model facts.
package report

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	inspection "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const SchemaVersion = "cosmoedge.inspection.report.v2"

const (
	visibleScopeLimitation = "仅反映本次采样中摄像头可见范围，不替代人工复核或监管合规结论。"

	// These ceilings mirror the frozen-plan, stored-outcome, and HTTP public
	// projection limits. Keep report composition inside the same bounded public
	// data contract rather than creating a larger downstream trust boundary.
	maxPublicItems          = 10_000
	maxFindingSamples       = 100
	maxFindingReasonCodes   = 32
	maxFindingEvidenceRefs  = 32
	maxFindingResults       = 100
	maxFindingLimitations   = 16
	maxReportLimitations    = 16
	maxPublicReferenceBytes = 128
)

// ErrResourceLimitExceeded identifies report input that cannot be composed
// without exceeding the bounded public inspection contract. Callers must not
// treat this as permission to truncate findings or other business facts.
var ErrResourceLimitExceeded = errors.New("inspection report resource limit exceeded")

var (
	publicRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	protectedText    = regexp.MustCompile(`(?i)(?:https?|rtsps?)://|(?:image)?base64|"(?:password|token|cookie|authorization|endpoint|deviceId|cameraId|prompt|raw)"\s*:`)
)

// Coverage is a stable report projection of the Oracle-owned coverage facts.
type Coverage struct {
	Required     int     `json:"required"`
	Conclusive   int     `json:"conclusive"`
	Inconclusive int     `json:"inconclusive"`
	Missing      int     `json:"missing"`
	Ratio        float64 `json:"ratio"`
}

// Freshness reports observable timestamps without inventing a stale threshold.
type Freshness struct {
	Status              string     `json:"status"`
	OldestObservationAt *time.Time `json:"oldestObservationAt,omitempty"`
	LatestObservationAt *time.Time `json:"latestObservationAt,omitempty"`
	OldestAgeSeconds    *int64     `json:"oldestAgeSeconds,omitempty"`
}

// Finding contains only friendly target and criterion labels plus an opaque
// evidence reference. Source reason codes, facts, prompts, and model prose do
// not cross this boundary.
type Finding struct {
	Target       string                `json:"target"`
	Criterion    string                `json:"criterion"`
	Assessment   inspection.Assessment `json:"assessment"`
	SampleCount  int                   `json:"sampleCount"`
	EvidenceRefs []string              `json:"evidenceRefs"`
	Results      []Result              `json:"results"`
	ObservedAt   *time.Time            `json:"observedAt,omitempty"`
	Limitations  []string              `json:"limitations"`
}

// Result is the standard-report projection of one typed sample. It contains no
// source identity, analyzer metadata, execution internals, display text, or
// unrestricted model prose.
type Result struct {
	ResultRef    string                  `json:"resultRef"`
	SampleRef    string                  `json:"sampleRef"`
	Kind         inspection.ResultKind   `json:"kind"`
	Value        *inspection.ResultValue `json:"value,omitempty"`
	EvidenceRefs []string                `json:"evidenceRefs"`
	StartAt      time.Time               `json:"startAt"`
	EndAt        time.Time               `json:"endAt"`
}

// Immediate is the deterministic report for one inspection run.
type Immediate struct {
	Schema            string                `json:"schema"`
	Kind              string                `json:"kind"`
	RunRef            string                `json:"runRef"`
	Site              string                `json:"site"`
	ExecutionState    inspection.RunState   `json:"executionState"`
	OverallAssessment inspection.Assessment `json:"overallAssessment"`
	Summary           string                `json:"summary"`
	Coverage          Coverage              `json:"coverage"`
	Freshness         Freshness             `json:"freshness"`
	Findings          []Finding             `json:"findings"`
	Limitations       []string              `json:"limitations"`
	GeneratedAt       time.Time             `json:"generatedAt"`
}

// RunCounts keeps execution completion distinct from the business assessment.
type RunCounts struct {
	Total          int `json:"total"`
	Completed      int `json:"completed"`
	Partial        int `json:"partial"`
	OtherTerminal  int `json:"otherTerminal"`
	MeetsRule      int `json:"meetsRule"`
	NeedsAttention int `json:"needsAttention"`
	Inconclusive   int `json:"inconclusive"`
}

// DailyRun is a bounded run-level projection used by the daily report.
type DailyRun struct {
	RunRef            string                `json:"runRef"`
	ExecutionState    inspection.RunState   `json:"executionState"`
	OverallAssessment inspection.Assessment `json:"overallAssessment"`
	Coverage          Coverage              `json:"coverage"`
	GeneratedAt       time.Time             `json:"generatedAt"`
}

// Highlight keeps the originating opaque run reference while retaining only
// the safe finding projection.
type Highlight struct {
	RunRef       string                `json:"runRef"`
	Target       string                `json:"target"`
	Criterion    string                `json:"criterion"`
	Assessment   inspection.Assessment `json:"assessment"`
	EvidenceRefs []string              `json:"evidenceRefs"`
	Results      []Result              `json:"results"`
	ObservedAt   *time.Time            `json:"observedAt,omitempty"`
	Limitations  []string              `json:"limitations"`
}

// Daily aggregates already-composed run reports for one site-local day.
type Daily struct {
	Schema            string                `json:"schema"`
	Kind              string                `json:"kind"`
	Site              string                `json:"site"`
	Day               string                `json:"day"`
	Timezone          string                `json:"timezone"`
	OverallAssessment inspection.Assessment `json:"overallAssessment"`
	Summary           string                `json:"summary"`
	RunCounts         RunCounts             `json:"runCounts"`
	Coverage          Coverage              `json:"coverage"`
	Freshness         Freshness             `json:"freshness"`
	Runs              []DailyRun            `json:"runs"`
	Highlights        []Highlight           `json:"highlights"`
	Limitations       []string              `json:"limitations"`
	GeneratedAt       time.Time             `json:"generatedAt"`
}

type planKey struct {
	targetID    string
	criterionID string
}

type plannedLabel struct {
	targetID        string
	criterionID     string
	target          string
	criterion       string
	required        bool
	evidence        bool
	expectedSamples int
}

// ComposeImmediate produces a safe report without reinterpreting analyzer
// prose. Business assessment remains separate from execution completion.
func ComposeImmediate(run inspection.Run, plan inspection.ExecutionPlan, outcome inspection.Outcome, generatedAt time.Time) (Immediate, error) {
	if err := validateInputs(run, plan, outcome, generatedAt); err != nil {
		return Immediate{}, err
	}
	if err := validateOutcomeResourceBounds(outcome); err != nil {
		return Immediate{}, err
	}
	labels, required, err := planLabels(plan)
	if err != nil {
		return Immediate{}, err
	}
	if err := validateCoverage(outcome.Coverage, required, outcome.State); err != nil {
		return Immediate{}, err
	}

	sourceFindings := make(map[planKey]inspection.Finding, len(outcome.Findings))
	for _, finding := range outcome.Findings {
		key := planKey{targetID: finding.TargetID, criterionID: finding.CriterionID}
		if _, ok := labels[key]; !ok {
			return Immediate{}, errors.New("inspection outcome contains a finding outside the frozen plan")
		}
		if _, duplicate := sourceFindings[key]; duplicate {
			return Immediate{}, errors.New("inspection outcome repeats a target and criterion finding")
		}
		if !finding.Assessment.Valid() || finding.SampleCount < 0 {
			return Immediate{}, errors.New("inspection outcome finding is invalid")
		}
		sourceFindings[key] = finding
	}

	ordered := make([]plannedLabel, 0, len(labels))
	for _, label := range labels {
		ordered = append(ordered, label)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].target != ordered[j].target {
			return ordered[i].target < ordered[j].target
		}
		if ordered[i].criterion != ordered[j].criterion {
			return ordered[i].criterion < ordered[j].criterion
		}
		if ordered[i].targetID != ordered[j].targetID {
			return ordered[i].targetID < ordered[j].targetID
		}
		return ordered[i].criterionID < ordered[j].criterionID
	})

	findings := make([]Finding, 0, len(ordered))
	for _, label := range ordered {
		key := planKey{targetID: label.targetID, criterionID: label.criterionID}
		source, ok := sourceFindings[key]
		if !ok {
			if outcome.State == inspection.RunCompleted {
				return Immediate{}, errors.New("completed inspection outcome is missing a planned finding")
			}
			source = inspection.Finding{Assessment: inspection.AssessmentNotObservable}
		}
		projected, err := projectFinding(label, source, generatedAt)
		if err != nil {
			return Immediate{}, err
		}
		findings = append(findings, projected)
	}
	if err := validateProjectedOutcome(ordered, findings, outcome); err != nil {
		return Immediate{}, err
	}

	overallAssessment := outcome.OverallAssessment
	if !overallAssessment.Valid() {
		overallAssessment = inspection.AssessmentUncertain
	}
	if outcome.State == inspection.RunCompleted && overallAssessment != inspection.AssessmentMeetsRule && overallAssessment != inspection.AssessmentNeedsAttention {
		return Immediate{}, errors.New("completed inspection outcome lacks a conclusive business assessment")
	}
	limitations := reportLimitations(run, plan, outcome, findings)
	report := Immediate{
		Schema: SchemaVersion, Kind: "immediate", RunRef: run.RunID, Site: plan.SiteID,
		ExecutionState: outcome.State, OverallAssessment: overallAssessment,
		Summary: summaryFor(outcome.State, overallAssessment), Coverage: projectCoverage(outcome.Coverage),
		Freshness: composeFreshness(findings, generatedAt), Findings: findings,
		Limitations: limitations, GeneratedAt: generatedAt.UTC(),
	}
	if err := validateImmediatePublic(report); err != nil {
		return Immediate{}, err
	}
	return report, nil
}

// ComposeDaily aggregates reports generated for one site-local calendar day.
// The generated time is derived deterministically from the latest input report,
// or the start of the requested day when there are no runs.
func ComposeDaily(site string, day time.Time, reports []Immediate) (Daily, error) {
	if err := validateFriendly("site", site); err != nil || day.IsZero() {
		return Daily{}, errors.New("complete daily report site and day are required")
	}
	if err := validateItemLimit("daily run reports", len(reports), maxPublicItems); err != nil {
		return Daily{}, err
	}
	location := day.Location()
	if err := validateFriendly("timezone", location.String()); err != nil {
		return Daily{}, err
	}
	dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, location)
	dayKey := dayStart.Format("2006-01-02")
	totalFindings := 0
	totalHighlights := 0
	seenRunRefs := make(map[string]struct{}, len(reports))
	for _, report := range reports {
		if len(report.Findings) > maxPublicItems-totalFindings {
			return Daily{}, resourceLimitError("daily findings", maxPublicItems)
		}
		if err := validateImmediatePublic(report); err != nil {
			return Daily{}, err
		}
		if report.Site != site || report.GeneratedAt.In(location).Format("2006-01-02") != dayKey {
			return Daily{}, errors.New("daily report contains a run outside its site or local day")
		}
		if _, duplicate := seenRunRefs[report.RunRef]; duplicate {
			return Daily{}, errors.New("daily report repeats a run reference")
		}
		seenRunRefs[report.RunRef] = struct{}{}
		totalFindings += len(report.Findings)
		for _, finding := range report.Findings {
			if finding.Assessment != inspection.AssessmentMeetsRule {
				totalHighlights++
			}
		}
	}
	ordered := append([]Immediate(nil), reports...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].GeneratedAt.Equal(ordered[j].GeneratedAt) {
			return ordered[i].GeneratedAt.Before(ordered[j].GeneratedAt)
		}
		return ordered[i].RunRef < ordered[j].RunRef
	})

	daily := Daily{
		Schema: SchemaVersion, Kind: "daily", Site: site, Day: dayKey, Timezone: location.String(),
		OverallAssessment: inspection.AssessmentUncertain,
		Runs:              make([]DailyRun, 0, len(ordered)),
		Highlights:        make([]Highlight, 0, totalHighlights),
		Limitations:       []string{visibleScopeLimitation},
		GeneratedAt:       dayStart.UTC(),
	}
	allCompleteAndMeet := len(ordered) > 0
	attention := false
	hasIncomplete := false
	allFindings := make([]Finding, 0, totalFindings)
	for _, report := range ordered {
		daily.RunCounts.Total++
		switch report.ExecutionState {
		case inspection.RunCompleted:
			daily.RunCounts.Completed++
		case inspection.RunPartial:
			daily.RunCounts.Partial++
			hasIncomplete = true
		default:
			daily.RunCounts.OtherTerminal++
			hasIncomplete = true
		}
		switch report.OverallAssessment {
		case inspection.AssessmentMeetsRule:
			daily.RunCounts.MeetsRule++
		case inspection.AssessmentNeedsAttention:
			daily.RunCounts.NeedsAttention++
			attention = true
		default:
			daily.RunCounts.Inconclusive++
		}
		if report.ExecutionState != inspection.RunCompleted || report.OverallAssessment != inspection.AssessmentMeetsRule {
			allCompleteAndMeet = false
		}
		daily.Coverage.Required += report.Coverage.Required
		daily.Coverage.Conclusive += report.Coverage.Conclusive
		daily.Coverage.Inconclusive += report.Coverage.Inconclusive
		daily.Coverage.Missing += report.Coverage.Missing
		daily.Runs = append(daily.Runs, DailyRun{
			RunRef: report.RunRef, ExecutionState: report.ExecutionState,
			OverallAssessment: report.OverallAssessment, Coverage: report.Coverage,
			GeneratedAt: report.GeneratedAt.UTC(),
		})
		if report.GeneratedAt.After(daily.GeneratedAt) {
			daily.GeneratedAt = report.GeneratedAt.UTC()
		}
		allFindings = append(allFindings, report.Findings...)
		for _, finding := range report.Findings {
			if finding.Assessment == inspection.AssessmentMeetsRule {
				continue
			}
			daily.Highlights = append(daily.Highlights, Highlight{
				RunRef: report.RunRef, Target: finding.Target, Criterion: finding.Criterion,
				Assessment: finding.Assessment, EvidenceRefs: append([]string{}, finding.EvidenceRefs...),
				Results:    clonePublicResults(finding.Results),
				ObservedAt: cloneTime(finding.ObservedAt), Limitations: append([]string{}, finding.Limitations...),
			})
		}
	}
	if daily.Coverage.Required > 0 {
		daily.Coverage.Ratio = float64(daily.Coverage.Conclusive) / float64(daily.Coverage.Required)
	}
	daily.Freshness = composeFreshness(allFindings, daily.GeneratedAt)
	sort.SliceStable(daily.Highlights, func(i, j int) bool {
		if daily.Highlights[i].RunRef != daily.Highlights[j].RunRef {
			return daily.Highlights[i].RunRef < daily.Highlights[j].RunRef
		}
		if daily.Highlights[i].Target != daily.Highlights[j].Target {
			return daily.Highlights[i].Target < daily.Highlights[j].Target
		}
		return daily.Highlights[i].Criterion < daily.Highlights[j].Criterion
	})

	switch {
	case len(ordered) == 0:
		daily.Summary = "本日没有可汇总的巡检报告，无法判断现场情况。"
		daily.Limitations = append(daily.Limitations, "本日没有已生成的巡检观察。")
	case attention:
		daily.OverallAssessment = inspection.AssessmentNeedsAttention
		if hasIncomplete {
			daily.Summary = fmt.Sprintf("本日汇总 %d 次巡检，其中 %d 次发现需要关注的可见情况；同时存在部分或不确定结果，不能判断全部范围。", daily.RunCounts.Total, daily.RunCounts.NeedsAttention)
			daily.Limitations = append(daily.Limitations, "本日存在未完整覆盖或结论不确定的巡检。")
		} else {
			daily.Summary = fmt.Sprintf("本日汇总 %d 次巡检，其中 %d 次发现需要关注的可见情况。", daily.RunCounts.Total, daily.RunCounts.NeedsAttention)
		}
	case allCompleteAndMeet:
		daily.OverallAssessment = inspection.AssessmentMeetsRule
		daily.Summary = fmt.Sprintf("本日汇总 %d 次完整巡检；各次已覆盖的可见范围符合当前规则，但不代表全面卫生或监管合规。", daily.RunCounts.Total)
	default:
		daily.Summary = fmt.Sprintf("本日汇总 %d 次巡检，其中存在部分或不确定结果，不能判断全部范围符合当前规则。", daily.RunCounts.Total)
		daily.Limitations = append(daily.Limitations, "本日存在未完整覆盖或结论不确定的巡检。")
	}
	daily.Limitations = uniqueSorted(daily.Limitations)
	if err := validateDailyPublic(daily); err != nil {
		return Daily{}, err
	}
	return daily, nil
}

func validateOutcomeResourceBounds(outcome inspection.Outcome) error {
	if err := validateItemLimit("outcome findings", len(outcome.Findings), maxPublicItems); err != nil {
		return err
	}
	for _, value := range []struct {
		name  string
		count int
	}{
		{name: "outcome required coverage", count: outcome.Coverage.Required},
		{name: "outcome conclusive coverage", count: outcome.Coverage.Conclusive},
		{name: "outcome inconclusive coverage", count: outcome.Coverage.Inconclusive},
		{name: "outcome missing coverage", count: outcome.Coverage.Missing},
	} {
		if value.count > maxPublicItems {
			return resourceLimitError(value.name, maxPublicItems)
		}
	}
	for _, finding := range outcome.Findings {
		if finding.SampleCount > maxFindingSamples {
			return resourceLimitError("finding sample count", maxFindingSamples)
		}
		if err := validateItemLimit("finding reason codes", len(finding.ReasonCodes), maxFindingReasonCodes); err != nil {
			return err
		}
		if err := validateItemLimit("finding evidence references", len(finding.EvidenceRefs), maxFindingEvidenceRefs); err != nil {
			return err
		}
		if err := validateItemLimit("finding typed results", len(finding.Results), maxFindingResults); err != nil {
			return err
		}
		if err := validateItemLimit("finding limitations", len(finding.Limitations), maxFindingLimitations); err != nil {
			return err
		}
	}
	return nil
}

func validateInputs(run inspection.Run, plan inspection.ExecutionPlan, outcome inspection.Outcome, generatedAt time.Time) error {
	if !inspection.Terminal(run.State) || run.State != outcome.State || run.RunID == "" || run.UpdatedAt.IsZero() || generatedAt.IsZero() {
		return errors.New("complete terminal inspection run and outcome are required")
	}
	if generatedAt.Before(run.UpdatedAt) {
		return errors.New("inspection report generation time precedes the terminal run")
	}
	if run.TenantID != plan.TenantID || run.SiteID != plan.SiteID || run.PlanSHA256 == "" || run.PlanSHA256 != plan.PlanSHA256 {
		return errors.New("inspection report run and plan bindings do not match")
	}
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("validate frozen inspection plan: %w", err)
	}
	if run.PersistentConfigWrites != 0 {
		return errors.New("inspection report cannot project a persistent device configuration write")
	}
	return nil
}

func planLabels(plan inspection.ExecutionPlan) (map[planKey]plannedLabel, int, error) {
	labels := map[planKey]plannedLabel{}
	required := 0
	for _, target := range plan.Targets {
		if err := validateFriendly("target", target.FriendlyName); err != nil {
			return nil, 0, err
		}
		for _, plannedCriterion := range target.Criteria {
			criterion := plannedCriterion.Criterion
			if err := validateFriendly("criterion", criterion.Name); err != nil {
				return nil, 0, err
			}
			key := planKey{targetID: target.TargetID, criterionID: criterion.ID}
			if _, exists := labels[key]; exists {
				return nil, 0, errors.New("inspection plan repeats a target and criterion binding")
			}
			labels[key] = plannedLabel{
				targetID: target.TargetID, criterionID: criterion.ID,
				target: target.FriendlyName, criterion: criterion.Name,
				required: criterion.Required, evidence: plan.Evidence.Required,
				expectedSamples: target.Acquisition.Samples,
			}
			if criterion.Required {
				required++
			}
		}
	}
	if len(labels) == 0 || required == 0 {
		return nil, 0, errors.New("inspection plan has no reportable required criteria")
	}
	return labels, required, nil
}

func projectFinding(label plannedLabel, source inspection.Finding, generatedAt time.Time) (Finding, error) {
	evidence, err := safeEvidenceRefs(source.EvidenceRefs)
	if err != nil {
		return Finding{}, err
	}
	results := make([]Result, 0, len(source.Results))
	resultEvidence := make([]string, 0, len(source.EvidenceRefs))
	for _, value := range source.Results {
		if err := value.Validate(); err != nil {
			return Finding{}, fmt.Errorf("invalid Oracle result projection: %w", err)
		}
		if value.TimeWindow.EndAt.After(generatedAt) {
			return Finding{}, errors.New("inspection typed result is newer than its report")
		}
		refs, err := safeEvidenceRefs(value.EvidenceRefs)
		if err != nil {
			return Finding{}, err
		}
		results = append(results, Result{
			ResultRef: value.ResultID, SampleRef: value.SampleID, Kind: value.OutputKind,
			Value: cloneReportResultValue(value.Value), EvidenceRefs: refs,
			StartAt: value.TimeWindow.StartAt.UTC(), EndAt: value.TimeWindow.EndAt.UTC(),
		})
		resultEvidence = append(resultEvidence, refs...)
	}
	if source.SampleCount != len(source.Results) {
		return Finding{}, errors.New("inspection finding sample count does not match its typed results")
	}
	if !sameStrings(evidence, uniqueSorted(resultEvidence)) {
		return Finding{}, errors.New("inspection finding evidence does not match its typed results")
	}
	projected := Finding{
		Target: label.target, Criterion: label.criterion, Assessment: source.Assessment,
		SampleCount: source.SampleCount, EvidenceRefs: evidence, Results: results, Limitations: []string{},
	}
	if !source.ObservedAt.IsZero() {
		observedAt := source.ObservedAt.UTC()
		if observedAt.After(generatedAt) {
			return Finding{}, errors.New("inspection finding observation is newer than its report")
		}
		projected.ObservedAt = &observedAt
	}
	switch source.Assessment {
	case inspection.AssessmentUncertain:
		projected.Limitations = append(projected.Limitations, "该项观察不确定，不能判断是否符合当前规则。")
	case inspection.AssessmentNotObservable:
		projected.Limitations = append(projected.Limitations, "该项在本次采样中不可观察。")
	case inspection.AssessmentUnsupported:
		projected.Limitations = append(projected.Limitations, "当前执行能力不支持该项判断。")
	}
	if source.SampleCount == 0 || projected.ObservedAt == nil {
		projected.Limitations = append(projected.Limitations, "未取得可用于判断的新鲜观察。")
	}
	if source.SampleCount > 0 && source.SampleCount < label.expectedSamples {
		projected.Limitations = append(projected.Limitations, "未取得冻结采样计划要求的全部样本。")
	}
	if label.evidence && len(evidence) == 0 {
		projected.Limitations = append(projected.Limitations, "该项没有可展示的快照证据。")
	}
	projected.Limitations = uniqueSorted(projected.Limitations)
	return projected, nil
}

func validateCoverage(coverage inspection.Coverage, expectedRequired int, state inspection.RunState) error {
	if coverage.Required != expectedRequired || coverage.Conclusive < 0 || coverage.Inconclusive < 0 || coverage.Missing < 0 ||
		coverage.Conclusive+coverage.Inconclusive+coverage.Missing != coverage.Required {
		return errors.New("inspection outcome coverage does not match the frozen plan")
	}
	expectedRatio := float64(coverage.Conclusive) / float64(coverage.Required)
	if math.Abs(coverage.Ratio-expectedRatio) > 1e-9 {
		return errors.New("inspection outcome coverage ratio is inconsistent")
	}
	if state == inspection.RunCompleted && coverage.Conclusive != coverage.Required {
		return errors.New("completed inspection outcome is not fully conclusive")
	}
	if state == inspection.RunPartial && coverage.Conclusive == coverage.Required {
		return errors.New("partial inspection outcome claims complete coverage")
	}
	return nil
}

func validateProjectedOutcome(labels []plannedLabel, findings []Finding, outcome inspection.Outcome) error {
	if len(labels) != len(findings) {
		return errors.New("inspection report finding projection is incomplete")
	}
	derived := inspection.Coverage{}
	attention := false
	for index, finding := range findings {
		if finding.Assessment == inspection.AssessmentNeedsAttention {
			attention = true
		}
		if finding.SampleCount > labels[index].expectedSamples {
			return errors.New("inspection finding exceeds the frozen sample count")
		}
		samplesComplete := finding.SampleCount == labels[index].expectedSamples
		if (finding.Assessment == inspection.AssessmentMeetsRule || finding.Assessment == inspection.AssessmentNeedsAttention) &&
			(!samplesComplete || finding.ObservedAt == nil) && outcome.State == inspection.RunCompleted {
			return errors.New("conclusive inspection finding has no observed sample")
		}
		if !labels[index].required {
			continue
		}
		derived.Required++
		if finding.SampleCount == 0 {
			derived.Missing++
			continue
		}
		if !samplesComplete {
			derived.Inconclusive++
			continue
		}
		switch finding.Assessment {
		case inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention:
			derived.Conclusive++
		default:
			derived.Inconclusive++
		}
	}
	if derived.Required > 0 {
		derived.Ratio = float64(derived.Conclusive) / float64(derived.Required)
	}
	if derived.Required != outcome.Coverage.Required || derived.Conclusive != outcome.Coverage.Conclusive ||
		derived.Inconclusive != outcome.Coverage.Inconclusive || derived.Missing != outcome.Coverage.Missing ||
		math.Abs(derived.Ratio-outcome.Coverage.Ratio) > 1e-9 {
		return errors.New("inspection findings do not support the reported coverage")
	}
	if outcome.State == inspection.RunCompleted || outcome.State == inspection.RunPartial {
		expectedAssessment := inspection.AssessmentUncertain
		if attention {
			expectedAssessment = inspection.AssessmentNeedsAttention
		} else if derived.Conclusive == derived.Required {
			expectedAssessment = inspection.AssessmentMeetsRule
		}
		if outcome.OverallAssessment != expectedAssessment {
			return errors.New("inspection findings do not support the overall assessment")
		}
	}
	return nil
}

func projectCoverage(value inspection.Coverage) Coverage {
	return Coverage{Required: value.Required, Conclusive: value.Conclusive, Inconclusive: value.Inconclusive, Missing: value.Missing, Ratio: value.Ratio}
}

func summaryFor(state inspection.RunState, assessment inspection.Assessment) string {
	switch state {
	case inspection.RunCompleted:
		if assessment == inspection.AssessmentNeedsAttention {
			return "本次巡检执行完整，至少一项可见情况需要关注。"
		}
		return "本次巡检执行完整；已覆盖的可见范围符合当前规则，但不代表全面卫生或监管合规。"
	case inspection.RunPartial:
		if assessment == inspection.AssessmentNeedsAttention {
			return "本次巡检仅形成部分可信观察；已观察到需要关注的情况，其余范围不能判断。"
		}
		return "本次巡检仅形成部分可信观察，不能判断全部范围符合当前规则。"
	case inspection.RunUnknown:
		return "本次巡检执行结果不确定，不能据此判断现场是否符合当前规则。"
	case inspection.RunBlocked:
		return "本次巡检未进入有效观察阶段，无法形成现场判断。"
	case inspection.RunFailed:
		return "本次巡检执行失败，无法形成现场判断。"
	case inspection.RunCancelled:
		return "本次巡检已取消，无法形成完整现场判断。"
	case inspection.RunExpired:
		return "本次巡检已过期，无法形成完整现场判断。"
	default:
		return "本次巡检没有可报告的终态。"
	}
}

func reportLimitations(run inspection.Run, plan inspection.ExecutionPlan, outcome inspection.Outcome, findings []Finding) []string {
	limitations := []string{visibleScopeLimitation}
	if outcome.State != inspection.RunCompleted {
		limitations = append(limitations, "本次巡检未完整覆盖所有必选检查项。")
	}
	if run.CleanupPending > 0 {
		limitations = append(limitations, "本次巡检仍有临时资源等待清理。")
	}
	if run.UpdatedAt.After(plan.Deadline) {
		limitations = append(limitations, "本次巡检在请求期限之后才形成终态。")
	}
	observed := false
	for _, finding := range findings {
		if finding.ObservedAt != nil {
			observed = true
			break
		}
	}
	if !observed {
		limitations = append(limitations, "没有可用于判断新鲜度的观察时间。")
	}
	return uniqueSorted(limitations)
}

func composeFreshness(findings []Finding, generatedAt time.Time) Freshness {
	var oldest, latest time.Time
	observed := 0
	for _, finding := range findings {
		if finding.ObservedAt == nil {
			continue
		}
		observed++
		value := finding.ObservedAt.UTC()
		if oldest.IsZero() || value.Before(oldest) {
			oldest = value
		}
		if value.After(latest) {
			latest = value
		}
	}
	if observed == 0 {
		return Freshness{Status: "unavailable"}
	}
	age := int64(generatedAt.UTC().Sub(oldest).Seconds())
	status := "complete"
	if observed < len(findings) {
		status = "partial"
	}
	return Freshness{Status: status, OldestObservationAt: &oldest, LatestObservationAt: &latest, OldestAgeSeconds: &age}
}

func validateImmediatePublic(report Immediate) error {
	if err := validateItemLimit("immediate findings", len(report.Findings), maxPublicItems); err != nil {
		return err
	}
	if err := validateItemLimit("immediate limitations", len(report.Limitations), maxReportLimitations); err != nil {
		return err
	}
	if report.Schema != SchemaVersion || report.Kind != "immediate" || !inspection.Terminal(report.ExecutionState) ||
		!report.OverallAssessment.Valid() || report.GeneratedAt.IsZero() || !validPublicRef(report.RunRef) {
		return errors.New("invalid immediate inspection report")
	}
	if err := validateFriendly("site", report.Site); err != nil {
		return err
	}
	if err := validateSafeText("summary", report.Summary, 500); err != nil {
		return err
	}
	if err := validatePublicCoverage(report.Coverage); err != nil {
		return err
	}
	if report.Coverage.Required > len(report.Findings) {
		return errors.New("immediate inspection report coverage exceeds its findings")
	}
	for _, finding := range report.Findings {
		if err := validateFriendly("target", finding.Target); err != nil {
			return err
		}
		if err := validateFriendly("criterion", finding.Criterion); err != nil {
			return err
		}
		if finding.SampleCount > maxFindingSamples {
			return resourceLimitError("finding sample count", maxFindingSamples)
		}
		if !finding.Assessment.Valid() || finding.SampleCount < 0 ||
			(finding.ObservedAt != nil && (finding.ObservedAt.IsZero() || finding.ObservedAt.After(report.GeneratedAt))) {
			return errors.New("invalid immediate inspection finding")
		}
		if _, err := safeEvidenceRefs(finding.EvidenceRefs); err != nil {
			return err
		}
		if len(finding.Results) != finding.SampleCount || len(finding.Results) > maxFindingResults {
			return errors.New("invalid immediate inspection typed result count")
		}
		for _, result := range finding.Results {
			if err := validatePublicResult(result, report.GeneratedAt); err != nil {
				return err
			}
		}
		if err := validateItemLimit("finding limitations", len(finding.Limitations), maxFindingLimitations); err != nil {
			return err
		}
		for _, limitation := range finding.Limitations {
			if err := validateSafeText("finding limitation", limitation, 500); err != nil {
				return err
			}
		}
	}
	for _, limitation := range report.Limitations {
		if err := validateSafeText("report limitation", limitation, 500); err != nil {
			return err
		}
	}
	return nil
}

func validateDailyPublic(report Daily) error {
	if err := validateItemLimit("daily runs", len(report.Runs), maxPublicItems); err != nil {
		return err
	}
	if err := validateItemLimit("daily highlights", len(report.Highlights), maxPublicItems); err != nil {
		return err
	}
	if err := validateItemLimit("daily limitations", len(report.Limitations), maxReportLimitations); err != nil {
		return err
	}
	if report.Schema != SchemaVersion || report.Kind != "daily" || !report.OverallAssessment.Valid() || report.GeneratedAt.IsZero() {
		return errors.New("invalid daily inspection report")
	}
	if err := validateFriendly("site", report.Site); err != nil {
		return err
	}
	if err := validateSafeText("day", report.Day, len("2006-01-02")); err != nil {
		return err
	}
	if err := validateFriendly("timezone", report.Timezone); err != nil {
		return err
	}
	if err := validateSafeText("summary", report.Summary, 500); err != nil {
		return err
	}
	if err := validatePublicCoverage(report.Coverage); err != nil {
		return err
	}
	if report.RunCounts.Total != len(report.Runs) || report.RunCounts.Completed < 0 || report.RunCounts.Partial < 0 ||
		report.RunCounts.OtherTerminal < 0 || report.RunCounts.MeetsRule < 0 || report.RunCounts.NeedsAttention < 0 ||
		report.RunCounts.Inconclusive < 0 ||
		report.RunCounts.Completed+report.RunCounts.Partial+report.RunCounts.OtherTerminal != report.RunCounts.Total ||
		report.RunCounts.MeetsRule+report.RunCounts.NeedsAttention+report.RunCounts.Inconclusive != report.RunCounts.Total {
		return errors.New("invalid daily inspection run counts")
	}
	seenRunRefs := make(map[string]struct{}, len(report.Runs))
	for _, run := range report.Runs {
		if !validPublicRef(run.RunRef) || !inspection.Terminal(run.ExecutionState) ||
			!run.OverallAssessment.Valid() || run.GeneratedAt.IsZero() || run.GeneratedAt.After(report.GeneratedAt) {
			return errors.New("invalid daily inspection run")
		}
		if _, duplicate := seenRunRefs[run.RunRef]; duplicate {
			return errors.New("daily inspection report repeats a run reference")
		}
		seenRunRefs[run.RunRef] = struct{}{}
		if err := validatePublicCoverage(run.Coverage); err != nil {
			return err
		}
	}
	for _, highlight := range report.Highlights {
		if !validPublicRef(highlight.RunRef) || !highlight.Assessment.Valid() ||
			(highlight.ObservedAt != nil && (highlight.ObservedAt.IsZero() || highlight.ObservedAt.After(report.GeneratedAt))) {
			return errors.New("invalid daily inspection highlight")
		}
		if err := validateFriendly("target", highlight.Target); err != nil {
			return err
		}
		if err := validateFriendly("criterion", highlight.Criterion); err != nil {
			return err
		}
		if _, err := safeEvidenceRefs(highlight.EvidenceRefs); err != nil {
			return err
		}
		if len(highlight.Results) > maxFindingResults {
			return resourceLimitError("highlight typed results", maxFindingResults)
		}
		for _, result := range highlight.Results {
			if err := validatePublicResult(result, report.GeneratedAt); err != nil {
				return err
			}
		}
		if err := validateItemLimit("highlight limitations", len(highlight.Limitations), maxFindingLimitations); err != nil {
			return err
		}
		for _, limitation := range highlight.Limitations {
			if err := validateSafeText("highlight limitation", limitation, 500); err != nil {
				return err
			}
		}
	}
	for _, limitation := range report.Limitations {
		if err := validateSafeText("daily limitation", limitation, 500); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicCoverage(coverage Coverage) error {
	for _, value := range []struct {
		name  string
		count int
	}{
		{name: "required coverage", count: coverage.Required},
		{name: "conclusive coverage", count: coverage.Conclusive},
		{name: "inconclusive coverage", count: coverage.Inconclusive},
		{name: "missing coverage", count: coverage.Missing},
	} {
		if value.count > maxPublicItems {
			return resourceLimitError(value.name, maxPublicItems)
		}
		if value.count < 0 {
			return errors.New("inspection report coverage is invalid")
		}
	}
	if math.IsNaN(coverage.Ratio) || math.IsInf(coverage.Ratio, 0) || coverage.Ratio < 0 || coverage.Ratio > 1 ||
		coverage.Conclusive+coverage.Inconclusive+coverage.Missing != coverage.Required {
		return errors.New("inspection report coverage is invalid")
	}
	expectedRatio := 0.0
	if coverage.Required > 0 {
		expectedRatio = float64(coverage.Conclusive) / float64(coverage.Required)
	}
	if math.Abs(coverage.Ratio-expectedRatio) > 1e-9 {
		return errors.New("inspection report coverage ratio is inconsistent")
	}
	return nil
}

func safeEvidenceRefs(values []string) ([]string, error) {
	if err := validateItemLimit("finding evidence references", len(values), maxFindingEvidenceRefs); err != nil {
		return nil, err
	}
	for _, value := range values {
		if !validPublicRef(value) || protectedText.MatchString(value) {
			return nil, errors.New("inspection report evidence reference is not opaque")
		}
	}
	result := uniqueSorted(values)
	return result, nil
}

func validatePublicResult(result Result, generatedAt time.Time) error {
	if !validPublicRef(result.ResultRef) || !validPublicRef(result.SampleRef) || !result.Kind.Valid() ||
		result.StartAt.IsZero() || result.EndAt.IsZero() || result.EndAt.Before(result.StartAt) || result.EndAt.After(generatedAt) {
		return errors.New("invalid standard report typed result")
	}
	refs, err := safeEvidenceRefs(result.EvidenceRefs)
	if err != nil {
		return err
	}
	if len(refs) != len(result.EvidenceRefs) {
		return errors.New("standard report typed result repeats evidence")
	}
	if result.Value == nil {
		return nil
	}
	if result.Value.Kind != result.Kind {
		return errors.New("standard report typed result union tag mismatch")
	}
	window := inspection.ResultTimeWindow{StartAt: result.StartAt, EndAt: result.EndAt}
	if err := result.Value.Validate(result.EvidenceRefs, window); err != nil {
		return fmt.Errorf("invalid standard report typed value: %w", err)
	}
	return nil
}

func clonePublicResults(values []Result) []Result {
	result := make([]Result, len(values))
	for i, value := range values {
		result[i] = value
		result[i].Value = cloneReportResultValue(value.Value)
		result[i].EvidenceRefs = append([]string(nil), value.EvidenceRefs...)
	}
	return result
}

func cloneReportResultValue(value *inspection.ResultValue) *inspection.ResultValue {
	if value == nil {
		return nil
	}
	clone := *value
	if value.Classification != nil {
		member := *value.Classification
		member.Score = cloneReportFloat(member.Score)
		clone.Classification = &member
	}
	if value.Enum != nil {
		member := *value.Enum
		clone.Enum = &member
	}
	if value.Structured != nil {
		member := *value.Structured
		member.Fields = make([]inspection.StructuredField, len(value.Structured.Fields))
		for i, field := range value.Structured.Fields {
			member.Fields[i] = field
			member.Fields[i].Value.Enum = cloneReportString(field.Value.Enum)
			member.Fields[i].Value.Number = cloneReportFloat(field.Value.Number)
			member.Fields[i].Value.Integer = cloneReportInt64(field.Value.Integer)
			member.Fields[i].Value.Boolean = cloneReportBool(field.Value.Boolean)
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
			member.Objects = make([]inspection.DetectionObject, len(value.Detection.Objects))
			copy(member.Objects, value.Detection.Objects)
		}
		for i := range member.Objects {
			member.Objects[i].Score = cloneReportFloat(member.Objects[i].Score)
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

func cloneReportFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
func cloneReportString(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
func cloneReportInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
func cloneReportBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func validPublicRef(value string) bool {
	return len(value) <= maxPublicReferenceBytes && value == strings.TrimSpace(value) && publicRefPattern.MatchString(value)
}

func validateFriendly(name, value string) error {
	return validateSafeText(name, value, 160)
}

func validateSafeText(name, value string, maximum int) error {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return fmt.Errorf("inspection report %s is invalid or protected", name)
	}
	if strings.TrimSpace(value) == "" || protectedText.MatchString(value) {
		return fmt.Errorf("inspection report %s is invalid or protected", name)
	}
	for _, character := range value {
		if character < 0x20 && character != '\t' && character != '\n' && character != '\r' {
			return fmt.Errorf("inspection report %s contains control characters", name)
		}
	}
	return nil
}

func validateItemLimit(name string, count, maximum int) error {
	if count > maximum {
		return resourceLimitError(name, maximum)
	}
	return nil
}

func resourceLimitError(name string, maximum int) error {
	return fmt.Errorf("%w: %s exceeds maximum %d", ErrResourceLimitExceeded, name, maximum)
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
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

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}
