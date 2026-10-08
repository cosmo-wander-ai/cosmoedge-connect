package inspection

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

func compileExecutionSteps(targets []PlannedTarget, budget ResourceBudget, deadline time.Time) ([]ExecutionStep, error) {
	builder := stepBuilder{deadline: deadline.UTC(), budget: budget, outputs: map[string]struct{}{}}
	validationSteps := make([]string, 0)
	resourceSteps := make([]string, 0)

	for _, target := range targets {
		deviceBacked := false
		for _, source := range target.SourceBindings {
			if source.Kind == SourceCamera || source.Kind == SourceTaskEvidence {
				deviceBacked = true
				break
			}
		}
		resolveAuthority := StepAuthorityInspectionExecution
		if deviceBacked {
			resolveAuthority = StepAuthorityDeviceRead
		}
		resolve, err := builder.add(stepDraft{
			kind: StepResolveSource, authority: resolveAuthority, targetID: target.TargetID,
			outputs: []StepOutputSlot{outputSlot(StepValueResolvedSources, "resolved", target.TargetID)}, reconciliation: ReconcilePureReplay,
			budget: StepBudget{MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 3},
		})
		if err != nil {
			return nil, err
		}

		mediaInputs := make([]string, 0, len(target.SourceBindings))
		mediaDependencies := make([]string, 0, len(target.SourceBindings))
		evidenceInputs := make([]string, 0, len(target.SourceBindings))
		evidenceDependencies := make([]string, 0, len(target.SourceBindings))
		for _, source := range target.SourceBindings {
			switch source.Kind {
			case SourceTaskEvidence:
				task, ok := installedTaskForSource(target.InstalledTasks, source.SourceHandle)
				if !ok {
					return nil, errors.New("inspection task-evidence source has no frozen installed task")
				}
				read, err := builder.add(stepDraft{
					kind: StepReadExisting, authority: StepAuthorityDeviceRead,
					targetID: target.TargetID, sourceHandle: source.SourceHandle, taskID: task.TaskID,
					capabilityRefs: source.CapabilityRefs,
					dependsOn:      []string{resolve.StepID}, inputs: []string{resolve.OutputSlots[0].LogicalRef},
					outputs: []StepOutputSlot{
						outputSlot(StepValueExistingEvidence, "evidence", target.TargetID, string(source.Kind), source.SourceHandle, task.TaskID),
						outputSlot(StepValueMedia, "media", target.TargetID, string(source.Kind), source.SourceHandle, task.TaskID),
					},
					reconciliation: ReconcilePureReplay,
					budget:         StepBudget{MaxBytes: budget.MaxMediaBytes, MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 3},
				})
				if err != nil {
					return nil, err
				}
				evidenceInputs = append(evidenceInputs, outputRefByKind(read, StepValueExistingEvidence))
				evidenceDependencies = append(evidenceDependencies, read.StepID)
			default:
				kind := StepOpenMedia
				reconciliation := ReconcilePureReplay
				if source.Kind == SourceCamera {
					kind = StepAcquireMedia
					reconciliation = ReconcileBeforeRetry
				}
				media, err := builder.add(stepDraft{
					kind: kind, authority: StepAuthorityInspectionExecution,
					targetID: target.TargetID, sourceHandle: source.SourceHandle,
					dependsOn: []string{resolve.StepID}, inputs: []string{resolve.OutputSlots[0].LogicalRef},
					outputs:        []StepOutputSlot{outputSlot(StepValueMedia, "media", target.TargetID, string(source.Kind), source.SourceHandle)},
					reconciliation: reconciliation,
					budget:         acquisitionStepBudget(target.Acquisition, budget),
				})
				if err != nil {
					return nil, err
				}
				resourceSteps = append(resourceSteps, media.StepID)
				inputRef, dependency := media.OutputSlots[0].LogicalRef, media.StepID
				if target.StrategyPolicy.Strategy == StrategyClipAnalysis ||
					target.StrategyPolicy.Strategy == StrategyHybridAnalysis && target.Acquisition.MaxExtractedFrames > 0 &&
						containsMediaKind(source.MediaKinds, MediaVideoClip) {
					transformed, err := builder.add(stepDraft{
						kind: StepTransformMedia, authority: StepAuthorityInspectionExecution,
						targetID: target.TargetID, sourceHandle: source.SourceHandle,
						dependsOn: []string{media.StepID}, inputs: []string{media.OutputSlots[0].LogicalRef},
						outputs:        []StepOutputSlot{outputSlot(StepValueMedia, "frames", target.TargetID, string(source.Kind), source.SourceHandle)},
						reconciliation: ReconcileBeforeRetry,
						budget: StepBudget{MaxFrames: target.Acquisition.MaxExtractedFrames, MaxBytes: budget.MaxMediaBytes,
							MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 2},
					})
					if err != nil {
						return nil, err
					}
					resourceSteps = append(resourceSteps, transformed.StepID)
					inputRef, dependency = transformed.OutputSlots[0].LogicalRef, transformed.StepID
				}
				mediaInputs = append(mediaInputs, inputRef)
				mediaDependencies = append(mediaDependencies, dependency)
			}
		}

		for _, criterion := range target.Criteria {
			inputs := append(append([]string(nil), evidenceInputs...), mediaInputs...)
			dependencies := append(append([]string(nil), evidenceDependencies...), mediaDependencies...)
			var candidateRef string
			if target.StrategyPolicy.Strategy == StrategyExistingTaskRead {
				candidateRef = logicalRef("candidate", target.TargetID, criterion.Criterion.ID)
				// Validation owns the deterministic mapping from trusted task
				// evidence to the criterion's typed result.
			} else {
				analyze, err := builder.add(stepDraft{
					kind: StepAnalyze, authority: StepAuthorityInspectionExecution,
					targetID: target.TargetID, criterionID: criterion.Criterion.ID,
					dependsOn: dependencies, inputs: inputs,
					outputs:        []StepOutputSlot{outputSlot(StepValueAnalysis, "candidate", target.TargetID, criterion.Criterion.ID)},
					reconciliation: ReconcileIdempotencyKey,
					budget: StepBudget{MaxFrames: maxInt(target.Acquisition.Samples, target.Acquisition.MaxExtractedFrames),
						MaxBytes: budget.MaxMediaBytes, MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 2},
				})
				if err != nil {
					return nil, err
				}
				resourceSteps = append(resourceSteps, analyze.StepID)
				candidateRef = analyze.OutputSlots[0].LogicalRef
				dependencies = []string{analyze.StepID}
				inputs = []string{candidateRef}
			}
			validated, err := builder.add(stepDraft{
				kind: StepValidateResult, authority: StepAuthorityNone,
				targetID: target.TargetID, criterionID: criterion.Criterion.ID,
				dependsOn: dependencies, inputs: inputs,
				outputs:        []StepOutputSlot{outputSlot(StepValueResult, "result", target.TargetID, criterion.Criterion.ID)},
				reconciliation: ReconcilePureReplay,
				budget:         StepBudget{MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 1},
			})
			if err != nil {
				return nil, err
			}
			validationSteps = append(validationSteps, validated.StepID)
		}
	}

	aggregate, err := builder.add(stepDraft{
		kind: StepAggregate, authority: StepAuthorityNone, dependsOn: sortedUnique(validationSteps),
		inputs: builder.outputsForSteps(validationSteps), outputs: []StepOutputSlot{outputSlot(StepValueOutcome, "outcome", "run")},
		reconciliation: ReconcilePureReplay,
		budget:         StepBudget{MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 1},
	})
	if err != nil {
		return nil, err
	}
	cleanupDependencies := sortedUnique(append(append([]string(nil), resourceSteps...), aggregate.StepID))
	if _, err := builder.add(stepDraft{
		kind: StepCleanup, authority: StepAuthorityInspectionExecution, dependsOn: cleanupDependencies,
		inputs: builder.outputsForSteps(resourceSteps), outputs: []StepOutputSlot{outputSlot(StepValueCleanup, "cleanup", "run")},
		reconciliation: ReconcileNeverBlindReplay,
		budget:         StepBudget{MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 3},
		alwaysRun:      true,
	}); err != nil {
		return nil, err
	}
	return builder.steps, nil
}

type stepDraft struct {
	kind           StepKind
	authority      StepAuthority
	targetID       string
	criterionID    string
	sourceHandle   string
	taskID         string
	capabilityRefs []string
	dependsOn      []string
	inputs         []string
	outputs        []StepOutputSlot
	budget         StepBudget
	reconciliation ReconciliationPolicy
	alwaysRun      bool
}

type stepBuilder struct {
	deadline time.Time
	budget   ResourceBudget
	steps    []ExecutionStep
	outputs  map[string]struct{}
}

type knownStepOutput struct {
	producer string
	kind     StepValueKind
}

func (b *stepBuilder) add(draft stepDraft) (ExecutionStep, error) {
	sequence := len(b.steps) + 1
	identity := strings.Join([]string{
		strconv.Itoa(sequence), string(draft.kind), draft.targetID, draft.criterionID, draft.sourceHandle,
		draft.taskID, strings.Join(draft.capabilityRefs, "\x1f"),
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	stepID := "step_" + hex.EncodeToString(digest[:16])
	step := ExecutionStep{
		Sequence: sequence, StepID: stepID, Kind: draft.kind, Authority: draft.authority,
		TargetID: draft.targetID, CriterionID: draft.criterionID, SourceHandle: draft.sourceHandle,
		TaskID: draft.taskID, CapabilityRefs: append([]string(nil), draft.capabilityRefs...),
		DependsOn: sortedUnique(draft.dependsOn), InputRefs: sortedUnique(draft.inputs), OutputSlots: sortedUniqueOutputSlots(draft.outputs),
		Budget: draft.budget, Deadline: b.deadline, Reconciliation: draft.reconciliation, AlwaysRun: draft.alwaysRun,
	}
	if err := step.validateShape(); err != nil {
		return ExecutionStep{}, err
	}
	for _, output := range step.OutputSlots {
		if _, exists := b.outputs[output.LogicalRef]; exists {
			return ExecutionStep{}, errors.New("inspection execution steps repeat an output reference")
		}
		b.outputs[output.LogicalRef] = struct{}{}
	}
	b.steps = append(b.steps, step)
	return step, nil
}

func (b *stepBuilder) outputsForSteps(stepIDs []string) []string {
	set := make(map[string]struct{})
	steps := make(map[string]ExecutionStep, len(b.steps))
	for _, step := range b.steps {
		steps[step.StepID] = step
	}
	for _, stepID := range stepIDs {
		for _, output := range steps[stepID].OutputSlots {
			set[output.LogicalRef] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for output := range set {
		result = append(result, output)
	}
	sort.Strings(result)
	return result
}

func validateExecutionSteps(plan ExecutionPlan) error {
	if len(plan.Steps) < 3 || len(plan.Steps) > 10_000 {
		return errors.New("inspection execution plan step count is invalid")
	}
	knownSteps := make(map[string]ExecutionStep, len(plan.Steps))
	knownOutputs := make(map[string]knownStepOutput)
	targets := make(map[string]PlannedTarget, len(plan.Targets))
	for _, target := range plan.Targets {
		targets[target.TargetID] = target
	}
	aggregates, cleanups := 0, 0
	for index, step := range plan.Steps {
		if step.Sequence != index+1 || !step.Deadline.Equal(plan.Deadline) {
			return errors.New("inspection execution steps are not in canonical sequence")
		}
		if err := step.validateShape(); err != nil {
			return err
		}
		if _, duplicate := knownSteps[step.StepID]; duplicate {
			return errors.New("inspection execution plan repeats a step")
		}
		for _, dependency := range step.DependsOn {
			if _, exists := knownSteps[dependency]; !exists {
				return errors.New("inspection execution step depends on a missing or later step")
			}
		}
		reachable := dependencyClosure(step.DependsOn, knownSteps)
		for _, input := range step.InputRefs {
			producer, exists := knownOutputs[input]
			if !exists {
				return errors.New("inspection execution step input has no frozen producer")
			}
			if _, ordered := reachable[producer.producer]; !ordered {
				return errors.New("inspection execution step input producer is outside its dependency graph")
			}
		}
		if err := validateStepInputKinds(step, knownOutputs); err != nil {
			return err
		}
		for _, output := range step.OutputSlots {
			if _, exists := knownOutputs[output.LogicalRef]; exists {
				return errors.New("inspection execution plan repeats an output reference")
			}
			knownOutputs[output.LogicalRef] = knownStepOutput{producer: step.StepID, kind: output.Kind}
		}
		if step.Kind == StepAggregate {
			aggregates++
		}
		if step.Kind == StepCleanup {
			cleanups++
			if !step.AlwaysRun || index != len(plan.Steps)-1 {
				return errors.New("inspection cleanup must be the final always-run step")
			}
		}
		if step.Kind == StepReadExisting {
			target, ok := targets[step.TargetID]
			if !ok {
				return errors.New("inspection existing-evidence step references an unknown target")
			}
			task, ok := installedTaskForSource(target.InstalledTasks, step.SourceHandle)
			if !ok || task.TaskID != step.TaskID {
				return errors.New("inspection existing-evidence step references an unfrozen installed task")
			}
			source, ok := sourceBindingByHandle(target.SourceBindings, SourceTaskEvidence, step.SourceHandle)
			if !ok || !equalStrings(step.CapabilityRefs, source.CapabilityRefs) {
				return errors.New("inspection existing-evidence step capability binding is stale")
			}
			if !hasExactOutputKinds(step, StepValueExistingEvidence, StepValueMedia) {
				return errors.New("inspection existing-evidence step output contract is invalid")
			}
		}
		maxFrames := 0
		if target, ok := targets[step.TargetID]; ok {
			maxFrames = maxInt(target.Acquisition.Samples, target.Acquisition.MaxExtractedFrames)
		}
		if step.Budget.MaxFrames > maxFrames || step.Budget.MaxBytes > plan.Budget.MaxMediaBytes ||
			step.Budget.MaxDurationSeconds > plan.Budget.MaxDurationSeconds {
			return errors.New("inspection execution step exceeds the frozen run budget")
		}
		knownSteps[step.StepID] = step
	}
	if aggregates != 1 || cleanups != 1 {
		return errors.New("inspection execution plan requires one aggregate and one cleanup step")
	}
	return nil
}

func dependencyClosure(direct []string, known map[string]ExecutionStep) map[string]struct{} {
	result := make(map[string]struct{}, len(direct))
	stack := append([]string(nil), direct...)
	for len(stack) > 0 {
		last := len(stack) - 1
		stepID := stack[last]
		stack = stack[:last]
		if _, seen := result[stepID]; seen {
			continue
		}
		result[stepID] = struct{}{}
		if step, ok := known[stepID]; ok {
			stack = append(stack, step.DependsOn...)
		}
	}
	return result
}

func (s ExecutionStep) validateShape() error {
	if s.Sequence < 1 || validateRef("step", s.StepID) != nil || !s.Kind.valid() || !s.Authority.valid() ||
		s.Deadline.IsZero() || !s.Reconciliation.valid() {
		return errors.New("inspection execution step shape is invalid")
	}
	for _, value := range append(append([]string(nil), s.DependsOn...), s.InputRefs...) {
		if validateRef("step reference", value) != nil {
			return errors.New("inspection execution step contains an invalid reference")
		}
	}
	if !strictSorted(s.DependsOn) || !strictSorted(s.InputRefs) || !strictOutputSlots(s.OutputSlots) || len(s.OutputSlots) == 0 {
		return errors.New("inspection execution step references are not canonical")
	}
	if s.TargetID != "" && validateRef("step target", s.TargetID) != nil ||
		s.CriterionID != "" && validateRef("step criterion", s.CriterionID) != nil ||
		s.SourceHandle != "" && validateRef("step source", s.SourceHandle) != nil ||
		s.TaskID != "" && validateRef("step task", s.TaskID) != nil {
		return errors.New("inspection execution step binding is invalid")
	}
	if !strictSorted(s.CapabilityRefs) {
		return errors.New("inspection execution step capabilities are not canonical")
	}
	if s.Kind == StepReadExisting {
		if s.SourceHandle == "" || s.TaskID == "" || len(s.CapabilityRefs) == 0 {
			return errors.New("inspection existing-evidence step binding is incomplete")
		}
	} else if s.TaskID != "" || len(s.CapabilityRefs) != 0 {
		return errors.New("non-task inspection step carries an installed task binding")
	}
	if s.Budget.MaxFrames < 0 || s.Budget.MaxBytes < 0 || s.Budget.MaxDurationSeconds < 1 ||
		s.Budget.MaxAttempts < 1 || s.Budget.MaxAttempts > 16 {
		return errors.New("inspection execution step budget is invalid")
	}
	if s.Kind == StepResolveSource {
		if s.Authority != StepAuthorityDeviceRead && s.Authority != StepAuthorityInspectionExecution {
			return errors.New("inspection source resolution authority is invalid")
		}
	} else if expectedAuthority(s.Kind) != s.Authority {
		return errors.New("inspection execution step authority does not match its operation")
	}
	return nil
}

func (k StepKind) valid() bool {
	switch k {
	case StepResolveSource, StepReadExisting, StepAcquireMedia, StepOpenMedia, StepTransformMedia,
		StepAnalyze, StepValidateResult, StepAggregate, StepCleanup:
		return true
	default:
		return false
	}
}

func (a StepAuthority) valid() bool {
	return a == StepAuthorityNone || a == StepAuthorityDeviceRead || a == StepAuthorityInspectionExecution
}

func (k StepValueKind) valid() bool {
	switch k {
	case StepValueResolvedSources, StepValueExistingEvidence, StepValueMedia, StepValueAnalysis,
		StepValueResult, StepValueOutcome, StepValueCleanup:
		return true
	default:
		return false
	}
}

func (r ReconciliationPolicy) valid() bool {
	return r == ReconcilePureReplay || r == ReconcileIdempotencyKey || r == ReconcileBeforeRetry || r == ReconcileNeverBlindReplay
}

func expectedAuthority(kind StepKind) StepAuthority {
	switch kind {
	case StepReadExisting:
		return StepAuthorityDeviceRead
	case StepAcquireMedia, StepOpenMedia, StepTransformMedia, StepAnalyze, StepCleanup:
		return StepAuthorityInspectionExecution
	case StepValidateResult, StepAggregate:
		return StepAuthorityNone
	case StepResolveSource:
		// Resolve may be local-only or device-backed, so both read and bounded
		// execution authority are structurally valid and checked separately.
		return ""
	default:
		return ""
	}
}

func strictSorted(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func strictOutputSlots(values []StepOutputSlot) bool {
	for index, value := range values {
		if validateRef("step output", value.LogicalRef) != nil || !value.Kind.valid() ||
			index > 0 && values[index-1].LogicalRef >= value.LogicalRef {
			return false
		}
	}
	return true
}

func sortedUniqueOutputSlots(values []StepOutputSlot) []StepOutputSlot {
	result := append([]StepOutputSlot(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].LogicalRef < result[j].LogicalRef })
	return result
}

func outputSlot(kind StepValueKind, prefix string, values ...string) StepOutputSlot {
	return StepOutputSlot{LogicalRef: logicalRef(prefix, values...), Kind: kind}
}

func outputRefByKind(step ExecutionStep, kind StepValueKind) string {
	for _, output := range step.OutputSlots {
		if output.Kind == kind {
			return output.LogicalRef
		}
	}
	return ""
}

func hasExactOutputKinds(step ExecutionStep, expected ...StepValueKind) bool {
	if len(step.OutputSlots) != len(expected) {
		return false
	}
	want := append([]StepValueKind(nil), expected...)
	got := make([]StepValueKind, len(step.OutputSlots))
	for index, output := range step.OutputSlots {
		got[index] = output.Kind
	}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	for index := range want {
		if want[index] != got[index] {
			return false
		}
	}
	return true
}

func validateStepInputKinds(step ExecutionStep, known map[string]knownStepOutput) error {
	kinds := make([]StepValueKind, 0, len(step.InputRefs))
	for _, ref := range step.InputRefs {
		kinds = append(kinds, known[ref].kind)
	}
	all := func(allowed ...StepValueKind) bool {
		for _, kind := range kinds {
			matched := false
			for _, candidate := range allowed {
				matched = matched || kind == candidate
			}
			if !matched {
				return false
			}
		}
		return true
	}
	valid := false
	switch step.Kind {
	case StepResolveSource:
		valid = len(kinds) == 0 && hasExactOutputKinds(step, StepValueResolvedSources)
	case StepReadExisting:
		valid = len(kinds) == 1 && kinds[0] == StepValueResolvedSources
	case StepAcquireMedia, StepOpenMedia:
		valid = len(kinds) == 1 && kinds[0] == StepValueResolvedSources && hasExactOutputKinds(step, StepValueMedia)
	case StepTransformMedia:
		valid = len(kinds) == 1 && kinds[0] == StepValueMedia && hasExactOutputKinds(step, StepValueMedia)
	case StepAnalyze:
		valid = len(kinds) > 0 && all(StepValueExistingEvidence, StepValueMedia) && hasExactOutputKinds(step, StepValueAnalysis)
	case StepValidateResult:
		valid = len(kinds) > 0 && all(StepValueExistingEvidence) || len(kinds) == 1 && kinds[0] == StepValueAnalysis
		valid = valid && hasExactOutputKinds(step, StepValueResult)
	case StepAggregate:
		valid = len(kinds) > 0 && all(StepValueResult) && hasExactOutputKinds(step, StepValueOutcome)
	case StepCleanup:
		valid = all(StepValueMedia, StepValueAnalysis) && hasExactOutputKinds(step, StepValueCleanup)
	}
	if !valid {
		return errors.New("inspection execution step value types do not match its operation")
	}
	return nil
}

func installedTaskForSource(tasks []InstalledTaskBinding, sourceHandle string) (InstalledTaskBinding, bool) {
	for _, task := range tasks {
		for _, source := range task.Sources {
			if source.SourceHandle == sourceHandle {
				return task, true
			}
		}
	}
	return InstalledTaskBinding{}, false
}

func sourceBindingByHandle(sources []SourceBinding, kind SourceKind, sourceHandle string) (SourceBinding, bool) {
	for _, source := range sources {
		if source.Kind == kind && source.SourceHandle == sourceHandle {
			return source, true
		}
	}
	return SourceBinding{}, false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func logicalRef(prefix string, values ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(append([]string{prefix}, values...), "\x00")))
	return "slot_" + hex.EncodeToString(digest[:16])
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func acquisitionStepBudget(acquisition AcquisitionPolicy, budget ResourceBudget) StepBudget {
	frames := acquisition.Samples
	if acquisition.MaxExtractedFrames > frames {
		frames = acquisition.MaxExtractedFrames
	}
	return StepBudget{
		MaxFrames: frames, MaxBytes: budget.MaxMediaBytes,
		MaxDurationSeconds: boundedStepDuration(budget.MaxDurationSeconds), MaxAttempts: 2,
	}
}

func boundedStepDuration(runMaximum int) int {
	if runMaximum < 60 {
		return runMaximum
	}
	return 60
}

func maxInt(values ...int) int {
	maximum := 0
	for _, value := range values {
		if value > maximum {
			maximum = value
		}
	}
	return maximum
}

func (s ExecutionStep) String() string {
	return fmt.Sprintf("%s:%s", s.StepID, s.Kind)
}
