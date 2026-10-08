package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

var (
	runtimeOpaqueRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	runtimeSHA256    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type stepExecutionResult struct {
	state       inspection.StepState
	outputs     []inspection.StepOutput
	reason      string
	interrupted bool
}

func (m *Manager) executeStep(
	ctx context.Context,
	run inspection.Run,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
) stepExecutionResult {
	inputs, err := m.stepInputs(ctx, run.RunID, plan, step)
	if err != nil {
		return failedStep("step_input_contract_invalid")
	}

	var outputs []inspection.StepOutput
	var output inspection.StepOutput
	switch step.Kind {
	case inspection.StepResolveSource:
		output, err = m.resolveSource(ctx, run, plan, step, attempt)
	case inspection.StepReadExisting:
		outputs, err = m.readExistingEvidence(ctx, run, plan, step, attempt, inputs)
	case inspection.StepAcquireMedia, inspection.StepOpenMedia:
		output, err = m.acquireMedia(ctx, run, plan, step, attempt, inputs)
	case inspection.StepTransformMedia:
		output, err = m.transformMedia(ctx, run, plan, step, attempt, inputs)
	case inspection.StepAnalyze:
		output, err = m.analyze(ctx, run, plan, step, attempt, inputs)
	case inspection.StepValidateResult:
		output, err = m.validateResult(ctx, run, plan, step, attempt, inputs)
	case inspection.StepAggregate:
		output, err = m.aggregate(ctx, run, plan, step)
	case inspection.StepCleanup:
		output, err = m.cleanup(ctx, run, step, attempt, inputs)
	default:
		err = ErrUnsupported
	}
	if err == nil {
		if outputs == nil {
			outputs = []inspection.StepOutput{output}
		}
		return stepExecutionResult{
			state: inspection.StepSucceeded, outputs: outputs, reason: "step_succeeded",
		}
	}
	return stepErrorResult(err)
}

func stepErrorResult(err error) stepExecutionResult {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return stepExecutionResult{interrupted: true}
	}
	if errors.Is(err, ErrOutcomeUnknown) {
		return stepExecutionResult{state: inspection.StepOutcomeUnknown, outputs: []inspection.StepOutput{}, reason: "step_outcome_unknown"}
	}
	return failedStep(executionFailureReason(err))
}

func failedStep(reason string) stepExecutionResult {
	return stepExecutionResult{state: inspection.StepFailed, outputs: []inspection.StepOutput{}, reason: reason}
}

func executionFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrWaitingForSite):
		return "site_session_unavailable"
	case errors.Is(err, ErrBindingStale):
		return "execution_binding_stale"
	case errors.Is(err, ErrResourceBusy):
		return "execution_resource_busy"
	case errors.Is(err, ErrAuthorityRejected):
		return "execution_authority_rejected"
	case errors.Is(err, ErrUnsupported):
		return "execution_operation_unsupported"
	default:
		return "execution_contract_invalid"
	}
}

func (m *Manager) stepInputs(ctx context.Context, runID string, plan inspection.ExecutionPlan, step inspection.ExecutionStep) ([]ValueReference, error) {
	records, err := m.repository.ListSteps(ctx, runID)
	if err != nil {
		return nil, err
	}
	if len(records) != len(plan.Steps) {
		return nil, errors.New("inspection step ledger does not match the frozen plan")
	}
	type producedValue struct {
		output  inspection.StepOutput
		stepID  string
		attempt int
		kind    inspection.StepKind
		state   inspection.StepState
	}
	producers := make(map[string]producedValue, len(plan.Steps))
	for index, planned := range plan.Steps {
		record := records[index]
		if record.StepID != planned.StepID || record.Kind != planned.Kind || record.Sequence != planned.Sequence {
			return nil, errors.New("inspection step ledger binding mismatch")
		}
		for _, slot := range planned.OutputSlots {
			logicalRef := slot.LogicalRef
			value := producedValue{stepID: planned.StepID, attempt: record.AttemptCount, kind: planned.Kind, state: record.State}
			if record.State == inspection.StepSucceeded {
				for _, output := range record.Outputs {
					if output.LogicalRef == logicalRef {
						value.output = output
						break
					}
				}
				if value.output.LogicalRef == "" {
					return nil, errors.New("successful inspection dependency has no frozen output")
				}
			}
			producers[logicalRef] = value
		}
	}

	inputs := make([]ValueReference, 0, len(step.InputRefs))
	for _, logicalRef := range step.InputRefs {
		producer, ok := producers[logicalRef]
		if !ok {
			return nil, errors.New("inspection step input has no frozen producer")
		}
		if producer.state != inspection.StepSucceeded {
			if step.Kind == inspection.StepCleanup && producer.state == inspection.StepOutcomeUnknown {
				inputs = append(inputs, ValueReference{
					LogicalRef: logicalRef, ProducerStepID: producer.stepID, Attempt: producer.attempt, ProducerKind: producer.kind,
				})
				continue
			}
			if step.Kind == inspection.StepCleanup {
				continue
			}
			return nil, errors.New("inspection step input dependency did not succeed")
		}
		inputs = append(inputs, ValueReference{
			LogicalRef: logicalRef, ProducerStepID: producer.stepID, Attempt: producer.attempt,
			ValueRef: producer.output.ValueRef, SHA256: producer.output.SHA256, ProducerKind: producer.kind,
		})
	}
	return inputs, nil
}

func (m *Manager) resolveSource(
	ctx context.Context,
	run inspection.Run,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
) (inspection.StepOutput, error) {
	target, ok := plannedTarget(plan, step.TargetID)
	if !ok || step.SourceHandle != "" || step.CriterionID != "" {
		return inspection.StepOutput{}, ErrBindingStale
	}
	result, err := m.ports.Sources.Resolve(ctx, ResolveSourceRequest{
		RunID: run.RunID, StepID: step.StepID, TenantID: plan.TenantID, SiteID: plan.SiteID,
		TargetID: target.TargetID, Sources: cloneSourceBindings(target.SourceBindings),
		InstalledTasks: cloneInstalledTaskBindings(target.InstalledTasks), Attempt: attempt.Number,
		Deadline: step.Deadline, Budget: step.Budget,
	})
	if err != nil {
		return inspection.StepOutput{}, err
	}
	digest, err := canonicalDigest(struct {
		RunID          string `json:"runId"`
		StepID         string `json:"stepId"`
		Attempt        int    `json:"attempt"`
		ResolutionRef  string `json:"resolutionRef"`
		AdapterVersion string `json:"adapterVersion"`
	}{result.RunID, result.StepID, result.Attempt, result.ResolutionRef, result.AdapterVersion})
	if err != nil || result.RunID != run.RunID || result.StepID != step.StepID || result.Attempt != attempt.Number ||
		!validOpaqueRuntimeRef(result.ResolutionRef) || !validRuntimeVersion(result.AdapterVersion) ||
		result.SHA256 != "" && result.SHA256 != digest {
		return inspection.StepOutput{}, errors.New("source resolver returned an invalid typed reference")
	}
	return oneStepOutput(step, result.ResolutionRef, digest)
}

func (m *Manager) readExistingEvidence(
	ctx context.Context,
	run inspection.Run,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
	inputs []ValueReference,
) ([]inspection.StepOutput, error) {
	target, ok := plannedTarget(plan, step.TargetID)
	source, sourceOK := plannedTargetSourceByKind(target, step.SourceHandle, inspection.SourceTaskEvidence)
	task, taskOK := plannedTargetTask(target, step.TaskID, step.SourceHandle)
	if !ok || !sourceOK || !taskOK ||
		!equalStrings(step.CapabilityRefs, source.CapabilityRefs) || len(inputs) != 1 ||
		inputs[0].ProducerKind != inspection.StepResolveSource {
		return nil, ErrBindingStale
	}
	result, err := m.ports.Existing.Read(ctx, ExistingEvidenceRequest{
		RunID: run.RunID, StepID: step.StepID, TenantID: plan.TenantID, SiteID: plan.SiteID,
		TargetID: target.TargetID, ResolutionRef: inputs[0].ValueRef, Source: cloneSourceBinding(source),
		InstalledTask: cloneInstalledTaskBinding(task), CapabilityRefs: append([]string(nil), step.CapabilityRefs...),
		Attempt: attempt.Number, Deadline: step.Deadline, Budget: step.Budget,
	})
	if err != nil {
		return nil, err
	}
	digest, err := validateExistingEvidence(result, run.RunID, plan, step, attempt.Number, source)
	if err != nil || result.SHA256 != "" && result.SHA256 != digest {
		return nil, errors.New("existing evidence reader returned an invalid typed result")
	}
	evidenceSlot, mediaSlot, ok := existingEvidenceOutputSlots(step)
	if !ok {
		return nil, errors.New("existing evidence step has an invalid frozen output contract")
	}
	outputs := []inspection.StepOutput{
		{LogicalRef: evidenceSlot.LogicalRef, Kind: evidenceSlot.Kind, ValueRef: result.EvidenceRef, SHA256: digest},
		{LogicalRef: mediaSlot.LogicalRef, Kind: mediaSlot.Kind, ValueRef: result.Descriptor.MediaRef, SHA256: result.Descriptor.Integrity.SHA256},
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].LogicalRef < outputs[j].LogicalRef })
	return outputs, nil
}

func (m *Manager) acquireMedia(
	ctx context.Context,
	run inspection.Run,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
	inputs []ValueReference,
) (inspection.StepOutput, error) {
	target, ok := plannedTarget(plan, step.TargetID)
	var source inspection.SourceBinding
	var sourceOK bool
	if step.Kind == inspection.StepAcquireMedia {
		source, sourceOK = plannedTargetSourceByKind(target, step.SourceHandle, inspection.SourceCamera)
	} else if step.Kind == inspection.StepOpenMedia {
		source, sourceOK = plannedTargetSourceByPredicate(target, step.SourceHandle, func(candidate inspection.SourceBinding) bool {
			return candidate.Kind != inspection.SourceCamera && candidate.Kind != inspection.SourceTaskEvidence
		})
	}
	if !ok || !sourceOK || len(inputs) != 1 || inputs[0].ProducerKind != inspection.StepResolveSource {
		return inspection.StepOutput{}, ErrBindingStale
	}
	result, err := m.ports.Acquisition.Acquire(ctx, MediaAcquireRequest{
		Operation: step.Kind, RunID: run.RunID, StepID: step.StepID, TenantID: plan.TenantID, SiteID: plan.SiteID,
		TargetID: target.TargetID, ResolutionRef: inputs[0].ValueRef, Source: cloneSourceBinding(source),
		Acquisition: target.Acquisition, Evidence: plan.Evidence, Attempt: attempt.Number,
		IdempotencyKey: attempt.AttemptID, Deadline: step.Deadline, Budget: step.Budget,
	})
	if err != nil {
		return inspection.StepOutput{}, err
	}
	if err := validateMediaDescriptor(result.Descriptor, run.RunID, plan, step, attempt, source, ""); err != nil {
		return inspection.StepOutput{}, err
	}
	stored, err := m.ports.Acquisition.Describe(ctx, result.Descriptor.MediaRef)
	if err != nil || !equalDescriptor(stored, result.Descriptor) {
		return inspection.StepOutput{}, errors.New("media acquisition reference cannot be verified")
	}
	return oneStepOutput(step, result.Descriptor.MediaRef, result.Descriptor.Integrity.SHA256)
}

func (m *Manager) transformMedia(
	ctx context.Context,
	run inspection.Run,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
	inputs []ValueReference,
) (inspection.StepOutput, error) {
	target, ok := plannedTarget(plan, step.TargetID)
	if !ok || len(inputs) != 1 {
		return inspection.StepOutput{}, ErrBindingStale
	}
	var source inspection.SourceBinding
	var sourceOK bool
	switch inputs[0].ProducerKind {
	case inspection.StepAcquireMedia:
		source, sourceOK = plannedTargetSourceByKind(target, step.SourceHandle, inspection.SourceCamera)
	case inspection.StepOpenMedia:
		source, sourceOK = plannedTargetSourceByPredicate(target, step.SourceHandle, func(candidate inspection.SourceBinding) bool {
			return candidate.Kind != inspection.SourceCamera && candidate.Kind != inspection.SourceTaskEvidence
		})
	}
	if !sourceOK {
		return inspection.StepOutput{}, ErrBindingStale
	}
	input, err := m.describeMedia(ctx, inputs[0])
	if err != nil || input.Integrity.SHA256 != inputs[0].SHA256 {
		return inspection.StepOutput{}, errors.New("media transform input cannot be verified")
	}
	result, err := m.ports.Transform.Transform(ctx, MediaTransformRequest{
		RunID: run.RunID, StepID: step.StepID, TenantID: plan.TenantID, SiteID: plan.SiteID,
		TargetID: target.TargetID, SourceRef: source.SourceHandle, Input: input,
		Acquisition: target.Acquisition, Evidence: plan.Evidence, Attempt: attempt.Number,
		IdempotencyKey: attempt.AttemptID, Deadline: step.Deadline, Budget: step.Budget,
	})
	if err != nil {
		return inspection.StepOutput{}, err
	}
	if err := validateMediaDescriptor(result.Descriptor, run.RunID, plan, step, attempt, source, input.MediaRef); err != nil {
		return inspection.StepOutput{}, err
	}
	stored, err := m.ports.Transform.Describe(ctx, result.Descriptor.MediaRef)
	if err != nil || !equalDescriptor(stored, result.Descriptor) {
		return inspection.StepOutput{}, errors.New("media transform reference cannot be verified")
	}
	return oneStepOutput(step, result.Descriptor.MediaRef, result.Descriptor.Integrity.SHA256)
}

func (m *Manager) analyze(
	ctx context.Context,
	run inspection.Run,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
	inputs []ValueReference,
) (inspection.StepOutput, error) {
	target, planned, ok := plannedTargetCriterion(plan, step.TargetID, step.CriterionID)
	if !ok || target.StrategyPolicy.Strategy == inspection.StrategyExistingTaskRead || len(inputs) == 0 {
		return inspection.StepOutput{}, ErrBindingStale
	}
	analysisInputs := make([]AnalysisInput, 0, len(inputs))
	for _, input := range inputs {
		value := AnalysisInput{
			ProducerStepID: input.ProducerStepID, ProducerKind: input.ProducerKind, Attempt: input.Attempt,
			ValueRef: input.ValueRef, SHA256: input.SHA256,
		}
		switch input.ProducerKind {
		case inspection.StepAcquireMedia, inspection.StepOpenMedia, inspection.StepTransformMedia:
			descriptor, err := m.describeMedia(ctx, input)
			if err != nil || descriptor.Integrity.SHA256 != input.SHA256 {
				return inspection.StepOutput{}, errors.New("analysis media input cannot be verified")
			}
			value.Descriptor = &descriptor
		case inspection.StepReadExisting:
			evidence, err := m.ports.Existing.Result(ctx, input.ValueRef)
			if err != nil {
				return inspection.StepOutput{}, err
			}
			producer, found := planStep(plan, input.ProducerStepID)
			if !found {
				return inspection.StepOutput{}, errors.New("analysis evidence input has no frozen producer")
			}
			source, sourceOK := plannedTargetSourceByKind(target, producer.SourceHandle, inspection.SourceTaskEvidence)
			if !sourceOK {
				return inspection.StepOutput{}, errors.New("analysis evidence input has no unique frozen task-evidence source")
			}
			digest, err := validateExistingEvidence(evidence, run.RunID, plan, producer, input.Attempt, source)
			if err != nil || digest != input.SHA256 {
				return inspection.StepOutput{}, errors.New("analysis evidence input cannot be verified")
			}
			value.Evidence = &evidence
		default:
			return inspection.StepOutput{}, errors.New("analysis input is not a typed media or evidence reference")
		}
		analysisInputs = append(analysisInputs, value)
	}
	result, err := m.ports.Analysis.Analyze(ctx, AnalyzeRequest{
		RunID: run.RunID, StepID: step.StepID, TenantID: plan.TenantID, SiteID: plan.SiteID,
		TargetID: target.TargetID, CriterionID: planned.Criterion.ID, Attempt: attempt.Number,
		Method: planned.Criterion.Method, AnalysisPolicyRef: target.StrategyPolicy.AnalysisPolicyRef,
		Prompt: planned.Prompt, PromptSHA256: planned.PromptSHA, Output: planned.Criterion.Output,
		Inputs: analysisInputs, IdempotencyKey: attempt.AttemptID, Deadline: step.Deadline, Budget: step.Budget,
	})
	if err != nil {
		return inspection.StepOutput{}, err
	}
	digest, err := validateAnalysisReference(result, run.RunID, plan, step, attempt)
	if err != nil || result.SHA256 != "" && result.SHA256 != digest {
		return inspection.StepOutput{}, errors.New("analyzer returned an invalid typed result")
	}
	stored, err := m.ports.Analysis.Result(ctx, result.ResultRef)
	if err != nil {
		return inspection.StepOutput{}, err
	}
	storedDigest, err := validateAnalysisReference(stored, run.RunID, plan, step, attempt)
	if err != nil || storedDigest != digest {
		return inspection.StepOutput{}, errors.New("analyzer result reference cannot be verified")
	}
	return oneStepOutput(step, result.ResultRef, digest)
}

func (m *Manager) validateResult(
	ctx context.Context,
	run inspection.Run,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
	inputs []ValueReference,
) (inspection.StepOutput, error) {
	target, planned, ok := plannedTargetCriterion(plan, step.TargetID, step.CriterionID)
	if !ok || len(inputs) == 0 {
		return inspection.StepOutput{}, ErrBindingStale
	}

	var (
		candidate      analysiscontract.Candidate
		resultRef      string
		producerStepID string
		adapterVersion string
		modelVersion   string
		startedAt      time.Time
		completedAt    time.Time
		descriptors    []media.Descriptor
	)
	if target.StrategyPolicy.Strategy == inspection.StrategyExistingTaskRead {
		for index, input := range inputs {
			if input.ProducerKind != inspection.StepReadExisting {
				return inspection.StepOutput{}, errors.New("existing-result validation received a non-evidence input")
			}
			evidence, err := m.ports.Existing.Result(ctx, input.ValueRef)
			if err != nil {
				return inspection.StepOutput{}, err
			}
			producer, found := planStep(plan, input.ProducerStepID)
			if !found {
				return inspection.StepOutput{}, errors.New("existing evidence input has no frozen producer")
			}
			source, sourceOK := plannedTargetSourceByKind(target, producer.SourceHandle, inspection.SourceTaskEvidence)
			if !sourceOK {
				return inspection.StepOutput{}, errors.New("existing result has no unique frozen task-evidence source")
			}
			digest, err := validateExistingEvidence(evidence, run.RunID, plan, producer, input.Attempt, source)
			if err != nil || digest != input.SHA256 {
				return inspection.StepOutput{}, errors.New("existing evidence result cannot be verified")
			}
			if index == 0 {
				candidate, resultRef = evidence.Candidate, evidence.EvidenceRef
				adapterVersion, modelVersion = evidence.AdapterVersion, "existing-evidence-v2"
				startedAt, completedAt = evidence.ObservedAt.UTC(), evidence.ObservedAt.UTC()
				producerStepID = input.ProducerStepID
			} else if !equalCandidate(candidate, evidence.Candidate) {
				return inspection.StepOutput{}, errors.New("existing evidence candidates conflict")
			}
			descriptors = append(descriptors, evidence.Descriptor)
		}
	} else {
		if len(inputs) != 1 || inputs[0].ProducerKind != inspection.StepAnalyze {
			return inspection.StepOutput{}, errors.New("analysis result validation requires one analyzer reference")
		}
		analysis, err := m.ports.Analysis.Result(ctx, inputs[0].ValueRef)
		if err != nil {
			return inspection.StepOutput{}, err
		}
		producerStepID = inputs[0].ProducerStepID
		producer, ok := planStep(plan, producerStepID)
		if !ok {
			return inspection.StepOutput{}, errors.New("analysis result has no frozen producer")
		}
		digest, err := validateAnalysisReference(analysis, run.RunID, plan, producer, inspection.StepAttempt{Number: inputs[0].Attempt})
		if err != nil || digest != inputs[0].SHA256 {
			return inspection.StepOutput{}, errors.New("analysis result cannot be verified")
		}
		candidate, resultRef = analysis.Candidate, analysis.ResultRef
		adapterVersion, modelVersion = analysis.AdapterVersion, analysis.ModelVersion
		startedAt, completedAt = analysis.StartedAt.UTC(), analysis.CompletedAt.UTC()
		analysisInputs, err := m.inputsForLogicalStep(ctx, run.RunID, plan, producer)
		if err != nil {
			return inspection.StepOutput{}, err
		}
		for _, input := range analysisInputs {
			switch input.ProducerKind {
			case inspection.StepAcquireMedia, inspection.StepOpenMedia, inspection.StepTransformMedia:
				descriptor, err := m.describeMedia(ctx, input)
				if err != nil || descriptor.Integrity.SHA256 != input.SHA256 {
					return inspection.StepOutput{}, errors.New("analysis source media cannot be verified")
				}
				descriptors = append(descriptors, descriptor)
			case inspection.StepReadExisting:
				evidence, err := m.ports.Existing.Result(ctx, input.ValueRef)
				if err != nil {
					return inspection.StepOutput{}, err
				}
				evidenceProducer, found := planStep(plan, input.ProducerStepID)
				if !found {
					return inspection.StepOutput{}, errors.New("analysis source evidence has no frozen producer")
				}
				source, sourceOK := plannedTargetSourceByKind(target, evidenceProducer.SourceHandle, inspection.SourceTaskEvidence)
				if !sourceOK {
					return inspection.StepOutput{}, errors.New("analysis source evidence has no unique frozen task-evidence source")
				}
				digest, err := validateExistingEvidence(evidence, run.RunID, plan, evidenceProducer, input.Attempt, source)
				if err != nil || digest != input.SHA256 {
					return inspection.StepOutput{}, errors.New("analysis source evidence cannot be verified")
				}
				descriptors = append(descriptors, evidence.Descriptor)
			default:
				return inspection.StepOutput{}, errors.New("analysis source is not a typed media or evidence reference")
			}
		}
	}
	if producerStepID == "" {
		return inspection.StepOutput{}, errors.New("validated result has no frozen producer")
	}

	envelope, err := buildEnvelope(plan, target, planned, resultRef, producerStepID, candidate, descriptors,
		adapterVersion, modelVersion, startedAt, completedAt, resultAttempt(inputs, attempt.Number), run.RunID)
	if err != nil {
		return inspection.StepOutput{}, err
	}
	typed, err := envelope.TypedResult()
	if err != nil {
		return inspection.StepOutput{}, err
	}
	allowed := false
	for _, assessment := range planned.Criterion.Output.AllowedAssessments {
		allowed = allowed || assessment == typed.Assessment
	}
	if !allowed {
		return inspection.StepOutput{}, errors.New("analysis result assessment is outside its frozen output contract")
	}
	observationID := deterministicRef("obs", run.RunID, step.StepID)
	observation := inspection.Observation{
		ObservationID: observationID,
		SampleID:      deterministicRef("sample", run.RunID, target.TargetID, planned.Criterion.ID),
		Result:        typed,
	}
	if err := observation.Validate(); err != nil {
		return inspection.StepOutput{}, err
	}
	existingObservations, err := m.repository.ListObservations(ctx, run.RunID)
	if err != nil {
		return inspection.StepOutput{}, err
	}
	for _, existing := range existingObservations {
		if existing.ObservationID != observationID {
			continue
		}
		if !equalObservation(existing, observation) {
			return inspection.StepOutput{}, errors.New("persisted observation conflicts with replayed typed result")
		}
		digest, err := canonicalDigest(existing)
		if err != nil {
			return inspection.StepOutput{}, err
		}
		return oneStepOutput(step, existing.ObservationID, digest)
	}
	if err := m.repository.RecordObservation(ctx, m.ownerID, observation, m.now().UTC()); err != nil {
		return inspection.StepOutput{}, err
	}
	digest, err := canonicalDigest(observation)
	if err != nil {
		return inspection.StepOutput{}, err
	}
	return oneStepOutput(step, observation.ObservationID, digest)
}

func (m *Manager) aggregate(ctx context.Context, run inspection.Run, plan inspection.ExecutionPlan, step inspection.ExecutionStep) (inspection.StepOutput, error) {
	observations, err := m.repository.ListObservations(ctx, run.RunID)
	if err != nil {
		return inspection.StepOutput{}, err
	}
	outcome, err := inspection.Evaluate(plan, observations)
	if err != nil {
		return inspection.StepOutput{}, err
	}
	digest, err := canonicalDigest(outcome)
	if err != nil {
		return inspection.StepOutput{}, err
	}
	return oneStepOutput(step, "outcome_"+digest[:32], digest)
}

func (m *Manager) cleanup(
	ctx context.Context,
	run inspection.Run,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
	inputs []ValueReference,
) (inspection.StepOutput, error) {
	result, err := m.ports.Cleanup.Cleanup(ctx, CleanupRequest{
		RunID: run.RunID, StepID: step.StepID, TenantID: run.TenantID, SiteID: run.SiteID,
		Attempt: attempt.Number, Inputs: append([]ValueReference(nil), inputs...), Deadline: step.Deadline, Budget: step.Budget,
	})
	if err != nil {
		return inspection.StepOutput{}, err
	}
	if result.RunID != run.RunID || result.StepID != step.StepID || result.Attempt != attempt.Number ||
		!validOpaqueRuntimeRef(result.ResultRef) || result.Created != len(inputs) || result.Removed < 0 || result.Pending < 0 ||
		result.Removed+result.Pending != result.Created {
		return inspection.StepOutput{}, errors.New("temporary resource cleaner returned invalid accounting")
	}
	digest, err := canonicalDigest(struct {
		RunID     string `json:"runId"`
		StepID    string `json:"stepId"`
		Attempt   int    `json:"attempt"`
		ResultRef string `json:"resultRef"`
		Created   int    `json:"created"`
		Removed   int    `json:"removed"`
		Pending   int    `json:"pending"`
	}{result.RunID, result.StepID, result.Attempt, result.ResultRef, result.Created, result.Removed, result.Pending})
	if err != nil || result.SHA256 != "" && result.SHA256 != digest {
		return inspection.StepOutput{}, errors.New("temporary resource cleaner returned an invalid result reference")
	}
	if err := m.repository.RecordResourceUsage(ctx, run.RunID, m.ownerID, result.Created, result.Pending, m.now().UTC()); err != nil {
		return inspection.StepOutput{}, err
	}
	return oneStepOutput(step, result.ResultRef, digest)
}

func (m *Manager) inputsForLogicalStep(ctx context.Context, runID string, plan inspection.ExecutionPlan, step inspection.ExecutionStep) ([]ValueReference, error) {
	return m.stepInputs(ctx, runID, plan, step)
}

func (m *Manager) describeMedia(ctx context.Context, input ValueReference) (media.Descriptor, error) {
	switch input.ProducerKind {
	case inspection.StepAcquireMedia, inspection.StepOpenMedia:
		return m.ports.Acquisition.Describe(ctx, input.ValueRef)
	case inspection.StepTransformMedia:
		return m.ports.Transform.Describe(ctx, input.ValueRef)
	default:
		return media.Descriptor{}, errors.New("value reference is not media")
	}
}

func validateExistingEvidence(
	result ExistingEvidenceResult,
	runID string,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt int,
	source inspection.SourceBinding,
) (string, error) {
	if result.RunID != runID || result.StepID != step.StepID || result.Attempt != attempt ||
		!validOpaqueRuntimeRef(result.EvidenceRef) || !validRuntimeVersion(result.AdapterVersion) || result.ObservedAt.IsZero() ||
		result.ObservedAt.Before(plan.RequestedAt) || result.ObservedAt.After(plan.Deadline) || source.SourceHandle == "" {
		return "", errors.New("existing evidence binding is invalid")
	}
	if err := result.Candidate.Validate(); err != nil {
		return "", err
	}
	if err := validateReferencedDescriptor(result.Descriptor, plan, source); err != nil {
		return "", err
	}
	if result.Descriptor.CreatedAt.After(result.ObservedAt.Add(time.Second)) {
		return "", errors.New("existing evidence media was created after its observation")
	}
	digest, err := canonicalDigest(struct {
		RunID          string                     `json:"runId"`
		StepID         string                     `json:"stepId"`
		Attempt        int                        `json:"attempt"`
		EvidenceRef    string                     `json:"evidenceRef"`
		Descriptor     media.Descriptor           `json:"descriptor"`
		Candidate      analysiscontract.Candidate `json:"candidate"`
		ObservedAt     time.Time                  `json:"observedAt"`
		AdapterVersion string                     `json:"adapterVersion"`
	}{result.RunID, result.StepID, result.Attempt, result.EvidenceRef, result.Descriptor, result.Candidate, result.ObservedAt.UTC(), result.AdapterVersion})
	if err != nil || result.SHA256 != "" && result.SHA256 != digest {
		return "", errors.New("existing evidence result digest is invalid")
	}
	return digest, nil
}

func validateAnalysisReference(result AnalysisReference, runID string, plan inspection.ExecutionPlan, step inspection.ExecutionStep, attempt inspection.StepAttempt) (string, error) {
	if result.RunID != runID || result.StepID != step.StepID || result.Attempt != attempt.Number ||
		!validOpaqueRuntimeRef(result.ResultRef) || !validRuntimeVersion(result.ModelVersion) || !validRuntimeVersion(result.AdapterVersion) ||
		result.StartedAt.IsZero() || result.CompletedAt.Before(result.StartedAt) || result.StartedAt.Before(plan.RequestedAt) ||
		result.CompletedAt.After(step.Deadline) || attempt.Number < 1 || attempt.Number > step.Budget.MaxAttempts {
		return "", errors.New("analysis result binding is invalid")
	}
	if err := result.Candidate.Validate(); err != nil {
		return "", err
	}
	digest, err := canonicalDigest(struct {
		RunID          string                     `json:"runId"`
		StepID         string                     `json:"stepId"`
		Attempt        int                        `json:"attempt"`
		ResultRef      string                     `json:"resultRef"`
		Candidate      analysiscontract.Candidate `json:"candidate"`
		ModelVersion   string                     `json:"modelVersion"`
		AdapterVersion string                     `json:"adapterVersion"`
		StartedAt      time.Time                  `json:"startedAt"`
		CompletedAt    time.Time                  `json:"completedAt"`
	}{result.RunID, result.StepID, result.Attempt, result.ResultRef, result.Candidate, result.ModelVersion, result.AdapterVersion, result.StartedAt.UTC(), result.CompletedAt.UTC()})
	if err != nil || result.SHA256 != "" && result.SHA256 != digest {
		return "", errors.New("analysis result digest is invalid")
	}
	return digest, nil
}

func validateMediaDescriptor(
	descriptor media.Descriptor,
	runID string,
	plan inspection.ExecutionPlan,
	step inspection.ExecutionStep,
	attempt inspection.StepAttempt,
	source inspection.SourceBinding,
	parentMediaRef string,
) error {
	if step.Kind == inspection.StepTransformMedia {
		if err := validateBoundDescriptor(descriptor, plan, source); err != nil {
			return err
		}
		if descriptor.Kind != media.KindFrameSet || !sourceAllowsMediaKind(source, media.KindVideoClip) {
			return errors.New("transformed media is not derived from a frozen video capability")
		}
	} else if err := validateReferencedDescriptor(descriptor, plan, source); err != nil {
		return err
	}
	if descriptor.CreatedAt.Before(plan.RequestedAt) || descriptor.CreatedAt.After(step.Deadline) {
		return errors.New("media descriptor creation time is outside the frozen execution window")
	}
	if step.Kind == inspection.StepAcquireMedia || step.Kind == inspection.StepOpenMedia || step.Kind == inspection.StepTransformMedia {
		if descriptor.Binding.RunID != runID || descriptor.Binding.StepID != step.StepID || descriptor.Binding.Attempt != attempt.Number {
			return errors.New("media descriptor execution binding is invalid")
		}
	}
	if parentMediaRef == "" {
		if descriptor.Lineage.ParentMediaRef != "" {
			return errors.New("acquired media unexpectedly claims transform lineage")
		}
		if step.Kind == inspection.StepOpenMedia && descriptor.RuntimeLease.SourceMediaRef == "" {
			return errors.New("opened media has no formal runtime lease")
		}
		if step.Kind == inspection.StepAcquireMedia && descriptor.RuntimeLease.SourceMediaRef != "" {
			return errors.New("newly acquired media unexpectedly claims a runtime lease")
		}
	} else {
		if descriptor.Lineage.ParentMediaRef != parentMediaRef || descriptor.RuntimeLease.SourceMediaRef != "" {
			return errors.New("transformed media parent binding is invalid")
		}
	}
	return nil
}

func validateReferencedDescriptor(descriptor media.Descriptor, plan inspection.ExecutionPlan, source inspection.SourceBinding) error {
	if err := validateBoundDescriptor(descriptor, plan, source); err != nil {
		return err
	}
	if !sourceAllowsMediaKind(source, descriptor.Kind) {
		return errors.New("media descriptor kind is outside the frozen source binding")
	}
	return nil
}

func validateBoundDescriptor(descriptor media.Descriptor, plan inspection.ExecutionPlan, source inspection.SourceBinding) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if descriptor.Schema != media.Schema || !validOpaqueRuntimeRef(descriptor.MediaRef) || descriptor.Availability != media.AvailabilityAvailable ||
		descriptor.Binding.TenantID != plan.TenantID || descriptor.Binding.SiteID != plan.SiteID ||
		descriptor.Binding.SourceRef != source.SourceHandle || !runtimeSHA256.MatchString(descriptor.Integrity.SHA256) ||
		descriptor.Integrity.SizeBytes < 0 || descriptor.CreatedAt.IsZero() {
		return errors.New("media descriptor binding or integrity is invalid")
	}
	if descriptor.Kind == media.KindFrameSet {
		if descriptor.Integrity.SizeBytes != 0 || len(descriptor.FrameMembers) == 0 {
			return errors.New("media frame set descriptor is invalid")
		}
	} else if descriptor.Integrity.SizeBytes < 1 {
		return errors.New("media descriptor has no bounded content")
	}
	return nil
}

func sourceAllowsMediaKind(source inspection.SourceBinding, kind media.Kind) bool {
	for _, allowed := range source.MediaKinds {
		if allowed == kind {
			return true
		}
	}
	return false
}

func buildEnvelope(
	plan inspection.ExecutionPlan,
	target inspection.PlannedTarget,
	planned inspection.PlannedCriterion,
	resultRef string,
	stepID string,
	candidate analysiscontract.Candidate,
	descriptors []media.Descriptor,
	adapterVersion string,
	modelVersion string,
	startedAt time.Time,
	completedAt time.Time,
	attempt int,
	runID string,
) (analysiscontract.Envelope, error) {
	if len(descriptors) == 0 {
		return analysiscontract.Envelope{}, errors.New("analysis result has no typed source media")
	}
	if startedAt.IsZero() {
		startedAt = completedAt
	}
	if completedAt.IsZero() {
		completedAt = startedAt
	}
	startedAt, completedAt = startedAt.UTC(), completedAt.UTC()
	sort.Slice(descriptors, func(i, j int) bool {
		left, right := descriptorCapturedAt(descriptors[i]), descriptorCapturedAt(descriptors[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		return descriptors[i].MediaRef < descriptors[j].MediaRef
	})
	mediaValues := make([]inspection.ResultSourceMedia, 0, len(descriptors))
	seen := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		if _, duplicate := seen[descriptor.MediaRef]; duplicate {
			continue
		}
		seen[descriptor.MediaRef] = struct{}{}
		capturedAt := descriptorCapturedAt(descriptor)
		freshness := startedAt.Sub(capturedAt)
		if freshness < 0 {
			freshness = 0
		}
		mediaValues = append(mediaValues, inspection.ResultSourceMedia{
			SourceRef: descriptor.Binding.SourceRef, MediaRef: descriptor.MediaRef, SHA256: descriptor.Integrity.SHA256,
			CapturedAt: capturedAt, FreshnessMS: freshness.Milliseconds(), SampleOrdinal: len(mediaValues) + 1,
		})
	}
	if len(mediaValues) == 0 {
		return analysiscontract.Envelope{}, errors.New("analysis result has no unique source media")
	}
	kind, err := analyzerKind(planned.Criterion.Method)
	if err != nil {
		return analysiscontract.Envelope{}, err
	}
	contractSHA, err := analysisOutputContractDigest(planned.Criterion.Output)
	if err != nil {
		return analysiscontract.Envelope{}, err
	}
	promptSHA := planned.PromptSHA
	if promptSHA == "" {
		promptSHA = analysiscontract.Digest([]byte(planned.Prompt))
	}
	trusted := analysiscontract.TrustedFields{
		Binding: inspection.ResultBinding{
			ResultID: resultRef, RunID: runID, StepID: stepID,
			TargetID: target.TargetID, CriterionID: planned.Criterion.ID,
			CriterionVersion: strconv.FormatUint(planned.Criterion.RuleVersion, 10),
			OutputKind:       planned.Criterion.Output.Mode, OutputSchemaVersion: planned.Criterion.Output.SchemaVersion,
			Usage: inspection.ResultUsageInspection,
			TimeWindow: inspection.ResultTimeWindow{
				StartAt: mediaValues[0].CapturedAt, EndAt: mediaValues[len(mediaValues)-1].CapturedAt,
			},
			SourceMedia: mediaValues,
		},
		Analyzer: inspection.ResultAnalyzer{
			Kind: kind, AdapterVersion: normalizedVersion(adapterVersion, "unknown-v2"),
			ModelPolicy:           normalizedStableID(target.StrategyPolicy.AnalysisPolicyRef, "existing-evidence-v2"),
			ResolvedModelVersion:  normalizedVersion(modelVersion, "unknown-v2"),
			PromptTemplateID:      planned.Criterion.ID,
			PromptTemplateVersion: strconv.FormatUint(plan.TemplateRevision, 10),
			PromptTemplateSHA256:  promptSHA,
		},
		Execution: inspection.ResultExecution{
			Attempt: attempt, StartedAt: startedAt.UTC(), CompletedAt: completedAt.UTC(),
			LatencyMS: completedAt.Sub(startedAt).Milliseconds(), PersistentConfigWrites: 0,
		},
		Integrity: inspection.ResultIntegrity{
			RawOutputSHA256: analysiscontract.Digest(mustCanonicalJSON(candidate)), ContractSHA256: contractSHA,
		},
	}
	return analysiscontract.Build(trusted, candidate)
}

func analyzerKind(method inspection.Method) (inspection.ResultAnalyzerKind, error) {
	switch method {
	case inspection.MethodCV:
		return inspection.ResultAnalyzerCV, nil
	case inspection.MethodVLM:
		return inspection.ResultAnalyzerVLM, nil
	case inspection.MethodHybrid:
		return inspection.ResultAnalyzerHybrid, nil
	case inspection.MethodEvent:
		return inspection.ResultAnalyzerEvent, nil
	default:
		return "", errors.New("inspection criterion method is outside the typed analysis contract")
	}
}

func analysisOutputContractDigest(contract inspection.OutputContract) (string, error) {
	return canonicalDigest(struct {
		EnvelopeSchema string                    `json:"envelopeSchema"`
		Output         inspection.OutputContract `json:"output"`
	}{analysiscontract.SchemaVersion, contract})
}

func plannedTarget(plan inspection.ExecutionPlan, targetID string) (inspection.PlannedTarget, bool) {
	for _, target := range plan.Targets {
		if target.TargetID == targetID {
			return target, true
		}
	}
	return inspection.PlannedTarget{}, false
}

func plannedTargetSource(plan inspection.ExecutionPlan, targetID, sourceHandle string) (inspection.PlannedTarget, inspection.SourceBinding, bool) {
	target, ok := plannedTarget(plan, targetID)
	if !ok {
		return inspection.PlannedTarget{}, inspection.SourceBinding{}, false
	}
	source, ok := plannedTargetSourceByPredicate(target, sourceHandle, func(inspection.SourceBinding) bool { return true })
	if !ok {
		return inspection.PlannedTarget{}, inspection.SourceBinding{}, false
	}
	return target, source, true
}

func plannedTargetSourceByKind(target inspection.PlannedTarget, sourceHandle string, kind inspection.SourceKind) (inspection.SourceBinding, bool) {
	return plannedTargetSourceByPredicate(target, sourceHandle, func(candidate inspection.SourceBinding) bool {
		return candidate.Kind == kind
	})
}

func plannedTargetSourceByPredicate(target inspection.PlannedTarget, sourceHandle string, matches func(inspection.SourceBinding) bool) (inspection.SourceBinding, bool) {
	var result inspection.SourceBinding
	found := false
	for _, source := range target.SourceBindings {
		if source.SourceHandle != sourceHandle || !matches(source) {
			continue
		}
		if found {
			return inspection.SourceBinding{}, false
		}
		result, found = source, true
	}
	return result, found
}

func plannedTargetTask(target inspection.PlannedTarget, taskID, sourceHandle string) (inspection.InstalledTaskBinding, bool) {
	for _, task := range target.InstalledTasks {
		if task.TaskID != taskID {
			continue
		}
		for _, source := range task.Sources {
			if source.SourceHandle == sourceHandle {
				return task, true
			}
		}
	}
	return inspection.InstalledTaskBinding{}, false
}

func plannedTargetCriterion(plan inspection.ExecutionPlan, targetID, criterionID string) (inspection.PlannedTarget, inspection.PlannedCriterion, bool) {
	target, ok := plannedTarget(plan, targetID)
	if !ok {
		return inspection.PlannedTarget{}, inspection.PlannedCriterion{}, false
	}
	for _, criterion := range target.Criteria {
		if criterion.Criterion.ID == criterionID {
			return target, criterion, true
		}
	}
	return inspection.PlannedTarget{}, inspection.PlannedCriterion{}, false
}

func producerStep(plan inspection.ExecutionPlan, logicalRef string) string {
	for _, step := range plan.Steps {
		for _, output := range step.OutputSlots {
			if output.LogicalRef == logicalRef {
				return step.StepID
			}
		}
	}
	return ""
}

func resultAttempt(inputs []ValueReference, fallback int) int {
	if len(inputs) > 0 && inputs[0].Attempt > 0 {
		return inputs[0].Attempt
	}
	return fallback
}

func oneStepOutput(step inspection.ExecutionStep, valueRef, digest string) (inspection.StepOutput, error) {
	if len(step.OutputSlots) != 1 || !validOpaqueRuntimeRef(valueRef) || !runtimeSHA256.MatchString(digest) {
		return inspection.StepOutput{}, errors.New("inspection step output does not match its frozen contract")
	}
	slot := step.OutputSlots[0]
	return inspection.StepOutput{LogicalRef: slot.LogicalRef, Kind: slot.Kind, ValueRef: valueRef, SHA256: digest}, nil
}

func existingEvidenceOutputSlots(step inspection.ExecutionStep) (inspection.StepOutputSlot, inspection.StepOutputSlot, bool) {
	var evidence, mediaSlot inspection.StepOutputSlot
	for _, slot := range step.OutputSlots {
		switch slot.Kind {
		case inspection.StepValueExistingEvidence:
			evidence = slot
		case inspection.StepValueMedia:
			mediaSlot = slot
		default:
			return inspection.StepOutputSlot{}, inspection.StepOutputSlot{}, false
		}
	}
	return evidence, mediaSlot, evidence.LogicalRef != "" && mediaSlot.LogicalRef != "" && len(step.OutputSlots) == 2
}

func canonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return analysiscontract.Digest(raw), nil
}

func mustCanonicalJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func deterministicRef(prefix string, values ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return prefix + "_" + hex.EncodeToString(digest[:16])
}

func validOpaqueRuntimeRef(value string) bool {
	if !runtimeOpaqueRef.MatchString(value) || strings.TrimSpace(value) != value {
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"http:", "https:", "rtsp:", "rtsps:", "file:", "data:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func validRuntimeVersion(value string) bool {
	return validOpaqueRuntimeRef(value) && len(value) <= 64
}

func normalizedVersion(value, fallback string) string {
	if validRuntimeVersion(value) {
		return value
	}
	return fallback
}

func normalizedStableID(value, fallback string) string {
	if value != "" && value[0] >= 'a' && value[0] <= 'z' && validOpaqueRuntimeRef(value) {
		return value
	}
	return fallback
}

func cloneSourceBindings(values []inspection.SourceBinding) []inspection.SourceBinding {
	result := make([]inspection.SourceBinding, len(values))
	for index, value := range values {
		result[index] = cloneSourceBinding(value)
	}
	return result
}

func cloneSourceBinding(value inspection.SourceBinding) inspection.SourceBinding {
	value.CapabilityRefs = append([]string(nil), value.CapabilityRefs...)
	value.MediaKinds = append([]inspection.MediaKind(nil), value.MediaKinds...)
	return value
}

func cloneInstalledTaskBindings(values []inspection.InstalledTaskBinding) []inspection.InstalledTaskBinding {
	result := make([]inspection.InstalledTaskBinding, len(values))
	for index, value := range values {
		result[index] = cloneInstalledTaskBinding(value)
	}
	return result
}

func cloneInstalledTaskBinding(value inspection.InstalledTaskBinding) inspection.InstalledTaskBinding {
	value.Sources = append([]inspection.InstalledTaskSourceBinding(nil), value.Sources...)
	value.Capabilities = append([]inspection.InstalledTaskCapabilityBinding(nil), value.Capabilities...)
	for index := range value.Capabilities {
		value.Capabilities[index].MediaKinds = append([]inspection.MediaKind(nil), value.Capabilities[index].MediaKinds...)
	}
	return value
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

func descriptorCapturedAt(descriptor media.Descriptor) time.Time {
	if descriptor.Temporal.WindowEnd != nil {
		return descriptor.Temporal.WindowEnd.UTC()
	}
	if descriptor.Temporal.WindowStart != nil {
		return descriptor.Temporal.WindowStart.UTC()
	}
	return descriptor.CreatedAt.UTC()
}

func equalDescriptor(left, right media.Descriptor) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}

func equalCandidate(left, right analysiscontract.Candidate) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}

func equalObservation(left, right inspection.Observation) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}
