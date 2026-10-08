package inspection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

func CompilePlan(template InspectionTemplate, assignment Assignment, request CreateRunRequest) (ExecutionPlan, error) {
	if err := template.Validate(); err != nil {
		return ExecutionPlan{}, err
	}
	if template.State != TemplatePublished {
		return ExecutionPlan{}, errors.New("inspection template is not published")
	}
	if err := assignment.Validate(); err != nil {
		return ExecutionPlan{}, err
	}
	if !assignment.Published {
		return ExecutionPlan{}, errors.New("inspection assignment is not published")
	}
	if err := request.Validate(); err != nil {
		return ExecutionPlan{}, err
	}
	if request.TenantID != template.TenantID || assignment.TenantID != template.TenantID {
		return ExecutionPlan{}, errors.New("inspection tenant binding does not match")
	}
	if request.SiteID != assignment.SiteID {
		return ExecutionPlan{}, errors.New("inspection site binding does not match")
	}
	if request.TemplateID != template.TemplateID || assignment.TemplateID != template.TemplateID {
		return ExecutionPlan{}, errors.New("inspection template binding does not match")
	}
	if request.TemplateRevision != template.Revision || assignment.TemplateRevision != template.Revision {
		return ExecutionPlan{}, errors.New("inspection template revision is stale")
	}
	if request.AssignmentID != assignment.AssignmentID || request.AssignmentRevision != assignment.Revision {
		return ExecutionPlan{}, errors.New("inspection assignment revision is stale")
	}
	if request.Deadline.Sub(request.RequestedAt).Seconds() > float64(template.Budget.MaxDurationSeconds) {
		return ExecutionPlan{}, errors.New("inspection request exceeds its duration budget")
	}

	criteria := make(map[string]Criterion, len(template.Criteria))
	declaredVariables := make(map[string]struct{})
	for _, criterion := range template.Criteria {
		criteria[criterion.ID] = criterion
		for _, variable := range criterion.Prompt.Variables {
			declaredVariables[variable.Name] = struct{}{}
		}
	}
	for name := range request.Variables {
		if _, ok := declaredVariables[name]; !ok {
			return ExecutionPlan{}, fmt.Errorf("undeclared prompt variable %q", name)
		}
	}
	selectedTargets, err := selectTargets(assignment.Targets, request.TargetIDs)
	if err != nil {
		return ExecutionPlan{}, err
	}
	if len(selectedTargets) > template.Budget.MaxTargets {
		return ExecutionPlan{}, errors.New("inspection request exceeds its target budget")
	}
	minimumWait := time.Duration(0)
	for _, target := range selectedTargets {
		minimumWait += time.Duration(target.Acquisition.Samples-1) * time.Duration(target.Acquisition.IntervalMillis) * time.Millisecond
	}
	if minimumWait > request.Deadline.Sub(request.RequestedAt) {
		return ExecutionPlan{}, errors.New("inspection sampling intervals cannot fit within the request deadline")
	}
	analysisCount := 0
	plannedTargets := make([]PlannedTarget, 0, len(selectedTargets))
	for _, target := range selectedTargets {
		policy, ok := strategyPolicy(template.Strategies, target.Strategy)
		if !ok {
			return ExecutionPlan{}, fmt.Errorf("inspection target %q selects an unsupported strategy", target.TargetID)
		}
		if !target.Acquisition.within(policy.MaximumAcquisition) {
			return ExecutionPlan{}, fmt.Errorf("inspection target %q acquisition exceeds its strategy policy", target.TargetID)
		}
		if err := policy.validateBindings(target.SourceBindings); err != nil {
			return ExecutionPlan{}, fmt.Errorf("inspection target %q source policy: %w", target.TargetID, err)
		}
		planned := PlannedTarget{
			TargetID: target.TargetID, FriendlyName: target.FriendlyName, SourceBindings: cloneSourceBindings(target.SourceBindings),
			InstalledTasks: cloneInstalledTaskBindings(target.InstalledTasks),
			StrategyPolicy: cloneStrategyPolicy(policy), Acquisition: target.Acquisition, Criteria: []PlannedCriterion{},
		}
		for _, criterionID := range target.CriterionIDs {
			criterion, ok := criteria[criterionID]
			if !ok {
				return ExecutionPlan{}, fmt.Errorf("inspection assignment references unknown criterion %q", criterionID)
			}
			if !methodSupportedByStrategy(criterion.Method, policy.Strategy) {
				return ExecutionPlan{}, fmt.Errorf("criterion %q is incompatible with strategy %q", criterionID, policy.Strategy)
			}
			promptVariables := make(map[string]string, len(criterion.Prompt.Variables))
			for _, variable := range criterion.Prompt.Variables {
				if value, supplied := request.Variables[variable.Name]; supplied {
					promptVariables[variable.Name] = value
				}
			}
			prompt, digest, err := CompilePrompt(criterion.Prompt, promptVariables)
			if err != nil {
				return ExecutionPlan{}, fmt.Errorf("compile criterion %q prompt: %w", criterionID, err)
			}
			planned.Criteria = append(planned.Criteria, PlannedCriterion{Criterion: criterion, Prompt: prompt, PromptSHA: digest})
			if policy.Strategy != StrategyExistingTaskRead {
				analysisCount += target.Acquisition.Samples
			}
		}
		plannedTargets = append(plannedTargets, planned)
	}
	if analysisCount > template.Budget.MaxAnalyses {
		return ExecutionPlan{}, errors.New("inspection request exceeds its analysis budget")
	}

	requestKey := RequestKey(request.TenantID, request.Origin, request.RequestID)
	plan := ExecutionPlan{
		Schema: SchemaVersion, TenantID: request.TenantID, SiteID: request.SiteID,
		TemplateID: template.TemplateID, TemplateRevision: template.Revision,
		AssignmentID: assignment.AssignmentID, AssignmentRevision: assignment.Revision,
		SourceCatalogFingerprint: assignment.SourceCatalogFingerprint, Origin: request.Origin,
		RequestID: request.RequestID, RequestKey: requestKey,
		Targets: plannedTargets, Budget: template.Budget,
		Evidence: template.Evidence, OutputSchemaVersion: template.OutputSchemaVersion,
		RequestedAt: request.RequestedAt.UTC(), Deadline: request.Deadline.UTC(),
	}
	plan.Steps, err = compileExecutionSteps(plan.Targets, plan.Budget, plan.Deadline)
	if err != nil {
		return ExecutionPlan{}, fmt.Errorf("compile inspection execution steps: %w", err)
	}
	digest, err := digestPlan(plan)
	if err != nil {
		return ExecutionPlan{}, err
	}
	plan.PlanSHA256 = digest
	if err := plan.Validate(); err != nil {
		return ExecutionPlan{}, fmt.Errorf("validate compiled inspection plan: %w", err)
	}
	return plan, nil
}

func strategyPolicy(values []StrategyPolicy, strategy ExecutionStrategy) (StrategyPolicy, bool) {
	index := sort.Search(len(values), func(index int) bool { return values[index].Strategy >= strategy })
	if index >= len(values) || values[index].Strategy != strategy {
		return StrategyPolicy{}, false
	}
	return values[index], true
}

func cloneStrategyPolicy(policy StrategyPolicy) StrategyPolicy {
	policy.AllowedSourceKinds = append([]SourceKind(nil), policy.AllowedSourceKinds...)
	policy.RequiredCapabilityRefs = append([]string(nil), policy.RequiredCapabilityRefs...)
	return policy
}

func cloneSourceBindings(bindings []SourceBinding) []SourceBinding {
	cloned := make([]SourceBinding, len(bindings))
	for index, binding := range bindings {
		binding.CapabilityRefs = append([]string(nil), binding.CapabilityRefs...)
		binding.MediaKinds = append([]MediaKind(nil), binding.MediaKinds...)
		cloned[index] = binding
	}
	return cloned
}

func cloneInstalledTaskBindings(bindings []InstalledTaskBinding) []InstalledTaskBinding {
	cloned := make([]InstalledTaskBinding, len(bindings))
	for index, binding := range bindings {
		binding.Sources = append([]InstalledTaskSourceBinding(nil), binding.Sources...)
		binding.Capabilities = append([]InstalledTaskCapabilityBinding(nil), binding.Capabilities...)
		for capabilityIndex := range binding.Capabilities {
			binding.Capabilities[capabilityIndex].MediaKinds = append([]MediaKind(nil), binding.Capabilities[capabilityIndex].MediaKinds...)
		}
		cloned[index] = binding
	}
	return cloned
}

func RequestKey(tenantID string, origin RunOrigin, requestID string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{tenantID, string(origin), requestID}, "\x00")))
	return "req_" + hex.EncodeToString(digest[:16])
}

func selectTargets(available []TargetBinding, requested []string) ([]TargetBinding, error) {
	if len(requested) == 0 {
		result := append([]TargetBinding(nil), available...)
		sort.SliceStable(result, func(i, j int) bool { return result[i].TargetID < result[j].TargetID })
		return result, nil
	}
	byID := make(map[string]TargetBinding, len(available))
	for _, target := range available {
		byID[target.TargetID] = target
	}
	result := make([]TargetBinding, 0, len(requested))
	for _, targetID := range requested {
		target, ok := byID[targetID]
		if !ok {
			return nil, fmt.Errorf("inspection target %q is unavailable or stale", targetID)
		}
		result = append(result, target)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].TargetID < result[j].TargetID })
	return result, nil
}

func digestPlan(plan ExecutionPlan) (string, error) {
	plan.PlanSHA256 = ""
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
