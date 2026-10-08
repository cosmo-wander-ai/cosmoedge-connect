package inspection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

var (
	publicRefPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sha256Pattern         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	promptVariablePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	protectedPublicData   = regexp.MustCompile(`(?i)(?:https?|rtsps?)://|"(?:password|token|cookie|authorization|endpoint|deviceId|cameraId|cameraHandle|sourceBindings?|sourceHandle|sourceRevision|sourceFingerprint|sourceCatalogFingerprint|capabilityRefs|imageBase64)"\s*:`)
	protectedDisplayData  = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]{1,15}://|\b(?:password|passwd|authorization|bearer|cookie|access[_-]?token|refresh[_-]?token|device[_-]?id|camera[_-]?id|image[_-]?base64|rtsp[_-]?url)\b|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2})`)
)

func (t InspectionTemplate) Validate() error {
	if t.Schema != SchemaVersion {
		return errors.New("inspection template schema is invalid")
	}
	if err := validateRef("tenant", t.TenantID); err != nil {
		return err
	}
	if err := validateRef("template", t.TemplateID); err != nil {
		return err
	}
	if t.Revision == 0 {
		return errors.New("inspection template revision is required")
	}
	if err := validateText("template name", t.Name, 1, 160); err != nil {
		return err
	}
	if err := validateText("business purpose", t.BusinessPurpose, 1, 1000); err != nil {
		return err
	}
	if t.State != TemplateDraft && t.State != TemplatePublished && t.State != TemplateDeprecated {
		return errors.New("inspection template state is invalid")
	}
	if t.CreatedAt.IsZero() {
		return errors.New("inspection template creation metadata is required")
	}
	if err := validateRef("template creator", t.CreatedBy); err != nil {
		return err
	}
	if len(t.Criteria) == 0 || len(t.Criteria) > 100 {
		return errors.New("inspection template requires 1 to 100 criteria")
	}
	seen := map[string]struct{}{}
	required := 0
	for _, criterion := range t.Criteria {
		if _, ok := seen[criterion.ID]; ok {
			return fmt.Errorf("duplicate inspection criterion %q", criterion.ID)
		}
		seen[criterion.ID] = struct{}{}
		if criterion.Required {
			required++
		}
		if err := criterion.Validate(); err != nil {
			return fmt.Errorf("criterion %q: %w", criterion.ID, err)
		}
	}
	if required == 0 {
		return errors.New("inspection template requires at least one required criterion")
	}
	if len(t.Strategies) == 0 || len(t.Strategies) > 4 {
		return errors.New("inspection template requires 1 to 4 strategy policies")
	}
	for index, policy := range t.Strategies {
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("inspection strategy policy %d: %w", index+1, err)
		}
		if index > 0 && t.Strategies[index-1].Strategy >= policy.Strategy {
			return errors.New("inspection strategy policies are not canonical")
		}
	}
	if err := t.Budget.Validate(); err != nil {
		return err
	}
	for _, policy := range t.Strategies {
		if policy.MaximumAcquisition.Samples > t.Budget.MaxSamplesPerTarget {
			return errors.New("strategy acquisition exceeds the per-target sample budget")
		}
		minimumWaitMillis := int64(policy.MaximumAcquisition.Samples-1) * int64(policy.MaximumAcquisition.IntervalMillis)
		if minimumWaitMillis > int64(t.Budget.MaxDurationSeconds)*1000 {
			return errors.New("strategy acquisition intervals exceed the inspection duration budget")
		}
	}
	if t.Evidence.RetentionSeconds < 0 || t.Evidence.RetentionSeconds > 365*24*60*60 {
		return errors.New("inspection evidence retention is invalid")
	}
	if t.Evidence.Required && t.Evidence.RetentionSeconds == 0 {
		return errors.New("required inspection evidence needs a positive retention")
	}
	if t.Evidence.RedactionProfile != "" {
		if err := validateRef("evidence redaction profile", t.Evidence.RedactionProfile); err != nil {
			return err
		}
	}
	if err := validateRef("output schema version", t.OutputSchemaVersion); err != nil {
		return err
	}
	return nil
}

func (b ResourceBudget) Validate() error {
	if b.MaxTargets < 1 || b.MaxTargets > 100 || b.MaxSamplesPerTarget < 1 || b.MaxSamplesPerTarget > 100 {
		return errors.New("inspection target or sample budget is invalid")
	}
	if b.MaxAnalyses < 1 || b.MaxAnalyses > 10000 || b.MaxDurationSeconds < 1 || b.MaxDurationSeconds > 24*60*60 {
		return errors.New("inspection analysis or duration budget is invalid")
	}
	if b.MaxMediaBytes < 1 || b.MaxMediaBytes > 10<<30 {
		return errors.New("inspection media budget is invalid")
	}
	return nil
}

// Validate verifies that an execution plan is a complete, bounded, internally
// consistent snapshot and that its digest binds the exact snapshot content.
// It does not prove who created the plan or grant device authority.
func (p ExecutionPlan) Validate() error {
	if p.Schema != SchemaVersion {
		return errors.New("inspection execution plan schema is invalid")
	}
	for name, value := range map[string]string{
		"tenant": p.TenantID, "site": p.SiteID, "template": p.TemplateID,
		"assignment": p.AssignmentID,
		"request":    p.RequestID, "output schema version": p.OutputSchemaVersion,
	} {
		if err := validateRef(name, value); err != nil {
			return err
		}
	}
	if p.TemplateRevision == 0 || p.AssignmentRevision == 0 {
		return errors.New("inspection execution plan revisions are required")
	}
	if err := validateSHA256("source catalog fingerprint", p.SourceCatalogFingerprint); err != nil {
		return err
	}
	if p.Origin != OriginUser && p.Origin != OriginSchedule && p.Origin != OriginAPI {
		return errors.New("inspection execution plan origin is invalid")
	}
	if p.RequestKey != RequestKey(p.TenantID, p.Origin, p.RequestID) {
		return errors.New("inspection execution plan request key does not match its request")
	}
	if p.RequestedAt.IsZero() || !p.Deadline.After(p.RequestedAt) {
		return errors.New("inspection execution plan times are invalid")
	}
	if err := p.Budget.Validate(); err != nil {
		return err
	}
	if len(p.Targets) == 0 || len(p.Targets) > p.Budget.MaxTargets ||
		p.Deadline.Sub(p.RequestedAt) > time.Duration(p.Budget.MaxDurationSeconds)*time.Second {
		return errors.New("inspection execution plan exceeds its target or duration budget")
	}
	if p.Evidence.RetentionSeconds < 0 || p.Evidence.RetentionSeconds > 365*24*60*60 ||
		(p.Evidence.Required && p.Evidence.RetentionSeconds == 0) {
		return errors.New("inspection execution plan evidence policy is invalid")
	}
	if p.Evidence.RedactionProfile != "" {
		if err := validateRef("evidence redaction profile", p.Evidence.RedactionProfile); err != nil {
			return err
		}
	}

	seenTargets := make(map[string]struct{}, len(p.Targets))
	analyses := 0
	minimumWaitMillis := int64(0)
	for _, target := range p.Targets {
		if err := validateRef("target", target.TargetID); err != nil {
			return err
		}
		if err := validateText("target friendly name", target.FriendlyName, 1, 160); err != nil {
			return err
		}
		if err := validateSourceBindings(target.SourceBindings); err != nil {
			return err
		}
		if err := validateInstalledTaskBindings(target.SourceBindings, target.InstalledTasks); err != nil {
			return err
		}
		if err := target.StrategyPolicy.Validate(); err != nil {
			return err
		}
		if err := target.Acquisition.Validate(target.StrategyPolicy.Strategy); err != nil {
			return err
		}
		if !target.Acquisition.within(target.StrategyPolicy.MaximumAcquisition) {
			return errors.New("inspection execution plan acquisition exceeds its strategy policy")
		}
		if err := target.StrategyPolicy.validateBindings(target.SourceBindings); err != nil {
			return err
		}
		if target.Acquisition.Samples > p.Budget.MaxSamplesPerTarget {
			return errors.New("inspection execution plan exceeds its per-target sample budget")
		}
		minimumWaitMillis += int64(target.Acquisition.Samples-1) * int64(target.Acquisition.IntervalMillis)
		if len(target.Criteria) == 0 || len(target.Criteria) > 100 {
			return errors.New("inspection execution plan target criteria are invalid")
		}
		if _, duplicate := seenTargets[target.TargetID]; duplicate {
			return errors.New("inspection execution plan repeats a target")
		}
		seenTargets[target.TargetID] = struct{}{}

		seenCriteria := make(map[string]struct{}, len(target.Criteria))
		for _, planned := range target.Criteria {
			if err := planned.Criterion.Validate(); err != nil {
				return err
			}
			if _, duplicate := seenCriteria[planned.Criterion.ID]; duplicate {
				return errors.New("inspection execution plan repeats a target criterion")
			}
			seenCriteria[planned.Criterion.ID] = struct{}{}
			if !methodSupportedByStrategy(planned.Criterion.Method, target.StrategyPolicy.Strategy) {
				return errors.New("inspection criterion method is incompatible with the frozen strategy")
			}
			if target.StrategyPolicy.Strategy != StrategyExistingTaskRead {
				analyses += target.Acquisition.Samples
			}

			hasTemplate := strings.TrimSpace(planned.Criterion.Prompt.Template) != ""
			if !hasTemplate {
				if planned.Prompt != "" || planned.PromptSHA != "" {
					return errors.New("inspection execution plan has a prompt without a prompt contract")
				}
				continue
			}
			if err := validateText("compiled prompt", planned.Prompt, 1, 4096); err != nil {
				return err
			}
			if !strings.HasPrefix(planned.Prompt, promptInjectionGuard) || strings.Contains(planned.Prompt, "{{") || strings.Contains(planned.Prompt, "}}") {
				return errors.New("inspection execution plan compiled prompt is not safely resolved")
			}
			digest := sha256.Sum256([]byte(planned.Prompt))
			if planned.PromptSHA != hex.EncodeToString(digest[:]) {
				return errors.New("inspection execution plan prompt digest is invalid")
			}
		}
	}
	if time.Duration(minimumWaitMillis)*time.Millisecond > p.Deadline.Sub(p.RequestedAt) {
		return errors.New("inspection execution plan acquisition intervals exceed its deadline")
	}
	if analyses > p.Budget.MaxAnalyses {
		return errors.New("inspection execution plan exceeds its analysis budget")
	}
	if err := validateExecutionSteps(p); err != nil {
		return err
	}
	digest, err := digestPlan(p)
	if err != nil {
		return err
	}
	if p.PlanSHA256 != digest {
		return errors.New("inspection execution plan digest does not match its content")
	}
	return nil
}

func (c Criterion) Validate() error {
	if err := validateRef("criterion", c.ID); err != nil {
		return err
	}
	if err := validateText("criterion name", c.Name, 1, 160); err != nil {
		return err
	}
	if c.Method != MethodCV && c.Method != MethodVLM && c.Method != MethodHybrid && c.Method != MethodEvent {
		return errors.New("inspection criterion method is invalid")
	}
	if err := validateRef("rule reference", c.RuleRef); err != nil {
		return err
	}
	if c.RuleVersion == 0 {
		return errors.New("inspection criterion rule version is required")
	}
	if err := c.Prompt.Validate(c.Method == MethodVLM || c.Method == MethodHybrid); err != nil {
		return err
	}
	if err := c.Output.Validate(); err != nil {
		return err
	}
	if !c.MayAssertCompliance {
		for _, value := range c.Output.AllowedAssessments {
			if value == AssessmentMeetsRule {
				return errors.New("an observational criterion cannot emit a compliance result")
			}
		}
	}
	return nil
}

func (p PromptContract) Validate(required bool) error {
	if strings.TrimSpace(p.Template) == "" {
		if required {
			return errors.New("VLM inspection criterion requires a prompt template")
		}
		if len(p.Variables) != 0 {
			return errors.New("prompt variables require a prompt template")
		}
		return nil
	}
	if err := validateText("prompt template", p.Template, 1, 4096); err != nil {
		return err
	}
	if len(p.Variables) > 100 {
		return errors.New("inspection prompt variable list is too large")
	}
	seen := map[string]struct{}{}
	for _, variable := range p.Variables {
		if !promptVariablePattern.MatchString(variable.Name) {
			return errors.New("prompt variable name is invalid")
		}
		if _, ok := seen[variable.Name]; ok {
			return fmt.Errorf("duplicate prompt variable %q", variable.Name)
		}
		seen[variable.Name] = struct{}{}
		if variable.MaxLength < 1 || variable.MaxLength > 512 {
			return fmt.Errorf("prompt variable %q has an invalid maximum length", variable.Name)
		}
		if len(variable.AllowedValues) == 0 || len(variable.AllowedValues) > 100 {
			return fmt.Errorf("prompt variable %q requires 1 to 100 approved values", variable.Name)
		}
		allowed := map[string]struct{}{}
		for _, value := range variable.AllowedValues {
			if err := validatePromptValue(value, variable.MaxLength); err != nil {
				return fmt.Errorf("prompt variable %q allowed value: %w", variable.Name, err)
			}
			if _, ok := allowed[value]; ok {
				return fmt.Errorf("prompt variable %q repeats an allowed value", variable.Name)
			}
			allowed[value] = struct{}{}
		}
	}
	placeholders := promptPlaceholders(p.Template)
	for name := range placeholders {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("prompt template uses undeclared variable %q", name)
		}
	}
	for name := range seen {
		if _, ok := placeholders[name]; !ok {
			return fmt.Errorf("prompt variable %q is not used by the template", name)
		}
	}
	return nil
}

func (o OutputContract) Validate() error {
	if !ResultKind(o.Mode).Valid() {
		return errors.New("inspection output mode is invalid")
	}
	if err := validateRef("output contract schema version", o.SchemaVersion); err != nil {
		return err
	}
	if len(o.AllowedAssessments) == 0 || len(o.AllowedAssessments) > 5 {
		return errors.New("inspection output requires allowed assessments")
	}
	seen := map[Assessment]struct{}{}
	for _, assessment := range o.AllowedAssessments {
		if !assessment.Valid() {
			return errors.New("inspection output contains an invalid assessment")
		}
		if _, ok := seen[assessment]; ok {
			return errors.New("inspection output repeats an assessment")
		}
		seen[assessment] = struct{}{}
	}
	return nil
}

func (a Assignment) Validate() error {
	if a.Schema != SchemaVersion {
		return errors.New("inspection assignment schema is invalid")
	}
	for name, value := range map[string]string{
		"tenant": a.TenantID, "assignment": a.AssignmentID, "template": a.TemplateID, "site": a.SiteID,
	} {
		if err := validateRef(name, value); err != nil {
			return err
		}
	}
	if a.Revision == 0 || a.TemplateRevision == 0 {
		return errors.New("inspection assignment revisions are required")
	}
	if err := validateSHA256("source catalog fingerprint", a.SourceCatalogFingerprint); err != nil {
		return err
	}
	if a.ZoneID != "" {
		if err := validateRef("zone", a.ZoneID); err != nil {
			return err
		}
	}
	if len(a.Targets) == 0 || len(a.Targets) > 100 {
		return errors.New("inspection assignment requires 1 to 100 targets")
	}
	seen := map[string]struct{}{}
	for _, target := range a.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
		if _, ok := seen[target.TargetID]; ok {
			return fmt.Errorf("duplicate inspection target %q", target.TargetID)
		}
		seen[target.TargetID] = struct{}{}
	}
	return nil
}

func (t TargetBinding) Validate() error {
	if err := validateRef("target", t.TargetID); err != nil {
		return err
	}
	if err := validateText("target friendly name", t.FriendlyName, 1, 160); err != nil {
		return err
	}
	if err := validateSourceBindings(t.SourceBindings); err != nil {
		return err
	}
	if err := validateInstalledTaskBindings(t.SourceBindings, t.InstalledTasks); err != nil {
		return err
	}
	if !t.Strategy.Valid() {
		return errors.New("inspection target execution strategy is invalid")
	}
	if err := t.Acquisition.Validate(t.Strategy); err != nil {
		return err
	}
	if len(t.CriterionIDs) == 0 || len(t.CriterionIDs) > 100 {
		return errors.New("inspection target requires criteria")
	}
	seen := map[string]struct{}{}
	for _, criterionID := range t.CriterionIDs {
		if err := validateRef("criterion", criterionID); err != nil {
			return err
		}
		if _, ok := seen[criterionID]; ok {
			return fmt.Errorf("inspection target repeats criterion %q", criterionID)
		}
		seen[criterionID] = struct{}{}
	}
	return nil
}

func (k SourceKind) Valid() bool {
	switch k {
	case SourceCamera, SourceUploadedImage, SourceUploadedVideo, SourceTaskEvidence, SourceRetainedMedia:
		return true
	default:
		return false
	}
}

func (s ExecutionStrategy) Valid() bool {
	switch s {
	case StrategyExistingTaskRead, StrategySnapshotAnalysis, StrategyClipAnalysis, StrategyHybridAnalysis:
		return true
	default:
		return false
	}
}

func (p TimePolicy) Validate() error {
	if p.MaxAgeSeconds < 1 || p.MaxAgeSeconds > 30*24*60*60 {
		return errors.New("inspection time policy maximum age is invalid")
	}
	switch p.Mode {
	case TimeCurrent:
		if p.WindowSeconds != 0 {
			return errors.New("current inspection time policy cannot carry a window")
		}
	case TimeRecentWindow:
		if p.WindowSeconds < 1 || p.WindowSeconds > 30*24*60*60 || p.WindowSeconds > p.MaxAgeSeconds {
			return errors.New("recent inspection time window is invalid")
		}
	default:
		return errors.New("inspection time policy mode is invalid")
	}
	return nil
}

func (p AcquisitionPolicy) Validate(strategy ExecutionStrategy) error {
	if !strategy.Valid() || p.Samples < 1 || p.Samples > 100 || p.IntervalMillis < 0 || p.IntervalMillis > 24*60*60*1000 ||
		p.ClipDurationMillis < 0 || p.ClipDurationMillis > 10*60*1000 || p.MaxExtractedFrames < 0 || p.MaxExtractedFrames > 100 {
		return errors.New("inspection acquisition policy is invalid")
	}
	switch strategy {
	case StrategyExistingTaskRead:
		if p.Samples != 1 || p.IntervalMillis != 0 || p.ClipDurationMillis != 0 || p.MaxExtractedFrames != 0 {
			return errors.New("existing-task acquisition policy contains unsupported work")
		}
	case StrategySnapshotAnalysis:
		if p.ClipDurationMillis != 0 || p.MaxExtractedFrames != 0 {
			return errors.New("snapshot acquisition policy contains clip work")
		}
	case StrategyClipAnalysis:
		if p.Samples != 1 || p.IntervalMillis != 0 || p.ClipDurationMillis < 1 || p.MaxExtractedFrames < 1 {
			return errors.New("clip acquisition policy is incomplete")
		}
	case StrategyHybridAnalysis:
		if (p.ClipDurationMillis == 0) != (p.MaxExtractedFrames == 0) {
			return errors.New("hybrid clip acquisition fields must be set together")
		}
	}
	return nil
}

func (p AcquisitionPolicy) within(maximum AcquisitionPolicy) bool {
	return p.Samples <= maximum.Samples && p.IntervalMillis <= maximum.IntervalMillis &&
		p.ClipDurationMillis <= maximum.ClipDurationMillis && p.MaxExtractedFrames <= maximum.MaxExtractedFrames
}

func (p StrategyPolicy) Validate() error {
	if !p.Strategy.Valid() || p.MinimumSources < 1 || p.MaximumSources < p.MinimumSources || p.MaximumSources > 16 {
		return errors.New("inspection strategy source bounds are invalid")
	}
	if len(p.AllowedSourceKinds) == 0 || len(p.AllowedSourceKinds) > 5 {
		return errors.New("inspection strategy requires allowed source kinds")
	}
	for index, kind := range p.AllowedSourceKinds {
		if !kind.Valid() || index > 0 && p.AllowedSourceKinds[index-1] >= kind || !strategyAllowsKind(p.Strategy, kind) {
			return errors.New("inspection strategy source kinds are invalid or not canonical")
		}
	}
	if len(p.RequiredCapabilityRefs) == 0 || len(p.RequiredCapabilityRefs) > 16 {
		return errors.New("inspection strategy requires capability references")
	}
	if err := validateRefList("strategy capability", p.RequiredCapabilityRefs, 16); err != nil {
		return err
	}
	for index := 1; index < len(p.RequiredCapabilityRefs); index++ {
		if p.RequiredCapabilityRefs[index-1] >= p.RequiredCapabilityRefs[index] {
			return errors.New("inspection strategy capability references are not canonical")
		}
	}
	if err := p.Time.Validate(); err != nil {
		return err
	}
	if p.Strategy == StrategyExistingTaskRead {
		if p.AnalysisPolicyRef != "" {
			return errors.New("existing-task strategy cannot carry an analysis policy")
		}
	} else if err := validateRef("strategy analysis policy", p.AnalysisPolicyRef); err != nil {
		return err
	}
	return p.MaximumAcquisition.Validate(p.Strategy)
}

func (p StrategyPolicy) validateBindings(bindings []SourceBinding) error {
	if len(bindings) < p.MinimumSources || len(bindings) > p.MaximumSources {
		return errors.New("inspection source count is outside the strategy policy")
	}
	allowed := make(map[SourceKind]struct{}, len(p.AllowedSourceKinds))
	for _, kind := range p.AllowedSourceKinds {
		allowed[kind] = struct{}{}
	}
	capabilities := make(map[string]struct{})
	hasTask, hasVisual := false, false
	for _, binding := range bindings {
		if _, ok := allowed[binding.Kind]; !ok {
			return errors.New("inspection source kind is outside the strategy policy")
		}
		if binding.Kind == SourceTaskEvidence {
			hasTask = true
		} else {
			hasVisual = true
		}
		if p.Strategy == StrategySnapshotAnalysis && !containsMediaKind(binding.MediaKinds, MediaImage) {
			return errors.New("snapshot strategy source does not provide image media")
		}
		if p.Strategy == StrategyClipAnalysis && !containsMediaKind(binding.MediaKinds, MediaVideoClip) {
			return errors.New("clip strategy source does not provide video media")
		}
		for _, capability := range binding.CapabilityRefs {
			capabilities[capability] = struct{}{}
		}
	}
	for _, required := range p.RequiredCapabilityRefs {
		if _, ok := capabilities[required]; !ok {
			return errors.New("inspection source bindings do not provide a required strategy capability")
		}
	}
	if p.Strategy == StrategyExistingTaskRead && !hasTask || p.Strategy == StrategyHybridAnalysis && (!hasTask || !hasVisual) {
		return errors.New("inspection source combination does not satisfy the selected strategy")
	}
	return nil
}

func containsMediaKind(values []MediaKind, expected MediaKind) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func strategyAllowsKind(strategy ExecutionStrategy, kind SourceKind) bool {
	switch strategy {
	case StrategyExistingTaskRead:
		return kind == SourceTaskEvidence
	case StrategySnapshotAnalysis:
		return kind == SourceCamera || kind == SourceUploadedImage || kind == SourceRetainedMedia
	case StrategyClipAnalysis:
		return kind == SourceCamera || kind == SourceUploadedVideo || kind == SourceRetainedMedia
	case StrategyHybridAnalysis:
		return kind == SourceCamera || kind == SourceUploadedImage || kind == SourceUploadedVideo || kind == SourceTaskEvidence || kind == SourceRetainedMedia
	default:
		return false
	}
}

func methodSupportedByStrategy(method Method, strategy ExecutionStrategy) bool {
	switch strategy {
	case StrategyExistingTaskRead:
		return method == MethodEvent
	case StrategySnapshotAnalysis, StrategyClipAnalysis:
		return method == MethodCV || method == MethodVLM || method == MethodHybrid
	case StrategyHybridAnalysis:
		return method == MethodCV || method == MethodVLM || method == MethodHybrid || method == MethodEvent
	default:
		return false
	}
}

func (s SourceBinding) Validate() error {
	if !s.Kind.Valid() {
		return errors.New("inspection source kind is invalid")
	}
	if err := validateRef("source handle", s.SourceHandle); err != nil {
		return err
	}
	if s.SourceRevision == 0 {
		return errors.New("inspection source revision is required")
	}
	if err := validateSHA256("source fingerprint", s.SourceFingerprint); err != nil {
		return err
	}
	if len(s.CapabilityRefs) == 0 || len(s.CapabilityRefs) > 16 {
		return errors.New("inspection source requires 1 to 16 capability references")
	}
	if err := validateRefList("source capability", s.CapabilityRefs, 16); err != nil {
		return err
	}
	for index := 1; index < len(s.CapabilityRefs); index++ {
		if s.CapabilityRefs[index-1] >= s.CapabilityRefs[index] {
			return errors.New("inspection source capability references are not canonical")
		}
	}
	if len(s.MediaKinds) == 0 || len(s.MediaKinds) > 6 {
		return errors.New("inspection source requires media kinds")
	}
	for index, mediaKind := range s.MediaKinds {
		if !mediaKind.Valid() || index > 0 && s.MediaKinds[index-1] >= mediaKind || !sourceKindSupportsMedia(s.Kind, mediaKind) {
			return errors.New("inspection source media kinds are invalid or not canonical")
		}
	}
	if s.ROIRef != "" {
		if err := validateRef("source ROI", s.ROIRef); err != nil {
			return err
		}
	}
	return nil
}

// Validate rejects incomplete or non-canonical installed-task snapshots. The
// snapshot is intentionally stricter than a display summary because it is an
// execution authority input and must be safe to compare with the live catalog.
func (b InstalledTaskBinding) Validate() error {
	if err := validateRef("installed task", b.TaskID); err != nil {
		return err
	}
	if b.TaskRevision == 0 {
		return errors.New("installed task revision is required")
	}
	if err := validateSHA256("installed task binding fingerprint", b.BindingFingerprint); err != nil {
		return err
	}
	if b.ObservedAt.IsZero() {
		return errors.New("installed task observation time is required")
	}
	if len(b.Sources) == 0 || len(b.Sources) > 32 {
		return errors.New("installed task requires 1 to 32 frozen sources")
	}
	for index, source := range b.Sources {
		if err := validateRef("installed task source", source.SourceHandle); err != nil {
			return err
		}
		if source.SourceRevision == 0 {
			return errors.New("installed task source revision is required")
		}
		if err := validateSHA256("installed task source fingerprint", source.SourceFingerprint); err != nil {
			return err
		}
		if index > 0 && b.Sources[index-1].SourceHandle >= source.SourceHandle {
			return errors.New("installed task sources are not canonical or repeat a source")
		}
	}
	if len(b.Capabilities) == 0 || len(b.Capabilities) > 16 {
		return errors.New("installed task requires 1 to 16 frozen capabilities")
	}
	for index, capability := range b.Capabilities {
		if err := validateRef("installed task capability", capability.Ref); err != nil {
			return err
		}
		if capability.Revision == 0 {
			return errors.New("installed task capability revision is required")
		}
		if err := validateSHA256("installed task capability digest", capability.Digest); err != nil {
			return err
		}
		if err := validateRef("installed task result schema", capability.ResultSchema); err != nil {
			return err
		}
		if len(capability.MediaKinds) == 0 || len(capability.MediaKinds) > 6 {
			return errors.New("installed task capability requires media kinds")
		}
		for mediaIndex, mediaKind := range capability.MediaKinds {
			if !mediaKind.Valid() || !sourceKindSupportsMedia(SourceTaskEvidence, mediaKind) ||
				mediaIndex > 0 && capability.MediaKinds[mediaIndex-1] >= mediaKind {
				return errors.New("installed task capability media kinds are invalid or not canonical")
			}
		}
		if index > 0 && b.Capabilities[index-1].Ref >= capability.Ref {
			return errors.New("installed task capabilities are not canonical or repeat a capability")
		}
	}
	return nil
}

// TaskEvidenceSourceBindings derives the complete set of valid task-evidence
// source shapes for this frozen installed task. Callers must Validate the task
// first. A task identifier is never overloaded as a source identifier.
func (b InstalledTaskBinding) TaskEvidenceSourceBindings() []SourceBinding {
	capabilityRefs := make([]string, 0, len(b.Capabilities))
	mediaSet := make(map[MediaKind]struct{})
	for _, capability := range b.Capabilities {
		capabilityRefs = append(capabilityRefs, capability.Ref)
		for _, mediaKind := range capability.MediaKinds {
			mediaSet[mediaKind] = struct{}{}
		}
	}
	mediaKinds := make([]MediaKind, 0, len(mediaSet))
	for mediaKind := range mediaSet {
		mediaKinds = append(mediaKinds, mediaKind)
	}
	sort.Slice(mediaKinds, func(left, right int) bool { return mediaKinds[left] < mediaKinds[right] })
	result := make([]SourceBinding, 0, len(b.Sources))
	for _, source := range b.Sources {
		result = append(result, SourceBinding{
			Kind: SourceTaskEvidence, SourceHandle: source.SourceHandle, SourceRevision: source.SourceRevision,
			SourceFingerprint: source.SourceFingerprint, CapabilityRefs: append([]string(nil), capabilityRefs...),
			MediaKinds: append([]MediaKind(nil), mediaKinds...),
		})
	}
	return result
}

func validateInstalledTaskBindings(sources []SourceBinding, tasks []InstalledTaskBinding) error {
	taskSources := make(map[string]SourceBinding)
	for _, source := range sources {
		if source.Kind != SourceTaskEvidence {
			continue
		}
		taskSources[source.SourceHandle] = source
	}
	expectedSources := make(map[string]SourceBinding)
	for index, task := range tasks {
		if err := task.Validate(); err != nil {
			return err
		}
		if index > 0 && tasks[index-1].TaskID >= task.TaskID {
			return errors.New("inspection installed task bindings are not canonical or repeat a task")
		}
		for _, expected := range task.TaskEvidenceSourceBindings() {
			if _, duplicate := expectedSources[expected.SourceHandle]; duplicate {
				return errors.New("inspection installed task bindings ambiguously share a source")
			}
			expectedSources[expected.SourceHandle] = expected
		}
	}
	if len(taskSources) != len(expectedSources) {
		return errors.New("inspection task-evidence sources and installed task bindings do not match")
	}
	for sourceHandle, expected := range expectedSources {
		actual, ok := taskSources[sourceHandle]
		if !ok || !equalSourceBinding(actual, expected) {
			return errors.New("inspection installed task binding is incomplete or differs from its task-evidence source")
		}
	}
	return nil
}

func equalSourceBinding(left, right SourceBinding) bool {
	if left.Kind != right.Kind || left.SourceHandle != right.SourceHandle || left.SourceRevision != right.SourceRevision ||
		left.SourceFingerprint != right.SourceFingerprint || left.ROIRef != right.ROIRef ||
		len(left.CapabilityRefs) != len(right.CapabilityRefs) || len(left.MediaKinds) != len(right.MediaKinds) {
		return false
	}
	for index := range left.CapabilityRefs {
		if left.CapabilityRefs[index] != right.CapabilityRefs[index] {
			return false
		}
	}
	for index := range left.MediaKinds {
		if left.MediaKinds[index] != right.MediaKinds[index] {
			return false
		}
	}
	return true
}

func (k MediaKind) Valid() bool {
	switch k {
	case MediaImage, MediaFrameSet, MediaVideoClip, MediaMetric, MediaDetection, MediaEvent:
		return true
	default:
		return false
	}
}

func sourceKindSupportsMedia(source SourceKind, media MediaKind) bool {
	switch source {
	case SourceCamera:
		return media == MediaImage || media == MediaFrameSet || media == MediaVideoClip
	case SourceUploadedImage:
		return media == MediaImage
	case SourceUploadedVideo:
		return media == MediaVideoClip
	case SourceTaskEvidence:
		return media == MediaImage || media == MediaMetric || media == MediaDetection || media == MediaEvent
	case SourceRetainedMedia:
		return media == MediaImage || media == MediaFrameSet || media == MediaVideoClip
	default:
		return false
	}
}

func validateSourceBindings(bindings []SourceBinding) error {
	if len(bindings) == 0 || len(bindings) > 16 {
		return errors.New("inspection target requires 1 to 16 source bindings")
	}
	previous := ""
	for index, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return err
		}
		key := string(binding.Kind) + "\x00" + binding.SourceHandle
		if index > 0 && previous >= key {
			return errors.New("inspection target source bindings are not canonical or repeat a source")
		}
		previous = key
	}
	return nil
}

func (r CreateRunRequest) Validate() error {
	if r.Schema != SchemaVersion {
		return errors.New("inspection run request schema is invalid")
	}
	for name, value := range map[string]string{
		"tenant": r.TenantID, "site": r.SiteID, "template": r.TemplateID,
		"assignment": r.AssignmentID, "request": r.RequestID,
	} {
		if err := validateRef(name, value); err != nil {
			return err
		}
	}
	if r.TemplateRevision == 0 || r.AssignmentRevision == 0 {
		return errors.New("inspection run request revisions are required")
	}
	if r.Origin != OriginUser && r.Origin != OriginSchedule && r.Origin != OriginAPI {
		return errors.New("inspection run origin is invalid")
	}
	if r.RequestedAt.IsZero() || !r.Deadline.After(r.RequestedAt) {
		return errors.New("inspection run request times are invalid")
	}
	if len(r.TargetIDs) > 100 {
		return errors.New("inspection run request target list is too large")
	}
	seen := map[string]struct{}{}
	for _, targetID := range r.TargetIDs {
		if err := validateRef("target", targetID); err != nil {
			return err
		}
		if _, ok := seen[targetID]; ok {
			return fmt.Errorf("inspection request repeats target %q", targetID)
		}
		seen[targetID] = struct{}{}
	}
	if len(r.Variables) > 256 {
		return errors.New("inspection run request variable map is too large")
	}
	for name, value := range r.Variables {
		if !promptVariablePattern.MatchString(name) {
			return fmt.Errorf("inspection prompt variable name %q is invalid", name)
		}
		if err := validatePromptValue(value, 512); err != nil {
			return fmt.Errorf("inspection prompt variable %q: %w", name, err)
		}
	}
	return nil
}

func (o Observation) Validate() error {
	if err := validateRef("observation", o.ObservationID); err != nil {
		return err
	}
	if err := validateRef("sample", o.SampleID); err != nil {
		return err
	}
	return o.Result.Validate()
}

func (r AnalysisResult) Validate() error {
	if err := r.Binding.Validate(); err != nil {
		return err
	}
	if !r.Assessment.Valid() {
		return errors.New("inspection analysis result assessment is invalid")
	}
	if !r.Observability.Valid() {
		return errors.New("inspection analysis result observability is invalid")
	}
	if r.Confidence != nil && (!finite(*r.Confidence) || *r.Confidence < 0 || *r.Confidence > 1) {
		return errors.New("inspection analysis result confidence is invalid")
	}
	if err := validateRefList("result evidence", r.EvidenceRefs, 16); err != nil {
		return err
	}
	if err := validateRefList("result reason", r.ReasonCodes, 16); err != nil {
		return err
	}
	if err := validateRefList("result limitation", r.Limitations, 16); err != nil {
		return err
	}
	if len(r.ReasonCodes) == 0 {
		return errors.New("inspection analysis result requires a reason code")
	}
	reasons := make(map[string]struct{}, len(r.ReasonCodes))
	for _, reason := range r.ReasonCodes {
		if !validResultReason(reason) {
			return errors.New("inspection analysis result contains an unknown reason code")
		}
		reasons[reason] = struct{}{}
	}
	limitations := make(map[string]struct{}, len(r.Limitations))
	for _, limitation := range r.Limitations {
		if !validResultLimitation(limitation) {
			return errors.New("inspection analysis result contains an unknown limitation")
		}
		limitations[limitation] = struct{}{}
	}
	if err := validateResultSemantics(r, reasons, limitations); err != nil {
		return err
	}
	media := make(map[string]struct{}, len(r.Binding.SourceMedia))
	for _, source := range r.Binding.SourceMedia {
		media[source.MediaRef] = struct{}{}
	}
	for _, ref := range r.EvidenceRefs {
		if _, ok := media[ref]; !ok {
			return errors.New("inspection analysis result references evidence outside its binding")
		}
	}
	conclusive := r.Assessment == AssessmentMeetsRule || r.Assessment == AssessmentNeedsAttention
	if conclusive {
		if r.Value == nil || len(r.EvidenceRefs) == 0 {
			return errors.New("conclusive inspection analysis result requires a typed value and evidence")
		}
	} else if r.Value != nil {
		return errors.New("inconclusive inspection analysis result cannot carry a typed value")
	}
	if r.Value != nil {
		if r.Value.Kind != r.Binding.OutputKind {
			return errors.New("inspection analysis result kind does not match its frozen output contract")
		}
		if err := r.Value.Validate(r.EvidenceRefs, r.Binding.TimeWindow); err != nil {
			return err
		}
	}
	if err := r.Analyzer.Validate(); err != nil {
		return err
	}
	if err := r.Execution.Validate(); err != nil {
		return err
	}
	if r.Binding.TimeWindow.EndAt.After(r.Execution.CompletedAt) {
		return errors.New("inspection result scene-time window ends after trusted execution")
	}
	if err := r.Integrity.Validate(); err != nil {
		return err
	}
	for _, source := range r.Binding.SourceMedia {
		age := r.Execution.StartedAt.Sub(source.CapturedAt)
		if age < -time.Second || source.CapturedAt.After(r.Execution.CompletedAt.Add(time.Second)) {
			return errors.New("inspection analysis result media time contradicts trusted execution")
		}
		if absoluteDuration(age-time.Duration(source.FreshnessMS)*time.Millisecond) > time.Second {
			return errors.New("inspection analysis result media freshness contradicts trusted execution")
		}
	}
	if r.Display == nil {
		return nil
	}
	if r.Binding.Usage != ResultUsageTemporaryObservation {
		return errors.New("standard inspection result cannot carry model display text")
	}
	if err := validateRef("display policy", r.Display.PolicyRef); err != nil {
		return err
	}
	if err := validateRef("display locale", r.Display.Locale); err != nil {
		return err
	}
	if err := validateText("policy-bound display text", r.Display.Text, 1, 1024); err != nil {
		return err
	}
	if protectedDisplayData.MatchString(r.Display.Text) {
		return errors.New("policy-bound display text contains protected data")
	}
	return nil
}

func (b ResultBinding) Validate() error {
	for name, value := range map[string]string{
		"result": b.ResultID, "run": b.RunID, "step": b.StepID, "target": b.TargetID,
		"criterion": b.CriterionID, "criterion version": b.CriterionVersion,
		"output schema version": b.OutputSchemaVersion,
	} {
		if err := validateRef(name, value); err != nil {
			return err
		}
	}
	if !b.OutputKind.Valid() {
		return errors.New("inspection result binding output kind is invalid")
	}
	if b.Usage != ResultUsageInspection && b.Usage != ResultUsageTemporaryObservation {
		return errors.New("inspection result binding usage is invalid")
	}
	if err := b.TimeWindow.Validate(); err != nil {
		return err
	}
	if len(b.SourceMedia) < 1 || len(b.SourceMedia) > 16 {
		return errors.New("inspection result binding requires 1 to 16 source media entries")
	}
	mediaRefs := make(map[string]struct{}, len(b.SourceMedia))
	ordinals := make(map[int]struct{}, len(b.SourceMedia))
	for _, source := range b.SourceMedia {
		if err := source.Validate(b.TimeWindow); err != nil {
			return err
		}
		if _, duplicate := mediaRefs[source.MediaRef]; duplicate {
			return errors.New("inspection result binding repeats a media reference")
		}
		if _, duplicate := ordinals[source.SampleOrdinal]; duplicate {
			return errors.New("inspection result binding repeats a sample ordinal")
		}
		mediaRefs[source.MediaRef] = struct{}{}
		ordinals[source.SampleOrdinal] = struct{}{}
	}
	return nil
}

func (w ResultTimeWindow) Validate() error {
	if w.StartAt.IsZero() || w.EndAt.IsZero() || w.EndAt.Before(w.StartAt) || w.EndAt.Sub(w.StartAt) > 24*time.Hour {
		return errors.New("inspection result time window is invalid")
	}
	return nil
}

func (s ResultSourceMedia) Validate(window ResultTimeWindow) error {
	if err := validateRef("result source", s.SourceRef); err != nil {
		return err
	}
	if err := validateRef("result media", s.MediaRef); err != nil {
		return err
	}
	if err := validateSHA256("result media sha256", s.SHA256); err != nil {
		return err
	}
	if s.CapturedAt.IsZero() || s.CapturedAt.Before(window.StartAt) || s.CapturedAt.After(window.EndAt) {
		return errors.New("inspection result media capture is outside its time window")
	}
	if s.FreshnessMS < 0 || s.FreshnessMS > 86_400_000 || s.SampleOrdinal < 1 || s.SampleOrdinal > 100 {
		return errors.New("inspection result media freshness or ordinal is invalid")
	}
	return nil
}

func (a ResultAnalyzer) Validate() error {
	switch a.Kind {
	case ResultAnalyzerCV, ResultAnalyzerVLM, ResultAnalyzerHybrid, ResultAnalyzerEvent, ResultAnalyzerFixture:
	default:
		return errors.New("inspection result analyzer kind is invalid")
	}
	for name, value := range map[string]string{
		"analyzer adapter version": a.AdapterVersion,
		"analyzer model policy":    a.ModelPolicy,
		"prompt template":          a.PromptTemplateID,
		"prompt template version":  a.PromptTemplateVersion,
	} {
		if err := validateRef(name, value); err != nil {
			return err
		}
	}
	if a.ResolvedModelVersion != "" {
		if err := validateRef("resolved model version", a.ResolvedModelVersion); err != nil {
			return err
		}
	}
	return validateSHA256("prompt template sha256", a.PromptTemplateSHA256)
}

func (e ResultExecution) Validate() error {
	if e.Attempt < 1 || e.Attempt > 16 || e.StartedAt.IsZero() || e.CompletedAt.IsZero() || e.CompletedAt.Before(e.StartedAt) {
		return errors.New("inspection result execution identity or time is invalid")
	}
	if e.LatencyMS < 0 || e.LatencyMS > 3_600_000 || absoluteDuration(e.CompletedAt.Sub(e.StartedAt)-time.Duration(e.LatencyMS)*time.Millisecond) > time.Second {
		return errors.New("inspection result execution latency is invalid")
	}
	if e.TemporaryResourcesCreated < 0 || e.TemporaryResourcesCreated > 64 || e.TemporaryResourcesCleaned < 0 || e.TemporaryResourcesCleaned > e.TemporaryResourcesCreated {
		return errors.New("inspection result temporary resource accounting is invalid")
	}
	if e.PersistentConfigWrites != 0 {
		return errors.New("inspection result persistent configuration writes must equal zero")
	}
	return nil
}

func (i ResultIntegrity) Validate() error {
	if err := validateSHA256("result raw output sha256", i.RawOutputSHA256); err != nil {
		return err
	}
	return validateSHA256("result contract sha256", i.ContractSHA256)
}

func (v ResultValue) Validate(evidenceRefs []string, window ResultTimeWindow) error {
	if !v.Kind.Valid() {
		return errors.New("inspection typed result kind is invalid")
	}
	active := 0
	for _, present := range []bool{v.Classification != nil, v.Enum != nil, v.Structured != nil, v.Metric != nil, v.Detection != nil, v.Count != nil, v.Event != nil} {
		if present {
			active++
		}
	}
	if active != 1 {
		return errors.New("inspection typed result must contain exactly one union member")
	}
	evidence := make(map[string]struct{}, len(evidenceRefs))
	for _, ref := range evidenceRefs {
		evidence[ref] = struct{}{}
	}
	switch v.Kind {
	case ResultClassification:
		if v.Classification == nil {
			return errors.New("inspection classification result union tag mismatch")
		}
		if err := validateRef("classification label", v.Classification.Label); err != nil {
			return err
		}
		return validateScore(v.Classification.Score)
	case ResultEnum:
		if v.Enum == nil {
			return errors.New("inspection enum result union tag mismatch")
		}
		return validateRef("enum value", v.Enum.Value)
	case ResultStructured:
		if v.Structured == nil {
			return errors.New("inspection structured result union tag mismatch")
		}
		return v.Structured.Validate()
	case ResultMetric:
		if v.Metric == nil || !finite(v.Metric.Value) {
			return errors.New("inspection metric result union tag or value is invalid")
		}
		return validateRef("metric unit", v.Metric.Unit)
	case ResultDetection:
		if v.Detection == nil {
			return errors.New("inspection detection result union tag mismatch")
		}
		return v.Detection.Validate(evidence)
	case ResultCount:
		if v.Count == nil || v.Count.Value < 0 || v.Count.Value > 1_000_000_000 {
			return errors.New("inspection count result union tag or value is invalid")
		}
		if err := validateRef("count label", v.Count.Label); err != nil {
			return err
		}
		return validateRef("count unit", v.Count.Unit)
	case ResultEvent:
		if v.Event == nil {
			return errors.New("inspection event result union tag mismatch")
		}
		return v.Event.Validate(evidence, window)
	default:
		return errors.New("inspection typed result union tag is invalid")
	}
}

func (v StructuredValue) Validate() error {
	if len(v.Fields) < 1 || len(v.Fields) > 32 {
		return errors.New("inspection structured result requires 1 to 32 fields")
	}
	seen := make(map[string]struct{}, len(v.Fields))
	for _, field := range v.Fields {
		if err := validateRef("structured field", field.Name); err != nil {
			return err
		}
		if _, duplicate := seen[field.Name]; duplicate {
			return errors.New("inspection structured result repeats a field")
		}
		seen[field.Name] = struct{}{}
		if err := field.Value.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (v StructuredScalar) Validate() error {
	active := 0
	for _, present := range []bool{v.Enum != nil, v.Number != nil, v.Integer != nil, v.Boolean != nil} {
		if present {
			active++
		}
	}
	if active != 1 {
		return errors.New("inspection structured scalar must contain exactly one union member")
	}
	switch v.Kind {
	case StructuredEnum:
		if v.Enum == nil {
			return errors.New("inspection structured enum tag mismatch")
		}
		return validateRef("structured enum", *v.Enum)
	case StructuredNumber:
		if v.Number == nil || !finite(*v.Number) {
			return errors.New("inspection structured number is invalid")
		}
	case StructuredInteger:
		if v.Integer == nil {
			return errors.New("inspection structured integer tag mismatch")
		}
	case StructuredBoolean:
		if v.Boolean == nil {
			return errors.New("inspection structured boolean tag mismatch")
		}
	default:
		return errors.New("inspection structured scalar kind is invalid")
	}
	return nil
}

func (v DetectionValue) Validate(evidence map[string]struct{}) error {
	if v.Objects == nil || len(v.Objects) > 64 {
		return errors.New("inspection detection objects must be present and bounded")
	}
	for _, object := range v.Objects {
		if err := validateRef("detection label", object.Label); err != nil {
			return err
		}
		if err := validateScore(object.Score); err != nil {
			return err
		}
		if err := object.Region.Validate(); err != nil {
			return err
		}
		if _, ok := evidence[object.EvidenceRef]; !ok {
			return errors.New("inspection detection references unbound evidence")
		}
	}
	return nil
}

func (v EventValue) Validate(evidence map[string]struct{}, window ResultTimeWindow) error {
	if err := validateRef("event type", v.Type); err != nil {
		return err
	}
	switch v.State {
	case EventOccurred, EventStarted, EventActive, EventEnded:
	default:
		return errors.New("inspection event state is invalid")
	}
	if v.OccurredAt.IsZero() || v.OccurredAt.Before(window.StartAt) || v.OccurredAt.After(window.EndAt) {
		return errors.New("inspection event time is outside its bound time window")
	}
	if _, ok := evidence[v.EvidenceRef]; !ok {
		return errors.New("inspection event references unbound evidence")
	}
	return nil
}

func (r NormalizedRegion) Validate() error {
	values := []float64{r.X, r.Y, r.Width, r.Height}
	for _, value := range values {
		if !finite(value) {
			return errors.New("inspection normalized region contains a non-finite coordinate")
		}
	}
	if r.X < 0 || r.X > 1 || r.Y < 0 || r.Y > 1 || r.Width <= 0 || r.Width > 1 || r.Height <= 0 || r.Height > 1 || r.X+r.Width > 1+1e-12 || r.Y+r.Height > 1+1e-12 {
		return errors.New("inspection normalized region is outside the unit frame")
	}
	return nil
}

func (p ResultProjection) Validate() error {
	if err := validateRef("projected result", p.ResultID); err != nil {
		return err
	}
	if err := validateRef("projected sample", p.SampleID); err != nil {
		return err
	}
	if !p.OutputKind.Valid() {
		return errors.New("inspection projected result output kind is invalid")
	}
	if err := validateRefList("projected result evidence", p.EvidenceRefs, 16); err != nil {
		return err
	}
	if err := p.TimeWindow.Validate(); err != nil {
		return err
	}
	if p.Value != nil {
		if p.Value.Kind != p.OutputKind {
			return errors.New("inspection projected result kind mismatch")
		}
		return p.Value.Validate(p.EvidenceRefs, p.TimeWindow)
	}
	return nil
}

func (k ResultKind) Valid() bool {
	switch k {
	case ResultClassification, ResultEnum, ResultStructured, ResultMetric, ResultDetection, ResultCount, ResultEvent:
		return true
	default:
		return false
	}
}

func (o ResultObservability) Valid() bool {
	switch o {
	case ResultFullyVisible, ResultPartiallyVisible, ResultNotVisible, ResultUnusable:
		return true
	default:
		return false
	}
}

func validateResultSemantics(result AnalysisResult, reasons, limitations map[string]struct{}) error {
	hasReason := func(values ...string) bool {
		for _, value := range values {
			if _, ok := reasons[value]; ok {
				return true
			}
		}
		return false
	}
	hasLimitation := func(values ...string) bool {
		for _, value := range values {
			if _, ok := limitations[value]; ok {
				return true
			}
		}
		return false
	}
	if result.Observability == ResultFullyVisible && hasLimitation("occlusion", "out_of_frame") {
		return errors.New("fully visible inspection result contradicts its limitations")
	}
	switch result.Assessment {
	case AssessmentMeetsRule:
		if !hasReason("criterion_met") || hasReason("criterion_violated", "insufficient_evidence", "invalid_model_output", "analyzer_timeout", "unsupported_criterion", "inconsistent_samples") ||
			result.Observability == ResultNotVisible || result.Observability == ResultUnusable ||
			hasLimitation("occlusion", "out_of_frame", "stale_capture", "insufficient_samples", "conflicting_samples", "criterion_not_visual", "analyzer_limit") {
			return errors.New("meets_rule inspection result has contradictory evidence semantics")
		}
	case AssessmentNeedsAttention:
		if !hasReason("criterion_violated") || hasReason("criterion_met", "insufficient_evidence", "invalid_model_output", "analyzer_timeout", "unsupported_criterion", "inconsistent_samples") ||
			result.Observability == ResultNotVisible || result.Observability == ResultUnusable ||
			hasLimitation("stale_capture", "insufficient_samples", "conflicting_samples", "criterion_not_visual", "analyzer_limit") {
			return errors.New("needs_attention inspection result has contradictory evidence semantics")
		}
	case AssessmentUncertain:
		if !hasReason("insufficient_evidence", "invalid_model_output", "analyzer_timeout", "inconsistent_samples") ||
			hasReason("criterion_met", "criterion_violated", "unsupported_criterion") {
			return errors.New("uncertain inspection result has contradictory evidence semantics")
		}
	case AssessmentNotObservable:
		if (result.Observability != ResultNotVisible && result.Observability != ResultUnusable) ||
			!hasReason("not_visible", "unusable_media") || hasReason("criterion_met", "criterion_violated", "unsupported_criterion") {
			return errors.New("not_observable inspection result has contradictory evidence semantics")
		}
	case AssessmentUnsupported:
		if !hasReason("unsupported_criterion") || hasReason("criterion_met", "criterion_violated") ||
			!hasLimitation("criterion_not_visual", "analyzer_limit") {
			return errors.New("unsupported inspection result has contradictory evidence semantics")
		}
	}
	return nil
}

func validResultReason(value string) bool {
	switch value {
	case "criterion_met", "criterion_violated", "insufficient_evidence", "not_visible", "unusable_media",
		"invalid_model_output", "analyzer_timeout", "unsupported_criterion", "inconsistent_samples":
		return true
	default:
		return false
	}
}

func validResultLimitation(value string) bool {
	switch value {
	case "occlusion", "low_light", "glare", "motion_blur", "low_resolution", "out_of_frame", "stale_capture",
		"insufficient_samples", "conflicting_samples", "criterion_not_visual", "analyzer_limit":
		return true
	default:
		return false
	}
}

func validateScore(value *float64) error {
	if value != nil && (!finite(*value) || *value < 0 || *value > 1) {
		return errors.New("inspection result score is invalid")
	}
	return nil
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func absoluteDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func (a Assessment) Valid() bool {
	switch a {
	case AssessmentMeetsRule, AssessmentNeedsAttention, AssessmentUncertain, AssessmentNotObservable, AssessmentUnsupported:
		return true
	default:
		return false
	}
}

func validateRef(name, value string) error {
	if value != strings.TrimSpace(value) || !publicRefPattern.MatchString(value) {
		return fmt.Errorf("inspection %s reference is invalid", name)
	}
	return nil
}

func validateSHA256(name, value string) error {
	if !sha256Pattern.MatchString(value) {
		return fmt.Errorf("inspection %s is invalid", name)
	}
	return nil
}

func validateText(name, value string, minimum, maximum int) error {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum {
		return fmt.Errorf("inspection %s is invalid", name)
	}
	for _, r := range value {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return fmt.Errorf("inspection %s contains control characters", name)
		}
	}
	return nil
}

func validateStringList(name string, values []string, maximumItems, maximumLength int) error {
	if len(values) > maximumItems {
		return fmt.Errorf("inspection %s list is too large", name)
	}
	for _, value := range values {
		if err := validateText(name, value, 1, maximumLength); err != nil {
			return err
		}
	}
	return nil
}

func validateRefList(name string, values []string, maximumItems int) error {
	if len(values) > maximumItems {
		return fmt.Errorf("inspection %s list is too large", name)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateRef(name, value); err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("inspection %s list repeats %q", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func decodeStrict(raw []byte, output any) error {
	if err := validateJSONStructure(raw, 16); err != nil {
		return err
	}
	if err := strictjson.ValidateExactFields(raw, output, 16); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func validateJSONStructure(raw []byte, maximumDepth int) error {
	if maximumDepth < 1 {
		return errors.New("JSON depth limit is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0, maximumDepth); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth, maximumDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if depth >= maximumDepth {
		return errors.New("JSON nesting exceeds the allowed depth")
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1, maximumDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1, maximumDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("JSON compound delimiter is invalid")
	}
	return nil
}
