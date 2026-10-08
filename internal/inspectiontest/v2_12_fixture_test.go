package inspectiontest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const (
	gateTenantID     = "tenant-gate"
	gateSiteID       = "site-gate"
	gateTemplateID   = "scene-condition-template"
	gateAssignmentID = "scene-condition-assignment"
	gateTargetID     = "zone-alpha"
	gateCriterionID  = "scene-condition"
	gateTaskID       = "task-scene-alpha"
	gateTaskSource   = "source-task-alpha"
	gateCameraSource = "source-camera-alpha"
)

type gateMode string

const (
	gateExisting      gateMode = "existing"
	gateSnapshot      gateMode = "snapshot"
	gateUploadedImage gateMode = "uploaded-image"
	gateClip          gateMode = "clip"
	gateHybrid        gateMode = "hybrid"
)

type gateFixture struct {
	Mode       gateMode
	Template   inspection.InspectionTemplate
	Assignment inspection.Assignment
	Request    inspection.CreateRunRequest
}

func newGateFixture(base time.Time, mode gateMode, requestID string, taskOverride *inspection.InstalledTaskBinding) (gateFixture, error) {
	base = base.UTC().Truncate(time.Millisecond)
	if requestID == "" {
		requestID = "gate-request-" + string(mode)
	}
	method := inspection.MethodVLM
	prompt := inspection.PromptContract{
		Template:  "Inspect the declared scene condition using only the supplied bounded evidence.",
		Variables: []inspection.PromptVariable{},
	}
	strategy := inspection.StrategySnapshotAnalysis
	policy := inspection.StrategyPolicy{
		Strategy: strategy, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera},
		RequiredCapabilityRefs: []string{"snapshot-input"}, MinimumSources: 1, MaximumSources: 1,
		Time:               inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
		AnalysisPolicyRef:  "bounded-vlm-v2",
		MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1},
	}
	acquisition := inspection.AcquisitionPolicy{Samples: 1}
	installedTask := syntheticGateTask(base)
	if taskOverride != nil {
		installedTask = cloneGateTask(*taskOverride)
	}
	var sources []inspection.SourceBinding
	var installedTasks []inspection.InstalledTaskBinding
	switch mode {
	case gateExisting:
		method = inspection.MethodEvent
		prompt = inspection.PromptContract{Variables: []inspection.PromptVariable{}}
		strategy = inspection.StrategyExistingTaskRead
		policy = inspection.StrategyPolicy{
			Strategy: strategy, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceTaskEvidence},
			RequiredCapabilityRefs: []string{"existing-evidence"}, MinimumSources: 1, MaximumSources: 1,
			Time:               inspection.TimePolicy{Mode: inspection.TimeRecentWindow, WindowSeconds: 60, MaxAgeSeconds: 120},
			MaximumAcquisition: acquisition,
		}
		sources = installedTask.TaskEvidenceSourceBindings()
		installedTasks = []inspection.InstalledTaskBinding{installedTask}
	case gateSnapshot:
		sources = []inspection.SourceBinding{gateVisualSource(inspection.SourceCamera, gateCameraSource, "snapshot-input", inspection.MediaImage)}
	case gateUploadedImage:
		policy.AllowedSourceKinds = []inspection.SourceKind{inspection.SourceUploadedImage}
		sources = []inspection.SourceBinding{gateVisualSource(inspection.SourceUploadedImage, "source-upload-image-alpha", "snapshot-input", inspection.MediaImage)}
	case gateClip:
		strategy = inspection.StrategyClipAnalysis
		acquisition = inspection.AcquisitionPolicy{Samples: 1, ClipDurationMillis: 1500, MaxExtractedFrames: 3}
		policy = inspection.StrategyPolicy{
			Strategy: strategy, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceUploadedVideo},
			RequiredCapabilityRefs: []string{"clip-input"}, MinimumSources: 1, MaximumSources: 1,
			Time:              inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
			AnalysisPolicyRef: "bounded-vlm-v2", MaximumAcquisition: acquisition,
		}
		sources = []inspection.SourceBinding{gateVisualSource(inspection.SourceUploadedVideo, "source-upload-video-alpha", "clip-input", inspection.MediaVideoClip)}
	case gateHybrid:
		method = inspection.MethodHybrid
		strategy = inspection.StrategyHybridAnalysis
		policy = inspection.StrategyPolicy{
			Strategy:               strategy,
			AllowedSourceKinds:     []inspection.SourceKind{inspection.SourceCamera, inspection.SourceTaskEvidence},
			RequiredCapabilityRefs: []string{"existing-evidence", "snapshot-input"}, MinimumSources: 2, MaximumSources: 2,
			Time:              inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
			AnalysisPolicyRef: "hybrid-cv-vlm-v2", MaximumAcquisition: acquisition,
		}
		sources = append([]inspection.SourceBinding{
			gateVisualSource(inspection.SourceCamera, gateCameraSource, "snapshot-input", inspection.MediaImage),
		}, installedTask.TaskEvidenceSourceBindings()...)
		installedTasks = []inspection.InstalledTaskBinding{installedTask}
	default:
		return gateFixture{}, fmt.Errorf("unknown v2-12 gate mode %q", mode)
	}

	template := inspection.InspectionTemplate{
		Schema: inspection.SchemaVersion, TenantID: gateTenantID, TemplateID: gateTemplateID,
		Revision: 1, Name: "Generic scene condition inspection",
		BusinessPurpose: "Evaluate one declared scene condition from bounded typed evidence.",
		Criteria: []inspection.Criterion{{
			ID: gateCriterionID, Name: "Declared scene condition", Method: method, Required: true,
			RuleRef: "scene-condition-rule-v2", RuleVersion: 1, MayAssertCompliance: true,
			Prompt: prompt,
			Output: inspection.OutputContract{
				Mode: inspection.ResultClassification, SchemaVersion: "classification.v2",
				AllowedAssessments: []inspection.Assessment{
					inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention,
					inspection.AssessmentUncertain, inspection.AssessmentNotObservable,
				},
			},
		}},
		Strategies: []inspection.StrategyPolicy{policy},
		Budget: inspection.ResourceBudget{
			MaxTargets: 1, MaxSamplesPerTarget: 1, MaxAnalyses: 4,
			MaxDurationSeconds: 300, MaxMediaBytes: 8 << 20,
		},
		Evidence: inspection.EvidencePolicy{
			Required: true, RetentionSeconds: 1200, RedactionProfile: "generic-redaction-v2",
		},
		OutputSchemaVersion: "report.v2", State: inspection.TemplatePublished,
		CreatedBy: "inspectiontest-v2-12", CreatedAt: base.Add(-time.Hour),
	}
	assignment := inspection.Assignment{
		Schema: inspection.SchemaVersion, TenantID: gateTenantID, AssignmentID: gateAssignmentID,
		Revision: 1, TemplateID: gateTemplateID, TemplateRevision: 1, SiteID: gateSiteID,
		ZoneID: "zone-alpha", SourceCatalogFingerprint: gateDigest("catalog:" + string(mode)), Published: true,
		Targets: []inspection.TargetBinding{{
			TargetID: gateTargetID, FriendlyName: "Generic zone alpha", SourceBindings: sources,
			InstalledTasks: installedTasks, CriterionIDs: []string{gateCriterionID}, Strategy: strategy,
			Acquisition: acquisition,
		}},
	}
	request := inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: gateTenantID, SiteID: gateSiteID,
		TemplateID: gateTemplateID, TemplateRevision: 1,
		AssignmentID: gateAssignmentID, AssignmentRevision: 1,
		Origin: inspection.OriginAPI, RequestID: requestID, Variables: map[string]string{},
		RequestedAt: base, Deadline: base.Add(5 * time.Minute),
	}
	fixture := gateFixture{Mode: mode, Template: template, Assignment: assignment, Request: request}
	if _, err := inspection.CompilePlan(fixture.Template, fixture.Assignment, fixture.Request); err != nil {
		return gateFixture{}, err
	}
	return fixture, nil
}

func syntheticGateTask(base time.Time) inspection.InstalledTaskBinding {
	return inspection.InstalledTaskBinding{
		TaskID: gateTaskID, TaskRevision: 1, BindingFingerprint: gateDigest("task-binding:" + gateTaskID),
		Sources: []inspection.InstalledTaskSourceBinding{{
			SourceHandle: gateTaskSource, SourceRevision: 1, SourceFingerprint: gateDigest("source:" + gateTaskSource),
		}},
		Capabilities: []inspection.InstalledTaskCapabilityBinding{{
			Ref: "existing-evidence", Revision: 1, Digest: gateDigest("capability:existing-evidence"),
			ResultSchema: "classification.v2", MediaKinds: []inspection.MediaKind{inspection.MediaEvent},
		}},
		ObservedAt: base.Add(-time.Minute),
	}
}

func gateVisualSource(kind inspection.SourceKind, handle, capability string, mediaKind inspection.MediaKind) inspection.SourceBinding {
	return inspection.SourceBinding{
		Kind: kind, SourceHandle: handle, SourceRevision: 1,
		SourceFingerprint: gateDigest("source:" + handle), CapabilityRefs: []string{capability},
		MediaKinds: []inspection.MediaKind{mediaKind},
	}
}

func gateDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func gateOpaqueRef(prefix string, values ...string) string {
	joined := prefix
	for _, value := range values {
		joined += "\x00" + value
	}
	return prefix + "_" + gateDigest(joined)[:32]
}

func cloneGateTask(task inspection.InstalledTaskBinding) inspection.InstalledTaskBinding {
	task.Sources = append([]inspection.InstalledTaskSourceBinding(nil), task.Sources...)
	task.Capabilities = append([]inspection.InstalledTaskCapabilityBinding(nil), task.Capabilities...)
	for index := range task.Capabilities {
		task.Capabilities[index].MediaKinds = append([]inspection.MediaKind(nil), task.Capabilities[index].MediaKinds...)
	}
	return task
}
