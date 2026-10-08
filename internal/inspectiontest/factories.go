// Package inspectiontest provides deterministic, network-free fixtures for
// inspection control-path tests. Everything in this package is generated: it
// contains no customer media, credentials, device addresses, or write method.
package inspectiontest

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const (
	FixtureTenantID     = "tenant-fixture"
	FixtureSiteID       = "site-fixture"
	SceneTemplateID     = "scene-condition-template"
	SceneAssignmentID   = "scene-condition-assignment"
	BusinessCriterionID = "business-criterion"
	SceneTargetAlphaID  = "scene-alpha"
	SceneTargetBetaID   = "scene-beta"
	SceneConditionValue = "scene-condition"
)

var FixtureCatalogFingerprint = fixtureDigest("scene-source-catalog-v2")

// FixtureBaseTime is fixed so fixture digests and request windows remain stable.
var FixtureBaseTime = time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)

// PublishedSceneTemplate returns a fresh, valid template with one structured
// VLM business criterion and a bounded evidence policy.
func PublishedSceneTemplate() inspection.InspectionTemplate {
	return inspection.InspectionTemplate{
		Schema: inspection.SchemaVersion, TenantID: FixtureTenantID,
		TemplateID: SceneTemplateID, Revision: 1, Name: "Scene condition inspection",
		BusinessPurpose: "Evaluate a declared scene condition from bounded evidence without claiming complete site or regulatory compliance.",
		Criteria: []inspection.Criterion{{
			ID: BusinessCriterionID, Name: "Declared business criterion", Method: inspection.MethodVLM, Required: true,
			RuleRef: "fixture-business-criterion-v2", RuleVersion: 1, MayAssertCompliance: true,
			Prompt: inspection.PromptContract{
				Template: "Evaluate the {{scene}} source against the declared business criterion.",
				Variables: []inspection.PromptVariable{{
					Name: "scene", Required: true, MaxLength: 32,
					AllowedValues: []string{SceneConditionValue},
				}},
			},
			Output: inspection.OutputContract{
				Mode: inspection.ResultStructured, SchemaVersion: "finding.v2",
				AllowedAssessments: []inspection.Assessment{
					inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention,
					inspection.AssessmentUncertain, inspection.AssessmentNotObservable,
				},
			},
		}},
		Strategies: []inspection.StrategyPolicy{{
			Strategy:               inspection.StrategySnapshotAnalysis,
			AllowedSourceKinds:     []inspection.SourceKind{inspection.SourceCamera, inspection.SourceRetainedMedia},
			RequiredCapabilityRefs: []string{"fixture-read-capability"}, MinimumSources: 1, MaximumSources: 2,
			Time:               inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
			AnalysisPolicyRef:  "fixture-snapshot-vlm-v2",
			MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 3, IntervalMillis: 60_000},
		}},
		Budget: inspection.ResourceBudget{
			MaxTargets: 4, MaxSamplesPerTarget: 3, MaxAnalyses: 12,
			MaxDurationSeconds: 600, MaxMediaBytes: 10 << 20,
		},
		Evidence: inspection.EvidencePolicy{
			Required: true, RetentionSeconds: 3600, RedactionProfile: "fixture-redaction-v1",
		},
		OutputSchemaVersion: "report.v2", State: inspection.TemplatePublished,
		CreatedBy: "inspectiontest", CreatedAt: FixtureBaseTime.Add(-time.Hour),
	}
}

// PublishedSceneAssignment returns two friendly targets bound only to generated,
// opaque source handles. Target alpha deliberately freezes two sources so
// fixture execution exercises the collection contract rather than assuming a
// target always has one source.
func PublishedSceneAssignment() inspection.Assignment {
	return inspection.Assignment{
		Schema: inspection.SchemaVersion, TenantID: FixtureTenantID,
		AssignmentID: SceneAssignmentID, Revision: 1,
		TemplateID: SceneTemplateID, TemplateRevision: 1,
		SiteID: FixtureSiteID, ZoneID: "scene-zone", SourceCatalogFingerprint: FixtureCatalogFingerprint, Published: true,
		Targets: []inspection.TargetBinding{
			{
				TargetID: SceneTargetBetaID, FriendlyName: "Scene beta",
				SourceBindings: fixtureSourceBindings(SceneTargetBetaID),
				CriterionIDs:   []string{BusinessCriterionID}, Strategy: inspection.StrategySnapshotAnalysis,
				Acquisition: inspection.AcquisitionPolicy{Samples: 1},
			},
			{
				TargetID: SceneTargetAlphaID, FriendlyName: "Scene alpha",
				SourceBindings: fixtureSourceBindings(SceneTargetAlphaID),
				CriterionIDs:   []string{BusinessCriterionID}, Strategy: inspection.StrategySnapshotAnalysis,
				Acquisition: inspection.AcquisitionPolicy{Samples: 1},
			},
		},
	}
}

func fixtureSourceBindings(targetID string) []inspection.SourceBinding {
	switch targetID {
	case SceneTargetAlphaID:
		return []inspection.SourceBinding{
			fixtureSourceBinding(inspection.SourceCamera, "source-alpha", "roi-alpha", "fixture-read-capability"),
			fixtureSourceBinding(inspection.SourceRetainedMedia, "context-alpha", "", "fixture-context-read-capability"),
		}
	case SceneTargetBetaID:
		return []inspection.SourceBinding{
			fixtureSourceBinding(inspection.SourceCamera, "source-beta", "roi-beta", "fixture-read-capability"),
		}
	default:
		return nil
	}
}

func fixtureSourceBinding(kind inspection.SourceKind, handle, roiRef string, capabilityRefs ...string) inspection.SourceBinding {
	return inspection.SourceBinding{
		Kind: kind, SourceHandle: handle, SourceRevision: 1,
		SourceFingerprint: fixtureDigest("source:" + handle),
		CapabilityRefs:    append([]string(nil), capabilityRefs...),
		MediaKinds:        fixtureMediaKinds(kind),
		ROIRef:            roiRef,
	}
}

func fixtureMediaKinds(kind inspection.SourceKind) []inspection.MediaKind {
	switch kind {
	case inspection.SourceUploadedVideo:
		return []inspection.MediaKind{inspection.MediaVideoClip}
	case inspection.SourceTaskEvidence:
		return []inspection.MediaKind{inspection.MediaMetric}
	default:
		return []inspection.MediaKind{inspection.MediaImage}
	}
}

func fixtureDigest(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

// SceneRunRequest returns a stable request that selects all published targets.
func SceneRunRequest() inspection.CreateRunRequest {
	return inspection.CreateRunRequest{
		Schema: inspection.SchemaVersion, TenantID: FixtureTenantID, SiteID: FixtureSiteID,
		TemplateID: SceneTemplateID, TemplateRevision: 1,
		AssignmentID: SceneAssignmentID, AssignmentRevision: 1,
		Origin: inspection.OriginUser, RequestID: "fixture-request-1",
		Variables:   map[string]string{"scene": SceneConditionValue},
		RequestedAt: FixtureBaseTime, Deadline: FixtureBaseTime.Add(5 * time.Minute),
	}
}

// SceneExecutionPlan compiles a fresh deterministic plan from the published
// fixtures. Callers receive independent slices and maps on every call.
func SceneExecutionPlan() (inspection.ExecutionPlan, error) {
	return inspection.CompilePlan(PublishedSceneTemplate(), PublishedSceneAssignment(), SceneRunRequest())
}
