package inspectionfixture

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
)

const (
	fixtureProfileID   = "profile-offline-fixture"
	fixtureSourceID    = "source-public-area"
	fixtureTaskID      = "task-scene-state"
	fixtureCriterionID = "scene-state"
	fixtureZoneID      = "public-area"
	fixtureROI         = "full-frame"

	capabilitySnapshot = "snapshot-read"
	capabilityClip     = "clip-read"
	capabilityTask     = "task-evidence"
)

var fixtureTemplateTime = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

type seededCatalog struct {
	source      catalog.Source
	task        catalog.DeviceTaskBinding
	installed   inspection.InstalledTaskBinding
	fingerprint string
}

func seedCatalog(ctx context.Context, config Config, fixtureAssets assets, sources *catalog.Store, runs *inspectionstore.Store) (seededCatalog, error) {
	if sources == nil || runs == nil || fixtureAssets.validate() != nil {
		return seededCatalog{}, errors.New("fixture catalog and run stores are required")
	}
	sourceCapabilities := []catalog.Capability{
		{Ref: capabilityClip, Kind: catalog.CapabilityClip, Revision: 1, Constraints: catalog.Constraints{
			MediaKinds: []inspection.MediaKind{inspection.MediaVideoClip}, MaxBytes: 8 << 20,
			MaxFrames: 1, MaxDurationSeconds: 60, MaxFreshnessSeconds: 120,
		}},
		{Ref: capabilitySnapshot, Kind: catalog.CapabilitySnapshot, Revision: 1, Constraints: catalog.Constraints{
			MediaKinds: []inspection.MediaKind{inspection.MediaImage}, MaxBytes: 2 << 20,
			MaxFrames: 1, MaxFreshnessSeconds: 30,
		}},
		{Ref: capabilityTask, Kind: catalog.CapabilityTaskEvidence, Revision: 1, ResultSchema: "classification.v2", Constraints: catalog.Constraints{
			MediaKinds: []inspection.MediaKind{inspection.MediaEvent}, MaxBytes: 64 << 10, MaxFreshnessSeconds: 120,
		}},
	}
	normalizedSourceCapabilities, err := catalog.NormalizeCapabilities(sourceCapabilities)
	if err != nil {
		return seededCatalog{}, err
	}
	source, err := sources.Get(ctx, config.TenantID, config.SiteID, fixtureSourceID)
	if errors.Is(err, catalog.ErrNotFound) {
		source, err = sources.Create(ctx, catalog.NewSource{
			TenantID: config.TenantID, SiteID: config.SiteID, DeviceProfileID: fixtureProfileID,
			Handle: fixtureSourceID, Kind: inspection.SourceCamera,
			IdentityFingerprint: digest("offline-fixture-source-identity"), NativeLocator: "fixture-native-source",
			Alias: SourceAlias, ZoneID: fixtureZoneID, Capabilities: sourceCapabilities,
		})
	}
	if err != nil {
		return seededCatalog{}, err
	}
	if source.DeviceProfileID != fixtureProfileID || source.Kind != inspection.SourceCamera ||
		source.IdentityFingerprint != digest("offline-fixture-source-identity") || source.NativeLocator != "fixture-native-source" ||
		source.Alias != SourceAlias || source.ZoneID != fixtureZoneID || !reflect.DeepEqual(source.Capabilities, normalizedSourceCapabilities) ||
		source.State != catalog.StateActive {
		return seededCatalog{}, errors.New("stored fixture source conflicts with the direct fixture catalog")
	}

	taskCapabilities := []catalog.Capability{{
		Ref: capabilityTask, Kind: catalog.CapabilityTaskEvidence, Revision: 1, ResultSchema: "classification.v2",
		Constraints: catalog.Constraints{MediaKinds: []inspection.MediaKind{inspection.MediaEvent}, MaxBytes: 64 << 10, MaxFreshnessSeconds: 120},
	}}
	normalizedTaskCapabilities, err := catalog.NormalizeTaskCapabilities(taskCapabilities)
	if err != nil {
		return seededCatalog{}, err
	}
	task, err := sources.GetTask(ctx, config.TenantID, config.SiteID, fixtureTaskID)
	if errors.Is(err, catalog.ErrTaskNotFound) {
		task, err = sources.CreateTask(ctx, catalog.NewDeviceTaskBinding{
			TenantID: config.TenantID, SiteID: config.SiteID, DeviceProfileID: fixtureProfileID,
			TaskHandle: fixtureTaskID, IdentityFingerprint: digest("offline-fixture-task-identity"),
			NativeLocator: "fixture-native-task", Alias: TaskAlias, SourceHandles: []string{fixtureSourceID},
			Capabilities: taskCapabilities, ObservedAt: time.Now().UTC().Add(-time.Second),
		})
	}
	if err != nil {
		return seededCatalog{}, err
	}
	if task.DeviceProfileID != fixtureProfileID || task.IdentityFingerprint != digest("offline-fixture-task-identity") ||
		task.NativeLocator != "fixture-native-task" || task.Alias != TaskAlias ||
		!reflect.DeepEqual(task.SourceHandles, []string{fixtureSourceID}) || !reflect.DeepEqual(task.Capabilities, normalizedTaskCapabilities) ||
		task.State != catalog.StateActive {
		return seededCatalog{}, errors.New("stored fixture task conflicts with the direct fixture catalog")
	}

	// Catalog facts are intentionally short-lived. Refresh the fixture facts
	// before half of the maximum planning lifetime elapses, then publish one new
	// assignment revision bound to the new catalog fingerprint. Historical runs
	// keep their immutable older revisions.
	now := time.Now().UTC()
	if source.UpdatedAt.Before(now.Add(-12*time.Hour)) || task.ObservedAt.Before(now.Add(-12*time.Hour)) {
		source, err = sources.Update(ctx, catalog.UpdateSource{
			TenantID: source.TenantID, SiteID: source.SiteID, Handle: source.Handle, ExpectedRevision: source.Revision,
			DeviceProfileID: source.DeviceProfileID, IdentityFingerprint: source.IdentityFingerprint,
			NativeLocator: source.NativeLocator, Alias: source.Alias, ZoneID: source.ZoneID,
			State: catalog.StateActive, Capabilities: sourceCapabilities,
		})
		if err != nil {
			return seededCatalog{}, err
		}
		task, err = sources.RefreshTask(ctx, catalog.RefreshDeviceTaskBinding{
			TenantID: task.TenantID, SiteID: task.SiteID, TaskHandle: task.TaskHandle,
			ExpectedRevision: task.Revision, DeviceProfileID: task.DeviceProfileID,
			IdentityFingerprint: task.IdentityFingerprint, NativeLocator: task.NativeLocator,
			Alias: task.Alias, SourceHandles: task.SourceHandles, Capabilities: taskCapabilities,
			State: catalog.StateActive, ObservedAt: time.Now().UTC(),
		})
		if err != nil {
			return seededCatalog{}, err
		}
	}

	installed, err := sources.FreezeInstalledTask(ctx, config.TenantID, config.SiteID, fixtureTaskID, []string{capabilityTask})
	if err != nil {
		return seededCatalog{}, err
	}
	fingerprint, err := sources.Fingerprint(ctx, config.TenantID, config.SiteID)
	if err != nil {
		return seededCatalog{}, err
	}
	seeded := seededCatalog{source: source, task: task, installed: installed, fingerprint: fingerprint}
	if err := seedPublishedPlans(ctx, config, fixtureAssets, runs, seeded); err != nil {
		return seededCatalog{}, err
	}
	return seeded, nil
}

type routePlan struct {
	name        string
	method      inspection.Method
	strategy    inspection.StrategyPolicy
	acquisition inspection.AcquisitionPolicy
	sources     []inspection.SourceBinding
	tasks       []inspection.InstalledTaskBinding
}

func routePlans(seed seededCatalog, fixtureAssets assets) ([]routePlan, error) {
	snapshot, err := seed.source.Binding([]string{capabilitySnapshot}, fixtureROI)
	if err != nil {
		return nil, err
	}
	clip, err := seed.source.Binding([]string{capabilityClip}, fixtureROI)
	if err != nil {
		return nil, err
	}
	taskSource := seed.installed.TaskEvidenceSourceBindings()[0]
	return []routePlan{
		{
			name: "existing", method: inspection.MethodEvent,
			strategy: inspection.StrategyPolicy{
				Strategy: inspection.StrategyExistingTaskRead, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceTaskEvidence},
				RequiredCapabilityRefs: []string{capabilityTask}, MinimumSources: 1, MaximumSources: 1,
				Time:               inspection.TimePolicy{Mode: inspection.TimeRecentWindow, WindowSeconds: 60, MaxAgeSeconds: 120},
				MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1},
			},
			acquisition: inspection.AcquisitionPolicy{Samples: 1}, sources: []inspection.SourceBinding{taskSource},
			tasks: []inspection.InstalledTaskBinding{seed.installed},
		},
		{
			name: "snapshot", method: inspection.MethodVLM,
			strategy: inspection.StrategyPolicy{
				Strategy: inspection.StrategySnapshotAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera},
				RequiredCapabilityRefs: []string{capabilitySnapshot}, MinimumSources: 1, MaximumSources: 1,
				Time:              inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
				AnalysisPolicyRef: "offline-visual-policy", MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1},
			},
			acquisition: inspection.AcquisitionPolicy{Samples: 1}, sources: []inspection.SourceBinding{snapshot},
		},
		{
			name: "clip", method: inspection.MethodVLM,
			strategy: inspection.StrategyPolicy{
				Strategy: inspection.StrategyClipAnalysis, AllowedSourceKinds: []inspection.SourceKind{inspection.SourceCamera},
				RequiredCapabilityRefs: []string{capabilityClip}, MinimumSources: 1, MaximumSources: 1,
				Time:               inspection.TimePolicy{Mode: inspection.TimeRecentWindow, WindowSeconds: int(fixtureAssets.clipDuration / 1000), MaxAgeSeconds: 120},
				AnalysisPolicyRef:  "offline-clip-policy",
				MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1, ClipDurationMillis: int(fixtureAssets.clipDuration), MaxExtractedFrames: 1},
			},
			acquisition: inspection.AcquisitionPolicy{Samples: 1, ClipDurationMillis: int(fixtureAssets.clipDuration), MaxExtractedFrames: 1},
			sources:     []inspection.SourceBinding{clip},
		},
		{
			name: "hybrid", method: inspection.MethodHybrid,
			strategy: inspection.StrategyPolicy{
				Strategy:               inspection.StrategyHybridAnalysis,
				AllowedSourceKinds:     []inspection.SourceKind{inspection.SourceCamera, inspection.SourceTaskEvidence},
				RequiredCapabilityRefs: []string{capabilitySnapshot, capabilityTask}, MinimumSources: 2, MaximumSources: 2,
				Time:              inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
				AnalysisPolicyRef: "offline-hybrid-policy", MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1},
			},
			acquisition: inspection.AcquisitionPolicy{Samples: 1}, sources: []inspection.SourceBinding{snapshot, taskSource},
			tasks: []inspection.InstalledTaskBinding{seed.installed},
		},
	}, nil
}

func seedPublishedPlans(ctx context.Context, config Config, fixtureAssets assets, runs *inspectionstore.Store, seed seededCatalog) error {
	plans, err := routePlans(seed, fixtureAssets)
	if err != nil {
		return err
	}
	existing, err := runs.ListAssignments(ctx, config.TenantID, config.SiteID)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		prompt := inspection.PromptContract{}
		if plan.method == inspection.MethodVLM || plan.method == inspection.MethodHybrid {
			prompt = inspection.PromptContract{Template: "仅根据已提供的类型化现场依据判断当前可见的现场状态。"}
		}
		template := inspection.InspectionTemplate{
			Schema: inspection.SchemaVersion, TenantID: config.TenantID,
			TemplateID: "offline-template-" + plan.name, Revision: 1,
			Name: "通用现场巡检", BusinessPurpose: "根据限定范围内的现场依据给出辅助观察结论。",
			Criteria: []inspection.Criterion{{
				ID: fixtureCriterionID, Name: ObservableName, Method: plan.method, Required: true,
				RuleRef: "offline-scene-rule", RuleVersion: 1, Prompt: prompt,
				Output: inspection.OutputContract{
					Mode: inspection.ResultClassification, SchemaVersion: "classification.v2",
					AllowedAssessments: []inspection.Assessment{
						inspection.AssessmentNeedsAttention, inspection.AssessmentUncertain, inspection.AssessmentNotObservable,
					},
				},
			}},
			Strategies: []inspection.StrategyPolicy{plan.strategy},
			Budget: inspection.ResourceBudget{
				MaxTargets: 1, MaxSamplesPerTarget: 3, MaxAnalyses: 1,
				MaxDurationSeconds: 300, MaxMediaBytes: 16 << 20,
			},
			Evidence:            inspection.EvidencePolicy{Required: true, RetentionSeconds: 3600, RedactionProfile: "offline-default-redaction"},
			OutputSchemaVersion: "report.v2", State: inspection.TemplatePublished,
			CreatedBy: "inspectionfixture", CreatedAt: fixtureTemplateTime,
		}
		if err := runs.SaveInspectionTemplate(ctx, template); err != nil {
			return err
		}
		assignmentID := "offline-assignment-" + plan.name
		revision := uint64(1)
		alreadyCurrent := false
		for _, item := range existing {
			if item.AssignmentID != assignmentID {
				continue
			}
			if item.Revision >= revision {
				revision = item.Revision + 1
			}
			if item.SourceCatalogFingerprint == seed.fingerprint && item.TemplateID == template.TemplateID &&
				item.TemplateRevision == template.Revision && item.Published && len(item.Targets) == 1 &&
				reflect.DeepEqual(item.Targets[0].SourceBindings, plan.sources) &&
				reflect.DeepEqual(item.Targets[0].InstalledTasks, plan.tasks) && item.Targets[0].Strategy == plan.strategy.Strategy {
				alreadyCurrent = true
			}
		}
		if alreadyCurrent {
			continue
		}
		assignment := inspection.Assignment{
			Schema: inspection.SchemaVersion, TenantID: config.TenantID, AssignmentID: assignmentID, Revision: revision,
			TemplateID: template.TemplateID, TemplateRevision: template.Revision,
			SiteID: config.SiteID, ZoneID: fixtureZoneID, SourceCatalogFingerprint: seed.fingerprint, Published: true,
			Targets: []inspection.TargetBinding{{
				TargetID: "offline-target-" + plan.name, FriendlyName: SourceAlias,
				SourceBindings: plan.sources, InstalledTasks: plan.tasks,
				CriterionIDs: []string{fixtureCriterionID}, Strategy: plan.strategy.Strategy, Acquisition: plan.acquisition,
			}},
		}
		if err := runs.SaveAssignment(ctx, assignment, time.Now().UTC()); err != nil {
			return err
		}
	}
	return nil
}
