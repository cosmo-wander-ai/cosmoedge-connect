package inspectionlive

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const (
	snapshotCapability = "snapshot-current"
	criterionID        = "current-scene-attention"
	templateID         = "template-current-scene"
	assignmentID       = "assignment-current-scene"
	targetID           = "target-current-camera"
	zoneID             = "current-area"
	fullFrameROI       = "full-frame"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type catalogSynchronizer struct {
	mu        sync.Mutex
	snapshots SnapshotReader
	catalog   *catalog.Store
	runs      *inspectionstore.Store
	now       func() time.Time

	verifiedAt time.Time
}

func newCatalogSynchronizer(snapshots SnapshotReader, sources *catalog.Store, runs *inspectionstore.Store) *catalogSynchronizer {
	return &catalogSynchronizer{snapshots: snapshots, catalog: sources, runs: runs, now: time.Now}
}

func (s *catalogSynchronizer) Sync(ctx context.Context) error {
	if s == nil || s.snapshots == nil || s.catalog == nil || s.runs == nil {
		return errors.New("live inspection catalog synchronizer is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.snapshots.Read(ctx)
	if err != nil {
		if errors.Is(err, session.ErrNotConnected) {
			return ErrConnectionRequired
		}
		return err
	}
	if snapshot.Identity.Serial == "" || len(snapshot.Cameras) == 0 {
		return ErrCameraUnavailable
	}
	selected, ok := SelectCamera(snapshot)
	if !ok {
		return ErrCameraUnavailable
	}
	fingerprint := SourceFingerprint(snapshot, selected)
	capabilities := sourceCapabilities()
	current, err := s.catalog.Get(ctx, TenantID, SiteID, SourceHandle)
	switch {
	case errors.Is(err, catalog.ErrNotFound):
		current, err = s.catalog.Create(ctx, catalog.NewSource{
			TenantID: TenantID, SiteID: SiteID, DeviceProfileID: DeviceProfileID,
			Handle: SourceHandle, Kind: inspection.SourceCamera,
			IdentityFingerprint: fingerprint, NativeLocator: selected.ID,
			Alias: SourceAlias, ZoneID: zoneID, Capabilities: capabilities,
		})
	case err != nil:
		return err
	default:
		if current.IdentityFingerprint != fingerprint {
			drifted, updateErr := s.catalog.Update(ctx, catalog.UpdateSource{
				TenantID: TenantID, SiteID: SiteID, Handle: SourceHandle, ExpectedRevision: current.Revision,
				DeviceProfileID: DeviceProfileID, IdentityFingerprint: fingerprint,
				NativeLocator: selected.ID, Alias: SourceAlias, ZoneID: zoneID,
				State: catalog.StateActive, Capabilities: capabilities,
			})
			if !errors.Is(updateErr, catalog.ErrIdentityDrift) {
				return updateErr
			}
			current, err = s.catalog.Repin(ctx, catalog.UpdateSource{
				TenantID: TenantID, SiteID: SiteID, Handle: SourceHandle, ExpectedRevision: drifted.Revision,
				DeviceProfileID: DeviceProfileID, IdentityFingerprint: fingerprint,
				NativeLocator: selected.ID, Alias: SourceAlias, ZoneID: zoneID,
				State: catalog.StateActive, Capabilities: capabilities,
			})
		} else if sourceNeedsRefresh(current, selected, capabilities, s.now().UTC()) {
			current, err = s.catalog.Update(ctx, catalog.UpdateSource{
				TenantID: TenantID, SiteID: SiteID, Handle: SourceHandle, ExpectedRevision: current.Revision,
				DeviceProfileID: DeviceProfileID, IdentityFingerprint: fingerprint,
				NativeLocator: selected.ID, Alias: SourceAlias, ZoneID: zoneID,
				State: catalog.StateActive, Capabilities: capabilities,
			})
		}
	}
	if err != nil {
		return err
	}
	if err := seedPublishedSnapshotPlan(ctx, s.catalog, s.runs, current, s.now().UTC()); err != nil {
		return err
	}
	s.verifiedAt = s.now().UTC()
	return nil
}

// SourceFingerprint and SelectCamera preserve the legacy default selection.
func SourceFingerprint(snapshot device.Snapshot, camera device.Camera) string {
	return livevision.SourceFingerprint(snapshot, camera)
}
func SelectCamera(snapshot device.Snapshot) (device.Camera, bool) {
	return livevision.SelectCamera(snapshot)
}

func sourceCapabilities() []catalog.Capability {
	return []catalog.Capability{{
		Ref: snapshotCapability, Kind: catalog.CapabilitySnapshot, Revision: 1,
		Constraints: catalog.Constraints{
			MediaKinds: []inspection.MediaKind{inspection.MediaImage}, MaxBytes: 8 << 20,
			MaxFrames: 1, MaxFreshnessSeconds: 30,
		},
	}}
}

func sourceNeedsRefresh(current catalog.Source, camera device.Camera, capabilities []catalog.Capability, now time.Time) bool {
	normalized, err := catalog.NormalizeCapabilities(capabilities)
	return err != nil || current.DeviceProfileID != DeviceProfileID || current.NativeLocator != camera.ID ||
		current.Alias != SourceAlias || current.ZoneID != zoneID || current.State != catalog.StateActive ||
		!reflect.DeepEqual(current.Capabilities, normalized) || current.UpdatedAt.Before(now.Add(-4*time.Minute))
}

func seedPublishedSnapshotPlan(ctx context.Context, sources *catalog.Store, runs *inspectionstore.Store, source catalog.Source, now time.Time) error {
	binding, err := source.Binding([]string{snapshotCapability}, fullFrameROI)
	if err != nil {
		return err
	}
	template := inspection.InspectionTemplate{
		Schema: inspection.SchemaVersion, TenantID: TenantID, TemplateID: templateID, Revision: 1,
		Name: "通用现场巡检", BusinessPurpose: "根据当前现场画面给出辅助观察结论。",
		Criteria: []inspection.Criterion{{
			ID: criterionID, Name: ObservableName, Method: inspection.MethodVLM, Required: true,
			RuleRef: "current-scene-rule", RuleVersion: 1, MayAssertCompliance: true,
			Prompt: inspection.PromptContract{Template: "只观察这张现场图片。当前画面是否存在需要关注的明显情况？仅回答是或否。"},
			Output: inspection.OutputContract{
				Mode: inspection.ResultClassification, SchemaVersion: "classification.v2",
				AllowedAssessments: []inspection.Assessment{
					inspection.AssessmentMeetsRule, inspection.AssessmentNeedsAttention, inspection.AssessmentUncertain,
					inspection.AssessmentNotObservable,
				},
			},
		}},
		Strategies: []inspection.StrategyPolicy{{
			Strategy:               inspection.StrategySnapshotAnalysis,
			AllowedSourceKinds:     []inspection.SourceKind{inspection.SourceCamera},
			RequiredCapabilityRefs: []string{snapshotCapability}, MinimumSources: 1, MaximumSources: 1,
			Time:              inspection.TimePolicy{Mode: inspection.TimeCurrent, MaxAgeSeconds: 30},
			AnalysisPolicyRef: "current-scene-vlm", MaximumAcquisition: inspection.AcquisitionPolicy{Samples: 1},
		}},
		Budget: inspection.ResourceBudget{
			MaxTargets: 1, MaxSamplesPerTarget: 1, MaxAnalyses: 1,
			MaxDurationSeconds: 300, MaxMediaBytes: 8 << 20,
		},
		Evidence: inspection.EvidencePolicy{
			Required: true, RetentionSeconds: 3600, RedactionProfile: "live-default-redaction",
		},
		OutputSchemaVersion: "report.v2", State: inspection.TemplatePublished,
		CreatedBy: "inspectionlive", CreatedAt: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
	}
	if err := runs.SaveInspectionTemplate(ctx, template); err != nil {
		return err
	}
	fingerprint, err := sources.Fingerprint(ctx, TenantID, SiteID)
	if err != nil {
		return err
	}
	existing, err := runs.ListAssignments(ctx, TenantID, SiteID)
	if err != nil {
		return err
	}
	target := inspection.TargetBinding{
		TargetID: targetID, FriendlyName: SourceAlias, SourceBindings: []inspection.SourceBinding{binding},
		CriterionIDs: []string{criterionID}, Strategy: inspection.StrategySnapshotAnalysis,
		Acquisition: inspection.AcquisitionPolicy{Samples: 1},
	}
	revision := uint64(1)
	for _, item := range existing {
		if item.AssignmentID != assignmentID {
			continue
		}
		if item.SourceCatalogFingerprint == fingerprint && item.TemplateID == templateID && item.TemplateRevision == 1 &&
			item.Published && item.ZoneID == zoneID && reflect.DeepEqual(item.Targets, []inspection.TargetBinding{target}) {
			return nil
		}
		if item.Revision >= revision {
			revision = item.Revision + 1
		}
	}
	return runs.SaveAssignment(ctx, inspection.Assignment{
		Schema: inspection.SchemaVersion, TenantID: TenantID, AssignmentID: assignmentID, Revision: revision,
		TemplateID: templateID, TemplateRevision: 1, SiteID: SiteID, ZoneID: zoneID,
		SourceCatalogFingerprint: fingerprint, Published: true, Targets: []inspection.TargetBinding{target},
	}, now)
}
