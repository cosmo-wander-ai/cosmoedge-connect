package inspectiontest

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	inspectionauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	inspectionruntime "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/runtime"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
)

type gateHarness struct {
	t          *testing.T
	fixture    gateFixture
	root       string
	database   string
	mediaRoot  string
	repository *inspectionstore.Store
	media      *media.Store
	clock      *MonotonicClock
	ports      *gatePorts
	manager    *inspectionruntime.Manager
	broker     *inspectionauthority.EphemeralBroker
	lease      time.Duration
}

func newGateHarness(t *testing.T, fixture gateFixture, lease time.Duration) *gateHarness {
	t.Helper()
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	clock, err := NewMonotonicClock(fixture.Request.RequestedAt.Add(time.Second), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	harness := &gateHarness{
		t: t, fixture: fixture, root: root,
		database: filepath.Join(root, "inspection.db"), mediaRoot: filepath.Join(root, "media"),
		clock: clock, lease: lease,
	}
	harness.open()
	t.Cleanup(func() {
		_ = harness.repository.Close()
		if harness.broker != nil {
			harness.broker.Close()
		}
	})
	return harness
}

func (h *gateHarness) open() {
	h.t.Helper()
	repository, err := inspectionstore.Open(h.database)
	if err != nil {
		h.t.Fatal(err)
	}
	mediaStore, err := media.New(media.Config{
		Root: h.mediaRoot, MaxObjectBytes: 2 << 20, MaxTotalBytes: 32 << 20,
		MaxDescriptors: 256, DefaultTTL: time.Hour, MaximumTTL: time.Hour, Now: h.clock.Now,
	})
	if err != nil {
		_ = repository.Close()
		h.t.Fatal(err)
	}
	ports := newGatePorts(h.fixture, mediaStore, h.clock.Now)
	if err := ports.seedUploaded(context.Background()); err != nil {
		_ = repository.Close()
		h.t.Fatal(err)
	}
	if h.broker == nil {
		broker, err := inspectionauthority.NewEphemeralBroker(
			"gate-runtime-broker", []byte(strings.Repeat("k", 32)), 5*time.Minute, h.clock.Now,
		)
		if err != nil {
			_ = repository.Close()
			h.t.Fatal(err)
		}
		h.broker = broker
	}
	options := []inspectionruntime.Option{
		inspectionruntime.WithClock(h.clock.Now),
		inspectionruntime.WithRuntimeID("gate-runtime-v2"),
	}
	if h.lease != 0 {
		options = append(options, inspectionruntime.WithLease(h.lease))
	}
	manager, err := inspectionruntime.New(repository, h.broker, ports.Ports(), options...)
	if err != nil {
		_ = repository.Close()
		h.t.Fatal(err)
	}
	h.repository, h.media, h.ports, h.manager = repository, mediaStore, ports, manager
}

func (h *gateHarness) reopen() {
	h.t.Helper()
	if err := h.repository.Close(); err != nil {
		h.t.Fatal(err)
	}
	h.broker.Close()
	h.broker = nil
	h.open()
}

func (h *gateHarness) submitAndProcess() inspection.Run {
	h.t.Helper()
	run, created, err := h.manager.Submit(context.Background(), h.fixture.Template, h.fixture.Assignment, gateSubmission(h.t, h.fixture.Request))
	if err != nil || !created {
		h.t.Fatalf("Submit()=(%+v,%v,%v)", run, created, err)
	}
	processed, err := h.manager.ProcessOne(context.Background())
	if err != nil || !processed {
		h.t.Fatalf("ProcessOne()=(%v,%v)", processed, err)
	}
	stored, err := h.repository.GetRun(context.Background(), run.RunID)
	if err != nil {
		h.t.Fatal(err)
	}
	return stored
}

type snapshotGateContract struct {
	Kind             media.Kind
	Encoding         media.Encoding
	ContentSHA256    string
	Method           inspection.Method
	AnalysisPolicy   string
	Prompt           string
	PromptSHA256     string
	Output           inspection.OutputContract
	InputHasEvidence bool
}

func TestV212DeviceIndependentFourStrategyGate(t *testing.T) {
	base := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Millisecond)
	snapshotContracts := make(map[gateMode]snapshotGateContract)
	for _, mode := range []gateMode{gateExisting, gateSnapshot, gateUploadedImage, gateClip, gateHybrid} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			fixture, err := newGateFixture(base, mode, "gate-four-strategy-"+string(mode), nil)
			if err != nil {
				t.Fatal(err)
			}
			assertGenericGateFixture(t, fixture)
			plan, err := inspection.CompilePlan(fixture.Template, fixture.Assignment, fixture.Request)
			if err != nil {
				t.Fatal(err)
			}
			assertTypedOutputSlots(t, plan)
			harness := newGateHarness(t, fixture, 0)
			run := harness.submitAndProcess()
			if run.State != inspection.RunCompleted || run.PersistentConfigWrites != 0 || run.CleanupPending != 0 {
				steps, _ := harness.repository.ListSteps(context.Background(), run.RunID)
				t.Fatalf("run=%+v steps=%+v ports=%+v", run, steps, harness.ports.Stats())
			}
			stats := harness.ports.Stats()
			if stats.ResolveCalls != 1 || stats.CleanupCalls != 1 {
				t.Fatalf("common gate calls=%+v", stats)
			}
			switch mode {
			case gateExisting:
				if stats.ExistingCalls != 1 || stats.AcquireCalls != 0 || stats.TransformCalls != 0 || stats.AnalyzeCalls != 0 {
					t.Fatalf("existing-task read crossed acquisition/analysis boundary: %+v", stats)
				}
			case gateSnapshot, gateUploadedImage:
				if stats.ExistingCalls != 0 || stats.AcquireCalls != 1 || stats.TransformCalls != 0 || stats.AnalyzeCalls != 1 ||
					len(stats.AnalysisRequests) != 1 || len(stats.AnalysisRequests[0].Inputs) != 1 {
					t.Fatalf("snapshot gate calls=%+v", stats)
				}
				request := stats.AnalysisRequests[0]
				input := request.Inputs[0]
				if input.Descriptor == nil {
					t.Fatal("snapshot analyzer has no typed descriptor")
				}
				if mode == gateSnapshot && input.Descriptor.RuntimeLease.SourceMediaRef != "" {
					t.Fatalf("new snapshot unexpectedly used a pre-existing media lease: %+v", input.Descriptor.RuntimeLease)
				}
				if mode == gateUploadedImage {
					assertRunLease(t, harness, run.RunID, *input.Descriptor)
				}
				snapshotContracts[mode] = snapshotGateContract{
					Kind: input.Descriptor.Kind, Encoding: input.Descriptor.Encoding,
					ContentSHA256: input.Descriptor.Integrity.SHA256,
					Method:        request.Method, AnalysisPolicy: request.AnalysisPolicyRef,
					Prompt: request.Prompt, PromptSHA256: request.PromptSHA256, Output: request.Output,
					InputHasEvidence: input.Evidence != nil,
				}
				expectedOperation := inspection.StepAcquireMedia
				if mode == gateUploadedImage {
					expectedOperation = inspection.StepOpenMedia
				}
				if !reflect.DeepEqual(stats.AcquisitionOperations, []inspection.StepKind{expectedOperation}) {
					t.Fatalf("snapshot operation=%v want=%v", stats.AcquisitionOperations, expectedOperation)
				}
			case gateClip:
				assertClipGate(t, harness, stats)
			case gateHybrid:
				assertHybridGate(t, stats)
			}
		})
	}
	if !reflect.DeepEqual(snapshotContracts[gateSnapshot], snapshotContracts[gateUploadedImage]) {
		t.Fatalf("uploaded image and synthetic snapshot diverged at media/VLM contract: camera=%+v upload=%+v",
			snapshotContracts[gateSnapshot], snapshotContracts[gateUploadedImage])
	}
}

func assertTypedOutputSlots(t *testing.T, plan inspection.ExecutionPlan) {
	t.Helper()
	allowed := map[inspection.StepValueKind]struct{}{
		inspection.StepValueResolvedSources: {}, inspection.StepValueExistingEvidence: {},
		inspection.StepValueMedia: {}, inspection.StepValueAnalysis: {}, inspection.StepValueResult: {},
		inspection.StepValueOutcome: {}, inspection.StepValueCleanup: {},
	}
	for _, step := range plan.Steps {
		if len(step.OutputSlots) == 0 {
			t.Fatalf("step %s has no declared output slot", step.StepID)
		}
		for _, slot := range step.OutputSlots {
			if slot.LogicalRef == "" {
				t.Fatalf("step %s has an empty output reference", step.StepID)
			}
			if _, ok := allowed[slot.Kind]; !ok {
				t.Fatalf("step %s output %s has untyped kind %q", step.StepID, slot.LogicalRef, slot.Kind)
			}
		}
	}
}

func TestV212RuntimeStateGate(t *testing.T) {
	base := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Millisecond)

	t.Run("repeated request", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateSnapshot, "gate-duplicate", nil)
		harness := newGateHarness(t, fixture, 0)
		first, created, err := harness.manager.Submit(context.Background(), fixture.Template, fixture.Assignment, gateSubmission(t, fixture.Request))
		if err != nil || !created {
			t.Fatalf("first Submit()=(%+v,%v,%v)", first, created, err)
		}
		second, created, err := harness.manager.Submit(context.Background(), fixture.Template, fixture.Assignment, gateSubmission(t, fixture.Request))
		if err != nil || created || second.RunID != first.RunID {
			t.Fatalf("duplicate Submit()=(%+v,%v,%v), first=%+v", second, created, err, first)
		}
		if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || !processed {
			t.Fatalf("ProcessOne()=(%v,%v)", processed, err)
		}
		stored, _ := harness.repository.GetRun(context.Background(), first.RunID)
		if stored.State != inspection.RunCompleted {
			t.Fatalf("duplicate request run=%+v", stored)
		}
	})

	t.Run("queued expiry", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateSnapshot, "gate-expired", nil)
		harness := newGateHarness(t, fixture, 0)
		run, _, err := harness.manager.Submit(context.Background(), fixture.Template, fixture.Assignment, gateSubmission(t, fixture.Request))
		if err != nil {
			t.Fatal(err)
		}
		if err := harness.clock.Advance(6 * time.Minute); err != nil {
			t.Fatal(err)
		}
		if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || processed {
			t.Fatalf("expired ProcessOne()=(%v,%v)", processed, err)
		}
		stored, _ := harness.repository.GetRun(context.Background(), run.RunID)
		if stored.State != inspection.RunExpired || stored.Reason != "queue_deadline_exceeded" {
			t.Fatalf("expired run=%+v", stored)
		}
	})

	t.Run("stale installed-task catalog", func(t *testing.T) {
		catalogStore, frozen := staleGateCatalog(t, base)
		fixture := mustGateFixture(t, base, gateExisting, "gate-stale-catalog", &frozen)
		harness := newGateHarness(t, fixture, 0)
		harness.ports.catalog = catalogStore
		run := harness.submitAndProcess()
		if run.State != inspection.RunBlocked || run.Reason != "execution_binding_stale" {
			t.Fatalf("stale catalog run=%+v", run)
		}
		stats := harness.ports.Stats()
		if stats.ExistingCalls != 0 || stats.AcquireCalls != 0 || stats.AnalyzeCalls != 0 || stats.CleanupCalls != 1 {
			t.Fatalf("stale catalog crossed execution boundary: %+v", stats)
		}
	})

	t.Run("invalid model identity", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateSnapshot, "gate-invalid-model", nil)
		harness := newGateHarness(t, fixture, 0)
		harness.ports.invalidModel = true
		run := harness.submitAndProcess()
		if run.State != inspection.RunUnknown || run.Reason != "execution_step_failed" {
			t.Fatalf("invalid model run=%+v", run)
		}
	})

	t.Run("existing evidence kind outside frozen source binding", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateExisting, "gate-wrong-existing-kind", nil)
		harness := newGateHarness(t, fixture, 0)
		harness.ports.wrongExistingMediaKind = true
		run := harness.submitAndProcess()
		if run.State != inspection.RunUnknown || run.Reason != "execution_step_failed" {
			t.Fatalf("wrong-kind evidence run=%+v", run)
		}
		stats := harness.ports.Stats()
		if stats.ExistingCalls != 1 || stats.AnalyzeCalls != 0 {
			t.Fatalf("wrong-kind evidence crossed the frozen media-kind boundary: %+v", stats)
		}
	})

	t.Run("hybrid evidence substitution after analysis", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateHybrid, "gate-hybrid-evidence-substitution", nil)
		harness := newGateHarness(t, fixture, 0)
		harness.ports.swapEvidenceAfterAnalysis = true
		run := harness.submitAndProcess()
		if run.State != inspection.RunUnknown || run.Reason != "execution_step_failed" {
			t.Fatalf("substituted hybrid evidence run=%+v", run)
		}
		stats := harness.ports.Stats()
		if stats.ExistingCalls != 1 || stats.AnalyzeCalls != 1 {
			t.Fatalf("hybrid substitution did not reach the post-analysis validation boundary: %+v", stats)
		}
	})

	t.Run("cleanup failure", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateSnapshot, "gate-cleanup-failure", nil)
		harness := newGateHarness(t, fixture, 0)
		harness.ports.cleanupFailure = true
		run := harness.submitAndProcess()
		if run.State != inspection.RunUnknown || run.Reason != "cleanup_failed" || run.PersistentConfigWrites != 0 {
			t.Fatalf("cleanup failure run=%+v", run)
		}
	})

	t.Run("queued restart", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateSnapshot, "gate-queued-restart", nil)
		harness := newGateHarness(t, fixture, 0)
		run, _, err := harness.manager.Submit(context.Background(), fixture.Template, fixture.Assignment, gateSubmission(t, fixture.Request))
		if err != nil {
			t.Fatal(err)
		}
		harness.reopen()
		replayed, created, err := harness.manager.Submit(context.Background(), fixture.Template, fixture.Assignment, gateSubmission(t, fixture.Request))
		if err != nil || created || replayed.RunID != run.RunID {
			t.Fatalf("restart admission replay=(%+v,%v,%v), first=%+v", replayed, created, err, run)
		}
		if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || !processed {
			t.Fatalf("restarted ProcessOne()=(%v,%v)", processed, err)
		}
		stored, _ := harness.repository.GetRun(context.Background(), run.RunID)
		if stored.State != inspection.RunCompleted || stored.PersistentConfigWrites != 0 || stored.CleanupPending != 0 {
			t.Fatalf("queued restart run=%+v", stored)
		}
	})

	t.Run("interrupted acquisition restart", func(t *testing.T) {
		fixture := mustGateFixture(t, base, gateSnapshot, "gate-interrupted-restart", nil)
		harness := newGateHarness(t, fixture, 40*time.Millisecond)
		harness.ports.blockAcquire = true
		harness.ports.acquireEntered = make(chan struct{})
		run, _, err := harness.manager.Submit(context.Background(), fixture.Template, fixture.Assignment, gateSubmission(t, fixture.Request))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		type processResult struct {
			processed bool
			err       error
		}
		done := make(chan processResult, 1)
		go func() {
			processed, processErr := harness.manager.ProcessOne(ctx)
			done <- processResult{processed: processed, err: processErr}
		}()
		select {
		case <-harness.ports.acquireEntered:
		case <-time.After(time.Second):
			t.Fatal("acquisition port was not entered")
		}
		cancel()
		select {
		case result := <-done:
			if !result.processed || !errors.Is(result.err, context.Canceled) {
				t.Fatalf("cancelled ProcessOne()=(%v,%v)", result.processed, result.err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancelled ProcessOne did not return")
		}
		steps, err := harness.repository.ListSteps(context.Background(), run.RunID)
		if err != nil {
			t.Fatal(err)
		}
		running := 0
		for _, step := range steps {
			if step.State == inspection.StepRunning {
				running++
			}
		}
		if running != 1 {
			t.Fatalf("interrupted step was flattened: %+v", steps)
		}
		if err := harness.clock.Advance(time.Minute); err != nil {
			t.Fatal(err)
		}
		harness.reopen()
		if processed, err := harness.manager.ProcessOne(context.Background()); err != nil || processed {
			t.Fatalf("recovery ProcessOne()=(%v,%v)", processed, err)
		}
		stored, _ := harness.repository.GetRun(context.Background(), run.RunID)
		if stored.State != inspection.RunReconciliationRequired {
			t.Fatalf("interrupted side effect was replayed after restart: %+v", stored)
		}
	})
}

func assertClipGate(t *testing.T, harness *gateHarness, stats gatePortStats) {
	t.Helper()
	if stats.ExistingCalls != 0 || stats.AcquireCalls != 1 || stats.TransformCalls != 1 || stats.AnalyzeCalls != 1 ||
		len(stats.TransformResults) != 1 || len(stats.AnalysisRequests) != 1 {
		t.Fatalf("clip gate calls=%+v", stats)
	}
	frameSet := stats.TransformResults[0]
	if frameSet.Kind != media.KindFrameSet || frameSet.Lineage.ParentMediaRef == "" ||
		frameSet.Lineage.TransformPolicyRef != "bounded-frames-v2" || len(frameSet.FrameMembers) != 3 {
		t.Fatalf("frame set=%+v", frameSet)
	}
	parent, err := harness.media.Describe(frameSet.Lineage.ParentMediaRef)
	if err != nil || parent.Kind != media.KindVideoClip || parent.Temporal.DurationMillis != 1500 {
		t.Fatalf("clip parent=%+v err=%v", parent, err)
	}
	assertRunLease(t, harness, frameSet.Binding.RunID, parent)
	for index, member := range frameSet.FrameMembers {
		if member.Ordinal != index || member.OffsetMillis != int64(index*500) ||
			member.TransformPolicyRef != "bounded-frames-v2" || member.SHA256 == "" {
			t.Fatalf("frame member[%d]=%+v", index, member)
		}
		child, err := harness.media.Describe(member.MediaRef)
		if err != nil || child.Kind != media.KindImage || child.Integrity.SHA256 != member.SHA256 ||
			child.Lineage.ParentMediaRef != frameSet.MediaRef || child.Lineage.Ordinal != index ||
			child.Lineage.OffsetMillis != member.OffsetMillis || child.Lineage.TransformPolicyRef != member.TransformPolicyRef {
			t.Fatalf("frame child[%d]=%+v err=%v", index, child, err)
		}
	}
	request := stats.AnalysisRequests[0]
	if len(request.Inputs) != 1 || request.Inputs[0].Descriptor == nil ||
		request.Inputs[0].Descriptor.MediaRef != frameSet.MediaRef {
		t.Fatalf("clip analyzer input=%+v", request.Inputs)
	}
}

func assertRunLease(t *testing.T, harness *gateHarness, runID string, lease media.Descriptor) {
	t.Helper()
	if lease.Binding.RunID != runID || lease.RuntimeLease.SourceMediaRef == "" ||
		lease.RuntimeLease.SourceSHA256 != lease.Integrity.SHA256 ||
		lease.RuntimeLease.PolicyRef != "inspection-run-lease-v2" || lease.Lineage != (media.Lineage{}) {
		t.Fatalf("media is not a formal run lease: %+v", lease)
	}
	source, err := harness.media.Describe(lease.RuntimeLease.SourceMediaRef)
	if err != nil || source.Binding.RunID == runID || source.RuntimeLease.SourceMediaRef != "" ||
		source.Integrity != lease.Integrity || source.Kind != lease.Kind || source.Encoding != lease.Encoding {
		t.Fatalf("run lease source=%+v lease=%+v err=%v", source, lease, err)
	}
	run, err := harness.repository.GetRun(context.Background(), runID)
	if err != nil || source.CreatedAt.After(run.CreatedAt) {
		t.Fatalf("uploaded source was not persistent before run admission: source=%+v run=%+v err=%v", source, run, err)
	}
}

func assertHybridGate(t *testing.T, stats gatePortStats) {
	t.Helper()
	if stats.ExistingCalls != 1 || stats.AcquireCalls != 1 || stats.TransformCalls != 0 || stats.AnalyzeCalls != 1 ||
		stats.CVSelectionCalls != 1 || stats.VLMFollowupCalls != 1 || len(stats.AnalysisRequests) != 1 ||
		len(stats.CVSelectedMedia) != 1 || len(stats.CVSelectedMedia[0]) != 1 {
		t.Fatalf("hybrid gate calls=%+v", stats)
	}
	request := stats.AnalysisRequests[0]
	if request.Method != inspection.MethodHybrid || request.AnalysisPolicyRef != "hybrid-cv-vlm-v2" || len(request.Inputs) != 2 {
		t.Fatalf("hybrid request=%+v", request)
	}
	declared := make(map[string]struct{}, len(request.Inputs))
	evidenceCount, imageCount := 0, 0
	for _, input := range request.Inputs {
		declared[input.ValueRef] = struct{}{}
		if input.Evidence != nil {
			evidenceCount++
		}
		if input.Descriptor != nil && input.Descriptor.Kind == media.KindImage {
			imageCount++
		}
	}
	if evidenceCount != 1 || imageCount != 1 {
		t.Fatalf("hybrid typed input split evidence=%d image=%d inputs=%+v", evidenceCount, imageCount, request.Inputs)
	}
	if _, ok := declared[stats.CVSelectedMedia[0][0]]; !ok {
		t.Fatalf("hybrid selected undeclared media %q from %+v", stats.CVSelectedMedia[0][0], request.Inputs)
	}
}

func assertGenericGateFixture(t *testing.T, fixture gateFixture) {
	t.Helper()
	raw, err := json.Marshal(struct {
		Template   inspection.InspectionTemplate
		Assignment inspection.Assignment
		Request    inspection.CreateRunRequest
	}{fixture.Template, fixture.Assignment, fixture.Request})
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		"dining", "hygiene", "restaurant", "password", "credential", "nativelocator",
		"http://", "https://", "rtsp://", "rtsps://", "deviceid", "cameraid",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("generic fixture contains forbidden business/device token %q: %s", forbidden, raw)
		}
	}
}

func mustGateFixture(t *testing.T, base time.Time, mode gateMode, requestID string, task *inspection.InstalledTaskBinding) gateFixture {
	t.Helper()
	fixture, err := newGateFixture(base, mode, requestID, task)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func staleGateCatalog(t *testing.T, base time.Time) (*catalog.Store, inspection.InstalledTaskBinding) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "catalog-state")
	if err := localstate.PrepareStateRoot(root); err != nil {
		t.Fatal(err)
	}
	store, err := catalog.Open(filepath.Join(root, "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	_, err = store.Create(context.Background(), catalog.NewSource{
		TenantID: gateTenantID, SiteID: gateSiteID, DeviceProfileID: "profile-gate",
		Handle: gateTaskSource, Kind: inspection.SourceCamera,
		IdentityFingerprint: gateDigest("catalog-source:" + gateTaskSource),
		NativeLocator:       "fixture-locator-alpha", Alias: "Generic source alpha", ZoneID: "zone-alpha",
		Capabilities: []catalog.Capability{{
			Ref: "snapshot-input", Kind: catalog.CapabilitySnapshot, Revision: 1,
			Constraints: catalog.Constraints{MediaKinds: []catalog.MediaKind{catalog.MediaImage}, MaxBytes: 2 << 20, MaxFrames: 1, MaxFreshnessSeconds: 30},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateTask(context.Background(), catalog.NewDeviceTaskBinding{
		TenantID: gateTenantID, SiteID: gateSiteID, DeviceProfileID: "profile-gate",
		TaskHandle: gateTaskID, IdentityFingerprint: gateDigest("catalog-task:" + gateTaskID),
		NativeLocator: "fixture-task-alpha", Alias: "Generic task alpha", SourceHandles: []string{gateTaskSource},
		Capabilities: []catalog.Capability{{
			Ref: "existing-evidence", Kind: catalog.CapabilityTaskEvidence, Revision: 1,
			ResultSchema: "classification.v2",
			Constraints:  catalog.Constraints{MediaKinds: []catalog.MediaKind{catalog.MediaEvent}, MaxBytes: 1 << 20, MaxFreshnessSeconds: 120},
		}},
		ObservedAt: base.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := store.FreezeInstalledTask(context.Background(), gateTenantID, gateSiteID, gateTaskID, []string{"existing-evidence"})
	if err != nil {
		t.Fatal(err)
	}
	refresh := catalog.RefreshDeviceTaskBinding{
		TenantID: created.TenantID, SiteID: created.SiteID, TaskHandle: created.TaskHandle,
		ExpectedRevision: created.Revision, DeviceProfileID: created.DeviceProfileID,
		IdentityFingerprint: created.IdentityFingerprint, NativeLocator: created.NativeLocator,
		Alias: "Generic task alpha refreshed", SourceHandles: append([]string(nil), created.SourceHandles...),
		Capabilities: cloneGateCatalogCapabilities(created.Capabilities), State: created.State,
		ObservedAt: time.Now().UTC().Add(-time.Millisecond),
	}
	if _, err := store.RefreshTask(context.Background(), refresh); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateInstalledTask(context.Background(), gateTenantID, gateSiteID, frozen); !errors.Is(err, catalog.ErrTaskStale) {
		t.Fatalf("catalog did not make frozen task stale: %v", err)
	}
	return store, frozen
}

func cloneGateCatalogCapabilities(values []catalog.Capability) []catalog.Capability {
	result := append([]catalog.Capability(nil), values...)
	for index := range result {
		result[index].Constraints.MediaKinds = append([]catalog.MediaKind(nil), result[index].Constraints.MediaKinds...)
	}
	return result
}

func gateSubmission(t *testing.T, request inspection.CreateRunRequest) inspectionauthority.Submission {
	t.Helper()
	identity, err := inspectionauthority.ExecutionIdentityForOrigin(request.Origin, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	submission, err := inspectionauthority.NewSubmission(request, identity)
	if err != nil {
		t.Fatal(err)
	}
	return submission
}
