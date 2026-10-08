package runtime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/analysiscontract"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
)

func TestRuntimeRequiresAllSixNarrowPorts(t *testing.T) {
	if portType := reflect.TypeOf(Ports{}); portType.NumField() != 6 {
		t.Fatalf("runtime dependency set has %d ports, want exactly 6", portType.NumField())
	}
	complete := Ports{
		Sources: sourceResolverStub{}, Existing: existingReaderStub{}, Acquisition: mediaAcquirerStub{},
		Transform: mediaTransformerStub{}, Analysis: analyzerStub{}, Cleanup: cleanerStub{},
	}
	if err := complete.validate(); err != nil {
		t.Fatalf("complete ports rejected: %v", err)
	}
	tests := []struct {
		name string
		drop func(*Ports)
	}{
		{"source resolver", func(p *Ports) { p.Sources = nil }},
		{"existing reader", func(p *Ports) { p.Existing = nil }},
		{"media acquirer", func(p *Ports) { p.Acquisition = nil }},
		{"media transformer", func(p *Ports) { p.Transform = nil }},
		{"analyzer", func(p *Ports) { p.Analysis = nil }},
		{"resource cleaner", func(p *Ports) { p.Cleanup = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ports := complete
			test.drop(&ports)
			if err := ports.validate(); err == nil {
				t.Fatal("runtime accepted an incomplete port set")
			}
		})
	}
}

func TestRuntimeHasNoLegacyExecutorContract(t *testing.T) {
	forbidden := map[string]struct{}{
		"SiteExecutor": {}, "CaptureResult": {}, "AnalysisRequest": {}, "LocalArtifactStore": {},
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			typeSpec, ok := node.(*ast.TypeSpec)
			if !ok {
				return true
			}
			if _, legacy := forbidden[typeSpec.Name.Name]; legacy {
				t.Fatalf("%s still declares removed runtime type %s", entry.Name(), typeSpec.Name.Name)
			}
			return true
		})
	}
}

func TestPortShapesEnforceAuthoritySeparation(t *testing.T) {
	assertNoFieldFragments(t, reflect.TypeOf(ExistingEvidenceRequest{}),
		"prompt", "model", "credential", "password", "token", "endpoint", "url", "connection")
	assertNoFieldFragments(t, reflect.TypeOf(AnalyzeRequest{}),
		"sourcebinding", "resolution", "credential", "password", "token", "endpoint", "url", "connection", "device")
	assertNoFieldFragments(t, reflect.TypeOf(MediaAcquireResult{}), "bytes", "payload", "frame", "path", "url")
	assertNoFieldFragments(t, reflect.TypeOf(AnalysisInput{}), "bytes", "payload", "frame", "path", "url")
}

func TestRuntimeProductionImportsExcludeDeviceAuthorityAndCredentialPackages(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, imported := range parsed.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			for _, forbidden := range []string{
				"/operator/credential", "/operator/authority", "/operator/onboarding", "/operator/profile", "/devwrite", "/devauthority",
			} {
				if strings.Contains(path, forbidden) {
					t.Fatalf("%s imports forbidden authority package %q", entry.Name(), path)
				}
			}
		}
	}
}

func TestExecutionFailureClassificationPreservesUnknown(t *testing.T) {
	if result := stepErrorResult(ErrOutcomeUnknown); result.state != inspection.StepOutcomeUnknown || result.reason != "step_outcome_unknown" {
		t.Fatalf("unknown result=%+v", result)
	}
	for err, reason := range map[error]string{
		ErrWaitingForSite:    "site_session_unavailable",
		ErrBindingStale:      "execution_binding_stale",
		ErrResourceBusy:      "execution_resource_busy",
		ErrAuthorityRejected: "execution_authority_rejected",
		ErrUnsupported:       "execution_operation_unsupported",
	} {
		if got := executionFailureReason(err); got != reason {
			t.Fatalf("executionFailureReason(%v)=%q, want %q", err, got, reason)
		}
	}
}

func TestHybridSourceSelectionKeepsSameHandleKindsDistinct(t *testing.T) {
	target := inspection.PlannedTarget{
		TargetID: "hybrid-target",
		SourceBindings: []inspection.SourceBinding{
			{Kind: inspection.SourceCamera, SourceHandle: "shared-source"},
			{Kind: inspection.SourceTaskEvidence, SourceHandle: "shared-source"},
		},
	}
	camera, cameraOK := plannedTargetSourceByKind(target, "shared-source", inspection.SourceCamera)
	evidence, evidenceOK := plannedTargetSourceByKind(target, "shared-source", inspection.SourceTaskEvidence)
	if !cameraOK || camera.Kind != inspection.SourceCamera || !evidenceOK || evidence.Kind != inspection.SourceTaskEvidence {
		t.Fatalf("hybrid source selection camera=%+v/%v evidence=%+v/%v", camera, cameraOK, evidence, evidenceOK)
	}
	plan := inspection.ExecutionPlan{Targets: []inspection.PlannedTarget{target}}
	if _, _, ok := plannedTargetSource(plan, target.TargetID, "shared-source"); ok {
		t.Fatal("kind-agnostic lookup accepted an ambiguous hybrid source handle")
	}
	target.SourceBindings = append(target.SourceBindings, inspection.SourceBinding{Kind: inspection.SourceTaskEvidence, SourceHandle: "shared-source"})
	if _, ok := plannedTargetSourceByKind(target, "shared-source", inspection.SourceTaskEvidence); ok {
		t.Fatal("kind-exact lookup accepted duplicate task-evidence bindings")
	}
}

func TestAnalysisEnvelopeUsesOnlyV2Schema(t *testing.T) {
	output := inspection.OutputContract{
		Mode: inspection.ResultStructured, SchemaVersion: "finding.v2",
		AllowedAssessments: []inspection.Assessment{inspection.AssessmentMeetsRule},
	}
	digest, err := analysisOutputContractDigest(output)
	if err != nil || !runtimeSHA256.MatchString(digest) {
		t.Fatalf("analysisOutputContractDigest()=(%q,%v)", digest, err)
	}
	if analysiscontract.SchemaVersion != "inspection.analysis.v2" || inspection.SchemaVersion != "cosmoedge.inspection.v2" {
		t.Fatalf("unexpected v2 schema constants: %q %q", analysiscontract.SchemaVersion, inspection.SchemaVersion)
	}
}

func TestBuildEnvelopeBindsStrictTypedResult(t *testing.T) {
	now := time.Date(2026, 7, 19, 8, 0, 0, 0, time.UTC)
	mediaRef := "media_0123456789abcdef0123456789abcdef"
	visibleResidue := false
	candidate := analysiscontract.Candidate{
		Assessment: inspection.AssessmentMeetsRule, Observability: inspection.ResultFullyVisible,
		Value: &inspection.ResultValue{
			Kind: inspection.ResultStructured,
			Structured: &inspection.StructuredValue{Fields: []inspection.StructuredField{{
				Name:  "visible_residue",
				Value: inspection.StructuredScalar{Kind: inspection.StructuredBoolean, Boolean: &visibleResidue},
			}}},
		},
		EvidenceRefs: []string{mediaRef}, Limitations: []analysiscontract.Limitation{},
		ReasonCodes: []analysiscontract.ReasonCode{analysiscontract.ReasonCriterionMet},
	}
	planned := inspection.PlannedCriterion{Criterion: inspection.Criterion{
		ID: "visible-residue", Method: inspection.MethodVLM, RuleVersion: 2,
		Output: inspection.OutputContract{Mode: inspection.ResultStructured, SchemaVersion: "finding.v2"},
	}}
	envelope, err := buildEnvelope(
		inspection.ExecutionPlan{TemplateRevision: 7},
		inspection.PlannedTarget{TargetID: "scene-alpha", StrategyPolicy: inspection.StrategyPolicy{AnalysisPolicyRef: "fixture-vlm-v2"}},
		planned, "analysis_0123456789abcdef0123456789abcdef", "step_0123456789abcdef0123456789abcdef", candidate,
		[]media.Descriptor{{
			MediaRef: mediaRef, Binding: media.Binding{SourceRef: "source-alpha"},
			Integrity: media.Integrity{SHA256: strings.Repeat("a", 64)}, CreatedAt: now,
		}},
		"fixture-adapter-v2", "fixture-model-v2", now.Add(time.Second), now.Add(2*time.Second), 1,
		"run_0123456789abcdef0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("buildEnvelope() error = %v", err)
	}
	result, err := envelope.TypedResult()
	if err != nil {
		t.Fatalf("TypedResult() error = %v", err)
	}
	if result.Binding.TargetID != "scene-alpha" || result.Binding.OutputKind != inspection.ResultStructured ||
		result.Binding.SourceMedia[0].SourceRef != "source-alpha" || result.Value == nil || result.Value.Structured == nil ||
		len(result.EvidenceRefs) != 1 || result.EvidenceRefs[0] != mediaRef || result.Display != nil {
		t.Fatalf("typed result binding = %+v", result)
	}
}

func TestRuntimeOptionBounds(t *testing.T) {
	manager := &Manager{}
	for name, option := range map[string]Option{
		"lease": WithLease(24*time.Hour + time.Second), "tick": WithWorkerTick(24*time.Hour + time.Second),
		"cleanup": WithCleanupTimeout(5*time.Minute + time.Second),
	} {
		if err := option(manager); err == nil {
			t.Fatalf("%s accepted an unbounded duration", name)
		}
	}
}

func TestRuntimeIdentityOptionIsStableAndOpaque(t *testing.T) {
	manager := &Manager{}
	for _, value := range []string{"", "https://runtime.example", strings.Repeat("r", 65)} {
		if err := WithRuntimeID(value)(manager); err == nil {
			t.Fatalf("WithRuntimeID(%q) unexpectedly succeeded", value)
		}
	}
	if err := WithRuntimeID("cosmoedge-connect-runtime-v2")(manager); err != nil || manager.ownerID != "cosmoedge-connect-runtime-v2" {
		t.Fatalf("stable runtime identity owner=%q err=%v", manager.ownerID, err)
	}
}

func assertNoFieldFragments(t *testing.T, value reflect.Type, forbidden ...string) {
	t.Helper()
	for index := 0; index < value.NumField(); index++ {
		name := strings.ToLower(value.Field(index).Name)
		for _, fragment := range forbidden {
			if strings.Contains(name, fragment) {
				t.Fatalf("%s unexpectedly exposes field %s", value.Name(), value.Field(index).Name)
			}
		}
	}
}

type sourceResolverStub struct{ SourceResolver }
type existingReaderStub struct{ ExistingEvidenceReader }
type mediaAcquirerStub struct{ MediaAcquirer }
type mediaTransformerStub struct{ MediaTransformer }
type analyzerStub struct{ Analyzer }
type cleanerStub struct{ TemporaryResourceCleaner }
