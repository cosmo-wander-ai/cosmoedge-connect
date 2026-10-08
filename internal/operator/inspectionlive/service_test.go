package inspectionlive

import (
	"bytes"
	"context"
	"errors"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/teststate"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/catalog"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	inspectionstore "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/store"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionhost"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func TestNaturalInterpreterMapsOrdinaryChineseRequestToSnapshot(t *testing.T) {
	result, err := (naturalInterpreter{}).Interpret(context.Background(), planning.InterpretationRequest{
		Instruction: "帮我看看公共区域现在是什么情况",
		Vocabulary:  planning.BusinessVocabulary{SourceNames: []string{SourceAlias}, ObservableNames: []string{ObservableName}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Goal != planning.IntentInspect || result.Inspection == nil || result.Inspection.Preference != planning.PreferSnapshot ||
		result.Inspection.SourceName != SourceAlias || result.Inspection.ObservableName != ObservableName {
		t.Fatalf("unexpected interpretation: %#v", result)
	}
	if _, err := (naturalInterpreter{}).Interpret(context.Background(), planning.InterpretationRequest{
		Instruction: "帮我调取录像", Vocabulary: planning.BusinessVocabulary{SourceNames: []string{SourceAlias}, ObservableNames: []string{ObservableName}},
	}); err == nil {
		t.Fatal("video request must remain explicitly unsupported")
	}
}

func TestNaturalInterpreterKeepsSpecificBusinessQuestionTemporary(t *testing.T) {
	vocabulary := planning.BusinessVocabulary{
		SourceNames: []string{SourceAlias}, ObservableNames: []string{ObservableName},
	}
	for _, test := range []struct {
		instruction string
		subject     string
		region      string
		observable  string
	}{
		{instruction: "帮我看看当前区域桌椅摆放是否整齐", subject: "桌椅", region: "当前区域", observable: "桌椅摆放是否整齐"},
		{instruction: "帮我看看当前区域桌椅摆放是否整齐，并把现场图片发回来。", subject: "桌椅", region: "当前区域", observable: "桌椅摆放是否整齐"},
		{instruction: "检查墙上图片是否歪斜，并附上现场快照", subject: "现场情况", region: "当前区域", observable: "墙上图片是否歪斜"},
		{instruction: "看看西侧就餐区有没有积水", subject: "地面", region: "西侧就餐区", observable: "有没有积水"},
		{instruction: "检查公共区域的卫生情况", subject: "环境卫生", region: "公共区域", observable: "卫生情况"},
	} {
		t.Run(test.subject+test.region, func(t *testing.T) {
			result, err := (naturalInterpreter{}).Interpret(context.Background(), planning.InterpretationRequest{
				Instruction: test.instruction, Vocabulary: vocabulary,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Goal != planning.IntentInspect || result.Inspection == nil ||
				result.Inspection.Mode != planning.ModeTemporaryVisual || result.Inspection.Preference != planning.PreferSnapshot ||
				result.Inspection.ObservableName != "" || result.Inspection.Temporary == nil {
				t.Fatalf("specific request did not use the temporary visual route: %#v", result)
			}
			intent := result.Inspection.Temporary
			if intent.Subject != test.subject || intent.Region != test.region || intent.Observable != test.observable ||
				intent.Locale != "zh-CN" || intent.EvidenceTTLSeconds != 600 {
				t.Fatalf("temporary intent = %#v", intent)
			}
		})
	}

	result, err := (naturalInterpreter{}).Interpret(context.Background(), planning.InterpretationRequest{
		Instruction: "帮我看看公共区域现在是什么情况", Vocabulary: vocabulary,
	})
	if err != nil || result.Inspection == nil || result.Inspection.Mode != planning.ModeStandard {
		t.Fatalf("generic request must retain the standard route: %#v, %v", result, err)
	}
	result, err = (naturalInterpreter{}).Interpret(context.Background(), planning.InterpretationRequest{
		Instruction: "帮我查看当前现场情况，同时返回图片。", Vocabulary: vocabulary,
	})
	if err != nil || result.Inspection == nil || result.Inspection.Mode != planning.ModeStandard {
		t.Fatalf("generic request with snapshot delivery must retain the standard route: %#v, %v", result, err)
	}
	if _, err := (naturalInterpreter{}).Interpret(context.Background(), planning.InterpretationRequest{
		Instruction: "查看摄像头 camera_id=12 的画面", Vocabulary: vocabulary,
	}); err == nil {
		t.Fatal("protected native camera identity reached temporary intent")
	}
}

func TestLiveTemporaryCompilerFreezesCurrentSnapshotOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	spec, err := temporary.NewSpec(temporary.Intent{
		Subject: "桌椅", Region: "当前区域", Observable: "桌椅摆放是否整齐", Locale: "zh-CN",
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := (liveTemporaryCompiler{}).Compile(context.Background(), planning.TemporaryMediaCompilation{
		TenantID: TenantID, SiteID: SiteID, RequestID: "request-temporary-live", RequestedAt: now,
		Spec: spec, SourceRef: SourceHandle, CapabilityRef: snapshotCapability,
		RuntimeRunID:       "temporary_0123456789abcdef0123456789abcdef",
		RuntimeStepID:      "tempmedia_0123456789abcdef0123456789abcdef",
		AudienceBindingRef: "audience_current_user", AudienceSHA256: strings.Repeat("a", 64),
		EvidenceExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Validate() != nil || frozen.Media.Kind != media.KindImage || frozen.Media.Attempt != 1 ||
		!frozen.TimeScope.WindowStart.Equal(now) || !frozen.TimeScope.WindowEnd.Equal(now) ||
		frozen.TimeScope.DurationMillis != 0 || frozen.TimeScope.SampleOrdinal != 0 ||
		frozen.SourceRef != SourceHandle || frozen.CapabilityRef != snapshotCapability {
		t.Fatalf("frozen temporary snapshot request = %#v", frozen)
	}
	prompt, err := temporary.CompilePrompt(spec)
	if err != nil || !strings.Contains(prompt.Text, spec.Subject) || !strings.Contains(prompt.Text, spec.Region) ||
		!strings.Contains(prompt.Text, spec.Observable) || len(prompt.Text)+len("\n本次媒体证据编号：media_0123456789abcdef0123456789abcdef") > 2056 {
		t.Fatalf("bounded business prompt length=%d error=%v", len(prompt.Text), err)
	}
}

func TestCatalogSynchronizerSeedsOnlyRealSnapshotPlan(t *testing.T) {
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	sources, err := catalog.Open(filepath.Join(root, "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	runs, err := inspectionstore.Open(filepath.Join(root, "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	snapshot := device.Snapshot{
		Identity: device.Identity{Serial: "serial-private"},
		Cameras:  []device.Camera{{ID: "1", Name: "东侧"}, {ID: "5", Name: "西侧"}},
		Tasks:    []device.Task{{ChannelID: "5", AlgorithmName: "vlm"}},
	}
	syncer := newCatalogSynchronizer(snapshotReaderStub{snapshot: snapshot}, sources, runs)
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored, err := sources.Get(context.Background(), TenantID, SiteID, SourceHandle)
	if err != nil {
		t.Fatal(err)
	}
	if stored.NativeLocator != "5" || stored.Alias != SourceAlias || stored.IdentityFingerprint != SourceFingerprint(snapshot, snapshot.Cameras[1]) {
		t.Fatalf("unexpected live source: %#v", stored)
	}
	assignments, err := runs.ListAssignments(context.Background(), TenantID, SiteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 1 || len(assignments[0].Targets) != 1 || assignments[0].Targets[0].Strategy != inspection.StrategySnapshotAnalysis {
		t.Fatalf("unexpected assignments: %#v", assignments)
	}
	if err := syncer.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	replayed, err := runs.ListAssignments(context.Background(), TenantID, SiteID)
	if err != nil || len(replayed) != 1 {
		t.Fatalf("catalog replay created another assignment: %d, %v", len(replayed), err)
	}
}

func TestDisconnectedCatalogIsHonest(t *testing.T) {
	root := t.TempDir()
	if err := teststate.ProtectDir(root); err != nil {
		t.Fatal(err)
	}
	sources, err := catalog.Open(filepath.Join(root, "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	runs, err := inspectionstore.Open(filepath.Join(root, "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	syncer := newCatalogSynchronizer(snapshotReaderStub{err: session.ErrNotConnected}, sources, runs)
	if err := syncer.Sync(context.Background()); !errors.Is(err, ErrConnectionRequired) {
		t.Fatalf("error = %v", err)
	}
}

func TestLiveProjectorUsesSnapshotObservationLanguage(t *testing.T) {
	projector := liveProjector{inner: application.NewBusinessResultProjector()}
	result, err := projector.Project(context.Background(), application.ProjectionInput{
		OverallAssessment: inspection.AssessmentMeetsRule,
		Coverage:          inspection.Coverage{Required: 1, Conclusive: 1, Ratio: 1},
		CompletedAt:       time.Now().UTC(),
		Findings: []application.ProjectionFindingInput{{
			TargetTitle: SourceAlias, CriterionTitle: ObservableName, Assessment: inspection.AssessmentMeetsRule,
			Values: []application.ProjectionValue{{Kind: inspection.ResultClassification, Label: "normal"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := result.Summary + strings.Join(result.Limitations, "") + result.Sections[0].Conclusion + strings.Join(result.Sections[0].Details, "")
	for _, forbidden := range []string{"符合要求", "normal", "模拟", "合规结论。整体"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("projection leaked %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(raw, "现场快照") || !strings.Contains(raw, "辅助观察") {
		t.Fatalf("projection missed live limitation: %s", raw)
	}
}

func TestServiceRequiresOwnerOnlyExistingToken(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "access.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{
		StateRoot: filepath.Join(root, "state"), TokenFile: token,
		Snapshots: snapshotReaderStub{err: session.ErrNotConnected}, Connections: connectionProviderStub{}, Sessions: session.New(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceCredentialFactoryCanReopenBeforeServiceStop(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "access.token")
	if err := os.WriteFile(token, []byte("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{
		StateRoot: filepath.Join(root, "state"), TokenFile: token,
		Snapshots: snapshotReaderStub{err: session.ErrNotConnected}, Connections: connectionProviderStub{}, Sessions: session.New(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Stop()
	credentialRoot := filepath.Join(root, "credentials")
	first, err := service.openCredentialStore(context.Background(), credentialRoot)
	if err != nil {
		t.Fatal(err)
	}
	putID, err := credential.NewPutOperationID()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := first.Value.Put(context.Background(), putID, []byte("restartable-authority-envelope"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := service.openCredentialStore(context.Background(), credentialRoot)
	if err != nil {
		t.Fatalf("second credential open before Service.Stop failed: %v", err)
	}
	defer second.Close()
	recovered, err := second.Value.RecoverPut(context.Background(), putID)
	if err != nil || recovered != receipt {
		t.Fatalf("second credential open lost durable receipt: %#v, %v", recovered, err)
	}
}

func TestServiceStartsUnattendedAndReopensEncryptedAuthorityState(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	token := filepath.Join(root, "access.token")
	rawToken := []byte("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	if err := os.WriteFile(token, append(append([]byte(nil), rawToken...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	startAndStop := func() {
		service, err := New(Config{
			StateRoot: stateRoot, TokenFile: token, Address: availableInspectionAddress(t),
			Snapshots: snapshotReaderStub{err: session.ErrNotConnected}, Connections: connectionProviderStub{}, Sessions: session.New(nil),
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := service.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if readiness := service.Readiness(); !readiness.Ready || readiness.State != inspectionhost.StateReady {
			t.Fatalf("unexpected service readiness: %#v", readiness)
		}
		if err := service.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	startAndStop()
	credentialPath := filepath.Join(stateRoot, "inspection-v2", "credentials", "inspection-authority-secrets.bin")
	if _, err := os.Stat(credentialPath); err != nil {
		t.Fatalf("encrypted authority store was not created: %v", err)
	}
	if err := filepath.WalkDir(stateRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, rawToken) {
			return errors.New("raw access token entered persistent inspection state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	startAndStop()
}

func TestServiceCanRetryAfterListenerFailureOpenedCredentialState(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "access.token")
	if err := os.WriteFile(token, []byte("13579bdf2468ace013579bdf2468ace013579bdf2468ace013579bdf2468ace0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := localstate.ProtectFile(token); err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := occupied.Addr().String()
	service, err := New(Config{
		StateRoot: filepath.Join(root, "state"), TokenFile: token, Address: address,
		Snapshots: snapshotReaderStub{err: session.ErrNotConnected}, Connections: connectionProviderStub{}, Sessions: session.New(nil),
	})
	if err != nil {
		_ = occupied.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := service.Start(ctx); err == nil {
		_ = occupied.Close()
		_ = service.Stop()
		t.Fatal("service unexpectedly acquired an occupied listener")
	}
	if err := occupied.Close(); err != nil {
		_ = service.Stop()
		t.Fatal(err)
	}
	if err := service.Start(ctx); err != nil {
		_ = service.Stop()
		t.Fatalf("service could not reopen credentials after startup rollback: %v", err)
	}
	if readiness := service.Readiness(); !readiness.Ready || readiness.State != inspectionhost.StateReady {
		_ = service.Stop()
		t.Fatalf("unexpected retry readiness: %#v", readiness)
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
}

func availableInspectionAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

type snapshotReaderStub struct {
	snapshot device.Snapshot
	err      error
}

func (s snapshotReaderStub) Read(context.Context) (device.Snapshot, error) { return s.snapshot, s.err }

type connectionProviderStub struct{}

func (connectionProviderStub) LiveClient(context.Context, string, string, string) (inspectionadapter.LiveClient, error) {
	return nil, inspectionadapter.ErrUnavailable
}
