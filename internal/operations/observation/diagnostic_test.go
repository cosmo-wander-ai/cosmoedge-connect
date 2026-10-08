package observation

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

// These failures cross the real HTTP adapter, livevision sanitizer, acquisition
// or analysis manager, and durable operation store. Fixtures never use a device.
func TestAdapterFailureDiagnosticsPersistAcrossObservationRestart(t *testing.T) {
	const secret = "http://user:opaque@device/private?key=hidden-answer"
	for _, stage := range []string{"capture", "download", "create", "detect", "cancel", "detect-and-cancel"} {
		t.Run(stage, func(t *testing.T) {
			var mu sync.Mutex
			calls := map[string]int{}
			var content []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls[r.URL.Path]++
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				path := r.URL.Path
				fail := stage == "capture" && path == "/gtw/cwai/Camera/GetPicture" || stage == "create" && path == "/gtw/cwai/aihost/PTaskCreate" ||
					(stage == "detect" || stage == "detect-and-cancel") && path == "/gtw/cwai/aihost/PTaskDetectPic" ||
					(stage == "cancel" || stage == "detect-and-cancel") && path == "/gtw/cwai/aihost/PTaskCancle"
				if fail {
					_ = json.NewEncoder(w).Encode(map[string]any{"resCode": 0, "resMsg": []any{map[string]any{"msgCode": "12314", "msgText": secret}}})
					return
				}
				switch path {
				case "/gtw/cwai/Camera/GetPicture":
					fmt.Fprint(w, `{"resCode":1,"resData":{"url":"/web/2026/01/01/test-frame.jpg"}}`)
				case "/web/2026/01/01/test-frame.jpg":
					w.Header().Set("Content-Type", "image/jpeg")
					if stage == "download" {
						fmt.Fprint(w, secret)
					} else {
						_, _ = w.Write(content)
					}
				case "/gtw/cwai/aihost/PTaskCreate", "/gtw/cwai/aihost/PTaskCancle":
					fmt.Fprint(w, `{"resCode":1,"resData":{}}`)
				case "/gtw/cwai/aihost/PTaskDetectPic":
					fmt.Fprint(w, `{"resCode":1,"resData":{"algorithmCode":"89336","areaList":[{"bDetected":true,"targetList":[{"confidence":[{"label":"是","confidence":1}]}]}]}}`)
				default:
					t.Errorf("unexpected fixture request path")
					http.Error(w, "unexpected path", http.StatusNotFound)
				}
			}))
			defer server.Close()
			service, fake, root := newObservationHarness(t, func(fake *observationDevice) device.Client {
				return diagnosticTransportDevice{observationDevice: fake, transport: adapter.NewClient(server.URL, "synthetic-user", "synthetic-secret")}
			})
			content = fake.images["camera-a"]
			result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "failure-" + stage, SourceName: "室内", Question: "画面中是否有人"})
			if err != nil {
				t.Fatal(err)
			}
			result = awaitTerminal(t, service, testOwner, result.OperationRef)
			if result.Status == "succeeded" {
				t.Fatal("failure produced success")
			}
			value, err := service.resource.operations.get(context.Background(), testOwner, result.OperationRef)
			if err != nil {
				t.Fatal(err)
			}
			diagnostics, err := service.resource.operations.diagnostics(context.Background(), value.RunID)
			if err != nil {
				t.Fatal(err)
			}
			wantOperation := map[string]string{"capture": safediagnostic.OperationCameraPicture, "download": safediagnostic.OperationPictureDownload, "create": safediagnostic.OperationPictureCreate, "detect": safediagnostic.OperationPictureDetect, "cancel": safediagnostic.OperationPictureCancel, "detect-and-cancel": safediagnostic.OperationPictureDetect}[stage]
			wantCount := 1
			if stage == "detect-and-cancel" {
				wantCount = 2
			}
			if len(diagnostics) != wantCount || diagnostics[0].Operation != wantOperation {
				t.Fatalf("diagnostic stages: %+v", diagnostics)
			}
			for _, diagnostic := range diagnostics {
				if stage == "download" {
					if diagnostic.Phase != safediagnostic.PhaseValidateJPEG || diagnostic.ValidationCode != safediagnostic.ValidationInvalidJPEG {
						t.Fatalf("download diagnostic: %+v", diagnostic)
					}
				} else if diagnostic.Phase != safediagnostic.PhaseNativeResponse || diagnostic.Class != safediagnostic.ClassNativeRejected || diagnostic.HTTPStatus != 200 || diagnostic.ResCode == nil || *diagnostic.ResCode != 0 || diagnostic.MsgCode != "12314" {
					t.Fatalf("native diagnostic lost: %+v", diagnostic)
				}
			}
			if stage == "detect" && result.CleanupStatus != livevision.TaskCancelAcknowledged {
				t.Fatal("successful cleanup did not preserve failed analysis")
			}
			mu.Lock()
			captureBefore, createBefore, detectBefore := calls["/gtw/cwai/Camera/GetPicture"], calls["/gtw/cwai/aihost/PTaskCreate"], calls["/gtw/cwai/aihost/PTaskDetectPic"]
			mu.Unlock()
			if err := service.Stop(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(root, "operations", "observation", "operations.db"))
			if err != nil || bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("hidden-answer")) || bytes.Contains(raw, []byte(server.URL)) {
				t.Fatal("sensitive transport text entered operation database", err)
			}
			if err := service.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			reopened, err := service.resource.operations.diagnostics(context.Background(), value.RunID)
			if err != nil || !reflect.DeepEqual(diagnostics, reopened) {
				t.Fatalf("reopen changed diagnostics: %+v %v", reopened, err)
			}
			resumed, err := service.Get(context.Background(), testOwner, result.OperationRef)
			if err != nil || resumed.Status != result.Status {
				t.Fatalf("reopen changed original result: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if calls["/gtw/cwai/Camera/GetPicture"] != captureBefore || calls["/gtw/cwai/aihost/PTaskCreate"] != createBefore || calls["/gtw/cwai/aihost/PTaskDetectPic"] != detectBefore {
				t.Fatal("diagnostic restart redispatched capture/create/detect")
			}
		})
	}
}

type diagnosticTransportDevice struct {
	*observationDevice
	transport *adapter.Client
}

func (d diagnosticTransportDevice) GetCameraPictureContext(ctx context.Context, id string) (adapter.CameraPicture, error) {
	return d.transport.GetCameraPictureContext(ctx, id)
}
func (d diagnosticTransportDevice) DownloadFreshCameraPictureJPEG(ctx context.Context, picture adapter.CameraPicture, limit int64) (adapter.InspectionJPEG, error) {
	return d.transport.DownloadFreshCameraPictureJPEG(ctx, picture, limit)
}
func (d diagnosticTransportDevice) CreatePictureTaskContext(ctx context.Context, request adapter.PictureTaskCreateRequest) error {
	return d.transport.CreatePictureTaskContext(ctx, request)
}
func (d diagnosticTransportDevice) DetectPictureTaskContext(ctx context.Context, request adapter.PictureTaskDetectRequest) (adapter.PictureTaskDetectResult, error) {
	return d.transport.DetectPictureTaskContext(ctx, request)
}
func (d diagnosticTransportDevice) CancelPictureTaskContext(ctx context.Context, request adapter.PictureTaskCancelRequest) error {
	return d.transport.CancelPictureTaskContext(ctx, request)
}

func TestDiagnosticWriteFailureKeepsTerminalMediaAndNeverRedispatches(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	ctx := context.Background()
	first, err := service.Observe(ctx, testOwner, Request{RequestID: "retained-result", SourceName: "室内", Question: "是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	first = awaitTerminal(t, service, testOwner, first.OperationRef)
	if len(first.Attachments) != 1 {
		t.Fatal("missing seed media")
	}
	// Reject only diagnostic insertion; the existing terminal/task commits must
	// still succeed. No database close or production device failure is simulated.
	if _, err := service.resource.operations.db.Exec(`CREATE TRIGGER reject_diagnostic BEFORE INSERT ON failure_diagnostics BEGIN SELECT RAISE(FAIL, 'synthetic disk fault'); END`); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.answer = "maybe"
	fake.mu.Unlock()
	failed, err := service.Observe(ctx, testOwner, Request{RequestID: "diagnostic-storage-fault", SourceName: "室内", Question: "是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	failed = awaitTerminal(t, service, testOwner, failed.OperationRef)
	if failed.Status != "analysis_failed" && failed.Status != "failed" {
		t.Fatalf("original failure terminal lost: %s", failed.Status)
	}
	if _, err := service.Observe(ctx, testOwner, Request{RequestID: "must-not-dispatch", SourceName: "室内", Question: "是否有人"}); !errors.Is(err, livevision.ErrDiagnosticPersistence) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("diagnostic write failure hidden: %v", err)
	}
	if retained, err := service.Get(ctx, testOwner, first.OperationRef); err != nil || retained.Status != first.Status {
		t.Fatalf("diagnostic fault hid old result: %v", err)
	}
	if _, err := service.ReadMedia(ctx, testOwner, first.Attachments[0].MediaRef); err != nil {
		t.Fatalf("diagnostic fault hid old image: %v", err)
	}
	fake.mu.Lock()
	captures, creates, detects := len(fake.captures), len(fake.creates), fake.detects
	fake.mu.Unlock()
	if _, err := service.resource.operations.db.Exec(`DROP TRIGGER reject_diagnostic`); err != nil {
		t.Fatal(err)
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if result, err := service.Get(ctx, testOwner, failed.OperationRef); err != nil || result.Status != failed.Status {
		t.Fatal("restart lost original terminal", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.captures) != captures || len(fake.creates) != creates || fake.detects != detects {
		t.Fatal("diagnostic write failure caused redispatch")
	}
}

func TestLocalValidationDiagnosticPersistsAfterReopen(t *testing.T) {
	for _, test := range []struct{ name, answer, phase, code string }{
		{"label-extraction", "x", safediagnostic.PhaseExtractLabel, safediagnostic.ValidationEncodingInvalid},
		{"encoding", "\xff\xfe", safediagnostic.PhaseValidateClosedVocabulary, safediagnostic.ValidationEncodingInvalid},
		{"normalization", "是 ", safediagnostic.PhaseValidateClosedVocabulary, safediagnostic.ValidationNormalizationInvalid},
		{"vocabulary", "maybe", safediagnostic.PhaseValidateClosedVocabulary, safediagnostic.ValidationVocabularyInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, fake, root := newObservationHarness(t)
			fake.mu.Lock()
			fake.answer = test.answer
			fake.mu.Unlock()
			ctx := context.Background()
			result, err := service.Observe(ctx, testOwner, Request{RequestID: "local-" + test.name, SourceName: "室内", Question: "是否有人"})
			if err != nil {
				t.Fatal(err)
			}
			result = awaitTerminal(t, service, testOwner, result.OperationRef)
			value, err := service.resource.operations.get(ctx, testOwner, result.OperationRef)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.Stop(); err != nil {
				t.Fatal(err)
			}
			store, err := openStore(filepath.Join(root, "operations", "observation", "operations.db"), 100)
			if err != nil {
				t.Fatal(err)
			}
			defer store.db.Close()
			diagnostics, err := store.diagnostics(ctx, value.RunID)
			if err != nil || len(diagnostics) != 1 || diagnostics[0].Phase != test.phase || diagnostics[0].ValidationCode != test.code {
				t.Fatalf("reopened local failure: %+v %v", diagnostics, err)
			}
			var raw []byte
			if err := store.db.QueryRow(`SELECT diagnostic_json FROM failure_diagnostics WHERE run_id=?`, value.RunID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			answerJSON, _ := json.Marshal(test.answer)
			if bytes.Contains(raw, answerJSON) {
				t.Fatal("model answer entered diagnostic")
			}
		})
	}
}

func TestDiagnosticExtensionPreservesV1RollbackAndOriginalRecords(t *testing.T) {
	service, _, root := newObservationHarness(t)
	ctx := context.Background()
	result, err := service.Observe(ctx, testOwner, Request{RequestID: "v1-seed", SourceName: "室内", Question: "是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	value, err := service.resource.operations.get(ctx, testOwner, result.OperationRef)
	if err != nil {
		t.Fatal(err)
	}
	var before, taskBefore []byte
	if err := service.resource.operations.db.QueryRow(`SELECT record_json FROM operations WHERE run_id=?`, value.RunID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := service.resource.operations.db.QueryRow(`SELECT task_json FROM temporary_tasks WHERE run_id=?`, value.RunID).Scan(&taskBefore); err != nil {
		t.Fatal(err)
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "operations", "observation", "operations.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`DROP TABLE temporary_uploads; DROP TABLE failure_diagnostics; DROP TABLE observation_extensions;`); err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()
	store, err := openStore(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic := safediagnostic.Diagnostic{Operation: safediagnostic.OperationAnalysis, Phase: safediagnostic.PhaseValidateClosedVocabulary, Class: safediagnostic.ClassLocalContractRejected, ValidationCode: safediagnostic.ValidationVocabularyInvalid}
	if err := store.putDiagnostic(ctx, value.RunID, diagnostic); err != nil {
		t.Fatal(err)
	}
	_ = store.db.Close()
	// The frozen rc10 openStore is exercised below without the extension code.
	rollback, err := openFrozenV1Store(path, 100)
	if err != nil {
		t.Fatal("frozen v1 rollback refused additive diagnostics", err)
	}
	defer rollback.db.Close()
	restored, err := rollback.get(ctx, testOwner, result.OperationRef)
	if err != nil || !reflect.DeepEqual(value, restored) {
		t.Fatal("v1 could not read unchanged operation", err)
	}
	var after, taskAfter []byte
	if err := rollback.db.QueryRow(`SELECT record_json FROM operations WHERE run_id=?`, value.RunID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := rollback.db.QueryRow(`SELECT task_json FROM temporary_tasks WHERE run_id=?`, value.RunID).Scan(&taskAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !bytes.Equal(taskBefore, taskAfter) {
		t.Fatal("extension changed v1 operation/task JSON")
	}
	var coreVersion, extensionVersion int
	if err := rollback.db.QueryRow(`PRAGMA user_version`).Scan(&coreVersion); err != nil {
		t.Fatal(err)
	}
	if err := rollback.db.QueryRow(`SELECT version FROM observation_extensions WHERE name='failure_diagnostics'`).Scan(&extensionVersion); err != nil || coreVersion != 1 || extensionVersion != 1 {
		t.Fatal("extension changed core version", err)
	}
}

// Exact openStore from frozen rc10 5218acb1290a; only the function name differs.
func openFrozenV1Store(path string, maximum int) (*operationStore, error) {
	if err := localstate.PrepareStateRoot(filepath.Dir(path)); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		created = true
	} else if err != nil {
		return nil, err
	}
	if err := localstate.ValidateFile(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*operationStore, error) { _ = db.Close(); return nil, err }
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON"} {
		if _, err := db.Exec(pragma); err != nil {
			return fail(err)
		}
	}
	var version, appID int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if err := db.QueryRow("PRAGMA application_id").Scan(&appID); err != nil {
		return fail(err)
	}
	if created && version == 0 && appID == 0 {
		tx, err := db.Begin()
		if err != nil {
			return fail(err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(operationSchema); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec("PRAGMA user_version=1"); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec("PRAGMA application_id=1397703217"); err != nil {
			return fail(err)
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != 1 || appID != 1397703217 {
		return fail(errors.New("observation operation store is incompatible"))
	}
	return &operationStore{db: db, maximum: maximum}, nil
}
