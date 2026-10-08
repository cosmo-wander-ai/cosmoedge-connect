package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

func (*observationDevice) QueryUploadCapabilitiesContext(context.Context) (adapter.UploadCapabilities, error) {
	return adapter.UploadCapabilities{MaxChunkSize: 8 << 20, IdleTimeoutMs: 1800000, AvailableForNewUploadsBytes: 64 << 20, MaxEncodedImageBytes: 16 << 20, MaxImagePixels: 33177600}, nil
}

func (d *observationDevice) UploadPictureJPEGContext(_ context.Context, request adapter.StagedPictureUploadRequest) (adapter.StagedPictureUpload, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	request.JPEG = bytes.Clone(request.JPEG)
	d.uploads = append(d.uploads, request)
	upload := adapter.StagedPictureUpload{ClientRequestID: request.ClientRequestID, UploadID: "staged_" + digestText(request.ClientRequestID)[:32], SHA256: digestText(string(request.JPEG)), SizeBytes: uint64(len(request.JPEG)), TotalChunks: 1, NextChunkIndex: 1, Complete: true}
	if d.uploadErr != nil {
		upload.NextChunkIndex, upload.Complete = 0, false
	}
	if d.uploadNoID {
		upload.UploadID = ""
	}
	if d.uploaded == nil {
		d.uploaded = make(map[string][]byte)
	}
	d.uploaded[upload.UploadID] = bytes.Clone(request.JPEG)
	return upload, d.uploadErr
}

func (d *observationDevice) CancelPictureUploadContext(ctx context.Context, upload adapter.StagedPictureUpload) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.uploadCancels = append(d.uploadCancels, upload)
	if d.uploadCancelErr == nil {
		delete(d.uploaded, upload.UploadID)
	}
	return d.uploadCancelErr
}

func observedUpload(t *testing.T, service *Service, ref string) (operation, livevision.TemporaryUpload, string) {
	t.Helper()
	value, err := service.resource.operations.get(context.Background(), testOwner, ref)
	if err != nil {
		t.Fatal(err)
	}
	upload, _, disposition, _, err := scanUpload(service.resource.operations.db.QueryRow("SELECT "+uploadColumns+" FROM temporary_uploads WHERE run_id=?", value.RunID))
	if err != nil {
		t.Fatal(err)
	}
	return value, upload, disposition
}

func TestObservationStagesExactOriginalBeforeSingleDetect(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "staged-exact-original", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	if result.Status != "succeeded" || result.CleanupStatus != livevision.TaskCancelAcknowledged {
		t.Fatalf("result status=%s cleanup=%s", result.Status, result.CleanupStatus)
	}
	value, owned, disposition := observedUpload(t, service, result.OperationRef)
	if disposition != livevision.UploadCancelAcknowledged || owned.OwnerHash != testOwner || owned.RunID != value.RunID || owned.Upload.SHA256 != result.Attachments[0].SHA256 || owned.Upload.ClientRequestID != livevision.TemporaryUploadClientRequestID(testOwner, value.RunID, owned.Upload.SHA256) {
		t.Fatal("upload lost original/owner/run binding")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.uploads) != 1 || len(fake.detectRequests) != 1 || len(fake.uploadCancels) != 1 || !bytes.Equal(fake.uploads[0].JPEG, fake.images["camera-a"]) {
		t.Fatal("original bytes changed or lifecycle repeated")
	}
	detect := fake.detectRequests[0]
	if len(detect.JPEG) != 0 || detect.UploadID != owned.Upload.UploadID || !reflect.DeepEqual(fake.uploadCancels[0], owned.Upload) {
		t.Fatal("detect/cleanup did not use exact staged handle")
	}
	params := detect.TaskConfig.Params
	if len(params) != 3 || params[0].Key != "advanced_mode" || params[0].Value != "1" || params[1].Key != "generationStyle" || params[1].Value != "strict" || params[2].Key != "keywords" || params[2].Value == "" {
		t.Fatal("staging changed picture task config")
	}
}

func TestUploadUnknownPreservesKnownOrAliasAndNeverDetects(t *testing.T) {
	for _, noID := range []bool{false, true} {
		t.Run(map[bool]string{false: "known-handle", true: "first-response-lost"}[noID], func(t *testing.T) {
			service, fake, _ := newObservationHarness(t)
			fake.mu.Lock()
			fake.uploadNoID = noID
			fake.uploadErr = safediagnostic.Wrap(context.DeadlineExceeded, safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureUpload, Phase: safediagnostic.PhaseTransport, Class: safediagnostic.ClassOutcomeUnknown})
			fake.mu.Unlock()
			result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "upload-unknown", SourceName: "室内", Question: "画面中是否有人"})
			if err != nil {
				t.Fatal(err)
			}
			result = awaitTerminal(t, service, testOwner, result.OperationRef)
			if result.Status == "succeeded" {
				t.Fatal("upload failure became analysis success")
			}
			_, owned, disposition := observedUpload(t, service, result.OperationRef)
			if disposition != livevision.UploadCancelAcknowledged || (owned.Upload.UploadID == "") != noID {
				t.Fatal("known cleanup target was lost")
			}
			fake.mu.Lock()
			if len(fake.uploads) != 1 || fake.detects != 0 || len(fake.uploadCancels) != 1 || fake.uploadCancels[0].CleanupRef() != owned.Upload.CleanupRef() {
				t.Fatal("unknown upload was replayed/detected or wrong cleanup target")
			}
			fake.mu.Unlock()
			if err := service.Stop(); err != nil {
				t.Fatal(err)
			}
			if err := service.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(30 * time.Millisecond)
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if len(fake.uploads) != 1 || fake.detects != 0 || len(fake.uploadCancels) != 1 {
				t.Fatal("restart replayed upload/Detect/acknowledged cleanup")
			}
		})
	}
}

func TestUploadCleanupRestartRetriesOnlyOwnedCancel(t *testing.T) {
	service, fake, _ := newObservationHarness(t)
	fake.mu.Lock()
	fake.detectErr = safediagnostic.Wrap(context.DeadlineExceeded, safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureDetect, Phase: safediagnostic.PhaseTransport, Class: safediagnostic.ClassOutcomeUnknown})
	fake.uploadCancelErr = context.DeadlineExceeded
	fake.mu.Unlock()
	result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "upload-cleanup-restart", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	if result.Status == "succeeded" || result.CleanupStatus != livevision.TaskCleanupUnconfirmed {
		t.Fatal("unknown Detect/cleanup was hidden")
	}
	_, owned, disposition := observedUpload(t, service, result.OperationRef)
	if disposition != livevision.UploadCleanupUnconfirmed {
		t.Fatal("cleanup uncertainty not durable")
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.uploadCancelErr = nil
	fake.mu.Unlock()
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		current, err := service.Get(context.Background(), testOwner, result.OperationRef)
		if err != nil {
			t.Fatal(err)
		}
		if current.CleanupStatus == livevision.TaskCancelAcknowledged {
			if current.Status != result.Status {
				t.Fatal("cleanup changed original unknown result")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restart did not clean recorded upload")
		}
		time.Sleep(5 * time.Millisecond)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.uploads) != 1 || fake.detects != 1 || len(fake.uploadCancels) != 2 || !reflect.DeepEqual(fake.uploadCancels[1], owned.Upload) {
		t.Fatal("recovery did more than exact owned cancel")
	}
}

func TestUploadJournalReopenPreservesAliasAndRejectsOwnershipMutation(t *testing.T) {
	service, _, root := newObservationHarness(t)
	result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "upload-journal-reopen", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	value, owned, _ := observedUpload(t, service, result.OperationRef)
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "operations", "observation", "operations.db")
	store, err := openStore(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	journal := &taskJournal{store: store}
	// Simulate a crash after durable reservation and before receiving an ACK.
	if _, err := store.db.Exec("DELETE FROM temporary_uploads WHERE run_id=?", value.RunID); err != nil {
		t.Fatal(err)
	}
	owned.Upload.UploadID, owned.Upload.TotalChunks, owned.Upload.NextChunkIndex, owned.Upload.Complete = "", 0, 0, false
	if err := journal.BeforeUpload(context.Background(), owned); err != nil {
		t.Fatal(err)
	}
	if err := journal.BeforeUpload(context.Background(), owned); err == nil {
		t.Fatal("duplicate reservation allowed another upload")
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openStore(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	journal = &taskJournal{store: store}
	pending, err := journal.pendingUploads(context.Background(), owned.ConnectionEpoch)
	if err != nil || len(pending) != 1 || !reflect.DeepEqual(pending[0], owned) {
		t.Fatal("lost pre-ACK alias", err)
	}
	changed := owned
	changed.OwnerHash = otherOwner
	changed.Upload.ClientRequestID = livevision.TemporaryUploadClientRequestID(otherOwner, changed.RunID, changed.Upload.SHA256)
	if allowed, err := journal.BeforeUploadCancel(context.Background(), changed); err == nil || allowed {
		t.Fatal("cross-owner cancel accepted")
	}
	changed = owned
	changed.Upload.UploadID = "unowned_other_handle"
	if allowed, err := journal.BeforeUploadCancel(context.Background(), changed); err != nil || allowed {
		t.Fatal("unrecorded handle cancel accepted")
	}
	if allowed, err := journal.BeforeUploadCancel(context.Background(), owned); err != nil || !allowed {
		t.Fatal("owned alias cleanup rejected", err)
	}
	if err := journal.FinishUpload(context.Background(), owned, livevision.UploadCleanupUnconfirmed); err != nil {
		t.Fatal(err)
	}
	if allowed, err := journal.BeforeUploadCancel(context.Background(), owned); err != nil || !allowed {
		t.Fatal("bounded retry rejected", err)
	}
	if allowed, err := journal.BeforeUploadCancel(context.Background(), owned); err != nil || allowed {
		t.Fatal("third cleanup attempt allowed")
	}
	// Checked JSON hash rejects altered cleanup evidence on recovery.
	raw, _ := json.Marshal(changed)
	if _, err := store.db.Exec("UPDATE temporary_uploads SET upload_json=?,cancel_attempts=0", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.pendingUploads(context.Background(), owned.ConnectionEpoch); !errors.Is(err, ErrUnavailable) {
		t.Fatal("tampered handle not rejected", err)
	}
}

func TestUploadExtensionPreservesCoreV1RecordsAndHashes(t *testing.T) {
	service, _, root := newObservationHarness(t)
	result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "upload-extension-v1", SourceName: "室内", Question: "画面中是否有人"})
	if err != nil {
		t.Fatal(err)
	}
	result = awaitTerminal(t, service, testOwner, result.OperationRef)
	value, _, _ := observedUpload(t, service, result.OperationRef)
	var operationJSON, taskJSON []byte
	var operationSHA, taskSHA string
	if err := service.resource.operations.db.QueryRow(`SELECT record_json,record_sha256 FROM operations WHERE run_id=?`, value.RunID).Scan(&operationJSON, &operationSHA); err != nil {
		t.Fatal(err)
	}
	if err := service.resource.operations.db.QueryRow(`SELECT task_json,task_sha256 FROM temporary_tasks WHERE run_id=?`, value.RunID).Scan(&taskJSON, &taskSHA); err != nil {
		t.Fatal(err)
	}
	if err := service.Stop(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "operations", "observation", "operations.db")
	legacy, err := openFrozenV1Store(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.db.Exec(`DROP TABLE temporary_uploads; DELETE FROM observation_extensions WHERE name='temporary_uploads'`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.db.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		store, err := openStore(path, 100)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	rollback, err := openFrozenV1Store(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback.db.Close()
	var restoredOperation, restoredTask []byte
	var restoredOperationSHA, restoredTaskSHA string
	if err := rollback.db.QueryRow(`SELECT record_json,record_sha256 FROM operations WHERE run_id=?`, value.RunID).Scan(&restoredOperation, &restoredOperationSHA); err != nil {
		t.Fatal(err)
	}
	if err := rollback.db.QueryRow(`SELECT task_json,task_sha256 FROM temporary_tasks WHERE run_id=?`, value.RunID).Scan(&restoredTask, &restoredTaskSHA); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(operationJSON, restoredOperation) || !bytes.Equal(taskJSON, restoredTask) || operationSHA != restoredOperationSHA || taskSHA != restoredTaskSHA {
		t.Fatal("upload extension changed original core records/hashes")
	}
	var coreVersion, extensionVersion, operations, tasks, uploads int
	if err := rollback.db.QueryRow(`PRAGMA user_version`).Scan(&coreVersion); err != nil {
		t.Fatal(err)
	}
	if err := rollback.db.QueryRow(`SELECT version FROM observation_extensions WHERE name='temporary_uploads'`).Scan(&extensionVersion); err != nil {
		t.Fatal(err)
	}
	if err := rollback.db.QueryRow(`SELECT count(*) FROM operations`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if err := rollback.db.QueryRow(`SELECT count(*) FROM temporary_tasks`).Scan(&tasks); err != nil {
		t.Fatal(err)
	}
	if err := rollback.db.QueryRow(`SELECT count(*) FROM temporary_uploads`).Scan(&uploads); err != nil {
		t.Fatal(err)
	}
	if coreVersion != 1 || extensionVersion != 1 || operations != 1 || tasks != 1 || uploads != 0 {
		t.Fatal("extension altered core version/counts or invented upload")
	}
	if _, err := rollback.get(context.Background(), testOwner, result.OperationRef); err != nil {
		t.Fatal("old reader lost original operation", err)
	}
}

func TestUploadJournalWriteFailureStopsBeforeDetectAndKeepsAliasCleanup(t *testing.T) {
	for _, failReservation := range []bool{true, false} {
		t.Run(map[bool]string{true: "reservation", false: "canonical-ack"}[failReservation], func(t *testing.T) {
			service, fake, _ := newObservationHarness(t)
			trigger := `CREATE TRIGGER fail_staged_journal BEFORE UPDATE OF upload_json ON temporary_uploads BEGIN SELECT RAISE(FAIL,'private SQL diagnostic must not escape'); END`
			if failReservation {
				trigger = `CREATE TRIGGER fail_staged_journal BEFORE INSERT ON temporary_uploads BEGIN SELECT RAISE(FAIL,'private SQL diagnostic must not escape'); END`
			}
			if _, err := service.resource.operations.db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			result, err := service.Observe(context.Background(), testOwner, Request{RequestID: "upload-journal-write-failure", SourceName: "室内", Question: "画面中是否有人"})
			if err != nil {
				t.Fatal(err)
			}
			result = awaitTerminal(t, service, testOwner, result.OperationRef)
			if result.Status == "succeeded" {
				t.Fatal("journal failure became success")
			}
			value, err := service.resource.operations.get(context.Background(), testOwner, result.OperationRef)
			if err != nil {
				t.Fatal(err)
			}
			diagnostics, err := service.resource.operations.diagnostics(context.Background(), value.RunID)
			if err != nil || len(diagnostics) != 1 || diagnostics[0].Operation != safediagnostic.OperationPictureUpload || diagnostics[0].Phase != safediagnostic.PhaseJournal || diagnostics[0].Class != safediagnostic.ClassPersistenceFailed {
				t.Fatalf("journal classification lost: %+v %v", diagnostics, err)
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			wantUploads := 1
			if failReservation {
				wantUploads = 0
			}
			if len(fake.uploads) != wantUploads || fake.detects != 0 || len(fake.uploadCancels) != wantUploads || len(fake.cancels) != 1 {
				t.Fatal("journal failure dispatched extra work or skipped cleanup")
			}
			if !failReservation && (fake.uploadCancels[0].UploadID != "" || fake.uploadCancels[0].CleanupRef() != fake.uploads[0].ClientRequestID) {
				t.Fatal("failed ACK persistence lost original alias cleanup")
			}
		})
	}
}
