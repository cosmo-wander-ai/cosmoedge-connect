package livevision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/inspectionadapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

const (
	UploadCancelAcknowledged = "cancel_acknowledged"
	UploadCleanupUnconfirmed = "cleanup_unconfirmed"
)

// TemporaryUpload is private cleanup evidence. It binds an upload alias before
// dispatch, so even a lost first response leaves an exact owned cleanup target.
// It contains no JPEG, prompt, answer, address or credential.
type TemporaryUpload struct {
	RunID                string                      `json:"runId"`
	OwnerHash            string                      `json:"ownerHash"`
	DeviceIdentitySHA256 string                      `json:"deviceIdentitySha256"`
	ConnectionEpoch      string                      `json:"connectionEpoch"`
	Upload               adapter.StagedPictureUpload `json:"upload"`
}

func (TemporaryUpload) String() string   { return "[owned-temporary-upload]" }
func (TemporaryUpload) GoString() string { return "livevision.TemporaryUpload([redacted])" }

func TemporaryUploadClientRequestID(owner, run, originalSHA string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"cosmoedge-connect.observation.upload.v1", owner, run, originalSHA}, "\x00")))
	return "observation-upload-" + hex.EncodeToString(sum[:])
}

func (u TemporaryUpload) Validate() error {
	v := u.Upload
	if u.RunID == "" || len(u.RunID) > 128 || !digestPattern.MatchString(u.OwnerHash) ||
		!digestPattern.MatchString(u.DeviceIdentitySHA256) || !digestPattern.MatchString(u.ConnectionEpoch) ||
		!digestPattern.MatchString(v.SHA256) || v.SizeBytes == 0 || v.SizeBytes > uint64(maxLiveJPEGBytes) ||
		v.ClientRequestID != TemporaryUploadClientRequestID(u.OwnerHash, u.RunID, v.SHA256) || v.CleanupRef() == "" ||
		v.TotalChunks > 1024 || v.NextChunkIndex > v.TotalChunks ||
		(v.Complete && (v.UploadID == "" || v.TotalChunks == 0 || v.NextChunkIndex != v.TotalChunks)) ||
		(!v.Complete && v.TotalChunks != 0 && v.NextChunkIndex == v.TotalChunks) {
		return inspectionadapter.ErrBindingStale
	}
	return nil
}

// BeforeUpload is a durable, insert-only reservation. RecordUpload retains the
// acknowledged handle before Detect. Cancel attempts are reserved before the
// request; recovery may only cancel, never upload or Detect again.
type TemporaryUploadJournal interface {
	BeforeUpload(context.Context, TemporaryUpload) error
	RecordUpload(context.Context, TemporaryUpload) error
	BeforeUploadCancel(context.Context, TemporaryUpload) (bool, error)
	FinishUpload(context.Context, TemporaryUpload, string) error
}

func WithTemporaryUploadJournal(ownerHash string, journal TemporaryUploadJournal) ConnectionOption {
	return func(p *vaultConnections) error {
		if !digestPattern.MatchString(ownerHash) || journal == nil {
			return errors.New("temporary upload owner and journal are required")
		}
		p.uploadOwnerHash, p.uploadJournal = ownerHash, journal
		return nil
	}
}

// CancelRecordedTemporaryUpload checks the same device and admission epoch,
// then cancels exactly the persisted handle. A successful cancel may mean the
// server already consumed the upload; it does not prove inference success.
func CancelRecordedTemporaryUpload(ctx context.Context, vault *session.Vault, upload TemporaryUpload, journal TemporaryUploadJournal) (cleanupErr error) {
	recorder, _ := journal.(TemporaryFailureRecorder)
	defer func() {
		cleanupErr = recordTemporaryFailure(ctx, recorder, upload.RunID, cleanupErr,
			localDiagnostic(safediagnostic.OperationPictureUploadCancel, safediagnostic.PhaseSourceBinding, safediagnostic.ValidationBindingInvalid))
	}()
	if vault == nil || journal == nil || upload.Validate() != nil {
		return ErrTemporaryCleanupUnconfirmed
	}
	bounded, cancel := context.WithTimeout(ctx, failedTaskCleanupLimit)
	defer cancel()
	connection, err := vault.InspectionConnection(bounded)
	if err != nil || connection.Client() == nil || deviceIdentityDigest(connection.Snapshot()) != upload.DeviceIdentitySHA256 || connectionEpoch(connection) != upload.ConnectionEpoch {
		return ErrTemporaryCleanupUnconfirmed
	}
	client, ok := connection.Client().(device.StagedPictureClient)
	if !ok {
		return ErrTemporaryCleanupUnconfirmed
	}
	return cancelJournaledUpload(bounded, client, upload, journal)
}

func cancelJournaledUpload(ctx context.Context, client device.StagedPictureClient, upload TemporaryUpload, journal TemporaryUploadJournal) error {
	bounded, cancel := context.WithTimeout(ctx, failedTaskCleanupLimit)
	defer cancel()
	recorder, _ := journal.(TemporaryFailureRecorder)
	allowed, err := journal.BeforeUploadCancel(bounded, upload)
	if err != nil {
		return recordTemporaryFailure(ctx, recorder, upload.RunID, ErrTemporaryCleanupUnconfirmed, journalPersistenceDiagnostic(safediagnostic.OperationPictureUploadCancel))
	}
	if !allowed {
		return recordTemporaryFailure(ctx, recorder, upload.RunID, ErrTemporaryCleanupUnconfirmed,
			localDiagnostic(safediagnostic.OperationPictureUploadCancel, safediagnostic.PhaseJournal, safediagnostic.ValidationBindingInvalid))
	}
	cancelErr := recordTemporaryFailure(ctx, recorder, upload.RunID, sanitizeDeviceError(client.CancelPictureUploadContext(bounded, upload.Upload)),
		safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureUploadCancel, Phase: safediagnostic.PhaseCleanup, Class: safediagnostic.ClassOutcomeUnknown})
	disposition := UploadCancelAcknowledged
	if cancelErr != nil {
		disposition = UploadCleanupUnconfirmed
	}
	writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), failedTaskCleanupLimit)
	journalErr := journal.FinishUpload(writeCtx, upload, disposition)
	writeCancel()
	if journalErr != nil {
		journalErr = recordTemporaryFailure(ctx, recorder, upload.RunID, ErrTemporaryCleanupUnconfirmed, journalPersistenceDiagnostic(safediagnostic.OperationPictureUploadCancel))
	}
	if cancelErr != nil || journalErr != nil {
		return errors.Join(ErrTemporaryCleanupUnconfirmed, inspectionadapter.ErrOutcomeUnknown, cancelErr, journalErr)
	}
	return nil
}

func (p *vaultConnections) detectStagedTemporaryPicture(ctx context.Context, connection session.InspectionConnection, request temporaryVisionAnalysis, detect adapter.PictureTaskDetectRequest) (result adapter.PictureTaskDetectResult, resultErr error) {
	client, ok := connection.Client().(device.StagedPictureClient)
	if !ok {
		return result, safediagnostic.Wrap(inspectionadapter.ErrUnavailable, localDiagnostic(safediagnostic.OperationUploadCapabilities, safediagnostic.PhaseBeforeDispatch, safediagnostic.ValidationInvalidRequest))
	}
	caps, err := client.QueryUploadCapabilitiesContext(ctx)
	if err != nil {
		return result, p.recordFailure(ctx, sanitizeDeviceError(err), safediagnostic.Diagnostic{Operation: safediagnostic.OperationUploadCapabilities, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassUnavailable})
	}
	sum := sha256.Sum256(request.jpeg)
	if hex.EncodeToString(sum[:]) != request.evidenceSHA {
		return result, safediagnostic.Wrap(inspectionadapter.ErrBindingStale, localDiagnostic(safediagnostic.OperationPictureUpload, safediagnostic.PhaseBeforeDispatch, safediagnostic.ValidationBindingInvalid))
	}
	owned := TemporaryUpload{RunID: request.runID, OwnerHash: p.uploadOwnerHash,
		DeviceIdentitySHA256: deviceIdentityDigest(connection.Snapshot()), ConnectionEpoch: connectionEpoch(connection),
		Upload: adapter.StagedPictureUpload{ClientRequestID: TemporaryUploadClientRequestID(p.uploadOwnerHash, request.runID, request.evidenceSHA), SHA256: request.evidenceSHA, SizeBytes: uint64(len(request.jpeg))}}
	if owned.Validate() != nil {
		return result, inspectionadapter.ErrBindingStale
	}
	if err := p.uploadJournal.BeforeUpload(ctx, owned); err != nil {
		return result, p.recordFailure(ctx, errors.Join(inspectionadapter.ErrOutcomeUnknown, ErrTemporaryCleanupUnconfirmed), journalPersistenceDiagnostic(safediagnostic.OperationPictureUpload))
	}
	defer func() {
		cleanupErr := cancelJournaledUpload(context.WithoutCancel(ctx), client, owned, p.uploadJournal)
		if cleanupErr != nil {
			resultErr = errors.Join(resultErr, inspectionadapter.ErrOutcomeUnknown, cleanupErr)
		}
	}()
	upload, uploadErr := client.UploadPictureJPEGContext(ctx, adapter.StagedPictureUploadRequest{ClientRequestID: owned.Upload.ClientRequestID, JPEG: request.jpeg, Capabilities: caps})
	if upload.ClientRequestID != "" {
		updated := owned
		updated.Upload = upload
		if updated.Validate() != nil || upload.ClientRequestID != owned.Upload.ClientRequestID || upload.SHA256 != owned.Upload.SHA256 || upload.SizeBytes != owned.Upload.SizeBytes {
			return result, p.recordFailure(ctx, inspectionadapter.ErrOutcomeUnknown, localDiagnostic(safediagnostic.OperationPictureUpload, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ValidationBindingInvalid))
		}
		// A cancelled caller cannot discard a returned canonical handle. If this
		// write fails, the durable alias remains the exact owned cleanup target.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), failedTaskCleanupLimit)
		err := p.uploadJournal.RecordUpload(writeCtx, updated)
		cancel()
		if err != nil {
			return result, p.recordFailure(ctx, errors.Join(inspectionadapter.ErrOutcomeUnknown, ErrTemporaryCleanupUnconfirmed), journalPersistenceDiagnostic(safediagnostic.OperationPictureUpload))
		}
		owned = updated
	}
	if uploadErr != nil {
		return result, p.recordFailure(ctx, sanitizeDeviceError(uploadErr), safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureUpload, Phase: safediagnostic.PhaseNativeResponse, Class: safediagnostic.ClassUnavailable})
	}
	if !owned.Upload.Complete || owned.Upload.UploadID == "" {
		return result, p.recordFailure(ctx, inspectionadapter.ErrOutcomeUnknown, localDiagnostic(safediagnostic.OperationPictureUpload, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ValidationInvalidResponse))
	}
	detect.JPEG, detect.UploadID = nil, owned.Upload.UploadID
	// Exactly one Detect, even when its response is lost. The surrounding
	// temporary manager commits its existing non-replayable terminal boundary.
	return connection.Client().DetectPictureTaskContext(ctx, detect)
}
