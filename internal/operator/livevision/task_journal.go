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

var ErrTemporaryCleanupUnconfirmed = errors.New("temporary picture task cleanup is unconfirmed")

// ErrDiagnosticPersistence must remain visible even when the analysis manager
// consumes the analysis error while committing its non-replayable terminal.
var ErrDiagnosticPersistence = errors.New("temporary failure diagnostic could not be persisted")

// TemporaryFailureRecorder persists closed classifications only. Implementations
// must retain write failures for their worker to report after terminal commit.
type TemporaryFailureRecorder interface {
	RecordFailure(context.Context, string, safediagnostic.Diagnostic) error
}

func WithTemporaryDiagnostics(runID string, recorder TemporaryFailureRecorder) ConnectionOption {
	return func(p *vaultConnections) error {
		if runID == "" || recorder == nil {
			return errors.New("temporary diagnostic run and recorder are required")
		}
		p.diagnosticRunID, p.diagnostics = runID, recorder
		return nil
	}
}

func localDiagnostic(operation, phase, validation string) safediagnostic.Diagnostic {
	return safediagnostic.Diagnostic{Operation: operation, Phase: phase, Class: safediagnostic.ClassLocalContractRejected, ValidationCode: validation}
}

func journalPersistenceDiagnostic(operation string) safediagnostic.Diagnostic {
	return safediagnostic.Diagnostic{Operation: operation, Phase: safediagnostic.PhaseJournal, Class: safediagnostic.ClassPersistenceFailed, ValidationCode: safediagnostic.ValidationJournalFailed}
}

func recordTemporaryFailure(ctx context.Context, recorder TemporaryFailureRecorder, runID string, cause error, fallback safediagnostic.Diagnostic) error {
	if cause == nil || errors.Is(cause, ErrDiagnosticPersistence) {
		return cause
	}
	diagnostic := safediagnostic.FromError(cause)
	if diagnostic == nil {
		diagnostic = &fallback
	}
	cause = safediagnostic.Wrap(cause, *diagnostic)
	if recorder == nil {
		return cause
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), failedTaskCleanupLimit)
	defer cancel()
	if err := recorder.RecordFailure(writeCtx, runID, *diagnostic); err != nil {
		// Never carry database text or a path over this boundary.
		return errors.Join(cause, ErrDiagnosticPersistence)
	}
	return cause
}

func (p *vaultConnections) recordFailure(ctx context.Context, cause error, fallback safediagnostic.Diagnostic) error {
	return recordTemporaryFailure(ctx, p.diagnostics, p.diagnosticRunID, cause, fallback)
}

const (
	TaskNotCreated         = "not_created"
	TaskCancelAcknowledged = "cancel_acknowledged"
	TaskCleanupUnconfirmed = "cleanup_unconfirmed"
)

// TemporaryTask is a protected, exact cleanup target written before creation.
// The device identity digest prevents a recovery cancel against another box.
type TemporaryTask struct {
	RunID                string `json:"runId"`
	TaskID               string `json:"taskId"`
	AlgorithmCode        string `json:"algorithmCode"`
	DeviceIdentitySHA256 string `json:"deviceIdentitySha256"`
	ConnectionEpoch      string `json:"connectionEpoch,omitempty"`
}

// TemporaryTaskJournal persists the non-replayable creation boundary and
// bounded cancellation attempts. BeforeCancel must durably reserve an attempt
// before returning true. No method may create or retry an analysis task.
type TemporaryTaskJournal interface {
	BeforeCreate(context.Context, TemporaryTask) error
	BeforeCancel(context.Context, TemporaryTask) (bool, error)
	FinishTask(context.Context, TemporaryTask, string) error
}

type ConnectionOption func(*vaultConnections) error

func WithTemporaryTaskJournal(journal TemporaryTaskJournal) ConnectionOption {
	return func(p *vaultConnections) error {
		if journal == nil {
			return errors.New("temporary task journal is required")
		}
		p.taskJournal = journal
		return nil
	}
}

// CancelRecordedTemporaryTask only cancels one previously journaled exact
// temporary task. It never creates or detects, including after restart.
func CancelRecordedTemporaryTask(ctx context.Context, vault *session.Vault, task TemporaryTask, journal TemporaryTaskJournal) (cleanupErr error) {
	defer func() {
		recorder, _ := journal.(TemporaryFailureRecorder)
		cleanupErr = recordTemporaryFailure(ctx, recorder, task.RunID, cleanupErr, localDiagnostic(safediagnostic.OperationPictureCancel, safediagnostic.PhaseSourceBinding, safediagnostic.ValidationBindingInvalid))
	}()
	if vault == nil || journal == nil || task.RunID == "" || !strings.HasPrefix(task.TaskID, "inspection-") ||
		len(task.TaskID) != len("inspection-")+32 || task.AlgorithmCode == "" || !digestPattern.MatchString(task.DeviceIdentitySHA256) {
		return ErrTemporaryCleanupUnconfirmed
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(task.TaskID, "inspection-")); err != nil {
		return ErrTemporaryCleanupUnconfirmed
	}
	ctx, cancel := context.WithTimeout(ctx, failedTaskCleanupLimit)
	defer cancel()
	connection, err := vault.InspectionConnection(ctx)
	if err != nil || connection.Client() == nil || deviceIdentityDigest(connection.Snapshot()) != task.DeviceIdentitySHA256 || task.ConnectionEpoch != "" && task.ConnectionEpoch != connectionEpoch(connection) {
		return ErrTemporaryCleanupUnconfirmed
	}
	return cancelJournaledTask(ctx, connection, task, journal)
}

func cancelJournaledTask(ctx context.Context, connection session.InspectionConnection, task TemporaryTask, journal TemporaryTaskJournal) error {
	cleanupCtx, cancel := context.WithTimeout(ctx, failedTaskCleanupLimit)
	defer cancel()
	recorder, _ := journal.(TemporaryFailureRecorder)
	if journal != nil {
		allowed, err := journal.BeforeCancel(cleanupCtx, task)
		if err != nil {
			return recordTemporaryFailure(ctx, recorder, task.RunID, ErrTemporaryCleanupUnconfirmed, journalPersistenceDiagnostic(safediagnostic.OperationPictureCancel))
		}
		if !allowed {
			return recordTemporaryFailure(ctx, recorder, task.RunID, ErrTemporaryCleanupUnconfirmed, localDiagnostic(safediagnostic.OperationPictureCancel, safediagnostic.PhaseJournal, safediagnostic.ValidationBindingInvalid))
		}
	}
	cancelErr := connection.Client().CancelPictureTaskContext(cleanupCtx, adapter.PictureTaskCancelRequest{TaskID: task.TaskID, AlgorithmCode: task.AlgorithmCode})
	cancelErr = recordTemporaryFailure(ctx, recorder, task.RunID, sanitizeDeviceError(cancelErr), safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureCancel, Phase: safediagnostic.PhaseCleanup, Class: safediagnostic.ClassOutcomeUnknown})
	disposition := TaskCancelAcknowledged
	if cancelErr != nil {
		disposition = TaskCleanupUnconfirmed
	}
	var journalErr error
	if journal != nil {
		writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), failedTaskCleanupLimit)
		journalErr = journal.FinishTask(writeCtx, task, disposition)
		writeCancel()
		if journalErr != nil {
			journalErr = recordTemporaryFailure(ctx, recorder, task.RunID, ErrTemporaryCleanupUnconfirmed, journalPersistenceDiagnostic(safediagnostic.OperationPictureCancel))
		}
	}
	if cancelErr != nil || journalErr != nil {
		return errors.Join(ErrTemporaryCleanupUnconfirmed, inspectionadapter.ErrOutcomeUnknown, cancelErr, journalErr)
	}
	return nil
}

func deviceIdentityDigest(snapshot device.Snapshot) string {
	if snapshot.Identity.Serial == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("cosmoedge-connect.temporary.device.v1\x00" + snapshot.Identity.Serial + "\x00" + snapshot.Identity.Type))
	return hex.EncodeToString(digest[:])
}

func connectionEpoch(connection session.InspectionConnection) string {
	return normalizeConnectionEpoch(connection.ConnectionEpoch())
}
func CurrentTemporaryConnectionEpoch(vault *session.Vault) (string, bool) {
	if vault == nil {
		return "", false
	}
	epoch, ok := vault.ConnectionEpoch()
	if !ok {
		return "", false
	}
	return normalizeConnectionEpoch(epoch), true
}
func normalizeConnectionEpoch(value string) string {
	if value != "" {
		return value
	}
	digest := sha256.Sum256([]byte("cosmoedge-connect.connection-epoch.unscoped.v1"))
	return hex.EncodeToString(digest[:])
}
