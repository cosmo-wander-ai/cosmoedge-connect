package observation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

type taskJournal struct {
	store         *operationStore
	diagnosticMu  sync.Mutex
	diagnosticErr error
}

func (j *taskJournal) RecordFailure(ctx context.Context, runID string, diagnostic safediagnostic.Diagnostic) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := j.store.putDiagnostic(ctx, runID, diagnostic); err != nil {
		j.diagnosticMu.Lock()
		j.diagnosticErr = livevision.ErrDiagnosticPersistence
		j.diagnosticMu.Unlock()
		return livevision.ErrDiagnosticPersistence
	}
	return nil
}

func (j *taskJournal) diagnosticFailure() error {
	j.diagnosticMu.Lock()
	defer j.diagnosticMu.Unlock()
	return j.diagnosticErr
}

func (j *taskJournal) BeforeCreate(ctx context.Context, task livevision.TemporaryTask) error {
	if _, err := j.store.byRun(ctx, task.RunID); err != nil {
		return err
	}
	raw, digest, err := canonical(task)
	if err != nil {
		return err
	}
	_, err = j.store.db.ExecContext(ctx, `INSERT INTO temporary_tasks(task_id,run_id,task_json,task_sha256,disposition,cancel_attempts) VALUES(?,?,?,?,'reserved',0)`, task.TaskID, task.RunID, raw, digest)
	return err
}
func (j *taskJournal) BeforeCancel(ctx context.Context, task livevision.TemporaryTask) (bool, error) {
	_, digest, err := canonical(task)
	if err != nil {
		return false, err
	}
	result, err := j.store.db.ExecContext(ctx, `UPDATE temporary_tasks SET cancel_attempts=cancel_attempts+1,disposition='cleanup_unconfirmed' WHERE task_id=? AND run_id=? AND task_sha256=? AND disposition IN ('reserved','cleanup_unconfirmed') AND cancel_attempts<2`, task.TaskID, task.RunID, digest)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}
func (j *taskJournal) FinishTask(ctx context.Context, task livevision.TemporaryTask, disposition string) error {
	if disposition != livevision.TaskNotCreated && disposition != livevision.TaskCancelAcknowledged && disposition != livevision.TaskCleanupUnconfirmed {
		return ErrInvalidRequest
	}
	_, digest, err := canonical(task)
	if err != nil {
		return err
	}
	result, err := j.store.db.ExecContext(ctx, `UPDATE temporary_tasks SET disposition=? WHERE task_id=? AND run_id=? AND task_sha256=?`, disposition, task.TaskID, task.RunID, digest)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNotFound
	}
	return nil
}
func (j *taskJournal) status(ctx context.Context, run string) (string, error) {
	taskStatus, err := j.taskStatus(ctx, run)
	if err != nil {
		return "", err
	}
	uploadStatus, err := j.uploadStatus(ctx, run)
	if err != nil {
		return "", err
	}
	if taskStatus == livevision.TaskCleanupUnconfirmed || uploadStatus == livevision.UploadCleanupUnconfirmed {
		return livevision.TaskCleanupUnconfirmed, nil
	}
	if taskStatus == "not_started" && uploadStatus != "not_started" {
		return uploadStatus, nil
	}
	return taskStatus, nil
}
func (j *taskJournal) taskStatus(ctx context.Context, run string) (string, error) {
	var disposition string
	err := j.store.db.QueryRowContext(ctx, `SELECT disposition FROM temporary_tasks WHERE run_id=?`, run).Scan(&disposition)
	if errors.Is(err, sql.ErrNoRows) {
		return "not_started", nil
	}
	if disposition == "reserved" {
		disposition = livevision.TaskCleanupUnconfirmed
	}
	return disposition, err
}
func (j *taskJournal) pending(ctx context.Context, epoch string) ([]livevision.TemporaryTask, error) {
	rows, err := j.store.db.QueryContext(ctx, `SELECT task_json,task_sha256 FROM temporary_tasks WHERE disposition IN ('reserved','cleanup_unconfirmed') AND cancel_attempts<2 AND json_extract(task_json,'$.connectionEpoch')=? ORDER BY rowid LIMIT 16`, epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []livevision.TemporaryTask{}
	for rows.Next() {
		var raw []byte
		var digest string
		if err := rows.Scan(&raw, &digest); err != nil {
			return nil, err
		}
		var task livevision.TemporaryTask
		if len(raw) > 4096 || json.Unmarshal(raw, &task) != nil {
			return nil, ErrUnavailable
		}
		_, computed, err := canonical(task)
		if err != nil || computed != digest {
			return nil, ErrUnavailable
		}
		if task.ConnectionEpoch == "" {
			continue
		} // Pre-epoch cleanup remains unconfirmed, never retargeted.
		result = append(result, task)
	}
	return result, rows.Err()
}

var _ livevision.TemporaryTaskJournal = (*taskJournal)(nil)
