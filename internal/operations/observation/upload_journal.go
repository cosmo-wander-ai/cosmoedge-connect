package observation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/livevision"
)

const uploadSchema = `CREATE TABLE temporary_uploads (
 client_request_id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE REFERENCES operations(run_id),
 owner_hash TEXT NOT NULL, connection_epoch TEXT NOT NULL,
 upload_json BLOB NOT NULL, upload_sha256 TEXT NOT NULL,
 disposition TEXT NOT NULL CHECK(disposition IN ('reserved','cancel_acknowledged','cleanup_unconfirmed')),
 cancel_attempts INTEGER NOT NULL CHECK(cancel_attempts>=0 AND cancel_attempts<=2)
);`

func openUploadExtension(db *sql.DB) error {
	// Like failure diagnostics, upload cleanup has its own additive version.
	// Existing core records and PRAGMA user_version=1 are never rewritten.
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	err = tx.QueryRow(`SELECT version FROM observation_extensions WHERE name='temporary_uploads'`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.Exec(uploadSchema); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO observation_extensions(name,version) VALUES('temporary_uploads',1)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if version != 1 {
		return errors.New("observation upload extension is incompatible")
	}
	rows, err := tx.Query(`SELECT client_request_id,run_id,owner_hash,connection_epoch,upload_json,upload_sha256,disposition,cancel_attempts FROM temporary_uploads LIMIT 0`)
	if err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	return tx.Commit()
}

func (j *taskJournal) validateUploadOwner(ctx context.Context, upload livevision.TemporaryUpload) error {
	if upload.Validate() != nil {
		return ErrInvalidRequest
	}
	value, err := j.store.byRun(ctx, upload.RunID)
	if err != nil {
		return err
	}
	if value.OwnerHash != upload.OwnerHash || value.Source.DeviceIdentitySHA256 != upload.DeviceIdentitySHA256 || value.Source.ConnectionEpoch != upload.ConnectionEpoch {
		return ErrInvalidRequest
	}
	return nil
}

func (j *taskJournal) BeforeUpload(ctx context.Context, upload livevision.TemporaryUpload) error {
	if err := j.validateUploadOwner(ctx, upload); err != nil {
		return err
	}
	if upload.Upload.UploadID != "" || upload.Upload.NextChunkIndex != 0 || upload.Upload.TotalChunks != 0 || upload.Upload.Complete {
		return ErrInvalidRequest
	}
	raw, digest, err := canonical(upload)
	if err != nil {
		return err
	}
	_, err = j.store.db.ExecContext(ctx, `INSERT INTO temporary_uploads(client_request_id,run_id,owner_hash,connection_epoch,upload_json,upload_sha256,disposition,cancel_attempts) VALUES(?,?,?,?,?,?,'reserved',0)`, upload.Upload.ClientRequestID, upload.RunID, upload.OwnerHash, upload.ConnectionEpoch, raw, digest)
	return err
}

func scanUpload(row scanner) (livevision.TemporaryUpload, string, string, int, error) {
	var alias, run, owner, epoch, digest, disposition string
	var raw []byte
	var attempts int
	var upload livevision.TemporaryUpload
	if err := row.Scan(&alias, &run, &owner, &epoch, &raw, &digest, &disposition, &attempts); err != nil {
		return upload, "", "", 0, err
	}
	if len(raw) > 4096 || json.Unmarshal(raw, &upload) != nil || upload.Validate() != nil {
		return upload, "", "", 0, ErrUnavailable
	}
	_, computed, err := canonical(upload)
	if err != nil || computed != digest || alias != upload.Upload.ClientRequestID || run != upload.RunID || owner != upload.OwnerHash || epoch != upload.ConnectionEpoch || attempts < 0 || attempts > 2 || (disposition != "reserved" && disposition != livevision.UploadCancelAcknowledged && disposition != livevision.UploadCleanupUnconfirmed) {
		return upload, "", "", 0, ErrUnavailable
	}
	return upload, digest, disposition, attempts, nil
}

const uploadColumns = "client_request_id,run_id,owner_hash,connection_epoch,upload_json,upload_sha256,disposition,cancel_attempts"

func (j *taskJournal) RecordUpload(ctx context.Context, upload livevision.TemporaryUpload) error {
	if err := j.validateUploadOwner(ctx, upload); err != nil {
		return err
	}
	old, oldDigest, disposition, attempts, err := scanUpload(j.store.db.QueryRowContext(ctx, "SELECT "+uploadColumns+" FROM temporary_uploads WHERE client_request_id=?", upload.Upload.ClientRequestID))
	if err != nil {
		return err
	}
	if disposition != "reserved" || attempts != 0 || old.RunID != upload.RunID || old.OwnerHash != upload.OwnerHash || old.DeviceIdentitySHA256 != upload.DeviceIdentitySHA256 || old.ConnectionEpoch != upload.ConnectionEpoch || old.Upload.SHA256 != upload.Upload.SHA256 || old.Upload.SizeBytes != upload.Upload.SizeBytes || (old.Upload.UploadID != "" && old.Upload.UploadID != upload.Upload.UploadID) || (old.Upload.TotalChunks != 0 && old.Upload.TotalChunks != upload.Upload.TotalChunks) || upload.Upload.NextChunkIndex < old.Upload.NextChunkIndex || (old.Upload.Complete && !upload.Upload.Complete) {
		return ErrInvalidRequest
	}
	raw, digest, err := canonical(upload)
	if err != nil {
		return err
	}
	result, err := j.store.db.ExecContext(ctx, `UPDATE temporary_uploads SET upload_json=?,upload_sha256=? WHERE client_request_id=? AND upload_sha256=? AND disposition='reserved' AND cancel_attempts=0`, raw, digest, upload.Upload.ClientRequestID, oldDigest)
	return uploadUpdated(result, err)
}

func (j *taskJournal) BeforeUploadCancel(ctx context.Context, upload livevision.TemporaryUpload) (bool, error) {
	if err := j.validateUploadOwner(ctx, upload); err != nil {
		return false, err
	}
	_, digest, err := canonical(upload)
	if err != nil {
		return false, err
	}
	result, err := j.store.db.ExecContext(ctx, `UPDATE temporary_uploads SET cancel_attempts=cancel_attempts+1,disposition='cleanup_unconfirmed' WHERE client_request_id=? AND run_id=? AND owner_hash=? AND upload_sha256=? AND disposition IN ('reserved','cleanup_unconfirmed') AND cancel_attempts<2`, upload.Upload.ClientRequestID, upload.RunID, upload.OwnerHash, digest)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (j *taskJournal) FinishUpload(ctx context.Context, upload livevision.TemporaryUpload, disposition string) error {
	if disposition != livevision.UploadCancelAcknowledged && disposition != livevision.UploadCleanupUnconfirmed {
		return ErrInvalidRequest
	}
	if err := j.validateUploadOwner(ctx, upload); err != nil {
		return err
	}
	_, digest, err := canonical(upload)
	if err != nil {
		return err
	}
	result, err := j.store.db.ExecContext(ctx, `UPDATE temporary_uploads SET disposition=? WHERE client_request_id=? AND run_id=? AND owner_hash=? AND upload_sha256=? AND disposition='cleanup_unconfirmed' AND cancel_attempts>0`, disposition, upload.Upload.ClientRequestID, upload.RunID, upload.OwnerHash, digest)
	return uploadUpdated(result, err)
}

func uploadUpdated(result sql.Result, err error) error {
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

func (j *taskJournal) pendingUploads(ctx context.Context, epoch string) ([]livevision.TemporaryUpload, error) {
	rows, err := j.store.db.QueryContext(ctx, "SELECT "+uploadColumns+" FROM temporary_uploads WHERE connection_epoch=? AND disposition IN ('reserved','cleanup_unconfirmed') AND cancel_attempts<2 ORDER BY rowid LIMIT 16", epoch)
	if err != nil {
		return nil, err
	}
	var uploads []livevision.TemporaryUpload
	for rows.Next() {
		upload, _, _, _, err := scanUpload(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		uploads = append(uploads, upload)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	for _, upload := range uploads {
		if err := j.validateUploadOwner(ctx, upload); err != nil {
			return nil, err
		}
	}
	return uploads, nil
}

func (j *taskJournal) uploadStatus(ctx context.Context, run string) (string, error) {
	_, _, disposition, _, err := scanUpload(j.store.db.QueryRowContext(ctx, "SELECT "+uploadColumns+" FROM temporary_uploads WHERE run_id=?", run))
	if errors.Is(err, sql.ErrNoRows) {
		return "not_started", nil
	}
	if disposition == "reserved" {
		disposition = livevision.UploadCleanupUnconfirmed
	}
	return disposition, err
}

var _ livevision.TemporaryUploadJournal = (*taskJournal)(nil)
