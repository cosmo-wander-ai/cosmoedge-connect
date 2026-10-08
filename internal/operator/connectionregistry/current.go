package connectionregistry

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	_ "modernc.org/sqlite"
)

// CurrentStore selects exactly one current profile. Old profiles, credentials
// and onboarding sagas remain intact; this store contains no secret material.
type CurrentStore struct{ db *sql.DB }
type Selection struct {
	ProfileID string
	Revision  uint64
}

const currentSchema = `CREATE TABLE current_connection (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0));
CREATE TABLE replacements (
 operation_id TEXT PRIMARY KEY, previous_profile_id TEXT NOT NULL,
 previous_revision INTEGER NOT NULL, new_profile_id TEXT NOT NULL UNIQUE,
 target_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','switched')),
 created_at TEXT NOT NULL, switched_at TEXT NOT NULL DEFAULT '');`

func OpenCurrentStore(path, initialProfileID string) (*CurrentStore, error) {
	if !profileIDPattern.MatchString(initialProfileID) {
		return nil, ErrInvalidConfig
	}
	if err := localstate.PrepareStateRoot(filepath.Dir(path)); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		if err := localstate.ProtectFile(path); err != nil {
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
	fail := func(err error) (*CurrentStore, error) { _ = db.Close(); return nil, err }
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA trusted_schema=OFF", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL"} {
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
		if _, err := tx.Exec(currentSchema); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec("INSERT INTO current_connection(singleton,profile_id,revision) VALUES(1,?,1)", initialProfileID); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec("PRAGMA user_version=1"); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec("PRAGMA application_id=1396918867"); err != nil {
			return fail(err)
		}
		if err := tx.Commit(); err != nil {
			return fail(err)
		}
	} else if version != 1 || appID != 1396918867 {
		return fail(ErrInvalidConfig)
	}
	s := &CurrentStore{db: db}
	if _, err := s.Current(context.Background()); err != nil {
		return fail(err)
	}
	return s, nil
}
func (s *CurrentStore) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}
func (s *CurrentStore) Current(ctx context.Context) (Selection, error) {
	var value Selection
	err := s.db.QueryRowContext(ctx, "SELECT profile_id,revision FROM current_connection WHERE singleton=1").Scan(&value.ProfileID, &value.Revision)
	if err != nil {
		return Selection{}, err
	}
	if !profileIDPattern.MatchString(value.ProfileID) || value.Revision == 0 {
		return Selection{}, ErrBindingConflict
	}
	return value, nil
}
func (s *CurrentStore) prepare(ctx context.Context, expected Selection, operationID, newProfileID, targetDigest string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current Selection
	if err := tx.QueryRowContext(ctx, "SELECT profile_id,revision FROM current_connection WHERE singleton=1").Scan(&current.ProfileID, &current.Revision); err != nil {
		return err
	}
	if current != expected {
		return ErrBindingConflict
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM replacements").Scan(&count); err != nil {
		return err
	}
	if count >= 10000 {
		return ErrSavedConnectionAttention
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO replacements(operation_id,previous_profile_id,previous_revision,new_profile_id,target_digest,state,created_at) VALUES(?,?,?,?,?,'prepared',?)`, operationID, expected.ProfileID, expected.Revision, newProfileID, targetDigest, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *CurrentStore) switchCurrent(ctx context.Context, expected Selection, operationID, newProfileID, targetDigest string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE replacements SET state='switched',switched_at=? WHERE operation_id=? AND previous_profile_id=? AND previous_revision=? AND new_profile_id=? AND target_digest=? AND state='prepared'`, time.Now().UTC().Format(time.RFC3339Nano), operationID, expected.ProfileID, expected.Revision, newProfileID, targetDigest)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrBindingConflict
	}
	result, err = tx.ExecContext(ctx, "UPDATE current_connection SET profile_id=?,revision=revision+1 WHERE singleton=1 AND profile_id=? AND revision=?", newProfileID, expected.ProfileID, expected.Revision)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrBindingConflict
	}
	return tx.Commit()
}
