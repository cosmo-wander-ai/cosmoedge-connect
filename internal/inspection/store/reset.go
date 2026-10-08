package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
)

const DevelopmentResetConfirmation = "RESET INSPECTION V2 DEVELOPMENT STATE"

var resetInspectionStatements = []string{
	"DROP TRIGGER inspection_assignments_no_delete",
	"DROP TRIGGER inspection_assignments_no_update",
	"DROP TRIGGER inspection_result_media_no_delete",
	"DROP TRIGGER inspection_result_media_no_update",
	"DROP TRIGGER inspection_results_no_delete",
	"DROP TRIGGER inspection_results_no_update",
	"DROP TRIGGER inspection_run_events_no_delete",
	"DROP TRIGGER inspection_run_events_no_update",
	"DROP TRIGGER inspection_step_attempts_no_delete",
	"DROP TRIGGER inspection_step_reconciliations_no_delete",
	"DROP TRIGGER inspection_step_reconciliations_no_update",
	"DROP TRIGGER inspection_store_meta_no_delete",
	"DROP TRIGGER inspection_store_meta_no_update",
	"DROP TRIGGER inspection_templates_no_delete",
	"DROP TRIGGER inspection_templates_no_update",
	"DROP TABLE inspection_result_media",
	"DROP TABLE inspection_outbox",
	"DROP TABLE inspection_results",
	"DROP TABLE inspection_run_events",
	"DROP TABLE inspection_step_reconciliations",
	"DROP TABLE inspection_step_attempts",
	"DROP TABLE inspection_steps",
	"DROP TABLE inspection_runs",
	"DROP TABLE inspection_assignments",
	"DROP TABLE inspection_templates",
	"DROP TABLE inspection_store_meta",
}

// ResetDevelopmentState replaces an exact, validated v2 inspection schema
// with a fresh v2 schema in one transaction. It never accepts an old or
// approximate schema and never drops non-inspection objects in the database.
func ResetDevelopmentState(ctx context.Context, path, confirmation string) error {
	if confirmation != DevelopmentResetConfirmation {
		return errors.New("exact inspection development reset confirmation is required")
	}
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "?#\x00") {
		return errors.New("inspection store path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root := filepath.Dir(absolute)
	if err := localstate.ValidateStateRoot(root); err != nil {
		return fmt.Errorf("reject inspection development reset root: %w", err)
	}
	if _, err := os.Lstat(absolute); err != nil {
		return fmt.Errorf("reject inspection development reset database: %w", err)
	}
	if err := localstate.ValidateFile(absolute); err != nil {
		return fmt.Errorf("reject inspection development reset database: %w", err)
	}

	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return err
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := database.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure inspection development reset: %w", err)
		}
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateSchemaShapeTx(ctx, tx); err != nil {
		return fmt.Errorf("refuse inspection development reset of unverified state: %w", err)
	}
	var integrity string
	if err := tx.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("refuse inspection development reset of corrupt state: result=%q error=%w", integrity, err)
	}
	for _, statement := range resetInspectionStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("reset exact inspection v2 state: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, schemaV5); err != nil {
		return fmt.Errorf("recreate exact inspection v2 state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO inspection_store_meta(schema, version, schema_sha256, created_at) VALUES(?, ?, ?, ?)`,
		storeSchemaID, schemaVersion, storeSchemaSHA256, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	if err := validateSchemaShapeTx(ctx, tx); err != nil {
		return fmt.Errorf("verify recreated inspection v2 state: %w", err)
	}
	return tx.Commit()
}
