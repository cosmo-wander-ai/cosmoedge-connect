package store

const (
	schemaVersion     = 5
	storeSchemaID     = "cosmoedge.inspection.store.v2"
	storeSchemaSHA256 = "9f58aa99f40bc76fb59116dea6d3421140f0815cc84595477b22621ecbb096e9"
)

var expectedInspectionTables = map[string][]string{
	"inspection_store_meta":           {"schema", "version", "schema_sha256", "created_at"},
	"inspection_templates":            {"tenant_id", "template_id", "revision", "state", "content_sha256", "template_json", "created_at"},
	"inspection_assignments":          {"tenant_id", "assignment_id", "revision", "template_id", "template_revision", "site_id", "published", "content_sha256", "assignment_json", "created_at"},
	"inspection_runs":                 {"run_id", "tenant_id", "site_id", "request_key", "plan_sha256", "plan_json", "state", "conclusion", "reason", "persistent_config_writes", "temporary_resources", "cleanup_pending", "outcome_json", "lease_owner", "lease_expires_at", "authority_release_state", "authority_released_at", "deadline", "created_at", "updated_at"},
	"inspection_steps":                {"run_id", "step_id", "sequence", "kind", "authority", "state", "attempt_count", "output_json", "output_sha256", "reason", "lease_owner", "lease_expires_at", "created_at", "updated_at"},
	"inspection_step_attempts":        {"attempt_id", "run_id", "step_id", "attempt_number", "state", "owner", "lease_expires_at", "output_json", "output_sha256", "reason", "started_at", "updated_at", "finished_at"},
	"inspection_step_reconciliations": {"reconciliation_id", "run_id", "step_id", "attempt_id", "decision", "reconciled_by", "output_json", "output_sha256", "reason", "created_at"},
	"inspection_run_events":           {"sequence", "run_id", "event_type", "from_state", "to_state", "phase", "reason", "occurred_at", "public_json"},
	"inspection_results":              {"observation_id", "result_id", "run_id", "target_id", "criterion_id", "sample_id", "usage", "output_kind", "assessment", "content_sha256", "result_json", "captured_at", "observed_at", "recorded_at"},
	"inspection_result_media":         {"observation_id", "ordinal", "media_ref", "content_sha256", "source_ref", "captured_at"},
	"inspection_outbox":               {"message_id", "run_id", "topic", "payload_json", "content_sha256", "state", "attempts", "available_at", "lease_owner", "lease_expires_at", "created_at", "materialized_at"},
}

var expectedInspectionTriggers = []string{
	"inspection_assignments_no_delete",
	"inspection_assignments_no_update",
	"inspection_result_media_no_delete",
	"inspection_result_media_no_update",
	"inspection_results_no_delete",
	"inspection_results_no_update",
	"inspection_run_events_no_delete",
	"inspection_run_events_no_update",
	"inspection_runs_authority_no_reopen",
	"inspection_step_attempts_no_delete",
	"inspection_step_reconciliations_no_delete",
	"inspection_step_reconciliations_no_update",
	"inspection_store_meta_no_delete",
	"inspection_store_meta_no_update",
	"inspection_templates_no_delete",
	"inspection_templates_no_update",
}

var expectedInspectionIndexes = map[string][]string{
	"inspection_outbox_lease_idx":              {"state", "lease_expires_at", "message_id"},
	"inspection_outbox_pending_idx":            {"state", "available_at", "message_id"},
	"inspection_result_media_ref_idx":          {"media_ref", "observation_id"},
	"inspection_results_run_idx":               {"run_id", "observed_at", "observation_id"},
	"inspection_run_events_run_idx":            {"run_id", "sequence"},
	"inspection_runs_lease_idx":                {"state", "lease_expires_at"},
	"inspection_runs_authority_release_idx":    {"authority_release_state", "state", "run_id"},
	"inspection_runs_queue_idx":                {"state", "created_at", "run_id"},
	"inspection_step_attempts_lease_idx":       {"state", "lease_expires_at"},
	"inspection_step_attempts_step_idx":        {"run_id", "step_id", "attempt_number"},
	"inspection_step_reconciliations_step_idx": {"run_id", "step_id", "created_at"},
	"inspection_steps_lease_idx":               {"state", "lease_expires_at"},
	"inspection_steps_ready_idx":               {"run_id", "state", "sequence"},
}

const schemaV5 = `
CREATE TABLE inspection_store_meta (
    schema TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    schema_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER inspection_store_meta_no_update BEFORE UPDATE ON inspection_store_meta
BEGIN SELECT RAISE(ABORT, 'inspection store metadata is immutable'); END;
CREATE TRIGGER inspection_store_meta_no_delete BEFORE DELETE ON inspection_store_meta
BEGIN SELECT RAISE(ABORT, 'inspection store metadata is immutable'); END;

CREATE TABLE inspection_templates (
    tenant_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    state TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    template_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, template_id, revision)
);
CREATE TRIGGER inspection_templates_no_update BEFORE UPDATE ON inspection_templates
BEGIN SELECT RAISE(ABORT, 'inspection templates are immutable'); END;
CREATE TRIGGER inspection_templates_no_delete BEFORE DELETE ON inspection_templates
BEGIN SELECT RAISE(ABORT, 'inspection templates are immutable'); END;

CREATE TABLE inspection_assignments (
    tenant_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    template_id TEXT NOT NULL,
    template_revision INTEGER NOT NULL CHECK(template_revision >= 1),
    site_id TEXT NOT NULL,
    published INTEGER NOT NULL CHECK(published IN (0, 1)),
    content_sha256 TEXT NOT NULL,
    assignment_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, assignment_id, revision)
);
CREATE TRIGGER inspection_assignments_no_update BEFORE UPDATE ON inspection_assignments
BEGIN SELECT RAISE(ABORT, 'inspection assignments are immutable'); END;
CREATE TRIGGER inspection_assignments_no_delete BEFORE DELETE ON inspection_assignments
BEGIN SELECT RAISE(ABORT, 'inspection assignments are immutable'); END;

CREATE TABLE inspection_runs (
    run_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    state TEXT NOT NULL,
    conclusion TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    persistent_config_writes INTEGER NOT NULL DEFAULT 0 CHECK(persistent_config_writes = 0),
    temporary_resources INTEGER NOT NULL DEFAULT 0 CHECK(temporary_resources >= 0),
    cleanup_pending INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_pending >= 0 AND cleanup_pending <= temporary_resources),
    outcome_json TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    authority_release_state TEXT NOT NULL DEFAULT 'pending' CHECK(authority_release_state IN ('pending','released')),
    authority_released_at TEXT NOT NULL DEFAULT '',
    deadline TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK((authority_release_state='pending' AND authority_released_at='') OR
          (authority_release_state='released' AND authority_released_at<>'')),
    UNIQUE (tenant_id, request_key)
);
CREATE INDEX inspection_runs_queue_idx ON inspection_runs(state, created_at, run_id);
CREATE INDEX inspection_runs_lease_idx ON inspection_runs(state, lease_expires_at);
CREATE INDEX inspection_runs_authority_release_idx ON inspection_runs(authority_release_state, state, run_id);
CREATE TRIGGER inspection_runs_authority_no_reopen BEFORE UPDATE OF authority_release_state, authority_released_at ON inspection_runs
WHEN OLD.authority_release_state='released' AND
     (NEW.authority_release_state<>'released' OR NEW.authority_released_at<>OLD.authority_released_at)
BEGIN SELECT RAISE(ABORT, 'inspection run authority release is irreversible'); END;

CREATE TABLE inspection_steps (
    run_id TEXT NOT NULL REFERENCES inspection_runs(run_id) ON DELETE RESTRICT,
    step_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence >= 1),
    kind TEXT NOT NULL,
    authority TEXT NOT NULL,
    state TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    output_json TEXT NOT NULL DEFAULT '[]',
    output_sha256 TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    lease_owner TEXT,
    lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (run_id, step_id),
    UNIQUE (run_id, sequence)
);
CREATE INDEX inspection_steps_ready_idx ON inspection_steps(run_id, state, sequence);
CREATE INDEX inspection_steps_lease_idx ON inspection_steps(state, lease_expires_at);

CREATE TABLE inspection_step_attempts (
    attempt_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
    state TEXT NOT NULL,
    owner TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    output_json TEXT NOT NULL DEFAULT '[]',
    output_sha256 TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (run_id, step_id) REFERENCES inspection_steps(run_id, step_id) ON DELETE RESTRICT,
    UNIQUE (run_id, step_id, attempt_number)
);
CREATE INDEX inspection_step_attempts_step_idx ON inspection_step_attempts(run_id, step_id, attempt_number);
CREATE INDEX inspection_step_attempts_lease_idx ON inspection_step_attempts(state, lease_expires_at);
CREATE TRIGGER inspection_step_attempts_no_delete BEFORE DELETE ON inspection_step_attempts
BEGIN SELECT RAISE(ABORT, 'inspection step attempts are append-only'); END;

CREATE TABLE inspection_step_reconciliations (
    reconciliation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL REFERENCES inspection_step_attempts(attempt_id) ON DELETE RESTRICT,
    decision TEXT NOT NULL,
    reconciled_by TEXT NOT NULL,
    output_json TEXT NOT NULL DEFAULT '[]',
    output_sha256 TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id, step_id) REFERENCES inspection_steps(run_id, step_id) ON DELETE RESTRICT,
    UNIQUE (attempt_id)
);
CREATE INDEX inspection_step_reconciliations_step_idx ON inspection_step_reconciliations(run_id, step_id, created_at);
CREATE TRIGGER inspection_step_reconciliations_no_update BEFORE UPDATE ON inspection_step_reconciliations
BEGIN SELECT RAISE(ABORT, 'inspection step reconciliations are append-only'); END;
CREATE TRIGGER inspection_step_reconciliations_no_delete BEFORE DELETE ON inspection_step_reconciliations
BEGIN SELECT RAISE(ABORT, 'inspection step reconciliations are append-only'); END;

CREATE TABLE inspection_run_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES inspection_runs(run_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL,
    from_state TEXT NOT NULL DEFAULT '',
    to_state TEXT NOT NULL DEFAULT '',
    phase TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    public_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX inspection_run_events_run_idx ON inspection_run_events(run_id, sequence);
CREATE TRIGGER inspection_run_events_no_update BEFORE UPDATE ON inspection_run_events
BEGIN SELECT RAISE(ABORT, 'inspection run events are append-only'); END;
CREATE TRIGGER inspection_run_events_no_delete BEFORE DELETE ON inspection_run_events
BEGIN SELECT RAISE(ABORT, 'inspection run events are append-only'); END;

CREATE TABLE inspection_results (
    observation_id TEXT PRIMARY KEY,
    result_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL REFERENCES inspection_runs(run_id) ON DELETE RESTRICT,
    target_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    sample_id TEXT NOT NULL,
    usage TEXT NOT NULL,
    output_kind TEXT NOT NULL,
    assessment TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    result_json TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    UNIQUE (run_id, target_id, criterion_id, sample_id)
);
CREATE INDEX inspection_results_run_idx ON inspection_results(run_id, observed_at, observation_id);
CREATE TRIGGER inspection_results_no_update BEFORE UPDATE ON inspection_results
BEGIN SELECT RAISE(ABORT, 'inspection results are append-only'); END;
CREATE TRIGGER inspection_results_no_delete BEFORE DELETE ON inspection_results
BEGIN SELECT RAISE(ABORT, 'inspection results are append-only'); END;

CREATE TABLE inspection_result_media (
    observation_id TEXT NOT NULL REFERENCES inspection_results(observation_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
    media_ref TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    PRIMARY KEY (observation_id, ordinal),
    UNIQUE (observation_id, media_ref)
);
CREATE INDEX inspection_result_media_ref_idx ON inspection_result_media(media_ref, observation_id);
CREATE TRIGGER inspection_result_media_no_update BEFORE UPDATE ON inspection_result_media
BEGIN SELECT RAISE(ABORT, 'inspection result media bindings are append-only'); END;
CREATE TRIGGER inspection_result_media_no_delete BEFORE DELETE ON inspection_result_media
BEGIN SELECT RAISE(ABORT, 'inspection result media bindings are append-only'); END;

CREATE TABLE inspection_outbox (
    message_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES inspection_runs(run_id) ON DELETE RESTRICT,
    topic TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK(attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    materialized_at TEXT NOT NULL
);
CREATE INDEX inspection_outbox_pending_idx ON inspection_outbox(state, available_at, message_id);
CREATE INDEX inspection_outbox_lease_idx ON inspection_outbox(state, lease_expires_at, message_id);
`
