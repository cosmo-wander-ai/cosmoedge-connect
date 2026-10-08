package dataset

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
	_ "modernc.org/sqlite"
)

const (
	datasetDatabaseVersion       = 3
	datasetDatabaseApplicationID = 0x43454433 // CED3
	maximumStoredDatasetBytes    = 16 << 20
	maximumStoredDatasets        = 10_000
	maximumStoredReviews         = 100_000
	maximumStoredReviewBytes     = 64 << 10
	maximumStoredLedgerRows      = 2_000_000
	maximumStoredRepositoryBytes = 1 << 30
	maximumAdmissionBytes        = 64 << 20
	datasetTimestampLayout       = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	ErrUnsupportedRepositorySchema = errors.New("unsupported dataset repository schema")
	ErrCorruptRepository           = errors.New("dataset repository integrity failure")
	ErrCreateFailed                = errors.New("dataset create definitely failed")
	ErrCreateOutcomeUnknown        = errors.New("dataset create outcome is unknown")
	ErrPurgeFailed                 = errors.New("dataset purge definitely failed")
	ErrPurgeOutcomeUnknown         = errors.New("dataset purge outcome is unknown")
)

var protectedDatasetPayload = regexp.MustCompile(`(?i)(?:https?|rtsps?|file|data):|"(?:tenantId|siteId|sourceRef|reviewerSha256|descriptorSha256|labelSha256|authorityRef|principalSha256|password|token|credential|endpoint|path|url|base64|bytes)"\s*:`)

const (
	createRepositoryControl = `CREATE TABLE repository_control (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    write_lock INTEGER NOT NULL CHECK(write_lock=0)
)`
	createDatasetRecords = `CREATE TABLE dataset_records (
    tenant_stratum TEXT NOT NULL,
    site_stratum TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    purpose_ref TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    retain_until TEXT NOT NULL,
    governance_state TEXT NOT NULL CHECK(governance_state IN ('active','purge_submitting','tombstoned')),
    created_at TEXT NOT NULL,
    tombstoned_at TEXT,
    content_sha256 TEXT NOT NULL,
    projection_sha256 TEXT NOT NULL,
    claims_sha256 TEXT NOT NULL,
    intervals_sha256 TEXT NOT NULL,
    reviews_sha256 TEXT NOT NULL,
    dataset_json BLOB,
    PRIMARY KEY(tenant_stratum, site_stratum, dataset_id, revision),
    CHECK((governance_state='active' AND dataset_json IS NOT NULL AND tombstoned_at IS NULL) OR
          (governance_state='purge_submitting' AND dataset_json IS NOT NULL AND tombstoned_at IS NULL) OR
          (governance_state='tombstoned' AND dataset_json IS NULL AND tombstoned_at IS NOT NULL))
)`
	createDatasetItems = `CREATE TABLE dataset_items (
    tenant_stratum TEXT NOT NULL,
    site_stratum TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    item_id TEXT NOT NULL,
    media_ref TEXT NOT NULL,
    item_sha256 TEXT NOT NULL,
    PRIMARY KEY(tenant_stratum, site_stratum, dataset_id, revision, ordinal),
    UNIQUE(tenant_stratum, site_stratum, dataset_id, revision, item_id),
    UNIQUE(tenant_stratum, site_stratum, dataset_id, revision, media_ref),
    FOREIGN KEY(tenant_stratum, site_stratum, dataset_id, revision)
        REFERENCES dataset_records(tenant_stratum, site_stratum, dataset_id, revision) ON DELETE RESTRICT
)`
	createDatasetAnnotations = `CREATE TABLE dataset_annotations (
    tenant_stratum TEXT NOT NULL,
    site_stratum TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    item_ordinal INTEGER NOT NULL CHECK(item_ordinal >= 0),
    annotation_ordinal INTEGER NOT NULL CHECK(annotation_ordinal >= 0),
    annotation_id TEXT NOT NULL,
    annotation_sha256 TEXT NOT NULL,
    projection_sha256 TEXT NOT NULL,
    PRIMARY KEY(tenant_stratum, site_stratum, dataset_id, revision, item_ordinal, annotation_ordinal),
    UNIQUE(tenant_stratum, site_stratum, dataset_id, revision, item_ordinal, annotation_id),
    FOREIGN KEY(tenant_stratum, site_stratum, dataset_id, revision, item_ordinal)
        REFERENCES dataset_items(tenant_stratum, site_stratum, dataset_id, revision, ordinal) ON DELETE RESTRICT
)`
	createIdentityLedger = `CREATE TABLE identity_ledger (
    identity_kind TEXT NOT NULL,
    identity_sha256 TEXT NOT NULL,
    split TEXT NOT NULL CHECK(split IN ('train','validation','test')),
    first_claimed_at TEXT NOT NULL,
    first_tenant_stratum TEXT NOT NULL,
    first_site_stratum TEXT NOT NULL,
    first_dataset_id TEXT NOT NULL,
    first_revision INTEGER NOT NULL CHECK(first_revision >= 1),
    provenance_sha256 TEXT NOT NULL,
    PRIMARY KEY(identity_kind, identity_sha256)
)`
	createDatasetClaims = `CREATE TABLE dataset_identity_claims (
    tenant_stratum TEXT NOT NULL,
    site_stratum TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    identity_kind TEXT NOT NULL,
    identity_sha256 TEXT NOT NULL,
    split TEXT NOT NULL CHECK(split IN ('train','validation','test')),
    claim_sha256 TEXT NOT NULL,
    PRIMARY KEY(tenant_stratum, site_stratum, dataset_id, revision, ordinal),
    UNIQUE(tenant_stratum, site_stratum, dataset_id, revision, identity_kind, identity_sha256),
    FOREIGN KEY(tenant_stratum, site_stratum, dataset_id, revision)
        REFERENCES dataset_records(tenant_stratum, site_stratum, dataset_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY(identity_kind, identity_sha256)
        REFERENCES identity_ledger(identity_kind, identity_sha256) ON DELETE RESTRICT
)`
	createSourceIntervalLedger = `CREATE TABLE source_interval_ledger (
    source_sha256 TEXT NOT NULL,
    interval_sha256 TEXT NOT NULL,
    split TEXT NOT NULL CHECK(split IN ('train','validation','test')),
    window_start_ns INTEGER NOT NULL,
    window_end_ns INTEGER NOT NULL,
    guard_start_ns INTEGER NOT NULL,
    guard_end_ns INTEGER NOT NULL,
    adjacency_seconds INTEGER NOT NULL CHECK(adjacency_seconds >= 0 AND adjacency_seconds <= 604800),
    first_claimed_at TEXT NOT NULL,
    first_tenant_stratum TEXT NOT NULL,
    first_site_stratum TEXT NOT NULL,
    first_dataset_id TEXT NOT NULL,
    first_revision INTEGER NOT NULL CHECK(first_revision >= 1),
    provenance_sha256 TEXT NOT NULL,
    PRIMARY KEY(source_sha256, interval_sha256),
    CHECK(window_end_ns >= window_start_ns AND guard_start_ns <= window_start_ns AND guard_end_ns >= window_end_ns)
)`
	createDatasetSourceIntervals = `CREATE TABLE dataset_source_interval_claims (
    tenant_stratum TEXT NOT NULL,
    site_stratum TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    source_sha256 TEXT NOT NULL,
    interval_sha256 TEXT NOT NULL,
    split TEXT NOT NULL CHECK(split IN ('train','validation','test')),
    window_start_ns INTEGER NOT NULL,
    window_end_ns INTEGER NOT NULL,
    guard_start_ns INTEGER NOT NULL,
    guard_end_ns INTEGER NOT NULL,
    adjacency_seconds INTEGER NOT NULL CHECK(adjacency_seconds >= 0 AND adjacency_seconds <= 604800),
    claim_sha256 TEXT NOT NULL,
    PRIMARY KEY(tenant_stratum, site_stratum, dataset_id, revision, ordinal),
    UNIQUE(tenant_stratum, site_stratum, dataset_id, revision, source_sha256, interval_sha256),
    FOREIGN KEY(tenant_stratum, site_stratum, dataset_id, revision)
        REFERENCES dataset_records(tenant_stratum, site_stratum, dataset_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY(source_sha256, interval_sha256)
        REFERENCES source_interval_ledger(source_sha256, interval_sha256) ON DELETE RESTRICT
)`
	createReviewRecords = `CREATE TABLE review_records (
    annotation_sha256 TEXT NOT NULL,
    review_id TEXT NOT NULL,
    reviewer_sha256 TEXT NOT NULL,
    reviewer_role TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
    policy_ref TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    review_json BLOB NOT NULL,
    PRIMARY KEY(annotation_sha256, review_id),
    UNIQUE(record_sha256)
)`
	createDatasetAnnotationReviews = `CREATE TABLE dataset_annotation_reviews (
    tenant_stratum TEXT NOT NULL,
    site_stratum TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    item_ordinal INTEGER NOT NULL CHECK(item_ordinal >= 0),
    annotation_ordinal INTEGER NOT NULL CHECK(annotation_ordinal >= 0),
    review_ordinal INTEGER NOT NULL CHECK(review_ordinal >= 0),
    item_id TEXT NOT NULL,
    annotation_id TEXT NOT NULL,
    annotation_sha256 TEXT NOT NULL,
    review_set_sha256 TEXT NOT NULL,
    review_id TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    policy_ref TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
    reviewer_sha256 TEXT NOT NULL,
    reviewer_role TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    review_json BLOB NOT NULL,
    PRIMARY KEY(tenant_stratum, site_stratum, dataset_id, revision, item_ordinal, annotation_ordinal, review_ordinal),
    UNIQUE(tenant_stratum, site_stratum, dataset_id, revision, item_ordinal, annotation_ordinal, review_id),
    FOREIGN KEY(tenant_stratum, site_stratum, dataset_id, revision)
        REFERENCES dataset_records(tenant_stratum, site_stratum, dataset_id, revision) ON DELETE RESTRICT
)`
	createGovernanceOperations = `CREATE TABLE governance_operations (
    operation_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL CHECK(operation_kind='dataset_purge'),
    tenant_stratum TEXT NOT NULL,
    site_stratum TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    content_sha256 TEXT NOT NULL,
    authorization_sha256 TEXT NOT NULL,
    authorization_json BLOB NOT NULL,
    requested_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('submitting_unknown','completed')),
    completed_at TEXT,
    operation_sha256 TEXT NOT NULL,
    UNIQUE(tenant_stratum, site_stratum, dataset_id, revision),
    FOREIGN KEY(tenant_stratum, site_stratum, dataset_id, revision)
        REFERENCES dataset_records(tenant_stratum, site_stratum, dataset_id, revision) ON DELETE RESTRICT,
    CHECK((state='submitting_unknown' AND completed_at IS NULL) OR (state='completed' AND completed_at IS NOT NULL))
)`
)

const datasetDatabaseSchema = createRepositoryControl + `;
INSERT INTO repository_control(singleton,write_lock) VALUES(1,0);
` + createDatasetRecords + `;
CREATE INDEX idx_dataset_records_scope ON dataset_records(tenant_stratum, site_stratum, dataset_id, revision);
` + createDatasetItems + `;
CREATE INDEX idx_dataset_media_ref ON dataset_items(media_ref, tenant_stratum, site_stratum, dataset_id, revision);
` + createDatasetAnnotations + `;
CREATE INDEX idx_dataset_annotation_digest ON dataset_annotations(annotation_sha256, tenant_stratum, site_stratum, dataset_id, revision);
` + createIdentityLedger + `;
` + createDatasetClaims + `;
CREATE INDEX idx_dataset_claim_identity ON dataset_identity_claims(identity_kind, identity_sha256, split);
` + createSourceIntervalLedger + `;
CREATE INDEX idx_source_interval_guard ON source_interval_ledger(source_sha256, split, guard_start_ns, guard_end_ns, window_start_ns, window_end_ns);
` + createDatasetSourceIntervals + `;
CREATE INDEX idx_dataset_source_interval ON dataset_source_interval_claims(source_sha256, interval_sha256, split);
` + createReviewRecords + `;
CREATE INDEX idx_review_policy ON review_records(annotation_sha256, policy_ref, reviewed_at);
` + createDatasetAnnotationReviews + `;
CREATE INDEX idx_dataset_annotation_review_set ON dataset_annotation_reviews(tenant_stratum,site_stratum,dataset_id,revision,review_set_sha256);
` + createGovernanceOperations + `;
CREATE TRIGGER dataset_records_no_delete BEFORE DELETE ON dataset_records BEGIN SELECT RAISE(ABORT, 'dataset records cannot be deleted'); END;
CREATE TRIGGER repository_control_no_delete BEFORE DELETE ON repository_control BEGIN SELECT RAISE(ABORT, 'repository control is permanent'); END;
CREATE TRIGGER repository_control_guard_update BEFORE UPDATE ON repository_control WHEN NOT (OLD.singleton=1 AND NEW.singleton=1 AND OLD.write_lock=0 AND NEW.write_lock=0) BEGIN SELECT RAISE(ABORT, 'invalid repository control update'); END;
CREATE TRIGGER dataset_records_guard_update BEFORE UPDATE ON dataset_records WHEN NOT (
    OLD.tenant_stratum=NEW.tenant_stratum AND OLD.site_stratum=NEW.site_stratum AND OLD.dataset_id=NEW.dataset_id AND OLD.revision=NEW.revision AND
    OLD.purpose_ref=NEW.purpose_ref AND OLD.policy_sha256=NEW.policy_sha256 AND OLD.retain_until=NEW.retain_until AND OLD.created_at=NEW.created_at AND
    OLD.content_sha256=NEW.content_sha256 AND OLD.projection_sha256=NEW.projection_sha256 AND OLD.claims_sha256=NEW.claims_sha256 AND OLD.intervals_sha256=NEW.intervals_sha256 AND OLD.reviews_sha256=NEW.reviews_sha256 AND
    ((OLD.governance_state='active' AND NEW.governance_state='purge_submitting' AND OLD.dataset_json=NEW.dataset_json AND NEW.tombstoned_at IS NULL) OR
     (OLD.governance_state='purge_submitting' AND NEW.governance_state='tombstoned' AND NEW.dataset_json IS NULL AND NEW.tombstoned_at IS NOT NULL))
) BEGIN SELECT RAISE(ABORT, 'invalid dataset governance transition'); END;
CREATE TRIGGER dataset_items_no_update BEFORE UPDATE ON dataset_items BEGIN SELECT RAISE(ABORT, 'dataset items are immutable'); END;
CREATE TRIGGER dataset_items_guard_delete BEFORE DELETE ON dataset_items WHEN NOT EXISTS (
    SELECT 1 FROM dataset_records r WHERE r.tenant_stratum=OLD.tenant_stratum AND r.site_stratum=OLD.site_stratum AND
    r.dataset_id=OLD.dataset_id AND r.revision=OLD.revision AND r.governance_state='purge_submitting'
) BEGIN SELECT RAISE(ABORT, 'dataset items can only be purged by governance'); END;
CREATE TRIGGER dataset_annotations_no_update BEFORE UPDATE ON dataset_annotations BEGIN SELECT RAISE(ABORT, 'dataset annotations are immutable'); END;
CREATE TRIGGER dataset_annotations_guard_delete BEFORE DELETE ON dataset_annotations WHEN NOT EXISTS (
    SELECT 1 FROM dataset_records r WHERE r.tenant_stratum=OLD.tenant_stratum AND r.site_stratum=OLD.site_stratum AND
    r.dataset_id=OLD.dataset_id AND r.revision=OLD.revision AND r.governance_state='purge_submitting'
) BEGIN SELECT RAISE(ABORT, 'dataset annotations can only be purged by governance'); END;
CREATE TRIGGER identity_ledger_no_update BEFORE UPDATE ON identity_ledger BEGIN SELECT RAISE(ABORT, 'identity ledger is immutable'); END;
CREATE TRIGGER identity_ledger_no_delete BEFORE DELETE ON identity_ledger BEGIN SELECT RAISE(ABORT, 'identity ledger is permanent'); END;
CREATE TRIGGER dataset_claims_no_update BEFORE UPDATE ON dataset_identity_claims BEGIN SELECT RAISE(ABORT, 'dataset claims are immutable'); END;
CREATE TRIGGER dataset_claims_no_delete BEFORE DELETE ON dataset_identity_claims BEGIN SELECT RAISE(ABORT, 'dataset claims are permanent'); END;
CREATE TRIGGER source_interval_ledger_no_update BEFORE UPDATE ON source_interval_ledger BEGIN SELECT RAISE(ABORT, 'source interval ledger is immutable'); END;
CREATE TRIGGER source_interval_ledger_no_delete BEFORE DELETE ON source_interval_ledger BEGIN SELECT RAISE(ABORT, 'source interval ledger is permanent'); END;
CREATE TRIGGER dataset_source_intervals_no_update BEFORE UPDATE ON dataset_source_interval_claims BEGIN SELECT RAISE(ABORT, 'dataset source intervals are immutable'); END;
CREATE TRIGGER dataset_source_intervals_no_delete BEFORE DELETE ON dataset_source_interval_claims BEGIN SELECT RAISE(ABORT, 'dataset source intervals are permanent'); END;
CREATE TRIGGER review_records_no_update BEFORE UPDATE ON review_records BEGIN SELECT RAISE(ABORT, 'review records are immutable'); END;
CREATE TRIGGER review_records_no_delete BEFORE DELETE ON review_records BEGIN SELECT RAISE(ABORT, 'review records are immutable'); END;
CREATE TRIGGER dataset_annotation_reviews_no_update BEFORE UPDATE ON dataset_annotation_reviews BEGIN SELECT RAISE(ABORT, 'dataset annotation reviews are immutable'); END;
CREATE TRIGGER dataset_annotation_reviews_no_delete BEFORE DELETE ON dataset_annotation_reviews BEGIN SELECT RAISE(ABORT, 'dataset annotation reviews are permanent'); END;
CREATE TRIGGER governance_operations_no_delete BEFORE DELETE ON governance_operations BEGIN SELECT RAISE(ABORT, 'governance operations are permanent'); END;
CREATE TRIGGER governance_operations_guard_update BEFORE UPDATE ON governance_operations WHEN NOT (
    OLD.operation_id=NEW.operation_id AND OLD.operation_kind=NEW.operation_kind AND OLD.tenant_stratum=NEW.tenant_stratum AND OLD.site_stratum=NEW.site_stratum AND
    OLD.dataset_id=NEW.dataset_id AND OLD.revision=NEW.revision AND OLD.content_sha256=NEW.content_sha256 AND
    OLD.authorization_sha256=NEW.authorization_sha256 AND OLD.authorization_json=NEW.authorization_json AND OLD.requested_at=NEW.requested_at AND OLD.operation_sha256=NEW.operation_sha256 AND
    OLD.state='submitting_unknown' AND NEW.state='completed' AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL
) BEGIN SELECT RAISE(ABORT, 'invalid governance operation transition'); END;`

type SQLiteRepositoryOptions struct {
	GovernanceAuthorizer GovernanceAuthorizer
	ReviewVerifier       ReviewVerifier
	Now                  func() time.Time
	IntegrityKey         []byte
}

type SQLiteRepository struct {
	db                   *sql.DB
	commit               func(*sql.Tx) error
	governanceAuthorizer GovernanceAuthorizer
	reviewVerifier       ReviewVerifier
	now                  func() time.Time
	integrityKey         []byte
	governanceLookup     func(context.Context, string, string, string, uint64) (GovernanceRecord, error)
}

type identityLedgerProvenance struct {
	IdentityKind       string    `json:"identityKind"`
	IdentitySHA256     string    `json:"identitySha256"`
	Split              Split     `json:"split"`
	FirstClaimedAt     time.Time `json:"firstClaimedAt"`
	FirstTenantStratum string    `json:"firstTenantStratum"`
	FirstSiteStratum   string    `json:"firstSiteStratum"`
	FirstDatasetID     string    `json:"firstDatasetId"`
	FirstRevision      uint64    `json:"firstRevision"`
}

type sourceLedgerProvenance struct {
	SourceSHA256        string    `json:"sourceSha256"`
	IntervalSHA256      string    `json:"intervalSha256"`
	Split               Split     `json:"split"`
	WindowStartUnixNano int64     `json:"windowStartUnixNano"`
	WindowEndUnixNano   int64     `json:"windowEndUnixNano"`
	GuardStartUnixNano  int64     `json:"guardStartUnixNano"`
	GuardEndUnixNano    int64     `json:"guardEndUnixNano"`
	AdjacencySeconds    int       `json:"adjacencySeconds"`
	FirstClaimedAt      time.Time `json:"firstClaimedAt"`
	FirstTenantStratum  string    `json:"firstTenantStratum"`
	FirstSiteStratum    string    `json:"firstSiteStratum"`
	FirstDatasetID      string    `json:"firstDatasetId"`
	FirstRevision       uint64    `json:"firstRevision"`
}

func (r *SQLiteRepository) ledgerProvenanceDigest(domain string, value any) (string, error) {
	return r.integrityDigest(domain, value)
}

func (r *SQLiteRepository) integrityDigest(domain string, value any) (string, error) {
	if r == nil || len(r.integrityKey) < 32 {
		return "", ErrCorruptRepository
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, r.integrityKey)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func reviewBindingOrdinal(value Dataset, itemOrdinal, annotationOrdinal int) int {
	ordinal := annotationOrdinal
	for index := 0; index < itemOrdinal; index++ {
		ordinal += len(value.Items[index].Annotations)
	}
	return ordinal
}

type CreateReceipt struct {
	TenantStratum string `json:"tenantStratum"`
	SiteStratum   string `json:"siteStratum"`
	DatasetID     string `json:"datasetId"`
	Revision      uint64 `json:"revision"`
	ContentSHA256 string `json:"contentSha256"`
}
type CreateOutcomeUnknownError struct{ Receipt CreateReceipt }

func (e *CreateOutcomeUnknownError) Error() string { return ErrCreateOutcomeUnknown.Error() }
func (e *CreateOutcomeUnknownError) Unwrap() error { return ErrCreateOutcomeUnknown }

type CreateResolutionState string

const (
	CreateCommitted    CreateResolutionState = "committed"
	CreateNotCommitted CreateResolutionState = "not_committed"
	CreateConflict     CreateResolutionState = "conflict"
	CreateUnknown      CreateResolutionState = "unknown"
)

type CreateResolution struct {
	State CreateResolutionState `json:"state"`
}

type PurgeOutcomeUnknownError struct{ Receipt PurgeReceipt }

func (e *PurgeOutcomeUnknownError) Error() string { return ErrPurgeOutcomeUnknown.Error() }
func (e *PurgeOutcomeUnknownError) Unwrap() error { return ErrPurgeOutcomeUnknown }

type PurgeResolutionState string

const (
	PurgeCompleted  PurgeResolutionState = "completed"
	PurgePending    PurgeResolutionState = "pending"
	PurgeNotStarted PurgeResolutionState = "not_started"
	PurgeConflict   PurgeResolutionState = "conflict"
	PurgeUnknown    PurgeResolutionState = "unknown"
)

type PurgeResolution struct {
	State PurgeResolutionState `json:"state"`
}

func OpenSQLiteRepository(path string, options SQLiteRepositoryOptions) (*SQLiteRepository, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "?#\x00") || options.GovernanceAuthorizer == nil || options.ReviewVerifier == nil || options.Now == nil ||
		len(options.IntegrityKey) < 32 || len(options.IntegrityKey) > 128 {
		return nil, errors.Join(ErrUnsupportedRepositorySchema, errors.New("dataset repository configuration is invalid"))
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(absolute)
	if err := localstate.PrepareStateRoot(root); err != nil {
		return nil, err
	}
	created := false
	if _, err := os.Lstat(absolute); err == nil {
		if err := localstate.ValidateFile(absolute); err != nil {
			return nil, fmt.Errorf("reject existing dataset repository: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, closeErr
		}
		if err := localstate.ProtectFile(absolute); err != nil {
			return nil, err
		}
		created = true
	}
	database, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	closeOnError := func(openErr error) (*SQLiteRepository, error) { _ = database.Close(); return nil, openErr }
	for _, pragma := range []string{"PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA trusted_schema=OFF", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON"} {
		if _, err := database.Exec(pragma); err != nil {
			return closeOnError(err)
		}
	}
	var version, applicationID int
	if err := database.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return closeOnError(err)
	}
	if err := database.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil {
		return closeOnError(err)
	}
	if version == 0 {
		if applicationID != 0 {
			return closeOnError(ErrUnsupportedRepositorySchema)
		}
	} else if version != datasetDatabaseVersion || applicationID != datasetDatabaseApplicationID {
		return closeOnError(ErrUnsupportedRepositorySchema)
	}
	if version == 0 && !created {
		return closeOnError(ErrUnsupportedRepositorySchema)
	}
	if version == 0 {
		tx, err := database.Begin()
		if err != nil {
			return closeOnError(err)
		}
		if _, err := tx.Exec(datasetDatabaseSchema); err != nil {
			_ = tx.Rollback()
			return closeOnError(err)
		}
		for _, statement := range []string{fmt.Sprintf("PRAGMA application_id=%d", datasetDatabaseApplicationID), fmt.Sprintf("PRAGMA user_version=%d", datasetDatabaseVersion)} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return closeOnError(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return closeOnError(err)
		}
	}
	if err := validateDatasetDatabaseShape(database); err != nil {
		return closeOnError(err)
	}
	if err := localstate.ProtectFile(absolute); err != nil {
		return closeOnError(err)
	}
	repository := &SQLiteRepository{db: database, commit: func(tx *sql.Tx) error { return tx.Commit() }, governanceAuthorizer: options.GovernanceAuthorizer,
		reviewVerifier: options.ReviewVerifier, now: options.Now, integrityKey: append([]byte(nil), options.IntegrityKey...)}
	repository.governanceLookup = repository.GetGovernance
	if err := repository.validateStoredContent(context.Background()); err != nil {
		for index := range repository.integrityKey {
			repository.integrityKey[index] = 0
		}
		repository.integrityKey = nil
		return closeOnError(err)
	}
	return repository, nil
}

func (r *SQLiteRepository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	err := r.db.Close()
	for index := range r.integrityKey {
		r.integrityKey[index] = 0
	}
	r.integrityKey = nil
	return err
}
func (r *SQLiteRepository) Create(ctx context.Context, value Dataset) error {
	_, err := r.CreateWithReceipt(ctx, value)
	return err
}

func (r *SQLiteRepository) CreateWithReceipt(ctx context.Context, value Dataset) (CreateReceipt, error) {
	if r == nil || r.db == nil || r.commit == nil {
		return CreateReceipt{}, ErrCreateFailed
	}
	if err := ctx.Err(); err != nil {
		return CreateReceipt{}, errors.Join(ErrCreateFailed, err)
	}
	raw, projectionDigest, contentDigest, claimsDigest, intervalsDigest, reviewsDigest, err := marshalStoredDataset(value)
	if err != nil {
		return CreateReceipt{}, err
	}
	admissionBytes, err := storedAdmissionBytes(value, raw)
	if err != nil {
		return CreateReceipt{}, err
	}
	receipt := CreateReceipt{value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, contentDigest}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, errors.Join(ErrCreateFailed, err)
	}
	defer tx.Rollback()
	if err := acquireRepositoryWriteLock(ctx, tx); err != nil {
		return receipt, errors.Join(ErrCreateFailed, err)
	}
	var existingContent string
	err = tx.QueryRowContext(ctx, `SELECT content_sha256 FROM dataset_records WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`,
		value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision).Scan(&existingContent)
	switch {
	case err == nil && existingContent == contentDigest:
		// The no-op control update is deliberately rolled back. No business row
		// changed, and the original create receipt remains authoritative even
		// after the dataset has been tombstoned.
		return receipt, nil
	case err == nil:
		return receipt, ErrConflict
	case !errors.Is(err, sql.ErrNoRows):
		return receipt, errors.Join(ErrCreateFailed, err)
	}
	if err := checkCreateCapacity(ctx, tx, value, admissionBytes); err != nil {
		if errors.Is(err, ErrCapacity) || errors.Is(err, ErrCorruptRepository) {
			return receipt, err
		}
		return receipt, errors.Join(ErrCreateFailed, err)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO dataset_records(tenant_stratum,site_stratum,dataset_id,revision,purpose_ref,policy_sha256,retain_until,governance_state,created_at,tombstoned_at,content_sha256,projection_sha256,claims_sha256,intervals_sha256,reviews_sha256,dataset_json)
		SELECT ?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM dataset_records) < ?`,
		value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, value.PurposeRef, value.PolicySHA256, formatDatasetTime(value.RetainUntil), string(GovernanceActive), formatDatasetTime(value.CreatedAt),
		contentDigest, projectionDigest, claimsDigest, intervalsDigest, reviewsDigest, raw, maximumStoredDatasets)
	if err != nil {
		return receipt, classifyDefiniteCreateError(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return receipt, ErrCapacity
	}
	for itemOrdinal, item := range value.Items {
		itemDigest, digestErr := digestStoredValue(item)
		if digestErr != nil {
			return receipt, errors.Join(ErrCreateFailed, digestErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO dataset_items(tenant_stratum,site_stratum,dataset_id,revision,ordinal,item_id,media_ref,item_sha256) VALUES(?,?,?,?,?,?,?,?)`, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, itemOrdinal, item.ItemID, item.MediaRef, itemDigest); err != nil {
			return receipt, classifyDefiniteCreateError(err)
		}
		for annotationOrdinal, annotation := range item.Annotations {
			projectionDigest, digestErr := digestStoredValue(annotation)
			if digestErr != nil {
				return receipt, errors.Join(ErrCreateFailed, digestErr)
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO dataset_annotations(tenant_stratum,site_stratum,dataset_id,revision,item_ordinal,annotation_ordinal,annotation_id,annotation_sha256,projection_sha256) VALUES(?,?,?,?,?,?,?,?,?)`, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, itemOrdinal, annotationOrdinal, annotation.AnnotationID, annotation.AnnotationSHA256, projectionDigest); err != nil {
				return receipt, classifyDefiniteCreateError(err)
			}
		}
	}
	for itemOrdinal, item := range value.Items {
		for annotationOrdinal := range item.Annotations {
			binding := value.reviewBindings[reviewBindingOrdinal(value, itemOrdinal, annotationOrdinal)]
			for reviewOrdinal, review := range binding.Reviews {
				rawReview, marshalErr := json.Marshal(review)
				if marshalErr != nil || len(rawReview) > maximumStoredReviewBytes {
					return receipt, ErrCreateFailed
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO dataset_annotation_reviews(tenant_stratum,site_stratum,dataset_id,revision,item_ordinal,annotation_ordinal,review_ordinal,item_id,annotation_id,annotation_sha256,review_set_sha256,review_id,record_sha256,policy_ref,decision,reviewer_sha256,reviewer_role,reviewed_at,review_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
					value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, itemOrdinal, annotationOrdinal, reviewOrdinal,
					binding.ItemID, binding.AnnotationID, binding.AnnotationSHA256, binding.ReviewSetSHA256, review.ReviewID, review.RecordSHA256, review.PolicyRef, string(review.Decision),
					review.ReviewerSHA256, review.ReviewerRole, formatDatasetTime(review.ReviewedAt), rawReview); err != nil {
					return receipt, classifyDefiniteCreateError(err)
				}
			}
		}
	}
	for ordinal, claim := range value.claims {
		provenance := identityLedgerProvenance{IdentityKind: claim.Kind, IdentitySHA256: claim.SHA256, Split: claim.Split,
			FirstClaimedAt: value.CreatedAt, FirstTenantStratum: value.TenantStratum, FirstSiteStratum: value.SiteStratum,
			FirstDatasetID: value.DatasetID, FirstRevision: value.Revision}
		provenanceDigest, digestErr := r.ledgerProvenanceDigest("identity-ledger-v1", provenance)
		if digestErr != nil {
			return receipt, ErrCreateFailed
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_ledger(identity_kind,identity_sha256,split,first_claimed_at,first_tenant_stratum,first_site_stratum,first_dataset_id,first_revision,provenance_sha256) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(identity_kind,identity_sha256) DO NOTHING`,
			claim.Kind, claim.SHA256, string(claim.Split), formatDatasetTime(value.CreatedAt), value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, provenanceDigest); err != nil {
			return receipt, classifyDefiniteCreateError(err)
		}
		var existing identityLedgerProvenance
		var existingSplit, firstAt, storedProvenance string
		if err = tx.QueryRowContext(ctx, `SELECT split,first_claimed_at,first_tenant_stratum,first_site_stratum,first_dataset_id,first_revision,provenance_sha256 FROM identity_ledger WHERE identity_kind=? AND identity_sha256=?`, claim.Kind, claim.SHA256).
			Scan(&existingSplit, &firstAt, &existing.FirstTenantStratum, &existing.FirstSiteStratum, &existing.FirstDatasetID, &existing.FirstRevision, &storedProvenance); err != nil {
			return receipt, errors.Join(ErrCreateFailed, err)
		}
		existing.IdentityKind, existing.IdentitySHA256, existing.Split = claim.Kind, claim.SHA256, Split(existingSplit)
		existing.FirstClaimedAt, err = parseDatasetTime(firstAt)
		expectedProvenance, provenanceErr := r.ledgerProvenanceDigest("identity-ledger-v1", existing)
		if err != nil || provenanceErr != nil || storedProvenance != expectedProvenance {
			return receipt, ErrCorruptRepository
		}
		if existingSplit != string(claim.Split) {
			return receipt, ErrLeakage
		}
		claimDigest, digestErr := digestStoredValue(claim)
		if digestErr != nil {
			return receipt, errors.Join(ErrCreateFailed, digestErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO dataset_identity_claims(tenant_stratum,site_stratum,dataset_id,revision,ordinal,identity_kind,identity_sha256,split,claim_sha256) VALUES(?,?,?,?,?,?,?,?,?)`, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, ordinal, claim.Kind, claim.SHA256, string(claim.Split), claimDigest); err != nil {
			return receipt, classifyDefiniteCreateError(err)
		}
	}
	for ordinal, interval := range value.sourceIntervals {
		var conflict int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM source_interval_ledger WHERE source_sha256=? AND split<>? AND ((guard_start_ns<=? AND guard_end_ns>=?) OR (window_start_ns<=? AND window_end_ns>=?)) LIMIT 1`,
			interval.SourceSHA256, string(interval.Split), interval.WindowEndUnixNano, interval.WindowStartUnixNano, interval.GuardEndUnixNano, interval.GuardStartUnixNano).Scan(&conflict)
		if err == nil {
			return receipt, ErrLeakage
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return receipt, errors.Join(ErrCreateFailed, err)
		}
		provenance := sourceLedgerProvenance{SourceSHA256: interval.SourceSHA256, IntervalSHA256: interval.IntervalSHA256, Split: interval.Split,
			WindowStartUnixNano: interval.WindowStartUnixNano, WindowEndUnixNano: interval.WindowEndUnixNano, GuardStartUnixNano: interval.GuardStartUnixNano,
			GuardEndUnixNano: interval.GuardEndUnixNano, AdjacencySeconds: interval.AdjacencySeconds, FirstClaimedAt: value.CreatedAt,
			FirstTenantStratum: value.TenantStratum, FirstSiteStratum: value.SiteStratum, FirstDatasetID: value.DatasetID, FirstRevision: value.Revision}
		provenanceDigest, digestErr := r.ledgerProvenanceDigest("source-interval-ledger-v1", provenance)
		if digestErr != nil {
			return receipt, ErrCreateFailed
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO source_interval_ledger(source_sha256,interval_sha256,split,window_start_ns,window_end_ns,guard_start_ns,guard_end_ns,adjacency_seconds,first_claimed_at,first_tenant_stratum,first_site_stratum,first_dataset_id,first_revision,provenance_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_sha256,interval_sha256) DO NOTHING`,
			interval.SourceSHA256, interval.IntervalSHA256, string(interval.Split), interval.WindowStartUnixNano, interval.WindowEndUnixNano,
			interval.GuardStartUnixNano, interval.GuardEndUnixNano, interval.AdjacencySeconds, formatDatasetTime(value.CreatedAt), value.TenantStratum,
			value.SiteStratum, value.DatasetID, value.Revision, provenanceDigest); err != nil {
			return receipt, classifyDefiniteCreateError(err)
		}
		var storedSplit, firstAt, firstTenant, firstSite, firstDataset, storedProvenance string
		var storedStart, storedEnd, storedGuardStart, storedGuardEnd int64
		var storedAdjacency, firstRevision int
		if err = tx.QueryRowContext(ctx, `SELECT split,window_start_ns,window_end_ns,guard_start_ns,guard_end_ns,adjacency_seconds,first_claimed_at,first_tenant_stratum,first_site_stratum,first_dataset_id,first_revision,provenance_sha256 FROM source_interval_ledger WHERE source_sha256=? AND interval_sha256=?`, interval.SourceSHA256, interval.IntervalSHA256).
			Scan(&storedSplit, &storedStart, &storedEnd, &storedGuardStart, &storedGuardEnd, &storedAdjacency, &firstAt, &firstTenant, &firstSite, &firstDataset, &firstRevision, &storedProvenance); err != nil {
			return receipt, errors.Join(ErrCreateFailed, err)
		}
		firstClaimedAt, parseErr := parseDatasetTime(firstAt)
		storedRow := sourceLedgerProvenance{interval.SourceSHA256, interval.IntervalSHA256, Split(storedSplit), storedStart, storedEnd, storedGuardStart, storedGuardEnd,
			storedAdjacency, firstClaimedAt, firstTenant, firstSite, firstDataset, uint64(firstRevision)}
		expectedProvenance, provenanceErr := r.ledgerProvenanceDigest("source-interval-ledger-v1", storedRow)
		if storedSplit != string(interval.Split) || storedStart != interval.WindowStartUnixNano || storedEnd != interval.WindowEndUnixNano ||
			storedGuardStart != interval.GuardStartUnixNano || storedGuardEnd != interval.GuardEndUnixNano || storedAdjacency != interval.AdjacencySeconds ||
			parseErr != nil || provenanceErr != nil || storedProvenance != expectedProvenance {
			return receipt, ErrLeakage
		}
		intervalDigest, digestErr := digestStoredValue(interval)
		if digestErr != nil {
			return receipt, errors.Join(ErrCreateFailed, digestErr)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO dataset_source_interval_claims(tenant_stratum,site_stratum,dataset_id,revision,ordinal,source_sha256,interval_sha256,split,window_start_ns,window_end_ns,guard_start_ns,guard_end_ns,adjacency_seconds,claim_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, ordinal, interval.SourceSHA256, interval.IntervalSHA256, string(interval.Split),
			interval.WindowStartUnixNano, interval.WindowEndUnixNano, interval.GuardStartUnixNano, interval.GuardEndUnixNano, interval.AdjacencySeconds, intervalDigest); err != nil {
			return receipt, classifyDefiniteCreateError(err)
		}
	}
	if err := r.commit(tx); err != nil {
		return receipt, &CreateOutcomeUnknownError{Receipt: receipt}
	}
	return receipt, nil
}

func (r *SQLiteRepository) ResolveCreate(ctx context.Context, receipt CreateReceipt) (CreateResolution, error) {
	if r == nil || r.db == nil || !validCreateReceipt(receipt) {
		return CreateResolution{CreateUnknown}, ErrCreateOutcomeUnknown
	}
	var digest string
	err := r.db.QueryRowContext(ctx, `SELECT content_sha256 FROM dataset_records WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision).Scan(&digest)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return CreateResolution{CreateNotCommitted}, nil
	case err != nil:
		return CreateResolution{CreateUnknown}, ErrCreateOutcomeUnknown
	case digest == receipt.ContentSHA256:
		return CreateResolution{CreateCommitted}, nil
	default:
		return CreateResolution{CreateConflict}, nil
	}
}

func (r *SQLiteRepository) Get(ctx context.Context, tenantStratum, siteStratum, datasetID string, revision uint64) (Dataset, error) {
	if r == nil || r.db == nil || !validPseudonym("tenant", tenantStratum) || !validPseudonym("site", siteStratum) || !validNamespacedRef("dataset-", datasetID) || revision < 1 {
		return Dataset{}, ErrNotFound
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Dataset{}, err
	}
	defer tx.Rollback()
	value, err := decodeStoredDataset(ctx, tx, tenantStratum, siteStratum, datasetID, revision)
	if err != nil {
		return Dataset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Dataset{}, err
	}
	return value, nil
}

func (r *SQLiteRepository) List(ctx context.Context, tenantStratum, siteStratum string) ([]Dataset, error) {
	if r == nil || r.db == nil || !validPseudonym("tenant", tenantStratum) || !validPseudonym("site", siteStratum) {
		return nil, ErrNotFound
	}
	rows, err := r.db.QueryContext(ctx, `SELECT dataset_id,revision FROM dataset_records WHERE tenant_stratum=? AND site_stratum=? AND governance_state='active' ORDER BY dataset_id,revision LIMIT ?`, tenantStratum, siteStratum, maximumStoredDatasets+1)
	if err != nil {
		return nil, err
	}
	type key struct {
		id       string
		revision uint64
	}
	keys := make([]key, 0)
	for rows.Next() {
		var value key
		if err := rows.Scan(&value.id, &value.revision); err != nil {
			_ = rows.Close()
			return nil, err
		}
		keys = append(keys, value)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(keys) > maximumStoredDatasets {
		return nil, ErrCorruptRepository
	}
	result := make([]Dataset, 0, len(keys))
	for _, key := range keys {
		value, err := r.Get(ctx, tenantStratum, siteStratum, key.id, key.revision)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func (r *SQLiteRepository) RecordReview(ctx context.Context, record ReviewRecord) error {
	if r == nil || r.db == nil || r.reviewVerifier == nil || validateReviewRecord(record) != nil {
		return ErrReviewIncomplete
	}
	if record.ReviewerRole != ReviewerRoleDataset {
		return ErrReviewIncomplete
	}
	if err := r.reviewVerifier.VerifyReview(ctx, ReviewVerificationDemand{Record: record}); err != nil {
		return ErrReviewIncomplete
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maximumStoredReviewBytes {
		return ErrReviewIncomplete
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrReviewUnavailable
	}
	defer tx.Rollback()
	if err := acquireRepositoryWriteLock(ctx, tx); err != nil {
		return ErrReviewUnavailable
	}
	var existingDigest string
	err = tx.QueryRowContext(ctx, `SELECT record_sha256 FROM review_records WHERE annotation_sha256=? AND review_id=?`, record.AnnotationSHA256, record.ReviewID).Scan(&existingDigest)
	switch {
	case err == nil && existingDigest == record.RecordSHA256:
		return nil
	case err == nil:
		return ErrConflict
	case !errors.Is(err, sql.ErrNoRows):
		return ErrReviewUnavailable
	}
	if err := checkReviewCapacity(ctx, tx, len(raw), record.AnnotationSHA256); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO review_records(annotation_sha256,review_id,reviewer_sha256,reviewer_role,decision,policy_ref,reviewed_at,record_sha256,review_json)
		SELECT ?,?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM review_records) < ? AND (SELECT COUNT(*) FROM review_records WHERE annotation_sha256=?) < ?`,
		record.AnnotationSHA256, record.ReviewID, record.ReviewerSHA256, record.ReviewerRole, string(record.Decision), record.PolicyRef,
		formatDatasetTime(record.ReviewedAt), record.RecordSHA256, raw, maximumStoredReviews, record.AnnotationSHA256, maximumReviewDecisions)
	if err != nil {
		if isConstraint(err) {
			return ErrConflict
		}
		return ErrReviewUnavailable
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return ErrCapacity
	}
	if err := tx.Commit(); err != nil {
		return ErrReviewUnavailable
	}
	return nil
}

func (r *SQLiteRepository) ListReviews(ctx context.Context, query ReviewQuery) ([]ReviewRecord, error) {
	if r == nil || r.db == nil || !validDigest(query.AnnotationSHA256) || !validOpaqueRef(query.PolicyRef) || !canonicalTime(query.NotAfter) {
		return nil, ErrReviewUnavailable
	}
	rows, err := r.db.QueryContext(ctx, `SELECT review_id,reviewer_sha256,reviewer_role,decision,policy_ref,reviewed_at,record_sha256,review_json FROM review_records WHERE annotation_sha256=? AND policy_ref=? AND reviewed_at<=? ORDER BY review_id LIMIT ?`, query.AnnotationSHA256, query.PolicyRef, formatDatasetTime(query.NotAfter), maximumReviewDecisions+1)
	if err != nil {
		return nil, ErrReviewUnavailable
	}
	result := make([]ReviewRecord, 0)
	for rows.Next() {
		var reviewID, reviewer, reviewerRole, decision, policy, reviewedAt, digest string
		var raw []byte
		if err := rows.Scan(&reviewID, &reviewer, &reviewerRole, &decision, &policy, &reviewedAt, &digest, &raw); err != nil {
			_ = rows.Close()
			return nil, ErrReviewUnavailable
		}
		record, decodeErr := decodeReviewRecord(raw)
		if decodeErr != nil || record.ReviewID != reviewID || record.AnnotationSHA256 != query.AnnotationSHA256 || record.ReviewerSHA256 != reviewer || record.ReviewerRole != reviewerRole || string(record.Decision) != decision || record.PolicyRef != policy || formatDatasetTime(record.ReviewedAt) != reviewedAt || record.RecordSHA256 != digest {
			_ = rows.Close()
			return nil, ErrCorruptRepository
		}
		result = append(result, record)
	}
	if err := rows.Close(); err != nil {
		return nil, ErrReviewUnavailable
	}
	if len(result) > maximumReviewDecisions {
		return nil, ErrReviewIncomplete
	}
	return result, nil
}

func (r *SQLiteRepository) GetGovernance(ctx context.Context, tenantStratum, siteStratum, datasetID string, revision uint64) (GovernanceRecord, error) {
	if r == nil || r.db == nil || !validPseudonym("tenant", tenantStratum) || !validPseudonym("site", siteStratum) || !validNamespacedRef("dataset-", datasetID) || revision < 1 {
		return GovernanceRecord{}, ErrNotFound
	}
	var content, retain, state string
	var tombstone sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT content_sha256,retain_until,governance_state,tombstoned_at FROM dataset_records WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`, tenantStratum, siteStratum, datasetID, revision).Scan(&content, &retain, &state, &tombstone)
	if errors.Is(err, sql.ErrNoRows) {
		return GovernanceRecord{}, ErrNotFound
	}
	if err != nil {
		return GovernanceRecord{}, err
	}
	retainAt, err := parseDatasetTime(retain)
	if err != nil {
		return GovernanceRecord{}, ErrCorruptRepository
	}
	record := GovernanceRecord{tenantStratum, siteStratum, datasetID, revision, content, retainAt, GovernanceState(state), nil}
	if tombstone.Valid {
		at, parseErr := parseDatasetTime(tombstone.String)
		if parseErr != nil {
			return GovernanceRecord{}, ErrCorruptRepository
		}
		record.TombstonedAt = &at
	}
	if validateGovernanceRecord(record) != nil {
		return GovernanceRecord{}, ErrCorruptRepository
	}
	return record, nil
}

func (r *SQLiteRepository) Purge(ctx context.Context, request PurgeRequest) (PurgeReceipt, error) {
	if r == nil || r.db == nil || r.commit == nil || r.governanceAuthorizer == nil || r.governanceLookup == nil || r.now == nil || validatePurgeRequest(request) != nil {
		return PurgeReceipt{}, ErrPurgeFailed
	}
	now := r.now().UTC()
	if now.IsZero() {
		return PurgeReceipt{}, ErrPurgeFailed
	}
	preflight := GovernancePreflightDemand{AuthorityRef: request.AuthorityRef, PrincipalSHA256: request.PrincipalSHA256,
		OperationID: request.OperationID, Operation: OperationPurge, TenantStratum: request.TenantStratum, SiteStratum: request.SiteStratum,
		DatasetID: request.DatasetID, Revision: request.Revision, At: now}
	if err := r.governanceAuthorizer.PreflightGovernance(ctx, preflight); err != nil {
		return PurgeReceipt{}, ErrUnauthorized
	}
	record, err := r.governanceLookup(ctx, request.TenantStratum, request.SiteStratum, request.DatasetID, request.Revision)
	if err != nil {
		return PurgeReceipt{}, err
	}
	receipt := PurgeReceipt{request.OperationID, request.TenantStratum, request.SiteStratum, request.DatasetID, request.Revision, record.ContentSHA256}
	demand := GovernanceDemand{Preflight: preflight, ContentSHA256: record.ContentSHA256, RetainUntil: record.RetainUntil}
	if err := r.governanceAuthorizer.AuthorizeGovernance(ctx, demand); err != nil {
		return receipt, ErrUnauthorized
	}
	if record.State == GovernanceTombstoned {
		resolution, resolveErr := r.ResolvePurge(ctx, receipt)
		if resolveErr == nil && resolution.State == PurgeCompleted {
			return receipt, nil
		}
		return receipt, ErrConflict
	}
	if record.State == GovernancePurgeSubmitting {
		resolution, resolveErr := r.ResolvePurge(ctx, receipt)
		if resolveErr == nil && resolution.State == PurgePending {
			if finishErr := r.finishPurge(ctx, receipt, now); finishErr != nil {
				return receipt, finishErr
			}
			return receipt, nil
		}
		return receipt, ErrConflict
	}
	if now.Before(record.RetainUntil) {
		return receipt, ErrRetentionActive
	}
	authorizationRaw, err := json.Marshal(demand)
	if err != nil || len(authorizationRaw) == 0 || len(authorizationRaw) > maximumStoredReviewBytes {
		return receipt, ErrPurgeFailed
	}
	authorizationDigest, err := r.integrityDigest("governance-demand-v1", demand)
	if err != nil {
		return receipt, ErrPurgeFailed
	}
	operationDigest, err := purgeOperationDigest(receipt, authorizationDigest, now)
	if err != nil {
		return receipt, ErrPurgeFailed
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, ErrPurgeFailed
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE dataset_records SET governance_state='purge_submitting' WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=? AND governance_state='active' AND content_sha256=?`, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision, receipt.ContentSHA256)
	if err != nil {
		return receipt, ErrPurgeFailed
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return receipt, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO governance_operations(operation_id,operation_kind,tenant_stratum,site_stratum,dataset_id,revision,content_sha256,authorization_sha256,authorization_json,requested_at,state,completed_at,operation_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,'submitting_unknown',NULL,?)`,
		receipt.OperationID, OperationPurge, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision, receipt.ContentSHA256,
		authorizationDigest, authorizationRaw, formatDatasetTime(now), operationDigest)
	if err != nil {
		return receipt, classifyDefinitePurgeError(err)
	}
	if err := r.commit(tx); err != nil {
		return receipt, &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	if err := r.finishPurge(ctx, receipt, now); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func (r *SQLiteRepository) finishPurge(ctx context.Context, receipt PurgeReceipt, completedAt time.Time) error {
	if !canonicalTime(completedAt) {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	defer tx.Rollback()
	var operationState, content, requestedAtRaw, retainUntilRaw, authorizationSHA256 string
	var authorizationRaw []byte
	if err := tx.QueryRowContext(ctx, `SELECT o.state,o.content_sha256,o.requested_at,d.retain_until,o.authorization_sha256,o.authorization_json FROM governance_operations o JOIN dataset_records d ON d.tenant_stratum=o.tenant_stratum AND d.site_stratum=o.site_stratum AND d.dataset_id=o.dataset_id AND d.revision=o.revision WHERE o.operation_id=? AND o.tenant_stratum=? AND o.site_stratum=? AND o.dataset_id=? AND o.revision=?`, receipt.OperationID, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision).
		Scan(&operationState, &content, &requestedAtRaw, &retainUntilRaw, &authorizationSHA256, &authorizationRaw); err != nil {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	requestedAt, requestedErr := parseDatasetTime(requestedAtRaw)
	retainUntil, retainErr := parseDatasetTime(retainUntilRaw)
	if requestedErr != nil || retainErr != nil || completedAt.Before(requestedAt) || completedAt.Before(retainUntil) {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	if err := r.validateGovernanceAuthorizationProof(authorizationRaw, authorizationSHA256, receipt, requestedAt, retainUntil); err != nil {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	if content != receipt.ContentSHA256 {
		return ErrConflict
	}
	if operationState == "completed" {
		return tx.Commit()
	}
	if operationState != "submitting_unknown" {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	for _, statement := range []string{`DELETE FROM dataset_annotations WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`, `DELETE FROM dataset_items WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`} {
		if _, err := tx.ExecContext(ctx, statement, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision); err != nil {
			return &PurgeOutcomeUnknownError{Receipt: receipt}
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE dataset_records SET governance_state='tombstoned',tombstoned_at=?,dataset_json=NULL WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=? AND governance_state='purge_submitting' AND content_sha256=?`, formatDatasetTime(completedAt), receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision, receipt.ContentSHA256)
	if err != nil {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	result, err = tx.ExecContext(ctx, `UPDATE governance_operations SET state='completed',completed_at=? WHERE operation_id=? AND state='submitting_unknown'`, formatDatasetTime(completedAt), receipt.OperationID)
	if err != nil {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	if err := r.commit(tx); err != nil {
		return &PurgeOutcomeUnknownError{Receipt: receipt}
	}
	return nil
}

func (r *SQLiteRepository) ResolvePurge(ctx context.Context, receipt PurgeReceipt) (PurgeResolution, error) {
	if r == nil || r.db == nil || !validPurgeReceipt(receipt) {
		return PurgeResolution{PurgeUnknown}, ErrPurgeOutcomeUnknown
	}
	var state, content string
	err := r.db.QueryRowContext(ctx, `SELECT state,content_sha256 FROM governance_operations WHERE operation_id=? AND tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`, receipt.OperationID, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision).Scan(&state, &content)
	if errors.Is(err, sql.ErrNoRows) {
		return PurgeResolution{PurgeNotStarted}, nil
	}
	if err != nil {
		return PurgeResolution{PurgeUnknown}, ErrPurgeOutcomeUnknown
	}
	if content != receipt.ContentSHA256 {
		return PurgeResolution{PurgeConflict}, nil
	}
	record, err := r.GetGovernance(ctx, receipt.TenantStratum, receipt.SiteStratum, receipt.DatasetID, receipt.Revision)
	if err != nil {
		return PurgeResolution{PurgeUnknown}, ErrPurgeOutcomeUnknown
	}
	switch {
	case state == "submitting_unknown" && record.State == GovernancePurgeSubmitting:
		return PurgeResolution{PurgePending}, nil
	case state == "completed" && record.State == GovernanceTombstoned:
		return PurgeResolution{PurgeCompleted}, nil
	default:
		return PurgeResolution{PurgeUnknown}, ErrPurgeOutcomeUnknown
	}
}

func (r *SQLiteRepository) RecoverPurges(ctx context.Context) ([]PurgeReceipt, error) {
	if r == nil || r.db == nil || r.now == nil {
		return nil, ErrPurgeOutcomeUnknown
	}
	rows, err := r.db.QueryContext(ctx, `SELECT o.operation_id,o.tenant_stratum,o.site_stratum,o.dataset_id,o.revision,o.content_sha256,o.requested_at,d.retain_until FROM governance_operations o JOIN dataset_records d ON d.tenant_stratum=o.tenant_stratum AND d.site_stratum=o.site_stratum AND d.dataset_id=o.dataset_id AND d.revision=o.revision WHERE o.state='submitting_unknown' ORDER BY o.operation_id LIMIT ?`, maximumStoredDatasets+1)
	if err != nil {
		return nil, ErrPurgeOutcomeUnknown
	}
	type pendingPurge struct {
		receipt              PurgeReceipt
		requested, retention time.Time
	}
	pending := make([]pendingPurge, 0)
	for rows.Next() {
		var value pendingPurge
		var requestedRaw, retentionRaw string
		if err := rows.Scan(&value.receipt.OperationID, &value.receipt.TenantStratum, &value.receipt.SiteStratum, &value.receipt.DatasetID, &value.receipt.Revision, &value.receipt.ContentSHA256, &requestedRaw, &retentionRaw); err != nil {
			_ = rows.Close()
			return nil, ErrPurgeOutcomeUnknown
		}
		value.requested, err = parseDatasetTime(requestedRaw)
		if err != nil {
			_ = rows.Close()
			return nil, ErrPurgeOutcomeUnknown
		}
		value.retention, err = parseDatasetTime(retentionRaw)
		if err != nil {
			_ = rows.Close()
			return nil, ErrPurgeOutcomeUnknown
		}
		pending = append(pending, value)
	}
	if err := rows.Close(); err != nil {
		return nil, ErrPurgeOutcomeUnknown
	}
	if len(pending) > maximumStoredDatasets {
		return nil, ErrPurgeOutcomeUnknown
	}
	completedAt := r.now().UTC()
	if completedAt.IsZero() {
		return nil, ErrPurgeOutcomeUnknown
	}
	receipts := make([]PurgeReceipt, 0, len(pending))
	for _, value := range pending {
		receipts = append(receipts, value.receipt)
		if completedAt.Before(value.requested) || completedAt.Before(value.retention) {
			return receipts, ErrPurgeOutcomeUnknown
		}
		if err := r.finishPurge(ctx, value.receipt, completedAt); err != nil {
			return receipts, err
		}
	}
	return receipts, nil
}

func decodeStoredDataset(ctx context.Context, tx *sql.Tx, tenantStratum, siteStratum, datasetID string, revision uint64) (Dataset, error) {
	var storedTenant, storedSite, storedID, purpose, policy, retain, state, created, content, projection, claims, intervals, reviews string
	var storedRevision uint64
	var tombstone sql.NullString
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT tenant_stratum,site_stratum,dataset_id,revision,purpose_ref,policy_sha256,retain_until,governance_state,created_at,tombstoned_at,content_sha256,projection_sha256,claims_sha256,intervals_sha256,reviews_sha256,dataset_json FROM dataset_records WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`, tenantStratum, siteStratum, datasetID, revision).
		Scan(&storedTenant, &storedSite, &storedID, &storedRevision, &purpose, &policy, &retain, &state, &created, &tombstone, &content, &projection, &claims, &intervals, &reviews, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Dataset{}, ErrNotFound
	}
	if err != nil {
		return Dataset{}, err
	}
	if state == string(GovernancePurgeSubmitting) {
		return Dataset{}, ErrGovernanceInProgress
	}
	if state == string(GovernanceTombstoned) {
		return Dataset{}, ErrTombstoned
	}
	if state != string(GovernanceActive) {
		return Dataset{}, ErrCorruptRepository
	}
	if len(raw) == 0 || len(raw) > maximumStoredDatasetBytes || !validDigest(content) || !validDigest(projection) || digestBytesForDataset(raw) != projection ||
		storedContentDigest(projection, claims, intervals, reviews) != content || protectedDatasetPayload.Match(raw) {
		return Dataset{}, ErrCorruptRepository
	}
	value, err := decodeDatasetProjection(raw)
	if err != nil || validateProjection(value) != nil || storedTenant != tenantStratum || storedSite != siteStratum || storedID != datasetID || storedRevision != revision || value.TenantStratum != storedTenant || value.SiteStratum != storedSite || value.DatasetID != storedID || value.Revision != storedRevision || value.PurposeRef != purpose || value.PolicySHA256 != policy || formatDatasetTime(value.RetainUntil) != retain || string(value.GovernanceState) != state || formatDatasetTime(value.CreatedAt) != created || tombstone.Valid {
		return Dataset{}, ErrCorruptRepository
	}
	if err := validateStoredIndexes(ctx, tx, value, claims, intervals, reviews); err != nil {
		return Dataset{}, err
	}
	return cloneDataset(value, false), nil
}

func validateStoredIndexes(ctx context.Context, tx *sql.Tx, value Dataset, expectedClaimsDigest, expectedIntervalsDigest, expectedReviewsDigest string) error {
	rows, err := tx.QueryContext(ctx, `SELECT ordinal,item_id,media_ref,item_sha256 FROM dataset_items WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=? ORDER BY ordinal LIMIT ?`, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, MaximumItems+1)
	if err != nil {
		return err
	}
	ordinal := 0
	for rows.Next() {
		var storedOrdinal int
		var itemID, mediaRef, digest string
		if err := rows.Scan(&storedOrdinal, &itemID, &mediaRef, &digest); err != nil {
			_ = rows.Close()
			return err
		}
		if ordinal >= len(value.Items) || storedOrdinal != ordinal || value.Items[ordinal].ItemID != itemID || value.Items[ordinal].MediaRef != mediaRef {
			_ = rows.Close()
			return ErrCorruptRepository
		}
		computed, _ := digestStoredValue(value.Items[ordinal])
		if computed != digest {
			_ = rows.Close()
			return ErrCorruptRepository
		}
		ordinal++
	}
	if err := rows.Close(); err != nil || ordinal != len(value.Items) {
		return ErrCorruptRepository
	}
	for itemOrdinal, item := range value.Items {
		rows, err := tx.QueryContext(ctx, `SELECT annotation_ordinal,annotation_id,annotation_sha256,projection_sha256 FROM dataset_annotations WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=? AND item_ordinal=? ORDER BY annotation_ordinal LIMIT ?`, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, itemOrdinal, MaximumAnnotationsPerItem+1)
		if err != nil {
			return err
		}
		annotationOrdinal := 0
		for rows.Next() {
			var storedOrdinal int
			var id, annotationDigest, projectionDigest string
			if err := rows.Scan(&storedOrdinal, &id, &annotationDigest, &projectionDigest); err != nil {
				_ = rows.Close()
				return err
			}
			if annotationOrdinal >= len(item.Annotations) || storedOrdinal != annotationOrdinal || item.Annotations[annotationOrdinal].AnnotationID != id || item.Annotations[annotationOrdinal].AnnotationSHA256 != annotationDigest {
				_ = rows.Close()
				return ErrCorruptRepository
			}
			computed, _ := digestStoredValue(item.Annotations[annotationOrdinal])
			if computed != projectionDigest {
				_ = rows.Close()
				return ErrCorruptRepository
			}
			annotationOrdinal++
		}
		if err := rows.Close(); err != nil || annotationOrdinal != len(item.Annotations) {
			return ErrCorruptRepository
		}
	}
	claims, err := readStoredClaims(ctx, tx, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision)
	if err != nil {
		return err
	}
	digest, err := digestStoredValue(claims)
	if err != nil || digest != expectedClaimsDigest {
		return ErrCorruptRepository
	}
	intervals, err := readStoredSourceIntervals(ctx, tx, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision)
	if err != nil || len(intervals) != len(value.Items) {
		return ErrCorruptRepository
	}
	digest, err = digestStoredValue(intervals)
	if err != nil || digest != expectedIntervalsDigest {
		return ErrCorruptRepository
	}
	reviewBindings, err := readStoredReviewBindings(ctx, tx, value)
	if err != nil || len(reviewBindings) != value.AnnotationCount {
		return ErrCorruptRepository
	}
	digest, err = digestStoredValue(reviewBindings)
	if err != nil || digest != expectedReviewsDigest {
		return ErrCorruptRepository
	}
	return nil
}

func readStoredClaims(ctx context.Context, tx *sql.Tx, tenant, site, datasetID string, revision uint64) ([]identityClaim, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.ordinal,c.identity_kind,c.identity_sha256,c.split,c.claim_sha256,l.split FROM dataset_identity_claims c JOIN identity_ledger l ON l.identity_kind=c.identity_kind AND l.identity_sha256=c.identity_sha256 WHERE c.tenant_stratum=? AND c.site_stratum=? AND c.dataset_id=? AND c.revision=? ORDER BY c.ordinal LIMIT ?`, tenant, site, datasetID, revision, MaximumClaimsPerDataset+1)
	if err != nil {
		return nil, err
	}
	claims := make([]identityClaim, 0)
	ordinal := 0
	previous := ""
	for rows.Next() {
		var storedOrdinal int
		var claim identityClaim
		var split, digest, ledgerSplit string
		if err := rows.Scan(&storedOrdinal, &claim.Kind, &claim.SHA256, &split, &digest, &ledgerSplit); err != nil {
			_ = rows.Close()
			return nil, err
		}
		claim.Split = Split(split)
		key := claim.Kind + "\x00" + claim.SHA256
		computed, _ := digestStoredValue(claim)
		if storedOrdinal != ordinal || key <= previous || validateIdentityClaim(claim) != nil || digest != computed || ledgerSplit != split {
			_ = rows.Close()
			return nil, ErrCorruptRepository
		}
		claims = append(claims, claim)
		previous = key
		ordinal++
	}
	if err := rows.Close(); err != nil || len(claims) == 0 || len(claims) > MaximumClaimsPerDataset {
		return nil, ErrCorruptRepository
	}
	return claims, nil
}

func readStoredSourceIntervals(ctx context.Context, tx *sql.Tx, tenant, site, datasetID string, revision uint64) ([]sourceIntervalClaim, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.ordinal,c.source_sha256,c.interval_sha256,c.split,c.window_start_ns,c.window_end_ns,c.guard_start_ns,c.guard_end_ns,c.adjacency_seconds,c.claim_sha256,l.split,l.window_start_ns,l.window_end_ns,l.guard_start_ns,l.guard_end_ns,l.adjacency_seconds FROM dataset_source_interval_claims c JOIN source_interval_ledger l ON l.source_sha256=c.source_sha256 AND l.interval_sha256=c.interval_sha256 WHERE c.tenant_stratum=? AND c.site_stratum=? AND c.dataset_id=? AND c.revision=? ORDER BY c.ordinal LIMIT ?`, tenant, site, datasetID, revision, MaximumItems+1)
	if err != nil {
		return nil, err
	}
	intervals := make([]sourceIntervalClaim, 0)
	ordinal := 0
	for rows.Next() {
		var storedOrdinal int
		var interval sourceIntervalClaim
		var split, digest, ledgerSplit string
		var ledgerStart, ledgerEnd, ledgerGuardStart, ledgerGuardEnd int64
		var ledgerAdjacency int
		if err := rows.Scan(&storedOrdinal, &interval.SourceSHA256, &interval.IntervalSHA256, &split, &interval.WindowStartUnixNano, &interval.WindowEndUnixNano,
			&interval.GuardStartUnixNano, &interval.GuardEndUnixNano, &interval.AdjacencySeconds, &digest, &ledgerSplit, &ledgerStart, &ledgerEnd,
			&ledgerGuardStart, &ledgerGuardEnd, &ledgerAdjacency); err != nil {
			_ = rows.Close()
			return nil, err
		}
		interval.Split = Split(split)
		interval.WindowStart = time.Unix(0, interval.WindowStartUnixNano).UTC()
		interval.WindowEnd = time.Unix(0, interval.WindowEndUnixNano).UTC()
		computed, _ := digestStoredValue(interval)
		if storedOrdinal != ordinal || validateSourceIntervalClaim(interval) != nil || digest != computed || ledgerSplit != split ||
			ledgerStart != interval.WindowStartUnixNano || ledgerEnd != interval.WindowEndUnixNano || ledgerGuardStart != interval.GuardStartUnixNano ||
			ledgerGuardEnd != interval.GuardEndUnixNano || ledgerAdjacency != interval.AdjacencySeconds {
			_ = rows.Close()
			return nil, ErrCorruptRepository
		}
		if ordinal > 0 {
			previous := intervals[ordinal-1]
			if interval.SourceSHA256 < previous.SourceSHA256 ||
				(interval.SourceSHA256 == previous.SourceSHA256 && interval.WindowStartUnixNano < previous.WindowStartUnixNano) ||
				(interval.SourceSHA256 == previous.SourceSHA256 && interval.WindowStartUnixNano == previous.WindowStartUnixNano && interval.IntervalSHA256 <= previous.IntervalSHA256) {
				_ = rows.Close()
				return nil, ErrCorruptRepository
			}
		}
		intervals = append(intervals, interval)
		ordinal++
	}
	if err := rows.Close(); err != nil || len(intervals) == 0 || len(intervals) > MaximumItems {
		return nil, ErrCorruptRepository
	}
	return intervals, nil
}

func readStoredReviewBindings(ctx context.Context, tx *sql.Tx, value Dataset) ([]annotationReviewBinding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT item_ordinal,annotation_ordinal,review_ordinal,item_id,annotation_id,annotation_sha256,review_set_sha256,review_id,record_sha256,policy_ref,decision,reviewer_sha256,reviewer_role,reviewed_at,review_json
		FROM dataset_annotation_reviews WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?
		ORDER BY item_ordinal,annotation_ordinal,review_ordinal LIMIT ?`, value.TenantStratum, value.SiteStratum, value.DatasetID, value.Revision, MaximumAnnotations*maximumReviewDecisions+1)
	if err != nil {
		return nil, err
	}
	bindings := make([]annotationReviewBinding, 0, value.AnnotationCount)
	rowCount := 0
	for itemOrdinal, item := range value.Items {
		for annotationOrdinal, annotation := range item.Annotations {
			binding := annotationReviewBinding{ItemID: item.ItemID, AnnotationID: annotation.AnnotationID,
				AnnotationSHA256: annotation.AnnotationSHA256, ReviewSetSHA256: annotation.ReviewSetSHA256,
				Reviews: make([]ReviewRecord, 0, annotation.ApprovalCount)}
			seenReviewers := make(map[string]struct{}, annotation.ApprovalCount)
			var latest time.Time
			for reviewOrdinal := 0; reviewOrdinal < annotation.ApprovalCount; reviewOrdinal++ {
				if !rows.Next() {
					_ = rows.Close()
					return nil, ErrCorruptRepository
				}
				rowCount++
				var storedItem, storedAnnotation, storedReview int
				var itemID, annotationID, annotationDigest, reviewSetDigest, reviewID, recordDigest, policy, decision, reviewer, reviewerRole, reviewedAt string
				var raw []byte
				if err := rows.Scan(&storedItem, &storedAnnotation, &storedReview, &itemID, &annotationID, &annotationDigest, &reviewSetDigest, &reviewID, &recordDigest,
					&policy, &decision, &reviewer, &reviewerRole, &reviewedAt, &raw); err != nil {
					_ = rows.Close()
					return nil, ErrCorruptRepository
				}
				review, decodeErr := decodeReviewRecord(raw)
				if decodeErr != nil || storedItem != itemOrdinal || storedAnnotation != annotationOrdinal || storedReview != reviewOrdinal || itemID != item.ItemID || annotationID != annotation.AnnotationID ||
					annotationDigest != annotation.AnnotationSHA256 || reviewSetDigest != annotation.ReviewSetSHA256 || review.ReviewID != reviewID ||
					review.RecordSHA256 != recordDigest || review.PolicyRef != policy || string(review.Decision) != decision ||
					review.ReviewerSHA256 != reviewer || review.ReviewerRole != reviewerRole || formatDatasetTime(review.ReviewedAt) != reviewedAt {
					_ = rows.Close()
					return nil, ErrCorruptRepository
				}
				if review.Decision != ReviewApproved {
					_ = rows.Close()
					return nil, ErrCorruptRepository
				}
				if _, duplicate := seenReviewers[review.ReviewerSHA256]; duplicate {
					_ = rows.Close()
					return nil, ErrCorruptRepository
				}
				seenReviewers[review.ReviewerSHA256] = struct{}{}
				if review.ReviewedAt.After(latest) {
					latest = review.ReviewedAt
				}
				binding.Reviews = append(binding.Reviews, review)
			}
			reviewSetDigest, digestErr := digestStoredValue(binding.Reviews)
			if digestErr != nil || reviewSetDigest != binding.ReviewSetSHA256 || !latest.Equal(annotation.LastReviewedAt) {
				_ = rows.Close()
				return nil, ErrCorruptRepository
			}
			bindings = append(bindings, binding)
		}
	}
	if rows.Next() || rowCount > MaximumAnnotations*maximumReviewDecisions {
		_ = rows.Close()
		return nil, ErrCorruptRepository
	}
	if err := rows.Close(); err != nil {
		return nil, ErrCorruptRepository
	}
	return bindings, nil
}

type datasetQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readFrozenReviewBindings(ctx context.Context, queryer datasetQueryer, tenant, site, datasetID string, revision uint64) ([]annotationReviewBinding, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT item_ordinal,annotation_ordinal,review_ordinal,item_id,annotation_id,annotation_sha256,review_set_sha256,review_id,record_sha256,policy_ref,decision,reviewer_sha256,reviewer_role,reviewed_at,review_json
		FROM dataset_annotation_reviews WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?
		ORDER BY item_ordinal,annotation_ordinal,review_ordinal LIMIT ?`, tenant, site, datasetID, revision, MaximumAnnotations*maximumReviewDecisions+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := make([]annotationReviewBinding, 0)
	lastItem, lastAnnotation, expectedReview := -1, -1, 0
	totalBytes := 0
	for rows.Next() {
		var itemOrdinal, annotationOrdinal, reviewOrdinal int
		var itemID, annotationID, annotationDigest, reviewSetDigest, reviewID, recordDigest, policy, decision, reviewer, reviewerRole, reviewedAt string
		var raw []byte
		if err := rows.Scan(&itemOrdinal, &annotationOrdinal, &reviewOrdinal, &itemID, &annotationID, &annotationDigest, &reviewSetDigest,
			&reviewID, &recordDigest, &policy, &decision, &reviewer, &reviewerRole, &reviewedAt, &raw); err != nil {
			return nil, ErrCorruptRepository
		}
		totalBytes += len(raw)
		if totalBytes > maximumStoredDatasetBytes {
			return nil, ErrCorruptRepository
		}
		if itemOrdinal != lastItem || annotationOrdinal != lastAnnotation {
			if len(bindings) > 0 {
				previous := &bindings[len(bindings)-1]
				digest, _ := digestStoredValue(previous.Reviews)
				if digest != previous.ReviewSetSHA256 {
					return nil, ErrCorruptRepository
				}
			}
			if reviewOrdinal != 0 || itemOrdinal < lastItem || (itemOrdinal == lastItem && annotationOrdinal <= lastAnnotation) || len(bindings) >= MaximumAnnotations {
				return nil, ErrCorruptRepository
			}
			bindings = append(bindings, annotationReviewBinding{ItemID: itemID, AnnotationID: annotationID, AnnotationSHA256: annotationDigest,
				ReviewSetSHA256: reviewSetDigest, Reviews: make([]ReviewRecord, 0)})
			lastItem, lastAnnotation, expectedReview = itemOrdinal, annotationOrdinal, 0
		}
		binding := &bindings[len(bindings)-1]
		if reviewOrdinal != expectedReview || expectedReview >= maximumReviewDecisions || binding.ItemID != itemID || binding.AnnotationID != annotationID ||
			binding.AnnotationSHA256 != annotationDigest || binding.ReviewSetSHA256 != reviewSetDigest {
			return nil, ErrCorruptRepository
		}
		review, decodeErr := decodeReviewRecord(raw)
		if decodeErr != nil || review.ReviewID != reviewID || review.RecordSHA256 != recordDigest || review.PolicyRef != policy ||
			string(review.Decision) != decision || review.ReviewerSHA256 != reviewer || review.ReviewerRole != reviewerRole ||
			formatDatasetTime(review.ReviewedAt) != reviewedAt || review.AnnotationSHA256 != annotationDigest {
			return nil, ErrCorruptRepository
		}
		binding.Reviews = append(binding.Reviews, review)
		expectedReview++
	}
	if err := rows.Err(); err != nil || len(bindings) == 0 {
		return nil, ErrCorruptRepository
	}
	last := &bindings[len(bindings)-1]
	digest, _ := digestStoredValue(last.Reviews)
	if digest != last.ReviewSetSHA256 {
		return nil, ErrCorruptRepository
	}
	return bindings, nil
}

func (r *SQLiteRepository) validateStoredContent(ctx context.Context) error {
	var controlCount, singleton, writeLock int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(singleton),0),COALESCE(MIN(write_lock),-1) FROM repository_control`).
		Scan(&controlCount, &singleton, &writeLock); err != nil || controlCount != 1 || singleton != 1 || writeLock != 0 {
		return ErrCorruptRepository
	}
	var pageCount, pageSize int64
	if err := r.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return ErrCorruptRepository
	}
	if err := r.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil || pageCount <= 0 || pageSize <= 0 || pageCount > maximumStoredRepositoryBytes/pageSize {
		return ErrCorruptRepository
	}
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_stratum,site_stratum,dataset_id,revision,purpose_ref,policy_sha256,retain_until,created_at,governance_state,dataset_json,tombstoned_at,projection_sha256,claims_sha256,intervals_sha256,reviews_sha256,content_sha256 FROM dataset_records ORDER BY tenant_stratum,site_stratum,dataset_id,revision LIMIT ?`, maximumStoredDatasets+1)
	if err != nil {
		return errors.Join(ErrCorruptRepository, err)
	}
	type record struct {
		tenant, site, id                   string
		revision                           uint64
		purpose, policy, retain, createdAt string
		state                              string
		raw                                []byte
		tombstone                          sql.NullString
		claimsSHA256                       string
		intervalsSHA256                    string
		projectionSHA256                   string
		reviewsSHA256                      string
		contentSHA256                      string
	}
	records := make([]record, 0)
	for rows.Next() {
		var value record
		if err := rows.Scan(&value.tenant, &value.site, &value.id, &value.revision, &value.purpose, &value.policy, &value.retain, &value.createdAt, &value.state, &value.raw, &value.tombstone, &value.projectionSHA256, &value.claimsSHA256, &value.intervalsSHA256, &value.reviewsSHA256, &value.contentSHA256); err != nil {
			_ = rows.Close()
			return ErrCorruptRepository
		}
		records = append(records, value)
	}
	if err := rows.Close(); err != nil || len(records) > maximumStoredDatasets {
		return ErrCorruptRepository
	}
	for _, record := range records {
		retainUntil, retainErr := parseDatasetTime(record.retain)
		createdAt, createdErr := parseDatasetTime(record.createdAt)
		if !validPseudonym("tenant", record.tenant) || !validPseudonym("site", record.site) || !validNamespacedRef("dataset-", record.id) || record.revision < 1 ||
			!validNamespacedRef("purpose-", record.purpose) || !validDigest(record.policy) || retainErr != nil || createdErr != nil || !retainUntil.After(createdAt) ||
			!validDigest(record.projectionSHA256) || !validDigest(record.claimsSHA256) || !validDigest(record.intervalsSHA256) || !validDigest(record.reviewsSHA256) ||
			!validDigest(record.contentSHA256) || storedContentDigest(record.projectionSHA256, record.claimsSHA256, record.intervalsSHA256, record.reviewsSHA256) != record.contentSHA256 {
			return ErrCorruptRepository
		}
		tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return ErrCorruptRepository
		}
		claims, claimErr := readStoredClaims(ctx, tx, record.tenant, record.site, record.id, record.revision)
		_ = tx.Rollback()
		claimsDigest, digestErr := digestStoredValue(claims)
		if claimErr != nil || digestErr != nil || claimsDigest != record.claimsSHA256 {
			return ErrCorruptRepository
		}
		intervalTx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return ErrCorruptRepository
		}
		intervals, intervalErr := readStoredSourceIntervals(ctx, intervalTx, record.tenant, record.site, record.id, record.revision)
		_ = intervalTx.Rollback()
		intervalsDigest, digestErr := digestStoredValue(intervals)
		if intervalErr != nil || digestErr != nil || intervalsDigest != record.intervalsSHA256 {
			return ErrCorruptRepository
		}
		switch GovernanceState(record.state) {
		case GovernanceActive:
			if _, err := r.Get(ctx, record.tenant, record.site, record.id, record.revision); err != nil {
				return errors.Join(ErrCorruptRepository, err)
			}
		case GovernancePurgeSubmitting:
			if len(record.raw) == 0 || record.tombstone.Valid || digestBytesForDataset(record.raw) != record.projectionSHA256 {
				return ErrCorruptRepository
			}
			value, decodeErr := decodeDatasetProjection(record.raw)
			if decodeErr != nil || validateProjection(value) != nil || value.TenantStratum != record.tenant || value.SiteStratum != record.site ||
				value.DatasetID != record.id || value.Revision != record.revision || value.PurposeRef != record.purpose || value.PolicySHA256 != record.policy ||
				!value.RetainUntil.Equal(retainUntil) || !value.CreatedAt.Equal(createdAt) {
				return ErrCorruptRepository
			}
			indexTx, beginErr := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if beginErr != nil {
				return ErrCorruptRepository
			}
			indexErr := validateStoredIndexes(ctx, indexTx, value, record.claimsSHA256, record.intervalsSHA256, record.reviewsSHA256)
			_ = indexTx.Rollback()
			if indexErr != nil {
				return ErrCorruptRepository
			}
			var count int
			if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM governance_operations WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=? AND state='submitting_unknown'`, record.tenant, record.site, record.id, record.revision).Scan(&count); err != nil || count != 1 {
				return ErrCorruptRepository
			}
		case GovernanceTombstoned:
			if len(record.raw) != 0 || !record.tombstone.Valid {
				return ErrCorruptRepository
			}
			var itemCount int
			if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dataset_items WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`, record.tenant, record.site, record.id, record.revision).Scan(&itemCount); err != nil || itemCount != 0 {
				return ErrCorruptRepository
			}
			var frozenReviews int
			if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dataset_annotation_reviews WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=?`, record.tenant, record.site, record.id, record.revision).Scan(&frozenReviews); err != nil || frozenReviews < 1 {
				return ErrCorruptRepository
			}
			frozenBindings, bindingErr := readFrozenReviewBindings(ctx, r.db, record.tenant, record.site, record.id, record.revision)
			bindingDigest, digestErr := digestStoredValue(frozenBindings)
			if bindingErr != nil || digestErr != nil || bindingDigest != record.reviewsSHA256 {
				return ErrCorruptRepository
			}
			var operationCount int
			if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM governance_operations WHERE tenant_stratum=? AND site_stratum=? AND dataset_id=? AND revision=? AND state='completed'`, record.tenant, record.site, record.id, record.revision).Scan(&operationCount); err != nil || operationCount != 1 {
				return ErrCorruptRepository
			}
		default:
			return ErrCorruptRepository
		}
	}
	var orphan int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_ledger l LEFT JOIN dataset_identity_claims c ON c.identity_kind=l.identity_kind AND c.identity_sha256=l.identity_sha256 WHERE c.identity_sha256 IS NULL`).Scan(&orphan); err != nil || orphan != 0 {
		return ErrCorruptRepository
	}
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM source_interval_ledger l LEFT JOIN dataset_source_interval_claims c ON c.source_sha256=l.source_sha256 AND c.interval_sha256=l.interval_sha256 WHERE c.interval_sha256 IS NULL`).Scan(&orphan); err != nil || orphan != 0 {
		return ErrCorruptRepository
	}
	operationRows, err := r.db.QueryContext(ctx, `SELECT operation_id,tenant_stratum,site_stratum,dataset_id,revision,content_sha256,authorization_sha256,authorization_json,requested_at,state,completed_at,operation_sha256 FROM governance_operations ORDER BY operation_id LIMIT ?`, maximumStoredDatasets+1)
	if err != nil {
		return ErrCorruptRepository
	}
	type storedOperation struct {
		receipt                              PurgeReceipt
		authorization, requested, state, sha string
		authorizationRaw                     []byte
		completed                            sql.NullString
	}
	operations := make([]storedOperation, 0)
	for operationRows.Next() {
		var operation storedOperation
		if err := operationRows.Scan(&operation.receipt.OperationID, &operation.receipt.TenantStratum, &operation.receipt.SiteStratum, &operation.receipt.DatasetID, &operation.receipt.Revision, &operation.receipt.ContentSHA256, &operation.authorization, &operation.authorizationRaw, &operation.requested, &operation.state, &operation.completed, &operation.sha); err != nil {
			_ = operationRows.Close()
			return ErrCorruptRepository
		}
		operations = append(operations, operation)
	}
	if err := operationRows.Close(); err != nil || len(operations) > maximumStoredDatasets {
		return ErrCorruptRepository
	}
	for _, operation := range operations {
		requestedAt, parseErr := parseDatasetTime(operation.requested)
		expectedDigest, digestErr := purgeOperationDigest(operation.receipt, operation.authorization, requestedAt)
		if parseErr != nil || digestErr != nil || !validPurgeReceipt(operation.receipt) || !validDigest(operation.authorization) || operation.sha != expectedDigest {
			return ErrCorruptRepository
		}
		governance, governanceErr := r.GetGovernance(ctx, operation.receipt.TenantStratum, operation.receipt.SiteStratum, operation.receipt.DatasetID, operation.receipt.Revision)
		if governanceErr != nil || governance.ContentSHA256 != operation.receipt.ContentSHA256 ||
			r.validateGovernanceAuthorizationProof(operation.authorizationRaw, operation.authorization, operation.receipt, requestedAt, governance.RetainUntil) != nil ||
			(operation.state == "submitting_unknown" && (operation.completed.Valid || governance.State != GovernancePurgeSubmitting)) ||
			(operation.state == "completed" && (!operation.completed.Valid || governance.State != GovernanceTombstoned)) ||
			(operation.state != "submitting_unknown" && operation.state != "completed") {
			return ErrCorruptRepository
		}
		if operation.completed.Valid {
			completedAt, err := parseDatasetTime(operation.completed.String)
			if err != nil || governance.TombstonedAt == nil || !completedAt.Equal(*governance.TombstonedAt) {
				return ErrCorruptRepository
			}
		}
	}
	if err := r.validateLedgerProvenance(ctx); err != nil {
		return err
	}
	reviewRows, err := r.db.QueryContext(ctx, `SELECT annotation_sha256,review_id,reviewer_sha256,reviewer_role,decision,policy_ref,reviewed_at,record_sha256,review_json FROM review_records ORDER BY annotation_sha256,review_id LIMIT ?`, maximumStoredReviews+1)
	if err != nil {
		return ErrCorruptRepository
	}
	reviewCount := 0
	for reviewRows.Next() {
		reviewCount++
		var annotation, reviewID, reviewer, reviewerRole, decision, policy, reviewedAt, recordDigest string
		var raw []byte
		if err := reviewRows.Scan(&annotation, &reviewID, &reviewer, &reviewerRole, &decision, &policy, &reviewedAt, &recordDigest, &raw); err != nil {
			_ = reviewRows.Close()
			return ErrCorruptRepository
		}
		record, err := decodeReviewRecord(raw)
		if err != nil || record.AnnotationSHA256 != annotation || record.ReviewID != reviewID || record.ReviewerSHA256 != reviewer || record.ReviewerRole != reviewerRole || string(record.Decision) != decision || record.PolicyRef != policy || formatDatasetTime(record.ReviewedAt) != reviewedAt || record.RecordSHA256 != recordDigest {
			_ = reviewRows.Close()
			return ErrCorruptRepository
		}
	}
	if err := reviewRows.Close(); err != nil || reviewCount > maximumStoredReviews {
		return ErrCorruptRepository
	}
	return nil
}

func (r *SQLiteRepository) validateLedgerProvenance(ctx context.Context) error {
	identityRows, err := r.db.QueryContext(ctx, `SELECT identity_kind,identity_sha256,split,first_claimed_at,first_tenant_stratum,first_site_stratum,first_dataset_id,first_revision,provenance_sha256 FROM identity_ledger ORDER BY identity_kind,identity_sha256 LIMIT ?`, maximumStoredLedgerRows+1)
	if err != nil {
		return ErrCorruptRepository
	}
	identityCount := 0
	for identityRows.Next() {
		identityCount++
		var row identityLedgerProvenance
		var split, firstAt, digest string
		if err := identityRows.Scan(&row.IdentityKind, &row.IdentitySHA256, &split, &firstAt, &row.FirstTenantStratum, &row.FirstSiteStratum,
			&row.FirstDatasetID, &row.FirstRevision, &digest); err != nil {
			_ = identityRows.Close()
			return ErrCorruptRepository
		}
		row.Split = Split(split)
		row.FirstClaimedAt, err = parseDatasetTime(firstAt)
		expected, digestErr := r.ledgerProvenanceDigest("identity-ledger-v1", row)
		if err != nil || digestErr != nil || expected != digest || validateIdentityClaim(identityClaim{Kind: row.IdentityKind, SHA256: row.IdentitySHA256, Split: row.Split}) != nil ||
			!validPseudonym("tenant", row.FirstTenantStratum) || !validPseudonym("site", row.FirstSiteStratum) || !validNamespacedRef("dataset-", row.FirstDatasetID) || row.FirstRevision < 1 {
			_ = identityRows.Close()
			return ErrCorruptRepository
		}
	}
	if err := identityRows.Close(); err != nil || identityCount > maximumStoredLedgerRows {
		return ErrCorruptRepository
	}
	sourceRows, err := r.db.QueryContext(ctx, `SELECT source_sha256,interval_sha256,split,window_start_ns,window_end_ns,guard_start_ns,guard_end_ns,adjacency_seconds,first_claimed_at,first_tenant_stratum,first_site_stratum,first_dataset_id,first_revision,provenance_sha256 FROM source_interval_ledger ORDER BY source_sha256,interval_sha256 LIMIT ?`, maximumStoredLedgerRows+1)
	if err != nil {
		return ErrCorruptRepository
	}
	sourceCount := 0
	for sourceRows.Next() {
		sourceCount++
		var row sourceLedgerProvenance
		var split, firstAt, digest string
		if err := sourceRows.Scan(&row.SourceSHA256, &row.IntervalSHA256, &split, &row.WindowStartUnixNano, &row.WindowEndUnixNano,
			&row.GuardStartUnixNano, &row.GuardEndUnixNano, &row.AdjacencySeconds, &firstAt, &row.FirstTenantStratum,
			&row.FirstSiteStratum, &row.FirstDatasetID, &row.FirstRevision, &digest); err != nil {
			_ = sourceRows.Close()
			return ErrCorruptRepository
		}
		row.Split = Split(split)
		row.FirstClaimedAt, err = parseDatasetTime(firstAt)
		expected, digestErr := r.ledgerProvenanceDigest("source-interval-ledger-v1", row)
		if err != nil || digestErr != nil || expected != digest || !validDigest(row.SourceSHA256) || !validDigest(row.IntervalSHA256) || !validSplit(row.Split) ||
			row.WindowEndUnixNano < row.WindowStartUnixNano || row.GuardStartUnixNano > row.WindowStartUnixNano || row.GuardEndUnixNano < row.WindowEndUnixNano ||
			row.AdjacencySeconds < 0 || row.AdjacencySeconds > maximumAdjacentWindow || !validPseudonym("tenant", row.FirstTenantStratum) ||
			!validPseudonym("site", row.FirstSiteStratum) || !validNamespacedRef("dataset-", row.FirstDatasetID) || row.FirstRevision < 1 {
			_ = sourceRows.Close()
			return ErrCorruptRepository
		}
	}
	if err := sourceRows.Close(); err != nil || sourceCount > maximumStoredLedgerRows {
		return ErrCorruptRepository
	}
	return nil
}

func marshalStoredDataset(value Dataset) ([]byte, string, string, string, string, string, error) {
	if validateAdmission(value) != nil {
		return nil, "", "", "", "", "", ErrInvalidRequest
	}
	raw, err := marshalDatasetProjection(value)
	if err != nil || len(raw) == 0 || len(raw) > maximumStoredDatasetBytes || protectedDatasetPayload.Match(raw) {
		return nil, "", "", "", "", "", ErrInvalidRequest
	}
	projectionDigest := digestBytesForDataset(raw)
	claimsDigest, err := digestStoredValue(value.claims)
	if err != nil {
		return nil, "", "", "", "", "", ErrInvalidRequest
	}
	intervalsDigest, err := digestStoredValue(value.sourceIntervals)
	if err != nil {
		return nil, "", "", "", "", "", ErrInvalidRequest
	}
	reviewsRaw, err := json.Marshal(value.reviewBindings)
	if err != nil || len(reviewsRaw) > maximumStoredDatasetBytes {
		return nil, "", "", "", "", "", ErrInvalidRequest
	}
	reviewsDigest := digestBytesForDataset(reviewsRaw)
	contentDigest := storedContentDigest(projectionDigest, claimsDigest, intervalsDigest, reviewsDigest)
	if !validDigest(contentDigest) {
		return nil, "", "", "", "", "", ErrInvalidRequest
	}
	return raw, projectionDigest, contentDigest, claimsDigest, intervalsDigest, reviewsDigest, nil
}

func storedContentDigest(projection, claims, intervals, reviews string) string {
	digest, err := sha256JSON(struct {
		ProjectionSHA256 string `json:"projectionSha256"`
		ClaimsSHA256     string `json:"claimsSha256"`
		IntervalsSHA256  string `json:"intervalsSha256"`
		ReviewsSHA256    string `json:"reviewsSha256"`
	}{projection, claims, intervals, reviews})
	if err != nil {
		return ""
	}
	return digest
}

func decodeDatasetProjection(raw []byte) (Dataset, error) {
	var value Dataset
	if err := strictjson.ValidateExactFields(raw, &value, maximumIntakeJSONDepth); err != nil {
		return Dataset{}, ErrCorruptRepository
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Dataset{}, ErrCorruptRepository
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Dataset{}, ErrCorruptRepository
	}
	return value, nil
}
func decodeReviewRecord(raw []byte) (ReviewRecord, error) {
	var value ReviewRecord
	if len(raw) == 0 || len(raw) > 64<<10 || strictjson.ValidateExactFields(raw, &value, 8) != nil {
		return ReviewRecord{}, ErrCorruptRepository
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return ReviewRecord{}, ErrCorruptRepository
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || validateReviewRecord(value) != nil {
		return ReviewRecord{}, ErrCorruptRepository
	}
	return value, nil
}

func storedAdmissionBytes(value Dataset, projection []byte) (int, error) {
	parts := []any{value.claims, value.sourceIntervals, value.reviewBindings}
	total := int64(len(projection))
	for _, part := range parts {
		raw, err := json.Marshal(part)
		if err != nil {
			return 0, ErrInvalidRequest
		}
		total += int64(len(raw))
		if total > maximumAdmissionBytes {
			return 0, ErrCapacity
		}
	}
	return int(total), nil
}

func acquireRepositoryWriteLock(ctx context.Context, tx *sql.Tx) error {
	result, err := tx.ExecContext(ctx, `UPDATE repository_control SET write_lock=write_lock WHERE singleton=1`)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrCorruptRepository
	}
	return nil
}

func checkCreateCapacity(ctx context.Context, tx *sql.Tx, value Dataset, incomingBytes int) error {
	frozenReviews := 0
	for _, binding := range value.reviewBindings {
		frozenReviews += len(binding.Reviews)
		if frozenReviews > maximumStoredLedgerRows {
			return ErrCapacity
		}
	}
	checks := []struct {
		query    string
		incoming int
		limit    int
	}{
		{`SELECT COUNT(*) FROM dataset_records`, 1, maximumStoredDatasets},
		{`SELECT COUNT(*) FROM dataset_items`, len(value.Items), maximumStoredLedgerRows},
		{`SELECT COUNT(*) FROM dataset_annotations`, value.AnnotationCount, maximumStoredLedgerRows},
		{`SELECT COUNT(*) FROM identity_ledger`, len(value.claims), maximumStoredLedgerRows},
		{`SELECT COUNT(*) FROM dataset_identity_claims`, len(value.claims), maximumStoredLedgerRows},
		{`SELECT COUNT(*) FROM source_interval_ledger`, len(value.sourceIntervals), maximumStoredLedgerRows},
		{`SELECT COUNT(*) FROM dataset_source_interval_claims`, len(value.sourceIntervals), maximumStoredLedgerRows},
		{`SELECT COUNT(*) FROM dataset_annotation_reviews`, frozenReviews, maximumStoredLedgerRows},
	}
	for _, check := range checks {
		var count int64
		if err := tx.QueryRowContext(ctx, check.query).Scan(&count); err != nil {
			return err
		}
		if count < 0 || int64(check.incoming) > int64(check.limit)-count {
			return ErrCapacity
		}
	}
	return checkRepositoryByteCapacity(ctx, tx, incomingBytes)
}

func checkReviewCapacity(ctx context.Context, tx *sql.Tx, incomingBytes int, annotationSHA256 string) error {
	var total, annotationCount int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM review_records`).Scan(&total); err != nil {
		return ErrReviewUnavailable
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM review_records WHERE annotation_sha256=?`, annotationSHA256).Scan(&annotationCount); err != nil {
		return ErrReviewUnavailable
	}
	if total < 0 || annotationCount < 0 || total >= maximumStoredReviews || annotationCount >= maximumReviewDecisions {
		return ErrCapacity
	}
	if err := checkRepositoryByteCapacity(ctx, tx, incomingBytes); err != nil {
		if errors.Is(err, ErrCapacity) {
			return ErrCapacity
		}
		return ErrReviewUnavailable
	}
	return nil
}

func checkRepositoryByteCapacity(ctx context.Context, tx *sql.Tx, incomingBytes int) error {
	if incomingBytes < 0 || incomingBytes > maximumAdmissionBytes {
		return ErrCapacity
	}
	var pageCount, pageSize int64
	if err := tx.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return err
	}
	if pageCount <= 0 || pageSize <= 0 || pageCount > maximumStoredRepositoryBytes/pageSize {
		return ErrCapacity
	}
	currentBytes := pageCount * pageSize
	// Payloads are duplicated across immutable business rows and indexes. An
	// eight-fold reservation is intentionally conservative and is evaluated
	// while the repository write lock is held.
	const storageAmplification = int64(8)
	remaining := int64(maximumStoredRepositoryBytes) - currentBytes
	if int64(incomingBytes) > remaining/storageAmplification {
		return ErrCapacity
	}
	return nil
}

func (r *SQLiteRepository) validateGovernanceAuthorizationProof(raw []byte, storedHMAC string, receipt PurgeReceipt, requestedAt, retainUntil time.Time) error {
	if len(raw) == 0 || len(raw) > maximumStoredReviewBytes || !validDigest(storedHMAC) || !canonicalTime(requestedAt) || !canonicalTime(retainUntil) {
		return ErrCorruptRepository
	}
	var demand GovernanceDemand
	if strictjson.ValidateExactFields(raw, &demand, 8) != nil {
		return ErrCorruptRepository
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&demand); err != nil {
		return ErrCorruptRepository
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrCorruptRepository
	}
	canonical, err := json.Marshal(demand)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrCorruptRepository
	}
	expectedHMAC, err := r.integrityDigest("governance-demand-v1", demand)
	if err != nil || !hmac.Equal([]byte(storedHMAC), []byte(expectedHMAC)) {
		return ErrCorruptRepository
	}
	preflight := demand.Preflight
	if !validOpaqueRef(preflight.AuthorityRef) || !validDigest(preflight.PrincipalSHA256) || preflight.OperationID != receipt.OperationID ||
		preflight.Operation != OperationPurge || preflight.TenantStratum != receipt.TenantStratum || preflight.SiteStratum != receipt.SiteStratum ||
		preflight.DatasetID != receipt.DatasetID || preflight.Revision != receipt.Revision || !preflight.At.Equal(requestedAt) ||
		demand.ContentSHA256 != receipt.ContentSHA256 || !demand.RetainUntil.Equal(retainUntil) {
		return ErrCorruptRepository
	}
	return nil
}
func digestStoredValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digestBytesForDataset(raw), nil
}
func digestBytesForDataset(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func validCreateReceipt(value CreateReceipt) bool {
	return validPseudonym("tenant", value.TenantStratum) && validPseudonym("site", value.SiteStratum) && validNamespacedRef("dataset-", value.DatasetID) && value.Revision > 0 && validDigest(value.ContentSHA256)
}
func validPurgeReceipt(value PurgeReceipt) bool {
	return validOpaqueRef(value.OperationID) && validPseudonym("tenant", value.TenantStratum) && validPseudonym("site", value.SiteStratum) && validNamespacedRef("dataset-", value.DatasetID) && value.Revision > 0 && validDigest(value.ContentSHA256)
}
func validatePurgeRequest(value PurgeRequest) error {
	if value.Schema != GovernanceRequestSchema || !validOpaqueRef(value.OperationID) || !validOpaqueRef(value.AuthorityRef) || !validDigest(value.PrincipalSHA256) || !validPseudonym("tenant", value.TenantStratum) || !validPseudonym("site", value.SiteStratum) || !validNamespacedRef("dataset-", value.DatasetID) || value.Revision < 1 {
		return ErrInvalidRequest
	}
	return nil
}
func validateGovernanceRecord(value GovernanceRecord) error {
	if !validPseudonym("tenant", value.TenantStratum) || !validPseudonym("site", value.SiteStratum) || !validNamespacedRef("dataset-", value.DatasetID) || value.Revision < 1 || !validDigest(value.ContentSHA256) || !canonicalTime(value.RetainUntil) {
		return ErrCorruptRepository
	}
	switch value.State {
	case GovernanceActive, GovernancePurgeSubmitting:
		if value.TombstonedAt != nil {
			return ErrCorruptRepository
		}
	case GovernanceTombstoned:
		if value.TombstonedAt == nil || !canonicalTime(*value.TombstonedAt) {
			return ErrCorruptRepository
		}
	default:
		return ErrCorruptRepository
	}
	return nil
}
func validateIdentityClaim(value identityClaim) error {
	if !validIdentityKind(value.Kind) || !validDigest(value.SHA256) || !validSplit(value.Split) {
		return ErrInvalidRequest
	}
	return nil
}
func purgeOperationDigest(receipt PurgeReceipt, authorization string, at time.Time) (string, error) {
	return sha256JSON(struct {
		Receipt             PurgeReceipt `json:"receipt"`
		AuthorizationSHA256 string       `json:"authorizationSha256"`
		RequestedAt         time.Time    `json:"requestedAt"`
	}{receipt, authorization, at})
}
func classifyDefiniteCreateError(err error) error {
	if isConstraint(err) {
		return ErrConflict
	}
	return ErrCreateFailed
}
func classifyDefinitePurgeError(err error) error {
	if isConstraint(err) {
		return ErrConflict
	}
	return ErrPurgeFailed
}
func isConstraint(err error) bool {
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "constraint") || strings.Contains(lower, "unique")
}
func formatDatasetTime(value time.Time) string { return value.UTC().Format(datasetTimestampLayout) }
func parseDatasetTime(value string) (time.Time, error) {
	parsed, err := time.Parse(datasetTimestampLayout, value)
	if err != nil || !canonicalTime(parsed) || formatDatasetTime(parsed) != value {
		return time.Time{}, ErrCorruptRepository
	}
	return parsed, nil
}

func validateDatasetDatabaseShape(database *sql.DB) error {
	var integrity string
	if err := database.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return ErrCorruptRepository
	}
	expected, err := expectedDatasetDatabaseObjects()
	if err != nil {
		return ErrUnsupportedRepositorySchema
	}
	actual, err := readDatasetDatabaseObjects(database)
	if err != nil || len(actual) != len(expected) {
		return ErrUnsupportedRepositorySchema
	}
	for key, expectedSQL := range expected {
		actualSQL, exists := actual[key]
		if !exists || normalizeDatasetSQL(actualSQL) != normalizeDatasetSQL(expectedSQL) {
			return ErrUnsupportedRepositorySchema
		}
	}
	foreign, err := database.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return ErrCorruptRepository
	}
	if foreign.Next() {
		_ = foreign.Close()
		return ErrCorruptRepository
	}
	if err := foreign.Close(); err != nil {
		return ErrCorruptRepository
	}
	return nil
}

func expectedDatasetDatabaseObjects() (map[string]string, error) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer database.Close()
	if _, err := database.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		return nil, err
	}
	if _, err := database.Exec(datasetDatabaseSchema); err != nil {
		return nil, err
	}
	return readDatasetDatabaseObjects(database)
}

func readDatasetDatabaseObjects(database *sql.DB) (map[string]string, error) {
	rows, err := database.Query(`SELECT type,name,sql FROM sqlite_master WHERE type IN ('table','index','trigger','view') AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY type,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var kind, name, sqlText string
		if err := rows.Scan(&kind, &name, &sqlText); err != nil {
			return nil, err
		}
		key := kind + "\x00" + name
		if _, duplicate := result[key]; duplicate {
			return nil, ErrUnsupportedRepositorySchema
		}
		result[key] = sqlText
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
func normalizeDatasetSQL(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}
