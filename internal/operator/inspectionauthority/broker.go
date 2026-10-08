// Package inspectionauthority owns the restart-safe Operator implementation
// of the InspectionExecution authority broker. The SQLite file contains only
// integrity-protected bindings and consumption facts; the independent MAC key
// is held exclusively by credential.SecretStore.
package inspectionauthority

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	coreauthority "github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/authority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
)

const (
	// DatabaseFilename is the single production state filename owned by this
	// broker under the Operator's protected product root.
	DatabaseFilename            = "execution-authority.db"
	macKeyEntropyBytes          = 32
	macKeyBytes                 = 64 // lowercase hex; accepted by every native SecretStore backend
	maximumStepScopes           = 10_000
	authorizationProofDomain    = "cosmoedge.inspection.execution-authority.v3\x00"
	authorizationRecordDomain   = "cosmoedge.operator.inspection-authority.authorization.v1\x00"
	consumptionRecordDomain     = "cosmoedge.operator.inspection-authority.consumption.v1\x00"
	consumptionOperationDomain  = "cosmoedge.operator.inspection-authority.operation.v1\x00"
	consumptionAnchorDomain     = "cosmoedge.operator.inspection-authority.consumption-anchor.v1\x00"
	consumptionGenesisDomain    = "cosmoedge.operator.inspection-authority.consumption-genesis.v1\x00"
	consumptionTransitionDomain = "cosmoedge.operator.inspection-authority.consumption-transition.v1\x00"
	revocationAnchorDomain      = "cosmoedge.operator.inspection-authority.revocation-anchor.v1\x00"
	revocationRecordDomain      = "cosmoedge.operator.inspection-authority.revocation-record.v1\x00"
)

var (
	ErrInvalidConfig  = errors.New("inspection authority configuration is invalid")
	ErrSchema         = errors.New("inspection authority store schema is unsupported")
	ErrIntegrity      = errors.New("inspection authority state integrity check failed")
	ErrKeyUnavailable = errors.New("inspection authority key is unavailable")

	protectedRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requestKeyPattern   = regexp.MustCompile(`^req_[0-9a-f]{32}$`)
)

// Config has no fallback key or in-memory mode. Secrets is mandatory and the
// supplied store remains the sole owner of the MAC key across restarts.
type Config struct {
	Path     string
	IssuerID string
	Secrets  credential.SecretStore
	Now      func() time.Time
}

// DurableBroker implements the narrow core authority.Broker contract. It does
// not expose its database, credential reference, key, identities, or records.
type DurableBroker struct {
	mu       sync.RWMutex
	writeMu  sync.Mutex
	db       *sql.DB
	key      []byte
	path     string
	issuerID string
	secrets  credential.SecretStore
	now      func() time.Time
}

var _ coreauthority.Broker = (*DurableBroker)(nil)

func (*DurableBroker) String() string   { return "[inspection-durable-authority-broker]" }
func (*DurableBroker) GoString() string { return "inspectionauthority.DurableBroker([redacted])" }
func (*DurableBroker) LogValue() slog.Value {
	return slog.StringValue("[inspection-durable-authority-broker]")
}

func Open(config Config) (*DurableBroker, error) {
	if !validProtectedRef(config.IssuerID) || strings.TrimSpace(config.Path) == "" ||
		strings.ContainsAny(config.Path, "\x00?#") || interfaceNil(config.Secrets) {
		return nil, ErrInvalidConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	lock, err := acquireSagaLock(config.Path)
	if err != nil {
		return nil, err
	}
	database, err := openDatabase(config.Path)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	fail := func(openErr error, key []byte) (*DurableBroker, error) {
		clearBytes(key)
		_ = database.Close()
		_ = lock.Close()
		return nil, openErr
	}
	key, err := establishKey(context.Background(), database, config.Secrets, config.IssuerID)
	if err != nil {
		return fail(err, key)
	}
	if err := recoverPendingConsumption(context.Background(), database, config.Secrets, key); err != nil {
		return fail(err, key)
	}
	if err := lock.Close(); err != nil {
		return fail(err, key)
	}
	lock = nil
	if err := validateDatabaseContent(context.Background(), database, key, config.IssuerID); err != nil {
		return fail(err, key)
	}
	absolute, err := filepath.Abs(config.Path)
	if err != nil {
		return fail(err, key)
	}
	return &DurableBroker{
		db: database, key: key, path: absolute, issuerID: config.IssuerID, secrets: config.Secrets, now: config.Now,
	}, nil
}

func (b *DurableBroker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	clearBytes(b.key)
	b.key = nil
	b.secrets = nil
	b.path = ""
	if b.db == nil {
		return nil
	}
	err := b.db.Close()
	b.db = nil
	return err
}

func (b *DurableBroker) Issue(ctx context.Context, demand coreauthority.IssueDemand) (coreauthority.Authorization, bool, error) {
	if err := contextError(ctx); err != nil {
		return coreauthority.Authorization{}, false, err
	}
	if b == nil {
		return coreauthority.Authorization{}, false, coreauthority.ErrClosed
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.db == nil || len(b.key) != macKeyBytes {
		return coreauthority.Authorization{}, false, coreauthority.ErrClosed
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	lock, err := acquireSagaLock(b.path)
	if err != nil {
		return coreauthority.Authorization{}, false, err
	}
	defer lock.Close()
	if err := recoverPendingConsumption(ctx, b.db, b.secrets, b.key); err != nil {
		return coreauthority.Authorization{}, false, err
	}
	if err := b.validateAnchoredState(ctx); err != nil {
		return coreauthority.Authorization{}, false, err
	}
	at := b.now().UTC()
	demand.Steps = cloneAndSortScopes(demand.Steps)
	if !validIssueDemand(demand, at) {
		return coreauthority.Authorization{}, false, coreauthority.ErrUnauthorized
	}

	existing, err := loadAuthorization(ctx, b.db, b.key, demand.RunID)
	if err == nil {
		if !authorizationMatchesDemand(existing.authorization, demand) {
			return coreauthority.Authorization{}, false, coreauthority.ErrConflict
		}
		if !existing.revokedAt.IsZero() || !at.Before(existing.authorization.ExpiresAt) {
			return coreauthority.Authorization{}, false, coreauthority.ErrConflict
		}
		return cloneAuthorization(existing.authorization), false, nil
	}
	if !errors.Is(err, coreauthority.ErrNotFound) {
		return coreauthority.Authorization{}, false, err
	}

	authorizationID, err := randomAuthorizationID(rand.Reader)
	if err != nil {
		return coreauthority.Authorization{}, false, err
	}
	authorization := coreauthority.Authorization{
		Schema: coreauthority.SchemaVersion, IssuerID: b.issuerID, AuthorizationID: authorizationID,
		Identity: demand.Identity, TenantID: demand.TenantID, SiteID: demand.SiteID, RunID: demand.RunID,
		PlanSHA256: demand.PlanSHA256, AssignmentID: demand.AssignmentID,
		AssignmentRevision: demand.AssignmentRevision, RequestKey: demand.RequestKey,
		RuntimeID: demand.RuntimeID, Steps: cloneScopes(demand.Steps), IssuedAt: at,
		ExpiresAt: demand.Deadline.UTC(),
	}
	authorization.ProofSHA256, err = proofFor(b.key, authorization)
	if err != nil || !validAuthorization(authorization) {
		return coreauthority.Authorization{}, false, coreauthority.ErrUnauthorized
	}
	record, err := newAuthorizationRecord(b.key, authorization, time.Time{})
	if err != nil {
		return coreauthority.Authorization{}, false, err
	}
	result, err := b.db.ExecContext(ctx, insertAuthorizationSQL, authorizationRecordValues(record)...)
	if err != nil {
		return coreauthority.Authorization{}, false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return coreauthority.Authorization{}, false, err
	}
	if inserted == 1 {
		return cloneAuthorization(authorization), true, nil
	}
	// Another process won the insert. Only an exact active replay converges.
	existing, err = loadAuthorization(ctx, b.db, b.key, demand.RunID)
	if err != nil {
		return coreauthority.Authorization{}, false, err
	}
	if !authorizationMatchesDemand(existing.authorization, demand) || !existing.revokedAt.IsZero() || !at.Before(existing.authorization.ExpiresAt) {
		return coreauthority.Authorization{}, false, coreauthority.ErrConflict
	}
	return cloneAuthorization(existing.authorization), false, nil
}

func (b *DurableBroker) Lookup(ctx context.Context, runID string) (coreauthority.Authorization, error) {
	if err := contextError(ctx); err != nil {
		return coreauthority.Authorization{}, err
	}
	if b == nil || !validProtectedRef(runID) {
		return coreauthority.Authorization{}, coreauthority.ErrNotFound
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.db == nil || len(b.key) != macKeyBytes {
		return coreauthority.Authorization{}, coreauthority.ErrClosed
	}
	if err := b.validateAnchoredState(ctx); err != nil {
		return coreauthority.Authorization{}, err
	}
	record, err := loadAuthorization(ctx, b.db, b.key, runID)
	if err != nil {
		return coreauthority.Authorization{}, err
	}
	at := b.now().UTC()
	if at.IsZero() || at.Before(record.authorization.IssuedAt) || !at.Before(record.authorization.ExpiresAt) || !record.revokedAt.IsZero() {
		return coreauthority.Authorization{}, coreauthority.ErrNotFound
	}
	return cloneAuthorization(record.authorization), nil
}

func (b *DurableBroker) VerifyAndConsume(ctx context.Context, supplied coreauthority.Authorization, demand coreauthority.StepDemand) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if b == nil {
		return coreauthority.ErrUnauthorized
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.db == nil || len(b.key) != macKeyBytes || !validAuthorization(supplied) || !validStepDemand(demand) {
		return coreauthority.ErrUnauthorized
	}
	record, err := loadAuthorization(ctx, b.db, b.key, demand.RunID)
	if err != nil {
		if errors.Is(err, ErrIntegrity) {
			return errors.Join(coreauthority.ErrUnauthorized, err)
		}
		return coreauthority.ErrUnauthorized
	}
	if !sameAuthorization(record.authorization, supplied) || !record.revokedAt.IsZero() {
		return coreauthority.ErrUnauthorized
	}
	at := b.now().UTC()
	if at.IsZero() || at.Before(supplied.IssuedAt) || !at.Before(supplied.ExpiresAt) || !authorizationAllows(supplied, demand) {
		return coreauthority.ErrUnauthorized
	}
	return b.consumeAnchored(ctx, supplied, demand, at)
}

func (b *DurableBroker) Revoke(ctx context.Context, runID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if b == nil || !validProtectedRef(runID) {
		return coreauthority.ErrNotFound
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.db == nil || len(b.key) != macKeyBytes {
		return coreauthority.ErrClosed
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	lock, err := acquireSagaLock(b.path)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := recoverPendingConsumption(ctx, b.db, b.secrets, b.key); err != nil {
		return err
	}
	record, err := loadAuthorization(ctx, b.db, b.key, runID)
	if err != nil {
		return err
	}
	if !record.revokedAt.IsZero() {
		state, found, stateErr := readKeyRecord(ctx, b.db)
		if stateErr != nil || !found {
			return errors.Join(ErrIntegrity, stateErr)
		}
		return validateConsumptionChain(ctx, b.db, b.key, state)
	}
	revokedAt := b.now().UTC()
	if revokedAt.IsZero() {
		return coreauthority.ErrUnauthorized
	}
	if revokedAt.Before(record.authorization.IssuedAt) {
		revokedAt = record.authorization.IssuedAt
	}
	return b.revokeAnchoredLocked(ctx, record, revokedAt)
}

type authorizationRecord struct {
	authorization      coreauthority.Authorization
	stepsJSON          []byte
	revokedAt          time.Time
	recordHMAC         string
	previousRecordHMAC string
}

type consumptionRecord struct {
	authorizationID   string
	stepID            string
	attemptID         string
	authority         coreauthority.StepAuthority
	operationSHA256   string
	consumedAt        time.Time
	anchorGeneration  uint64
	previousAnchorSHA string
	anchorSHA         string
	recordHMAC        string
}

func newAuthorizationRecord(key []byte, authorization coreauthority.Authorization, revokedAt time.Time) (authorizationRecord, error) {
	stepsJSON, err := json.Marshal(authorization.Steps)
	if err != nil {
		return authorizationRecord{}, err
	}
	record := authorizationRecord{authorization: cloneAuthorization(authorization), stepsJSON: stepsJSON, revokedAt: revokedAt}
	record.recordHMAC, err = authorizationRecordHMAC(key, record)
	record.previousRecordHMAC = record.recordHMAC
	return record, err
}

func newConsumptionRecord(authorizationID string, demand coreauthority.StepDemand, at time.Time) (consumptionRecord, error) {
	operation, err := consumptionOperationDigest(demand)
	if err != nil {
		return consumptionRecord{}, err
	}
	record := consumptionRecord{
		authorizationID: authorizationID, stepID: demand.StepID, attemptID: demand.AttemptID,
		authority: demand.Authority, operationSHA256: operation, consumedAt: at.UTC(),
	}
	return record, nil
}

func validIssueDemand(demand coreauthority.IssueDemand, at time.Time) bool {
	return demand.Identity.Validate() == nil && validProtectedRef(demand.TenantID) && validProtectedRef(demand.SiteID) &&
		validProtectedRef(demand.RunID) && validDigest(demand.PlanSHA256) && validProtectedRef(demand.AssignmentID) &&
		demand.AssignmentRevision > 0 && requestKeyPattern.MatchString(demand.RequestKey) &&
		validProtectedRef(demand.RuntimeID) && validScopes(demand.Steps) && !at.IsZero() && demand.Deadline.UTC().After(at)
}

func validAuthorization(value coreauthority.Authorization) bool {
	return value.Schema == coreauthority.SchemaVersion && validProtectedRef(value.IssuerID) &&
		validProtectedRef(value.AuthorizationID) && value.Identity.Validate() == nil &&
		validProtectedRef(value.TenantID) && validProtectedRef(value.SiteID) && validProtectedRef(value.RunID) &&
		validDigest(value.PlanSHA256) && validProtectedRef(value.AssignmentID) && value.AssignmentRevision > 0 &&
		requestKeyPattern.MatchString(value.RequestKey) && validProtectedRef(value.RuntimeID) && validScopes(value.Steps) &&
		!value.IssuedAt.IsZero() && value.IssuedAt == value.IssuedAt.UTC() && value.ExpiresAt == value.ExpiresAt.UTC() &&
		value.ExpiresAt.After(value.IssuedAt) && validDigest(value.ProofSHA256)
}

func validStepDemand(demand coreauthority.StepDemand) bool {
	return demand.Identity.Validate() == nil && validProtectedRef(demand.TenantID) && validProtectedRef(demand.SiteID) &&
		validProtectedRef(demand.RunID) && validDigest(demand.PlanSHA256) && validProtectedRef(demand.AssignmentID) &&
		demand.AssignmentRevision > 0 && requestKeyPattern.MatchString(demand.RequestKey) && validProtectedRef(demand.RuntimeID) &&
		validProtectedRef(demand.StepID) && validProtectedRef(demand.AttemptID) && validStepAuthority(demand.Authority)
}

func validScopes(scopes []coreauthority.StepScope) bool {
	if len(scopes) == 0 || len(scopes) > maximumStepScopes {
		return false
	}
	previous := ""
	for _, scope := range scopes {
		if !validProtectedRef(scope.StepID) || !validStepAuthority(scope.Authority) || scope.StepID <= previous {
			return false
		}
		previous = scope.StepID
	}
	return true
}

func validStepAuthority(value coreauthority.StepAuthority) bool {
	return value == coreauthority.StepAuthorityNone || value == coreauthority.StepAuthorityDeviceRead ||
		value == coreauthority.StepAuthorityInspectionExecution
}

func authorizationMatchesDemand(value coreauthority.Authorization, demand coreauthority.IssueDemand) bool {
	return value.Identity == demand.Identity && value.TenantID == demand.TenantID && value.SiteID == demand.SiteID &&
		value.RunID == demand.RunID && value.PlanSHA256 == demand.PlanSHA256 && value.AssignmentID == demand.AssignmentID &&
		value.AssignmentRevision == demand.AssignmentRevision && value.RequestKey == demand.RequestKey &&
		value.RuntimeID == demand.RuntimeID && value.ExpiresAt.Equal(demand.Deadline.UTC()) && sameScopes(value.Steps, demand.Steps)
}

func authorizationAllows(value coreauthority.Authorization, demand coreauthority.StepDemand) bool {
	if value.Identity != demand.Identity || value.TenantID != demand.TenantID || value.SiteID != demand.SiteID ||
		value.RunID != demand.RunID || value.PlanSHA256 != demand.PlanSHA256 || value.AssignmentID != demand.AssignmentID ||
		value.AssignmentRevision != demand.AssignmentRevision || value.RequestKey != demand.RequestKey || value.RuntimeID != demand.RuntimeID {
		return false
	}
	index := sort.Search(len(value.Steps), func(index int) bool { return value.Steps[index].StepID >= demand.StepID })
	return index < len(value.Steps) && value.Steps[index].StepID == demand.StepID && value.Steps[index].Authority == demand.Authority
}

func sameAuthorization(left, right coreauthority.Authorization) bool {
	return left.Schema == right.Schema && left.IssuerID == right.IssuerID && left.AuthorizationID == right.AuthorizationID &&
		left.Identity == right.Identity && left.TenantID == right.TenantID && left.SiteID == right.SiteID &&
		left.RunID == right.RunID && left.PlanSHA256 == right.PlanSHA256 && left.AssignmentID == right.AssignmentID &&
		left.AssignmentRevision == right.AssignmentRevision && left.RequestKey == right.RequestKey &&
		left.RuntimeID == right.RuntimeID && left.IssuedAt.Equal(right.IssuedAt) && left.ExpiresAt.Equal(right.ExpiresAt) &&
		subtle.ConstantTimeCompare([]byte(left.ProofSHA256), []byte(right.ProofSHA256)) == 1 && sameScopes(left.Steps, right.Steps)
}

func sameScopes(left, right []coreauthority.StepScope) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func proofFor(key []byte, authorization coreauthority.Authorization) (string, error) {
	canonical := struct {
		Schema             string                              `json:"schema"`
		IssuerID           string                              `json:"issuerId"`
		AuthorizationID    string                              `json:"authorizationId"`
		IdentityKind       coreauthority.ExecutionIdentityKind `json:"identityKind"`
		PrincipalSHA256    string                              `json:"principalSha256"`
		TenantID           string                              `json:"tenantId"`
		SiteID             string                              `json:"siteId"`
		RunID              string                              `json:"runId"`
		PlanSHA256         string                              `json:"planSha256"`
		AssignmentID       string                              `json:"assignmentId"`
		AssignmentRevision uint64                              `json:"assignmentRevision"`
		RequestKey         string                              `json:"requestKey"`
		RuntimeID          string                              `json:"runtimeId"`
		Steps              []coreauthority.StepScope           `json:"steps"`
		IssuedAt           time.Time                           `json:"issuedAt"`
		ExpiresAt          time.Time                           `json:"expiresAt"`
	}{
		authorization.Schema, authorization.IssuerID, authorization.AuthorizationID,
		authorization.Identity.Kind, authorization.Identity.PrincipalSHA256, authorization.TenantID,
		authorization.SiteID, authorization.RunID, authorization.PlanSHA256, authorization.AssignmentID,
		authorization.AssignmentRevision, authorization.RequestKey, authorization.RuntimeID,
		cloneScopes(authorization.Steps), authorization.IssuedAt, authorization.ExpiresAt,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return keyedDigest(key, authorizationProofDomain, raw), nil
}

func authorizationRecordHMAC(key []byte, record authorizationRecord) (string, error) {
	canonical := struct {
		Schema             string                              `json:"schema"`
		IssuerID           string                              `json:"issuerId"`
		AuthorizationID    string                              `json:"authorizationId"`
		IdentityKind       coreauthority.ExecutionIdentityKind `json:"identityKind"`
		PrincipalSHA256    string                              `json:"principalSha256"`
		TenantID           string                              `json:"tenantId"`
		SiteID             string                              `json:"siteId"`
		RunID              string                              `json:"runId"`
		PlanSHA256         string                              `json:"planSha256"`
		AssignmentID       string                              `json:"assignmentId"`
		AssignmentRevision uint64                              `json:"assignmentRevision"`
		RequestKey         string                              `json:"requestKey"`
		RuntimeID          string                              `json:"runtimeId"`
		StepsJSON          json.RawMessage                     `json:"steps"`
		IssuedAt           string                              `json:"issuedAt"`
		ExpiresAt          string                              `json:"expiresAt"`
		ProofSHA256        string                              `json:"proofSha256"`
		RevokedAt          string                              `json:"revokedAt"`
	}{
		record.authorization.Schema, record.authorization.IssuerID, record.authorization.AuthorizationID,
		record.authorization.Identity.Kind, record.authorization.Identity.PrincipalSHA256,
		record.authorization.TenantID, record.authorization.SiteID, record.authorization.RunID,
		record.authorization.PlanSHA256, record.authorization.AssignmentID, record.authorization.AssignmentRevision,
		record.authorization.RequestKey, record.authorization.RuntimeID, json.RawMessage(record.stepsJSON),
		formatTime(record.authorization.IssuedAt), formatTime(record.authorization.ExpiresAt),
		record.authorization.ProofSHA256, formatOptionalTime(record.revokedAt),
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return keyedDigest(key, authorizationRecordDomain, raw), nil
}

func consumptionOperationDigest(demand coreauthority.StepDemand) (string, error) {
	canonical := struct {
		IdentityKind       coreauthority.ExecutionIdentityKind `json:"identityKind"`
		PrincipalSHA256    string                              `json:"principalSha256"`
		Authority          coreauthority.StepAuthority         `json:"authority"`
		TenantID           string                              `json:"tenantId"`
		SiteID             string                              `json:"siteId"`
		RunID              string                              `json:"runId"`
		PlanSHA256         string                              `json:"planSha256"`
		AssignmentID       string                              `json:"assignmentId"`
		AssignmentRevision uint64                              `json:"assignmentRevision"`
		RequestKey         string                              `json:"requestKey"`
		RuntimeID          string                              `json:"runtimeId"`
		StepID             string                              `json:"stepId"`
		AttemptID          string                              `json:"attemptId"`
	}{demand.Identity.Kind, demand.Identity.PrincipalSHA256, demand.Authority, demand.TenantID, demand.SiteID,
		demand.RunID, demand.PlanSHA256, demand.AssignmentID, demand.AssignmentRevision, demand.RequestKey,
		demand.RuntimeID, demand.StepID, demand.AttemptID}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(consumptionOperationDomain), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func consumptionRecordHMAC(key []byte, record consumptionRecord) (string, error) {
	canonical := struct {
		AuthorizationID  string                      `json:"authorizationId"`
		StepID           string                      `json:"stepId"`
		AttemptID        string                      `json:"attemptId"`
		Authority        coreauthority.StepAuthority `json:"authority"`
		Operation        string                      `json:"operationSha256"`
		ConsumedAt       string                      `json:"consumedAt"`
		AnchorGeneration uint64                      `json:"anchorGeneration"`
		PreviousAnchor   string                      `json:"previousAnchorSha256"`
		Anchor           string                      `json:"anchorSha256"`
	}{record.authorizationID, record.stepID, record.attemptID, record.authority, record.operationSHA256,
		formatTime(record.consumedAt), record.anchorGeneration, record.previousAnchorSHA, record.anchorSHA}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return keyedDigest(key, consumptionRecordDomain, raw), nil
}

func keyedDigest(key []byte, domain string, raw []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

type secretEnvelopeDisk struct {
	Version    int    `json:"version"`
	KeyHex     string `json:"keyHex"`
	Generation uint64 `json:"generation"`
	AnchorSHA  string `json:"anchorSha256"`
}

func encodeSecretEnvelope(key []byte, generation uint64, anchorSHA string) ([]byte, error) {
	if len(key) != macKeyBytes || !validDigest(string(key)) || !validDigest(anchorSHA) {
		return nil, ErrIntegrity
	}
	return json.Marshal(secretEnvelopeDisk{Version: 1, KeyHex: string(key), Generation: generation, AnchorSHA: anchorSHA})
}

func decodeSecretEnvelope(raw []byte) ([]byte, uint64, string, error) {
	if len(raw) == 0 || len(raw) > 1024 {
		return nil, 0, "", ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var disk secretEnvelopeDisk
	if err := decoder.Decode(&disk); err != nil {
		return nil, 0, "", ErrIntegrity
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || disk.Version != 1 ||
		!validDigest(disk.KeyHex) || !validDigest(disk.AnchorSHA) {
		return nil, 0, "", ErrIntegrity
	}
	canonical, err := json.Marshal(disk)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, 0, "", ErrIntegrity
	}
	return []byte(disk.KeyHex), disk.Generation, disk.AnchorSHA, nil
}

func genesisAnchor(key []byte) string { return keyedDigest(key, consumptionGenesisDomain, nil) }

func decodeScopes(raw []byte) ([]coreauthority.StepScope, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrIntegrity
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var scopes []coreauthority.StepScope
	if err := decoder.Decode(&scopes); err != nil {
		return nil, ErrIntegrity
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !validScopes(scopes) {
		return nil, ErrIntegrity
	}
	canonical, err := json.Marshal(scopes)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrIntegrity
	}
	return scopes, nil
}

func cloneAuthorization(value coreauthority.Authorization) coreauthority.Authorization {
	value.Steps = cloneScopes(value.Steps)
	return value
}

func cloneScopes(values []coreauthority.StepScope) []coreauthority.StepScope {
	return append([]coreauthority.StepScope(nil), values...)
}

func cloneAndSortScopes(values []coreauthority.StepScope) []coreauthority.StepScope {
	result := cloneScopes(values)
	sort.Slice(result, func(left, right int) bool { return result[left].StepID < result[right].StepID })
	return result
}

func validProtectedRef(value string) bool {
	return value == strings.TrimSpace(value) && protectedRefPattern.MatchString(value)
}

func validDigest(value string) bool {
	if !digestPattern.MatchString(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatTime(value)
}

func randomAuthorizationID(reader io.Reader) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(reader, buffer); err != nil {
		return "", err
	}
	return "authorization_" + hex.EncodeToString(buffer), nil
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("inspection authority context is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
