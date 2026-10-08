package authority

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

const (
	minimumSigningKeyBytes  = 32
	maximumSigningKeyBytes  = 128
	minimumAuthorizationTTL = time.Second
)

// EphemeralBroker is a concurrency-safe, signed broker for one runtime
// process. The signing key is injected and every admission carries one
// explicit protected execution identity; no key is generated or serialized.
// Deployments that must survive process
// restart should provide another Broker implementation backed by protected
// authority state.
type EphemeralBroker struct {
	mu       sync.Mutex
	issuerID string
	key      []byte
	ttl      time.Duration
	now      func() time.Time
	active   map[string]Authorization
	consumed map[string]struct{}
	revoked  map[string]struct{}
}

func NewEphemeralBroker(issuerID string, key []byte, ttl time.Duration, now func() time.Time) (*EphemeralBroker, error) {
	if !validRef(issuerID) || len(key) < minimumSigningKeyBytes || len(key) > maximumSigningKeyBytes ||
		ttl < minimumAuthorizationTTL || now == nil {
		return nil, errors.New("inspection authority broker configuration is invalid")
	}
	return &EphemeralBroker{
		issuerID: issuerID, key: append([]byte(nil), key...), ttl: ttl, now: now,
		active: make(map[string]Authorization), consumed: make(map[string]struct{}), revoked: make(map[string]struct{}),
	}, nil
}

func (b *EphemeralBroker) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	clear(b.key)
	b.key = nil
	clear(b.active)
	clear(b.consumed)
	clear(b.revoked)
	b.mu.Unlock()
}

func (b *EphemeralBroker) Issue(ctx context.Context, demand IssueDemand) (Authorization, bool, error) {
	if b == nil {
		return Authorization{}, false, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, false, err
	}
	at := b.now().UTC()
	demand.Steps = cloneAndSortStepScopes(demand.Steps)
	if !validIssueDemand(demand, at) {
		return Authorization{}, false, ErrUnauthorized
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.key) == 0 {
		return Authorization{}, false, ErrClosed
	}
	if _, terminal := b.revoked[demand.RunID]; terminal {
		return Authorization{}, false, ErrUnauthorized
	}
	if existing, exists := b.active[demand.RunID]; exists {
		if at.Before(existing.ExpiresAt) {
			if !authorizationMatches(existing, demand) {
				return Authorization{}, false, ErrConflict
			}
			return cloneAuthorization(existing), false, nil
		}
		b.removeAuthorization(existing)
	}
	authorizationID, err := randomAuthorizationID()
	if err != nil {
		return Authorization{}, false, err
	}
	expiresAt := demand.Deadline.UTC()
	if candidate := at.Add(b.ttl); candidate.After(at) && candidate.Before(expiresAt) {
		expiresAt = candidate
	}
	authorization := Authorization{
		Schema: SchemaVersion, IssuerID: b.issuerID, AuthorizationID: authorizationID, Identity: demand.Identity,
		TenantID: demand.TenantID, SiteID: demand.SiteID, RunID: demand.RunID, PlanSHA256: demand.PlanSHA256,
		AssignmentID: demand.AssignmentID, AssignmentRevision: demand.AssignmentRevision,
		RequestKey: demand.RequestKey, RuntimeID: demand.RuntimeID, Steps: cloneStepScopes(demand.Steps),
		IssuedAt: at, ExpiresAt: expiresAt,
	}
	proof, err := proofFor(b.key, authorization)
	if err != nil {
		return Authorization{}, false, err
	}
	authorization.ProofSHA256 = proof
	if err := authorization.validate(); err != nil {
		return Authorization{}, false, err
	}
	b.active[demand.RunID] = cloneAuthorization(authorization)
	return cloneAuthorization(authorization), true, nil
}

func (b *EphemeralBroker) Lookup(ctx context.Context, runID string) (Authorization, error) {
	if b == nil || !validRef(runID) {
		return Authorization{}, ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.key) == 0 {
		return Authorization{}, ErrClosed
	}
	authorization, exists := b.active[runID]
	if !exists {
		return Authorization{}, ErrNotFound
	}
	return cloneAuthorization(authorization), nil
}

func (b *EphemeralBroker) VerifyAndConsume(ctx context.Context, authorization Authorization, demand StepDemand) error {
	if b == nil {
		return ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if authorization.validate() != nil || !validStepDemand(demand) {
		return ErrUnauthorized
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.key) == 0 {
		return ErrUnauthorized
	}
	stored, exists := b.active[demand.RunID]
	if !exists || stored.AuthorizationID != authorization.AuthorizationID ||
		subtle.ConstantTimeCompare([]byte(stored.ProofSHA256), []byte(authorization.ProofSHA256)) != 1 {
		return ErrUnauthorized
	}
	want, err := proofFor(b.key, authorization)
	if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(authorization.ProofSHA256)) != 1 {
		return ErrUnauthorized
	}
	at := b.now().UTC()
	if at.IsZero() || at.Before(authorization.IssuedAt) || !at.Before(authorization.ExpiresAt) ||
		!authorizationAllows(authorization, demand) {
		return ErrUnauthorized
	}
	// Consumption is bound to the stable run operation rather than to one
	// renewable authorization ID. Reissuing an expired or revoked exact grant
	// must never make the same step attempt executable again.
	consumeKey := demand.RunID + "\x00" + demand.StepID + "\x00" + demand.AttemptID
	if _, replayed := b.consumed[consumeKey]; replayed {
		return ErrUnauthorized
	}
	b.consumed[consumeKey] = struct{}{}
	return nil
}

func (b *EphemeralBroker) Revoke(ctx context.Context, runID string) error {
	if b == nil || !validRef(runID) {
		return ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	authorization, exists := b.active[runID]
	if !exists {
		if _, alreadyRevoked := b.revoked[runID]; alreadyRevoked {
			return nil
		}
		return ErrNotFound
	}
	b.removeAuthorization(authorization)
	b.revoked[runID] = struct{}{}
	return nil
}

func (b *EphemeralBroker) removeAuthorization(authorization Authorization) {
	delete(b.active, authorization.RunID)
}

func authorizationMatches(authorization Authorization, demand IssueDemand) bool {
	if authorization.Identity != demand.Identity || authorization.TenantID != demand.TenantID ||
		authorization.SiteID != demand.SiteID || authorization.RunID != demand.RunID ||
		authorization.PlanSHA256 != demand.PlanSHA256 || authorization.AssignmentID != demand.AssignmentID ||
		authorization.AssignmentRevision != demand.AssignmentRevision || authorization.RequestKey != demand.RequestKey ||
		authorization.RuntimeID != demand.RuntimeID || !sameStepScopes(authorization.Steps, demand.Steps) {
		return false
	}
	return true
}

func sameStepScopes(left, right []StepScope) bool {
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

func authorizationAllows(a Authorization, d StepDemand) bool {
	if d.Identity != a.Identity || d.TenantID != a.TenantID || d.SiteID != a.SiteID || d.RunID != a.RunID ||
		d.PlanSHA256 != a.PlanSHA256 || d.AssignmentID != a.AssignmentID || d.AssignmentRevision != a.AssignmentRevision ||
		d.RequestKey != a.RequestKey || d.RuntimeID != a.RuntimeID {
		return false
	}
	index := sort.Search(len(a.Steps), func(index int) bool { return a.Steps[index].StepID >= d.StepID })
	return index < len(a.Steps) && a.Steps[index].StepID == d.StepID && a.Steps[index].Authority == d.Authority
}

func proofFor(key []byte, authorization Authorization) (string, error) {
	canonical := struct {
		Schema             string                `json:"schema"`
		IssuerID           string                `json:"issuerId"`
		AuthorizationID    string                `json:"authorizationId"`
		IdentityKind       ExecutionIdentityKind `json:"identityKind"`
		PrincipalSHA256    string                `json:"principalSha256"`
		TenantID           string                `json:"tenantId"`
		SiteID             string                `json:"siteId"`
		RunID              string                `json:"runId"`
		PlanSHA256         string                `json:"planSha256"`
		AssignmentID       string                `json:"assignmentId"`
		AssignmentRevision uint64                `json:"assignmentRevision"`
		RequestKey         string                `json:"requestKey"`
		RuntimeID          string                `json:"runtimeId"`
		Steps              []StepScope           `json:"steps"`
		IssuedAt           time.Time             `json:"issuedAt"`
		ExpiresAt          time.Time             `json:"expiresAt"`
	}{
		authorization.Schema, authorization.IssuerID, authorization.AuthorizationID,
		authorization.Identity.Kind, authorization.Identity.PrincipalSHA256,
		authorization.TenantID, authorization.SiteID, authorization.RunID, authorization.PlanSHA256,
		authorization.AssignmentID, authorization.AssignmentRevision, authorization.RequestKey,
		authorization.RuntimeID, cloneStepScopes(authorization.Steps), authorization.IssuedAt, authorization.ExpiresAt,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("cosmoedge.inspection.execution-authority.v3\x00"))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func randomAuthorizationID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "authorization_" + hex.EncodeToString(raw), nil
}

func cloneAuthorization(value Authorization) Authorization {
	value.Steps = cloneStepScopes(value.Steps)
	return value
}

func cloneStepScopes(values []StepScope) []StepScope {
	return append([]StepScope(nil), values...)
}

func cloneAndSortStepScopes(values []StepScope) []StepScope {
	result := cloneStepScopes(values)
	sort.Slice(result, func(i, j int) bool { return result[i].StepID < result[j].StepID })
	return result
}
