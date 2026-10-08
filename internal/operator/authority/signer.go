package authority

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	minimumSigningKeyBytes = 32
	maximumSigningKeyBytes = 128
)

var (
	ErrUnauthorized = errors.New("authority grant is not authorized")
	ErrClosed       = errors.New("authority signer is closed")
)

// Demand is the exact operation a trusted application service is about to
// perform. Verify requires every non-empty binding and every positive budget
// to fit inside the signed grant; structural validation alone never grants
// authority.
type Demand struct {
	Class              Class
	OperationKind      string
	PrincipalSHA256    string
	TenantID           string
	SiteID             string
	DeviceProfileID    string
	SourceHandles      []string
	RunID              string
	ScheduleID         string
	PolicySHA256       string
	MaxFrames          int
	MaxBytes           int64
	MaxDurationSeconds int
}

// Signer is an in-process capability issuer/verifier. Production composition
// must load its key from protected local state; the key is never serialized in
// a Grant. Signer is safe for concurrent use and can be explicitly closed to
// clear its in-memory key copy.
type Signer struct {
	mu       sync.RWMutex
	issuerID string
	key      []byte
}

func GenerateSigner(issuerID string) (*Signer, error) {
	key := make([]byte, minimumSigningKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	signer, err := NewSigner(issuerID, key)
	clear(key)
	return signer, err
}

func NewSigner(issuerID string, key []byte) (*Signer, error) {
	issuerID = strings.TrimSpace(issuerID)
	if !validRef(issuerID) || len(key) < minimumSigningKeyBytes || len(key) > maximumSigningKeyBytes {
		return nil, errors.New("authority signer configuration is invalid")
	}
	return &Signer{issuerID: issuerID, key: append([]byte(nil), key...)}, nil
}

func (s *Signer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	clear(s.key)
	s.key = nil
	s.mu.Unlock()
}

func (s *Signer) Issue(grantID string, class Class, principalSHA256 string, scope Scope, issuedAt, expiresAt time.Time) (Grant, error) {
	if s == nil {
		return Grant{}, ErrClosed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.key) == 0 {
		return Grant{}, ErrClosed
	}
	grant, err := newUnsignedGrant(s.issuerID, grantID, class, principalSHA256, scope, issuedAt, expiresAt)
	if err != nil {
		return Grant{}, err
	}
	proof, err := proofFor(s.key, grant)
	if err != nil {
		return Grant{}, err
	}
	grant.ProofSHA256 = proof
	return grant, grant.Validate()
}

func (s *Signer) Verify(grant Grant, demand Demand, at time.Time) error {
	if s == nil {
		return ErrUnauthorized
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.key) == 0 || grant.IssuerID != s.issuerID || grant.Validate() != nil {
		return ErrUnauthorized
	}
	want, err := proofFor(s.key, grant)
	if err != nil || subtle.ConstantTimeCompare([]byte(grant.ProofSHA256), []byte(want)) != 1 {
		return ErrUnauthorized
	}
	at = at.UTC()
	if at.IsZero() || at.Before(grant.IssuedAt) || !at.Before(grant.ExpiresAt) {
		return ErrUnauthorized
	}
	if !demandAllowed(grant, demand) {
		return ErrUnauthorized
	}
	return nil
}

func proofFor(key []byte, grant Grant) (string, error) {
	unsigned := struct {
		Schema          string    `json:"schema"`
		IssuerID        string    `json:"issuerId"`
		GrantID         string    `json:"grantId"`
		Class           Class     `json:"class"`
		PrincipalSHA256 string    `json:"principalSha256"`
		Scope           Scope     `json:"scope"`
		ScopeSHA256     string    `json:"scopeSha256"`
		IssuedAt        time.Time `json:"issuedAt"`
		ExpiresAt       time.Time `json:"expiresAt"`
	}{
		Schema: grant.Schema, IssuerID: grant.IssuerID, GrantID: grant.GrantID,
		Class: grant.Class, PrincipalSHA256: grant.PrincipalSHA256,
		Scope: grant.Scope, ScopeSHA256: grant.ScopeSHA256,
		IssuedAt: grant.IssuedAt.UTC(), ExpiresAt: grant.ExpiresAt.UTC(),
	}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func demandAllowed(grant Grant, demand Demand) bool {
	demand.PrincipalSHA256 = strings.TrimSpace(demand.PrincipalSHA256)
	demand.TenantID = strings.TrimSpace(demand.TenantID)
	demand.SiteID = strings.TrimSpace(demand.SiteID)
	demand.DeviceProfileID = strings.TrimSpace(demand.DeviceProfileID)
	demand.RunID = strings.TrimSpace(demand.RunID)
	demand.ScheduleID = strings.TrimSpace(demand.ScheduleID)
	demand.PolicySHA256 = strings.TrimSpace(demand.PolicySHA256)
	demand.OperationKind = strings.TrimSpace(demand.OperationKind)
	demand.SourceHandles = normalizeList(demand.SourceHandles)

	if !validDemandShape(demand) {
		return false
	}
	if demand.Class != grant.Class || demand.PrincipalSHA256 != grant.PrincipalSHA256 ||
		demand.TenantID != grant.Scope.TenantID || demand.SiteID != grant.Scope.SiteID ||
		!operationAllowed(grant.Scope.OperationKinds, demand.OperationKind) {
		return false
	}
	if demand.DeviceProfileID != grant.Scope.DeviceProfileID {
		return false
	}
	if demand.RunID != grant.Scope.RunID {
		return false
	}
	if demand.ScheduleID != grant.Scope.ScheduleID {
		return false
	}
	if demand.PolicySHA256 != grant.Scope.PolicySHA256 {
		return false
	}
	if demand.MaxFrames < 0 || demand.MaxBytes < 0 || demand.MaxDurationSeconds < 0 ||
		demand.MaxFrames > grant.Scope.MaxFrames || demand.MaxBytes > grant.Scope.MaxBytes ||
		demand.MaxDurationSeconds > grant.Scope.MaxDurationSeconds {
		return false
	}
	return isSubset(demand.SourceHandles, grant.Scope.SourceHandles)
}

func validDemandShape(demand Demand) bool {
	if !digestPattern.MatchString(demand.PrincipalSHA256) || !validRef(demand.TenantID) ||
		!validRef(demand.SiteID) || demand.OperationKind == "" {
		return false
	}
	for _, source := range demand.SourceHandles {
		if !validRef(source) {
			return false
		}
	}
	switch demand.Class {
	case ConnectionProfileWrite:
		if demand.OperationKind != OpProfileCreate && !validRef(demand.DeviceProfileID) {
			return false
		}
		return demand.RunID == "" && demand.ScheduleID == "" && demand.PolicySHA256 == "" && len(demand.SourceHandles) == 0 &&
			demand.MaxFrames == 0 && demand.MaxBytes == 0 && demand.MaxDurationSeconds == 0
	case DeviceRead:
		return validRef(demand.DeviceProfileID) && demand.RunID == "" && demand.ScheduleID == "" && demand.PolicySHA256 == "" &&
			demand.MaxFrames == 0 && demand.MaxBytes == 0 && demand.MaxDurationSeconds == 0
	case InspectionExecution:
		return validRef(demand.RunID) && demand.ScheduleID == "" &&
			(demand.PolicySHA256 == "" || digestPattern.MatchString(demand.PolicySHA256)) && demand.MaxFrames > 0 &&
			demand.MaxBytes > 0 && demand.MaxDurationSeconds > 0 && operationSourceDemandValid(demand)
	case PersistentDeviceWrite:
		return validRef(demand.DeviceProfileID) && demand.RunID == "" && demand.ScheduleID == "" && demand.PolicySHA256 == "" &&
			len(demand.SourceHandles) == 0 && demand.MaxFrames == 0 && demand.MaxBytes == 0 && demand.MaxDurationSeconds == 0
	case ServiceExecution:
		return validRef(demand.ScheduleID) && demand.RunID == "" && digestPattern.MatchString(demand.PolicySHA256) && demand.MaxFrames > 0 &&
			demand.MaxBytes > 0 && demand.MaxDurationSeconds > 0 && operationSourceDemandValid(demand)
	default:
		return false
	}
}

func operationSourceDemandValid(demand Demand) bool {
	switch demand.OperationKind {
	case OpSourceAcquire, OpReadExistingEvidence:
		return len(demand.SourceHandles) > 0
	default:
		return true
	}
}

func operationAllowed(allowed []string, operation string) bool {
	if operation == "" {
		return false
	}
	index := sort.SearchStrings(allowed, operation)
	return index < len(allowed) && allowed[index] == operation
}

func isSubset(values, allowed []string) bool {
	for _, value := range values {
		index := sort.SearchStrings(allowed, value)
		if index >= len(allowed) || allowed[index] != value {
			return false
		}
	}
	return true
}
