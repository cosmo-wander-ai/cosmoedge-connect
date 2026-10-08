package deployment

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
)

var (
	ErrInvalidRequest = errors.New("invalid deployment request")
	ErrUnavailable    = errors.New("deployment target or connection is unavailable")
	ErrAlgorithmUsage = errors.New("algorithm does not support continuous tasks")
	ErrConflict       = errors.New("deployment request or session conflicts with existing authority")
)

const proposalTTL = 15 * time.Minute

type Service struct {
	store          *ledger.Store
	provider       ConnectionProvider
	now            func() time.Time
	mu             sync.Mutex
	materials      map[string]*material
	verifyDuration time.Duration
	verifyInterval time.Duration
}

type material struct {
	meta              metadata
	before            State
	target            Configuration
	token             string
	confirmed         bool
	serial            string
	transport         string
	sourceFingerprint string
	session           string
	expiresAt         time.Time
}

// Only stable targets, configuration digests and display labels are durable.
// Native parameter values and confirmation authority stay in process memory.
type metadata struct {
	Target              Proposal `json:"target"`
	ConfigurationDigest string   `json:"configurationDigest"`
	ConnectionDigest    string   `json:"connectionDigest"`
	RequestDigest       string   `json:"requestDigest"`
}

func New(store *ledger.Store, provider ConnectionProvider) (*Service, error) {
	if store == nil || provider == nil {
		return nil, errors.New("deployment ledger and connection provider are required")
	}
	return &Service{store: store, provider: provider, now: time.Now, materials: map[string]*material{}, verifyDuration: 15 * time.Second, verifyInterval: time.Second}, nil
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.materials {
		s.deleteLocked(id)
	}
}

func (s *Service) Prepare(ctx context.Context, sessionID string, request Request) (Proposal, error) {
	if !validID(sessionID) || !validID(request.RequestID) || !validID(request.SourceID) || !validID(request.AlgorithmID) {
		return Proposal{}, ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.materials) >= 128 {
		return Proposal{}, ErrUnavailable
	}
	owner := digest("deployment-session", sessionID)
	id := "dep_" + digest(owner, request.RequestID)[len("sha256:"):]
	requestDigest := digest(request.SourceID, request.AlgorithmID, boolString(request.Enabled))
	if record, err := s.store.Get(ctx, id); err == nil {
		var meta metadata
		if record.Kind != Kind || record.SessionBinding != owner || json.Unmarshal([]byte(record.PublicJSON), &meta) != nil || meta.RequestDigest != requestDigest {
			return Proposal{}, ErrConflict
		}
		return s.proposalLocked(record, meta), nil
	} else if !errors.Is(err, ledger.ErrNotFound) {
		return Proposal{}, err
	}
	connection, client, err := s.connection()
	if err != nil {
		return Proposal{}, err
	}
	snapshot, err := connection.Client.Read(ctx)
	if err != nil || snapshot.Identity.Serial != connection.Serial {
		return Proposal{}, ErrUnavailable
	}
	var source device.Camera
	matches := 0
	for _, camera := range snapshot.Cameras {
		if camera.ID == request.SourceID {
			source, matches = camera, matches+1
		}
	}
	if matches != 1 {
		return Proposal{}, ErrUnavailable
	}
	algReader, ok := connection.Client.(device.AlgorithmReader)
	if !ok {
		return Proposal{}, ErrUnavailable
	}
	algorithms, err := algReader.ReadAlgorithms(ctx)
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	var algorithm device.Algorithm
	matches = 0
	for _, candidate := range algorithms {
		if candidate.ID == request.AlgorithmID {
			algorithm, matches = candidate, matches+1
		}
	}
	if matches != 1 {
		return Proposal{}, ErrUnavailable
	}
	if algorithm.Usage == "2" {
		return Proposal{}, ErrAlgorithmUsage
	}
	resource := digest(connection.Serial, "deployment-binding", request.SourceID, request.AlgorithmID)
	for activeID, active := range s.materials {
		if active.meta.Target.SourceID != request.SourceID || active.meta.Target.AlgorithmID != request.AlgorithmID || active.serial != connection.Serial {
			continue
		}
		record, err := s.store.Get(ctx, activeID)
		if err == nil && (record.State == "proposed" || record.State == "queued" || record.State == "claimed" || record.State == "dispatching" || record.State == "verifying") {
			return Proposal{}, ErrConflict
		}
	}
	before, err := client.ReadDeployment(ctx, request.SourceID, request.AlgorithmID)
	if err != nil || before.SourceID != request.SourceID || before.AlgorithmID != request.AlgorithmID || before.ObservedAt.IsZero() ||
		(before.Exists && (before.TaskID == "" || (before.Enabled != 0 && before.Enabled != 1))) {
		return Proposal{}, ErrUnavailable
	}
	if !before.Exists && !request.Enabled {
		return Proposal{}, ErrUnavailable
	}
	target := before.Configuration
	if !before.Exists {
		target, err = client.DefaultDeployment(ctx, request.SourceID, request.AlgorithmID)
		if err != nil {
			return Proposal{}, ErrUnavailable
		}
	}
	proposal := Proposal{ActionRef: id, State: "proposed", SourceID: source.ID, SourceName: source.Name,
		AlgorithmID: algorithm.ID, AlgorithmName: algorithm.Name, Enabled: request.Enabled,
		ExistingBinding: before.Exists, ConfigurationKind: target.Shape, ExpiresAt: s.now().UTC().Add(proposalTTL)}
	if !target.Ready {
		proposal.State, proposal.Missing = "needs_input", append([]string(nil), target.Missing...)
		if len(proposal.Missing) == 0 {
			proposal.Missing = []string{"算法参数或检测区域需要确认"}
		}
		proposal.ActionRef, proposal.ExpiresAt = "", time.Time{}
		return proposal, nil
	}
	configDigest, err := configurationDigest(target)
	if err != nil {
		return Proposal{}, ErrUnavailable
	}
	meta := metadata{Target: proposal, ConfigurationDigest: configDigest, ConnectionDigest: digest(connection.Serial, connection.EndpointFingerprint, source.SourceFingerprint), RequestDigest: requestDigest}
	raw, err := json.Marshal(meta)
	if err != nil {
		return Proposal{}, err
	}
	token, err := randomToken()
	if err != nil {
		return Proposal{}, err
	}
	if err := s.store.Create(ctx, ledger.NewAction{ID: id, Kind: Kind, SessionBinding: owner, ResourceKey: resource, PublicJSON: string(raw), CreatedAt: s.now().UTC(), ExpiresAt: proposal.ExpiresAt}); err != nil {
		return Proposal{}, err
	}
	s.materials[id] = &material{meta: meta, before: cloneState(before), target: cloneConfiguration(target), token: token,
		serial: connection.Serial, transport: connection.EndpointFingerprint, sourceFingerprint: source.SourceFingerprint,
		session: owner, expiresAt: proposal.ExpiresAt}
	proposal.ConfirmationToken = token
	return proposal, nil
}

func (s *Service) Confirm(ctx context.Context, sessionID, actionRef, token string) error {
	_, err := s.ConfirmWithReceipt(ctx, sessionID, actionRef, token)
	return err
}

func (s *Service) ConfirmWithReceipt(ctx context.Context, sessionID, actionRef, token string) (ConfirmationReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	item := s.materials[actionRef]
	if item == nil || item.session != digest("deployment-session", sessionID) || len(token) == 0 || subtle.ConstantTimeCompare([]byte(token), []byte(item.token)) != 1 {
		return ConfirmationReceipt{}, ErrConflict
	}
	if item.confirmed {
		return ConfirmationReceipt{Disposition: "already_confirmed"}, nil // No new durable confirmation.
	}
	connection, _, err := s.connection()
	if err != nil {
		return ConfirmationReceipt{}, err
	}
	// Check the same selection epoch used by Validate and Dispatch before
	// consuming authority. Returning to the original device is a new epoch.
	if connection.Serial != item.serial || connection.EndpointFingerprint != item.transport {
		return ConfirmationReceipt{}, ErrConflict
	}
	if err := s.store.Confirm(ctx, actionRef, item.session, s.now().UTC()); err != nil {
		return ConfirmationReceipt{}, err
	}
	item.confirmed = true
	return ConfirmationReceipt{Disposition: "accepted", NewConfirmationAccepted: true}, nil
}

func (s *Service) Cancel(ctx context.Context, sessionID, actionRef string) error {
	record, err := s.store.Get(ctx, actionRef)
	if err != nil {
		return err
	}
	if record.Kind != Kind || record.SessionBinding != digest("deployment-session", sessionID) {
		return ErrConflict
	}
	if err := s.store.Cancel(ctx, actionRef, digest("deployment-session", sessionID), s.now().UTC()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(actionRef)
	return nil
}

func (s *Service) Status(ctx context.Context, sessionID, actionRef string) (Status, error) {
	record, err := s.store.Inspect(ctx, actionRef)
	if err != nil {
		return Status{}, err
	}
	var meta metadata
	if record.Kind != Kind || record.SessionBinding != digest("deployment-session", sessionID) || json.Unmarshal([]byte(record.PublicJSON), &meta) != nil {
		return Status{}, ErrConflict
	}
	status := Status{ActionRef: actionRef, State: record.State, Class: record.ResultClass, Reason: record.Reason,
		Conclusion: record.Conclusion, Dispatches: record.Dispatches, DeviceWrites: record.DeviceWrites, Target: meta.Target}
	status.Diagnostic, status.DiagnosticMessage = dispatchDiagnostic(record)
	// Project only the existing ledger's closed dispatch outcome. In particular,
	// zero write accounting alone does not distinguish a no-op from rejection.
	switch record.DispatchOutcome {
	case "accepted", "known_failed", "outcome_unknown":
		status.DispatchOutcome = record.DispatchOutcome
	}
	// Read only after the existing kind/owner authorization. A legacy, pending,
	// invalid or unavailable evidence row cannot manufacture historical facts.
	if record.EvidenceStatus == "sealed" {
		if evidence, err := s.store.InspectEvidence(ctx, actionRef); err == nil {
			status.OriginalVerification = originalVerification(evidence, meta.Target)
			status.OriginalVerificationAvailable = status.OriginalVerification != nil
		}
	}
	if record.State == "proposed" {
		s.mu.Lock()
		s.sweepLocked()
		status.Target = s.proposalLocked(record.Action, meta)
		s.mu.Unlock()
	}
	if record.State == "completed" || record.State == "unknown" || record.State == "blocked" {
		if connection, client, err := s.connection(); err == nil {
			if snapshot, err := connection.Client.Read(ctx); err == nil && snapshot.Identity.Serial == connection.Serial {
				for _, source := range snapshot.Cameras {
					if source.ID == meta.Target.SourceID && digest(connection.Serial, connection.EndpointFingerprint, source.SourceFingerprint) == meta.ConnectionDigest {
						observation := s.observe(ctx, client, meta, false)
						if !observation.ObservedAt.IsZero() {
							status.Current = &observation
						}
						break
					}
				}
			}
		}
	}
	// Target is the immutable proposal snapshot. Its saved "proposed" state is
	// not another current lifecycle state; Status.State carries that fact.
	status.Target.State = ""
	return status, nil
}

// GetByRequest resolves an earlier request after a lost HTTP response. It only
// inspects the ledger and current facts and cannot enqueue or repeat a write.
func (s *Service) GetByRequest(ctx context.Context, sessionID, requestID string) (Status, error) {
	if !validID(sessionID) || !validID(requestID) {
		return Status{}, ErrInvalidRequest
	}
	owner := digest("deployment-session", sessionID)
	return s.Status(ctx, sessionID, "dep_"+digest(owner, requestID)[len("sha256:"):])
}

func (s *Service) connection() (device.ActionConnection, Client, error) {
	connection, err := s.provider.ActionConnection()
	if err != nil || connection.Client == nil || connection.Serial == "" || connection.EndpointFingerprint == "" {
		return device.ActionConnection{}, nil, ErrUnavailable
	}
	client, ok := connection.Client.(Client)
	if !ok {
		return device.ActionConnection{}, nil, ErrUnavailable
	}
	return connection, client, nil
}

func (s *Service) proposalLocked(record ledger.Action, meta metadata) Proposal {
	proposal := meta.Target
	proposal.State = record.State
	if item := s.materials[record.ID]; item != nil && !item.confirmed && record.State == "proposed" {
		proposal.ConfirmationToken = item.token
	}
	return proposal
}

func (s *Service) material(id string) (*material, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	item := s.materials[id]
	if item == nil {
		return nil, ErrUnavailable
	}
	copy := *item
	copy.target, copy.before = cloneConfiguration(item.target), cloneState(item.before)
	return &copy, nil
}

func (s *Service) sweepLocked() {
	for id, item := range s.materials {
		if !s.now().UTC().Before(item.expiresAt) {
			s.deleteLocked(id)
		}
	}
}

func (s *Service) deleteLocked(id string) {
	if item := s.materials[id]; item != nil {
		clear(item.target.Document)
		clear(item.before.Configuration.Document)
		item.token = ""
		delete(s.materials, id)
	}
}

func cloneConfiguration(config Configuration) Configuration {
	config.Document = append([]byte(nil), config.Document...)
	config.Missing = append([]string(nil), config.Missing...)
	return config
}

func cloneState(state State) State {
	state.Configuration = cloneConfiguration(state.Configuration)
	return state
}
func boolString(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
