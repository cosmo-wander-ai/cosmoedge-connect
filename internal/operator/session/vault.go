package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/connectiondiagnostic"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/credential"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

var (
	ErrUnauthorized          = errors.New("foreground browser session is unavailable")
	ErrConflict              = errors.New("one-time capability is invalid or already consumed")
	ErrNotConnected          = errors.New("device is not connected")
	ErrIdentityDrift         = errors.New("observed device identity changed")
	ErrInspectionUnsupported = errors.New("connected device does not support typed inspection")
	// Connection-stage errors are deliberately coarse and contain no wrapped
	// transport, endpoint, account, credential, or v1 response detail. Local
	// product surfaces may distinguish the recovery step without projecting a
	// device error across the protected connection boundary.
	ErrConnectionLoginRejected      = errors.New("device login was rejected")
	ErrConnectionLoginThrottled     = errors.New("device login is temporarily throttled")
	ErrConnectionLoginUnavailable   = errors.New("device login is unavailable")
	ErrConnectionReadUnavailable    = errors.New("device information is unavailable after login")
	ErrConnectionPersistenceFailure = errors.New("verified device connection could not be persisted")
	inspectionHandoffRefPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

const (
	bootstrapTTL = 2 * time.Minute
	browserTTL   = 8 * time.Hour
	candidateTTL = 15 * time.Minute

	ViewInspectionInteraction  = "inspection_interaction"
	ViewDeploymentConfirmation = "deployment_confirmation"
	ViewConnection             = "connection"
)

type BrowserAuth struct {
	SessionID  string
	CSRF       string
	View       string
	TaskName   string
	TaskAction string

	inspectionHandoffRef string
	seal                 [32]byte
}

func (BrowserAuth) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (BrowserAuth) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (BrowserAuth) String() string               { return "[operator-browser-auth]" }
func (BrowserAuth) GoString() string             { return "session.BrowserAuth([redacted])" }
func (BrowserAuth) LogValue() slog.Value         { return slog.StringValue("[operator-browser-auth]") }

type OpenIntent struct {
	View       string
	TaskName   string
	TaskAction string
	HandoffRef string
}

func (OpenIntent) MarshalJSON() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (OpenIntent) MarshalText() ([]byte, error) { return nil, credential.ErrProtectedProjection }
func (OpenIntent) String() string               { return "[operator-open-intent]" }
func (OpenIntent) GoString() string             { return "session.OpenIntent([redacted])" }
func (OpenIntent) LogValue() slog.Value         { return slog.StringValue("[operator-open-intent]") }

type ConnectionPreview struct {
	Token                string
	Destination          string
	ExpiresAt            time.Time
	CurrentDestination   string
	ReplacementRequired  bool
	ReplacementAvailable bool
}

type ConnectionInfo struct {
	State    string `json:"state"`
	MaskedID string `json:"maskedId"`
	Type     string `json:"type"`
}

// InspectionConnection is a short-lived, identity-checked view of the current
// foreground device session. It contains no endpoint, credential, token,
// username, serial projection, or endpoint fingerprint. Formatting and
// serialization remain redacted; only the live inspection bridge should use
// Client and Snapshot during one operation.
type InspectionConnection struct {
	client   device.InspectionClient
	snapshot device.Snapshot
	epoch    string
}

// ConnectionEpoch is opaque admission identity, distinct from the physical
// device identity. An explicit A-to-B-to-A replacement cannot reuse an epoch.
func (c InspectionConnection) ConnectionEpoch() string { return c.epoch }

func (InspectionConnection) MarshalJSON() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (InspectionConnection) MarshalText() ([]byte, error) {
	return nil, credential.ErrProtectedProjection
}
func (InspectionConnection) String() string { return "[operator-inspection-connection]" }
func (InspectionConnection) GoString() string {
	return "session.InspectionConnection([redacted])"
}
func (InspectionConnection) LogValue() slog.Value {
	return slog.StringValue("[operator-inspection-connection]")
}

func (c InspectionConnection) Client() device.InspectionClient { return c.client }
func (c InspectionConnection) Snapshot() device.Snapshot       { return cloneInspectionSnapshot(c.snapshot) }

type candidate struct {
	browserID             string
	endpoint              Endpoint
	username              string
	expiresAt             time.Time
	prepared              PreparedConnection
	persistenceGeneration uint64
}

type connection struct {
	client      device.Client
	endpoint    Endpoint
	fingerprint string
	serial      string
	deviceType  string
	epoch       string
}

type Vault struct {
	mu                    sync.Mutex
	now                   func() time.Time
	factory               device.Factory
	persistence           ConnectionPersistence
	persistenceGeneration uint64
	persistenceSeal       [32]byte

	bootstraps map[string]bootstrap
	browsers   map[string]browserSession
	candidates map[string]candidate
	connected  *connection
	connecting bool
	// True only after a saved binding was loaded and a retryable restore failed.
	retrySavedConnection bool
}

type browserSession struct {
	csrf       string
	view       string
	taskName   string
	taskAction string
	handoffRef string
	seal       [32]byte
	expiresAt  time.Time
}

type bootstrap struct {
	view       string
	taskName   string
	taskAction string
	handoffRef string
	expiresAt  time.Time
}

func New(factory device.Factory) *Vault {
	if factory == nil {
		factory = device.NewV1Client
	}
	return &Vault{
		now: time.Now, factory: factory,
		bootstraps: map[string]bootstrap{}, browsers: map[string]browserSession{}, candidates: map[string]candidate{},
	}
}

// BindConnectionPersistence installs the Product-owned registry before an
// ordinary connection page or startup restore is admitted. Rebinding is
// allowed only while disconnected and idle, which lets a stopped Product
// replace a closed generation without exposing stale persistent resources.
func (v *Vault) BindConnectionPersistence(value ConnectionPersistence) (PersistenceLease, error) {
	if v == nil || value == nil {
		return PersistenceLease{}, errors.New("connection persistence is required")
	}
	seal, err := randomSeal()
	if err != nil {
		return PersistenceLease{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.connecting || v.connected != nil || v.persistence != nil {
		return PersistenceLease{}, ErrConflict
	}
	v.persistenceGeneration++
	if v.persistenceGeneration == 0 {
		v.persistenceGeneration++
	}
	v.persistence = value
	v.persistenceSeal = seal
	v.retrySavedConnection = false
	return PersistenceLease{vault: v, generation: v.persistenceGeneration, seal: seal}, nil
}

func (v *Vault) IssueBootstrap() (string, error) {
	return v.IssueBootstrapForView("home")
}

func (v *Vault) IssueBootstrapForView(view string) (string, error) {
	return v.IssueBootstrapForIntent(OpenIntent{View: view})
}

func (v *Vault) IssueBootstrapForIntent(intent OpenIntent) (string, error) {
	intent, err := normalizeOpenIntent(intent)
	if err != nil {
		return "", err
	}
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	v.mu.Lock()
	v.bootstraps[token] = bootstrap{
		view: intent.View, taskName: intent.TaskName, taskAction: intent.TaskAction,
		handoffRef: intent.HandoffRef,
		expiresAt:  v.now().Add(bootstrapTTL),
	}
	v.mu.Unlock()
	return token, nil
}

func (v *Vault) ConsumeBootstrap(token string) (BrowserAuth, error) {
	token = strings.TrimSpace(token)
	v.mu.Lock()
	issued, ok := v.bootstraps[token]
	delete(v.bootstraps, token)
	v.mu.Unlock()
	if !ok || !v.now().Before(issued.expiresAt) {
		return BrowserAuth{}, ErrConflict
	}
	sessionID, err := randomHex(32)
	if err != nil {
		return BrowserAuth{}, err
	}
	csrf, err := randomHex(32)
	if err != nil {
		return BrowserAuth{}, err
	}
	seal, err := randomSeal()
	if err != nil {
		return BrowserAuth{}, err
	}
	browser := browserSession{
		csrf: csrf, view: issued.view, taskName: issued.taskName, taskAction: issued.taskAction,
		handoffRef: issued.handoffRef, seal: seal,
		expiresAt: v.now().Add(browserTTL),
	}
	v.mu.Lock()
	v.browsers[sessionID] = browser
	v.mu.Unlock()
	return browserAuth(sessionID, browser), nil
}

func (v *Vault) Authenticate(sessionID string) (BrowserAuth, error) {
	sessionID = strings.TrimSpace(sessionID)
	v.mu.Lock()
	defer v.mu.Unlock()
	browser, ok := v.browsers[sessionID]
	if !ok || !v.now().Before(browser.expiresAt) {
		delete(v.browsers, sessionID)
		return BrowserAuth{}, ErrUnauthorized
	}
	return browserAuth(sessionID, browser), nil
}

// InspectionHandoff verifies that auth was minted by this exact Vault for the
// currently-live browser session and returns its bootstrap-bound interaction.
// A caller cannot manufacture or retarget the proof because the random seal
// and bound handoff are private fields copied only by Vault authentication.
func (v *Vault) InspectionHandoff(auth BrowserAuth) (string, error) {
	return v.boundHandoff(auth, ViewInspectionInteraction)
}

// DeploymentHandoff accepts only a live, privately sealed deployment browser.
func (v *Vault) DeploymentHandoff(auth BrowserAuth) (string, error) {
	return v.boundHandoff(auth, ViewDeploymentConfirmation)
}

func (v *Vault) boundHandoff(auth BrowserAuth, view string) (string, error) {
	if v == nil || auth.SessionID != strings.TrimSpace(auth.SessionID) {
		return "", ErrUnauthorized
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	browser, ok := v.browsers[auth.SessionID]
	if !ok || !v.now().Before(browser.expiresAt) {
		delete(v.browsers, auth.SessionID)
		return "", ErrUnauthorized
	}
	current := browserAuth(auth.SessionID, browser)
	if auth.SessionID != current.SessionID || auth.View != current.View || auth.TaskName != current.TaskName ||
		auth.TaskAction != current.TaskAction || auth.inspectionHandoffRef != current.inspectionHandoffRef ||
		subtle.ConstantTimeCompare([]byte(auth.CSRF), []byte(current.CSRF)) != 1 ||
		subtle.ConstantTimeCompare(auth.seal[:], current.seal[:]) != 1 ||
		current.View != view || !validInspectionHandoffRef(current.inspectionHandoffRef) {
		return "", ErrUnauthorized
	}
	return current.inspectionHandoffRef, nil
}

func (v *Vault) PrepareConnection(browserID, rawEndpoint, username string) (ConnectionPreview, error) {
	if _, err := v.Authenticate(browserID); err != nil {
		return ConnectionPreview{}, err
	}
	endpoint, err := NormalizeDeviceAddress(rawEndpoint)
	if err != nil {
		return ConnectionPreview{}, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return ConnectionPreview{}, errors.New("device account is required")
	}
	v.mu.Lock()
	persistence, generation, connecting := v.persistence, v.persistenceGeneration, v.connecting
	v.mu.Unlock()
	if connecting {
		return ConnectionPreview{}, ErrConflict
	}
	var prepared PreparedConnection
	if provider, ok := persistence.(ConnectionPreparer); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		prepared, err = provider.PrepareConnection(ctx, endpoint.URL, username)
		cancel()
		if err != nil {
			return ConnectionPreview{}, ErrConnectionPersistenceFailure
		}
	}
	token, err := randomHex(32)
	if err != nil {
		return ConnectionPreview{}, err
	}
	expiresAt := v.now().Add(candidateTTL)
	v.mu.Lock()
	if generation != v.persistenceGeneration || v.connecting {
		v.mu.Unlock()
		return ConnectionPreview{}, ErrConflict
	}
	v.candidates[token] = candidate{browserID: browserID, endpoint: endpoint, username: username, expiresAt: expiresAt, prepared: prepared, persistenceGeneration: generation}
	v.mu.Unlock()
	preview := ConnectionPreview{Token: token, Destination: endpoint.Masked(), ExpiresAt: expiresAt}
	if prepared != nil {
		preview.CurrentDestination = prepared.CurrentDestination()
		preview.ReplacementRequired = prepared.ReplacementRequired()
		preview.ReplacementAvailable = prepared.ReplacementAvailable()
	}
	return preview, nil
}

func (v *Vault) Connect(ctx context.Context, browserID, token string, password []byte) (ConnectionInfo, error) {
	return v.ConnectConfirmed(ctx, browserID, token, password, false)
}

var ErrConnectionReplacementRequired = errors.New("saved device replacement requires explicit local confirmation")

func (v *Vault) ConnectConfirmed(ctx context.Context, browserID, token string, password []byte, replace bool) (ConnectionInfo, error) {
	defer clearBytes(password)
	if _, err := v.Authenticate(browserID); err != nil {
		return ConnectionInfo{}, err
	}
	v.mu.Lock()
	candidate, ok := v.candidates[strings.TrimSpace(token)]
	delete(v.candidates, strings.TrimSpace(token))
	if !ok || candidate.browserID != browserID || !v.now().Before(candidate.expiresAt) || v.connecting || candidate.persistenceGeneration != v.persistenceGeneration {
		v.mu.Unlock()
		return ConnectionInfo{}, ErrConflict
	}
	if replace && (candidate.prepared == nil || !candidate.prepared.ReplacementAvailable()) || !replace && candidate.prepared != nil && candidate.prepared.ReplacementRequired() {
		v.mu.Unlock()
		return ConnectionInfo{}, ErrConnectionReplacementRequired
	}
	v.connecting = true
	persistence := v.persistence
	v.mu.Unlock()
	if candidate.prepared != nil {
		if err := candidate.prepared.Validate(ctx); err != nil {
			v.mu.Lock()
			v.connecting = false
			v.mu.Unlock()
			return ConnectionInfo{}, ErrConflict
		}
	}

	secret := string(password)
	client := v.factory(candidate.endpoint.URL, candidate.username, secret)
	secret = ""
	err := client.Login(ctx)
	var snapshot device.Snapshot
	if err != nil {
		err = classifyConnectionLoginError(err)
	} else {
		snapshot, err = client.Read(ctx)
		if err != nil {
			err = ErrConnectionReadUnavailable
		}
	}

	verified := verifiedConnection(candidate.endpoint, candidate.username, snapshot.Identity)
	if err == nil && !verified.valid() {
		err = ErrConnectionReadUnavailable
	}
	commitAttempted := false
	epoch := ""
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && persistence != nil {
		commitAttempted = true
		commitSecret := append([]byte(nil), password...)
		var commitErr error
		if candidate.prepared != nil {
			commitErr = candidate.prepared.Commit(ctx, verified, commitSecret, strings.TrimSpace(token), replace)
		} else {
			commitErr = persistence.CommitVerified(ctx, verified, commitSecret)
		}
		if commitErr != nil {
			err = ErrConnectionPersistenceFailure
		} else {
			if provider, ok := persistence.(ConnectionPreparer); ok {
				epoch, commitErr = provider.ConnectionEpoch(ctx)
				if commitErr != nil {
					err = ErrConnectionPersistenceFailure
				}
			}
		}
		clearBytes(commitSecret)
	}

	v.mu.Lock()
	v.connecting = false
	if err == nil {
		v.connected = &connection{
			client: client, endpoint: candidate.endpoint,
			fingerprint: executionFingerprint(verified.TransportFingerprint, epoch), epoch: epoch,
			serial: verified.PinnedSerial, deviceType: verified.PinnedType,
		}
	} else if commitAttempted && replace {
		v.connected = nil
	}
	v.mu.Unlock()
	if err != nil {
		return ConnectionInfo{}, err
	}
	return ConnectionInfo{State: "connecting", MaskedID: maskIdentifier(snapshot.Identity.Serial), Type: snapshot.Identity.Type}, nil
}

type loginThrottleMarker interface {
	LoginThrottled() bool
}

type authenticationRejectedMarker interface {
	AuthenticationRejected() bool
}

func classifyConnectionLoginError(err error) error {
	var throttled loginThrottleMarker
	if errors.As(err, &throttled) && throttled.LoginThrottled() {
		return ErrConnectionLoginThrottled
	}
	var rejected authenticationRejectedMarker
	if errors.As(err, &rejected) && rejected.AuthenticationRejected() {
		return ErrConnectionLoginRejected
	}
	return ErrConnectionLoginUnavailable
}

// Restore admits the single durable current profile to the live Vault. It
// performs a new login and identity read on every process start and never
// publishes the client before the persisted endpoint, account fingerprint,
// serial, and device type have all been re-verified.
func (v *Vault) Restore(ctx context.Context) (RestoreResult, error) {
	if v == nil {
		return RestoreResult{}, errors.New("session Vault is required")
	}
	if ctx == nil {
		return RestoreResult{}, errors.New("restore context is required")
	}
	if err := ctx.Err(); err != nil {
		return RestoreResult{}, err
	}
	v.mu.Lock()
	if v.connected != nil {
		v.mu.Unlock()
		return RestoreResult{State: RestoreConnected}, nil
	}
	if v.connecting {
		v.mu.Unlock()
		return RestoreResult{}, ErrConflict
	}
	persistence := v.persistence
	if persistence == nil {
		v.mu.Unlock()
		return RestoreResult{State: RestoreNotConfigured}, nil
	}
	v.connecting = true
	v.mu.Unlock()
	retryAvailable := false
	defer func() {
		v.mu.Lock()
		v.connecting = false
		v.retrySavedConnection = retryAvailable
		v.mu.Unlock()
	}()

	candidate, err := persistence.LoadCurrent(ctx)
	if errors.Is(err, ErrNoSavedConnection) {
		return RestoreResult{State: RestoreNotConfigured}, nil
	}
	if errors.Is(err, ErrSavedConnectionAttention) {
		return RestoreResult{State: RestoreNeedsAttention}, nil
	}
	if err != nil {
		return RestoreResult{}, err
	}
	defer clearRestoreCandidate(&candidate)
	if !candidate.binding.valid() || len(candidate.secret) == 0 {
		return RestoreResult{}, errors.New("saved connection state is invalid")
	}
	endpoint, err := NormalizeDeviceAddress(candidate.binding.Endpoint)
	if err != nil || endpoint.URL != candidate.binding.Endpoint ||
		endpointFingerprint(endpoint, candidate.binding.Username) != candidate.binding.TransportFingerprint {
		return RestoreResult{}, errors.New("saved connection transport binding is invalid")
	}
	retryAvailable = true
	secret := string(candidate.secret)
	started := time.Now()
	client := v.factory(endpoint.URL, candidate.binding.Username, secret)
	secret = ""
	clearBytes(candidate.secret)
	candidate.secret = nil
	if loginErr := client.Login(ctx); loginErr != nil {
		connectiondiagnostic.RecordFailure(ctx, connectiondiagnostic.Login, loginErr, started)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return RestoreResult{}, ctxErr
		}
		if errors.Is(classifyConnectionLoginError(loginErr), ErrConnectionLoginRejected) {
			retryAvailable = false
			if markErr := persistence.MarkCredentialUnavailable(ctx, candidate.binding); markErr != nil {
				return RestoreResult{}, markErr
			}
		}
		return RestoreResult{State: RestoreNeedsAttention}, nil
	}
	connectiondiagnostic.Record(ctx, connectiondiagnostic.Login, connectiondiagnostic.OK, started)
	started = time.Now()
	snapshot, err := client.Read(ctx)
	if err != nil {
		connectiondiagnostic.RecordFailure(ctx, connectiondiagnostic.DeviceRead, err, started)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return RestoreResult{}, ctxErr
		}
		return RestoreResult{State: RestoreNeedsAttention}, nil
	}
	// Some device readers retain partial metadata when optional probes time
	// out. Do not publish that snapshot after the restore budget has expired.
	if err := ctx.Err(); err != nil {
		connectiondiagnostic.Record(ctx, connectiondiagnostic.DeviceRead, connectiondiagnostic.Failure(ctx, err), started)
		return RestoreResult{}, err
	}
	connectiondiagnostic.Record(ctx, connectiondiagnostic.DeviceRead, connectiondiagnostic.OK, started)
	started = time.Now()
	observed := verifiedConnection(endpoint, candidate.binding.Username, snapshot.Identity)
	if !observed.valid() || observed.PinnedSerial != candidate.binding.PinnedSerial ||
		observed.PinnedType != candidate.binding.PinnedType ||
		observed.TransportFingerprint != candidate.binding.TransportFingerprint {
		retryAvailable = false
		connectiondiagnostic.Record(ctx, connectiondiagnostic.Commit, connectiondiagnostic.IdentityMismatch, started)
		if markErr := persistence.MarkIdentityDrift(ctx, candidate.binding); markErr != nil {
			return RestoreResult{}, markErr
		}
		return RestoreResult{State: RestoreNeedsAttention}, nil
	}

	epoch := ""
	if provider, ok := persistence.(ConnectionPreparer); ok {
		epoch, err = provider.ConnectionEpoch(ctx)
		if err != nil {
			connectiondiagnostic.Record(ctx, connectiondiagnostic.Commit, connectiondiagnostic.Failure(ctx, err), started)
			return RestoreResult{}, err
		}
	}
	v.mu.Lock()
	v.connected = &connection{
		client: client, endpoint: endpoint, fingerprint: executionFingerprint(observed.TransportFingerprint, epoch), epoch: epoch,
		serial: observed.PinnedSerial, deviceType: observed.PinnedType,
	}
	v.mu.Unlock()
	connectiondiagnostic.Record(ctx, connectiondiagnostic.Commit, connectiondiagnostic.OK, started)
	return RestoreResult{State: RestoreConnected}, nil
}

func (v *Vault) Read(ctx context.Context) (device.Snapshot, error) {
	v.mu.Lock()
	connected := v.connected
	v.mu.Unlock()
	if connected == nil {
		return device.Snapshot{}, ErrNotConnected
	}
	snapshot, err := connected.client.Read(ctx)
	if err != nil {
		return device.Snapshot{}, err
	}
	if snapshot.Identity.Serial != connected.serial {
		return device.Snapshot{}, ErrIdentityDrift
	}
	return snapshot, nil
}

func (v *Vault) ObserveEvents(ctx context.Context, tasks []device.Task, window device.EventWindow) (device.EventObservation, error) {
	v.mu.Lock()
	connected := v.connected
	v.mu.Unlock()
	if connected == nil {
		return device.EventObservation{}, ErrNotConnected
	}
	return connected.client.ObserveEvents(ctx, tasks, window), nil
}

func (v *Vault) ConnectedIdentity() (maskedID, deviceType string, ok bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.connected == nil {
		return "", "", false
	}
	return maskIdentifier(v.connected.serial), v.connected.deviceType, true
}

// ConnectionEpoch returns only the opaque current admission identity, without
// a device request, so recovery can select its own exact cleanup records.
func (v *Vault) ConnectionEpoch() (string, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.connected == nil {
		return "", false
	}
	return v.connected.epoch, true
}

func (v *Vault) ActionConnection() (device.ActionConnection, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.connected == nil {
		return device.ActionConnection{}, ErrNotConnected
	}
	client, ok := v.connected.client.(device.ActionClient)
	if !ok {
		return device.ActionConnection{}, errors.New("connected client does not support actions")
	}
	return device.ActionConnection{
		Client: client, Serial: v.connected.serial, EndpointFingerprint: v.connected.fingerprint,
	}, nil
}

// InspectionConnection returns the typed inspection surface for the exact
// connection that passed a fresh identity read. A concurrent reconnect makes
// the result unavailable instead of allowing an old authenticated client to
// escape the Vault.
func (v *Vault) InspectionConnection(ctx context.Context) (InspectionConnection, error) {
	if v == nil {
		return InspectionConnection{}, ErrNotConnected
	}
	if ctx == nil {
		ctx = context.Background()
	}
	v.mu.Lock()
	connected := v.connected
	v.mu.Unlock()
	if connected == nil {
		return InspectionConnection{}, ErrNotConnected
	}
	client, ok := connected.client.(device.InspectionClient)
	if !ok {
		return InspectionConnection{}, ErrInspectionUnsupported
	}
	snapshot, err := client.Read(ctx)
	if err != nil {
		return InspectionConnection{}, err
	}
	if snapshot.Identity.Serial == "" || snapshot.Identity.Serial != connected.serial {
		return InspectionConnection{}, ErrIdentityDrift
	}
	v.mu.Lock()
	unchanged := v.connected == connected
	v.mu.Unlock()
	if !unchanged {
		return InspectionConnection{}, ErrNotConnected
	}
	return InspectionConnection{client: client, snapshot: cloneInspectionSnapshot(snapshot), epoch: connected.epoch}, nil
}

func executionFingerprint(transport, epoch string) string {
	if epoch == "" {
		return transport
	}
	digest := sha256.Sum256([]byte("cosmoedge-connect.execution-connection.v1\x00" + transport + "\x00" + epoch))
	return hex.EncodeToString(digest[:])
}

func cloneInspectionSnapshot(snapshot device.Snapshot) device.Snapshot {
	cloned := snapshot
	cloned.Cameras = append([]device.Camera(nil), snapshot.Cameras...)
	cloned.Tasks = append([]device.Task(nil), snapshot.Tasks...)
	if snapshot.Health.CPUPercent != nil {
		cpu := *snapshot.Health.CPUPercent
		cloned.Health.CPUPercent = &cpu
	}
	return cloned
}

func randomHex(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func randomSeal() ([32]byte, error) {
	var seal [32]byte
	_, err := rand.Read(seal[:])
	return seal, err
}

func browserAuth(sessionID string, browser browserSession) BrowserAuth {
	return BrowserAuth{
		SessionID: sessionID, CSRF: browser.csrf, View: browser.view,
		TaskName: browser.taskName, TaskAction: browser.taskAction,
		inspectionHandoffRef: browser.handoffRef, seal: browser.seal,
	}
}

func maskIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 4 {
		return "***"
	}
	return "***" + value[len(value)-4:]
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func normalizeView(view string) string {
	switch strings.TrimSpace(view) {
	case "manage_tasks", "manage_sources", "inspect_runtime", "inspect_alerts", ViewInspectionInteraction, ViewDeploymentConfirmation, ViewConnection:
		return strings.TrimSpace(view)
	default:
		return "home"
	}
}

func normalizeOpenIntent(intent OpenIntent) (OpenIntent, error) {
	intent.View = normalizeView(intent.View)
	intent.TaskName = strings.TrimSpace(intent.TaskName)
	intent.TaskAction = strings.TrimSpace(intent.TaskAction)
	if len(intent.TaskName) > 256 || len(intent.TaskAction) > 16 {
		return OpenIntent{}, errors.New("open intent is too large")
	}
	if intent.View == ViewInspectionInteraction || intent.View == ViewDeploymentConfirmation {
		if intent.TaskName != "" || intent.TaskAction != "" || !validInspectionHandoffRef(intent.HandoffRef) {
			return OpenIntent{}, errors.New("invalid inspection interaction intent")
		}
		return intent, nil
	}
	if intent.HandoffRef != "" {
		return OpenIntent{}, errors.New("inspection handoff requires inspection interaction intent")
	}
	if intent.TaskName == "" && intent.TaskAction == "" {
		return intent, nil
	}
	if intent.View != "manage_tasks" || intent.TaskName == "" || (intent.TaskAction != "enable" && intent.TaskAction != "disable" && intent.TaskAction != "parameters") {
		return OpenIntent{}, errors.New("invalid task open intent")
	}
	return intent, nil
}

func validInspectionHandoffRef(value string) bool {
	return value == strings.TrimSpace(value) && inspectionHandoffRefPattern.MatchString(value)
}
