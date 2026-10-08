package devauthority

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

const (
	minimumLifetime = time.Hour
	maximumLifetime = 90 * 24 * time.Hour
)

type AuthorizationRequest struct {
	Endpoint                 string `json:"endpoint"`
	Username                 string `json:"username"`
	PasswordBase64           string `json:"passwordBase64"`
	ValidForHours            int    `json:"validForHours"`
	AllowTaskSwitchRoundTrip bool   `json:"allowTaskSwitchRoundTrip"`
}

type AuthorizationResult struct {
	Status         string    `json:"status"`
	Device         string    `json:"device"`
	DeviceType     string    `json:"deviceType"`
	AllowedActions []string  `json:"allowedActions"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type ReadResult struct {
	Status         string        `json:"status"`
	Device         string        `json:"device"`
	DeviceType     string        `json:"deviceType"`
	ObservedAt     time.Time     `json:"observedAt"`
	CameraCount    int           `json:"cameraCount"`
	TaskCount      int           `json:"taskCount"`
	Enabled        int           `json:"enabled"`
	Disabled       int           `json:"disabled"`
	EnableUnknown  int           `json:"enableUnknown"`
	Running        int           `json:"running"`
	Stopped        int           `json:"stopped"`
	RuntimeUnknown int           `json:"runtimeUnknown"`
	Tasks          []TaskSummary `json:"tasks"`
}

type TaskSummary struct {
	Index        int    `json:"index"`
	Name         string `json:"name"`
	Camera       string `json:"camera"`
	Algorithm    string `json:"algorithm"`
	EnabledState string `json:"enabledState"`
	RuntimeState string `json:"runtimeState"`
}

// TaskRoundTripSession is consumed only by the separately compiled
// development write validator. Read-only callers use ReadLease instead.
type TaskRoundTripSession struct {
	Device       string
	Snapshot     device.Snapshot
	Vault        *session.Vault
	BrowserID    string
	EvidenceRoot string
}

type StatusResult struct {
	Status         string     `json:"status"`
	Device         string     `json:"device,omitempty"`
	DeviceType     string     `json:"deviceType,omitempty"`
	AllowedActions []string   `json:"allowedActions,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
}

type Authority struct {
	store     *Store
	factory   device.Factory
	now       func() time.Time
	protect   func([]byte) ([]byte, error)
	unprotect func([]byte) ([]byte, error)
}

func New(store *Store) (*Authority, error) {
	if store == nil {
		return nil, errors.New("development authority store is required")
	}
	return &Authority{
		store: store, factory: device.NewV1Client, now: time.Now,
		protect: protectSecret, unprotect: unprotectSecret,
	}, nil
}

func (a *Authority) Authorize(ctx context.Context, request AuthorizationRequest) (AuthorizationResult, error) {
	endpoint, err := session.NormalizeDeviceAddress(request.Endpoint)
	if err != nil {
		return AuthorizationResult{}, err
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 256 {
		return AuthorizationResult{}, errors.New("device account is invalid")
	}
	if request.ValidForHours < int(minimumLifetime/time.Hour) || request.ValidForHours > int(maximumLifetime/time.Hour) {
		return AuthorizationResult{}, errors.New("development authority lifetime must be between 1 hour and 90 days")
	}
	lifetime := time.Duration(request.ValidForHours) * time.Hour
	password, err := base64.StdEncoding.DecodeString(strings.TrimSpace(request.PasswordBase64))
	if err != nil || len(password) == 0 || len(password) > 4096 {
		clear(password)
		return AuthorizationResult{}, errors.New("device credential is invalid")
	}
	defer clear(password)

	vault, snapshot, _, err := connect(ctx, endpoint.URL, request.Username, password, a.factory)
	if err != nil {
		return AuthorizationResult{}, err
	}
	_ = vault
	if strings.TrimSpace(snapshot.Identity.Serial) == "" || strings.TrimSpace(snapshot.Identity.Type) == "" {
		return AuthorizationResult{}, errors.New("device identity is incomplete")
	}
	protected, err := a.protect(password)
	if err != nil {
		return AuthorizationResult{}, err
	}
	defer clear(protected)
	actions := []string{ActionRead}
	if request.AllowTaskSwitchRoundTrip {
		actions = append(actions, ActionTaskSwitchRoundTrip)
	}
	sort.Strings(actions)
	now := a.now().UTC()
	profile := Profile{
		Version: profileVersion, Endpoint: endpoint.URL, Username: request.Username,
		DeviceFingerprint: deviceFingerprint(snapshot.Identity.Serial), DeviceHint: maskDevice(snapshot.Identity.Serial),
		DeviceType: snapshot.Identity.Type, AllowedActions: actions,
		EncryptedPassword: base64.StdEncoding.EncodeToString(protected), CreatedAt: now, ExpiresAt: now.Add(lifetime),
	}
	if err := a.store.Save(profile); err != nil {
		return AuthorizationResult{}, err
	}
	return AuthorizationResult{
		Status: "authorized", Device: profile.DeviceHint, DeviceType: profile.DeviceType,
		AllowedActions: append([]string(nil), profile.AllowedActions...), ExpiresAt: profile.ExpiresAt,
	}, nil
}

func (a *Authority) Status() StatusResult {
	profile, err := a.store.Load(a.now().UTC())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StatusResult{Status: "not_authorized"}
		}
		return StatusResult{Status: "invalid_or_expired"}
	}
	return StatusResult{
		Status: "authorized", Device: profile.DeviceHint, DeviceType: profile.DeviceType,
		AllowedActions: append([]string(nil), profile.AllowedActions...), ExpiresAt: &profile.ExpiresAt,
	}
}

func (a *Authority) Revoke() error { return a.store.Revoke() }

func (a *Authority) VerifyRead(ctx context.Context) (ReadResult, error) {
	profile, vault, snapshot, _, err := a.open(ctx, ActionRead)
	if err != nil {
		return ReadResult{}, err
	}
	_ = vault
	result := ReadResult{
		Status: "passed", Device: profile.DeviceHint, DeviceType: snapshot.Identity.Type,
		ObservedAt: snapshot.ObservedAt, CameraCount: len(snapshot.Cameras), TaskCount: len(snapshot.Tasks), Tasks: []TaskSummary{},
	}
	for index, task := range snapshot.Tasks {
		switch task.Enabled {
		case 0:
			result.Disabled++
		case 1:
			result.Enabled++
		default:
			result.EnableUnknown++
		}
		switch task.Running {
		case "running":
			result.Running++
		case "stopped":
			result.Stopped++
		default:
			result.RuntimeUnknown++
		}
		result.Tasks = append(result.Tasks, TaskSummary{
			Index: index + 1, Name: task.DisplayName, Camera: task.CameraName, Algorithm: task.AlgorithmName,
			EnabledState: switchState(task.Enabled), RuntimeState: task.Running,
		})
	}
	return result, nil
}

func (a *Authority) OpenTaskRoundTripSession(ctx context.Context) (TaskRoundTripSession, error) {
	profile, vault, snapshot, browserID, err := a.open(ctx, ActionTaskSwitchRoundTrip)
	if err != nil {
		return TaskRoundTripSession{}, err
	}
	return TaskRoundTripSession{
		Device: profile.DeviceHint, Snapshot: snapshot, Vault: vault,
		BrowserID: browserID, EvidenceRoot: a.store.Root(),
	}, nil
}

func (a *Authority) open(ctx context.Context, action string) (Profile, *session.Vault, device.Snapshot, string, error) {
	profile, err := a.store.Load(a.now().UTC())
	if err != nil {
		return Profile{}, nil, device.Snapshot{}, "", err
	}
	if !profile.Allows(action) {
		return Profile{}, nil, device.Snapshot{}, "", errors.New("development authority does not allow this action")
	}
	protected, err := base64.StdEncoding.DecodeString(profile.EncryptedPassword)
	if err != nil {
		return Profile{}, nil, device.Snapshot{}, "", errors.New("development credential envelope is invalid")
	}
	defer clear(protected)
	password, err := a.unprotect(protected)
	if err != nil {
		return Profile{}, nil, device.Snapshot{}, "", err
	}
	defer clear(password)
	vault, snapshot, browserID, err := connect(ctx, profile.Endpoint, profile.Username, password, a.factory)
	if err != nil {
		return Profile{}, nil, device.Snapshot{}, "", err
	}
	if deviceFingerprint(snapshot.Identity.Serial) != profile.DeviceFingerprint || snapshot.Identity.Type != profile.DeviceType {
		return Profile{}, nil, device.Snapshot{}, "", errors.New("development authority rejected device identity drift")
	}
	return profile, vault, snapshot, browserID, nil
}

func connect(ctx context.Context, endpoint, username string, password []byte, factory device.Factory) (*session.Vault, device.Snapshot, string, error) {
	vault := session.New(factory)
	bootstrap, err := vault.IssueBootstrap()
	if err != nil {
		return nil, device.Snapshot{}, "", err
	}
	browser, err := vault.ConsumeBootstrap(bootstrap)
	if err != nil {
		return nil, device.Snapshot{}, "", err
	}
	preview, err := vault.PrepareConnection(browser.SessionID, endpoint, username)
	if err != nil {
		return nil, device.Snapshot{}, "", err
	}
	credential := append([]byte(nil), password...)
	if _, err := vault.Connect(ctx, browser.SessionID, preview.Token, credential); err != nil {
		return nil, device.Snapshot{}, "", err
	}
	snapshot, err := vault.Read(ctx)
	if err != nil {
		return nil, device.Snapshot{}, "", err
	}
	return vault, snapshot, browser.SessionID, nil
}

func switchState(value int) string {
	if value == 1 {
		return "enabled"
	}
	if value == 0 {
		return "disabled"
	}
	return "unknown"
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
