package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/kernel"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
)

const proposalTTL = 15 * time.Minute

type Manager struct {
	provider ConnectionProvider
	store    *ledger.Store
	worker   *kernel.Kernel
	vault    *memoryVault
	now      func() time.Time
}

func New(store *ledger.Store, provider ConnectionProvider) (*Manager, error) {
	return NewWithHandlers(store, provider, nil)
}

// NewWithHandlers registers additional business handlers on the same action
// worker and ledger. A caller must not start a second kernel for those actions.
func NewWithHandlers(store *ledger.Store, provider ConnectionProvider, additional map[string]kernel.Handler) (*Manager, error) {
	if store == nil || provider == nil {
		return nil, errors.New("action manager dependencies are required")
	}
	manager := &Manager{provider: provider, store: store, now: time.Now}
	manager.vault = newMemoryVault(func() time.Time { return manager.now().UTC() })
	handlers := map[string]kernel.Handler{
		KindTaskSwitch: manager, KindTaskParameters: manager, KindCameraSource: manager,
	}
	for kind, handler := range additional {
		if strings.TrimSpace(kind) != kind || kind == "" || handler == nil || handlers[kind] != nil {
			return nil, errors.New("additional action handler must have a unique nonempty kind")
		}
		handlers[kind] = handler
	}
	worker, err := kernel.New(store, handlers)
	if err != nil {
		return nil, err
	}
	manager.worker = worker
	return manager, nil
}

func (m *Manager) Start(ctx context.Context) error {
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := m.worker.Start(ctx)
		if !errors.Is(err, kernel.ErrWorkerUnavailable) || time.Now().After(deadline) {
			return err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Manager) Stop() { m.worker.Stop() }

func (m *Manager) PrepareTaskSwitch(ctx context.Context, browserID string, snapshot device.Snapshot, task device.Task, target int) (Proposal, error) {
	if target != 0 && target != 1 || task.Enabled != 0 && task.Enabled != 1 || target == task.Enabled || !task.SwitchVerified {
		return Proposal{}, errors.New("task switch proposal is invalid")
	}
	connection, err := m.boundConnection(snapshot.Identity.Serial)
	if err != nil || !containsTask(snapshot, task) {
		return Proposal{}, ErrActionUnavailable
	}
	expiresAt := m.now().UTC().Add(proposalTTL)
	item := &material{
		kind: KindTaskSwitch, sessionBinding: bindingDigest(browserID),
		resourceKey: resourceDigest(snapshot.Identity.Serial, KindTaskSwitch, task.ChannelID, task.AlgorithmID, task.ID),
		serial:      snapshot.Identity.Serial, endpointFingerprint: connection.EndpointFingerprint, expiresAt: expiresAt,
		task: task, originalSwitch: task.Enabled, targetSwitch: target,
	}
	targetState := map[int]string{0: "disabled", 1: "enabled"}[target]
	return m.propose(ctx, item, publicMetadata{Action: KindTaskSwitch, TargetState: targetState})
}

func (m *Manager) CurrentTaskParameters(ctx context.Context, snapshot device.Snapshot, task device.Task) ([]ParameterField, error) {
	connection, err := m.boundConnection(snapshot.Identity.Serial)
	if err != nil || !containsTask(snapshot, task) {
		return nil, ErrActionUnavailable
	}
	fields, err := connection.Client.ReadTaskParameters(ctx, task)
	if err != nil {
		return nil, ErrActionUnavailable
	}
	result := make([]ParameterField, 0, len(fields))
	for _, field := range fields {
		result = append(result, ParameterField{Key: field.Key, Value: field.Value})
	}
	return result, nil
}

func (m *Manager) PrepareTaskParameters(ctx context.Context, browserID string, snapshot device.Snapshot, task device.Task, target []device.ParameterField) (Proposal, error) {
	connection, err := m.boundConnection(snapshot.Identity.Serial)
	if err != nil || !containsTask(snapshot, task) {
		return Proposal{}, ErrActionUnavailable
	}
	before, err := connection.Client.ReadTaskParameters(ctx, task)
	if err != nil {
		return Proposal{}, ErrActionUnavailable
	}
	before, err = normalizeFields(before)
	if err != nil {
		return Proposal{}, err
	}
	target, err = normalizeFields(target)
	if err != nil || !sameFieldSet(before, target) || sameFields(before, target) {
		return Proposal{}, errors.New("task parameter proposal is invalid")
	}
	expiresAt := m.now().UTC().Add(proposalTTL)
	item := &material{
		kind: KindTaskParameters, sessionBinding: bindingDigest(browserID),
		resourceKey: resourceDigest(snapshot.Identity.Serial, KindTaskParameters, task.ChannelID, task.AlgorithmID, task.ID),
		serial:      snapshot.Identity.Serial, endpointFingerprint: connection.EndpointFingerprint, expiresAt: expiresAt,
		task: task, beforeParameters: cloneFields(before), targetParameters: cloneFields(target),
	}
	changed := changedFieldCount(before, target)
	return m.propose(ctx, item, publicMetadata{Action: KindTaskParameters, ChangedCount: changed})
}

func (m *Manager) PrepareCameraSource(ctx context.Context, browserID, name string, sourceURL []byte) (Proposal, error) {
	defer clear(sourceURL)
	name = strings.TrimSpace(name)
	parsed, err := url.Parse(string(sourceURL))
	if name == "" || len(name) > 128 || len(sourceURL) == 0 || len(sourceURL) > 4096 || err != nil || (parsed.Scheme != "rtsp" && parsed.Scheme != "rtsps") || parsed.Host == "" || parsed.Fragment != "" {
		return Proposal{}, errors.New("camera source proposal is invalid")
	}
	connection, err := m.provider.ActionConnection()
	if err != nil || connection.Client == nil || connection.Serial == "" || connection.EndpointFingerprint == "" {
		return Proposal{}, ErrActionUnavailable
	}
	snapshot, err := connection.Client.Read(ctx)
	if err != nil || snapshot.Identity.Serial != connection.Serial || cameraNameExists(snapshot.Cameras, name) {
		return Proposal{}, ErrActionUnavailable
	}
	expiresAt := m.now().UTC().Add(proposalTTL)
	item := &material{
		kind: KindCameraSource, sessionBinding: bindingDigest(browserID),
		resourceKey: resourceDigest(snapshot.Identity.Serial, KindCameraSource, "camera-source-catalog"),
		serial:      snapshot.Identity.Serial, endpointFingerprint: connection.EndpointFingerprint, expiresAt: expiresAt,
		sourceName: name, sourceURL: append([]byte(nil), sourceURL...), sourceFingerprint: rawDigest(sourceURL),
		catalogFingerprint: cameraCatalogFingerprint(snapshot.Cameras), catalogCountBefore: len(snapshot.Cameras),
	}
	return m.propose(ctx, item, publicMetadata{Action: KindCameraSource, CatalogBefore: len(snapshot.Cameras)})
}

func (m *Manager) Confirm(ctx context.Context, browserID, token string) (string, error) {
	return m.ConfirmExpected(ctx, browserID, token, "")
}

func (m *Manager) ConfirmExpected(ctx context.Context, browserID, token, expectedID string) (string, error) {
	binding := bindingDigest(browserID)
	connection, err := m.provider.ActionConnection()
	if err != nil || connection.Client == nil || connection.Serial == "" || connection.EndpointFingerprint == "" {
		return "", ErrActionUnavailable
	}
	id, err := m.vault.consume(strings.TrimSpace(token), binding, expectedID, connection.Serial, connection.EndpointFingerprint)
	if err != nil {
		return "", err
	}
	if err := m.worker.Confirm(ctx, id, binding); err != nil {
		return "", err
	}
	return id, nil
}

func (m *Manager) Cancel(ctx context.Context, browserID, id string) error {
	binding := bindingDigest(browserID)
	if !m.vault.owns(id, binding) {
		return ErrActionConflict
	}
	if err := m.worker.Cancel(ctx, id, binding); err != nil {
		return err
	}
	m.vault.delete(id)
	return nil
}

func (m *Manager) Status(ctx context.Context, id string) (Status, error) {
	record, err := m.store.Inspect(ctx, id)
	if err != nil {
		return Status{}, err
	}
	var public publicMetadata
	if err := json.Unmarshal([]byte(record.PublicJSON), &public); err != nil {
		return Status{}, err
	}
	state := record.State
	if record.Reason == "cancelled_by_user" {
		state = "cancelled"
	} else if record.Reason == "proposal_expired" {
		state = "expired"
	}
	return Status{
		ActionID: record.ID, Kind: record.Kind, State: state, Class: record.ResultClass,
		Evidence: record.EvidenceStatus, Conclusion: record.Conclusion, Reason: record.Reason,
		Dispatches: record.Dispatches, DeviceWrites: record.DeviceWrites,
		TargetState: public.TargetState, ChangedCount: public.ChangedCount, CatalogBefore: public.CatalogBefore,
	}, nil
}

func (m *Manager) propose(ctx context.Context, item *material, public publicMetadata) (Proposal, error) {
	raw, err := json.Marshal(public)
	if err != nil {
		return Proposal{}, err
	}
	action, err := m.worker.Propose(ctx, ledger.NewAction{
		Kind: item.kind, SessionBinding: item.sessionBinding, ResourceKey: item.resourceKey,
		PublicJSON: string(raw), ExpiresAt: item.expiresAt,
	})
	if err != nil {
		return Proposal{}, err
	}
	item.id = action.ID
	token, err := m.vault.put(item)
	if err != nil {
		_ = m.worker.Cancel(ctx, action.ID, item.sessionBinding)
		return Proposal{}, err
	}
	return Proposal{
		ActionID: action.ID, Kind: item.kind, State: "awaiting_approval", ConfirmationToken: token, ExpiresAt: item.expiresAt,
		TargetState: public.TargetState, ChangedCount: public.ChangedCount,
		CatalogCountBefore: public.CatalogBefore, CatalogCountTarget: public.CatalogBefore + 1,
	}, nil
}

func (m *Manager) boundConnection(serial string) (device.ActionConnection, error) {
	connection, err := m.provider.ActionConnection()
	if err != nil || connection.Client == nil || connection.Serial != serial || connection.EndpointFingerprint == "" {
		return device.ActionConnection{}, ErrActionUnavailable
	}
	return connection, nil
}

func bindingDigest(browserID string) string {
	return digest("browser-session", strings.TrimSpace(browserID))
}

func resourceDigest(parts ...string) string { return digest(parts...) }

func digest(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func containsTask(snapshot device.Snapshot, target device.Task) bool {
	_, ok := findTask(snapshot, target)
	return ok
}

func findTask(snapshot device.Snapshot, target device.Task) (device.Task, bool) {
	for _, candidate := range snapshot.Tasks {
		if candidate.ID == target.ID && candidate.ChannelID == target.ChannelID && candidate.AlgorithmID == target.AlgorithmID {
			return candidate, true
		}
	}
	return device.Task{}, false
}

func normalizeFields(fields []device.ParameterField) ([]device.ParameterField, error) {
	if len(fields) == 0 || len(fields) > 128 {
		return nil, errors.New("task parameter field count is invalid")
	}
	result := cloneFields(fields)
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	for index := range result {
		result[index].Key = strings.TrimSpace(result[index].Key)
		if result[index].Key == "" || len(result[index].Key) > 512 || len(result[index].Value) > 2056 || index > 0 && result[index-1].Key == result[index].Key {
			return nil, errors.New("task parameter fields are invalid")
		}
	}
	return result, nil
}

func sameFieldSet(left, right []device.ParameterField) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Key != right[index].Key {
			return false
		}
	}
	return true
}

func sameFields(left, right []device.ParameterField) bool {
	if !sameFieldSet(left, right) {
		return false
	}
	for index := range left {
		if left[index].Value != right[index].Value {
			return false
		}
	}
	return true
}

func cloneFields(fields []device.ParameterField) []device.ParameterField {
	return append([]device.ParameterField(nil), fields...)
}

func changedFieldCount(left, right []device.ParameterField) int {
	count := 0
	for index := range left {
		if left[index].Value != right[index].Value {
			count++
		}
	}
	return count
}

func cameraNameExists(cameras []device.Camera, name string) bool {
	for _, camera := range cameras {
		if strings.EqualFold(strings.TrimSpace(camera.Name), name) {
			return true
		}
	}
	return false
}

func cameraCatalogFingerprint(cameras []device.Camera) string {
	parts := make([]string, 0, len(cameras))
	for _, camera := range cameras {
		parts = append(parts, strings.Join([]string{camera.ID, camera.Name, camera.SourceFingerprint}, "\x00"))
	}
	sort.Strings(parts)
	return rawDigest([]byte(strings.Join(parts, "\x01")))
}
