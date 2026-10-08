package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const maxTaskSourceHandlesJSON = 32 << 10

func (s *Store) CreateTask(ctx context.Context, input NewDeviceTaskBinding) (DeviceTaskBinding, error) {
	now := s.now().UTC()
	observedAt := input.ObservedAt.UTC()
	if input.ObservedAt.IsZero() {
		observedAt = now
	}
	sourceHandles, err := normalizeTaskSourceHandles(input.SourceHandles)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	capabilities, err := NormalizeTaskCapabilities(input.Capabilities)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	item := DeviceTaskBinding{
		Schema: SchemaVersion, TenantID: strings.TrimSpace(input.TenantID), SiteID: strings.TrimSpace(input.SiteID),
		DeviceProfileID: strings.TrimSpace(input.DeviceProfileID), TaskHandle: strings.TrimSpace(input.TaskHandle),
		Revision: 1, IdentityFingerprint: strings.TrimSpace(input.IdentityFingerprint),
		NativeLocator: strings.TrimSpace(input.NativeLocator), Alias: strings.TrimSpace(input.Alias),
		SourceHandles: sourceHandles, Capabilities: capabilities, State: StateActive,
		ObservedAt: observedAt, CreatedAt: now, UpdatedAt: now,
	}
	if err := item.Validate(); err != nil {
		return DeviceTaskBinding{}, err
	}
	sourceRaw, err := marshalTaskSourceHandles(item.SourceHandles)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	capabilityRaw, err := marshalCapabilities(item.Capabilities)
	if err != nil {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	defer tx.Rollback()
	if _, err := taskSourcesForProfile(ctx, tx, item.TenantID, item.SiteID, item.DeviceProfileID, item.SourceHandles); err != nil {
		return DeviceTaskBinding{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO device_task_bindings(
        tenant_id, site_id, task_handle, device_profile_id, revision,
        identity_fingerprint, native_locator, alias, source_handles_json,
        capabilities_json, state, observed_at, created_at, updated_at
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.TenantID, item.SiteID, item.TaskHandle, item.DeviceProfileID, item.Revision,
		item.IdentityFingerprint, item.NativeLocator, item.Alias, sourceRaw, capabilityRaw,
		item.State, formatTime(item.ObservedAt), formatTime(item.CreatedAt), formatTime(item.UpdatedAt))
	if err != nil {
		if !isConstraintError(err) {
			return DeviceTaskBinding{}, err
		}
		current, lookupErr := scanDeviceTask(tx.QueryRowContext(ctx, selectDeviceTask+`
            WHERE tenant_id=? AND site_id=? AND task_handle=?`, item.TenantID, item.SiteID, item.TaskHandle))
		if lookupErr == nil && sameTaskCreateFact(current, item) {
			return cloneDeviceTask(current), nil
		}
		return DeviceTaskBinding{}, ErrTaskConflict
	}
	if err := appendTaskEvent(ctx, tx, item, "created"); err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceTaskBinding{}, err
	}
	return cloneDeviceTask(item), nil
}

func (s *Store) GetTask(ctx context.Context, tenantID, siteID, taskHandle string) (DeviceTaskBinding, error) {
	if !validRef(tenantID) || !validRef(siteID) || !validRef(taskHandle) {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	item, err := scanDeviceTask(s.db.QueryRowContext(ctx, selectDeviceTask+`
        WHERE tenant_id=? AND site_id=? AND task_handle=?`,
		strings.TrimSpace(tenantID), strings.TrimSpace(siteID), strings.TrimSpace(taskHandle)))
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := s.validateStoredTaskSources(ctx, item); err != nil {
		return DeviceTaskBinding{}, err
	}
	return item, nil
}

func (s *Store) ListTasks(ctx context.Context, tenantID, siteID string) ([]DeviceTaskBinding, error) {
	if !validRef(tenantID) || !validRef(siteID) {
		return nil, ErrInvalidTask
	}
	rows, err := s.db.QueryContext(ctx, selectDeviceTask+`
        WHERE tenant_id=? AND site_id=? ORDER BY alias COLLATE NOCASE, task_handle`,
		strings.TrimSpace(tenantID), strings.TrimSpace(siteID))
	if err != nil {
		return nil, err
	}
	result := []DeviceTaskBinding{}
	for rows.Next() {
		item, err := scanDeviceTask(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, item := range result {
		if err := s.validateStoredTaskSources(ctx, item); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Store) ResolveTaskAlias(ctx context.Context, tenantID, siteID, alias string) (DeviceTaskBinding, error) {
	alias = taskAliasKey(alias)
	if !validRef(tenantID) || !validRef(siteID) || validateBusinessText("task alias", alias, 160) != nil {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	rows, err := s.db.QueryContext(ctx, selectDeviceTask+`
        WHERE tenant_id=? AND site_id=? AND alias=? COLLATE NOCASE ORDER BY task_handle LIMIT 2`,
		strings.TrimSpace(tenantID), strings.TrimSpace(siteID), alias)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	matches := make([]DeviceTaskBinding, 0, 2)
	for rows.Next() {
		item, err := scanDeviceTask(rows)
		if err != nil {
			_ = rows.Close()
			return DeviceTaskBinding{}, err
		}
		matches = append(matches, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return DeviceTaskBinding{}, err
	}
	if err := rows.Close(); err != nil {
		return DeviceTaskBinding{}, err
	}
	switch len(matches) {
	case 0:
		return DeviceTaskBinding{}, ErrTaskNotFound
	case 1:
		if err := s.validateStoredTaskSources(ctx, matches[0]); err != nil {
			return DeviceTaskBinding{}, err
		}
		return matches[0], nil
	default:
		return DeviceTaskBinding{}, ErrTaskAmbiguous
	}
}

func (s *Store) RefreshTask(ctx context.Context, input RefreshDeviceTaskBinding) (DeviceTaskBinding, error) {
	if err := validateTaskRefreshIdentity(input); err != nil {
		return DeviceTaskBinding{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	defer tx.Rollback()
	current, err := scanDeviceTask(tx.QueryRowContext(ctx, selectDeviceTask+`
        WHERE tenant_id=? AND site_id=? AND task_handle=?`,
		strings.TrimSpace(input.TenantID), strings.TrimSpace(input.SiteID), strings.TrimSpace(input.TaskHandle)))
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	if current.Revision != input.ExpectedRevision {
		return DeviceTaskBinding{}, ErrTaskConflict
	}
	if strings.TrimSpace(input.DeviceProfileID) != current.DeviceProfileID {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	if _, err := taskSourcesForProfile(ctx, tx, current.TenantID, current.SiteID, current.DeviceProfileID, current.SourceHandles); err != nil {
		return DeviceTaskBinding{}, err
	}
	now := s.now().UTC()
	observedAt := input.ObservedAt.UTC()
	if now.Before(current.UpdatedAt) || observedAt.Before(current.ObservedAt) || observedAt.After(now) {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	if strings.TrimSpace(input.IdentityFingerprint) != current.IdentityFingerprint {
		drifted := cloneDeviceTask(current)
		drifted.Revision++
		drifted.State = StateIdentityDrift
		drifted.ObservedAt = observedAt
		drifted.UpdatedAt = now
		if err := updateTaskRow(ctx, tx, current.Revision, drifted); err != nil {
			return DeviceTaskBinding{}, err
		}
		if err := appendTaskEvent(ctx, tx, drifted, "identity_drift"); err != nil {
			return DeviceTaskBinding{}, err
		}
		if err := tx.Commit(); err != nil {
			return DeviceTaskBinding{}, err
		}
		return cloneDeviceTask(drifted), errors.Join(ErrTaskIdentityDrift, ErrIdentityDrift)
	}
	next, err := refreshedTask(current, input, now, observedAt)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	if _, err := taskSourcesForProfile(ctx, tx, next.TenantID, next.SiteID, next.DeviceProfileID, next.SourceHandles); err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := updateTaskRow(ctx, tx, current.Revision, next); err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := appendTaskEvent(ctx, tx, next, "refreshed"); err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceTaskBinding{}, err
	}
	return cloneDeviceTask(next), nil
}

func (s *Store) RepinTask(ctx context.Context, input RefreshDeviceTaskBinding) (DeviceTaskBinding, error) {
	if err := validateTaskRefreshIdentity(input); err != nil {
		return DeviceTaskBinding{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	defer tx.Rollback()
	current, err := scanDeviceTask(tx.QueryRowContext(ctx, selectDeviceTask+`
        WHERE tenant_id=? AND site_id=? AND task_handle=?`,
		strings.TrimSpace(input.TenantID), strings.TrimSpace(input.SiteID), strings.TrimSpace(input.TaskHandle)))
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	if current.Revision != input.ExpectedRevision {
		return DeviceTaskBinding{}, ErrTaskConflict
	}
	if strings.TrimSpace(input.DeviceProfileID) != current.DeviceProfileID {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	if _, err := taskSourcesForProfile(ctx, tx, current.TenantID, current.SiteID, current.DeviceProfileID, current.SourceHandles); err != nil {
		return DeviceTaskBinding{}, err
	}
	if current.State != StateIdentityDrift || strings.TrimSpace(input.IdentityFingerprint) == current.IdentityFingerprint {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	if input.State != StateActive {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	now := s.now().UTC()
	observedAt := input.ObservedAt.UTC()
	if now.Before(current.UpdatedAt) || observedAt.Before(current.ObservedAt) || observedAt.After(now) {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	next, err := refreshedTask(current, input, now, observedAt)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	next.IdentityFingerprint = strings.TrimSpace(input.IdentityFingerprint)
	next.State = StateActive
	if err := next.Validate(); err != nil {
		return DeviceTaskBinding{}, err
	}
	if _, err := taskSourcesForProfile(ctx, tx, next.TenantID, next.SiteID, next.DeviceProfileID, next.SourceHandles); err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := updateTaskRow(ctx, tx, current.Revision, next); err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := appendTaskEvent(ctx, tx, next, "identity_repinned"); err != nil {
		return DeviceTaskBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceTaskBinding{}, err
	}
	return cloneDeviceTask(next), nil
}

func (s *Store) FreezeInstalledTask(ctx context.Context, tenantID, siteID, taskID string, requiredCapabilities []string) (inspection.InstalledTaskBinding, error) {
	if !validRef(tenantID) || !validRef(siteID) || !validRef(taskID) {
		return inspection.InstalledTaskBinding{}, ErrInvalidTask
	}
	required, err := canonicalRequiredTaskCapabilities(requiredCapabilities)
	if err != nil {
		return inspection.InstalledTaskBinding{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inspection.InstalledTaskBinding{}, err
	}
	defer tx.Rollback()
	task, err := scanDeviceTask(tx.QueryRowContext(ctx, selectDeviceTask+`
        WHERE tenant_id=? AND site_id=? AND task_handle=?`,
		strings.TrimSpace(tenantID), strings.TrimSpace(siteID), strings.TrimSpace(taskID)))
	if err != nil {
		return inspection.InstalledTaskBinding{}, err
	}
	if task.State == StateIdentityDrift {
		return inspection.InstalledTaskBinding{}, ErrTaskIdentityDrift
	}
	if task.State != StateActive {
		return inspection.InstalledTaskBinding{}, ErrTaskCapability
	}
	sources, err := taskSourcesForProfile(ctx, tx, task.TenantID, task.SiteID, task.DeviceProfileID, task.SourceHandles)
	if err != nil {
		return inspection.InstalledTaskBinding{}, err
	}
	frozenSources := make([]inspection.InstalledTaskSourceBinding, 0, len(sources))
	for _, source := range sources {
		if source.State == StateIdentityDrift {
			return inspection.InstalledTaskBinding{}, ErrIdentityDrift
		}
		if source.State != StateActive {
			return inspection.InstalledTaskBinding{}, ErrTaskCapability
		}
		frozenSources = append(frozenSources, inspection.InstalledTaskSourceBinding{
			SourceHandle: source.Handle, SourceRevision: source.Revision, SourceFingerprint: source.IdentityFingerprint,
		})
	}
	byRef := make(map[string]Capability, len(task.Capabilities))
	for _, capability := range task.Capabilities {
		byRef[capability.Ref] = capability
	}
	frozenCapabilities := make([]inspection.InstalledTaskCapabilityBinding, 0, len(required))
	for _, ref := range required {
		capability, ok := byRef[ref]
		if !ok {
			return inspection.InstalledTaskBinding{}, ErrTaskCapability
		}
		frozenCapabilities = append(frozenCapabilities, inspection.InstalledTaskCapabilityBinding{
			Ref: capability.Ref, Revision: capability.Revision, Digest: capability.Digest,
			ResultSchema: capability.ResultSchema,
			MediaKinds:   append([]MediaKind(nil), capability.Constraints.MediaKinds...),
		})
	}
	bindingFingerprint, err := installedTaskBindingFingerprint(task.TaskHandle, task.Revision, task.IdentityFingerprint, frozenSources, frozenCapabilities)
	if err != nil {
		return inspection.InstalledTaskBinding{}, err
	}
	result := inspection.InstalledTaskBinding{
		TaskID: task.TaskHandle, TaskRevision: task.Revision, BindingFingerprint: bindingFingerprint,
		Sources: frozenSources, Capabilities: frozenCapabilities, ObservedAt: task.ObservedAt,
	}
	if err := result.Validate(); err != nil {
		return inspection.InstalledTaskBinding{}, ErrInvalidTask
	}
	return result, nil
}

// ValidateInstalledTask proves that an assignment's task binding still names the
// same active installed task, source identities, and capability result shapes.
// Any refresh, drift, repin, or source revision change makes the ref stale.
func (s *Store) ValidateInstalledTask(ctx context.Context, tenantID, siteID string, frozen inspection.InstalledTaskBinding) error {
	if !validRef(tenantID) || !validRef(siteID) || frozen.Validate() != nil {
		return ErrInvalidTask
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	task, err := scanDeviceTask(tx.QueryRowContext(ctx, selectDeviceTask+`
        WHERE tenant_id=? AND site_id=? AND task_handle=?`,
		strings.TrimSpace(tenantID), strings.TrimSpace(siteID), frozen.TaskID))
	if err != nil {
		return err
	}
	if task.State == StateIdentityDrift {
		return ErrTaskIdentityDrift
	}
	if task.State != StateActive {
		return ErrTaskCapability
	}
	if task.Revision != frozen.TaskRevision || !task.ObservedAt.Equal(frozen.ObservedAt) {
		return ErrTaskStale
	}
	sources, err := taskSourcesForProfile(ctx, tx, task.TenantID, task.SiteID, task.DeviceProfileID, task.SourceHandles)
	if err != nil {
		return err
	}
	if len(sources) != len(frozen.Sources) {
		return ErrTaskStale
	}
	for index, source := range sources {
		if source.State == StateIdentityDrift {
			return ErrIdentityDrift
		}
		if source.State != StateActive {
			return ErrTaskCapability
		}
		bound := frozen.Sources[index]
		if source.Handle != bound.SourceHandle || source.Revision != bound.SourceRevision ||
			source.IdentityFingerprint != bound.SourceFingerprint {
			return ErrTaskStale
		}
	}
	byRef := make(map[string]Capability, len(task.Capabilities))
	for _, capability := range task.Capabilities {
		byRef[capability.Ref] = capability
	}
	for _, bound := range frozen.Capabilities {
		capability, ok := byRef[bound.Ref]
		if !ok || capability.Revision != bound.Revision || capability.Digest != bound.Digest ||
			capability.ResultSchema != bound.ResultSchema || !equalMediaKinds(capability.Constraints.MediaKinds, bound.MediaKinds) {
			return ErrTaskStale
		}
	}
	fingerprint, err := installedTaskBindingFingerprint(task.TaskHandle, task.Revision, task.IdentityFingerprint, frozen.Sources, frozen.Capabilities)
	if err != nil || fingerprint != frozen.BindingFingerprint {
		return ErrTaskStale
	}
	return nil
}

func installedTaskBindingFingerprint(taskID string, taskRevision uint64, identityFingerprint string,
	sources []inspection.InstalledTaskSourceBinding, capabilities []inspection.InstalledTaskCapabilityBinding) (string, error) {
	canonical := struct {
		Domain              string                                      `json:"domain"`
		TaskID              string                                      `json:"taskId"`
		TaskRevision        uint64                                      `json:"taskRevision"`
		IdentityFingerprint string                                      `json:"identityFingerprint"`
		Sources             []inspection.InstalledTaskSourceBinding     `json:"sources"`
		Capabilities        []inspection.InstalledTaskCapabilityBinding `json:"capabilities"`
	}{
		Domain: "cosmoedge.inspection.installed-task-binding.v2", TaskID: taskID,
		TaskRevision: taskRevision, IdentityFingerprint: identityFingerprint,
		Sources: sources, Capabilities: capabilities,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validateTaskRefreshIdentity(input RefreshDeviceTaskBinding) error {
	if !validRef(input.TenantID) || !validRef(input.SiteID) || !validRef(input.TaskHandle) ||
		input.ExpectedRevision == 0 || !validRef(input.DeviceProfileID) ||
		!digestPattern.MatchString(strings.TrimSpace(input.IdentityFingerprint)) || input.ObservedAt.IsZero() {
		return ErrInvalidTask
	}
	return nil
}

func refreshedTask(current DeviceTaskBinding, input RefreshDeviceTaskBinding, now, observedAt time.Time) (DeviceTaskBinding, error) {
	if strings.TrimSpace(input.DeviceProfileID) != current.DeviceProfileID || input.State == StateIdentityDrift || !validState(input.State) {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	sourceHandles, err := normalizeTaskSourceHandles(input.SourceHandles)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	capabilities, err := NormalizeTaskCapabilities(input.Capabilities)
	if err != nil {
		return DeviceTaskBinding{}, err
	}
	next := cloneDeviceTask(current)
	next.Revision++
	next.NativeLocator = strings.TrimSpace(input.NativeLocator)
	next.Alias = strings.TrimSpace(input.Alias)
	next.SourceHandles = sourceHandles
	next.Capabilities = capabilities
	next.State = input.State
	next.ObservedAt = observedAt
	next.UpdatedAt = now
	if err := next.Validate(); err != nil {
		return DeviceTaskBinding{}, err
	}
	return next, nil
}

const selectDeviceTask = `SELECT tenant_id, site_id, task_handle, device_profile_id,
    revision, identity_fingerprint, native_locator, alias, source_handles_json,
    capabilities_json, state, observed_at, created_at, updated_at FROM device_task_bindings`

func scanDeviceTask(row rowScanner) (DeviceTaskBinding, error) {
	var item DeviceTaskBinding
	var revision int64
	var sourceRaw, capabilityRaw []byte
	var observedAt, createdAt, updatedAt string
	err := row.Scan(&item.TenantID, &item.SiteID, &item.TaskHandle, &item.DeviceProfileID,
		&revision, &item.IdentityFingerprint, &item.NativeLocator, &item.Alias, &sourceRaw,
		&capabilityRaw, &item.State, &observedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceTaskBinding{}, ErrTaskNotFound
	}
	if err != nil || revision < 1 {
		return DeviceTaskBinding{}, firstError(err, ErrInvalidTask)
	}
	item.Schema = SchemaVersion
	item.Revision = uint64(revision)
	if item.SourceHandles, err = parseTaskSourceHandles(sourceRaw); err != nil {
		return DeviceTaskBinding{}, err
	}
	if item.Capabilities, err = parseTaskCapabilities(capabilityRaw); err != nil {
		return DeviceTaskBinding{}, err
	}
	if item.ObservedAt, err = parseTime(observedAt); err != nil {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	if item.CreatedAt, err = parseTime(createdAt); err != nil {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	if item.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return DeviceTaskBinding{}, ErrInvalidTask
	}
	if err := item.Validate(); err != nil {
		return DeviceTaskBinding{}, err
	}
	return cloneDeviceTask(item), nil
}

func updateTaskRow(ctx context.Context, tx *sql.Tx, expectedRevision uint64, item DeviceTaskBinding) error {
	sourceRaw, err := marshalTaskSourceHandles(item.SourceHandles)
	if err != nil {
		return err
	}
	capabilityRaw, err := marshalCapabilities(item.Capabilities)
	if err != nil {
		return ErrInvalidTask
	}
	result, err := tx.ExecContext(ctx, `UPDATE device_task_bindings SET revision=?,
        identity_fingerprint=?, native_locator=?, alias=?, source_handles_json=?,
        capabilities_json=?, state=?, observed_at=?, updated_at=?
        WHERE tenant_id=? AND site_id=? AND task_handle=? AND revision=?`,
		item.Revision, item.IdentityFingerprint, item.NativeLocator, item.Alias, sourceRaw,
		capabilityRaw, item.State, formatTime(item.ObservedAt), formatTime(item.UpdatedAt),
		item.TenantID, item.SiteID, item.TaskHandle, expectedRevision)
	if err != nil {
		if isConstraintError(err) {
			return ErrTaskConflict
		}
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrTaskConflict
	}
	return nil
}

func appendTaskEvent(ctx context.Context, tx *sql.Tx, item DeviceTaskBinding, eventType string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO device_task_binding_events(
        tenant_id, site_id, task_handle, event_type, revision, state, observed_at, occurred_at
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, item.TenantID, item.SiteID, item.TaskHandle,
		eventType, item.Revision, item.State, formatTime(item.ObservedAt), formatTime(item.UpdatedAt))
	return err
}

func taskSourcesForProfile(ctx context.Context, tx *sql.Tx, tenantID, siteID, profileID string, handles []string) ([]Source, error) {
	result := make([]Source, 0, len(handles))
	for _, handle := range handles {
		source, err := scanSource(tx.QueryRowContext(ctx, selectSource+`
            WHERE tenant_id=? AND site_id=? AND source_handle=?`, tenantID, siteID, handle))
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidSource) || err == nil && source.DeviceProfileID != profileID {
			return nil, ErrInvalidTask
		}
		if err != nil {
			return nil, err
		}
		result = append(result, source)
	}
	return result, nil
}

func (s *Store) validateStoredTaskSources(ctx context.Context, task DeviceTaskBinding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = taskSourcesForProfile(ctx, tx, task.TenantID, task.SiteID, task.DeviceProfileID, task.SourceHandles)
	return err
}

func marshalTaskSourceHandles(values []string) ([]byte, error) {
	raw, err := json.Marshal(values)
	if err != nil || len(raw) == 0 || len(raw) > maxTaskSourceHandlesJSON {
		return nil, ErrInvalidTask
	}
	return raw, nil
}

func parseTaskSourceHandles(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > maxTaskSourceHandlesJSON {
		return nil, ErrInvalidTask
	}
	var values []string
	if err := strictjson.ValidateExactFields(raw, &values, 4); err != nil || json.Unmarshal(raw, &values) != nil {
		return nil, ErrInvalidTask
	}
	if len(values) == 0 || len(values) > 32 {
		return nil, ErrInvalidTask
	}
	for index, value := range values {
		if !validRef(value) || index > 0 && values[index-1] >= value {
			return nil, ErrInvalidTask
		}
	}
	return values, nil
}

func parseTaskCapabilities(raw []byte) ([]Capability, error) {
	values, err := parseCapabilities(raw)
	if err != nil {
		return nil, ErrInvalidTask
	}
	for _, capability := range values {
		if capability.Kind != CapabilityTaskEvidence || capability.ResultSchema == "" {
			return nil, ErrInvalidTask
		}
	}
	return values, nil
}

func isConstraintError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "constraint")
}

func equalMediaKinds(left, right []MediaKind) bool {
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
