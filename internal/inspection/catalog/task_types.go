package catalog

import (
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"
)

var (
	ErrTaskNotFound      = errors.New("installed device task was not found")
	ErrTaskConflict      = errors.New("installed device task revision conflict")
	ErrInvalidTask       = errors.New("installed device task is invalid")
	ErrTaskIdentityDrift = errors.New("installed device task identity drifted")
	ErrTaskAmbiguous     = errors.New("installed device task match is ambiguous")
	ErrTaskCapability    = errors.New("installed device task capability is unavailable")
	ErrTaskStale         = errors.New("installed device task assignment binding is stale")
)

// DeviceTaskBinding is an independent protected catalog fact for one already
// installed device task. NativeLocator is adapter-only state; it must never be
// copied into an inspection assignment or business projection.
type DeviceTaskBinding struct {
	Schema              string
	TenantID            string
	SiteID              string
	DeviceProfileID     string
	TaskHandle          string
	Revision            uint64
	IdentityFingerprint string
	NativeLocator       string
	Alias               string
	SourceHandles       []string
	Capabilities        []Capability
	State               State
	ObservedAt          time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (DeviceTaskBinding) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (DeviceTaskBinding) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
func (DeviceTaskBinding) String() string               { return "[protected-device-task-binding]" }
func (DeviceTaskBinding) GoString() string {
	return "catalog.DeviceTaskBinding([redacted])"
}
func (DeviceTaskBinding) LogValue() slog.Value {
	return slog.StringValue("[protected-device-task-binding]")
}

type NewDeviceTaskBinding struct {
	TenantID            string
	SiteID              string
	DeviceProfileID     string
	TaskHandle          string
	IdentityFingerprint string
	NativeLocator       string
	Alias               string
	SourceHandles       []string
	Capabilities        []Capability
	ObservedAt          time.Time
}

func (NewDeviceTaskBinding) MarshalJSON() ([]byte, error) { return nil, ErrProtectedProjection }
func (NewDeviceTaskBinding) MarshalText() ([]byte, error) { return nil, ErrProtectedProjection }
func (NewDeviceTaskBinding) String() string               { return "[protected-new-device-task-binding]" }
func (NewDeviceTaskBinding) GoString() string {
	return "catalog.NewDeviceTaskBinding([redacted])"
}
func (NewDeviceTaskBinding) LogValue() slog.Value {
	return slog.StringValue("[protected-new-device-task-binding]")
}

// RefreshDeviceTaskBinding is a complete CAS refresh. A changed identity is
// recorded as drift without trusting any of the new locator, source, or
// capability data. RepinTask is the only API that accepts those fields for a
// changed identity.
type RefreshDeviceTaskBinding struct {
	TenantID            string
	SiteID              string
	TaskHandle          string
	ExpectedRevision    uint64
	DeviceProfileID     string
	IdentityFingerprint string
	NativeLocator       string
	Alias               string
	SourceHandles       []string
	Capabilities        []Capability
	State               State
	ObservedAt          time.Time
}

func (RefreshDeviceTaskBinding) MarshalJSON() ([]byte, error) {
	return nil, ErrProtectedProjection
}
func (RefreshDeviceTaskBinding) MarshalText() ([]byte, error) {
	return nil, ErrProtectedProjection
}
func (RefreshDeviceTaskBinding) String() string { return "[protected-refresh-device-task-binding]" }
func (RefreshDeviceTaskBinding) GoString() string {
	return "catalog.RefreshDeviceTaskBinding([redacted])"
}
func (RefreshDeviceTaskBinding) LogValue() slog.Value {
	return slog.StringValue("[protected-refresh-device-task-binding]")
}

type TaskCapabilitySummary struct {
	Ref          string      `json:"ref"`
	Revision     uint64      `json:"revision"`
	ResultSchema string      `json:"resultSchema"`
	MediaKinds   []MediaKind `json:"mediaKinds"`
}

// DeviceTaskSummary is the only task shape intended for business channels.
// It deliberately excludes tenant/site/profile binding, native locator, and
// identity/capability fingerprints.
type DeviceTaskSummary struct {
	TaskHandle    string                  `json:"taskHandle"`
	Alias         string                  `json:"alias"`
	Revision      uint64                  `json:"revision"`
	State         State                   `json:"state"`
	SourceHandles []string                `json:"sourceHandles"`
	Capabilities  []TaskCapabilitySummary `json:"capabilities"`
	ObservedAt    time.Time               `json:"observedAt"`
}

func NormalizeTaskCapabilities(values []Capability) ([]Capability, error) {
	result, err := NormalizeCapabilities(values)
	if err != nil {
		return nil, ErrInvalidTask
	}
	for _, capability := range result {
		if capability.Kind != CapabilityTaskEvidence || capability.ResultSchema == "" {
			return nil, ErrInvalidTask
		}
	}
	return result, nil
}

func normalizeTaskSourceHandles(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 32 {
		return nil, ErrInvalidTask
	}
	result := make([]string, len(values))
	for index, value := range values {
		value = strings.TrimSpace(value)
		if !validRef(value) {
			return nil, ErrInvalidTask
		}
		result[index] = value
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, ErrInvalidTask
		}
	}
	return result, nil
}

func (task DeviceTaskBinding) Validate() error {
	if task.Schema != SchemaVersion || !validRef(task.TenantID) || !validRef(task.SiteID) ||
		!validRef(task.DeviceProfileID) || !validRef(task.TaskHandle) || task.Revision == 0 ||
		!digestPattern.MatchString(task.IdentityFingerprint) || !validState(task.State) ||
		task.ObservedAt.IsZero() || task.CreatedAt.IsZero() || task.UpdatedAt.Before(task.CreatedAt) ||
		task.ObservedAt.After(task.UpdatedAt) {
		return ErrInvalidTask
	}
	if err := validateProtectedText("native task locator", task.NativeLocator, 512); err != nil {
		return errors.Join(ErrInvalidTask, err)
	}
	if err := validateBusinessText("task alias", task.Alias, 160); err != nil {
		return errors.Join(ErrInvalidTask, err)
	}
	if len(task.SourceHandles) == 0 || len(task.SourceHandles) > 32 {
		return ErrInvalidTask
	}
	for index, handle := range task.SourceHandles {
		if !validRef(handle) || index > 0 && task.SourceHandles[index-1] >= handle {
			return ErrInvalidTask
		}
	}
	if len(task.Capabilities) == 0 || len(task.Capabilities) > 32 {
		return ErrInvalidTask
	}
	for index, capability := range task.Capabilities {
		if capability.Kind != CapabilityTaskEvidence || capability.ResultSchema == "" ||
			validateCapability(capability, true) != nil || index > 0 && task.Capabilities[index-1].Ref >= capability.Ref {
			return ErrInvalidTask
		}
	}
	return nil
}

func (task DeviceTaskBinding) Summary() (DeviceTaskSummary, error) {
	if err := task.Validate(); err != nil {
		return DeviceTaskSummary{}, err
	}
	summary := DeviceTaskSummary{
		TaskHandle: task.TaskHandle, Alias: task.Alias, Revision: task.Revision, State: task.State,
		SourceHandles: append([]string(nil), task.SourceHandles...), ObservedAt: task.ObservedAt,
		Capabilities: make([]TaskCapabilitySummary, 0, len(task.Capabilities)),
	}
	for _, capability := range task.Capabilities {
		summary.Capabilities = append(summary.Capabilities, TaskCapabilitySummary{
			Ref: capability.Ref, Revision: capability.Revision, ResultSchema: capability.ResultSchema,
			MediaKinds: append([]MediaKind(nil), capability.Constraints.MediaKinds...),
		})
	}
	return summary, nil
}

func cloneDeviceTask(task DeviceTaskBinding) DeviceTaskBinding {
	task.SourceHandles = append([]string(nil), task.SourceHandles...)
	task.Capabilities = cloneTaskCapabilities(task.Capabilities)
	return task
}

func cloneTaskCapabilities(values []Capability) []Capability {
	result := append([]Capability(nil), values...)
	for index := range result {
		result[index].Constraints.MediaKinds = append([]MediaKind(nil), result[index].Constraints.MediaKinds...)
	}
	return result
}

func canonicalRequiredTaskCapabilities(values []string) ([]string, error) {
	result := normalizeRefs(values)
	if len(result) == 0 || len(result) > 16 {
		return nil, ErrTaskCapability
	}
	for _, value := range result {
		if !validRef(value) {
			return nil, ErrTaskCapability
		}
	}
	sort.Strings(result)
	return result, nil
}

func sameTaskCreateFact(current DeviceTaskBinding, requested DeviceTaskBinding) bool {
	if current.TenantID != requested.TenantID || current.SiteID != requested.SiteID ||
		current.DeviceProfileID != requested.DeviceProfileID || current.TaskHandle != requested.TaskHandle ||
		current.IdentityFingerprint != requested.IdentityFingerprint || current.NativeLocator != requested.NativeLocator ||
		current.Alias != requested.Alias || current.State != StateActive || !current.ObservedAt.Equal(requested.ObservedAt) ||
		!equalStrings(current.SourceHandles, requested.SourceHandles) || len(current.Capabilities) != len(requested.Capabilities) {
		return false
	}
	for index := range current.Capabilities {
		if current.Capabilities[index].Digest != requested.Capabilities[index].Digest {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
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

func taskAliasKey(value string) string { return strings.TrimSpace(value) }
