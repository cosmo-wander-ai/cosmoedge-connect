package devlab

import (
	"context"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/devauthority"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

const (
	MaximumRunDuration = 10 * time.Minute
	MaximumReads       = 200
	MaximumRepeat      = 50
	MinimumInterval    = 250 * time.Millisecond
)

type Lease interface {
	Read(context.Context) (device.Snapshot, error)
	ObserveTaskEvents(context.Context, device.Task, device.EventWindow) (device.Snapshot, device.TaskEventObservation, error)
	Close() error
}

type OpenLeaseFunc func(context.Context, time.Duration) (Lease, device.Snapshot, devauthority.ReadLeaseInfo, error)

func AuthorityOpener(authority *devauthority.Authority) OpenLeaseFunc {
	return func(ctx context.Context, duration time.Duration) (Lease, device.Snapshot, devauthority.ReadLeaseInfo, error) {
		return authority.OpenReadLease(ctx, duration)
	}
}

type BeginRequest struct {
	DurationSeconds int    `json:"durationSeconds"`
	Commit          string `json:"commit"`
	ChangeDigest    string `json:"changeDigest"`
}

type RunInfo struct {
	RunID          string    `json:"runId"`
	Status         string    `json:"status"`
	Device         string    `json:"device"`
	DeviceType     string    `json:"deviceType"`
	OpenedAt       time.Time `json:"openedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	ReadCount      int       `json:"readCount"`
	DeviceWrites   int       `json:"deviceWrites"`
	ProbeCount     int       `json:"probeCount"`
	AssertionCount int       `json:"assertionCount"`
}

type ProbeRequest struct {
	Kind       string          `json:"kind"`
	Handle     string          `json:"handle,omitempty"`
	Repeat     int             `json:"repeat,omitempty"`
	IntervalMS int             `json:"intervalMs,omitempty"`
	Window     string          `json:"window,omitempty"`
	Hypothesis string          `json:"hypothesis,omitempty"`
	Assertions []AssertionSpec `json:"assertions,omitempty"`
}

type ProbeResult struct {
	RunID          string            `json:"runId"`
	ProbeID        string            `json:"probeId"`
	Kind           string            `json:"kind"`
	Status         string            `json:"status"`
	Samples        []map[string]any  `json:"samples"`
	Assertions     []AssertionResult `json:"assertions"`
	ReadCount      int               `json:"readCount"`
	RemainingReads int               `json:"remainingReads"`
	DeviceWrites   int               `json:"deviceWrites"`
	ObservedAt     time.Time         `json:"observedAt"`
}

type AssertionSpec struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Expected any    `json:"expected,omitempty"`
}

type AssertionResult struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Status   string `json:"status"`
	Observed any    `json:"observed,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type FinishResult struct {
	RunInfo
	Result string `json:"result"`
}

type Recorder interface {
	StartRun(context.Context, EvidenceRun) error
	RecordProbe(context.Context, EvidenceProbe) error
	FinishRun(context.Context, string, string, time.Time, int, int, int) error
}

type EvidenceRun struct {
	RunID, Device, DeviceType, Commit, ChangeDigest string
	OpenedAt, ExpiresAt                             time.Time
}

type EvidenceProbe struct {
	RunID, ProbeID, Kind, HypothesisDigest, PublicJSON string
	Assertions                                         []AssertionResult
	ObservedAt                                         time.Time
	ReadCount, DeviceWrites                            int
}
