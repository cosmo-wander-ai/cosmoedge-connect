package device

import (
	"context"
	"encoding/json"
	"time"
)

// DeploymentClient is an optional capability on the existing connection.
// Configuration documents keep native parameter and schedule structure.
type DeploymentClient interface {
	ReadDeployment(context.Context, string, string) (DeploymentState, error)
	DefaultDeployment(context.Context, string, string) (DeploymentConfiguration, error)
	SaveDeployment(context.Context, DeploymentTarget) error
	ReadDeploymentRuntime(context.Context, Task) (DeploymentRuntime, error)
}

type DeploymentConfiguration struct {
	Document       json.RawMessage
	Shape          string
	Ready          bool
	Missing        []string
	ScheduleDigest string
}

type DeploymentTarget struct {
	SourceID      string
	AlgorithmID   string
	TaskID        string
	Configuration DeploymentConfiguration
}

type DeploymentState struct {
	SourceID      string
	AlgorithmID   string
	TaskID        string
	Exists        bool
	Enabled       int // -1 means unavailable; 0 and 1 are verified switch values.
	Configuration DeploymentConfiguration
	ObservedAt    time.Time
}

// Counters contain only actual processing counters for stable runtime nodes.
// Required counters include decoder, primary inference, and a supported task-local
// downstream queue. Shared inference growth alone cannot prove this task advanced.
type DeploymentRuntime struct {
	TaskID     string
	Active     bool
	Stopped    bool
	Known      bool
	Counters   map[string]uint64
	ObservedAt time.Time
}
