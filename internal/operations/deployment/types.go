// Package deployment manages one durable camera/installed-algorithm binding
// through the existing action ledger and worker. It owns no device connection.
package deployment

import (
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

const Kind = "algorithm_deployment"

type ConnectionProvider interface {
	ActionConnection() (device.ActionConnection, error)
}

// Client is implemented by the controlled device adapter. Configuration is the
// complete native document; flattening it would lose pipeline and schedule data.
type Client = device.DeploymentClient
type Configuration = device.DeploymentConfiguration
type Target = device.DeploymentTarget
type State = device.DeploymentState
type Runtime = device.DeploymentRuntime

type Request struct {
	RequestID   string `json:"requestId"`
	SourceID    string `json:"sourceId"`
	AlgorithmID string `json:"algorithmId"`
	Enabled     bool   `json:"enabled"`
}

type Proposal struct {
	ActionRef         string `json:"actionRef"`
	State             string `json:"state,omitempty"`
	SourceID          string `json:"sourceId"`
	SourceName        string `json:"sourceName"`
	AlgorithmID       string `json:"algorithmId"`
	AlgorithmName     string `json:"algorithmName"`
	Enabled           bool   `json:"enabled"`
	ExistingBinding   bool   `json:"existingBinding"`
	ConfigurationKind string `json:"configurationKind,omitempty"`
	// Confirmation authority is internal to the local browser gate, never an API projection.
	ConfirmationToken string    `json:"-"`
	ExpiresAt         time.Time `json:"expiresAt,omitempty"`
	Missing           []string  `json:"missing,omitempty"`
}

type Observation struct {
	SourceID           string     `json:"sourceId"`
	AlgorithmID        string     `json:"algorithmId"`
	TaskID             string     `json:"taskId,omitempty"`
	Exists             bool       `json:"exists"`
	Enabled            int        `json:"enabled"`
	ConfigurationMatch bool       `json:"configurationMatch"`
	Runtime            string     `json:"runtime"`
	Progress           []Progress `json:"progress,omitempty"`
	ObservedAt         time.Time  `json:"observedAt"`
}

type Progress struct {
	NodeID string `json:"nodeId"`
	Before uint64 `json:"before"`
	After  uint64 `json:"after"`
}

// ConfirmationReceipt describes this Confirm call, never a device dispatch delta.
// An already-confirmed operation can still be progressing independently.
type ConfirmationReceipt struct {
	Disposition             string `json:"disposition"`
	NewConfirmationAccepted bool   `json:"newConfirmationAccepted"`
}

// VerificationSnapshot is the original sealed readback, not a new device read
// or proof that a dispatch with an unknown outcome succeeded.
type VerificationSnapshot struct {
	Exists             bool       `json:"exists"`
	Enabled            int        `json:"enabled"`
	ConfigurationMatch bool       `json:"configurationMatch"`
	Runtime            string     `json:"runtime"`
	Progress           []Progress `json:"progress,omitempty"`
	ObservedAt         time.Time  `json:"observedAt"`
	SealedAt           time.Time  `json:"sealedAt"`
}

type Status struct {
	OriginalVerificationAvailable bool                       `json:"originalVerificationAvailable"`
	OriginalVerification          *VerificationSnapshot      `json:"originalVerification,omitempty"`
	ActionRef                     string                     `json:"actionRef"`
	State                         string                     `json:"state"`
	Class                         string                     `json:"class,omitempty"`
	Reason                        string                     `json:"reason,omitempty"`
	Conclusion                    string                     `json:"conclusion,omitempty"`
	Dispatches                    int                        `json:"dispatches"`
	DeviceWrites                  int                        `json:"deviceWrites"`
	DispatchOutcome               string                     `json:"dispatchOutcome,omitempty"`
	Diagnostic                    *safediagnostic.Diagnostic `json:"diagnostic,omitempty"`
	DiagnosticMessage             string                     `json:"diagnosticMessage,omitempty"`
	Target                        Proposal                   `json:"target"`
	Current                       *Observation               `json:"current,omitempty"`
}
