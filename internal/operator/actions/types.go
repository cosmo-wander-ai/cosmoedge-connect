package actions

import (
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

const (
	KindTaskSwitch     = "task_switch"
	KindTaskParameters = "task_parameters"
	KindCameraSource   = "camera_source"
)

type ConnectionProvider interface {
	ActionConnection() (device.ActionConnection, error)
}

type Proposal struct {
	ActionID           string    `json:"-"`
	Kind               string    `json:"kind"`
	State              string    `json:"state"`
	ConfirmationToken  string    `json:"businessConfirmationToken"`
	ExpiresAt          time.Time `json:"expiresAt"`
	TargetState        string    `json:"targetState,omitempty"`
	ChangedCount       int       `json:"changedCount,omitempty"`
	CatalogCountBefore int       `json:"catalogCountBefore,omitempty"`
	CatalogCountTarget int       `json:"catalogCountTarget,omitempty"`
}

type Status struct {
	ActionID      string `json:"-"`
	Kind          string `json:"kind"`
	State         string `json:"state"`
	Class         string `json:"class,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	Conclusion    string `json:"conclusion,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Dispatches    int    `json:"dispatches"`
	DeviceWrites  int    `json:"deviceWrites"`
	TargetState   string `json:"targetState,omitempty"`
	ChangedCount  int    `json:"changedCount,omitempty"`
	CatalogBefore int    `json:"catalogCountBefore,omitempty"`
}

type ParameterField struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Before  string `json:"before,omitempty"`
	Changed bool   `json:"changed,omitempty"`
}

type publicMetadata struct {
	Action        string `json:"action"`
	TargetState   string `json:"targetState,omitempty"`
	ChangedCount  int    `json:"changedCount,omitempty"`
	CatalogBefore int    `json:"catalogCountBefore,omitempty"`
}
