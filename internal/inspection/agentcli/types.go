// Package agentcli owns the small Codex-facing process contract over the
// protected Inspection Product. Product remains the only inspection state,
// runtime, credential, worker, media and device-adapter owner.
package agentcli

import (
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
)

const SchemaVersion = "cosmoedge.inspection.agent.v1"

type Envelope struct {
	Schema       string       `json:"schema"`
	Command      string       `json:"command"`
	State        string       `json:"state"`
	Message      string       `json:"message"`
	ContextLabel string       `json:"contextLabel,omitempty"`
	Offerings    []Offering   `json:"offerings,omitempty"`
	Interaction  *Interaction `json:"interaction,omitempty"`
	RunRef       string       `json:"runRef,omitempty"`
	Result       *TextResult  `json:"result,omitempty"`
	Candidates   []Candidate  `json:"candidates,omitempty"`
}

type Offering struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Examples    []string `json:"examples"`
}

type Interaction struct {
	Title       string `json:"title"`
	Message     string `json:"message"`
	ActionLabel string `json:"actionLabel"`
	Capability  string `json:"capability"`
	HandoffRef  string `json:"handoffRef,omitempty"`
}

type StartRequest struct {
	Instruction string            `json:"instruction"`
	Context     []BusinessContext `json:"context,omitempty"`
}

type BusinessContext struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ContinueRequest struct {
	RunRef string `json:"runRef,omitempty"`
}

type Candidate struct {
	RunRef    string    `json:"runRef"`
	Area      string    `json:"area"`
	Goal      string    `json:"goal"`
	StartedAt time.Time `json:"startedAt"`
}

type TextResult struct {
	RunRef      string        `json:"runRef"`
	Summary     string        `json:"summary"`
	Answer      string        `json:"answer,omitempty"`
	Question    string        `json:"question,omitempty"`
	Sections    []TextSection `json:"sections"`
	Limitations []string      `json:"limitations"`
	CompletedAt time.Time     `json:"completedAt"`
}

type TextSection struct {
	Title      string   `json:"title"`
	Conclusion string   `json:"conclusion"`
	Details    []string `json:"details"`
}

type capabilitySet = httpapi.CapabilitySet
