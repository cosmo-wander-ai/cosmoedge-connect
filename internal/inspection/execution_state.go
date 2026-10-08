package inspection

import "time"

// StepState is the durable state of one frozen execution step. A step in
// outcome_unknown can only move again through an explicit reconciliation
// decision; it is never treated as retryable by default.
type StepState string

const (
	StepPending        StepState = "pending"
	StepRunning        StepState = "running"
	StepSucceeded      StepState = "succeeded"
	StepFailed         StepState = "failed"
	StepOutcomeUnknown StepState = "outcome_unknown"
	StepSkipped        StepState = "skipped"
)

type AttemptState string

const (
	AttemptRunning        AttemptState = "running"
	AttemptSucceeded      AttemptState = "succeeded"
	AttemptFailed         AttemptState = "failed"
	AttemptOutcomeUnknown AttemptState = "outcome_unknown"
	AttemptAbandoned      AttemptState = "abandoned"
)

// StepOutput binds one logical plan output to an opaque, integrity-bound
// value reference. It cannot carry bytes, paths, URLs, prompts, or native
// device identifiers.
type StepOutput struct {
	LogicalRef string        `json:"logicalRef"`
	Kind       StepValueKind `json:"kind"`
	ValueRef   string        `json:"valueRef"`
	SHA256     string        `json:"sha256"`
}

type StepRecord struct {
	RunID        string        `json:"runId"`
	StepID       string        `json:"stepId"`
	Sequence     int           `json:"sequence"`
	Kind         StepKind      `json:"kind"`
	Authority    StepAuthority `json:"authority"`
	State        StepState     `json:"state"`
	AttemptCount int           `json:"attemptCount"`
	Outputs      []StepOutput  `json:"outputs"`
	Reason       string        `json:"reason,omitempty"`
	CreatedAt    time.Time     `json:"createdAt"`
	UpdatedAt    time.Time     `json:"updatedAt"`
}

type StepAttempt struct {
	AttemptID    string       `json:"attemptId"`
	RunID        string       `json:"runId"`
	StepID       string       `json:"stepId"`
	Number       int          `json:"number"`
	State        AttemptState `json:"state"`
	Owner        string       `json:"owner"`
	LeaseExpires time.Time    `json:"leaseExpiresAt"`
	Outputs      []StepOutput `json:"outputs"`
	Reason       string       `json:"reason,omitempty"`
	StartedAt    time.Time    `json:"startedAt"`
	UpdatedAt    time.Time    `json:"updatedAt"`
	FinishedAt   time.Time    `json:"finishedAt,omitempty"`
}

type ReconciliationDecision string

const (
	ReconciliationRetry     ReconciliationDecision = "retry"
	ReconciliationSucceeded ReconciliationDecision = "succeeded"
	ReconciliationFailed    ReconciliationDecision = "failed"
)

type StepReconciliation struct {
	ReconciliationID string                 `json:"reconciliationId"`
	RunID            string                 `json:"runId"`
	StepID           string                 `json:"stepId"`
	AttemptID        string                 `json:"attemptId"`
	Decision         ReconciliationDecision `json:"decision"`
	ReconciledBy     string                 `json:"reconciledBy"`
	Outputs          []StepOutput           `json:"outputs"`
	Reason           string                 `json:"reason"`
	CreatedAt        time.Time              `json:"createdAt"`
}

func (s StepState) Terminal() bool {
	return s == StepSucceeded || s == StepFailed || s == StepOutcomeUnknown || s == StepSkipped
}

func (s StepState) Valid() bool {
	return s == StepPending || s == StepRunning || s.Terminal()
}

func (s AttemptState) Valid() bool {
	return s == AttemptRunning || s == AttemptSucceeded || s == AttemptFailed ||
		s == AttemptOutcomeUnknown || s == AttemptAbandoned
}
