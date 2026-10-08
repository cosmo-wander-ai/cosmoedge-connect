// Package observation owns one session-bound temporary visual observation.
// It composes livevision, media preparation and temporary runtime directly.
package observation

import (
	"context"
	"errors"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

var (
	ErrNotFound           = errors.New("observation was not found in this session")
	ErrConflict           = errors.New("observation request identifier has different content")
	ErrInvalidRequest     = errors.New("observation request is invalid")
	ErrUnavailable        = errors.New("observation service is unavailable")
	ErrConnectionRequired = errors.New("observation requires a current device connection")
	ErrMediaUnavailable   = errors.New("observation image is unavailable or expired")
	ErrCapacity           = errors.New("observation retained operation capacity is exhausted")
)

type Config struct {
	StateRoot      string
	Vault          *session.Vault
	WorkerInterval time.Duration
	RunTimeout     time.Duration
	EvidenceTTL    time.Duration
	MaxOperations  int
	Now            func() time.Time
}

type Request struct {
	SourceRef  string `json:"sourceRef,omitempty"`
	RequestID  string `json:"requestId"`
	SourceName string `json:"sourceName"`
	Question   string `json:"question"`
	Subject    string `json:"subject,omitempty"`
	// Empty keeps the original edge-analysis contract, including old records.
	Mode string `json:"mode,omitempty"`
}

const CaptureOnly = "capture"

type Result struct {
	Kind           string           `json:"kind"`
	AnalysisSource string           `json:"analysisSource"`
	OperationRef   string           `json:"operationRef"`
	RequestID      string           `json:"requestId"`
	Pending        bool             `json:"pending"`
	Status         string           `json:"status"`
	Question       string           `json:"question"`
	Answer         temporary.Answer `json:"answer,omitempty"`
	Facts          []string         `json:"facts,omitempty"`
	Limitations    []string         `json:"limitations"`
	SourceName     string           `json:"sourceName"`
	SourceKind     string           `json:"sourceKind"`
	TimeMeaning    string           `json:"timeMeaning"`
	FrameTimeKnown bool             `json:"frameTimeKnown"`
	ObservedAt     *time.Time       `json:"observedAt,omitempty"`
	Attachments    []Attachment     `json:"attachments"`
	CleanupStatus  string           `json:"cleanupStatus,omitempty"`
}

type Attachment struct {
	MediaRef  string    `json:"mediaRef"`
	MIMEType  string    `json:"mimeType"`
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"sizeBytes"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Media struct {
	Content  []byte
	MIMEType string
	SHA256   string
}

type SourceChoice struct {
	Name      string `json:"name"`
	SourceRef string `json:"sourceRef"`
}
type SourceSelectionError struct {
	Code    string         `json:"code"`
	Choices []SourceChoice `json:"choices"`
}

func (e *SourceSelectionError) Error() string { return "an exact observation source must be selected" }

// API is the host-facing surface; reads never acquire a fresh picture or submit
// a task. ownerHash must come from the authenticated conversation capability.
type API interface {
	Observe(context.Context, string, Request) (Result, error)
	Get(context.Context, string, string) (Result, error)
	GetByRequest(context.Context, string, string) (Result, error)
	ReadMedia(context.Context, string, string) (Media, error)
}
