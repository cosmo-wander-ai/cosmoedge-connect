// Package delivery owns channel delivery identities, leases and truthful
// unknown-outcome handling. Payloads contain only business-safe text and media
// references; transports never receive device locators or local media paths.
package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "cosmoedge.inspection.delivery.v2"

var (
	ErrInvalid        = errors.New("inspection delivery is invalid")
	ErrConflict       = errors.New("inspection delivery conflicts with stored state")
	ErrNotFound       = errors.New("inspection delivery was not found")
	ErrLeaseLost      = errors.New("inspection delivery lease was lost")
	ErrOutcomeUnknown = errors.New("inspection delivery outcome is unknown")
	refPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	mediaRefPattern   = regexp.MustCompile(`^media_[0-9a-f]{32}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	protectedText     = regexp.MustCompile(`(?i)(?:https?|rtsps?)://|(?:image)?base64|\b(?:password|passwd|token|cookie|authorization|prompt|endpoint|device[_-]?id|camera[_-]?id|model[_-]?output)\b`)
)

type State string

const (
	StatePending        State = "pending"
	StateSending        State = "sending"
	StateDelivered      State = "delivered"
	StateOutcomeUnknown State = "outcome_unknown"
	StateFailed         State = "failed"
)

type Audience struct {
	TenantID        string `json:"tenantId"`
	SiteID          string `json:"siteId"`
	Channel         string `json:"channel"`
	ConversationRef string `json:"conversationRef"`
	RecipientRef    string `json:"recipientRef"`
}

func (a Audience) Validate() error {
	for _, value := range []string{a.TenantID, a.SiteID, a.Channel, a.ConversationRef, a.RecipientRef} {
		if !validRef(value) {
			return ErrInvalid
		}
	}
	return nil
}

func (a Audience) SHA256() (string, error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

type Attachment struct {
	MediaRef       string    `json:"mediaRef"`
	SHA256         string    `json:"sha256"`
	Kind           string    `json:"kind"`
	AudienceSHA256 string    `json:"audienceSha256"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type Presentation struct {
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	DetailLabel string `json:"detailLabel,omitempty"`
}

type Message struct {
	Schema         string       `json:"schema"`
	DeliveryID     string       `json:"deliveryId"`
	IdempotencyKey string       `json:"idempotencyKey"`
	RunRef         string       `json:"runRef"`
	ResultRef      string       `json:"resultRef"`
	Audience       Audience     `json:"audience"`
	AudienceSHA256 string       `json:"audienceSha256"`
	Presentation   Presentation `json:"presentation"`
	Attachments    []Attachment `json:"attachments"`
	CreatedAt      time.Time    `json:"createdAt"`
}

func NewMessage(runRef, resultRef string, audience Audience, presentation Presentation, attachments []Attachment, createdAt time.Time) (Message, error) {
	audienceDigest, err := audience.SHA256()
	if err != nil {
		return Message{}, err
	}
	identity := strings.Join([]string{audience.TenantID, audience.SiteID, audience.Channel, audience.ConversationRef, audience.RecipientRef, runRef, resultRef}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	id := "delivery_" + hex.EncodeToString(sum[:16])
	message := Message{
		Schema: SchemaVersion, DeliveryID: id, IdempotencyKey: id, RunRef: runRef, ResultRef: resultRef,
		Audience: audience, AudienceSHA256: audienceDigest, Presentation: presentation,
		Attachments: append([]Attachment(nil), attachments...), CreatedAt: createdAt.UTC(),
	}
	for index := range message.Attachments {
		message.Attachments[index].AudienceSHA256 = audienceDigest
	}
	sort.Slice(message.Attachments, func(i, j int) bool { return message.Attachments[i].MediaRef < message.Attachments[j].MediaRef })
	if err := message.Validate(); err != nil {
		return Message{}, err
	}
	return message, nil
}

// ResultRefForRun is the sole public result identity derivation. Delivery,
// application projections and offline evaluators use the same domain-separated
// mapping rather than duplicating it.
func ResultRefForRun(publicRunRef string) (string, error) {
	if !validRef(publicRunRef) {
		return "", ErrInvalid
	}
	digest := sha256.Sum256([]byte("inspection-result\x00" + publicRunRef))
	return "result_" + hex.EncodeToString(digest[:16]), nil
}

func (m Message) Validate() error {
	if m.Schema != SchemaVersion || !validRef(m.DeliveryID) || m.IdempotencyKey != m.DeliveryID ||
		!validRef(m.RunRef) || !validRef(m.ResultRef) || m.CreatedAt.IsZero() || m.Audience.Validate() != nil {
		return ErrInvalid
	}
	digest, err := m.Audience.SHA256()
	if err != nil || m.AudienceSHA256 != digest {
		return ErrInvalid
	}
	if !safeText(m.Presentation.Title, 1, 128) || !safeText(m.Presentation.Summary, 1, 1000) ||
		(m.Presentation.DetailLabel != "" && !safeText(m.Presentation.DetailLabel, 1, 128)) {
		return ErrInvalid
	}
	if len(m.Attachments) > 16 {
		return ErrInvalid
	}
	for index, attachment := range m.Attachments {
		if !mediaRefPattern.MatchString(attachment.MediaRef) || !digestPattern.MatchString(attachment.SHA256) || !validAttachmentKind(attachment.Kind) ||
			attachment.AudienceSHA256 != m.AudienceSHA256 || !attachment.ExpiresAt.After(m.CreatedAt) ||
			attachment.ExpiresAt.Sub(m.CreatedAt) > 30*24*time.Hour ||
			index > 0 && m.Attachments[index-1].MediaRef >= attachment.MediaRef {
			return ErrInvalid
		}
	}
	return nil
}

func validAttachmentKind(value string) bool {
	switch value {
	case "image", "frame_set", "video_clip", "metric", "detection", "event":
		return true
	default:
		return false
	}
}

type Attempt struct {
	AttemptID      string
	DeliveryID     string
	Number         int
	Owner          string
	LeaseExpiresAt time.Time
	StartedAt      time.Time
}

type Record struct {
	Message                Message
	State                  State
	Attempts               int
	ReconciliationAttempts int
	AvailableAt            time.Time
	LeaseOwner             string
	LeaseExpiresAt         time.Time
	ReceiptRef             string
	Reason                 string
	UpdatedAt              time.Time
	DeliveredAt            time.Time
}

// ReconciliationAttempt is a private claim on one outcome-unknown delivery.
// It binds the stable delivery, idempotency and audience identities to the
// exact store generation that a reconciler is allowed to complete.
type ReconciliationAttempt struct {
	DeliveryID     string
	IdempotencyKey string
	AudienceSHA256 string
	Number         int
	Owner          string
	LeaseExpiresAt time.Time
	StartedAt      time.Time
}

// Acknowledgement is a trusted local observation of a channel receipt.
// ObservedAt is the local ingestion time, never a channel-supplied event time.
type Acknowledgement struct {
	DeliveryID     string
	IdempotencyKey string
	AudienceSHA256 string
	ReceiptRef     string
	ObservedAt     time.Time
}

type Recovery struct {
	SendingBecameUnknown     int
	ReconciliationLeaseFreed int
}

type Reconciliation string

const (
	ReconciliationDelivered    Reconciliation = "delivered"
	ReconciliationNotDelivered Reconciliation = "not_delivered"
	ReconciliationUnknown      Reconciliation = "unknown"
)

func validRef(value string) bool {
	return strings.TrimSpace(value) == value && refPattern.MatchString(value)
}

func safeText(value string, minimum, maximum int) bool {
	return strings.TrimSpace(value) == value && utf8.ValidString(value) && utf8.RuneCountInString(value) >= minimum &&
		utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\x00\r") && !protectedText.MatchString(value)
}

func messageDigest(message Message) (string, error) {
	raw, err := json.Marshal(message)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
