package result

import (
	"errors"
	"strings"
	"time"
)

type Class string

const (
	Completed Class = "completed"
	Blocked   Class = "blocked"
	Unknown   Class = "unknown"
)

type EvidenceStatus string

const (
	EvidenceSealed  EvidenceStatus = "sealed"
	EvidencePending EvidenceStatus = "evidence_pending"
)

type Trusted struct {
	Class          Class
	EvidenceStatus EvidenceStatus
	Conclusion     string
	Reason         string
	EvidenceJSON   string
	ObservedAt     time.Time
}

func (r Trusted) Validate() error {
	if r.Class != Completed && r.Class != Blocked && r.Class != Unknown {
		return errors.New("trusted result class is invalid")
	}
	if r.EvidenceStatus != EvidenceSealed && r.EvidenceStatus != EvidencePending {
		return errors.New("trusted evidence status is invalid")
	}
	if strings.TrimSpace(r.Conclusion) == "" || strings.TrimSpace(r.Reason) == "" {
		return errors.New("trusted result conclusion and reason are required")
	}
	if r.ObservedAt.IsZero() {
		return errors.New("trusted result observation time is required")
	}
	return nil
}
