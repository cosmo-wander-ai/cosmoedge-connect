package deployment

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
)

// originalVerification reads only the closed Observation schema written by
// Verify. It never guesses from the operation conclusion, counters, or Current.
func originalVerification(e ledger.EvidenceRecord, target Proposal) *VerificationSnapshot {
	if e.Status != "sealed" || len(e.PayloadJSON) > 128*1024 || !json.Valid([]byte(e.PayloadJSON)) {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(e.PayloadJSON), &fields) != nil {
		return nil
	}
	for _, key := range []string{"sourceId", "algorithmId", "exists", "enabled", "configurationMatch", "runtime", "observedAt"} {
		raw, ok := fields[key]
		if !ok || string(raw) == "null" {
			return nil
		}
	}
	var observation Observation
	decoder := json.NewDecoder(strings.NewReader(e.PayloadJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&observation) != nil || observation.SourceID != target.SourceID || observation.AlgorithmID != target.AlgorithmID || observation.ObservedAt.IsZero() || observation.Enabled < -1 || observation.Enabled > 1 {
		return nil
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, e.ObservedAt)
	if err != nil || recordedAt.IsZero() {
		return nil
	}
	sealedAt, err := time.Parse(time.RFC3339Nano, e.SealedAt)
	if err != nil || sealedAt.IsZero() || !recordedAt.Equal(sealedAt) || observation.ObservedAt.After(sealedAt) {
		return nil
	}
	switch observation.Runtime {
	case "unknown", "processing_unconfirmed":
		if len(observation.Progress) != 0 {
			return nil
		}
	case "stopped":
		if !observation.Exists || observation.Enabled != 0 || len(observation.Progress) != 0 {
			return nil
		}
	case "processing":
		if !observation.Exists || observation.Enabled != 1 || !observation.ConfigurationMatch || len(observation.Progress) == 0 {
			return nil
		}
	default:
		return nil
	}
	seen := map[string]bool{}
	for _, progress := range observation.Progress {
		if progress.NodeID == "" || seen[progress.NodeID] || progress.After <= progress.Before {
			return nil
		}
		seen[progress.NodeID] = true
	}
	// Source/algorithm were checked against the action's pinned target. Neither
	// arbitrary task strings nor the raw stored payload are exposed here.
	return &VerificationSnapshot{Exists: observation.Exists, Enabled: observation.Enabled, ConfigurationMatch: observation.ConfigurationMatch, Runtime: observation.Runtime, Progress: observation.Progress, ObservedAt: observation.ObservedAt.UTC(), SealedAt: sealedAt.UTC()}
}
