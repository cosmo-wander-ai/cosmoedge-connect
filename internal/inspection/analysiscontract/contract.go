package analysiscontract

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

func Digest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// Build combines one validated candidate with CosmoEdge Connect-owned bindings. No
// envelope field can be sourced from model output.
func Build(trusted TrustedFields, candidate Candidate) (Envelope, error) {
	if err := trusted.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("validate trusted analysis fields: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("validate analysis candidate: %w", err)
	}
	envelope := Envelope{
		SchemaVersion: SchemaVersion,
		Binding:       cloneBinding(trusted.Binding),
		Analyzer:      trusted.Analyzer,
		Candidate:     cloneCandidate(candidate),
		Execution:     trusted.Execution,
		Integrity:     trusted.Integrity,
		DisplayPolicy: cloneDisplayPolicy(trusted.DisplayPolicy),
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("build analysis envelope: %w", err)
	}
	return envelope, nil
}

func BuildFromRaw(trusted TrustedFields, rawCandidate []byte) (Envelope, error) {
	candidate, err := ParseCandidate(rawCandidate)
	if err != nil {
		return Envelope{}, err
	}
	digest := Digest(rawCandidate)
	if trusted.Integrity.RawOutputSHA256 == "" {
		trusted.Integrity.RawOutputSHA256 = digest
	} else if !equalDigest(trusted.Integrity.RawOutputSHA256, digest) {
		return Envelope{}, errors.New("candidate bytes do not match rawOutputSha256")
	}
	return Build(trusted, candidate)
}

func (t TrustedFields) Validate() error {
	if err := t.Binding.Validate(); err != nil {
		return err
	}
	if err := t.Analyzer.Validate(); err != nil {
		return err
	}
	if err := t.Execution.Validate(); err != nil {
		return err
	}
	if err := t.Integrity.Validate(); err != nil {
		return err
	}
	if t.DisplayPolicy == nil {
		return nil
	}
	if t.Binding.Usage != inspection.ResultUsageTemporaryObservation {
		return errors.New("display policy is forbidden for a standard inspection result")
	}
	if err := t.DisplayPolicy.validate(); err != nil {
		return err
	}
	return nil
}

func (e Envelope) ValidateBindings(trusted TrustedFields) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if err := trusted.Validate(); err != nil {
		return fmt.Errorf("trusted analysis fields: %w", err)
	}
	if !equalBinding(e.Binding, trusted.Binding) {
		return errors.New("analysis result binding mismatch")
	}
	if e.Analyzer != trusted.Analyzer {
		return errors.New("analysis analyzer or prompt binding mismatch")
	}
	if !equalExecution(e.Execution, trusted.Execution) {
		return errors.New("analysis execution binding mismatch")
	}
	if !equalDigest(e.Integrity.RawOutputSHA256, trusted.Integrity.RawOutputSHA256) {
		return errors.New("analysis rawOutputSha256 binding mismatch")
	}
	if !equalDigest(e.Integrity.ContractSHA256, trusted.Integrity.ContractSHA256) {
		return errors.New("analysis contractSha256 binding mismatch")
	}
	if !reflect.DeepEqual(e.DisplayPolicy, trusted.DisplayPolicy) {
		return errors.New("analysis display policy binding mismatch")
	}
	return nil
}

func ParseAndValidateEnvelope(raw []byte, trusted TrustedFields) (Envelope, error) {
	envelope, err := ParseEnvelope(raw)
	if err != nil {
		return Envelope{}, err
	}
	if err := envelope.ValidateBindings(trusted); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func equalBinding(left, right inspection.ResultBinding) bool {
	if left.ResultID != right.ResultID || left.RunID != right.RunID || left.StepID != right.StepID ||
		left.TargetID != right.TargetID || left.CriterionID != right.CriterionID || left.CriterionVersion != right.CriterionVersion ||
		left.OutputKind != right.OutputKind || left.OutputSchemaVersion != right.OutputSchemaVersion || left.Usage != right.Usage ||
		!left.TimeWindow.StartAt.Equal(right.TimeWindow.StartAt) || !left.TimeWindow.EndAt.Equal(right.TimeWindow.EndAt) ||
		len(left.SourceMedia) != len(right.SourceMedia) {
		return false
	}
	for i := range left.SourceMedia {
		a, b := left.SourceMedia[i], right.SourceMedia[i]
		if a.SourceRef != b.SourceRef || a.MediaRef != b.MediaRef || !equalDigest(a.SHA256, b.SHA256) ||
			!a.CapturedAt.Equal(b.CapturedAt) || a.FreshnessMS != b.FreshnessMS || a.SampleOrdinal != b.SampleOrdinal {
			return false
		}
	}
	return true
}

func equalExecution(left, right inspection.ResultExecution) bool {
	return left.Attempt == right.Attempt && left.StartedAt.Equal(right.StartedAt) && left.CompletedAt.Equal(right.CompletedAt) &&
		left.LatencyMS == right.LatencyMS && left.TemporaryResourcesCreated == right.TemporaryResourcesCreated &&
		left.TemporaryResourcesCleaned == right.TemporaryResourcesCleaned && left.PersistentConfigWrites == right.PersistentConfigWrites
}

func equalDigest(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func cloneBinding(value inspection.ResultBinding) inspection.ResultBinding {
	clone := value
	clone.SourceMedia = append([]inspection.ResultSourceMedia(nil), value.SourceMedia...)
	return clone
}

func cloneCandidate(candidate Candidate) Candidate {
	clone := candidate
	clone.Confidence = cloneFloat(candidate.Confidence)
	clone.Value = cloneResultValue(candidate.Value)
	if candidate.EvidenceRefs != nil {
		clone.EvidenceRefs = make([]string, len(candidate.EvidenceRefs))
		copy(clone.EvidenceRefs, candidate.EvidenceRefs)
	}
	if candidate.Limitations != nil {
		clone.Limitations = make([]Limitation, len(candidate.Limitations))
		copy(clone.Limitations, candidate.Limitations)
	}
	if candidate.ReasonCodes != nil {
		clone.ReasonCodes = make([]ReasonCode, len(candidate.ReasonCodes))
		copy(clone.ReasonCodes, candidate.ReasonCodes)
	}
	return clone
}

func cloneDisplayPolicy(value *DisplayPolicy) *DisplayPolicy {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneResultValue(value *inspection.ResultValue) *inspection.ResultValue {
	if value == nil {
		return nil
	}
	clone := *value
	if value.Classification != nil {
		member := *value.Classification
		member.Score = cloneFloat(value.Classification.Score)
		clone.Classification = &member
	}
	if value.Enum != nil {
		member := *value.Enum
		clone.Enum = &member
	}
	if value.Structured != nil {
		member := *value.Structured
		member.Fields = make([]inspection.StructuredField, len(value.Structured.Fields))
		for i, field := range value.Structured.Fields {
			member.Fields[i] = field
			member.Fields[i].Value.Enum = cloneString(field.Value.Enum)
			member.Fields[i].Value.Number = cloneFloat(field.Value.Number)
			member.Fields[i].Value.Integer = cloneInt64(field.Value.Integer)
			member.Fields[i].Value.Boolean = cloneBool(field.Value.Boolean)
		}
		clone.Structured = &member
	}
	if value.Metric != nil {
		member := *value.Metric
		clone.Metric = &member
	}
	if value.Detection != nil {
		member := *value.Detection
		if value.Detection.Objects != nil {
			member.Objects = make([]inspection.DetectionObject, len(value.Detection.Objects))
			copy(member.Objects, value.Detection.Objects)
		}
		for i := range member.Objects {
			member.Objects[i].Score = cloneFloat(member.Objects[i].Score)
		}
		clone.Detection = &member
	}
	if value.Count != nil {
		member := *value.Count
		clone.Count = &member
	}
	if value.Event != nil {
		member := *value.Event
		clone.Event = &member
	}
	return &clone
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
