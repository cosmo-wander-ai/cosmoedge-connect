package temporary

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

func ParseSpec(raw []byte) (TemporaryObservationSpec, error) {
	var spec TemporaryObservationSpec
	if err := decodeStrict(raw, &spec); err != nil {
		return TemporaryObservationSpec{}, fmt.Errorf("parse temporary observation spec: %w", err)
	}
	if err := validateSpecFieldPresence(raw); err != nil {
		return TemporaryObservationSpec{}, fmt.Errorf("parse temporary observation spec: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return TemporaryObservationSpec{}, fmt.Errorf("validate temporary observation spec: %w", err)
	}
	return spec, nil
}

func validateSpecFieldPresence(raw []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	for _, field := range []string{
		"schema", "subject", "region", "observable", "locale", "timeScope",
		"evidenceTtlSeconds", "normalizedIntentSha256",
	} {
		if _, present := root[field]; !present {
			return fmt.Errorf("required field %q is missing", field)
		}
	}
	var scope map[string]json.RawMessage
	if err := json.Unmarshal(root["timeScope"], &scope); err != nil {
		return err
	}
	for _, field := range []string{"kind", "windowSeconds"} {
		if _, present := scope[field]; !present {
			return fmt.Errorf("required timeScope field %q is missing", field)
		}
	}
	return nil
}

func ParseCandidate(raw []byte) (Candidate, error) {
	var candidate Candidate
	if err := decodeStrictBounded(raw, &candidate, MaxCandidateJSONBytes); err != nil {
		return Candidate{}, fmt.Errorf("parse temporary observation candidate: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return Candidate{}, fmt.Errorf("validate temporary observation candidate: %w", err)
	}
	return candidate, nil
}
func ParseAndBindCandidate(raw []byte, spec TemporaryObservationSpec, available []EvidenceBinding, generatedAt time.Time) (Observation, error) {
	candidate, err := ParseCandidate(raw)
	if err != nil {
		return Observation{}, err
	}
	return BindCandidate(spec, candidate, available, generatedAt)
}

func decodeStrict(raw []byte, output any) error {
	return decodeStrictBounded(raw, output, MaxJSONBytes)
}

func decodeStrictBounded(raw []byte, output any, maximumBytes int) error {
	if len(raw) < 1 || len(raw) > maximumBytes {
		return fmt.Errorf("temporary observation JSON size must be between 1 and %d bytes", maximumBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("temporary observation JSON is not valid UTF-8")
	}
	if err := validateJSONStructure(raw); err != nil {
		return err
	}
	if err := strictjson.ValidateExactFields(raw, output, MaxJSONDepth); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func validateJSONStructure(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if first != json.Delim('{') {
		return errors.New("temporary observation JSON root must be an object")
	}
	if err := consumeJSONObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("temporary observation JSON null is not allowed")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if depth >= MaxJSONDepth {
		return errors.New("temporary observation JSON nesting exceeds the allowed depth")
	}
	switch delimiter {
	case '{':
		return consumeJSONObject(decoder, depth+1)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("temporary observation JSON array is not closed")
		}
		return nil
	default:
		return errors.New("temporary observation JSON delimiter is invalid")
	}
}

func consumeJSONObject(decoder *json.Decoder, depth int) error {
	if depth > MaxJSONDepth {
		return errors.New("temporary observation JSON nesting exceeds the allowed depth")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("temporary observation JSON object key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate JSON object key %q", key)
		}
		seen[key] = struct{}{}
		if err := consumeJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("temporary observation JSON object is not closed")
	}
	return nil
}
