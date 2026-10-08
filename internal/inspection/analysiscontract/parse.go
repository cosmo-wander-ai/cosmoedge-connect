package analysiscontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

// ParseCandidate accepts exactly one bounded candidate JSON object. Envelope
// fields such as runId, media, analyzer, execution, or integrity are unknown
// fields here and are therefore rejected.
func ParseCandidate(raw []byte) (Candidate, error) {
	var candidate Candidate
	if err := decodeStrict(raw, &candidate); err != nil {
		return Candidate{}, fmt.Errorf("parse analysis candidate: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return Candidate{}, fmt.Errorf("validate analysis candidate: %w", err)
	}
	return candidate, nil
}

// ParseEnvelope parses and internally validates a complete trusted envelope.
// Call ValidateBindings before accepting an envelope received across a process
// boundary.
func ParseEnvelope(raw []byte) (Envelope, error) {
	var envelope Envelope
	if err := decodeStrict(raw, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("parse analysis envelope: %w", err)
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("validate analysis envelope: %w", err)
	}
	return envelope, nil
}

func decodeStrict(raw []byte, output any) error {
	if len(raw) == 0 || len(raw) > MaxJSONBytes {
		return fmt.Errorf("JSON size must be between 1 and %d bytes", MaxJSONBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
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
		return errors.New("JSON root must be an object")
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
		return errors.New("JSON null is not allowed")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if depth >= MaxJSONDepth {
		return errors.New("JSON nesting exceeds the allowed depth")
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
			return errors.New("JSON array is not closed")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func consumeJSONObject(decoder *json.Decoder, depth int) error {
	if depth > MaxJSONDepth {
		return errors.New("JSON nesting exceeds the allowed depth")
	}
	keys := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("JSON object key is invalid")
		}
		if _, exists := keys[key]; exists {
			return fmt.Errorf("duplicate JSON object key %q", key)
		}
		keys[key] = struct{}{}
		if err := consumeJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("JSON object is not closed")
	}
	return nil
}
