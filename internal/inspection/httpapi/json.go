package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

var (
	errBodyTooLarge       = errors.New("inspection HTTP body is too large")
	errUnsupportedMedia   = errors.New("inspection HTTP content type is unsupported")
	errMalformedJSON      = errors.New("inspection HTTP JSON is malformed")
	publicRefPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	forbiddenFieldPattern = regexp.MustCompile(`(?i)"(?:tenantId|siteId|channelId|executionPlan|cameraHandle|cameraId|deviceId|nativeId|sourceId|sourceBindings?|sourceHandle|sourceRevision|sourceFingerprint|sourceCatalogFingerprint|prompt|rawPrompt|rawModelOutput|facts|modelVersion|adapterVersion|endpoint|deviceUrl|path|url|password|credential|secret|token|cookie|authorization|imageBase64|videoBase64)"\s*:`)
	forbiddenValuePattern = regexp.MustCompile(`(?i)(?:https?|rtsps?|file)://|data:(?:image|video)/[A-Za-z0-9.+-]+;base64,|"[A-Za-z0-9+/]{256,}={0,2}"`)
)

func decodeRequiredJSON(w http.ResponseWriter, r *http.Request, output any) error {
	raw, err := readBoundedBody(w, r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return errMalformedJSON
	}
	if err := requireJSONContentType(r); err != nil {
		return err
	}
	return decodeStrictJSON(raw, output)
}

func decodeOptionalEmptyObject(w http.ResponseWriter, r *http.Request) error {
	raw, err := readBoundedBody(w, r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := requireJSONContentType(r); err != nil {
		return err
	}
	var input struct{}
	return decodeStrictJSON(raw, &input)
}

func readBoundedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	limited := http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	raw, err := io.ReadAll(limited)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, errBodyTooLarge
		}
		return nil, errMalformedJSON
	}
	return raw, nil
}

func requireJSONContentType(r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMedia
	}
	return nil
}

func decodeStrictJSON(raw []byte, output any) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return errMalformedJSON
	}
	if err := strictjson.ValidateExactFields(raw, output, maximumJSONDepth); err != nil {
		return errMalformedJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errMalformedJSON
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errMalformedJSON
	}
	return nil
}

const maximumJSONDepth = 16

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errMalformedJSON
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if depth >= maximumJSONDepth {
		return errMalformedJSON
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errMalformedJSON
			}
			if _, duplicated := seen[key]; duplicated {
				return errMalformedJSON
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errMalformedJSON
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errMalformedJSON
		}
	default:
		return errMalformedJSON
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBodyTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
	case errors.Is(err, errUnsupportedMedia):
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "content type must be application/json")
	default:
		writeError(w, http.StatusBadRequest, "invalid_json", "request JSON is invalid")
	}
}

// MarshalPublicJSON prevents protected fields and values from entering either
// HTTP responses or agent-facing process output.
func MarshalPublicJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if forbiddenFieldPattern.Match(raw) || forbiddenValuePattern.Match(raw) {
		return nil, errors.New("inspection public response contains protected data")
	}
	return raw, nil
}

func writePublicJSON(w http.ResponseWriter, status int, value any) error {
	raw, err := MarshalPublicJSON(value)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, err = w.Write(append(raw, '\n'))
	return err
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	raw, _ := json.Marshal(struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}

func writeInteractionRequired(w http.ResponseWriter, interaction InteractionRequired) {
	payload := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		InteractionRequired InteractionRequired `json:"interactionRequired"`
	}{InteractionRequired: interaction}
	payload.Error.Code = "interaction_required"
	payload.Error.Message = "local interaction is required"
	if err := writePublicJSON(w, http.StatusConflict, payload); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func validPublicRef(value string) bool {
	return value == strings.TrimSpace(value) && publicRefPattern.MatchString(value)
}
