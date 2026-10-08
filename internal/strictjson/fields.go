// Package strictjson provides small admission checks that complement Go's
// encoding/json decoder. In particular, encoding/json matches struct fields
// case-insensitively, while public JSON contracts require exact field names.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// ValidateExactFields rejects duplicate object keys and struct-field aliases.
// Object keys that bind to Go structs must exactly match their canonical JSON
// names; map and RawMessage keys remain application-defined and case-sensitive.
func ValidateExactFields(raw []byte, output any, maximumDepth int) error {
	if maximumDepth < 1 {
		return errors.New("strict JSON depth limit is invalid")
	}
	typeOfOutput := reflect.TypeOf(output)
	if typeOfOutput == nil || typeOfOutput.Kind() != reflect.Pointer || typeOfOutput.Elem().Kind() == reflect.Invalid {
		return errors.New("strict JSON output must be a typed pointer")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeValue(decoder, typeOfOutput.Elem(), 0, maximumDepth); err != nil {
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

func consumeValue(decoder *json.Decoder, expected reflect.Type, depth, maximumDepth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if depth >= maximumDepth {
		return errors.New("JSON nesting exceeds the allowed depth")
	}

	expected = indirectType(expected)
	switch delimiter {
	case '{':
		return consumeObject(decoder, expected, depth+1, maximumDepth)
	case '[':
		return consumeArray(decoder, expected, depth+1, maximumDepth)
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func consumeObject(decoder *json.Decoder, expected reflect.Type, depth, maximumDepth int) error {
	seen := make(map[string]struct{})
	fields, typedStruct := exactStructFields(expected)
	mapElement, typedMap := mapElementType(expected)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("JSON object key is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate JSON object key %q", key)
		}
		seen[key] = struct{}{}

		var childType reflect.Type
		switch {
		case typedStruct:
			var exists bool
			childType, exists = fields[key]
			if !exists {
				return fmt.Errorf("unknown field %q or non-canonical JSON field name", key)
			}
		case typedMap:
			childType = mapElement
		}
		if err := consumeValue(decoder, childType, depth, maximumDepth); err != nil {
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

func consumeArray(decoder *json.Decoder, expected reflect.Type, depth, maximumDepth int) error {
	var element reflect.Type
	if expected != nil && (expected.Kind() == reflect.Array || expected.Kind() == reflect.Slice) && expected != reflect.TypeOf(json.RawMessage{}) {
		element = expected.Elem()
	}
	for decoder.More() {
		if err := consumeValue(decoder, element, depth, maximumDepth); err != nil {
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
}

func exactStructFields(value reflect.Type) (map[string]reflect.Type, bool) {
	if value == nil || value.Kind() != reflect.Struct || customJSONType(value) {
		return nil, false
	}
	fields := make(map[string]reflect.Type)
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields, true
}

func mapElementType(value reflect.Type) (reflect.Type, bool) {
	if value == nil || value.Kind() != reflect.Map {
		return nil, false
	}
	return value.Elem(), true
}

func indirectType(value reflect.Type) reflect.Type {
	for value != nil && value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	return value
}

func customJSONType(value reflect.Type) bool {
	if value.Implements(jsonUnmarshalerType) {
		return true
	}
	return value.Kind() != reflect.Pointer && reflect.PointerTo(value).Implements(jsonUnmarshalerType)
}
