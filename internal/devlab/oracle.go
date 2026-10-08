package devlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var assertionPath = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:\.(?:[A-Za-z][A-Za-z0-9]*|[0-9]+))*$`)

func EvaluateAssertions(samples []map[string]any, specs []AssertionSpec) []AssertionResult {
	results := make([]AssertionResult, 0, len(specs))
	for _, spec := range specs {
		result := AssertionResult{Kind: spec.Kind, Path: spec.Path, Status: "failed"}
		values := make([]any, 0, len(samples))
		missing := false
		for _, sample := range samples {
			value, ok := valueAt(sample, spec.Path)
			if !ok {
				missing = true
				break
			}
			values = append(values, value)
		}
		switch spec.Kind {
		case "known":
			if !missing && allKnown(values) {
				result.Status = "passed"
			} else {
				result.Reason = "value_unknown"
			}
		case "non_empty":
			if !missing && allNonEmpty(values) {
				result.Status = "passed"
			} else {
				result.Reason = "value_empty"
			}
		case "stable":
			if !missing && len(values) > 0 && allEqual(values) {
				result.Status = "passed"
			} else {
				result.Reason = "value_changed"
			}
		case "equals":
			if !missing && len(values) > 0 && allExpected(values, spec.Expected) {
				result.Status = "passed"
			} else {
				result.Reason = "value_mismatch"
			}
		default:
			result.Reason = "unsupported_assertion"
		}
		if len(values) > 0 {
			result.Observed = values[len(values)-1]
		}
		results = append(results, result)
	}
	return results
}

func valueAt(root any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" || path == "." {
		return root, true
	}
	current := root
	for _, part := range strings.Split(strings.TrimPrefix(path, "."), ".") {
		switch typed := current.(type) {
		case map[string]any:
			current, _ = typed[part]
			if current == nil {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func allKnown(values []any) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value == nil || value == "unknown" {
			return false
		}
	}
	return true
}

func allNonEmpty(values []any) bool {
	if !allKnown(values) {
		return false
	}
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) == "" {
				return false
			}
		case []any:
			if len(typed) == 0 {
				return false
			}
		case map[string]any:
			if len(typed) == 0 {
				return false
			}
		}
	}
	return true
}

func allEqual(values []any) bool {
	for index := 1; index < len(values); index++ {
		if !reflect.DeepEqual(values[0], values[index]) {
			return false
		}
	}
	return true
}

func allExpected(values []any, expected any) bool {
	for _, value := range values {
		left, _ := json.Marshal(value)
		right, _ := json.Marshal(expected)
		if string(left) != string(right) {
			return false
		}
	}
	return true
}

func validateAssertions(specs []AssertionSpec) error {
	if len(specs) > 32 {
		return errors.New("too many assertions")
	}
	for _, spec := range specs {
		if len(spec.Path) > 256 || !assertionPath.MatchString(spec.Path) {
			return errors.New("assertion path is invalid")
		}
		switch spec.Kind {
		case "known", "non_empty", "stable":
			if spec.Expected != nil {
				return fmt.Errorf("%s assertion does not accept expected", spec.Kind)
			}
		case "equals":
			if spec.Expected == nil {
				return errors.New("equals assertion requires expected")
			}
		default:
			return fmt.Errorf("unsupported assertion %q", spec.Kind)
		}
	}
	return nil
}
