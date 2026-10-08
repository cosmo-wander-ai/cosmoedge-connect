package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

func configurationDigest(config Configuration) (string, error) {
	if len(config.Document) == 0 || len(config.Document) > 1<<20 {
		return "", errors.New("deployment configuration is unavailable or too large")
	}
	var document map[string]any
	if json.Unmarshal(config.Document, &document) != nil || document == nil {
		return "", errors.New("deployment configuration is not an object")
	}
	// Parameter arrays are keyed sets in both supported native structures;
	// polygon point order and other arrays remain significant.
	if err := normalizeConfiguration(document); err != nil {
		return "", err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", errors.New("deployment configuration is invalid")
	}
	sum := sha256.Sum256(append(append(raw, 0), []byte(config.ScheduleDigest)...))
	return hex.EncodeToString(sum[:]), nil
}

func normalizeConfiguration(value any) error {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if key == "params" {
				if params, ok := child.([]any); ok {
					keys := map[string]bool{}
					for _, raw := range params {
						param, ok := raw.(map[string]any)
						if !ok {
							return errors.New("deployment parameter row is invalid")
						}
						key, ok := param["key"].(string)
						if !ok || key == "" || keys[key] {
							return errors.New("deployment parameter keys are incomplete or duplicated")
						}
						keys[key] = true
					}
					sort.Slice(params, func(i, j int) bool {
						return params[i].(map[string]any)["key"].(string) < params[j].(map[string]any)["key"].(string)
					})
				}
			}
			if err := normalizeConfiguration(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range current {
			if err := normalizeConfiguration(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func progressBetween(before, after Runtime, taskID string) ([]Progress, bool) {
	if !before.Known || !after.Known || !after.Active || before.TaskID != taskID || after.TaskID != taskID ||
		before.ObservedAt.IsZero() || !after.ObservedAt.After(before.ObservedAt) || len(before.Counters) == 0 || len(before.Counters) != len(after.Counters) {
		return nil, false
	}
	progress := make([]Progress, 0, len(before.Counters))
	advanced := true
	for id, first := range before.Counters {
		last, exists := after.Counters[id]
		if !exists || last < first {
			return nil, false // A reset or changed node set requires fresh samples.
		}
		if last == first {
			advanced = false
		}
		progress = append(progress, Progress{NodeID: id, Before: first, After: last})
	}
	sort.Slice(progress, func(i, j int) bool { return progress[i].NodeID < progress[j].NodeID })
	return progress, advanced
}

func digest(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(h[:])
}

func validID(id string) bool {
	return strings.TrimSpace(id) == id && id != "" && len(id) <= 256 && !strings.ContainsAny(id, "\x00\r\n")
}
