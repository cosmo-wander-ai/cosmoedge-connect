package parity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

func WriteNormalizedFile(path string, results []NormalizedResult) error {
	if path == "" {
		return errors.New("normalized result path is required")
	}
	copyOfResults := append([]NormalizedResult(nil), results...)
	sort.Slice(copyOfResults, func(i, j int) bool { return copyOfResults[i].Scenario < copyOfResults[j].Scenario })
	if _, err := indexNormalized(copyOfResults); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(copyOfResults, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func ReadNormalizedFile(path string) ([]NormalizedResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var results []NormalizedResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil, err
	}
	if _, err := indexNormalized(results); err != nil {
		return nil, err
	}
	return results, nil
}
