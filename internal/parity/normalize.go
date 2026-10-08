package parity

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

type NormalizedResult struct {
	Scenario       string `json:"scenario"`
	Class          string `json:"class"`
	State          string `json:"state"`
	View           string `json:"view,omitempty"`
	Conclusion     string `json:"conclusion"`
	EvidenceStatus string `json:"evidenceStatus,omitempty"`
	TaskName       string `json:"taskName,omitempty"`
	CameraName     string `json:"cameraName,omitempty"`
	AlgorithmName  string `json:"algorithmName,omitempty"`
	CanPrepare     bool   `json:"canPrepare"`
	CanConfirm     bool   `json:"canConfirm"`
	CanCancel      bool   `json:"canCancel"`
	CanUndo        bool   `json:"canUndo"`
	DeviceWrites   int    `json:"deviceWrites"`
	Dispatches     int    `json:"dispatches"`
}

func NormalizeTaskState(scenario string, object map[string]any, snapshot FixtureSnapshot) (NormalizedResult, error) {
	state := StringField(object, "state")
	resultClass := classifyState(state)
	if resultClass == "" {
		return NormalizedResult{}, fmt.Errorf("unrecognized ordinary state %q", state)
	}
	return NormalizedResult{
		Scenario: scenario, Class: resultClass, State: state,
		View: StringField(object, "view"), Conclusion: StringField(object, "conclusion"),
		EvidenceStatus: StringField(object, "report", "evidenceStatus"),
		TaskName:       StringField(object, "selection", "selected", "displayName"),
		CameraName:     StringField(object, "selection", "selected", "cameraName"),
		AlgorithmName:  StringField(object, "selection", "selected", "algorithmName"),
		CanPrepare:     BoolField(object, "capabilities", "canPrepare"),
		CanConfirm:     BoolField(object, "capabilities", "canConfirm"),
		CanCancel:      BoolField(object, "capabilities", "canCancel"),
		CanUndo:        BoolField(object, "capabilities", "canUndo"),
		DeviceWrites:   snapshot.TaskWrites, Dispatches: snapshot.TaskWrites,
	}, nil
}

func classifyState(state string) string {
	switch state {
	case "complete", "succeeded":
		return "completed"
	case "blocked", "cancelled", "expired", "recovery_required", "failed_known":
		return "blocked"
	case "outcome_unknown", "external_drift", "unverified":
		return "unknown"
	case "disconnected", "connecting", "ready", "target_unresolved", "proposal_ready", "awaiting_confirmation", "queued", "switching", "observing", "restoring", "evidence_pending", "awaiting_approval", "executing", "verifying", "reconciling", "editable":
		return "in_progress"
	default:
		return ""
	}
}

func ScanProtected(raw []byte, protected ...string) error {
	text := string(raw)
	for _, value := range protected {
		if value != "" && contains(text, value) {
			return fmt.Errorf("protected value appeared in ordinary surface")
		}
	}
	for _, forbidden := range []string{
		`"operationId"`, `"operationRevision"`, `"proposalFingerprint"`,
		`"sessionBinding"`, `"expectedDeviceSn"`, `"bearerToken"`,
		`"confirmationText"`,
	} {
		if contains(text, forbidden) {
			return fmt.Errorf("internal authority field %s appeared in ordinary surface", forbidden)
		}
	}
	return nil
}

func contains(text, value string) bool {
	for i := 0; i+len(value) <= len(text); i++ {
		if text[i:i+len(value)] == value {
			return true
		}
	}
	return false
}

func ScanTreeProtected(root string, protected ...string) error {
	matches, err := FilesContaining(root, protected...)
	if err != nil {
		return err
	}
	if len(matches) != 0 {
		return fmt.Errorf("protected value appeared in runtime file %s", matches[0])
	}
	return nil
}

func FilesContaining(root string, protected ...string) ([]string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range protected {
			if value != "" && bytes.Contains(raw, []byte(value)) {
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					return relErr
				}
				matches = append(matches, relative)
				break
			}
		}
		return nil
	})
	return matches, err
}
