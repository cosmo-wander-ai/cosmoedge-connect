package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

// Remember field presence to reject conflicting selectors and empty/null lists.
// The legacy scalar's empty/null value still means all sources.
func (q *SummaryRequest) UnmarshalJSON(data []byte) error {
	type wireRequest SummaryRequest
	var wire wireRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*q = SummaryRequest(wire)
	for name := range fields {
		q.sourceNameProvided = q.sourceNameProvided || strings.EqualFold(name, "sourceName")
		q.sourceNamesProvided = q.sourceNamesProvided || strings.EqualFold(name, "sourceNames")
	}
	return nil
}

func (h *Handler) summarySourceNames(w http.ResponseWriter, q SummaryRequest) ([]string, bool) {
	single := q.sourceNameProvided || q.SourceName != ""
	multiple := q.sourceNamesProvided || q.SourceNames != nil
	if single && multiple {
		h.fail(w, http.StatusBadRequest, "source_filters_conflict", "请只提供一组机位名称。")
		return nil, false
	}
	if !single && !multiple {
		return nil, true
	}
	names := q.SourceNames
	if single {
		if strings.TrimSpace(q.SourceName) == "" {
			return nil, true
		}
		names = []string{q.SourceName}
	}
	if len(names) == 0 {
		h.fail(w, http.StatusBadRequest, "source_names_invalid", "请至少提供一个明确的机位名称。")
		return nil, false
	}
	trimmed := make([]string, len(names))
	for i, name := range names {
		trimmed[i] = strings.TrimSpace(name)
		if trimmed[i] == "" {
			h.fail(w, http.StatusBadRequest, "source_names_invalid", "机位名称不能为空，请补全要查询的机位。")
			return nil, false
		}
	}
	return trimmed, true
}

// Resolve the entire set before any event read. Source selection is independent
// of algorithm selection, so a source-only query keeps every algorithm there.
func (h *Handler) resolveSummarySources(w http.ResponseWriter, names []string, cameras []device.Camera) ([]string, string, bool) {
	var ids, canonicalNames []string
	seen := map[string]bool{}
	for _, name := range names {
		matches := map[string]device.Camera{}
		for _, camera := range cameras {
			if strings.EqualFold(name, camera.Name) {
				matches[camera.ID] = camera
			}
		}
		if len(matches) != 1 {
			h.fail(w, http.StatusConflict, "source_ambiguous_or_missing", "没有找到唯一对应的机位，请从当前机位名称中明确选择。")
			return nil, "", false
		}
		for id, camera := range matches {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
				canonicalNames = append(canonicalNames, camera.Name)
			}
		}
	}
	return ids, strings.Join(canonicalNames, "、"), true
}
