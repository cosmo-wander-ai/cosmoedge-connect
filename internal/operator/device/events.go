package device

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

// MaxEventPageSize bounds native historical event reads. The summary service
// shares this limit so its default request cannot exceed the reader contract.
const MaxEventPageSize = 5000

// EventPageReader is an optional read capability on the existing device
// connection. It neither creates a session nor depends on current task bindings.
type EventPageReader interface {
	ReadEventPage(context.Context, EventPageRequest) (EventPage, error)
}

type EventPageRequest struct {
	Window       EventWindow
	Page         int
	PageSize     int
	AlgorithmIDs []string
}

// HistoricalEvent contains only event facts; names are historical display
// labels, never selectors. Empty identity/time fields mark an unusable row.
// Missing rows must remain visible to callers through the page's row count.
type HistoricalEvent struct {
	ID            string    `json:"eventId"`
	OccurredAt    time.Time `json:"occurredAt"`
	SourceID      string    `json:"sourceId"`
	SourceName    string    `json:"sourceName,omitempty"`
	AlgorithmID   string    `json:"algorithmId"`
	AlgorithmName string    `json:"algorithmName,omitempty"`
}

type EventPage struct {
	Events []HistoricalEvent
	// Total is the device's total for this query, not the number of matching
	// events after client-side filtering or deduplication. Nil means unknown.
	Total *int
}

var _ EventPageReader = (*v1Client)(nil)

func (c *v1Client) ReadEventPage(ctx context.Context, request EventPageRequest) (EventPage, error) {
	if request.Window.Start.IsZero() || request.Window.End.IsZero() ||
		!request.Window.Start.Before(request.Window.End) || request.Page < 1 ||
		request.PageSize < 1 || request.PageSize > MaxEventPageSize || len(request.AlgorithmIDs) > 128 {
		return EventPage{}, errors.New("invalid event page request")
	}
	queryEnd := request.Window.End.UTC().Truncate(time.Millisecond)
	if queryEnd.Before(request.Window.End) {
		queryEnd = queryEnd.Add(time.Millisecond)
	}
	body := map[string]any{
		"pageNum": request.Page, "pageSize": request.PageSize,
		"timeBegin": request.Window.Start.UTC().UnixMilli(),
		"timeEnd":   queryEnd.UnixMilli(),
	}
	if len(request.AlgorithmIDs) > 0 {
		for _, id := range request.AlgorithmIDs {
			if strings.TrimSpace(id) == "" || len(id) > 256 {
				return EventPage{}, errors.New("invalid algorithm filter")
			}
		}
		body["algorithmCodes"] = append([]string(nil), request.AlgorithmIDs...)
	}
	// Source filtering is deliberately performed against stable IDs by the
	// summary use case: videoChannelName is ambiguous and cannot select deleted
	// or renamed sources reliably.
	response, err := c.client.QueryEventsWithBodyContext(ctx, body)
	if err != nil {
		return EventPage{}, err
	}
	result := EventPage{Events: []HistoricalEvent{}}
	if value := response["total"]; value != nil {
		total, ok := eventInteger(value)
		if !ok || total < 0 || total > int64(math.MaxInt) {
			return EventPage{}, errors.New("event total is malformed")
		}
		n := int(total)
		result.Total = &n
	}
	rows, ok := response["events"].([]any)
	// The adapter normalizes an absent or malformed rows field to a nil slice.
	// Only an explicit zero total establishes that such a response is empty.
	if !ok || (rows == nil && (result.Total == nil || *result.Total != 0)) {
		return EventPage{}, errors.New("event rows are unavailable")
	}
	if len(rows) > request.PageSize {
		return EventPage{}, errors.New("event page exceeds requested size")
	}
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		event := HistoricalEvent{
			ID:            eventString(row, "id", "eventId"),
			SourceID:      eventString(row, "videoChannelId", "channelId"),
			SourceName:    eventString(row, "videoChannelName", "channelName"),
			AlgorithmID:   eventString(row, "algorithmCode", "algorithmId"),
			AlgorithmName: eventString(row, "algorithmName"),
		}
		if timestamp, ok := eventInteger(row["timestamp"]); ok && timestamp > 0 && timestamp < 253402300800000 {
			event.OccurredAt = time.UnixMilli(timestamp).UTC()
		}
		// Preserve malformed rows as empty facts so the summary cannot silently
		// turn an incomplete response into an exact zero.
		result.Events = append(result.Events, event)
	}
	return result, nil
}

func eventString(row map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := row[key].(string)
		if ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func eventInteger(value any) (int64, bool) {
	switch n := value.(type) {
	case float64:
		// JSON integers beyond float64's exact range cannot be event evidence.
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Abs(n) > 9007199254740991 || n != math.Trunc(n) {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		parsed, err := n.Int64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}
