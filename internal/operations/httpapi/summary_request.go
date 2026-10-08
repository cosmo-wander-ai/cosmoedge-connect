package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
)

// Check time before touching the connection or resolving source names. Return
// the requested range unchanged; a suggested end is never applied implicitly.
func (h *Handler) validateSummaryTime(w http.ResponseWriter, q SummaryRequest) bool {
	zone := q.TimeZone
	if zone == "" {
		zone = "UTC"
	}
	response := map[string]any{
		"ok":              false,
		"requestedWindow": map[string]any{"start": q.Start, "end": q.End, "timeZone": zone},
	}
	err := summary.ValidateRequest(summary.Request{Start: q.Start, End: q.End, TimeZone: zone})
	code, message := "", ""
	switch {
	case errors.Is(err, summary.ErrTimeRangeMissing):
		code, message = "time_range_missing", "请提供查询的开始时间和结束时间。"
	case errors.Is(err, summary.ErrTimeRangeInvalidOrder):
		code, message = "time_range_invalid_order", "结束时间必须晚于开始时间，请检查这两个时间。"
	case errors.Is(err, summary.ErrTimeRangeTooLong):
		code, message = "time_range_too_long", "单次查询时段不能超过 31 天，请缩短起止时间之间的跨度。"
	case errors.Is(err, summary.ErrTimeZoneInvalid):
		code, message = "time_zone_invalid", "时区无效，请使用明确的时区名称，例如 Asia/Shanghai 或 UTC。"
	case err != nil:
		code, message = "invalid_summary", "查询参数无效，请检查起止时间和时区。"
	default:
		now := h.config.Now().UTC()
		if q.End.After(now) {
			location, _ := time.LoadLocation(zone) // Already validated above.
			availableEnd := now.In(location)
			code = "time_range_future_end"
			message = "结束时间晚于当前时间；如需查到现在，可将结束时间设为 " + availableEnd.Format(time.RFC3339Nano) + "。"
			if !q.Start.Before(now) {
				message = "查询的开始时间尚未到达，请选择当前时间（" + availableEnd.Format(time.RFC3339Nano) + "）之前的查询时段。"
			}
			response["serverTime"], response["availableEnd"] = now, availableEnd
		}
	}
	if code == "" {
		return true
	}
	response["code"], response["userMessage"] = code, message
	h.reply(w, http.StatusBadRequest, response)
	return false
}
