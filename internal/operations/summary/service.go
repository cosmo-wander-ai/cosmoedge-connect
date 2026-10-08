package summary

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

var ErrInvalidRequest = errors.New("invalid summary request")

var (
	ErrTimeRangeMissing      = fmt.Errorf("%w: start and end are required", ErrInvalidRequest)
	ErrTimeRangeInvalidOrder = fmt.Errorf("%w: end must be after start", ErrInvalidRequest)
	ErrTimeRangeTooLong      = fmt.Errorf("%w: window exceeds 31 days", ErrInvalidRequest)
	ErrTimeZoneInvalid       = fmt.Errorf("%w: timeZone must name an explicit IANA zone", ErrInvalidRequest)
)

const (
	MaxWindow           = 31 * 24 * time.Hour
	defaultPageSize     = device.MaxEventPageSize
	defaultMaxPages     = 1000
	representativeLimit = 20
)

type Service struct {
	reader   EventReader
	pageSize int
	maxPages int
}

func New(reader EventReader) *Service {
	return &Service{reader: reader, pageSize: defaultPageSize, maxPages: defaultMaxPages}
}

// Summarize returns read failures as explicit coverage gaps alongside verified
// counts. Only invalid input or a missing reader returns an error. Device error
// strings are not projected because they can contain connection details.
func (s *Service) Summarize(ctx context.Context, request Request) (Result, error) {
	request, zone, err := normalizeRequest(request)
	if err != nil {
		return Result{}, err
	}
	if s == nil || s.reader == nil {
		return Result{}, errors.New("summary event reader is unavailable")
	}
	result := emptyResult(request, zone)
	seen := map[string]device.HistoricalEvent{}
	conflicts := map[string]bool{}
	pageHashes := map[[32]byte]bool{}
	pageSize, maxPages := s.pageSize, s.maxPages
	if pageSize <= 0 || maxPages <= 0 {
		return Result{}, errors.New("summary paging limits are invalid")
	}
	retrievalEnded, compromised := false, false
	addGap := func(code, detail string) {
		compromised = true
		for _, gap := range result.Coverage.Gaps {
			if gap.Code == code {
				return
			}
		}
		result.Coverage.Gaps = append(result.Coverage.Gaps, Gap{Code: code, Window: result.Window, Detail: detail})
	}
	for pageNumber := 1; pageNumber <= maxPages; pageNumber++ {
		if err := ctx.Err(); err != nil {
			addGap("read_interrupted", "读取被中断；尚未读取的事件数量和所属时段未知。")
			break
		}
		page, err := s.reader.ReadEventPage(ctx, device.EventPageRequest{
			Window: device.EventWindow{Start: request.Start, End: request.End},
			Page:   pageNumber, PageSize: pageSize, AlgorithmIDs: append([]string(nil), request.AlgorithmIDs...),
		})
		if err != nil {
			code := "event_page_unavailable"
			if ctx.Err() != nil {
				code = "read_interrupted"
			}
			addGap(code, "未能完整读取事件页；缺失记录可能位于请求范围内的任意时段。")
			break
		}
		if len(page.Events) > pageSize || (page.Total != nil && *page.Total < 0) {
			addGap("event_page_malformed", "设备事件页或总数不符合分页约定。")
			break
		}
		result.Coverage.PagesRead++
		result.Coverage.RowsRead += len(page.Events)
		if page.Total != nil {
			if result.Coverage.ReportedTotal != nil && *result.Coverage.ReportedTotal != *page.Total {
				addGap("total_changed", "分页期间设备报告的总数发生变化；本次读取没有一致快照保证。")
			}
			if result.Coverage.ReportedTotal == nil || *page.Total > *result.Coverage.ReportedTotal {
				total := *page.Total
				result.Coverage.ReportedTotal = &total
			}
		}
		for _, event := range page.Events {
			if !validEvent(event) {
				result.Coverage.InvalidRows++
				continue
			}
			if previous, exists := seen[event.ID]; exists {
				result.Coverage.Duplicates++
				if !sameFact(previous, event) {
					conflicts[event.ID] = true
				}
				continue
			}
			seen[event.ID] = event
		}
		if len(page.Events) > 0 {
			hash := pageHash(page.Events)
			if pageHashes[hash] {
				addGap("page_repeated", "设备重复返回同一事件页；停止读取以避免把分页循环当成完整记录。")
				break
			}
			pageHashes[hash] = true
		}
		if total := result.Coverage.ReportedTotal; total != nil {
			if result.Coverage.RowsRead > *total {
				addGap("total_inconsistent", "读取行数超过设备报告的总数，记录完整性无法确认。")
			}
			if result.Coverage.RowsRead >= *total {
				retrievalEnded = true
				break
			}
			if len(page.Events) == 0 {
				addGap("page_ended_early", "事件页提前结束，尚未达到设备报告的总数。")
				break
			}
		} else if len(page.Events) < pageSize {
			retrievalEnded = true
			break
		}
		if pageNumber == maxPages {
			addGap("page_limit_reached", "达到单次读取上限；可缩小时间范围后重新查询。")
		}
	}
	if result.Coverage.InvalidRows > 0 {
		addGap("invalid_event_rows", "部分记录缺少可靠事件 ID、时间或来源/算法归属，未计入统计。")
	}
	result.Coverage.ConflictingIDs = len(conflicts)
	if len(conflicts) > 0 {
		addGap("conflicting_event_ids", "相同事件 ID 对应不同时间或来源/算法，冲突记录未计入统计。")
	}
	filtered := make([]device.HistoricalEvent, 0, len(seen))
	for id, event := range seen {
		if conflicts[id] {
			continue
		}
		if event.OccurredAt.Before(request.Start) || !event.OccurredAt.Before(request.End) ||
			!selected(request.SourceIDs, event.SourceID) || !selected(request.AlgorithmIDs, event.AlgorithmID) {
			result.Coverage.ExcludedRows++
			continue
		}
		filtered = append(filtered, event)
	}
	// Deterministic output and representatives do not depend on page ordering.
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].OccurredAt.Equal(filtered[j].OccurredAt) {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].OccurredAt.After(filtered[j].OccurredAt)
	})
	projectCounts(&result, filtered, zone, request.SourceKinds)
	result.Coverage.RetrievalComplete = retrievalEnded && !compromised
	if result.Coverage.RetrievalComplete {
		result.SourceKindScope = "retained_window"
	}
	switch {
	case result.Coverage.RetrievalComplete:
		result.Coverage.Accuracy = "exact_retained"
	case result.Count > 0:
		result.Coverage.Accuracy = "lower_bound"
	default:
		result.Coverage.Accuracy = "unknown"
	}
	return result, nil
}

// ValidateRequest performs the same local validation as Summarize without a
// device read. The HTTP caller checks a future end against its own clock.
func ValidateRequest(request Request) error {
	_, _, err := normalizeRequest(request)
	return err
}

func normalizeRequest(request Request) (Request, *time.Location, error) {
	if request.Start.IsZero() || request.End.IsZero() {
		return Request{}, nil, ErrTimeRangeMissing
	}
	if !request.Start.Before(request.End) {
		return Request{}, nil, ErrTimeRangeInvalidOrder
	}
	if request.End.Sub(request.Start) > MaxWindow {
		return Request{}, nil, ErrTimeRangeTooLong
	}
	if request.TimeZone == "" {
		request.TimeZone = "UTC"
	}
	zone, err := time.LoadLocation(request.TimeZone)
	if err != nil || request.TimeZone == "Local" {
		return Request{}, nil, ErrTimeZoneInvalid
	}
	request.Start, request.End = request.Start.UTC(), request.End.UTC()
	if request.SourceIDs, err = normalizeIDs(request.SourceIDs); err != nil {
		return Request{}, nil, err
	}
	if request.AlgorithmIDs, err = normalizeIDs(request.AlgorithmIDs); err != nil {
		return Request{}, nil, err
	}
	if request.SourceKinds != nil {
		kinds := make(map[string]string, len(request.SourceKinds))
		for id, kind := range request.SourceKinds {
			kinds[id] = normalizedSourceKind(kind)
		}
		request.SourceKinds = kinds
	}
	return request, zone, nil
}

func normalizedSourceKind(kind string) string {
	switch kind {
	case "test_video", "network_camera", "usb_camera":
		return kind
	default:
		return "unknown"
	}
}

func normalizeIDs(ids []string) ([]string, error) {
	if len(ids) > 128 {
		return nil, fmt.Errorf("%w: at most 128 exact IDs per filter", ErrInvalidRequest)
	}
	unique := map[string]bool{}
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id || len(id) > 256 || strings.ContainsAny(id, "\x00\r\n") {
			return nil, fmt.Errorf("%w: filters require nonempty exact IDs", ErrInvalidRequest)
		}
		unique[id] = true
	}
	result := make([]string, 0, len(unique))
	for id := range unique {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func emptyResult(request Request, zone *time.Location) Result {
	window := Window{Start: request.Start, End: request.End}
	result := Result{
		Window: window, TimeZone: request.TimeZone, SourceIDs: request.SourceIDs, AlgorithmIDs: request.AlgorithmIDs,
		ByDay: []DailyCount{}, ByDaySource: []DaySourceCount{}, BySource: []Count{}, ByAlgorithm: []Count{}, BySourceAlgorithm: []SourceAlgorithmCount{},
		BySourceKind: []SourceKindCount{}, SourceKindScope: "retrieved_records", SourceKindBasis: "unavailable",
		RepresentativeEvents: []device.HistoricalEvent{},
		Coverage: Coverage{Accuracy: "unknown", HistoryCoverage: "unknown", Gaps: []Gap{{
			Code: "history_coverage_unknown", Window: window,
			Detail: "设备未提供本时段的留存起点、删除记录或在线历史，无法证明全时段连续覆盖。",
		}}},
		Notes: []string{
			"数量仅指请求范围内已读取且按事件 ID 去重的留存告警，不代表现实发生次数或算法准确率。",
			"零条记录不证明安全、无人、无事件或设备在线；测试视频记录不得表述为真实现场业务次数。来源类型本身不证明循环播放，也不能解释告警总量的原因。",
			"来源/算法名称来自历史事件；当前目录和任务启停状态不限制历史统计。",
			"来源类型按当前目录中的稳定来源 ID 分类；目录缺失或类型不明的历史记录仍计入 unknown，不据此推定事件发生时的来源类型。",
			"按来源类型汇总的条数是已读取、去重且符合筛选的告警数，来源数是这些记录涉及的不同来源数量；多数告警按条数判断，不能用来源数量替代。读取不完整时仅代表已读取记录。",
		},
	}
	if request.SourceKinds != nil {
		result.SourceKindBasis = "current_source_catalog"
	}
	localStart := request.Start.In(zone)
	day := time.Date(localStart.Year(), localStart.Month(), localStart.Day(), 0, 0, 0, 0, zone)
	for day.Before(request.End) {
		result.ByDay = append(result.ByDay, DailyCount{Date: day.Format("2006-01-02")})
		day = day.AddDate(0, 0, 1)
	}
	return result
}

func validEvent(event device.HistoricalEvent) bool {
	return strings.TrimSpace(event.ID) != "" && !event.OccurredAt.IsZero() &&
		strings.TrimSpace(event.SourceID) != "" && strings.TrimSpace(event.AlgorithmID) != ""
}

func selected(ids []string, id string) bool {
	if len(ids) == 0 {
		return true
	}
	i := sort.SearchStrings(ids, id)
	return i < len(ids) && ids[i] == id
}

func sameFact(a, b device.HistoricalEvent) bool {
	return a.OccurredAt.Equal(b.OccurredAt) && a.SourceID == b.SourceID && a.AlgorithmID == b.AlgorithmID
}

func pageHash(events []device.HistoricalEvent) [32]byte {
	hash := sha256.New()
	for _, event := range events {
		fmt.Fprintf(hash, "%q %q %q %q\n", event.ID, event.SourceID, event.AlgorithmID, event.OccurredAt.UTC().Format(time.RFC3339Nano))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func projectCounts(result *Result, events []device.HistoricalEvent, zone *time.Location, sourceKinds map[string]string) {
	result.Count = len(events)
	result.ShareBasis = ShareBasis{
		Scope: "selected_window_retrieved_records", Denominator: result.Count,
		NumeratorFields: map[string]string{
			"byDay": "count", "byDaySource": "count", "bySource": "count", "byAlgorithm": "count",
			"bySourceAlgorithm": "count", "bySourceKind": "retainedRecordCount",
		},
	}
	days, sources, algorithms := map[string]int{}, map[string]Count{}, map[string]Count{}
	type daySource struct{ date, sourceID string }
	daySources := map[daySource]int{}
	type pair struct{ sourceID, algorithmID string }
	pairs := map[pair]SourceAlgorithmCount{}
	for _, event := range events {
		date := event.OccurredAt.In(zone).Format("2006-01-02")
		days[date]++
		daySources[daySource{date, event.SourceID}]++
		source := sources[event.SourceID]
		source.ID, source.Count = event.SourceID, source.Count+1
		if source.Name == "" {
			source.Name = event.SourceName
		}
		sources[event.SourceID] = source
		algorithm := algorithms[event.AlgorithmID]
		algorithm.ID, algorithm.Count = event.AlgorithmID, algorithm.Count+1
		if algorithm.Name == "" {
			algorithm.Name = event.AlgorithmName
		}
		algorithms[event.AlgorithmID] = algorithm
		key := pair{event.SourceID, event.AlgorithmID}
		entry := pairs[key]
		entry.SourceID, entry.AlgorithmID, entry.Count = event.SourceID, event.AlgorithmID, entry.Count+1
		if entry.SourceName == "" {
			entry.SourceName = event.SourceName
		}
		if entry.AlgorithmName == "" {
			entry.AlgorithmName = event.AlgorithmName
		}
		pairs[key] = entry
	}
	for i := range result.ByDay {
		result.ByDay[i].Count = days[result.ByDay[i].Date]
		result.ByDay[i].SharePercent = sharePercent(result.ByDay[i].Count, result.Count)
	}
	// Include known zero-record sources without adding them to the historical
	// source/type totals. An explicit filter excludes all other catalog sources.
	gridSources := map[string]string{}
	for id, source := range sources {
		gridSources[id] = source.Name
	}
	if len(result.SourceIDs) > 0 {
		for _, id := range result.SourceIDs {
			if _, exists := gridSources[id]; !exists {
				gridSources[id] = ""
			}
		}
	} else {
		for id := range sourceKinds {
			if _, exists := gridSources[id]; !exists {
				gridSources[id] = ""
			}
		}
	}
	ids := make([]string, 0, len(gridSources))
	for id := range gridSources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, day := range result.ByDay {
		for _, id := range ids {
			count := daySources[daySource{day.Date, id}]
			result.ByDaySource = append(result.ByDaySource, DaySourceCount{
				Date: day.Date, SourceID: id, SourceName: gridSources[id], Count: count, SharePercent: sharePercent(count, result.Count),
			})
		}
	}
	kinds := map[string]SourceKindCount{}
	for _, source := range sources {
		source.SharePercent = sharePercent(source.Count, result.Count)
		result.BySource = append(result.BySource, source)
		kind := normalizedSourceKind(sourceKinds[source.ID])
		entry := kinds[kind]
		entry.SourceKind = kind
		entry.RetainedRecordCount += source.Count
		entry.SourceCount++
		kinds[kind] = entry
	}
	for _, kind := range kinds {
		kind.SharePercent = sharePercent(kind.RetainedRecordCount, result.Count)
		result.BySourceKind = append(result.BySourceKind, kind)
	}
	for _, algorithm := range algorithms {
		algorithm.SharePercent = sharePercent(algorithm.Count, result.Count)
		result.ByAlgorithm = append(result.ByAlgorithm, algorithm)
	}
	for _, entry := range pairs {
		entry.SharePercent = sharePercent(entry.Count, result.Count)
		result.BySourceAlgorithm = append(result.BySourceAlgorithm, entry)
	}
	sortCounts := func(counts []Count) {
		sort.Slice(counts, func(i, j int) bool {
			if counts[i].Count == counts[j].Count {
				return counts[i].ID < counts[j].ID
			}
			return counts[i].Count > counts[j].Count
		})
	}
	sortCounts(result.BySource)
	sortCounts(result.ByAlgorithm)
	sort.Slice(result.BySourceKind, func(i, j int) bool {
		a, b := result.BySourceKind[i], result.BySourceKind[j]
		if a.RetainedRecordCount != b.RetainedRecordCount {
			return a.RetainedRecordCount > b.RetainedRecordCount
		}
		return a.SourceKind < b.SourceKind
	})
	sort.Slice(result.BySourceAlgorithm, func(i, j int) bool {
		a, b := result.BySourceAlgorithm[i], result.BySourceAlgorithm[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		return a.AlgorithmID < b.AlgorithmID
	})
	if len(events) > representativeLimit {
		events = events[:representativeLimit]
	}
	result.RepresentativeEvents = append(result.RepresentativeEvents, events...)
}

func sharePercent(numerator, denominator int) *float64 {
	if denominator == 0 {
		return nil
	}
	value := math.Round(float64(numerator)*10000/float64(denominator)) / 100
	return &value
}
