package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
)

const summaryGroupDisplayLimit = 6

// The report is exactly UserMessage's UTF-8 bytes, with no client reformatting.
// Candidate identity is attached to this response, not inferred from an earlier
// version request which could have preceded a service replacement.
type summaryReport struct {
	SchemaVersion int               `json:"schemaVersion"`
	ContentType   string            `json:"contentType"`
	SHA256        string            `json:"sha256"`
	SizeBytes     int               `json:"sizeBytes"`
	Candidate     buildinfo.Info    `json:"candidate"`
	Headline      string            `json:"headline"`
	Filters       map[string]string `json:"filters"`
}

func newSummaryReport(result summary.Result, message, sourceName, algorithmName string) summaryReport {
	digest := sha256.Sum256([]byte(message))
	return summaryReport{SchemaVersion: 1, ContentType: "text/markdown; charset=utf-8",
		SHA256: hex.EncodeToString(digest[:]), SizeBytes: len([]byte(message)), Candidate: buildinfo.Current(),
		Headline: summaryHeadline(result, sourceName, algorithmName),
		Filters:  map[string]string{"sourceName": sourceName, "algorithmName": algorithmName}}
}

// summaryHeadline is a conversational view of the already counted result. The
// full report remains byte-for-byte UserMessage, while structured groupings are
// available for follow-up questions beyond this short overview.
func summaryHeadline(result summary.Result, sourceName, algorithmName string) string {
	zone, err := time.LoadLocation(result.TimeZone)
	if err != nil {
		return "统计结果的时区无法确认，暂时不能可靠表述查询范围。"
	}
	start, end := result.Window.Start.In(zone), result.Window.End.In(zone)
	zoneName := result.TimeZone
	if zoneName == "Asia/Shanghai" {
		zoneName = "北京时间"
	}
	const timestamp = "2006-01-02 15:04:05.999999999"
	window := fmt.Sprintf("%s 至 %s（%s，不含结束时刻）", start.Format(timestamp), end.Format(timestamp), zoneName)
	if start.Equal(time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, zone)) &&
		end.Equal(time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, zone)) {
		lastDay := end.AddDate(0, 0, -1)
		window = start.Format("2006-01-02")
		if !start.Equal(lastDay) {
			window += " 至 " + lastDay.Format("2006-01-02")
		}
		window += "（" + zoneName + "）"
	}
	filters := []string{}
	if sourceName != "" {
		filters = append(filters, "机位"+summaryDisplayName(sourceName, ""))
	}
	if algorithmName != "" {
		filters = append(filters, "算法"+summaryDisplayName(algorithmName, ""))
	}
	if len(filters) > 0 {
		window += "，" + strings.Join(filters, "、")
	}
	lines := []string{fmt.Sprintf("%s，留存告警共 %d 条。", window, result.Count)}
	if !result.Coverage.RetrievalComplete {
		lines[0] = fmt.Sprintf("%s，已读到 %d 条留存告警，数据尚未读全。", window, result.Count)
	}
	if peak := summaryPeak(result); peak != nil {
		dates := []string{}
		for _, day := range result.ByDay {
			if day.Count == peak.Count {
				dates = append(dates, day.Date)
			}
		}
		peakText := fmt.Sprintf("%s 最多，为 %d 条。", peak.Date, peak.Count)
		if len(dates) > 1 {
			listed := strings.Join(dates[:min(3, len(dates))], "、")
			if len(dates) > 3 {
				listed += fmt.Sprintf("等 %d 天", len(dates))
			}
			peakText = fmt.Sprintf("%s 并列最多，各 %d 条。", listed, peak.Count)
		}
		if !result.Coverage.RetrievalComplete {
			peakText = "已读取记录中，" + peakText + "完整时段的排名仍无法确定。"
		}
		lines = append(lines, peakText)
	}
	for _, group := range []struct {
		label  string
		counts []summary.Count
	}{{"主要机位", result.BySource}, {"主要算法", result.ByAlgorithm}} {
		parts := []string{}
		for _, item := range group.counts[:min(3, len(group.counts))] {
			if item.Count > 0 {
				parts = append(parts, fmt.Sprintf("%s %d 条", summaryDisplayName(item.Name, "名称未提供"), item.Count))
			}
		}
		if len(parts) > 0 {
			lines = append(lines, group.label+"："+strings.Join(parts, "；")+"。")
		}
	}
	for _, kind := range result.BySourceKind {
		if kind.SourceKind == "test_video" && kind.RetainedRecordCount > 0 {
			basis := "标为测试视频的来源"
			if result.SourceKindBasis == "current_source_catalog" {
				basis = "当前目录标为测试视频的来源"
			}
			lines = append(lines, fmt.Sprintf("其中 %d 条来自%s。", kind.RetainedRecordCount, basis))
		}
	}
	if result.Count == 0 && result.Coverage.RetrievalComplete {
		lines = append(lines, "没有留存告警，不能说明当时一直正常或没有事件。")
	}
	return strings.Join(lines, "\n")
}

func summaryPeakMessage(result summary.Result) string {
	if peak := summaryPeak(result); peak != nil {
		prefix := "本窗口留存告警中"
		if !result.Coverage.RetrievalComplete {
			prefix = "已读取记录中"
		}
		return fmt.Sprintf("%s，%s 是条数最多的日期之一，为 %d 条。", prefix, peak.Date, peak.Count)
	}
	return ""
}

type summaryPeakFact struct {
	Date                string `json:"date"`
	Count               int    `json:"count"`
	Scope               string `json:"scope"`
	RetainedWindowKnown bool   `json:"retainedWindowKnown"`
}

func summaryPeak(result summary.Result) *summaryPeakFact {
	best := summary.DailyCount{}
	for _, day := range result.ByDay {
		if day.Count > best.Count {
			best = day
		}
	}
	if best.Count == 0 {
		return nil
	}
	scope := "retrieved_records"
	if result.Coverage.RetrievalComplete {
		scope = "retained_window"
	}
	return &summaryPeakFact{Date: best.Date, Count: best.Count, Scope: scope, RetainedWindowKnown: result.Coverage.RetrievalComplete}
}

// summaryUserMessage renders only this result's facts. It neither joins daily
// totals to whole-window groups nor uses current task state as historical evidence.
// Selection names come from the handler's unique catalog matches; native IDs are
// never used as display fallbacks. The structured result remains unchanged.
func summaryUserMessage(result summary.Result, sourceName, algorithmName string) string {
	zone, err := time.LoadLocation(result.TimeZone)
	if err != nil {
		return "统计结果的时区无法确认，暂时不能可靠表述查询范围。"
	}
	const timestamp = "2006-01-02 15:04:05.999999999 -07:00"
	lines := []string{fmt.Sprintf("统计范围：%s 至 %s（%s，起点计入、终点不计入）。筛选：机位%s；算法%s。",
		result.Window.Start.In(zone).Format(timestamp), result.Window.End.In(zone).Format(timestamp), result.TimeZone,
		summaryDisplayName(sourceName, "不限"), summaryDisplayName(algorithmName, "不限"))}
	if result.Coverage.RetrievalComplete {
		lines = append(lines, fmt.Sprintf("已读完设备返回的本窗口留存告警，共 %d 条（已去重）。", result.Count))
	} else {
		lines = append(lines, fmt.Sprintf("此次数据未读全；当前已读取并去重的留存告警共 %d 条。", result.Count))
	}
	if len(result.ByDay) > 0 {
		parts := make([]string, 0, len(result.ByDay))
		for _, day := range result.ByDay {
			parts = append(parts, fmt.Sprintf("%s %d 条", day.Date, day.Count))
		}
		lines = append(lines, "已读取记录按本次窗口与各自然日的交集计数："+strings.Join(parts, "；")+"。0 条仅表示未读取到该日符合条件的留存告警。")
	}
	if peak := summaryPeakMessage(result); peak != "" {
		lines = append(lines, peak)
	}
	if !result.Coverage.RetrievalComplete {
		lines = append(lines, "完整时段哪天最多尚无法确定。")
	}
	if len(result.ByDaySource) > 0 {
		lines = append(lines, "机位逐日计数（本次窗口内已读取的留存告警）：")
		if !result.Coverage.RetrievalComplete {
			lines = append(lines, "数据未读全，表中 0 仅表示本次尚未读到，不能确认该日没有留存记录。")
		}
		lines = append(lines, "", "| 日期 | 机位 | 已读告警条数 |", "| --- | --- | ---: |")
		for _, group := range result.ByDaySource {
			lines = append(lines, fmt.Sprintf("| %s | %s | %d |", group.Date, summaryDisplayName(group.SourceName, "名称未提供"), group.Count))
		}
		lines = append(lines, "")
	}
	if len(result.BySourceAlgorithm) > 0 {
		shown := min(len(result.BySourceAlgorithm), summaryGroupDisplayLimit)
		parts, subtotal := make([]string, 0, shown), 0
		for _, group := range result.BySourceAlgorithm[:shown] {
			parts = append(parts, fmt.Sprintf("机位%s／算法%s %d 条", summaryDisplayName(group.SourceName, "名称未提供"), summaryDisplayName(group.AlgorithmName, "名称未提供"), group.Count))
			subtotal += group.Count
		}
		lines = append(lines, fmt.Sprintf("本次窗口内已读取记录的机位／算法分布（列出 %d 组）：%s。列出项合计 %d 条；其余 %d 组共 %d 条。",
			shown, strings.Join(parts, "；"), subtotal, len(result.BySourceAlgorithm)-shown, result.Count-subtotal))
	}
	if len(result.BySourceKind) > 0 {
		parts := make([]string, 0, len(result.BySourceKind))
		for _, kind := range result.BySourceKind {
			label := "类型未知"
			switch kind.SourceKind {
			case "test_video":
				label = "测试视频"
			case "network_camera":
				label = "网络摄像头"
			case "usb_camera":
				label = "USB 摄像头"
			}
			parts = append(parts, fmt.Sprintf("%s %d 条（%d 个来源）", label, kind.RetainedRecordCount, kind.SourceCount))
		}
		basis := "来源类型依据未提供，已读取记录中："
		if result.SourceKindBasis == "current_source_catalog" {
			basis = "按当前目录分类，已读取记录中："
		}
		lines = append(lines, basis+strings.Join(parts, "；")+"。来源数仅指这些记录涉及的来源，不是整个目录；来源数不等于告警条数。")
	}
	lines = append(lines,
		"机位／算法分布仅适用于本次窗口；未提供逐日与算法的联合分组，不能将整个窗口的算法分布当作某日构成。",
		"这些是留存告警条数，不是真实发生次数。来源类型不证明循环播放或告警数量的原因，也不能由条数推断播放或处理批次。",
		"本次未提供历史启停、机位／算法增撤或原因证据；留存与在线历史未知，不能据此判断连续覆盖或安全状况。")
	return strings.Join(lines, "\n")
}

func summaryDisplayName(name, fallback string) string {
	if name == "" {
		return fallback
	}
	// Quote controls first, then escape every CommonMark ASCII punctuation
	// character. Names remain literal text even when the host renders Markdown;
	// this also protects the backslashes introduced by Quote from reinterpretation.
	var literal strings.Builder
	for _, r := range strconv.Quote(name) {
		if r >= '!' && r <= '/' || r >= ':' && r <= '@' || r >= '[' && r <= '`' || r >= '{' && r <= '~' {
			literal.WriteByte('\\')
		}
		literal.WriteRune(r)
	}
	return literal.String()
}
