package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
)

func TestSummaryReportHeadlineKeepsFactsAndOriginalBytes(t *testing.T) {
	for _, complete := range []bool{true, false} {
		for _, count := range []int{0, 7} {
			result := summaryMessageResult(count, count)
			result.Coverage.RetrievalComplete = complete
			// Both positive peak dates are named; zero has no peak.
			result.ByDay = []summary.DailyCount{{Date: "2026-04-06", Count: count}, {Date: "2026-04-07", Count: count}}
			result.Count = 2 * count
			message := summaryUserMessage(result, "入口![数据](https://example.invalid/x)", "检测\n第二行")
			before, _ := json.Marshal(result)
			report := newSummaryReport(result, message, "入口![数据](https://example.invalid/x)", "检测\n第二行")
			digest := sha256.Sum256([]byte(message))
			if report.SizeBytes != len([]byte(message)) || report.SizeBytes == len([]rune(message)) || report.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("report must describe UTF-8 original bytes")
			}
			requireSummaryText(t, report.Headline, "2026-04-06 至 2026-04-08（北京时间）", fmt.Sprintf("%d 条", 2*count),
				summaryDisplayName("入口![数据](https://example.invalid/x)", ""), summaryDisplayName("检测\n第二行", ""))
			if count > 0 {
				requireSummaryText(t, report.Headline, fmt.Sprintf("2026-04-06、2026-04-07 并列最多，各 %d 条", count))
			}
			if strings.Contains(report.Headline, "最多") != (count > 0) ||
				strings.Contains(report.Headline, "数据尚未读全") == complete ||
				strings.Contains(report.Headline, "完整时段的排名仍无法确定") != (!complete && count > 0) ||
				strings.Contains(report.Headline, "没有留存告警，不能说明") != (complete && count == 0) ||
				strings.Contains(report.Headline, "列出项") || report.Filters["algorithmName"] != "检测\n第二行" {
				t.Fatalf("headline/filter boundary incorrect: %+v", report)
			}
			if !complete && strings.Contains(report.Headline, "留存告警共") {
				t.Fatal("partial headline claimed a whole-window total")
			}
			after, _ := json.Marshal(result)
			if string(before) != string(after) {
				t.Fatal("report changed statistical input")
			}
		}
	}
}

func TestSummaryHeadlineAnswersWindowGroupsWithoutInventingDailyComposition(t *testing.T) {
	result := summaryMessageResult(8, 5)
	result.BySource[0].Name, result.BySource[1].Name = "大厅", "入口"
	result.ByAlgorithm = []summary.Count{{ID: "private-a", Name: "人员聚集", Count: 7}, {ID: "private-b", Name: "未戴安全帽", Count: 6}}
	result.ByDay = []summary.DailyCount{{Date: "2026-04-06", Count: 6}, {Date: "2026-04-07", Count: 4}, {Date: "2026-04-08", Count: 3}}
	result.BySourceKind = []summary.SourceKindCount{
		{SourceKind: "network_camera", RetainedRecordCount: 8, SourceCount: 1},
		{SourceKind: "test_video", RetainedRecordCount: 5, SourceCount: 1},
	}
	before, _ := json.Marshal(result)
	headline := summaryHeadline(result, "", "")
	requireSummaryText(t, headline, "留存告警共 13 条", "2026-04-06 最多，为 6 条",
		"主要机位："+summaryDisplayName("大厅", "")+" 8 条；"+summaryDisplayName("入口", "")+" 5 条",
		"主要算法："+summaryDisplayName("人员聚集", "")+" 7 条；"+summaryDisplayName("未戴安全帽", "")+" 6 条",
		"其中 5 条来自当前目录标为测试视频的来源")
	for _, unsupported := range []string{"private-", "循环播放", "在线", "运行正常", "导致", "发生 13", "条数最多的日期之一"} {
		if strings.Contains(headline, unsupported) {
			t.Fatalf("headline contains an unsupported inference or technical detail %q: %s", unsupported, headline)
		}
	}
	after, _ := json.Marshal(result)
	if string(before) != string(after) {
		t.Fatal("headline mutated the full structured facts used for follow-ups")
	}
	// A fresh explicit-day query still has its own groups; the whole-window
	// leader above must not be reused to answer the composition of this day.
	day := summaryMessageResult(5, 1)
	day.Window.End = day.Window.Start.AddDate(0, 0, 1)
	day.BySource[0].Name, day.BySource[1].Name = "入口", "大厅"
	requireSummaryText(t, summaryHeadline(day, "", ""), "2026-04-06（北京时间）", "留存告警共 6 条",
		"主要机位："+summaryDisplayName("入口", "")+" 5 条；"+summaryDisplayName("大厅", "")+" 1 条")
}

func summaryMessageResult(counts ...int) summary.Result {
	start := time.Date(2026, 4, 5, 16, 0, 0, 0, time.UTC)
	result := summary.Result{Window: summary.Window{Start: start, End: start.AddDate(0, 0, 3)}, TimeZone: "Asia/Shanghai",
		Coverage:        summary.Coverage{RetrievalComplete: true, HistoryCoverage: "unknown"},
		SourceKindBasis: "current_source_catalog", SourceKindScope: "retained_window"}
	for i, count := range counts {
		result.Count += count
		result.BySourceAlgorithm = append(result.BySourceAlgorithm, summary.SourceAlgorithmCount{
			SourceID: fmt.Sprintf("private-source-%d", i), SourceName: fmt.Sprintf("机位 %d", i+1),
			AlgorithmID: "private-algorithm", AlgorithmName: "检测", Count: count})
		result.BySource = append(result.BySource, summary.Count{ID: fmt.Sprintf("private-source-%d", i), Name: fmt.Sprintf("机位 %d", i+1), Count: count})
	}
	result.ByDay = []summary.DailyCount{{Date: "2026-04-06", Count: result.Count}, {Date: "2026-04-07"}, {Date: "2026-04-08"}}
	if result.Count > 0 {
		result.ByAlgorithm = []summary.Count{{ID: "private-algorithm", Name: "检测", Count: result.Count}}
		result.BySourceKind = []summary.SourceKindCount{{SourceKind: "network_camera", RetainedRecordCount: result.Count, SourceCount: len(counts)}}
	}
	return result
}

func requireSummaryText(t *testing.T, message string, facts ...string) {
	t.Helper()
	for _, fact := range facts {
		if !strings.Contains(message, fact) {
			t.Fatalf("missing scoped fact %q:\n%s", fact, message)
		}
	}
}

func TestSummaryMessageUsesExactWindowAndSelections(t *testing.T) {
	result := summaryMessageResult(7)
	result.Window.Start = result.Window.Start.Add(12*time.Hour + 34*time.Minute + 56*time.Second + 789*time.Millisecond)
	result.Window.End = result.Window.Start.Add(13 * time.Hour)
	result.ByDay = []summary.DailyCount{{Date: "2026-04-06", Count: 5}, {Date: "2026-04-07", Count: 2}}
	message := summaryUserMessage(result, "机位 1", "检测")
	requireSummaryText(t, message, "2026-04-06 12:34:56.789 +08:00", "2026-04-07 01:34:56.789 +08:00",
		"Asia/Shanghai，起点计入、终点不计入", `筛选：机位\"机位 1\"；算法\"检测\"`,
		"共 7 条（已去重）", "2026-04-06 5 条；2026-04-07 2 条", "窗口与各自然日的交集", "为 5 条")
	requireSummaryText(t, summaryHeadline(result, "机位 1", "检测"), "2026-04-06 12:34:56.789 至 2026-04-07 01:34:56.789",
		"北京时间，不含结束时刻", "留存告警共 7 条", "2026-04-06 最多，为 5 条")
}

func TestSummaryMessageTruncationAccountsForUnlistedGroupsWithoutChangingFacts(t *testing.T) {
	result := summaryMessageResult(1000, 700, 500, 500, 450, 439, 373)
	before, _ := json.Marshal(result)
	message := summaryUserMessage(result, "", "")
	requireSummaryText(t, message, "共 3962 条（已去重）", "本次窗口内已读取记录", "列出 6 组", "列出项合计 3589 条；其余 1 组共 373 条")
	if strings.Contains(message, `机位\"机位 7\"`) || strings.Contains(message, "private-") {
		t.Fatalf("unlisted group or native reference leaked:\n%s", message)
	}
	after, _ := json.Marshal(result)
	if string(before) != string(after) || message != summaryUserMessage(result, "", "") {
		t.Fatal("message rendering mutated or nondeterministically projected the result")
	}
}

func TestSummaryMessagePartialAndZeroDoNotClaimHistoryOrUnseenPeak(t *testing.T) {
	for _, count := range []int{0, 4} {
		for _, complete := range []bool{false, true} {
			t.Run(fmt.Sprintf("count=%d/complete=%v", count, complete), func(t *testing.T) {
				result := summaryMessageResult()
				if count > 0 {
					result = summaryMessageResult(count)
				}
				result.Coverage.RetrievalComplete = complete
				message := summaryUserMessage(result, "", "")
				requireSummaryText(t, message, fmt.Sprintf("共 %d 条", count), "0 条仅表示未读取到", "留存与在线历史未知")
				peak := summaryPeak(result)
				if (peak == nil) != (count == 0) {
					t.Fatal("zero retained records acquired a peak")
				}
				if !complete {
					requireSummaryText(t, message, "此次数据未读全", "完整时段哪天最多尚无法确定")
					if strings.Contains(message, "已读完") || strings.Contains(message, "本窗口留存告警中") {
						t.Fatalf("partial retrieval was promoted:\n%s", message)
					}
					if count > 0 {
						requireSummaryText(t, message, "已读取记录中，2026-04-06")
						if peak.Scope != "retrieved_records" || peak.RetainedWindowKnown {
							t.Fatal("partial structured peak was promoted")
						}
					}
				}
			})
		}
	}
}

func TestSummaryMessageGroupsDoNotEstablishBatchesOrConfigurationHistory(t *testing.T) {
	result := summaryMessageResult(12, 12, 12, 12, 12, 12)
	result.ByDay = []summary.DailyCount{{Date: "2026-04-06", Count: 24}, {Date: "2026-04-07", Count: 24}, {Date: "2026-04-08", Count: 24}}
	result.BySourceKind = []summary.SourceKindCount{{SourceKind: "test_video", RetainedRecordCount: 72, SourceCount: 6}}
	message := summaryUserMessage(result, "", "")
	requireSummaryText(t, message, "列出项合计 72 条；其余 0 组共 0 条", "测试视频 72 条（6 个来源）",
		"来源数仅指这些记录涉及的来源，不是整个目录", "不能由条数推断播放或处理批次",
		"本次未提供历史启停、机位／算法增撤或原因证据", "不能将整个窗口的算法分布当作某日构成")
	for _, unsupported := range []string{"没有新增", "没有撤除", "一次性", "已停用", "运行正常", "分三批", "导致"} {
		if strings.Contains(message, unsupported) {
			t.Fatalf("invented history or causality %q:\n%s", unsupported, message)
		}
	}
}

func TestSummaryMessageUnknownNamesKindsAndMissingCatalogRemainExplicit(t *testing.T) {
	result := summaryMessageResult(5)
	result.BySourceAlgorithm[0].SourceName = ""
	result.BySourceAlgorithm[0].AlgorithmName = "名称\n\"仅作标签\""
	result.BySourceKind = []summary.SourceKindCount{{SourceKind: "unknown", RetainedRecordCount: 5, SourceCount: 1}}
	result.SourceKindBasis = "unavailable"
	message := summaryUserMessage(result, "", "")
	requireSummaryText(t, message, "筛选：机位不限；算法不限", "机位名称未提供", `算法\"名称\\n\\\"仅作标签\\\"\"`, "来源类型依据未提供", "类型未知 5 条（1 个来源）")
	if strings.Contains(message, "private-") || strings.Contains(message, "按当前目录分类") {
		t.Fatalf("missing names/catalog were invented:\n%s", message)
	}
}

func TestSummaryMessageNamesRemainCommonMarkLiteralData(t *testing.T) {
	for _, tc := range []struct {
		name, want string
	}{
		{"大厅（东侧）", `\"大厅（东侧）\"`},
		{"![仅名称字段](https://example.invalid/name-only.png)", `\"\!\[仅名称字段\]\(https\:\/\/example\.invalid\/name\-only\.png\)\"`},
		{"**总数999条**", `\"\*\*总数999条\*\*\"`},
		{"<script>alert(1)</script>", `\"\<script\>alert\(1\)\<\/script\>\"`},
		{"首行\n**第二行**", `\"首行\\n\*\*第二行\*\*\"`},
	} {
		if got := summaryDisplayName(tc.name, "名称未提供"); got != tc.want {
			t.Fatalf("name was not literal CommonMark data: name=%q got=%q want=%q", tc.name, got, tc.want)
		}
	}
	// These actual formatter outputs also serve as input to the independent
	// bundled-marked rendering check. Nothing here loads or fetches a name URL.
	for _, name := range []string{
		"大厅（东侧）",
		"![仅名称字段](https://example.invalid/name-only.png)",
		"[名称链接](https://example.invalid/name-only)",
		"**总数999条** _名称强调_ ~~删除样式~~",
		"<img src=x onerror=alert(1)><script>alert(1)</script>",
		"`名称代码` ```代码围栏```",
		"首行\n![第二行](https://example.invalid/n.png)\r\n# 标题\t末尾",
		"\\![转义组合](https://example.invalid/) &lt;strong&gt;名称&lt;/strong&gt;",
		"https://example.invalid/plain?x=1&y=2 user@example.invalid",
		"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
	} {
		result := summaryMessageResult(5)
		result.BySourceAlgorithm[0].SourceName = name
		result.BySourceAlgorithm[0].AlgorithmName = name
		message := summaryUserMessage(result, name, name)
		if strings.Count(message, summaryDisplayName(name, "")) != 4 {
			t.Fatalf("a filter or group name escaped a different path: %q", name)
		}
		plain := summaryUserMessage(summaryMessageResult(5), "机位 1", "检测")
		if strings.Count(message, "\n") != strings.Count(plain, "\n") {
			t.Fatalf("a name introduced a Markdown block boundary: %q", name)
		}
		requireSummaryText(t, message, "共 5 条（已去重）", "列出项合计 5 条；其余 0 组共 0 条", "2026-04-06 5 条")
		encoded, err := json.Marshal(map[string]string{"name": name, "visibleName": strconv.Quote(name), "message": message})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("MARKDOWN_NAME_CASE %s", encoded)
	}
}
