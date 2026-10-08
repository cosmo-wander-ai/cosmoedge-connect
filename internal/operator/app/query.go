package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/read"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

func (s *Service) Status(context.Context) string {
	maskedID, deviceType, connected := s.vault.ConnectedIdentity()
	if !connected {
		return "连接状态：尚未连接设备。\n下一步：打开 CosmoEdge 设备运营页面。\n"
	}
	return fmt.Sprintf("连接状态：已连接。\n设备：%s\n", strings.Trim(strings.TrimSpace(deviceType+" · "+maskedID), " ·"))
}

func (s *Service) Query(ctx context.Context, kind, window string) (string, error) {
	kind = strings.TrimSpace(kind)
	window = normalizeQueryWindow(window)
	if kind == "capabilities" {
		return "当前可查询：连接状态、设备脱敏身份、摄像头/视频通道数量、任务列表、任务启停与运行状态、今日/昨天/最近 1 小时/最近 24 小时告警摘要和最近明细。\n当前可操作：为一个已配置任务准备持久启用或停用、参数修改方案，以及新增一个 RTSP/RTSPS 网络视频源；所有写入都在本地页面核对并完成最后确认。\n", nil
	}
	if _, _, connected := s.vault.ConnectedIdentity(); !connected {
		return "本地设备运营当前未连接设备，或只读状态已经失效。\n下一步：打开 CosmoEdge 设备运营页面。\n", session.ErrNotConnected
	}
	intent := "manage_tasks"
	if kind == "overview" {
		intent = "home"
	} else if kind == "alarms" {
		intent = "inspect_alerts"
	} else if kind != "cameras" && kind != "tasks" && kind != "runtime" {
		return "不支持该只读查询。\n", errors.New("unsupported read query")
	}
	projection, _, err := s.reader.Present(ctx, intent, window)
	if err != nil {
		return projection.Conclusion + "\n", err
	}
	switch kind {
	case "overview":
		return overviewText(projection), nil
	case "cameras":
		return camerasText(projection), nil
	case "tasks":
		return tasksText(projection), nil
	case "runtime":
		return runtimeText(projection), nil
	default:
		return alarmsText(projection), nil
	}
}

func overviewText(projection read.Projection) string {
	var output strings.Builder
	fmt.Fprintf(&output, "连接状态：已连接。\n设备：%s\n", strings.Trim(strings.TrimSpace(projection.Device.Type+" · "+projection.Device.MaskedID), " ·"))
	if len(projection.OperationsSummaries) == 0 {
		output.WriteString("设备概况仍在刷新，摄像头、任务和今日告警数量暂不可用。\n")
		return output.String()
	}
	summary := projection.OperationsSummaries[0]
	fmt.Fprintf(&output, "设备概况：%d 路摄像头/视频通道，%d 个分析任务。\n", summary.CameraCount, summary.TaskCount)
	fmt.Fprintf(&output, "今日运行证据：运行 %d 个，停止 %d 个，未知 %d 个；结构化告警：%s。\n", summary.Running, summary.Stopped, summary.Unknown, summary.AlarmText)
	fmt.Fprintf(&output, "统计窗口：%s 至 %s（%s）。\n", summary.WindowStart, summary.WindowEnd, summary.Timezone)
	return output.String()
}

func camerasText(projection read.Projection) string {
	if len(projection.OperationsSummaries) == 0 {
		return "摄像头/视频通道目录仍在刷新，当前不能给出可靠数量。\n"
	}
	summary := projection.OperationsSummaries[0]
	names := map[string]bool{}
	for _, task := range projection.Read.Tasks {
		if task.CameraName != "" {
			names[task.CameraName] = true
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	text := fmt.Sprintf("当前接入 %d 路摄像头/视频通道。\n", summary.CameraCount)
	if len(ordered) > 0 {
		text += "已配置任务关联的摄像头：" + strings.Join(ordered, "、") + "。\n"
	}
	return text
}

func tasksText(projection read.Projection) string {
	if len(projection.Read.Tasks) == 0 {
		return "当前没有读取到可展示的分析任务，或任务目录仍在刷新。\n"
	}
	var output strings.Builder
	fmt.Fprintf(&output, "当前读取到 %d 个分析任务：\n", len(projection.Read.Tasks))
	for _, task := range projection.Read.Tasks {
		fmt.Fprintf(&output, "%d. %s；摄像头：%s；业务：%s；启停：%s；运行：%s。\n", task.Index, task.DisplayName, task.CameraName, task.AlgorithmName, task.EnabledState, task.RunningState)
	}
	return output.String()
}

func runtimeText(projection read.Projection) string {
	counts := map[string]int{"运行中": 0, "已停止": 0, "状态未知": 0}
	for _, task := range projection.Read.Tasks {
		counts[task.RunningState]++
	}
	var output strings.Builder
	fmt.Fprintf(&output, "当前任务运行状态：运行 %d 个，停止 %d 个，未知 %d 个。\n", counts["运行中"], counts["已停止"], counts["状态未知"])
	for _, task := range projection.Read.Tasks {
		fmt.Fprintf(&output, "- %s：%s，启停状态 %s，摄像头 %s。\n", task.DisplayName, task.RunningState, task.EnabledState, task.CameraName)
	}
	return output.String()
}

func alarmsText(projection read.Projection) string {
	if len(projection.OperationsSummaries) == 0 {
		return "告警摘要仍在刷新。\n"
	}
	summary := projection.OperationsSummaries[0]
	var output strings.Builder
	fmt.Fprintf(&output, "%s告警：%s；运行证据为运行 %d 个、停止 %d 个、未知 %d 个。\n", summary.Label, summary.AlarmText, summary.Running, summary.Stopped, summary.Unknown)
	fmt.Fprintf(&output, "统计窗口：%s 至 %s（%s），计数精度：%s。\n", summary.WindowStart, summary.WindowEnd, summary.Timezone, map[string]string{"exact": "精确", "lower_bound": "下限", "unknown": "未知"}[summary.AlarmAccuracy])
	for _, task := range summary.Tasks {
		fmt.Fprintf(&output, "- %s：%s，结构化告警 %s。\n", task.DisplayName, task.RunningState, countText(task.AlarmCount, task.AlarmAccuracy))
	}
	if len(summary.RecentAlarms) > 0 {
		output.WriteString("最近明细：\n")
		for _, alarm := range summary.RecentAlarms {
			fmt.Fprintf(&output, "- %s；任务：%s；摄像头：%s；业务：%s。\n", alarm.OccurredAt, alarm.TaskName, alarm.CameraName, alarm.AlgorithmName)
		}
	}
	return output.String()
}

func countText(count int, accuracy string) string {
	if accuracy == "exact" {
		return fmt.Sprintf("%d 条", count)
	}
	if accuracy == "lower_bound" {
		return fmt.Sprintf("至少 %d 条", count)
	}
	return "数量未知"
}

func normalizeQueryWindow(window string) string {
	switch strings.TrimSpace(window) {
	case "yesterday", "last_1h", "last_24h":
		return strings.TrimSpace(window)
	default:
		return "today"
	}
}
