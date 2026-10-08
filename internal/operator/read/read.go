package read

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

type Source interface {
	Read(context.Context) (device.Snapshot, error)
	ObserveEvents(context.Context, []device.Task, device.EventWindow) (device.EventObservation, error)
	ConnectedIdentity() (maskedID, deviceType string, ok bool)
}

type Service struct {
	source Source
	now    func() time.Time
}

func New(source Source) *Service { return &Service{source: source, now: time.Now} }

type Projection struct {
	Schema                    string              `json:"schema"`
	State                     string              `json:"state"`
	View                      string              `json:"view"`
	Conclusion                string              `json:"conclusion"`
	Device                    Device              `json:"device"`
	Read                      ReadSurface         `json:"read"`
	Capabilities              Capabilities        `json:"capabilities"`
	Selection                 *Selection          `json:"selection,omitempty"`
	BusinessConfirmationToken string              `json:"businessConfirmationToken,omitempty"`
	Report                    *ActionReport       `json:"report,omitempty"`
	OperationsSummaries       []OperationsSummary `json:"operationsSummaries"`
	NextSteps                 []string            `json:"nextSteps"`
}

type ActionReport struct {
	BusinessConclusion string `json:"businessConclusion"`
	EvidenceStatus     string `json:"evidenceStatus"`
	Dispatches         int    `json:"dispatches"`
	DeviceWrites       int    `json:"deviceWrites"`
}

type Device struct {
	MaskedID string `json:"maskedId"`
	Type     string `json:"type"`
}

type ReadSurface struct {
	State       string `json:"state"`
	Conclusion  string `json:"conclusion"`
	ChoiceSetID string `json:"choiceSetId,omitempty"`
	Tasks       []Task `json:"tasks"`
}

type Task struct {
	Index         int    `json:"index"`
	DisplayName   string `json:"displayName"`
	CameraName    string `json:"cameraName"`
	AlgorithmName string `json:"algorithmName"`
	EnabledState  string `json:"enabledState"`
	RunningState  string `json:"runningState"`
}

type Selection struct {
	Status   string `json:"status"`
	Selected *Task  `json:"selected,omitempty"`
}

type Capabilities struct {
	CanPrepare bool `json:"canPrepare"`
	CanConfirm bool `json:"canConfirm"`
	CanCancel  bool `json:"canCancel"`
	CanReset   bool `json:"canReset"`
	CanUndo    bool `json:"canUndo"`
}

type OperationsSummary struct {
	Window        string           `json:"window"`
	Label         string           `json:"label"`
	Conclusion    string           `json:"conclusion"`
	WindowStart   string           `json:"windowStart"`
	WindowEnd     string           `json:"windowEnd"`
	Timezone      string           `json:"timezone"`
	CameraCount   int              `json:"cameraCount"`
	TaskCount     int              `json:"taskCount"`
	Running       int              `json:"running"`
	Stopped       int              `json:"stopped"`
	Unknown       int              `json:"unknown"`
	AlarmCount    int              `json:"alarmCount"`
	AlarmAccuracy string           `json:"alarmAccuracy"`
	AlarmText     string           `json:"alarmText"`
	Tasks         []OperationsTask `json:"tasks"`
	RecentAlarms  []Alarm          `json:"recentAlarms"`
	ObservedAt    time.Time        `json:"observedAt"`
}

type OperationsTask struct {
	DisplayName   string `json:"displayName"`
	CameraName    string `json:"cameraName"`
	AlgorithmName string `json:"algorithmName"`
	RunningState  string `json:"runningState"`
	AlarmCount    int    `json:"alarmCount"`
	AlarmAccuracy string `json:"alarmAccuracy"`
}

type Alarm struct {
	OccurredAt    string `json:"occurredAt,omitempty"`
	CameraName    string `json:"cameraName,omitempty"`
	TaskName      string `json:"taskName,omitempty"`
	AlgorithmName string `json:"algorithmName,omitempty"`
}

func (s *Service) Present(ctx context.Context, intent, window string) (Projection, device.Snapshot, error) {
	if s == nil || s.source == nil {
		return Disconnected(intent), device.Snapshot{}, session.ErrNotConnected
	}
	intent = normalizeIntent(intent)
	window = normalizeWindow(window)
	snapshot, err := s.source.Read(ctx)
	if err != nil {
		if errors.Is(err, session.ErrNotConnected) {
			return Disconnected(intent), device.Snapshot{}, err
		}
		return Failed(intent, s.source, err), device.Snapshot{}, err
	}
	projection := Projection{
		Schema: "cosmoedge.operator.v1", State: "ready", View: intent,
		Conclusion:   "设备事实已完成新鲜回读。",
		Device:       Device{MaskedID: maskIdentifier(snapshot.Identity.Serial), Type: snapshot.Identity.Type},
		Read:         ReadSurface{State: "ready", Conclusion: "设备只读事实已刷新。", Tasks: []Task{}},
		Capabilities: Capabilities{}, OperationsSummaries: []OperationsSummary{}, NextSteps: []string{},
	}
	if intent == "manage_tasks" {
		projection.Read.ChoiceSetID = snapshot.CatalogFingerprint()
		for index, task := range snapshot.Tasks {
			projection.Read.Tasks = append(projection.Read.Tasks, projectTask(index+1, task))
		}
	}
	if intent == "home" {
		for _, item := range []string{"today", "yesterday", "last_1h", "last_24h"} {
			projection.OperationsSummaries = append(projection.OperationsSummaries, s.summarize(ctx, snapshot, item))
		}
	} else {
		projection.OperationsSummaries = append(projection.OperationsSummaries, s.summarize(ctx, snapshot, window))
	}
	return projection, snapshot, nil
}

func Disconnected(intent string) Projection {
	return Projection{
		Schema: "cosmoedge.operator.v1", State: "disconnected", View: normalizeIntent(intent),
		Conclusion:          "尚未连接设备。",
		Read:                ReadSurface{State: "disconnected", Conclusion: "请先在本机页面连接设备。", Tasks: []Task{}},
		OperationsSummaries: []OperationsSummary{}, NextSteps: []string{"确认设备地址后输入账号和密码"},
	}
}

func Failed(intent string, source Source, err error) Projection {
	maskedID, deviceType, _ := source.ConnectedIdentity()
	state := "catalog_incomplete"
	conclusion := "设备只读事实暂不完整。"
	if errors.Is(err, session.ErrIdentityDrift) {
		state = "identity_changed"
		conclusion = "设备身份发生变化，已停止继续读取和授权。"
	}
	return Projection{
		Schema: "cosmoedge.operator.v1", State: "disconnected", View: normalizeIntent(intent), Conclusion: conclusion,
		Device:       Device{MaskedID: maskedID, Type: deviceType},
		Read:         ReadSurface{State: state, Conclusion: conclusion, Tasks: []Task{}},
		Capabilities: Capabilities{}, OperationsSummaries: []OperationsSummary{}, NextSteps: []string{"重新连接并核对设备身份"},
	}
}

func Selected(projection Projection, selected Task) Projection {
	projection.State = "target_selected"
	projection.Selection = &Selection{Status: "selected", Selected: &selected}
	projection.Capabilities.CanPrepare = true
	return projection
}

func Stale(projection Projection) Projection {
	projection.State = "target_unresolved"
	projection.Selection = &Selection{Status: "target_stale"}
	projection.Capabilities = Capabilities{}
	projection.Conclusion = "显示的任务目录已经变化，请刷新后重新选择。"
	return projection
}

func projectTask(index int, task device.Task) Task {
	enabled := "状态未知"
	if task.Enabled == 1 {
		enabled = "已启用"
	} else if task.Enabled == 0 {
		enabled = "已停用"
	}
	running := map[string]string{"running": "运行中", "stopped": "已停止"}[task.Running]
	if running == "" {
		running = "状态未知"
	}
	return Task{
		Index: index, DisplayName: task.DisplayName, CameraName: task.CameraName,
		AlgorithmName: task.AlgorithmName, EnabledState: enabled, RunningState: running,
	}
}

func (s *Service) summarize(ctx context.Context, snapshot device.Snapshot, window string) OperationsSummary {
	resolved := resolveWindow(window, s.now())
	events, eventErr := s.source.ObserveEvents(ctx, snapshot.Tasks, device.EventWindow{Start: resolved.start, End: resolved.end})
	summary := OperationsSummary{
		Window: window, Label: windowLabel(window), Conclusion: "运营摘要读取完成",
		WindowStart: resolved.start.In(resolved.location).Format("2006-01-02 15:04:05"),
		WindowEnd:   resolved.end.In(resolved.location).Format("2006-01-02 15:04:05"),
		Timezone:    timezoneLabel(resolved.location, resolved.end),
		CameraCount: len(snapshot.Cameras), TaskCount: len(snapshot.Tasks), AlarmAccuracy: "exact",
		Tasks: []OperationsTask{}, RecentAlarms: []Alarm{}, ObservedAt: snapshot.ObservedAt,
	}
	for _, task := range snapshot.Tasks {
		switch task.Running {
		case "running":
			summary.Running++
		case "stopped":
			summary.Stopped++
		default:
			summary.Unknown++
		}
		observed := events.ByTask[task.ID]
		accuracy := observed.Accuracy
		if accuracy == "" {
			accuracy = "unknown"
		}
		summary.AlarmCount += observed.Count
		summary.AlarmAccuracy = mergeAccuracy(summary.AlarmAccuracy, accuracy)
		summary.Tasks = append(summary.Tasks, OperationsTask{
			DisplayName: task.DisplayName, CameraName: task.CameraName, AlgorithmName: task.AlgorithmName,
			RunningState: task.Running, AlarmCount: observed.Count, AlarmAccuracy: accuracy,
		})
		for _, alarm := range observed.Events {
			summary.RecentAlarms = append(summary.RecentAlarms, Alarm{
				OccurredAt: alarm.OccurredAt, CameraName: alarm.CameraName,
				TaskName: alarm.TaskName, AlgorithmName: alarm.AlgorithmName,
			})
		}
	}
	if eventErr != nil {
		summary.AlarmAccuracy = "unknown"
	}
	switch summary.AlarmAccuracy {
	case "exact":
		summary.AlarmText = fmt.Sprintf("%d 条告警", summary.AlarmCount)
	case "lower_bound":
		summary.AlarmText = fmt.Sprintf("至少 %d 条告警", summary.AlarmCount)
		summary.Conclusion = "运营摘要已读取，部分信息暂不完整"
	default:
		summary.AlarmText = "告警数量暂不确定"
		summary.Conclusion = "运营摘要已读取，部分信息暂不完整"
	}
	sort.SliceStable(summary.RecentAlarms, func(i, j int) bool { return summary.RecentAlarms[i].OccurredAt > summary.RecentAlarms[j].OccurredAt })
	if len(summary.RecentAlarms) > 10 {
		summary.RecentAlarms = summary.RecentAlarms[:10]
	}
	return summary
}

type resolvedWindow struct {
	start, end time.Time
	location   *time.Location
}

func resolveWindow(kind string, now time.Time) resolvedWindow {
	location := time.Local
	end := now.In(location)
	var start time.Time
	switch normalizeWindow(kind) {
	case "last_1h":
		start = end.Add(-time.Hour)
	case "last_24h":
		start = end.Add(-24 * time.Hour)
	case "yesterday":
		year, month, day := end.Date()
		end = time.Date(year, month, day, 0, 0, 0, 0, location)
		start = end.AddDate(0, 0, -1)
	default:
		year, month, day := end.Date()
		start = time.Date(year, month, day, 0, 0, 0, 0, location)
	}
	return resolvedWindow{start: start, end: end, location: location}
}

func timezoneLabel(location *time.Location, at time.Time) string {
	name, offset := at.In(location).Zone()
	if name != "" {
		return name
	}
	return fmt.Sprintf("UTC%+03d:%02d", offset/3600, (offset%3600)/60)
}

func mergeAccuracy(current, next string) string {
	if current == "unknown" || next == "unknown" {
		return "unknown"
	}
	if current == "lower_bound" || next == "lower_bound" {
		return "lower_bound"
	}
	return "exact"
}

func normalizeIntent(value string) string {
	switch strings.TrimSpace(value) {
	case "manage_tasks", "inspect_runtime", "inspect_alerts", "manage_sources":
		return strings.TrimSpace(value)
	default:
		return "home"
	}
}

func normalizeWindow(value string) string {
	switch strings.TrimSpace(value) {
	case "today", "yesterday", "last_1h", "last_24h":
		return strings.TrimSpace(value)
	default:
		return "today"
	}
}

func windowLabel(value string) string {
	return map[string]string{"today": "今日", "yesterday": "昨天", "last_1h": "最近 1 小时", "last_24h": "最近 24 小时"}[normalizeWindow(value)]
}

func maskIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 4 {
		return "***"
	}
	return "***" + value[len(value)-4:]
}
