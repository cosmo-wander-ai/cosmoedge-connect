package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
)

// Client is the narrow V1 boundary used by the replacement ordinary path.
// Write methods are added here only when an Action Kernel action needs them.
type Client interface {
	Login(context.Context) error
	Read(context.Context) (Snapshot, error)
	ObserveEvents(context.Context, []Task, EventWindow) EventObservation
}

type ActionClient interface {
	Client
	SwitchTask(context.Context, Task, int) error
	ReadTaskParameters(context.Context, Task) ([]ParameterField, error)
	UpdateTaskParameters(context.Context, Task, []ParameterField) error
	AddCameraSource(context.Context, string, []byte) error
}

// InspectionClient is the closed typed CosmoEdge surface used by the live
// inspection bridge. It deliberately exposes neither the generic V1 client
// nor connection, credential, token, endpoint, or arbitrary-route access.
type InspectionClient interface {
	Client
	GetCameraPictureContext(context.Context, string) (adapter.CameraPicture, error)
	DownloadFreshCameraPictureJPEG(context.Context, adapter.CameraPicture, int64) (adapter.InspectionJPEG, error)
	QueryPictureAlgorithmsContext(context.Context, int, int) (adapter.PictureAlgorithmPage, error)
	QueryAlgorithmLayoutDetailContext(context.Context, string) (adapter.AlgorithmLayoutDetail, error)
	CreatePictureTaskContext(context.Context, adapter.PictureTaskCreateRequest) error
	DetectPictureTaskContext(context.Context, adapter.PictureTaskDetectRequest) (adapter.PictureTaskDetectResult, error)
	CancelPictureTaskContext(context.Context, adapter.PictureTaskCancelRequest) error
}

type ActionConnection struct {
	Client              ActionClient
	Serial              string
	EndpointFingerprint string
}

type Factory func(endpoint, username, password string) Client

func NewV1Client(endpoint, username, password string) Client {
	client := adapter.NewClient(endpoint, username, password)
	if mediaOrigin := cosmoEdgeMediaOrigin(endpoint); mediaOrigin != "" {
		client.SetImageBaseURL(mediaOrigin)
	}
	return &v1Client{client: client}
}

// cosmoEdgeMediaOrigin derives the device's static Web origin from its API
// endpoint. The V1 API normally listens on a management port, while relative
// /web/... capture references are served by the device's standard HTTP(S)
// origin. Keeping this binding in the concrete device client preserves the
// adapter's strict same-origin/path checks without sending a capture request to
// the API listener.
func cosmoEdgeMediaOrigin(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || strings.Trim(parsed.EscapedPath(), "/") != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil && strings.Contains(ip.String(), ":") {
		host = "[" + ip.String() + "]"
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: host}).String()
}

type Identity struct {
	Serial string
	Type   string
}

type Health struct {
	CPUPercent *float64
	ObservedAt time.Time
}

type Camera struct {
	ID                string
	Name              string
	SourceFingerprint string
	SourceKind        string
}

type ParameterField struct {
	Key   string
	Value string
}

type Task struct {
	ID             string
	ChannelID      string
	AlgorithmID    string
	DisplayName    string
	CameraName     string
	AlgorithmName  string
	Enabled        int
	Running        string
	SwitchVerified bool
}

type Alarm struct {
	OccurredAt    string
	CameraName    string
	TaskName      string
	AlgorithmName string
}

type EventWindow struct {
	Start time.Time
	End   time.Time
}

type TaskEventObservation struct {
	Count    int
	Accuracy string
	Complete bool
	Reason   string
	Events   []Alarm
}

type EventObservation struct {
	ByTask map[string]TaskEventObservation
}

type Snapshot struct {
	Identity   Identity
	Health     Health
	Cameras    []Camera
	Tasks      []Task
	ObservedAt time.Time
}

func (s Snapshot) CatalogFingerprint() string {
	parts := make([]string, 0, len(s.Tasks))
	for _, task := range s.Tasks {
		parts = append(parts, strings.Join([]string{
			task.ID, task.ChannelID, task.AlgorithmID, task.DisplayName,
			fmt.Sprint(task.Enabled), task.Running,
		}, "\x00"))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x01")))
	return hex.EncodeToString(sum[:])
}

type v1Client struct {
	client *adapter.Client
}

var _ InspectionClient = (*v1Client)(nil)

func (c *v1Client) Login(ctx context.Context) error {
	return c.client.LoginContext(ctx)
}

func (c *v1Client) GetCameraPictureContext(ctx context.Context, channelID string) (adapter.CameraPicture, error) {
	return c.client.GetCameraPictureContext(ctx, channelID)
}

func (c *v1Client) DownloadFreshCameraPictureJPEG(
	ctx context.Context,
	picture adapter.CameraPicture,
	maxBytes int64,
) (adapter.InspectionJPEG, error) {
	return c.client.DownloadFreshCameraPictureJPEG(ctx, picture, maxBytes)
}

func (c *v1Client) QueryPictureAlgorithmsContext(ctx context.Context, page, pageSize int) (adapter.PictureAlgorithmPage, error) {
	return c.client.QueryPictureAlgorithmsContext(ctx, page, pageSize)
}

func (c *v1Client) QueryAlgorithmLayoutDetailContext(ctx context.Context, algorithmID string) (adapter.AlgorithmLayoutDetail, error) {
	return c.client.QueryAlgorithmLayoutDetailContext(ctx, algorithmID)
}

func (c *v1Client) CreatePictureTaskContext(ctx context.Context, request adapter.PictureTaskCreateRequest) error {
	return c.client.CreatePictureTaskContext(ctx, request)
}

func (c *v1Client) DetectPictureTaskContext(
	ctx context.Context,
	request adapter.PictureTaskDetectRequest,
) (adapter.PictureTaskDetectResult, error) {
	return c.client.DetectPictureTaskContext(ctx, request)
}

func (c *v1Client) CancelPictureTaskContext(ctx context.Context, request adapter.PictureTaskCancelRequest) error {
	return c.client.CancelPictureTaskContext(ctx, request)
}

func (c *v1Client) Read(ctx context.Context) (Snapshot, error) {
	info, err := c.client.QueryDeviceInfoContext(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("identify device: %w", err)
	}
	identity := Identity{
		Serial: deviceInfoValue(info, "deviceSn"),
		Type:   firstNonEmpty(deviceInfoValue(info, "productModel"), deviceInfoValue(info, "deviceType")),
	}
	if identity.Serial == "" {
		return Snapshot{}, errors.New("identify device: serial is unavailable")
	}

	now := time.Now().UTC()
	snapshot := Snapshot{
		Identity: identity, Health: Health{ObservedAt: now},
		Cameras: []Camera{}, Tasks: []Task{}, ObservedAt: now,
	}
	if hardware, hardwareErr := c.client.QueryHardwareResourceContext(ctx); hardwareErr == nil {
		if cpu, ok := nestedNumber(hardware, "cpuUtilization", "usedPercent"); ok {
			snapshot.Health.CPUPercent = &cpu
		}
	}
	rows, err := c.readCameraRows(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	algorithmNames := c.readAlgorithmNames(ctx)
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return Snapshot{}, errors.New("read camera catalog: row is malformed")
		}
		cameraID := stringValue(row, "videoChannelId", "channelId", "id")
		cameraName := firstNonEmpty(stringValue(row, "channelName", "name"), "未命名视频源")
		if cameraID == "" {
			return Snapshot{}, errors.New("read camera catalog: camera binding is incomplete")
		}
		kind := "unknown"
		if value, ok := intValue(row["channelType"]); ok {
			switch value {
			case 3:
				kind = "test_video"
			case 0:
				kind = "network_camera"
			case 6:
				kind = "usb_camera"
			}
		}
		snapshot.Cameras = append(snapshot.Cameras, Camera{
			ID: cameraID, Name: cameraName, SourceFingerprint: fingerprintText(stringValue(row, "url")), SourceKind: kind,
		})
		taskRows, _ := arrayValue(row, "taskList", "tasks")
		for _, taskRaw := range taskRows {
			taskMap, ok := taskRaw.(map[string]any)
			if !ok {
				return Snapshot{}, errors.New("read camera catalog: task row is malformed")
			}
			algorithmID := stringValue(taskMap, "algorithmId", "algorithmCode")
			if algorithmID == "" {
				return Snapshot{}, errors.New("read camera catalog: task binding is incomplete")
			}
			taskID := canonicalTaskID(cameraID, algorithmID, stringValue(taskMap, "id", "taskId"))
			enabled, enabledOK := firstInt(taskMap, "enableStatus", "enable", "switch", "taskEnableStatus")
			if !enabledOK || (enabled != 0 && enabled != 1) {
				enabled = -1
			}
			running := "unknown"
			if enabled == 0 {
				running = "stopped"
			}
			algorithmName := firstNonEmpty(stringValue(taskMap, "algorithmName", "name"), algorithmNames[algorithmID], "未命名分析")
			snapshot.Tasks = append(snapshot.Tasks, Task{
				ID: taskID, ChannelID: cameraID, AlgorithmID: algorithmID,
				DisplayName: algorithmName + " + " + cameraName,
				CameraName:  cameraName, AlgorithmName: algorithmName,
				Enabled: enabled, Running: running,
			})
		}
	}
	c.refreshRuntime(ctx, snapshot.Tasks)
	return snapshot, nil
}

func (c *v1Client) SwitchTask(ctx context.Context, task Task, target int) error {
	if target != 0 && target != 1 {
		return errors.New("task switch target is invalid")
	}
	_, err := c.client.SwitchTaskContext(ctx, map[string]any{
		"id": task.ID, "channelId": task.ChannelID, "algorithmId": task.AlgorithmID, "switch": target,
	})
	return err
}

func (c *v1Client) ReadTaskParameters(ctx context.Context, task Task) ([]ParameterField, error) {
	current, err := c.client.QueryTaskParamContext(ctx, task.ChannelID, task.AlgorithmID)
	if err != nil {
		return nil, err
	}
	configured, err := c.client.QueryTaskConfigContext(ctx, task.ChannelID, task.AlgorithmID)
	if err != nil {
		return nil, err
	}
	currentFields, err := parameterFields(current)
	if err != nil {
		return nil, err
	}
	configuration, ok := configured["taskConfig"].(map[string]any)
	if !ok {
		return nil, errors.New("task parameter configuration is unavailable")
	}
	configuredFields, err := parameterFields(configuration)
	if err != nil {
		return nil, err
	}
	if !sameParameterFields(currentFields, configuredFields) {
		return nil, errors.New("task parameter read sources do not agree")
	}
	return currentFields, nil
}

func (c *v1Client) UpdateTaskParameters(ctx context.Context, task Task, fields []ParameterField) error {
	if err := validateParameterFields(fields); err != nil {
		return err
	}
	params := make([]any, 0, len(fields))
	for _, field := range fields {
		params = append(params, map[string]any{"key": field.Key, "value": field.Value})
	}
	_, err := c.client.UpdateTaskParametersContext(ctx, map[string]any{
		"id": task.ID, "channelId": task.ChannelID, "algorithmId": task.AlgorithmID,
		"taskConfig": map[string]any{"params": params},
	})
	return err
}

func (c *v1Client) AddCameraSource(ctx context.Context, name string, sourceURL []byte) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || len(sourceURL) == 0 || len(sourceURL) > 4096 {
		return errors.New("camera source input is invalid")
	}
	parsed, err := url.Parse(string(sourceURL))
	if err != nil || (parsed.Scheme != "rtsp" && parsed.Scheme != "rtsps") || parsed.Host == "" || parsed.Fragment != "" {
		return errors.New("camera source address is invalid")
	}
	_, err = c.client.AddCameraSourceContext(ctx, map[string]any{
		"channelName": name, "channelType": 0, "url": string(sourceURL),
	})
	return err
}

func (c *v1Client) readCameraRows(ctx context.Context) ([]any, error) {
	const pageSize, maxPages = 50, 20
	var rows []any
	expectedTotal := -1
	for page := 1; page <= maxPages; page++ {
		response, err := c.client.QueryCameraPageContext(ctx, page, pageSize)
		if err != nil {
			return nil, fmt.Errorf("read camera catalog page %d: %w", page, err)
		}
		pageRows, ok := arrayValue(response, "rows", "list", "items")
		if !ok {
			return nil, errors.New("read camera catalog: rows are unavailable")
		}
		if total, ok := intValue(response["total"]); ok {
			if expectedTotal < 0 {
				expectedTotal = total
			} else if total != expectedTotal {
				return nil, errors.New("read camera catalog: total changed during paging")
			}
		}
		rows = append(rows, pageRows...)
		if len(pageRows) == 0 || (expectedTotal >= 0 && len(rows) >= expectedTotal) {
			return rows, nil
		}
	}
	return nil, errors.New("read camera catalog: page safety limit exceeded")
}

func canonicalTaskID(channelID, algorithmID, explicitID string) string {
	if explicitID = strings.TrimSpace(explicitID); explicitID != "" {
		return explicitID
	}
	channelID = strings.TrimSpace(channelID)
	algorithmID = strings.TrimSpace(algorithmID)
	if channelID == "" || algorithmID == "" {
		return ""
	}
	return channelID + "_" + algorithmID
}

func (c *v1Client) readAlgorithmNames(ctx context.Context) map[string]string {
	names := map[string]string{}
	response, err := c.client.QueryAlgorithmPageContext(ctx, 1, 1000)
	if err == nil {
		rows, _ := arrayValue(response, "rows", "list", "items")
		for _, raw := range rows {
			row, _ := raw.(map[string]any)
			id := stringValue(row, "algorithmId", "algorithmCode", "id")
			if id != "" {
				names[id] = stringValue(row, "algorithmName", "name")
			}
		}
	}
	_, _ = c.client.QueryAtomicModelPageContext(ctx, 1, 1000)
	_, _ = c.client.QueryAlgorithmLayoutListContext(ctx)
	return names
}

func (c *v1Client) refreshRuntime(ctx context.Context, tasks []Task) {
	ids := make([]string, 0, len(tasks))
	for _, task := range tasks {
		ids = append(ids, task.ID)
	}
	running := map[string]bool{}
	if len(ids) > 0 {
		if response, err := c.client.QueryTaskRunningDetailContext(ctx, ids); err == nil {
			rows, _ := arrayValue(response, "status", "taskList", "tasks", "rows", "list")
			for _, raw := range rows {
				row, _ := raw.(map[string]any)
				if id := stringValue(row, "taskId", "id"); id != "" {
					running[id] = true
				}
			}
		}
	}
	for index := range tasks {
		response, err := c.client.QueryTaskSwitchContext(ctx, map[string]any{
			"id": tasks[index].ID, "channelId": tasks[index].ChannelID, "algorithmId": tasks[index].AlgorithmID,
		})
		if err != nil {
			continue
		}
		switchValue, ok := firstInt(response, "switch", "enable", "enableStatus", "taskEnableStatus", "state")
		if !ok {
			continue
		}
		tasks[index].Enabled = switchValue
		tasks[index].SwitchVerified = switchValue == 0 || switchValue == 1
		if switchValue == 0 {
			tasks[index].Running = "stopped"
		} else if running[tasks[index].ID] {
			tasks[index].Running = "running"
		}
	}
}

func (c *v1Client) ObserveEvents(ctx context.Context, tasks []Task, window EventWindow) EventObservation {
	observation := EventObservation{ByTask: map[string]TaskEventObservation{}}
	nameCounts := map[string]int{}
	for _, task := range tasks {
		nameCounts[task.CameraName]++
	}
	for _, task := range tasks {
		observation.ByTask[task.ID] = c.observeTaskEvents(ctx, task, window, nameCounts[task.CameraName] == 1)
	}
	return observation
}

func (c *v1Client) observeTaskEvents(ctx context.Context, task Task, window EventWindow, useName bool) TaskEventObservation {
	const pageSize, maxPages, displayLimit = 100, 5, 20
	result := TaskEventObservation{Accuracy: "unknown", Events: []Alarm{}}
	if window.Start.IsZero() || window.End.IsZero() || !window.Start.Before(window.End) {
		result.Reason = "invalid event window"
		return result
	}
	seen := map[string]bool{}
	returned, deviceTotal, totalKnown := 0, 0, false
	for page := 1; page <= maxPages; page++ {
		body := map[string]any{
			"pageNum": page, "pageSize": pageSize,
			"timeBegin": window.Start.UTC().UnixMilli(), "timeEnd": window.End.UTC().UnixMilli(),
			"algorithmCodes": []string{task.AlgorithmID},
		}
		if useName {
			body["videoChannelName"] = task.CameraName
		}
		response, err := c.client.QueryEventsWithBodyContext(ctx, body)
		if err != nil {
			result.Reason = "event page unavailable"
			if result.Count > 0 {
				result.Accuracy = "lower_bound"
			}
			return result
		}
		rows, ok := arrayValue(response, "events", "rows", "list")
		if !ok {
			result.Reason = "event rows are unavailable"
			if result.Count > 0 {
				result.Accuracy = "lower_bound"
			}
			return result
		}
		returned += len(rows)
		if total, ok := intValue(response["total"]); ok {
			if !totalKnown || total > deviceTotal {
				deviceTotal = total
			}
			totalKnown = true
		}
		for _, raw := range rows {
			row, _ := raw.(map[string]any)
			channelID := stringValue(row, "videoChannelId", "channelId")
			algorithmID := stringValue(row, "algorithmCode", "algorithmId")
			timestamp, timestampOK := int64Value(row["timestamp"])
			if channelID != task.ChannelID || algorithmID != task.AlgorithmID || !timestampOK || timestamp < window.Start.UTC().UnixMilli() || timestamp >= window.End.UTC().UnixMilli() {
				continue
			}
			key := firstNonEmpty(stringValue(row, "id", "eventId"), fmt.Sprintf("%s\x00%s\x00%d", channelID, algorithmID, timestamp))
			if seen[key] {
				continue
			}
			seen[key] = true
			result.Count++
			if len(result.Events) < displayLimit {
				result.Events = append(result.Events, Alarm{
					OccurredAt: time.UnixMilli(timestamp).UTC().Format(time.RFC3339Nano),
					CameraName: task.CameraName, TaskName: task.DisplayName, AlgorithmName: task.AlgorithmName,
				})
			}
		}
		if (totalKnown && returned >= deviceTotal) || (!totalKnown && len(rows) < pageSize) {
			result.Accuracy, result.Complete = "exact", true
			return result
		}
		if totalKnown && len(rows) == 0 {
			result.Reason, result.Accuracy = "event page ended before reported total", "lower_bound"
			return result
		}
	}
	result.Accuracy, result.Reason = "lower_bound", "event page safety limit reached"
	return result
}

func deviceInfoValue(info map[string]any, key string) string {
	if value := stringValue(info, key); value != "" {
		return value
	}
	for _, listKey := range []string{"devInfoList", "list", "items"} {
		rows, _ := info[listKey].([]any)
		for _, raw := range rows {
			item, _ := raw.(map[string]any)
			name := strings.TrimSpace(fmt.Sprint(item["key"]))
			if strings.EqualFold(name, key) || (key == "deviceSn" && strings.EqualFold(name, "sn")) {
				return cleanString(item["value"])
			}
		}
	}
	return ""
}

func arrayValue(object map[string]any, keys ...string) ([]any, bool) {
	for _, key := range keys {
		if rows, ok := object[key].([]any); ok {
			return rows, true
		}
	}
	return nil, false
}

func stringValue(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := cleanString(object[key]); value != "" {
			return value
		}
	}
	return ""
}

func cleanString(value any) string {
	if value == nil {
		return ""
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "<nil>" {
		return ""
	}
	return text
}

func nestedNumber(object map[string]any, first, second string) (float64, bool) {
	nested, ok := object[first].(map[string]any)
	if !ok {
		return 0, false
	}
	switch value := nested[second].(type) {
	case float64:
		return value, true
	case int:
		return float64(value), true
	default:
		return 0, false
	}
}

func intValue(value any) (int, bool) {
	switch value := value.(type) {
	case float64:
		if value != float64(int(value)) {
			return 0, false
		}
		return int(value), true
	case int:
		return value, true
	default:
		return 0, false
	}
}

func int64Value(value any) (int64, bool) {
	switch value := value.(type) {
	case float64:
		if value != float64(int64(value)) {
			return 0, false
		}
		return int64(value), true
	case int:
		return int64(value), true
	case int64:
		return value, true
	default:
		return 0, false
	}
}

func firstInt(object map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if value, ok := intValue(object[key]); ok {
			return value, true
		}
	}
	return 0, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parameterFields(document map[string]any) ([]ParameterField, error) {
	rows, ok := document["params"].([]any)
	if !ok || len(rows) == 0 || len(rows) > 128 {
		return nil, errors.New("task parameters are unavailable or outside supported bounds")
	}
	fields := make([]ParameterField, 0, len(rows))
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("task parameter row is malformed")
		}
		key := strings.TrimSpace(fmt.Sprint(row["key"]))
		value := fmt.Sprint(row["value"])
		if key == "" || key == "<nil>" || value == "<nil>" {
			return nil, errors.New("task parameter row is incomplete")
		}
		fields = append(fields, ParameterField{Key: key, Value: value})
	}
	if err := validateParameterFields(fields); err != nil {
		return nil, err
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Key < fields[j].Key })
	return fields, nil
}

func validateParameterFields(fields []ParameterField) error {
	if len(fields) == 0 || len(fields) > 128 {
		return errors.New("task parameter field count is invalid")
	}
	seen := map[string]bool{}
	for _, field := range fields {
		key := strings.TrimSpace(field.Key)
		if key == "" || len(key) > 512 || len(field.Value) > 2056 || seen[key] {
			return errors.New("task parameter fields are invalid or duplicated")
		}
		seen[key] = true
	}
	return nil
}

func sameParameterFields(left, right []ParameterField) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func fingerprintText(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
