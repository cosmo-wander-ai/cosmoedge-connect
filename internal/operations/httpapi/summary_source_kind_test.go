package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/summary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
)

func TestSummaryHTTPReportsRecordMajorityIndependentlyOfSourceMajority(t *testing.T) {
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	var cameras []device.Camera
	var first, second []device.HistoricalEvent
	appendEvents := func(target *[]device.HistoricalEvent, source string, count int) {
		for i := 0; i < count; i++ {
			*target = append(*target, device.HistoricalEvent{ID: fmt.Sprintf("%s-%d", source, i), OccurredAt: start.Add(time.Minute), SourceID: source, SourceName: "共有名称", AlgorithmID: "algorithm"})
		}
	}
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("test-%d", i)
		cameras = append(cameras, device.Camera{ID: id, Name: "共有名称", SourceKind: "test_video"})
		appendEvents(&first, id, 2)
	}
	cameras = append(cameras, device.Camera{ID: "network", Name: "共有名称", SourceKind: "network_camera"})
	appendEvents(&second, "network", 31)
	appendEvents(&second, "deleted", 4)
	second = append(second, first[0])
	calls := 0
	client := &summaryHTTPDevice{cameras: cameras, readPage: func(_ context.Context, request device.EventPageRequest) (device.EventPage, error) {
		calls++
		total := len(first) + len(second)
		switch request.Page {
		case 1:
			return device.EventPage{Events: first, Total: &total}, nil
		case 2:
			return device.EventPage{Events: second, Total: &total}, nil
		default:
			t.Fatalf("unexpected page %d", request.Page)
			return device.EventPage{}, nil
		}
	}}
	handler, token := newSummaryHTTPHandler(t, client, start.Add(48*time.Hour))
	issued := callSummaryHTTP(handler, token, "session", "", "{}")
	var issuedSession struct {
		SessionRef string `json:"sessionRef"`
	}
	if err := json.Unmarshal(issued.Body.Bytes(), &issuedSession); err != nil || issued.Code != http.StatusOK {
		t.Fatal("session issuance failed", err)
	}
	body, err := json.Marshal(SummaryRequest{Start: start, End: start.Add(24 * time.Hour), TimeZone: "Asia/Shanghai"})
	if err != nil {
		t.Fatal(err)
	}
	w := callSummaryHTTP(handler, token, "summary", issuedSession.SessionRef, string(body))
	var response struct {
		Summary     summary.Result    `json:"summary"`
		SourceKinds map[string]string `json:"sourceKinds"`
		UserMessage string            `json:"userMessage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || calls != 2 {
		t.Fatalf("summary failed: status=%d calls=%d err=%v", w.Code, calls, err)
	}
	networkShare, videoShare, unknownShare := 68.89, 22.22, 8.89
	want := []summary.SourceKindCount{
		{SourceKind: "network_camera", RetainedRecordCount: 31, SourceCount: 1, SharePercent: &networkShare},
		{SourceKind: "test_video", RetainedRecordCount: 10, SourceCount: 5, SharePercent: &videoShare},
		{SourceKind: "unknown", RetainedRecordCount: 4, SourceCount: 1, SharePercent: &unknownShare},
	}
	if response.Summary.Count != 45 || !reflect.DeepEqual(response.Summary.BySourceKind, want) || response.Summary.SourceKindScope != "retained_window" || response.Summary.SourceKindBasis != "current_source_catalog" {
		t.Fatalf("source majority was confused with record majority or history was dropped: %s", w.Body)
	}
	if response.SourceKinds["共有名称"] != "unknown" {
		t.Fatal("same-name legacy labels invented one source type")
	}
	for _, statement := range []string{"网络摄像头 31 条（1 个来源）", "测试视频 10 条（5 个来源）", "类型未知 4 条（1 个来源）", "来源数不等于告警条数", "来源类型不证明循环播放或告警数量的原因"} {
		if !strings.Contains(response.UserMessage, statement) {
			t.Fatalf("missing classification evidence %q: %s", statement, response.UserMessage)
		}
	}
}
