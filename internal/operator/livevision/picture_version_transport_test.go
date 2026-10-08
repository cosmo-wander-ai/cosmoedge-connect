package livevision

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/adapter"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/device"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/session"
)

// Exercise the real layout/detail decoder and selector through temporary
// analysis, with localhost transport and a fake authenticated device snapshot.
// No deployed algorithm ID, version, device, or evidence is used.
func TestTemporaryAnalysisBindsCurrentPictureVersionFromTransport(t *testing.T) {
	const code, currentTime, oldTime = "picture-model-7", "1770000000000", "1760000000000"
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		valid  bool
	}{
		{name: "empty current code inherits exact parent", valid: true},
		{name: "omitted current code inherits exact parent", valid: true, mutate: func(_ map[string]any, v map[string]any) { delete(v, "algorithmCode") }},
		{name: "explicit matching code", valid: true, mutate: func(_ map[string]any, v map[string]any) { v["algorithmCode"] = code }},
		{name: "string current timestamp", valid: true, mutate: func(_ map[string]any, v map[string]any) { v["algorithmUpdateTime"] = currentTime }},
		{name: "different parent rejected", mutate: func(d map[string]any, _ map[string]any) {
			d["algorithmCode"] = "different-model"
			for _, item := range d["configVersionList"].([]any) {
				item.(map[string]any)["algorithmCode"] = "different-model"
			}
		}},
		{name: "empty parent rejected", mutate: func(d map[string]any, _ map[string]any) { d["algorithmCode"] = "" }},
		{name: "conflicting nested code rejected", mutate: func(_ map[string]any, v map[string]any) { v["algorithmCode"] = "different-model" }},
		{name: "whitespace nested code rejected", mutate: func(_ map[string]any, v map[string]any) { v["algorithmCode"] = " " }},
		{name: "missing current version never falls back", mutate: func(d map[string]any, _ map[string]any) { d["confVersionId"] = "missing-version" }},
		{name: "empty current version never falls back", mutate: func(d map[string]any, _ map[string]any) { d["confVersionId"] = "" }},
		{name: "duplicate current version rejected", mutate: func(d map[string]any, _ map[string]any) {
			d["configVersionList"].([]any)[0].(map[string]any)["id"] = "version-current"
		}},
		{name: "invalid current timestamp never uses old version", mutate: func(_ map[string]any, v map[string]any) { v["algorithmUpdateTime"] = "bad-time" }},
		{name: "duplicate timestamp rejected", mutate: func(_ map[string]any, v map[string]any) { v["algorithmUpdateTime"] = oldTime }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := map[string]any{"id": "version-current", "algorithmCode": "", "algorithmUpdateTime": int64(1770000000000)}
			detail := map[string]any{
				"algorithmCode": code, "algorithmName": "VLM", "algorithmUsage": "2", "confVersionId": "version-current",
				"configVersionList": []any{
					map[string]any{"id": "version-old", "algorithmCode": code, "algorithmUpdateTime": oldTime}, current,
				},
			}
			if test.mutate != nil {
				test.mutate(detail, current)
			}
			journal := &pictureVersionJournal{}
			var creates atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid transport request JSON")
					http.Error(w, "invalid JSON", http.StatusBadRequest)
					return
				}
				var data any
				switch r.URL.Path {
				case "/gtw/cwai/Algorithm/Page":
					if body["algorithmUsage"] != "2" || body["pageNum"] != float64(1) || body["pageSize"] != float64(100) {
						t.Errorf("unexpected picture catalog request: %#v", body)
					}
					data = map[string]any{"total": 1, "rows": []any{map[string]any{"algorithmId": code, "algorithmName": "VLM", "algorithmUsage": "2"}}}
				case "/gtw/cwai/algorithm/layout/detail":
					if len(body) != 1 || body["id"] != code {
						t.Errorf("unexpected detail request: %#v", body)
					}
					data = detail
				case "/gtw/cwai/aihost/PTaskCreate":
					creates.Add(1)
					taskID, taskIDValid := body["taskId"].(string)
					if journal.reserved.Load() != 1 || len(body) != 3 || body["algorithmCode"] != code || body["algorithmUpdateTime"] != currentTime || !taskIDValid || taskID == "" {
						t.Errorf("create was not journaled with the exact current version: %#v", body)
					}
					data = map[string]any{}
				default:
					t.Errorf("unexpected transport path: %s", r.URL.Path)
					http.Error(w, "unexpected path", http.StatusNotFound)
					return
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"resCode": 1, "resData": data}); err != nil {
					t.Errorf("encode fixture response: %v", err)
				}
			}))
			defer server.Close()
			fake := &inspectionDeviceStub{
				snapshot: device.Snapshot{Identity: device.Identity{Serial: "test-serial", Type: "test-edge"}, ObservedAt: time.Now().UTC()},
				detect: adapter.PictureTaskDetectResult{AlgorithmCode: code, Areas: []adapter.PictureTaskArea{{
					Detected: true, Targets: []adapter.PictureTaskTarget{{Confidence: []adapter.PictureTaskConfidence{{Label: "是", Confidence: 1}}}},
				}}},
			}
			client := &pictureVersionTransportDevice{inspectionDeviceStub: fake, transport: adapter.NewClient(server.URL, "test-user", "test-password")}
			vault := session.New(func(_, _, _ string) device.Client { return client })
			connectVault(t, vault)
			connections, err := NewVaultConnections(vault, WithTemporaryTaskJournal(journal))
			if err != nil {
				t.Fatal(err)
			}
			spec, err := temporary.NewSpec(temporary.Intent{Subject: "人", Region: "当前区域", Observable: "是否有人", Locale: "zh-CN", TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: 600})
			if err != nil {
				t.Fatal(err)
			}
			prompt, err := temporary.CompilePrompt(spec)
			if err != nil {
				t.Fatal(err)
			}
			content := liveJPEG(t)
			at := time.Now().UTC()
			raw, err := NewTemporaryAnalyzer(connections).Analyze(context.Background(), temporary.AnalysisRequest{
				RunID: "temporary_0123456789abcdef0123456789abcdef", Prompt: prompt,
				Evidence: temporary.AnalysisEvidence{EvidenceRef: "media_0123456789abcdef0123456789abcdef", SHA256: liveDigest(string(content)), MIMEType: "image/jpeg", CapturedAt: at, ExpiresAt: at.Add(time.Hour), Content: content},
			})
			_, detected, cancelled := fake.operationRequests()
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
				candidate, parseErr := temporary.ParseCandidate(raw)
				if parseErr != nil || candidate.Answer != temporary.AnswerYes || creates.Load() != 1 || len(detected) != 1 || len(cancelled) != 1 || journal.finished.Load() != 1 {
					t.Fatalf("temporary lifecycle candidate=%+v parse=%v create=%d detect=%d cancel=%d finished=%d", candidate, parseErr, creates.Load(), len(detected), len(cancelled), journal.finished.Load())
				}
			} else if !errors.Is(err, temporary.ErrAnalysisDefinitelyFailed) || len(raw) != 0 || journal.reserved.Load() != 0 || creates.Load() != 0 || len(detected) != 0 || len(cancelled) != 0 {
				t.Fatalf("invalid binding reached device writes: error=%v reserved=%d create=%d detect=%d cancel=%d", err, journal.reserved.Load(), creates.Load(), len(detected), len(cancelled))
			}
		})
	}
}

type pictureVersionTransportDevice struct {
	*inspectionDeviceStub
	transport *adapter.Client
}

func (d *pictureVersionTransportDevice) QueryPictureAlgorithmsContext(ctx context.Context, page, size int) (adapter.PictureAlgorithmPage, error) {
	return d.transport.QueryPictureAlgorithmsContext(ctx, page, size)
}
func (d *pictureVersionTransportDevice) QueryAlgorithmLayoutDetailContext(ctx context.Context, id string) (adapter.AlgorithmLayoutDetail, error) {
	return d.transport.QueryAlgorithmLayoutDetailContext(ctx, id)
}
func (d *pictureVersionTransportDevice) CreatePictureTaskContext(ctx context.Context, request adapter.PictureTaskCreateRequest) error {
	return d.transport.CreatePictureTaskContext(ctx, request)
}

type pictureVersionJournal struct {
	reserved atomic.Int32
	finished atomic.Int32
}

func (j *pictureVersionJournal) BeforeCreate(context.Context, TemporaryTask) error {
	j.reserved.Add(1)
	return nil
}
func (j *pictureVersionJournal) BeforeCancel(context.Context, TemporaryTask) (bool, error) {
	return true, nil
}
func (j *pictureVersionJournal) FinishTask(_ context.Context, _ TemporaryTask, disposition string) error {
	if disposition == TaskCancelAcknowledged {
		j.finished.Add(1)
	}
	return nil
}
