package httpapi

// These tests exercise the HTTP seam with a recording API. They do not claim
// real camera acquisition, model quality, device cleanup, or WorkBuddy delivery.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/observation"
)

type observationHTTPCall struct {
	method string
	owner  string
	ref    string
}

type recordingObservationAPI struct {
	calls      []observationHTTPCall
	owner      string
	result     observation.Result
	request    observation.Request
	err        error
	media      map[string]observation.Media
	mediaError map[string]error
}

func (s *recordingObservationAPI) Observe(_ context.Context, owner string, request observation.Request) (observation.Result, error) {
	s.calls = append(s.calls, observationHTTPCall{"observe", owner, request.RequestID})
	s.request = request
	if s.err != nil {
		return observation.Result{}, s.err
	}
	if s.owner == "" {
		s.owner = owner
	}
	if s.owner != owner {
		return observation.Result{}, observation.ErrNotFound
	}
	return s.result, nil
}
func (s *recordingObservationAPI) Get(_ context.Context, owner, ref string) (observation.Result, error) {
	s.calls = append(s.calls, observationHTTPCall{"get", owner, ref})
	if s.err != nil {
		return observation.Result{}, s.err
	}
	if owner != s.owner || ref != s.result.OperationRef {
		return observation.Result{}, observation.ErrNotFound
	}
	return s.result, nil
}
func (s *recordingObservationAPI) GetByRequest(_ context.Context, owner, ref string) (observation.Result, error) {
	s.calls = append(s.calls, observationHTTPCall{"by-request", owner, ref})
	if s.err != nil {
		return observation.Result{}, s.err
	}
	if owner != s.owner || ref != s.result.RequestID {
		return observation.Result{}, observation.ErrNotFound
	}
	return s.result, nil
}
func (s *recordingObservationAPI) ReadMedia(_ context.Context, owner, ref string) (observation.Media, error) {
	s.calls = append(s.calls, observationHTTPCall{"media", owner, ref})
	if owner != s.owner {
		return observation.Media{}, observation.ErrNotFound
	}
	if err := s.mediaError[ref]; err != nil {
		return observation.Media{}, err
	}
	if media, ok := s.media[ref]; ok {
		return media, nil
	}
	return observation.Media{}, observation.ErrNotFound
}

type observationHTTPFixture struct {
	t       *testing.T
	handler *Handler
	api     *recordingObservationAPI
	token   string
	now     time.Time
}

func newObservationHTTPFixture(t *testing.T) *observationHTTPFixture {
	t.Helper()
	f := &observationHTTPFixture{t: t, token: strings.Repeat("9", 64), now: time.Date(2026, 9, 7, 6, 30, 0, 0, time.UTC)}
	f.api = &recordingObservationAPI{
		result: observation.Result{OperationRef: "observation_original", RequestID: "request_original", Status: "succeeded",
			Question: "画面中有没有人员", Answer: temporary.AnswerYes, Facts: []string{"画面右侧可见一人"},
			Limitations: []string{}, SourceName: "入口测试机位", SourceKind: "test_video", TimeMeaning: "image_retrieved_at",
			Attachments: []observation.Attachment{}},
		media: make(map[string]observation.Media), mediaError: make(map[string]error),
	}
	digest := sha256.Sum256([]byte(f.token))
	var err error
	f.handler, err = New(Config{TokenDigest: hex.EncodeToString(digest[:]), Connections: &unavailableConnection{}, Observations: f.api, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *observationHTTPFixture) call(method, path, sessionRef, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, "http://127.0.0.1:37789"+Prefix+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+f.token)
	r.Header.Set("X-CosmoEdge-Session", sessionRef)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}
func (f *observationHTTPFixture) issue() string {
	f.t.Helper()
	w := f.call(http.MethodPost, "session", "", "{}")
	var result struct {
		OK         bool   `json:"ok"`
		SessionRef string `json:"sessionRef"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != http.StatusOK || !result.OK || !f.handler.validSession(result.SessionRef) {
		f.t.Fatal("public session issuance failed", w.Code, err)
	}
	return result.SessionRef
}
func observationOwner(ref string) string {
	digest := sha256.Sum256([]byte(ref))
	return hex.EncodeToString(digest[:])
}
func decodeObservationEnvelope(t *testing.T, w *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	var result map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal("invalid public JSON", err)
	}
	return result
}
func decodeObservationMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var message string
	if err := json.Unmarshal(decodeObservationEnvelope(t, w)["userMessage"], &message); err != nil {
		t.Fatal(err)
	}
	return message
}

func TestObservationHTTPSignedOwnerScopesSubmissionReadsAndMedia(t *testing.T) {
	f := newObservationHTTPFixture(t)
	first, second := f.issue(), f.issue()
	if first == second || observationOwner(first) == observationOwner(second) {
		t.Fatal("two issued sessions were not isolated")
	}
	body := `{"requestId":"request_original","sourceName":"入口测试机位","question":"画面中有没有人员","subject":"人员"}`
	w := f.call(http.MethodPost, "observations", first, body)
	if w.Code != http.StatusOK || f.api.owner != observationOwner(first) || f.api.owner == first {
		t.Fatal("submission did not use the hash of its signed session", w.Code)
	}
	if f.api.request.SourceName != "入口测试机位" || f.api.request.RequestID != "request_original" || f.api.request.Subject != "人员" {
		t.Fatal("structured request changed before reaching the observation API")
	}
	content := []byte("HTTP media ownership contract bytes")
	sum := sha256.Sum256(content)
	f.api.media["media_owned"] = observation.Media{Content: content, MIMEType: "image/png", SHA256: hex.EncodeToString(sum[:])}
	for _, route := range []string{"observations/observation_original", "observations/by-request/request_original", "media/media_owned"} {
		if w := f.call(http.MethodGet, route, first, ""); w.Code != http.StatusOK {
			t.Fatalf("owner cannot read %s: %d", route, w.Code)
		}
		if w := f.call(http.MethodGet, route, second, ""); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), string(content)) {
			t.Fatalf("other signed session could read %s: %d", route, w.Code)
		}
	}
	wantMethods := []string{"observe", "get", "get", "by-request", "by-request", "media", "media"}
	var methods []string
	for index, call := range f.api.calls {
		methods = append(methods, call.method)
		expected := observationOwner(first)
		if index > 0 && index%2 == 0 {
			expected = observationOwner(second)
		}
		if call.owner != expected {
			t.Fatalf("call %d forwarded the wrong signed owner", index)
		}
	}
	if !reflect.DeepEqual(methods, wantMethods) {
		t.Fatalf("read routes resubmitted an observation: %#v", methods)
	}
}

func TestObservationHTTPCaptureUsesSameOwnerAndReadRoutesWithoutAnAnswer(t *testing.T) {
	f := newObservationHTTPFixture(t)
	ref := f.issue()
	f.api.result.Kind, f.api.result.AnalysisSource = "capture", "none"
	f.api.result.Status, f.api.result.Question, f.api.result.Answer, f.api.result.Facts = "captured", "", "", nil
	w := f.call(http.MethodPost, "captures", ref, `{"requestId":"request_original","sourceName":"入口测试机位"}`)
	if w.Code != http.StatusOK || f.api.owner != observationOwner(ref) || f.api.request.Mode != observation.CaptureOnly || f.api.request.Question != "" || f.api.request.Subject != "" {
		t.Fatalf("capture required an analysis question or changed owner: %d %+v", w.Code, f.api.request)
	}
	envelope := decodeObservationEnvelope(t, w)
	var result map[string]json.RawMessage
	if err := json.Unmarshal(envelope["observation"], &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"answer", "facts", "cleanupStatus"} {
		if _, present := result[key]; present {
			t.Errorf("capture exposed analysis field %s", key)
		}
	}
	if string(result["kind"]) != `"capture"` || string(result["analysisSource"]) != `"none"` || string(result["status"]) != `"captured"` || string(result["frameTimeKnown"]) != "false" {
		t.Fatalf("capture scope or frame-time boundary lost: %s", envelope["observation"])
	}
	var pollPath string
	if err := json.Unmarshal(envelope["pollPath"], &pollPath); err != nil || pollPath != Prefix+"observations/observation_original" {
		t.Fatalf("capture cannot use existing continuation: %q %v", pollPath, err)
	}
	for _, path := range []string{"observations/observation_original", "observations/by-request/request_original"} {
		w := f.call(http.MethodGet, path, ref, "")
		if w.Code != http.StatusOK || strings.Contains(decodeObservationMessage(t, w), "无法判断") {
			t.Fatalf("capture continuation became an edge answer: %s %d", path, w.Code)
		}
	}
	if len(f.api.calls) != 3 || f.api.calls[1].method != "get" || f.api.calls[2].method != "by-request" {
		t.Fatalf("capture continuation resubmitted: %+v", f.api.calls)
	}
}

func TestObservationHTTPCaptureAndEdgeEntryPointsDoNotSwitchAnalysisMode(t *testing.T) {
	f := newObservationHTTPFixture(t)
	ref := f.issue()
	for _, test := range []struct{ path, body string }{
		{"captures", `{"requestId":"capture","sourceName":"入口","mode":"edge"}`},
		{"captures", `{"requestId":"capture","sourceName":"入口","subject":"人员"}`},
		{"observations", `{"requestId":"edge","sourceName":"入口","question":"是否有人","mode":"capture"}`},
	} {
		if w := f.call(http.MethodPost, test.path, ref, test.body); w.Code != http.StatusBadRequest {
			t.Fatalf("unsupported mode reached %s: %d", test.path, w.Code)
		}
	}
	if len(f.api.calls) != 0 {
		t.Fatalf("mode override reached service: %+v", f.api.calls)
	}
	if w := f.call(http.MethodPost, "captures", "", `{"requestId":"capture","sourceName":"入口"}`); w.Code != http.StatusForbidden || len(f.api.calls) != 0 {
		t.Fatal("unauthenticated capture reached service")
	}
}

func TestObservationHTTPRejectsMissingTamperedExpiredSessionBeforeAPI(t *testing.T) {
	f := newObservationHTTPFixture(t)
	valid := f.issue()
	for _, ref := range []string{"", strings.Repeat("f", 64), valid[:len(valid)-1] + "z"} {
		for _, route := range []string{"observations/observation_original", "observations/by-request/request_original", "media/media_owned"} {
			if w := f.call(http.MethodGet, route, ref, ""); w.Code != http.StatusForbidden {
				t.Fatalf("invalid session reached %s: %d", route, w.Code)
			}
		}
	}
	f.now = f.now.Add(8 * 24 * time.Hour)
	if w := f.call(http.MethodPost, "observations", valid, `{}`); w.Code != http.StatusForbidden {
		t.Fatal("expired session reached observation submission")
	}
	if len(f.api.calls) != 0 {
		t.Fatal("invalid signed session reached observation API")
	}
}

func TestObservationHTTPOwnerCannotBeOverriddenByPayloadOrOtherHeader(t *testing.T) {
	f := newObservationHTTPFixture(t)
	ref := f.issue()
	body := `{"requestId":"request_original","sourceName":"入口","question":"有没有人","ownerHash":"forged"}`
	if w := f.call(http.MethodPost, "observations", ref, body); w.Code != http.StatusBadRequest || len(f.api.calls) != 0 {
		t.Fatal("payload owner override reached API", w.Code)
	}
	f.api.owner = observationOwner(ref)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:37789"+Prefix+"observations/by-request/request_original?ownerHash=forged", nil)
	r.Header.Set("Authorization", "Bearer "+f.token)
	r.Header.Set("X-CosmoEdge-Session", ref)
	r.Header.Set("X-CosmoEdge-Owner", "forged")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK || len(f.api.calls) != 1 || f.api.calls[0].owner != observationOwner(ref) || f.api.calls[0].method != "by-request" {
		t.Fatal("read request changed owner from the signed session", w.Code)
	}
}

func TestObservationHTTPThreeStateAnswersKeepSourceAndTimeMeaning(t *testing.T) {
	for _, test := range []struct {
		answer temporary.Answer
		phrase string
	}{
		{temporary.AnswerYes, "：是。"},
		{temporary.AnswerNo, "：否。"},
		{temporary.AnswerUnable, "：无法判断。"},
	} {
		t.Run(string(test.answer), func(t *testing.T) {
			f := newObservationHTTPFixture(t)
			ref := f.issue()
			f.api.owner = observationOwner(ref)
			at := time.Date(2026, 9, 7, 14, 30, 0, 0, time.FixedZone("business", 8*60*60))
			f.api.result.Answer = test.answer
			f.api.result.ObservedAt = &at
			if test.answer != temporary.AnswerYes {
				f.api.result.Facts = []string{}
			}
			if test.answer == temporary.AnswerUnable {
				f.api.result.Limitations = []string{"画面模糊，无法辨认人员"}
			}
			w := f.call(http.MethodGet, "observations/observation_original", ref, "")
			if w.Code != http.StatusOK {
				t.Fatal(w.Code)
			}
			var result observation.Result
			if err := json.Unmarshal(decodeObservationEnvelope(t, w)["observation"], &result); err != nil {
				t.Fatal(err)
			}
			message := decodeObservationMessage(t, w)
			for _, expected := range []string{test.phrase, "图片获取时间：2026-09-07T14:30:00+08:00", "这不是经核准的摄像头画面时间", "测试视频", "只对应本次取得的测试帧"} {
				if !strings.Contains(message, expected) {
					t.Fatalf("public answer dropped boundary %q: %s", expected, message)
				}
			}
			if result.Answer != test.answer || result.SourceName != "入口测试机位" || result.SourceKind != "test_video" || result.TimeMeaning != "image_retrieved_at" || result.ObservedAt == nil || !result.ObservedAt.Equal(at) {
				t.Fatal("answer/source/time provenance changed in HTTP projection")
			}
			if test.answer == temporary.AnswerUnable && !strings.Contains(message, "画面模糊") {
				t.Fatal("unable lost its visible evidence limitation")
			}
		})
	}
}

func TestObservationHTTPPendingAndMissingTimeDoNotInventCurrentFrame(t *testing.T) {
	f := newObservationHTTPFixture(t)
	ref := f.issue()
	f.api.owner = observationOwner(ref)
	f.api.result.SourceKind = "rtsp"
	f.api.result.SourceName = "实时入口"
	f.api.result.ObservedAt = nil
	w := f.call(http.MethodGet, "observations/observation_original", ref, "")
	message := decodeObservationMessage(t, w)
	if strings.Contains(message, "图片获取时间") || strings.Contains(message, "测试视频") {
		t.Fatal("HTTP invented missing time or a different source kind", message)
	}
	f.api.result.Pending = true
	f.api.result.Status = "queued"
	f.api.result.Answer = ""
	f.api.result.Facts = nil
	w = f.call(http.MethodGet, "observations/by-request/request_original", ref, "")
	envelope := decodeObservationEnvelope(t, w)
	var pending bool
	var operationRef, requestID, pollPath string
	json.Unmarshal(envelope["pending"], &pending)
	json.Unmarshal(envelope["operationRef"], &operationRef)
	json.Unmarshal(envelope["requestId"], &requestID)
	json.Unmarshal(envelope["pollPath"], &pollPath)
	if !pending || operationRef != "observation_original" || requestID != "request_original" || pollPath != Prefix+"observations/observation_original" {
		t.Fatal("pending result lost its original read continuation")
	}
	if message := decodeObservationMessage(t, w); !strings.Contains(message, "已受理") || strings.Contains(message, "：是。") || strings.Contains(message, "已完成") {
		t.Fatal("queued result claimed completed visual facts", message)
	}
	if len(f.api.calls) != 2 || f.api.calls[0].method != "get" || f.api.calls[1].method != "by-request" {
		t.Fatal("pending follow-up took a new picture")
	}
}

func TestObservationHTTPPartialMediaPreservesTextAndAttachmentStates(t *testing.T) {
	f := newObservationHTTPFixture(t)
	ref := f.issue()
	f.api.owner = observationOwner(ref)
	content := []byte("test image transport bytes")
	digest := sha256.Sum256(content)
	sha := hex.EncodeToString(digest[:])
	f.api.result.Attachments = []observation.Attachment{
		{MediaRef: "media_good", MIMEType: "image/png", SHA256: sha, SizeBytes: int64(len(content)), Status: "available", ExpiresAt: f.now.Add(time.Hour)},
		{MediaRef: "media_expired", MIMEType: "image/png", SHA256: strings.Repeat("f", 64), SizeBytes: 20, Status: "unavailable", ExpiresAt: f.now.Add(-time.Minute)},
	}
	f.api.result.Limitations = []string{"部分原图暂不可读取，文字结果仍保留"}
	f.api.media["media_good"] = observation.Media{Content: content, MIMEType: "image/png", SHA256: sha}
	f.api.mediaError["media_expired"] = observation.ErrMediaUnavailable
	w := f.call(http.MethodGet, "observations/observation_original", ref, "")
	envelope := decodeObservationEnvelope(t, w)
	var attachments []struct {
		Path        string `json:"path"`
		Status      string `json:"status"`
		ContentType string `json:"contentType"`
		SHA256      string `json:"sha256"`
	}
	if err := json.Unmarshal(envelope["attachments"], &attachments); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(attachments) != 2 || attachments[0].Status != "available" || attachments[1].Status != "unavailable" || attachments[0].Path != Prefix+"media/media_good" || attachments[0].SHA256 != sha {
		t.Fatal("partial observation lost original attachment status and identity")
	}
	message := decodeObservationMessage(t, w)
	if !strings.Contains(message, "画面右侧可见一人") || !strings.Contains(message, "部分原图暂不可读取") {
		t.Fatal("partial media erased text or its failure boundary", message)
	}
	good := f.call(http.MethodGet, "media/media_good", ref, "")
	if good.Code != http.StatusOK || !reflect.DeepEqual(good.Body.Bytes(), content) || good.Header().Get("Content-Type") != "image/png" || good.Header().Get("X-Content-SHA256") != sha || good.Header().Get("Content-Length") != fmt.Sprint(len(content)) {
		t.Fatal("media response changed content or integrity metadata")
	}
	if good.Header().Get("Cache-Control") != "no-store" || good.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("authenticated media lost response privacy headers")
	}
	expired := f.call(http.MethodGet, "media/media_expired", ref, "")
	if expired.Code != http.StatusGone || !strings.Contains(decodeObservationMessage(t, expired), "文字结果仍可续查") {
		t.Fatal("expired image was returned as a valid current picture", expired.Code)
	}
	if f.api.calls[0].method != "get" || f.api.calls[1].method != "media" || f.api.calls[2].method != "media" {
		t.Fatal("image retrieval triggered a new observation")
	}
}

func TestObservationHTTPErrorMappingPreservesMeaningWithoutPrivateErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"invalid", observation.ErrInvalidRequest, 400, "invalid_observation"},
		{"missing", observation.ErrNotFound, 404, "observation_not_found"},
		{"reused-different-request", observation.ErrConflict, 409, "observation_conflict"},
		{"connection", observation.ErrConnectionRequired, 409, "connection_required"},
		{"expired-media", observation.ErrMediaUnavailable, 410, "image_unavailable"},
		{"unexpected", errors.New("private-device-endpoint-and-credential"), 503, "observation_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newObservationHTTPFixture(t)
			ref := f.issue()
			f.api.err = fmt.Errorf("private-device-endpoint-and-credential: %w", test.err)
			w := f.call(http.MethodPost, "observations", ref, `{"requestId":"r","sourceName":"入口","question":"有没有人"}`)
			var body struct {
				OK   bool   `json:"ok"`
				Code string `json:"code"`
			}
			json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != test.status || body.OK || body.Code != test.code || strings.Contains(w.Body.String(), "private-device") {
				t.Fatal("error boundary changed or leaked private details", w.Code, w.Body.String())
			}
		})
	}
	f := newObservationHTTPFixture(t)
	ref := f.issue()
	f.api.err = &observation.SourceSelectionError{Code: "source_required", Choices: []observation.SourceChoice{{Name: "前厅"}, {Name: "后门"}}}
	w := f.call(http.MethodPost, "observations", ref, `{"requestId":"r","question":"有没有人"}`)
	var selection struct {
		OK                  bool                       `json:"ok"`
		InteractionRequired bool                       `json:"interactionRequired"`
		Choices             []observation.SourceChoice `json:"choices"`
	}
	json.Unmarshal(w.Body.Bytes(), &selection)
	if w.Code != http.StatusConflict || selection.OK || !selection.InteractionRequired || len(selection.Choices) != 2 || !strings.Contains(decodeObservationMessage(t, w), "没有取图或提交分析") {
		t.Fatal("source ambiguity became a fabricated observation")
	}
}

func TestObservationHTTPMalformedInputAndUnavailableServiceDoNotSubmit(t *testing.T) {
	f := newObservationHTTPFixture(t)
	ref := f.issue()
	for _, body := range []string{`{"unknown":"input"}`, `{} {}`, `{"requestId":4}`, strings.Repeat(" ", 33<<10)} {
		if w := f.call(http.MethodPost, "observations", ref, body); w.Code != http.StatusBadRequest {
			t.Fatal("malformed observation body reached API", w.Code)
		}
	}
	if len(f.api.calls) != 0 {
		t.Fatal("malformed input invoked observation API")
	}
	f.handler.config.Observations = nil
	for _, test := range []struct{ method, path, body string }{
		{http.MethodPost, "observations", "{}"},
		{http.MethodGet, "observations/observation_original", ""},
		{http.MethodGet, "observations/by-request/request_original", ""},
		{http.MethodGet, "media/media_good", ""},
	} {
		w := f.call(test.method, test.path, ref, test.body)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "observation_unavailable") {
			t.Fatal("absent operation service was reported as ready", w.Code)
		}
	}
}
