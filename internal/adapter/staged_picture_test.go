package adapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

func stagedTestCapabilities() UploadCapabilities {
	return UploadCapabilities{MaxChunkSize: 8 << 20, IdleTimeoutMs: 60000, AvailableBytes: 1 << 30, AvailableForNewUploadsBytes: 1 << 29, MaxEncodedImageBytes: 99532800, MaxImagePixels: 33177600, Resumable: true, PersistentAcrossRestart: true}
}

func stagedCapabilityBody() map[string]any {
	return map[string]any{"maxTotalSize": "0", "maxChunkSize": "8388608", "maxChunks": "0", "idleTimeoutMs": "60000", "absoluteTimeoutMs": "0", "availableBytes": "18446744073709551615", "reserveBytes": "1024", "availableForNewUploadsBytes": "100000000", "reservedBySessionsBytes": "0", "activeSessions": "0", "maxEncodedImageBytes": "99532800", "maxImagePixels": "33177600", "resumable": true, "persistentAcrossRestart": true}
}

func TestUploadCapabilitiesTypedLimitsAndZeroUnlimited(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"valid", nil, true},
		{"missing-limit", func(m map[string]any) { delete(m, "maxTotalSize") }, false},
		{"overflow", func(m map[string]any) { m["maxTotalSize"] = "18446744073709551616" }, false},
		{"imprecise-number", func(m map[string]any) { m["maxTotalSize"] = float64(1 << 54) }, false},
		{"negative", func(m map[string]any) { m["activeSessions"] = "-1" }, false},
		{"zero-chunk", func(m map[string]any) { m["maxChunkSize"] = "0" }, false},
		{"boolean-string", func(m map[string]any) { m["resumable"] = "true" }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := stagedCapabilityBody()
			if tt.mutate != nil {
				tt.mutate(body)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != apiPrefix+uploadCapabilitiesPath || r.Header.Get("mtk") != "private-mtk" || r.Header.Get("token") != "private-mtk" {
					t.Error("wrong read contract")
				}
				json.NewEncoder(w).Encode(map[string]any{"resCode": 1, "resData": body})
			}))
			defer server.Close()
			client := NewClient(server.URL, "user", "secret")
			client.setMTK("private-mtk")
			caps, err := client.QueryUploadCapabilitiesContext(context.Background())
			if calls.Load() != 1 {
				t.Fatal("capability query repeated")
			}
			if tt.valid {
				if err != nil || caps.Validate() != nil || caps.MaxTotalSize != 0 || caps.MaxChunks != 0 || caps.AbsoluteTimeoutMs != 0 || caps.AvailableBytes != ^uint64(0) || !caps.PersistentAcrossRestart {
					t.Fatalf("caps=%+v err=%v", caps, err)
				}
			} else {
				requireSafeDiagnostic(t, err, safediagnostic.OperationUploadCapabilities, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ClassProtocolInvalid)
			}
		})
	}
}

func TestStagedUploadPreservesExactBytesThenExplicitDetectAndOwnedCancel(t *testing.T) {
	original := inspectionTestJPEG(t, 7, 5)
	before := bytes.Clone(original)
	digest := sha256.Sum256(original)
	caps := stagedTestCapabilities()
	caps.MaxChunkSize = 128
	const alias, id = "owned-run:original-sha", "server-generated-upload-1"
	var received []byte
	var chunkCalls, detectCalls, cancelCalls int
	config := PictureTaskConfig{Params: []PictureTaskParameter{{Key: "keywords", Value: "unchanged synthetic question"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("mtk") != "mtk-only" || r.Header.Get("token") != "mtk-only" {
			t.Error("auth missing")
		}
		switch r.URL.Path {
		case apiPrefix + uploadPicturePath:
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatal(err)
			}
			defer r.MultipartForm.RemoveAll()
			f, h, err := r.FormFile("file")
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(f)
			f.Close()
			if h.Filename != "capture.jpg" || r.FormValue("purpose") != "image" || r.FormValue("clientRequestId") != alias || r.FormValue("sha256") != hex.EncodeToString(digest[:]) {
				t.Error("upload identity/bytes contract changed")
			}
			index, _ := strconv.Atoi(r.FormValue("chunkIndex"))
			total, _ := strconv.Atoi(r.FormValue("totalChunks"))
			if index != chunkCalls || r.FormValue("totalSize") != strconv.Itoa(len(original)) || r.FormValue("chunkSize") != strconv.Itoa(len(raw)) {
				t.Error("wrong sequential part metadata")
			}
			if index == 0 && r.FormValue("uploadId") != "" || index > 0 && r.FormValue("uploadId") != id {
				t.Error("wrong canonical upload binding")
			}
			received = append(received, raw...)
			chunkCalls++
			json.NewEncoder(w).Encode(map[string]any{"resCode": 1, "resData": map[string]any{"uploadId": id, "nextChunkIndex": strconv.Itoa(index + 1), "complete": index+1 == total, "filePath": "upload://ignored-private-alias"}})
		case apiPrefix + detectPictureTaskPath:
			detectCalls++
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["uploadId"] != id || body["taskId"] != "exact-task" || body["algorithmCode"] != "exact-algorithm" {
				t.Error("wrong detect target")
			}
			for _, key := range []string{"imageBase64", "imageUrl", "filePath"} {
				if _, ok := body[key]; ok {
					t.Errorf("forbidden detect field %s", key)
				}
			}
			encoded, _ := json.Marshal(body["taskConfig"])
			want, _ := json.Marshal(config)
			if !bytes.Equal(encoded, want) {
				t.Error("prompt/config changed")
			}
			fmt.Fprint(w, `{"resCode":1,"resData":{"algorithmCode":"exact-algorithm","areaList":[{"bDetected":true}]}}`)
		case apiPrefix + cancelPictureUploadPath:
			cancelCalls++
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if len(body) != 1 || body["uploadId"] != id {
				t.Error("cancel not exact owned canonical ID")
			}
			fmt.Fprint(w, `{"resCode":1,"resData":{}}`)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, "user", "secret")
	client.setMTK("mtk-only")
	upload, err := client.UploadPictureJPEGContext(context.Background(), StagedPictureUploadRequest{ClientRequestID: alias, JPEG: original, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	if !upload.Complete || upload.CleanupRef() != id || upload.NextChunkIndex != upload.TotalChunks || upload.SHA256 != hex.EncodeToString(digest[:]) || upload.SizeBytes != uint64(len(original)) {
		t.Fatalf("invalid upload result: %+v", upload)
	}
	if !bytes.Equal(original, before) || !bytes.Equal(original, received) {
		t.Fatal("original JPEG bytes changed")
	}
	if _, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{TaskID: "exact-task", AlgorithmCode: "exact-algorithm", UploadID: upload.UploadID, TaskConfig: config}); err != nil {
		t.Fatal(err)
	}
	if err := client.CancelPictureUploadContext(context.Background(), upload); err != nil {
		t.Fatal(err)
	}
	if detectCalls != 1 || cancelCalls != 1 || chunkCalls != int(upload.TotalChunks) {
		t.Fatal("write repeated")
	}
}

func TestStagedUploadFailureRetainsOwnedCleanupAndDoesNotRetry(t *testing.T) {
	original := inspectionTestJPEG(t, 3, 2)
	for _, tt := range []struct {
		name      string
		status    int
		body      string
		canonical string
		unknown   bool
	}{
		{"native-reject", 200, `{"resCode":0,"resMsg":[{"msgCode":"12314","msgText":"private-answer"}]}`, "", false},
		{"authentication", 401, `private response`, "", false},
		{"http5xx", 503, `private response`, "", true},
		{"malformed", 200, `{`, "", true},
		{"bad-ack", 200, `{"resCode":1,"resData":{"uploadId":"canonical-id","nextChunkIndex":"0","complete":false}}`, "canonical-id", true},
		{"unsafe-id", 200, `{"resCode":1,"resData":{"uploadId":"https://private/secret","nextChunkIndex":"1","complete":true}}`, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var uploads, cancels, logins atomic.Int32
			var cancelRef string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == apiPrefix+cancelPictureUploadPath {
					cancels.Add(1)
					var body map[string]string
					json.NewDecoder(r.Body).Decode(&body)
					cancelRef = body["uploadId"]
					fmt.Fprint(w, `{"resCode":1,"resData":{}}`)
					return
				}
				if r.URL.Path == apiPrefix+"/login/DoLogin" {
					logins.Add(1)
				}
				uploads.Add(1)
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			c := NewClient(server.URL, "user", "secret")
			upload, err := c.UploadPictureJPEGContext(context.Background(), StagedPictureUploadRequest{ClientRequestID: "stable-alias", JPEG: original, Capabilities: stagedTestCapabilities()})
			if err == nil || uploads.Load() != 1 || logins.Load() != 0 || upload.UploadID != tt.canonical || upload.ClientRequestID != "stable-alias" || upload.Complete {
				t.Fatal("write failure lost ownership or repeated")
			}
			d := safediagnostic.FromError(err)
			if d == nil || d.Operation != safediagnostic.OperationPictureUpload || d.HTTPStatus != tt.status {
				t.Fatalf("diagnostic=%+v", d)
			}
			var unknown *OutcomeUnknownError
			if errors.As(err, &unknown) != tt.unknown {
				t.Fatal("incorrect ambiguity marker")
			}
			if err := c.CancelPictureUploadContext(context.Background(), upload); err != nil {
				t.Fatal(err)
			}
			wantRef := tt.canonical
			if wantRef == "" {
				wantRef = "stable-alias"
			}
			if cancelRef != wantRef || cancels.Load() != 1 {
				t.Fatal("wrong owned cleanup ref")
			}
			encoded, _ := json.Marshal(d)
			for _, word := range []string{"private", "secret", "answer", "stable-alias", "canonical-id"} {
				if bytes.Contains(encoded, []byte(word)) {
					t.Fatal("unsafe diagnostic")
				}
			}
		})
	}
}

func TestStagedUploadChangedCanonicalIDStopsBeforeAnotherPart(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		id := "canonical-first"
		if n > 1 {
			id = "canonical-other"
		}
		json.NewEncoder(w).Encode(map[string]any{"resCode": 1, "resData": map[string]any{"uploadId": id, "nextChunkIndex": strconv.Itoa(int(n)), "complete": false}})
	}))
	defer server.Close()
	caps := stagedTestCapabilities()
	caps.MaxChunkSize = 128
	u, err := NewClient(server.URL, "", "").UploadPictureJPEGContext(context.Background(), StagedPictureUploadRequest{ClientRequestID: "stable", JPEG: inspectionTestJPEG(t, 3, 2), Capabilities: caps})
	if err == nil || count.Load() != 2 || u.UploadID != "canonical-first" || u.NextChunkIndex != 1 || u.Complete {
		t.Fatal("changed ID trusted or upload replayed")
	}
	requireSafeDiagnostic(t, err, safediagnostic.OperationPictureUpload, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ClassOutcomeUnknown)
}

func TestStagedUploadPreflightAndDetectExclusiveInputs(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); http.Error(w, "unexpected", 500) }))
	defer server.Close()
	c := NewClient(server.URL, "", "")
	jpeg := inspectionTestJPEG(t, 3, 2)
	for _, mutate := range []func(*StagedPictureUploadRequest){
		func(r *StagedPictureUploadRequest) { r.ClientRequestID = "https://private/secret" },
		func(r *StagedPictureUploadRequest) { r.Capabilities.AvailableForNewUploadsBytes = 0 },
		func(r *StagedPictureUploadRequest) { r.Capabilities.MaxTotalSize = 1 },
		func(r *StagedPictureUploadRequest) { r.Capabilities.MaxImagePixels = 1 },
		func(r *StagedPictureUploadRequest) { r.Capabilities.MaxEncodedImageBytes = 1 },
		func(r *StagedPictureUploadRequest) { r.Capabilities.MaxChunkSize = 1; r.Capabilities.MaxChunks = 1 },
		func(r *StagedPictureUploadRequest) { r.JPEG = []byte("invalid") },
	} {
		r := StagedPictureUploadRequest{ClientRequestID: "stable", JPEG: jpeg, Capabilities: stagedTestCapabilities()}
		mutate(&r)
		if _, err := c.UploadPictureJPEGContext(context.Background(), r); err == nil {
			t.Fatal("invalid upload dispatched")
		}
	}
	for _, r := range []PictureTaskDetectRequest{
		{TaskID: "task", AlgorithmCode: "alg"},
		{TaskID: "task", AlgorithmCode: "alg", JPEG: jpeg, UploadID: "canonical"},
		{TaskID: "task", AlgorithmCode: "alg", UploadID: "https://private/secret"},
	} {
		if _, err := c.DetectPictureTaskContext(context.Background(), r); !errors.Is(err, ErrInvalidInspectionRequest) {
			t.Fatal("nonexclusive or unsafe input allowed")
		}
	}
	if err := c.CancelPictureUploadContext(context.Background(), StagedPictureUpload{ClientRequestID: "stable", UploadID: "/private/path"}); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatal("unsafe cleanup allowed")
	}
	if count.Load() != 0 {
		t.Fatal("preflight made a request")
	}
}

func TestStagedOperationsBlockRedirectEvenWithCallerTransport(t *testing.T) {
	var escaped atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1); fmt.Fprint(w, `{"resCode":1}`) }))
	defer target.Close()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
	}))
	defer server.Close()
	c := NewClientWithHTTPClient(server.URL, "", "", &http.Client{})
	c.setMTK("secret-token")
	_, _ = c.QueryUploadCapabilitiesContext(context.Background())
	_, _ = c.UploadPictureJPEGContext(context.Background(), StagedPictureUploadRequest{ClientRequestID: "owned-alias", JPEG: inspectionTestJPEG(t, 3, 2), Capabilities: stagedTestCapabilities()})
	_ = c.CancelPictureUploadContext(context.Background(), StagedPictureUpload{ClientRequestID: "owned-alias"})
	_, _ = c.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{TaskID: "task", AlgorithmCode: "alg", UploadID: "canonical-id"})
	if calls.Load() != 4 || escaped.Load() != 0 {
		t.Fatal("redirect escaped or request repeated")
	}
}

func TestStagedUploadTransportFailureKeepsStableAliasAndOriginal(t *testing.T) {
	var count atomic.Int32
	c := NewClientWithHTTPClient("http://device.invalid", "", "", &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) { count.Add(1); return nil, context.DeadlineExceeded })})
	jpeg := inspectionTestJPEG(t, 3, 2)
	before := bytes.Clone(jpeg)
	u, err := c.UploadPictureJPEGContext(context.Background(), StagedPictureUploadRequest{ClientRequestID: "stable-before-first-write", JPEG: jpeg, Capabilities: stagedTestCapabilities()})
	if !errors.Is(err, context.DeadlineExceeded) || u.CleanupRef() != "stable-before-first-write" || u.UploadID != "" || count.Load() != 1 || !reflect.DeepEqual(jpeg, before) {
		t.Fatal("ambiguous first write lost ownership/original")
	}
	d := requireSafeDiagnostic(t, err, safediagnostic.OperationPictureUpload, safediagnostic.PhaseTransport, safediagnostic.ClassOutcomeUnknown)
	if d.ValidationCode != safediagnostic.ValidationDeadlineExpired {
		t.Fatal("deadline evidence lost")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", u, u), u.ClientRequestID) {
		t.Fatal("upload ownership printed by default")
	}
}

func TestCapabilitiesDoNotProveUploadIDDetectSupport(t *testing.T) {
	var detects, uploads, capabilities atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case apiPrefix + uploadCapabilitiesPath:
			capabilities.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"resCode": 1, "resData": stagedCapabilityBody()})
		case apiPrefix + uploadPicturePath:
			uploads.Add(1)
			fmt.Fprint(w, `{"resCode":1,"resData":{"uploadId":"owned-canonical","nextChunkIndex":"1","complete":true}}`)
		case apiPrefix + detectPictureTaskPath:
			detects.Add(1)
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["uploadId"] != "owned-canonical" {
				t.Error("missing explicit upload ID")
			}
			if _, fallback := body["imageBase64"]; fallback {
				t.Error("silent base64 fallback")
			}
			fmt.Fprint(w, `{"resCode":12314,"resMsg":[{"msgCode":"12314"}]}`)
		default:
			t.Error("unexpected request")
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, "", "")
	caps, err := c.QueryUploadCapabilitiesContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	upload, err := c.UploadPictureJPEGContext(context.Background(), StagedPictureUploadRequest{ClientRequestID: "owned-alias", JPEG: inspectionTestJPEG(t, 3, 2), Capabilities: caps})
	if err != nil || !upload.Complete {
		t.Fatal("fixture upload failed", err)
	}
	_, err = c.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{TaskID: "exact-task", AlgorithmCode: "exact-algorithm", UploadID: upload.UploadID})
	var rejected *V1Error
	if !errors.As(err, &rejected) || !rejected.KnownFailure() {
		t.Fatal("capabilities/upload acknowledgement falsely established detect support")
	}
	requireSafeDiagnostic(t, err, safediagnostic.OperationPictureDetect, safediagnostic.PhaseNativeResponse, safediagnostic.ClassNativeRejected)
	if detects.Load() != 1 || uploads.Load() != 1 || capabilities.Load() != 1 {
		t.Fatal("unsupported Detect retried or fell back")
	}
}

func TestOversizedUploadAcknowledgementKeepsAliasAndStops(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		fmt.Fprint(w, strings.Repeat("x", int(maxStagedPictureResponseBytes)+1))
	}))
	defer server.Close()
	upload, err := NewClient(server.URL, "", "").UploadPictureJPEGContext(context.Background(), StagedPictureUploadRequest{ClientRequestID: "owned-alias", JPEG: inspectionTestJPEG(t, 3, 2), Capabilities: stagedTestCapabilities()})
	if upload.CleanupRef() != "owned-alias" || count.Load() != 1 {
		t.Fatal("lost cleanup ownership or retried")
	}
	requireSafeDiagnostic(t, err, safediagnostic.OperationPictureUpload, safediagnostic.PhaseDecodeJSON, safediagnostic.ClassOutcomeUnknown)
}
