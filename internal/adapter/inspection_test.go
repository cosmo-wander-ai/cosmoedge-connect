package adapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestInspectionTransportUsesTypedDeviceContracts(t *testing.T) {
	jpegContent := inspectionTestJPEG(t, 3, 2)
	seen := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode %s body: %v", r.URL.Path, err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		seen[r.URL.Path] = true
		switch r.URL.Path {
		case "/gtw/cwai/Camera/GetPicture":
			assertInspectionBody(t, body, map[string]any{"videoChannelId": "camera-native-1"})
			fmt.Fprint(w, `{"resCode":1,"resData":{"url":"/web/2026/07/20/capture-1.jpg"}}`)
		case "/gtw/cwai/Algorithm/Page":
			assertInspectionBody(t, body, map[string]any{
				"algorithmUsage": "2", "pageNum": float64(1), "pageSize": float64(100),
			})
			fmt.Fprint(w, `{"resCode":1,"resData":{"total":1,"rows":[{"algorithmId":"vlm-native-1","algorithmName":"VLM","algorithmCategory":"inspection","algorithmUsage":"2","versions":{"gpuCode":"local","versionNumber":"1.2.3","status":1}}]}}`)
		case "/gtw/cwai/algorithm/layout/detail":
			assertInspectionBody(t, body, map[string]any{"id": "vlm-native-1"})
			fmt.Fprint(w, `{"resCode":1,"resData":{"algorithmCode":"vlm-native-1","algorithmName":"VLM","algorithmUsage":"2","confVersionId":"version-current","configVersionList":[{"id":"version-current","name":"当前版本","algorithmCode":"vlm-native-1","algorithmUpdateTime":1752998400000}]}}`)
		case "/gtw/cwai/aihost/PTaskCreate":
			assertInspectionBody(t, body, map[string]any{
				"taskId": "run-task-1", "algorithmCode": "vlm-native-1", "algorithmUpdateTime": "1752998400000",
				"taskConfig": map[string]any{"params": []any{map[string]any{"key": "generationStyle", "value": "strict"}}},
			})
			fmt.Fprint(w, `{"resCode":1,"resData":{}}`)
		case "/gtw/cwai/aihost/PTaskDetectPic":
			if _, present := body["imageUrl"]; present {
				t.Error("PTaskDetectPic body contains forbidden imageUrl")
			}
			if _, present := body["needRetImg"]; present {
				t.Error("PTaskDetectPic body contains ineffective needRetImg")
			}
			assertInspectionBody(t, body, map[string]any{
				"taskId": "run-task-1", "algorithmCode": "vlm-native-1",
				"imageBase64": base64.StdEncoding.EncodeToString(jpegContent),
				"taskConfig":  map[string]any{"params": []any{map[string]any{"key": "keywords", "value": "桌面是否整洁"}}},
			})
			fmt.Fprint(w, `{"resCode":1,"resData":{"algorithmCode":"vlm-native-1","fullPicture":"data:image/jpeg;base64,discarded","areaList":[{"areaId":"-1","areaName":"default","bDetected":true,"targetList":[{"box":{"x":0,"y":0,"width":0,"height":0},"confidence":[{"label":"是","confidence":1}]}]}]}}`)
		case "/gtw/cwai/aihost/PTaskCancle":
			assertInspectionBody(t, body, map[string]any{
				"taskId": "run-task-1", "algorithmCode": "vlm-native-1", "mvDebug": pictureTaskDebugMode,
			})
			fmt.Fprint(w, `{"resCode":1,"resData":{}}`)
		default:
			t.Errorf("unexpected device path %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "admin", "secret")
	picture, err := client.GetCameraPictureContext(context.Background(), "camera-native-1")
	if err != nil || picture.reference != "/web/2026/07/20/capture-1.jpg" {
		t.Fatalf("GetCameraPictureContext() = %#v, %v", picture, err)
	}
	algorithms, err := client.QueryPictureAlgorithmsContext(context.Background(), 1, 100)
	if err != nil {
		t.Fatalf("QueryPictureAlgorithmsContext() error = %v", err)
	}
	if algorithms.Total != 1 || len(algorithms.Rows) != 1 || algorithms.Rows[0].AlgorithmUsage != "2" ||
		algorithms.Rows[0].Version.VersionNumber != "1.2.3" {
		t.Fatalf("picture algorithms = %#v", algorithms)
	}
	detail, err := client.QueryAlgorithmLayoutDetailContext(context.Background(), "vlm-native-1")
	if err != nil {
		t.Fatalf("QueryAlgorithmLayoutDetailContext() error = %v", err)
	}
	if detail.AlgorithmCode != "vlm-native-1" || detail.ConfigVersionID != "version-current" ||
		len(detail.Versions) != 1 || detail.Versions[0].AlgorithmUpdateTime != "1752998400000" {
		t.Fatalf("algorithm layout detail = %#v", detail)
	}
	if err := client.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{
		TaskID: "run-task-1", AlgorithmCode: "vlm-native-1", AlgorithmUpdateTime: "1752998400000",
		TaskConfig: PictureTaskConfig{Params: []PictureTaskParameter{{Key: "generationStyle", Value: "strict"}}},
	}); err != nil {
		t.Fatalf("CreatePictureTaskContext() error = %v", err)
	}
	result, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{
		TaskID: "run-task-1", AlgorithmCode: "vlm-native-1", JPEG: jpegContent,
		TaskConfig: PictureTaskConfig{Params: []PictureTaskParameter{{Key: "keywords", Value: "桌面是否整洁"}}},
	})
	if err != nil {
		t.Fatalf("DetectPictureTaskContext() error = %v", err)
	}
	if result.AlgorithmCode != "vlm-native-1" || result.Timestamp != "" || len(result.Areas) != 1 ||
		len(result.Areas[0].Targets) != 1 || len(result.Areas[0].Targets[0].Confidence) != 1 ||
		result.Areas[0].Targets[0].Confidence[0].Label != "是" {
		t.Fatalf("detect result = %#v", result)
	}
	if err := client.CancelPictureTaskContext(context.Background(), PictureTaskCancelRequest{
		TaskID: "run-task-1", AlgorithmCode: "vlm-native-1",
	}); err != nil {
		t.Fatalf("CancelPictureTaskContext() error = %v", err)
	}

	for _, path := range []string{
		"/gtw/cwai/Camera/GetPicture", "/gtw/cwai/Algorithm/Page", "/gtw/cwai/algorithm/layout/detail", "/gtw/cwai/aihost/PTaskCreate",
		"/gtw/cwai/aihost/PTaskDetectPic", "/gtw/cwai/aihost/PTaskCancle",
	} {
		if !seen[path] {
			t.Fatalf("device path %s was not called", path)
		}
	}
}

func TestInspectionReadsReloginAndRetryOnce(t *testing.T) {
	tests := []struct {
		name string
		path string
		call func(*Client) error
	}{
		{
			name: "camera picture",
			path: "/gtw/cwai/Camera/GetPicture",
			call: func(client *Client) error {
				_, err := client.GetCameraPictureContext(context.Background(), "camera-native-1")
				return err
			},
		},
		{
			name: "picture algorithms",
			path: "/gtw/cwai/Algorithm/Page",
			call: func(client *Client) error {
				_, err := client.QueryPictureAlgorithmsContext(context.Background(), 1, 10)
				return err
			},
		},
		{
			name: "algorithm layout detail",
			path: "/gtw/cwai/algorithm/layout/detail",
			call: func(client *Client) error {
				_, err := client.QueryAlgorithmLayoutDetailContext(context.Background(), "vlm-native-1")
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var loginCalls int32
			var operationCalls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/gtw/cwai/login/DoLogin":
					atomic.AddInt32(&loginCalls, 1)
					fmt.Fprint(w, `{"resCode":1,"resData":{"mtk":"fresh-token"}}`)
				case test.path:
					call := atomic.AddInt32(&operationCalls, 1)
					if call == 1 {
						fmt.Fprint(w, `{"resCode":401,"resMsg":[{"msgText":"token expired","msgCode":"TOKEN_EXPIRED"}]}`)
						return
					}
					if got := r.Header.Get("mtk"); got != "fresh-token" {
						t.Errorf("retried mtk = %q, want fresh-token", got)
					}
					if test.path == "/gtw/cwai/Camera/GetPicture" {
						fmt.Fprint(w, `{"resCode":1,"resData":{"url":"/web/2026/07/20/fresh.jpg"}}`)
					} else if test.path == "/gtw/cwai/Algorithm/Page" {
						fmt.Fprint(w, `{"resCode":1,"resData":{"total":0,"rows":[]}}`)
					} else {
						fmt.Fprint(w, `{"resCode":1,"resData":{"algorithmCode":"vlm-native-1","algorithmUsage":"2","configVersionList":[{"algorithmCode":"vlm-native-1","algorithmUpdateTime":1752998400000}]}}`)
					}
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					http.Error(w, "unexpected", http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := NewClient(server.URL, "admin", "secret")
			client.setMTK("expired-token")
			if err := test.call(client); err != nil {
				t.Fatalf("read error = %v", err)
			}
			if got := atomic.LoadInt32(&loginCalls); got != 1 {
				t.Fatalf("login calls = %d, want 1", got)
			}
			if got := atomic.LoadInt32(&operationCalls); got != 2 {
				t.Fatalf("operation calls = %d, want 2", got)
			}
		})
	}
}

func TestPictureTaskOperationsDoNotRetryAndKeepOutcomeUnknown(t *testing.T) {
	jpegContent := inspectionTestJPEG(t, 2, 2)
	tests := []struct {
		name string
		path string
		call func(*Client) error
	}{
		{
			name: "create", path: createPictureTaskPath,
			call: func(client *Client) error {
				return client.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", AlgorithmUpdateTime: "1752998400000",
				})
			},
		},
		{
			name: "detect", path: detectPictureTaskPath,
			call: func(client *Client) error {
				_, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", JPEG: jpegContent,
				})
				return err
			},
		},
		{
			name: "cancel", path: cancelPictureTaskPath,
			call: func(client *Client) error {
				return client.CancelPictureTaskContext(context.Background(), PictureTaskCancelRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1",
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				fmt.Fprint(w, `{not-json`)
			}))
			defer server.Close()
			client := NewClient(server.URL, "admin", "secret")

			err := test.call(client)
			var unknown *OutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("error = %T %v, want OutcomeUnknownError", err, err)
			}
			if unknown.Path != test.path || unknown.Phase != "decode_response" {
				t.Fatalf("unknown = %#v", unknown)
			}
			if got := atomic.LoadInt32(&calls); got != 1 {
				t.Fatalf("calls = %d, want 1", got)
			}
		})
	}
}

func TestPictureTaskTransportFailureIsOutcomeUnknown(t *testing.T) {
	jpegContent := inspectionTestJPEG(t, 2, 2)
	transportErr := errors.New("connection stopped after dispatch")
	var calls int32
	client := NewClientWithHTTPClient("http://device.invalid", "admin", "secret", &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			atomic.AddInt32(&calls, 1)
			return nil, transportErr
		}),
	})
	tests := []struct {
		name string
		path string
		call func() error
	}{
		{
			name: "create", path: createPictureTaskPath,
			call: func() error {
				return client.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", AlgorithmUpdateTime: "1752998400000",
				})
			},
		},
		{
			name: "detect", path: detectPictureTaskPath,
			call: func() error {
				_, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", JPEG: jpegContent,
				})
				return err
			},
		},
		{
			name: "cancel", path: cancelPictureTaskPath,
			call: func() error {
				return client.CancelPictureTaskContext(context.Background(), PictureTaskCancelRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1",
				})
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			var unknown *OutcomeUnknownError
			if !errors.As(err, &unknown) || unknown.Path != test.path || unknown.Phase != "transport" ||
				!errors.Is(err, transportErr) {
				t.Fatalf("error = %T %v, want %s transport OutcomeUnknownError", err, err, test.path)
			}
			if got := atomic.LoadInt32(&calls); got != int32(index+1) {
				t.Fatalf("transport calls = %d, want %d", got, index+1)
			}
		})
	}
}

func TestPictureTaskDeadlineIsOutcomeUnknownAndNotRetried(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.CloseClientConnections()
		server.Close()
	}()
	client := NewClient(server.URL, "admin", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := client.CreatePictureTaskContext(ctx, PictureTaskCreateRequest{
		TaskID: "run-task-1", AlgorithmCode: "vlm-1", AlgorithmUpdateTime: "1752998400000",
	})
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) || unknown.Phase != "transport" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %T %v, want deadline OutcomeUnknownError", err, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestPictureTaskAuthRejectionDoesNotReloginOrRetry(t *testing.T) {
	jpegContent := inspectionTestJPEG(t, 2, 2)
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{
			name: "create",
			call: func(client *Client) error {
				return client.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", AlgorithmUpdateTime: "1752998400000",
				})
			},
		},
		{
			name: "detect",
			call: func(client *Client) error {
				_, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", JPEG: jpegContent,
				})
				return err
			},
		},
		{
			name: "cancel",
			call: func(client *Client) error {
				return client.CancelPictureTaskContext(context.Background(), PictureTaskCancelRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1",
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var operationCalls int32
			var loginCalls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/gtw/cwai/login/DoLogin" {
					atomic.AddInt32(&loginCalls, 1)
					fmt.Fprint(w, `{"resCode":1,"resData":{"mtk":"unexpected"}}`)
					return
				}
				atomic.AddInt32(&operationCalls, 1)
				fmt.Fprint(w, `{"resCode":401,"resMsg":[{"msgText":"token expired","msgCode":"TOKEN_EXPIRED"}]}`)
			}))
			defer server.Close()
			client := NewClient(server.URL, "admin", "secret")
			client.setMTK("expired-token")

			err := test.call(client)
			var v1Err *V1Error
			if !errors.As(err, &v1Err) || !v1Err.AuthenticationRejected() {
				t.Fatalf("error = %T %v, want auth-rejected V1Error", err, err)
			}
			var unknown *OutcomeUnknownError
			if errors.As(err, &unknown) {
				t.Fatalf("auth rejection became OutcomeUnknownError: %#v", unknown)
			}
			if got := atomic.LoadInt32(&operationCalls); got != 1 {
				t.Fatalf("operation calls = %d, want 1", got)
			}
			if got := atomic.LoadInt32(&loginCalls); got != 0 {
				t.Fatalf("login calls = %d, want 0", got)
			}
		})
	}
}

func TestPictureTaskHTTP5xxIsOutcomeUnknownAndNotRetried(t *testing.T) {
	jpegContent := inspectionTestJPEG(t, 2, 2)
	tests := []struct {
		name string
		path string
		call func(*Client) error
	}{
		{
			name: "create", path: createPictureTaskPath,
			call: func(client *Client) error {
				return client.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", AlgorithmUpdateTime: "1752998400000",
				})
			},
		},
		{
			name: "detect", path: detectPictureTaskPath,
			call: func(client *Client) error {
				_, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1", JPEG: jpegContent,
				})
				return err
			},
		},
		{
			name: "cancel", path: cancelPictureTaskPath,
			call: func(client *Client) error {
				return client.CancelPictureTaskContext(context.Background(), PictureTaskCancelRequest{
					TaskID: "run-task-1", AlgorithmCode: "vlm-1",
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				http.Error(w, "device failed after dispatch", http.StatusInternalServerError)
			}))
			defer server.Close()
			client := NewClient(server.URL, "admin", "secret")

			err := test.call(client)
			var unknown *OutcomeUnknownError
			if !errors.As(err, &unknown) || unknown.Path != test.path || unknown.Phase != "http_status" {
				t.Fatalf("error = %T %v, want %s HTTP outcome unknown", err, err, test.path)
			}
			if got := atomic.LoadInt32(&calls); got != 1 {
				t.Fatalf("calls = %d, want 1", got)
			}
		})
	}
}

func TestDetectTypedResponseFailureIsOutcomeUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resCode":1,"resData":{"algorithmCode":17,"timestamp":false,"areaList":"invalid"}}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, "admin", "secret")
	_, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{
		TaskID: "run-task-1", AlgorithmCode: "vlm-1", JPEG: inspectionTestJPEG(t, 2, 2),
	})
	var unknown *OutcomeUnknownError
	if !errors.As(err, &unknown) || unknown.Phase != "decode_typed_response" {
		t.Fatalf("error = %T %v, want typed-response OutcomeUnknownError", err, err)
	}
}

func TestInspectionTransportRejectsInvalidRequestsBeforeDeviceCall(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := NewClient(server.URL, "admin", "secret")

	if _, err := client.GetCameraPictureContext(context.Background(), " "); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("empty camera error = %v", err)
	}
	if _, err := client.QueryPictureAlgorithmsContext(context.Background(), 0, 100); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("invalid page error = %v", err)
	}
	if _, err := client.QueryAlgorithmLayoutDetailContext(context.Background(), " "); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("invalid algorithm detail error = %v", err)
	}
	if err := client.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{}); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("invalid create error = %v", err)
	}
	if err := client.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{
		TaskID: "run-task-1", AlgorithmCode: "vlm-1", AlgorithmUpdateTime: "not-device-millis",
	}); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("invalid algorithm update time error = %v", err)
	}
	if _, err := client.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{
		TaskID: "run-task-1", AlgorithmCode: "vlm-1", JPEG: []byte("https://untrusted.example/image.jpg"),
	}); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("URL-like detect input error = %v", err)
	}
	if err := client.CancelPictureTaskContext(context.Background(), PictureTaskCancelRequest{}); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("invalid cancel error = %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("device calls = %d, want 0", got)
	}
}

func TestDownloadFreshCameraPictureJPEGEnforcesOriginPathRedirectSizeAndJPEG(t *testing.T) {
	jpegContent := inspectionTestJPEG(t, 4, 3)
	var redirectTargetCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("mtk"); got != "" {
			t.Errorf("camera picture GET leaked mtk header")
		}
		if got := r.Header.Get("token"); got != "" {
			t.Errorf("camera picture GET leaked token header")
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("camera picture GET leaked Authorization header")
		}
		switch r.URL.Path {
		case "/web/2026/07/20/fresh.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(jpegContent)
		case "/web/2026/07/20/redirect.jpg":
			http.Redirect(w, r, "/web/2026/07/20/redirect-target.jpg", http.StatusFound)
		case "/web/2026/07/20/redirect-target.jpg":
			atomic.AddInt32(&redirectTargetCalls, 1)
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(jpegContent)
		case "/web/2026/07/20/large.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(jpegContent)
		case "/web/2026/07/20/chunked-large.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			_, _ = w.Write(jpegContent)
		case "/web/2026/07/20/invalid.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			fmt.Fprint(w, "not a jpeg")
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Use a caller-supplied client that follows redirects by default. The
	// inspection downloader must still override that behavior and fail closed.
	client := NewClientWithHTTPClient(server.URL, "admin", "secret", &http.Client{})
	client.setMTK("must-not-leak")
	got, err := client.DownloadFreshCameraPictureJPEG(
		context.Background(), CameraPicture{reference: "/web/2026/07/20/fresh.jpg"}, int64(len(jpegContent)),
	)
	if err != nil {
		t.Fatalf("relative fresh download error = %v", err)
	}
	if got.Width != 4 || got.Height != 3 || !bytes.Equal(got.Content, jpegContent) {
		t.Fatalf("downloaded JPEG = %dx%d %d bytes", got.Width, got.Height, len(got.Content))
	}
	if _, err := client.DownloadFreshCameraPictureJPEG(
		context.Background(), CameraPicture{reference: server.URL + "/web/2026/07/20/fresh.jpg"}, int64(len(jpegContent)),
	); err != nil {
		t.Fatalf("same-origin absolute download error = %v", err)
	}

	attackerCalls := int32(0)
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attackerCalls, 1)
		_, _ = w.Write(jpegContent)
	}))
	defer attacker.Close()

	rejections := []struct {
		name      string
		reference string
		want      error
	}{
		{name: "cross origin", reference: attacker.URL + "/web/2026/07/20/stolen.jpg", want: ErrUnsafePictureReference},
		{name: "scheme relative", reference: "//untrusted.example/web/2026/07/20/stolen.jpg", want: ErrUnsafePictureReference},
		{name: "non web", reference: "/event/2026/07/20/event.jpg", want: ErrUnsafePictureReference},
		{name: "cache fallback", reference: "/web/camera-native-1.jpg", want: ErrCachedPicture},
		{name: "path traversal", reference: "/web/2026/07/20/../stale.jpg", want: ErrUnsafePictureReference},
		{name: "encoded traversal", reference: "/web/2026/07/20/%2e%2e/stale.jpg", want: ErrUnsafePictureReference},
		{name: "query", reference: "/web/2026/07/20/fresh.jpg?source=other", want: ErrUnsafePictureReference},
		{name: "invalid date", reference: "/web/2026/13/40/fresh.jpg", want: ErrUnsafePictureReference},
	}
	for _, test := range rejections {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.DownloadFreshCameraPictureJPEG(
				context.Background(), CameraPicture{reference: test.reference}, int64(len(jpegContent)),
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if got := atomic.LoadInt32(&attackerCalls); got != 0 {
		t.Fatalf("cross-origin server calls = %d, want 0", got)
	}

	if _, err := client.DownloadFreshCameraPictureJPEG(
		context.Background(), CameraPicture{reference: "/web/2026/07/20/redirect.jpg"}, int64(len(jpegContent)),
	); !errors.Is(err, ErrPictureRedirect) {
		t.Fatalf("redirect error = %v, want ErrPictureRedirect", err)
	}
	if got := atomic.LoadInt32(&redirectTargetCalls); got != 0 {
		t.Fatalf("redirect target calls = %d, want 0", got)
	}
	if _, err := client.DownloadFreshCameraPictureJPEG(
		context.Background(), CameraPicture{reference: "/web/2026/07/20/large.jpg"}, int64(len(jpegContent)-1),
	); !errors.Is(err, ErrPictureTooLarge) {
		t.Fatalf("large response error = %v, want ErrPictureTooLarge", err)
	}
	if _, err := client.DownloadFreshCameraPictureJPEG(
		context.Background(), CameraPicture{reference: "/web/2026/07/20/chunked-large.jpg"}, int64(len(jpegContent)-1),
	); !errors.Is(err, ErrPictureTooLarge) {
		t.Fatalf("chunked large response error = %v, want ErrPictureTooLarge", err)
	}
	if _, err := client.DownloadFreshCameraPictureJPEG(
		context.Background(), CameraPicture{reference: "/web/2026/07/20/invalid.jpg"}, 1024,
	); !errors.Is(err, ErrInvalidPictureJPEG) {
		t.Fatalf("invalid JPEG error = %v, want ErrInvalidPictureJPEG", err)
	}
	if _, err := client.DownloadFreshCameraPictureJPEG(
		context.Background(), CameraPicture{reference: "/web/2026/07/20/fresh.jpg"}, maxInspectionJPEGBytes+1,
	); !errors.Is(err, ErrInvalidInspectionRequest) {
		t.Fatalf("unbounded maxBytes error = %v, want ErrInvalidInspectionRequest", err)
	}
}

func inspectionTestJPEG(t *testing.T, width, height int) []byte {
	t.Helper()
	value := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			value.Set(x, y, color.RGBA{R: uint8(40 + x), G: uint8(80 + y), B: 120, A: 255})
		}
	}
	var output bytes.Buffer
	if err := jpeg.Encode(&output, value, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode test JPEG: %v", err)
	}
	return output.Bytes()
}

func assertInspectionBody(t *testing.T, got, want map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request body = %#v, want %#v", got, want)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
