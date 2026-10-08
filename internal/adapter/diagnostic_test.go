package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

func requireSafeDiagnostic(t *testing.T, err error, operation, phase, class string) *safediagnostic.Diagnostic {
	t.Helper()
	d := safediagnostic.FromError(err)
	if d == nil || d.Validate() != nil || d.Operation != operation || d.Phase != phase || d.Class != class {
		t.Fatalf("diagnostic = %#v, want %s/%s/%s", d, operation, phase, class)
	}
	raw, _ := json.Marshal(d)
	for _, forbidden := range []string{"password", "private", "credential", "secret", "answer", "http://", "https://", "/web/"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("diagnostic leaked %q", forbidden)
		}
	}
	return d
}

func TestCameraCaptureNativeCodeAndResponseStages(t *testing.T) {
	tests := []struct {
		name, body, phase, class string
		code                     string
		invalid                  bool
	}{
		{"native-string", `{"resCode":0,"resMsg":[{"msgCode":"12314","msgText":"http://user:opaque@device/private?key=hidden answer"}]}`, safediagnostic.PhaseNativeResponse, safediagnostic.ClassNativeRejected, "12314", false},
		{"native-number", `{"resCode":0,"resMsg":[{"msgCode":12314}]}`, safediagnostic.PhaseNativeResponse, safediagnostic.ClassNativeRejected, "12314", false},
		{"unsafe-message", `{"resCode":0,"resMsg":[{"msgCode":"private-answer"}]}`, safediagnostic.PhaseNativeResponse, safediagnostic.ClassNativeRejected, "", false},
		{"malformed-json", `{`, safediagnostic.PhaseDecodeJSON, safediagnostic.ClassProtocolInvalid, "", false},
		{"missing-rescode", `{"resData":{}}`, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ClassProtocolInvalid, "", true},
		{"typed-decode", `{"resCode":1,"resData":{"url":17}}`, safediagnostic.PhaseDecodeTypedResponse, safediagnostic.ClassProtocolInvalid, "", true},
		{"no-reference", `{"resCode":1,"resData":{"url":""}}`, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ClassProtocolInvalid, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, tt.body) }))
			defer server.Close()
			_, err := NewClient(server.URL, "", "").GetCameraPictureContext(context.Background(), "owned-camera")
			d := requireSafeDiagnostic(t, err, safediagnostic.OperationCameraPicture, tt.phase, tt.class)
			if d.HTTPStatus != 200 || d.MsgCode != tt.code || calls.Load() != 1 {
				t.Fatalf("diagnostic=%#v calls=%d", d, calls.Load())
			}
			if tt.class == safediagnostic.ClassNativeRejected && (d.ResCode == nil || *d.ResCode != 0) {
				t.Fatal("native zero code lost")
			}
			if tt.class != safediagnostic.ClassNativeRejected && d.ResCode != nil {
				t.Fatal("invented native result code")
			}
			if tt.invalid && !errors.Is(err, ErrInvalidInspectionResponse) {
				t.Fatal("sentinel lost")
			}
		})
	}
}

func TestNativeBusinessCodesAreNotHTTPStatusesAndWritesNeverRetry(t *testing.T) {
	jpeg := inspectionTestJPEG(t, 2, 2)
	calls := []struct {
		operation string
		call      func(*Client) error
	}{
		{safediagnostic.OperationPictureCreate, func(c *Client) error {
			return c.CreatePictureTaskContext(context.Background(), PictureTaskCreateRequest{TaskID: "task", AlgorithmCode: "algorithm", AlgorithmUpdateTime: "1752998400000"})
		}},
		{safediagnostic.OperationPictureDetect, func(c *Client) error {
			_, err := c.DetectPictureTaskContext(context.Background(), PictureTaskDetectRequest{TaskID: "task", AlgorithmCode: "algorithm", JPEG: jpeg})
			return err
		}},
		{safediagnostic.OperationPictureCancel, func(c *Client) error {
			return c.CancelPictureTaskContext(context.Background(), PictureTaskCancelRequest{TaskID: "task", AlgorithmCode: "algorithm"})
		}},
		{safediagnostic.OperationTaskSwitch, func(c *Client) error {
			_, err := c.postWriteWithContext(context.Background(), "/Task/SwitchTask", map[string]any{})
			return err
		}},
		{safediagnostic.OperationDeploymentSave, func(c *Client) error {
			_, err := c.postWriteWithContext(context.Background(), "/task/saveOrUpdate", map[string]any{})
			return err
		}},
	}
	for _, call := range calls {
		for _, response := range []struct {
			name    string
			status  int
			body    string
			class   string
			unknown bool
		}{
			{"native-high", 200, `{"resCode":12314,"resMsg":[{"msgCode":"12314","msgText":"private answer"}]}`, safediagnostic.ClassNativeRejected, false},
			{"http500", 500, `{"resCode":0,"resMsg":[{"msgCode":"12314"}]}`, safediagnostic.ClassOutcomeUnknown, true},
			{"malformed-envelope", 200, `{"resCode":"private"}`, safediagnostic.ClassOutcomeUnknown, true},
		} {
			t.Run(call.operation+"/"+response.name, func(t *testing.T) {
				var count atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					count.Add(1)
					w.WriteHeader(response.status)
					fmt.Fprint(w, response.body)
				}))
				defer server.Close()
				err := call.call(NewClient(server.URL, "admin", "password"))
				phase := safediagnostic.PhaseNativeResponse
				if response.name == "malformed-envelope" {
					phase = safediagnostic.PhaseValidateTypedResponse
				}
				d := requireSafeDiagnostic(t, err, call.operation, phase, response.class)
				if d.HTTPStatus != response.status || count.Load() != 1 {
					t.Fatalf("status=%d calls=%d", d.HTTPStatus, count.Load())
				}
				var native *V1Error
				var unknown *OutcomeUnknownError
				if response.name == "native-high" {
					if !errors.As(err, &native) || !native.KnownFailure() || errors.As(err, &unknown) || d.ResCode == nil || *d.ResCode != 12314 {
						t.Fatal("native rejection reclassified")
					}
				} else if d.ResCode != nil {
					t.Fatal("HTTP code or malformed envelope became native code")
				}
				if response.unknown && (strings.HasPrefix(call.operation, "picture_") || response.name == "malformed-envelope") && !errors.As(err, &unknown) {
					t.Fatal("unknown write marker lost")
				}
			})
		}
	}
}

func TestFreshPictureDownloadFailureDiagnostics(t *testing.T) {
	tests := []struct {
		name, reference, body, phase, class, validation string
		status                                          int
		sentinel                                        error
	}{
		{"cached", "/web/camera.jpg", "", safediagnostic.PhaseValidateReference, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationCachedReference, 0, ErrCachedPicture},
		{"unsafe", "https://user:password@device/private?credential=secret", "", safediagnostic.PhaseValidateReference, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationUnsafeReference, 0, ErrUnsafePictureReference},
		{"redirect", "/web/2026/09/07/capture.jpg", "", safediagnostic.PhaseDownload, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationRedirect, 302, ErrPictureRedirect},
		{"http-error", "/web/2026/09/07/capture.jpg", "private answer", safediagnostic.PhaseNativeResponse, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, 404, ErrInvalidInspectionResponse},
		{"invalid-jpeg", "/web/2026/09/07/capture.jpg", "private answer", safediagnostic.PhaseValidateJPEG, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidJPEG, 200, ErrInvalidPictureJPEG},
		{"too-large", "/web/2026/09/07/capture.jpg", strings.Repeat("x", 2048), safediagnostic.PhaseDownload, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationTooLarge, 200, ErrPictureTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.Header().Set("Location", "https://user:password@device/private")
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			_, err := NewClient(server.URL, "", "").DownloadFreshCameraPictureJPEG(context.Background(), CameraPicture{reference: tt.reference}, 1024)
			d := requireSafeDiagnostic(t, err, safediagnostic.OperationPictureDownload, tt.phase, tt.class)
			if !errors.Is(err, tt.sentinel) || d.HTTPStatus != tt.status || d.ValidationCode != tt.validation || d.ResCode != nil {
				t.Fatalf("diagnostic=%#v sentinel=%v", d, errors.Is(err, tt.sentinel))
			}
			wantCalls := int32(1)
			if tt.status == 0 {
				wantCalls = 0
			}
			if count.Load() != wantCalls {
				t.Fatalf("calls=%d", count.Load())
			}
		})
	}
}

type diagnosticTransport func(*http.Request) (*http.Response, error)

func (f diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type diagnosticBrokenBody struct{}

func (diagnosticBrokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (diagnosticBrokenBody) Close() error             { return nil }

func TestCaptureAndDownloadTransportDiagnosticPreservesCause(t *testing.T) {
	for _, download := range []bool{false, true} {
		c := NewClientWithHTTPClient("http://device.invalid", "", "", &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })})
		var err error
		op, phase := safediagnostic.OperationCameraPicture, safediagnostic.PhaseTransport
		if download {
			op, phase = safediagnostic.OperationPictureDownload, safediagnostic.PhaseDownload
			_, err = c.DownloadFreshCameraPictureJPEG(context.Background(), CameraPicture{reference: "/web/2026/09/07/capture.jpg"}, 1024)
		} else {
			_, err = c.GetCameraPictureContext(context.Background(), "camera")
		}
		d := requireSafeDiagnostic(t, err, op, phase, safediagnostic.ClassTransportFailed)
		if !errors.Is(err, context.DeadlineExceeded) || d.ValidationCode != safediagnostic.ValidationDeadlineExpired {
			t.Fatal("deadline cause lost")
		}
	}
	c := NewClientWithHTTPClient("http://device.invalid", "", "", &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: diagnosticBrokenBody{}}, nil
	})})
	_, err := c.DownloadFreshCameraPictureJPEG(context.Background(), CameraPicture{reference: "/web/2026/09/07/capture.jpg"}, 1024)
	d := requireSafeDiagnostic(t, err, safediagnostic.OperationPictureDownload, safediagnostic.PhaseDownload, safediagnostic.ClassTransportFailed)
	if !errors.Is(err, io.ErrUnexpectedEOF) || d.HTTPStatus != 200 {
		t.Fatal("body read cause lost")
	}
}
