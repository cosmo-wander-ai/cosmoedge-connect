package adapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image/jpeg"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

const (
	getCameraPicturePath     = "/Camera/GetPicture"
	queryPictureAlgorithms   = "/Algorithm/Page"
	queryAlgorithmLayoutPath = "/algorithm/layout/detail"
	createPictureTaskPath    = "/aihost/PTaskCreate"
	detectPictureTaskPath    = "/aihost/PTaskDetectPic"
	cancelPictureTaskPath    = "/aihost/PTaskCancle"
	pictureAlgorithmUsage    = "2"
	pictureTaskCancelTimeout = 30 * time.Second
	pictureTaskDetectTimeout = 60 * time.Second
	pictureTaskCreateTimeout = 120 * time.Second
	maxInspectionJPEGBytes   = int64(16 << 20)
	pictureTaskDebugMode     = "Cosmo-Debug"
)

var (
	ErrInvalidInspectionRequest  = errors.New("invalid inspection transport request")
	ErrInvalidInspectionResponse = errors.New("invalid inspection transport response")
	ErrUnsafePictureReference    = errors.New("unsafe camera picture reference")
	ErrCachedPicture             = errors.New("camera picture is a cached fallback")
	ErrPictureRedirect           = errors.New("camera picture redirect is not allowed")
	ErrPictureTooLarge           = errors.New("camera picture exceeds the byte limit")
	ErrInvalidPictureJPEG        = errors.New("camera picture is not a valid JPEG")

	freshPicturePathPattern    = regexp.MustCompile(`^/web/([0-9]{4})/([0-9]{2})/([0-9]{2})/([A-Za-z0-9][A-Za-z0-9._-]*\.jpg)$`)
	cachedPicturePathPattern   = regexp.MustCompile(`^/web/[^/]+\.jpg$`)
	algorithmUpdateTimePattern = regexp.MustCompile(`^[0-9]{13}$`)
)

// CameraPicture is the opaque media reference returned by Camera/GetPicture.
// It is not safe to fetch until DownloadFreshCameraPictureJPEG validates it.
type CameraPicture struct {
	reference string
}

func (CameraPicture) String() string   { return "[camera-picture-reference]" }
func (CameraPicture) GoString() string { return "adapter.CameraPicture([redacted])" }

// InspectionJPEG is a bounded, decoded-config-verified JPEG response.
type InspectionJPEG struct {
	Content []byte
	Width   int
	Height  int
}

// PictureAlgorithmPage is the typed Algorithm/Page projection for algorithms
// whose device-side usage is picture analysis (algorithmUsage=2).
type PictureAlgorithmPage struct {
	Total int
	Rows  []PictureAlgorithm
}

type PictureAlgorithm struct {
	AlgorithmID       string                  `json:"algorithmId"`
	AlgorithmName     string                  `json:"algorithmName"`
	AlgorithmCategory string                  `json:"algorithmCategory"`
	AlgorithmUsage    string                  `json:"algorithmUsage"`
	CategoryName      string                  `json:"categoryName"`
	Supplier          string                  `json:"supplier"`
	ConfigType        string                  `json:"configType"`
	ReleaseTime       string                  `json:"releaseTime"`
	ConfigVersionName string                  `json:"confVersionName"`
	VersionCount      int                     `json:"versionCount"`
	Authorization     int                     `json:"authStatus"`
	RunningStatus     int                     `json:"runningStatus"`
	Version           PictureAlgorithmVersion `json:"versions"`
}

type PictureAlgorithmVersion struct {
	GPUCode       string `json:"gpuCode"`
	VersionNumber string `json:"versionNumber"`
	Status        int    `json:"status"`
}

// AlgorithmLayoutDetail is the authoritative device-side version projection
// used when creating one run-scoped picture task. Algorithm/Page identifies a
// candidate algorithm, but its summary DTO does not carry algorithmUpdateTime.
type AlgorithmLayoutDetail struct {
	AlgorithmCode   string
	AlgorithmName   string
	AlgorithmUsage  string
	ConfigVersionID string
	Versions        []AlgorithmLayoutVersion
}

type AlgorithmLayoutVersion struct {
	ID                  string
	Name                string
	AlgorithmCode       string
	AlgorithmUpdateTime string
}

type PictureTaskParameter struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type PictureTaskConfig struct {
	Params []PictureTaskParameter `json:"params,omitempty"`
}

type PictureTaskCreateRequest struct {
	TaskID              string
	AlgorithmCode       string
	AlgorithmUpdateTime string
	TaskConfig          PictureTaskConfig
}

// PictureTaskDetectRequest accepts exactly one of original JPEG bytes or a
// previously completed owned UploadID. Neither option permits an image URL.
type PictureTaskDetectRequest struct {
	TaskID        string
	AlgorithmCode string
	JPEG          []byte
	UploadID      string
	TaskConfig    PictureTaskConfig
}

type PictureTaskCancelRequest struct {
	TaskID        string
	AlgorithmCode string
}

type PictureTaskDetectResult struct {
	AlgorithmCode string
	Timestamp     string
	Areas         []PictureTaskArea
}

type PictureTaskArea struct {
	AreaID   string              `json:"areaId"`
	AreaName string              `json:"areaName"`
	Detected bool                `json:"bDetected"`
	Targets  []PictureTaskTarget `json:"targetList"`
}

type PictureTaskTarget struct {
	Box         PictureTaskBox          `json:"box"`
	LogicResult *bool                   `json:"bLogicResult,omitempty"`
	Confidence  []PictureTaskConfidence `json:"confidence,omitempty"`
}

type PictureTaskBox struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type PictureTaskConfidence struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
}

// GetCameraPictureContext asks the device for one camera picture reference.
// The v1 endpoint is treated as an authenticated read and may relogin and
// replay once only after an explicit authentication rejection.
func (c *Client) GetCameraPictureContext(ctx context.Context, videoChannelID string) (CameraPicture, error) {
	if strings.TrimSpace(videoChannelID) == "" {
		return CameraPicture{}, invalidInspectionRequest(getCameraPicturePath)
	}
	response, err := c.postWithContext(ctx, getCameraPicturePath, map[string]string{
		"videoChannelId": videoChannelID,
	})
	if err != nil {
		return CameraPicture{}, err
	}
	var data struct {
		URL string `json:"url"`
	}
	if err := decodeInspectionData(response, &data); err != nil {
		return CameraPicture{}, wrapRouteDiagnostic(ErrInvalidInspectionResponse, getCameraPicturePath, safediagnostic.PhaseDecodeTypedResponse, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, http.StatusOK)
	}
	if strings.TrimSpace(data.URL) == "" {
		return CameraPicture{}, wrapRouteDiagnostic(ErrInvalidInspectionResponse, getCameraPicturePath, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, http.StatusOK)
	}
	return CameraPicture{reference: data.URL}, nil
}

// QueryPictureAlgorithmsContext returns only device algorithms registered for
// picture analysis. Authentication rejection may relogin and replay once.
func (c *Client) QueryPictureAlgorithmsContext(ctx context.Context, pageNum, pageSize int) (PictureAlgorithmPage, error) {
	if pageNum < 1 || pageSize < 1 || pageSize > 1000 {
		return PictureAlgorithmPage{}, ErrInvalidInspectionRequest
	}
	response, err := c.postWithContext(ctx, queryPictureAlgorithms, map[string]any{
		"algorithmUsage": pictureAlgorithmUsage,
		"pageNum":        pageNum,
		"pageSize":       pageSize,
	})
	if err != nil {
		return PictureAlgorithmPage{}, err
	}
	var data struct {
		Total int                `json:"total"`
		Rows  []PictureAlgorithm `json:"rows"`
	}
	if err := decodeInspectionData(response, &data); err != nil || data.Total < len(data.Rows) {
		return PictureAlgorithmPage{}, ErrInvalidInspectionResponse
	}
	for _, algorithm := range data.Rows {
		if strings.TrimSpace(algorithm.AlgorithmID) == "" || algorithm.AlgorithmUsage != pictureAlgorithmUsage {
			return PictureAlgorithmPage{}, ErrInvalidInspectionResponse
		}
	}
	return PictureAlgorithmPage{Total: data.Total, Rows: data.Rows}, nil
}

// QueryAlgorithmLayoutDetailContext resolves the exact version timestamp
// required by PTaskCreate. It is an authenticated read and may relogin and
// replay once only after an explicit authentication rejection.
func (c *Client) QueryAlgorithmLayoutDetailContext(ctx context.Context, algorithmID string) (AlgorithmLayoutDetail, error) {
	algorithmID = strings.TrimSpace(algorithmID)
	if algorithmID == "" || len(algorithmID) > 256 || strings.ContainsAny(algorithmID, "\r\n\x00") {
		return AlgorithmLayoutDetail{}, ErrInvalidInspectionRequest
	}
	response, err := c.postWithContext(ctx, queryAlgorithmLayoutPath, map[string]string{"id": algorithmID})
	if err != nil {
		return AlgorithmLayoutDetail{}, err
	}
	var data struct {
		AlgorithmCode   string `json:"algorithmCode"`
		AlgorithmName   string `json:"algorithmName"`
		AlgorithmUsage  string `json:"algorithmUsage"`
		ConfigVersionID string `json:"confVersionId"`
		Versions        []struct {
			ID                  string          `json:"id"`
			Name                string          `json:"name"`
			AlgorithmCode       string          `json:"algorithmCode"`
			AlgorithmUpdateTime json.RawMessage `json:"algorithmUpdateTime"`
		} `json:"configVersionList"`
	}
	if err := decodeInspectionData(response, &data); err != nil || data.AlgorithmCode != algorithmID ||
		data.AlgorithmUsage != pictureAlgorithmUsage || len(data.Versions) == 0 {
		return AlgorithmLayoutDetail{}, ErrInvalidInspectionResponse
	}
	detail := AlgorithmLayoutDetail{
		AlgorithmCode: data.AlgorithmCode, AlgorithmName: data.AlgorithmName,
		AlgorithmUsage: data.AlgorithmUsage, ConfigVersionID: data.ConfigVersionID,
		Versions: make([]AlgorithmLayoutVersion, len(data.Versions)),
	}
	seen := make(map[string]struct{}, len(data.Versions))
	for index, version := range data.Versions {
		updateTime, parseErr := parseAlgorithmUpdateTime(version.AlgorithmUpdateTime)
		algorithmCode := version.AlgorithmCode
		// The product writes new versions' algorithmCode as a number, while
		// layout/detail projects only string values and emits an empty field.
		// Versions belong to this exact requested parent algorithm. Inherit only
		// an absent code; an explicit conflicting code remains invalid.
		if algorithmCode == "" {
			algorithmCode = data.AlgorithmCode
		}
		if parseErr != nil || algorithmCode != data.AlgorithmCode {
			return AlgorithmLayoutDetail{}, ErrInvalidInspectionResponse
		}
		if _, duplicate := seen[updateTime]; duplicate {
			return AlgorithmLayoutDetail{}, ErrInvalidInspectionResponse
		}
		seen[updateTime] = struct{}{}
		detail.Versions[index] = AlgorithmLayoutVersion{
			ID: version.ID, Name: version.Name, AlgorithmCode: algorithmCode,
			AlgorithmUpdateTime: updateTime,
		}
	}
	return detail, nil
}

// CreatePictureTaskContext creates a run-scoped temporary picture task. It is
// never retried automatically because a failed transport or response decode
// cannot prove that the device did not create the task.
func (c *Client) CreatePictureTaskContext(ctx context.Context, request PictureTaskCreateRequest) error {
	if !validPictureTaskBinding(request.TaskID, request.AlgorithmCode) ||
		!algorithmUpdateTimePattern.MatchString(request.AlgorithmUpdateTime) || validatePictureTaskConfig(request.TaskConfig) != nil {
		return invalidInspectionRequest(createPictureTaskPath)
	}
	ctx, cancel := inspectionOperationContext(ctx, pictureTaskCreateTimeout)
	defer cancel()
	body := struct {
		TaskID              string             `json:"taskId"`
		AlgorithmCode       string             `json:"algorithmCode"`
		AlgorithmUpdateTime string             `json:"algorithmUpdateTime"`
		TaskConfig          *PictureTaskConfig `json:"taskConfig,omitempty"`
	}{
		TaskID: request.TaskID, AlgorithmCode: request.AlgorithmCode,
		AlgorithmUpdateTime: request.AlgorithmUpdateTime,
		TaskConfig:          optionalPictureTaskConfig(request.TaskConfig),
	}
	_, err := c.postWriteWithContext(ctx, createPictureTaskPath, body)
	return pictureTaskWriteError(createPictureTaskPath, err)
}

// DetectPictureTaskContext synchronously analyzes one local JPEG. The request
// has no imageUrl escape hatch and is never retried automatically.
func (c *Client) DetectPictureTaskContext(ctx context.Context, request PictureTaskDetectRequest) (PictureTaskDetectResult, error) {
	if !validPictureTaskBinding(request.TaskID, request.AlgorithmCode) || validatePictureTaskConfig(request.TaskConfig) != nil {
		return PictureTaskDetectResult{}, invalidInspectionRequest(detectPictureTaskPath)
	}
	if (len(request.JPEG) == 0) == (request.UploadID == "") || (request.UploadID != "" && !uploadIDPattern.MatchString(request.UploadID)) {
		return PictureTaskDetectResult{}, invalidInspectionRequest(detectPictureTaskPath)
	}
	if len(request.JPEG) != 0 {
		if _, _, err := validateJPEG(request.JPEG, maxInspectionJPEGBytes); err != nil {
			return PictureTaskDetectResult{}, invalidInspectionRequest(detectPictureTaskPath)
		}
	}
	ctx, cancel := inspectionOperationContext(ctx, pictureTaskDetectTimeout)
	defer cancel()
	body := struct {
		TaskID        string             `json:"taskId"`
		AlgorithmCode string             `json:"algorithmCode"`
		ImageBase64   string             `json:"imageBase64,omitempty"`
		UploadID      string             `json:"uploadId,omitempty"`
		TaskConfig    *PictureTaskConfig `json:"taskConfig,omitempty"`
	}{
		TaskID: request.TaskID, AlgorithmCode: request.AlgorithmCode,
		ImageBase64: base64.StdEncoding.EncodeToString(request.JPEG),
		UploadID:    request.UploadID,
		TaskConfig:  optionalPictureTaskConfig(request.TaskConfig),
	}
	response, err := c.postWriteWithContext(ctx, detectPictureTaskPath, body)
	if err != nil {
		return PictureTaskDetectResult{}, pictureTaskWriteError(detectPictureTaskPath, err)
	}
	var data struct {
		AlgorithmCode string            `json:"algorithmCode"`
		Timestamp     string            `json:"timestamp"`
		Areas         []PictureTaskArea `json:"areaList"`
		FullPicture   string            `json:"fullPicture"`
	}
	if err := decodeInspectionData(response, &data); err != nil {
		return PictureTaskDetectResult{}, newOutcomeUnknownError(detectPictureTaskPath, "decode_typed_response", err)
	}
	// The deployed BM1688 picture-task response does not provide a timestamp.
	// Freshness is bound to the independently acquired camera evidence, so the
	// transport must validate the algorithm and result areas without inventing
	// a timestamp requirement that the device contract does not satisfy.
	if data.AlgorithmCode != request.AlgorithmCode || len(data.Areas) == 0 {
		return PictureTaskDetectResult{}, newOutcomeUnknownError(
			detectPictureTaskPath, "validate_typed_response", ErrInvalidInspectionResponse,
		)
	}
	return PictureTaskDetectResult{
		AlgorithmCode: data.AlgorithmCode,
		Timestamp:     data.Timestamp,
		Areas:         data.Areas,
	}, nil
}

// CancelPictureTaskContext removes one run-scoped temporary picture task. The
// internal device compatibility marker is supplied here rather than exposed to
// a Skill or runtime request. Cancellation is never retried automatically.
func (c *Client) CancelPictureTaskContext(ctx context.Context, request PictureTaskCancelRequest) error {
	if !validPictureTaskBinding(request.TaskID, request.AlgorithmCode) {
		return invalidInspectionRequest(cancelPictureTaskPath)
	}
	ctx, cancel := inspectionOperationContext(ctx, pictureTaskCancelTimeout)
	defer cancel()
	body := struct {
		TaskID        string `json:"taskId"`
		AlgorithmCode string `json:"algorithmCode"`
		MVDebug       string `json:"mvDebug"`
	}{
		TaskID: request.TaskID, AlgorithmCode: request.AlgorithmCode, MVDebug: pictureTaskDebugMode,
	}
	_, err := c.postWriteWithContext(ctx, cancelPictureTaskPath, body)
	return pictureTaskWriteError(cancelPictureTaskPath, err)
}

// DownloadFreshCameraPictureJPEG resolves and downloads a Camera/GetPicture
// reference only from the configured device media origin. It accepts the
// dated live-capture shape /web/YYYY/MM/DD/<name>.jpg, rejects the device's
// root-level cached fallback, disables redirects, and validates bounded JPEG
// bytes before returning them.
func (c *Client) DownloadFreshCameraPictureJPEG(ctx context.Context, picture CameraPicture, maxBytes int64) (InspectionJPEG, error) {
	if maxBytes < 1 || maxBytes > maxInspectionJPEGBytes {
		return InspectionJPEG{}, pictureDownloadDiagnostic(ErrInvalidInspectionRequest, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidRequest, 0)
	}
	target, err := c.safeFreshPictureURL(picture.reference)
	if err != nil {
		validation := safediagnostic.ValidationUnsafeReference
		if errors.Is(err, ErrCachedPicture) {
			validation = safediagnostic.ValidationCachedReference
		}
		return InspectionJPEG{}, pictureDownloadDiagnostic(err, safediagnostic.PhaseValidateReference, safediagnostic.ClassLocalContractRejected, validation, 0)
	}
	ctx, cancel := inspectionOperationContext(ctx, defaultTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return InspectionJPEG{}, pictureDownloadDiagnostic(ErrUnsafePictureReference, safediagnostic.PhaseValidateReference, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationUnsafeReference, 0)
	}
	request.Header.Set("Accept", "image/jpeg")

	httpClient := http.Client{}
	if c.client != nil {
		httpClient = *c.client
	}
	// Camera media is public on current devices. Do not let a caller-owned jar
	// attach unrelated session cookies to the media request.
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return InspectionJPEG{}, pictureDownloadDiagnostic(newPictureDownloadError(err), safediagnostic.PhaseDownload, safediagnostic.ClassTransportFailed, "", 0)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return InspectionJPEG{}, pictureDownloadDiagnostic(ErrPictureRedirect, safediagnostic.PhaseDownload, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationRedirect, response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return InspectionJPEG{}, pictureDownloadDiagnostic(ErrInvalidInspectionResponse, safediagnostic.PhaseNativeResponse, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, response.StatusCode)
	}
	if response.ContentLength > maxBytes {
		return InspectionJPEG{}, pictureDownloadDiagnostic(ErrPictureTooLarge, safediagnostic.PhaseDownload, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationTooLarge, response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return InspectionJPEG{}, pictureDownloadDiagnostic(newPictureDownloadError(err), safediagnostic.PhaseDownload, safediagnostic.ClassTransportFailed, "", response.StatusCode)
	}
	width, height, err := validateJPEG(content, maxBytes)
	if errors.Is(err, ErrPictureTooLarge) {
		return InspectionJPEG{}, pictureDownloadDiagnostic(err, safediagnostic.PhaseValidateJPEG, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationTooLarge, response.StatusCode)
	}
	if err != nil {
		return InspectionJPEG{}, pictureDownloadDiagnostic(ErrInvalidPictureJPEG, safediagnostic.PhaseValidateJPEG, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidJPEG, response.StatusCode)
	}
	return InspectionJPEG{Content: content, Width: width, Height: height}, nil
}

func (c *Client) safeFreshPictureURL(reference string) (*url.URL, error) {
	trusted, err := url.Parse(c.ImageBaseURL())
	if err != nil || !validMediaOrigin(trusted) {
		return nil, ErrUnsafePictureReference
	}
	referenceURL, err := url.Parse(strings.TrimSpace(reference))
	if err != nil || referenceURL.User != nil || referenceURL.RawQuery != "" || referenceURL.Fragment != "" ||
		referenceURL.RawPath != "" || strings.Contains(referenceURL.EscapedPath(), "%") {
		return nil, ErrUnsafePictureReference
	}
	if referenceURL.IsAbs() {
		if !sameOrigin(trusted, referenceURL) {
			return nil, ErrUnsafePictureReference
		}
	} else if referenceURL.Host != "" || !strings.HasPrefix(referenceURL.Path, "/") {
		return nil, ErrUnsafePictureReference
	}
	if path.Clean(referenceURL.Path) != referenceURL.Path {
		return nil, ErrUnsafePictureReference
	}
	if cachedPicturePathPattern.MatchString(referenceURL.Path) {
		return nil, ErrCachedPicture
	}
	match := freshPicturePathPattern.FindStringSubmatch(referenceURL.Path)
	if len(match) != 5 {
		return nil, ErrUnsafePictureReference
	}
	if _, err := time.Parse("2006/01/02", strings.Join(match[1:4], "/")); err != nil {
		return nil, ErrUnsafePictureReference
	}
	if !referenceURL.IsAbs() {
		origin := *trusted
		origin.Path, origin.RawPath, origin.RawQuery, origin.Fragment = "/", "", "", ""
		referenceURL = origin.ResolveReference(referenceURL)
	}
	if !sameOrigin(trusted, referenceURL) {
		return nil, ErrUnsafePictureReference
	}
	return referenceURL, nil
}

func validMediaOrigin(value *url.URL) bool {
	return value != nil && (value.Scheme == "http" || value.Scheme == "https") && value.Host != "" &&
		value.User == nil && value.RawQuery == "" && value.Fragment == ""
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) && effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	return "80"
}

func decodeInspectionData(response map[string]any, destination any) error {
	data, ok := response["resData"]
	if !ok || data == nil {
		return ErrInvalidInspectionResponse
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return err
	}
	return nil
}

func inspectionOperationContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, timeout)
}

func validPictureTaskBinding(taskID, algorithmCode string) bool {
	return strings.TrimSpace(taskID) != "" && strings.TrimSpace(algorithmCode) != ""
}

func validatePictureTaskConfig(config PictureTaskConfig) error {
	seen := make(map[string]struct{}, len(config.Params))
	for _, parameter := range config.Params {
		if parameter.Key == "" || len(parameter.Key) > 512 || len(parameter.Value) > 2056 {
			return ErrInvalidInspectionRequest
		}
		if _, duplicate := seen[parameter.Key]; duplicate {
			return ErrInvalidInspectionRequest
		}
		seen[parameter.Key] = struct{}{}
	}
	return nil
}

func optionalPictureTaskConfig(config PictureTaskConfig) *PictureTaskConfig {
	if len(config.Params) == 0 {
		return nil
	}
	copyConfig := PictureTaskConfig{Params: append([]PictureTaskParameter(nil), config.Params...)}
	return &copyConfig
}

func parseAlgorithmUpdateTime(raw json.RawMessage) (string, error) {
	value := strings.TrimSpace(string(raw))
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		var decoded string
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return "", err
		}
		value = decoded
	}
	if !algorithmUpdateTimePattern.MatchString(value) {
		return "", ErrInvalidInspectionResponse
	}
	return value, nil
}

func pictureTaskWriteError(operationPath string, err error) error {
	if err == nil {
		return nil
	}
	var deviceErr *V1Error
	// ResCode belongs to the native API; only an actual HTTP 5xx makes this
	// response ambiguous. Native rejections may use codes well above 500.
	if errors.As(err, &deviceErr) && deviceErr.HTTPStatus >= http.StatusInternalServerError {
		return newOutcomeUnknownError(operationPath, "http_status", err)
	}
	return err
}

func invalidInspectionRequest(route string) error {
	return wrapRouteDiagnostic(ErrInvalidInspectionRequest, route, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidRequest, 0)
}

func pictureDownloadDiagnostic(cause error, phase, class, validation string, httpStatus int) error {
	if errors.Is(cause, context.DeadlineExceeded) {
		validation = safediagnostic.ValidationDeadlineExpired
	}
	return safediagnostic.Wrap(cause, safediagnostic.Diagnostic{Operation: safediagnostic.OperationPictureDownload, Phase: phase, Class: class, ValidationCode: validation, HTTPStatus: httpStatus})
}

func validateJPEG(content []byte, maxBytes int64) (int, int, error) {
	if len(content) == 0 {
		return 0, 0, ErrInvalidPictureJPEG
	}
	if int64(len(content)) > maxBytes {
		return 0, 0, ErrPictureTooLarge
	}
	config, err := jpeg.DecodeConfig(bytes.NewReader(content))
	if err != nil || config.Width < 1 || config.Height < 1 {
		return 0, 0, ErrInvalidPictureJPEG
	}
	return config.Width, config.Height, nil
}

type pictureDownloadError struct {
	cause error
}

func (pictureDownloadError) Error() string {
	return "camera picture download failed"
}

func (err pictureDownloadError) Unwrap() error {
	return err.cause
}

func newPictureDownloadError(cause error) error {
	return pictureDownloadError{cause: cause}
}
