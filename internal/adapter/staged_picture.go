package adapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"mime/multipart"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/safediagnostic"
)

const (
	uploadCapabilitiesPath        = "/atomic/model/uploadCapabilities"
	uploadPicturePath             = "/atomic/model/uploadTemp"
	cancelPictureUploadPath       = "/atomic/model/cancelUpload"
	maxPictureUploadChunkBytes    = uint64(8 << 20)
	maxPictureUploadChunks        = uint64(1024)
	maxStagedPictureResponseBytes = int64(64 << 10)
	pictureUploadTimeout          = 120 * time.Second
)

var (
	uploadClientRequestPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	uploadIDPattern            = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// UploadCapabilities describes upload transport limits, not proof that the
// deployed PTaskDetectPic supports uploadId or any particular picture model.
// MaxTotalSize, MaxChunks and AbsoluteTimeoutMs use zero for no configured limit.
type UploadCapabilities struct {
	MaxTotalSize                uint64
	MaxChunkSize                uint64
	MaxChunks                   uint64
	IdleTimeoutMs               uint64
	AbsoluteTimeoutMs           uint64
	AvailableBytes              uint64
	ReserveBytes                uint64
	AvailableForNewUploadsBytes uint64
	ReservedBySessionsBytes     uint64
	ActiveSessions              uint64
	MaxEncodedImageBytes        uint64
	MaxImagePixels              uint64
	Resumable                   bool
	PersistentAcrossRestart     bool
}

func (c UploadCapabilities) Validate() error {
	if c.MaxChunkSize == 0 || c.IdleTimeoutMs == 0 || c.MaxEncodedImageBytes == 0 || c.MaxImagePixels == 0 {
		return ErrInvalidInspectionResponse
	}
	return nil
}

type StagedPictureUploadRequest struct {
	// The owner must durably bind this stable alias to its exact run and original
	// SHA before calling. It permits owned cleanup if the first response is lost.
	ClientRequestID string
	JPEG            []byte
	Capabilities    UploadCapabilities
}

// StagedPictureUpload is private ownership/recovery evidence. On failure it
// retains the original alias and any acknowledged canonical ID. A completed
// upload is single-use when consumed by Detect and is not an analysis result.
type StagedPictureUpload struct {
	ClientRequestID string `json:"clientRequestId"`
	UploadID        string `json:"uploadId,omitempty"`
	SHA256          string `json:"sha256"`
	SizeBytes       uint64 `json:"sizeBytes"`
	NextChunkIndex  uint64 `json:"nextChunkIndex"`
	TotalChunks     uint64 `json:"totalChunks"`
	Complete        bool   `json:"complete"`
}

func (StagedPictureUpload) String() string   { return "[owned-picture-upload]" }
func (StagedPictureUpload) GoString() string { return "adapter.StagedPictureUpload([redacted])" }

// CleanupRef returns only a valid owned reference, never a path or URL. The
// caller is responsible for retrieving this value from its own run journal.
func (u StagedPictureUpload) CleanupRef() string {
	if !uploadClientRequestPattern.MatchString(u.ClientRequestID) {
		return ""
	}
	if u.UploadID != "" {
		if uploadIDPattern.MatchString(u.UploadID) && u.UploadID != u.ClientRequestID {
			return u.UploadID
		}
		return ""
	}
	return u.ClientRequestID
}

// QueryUploadCapabilitiesContext is an authenticated read. As with other
// reads, only an explicit authentication rejection may cause one login/replay.
func (c *Client) QueryUploadCapabilitiesContext(ctx context.Context) (UploadCapabilities, error) {
	response, err := c.postWithContext(ctx, uploadCapabilitiesPath, map[string]any{})
	if err != nil {
		return UploadCapabilities{}, err
	}
	data, ok := response["resData"].(map[string]any)
	if !ok {
		return UploadCapabilities{}, invalidUploadCapabilities()
	}
	var result UploadCapabilities
	fields := []struct {
		name   string
		target *uint64
	}{
		{"maxTotalSize", &result.MaxTotalSize}, {"maxChunkSize", &result.MaxChunkSize},
		{"maxChunks", &result.MaxChunks}, {"idleTimeoutMs", &result.IdleTimeoutMs},
		{"absoluteTimeoutMs", &result.AbsoluteTimeoutMs}, {"availableBytes", &result.AvailableBytes},
		{"reserveBytes", &result.ReserveBytes}, {"availableForNewUploadsBytes", &result.AvailableForNewUploadsBytes},
		{"reservedBySessionsBytes", &result.ReservedBySessionsBytes}, {"activeSessions", &result.ActiveSessions},
		{"maxEncodedImageBytes", &result.MaxEncodedImageBytes}, {"maxImagePixels", &result.MaxImagePixels},
	}
	for _, field := range fields {
		value, valid := uploadUnsigned(data[field.name])
		if !valid {
			return UploadCapabilities{}, invalidUploadCapabilities()
		}
		*field.target = value
	}
	result.Resumable, ok = data["resumable"].(bool)
	if !ok {
		return UploadCapabilities{}, invalidUploadCapabilities()
	}
	result.PersistentAcrossRestart, ok = data["persistentAcrossRestart"].(bool)
	if !ok || result.Validate() != nil {
		return UploadCapabilities{}, invalidUploadCapabilities()
	}
	return result, nil
}

func invalidUploadCapabilities() error {
	return wrapRouteDiagnostic(ErrInvalidInspectionResponse, uploadCapabilitiesPath, safediagnostic.PhaseValidateTypedResponse, safediagnostic.ClassProtocolInvalid, safediagnostic.ValidationInvalidResponse, http.StatusOK)
}

// UploadPictureJPEGContext sends exact original JPEG bytes sequentially, with
// no resizing, re-encoding, automatic write retry or implicit cleanup. The final
// part performs server-side Complete. Its result must be retained even on error.
func (c *Client) UploadPictureJPEGContext(ctx context.Context, request StagedPictureUploadRequest) (StagedPictureUpload, error) {
	var result StagedPictureUpload
	if !uploadClientRequestPattern.MatchString(request.ClientRequestID) || request.Capabilities.Validate() != nil {
		return result, invalidInspectionRequest(uploadPicturePath)
	}
	width, height, err := validateJPEG(request.JPEG, maxInspectionJPEGBytes)
	if err != nil {
		return result, wrapRouteDiagnostic(err, uploadPicturePath, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidJPEG, 0)
	}
	size, caps := uint64(len(request.JPEG)), request.Capabilities
	chunkSize := min(caps.MaxChunkSize, maxPictureUploadChunkBytes)
	chunks := (size-1)/chunkSize + 1
	if size > caps.MaxEncodedImageBytes || size > caps.AvailableForNewUploadsBytes ||
		(caps.MaxTotalSize != 0 && size > caps.MaxTotalSize) || (caps.MaxChunks != 0 && chunks > caps.MaxChunks) || chunks > maxPictureUploadChunks ||
		uint64(width) > caps.MaxImagePixels/uint64(height) {
		return result, wrapRouteDiagnostic(ErrPictureTooLarge, uploadPicturePath, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationTooLarge, 0)
	}
	// Freeze a private copy so every chunk/hash refers to the same original
	// input. No filename or server path is accepted from the caller.
	content := bytes.Clone(request.JPEG)
	digest := sha256.Sum256(content)
	result = StagedPictureUpload{ClientRequestID: request.ClientRequestID, SHA256: hex.EncodeToString(digest[:]), SizeBytes: size, TotalChunks: chunks}
	ctx, cancel := inspectionOperationContext(ctx, pictureUploadTimeout)
	defer cancel()
	for index := uint64(0); index < chunks; {
		if err := ctx.Err(); err != nil {
			return result, wrapRouteDiagnostic(err, uploadPicturePath, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassUnavailable, "", 0)
		}
		end := min((index+1)*chunkSize, size)
		body, contentType, err := pictureMultipart(result, index, content[index*chunkSize:end])
		if err != nil {
			return result, wrapRouteDiagnostic(err, uploadPicturePath, safediagnostic.PhaseBeforeDispatch, safediagnostic.ClassLocalContractRejected, safediagnostic.ValidationInvalidRequest, 0)
		}
		response, err := c.doContentPostOnce(ctx, uploadPicturePath, body, contentType, true)
		if err != nil {
			return result, pictureTaskWriteError(uploadPicturePath, err)
		}
		data, ok := response["resData"].(map[string]any)
		if !ok {
			return result, newOutcomeUnknownError(uploadPicturePath, "decode_typed_response", ErrInvalidInspectionResponse)
		}
		id, idOK := data["uploadId"].(string)
		// Never substitute a changed or unsafe ID. The original alias remains
		// usable for cleanup if an invalid response follows a dispatched write.
		if !idOK || !uploadIDPattern.MatchString(id) || id == result.ClientRequestID || (result.UploadID != "" && result.UploadID != id) {
			return result, newOutcomeUnknownError(uploadPicturePath, "validate_typed_response", ErrInvalidInspectionResponse)
		}
		result.UploadID = id
		next, nextOK := uploadUnsigned(data["nextChunkIndex"])
		complete, completeOK := data["complete"].(bool)
		if !nextOK || next <= index || next > chunks || !completeOK || complete != (next == chunks) {
			return result, newOutcomeUnknownError(uploadPicturePath, "validate_typed_response", ErrInvalidInspectionResponse)
		}
		result.NextChunkIndex, result.Complete = next, complete
		index = next
	}
	return result, nil
}

func pictureMultipart(upload StagedPictureUpload, index uint64, chunk []byte) ([]byte, string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "capture.jpg")
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(chunk); err != nil {
		return nil, "", err
	}
	fields := []struct{ name, value string }{
		{"purpose", "image"}, {"chunkIndex", strconv.FormatUint(index, 10)}, {"totalChunks", strconv.FormatUint(upload.TotalChunks, 10)},
		{"totalSize", strconv.FormatUint(upload.SizeBytes, 10)}, {"chunkSize", strconv.Itoa(len(chunk))},
		{"clientRequestId", upload.ClientRequestID}, {"sha256", upload.SHA256},
	}
	if index != 0 {
		fields = append(fields, struct{ name, value string }{"uploadId", upload.UploadID})
	}
	for _, field := range fields {
		if err := writer.WriteField(field.name, field.value); err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return body.Bytes(), writer.FormDataContentType(), nil
}

// CancelPictureUploadContext cancels only the supplied owned handle/alias under
// this client's current principal. It does not cancel an AI task. It is never
// retried; a successful response can mean the upload was already consumed.
func (c *Client) CancelPictureUploadContext(ctx context.Context, upload StagedPictureUpload) error {
	reference := upload.CleanupRef()
	if reference == "" {
		return invalidInspectionRequest(cancelPictureUploadPath)
	}
	ctx, cancel := inspectionOperationContext(ctx, pictureTaskCancelTimeout)
	defer cancel()
	_, err := c.postWriteWithContext(ctx, cancelPictureUploadPath, struct {
		UploadID string `json:"uploadId"`
	}{reference})
	return pictureTaskWriteError(cancelPictureUploadPath, err)
}

func uploadUnsigned(raw any) (uint64, bool) {
	switch v := raw.(type) {
	case string:
		if len(v) == 0 || len(v) > 20 {
			return 0, false
		}
		for _, ch := range v {
			if ch < '0' || ch > '9' {
				return 0, false
			}
		}
		value, err := strconv.ParseUint(v, 10, 64)
		return value, err == nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1<<53-1 || v != math.Trunc(v) {
			return 0, false
		}
		return uint64(v), true
	default:
		return 0, false
	}
}

func stagedPictureRoute(route string) bool {
	return route == uploadCapabilitiesPath || route == uploadPicturePath || route == cancelPictureUploadPath
}
