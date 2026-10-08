package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/observation"
)

func (h *Handler) registerObservation() {
	h.mux.HandleFunc("POST "+Prefix+"captures", h.capture)
	h.mux.HandleFunc("POST "+Prefix+"observations", h.observe)
	h.mux.HandleFunc("GET "+Prefix+"observations/by-request/{requestID}", h.observationByRequest)
	h.mux.HandleFunc("GET "+Prefix+"observations/{operationRef}", h.observationStatus)
	h.mux.HandleFunc("GET "+Prefix+"media/{mediaRef}", h.observationMedia)
}

func (h *Handler) capture(w http.ResponseWriter, r *http.Request) {
	if !h.observationAvailable(w) {
		return
	}
	var q struct {
		RequestID  string `json:"requestId"`
		SourceName string `json:"sourceName"`
		SourceRef  string `json:"sourceRef,omitempty"`
		Question   string `json:"question,omitempty"`
	}
	if !h.decode(w, r, &q) {
		return
	}
	result, err := h.config.Observations.Observe(r.Context(), SessionOwner(r), observation.Request{
		RequestID: q.RequestID, SourceName: q.SourceName, SourceRef: q.SourceRef, Question: q.Question, Mode: observation.CaptureOnly,
	})
	if err != nil {
		h.observationError(w, err)
		return
	}
	h.replyObservation(w, result)
}
func (h *Handler) observationAvailable(w http.ResponseWriter) bool {
	if h.config.Observations == nil {
		h.fail(w, 503, "observation_unavailable", "临时看图暂时不可用。")
		return false
	}
	return true
}
func (h *Handler) observe(w http.ResponseWriter, r *http.Request) {
	if !h.observationAvailable(w) {
		return
	}
	var q observation.Request
	if !h.decode(w, r, &q) {
		return
	}
	if q.Mode != "" {
		h.observationError(w, observation.ErrInvalidRequest)
		return
	}
	result, err := h.config.Observations.Observe(r.Context(), SessionOwner(r), q)
	if err != nil {
		h.observationError(w, err)
		return
	}
	h.replyObservation(w, result)
}
func (h *Handler) observationStatus(w http.ResponseWriter, r *http.Request) {
	if !h.observationAvailable(w) {
		return
	}
	result, err := h.config.Observations.Get(r.Context(), SessionOwner(r), r.PathValue("operationRef"))
	if err != nil {
		h.observationError(w, err)
		return
	}
	h.replyObservation(w, result)
}
func (h *Handler) observationByRequest(w http.ResponseWriter, r *http.Request) {
	if !h.observationAvailable(w) {
		return
	}
	result, err := h.config.Observations.GetByRequest(r.Context(), SessionOwner(r), r.PathValue("requestID"))
	if err != nil {
		h.observationError(w, err)
		return
	}
	h.replyObservation(w, result)
}
func (h *Handler) observationMedia(w http.ResponseWriter, r *http.Request) {
	if !h.observationAvailable(w) {
		return
	}
	media, err := h.config.Observations.ReadMedia(r.Context(), SessionOwner(r), r.PathValue("mediaRef"))
	if err != nil {
		h.observationError(w, err)
		return
	}
	w.Header().Set("Content-Type", media.MIMEType)
	w.Header().Set("Content-Length", strconv.Itoa(len(media.Content)))
	w.Header().Set("X-Content-SHA256", media.SHA256)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(media.Content)
}
func (h *Handler) replyObservation(w http.ResponseWriter, r observation.Result) {
	attachments := make([]map[string]any, 0, len(r.Attachments))
	for _, a := range r.Attachments {
		attachments = append(attachments, map[string]any{"mediaRef": a.MediaRef, "path": Prefix + "media/" + a.MediaRef,
			"contentType": a.MIMEType, "sha256": a.SHA256, "sizeBytes": a.SizeBytes, "status": a.Status, "expiresAt": a.ExpiresAt})
	}
	message := "已受理本次看图，正在获取并分析指定机位图片。"
	if r.Kind == "capture" {
		message = "正在获取机位画面。"
		if !r.Pending {
			if r.Status == "captured" {
				message = "已取得机位原图。"
			} else {
				message = "这次未能取得可用原图。"
			}
		}
	} else if !r.Pending {
		answer := "无法判断"
		switch string(r.Answer) {
		case "yes":
			answer = "是"
		case "no":
			answer = "否"
		}
		message = fmt.Sprintf("关于“%s”：%s。", r.Question, answer)
		if len(r.Facts) > 0 {
			message += strings.Join(r.Facts, "；") + "。"
		}
		if r.ObservedAt != nil {
			message += "图片获取时间：" + r.ObservedAt.Format("2006-01-02T15:04:05Z07:00") + "；这不是经核准的摄像头画面时间。"
		}
		if r.SourceKind == "test_video" {
			message += "该机位为测试视频，结论只对应本次取得的测试帧。"
		}
		if len(r.Limitations) > 0 {
			message += strings.Join(r.Limitations, "；") + "。"
		}
	}
	h.reply(w, 200, map[string]any{"ok": true, "pending": r.Pending, "operationRef": r.OperationRef, "requestId": r.RequestID,
		"pollPath": Prefix + "observations/" + r.OperationRef, "observation": r, "attachments": attachments, "userMessage": message})
}
func (h *Handler) observationError(w http.ResponseWriter, err error) {
	var selection *observation.SourceSelectionError
	switch {
	case errors.As(err, &selection):
		h.reply(w, 409, map[string]any{"ok": false, "code": selection.Code, "interactionRequired": true, "choices": selection.Choices, "userMessage": "请明确选择一个机位；本次没有取图或提交分析。"})
	case errors.Is(err, observation.ErrInvalidRequest):
		h.fail(w, 400, "invalid_observation", "请明确机位、要观察的问题和本次请求。")
	case errors.Is(err, observation.ErrNotFound):
		h.fail(w, 404, "observation_not_found", "本次对话没有这条观察记录。")
	case errors.Is(err, observation.ErrConflict):
		h.fail(w, 409, "observation_conflict", "该请求编号已有不同内容，请续查原请求；本次没有重复分析。")
	case errors.Is(err, observation.ErrConnectionRequired):
		h.fail(w, 409, "connection_required", "设备尚未接入或当前不可达，请在本机接入页面核对连接。")
	case errors.Is(err, observation.ErrMediaUnavailable):
		h.fail(w, 410, "image_unavailable", "原图片已失效或暂时无法取得；文字结果仍可续查。")
	default:
		h.fail(w, 503, "observation_unavailable", "当前观察结果暂时无法可靠取得，请续查原请求。")
	}
}
