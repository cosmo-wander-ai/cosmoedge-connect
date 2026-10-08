package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operations/deployment"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/operator/ledger"
)

type deploymentRequest struct {
	RequestID     string `json:"requestId"`
	SourceName    string `json:"sourceName"`
	AlgorithmName string `json:"algorithmName"`
	Enabled       *bool  `json:"enabled"`
}

func (h *Handler) registerDeployment() {
	h.mux.HandleFunc("POST "+Prefix+"deployments", h.prepareDeployment)
	h.mux.HandleFunc("POST "+Prefix+"deployments/confirm", h.confirmDeployment)
	h.mux.HandleFunc("POST "+Prefix+"deployments/review", h.reviewDeployment)
	h.mux.HandleFunc("POST "+Prefix+"deployments/cancel", h.cancelDeployment)
	h.mux.HandleFunc("GET "+Prefix+"deployments/by-request/{requestID}", h.deploymentByRequest)
	h.mux.HandleFunc("GET "+Prefix+"deployments/{operationRef}", h.deploymentStatus)
}
func (h *Handler) prepareDeployment(w http.ResponseWriter, r *http.Request) {
	if h.config.Deployments == nil {
		h.fail(w, 503, "deployment_unavailable", "当前候选尚未提供持续部署，请先查询现有状态。")
		return
	}
	var q deploymentRequest
	if !h.decode(w, r, &q) {
		return
	}
	if q.Enabled == nil || strings.TrimSpace(q.SourceName) == "" || strings.TrimSpace(q.AlgorithmName) == "" {
		h.fail(w, 400, "target_required", "请明确要操作的机位和算法。")
		return
	}
	c, ok := h.connection(w, r)
	if !ok {
		return
	}
	sid, aid := "", ""
	sources, algorithms := 0, 0
	for _, s := range c.Snapshot().Cameras {
		if strings.EqualFold(strings.TrimSpace(q.SourceName), s.Name) {
			sid = s.ID
			sources++
		}
	}
	list, err := h.readAlgorithms(r.Context(), c)
	if err != nil {
		h.fail(w, 502, "catalog_unavailable", "算法目录暂时无法完整读取。")
		return
	}
	for _, a := range list {
		if strings.EqualFold(strings.TrimSpace(q.AlgorithmName), a.Name) {
			aid = a.ID
			algorithms++
		}
	}
	if sources != 1 || algorithms != 1 {
		h.fail(w, 409, "target_ambiguous_or_missing", "没有找到唯一对应的机位和算法，请从当前目录明确选择。")
		return
	}
	p, err := h.config.Deployments.Prepare(r.Context(), SessionOwner(r), deployment.Request{RequestID: q.RequestID, SourceID: sid, AlgorithmID: aid, Enabled: *q.Enabled})
	if err != nil {
		h.deploymentError(w, err)
		return
	}
	p.SourceID = publicRef("source", p.SourceID)
	p.AlgorithmID = publicRef("algorithm", p.AlgorithmID)
	if p.State == "needs_input" {
		h.reply(w, 200, map[string]any{"ok": false, "interactionRequired": false, "proposalCreated": false, "supportedInteraction": "none", "configurationRequirement": p, "requestId": q.RequestID, "userMessage": "该算法还需要明确配置：" + strings.Join(p.Missing, "；") + "。当前入口没有可用的配置页面，尚未创建方案。"})
		return
	}
	if p.State != "proposed" {
		status, err := h.config.Deployments.Status(r.Context(), SessionOwner(r), p.ActionRef)
		if err != nil {
			h.deploymentError(w, err)
			return
		}
		h.replyDeploymentStatus(w, status)
		return
	}
	message := deploymentProposalMessage(p)
	h.replyDeploymentProposal(w, 200, map[string]any{"ok": true, "interactionRequired": true, "proposalCreated": true, "confirmationMode": "local_page", "supportedInteraction": "deployment_confirmation", "operationRef": p.ActionRef, "requestId": q.RequestID, "proposal": p}, message)
}

// Proposal and page-opening receipts describe this proposal's disposition.
// Preparation may have inspected saved configuration, but these replies do
// not contain a current device-state readback. Keep that boundary explicit.
func (h *Handler) replyDeploymentProposal(w http.ResponseWriter, status int, response map[string]any, message string) {
	response["deploymentEvidence"] = map[string]any{"resultScope": "proposal_only", "targetScope": "original_proposal", "currentScope": "not_provided", "currentReadbackProvided": false}
	response["userMessage"] = message
	h.reply(w, status, response)
}

func deploymentProposalMessage(p deployment.Proposal) string {
	verb := "启用"
	if !p.Enabled {
		verb = "停用"
	}
	message := fmt.Sprintf("将在“%s”机位%s“%s”。", p.SourceName, verb, p.AlgorithmName)
	if p.ExistingBinding {
		message += "沿用已有参数和时间计划。"
	} else {
		message += "将新建这项任务，使用设备默认参数和区域。"
	}
	message += "请在本机页面确认。"
	return message
}
func (h *Handler) confirmDeployment(w http.ResponseWriter, r *http.Request) {
	// The model-facing bearer/session protocol cannot attest a user click.
	// This legacy endpoint must never consume even a previously issued token.
	h.fail(w, 409, "local_confirmation_required", "聊天接口不能确认设备变更。请打开本机核对页，由用户在页面中确认；本次没有派发。")
}

func (h *Handler) reviewDeployment(w http.ResponseWriter, r *http.Request) {
	if h.config.Deployments == nil {
		h.fail(w, 503, "deployment_unavailable", "持续部署暂时不可用。")
		return
	}
	var q struct {
		OperationRef string `json:"operationRef"`
	}
	if !h.decode(w, r, &q) {
		return
	}
	status, err := h.config.Deployments.Status(r.Context(), SessionOwner(r), q.OperationRef)
	if err != nil {
		h.deploymentError(w, err)
		return
	}
	if status.State != "proposed" || status.Target.ConfirmationToken == "" {
		h.replyDeploymentStatus(w, status)
		return
	}
	if h.config.OpenDeploymentReview == nil || h.config.OpenDeploymentReview(r.Context(), SessionOwner(r), q.OperationRef) != nil {
		h.replyDeploymentProposal(w, 503, map[string]any{"ok": false, "code": "local_review_unavailable", "operationRef": q.OperationRef, "confirmationMode": "local_page", "pageOpened": false}, "暂时打不开确认页，待办已保留。")
		return
	}
	h.replyDeploymentProposal(w, 200, map[string]any{"ok": true, "interactionRequired": true, "operationRef": q.OperationRef, "confirmationMode": "local_page", "supportedInteraction": "deployment_confirmation", "pageOpened": true}, "确认页已打开，请核对后确认。")
}

func (h *Handler) cancelDeployment(w http.ResponseWriter, r *http.Request) {
	if h.config.Deployments == nil {
		h.fail(w, 503, "deployment_unavailable", "持续部署暂时不可用。")
		return
	}
	var q struct {
		OperationRef string `json:"operationRef"`
	}
	if !h.decode(w, r, &q) {
		return
	}
	if strings.TrimSpace(q.OperationRef) == "" {
		h.fail(w, 400, "invalid_deployment", "请明确要取消的待办。")
		return
	}
	// Cancel is an atomic transition of this owner's unconfirmed proposal. If
	// confirmation won the race, inspect that same operation instead of trying
	// to stop it or obtaining another confirmation on the user's behalf.
	err := h.config.Deployments.Cancel(r.Context(), SessionOwner(r), q.OperationRef)
	if err != nil && !errors.Is(err, ledger.ErrConflict) {
		h.deploymentError(w, err)
		return
	}
	status, err := h.config.Deployments.Status(r.Context(), SessionOwner(r), q.OperationRef)
	if err != nil {
		h.deploymentError(w, err)
		return
	}
	cancelled := status.State == "blocked" && status.Reason == "cancelled_by_user"
	h.replyDeploymentResult(w, status, &cancelled)
}
func (h *Handler) deploymentStatus(w http.ResponseWriter, r *http.Request) {
	if h.config.Deployments == nil {
		h.fail(w, 503, "deployment_unavailable", "持续部署暂时不可用。")
		return
	}
	status, err := h.config.Deployments.Status(r.Context(), SessionOwner(r), r.PathValue("operationRef"))
	if err != nil {
		h.deploymentError(w, err)
		return
	}
	h.replyDeploymentStatus(w, status)
}
func (h *Handler) deploymentByRequest(w http.ResponseWriter, r *http.Request) {
	if h.config.Deployments == nil {
		h.fail(w, 503, "deployment_unavailable", "持续部署暂时不可用。")
		return
	}
	status, err := h.config.Deployments.GetByRequest(r.Context(), SessionOwner(r), r.PathValue("requestID"))
	if err != nil {
		h.deploymentError(w, err)
		return
	}
	h.replyDeploymentStatus(w, status)
}
func (h *Handler) replyDeploymentStatus(w http.ResponseWriter, s deployment.Status) {
	h.replyDeploymentResult(w, s, nil)
}

func (h *Handler) replyDeploymentResult(w http.ResponseWriter, s deployment.Status, cancelled *bool) {
	s.Target.SourceID = publicRef("source", s.Target.SourceID)
	s.Target.AlgorithmID = publicRef("algorithm", s.Target.AlgorithmID)
	if s.State == "proposed" {
		s.Target.State = s.State // This branch returns an active proposal, not a target snapshot.
	}
	if s.State == "proposed" && s.Target.ConfirmationToken == "" {
		h.replyDeploymentProposal(w, 200, map[string]any{"ok": false, "code": "local_confirmation_unavailable", "operationRef": s.ActionRef, "proposalCreated": true, "proposal": s.Target, "confirmationMode": "local_page", "supportedInteraction": "none", "pageOpened": false}, "这次待办的确认已失效，不能继续执行。")
		return
	}
	if s.State == "proposed" && s.Target.ConfirmationToken != "" {
		h.replyDeploymentProposal(w, 200, map[string]any{"ok": true, "interactionRequired": true, "proposalCreated": true, "confirmationMode": "local_page", "supportedInteraction": "deployment_confirmation", "operationRef": s.ActionRef, "proposal": s.Target}, deploymentProposalMessage(s.Target))
		return
	}
	s.Target.ConfirmationToken = ""
	s.Target.State = ""
	if s.OriginalVerification != nil {
		// Copy before redaction: a formatter must not mutate retained service facts.
		original := *s.OriginalVerification
		original.Progress = append([]deployment.Progress(nil), original.Progress...)
		for i := range original.Progress {
			original.Progress[i].NodeID = publicRef("node", original.Progress[i].NodeID)
		}
		s.OriginalVerification = &original
	}
	if s.Current != nil {
		current := *s.Current
		current.Progress = append([]deployment.Progress(nil), current.Progress...)
		s.Current = &current
		s.Current.SourceID = publicRef("source", s.Current.SourceID)
		s.Current.AlgorithmID = publicRef("algorithm", s.Current.AlgorithmID)
		s.Current.TaskID = publicRef("task", s.Current.TaskID)
		for i := range s.Current.Progress {
			s.Current.Progress[i].NodeID = publicRef("node", s.Current.Progress[i].NodeID)
		}
	}
	pending := s.State == "queued" || s.State == "claimed" || s.State == "dispatching" || s.State == "verifying"
	message := deploymentStatusMessage(s, pending)
	response := map[string]any{"ok": s.Class == "completed" || pending || s.State == "proposed", "pending": pending, "confirmationMode": "local_page", "supportedInteraction": "none", "pageOpened": false, "operationRef": s.ActionRef, "pollPath": Prefix + "deployments/" + s.ActionRef, "deployment": s,
		"deploymentEvidence": map[string]any{"counterScope": "operation_lifetime", "deviceWriteScope": "configuration_and_enable_switch_accounting", "resultScope": "original_operation", "currentScope": "readback_at_observed_at", "originalVerificationScope": "immutable_sealed_readback", "targetScope": "original_proposal"}}
	response["userMessage"] = message
	statusCode := http.StatusOK
	if cancelled != nil {
		response["cancelled"], response["ok"] = *cancelled, *cancelled
		if *cancelled {
			response["userMessage"] = "已取消这次待办。"
		} else {
			statusCode = http.StatusConflict
			response["code"] = "deployment_not_cancellable"
			response["userMessage"] = "这次操作已确认或结束，不能再作为待办取消。"
			if s.Reason == "proposal_expired" {
				response["userMessage"] = "这次待办已经过期。"
			}
		}
	}
	h.reply(w, statusCode, response)
}

// Keep execution history and current facts distinct without making the user
// read the ledger accounting rules. All snapshots and counters remain in the
// structured deployment response for follow-up questions.
func deploymentStatusMessage(s deployment.Status, pending bool) string {
	target := "这项任务"
	if s.Target.SourceName != "" && s.Target.AlgorithmName != "" {
		target = "“" + s.Target.SourceName + "”的“" + s.Target.AlgorithmName + "”"
	}
	if pending {
		return target + "的操作已确认，正在处理。"
	}
	parts := []string{}
	switch s.State {
	case "unknown":
		parts = append(parts, target+"的执行结果还未确认。")
	case "blocked":
		switch s.Reason {
		case "cancelled_by_user":
			parts = append(parts, "这次待办已取消。")
		case "proposal_expired":
			parts = append(parts, "这次待办已过期。")
		case "deployment_rejected":
			if s.DiagnosticMessage != "" {
				parts = append(parts, s.DiagnosticMessage)
			} else {
				parts = append(parts, "设备未接受这次操作。")
			}
		default:
			parts = append(parts, "这次操作未完成。")
		}
	case "completed":
		if s.OriginalVerification == nil && s.Current == nil {
			parts = append(parts, "这次操作已有完成记录。")
		}
	default:
		parts = append(parts, "这次操作尚未完成。")
	}
	original := s.OriginalVerification
	changed := original != nil && s.Current != nil && original.Enabled >= 0 && s.Current.Enabled >= 0 && original.Enabled != s.Current.Enabled
	if original != nil && (s.Current == nil || changed) {
		fact := "此前的处理状态未完全确认。"
		if original.Exists && original.ConfigurationMatch {
			if original.Enabled == 1 && original.Runtime == "processing" {
				fact = "此前已确认运行。"
			} else if original.Enabled == 0 && original.Runtime == "stopped" {
				fact = "此前已确认停用。"
			}
		}
		parts = append(parts, target+fact)
	}
	if current := s.Current; current != nil {
		fact := "当前运行状态还未确认。"
		switch {
		case !current.Exists:
			fact = "当前未确认存在。"
		case current.Enabled == 1 && current.ConfigurationMatch && current.Runtime == "processing":
			fact = "目前正在运行。"
		case current.Enabled == 0 && current.Runtime == "stopped":
			fact = "目前处于停用状态。"
		case current.Enabled == 1 && !current.ConfigurationMatch:
			fact = "开关已开启，配置尚未核对一致。"
		case current.Enabled == 1:
			fact = "开关已开启，实际处理还未确认。"
		}
		parts = append(parts, target+fact)
		if changed {
			parts = append(parts, "状态变化的原因还未确认。")
		}
	} else if s.Reason != "cancelled_by_user" && s.Reason != "proposal_expired" {
		parts = append(parts, "暂时没取到最新状态。")
	}
	return strings.Join(parts, "")
}

func (h *Handler) deploymentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, deployment.ErrInvalidRequest):
		h.fail(w, 400, "invalid_deployment", "部署请求的对象或标识不完整，请重新确认。")
	case errors.Is(err, deployment.ErrAlgorithmUsage):
		h.reply(w, 409, map[string]any{"ok": false, "code": "algorithm_usage_unsupported", "proposalCreated": false, "supportedInteraction": "none", "userMessage": "所选算法仅供图片分析，当前持续任务入口不支持此算法；未创建提议，设备任务未更改。"})
	case errors.Is(err, deployment.ErrConflict), errors.Is(err, ledger.ErrNotFound):
		h.fail(w, 409, "deployment_conflict", "该请求不属于本次对话、已失效或同一目标已有待处理操作；本次没有重复派发。")
	default:
		h.fail(w, 503, "deployment_unavailable", "当前算法配置、设备连接或运行事实无法可靠确认；本次不宣称部署成功。")
	}
}
