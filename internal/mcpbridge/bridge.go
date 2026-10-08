package mcpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Bridge struct {
	mu           sync.Mutex
	client       *apiClient
	journal      *journal
	pollInterval time.Duration
}

func New(c Config) (*Bridge, error) {
	client, err := newClient(c)
	if err != nil {
		return nil, err
	}
	j, err := openJournal(c.StateRoot, sha([]byte(c.BaseURL+"\x00"+client.token)))
	if err != nil {
		return nil, err
	}
	return &Bridge{client: client, journal: j, pollInterval: time.Second}, nil
}
func (b *Bridge) Close() error { b.mu.Lock(); defer b.mu.Unlock(); return b.journal.close() }

func (b *Bridge) Maintain(days int, apply bool) (Maintenance, error) {
	if days < 1 || days > 3650 {
		return Maintenance{}, errors.New("retention_days_must_be_1_to_3650")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.journal.maintain(time.Now().Add(-time.Duration(days)*24*time.Hour), apply)
}

// Result is the public v1 envelope. Data preserves typed service facts,
// including coverage and original versus current observation timestamps.
type Result struct {
	OK             bool           `json:"ok"`
	APIVersion     string         `json:"apiVersion"`
	Code           string         `json:"code,omitempty"`
	Message        string         `json:"message"`
	ContextRef     string         `json:"contextRef,omitempty"`
	OperationRef   string         `json:"operationRef,omitempty"`
	RequestKey     string         `json:"requestKey,omitempty"`
	State          string         `json:"state,omitempty"`
	Pending        bool           `json:"pending"`
	Unknown        bool           `json:"unknown"`
	Data           map[string]any `json:"data,omitempty"`
	Artifacts      []artifact     `json:"artifacts,omitempty"`
	ArtifactErrors []string       `json:"artifactErrors,omitempty"`
}

type ContextInput struct {
	ContextRef string `json:"contextRef" jsonschema:"Opaque business context returned by cosmoedge_begin_context or cosmoedge_open_connection. This is not an MCP transport or host chat ID."`
}
type OpenConnectionInput struct {
	ContextRef         string `json:"contextRef,omitempty" jsonschema:"Existing context for this workflow, if available. Omit to create an independent context and open the connection page in one call. An explicitly empty, invalid or expired reference is rejected."`
	contextRefProvided bool
}

func (in *OpenConnectionInput) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	*in = OpenConnectionInput{}
	value, present := fields["contextRef"]
	if !present {
		return nil
	}
	// Presence matters: an explicit invalid reference must never create a
	// replacement workflow. The MCP schema also rejects non-string values.
	in.contextRefProvided = true
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return errors.New("invalid_context_ref")
	}
	return json.Unmarshal(value, &in.ContextRef)
}

type SummaryInput struct {
	ContextRef    string   `json:"contextRef"`
	Start         string   `json:"start" jsonschema:"RFC3339 inclusive absolute instant. Prefer UTC Z: for past 24 hours subtract 24 hours from a freshly read capabilities.serverTime and keep Z. Never replace Z with a local offset without converting the clock time."`
	End           string   `json:"end" jsonschema:"RFC3339 exclusive absolute instant; cannot be in the future. For a window ending now pass freshly read capabilities.serverTime unchanged, including its Z suffix. timeZone does not require converting this value."`
	TimeZone      string   `json:"timeZone" jsonschema:"IANA timezone for calendar-day grouping and report display, e.g. Asia/Shanghai. Does not shift start/end instants: UTC Z input is valid with this timezone."`
	SourceName    string   `json:"sourceName,omitempty"`
	SourceNames   []string `json:"sourceNames,omitempty"`
	AlgorithmName string   `json:"algorithmName,omitempty" jsonschema:"Only when the user explicitly restricts the algorithm; a camera name is not an algorithm filter."`
}
type CaptureInput struct {
	ContextRef  string `json:"contextRef"`
	RequestKey  string `json:"requestKey" jsonschema:"Caller-created unique key for this new capture, 1-128 ASCII letters/digits/dot/underscore/hyphen. Keep exactly the same key for retries; never use a JSON-RPC request id."`
	SourceName  string `json:"sourceName"`
	SourceRef   string `json:"sourceRef,omitempty"`
	Question    string `json:"question,omitempty"`
	WaitSeconds int    `json:"waitSeconds,omitempty" jsonschema:"Bounded polling budget 0-45 seconds, default 0. Continue the same operation when pending."`
}
type ChangeInput struct {
	ContextRef    string `json:"contextRef"`
	RequestKey    string `json:"requestKey" jsonschema:"Unique stable idempotency key for this intent; retain it after timeout and retry the same key or query the original operation."`
	SourceName    string `json:"sourceName"`
	AlgorithmName string `json:"algorithmName"`
	Enabled       bool   `json:"enabled"`
}
type OperationInput struct {
	ContextRef   string `json:"contextRef"`
	OperationRef string `json:"operationRef,omitempty"`
	RequestKey   string `json:"requestKey,omitempty" jsonschema:"Use exactly one of operationRef or original requestKey."`
	WaitSeconds  int    `json:"waitSeconds,omitempty" jsonschema:"0-45 seconds, default 0; only reads the same operation."`
}
type ReviewInput struct {
	ContextRef   string `json:"contextRef"`
	OperationRef string `json:"operationRef"`
	WaitSeconds  int    `json:"waitSeconds,omitempty"`
}
type CancelInput struct {
	ContextRef   string `json:"contextRef"`
	OperationRef string `json:"operationRef"`
}
type ArtifactInput struct {
	ContextRef  string `json:"contextRef"`
	ArtifactRef string `json:"artifactRef"`
}

func result(data map[string]any) Result {
	r := Result{OK: data["ok"] == true, APIVersion: APIVersion, Message: stringField(data, "userMessage"), Code: stringField(data, "code"), Pending: data["pending"] == true, Unknown: data["unknown"] == true, Data: sanitize(data).(map[string]any)}
	if r.Message == "" {
		r.Message = "CosmoEdge Connect returned structured facts."
	}
	return r
}
func failure(err error) Result {
	return Result{APIVersion: APIVersion, Code: err.Error(), Message: "This call could not complete. Preserve the original context and request key; recover the original operation rather than submitting a new intent."}
}
func stringField(m map[string]any, key string) string { s, _ := m[key].(string); return s }
func sanitize(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			switch k {
			case "sessionRef", "requestId", "operationRef", "pollPath", "attachments", "confirmationToken", "confirmationReceipt":
				continue
			}
			out[k] = sanitize(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitize(item)
		}
		return out
	default:
		return value
	}
}
func validText(s string, max int) bool {
	return utf8.ValidString(s) && strings.TrimSpace(s) != "" && len(s) <= max && !strings.ContainsRune(s, 0)
}
func (b *Bridge) context(ctx context.Context, ref string) (businessContext, error) {
	c, err := b.journal.context(ref)
	if err != nil {
		return c, err
	}
	if err = b.client.verify(ctx); err != nil {
		return c, err
	}
	return c, nil
}
func (b *Bridge) capabilities(ctx context.Context) (Result, []mcp.Content) {
	err := b.client.verify(ctx)
	r := Result{OK: err == nil, APIVersion: APIVersion, Message: "Local CosmoEdge Connect operations. Business contexts are explicit; a transport connection is not a conversation identity.", Data: map[string]any{"transport": "stdio", "serviceIdentity": b.client.identity, "serviceAvailable": err == nil, "maxWaitSeconds": 45, "confirmationMode": "local_page", "remoteHosting": false, "automaticChatIsolation": false, "edgeObserve": false, "artifactDelivery": "image_content_and_embedded_resource", "requestKeyRequired": true, "completedContextRetentionDays": 30}}
	if err != nil {
		r.Code = err.Error()
	}
	r.Data["serverTime"] = b.client.serverTime
	r.Data["serverTimeAvailable"] = err == nil && b.client.serverTime != ""
	return r, nil
}
func (b *Bridge) begin(ctx context.Context) (Result, []mcp.Content) {
	if _, err := b.journal.maintain(time.Now().Add(-30*24*time.Hour), true); err != nil {
		return failure(err), nil
	}
	if err := b.client.verify(ctx); err != nil {
		return failure(err), nil
	}
	data, err := b.client.request(ctx, "", apiPrefix+"session", map[string]any{})
	if err != nil {
		return failure(err), nil
	}
	if data["ok"] != true {
		return result(data), nil
	}
	session := stringField(data, "sessionRef")
	if !sessionPattern.MatchString(session) {
		return failure(errors.New("invalid_session_response")), nil
	}
	c, err := b.journal.addContext(session)
	if err != nil {
		return failure(err), nil
	}
	r := result(data)
	r.ContextRef = c.Ref
	r.Message = "Business context created. Use this context only for the intended workflow; do not infer chat identity from the MCP connection."
	return r, nil
}
func (b *Bridge) simple(ctx context.Context, in ContextInput, path string, body any) (Result, []mcp.Content) {
	c, err := b.context(ctx, in.ContextRef)
	if err != nil {
		return failure(err), nil
	}
	d, err := b.client.request(ctx, c.Session, apiPrefix+path, body)
	if err != nil {
		return failure(err), nil
	}
	r := result(d)
	r.ContextRef = c.Ref
	return r, nil
}
func (b *Bridge) openConnection(ctx context.Context, in OpenConnectionInput) (Result, []mcp.Content) {
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	var c businessContext
	var err error
	if !in.contextRefProvided && in.ContextRef == "" {
		created, _ := b.begin(ctx)
		if !created.OK {
			return created, nil
		}
		// begin already verifies the paired service before creating the session.
		// Keep its context even when the subsequent page dispatch fails.
		c, err = b.journal.context(created.ContextRef)
		if err != nil {
			r := failure(err)
			r.ContextRef = created.ContextRef
			return r, nil
		}
	} else {
		c, err = b.context(ctx, in.ContextRef)
		if err != nil {
			r := failure(err)
			r.ContextRef = c.Ref
			return r, nil
		}
	}
	data, err := b.client.request(ctx, c.Session, apiPrefix+"connection", map[string]any{})
	var r Result
	if err != nil {
		r = failure(err)
	} else if data["ok"] == true && (data["pageState"] != "dispatched" || data["interactionRequired"] != true || data["supportedInteraction"] != "connection_only") {
		r = failure(errors.New("invalid_connection_response"))
	} else {
		r = result(data)
	}
	r.ContextRef = c.Ref
	return r, nil
}
func (b *Bridge) summary(ctx context.Context, in SummaryInput) (Result, []mcp.Content) {
	if (in.SourceName != "" && in.SourceNames != nil) || (in.SourceNames != nil && len(in.SourceNames) == 0) || len(in.SourceNames) > 64 || !validText(in.TimeZone, 100) {
		return failure(errors.New("invalid_summary_request")), nil
	}
	for _, name := range in.SourceNames {
		if !validText(name, 1024) {
			return failure(errors.New("invalid_source_name")), nil
		}
	}
	if _, err := time.Parse(time.RFC3339, in.Start); err != nil {
		return failure(errors.New("invalid_summary_start")), nil
	}
	if _, err := time.Parse(time.RFC3339, in.End); err != nil {
		return failure(errors.New("invalid_summary_end")), nil
	}
	c, err := b.context(ctx, in.ContextRef)
	if err != nil {
		return failure(err), nil
	}
	payload := map[string]any{"start": in.Start, "end": in.End, "timeZone": in.TimeZone}
	if len(in.SourceNames) > 0 {
		payload["sourceNames"] = in.SourceNames
	} else if in.SourceName != "" {
		payload["sourceName"] = in.SourceName
	}
	if in.AlgorithmName != "" {
		payload["algorithmName"] = in.AlgorithmName
	}
	data, err := b.client.request(ctx, c.Session, apiPrefix+"summary", payload)
	if err != nil {
		return failure(err), nil
	}
	r := result(data)
	r.ContextRef = c.Ref
	if !r.OK {
		return r, nil
	}
	meta, ok := data["summaryReport"].(map[string]any)
	raw := []byte(stringField(data, "userMessage"))
	var candidate Identity
	encoded, _ := json.Marshal(meta["candidate"])
	if !ok || meta["schemaVersion"] != float64(1) || meta["contentType"] != "text/markdown; charset=utf-8" || meta["sizeBytes"] != float64(len(raw)) || len(raw) == 0 || len(raw) > maxReport || meta["sha256"] != sha(raw) || json.Unmarshal(encoded, &candidate) != nil || candidate != b.client.identity {
		r.ArtifactErrors = []string{"report_integrity_or_candidate_mismatch"}
		return r, nil
	}
	a, err := b.journal.addArtifact(c.Ref, "", "text/markdown", raw, candidate)
	if err != nil {
		r.ArtifactErrors = []string{err.Error()}
		return r, nil
	}
	r.Artifacts = []artifact{a}
	r.Message = stringField(meta, "headline")
	if r.Message == "" {
		r.Message = "Retained alarm statistics and original report are available."
	}
	delete(r.Data, "userMessage")
	return r, artifactContent(a)
}

func (b *Bridge) submit(ctx context.Context, contextRef, key, kind string, payload map[string]any, wait int) (Result, []mcp.Content) {
	if !referencePattern.MatchString(key) || wait < 0 || wait > 45 {
		return failure(errors.New("invalid_request_key_or_wait")), nil
	}
	c, err := b.context(ctx, contextRef)
	if err != nil {
		return failure(err), nil
	}
	op, fresh, err := b.journal.prepare(c.Ref, key, kind, payload)
	if err != nil {
		return failure(err), nil
	}
	if !fresh {
		if op.State == "rejected" {
			return b.finish(ctx, c, op)
		}
		return b.poll(ctx, c, op, wait, false)
	}
	payload["requestId"] = op.RequestID
	path := "captures"
	if kind == "deployment" {
		path = "deployments"
	}
	d, err := b.client.request(ctx, c.Session, apiPrefix+path, payload)
	if err != nil {
		return uncertain(op, err), nil
	}
	if err = b.accept(&op, d); err != nil {
		return uncertain(op, err), nil
	}
	if wait > 0 && op.State == "pending" {
		return b.poll(ctx, c, op, wait, false)
	}
	return b.finish(ctx, c, op)
}
func (b *Bridge) capture(ctx context.Context, in CaptureInput) (Result, []mcp.Content) {
	if !validText(in.SourceName, 1024) || len(in.Question) > 4096 || (in.SourceRef != "" && !referencePattern.MatchString(in.SourceRef)) {
		return failure(errors.New("invalid_capture_request")), nil
	}
	p := map[string]any{"sourceName": in.SourceName, "question": in.Question}
	if in.SourceRef != "" {
		p["sourceRef"] = in.SourceRef
	}
	return b.submit(ctx, in.ContextRef, in.RequestKey, "observation", p, in.WaitSeconds)
}
func (b *Bridge) prepare(ctx context.Context, in ChangeInput) (Result, []mcp.Content) {
	if !validText(in.SourceName, 1024) || !validText(in.AlgorithmName, 1024) {
		return failure(errors.New("invalid_deployment_request")), nil
	}
	return b.submit(ctx, in.ContextRef, in.RequestKey, "deployment", map[string]any{"sourceName": in.SourceName, "algorithmName": in.AlgorithmName, "enabled": in.Enabled}, 0)
}
func uncertain(op operation, err error) Result {
	r := failure(err)
	r.ContextRef = op.Context
	r.OperationRef = op.Ref
	r.RequestKey = op.RequestKey
	r.State = op.State
	r.Unknown = true
	if len(op.Result) > 0 {
		r.Data = map[string]any{"previousReceipt": sanitize(op.Result), "currentReadUnavailable": true}
	}
	return r
}
func (b *Bridge) accept(op *operation, data map[string]any) error {
	if rid := stringField(data, "requestId"); rid != "" && rid != op.RequestID {
		return errors.New("request_binding_mismatch")
	}
	ref := stringField(data, "operationRef")
	if ref != "" && (!referencePattern.MatchString(ref) || (op.ServiceRef != "" && ref != op.ServiceRef)) {
		return errors.New("operation_binding_mismatch")
	}
	if path := stringField(data, "pollPath"); path != "" && path != apiPrefix+op.Kind+"s/"+ref {
		return errors.New("poll_binding_mismatch")
	}
	if data["ok"] == true && ref == "" && data["proposalCreated"] != false {
		return errors.New("operation_binding_missing")
	}
	if ref != "" {
		op.ServiceRef = ref
	}
	// A failed status read is not a new observation and must not erase the
	// accepted receipt or turn an uncertain request into a safe-to-repeat one.
	if data["ok"] == false && data["deployment"] == nil && data["observation"] == nil && data["proposal"] == nil {
		if op.State != "submission_unknown" || stringField(data, "code") == "observation_not_found" || stringField(data, "code") == "deployment_not_found" {
			return errors.New("current_read_unavailable")
		}
		// Input rejections are definite refusals. Transport/server errors remain
		// unknown and recoverable even if a later new call uses the same key.
		code := stringField(data, "code")
		definite := map[string]bool{"invalid_observation": true, "invalid_deployment": true, "target_required": true, "target_ambiguous_or_missing": true, "source_ambiguous": true, "source_missing": true, "connection_required": true, "invalid_request_id": true}
		if !definite[code] && data["proposalCreated"] != false {
			return errors.New("current_read_unavailable")
		}
		op.State = "rejected"
	} else {
		op.State = "completed"
		if data["pending"] == true {
			op.State = "pending"
		}
		if p, ok := data["proposal"].(map[string]any); ok && p["state"] == "proposed" {
			op.State = "proposed"
		}
		if data["interactionRequired"] == true && data["supportedInteraction"] == "deployment_confirmation" && data["confirmationMode"] == "local_page" {
			op.State = "proposed"
		}
		if v, ok := data["deployment"].(map[string]any); ok {
			if s := stringField(v, "state"); s != "" {
				op.State = s
			}
			if data["pending"] == true {
				op.State = "pending"
			}
		}
		if v, ok := data["observation"].(map[string]any); ok && data["pending"] != true {
			if s := stringField(v, "status"); s != "" {
				op.State = s
			}
		}
	}
	op.Result = data
	return b.journal.save(op)
}
func (b *Bridge) poll(ctx context.Context, c businessContext, op operation, wait int, review bool) (Result, []mcp.Content) {
	if wait < 0 || wait > 45 {
		return failure(errors.New("invalid_wait")), nil
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		path := apiPrefix + op.Kind + "s/" + op.ServiceRef
		if op.ServiceRef == "" {
			path = apiPrefix + op.Kind + "s/by-request/" + op.RequestID
		}
		d, err := b.client.request(ctx, c.Session, path, nil)
		if err != nil {
			return uncertain(op, err), nil
		}
		if err = b.accept(&op, d); err != nil {
			return uncertain(op, err), nil
		}
		if (op.State != "pending" && !(review && op.State == "proposed")) || wait == 0 || time.Now().After(deadline) {
			return b.finish(ctx, c, op)
		}
		timer := time.NewTimer(min(b.pollInterval, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return uncertain(op, errors.New("poll_interrupted")), nil
		case <-timer.C:
		}
	}
}
func (b *Bridge) get(ctx context.Context, in OperationInput) (Result, []mcp.Content) {
	c, err := b.context(ctx, in.ContextRef)
	if err != nil {
		return failure(err), nil
	}
	op, err := b.journal.operation(c.Ref, in.OperationRef, in.RequestKey)
	if err != nil {
		return failure(err), nil
	}
	if op.State == "rejected" {
		return b.finish(ctx, c, op)
	}
	return b.poll(ctx, c, op, in.WaitSeconds, false)
}
func (b *Bridge) review(ctx context.Context, in ReviewInput) (Result, []mcp.Content) {
	if in.WaitSeconds < 0 || in.WaitSeconds > 45 {
		return failure(errors.New("invalid_wait")), nil
	}
	c, err := b.context(ctx, in.ContextRef)
	if err != nil {
		return failure(err), nil
	}
	op, err := b.journal.operation(c.Ref, in.OperationRef, "")
	if err != nil {
		return failure(err), nil
	}
	if op.Kind != "deployment" || op.ServiceRef == "" {
		return failure(errors.New("deployment_required")), nil
	}
	// Only opens the protected local page. There is no /confirm call anywhere
	// in this adapter and no model-supplied confirmation material.
	d, err := b.client.request(ctx, c.Session, apiPrefix+"deployments/review", map[string]any{"operationRef": op.ServiceRef})
	if err != nil {
		return uncertain(op, err), nil
	}
	if d["pageOpened"] == true && (d["confirmationMode"] != "local_page" || d["supportedInteraction"] != "deployment_confirmation" || d["ok"] != true) {
		return uncertain(op, errors.New("invalid_review_response")), nil
	}
	if err = b.accept(&op, d); err != nil {
		return uncertain(op, err), nil
	}
	if in.WaitSeconds > 0 {
		return b.poll(ctx, c, op, in.WaitSeconds, true)
	}
	return b.finish(ctx, c, op)
}
func (b *Bridge) cancel(ctx context.Context, in CancelInput) (Result, []mcp.Content) {
	c, err := b.context(ctx, in.ContextRef)
	if err != nil {
		return failure(err), nil
	}
	op, err := b.journal.operation(c.Ref, in.OperationRef, "")
	if err != nil {
		return failure(err), nil
	}
	if op.Kind != "deployment" || op.ServiceRef == "" {
		return failure(errors.New("deployment_required")), nil
	}
	d, err := b.client.request(ctx, c.Session, apiPrefix+"deployments/cancel", map[string]any{"operationRef": op.ServiceRef})
	if err != nil {
		return uncertain(op, err), nil
	}
	if err = b.accept(&op, d); err != nil {
		return uncertain(op, err), nil
	}
	return b.finish(ctx, c, op)
}
func (b *Bridge) pending(in ContextInput) (Result, []mcp.Content) {
	c, err := b.journal.context(in.ContextRef)
	if err != nil {
		return failure(err), nil
	}
	ops, total, err := b.journal.pending(c.Ref)
	if err != nil {
		return failure(err), nil
	}
	message := "Locally persisted unfinished requests. These records do not by themselves prove service acceptance; query the original operation."
	if total > len(ops) {
		message += " Only the first 100 unfinished requests are shown. Resolve the listed original operations and list again; do not treat this as the complete pending inventory."
	}
	return Result{OK: true, APIVersion: APIVersion, ContextRef: c.Ref, Message: message, Data: map[string]any{"operations": ops, "totalPending": total, "returned": len(ops), "truncated": total > len(ops)}}, nil
}
func (b *Bridge) getArtifact(in ArtifactInput) (Result, []mcp.Content) {
	if _, err := b.journal.context(in.ContextRef); err != nil {
		return failure(err), nil
	}
	a, err := b.journal.artifact(in.ContextRef, in.ArtifactRef)
	if err != nil {
		return failure(err), nil
	}
	return Result{OK: true, APIVersion: APIVersion, ContextRef: in.ContextRef, Message: "Verified original artifact; no new capture or statistics query was made. Host UI delivery is not attested by this tool.", Artifacts: []artifact{a}}, artifactContent(a)
}
func artifactContent(a artifact) []mcp.Content {
	if strings.HasPrefix(a.MIME, "image/") {
		return []mcp.Content{&mcp.ImageContent{Data: a.Content, MIMEType: a.MIME}}
	}
	return []mcp.Content{&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{URI: "cosmoedge://artifacts/" + a.Ref, MIMEType: a.MIME, Text: string(a.Content)}}}
}
func (b *Bridge) finish(ctx context.Context, c businessContext, op operation) (Result, []mcp.Content) {
	r := result(op.Result)
	r.ContextRef = c.Ref
	r.OperationRef = op.Ref
	r.RequestKey = op.RequestKey
	r.State = op.State
	if op.State == "unknown" || op.State == "submission_unknown" || op.State == "outcome_unknown" {
		r.Unknown = true
	}
	var content []mcp.Content
	attachments, _ := op.Result["attachments"].([]any)
	budget := maxImage
	for i, item := range attachments {
		if i >= 8 {
			r.ArtifactErrors = append(r.ArtifactErrors, "attachment_limit")
			break
		}
		meta, ok := item.(map[string]any)
		if !ok {
			r.ArtifactErrors = append(r.ArtifactErrors, "invalid_media_metadata")
			continue
		}
		a, err := b.media(ctx, c, op, meta, budget)
		if err != nil {
			r.ArtifactErrors = append(r.ArtifactErrors, err.Error())
			continue
		}
		budget -= a.Size
		r.Artifacts = append(r.Artifacts, a)
		content = append(content, artifactContent(a)...)
	}
	return r, content
}
func (b *Bridge) media(ctx context.Context, c businessContext, op operation, meta map[string]any, budget int) (artifact, error) {
	ref := stringField(meta, "mediaRef")
	path := stringField(meta, "path")
	expected := stringField(meta, "contentType")
	digest := stringField(meta, "sha256")
	size, ok := meta["sizeBytes"].(float64)
	if !referencePattern.MatchString(ref) || path != apiPrefix+"media/"+ref || !digestPattern.MatchString(digest) || !ok || size <= 0 || size > float64(budget) || size != float64(int(size)) {
		return artifact{}, errors.New("invalid_media_metadata")
	}
	if expected != "image/jpeg" && expected != "image/png" && expected != "image/webp" {
		return artifact{}, errors.New("unsupported_media_type")
	}
	status, headers, raw, err := b.client.read(ctx, c.Session, path, nil, int64(budget))
	if err != nil {
		return artifact{}, err
	}
	actual, _, _ := mime.ParseMediaType(headers.Get("Content-Type"))
	if status != 200 || actual != expected || len(raw) != int(size) || sha(raw) != digest || headers.Get("X-Content-SHA256") != digest {
		return artifact{}, errors.New("media_integrity_failure")
	}
	if header := headers.Get("Content-Length"); header != "" && header != strconv.Itoa(len(raw)) {
		return artifact{}, errors.New("media_length_mismatch")
	}
	magic := expected == "image/jpeg" && bytes.HasPrefix(raw, []byte{0xff, 0xd8, 0xff}) || expected == "image/png" && bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) || expected == "image/webp" && len(raw) >= 12 && string(raw[:4]) == "RIFF" && string(raw[8:12]) == "WEBP"
	if !magic {
		return artifact{}, errors.New("invalid_image_bytes")
	}
	return b.journal.addArtifact(c.Ref, op.Ref, expected, raw, b.client.identity)
}
