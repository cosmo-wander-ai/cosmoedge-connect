package mcpbridge

import (
	"context"
	"encoding/json"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server exposes one stable tool contract, independent of a consumer's build.
// The local adapter and service still require the paired release identity.
func (b *Bridge) Server() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "cosmoedge", Version: "1.0.0"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{}, Instructions: `When asked to connect a device or open the connection page, call cosmoedge_open_connection directly; no preceding capabilities, begin_context or catalog call is needed. Omit contextRef if this workflow has none; retain the returned contextRef only for this workflow, including after a page-dispatch failure. Reuse a valid contextRef when already available; never replace an explicitly rejected reference. For other new workflows use cosmoedge_begin_context and retain its opaque contextRef. A dispatched connection page still requires user interaction and does not prove device connectivity. An MCP connection is not a host conversation identity. Capture and algorithm proposals require a new caller-created requestKey for each new intent; reuse the exact key after timeout. Recover with cosmoedge_get_operation or cosmoedge_list_pending_operations, never invent a replacement key for an unknown result. Credentials stay in the local connection page. cosmoedge_open_review only opens a page; the user must confirm there. Never automate that click. Inspect returned image content to answer visual questions. Capture completion is not a visual answer. Same-image follow-ups use cosmoedge_get_artifact with the original artifactRef, not cosmoedge_capture. Embedded resource URIs are artifact labels; use cosmoedge_get_artifact for owner-bound rereads. Tool content delivery does not prove a host showed an attachment. Preserve partial coverage and original versus current timestamps.`})
	add(s, b, "cosmoedge_capabilities", "Read the stable adapter contract, internal paired identity and current service availability.", true, func(ctx context.Context, _ struct{}) (Result, []mcp.Content) { return b.capabilities(ctx) })
	add(s, b, "cosmoedge_begin_context", "Create an explicit business context; call once for a new workflow. Do not infer chat identity from an MCP connection.", false, func(ctx context.Context, _ struct{}) (Result, []mcp.Content) { return b.begin(ctx) })
	add(s, b, "cosmoedge_open_connection", "Open the local device connection page directly, without first calling capabilities, begin_context or catalog. Omit contextRef to create an independent workflow; reuse it when this workflow already has one. Retain the returned contextRef even if page dispatch fails. Dispatched means the browser launch was requested, not that the device is connected. Credentials are entered locally, never in tool arguments.", false, b.openConnection)
	add(s, b, "cosmoedge_catalog", "Read real source and installed algorithm names, configured switches and current runtime facts. Use data.totals for source counts by kind, algorithm/task totals and runtime counts instead of counting long lists. runningTaskCount counts runtime=running, not enabled switches or verified processing progress; unknown states remain separate.", true, func(ctx context.Context, in ContextInput) (Result, []mcp.Content) {
		return b.simple(ctx, in, "catalog", nil)
	})
	add(s, b, "cosmoedge_summary", "Query retained alarm statistics in an explicit window and return the verified original report. For relative windows first refresh capabilities.serverTime; pass that UTC Z instant unchanged as end and subtract the requested duration for start. timeZone only controls grouping/display: never just replace Z with +08:00. Check the returned scope before reporting. A zero count cannot establish historical uptime or event causes.", true, b.summary)
	add(s, b, "cosmoedge_capture", "Capture one source for host multimodal analysis. Returns verified original image content; use the same operation for polling and the original artifact for follow-ups. Requires a stable requestKey.", false, b.capture)
	add(s, b, "cosmoedge_get_operation", "Read an owner-bound operation by operationRef or original requestKey. Bounded waiting never submits another device change.", true, b.get)
	add(s, b, "cosmoedge_list_pending_operations", "List this context's locally persisted pending/unknown requests, including requests whose first output was lost. This is not proof of service acceptance.", true, func(_ context.Context, in ContextInput) (Result, []mcp.Content) { return b.pending(in) })
	add(s, b, "cosmoedge_prepare_algorithm_change", "Prepare enable/disable of one installed algorithm on one exact source, preserving existing configuration. Does not execute; user confirmation remains on the local review page.", false, b.prepare)
	add(s, b, "cosmoedge_open_review", "Open the original proposal's protected local review page. Never confirms; only the user can click. May wait by reading the same operation.", false, b.review)
	add(s, b, "cosmoedge_cancel", "Cancel an unconfirmed proposal in this context. Inspect cancelled/result state; cannot undo an already executed action.", false, b.cancel)
	add(s, b, "cosmoedge_get_artifact", "Return the same hash-verified original image/report for this context. No new capture/query. Other contexts cannot retrieve it.", true, func(_ context.Context, in ArtifactInput) (Result, []mcp.Content) { return b.getArtifact(in) })
	return s
}

func add[In any](s *mcp.Server, b *Bridge, name, description string, readOnly bool, fn func(context.Context, In) (Result, []mcp.Content)) {
	no := false
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &no, OpenWorldHint: &no, IdempotentHint: readOnly || name == "cosmoedge_capture" || name == "cosmoedge_prepare_algorithm_change" || name == "cosmoedge_cancel"}}, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Result, error) {
		ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
		defer cancel()
		// The bounded local worker serializes journal/request transitions. It is
		// not a mapping of an MCP session or process to a business context.
		for !b.mu.TryLock() {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				r := failure(ctx.Err())
				raw, _ := json.Marshal(r)
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}, r, nil
			case <-timer.C:
			}
		}
		defer b.mu.Unlock()
		r, media := fn(ctx, in)
		raw, _ := json.Marshal(r)
		content := append([]mcp.Content{&mcp.TextContent{Text: string(raw)}}, media...)
		return &mcp.CallToolResult{Content: content, IsError: !r.OK}, r, nil
	})
}
