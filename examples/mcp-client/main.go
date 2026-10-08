// mcp-client demonstrates a normal MCP consumer with no Skill or model. --mock
// runs the complete adapter contract against a synthetic local service only.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "MCP example:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	f := flag.NewFlagSet("mcp-client", flag.ContinueOnError)
	server := f.String("server", "", "path to the cosmoedge-mcp executable")
	mock := f.Bool("mock", false, "use a synthetic loopback service; never connect to a device")
	base := f.String("base-url", "http://127.0.0.1:37789", "existing local operations service")
	token := f.String("token-file", "", "existing private token path")
	state := f.String("state-root", "", "private MCP journal root")
	candidate := f.String("candidate-file", "", "paired candidate JSON")
	if f.Parse(args) != nil || *server == "" {
		return errors.New("--server is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	serverArgs := []string{"--base-url", *base, "--token-file", *token, "--state-root", *state, "--candidate-file", *candidate}
	var fixture *mockService
	if *mock {
		var cleanup func()
		var err error
		fixture, serverArgs, cleanup, err = newMock(ctx, *server)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	connect := func() (*mcp.ClientSession, error) {
		client := mcp.NewClient(&mcp.Implementation{Name: "cosmoedge-connect-developer-example", Version: "1.0.0"}, nil)
		command := exec.CommandContext(ctx, *server, serverArgs...)
		command.Stderr = os.Stderr
		return client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	}
	client, err := connect()
	if err != nil {
		return err
	}
	defer client.Close()
	serverInfo := client.InitializeResult().ServerInfo
	if serverInfo == nil || serverInfo.Name != "cosmoedge" {
		return errors.New("expected the cosmoedge MCP server")
	}
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		return err
	}
	if len(listed.Tools) != 12 {
		return fmt.Errorf("expected 12 v1 tools, got %d", len(listed.Tools))
	}
	expectedTools := map[string]bool{}
	for _, suffix := range []string{"capabilities", "begin_context", "open_connection", "catalog", "summary", "capture", "get_operation", "list_pending_operations", "prepare_algorithm_change", "open_review", "cancel", "get_artifact"} {
		expectedTools["cosmoedge_"+suffix] = true
	}
	for _, tool := range listed.Tools {
		if !expectedTools[tool.Name] {
			return fmt.Errorf("unexpected or duplicate MCP tool: %s", tool.Name)
		}
		delete(expectedTools, tool.Name)
	}
	call := func(c *mcp.ClientSession, name string, arguments any) (map[string]any, *mcp.CallToolResult, error) {
		r, err := c.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
		if err != nil {
			return nil, nil, err
		}
		blob, _ := json.Marshal(r.StructuredContent)
		var data map[string]any
		if json.Unmarshal(blob, &data) != nil {
			return nil, r, errors.New("structured result missing")
		}
		return data, r, nil
	}
	caps, capResult, err := call(client, "cosmoedge_capabilities", map[string]any{})
	if err != nil {
		return err
	}
	if capResult.IsError {
		return errors.New("paired service is unavailable")
	}
	if caps["apiVersion"] != "cosmoedge.mcp.v1" {
		return errors.New("unexpected MCP contract version")
	}
	out := map[string]any{"mock": *mock, "serverName": serverInfo.Name, "protocolVersion": client.InitializeResult().ProtocolVersion, "tools": len(listed.Tools), "capabilities": caps}
	if !*mock {
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	// A second real stdio process shares this configuration/journal. Business
	// contexts still cannot read one another's operations or artifacts.
	second, err := connect()
	if err != nil {
		return err
	}
	defer second.Close()
	one, _, err := call(client, "cosmoedge_begin_context", map[string]any{})
	if err != nil {
		return err
	}
	two, _, err := call(second, "cosmoedge_begin_context", map[string]any{})
	if err != nil {
		return err
	}
	firstContext, _ := one["contextRef"].(string)
	secondContext, _ := two["contextRef"].(string)
	if firstContext == "" || secondContext == "" || firstContext == secondContext {
		return errors.New("contexts not distinct")
	}
	shot, shotResult, err := call(client, "cosmoedge_capture", map[string]any{"contextRef": firstContext, "requestKey": "example-shot-1", "sourceName": "Synthetic Gate"})
	if err != nil || shotResult.IsError {
		return errors.New("synthetic capture failed")
	}
	imageOK := false
	for _, block := range shotResult.Content {
		if v, ok := block.(*mcp.ImageContent); ok && len(v.Data) > 0 {
			imageOK = true
		}
	}
	artifacts, _ := shot["artifacts"].([]any)
	if len(artifacts) != 1 {
		return errors.New("capture artifact missing")
	}
	art, _ := artifacts[0].(map[string]any)
	_, denied, err := call(second, "cosmoedge_get_artifact", map[string]any{"contextRef": secondContext, "artifactRef": art["artifactRef"]})
	if err != nil || !denied.IsError {
		return errors.New("cross-context artifact access allowed")
	}
	_, same, err := call(second, "cosmoedge_get_artifact", map[string]any{"contextRef": firstContext, "artifactRef": art["artifactRef"]})
	if err != nil || same.IsError {
		return errors.New("original context recovery across process failed")
	}
	_, report, err := call(client, "cosmoedge_summary", map[string]any{"contextRef": firstContext, "start": "2026-09-01T00:00:00Z", "end": "2026-09-02T00:00:00Z", "timeZone": "UTC"})
	if err != nil || report.IsError {
		return errors.New("synthetic report failed")
	}
	reportOK := false
	for _, block := range report.Content {
		if v, ok := block.(*mcp.EmbeddedResource); ok && v.Resource.MIMEType == "text/markdown" && v.Resource.Text != "" && strings.HasPrefix(v.Resource.URI, "cosmoedge://artifacts/") {
			reportOK = true
		}
	}
	proposal, pr, err := call(client, "cosmoedge_prepare_algorithm_change", map[string]any{"contextRef": firstContext, "requestKey": "example-change-1", "sourceName": "Synthetic Gate", "algorithmName": "Synthetic People", "enabled": true})
	if err != nil || pr.IsError {
		return errors.New("synthetic proposal failed")
	}
	review, rr, err := call(client, "cosmoedge_open_review", map[string]any{"contextRef": firstContext, "operationRef": proposal["operationRef"]})
	if err != nil || rr.IsError || review["state"] != "proposed" {
		return errors.New("review incorrectly classified")
	}
	_, cr, err := call(client, "cosmoedge_cancel", map[string]any{"contextRef": firstContext, "operationRef": proposal["operationRef"]})
	if err != nil || cr.IsError {
		return errors.New("synthetic cancellation failed")
	}
	if !imageOK || !reportOK {
		return errors.New("native MCP content missing")
	}
	fixture.mu.Lock()
	out["syntheticDeviceWrites"] = fixture.writes
	out["captureSubmissions"] = fixture.captures
	fixture.mu.Unlock()
	out["twoStdioProcessesSharedJournal"] = true
	out["crossContextReadDenied"] = true
	out["imageContent"] = imageOK
	out["originalReportResource"] = reportOK
	out["reviewRequiresUser"] = true
	return json.NewEncoder(os.Stdout).Encode(out)
}
