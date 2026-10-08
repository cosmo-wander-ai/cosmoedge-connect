// cosmoedge-mcp is a local stdio adapter for a paired, already running CosmoEdge Connect.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/buildinfo"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/mcpbridge"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version-json" {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "CosmoEdge Connect MCP could not start or stopped:", err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	var c mcpbridge.Config
	var maintenance, apply bool
	var retention int
	f := flag.NewFlagSet("cosmoedge-mcp", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.BaseURL, "base-url", "http://127.0.0.1:37789", "literal loopback operations endpoint")
	f.StringVar(&c.TokenFile, "token-file", "", "existing private access token file")
	f.StringVar(&c.StateRoot, "state-root", "", "private, dedicated MCP journal directory")
	f.StringVar(&c.CandidateFile, "candidate-file", "", "paired candidate identity JSON")
	f.BoolVar(&maintenance, "maintenance", false, "report old settled contexts eligible for cleanup; no service or device calls")
	f.BoolVar(&apply, "apply", false, "apply the selected maintenance retention policy")
	f.IntVar(&retention, "retention-days", 30, "completed context retention, 1-3650 days; unresolved work always retained")
	if f.Parse(args) != nil || f.NArg() != 0 || c.TokenFile == "" || c.StateRoot == "" || c.CandidateFile == "" {
		return fmt.Errorf("required: --token-file, --state-root, --candidate-file; optional --base-url")
	}
	b, err := mcpbridge.New(c)
	if err != nil {
		return err
	}
	defer b.Close()
	if maintenance {
		r, err := b.Maintain(retention, apply)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	if apply {
		return fmt.Errorf("--apply requires --maintenance")
	}
	return b.Server().Run(ctx, &mcp.StdioTransport{MaxLineLength: 64 << 10})
}
