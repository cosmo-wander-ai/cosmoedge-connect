package main

import (
	"context"
	"fmt"
	"os"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/agentcli"
)

func main() {
	if err := agentcli.Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "inspection command could not produce a trusted response")
		os.Exit(2)
	}
}
