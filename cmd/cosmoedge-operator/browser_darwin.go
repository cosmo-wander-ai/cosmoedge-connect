//go:build darwin

package main

import (
	"os"
	"os/exec"
	"strings"
)

func openBrowser(rawURL string) error {
	browser := strings.TrimSpace(os.Getenv("COSMOEDGE_OPERATOR_BROWSER"))
	if browser == "" {
		browser = "/usr/bin/open"
	}
	return startBrowserCommand(browser, rawURL)
}

func startBrowserCommand(browser, rawURL string) error {
	command := exec.Command(browser, rawURL)
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}
