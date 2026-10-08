//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
)

func openBrowser(rawURL string) error {
	if browser := strings.TrimSpace(os.Getenv("COSMOEDGE_OPERATOR_BROWSER")); browser != "" {
		return startBrowserCommand(browser, rawURL)
	}
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", rawURL).Start()
}

func startBrowserCommand(browser, rawURL string) error {
	command := exec.Command(browser, rawURL)
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}
