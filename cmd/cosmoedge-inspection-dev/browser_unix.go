//go:build !darwin && !windows

package main

import "os/exec"

func openBrowser(rawURL string) error {
	return exec.Command("xdg-open", rawURL).Start()
}
