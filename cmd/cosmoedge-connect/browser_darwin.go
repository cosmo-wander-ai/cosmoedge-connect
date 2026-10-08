//go:build darwin

package main

import "os/exec"

func openBrowser(rawURL string) error {
	return exec.Command("open", rawURL).Start()
}
