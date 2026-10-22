package main

import "os/exec"

// openBrowser asks macOS to open url with open(1). url is the approval URL
// checkBegin rebuilt from checked parts, passed as one argument with no
// shell.
func openBrowser(url string) error {
	cmd := exec.Command("open", url) //nolint:gosec // G204: a checked https URL as one argument, no shell
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
