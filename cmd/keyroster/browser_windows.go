package main

import "os/exec"

// openBrowser asks Windows to open url in the default browser through
// rundll32 url.dll,FileProtocolHandler. url is the approval URL checkBegin
// rebuilt from checked parts (https, a checked origin, /login/<hex>),
// passed as one argument with no shell.
func openBrowser(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec // G204: a checked https URL as one argument, no shell
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
