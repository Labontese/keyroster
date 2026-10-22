//go:build !linux && !darwin && !windows

package main

import "errors"

// openBrowser has no opener on this OS; keyroster login prints the URL.
func openBrowser(string) error {
	return errors.New("no browser opener on this OS")
}
