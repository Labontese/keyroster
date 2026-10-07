//go:build linux

package agent

import "time"

// SetRequestTimeout sets the agent request timeout for a test and returns
// a function that restores it.
func SetRequestTimeout(d time.Duration) func() {
	old := requestTimeout
	requestTimeout = d
	return func() { requestTimeout = old }
}
