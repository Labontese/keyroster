//go:build !linux

// Command keyroster-agent-fetch is the keyroster agent's unprivileged
// fetcher. In Phase 3 the agent runs on Linux only, so on every other OS
// it only reports that.
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "keyroster-agent-fetch runs on Linux only in this version (Phase 3)")
	os.Exit(1)
}
