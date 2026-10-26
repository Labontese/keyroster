//go:build !linux

// Command keyroster-agent keeps an enrolled host's sshd trust files in
// sync. In Phase 3 it runs on Linux only, so on every other OS it only
// reports that.
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "keyroster-agent runs on Linux only in this version (Phase 3)")
	os.Exit(1)
}
