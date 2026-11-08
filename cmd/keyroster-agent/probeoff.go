//go:build linux && !keyroster_e2e

package main

import (
	"fmt"
	"io"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

// checkProbeOff refuses --probe-self-test off (03-10b, T-03-243): only the
// e2e test build can switch the probe self-test off. It runs right after
// the flags are parsed, so nothing is resolved, read or written first.
func checkProbeOff(stderr io.Writer) error {
	_, _ = fmt.Fprintln(stderr, "probe_self_test_off_refused: --probe-self-test off exists only in the e2e test build")
	return errUsage
}

// disableProbes is unreachable in this build: checkProbeOff refused off.
func disableProbes(*apply.Config) {}
