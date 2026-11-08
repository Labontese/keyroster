//go:build linux && keyroster_e2e

package main

import (
	"io"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

// checkProbeOff accepts --probe-self-test off in the e2e test build
// (03-10b): the e2e and distro harnesses switch the probe self-test off for
// every host but the probe tests' own.
func checkProbeOff(io.Writer) error { return nil }

// disableProbes switches the probe self-test off for cfg.
func disableProbes(cfg *apply.Config) { apply.DisableProbes(cfg) }
