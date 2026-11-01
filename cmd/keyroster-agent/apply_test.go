//go:build linux

package main

import (
	"errors"
	"strings"
	"testing"
)

// TestApplyFlags pins apply's path defaults: they are run's and identity's
// (--state-dir defaultStateDir, --spool <state-dir>/spool), so the
// sudo keyroster-agent apply --once that host-setup.md and the code's hints
// name runs as written. parseApply only parses: no service detection and
// no file access, so nothing here touches /var/lib.
func TestApplyFlags(t *testing.T) {
	for _, c := range []struct {
		name            string
		args            []string
		spool, stateDir string
	}{
		{"no_path_flag", []string{"--once"}, "/var/lib/keyroster-agent/spool", "/var/lib/keyroster-agent"},
		{"state_dir_only", []string{"--once", "--state-dir", "/x"}, "/x/spool", "/x"},
		{"spool_only", []string{"--once", "--spool", "/y"}, "/y", "/var/lib/keyroster-agent"},
		{"both", []string{"--once", "--spool", "/y", "--state-dir", "/x/"}, "/y", "/x"},
	} {
		var stderr strings.Builder
		a, err := parseApply(c.args, &stderr)
		if err != nil || a.spool != c.spool || a.stateDir != c.stateDir || !a.once {
			t.Errorf("%s: apply %v: spool %q, state directory %q, %v (%s), want %q, %q",
				c.name, c.args, a.spool, a.stateDir, err, stderr.String(), c.spool, c.stateDir)
		}
	}
	for _, c := range []struct {
		name string
		args []string
	}{
		{"relative_state_dir", []string{"--once", "--state-dir", "x"}},
		{"relative_spool", []string{"--once", "--spool", "y"}},
		{"no_once", []string{"--state-dir", "/x"}},
		{"argument", []string{"--once", "extra"}},
	} {
		var stderr strings.Builder
		if _, err := parseApply(c.args, &stderr); !errors.Is(err, errUsage) {
			t.Errorf("%s: apply %v: %v, want a usage error", c.name, c.args, err)
		}
	}
	var stderr strings.Builder
	if _, err := parseApply([]string{"-h"}, &stderr); !errors.Is(err, errUsage) ||
		!strings.Contains(stderr.String(), "--spool defaults to <state-dir>/spool, --state-dir to /var/lib/keyroster-agent.") {
		t.Errorf("apply -h: %v, %q, want the usage naming both defaults", err, stderr.String())
	}
}
