//go:build linux && !keyroster_e2e

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeFlags (03-10b): apply's and run's probe flags, their defaults
// and their refusals, all before anything is resolved.
func TestProbeFlags(t *testing.T) {
	var stderr bytes.Buffer
	a, err := parseApply([]string{"--once"}, &stderr)
	if err != nil || *a.probe.account != "keyroster-probe" || *a.probe.mode != "required" {
		t.Fatalf("defaults: %+v, %v (%s)", a.probe, err, stderr.String())
	}
	for _, args := range [][]string{
		{"--once", "--probe-account", "Not Valid"},
		{"--once", "--probe-account", ""},
		{"--once", "--probe-self-test", "optional"},
		{"--once", "--probe-self-test", ""},
	} {
		stderr.Reset()
		if _, err := parseApply(args, &stderr); err == nil {
			t.Fatalf("%q: accepted", args)
		}
	}
	for _, args := range [][]string{{"--probe-account", "Not Valid"}, {"--probe-self-test", "optional"}} {
		stderr.Reset()
		if code := dispatch(context.Background(), append([]string{"run"}, args...), &bytes.Buffer{}, &stderr); code != 2 {
			t.Fatalf("run %q: exit %d, want 2", args, code)
		}
	}
	stderr.Reset()
	if a, err := parseApply([]string{"--once", "--probe-account", "probe1"}, &stderr); err != nil || *a.probe.account != "probe1" {
		t.Fatalf("an account name: %+v, %v", a.probe, err)
	}
}

// TestProbeSelfTestOffRefusedInDefaultBuild (03-10b, T-03-243): a build
// without the e2e test build's tag refuses --probe-self-test off with exit
// status 2 and probe_self_test_off_refused on stderr, and writes nothing.
func TestProbeSelfTestOffRefusedInDefaultBuild(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	for _, cmd := range []string{"apply", "run"} {
		args := []string{cmd, "--probe-self-test", "off", "--state-dir", state, "--root", filepath.Join(base, "root")}
		if cmd == "apply" {
			args = append(args, "--once")
		}
		var stdout, stderr bytes.Buffer
		if code := dispatch(context.Background(), args, &stdout, &stderr); code != 2 {
			t.Fatalf("%s: exit %d, want 2 (stderr %s)", cmd, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "probe_self_test_off_refused") {
			t.Fatalf("%s: stderr %q", cmd, stderr.String())
		}
		if _, err := os.Stat(state); !os.IsNotExist(err) {
			t.Fatalf("%s: the state directory exists after the refusal: %v", cmd, err)
		}
	}
}
