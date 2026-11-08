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
	// 03-10c: preflight and check take --probe-account alone, validated
	// before anything is resolved or read; --probe-self-test stays on run
	// and apply. Both commands then fail later (the missing sshd or state
	// directory), after the flags.
	base := t.TempDir()
	missing := []string{"--root", filepath.Join(base, "root"), "--state-dir", filepath.Join(base, "state"), "--sshd", filepath.Join(base, "no-sshd"), "--sshd-config", filepath.Join(base, "no-sshd_config")}
	agent := func(cmd string, args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := dispatch(context.Background(), append(append([]string{cmd}, args...), missing...), &stdout, &stderr)
		return code, stderr.String()
	}
	t.Run("preflight_and_check_accept_probe_account", func(t *testing.T) {
		for _, cmd := range []string{"preflight", "check"} {
			_, msg := agent(cmd, "--probe-account", "probe1")
			if strings.Contains(msg, "flag provided but not defined") || strings.Contains(msg, "not a valid account name") {
				t.Fatalf("%s --probe-account probe1: %q", cmd, msg)
			}
		}
	})
	t.Run("preflight_and_check_refuse_probe_self_test", func(t *testing.T) {
		for _, cmd := range []string{"preflight", "check"} {
			if code, msg := agent(cmd, "--probe-self-test", "required"); code != 2 || !strings.Contains(msg, "flag provided but not defined: -probe-self-test") {
				t.Fatalf("%s --probe-self-test: exit %d, %q", cmd, code, msg)
			}
		}
	})
	t.Run("invalid_account_refused_before_any_read", func(t *testing.T) {
		for _, cmd := range []string{"preflight", "check"} {
			code, msg := agent(cmd, "--probe-account", "Not Valid")
			if code != 2 || !strings.Contains(msg, `--probe-account "Not Valid" is not a valid account name`) || strings.Contains(msg, "no-sshd") {
				t.Fatalf("%s: exit %d, %q", cmd, code, msg)
			}
			if _, err := os.Stat(filepath.Join(base, "state")); !os.IsNotExist(err) {
				t.Fatalf("%s: the state directory exists: %v", cmd, err)
			}
		}
	})
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
