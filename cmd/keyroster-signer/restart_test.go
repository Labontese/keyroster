//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/keystore"
)

// TestCredentialRefusedExitStatus (D-CR-01): an error that wraps
// keystore.ErrCredentialRefused (a PIV PIN or TPM auth value the device
// refused) ends the process with exitCredentialRefused, any other error
// with 1, so systemd can tell the two apart.
func TestCredentialRefusedExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"credential_refused", fmt.Errorf("signer: bundle key for role user: %w", keystore.ErrCredentialRefused), exitCredentialRefused},
		{"other_error", fmt.Errorf("signer: bundle key for role user: %w", os.ErrNotExist), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "test-" + tc.name
			registry[name] = command{Name: name, Run: func(context.Context, []string, io.Writer, io.Writer) error { return tc.err }}
			t.Cleanup(func() { delete(registry, name) })
			var stderr bytes.Buffer
			if got := dispatch(context.Background(), []string{name}, io.Discard, &stderr); got != tc.want {
				t.Fatalf("exit status %d, want %d (stderr %q)", got, tc.want, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.err.Error()) {
				t.Fatalf("stderr %q does not carry the error", stderr.String())
			}
		})
	}
	if exitCredentialRefused == 0 || exitCredentialRefused == 1 || exitCredentialRefused == 2 {
		t.Fatalf("exitCredentialRefused = %d collides with a generic exit status", exitCredentialRefused)
	}
}

// unitDirectives parses a systemd unit file into section -> key -> values.
func unitDirectives(t *testing.T, path string) map[string]map[string][]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: the unit file in this repository
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]map[string][]string{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line
			if out[section] == nil {
				out[section] = map[string][]string{}
			}
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok || section == "" {
				t.Fatalf("%s: unparsable line %q", path, line)
			}
			out[section][k] = append(out[section][k], v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestUnitRestartPolicy (D-CR-01): the shipped keyroster-signer.service
// never restarts on exitCredentialRefused, waits between other restarts,
// and caps how often it restarts, so a wrong PIN or auth value cannot burn
// the device's attempts in a start loop.
func TestUnitRestartPolicy(t *testing.T) {
	u := unitDirectives(t, filepath.Join("..", "..", "deploy", "systemd", "keyroster-signer.service"))
	svc, unit := u["[Service]"], u["[Unit]"]
	if got := svc["Restart"]; len(got) != 1 || got[0] != "on-failure" {
		t.Fatalf("Restart = %v, want on-failure", got)
	}
	if got := svc["RestartPreventExitStatus"]; len(got) != 1 || got[0] != strconv.Itoa(exitCredentialRefused) {
		t.Fatalf("RestartPreventExitStatus = %v, want exactly %d (exitCredentialRefused)", got, exitCredentialRefused)
	}
	rs := svc["RestartSec"]
	if len(rs) != 1 {
		t.Fatalf("RestartSec = %v, want one value", rs)
	}
	if d, err := time.ParseDuration(rs[0]); err != nil || d < 5*time.Second {
		t.Fatalf("RestartSec = %q, want at least 5s", rs[0])
	}
	// StartLimit* belong in [Unit]; in [Service] systemd ignores them.
	for _, k := range []string{"StartLimitIntervalSec", "StartLimitBurst"} {
		if len(unit[k]) != 1 {
			t.Fatalf("[Unit] %s = %v, want one value", k, unit[k])
		}
		if _, misplaced := svc[k]; misplaced {
			t.Fatalf("%s is in [Service], where systemd ignores it", k)
		}
	}
	if n, err := strconv.Atoi(unit["StartLimitBurst"][0]); err != nil || n < 1 || n > 5 {
		t.Fatalf("StartLimitBurst = %q, want 1 to 5", unit["StartLimitBurst"][0])
	}
}
