//go:build unix

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestPIVSecretEntryScript runs the script of docs/backends/piv.md steps 3
// and 5 (pivSecretEntryScript) with the system's sh and never with a
// terminal. It proves that the script parses, that it refuses a path that
// already exists, whatever it is, before it touches the terminal, and that a
// run without a terminal writes nothing and exits 1. The entry under a
// terminal (the echo off, two equal entries, the echo on again afterwards) is
// not run here: no CI job runs steps 3 or 5 of the guide with a terminal.
func TestPIVSecretEntryScript(t *testing.T) {
	// run starts the script with a pipe on stdin that holds two equal
	// lines, and returns its stderr and exit status.
	run := func(t *testing.T, path string) (string, int) {
		t.Helper()
		cmd := exec.Command("sh", "-c", pivSecretEntryScript, "sh", path) //nolint:gosec // G204: the guide's script under test, run by the system's sh
		cmd.Stdin = strings.NewReader("S3cret-9f2A\nS3cret-9f2A\n")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err == nil {
			return stderr.String(), 0
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running sh: %v", err)
		}
		return stderr.String(), ee.ExitCode()
	}

	t.Run("parses", func(t *testing.T) {
		cmd := exec.Command("sh", "-n", "-c", pivSecretEntryScript) //nolint:gosec // G204: the guide's script under test, run by the system's sh
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sh -n -c: %v\n%s", err, out)
		}
	})

	t.Run("no_terminal_writes_nothing", func(t *testing.T) {
		// A new path and a pipe on stdin: stty -echo cannot run, so the
		// script refuses. Its complaints (stty's, one before the message
		// and one from the exit trap after it) are worded differently on
		// each system and are not compared.
		path := filepath.Join(t.TempDir(), "secret")
		stderr, code := run(t, path)
		if code != 1 {
			t.Errorf("exit status %d, want 1", code)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the path exists after a run without a terminal: %v", err)
		}
		lines := strings.Split(strings.TrimRight(stderr, "\n"), "\n")
		hasMessage := false
		for _, l := range lines {
			if l == "nothing written" {
				hasMessage = true
			}
		}
		if !hasMessage {
			t.Errorf("stderr lacks the line `nothing written`: %q", stderr)
		}
		if len(lines) < 2 {
			t.Errorf("stderr holds %d line, want the message and at least one complaint of stty: %q", len(lines), stderr)
		}
	})

	// An existing path is refused before the script asks, so that stty never
	// runs: stderr is the message and nothing else.
	refused := func(t *testing.T, path string) {
		t.Helper()
		stderr, code := run(t, path)
		if code != 1 {
			t.Errorf("exit status %d, want 1", code)
		}
		if stderr != "nothing written\n" {
			t.Errorf("stderr %q, want exactly %q", stderr, "nothing written\n")
		}
	}

	t.Run("existing_regular_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, path)
		if got, err := os.ReadFile(path); err != nil || string(got) != "old\n" { //nolint:gosec // G304: a path in this test's own temporary directory
			t.Errorf("the file is %q (%v), want %q", got, err, "old\n")
		}
	})

	t.Run("existing_fifo", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, path)
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("the path is no longer the FIFO: %v, %v", fi, err)
		}
	})

	t.Run("link_to_nothing", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		target := filepath.Join(dir, "nowhere")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		refused(t, path)
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the link's target was created: %v", err)
		}
		if got, err := os.Readlink(path); err != nil || got != target {
			t.Errorf("the link is %q (%v), want it unchanged", got, err)
		}
	})
}
