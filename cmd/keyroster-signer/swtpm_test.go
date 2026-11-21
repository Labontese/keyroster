//go:build linux

package main

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startSWTPM runs a private swtpm with a unixio socket and returns the
// socket path; the swtpm is stopped at cleanup (03-12f). It is a copy of
// startSWTPM in internal/keystore/tpm/tpm_test.go, which is private to
// package tpm, with the same guard: KEYROSTER_SWTPM names the binary,
// otherwise swtpm is looked up on PATH; without it the test skips, unless
// KEYROSTER_TPM_REQUIRE=1 (set by the e2e-tpm workflow), when a missing
// swtpm fails it. A test still closes every backend before it opens the
// next, but nothing on swtpm checks that: go-tpm's socket transport
// connects for each command and disconnects after the answer.
func startSWTPM(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("KEYROSTER_SWTPM")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("swtpm"); err != nil {
			if os.Getenv("KEYROSTER_TPM_REQUIRE") == "1" {
				t.Fatal("swtpm not found and KEYROSTER_TPM_REQUIRE=1")
			}
			t.Skip("swtpm not installed; the e2e-tpm workflow runs these tests")
		}
	}
	dir, err := os.MkdirTemp("", "swtpm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "swtpm.sock")
	cmd := exec.Command(bin, "socket", "--tpm2", //nolint:gosec // G204: the swtpm under test
		"--server", "type=unixio,path="+sock,
		"--ctrl", "type=unixio,path="+filepath.Join(dir, "swtpm.ctrl"),
		"--tpmstate", "dir="+state,
		"--flags", "not-need-init,startup-clear")
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			return sock
		}
		select {
		case <-done:
			t.Fatalf("swtpm exited early:\n%s", log.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("swtpm socket did not appear")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
