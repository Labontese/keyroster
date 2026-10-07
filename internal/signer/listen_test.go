//go:build linux

package signer_test

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/signer"
)

// TestListenKeepsLiveSocket (A-CR-01): Listen replaces a stale socket but
// never unlinks one that still accepts connections, so a second serve
// cannot silently take over a running signer's socket.
func TestListenKeepsLiveSocket(t *testing.T) {
	dir := shortTempDir(t)

	t.Run("live_socket_refused", func(t *testing.T) {
		path := filepath.Join(dir, "live.sock")
		live, err := signer.Listen(path, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = live.Close() }()
		if l, err := signer.Listen(path, -1); err == nil || !strings.Contains(err.Error(), "another signer is already serving") {
			if l != nil {
				_ = l.Close()
			}
			t.Fatalf("Listen on a live socket = %v, want a refusal", err)
		}
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("the live socket no longer accepts connections: %v", err)
		}
		_ = c.Close()
	})

	t.Run("stale_socket_replaced", func(t *testing.T) {
		path := filepath.Join(dir, "stale.sock")
		old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		old.SetUnlinkOnClose(false)
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("stale socket file missing: %v", err)
		}
		l, err := signer.Listen(path, -1)
		if err != nil {
			t.Fatalf("Listen over a stale socket: %v", err)
		}
		_ = l.Close()
	})

	t.Run("regular_file_refused", func(t *testing.T) {
		path := filepath.Join(dir, "file")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if l, err := signer.Listen(path, -1); err == nil {
			_ = l.Close()
			t.Fatal("Listen over a regular file succeeded")
		}
	})
}
