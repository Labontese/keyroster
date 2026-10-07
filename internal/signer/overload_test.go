//go:build linux

package signer

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/tlog"
)

// TestOverloadDoesNotStallAccept (A-WR-07): with every connection slot busy
// and s.mu held (an issuance signing with the CA key), the accept loop
// still closes each further connection at once instead of waiting for
// s.mu, and the refused connections are counted in a refusal_summary leaf.
func TestOverloadDoesNotStallAccept(t *testing.T) {
	e := newLogEnv(t)
	dir, err := os.MkdirTemp("", "krov")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	l, err := Listen(sock, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- e.s.Serve(ctx, l) }()

	e.s.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			e.s.mu.Unlock()
		}
	}
	defer unlock()

	// Fill every slot. Accept order is dial order, so the connections
	// dialled after these find no free slot.
	busy := make([]net.Conn, 0, maxConns)
	defer func() {
		for _, c := range busy {
			_ = c.Close()
		}
	}()
	for range maxConns {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		busy = append(busy, c)
	}
	const extra = 3
	for i := range extra {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(make([]byte, 1))
		_ = c.Close()
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("connection %d over capacity: read %d bytes, %v; want it closed at once (EOF) while s.mu is held", maxConns+i+1, n, err)
		}
	}

	unlock()
	for _, c := range busy {
		_ = c.Close()
	}
	busy = nil
	cancel()
	if err := <-served; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var overloaded uint64
	for _, leaf := range e.leavesOf() {
		if leaf.Kind != tlog.KindRefusalSummary {
			continue
		}
		b, err := tlog.DecodeRefusalSummaryBody(leaf.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range b.Counts {
			if c.Reason == tlog.ReasonOverloaded {
				overloaded += c.Count
			}
		}
	}
	if overloaded != extra {
		t.Fatalf("refusal summaries count %d overloaded connections, want %d", overloaded, extra)
	}
}
