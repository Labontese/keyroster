//go:build linux

package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestOverloadDoesNotStallAccept (A-WR-07): with every connection slot busy
// and s.mu held (an issuance signing with the CA key), the accept loop
// still closes each further connection at once instead of waiting for
// s.mu, and the refused connections are counted in a refusal_summary leaf.
// F16 (03-08h): one uid now holds at most maxConnsPerPeer slots, so the
// global cap is filled by a foreign uid's share in the accounting and the
// test's own share over the socket.
func TestOverloadDoesNotStallAccept(t *testing.T) {
	e := newLogEnv(t)
	own := uint32(os.Getuid()) //nolint:gosec // G115: a uid fits uint32
	for range maxConnsPerPeer {
		if ok, detail := e.s.conns.take(own + 1); !ok {
			t.Fatalf("pre-fill of a foreign share refused: %s", detail)
		}
	}
	sock, stop := serveShare(t, e)

	e.s.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			e.s.mu.Unlock()
		}
	}
	defer unlock()

	// Fill the rest of the slots. Accept order is dial order, so the
	// connections dialled after these find no free slot.
	busy := dialIdle(t, sock, maxConns-maxConnsPerPeer)
	const extra = 3
	for i := range extra {
		closedAtOnce(t, sock, fmt.Sprintf("connection %d over capacity, while s.mu is held", maxConns+i+1))
	}

	unlock()
	for _, c := range busy {
		_ = c.Close()
	}
	if err := stop(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if n := overloadedCount(t, e); n != extra {
		t.Fatalf("refusal summaries count %d overloaded connections, want %d", n, extra)
	}
}

// TestConnSlots (F16 (03-08h)): the accept loop's accounting gives each
// uid at most maxConnsPerPeer of the maxConns slots, and keyroster-server's
// ceiling stays 3 below the share.
func TestConnSlots(t *testing.T) {
	const a, b, c = 1000, 1001, 1002
	fill := func(t *testing.T, s *connSlots, uid uint32, n int) {
		t.Helper()
		for i := range n {
			if ok, detail := s.take(uid); !ok {
				t.Fatalf("take %d for uid %d refused: %s", i+1, uid, detail)
			}
		}
	}
	t.Run("share_per_uid", func(t *testing.T) {
		s := newConnSlots()
		fill(t, s, a, maxConnsPerPeer)
		if ok, detail := s.take(a); ok || detail != "uid_share_exceeded" {
			t.Fatalf("take over the share = %v, %q; want uid_share_exceeded", ok, detail)
		}
		if ok, detail := s.take(b); !ok {
			t.Fatalf("take for another uid refused: %s", detail)
		}
	})
	t.Run("global_cap", func(t *testing.T) {
		s := newConnSlots()
		fill(t, s, a, maxConnsPerPeer)
		fill(t, s, b, maxConnsPerPeer)
		if ok, detail := s.take(c); ok || detail != "too_many_connections" {
			t.Fatalf("take over the global cap = %v, %q; want too_many_connections", ok, detail)
		}
	})
	t.Run("put_frees_and_deletes", func(t *testing.T) {
		s := newConnSlots()
		fill(t, s, a, maxConnsPerPeer)
		for range maxConnsPerPeer {
			s.put(a)
		}
		if _, ok := s.perUID[a]; ok || s.total != 0 {
			t.Fatalf("after every put: perUID %v, total %d; want no key and 0", s.perUID, s.total)
		}
		fill(t, s, a, maxConnsPerPeer)
	})
	t.Run("unknown_peer_own_key", func(t *testing.T) {
		s := newConnSlots()
		fill(t, s, tlog.PeerUnknown, maxConnsPerPeer)
		if ok, detail := s.take(tlog.PeerUnknown); ok || detail != "uid_share_exceeded" {
			t.Fatalf("take over the unknown peer's share = %v, %q; want uid_share_exceeded", ok, detail)
		}
		if s.perUID[tlog.PeerUnknown] != maxConnsPerPeer {
			t.Fatalf("perUID = %v, want tlog.PeerUnknown counted under its own key", s.perUID)
		}
		fill(t, s, a, maxConnsPerPeer)
	})
	t.Run("arithmetic", func(t *testing.T) {
		if maxConnsPerPeer != wire.MaxPeerConns {
			t.Fatalf("maxConnsPerPeer %d, want wire.MaxPeerConns %d", maxConnsPerPeer, wire.MaxPeerConns)
		}
		if maxConns < 2*maxConnsPerPeer {
			t.Fatalf("maxConns %d, want at least two shares (%d)", maxConns, 2*maxConnsPerPeer)
		}
		// The server's ceiling: its budget plus the one GetKRL outside it
		// (Q-G5).
		ceiling := wire.MaxServerSignerCalls + 1
		if ceiling != 13 || ceiling > maxConnsPerPeer-3 || ceiling > maxConns-maxConnsPerPeer-3 {
			t.Fatalf("server ceiling %d, want 13, at most %d (its share less 3) and at most %d (beside another full share, less 3)",
				ceiling, maxConnsPerPeer-3, maxConns-maxConnsPerPeer-3)
		}
	})
}

// serveShare serves e's signer on a fresh socket and returns its path and
// a stop function that ends Serve and returns its error.
func serveShare(t *testing.T, e *logEnv) (string, func() error) {
	t.Helper()
	dir, err := os.MkdirTemp("", "krps")
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
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		return <-served
	}
	t.Cleanup(func() { _ = stop() })
	return sock, stop
}

// overloadedCount is the overloaded connections the refusal summaries
// count.
func overloadedCount(t *testing.T, e *logEnv) uint64 {
	t.Helper()
	var n uint64
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
				n += c.Count
			}
		}
	}
	return n
}

// dialIdle dials n connections that send nothing; they are closed at the
// end of the test.
func dialIdle(t *testing.T, sock string, n int) []net.Conn {
	t.Helper()
	out := make([]net.Conn, 0, n)
	for range n {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	t.Cleanup(func() {
		for _, c := range out {
			_ = c.Close()
		}
	})
	return out
}

// closedAtOnce dials one connection and requires the signer to close it
// unanswered within 3 s.
func closedAtOnce(t *testing.T, sock, what string) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("%s: read %d bytes, %v; want it closed at once (EOF)", what, n, err)
	}
}

// syncBuffer is a bytes.Buffer safe for the signer's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// slotsOf is uid's count in e's accounting.
func slotsOf(e *logEnv, uid uint32) int {
	e.s.conns.mu.Lock()
	defer e.s.conns.mu.Unlock()
	return e.s.conns.perUID[uid]
}

// TestPeerShare (F16 (03-08h)): through the real accept loop, no account
// (uid) holds more than its share of the signer's connections, another
// account's full share leaves the test's own answered, the refused uid
// reaches the operator log at a bounded rate, and a connection's slot is
// released before the connection closes.
func TestPeerShare(t *testing.T) {
	own := uint32(os.Getuid()) //nolint:gosec // G115: a uid fits uint32
	t.Run("own_share_full_next_closed", func(t *testing.T) {
		e := newLogEnv(t)
		sock, stop := serveShare(t, e)
		e.s.mu.Lock()
		locked := true
		defer func() {
			if locked {
				e.s.mu.Unlock()
			}
		}()
		busy := dialIdle(t, sock, maxConnsPerPeer)
		closedAtOnce(t, sock, "the connection over the uid's share, with maxConns-maxConnsPerPeer slots free and s.mu held")
		e.s.mu.Unlock()
		locked = false
		for _, c := range busy {
			_ = c.Close()
		}
		if err := stop(); err != nil {
			t.Fatalf("Serve: %v", err)
		}
		if n := overloadedCount(t, e); n != 1 {
			t.Fatalf("refusal summaries count %d overloaded connections, want 1", n)
		}
	})
	t.Run("other_account_share_full_status_answered", func(t *testing.T) {
		e := newLogEnv(t)
		e.s.allowUIDs = []uint32{own}
		for range maxConnsPerPeer {
			if ok, detail := e.s.conns.take(own + 1); !ok {
				t.Fatalf("pre-fill of a foreign share refused: %s", detail)
			}
		}
		sock, _ := serveShare(t, e)
		dialIdle(t, sock, maxConnsPerPeer-1)
		// The test uid's 16th slot, and the global 32nd.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := signerclient.Status(ctx, sock); err != nil {
			t.Fatalf("Status beside another account's full share: %v; want it answered", err)
		}
	})
	t.Run("operator_log_names_uid_rate_limited", func(t *testing.T) {
		e := newLogEnv(t)
		var log syncBuffer
		e.s.log = slog.New(slog.NewTextHandler(&log, nil))
		sock, stop := serveShare(t, e)
		e.s.mu.Lock()
		locked := true
		defer func() {
			if locked {
				e.s.mu.Unlock()
			}
		}()
		busy := dialIdle(t, sock, maxConnsPerPeer)
		const extra = 40
		for i := range extra {
			closedAtOnce(t, sock, fmt.Sprintf("connection %d over the share", i+1))
		}
		e.s.mu.Unlock()
		locked = false
		for _, c := range busy {
			_ = c.Close()
		}
		if err := stop(); err != nil {
			t.Fatalf("Serve: %v", err)
		}
		lines := 0
		for _, l := range strings.Split(log.String(), "\n") {
			if !strings.Contains(l, "msg=refused") || !strings.Contains(l, "reason=uid_share_exceeded") {
				continue
			}
			if !strings.Contains(l, fmt.Sprintf("uid=%d ", own)) {
				t.Fatalf("refused line %q does not name uid %d", l, own)
			}
			lines++
		}
		t.Logf("%d refused lines for uid_share_exceeded of %d refused connections", lines, extra)
		if lines < 1 || lines > DefaultRefusalLogBurst+1 {
			t.Fatalf("%d refused lines for uid_share_exceeded, want 1 to %d", lines, DefaultRefusalLogBurst+1)
		}
		if n := overloadedCount(t, e); n != extra {
			t.Fatalf("refusal summaries count %d overloaded connections, want %d", n, extra)
		}
	})
	t.Run("slot_released_before_close", func(t *testing.T) {
		e := newLogEnv(t)
		e.s.allowUIDs = []uint32{own}
		sock, _ := serveShare(t, e)
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		// 1. Hold the accounting's mutex once the slot is taken.
		deadline := time.Now().Add(3 * time.Second)
		for {
			e.s.conns.mu.Lock()
			if e.s.conns.perUID[own] == 1 {
				break
			}
			e.s.conns.mu.Unlock()
			if time.Now().After(deadline) {
				t.Fatal("the connection's slot was never taken")
			}
			time.Sleep(5 * time.Millisecond)
		}
		held := true
		defer func() {
			if held {
				e.s.conns.mu.Unlock()
			}
		}()
		// 2. One Status request, and its whole response frame.
		if err := wire.WriteMessage(c, wire.TypeStatus, nil); err != nil {
			t.Fatal(err)
		}
		if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := wire.ReadMessage(c, wire.ResponseCaps(wire.TypeStatusResponse)); err != nil {
			t.Fatalf("Status response: %v", err)
		}
		// 3. The handler's release waits for the mutex, and the close
		// follows the release: the connection is still open.
		if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read while the release waits: %d bytes, %v; want a timeout (closed before the slot was released)", n, err)
		}
		// 4. Released, then closed.
		held = false
		e.s.conns.mu.Unlock()
		if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("read after the release: %d bytes, %v; want EOF", n, err)
		}
		if n := slotsOf(e, own); n != 0 {
			t.Fatalf("uid %d holds %d slots after the close, want 0", own, n)
		}
	})
}
