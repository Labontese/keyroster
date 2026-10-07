package signer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// connDeadline bounds one connection: peer check, one request, one response.
const connDeadline = 10 * time.Second

// maxConns bounds concurrently handled connections.
const maxConns = 32

// Peer is the kernel-reported identity of a connected client.
type Peer struct {
	UID    uint32
	GID    uint32 // primary gid
	PID    int32
	Groups []uint32 // supplementary gids (SO_PEERGROUPS)
}

// Listen binds a path-based Unix socket at path with mode 0660. A stale
// socket at path (one that refuses connections) is removed first; a socket
// that still accepts connections belongs to a running signer and is an
// error, as is any other kind of file there. When gid >= 0 the socket's
// group is set to gid.
func Listen(path string, gid int) (*net.UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("signer: %s exists and is not a socket", path)
		}
		// Never unlink a live signer's socket: probe it first. The probe
		// shows up in the running signer's log as a refused connection.
		conn, derr := net.DialTimeout("unix", path, time.Second)
		if derr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("signer: %s accepts connections: another signer is already serving on it", path)
		}
		if !errors.Is(derr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("signer: %s exists and cannot be probed, so it is not removed: %w", path, derr)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("signer: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("signer: %w", err)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("signer: listen: %w", err)
	}
	l.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // G302: group access is the point; peers are checked per connection
		_ = l.Close()
		return nil, fmt.Errorf("signer: chmod socket: %w", err)
	}
	if gid >= 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("signer: chown socket: %w", err)
		}
	}
	return l, nil
}

// Serve accepts connections on l until ctx is cancelled, then closes l,
// waits for the open connections to finish and flushes the pending refusal
// counts as a final refusal_summary leaf. While serving, the counts are
// flushed every minute.
func (s *Signer) Serve(ctx context.Context, l *net.UnixListener) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	loopCtx, cancelLoop := context.WithCancel(ctx)
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		s.flushLoop(loopCtx)
	}()
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		cancelLoop()
		<-flushDone
		s.flushSummaries(context.WithoutCancel(ctx))
	}()
	sem := make(chan struct{}, maxConns)
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("signer: accept: %w", err)
		}
		select {
		case sem <- struct{}{}:
		default:
			// Over capacity. The accept loop must not wait for s.mu, which
			// an in-flight issuance holds across CA signing: close, count
			// atomically for the next refusal_summary leaf (flushSummaries),
			// and keep accepting. Nothing is sent.
			_ = conn.Close()
			s.overloaded.Add(1)
			s.log.Warn("refused", "uid", tlog.PeerUnknown, "pid", 0, "reason", "too_many_connections",
				"class", tlog.ReasonName(tlog.ReasonOverloaded), "code", codeFor(tlog.ReasonOverloaded).String())
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handle(ctx, conn)
		}()
	}
}

// handle serves one connection: peer check before reading anything, one
// request frame, one response frame. Every refusal goes through refuse
// (slog plus the rate-limited audit log, D-14).
func (s *Signer) handle(ctx context.Context, conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(connDeadline)); err != nil {
		return
	}
	peer, err := peerCredentials(conn)
	if err != nil {
		_ = s.refuse(ctx, Peer{UID: tlog.PeerUnknown}, [32]byte{}, tlog.ReasonPeerNotAllowed, "peer_credentials_unavailable") // logged; nothing is sent
		return
	}
	if !s.allowed(peer) {
		// Nothing is read from or sent to a peer that is not allowed.
		_ = s.refuse(ctx, peer, [32]byte{}, tlog.ReasonPeerNotAllowed, "peer_not_allowed")
		return
	}
	msgType, body, err := wire.ReadMessage(conn)
	if err != nil {
		s.reply(conn, s.refuse(ctx, peer, [32]byte{}, tlog.ReasonMalformed, "malformed_frame"))
		return
	}
	if msgType != wire.TypeIssueRequest {
		s.reply(conn, s.refuse(ctx, peer, [32]byte{}, tlog.ReasonMalformed, "unknown_message_type"))
		return
	}
	req, err := wire.ParseIssueRequest(body)
	if err != nil {
		s.reply(conn, s.refuse(ctx, peer, [32]byte{}, tlog.ReasonMalformed, "malformed_request"))
		return
	}
	resp, refused := s.issueOrRefuse(ctx, peer, req)
	if refused != nil {
		s.reply(conn, refused)
		return
	}
	out, err := resp.Marshal()
	if err != nil {
		s.reply(conn, s.refuse(ctx, peer, req.Digest(), tlog.ReasonInternal, "response_encoding"))
		return
	}
	if err := wire.WriteMessage(conn, wire.TypeIssueResponse, out); err != nil {
		s.log.Warn("response not delivered", "uid", peer.UID, "pid", peer.PID, "serial", resp.Serial)
	}
}

// reply sends a refusal to the peer. Only the reason code leaves the
// process; request bytes are never echoed.
func (s *Signer) reply(conn *net.UnixConn, e *wire.ErrorResponse) {
	body, err := e.Marshal()
	if err != nil {
		return
	}
	_ = wire.WriteMessage(conn, wire.TypeError, body)
}
