package signer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

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
// socket at path is removed first; any other kind of file there is an
// error. When gid >= 0 the socket's group is set to gid.
func Listen(path string, gid int) (*net.UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("signer: %s exists and is not a socket", path)
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

// Serve accepts connections on l until ctx is cancelled, then closes l and
// waits for the open connections to finish.
func (s *Signer) Serve(ctx context.Context, l *net.UnixListener) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
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
			s.log.Warn("refused", "reason", "too_many_connections")
			_ = conn.Close()
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
// request frame, one response frame.
func (s *Signer) handle(ctx context.Context, conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(connDeadline)); err != nil {
		return
	}
	peer, err := peerCredentials(conn)
	if err != nil {
		s.log.Warn("refused", "reason", "peer_credentials_unavailable")
		return
	}
	if !s.allowed(peer) {
		s.log.Warn("refused", "uid", peer.UID, "pid", peer.PID, "reason", "peer_not_allowed")
		return
	}
	msgType, body, err := wire.ReadMessage(conn)
	if err != nil {
		s.reply(conn, peer, refuse(wire.CodeMalformed, "malformed_frame", err))
		return
	}
	if msgType != wire.TypeIssueRequest {
		s.reply(conn, peer, refuse(wire.CodeMalformed, "unknown_message_type", nil))
		return
	}
	req, err := wire.ParseIssueRequest(body)
	if err != nil {
		s.reply(conn, peer, refuse(wire.CodeMalformed, "malformed_request", err))
		return
	}
	resp, err := s.Issue(ctx, peer, req)
	if err != nil {
		s.reply(conn, peer, err)
		return
	}
	out, err := resp.Marshal()
	if err != nil {
		s.reply(conn, peer, refuse(wire.CodeInternal, "response_encoding", err))
		return
	}
	if err := wire.WriteMessage(conn, wire.TypeIssueResponse, out); err != nil {
		s.log.Warn("response not delivered", "uid", peer.UID, "pid", peer.PID, "serial", resp.Serial)
	}
}

// reply logs a refusal and sends it to the peer as an ErrorResponse. Only
// the reason code leaves the process; request bytes are never echoed.
func (s *Signer) reply(conn *net.UnixConn, peer Peer, err error) {
	var r *refusal
	if !errors.As(err, &r) {
		r = &refusal{code: wire.CodeInternal, reason: "internal_error", cause: err}
	}
	s.log.Warn("refused", "uid", peer.UID, "pid", peer.PID, "reason", r.reason, "code", r.code.String())
	body, mErr := (&wire.ErrorResponse{Code: r.code, Message: r.reason}).Marshal()
	if mErr != nil {
		return
	}
	_ = wire.WriteMessage(conn, wire.TypeError, body)
}
