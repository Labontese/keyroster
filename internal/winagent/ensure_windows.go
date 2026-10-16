//go:build windows

package winagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"syscall"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

// startWait bounds the wait for a freshly started agent's pipe, and each dial.
const startWait = 5 * time.Second

// Ensure returns a connection to the current user's keyroster agent, starting
// `exe agent` detached when no agent serves PipePath(). The connection is
// returned only after VerifyServerOwner accepted the pipe's server process
// and the agent answered one List request; from then on the agent counts the
// connection as open and does not exit while it stays open. Ensure dials only
// PipePath(), never the inbox OpenSSH agent's pipe, and has no test hook.
func Ensure(ctx context.Context, exe string) (net.Conn, error) {
	path, err := PipePath()
	if err != nil {
		return nil, err
	}
	start := func() error {
		cmd := exec.Command(exe, "agent") //nolint:gosec // G204: exe is the running keyroster binary, chosen by the caller
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
			HideWindow:    true,
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start keyroster agent: %w", err)
		}
		// The agent outlives this process and exits by its own rule.
		_ = cmd.Process.Release()
		return nil
	}
	return ensure(ctx, path, start, VerifyServerOwner)
}

// ensure is Ensure with the pipe, the start function and the owner check as
// parameters, so tests can use a test pipe, an in-process Serve and a
// rejecting verifier. Production code reaches it only through Ensure.
//
// Steps: dial path (starting the agent when the pipe does not exist), verify
// the server, confirm with one List. If List fails because the agent was
// shutting down, the steps run once more, which starts a fresh agent.
func ensure(ctx context.Context, path string, start func() error, verify func(net.Conn) error) (net.Conn, error) {
	for attempt := 1; ; attempt++ {
		conn, err := dialOrStart(ctx, path, start)
		if err != nil {
			return nil, err
		}
		if err := verify(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		transportErr, err := listOnce(conn)
		if err == nil {
			return conn, nil
		}
		_ = conn.Close()
		if attempt == 1 && agentClosing(transportErr) {
			continue
		}
		return nil, fmt.Errorf("keyroster agent on %s did not answer: %w", path, err)
	}
}

// dialOrStart dials path; when the pipe does not exist it calls start and
// polls the pipe for up to startWait.
func dialOrStart(ctx context.Context, path string, start func() error) (net.Conn, error) {
	conn, err := dial(ctx, path)
	if err == nil || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return conn, err
	}
	if err := start(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(startWait)
	for {
		conn, err := dial(ctx, path)
		if err == nil || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return conn, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("keyroster agent did not create %s within %s", path, startWait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// dial opens path once (go-winio retries a busy pipe until startWait). An
// access-denied result means the pipe belongs to a process this one cannot
// use: an elevated agent, or another account's process that took the name.
// That is ErrOwnerUnverifiable, fail closed.
func dial(ctx context.Context, path string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, startWait)
	defer cancel()
	conn, err := winio.DialPipeContext(dctx, path)
	switch {
	case err == nil:
		return conn, nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return nil, unverifiable("connect to "+path, err)
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return nil, err
	default:
		return nil, fmt.Errorf("connect to %s: %w", path, err)
	}
}

// listOnce sends one List request on conn. The x/crypto client gets conn as
// a plain io.ReadWriter (not an io.Closer), so it uses its serial path and
// leaves no background reader on conn, which goes to the caller afterwards.
// transportErr is the first read or write error on conn, which the client's
// own error does not wrap.
func listOnce(conn net.Conn) (transportErr, err error) {
	rec := &ioRecorder{rw: conn}
	_, err = agent.NewClient(rec).List()
	return rec.err, err
}

// ioRecorder passes reads and writes through and keeps the first error.
type ioRecorder struct {
	rw  io.ReadWriter
	err error
}

func (r *ioRecorder) Read(b []byte) (int, error) {
	n, err := r.rw.Read(b)
	if err != nil && r.err == nil {
		r.err = err
	}
	return n, err
}

func (r *ioRecorder) Write(b []byte) (int, error) {
	n, err := r.rw.Write(b)
	if err != nil && r.err == nil {
		r.err = err
	}
	return n, err
}

// agentClosing reports whether err is what a client sees when the agent
// closed the connection, as Serve does to connections accepted after its
// exit decision.
func agentClosing(err error) bool {
	return err != nil && (errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED))
}
