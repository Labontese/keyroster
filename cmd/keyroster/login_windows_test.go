//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/winagent"
)

// useUnusableLoginAgent leaves keyroster login without a usable agent the
// Windows way: connectLoginAgent fails as winagent.Ensure does when it
// cannot verify who serves the pipe. It returns the text the login must
// print.
func useUnusableLoginAgent(t *testing.T) string {
	t.Helper()
	prev := connectLoginAgent
	connectLoginAgent = func(context.Context) (net.Conn, error) {
		return nil, fmt.Errorf("%w: test pipe", winagent.ErrOwnerUnverifiable)
	}
	t.Cleanup(func() { connectLoginAgent = prev })
	return winagent.ErrOwnerUnverifiable.Error()
}

// startLoginTestAgent runs keyroster's own agent (winagent.Serve) in
// process on a random test pipe and points connectLoginAgent at it: the
// replacement dials the pipe and returns the connection only after
// winagent.VerifyServerOwner accepted it, so the Windows add with a
// lifetime and the listing check run against a real keyring over a real
// named pipe. It never dials winagent.PipePath(), so a keyroster agent the
// account already runs is never touched. The default connectLoginAgent
// (os.Executable, then winagent.Ensure) is not run here. It returns a
// function that lists the agent.
func startLoginTestAgent(t *testing.T) func(t *testing.T) []*agent.Key {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	pipe := `\\.\pipe\keyroster-test-` + hex.EncodeToString(b[:])
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- winagent.Serve(ctx, pipe, winagent.Options{Poll: 200 * time.Millisecond, IdleExit: 2 * time.Minute})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	dial := func(ctx context.Context) (net.Conn, error) {
		conn, err := winio.DialPipeContext(ctx, pipe)
		if err != nil {
			return nil, err
		}
		if err := winagent.VerifyServerOwner(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dial(dctx)
		dcancel()
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the test agent pipe %s did not come up within 5 s: %v", pipe, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	prev := connectLoginAgent
	connectLoginAgent = dial
	t.Cleanup(func() { connectLoginAgent = prev })
	return func(t *testing.T) []*agent.Key {
		t.Helper()
		lctx, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer lcancel()
		conn, err := dial(lctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		keys, err := agent.NewClient(conn).List()
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}
}
