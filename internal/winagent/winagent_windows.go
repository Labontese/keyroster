//go:build windows

// Package winagent is keyroster's own in-memory ssh-agent for Windows (owner
// decision D-15 option A). The inbox Win32-OpenSSH agent refuses lifetime
// constraints and stores every key DPAPI-encrypted in the registry, so login
// keys never go there. Instead `keyroster agent` serves an x/crypto keyring on
// a per-user named pipe, honours each key's lifetime, keeps keys only in
// memory, and exits once its last key has expired.
//
// The pipe is \\.\pipe\keyroster-agent-<user SID>. Its security descriptor
// grants only that SID and denies network logons, and the first-instance
// creation refuses an existing pipe, so neither a second agent nor a squatter
// can take it over. Clients check the pipe's server process with
// VerifyServerOwner before they send a key (Ensure does so).
package winagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

const (
	pipePrefix = `\\.\pipe\keyroster-agent-`

	// DefaultPoll is how often Serve expires keys and checks its exit rule.
	DefaultPoll = 5 * time.Second
	// DefaultIdleExit is how long Serve waits for a first key before it exits.
	DefaultIdleExit = 5 * time.Minute
)

// Options tunes Serve's timings. Zero fields take the defaults; the fields
// exist so tests can shorten them. There is no environment or flag override.
type Options struct {
	// Poll is the interval at which expired keys are dropped and the exit
	// rule is checked (default DefaultPoll).
	Poll time.Duration
	// IdleExit is how long Serve runs without any key ever being added
	// (default DefaultIdleExit).
	IdleExit time.Duration
}

// currentSID returns the SID of the user this process runs as.
func currentSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the current user's SID: %w", err)
	}
	return tu.User.Sid.Copy()
}

// PipePath returns the current user's agent pipe,
// \\.\pipe\keyroster-agent-<SID>.
func PipePath() (string, error) {
	sid, err := currentSID()
	if err != nil {
		return "", err
	}
	return pipePrefix + sid.String(), nil
}

// OpenSSHSpelling returns pipe (\\.\pipe\name) as //./pipe/name, the spelling
// Windows OpenSSH accepts in IdentityAgent (the -o option and ssh_config) as
// well as in SSH_AUTH_SOCK. OpenSSH treats backslashes in IdentityAgent as
// escapes, so the backslash spelling fails there ("No such file or
// directory"; verified with inbox OpenSSH_for_Windows_9.5p2, 02-02 Task 1).
func OpenSSHSpelling(pipe string) string {
	return strings.ReplaceAll(pipe, `\`, "/")
}

// SDDL returns the pipe's security descriptor: a protected DACL that denies
// network logons (NU) and grants only sid.
func SDDL(sid string) string {
	return "D:P(D;;GA;;;NU)(A;;GA;;;" + sid + ")"
}

// trackingAgent is the served keyring. It records that a key was added, so
// the exit rule can tell "every key has expired" from "no key yet" even when
// a short-lived key is added and expires between two polls.
type trackingAgent struct {
	agent.ExtendedAgent
	added func()
}

func (a trackingAgent) Add(key agent.AddedKey) error {
	if err := a.ExtendedAgent.Add(key); err != nil {
		return err
	}
	a.added()
	return nil
}

// Serve listens on path and serves one in-memory keyring to every connection
// until the exit rule holds, then returns nil:
//   - a key was added at some point and the keyring is now empty (every key
//     expired or was removed), or no key was added within opts.IdleExit; and
//   - no client connection is open.
//
// The exit decision and connection accounting share one mutex: a connection
// accepted after the decision is closed at once, and Serve returns only after
// every serving goroutine has ended, so a key added on an open connection is
// never lost to an exit. Serve never listens again after it closes the
// listener, since recreating the pipe would reopen a window in which another
// process could create it first. When ctx ends, Serve stops the same way and
// returns ctx.Err().
func Serve(ctx context.Context, path string, opts Options) error {
	if opts.Poll <= 0 {
		opts.Poll = DefaultPoll
	}
	if opts.IdleExit <= 0 {
		opts.IdleExit = DefaultIdleExit
	}
	sid, err := currentSID()
	if err != nil {
		return err
	}
	l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: SDDL(sid.String())})
	if err != nil {
		return fmt.Errorf("create agent pipe %s: %w (the pipe already exists: another keyroster agent, or another process, serves it)", path, err)
	}

	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		_ = l.Close()
		return errors.New("x/crypto keyring does not implement ExtendedAgent")
	}
	var (
		mu      sync.Mutex
		conns   = map[net.Conn]struct{}{} // open client connections
		added   bool                      // a key was added at some point
		exiting bool                      // the exit decision was made; refuse new connections
		wg      sync.WaitGroup
	)
	served := trackingAgent{ExtendedAgent: keyring, added: func() {
		mu.Lock()
		added = true
		mu.Unlock()
	}}

	acceptDone := make(chan error, 1)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					err = nil
				}
				acceptDone <- err
				return
			}
			mu.Lock()
			if exiting {
				mu.Unlock()
				_ = conn.Close()
				continue
			}
			conns[conn] = struct{}{}
			wg.Add(1)
			mu.Unlock()
			go func(c net.Conn) {
				defer wg.Done()
				_ = agent.ServeAgent(served, c)
				_ = c.Close()
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
			}(conn)
		}
	}()

	// stopNow ends serving without waiting for clients: it refuses new
	// connections and closes the open ones (cancellation or listener failure
	// only; the normal exit rule never closes an open connection).
	stopNow := func() {
		mu.Lock()
		exiting = true
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}

	start := time.Now()
	ticker := time.NewTicker(opts.Poll)
	defer ticker.Stop()
	var result error
loop:
	for {
		select {
		case <-ctx.Done():
			stopNow()
			result = ctx.Err()
			break loop
		case err := <-acceptDone:
			// The listener failed on its own; stop serving.
			stopNow()
			wg.Wait()
			_ = keyring.RemoveAll()
			if err == nil {
				err = errors.New("agent pipe listener closed unexpectedly")
			}
			return err
		case <-ticker.C:
		}
		mu.Lock()
		// List drops lifetime-expired keys (and returns nothing while the
		// keyring is locked, so a locked agent exits and its keys go with it).
		keys, err := keyring.List()
		if err == nil && len(conns) == 0 &&
			((added && len(keys) == 0) || (!added && time.Since(start) >= opts.IdleExit)) {
			exiting = true
			mu.Unlock()
			break loop
		}
		mu.Unlock()
	}
	_ = l.Close()
	if err := <-acceptDone; err != nil && result == nil {
		result = err
	}
	wg.Wait()
	_ = keyring.RemoveAll()
	return result
}
