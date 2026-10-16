//go:build windows

package winagent

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// ErrOwnerUnverifiable reports that the agent pipe is served by a process
// this process may not inspect. Callers fail closed: no key is sent.
var ErrOwnerUnverifiable = errors.New("cannot verify who serves the keyroster agent pipe")

// elevationGuidance explains the two causes of ErrOwnerUnverifiable. The pipe
// name is derived from the user's SID, which is not secret, and any local
// account can create it while no agent of ours runs.
const elevationGuidance = "the agent pipe is held by a process this shell cannot use or inspect. " +
	"Either it is a keyroster agent started from an elevated (\"Run as administrator\") shell: stop that process, or wait until it exits on its own (when its last key expires, or 5 minutes after start without a key), then run the command again from a normal shell. " +
	"Or another account's process took this pipe name first, which does not exit on its own: if the pipe is still there after 5 minutes, ask an administrator to find and stop the process holding it"

// unverifiable maps an access-denied result to ErrOwnerUnverifiable with the
// guidance and returns every other error unchanged.
func unverifiable(step string, err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%w: %s: %s (%w)", ErrOwnerUnverifiable, step, elevationGuidance, err)
	}
	return fmt.Errorf("%s: %w", step, err)
}

// VerifyServerOwner checks that the process serving the named pipe behind
// conn runs as the current user (pipe-squatting guard, T-02-07). It fails
// closed: any error means the caller must not send a key on conn.
func VerifyServerOwner(conn net.Conn) error {
	fc, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("verify agent pipe owner: %T is not a named-pipe connection", conn)
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(fc.Fd()), &pid); err != nil {
		return fmt.Errorf("verify agent pipe owner: server process id: %w", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return unverifiable(fmt.Sprintf("verify agent pipe owner: open server process %d", pid), err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil {
		return unverifiable(fmt.Sprintf("verify agent pipe owner: open token of server process %d", pid), err)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("verify agent pipe owner: read server process user: %w", err)
	}
	me, err := currentSID()
	if err != nil {
		return err
	}
	return checkOwner(tu.User.Sid, me)
}

// checkOwner returns nil only when the pipe server's SID equals want. It is
// the one place where the SIDs are compared.
func checkOwner(server, want *windows.SID) error {
	if server == nil || want == nil {
		return errors.New("verify agent pipe owner: missing SID")
	}
	if !server.Equals(want) {
		return fmt.Errorf("agent pipe is served by %s, not by the current user %s; refusing to send a key to it", server.String(), want.String())
	}
	return nil
}
