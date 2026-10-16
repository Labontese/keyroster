//go:build windows

package winagent

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

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
// conn runs as the current user, at Medium integrity or above, and without a
// restricted token (pipe-squatting guard, T-02-07): a sandboxed process of
// the same user can create the pipe while no agent runs. It fails closed:
// any error means the caller must not send a key on conn.
func VerifyServerOwner(conn net.Conn) error {
	fc, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("verify agent pipe owner: %T is not a named-pipe connection", conn)
	}
	me, err := currentSID()
	if err != nil {
		return err
	}
	pipe := windows.Handle(fc.Fd())
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil {
		return fmt.Errorf("verify agent pipe owner: server process id: %w", err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return deniedServer(pipe, me, fmt.Sprintf("verify agent pipe owner: open server process %d", pid), err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil {
		return deniedServer(pipe, me, fmt.Sprintf("verify agent pipe owner: open token of server process %d", pid), err)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("verify agent pipe owner: read server process user: %w", err)
	}
	if err := checkOwner(tu.User.Sid, me); err != nil {
		return err
	}
	if err := checkIntegrity(tok); err != nil {
		return err
	}
	// A restricted token (a sandbox that keeps Medium integrity) can create
	// the pipe as well.
	restricted, err := tok.IsRestricted()
	if err != nil {
		return fmt.Errorf("verify agent pipe owner: read server token restriction: %w", err)
	}
	if restricted {
		return errors.New("agent pipe is served by a process of the current user with a restricted token (a sandboxed process); refusing to send a key to it")
	}
	return nil
}

// mediumIntegrityRID is SECURITY_MANDATORY_MEDIUM_RID, the integrity level of
// a normal shell and of the agent it starts.
const mediumIntegrityRID = 0x2000

// checkIntegrity refuses a server below Medium integrity: a sandboxed process
// of the same user (Low integrity, which includes every AppContainer) can
// create the pipe while no agent runs, and would pass the SID check. The bar
// is Medium, not the caller's level, so an elevated client still accepts the
// agent of a normal shell.
func checkIntegrity(tok windows.Token) error {
	n := uint32(64)
	for {
		buf := make([]byte, n)
		err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return fmt.Errorf("verify agent pipe owner: read server integrity level: %w", err)
		}
		il := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid //nolint:gosec // G103: GetTokenInformation fills buf with a TOKEN_MANDATORY_LABEL
		if c := il.SubAuthorityCount(); c == 0 || il.SubAuthority(uint32(c-1)) < mediumIntegrityRID {
			return fmt.Errorf("agent pipe is served by a process of the current user at integrity level %s, below Medium (a sandboxed or low-integrity process); refusing to send a key to it", il.String())
		}
		return nil
	}
}

// deniedServer handles a server process this process may not inspect. The
// pipe object's owner, readable through the client handle, tells the two
// causes apart: a pipe owned by neither the current user nor Administrators
// (the owner of a pipe an elevated agent creates) was created by another
// account. Every access-denied err becomes ErrOwnerUnverifiable.
func deniedServer(pipe windows.Handle, me *windows.SID, step string, err error) error {
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return unverifiable(step, err)
	}
	sd, serr := windows.GetSecurityInfo(pipe, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if serr != nil {
		return unverifiable(step, err)
	}
	owner, _, serr := sd.Owner()
	if serr != nil || owner == nil || owner.Equals(me) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return unverifiable(step, err)
	}
	return fmt.Errorf("%w: %s: the agent pipe was created by %s, not by the current user %s: another account's process holds the pipe name (possible squatting) and does not exit on its own; refusing to send a key to it (%w)",
		ErrOwnerUnverifiable, step, owner.String(), me.String(), err)
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
