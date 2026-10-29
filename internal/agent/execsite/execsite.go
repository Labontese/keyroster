//go:build linux

// Package execsite holds every program the keyroster agent runs (D-05,
// T-03-31, PR #67 review). It is the only package under internal/agent and
// cmd/keyroster-agent that imports os/exec: each exec site is a
// constructor with its binary and fixed flags (paths.ExecSites pins every
// constructor, its argument shape and its one caller), Cmd's fields are
// unexported so no other package can build a command, and ExecRunner.Run
// is the one place a Cmd runs. internal/agent/paths' TestPaths and
// capslock's baseline (EXEC only in this package) gate it.
package execsite

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// Cmd is one prepared program run: the binary and its argv (argv[0] is
// the binary). Only the constructors below make one.
type Cmd struct {
	path string
	args []string
}

// Path is the binary Cmd runs.
func (c Cmd) Path() string { return c.path }

// Args is Cmd's argv, argv[0] included (a copy).
func (c Cmd) Args() []string { return append([]string(nil), c.args...) }

// SSHDTest is sshd -t -f config: the service's own binary checks the
// configuration it will load at the next reload.
func SSHDTest(sshd, config string) Cmd {
	return Cmd{path: sshd, args: []string{sshd, "-t", "-f", config}}
}

// SSHDDump is sshd -T -f config: the effective configuration.
func SSHDDump(sshd, config string) Cmd {
	return Cmd{path: sshd, args: []string{sshd, "-T", "-f", config}}
}

// SSHDDumpFor is sshd -T -f config -C spec: the effective configuration
// for one connection specification.
func SSHDDumpFor(sshd, config, spec string) Cmd {
	return Cmd{path: sshd, args: []string{sshd, "-T", "-f", config, "-C", spec}}
}

// SSHDVersion is sshd -V: the service's binary prints its version, for
// the heartbeat (03-08, AGENT-07). An sshd without -V prints its version
// in its usage text.
func SSHDVersion(sshd string) Cmd {
	return Cmd{path: sshd, args: []string{sshd, "-V"}}
}

// KeygenFingerprint is ssh-keygen -l -f file: the host's own tools must
// read a CA key line.
func KeygenFingerprint(keygen, file string) Cmd {
	return Cmd{path: keygen, args: []string{keygen, "-l", "-f", file}}
}

// KeygenQuery is ssh-keygen -Q -f krl pub: exit 0 means the host's own
// tools read the KRL and it does not revoke pub.
func KeygenQuery(keygen, krl, pub string) Cmd {
	return Cmd{path: keygen, args: []string{keygen, "-Q", "-f", krl, pub}}
}

// SystemctlReload is systemctl reload unit.
func SystemctlReload(systemctl, unit string) Cmd {
	return Cmd{path: systemctl, args: []string{systemctl, "reload", unit}}
}

// SystemctlTryReloadOrRestart is systemctl try-reload-or-restart unit:
// a running unit re-reads its configuration, a stopped one stays stopped
// and reads the files on disk when it next starts (the socket-activated
// sshd's strategy, PR #68 review D-R1).
func SystemctlTryReloadOrRestart(systemctl, unit string) Cmd {
	return Cmd{path: systemctl, args: []string{systemctl, "try-reload-or-restart", unit}}
}

// SystemctlShow is systemctl show for the units sshd may run as: each
// unit's Id, LoadState, ActiveState, ExecStart, EnvironmentFiles and
// Environment, as KEY=VALUE blocks separated by blank lines (03-06
// Detect; the last two resolve a $VAR in ExecStart, PR #68 review D-R4).
func SystemctlShow(systemctl string) Cmd {
	return Cmd{path: systemctl, args: []string{systemctl, "show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "-p", "ExecStart", "-p", "EnvironmentFiles", "-p", "Environment", "ssh.socket", "ssh.service", "sshd.service"}}
}

// RCServiceReload is rc-service sshd reload.
func RCServiceReload(rcService string) Cmd {
	return Cmd{path: rcService, args: []string{rcService, "sshd", "reload"}}
}

// Result is what one run of a program gave: its output, capped, and its
// exit status.
type Result struct {
	Stdout, Stderr []byte
	Code           int
}

// Runner runs a Cmd. ExecRunner runs it; tests substitute a fake that
// answers by Path and Args without running anything.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

// Output caps of one program run.
const (
	maxStdout = 1 << 20
	maxStderr = 64 << 10
)

// cappedBuffer keeps at most max bytes and drops the rest.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// ExecRunner runs commands with a minimal environment and capped output.
type ExecRunner struct{}

// Run runs c until it exits or ctx ends. A non-zero exit is a Result, not
// an error; an error is a program that could not be started or was
// killed by its context.
func (ExecRunner) Run(ctx context.Context, c Cmd) (Result, error) {
	if len(c.args) == 0 || c.path == "" {
		return Result{}, errors.New("execsite: an empty command")
	}
	cmd := exec.CommandContext(ctx, c.path, c.args[1:]...) //nolint:gosec // G204: c comes only from this package's pinned constructors
	out, errOut := &cappedBuffer{max: maxStdout}, &cappedBuffer{max: maxStderr}
	cmd.Stdout, cmd.Stderr, cmd.Stdin = out, errOut, nil
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	err := cmd.Run()
	res := Result{Stdout: out.buf.Bytes(), Stderr: errOut.buf.Bytes()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		res.Code = ee.ExitCode()
	default:
		return res, err
	}
	return res, nil
}
