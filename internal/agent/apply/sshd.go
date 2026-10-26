//go:build linux

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
)

// This file holds every exec site of the applier (paths.ExecSites; the
// AST walk in internal/agent/paths pins them): each runs a binary from
// the Config or a fixed absolute path, with literal flags, through
// Config.Exec. Nothing else in internal/agent runs a program.

// Result is what one run of a program gave: its output, capped, and its
// exit status.
type Result struct {
	Stdout, Stderr []byte
	Code           int
}

// Runner runs a prepared command. ExecRunner runs it; tests substitute a
// fake that answers by cmd.Path and cmd.Args without running anything.
type Runner interface {
	Run(cmd *exec.Cmd) (Result, error)
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

// Run runs cmd. A non-zero exit is a Result, not an error; an error is a
// program that could not be started or was killed by its context.
func (ExecRunner) Run(cmd *exec.Cmd) (Result, error) {
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

// run runs cmd through the configured runner.
func (e *engine) run(cmd *exec.Cmd) (Result, error) {
	return e.cfg.Exec.Run(cmd)
}

// firstLine is the first line of a program's error output, for messages.
func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return s
}

// sshdTest runs sshd -t -f <config>: the service's own binary checks the
// configuration it will load at the next reload.
func (e *engine) sshdTest(ctx context.Context) error {
	res, err := e.run(exec.CommandContext(ctx, e.cfg.SSHD, "-t", "-f", e.cfg.SSHDConfig)) //nolint:gosec // G204: an exec site of paths.ExecSites, absolute paths from the operator's configuration
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHDTest, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: sshd -t exited %d: %s", ErrSSHDTest, res.Code, firstLine(res.Stderr))
	}
	return nil
}

// sshdDump runs sshd -T -f <config>, with -C spec when spec is not empty,
// and parses its output.
func (e *engine) sshdDump(ctx context.Context, spec string) (Dump, error) {
	var cmd *exec.Cmd
	if spec == "" {
		cmd = exec.CommandContext(ctx, e.cfg.SSHD, "-T", "-f", e.cfg.SSHDConfig) //nolint:gosec // G204: an exec site of paths.ExecSites
	} else {
		cmd = exec.CommandContext(ctx, e.cfg.SSHD, "-T", "-f", e.cfg.SSHDConfig, "-C", spec) //nolint:gosec // G204: an exec site of paths.ExecSites
	}
	res, err := e.run(cmd)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSSHDDump, err)
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("%w: sshd -T exited %d: %s", ErrSSHDDump, res.Code, firstLine(res.Stderr))
	}
	return ParseDump(res.Stdout), nil
}

// keygenFingerprint runs ssh-keygen -l -f file: the host's own tools must
// read a CA key line.
func (e *engine) keygenFingerprint(ctx context.Context, file string) (Result, error) {
	return e.run(exec.CommandContext(ctx, e.cfg.SSHKeygen, "-l", "-f", file)) //nolint:gosec // G204: an exec site of paths.ExecSites; file is the agent's own check file
}

// keygenQuery runs ssh-keygen -Q -f krl pub: exit 0 means the host's own
// tools read the KRL and it does not revoke pub.
func (e *engine) keygenQuery(ctx context.Context, krlFile, pub string) (Result, error) {
	return e.run(exec.CommandContext(ctx, e.cfg.SSHKeygen, "-Q", "-f", krlFile, pub)) //nolint:gosec // G204: an exec site of paths.ExecSites; both files are the agent's own
}

// reloadSystemd runs systemctl reload <unit> with the first of
// paths.Systemctl that exists.
func (e *engine) reloadSystemd(ctx context.Context, unit string) error {
	systemctl := ""
	for _, p := range paths.Systemctl {
		if _, err := os.Stat(p); err == nil {
			systemctl = p
			break
		}
	}
	if systemctl == "" {
		return fmt.Errorf("%w: no systemctl at %s", ErrReload, strings.Join(paths.Systemctl, " or "))
	}
	res, err := e.run(exec.CommandContext(ctx, systemctl, "reload", unit)) //nolint:gosec // G204: a fixed systemctl path and a unit name checked against unitRE
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReload, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: systemctl reload %s exited %d: %s", ErrReload, unit, res.Code, firstLine(res.Stderr))
	}
	return nil
}

// reloadOpenRC runs rc-service sshd reload.
func (e *engine) reloadOpenRC(ctx context.Context) error {
	rcService := paths.RCService
	res, err := e.run(exec.CommandContext(ctx, rcService, "sshd", "reload")) //nolint:gosec // G204: a fixed path
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReload, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: rc-service sshd reload exited %d: %s", ErrReload, res.Code, firstLine(res.Stderr))
	}
	return nil
}

// Errors of the sshd helpers.
var (
	ErrSSHDTest = errors.New("sshd_t_failed")
	ErrSSHDDump = errors.New("sshd_T_failed")
	ErrReload   = errors.New("reload_failed")
)

// unitRE is a systemd service name the systemd reload strategy accepts.
var unitRE = regexp.MustCompile(`^[a-z0-9@._-]+\.service$`)

// CheckReload checks a --reload strategy: signal, systemd:<unit> or
// openrc.
func CheckReload(s string) error {
	switch {
	case s == "signal" || s == "openrc":
		return nil
	case strings.HasPrefix(s, "systemd:") && unitRE.MatchString(strings.TrimPrefix(s, "systemd:")):
		return nil
	}
	return fmt.Errorf("%w: reload strategy %q: want signal, systemd:<unit>.service or openrc", ErrReload, s)
}

// reload makes sshd re-read its configuration by the configured strategy
// (a closed set): signal sends SIGHUP to the pid in the PidFile sshd -T
// names, when that process runs the configured sshd, and runs nothing; systemd:<unit> runs systemctl reload <unit>;
// openrc runs rc-service sshd reload.
func (e *engine) reload(ctx context.Context, dump Dump) error {
	if err := CheckReload(e.cfg.Reload); err != nil {
		return err
	}
	switch e.cfg.Reload {
	case "signal":
		return reloadSignal(e.cfg.SSHD, dump)
	case "openrc":
		return e.reloadOpenRC(ctx)
	default:
		return e.reloadSystemd(ctx, strings.TrimPrefix(e.cfg.Reload, "systemd:"))
	}
}

// reloadSignal sends SIGHUP to sshd's listener, read from its PidFile,
// and only when that process runs the configured sshd binary (PR #67
// review: a stale PidFile can name a reused PID). The process is held by
// a pidfd from before the check to the signal, so a PID reused in
// between is never signalled.
func reloadSignal(sshd string, dump Dump) error {
	pidFile := dump.One("pidfile")
	if pidFile == "" || pidFile == "none" {
		return fmt.Errorf("%w: sshd -T names no pidfile", ErrReload)
	}
	f, err := os.Open(pidFile) //nolint:gosec // G304: the PidFile sshd's own configuration names
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReload, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReload, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("%w: %s does not hold a process ID", ErrReload, pidFile)
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("%w: process %d named by %s: %w", ErrReload, pid, pidFile, err)
	}
	defer func() { _ = unix.Close(pidfd) }()
	if err := runsBinary(pid, sshd); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrReload, pidFile, err)
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGHUP, nil, 0); err != nil {
		return fmt.Errorf("%w: SIGHUP to %d: %w", ErrReload, pid, err)
	}
	return nil
}

// runsBinary checks that process pid runs the binary at path: its
// /proc/<pid>/exe is that file, or, after an upgrade replaced the file
// under the running process, names path marked " (deleted)".
func runsBinary(pid int, path string) error {
	exe := "/proc/" + strconv.Itoa(pid) + "/exe"
	if want, err := os.Stat(path); err == nil {
		if got, err := os.Stat(exe); err == nil && os.SameFile(want, got) {
			return nil
		}
	}
	target, err := os.Readlink(exe)
	if err != nil {
		return fmt.Errorf("process %d: %w", pid, err)
	}
	if strings.TrimSuffix(target, " (deleted)") == filepath.Clean(path) {
		return nil
	}
	return fmt.Errorf("process %d runs %s, not %s", pid, target, path)
}

// Dump is sshd -T output: lowercase keyword to its values, one per line
// sshd printed for it, in order.
type Dump map[string][]string

// ParseDump parses sshd -T output.
func ParseDump(out []byte) Dump {
	d := Dump{}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		d[k] = append(d[k], strings.TrimSpace(v))
	}
	return d
}

// One is the first value of keyword k, or "".
func (d Dump) One(k string) string {
	if v := d[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Login grace refusals.
var (
	ErrLoginGraceUnbounded = errors.New("login_grace_unbounded")
	ErrLoginGraceUnknown   = errors.New("login_grace_unknown")
)

// LoginGrace returns sshd's effective LoginGraceTime in whole seconds.
// sshd_config(5) does not allow LoginGraceTime inside a Match block, so
// the global sshd -T value is the one every connection gets. 0 (no limit)
// is login_grace_unbounded, because the two-step swap needs a bound; a
// value that is not a whole number of seconds is login_grace_unknown.
func (d Dump) LoginGrace() (int, error) {
	v := d.One("logingracetime")
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 86400 {
		return 0, fmt.Errorf("%w: sshd -T reports logingracetime %q", ErrLoginGraceUnknown, v)
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: sshd -T reports logingracetime 0 (no limit); set LoginGraceTime in sshd_config", ErrLoginGraceUnbounded)
	}
	return n, nil
}
