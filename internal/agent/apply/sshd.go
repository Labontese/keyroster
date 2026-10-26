//go:build linux

package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/paths"
)

// This file holds every exec site of the applier: each builds its
// command with a constructor of internal/agent/execsite, the only package
// that imports os/exec, from a binary in the Config or a fixed absolute
// path, and runs it through Config.Exec. paths.ExecSites pins each site,
// its constructor and its binary (TestPaths).

// Result is execsite's: a run's capped output and exit status.
type Result = execsite.Result

// Runner is execsite's: what runs a command (tests substitute a fake).
type Runner = execsite.Runner

// run runs c through the configured runner.
func (e *engine) run(ctx context.Context, c execsite.Cmd) (Result, error) {
	return e.cfg.Exec.Run(ctx, c)
}

// firstLine is the first line of a program's error output, for messages.
func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return s
}

// sshdTest runs sshd -t -f <config>: the service's own binary checks the
// configuration it will load at the next reload.
func (e *engine) sshdTest(ctx context.Context) error {
	res, err := e.run(ctx, execsite.SSHDTest(e.cfg.SSHD, e.cfg.SSHDConfig))
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
	c := execsite.SSHDDump(e.cfg.SSHD, e.cfg.SSHDConfig)
	if spec != "" {
		c = execsite.SSHDDumpFor(e.cfg.SSHD, e.cfg.SSHDConfig, spec)
	}
	res, err := e.run(ctx, c)
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
	return e.run(ctx, execsite.KeygenFingerprint(e.cfg.SSHKeygen, file))
}

// keygenQuery runs ssh-keygen -Q -f krl pub: exit 0 means the host's own
// tools read the KRL and it does not revoke pub.
func (e *engine) keygenQuery(ctx context.Context, krlFile, pub string) (Result, error) {
	return e.run(ctx, execsite.KeygenQuery(e.cfg.SSHKeygen, krlFile, pub))
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
	res, err := e.run(ctx, execsite.SystemctlReload(systemctl, unit))
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
	res, err := e.run(ctx, execsite.RCServiceReload(paths.RCService))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReload, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("%w: rc-service sshd reload exited %d: %s", ErrReload, res.Code, firstLine(res.Stderr))
	}
	return nil
}

// systemctlShow runs systemctl show for ssh.socket, ssh.service and
// sshd.service (Detect): the service manager says which binary and
// configuration the running sshd uses.
func systemctlShow(ctx context.Context, r Runner, systemctl string) (Result, error) {
	return r.Run(ctx, execsite.SystemctlShow(systemctl))
}

// Errors of the sshd helpers.
var (
	ErrSSHDTest = errors.New("sshd_t_failed")
	ErrSSHDDump = errors.New("sshd_T_failed")
	ErrReload   = errors.New("reload_failed")
)

// unitRE is a systemd service name the systemd reload strategy accepts.
var unitRE = regexp.MustCompile(`^[a-z0-9@._-]+\.service$`)

// ReloadNone is the reload strategy of a socket-activated sshd whose
// service is not running (Ubuntu's ssh.socket with ssh.service inactive):
// the next connection starts sshd, which reads the configuration fresh,
// so nothing is reloaded. sshd -t still checks every changed drop-in.
const ReloadNone = "none"

// CheckReload checks a --reload strategy: signal, systemd:<unit>, openrc
// or none.
func CheckReload(s string) error {
	switch {
	case s == "signal" || s == "openrc" || s == ReloadNone:
		return nil
	case strings.HasPrefix(s, "systemd:") && unitRE.MatchString(strings.TrimPrefix(s, "systemd:")):
		return nil
	}
	return fmt.Errorf("%w: reload strategy %q: want signal, systemd:<unit>.service, openrc or none", ErrReload, s)
}

// reload makes sshd re-read its configuration by the configured strategy
// (a closed set): signal sends SIGHUP to the pid in the PidFile sshd -T
// names, when that process runs the configured sshd, and runs nothing; systemd:<unit> runs systemctl reload <unit>;
// openrc runs rc-service sshd reload; none does nothing (ReloadNone). It
// reports whether it reloaded.
func (e *engine) reload(ctx context.Context, dump Dump) (bool, error) {
	if err := CheckReload(e.cfg.Reload); err != nil {
		return false, err
	}
	switch e.cfg.Reload {
	case ReloadNone:
		return false, nil
	case "signal":
		return true, reloadSignal(e.cfg.SSHD, dump)
	case "openrc":
		return true, e.reloadOpenRC(ctx)
	default:
		return true, e.reloadSystemd(ctx, strings.TrimPrefix(e.cfg.Reload, "systemd:"))
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
// under the running process, names path marked " (deleted)". The kernel
// names the file by its canonical directory, so path is compared as
// written and with its directory's symlinks resolved (PR #67 fix round 2:
// /usr/sbin a symlink to bin, or /sbin on merged-/usr).
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
	if got := strings.TrimSuffix(target, " (deleted)"); got == filepath.Clean(path) || got == resolvedDir(path) {
		return nil
	}
	return fmt.Errorf("process %d runs %s, not %s", pid, target, path)
}

// resolvedDir is path with the symlinks of its directory resolved, or
// path cleaned when they cannot be.
func resolvedDir(path string) string {
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Join(dir, filepath.Base(path))
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
