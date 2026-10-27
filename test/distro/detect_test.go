//go:build e2edistro && linux

package distro

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/apply"
	"github.com/Labontese/keyroster/internal/agent/execsite"
)

// showRunner answers Detect's one systemctl show with output built from
// the image's own unit file (no systemd runs in the container).
type showRunner struct{ out string }

func (s showRunner) Run(context.Context, execsite.Cmd) (apply.Result, error) {
	return apply.Result{Stdout: []byte(s.out)}, nil
}

// unitShow builds systemctl show's block for a unit file: Id,
// LoadState=loaded, ActiveState=active, ExecStart as systemctl prints it
// (path and argv, with systemd's prefixes - @ + ! : removed), one
// EnvironmentFiles= line per EnvironmentFile= (a leading - is
// ignore_errors=yes) and the Environment= assignments.
func unitShow(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the image's own unit file
	if err != nil {
		t.Fatal(err)
	}
	id := filepath.Base(path)
	var start string
	var files, env []string
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "ExecStart":
			if start != "" {
				t.Fatalf("%s has more than one ExecStart", path)
			}
			start = strings.TrimLeft(v, "-@+!:")
		case "EnvironmentFile":
			opt := "no"
			if strings.HasPrefix(v, "-") {
				opt, v = "yes", v[1:]
			}
			files = append(files, v+" (ignore_errors="+opt+")")
		case "Environment":
			env = append(env, v)
		}
	}
	argv := strings.Fields(start)
	if len(argv) == 0 {
		t.Fatalf("%s has no ExecStart", path)
	}
	out := fmt.Sprintf("Id=%s\nLoadState=loaded\nActiveState=active\nExecStart={ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n", id, argv[0], start)
	for _, f := range files {
		out += "EnvironmentFiles=" + f + "\n"
	}
	return out + "Environment=" + strings.Join(env, " ") + "\n"
}

// mkTemp creates path (a directory when dir is set, else an empty file),
// removed again when the test ends, unless it already exists.
func mkTemp(t *testing.T, path string, dir bool) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		return
	}
	var err error
	if dir {
		err = os.MkdirAll(path, 0o755) //nolint:gosec // a marker directory Detect looks for
	} else {
		err = os.WriteFile(path, nil, 0o755) //nolint:gosec // a placeholder Detect looks for; never run
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
}

// TestDistroDetectStock is D-R4 (PR #68 review) against each image's own
// service definition: Detect, on the container's real file system (its
// ownership and modes), accepts the stock sshd command line with its
// stock EnvironmentFile and finds /etc/ssh/sshd_config. The systemd
// images get systemctl show output built from their own unit file; the
// container runs no systemd, so systemctl's real output is UNVERIFIED
// here. Alpine is read through its own /etc/conf.d/sshd (OpenRC).
func TestDistroDetectStock(t *testing.T) {
	_ = newHost(t, true, hostEdit{})
	unit := ""
	for _, p := range []string{"/usr/lib/systemd/system/ssh.service", "/lib/systemd/system/ssh.service", "/usr/lib/systemd/system/sshd.service", "/lib/systemd/system/sshd.service"} {
		if _, err := os.Stat(p); err == nil {
			unit = p
			break
		}
	}
	var r apply.Runner
	want := "openrc"
	if unit != "" {
		show := unitShow(t, unit)
		t.Logf("systemctl show built from %s:\n%s", unit, show)
		mkTemp(t, "/run/systemd/system", true)
		mkTemp(t, "/usr/bin/systemctl", false)
		r, want = showRunner{out: show}, "systemd"
	} else if _, err := os.Stat("/etc/init.d/sshd"); err != nil {
		t.Fatalf("no sshd unit file and no /etc/init.d/sshd in %s", distro)
	}
	svc, err := apply.Detect(t.Context(), r, "/")
	if err != nil || svc.Manager != want || svc.Config != sshdConfig {
		t.Fatalf("Detect on the stock %s service: %+v, %v", distro, svc, err)
	}
	t.Logf("FACT image=%s | detect_stock=%s %s %s %s", distro, svc.Manager, svc.SSHD, svc.Config, svc.Reload)
}

// TestDistroDetectRefusesSSHDArgs: keyroster-agent preflight without
// --sshd and --sshd-config, on a host whose OpenRC settings start sshd
// with -o RevokedKeys=none, refuses with sshd_command_unknown (exit 3)
// and writes nothing (D-R4). OpenRC's /etc/conf.d/sshd is the path a
// container can take: it runs no systemd. Where the image has no OpenRC
// script, the test writes a placeholder one and removes it again.
func TestDistroDetectRefusesSSHDArgs(t *testing.T) {
	h := newHost(t, true, hostEdit{})
	h.w.publish(account, h.hostKey, "role:ops")
	h.enroll()
	mkTemp(t, "/etc/init.d", true)
	mkTemp(t, "/etc/init.d/sshd", false)
	mkTemp(t, "/etc/conf.d", true)
	const conf = "/etc/conf.d/sshd"
	old, err := os.ReadFile(conf)
	switch {
	case err == nil:
		t.Cleanup(func() { _ = os.WriteFile(conf, old, 0o644) }) //nolint:gosec // the image's own mode
	case errors.Is(err, os.ErrNotExist):
		t.Cleanup(func() { _ = os.Remove(conf) })
	default:
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, append(append([]byte{}, old...), "\ncommand_args=\"-o RevokedKeys=none\"\n"...), 0o644); err != nil { //nolint:gosec // OpenRC's mode
		t.Fatal(err)
	}
	code, out, _ := agent(t, "preflight", "--root", "/", "--ssh-keygen", keygen, "--state-dir", stateDir, "--spool", spoolDir)
	r := decode[apply.PreflightReport](t, out)
	if f := findingOf(r, apply.CodeSSHDCommand); code != 3 || f == nil || !f.Refusal || !strings.Contains(f.Message, "-o") {
		t.Fatalf("preflight with command_args=-o RevokedKeys=none: exit %d, %+v", code, r.Findings)
	}
	nothingWritten(t, "after the refusal")
}
