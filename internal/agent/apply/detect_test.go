//go:build linux

package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/execsite"
)

// showRunner answers systemctl show with a fixed output and records the
// command it got.
type showRunner struct {
	out  string
	code int
	got  []string
}

func (s *showRunner) Run(_ context.Context, c execsite.Cmd) (Result, error) {
	s.got = c.Args()
	return Result{Stdout: []byte(s.out), Code: s.code}, nil
}

// systemd show blocks in the format systemctl show -p prints them. They
// are constructed from systemd's documented output, not captured from the
// distributions' hosts: a real systemd is UNVERIFIED until 03-16.
func unitBlock(id, load, active, execStart string) string {
	b := "Id=" + id + "\nLoadState=" + load + "\nActiveState=" + active + "\n"
	if execStart != "" {
		b += "ExecStart=" + execStart + "\n"
	}
	return b
}

func execStart(path, argv string) string {
	return "{ path=" + path + " ; argv[]=" + argv + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
}

func systemdRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"run/systemd/system", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/systemctl"), []byte("#!/bin/false\n"), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return root
}

func TestDetect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		show   string
		want   Service
		errIs  error
		openrc string // /etc/conf.d/sshd; "-" means an OpenRC host without it
	}{
		{name: "debian_ssh_service", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "inactive", ""),
			unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
			unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")), // sshd.service is an alias
		}, "\n"), want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "ubuntu_socket_activated_reload_none", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "active", ""),
			unitBlock("ssh.service", "loaded", "inactive", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
			unitBlock("ssh.service", "loaded", "inactive", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
		}, "\n"), want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: ReloadNone, Socket: true}},
		{name: "ubuntu_socket_started_service_reloads", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "active", ""),
			unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
		}, "\n"), want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "rhel_sshd_service", show: strings.Join([]string{
			unitBlock("ssh.socket", "not-found", "inactive", ""),
			unitBlock("ssh.service", "not-found", "inactive", ""),
			unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $OPTIONS")),
		}, "\n"), want: Service{Manager: "systemd", Unit: "sshd.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:sshd.service"}},
		{name: "arch_sshd_service_notify_reload", show: strings.Join([]string{
			unitBlock("ssh.socket", "not-found", "inactive", ""),
			unitBlock("ssh.service", "not-found", "inactive", ""),
			unitBlock("sshd.service", "loaded", "active", execStart("/usr/bin/sshd", "/usr/bin/sshd -D")),
		}, "\n"), want: Service{Manager: "systemd", Unit: "sshd.service", SSHD: "/usr/bin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:sshd.service"}},
		{name: "config_from_dash_f", show: unitBlock("sshd.service", "loaded", "active", execStart("/opt/ssh/sbin/sshd", "/opt/ssh/sbin/sshd -D -f /opt/ssh/etc/sshd_config")),
			want: Service{Manager: "systemd", Unit: "sshd.service", SSHD: "/opt/ssh/sbin/sshd", Config: "/opt/ssh/etc/sshd_config", Reload: "systemd:sshd.service"}},
		{name: "no_ssh_unit_refused", show: unitBlock("ssh.socket", "not-found", "inactive", "") + "\n" + unitBlock("ssh.service", "not-found", "inactive", "") + "\n" + unitBlock("sshd.service", "not-found", "inactive", ""), errIs: ErrNotDetected},
		{name: "relative_exec_start_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("sshd", "sshd -D")), errIs: ErrNotDetected},
		{name: "alpine_openrc_sshd_pam", openrc: "# sshd settings\nSSHD_BINARY=\"/usr/sbin/sshd.pam\"\n#SSHD_CONFIG=/etc/ssh/other\n",
			want: Service{Manager: "openrc", SSHD: "/usr/sbin/sshd.pam", Config: "/etc/ssh/sshd_config", Reload: "openrc"}},
		{name: "openrc_defaults", openrc: "-", want: Service{Manager: "openrc", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "openrc"}},
		{name: "openrc_variable_refused", openrc: "SSHD_CONFIG=\"${SSHD_CONFDIR}/sshd_config\"\n", errIs: ErrNotDetected},
		{name: "neither_refused", errIs: ErrNotDetected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var root string
			switch {
			case tc.show != "":
				root = systemdRoot(t)
			default:
				root = t.TempDir()
				if tc.openrc != "" {
					for _, f := range []string{"etc/init.d/sshd", "etc/conf.d/sshd"} {
						if f == "etc/conf.d/sshd" && tc.openrc == "-" {
							continue
						}
						if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil { //nolint:gosec // test fixture
							t.Fatal(err)
						}
						content := "#!/sbin/openrc-run\n"
						if f == "etc/conf.d/sshd" {
							content = tc.openrc
						}
						if err := os.WriteFile(filepath.Join(root, f), []byte(content), 0o644); err != nil { //nolint:gosec // test fixture
							t.Fatal(err)
						}
					}
				}
			}
			r := &showRunner{out: tc.show}
			got, err := Detect(context.Background(), r, root)
			if tc.errIs != nil {
				if !errors.Is(err, tc.errIs) {
					t.Fatalf("Detect = %+v, %v; want %v", got, err, tc.errIs)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Detect = %+v, %v; want %+v", got, err, tc.want)
			}
			if tc.show != "" && strings.Join(r.got, " ") != "/usr/bin/systemctl show -p Id -p LoadState -p ActiveState -p ExecStart ssh.socket ssh.service sshd.service" {
				t.Fatalf("ran %q", r.got)
			}
		})
	}
}
