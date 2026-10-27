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

// withProps adds more KEY=VALUE lines to a unit block (EnvironmentFiles,
// Environment), in systemctl show's format: one EnvironmentFiles= line per
// file, "path (ignore_errors=yes|no)".
func withProps(block string, props ...string) string {
	for _, p := range props {
		block += p + "\n"
	}
	return block
}

// The stock environment files of the CI images, as captured from them
// (03-06 review fix round; blank lines dropped by the capture).
const (
	debianDefaultSSH  = "# Default settings for openssh-server. This file is sourced by /bin/sh from\n# /etc/init.d/ssh.\n\n# Options to pass to sshd\nSSHD_OPTS=\n"
	almaSysconfigSSHD = "# Configuration file for the sshd service.\n# The server keys are automatically generated if they are missing.\n# To change the automatic creation, adjust sshd.service options for\n# example using  systemctl enable sshd-keygen@dsa.service  to allow creation\n# of DSA key or  systemctl mask sshd-keygen@rsa.service  to disable RSA key\n# creation.\n#SSH_RSA_BITS=3072\n#SSH_ECDSA_BITS=256\n"
	alpineConfDSSHD   = "# Configuration for /etc/init.d/sshd\n\n# Path of sshd_config file.\n#cfgfile=\"/etc/ssh/sshd_config\"\n\n# Any random options you want to pass to sshd.\n# See the sshd(8) manpage for more info.\n#command_args=\"\"\n\n#key_types_to_generate=\"\"\n#ecdsa_bit_size=\"256\"\n#rsa_bit_size=\"3072\"\n"
)

// debianUnit is Debian's and Ubuntu's ssh.service as systemctl show prints
// it, active, with its EnvironmentFile=-/etc/default/ssh and argv.
func debianUnit(argv, envFile string, env string) string {
	return withProps(unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", argv)), "EnvironmentFiles="+envFile, "Environment="+env)
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
		// files are written below the root, mode 0644; setup runs after.
		files map[string]string
		setup func(t *testing.T, root string)
	}{
		{name: "debian_ssh_service", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "inactive", ""),
			unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
			unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")), // sshd.service is an alias
		}, "\n"), want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		// PR #68 review D-R1: an active ssh.socket gives
		// systemd-socket:<unit> (try-reload-or-restart at every reload)
		// whatever the service's own state; nothing maps to "none".
		{name: "ubuntu_socket_activated_service_inactive", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "active", ""),
			unitBlock("ssh.service", "loaded", "inactive", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
			unitBlock("ssh.service", "loaded", "inactive", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
		}, "\n"), want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd-socket:ssh.service", Socket: true}},
		{name: "ubuntu_socket_started_service_active", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "active", ""),
			unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
		}, "\n"), want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd-socket:ssh.service", Socket: true}},
		{name: "socket_service_activating_refused", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "active", ""),
			unitBlock("ssh.service", "loaded", "activating", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
		}, "\n"), errIs: ErrNotDetected},
		{name: "service_reloading_refused", show: unitBlock("sshd.service", "loaded", "reloading", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D")), errIs: ErrNotDetected},
		{name: "service_deactivating_refused", show: unitBlock("sshd.service", "loaded", "deactivating", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D")), errIs: ErrNotDetected},
		{name: "socket_activating_refused", show: strings.Join([]string{
			unitBlock("ssh.socket", "loaded", "activating", ""),
			unitBlock("ssh.service", "loaded", "inactive", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
		}, "\n"), errIs: ErrNotDetected},
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
		// PR #68 review D-R4 (F6, F11): the stock units and files of the CI
		// images pass; any other sshd argument is refused.
		{name: "debian_stock_unit_and_default_file", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": debianDefaultSSH},
			want:  Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "el9_stock_unit_and_sysconfig", show: withProps(unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $OPTIONS")), "EnvironmentFiles=/etc/sysconfig/sshd (ignore_errors=yes)", "Environment="),
			files: map[string]string{"etc/sysconfig/sshd": almaSysconfigSSHD},
			want:  Service{Manager: "systemd", Unit: "sshd.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:sshd.service"}},
		{name: "optional_env_file_missing", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "required_env_file_missing_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=no)", ""), errIs: ErrSSHDCommand},
		{name: "sshd_opts_dash_f_sets_config", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=\"-f /etc/ssh/sshd_config.prod\"\n"},
			want:  Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config.prod", Reload: "systemd:ssh.service"}},
		{name: "sshd_opts_dash_o_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=-o RevokedKeys=none\n"}, errIs: ErrSSHDCommand},
		{name: "el9_options_dash_o_refused", show: withProps(unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $OPTIONS")), "EnvironmentFiles=/etc/sysconfig/sshd (ignore_errors=yes)"),
			files: map[string]string{"etc/sysconfig/sshd": almaSysconfigSSHD + "OPTIONS=\"-oLoginGraceTime=0\"\n"}, errIs: ErrSSHDCommand},
		{name: "exec_start_dash_o_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D -o RevokedKeys=none")), errIs: ErrSSHDCommand},
		{name: "exec_start_unknown_flag_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D -p 2222")), errIs: ErrSSHDCommand},
		{name: "exec_start_combined_flags_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -De")), errIs: ErrSSHDCommand},
		{name: "exec_start_dash_f_twice_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D -f /etc/ssh/a -f/etc/ssh/b")), errIs: ErrSSHDCommand},
		{name: "exec_start_embedded_variable_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D -f$CONF")), errIs: ErrSSHDCommand},
		{name: "environment_property_resolved", show: withProps(unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")), "Environment=SSHD_OPTS=-e LANG=C"),
			want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "env_file_overrides_environment", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", "SSHD_OPTS=-e"),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS='-o PermitRootLogin=yes'\n"}, errIs: ErrSSHDCommand},
		{name: "later_env_file_overrides_earlier", show: withProps(unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
			"EnvironmentFiles=/etc/default/ssh (ignore_errors=yes)", "EnvironmentFiles=/etc/default/ssh-local (ignore_errors=yes)", "Environment="),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=\n", "etc/default/ssh-local": "SSHD_OPTS=-oX=y\n"}, errIs: ErrSSHDCommand},
		{name: "braced_variable_one_word", show: unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D ${SSHD_OPTS}")) + "Environment=SSHD_OPTS=-e\n",
			want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "braced_variable_with_whitespace_refused", show: debianUnit("/usr/sbin/sshd -D ${SSHD_OPTS}", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=\"-f /etc/ssh/x\"\n"}, errIs: ErrSSHDCommand},
		{name: "env_file_writable_by_others_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": debianDefaultSSH},
			setup: func(t *testing.T, root string) { chmod(t, filepath.Join(root, "etc/default/ssh"), 0o666) }, errIs: ErrUnsafeFile},
		{name: "env_file_behind_symlink_into_open_dir_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"open/ssh": debianDefaultSSH},
			setup: func(t *testing.T, root string) {
				chmod(t, filepath.Join(root, "open"), 0o777)                                   //nolint:gosec // the directory under test is world-writable
				if err := os.MkdirAll(filepath.Join(root, "etc/default"), 0o755); err != nil { //nolint:gosec // test fixture
					t.Fatal(err)
				}
				if err := os.Symlink("../../open/ssh", filepath.Join(root, "etc/default/ssh")); err != nil {
					t.Fatal(err)
				}
			}, errIs: ErrUnsafeFile},
		{name: "env_file_root_symlink_followed", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"usr/share/ssh/default": "SSHD_OPTS=-e\n"},
			setup: func(t *testing.T, root string) {
				if err := os.MkdirAll(filepath.Join(root, "etc/default"), 0o755); err != nil { //nolint:gosec // test fixture
					t.Fatal(err)
				}
				if err := os.Symlink("../../usr/share/ssh/default", filepath.Join(root, "etc/default/ssh")); err != nil {
					t.Fatal(err)
				}
			},
			want: Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "env_file_unexpanded_value_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=\"$EXTRA\"\n"}, errIs: ErrSSHDCommand},
		{name: "env_file_unrelated_unexpanded_value_ignored", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "OTHER=\"$HOME/x\"\nSSHD_OPTS=\n"},
			want:  Service{Manager: "systemd", Unit: "ssh.service", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "systemd:ssh.service"}},
		{name: "env_file_continuation_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=-e \\\n-o RevokedKeys=none\n"}, errIs: ErrSSHDCommand},
		{name: "two_exec_start_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D")) + "ExecStart=" + execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D -o X=y") + "\n", errIs: ErrSSHDCommand},
		{name: "alpine_stock_conf_d", openrc: alpineConfDSSHD, want: Service{Manager: "openrc", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "openrc"}},
		{name: "openrc_cfgfile_sets_config", openrc: "cfgfile=\"/etc/ssh/sshd_config.alt\"\nSSHD_CONFIG=/etc/ssh/ignored\n", want: Service{Manager: "openrc", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config.alt", Reload: "openrc"}},
		{name: "openrc_confdir_sets_config", openrc: "SSHD_CONFDIR=/opt/ssh\n", want: Service{Manager: "openrc", SSHD: "/usr/sbin/sshd", Config: "/opt/ssh/sshd_config", Reload: "openrc"}},
		{name: "openrc_command_args_dash_o_refused", openrc: "command_args=\"-o RevokedKeys=none\"\n", errIs: ErrSSHDCommand},
		{name: "openrc_sshd_opts_dash_f_refused", openrc: "SSHD_OPTS=\"-f /etc/ssh/other\"\n", errIs: ErrSSHDCommand},
		// PR #68 review fix round 2, P7: sh sources /etc/conf.d/sshd, so any
		// line but a comment, a blank line or one plain assignment refuses
		// the whole file.
		{name: "openrc_export_refused", openrc: "export SSHD_OPTS=\"-o RevokedKeys=none\"\n", errIs: ErrSSHDCommand},
		{name: "openrc_compound_line_refused", openrc: "true; command_args=-oRevokedKeys=none\n", errIs: ErrSSHDCommand},
		{name: "openrc_default_assignment_in_other_variable_refused", openrc: "FOO=\"${command_args:=-oRevokedKeys=none}\"\n", errIs: ErrSSHDCommand},
		{name: "openrc_unquoted_space_refused", openrc: "rc_need=net command_args=-oRevokedKeys=none\n", errIs: ErrSSHDCommand},
		{name: "openrc_open_quote_refused", openrc: "rc_need=\"net\nSSHD_OPTS=\"-o RevokedKeys=none\"\n", errIs: ErrSSHDCommand},
		{name: "openrc_plain_assignments_pass", openrc: alpineConfDSSHD + "rc_need=\"net\"\nSSHD_DISABLE_KEYGEN='yes'\nkey_types_to_generate=ed25519\n",
			want: Service{Manager: "openrc", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "openrc"}},
		// P5: a file past the agent's read limit is refused, not truncated.
		{name: "openrc_conf_d_over_limit_refused", openrc: alpineConfDSSHD + strings.Repeat("#\n", 33<<10) + "command_args=-oRevokedKeys=none\n", errIs: ErrUnsafeFile},
		{name: "env_file_over_limit_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=\n" + strings.Repeat("#\n", 33<<10) + "SSHD_OPTS=-oRevokedKeys=none\n"}, errIs: ErrUnsafeFile},
		// P6: a line whose extent the agent cannot be sure of (systemd's
		// quoted values span lines; a comment ending in a backslash
		// continues) refuses the whole file.
		{name: "env_file_multiline_single_quote_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=-oRevokedKeys=none\nDUMMY='\nSSHD_OPTS=\nEND='\n"}, errIs: ErrSSHDCommand},
		{name: "env_file_multiline_after_closed_quote_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=-oRevokedKeys=none\nDUMMY=\"a\"'b\nSSHD_OPTS=\nEND='\n"}, errIs: ErrSSHDCommand},
		{name: "env_file_comment_continuation_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=-oRevokedKeys=none\n# reset below \\\nSSHD_OPTS=\n"}, errIs: ErrSSHDCommand},
		{name: "env_file_escaped_quote_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=-oRevokedKeys=none\nDUMMY=\"a\\\"\nSSHD_OPTS=\nEND=\"x\"\n"}, errIs: ErrSSHDCommand},
		{name: "env_file_two_quoted_strings_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "DUMMY=\"a\"'b'\nSSHD_OPTS=\n"}, errIs: ErrSSHDCommand},
		{name: "env_file_export_refused", show: debianUnit("/usr/sbin/sshd -D $SSHD_OPTS", "/etc/default/ssh (ignore_errors=yes)", ""),
			files: map[string]string{"etc/default/ssh": "export SSHD_OPTS=\n"}, errIs: ErrSSHDCommand},
		// P10: each EnvironmentFiles line is read (parseShow keeps every
		// value of a repeated key), and so is Environment=.
		{name: "first_of_two_env_files_sets_option_refused", show: withProps(unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")),
			"EnvironmentFiles=/etc/default/ssh (ignore_errors=yes)", "EnvironmentFiles=/etc/default/ssh-local (ignore_errors=yes)", "Environment="),
			files: map[string]string{"etc/default/ssh": "SSHD_OPTS=-oX=y\n", "etc/default/ssh-local": "OTHER=1\n"}, errIs: ErrSSHDCommand},
		{name: "two_exec_start_bad_first_refused", show: unitBlock("sshd.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D -o X=y")) + "ExecStart=" + execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D") + "\n", errIs: ErrSSHDCommand},
		{name: "environment_property_dash_o_refused", show: withProps(unitBlock("ssh.service", "loaded", "active", execStart("/usr/sbin/sshd", "/usr/sbin/sshd -D $SSHD_OPTS")), "Environment=SSHD_OPTS=-oRevokedKeys=none"), errIs: ErrSSHDCommand},
		{name: "openrc_sshd_opts_dash_e", openrc: "SSHD_OPTS=\"-e\"\n", want: Service{Manager: "openrc", SSHD: "/usr/sbin/sshd", Config: "/etc/ssh/sshd_config", Reload: "openrc"}},
		{name: "openrc_conf_d_writable_by_others_refused", openrc: alpineConfDSSHD,
			setup: func(t *testing.T, root string) { chmod(t, filepath.Join(root, "etc/conf.d/sshd"), 0o666) }, errIs: ErrSSHDCommand},
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
			for f, content := range tc.files {
				p := filepath.Join(root, f)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // test fixture
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(content), 0o644); err != nil { //nolint:gosec // test fixture
					t.Fatal(err)
				}
			}
			if tc.setup != nil {
				tc.setup(t, root)
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
			if tc.show != "" && strings.Join(r.got, " ") != "/usr/bin/systemctl show -p Id -p LoadState -p ActiveState -p ExecStart -p EnvironmentFiles -p Environment ssh.socket ssh.service sshd.service" {
				t.Fatalf("ran %q", r.got)
			}
		})
	}
}

// chmod sets mode exactly, whatever the umask.
func chmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}
