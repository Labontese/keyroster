//go:build linux

package apply

import (
	"strings"
	"testing"
)

// unitLines are the unit's lines.
func unitLines(s string) []string { return strings.Split(s, "\n") }

// unitHasLine reports whether text has exactly the line l.
func unitHasLine(text, l string) bool {
	for _, x := range strings.Split(text, "\n") {
		if x == l {
			return true
		}
	}
	return false
}

// TestUnits (03-08, D-05, Codex 03-08 LOW): the rendered units carry the
// sandbox the plan pins, and exactly the writable paths it lists.
func TestUnits(t *testing.T) {
	c := UnitConfig{BinDir: DefaultBinDir, StateDir: "/var/lib/keyroster-agent"}
	t.Run("applier_unit", func(t *testing.T) {
		u, err := ApplierSystemdUnit(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range []string{"IPAddressDeny=any", "IPAddressAllow=localhost", "NoNewPrivileges=yes", "ProtectSystem=strict",
			"ReadWritePaths=/etc/ssh/keyroster /etc/ssh/sshd_config.d /var/lib/keyroster-agent", "CapabilityBoundingSet=",
			"ExecStart=/usr/local/bin/keyroster-agent run --state-dir /var/lib/keyroster-agent"} {
			if !unitHasLine(u, l) {
				t.Errorf("keyroster-agent.service lacks the line %q:\n%s", l, u)
			}
		}
		requireOneReadWritePaths(t, u)
		if strings.Contains(u, "User=") {
			t.Error("the applier unit names a User: it runs as root")
		}
	})
	t.Run("fetcher_unit", func(t *testing.T) {
		u, err := FetcherSystemdUnit(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range []string{"User=keyroster-agent", "CapabilityBoundingSet=", "NoNewPrivileges=yes", "ProtectSystem=strict",
			"ReadWritePaths=/var/lib/keyroster-agent-fetch /var/lib/keyroster-agent/spool",
			"ExecStart=/usr/local/bin/keyroster-agent-fetch --config /etc/keyroster-agent/fetch.json --dir /var/lib/keyroster-agent-fetch --spool /var/lib/keyroster-agent/spool --outbox /var/lib/keyroster-agent/outbox"} {
			if !unitHasLine(u, l) {
				t.Errorf("keyroster-agent-fetch.service lacks the line %q:\n%s", l, u)
			}
		}
		requireOneReadWritePaths(t, u)
		if strings.Contains(u, "AF_UNIX") || strings.Contains(u, "IPAddressAllow=") {
			t.Error("the fetcher unit allows Unix sockets or an IP allowlist it does not need")
		}
	})
	t.Run("openrc_scripts", func(t *testing.T) {
		a, err := ApplierOpenRCScript(c)
		if err != nil {
			t.Fatal(err)
		}
		f, err := FetcherOpenRCScript(c)
		if err != nil {
			t.Fatal(err)
		}
		if !unitHasLine(f, `command_user="keyroster-agent"`) {
			t.Errorf("the fetcher's OpenRC script does not run as keyroster-agent:\n%s", f)
		}
		if strings.Contains(a, "command_user") {
			t.Errorf("the applier's OpenRC script names a user: it runs as root:\n%s", a)
		}
		for _, s := range []string{a, f} {
			if !strings.HasPrefix(s, "#!/sbin/openrc-run\n") {
				t.Errorf("not an openrc-run script:\n%s", s)
			}
		}
	})
	t.Run("state_dir_follows_config", func(t *testing.T) {
		u, err := FetcherSystemdUnit(UnitConfig{BinDir: "/usr/bin", StateDir: "/srv/agent"})
		if err != nil {
			t.Fatal(err)
		}
		if !unitHasLine(u, "ReadWritePaths=/var/lib/keyroster-agent-fetch /srv/agent/spool") || !strings.Contains(u, "ExecStart=/usr/bin/keyroster-agent-fetch ") {
			t.Fatalf("the unit does not follow its config:\n%s", u)
		}
	})
	t.Run("unsafe_paths_refused", func(t *testing.T) {
		for _, p := range []string{"relative", "/var/lib/a b", "/var/lib/a\nExecStartPre=/bin/sh", "/var/lib/$x", `/var/lib/a"`, "/var/lib/a/../b"} {
			for _, r := range []func(UnitConfig) (string, error){ApplierSystemdUnit, FetcherSystemdUnit, ApplierOpenRCScript, FetcherOpenRCScript} {
				if _, err := r(UnitConfig{BinDir: DefaultBinDir, StateDir: p}); err == nil {
					t.Errorf("state directory %q accepted", p)
				}
				if _, err := r(UnitConfig{BinDir: p, StateDir: "/var/lib/keyroster-agent"}); err == nil {
					t.Errorf("bin directory %q accepted", p)
				}
			}
		}
	})
}

// requireOneReadWritePaths fails unless u has exactly one ReadWritePaths
// line (a second line would add paths).
func requireOneReadWritePaths(t *testing.T, u string) {
	t.Helper()
	n := 0
	for _, l := range unitLines(u) {
		if strings.HasPrefix(strings.TrimSpace(l), "ReadWritePaths") || strings.HasPrefix(strings.TrimSpace(l), "StateDirectory") ||
			strings.HasPrefix(strings.TrimSpace(l), "RuntimeDirectory") || strings.HasPrefix(strings.TrimSpace(l), "LogsDirectory") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d writable-path lines, want exactly one ReadWritePaths:\n%s", n, u)
	}
}
