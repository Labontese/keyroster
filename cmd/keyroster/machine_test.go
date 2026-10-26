package main

import (
	"strings"
	"testing"
)

// TestMachineCommands covers keyroster machine add, remove and list
// against the fake server, whose policy caps user certificates at 12 h and
// machine certificates at 24 h.
func TestMachineCommands(t *testing.T) {
	t.Run("machine_add_default_ttl_is_machine_cap", func(t *testing.T) {
		e := roleEnv(t, nil)
		keyFile, key := writeEntryKey(t, "ci")
		code, stdout, stderr := run(t, "machine", "add", "ci", "--key", keyFile, "--role", "ops", "--yes")
		if code != 0 || !strings.Contains(stdout, "+ machine ci status=active key=ssh-ed25519 SHA256:") || !strings.Contains(stdout, "roles=[ops] max_ttl_seconds=86400") {
			t.Fatalf("machine add: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		d := installedDir(t, e)
		m, ok := d.MachineByName("ci")
		if !ok || m.Key != key || m.MaxTTLSeconds != 86400 || d.InstallationID != e.bundle.InstallationID {
			t.Fatalf("installed machine %+v, %v, installation %q", m, ok, d.InstallationID)
		}
	})
	t.Run("machine_add_refusals", func(t *testing.T) {
		e := roleEnv(t, nil)
		keyFile, _ := writeEntryKey(t, "ci")
		for _, tc := range []struct {
			name string
			args []string
			want string
		}{
			{"above_machine_cap", []string{"--key", keyFile, "--role", "ops", "--max-ttl", "25h"}, "above the machine CA cap 24h0m0s"},
			{"below_minimum", []string{"--key", keyFile, "--role", "ops", "--max-ttl", "30s"}, "at least 60s"},
			{"unknown_role", []string{"--key", keyFile, "--role", "deploy"}, `there is no role "deploy"`},
			{"missing_key", []string{"--role", "ops"}, "--key and at least one --role are required"},
			{"missing_role", []string{"--key", keyFile}, "--key and at least one --role are required"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				check := unchanged(t, e)
				code, _, stderr := run(t, append([]string{"machine", "add", "ci", "--yes"}, tc.args...)...)
				if code == 0 || !strings.Contains(stderr, tc.want) {
					t.Fatalf("machine add %v: exit %d, stderr %q; want %q", tc.args, code, stderr, tc.want)
				}
				check()
			})
		}
	})
	t.Run("machine_key_equals_host_key_refused", func(t *testing.T) {
		e := roleEnv(t, nil)
		keyFile, _ := writeEntryKey(t, "web1")
		if code, _, stderr := run(t, "host", "add", "web1", "--group", "web", "--key", keyFile, "--principal", "web1", "--yes"); code != 0 {
			t.Fatal(stderr)
		}
		check := unchanged(t, e)
		code, _, stderr := run(t, "machine", "add", "ci", "--key", keyFile, "--role", "ops", "--yes")
		if code == 0 || !strings.Contains(stderr, "is the host key of host web1") {
			t.Fatalf("machine add with web1's host key: exit %d, stderr %q", code, stderr)
		}
		check()
	})
	t.Run("machine_only_role_takes_machine_cap", func(t *testing.T) {
		// deploy is granted to no user or group: once machine ci names it,
		// it is checked against the 24 h machine cap, not the 12 h user cap.
		e := roleEnv(t, nil)
		if code, _, stderr := run(t, "role", "add", "deploy", "--max-ttl", "1h", "--yes"); code != 0 {
			t.Fatal(stderr)
		}
		if code, _, stderr := run(t, "role", "update", "deploy", "--max-ttl", "20h", "--yes"); code == 0 || !strings.Contains(stderr, "above the user CA cap") {
			t.Fatalf("role update deploy to 20 h before a machine names it: exit %d, stderr %q", code, stderr)
		}
		keyFile, _ := writeEntryKey(t, "ci")
		if code, _, stderr := run(t, "machine", "add", "ci", "--key", keyFile, "--role", "deploy", "--yes"); code != 0 {
			t.Fatal(stderr)
		}
		if code, _, stderr := run(t, "role", "update", "deploy", "--max-ttl", "20h", "--yes"); code != 0 {
			t.Fatalf("role update deploy to 20 h, machine-only: exit %d, stderr %q", code, stderr)
		}
		if r := roleOf(t, installedDir(t, e), "deploy"); r.MaxTTLSeconds != 20*3600 {
			t.Fatalf("deploy max TTL %d", r.MaxTTLSeconds)
		}
		// Granting it to a user now makes it user-facing: refused.
		if code, _, stderr := run(t, "role", "grant", "deploy", "--user", "alice", "--yes"); code == 0 || !strings.Contains(stderr, "above the user CA cap") {
			t.Fatalf("role grant deploy to alice at 20 h: exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("machine_remove_machine_only_role_above_user_cap", func(t *testing.T) {
		// deploy is machine-only at 20 h. Removing the last machine that
		// names it would put it under the 12 h user cap: refused, with the
		// role named and the two ways out, both run here (pre-merge
		// review, 03-04).
		e := roleEnv(t, nil)
		ciKey, _ := writeEntryKey(t, "ci")
		for _, args := range [][]string{
			{"role", "add", "deploy", "--max-ttl", "1h", "--yes"},
			{"machine", "add", "ci", "--key", ciKey, "--role", "deploy", "--yes"},
			{"role", "update", "deploy", "--max-ttl", "20h", "--yes"},
		} {
			if code, _, stderr := run(t, args...); code != 0 {
				t.Fatalf("%v: %s", args, stderr)
			}
		}
		// Key rotation: the new machine first, then the old one goes.
		ci2Key, _ := writeEntryKey(t, "ci2")
		if code, _, stderr := run(t, "machine", "add", "ci2", "--key", ci2Key, "--role", "deploy", "--yes"); code != 0 {
			t.Fatalf("machine add ci2: %s", stderr)
		}
		if code, _, stderr := run(t, "machine", "remove", "ci", "--yes"); code != 0 {
			t.Fatalf("machine remove ci after ci2 names deploy: exit %d, stderr %q", code, stderr)
		}
		// The last machine: refused, actionably.
		check := unchanged(t, e)
		code, _, stderr := run(t, "machine", "remove", "ci2", "--yes")
		for _, want := range []string{
			"role deploy: max_ttl_seconds 72000 is above the user CA cap 43200",
			"Removing machine ci2 leaves role deploy granted to no user, group or machine",
			"keyroster machine add NEW --key FILE --role deploy), then remove ci2",
			"keyroster role update deploy --max-ttl D), then remove ci2",
		} {
			if code == 0 || !strings.Contains(stderr, want) {
				t.Fatalf("machine remove ci2: exit %d, stderr %q; want %q", code, stderr, want)
			}
		}
		check()
		// Within the user cap first, then the removal goes through.
		if code, _, stderr := run(t, "role", "update", "deploy", "--max-ttl", "12h", "--yes"); code != 0 {
			t.Fatalf("role update deploy to 12 h: %s", stderr)
		}
		if code, _, stderr := run(t, "machine", "remove", "ci2", "--yes"); code != 0 {
			t.Fatalf("machine remove ci2 with deploy within the user cap: exit %d, stderr %q", code, stderr)
		}
		if d := installedDir(t, e); len(d.Machines) != 0 || roleOf(t, d, "deploy").MaxTTLSeconds != 12*3600 {
			t.Fatalf("installed machines %+v, deploy %+v", d.Machines, roleOf(t, d, "deploy"))
		}
	})
	t.Run("machine_list_and_remove", func(t *testing.T) {
		e := roleEnv(t, nil)
		keyFile, _ := writeEntryKey(t, "ci")
		if code, _, stderr := run(t, "machine", "add", "ci", "--key", keyFile, "--role", "ops", "--max-ttl", "2h", "--yes"); code != 0 {
			t.Fatal(stderr)
		}
		code, stdout, stderr := run(t, "machine", "list")
		if code != 0 || !strings.Contains(stdout, "ci status=active key=ssh-ed25519 SHA256:") || !strings.Contains(stdout, "max_ttl_seconds=7200") {
			t.Fatalf("machine list: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr := run(t, "machine", "remove", "ci", "--yes"); code != 0 || !strings.Contains(stdout, "- machine ci ") {
			t.Fatalf("machine remove: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if _, ok := installedDir(t, e).MachineByName("ci"); ok {
			t.Fatal("ci is still installed")
		}
		if code, stdout, _ := run(t, "machine", "list"); code != 0 || !strings.Contains(stdout, "names no machine") {
			t.Fatalf("machine list after remove: exit %d, stdout %q", code, stdout)
		}
	})
}
