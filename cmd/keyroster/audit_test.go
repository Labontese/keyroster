package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestVerifyOutput: the OK line, then "host certificates: N" when the log
// holds host_issue entries, and no such line otherwise (03-09).
func TestVerifyOutput(t *testing.T) {
	for _, n := range []uint64{3, 0} {
		rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindHostIssue: n}, IssuedByCA: map[string]int{}}
		var b bytes.Buffer
		if err := printVerifyOK(&b, verifyResultOf(rep), rep); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(b.String()), "\n")
		if !strings.HasPrefix(lines[0], "OK: ") {
			t.Fatalf("first line %q", lines[0])
		}
		has := strings.Contains(b.String(), "\nhost certificates: ")
		switch {
		case n > 0 && (len(lines) < 2 || lines[1] != "host certificates: 3"):
			t.Fatalf("output %q, want host certificates: 3 after the OK line", b.String())
		case n == 0 && has:
			t.Fatalf("output %q, want no host certificates line", b.String())
		}
	}
}

// TestAuditVerifyProbeLine (03-10c, owner answer P2, 2026-11-07): when the
// log holds probe_issue entries, the line "probe certificates: N, negative
// probes no published KRL lists yet: M" follows the host certificate line,
// and --json carries M as pending_negative_probes, omitted when zero.
func TestAuditVerifyProbeLine(t *testing.T) {
	out := func(t *testing.T, rep *audit.Report) string {
		t.Helper()
		var b bytes.Buffer
		if err := printVerifyOK(&b, verifyResultOf(rep), rep); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	t.Run("no_line_without_probe_entries", func(t *testing.T) {
		rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindHostIssue: 2}, IssuedByCA: map[string]int{}}
		if s := out(t, rep); strings.Contains(s, "probe certificates") {
			t.Fatalf("output %q, want no probe certificates line", s)
		}
	})
	t.Run("line_counts_probe_certificates_and_pending_negatives", func(t *testing.T) {
		rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindHostIssue: 2, tlog.KindProbeIssue: 7}, IssuedByCA: map[string]int{}, PendingNegativeProbes: 3}
		lines := strings.Split(strings.TrimSpace(out(t, rep)), "\n")
		if len(lines) != 3 || lines[1] != "host certificates: 2" || lines[2] != "probe certificates: 7, negative probes no published KRL lists yet: 3" {
			t.Fatalf("output %q, want the probe certificates line after the host certificate line", lines)
		}
		rep.Counts[tlog.KindHostIssue] = 0
		lines = strings.Split(strings.TrimSpace(out(t, rep)), "\n")
		if len(lines) != 2 || lines[1] != "probe certificates: 7, negative probes no published KRL lists yet: 3" {
			t.Fatalf("output %q, want the probe certificates line after the OK line", lines)
		}
	})
	t.Run("json_has_pending_negative_probes", func(t *testing.T) {
		for _, n := range []int{3, 0} {
			rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindProbeIssue: 7}, IssuedByCA: map[string]int{}, PendingNegativeProbes: n}
			b, err := json.Marshal(verifyResultOf(rep))
			if err != nil {
				t.Fatal(err)
			}
			has := strings.Contains(string(b), `"pending_negative_probes":`)
			switch {
			case n > 0 && !strings.Contains(string(b), `"pending_negative_probes":3`):
				t.Fatalf("--json %s, want pending_negative_probes 3", b)
			case n == 0 && has:
				t.Fatalf("--json %s, want pending_negative_probes omitted when zero", b)
			}
		}
	})
	t.Run("existing_output_unchanged", func(t *testing.T) {
		rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindHostIssue: 3}, IssuedByCA: map[string]int{"user": 1}, Size: 9, Serials: 1, BundleVersion: 2, PolicyVersion: 4}
		want := "OK: 9 entries, root , issued 1 (user 1, host 0, machine 0), login certificates 0, directory installs 0, refusals 0, trust bundle v2, policy v4, log key \nhost certificates: 3\n"
		if s := out(t, rep); s != want {
			t.Fatalf("output %q, want %q", s, want)
		}
	})
}

// TestVerifyOutputMachineLine (03-11b, b-C12): when the log holds
// machine_issue entries, "machine certificates: N" follows the host line
// and comes before the probe line.
func TestVerifyOutputMachineLine(t *testing.T) {
	out := func(t *testing.T, rep *audit.Report) string {
		t.Helper()
		var b bytes.Buffer
		if err := printVerifyOK(&b, verifyResultOf(rep), rep); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	t.Run("line_after_host_before_probe", func(t *testing.T) {
		rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindHostIssue: 3, tlog.KindMachineIssue: 2, tlog.KindProbeIssue: 4}, IssuedByCA: map[string]int{}}
		lines := strings.Split(strings.TrimSuffix(out(t, rep), "\n"), "\n")
		if len(lines) != 4 || !strings.HasPrefix(lines[0], "OK: ") || lines[1] != "host certificates: 3" || lines[2] != "machine certificates: 2" ||
			!strings.HasPrefix(lines[3], "probe certificates: 4, ") {
			t.Fatalf("lines %q, want OK, host, machine, probe", lines)
		}
	})
	t.Run("none_without_machine_entries", func(t *testing.T) {
		rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindHostIssue: 3, tlog.KindProbeIssue: 4}, IssuedByCA: map[string]int{}}
		if s := out(t, rep); strings.Contains(s, "machine certificates") {
			t.Fatalf("output %q, want no machine certificates line", s)
		}
	})
}

// lineAfter is the line of out right after the first line that starts
// with prefix ("" when there is none).
func lineAfter(out, prefix string) string {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	return ""
}

// TestAuditVerifyInstallation (03-14c, F05, Q-C7): keyroster audit verify
// names the installation of the log it verified, binds the result to
// --installation-id, refuses another installation's log naming both IDs,
// and refuses an installation-bound log unless --installation-id or
// --any-installation is given; an ID-less log needs neither.
func TestAuditVerifyInstallation(t *testing.T) {
	e := newDirEnv(t, 1, 1)
	id := e.bundle.InstallationID
	if id == "" {
		t.Fatal("the dirEnv bundle names no installation ID")
	}
	b := newLogBuilder(t, e, nil)
	b.issue(trust.RoleUser)
	b.publish()
	export := b.export(-1)
	verify := func(file string, extra ...string) (int, string, string) {
		args := []string{"audit", "verify", "--threshold", "1"}
		for _, p := range e.cfg.TrustPins {
			args = append(args, "--pin", p)
		}
		return run(t, append(append(args, extra...), file)...)
	}
	const other = "ffffffffffffffffffffffffffffffff"

	t.Run("unbound_refused", func(t *testing.T) {
		code, out, errOut := verify(export)
		if code == 0 || !strings.Contains(errOut, "names installation "+id+": pass --installation-id") ||
			!strings.Contains(errOut, "--any-installation") || out != "" {
			t.Fatalf("no flag: exit %d, stdout %q, stderr %q; want a refusal naming %s and both flags, and no stdout", code, out, errOut, id)
		}
	})
	t.Run("unbound_json_refused", func(t *testing.T) {
		code, out, errOut := verify(export, "--json")
		if code == 0 || out != "" || !strings.Contains(errOut, "names installation "+id+": pass --installation-id") {
			t.Fatalf("--json and no flag: exit %d, stdout %q, stderr %q; want the refusal naming %s and no stdout", code, out, errOut, id)
		}
	})
	t.Run("any_installation_prints_unchecked", func(t *testing.T) {
		code, out, errOut := verify(export, "--any-installation")
		want := "installation id: " + id + " (not checked: --any-installation)"
		if code != 0 || lineAfter(out, "anchored: ") != want {
			t.Fatalf("--any-installation: exit %d, want %q right after anchored:\n%s%s", code, want, out, errOut)
		}
	})
	t.Run("checked_ok", func(t *testing.T) {
		code, out, errOut := verify(export, "--installation-id", id)
		want := "installation id: " + id + " (checked against --installation-id)"
		if code != 0 || lineAfter(out, "anchored: ") != want {
			t.Fatalf("--installation-id %s: exit %d, want %q right after anchored:\n%s%s", id, code, want, out, errOut)
		}
	})
	t.Run("other_refused", func(t *testing.T) {
		code, out, errOut := verify(export, "--installation-id", other)
		if code == 0 || !strings.Contains(errOut, id) || !strings.Contains(errOut, other) || strings.Contains(out, "OK:") {
			t.Fatalf("--installation-id %s: exit %d, want a refusal naming %s and %s and no OK:\n%s%s", other, code, id, other, out, errOut)
		}
	})
	t.Run("both_flags_usage", func(t *testing.T) {
		code, out, errOut := verify(export, "--installation-id", id, "--any-installation")
		if code != 2 || !strings.Contains(errOut, "--installation-id and --any-installation exclude each other") {
			t.Fatalf("both flags: exit %d, want 2 and the usage error:\n%s%s", code, out, errOut)
		}
	})
	t.Run("json_carries_id", func(t *testing.T) {
		code, out, errOut := verify(export, "--json", "--installation-id", id)
		var res map[string]any
		if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res["installation_id"] != id {
			t.Fatalf("--json --installation-id: exit %d, want installation_id %s:\n%s%s", code, id, out, errOut)
		}
	})
	t.Run("id_less_needs_no_flag", func(t *testing.T) {
		g, _ := noIDBundles(t, e)
		nb := newLogBuilder(t, e, g)
		nb.issue(trust.RoleUser)
		idLess := nb.export(-1)
		code, out, errOut := verify(idLess)
		want := "installation id: none (the trust bundle in force names none)"
		if code != 0 || lineAfter(out, "anchored: ") != want {
			t.Fatalf("an ID-less log without a flag: exit %d, want %q right after anchored:\n%s%s", code, want, out, errOut)
		}
		code, out, errOut = verify(idLess, "--json")
		if code != 0 || !strings.Contains(out, `"installation_id":""`) {
			t.Fatalf("an ID-less log with --json: exit %d, want \"installation_id\":\"\":\n%s%s", code, out, errOut)
		}
	})
	t.Run("malformed_flag_usage", func(t *testing.T) {
		code, out, errOut := verify(export, "--installation-id", "ABC")
		if code != 2 || strings.Contains(out, "OK:") {
			t.Fatalf("--installation-id ABC: exit %d, want 2 and no OK:\n%s%s", code, out, errOut)
		}
	})
}

// TestAuditVerifyClock (03-14c, F10, Q-C4 B): keyroster audit verify
// prints the last entry's time and index, and in --json its time, and
// refuses a log whose last entry is more than 300 s after its clock,
// naming the time it clears. It sets auditClock, so it is not parallel.
func TestAuditVerifyClock(t *testing.T) {
	e := newDirEnv(t, 1, 1)
	id := e.bundle.InstallationID
	b := newLogBuilder(t, e, nil)
	b.issue(trust.RoleUser)
	b.publish()
	export := b.export(-1)
	verify := func(extra ...string) (int, string, string) {
		args := []string{"audit", "verify", "--threshold", "1", "--installation-id", id}
		for _, p := range e.cfg.TrustPins {
			args = append(args, "--pin", p)
		}
		return run(t, append(append(args, extra...), export)...)
	}
	rfc := func(us uint64) string { return time.UnixMicro(int64(us)).UTC().Format(time.RFC3339Nano) } //nolint:gosec // G115: test times

	t.Run("prints_last_entry_time", func(t *testing.T) {
		code, out, errOut := verify()
		want := "last entry time: " + rfc(b.micros) + " (entry " + strconv.Itoa(len(b.leaves)-1) + ")"
		if code != 0 || lineAfter(out, "installation id: ") != want {
			t.Fatalf("exit %d, want %q right after the installation id line:\n%s%s", code, want, out, errOut)
		}
		code, out, errOut = verify("--json")
		if code != 0 || !strings.Contains(out, `"last_entry_time_micros":`+strconv.FormatUint(b.micros, 10)) {
			t.Fatalf("--json: exit %d, want last_entry_time_micros %d:\n%s%s", code, b.micros, out, errOut)
		}
	})
	t.Run("clock_behind_refused", func(t *testing.T) {
		prev := auditClock
		auditClock = func() time.Time { return time.UnixMicro(int64(b.micros)).Add(-time.Hour) } //nolint:gosec // G115: a test time
		t.Cleanup(func() { auditClock = prev })
		code, out, errOut := verify()
		clears := rfc(b.micros - krl.PruneMargin*1_000_000)
		if code == 0 || !strings.Contains(errOut, "it clears when this clock reaches "+clears) || strings.Contains(out, "OK:") {
			t.Fatalf("a clock an hour behind the log: exit %d, want a refusal naming %s and no OK:\n%s%s", code, clears, out, errOut)
		}
	})
}
