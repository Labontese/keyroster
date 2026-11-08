package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/tlog"
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
