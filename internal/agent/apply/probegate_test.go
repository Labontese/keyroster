//go:build linux

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	probecert "github.com/Labontese/keyroster/internal/agent/probe"
	certpkg "github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// lockedEngine is h's bare engine past the apply lock, as the gate's
// writer needs it.
func lockedEngine(h *testHost) *engine {
	e := h.engine()
	e.locked = true
	return e
}

// isReset reports whether st is the exhausted hour a refused
// probe-state.json reads as (T-03-376).
func isReset(st *probeState, now uint64) bool {
	if !st.reset || st.ResetAt != now || len(st.Negatives) != ProbeNegativesPerHour {
		return false
	}
	for _, n := range st.Negatives {
		if n != now {
			return false
		}
	}
	return true
}

// TestProbeStateIO (03-10b, T-03-376): the reader of probe-state.json
// fails closed, and the writer needs the lock.
func TestProbeStateIO(t *testing.T) {
	full := func(now uint64) *probeState {
		return &probeState{Version: 1, Negatives: []uint64{now - 100, now - 10}, LastPair: now - 10, LastOpportunistic: now - 700,
			Failure: &probeFailure{Code: "probe_inconclusive", Key: strings.Repeat("cd", 32), At: now - 10, Count: 2},
			Alarm:   "probe_positive_refused", Held: &probeHeld{Reason: "failure_backoff", Bundle: 1, Directory: 4, KRL: 9, At: now - 10}}
	}
	setup := func(t *testing.T) (*testHost, *engine, uint64) {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		return h, lockedEngine(h), uint64(h.clock.Now().Unix()) //nolint:gosec // G115: test clock
	}
	good := func(t *testing.T, now uint64) []byte {
		t.Helper()
		b, err := full(now).encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("missing_is_empty", func(t *testing.T) {
		_, e, _ := setup(t)
		st := e.readProbeState()
		if st.reset || st.Version != 1 || len(st.Negatives) != 0 || st.Held != nil || st.Failure != nil || st.Alarm != "" || st.ResetAt != 0 {
			t.Fatalf("a missing file: %+v", st)
		}
	})
	t.Run("roundtrip_canonical_0600", func(t *testing.T) {
		h, e, now := setup(t)
		if err := e.writeProbeState(full(now)); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(h.l.State(probeStateFile))
		if err != nil {
			t.Fatal(err)
		}
		c, err := trust.CanonicalJSON(full(now))
		if err != nil || !bytes.Equal(b, c) {
			t.Fatalf("not canonical (%v):\n%s\n%s", err, b, c)
		}
		if fi, err := os.Stat(h.l.State(probeStateFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v (%v)", fi.Mode(), err)
		}
		st := e.readProbeState()
		if st.reset || st.Held == nil || *st.Held != *full(now).Held || *st.Failure != *full(now).Failure || len(st.Negatives) != 2 || st.Alarm != "probe_positive_refused" {
			t.Fatalf("read back %+v", st)
		}
		// The empty state encodes negatives as a list, never null.
		if err := e.writeProbeState(&probeState{Version: 1}); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(h.l.State(probeStateFile)); !strings.Contains(string(b), `"negatives":[]`) {
			t.Fatalf("the empty state: %s", b)
		}
	})
	resets := func(t *testing.T, write func(h *testHost, now uint64)) {
		t.Helper()
		h, e, now := setup(t)
		write(h, now)
		if st := e.readProbeState(); !isReset(st, now) {
			t.Fatalf("read %+v, want the exhausted hour", st)
		}
	}
	t.Run("unknown_field_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			b := strings.Replace(string(good(t, now)), `"version":1`, `"version":1,"extra":1`, 1)
			if err := os.WriteFile(h.l.State(probeStateFile), []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("symlink_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			other := filepath.Join(t.TempDir(), "probe-state.json")
			if err := os.WriteFile(other, good(t, now), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, h.l.State(probeStateFile)); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("mode_0644_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			if err := os.WriteFile(h.l.State(probeStateFile), good(t, now), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.l.State(probeStateFile), 0o644); err != nil { //nolint:gosec // the mode under test
				t.Fatal(err)
			}
		})
	})
	t.Run("foreign_owner_resets", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("chown needs root; the owner is compared like the mode")
		}
		resets(t, func(h *testHost, now uint64) {
			if err := os.WriteFile(h.l.State(probeStateFile), good(t, now), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(h.l.State(probeStateFile), 65534, 65534); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("oversize_resets", func(t *testing.T) {
		resets(t, func(h *testHost, _ uint64) {
			if err := os.WriteFile(h.l.State(probeStateFile), bytes.Repeat([]byte(" "), maxProbeState+1), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("truncated_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			b := good(t, now)
			if err := os.WriteFile(h.l.State(probeStateFile), b[:len(b)/2], 0o600); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("reset_counts_an_exhausted_hour", func(t *testing.T) {
		h, e, now := setup(t)
		h.cfg.probeOff = false
		e.cfg.probeOff = false
		if err := os.WriteFile(h.l.State(probeStateFile), []byte(`{"version":2}`), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := e.loadProbeState()
		if st.reset = true; err != nil || !isReset(st, now) {
			t.Fatalf("load %+v (%v), want the exhausted hour", st, err)
		}
		// Rewritten once: the file now reads as six negatives at now with
		// reset_at now, which reports probe_state_reset for an hour.
		again := e.readProbeState()
		if again.reset || again.ResetAt != now || len(again.Negatives) != ProbeNegativesPerHour {
			t.Fatalf("after the rewrite %+v", again)
		}
		var s heartbeat.Status
		e.probeStatus(&s)
		if s.ProbeDetail != DetailProbeStateReset {
			t.Fatalf("probe_detail %q", s.ProbeDetail)
		}
	})
	t.Run("future_entries_clamped_to_now", func(t *testing.T) {
		h, e, now := setup(t)
		st := full(now)
		st.Negatives = []uint64{now + 5000, now - 5}
		st.LastPair, st.LastOpportunistic, st.ResetAt = now+50, now+60, now+70
		st.Failure.At, st.Held.At = now+80, now+90
		b, err := st.encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.l.State(probeStateFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		got := e.readProbeState()
		if got.reset || got.Negatives[0] != now || got.Negatives[1] != now-5 || got.LastPair != now || got.LastOpportunistic != now ||
			got.ResetAt != now || got.Failure.At != now || got.Held.At != now {
			t.Fatalf("read %+v %+v %+v", got, got.Failure, got.Held)
		}
	})
	t.Run("never_written_outside_lock", func(t *testing.T) {
		h, e, now := setup(t)
		e.locked = false
		if err := e.writeProbeState(full(now)); err == nil {
			t.Fatal("written without the lock")
		}
		if _, err := os.Lstat(h.l.State(probeStateFile)); !os.IsNotExist(err) {
			t.Fatalf("the file exists: %v", err)
		}
	})
}

// FuzzParseState (03-10b): the strict decode of probe-state.json never
// panics, whatever it accepts re-encodes to the same bytes, and any input
// reads either as that state with nothing after now or as the exhausted
// hour.
func FuzzParseState(f *testing.F) {
	const now = 1_800_000_000
	st := &probeState{Version: 1, Negatives: []uint64{now - 1}, LastPair: now - 1,
		Failure: &probeFailure{Code: "probe_inconclusive", Key: strings.Repeat("ab", 32), At: now, Count: 1},
		Held:    &probeHeld{Reason: "budget", Bundle: 1, Directory: 1, KRL: 1, At: now}, Alarm: "probe_krl_not_enforced"}
	for _, s := range []*probeState{st, {Version: 1}} {
		b, err := s.encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"version":1,"negatives":null}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got := decodeProbeState(data, now)
		if got.reset {
			if !isReset(got, now) {
				t.Fatalf("a refused input reads as %+v", got)
			}
			return
		}
		parsed, err := parseProbeState(data)
		if err != nil {
			t.Fatalf("accepted by decodeProbeState, refused by parseProbeState: %v", err)
		}
		b, err := parsed.encode()
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("an accepted state re-encodes differently (%v):\n%s\n%s", err, data, b)
		}
		late := got.LastPair > now || got.LastOpportunistic > now || got.ResetAt > now ||
			got.Failure != nil && got.Failure.At > now || got.Held != nil && got.Held.At > now
		for _, n := range got.Negatives {
			late = late || n > now
		}
		if late {
			t.Fatalf("an entry after now survived the read: %+v", got)
		}
	})
}

// TestProbeClassify (03-10b, T-03-373): the class of a change comes from
// its content, and the probe-file exemption holds only for the generated
// probe file on both sides.
func TestProbeClassify(t *testing.T) {
	f := newFixture(t)
	ca := trust.FormatKey(f.user.PublicKey()) + "\n"
	probe := PrincipalsDir + "/" + certpkg.ReservedAccountName
	gen := func(host string, files ...string) *Generation {
		g := &Generation{Host: host, Files: map[string][]byte{CAFile: []byte(ca), KRLFile: []byte("krl-1")}}
		for i := 0; i+1 < len(files); i += 2 {
			g.Files[files[i]] = []byte(files[i+1])
		}
		return g
	}
	dir := func(lines ...string) string { return "# keyroster: directory version 1\n" + strings.Join(lines, "") }
	deploy := PrincipalsDir + "/deploy"
	agent, none := link{kind: linkAgent, n: 1}, link{kind: linkNone}
	cur := gen("web1", deploy, dir("role:a\n", "role:b\n"))
	want := func(t *testing.T, got, want probeClass) {
		t.Helper()
		if got != want {
			t.Fatalf("class %d, want %d", got, want)
		}
	}
	acct := certpkg.ReservedAccountName
	t.Run("first_install_no_last_good", func(t *testing.T) {
		want(t, classify(none, cur, gen("web1", deploy, dir("role:c\n")), acct), classFirstInstall)
	})
	t.Run("no_current_is_exempt", func(t *testing.T) {
		want(t, classify(agent, nil, gen("web1", deploy, dir("role:c\n")), acct), classFirstInstall)
	})
	t.Run("trust_only_when_no_principals_file", func(t *testing.T) {
		// An unauthorized directory, a disabled host and a removed host all
		// render the trust files alone; here each also adds a CA key.
		for _, host := range []string{"", "web1", "web0"} {
			g := gen(host)
			g.Files[CAFile] = []byte(ca + trust.FormatKey(f.mach.PublicKey()) + "\n")
			want(t, classify(agent, cur, g, acct), classTrustOnly)
		}
	})
	t.Run("narrowing_removed_line", func(t *testing.T) {
		want(t, classify(agent, cur, gen("web1", deploy, dir("role:a\n")), acct), classNarrowing)
	})
	t.Run("krl_only_is_narrowing", func(t *testing.T) {
		g := gen("web1", deploy, dir("role:a\n", "role:b\n"))
		g.Files[KRLFile] = []byte("krl-2")
		want(t, classify(agent, cur, g, acct), classNarrowing)
	})
	t.Run("probe_file_only_when_only_that_file_is_added", func(t *testing.T) {
		want(t, classify(agent, cur, gen("web1", deploy, dir("role:a\n", "role:b\n"), probe, string(probeFileFor("web1"))), acct), classProbeFileOnly)
	})
	t.Run("probe_file_plus_other_line_is_widening", func(t *testing.T) {
		want(t, classify(agent, cur, gen("web1", deploy, dir("role:a\n", "role:b\n", "role:c\n"), probe, string(probeFileFor("web1"))), acct), classWidening)
	})
	t.Run("probe_file_with_foreign_line_is_widening", func(t *testing.T) {
		want(t, classify(agent, cur, gen("web1", deploy, dir("role:a\n", "role:b\n"), probe, string(probeFileFor("web1"))+"role:root\n"), acct), classWidening)
	})
	t.Run("mapped_probe_account_addition_is_widening", func(t *testing.T) {
		c := gen("web1", deploy, dir("role:a\n"), probe, dir("role:a\n"))
		want(t, classify(agent, c, gen("web1", deploy, dir("role:a\n"), probe, dir("role:a\n", "role:x\n")), acct), classWidening)
	})
	t.Run("widening_added_line", func(t *testing.T) {
		want(t, classify(agent, cur, gen("web1", deploy, dir("role:a\n", "role:b\n", "role:c\n")), acct), classWidening)
	})
	t.Run("ca_line_added_is_widening", func(t *testing.T) {
		g := gen("web1", deploy, dir("role:a\n", "role:b\n"))
		g.Files[CAFile] = []byte(ca + trust.FormatKey(f.mach.PublicKey()) + "\n")
		want(t, classify(agent, cur, g, acct), classWidening)
	})
	t.Run("mixed_is_widening", func(t *testing.T) {
		want(t, classify(agent, cur, gen("web1", deploy, dir("role:a\n", "role:c\n")), acct), classWidening)
	})
	t.Run("account_rename_is_probe_file_only", func(t *testing.T) {
		c := gen("web1", deploy, dir("role:a\n"), probe, string(probeFileFor("web1")))
		want(t, classify(agent, c, gen("web1", deploy, dir("role:a\n"), PrincipalsDir+"/probe2", string(probeFileFor("web1"))), "probe2"), classProbeFileOnly)
	})
	t.Run("host_rename_is_probe_file_only", func(t *testing.T) {
		c := gen("web0", deploy, dir("role:a\n"), probe, string(probeFileFor("web0")))
		want(t, classify(agent, c, gen("web1", deploy, dir("role:a\n"), probe, string(probeFileFor("web1"))), acct), classProbeFileOnly)
	})
	t.Run("is_probe_file_exact", func(t *testing.T) {
		good := string(probeFileFor("web1"))
		if !isProbeFile([]byte(good), "web1") || !isProbeFile([]byte(good), "") {
			t.Fatalf("the generated file is refused:\n%s", good)
		}
		l := strings.SplitAfter(good, "\n")
		for name, b := range map[string]string{
			"missing_line":  l[0] + l[1],
			"extra_line":    good + "role:root\n",
			"reordered":     l[1] + l[0] + l[2],
			"altered":       l[0] + "# probe account, host  web1\n" + l[2],
			"trailing_line": good + "\n",
			"wrong_prefix":  l[0] + l[1] + "keyroster-prob:web1\n",
			"other_host":    l[0] + l[1] + certpkg.ReservedPrincipalPrefix + "web2\n",
			"intermediate":  intermediateHeader + certpkg.ReservedPrincipalPrefix + "web1\n",
		} {
			if isProbeFile([]byte(b), "web1") {
				t.Errorf("%s: accepted:\n%s", name, b)
			}
		}
		if isProbeFile([]byte(good), "web2") {
			t.Error("a probe file for web1 is accepted for web2")
		}
	})
	t.Run("is_cur_probe_file_table", func(t *testing.T) {
		for b, ok := range map[string]bool{
			string(probeFileFor("web1")): true,
			intermediateHeader:           true,
			intermediateHeader + certpkg.ReservedPrincipalPrefix + "web1\n":    true,
			intermediateHeader + "role:a\n":                                    false,
			intermediateHeader + certpkg.ReservedPrincipalPrefix + "web1\nx\n": false,
			dir("role:a\n"):           false,
			intermediateHeader + "\n": false,
		} {
			if got := isCurProbeFile([]byte(b)); got != ok {
				t.Errorf("isCurProbeFile(%q) = %t, want %t", b, got, ok)
			}
			if strings.HasPrefix(b, intermediateHeader) && isProbeFile([]byte(b), "") {
				t.Errorf("isProbeFile accepts the intermediate form %q", b)
			}
		}
	})
}

// TestProbeAccount (03-10b): the minimal probe account check over the
// fixture passwd.
func TestProbeAccount(t *testing.T) {
	const acct = certpkg.ReservedAccountName
	setup := func(t *testing.T, passwd string) string {
		t.Helper()
		root := t.TempDir()
		for _, d := range []string{"etc", "usr/sbin", "bin", "sbin/dir/nologin"} {
			if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}
		for name, mode := range map[string]os.FileMode{"usr/sbin/nologin": 0o755, "bin/sh": 0o755, "bin/nologin": 0o644} {
			if err := os.WriteFile(filepath.Join(root, name), []byte("#!/bin/false\n"), mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, name), mode); err != nil {
				t.Fatal(err)
			}
		}
		if passwd != "" {
			if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte(passwd), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}
		return root
	}
	line := func(uid, shell string) string { return acct + ":x:" + uid + ":990::/nonexistent:" + shell }
	ok := line("990", "/usr/sbin/nologin")
	for _, c := range []struct {
		name, passwd, reason string
	}{
		{"ok", "root:x:0:0:root:/root:/bin/bash\n" + ok + "\n", ""},
		{"missing_file", "", accountMissing},
		{"account_missing", "root:x:0:0:root:/root:/bin/bash\n", accountMissing},
		{"unparsable_own_line", acct + ":x:990:990::/nonexistent\n", accountUnparsable},
		{"duplicate_lines", ok + "\n" + ok + "\n", accountUnparsable},
		{"other_lines_malformed_are_ignored", "garbage\n+::::::\nnis:x\n\n" + ok + "\n", ""},
		{"uid_zero", line("0", "/usr/sbin/nologin") + "\n", accountUIDZero},
		{"shell_missing", line("990", "/sbin/nologin") + "\n", shellMissing},
		{"shell_not_executable", line("990", "/bin/nologin") + "\n", shellMissing},
		{"shell_is_directory", line("990", "/sbin/dir/nologin") + "\n", shellMissing},
		{"shell_not_nologin", line("990", "/bin/sh") + "\n", shellNotNologin},
		{"shell_relative_path_unparsable", line("990", "usr/sbin/nologin") + "\n", accountUnparsable},
		{"oversize_file_unparsable", ok + "\n" + strings.Repeat("#", maxPasswd) + "\n", accountUnparsable},
	} {
		t.Run(c.name, func(t *testing.T) {
			reason, got := checkProbeAccount(setup(t, c.passwd), acct)
			if reason != c.reason {
				t.Fatalf("reason %q, want %q", reason, c.reason)
			}
			if c.reason == "" && got != ok {
				t.Fatalf("line %q, want %q", got, ok)
			}
		})
	}
}

// gateHost is a host with the probe gate on, first-installed (exempt) with
// principals for deploy.
func gateHost(t *testing.T, principals ...string) *testHost {
	t.Helper()
	h := newTestHost(t, newFixture(t))
	h.gateOn()
	h.installed(principals...)
	return h
}

// ready gives h a usable committed pair whose negative the KRL in force
// lists, applied as a KRL-only change.
func (h *testHost) ready() probecert.Pair {
	h.t.Helper()
	p := h.seedPair(10*time.Minute, false)
	h.listMach(p.Negative.Serial)
	h.mustApply()
	return p
}

// probeStateNow is probe-state.json as the gate reads it (nil: absent).
func (h *testHost) probeStateNow() *probeState {
	h.t.Helper()
	b, err := os.ReadFile(h.l.State(probeStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	st, err := parseProbeState(b)
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

// heldNow is the held record's reason ("" for none).
func (h *testHost) heldNow() string {
	h.t.Helper()
	if st := h.probeStateNow(); st != nil && st.Held != nil {
		return st.Held.Reason
	}
	return ""
}

// setProbeState writes probe-state.json through the engine's writer.
func (h *testHost) setProbeState(st *probeState) {
	h.t.Helper()
	if err := lockedEngine(h).writeProbeState(st); err != nil {
		h.t.Fatal(err)
	}
}

// probeDetail is the heartbeat's probe_detail now.
func (h *testHost) probeDetail() string {
	h.t.Helper()
	var s heartbeat.Status
	lockedEngine(h).probeStatus(&s)
	return s.ProbeDetail
}

// acceptedDir is accepted/'s directory version.
func (h *testHost) acceptedDir() uint64 {
	h.t.Helper()
	s, err := h.accepted()
	if err != nil {
		h.t.Fatal(err)
	}
	return s.DirectoryVersion
}

// mustHeld requires a run held for reason, with the held record written.
func mustHeld(t *testing.T, h *testHost, r *Report, err error, reason string) {
	t.Helper()
	if !errors.Is(err, ErrProbeHeld) || !strings.Contains(err.Error(), "probe_held: "+reason) || r.Detail != "probe_held:"+reason {
		t.Fatalf("want held %s: err %v, detail %q", reason, err, r.Detail)
	}
	if r.ProbePositive != probeSkippedNotReady || r.ProbeNegative != probeSkippedNotReady {
		t.Fatalf("held probes %q %q", r.ProbePositive, r.ProbeNegative)
	}
	if got := h.heldNow(); got != reason {
		t.Fatalf("held record %q, want %q", got, reason)
	}
}

// mustPrincipals requires deploy's principals in current.
func mustPrincipals(t *testing.T, h *testHost, want ...string) {
	t.Helper()
	if got := h.principals("deploy"); !slices.Equal(got, want) {
		t.Fatalf("principals %v, want %v", got, want)
	}
}

// diskState is what a held retry must leave alone: the generations, the
// links, last_swap.json, accepted/ and probe-state.json.
func (h *testHost) diskState() string {
	h.t.Helper()
	var b strings.Builder
	entries, err := os.ReadDir(h.l.GenDir())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range entries {
		b.WriteString(e.Name() + " ")
	}
	fmt.Fprintf(&b, "\ncurrent %d last-good %d\n%s\n", h.current(), h.lastGood(), acceptedSnapshots(h.t, h))
	for _, n := range []string{lastSwapFile, probeStateFile} {
		x, _ := os.ReadFile(h.l.State(n))
		b.Write(x)
		b.WriteString("\n")
	}
	return b.String()
}

// TestProbeGate (03-10b, owner decision Q2, T-03-373 to T-03-375): an
// addition waits for the probe gate, its removal part and every KRL land
// at once, the held record is written before the commit, and a retry
// writes nothing.
func TestProbeGate(t *testing.T) {
	t.Run("narrowing_lands_without_probes", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b")
		h.publishDir(h.spec("role:a"))
		r := h.mustApply()
		mustPrincipals(t, h, "role:a")
		if r.Detail != "" || h.heldNow() != "" {
			t.Fatalf("detail %q, held %q", r.Detail, h.heldNow())
		}
	})
	t.Run("krl_only_lands_while_account_missing", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		h.publishKRL(77)
		r := h.mustApply()
		if !h.krlRevokes(h.l.Current(), 77) || r.KRLVersion != h.f.krlVersion || h.heldNow() != "" {
			t.Fatalf("the KRL did not land alone: %+v, held %q", r, h.heldNow())
		}
		if s, err := h.accepted(); err != nil || s.KRLVersion != h.f.krlVersion {
			t.Fatalf("accepted/ KRL: %+v %v", s, err)
		}
	})
	t.Run("widening_held_narrow_part_lands", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b")
		h.publishDir(h.spec("role:a", "role:c"))
		h.publishKRL(5)
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		mustPrincipals(t, h, "role:a")
		if !h.krlRevokes(h.l.Current(), 5) || h.acceptedDir() != 2 || h.lastGood() != h.current() {
			t.Fatalf("KRL %t, accepted/ directory %d, last-good %d, current %d", h.krlRevokes(h.l.Current(), 5), h.acceptedDir(), h.lastGood(), h.current())
		}
	})
	t.Run("pure_addition_held_changes_nothing_on_disk", func(t *testing.T) {
		h := gateHost(t, "role:a")
		cur := h.current()
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		mustPrincipals(t, h, "role:a")
		if h.current() != cur || h.lastGood() != cur || h.acceptedDir() != 2 {
			t.Fatalf("current %d (was %d), last-good %d, accepted/ directory %d", h.current(), cur, h.lastGood(), h.acceptedDir())
		}
	})
	t.Run("held_retry_writes_nothing", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b")
		h.publishDir(h.spec("role:a", "role:c"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		before := h.diskState()
		h.cfg.Fault = func(p string) error {
			if p == "marker" || p == "save-state" {
				t.Errorf("a held retry reached the %s fault point", p)
			}
			return nil
		}
		for i := range 5 {
			h.clock.advance(time.Minute)
			r, err := h.apply()
			mustHeld(t, h, r, err, "cert_missing")
			if after := h.diskState(); after != before {
				t.Fatalf("retry %d wrote:\n%s\nwas:\n%s", i, after, before)
			}
		}
	})
	t.Run("held_retried_when_ready", func(t *testing.T) {
		h := gateHost(t, "role:a")
		p := probecert.Pair{Positive: h.probeCert(10*time.Minute, h.f.mach), Negative: h.probeCert(10*time.Minute, h.f.mach)}
		h.listMach(p.Negative.Serial)
		h.mustApply()
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		h.storePair(p, false)
		h.mustApply() // the capture is unchanged: the held record renders again
		mustPrincipals(t, h, "role:a", "role:b")
		if h.heldNow() != "" {
			t.Fatalf("held %q after the addition landed", h.heldNow())
		}
	})
	t.Run("held_survives_restart", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		for range 2 {
			r, err := h.apply() // a new Apply on an unchanged spool, as a restart does
			mustHeld(t, h, r, err, "cert_missing")
			if r.NoOp {
				t.Fatal("a held retry is a no-op")
			}
		}
		h.ready()
		mustPrincipals(t, h, "role:a", "role:b")
	})
	t.Run("held_record_written_before_commit", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b")
		h.publishDir(h.spec("role:a", "role:c"))
		h.cfg.Fault = func(p string) error {
			if p == "save-state" {
				return errCrash
			}
			return nil
		}
		if _, err := h.apply(); !errors.Is(err, errCrash) {
			t.Fatalf("apply: %v, want the crash", err)
		}
		if h.heldNow() != "cert_missing" || h.acceptedDir() != 1 {
			t.Fatalf("at the crash: held %q, accepted/ directory %d", h.heldNow(), h.acceptedDir())
		}
		h.cfg.Fault = nil
		_, _ = h.apply()
		if h.heldNow() == "" && !slices.Contains(h.principals("deploy"), "role:c") {
			t.Fatal("the addition was lost: no held record and not in force")
		}
		h.ready()
		mustPrincipals(t, h, "role:a", "role:c")
	})
	t.Run("held_clears_when_widening_lands", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		h.ready()
		mustPrincipals(t, h, "role:a", "role:b")
		if h.heldNow() != "" || strings.HasPrefix(h.probeDetail(), "probe_held") {
			t.Fatalf("held %q, probe_detail %q", h.heldNow(), h.probeDetail())
		}
	})
	t.Run("held_clears_when_widening_reverted", func(t *testing.T) {
		for _, mixed := range []bool{false, true} {
			h := gateHost(t, "role:a", "role:b")
			add := h.spec("role:a", "role:b", "role:c")
			if mixed {
				add = h.spec("role:a", "role:c")
			}
			h.publishDir(add)
			r, err := h.apply()
			mustHeld(t, h, r, err, "cert_missing")
			back := h.spec("role:a", "role:b")
			if mixed {
				back = h.spec("role:a") // the same content as the intermediate-headed current
			}
			h.publishDir(back)
			if _, err := h.apply(); err != nil {
				t.Fatalf("mixed %t: the revert: %v", mixed, err)
			}
			if h.heldNow() != "" || strings.HasPrefix(h.probeDetail(), "probe_held") {
				t.Fatalf("mixed %t: held %q, probe_detail %q after the revert", mixed, h.heldNow(), h.probeDetail())
			}
			h.clock.advance(time.Minute)
			if r := h.mustApply(); !r.NoOp {
				t.Fatalf("mixed %t: the retry did not stop: %+v", mixed, r)
			}
		}
	})
	t.Run("probe_file_only_after_a_hold", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		h.installed("role:a", "role:b") // probes off: current has no probe file
		h.gateOn()
		h.publishDir(h.spec("role:a", "role:c"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		if got := h.file(PrincipalsDir + "/" + certpkg.ReservedAccountName); got != intermediateHeader {
			t.Fatalf("the intermediate's probe file is %q, want the header alone", got)
		}
		h.publishDir(h.spec("role:a"))
		r = h.mustApply()
		if h.heldNow() != "" || r.ProbePositive != "skipped:exempt_probe_file_only" {
			t.Fatalf("held %q, probe_positive %q", h.heldNow(), r.ProbePositive)
		}
		if !isProbeFile([]byte(h.file(PrincipalsDir+"/"+certpkg.ReservedAccountName)), "web1") {
			t.Fatal("the probe file is not in force")
		}
	})
	t.Run("probe_file_only_widening_exempt", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		h.installed("role:a")
		h.gateOn()
		h.publishDir(h.spec("role:a"))
		r := h.mustApply()
		if r.ProbePositive != "skipped:exempt_probe_file_only" || r.ProbeNegative != "skipped:exempt_probe_file_only" {
			t.Fatalf("probes %q %q", r.ProbePositive, r.ProbeNegative)
		}
		if !isProbeFile([]byte(h.file(PrincipalsDir+"/"+certpkg.ReservedAccountName)), "web1") {
			t.Fatal("the probe file is not in force")
		}
	})
	t.Run("first_install_exempt", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		h.gateOn()
		r := h.installed("role:a")
		if r.ProbePositive != "skipped:exempt_first_install" || h.heldNow() != "" {
			t.Fatalf("probe_positive %q, held %q", r.ProbePositive, h.heldNow())
		}
		mustPrincipals(t, h, "role:a")
	})
	trustOnly := func(t *testing.T, s func(h *testHost) dirSpec) {
		t.Helper()
		h := gateHost(t, "role:ops")
		next := seedKey(t, 31)
		_, d2 := h.f.successorNextUnder(h.f.bundle, h.f.bundleDoc, h.f.policyDoc, "2026-10-02T00:00:00Z", next)
		h.state.Bundles[2] = d2
		h.publishDir(s(h))
		r, err := h.apply()
		if errors.Is(err, ErrProbeHeld) || r.ProbePositive != "skipped:exempt_trust_only" {
			t.Fatalf("err %v, probe_positive %q", err, r.ProbePositive)
		}
		if !strings.Contains(h.file(CAFile), trust.FormatKey(next.PublicKey())) || h.principals("deploy") != nil {
			t.Fatalf("CA list %q, principals %v", h.file(CAFile), h.principals("deploy"))
		}
	}
	t.Run("trust_only_disabled_exempt", func(t *testing.T) {
		trustOnly(t, func(h *testHost) dirSpec {
			s := h.spec("role:ops", "role:new")
			s.status = directory.StatusDisabled
			return s
		})
	})
	t.Run("trust_only_removed_exempt", func(t *testing.T) {
		trustOnly(t, func(h *testHost) dirSpec {
			s := h.spec("role:ops", "role:new")
			s.noHost = true
			return s
		})
	})
	t.Run("trust_only_unauthorized_exempt", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops") // probes off for the set-up
		h.publishDir(h.spec("role:evil"))
		h.mustApply()
		h.gateOn()
		bob, next := seedKey(t, 11), seedKey(t, 31)
		_, d2, p2 := f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-02T00:00:00Z", next)
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		r, err := h.apply()
		if errors.Is(err, ErrProbeHeld) || !r.DirectoryUnauthorized || r.ProbePositive != "skipped:exempt_trust_only" {
			t.Fatalf("err %v, unauthorized %t, probe_positive %q", err, r.DirectoryUnauthorized, r.ProbePositive)
		}
		if !strings.Contains(h.file(CAFile), trust.FormatKey(next.PublicKey())) {
			t.Fatal("the new CA key is not in force")
		}
	})
	t.Run("account_reasons_hold", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		h.writeRootFile("bin/sh", []byte("#!/bin/false\n"), 0o755)
		h.publishDir(h.spec("role:a", "role:b"))
		for _, c := range []struct{ passwd, reason string }{
			{"root:x:0:0:root:/root:/bin/bash\n", accountMissing},
			{certpkg.ReservedAccountName + ":x:990:990::/nonexistent\n", accountUnparsable},
			{certpkg.ReservedAccountName + ":x:0:0::/nonexistent:/usr/sbin/nologin\n", accountUIDZero},
			{certpkg.ReservedAccountName + ":x:990:990::/nonexistent:/sbin/nologin\n", shellMissing},
			{certpkg.ReservedAccountName + ":x:990:990::/nonexistent:/bin/sh\n", shellNotNologin},
		} {
			h.writePasswd(c.passwd)
			r, err := h.apply()
			mustHeld(t, h, r, err, c.reason)
			mustPrincipals(t, h, "role:a")
		}
	})
	mapped := func(t *testing.T, accounts ...string) *testHost {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		h.gateOn()
		s := h.spec("role:a")
		s.accounts = accounts
		h.publishDir(s)
		h.mustApply()
		h.ready()
		s = h.spec("role:a", "role:b")
		s.accounts = accounts
		h.publishDir(s)
		return h
	}
	t.Run("mapped_account_holds_account_is_managed", func(t *testing.T) {
		h := mapped(t, "deploy", certpkg.ReservedAccountName)
		r, err := h.apply()
		mustHeld(t, h, r, err, "account_is_managed")
		if got := h.principals(certpkg.ReservedAccountName); !slices.Equal(got, []string{"role:a"}) {
			t.Fatalf("the mapped probe account holds %v", got)
		}
	})
	t.Run("mapped_probe_account_addition_held", func(t *testing.T) {
		h := mapped(t, certpkg.ReservedAccountName)
		r, err := h.apply()
		mustHeld(t, h, r, err, "account_is_managed")
		if got := h.principals(certpkg.ReservedAccountName); !slices.Equal(got, []string{"role:a"}) {
			t.Fatalf("the mapped probe account holds %v: an addition landed unprobed", got)
		}
	})
	pairHold := func(t *testing.T, reason string, set func(h *testHost)) {
		t.Helper()
		h := gateHost(t, "role:a")
		set(h)
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustHeld(t, h, r, err, reason)
		mustPrincipals(t, h, "role:a")
	}
	t.Run("pair_ca_mismatch_holds", func(t *testing.T) {
		pairHold(t, probecert.CAMismatch, func(h *testHost) {
			p := h.storePair(probecert.Pair{Positive: h.probeCert(10*time.Minute, seedKey(t, 41)), Negative: h.probeCert(10*time.Minute, h.f.mach)}, false)
			h.listMach(p.Negative.Serial)
			h.mustApply()
		})
	})
	t.Run("positive_in_krl_holds", func(t *testing.T) {
		pairHold(t, probecert.PositiveInKRL, func(h *testHost) {
			p := h.seedPair(10*time.Minute, false)
			h.listMach(p.Positive.Serial, p.Negative.Serial)
			h.mustApply()
		})
	})
	t.Run("negative_not_in_krl_holds", func(t *testing.T) {
		pairHold(t, probecert.NegativeNotInKRL, func(h *testHost) { h.seedPair(10*time.Minute, false) })
	})
	t.Run("issue_refused_names_sticky_refusal", func(t *testing.T) {
		pairHold(t, "issue_refused", func(h *testHost) {
			e := lockedEngine(h)
			rec := e.readProbeRecord()
			rec.Attempts.Positive.Sticky = &hostcert.StickyHold{Code: "host_disabled", Bundle: 1, Policy: 1, Directory: 1, At: e.probeNow()}
			if err := e.saveProbeRecord(rec); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("issue_unanswered_names_pending_request", func(t *testing.T) {
		pairHold(t, "issue_unanswered", func(h *testHost) {
			e := lockedEngine(h)
			rec := e.readProbeRecord()
			rec.Attempts.Negative.AddRequest(strings.Repeat("ef", 16), e.probeNow(), h.f.user.PublicKey().Marshal())
			if err := e.saveProbeRecord(rec); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("pair_validity_needs_wait_margin", func(t *testing.T) {
		// Valid now, but not past LoginGraceTime + 30 s and two self-test
		// timeouts plus the missing margin.
		pairHold(t, probecert.CertMissing, func(h *testHost) {
			p := h.seedPair(180*time.Second, false)
			h.listMach(p.Negative.Serial)
			h.mustApply()
			if probecert.PairUsable(p, h.clock.Now(), genKRL(h.genNow()), genCAKeys(h.genNow())) != "" {
				t.Fatal("the pair is not usable now")
			}
		})
	})
	budget := func(t *testing.T, held bool, set func(st *probeState, now uint64)) {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		h.run.grace = "10" // a widening wait of 40 s
		h.gateOn()
		h.installed("role:a")
		h.ready()
		now := uint64(h.clock.Now().Unix()) //nolint:gosec // G115: test clock
		st := newProbeState()
		set(st, now)
		h.setProbeState(st)
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		if held {
			mustHeld(t, h, r, err, "budget")
			return
		}
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		mustPrincipals(t, h, "role:a", "role:b")
	}
	t.Run("budget_lookahead_spacing", func(t *testing.T) {
		// The probes run 40 s from now: a pair 21 s ago is 61 s old then,
		// one 19 s ago 59 s.
		budget(t, false, func(st *probeState, now uint64) { st.LastPair = now - 21 })
		budget(t, true, func(st *probeState, now uint64) { st.LastPair = now - 19 })
	})
	t.Run("over_budget_widening_held", func(t *testing.T) {
		budget(t, true, func(st *probeState, now uint64) {
			for i := range ProbeNegativesPerHour {
				st.Negatives = append(st.Negatives, now-3000+uint64(i)) //nolint:gosec // G115: a small index
			}
		})
		budget(t, false, func(st *probeState, now uint64) {
			for i := range ProbeNegativesPerHour - 1 {
				st.Negatives = append(st.Negatives, now-3000+uint64(i)) //nolint:gosec // G115: a small index
			}
			st.Negatives = append(st.Negatives, now-3601)
		})
	})
	t.Run("failure_backoff_blocks_until_input_changes", func(t *testing.T) {
		for _, change := range []string{"passwd", "pair", "candidate"} {
			h := gateHost(t, "role:a")
			p := h.ready()
			cur, _, err := lockedEngine(h).readCurrent()
			if err != nil {
				t.Fatal(err)
			}
			cur.Files[PrincipalsDir+"/deploy"] = []byte("role:a\nrole:b\n")
			st := newProbeState()
			st.Failure = &probeFailure{Code: ErrProbePositiveRefused.Error(), Key: failureKey(cur, p, probeLogin), At: lockedEngine(h).probeNow(), Count: 1}
			h.setProbeState(st)
			h.publishDir(h.spec("role:a", "role:b"))
			r, err := h.apply()
			mustHeld(t, h, r, err, "failure_backoff")
			switch change {
			case "passwd":
				h.writePasswd(strings.Replace(probeLogin, ":990:990:", ":990:991:", 1) + "\n")
				h.mustApply()
			case "pair":
				h.ready()
			case "candidate":
				h.publishDir(h.spec("role:a", "role:b", "role:c"))
				h.mustApply()
			}
			if !slices.Contains(h.principals("deploy"), "role:b") {
				t.Fatalf("%s changed: the addition did not land at once", change)
			}
		}
	})
	t.Run("off_never_gates", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.cfg.probeOff = true
		h.publishDir(h.spec("role:a", "role:b"))
		r := h.mustApply()
		mustPrincipals(t, h, "role:a", "role:b")
		if r.Detail != DetailProbeSelfTestOff || r.ProbePositive != probeSkippedOff || h.probeStateNow() != nil {
			t.Fatalf("detail %q, probe_positive %q, state %+v", r.Detail, r.ProbePositive, h.probeStateNow())
		}
	})
	t.Run("dry_run_never_gates", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.publishDir(h.spec("role:a", "role:b"))
		h.cfg.DryRun = true
		r, err := h.apply()
		if err != nil || len(r.Diff) == 0 || r.Detail != "" || h.probeStateNow() != nil {
			t.Fatalf("dry run: %v, diff %v, detail %q, state %+v", err, r.Diff, r.Detail, h.probeStateNow())
		}
	})
	t.Run("krl_alone_pass_is_classified", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b")
		h.publishDir(h.spec("role:a", "role:c"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		// A refused candidate: its KRL-alone pass renders accepted/'s
		// directory, the held addition included, which is gated again.
		s := h.spec("role:a", "role:c")
		s.bulkRoles = 17
		h.publishDir(s)
		h.publishKRL(88)
		r, err = h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		mustPrincipals(t, h, "role:a")
		if !h.krlRevokes(h.l.Current(), 88) {
			t.Fatal("the KRL of the refused capture is not in force")
		}
	})
	t.Run("superseded_target_reclassified", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready() // a swap just now: the widening waits
		h.writeRootFile("bin/sh", []byte("#!/bin/false\n"), 0o755)
		h.publishDir(h.spec("role:a", "role:b"))
		fired := false
		h.clock.onSleep = func(time.Duration) {
			if fired {
				return
			}
			fired = true
			h.publishDir(h.spec("role:a", "role:b", "role:c"))
			h.write()
			h.writePasswd(certpkg.ReservedAccountName + ":x:990:990::/nonexistent:/bin/sh\n")
		}
		r, err := h.apply()
		if !fired {
			t.Fatal("the widening did not wait")
		}
		mustHeld(t, h, r, err, shellNotNologin)
		mustPrincipals(t, h, "role:a")
		if h.acceptedDir() != 3 || h.current() != h.lastGood() {
			t.Fatalf("accepted/ directory %d, current %d, last-good %d", h.acceptedDir(), h.current(), h.lastGood())
		}
	})
	t.Run("held_pass_then_krl_alone_pass_reports_no_hold", func(t *testing.T) {
		// The held candidate's intermediate is refused (a CA line), so the
		// KRL-alone pass commits without a hold: its report carries no
		// probe_held from the first pass.
		h := gateHost(t, "role:a", "role:b")
		machine := trust.FormatKey(h.f.mach.PublicKey())
		armed := true
		h.run.rejectCA = func(line string) bool {
			if armed && line == machine {
				armed = false
				return true
			}
			return false
		}
		h.publishDir(h.spec("role:a", "role:c"))
		h.publishKRL(9)
		r, _ := h.apply()
		if armed || !h.krlRevokes(h.l.Current(), 9) {
			t.Fatalf("the intermediate was not refused (%t) or the KRL-alone pass did not land", !armed)
		}
		if strings.HasPrefix(r.Detail, "probe_held") || r.ProbePositive == probeSkippedNotReady && r.Detail != "" {
			t.Fatalf("a stale hold in the report: detail %q, probes %q %q", r.Detail, r.ProbePositive, r.ProbeNegative)
		}
	})
	probeGateRuns(t)
}

// scriptProbes makes h's probe queries answer outs in order and then as
// sshd does (sshdProbe); every query is recorded.
func (h *testHost) scriptProbes(outs ...ProbeOutcome) {
	h.cfg.probeQuery = func(ctx context.Context, t ProbeTarget, c *ssh.Certificate, d time.Time) (ProbeOutcome, error) {
		h.probeMu.Lock()
		if len(outs) > 0 {
			o := outs[0]
			outs = outs[1:]
			h.queries = append(h.queries, t)
			h.probeMu.Unlock()
			return o, nil
		}
		h.probeMu.Unlock()
		return h.sshdProbe(ctx, t, c, d)
	}
}

// readyFor is ready with a pair of the given lifetime.
func (h *testHost) readyFor(d time.Duration) probecert.Pair {
	h.t.Helper()
	p := h.seedPair(d, false)
	h.listMach(p.Negative.Serial)
	h.mustApply()
	return p
}

// mustFailed requires a run whose probes failed with code: the error, the
// rollback, the detail and the failure record.
func mustFailed(t *testing.T, h *testHost, r *Report, err error, code error) {
	t.Helper()
	if !errors.Is(err, code) || !r.Rollback || r.Detail != code.Error() {
		t.Fatalf("want %v rolled back: err %v, rollback %t, detail %q", code, err, r.Rollback, r.Detail)
	}
	if st := h.probeStateNow(); st == nil || st.Failure == nil || st.Failure.Code != code.Error() {
		t.Fatalf("failure record %+v", st)
	}
}

// mixedFail runs a mixed change (role:a removed, role:c added, KRL 66)
// whose probes answer outs on a host with role:a and role:b, recording
// deploy's principals at every swap, and requires that the removal stayed
// in force from the narrowing swap on (03-10b, D13).
func mixedFail(t *testing.T, code error, outs ...ProbeOutcome) (*testHost, *Report) {
	t.Helper()
	h := gateHost(t, "role:a", "role:b")
	h.ready()
	lg0 := h.lastGood()
	var swaps [][]string
	h.cfg.Fault = func(p string) error {
		if p == "swap" {
			swaps = append(swaps, h.principals("deploy"))
		}
		return nil
	}
	h.scriptProbes(outs...)
	h.publishDir(h.spec("role:b", "role:c"))
	h.publishKRL(66)
	r, err := h.apply()
	h.cfg.Fault = nil
	mustFailed(t, h, r, err, code)
	if len(swaps) < 2 {
		t.Fatalf("swaps %v", swaps)
	}
	for i, s := range swaps[1:] {
		if slices.Contains(s, "role:a") {
			t.Fatalf("swap %d: role:a was in force again: %v", i+1, s)
		}
	}
	mustPrincipals(t, h, "role:b")
	if h.current() != h.lastGood() || h.current() == lg0 || h.current() != r.Generation {
		t.Fatalf("current %d, last-good %d (was %d), report generation %d", h.current(), h.lastGood(), lg0, r.Generation)
	}
	if h.acceptedDir() != 2 || !h.krlRevokes(h.l.Current(), 66) {
		t.Fatalf("accepted/ directory %d, KRL 66 in force %t", h.acceptedDir(), h.krlRevokes(h.l.Current(), 66))
	}
	if h.heldNow() != "failure_backoff" {
		t.Fatalf("held %q", h.heldNow())
	}
	return h, r
}

// probeGateRuns are TestProbeGate's subtests of the probes after a swap
// (03-10b, Task 4: T-03-66, T-03-67, T-03-374).
func probeGateRuns(t *testing.T) {
	t.Run("widening_passes_both_probes", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustHeld(t, h, r, err, "cert_missing")
		p := h.seedPair(10*time.Minute, false)
		h.listMach(p.Negative.Serial)
		r = h.mustApply()
		mustPrincipals(t, h, "role:a", "role:b")
		st := h.probeStateNow()
		if r.ProbePositive != probePass || r.ProbeNegative != probePass || r.Rollback || h.current() != h.lastGood() {
			t.Fatalf("report %+v", r)
		}
		if st.Held != nil || st.Failure != nil || len(st.Negatives) != 1 || len(h.probeQueries()) != 2 {
			t.Fatalf("state %+v, %d queries", st, len(h.probeQueries()))
		}
	})
	t.Run("widening_positive_refused_rolls_back", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		cur := h.current()
		h.scriptProbes(ProbeRefused)
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustFailed(t, h, r, err, ErrProbePositiveRefused)
		mustPrincipals(t, h, "role:a")
		if h.current() != cur || h.lastGood() != cur || h.acceptedDir() != 1 || h.heldNow() != "" {
			t.Fatalf("current %d, last-good %d (was %d), accepted/ directory %d, held %q", h.current(), h.lastGood(), cur, h.acceptedDir(), h.heldNow())
		}
		q := len(h.probeQueries())
		r, err = h.apply()
		mustHeld(t, h, r, err, "failure_backoff")
		if len(h.probeQueries()) != q {
			t.Fatal("the held retry sent a query")
		}
	})
	t.Run("mixed_positive_refused_keeps_removal", func(t *testing.T) {
		mixedFail(t, ErrProbePositiveRefused, ProbeRefused)
	})
	t.Run("mixed_negative_accepted_keeps_removal", func(t *testing.T) {
		mixedFail(t, ErrProbeKRLNotEnforced, ProbeAccepted, ProbeAccepted)
	})
	t.Run("mixed_inconclusive_keeps_removal", func(t *testing.T) {
		mixedFail(t, ErrProbeInconclusive, ProbeInconclusive)
	})
	t.Run("mixed_failure_next_apply_holds_and_writes_nothing", func(t *testing.T) {
		h, _ := mixedFail(t, ErrProbePositiveRefused, ProbeRefused)
		before, q := h.diskState(), len(h.probeQueries())
		h.cfg.Fault = func(p string) error {
			if p == "marker" || p == "save-state" {
				t.Errorf("the held retry reached the %s fault point", p)
			}
			return nil
		}
		r, err := h.apply()
		mustHeld(t, h, r, err, "failure_backoff")
		if after := h.diskState(); after != before || len(h.probeQueries()) != q {
			t.Fatalf("the retry wrote or queried:\n%s\nwas:\n%s", after, before)
		}
	})
	t.Run("addition_with_krl_change_failure_lands_the_krl", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		h.scriptProbes(ProbeRefused)
		h.publishDir(h.spec("role:a", "role:b"))
		h.publishKRL(67)
		r, err := h.apply()
		mustFailed(t, h, r, err, ErrProbePositiveRefused)
		mustPrincipals(t, h, "role:a")
		if !h.krlRevokes(h.l.Current(), 67) || h.current() != h.lastGood() {
			t.Fatalf("KRL 67 in force %t, current %d, last-good %d", h.krlRevokes(h.l.Current(), 67), h.current(), h.lastGood())
		}
	})
	t.Run("rollback_keeps_newer_krl", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		h.scriptProbes(ProbeInconclusive)
		h.publishDir(h.spec("role:a", "role:b"))
		h.publishKRL(68)
		r, err := h.apply()
		mustFailed(t, h, r, err, ErrProbeInconclusive)
		if !h.krlRevokes(h.l.Current(), 68) || !h.krlRevokes(h.l.LastGood(), 68) {
			t.Fatal("the newer KRL is not in force after the rollback")
		}
	})
	// supersede runs a change from to first on a host with principals
	// with, publishing then at the first sleep of the widening wait, and
	// records the generation current names at every swap.
	supersede := func(t *testing.T, with, first, then []string, krl uint64, outs ...ProbeOutcome) (*testHost, *Report, []uint64, error) {
		t.Helper()
		h := gateHost(t, with...)
		h.ready()
		h.scriptProbes(outs...)
		var swaps []uint64
		h.cfg.Fault = func(p string) error {
			if p == "swap" {
				swaps = append(swaps, h.current())
			}
			return nil
		}
		fired := false
		h.clock.onSleep = func(time.Duration) {
			if fired {
				return
			}
			fired = true
			h.publishDir(h.spec(then...))
			h.write()
		}
		h.publishDir(h.spec(first...))
		if krl != 0 {
			h.publishKRL(krl)
		}
		r, err := h.apply()
		h.cfg.Fault, h.clock.onSleep = nil, nil
		if !fired {
			t.Fatal("the widening did not wait")
		}
		return h, r, swaps, err
	}
	t.Run("superseded_mixed_failure_keeps_removal", func(t *testing.T) {
		h, r, swaps, err := supersede(t, []string{"role:a", "role:b"}, []string{"role:b", "role:c"}, []string{"role:b", "role:c"}, 70, ProbeRefused)
		mustFailed(t, h, r, err, ErrProbePositiveRefused)
		mustPrincipals(t, h, "role:b")
		if len(swaps) < 2 || h.current() != swaps[1] || h.lastGood() != h.current() {
			t.Fatalf("swaps %v, current %d, last-good %d", swaps, h.current(), h.lastGood())
		}
		if h.acceptedDir() != 3 || !h.krlRevokes(h.l.Current(), 70) {
			t.Fatalf("accepted/ directory %d, KRL 70 %t", h.acceptedDir(), h.krlRevokes(h.l.Current(), 70))
		}
		r, err = h.apply()
		mustHeld(t, h, r, err, "failure_backoff")
	})
	t.Run("superseded_readd_failure_keeps_last_good_lines", func(t *testing.T) {
		t.Run("full_readd", func(t *testing.T) {
			h, r, _, err := supersede(t, []string{"role:a", "role:b"}, []string{"role:b", "role:c"}, []string{"role:a", "role:b", "role:c"}, 0, ProbeRefused)
			mustFailed(t, h, r, err, ErrProbePositiveRefused)
			mustPrincipals(t, h, "role:a", "role:b")
			if h.current() != h.lastGood() || h.heldNow() != "" {
				t.Fatalf("current %d, last-good %d, held %q", h.current(), h.lastGood(), h.heldNow())
			}
			// The plain rollback leaves accepted/; the next round holds and
			// stores the newest version.
			r, err = h.apply()
			mustHeld(t, h, r, err, "failure_backoff")
			mustPrincipals(t, h, "role:a", "role:b")
			if h.acceptedDir() != 3 {
				t.Fatalf("accepted/ directory %d", h.acceptedDir())
			}
		})
		t.Run("partial_readd", func(t *testing.T) {
			h, r, _, err := supersede(t, []string{"role:a", "role:b", "role:d"}, []string{"role:b", "role:c"}, []string{"role:a", "role:b", "role:c"}, 70, ProbeRefused)
			mustFailed(t, h, r, err, ErrProbePositiveRefused)
			mustPrincipals(t, h, "role:a", "role:b")
			if h.current() != h.lastGood() || h.acceptedDir() != 3 || !h.krlRevokes(h.l.Current(), 70) {
				t.Fatalf("current %d, last-good %d, accepted/ directory %d", h.current(), h.lastGood(), h.acceptedDir())
			}
		})
		t.Run("readd_only_removes_from_last_good", func(t *testing.T) {
			// T2 re-adds role:a and keeps role:d removed: Intermediate(last-good,
			// T2) collapses to T2 itself, so the plain rollback would re-grant
			// role:d. The target settles on itself.
			h, r, _, err := supersede(t, []string{"role:a", "role:b", "role:d"}, []string{"role:b", "role:c"}, []string{"role:a", "role:b"}, 0, ProbeRefused)
			mustFailed(t, h, r, err, ErrProbePositiveRefused)
			mustPrincipals(t, h, "role:a", "role:b")
			if h.current() != h.lastGood() || h.acceptedDir() != 3 || h.heldNow() != "failure_backoff" {
				t.Fatalf("current %d, last-good %d, accepted/ directory %d, held %q", h.current(), h.lastGood(), h.acceptedDir(), h.heldNow())
			}
		})
	})
	t.Run("superseded_to_narrowing_runs_no_probes", func(t *testing.T) {
		h, r, _, err := supersede(t, []string{"role:a", "role:b"}, []string{"role:a", "role:b", "role:c"}, []string{"role:a"}, 0)
		if err != nil || r.Rollback {
			t.Fatalf("apply: %v, rollback %t", err, r.Rollback)
		}
		mustPrincipals(t, h, "role:a")
		if n := len(h.probeQueries()); n != 2 {
			t.Fatalf("%d queries, want only ready's opportunistic pair", n)
		}
	})
	t.Run("held_clears_after_settle_and_revert", func(t *testing.T) {
		h, _ := mixedFail(t, ErrProbePositiveRefused, ProbeRefused)
		h.publishDir(h.spec("role:b"))
		if _, err := h.apply(); err != nil {
			t.Fatal(err)
		}
		mustPrincipals(t, h, "role:b")
		if h.heldNow() != "" || strings.HasPrefix(h.probeDetail(), "probe_held") {
			t.Fatalf("held %q, probe_detail %q", h.heldNow(), h.probeDetail())
		}
	})
	t.Run("settle_listener_failure_falls_back_to_plain_rollback", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b")
		h.ready()
		h.cfg.probeQuery = func(context.Context, ProbeTarget, *ssh.Certificate, time.Time) (ProbeOutcome, error) {
			h.sshd.setStall(true) // the listener test fails after the move to M
			return ProbeRefused, nil
		}
		h.publishDir(h.spec("role:b", "role:c"))
		r, err := h.apply()
		h.sshd.setStall(false)
		if !errors.Is(err, ErrProbePositiveRefused) || !r.Rollback || h.heldNow() != "failure_backoff" {
			t.Fatalf("apply: %v, rollback %t, held %q", err, r.Rollback, h.heldNow())
		}
		// The fallback re-granted role:a (the named residual). Its way back
		// is a widening swap that waits LoginGraceTime + 30 s, longer than
		// the first back-off, so the next apply either holds or retries the
		// addition and settles again: role:a is gone either way.
		mustPrincipals(t, h, "role:a", "role:b")
		h.scriptProbes(ProbeRefused)
		_, err = h.apply()
		if !errors.Is(err, ErrProbeHeld) && !errors.Is(err, ErrProbePositiveRefused) {
			t.Fatalf("the next apply: %v", err)
		}
		mustPrincipals(t, h, "role:b")
		if h.heldNow() != "failure_backoff" {
			t.Fatalf("held %q", h.heldNow())
		}
	})
	t.Run("positive_refused_sends_no_negative", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		q := len(h.probeQueries())
		h.scriptProbes(ProbeRefused)
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustFailed(t, h, r, err, ErrProbePositiveRefused)
		if n := len(h.probeQueries()) - q; n != 1 || r.ProbePositive != probeFail || r.ProbeNegative != probeSkippedNotReady {
			t.Fatalf("%d queries, probes %q %q", n, r.ProbePositive, r.ProbeNegative)
		}
	})
	t.Run("widening_negative_accepted_rolls_back", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		h.scriptProbes(ProbeAccepted, ProbeAccepted)
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustFailed(t, h, r, err, ErrProbeKRLNotEnforced)
		mustPrincipals(t, h, "role:a")
	})
	t.Run("widening_inconclusive_rolls_back", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		h.scriptProbes(ProbeAccepted, ProbeInconclusive)
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		mustFailed(t, h, r, err, ErrProbeInconclusive)
		mustPrincipals(t, h, "role:a")
	})
	t.Run("pair_expired_during_wait_is_inconclusive", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		q := len(h.probeQueries())
		fired := false
		h.clock.onSleep = func(time.Duration) {
			if !fired {
				fired = true
				h.clock.advance(10 * time.Minute) // the pair runs out inside the wait
			}
		}
		h.publishDir(h.spec("role:a", "role:b"))
		r, err := h.apply()
		h.clock.onSleep = nil
		mustFailed(t, h, r, err, ErrProbeInconclusive)
		if !fired || len(h.probeQueries()) != q || r.ProbePositive != probeInconclusive {
			t.Fatalf("fired %t, %d queries, probe_positive %q", fired, len(h.probeQueries())-q, r.ProbePositive)
		}
	})
	narrow := func(t *testing.T, code error, outs ...ProbeOutcome) {
		t.Helper()
		h := gateHost(t, "role:a", "role:b")
		h.readyFor(time.Hour)
		h.clock.advance(11 * time.Minute)
		h.scriptProbes(outs...)
		h.publishDir(h.spec("role:a"))
		r := h.mustApply()
		mustPrincipals(t, h, "role:a")
		if r.Rollback || r.Detail != code.Error() || h.probeStateNow().Alarm != code.Error() {
			t.Fatalf("rollback %t, detail %q, alarm %q", r.Rollback, r.Detail, h.probeStateNow().Alarm)
		}
		if r := h.mustApply(); !r.NoOp || h.probeDetail() != code.Error() {
			t.Fatalf("after a no-op apply: noop %t, probe_detail %q", r.NoOp, h.probeDetail())
		}
	}
	t.Run("narrowing_negative_accepted_no_rollback_reports", func(t *testing.T) {
		narrow(t, ErrProbeKRLNotEnforced, ProbeAccepted, ProbeAccepted)
	})
	t.Run("narrowing_positive_refused_reports", func(t *testing.T) {
		narrow(t, ErrProbePositiveRefused, ProbeRefused)
	})
	t.Run("opportunistic_once_per_ten_minutes", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b", "role:c")
		h.readyFor(time.Hour)
		q := len(h.probeQueries())
		h.clock.advance(5 * time.Minute)
		h.publishDir(h.spec("role:a", "role:b"))
		if r := h.mustApply(); r.ProbePositive != probeSkippedBudget || len(h.probeQueries()) != q {
			t.Fatalf("5 min later: probes %q, %d queries", r.ProbePositive, len(h.probeQueries())-q)
		}
		h.clock.advance(6 * time.Minute)
		h.publishDir(h.spec("role:a"))
		if r := h.mustApply(); r.ProbePositive != probePass || len(h.probeQueries()) != q+2 {
			t.Fatalf("11 min later: probes %q, %d queries", r.ProbePositive, len(h.probeQueries())-q)
		}
	})
	opp := func(t *testing.T, negatives int, want string) {
		t.Helper()
		h := gateHost(t, "role:a", "role:b")
		h.readyFor(time.Hour)
		now := lockedEngine(h).probeNow()
		st := newProbeState()
		for i := range negatives {
			st.Negatives = append(st.Negatives, now-3000+uint64(i)) //nolint:gosec // G115: a small index
		}
		st.LastPair = now - 3000
		h.setProbeState(st)
		h.publishDir(h.spec("role:a"))
		if r := h.mustApply(); r.ProbePositive != want || r.ProbeNegative != want {
			t.Fatalf("%d negatives: probes %q %q, want %q", negatives, r.ProbePositive, r.ProbeNegative, want)
		}
	}
	t.Run("opportunistic_skips_after_three_negatives_in_the_hour", func(t *testing.T) {
		opp(t, ProbeOpportunisticNegatives, probeSkippedBudget)
		opp(t, ProbeOpportunisticNegatives-1, probePass)
	})
	t.Run("over_budget_narrowing_skips_negative", func(t *testing.T) {
		opp(t, ProbeNegativesPerHour, probeSkippedBudget)
	})
	t.Run("opportunistic_skipped_when_not_ready", func(t *testing.T) {
		h := gateHost(t, "role:a", "role:b")
		h.publishDir(h.spec("role:a"))
		if r := h.mustApply(); r.ProbePositive != probeSkippedNotReady || len(h.probeQueries()) != 0 {
			t.Fatalf("probes %q, %d queries", r.ProbePositive, len(h.probeQueries()))
		}
	})
	seeded := func(t *testing.T, set func(st *probeState, now uint64)) *testHost {
		t.Helper()
		h := gateHost(t, "role:a")
		h.readyFor(time.Hour)
		now := lockedEngine(h).probeNow()
		st := newProbeState()
		set(st, now)
		h.setProbeState(st)
		h.publishDir(h.spec("role:a", "role:b"))
		h.mustApply()
		mustPrincipals(t, h, "role:a", "role:b")
		return h
	}
	t.Run("failure_cleared_by_a_pass", func(t *testing.T) {
		h := seeded(t, func(st *probeState, now uint64) {
			st.Failure = &probeFailure{Code: ErrProbeInconclusive.Error(), Key: strings.Repeat("0", 64), At: now - 7200, Count: 1}
		})
		if st := h.probeStateNow(); st.Failure != nil {
			t.Fatalf("failure %+v after a pass", st.Failure)
		}
	})
	t.Run("alarm_cleared_by_a_pass", func(t *testing.T) {
		h := seeded(t, func(st *probeState, _ uint64) { st.Alarm = ErrProbeKRLNotEnforced.Error() })
		if st := h.probeStateNow(); st.Alarm != "" {
			t.Fatalf("alarm %q after a pass", st.Alarm)
		}
	})
	t.Run("reservation_before_send", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		n, q := len(h.probeStateNow().Negatives), len(h.probeQueries())
		h.cfg.Fault = func(p string) error {
			if p == "probe-send" {
				return errCrash
			}
			return nil
		}
		h.publishDir(h.spec("role:a", "role:b"))
		if _, err := h.apply(); !errors.Is(err, errCrash) {
			t.Fatalf("apply: %v, want the crash", err)
		}
		if got := len(h.probeStateNow().Negatives); got != n+1 || len(h.probeQueries()) != q {
			t.Fatalf("negatives %d (were %d), %d queries", got, n, len(h.probeQueries())-q)
		}
	})
	t.Run("probe_sleeps_for_spacing", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.readyFor(time.Hour)
		h.clock.advance(10 * time.Minute) // no widening wait: the probes run at once
		now := lockedEngine(h).probeNow()
		st := newProbeState()
		st.LastPair = now - 30
		h.setProbeState(st)
		var slept []time.Duration
		h.clock.onSleep = func(d time.Duration) { slept = append(slept, d) }
		h.publishDir(h.spec("role:a", "role:b"))
		r := h.mustApply()
		h.clock.onSleep = nil
		if r.ProbePositive != probePass || !slices.Contains(slept, 30*time.Second) || h.probeStateNow().LastPair != now+30 {
			t.Fatalf("probes %q, slept %v, last pair %d (now %d)", r.ProbePositive, slept, h.probeStateNow().LastPair, now)
		}
	})
	t.Run("probe_source_is_not_the_listener_source", func(t *testing.T) {
		h := gateHost(t, "role:a")
		h.ready()
		h.publishDir(h.spec("role:a", "role:b"))
		h.mustApply()
		qs := h.probeQueries()
		if len(qs) < 4 {
			t.Fatalf("%d queries", len(qs))
		}
		for _, q := range qs {
			if q.Source != ProbeSource {
				t.Fatalf("a query from %s", q.Source)
			}
		}
	})
}

// genNow is the generation current names.
func (h *testHost) genNow() *Generation {
	h.t.Helper()
	g, _, err := lockedEngine(h).readCurrent()
	if err != nil || g == nil {
		h.t.Fatalf("current: %v", err)
	}
	return g
}

// FuzzParsePasswdLine (03-10b): parsePasswdLine never panics, and a line it
// accepts has seven fields that join back to the line.
func FuzzParsePasswdLine(f *testing.F) {
	for _, s := range []string{"keyroster-probe:x:990:990::/nonexistent:/usr/sbin/nologin", "root:x:0:0:root:/root:/bin/bash", "a:b", "", "x:x:-1:0::/:/bin/sh", "::::::"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		fields, ok := parsePasswdLine(line)
		if !ok {
			return
		}
		if len(fields) != 7 || strings.Join(fields, ":") != line {
			t.Fatalf("accepted %q as %q", line, fields)
		}
	})
}
