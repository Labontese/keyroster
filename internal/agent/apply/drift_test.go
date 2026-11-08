//go:build linux

package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/paths"
)

func (h *testHost) check() (*DriftReport, error) {
	h.t.Helper()
	return Check(context.Background(), h.cfg, h.l)
}

// TestDrift is AGENT-05's check: effective settings per account and the
// generation's files against its record, without fixing anything.
func TestDrift(t *testing.T) {
	t.Run("clean_after_install", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		r, err := h.check()
		if err != nil || r.Drift() || r.Generation != h.current() || !r.LoginGraceObserved {
			t.Fatalf("check after install: %+v, %v", r, err)
		}
	})
	t.Run("dropin_edited_or_missing_is_drift", func(t *testing.T) {
		t.Parallel()
		// PR #68 review D-R2: sshd -T still reports the agent's three paths,
		// but the file is not the one the agent wrote.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		appendFile(t, h.l.DropIn(), "# managed by ansible\n")
		r, err := h.check()
		if err != nil || len(r.Files) != 1 || r.Files[0].File != h.l.DropIn() || r.Files[0].GotSHA256 == "" || len(r.Settings) != 0 {
			t.Fatalf("an edited drop-in: %+v, %v", r, err)
		}
		if err := os.Remove(h.l.DropIn()); err != nil {
			t.Fatal(err)
		}
		if r, err := h.check(); err != nil || !r.Drift() || !slices.ContainsFunc(r.Files, func(f FileDrift) bool { return f.File == h.l.DropIn() && f.GotSHA256 == "" }) {
			t.Fatalf("a missing drop-in: %+v, %v", r, err)
		}
	})
	t.Run("match_block_override_is_drift", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.run.match = map[string]map[string]string{"deploy": {"authorizedprincipalsfile": "none"}}
		r, err := h.check()
		if err != nil || !r.Drift() || len(r.Settings) != 1 || r.Settings[0] != (SettingDrift{Keyword: "authorizedprincipalsfile", Account: "deploy", Want: filepath.Join(h.l.Current(), PrincipalsDir, "%u"), Got: "none"}) {
			t.Fatalf("a Match override: %+v, %v", r, err)
		}
	})
	t.Run("earlier_file_is_drift", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.run.before = map[string]string{"trustedusercakeys": "/etc/ssh/other.pub"}
		r, err := h.check()
		if err != nil || len(r.Settings) != 2 { // global and for deploy
			t.Fatalf("an earlier TrustedUserCAKeys: %+v, %v", r, err)
		}
	})
	t.Run("changed_file_is_drift_and_not_fixed", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		p := filepath.Join(h.l.Gen(h.current()), PrincipalsDir, "deploy")
		if err := os.WriteFile(p, []byte("role:hand-edited\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		r, err := h.check()
		if err != nil || len(r.Files) != 1 || r.Files[0].File != p || r.Files[0].GotSHA256 == r.Files[0].WantSHA256 {
			t.Fatalf("a changed principals file: %+v, %v", r, err)
		}
		if readFile(t, p) != "role:hand-edited\n" {
			t.Fatal("check rewrote the file")
		}
	})
	t.Run("missing_and_added_files_are_drift", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		gen := h.l.Gen(h.current())
		if err := os.Remove(filepath.Join(gen, KRLFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(gen, PrincipalsDir, "root"), []byte("role:ops\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		r, err := h.check()
		if err != nil || len(r.Files) != 2 {
			t.Fatalf("a removed KRL and an added principals file: %+v, %v", r, err)
		}
	})
	t.Run("excluded_account_reported", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.run.extra = "allowusers alice\n"
		r, err := h.check()
		if err != nil || r.Drift() || len(r.Excluded) != 1 || r.Excluded[0].Account != "deploy" {
			t.Fatalf("AllowUsers alice: %+v, %v", r, err)
		}
	})
	t.Run("login_grace_unbounded_is_drift", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.run.grace = "0"
		r, err := h.check()
		if err != nil || len(r.Settings) != 1 || r.Settings[0].Keyword != "logingracetime" {
			t.Fatalf("LoginGraceTime 0: %+v, %v", r, err)
		}
	})
	t.Run("not_installed_is_a_tool_error", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		if _, err := h.check(); !errors.Is(err, ErrNotInstalled) {
			t.Fatalf("check before install: %v", err)
		}
	})
	t.Run("check_reads_current_once", func(t *testing.T) {
		t.Parallel()
		// An apply swaps current while the check runs (nemotron 03-08,
		// REVIEWS L659@e7b3b32): between the readlink and the hashing,
		// current moves to another generation. The check reports the
		// generation it resolved first, hashed by that resolved path, with
		// no drift.
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		first := h.current()
		h.publishDir(h.spec("role:ops")) // a narrowing change: swapped at once
		h.mustApply()
		second := h.current()
		if second == first {
			t.Fatal("no second generation")
		}
		swapped := false
		h.cfg.Fault = func(p string) error {
			if p == "check-resolved" && !swapped {
				swapped = true
				tmp := h.l.Current() + ".test"
				if err := os.Symlink(paths.GenLink(first), tmp); err != nil {
					return err
				}
				return os.Rename(tmp, h.l.Current())
			}
			return nil
		}
		r, err := h.check()
		if err != nil || !swapped || r.Generation != second || len(r.Files) != 0 {
			t.Fatalf("a swap during the check: %+v, %v (swapped %t)", r, err, swapped)
		}
	})
}

// TestDriftProbeAccount (03-10c, T-03-387): check reports the probe
// account in its own report-only list; a trust setting overridden for the
// probe account stays drift.
func TestDriftProbeAccount(t *testing.T) {
	probes := func(r *DriftReport, reason string) int {
		n := 0
		for _, f := range r.Probe {
			if f.Code == CodeProbeAccount && f.Account == probeAcct && strings.HasPrefix(f.Message, reason+":") && !f.Refusal {
				n++
			}
		}
		return n
	}
	t.Run("probe_spec_address", func(t *testing.T) {
		t.Parallel()
		h := gateHost(t, "role:a")
		r, err := h.check()
		if err != nil || r.Drift() || len(r.Probe) != 0 {
			t.Fatalf("a clean host: %+v, %v", r, err)
		}
		if n := h.run.dumps[probeSpecKey(h, ProbeSource, "127.0.0.1")]; n != 1 {
			t.Fatalf("sshd -T -C runs %v, want one from the probe source", h.run.dumps)
		}
	})
	t.Run("finding_is_not_drift", func(t *testing.T) {
		t.Parallel()
		h := gateHost(t, "role:a")
		h.setShadow("$6$salt$abcdef")
		r, err := h.check()
		if err != nil || r.Drift() || probes(r, passwordSet) != 1 {
			t.Fatalf("a probe account with a password: %+v, %v", r, err)
		}
	})
	t.Run("generic_excluded_not_duplicated", func(t *testing.T) {
		t.Parallel()
		h := gateHost(t, "role:a")
		if _, ok := h.genNow().Files[PrincipalsDir+"/"+probeAcct]; !ok {
			t.Fatal("current holds no probe principals file")
		}
		h.setFor("denyusers " + probeAcct + "\n")
		r, err := h.check()
		if err != nil || r.Drift() || probes(r, accountExcluded) != 1 {
			t.Fatalf("an excluded probe account: %+v, %v", r, err)
		}
		if slices.ContainsFunc(r.Excluded, func(f Finding) bool { return f.Account == probeAcct }) {
			t.Fatalf("the probe account is in Excluded too: %+v", r.Excluded)
		}
	})
	t.Run("probe_trust_override_still_drifts", func(t *testing.T) {
		t.Parallel()
		h := gateHost(t, "role:a")
		h.run.match = map[string]map[string]string{probeAcct: {"authorizedprincipalsfile": "/etc/ssh/other/%u"}}
		r, err := h.check()
		if err != nil || !r.Drift() || !slices.ContainsFunc(r.Settings, func(s SettingDrift) bool {
			return s.Account == probeAcct && s.Keyword == "authorizedprincipalsfile"
		}) {
			t.Fatalf("a Match block overriding the probe account's principals file: %+v, %v", r, err)
		}
		if probes(r, sshdOverride) != 1 {
			t.Fatalf("probe findings %+v", r.Probe)
		}
	})
	t.Run("mapped_probe_account_reported", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.gateOn()
		s := h.spec("role:a")
		s.accounts = []string{"deploy", probeAcct}
		h.publishDir(s)
		h.mustApply()
		r, err := h.check()
		if err != nil || r.Drift() || probes(r, "account_is_managed") != 1 {
			t.Fatalf("a mapped probe account: %+v, %v", r, err)
		}
	})
	t.Run("hash_never_in_report", func(t *testing.T) {
		t.Parallel()
		// The hash in shadow, then in passwd field 2.
		const marker = "$6$Zq9MarkerSalt$Zq9MarkerHashValue"
		h := gateHost(t, "role:a")
		for _, inPasswd := range []bool{false, true} {
			h.setShadow(marker)
			if inPasswd {
				h.setShadow("*")
				h.writePasswd(probeLine(marker, "/usr/sbin/nologin") + "\n")
			}
			r, err := h.check()
			if err != nil || probes(r, passwordSet) != 1 {
				t.Fatalf("%+v, %v", r, err)
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(b, []byte("Zq9Marker")) {
				t.Fatalf("the report carries the hash (in passwd: %t): %s", inPasswd, b)
			}
		}
	})
}
