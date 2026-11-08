package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// parSelf is this file, which cited_tests_exist does not read.
const parSelf = "probeaccount_runbook_test.go"

// parFamilies are the four families of test/distro/probe-account.sh, each
// a labelled command block of the runbook section.
var parFamilies = []string{"debian", "rhel", "alpine", "arch"}

// parReasons are the closed hold reasons of the probe gate (Contracts
// frozen by 03-10b and 03-10c), in the gate's order;
// TestProbeHoldReasonsDocumented checks the agent's own list against the
// same runbook.
var parReasons = []string{
	"account_missing", "account_unparsable", "account_uid_zero", "shell_missing", "shell_not_nologin",
	"password_empty", "password_set", "sshd_override", "account_excluded",
	"account_is_managed", "cert_missing", "issue_unanswered", "issue_refused", "positive_in_krl", "negative_not_in_krl", "ca_mismatch",
	"failure_backoff", "budget",
}

// parArm returns the lines of the script's arm for family: the lines
// between the label line `<family>)` and `;;`, their leading tab removed.
func parArm(t *testing.T, script, family string) []string {
	t.Helper()
	var arm []string
	in := false
	for _, l := range strings.Split(script, "\n") {
		switch {
		case !in && l == family+")":
			in = true
		case in && strings.TrimSpace(l) == ";;":
			return arm
		case in:
			arm = append(arm, strings.TrimPrefix(l, "\t"))
		}
	}
	t.Fatalf("probe-account.sh has no complete arm %s)", family)
	return nil
}

// parBlock returns the lines of the fenced block that follows the line
// `probe-account <family>` in sec.
func parBlock(t *testing.T, sec, family string) []string {
	t.Helper()
	lines := strings.Split(sec, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "probe-account "+family {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if !strings.HasPrefix(lines[j], "```") {
				continue
			}
			for k := j + 1; k < len(lines); k++ {
				if strings.HasPrefix(lines[k], "```") {
					return lines[j+1 : k]
				}
			}
			break
		}
	}
	t.Fatalf("the section has no fenced block after the line probe-account %s", family)
	return nil
}

// TestProbeAccountRunbook (03-10c): host-setup.md's section 'The probe
// account' says what to create and why, every hold reason with its fix,
// the upgrade order, the unit override, the machine-cap recommendation
// and the reservation; its account commands are the ones CI runs
// (test/distro/probe-account.sh), and it labels what CI exercises.
func TestProbeAccountRunbook(t *testing.T) {
	doc := htrbDoc(t, "host-setup.md")
	sec := htrbSection(doc, "## The probe account")
	if sec == "" {
		t.Fatal("host-setup.md has no section ## The probe account")
	}
	flat := htrbFlat(sec)
	t.Run("section_between_neighbours", func(t *testing.T) {
		host, probe, manual := strings.Index(doc, "\n## Host certificates\n"), strings.Index(doc, "\n## The probe account\n"), strings.Index(doc, "\n## Manual recovery\n")
		if host < 0 || probe < 0 || manual < 0 || host >= probe || probe >= manual {
			t.Fatalf("headings at %d, %d, %d: want Host certificates, then The probe account, then Manual recovery", host, probe, manual)
		}
		if end := strings.Index(doc, sec) + len(sec); !strings.HasPrefix(doc[end:], "\n## Manual recovery\n") {
			t.Fatalf("the section does not end where ## Manual recovery begins: %q", doc[end:min(end+60, len(doc))])
		}
	})
	t.Run("commands_match_ci", func(t *testing.T) {
		b, err := os.ReadFile(filepath.Join("..", "..", "test", "distro", "probe-account.sh"))
		if err != nil {
			t.Fatal(err)
		}
		for _, fam := range parFamilies {
			arm, block := parArm(t, string(b), fam), parBlock(t, sec, fam)
			if strings.Join(arm, "\n") != strings.Join(block, "\n") {
				t.Errorf("the runbook's block probe-account %s:\n%s\nis not the script's arm %s):\n%s", fam, strings.Join(block, "\n"), fam, strings.Join(arm, "\n"))
			}
			if len(block) == 0 || block[0] != "name=${KEYROSTER_PROBE_NAME:-keyroster-probe}" {
				t.Errorf("the block probe-account %s does not begin with the name line", fam)
			}
		}
	})
	t.Run("every_reason_documented", func(t *testing.T) {
		for _, r := range parReasons {
			item := htrbBetween(sec, "- `probe_held:"+r+"`", "\n- ")
			if i := strings.Index(item, "\n\n"); i >= 0 {
				item = item[:i] // the list's last item ends at the blank line
			}
			if item == "" {
				t.Errorf("no item - `probe_held:%s`", r)
				continue
			}
			if !strings.Contains(item, "Fix:") {
				t.Errorf("the item probe_held:%s has no Fix: sentence", r)
			}
		}
	})
	t.Run("shadow_star_recommended", func(t *testing.T) {
		htrbWant(t, "the shadow field", sec, "exactly `*`", "`!`", "UsePAM no", "`TestDistroProbeAccountBang`")
	})
	t.Run("nss_ldap_account_missing", func(t *testing.T) {
		htrbWant(t, "the account sources", sec, "`<root>/etc/passwd`", "`<root>/etc/shadow`", "NSS", "LDAP", "`account_missing`")
	})
	t.Run("upgrade_order", func(t *testing.T) {
		htrbWant(t, "the upgrade order", sec, "the signer first, then the server, then the agents", "`probe_detail`")
	})
	t.Run("unit_override", func(t *testing.T) {
		htrbWant(t, "the other account name", sec, "systemctl edit keyroster-agent", "--probe-account", "`keyroster-agent preflight`", "`keyroster-agent check`")
		if !regexp.MustCompile(`(?m)^ExecStart=$`).MatchString(sec) {
			t.Error("the unit override has no empty ExecStart= line")
		}
	})
	t.Run("machine_cap_recommendation", func(t *testing.T) {
		htrbWant(t, "the machine cap", sec, "at least 6 hours", "60 KRL versions an hour")
	})
	t.Run("reservation_and_krl_growth", func(t *testing.T) {
		htrbWant(t, "the reservation", sec, "`keyroster-probe:`", "`probe.`", "one negative probe serial")
	})
	t.Run("audit_line", func(t *testing.T) {
		htrbWant(t, "the audit line", sec, "keyroster audit verify", "probe certificates: N, negative probes no published KRL lists yet: M", "pending_negative_probes")
	})
	t.Run("p4_wait", func(t *testing.T) {
		htrbWant(t, "the wait after a state loss", sec, "up to about two hours", "P4")
	})
	t.Run("ci_labels", func(t *testing.T) {
		htrbWant(t, "the CI labels", sec, "Run in CI", "`TestDistroProbe`", "`TestDistroProbeFacts`", "`TestAgentSystemdSmoke`", "UNVERIFIED", "the e2e test build")
		if tag := "keyroster_" + "e2e"; strings.Contains(sec, tag) {
			t.Error("the section names the test-build tag")
		}
	})
	t.Run("no_address_but_loopback", func(t *testing.T) {
		for _, a := range regexp.MustCompile(`([0-9]{1,3}\.){3}[0-9]{1,3}`).FindAllString(flat, -1) {
			if !strings.HasPrefix(a, "127.") {
				t.Errorf("the section names the address %s", a)
			}
		}
	})
	t.Run("cited_tests_exist", func(t *testing.T) {
		self, err := filepath.Abs(parSelf)
		if err != nil {
			t.Fatal(err)
		}
		var src strings.Builder
		err = filepath.WalkDir(filepath.Join("..", ".."), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == ".git" || d.Name() == ".planning") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(p, "_test.go") {
				if abs, err := filepath.Abs(p); err == nil && abs == self {
					return nil
				}
				data, err := os.ReadFile(p) //nolint:gosec // G304: a test file of this repository
				if err != nil {
					return err
				}
				src.Write(data)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		all := src.String()
		if strings.Contains(all, "func TestProbeAccountRunbook(") {
			t.Fatal("the runbook test itself was read: a cited subtest name it quotes would satisfy the check")
		}
		cites := regexp.MustCompile("`(Test[A-Za-z0-9_]+)((?:/[a-z0-9_]+)*)`").FindAllStringSubmatch(sec, -1)
		if len(cites) == 0 {
			t.Fatal("the section cites no test")
		}
		for _, m := range cites {
			if !strings.Contains(all, "func "+m[1]+"(") {
				t.Errorf("the section cites %s, which no _test.go file defines", m[1])
			}
			for _, sub := range strings.Split(strings.TrimPrefix(m[2], "/"), "/") {
				if sub != "" && !strings.Contains(all, `"`+sub+`"`) {
					t.Errorf("the section cites %s%s, but no test names a subtest %q", m[1], m[2], sub)
				}
			}
		}
	})
}
