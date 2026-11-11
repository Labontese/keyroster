package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestRunbookGoToolchain: the install runbooks build with go.mod's
// toolchain line and check it in the binaries. An older toolchain builds
// fine (the go directive is lower) but links a standard library whose
// fixed vulnerabilities the server and client reach, and nothing else
// would notice.
func TestRunbookGoToolchain(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^toolchain (go1\.[0-9]+\.[0-9]+)\s*$`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("go.mod has no toolchain line")
	}
	toolchain := string(m[1])
	goVersion := regexp.MustCompile(`go1\.[0-9]+\.[0-9]+`)
	for _, name := range []string{"signer-install.md", "server-install.md"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", name)) //nolint:gosec // G304: a constant runbook name under docs/runbooks
		if err != nil {
			t.Fatal(err)
		}
		doc := string(data)
		for _, v := range goVersion.FindAllString(doc, -1) {
			if v != toolchain {
				t.Errorf("%s names %s, but go.mod's toolchain line is %s", name, v, toolchain)
			}
		}
		if !strings.Contains(doc, `export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)`) {
			t.Errorf("%s does not set GOTOOLCHAIN from go.mod's toolchain line before building", name)
		}
		if !regexp.MustCompile(`(?m)^go version keyroster`).MatchString(doc) {
			t.Errorf("%s does not check the built binaries with go version", name)
		}
	}
}

// TestServerInstallTailscalePrerequisites: the "With Tailscale" path of
// server-install.md step 3 runs `tailscale cert`, which fails on a host
// without tailscaled joined to a tailnet with MagicDNS and HTTPS
// Certificates enabled, and the RP ID is the MagicDNS name. No step of the
// runbook sets these up, so "What you need" must list them.
func TestServerInstallTailscalePrerequisites(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", "server-install.md"))
	if err != nil {
		t.Fatal(err)
	}
	need := ""
	for _, sec := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n## ") {
		if strings.HasPrefix(sec, "What you need") {
			need = strings.Join(strings.Fields(sec), " ")
		}
	}
	if need == "" {
		t.Fatal(`server-install.md has no section "## What you need"`)
	}
	for _, want := range []string{"**With Tailscale**", "`tailscaled`", "joined to the tailnet", "MagicDNS", "HTTPS Certificates"} {
		if !strings.Contains(need, want) {
			t.Errorf("server-install.md \"What you need\" does not contain %q", want)
		}
	}
}

// hostSetupSection returns the text of the host-setup.md section whose
// heading starts with "## "+prefix, up to the next "## " heading.
func hostSetupSection(t *testing.T, prefix string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", "host-setup.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n## ") {
		if strings.HasPrefix(sec, prefix) {
			return sec
		}
	}
	t.Fatalf("host-setup.md has no section %q", "## "+prefix)
	return ""
}

// TestHostSetupSignerCheck: host principals and host ca-key render what
// the server serves, and a compromised server can serve any older
// version the admins or roots once signed. keyroster directory show reads
// the same server, so the runbook must send the admin to the signer's log
// (directory installs, trust bundle) before a rendered file is trusted.
func TestHostSetupSignerCheck(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"1.", "trust bundle v"},
		{"1.", "enroll-user.md#confirm-on-the-signer-host"},
		{"5.", "directory installs"},
		{"5.", "trust bundle v"},
		{"5.", "enroll-user.md#confirm-on-the-signer-host"},
		{"5.", "older"},
		{"5.", "Phase 4"},
	} {
		if !strings.Contains(hostSetupSection(t, tc.section), tc.want) {
			t.Errorf("host-setup.md step %s does not contain %q", tc.section, tc.want)
		}
	}
	for _, prefix := range []string{"3.", "5."} {
		for _, para := range strings.Split(hostSetupSection(t, prefix), "\n\n") {
			if strings.Contains(para, "directory show") && !strings.Contains(para, "server's word") {
				t.Errorf("host-setup.md step %s offers directory show without saying it is the server's word:\n%s", prefix, para)
			}
		}
	}
}

// TestHostSetupEffectiveSshdConfig: sshd keeps the first value it reads
// for TrustedUserCAKeys and AuthorizedPrincipalsFile, drop-ins are often
// included first, and lines after a Match block apply only to it. sshd -t
// checks syntax only, so the runbook must not say "add to sshd_config"
// and must check the effective values with sshd -T.
func TestHostSetupEffectiveSshdConfig(t *testing.T) {
	appendTo := regexp.MustCompile("(?i)add\\s+to\\s+`/etc/ssh/sshd_config`")
	for _, prefix := range []string{"1.", "2."} {
		if appendTo.MatchString(hostSetupSection(t, prefix)) {
			t.Errorf("host-setup.md step %s still says to add the setting to sshd_config", prefix)
		}
	}
	for _, tc := range []struct{ section, want string }{
		{"1.", "Where the sshd settings go"},
		{"2.", "Where the sshd settings go"},
		{"Where the sshd settings go", "sshd_config.d"},
		{"Where the sshd settings go", "Include"},
		{"Where the sshd settings go", "Match"},
		{"Where the sshd settings go", "first value"},
		{"4.", "sudo sshd -T -C user=<account>,host=<host>,addr=<address>"},
		{"4.", "trustedusercakeys /etc/ssh/keyroster_user_ca.pub"},
		{"4.", "authorizedprincipalsfile /etc/ssh/principals/%u"},
		{"5.", "sshd -T"},
	} {
		if !strings.Contains(hostSetupSection(t, tc.section), tc.want) {
			t.Errorf("host-setup.md section %q does not contain %q", tc.section, tc.want)
		}
	}
}

// signingSection is one successor-signing (or genesis-signing) runbook
// section whose confirmation list must carry the policy block, the warning,
// the roots and the pop line (03-14b, F04, F14). Later plans add their own
// successor-signing sections to successorSigningSections.
type signingSection struct {
	id      string
	file    string          // under docs/runbooks
	section string          // the "## " section prefix
	within  *signingSection // the window lies inside this entry's window
	start   string          // optional start marker: a trimmed line's prefix
	end     string          // optional fixed end marker, exactly once
	endNext func(trimmed string) bool
	want    []string // required, in whitespace-normalised form
}

var numberedStep = regexp.MustCompile(`^[0-9]+\. \*\*`)

// successorSigningSections lists every runbook section with a confirmation
// list for a successor or genesis signing (03-14b). 03-12, 03-13, 03-14 and
// 03-15 extend it with the sections they add.
func successorSigningSections() []*signingSection {
	step3 := &signingSection{id: "change_the_policy_step_3", file: "root-ceremony.md", section: "Change the policy",
		start: "3. **Sign the successor bundle", end: "4. **Verify against the paper",
		want: []string{"Policy in force:", "Successor policy:", "carried over", "CHANGED", "WARNING: this successor changes",
			"Agreed policy change", "Previous root keys", "Root keys (threshold",
			"without `--confirm`", "policy version", "bundle you pinned with", "do not apply there",
			"SHA256 fingerprint", "the record holds exactly the values",
			"`admin_quorum`, `admins`, `ca_profiles` and `timelock_seconds`", "with no WARNING"}}
	return []*signingSection{
		{id: "genesis_step_4", file: "root-ceremony.md", section: "4. Sign with root A",
			want: []string{"pop: none", "pop.hosts", "without `--confirm`"}},
		{id: "rotation_step_3", file: "root-ceremony.md", section: "Rotate the roots",
			start: "3. **Build the successor", end: "4. **Sign with a current root",
			want: []string{"Successor policy: unchanged, every field carried over", "without `--confirm`", "do not apply there"}},
		{id: "rotation_step_4", file: "root-ceremony.md", section: "Rotate the roots",
			start: "4. **Sign with a current root", end: "5. **Verify against the paper",
			want: []string{"checks of step 3", "policy block"}},
		{id: "change_the_policy_paragraph", file: "root-ceremony.md", section: "Change the policy",
			start: "`keyroster root successor-policy` changes only", end: "> **`rp_id` is a one-way setting.**",
			want: []string{"`admin_quorum`, `admins`, `ca_profiles` or `timelock_seconds`", "a cleared `pop.machines`", "with no WARNING"}},
		{id: "change_the_policy_you_need", file: "root-ceremony.md", section: "Change the policy",
			start: "You need everything from", end: "0. **Prepare.**",
			want: []string{"Agreed policy change", "never from the proposer"}},
		step3,
		{id: "change_the_policy_pop_item", file: "root-ceremony.md", section: "Change the policy", within: step3,
			start:   "- **The PoP switches.**",
			endNext: func(l string) bool { return strings.HasPrefix(l, "- **") || numberedStep.MatchString(l) },
			want:    []string{"pop: none (", "pop hosts=", "one-way", "as mandatory as the rp_id line"}},
		{id: "change_the_policy_intro", file: "root-ceremony.md", section: "Change the policy", within: step3,
			start:   "Before you confirm",
			endNext: func(l string) bool { return strings.HasPrefix(l, "- **") },
			want:    []string{"including one who did not see step 2's output", "same `--out-dir`"}},
		{id: "hardware_variant", file: "root-ceremony.md", section: "Hardware-root variant",
			want: []string{"before each touch"}},
		{id: "transcript_template", file: "ceremony-transcript-template.md", section: "Ceremony",
			want: []string{"root rotation / policy change / re-sign", "Agreed policy change (the changed field names", "someone other than its proposer",
				"checks every value"}},
		{id: "host_setup_pop", file: "host-setup.md", section: "Registering a host in the directory",
			want: []string{"successor_pop", "CHANGED"}},
		{id: "machine_identities_pop", file: "machine-identities.md", section: "Renewal needs pop.machines",
			want: []string{"machines=true", "CHANGED"}},
	}
}

// sectionWindow returns e's window in text: its "## " section, or its
// parent entry's window, narrowed from the start marker's line up to, not
// including, the end marker's line. A marker matches as the prefix of a
// line with its leading whitespace trimmed. It refuses a section prefix
// that matches other than one section, a start or fixed end marker that
// occurs other than exactly once in the parent window, an end before its
// start, and a missing next-line end.
func sectionWindow(text string, e *signingSection) (string, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var win []string
	if e.within != nil {
		w, err := sectionWindow(text, e.within)
		if err != nil {
			return "", fmt.Errorf("parent %s: %w", e.within.id, err)
		}
		win = strings.Split(w, "\n")
	} else {
		n := 0
		for i, l := range lines {
			if !strings.HasPrefix(l, "## ") || !strings.HasPrefix(l[3:], e.section) {
				continue
			}
			n++
			j := i + 1
			for j < len(lines) && !strings.HasPrefix(lines[j], "## ") {
				j++
			}
			win = lines[i:j]
		}
		if n != 1 {
			return "", fmt.Errorf("section %q matches %d sections, want 1", "## "+e.section, n)
		}
	}
	find := func(marker string) (int, error) {
		at, n := 0, 0
		for i, l := range win {
			if strings.HasPrefix(strings.TrimLeft(l, " \t"), marker) {
				at, n = i, n+1
			}
		}
		if n != 1 {
			return 0, fmt.Errorf("marker %q occurs %d times, want 1", marker, n)
		}
		return at, nil
	}
	from, to := 0, len(win)
	if e.start != "" {
		at, err := find(e.start)
		if err != nil {
			return "", err
		}
		from = at
	}
	switch {
	case e.end != "":
		at, err := find(e.end)
		if err != nil {
			return "", err
		}
		if at < from {
			return "", fmt.Errorf("end marker %q comes before start marker %q", e.end, e.start)
		}
		to = at
	case e.endNext != nil:
		to = -1
		for i := from + 1; i < len(win); i++ {
			if e.endNext(strings.TrimLeft(win[i], " \t")) {
				to = i
				break
			}
		}
		if to < 0 {
			return "", fmt.Errorf("no end line after start marker %q", e.start)
		}
	}
	return strings.Join(win[from:to], "\n"), nil
}

func normalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// policyCheckPrefixes are the output prefixes the runbooks quote for the
// policy checks (03-14b).
var policyCheckPrefixes = []string{
	"Policy in force: v", "Successor policy: unchanged, every field carried over", "WARNING: this successor changes",
	"Previous root keys (threshold", "Root keys (threshold", "pop hosts=", "pop: none (", "webauthn rp_id ", "pop.hosts is one-way",
}

// TestRootCeremonyPolicyChecks (03-14b, F04, F14): every successor-signing
// and genesis-signing runbook section makes the policy block, the warning
// line, the roots and the pop line mandatory checks, names where the agreed
// change comes from, and says that --confirm skips the read point. Its
// output_prefixes subtest proves that each prefix the runbooks quote for
// these checks is one the tool prints (it occurs in a ceremony golden); it
// does not prove every backticked span.
func TestRootCeremonyPolicyChecks(t *testing.T) {
	var windows []string
	for _, e := range successorSigningSections() {
		data := readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", e.file))
		w, err := sectionWindow(string(data), e)
		if err == nil {
			windows = append(windows, normalizeSpace(w))
		}
		t.Run(e.id, func(t *testing.T) {
			if err != nil {
				t.Fatalf("%s (%s): %v", e.id, e.file, err)
			}
			got := normalizeSpace(w)
			for _, want := range e.want {
				if !strings.Contains(got, want) {
					t.Errorf("%s (%s, %q): missing %q", e.id, e.file, "## "+e.section, want)
				}
			}
		})
	}
	t.Run("output_prefixes", func(t *testing.T) {
		goldens, err := filepath.Glob(filepath.Join("testdata", "ceremony", "*.golden"))
		if err != nil || len(goldens) == 0 {
			t.Fatalf("no ceremony goldens: %v", err)
		}
		var out []string
		for _, g := range goldens {
			out = append(out, normalizeSpace(string(readTestFile(t, g))))
		}
		for _, p := range policyCheckPrefixes {
			if !slices.ContainsFunc(windows, func(w string) bool { return strings.Contains(w, p) }) {
				t.Errorf("no successor-signing runbook section quotes %q", p)
			}
			if !slices.ContainsFunc(out, func(o string) bool { return strings.Contains(o, p) }) {
				t.Errorf("no ceremony golden prints %q", p)
			}
		}
	})
}

// TestSectionWindowRefusals (03-14b): sectionWindow refuses a duplicated
// marker, a missing marker and an end before its start.
func TestSectionWindowRefusals(t *testing.T) {
	text := "# T\n\n## Steps\n\n1. **One**\n   a\n2. **Two**\n   b\n2. **Two again**\n\n## Other\n"
	for _, c := range []struct {
		name string
		e    *signingSection
	}{
		{"duplicated_marker", &signingSection{id: "dup", section: "Steps", start: "1. **One", end: "2. **Two"}},
		{"missing_marker", &signingSection{id: "missing", section: "Steps", start: "3. **Three"}},
		{"end_before_start", &signingSection{id: "order", section: "Steps", start: "2. **Two again", end: "1. **One"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if w, err := sectionWindow(text, c.e); err == nil {
				t.Errorf("sectionWindow accepted the fixture, window %q", w)
			}
		})
	}
}
