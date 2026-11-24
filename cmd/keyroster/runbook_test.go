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

// TestHostSetupHandManagedCAKeyRule (03-12d, T-03-76): step 1 of
// host-setup.md tells the operator of a host that keyroster-agent does not
// manage to keep its keyroster_user_ca.pub equal to the output of
// keyroster host ca-key, says when to replace it, and that such a host is
// outside the live count of host status.
func TestHostSetupHandManagedCAKeyRule(t *testing.T) {
	flat := htrbFlat(hostSetupSection(t, "1."))
	for _, want := range []string{
		"must always equal the output of `keyroster host ca-key`",
		"after an abort",
		"when a draining key ends",
		"not in the live count",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("host-setup.md step 1 does not contain %q", want)
		}
	}
}

// TestHostSetupLiveCountRemedy (03-12d, T-03-447): the live count follows
// the agent's own next check, keyroster-agent check writes no status (so
// it never changes the count), and a stuck host waits for the manual
// recovery.
func TestHostSetupLiveCountRemedy(t *testing.T) {
	flat := htrbFlat(hostSetupSection(t, "Running the agent"))
	for _, want := range []string{
		"not counted until the agent's own next clean check",
		"writes no status and so does not change the count",
		"A stuck host is not counted until root has recovered it ([Manual recovery](#manual-recovery))",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("host-setup.md Running the agent does not contain %q", want)
		}
	}
	if strings.Contains(flat, "as root on the host runs one") {
		t.Error("host-setup.md Running the agent still says keyroster-agent check moves the count")
	}
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
			"`admin_quorum`, `admins`, `ca_profiles` and `timelock_seconds`", "with no WARNING",
			"CA entries: unchanged", "Root set:"}}
	// The CA rotation ceremonies (03-12b): ceremony 1 and the abort carry
	// the same checks as any successor, plus the CA-change line they
	// expect and the root-set line.
	caChecks := func(caLine string, extra ...string) []string {
		return append([]string{"Policy in force:", "Successor policy: unchanged, every field carried over", "WARNING: this successor changes",
			"Previous root keys", "Root keys (threshold", "pop hosts=", "pop: none (", "webauthn rp_id ", caLine, "Root set: unchanged",
			"without `--confirm`", "do not apply there"}, extra...)
	}
	return []*signingSection{
		{id: "genesis_step_4", file: "root-ceremony.md", section: "4. Sign with root A",
			want: []string{"pop: none", "pop.hosts", "without `--confirm`"}},
		{id: "rotation_step_3", file: "root-ceremony.md", section: "Rotate the roots",
			start: "3. **Build the successor", end: "4. **Sign with a current root",
			want: []string{"Successor policy: unchanged, every field carried over", "without `--confirm`", "do not apply there",
				"CA entries: unchanged", "Root set:"}},
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
				"checks every value", "next CA fingerprint as read from the signer console by",
				// The switch (03-12e2).
				"CA switch: role, new active fingerprint, draining fingerprint, trusted until and install by as read by", "doctor's pre-switch line"}},
		{id: "ca_next_sign", file: "ca-rotation.md", section: "Ceremony 1",
			want: caChecks("none -> next", "fingerprint as read from the signer console")},
		{id: "ca_abort_sign", file: "ca-rotation.md", section: "Abort",
			want: caChecks("next -> retired")},
		// Ceremony 2, the switch (03-12e2): the two CA-change lines, the
		// advice and what it is, and the comparison with doctor's
		// pre-switch line.
		{id: "ca_switch_sign", file: "ca-rotation.md", section: "Ceremony 2",
			want: caChecks("active -> draining, trusted until", "install by", "(advice)", "is advice and never a refusal", "next -> active",
				"at or after the earliest", "stop issuing")},
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
	"Root set: ", "CA entries: unchanged", "none -> next", "next -> retired",
	// The switch (03-12e2).
	"active -> draining, trusted until", "install by ", "next -> active",
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

// signerStateDir is the signer's state directory, which keyroster-signer
// owns (03-12b).
const signerStateDir = "/var/lib/keyroster-signer"

var (
	shellBinding = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=("?)` + regexp.QuoteMeta(signerStateDir) + `("?)$`)
	// runuserScript is the script argument of a runuser segment's sh -c,
	// which the signer's own shell runs: the only single-quoted text the
	// checker treats as opaque.
	runuserScript = regexp.MustCompile(`^(runuser -u keyroster-signer (?:-- )?sh -c )'[^']*'`)
	// shellRedirect is a redirect root's shell opens (>, >>, >|, <, &>,
	// &>>, with an optional fd), its target quoted or not.
	shellRedirect = regexp.MustCompile(`(?:&>>?|[0-9]*(?:>>|>\||>|<))\s*['"]?([^\s'"|;&<>]+)`)
	inlineSpan    = regexp.MustCompile("`([^`]+)`")
)

// signerDirLinkSafety checks the shell lines of text's fenced code blocks
// for a root write below the signer's state directory, which follows any
// link keyroster-signer planted there (03-12b, the lesson of 03-12's
// restore block). It is an allowlist: after joining backslash-continued
// lines and splitting each line at its unquoted control operators (;, &&,
// ||, | and &), every command that names the directory, or a variable
// bound to it earlier in the block, must start with runuser -u
// keyroster-signer, be an rm -f of direct children of the state directory
// ("$S/<name>", never one below incoming), or a read-only lock open; and
// no redirect root's shell opens may name the directory or the variable.
// Only the script argument of a runuser command's sh -c is opaque (the
// signer's own shell opens what it names). It returns the refused
// commands.
func signerDirLinkSafety(text string) []string {
	var bad []string
	for _, block := range fencedBlocks(text) {
		var vars []string
		for _, l := range joinContinued(block) {
			if strings.HasPrefix(l, "#") {
				continue
			}
			for _, cmd := range splitCommands(l) {
				if m := shellBinding.FindStringSubmatch(cmd); m != nil {
					vars = append(vars, m[1])
					continue
				}
				if !commandLinkSafe(cmd, vars) {
					bad = append(bad, cmd)
				}
			}
		}
	}
	return bad
}

// signerDirSpanSafety checks the inline code spans of text's prose, outside
// the fenced blocks, as signerDirLinkSafety checks a block line, with the
// variables the blocks bind (03-12b review): a span that names the state
// directory must be one of the allowed commands.
func signerDirSpanSafety(text string) []string {
	var vars []string
	var prose strings.Builder
	inBlock := false
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inBlock = !inBlock
			continue
		}
		if inBlock {
			if m := shellBinding.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
				vars = append(vars, m[1])
			}
			continue
		}
		prose.WriteString(l + "\n")
	}
	var bad []string
	for _, m := range inlineSpan.FindAllStringSubmatch(prose.String(), -1) {
		for _, cmd := range splitCommands(strings.Join(strings.Fields(m[1]), " ")) {
			if !commandLinkSafe(cmd, vars) {
				bad = append(bad, cmd)
			}
		}
	}
	return bad
}

// fencedBlocks returns the lines of each fenced code block of text.
func fencedBlocks(text string) [][]string {
	var out [][]string
	var block []string
	inBlock := false
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			if inBlock {
				out = append(out, block)
				block = nil
			}
			inBlock = !inBlock
			continue
		}
		if inBlock {
			block = append(block, l)
		}
	}
	return out
}

// joinContinued joins backslash-continued lines, with runs of white space
// collapsed.
func joinContinued(lines []string) []string {
	var joined []string
	cur := ""
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasSuffix(t, "\\") {
			cur += strings.TrimSuffix(t, "\\") + " "
			continue
		}
		joined = append(joined, strings.Join(strings.Fields(cur+t), " "))
		cur = ""
	}
	if cur != "" {
		joined = append(joined, strings.Join(strings.Fields(cur), " "))
	}
	return joined
}

// splitCommands splits a shell line at its unquoted control operators (;,
// &&, ||, | and &), leaving the redirects >|, &>, >& and <& whole; quotes
// and backslash escapes are kept in the commands it returns.
func splitCommands(l string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if c := strings.TrimSpace(cur.String()); c != "" {
			out = append(out, c)
		}
		cur.Reset()
	}
	quote := byte(0)
	for i := 0; i < len(l); i++ {
		c := l[i]
		split := false
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' && i+1 < len(l) {
				cur.WriteByte(c)
				i++
				c = l[i]
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '\\' && i+1 < len(l):
			cur.WriteByte(c)
			i++
			c = l[i]
		case c == ';':
			split = true
		case c == '|' && (i == 0 || l[i-1] != '>'):
			if i+1 < len(l) && l[i+1] == '|' {
				i++
			}
			split = true
		case c == '&' && i+1 < len(l) && l[i+1] == '&':
			i++
			split = true
		case c == '&' && (i+1 >= len(l) || l[i+1] != '>') && (i == 0 || (l[i-1] != '>' && l[i-1] != '<')):
			split = true
		}
		if split {
			flush()
			continue
		}
		cur.WriteByte(c)
	}
	flush()
	return out
}

// commandLinkSafe reports whether one shell command, with vars bound to the
// state directory, passes signerDirLinkSafety's allowlist.
func commandLinkSafe(cmd string, vars []string) bool {
	if cmd == "" || strings.HasPrefix(cmd, "#") {
		return true
	}
	names := func(s string) bool {
		for _, dir := range stateDirNames(vars) {
			if strings.Contains(s, dir) {
				return true
			}
		}
		return false
	}
	visible := runuserScript.ReplaceAllString(cmd, "$1''")
	if !names(visible) {
		return true
	}
	for _, dir := range stateDirNames(vars) {
		if regexp.MustCompile(`^exec [0-9]+<"?` + regexp.QuoteMeta(dir) + `/signer\.lock"?$`).MatchString(cmd) {
			return true
		}
	}
	if stateDirCreate(cmd, vars) {
		return true
	}
	if !strings.HasPrefix(cmd, "runuser -u keyroster-signer ") && !directChildRemoval(cmd, vars) {
		return false
	}
	for _, m := range shellRedirect.FindAllStringSubmatch(visible, -1) {
		if names(m[1]) {
			return false
		}
	}
	return true
}

// stateDirNames are the ways a shell line names the state directory: the
// literal path, and $V and ${V} for each variable V bound to it.
func stateDirNames(vars []string) []string {
	out := []string{signerStateDir}
	for _, v := range vars {
		out = append(out, "$"+v, "${"+v+"}")
	}
	return out
}

// stateDirCreate reports whether l is root's creation of the state
// directory itself, owned by keyroster-signer (signer-install.md step 4):
// its parent is root's, so no link of keyroster-signer's lies on the path.
// Nothing below the directory may be named.
func stateDirCreate(l string, vars []string) bool {
	op, ok := strings.CutPrefix(l, "install -d -o keyroster-signer -g keyroster-signer -m 0700 ")
	if !ok {
		return false
	}
	op = strings.Trim(op, `"`)
	return slices.Contains(stateDirNames(vars), op) || op == signerStateDir+"/"
}

// directChildRemoval reports whether l is an rm -f whose every operand is a
// direct child of the state directory ("$S/<name>" for a variable S bound
// to it, or the literal path), never incoming or anything below it.
func directChildRemoval(l string, vars []string) bool {
	ops, ok := strings.CutPrefix(l, "rm -f ")
	if !ok {
		return false
	}
	for _, op := range strings.Fields(ops) {
		op = strings.Trim(op, `"`)
		name := ""
		for _, dir := range stateDirNames(vars) {
			if rest, ok := strings.CutPrefix(op, dir+"/"); ok {
				name = rest
			}
		}
		if name == "" || strings.Contains(name, "/") || name == "incoming" || strings.ContainsAny(name, "*?[") {
			return false
		}
	}
	return true
}

// TestCARotationRunbookLinkSafety (03-12b): in ca-rotation.md root runs
// nothing below the signer's state directory: the files below incoming/
// are removed, written and read only as keyroster-signer, in the pinned
// forms, in the fenced blocks and in the prose's inline code spans. The
// fixture subtests pin what the checker refuses and accepts.
func TestCARotationRunbookLinkSafety(t *testing.T) {
	block := func(lines ...string) string { return "```\n" + strings.Join(lines, "\n") + "\n```\n" }
	const bind = "S=/var/lib/keyroster-signer"
	for _, c := range []struct {
		name string
		text string
		bad  bool
	}{
		{"one_line_root_write_refused", block("install -o keyroster-signer -g keyroster-signer -m 0600 /media/transfer/ceremony/* /var/lib/keyroster-signer/incoming/"), true},
		{"continuation_line_write_refused", block("install -o keyroster-signer -g keyroster-signer -m 0600 \\", "  /media/transfer/ceremony/* /var/lib/keyroster-signer/incoming/"), true},
		{"root_redirect_refused", block(bind, `runuser -u keyroster-signer -- cat /media/transfer/x >"$S/incoming/y"`), true},
		{"root_rm_under_incoming_refused", block(bind, `rm -f "$S/incoming/bundle.json"`), true},
		// A runuser prefix covers its own command only: root runs what
		// follows a control operator (03-12b review).
		{"and_list_after_runuser_refused", block(bind, `runuser -u keyroster-signer -- true && rm -f "$S/incoming/x"`), true},
		{"semicolon_after_runuser_refused", block(`runuser -u keyroster-signer -- true; chown root /var/lib/keyroster-signer/incoming/x`), true},
		{"pipe_to_root_tee_refused", block(bind, `runuser -u keyroster-signer -- cat /media/x | tee "$S/incoming/y"`), true},
		// Root's shell opens a redirect's target, quoted or not.
		{"single_quoted_redirect_target_refused", block(`runuser -u keyroster-signer -- cat /media/x >'/var/lib/keyroster-signer/incoming/y'`), true},
		{"noclobber_override_redirect_refused", block(bind, `runuser -u keyroster-signer -- cat /media/x >|"$S/incoming/y"`), true},
		{"ampersand_redirect_refused", block(bind, `runuser -u keyroster-signer -- cat /media/x &>"$S/incoming/y"`), true},
		{"inline_span_root_write_refused", block(bind, "true") + "Then run `rm -f \"$S/incoming/x\"` as root.\n", true},
		{"inline_span_literal_dir_refused", "Then run `chown root /var/lib/keyroster-signer/incoming/x`.\n", true},
		{"runuser_form_accepted", block(bind,
			`runuser -u keyroster-signer -- rm -f "$S/incoming/bundle.json" \`, `  "$S/incoming/policy.json"`,
			`runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/bundle.json" <"/media/transfer/succ/bundle.json"`,
			`runuser -u keyroster-signer -- cat "$S/incoming/user-g2.json" >/media/transfer/user-g2.json`,
			`rm -f "$S/restore-recovery-pending"`, `exec 9<"$S/signer.lock"`), false},
		{"state_dir_create_accepted", block("install -d -o keyroster-signer -g keyroster-signer -m 0700 /var/lib/keyroster-signer"), false},
		{"incoming_create_by_root_refused", block("install -d -o keyroster-signer -g keyroster-signer -m 0700 /var/lib/keyroster-signer/incoming"), true},
		{"inline_span_runuser_accepted", block(bind, "true") + "As the signer's user\n(`runuser -u keyroster-signer -- rm -f \"$S/software/user-g2.age\"`), or\nremove it.\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := append(signerDirLinkSafety(c.text), signerDirSpanSafety(c.text)...); (len(got) != 0) != c.bad {
				t.Fatalf("signerDirLinkSafety refused %q, want refused %t", got, c.bad)
			}
		})
	}
	t.Run("runbook_blocks_pass", func(t *testing.T) {
		data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "ca-rotation.md")))
		if bad := append(signerDirLinkSafety(data), signerDirSpanSafety(data)...); len(bad) != 0 {
			t.Fatalf("ca-rotation.md runs, as root, below the signer's state directory:\n%s", strings.Join(bad, "\n"))
		}
		for _, want := range []string{`runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"'`, "runuser -u keyroster-signer -- rm -f",
			// The switch (03-12e2): the export comes in as the signer's
			// user, and retire-key runs behind the pinned runuser form.
			`"$S/incoming/previous.jsonl"`, switchRunuser + "keyroster-signer ca-rotate retire-key"} {
			if !strings.Contains(data, want) {
				t.Errorf("ca-rotation.md lacks %q", want)
			}
		}
	})
}

// TestCARotationRunbookAbortPrev (03-12b review): the abort signs on the
// bundle in force, ceremony 1's successor in /media/transfer/succ, as the
// e2e test does (TestCANextAndAbort); ceremony 1's own --prev directory
// would fail on its SHA-256 or with no such entry.
func TestCARotationRunbookAbortPrev(t *testing.T) {
	data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "ca-rotation.md")))
	win, err := sectionWindow(data, &signingSection{id: "ca_abort_prev", file: "ca-rotation.md", section: "Abort"})
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(strings.ReplaceAll(win, "\\\n", " ")), " ")
	for _, want := range []string{"keyroster root sign --prev /media/transfer/succ --prev-sha256 ", "--policy /media/transfer/succ/policy.json"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the abort section lacks %q", want)
		}
	}
	if strings.Contains(win, "/media/transfer/prev") {
		t.Error("the abort section signs on ceremony 1's --prev directory, not on the bundle in force")
	}
}

// TestSignerInstallGenesisLinkSafety (03-12b review): in signer-install.md
// root reads, creates and writes nothing below the signer's state directory
// in the genesis steps 4 to 6 either: their fenced blocks pass
// signerDirLinkSafety (their prose names the directory's files as nouns,
// so its inline spans are not checked), and its runuser forms for the
// read, the directory and the writes are there.
func TestSignerInstallGenesisLinkSafety(t *testing.T) {
	data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	for _, section := range []string{"4. Create the state directory", "5. Root ceremony", "6. Install the bundle"} {
		win, err := sectionWindow(data, &signingSection{id: section, file: "signer-install.md", section: section})
		if err != nil {
			t.Fatal(err)
		}
		if bad := signerDirLinkSafety(win); len(bad) != 0 {
			t.Errorf("signer-install.md step %s runs, as root, below the signer's state directory:\n%s", section, strings.Join(bad, "\n"))
		}
	}
	for _, want := range []string{
		"runuser -u keyroster-signer -- cat /var/lib/keyroster-signer/ca-pubkeys.json >/media/transfer/ca-pubkeys.json",
		`runuser -u keyroster-signer -- sh -c 'umask 077 && mkdir -p "$1"' sh "$S/incoming"`,
		`runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/$f" <"/media/transfer/ceremony/$f"`,
	} {
		if !strings.Contains(data, want) {
			t.Errorf("signer-install.md lacks %q", want)
		}
	}
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

// switchRunuser is the prefix every signer command of the switch sections
// of signer-install.md runs behind (03-12e).
const switchRunuser = "runuser -u keyroster-signer -g keyroster-signer -G tss -- "

// switchSections are the "## " sections of signer-install.md that hold the
// switch install, the key removal and the restore from before a switch
// (03-12e).
var switchSections = []string{"Install a successor bundle: stop, install, start", "Snapshot restore: check the clock first"}

// TestSignerInstallSwitchFences (03-12e): signer-install.md tells the
// operator how to install a switch behind --previous, what each refusal
// means, how retire-key removes the old key per backend and proves before
// it removes, why serve and doctor refuse while the key is held, and how
// to recover a restore older than the last switch; it reads as written in
// its end state, naming neither 03-12e nor 03-12f outside a code span (the
// later 03-13 is named).
func TestSignerInstallSwitchFences(t *testing.T) {
	data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	flat := normalizeSpace(strings.ReplaceAll(data, "\\\n", " "))
	for _, want := range []string{
		"install_previous_required", "install_previous_not_extended", "drain_window_too_short", "drain_window_too_long",
		"ca-rotate retire-key", "active_key_unusable", "draining_key_still_usable", "ssh-add -d", "SSH_AUTH_SOCK",
		"deleted from the token", "a fresh export", "lost switch bundle", "does not hold the old key",
		"is a prefix of the newest saved export", "03-13",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("signer-install.md lacks %q", want)
		}
	}
	previous := false
	for _, block := range fencedBlocks(data) {
		for _, cmd := range joinContinued(block) {
			if strings.Contains(cmd, "keyroster-signer install-bundle ") && strings.Contains(cmd, " --previous ") {
				previous = true
			}
		}
	}
	if !previous {
		t.Error("signer-install.md has no install-bundle command with --previous")
	}
	var prose strings.Builder
	inBlock := false
	for _, l := range strings.Split(data, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inBlock = !inBlock
			continue
		}
		if !inBlock {
			prose.WriteString(l + "\n")
		}
	}
	bare := inlineSpan.ReplaceAllString(prose.String(), "")
	if strings.Contains(bare, "03-12e") {
		t.Error("signer-install.md names 03-12e outside a code span; describe the rotation as written in its end state")
	}
	// 03-12f is described in its end state too (03-12f); the exact token, so
	// that a later 03-12f2 does not trip it.
	for _, m := range planNumber.FindAllStringSubmatch(bare, -1) {
		if m[1] == "03-12f" {
			t.Error("signer-install.md names 03-12f outside a code span; describe the rotation as written in its end state")
		}
	}
}

// TestSignerInstallSwitchPreviousCopy (03-12e pre-merge review): the switch
// install block of signer-install.md removes an older incoming/previous.jsonl
// as the signer's user before it copies the newest export in (set -C refuses
// to overwrite, and a second switch is the normal case), and chains the rm,
// the copy and install-bundle with && so the install never runs against a
// stale export after a failed copy.
func TestSignerInstallSwitchPreviousCopy(t *testing.T) {
	data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	win, err := sectionWindow(data, &signingSection{id: "switch", file: "signer-install.md", section: switchSections[0]})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, b := range fencedBlocks(win) {
		if slices.ContainsFunc(b, func(l string) bool {
			return strings.Contains(l, "incoming/previous.jsonl") && strings.Contains(l, "set -C")
		}) {
			lines = b
		}
	}
	if lines == nil {
		t.Fatal("the switch section has no block that copies incoming/previous.jsonl in")
	}
	rm, cp, inst := -1, -1, -1
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "runuser -u keyroster-signer -- rm -f ") && strings.Contains(l, `"$S/incoming/previous.jsonl"`):
			rm = i
		case strings.HasPrefix(l, "runuser -u keyroster-signer -- sh -c ") && strings.Contains(l, "set -C") && strings.Contains(l, `"$S/incoming/previous.jsonl"`):
			cp = i
		case strings.HasPrefix(l, switchRunuser+"keyroster-signer install-bundle"):
			inst = i
		}
	}
	if rm < 0 || cp < 0 || inst < 0 {
		t.Fatalf("the block lacks the rm as the signer's user (%d), the copy (%d) or the install (%d):\n%s", rm, cp, inst, strings.Join(lines, "\n"))
	}
	if rm >= cp || cp >= inst {
		t.Errorf("order is rm %d, copy %d, install %d; want rm, then copy, then install", rm, cp, inst)
	}
	for name, i := range map[string]int{"rm": rm, "copy": cp} {
		if !strings.HasSuffix(strings.TrimSpace(lines[i]), "&&") {
			t.Errorf("the %s line does not end in && and so does not gate the next command: %q", name, lines[i])
		}
	}
	if cp != rm+1 || inst != cp+1 {
		t.Errorf("the rm, the copy and the install are not consecutive lines (%d, %d, %d)", rm, cp, inst)
	}
}

// TestRunbookAuditVerifyPins (03-12e pre-merge review): trust.MatchPins needs
// the pinned set to equal the bundle's root set, so every `keyroster audit
// verify --pin SHA256:` command of the runbooks pins both roots; one pin
// fails a valid export and sends the operator to escalate as for a fork.
func TestRunbookAuditVerifyPins(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "docs", "runbooks", "*.md"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no runbooks found: %v", err)
	}
	signerInstall := 0
	for _, f := range files {
		for i, l := range strings.Split(string(readTestFile(t, f)), "\n") {
			if !strings.Contains(l, "keyroster audit verify --pin SHA256:") {
				continue
			}
			if filepath.Base(f) == "signer-install.md" {
				signerInstall++
			}
			if n := strings.Count(l, "--pin SHA256:"); n != 2 {
				t.Errorf("%s:%d pins %d roots, want both: %s", filepath.Base(f), i+1, n, strings.TrimSpace(l))
			}
		}
	}
	if signerInstall < 9 {
		t.Errorf("signer-install.md has %d audit verify --pin commands, want at least 9", signerInstall)
	}
	data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	lines := strings.Split(data, "\n")
	restore := 0
	for i, l := range lines {
		if strings.Contains(l, "--previous /tmp/restored.jsonl <the newest saved export>") {
			restore++
			if i == 0 || strings.Count(lines[i-1], "--pin SHA256:") != 2 {
				t.Errorf("the restore check at line %d does not pin both roots", i+1)
			}
		}
	}
	if restore != 1 {
		t.Errorf("found %d restore step 5 checks, want 1", restore)
	}
}

// TestSwitchRunbookLinkSafety (03-12e): the switch sections of
// signer-install.md, which neither TestCARotationRunbookLinkSafety nor
// TestSignerInstallGenesisLinkSafety reads, run nothing as root below the
// signer's state directory: their fenced blocks pass signerDirLinkSafety
// (their prose names the directory's files as nouns, so the inline spans
// are not checked), and retire-key and install-bundle --previous run
// behind the pinned runuser form. The fixture subtests pin the checker's
// verdict on the root and runuser forms of both commands.
func TestSwitchRunbookLinkSafety(t *testing.T) {
	block := func(lines ...string) string { return "```\n" + strings.Join(lines, "\n") + "\n```\n" }
	const (
		retire  = "keyroster-signer ca-rotate retire-key --state-dir /var/lib/keyroster-signer --role user"
		install = "keyroster-signer install-bundle --state-dir /var/lib/keyroster-signer --bundle /var/lib/keyroster-signer/incoming/bundle.json --policy /var/lib/keyroster-signer/incoming/policy.json --previous /root/export.jsonl"
		// exempt is the one existing line of the restore section that names
		// the state directory as root: it only prints its name.
		exempt = `echo "$S is in use by another keyroster-signer process" >&2`
	)
	for _, c := range []struct {
		name string
		text string
		bad  bool
	}{
		{"root_retire_key_refused", block(retire), true},
		{"root_install_bundle_previous_refused", block(install), true},
		{"runuser_retire_key_accepted", block(switchRunuser + retire), false},
		{"runuser_install_bundle_previous_accepted", block(switchRunuser + install), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := signerDirLinkSafety(c.text); (len(got) != 0) != c.bad {
				t.Fatalf("signerDirLinkSafety refused %q, want refused %t", got, c.bad)
			}
		})
	}
	data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	windows := make([]string, 0, len(switchSections))
	for _, section := range switchSections {
		win, err := sectionWindow(data, &signingSection{id: section, file: "signer-install.md", section: section})
		if err != nil {
			t.Fatal(err)
		}
		windows = append(windows, win)
	}
	t.Run("switch_sections_pass_the_block_check", func(t *testing.T) {
		for i, win := range windows {
			var bad []string
			for _, cmd := range signerDirLinkSafety(win) {
				if cmd != exempt {
					bad = append(bad, cmd)
				}
			}
			if len(bad) != 0 {
				t.Errorf("signer-install.md section %q runs, as root, below the signer's state directory:\n%s", switchSections[i], strings.Join(bad, "\n"))
			}
		}
	})
	t.Run("switch_sections_pin_the_runuser_forms", func(t *testing.T) {
		retireForm, installForm := false, false
		for _, win := range windows {
			for _, b := range fencedBlocks(win) {
				for _, cmd := range joinContinued(b) {
					if strings.HasPrefix(cmd, switchRunuser+"keyroster-signer ca-rotate retire-key") {
						retireForm = true
					}
					if strings.HasPrefix(cmd, switchRunuser+"keyroster-signer install-bundle") && strings.Contains(cmd, "--previous") {
						installForm = true
					}
				}
			}
		}
		if !retireForm || !installForm {
			t.Fatalf("the switch sections lack the runuser form of retire-key (%t) or of install-bundle --previous (%t)", retireForm, installForm)
		}
	})
}

// TestCARotationAbortSentence (03-12e): ca-rotation.md's abort section no
// longer promises a retire-key command for an aborted key: retire-key
// removes draining keys only, and an aborted key is destroyed by hand.
func TestCARotationAbortSentence(t *testing.T) {
	data := string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "ca-rotation.md")))
	win, err := sectionWindow(data, &signingSection{id: "ca_abort_sentence", file: "ca-rotation.md", section: "Abort"})
	if err != nil {
		t.Fatal(err)
	}
	flat := normalizeSpace(win)
	if strings.Contains(flat, "no retire-key command yet") {
		t.Error("the abort section still says there is no retire-key command yet")
	}
	for _, want := range []string{"destroy the aborted key by hand", "retire-key removes draining keys only"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the abort section lacks %q", want)
		}
	}
}

// caRotationRunbook reads docs/runbooks/ca-rotation.md (03-12e2).
func caRotationRunbook(t *testing.T) string {
	t.Helper()
	return string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "ca-rotation.md")))
}

// caRotationWindow is the "## " section of ca-rotation.md whose heading
// starts with section (03-12e2).
func caRotationWindow(t *testing.T, data, section string) string {
	t.Helper()
	win, err := sectionWindow(data, &signingSection{id: section, file: "ca-rotation.md", section: section})
	if err != nil {
		t.Fatal(err)
	}
	return win
}

// blockCommands are the commands of text's fenced blocks, continuations
// joined and each line split at its control operators (03-12e2).
func blockCommands(text string) []string {
	var out []string
	for _, b := range fencedBlocks(text) {
		for _, l := range joinContinued(b) {
			out = append(out, splitCommands(l)...)
		}
	}
	return out
}

// commandPrefix strips the runuser, env and sudo prefixes a runbook puts
// before a command (03-12e2).
var commandPrefix = regexp.MustCompile(`^(?:(?:runuser(?: -[ugG] \S+)* --|env(?: [A-Za-z_][A-Za-z0-9_]*=\S*)*|sudo(?: -u \S+)?) )+`)

// planNumber is a plan number of this project in prose, such as 03-12b
// (03-12e2).
var planNumber = regexp.MustCompile(`(?:^|[^0-9A-Za-z-])(0[0-9]-[0-9]{2}[a-z0-9]*)`)

// retireFile is a file name that ca-rotate retire-key prints, with its
// optional surrounding quotes (03-12e2).
var retireFile = regexp.MustCompile(`"?[^\s"<>]*retire-[a-z]+-g[0-9]+(?:-cert\.pub)?"?`)

// TestCARotationSwitchRunbook (03-12e2): ca-rotation.md describes the
// whole rotation in its end state: the phrases of each step, no plan
// number of this rotation outside a code span, both roots pinned on every
// audit verify, and the files retire-key prints written by root only in a
// private directory of its own.
func TestCARotationSwitchRunbook(t *testing.T) {
	data := caRotationRunbook(t)
	t.Run("required_phrases", func(t *testing.T) {
		flat := normalizeSpace(strings.ReplaceAll(data, "\\\n", " "))
		for _, want := range []string{
			"Before ceremony 2", "upgrade gate", "switch_floor", "live on", "keyroster host forget", "--previous",
			"drain_window_too_short", "burned", "fresh output directory", "retire-key", "keyroster-agent check",
			"trust_expired", "bundle_behind", "clients have refreshed", "every copy of a refused bundle", "UNVERIFIED", "residual",
		} {
			if !strings.Contains(flat, want) {
				t.Errorf("ca-rotation.md lacks %q", want)
			}
		}
	})
	t.Run("no_plan_numbers", func(t *testing.T) {
		var prose strings.Builder
		inBlock := false
		for _, l := range strings.Split(data, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "```") {
				inBlock = !inBlock
				continue
			}
			if !inBlock {
				prose.WriteString(l + "\n")
			}
		}
		bare := inlineSpan.ReplaceAllString(prose.String(), "")
		for _, m := range planNumber.FindAllStringSubmatch(bare, -1) {
			// 03-12f and 03-12f2 are described in their end state; 03-13 and
			// 03-16 are still to come (03-12f2).
			if !slices.Contains([]string{"03-13", "03-16"}, m[1]) {
				t.Errorf("ca-rotation.md names plan %s outside a code span; describe the rotation in its end state", m[1])
			}
		}
	})
	// The host-CA gate in its end state (03-12f2): every new sentence of
	// ca-rotation.md on the host role, and the sentences of
	// machine-identities.md and signer-install.md that agree with it, each
	// in its own window; and none of the earlier wordings.
	t.Run("host_ca_gate", func(t *testing.T) {
		head := data
		if i := strings.Index(data, "\n## "); i >= 0 {
			head = data[:i]
		}
		window := func(e *signingSection) string {
			w, err := sectionWindow(string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", e.file))), e)
			if err != nil {
				t.Fatalf("%s: %v", e.id, err)
			}
			return w
		}
		machine := window(&signingSection{id: "machine_identities_host_trust", file: "machine-identities.md", section: "Renew a machine certificate"})
		switchTrust := window(&signingSection{id: "signer_install_switch_trust", file: "signer-install.md", section: "Install a successor bundle", start: "### Install a CA switch"})
		for _, w := range []struct {
			name, text      string
			holds, holdsNot []string
		}{
			{"ca-rotation.md \"The host CA\"", caRotationWindow(t, data, "The host CA"), []string{
				"clients have refreshed",
				"The gate concerns every account whose ssh reads keyroster's managed trust files",
				"into the `~/.ssh` of the account they run as",
				"before its first Host or Match line",
				"Such an account gains a host CA line only when it refreshes",
				"one `@cert-authority` line for each host CA the trust bundle trusts at the client's clock",
				"An account that never had these files keeps its own configuration",
				"no earlier than ceremony 1's install plus the user profile's max TTL",
				"the largest user `max_ttl_seconds` of the policy in force at ceremony 1's install and of every policy installed since",
				"every user certificate issued before ceremony 1's install under the policy then in force has expired",
				"one issued before the install under an earlier policy with a larger user cap may still be valid",
				"so a user whose only certificates were issued before that install under the policy then in force needs a new one, from a login or from an admin",
				"The wait does not show that a login refreshed",
				"Before ceremony 2's install, every account whose ssh reads the managed files has refreshed",
				"a user who always passes `--no-known-hosts` included",
				"An account has refreshed when its managed `~/.ssh/keyroster_known_hosts` holds the new host CA's line",
				"the `@cert-authority` line that ends `keyroster host CA generation <g>`",
				"An account that runs ssh from several computers has refreshed when the file on each of them holds the line",
				"A user refreshes with a `keyroster login` without `--no-known-hosts`",
				"The file shows whether it wrote the line",
				"the login succeeds whatever its host trust outcome",
				"run as the account ssh runs as and on the computer it runs from",
				"one that ran with `--no-known-hosts` adds no host CA line: it only narrows the file",
				"(a bundle installed in between still lists it when its ceremony printed no `CA host` line",
				"A user who always passes `--no-known-hosts` runs one `keyroster login` without it",
				"which exits 0 when it refreshed",
				"the file, not the exit, shows the new line",
				"Whichever way, the line is the check",
				"so a refresh that wrote only the old line is repeated until the file holds the new one",
				"It needs an admin key from the root-signed policy, loaded in ssh-agent",
				"is refreshed only by an admin who runs `keyroster known-hosts sync` as that account after ceremony 1's install and before ceremony 2's install",
				"who then checks that account's file for the line",
				"it is a client that never refreshes",
				"That sync signs with the admin key through the ssh-agent the account reaches",
				"its fingerprint given with `--admin-key`",
				"every one of its processes can ask it to sign with any key it holds",
				"at an admin quorum of 1, the default, one admin signature authorises a new directory",
				"use an agent that holds the admin key alone, run the sync while nothing else runs as that account, and end the agent's reach right after",
				"(UNVERIFIED: no test runs sync for another account.)",
				"No tool counts the clients that have refreshed",
				"the gate is the operator's",
				"which a bundle that changes only the host role leaves as it is",
				"`bundle v<N> on <X>/<M> hosts` of `keyroster host status`",
				"a host removed from the directory stays in M until `keyroster host forget`",
				"refuses the certificate the signer issues it after the switch (`answer_unpinned_ca`",
				"an answer by a host CA outside the agent's trusted set; UNVERIFIED end to end",
				"`TestDecide/backoff_schedule`",
				"(UNVERIFIED: no test shows a kept certificate surviving that refusal)",
				"until it takes that bundle or the old certificate runs out, after which clients refuse it",
				"uses the host profile's `max_ttl_seconds`",
				"each host whose certificate keyroster-agent renews keeps serving its certificate by the old host CA",
				"unless the agent replaces it earlier",
				"A certificate the agent obtains lives the smaller of 30 days and the host cap",
				"at most about 20 days after the switch, and for many hosts sooner",
				"moves to the new host CA only when an admin issues it a new one after the switch",
				"(UNVERIFIED: no test issues a host certificate by hand across a host-CA switch)",
				"holds both host CA lines and accepts either certificate",
				"holds only the old host CA's line: it reaches each host until that host moves",
				"`Host key verification failed` from then on, possibly weeks after the switch, until it refreshes",
				"Watching for failures right after the switch shows little",
				"No file that sshd reads lists a host CA key",
				"removes its line from `keyroster_known_hosts` once its `trusted_until` has passed on the client's clock",
				"each agent stops accepting answers signed by it at its `trusted_until`",
				"key's `trusted_until`, the earliest moment a client stops trusting it",
				"Run in CI: `TestHostCARotation`",
				"waits for the host's heartbeat to report ceremony 1's bundle before the switch",
				"the host asks for no certificate, installs no other and its agent refuses no answer",
				"is refused with `Host key verification failed` after the renewal",
				"The test does not wait the gate's time",
				// keyroster machine renew refreshes an automation account's host CA lines (03-12g).
				"a refresh writes one `@cert-authority` line for each host CA the trust bundle trusts at the client's clock, `keyroster machine renew` adds the line of an active or next host CA that the file lacks",
				"An automation account that has the managed files refreshes itself with `keyroster machine renew`, run as the account ssh runs as, with `$HOME` its home",
				"Every run, whether it renews the certificate or finds it not due, adds to the account's `keyroster_known_hosts` the line of each active or next host CA of the trust bundle that the file lacks",
				"over the host names that the file's lines for the host CAs the bundle trusts already name, in the form a refresh writes",
				"It adds no host name, writes no revocation and never creates the file",
				"an admin's `keyroster known-hosts sync` as that account is its first refresh, and it brings new host names and revocations",
				"When the certificate is written or not due but host trust could not be refreshed, it exits 4",
				"so the time between two of its runs bounds how soon that happens: check the file before ceremony 2's install",
				"nor a `keyroster machine renew` that runs (a host that ssh connects onward from, or an automation account that runs it with `--no-known-hosts`)",
				"The same holds for the first sync of an automation account",
				"never gains the new host CA's line, from a refresh or from `keyroster machine renew`, cannot be rotated safely",
				"one host at a host cap of 90 s and three clients on loopback",
				"A third client's file starts as the second's: `keyroster machine renew`, run after ceremony 1's install and not due, adds to it exactly the new host CA's line for the host's name",
				"(with `--no-known-hosts` it changes nothing), and with that file the client reaches the host right after the switch and after the renewal",
				"UNVERIFIED: the host drain's end on a real host and client (unit-tested only), a real fleet, a client on Windows, clients older than OpenSSH 8.5, real clients that never refresh, a `keyroster machine renew` that a real cron job or timer runs, and a sync run for another account",
				"The test renews from an account that also holds an administrator's configuration, not from an automation account of its own",
				// How the automation account runs it and when it has refreshed (03-12g,
				// pre-merge review).
				"with `$HOME` its home, and without `--no-known-hosts`",
				"Such an account has refreshed once a run after ceremony 1's install has left the new line in its file",
			}, []string{
				"UNVERIFIED until",
				// The wordings before keyroster machine renew refreshed host CA lines (03-12g).
				"is never rewritten by a full refresh",
				"(an automation account, or a host that ssh connects onward from)",
			}},
			{"ca-rotation.md before its first \"## \" line", head, []string{
				"`TestHostCARotation` for what the host CA's gate prevents",
			}, nil},
			{"ca-rotation.md \"Run in CI\"", caRotationWindow(t, data, "Run in CI"), []string{
				"`TestHostCARotation` (the same job: what the host CA's gate prevents",
				"UNVERIFIED: the drain on real hosts of a fleet, the machine CA, the host drain's end on a real host and client (unit-tested only)",
				// The third client, which keyroster machine renew refreshed (03-12g).
				"a client that refreshed and one that did not across the host's renewal, and one that `keyroster machine renew` refreshed",
			}, []string{"the host CA end to end"}},
			{"ca-rotation.md \"Before ceremony 2\"", caRotationWindow(t, data, "Before ceremony 2"), []string{
				"at least the user profile's max TTL after ceremony 1's install",
				"a user who always passes `--no-known-hosts` included",
				"gets the line from an admin who runs `keyroster known-hosts sync` as that account",
				"`bundle v<N> on <M>/<M> hosts` for the server's current bundle N",
				"ceremony 1's or a later one that still lists the new host CA",
				"no earlier than the gate of \"The host CA\" allows",
				"of every account whose ssh reads the managed files holds the new host CA's line",
				"`keyroster ca issue --ca host` lives as long as its `--ttl`, up to the host profile's `max_ttl_seconds`, which the floor of \"Ceremony 2\" covers",
				"lies past a role's floor only when a certificate was issued under an earlier policy whose cap for its role was larger",
				// An automation account gets the line from keyroster machine renew run
				// without --no-known-hosts (03-12g, pre-merge review).
				"an automation account that runs `keyroster machine renew` without `--no-known-hosts` gets the line from it",
				// Who gets the line from an admin (03-12g, pre-merge review).
				"an account that has neither a login of its own nor a `keyroster machine renew` that runs gets the line from an admin",
			}, []string{"has no cap on its validity", "can make the switch of the host role wait"}},
			{"ca-rotation.md \"What changes for nobody\"", caRotationWindow(t, data, "What changes for nobody"), []string{
				"a client must have refreshed first",
			}, nil},
			{"machine-identities.md \"Renew a machine certificate\"", machine, []string{
				"after ceremony 1's install and before ceremony 2's install",
				// keyroster machine renew refreshes the host CA lines, and exits 4 when it cannot (03-12g).
				"the only other files it changes are the account's host trust files",
				"keeps an automation account's host CA lines current",
				"every run, renewed or not due, adds to it the line of each active or next host CA of the root-verified trust bundle that the file lacks",
				"and records that bundle's version in `host-trust.json`, as a refresh does",
				"prints one line on stderr when it adds a line and nothing when nothing changed",
				"and `--no-known-hosts` turns it off",
				"It never adds a host name, never creates the file and never writes `keyroster_revoked_hosts.krl` or `keyroster_ssh_config`",
				"the file's first version, new host names and revocations reach the account only when an admin runs `keyroster known-hosts sync` as that account",
				"Run in CI: `TestMachineHostTrust`, `TestAddHostCALines` and, end to end, `TestHostCARotation`",
				"UNVERIFIED: a run by a real cron job or timer, an account whose renewal runs as another OS account than its ssh or with another `$HOME` than its home in the account database, Windows, and a sync that an admin runs for another account",
				"4 when the certificate was written or is not due but the host CA lines could not be refreshed",
				"1 for any refusal or failure of the renewal itself, whatever happened to the host CA lines",
				"An account whose home holds no `~/.ssh/keyroster_known_hosts`, or a run with `--no-known-hosts`, never gets 4",
				"one whose home holds it gets 4 on every run while the server serves an older trust bundle than the account verified before, while its managed file is damaged or its state is missing, damaged or of another installation, or while `$HOME` is set and is not the account's home",
				"The end-to-end run renews from an account that also holds an administrator's configuration; the command-level tests also renew from a configuration without a user",
				"checks the answer against the root-verified trust bundle before it writes the certificate: it is a user certificate",
				"An account whose file holds no line of a host CA the trust bundle trusts, as after a drain it missed, gets no line, and 0 unless the refresh fails for another reason: only an admin's `keyroster known-hosts sync` as that account gives it one again",
				// The account the renewal runs as, what exit 0 and 4 print, what exit 4
				// calls for, a run without $HOME, and what the step also does (03-12g,
				// pre-merge review).
				"for the OS account it runs as: run it as the account whose ssh reads the file",
				"0 when the certificate was written or is not due and the host CA lines were refreshed or needed no change",
				"the reason is the `Warning: host trust not refreshed in` line on stderr; the certificate is kept",
				"and neither does a run without `$HOME` (unset or empty), which changes no host CA line even when the account's home holds the file",
				"item 7 for an older trust bundle, item 8 for a damaged file or a state that is missing, damaged or of another installation (start over, then an admin's `keyroster known-hosts sync` as that account), and item 9 for `$HOME`",
				// The pointer sentence's lead-in (03-12g, pre-merge review).
				"What to do is in [enroll-user.md](enroll-user.md), \"Trusting hosts without TOFU\": item 7",
				"so that a server cannot later serve an older bundle unnoticed",
				"It also removes the lines of host CAs the bundle no longer trusts, as every command that verifies the bundle does",
				"It makes no request of its own for this",
			}, []string{
				"before a host-CA rotation",
				// The wordings before keyroster machine renew refreshed host CA lines (03-12g).
				"`keyroster machine renew` does not refresh the host trust files",
				"It writes only the certificate",
				"is refreshed only by an admin who runs",
				"0 when the certificate was written or is not due, 1",
				"before it writes anything",
			}},
			{"signer-install.md \"Install a CA switch\"", switchTrust, []string{
				"for the host role by the clients, and by the agents, which accept host certificates signed by it until then",
				"so that no certificate the signer issued under the old key outlives the trust in that key",
			}, []string{"trusted by hosts until", "the hosts' trust in it"}},
		} {
			flat := normalizeSpace(w.text)
			for _, want := range w.holds {
				if !strings.Contains(flat, want) {
					t.Errorf("%s lacks %q", w.name, want)
				}
			}
			for _, gone := range w.holdsNot {
				if strings.Contains(flat, gone) {
					t.Errorf("%s still holds %q", w.name, gone)
				}
			}
		}
	})
	t.Run("audit_verify_pins_both_roots", func(t *testing.T) {
		n := 0
		for _, cmd := range blockCommands(data) {
			if !strings.HasPrefix(commandPrefix.ReplaceAllString(cmd, ""), "keyroster audit verify") {
				continue
			}
			n++
			if c := strings.Count(cmd, "--pin SHA256:"); c != 2 {
				t.Errorf("an audit verify of ca-rotation.md pins %d roots, want both: %s", c, cmd)
			}
		}
		if n < 2 {
			t.Errorf("ca-rotation.md has %d keyroster audit verify commands, want at least 2 (after ceremony 1's install and after the switch)", n)
		}
	})
	// Review item A: every export of the runbook is copied onto the transfer
	// medium by the signer's user right after it is taken, its /tmp copy is
	// removed, the audit verify reads the copy on the medium, and the
	// switch install takes no export of its own.
	t.Run("exports_leave_the_box", func(t *testing.T) {
		copyLine := regexp.MustCompile(`^runuser -u keyroster-signer -- cat (/tmp/\S+) >(/media/transfer/\S+) &&$`)
		n := 0
		for _, b := range fencedBlocks(data) {
			lines := joinContinued(b)
			for i, l := range lines {
				if !strings.Contains(l, "keyroster-signer export-log ") {
					continue
				}
				n++
				out := ""
				if f := strings.Fields(l); slices.Contains(f, "--out") {
					out = f[slices.Index(f, "--out")+1]
				}
				if !strings.HasSuffix(l, " &&") || i+3 >= len(lines) {
					t.Errorf("the export-log line does not end in && before its copy and removal: %s", l)
					continue
				}
				m := copyLine.FindStringSubmatch(lines[i+1])
				if m == nil || m[1] != out {
					t.Errorf("the line after export-log --out %s is not a runuser cat of it onto /media/transfer chained with &&: %s", out, lines[i+1])
					continue
				}
				if lines[i+2] != "runuser -u keyroster-signer -- rm -f "+out {
					t.Errorf("the copy of %s is not followed by its removal as the signer's user: %s", out, lines[i+2])
				}
				if !strings.HasPrefix(lines[i+3], "keyroster audit verify ") || !strings.HasSuffix(lines[i+3], " "+m[2]) {
					t.Errorf("the audit verify after the export does not read the copy %s on the medium: %s", m[2], lines[i+3])
				}
			}
		}
		// The second export is written under the first one's name, so the
		// text before it says to move the first aside and keep it.
		if flat := normalizeSpace(caRotationWindow(t, data, "Remove the old key and restart")); !strings.Contains(flat, "First move `/media/transfer/export.jsonl` aside under another name and keep it") {
			t.Errorf("the section that overwrites /media/transfer/export.jsonl does not say to move the earlier export aside first")
		}
		// Every block that writes the export onto the medium, ceremony 1's
		// included (a second rotation's ceremony 1 writes over the first
		// rotation's switch export), has the sentence in the prose right
		// before it (03-12f).
		for _, p := range moveAsideBeforeExports(data) {
			t.Errorf("ca-rotation.md: %s", p)
		}
		if n != 2 {
			t.Errorf("%d export-log commands in ca-rotation.md, want 2 (after ceremony 1's install and after the switch)", n)
		}
		for _, b := range fencedBlocks(caRotationWindow(t, data, "Install the switch")) {
			for _, l := range b {
				if strings.Contains(l, "/tmp") || strings.Contains(l, "export-log") {
					t.Errorf("the switch install block names the signer box's own export: %s", l)
				}
			}
		}
	})
	// Review item D: a refused switch install leaves the signer stopped, so
	// the runbook says how to start it again, and not after a restore case.
	t.Run("refusal_restarts_the_signer", func(t *testing.T) {
		win := caRotationWindow(t, data, "Install the switch")
		flat := normalizeSpace(win)
		for _, want := range []string{
			"On any refusal except `install_previous_not_extended`, which goes to the restore section, destroy the refused files as stated above and then start the signer again, so that issuance is not left down",
			"The signer serves the bundle in force, whose old key is still active",
			"Repeat ceremony 2 later, from a fresh output directory.",
		} {
			if !strings.Contains(flat, want) {
				t.Errorf("the Install the switch section lacks %q", want)
			}
		}
		blocks := fencedBlocks(win)
		if len(blocks) < 2 {
			t.Fatalf("%d blocks in the Install the switch section, want the install and the start", len(blocks))
		}
		if last := blocks[len(blocks)-1]; len(last) != 1 || last[0] != "systemctl start keyroster-signer.service" {
			t.Errorf("the last block of the Install the switch section is not the single start command: %q", last)
		}
		if strings.Index(win, "systemctl start keyroster-signer.service") < strings.Index(win, "install_previous_not_extended") {
			t.Errorf("the start command comes before the refusal list")
		}
	})
	t.Run("retire_files_in_a_private_directory", func(t *testing.T) {
		cmds := blockCommands(caRotationWindow(t, data, "Remove the old key and restart"))
		if !slices.Contains(cmds, "D=$(mktemp -d)") {
			t.Fatalf("the retire section binds no root-owned D=$(mktemp -d):\n%s", strings.Join(cmds, "\n"))
		}
		files, adds := 0, 0
		for _, cmd := range cmds {
			for _, f := range retireFile.FindAllString(cmd, -1) {
				files++
				if !strings.HasPrefix(f, `"$D/retire-`) {
					t.Errorf("the retire section names %s, not \"$D/retire-...\": %s", f, cmd)
				}
			}
			if strings.Contains(cmd, "ssh-add") {
				adds++
				if !regexp.MustCompile(`^SSH_AUTH_SOCK=\S+ ssh-add -d "\$D/retire-[a-z]+-g[0-9]+(?:-cert\.pub)?"$`).MatchString(cmd) {
					t.Errorf("an ssh-add of the retire section is not the printed form on a $D path: %s", cmd)
				}
			}
		}
		if files == 0 || adds == 0 {
			t.Errorf("the retire section names %d retire- files and runs %d ssh-add commands; want both", files, adds)
		}
	})
}

// TestCARotationScopeIsCurrent (03-12e2): the Scope of ca-rotation.md
// describes a complete rotation, not one that still waits for a switch.
func TestCARotationScopeIsCurrent(t *testing.T) {
	flat := normalizeSpace(caRotationWindow(t, caRotationRunbook(t), "Scope"))
	for _, stale := range []string{"there is no switch", "no switch yet", "not a complete rotation", "ceremony 1 and abort only"} {
		if strings.Contains(flat, stale) {
			t.Errorf("the Scope still says %q", stale)
		}
	}
	for _, want := range []string{"ceremony 2", "drain"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the Scope lacks %q", want)
		}
	}
}

// installCopy is one copy line of an install block: the signer's user
// writes target, below $S/incoming, from source, under umask 077 and
// set -C (03-12e2).
var installCopy = regexp.MustCompile(`^runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"\$1"' sh ("\$S/incoming/[^"/]+") <"([^"]+)" &&$`)

// TestCARotationInstallBlocks (03-12e2, the lesson of 03-12e's review of
// signer-install.md): both install blocks of ca-rotation.md, ceremony 1's
// and the switch's, remove every file they copy into incoming as the
// signer's user first, copy each file under set -C as that user, and run
// install-bundle behind the pinned runuser form on exactly the copied
// files, every line before the install ending in && and the lines
// consecutive, so that a stale file never meets the install and a failed
// copy never reaches it.
func TestCARotationInstallBlocks(t *testing.T) {
	data := caRotationRunbook(t)
	for _, c := range []struct {
		section  string
		files    []string
		previous bool
	}{
		{"Install the successor", []string{"bundle.json", "bundle.json.sigs", "policy.json", "policy.json.sigs"}, false},
		{"Install the switch", []string{"bundle.json", "bundle.json.sigs", "policy.json", "policy.json.sigs", "previous.jsonl"}, true},
	} {
		t.Run(strings.ReplaceAll(strings.ToLower(c.section), " ", "_"), func(t *testing.T) {
			var blocks [][]string
			for _, b := range fencedBlocks(caRotationWindow(t, data, c.section)) {
				if slices.ContainsFunc(b, func(l string) bool { return strings.Contains(l, `"$S/incoming/`) && strings.Contains(l, "set -C") }) {
					blocks = append(blocks, joinContinued(b))
				}
			}
			if len(blocks) != 1 {
				t.Fatalf("%d blocks copy into incoming under set -C, want exactly 1", len(blocks))
			}
			lines := blocks[0]
			rm := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "runuser -u keyroster-signer -- rm -f ") })
			if rm < 0 {
				t.Fatalf("the block removes nothing as the signer's user first:\n%s", strings.Join(lines, "\n"))
			}
			want := make([]string, 0, len(c.files))
			for _, f := range c.files {
				want = append(want, `"$S/incoming/`+f+`"`)
			}
			removed := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(lines[rm], "runuser -u keyroster-signer -- rm -f "), " &&"))
			if !strings.HasSuffix(lines[rm], " &&") || !slices.Equal(slices.Sorted(slices.Values(removed)), slices.Sorted(slices.Values(want))) {
				t.Fatalf("the rm line removes %q and must end in &&; want exactly %q: %q", removed, want, lines[rm])
			}
			var copied []string
			i := rm + 1
			for ; i < len(lines); i++ {
				m := installCopy.FindStringSubmatch(lines[i])
				if m == nil {
					break
				}
				copied = append(copied, m[1])
				// The export is the anchor kept off the signer box: its copy
				// into incoming reads the transfer medium, never a path
				// below /tmp or anywhere else on the box (review item A).
				if m[1] == `"$S/incoming/previous.jsonl"` && (strings.Contains(m[2], "/tmp") || !strings.HasPrefix(m[2], "/media/transfer/")) {
					t.Errorf("the previous.jsonl copy reads %q, want a path on the transfer medium and never /tmp: %s", m[2], lines[i])
				}
			}
			if !slices.Equal(slices.Sorted(slices.Values(copied)), slices.Sorted(slices.Values(want))) {
				t.Fatalf("the consecutive copy lines after the rm write %q, want %q (each a runuser copy under umask 077 and set -C ending in &&):\n%s", copied, want, strings.Join(lines, "\n"))
			}
			if i >= len(lines) || !strings.HasPrefix(lines[i], switchRunuser+"keyroster-signer install-bundle ") {
				t.Fatalf("the line after the copies is not install-bundle behind %q:\n%s", switchRunuser, strings.Join(lines, "\n"))
			}
			args := strings.Fields(lines[i])
			operand := func(flag string) string {
				if j := slices.Index(args, flag); j >= 0 && j+1 < len(args) {
					return args[j+1]
				}
				return ""
			}
			for flag, wantOp := range map[string]string{"--bundle": `"$S/incoming/bundle.json"`, "--policy": `"$S/incoming/policy.json"`} {
				if got := operand(flag); got != wantOp {
					t.Errorf("install-bundle %s %s, want %s", flag, got, wantOp)
				}
			}
			if got := operand("--previous"); c.previous != (got != "") || (c.previous && got != `"$S/incoming/previous.jsonl"`) {
				t.Errorf("install-bundle --previous %q; want %t for this block, on the copied export", got, c.previous)
			}
		})
	}
}

// moveAsideSentence is the sentence that must stand before every block of
// ca-rotation.md that writes the export onto the medium, because each of
// them writes it under the same name (03-12f).
const moveAsideSentence = "First move `/media/transfer/export.jsonl` aside under another name and keep it"

// moveAsideBeforeExports returns one problem for every fenced block of text
// holding a command that writes >/media/transfer/export.jsonl whose
// preceding prose does not contain moveAsideSentence, whitespace-normalised.
// The preceding prose is the text between the block's opening fence and the
// latest of the end of the previous fenced block, the nearest heading line
// above the block and the start of the file (03-12f).
func moveAsideBeforeExports(text string) []string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var problems []string
	from, open, writes := 0, -1, false
	for i, l := range lines {
		fence := strings.HasPrefix(strings.TrimSpace(l), "```")
		switch {
		case fence && open < 0:
			open, writes = i, false
		case fence:
			if writes && !strings.Contains(normalizeSpace(strings.Join(lines[from:open], "\n")), moveAsideSentence) {
				problems = append(problems, fmt.Sprintf("the fenced block at line %d writes >/media/transfer/export.jsonl, and the prose before it lacks %q", open+1, moveAsideSentence))
			}
			open, from = -1, i+1
		case open >= 0:
			if strings.Contains(l, ">/media/transfer/export.jsonl") {
				writes = true
			}
		case strings.HasPrefix(l, "#"):
			from = i + 1
		}
	}
	return problems
}

// TestMoveAsideSentence (03-12f): moveAsideBeforeExports accepts the
// sentence in the prose right before each writing block, also when it
// wraps, and refuses its absence there, the sentence after the block, and
// the sentence above the heading of the block's section.
func TestMoveAsideSentence(t *testing.T) {
	const sentence = "First move `/media/transfer/export.jsonl` aside under another name\nand keep it: the block writes the new export under the same name."
	const block = "```\nrunuser -u keyroster-signer -- cat /tmp/x.jsonl >/media/transfer/export.jsonl &&\nrunuser -u keyroster-signer -- rm -f /tmp/x.jsonl\n```\n"
	// line is the 1-based line of the opening fence that follows prefix.
	line := func(prefix string) string { return fmt.Sprintf("line %d ", strings.Count(prefix, "\n")+1) }
	first := "# T\n\n## One\n\nIntro.\n" + sentence + "\n\n" + block + "\nAfter.\n\n## Two\n\nIntro.\n"
	for _, c := range []struct {
		name   string
		prefix string // the text before the block a problem must name
		text   string
		want   int
	}{
		{"sentence_present_accepted", "", first + sentence + "\n\n" + block, 0},
		{"sentence_absent_refused", first + "\n", first + "\n" + block, 1},
		{"sentence_after_block_refused", "# T\n\n## One\n\nIntro.\n\n", "# T\n\n## One\n\nIntro.\n\n" + block + "\n" + sentence + "\n", 1},
		{"sentence_in_previous_section_refused", "# T\n\n## One\n\n" + sentence + "\n\n## Two\n\nIntro.\n\n",
			"# T\n\n## One\n\n" + sentence + "\n\n## Two\n\nIntro.\n\n" + block, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := moveAsideBeforeExports(c.text)
			if len(got) != c.want {
				t.Fatalf("moveAsideBeforeExports gave %d problems, want %d: %q", len(got), c.want, got)
			}
			if c.want == 1 && !strings.Contains(got[0], line(c.prefix)) {
				t.Errorf("the problem %q does not name the block at %s", got[0], line(c.prefix))
			}
		})
	}
}

// pivMgmtKeyBlock is the management key's round trip of docs/backends/piv.md
// step 5, word for word, as five consecutive lines of one fenced block: it
// stops the signer, places the key at the stored path as the signer's
// user, runs one ca-rotate command, shreds the key on every exit status and
// starts the signer only after the shred and only when the command exited 0
// (03-12f).
var pivMgmtKeyBlock = []string{
	"sudo systemctl stop keyroster-signer.service",
	"K=/etc/keyroster-signer/piv/mgmt-key",
	`sudo runuser -u keyroster-signer -- rm -f "$K"`,
	`sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$K"`,
	`sudo runuser -u keyroster-signer -- keyroster-signer ca-rotate <arguments> --state-dir /var/lib/keyroster-signer; rc=$?; sudo runuser -u keyroster-signer -- shred -u "$K"; test "$rc" -eq 0 && sudo systemctl start keyroster-signer.service`,
}

// sudoRunuserScript is runuserScript with an optional leading sudo: the
// script argument of a runuser sh -c that the signer's own shell runs, the
// only single-quoted text pivMgmtKeyBlockProblems treats as opaque (03-12f).
var sudoRunuserScript = regexp.MustCompile(`^((?:sudo )?runuser -u keyroster-signer (?:-- )?sh -c )'[^']*'`)

// pivMgmtKeyBlockProblems applies the block rules of piv.md step 5 to win
// and returns one problem per broken rule, each starting with the rule's
// name: "consecutive" when no fenced block holds the lines of
// pivMgmtKeyBlock as consecutive whole lines in order; and, for every
// command of win's fenced blocks (continuations joined, each line split at
// its control operators) that names /etc/keyroster-signer/piv or $K, the
// binding of K excepted, "runuser" when it does not start with sudo runuser
// -u keyroster-signer, and "redirect" when, with its sh -c script masked,
// a redirect that root's shell opens names the directory or $K. The
// directory belongs to the signer's user, who could plant a link there
// (03-12f).
func pivMgmtKeyBlockProblems(win string) []string {
	const dir, binding = "/etc/keyroster-signer/piv", "K=/etc/keyroster-signer/piv/mgmt-key"
	var problems []string
	blocks := fencedBlocks(win)
	found := false
	for _, b := range blocks {
		for i := 0; i+len(pivMgmtKeyBlock) <= len(b) && !found; i++ {
			found = true
			for j, want := range pivMgmtKeyBlock {
				if strings.TrimSpace(b[i+j]) != want {
					found = false
					break
				}
			}
		}
	}
	if !found {
		problems = append(problems, "consecutive: no fenced block holds the five lines of the management key's round trip as consecutive whole lines, in order")
	}
	names := func(s string) bool {
		return strings.Contains(s, dir) || strings.Contains(s, "$K") || strings.Contains(s, "${K}")
	}
	for _, b := range blocks {
		for _, l := range joinContinued(b) {
			if strings.HasPrefix(l, "#") {
				continue
			}
			for _, cmd := range splitCommands(l) {
				if cmd == binding || !names(cmd) {
					continue
				}
				if !strings.HasPrefix(cmd, "sudo runuser -u keyroster-signer ") {
					problems = append(problems, "runuser: "+cmd)
					continue
				}
				for _, m := range shellRedirect.FindAllStringSubmatch(sudoRunuserScript.ReplaceAllString(cmd, "$1''"), -1) {
					if names(m[1]) {
						problems = append(problems, "redirect: "+cmd)
					}
				}
			}
		}
	}
	return problems
}

// TestCARotationBackendSteps (03-12f): the runbooks say, per backend, what
// prepare creates and how retire-key removes the old key, each phrase in
// the window it belongs to; ca-rotation.md names no backend as refused;
// and piv.md step 5 holds the management key's round trip as one block
// that runs as the signer's user and shreds the key on every exit status
// before the signer starts. The rule for emptying a generation slot, the
// abort's removal paths, what doctor shows on piv, and when a restore lets
// an unrecorded generation key go are pinned where each is stated, and so
// is the sentence of signer-install.md's tpm paragraph on what the console
// texts say about an unrecorded key file after a restore.
func TestCARotationBackendSteps(t *testing.T) {
	window := func(t *testing.T, data string, e *signingSection) string {
		t.Helper()
		win, err := sectionWindow(data, e)
		if err != nil {
			t.Fatalf("%s %s: %v", e.file, e.id, err)
		}
		return win
	}
	holds := func(t *testing.T, where, win string, want []string) {
		t.Helper()
		flat := normalizeSpace(win)
		for _, w := range want {
			if !strings.Contains(flat, w) {
				t.Errorf("%s lacks %q", where, w)
			}
		}
	}
	signerInstall := func(t *testing.T) string {
		t.Helper()
		return string(readTestFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	}
	t.Run("prepare_per_backend", func(t *testing.T) {
		win := window(t, caRotationRunbook(t), &signingSection{id: "prepare", file: "ca-rotation.md", section: "1. Prepare the next key"})
		holds(t, `ca-rotation.md "1. Prepare the next key"`, win, []string{
			"tpm/user-g2.tpmkey", "tpm/user-g2.auth", "0x87 to 0x95", "15 slots", "never reused", "piv_no_free_slot", "location:",
			"line into the transcript", "ErrSlotOccupied", "slot already holds a key", "no generation row records", "ykman piv keys delete",
			"never on a restored database", "ykman piv reset", "the block of piv.md step 5", "after a refused prepare",
			"no YubiKey or physical TPM has run it", "never while a signed bundle waits to be installed",
		})
	})
	t.Run("remove_per_backend", func(t *testing.T) {
		data := caRotationRunbook(t)
		section := &signingSection{id: "remove", file: "ca-rotation.md", section: "Remove the old key and restart"}
		tpmWin := window(t, data, &signingSection{id: "remove_tpm", file: "ca-rotation.md", within: section, start: "- **tpm:**", end: "- **piv:**"})
		holds(t, `the tpm bullet of ca-rotation.md "Remove the old key and restart"`, tpmWin, []string{
			"tpm/user.tpmkey", "tpm/user.auth", "delete both files as the signer's user", "no YubiKey or physical TPM has run it",
		})
		pivWin := window(t, data, &signingSection{id: "remove_piv", file: "ca-rotation.md", within: section,
			start: "- **piv:**", end: "Start the signer only after retire-key exits 0"})
		holds(t, `the piv bullet of ca-rotation.md "Remove the old key and restart"`, pivWin, []string{
			"throwaway key", "mgmt-key-file", "never reused", "the block of piv.md step 5",
		})
	})
	t.Run("no_backend_refused_by_name", func(t *testing.T) {
		if strings.Contains(caRotationRunbook(t), "rotation_not_supported_on_backend") {
			t.Error("ca-rotation.md still says that a backend is refused rotation_not_supported_on_backend")
		}
	})
	t.Run("signer_install_per_backend", func(t *testing.T) {
		data := signerInstall(t)
		prepare := window(t, data, &signingSection{id: "prepare", file: "signer-install.md", section: "Prepare a CA key generation"})
		holds(t, `signer-install.md "Prepare a CA key generation"`, prepare, []string{
			"tpm/<role>-g<N>.tpmkey", "0x87 to 0x95", "piv_no_free_slot", "mgmt-key-file", "ErrSlotOccupied", "slot already holds a key",
			"no generation row records", "ykman piv keys delete", "never on a restored database", "ykman piv reset",
			"the block of piv.md step 5", "after a refused prepare", "never while a signed bundle waits to be installed",
		})
		remove := window(t, data, &signingSection{id: "remove", file: "signer-install.md", section: "Install a successor bundle: stop, install, start",
			start: "### Remove the old key after a switch", end: "Other refusals:"})
		holds(t, `signer-install.md "### Remove the old key after a switch"`, remove, []string{
			"throwaway key", "tpm/<role>.tpmkey", "delete both files as the signer's user",
		})
		// The restore subsection runs to the next "### " or "## " heading;
		// today it is the last of the file, so it runs to the end.
		restore := strings.Split(window(t, data, &signingSection{id: "restore", file: "signer-install.md", section: "Snapshot restore: check the clock first",
			start: "### Restore from before the last switch"}), "\n")
		for i := 1; i < len(restore); i++ {
			if strings.HasPrefix(restore[i], "### ") || strings.HasPrefix(restore[i], "## ") {
				restore = restore[:i]
				break
			}
		}
		holds(t, `signer-install.md "### Restore from before the last switch"`, strings.Join(restore, "\n"), []string{
			"ls -la /var/lib/keyroster-signer/tpm/", "a restore from before a prepare",
		})
	})
	t.Run("piv_mgmt_key_round_trip", func(t *testing.T) {
		// The block rules first, on fixtures, so that a wrong rule cannot
		// pass piv.md: each refused fixture is refused by the rule named
		// only.
		fixture := func(lines ...string) string {
			return "### 5. Remove the management key from the signer host\n\n```\n" + strings.Join(lines, "\n") + "\n```\n"
		}
		b := pivMgmtKeyBlock
		for _, c := range []struct {
			name string
			text string
			rule string // the one rule that refuses it; "" for accepted
		}{
			{"the five lines as written", fixture(b...), ""},
			{"a start between the fourth and the fifth line", fixture(b[0], b[1], b[2], b[3], "sudo systemctl start keyroster-signer.service", b[4]), "consecutive"},
			{"the fifth line without its shred", fixture(b[0], b[1], b[2], b[3], strings.Replace(b[4], `sudo runuser -u keyroster-signer -- shred -u "$K"; `, "", 1)), "consecutive"},
			{"a sixth line with a root redirect to $K", fixture(append(slices.Clone(b), `sudo runuser -u keyroster-signer -- true >"$K"`)...), "redirect"},
			{"a sixth line that removes $K as root", fixture(append(slices.Clone(b), `sudo rm -f "$K"`)...), "runuser"},
		} {
			got := pivMgmtKeyBlockProblems(c.text)
			only := len(got) > 0
			for _, p := range got {
				if !strings.HasPrefix(p, c.rule+": ") {
					only = false
				}
			}
			if (c.rule == "" && len(got) != 0) || (c.rule != "" && !only) {
				t.Errorf("block fixture %s: problems %q, want refused by the %q rule only (\"\" for accepted)", c.name, got, c.rule)
			}
		}
		data := string(readTestFile(t, filepath.Join("..", "..", "docs", "backends", "piv.md")))
		// The "## Setup" section of piv.md ends at the line "## Options",
		// so this window runs from step 5 up to that line.
		win := window(t, data, &signingSection{id: "step_5", file: "piv.md", section: "Setup", start: "### 5. Remove the management key from the signer host"})
		for _, p := range pivMgmtKeyBlockProblems(win) {
			t.Errorf("piv.md step 5: %s", p)
		}
		for _, l := range strings.Split(win, "\n") {
			if strings.TrimSpace(l) == "sudo shred -u /etc/keyroster-signer/piv/mgmt-key" {
				t.Errorf("piv.md step 5 shreds the management key as root, below a directory of the signer's user: %s", l)
			}
		}
		holds(t, "piv.md step 5", win, []string{
			"on every exit status", "only after the shred", "copy-on-write", "after a refused prepare", "did not run to its end",
		})
	})
	t.Run("piv_generation_slots_rule", func(t *testing.T) {
		data := string(readTestFile(t, filepath.Join("..", "..", "docs", "backends", "piv.md")))
		win := window(t, data, &signingSection{id: "generation_slots", file: "piv.md", section: "Generation slots"})
		holds(t, `piv.md "Generation slots"`, win, []string{
			"Never on a restored database before the restore section of", "Never while a signed bundle waits to be installed",
			"Never a key you keep in a generation slot for another use", "no stored generation", "it is stopped for the delete",
		})
	})
	t.Run("abort_removal_paths", func(t *testing.T) {
		// No block of the abort section binds $S, so its inline commands
		// name the state directory itself.
		win := window(t, caRotationRunbook(t), &signingSection{id: "abort", file: "ca-rotation.md", section: "Abort"})
		holds(t, `ca-rotation.md "Abort: withdraw the next CA key"`, win, []string{
			"/var/lib/keyroster-signer/software/user-g2.age", "/var/lib/keyroster-signer/tpm/user-g2.tpmkey",
			"/var/lib/keyroster-signer/tpm/user-g2.auth",
		})
		if strings.Contains(win, "$S") {
			t.Errorf(`ca-rotation.md "Abort: withdraw the next CA key" uses $S, which no block of that section binds`)
		}
	})
	t.Run("remove_piv_doctor", func(t *testing.T) {
		win := window(t, caRotationRunbook(t), &signingSection{id: "remove", file: "ca-rotation.md", section: "Remove the old key and restart"})
		holds(t, `ca-rotation.md "Remove the old key and restart"`, win, []string{
			"WARN draining_key_unchecked", "not doctor, show whether the key is still held",
		})
	})
	t.Run("software_key_after_restore", func(t *testing.T) {
		data := string(readTestFile(t, filepath.Join("..", "..", "docs", "security", "custody.md")))
		win := window(t, data, &signingSection{id: "software_ca_keys", file: "custody.md", section: "Software CA keys (KEY-06)"})
		holds(t, `custody.md "Software CA keys (KEY-06)"`, win, []string{
			"after a restore only once the restore section of", "has run to its end",
		})
	})
	t.Run("restore_lost_bundle_stop", func(t *testing.T) {
		// The bullet runs from its bold start to the next bullet of the
		// same list.
		win := window(t, signerInstall(t), &signingSection{id: "lost_bundle_install", file: "signer-install.md",
			section: "Snapshot restore: check the clock first", start: "- **A lost `bundle_install`:**",
			endNext: func(l string) bool { return strings.HasPrefix(l, "- ") }})
		holds(t, "signer-install.md's restore bullet on a lost bundle_install", win, []string{
			"stop: the bundle names a CA key generation that the restored database lacks", "is kept, not destroyed",
		})
	})
	t.Run("unrecorded_key_files_after_restore", func(t *testing.T) {
		// The software paragraph and the tpm paragraph, each read as a
		// window of its own, let an unrecorded file go only after the
		// restore section has run to its end, and the tpm paragraph's
		// sentence on the console texts says the same for both backends.
		data := signerInstall(t)
		section := &signingSection{id: "prepare", file: "signer-install.md", section: "Prepare a CA key generation"}
		softWin := window(t, data, &signingSection{id: "prepare_software", file: "signer-install.md", within: section,
			start: "With the software backend,", end: "With the tpm backend,"})
		holds(t, `the software paragraph of signer-install.md "Prepare a CA key generation"`, softWin, []string{
			"but only after the restore section has run to its end",
		})
		tpmWin := window(t, data, &signingSection{id: "prepare_tpm", file: "signer-install.md", within: section,
			start: "With the tpm backend,", end: "With the piv backend,"})
		holds(t, `the tpm paragraph of signer-install.md "Prepare a CA key generation"`, tpmWin, []string{
			"but only after the restore section has run to its end",
			"destroy such a file only once the restore section has run to its end, and keep it where that section stops on a lost generation",
		})
		if strings.Contains(normalizeSpace(window(t, data, section)), "both say to destroy such a file after a restore") {
			t.Errorf(`signer-install.md "Prepare a CA key generation" still says the console texts "both say to destroy such a file after a restore"`)
		}
		restore := window(t, data, &signingSection{id: "restore", file: "signer-install.md", section: "Snapshot restore: check the clock first"})
		holds(t, `signer-install.md "Snapshot restore: check the clock first"`, restore, []string{
			"but only once this restore has run to its end", "The same holds for a `<role>-g<N>.tpmkey` and `.auth` pair",
		})
	})
}
