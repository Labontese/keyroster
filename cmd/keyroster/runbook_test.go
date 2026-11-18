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
				"checks every value", "next CA fingerprint as read from the signer console by"}},
		{id: "ca_next_sign", file: "ca-rotation.md", section: "Ceremony 1",
			want: caChecks("none -> next", "fingerprint as read from the signer console")},
		{id: "ca_abort_sign", file: "ca-rotation.md", section: "Abort",
			want: caChecks("next -> retired")},
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
		for _, want := range []string{`runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"'`, "runuser -u keyroster-signer -- rm -f"} {
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
// its end state, naming no plan of this rotation outside a code span (the
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
	if bare := inlineSpan.ReplaceAllString(prose.String(), ""); strings.Contains(bare, "03-12e") {
		t.Error("signer-install.md names 03-12e outside a code span; describe the rotation as written in its end state")
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
