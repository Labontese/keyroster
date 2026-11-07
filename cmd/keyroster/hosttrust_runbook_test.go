package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// htrbSelf is this file, which cited_tests_exist does not read.
const htrbSelf = "hosttrust_runbook_test.go"

// htrbDoc reads a runbook under docs/runbooks.
func htrbDoc(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", name)) //nolint:gosec // G304: a runbook of this repository
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// htrbFlat collapses every run of white space to one space and drops the
// blockquote markers, so a sentence wrapped inside a quote still matches.
func htrbFlat(s string) string {
	var out []string
	for _, f := range strings.Fields(s) {
		if f != ">" {
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

// htrbSection returns the text from the line heading to the next heading
// of the same or a higher level outside a code fence ("" when heading is
// missing).
func htrbSection(doc, heading string) string {
	i := strings.Index(doc, "\n"+heading+"\n")
	if i < 0 {
		return ""
	}
	level := len(strings.Fields(heading)[0])
	lines := strings.Split(doc[i+1:], "\n")
	fence := false
	for n, line := range lines[1:] {
		if strings.HasPrefix(line, "```") {
			fence = !fence
			continue
		}
		if fence {
			continue
		}
		if h := len(line) - len(strings.TrimLeft(line, "#")); h >= 1 && h <= level && strings.HasPrefix(line[h:], " ") {
			return strings.Join(lines[:n+1], "\n")
		}
	}
	return strings.Join(lines, "\n")
}

// htrbBetween returns the text of doc from the first occurrence of from to
// the next occurrence of to ("" when from is missing).
func htrbBetween(doc, from, to string) string {
	i := strings.Index(doc, from)
	if i < 0 {
		return ""
	}
	if j := strings.Index(doc[i:], to); j >= 0 {
		return doc[i : i+j]
	}
	return doc[i:]
}

// htrbWant fails for every token that text does not contain, white space
// collapsed on both sides.
func htrbWant(t *testing.T, what, text string, tokens ...string) {
	t.Helper()
	if text == "" {
		t.Fatalf("%s: the section is missing", what)
	}
	flat := htrbFlat(text)
	for _, tok := range tokens {
		if !strings.Contains(flat, htrbFlat(tok)) {
			t.Errorf("%s lacks %q", what, tok)
		}
	}
}

// htrbNewSections are the runbook texts 03-09b added, by name.
func htrbNewSections(t *testing.T) map[string]string {
	t.Helper()
	enroll, revoke, hostSetup := htrbDoc(t, "enroll-user.md"), htrbDoc(t, "revoke.md"), htrbDoc(t, "host-setup.md")
	return map[string]string{
		"enroll-user.md Trusting hosts without TOFU": htrbSection(enroll, "## Trusting hosts without TOFU"),
		"revoke.md 4b":                                htrbSection(revoke, "## 4b. Revoking a host: `keyroster revoke host`"),
		"host-setup.md Ports to Manual recovery":      htrbBetween(hostSetup, "**Ports.**", "## Manual recovery"),
		"host-setup.md Removing a host, the removal":  htrbBetween(hostSetup, "A host that holds host certificates: the removal revokes them first", "An enrolled agent that the directory approved once"),
		"host-setup.md approval binding (QB-4) block": htrbBetween(hostSetup, "The `agent identity:` line", "(Owner decision QB-4, 03-09b.)"),
	}
}

// TestHostTrustRunbooks (03-09b, D-20): the runbooks say what 03-09b
// built, label it with what exercises it, and no longer name 03-09b as the
// future.
func TestHostTrustRunbooks(t *testing.T) {
	t.Run("enroll_user_trusting_hosts", func(t *testing.T) {
		doc := htrbDoc(t, "enroll-user.md")
		sec := htrbSection(doc, "## Trusting hosts without TOFU")
		htrbWant(t, "item 1, the files", sec, "keyroster_known_hosts", "keyroster_revoked_hosts.krl", "keyroster_ssh_config", "host-trust.json",
			"before the first Host or Match line", "Include ~/.ssh/keyroster_ssh_config", "never falls back to `~/.ssh/known_hosts`")
		htrbWant(t, "item 2, refreshing", sec, "keyroster known-hosts sync", "--no-known-hosts", "Host trust refreshed (directory vN, KRL vK, M names).",
			"Host trust partly refreshed: revocations only", "Host trust not refreshed:", "exits 0 when refreshed or unchanged, 3 when partly refreshed, and 1 when nothing was written")
		htrbWant(t, "item 3, T-03-100", sec, "T-03-100", "whole admin-signed directory", "no secrets", "one installation serves one organisation")
		htrbWant(t, "item 4, the lag", sec, "T-03-240", "next login or sync", "never prompted")
		htrbWant(t, "item 5, the costs", sec, "unreachable until its host has a host certificate", "Names removed before the client's first verified refresh", "--keys")
		htrbWant(t, "item 6, ports", sec, "D7", "Port <n>", "HostKeyAlias <that same name>", "after the Include", "QB-6", "NEVERMATCH")
		htrbWant(t, "item 7, freshness and rollback", sec, "24 hours", "signer restore", "older trust bundle", "stored ops key", "older_bundle_freezes_ca_lines_krl_still_written")
		htrbWant(t, "item 8, starting over", sec, "delete the three files and the state file", "4 MiB")
		htrbWant(t, "item 9, the home", sec, "account database", "$HOME", "QB-5", "NSS or LDAP", "home_differs_from_account_refuses")
		htrbWant(t, "Logging in", htrbSection(doc, "## Logging in"), "--no-known-hosts", "(#trusting-hosts-without-tofu)")
	})
	t.Run("revoke_revoking_a_host", func(t *testing.T) {
		doc := htrbDoc(t, "revoke.md")
		sec := htrbSection(doc, "## 4b. Revoking a host: `keyroster revoke host`")
		htrbWant(t, "revoke.md 4b", sec, "keyroster revoke host NAME [--keys] [--yes]", "first sweep", "second sweep", "--keys", "never leaves the KRL",
			"3 beats 4", "1 beats both", "ANY newer version releases that hold", "cert_revoked", "keyroster revoke host OLDNAME", "serial or key ID",
			"keyroster host forget", "Certificates that a signer recovery kept are not covered by this revoke", "keyroster known-hosts sync")
		htrbWant(t, "revoke.md section 7", htrbSection(doc, "## 7. The audit log after a revocation"), "Certificates that a signer recovery kept are not covered by this revoke")
		htrbWant(t, "revoke.md refusals", htrbSection(doc, "## 5. Refusals"), "this signer revokes user and host subjects only", "upgrade the signer")
	})
	t.Run("revoke_placeholders_gone", func(t *testing.T) {
		docs := htrbDoc(t, "revoke.md") + "\n" + htrbDoc(t, "host-setup.md")
		for _, row := range []struct{ name, re string }{
			{"revoke_md_nothing_installs_yet", `nothing\s+installs\s+(it|the\s+KRL)\s+there\s+yet`},
			{"revoke_md_sync_arrives", `known-hosts\s+sync\s+arrives`},
			{"revoke_md_subjects_arrive", `host\s+and\s+machine\s+subjects\s+arrive\s+with\s+03-09b`},
			{"revoke_md_user_subjects_only", `revokes\s+user\s+subjects\s+only`},
			{"host_setup_until_03_09b", `until\s+03-09b`},
			{"host_setup_clients_are_03_09b", `setting\s+up\s+clients\s+is\s+03-09b`},
		} {
			if regexp.MustCompile(`(?is)` + row.re).MatchString(docs) {
				t.Errorf("placeholder present: %s", row.name)
			}
		}
	})
	t.Run("host_setup_approval_and_removal", func(t *testing.T) {
		doc := htrbDoc(t, "host-setup.md")
		htrbWant(t, "host-setup.md step 4", htrbBetween(doc, "**4. Approve the host", "**Refusals.**"), "is informational", "nothing binds the approval to it",
			"`--host-key`, the exact set", "host forget --identity", "QB-4")
		htrbWant(t, "host-setup.md Host certificates", htrbBetween(doc, "**Ports.**", "## Manual recovery"), "enroll-user.md", "run `keyroster revoke host <name>`")
		htrbWant(t, "host-setup.md Removing a host", htrbSection(doc, "## Removing a host"), "the removal revokes them first",
			"Installing version N first revokes every live host certificate of", "`--yes` or the prompt is consent",
			"`keyroster revoke host NAME` also works after the removal", "within the last 30 days", "keyroster revoke host OLDNAME",
			"revoked by serial", "a signer recovery kept", "needs quorum", "swept once more after the install",
			"TestEditRevokesLossesBeforeInstall", "TestDirectoryInstallLosses")
	})
	t.Run("labels_on_new_sections", func(t *testing.T) {
		for name, sec := range htrbNewSections(t) {
			low := strings.ToLower(htrbFlat(sec))
			if sec == "" {
				t.Errorf("%s: missing", name)
				continue
			}
			if name == "host-setup.md approval binding (QB-4) block" {
				if !strings.Contains(low, "run in ci") {
					t.Errorf("%s names no CI test", name)
				}
				continue
			}
			if !strings.Contains(low, "run in ci e2e (03-09b)") && !strings.Contains(low, "run in ci (03-09b)") {
				t.Errorf("%s has no 03-09b CI label", name)
			}
			if !strings.Contains(sec, "UNVERIFIED") {
				t.Errorf("%s says nothing is UNVERIFIED", name)
			}
		}
	})
	t.Run("cited_tests_exist", func(t *testing.T) {
		// This file quotes cited subtest names itself (htrbWant's tokens),
		// so it is left out: a renamed subtest must not be found here.
		self, err := filepath.Abs(htrbSelf)
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
		if strings.Contains(src.String(), "func TestHostTrustRunbooks(") {
			t.Fatal("the runbook test itself was read: a cited subtest name it quotes would satisfy the check")
		}
		all := src.String()
		cite := regexp.MustCompile("`(Test[A-Za-z0-9_]+)((?:/[a-z0-9_]+)*)`")
		for name, sec := range htrbNewSections(t) {
			for _, m := range cite.FindAllStringSubmatch(sec, -1) {
				if !strings.Contains(all, "func "+m[1]+"(") {
					t.Errorf("%s cites %s, which no _test.go file defines", name, m[1])
				}
				for _, sub := range strings.Split(strings.TrimPrefix(m[2], "/"), "/") {
					if sub != "" && !strings.Contains(all, `"`+sub+`"`) {
						t.Errorf("%s cites %s%s, but no test names a subtest %q", name, m[1], m[2], sub)
					}
				}
			}
		}
	})
}
