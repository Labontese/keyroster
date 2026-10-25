//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// replayExtractScript is the extraction step of docs/runbooks/signer-install.md
// "A restore brings back the older trust bundle, policy and directory",
// step 3, verbatim after the runbook's three variable assignments (V, SAVED
// and D, which the test passes in the environment). The runbook runs it in
// bash -eu from a heredoc (replayExtractBlock), and so does the test, so
// that a failing line stops it for an operator as it does here. Keep the
// two in sync: TestRestoreReplaysLostDirectory runs this text, so it is
// the runbook's command that is run in CI e2e, not a reimplementation of
// it, and requireReplayBlock checks that the runbook still has it.
const replayExtractScript = `mkdir -p "$D"
grep '"kind":"directory_install"' "$SAVED" | grep -E ",\"version\":$V[,}]" > "$D/line"
test "$(wc -l < "$D/line")" -eq 1
grep -o '"directory":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json"
grep -o '"sigs":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json.sigs"
test -s "$D/directory.json"
test -s "$D/directory.json.sigs"
rm "$D/line"
echo "wrote the proposal of directory version $V to $D"
`

// replayExtractBlock is the runbook's whole extraction block: the bash
// -eu heredoc with the three variable assignments and replayExtractScript.
const replayExtractBlock = "bash -eu <<'EOF'\n" +
	"V=2                                   # the lost directory version\n" +
	"SAVED=/root/latest-saved.jsonl\n" +
	"D=/root/replay/v$V\n" +
	replayExtractScript +
	"EOF\n"

// requireReplayBlock: the runbook has replayExtractBlock as whole,
// consecutive lines, indented as the code block of step 3's first item.
func requireReplayBlock(t *testing.T, runbook string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(replayExtractBlock, "\n"), "\n")
	for i := range lines {
		lines[i] = "        " + lines[i]
	}
	if !strings.Contains(runbook, "\n"+strings.Join(lines, "\n")+"\n") {
		t.Fatalf("signer-install.md step 3 no longer has the extraction block that TestRestoreReplaysLostDirectory runs:\n%s", replayExtractBlock)
	}
}

// restoreRunbookChecks are the instructions of the same runbook section
// that TestRestoreReplaysLostDirectory carries out with its own pins and
// paths (exportLog and auditVerifyPins) rather than as the runbook's text:
// step 1's export of the restored log, step 2's two audit verify runs of
// the saved export, and the export and the two audit verify runs of the
// post-replay log ("After the replay, the new export is the baseline").
// TestRestoreRunbookChecks requires each in the runbook, so removing one
// of these instructions fails the e2e suite as removing an extraction
// line does.
var restoreRunbookChecks = []string{
	"--out /tmp/restored.jsonl",
	restoreVerify + "\n/root/latest-saved.jsonl",
	restoreVerify + "\n--previous /tmp/restored.jsonl /root/latest-saved.jsonl",
	"`--out /tmp/after-replay.jsonl`",
	restoreVerify + "\n/tmp/after-replay.jsonl",
	restoreVerify + "\n--previous /tmp/restored.jsonl /tmp/after-replay.jsonl",
}

// restoreVerify is the first line of the runbook's audit verify commands.
const restoreVerify = `keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \`

// The order and the condition of step 2's verification of the saved
// export (03-02 pre-merge review, round 3): it runs whenever step 2's
// first command fails, whatever that reports, and before any grep reads
// the saved export.
const (
	// restoreFirstCheck is the end of step 2's first command.
	restoreFirstCheck = `--previous /root/latest-saved.jsonl /tmp/restored.jsonl`
	// restoreSavedVerify is the two audit verify runs of the saved export.
	restoreSavedVerify = restoreVerify + "\n/root/latest-saved.jsonl\n" +
		restoreVerify + "\n--previous /tmp/restored.jsonl /root/latest-saved.jsonl"
	// restoreSavedVerifyIf is the condition the runbook puts on them.
	restoreSavedVerifyIf = "If it fails, whatever it reports (`log shrank`, `log rewritten` or another refusal), verify the saved export itself"
	// restoreSavedStop is what to do when either fails.
	restoreSavedStop = "Both must pass. If either fails, do not use the saved export at all"
	// restoreShrankGate is the condition of 894a6c3, under which a saved
	// export reported as rewritten was read unverified.
	restoreShrankGate = "When it reports `log shrank`"
)

// restoreSavedGreps are the runbook's greps of the saved export: step 2's
// bundle version and directory install count, step 3's list and step 3's
// extraction. restoreSavedGrep finds any grep of it.
var (
	restoreSavedGreps = []string{
		`grep -o '"bundle_version":[0-9]*' /root/latest-saved.jsonl | tail -n 1`,
		`grep -c '"kind":"directory_install"' /root/latest-saved.jsonl`,
		`grep -n -o '"kind":"\(bundle\|directory\)_install"' /root/latest-saved.jsonl`,
		`grep '"kind":"directory_install"' "$SAVED"`,
	}
	restoreSavedGrep = regexp.MustCompile(`grep (?:-[a-zA-Z]+ )*'[^']*' (?:/root/latest-saved\.jsonl|"\$SAVED")`)
)

// TestRestoreRunbookChecks: signer-install.md still has every instruction
// of restoreRunbookChecks. The runbook and each check are compared with
// every line's leading and trailing space trimmed; a check of more than
// one line must be whole lines of the runbook. Step 2's verification of
// the saved export must also be unconditional on what the first command
// reports and come before every grep of the saved export (round 3).
func TestRestoreRunbookChecks(t *testing.T) {
	trim := func(s string) string {
		l := strings.Split(s, "\n")
		for i := range l {
			l[i] = strings.TrimSpace(l[i])
		}
		return strings.Join(l, "\n")
	}
	raw := string(readFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	requireReplayBlock(t, raw)
	runbook := "\n" + trim(raw) + "\n"
	for _, c := range restoreRunbookChecks {
		want := trim(c)
		if strings.Contains(want, "\n") {
			want = "\n" + want + "\n"
		}
		if !strings.Contains(runbook, want) {
			t.Errorf("signer-install.md no longer has %q, which TestRestoreReplaysLostDirectory carries out", c)
		}
	}

	// The order, on the runbook's restore section with its white space
	// collapsed, so that a sentence may wrap anywhere.
	squash := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	section := runbook
	if i := strings.Index(section, "### A restore brings back the older trust bundle"); i >= 0 {
		section = section[i:]
	} else {
		t.Fatal("signer-install.md has no section \"A restore brings back the older trust bundle\"")
	}
	section = squash(section)
	if strings.Contains(section, squash(restoreShrankGate)) {
		t.Errorf("signer-install.md verifies the saved export only %q; a log reported as rewritten is then read unverified", restoreShrankGate)
	}
	pos := func(what, s string) int {
		i := strings.Index(section, squash(s))
		if i < 0 {
			t.Fatalf("signer-install.md has no %s: %q", what, s)
		}
		return i
	}
	first := pos("step 2 first command", restoreFirstCheck)
	cond := pos("unconditional verification of the saved export", restoreSavedVerifyIf)
	block := pos("verification of the saved export", restoreSavedVerify)
	stop := pos("rule for a saved export that does not verify", restoreSavedStop)
	if first >= cond || cond >= block || block >= stop {
		t.Errorf("signer-install.md step 2 is out of order: first command at %d, %q at %d, the saved export's audit verify runs at %d, %q at %d",
			first, restoreSavedVerifyIf, cond, block, restoreSavedStop, stop)
	}
	for _, g := range restoreSavedGreps {
		pos("grep of the saved export", g)
	}
	greps := restoreSavedGrep.FindAllStringIndex(section, -1)
	if len(greps) < len(restoreSavedGreps) {
		t.Errorf("found %d greps of the saved export, want at least %d", len(greps), len(restoreSavedGreps))
	}
	for _, g := range greps {
		if g[0] < stop {
			t.Errorf("signer-install.md greps the saved export (%q) before it is verified", section[g[0]:g[1]])
		}
	}
}

// TestRestoreReplaysLostDirectory runs the signer restore procedure of
// signer-install.md step 3 on a test signer (03-02, D-20, review A-IN-01).
// Directory v1 (the first admin's approval) is installed; the signer is
// stopped and its signer.db copied; v2 (a role only, no passkey binding)
// is installed with keyroster directory install and the log exported. The
// signer is stopped, the copy restored and the signer started: it reports
// v1. The saved export verifies on its own and with the restored export
// as --previous; v2's directory.json and directory.json.sigs are written
// from it with the runbook's own commands and replayed with keyroster
// directory install: the signer reports v2 with the same bytes, and the
// new export verifies on its own and extends the restored export. It is
// no extension of the saved export (the replayed leaf is new), so audit
// verify --previous refuses it: the runbook says the post-replay export
// is the next baseline.
//
// A lost version that binds a passkey is not run here: the server refuses
// it with 409 credential_not_pending, and the runbook labels that case
// UNVERIFIED.
func TestRestoreReplaysLostDirectory(t *testing.T) {
	env := startServerEnv(t, serverOpts{StoppableSigner: true})
	stop := env.StopSigner
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	_, fp := enroll(t, env, admin, "admin1", webauthn.AlgEdDSA)
	if code, out, errOut := env.keyroster(t, admin, "", "user", "approve", "admin1", "--fingerprint", fp, "--yes"); code != 0 ||
		!strings.Contains(out, "The server reports directory version 1 installed") {
		t.Fatalf("user approve admin1: exit %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if resp, _ := signerDirectory(t, env); resp.Version != 1 {
		t.Fatalf("signer directory version %d, want 1", resp.Version)
	}

	// 1. The backup: signer.db and whatever SQLite files belong to it,
	// taken from a stopped signer.
	stop()
	backup := t.TempDir()
	copyDB(t, env.Signer.StateDir, backup)
	stop = serveStoppable(t, env.Signer)

	// 2. v2 after the backup, through a proposal, as an admin would.
	work := t.TempDir()
	if code, out, errOut := env.keyroster(t, admin, work, "role", "add", "ops", "--max-ttl", "1h", "--out", "V2", "--yes"); code != 0 {
		t.Fatalf("role add ops --out V2: exit %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if code, out, errOut := env.keyroster(t, admin, work, "directory", "install", "V2"); code != 0 ||
		!strings.Contains(out, "The server reports directory version 2 installed") {
		t.Fatalf("directory install V2: exit %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	v2, _ := signerDirectory(t, env)
	if v2.Version != 2 {
		t.Fatalf("signer directory version %d, want 2", v2.Version)
	}
	saved := env.Signer.exportLog(t)
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, saved); code != 0 || !strings.Contains(out, "directory installs 2") {
		t.Fatalf("audit verify of the saved export: exit %d:\n%s", code, out)
	}

	// 3. The restore: the copy replaces signer.db, and the newer WAL files
	// go, or SQLite would replay them onto the old database.
	// The restored log is exported while the signer is stopped (step 1).
	stop()
	restoreDB(t, backup, env.Signer.StateDir)
	restored := env.Signer.exportLog(t)
	serveStoppable(t, env.Signer) // stopped at cleanup, as every daemon of the harness
	if resp, _ := signerDirectory(t, env); resp.Version != 1 {
		t.Fatalf("restored signer directory version %d, want 1", resp.Version)
	}
	// Step 2: the saved export verifies on its own pins (above), and the
	// restored log is a prefix of it.
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, saved, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <saved export>: exit %d:\n%s", code, out)
	}

	// 4. The proposal from the saved export, with the runbook's commands
	// (which must still be the runbook's).
	requireReplayBlock(t, string(readFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md"))))
	replay := filepath.Join(t.TempDir(), "replay", "v2")
	cmd := exec.Command("bash", "-eu")
	cmd.Stdin = strings.NewReader(replayExtractScript)
	cmd.Env = append(os.Environ(), "V=2", "SAVED="+saved, "D="+replay)
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "wrote the proposal of directory version 2") {
		t.Fatalf("the runbook's extraction failed: %v\n%s", err, out)
	}
	doc := readFile(t, filepath.Join(replay, "directory.json"))
	sigs := readFile(t, filepath.Join(replay, "directory.json.sigs"))
	if !bytes.Equal(doc, v2.Directory) || !bytes.Equal(sigs, v2.Sigs) {
		t.Fatal("the extracted proposal is not the directory and signatures the signer installed as v2")
	}
	// The same bytes as the verified leaf carries, not only the
	// unverified "decoded" part of the line.
	body := directoryInstallLeaf(t, saved, 2)
	if !bytes.Equal(doc, body.Directory) || !bytes.Equal(sigs, body.Sigs) {
		t.Fatal("the extracted proposal differs from the directory_install leaf of v2")
	}

	// 5. The replay. keyroster-server caches the signer's status for up
	// to 5 s (statusTTL); wait it out, so the CLI's base check reads the
	// restored v1 and not the v2 the server saw before the restore.
	time.Sleep(6 * time.Second)
	code, out, errOut := env.keyroster(t, admin, "", "directory", "install", replay)
	if code != 0 || !strings.Contains(out, "The server reports directory version 2 installed") {
		t.Fatalf("directory install of the replayed v2: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	after, _ := signerDirectory(t, env)
	if after.Version != 2 || !bytes.Equal(after.Directory, v2.Directory) {
		t.Fatalf("signer directory after the replay: version %d, same bytes as v2: %v", after.Version, bytes.Equal(after.Directory, v2.Directory))
	}

	// 6. The new log verifies on its own and is the next baseline; it is
	// not an extension of the pre-restore export.
	replayed := env.Signer.exportLog(t)
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, replayed); code != 0 || !strings.Contains(out, "directory installs 2") {
		t.Fatalf("audit verify after the replay: exit %d:\n%s", code, out)
	}
	// It extends the restored log, so nothing was cut back or rewritten
	// between the restore and the replay.
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, replayed, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <post-replay export>: exit %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, replayed, "--previous", saved); code == 0 {
		t.Fatalf("audit verify --previous <pre-restore export> accepted the post-replay export:\n%s", out)
	}
}

// copyDB copies signer.db and its -wal and -shm files, where present, from
// the state directory to dir.
func copyDB(t *testing.T, state, dir string) {
	t.Helper()
	n := 0
	for _, name := range []string{"signer.db", "signer.db-wal", "signer.db-shm"} {
		data, err := os.ReadFile(filepath.Join(state, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if _, err := os.Stat(filepath.Join(dir, "signer.db")); err != nil {
		t.Fatalf("no signer.db copied (%d files): %v", n, err)
	}
}

// restoreDB removes signer.db and its -wal and -shm files from the state
// directory and puts back the ones in dir.
func restoreDB(t *testing.T, dir, state string) {
	t.Helper()
	for _, name := range []string{"signer.db", "signer.db-wal", "signer.db-shm"} {
		if err := os.Remove(filepath.Join(state, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	copyDB(t, dir, state)
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: a file the test wrote
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// directoryInstallLeaf returns the body of the directory_install leaf of
// version v in export, decoded from the leaf bytes.
func directoryInstallLeaf(t *testing.T, export string, v uint64) *tlog.DirectoryInstallBody {
	t.Helper()
	f, err := os.Open(export) //nolint:gosec // G304: the test's export
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var l struct {
				Leaf string `json:"leaf"`
			}
			if err := json.Unmarshal(line, &l); err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(l.Leaf)
			if err != nil {
				t.Fatal(err)
			}
			if leaf, err := tlog.DecodeLeaf(raw); err == nil && leaf.Kind == tlog.KindDirectoryInstall {
				b, err := tlog.DecodeDirectoryInstallBody(leaf.Body)
				if err != nil {
					t.Fatal(err)
				}
				if b.Version == v {
					return b
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("no directory_install leaf of version %d in %s", v, export)
	return nil
}
