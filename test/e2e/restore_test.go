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
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// replayExtractScript is the extraction step of docs/runbooks/signer-install.md
// "A restore brings back the older trust bundle, policy and directory",
// step 3, verbatim after the runbook's three variable assignments (V, SAVED
// and D, which the test passes in the environment). Keep the two in sync:
// TestRestoreReplaysLostDirectory runs this text, so it is the runbook's
// command that is run in CI e2e, not a reimplementation of it.
const replayExtractScript = `set -eu
mkdir -p "$D"
grep '"kind":"directory_install"' "$SAVED" | grep -E ",\"version\":$V[,}]" > "$D/line"
test "$(wc -l < "$D/line")" -eq 1
grep -o '"directory":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json"
grep -o '"sigs":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json.sigs"
test -s "$D/directory.json"
test -s "$D/directory.json.sigs"
rm "$D/line"
`

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
	// Step 3's first item: the saved export verifies on its own pins
	// (above), and the restored log is a prefix of it.
	if code, out := auditVerifyPins(t, env.Signer.RootFingerprints, saved, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <saved export>: exit %d:\n%s", code, out)
	}

	// 4. The proposal from the saved export, with the runbook's commands
	// (which must still be the runbook's).
	runbook := string(readFile(t, filepath.Join("..", "..", "docs", "runbooks", "signer-install.md")))
	for _, l := range strings.Split(strings.TrimSpace(replayExtractScript), "\n")[1:] {
		if !strings.Contains(runbook, "\n        "+l+"\n") {
			t.Fatalf("signer-install.md step 3 no longer has the line %q that this test runs", l)
		}
	}
	replay := filepath.Join(t.TempDir(), "replay", "v2")
	cmd := exec.Command("bash", "-c", replayExtractScript)
	cmd.Env = append(os.Environ(), "V=2", "SAVED="+saved, "D="+replay)
	if out, err := cmd.CombinedOutput(); err != nil {
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
