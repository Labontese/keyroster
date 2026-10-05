//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// auditEnv is a user CA in an agent and a signer whose state directory and
// log key the test can reach.
type auditEnv struct {
	caKey  string
	caFP   string
	agent  string
	signer *signerProc
}

func newAuditEnv(t *testing.T) *auditEnv {
	t.Helper()
	dir := t.TempDir()
	caKey := filepath.Join(dir, "user_ca")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user-ca", "-f", caKey)
	env := &auditEnv{caKey: caKey, caFP: fingerprint(t, caKey+".pub")}
	env.agent = startAgent(t)
	sshAdd(t, env.agent, caKey)
	env.signer = startSignerProc(t,
		"--allow-uid", strconv.Itoa(os.Getuid()),
		"--backend", "agent",
		"--backend-opt", "socket="+env.agent,
		"--user-ca-fp", env.caFP)
	return env
}

// exportLog runs keyroster-signer export-log against the running signer's
// state directory and returns the export file.
func (e *auditEnv) exportLog(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "log.jsonl")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, signerBin, "export-log", "--state-dir", e.signer.StateDir, "--out", out)
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keyroster-signer export-log: %v\n%s", err, b)
	}
	return out
}

// auditVerify runs keyroster audit verify and returns its exit code and
// output.
func auditVerify(t *testing.T, logPub, export string, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{"audit", "verify", "--log-key", logPub}, extra...)
	return runKeyroster(t, append(args, export)...)
}

// TestAuditVerifiesIssuance completes the Walking Skeleton: three
// certificates are issued (each logged with a signed checkpoint before it
// is released), one of them logs in to real sshd, and the exported log
// verifies end to end against the pinned log key.
func TestAuditVerifiesIssuance(t *testing.T) {
	login := currentUser(t)
	env := newAuditEnv(t)

	var keys []string
	for i := range 3 {
		key := newUserKey(t, "id_audit"+strconv.Itoa(i))
		out := issue(t, env.signer.Socket,
			"--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		if want := "log leaf: " + strconv.Itoa(i); !strings.Contains(out, want) {
			t.Fatalf("issue #%d output lacks %q:\n%s", i, want, out)
		}
		keys = append(keys, key)
	}

	port := startSSHD(t, sshdOptions{UserCAPub: env.caKey + ".pub", Principals: map[string][]string{login: {login}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: keys[0], Cert: keys[0] + "-cert.pub", User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with a logged certificate exited %d:\n%s", code, out)
	}

	export := env.exportLog(t)
	code, out := auditVerify(t, env.signer.LogPub, export)
	if code != 0 {
		t.Fatalf("keyroster audit verify exited %d:\n%s", code, out)
	}
	if !strings.HasPrefix(out, "OK: 3 entries,") || !strings.Contains(out, "issued 3") {
		t.Fatalf("audit verify output = %q, want OK with 3 entries and 3 issued", out)
	}
	t.Logf("audit verify: %s", strings.TrimSpace(out))

	// The pinned key matters: another key's verifier rejects the export.
	otherPub, _ := addLogKey(t, startAgent(t), t.TempDir())
	if code, out := auditVerify(t, otherPub, export); code == 0 {
		t.Fatalf("audit verify with another log key exited 0:\n%s", out)
	}
}

// editExport parses an export file into one map per line, lets edit change
// or replace them, and writes the result to a new file.
func editExport(t *testing.T, export string, edit func(lines []map[string]any) []map[string]any) string {
	t.Helper()
	data, err := os.ReadFile(export) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, m)
	}
	lines = edit(lines)
	var b strings.Builder
	for _, m := range lines {
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(out)
		b.WriteByte('\n')
	}
	path := filepath.Join(t.TempDir(), "edited.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAuditDetectsTampering runs the CLI against modified exports of a real
// signer's log, and checks --previous across two exports of a growing log.
func TestAuditDetectsTampering(t *testing.T) {
	login := currentUser(t)
	env := newAuditEnv(t)
	issueOne := func() {
		key := newUserKey(t, "id_t")
		issue(t, env.signer.Socket, "--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	}
	issueOne()
	issueOne()
	first := env.exportLog(t)
	issueOne()
	second := env.exportLog(t)

	if code, out := auditVerify(t, env.signer.LogPub, second, "--previous", first); code != 0 {
		t.Fatalf("verify --previous <earlier export> exited %d:\n%s", code, out)
	}
	if code, out := auditVerify(t, env.signer.LogPub, first, "--previous", second); code == 0 || !strings.Contains(out, "log shrank") {
		t.Fatalf("verify of the earlier export against the later checkpoint exited %d, want log shrank:\n%s", code, out)
	}

	flipped := editExport(t, second, func(lines []map[string]any) []map[string]any {
		raw, err := base64.StdEncoding.DecodeString(lines[1]["leaf"].(string))
		if err != nil {
			t.Fatal(err)
		}
		raw[64] ^= 1 // inside the request digest of an issue leaf
		lines[1]["leaf"] = base64.StdEncoding.EncodeToString(raw)
		return lines
	})
	if code, out := auditVerify(t, env.signer.LogPub, flipped); code != 1 || !strings.Contains(out, "root mismatch") {
		t.Fatalf("verify of a flipped leaf byte exited %d, want 1 with root mismatch:\n%s", code, out)
	}
	removed := editExport(t, second, func(lines []map[string]any) []map[string]any {
		return append(lines[:1:1], lines[2:]...)
	})
	if code, out := auditVerify(t, env.signer.LogPub, removed); code != 1 {
		t.Fatalf("verify of an export without one leaf exited %d, want 1:\n%s", code, out)
	}
	decodedOnly := editExport(t, second, func(lines []map[string]any) []map[string]any {
		lines[0]["decoded"] = map[string]any{"kind": "issue", "principals": []string{"root"}}
		return lines
	})
	if code, out := auditVerify(t, env.signer.LogPub, decodedOnly); code != 0 {
		t.Fatalf("verify after editing only decoded exited %d:\n%s", code, out)
	}
}
