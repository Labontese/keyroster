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

// bootstrapLeaves is the number of log entries a bootstrapped signer
// starts with: ca_init and bundle_install.
const bootstrapLeaves = 2

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
	env := bootstrapSigner(t, bootstrapOpts{})

	var keys []string
	for i := range 3 {
		key := newUserKey(t, "id_audit"+strconv.Itoa(i))
		out := env.issue(t,
			"--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		if want := "log leaf: " + strconv.Itoa(bootstrapLeaves+i); !strings.Contains(out, want) {
			t.Fatalf("issue #%d output lacks %q:\n%s", i, want, out)
		}
		keys = append(keys, key)
	}

	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {login}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: keys[0], Cert: keys[0] + "-cert.pub", User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with a logged certificate exited %d:\n%s", code, out)
	}

	export := env.exportLog(t)
	code, out := auditVerify(t, env.LogPub, export)
	if code != 0 {
		t.Fatalf("keyroster audit verify exited %d:\n%s", code, out)
	}
	if !strings.HasPrefix(out, "OK: 5 entries,") || !strings.Contains(out, "issued 3") {
		t.Fatalf("audit verify output = %q, want OK with 5 entries (ca_init, bundle_install, 3 issuances) and 3 issued", out)
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
	env := bootstrapSigner(t, bootstrapOpts{})
	issueOne := func() {
		key := newUserKey(t, "id_t")
		env.issue(t, "--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	}
	issueOne()
	issueOne()
	first := env.exportLog(t)
	issueOne()
	second := env.exportLog(t)

	if code, out := auditVerify(t, env.LogPub, second, "--previous", first); code != 0 {
		t.Fatalf("verify --previous <earlier export> exited %d:\n%s", code, out)
	}
	if code, out := auditVerify(t, env.LogPub, first, "--previous", second); code == 0 || !strings.Contains(out, "log shrank") {
		t.Fatalf("verify of the earlier export against the later checkpoint exited %d, want log shrank:\n%s", code, out)
	}

	flipped := editExport(t, second, func(lines []map[string]any) []map[string]any {
		second := bootstrapLeaves + 1 // the second issue leaf
		raw, err := base64.StdEncoding.DecodeString(lines[second]["leaf"].(string))
		if err != nil {
			t.Fatal(err)
		}
		raw[64] ^= 1 // inside the request digest of an issue leaf
		lines[second]["leaf"] = base64.StdEncoding.EncodeToString(raw)
		return lines
	})
	if code, out := auditVerify(t, env.LogPub, flipped); code != 1 || !strings.Contains(out, "root mismatch") {
		t.Fatalf("verify of a flipped leaf byte exited %d, want 1 with root mismatch:\n%s", code, out)
	}
	removed := editExport(t, second, func(lines []map[string]any) []map[string]any {
		second := bootstrapLeaves + 1
		return append(lines[:second:second], lines[second+1:]...)
	})
	if code, out := auditVerify(t, env.LogPub, removed); code != 1 {
		t.Fatalf("verify of an export without one leaf exited %d, want 1:\n%s", code, out)
	}
	decodedOnly := editExport(t, second, func(lines []map[string]any) []map[string]any {
		lines[bootstrapLeaves]["decoded"] = map[string]any{"kind": "issue", "principals": []string{"root"}}
		return lines
	})
	if code, out := auditVerify(t, env.LogPub, decodedOnly); code != 0 {
		t.Fatalf("verify after editing only decoded exited %d:\n%s", code, out)
	}
}

// TestRefusalsAreAudited (D-14): refused requests reach the Merkle log, so
// three refused keyroster ca issue calls are three refusal entries in the
// exported, verified log; and serve documents the refusal rate flags.
func TestRefusalsAreAudited(t *testing.T) {
	login := currentUser(t)
	env := bootstrapSigner(t, bootstrapOpts{})
	key := newUserKey(t, "id_refused")
	for _, principal := range []string{"*", "Alice", "a,b"} {
		code, out := env.runIssue(t,
			"--pubkey", key+".pub", "--principal", principal, "--subject", "u:"+login, "--ttl", "10m")
		if code != 1 || !strings.Contains(out, "bad_principal") {
			t.Fatalf("ca issue --principal %q exited %d, want 1 with bad_principal:\n%s", principal, code, out)
		}
	}
	env.issue(t, "--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")

	export := env.exportLog(t)
	code, out := auditVerify(t, env.LogPub, export, "--json")
	if code != 0 {
		t.Fatalf("audit verify exited %d:\n%s", code, out)
	}
	var res struct {
		Entries uint64            `json:"entries"`
		Issued  int               `json:"issued"`
		Kinds   map[string]uint64 `json:"kinds"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("audit verify --json: %v\n%s", err, out)
	}
	if res.Entries != bootstrapLeaves+4 || res.Issued != 1 || res.Kinds["refusal"] != 3 ||
		res.Kinds["ca_init"] != 1 || res.Kinds["bundle_install"] != 1 {
		t.Fatalf("audit verify = %+v, want 6 entries: ca_init, bundle_install, 3 refusals and 1 issuance", res)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	help, _ := exec.CommandContext(ctx, signerBin, "serve", "--help").CombinedOutput()
	for _, flag := range []string{"-refusal-log-per-minute", "-refusal-log-burst"} {
		if !strings.Contains(string(help), flag) {
			t.Errorf("serve --help does not list %s:\n%s", flag, help)
		}
	}
}
