//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/wire"
)

// principalsHeader is the two header lines RenderPrincipalsFile writes
// for account in host group web of the installed directory doc.
func principalsHeader(account string, version uint64, doc []byte) string {
	return "# keyroster: generated AuthorizedPrincipalsFile; do not edit\n" +
		"# host group web, account " + account + ", directory version " + strconv.FormatUint(version, 10) + " sha256 " + trust.SHA256Hex(doc) + "\n"
}

// principalsLines turns keyroster host principals stdout into the lines
// startSSHD writes, which joins them with "\n" and adds one trailing
// newline: it removes exactly one trailing newline before splitting, and
// requires the lines to rejoin to exactly out, so the file sshd reads is
// keyroster's output byte for byte.
func principalsLines(t *testing.T, out string) []string {
	t.Helper()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("host principals stdout does not end in a newline: %q", out)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if strings.Join(lines, "\n")+"\n" != out {
		t.Fatalf("the principals lines %q do not rejoin to the stdout %q", lines, out)
	}
	return lines
}

// TestRolesHostPrincipalsEndToEnd (AUTHZ-01, success criterion 3, D-06,
// D-07): an admin makes role ops (default principal role:ops), group devs
// with alice, grants ops to devs, and maps the sshd login account to ops
// in host group web, each an admin-signed directory version through the
// CLI pipeline. keyroster host principals renders the account's
// AuthorizedPrincipalsFile and keyroster host ca-key the TrustedUserCAKeys
// line; a real sshd fed exactly that output accepts alice's login
// certificate, which carries exactly role:ops. After host-group unmap the
// re-rendered file is the header-only file, and a fresh sshd fed exactly
// that output refuses the same certificate (02-11-F2).
func TestRolesHostPrincipalsEndToEnd(t *testing.T) {
	ctx := context.Background()
	login := currentUser(t)
	if !directory.ValidAccountName(login) {
		t.Fatalf("the test user %q is not a valid keyroster account name", login)
	}
	env := startServerEnv(t, serverOpts{})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	// kr runs one CLI command and requires exit 0. The test makes more
	// admin requests than the server's per-client admin burst (20), so a
	// command the server rate-limited (refused before any handler ran, so
	// nothing was installed) runs again after the limiter refills.
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			t.Logf("keyroster %s was rate-limited; running it again in 2 s", strings.Join(args, " "))
			time.Sleep(2 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}

	// 1. admin1 and alice enrolled and approved.
	_, fpAdmin := enroll(t, env, admin, "admin1", webauthn.AlgEdDSA)
	kr("user", "approve", "admin1", "--fingerprint", fpAdmin, "--yes")
	alice, fpAlice := enroll(t, env, admin, "alice", webauthn.AlgES256)
	kr("user", "approve", "alice", "--fingerprint", fpAlice, "--yes")

	// 2. The role, the group, the grant, the host group and the mapping.
	if out := kr("role", "add", "ops", "--max-ttl", "1h", "--yes"); !strings.Contains(out, "+ role ops principals=[role:ops] max_ttl_seconds=3600") {
		t.Fatalf("role add ops: the diff does not add role ops with the default principal role:ops:\n%s", out)
	}
	kr("group", "add", "devs", "--member", "alice", "--yes")
	kr("role", "grant", "ops", "--group", "devs", "--yes")
	kr("host-group", "add", "web", "--yes")
	kr("host-group", "map", "web", login, "ops", "--yes")

	// 3. The rendered principals file: the header for the installed
	// version and exactly the default ops principal.
	resp, d := signerDirectory(t, env)
	out := kr("host", "principals", "web", login)
	if want := principalsHeader(login, resp.Version, resp.Directory) + "role:ops\n"; out != want {
		t.Fatalf("host principals web %s = %q, want %q", login, out, want)
	}
	acceptLines := principalsLines(t, out)

	// 4. host ca-key is the user CA key of the bootstrap.
	caLine := kr("host", "ca-key")
	gotCA, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(caLine))
	if err != nil {
		t.Fatalf("host ca-key printed %q: %v", caLine, err)
	}
	wantCA, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readPub(t, env.Signer.UserCAPub)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gotCA.Marshal(), wantCA.Marshal()) || comment != "keyroster user CA (bundle v1)" {
		t.Fatalf("host ca-key = %q, want the user CA key %s with comment \"keyroster user CA (bundle v1)\"", caLine, ssh.FingerprintSHA256(wantCA))
	}
	caFile := filepath.Join(t.TempDir(), "keyroster_user_ca.pub")
	if err := os.WriteFile(caFile, []byte(caLine), 0o644); err != nil { //nolint:gosec // test fixture: a public key
		t.Fatal(err)
	}

	// 5. alice's login: no roles named, the principals the signer's
	// directory grants her, approved by her passkey.
	grant, err := d.Authorize("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(grant.Principals, []string{"role:ops"}) || !slices.Equal(grant.Roles, []string{"ops"}) {
		t.Fatalf("alice's grant = %+v, want role ops with principals [role:ops]", grant)
	}
	ephPub, ephPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	req := &wire.LoginIssueRequest{
		SubjectKey:      sshPub.Marshal(),
		Subject:         "alice",
		Principals:      grant.Principals,
		ValidForSeconds: 600,
		CreatedAt:       uint64(time.Now().Unix()), //nolint:gosec // G115: test clock after 1970
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	a := alice.Assert(serverRPID, env.URL, req.Digest())
	blob, err := (&wire.WebAuthnAssertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}}
	issued, err := signerclient.Login(ctx, env.Signer.Socket, req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	c := parseCert(t, issued.Cert)
	if !slices.Equal(c.ValidPrincipals, []string{"role:ops"}) {
		t.Fatalf("ValidPrincipals = %q, want exactly [role:ops]", c.ValidPrincipals)
	}
	keyFile, certFile := writeLoginKey(t, ephPriv, issued.Cert)

	// 6. Control: sshd with keyroster's CA line and keyroster's rendered
	// file accepts the certificate.
	port := startSSHD(t, sshdOptions{UserCAPub: caFile, Principals: map[string][]string{login: acceptLines}})
	if code, sshOut := sshLogin(t, loginOptions{Port: port, Key: keyFile, Cert: certFile, User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the rendered principals file exited %d, want 0:\n%s", code, sshOut)
	}
	t.Logf("sshd with the rendered principals file accepted alice's certificate")

	// 7. Refusal: unmap, re-render (exit 0, the header-only file of the
	// new version), and a fresh sshd fed exactly that output refuses the
	// same certificate.
	kr("host-group", "unmap", "web", login, "--yes")
	resp2, _ := signerDirectory(t, env)
	if resp2.Version != resp.Version+1 {
		t.Fatalf("signer directory version %d after the unmap, want %d", resp2.Version, resp.Version+1)
	}
	out = kr("host", "principals", "web", login)
	if want := principalsHeader(login, resp2.Version, resp2.Directory); out != want {
		t.Fatalf("host principals web %s after the unmap = %q, want the header-only file %q", login, out, want)
	}
	refuseLines := principalsLines(t, out)
	for _, l := range refuseLines {
		if !strings.HasPrefix(l, "#") {
			t.Fatalf("the re-rendered file after the unmap has a principal line %q", l)
		}
	}
	port = startSSHD(t, sshdOptions{UserCAPub: caFile, Principals: map[string][]string{login: refuseLines}})
	code, sshOut := sshLogin(t, loginOptions{Port: port, Key: keyFile, Cert: certFile, User: login, Command: "true"})
	if code == 0 || !strings.Contains(sshOut, "Permission denied") {
		t.Fatalf("ssh login with the header-only principals file exited %d, want a refusal:\n%s", code, sshOut)
	}
	t.Logf("sshd with the header-only principals file refused alice's certificate (exit %d)", code)
}
