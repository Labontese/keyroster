//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// The relying party of the login tracer.
const (
	loginRPID   = "keyroster.localhost"
	loginOrigin = "https://keyroster.localhost"
)

// TestLoginSignerEndToEnd is the Phase 2 tracer (KEY-02, AUTHZ-01): a
// root-signed policy carrying the WebAuthn RP; an admin-signed directory
// binding a soft-authenticator credential to alice and granting role ops
// the principal role:ops, installed online into the running signer; a
// LoginIssueRequest approved by an assertion over its exact signing
// bytes; a kr2 certificate with exactly the role's principals; and a real
// sshd that accepts it for an account whose AuthorizedPrincipalsFile lists
// role:ops and refuses it for one that lists only u:other. The signer then
// restarts on the same state (a log holding directory_install and
// login_issue leaves) and issues a second login certificate under the
// stored directory.
func TestLoginSignerEndToEnd(t *testing.T) {
	ctx := context.Background()
	login := currentUser(t)

	// 1. A signer under a policy with the RP, started so it can be stopped.
	env := prepareSigner(t, bootstrapOpts{WebAuthnRPID: loginRPID, WebAuthnOrigins: []string{loginOrigin}})
	stop := serveStoppable(t, env)

	// 2. alice's passkey: an EdDSA soft authenticator.
	auth, err := webauthntest.New(webauthn.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	cred := auth.Credential()

	// 3. Directory v1, signed by the admin key in the admin agent and
	// installed online.
	dir := &directory.Directory{
		Version: 1,
		Prev:    trust.GenesisPrev,
		Users: []directory.User{{Name: "alice", Status: directory.StatusActive, Credentials: []directory.Credential{{
			ID:   base64.RawURLEncoding.EncodeToString(cred.ID),
			Alg:  cred.Alg,
			SPKI: base64.StdEncoding.EncodeToString(cred.SPKI),
		}}}},
		Roles: []directory.Role{{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600, Users: []string{"alice"}}},
	}
	dir.Sort()
	doc, err := dir.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		t.Fatalf("the test directory does not parse: %v", err)
	}
	sig := adminSign(t, env, directory.Namespace, doc)
	installed, err := signerclient.InstallDirectory(ctx, env.Socket, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sig})
	if err != nil {
		t.Fatalf("install directory: %v", err)
	}
	if installed.Version != 1 || installed.SHA256 != sha256.Sum256(doc) {
		t.Fatalf("installed directory %+v, want version 1 with the document's SHA-256", installed)
	}

	// 4-5. A login request for alice (no roles named: all of hers) with an
	// in-memory ephemeral key, approved by an assertion over its Digest.
	ephPub, ephPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	resp, err := signerclient.Login(ctx, env.Socket, loginRequest(t, auth, sshPub))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	after := time.Now()

	// 6. Real sshd: the account whose principals file lists role:ops
	// accepts the certificate (control); an account listing only u:other
	// refuses the same certificate.
	keyFile, certFile := writeLoginKey(t, ephPriv, resp.Cert)
	accept := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {"role:ops"}}})
	code, out := sshLogin(t, loginOptions{Port: accept, Key: keyFile, Cert: certFile, User: login, Command: "true"})
	if code != 0 {
		t.Fatalf("ssh login with principals file [role:ops] exited %d, want 0:\n%s", code, out)
	}
	t.Logf("sshd with principals [role:ops] accepted the login certificate (exit %d)", code)
	refuse := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {"u:other"}}})
	code, out = sshLogin(t, loginOptions{Port: refuse, Key: keyFile, Cert: certFile, User: login, Command: "true"})
	if code == 0 || !strings.Contains(out, "Permission denied") {
		t.Fatalf("ssh login with principals file [u:other] exited %d, want a refusal:\n%s", code, out)
	}
	t.Logf("sshd with principals [u:other] refused the login certificate (exit %d): %s", code, strings.TrimSpace(out))

	// 7-8. The certificate as the signer issued it: kr2 key ID naming alice
	// and role ops, exactly the role's principals, the ephemeral key, and
	// a span of the requested 600 s plus cert.Build's 300 s backdate.
	c := parseCert(t, resp.Cert)
	if !strings.HasPrefix(c.KeyId, "kr2/ca=user/sub=alice/") || !strings.Contains(c.KeyId, "/roles=ops/") {
		t.Fatalf("key ID %q, want kr2/ca=user/sub=alice/... with /roles=ops/", c.KeyId)
	}
	if !slices.Equal(c.ValidPrincipals, []string{"role:ops"}) {
		t.Fatalf("ValidPrincipals = %q, want exactly [role:ops]", c.ValidPrincipals)
	}
	if c.CertType != ssh.UserCert {
		t.Fatalf("CertType = %d, want a user certificate", c.CertType)
	}
	if string(c.Key.Marshal()) != string(sshPub.Marshal()) {
		t.Fatal("the certificate is not for the request's ephemeral key")
	}
	if span := c.ValidBefore - c.ValidAfter; span != 900 {
		t.Fatalf("ValidBefore - ValidAfter = %d, want 900 (600 s requested + 300 s backdate)", span)
	}
	lo, hi := uint64(before.Unix()+600), uint64(after.Unix()+600) //nolint:gosec // G115: test clock after 1970
	if c.ValidBefore < lo || c.ValidBefore > hi {
		t.Fatalf("ValidBefore = %d, want between %d and %d", c.ValidBefore, lo, hi)
	}

	// 9. Restart on the same state directory: the log now holds a
	// directory_install leaf, a login_issue leaf and an issuance row written
	// by a login. The start must succeed, load and authorize the stored
	// directory, and issue a second login certificate under it.
	stop()
	serveStoppable(t, env)
	ephPub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub2, err := ssh.NewPublicKey(ephPub2)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := signerclient.Login(ctx, env.Socket, loginRequest(t, auth, sshPub2))
	if err != nil {
		t.Fatalf("login after the restart: %v", err)
	}
	c2 := parseCert(t, resp2.Cert)
	if !strings.Contains(c2.KeyId, "/dir=1/") || !strings.HasPrefix(c2.KeyId, "kr2/ca=user/sub=alice/") {
		t.Fatalf("key ID after the restart %q, want kr2 for alice with /dir=1/", c2.KeyId)
	}
	if c2.Serial <= c.Serial {
		t.Fatalf("serial after the restart %d, want above %d", c2.Serial, c.Serial)
	}
	t.Logf("after the restart the signer issued %s", c2.KeyId)
}

// loginRequest builds a login request for alice with no roles named,
// principals [role:ops], 600 s, a fresh request id and the current time,
// and attaches auth's assertion over its Digest as the only evidence.
func loginRequest(t *testing.T, auth *webauthntest.Authenticator, key ssh.PublicKey) *wire.LoginIssueRequest {
	t.Helper()
	return withAssertion(t, auth, unsignedLoginRequest(t, key))
}

// unsignedLoginRequest is loginRequest without evidence.
func unsignedLoginRequest(t *testing.T, key ssh.PublicKey) *wire.LoginIssueRequest {
	t.Helper()
	req := &wire.LoginIssueRequest{
		SubjectKey:      key.Marshal(),
		Subject:         "alice",
		Principals:      []string{"role:ops"},
		ValidForSeconds: 600,
		CreatedAt:       uint64(time.Now().Unix()), //nolint:gosec // G115: test clock after 1970
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	return req
}

// withAssertion replaces req's evidence with auth's assertion over req's
// Digest, as it is at the time of the call, and returns req.
func withAssertion(t *testing.T, auth *webauthntest.Authenticator, req *wire.LoginIssueRequest) *wire.LoginIssueRequest {
	t.Helper()
	a := auth.Assert(loginRPID, loginOrigin, req.Digest())
	blob, err := (&wire.WebAuthnAssertion{
		CredentialID:      a.CredentialID,
		AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON:    a.ClientDataJSON,
		Signature:         a.Signature,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}}
	return req
}

// adminSign signs doc under namespace with env's first admin key, through
// its ssh-agent, and returns the armored SSHSIG.
func adminSign(t *testing.T, env *signerEnv, namespace string, doc []byte) []byte {
	t.Helper()
	conn, err := net.Dial("unix", env.AdminAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range signers {
		if ssh.FingerprintSHA256(s.PublicKey()) == env.AdminFingerprint {
			sig, err := sshsig.Sign(rand.Reader, s, namespace, doc)
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}
	}
	t.Fatalf("admin agent holds no key %s", env.AdminFingerprint)
	return nil
}

// writeLoginKey writes the ephemeral private key (OpenSSH format, 0600)
// and the certificate to files for ssh, and returns their paths.
func writeLoginKey(t *testing.T, priv ed25519.PrivateKey, certBytes []byte) (keyFile, certFile string) {
	t.Helper()
	dir := t.TempDir()
	block, err := ssh.MarshalPrivateKey(priv, "keyroster login e2e")
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(dir, "id_login")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	certFile = keyFile + "-cert.pub"
	if err := os.WriteFile(certFile, ssh.MarshalAuthorizedKey(parseCert(t, certBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, certFile
}

// parseCert parses an SSH wire-format certificate.
func parseCert(t *testing.T, b []byte) *ssh.Certificate {
	t.Helper()
	pk, err := ssh.ParsePublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("got a %s, want a certificate", pk.Type())
	}
	return c
}
