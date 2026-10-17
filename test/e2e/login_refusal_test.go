//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestLoginRefusals is success criterion 4 through the real socket
// (KEY-02): the signer refuses to issue a login certificate when the
// WebAuthn assertion is missing, when the same request is replayed, when
// the assertion approves another request digest, when the directory was
// not signed by the admin quorum of the policy in force, when the policy
// carries no WebAuthn RP, and when the login request carries admin
// evidence. Every refusal names its detail, and each case has a control
// that succeeds, so a refusal cannot pass because of an unrelated failure.
// The RP signer's exported log records the refusals with the refused
// requests' digests, and a login_issue entry for a refused request's
// digest only for each certificate a control got for that same digest.
func TestLoginRefusals(t *testing.T) {
	ctx := context.Background()
	rpPolicy := bootstrapOpts{WebAuthnRPID: loginRPID, WebAuthnOrigins: []string{loginOrigin}}
	env := bootstrapSigner(t, rpPolicy)
	auth, err := webauthntest.New(webauthn.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	doc := aliceDirectory(t, auth)
	if _, err := signerclient.InstallDirectory(ctx, env.Socket, &wire.InstallDirectoryRequest{
		Directory: doc, Sigs: adminSign(t, env, directory.Namespace, doc),
	}); err != nil {
		t.Fatalf("install the admin-signed directory: %v", err)
	}
	// refused maps the digest of every request the RP signer refused to
	// the detail it was refused with; the exported log must record each.
	// certs counts the certificates controls got for those same digests.
	refused, certs := map[[32]byte]string{}, map[[32]byte]int{}

	t.Run("missing_assertion", func(t *testing.T) {
		req := unsignedLoginRequest(t, ephemeralKey(t))
		_, err := signerclient.Login(ctx, env.Socket, req)
		wantLoginRefused(t, err, "missing_evidence")
		refused[req.Digest()] = "missing_evidence"

		// Control: the same request, approved, with a fresh request id.
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		wantLoginCert(t, env.Socket, withAssertion(t, auth, req))
	})

	t.Run("replayed_request", func(t *testing.T) {
		req := loginRequest(t, auth, ephemeralKey(t))
		first, err := req.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		wantLoginCert(t, env.Socket, req)
		certs[req.Digest()]++
		again, err := req.Marshal()
		if err != nil || !bytes.Equal(again, first) {
			t.Fatalf("the replayed request does not have the identical bytes (%v)", err)
		}
		_, err = signerclient.Login(ctx, env.Socket, req)
		wantLoginRefused(t, err, "duplicate_request")
		refused[req.Digest()] = "duplicate_request"
	})

	t.Run("wrong_digest", func(t *testing.T) {
		// The assertion approves request A; only the request id changes
		// before sending, so the principals stay valid and only the
		// digest differs.
		req := loginRequest(t, auth, ephemeralKey(t))
		approved := req.Digest()
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		if req.Digest() == approved {
			t.Fatal("changing the request id left the digest unchanged")
		}
		_, err := signerclient.Login(ctx, env.Socket, req)
		wantLoginRefused(t, err, "challenge_mismatch")
		refused[req.Digest()] = "challenge_mismatch"

		// Control: an assertion over the modified request.
		wantLoginCert(t, env.Socket, withAssertion(t, auth, req))
		certs[req.Digest()]++
	})

	t.Run("directory_not_quorum_signed", func(t *testing.T) {
		fresh := bootstrapSigner(t, rpPolicy)
		_, outsider, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		notAdmin, err := ssh.NewSignerFromKey(outsider)
		if err != nil {
			t.Fatal(err)
		}
		outsiderSig, err := sshsig.Sign(rand.Reader, notAdmin, directory.Namespace, doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signerclient.InstallDirectory(ctx, fresh.Socket, &wire.InstallDirectoryRequest{Directory: doc, Sigs: outsiderSig}); !isRefusal(err, "directory_quorum_not_met") {
			t.Fatalf("install of a directory signed only by a non-admin key: %v, want directory_quorum_not_met", err)
		}
		got, err := signerclient.GetDirectory(ctx, fresh.Socket)
		if err != nil {
			t.Fatalf("GetDirectory after the refused install: %v", err)
		}
		if got.Version != 0 || len(got.Directory) != 0 || len(got.Sigs) != 0 || got.Authorized {
			t.Fatalf("GetDirectory after the refused install = version %d, %d directory bytes, %d signature bytes, authorized %v; want version 0, empty, empty, false",
				got.Version, len(got.Directory), len(got.Sigs), got.Authorized)
		}
		_, err = signerclient.Login(ctx, fresh.Socket, loginRequest(t, auth, ephemeralKey(t)))
		wantLoginRefused(t, err, "directory_not_installed")

		// Control: the admin-signed directory installs, GetDirectory
		// reports exactly what was sent, and the login issues.
		install := &wire.InstallDirectoryRequest{Directory: doc, Sigs: adminSign(t, fresh, directory.Namespace, doc)}
		if _, err := signerclient.InstallDirectory(ctx, fresh.Socket, install); err != nil {
			t.Fatalf("install the admin-signed directory: %v", err)
		}
		got, err = signerclient.GetDirectory(ctx, fresh.Socket)
		if err != nil {
			t.Fatalf("GetDirectory after the install: %v", err)
		}
		if got.Version != 1 || !bytes.Equal(got.Directory, install.Directory) || !bytes.Equal(got.Sigs, install.Sigs) || !got.Authorized {
			t.Fatalf("GetDirectory after the install = version %d, directory equal %v, signatures equal %v, authorized %v; want 1, true, true, true",
				got.Version, bytes.Equal(got.Directory, install.Directory), bytes.Equal(got.Sigs, install.Sigs), got.Authorized)
		}
		wantLoginCert(t, fresh.Socket, loginRequest(t, auth, ephemeralKey(t)))
	})

	t.Run("policy_without_rp", func(t *testing.T) {
		noRP := bootstrapSigner(t, bootstrapOpts{})
		if _, err := signerclient.InstallDirectory(ctx, noRP.Socket, &wire.InstallDirectoryRequest{
			Directory: doc, Sigs: adminSign(t, noRP, directory.Namespace, doc),
		}); err != nil {
			t.Fatalf("a signer without an RP refused the admin-signed directory: %v", err)
		}
		_, err := signerclient.Login(ctx, noRP.Socket, loginRequest(t, auth, ephemeralKey(t)))
		wantLoginRefused(t, err, "no_webauthn_policy")
		// Control: the same login on the RP signer issues (as in
		// missing_assertion's control).
		wantLoginCert(t, env.Socket, loginRequest(t, auth, ephemeralKey(t)))
	})

	t.Run("wrong_evidence_type", func(t *testing.T) {
		req := unsignedLoginRequest(t, ephemeralKey(t))
		req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: adminSign(t, env, wire.AdminSSHSIGNamespace, req.SigningBytes())}}
		_, err := signerclient.Login(ctx, env.Socket, req)
		wantLoginRefused(t, err, "unknown_evidence_type")
		refused[req.Digest()] = "unknown_evidence_type"

		// Control: the same admin key still issues on the admin path.
		login := currentUser(t)
		key := newUserKey(t, "id_admin_control")
		env.issue(t, "--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		if _, err := os.Stat(key + "-cert.pub"); err != nil {
			t.Fatalf("admin issuance after the refusal: %v", err)
		}
	})

	// Every refusal above is within the default refusal rate (10 per
	// minute, burst 10), so each one is an individual refusal leaf. A
	// refusal that issued anyway would add a login_issue entry beyond the
	// controls' certificates.
	logged, issued := exportedLog(t, env)
	for digest, detail := range refused {
		if got, ok := logged[digest]; !ok || got != detail {
			t.Errorf("the exported log records the refused request %x as %q (present %v), want %q", digest[:4], got, ok, detail)
		}
		if issued[digest] != certs[digest] {
			t.Errorf("the exported log has %d login_issue entries for the request %x refused %s, want %d (the controls' certificates)", issued[digest], digest[:4], detail, certs[digest])
		}
	}
}

// aliceDirectory returns the canonical bytes of directory version 1:
// alice, active, with auth's credential, and role ops granting her
// role:ops for up to 3600 s.
func aliceDirectory(t *testing.T, auth *webauthntest.Authenticator) []byte {
	t.Helper()
	cred := auth.Credential()
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
	return doc
}

// ephemeralKey returns a fresh Ed25519 public key for a login request.
func ephemeralKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// isRefusal reports whether err is the signer's refusal with detail.
func isRefusal(err error, detail string) bool {
	var e *wire.ErrorResponse
	return errors.As(err, &e) && e.Message == detail
}

// wantLoginRefused requires the refusal with detail. signerclient.Login
// returns no response with an error, so whether a certificate was issued
// anyway is checked in the exported log (TestLoginRefusals).
func wantLoginRefused(t *testing.T, err error, detail string) {
	t.Helper()
	if !isRefusal(err, detail) {
		t.Fatalf("login: %v, want the refusal %s", err, detail)
	}
}

// wantLoginCert requires req to yield a kr2 user certificate for alice.
func wantLoginCert(t *testing.T, socket string, req *wire.LoginIssueRequest) {
	t.Helper()
	resp, err := signerclient.Login(context.Background(), socket, req)
	if err != nil {
		t.Fatalf("control login: %v", err)
	}
	if c := parseCert(t, resp.Cert); c.CertType != ssh.UserCert || !strings.HasPrefix(c.KeyId, "kr2/ca=user/sub=alice/") {
		t.Fatalf("control login returned %q (type %d), want a kr2 user certificate", c.KeyId, c.CertType)
	}
}

// exportedLog exports env's log and returns the detail of every individual
// refusal leaf by request digest, and the number of login_issue leaves by
// the digest of the request they issued for.
func exportedLog(t *testing.T, env *signerEnv) (map[[32]byte]string, map[[32]byte]int) {
	t.Helper()
	f, err := os.Open(env.exportLog(t)) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out, issued := map[[32]byte]string{}, map[[32]byte]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		var line struct {
			Leaf string `json:"leaf"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		if line.Leaf == "" {
			continue // the checkpoint line
		}
		raw, err := base64.StdEncoding.DecodeString(line.Leaf)
		if err != nil {
			t.Fatal(err)
		}
		l, err := tlog.DecodeLeaf(raw)
		if err != nil {
			t.Fatal(err)
		}
		if l.Kind == tlog.KindLoginIssue {
			b, err := tlog.DecodeLoginIssueBody(l.Body)
			if err != nil {
				t.Fatal(err)
			}
			// Request is the signing bytes; Digest is their SHA-256.
			issued[sha256.Sum256(b.Request)]++
			continue
		}
		if l.Kind != tlog.KindRefusal {
			continue
		}
		b, err := tlog.DecodeRefusalBody(l.Body)
		if err != nil {
			t.Fatal(err)
		}
		out[b.RequestDigest] = b.Detail
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out, issued
}
