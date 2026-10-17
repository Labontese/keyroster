package signer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// The relying party of the login tests.
const (
	loginRP     = "keyroster.localhost"
	loginOrigin = "https://keyroster.localhost"
)

// loginPrincipals is what role ops of loginDirectory grants.
var loginPrincipals = []string{"role:ops", "role:ops-ro"}

// tickClock returns a signer clock that starts at the current whole second
// and moves one microsecond per read. Request times taken from it are
// exact seconds, so a CreatedAt 301 s off is always outside the ±300 s
// window, and serials always progress.
func tickClock() func() time.Time {
	base := time.Unix(time.Now().Unix(), 0)
	var n atomic.Int64
	return func() time.Time { return base.Add(time.Duration(n.Add(1)) * time.Microsecond) }
}

// passkeys are the soft authenticators of the login tests: alice holds one
// credential per algorithm the signer accepts, bob (disabled) and carol
// one EdDSA credential each.
type passkeys struct {
	eddsa, es256, rs256 *webauthntest.Authenticator
	bob, carol          *webauthntest.Authenticator
}

func newPasskeys(t *testing.T) *passkeys {
	t.Helper()
	gen := func(alg int64) *webauthntest.Authenticator {
		a, err := webauthntest.New(alg)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	return &passkeys{
		eddsa: gen(webauthn.AlgEdDSA), es256: gen(webauthn.AlgES256), rs256: gen(webauthn.AlgRS256),
		bob: gen(webauthn.AlgEdDSA), carol: gen(webauthn.AlgEdDSA),
	}
}

// boundCredential is a's credential as a directory binds it.
func boundCredential(a *webauthntest.Authenticator) directory.Credential {
	c := a.Credential()
	return directory.Credential{ID: base64.RawURLEncoding.EncodeToString(c.ID), Alg: c.Alg, SPKI: base64.StdEncoding.EncodeToString(c.SPKI)}
}

// loginDirectory is directory version with prev: alice (active, three
// credentials), bob (disabled) and carol (active); role ops grants
// loginPrincipals for up to 3600 s with permit-pty to all three, role dev
// grants role:dev to carol only.
func loginDirectory(pk *passkeys, version uint64, prev string) *directory.Directory {
	d := &directory.Directory{
		Version: version,
		Prev:    prev,
		Users: []directory.User{
			{Name: "alice", Status: directory.StatusActive, Credentials: []directory.Credential{
				boundCredential(pk.eddsa), boundCredential(pk.es256), boundCredential(pk.rs256)}},
			{Name: "bob", Status: directory.StatusDisabled, Credentials: []directory.Credential{boundCredential(pk.bob)}},
			{Name: "carol", Status: directory.StatusActive, Credentials: []directory.Credential{boundCredential(pk.carol)}},
		},
		Roles: []directory.Role{
			{Name: "dev", Principals: []string{"role:dev"}, MaxTTLSeconds: 3600, Users: []string{"carol"}},
			{Name: "ops", Principals: loginPrincipals, MaxTTLSeconds: 3600, Extensions: []string{"permit-pty"},
				Users: []string{"alice", "bob", "carol"}},
		},
	}
	d.Sort()
	return d
}

// signDirectory returns d's canonical bytes and the SSHSIG signatures of
// every signer over them.
func signDirectory(t *testing.T, d *directory.Directory, signers ...ssh.Signer) (doc, sigs []byte) {
	t.Helper()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return doc, signDoc(t, doc, signers...)
}

// signDoc returns the SSHSIG signatures of every signer over doc under the
// directory namespace.
func signDoc(t *testing.T, doc []byte, signers ...ssh.Signer) []byte {
	t.Helper()
	var sigs []byte
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, directory.Namespace, doc)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, sig...)
	}
	return sigs
}

// newLoginEnv is a logEnv on tickClock whose genesis policy names the RP
// when rp is set, with loginDirectory version 1 installed (signed by the
// fixture's admin quorum) when install is set.
func newLoginEnv(t *testing.T, pk *passkeys, fx *Fixture, rp, install bool) *logEnv {
	t.Helper()
	if rp {
		fx.PolicyEdit = func(p *trust.Policy) {
			p.WebAuthn = &trust.WebAuthnRP{RPID: loginRP, Origins: []string{loginOrigin}}
		}
	}
	e := newLogEnvClock(t, fx, tickClock())
	if install {
		doc, sigs := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), fx.Admins[:fx.Quorum]...)
		e.installDirectory(t, doc, sigs)
	}
	return e
}

// installDirectory installs doc with sigs and requires success.
func (e *logEnv) installDirectory(t *testing.T, doc, sigs []byte) *wire.InstallDirectoryResponse {
	t.Helper()
	resp, err := e.s.InstallDirectory(context.Background(), Peer{UID: 1000}, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs})
	if err != nil {
		t.Fatalf("InstallDirectory: %v", err)
	}
	return resp
}

// loginReq is an unapproved login request by user for role ops'
// principals, 600 s, created now on the signer's clock.
func (e *logEnv) loginReq(t *testing.T, user string) *wire.LoginIssueRequest {
	t.Helper()
	req := &wire.LoginIssueRequest{
		SubjectKey:      newEd25519(t).PublicKey().Marshal(),
		Subject:         user,
		Principals:      slices.Clone(loginPrincipals),
		ValidForSeconds: 600,
		CreatedAt:       uint64(e.clock().Unix()), //nolint:gosec // G115: after 1970
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	return req
}

// assertionEvidence is a as webauthn-assertion/v1 evidence.
func assertionEvidence(t *testing.T, a webauthn.Assertion) wire.Evidence {
	t.Helper()
	blob, err := (&wire.WebAuthnAssertion{
		CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON: a.ClientDataJSON, Signature: a.Signature,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return wire.Evidence{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}
}

// approve sets req's only evidence to auth's assertion over req's Digest
// for the test RP, changed by edit when it is not nil, and returns req.
func approve(t *testing.T, auth *webauthntest.Authenticator, req *wire.LoginIssueRequest, edit func(*webauthn.Assertion), opts ...webauthntest.Option) *wire.LoginIssueRequest {
	t.Helper()
	a := auth.Assert(loginRP, loginOrigin, req.Digest(), opts...)
	if edit != nil {
		edit(&a)
	}
	req.Evidence = []wire.Evidence{assertionEvidence(t, a)}
	return req
}

// clientDataFor returns the clientDataJSON text format with CHALLENGE
// replaced by req's Digest (unpadded base64url) and ORIGIN by the test
// origin.
func clientDataFor(req *wire.LoginIssueRequest, format string) []byte {
	d := req.Digest()
	return []byte(strings.NewReplacer("CHALLENGE", base64.RawURLEncoding.EncodeToString(d[:]), "ORIGIN", loginOrigin).Replace(format))
}

// mustLogin requires req to issue and returns the certificate.
func (e *logEnv) mustLogin(t *testing.T, req *wire.LoginIssueRequest) *ssh.Certificate {
	t.Helper()
	resp, err := e.s.LoginIssue(context.Background(), Peer{UID: 1000}, req)
	if err != nil {
		t.Fatalf("LoginIssue: %v", err)
	}
	pub, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok || !strings.HasPrefix(c.KeyId, "kr2/ca=user/") {
		t.Fatalf("LoginIssue returned %T %q, want a kr2 user certificate", pub, c.KeyId)
	}
	return c
}

// refuseLogin runs req through the signer's dispatch path (loginOrRefuse),
// as the socket server does, and requires the refusal detail, nothing
// issued and exactly one new refusal leaf with detail, its class (never
// internal) and the request's digest (D-14, T-02-83).
func (e *logEnv) refuseLogin(t *testing.T, req *wire.LoginIssueRequest, detail string) {
	t.Helper()
	class := classify(detail)
	if class == tlog.ReasonInternal {
		t.Fatalf("classify(%q) is internal", detail)
	}
	leavesBefore, issuedBefore, serialBefore := e.counts()
	resp, er := e.s.loginOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if resp != nil || er == nil {
		t.Fatalf("login issued (%+v), want the refusal %s", resp, detail)
	}
	if er.Message != detail {
		t.Fatalf("refusal %s: %s, want %s", er.Code, er.Message, detail)
	}
	leaves, issued, serial := e.counts()
	if issued != issuedBefore || serial != serialBefore || leaves != leavesBefore+1 {
		t.Fatalf("after the refusal: %d leaves, %d issuances, serial %d; want %d, %d, %d",
			leaves, issued, serial, leavesBefore+1, issuedBefore, serialBefore)
	}
	all := e.leavesOf()
	last := all[len(all)-1]
	if last.Kind != tlog.KindRefusal {
		t.Fatalf("last leaf is %s, want a refusal", last.Kind)
	}
	b, err := tlog.DecodeRefusalBody(last.Body)
	if err != nil {
		t.Fatal(err)
	}
	if b.Reason != class || b.Detail != detail || b.RequestDigest != req.Digest() {
		t.Fatalf("refusal leaf %s/%s, want %s/%s with the request digest", tlog.ReasonName(b.Reason), b.Detail, tlog.ReasonName(class), detail)
	}
}

// restartUnderNewAdmins stops e's signer, installs bundle version 2 whose
// policy (version 2, otherwise policyV2) names one fresh admin b instead
// of the fixture's admins, as install-bundle would, and starts the signer
// again under it. It returns b.
func (e *logEnv) restartUnderNewAdmins(t *testing.T) ssh.Signer {
	t.Helper()
	_, b := NewEd25519Key(t)
	e.restartUnderPolicy(t, func(p *trust.Policy) {
		p.Admins = []trust.AdminKey{{Name: "adminb", Key: trust.FormatKey(b.PublicKey())}}
	})
	return b
}

// restartUnderPolicy stops e's signer, installs bundle version 2 whose
// policy is policyV2 changed by edit, as install-bundle would, and starts
// the signer again under it.
func (e *logEnv) restartUnderPolicy(t *testing.T, edit func(*trust.Policy)) {
	t.Helper()
	e.close()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ie := &installEnv{fx: e.fx, db: db, be: e.backend}
	pol := policyV2(t, e.fx)
	edit(pol)
	if _, err := ie.install(nil, 0, docs4(t, successor(t, ie.genesis(t), pol), pol, e.fx.Root)); err != nil {
		t.Fatalf("install the successor bundle: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.open(); err != nil {
		t.Fatalf("restart under the successor policy: %v", err)
	}
}

// TestLoginDefaultExtension: CheckPolicy lets a role list one of the user
// profile's default extensions (default ∪ allowed), so a login that
// requests it must be issued, with the extension carried once as the
// default, not refused by cert.Build as an extra outside AllowedExtensions.
func TestLoginDefaultExtension(t *testing.T) {
	const rpID, origin = "keyroster.localhost", "https://keyroster.localhost"
	ctx := context.Background()
	fx := NewFixture(t, 1, 1)
	fx.PolicyEdit = func(p *trust.Policy) {
		p.WebAuthn = &trust.WebAuthnRP{RPID: rpID, Origins: []string{origin}}
	}
	e := newLogEnvFx(t, fx)

	auth, err := webauthntest.New(webauthn.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	cred := auth.Credential()
	dir := &directory.Directory{
		Version: 1,
		Prev:    trust.GenesisPrev,
		Users: []directory.User{{Name: "alice", Status: directory.StatusActive, Credentials: []directory.Credential{{
			ID:   base64.RawURLEncoding.EncodeToString(cred.ID),
			Alg:  cred.Alg,
			SPKI: base64.StdEncoding.EncodeToString(cred.SPKI),
		}}}},
		Roles: []directory.Role{{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600,
			Extensions: []string{"permit-pty"}, Users: []string{"alice"}}},
	}
	dir.Sort()
	doc, err := dir.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, fx.Admins[0], directory.Namespace, doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.InstallDirectory(ctx, Peer{UID: 1000}, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sig}); err != nil {
		t.Fatalf("install a directory whose role lists the default extension permit-pty: %v", err)
	}

	for _, tc := range []struct {
		name       string
		extensions []string
	}{
		{"no_extension_requested", nil},
		{"default_extension_requested", []string{"permit-pty"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &wire.LoginIssueRequest{
				SubjectKey:      newEd25519(t).PublicKey().Marshal(),
				Subject:         "alice",
				Principals:      []string{"role:ops"},
				ValidForSeconds: 600,
				CreatedAt:       uint64(time.Now().Unix()), //nolint:gosec // G115: after 1970
				Extensions:      tc.extensions,
			}
			if _, err := rand.Read(req.RequestID[:]); err != nil {
				t.Fatal(err)
			}
			a := auth.Assert(rpID, origin, req.Digest())
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
			resp, err := e.s.LoginIssue(ctx, Peer{UID: 1000}, req)
			if err != nil {
				t.Fatalf("LoginIssue: %v", err)
			}
			pub, err := ssh.ParsePublicKey(resp.Cert)
			if err != nil {
				t.Fatal(err)
			}
			c, ok := pub.(*ssh.Certificate)
			if !ok {
				t.Fatal("the response is not a certificate")
			}
			if want := map[string]string{"permit-pty": ""}; !maps.Equal(c.Extensions, want) {
				t.Fatalf("Extensions = %v, want exactly %v", c.Extensions, want)
			}
		})
	}
}

// TestLoginRefusalMatrix (KEY-02, D-14): every way a login request can
// fail the signer's own checks is refused with its named detail, through
// LoginIssue with real soft-authenticator assertions under an
// admin-signed directory, and logged as a refusal leaf with the request's
// digest. Each case runs on a fresh signer and has a control: a valid
// login on the same signer issues after the refusal.
func TestLoginRefusalMatrix(t *testing.T) {
	pk := newPasskeys(t)
	cd := func(t *testing.T, req *wire.LoginIssueRequest, format string) *wire.LoginIssueRequest {
		t.Helper()
		return approve(t, pk.eddsa, req, nil, webauthntest.WithClientDataJSON(clientDataFor(req, format)))
	}
	withOrigin := func(t *testing.T, req *wire.LoginIssueRequest, origin string) *wire.LoginIssueRequest {
		t.Helper()
		req.Evidence = []wire.Evidence{assertionEvidence(t, pk.eddsa.Assert(loginRP, origin, req.Digest()))}
		return req
	}
	flipSig := func(a *webauthn.Assertion) { a.Signature[len(a.Signature)/2] ^= 0x01 }
	cases := []struct {
		name, detail string
		request      func(t *testing.T, e *logEnv) *wire.LoginIssueRequest
	}{
		// Evidence.
		{"missing_evidence", "missing_evidence", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return e.loginReq(t, "alice")
		}},
		{"too_many_evidence", "too_many_evidence", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := approve(t, pk.eddsa, e.loginReq(t, "alice"), nil)
			req.Evidence = append(req.Evidence, req.Evidence[0])
			return req
		}},
		{"unknown_evidence_type", "unknown_evidence_type", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Evidence = []wire.Evidence{sshsigEvidence(t, e.fx.Admins[0], wire.AdminSSHSIGNamespace, req.SigningBytes())}
			return req
		}},
		{"bad_evidence", "bad_evidence", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: []byte("not an assertion blob")}}
			return req
		}},
		// User and credential.
		{"unknown_user", "unknown_user", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "dave"), nil)
		}},
		{"user_disabled", "user_disabled", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.bob, e.loginReq(t, "bob"), nil)
		}},
		{"role_not_granted", "role_not_granted", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Roles, req.Principals = []string{"dev"}, []string{"role:dev"}
			return approve(t, pk.eddsa, req, nil)
		}},
		{"unknown_credential", "unknown_credential", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.carol, e.loginReq(t, "alice"), nil) // carol's credential, alice's login
		}},
		// Authenticator data: exactly 37 bytes with AT and ED clear, the
		// RP's hash, UP and UV set.
		{"bad_authenticator_data/36_bytes", "bad_authenticator_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), func(a *webauthn.Assertion) { a.AuthenticatorData = a.AuthenticatorData[:36] })
		}},
		{"bad_authenticator_data/38_bytes", "bad_authenticator_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), func(a *webauthn.Assertion) { a.AuthenticatorData = append(a.AuthenticatorData, 0) })
		}},
		{"bad_authenticator_data/at_set", "bad_authenticator_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), nil, webauthntest.WithFlags(0x45))
		}},
		{"bad_authenticator_data/ed_set", "bad_authenticator_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), nil, webauthntest.WithFlags(0x85))
		}},
		{"rp_mismatch", "rp_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Evidence = []wire.Evidence{assertionEvidence(t, pk.eddsa.Assert("other.localhost", loginOrigin, req.Digest()))}
			return req
		}},
		{"user_presence_missing", "user_presence_missing", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), nil, webauthntest.WithFlags(0x04))
		}},
		{"user_verification_missing", "user_verification_missing", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), nil, webauthntest.WithFlags(0x01))
		}},
		// Client data.
		{"bad_client_data/duplicate_type", "bad_client_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return cd(t, e.loginReq(t, "alice"), `{"type":"webauthn.get","type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":false}`)
		}},
		{"bad_client_data/invalid_utf8", "bad_client_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return cd(t, e.loginReq(t, "alice"), "{\"type\":\"webauthn.get\xff\",\"challenge\":\"CHALLENGE\",\"origin\":\"ORIGIN\",\"crossOrigin\":false}")
		}},
		{"bad_client_data/cross_origin_string_false", "bad_client_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return cd(t, e.loginReq(t, "alice"), `{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":"false"}`)
		}},
		{"bad_client_data/trailing_data", "bad_client_data", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return cd(t, e.loginReq(t, "alice"), `{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":false}{}`)
		}},
		{"type_mismatch", "type_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), nil, webauthntest.WithType("webauthn.create"))
		}},
		{"challenge_mismatch", "challenge_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			other := e.loginReq(t, "alice")
			req.Evidence = []wire.Evidence{assertionEvidence(t, pk.eddsa.Assert(loginRP, loginOrigin, other.Digest()))}
			return req
		}},
		{"origin_mismatch/http_scheme", "origin_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return withOrigin(t, e.loginReq(t, "alice"), "http://keyroster.localhost")
		}},
		{"origin_mismatch/other_host", "origin_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return withOrigin(t, e.loginReq(t, "alice"), "https://other.localhost")
		}},
		{"origin_mismatch/extra_port", "origin_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return withOrigin(t, e.loginReq(t, "alice"), loginOrigin+":8443")
		}},
		{"cross_origin_refused/cross_origin_true", "cross_origin_refused", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return cd(t, e.loginReq(t, "alice"), `{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":true}`)
		}},
		{"cross_origin_refused/top_origin_present", "cross_origin_refused", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return cd(t, e.loginReq(t, "alice"), `{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":false,"topOrigin":"https://other.localhost"}`)
		}},
		// Signature: one flipped bit, for each algorithm.
		{"assertion_signature_invalid/eddsa", "assertion_signature_invalid", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.eddsa, e.loginReq(t, "alice"), flipSig)
		}},
		{"assertion_signature_invalid/es256", "assertion_signature_invalid", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.es256, e.loginReq(t, "alice"), flipSig)
		}},
		{"assertion_signature_invalid/rs256", "assertion_signature_invalid", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			return approve(t, pk.rs256, e.loginReq(t, "alice"), flipSig)
		}},
		// Grant checks.
		{"principals_mismatch/subset", "principals_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Principals = []string{"role:ops"}
			return approve(t, pk.eddsa, req, nil)
		}},
		{"principals_mismatch/superset", "principals_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Principals = []string{"role:dev", "role:ops", "role:ops-ro"}
			return approve(t, pk.eddsa, req, nil)
		}},
		{"principals_mismatch/unsorted", "principals_mismatch", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Principals = []string{"role:ops-ro", "role:ops"}
			return approve(t, pk.eddsa, req, nil)
		}},
		{"ttl_exceeds_role", "ttl_exceeds_role", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.ValidForSeconds = 3600 + 1
			return approve(t, pk.eddsa, req, nil)
		}},
		{"extension_not_allowed", "extension_not_allowed", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.Extensions = []string{"permit-port-forwarding"}
			return approve(t, pk.eddsa, req, nil)
		}},
		// A subject key that parses but is not canonically encoded: the
		// certificate would carry its canonical encoding, and audit verify
		// binds the logged request bytes to the certificate key.
		{"bad_subject_key/non_canonical_rsa", "bad_subject_key", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.SubjectKey = NonCanonicalRSAKey(t)
			return approve(t, pk.eddsa, req, nil)
		}},
		// Request freshness and replay.
		{"request_time_skew/plus_301_s", "request_time_skew", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.CreatedAt += 301
			return approve(t, pk.eddsa, req, nil)
		}},
		{"request_time_skew/minus_301_s", "request_time_skew", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := e.loginReq(t, "alice")
			req.CreatedAt -= 301
			return approve(t, pk.eddsa, req, nil)
		}},
		{"duplicate_request/login_replayed", "duplicate_request", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			req := approve(t, pk.eddsa, e.loginReq(t, "alice"), nil)
			e.mustLogin(t, req)
			return req
		}},
		{"duplicate_request/after_admin_issue", "duplicate_request", func(t *testing.T, e *logEnv) *wire.LoginIssueRequest {
			admin := e.request()
			if _, err := e.s.Issue(context.Background(), Peer{UID: 1000}, admin); err != nil {
				t.Fatalf("admin issuance: %v", err)
			}
			req := e.loginReq(t, "alice")
			req.RequestID = admin.RequestID // one request id namespace
			return approve(t, pk.eddsa, req, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
			e.refuseLogin(t, tc.request(t, e), tc.detail)
			// Control: a valid login on the same signer issues.
			e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil))
		})
	}

	// The policy and directory states that refuse every login, each with
	// its own control.
	t.Run("no_webauthn_policy", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), false, true)
		e.refuseLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil), "no_webauthn_policy")
		// Control: the same directory under a policy with the RP.
		rp := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		rp.mustLogin(t, approve(t, pk.eddsa, rp.loginReq(t, "alice"), nil))
	})
	t.Run("directory_not_installed", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, false)
		e.refuseLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil), "directory_not_installed")
		// Control: once a directory is installed, the login issues.
		doc, sigs := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), e.fx.Admins[0])
		e.installDirectory(t, doc, sigs)
		e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil))
	})
	t.Run("directory_not_authorized", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		b := e.restartUnderNewAdmins(t)
		e.refuseLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil), "directory_not_authorized")
		// Control: version 2 signed by the new admin restores logins.
		v1 := e.s.GetDirectory()
		doc, sigs := signDirectory(t, loginDirectory(pk, 2, trust.SHA256Hex(v1.Directory)), b)
		e.installDirectory(t, doc, sigs)
		e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil))
	})
}

// TestLoginAfterClockStepBackVerifies: a forward wall-clock excursion of
// 600 s during which one login is refused (request_time_skew, logged as a
// refusal leaf at the excursion time), then the clock is stepped back and
// the next login is issued. appendLocked raises that login's leaf time to
// the refusal's; the signer's own export must still verify, because audit
// verify measures freshness against the serial and the certificate's
// issuance time, never raised, not against the entry time.
func TestLoginAfterClockStepBackVerifies(t *testing.T) {
	pk := newPasskeys(t)
	var offset atomic.Int64
	base := tickClock()
	clock := func() time.Time { return base().Add(time.Duration(offset.Load())) }
	fx := NewFixture(t, 1, 1)
	fx.PolicyEdit = func(p *trust.Policy) {
		p.WebAuthn = &trust.WebAuthnRP{RPID: loginRP, Origins: []string{loginOrigin}}
	}
	e := newLogEnvClock(t, fx, clock)
	doc, sigs := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), fx.Admins[:fx.Quorum]...)
	e.installDirectory(t, doc, sigs)
	e.verifyExport()

	realNow := uint64(base().Unix()) //nolint:gosec // G115: after 1970
	offset.Store(int64(600 * time.Second))
	req := e.loginReq(t, "alice")
	req.CreatedAt = realNow // the client's clock is right
	e.refuseLogin(t, approve(t, pk.eddsa, req, nil), "request_time_skew")

	offset.Store(0) // NTP steps the signer's clock back
	e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil))
	leaves := e.leavesOf()
	if last := leaves[len(leaves)-1]; last.Kind != tlog.KindLoginIssue || last.TimeMicros < leaves[len(leaves)-2].TimeMicros ||
		last.TimeMicros/1e6 < realNow+300 {
		t.Fatalf("the login leaf (%s at %d us) was not raised to the refusal's time: the case does not test the raise", last.Kind, last.TimeMicros)
	}
	e.verifyExport()
}

// TestLoginRefusalLeaves (T-02-83): a refused login is logged with its
// exact detail, class and request digest.
func TestLoginRefusalLeaves(t *testing.T) {
	pk := newPasskeys(t)
	t.Run("login_refusal_leaf_carries_digest", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), false, true)
		before := len(e.leavesOf())
		req := approve(t, pk.eddsa, e.loginReq(t, "alice"), nil)
		if resp, er := e.s.loginOrRefuse(context.Background(), Peer{UID: 1000}, req); resp != nil || er == nil || er.Message != "no_webauthn_policy" {
			t.Fatalf("login under a policy without an RP: %+v, %+v; want no_webauthn_policy", resp, er)
		}
		leaves := e.leavesOf()
		if len(leaves) != before+1 || leaves[before].Kind != tlog.KindRefusal {
			t.Fatalf("%d new leaves, want exactly one refusal leaf", len(leaves)-before)
		}
		b, err := tlog.DecodeRefusalBody(leaves[before].Body)
		if err != nil {
			t.Fatal(err)
		}
		if want := req.Digest(); b.Detail != "no_webauthn_policy" || b.Reason != tlog.ReasonUnauthorized || b.RequestDigest != want {
			t.Fatalf("refusal leaf %s/%s digest %x, want unauthorized/no_webauthn_policy with digest %x",
				tlog.ReasonName(b.Reason), b.Detail, b.RequestDigest, want)
		}
	})
}

// TestLoginRefusalClasses: every refusal detail of the login and
// directory paths has a class other than internal, and every verifier
// sentinel maps to its detail. Two of them cannot be reached through
// LoginIssue: credential_mismatch (the signer looks the credential up by
// the assertion's own ID) and unsupported_algorithm (a directory binding
// another algorithm does not validate), so their mapping is checked here.
func TestLoginRefusalClasses(t *testing.T) {
	for _, d := range []string{
		"missing_evidence", "too_many_evidence", "unknown_evidence_type", "bad_evidence",
		"no_webauthn_policy", "directory_not_installed", "directory_not_authorized",
		"unknown_user", "user_disabled", "role_not_granted", "unknown_credential", "credential_mismatch",
		"bad_authenticator_data", "rp_mismatch", "user_presence_missing", "user_verification_missing",
		"bad_client_data", "type_mismatch", "challenge_mismatch", "origin_mismatch", "cross_origin_refused",
		"assertion_signature_invalid", "unsupported_algorithm",
		"principals_mismatch", "ttl_exceeds_role", "extension_not_allowed", "request_time_skew", "duplicate_request",
		"directory_changed", "trust_changed",
		"directory_invalid", "directory_version_chain", "directory_quorum_not_met", "directory_exceeds_policy",
	} {
		if classify(d) == tlog.ReasonInternal {
			t.Errorf("classify(%q) is internal", d)
		}
	}
	for _, m := range []struct {
		err    error
		detail string
	}{
		{webauthn.ErrCredentialID, "credential_mismatch"},
		{webauthn.ErrAuthenticatorData, "bad_authenticator_data"},
		{webauthn.ErrRPMismatch, "rp_mismatch"},
		{webauthn.ErrUserPresence, "user_presence_missing"},
		{webauthn.ErrUserVerification, "user_verification_missing"},
		{webauthn.ErrClientData, "bad_client_data"},
		{webauthn.ErrType, "type_mismatch"},
		{webauthn.ErrChallenge, "challenge_mismatch"},
		{webauthn.ErrOrigin, "origin_mismatch"},
		{webauthn.ErrCrossOrigin, "cross_origin_refused"},
		{webauthn.ErrAlgorithm, "unsupported_algorithm"},
		{webauthn.ErrSignature, "assertion_signature_invalid"},
	} {
		if got := assertionRefusal(m.err); got != m.detail {
			t.Errorf("assertionRefusal(%v) = %q, want %q", m.err, got, m.detail)
		}
	}
}

// TestEvidenceMix (T-02-05): an evidence type authorizes only the message
// type it was defined for. An admin IssueRequest carrying a WebAuthn
// assertion and a LoginIssueRequest carrying admin SSHSIG evidence are
// both refused unknown_evidence_type; each path still issues with its own
// evidence (controls).
func TestEvidenceMix(t *testing.T) {
	pk := newPasskeys(t)
	t.Run("admin_request_with_webauthn_evidence", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		req := e.request()
		req.Evidence = []wire.Evidence{assertionEvidence(t, pk.eddsa.Assert(loginRP, loginOrigin, req.Digest()))}
		e.refuseThroughSigner(t, req, tlog.ReasonUnauthorized, "unknown_evidence_type")
		if _, err := e.issue(); err != nil {
			t.Fatalf("control: admin issuance with admin evidence: %v", err)
		}
	})
	t.Run("login_request_with_admin_evidence", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		req := e.loginReq(t, "alice")
		req.Evidence = []wire.Evidence{sshsigEvidence(t, e.fx.Admins[0], wire.AdminSSHSIGNamespace, req.SigningBytes())}
		e.refuseLogin(t, req, "unknown_evidence_type")
		e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil))
	})
}

// TestLoginConcurrency (KEY-02 edge: concurrency, T-02-16): identical
// login requests in parallel yield exactly one certificate, and a
// directory row written by another process between authorization and
// commit refuses the login (directory_changed, logged as a refusal) with
// nothing issued.
func TestLoginConcurrency(t *testing.T) {
	pk := newPasskeys(t)
	ctx := context.Background()
	t.Run("identical_bytes_16_goroutines", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		body, err := approve(t, pk.eddsa, e.loginReq(t, "alice"), nil).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		_, issuedBefore, _ := e.counts()
		const n = 16
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			certs    int
			refusals = map[string]int{}
		)
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, err := wire.ParseLoginIssueRequest(body)
				if err != nil {
					t.Error(err)
					return
				}
				resp, er := e.s.loginOrRefuse(ctx, Peer{UID: 1000}, req)
				mu.Lock()
				defer mu.Unlock()
				if resp != nil {
					certs++
				} else {
					refusals[er.Message]++
				}
			}()
		}
		wg.Wait()
		if certs != 1 || refusals["duplicate_request"] != n-1 || len(refusals) != 1 {
			t.Fatalf("%d certificates and refusals %v, want 1 certificate and %d duplicate_request", certs, refusals, n-1)
		}
		if _, issued, _ := e.counts(); issued != issuedBefore+1 {
			t.Fatalf("%d issuance rows, want %d", issued, issuedBefore+1)
		}
		// Every refusal is in the log: an individual leaf within the
		// refusal rate, the rest in the refusal_summary flushed now.
		e.s.flushSummaries(ctx)
		var logged uint64
		for _, l := range e.leavesOf() {
			switch l.Kind {
			case tlog.KindRefusal:
				b, err := tlog.DecodeRefusalBody(l.Body)
				if err != nil {
					t.Fatal(err)
				}
				if b.Detail == "duplicate_request" {
					logged++
				}
			case tlog.KindRefusalSummary:
				b, err := tlog.DecodeRefusalSummaryBody(l.Body)
				if err != nil {
					t.Fatal(err)
				}
				for _, c := range b.Counts {
					if c.Reason == tlog.ReasonDuplicateRequest {
						logged += c.Count
					}
				}
			}
		}
		if logged != n-1 {
			t.Fatalf("%d duplicate_request refusals logged (leaves and summaries), want %d", logged, n-1)
		}
	})
	t.Run("directory_changed_before_commit", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		e.close()
		be := newSignHookBackend(e.backend)
		userFP := ssh.FingerprintSHA256(e.fx.Roles[keystore.RoleUser].PublicKey())
		db, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(Config{Backend: be, DB: db, Clock: e.clock, AllowUIDs: []uint32{1000}, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		e.db, e.s = db, s // e.close (a cleanup) closes db; counts reads it
		other, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		// After authorization, while the CA key signs, another process
		// writes directory version 2, bypassing the signer.
		var once sync.Once
		be.hooks[userFP] = func() {
			once.Do(func() {
				if err := other.WithTx(ctx, func(tx *sql.Tx) error {
					_, err := tx.Exec(`INSERT INTO directory (version, doc, sigs, policy_version, installed_at_us) VALUES (2, 'x', 'x', 1, 1)`)
					return err
				}); err != nil {
					t.Error(err)
				}
			})
		}
		leaves, issuedBefore, serialBefore := e.counts()
		// Through the dispatch path, as the socket server runs it.
		req := approve(t, pk.eddsa, e.loginReq(t, "alice"), nil)
		resp, er := s.loginOrRefuse(ctx, Peer{UID: 1000}, req)
		if resp != nil || er == nil || er.Message != "directory_changed" {
			t.Fatalf("login with a directory written before commit: %+v, %+v; want directory_changed", resp, er)
		}
		if n := be.count(userFP); n != 1 {
			t.Fatalf("user CA signed %d times, want 1 (the dropped certificate)", n)
		}
		// Nothing issued: no issuance row, no serial, no login_issue leaf.
		// The refusal itself is logged (D-14): one refusal leaf with the
		// request's digest.
		n, issued, serial := e.counts()
		if issued != issuedBefore || serial != serialBefore || n != leaves+1 {
			t.Fatalf("after the refusal: %d leaves, %d issuance rows, serial %d; want %d, %d, %d (only the refusal leaf)",
				n, issued, serial, leaves+1, issuedBefore, serialBefore)
		}
		all := e.leavesOf()
		b, err := tlog.DecodeRefusalBody(all[len(all)-1].Body)
		if all[len(all)-1].Kind != tlog.KindRefusal || err != nil || b.Detail != "directory_changed" ||
			b.Reason != tlog.ReasonUnavailable || b.RequestDigest != req.Digest() {
			t.Fatalf("last leaf %s (%v) %+v, want an unavailable/directory_changed refusal with the request digest", all[len(all)-1].Kind, err, b)
		}
	})
}

// TestLoginPolicyClause (SC4, policy clause): a policy version that would
// add the WebAuthn RP, in a successor bundle that only a key outside the
// previous root set signed, is refused at install with
// trust.ErrThreshold, so LoginIssue keeps refusing no_webauthn_policy,
// also after a restart. Control: the same policy in a successor signed by
// the fixture's root installs, the directory stays authorized under it,
// and after a restart the same login issues.
func TestLoginPolicyClause(t *testing.T) {
	pk := newPasskeys(t)
	t.Run("policy_not_root_signed", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), false, true)
		v1, err := e.fx.Policy().Canonical()
		if err != nil {
			t.Fatal(err)
		}
		// Only version, prev and the RP change, so the installed
		// directory still fits the policy.
		rpPolicy := e.fx.Policy()
		rpPolicy.Version, rpPolicy.Prev = 2, trust.SHA256Hex(v1)
		rpPolicy.WebAuthn = &trust.WebAuthnRP{RPID: loginRP, Origins: []string{loginOrigin}}

		other, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		ie := &installEnv{fx: e.fx, db: other, be: e.backend}
		genesis := ie.genesis(t)
		forged := successor(t, genesis, rpPolicy)
		_, r2 := NewEd25519Key(t)
		forged.Root.Keys = []trust.RootKey{{Key: trust.FormatKey(r2.PublicKey()), Custody: "software"}}
		leaves := leafCount(t, other)
		if _, err := ie.install(nil, 0, docs4(t, forged, rpPolicy, r2)); !errors.Is(err, trust.ErrThreshold) {
			t.Fatalf("install of an RP policy signed only by a key outside the root set = %v, want trust.ErrThreshold", err)
		}
		if n := leafCount(t, other); n != leaves {
			t.Fatalf("%d leaves after the refused install, want %d (no bundle_install entry)", n, leaves)
		}
		if sb, err := other.LatestBundle(context.Background()); err != nil || sb.Version != 1 {
			t.Fatalf("LatestBundle after the refused install: %v, %v; want version 1", sb, err)
		}

		req := approve(t, pk.eddsa, e.loginReq(t, "alice"), nil)
		e.refuseLogin(t, req, "no_webauthn_policy")
		e.close()
		if err := e.open(); err != nil {
			t.Fatalf("restart after the refused install: %v", err)
		}
		retry := *req
		if _, err := rand.Read(retry.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		e.refuseLogin(t, approve(t, pk.eddsa, &retry, nil), "no_webauthn_policy")

		// Control: the same policy, root-signed, installs; after a restart
		// the same login (fresh request id) issues under policy 2.
		if _, err := ie.install(nil, 0, docs4(t, successor(t, genesis, rpPolicy), rpPolicy, e.fx.Root)); err != nil {
			t.Fatalf("install of the root-signed RP policy: %v", err)
		}
		e.close()
		if err := e.open(); err != nil {
			t.Fatalf("restart under the RP policy: %v", err)
		}
		control := *req
		if _, err := rand.Read(control.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		c := e.mustLogin(t, approve(t, pk.eddsa, &control, nil))
		if !strings.Contains(c.KeyId, "/pol=2/dir=1/") {
			t.Fatalf("key ID %q, want pol=2 and dir=1", c.KeyId)
		}
	})
}
