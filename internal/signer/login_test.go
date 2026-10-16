package signer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

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
