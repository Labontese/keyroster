package tlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

// certSigner returns a fresh Ed25519 signer (03-12e).
func certSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// leafCert returns a user certificate signed by ca with serial.
func leafCert(t testing.TB, ca ssh.Signer, serial uint64) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key: certSigner(t).PublicKey(), Serial: serial, CertType: ssh.UserCert, KeyId: "kid",
		ValidPrincipals: []string{"alice"}, ValidAfter: 1, ValidBefore: 1 << 40,
	}
	if err := c.SignCert(rand.Reader, ca); err != nil { //nolint:forbidigo // a test double: tlog has no CA profile to build with (03-12e)
		t.Fatal(err)
	}
	return c
}

// TestLeafCertificates (03-12e): the certificates a leaf records, which the
// signer's and audit's drain scans both read through this one function.
func TestLeafCertificates(t *testing.T) {
	ca := certSigner(t)
	t.Run("issue_leaf_returns_its_certificate", func(t *testing.T) {
		c := leafCert(t, ca, 7)
		body, err := (&IssueBody{CARole: 1, Serial: 7, PolicyVersion: 1, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := LeafCertificates(Leaf{Kind: KindIssue, Body: body})
		if err != nil {
			t.Fatalf("LeafCertificates: %v", err)
		}
		if len(got) != 1 || !bytes.Equal(got[0].Marshal(), c.Marshal()) {
			t.Fatalf("LeafCertificates returned %d certificates, want the issue leaf's one", len(got))
		}
	})
	t.Run("leaf_without_certificates_returns_none", func(t *testing.T) {
		body, err := (&RefusalBody{PeerUID: 1000, Reason: ReasonBadPrincipal, Detail: "bad_principal"}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := LeafCertificates(Leaf{Kind: KindRefusal, Body: body})
		if err != nil || len(got) != 0 {
			t.Fatalf("LeafCertificates(refusal) = %d certificates, %v; want none", len(got), err)
		}
	})
}
