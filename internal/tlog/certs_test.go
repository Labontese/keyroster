package tlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/wire"
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

// carrying is every leaf kind that records certificates (03-12e).
var carrying = []Kind{KindIssue, KindLoginIssue, KindHostIssue, KindMachineIssue, KindProbeIssue, KindRevocationRecovery}

// kindBody encodes a body of kind k, a kind that carries one certificate
// (not revocation_recovery), whose certificate bytes are blob.
func kindBody(t testing.TB, k Kind, blob []byte) []byte {
	t.Helper()
	ev := func(typ string) wire.Evidence {
		return wire.Evidence{Type: typ, Blob: []byte("evidence (test vector)")}
	}
	var (
		enc []byte
		err error
	)
	switch k {
	case KindIssue:
		enc, err = (&IssueBody{CARole: 1, Serial: 7, PolicyVersion: 1, Cert: blob, KeyID: "kid"}).Encode()
	case KindLoginIssue:
		enc, err = (&LoginIssueBody{Serial: 7, PolicyVersion: 1, DirectoryVersion: 1, Request: []byte("r"),
			Evidence: []wire.Evidence{ev(wire.EvidenceWebAuthnAssertion)}, Cert: blob, KeyID: "kid"}).Encode()
	case KindHostIssue:
		enc, err = (&HostIssueBody{Serial: 7, PolicyVersion: 1, DirectoryVersion: 1, CapSeconds: 90, Request: []byte("r"),
			Evidence: []wire.Evidence{ev(wire.EvidenceHostPoP)}, Cert: blob, KeyID: "kid"}).Encode()
	case KindMachineIssue:
		enc, err = (&MachineIssueBody{Serial: 7, PolicyVersion: 1, DirectoryVersion: 1, CapSeconds: 90, Request: []byte("r"),
			Evidence: []wire.Evidence{ev(wire.EvidenceMachinePoP)}, Cert: blob, KeyID: "kid"}).Encode()
	case KindProbeIssue:
		enc, err = (&ProbeIssueBody{Serial: 7, PolicyVersion: 1, DirectoryVersion: 1, CapSeconds: 90, Request: []byte("r"),
			Evidence: []wire.Evidence{ev(wire.EvidenceHostPoP), ev(wire.EvidenceProbePoP)}, Cert: blob, KeyID: "kid"}).Encode()
	default:
		t.Fatalf("kindBody: %s carries no single certificate", k)
	}
	if err != nil {
		t.Fatalf("%s body: %v", k, err)
	}
	return enc
}

// recoverySigning returns the signing bytes of a recovery request that
// carries certs, the i-th revoked when revoke[i].
func recoverySigning(t testing.TB, certs []*ssh.Certificate, revoke ...bool) []byte {
	t.Helper()
	r := &wire.RecoveryRequest{InstallationID: strings.Repeat("ab", 16), CreatedAt: 1_790_000_000, RestoredSize: 3}
	for i, c := range certs {
		r.Certificates = append(r.Certificates, wire.RecoveredCertificate{Cert: c.Marshal(), Revoke: i < len(revoke) && revoke[i]})
	}
	sb, err := r.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

// recoveryLeaf is a revocation_recovery leaf whose request is sb.
func recoveryLeaf(t testing.TB, sb []byte) Leaf {
	t.Helper()
	enc, err := (&RecoveryBody{PolicyVersion: 1, ResolvedAtSeconds: 1_790_000_100, Request: sb,
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sig (test vector)")}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{Kind: KindRevocationRecovery, Body: enc}
}

// swapCarried replaces, in the recovery signing bytes sb, the carried
// certificate old with blob, its uint24 length included: the certificate
// list is a count followed by length-prefixed blobs with nothing around
// them, so the bytes still decode although Validate never saw blob.
func swapCarried(t testing.TB, sb, old, blob []byte) []byte {
	t.Helper()
	i := bytes.Index(sb, old)
	if i < 3 || int(sb[i-3])<<16|int(sb[i-2])<<8|int(sb[i-1]) != len(old) {
		t.Fatal("the carried certificate is not where the request encodes it")
	}
	out := append([]byte(nil), sb[:i-3]...)
	out = append(out, byte(len(blob)>>16), byte(len(blob)>>8), byte(len(blob))) //nolint:gosec // G115: the bytes of a uint24 length; a test certificate is far shorter
	out = append(out, blob...)
	return append(out, sb[i+len(old):]...)
}

// unparsable is blob with the 4-byte length of its type name overwritten:
// the same length, and it no longer parses.
func unparsable(blob []byte) []byte {
	out := append([]byte(nil), blob...)
	copy(out, []byte{0xff, 0xff, 0xff, 0xff})
	return out
}

// nonCanonicalCert returns the bytes of a certificate of ca whose subject
// is an RSA key with its exponent written as the padded mpint 00 01 00 01:
// ssh.ParsePublicKey accepts it, and its Marshal is one byte shorter.
func nonCanonicalCert(t testing.TB, ca ssh.Signer, serial uint64) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c := &ssh.Certificate{Key: sub, Serial: serial, CertType: ssh.UserCert, KeyId: "kid", ValidPrincipals: []string{"alice"}, ValidAfter: 1, ValidBefore: 1 << 40}
	if err := c.SignCert(rand.Reader, ca); err != nil { //nolint:forbidigo // a test double: tlog has no CA profile to build with (03-12e)
		t.Fatal(err)
	}
	canon := c.Marshal()
	out := bytes.Replace(canon, []byte{0, 0, 0, 3, 1, 0, 1}, []byte{0, 0, 0, 4, 0, 1, 0, 1}, 1)
	if len(out) != len(canon)+1 {
		t.Fatal("the RSA exponent is not where the certificate encodes it")
	}
	pub, err := ssh.ParsePublicKey(out)
	if err != nil {
		t.Fatalf("the padded certificate does not parse: %v", err)
	}
	if bytes.Equal(pub.Marshal(), out) {
		t.Fatal("the padded certificate re-encodes identically")
	}
	return out
}

// TestLeafCertificates (03-12e): the certificates a leaf records, which the
// signer's and audit's drain scans both read through this one function.
func TestLeafCertificates(t *testing.T) {
	ca := certSigner(t)
	one := func(t *testing.T, k Kind) {
		t.Helper()
		c := leafCert(t, ca, 7)
		got, err := LeafCertificates(Leaf{Kind: k, Body: kindBody(t, k, c.Marshal())})
		if err != nil {
			t.Fatalf("LeafCertificates(%s): %v", k, err)
		}
		if len(got) != 1 || !bytes.Equal(got[0].Marshal(), c.Marshal()) {
			t.Fatalf("LeafCertificates(%s) returned %d certificates, want its one", k, len(got))
		}
	}
	t.Run("login_issue_leaf", func(t *testing.T) { one(t, KindLoginIssue) })
	t.Run("host_issue_leaf", func(t *testing.T) { one(t, KindHostIssue) })
	t.Run("machine_issue_leaf", func(t *testing.T) { one(t, KindMachineIssue) })
	t.Run("probe_issue_both_polarities", func(t *testing.T) {
		for _, neg := range []bool{false, true} {
			c := leafCert(t, ca, 9)
			enc, err := (&ProbeIssueBody{Serial: 9, Negative: neg, PolicyVersion: 1, DirectoryVersion: 1, CapSeconds: 90, Request: []byte("r"),
				Evidence: []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: []byte("h")}, {Type: wire.EvidenceProbePoP, Blob: []byte("p")}},
				Cert:     c.Marshal(), KeyID: "kid"}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			got, err := LeafCertificates(Leaf{Kind: KindProbeIssue, Body: enc})
			if err != nil || len(got) != 1 || !bytes.Equal(got[0].Marshal(), c.Marshal()) {
				t.Fatalf("LeafCertificates(probe_issue, negative %t) = %d certificates, %v; want its one", neg, len(got), err)
			}
		}
	})
	t.Run("recovery_carried_kept_and_revoked", func(t *testing.T) {
		kept, revoked := leafCert(t, ca, 21), leafCert(t, ca, 22)
		got, err := LeafCertificates(recoveryLeaf(t, recoverySigning(t, []*ssh.Certificate{kept, revoked}, false, true)))
		if err != nil {
			t.Fatalf("LeafCertificates(revocation_recovery): %v", err)
		}
		if len(got) != 2 || !bytes.Equal(got[0].Marshal(), kept.Marshal()) || !bytes.Equal(got[1].Marshal(), revoked.Marshal()) {
			t.Fatalf("LeafCertificates(revocation_recovery) returned %d certificates, want the kept and the revoked one in order", len(got))
		}
	})
	t.Run("refusal_and_clock_regression_carry_none", func(t *testing.T) {
		ref, err := (&RefusalBody{PeerUID: 1000, Reason: ReasonBadPrincipal, Detail: "bad_principal"}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		clk, err := (&ClockRegressionBody{NowMicros: 1, HighWaterMicros: 2}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range []Leaf{{Kind: KindRefusal, Body: ref}, {Kind: KindClockRegression, Body: clk}} {
			if got, err := LeafCertificates(l); err != nil || len(got) != 0 {
				t.Fatalf("LeafCertificates(%s) = %d certificates, %v; want none", l.Kind, len(got), err)
			}
		}
	})
	// bad requires LeafCertificates to fail for every carrying kind whose
	// certificate is replaced by mutate(c), naming the kind and, for a
	// recovery leaf, the certificate's position (the second one).
	bad := func(t *testing.T, mutate func(c *ssh.Certificate) []byte) {
		t.Helper()
		for _, k := range carrying {
			c := leafCert(t, ca, 31)
			var l Leaf
			if k == KindRevocationRecovery {
				sb := recoverySigning(t, []*ssh.Certificate{leafCert(t, ca, 30), c}, true, true)
				l = recoveryLeaf(t, swapCarried(t, sb, c.Marshal(), mutate(c)))
			} else {
				l = Leaf{Kind: k, Body: kindBody(t, k, mutate(c))}
			}
			got, err := LeafCertificates(l)
			if err == nil {
				t.Fatalf("LeafCertificates(%s) = %d certificates, nil; want an error", k, len(got))
			}
			if !strings.Contains(err.Error(), k.String()) {
				t.Fatalf("the error of %s does not name the kind: %v", k, err)
			}
			if k == KindRevocationRecovery && !strings.Contains(err.Error(), "certificate 1") {
				t.Fatalf("the error of %s does not name the certificate's position: %v", k, err)
			}
		}
	}
	t.Run("unparsable_certificate_refused", func(t *testing.T) {
		bad(t, func(c *ssh.Certificate) []byte { return unparsable(c.Marshal()) })
	})
	t.Run("not_a_certificate_refused", func(t *testing.T) {
		bad(t, func(c *ssh.Certificate) []byte { return c.Key.Marshal() })
	})
	t.Run("non_canonical_encoding_refused", func(t *testing.T) {
		nc := nonCanonicalCert(t, ca, 31)
		bad(t, func(*ssh.Certificate) []byte { return nc })
	})
	t.Run("every_kind_is_classified", func(t *testing.T) {
		carries := map[Kind]bool{
			KindIssue: true, KindLoginIssue: true, KindHostIssue: true, KindMachineIssue: true, KindProbeIssue: true, KindRevocationRecovery: true,
			KindRefusal: false, KindRefusalSummary: false, KindClockRegression: false, KindCAInit: false, KindBundleInstall: false,
			KindDirectoryInstall: false, KindRevoke: false, KindKRLPublish: false, KindCAGeneration: false, KindHostForget: false,
		}
		for i := range 256 {
			k := Kind(i) //nolint:gosec // G115: i is below 256
			c, ok := carries[k]
			if k.valid() != ok {
				t.Fatalf("kind %d (%s): valid() is %t, classified %t; classify every leaf kind as carrying certificates or not (T-03-450)", i, k, k.valid(), ok)
			}
			if !ok {
				continue
			}
			// A body that does not decode: a kind that carries
			// certificates must decode it and fail; one that carries
			// none must not read it.
			got, err := LeafCertificates(Leaf{Kind: k, Body: []byte("not a body")})
			if c && err == nil {
				t.Fatalf("kind %s carries certificates, but LeafCertificates read a body that does not decode as none (%d certificates)", k, len(got))
			}
			if !c && (err != nil || len(got) != 0) {
				t.Fatalf("kind %s carries no certificate, but LeafCertificates returned %d certificates, %v", k, len(got), err)
			}
		}
	})
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
