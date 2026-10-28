package enroll

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

func ed25519Signer(t *testing.T) ssh.Signer {
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

func ecdsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// statement is a valid PoP over signers' keys, with the signers in
// HostKeys order.
func statement(t *testing.T, signers ...ssh.Signer) (PoP, []ssh.Signer) {
	t.Helper()
	facts, err := FactsSHA256(Facts{OSID: "debian", OSVersionID: "13", Hostname: "web1"})
	if err != nil {
		t.Fatal(err)
	}
	var pubs []ssh.PublicKey
	for _, s := range signers {
		pubs = append(pubs, s.PublicKey())
	}
	p := PoP{Domain: Domain, InstallationID: "0123456789abcdef0123456789abcdef", TokenSHA256: strings.Repeat("ab", 32),
		IdentitySPKISHA256: strings.Repeat("cd", 32), HostKeys: SortHostKeys(pubs), FactsSHA256: facts}
	ordered := make([]ssh.Signer, len(p.HostKeys))
	for i, k := range p.HostKeys {
		for _, s := range signers {
			if trust.FormatKey(s.PublicKey()) == k {
				ordered[i] = s
			}
		}
	}
	return p, ordered
}

// TestPoP: every host key must have signed exactly this statement under
// Namespace (AGENT-01, T-03-45).
func TestPoP(t *testing.T) {
	a, b := ed25519Signer(t), ecdsaSigner(t)
	p, signers := statement(t, a, b)
	sigs, err := Sign(p, signers)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("valid", func(t *testing.T) {
		if err := Verify(p, nil, sigs); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("signature_by_another_key_refused", func(t *testing.T) {
		other := ed25519Signer(t)
		forged, err := sshsig.Sign(rand.Reader, other, Namespace, mustCanonical(t, p))
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(p, nil, [][]byte{forged, sigs[1]}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("a signature by another key: %v", err)
		}
		if err := Verify(p, nil, [][]byte{sigs[1], sigs[0]}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("signatures in the wrong order: %v", err)
		}
	})
	t.Run("other_namespace_refused", func(t *testing.T) {
		wrong, err := sshsig.Sign(rand.Reader, signers[0], "keyroster/agent-enroll/v2", mustCanonical(t, p))
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(p, nil, [][]byte{wrong, sigs[1]}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("a signature under another namespace: %v", err)
		}
	})
	for name, edit := range map[string]func(q *PoP){
		"other_identity_refused":     func(q *PoP) { q.IdentitySPKISHA256 = strings.Repeat("ef", 32) },
		"other_token_refused":        func(q *PoP) { q.TokenSHA256 = strings.Repeat("01", 32) },
		"other_installation_refused": func(q *PoP) { q.InstallationID = "fedcba9876543210fedcba9876543210" },
		"other_facts_refused":        func(q *PoP) { q.FactsSHA256 = strings.Repeat("02", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			q.HostKeys = append([]string(nil), p.HostKeys...)
			edit(&q)
			if err := Verify(q, nil, sigs); !errors.Is(err, ErrInvalid) {
				t.Fatalf("the signatures verify over another statement: %v", err)
			}
		})
	}
	t.Run("missing_signature_refused", func(t *testing.T) {
		if err := Verify(p, nil, sigs[:1]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("one signature for two host keys: %v", err)
		}
	})
	t.Run("check_refuses_malformed_statements", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		for name, edit := range map[string]func(q *PoP){
			"domain":           func(q *PoP) { q.Domain = "keyroster/other" },
			"installation":     func(q *PoP) { q.InstallationID = strings.ToUpper(q.InstallationID) },
			"hash_uppercase":   func(q *PoP) { q.TokenSHA256 = strings.ToUpper(q.TokenSHA256) },
			"no_host_keys":     func(q *PoP) { q.HostKeys = nil },
			"unsorted":         func(q *PoP) { q.HostKeys = []string{q.HostKeys[1], q.HostKeys[0]} },
			"duplicate":        func(q *PoP) { q.HostKeys = []string{q.HostKeys[0], q.HostKeys[0]} },
			"rsa_host_key":     func(q *PoP) { q.HostKeys = []string{trust.FormatKey(rsaPub)} },
			"key_with_comment": func(q *PoP) { q.HostKeys = []string{q.HostKeys[0] + " host"} },
		} {
			q := p
			q.HostKeys = append([]string(nil), p.HostKeys...)
			edit(&q)
			if err := Check(&q); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: Check = %v", name, err)
			}
		}
	})
	t.Run("sign_refuses_signer_of_another_key", func(t *testing.T) {
		if _, err := Sign(p, []ssh.Signer{signers[1], signers[0]}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Sign with the signers swapped: %v", err)
		}
	})
}

// TestFacts: facts are printable ASCII of at most MaxFactLen bytes.
func TestFacts(t *testing.T) {
	for _, f := range []Facts{{Hostname: "web1\x1b[31m"}, {OSID: strings.Repeat("a", MaxFactLen+1)}, {OSVersionID: "13\n"}, {SSHDVersion: "é"}} {
		if err := CheckFacts(f); !errors.Is(err, ErrInvalid) {
			t.Errorf("CheckFacts(%q) = %v", f, err)
		}
		g := Facts{SSHDVersion: SanitizeFact(f.SSHDVersion), OSID: SanitizeFact(f.OSID), OSVersionID: SanitizeFact(f.OSVersionID), Hostname: SanitizeFact(f.Hostname)}
		if err := CheckFacts(g); err != nil {
			t.Errorf("CheckFacts(SanitizeFact(%q)) = %v", f, err)
		}
	}
	if IdentityFingerprint(make([]byte, 32)) != "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("IdentityFingerprint = %s", IdentityFingerprint(make([]byte, 32)))
	}
}

func mustCanonical(t *testing.T, p PoP) []byte {
	t.Helper()
	b, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
