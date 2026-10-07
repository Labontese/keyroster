package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

// Test keys are generated once per test binary; RSA generation is slow.
var (
	testRSA2048 = mustRSA(2048)
	testRSA3072 = mustRSA(3072)
)

func mustRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return k
}

func newEd25519Signer(t testing.TB) ssh.Signer {
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

func newECDSASigner(t testing.TB, curve elliptic.Curve) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newRSASigner(t testing.TB, k *rsa.PrivateKey) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// skKeyBlob assembles the SSH wire blob of a security-key public key:
// key type, the type-specific key fields, and the application "ssh:".
func skKeyBlob(t testing.TB, keyType string, fields ...[]byte) ssh.PublicKey {
	t.Helper()
	var b cryptobyte.Builder
	addSSHString(&b, []byte(keyType))
	for _, f := range fields {
		addSSHString(&b, f)
	}
	addSSHString(&b, []byte("ssh:"))
	pub, err := ssh.ParsePublicKey(b.BytesOrPanic())
	if err != nil {
		t.Fatalf("parse %s blob: %v", keyType, err)
	}
	return pub
}

func addSSHString(b *cryptobyte.Builder, v []byte) {
	b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(v) })
}

func newSKEd25519(t testing.TB) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return skKeyBlob(t, ssh.KeyAlgoSKED25519, pub)
}

func newSKECDSA(t testing.TB) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return skKeyBlob(t, ssh.KeyAlgoSKECDSA256, []byte("nistp256"), ecdhPub.Bytes())
}

// dsaBlob assembles an ssh-dss public key blob (p, q, g, y as mpints) by
// hand, with the 1024-bit p and 160-bit q that x/crypto's parser expects;
// crypto/dsa is deprecated and never used.
func dsaBlob() []byte {
	var b cryptobyte.Builder
	addSSHString(&b, []byte("ssh-dss"))
	// mpint returns an n-byte positive integer with the top bit set,
	// preceded by the zero byte the mpint encoding then requires.
	mpint := func(n int, fill byte) []byte {
		return append([]byte{0}, bytes.Repeat([]byte{fill}, n)...)
	}
	addSSHString(&b, mpint(128, 0xab)) // p: 1024 bits
	addSSHString(&b, mpint(20, 0xcd))  // q: 160 bits
	addSSHString(&b, mpint(128, 0x91)) // g
	addSSHString(&b, mpint(128, 0xa2)) // y
	return b.BytesOrPanic()
}

const testRequestHex = "0123456789abcdef0123456789abcdef"

func testKeyID(serial uint64) KeyID {
	return KeyID{CA: "user", Subject: "u:alice", Request: testRequestHex, Policy: 0, Serial: serial}
}

// validRequest returns a request that Build accepts.
func validRequest(t testing.TB, subject ssh.PublicKey) Request {
	t.Helper()
	return Request{
		Profile:    DefaultUserProfile(),
		Subject:    subject,
		Principals: []string{"alice"},
		Now:        time.Now(),
		ValidFor:   time.Hour,
		KeyID:      testKeyID(42),
		Serial:     42,
	}
}

// verifyCert checks c's signature against ca with x/crypto's CertChecker.
func verifyCert(t *testing.T, c *ssh.Certificate, ca ssh.PublicKey, principal string) {
	t.Helper()
	if !bytes.Equal(c.SignatureKey.Marshal(), ca.Marshal()) {
		t.Fatalf("certificate names CA %s, want %s", ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(ca))
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), ca.Marshal()) },
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool { return bytes.Equal(auth.Marshal(), ca.Marshal()) },
	}
	if err := checker.CheckCert(principal, c); err != nil {
		t.Fatalf("certificate does not verify: %v", err)
	}
}

// wantErrIs fails unless err matches want (nil means success).
func wantErrIs(t *testing.T, err, want error) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestValidatePrincipals(t *testing.T) {
	many := make([]string, MaxPrincipals+1)
	for i := range many {
		many[i] = "p" + strings.Repeat("x", i)
	}
	tests := []struct {
		name string
		in   []string
		want error
	}{
		{"nil_list", nil, ErrEmptyPrincipals},
		{"empty_list", []string{}, ErrEmptyPrincipals},
		{"single_alice", []string{"alice"}, nil},
		{"all_allowed_symbols", []string{"a0._@:+-z"}, nil},
		{"max_32_principals", many[:MaxPrincipals], nil},
		{"len_128_bytes", []string{strings.Repeat("a", 128)}, nil},
		{"len_129_bytes", []string{strings.Repeat("a", 129)}, ErrPrincipal},
		{"empty_string", []string{""}, ErrPrincipal},
		{"wildcard_star", []string{"*"}, ErrPrincipal},
		{"wildcard_question", []string{"?"}, ErrPrincipal},
		{"comma_list", []string{"a,b"}, ErrPrincipal},
		{"negation_bang", []string{"!a"}, ErrPrincipal},
		{"leading_space", []string{" alice"}, ErrPrincipal},
		{"trailing_newline", []string{"alice\n"}, ErrPrincipal},
		{"inner_space", []string{"ali ce"}, ErrPrincipal},
		{"tab", []string{"ali\tce"}, ErrPrincipal},
		{"uppercase", []string{"Alice"}, ErrPrincipal},
		{"nul_byte", []string{"alice\x00"}, ErrPrincipal},
		{"control_char", []string{"ali\x1bce"}, ErrPrincipal},
		{"slash", []string{"a/b"}, ErrPrincipal},
		{"cyrillic_a", []string{"аlice"}, ErrPrincipal},
		{"nfc_e_acute", []string{"café"}, ErrPrincipal},
		{"nfd_e_acute", []string{"café"}, ErrPrincipal},
		{"invalid_utf8", []string{"ali\xffce"}, ErrPrincipal},
		{"leading_dot", []string{".alice"}, ErrPrincipal},
		{"duplicate_exact", []string{"alice", "alice"}, ErrPrincipal},
		{"duplicate_after_valid", []string{"bob", "alice", "bob"}, ErrPrincipal},
		{"distinct_pair", []string{"alice", "bob"}, nil},
		{"principals_33", many, ErrPrincipal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantErrIs(t, ValidatePrincipals(tc.in), tc.want)
		})
	}
}

func TestBuildPrincipals(t *testing.T) {
	ca := newEd25519Signer(t)
	subject := newEd25519Signer(t).PublicKey()
	tests := []struct {
		name string
		in   []string
		want error
	}{
		{"nil_list", nil, ErrEmptyPrincipals},
		{"empty_list", []string{}, ErrEmptyPrincipals},
		{"single_principal", []string{"alice"}, nil},
		{"wildcard_star", []string{"*"}, ErrPrincipal},
		{"nfd_e_acute", []string{"café"}, ErrPrincipal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest(t, subject)
			req.Principals = tc.in
			c, err := Build(req, ca, rand.Reader)
			wantErrIs(t, err, tc.want)
			if tc.want == nil {
				if len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != "alice" {
					t.Fatalf("principals = %q, want [alice]", c.ValidPrincipals)
				}
				verifyCert(t, c, ca.PublicKey(), "alice")
			}
		})
	}
}

func TestBuildExtensions(t *testing.T) {
	ca := newEd25519Signer(t)
	subject := newEd25519Signer(t).PublicKey()

	t.Run("default_user_permit_pty_only", func(t *testing.T) {
		c, err := Build(validRequest(t, subject), ca, rand.Reader)
		wantErrIs(t, err, nil)
		if len(c.Extensions) != 1 || c.Extensions["permit-pty"] != "" {
			t.Fatalf("extensions = %v, want exactly {permit-pty: \"\"}", c.Extensions)
		}
		if _, ok := c.Extensions["permit-pty"]; !ok {
			t.Fatalf("extensions = %v, permit-pty missing", c.Extensions)
		}
		if len(c.CriticalOptions) != 0 {
			t.Fatalf("critical options = %v, want none", c.CriticalOptions)
		}
	})
	t.Run("extra_extension_not_allowed", func(t *testing.T) {
		req := validRequest(t, subject)
		req.ExtraExtensions = map[string]string{"permit-port-forwarding": ""}
		_, err := Build(req, ca, rand.Reader)
		wantErrIs(t, err, ErrExtension)
	})
	t.Run("extra_extension_allowed_by_profile", func(t *testing.T) {
		req := validRequest(t, subject)
		req.Profile.AllowedExtensions = []string{"permit-agent-forwarding"}
		req.ExtraExtensions = map[string]string{"permit-agent-forwarding": ""}
		c, err := Build(req, ca, rand.Reader)
		wantErrIs(t, err, nil)
		if len(c.Extensions) != 2 {
			t.Fatalf("extensions = %v, want permit-pty and permit-agent-forwarding", c.Extensions)
		}
	})
	t.Run("host_cert_no_extensions", func(t *testing.T) {
		req := validRequest(t, subject)
		req.Profile = Profile{CertType: ssh.HostCert, MaxTTL: 24 * time.Hour}
		req.Principals = []string{"host.example"}
		c, err := Build(req, ca, rand.Reader)
		wantErrIs(t, err, nil)
		if c.CertType != ssh.HostCert || len(c.Extensions) != 0 {
			t.Fatalf("cert type %d, extensions %v; want a host certificate without extensions", c.CertType, c.Extensions)
		}
		verifyCert(t, c, ca.PublicKey(), "host.example")
	})
	t.Run("host_cert_with_default_extension", func(t *testing.T) {
		req := validRequest(t, subject)
		req.Profile = Profile{CertType: ssh.HostCert, MaxTTL: 24 * time.Hour, DefaultExtensions: map[string]string{"permit-pty": ""}}
		_, err := Build(req, ca, rand.Reader)
		wantErrIs(t, err, ErrExtension)
	})
	t.Run("critical_option_not_allowed", func(t *testing.T) {
		req := validRequest(t, subject)
		req.CriticalOptions = map[string]string{"force-command": "/bin/true"}
		_, err := Build(req, ca, rand.Reader)
		wantErrIs(t, err, ErrExtension)
	})
	t.Run("unknown_cert_type", func(t *testing.T) {
		req := validRequest(t, subject)
		req.Profile.CertType = 3
		_, err := Build(req, ca, rand.Reader)
		wantErrIs(t, err, ErrProfile)
	})
}

func TestBuildValidityAndSerial(t *testing.T) {
	ca := newEd25519Signer(t)
	subject := newEd25519Signer(t).PublicKey()
	maxTTL := DefaultUserProfile().MaxTTL
	tests := []struct {
		name     string
		validFor time.Duration
		serial   uint64
		keySer   uint64
		want     error
	}{
		{"valid_for_zero", 0, 42, 42, ErrValidity},
		{"valid_for_negative", -time.Hour, 42, 42, ErrValidity},
		{"valid_for_above_max_ttl", maxTTL + time.Second, 42, 42, ErrValidity},
		{"valid_for_infinite", time.Duration(math.MaxInt64), 42, 42, ErrValidity},
		{"valid_for_max_ttl", maxTTL, 42, 42, nil},
		{"serial_zero", time.Hour, 0, 0, ErrSerial},
		{"key_id_serial_differs", time.Hour, 42, 43, ErrSerial},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest(t, subject)
			req.ValidFor, req.Serial, req.KeyID = tc.validFor, tc.serial, testKeyID(tc.keySer)
			c, err := Build(req, ca, rand.Reader)
			wantErrIs(t, err, tc.want)
			if tc.want != nil {
				return
			}
			if c.ValidBefore == ssh.CertTimeInfinity {
				t.Fatal("ValidBefore is CertTimeInfinity")
			}
			if want := uint64(req.Now.Add(tc.validFor).Unix()); c.ValidBefore != want { //nolint:gosec // G115: a current time is positive
				t.Fatalf("ValidBefore = %d, want %d", c.ValidBefore, want)
			}
			if c.ValidAfter >= c.ValidBefore {
				t.Fatalf("ValidAfter %d is not before ValidBefore %d", c.ValidAfter, c.ValidBefore)
			}
		})
	}
	t.Run("zero_issuance_time", func(t *testing.T) {
		req := validRequest(t, subject)
		req.Now = time.Time{}
		_, err := Build(req, ca, rand.Reader)
		wantErrIs(t, err, ErrValidity)
	})
}

func TestBuildKeyID(t *testing.T) {
	ca := newEd25519Signer(t)
	subject := newEd25519Signer(t).PublicKey()
	tests := []struct {
		name string
		edit func(*KeyID)
		want error
	}{
		{"valid", func(*KeyID) {}, nil},
		{"slash_in_subject", func(k *KeyID) { k.Subject = "u:a/pol=9" }, ErrKeyID},
		{"equals_in_subject", func(k *KeyID) { k.Subject = "u=alice" }, ErrKeyID},
		{"empty_subject", func(k *KeyID) { k.Subject = "" }, ErrKeyID},
		{"empty_ca", func(k *KeyID) { k.CA = "" }, ErrKeyID},
		{"empty_request", func(k *KeyID) { k.Request = "" }, ErrKeyID},
		{"uppercase_request", func(k *KeyID) { k.Request = strings.ToUpper(testRequestHex) }, ErrKeyID},
		{"unknown_ca", func(k *KeyID) { k.CA = "root" }, ErrKeyID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest(t, subject)
			tc.edit(&req.KeyID)
			c, err := Build(req, ca, rand.Reader)
			wantErrIs(t, err, tc.want)
			if tc.want == nil && c.KeyId != req.KeyID.String() {
				t.Fatalf("KeyId = %q, want %q", c.KeyId, req.KeyID.String())
			}
		})
	}
}

func TestBuildSubjectKeys(t *testing.T) {
	ca := newEd25519Signer(t)
	certSubject := func(t *testing.T) ssh.PublicKey {
		c, err := Build(validRequest(t, newEd25519Signer(t).PublicKey()), ca, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	tests := []struct {
		name string
		key  func(t *testing.T) ssh.PublicKey
		want error
	}{
		{"certificate_subject", certSubject, ErrCertificateKey},
		{"rsa_2048_subject", func(t *testing.T) ssh.PublicKey { return newRSASigner(t, testRSA2048).PublicKey() }, ErrSubjectKey},
		{"subject_is_ca_key", func(*testing.T) ssh.PublicKey { return ca.PublicKey() }, ErrSubjectKey},
		{"nil_subject", func(*testing.T) ssh.PublicKey { return nil }, ErrSubjectKey},
		{"rsa_3072_subject", func(t *testing.T) ssh.PublicKey { return newRSASigner(t, testRSA3072).PublicKey() }, nil},
		{"ed25519_subject", func(t *testing.T) ssh.PublicKey { return newEd25519Signer(t).PublicKey() }, nil},
		{"ecdsa_p256_subject", func(t *testing.T) ssh.PublicKey { return newECDSASigner(t, elliptic.P256()).PublicKey() }, nil},
		{"ecdsa_p384_subject", func(t *testing.T) ssh.PublicKey { return newECDSASigner(t, elliptic.P384()).PublicKey() }, nil},
		{"ecdsa_p521_subject", func(t *testing.T) ssh.PublicKey { return newECDSASigner(t, elliptic.P521()).PublicKey() }, nil},
		{"sk_ed25519_subject", func(t *testing.T) ssh.PublicKey { return newSKEd25519(t) }, nil},
		{"sk_ecdsa_subject", func(t *testing.T) ssh.PublicKey { return newSKECDSA(t) }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.key(t)
			c, err := Build(validRequest(t, key), ca, rand.Reader)
			wantErrIs(t, err, tc.want)
			if tc.want == nil {
				if !bytes.Equal(c.Key.Marshal(), key.Marshal()) {
					t.Fatal("certificate certifies another key")
				}
				verifyCert(t, c, ca.PublicKey(), "alice")
			}
		})
	}
	// ssh-dss is refused either by x/crypto's parser or by CheckSubjectKey.
	t.Run("dsa_subject", func(t *testing.T) {
		pub, err := ssh.ParsePublicKey(dsaBlob())
		if err != nil {
			t.Logf("refused by ssh.ParsePublicKey: %v", err)
			return // refused at parse time: the signer maps this to bad_subject_key
		}
		if pub.Type() != "ssh-dss" {
			t.Fatalf("parsed type %q, want ssh-dss", pub.Type())
		}
		wantErrIs(t, CheckSubjectKey(pub, ca.PublicKey()), ErrSubjectKey)
		_, err = Build(validRequest(t, pub), ca, rand.Reader)
		wantErrIs(t, err, ErrSubjectKey)
	})
}

func TestBuildCAKeys(t *testing.T) {
	subject := newEd25519Signer(t).PublicKey()
	certAsCA := func(t *testing.T) ssh.Signer {
		inner := newEd25519Signer(t)
		other := newEd25519Signer(t)
		c, err := Build(validRequest(t, inner.PublicKey()), other, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := ssh.NewCertSigner(c, inner)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	}
	tests := []struct {
		name string
		ca   func(t *testing.T) ssh.Signer
		want error
	}{
		{"certificate_as_ca", certAsCA, ErrCertificateKey},
		{"rsa_3072_ca", func(t *testing.T) ssh.Signer { return newRSASigner(t, testRSA3072) }, ErrCAKeyAlgorithm},
		{"ecdsa_p384_ca", func(t *testing.T) ssh.Signer { return newECDSASigner(t, elliptic.P384()) }, ErrCAKeyAlgorithm},
		{"ecdsa_p521_ca", func(t *testing.T) ssh.Signer { return newECDSASigner(t, elliptic.P521()) }, ErrCAKeyAlgorithm},
		{"ed25519_ca", func(t *testing.T) ssh.Signer { return newEd25519Signer(t) }, nil},
		{"ecdsa_p256_ca", func(t *testing.T) ssh.Signer { return newECDSASigner(t, elliptic.P256()) }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := tc.ca(t)
			wantErrIs(t, CheckCAKey(ca.PublicKey()), tc.want)
			c, err := Build(validRequest(t, subject), ca, rand.Reader)
			wantErrIs(t, err, tc.want)
			if tc.want == nil {
				verifyCert(t, c, ca.PublicKey(), "alice")
			}
		})
	}
	t.Run("nil_ca", func(t *testing.T) {
		wantErrIs(t, CheckCAKey(nil), ErrCAKeyAlgorithm)
	})
}

// principalAllowed is an independent byte-wise statement of the principal
// allowlist ^[a-z0-9][a-z0-9._@:+-]{0,127}$.
func principalAllowed(p string) bool {
	if len(p) == 0 || len(p) > 128 {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && strings.IndexByte("._@:+-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func FuzzValidatePrincipals(f *testing.F) {
	for _, s := range []string{
		"alice", "a", strings.Repeat("a", 128), strings.Repeat("a", 129), "", "*", "?", "a,b", "!a",
		" alice", "alice\n", "Alice", "alice\x00", "аlice", "café", "café", "a0._@:+-z", ".a", "\xff",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		err := ValidatePrincipals([]string{p})
		if err != nil && !errors.Is(err, ErrPrincipal) {
			t.Fatalf("ValidatePrincipals(%q) = %v, want nil or ErrPrincipal", p, err)
		}
		accepted := err == nil
		if accepted != principalRE.MatchString(p) || accepted != principalAllowed(p) {
			t.Fatalf("ValidatePrincipals(%q) accepted=%v, regex=%v, byte-wise=%v", p, accepted, principalRE.MatchString(p), principalAllowed(p))
		}
		if accepted {
			if err := ValidatePrincipals([]string{p, p}); !errors.Is(err, ErrPrincipal) {
				t.Fatalf("duplicate %q accepted: %v", p, err)
			}
		}
	})
}

// TestCheckIssued (C-WR-06): CheckIssued accepts what Build issues under a
// profile, the full validity cap included, and refuses a certificate a
// CA-key holder signed outside it.
func TestCheckIssued(t *testing.T) {
	ca := newEd25519Signer(t)
	subject := newEd25519Signer(t).PublicKey()
	build := func(t *testing.T, edit func(*Request)) (*ssh.Certificate, Profile) {
		t.Helper()
		req := validRequest(t, subject)
		req.Profile.AllowedExtensions = []string{"permit-agent-forwarding"}
		req.Profile.AllowedCriticalOptions = []string{"source-address"}
		if edit != nil {
			edit(&req)
		}
		c, err := Build(req, ca, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return c, req.Profile
	}
	t.Run("built_at_the_cap", func(t *testing.T) {
		c, p := build(t, func(r *Request) {
			r.ValidFor = r.Profile.MaxTTL
			r.ExtraExtensions = map[string]string{"permit-agent-forwarding": ""}
			r.CriticalOptions = map[string]string{"source-address": "10.0.0.0/8"}
		})
		wantErrIs(t, CheckIssued(c, p), nil)
	})
	t.Run("built_host", func(t *testing.T) {
		c, p := build(t, func(r *Request) {
			r.Profile = Profile{CertType: ssh.HostCert, MaxTTL: 24 * time.Hour}
			r.Principals = []string{"host.example"}
		})
		wantErrIs(t, CheckIssued(c, p), nil)
	})
	cases := []struct {
		name string
		edit func(c *ssh.Certificate, p *Profile)
		want error
	}{
		{"one_second_over_the_cap", func(c *ssh.Certificate, p *Profile) {
			c.ValidBefore = c.ValidAfter + uint64((p.MaxTTL+backdate)/time.Second) + 1 //nolint:gosec // G115: a positive test duration
		}, ErrValidity},
		{"no_time_after_the_backdate", func(c *ssh.Certificate, _ *Profile) {
			c.ValidBefore = c.ValidAfter + uint64(backdate/time.Second)
		}, ErrValidity},
		{"forever", func(c *ssh.Certificate, _ *Profile) { c.ValidAfter, c.ValidBefore = 0, math.MaxUint64 }, ErrValidity},
		{"before_not_after_after", func(c *ssh.Certificate, _ *Profile) { c.ValidBefore = c.ValidAfter }, ErrValidity},
		{"extension_outside_profile", func(c *ssh.Certificate, _ *Profile) { c.Extensions["permit-port-forwarding"] = "" }, ErrExtension},
		{"critical_option_outside_profile", func(c *ssh.Certificate, _ *Profile) {
			c.CriticalOptions = map[string]string{"force-command": "/bin/sh"}
		}, ErrExtension},
		{"host_cert_with_extension", func(c *ssh.Certificate, p *Profile) {
			c.CertType, p.CertType = ssh.HostCert, ssh.HostCert
			p.DefaultExtensions, p.AllowedExtensions = nil, nil
		}, ErrExtension},
		{"wrong_cert_type", func(c *ssh.Certificate, _ *Profile) { c.CertType = ssh.HostCert }, ErrProfile},
		{"no_principals", func(c *ssh.Certificate, _ *Profile) { c.ValidPrincipals = nil }, ErrEmptyPrincipals},
		{"bad_principal", func(c *ssh.Certificate, _ *Profile) { c.ValidPrincipals = []string{"Alice Smith"} }, ErrPrincipal},
		{"subject_is_ca", func(c *ssh.Certificate, _ *Profile) { c.Key = c.SignatureKey }, ErrSubjectKey},
		{"serial_zero", func(c *ssh.Certificate, _ *Profile) { c.Serial = 0 }, ErrSerial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p := build(t, nil)
			tc.edit(c, &p)
			wantErrIs(t, CheckIssued(c, p), tc.want)
		})
	}
	t.Run("no_certificate", func(t *testing.T) {
		if err := CheckIssued(nil, DefaultUserProfile()); err == nil {
			t.Fatal("CheckIssued(nil) accepted")
		}
		c, p := build(t, nil)
		c.SignatureKey = nil
		if err := CheckIssued(c, p); err == nil {
			t.Fatal("CheckIssued accepted a certificate without a CA key")
		}
	})
	t.Run("unusable_profile", func(t *testing.T) {
		c, p := build(t, nil)
		p.CertType = 3
		wantErrIs(t, CheckIssued(c, p), ErrProfile)
		_, p = build(t, nil)
		p.MaxTTL = 0
		wantErrIs(t, CheckIssued(c, p), ErrProfile)
	})
}
