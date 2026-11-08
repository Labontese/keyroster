package probe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

const t0 = 1_800_000_000

func newSigner(t testing.TB) ssh.Signer {
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

// env is a host key, a machine CA, web1's entry and a serial counter.
type env struct {
	host, ca ssh.Signer
	entry    *directory.Host
	serial   uint64
}

func newEnv(t testing.TB) *env {
	t.Helper()
	e := &env{host: newSigner(t), ca: newSigner(t), serial: 100}
	e.entry = &directory.Host{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(e.host.PublicKey())}, Principals: []string{"web1"}, Status: directory.StatusActive}
	return e
}

// probeProfile is certprofile.ProbeProfile's shape with a 30-day cap, so a
// test can build a certificate above the probe maximum.
var probeProfile = cert.Profile{CertType: ssh.UserCert, MaxTTL: 30 * 24 * time.Hour, DefaultExtensions: map[string]string{},
	AllowedCriticalOptions: []string{"force-command", "source-address"}, ReservedPrincipals: true}

// issue builds a probe certificate for key, issued at issued for v
// seconds, by ca, as the signer does (cert.Build backdates five minutes).
func (e *env) issue(t testing.TB, key ssh.PublicKey, issued, v uint64, ca ssh.Signer) *ssh.Certificate {
	t.Helper()
	e.serial++
	c, err := cert.Build(cert.Request{Profile: probeProfile, Subject: key, Principals: []string{cert.ReservedPrincipalPrefix + "web1"},
		Now: time.Unix(int64(issued), 0), ValidFor: time.Duration(v) * time.Second, Serial: e.serial, //nolint:gosec // G115: test times
		KeyID:           cert.KeyID{V3: true, CA: "machine", Subject: "probe.web1", Request: strings.Repeat("ab", 16), Policy: 1, Directory: 1, Serial: e.serial},
		CriticalOptions: certprofile.ProbeCriticalOptions()}, ca, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// pair issues a positive and a negative for fresh keys at issued for v
// seconds by ca, with renewal times drawn by hostcert.RenewAt from rnd.
func (e *env) pair(t testing.TB, issued, v uint64, ca ssh.Signer, rnd io.Reader) Pair {
	t.Helper()
	var p Pair
	for _, pol := range Polarities {
		c := e.issue(t, newSigner(t).PublicKey(), issued, v, ca)
		r, err := hostcert.RenewAt(c, rnd)
		if err != nil {
			t.Fatal(err)
		}
		p.Set(pol, NewCert(c, r))
	}
	return p
}

// krlOf is a parsed KRL listing serials under ca, and keys explicitly.
func krlOf(t testing.TB, ca ssh.PublicKey, serials []uint64, keyIDs []string, keys ...ssh.PublicKey) *krl.Parsed {
	t.Helper()
	set := krl.Set{Keys: keys}
	if len(serials) > 0 || len(keyIDs) > 0 {
		set.Certs = []krl.CertSection{{CAKey: ca, Serials: serials, KeyIDs: keyIDs}}
	}
	b, err := krl.Encode(set, 1, time.Unix(t0, 0))
	if err != nil {
		t.Fatal(err)
	}
	k, err := krl.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// listing is a KRL that lists p's negative serial.
func (e *env) listing(t testing.TB, ps ...Pair) *krl.Parsed {
	t.Helper()
	var s []uint64
	for _, p := range ps {
		if p.Negative != nil {
			s = append(s, p.Negative.Serial)
		}
	}
	return krlOf(t, e.ca.PublicKey(), s, nil)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// failAfter supplies n random bytes, then fails.
type failAfter struct{ n int }

func (f *failAfter) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("rand exhausted")
	}
	k := min(len(p), f.n)
	if _, err := rand.Read(p[:k]); err != nil {
		return 0, err
	}
	f.n -= k
	return k, nil
}

const installation = "0123456789abcdef0123456789abcdef"

func TestBuildRequest(t *testing.T) {
	e := newEnv(t)
	now := time.Unix(t0, 0)
	t.Run("fields_bound", func(t *testing.T) {
		req, pk, err := BuildRequest(e.host, installation, "web1", true, now, rand.Reader, ed25519.GenerateKey)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case req.InstallationID != installation, req.HostName != "web1", !bytes.Equal(req.HostKey, e.host.PublicKey().Marshal()),
			!bytes.Equal(req.ProbeKey, pk.Marshal()), !req.Negative, req.ValidForSeconds != 0, req.RequestID == [16]byte{}, req.CreatedAt != t0:
			t.Fatalf("request %+v", req)
		}
		if pk.Type() != ssh.KeyAlgoED25519 || bytes.Equal(pk.Marshal(), e.host.PublicKey().Marshal()) {
			t.Fatalf("probe key %s", pk.Type())
		}
		pos, _, err := BuildRequest(e.host, installation, "web1", false, now, rand.Reader, ed25519.GenerateKey)
		if err != nil || pos.Negative {
			t.Fatalf("a positive request: %+v, %v", pos, err)
		}
	})
	t.Run("two_evidence_in_order", func(t *testing.T) {
		req, pk, err := BuildRequest(e.host, installation, "web1", false, now, rand.Reader, ed25519.GenerateKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(req.Evidence) != 2 || req.Evidence[0].Type != wire.EvidenceHostPoP || req.Evidence[1].Type != wire.EvidenceProbePoP {
			t.Fatalf("evidence %+v", req.Evidence)
		}
		for i, want := range []ssh.PublicKey{e.host.PublicKey(), pk} {
			s, err := sshsig.Parse(req.Evidence[i].Blob)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(s.PublicKey().Marshal(), want.Marshal()) {
				t.Fatalf("evidence %d is signed by another key", i)
			}
		}
	})
	t.Run("signed_under_probe_namespace", func(t *testing.T) {
		req, _, err := BuildRequest(e.host, installation, "web1", true, now, rand.Reader, ed25519.GenerateKey)
		if err != nil {
			t.Fatal(err)
		}
		for i, ev := range req.Evidence {
			s, err := sshsig.Parse(ev.Blob)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Verify(wire.ProbePoPNamespace, req.SigningBytes()); err != nil {
				t.Fatalf("evidence %d under the probe namespace: %v", i, err)
			}
			if err := s.Verify(wire.HostPoPNamespace, req.SigningBytes()); err == nil {
				t.Fatalf("evidence %d verifies under the host namespace", i)
			}
		}
	})
	t.Run("ephemeral_key_cleared", func(t *testing.T) {
		var kept ed25519.PrivateKey
		gen := func(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
			pub, priv, err := ed25519.GenerateKey(r)
			kept = priv
			return pub, priv, err
		}
		zero := func(what string) {
			t.Helper()
			if len(kept) != ed25519.PrivateKeySize {
				t.Fatalf("%s: the generator kept no key", what)
			}
			if !bytes.Equal(kept, make([]byte, ed25519.PrivateKeySize)) {
				t.Fatalf("%s: the probe private key was not cleared", what)
			}
		}
		if _, _, err := BuildRequest(e.host, installation, "web1", true, now, rand.Reader, gen); err != nil {
			t.Fatal(err)
		}
		zero("success")
		kept = nil
		// The key's 32 seed bytes, then the request ID read fails.
		if _, _, err := BuildRequest(e.host, installation, "web1", true, now, &failAfter{n: ed25519.SeedSize}, gen); err == nil {
			t.Fatal("a failing random source after the key: no error")
		}
		zero("request ID error")
		kept = nil
		if _, _, err := BuildRequest(e.host, "not-an-installation", "web1", true, now, rand.Reader, gen); err == nil {
			t.Fatal("an invalid installation ID: no error")
		}
		zero("validation error")
	})
	t.Run("fresh_key_per_request", func(t *testing.T) {
		n := 0
		gen := func(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
			n++
			return ed25519.GenerateKey(r)
		}
		a, ka, err := BuildRequest(e.host, installation, "web1", true, now, rand.Reader, gen)
		if err != nil {
			t.Fatal(err)
		}
		b, kb, err := BuildRequest(e.host, installation, "web1", true, now, rand.Reader, gen)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 || bytes.Equal(ka.Marshal(), kb.Marshal()) || a.RequestID == b.RequestID || bytes.Equal(a.ProbeKey, b.ProbeKey) {
			t.Fatalf("generator calls %d, same key %t, same ID %t", n, bytes.Equal(ka.Marshal(), kb.Marshal()), a.RequestID == b.RequestID)
		}
	})
	t.Run("wire_roundtrip", func(t *testing.T) {
		req, _, err := BuildRequest(e.host, installation, "web1", true, now, rand.Reader, ed25519.GenerateKey)
		if err != nil {
			t.Fatal(err)
		}
		b, err := req.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := wire.ParseProbeIssueRequest(b)
		if err != nil {
			t.Fatal(err)
		}
		again, err := got.Marshal()
		if err != nil || !bytes.Equal(b, again) || got.Digest() != req.Digest() {
			t.Fatalf("round trip differs (%v)", err)
		}
	})
}

func TestVerifyCert(t *testing.T) {
	e := newEnv(t)
	probe := newSigner(t).PublicKey()
	const v = 600
	now := time.Unix(t0+10, 0)
	check := CertCheck{HostName: "web1", ProbeKey: probe, CAKeys: []ssh.PublicKey{e.ca.PublicKey()}, Now: now}
	good := func() *ssh.Certificate { return e.issue(t, probe, t0, v, e.ca) }
	keyID := func(c *ssh.Certificate, edit func(*cert.KeyID)) string {
		k, err := cert.ParseKeyID(c.KeyId)
		if err != nil {
			t.Fatal(err)
		}
		edit(&k)
		return k.String()
	}
	t.Run("ok", func(t *testing.T) {
		if err := VerifyCert(good(), check); err != nil {
			t.Fatal(err)
		}
	})
	cases := []struct {
		code string
		mut  func(c *ssh.Certificate) *ssh.Certificate
		in   func(in CertCheck) CertCheck
	}{
		{code: "wrong_type_host_cert", mut: func(c *ssh.Certificate) *ssh.Certificate { c.CertType = ssh.HostCert; return c }},
		{code: "other_key", mut: func(_ *ssh.Certificate) *ssh.Certificate { return e.issue(t, newSigner(t).PublicKey(), t0, v, e.ca) }},
		{code: "principal_other_host", mut: func(c *ssh.Certificate) *ssh.Certificate {
			c.ValidPrincipals = []string{cert.ReservedPrincipalPrefix + "web9"}
			return c
		}},
		{code: "principal_without_prefix", mut: func(c *ssh.Certificate) *ssh.Certificate { c.ValidPrincipals = []string{"web1"}; return c }},
		{code: "two_principals", mut: func(c *ssh.Certificate) *ssh.Certificate {
			c.ValidPrincipals = append(c.ValidPrincipals, "role:ops")
			return c
		}},
		{code: "extension_present", mut: func(c *ssh.Certificate) *ssh.Certificate {
			c.Extensions = map[string]string{"permit-pty": ""}
			return c
		}},
		{code: "force_command_missing", mut: func(c *ssh.Certificate) *ssh.Certificate { delete(c.CriticalOptions, "force-command"); return c }},
		{code: "force_command_value", mut: func(c *ssh.Certificate) *ssh.Certificate { c.CriticalOptions["force-command"] = "/bin/sh"; return c }},
		{code: "source_address_missing", mut: func(c *ssh.Certificate) *ssh.Certificate { delete(c.CriticalOptions, "source-address"); return c }},
		{code: "source_address_value", mut: func(c *ssh.Certificate) *ssh.Certificate {
			c.CriticalOptions["source-address"] = "127.0.0.1/32"
			return c
		}},
		{code: "extra_critical_option", mut: func(c *ssh.Certificate) *ssh.Certificate { c.CriticalOptions["verify-required"] = ""; return c }},
		{code: "ca_not_trusted", mut: func(_ *ssh.Certificate) *ssh.Certificate { return e.issue(t, probe, t0, v, newSigner(t)) }},
		{code: "signature_invalid", mut: func(c *ssh.Certificate) *ssh.Certificate { c.Nonce = []byte("another nonce"); return c }},
		{code: "key_id_not_kr3", mut: func(c *ssh.Certificate) *ssh.Certificate { c.KeyId = "probe web1"; return c }},
		{code: "key_id_ca_not_machine", mut: func(c *ssh.Certificate) *ssh.Certificate {
			c.KeyId = keyID(c, func(k *cert.KeyID) { k.CA = "host" })
			return c
		}},
		{code: "key_id_subject_other_host", mut: func(c *ssh.Certificate) *ssh.Certificate {
			c.KeyId = keyID(c, func(k *cert.KeyID) { k.Subject = "probe.web9" })
			return c
		}},
		{code: "key_id_serial_mismatch", mut: func(c *ssh.Certificate) *ssh.Certificate {
			c.KeyId = keyID(c, func(k *cert.KeyID) { k.Serial++ })
			return c
		}},
		{code: "lifetime_zero", mut: func(c *ssh.Certificate) *ssh.Certificate { c.ValidBefore = c.ValidAfter + hostcert.Backdate; return c }},
		{code: "lifetime_over_seven_days", mut: func(_ *ssh.Certificate) *ssh.Certificate {
			return e.issue(t, probe, t0, certprofile.MaxProbeLifetimeSeconds+1, e.ca)
		}},
		{code: "not_yet_valid", in: func(in CertCheck) CertCheck { in.Now = time.Unix(t0-hostcert.Backdate-1, 0); return in }},
		{code: "expired_or_in_margin", in: func(in CertCheck) CertCheck { in.Now = time.Unix(t0+v-60, 0); return in }},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			c, in := good(), check
			if tc.mut != nil {
				c = tc.mut(c)
				// Every edited defect is signed again by the trusted machine
				// CA, so that a removed rule shows as an accepted
				// certificate, not as a signature refusal (03-10b); only
				// signature_invalid keeps a broken signature and
				// ca_not_trusted its untrusted one.
				if tc.code != "signature_invalid" && tc.code != "ca_not_trusted" {
					if err := c.SignCert(rand.Reader, e.ca); err != nil {
						t.Fatal(err)
					}
				}
				// signatureValid is false exactly for the broken signature,
				// so it is not vacuous.
				if valid := signatureValid(c); valid != (tc.code != "signature_invalid") {
					t.Fatalf("the defect certificate's signature verifies: %t", valid)
				}
			}
			if tc.in != nil {
				in = tc.in(in)
			}
			err := VerifyCert(c, in)
			if got := ErrCode(err); err == nil || got != tc.code {
				t.Fatalf("VerifyCert: %v (code %q), want %q", err, got, tc.code)
			}
		})
	}
}

// signatureValid reports whether c's signature verifies under its own
// SignatureKey: the signed bytes are the certificate's wire form without
// its trailing signature field.
func signatureValid(c *ssh.Certificate) bool {
	if c.Signature == nil || c.SignatureKey == nil {
		return false
	}
	b := c.Marshal()
	n := 4 + len(ssh.Marshal(c.Signature))
	if len(b) < n {
		return false
	}
	return c.SignatureKey.Verify(b[:len(b)-n], c.Signature) == nil
}

func TestPairUsable(t *testing.T) {
	e := newEnv(t)
	cas := []ssh.PublicKey{e.ca.PublicKey()}
	const v = 600
	p := e.pair(t, t0, v, e.ca, zeroReader{})
	k := e.listing(t, p)
	now := time.Unix(t0+10, 0)
	t.Run("usable", func(t *testing.T) {
		if r := PairUsable(p, now, k, cas); r != "" {
			t.Fatal(r)
		}
	})
	t.Run("valid_at_future_time", func(t *testing.T) {
		vb := p.Positive.ValidBefore
		if r := PairUsable(p, time.Unix(int64(vb-61), 0), k, cas); r != "" { //nolint:gosec // G115: test times
			t.Fatalf("61 s before ValidBefore: %s", r)
		}
		if r := PairUsable(p, time.Unix(int64(vb-60), 0), k, cas); r != CertMissing { //nolint:gosec // G115: test times
			t.Fatalf("60 s before ValidBefore: %q, want cert_missing", r)
		}
	})
	t.Run("margin_is_min_60_or_sixth", func(t *testing.T) {
		short := e.pair(t, t0, 120, e.ca, zeroReader{}) // V/6 = 20 s
		ks := e.listing(t, short)
		vb := short.Positive.ValidBefore
		if r := PairUsable(short, time.Unix(int64(vb-21), 0), ks, cas); r != "" { //nolint:gosec // G115: test times
			t.Fatalf("V=120, 21 s before ValidBefore: %s", r)
		}
		if r := PairUsable(short, time.Unix(int64(vb-20), 0), ks, cas); r != CertMissing { //nolint:gosec // G115: test times
			t.Fatalf("V=120, 20 s before ValidBefore: %q", r)
		}
	})
	t.Run("positive_in_krl", func(t *testing.T) {
		kk := krlOf(t, e.ca.PublicKey(), []uint64{p.Positive.Serial, p.Negative.Serial}, nil)
		if r := PairUsable(p, now, kk, cas); r != PositiveInKRL {
			t.Fatalf("%q", r)
		}
	})
	t.Run("negative_not_in_krl", func(t *testing.T) {
		neg := p.Negative.Parse()
		for name, kk := range map[string]*krl.Parsed{
			"none":   nil,
			"empty":  krlOf(t, e.ca.PublicKey(), nil, nil),
			"key_id": krlOf(t, e.ca.PublicKey(), nil, []string{neg.KeyId}),
			"key":    krlOf(t, e.ca.PublicKey(), nil, nil, neg.Key),
		} {
			if r := PairUsable(p, now, kk, cas); r != NegativeNotInKRL {
				t.Fatalf("%s: %q, want negative_not_in_krl", name, r)
			}
		}
	})
	t.Run("negative_listed_by_serial_range", func(t *testing.T) {
		s := p.Negative.Serial
		kk := krlOf(t, e.ca.PublicKey(), []uint64{s - 1, s, s + 1, s + 2}, nil)
		if p.Positive.Serial >= s-1 && p.Positive.Serial <= s+2 {
			kk = krlOf(t, e.ca.PublicKey(), []uint64{s, s + 1, s + 2}, nil)
		}
		if r := PairUsable(p, now, kk, cas); r != "" {
			t.Fatalf("%q", r)
		}
	})
	t.Run("ca_mismatch", func(t *testing.T) {
		other := newSigner(t)
		mixed := Pair{Positive: p.Positive}
		c := e.issue(t, newSigner(t).PublicKey(), t0, v, other)
		mixed.Negative = NewCert(c, hostcert.IssuedAt(c)+400)
		kk := krlOf(t, other.PublicKey(), []uint64{c.Serial}, nil)
		if r := PairUsable(mixed, now, kk, []ssh.PublicKey{e.ca.PublicKey(), other.PublicKey()}); r != CAMismatch {
			t.Fatalf("two CA keys: %q", r)
		}
		if r := PairUsable(p, now, k, []ssh.PublicKey{other.PublicKey()}); r != CAMismatch {
			t.Fatalf("an untrusted CA key: %q", r)
		}
	})
	t.Run("half_pair_is_missing", func(t *testing.T) {
		if r := PairUsable(Pair{Positive: p.Positive}, now, k, cas); r != CertMissing {
			t.Fatalf("%q", r)
		}
		if r := PairUsable(Pair{}, now, k, cas); r != CertMissing {
			t.Fatalf("empty: %q", r)
		}
	})
}

// input is Decide's input for e at now.
func (e *env) input(now uint64, committed, next Pair, a *Attempts, k *krl.Parsed) Input {
	if a == nil {
		a = &NewRecord().Attempts
	}
	return Input{Now: time.Unix(int64(now), 0), Committed: committed, Next: next, Attempts: a, Entry: e.entry, Authorized: true, //nolint:gosec // G115: test times
		Bundle: 1, Policy: 1, Directory: 1, CAKeys: []ssh.PublicKey{e.ca.PublicKey()}, KRL: k}
}

func wantRequests(t *testing.T, pl Plan, pols ...Polarity) {
	t.Helper()
	var got []Polarity
	for _, r := range pl.Requests {
		got = append(got, r.Polarity)
	}
	if !slices.Equal(got, pols) {
		t.Fatalf("requests %v, want %v (plan %+v)", got, pols, pl)
	}
}

func TestDecide(t *testing.T) {
	e := newEnv(t)
	const v = 600
	holds := []struct {
		name, want string
		nothing    bool
		edit       func(in *Input)
	}{
		{"hold_no_generation", hostcert.HoldNoGeneration, true, func(in *Input) { in.NoGeneration = true }},
		{"hold_apply_unfinished", hostcert.HoldApplyUnfinished, true, func(in *Input) { in.ApplyUnfinished = true }},
		{"hold_directory_unauthorized", hostcert.HoldDirectoryUnauthorized, false, func(in *Input) { in.Authorized = false }},
		{"hold_host_disabled", hostcert.HoldHostDisabled, false, func(in *Input) {
			en := *in.Entry
			en.Status = directory.StatusDisabled
			in.Entry = &en
		}},
		{"hold_host_removed", hostcert.HoldHostRemoved, false, func(in *Input) { in.Entry = nil }},
		{"hold_host_keys_rotated", hostcert.HoldHostKeysRotated, false, func(in *Input) { in.HostStatus = hostcert.HoldHostKeysRotated }},
		{"hold_host_keys_disagree", hostcert.HoldHostKeysDisagree, false, func(in *Input) { in.HostStatus = hostcert.HoldHostKeysDisagree }},
	}
	for _, h := range holds {
		t.Run(h.name, func(t *testing.T) {
			in := e.input(t0, Pair{}, Pair{}, nil, nil)
			h.edit(&in)
			pl := Decide(in)
			if pl.Hold != h.want || pl.WriteNothing != h.nothing || len(pl.Requests) != 0 || pl.Switch {
				t.Fatalf("plan %+v, want hold %s (write nothing %t)", pl, h.want, h.nothing)
			}
		})
	}
	t.Run("requests_both_polarities_when_no_pair", func(t *testing.T) {
		wantRequests(t, Decide(e.input(t0, Pair{}, Pair{}, nil, nil)), Positive, Negative)
	})
	t.Run("requests_only_the_missing_polarity_of_next", func(t *testing.T) {
		p := e.pair(t, t0, v, e.ca, zeroReader{})
		for _, tc := range []struct {
			next Pair
			want Polarity
		}{{Pair{Positive: p.Positive}, Negative}, {Pair{Negative: p.Negative}, Positive}} {
			wantRequests(t, Decide(e.input(t0+10, Pair{}, tc.next, nil, e.listing(t, p))), tc.want)
		}
	})
	t.Run("renew_pair_at_two_thirds", func(t *testing.T) {
		p := e.pair(t, t0, v, e.ca, rand.Reader)
		k := e.listing(t, p)
		renew := min(p.Positive.RenewAt, p.Negative.RenewAt)
		jitter := min(uint64(3600), v/10)
		early := t0 + 2*v/3 - jitter - 1
		if pl := Decide(e.input(early, p, Pair{}, nil, k)); len(pl.Requests) != 0 {
			t.Fatalf("at 2L/3 minus the jitter bound minus 1 s: %+v", pl)
		}
		pl := Decide(e.input(renew, p, Pair{}, nil, k))
		wantRequests(t, pl, Positive, Negative)
		if pl.Requests[0].Why != "renew" {
			t.Fatalf("why %q", pl.Requests[0].Why)
		}
	})
	t.Run("keep_old_pair_until_new_negative_listed", func(t *testing.T) {
		old := e.pair(t, t0, v, e.ca, zeroReader{})
		next := e.pair(t, t0+400, v, e.ca, zeroReader{})
		pl := Decide(e.input(t0+410, old, next, nil, e.listing(t, old)))
		if pl.Switch || pl.DropNext || len(pl.Requests) != 0 {
			t.Fatalf("a new pair whose negative is not listed: %+v", pl)
		}
	})
	t.Run("switch_when_next_negative_listed", func(t *testing.T) {
		old := e.pair(t, t0, v, e.ca, zeroReader{})
		next := e.pair(t, t0+400, v, e.ca, zeroReader{})
		pl := Decide(e.input(t0+410, old, next, nil, e.listing(t, old, next)))
		if !pl.Switch || len(pl.Requests) != 0 {
			t.Fatalf("plan %+v, want a switch", pl)
		}
	})
	t.Run("committed_missing_and_next_usable_switches", func(t *testing.T) {
		old := e.pair(t, t0, v, e.ca, zeroReader{})
		next := e.pair(t, t0+500, v, e.ca, zeroReader{})
		pl := Decide(e.input(t0+v-30, old, next, nil, e.listing(t, old, next)))
		if !pl.Switch {
			t.Fatalf("plan %+v, want a switch", pl)
		}
	})
	t.Run("positive_in_krl_is_missing", func(t *testing.T) {
		p := e.pair(t, t0, v, e.ca, zeroReader{})
		k := krlOf(t, e.ca.PublicKey(), []uint64{p.Positive.Serial, p.Negative.Serial}, nil)
		pl := Decide(e.input(t0+10, p, Pair{}, nil, k))
		wantRequests(t, pl, Positive, Negative)
		if pl.Requests[0].Why != "missing" {
			t.Fatalf("why %q", pl.Requests[0].Why)
		}
	})
	t.Run("ca_no_longer_trusted_is_missing", func(t *testing.T) {
		p := e.pair(t, t0, v, e.ca, zeroReader{})
		in := e.input(t0+10, p, Pair{}, nil, e.listing(t, p))
		in.CAKeys = []ssh.PublicKey{newSigner(t).PublicKey()}
		wantRequests(t, Decide(in), Positive, Negative)
	})
	t.Run("next_pair_ca_mismatch_requests_again", func(t *testing.T) {
		other := newSigner(t)
		next := e.pair(t, t0, v, other, zeroReader{})
		k := krlOf(t, other.PublicKey(), []uint64{next.Negative.Serial}, nil)
		pl := Decide(e.input(t0+10, Pair{}, next, nil, k))
		if pl.Switch || !pl.DropNext {
			t.Fatalf("plan %+v, want Next dropped", pl)
		}
		wantRequests(t, pl, Positive, Negative)
	})
	t.Run("pending_request_defers", func(t *testing.T) {
		a := &NewRecord().Attempts
		pk := newSigner(t).PublicKey().Marshal()
		a.Positive.AddRequest(strings.Repeat("01", 16), t0, pk)
		a.Negative.AddRequest(strings.Repeat("02", 16), t0, pk)
		pl := Decide(e.input(t0+10, Pair{}, Pair{}, a, nil))
		if len(pl.Requests) != 0 || pl.Defers[Positive] != DeferPending || pl.Defers[Negative] != DeferPending {
			t.Fatalf("plan %+v", pl)
		}
		// Abandoned after hostcert.RequestTTL: requested again.
		wantRequests(t, Decide(e.input(t0+hostcert.RequestTTL, Pair{}, Pair{}, a, nil)), Positive, Negative)
	})
	t.Run("backoff_defers", func(t *testing.T) {
		a := &NewRecord().Attempts
		a.Negative.NextAt = t0 + 60
		pl := Decide(e.input(t0+10, Pair{}, Pair{}, a, nil))
		wantRequests(t, pl, Positive)
		if pl.Defers[Negative] != DeferBackoff {
			t.Fatalf("plan %+v", pl)
		}
		wantRequests(t, Decide(e.input(t0+60, Pair{}, Pair{}, a, nil)), Positive, Negative)
	})
	t.Run("sticky_defers_until_version_changes_or_24h", func(t *testing.T) {
		a := &NewRecord().Attempts
		in := e.input(t0, Pair{}, Pair{}, a, nil)
		Fail(in, Positive, "host_disabled")
		if a.Positive.Sticky == nil {
			t.Fatal("host_disabled recorded no sticky hold")
		}
		pl := Decide(e.input(t0+3600, Pair{}, Pair{}, a, nil))
		if pl.Defers[Positive] != DeferRefusedPrefix+"host_disabled" {
			t.Fatalf("plan %+v", pl)
		}
		changed := e.input(t0+3600, Pair{}, Pair{}, a, nil)
		changed.Directory = 2
		wantRequests(t, Decide(changed), Positive, Negative)
		wantRequests(t, Decide(e.input(t0+hostcert.StickyRelease, Pair{}, Pair{}, a, nil)), Positive, Negative)
	})
	t.Run("recent_is_transient_with_backoff", func(t *testing.T) {
		// P4: after an agent-side state loss the record knows no earlier
		// certificate, so probe_cert_recent backs off like any transient.
		a := &NewRecord().Attempts
		Fail(e.input(t0, Pair{}, Pair{}, a, nil), Positive, "probe_cert_recent")
		if a.Positive.Sticky != nil || a.Positive.NextAt != t0+hostcert.BackoffMin {
			t.Fatalf("attempt %+v", a.Positive)
		}
		if pl := Decide(e.input(t0+30, Pair{}, Pair{}, a, nil)); pl.Defers[Positive] != DeferBackoff {
			t.Fatalf("plan %+v", pl)
		}
		wantRequests(t, Decide(e.input(t0+hostcert.BackoffMin, Pair{}, Pair{}, a, nil)), Positive, Negative)
	})
	t.Run("recent_waits_for_window_end_when_known", func(t *testing.T) {
		// A committed pair whose negative is not listed is not usable, so
		// both polarities are wanted; the record knows when the latest
		// positive was issued.
		p := e.pair(t, t0, v, e.ca, zeroReader{})
		a := &NewRecord().Attempts
		Fail(e.input(t0+50, p, Pair{}, a, nil), Positive, "probe_cert_recent")
		end := uint64(t0 + v/3) // certprofile.ProbeCertRecent: min(3600, L/3)
		if a.Positive.NextAt != end || a.Positive.Sticky != nil {
			t.Fatalf("next_at %d, want %d", a.Positive.NextAt, end)
		}
		if pl := Decide(e.input(end-1, p, Pair{}, a, nil)); pl.Defers[Positive] != DeferBackoff {
			t.Fatalf("plan %+v", pl)
		}
		wantRequests(t, Decide(e.input(end, p, Pair{}, a, nil)), Positive, Negative)
	})
}

func TestIsSticky(t *testing.T) {
	sticky := []string{"host_key_not_enrolled", "host_name_mismatch", "signer_too_old", "malformed_request", "unknown_host",
		"host_key_not_listed", "host_key_revoked", "host_disabled", "host_pop_not_enabled", "probe_issue_no_installation_id",
		"probe_issue_installation_mismatch", "probe_issue_valid_for_not_zero", "http_400", "http_403", "http_404", "http_413"}
	transient := []string{"request_time_skew", "directory_changed", "trust_changed", "probe_cert_recent", "duplicate_request",
		"host_pop_invalid", "probe_pop_invalid", "probe_key_unusable", "ca_not_configured", "directory_not_installed",
		"directory_not_authorized", "state_unavailable", "serial_unavailable", "clock_regression", "krl_too_large",
		"krl_no_installation_id", "revocations_not_logged", "http_429", "http_500", "http_503", "no_answer", "answer_too_large",
		"something_new", ""}
	for _, d := range sticky {
		if !IsSticky(d) {
			t.Errorf("%q: transient, want sticky", d)
		}
	}
	for _, d := range transient {
		if IsSticky(d) {
			t.Errorf("%q: sticky, want transient", d)
		}
	}
}

func FuzzParseRecord(f *testing.F) {
	e := newEnv(f)
	r := NewRecord()
	r.Committed = e.pair(f, t0, 600, e.ca, zeroReader{})
	r.Attempts.Negative.AddRequest(strings.Repeat("ab", 16), t0, newSigner(f).PublicKey().Marshal())
	r.Attempts.Positive.Sticky = &hostcert.StickyHold{Code: "host_disabled", Bundle: 1, Policy: 1, Directory: 1, At: t0}
	r.Detail = "probe_issue:backoff"
	good, err := r.Encode()
	if err != nil {
		f.Fatal(err)
	}
	empty, err := NewRecord().Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(empty)
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseRecord(data)
		if err != nil {
			return
		}
		b, err := r.Encode()
		if err != nil {
			t.Fatalf("an accepted record does not encode: %v", err)
		}
		if !bytes.Equal(b, data) {
			t.Fatalf("an accepted record re-encodes differently:\n%s\n%s", data, b)
		}
	})
}
