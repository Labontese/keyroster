package join

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/tlspin"
	"github.com/Labontese/keyroster/internal/trust"
)

// testRoot is a self-signed CA certificate in PEM and its pin.
func testRoot(t testing.TB, cn string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), tlspin.PinOf(c)
}

// trustPin is a trust root fingerprint.
func trustPin(t testing.TB) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(k)
}

// valid is a valid join token with two TLS roots and two trust pins.
func valid(t testing.TB) JoinToken {
	t.Helper()
	r1, p1 := testRoot(t, "root one")
	r2, p2 := testRoot(t, "root two")
	tok := make([]byte, TokenBytes)
	if _, err := rand.Read(tok); err != nil {
		t.Fatal(err)
	}
	return JoinToken{
		Version: Version, Server: "https://keyroster.example:8443", TLSRoots: []string{r1, r2},
		TLSPins: slices.Sorted(slices.Values([]string{p1, p2})), TrustPins: slices.Sorted(slices.Values([]string{trustPin(t), trustPin(t)})), Threshold: 2,
		InstallationID: "0123456789abcdef0123456789abcdef", Token: EncodeToken(tok), ExpectedName: "web1", ExpiresAt: "2026-10-28T12:30:00Z",
	}
}

// encode is Format without its sorting and checks: the join string of j's
// canonical JSON exactly as given.
func encode(t testing.TB, j JoinToken) string {
	t.Helper()
	b, err := trust.CanonicalJSON(j)
	if err != nil {
		t.Fatal(err)
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(b)
}

// TestParse pins every rule of a join string (AGENT-01 edges: empty,
// ordering, precision).
func TestParse(t *testing.T) {
	t.Run("round_trip", func(t *testing.T) {
		j := valid(t)
		s, err := Format(j)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(s + "\n")
		if err != nil {
			t.Fatal(err)
		}
		if again, err := Format(*got); err != nil || again != s {
			t.Fatalf("Format(Parse(s)) = %q, %v; want s", again, err)
		}
	})
	t.Run("expiry_boundary", func(t *testing.T) {
		// expires_at is RFC 3339 UTC with whole seconds, compared in whole
		// seconds; keyroster-server enforces it at the second (at
		// expires_at refused, one second before accepted, on its injected
		// clock: internal/server TestAgentEnroll/expiry_boundary).
		at, err := ParseExpiry("2026-10-28T12:30:00Z")
		if err != nil || !at.Equal(time.Date(2026, 10, 28, 12, 30, 0, 0, time.UTC)) {
			t.Fatalf("ParseExpiry = %v, %v", at, err)
		}
		if FormatExpiry(at.Add(999*time.Millisecond)) != "2026-10-28T12:30:00Z" || FormatExpiry(at.Add(-time.Second)) != "2026-10-28T12:29:59Z" {
			t.Fatal("FormatExpiry does not truncate to the second")
		}
		for _, bad := range []string{"2026-10-28T12:30:00.5Z", "2026-10-28T13:30:00+01:00", "2026-10-28 12:30:00Z", "2026-10-28T12:30Z", ""} {
			j := valid(t)
			j.ExpiresAt = bad
			if _, err := Parse(encode(t, j)); !errors.Is(err, ErrInvalid) {
				t.Errorf("expires_at %q: %v, want join_string_invalid", bad, err)
			}
		}
	})
	refused := func(name string, edit func(j *JoinToken)) {
		t.Run(name, func(t *testing.T) {
			j := valid(t)
			edit(&j)
			if _, err := Parse(encode(t, j)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse = %v, want join_string_invalid", err)
			}
			if _, err := Format(j); !errors.Is(err, ErrInvalid) && name != "unsorted_pins_refused" {
				t.Fatalf("Format = %v, want join_string_invalid", err)
			}
		})
	}
	refused("empty_server_refused", func(j *JoinToken) { j.Server = "" })
	refused("server_not_normal_form_refused", func(j *JoinToken) { j.Server = "https://Keyroster.example:8443" })
	refused("server_ip_literal_refused", func(j *JoinToken) { j.Server = "https://127.0.0.1:8443" })
	refused("no_tls_roots_refused", func(j *JoinToken) { j.TLSRoots = nil })
	refused("no_tls_pins_refused", func(j *JoinToken) { j.TLSPins = nil })
	refused("tls_pin_without_root_refused", func(j *JoinToken) { j.TLSRoots = j.TLSRoots[:1] })
	refused("tls_root_without_pin_refused", func(j *JoinToken) {
		r, _ := testRoot(t, "root three")
		j.TLSRoots = append(j.TLSRoots, r)
	})
	refused("no_trust_pins_refused", func(j *JoinToken) { j.TrustPins = nil; j.Threshold = 1 })
	refused("threshold_zero_refused", func(j *JoinToken) { j.Threshold = 0 })
	refused("threshold_above_pins_refused", func(j *JoinToken) { j.Threshold = 3 })
	refused("empty_installation_refused", func(j *JoinToken) { j.InstallationID = "" })
	refused("installation_case_differs_refused", func(j *JoinToken) { j.InstallationID = strings.ToUpper(j.InstallationID) })
	refused("empty_token_refused", func(j *JoinToken) { j.Token = "" })
	refused("token_not_32_bytes_refused", func(j *JoinToken) { j.Token = EncodeToken(make([]byte, TokenBytes-1)) })
	refused("token_33_bytes_refused", func(j *JoinToken) { j.Token = EncodeToken(make([]byte, TokenBytes+1)) })
	refused("token_padded_refused", func(j *JoinToken) { j.Token = base64.URLEncoding.EncodeToString(make([]byte, TokenBytes)) })
	refused("bad_host_name_refused", func(j *JoinToken) { j.ExpectedName = "Web 1" })
	refused("version_two_refused", func(j *JoinToken) { j.Version = 2 })
	refused("duplicate_pins_refused", func(j *JoinToken) { j.TrustPins[1] = j.TrustPins[0]; j.Threshold = 1 })
	t.Run("unsorted_pins_refused", func(t *testing.T) {
		j := valid(t)
		slices.Reverse(j.TrustPins)
		if _, err := Parse(encode(t, j)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsorted trust pins: %v", err)
		}
		j = valid(t)
		slices.Reverse(j.TLSPins)
		if _, err := Parse(encode(t, j)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsorted TLS pins: %v", err)
		}
		// Format sorts the sets it is given.
		if _, err := Format(j); err != nil {
			t.Fatalf("Format of unsorted pins: %v", err)
		}
	})
	t.Run("not_canonical_refused", func(t *testing.T) {
		j := valid(t)
		b, err := trust.CanonicalJSON(j)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range [][]byte{
			[]byte(" " + string(b)),
			[]byte(strings.Replace(string(b), `"version":1,`, `"version":1,"extra":1,`, 1)),
			[]byte(strings.Replace(string(b), `"version":1,`, `"version": 1,`, 1)),
		} {
			if _, err := Parse(Prefix + base64.RawURLEncoding.EncodeToString(raw)); !errors.Is(err, ErrInvalid) {
				t.Errorf("Parse of %q: %v", raw[:20], err)
			}
		}
		for _, s := range []string{"", "kr-join-v2:" + strings.TrimPrefix(encode(t, j), Prefix), strings.TrimPrefix(encode(t, j), Prefix),
			Prefix + "!!", Prefix + strings.Repeat("A", MaxString)} {
			if _, err := Parse(s); !errors.Is(err, ErrInvalid) {
				t.Errorf("Parse of a %d-byte string: %v", len(s), err)
			}
		}
	})
	t.Run("string_never_prints_token", func(t *testing.T) {
		j := valid(t)
		for _, s := range []string{j.String(), fmt.Sprintf("%v", j), fmt.Sprintf("%+v", j), fmt.Sprintf("%#v", j), fmt.Sprint(&j),
			FetcherTokenOf(&j).String(), fmt.Sprintf("%v", FetcherTokenOf(&j)), fmt.Sprintf("%#v", FetcherTokenOf(&j))} {
			if strings.Contains(s, j.Token) || !strings.Contains(s, "redacted") {
				t.Errorf("a formatted join token shows the token: %q", s)
			}
		}
		// A refusal names the rule, never the token.
		bad := j
		bad.Threshold = 0
		if _, err := Parse(encode(t, bad)); err == nil || strings.Contains(err.Error(), j.Token) {
			t.Errorf("Parse error %v carries the token", err)
		}
	})
	t.Run("token_sha256_hashes_raw_bytes", func(t *testing.T) {
		raw := make([]byte, TokenBytes)
		got := TokenSHA256(raw)
		if got != trust.SHA256Hex(raw) || got == trust.SHA256Hex([]byte(EncodeToken(raw))) {
			t.Fatalf("TokenSHA256 = %s, want the SHA-256 of the 32 raw bytes", got)
		}
	})
}

// TestFetcherFiles: the fetcher's part of a join string keeps the server,
// roots and pins and the token, never the trust pins.
func TestFetcherFiles(t *testing.T) {
	j := valid(t)
	fc := FetchConfigOf(&j)
	if err := CheckFetchConfig(&fc); err != nil {
		t.Fatal(err)
	}
	b, err := trust.CanonicalJSON(fc)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range j.TrustPins {
		if strings.Contains(string(b), p) {
			t.Fatal("fetch.json carries a trust pin")
		}
	}
	ft := FetcherTokenOf(&j)
	if err := CheckFetcherToken(&ft); err != nil || ft.Token != j.Token {
		t.Fatalf("CheckFetcherToken = %v", err)
	}
	fc.TLSPins = nil
	if err := CheckFetchConfig(&fc); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a fetch.json without pins: %v", err)
	}
}
