package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// Full-length pins an attacker wants the user to type. Short markers such
// as sha256/ATTACKER fit inside any excerpt cap, so they cannot show that
// the cap holds.
var (
	attackerTLSPin  = "sha256/" + strings.Repeat("QVRUQUNL", 5) + "QVQ="
	attackerRootPin = "SHA256:" + strings.Repeat("RVZJTA", 7) + "Q"
)

// attackerAdvice imitates the CLI's own re-pin advice with the attacker's
// pins.
var attackerAdvice = "keyroster init: the server's TLS certificate does not chain to a root you pinned with keyroster init. " +
	"Run `keyroster init --force --server https://localhost --tls-pin " + attackerTLSPin +
	" --root-pin " + attackerRootPin + " --threshold 1 --user alice`"

// paddedAdvice is attackerAdvice behind 4000 spaces: printable text that
// survives any control-character escape and, soft-wrapped, scrolls the
// CLI's real message off the screen.
var paddedAdvice = strings.Repeat(" ", 4000) + attackerAdvice

// requirePeerTextContained checks the security property of T-02-93 on a
// command's stderr: neither attacker pin appears, there is no run of more
// than 80 spaces, nothing but a newline is a control or format character,
// and when advice (the CLI's own re-pin error) is given it is the last
// thing printed.
func requirePeerTextContained(t *testing.T, stderr string, advice error) {
	t.Helper()
	for _, pin := range []string{attackerTLSPin, attackerRootPin} {
		if strings.Contains(stderr, pin) {
			t.Errorf("stderr carries the attacker's pin %s:\n%s", pin, stderr)
		}
	}
	if strings.Contains(stderr, strings.Repeat(" ", 81)) {
		t.Errorf("stderr carries a run of more than 80 spaces (%d bytes in all)", len(stderr))
	}
	for _, r := range stderr {
		if r != '\n' && !unicode.IsGraphic(r) {
			t.Errorf("stderr carries the raw character %U", r)
			break
		}
	}
	if advice != nil {
		if body := strings.TrimSuffix(stderr, "\n"); !strings.HasSuffix(body, advice.Error()) {
			t.Errorf("the CLI's own advice is not the last thing printed:\n%.2000s", body)
		}
	}
}

// newTestKey returns a fresh P-256 key.
func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// createCert signs tmpl for pub with signer as issuer (tmpl itself when
// issuer is nil).
func createCert(t *testing.T, tmpl, issuer *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	if issuer == nil {
		issuer = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// paddedSANLeaf (A) is a self-signed server certificate whose only
// dNSName is paddedAdvice: Go checks the host name before it builds a
// chain, so any network-position attacker gets an x509.HostnameError that
// lists it, with no CA involved.
func paddedSANLeaf(t *testing.T) tls.Certificate {
	t.Helper()
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "attacker"}, DNSNames: []string{paddedAdvice},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return tls.Certificate{Certificate: [][]byte{createCert(t, tmpl, nil, &key.PublicKey, key)}, PrivateKey: key}
}

// hintChain (B) is a leaf for localhost issued by a CA named
// paddedAdvice, sent with a bogus intermediate of that same name but
// another key. Chain building tries the intermediate, its signature check
// fails, and Go's x509.UnknownAuthorityError names it as the candidate
// authority, which puts the padded advice in the error text.
func hintChain(t *testing.T) tls.Certificate {
	t.Helper()
	caKey, bogusKey, leafKey := newTestKey(t), newTestKey(t), newTestKey(t)
	name := pkix.Name{CommonName: paddedAdvice}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12), Subject: name,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	bogus := createCert(t, caTmpl, nil, &bogusKey.PublicKey, bogusKey)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(13), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf := createCert(t, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	return tls.Certificate{Certificate: [][]byte{leaf, bogus}, PrivateKey: leafKey}
}

// trustCommand registers test-trust, which runs serverclient.Trust as
// every command after init does: pinned to srv's TLS root, against url.
func trustCommand(t *testing.T, srv *initServer, url string) {
	t.Helper()
	rootPEM := string(readTestFile(t, srv.rootFile))
	withTestCommand(t, command{
		Name: "test-trust",
		Run: func(ctx context.Context, _ []string, _, stderr io.Writer) error {
			c, err := serverclient.New(serverclient.Config{Server: url, RootsPEM: []string{rootPEM}, Pins: []string{srv.rootPin}, Stderr: stderr})
			if err != nil {
				return err
			}
			_, _, err = c.Trust(ctx, []string{srv.rootFP}, 1)
			return err
		},
	})
}

// TestPeerTextCannotForgeAdvice: whatever text a network-position attacker
// (A, B) chooses, stderr never carries a forged re-pin instruction: no attacker pin, no
// padding, and the CLI's own advice, when printed, comes last (T-02-93).
// Each case is a real TLS handshake or HTTP exchange through dispatch.
func TestPeerTextCannotForgeAdvice(t *testing.T) {
	srv := newInitServer(t, softwareCustody)
	useConfigDir(t)

	// initAt runs keyroster init against url and requires exit 1.
	initAt := func(t *testing.T, url string, extra ...string) string {
		t.Helper()
		bad := *srv
		bad.url = url
		code, _, stderr := run(t, bad.args(extra...)...)
		if code != 1 {
			t.Fatalf("init: exit %d, want 1: %.2000s", code, stderr)
		}
		return stderr
	}
	// trustAt runs serverclient.Trust against url and requires exit 1.
	trustAt := func(t *testing.T, url string) string {
		t.Helper()
		trustCommand(t, srv, url)
		code, _, stderr := run(t, "test-trust")
		if code != 1 {
			t.Fatalf("Trust: exit %d, want 1: %.2000s", code, stderr)
		}
		return stderr
	}

	// notValid is the CLI's own text for a certificate that does not
	// cover the host the user typed.
	const notValid = "the server's TLS certificate is not valid for localhost" + string('\n')
	t.Run("A_padded_san_init", func(t *testing.T) {
		url := serveTLS(t, paddedSANLeaf(t), http.NotFoundHandler())
		stderr := initAt(t, url)
		requirePeerTextContained(t, stderr, nil)
		if !strings.HasSuffix(stderr, notValid) {
			t.Errorf("stderr does not end in %q: %.2000s", notValid, stderr)
		}
	})
	t.Run("A_padded_san_serverclient", func(t *testing.T) {
		url := serveTLS(t, paddedSANLeaf(t), http.NotFoundHandler())
		stderr := trustAt(t, url)
		requirePeerTextContained(t, stderr, nil)
		if !strings.HasSuffix(stderr, notValid) {
			t.Errorf("stderr does not end in %q: %.2000s", notValid, stderr)
		}
	})
	t.Run("B_unknown_authority_hint_init", func(t *testing.T) {
		url := serveTLS(t, hintChain(t), http.NotFoundHandler())
		requirePeerTextContained(t, initAt(t, url), errInitUntrusted)
	})
	t.Run("B_unknown_authority_hint_serverclient", func(t *testing.T) {
		url := serveTLS(t, hintChain(t), http.NotFoundHandler())
		requirePeerTextContained(t, trustAt(t, url), serverclient.ErrTLSRootNotPinned)
	})
}
