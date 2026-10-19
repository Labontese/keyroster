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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// forgedInstruction is what a hostile peer wants the user to read as the
// CLI's own last line: a re-pin command with the attacker's pins.
const forgedInstruction = "keyroster init: the server's trust bundle is signed by roots that do not match the --root-pin set you gave keyroster init. " +
	"Run `keyroster init --force --server https://localhost --tls-pin sha256/ATTACKER --root-pin SHA256:ATTACKER --threshold 1 --user alice`"

// forgedSAN is a dNSName (an IA5String, so '\n' and ESC are allowed and
// Go parses it) that scrolls the real message away, erases the line and
// leaves forgedInstruction as the last thing on the terminal.
var forgedSAN = strings.Repeat("\n", 60) + "\x1b[2K" + forgedInstruction

// forgedLeaf is a self-signed server certificate for forgedSAN only. A
// network-position attacker needs no pinned root for it: Go checks the
// host name before it builds a chain, so the handshake fails with an
// x509.HostnameError that lists forgedSAN.
func forgedLeaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "attacker"}, DNSNames: []string{forgedSAN},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS serves h over TLS 1.3 with cert and returns
// https://localhost:PORT.
func serveTLS(t *testing.T, cert tls.Certificate, h http.Handler) string {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	_, port, err := net.SplitHostPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://localhost:" + port
}

// requireOneEscapedLine fails unless stderr is a single line (dispatch's
// own trailing newline only) with no control or format character, and
// shows want: the forged text behind its visibly escaped ESC sequence.
func requireOneEscapedLine(t *testing.T, stderr, want string) {
	t.Helper()
	body, ok := strings.CutSuffix(stderr, "\n")
	if !ok {
		t.Fatalf("stderr does not end in dispatch's newline: %q", stderr)
	}
	for _, r := range body {
		if !unicode.IsGraphic(r) {
			t.Fatalf("stderr carries the raw peer character %U (%d raw newlines in all):\n%s", r, strings.Count(stderr, "\n"), stderr)
		}
	}
	if !strings.Contains(body, want) {
		t.Fatalf("stderr does not show %q: %q", want, body)
	}
}

// TestRemoteTextEscaped: text the server or a network-position attacker
// chooses (a certificate's host names in a handshake error, a JSON error
// field) reaches stderr with every control character escaped, newlines
// included, so it cannot scroll the real message away and leave a forged
// re-pin instruction as the last line (T-02-93). Each case is a real TLS
// handshake or HTTP exchange through the CLI's dispatch.
func TestRemoteTextEscaped(t *testing.T) {
	srv := newInitServer(t, softwareCustody)
	evilURL := serveTLS(t, forgedLeaf(t), http.NotFoundHandler())
	useConfigDir(t)

	t.Run("init_handshake_san", func(t *testing.T) {
		// keyroster init's first connection (observeRoots).
		bad := *srv
		bad.url = evilURL
		code, _, stderr := run(t, bad.args()...)
		if code != 1 {
			t.Fatalf("init against a forged SAN: exit %d: %s", code, stderr)
		}
		requireOneEscapedLine(t, stderr, `\x1b[2K`+forgedInstruction)
	})

	t.Run("serverclient_handshake_san", func(t *testing.T) {
		// A serverclient.Client pinned to the real root, as every command
		// after init uses it.
		rootPEM := string(readTestFile(t, srv.rootFile))
		withTestCommand(t, command{
			Name: "test-remote",
			Run: func(ctx context.Context, _ []string, _, stderr io.Writer) error {
				c, err := serverclient.New(serverclient.Config{Server: evilURL, RootsPEM: []string{rootPEM}, Pins: []string{srv.rootPin}, Stderr: stderr})
				if err != nil {
					return err
				}
				_, _, err = c.Trust(ctx, []string{srv.rootFP}, 1)
				return err
			},
		})
		code, _, stderr := run(t, "test-remote")
		if code != 1 {
			t.Fatalf("Trust against a forged SAN: exit %d: %s", code, stderr)
		}
		requireOneEscapedLine(t, stderr, `\x1b[2K`+forgedInstruction)
	})

	t.Run("init_json_error", func(t *testing.T) {
		// The real server certificate, but the trust endpoint answers with
		// a JSON error field that carries "\r\n" and an ESC sequence.
		bad := *srv
		bad.url = serveTLS(t, srv.leaf, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"conflict\r\n\r\n\u001b[2K`+forgedInstruction+`"}`)
		}))
		code, _, stderr := run(t, bad.args()...)
		if code != 1 {
			t.Fatalf("init against a JSON error: exit %d: %s", code, stderr)
		}
		// The client caps the server's text at 200 bytes, so only its
		// start shows.
		requireOneEscapedLine(t, stderr, `conflict\r\n\r\n\x1b[2Kkeyroster init: the server's trust bundle`)
	})
}
