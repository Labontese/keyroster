package serverclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// tlsCA is a test certificate authority: a root or an intermediate.
type tlsCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// newRoot creates a self-signed root CA.
func newRoot(t *testing.T, name string) *tlsCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsCA{cert: c, key: key}
}

// intermediate issues an intermediate CA under ca.
func (ca *tlsCA) intermediate(t *testing.T, name string) *tlsCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsCA{cert: c, key: key}
}

// leaf issues a server certificate for dnsName valid from notBefore to
// notAfter and returns it as a tls.Certificate whose chain is the leaf
// followed by extra.
func (ca *tlsCA) leaf(t *testing.T, dnsName string, notBefore, notAfter time.Time, extra ...*tlsCA) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{der}
	for _, c := range extra {
		chain = append(chain, c.cert.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key}
}

// validLeaf is leaf for localhost, valid now.
func (ca *tlsCA) validLeaf(t *testing.T, extra ...*tlsCA) tls.Certificate {
	t.Helper()
	return ca.leaf(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), extra...)
}

func (ca *tlsCA) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
}

// startTLS serves h over TLS with cert and returns https://localhost:PORT.
func startTLS(t *testing.T, cert tls.Certificate, h http.Handler) string {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	_, port, err := net.SplitHostPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://localhost:" + port
}

// custodyHandler answers every path with {} and a custody header.
func custodyHandler(custody string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(CustodyHeader, custody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}\n"))
	})
}

const agentCustody = "user=agent, host=agent, machine=agent, ops=agent, log=agent"

// clientFor builds a Client for url pinned to root.
func clientFor(t *testing.T, url string, root *tlsCA, stderr *bytes.Buffer) *Client {
	t.Helper()
	c, err := New(Config{Server: url, RootsPEM: []string{root.pem()}, Pins: []string{PinOf(root.cert)}, Stderr: stderr})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func get(c *Client) error {
	var out map[string]any
	return c.GetJSON(context.Background(), "/healthz", &out)
}

func TestClientTLS(t *testing.T) {
	r := newRoot(t, "root R")

	t.Run("pinned_root_accepted", func(t *testing.T) {
		url := startTLS(t, r.validLeaf(t), custodyHandler(agentCustody))
		if err := get(clientFor(t, url, r, nil)); err != nil {
			t.Fatalf("a chain to the pinned root was refused: %v", err)
		}
	})

	t.Run("unpinned_root_error_names_repin", func(t *testing.T) {
		// A server whose chain ends in another root S: refused although
		// the chain is valid, because only the pinned roots are trusted
		// (the system pool is never consulted).
		s := newRoot(t, "root S")
		url := startTLS(t, s.validLeaf(t), custodyHandler(agentCustody))
		err := get(clientFor(t, url, r, nil))
		if !errors.Is(err, ErrTLSRootNotPinned) {
			t.Fatalf("chain to an unpinned root: err = %v, want ErrTLSRootNotPinned", err)
		}
		for _, want := range []string{"keyroster init", "TLS root changed", "not sending its full chain"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error lacks %q: %v", want, err)
			}
		}
	})

	t.Run("stored_root_without_pin_refused", func(t *testing.T) {
		// A stored root whose pin is not in the pin set (an edited
		// config) fails VerifyConnection with the same error.
		other := newRoot(t, "root O")
		url := startTLS(t, r.validLeaf(t), custodyHandler(agentCustody))
		c, err := New(Config{Server: url, RootsPEM: []string{r.pem()}, Pins: []string{PinOf(other.cert)}})
		if err != nil {
			t.Fatal(err)
		}
		if err := get(c); !errors.Is(err, ErrTLSRootNotPinned) {
			t.Fatalf("stored but unpinned root: err = %v, want ErrTLSRootNotPinned", err)
		}
	})

	t.Run("new_intermediate_same_root_accepted", func(t *testing.T) {
		i1, i2 := r.intermediate(t, "I1"), r.intermediate(t, "I2")
		var stderr bytes.Buffer
		url1 := startTLS(t, i1.validLeaf(t, i1), custodyHandler(agentCustody))
		c1 := clientFor(t, url1, r, &stderr)
		if err := get(c1); err != nil {
			t.Fatalf("leaf1 under I1: %v", err)
		}
		// The same client configuration against leaf2 under a new I2.
		url2 := startTLS(t, i2.validLeaf(t, i2), custodyHandler(agentCustody))
		c2, err := New(Config{Server: url2, RootsPEM: []string{r.pem()}, Pins: []string{PinOf(r.cert)}})
		if err != nil {
			t.Fatal(err)
		}
		if err := get(c2); err != nil {
			t.Fatalf("leaf2 under a new intermediate I2, same root: %v", err)
		}
	})

	t.Run("wrong_hostname_not_root_error", func(t *testing.T) {
		url := startTLS(t, r.leaf(t, "other.example", time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), custodyHandler(agentCustody))
		err := get(clientFor(t, url, r, nil))
		var he x509.HostnameError
		if err == nil || errors.Is(err, ErrTLSRootNotPinned) || !errors.As(err, &he) || strings.Contains(err.Error(), "keyroster init") {
			t.Fatalf("wrong host name: err = %v, want an x509.HostnameError without the re-pin hint", err)
		}
	})

	t.Run("expired_leaf_not_root_error", func(t *testing.T) {
		url := startTLS(t, r.leaf(t, "localhost", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)), custodyHandler(agentCustody))
		err := get(clientFor(t, url, r, nil))
		var ie x509.CertificateInvalidError
		if err == nil || errors.Is(err, ErrTLSRootNotPinned) || !errors.As(err, &ie) || ie.Reason != x509.Expired || strings.Contains(err.Error(), "keyroster init") {
			t.Fatalf("expired leaf: err = %v, want an x509.CertificateInvalidError (Expired) without the re-pin hint", err)
		}
	})

	t.Run("missing_intermediate_reports_root_error", func(t *testing.T) {
		// Known overlap: without I1 in the chain, Go reports an unknown
		// authority, exactly as for a changed root.
		i1 := r.intermediate(t, "I1")
		url := startTLS(t, i1.validLeaf(t), custodyHandler(agentCustody))
		err := get(clientFor(t, url, r, nil))
		if !errors.Is(err, ErrTLSRootNotPinned) || !strings.Contains(err.Error(), "not sending its full chain") {
			t.Fatalf("missing intermediate: err = %v, want ErrTLSRootNotPinned naming the full chain", err)
		}
	})
}

func TestClientCustody(t *testing.T) {
	r := newRoot(t, "root R")

	t.Run("banner_once_per_client", func(t *testing.T) {
		url := startTLS(t, r.validLeaf(t), custodyHandler("user=software, host=software, machine=software, ops=software, log=software"))
		var stderr bytes.Buffer
		c := clientFor(t, url, r, &stderr)
		for range 3 {
			if err := get(c); err != nil {
				t.Fatal(err)
			}
		}
		banner := custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"})
		if strings.Count(stderr.String(), banner) != 1 {
			t.Fatalf("banner printed %d times over three responses, want once:\n%s", strings.Count(stderr.String(), banner), stderr.String())
		}
		// A new Client prints it again.
		var again bytes.Buffer
		if err := get(clientFor(t, url, r, &again)); err != nil || !strings.Contains(again.String(), banner) {
			t.Fatalf("a second client: %v, stderr %q", err, again.String())
		}
	})

	t.Run("no_banner_without_software", func(t *testing.T) {
		url := startTLS(t, r.validLeaf(t), custodyHandler(agentCustody))
		var stderr bytes.Buffer
		if err := get(clientFor(t, url, r, &stderr)); err != nil || stderr.Len() != 0 {
			t.Fatalf("agent custody: %v, stderr %q", err, stderr.String())
		}
	})

	t.Run("missing_custody_refused", func(t *testing.T) {
		url := startTLS(t, r.validLeaf(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("{}"))
		}))
		if err := get(clientFor(t, url, r, nil)); !errors.Is(err, ErrNoCustody) {
			t.Fatalf("2xx without %s: %v, want ErrNoCustody", CustodyHeader, err)
		}
	})

	t.Run("malformed_custody_refused", func(t *testing.T) {
		for _, v := range []string{"user=software, user=agent", "user", "user=Software", "user=soft ware", ""} {
			url := startTLS(t, r.validLeaf(t), custodyHandler(v))
			if err := get(clientFor(t, url, r, nil)); err == nil {
				t.Errorf("%s %q accepted", CustodyHeader, v)
			}
		}
	})

	t.Run("api_error_quoted_and_capped", func(t *testing.T) {
		// A server error body is the server's text: it is quoted (no raw
		// control characters), capped and marked as the server's.
		forged := "\r\x1b[2K\x1b[1Aforged: run keyroster init --force --root-pin SHA256:EVIL " + strings.Repeat("x", 8<<10)
		body, err := json.Marshal(APIError{Error: forged})
		if err != nil {
			t.Fatal(err)
		}
		url := startTLS(t, r.validLeaf(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write(body)
		}))
		err = get(clientFor(t, url, r, nil))
		if err == nil {
			t.Fatal("a 409 was accepted")
		}
		msg := err.Error()
		if strings.ContainsAny(msg, "\r\x1b") || !strings.Contains(msg, `HTTP 409: server said: "\r\x1b[2K`) || len(msg) > 1024 {
			t.Fatalf("409 error = %q (%d bytes), want the body quoted after \"server said:\" and capped", msg, len(msg))
		}
	})

	t.Run("signer_unavailable_503", func(t *testing.T) {
		url := startTLS(t, r.validLeaf(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// A 503 never counts custody, even if a header were set.
			w.Header().Set(CustodyHeader, "user=software")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"signer unavailable"}`))
		}))
		var stderr bytes.Buffer
		if err := get(clientFor(t, url, r, &stderr)); !errors.Is(err, ErrSignerUnavailable) || stderr.Len() != 0 {
			t.Fatalf("503: %v, stderr %q; want ErrSignerUnavailable and no banner", err, stderr.String())
		}
	})
}

// TestClientTransport: the transport hardening of New. Redirects are not
// followed, a body over maxResponse is refused, and no proxy is used.
func TestClientTransport(t *testing.T) {
	r := newRoot(t, "root R")

	t.Run("redirect_not_followed", func(t *testing.T) {
		var followed atomic.Bool
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/elsewhere", http.StatusFound)
		})
		mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
			followed.Store(true)
			w.Header().Set(CustodyHeader, agentCustody)
			_, _ = w.Write([]byte("{}"))
		})
		c := clientFor(t, startTLS(t, r.validLeaf(t), mux), r, nil)
		err := get(c)
		if err == nil || !strings.Contains(err.Error(), "HTTP 302") || followed.Load() {
			t.Fatalf("302: err = %v, followed = %v; want an HTTP 302 error and no request to the target", err, followed.Load())
		}
		// Control: the same transport with Go's default redirect policy
		// reaches the target, so only CheckRedirect stops it above.
		follow := &http.Client{Transport: c.http.Transport}
		resp, err := follow.Get(c.Server() + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !followed.Load() {
			t.Fatalf("control: a following client got %d, followed = %v", resp.StatusCode, followed.Load())
		}
	})

	t.Run("oversized_body_refused", func(t *testing.T) {
		// A valid JSON string of n bytes, so only the size check can
		// refuse it.
		jsonString := func(n int) []byte {
			return append(append([]byte(`"`), bytes.Repeat([]byte("a"), n-2)...), '"')
		}
		var body atomic.Pointer[[]byte]
		url := startTLS(t, r.validLeaf(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(CustodyHeader, agentCustody)
			_, _ = w.Write(*body.Load())
		}))
		c := clientFor(t, url, r, nil)
		over := jsonString(maxResponse + 1)
		body.Store(&over)
		var out string
		if err := c.GetJSON(context.Background(), "/healthz", &out); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("a %d-byte body: err = %v, want \"response larger than\"", len(over), err)
		}
		// Control: exactly maxResponse bytes decode.
		limit := jsonString(maxResponse)
		body.Store(&limit)
		if err := c.GetJSON(context.Background(), "/healthz", &out); err != nil || len(out) != maxResponse-2 {
			t.Fatalf("control: a %d-byte body: %v, decoded %d bytes", len(limit), err, len(out))
		}
	})

	t.Run("no_proxy", func(t *testing.T) {
		tr, ok := clientFor(t, "https://keyroster.example", r, nil).http.Transport.(*http.Transport)
		if !ok || tr.Proxy != nil {
			t.Fatalf("transport %T with Proxy set; want an *http.Transport with Proxy nil", tr)
		}
	})
}

// trustDoc builds a TrustResponse whose bundle names roots at threshold
// and is signed by signers, with a matching policy.
func trustDoc(t *testing.T, roots []ssh.Signer, threshold uint32, signers ...ssh.Signer) TrustResponse {
	t.Helper()
	edKey := func() ssh.Signer {
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
	keyOf := func(s ssh.Signer) string { return trust.FormatKey(s.PublicKey()) }
	p := &trust.Policy{
		Version: 1, Prev: trust.GenesisPrev, AdminQuorum: 1,
		Admins: []trust.AdminKey{{Name: "alice", Key: keyOf(edKey())}},
		CAProfiles: []trust.CAProfile{
			{Role: trust.RoleUser, MaxTTLSeconds: 43200, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleHost, MaxTTLSeconds: 2592000, DefaultExtensions: []string{}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
		},
		WebAuthn: &trust.WebAuthnRP{RPID: "keyroster.example", Origins: []string{"https://keyroster.example"}},
	}
	policy, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	logKey := edKey()
	b := &trust.Bundle{
		Version: 1, Prev: trust.GenesisPrev, IssuedAt: "2026-10-19T00:00:00Z",
		Root: trust.RootSet{Threshold: threshold},
		CAs: []trust.CAEntry{
			{Role: trust.RoleUser, Key: keyOf(edKey()), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "active", Generation: 1},
			{Role: trust.RoleHost, Key: keyOf(edKey()), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "active", Generation: 1},
			{Role: trust.RoleMachine, Key: keyOf(edKey()), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "active", Generation: 1},
		},
		OpsKey:       trust.KeyEntry{Key: keyOf(edKey()), Alg: ssh.KeyAlgoED25519, Custody: "software"},
		Log:          trust.LogEntry{Key: keyOf(logKey), Alg: ssh.KeyAlgoED25519, Custody: "software", Origin: trust.LogOrigin(logKey.PublicKey())},
		PolicySHA256: trust.SHA256Hex(policy),
	}
	for _, r := range roots {
		b.Root.Keys = append(b.Root.Keys, trust.RootKey{Key: keyOf(r), Custody: "software"})
	}
	bundle, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.ParseBundle(bundle); err != nil {
		t.Fatalf("test bundle does not parse: %v", err)
	}
	var bundleSigs, policySigs []byte
	for _, s := range signers {
		bs, err := sshsig.Sign(rand.Reader, s, trust.NamespaceBundle, bundle)
		if err != nil {
			t.Fatal(err)
		}
		ps, err := sshsig.Sign(rand.Reader, s, trust.NamespacePolicy, policy)
		if err != nil {
			t.Fatal(err)
		}
		bundleSigs, policySigs = append(bundleSigs, bs...), append(policySigs, ps...)
	}
	return TrustResponse{Bundle: bundle, BundleSigs: bundleSigs, Policy: policy, PolicySigs: policySigs, BundleVersion: 1,
		Custody: []KeyCustody{{Role: "user", Alg: ssh.KeyAlgoED25519, Custody: "software", Fingerprint: "SHA256:x"}}}
}

func edSigner(t *testing.T) ssh.Signer {
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

func fp(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }

// serveTrust serves doc at TrustPath with agent custody.
func serveTrust(t *testing.T, r *tlsCA, doc TrustResponse) *Client {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	url := startTLS(t, r.validLeaf(t), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != TrustPath {
			http.NotFound(w, req)
			return
		}
		w.Header().Set(CustodyHeader, agentCustody)
		_, _ = w.Write(data)
	}))
	return clientFor(t, url, r, nil)
}

func TestClientTrust(t *testing.T) {
	r := newRoot(t, "root R")
	a, b := edSigner(t), edSigner(t)
	ctx := context.Background()

	t.Run("pinned_roots_verified", func(t *testing.T) {
		c := serveTrust(t, r, trustDoc(t, []ssh.Signer{a, b}, 1, a))
		bundle, policy, err := c.Trust(ctx, []string{fp(a), fp(b)}, 1)
		if err != nil || bundle.Version != 1 || policy.WebAuthn == nil {
			t.Fatalf("Trust = %v, %v, %v", bundle, policy, err)
		}
	})

	t.Run("non_pinned_root_refused", func(t *testing.T) {
		x := edSigner(t)
		c := serveTrust(t, r, trustDoc(t, []ssh.Signer{x}, 1, x))
		if _, _, err := c.Trust(ctx, []string{fp(a)}, 1); !errors.Is(err, ErrTrustRootNotPinned) {
			t.Fatalf("bundle signed by a non-pinned root: %v, want ErrTrustRootNotPinned", err)
		}
	})

	t.Run("rotated_roots_error_names_reinit", func(t *testing.T) {
		cRoot, dRoot := edSigner(t), edSigner(t)
		c := serveTrust(t, r, trustDoc(t, []ssh.Signer{cRoot, dRoot}, 2, cRoot, dRoot))
		_, _, err := c.Trust(ctx, []string{fp(a), fp(b)}, 2)
		if !errors.Is(err, ErrTrustRootNotPinned) {
			t.Fatalf("successor self-signed by new roots C and D: %v, want ErrTrustRootNotPinned", err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "keyroster init --force") || !strings.Contains(msg, "--root-pin") {
			t.Errorf("error lacks the re-init command: %v", err)
		}
		for _, served := range []string{fp(cRoot), fp(dRoot), strings.TrimPrefix(fp(cRoot), "SHA256:"), strings.TrimPrefix(fp(dRoot), "SHA256:")} {
			if strings.Contains(msg, served) {
				t.Fatalf("error names a served root fingerprint %s: %v", served, err)
			}
		}
		// Control: a bundle that fails VerifySelfSigned is not a
		// rotation and gets no re-init hint.
		bad := trustDoc(t, []ssh.Signer{cRoot, dRoot}, 2, cRoot) // one signature, threshold 2
		_, _, err = serveTrust(t, r, bad).Trust(ctx, []string{fp(a), fp(b)}, 2)
		if err == nil || errors.Is(err, ErrTrustRootNotPinned) {
			t.Fatalf("a bundle below its own threshold: %v, want a verification error that is not ErrTrustRootNotPinned", err)
		}
	})

	t.Run("policy_not_bundled_refused", func(t *testing.T) {
		doc := trustDoc(t, []ssh.Signer{a}, 1, a)
		other := trustDoc(t, []ssh.Signer{a}, 1, a)
		doc.Policy, doc.PolicySigs = other.Policy, other.PolicySigs // signed by a, but not this bundle's policy
		if _, _, err := serveTrust(t, r, doc).Trust(ctx, []string{fp(a)}, 1); !errors.Is(err, ErrPolicyNotBundled) {
			t.Fatalf("a root-signed policy the bundle does not name: %v, want ErrPolicyNotBundled", err)
		}
	})

	t.Run("bad_pins_refused_before_fetch", func(t *testing.T) {
		c := serveTrust(t, r, trustDoc(t, []ssh.Signer{a}, 1, a))
		if _, _, err := c.Trust(ctx, []string{fp(a)}, 2); !errors.Is(err, trust.ErrThreshold) {
			t.Fatalf("threshold above the pin count: %v, want ErrThreshold", err)
		}
	})
}

func TestParseServerURL(t *testing.T) {
	for _, ok := range []string{"https://keyroster.example", "https://keyroster.example:8443"} {
		if u, err := ParseServerURL(ok); err != nil || u.String() != ok {
			t.Errorf("ParseServerURL(%q) = %v, %v", ok, u, err)
		}
	}
	for _, bad := range []string{
		"http://keyroster.example", "https://192.0.2.1", "https://[::1]:8443", "https://keyroster.example/path",
		"https://keyroster.example/", "https://keyroster.example?x=1", "https://keyroster.example#f",
		"https://user@keyroster.example", "https://keyroster.example:0", "https://keyroster.example:99999", "keyroster.example",
		// IP literals that net.ParseIP alone does not see: an IPv6 zone,
		// a trailing dot, and the short and numeric forms OS resolvers
		// read as IPv4 addresses.
		"https://[fe80::1%25eth0]:8443", "https://[fe80::1%25eth0]", "https://[::1%25lo]", "https://192.0.2.1.", "https://192.0.2.1.:8443",
		"https://127.1", "https://2130706433", "https://0x7f000001", "https://keyroster.123",
	} {
		if _, err := ParseServerURL(bad); err == nil {
			t.Errorf("ParseServerURL(%q) accepted", bad)
		}
	}
}

func TestPinOf(t *testing.T) {
	r := newRoot(t, "root R")
	p := PinOf(r.cert)
	if err := CheckPin(p); err != nil || !strings.HasPrefix(p, "sha256/") || len(p) != len("sha256/")+44 {
		t.Fatalf("PinOf = %q (%v)", p, err)
	}
	for _, bad := range []string{"sha256/abc", "SHA256:" + strings.TrimPrefix(p, "sha256/"), "sha256/" + strconv.Itoa(1)} {
		if CheckPin(bad) == nil {
			t.Errorf("CheckPin(%q) accepted", bad)
		}
	}
}
