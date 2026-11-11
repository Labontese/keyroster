package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// initServer is a TLS server for localhost under a test root that serves
// a root-signed trust document.
type initServer struct {
	url      string
	rootFile string // the test root, PEM
	rootPin  string
	rootFP   string          // the trust root's SHA256 fingerprint
	otherPin string          // a well-formed pin of a root the server never presents
	leaf     tls.Certificate // the server's localhost certificate under the test root
	// installation is the served bundle's installation ID, "" for none
	// (03-14c, F06).
	installation string
}

// newInitServer signs a genesis bundle with one software root (the
// in-process ceremony of root_test.go) and serves it at /api/v1/trust over
// TLS with custody.
func newInitServer(t *testing.T, custody string) *initServer {
	t.Helper()
	return newInitServerEdit(t, custody, nil)
}

// newInitServerEdit is newInitServer with the genesis bundle changed by
// edit (nil: unchanged) and re-signed by the root (03-14c, F06).
func newInitServerEdit(t *testing.T, custody string, edit func(b *trust.Bundle)) *initServer {
	t.Helper()
	doc, rootFP := initTrustDocEdit(t, edit)
	root, rootKey := initTestRoot(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := initTestRoot(t)
	cert := tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: leafKey}
	is := &initServer{
		url:      serveTrustDoc(t, doc, custody, cert),
		rootFile: filepath.Join(t.TempDir(), "root.pem"),
		rootPin:  serverclient.PinOf(root),
		rootFP:   rootFP,
		otherPin: serverclient.PinOf(other),
		leaf:     cert,
	}
	var tr serverclient.TrustResponse
	if err := json.Unmarshal(doc, &tr); err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(tr.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	is.installation = b.InstallationID
	writeTestFile(t, is.rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	return is
}

// initTrustDoc signs a genesis bundle with one software root (the
// in-process ceremony of root_test.go) and returns the /api/v1/trust
// document and the trust root's fingerprint.
func initTrustDoc(t *testing.T) ([]byte, string) {
	t.Helper()
	return initTrustDocEdit(t, nil)
}

// initTrustDocEdit is initTrustDoc with the genesis bundle changed by edit
// (nil: unchanged) and re-signed by the root (03-14c, F06).
func initTrustDocEdit(t *testing.T, edit func(b *trust.Bundle)) ([]byte, string) {
	t.Helper()
	g := newCeremony(t, 1)
	useKeyring(t, g.rootKeys...)
	typeHashPrefix(t, g.out)
	if code, _, stderr := g.sign(t, "1", 0); code != 0 {
		t.Fatalf("root sign: exit %d: %s", code, stderr)
	}
	read := func(name string) []byte { return readTestFile(t, filepath.Join(g.out, name)) }
	bundle, bundleSigs := read("bundle.json"), read("bundle.json.sigs")
	if edit != nil {
		b, err := trust.ParseBundle(bundle)
		if err != nil {
			t.Fatal(err)
		}
		edit(b)
		if bundle, err = b.Canonical(); err != nil {
			t.Fatal(err)
		}
		root, err := ssh.NewSignerFromKey(g.rootKeys[0])
		if err != nil {
			t.Fatal(err)
		}
		if bundleSigs, err = sshsig.Sign(rand.Reader, root, trust.NamespaceBundle, bundle); err != nil {
			t.Fatal(err)
		}
	}
	doc, err := json.Marshal(serverclient.TrustResponse{
		Bundle: bundle, BundleSigs: bundleSigs,
		Policy: read("policy.json"), PolicySigs: read("policy.json.sigs"), BundleVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc, g.fingerprint(t, 0)
}

// serveTrustDoc serves doc at /api/v1/trust with custody over TLS with
// cert and returns https://localhost:PORT.
func serveTrustDoc(t *testing.T, doc []byte, custody string, cert tls.Certificate) string {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != serverclient.TrustPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set(serverclient.CustodyHeader, custody)
		_, _ = w.Write(doc)
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	_, port, err := net.SplitHostPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://localhost:" + port
}

func initTestRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "init test root"},
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
	return c, key
}

// useConfigDir points the config directory at a fresh temporary
// directory and returns the config file path.
func useConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := userConfigDir
	userConfigDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { userConfigDir = prev })
	return filepath.Join(dir, "keyroster", "config.json")
}

func (s *initServer) args(extra ...string) []string {
	return append([]string{"init", "--server", s.url, "--tls-root-file", s.rootFile, "--tls-pin", s.rootPin,
		"--root-pin", s.rootFP, "--threshold", "1", "--user", "alice"}, extra...)
}

// requireNoConfig fails if a config file was written.
func requireNoConfig(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused init wrote %s (%v)", path, err)
	}
}

// TestRepinInstructionsKeepIdentity: init --force builds the config from
// its flags alone, so every documented re-pin command and both re-pin
// error messages must pass --user and --admin-key again; otherwise an
// admin who follows them loses admin_key and user from the config.
func TestRepinInstructionsKeepIdentity(t *testing.T) {
	// The runbooks that give a re-pin remedy. 03-14c added the last four,
	// each of which must hold one (the installation pin's re-init);
	// machine-identities.md is not listed, because its automation-host
	// re-pin form has no --user by design.
	found := 0
	for _, name := range []string{"root-ceremony.md", "server-install.md", "signer-install.md", "host-setup.md", "revoke.md", "enroll-user.md"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", name)) //nolint:gosec // G304: a constant runbook name under docs/runbooks
		if err != nil {
			t.Fatal(err)
		}
		inFile := 0
		for _, para := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n") {
			if !(strings.Contains(para, "init") && strings.Contains(para, "--force") && strings.Contains(para, "--root-pin")) &&
				!(strings.Contains(para, "keyroster init") && strings.Contains(para, "--force")) {
				continue
			}
			found++
			inFile++
			if !strings.Contains(para, "--user") || !strings.Contains(para, "--admin-key") {
				t.Errorf("%s: a re-pin instruction without --user and --admin-key:\n%s", name, para)
			}
		}
		if name != "root-ceremony.md" && name != "server-install.md" && inFile == 0 {
			t.Errorf("%s: no re-pin instruction found, want the installation pin's re-init (03-14c)", name)
		}
	}
	if found < 2 {
		t.Fatalf("found %d re-pin instructions in the runbooks, want at least 2 (root-ceremony step 9, server-install TLS root changed)", found)
	}
	for _, err := range []error{serverclient.ErrTrustRootNotPinned, serverclient.ErrTLSRootNotPinned, serverclient.ErrInstallationNotPinned} {
		if !strings.Contains(err.Error(), "--user") || !strings.Contains(err.Error(), "--admin-key") {
			t.Errorf("re-pin error without --user and --admin-key: %v", err)
		}
	}
}

const softwareCustody = "user=software, host=software, machine=software, ops=software, log=software"

func TestInit(t *testing.T) {
	srv := newInitServer(t, softwareCustody)

	t.Run("pins_and_saves", func(t *testing.T) {
		cfgPath := useConfigDir(t)
		code, stdout, stderr := run(t, srv.args()...)
		if code != 0 {
			t.Fatalf("init exit %d:\n%s\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, srv.rootPin) || !strings.Contains(stdout, "trust bundle version 1") || !strings.Contains(stdout, srv.rootFP) {
			t.Fatalf("init stdout:\n%s", stdout)
		}
		if strings.Count(stderr, custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"})) != 1 {
			t.Fatalf("init stderr lacks the banner (exactly once):\n%s", stderr)
		}
		c, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if c.Server != srv.url || len(c.TLSPins) != 1 || c.TLSPins[0] != srv.rootPin || len(c.TLSRootsPEM) != 1 ||
			len(c.TrustPins) != 1 || c.TrustPins[0] != srv.rootFP || c.TrustThreshold != 1 || c.User != "alice" {
			t.Fatalf("saved config = %+v", c)
		}
		if runtime.GOOS != "windows" {
			fi, err := os.Stat(cfgPath)
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("config mode: %v %v, want 0600", fi, err)
			}
			di, err := os.Stat(filepath.Dir(cfgPath))
			if err != nil || di.Mode().Perm() != 0o700 {
				t.Fatalf("config directory mode: %v %v, want 0700", di, err)
			}
		}
		// The saved client works with the pinned root only.
		client, err := serverclient.New(serverclient.Config{Server: c.Server, RootsPEM: c.TLSRootsPEM, Pins: c.TLSPins})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := client.Trust(t.Context(), c.TrustPins, c.TrustThreshold, c.InstallationID); err != nil {
			t.Fatalf("Trust with the saved config: %v", err)
		}

		// refuses_existing_config_without_force, then --force replaces it.
		if code, _, stderr := run(t, srv.args()...); code != 1 || !strings.Contains(stderr, "--force") {
			t.Fatalf("second init without --force: exit %d: %s", code, stderr)
		}
		if code, _, stderr := run(t, srv.args("--force", "--user", "bob")...); code != 0 {
			t.Fatalf("init --force: exit %d: %s", code, stderr)
		}
		if c, err := loadConfig(); err != nil || c.User != "bob" {
			t.Fatalf("config after --force = %+v, %v", c, err)
		}
	})

	t.Run("stores_only_pinned_of_two_observed_roots", func(t *testing.T) {
		// The server chains to two roots: one intermediate (one key and
		// subject) is signed by root A and by root B, and both copies are
		// served. Init pins A only and must store A alone, never the
		// observed but unpinned B.
		doc, rootFP := initTrustDoc(t)
		rootA, keyA := initTestRoot(t)
		rootB, keyB := initTestRoot(t)
		interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		interTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "init test intermediate"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		}
		interA, err := x509.CreateCertificate(rand.Reader, interTmpl, rootA, &interKey.PublicKey, keyA)
		if err != nil {
			t.Fatal(err)
		}
		interTmpl.SerialNumber = big.NewInt(11)
		interB, err := x509.CreateCertificate(rand.Reader, interTmpl, rootB, &interKey.PublicKey, keyB)
		if err != nil {
			t.Fatal(err)
		}
		inter, err := x509.ParseCertificate(interA)
		if err != nil {
			t.Fatal(err)
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leaf, err := x509.CreateCertificate(rand.Reader, leafTmpl, inter, &leafKey.PublicKey, interKey)
		if err != nil {
			t.Fatal(err)
		}
		url := serveTrustDoc(t, doc, softwareCustody, tls.Certificate{Certificate: [][]byte{leaf, interA, interB}, PrivateKey: leafKey})
		rootFile := filepath.Join(t.TempDir(), "roots.pem")
		writeTestFile(t, rootFile, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootA.Raw}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootB.Raw})...))
		pinA, pinB := serverclient.PinOf(rootA), serverclient.PinOf(rootB)

		useConfigDir(t)
		code, stdout, stderr := run(t, "init", "--server", url, "--tls-root-file", rootFile, "--tls-pin", pinA,
			"--root-pin", rootFP, "--threshold", "1", "--user", "alice")
		if code != 0 {
			t.Fatalf("init exit %d:\n%s\n%s", code, stdout, stderr)
		}
		// Control: init observed both roots.
		if !strings.Contains(stdout, pinA) || !strings.Contains(stdout, pinB) {
			t.Fatalf("init did not print both observed roots:\n%s", stdout)
		}
		c, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.TLSPins) != 1 || c.TLSPins[0] != pinA || len(c.TLSRootsPEM) != 1 {
			t.Fatalf("saved TLS pins %q and %d roots, want only %s", c.TLSPins, len(c.TLSRootsPEM), pinA)
		}
		block, _ := pem.Decode([]byte(c.TLSRootsPEM[0]))
		if block == nil || !bytes.Equal(block.Bytes, rootA.Raw) {
			t.Fatal("the saved root is not root A")
		}
	})

	t.Run("discovery_without_tls_pin", func(t *testing.T) {
		cfgPath := useConfigDir(t)
		code, stdout, stderr := run(t, "init", "--server", srv.url, "--tls-root-file", srv.rootFile)
		if code != 2 || !strings.Contains(stdout, srv.rootPin) || !strings.Contains(stderr, "compare these with your invite and re-run with --tls-pin") {
			t.Fatalf("init without --tls-pin: exit %d\n%s\n%s", code, stdout, stderr)
		}
		requireNoConfig(t, cfgPath)
	})

	t.Run("no_banner_without_software", func(t *testing.T) {
		agent := newInitServer(t, "user=agent, host=agent, machine=agent, ops=agent, log=agent")
		useConfigDir(t)
		code, _, stderr := run(t, agent.args()...)
		if code != 0 || strings.Contains(stderr, "EVALUATION ONLY") {
			t.Fatalf("init against agent custody: exit %d:\n%s", code, stderr)
		}
	})

	refusals := []struct {
		name string
		args []string
		want string
	}{
		{"refuses_http_url", []string{"init", "--server", strings.Replace(srv.url, "https://", "http://", 1), "--tls-pin", srv.rootPin, "--root-pin", srv.rootFP, "--threshold", "1"}, "https"},
		{"refuses_ip_literal", []string{"init", "--server", strings.Replace(srv.url, "localhost", "127.0.0.1", 1), "--tls-pin", srv.rootPin, "--root-pin", srv.rootFP, "--threshold", "1"}, "IP address"},
		{"refuses_url_with_path", []string{"init", "--server", srv.url + "/api", "--tls-pin", srv.rootPin, "--root-pin", srv.rootFP, "--threshold", "1"}, "no path"},
		{"refuses_unobserved_tls_pin", []string{"init", "--server", srv.url, "--tls-root-file", srv.rootFile, "--tls-pin", srv.otherPin, "--root-pin", srv.rootFP, "--threshold", "1"}, "presented no chain"},
		{"refuses_wrong_root_pin", []string{"init", "--server", srv.url, "--tls-root-file", srv.rootFile, "--tls-pin", srv.rootPin, "--root-pin", "SHA256:" + strings.Repeat("A", 43), "--threshold", "1"}, "do not match the --root-pin set"},
		{"refuses_threshold_above_roots", []string{"init", "--server", srv.url, "--tls-root-file", srv.rootFile, "--tls-pin", srv.rootPin, "--root-pin", srv.rootFP, "--threshold", "2"}, "threshold"},
		{"refuses_system_roots_for_private_ca", []string{"init", "--server", srv.url, "--tls-pin", srv.rootPin, "--root-pin", srv.rootFP, "--threshold", "1"}, "certificate"},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			cfgPath := useConfigDir(t)
			code, _, stderr := run(t, c.args...)
			if code == 0 || !strings.Contains(stderr, c.want) {
				t.Fatalf("exit %d, want a refusal mentioning %q:\n%s", code, c.want, stderr)
			}
			requireNoConfig(t, cfgPath)
		})
	}

	// The installation pin (03-14c, F06): init saves the ID of the bundle
	// its root pins verified and prints it; an ID-less bundle saves none.
	t.Run("saves_installation", func(t *testing.T) {
		cfgPath := useConfigDir(t)
		code, stdout, stderr := run(t, srv.args()...)
		if code != 0 {
			t.Fatalf("init exit %d:\n%s\n%s", code, stdout, stderr)
		}
		var saved map[string]any
		if err := json.Unmarshal(readTestFile(t, cfgPath), &saved); err != nil {
			t.Fatal(err)
		}
		if srv.installation == "" || saved["installation_id"] != srv.installation {
			t.Fatalf("saved installation_id %v, want the bundle's %q", saved["installation_id"], srv.installation)
		}
		want := "installation id: " + srv.installation + " (saved with your pins; compare it with the installation ID on record: " +
			"the ceremony transcript's Installation ID line, or the one your admin gives you)\nsaved " + cfgPath + "\n"
		lines := strings.Split(stdout, "\n")
		// The line before it is the summary's last: the WebAuthn RP line, or
		// the log key line under a policy that names no RP.
		if !strings.HasSuffix(stdout, want) || len(lines) < 4 ||
			(!strings.HasPrefix(lines[len(lines)-4], "WebAuthn RP ") && !strings.HasPrefix(lines[len(lines)-4], "log key ")) {
			t.Fatalf("init stdout does not end with the summary, the installation line and the save:\n%s\nwant suffix\n%s", stdout, want)
		}
	})
	t.Run("id_less_bundle_saves_none", func(t *testing.T) {
		idless := newInitServerEdit(t, softwareCustody, func(b *trust.Bundle) { b.InstallationID = "" })
		cfgPath := useConfigDir(t)
		code, stdout, stderr := run(t, idless.args()...)
		if code != 0 {
			t.Fatalf("init exit %d:\n%s\n%s", code, stdout, stderr)
		}
		if strings.Contains(string(readTestFile(t, cfgPath)), "installation_id") {
			t.Fatalf("an ID-less bundle saved an installation_id:\n%s", readTestFile(t, cfgPath))
		}
		if !strings.Contains(stdout, "\ninstallation id: none (the trust bundle names none yet; run keyroster init again once it does)\nsaved ") {
			t.Fatalf("init stdout lacks the none line before the save:\n%s", stdout)
		}
	})

	t.Run("no_config_written_on_refusal", func(t *testing.T) {
		for _, c := range refusals {
			cfgPath := useConfigDir(t)
			if code, _, _ := run(t, c.args...); code == 0 {
				t.Fatalf("%s: init succeeded", c.name)
			}
			requireNoConfig(t, cfgPath)
			if _, err := os.Stat(filepath.Dir(cfgPath)); err == nil {
				entries, _ := os.ReadDir(filepath.Dir(cfgPath))
				if len(entries) != 0 {
					t.Fatalf("%s: the config directory holds %d files", c.name, len(entries))
				}
			}
		}
	})
}

// TestObserveRootsTransportText: init's first connection has no
// http.Client, so plain HTTP on the TLS port shows as Go's record-header
// error. Go wrote that text, so it is printed whole, not as a cut
// peer-text excerpt.
func TestObserveRootsTransportText(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(s.Close)
	_, port, err := net.SplitHostPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = observeRoots(context.Background(), "localhost:"+port, "localhost", port, x509.NewCertPool())
	var recErr tls.RecordHeaderError
	if !errors.As(err, &recErr) {
		t.Fatalf("plain HTTP: err = %v, want a tls.RecordHeaderError", err)
	}
	want := "connect to localhost:" + port + ": tls: first record does not look like a TLS handshake"
	if err.Error() != want {
		t.Fatalf("plain HTTP: err = %q, want %q", err.Error(), want)
	}
}
