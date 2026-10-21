package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// userAddEnv is a localhost TLS server under a test root that serves a
// root-signed trust document whose policy names inviteOrigin and answers
// the admin API with handler, a saved CLI config pinned to it, and an
// ssh-agent keyring holding the admin key.
type userAddEnv struct {
	cfg      *Config
	adminKey ed25519.PrivateKey
	adminFP  string
	root     *x509.Certificate
	requests []string // verified admin names, one per request
	hits     int      // every request the server saw
	trustDoc []byte   // the /api/v1/trust document served
}

func newUserAddEnv(t *testing.T, custody string, handler func(w http.ResponseWriter, r *http.Request, body []byte)) *userAddEnv {
	t.Helper()
	_, adminKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminSigner, err := ssh.NewSignerFromKey(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	e := &userAddEnv{adminKey: adminKey, adminFP: ssh.FingerprintSHA256(adminSigner.PublicKey())}
	admins := []trust.AdminKey{{Name: "root-admin", Key: trust.FormatKey(adminSigner.PublicKey())}}
	root, rootKey := initTestRoot(t)
	e.root = root
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
	var rootFP string
	e.trustDoc, rootFP = userAddTrustDoc(t)
	url := serveTLS(t, tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: leafKey}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits++
		if r.URL.Path == serverclient.TrustPath {
			w.Header().Set(serverclient.CustodyHeader, custody)
			_, _ = w.Write(e.trustDoc)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		// The server's checks: signed for the origin the request reached,
		// and the body is the signed one.
		name, _, digest, err := adminauth.Verify(r.Header, "https://"+r.Host, r.Method, r.RequestURI, time.Now(), admins)
		if err == nil {
			err = adminauth.CheckBody(digest, body)
		}
		w.Header().Set(serverclient.CustodyHeader, custody)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"admin authentication failed"}`)
			return
		}
		e.requests = append(e.requests, name)
		handler(w, r, body)
	}))
	e.cfg = &Config{
		Server:         url,
		TLSRootsPEM:    []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))},
		TLSPins:        []string{serverclient.PinOf(root)},
		TrustPins:      []string{rootFP},
		TrustThreshold: 1,
		User:           "admin",
		AdminKey:       e.adminFP,
	}
	useConfigDir(t)
	if _, err := saveConfig(e.cfg, false); err != nil {
		t.Fatal(err)
	}
	useKeyring(t, adminKey)
	return e
}

// inviteToken is a well-formed invite token.
var inviteToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

// inviteRPID is the relying party of the policy in userAddTrustDoc, and
// inviteOrigin its one webauthn origin. The CLI never connects to it; it
// only checks that an invite URL names it.
const (
	inviteRPID   = "keyroster.example"
	inviteOrigin = "https://" + inviteRPID
)

// userAddTrustDoc signs a genesis bundle whose policy names the WebAuthn
// RP inviteRPID with one software root (the in-process ceremony of
// root_test.go) and returns the /api/v1/trust document and the root's
// fingerprint.
func userAddTrustDoc(t *testing.T) ([]byte, string) {
	t.Helper()
	g := newCeremony(t, 1)
	g.policy = filepath.Join(g.dir, "webauthn-policy.json")
	if code, _, stderr := run(t, "root", "genesis-policy", "--admin", "alice="+filepath.Join(g.dir, "alice.pub"),
		"--webauthn-rp-id", inviteRPID, "--out", g.policy); code != 0 {
		t.Fatalf("genesis-policy exit %d: %s", code, stderr)
	}
	useKeyring(t, g.rootKeys...)
	typeHashPrefix(t, g.out)
	if code, _, stderr := g.sign(t, "1", 0); code != 0 {
		t.Fatalf("root sign: exit %d: %s", code, stderr)
	}
	read := func(name string) []byte { return readTestFile(t, filepath.Join(g.out, name)) }
	doc, err := json.Marshal(serverclient.TrustResponse{
		Bundle: read("bundle.json"), BundleSigs: read("bundle.json.sigs"),
		Policy: read("policy.json"), PolicySigs: read("policy.json.sigs"), BundleVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc, g.fingerprint(t, 0)
}

// created answers 201 with an invite at inviteOrigin.
func (e *userAddEnv) created(w http.ResponseWriter, _ *http.Request, body []byte) {
	var req serverclient.AddUserRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(serverclient.AddUserResponse{
		Name: req.Name, InviteURL: inviteOrigin + "/enroll/" + inviteToken, ExpiresAt: "2026-10-21T12:00:00Z",
	})
}

// answer replies code with body.
func answer(code int, body string) func(http.ResponseWriter, *http.Request, []byte) {
	return func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func TestUserAdd(t *testing.T) {
	agentCustody := "user=agent, host=agent, machine=agent, ops=agent, log=agent"

	t.Run("init_line_has_tls_root_file", func(t *testing.T) {
		var e *userAddEnv
		e = newUserAddEnv(t, agentCustody, func(w http.ResponseWriter, r *http.Request, b []byte) { e.created(w, r, b) })
		code, stdout, stderr := run(t, "user", "add", "carol")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if !strings.Contains(stdout, "Invite for carol: "+inviteOrigin+"/enroll/"+inviteToken+"\n") {
			t.Fatalf("no invite line:\n%s", stdout)
		}
		wantLine := "keyroster init --server " + e.cfg.Server + " --tls-root-file keyroster-tls-root.pem --tls-pin " + e.cfg.TLSPins[0] +
			" --root-pin " + e.cfg.TrustPins[0] + " --threshold 1 --user carol\n"
		if !strings.Contains(stdout, "\n"+wantLine) || strings.Count(stdout, "\nkeyroster init ") != 1 {
			t.Fatalf("want exactly one init line %q:\n%s", wantLine, stdout)
		}
		var certs []*x509.Certificate
		for rest := []byte(stdout); ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			certs = append(certs, c)
		}
		if len(certs) != 1 || !certs[0].Equal(e.root) {
			t.Fatalf("the printed PEM blocks are %d certificates, want exactly the pinned root", len(certs))
		}
		if len(e.requests) != 1 || e.requests[0] != "root-admin" {
			t.Fatalf("server saw admin requests %q", e.requests)
		}
		if stderr != "" {
			t.Fatalf("stderr %q, want nothing for agent custody", stderr)
		}
	})

	t.Run("non_canonical_saved_server", func(t *testing.T) {
		// A config saved before ParseServerURL canonicalized the host loads
		// as the canonical origin: the request goes out and the printed init
		// line names the canonical form.
		var e *userAddEnv
		e = newUserAddEnv(t, agentCustody, func(w http.ResponseWriter, r *http.Request, b []byte) { e.created(w, r, b) })
		canonical := e.cfg.Server
		e.cfg.Server = strings.Replace(canonical, "https://localhost:", "https://LocalHost.:", 1)
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := run(t, "user", "add", "carol")
		if code != 0 || !strings.Contains(stdout, "keyroster init --server "+canonical+" ") || strings.Contains(stdout, "LocalHost") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s\nwant the init line with %s", code, stderr, stdout, canonical)
		}
	})

	t.Run("software_custody_banner_once", func(t *testing.T) {
		var e *userAddEnv
		e = newUserAddEnv(t, "user=software, host=software, machine=software, ops=software, log=software",
			func(w http.ResponseWriter, r *http.Request, b []byte) { e.created(w, r, b) })
		code, _, stderr := run(t, "user", "add", "carol")
		if code != 0 || strings.Count(stderr, custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"})) != 1 {
			t.Fatalf("exit %d, stderr:\n%s\nwant the evaluation-only banner once", code, stderr)
		}
	})

	t.Run("no_admin_key_refused", func(t *testing.T) {
		e := newUserAddEnv(t, agentCustody, answer(http.StatusCreated, "{}"))
		e.cfg.AdminKey = ""
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := run(t, "user", "add", "carol")
		if code != 1 || !strings.Contains(stderr, "no admin key") || !strings.Contains(stderr, "--admin-key") || len(e.requests) != 0 {
			t.Fatalf("exit %d, stderr %q, want the no-admin-key refusal with instructions and no request", code, stderr)
		}
	})

	t.Run("admin_key_not_in_agent", func(t *testing.T) {
		e := newUserAddEnv(t, agentCustody, answer(http.StatusCreated, "{}"))
		_, other, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		useKeyring(t, other)
		code, _, stderr := run(t, "user", "add", "carol")
		if code != 1 || !strings.Contains(stderr, "ssh-agent does not hold the admin key "+e.adminFP) || len(e.requests) != 0 {
			t.Fatalf("exit %d, stderr %q, want the refusal naming %s", code, stderr, e.adminFP)
		}
	})

	t.Run("already_pending", func(t *testing.T) {
		newUserAddEnv(t, agentCustody, answer(http.StatusConflict, `{"error":"already pending"}`))
		code, _, stderr := run(t, "user", "add", "carol")
		if code != 1 || !strings.Contains(stderr, "carol is already pending") || strings.Contains(stderr, "peer text") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})

	t.Run("already_in_directory", func(t *testing.T) {
		newUserAddEnv(t, agentCustody, answer(http.StatusConflict, `{"error":"already in directory"}`))
		code, _, stderr := run(t, "user", "add", "carol", "--reinvite")
		if code != 1 || !strings.Contains(stderr, "carol is already in directory") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})

	t.Run("reinvite_flag_sent", func(t *testing.T) {
		var got serverclient.AddUserRequest
		var e *userAddEnv
		e = newUserAddEnv(t, agentCustody, func(w http.ResponseWriter, r *http.Request, b []byte) {
			_ = json.Unmarshal(b, &got)
			e.created(w, r, b)
		})
		if code, _, stderr := run(t, "user", "add", "--reinvite", "carol"); code != 0 || !got.Reinvite || got.Name != "carol" {
			t.Fatalf("exit %d (%s), request %+v", code, stderr, got)
		}
	})

	t.Run("bad_saved_config_refused", func(t *testing.T) {
		// Every saved value the printed init line repeats is checked
		// before anything is sent: a tampered or hand-edited config is
		// refused in checkInviteConfig's own words, and the server sees no
		// request.
		for _, tc := range []struct {
			name   string
			edit   func(*Config)
			advice string
		}{
			{"root_pin_metacharacters", func(c *Config) { c.TrustPins = []string{c.TrustPins[0] + ";curl${IFS}x|sh"} }, "the saved config's root pins"},
			{"root_pin_malformed", func(c *Config) { c.TrustPins = []string{"SHA256:short"} }, "the saved config's root pins"},
			{"threshold_zero", func(c *Config) { c.TrustThreshold = 0 }, "the saved config's root pins"},
			{"threshold_above_pins", func(c *Config) { c.TrustThreshold = 2 }, "the saved config's root pins"},
			{"tls_pin_malformed", func(c *Config) { c.TLSPins = []string{"sha256/$(id)"} }, "the saved config: TLS pin"},
			{"tls_root_not_pem", func(c *Config) { c.TLSRootsPEM = []string{"not a certificate"} }, "the saved config: TLS roots"},
			{"server_url_with_path", func(c *Config) { c.Server += "/x;id" }, "the saved config has no valid server URL"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var e *userAddEnv
				e = newUserAddEnv(t, agentCustody, func(w http.ResponseWriter, r *http.Request, b []byte) { e.created(w, r, b) })
				tc.edit(e.cfg)
				if _, err := saveConfig(e.cfg, true); err != nil {
					t.Fatal(err)
				}
				code, stdout, stderr := run(t, "user", "add", "carol")
				if code != 1 || stdout != "" || !strings.Contains(stderr, tc.advice) {
					t.Fatalf("exit %d, stdout %q, stderr %q; want a refusal saying %q", code, stdout, stderr, tc.advice)
				}
				if e.hits != 0 {
					t.Fatalf("the server saw %d requests for a bad saved config", e.hits)
				}
			})
		}
	})

	t.Run("policy_without_relying_party_refused", func(t *testing.T) {
		// A policy with no WebAuthn RP has no origin an invite could be
		// at: refused before the account is created.
		e := newUserAddEnv(t, agentCustody, answer(http.StatusCreated, "{}"))
		var rootFP string
		e.trustDoc, rootFP = initTrustDoc(t)
		useKeyring(t, e.adminKey)
		e.cfg.TrustPins = []string{rootFP}
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := run(t, "user", "add", "carol")
		if code != 1 || !strings.Contains(stderr, "names no WebAuthn relying party") || len(e.requests) != 0 {
			t.Fatalf("exit %d, stderr %q, admin requests %q; want a refusal before any admin request", code, stderr, e.requests)
		}
	})

	t.Run("server_url_not_policy_origin_diagnosed", func(t *testing.T) {
		// The saved server URL (https://localhost:PORT) is not a webauthn
		// origin of the verified policy (inviteOrigin). The request is
		// still sent; the server's uniform 401 is printed with that cause,
		// the policy's origin and the CLI's own advice last.
		e := newUserAddEnv(t, agentCustody, answer(http.StatusUnauthorized, `{"error":"admin authentication failed"}`))
		code, stdout, stderr := run(t, "user", "add", "carol")
		want := "admin authentication failed. The saved server URL " + e.cfg.Server +
			" is not a webauthn origin of the root-signed policy (" + inviteOrigin + ")"
		if code != 1 || stdout != "" || !strings.Contains(stderr, want) ||
			!strings.HasSuffix(strings.TrimSuffix(stderr, "\n"), errAdminOriginAdvice.Error()) {
			t.Fatalf("exit %d, stdout %q, stderr %q; want the 401 diagnosed as %q", code, stdout, stderr, want)
		}
		if len(e.requests) != 1 {
			t.Fatalf("server saw admin requests %q, want the one admin request sent", e.requests)
		}
	})

	t.Run("bad_name_refused_locally", func(t *testing.T) {
		e := newUserAddEnv(t, agentCustody, answer(http.StatusCreated, "{}"))
		for _, name := range []string{"Carol", "-x", "a;b", strings.Repeat("a", 65)} {
			if code, _, _ := run(t, "user", "add", "--", name); code == 0 {
				t.Fatalf("user add %q succeeded", name)
			}
		}
		if len(e.requests) != 0 {
			t.Fatalf("a bad name reached the server: %q", e.requests)
		}
	})
}

// TestAdminOriginDiagnosis: an admin authentication failure at a server URL
// the policy does not name gets the cause, the policy's origins and the
// advice appended, with AdminJSON's text (clock hint included) kept in
// front; at a policy origin, and for any other error, nothing changes.
func TestAdminOriginDiagnosis(t *testing.T) {
	origins := []string{"https://keyroster.example", "https://keyroster.example:8443"}
	authErr := fmt.Errorf("https://localhost:9443/api/v1/admin/users: %w (your clock differs from the server by 120s)", serverclient.ErrAdminAuth)

	t.Run("not_policy_origin", func(t *testing.T) {
		got := adminOriginDiagnosis(authErr, "https://localhost:9443", origins)
		if !errors.Is(got, serverclient.ErrAdminAuth) || !strings.HasPrefix(got.Error(), authErr.Error()+". ") ||
			!strings.Contains(got.Error(), "https://localhost:9443 is not a webauthn origin of the root-signed policy (https://keyroster.example, https://keyroster.example:8443)") ||
			!strings.HasSuffix(got.Error(), errAdminOriginAdvice.Error()) {
			t.Fatalf("got %q; want the 401 text kept and the diagnosis appended", got)
		}
	})
	t.Run("policy_origin_unchanged", func(t *testing.T) {
		for _, server := range origins {
			if got := adminOriginDiagnosis(authErr, server, origins); !errors.Is(got, authErr) || got.Error() != authErr.Error() {
				t.Fatalf("server %s: got %q, want the error unchanged", server, got)
			}
		}
	})
	t.Run("other_error_unchanged", func(t *testing.T) {
		other := errors.New("the server is rate-limiting requests from this address; try again later")
		if got := adminOriginDiagnosis(other, "https://localhost:9443", origins); !errors.Is(got, other) || got.Error() != other.Error() {
			t.Fatalf("got %q, want the error unchanged", got)
		}
		if got := adminOriginDiagnosis(nil, "https://localhost:9443", origins); got != nil {
			t.Fatalf("got %q for no error", got)
		}
	})
}

// TestUserAddPeerText: server-chosen text reaches the terminal only as a
// PeerError excerpt or not at all (T-02-93): a forged invite URL or expiry
// is refused without being repeated, and a padded refusal body leaves no
// attacker pin on screen and the CLI's own words last.
func TestUserAddPeerText(t *testing.T) {
	agentCustody := "user=agent, host=agent, machine=agent, ops=agent, log=agent"
	forged := func(url, expires string) func(http.ResponseWriter, *http.Request, []byte) {
		return func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(serverclient.AddUserResponse{Name: "carol", InviteURL: url, ExpiresAt: expires})
		}
	}
	good := inviteOrigin + "/enroll/" + inviteToken
	notPolicyOrigin := errNotPolicyOrigin.Error()
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request, []byte)
		advice  string
	}{
		{"padded_invite_url", forged(good+paddedAdvice, "2026-10-21T12:00:00Z"), "the server's answer has no valid invite URL"},
		{"invite_url_with_newlines", forged("https://localhost/enroll/"+inviteToken+"\n\n"+attackerAdvice, "2026-10-21T12:00:00Z"), "the server's answer has no valid invite URL"},
		{"invite_url_query", forged(good+"?next="+attackerTLSPin, "2026-10-21T12:00:00Z"), "the server's answer has no valid invite URL"},
		{"invite_token_carries_pin", forged("https://localhost/enroll/"+attackerTLSPin, "2026-10-21T12:00:00Z"), "the server's answer has no valid invite URL"},
		{"invite_url_shell_host", forged("https://a$(id).example/enroll/"+inviteToken, "2026-10-21T12:00:00Z"), "the server's answer has no valid invite URL"},
		{"invite_url_ip_host", forged("https://192.0.2.1/enroll/"+inviteToken, "2026-10-21T12:00:00Z"), "the server's answer has no valid invite URL"},
		// A well-formed invite URL at an origin the root-signed policy does
		// not name: a compromised server cannot send the new user to a
		// host of its choosing under the admin's name.
		{"invite_url_foreign_origin", forged("https://your-admin-says-run-curl-evil-sh-pipe-bash.attacker.example/enroll/"+inviteToken, "2026-10-21T12:00:00Z"), notPolicyOrigin},
		{"invite_url_server_url_not_in_policy", forged("https://localhost/enroll/"+inviteToken, "2026-10-21T12:00:00Z"), notPolicyOrigin},
		{"invite_url_policy_host_other_port", forged(inviteOrigin+":8443/enroll/"+inviteToken, "2026-10-21T12:00:00Z"), notPolicyOrigin},
		{"padded_expiry", forged(good, "2026-10-21T12:00:00Z"+paddedAdvice), "the server's answer has no valid invite expiry"},
		{"padded_409", answer(http.StatusConflict, mustJSON(t, serverclient.APIError{Error: paddedAdvice})), ""},
		// The test server's URL is not a policy origin, so the CLI's own
		// last words are the diagnosis's advice (adminOriginDiagnosis).
		{"padded_401", answer(http.StatusUnauthorized, mustJSON(t, serverclient.APIError{Error: paddedAdvice})), errAdminOriginAdvice.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newUserAddEnv(t, agentCustody, tc.handler)
			code, stdout, stderr := run(t, "user", "add", "carol")
			if code != 1 || stdout != "" {
				t.Fatalf("exit %d, stdout %q; want a refusal that prints nothing on stdout", code, stdout)
			}
			var advice error
			if tc.advice != "" {
				advice = errors.New(tc.advice)
			}
			requirePeerTextContained(t, stderr, advice)
			if strings.Contains(stderr, "attacker.example") || strings.Contains(stderr, "/enroll/") {
				t.Fatalf("stderr repeats the server's invite URL: %q", stderr)
			}
		})
	}
	t.Run("control_well_formed_answer", func(t *testing.T) {
		newUserAddEnv(t, agentCustody, forged(good, "2026-10-21T12:00:00+02:00"))
		code, stdout, stderr := run(t, "user", "add", "carol")
		if code != 0 || !strings.Contains(stdout, "Invite for carol: "+good+"\n") ||
			!strings.Contains(stdout, "expires at 2026-10-21T10:00:00Z") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("invite_url_printed_rebuilt", func(t *testing.T) {
		// An upper-case scheme and host, the default port and an empty
		// fragment marker are accepted, and the URL printed is the one
		// rebuilt from its parts, never the received text.
		newUserAddEnv(t, agentCustody, forged("HTTPS://KeyRoster.Example:443/enroll/"+inviteToken+"#", "2026-10-21T12:00:00Z"))
		code, stdout, stderr := run(t, "user", "add", "carol")
		if code != 0 || !strings.Contains(stdout, "Invite for carol: "+good+"\n") || strings.Contains(stdout, "KeyRoster") || strings.Contains(stdout, "#") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s\nwant the invite printed as %s", code, stderr, stdout, good)
		}
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
