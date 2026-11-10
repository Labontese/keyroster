package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/wire"
)

// krlDoc returns a served KRL document of version v whose manifest names
// logIndex and installation, signed by signer under krl.Namespace, over a
// KRL that lists serial 1729 under every CA key of the bundle.
func (e *dirEnv) krlDoc(t *testing.T, v, logIndex uint64, installation string, signer ssh.Signer) []byte {
	t.Helper()
	return e.krlDocAt(t, v, logIndex, installation, signer, time.Now())
}

// krlDocAt is krlDoc with the manifest issued at issued (whole seconds).
func (e *dirEnv) krlDocAt(t *testing.T, v, logIndex uint64, installation string, signer ssh.Signer, issued time.Time) []byte {
	t.Helper()
	var set krl.Set
	for _, role := range []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine} {
		set.Certs = append(set.Certs, krl.CertSection{CAKey: e.caKey(t, role), Serials: []uint64{1729}})
	}
	return e.krlDocData(t, v, logIndex, installation, signer, issued, e.encodeKRL(t, v, set))
}

// encodeKRL is krl.Encode of set as version v.
func (e *dirEnv) encodeKRL(t *testing.T, v uint64, set krl.Set) []byte {
	t.Helper()
	data, err := krl.Encode(set, v, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// krlDocData is the served KRL document over data, of version v, whose
// manifest names logIndex and installation, issued at issued and signed
// by signer under krl.Namespace.
func (e *dirEnv) krlDocData(t *testing.T, v, logIndex uint64, installation string, signer ssh.Signer, issued time.Time, data []byte) []byte {
	t.Helper()
	m := krl.Manifest{
		InstallationID: installation,
		KRLVersion:     v,
		KRLSHA256:      krl.SHA256Hex(data),
		IssuedAt:       issued.UTC().Truncate(time.Second).Format(trust.TimeFormat),
		BundleVersion:  1,
		LogIndex:       logIndex,
	}
	manifest, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, signer, krl.Namespace, manifest)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(serverclient.KRLDocument{KRL: data, Manifest: manifest, Sig: sig})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// caKey is the bundle's CA key of role.
func (e *dirEnv) caKey(t *testing.T, role string) ssh.PublicKey {
	t.Helper()
	for _, ca := range e.bundle.CAs {
		if ca.Role == role {
			pub, err := trust.ParseKey(ca.Key)
			if err != nil {
				t.Fatal(err)
			}
			return pub
		}
	}
	t.Fatalf("the bundle has no %s CA", role)
	return nil
}

// serveRevoke makes the stub server answer every revocation with ans
// (without any signer) and serve krlDoc (nil: no KRL published).
func (e *dirEnv) serveRevoke(ans serverclient.RevokeAnswer, krlDoc []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.override["POST "+serverclient.AdminRevokePath] = func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(ans)
	}
	if krlDoc != nil {
		e.override["GET "+serverclient.KRLPath] = func(w http.ResponseWriter) { _, _ = w.Write(krlDoc) }
	}
}

// TestRevokeRefusalText (pre-merge review): each refusal the runbook lists
// reaches the operator in the CLI's words. A key that is not a policy
// admin is refused by keyroster-server (401) before the signer sees the
// request; a 403 without a reason the CLI knows is any other refusal by
// the signer, such as request_time_skew when ssh-agent took over five
// minutes to sign.
func TestRevokeRefusalText(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "id.pub")
	writeTestFile(t, keyFile, ssh.MarshalAuthorizedKey(newRevokeKey(t)))
	keyID := []string{"revoke", "key-id", "kr1/ca=user/sub=u:x/ser=5"}
	key := []string{"revoke", "key", keyFile}
	for _, tc := range []struct {
		name, status, body string
		args               []string // nil: revoke serial 1729
		want               []string
	}{
		{"unknown_serial", "400", `{"error":"unknown_serial"}`, nil, []string{"the signer has issued no certificate with this serial; nothing was revoked",
			"keyroster revoke key-id", "keyroster revoke key FILE"}},
		{"ca_role_mismatch", "403", `{"error":"ca_role_mismatch"}`, nil, []string{"was not issued by that CA; pass the right --ca; nothing was revoked"}},
		{"duplicate_request", "403", `{"error":"duplicate_request"}`, nil, []string{"the signer has already accepted a request with this ID"}},
		{"other_signer_refusal", "403", `{"error":"request_time_skew"}`, nil, []string{"the signer refused the revocation; nothing was revoked"}},
		{"signer_unavailable", "503", `{"error":"signer unavailable"}`, nil, []string{"The signer's log names the reason"}},
		// 03-03's refusal details (03-03b): each in the CLI's own words.
		{"key_id_not_issued", "400", `{"error":"key_id_not_issued"}`, keyID, []string{"the signer has issued no certificate with this key ID under that CA; nothing was revoked",
			"keyroster revoke key FILE"}},
		{"explicit_key_cap_reached", "403", `{"error":"explicit_key_cap_reached"}`, key, []string{"explicit_key_cap_reached", "nothing was revoked",
			"docs/runbooks/revoke.md"}},
		{"key_is_ca_of_this_installation", "403", `{"error":"key_is_ca_of_this_installation"}`, key, []string{"a key of this installation's trust bundle",
			"emergency CA rotation", "nothing was revoked"}},
		{"subject_kind_unsupported", "403", `{"error":"subject_kind_unsupported"}`, nil, []string{"revokes user and host subjects only", "nothing was revoked"}},
		{"revoke_installation_missing", "403", `{"error":"revoke_installation_missing"}`, nil, []string{"revoke_installation_missing",
			"this CLI always names one", "nothing was revoked"}},
		{"revoke_installation_mismatch", "403", `{"error":"revoke_installation_mismatch"}`, nil, []string{"revoke_installation_mismatch",
			"another installation", "nothing was revoked"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDirEnv(t, 1, 1)
			e.mu.Lock()
			e.override["POST "+serverclient.AdminRevokePath] = func(w http.ResponseWriter) {
				code := http.StatusForbidden
				switch tc.status {
				case "503":
					code = http.StatusServiceUnavailable
				case "400":
					code = http.StatusBadRequest
				}
				w.WriteHeader(code)
				_, _ = io.WriteString(w, tc.body)
			}
			e.mu.Unlock()
			args := tc.args
			if args == nil {
				args = []string{"revoke", "serial", "1729"}
			}
			code, stdout, stderr := run(t, args...)
			if code == 0 || stdout != "" || strings.Contains(stderr, "is --admin-key a policy admin") || strings.Contains(stderr, "arrives in a later version") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want a refusal", code, stdout, stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(stderr, w) {
					t.Fatalf("stderr %q lacks %q", stderr, w)
				}
			}
		})
	}
	t.Run("not_a_policy_admin", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.agent.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		reached := false
		e.mu.Lock()
		e.override["POST "+serverclient.AdminRevokePath] = func(http.ResponseWriter) { reached = true }
		e.mu.Unlock()
		code, stdout, stderr := run(t, "revoke", "serial", "1729", "--admin-key", ssh.FingerprintSHA256(s.PublicKey()))
		e.mu.Lock()
		defer e.mu.Unlock()
		if code == 0 || stdout != "" || reached || !strings.Contains(stderr, serverclient.AdminRevokePath+": admin authentication failed") {
			t.Fatalf("exit %d, stdout %q, stderr %q, revoke handler reached %v; want admin authentication failed", code, stdout, stderr, reached)
		}
	})
}

// TestRevokeSerialConfirm (pre-merge review): the server's answer to a
// revocation is unsigned, so the CLI reports it as the server's and
// confirms it against the KRL the server then serves, which must verify
// against the root-pinned bundle and its installation ID with at least the
// reported version and krl_publish entry. An answer a server invented
// without the signer fails with a non-zero exit.
func TestRevokeSerialConfirm(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	ok := serverclient.RevokeAnswer{KRLVersion: 3, RevokeLeaf: 8, PublishLeaf: 9}
	t.Run("confirmed", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevoke(ok, e.krlDoc(t, 3, 9, e.bundle.InstallationID, e.ops))
		code, stdout, stderr := run(t, "revoke", "serial", "1729", "--reason", "test")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		for _, want := range []string{
			"The server reports serial 1729 (user) revoked: KRL v3 published (log entries 8, 9).\n",
			"Checked: the server serves KRL v3, signed by the ops key of your root-pinned trust bundle (log entry 9), issued at ",
			", at most 300 s before this request.\n",
			"Checked: KRL v3 lists serial 1729 under a user CA key of your trust bundle, so it revokes that certificate.\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout %q lacks %q", stdout, want)
			}
		}
		if strings.HasPrefix(stdout, "revoked serial") {
			t.Fatalf("stdout %q states the revocation as a fact", stdout)
		}
	})
	t.Run("request_names_installation", func(t *testing.T) {
		// Pre-merge review of PR #61 (owner decision 2026-10-26): the
		// request is v2, names the installation of the root-pinned bundle
		// and is signed under keyroster/revoke-request/v2.
		e := newDirEnv(t, 1, 1)
		e.serveRevoke(ok, e.krlDoc(t, 3, 9, e.bundle.InstallationID, e.ops))
		if code, _, stderr := run(t, "revoke", "serial", "1729"); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		e.mu.Lock()
		raw := e.revokeBody
		e.mu.Unlock()
		var body serverclient.RevokeBody
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		req, err := wire.ParseRevokeRequest(body.Request)
		if err != nil || e.bundle.InstallationID == "" || req.InstallationID != e.bundle.InstallationID || len(req.Evidence) != 1 {
			t.Fatalf("request %+v, %v; want one for installation %q", req, err, e.bundle.InstallationID)
		}
		sig, err := sshsig.Parse(req.Evidence[0].Blob)
		if err != nil || sig.Verify("keyroster/revoke-request/v2", req.SigningBytes()) != nil {
			t.Fatalf("the evidence is not an SSHSIG under keyroster/revoke-request/v2 over the request: %v", err)
		}
	})
	t.Run("issued_inside_window", func(t *testing.T) {
		// The signer sets issued_at from a clock reading within 300 s
		// of the request's CreatedAt, so a KRL issued that long before
		// the request may still be the one this revocation published.
		e := newDirEnv(t, 1, 1)
		e.serveRevoke(ok, e.krlDocAt(t, 3, 9, e.bundle.InstallationID, e.ops, time.Now().Add(-290*time.Second)))
		if code, stdout, stderr := run(t, "revoke", "serial", "1729"); code != 0 {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
	t.Run("enforcement_by_role", func(t *testing.T) {
		// sshd's RevokedKeys refuses user and machine certificates (both
		// user certificates); a host certificate is refused only by SSH
		// clients with RevokedHostKeys, never by a host's agent.
		e := newDirEnv(t, 1, 1)
		e.serveRevoke(ok, e.krlDoc(t, 3, 9, e.bundle.InstallationID, e.ops))
		for ca, want := range map[string]string{
			"user":    "Hosts enforce it once their keyroster agent applies this KRL.\n",
			"machine": "Hosts enforce it once their keyroster agent applies this KRL.\n",
			"host": "A host certificate is checked by SSH clients, not by sshd: clients refuse it once keyroster login or keyroster known-hosts sync " +
				"has written this KRL to ~/.ssh/keyroster_revoked_hosts.krl.\n",
		} {
			code, stdout, stderr := run(t, "revoke", "serial", "1729", "--ca", ca)
			if code != 0 || !strings.Contains(stdout, want) || (ca == "host" && strings.Contains(stdout, "Hosts enforce")) {
				t.Fatalf("--ca %s: exit %d, stdout %q, stderr %q; want %q", ca, code, stdout, stderr, want)
			}
		}
	})
	for _, tc := range []struct {
		name string
		ans  serverclient.RevokeAnswer
		doc  func(e *dirEnv) []byte
		want string
	}{
		{"no_krl_served", ok, func(*dirEnv) []byte { return nil }, "the server serves no KRL"},
		{"manifest_not_by_ops_key", ok, func(e *dirEnv) []byte { return e.krlDoc(t, 3, 9, e.bundle.InstallationID, otherSigner) }, "does not verify against your root-pinned trust bundle"},
		{"other_installation", ok, func(e *dirEnv) []byte {
			return e.krlDoc(t, 3, 9, "0123456789abcdef0123456789abcdef", e.ops)
		}, "does not verify against your root-pinned trust bundle"},
		{"older_krl_served", ok, func(e *dirEnv) []byte { return e.krlDoc(t, 2, 7, e.bundle.InstallationID, e.ops) }, "does not verify against your root-pinned trust bundle"},
		{"published_before_reported_entry", ok, func(e *dirEnv) []byte { return e.krlDoc(t, 3, 5, e.bundle.InstallationID, e.ops) }, "before the reported entry 9"},
		{"leaves_not_adjacent", serverclient.RevokeAnswer{KRLVersion: 3, RevokeLeaf: 4, PublishLeaf: 9}, func(e *dirEnv) []byte {
			return e.krlDoc(t, 3, 9, e.bundle.InstallationID, e.ops)
		}, "is not one the signer gives"},
		{"version_zero", serverclient.RevokeAnswer{KRLVersion: 0, RevokeLeaf: 8, PublishLeaf: 9}, func(e *dirEnv) []byte {
			return e.krlDoc(t, 3, 9, e.bundle.InstallationID, e.ops)
		}, "is not one the signer gives"},
		// A server that dropped the request replays the genuine KRL in
		// force (v3, published at entry 9 by an earlier revocation) under
		// an invented answer whose numbers match it.
		{"replayed_earlier_krl", ok, func(e *dirEnv) []byte {
			return e.krlDocAt(t, 3, 9, e.bundle.InstallationID, e.ops, time.Now().Add(-time.Hour))
		}, "more than 300 s before this request, so this revocation did not publish it"},
		{"replayed_just_outside_window", ok, func(e *dirEnv) []byte {
			return e.krlDocAt(t, 3, 9, e.bundle.InstallationID, e.ops, time.Now().Add(-301*time.Second))
		}, "more than 300 s before this request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDirEnv(t, 1, 1)
			e.serveRevoke(tc.ans, tc.doc(e))
			code, stdout, stderr := run(t, "revoke", "serial", "1729")
			if code == 0 || stdout != "" || !strings.Contains(stderr, "the server reports serial 1729 revoked, but that could not be confirmed") ||
				!strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "journalctl -u keyroster-signer") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want a refusal naming %q", code, stdout, stderr, tc.want)
			}
		})
	}
}

// newRevokeKey is a fresh Ed25519 public key.
func newRevokeKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// revokeOK answers a revocation with ans.
func revokeOK(ans serverclient.RevokeAnswer) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _ = json.NewEncoder(w).Encode(ans) }
}

// revokeRefusedAs answers a revocation with HTTP code and the signer's
// refusal detail.
func revokeRefusedAs(code int, detail string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(serverclient.APIError{Error: detail})
	}
}

// serveRevokes answers the revocations in order with answers (the last
// one repeats) and serves doc as the KRL.
func (e *dirEnv) serveRevokes(doc []byte, answers ...func(http.ResponseWriter)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	// Called with e.mu held (handle).
	e.override["POST "+serverclient.AdminRevokePath] = func(w http.ResponseWriter) {
		a := answers[min(n, len(answers)-1)]
		n++
		a(w)
	}
	e.override["GET "+serverclient.KRLPath] = func(w http.ResponseWriter) { _, _ = w.Write(doc) }
}

// postCalls returns the admin POSTs so far, in order, by short name:
// "revoke" or "directory".
func (e *dirEnv) postCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, c := range e.calls {
		switch c {
		case "POST " + serverclient.AdminRevokePath:
			out = append(out, "revoke")
		case "POST " + serverclient.AdminDirectoryPath:
			out = append(out, "directory")
		default:
			out = append(out, c)
		}
	}
	return out
}

// userKRLDoc is a served KRL document, version v at log entry logIndex,
// signed by the bundle's ops key and issued now, listing serials under
// the user CA key, keyIDs under the user CA key and keys explicitly.
func (e *dirEnv) userKRLDoc(t *testing.T, v, logIndex uint64, serials []uint64, keyIDs []string, keys ...ssh.PublicKey) []byte {
	t.Helper()
	set := krl.Set{Keys: keys}
	if len(serials) > 0 || len(keyIDs) > 0 {
		set.Certs = []krl.CertSection{{CAKey: e.caKey(t, trust.RoleUser), Serials: serials, KeyIDs: keyIDs}}
	}
	return e.krlDocData(t, v, logIndex, e.bundle.InstallationID, e.ops, time.Now(), e.encodeKRL(t, v, set))
}

// installAlice installs a directory version holding alice with one
// passkey, with status status.
func (e *dirEnv) installAlice(t *testing.T, status string) {
	t.Helper()
	cred, _ := pendingEntry(t, webauthn.AlgEdDSA)
	e.installDirect(t, buildDir(t, nil, func(d *directory.Directory) {
		addUser("alice", credOf(cred))(d)
		d.Users[0].Status = status
	}))
}

// aliceStatus is alice's status in the installed directory.
func (e *dirEnv) aliceStatus(t *testing.T) string {
	t.Helper()
	doc, _ := e.installed()
	d, err := directory.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range d.Users {
		if u.Name == "alice" {
			return u.Status
		}
	}
	return ""
}

// lastRevokeRequest parses the last revocation the stub server received.
func (e *dirEnv) lastRevokeRequest(t *testing.T) *wire.RevokeRequest {
	t.Helper()
	e.mu.Lock()
	raw := e.revokeBody
	e.mu.Unlock()
	var body serverclient.RevokeBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	req, err := wire.ParseRevokeRequest(body.Request)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestRevokeUser (03-03b, D-09): keyroster revoke user against a stub
// server. The requests go revoke, directory install, revoke; each answer's
// serials are printed and must be in the verified KRL; a partial result
// exits 3 and a disable that is only a proposal exits 4, each naming the
// re-run; a failed first revocation still disables and exits 1.
func TestRevokeUser(t *testing.T) {
	answer := func(v, leaf uint64, serials ...uint64) serverclient.RevokeAnswer {
		return serverclient.RevokeAnswer{KRLVersion: v, RevokeLeaf: leaf, PublishLeaf: leaf + 1, SerialCount: uint32(len(serials)), Serials: serials} //nolint:gosec // G115: a few test serials
	}
	first, second := answer(3, 8, 5, 6), answer(4, 11, 5, 6)
	t.Run("revoke_user_login_between_revoke_and_disable", func(t *testing.T) {
		// The CLI half of 03-03's TestRevokeSubject case of that name: a
		// certificate (serial 7) issued between the first revocation and
		// the install is in the second sweep's answer, next to the first
		// sweep's serials (re-listing), and is checked in the KRL.
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6, 7}, nil), revokeOK(first), revokeOK(answer(4, 11, 5, 6, 7)))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "directory", "revoke"}) {
			t.Fatalf("requests %v, want revoke, directory, revoke", got)
		}
		for _, want := range []string{
			"First revocation of alice: the server reports 2 certificate(s) revoked: KRL v3 published (log entries 8, 9).\nSerials: 5 6\n",
			"~ user alice active -> disabled",
			"The server reports directory version 2 installed",
			"Second revocation (after the disable) of alice: the server reports 3 certificate(s) revoked: KRL v4 published (log entries 11, 12).\nSerials: 5 6 7\n",
			"Checked: KRL v4 lists each of the 3 serial(s) the server's answer reports, under a user CA key of your trust bundle. The answer is unsigned",
			"alice is disabled, and the KRL lists every certificate of alice the server reported.",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Index(stdout, "First revocation") > strings.Index(stdout, "~ user alice") || strings.Index(stdout, "~ user alice") > strings.Index(stdout, "Second revocation") {
			t.Fatalf("stdout is not in the order revoke, disable, revoke:\n%s", stdout)
		}
		if s := e.aliceStatus(t); s != directory.StatusDisabled {
			t.Fatalf("alice is %s after revoke user, want disabled", s)
		}
	})
	t.Run("sweep_text_unchanged", func(t *testing.T) {
		// 03-09b made the sweep role-generic; a user's output is exactly
		// what it was.
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6}, nil), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		for _, want := range []string{
			"First revocation of alice: the server reports 2 certificate(s) revoked: KRL v3 published (log entries 8, 9).\nSerials: 5 6\n",
			"Checked: KRL v4 lists each of the 2 serial(s) the server's answer reports, under a user CA key of your trust bundle. " +
				"The answer is unsigned, so a certificate it does not report is not checked here; keyroster audit verify on an exported log checks every revocation.\n",
			"alice is disabled, and the KRL lists every certificate of alice the server reported. Hosts enforce it once their keyroster agent applies this KRL.\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout, "host CA key") || strings.Contains(stdout, "signer recovery kept") {
			t.Fatalf("revoke user printed host text:\n%s", stdout)
		}
	})
	t.Run("revoke_user_partial_directory_failure", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6}, nil), revokeOK(first), revokeOK(second))
		e.mu.Lock()
		e.post = func(w http.ResponseWriter, _ serverclient.InstallDirectoryRequest) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"directory_quorum_not_met"}`)
		}
		e.mu.Unlock()
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 3 || !strings.Contains(stdout, "Serials: 5 6\n") || !strings.Contains(stderr, "NOT disabled") ||
			!strings.Contains(stderr, "run keyroster revoke user alice again") || !strings.Contains(stderr, "keyroster user disable alone would leave") {
			t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 with the serials, NOT disabled and the re-run", code, stdout, stderr)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "directory"}) {
			t.Fatalf("requests %v, want revoke, directory and no second revoke", got)
		}
	})
	t.Run("revoke_user_already_disabled", func(t *testing.T) {
		// Pre-merge review of PR #64: another admin installed the disable
		// after the first revocation, and a login in between got serial
		// 7. The command makes no directory change but still sweeps, so
		// serial 7 is revoked and checked in the KRL.
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusDisabled)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6, 7}, nil), revokeOK(first), revokeOK(answer(4, 11, 5, 6, 7)))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		for _, want := range []string{
			"alice is already disabled, so no passkey login issues alice a certificate: no directory change.\n",
			"Second revocation (after reading the directory) of alice: the server reports 3 certificate(s) revoked: KRL v4 published (log entries 11, 12).\nSerials: 5 6 7\n",
			"Checked: KRL v4 lists each of the 3 serial(s) the server's answer reports",
			"That is the server's word: the admins signed directory version 1, the one the server serves, but the server may serve an older version than the signer holds. " +
				"The signer's audit log is the proof",
			"alice is already disabled (the server's word), and the KRL lists every certificate of alice the server reported.",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout lacks %q:\n%s", want, stdout)
			}
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "revoke"}) {
			t.Fatalf("requests %v, want two revokes and no directory install", got)
		}
		requireNotSigned(t, e, 0)
	})
	t.Run("revoke_user_not_in_directory", func(t *testing.T) {
		// No directory installed (version 0): no change, still two sweeps.
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6, 7}, nil), revokeOK(first), revokeOK(answer(4, 11, 5, 6, 7)))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 0 || !strings.Contains(stdout, "alice is not in the installed directory, so no passkey login issues alice a certificate: no directory change.\n") ||
			!strings.Contains(stdout, "That is the server's word: it serves no directory, so nothing admin-signed shows what the signer holds. The signer's audit log is the proof") ||
			!strings.Contains(stdout, "alice is not in the installed directory (the server's word), and the KRL lists") ||
			!strings.Contains(stdout, "Serials: 5 6 7\n") || strings.Contains(stdout, "alice is disabled") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "revoke"}) {
			t.Fatalf("requests %v, want two revokes and no directory install", got)
		}
		requireNotSigned(t, e, 0)
	})
	t.Run("revoke_user_not_in_directory_second_sweep_not_listed", func(t *testing.T) {
		// The second answer reports serial 7, which the KRL lacks: a
		// partial result, exit 3, and no "is disabled" for a missing user.
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6}, nil), revokeOK(first), revokeOK(answer(4, 11, 5, 6, 7)))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 3 || !strings.Contains(stderr, "alice is not in the installed directory (the server's word), but the second revocation failed") ||
			!strings.Contains(stderr, "does not list serial 7") || !strings.Contains(stderr, "run keyroster revoke user alice again") ||
			strings.Contains(stdout, "the KRL lists every certificate") {
			t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 naming serial 7 and the re-run", code, stdout, stderr)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "revoke"}) {
			t.Fatalf("requests %v, want two revokes", got)
		}
	})
	t.Run("revoke_user_none_found", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, nil, nil), revokeOK(answer(3, 8)), revokeOK(answer(4, 11)))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 0 || !strings.Contains(stdout, "the server reports 0 certificate(s) revoked") || strings.Contains(stdout, "Serials:") ||
			!strings.Contains(stdout, "live certificates of alice in this signer's records; revoke a certificate issued elsewhere with keyroster revoke key.") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("revoke_user_quorum_proposal_pending", func(t *testing.T) {
		e := newDirEnv(t, 2, 2)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6}, nil), revokeOK(first), revokeOK(second))
		out := filepath.Join(t.TempDir(), "proposal")
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes", "--out", out)
		if code != 4 || !strings.Contains(stdout, "Serials: 5 6\n") || !strings.Contains(stdout, "Wrote proposal "+out) {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		for _, want := range []string{"revoked, disable pending", "alice can still obtain certificates until the proposal is installed",
			"run keyroster revoke user alice again after the proposal is installed"} {
			if !strings.Contains(stderr, want) {
				t.Fatalf("stderr %q lacks %q", stderr, want)
			}
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke"}) {
			t.Fatalf("requests %v, want one revoke, no install and no second revoke", got)
		}
	})
	t.Run("revoke_user_second_sweep_failed", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6}, nil), revokeOK(first), revokeRefusedAs(http.StatusForbidden, "request_time_skew"))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 3 || !strings.Contains(stderr, "alice is disabled, but the second revocation failed") ||
			!strings.Contains(stderr, "run keyroster revoke user alice again") || strings.Contains(stdout, "alice is disabled, and the KRL lists") {
			t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 naming the re-run", code, stdout, stderr)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "directory", "revoke"}) {
			t.Fatalf("requests %v, want revoke, directory, revoke", got)
		}
	})
	t.Run("revoke_user_revoke_failed_still_disables", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6}, nil), revokeRefusedAs(http.StatusForbidden, "request_time_skew"))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 1 || !strings.Contains(stderr, "nothing is reported revoked") || !strings.Contains(stderr, "run keyroster revoke user alice again") ||
			strings.Contains(stdout, "Serials:") || !strings.Contains(stdout, "~ user alice active -> disabled") {
			t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1, the disable sent and nothing reported revoked", code, stdout, stderr)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "directory"}) {
			t.Fatalf("requests %v, want revoke then the directory install", got)
		}
		if s := e.aliceStatus(t); s != directory.StatusDisabled {
			t.Fatalf("alice is %s, want disabled", s)
		}
	})
	t.Run("revoke_user_answer_truncated", func(t *testing.T) {
		serials := make([]uint64, wire.MaxRevokeAnswerSerials)
		for i := range serials {
			serials[i] = uint64(10 + 2*i) //nolint:gosec // G115: a small test index
		}
		ans := serverclient.RevokeAnswer{KRLVersion: 3, RevokeLeaf: 8, PublishLeaf: 9, SerialCount: 5000, Serials: serials}
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusDisabled)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, serials, nil), revokeOK(ans))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		if code != 0 || !strings.Contains(stdout, "the server reports 5000 certificate(s) revoked") ||
			!strings.Contains(stdout, "The answer lists 4096 of the 5000 serials; the rest are not listed in the answer, so the KRL check below does not cover them. "+
				"keyroster audit verify on a log exported on the signer host checks them all.") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("revoke_user_not_a_terminal_refused_before_revoking", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		e.serveRevokes(e.userKRLDoc(t, 4, 12, []uint64{5, 6}, nil), revokeOK(first))
		code, _, stderr := run(t, "revoke", "user", "alice")
		if code != 1 || !strings.Contains(stderr, "re-run with --yes. Nothing was revoked") || len(e.postCalls()) != 0 {
			t.Fatalf("exit %d, stderr %q, requests %v; want a refusal before any request", code, stderr, e.postCalls())
		}
	})
}

// TestRevokeKRLCheck (owner decision 2026-10-25, PR #58 review): every
// revoke command parses the KRL it verified and exits non-zero unless it
// lists every target the command revoked, whatever the server answered.
// Each KRL here is correctly signed by the bundle's ops key, at the
// reported version and log entry, issued now.
func TestRevokeKRLCheck(t *testing.T) {
	ok := serverclient.RevokeAnswer{KRLVersion: 3, RevokeLeaf: 8, PublishLeaf: 9}
	key := newRevokeKey(t)
	keyFile := filepath.Join(t.TempDir(), "id.pub")
	writeTestFile(t, keyFile, ssh.MarshalAuthorizedKey(key))
	const keyID = "kr1/ca=user/sub=u:x/ser=5"
	requireNotListed := func(t *testing.T, code int, stdout, stderr, what string) {
		t.Helper()
		if code == 0 || strings.Contains(stdout, "Checked: KRL v3 lists") || !strings.Contains(stderr, "could not be confirmed") ||
			!strings.Contains(stderr, "does not list "+what) || !strings.Contains(stderr, "(not listed)") ||
			!strings.Contains(stderr, "the revocation is not effective") || !strings.Contains(stderr, "the entry was pruned") ||
			!strings.Contains(stderr, "journalctl -u keyroster-signer") {
			t.Fatalf("exit %d, stdout %q, stderr %q; want a refusal: %s not listed, either cause named", code, stdout, stderr, what)
		}
	}
	t.Run("revoke_krl_lists_serial", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, []uint64{1729}, nil), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "serial", "1729")
		if code != 0 || !strings.Contains(stdout, "Checked: KRL v3 lists serial 1729 under a user CA key of your trust bundle, so it revokes that certificate.\n") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("revoke_krl_lacks_serial", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, []uint64{1730}, nil), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "serial", "1729")
		requireNotListed(t, code, stdout, stderr, "serial 1729 under a user CA key of your trust bundle")
	})
	t.Run("revoke_krl_lacks_serial_under_role", func(t *testing.T) {
		// Listed, but under the user CA, not the host CA the command named.
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, []uint64{1729}, nil), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "serial", "1729", "--ca", "host")
		requireNotListed(t, code, stdout, stderr, "serial 1729 under a host CA key of your trust bundle")
	})
	t.Run("revoke_key_id_listed", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, nil, []string{keyID}), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "key-id", keyID, "--ca", "user")
		if code != 0 || !strings.Contains(stdout, `The server reports key ID "`+keyID+`" (user) revoked: KRL v3 published (log entries 8, 9).`) ||
			!strings.Contains(stdout, `Checked: KRL v3 lists key ID "`+keyID+`" under a user CA key of your trust bundle`) {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		req := e.lastRevokeRequest(t)
		if req.Target != wire.TargetKeyID || req.KeyID != keyID || req.CARole != wire.CARoleUser || req.InstallationID != e.bundle.InstallationID {
			t.Fatalf("request %+v, want a v2 key-ID request for %q under the user CA", req, keyID)
		}
	})
	t.Run("revoke_krl_lacks_key_id", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, []uint64{5}, []string{"kr1/other"}), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "key-id", keyID)
		requireNotListed(t, code, stdout, stderr, `key ID "`+keyID+`" under a user CA key of your trust bundle`)
	})
	t.Run("revoke_key_listed", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, nil, nil, key), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "key", keyFile)
		fp := ssh.FingerprintSHA256(key)
		if code != 0 || !strings.Contains(stdout, "The server reports key "+fp+" revoked") ||
			!strings.Contains(stdout, "Checked: KRL v3 lists key "+fp+" as an explicit key") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if req := e.lastRevokeRequest(t); req.Target != wire.TargetKey || !bytes.Equal(req.Key, key.Marshal()) {
			t.Fatalf("request %+v, want a key request for %s", req, fp)
		}
	})
	t.Run("revoke_key_of_certificate_file", func(t *testing.T) {
		// A certificate file revokes the certificate's key, with a note.
		caSigner, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, 32)))
		if err != nil {
			t.Fatal(err)
		}
		c, err := cert.Build(cert.Request{
			Profile:    cert.DefaultUserProfile(),
			Subject:    key,
			Principals: []string{"alice"},
			Now:        time.Now(),
			ValidFor:   10 * time.Minute,
			KeyID:      cert.KeyID{CA: "user", Subject: "u:alice", Request: "0123456789abcdef0123456789abcdef", Serial: 1},
			Serial:     1,
		}, caSigner, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certFile := filepath.Join(t.TempDir(), "id-cert.pub")
		writeTestFile(t, certFile, ssh.MarshalAuthorizedKey(c))
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, nil, nil, key), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "key", certFile)
		if code != 0 || !strings.Contains(stdout, "Note: "+certFile+" holds a certificate; this revokes its key "+ssh.FingerprintSHA256(key)) {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if req := e.lastRevokeRequest(t); !bytes.Equal(req.Key, key.Marshal()) {
			t.Fatal("the request does not name the certificate's key")
		}
	})
	t.Run("revoke_krl_lacks_key", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, nil, nil, newRevokeKey(t)), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "key", keyFile)
		requireNotListed(t, code, stdout, stderr, "key "+ssh.FingerprintSHA256(key))
	})
	t.Run("revoke_user_krl_lacks_reported_serial", func(t *testing.T) {
		// The first sweep reports 5 and 6; the KRL lists only 5. The
		// sweep is not reported (exit 1), and the disable still runs.
		e := newDirEnv(t, 1, 1)
		e.installAlice(t, directory.StatusActive)
		ans := serverclient.RevokeAnswer{KRLVersion: 3, RevokeLeaf: 8, PublishLeaf: 9, SerialCount: 2, Serials: []uint64{5, 6}}
		e.serveRevokes(e.userKRLDoc(t, 3, 9, []uint64{5}, nil), revokeOK(ans))
		code, stdout, stderr := run(t, "revoke", "user", "alice", "--yes")
		requireNotListed(t, code, stdout, stderr, "serial 6, which the server's answer reports, under a user CA key of your trust bundle")
		if code != 1 || strings.Contains(stdout, "Serials:") || !strings.Contains(stderr, "nothing is reported revoked") {
			t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1 with nothing reported revoked", code, stdout, stderr)
		}
	})
	t.Run("revoke_krl_does_not_parse", func(t *testing.T) {
		// A correctly signed manifest over bytes krl.Parse refuses.
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.krlDocData(t, 3, 9, e.bundle.InstallationID, e.ops, time.Now(), []byte("SSHKRL\n\x00test krl")), revokeOK(ok))
		code, stdout, stderr := run(t, "revoke", "serial", "1729")
		if code == 0 || stdout != "" || !strings.Contains(stderr, "the KRL the server serves (v3) is signed but does not parse, so nothing in it is reported") {
			t.Fatalf("exit %d, stdout %q, stderr %q; want the parse refusal", code, stdout, stderr)
		}
	})
}

// hostKRLDoc is a served KRL document, version v at log entry logIndex,
// signed by the bundle's ops key and issued now, listing serials under the
// host CA key and keys explicitly.
func (e *dirEnv) hostKRLDoc(t *testing.T, v, logIndex uint64, serials []uint64, keys ...ssh.PublicKey) []byte {
	t.Helper()
	set := krl.Set{Keys: keys}
	if len(serials) > 0 {
		set.Certs = []krl.CertSection{{CAKey: e.caKey(t, trust.RoleHost), Serials: serials}}
	}
	return e.krlDocData(t, v, logIndex, e.bundle.InstallationID, e.ops, time.Now(), e.encodeKRL(t, v, set))
}

// hostRevokeEnv is a fake server with admins policy admins at quorum,
// whose directory version 1 holds host web1 (principal web1) with status
// and nkeys fresh host keys, returned sorted by trust.FormatKey string.
func hostRevokeEnv(t *testing.T, admins, quorum int, status string, nkeys int) (*dirEnv, []ssh.PublicKey) {
	t.Helper()
	e := newDirEnv(t, admins, quorum)
	var pubs []ssh.PublicKey
	for range nkeys {
		pubs = append(pubs, newRevokeKey(t))
	}
	slices.SortFunc(pubs, func(a, b ssh.PublicKey) int { return strings.Compare(trust.FormatKey(a), trust.FormatKey(b)) })
	var keys []string
	for _, p := range pubs {
		keys = append(keys, trust.FormatKey(p))
	}
	e.installDirect(t, buildDir(t, nil, boundTo(e.bundle.InstallationID, roleBase(t, func(d *directory.Directory) {
		d.Hosts = []directory.Host{{Name: "web1", HostGroup: "web", Keys: keys, Principals: []string{"web1"}, Status: status}}
	}))))
	return e, pubs
}

// recordRevokes answers the revocations in order with answers (the last
// one repeats), serves doc as the KRL, and returns a function that lists
// the requests received so far.
func (e *dirEnv) recordRevokes(t *testing.T, doc []byte, answers ...func(http.ResponseWriter)) func() []*wire.RevokeRequest {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	var reqs []*wire.RevokeRequest
	// Called with e.mu held (handle), after e.revokeBody is set.
	e.override["POST "+serverclient.AdminRevokePath] = func(w http.ResponseWriter) {
		var body serverclient.RevokeBody
		if err := json.Unmarshal(e.revokeBody, &body); err == nil {
			if req, err := wire.ParseRevokeRequest(body.Request); err == nil {
				reqs = append(reqs, req)
			}
		}
		answers[max(0, min(len(reqs)-1, len(answers)-1))](w)
	}
	e.override["GET "+serverclient.KRLPath] = func(w http.ResponseWriter) { _, _ = w.Write(doc) }
	return func() []*wire.RevokeRequest {
		e.mu.Lock()
		defer e.mu.Unlock()
		return slices.Clone(reqs)
	}
}

// keyRequests returns the keys of the TargetKey requests among reqs.
func keyRequests(reqs []*wire.RevokeRequest) [][]byte {
	var out [][]byte
	for _, r := range reqs {
		if r.Target == wire.TargetKey {
			out = append(out, r.Key)
		}
	}
	return out
}

// installFails makes the stub server refuse every directory install.
func (e *dirEnv) installFails() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.post = func(w http.ResponseWriter, _ serverclient.InstallDirectoryRequest) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"directory_quorum_not_met"}`)
	}
}

// TestRevokeHost (03-09b, D2, D3, REVOKE-01's host subject): keyroster
// revoke host against a stub server: the order revoke, directory,
// revoke; the exit codes (0 done, 1 first sweep or setup failed, 3
// partial, 4 pending; 3 beats 4, 1 beats both); --keys from the verified
// entry only, a refused key omitted while the next is tried; the hold
// text; the agent kept served; the recovery notice.
func TestRevokeHost(t *testing.T) {
	answer := func(v, leaf uint64, serials ...uint64) serverclient.RevokeAnswer {
		return serverclient.RevokeAnswer{KRLVersion: v, RevokeLeaf: leaf, PublishLeaf: leaf + 1, SerialCount: uint32(len(serials)), Serials: serials} //nolint:gosec // G115: a few test serials
	}
	first, second := answer(3, 8, 5, 6), answer(9, 20, 5, 6, 7)
	notice := recoveryKeptNotice + "\n"
	successLine := "The host's agent keeps receiving state, and this KRL, until keyroster host forget.\n"
	hostStatus := func(t *testing.T, e *dirEnv) string {
		t.Helper()
		doc, _ := e.installed()
		d, err := directory.Parse(doc)
		if err != nil {
			t.Fatal(err)
		}
		if h, ok := d.HostByName("web1"); ok {
			return h.Status
		}
		return ""
	}

	t.Run("order_sweep_disable_sweep", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		e.serveRevokes(e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "directory", "revoke"}) {
			t.Fatalf("requests %v, want revoke, directory, revoke", got)
		}
		for _, want := range []string{
			"First revocation of web1: the server reports 2 certificate(s) revoked: KRL v3 published (log entries 8, 9).\nSerials: 5 6\n",
			"under a host CA key of your trust bundle",
			"The server reports directory version 2 installed",
			"Second revocation (after the disable) of web1: the server reports 3 certificate(s) revoked: KRL v9 published (log entries 20, 21).\nSerials: 5 6 7\n",
			"web1 is disabled, and the KRL lists every certificate of web1 the server reported.",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout lacks %q:\n%s", want, stdout)
			}
		}
		if i, j, k := strings.Index(stdout, "First revocation"), strings.Index(stdout, "directory version 2 installed"), strings.Index(stdout, "Second revocation"); i > j || j > k {
			t.Fatalf("stdout is not in the order revoke, disable, revoke:\n%s", stdout)
		}
		if s := hostStatus(t, e); s != directory.StatusDisabled {
			t.Fatalf("web1 is %s, want disabled", s)
		}
	})
	t.Run("already_disabled_sweeps_twice_exit_0", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusDisabled, 1)
		e.serveRevokes(e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 0 || !strings.Contains(stdout, "Directory version 1, the admin-signed version the server serves, lists web1 as disabled: no directory change. "+
			"That is the server's word: the CLI checks the admins' signatures, not that the signer holds that version, and there is no host trust state of this installation, so no version floor was checked.\n") ||
			!strings.Contains(stdout, "Second revocation (after reading the directory) of web1") ||
			!strings.Contains(stdout, "Directory version 1 lists web1 as disabled (the server's word), and the KRL lists every certificate of web1 the server reported.") ||
			strings.Contains(stdout, "web1 is disabled") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "revoke"}) {
			t.Fatalf("requests %v, want revoke, revoke", got)
		}
		requireNotSigned(t, e, 0)
	})

	// The host trust floor (pre-merge review, 03-09b): a served directory
	// older than the version this user's host-trust.json holds, or an
	// equal version with another SHA-256, fails the directory step (exit
	// 3): nothing is reported disabled, no key is taken from the stale
	// entry, and nothing is signed.
	seedFloor := func(t *testing.T, e *dirEnv, install string, v uint64, sha string) {
		t.Helper()
		p, err := hostTrustStatePath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		writeSeedStateAt(t, p, &hostTrustState{Format: 1, InstallationID: install, BundleVersion: e.bundle.Version, OpsKey: e.bundle.OpsKey.Key,
			DirectoryVersion: v, DirectorySHA256: sha, KRLVersion: 1, Names: []string{"web1"}})
	}
	servedSHA := func(e *dirEnv) string {
		doc, _ := e.installed()
		return trust.SHA256Hex(doc)
	}
	for _, tc := range []struct {
		name, status, want string
		v                  uint64
		otherSHA           bool
	}{
		{"stale_directory_already_disabled_refused_exit_3", directory.StatusDisabled, "the server serves directory version 1, older than version 2, which your host trust files hold", 2, false},
		{"stale_directory_active_refused_exit_3", directory.StatusActive, "the server serves directory version 1, older than version 2, which your host trust files hold", 2, false},
		{"equal_version_other_sha_refused_exit_3", directory.StatusDisabled, "the server serves directory version 1 with another SHA-256 than the version 1 your host trust files hold", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := hostRevokeEnv(t, 1, 1, tc.status, 1)
			sha := servedSHA(e)
			if tc.otherSHA || tc.v != 1 {
				sha = strings.Repeat("ef", 32)
			}
			seedFloor(t, e, e.bundle.InstallationID, tc.v, sha)
			reqs := e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
			code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys")
			if code != 3 || !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "web1 is NOT disabled") ||
				!strings.Contains(stderr, "--keys: the verified directory could not be read") {
				t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
			}
			if strings.Contains(stdout, "lists web1 as disabled") || strings.Contains(stdout, "web1 is disabled") || strings.Contains(stdout, "Second revocation") {
				t.Fatalf("a stale directory was reported or swept after:\n%s", stdout)
			}
			if got := e.postCalls(); !slices.Equal(got, []string{"revoke"}) {
				t.Fatalf("requests %v, want the first revocation only", got)
			}
			if n := len(keyRequests(reqs())); n != 0 {
				t.Fatalf("%d key requests from a stale entry, want none", n)
			}
			requireNotSigned(t, e, 0)
		})
	}
	t.Run("floor_equal_version_same_sha_exit_0", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusDisabled, 1)
		seedFloor(t, e, e.bundle.InstallationID, 1, servedSHA(e))
		e.serveRevokes(e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 0 || !strings.Contains(stdout, "not that the signer holds that version, and it is not older than directory version 1, which your host trust files hold.\n") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("floor_of_another_installation_ignored", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusDisabled, 1)
		seedFloor(t, e, htInstall(t), 5, strings.Repeat("ef", 32))
		e.serveRevokes(e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 0 || !strings.Contains(stdout, "and there is no host trust state of this installation, so no version floor was checked.\n") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("unreadable_floor_warns", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusDisabled, 1)
		p, err := hostTrustStatePath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, p, []byte("not json"))
		e.serveRevokes(e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 0 || !strings.Contains(stderr, "is not checked against the version your host trust files hold") ||
			!strings.Contains(stdout, "and your host trust state could not be read (see the warning), so no version floor was checked.\n") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("no_directory_served_says_so_exit_3", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.serveRevokes(e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(first))
		code, stdout, stderr := run(t, "revoke", "host", "web9", "--yes")
		if code != 3 || !strings.Contains(stdout, "web9 is in no directory: the server serves none, so there is no entry to disable. "+
			"That is the server's word: nothing admin-signed shows what the signer holds, and there is no host trust state of this installation, so no version floor was checked.\n") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke"}) {
			t.Fatalf("requests %v, want one revoke and no directory install", got)
		}
	})
	t.Run("unknown_name_sweeps_warns_exit_3", func(t *testing.T) {
		for _, ans := range []serverclient.RevokeAnswer{first, answer(3, 8)} {
			e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
			e.serveRevokes(e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(ans))
			code, stdout, stderr := run(t, "revoke", "host", "web9", "--yes")
			if code != 3 || !strings.Contains(stdout, "web9 is not in directory version 1, the admin-signed version the server serves: there is no entry to disable. "+
				"That is the server's word: the CLI checks the admins' signatures, not that the signer holds that version, and there is no host trust state of this installation, so no version floor was checked.\n") ||
				!strings.Contains(stdout, "Its live certificates are revoked as reported above. If web9 was removed, its agent may still be enrolled and still receives state: end that with keyroster host forget.") {
				t.Fatalf("%d serials: exit %d, stderr %q, stdout:\n%s", ans.SerialCount, code, stderr, stdout)
			}
			if got := e.postCalls(); !slices.Equal(got, []string{"revoke"}) {
				t.Fatalf("requests %v, want one revoke and no directory install", got)
			}
		}
	})
	t.Run("unknown_name_keys_exit_3", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(first))
		code, _, stderr := run(t, "revoke", "host", "web9", "--yes", "--keys")
		if code != 3 || !strings.Contains(stderr, "web9 has no entry, so no host keys are known; revoke a key file with keyroster revoke key FILE") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if n := len(keyRequests(reqs())); n != 0 {
			t.Fatalf("%d key requests, want none", n)
		}
	})
	t.Run("proposal_exit_4_text_names_hold", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 2, 2, directory.StatusActive, 1)
		e.serveRevokes(e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(first))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes", "--out", filepath.Join(t.TempDir(), "p"))
		if code != 4 {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		for _, want := range []string{"Revoked, disable pending.", "cert_revoked", "ANY newer version releases that hold", "Once it is installed, run keyroster revoke host web1 again",
			"A host key with no certificate yet is not held"} {
			if !strings.Contains(stderr, want) {
				t.Fatalf("stderr lacks %q:\n%s", want, stderr)
			}
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke"}) {
			t.Fatalf("requests %v, want one revoke (no second sweep after a proposal)", got)
		}
	})
	t.Run("dir_error_exit_3", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		e.serveRevokes(e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(first))
		e.installFails()
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 3 || !strings.Contains(stderr, "web1 is NOT disabled") || !strings.Contains(stderr, "run keyroster revoke host web1 again") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "directory"}) {
			t.Fatalf("requests %v, want revoke, directory and no second sweep", got)
		}
	})
	t.Run("second_sweep_fails_exit_3", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		e.serveRevokes(e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(first), revokeRefusedAs(http.StatusForbidden, "request_time_skew"))
		code, _, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 3 || !strings.Contains(stderr, "the second revocation failed") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("first_sweep_fails_still_disables_exit_1", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 3, 9, nil), revokeRefusedAs(http.StatusForbidden, "request_time_skew"))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys")
		if code != 1 || !strings.Contains(stderr, "nothing is reported revoked") || !strings.Contains(stderr, "run keyroster revoke host web1 again") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := e.postCalls(); !slices.Equal(got, []string{"revoke", "directory"}) {
			t.Fatalf("requests %v, want revoke, directory (no key request, no second sweep)", got)
		}
		if len(keyRequests(reqs())) != 0 || hostStatus(t, e) != directory.StatusDisabled {
			t.Fatal("a key was requested, or web1 was not disabled")
		}
	})

	// --keys.
	t.Run("keys_one_request_per_entry_key", func(t *testing.T) {
		e, pubs := hostRevokeEnv(t, 1, 1, directory.StatusActive, 2)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}, pubs...),
			revokeOK(first), revokeOK(answer(4, 10)), revokeOK(answer(5, 12)), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		got := keyRequests(reqs())
		if len(got) != 2 || !bytes.Equal(got[0], pubs[0].Marshal()) || !bytes.Equal(got[1], pubs[1].Marshal()) {
			t.Fatalf("%d key requests, want the entry's two keys in FormatKey order", len(got))
		}
		if p := e.postCalls(); !slices.Equal(p, []string{"revoke", "directory", "revoke", "revoke", "revoke"}) {
			t.Fatalf("requests %v", p)
		}
		if !strings.Contains(stdout, "The server reports host key "+ssh.FingerprintSHA256(pubs[0])+" revoked as an explicit key") {
			t.Fatalf("stdout:\n%s", stdout)
		}
	})
	t.Run("keys_from_verified_entry_not_server", func(t *testing.T) {
		e, pubs := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		other := newRevokeKey(t)
		served, err := json.Marshal(serverclient.PendingHostsAnswer{Hosts: []serverclient.PendingHost{},
			Served: []serverclient.ServedHost{{PendingHost: serverclient.PendingHost{ExpectedName: "web1", HostKeys: []string{trust.FormatKey(other)}}, State: serverclient.HostStateDisabled}}})
		if err != nil {
			t.Fatal(err)
		}
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminPendingHostsPath, &called, string(served), http.StatusOK)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}, append(slices.Clone(pubs), other)...), revokeOK(first), revokeOK(answer(4, 10)), revokeOK(second))
		if code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys"); code != 0 {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := keyRequests(reqs()); len(got) != 1 || !bytes.Equal(got[0], pubs[0].Marshal()) {
			t.Fatalf("%d key requests, want exactly the verified entry's key", len(got))
		}
	})
	t.Run("keys_cap_revokes_serials_disables_sweeps_exit_3", func(t *testing.T) {
		e, pubs := hostRevokeEnv(t, 1, 1, directory.StatusActive, 2)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}, pubs[1]),
			revokeOK(first), revokeRefusedAs(http.StatusForbidden, "explicit_key_cap_reached"), revokeOK(answer(5, 12)), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys")
		if code != 3 || !strings.Contains(stderr, "host key "+ssh.FingerprintSHA256(pubs[0])+" was not revoked as an explicit key") || !strings.Contains(stderr, "explicit_key_cap_reached") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if got := keyRequests(reqs()); len(got) != 2 {
			t.Fatalf("%d key requests, want both keys tried", len(got))
		}
		if p := e.postCalls(); !slices.Equal(p, []string{"revoke", "directory", "revoke", "revoke", "revoke"}) || hostStatus(t, e) != directory.StatusDisabled {
			t.Fatalf("requests %v; want the disable installed and the second sweep sent", p)
		}
		if strings.Contains(stdout, successLine) {
			t.Fatal("full success reported with a key omitted")
		}
	})
	t.Run("keys_cap_with_proposal_prints_both_exit_3", func(t *testing.T) {
		e, pubs := hostRevokeEnv(t, 2, 2, directory.StatusActive, 1)
		e.recordRevokes(t, e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(first), revokeRefusedAs(http.StatusForbidden, "explicit_key_cap_reached"))
		code, _, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys", "--out", filepath.Join(t.TempDir(), "p"))
		if code != 3 || !strings.Contains(stderr, "Revoked, disable pending.") || !strings.Contains(stderr, "host key "+ssh.FingerprintSHA256(pubs[0])+" was not revoked") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("key_is_ca_omitted_exit_3", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeRefusedAs(http.StatusForbidden, "key_is_ca_of_this_installation"), revokeOK(second))
		code, _, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys")
		if code != 3 || !strings.Contains(stderr, "a key of this installation's trust bundle") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("no_keys_flag_no_key_requests", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 2)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 0 || len(keyRequests(reqs())) != 0 ||
			!strings.Contains(stdout, "No host key was revoked as an explicit key (use --keys for a compromised host key; explicit keys never leave the KRL).\n") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("keys_attempted_after_directory_error", func(t *testing.T) {
		e, pubs := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6}, pubs...), revokeOK(first), revokeOK(answer(4, 10)))
		e.installFails()
		code, _, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys")
		if code != 3 || len(keyRequests(reqs())) != 1 || !strings.Contains(stderr, "web1 is NOT disabled") {
			t.Fatalf("exit %d, %d key requests, stderr %q", code, len(keyRequests(reqs())), stderr)
		}
	})
	t.Run("keys_not_attempted_when_directory_unreadable", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		reqs := e.recordRevokes(t, e.hostKRLDoc(t, 3, 9, []uint64{5, 6}), revokeOK(first))
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminDirectoryPath, &called, `{"error":"boom"}`, http.StatusInternalServerError)
		code, _, stderr := run(t, "revoke", "host", "web1", "--yes", "--keys")
		if code != 3 || len(keyRequests(reqs())) != 0 || !strings.Contains(stderr, "revoke a key file with keyroster revoke key FILE") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})

	// The rest.
	t.Run("serials_checked_under_host_ca", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		e.serveRevokes(e.userKRLDoc(t, 3, 9, []uint64{5, 6}, nil), revokeOK(first))
		code, _, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 1 || !strings.Contains(stderr, "does not list serial 5, which the server's answer reports, under a host CA key of your trust bundle (not listed)") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("noninteractive_without_yes_refused", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		code, stdout, stderr := run(t, "revoke", "host", "web1")
		if code != 1 || !strings.Contains(stderr, "refusing to start") || len(e.postCalls()) != 0 || strings.Contains(stdout, "signer recovery kept") {
			t.Fatalf("exit %d, stdout %q, stderr %q, requests %v", code, stdout, stderr, e.postCalls())
		}
	})
	t.Run("usage_and_name_grammar", func(t *testing.T) {
		hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		for _, args := range [][]string{{"revoke", "host"}, {"revoke", "host", "a", "b"}, {"revoke", "host", "web1", "--bogus"}} {
			if code, stdout, _ := run(t, args...); code != 2 || strings.Contains(stdout, "signer recovery kept") {
				t.Fatalf("%q: exit %d, stdout %q; want 2 and no notice", args, code, stdout)
			}
		}
		if code, _, stderr := run(t, "revoke", "host", "Web_1!", "--yes"); code != 1 || !strings.Contains(stderr, `host name "Web_1!"`) {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("success_line_says_agent_keeps_state", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		e.serveRevokes(e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		code, stdout, stderr := run(t, "revoke", "host", "web1", "--yes")
		if code != 0 || !strings.Contains(stdout, successLine) {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		// The text a 403 prints is serverclient's "HTTP 403"; a bare "403" matches random hex.
		for _, no := range []string{"HTTP 403", "not_approved"} {
			if strings.Contains(stdout+stderr, no) {
				t.Fatalf("output names %q:\n%s%s", no, stdout, stderr)
			}
		}
	})
	t.Run("enforcement_text_for_host", func(t *testing.T) {
		e, _ := hostRevokeEnv(t, 1, 1, directory.StatusActive, 1)
		e.serveRevokes(e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), revokeOK(first), revokeOK(second))
		_, stdout, _ := run(t, "revoke", "host", "web1", "--yes")
		if !strings.Contains(stdout, revokeEnforcement(wire.CARoleHost)) || strings.Contains(stdout, "Hosts enforce") {
			t.Fatalf("stdout:\n%s", stdout)
		}
	})
	t.Run("recovery_kept_notice_printed", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			quorum  int
			args    []string
			answers []func(http.ResponseWriter)
			code    int
		}{
			{"exit_0", 1, nil, []func(http.ResponseWriter){revokeOK(first), revokeOK(second)}, 0},
			{"exit_1", 1, nil, []func(http.ResponseWriter){revokeRefusedAs(http.StatusForbidden, "request_time_skew")}, 1},
			{"exit_3", 1, []string{"--keys"}, []func(http.ResponseWriter){revokeOK(first), revokeRefusedAs(http.StatusForbidden, "explicit_key_cap_reached"), revokeOK(second)}, 3},
			{"exit_4", 2, []string{"--out", filepath.Join(t.TempDir(), "p")}, []func(http.ResponseWriter){revokeOK(first)}, 4},
		} {
			e, _ := hostRevokeEnv(t, 2, tc.quorum, directory.StatusActive, 1)
			e.recordRevokes(t, e.hostKRLDoc(t, 9, 21, []uint64{5, 6, 7}), tc.answers...)
			code, stdout, stderr := run(t, append([]string{"revoke", "host", "web1", "--yes"}, tc.args...)...)
			if code != tc.code || !strings.HasSuffix(stdout, notice) || strings.Count(stdout, notice) != 1 {
				t.Fatalf("%s: exit %d, stderr %q, stdout:\n%s; want exit %d ending with the notice", tc.name, code, stderr, stdout, tc.code)
			}
		}
	})
}
