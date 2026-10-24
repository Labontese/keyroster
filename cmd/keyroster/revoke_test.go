package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// krlDoc returns a served KRL document of version v whose manifest names
// logIndex and installation, signed by signer under krl.Namespace.
func (e *dirEnv) krlDoc(t *testing.T, v, logIndex uint64, installation string, signer ssh.Signer) []byte {
	t.Helper()
	data := []byte("SSHKRL\n\x00test krl")
	m := krl.Manifest{
		InstallationID: installation,
		KRLVersion:     v,
		KRLSHA256:      krl.SHA256Hex(data),
		IssuedAt:       time.Now().UTC().Truncate(time.Second).Format(trust.TimeFormat),
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
	for _, tc := range []struct {
		name, status, body, want string
	}{
		{"unknown_serial", "403", `{"error":"unknown_serial"}`, "the signer has issued no certificate with this serial; nothing was revoked"},
		{"ca_role_mismatch", "403", `{"error":"ca_role_mismatch"}`, "was not issued by that CA; pass the right --ca; nothing was revoked"},
		{"duplicate_request", "403", `{"error":"duplicate_request"}`, "the signer has already accepted a request with this ID"},
		{"other_signer_refusal", "403", `{"error":"request_time_skew"}`, "the signer refused the revocation; nothing was revoked"},
		{"signer_unavailable", "503", `{"error":"signer unavailable"}`, "The signer's log names the reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDirEnv(t, 1, 1)
			e.mu.Lock()
			e.override["POST "+serverclient.AdminRevokePath] = func(w http.ResponseWriter) {
				code := http.StatusForbidden
				if tc.status == "503" {
					code = http.StatusServiceUnavailable
				}
				w.WriteHeader(code)
				_, _ = io.WriteString(w, tc.body)
			}
			e.mu.Unlock()
			code, stdout, stderr := run(t, "revoke", "serial", "1729")
			if code == 0 || stdout != "" || !strings.Contains(stderr, tc.want) || strings.Contains(stderr, "is --admin-key a policy admin") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want %q", code, stdout, stderr, tc.want)
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
			"Checked: the server serves KRL v3, signed by the ops key of your root-pinned trust bundle (log entry 9).\n",
			"Not checked: that this KRL lists serial 1729",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout %q lacks %q", stdout, want)
			}
		}
		if strings.HasPrefix(stdout, "revoked serial") {
			t.Fatalf("stdout %q states the revocation as a fact", stdout)
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
			"host":    "A host certificate is checked by SSH clients, not by sshd: the revocation takes effect only on clients whose RevokedHostKeys file holds this KRL.",
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
