package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// decoded renders leaf with Decode and returns the object.
func decoded(t *testing.T, leaf []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(Decode(leaf), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// loginIssueFixture returns a login_issue body for a fresh certificate
// whose WebAuthn evidence has 37 bytes of authenticator data with flags
// 0x05 (UP and UV), and the certificate.
func loginIssueFixture(t *testing.T) (*tlog.LoginIssueBody, *ssh.Certificate) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	kid := cert.KeyID{CA: "user", Subject: "alice", Request: "00112233445566778899aabbccddeeff", Policy: 2, Directory: 5, Roles: []string{"ops"}, Serial: 42}
	c, err := cert.Build(cert.Request{Profile: cert.DefaultUserProfile(), Subject: subject, Principals: []string{"role:ops"},
		Now: time.Now(), ValidFor: time.Hour, KeyID: kid, Serial: 42}, ca, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("keyroster.example"))
	authData := append(rp[:], 0x05, 0, 0, 0, 1)
	blob, err := (&wire.WebAuthnAssertion{CredentialID: []byte{1, 2, 3}, AuthenticatorData: authData, ClientDataJSON: []byte(`{}`), Signature: []byte{9}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &tlog.LoginIssueBody{
		Serial: 42, PolicyVersion: 2, DirectoryVersion: 5, Request: []byte("request signing bytes"),
		Evidence: []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}},
		Cert:     c.Marshal(), KeyID: c.KeyId,
	}, c
}

// leafOf encodes body as a leaf of kind.
func leafOf(t *testing.T, kind tlog.Kind, body []byte) []byte {
	t.Helper()
	leaf, err := tlog.MarshalLeaf(tlog.Leaf{Index: 3, TimeMicros: 1, Kind: kind, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// TestDecodeLoginIssue: the export's informational decoded field renders
// login_issue (kind 8) and directory_install (kind 7) leaves, degrading per
// field so a login's serial and key ID stay readable (02-14-F5/F13,
// 02-01-F5).
func TestDecodeLoginIssue(t *testing.T) {
	t.Run("login_issue", func(t *testing.T) {
		b, c := loginIssueFixture(t)
		body, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m := decoded(t, leafOf(t, tlog.KindLoginIssue, body))
		want := map[string]any{
			"kind": "login_issue", "serial": float64(42), "policy_version": float64(2), "directory_version": float64(5),
			"key_id": c.KeyId, "valid_after": float64(c.ValidAfter), "valid_before": float64(c.ValidBefore),
			"ca_fingerprint": ssh.FingerprintSHA256(c.SignatureKey), "ca_algorithm": c.SignatureKey.Type(),
			"key_fingerprint": ssh.FingerprintSHA256(c.Key), "authenticator_data_len": float64(37), "authenticator_flags": "05",
		}
		for k, v := range want {
			if m[k] != v {
				t.Fatalf("decoded %s = %v, want %v (all: %v)", k, m[k], v, m)
			}
		}
		if p, ok := m["principals"].([]any); !ok || len(p) != 1 || p[0] != "role:ops" {
			t.Fatalf("decoded principals = %v", m["principals"])
		}
		if e, ok := m["evidence_types"].([]any); !ok || len(e) != 1 || e[0] != wire.EvidenceWebAuthnAssertion {
			t.Fatalf("decoded evidence_types = %v", m["evidence_types"])
		}
	})
	t.Run("directory_install", func(t *testing.T) {
		body, err := (&tlog.DirectoryInstallBody{Version: 4, PolicyVersion: 2, Directory: []byte(`{"version":4}`), Sigs: []byte("sigs")}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		m := decoded(t, leafOf(t, tlog.KindDirectoryInstall, body))
		if m["kind"] != "directory_install" || m["version"] != float64(4) || m["policy_version"] != float64(2) {
			t.Fatalf("decoded = %v", m)
		}
		// The document and its signatures, as standard base64, for a
		// restore's replay (03-02).
		for field, want := range map[string]string{"directory": `{"version":4}`, "sigs": "sigs"} {
			s, _ := m[field].(string)
			got, err := base64.StdEncoding.DecodeString(s)
			if err != nil || string(got) != want {
				t.Fatalf("decoded %s = %q (%v), want base64 of %q", field, s, err, want)
			}
		}
	})
	t.Run("truncated_body_is_error", func(t *testing.T) {
		b, _ := loginIssueFixture(t)
		body, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m := decoded(t, leafOf(t, tlog.KindLoginIssue, body[:len(body)/2]))
		if _, ok := m["error"]; !ok || len(m) != 1 {
			t.Fatalf("decoded truncated body = %v, want only an error", m)
		}
	})
	t.Run("garbage_evidence_keeps_serial", func(t *testing.T) {
		b, c := loginIssueFixture(t)
		b.Evidence[0].Blob = []byte("garbage")
		body, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m := decoded(t, leafOf(t, tlog.KindLoginIssue, body))
		if m["serial"] != float64(42) || m["key_id"] != c.KeyId || m["key_fingerprint"] != ssh.FingerprintSHA256(c.Key) {
			t.Fatalf("decoded = %v, want the serial, key ID and key fingerprint kept", m)
		}
		if _, ok := m["authenticator_error"]; !ok {
			t.Fatalf("decoded = %v, want authenticator_error", m)
		}
		if _, ok := m["authenticator_data_len"]; ok {
			t.Fatalf("decoded = %v has authenticator data from a garbage blob", m)
		}
	})
	t.Run("garbage_cert_keeps_serial", func(t *testing.T) {
		b, _ := loginIssueFixture(t)
		b.Cert = []byte("not a certificate")
		body, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		m := decoded(t, leafOf(t, tlog.KindLoginIssue, body))
		if m["serial"] != float64(42) || m["authenticator_flags"] != "05" {
			t.Fatalf("decoded = %v, want the serial and the evidence fields kept", m)
		}
		if _, ok := m["cert_error"]; !ok {
			t.Fatalf("decoded = %v, want cert_error", m)
		}
	})
}
