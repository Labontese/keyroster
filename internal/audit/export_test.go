package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

// TestExportHostIssue: a host_issue line names the certificate and the
// request, under no key Verify binds to another kind (03-09).
func TestExportHostIssue(t *testing.T) {
	hf := newHostFixture(t, 90)
	h := hf.addHost(hf.key, nil, nil, nil)
	m := decoded(t, hf.leaves[len(hf.leaves)-1])
	for _, k := range []string{"kind", "serial", "policy_version", "directory_version", "key_id", "host_name", "host_key_fingerprint",
		"principals", "valid_after", "valid_before", "ca_fingerprint", "evidence_types"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the host_issue line has no %q: %v", k, m)
		}
	}
	for _, k := range []string{"version", "bundle_version", "directory", "sigs"} {
		if _, ok := m[k]; ok {
			t.Errorf("the host_issue line carries %q", k)
		}
	}
	if m["kind"] != "host_issue" || m["host_name"] != "web1" || m["host_key_fingerprint"] != ssh.FingerprintSHA256(hf.key.PublicKey()) || m["key_id"] != h.cert.KeyId {
		t.Fatalf("the host_issue line: %v", m)
	}
	if _, err := hf.verifyHosts(); err != nil {
		t.Fatalf("Verify of the export: %v", err)
	}
	// Every decoded field of a host_issue line is bound to its leaf: the
	// runbook takes a host's serials, name and key fingerprints from them.
	in := join(hf.lines())
	for _, mut := range [][2]string{
		{`"host_name":"web1"`, `"host_name":"db01"`},
		{`"host_key_fingerprint":"` + ssh.FingerprintSHA256(hf.key.PublicKey()) + `"`, `"host_key_fingerprint":"SHA256:x"`},
		{`"kind":"host_issue",`, `"kind":"host_issue","note":"x",`},
	} {
		if !strings.Contains(in, mut[0]) {
			t.Fatalf("the export holds no %s", mut[0])
		}
		if _, err := hf.verify(strings.Replace(in, mut[0], mut[1], 1), nil); err == nil || !strings.Contains(err.Error(), "host_issue leaf") {
			t.Errorf("a host_issue line with %s: %v, want it refused", mut[1], err)
		}
	}
}

// TestExportKeysLowercase (03-14c; PR #75 review): every key the export's
// decoders write is lowercase ASCII letters, digits and underscores, which
// Verify's charset rule requires of every line. The gate is syntactic: in
// the bodies of Decode, decodeLeaf and every function whose name starts
// with "decode", in the non-test files of this package, each string
// literal written as a map index (an index of an identifier the function
// declares with a map type) or as a map composite literal's key must match,
// and any other such key fails, except the one recorded site
// counts[tlog.ReasonName(c.Reason)], whose names are checked instead. A
// data-derived key needs its own charset proof or an allowlist entry here.
// Verification bookkeeping maps elsewhere in the package never reach an
// export line and are out of scope.
func TestExportKeysLowercase(t *testing.T) {
	const allowed = "counts[tlog.ReasonName(c.Reason)]"
	lower := regexp.MustCompile(`^[a-z0-9_]+$`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	keys, found := map[string]bool{}, map[string]bool{}
	allowedSeen := false
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || (fd.Name.Name != "Decode" && !strings.HasPrefix(fd.Name.Name, "decode")) {
				continue
			}
			found[fd.Name.Name] = true
			mapVars := mapIdents(fd)
			check := func(at ast.Node, key ast.Expr, site string) {
				if lit, ok := key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					k, err := strconv.Unquote(lit.Value)
					if err != nil || !lower.MatchString(k) {
						t.Errorf("%s: %s writes the key %s, which is not lowercase ASCII letters, digits and underscores", fset.Position(at.Pos()), fd.Name.Name, lit.Value)
					}
					keys[k] = true
					return
				}
				if site == allowed {
					allowedSeen = true
					return
				}
				t.Errorf("%s: %s writes the map key %s, which is not a string literal: a data-derived key needs its own charset proof or an allowlist entry in this test",
					fset.Position(at.Pos()), fd.Name.Name, types.ExprString(key))
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range n.Lhs {
						if ix, ok := lhs.(*ast.IndexExpr); ok {
							if id, ok := ix.X.(*ast.Ident); ok && mapVars[id.Name] {
								check(ix, ix.Index, types.ExprString(ix))
							}
						}
					}
				case *ast.CompositeLit:
					if _, ok := n.Type.(*ast.MapType); ok {
						for _, el := range n.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								check(kv, kv.Key, "")
							}
						}
					}
				}
				return true
			})
		}
	}
	if !allowedSeen {
		t.Errorf("the recorded site %s was not found: update this test's allowlist", allowed)
	}
	for i := range 256 {
		r := uint8(i) //nolint:gosec // G115: i < 256
		if tlog.ValidReason(r) && !lower.MatchString(tlog.ReasonName(r)) {
			t.Errorf("reason %d is named %q, which is not lowercase ASCII letters, digits and underscores", r, tlog.ReasonName(r))
		}
	}
	for _, k := range []string{"kind", "policy_version", "directory", "admin_fingerprints"} {
		if !keys[k] {
			t.Errorf("the decoders write no %q key: the scope matches nothing it should", k)
		}
	}
	for _, fn := range []string{"decodeLeaf", "decodeRevoke", "decodeRecovery", "decodeHostForget", "decodeLoginIssue", "decodeHostIssue", "decodeMachineIssue", "decodeProbeIssue"} {
		if !found[fn] {
			t.Errorf("no function %s found: the scope matches nothing it should", fn)
		}
	}
}

// mapIdents is the identifiers fd declares with a map type: a map-typed
// parameter, a variable declared with a map type, or one assigned a map
// composite literal or make(map[...]).
func mapIdents(fd *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	isMap := func(e ast.Expr) bool {
		switch e := e.(type) {
		case *ast.MapType:
			return true
		case *ast.CompositeLit:
			_, ok := e.Type.(*ast.MapType)
			return ok
		case *ast.CallExpr:
			if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "make" && len(e.Args) > 0 {
				_, ok := e.Args[0].(*ast.MapType)
				return ok
			}
		}
		return false
	}
	for _, p := range fd.Type.Params.List {
		if isMap(p.Type) {
			for _, n := range p.Names {
				out[n.Name] = true
			}
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for i, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && i < len(n.Rhs) && isMap(n.Rhs[i]) {
						out[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if (n.Type != nil && isMap(n.Type)) || (i < len(n.Values) && isMap(n.Values[i])) {
					out[id.Name] = true
				}
			}
		}
		return true
	})
	return out
}
