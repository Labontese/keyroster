package audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// forgetFixture is a revokeFixture whose policy has two admins, alice (the
// fixture admin) and bob, at admin quorum quorum, with two directory
// versions installed and signed by both: v1 holds web1 (active, key
// removed) and web2 (disabled, key held), v2 holds web2 only (03-08c).
type forgetFixture struct {
	*revokeFixture
	bob           ssh.Signer
	pol           *trust.Policy
	removed, held ssh.PublicKey
	docs          [][]byte // the installed directory documents, by version - 1
}

// newForgetFixture builds the log under root (nil: a new one).
func newForgetFixture(t testing.TB, quorum uint32, root ssh.Signer) *forgetFixture {
	t.Helper()
	f := newBareFixtureAt(t, "ed25519", time.Now().Truncate(time.Second))
	if root != nil {
		f.root = root
	}
	ff := &forgetFixture{revokeFixture: &revokeFixture{fixture: f}, bob: newSigner(t, "ed25519"),
		removed: newSigner(t, "ed25519").PublicKey(), held: newSigner(t, "ed25519").PublicKey()}
	ff.pol = f.policy()
	ff.pol.AdminQuorum = quorum
	ff.pol.Admins = append(ff.pol.Admins, trust.AdminKey{Name: "bob", Key: trust.FormatKey(ff.bob.PublicKey())})
	g := f.genesis()
	g.InstallationID = auditInstallationID
	f.addBundle(f.signDocs(g, ff.pol, f.root))
	web1 := directory.Host{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(ff.removed)}, Principals: []string{"web1"}, Status: directory.StatusActive}
	web2 := directory.Host{Name: "web2", HostGroup: "lab", Keys: []string{trust.FormatKey(ff.held)}, Principals: []string{"web2"}, Status: directory.StatusDisabled}
	prev := trust.GenesisPrev
	for v, hosts := range [][]directory.Host{{web1, web2}, {web2}} {
		d := &directory.Directory{
			Version: uint64(v + 1), Prev: prev, InstallationID: auditInstallationID,
			Roles:      []directory.Role{{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600}},
			HostGroups: []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}},
			Hosts:      hosts,
		}
		d.Sort()
		doc, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		var sigs []byte
		for _, s := range []ssh.Signer{f.admin, ff.bob} {
			sig, err := sshsig.Sign(rand.Reader, s, directory.Namespace, doc)
			if err != nil {
				t.Fatal(err)
			}
			sigs = append(sigs, sig...)
		}
		body, err := (&tlog.DirectoryInstallBody{Version: d.Version, PolicyVersion: 1, Directory: doc, Sigs: sigs}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		f.add(tlog.KindDirectoryInstall, body)
		ff.docs = append(ff.docs, doc)
		prev = trust.SHA256Hex(doc)
	}
	return ff
}

// request is a forget of the agent with host key removed, approved once,
// removed and confirmed at v2 with v2's document, created at the next
// leaf's whole seconds.
func (ff *forgetFixture) request() *wire.ForgetRequest {
	ff.t.Helper()
	req := &wire.ForgetRequest{InstallationID: auditInstallationID, ExpectedName: "web1", EnrolledAtMicros: 1_790_000_000_000_000,
		HostKeyFingerprints: [][32]byte{wire.HostKeyDigest(ff.removed)}, ApprovedOnce: true, RemovalVersion: 2, ConfirmedVersion: 2,
		ConfirmedSHA256: sha256.Sum256(ff.docs[1]), CreatedAt: ff.secs()}
	if _, err := rand.Read(req.AgentIdentity[:]); err != nil {
		ff.t.Fatal(err)
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		ff.t.Fatal(err)
	}
	return req
}

// forget logs a host_forget entry for req as the signer writes one: the
// policy and directory versions in force, resolved at the next leaf's
// whole seconds, the request's signing bytes and an admin-sshsig/v1 item
// by each signer (default alice and bob) under the forget namespace; edit
// (optional) changes the body after signing.
func (ff *forgetFixture) forget(req *wire.ForgetRequest, edit func(*tlog.HostForgetBody), signers ...ssh.Signer) {
	ff.t.Helper()
	if len(signers) == 0 {
		signers = []ssh.Signer{ff.admin, ff.bob}
	}
	b := &tlog.HostForgetBody{PolicyVersion: 1, DirectoryVersion: 2, ResolvedAtSeconds: ff.secs(), Request: req.SigningBytes()}
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, wire.ForgetSSHSIGNamespace, req.SigningBytes())
		if err != nil {
			ff.t.Fatal(err)
		}
		b.Evidence = append(b.Evidence, wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig})
	}
	if edit != nil {
		edit(b)
	}
	body, err := b.Encode()
	if err != nil {
		ff.t.Fatal(err)
	}
	ff.add(tlog.KindHostForget, body)
}

// TestVerifyHostForget (03-08c) checks every host_forget entry with the
// signer's rules, from the log alone: the installation, owner decision
// Q3's signature count over the exact signing bytes under the forget
// namespace, the policy and directory versions in force, the resolution
// time, an unused request ID, no host key the directory in force holds,
// and a confirmation of a logged directory at or below the one in force.
func TestVerifyHostForget(t *testing.T) {
	wantOK := func(t *testing.T, ff *forgetFixture) {
		t.Helper()
		rep, err := ff.verifyAll()
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if rep.Counts[tlog.KindHostForget] != 1 {
			t.Fatalf("host_forget entries %d, want 1", rep.Counts[tlog.KindHostForget])
		}
	}
	wantFail := func(t *testing.T, ff *forgetFixture, want string) {
		t.Helper()
		_, err := ff.verifyAll()
		if err == nil || !strings.Contains(err.Error(), "(host_forget)") || !strings.Contains(err.Error(), want) {
			t.Fatalf("Verify = %v, want a host_forget failure naming %q", err, want)
		}
	}
	t.Run("valid_passes", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		ff.forget(ff.request(), nil)
		wantOK(t, ff)
	})
	t.Run("never_approved_one_signature_passes", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		req.ApprovedOnce, req.RemovalVersion, req.ConfirmedVersion, req.ConfirmedSHA256 = false, 0, 0, [32]byte{}
		ff.forget(req, nil, ff.bob)
		wantOK(t, ff)
	})
	t.Run("approved_once_one_signature_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		ff.forget(ff.request(), nil, ff.admin)
		wantFail(t, ff, "admin_quorum_not_met")
	})
	t.Run("same_admin_twice_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		ff.forget(ff.request(), nil, ff.admin, ff.admin)
		wantFail(t, ff, "admin_quorum_not_met")
	})
	t.Run("quorum_1_one_signature_passes", func(t *testing.T) {
		ff := newForgetFixture(t, 1, nil)
		ff.forget(ff.request(), nil, ff.bob)
		wantOK(t, ff)
	})
	t.Run("wrong_namespace_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		ff.forget(req, func(b *tlog.HostForgetBody) {
			for i, s := range []ssh.Signer{ff.admin, ff.bob} {
				sig, err := sshsig.Sign(rand.Reader, s, wire.RevokeSSHSIGNamespace, req.SigningBytes())
				if err != nil {
					t.Fatal(err)
				}
				b.Evidence[i].Blob = sig
			}
		})
		wantFail(t, ff, "does not approve the logged request")
	})
	t.Run("wrong_installation_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		req.InstallationID = "ffeeddccbbaa99887766554433221100"
		ff.forget(req, nil)
		wantFail(t, ff, "forget_installation_mismatch")
	})
	t.Run("policy_version_mismatch_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		ff.forget(ff.request(), func(b *tlog.HostForgetBody) { b.PolicyVersion = 2 })
		wantFail(t, ff, "policy version 2")
	})
	t.Run("directory_version_mismatch_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		ff.forget(ff.request(), func(b *tlog.HostForgetBody) { b.DirectoryVersion = 1 })
		wantFail(t, ff, "directory version 1")
	})
	t.Run("host_key_in_directory_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		req.HostKeyFingerprints = append(req.HostKeyFingerprints, wire.HostKeyDigest(ff.held))
		slices.SortFunc(req.HostKeyFingerprints, func(x, y [32]byte) int { return bytes.Compare(x[:], y[:]) })
		ff.forget(req, nil)
		wantFail(t, ff, "forget_host_in_directory")
	})
	t.Run("confirmed_above_directory_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		req.ConfirmedVersion = 3
		ff.forget(req, nil)
		wantFail(t, ff, "forget_confirmation_invalid")
	})
	t.Run("confirmed_sha_not_logged_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		req.ConfirmedSHA256 = sha256.Sum256(ff.docs[0]) // v1's document at v2
		ff.forget(req, nil)
		wantFail(t, ff, "forget_confirmation_invalid")
	})
	t.Run("confirmed_older_logged_version_passes", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		req.RemovalVersion, req.ConfirmedVersion, req.ConfirmedSHA256 = 1, 1, sha256.Sum256(ff.docs[0])
		ff.forget(req, nil)
		wantOK(t, ff)
	})
	t.Run("request_id_reused_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		c := ff.issue()
		rev := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}
		ff.revoke(rev, []tlog.RevokedEntry{serialEntry(c)}, nil)
		ff.publish(nil)
		req := ff.request()
		req.RequestID = rev.RequestID
		ff.forget(req, nil)
		wantFail(t, ff, "replayed")
	})
	t.Run("request_id_reused_by_a_forget_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		ff.forget(req, nil)
		ff.forget(req, nil)
		wantFail(t, ff, "replayed")
	})
	t.Run("resolved_after_leaf_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		ff.forget(ff.request(), func(b *tlog.HostForgetBody) { b.ResolvedAtSeconds++ })
		wantFail(t, ff, "after the leaf time")
	})
	t.Run("created_skew_fails", func(t *testing.T) {
		ff := newForgetFixture(t, 2, nil)
		req := ff.request()
		req.CreatedAt -= 301
		ff.forget(req, nil)
		wantFail(t, ff, "accepts at most 300 s")
		ff = newForgetFixture(t, 2, nil)
		req = ff.request()
		req.CreatedAt -= 300
		ff.forget(req, nil)
		wantOK(t, ff)
	})
	t.Run("confirmed_sha_matches_the_heartbeat_basis", func(t *testing.T) {
		// Plan check item 8: the confirmation is the {version, sha256} a
		// heartbeat carries for the directory the agent stored, the
		// document served without signatures (apply/status.go hashes it
		// with trust.SHA256Hex). Audit's map over the logged
		// DirectoryInstallBody.Directory gives the same value, and the
		// entry verifies.
		ff := newForgetFixture(t, 2, nil)
		doc := heartbeat.Doc{Version: 2, SHA256: trust.SHA256Hex(ff.docs[1])}
		sum, err := hex.DecodeString(doc.SHA256)
		if err != nil || len(sum) != 32 {
			t.Fatal(err)
		}
		req := ff.request()
		req.ConfirmedVersion, req.ConfirmedSHA256 = doc.Version, [32]byte(sum)
		ff.forget(req, nil)
		wantOK(t, ff)
		var ds directoryInForce
		a := &anchor{}
		a.policy, a.bundle = ff.pol, &trust.Bundle{InstallationID: auditInstallationID}
		for _, raw := range ff.leaves {
			l, err := tlog.DecodeLeaf(raw)
			if err != nil || l.Kind != tlog.KindDirectoryInstall {
				continue
			}
			b, err := tlog.DecodeDirectoryInstallBody(l.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := ds.install(b, a); err != nil {
				t.Fatal(err)
			}
		}
		if got := ds.shas[2]; hex.EncodeToString(got[:]) != doc.SHA256 {
			t.Fatalf("audit's SHA-256 of directory v2 %x, the heartbeat's %s", got, doc.SHA256)
		}
	})
}

// TestExportHostForget (03-08c): the export renders a host_forget entry
// with the agent, the signed facts, the versions in force and the sorted
// fingerprints of the keys that signed, and no key of its own that Verify
// binds to another kind; Verify refuses a line whose rendered approved_once
// or host_gone was edited.
func TestExportHostForget(t *testing.T) {
	ff := newForgetFixture(t, 2, nil)
	req := ff.request()
	ff.forget(req, nil)
	lines := ff.lines()
	i := len(lines) - 2 // the host_forget line, before the checkpoint
	var line ExportLine
	if err := json.Unmarshal([]byte(lines[i]), &line); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(line.Decoded, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"identity", "expected_name", "host_key_fingerprints", "approved_once", "host_gone", "removal_version",
		"confirmed_version", "confirmed_sha256", "policy_version", "directory_version", "evidence_types", "admin_fingerprints",
		"enrolled_at_us", "request_id", "created_at", "resolved_at"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the export line lacks %q: %s", k, line.Decoded)
		}
	}
	for _, k := range []string{"bundle_version", "version", "directory", "sigs"} {
		if _, ok := m[k]; ok {
			t.Errorf("the export line has %q: %s", k, line.Decoded)
		}
	}
	if m["kind"] != "host_forget" || m["approved_once"] != true || m["host_gone"] != false || m["expected_name"] != "web1" ||
		m["confirmed_sha256"] != hex.EncodeToString(req.ConfirmedSHA256[:]) || m["confirmed_version"] != float64(2) ||
		m["identity"] != "SHA256:"+base64.RawStdEncoding.EncodeToString(req.AgentIdentity[:]) {
		t.Errorf("the export line %s", line.Decoded)
	}
	want := []any{ssh.FingerprintSHA256(ff.admin.PublicKey()), ssh.FingerprintSHA256(ff.bob.PublicKey())}
	slices.SortFunc(want, func(x, y any) int { return strings.Compare(x.(string), y.(string)) })
	if got, ok := m["admin_fingerprints"].([]any); !ok || !slices.Equal(got, want) {
		t.Errorf("admin_fingerprints %v, want %v sorted", m["admin_fingerprints"], want)
	}
	if fps, ok := m["host_key_fingerprints"].([]any); !ok || len(fps) != 1 || fps[0] != ssh.FingerprintSHA256(ff.removed) {
		t.Errorf("host_key_fingerprints %v, want %s", m["host_key_fingerprints"], ssh.FingerprintSHA256(ff.removed))
	}
	if _, err := ff.verify(join(lines), nil); err != nil {
		t.Fatalf("the export does not verify: %v", err)
	}
	// PR #75 review, owner decision D-1: verify binds every decoded field
	// of a host_forget line to its leaf. An unedited round trip verifies;
	// each field changed, each field removed, an added field, a duplicated
	// key and a re-encoded line are refused.
	if _, err := ff.verify(join(editDecodedLine(t, lines, i, func(map[string]any) {})), nil); err != nil {
		t.Fatalf("the host_forget line re-encoded unchanged does not verify: %v", err)
	}
	refused := func(what string, l []string) {
		t.Helper()
		if _, err := ff.verify(join(l), nil); err == nil || !strings.Contains(err.Error(), "host_forget") {
			t.Errorf("a host_forget line with %s verifies: %v", what, err)
		}
	}
	for k, v := range m {
		var changed any
		switch v := v.(type) {
		case string:
			changed = v + "0"
		case float64:
			changed = v + 1
		case bool:
			changed = !v
		case []any:
			changed = append(slices.Clone(v), "SHA256:mallory")
		default:
			t.Fatalf("decoded field %q has an unexpected type %T", k, v)
		}
		refused(k+" changed", editDecodedLine(t, lines, i, func(m map[string]any) { m[k] = changed }))
		refused(k+" removed", editDecodedLine(t, lines, i, func(m map[string]any) { delete(m, k) }))
	}
	refused("the admins swapped for another", editDecodedLine(t, lines, i, func(m map[string]any) { m["admin_fingerprints"] = []any{"SHA256:mallory"} }))
	refused("an added field", editDecodedLine(t, lines, i, func(m map[string]any) { m["note"] = "authorized" }))
	other := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	dup := strings.Replace(lines[i], `"decoded":{`, `"decoded":{"identity":"`+other+`",`, 1)
	refused("a duplicated key", append(append(slices.Clone(lines[:i]), dup), lines[i+1:]...))
	dupObj := strings.TrimSuffix(lines[i], "}") + `,"decoded":` + string(line.Decoded) + "}"
	dupObj = strings.Replace(dupObj, `"decoded":{"admin_fingerprints":[`, `"decoded":{"admin_fingerprints":["SHA256:mallory",`, 1)
	refused("a duplicated decoded object", append(append(slices.Clone(lines[:i]), dupObj), lines[i+1:]...))
	refused("extra white space", append(append(slices.Clone(lines[:i]), strings.Replace(lines[i], `,"decoded":`, `, "decoded":`, 1)), lines[i+1:]...))
	// Neither key on a line of another kind.
	if _, err := ff.verify(join(editDecodedLine(t, lines, 0, func(m map[string]any) { m["host_gone"] = false })), nil); err == nil {
		t.Error("a bundle_install line with host_gone verifies")
	}
}

// TestVerifyForgetKeysOnOtherKinds (PR #75 review, fix round 2): a reader
// that parses an export line as JSON (jq, Python, Go) keeps the last of
// repeated keys and unescapes them, so verify binds what such a reader
// sees, not only the raw bytes. Host V's forget is forged on a line of
// another kind: with an escaped or spaced duplicate "kind" key, an escaped
// duplicate "decoded" object, or only a host_forget key. Each is refused,
// and the unedited export still verifies. The last four cases each reach
// one check only: the parsed kind, a repeated key that is not "kind", a
// host_forget-only key, and a top-level key in another case.
func TestVerifyForgetKeysOnOtherKinds(t *testing.T) {
	ff := newForgetFixture(t, 2, nil)
	all := ff.lines() // bundle_install, directory_install v1, v2, checkpoint
	var v [32]byte
	if _, err := rand.Read(v[:]); err != nil {
		t.Fatal(err)
	}
	identity := "SHA256:" + base64.RawStdEncoding.EncodeToString(v[:])
	fps := `"` + ssh.FingerprintSHA256(ff.admin.PublicKey()) + `","` + ssh.FingerprintSHA256(ff.bob.PublicKey()) + `"`
	forged := `"identity":"` + identity + `","admin_fingerprints":[` + fps + `]`
	// inject appends frag to the decoded object of line i.
	inject := func(i int, frag string) []string {
		t.Helper()
		if !strings.HasSuffix(all[i], "}}") {
			t.Fatalf("line %d does not end with its decoded object", i)
		}
		l := slices.Clone(all)
		l[i] = strings.TrimSuffix(l[i], "}}") + frag + "}}"
		return l
	}
	raw := func(i int, old, repl string) []string {
		t.Helper()
		if !strings.Contains(all[i], old) {
			t.Fatalf("line %d has no %s", i, old)
		}
		l := slices.Clone(all)
		l[i] = strings.Replace(l[i], old, repl, 1)
		return l
	}
	decodedOf := func(i int) string {
		t.Helper()
		var line ExportLine
		if err := json.Unmarshal([]byte(all[i]), &line); err != nil {
			t.Fatal(err)
		}
		return string(line.Decoded)
	}
	cases := []struct {
		name  string
		lines []string
		want  string // "" = must verify
	}{
		{"as_exported_ok", all, ""},
		{"escaped_kind_on_bundle_install_refused", inject(0, `,"\u006bind":"host_forget",`+forged), `its key "kind" occurs twice in one object (bundle_install)`},
		{"escaped_kind_on_directory_install_refused", inject(1, `,"\u006bind":"host_forget",`+forged), `its key "kind" occurs twice in one object (directory_install)`},
		{"spaced_duplicate_kind_refused", inject(0, `,"kind" : "host_forget",`+forged), `its key "kind" occurs twice in one object (bundle_install)`},
		{"escaped_duplicate_decoded_refused", inject(0, `},"d\u0065coded":{"\u006bind":"host_forget",`+forged), `its key "decoded" occurs twice in one object (bundle_install)`},
		{"identity_on_bundle_install_refused", inject(0, `,"identity":"`+identity+`"`), "its decoded identity field is not one of a host_forget leaf (bundle_install)"},
		{"escaped_identity_on_directory_install_refused", inject(1, `,"\u0069dentity":"`+identity+`"`), "its decoded identity field is not one of a host_forget leaf (directory_install)"},
		{"kind_only_refused", raw(0, `"kind":"bundle_install"`, `"\u006bind":"host_forget","x":{"kind":"bundle_install"}`), "its decoded kind is not the kind of its leaf (bundle_install)"},
		{"duplicate_only_refused", inject(0, `,"\u0062undle_version":1`), `its key "bundle_version" occurs twice in one object (bundle_install)`},
		{"forget_key_only_refused", inject(0, `,"admin_fingerprints":[`+fps+`]`), "its decoded admin_fingerprints field is not one of a host_forget leaf (bundle_install)"},
		{"top_level_case_only_refused", raw(0, `,"decoded":`, `,"Decoded":{"x":1},"decoded":`), `its key "Decoded" is not one export writes (bundle_install)`},
		{"top_level_case_forged_refused", raw(0, `,"decoded":`+decodedOf(0)+`}`, `,"Decoded":`+decodedOf(0)+`,"decoded":{"\u006bind":"host_forget",`+forged+`}}`), `its key "Decoded" is not one export writes (bundle_install)`},
		{"nested_duplicate_refused", inject(0, `,"x":[{"a":1,"\u0061":2}]`), `its key "a" occurs twice in one object (bundle_install)`},
		{"checkpoint_key_case_refused", raw(3, `{"checkpoint":`, `{"Checkpoint":"x","checkpoint":`), `its key "Checkpoint" is not one export writes (checkpoint)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := ff.verify(join(tc.lines), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify = %+v, %v; want an error naming %q", rep, err, tc.want)
			}
		})
	}
}
