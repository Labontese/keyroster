package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// memLog is an in-memory LogSource.
type memLog struct {
	leaves [][]byte
	note   []byte
}

func (m *memLog) ReadLog(_ context.Context, fn func(uint64, []byte) error) ([]byte, uint64, error) {
	for i, l := range m.leaves {
		if err := fn(uint64(i), l); err != nil { //nolint:gosec // G115: test index
			return nil, 0, err
		}
	}
	return m.note, uint64(len(m.leaves)), nil
}

// fixture builds a log the way the signer does: a root key signs a genesis
// trust bundle and policy naming the log key and the user, host and machine
// CAs; the log starts with their bundle_install entry. Tests can tamper with
// any part of it and re-sign checkpoints as a log-key holder would.
type fixture struct {
	t         testing.TB
	root      ssh.Signer
	logKey    ssh.Signer
	ca        ssh.Signer // user CA
	hostCA    ssh.Signer
	machineCA ssh.Signer
	ops       ssh.Signer
	admin     ssh.Signer
	leaves    [][]byte
	micros    uint64
	serial    uint64
	request   byte
}

func newSigner(t testing.TB, alg string) ssh.Signer {
	t.Helper()
	var (
		s   ssh.Signer
		err error
	)
	switch alg {
	case "ed25519":
		var priv ed25519.PrivateKey
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err == nil {
			s, err = ssh.NewSignerFromKey(priv)
		}
	case "p256":
		var priv *ecdsa.PrivateKey
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			s, err = ssh.NewSignerFromKey(priv)
		}
	}
	if err != nil || s == nil {
		t.Fatalf("new %s key: %v", alg, err)
	}
	return s
}

// newBareFixture generates the keys but logs nothing.
func newBareFixture(t testing.TB, logAlg string) *fixture {
	t.Helper()
	return newBareFixtureAt(t, logAlg, time.Now())
}

// newBareFixtureAt is newBareFixture with a log that starts at start. The
// leaf time and the serial start at the same microsecond and each add
// raises the leaf time, so every issue leaf's time is at or after its
// serial, as the signer writes them (serial.Next).
func newBareFixtureAt(t testing.TB, logAlg string, start time.Time) *fixture {
	t.Helper()
	us := uint64(start.UnixMicro()) //nolint:gosec // G115: test times are after 1970
	return &fixture{
		t: t, root: newSigner(t, "ed25519"), logKey: newSigner(t, logAlg),
		ca: newSigner(t, "ed25519"), hostCA: newSigner(t, "ed25519"), machineCA: newSigner(t, "ed25519"),
		ops: newSigner(t, "ed25519"), admin: newSigner(t, "ed25519"),
		micros: us, serial: us,
	}
}

// newFixture is a log that starts with the root-signed genesis
// bundle_install entry, as every signer log does after ca-init.
func newFixture(t testing.TB, logAlg string) *fixture {
	t.Helper()
	return newFixtureAt(t, logAlg, time.Now())
}

// newFixtureAt is newFixture with a log that starts at start.
func newFixtureAt(t testing.TB, logAlg string, start time.Time) *fixture {
	t.Helper()
	f := newBareFixtureAt(t, logAlg, start)
	f.addBundle(f.signDocs(f.genesis(), f.policy(), f.root))
	return f
}

// issuedAt is the issuance time the signer pairs with serial: serials are
// allocated from the clock in microseconds (serial.Next), and the
// certificate is built right after.
func issuedAt(serial uint64) time.Time { return time.UnixMicro(int64(serial)) } //nolint:gosec // G115: test serials are microsecond times

// pins are the fixture root's fingerprint.
func (f *fixture) pins() []string { return []string{ssh.FingerprintSHA256(f.root.PublicKey())} }

// policy is the genesis policy: one admin, one profile per CA role.
func (f *fixture) policy() *trust.Policy {
	return &trust.Policy{
		Version: 1, Prev: trust.GenesisPrev, AdminQuorum: 1,
		Admins: []trust.AdminKey{{Name: "alice", Key: trust.FormatKey(f.admin.PublicKey())}},
		CAProfiles: []trust.CAProfile{
			{Role: trust.RoleUser, MaxTTLSeconds: 43200, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleHost, MaxTTLSeconds: 2592000, DefaultExtensions: []string{}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
		},
	}
}

// genesis is the version 1 bundle: the fixture root at threshold 1, its
// CAs, ops key and log key. signDocs sets the policy hash.
func (f *fixture) genesis() *trust.Bundle {
	ca := func(role string, s ssh.Signer) trust.CAEntry {
		return trust.CAEntry{Role: role, Key: trust.FormatKey(s.PublicKey()), Alg: s.PublicKey().Type(), Custody: "agent", State: "active", Generation: 1}
	}
	return &trust.Bundle{
		Version: 1, Prev: trust.GenesisPrev, IssuedAt: time.Now().UTC().Truncate(time.Second).Format(trust.TimeFormat),
		Root:   trust.RootSet{Keys: []trust.RootKey{{Key: trust.FormatKey(f.root.PublicKey()), Custody: "software"}}, Threshold: 1},
		CAs:    []trust.CAEntry{ca(trust.RoleUser, f.ca), ca(trust.RoleHost, f.hostCA), ca(trust.RoleMachine, f.machineCA)},
		OpsKey: trust.KeyEntry{Key: trust.FormatKey(f.ops.PublicKey()), Alg: f.ops.PublicKey().Type(), Custody: "agent"},
		Log: trust.LogEntry{Key: trust.FormatKey(f.logKey.PublicKey()), Alg: f.logKey.PublicKey().Type(), Custody: "agent",
			Origin: tlog.Origin(f.logKey.PublicKey())},
	}
}

// docs are the four documents of a bundle_install entry.
type docs struct {
	version                                uint64
	bundle, bundleSigs, policy, policySigs []byte
}

// signDocs sets b's policy hash and returns the canonical bundle and policy
// with detached SSHSIG signatures by every signer.
func (f *fixture) signDocs(b *trust.Bundle, pol *trust.Policy, signers ...ssh.Signer) docs {
	f.t.Helper()
	d := docs{version: b.Version}
	var err error
	if d.policy, err = pol.Canonical(); err != nil {
		f.t.Fatal(err)
	}
	b.PolicySHA256 = trust.SHA256Hex(d.policy)
	if d.bundle, err = b.Canonical(); err != nil {
		f.t.Fatal(err)
	}
	for _, s := range signers {
		bs, err := sshsig.Sign(rand.Reader, s, trust.NamespaceBundle, d.bundle)
		if err != nil {
			f.t.Fatal(err)
		}
		ps, err := sshsig.Sign(rand.Reader, s, trust.NamespacePolicy, d.policy)
		if err != nil {
			f.t.Fatal(err)
		}
		d.bundleSigs, d.policySigs = append(d.bundleSigs, bs...), append(d.policySigs, ps...)
	}
	return d
}

// addBundle logs a bundle_install entry for d.
func (f *fixture) addBundle(d docs) {
	f.t.Helper()
	b, err := (&tlog.BundleInstallBody{BundleVersion: d.version, Bundle: d.bundle, BundleSigs: d.bundleSigs, Policy: d.policy, PolicySigs: d.policySigs}).Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	f.add(tlog.KindBundleInstall, b)
}

// add appends a leaf of kind with body at the next index.
func (f *fixture) add(kind tlog.Kind, body []byte) {
	f.t.Helper()
	f.micros++
	raw, err := tlog.MarshalLeaf(tlog.Leaf{Index: uint64(len(f.leaves)), TimeMicros: f.micros, Kind: kind, Body: body})
	if err != nil {
		f.t.Fatal(err)
	}
	f.leaves = append(f.leaves, raw)
}

// newCert issues a real certificate through cert.Build.
func (f *fixture) newCert(serial uint64, now time.Time) *ssh.Certificate {
	f.t.Helper()
	subject := newSigner(f.t, "ed25519").PublicKey()
	f.request++
	keyID := cert.KeyID{CA: "user", Subject: "u:alice", Request: strings.Repeat(hex.EncodeToString([]byte{f.request}), 16), Policy: 1, Serial: serial}
	c, err := cert.Build(cert.Request{
		Profile: cert.DefaultUserProfile(), Subject: subject, Principals: []string{"alice"},
		Now: now, ValidFor: time.Hour, KeyID: keyID, Serial: serial,
	}, f.ca, rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// issueBody returns the issue leaf body for c.
func issueBody(t testing.TB, c *ssh.Certificate, serial uint64) []byte {
	t.Helper()
	b, err := (&tlog.IssueBody{CARole: uint8(wire.CARoleUser), Serial: serial, PolicyVersion: 1, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// addIssue issues and logs one certificate with the next serial.
func (f *fixture) addIssue() {
	f.t.Helper()
	f.serial++
	f.add(tlog.KindIssue, issueBody(f.t, f.newCert(f.serial, issuedAt(f.serial)), f.serial))
}

func (f *fixture) addRefusal() {
	f.t.Helper()
	b, err := (&tlog.RefusalBody{PeerUID: 1000, Reason: tlog.ReasonBadPrincipal, Detail: "bad_principal"}).Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	f.add(tlog.KindRefusal, b)
}

// checkpoint signs the checkpoint for the first n leaves with key.
func (f *fixture) checkpointWith(key ssh.Signer, origin string, n int) []byte {
	f.t.Helper()
	var hashes [][]byte
	for _, l := range f.leaves[:n] {
		hashes = append(hashes, tlog.HashLeaf(l))
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		f.t.Fatal(err)
	}
	root, err := tree.Root()
	if err != nil {
		f.t.Fatal(err)
	}
	ns, err := tlog.NewNoteSigner(origin, key)
	if err != nil {
		f.t.Fatal(err)
	}
	msg, err := tlog.SignCheckpoint(tlog.Checkpoint{Origin: origin, Size: uint64(n), Root: root}, ns) //nolint:gosec // G115: test size
	if err != nil {
		f.t.Fatal(err)
	}
	return msg
}

func (f *fixture) checkpoint(n int) []byte {
	return f.checkpointWith(f.logKey, tlog.Origin(f.logKey.PublicKey()), n)
}

// lines exports the whole log, checkpointed by the log key, as JSONL lines.
func (f *fixture) lines() []string {
	f.t.Helper()
	var buf bytes.Buffer
	if _, err := Export(context.Background(), &buf, &memLog{leaves: f.leaves, note: f.checkpoint(len(f.leaves))}); err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
}

func join(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func (f *fixture) verify(export string, previous []byte) (*Report, error) {
	return Verify(strings.NewReader(export), Options{Pins: f.pins(), Threshold: 1, Previous: previous})
}

// standard is a log of two issuances, a refusal and an issuance.
func standard(t testing.TB, logAlg string) *fixture {
	f := newFixture(t, logAlg)
	f.addIssue()
	f.addIssue()
	f.addRefusal()
	f.addIssue()
	return f
}

func TestVerifyOK(t *testing.T) {
	for _, alg := range []string{"ed25519", "p256"} {
		t.Run(alg, func(t *testing.T) {
			f := standard(t, alg)
			rep, err := f.verify(join(f.lines()), nil)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if rep.Size != 5 || rep.Serials != 3 || rep.Counts[tlog.KindIssue] != 3 || rep.Counts[tlog.KindRefusal] != 1 ||
				rep.Counts[tlog.KindBundleInstall] != 1 || rep.IssuedByCA["user"] != 3 || rep.BundleVersion != 1 || rep.PolicyVersion != 1 {
				t.Fatalf("report %+v", rep)
			}
		})
	}
}

// leafLine re-encodes line with its leaf bytes replaced.
func leafLine(t *testing.T, line string, edit func([]byte) []byte) string {
	t.Helper()
	var l ExportLine
	if err := json.Unmarshal([]byte(line), &l); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(l.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	l.Leaf = base64.StdEncoding.EncodeToString(edit(append([]byte(nil), raw...)))
	out, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestVerifyDetectsTampering: every modification of the export fails with a
// specific reason; editing only the informational "decoded" object does
// not.
func TestVerifyDetectsTampering(t *testing.T) {
	f := standard(t, "ed25519")
	all := f.lines() // bundle_install, 4 leaf lines, checkpoint
	bi, base := all[0], all[1:]
	cp := base[4]
	other := newSigner(t, "ed25519")
	// header (22 domain + 8 index + 8 time + 1 kind + 3 length) + role 1 +
	// serial 8 + policy 8 lands inside the request digest.
	const digestByte = 42 + 17 + 5
	cases := []struct {
		name  string
		lines func() []string
		want  string // "" = must verify
	}{
		{"flipped_leaf_byte", func() []string {
			l := append([]string(nil), base...)
			l[1] = leafLine(t, l[1], func(b []byte) []byte { b[digestByte] ^= 1; return b })
			return l
		}, "root mismatch"},
		{"removed_leaf_line", func() []string { return append(append([]string(nil), base[:1]...), base[2:]...) }, "missing"},
		{"truncated_tail_keeps_checkpoint", func() []string { return []string{base[0], base[1], cp} }, "checkpoint covers 5 entries"},
		{"checkpoint_other_key", func() []string {
			l := append([]string(nil), base[:4]...)
			forged := f.checkpointWith(other, tlog.Origin(f.logKey.PublicKey()), 5)
			out, _ := json.Marshal(ExportLine{Checkpoint: string(forged)})
			return append(l, string(out))
		}, "not signed by the log key"},
		{"checkpoint_not_last", func() []string { return []string{base[0], base[1], base[2], cp, base[3]} }, "not last"},
		{"two_checkpoint_lines", func() []string { return append(append([]string(nil), base...), cp) }, "more than one checkpoint"},
		{"duplicate_index", func() []string { return []string{base[0], base[1], base[1], base[2], base[3], cp} }, "repeated"},
		{"swapped_lines", func() []string { return []string{base[1], base[0], base[2], base[3], cp} }, "out of order"},
		{"no_leaf_after_bundle", func() []string { return nil }, "empty log"},
		{"no_checkpoint", func() []string { return base[:4] }, "empty log"},
		{"unknown_field", func() []string {
			l := append([]string(nil), base...)
			l[0] = strings.Replace(l[0], `{"index"`, `{"extra":1,"index"`, 1)
			return l
		}, "unknown field"},
		{"blank_line", func() []string { return []string{base[0], "", base[1], base[2], base[3], cp} }, "empty line"},
		{"decoded_only_edit_still_ok", func() []string {
			l := append([]string(nil), base...)
			var line ExportLine
			if err := json.Unmarshal([]byte(l[0]), &line); err != nil {
				t.Fatal(err)
			}
			line.Decoded = json.RawMessage(`{"kind":"issue","serial":1,"principals":["root"],"note":"edited"}`)
			out, _ := json.Marshal(line)
			l[0] = string(out)
			return l
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := f.verify(join(append([]string{bi}, tc.lines()...)), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Verify accepted the tampered export: %+v", rep)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestVerifyEmpty: an export without entries or without a checkpoint
// verifies nothing.
func TestVerifyEmpty(t *testing.T) {
	f := newFixture(t, "ed25519")
	cp := f.lines()[1]
	for name, export := range map[string]string{"empty_export": "", "checkpoint_without_entries": join([]string{cp})} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.verify(export, nil); err == nil || !strings.Contains(err.Error(), "empty log") {
				t.Fatalf("Verify error = %v, want empty log", err)
			}
		})
	}
}

// forgeCert signs c with ca outside cert.Build (as a compromised CA or a
// log-key holder rewriting history could), setting the nonce, signature
// key and signature over the certificate's signed bytes.
func forgeCert(t *testing.T, c *ssh.Certificate, ca ssh.Signer, sigKey ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	c.Nonce = make([]byte, 32)
	if _, err := rand.Read(c.Nonce); err != nil {
		t.Fatal(err)
	}
	c.SignatureKey = sigKey
	c.Signature = nil
	out := c.Marshal()
	sig, err := ca.Sign(rand.Reader, out[:len(out)-4])
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = sig
	return c
}

// TestVerifyChecksCertificates: a log-key holder can re-sign checkpoints,
// so audit verify also re-checks every logged certificate.
func TestVerifyChecksCertificates(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, f *fixture)
		want  string
	}{
		{"cert_bad_signature", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			c.Signature.Blob = append([]byte(nil), c.Signature.Blob...)
			c.Signature.Blob[0] ^= 1
			f.add(tlog.KindIssue, issueBody(t, c, f.serial))
		}, "CA signature"},
		{"leaf_serial_differs_from_cert", func(t *testing.T, f *fixture) {
			f.serial++
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, issuedAt(f.serial)), f.serial+1))
		}, "serial"},
		{"serial_not_increasing", func(t *testing.T, f *fixture) {
			f.addIssue()
			s := f.serial - 10
			f.add(tlog.KindIssue, issueBody(t, f.newCert(s, issuedAt(s)), s))
		}, "serial"},
		{"serial_repeated", func(t *testing.T, f *fixture) {
			f.addIssue()
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, issuedAt(f.serial)), f.serial))
		}, "serial"},
		{"key_id_serial_differs", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			c.KeyId = strings.Replace(c.KeyId, fmt.Sprintf("/ser=%d", f.serial), fmt.Sprintf("/ser=%d", f.serial+1), 1)
			c = forgeCert(t, c, f.ca, f.ca.PublicKey())
			b, err := (&tlog.IssueBody{CARole: 1, Serial: f.serial, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			f.add(tlog.KindIssue, b)
		}, "key ID"},
		// The admin path issues kr1; a kr2 (login) key ID on an issue
		// leaf would pass an admin issuance off as a passkey login.
		{"issue_with_kr2_key_id", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			kid, err := cert.ParseKeyID(c.KeyId)
			if err != nil {
				t.Fatal(err)
			}
			kid.Directory, kid.Roles = 1, []string{"ops"}
			c.KeyId = kid.String()
			f.add(tlog.KindIssue, issueBody(t, forgeCert(t, c, f.ca, f.ca.PublicKey()), f.serial))
		}, "kr1"},
		{"leaf_key_id_differs", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			b, err := (&tlog.IssueBody{CARole: 1, Serial: f.serial, Cert: c.Marshal(), KeyID: c.KeyId + "x"}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			f.add(tlog.KindIssue, b)
		}, "key ID"},
		{"signature_key_is_certificate", func(t *testing.T, f *fixture) {
			f.serial++
			caCert := f.newCert(f.serial, issuedAt(f.serial)) // a certificate standing in as the CA key
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			c = forgeCert(t, c, f.ca, caCert)
			f.add(tlog.KindIssue, issueBody(t, c, f.serial))
		}, "certificate"},
		{"leaf_time_decreases", func(_ *testing.T, f *fixture) {
			f.addIssue()
			f.micros -= 10
			f.addRefusal()
		}, "time"},
		{"leaf_records_wrong_index", func(t *testing.T, f *fixture) {
			f.addRefusal()
			b, err := (&tlog.RefusalBody{Reason: tlog.ReasonMalformed}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := tlog.MarshalLeaf(tlog.Leaf{Index: 7, TimeMicros: f.micros + 1, Kind: tlog.KindRefusal, Body: b})
			if err != nil {
				t.Fatal(err)
			}
			f.leaves = append(f.leaves, raw)
		}, "records index"},
		// C-WR-06: a CA-key holder signing outside the role's profile of
		// the policy in force (user: 43200 s, permit-pty only).
		{"validity_at_policy_cap_ok", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			c.ValidBefore = c.ValidAfter + 43200 + 300
			f.add(tlog.KindIssue, issueBody(t, forgeCert(t, c, f.ca, f.ca.PublicKey()), f.serial))
		}, ""},
		{"validity_above_policy_cap", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			c.ValidBefore = c.ValidAfter + 43200 + 300 + 1
			f.add(tlog.KindIssue, issueBody(t, forgeCert(t, c, f.ca, f.ca.PublicKey()), f.serial))
		}, "outside the user profile of policy v1"},
		{"extension_outside_policy", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			c.Extensions["permit-agent-forwarding"] = ""
			f.add(tlog.KindIssue, issueBody(t, forgeCert(t, c, f.ca, f.ca.PublicKey()), f.serial))
		}, "extension"},
		{"critical_option_outside_policy", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, issuedAt(f.serial))
			c.CriticalOptions = map[string]string{"force-command": "/bin/sh"}
			f.add(tlog.KindIssue, issueBody(t, forgeCert(t, c, f.ca, f.ca.PublicKey()), f.serial))
		}, "critical option"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "ed25519")
			f.addIssue()
			tc.build(t, f)
			_, err := f.verify(join(f.lines()), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestVerifyChecksIssuanceTime (F-WR-01): cert.Build sets ValidAfter to the
// issuance time minus its five-minute backdate, and the signer issues at a
// time between the serial (a microsecond clock reading, serial.Next) and
// the leaf time. A logged certificate whose validity starts anywhere else,
// postdated or backdated, is one the signer could not have produced, even
// with a span within the profile's cap.
func TestVerifyChecksIssuanceTime(t *testing.T) {
	year := 365 * 24 * time.Hour
	cases := []struct {
		name  string
		start time.Time // the log's first leaf time and serial
		build func(t *testing.T, f *fixture)
		want  string
	}{
		{"expired_certificate_still_ok", time.Now().Add(-2 * year), func(_ *testing.T, f *fixture) {
			f.addIssue()
		}, ""},
		{"postdated_to_2030", time.Now(), func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) // a 1 h span, within the 12 h cap
			f.add(tlog.KindIssue, issueBody(t, c, f.serial))
		}, "valid after"},
		{"postdated_by_a_minute", time.Now(), func(t *testing.T, f *fixture) {
			f.serial++
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, issuedAt(f.serial).Add(time.Minute)), f.serial))
		}, "valid after"},
		{"backdated_a_year", time.Now(), func(t *testing.T, f *fixture) {
			f.serial++
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, issuedAt(f.serial).Add(-year)), f.serial))
		}, "valid after"},
		{"serial_after_leaf_time", time.Now(), func(t *testing.T, f *fixture) {
			f.serial = f.micros + uint64(time.Second/time.Microsecond)
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, issuedAt(f.serial)), f.serial))
		}, "serial"},
		// The signer raises a leaf's time to its predecessor's when the
		// clock stepped back (appendLocked): a refusal logged an hour
		// ahead, then an issuance at the corrected clock.
		{"leaf_time_raised_ok", time.Now(), func(_ *testing.T, f *fixture) {
			f.micros += uint64(time.Hour / time.Microsecond)
			f.addRefusal()
			f.addIssue()
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixtureAt(t, "ed25519", tc.start)
			f.addIssue()
			tc.build(t, f)
			_, err := f.verify(join(f.lines()), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestIdenticalRefusalsAreDistinctEntries: two leaves with identical
// content except index and time both count (VIS-01 adjacency).
func TestIdenticalRefusalsAreDistinctEntries(t *testing.T) {
	f := newFixture(t, "ed25519")
	f.addRefusal()
	f.addRefusal()
	rep, err := f.verify(join(f.lines()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Size != 3 || rep.Counts[tlog.KindRefusal] != 2 {
		t.Fatalf("report %+v, want two refusal entries", rep)
	}
}

func TestVerifyPrevious(t *testing.T) {
	f := standard(t, "ed25519")
	export := join(f.lines())

	t.Run("previous_ok", func(t *testing.T) {
		if _, err := f.verify(export, f.checkpoint(3)); err != nil {
			t.Fatalf("Verify with an earlier checkpoint of this log: %v", err)
		}
	})
	t.Run("previous_same_size_ok", func(t *testing.T) {
		if _, err := f.verify(export, f.checkpoint(5)); err != nil {
			t.Fatalf("Verify with the current checkpoint as previous: %v", err)
		}
	})
	t.Run("previous_rewritten", func(t *testing.T) {
		g := &fixture{t: t, logKey: f.logKey, ca: f.ca, micros: f.micros, serial: f.serial}
		g.addRefusal()
		g.addRefusal()
		g.addRefusal()
		_, err := f.verify(export, g.checkpoint(3))
		if err == nil || !strings.Contains(err.Error(), "log rewritten") {
			t.Fatalf("Verify error = %v, want log rewritten", err)
		}
	})
	t.Run("previous_shrank", func(t *testing.T) {
		g := standard(t, "ed25519")
		g.logKey = f.logKey
		g.addRefusal()
		_, err := f.verify(export, g.checkpoint(6))
		if err == nil || !strings.Contains(err.Error(), "log shrank") {
			t.Fatalf("Verify error = %v, want log shrank", err)
		}
	})
	t.Run("previous_other_key", func(t *testing.T) {
		other := newSigner(t, "ed25519")
		_, err := f.verify(export, f.checkpointWith(other, tlog.Origin(f.logKey.PublicKey()), 3))
		if err == nil || !strings.Contains(err.Error(), "previous") {
			t.Fatalf("Verify error = %v, want a previous-checkpoint error", err)
		}
	})
}

// roleProfile returns a certificate profile of certType for test
// certificates of any role.
func roleProfile(certType uint32) cert.Profile {
	p := cert.Profile{CertType: certType, MaxTTL: 24 * time.Hour}
	if certType == ssh.UserCert {
		p.DefaultExtensions = map[string]string{"permit-pty": ""}
	}
	return p
}

// addRoleIssue logs a certificate of certType for CA role, signed by ca,
// whose key ID carries pol and whose leaf records leafPol.
func (f *fixture) addRoleIssue(role wire.CARole, ca ssh.Signer, certType uint32, pol, leafPol uint64) {
	f.t.Helper()
	f.serial++
	f.request++
	keyID := cert.KeyID{CA: role.String(), Subject: "s:e2e", Request: strings.Repeat(hex.EncodeToString([]byte{f.request}), 16), Policy: pol, Serial: f.serial}
	c, err := cert.Build(cert.Request{
		Profile: roleProfile(certType), Subject: newSigner(f.t, "ed25519").PublicKey(), Principals: []string{"alice"},
		Now: issuedAt(f.serial), ValidFor: time.Hour, KeyID: keyID, Serial: f.serial,
	}, ca, rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := (&tlog.IssueBody{CARole: uint8(role), Serial: f.serial, PolicyVersion: leafPol, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	f.add(tlog.KindIssue, b)
}

// successor returns the version 2 bundle after the genesis bundle g (the
// same keys unless edit changes them).
func (f *fixture) successor(g docs, edit func(*trust.Bundle)) *trust.Bundle {
	f.t.Helper()
	prev, err := trust.ParseBundle(g.bundle)
	if err != nil {
		f.t.Fatal(err)
	}
	next := *prev
	next.Version, next.Prev = 2, trust.SHA256Hex(g.bundle)
	if edit != nil {
		edit(&next)
	}
	return &next
}

// TestVerifyAnchoring (VIS-03): audit verify trusts the log key and the CA
// keys only through bundle_install entries that verify against the
// operator's pins, and checks every issuance against the bundle and policy
// in force.
func TestVerifyAnchoring(t *testing.T) {
	type tc struct {
		name      string
		build     func(t *testing.T) (*fixture, Options)
		want      string // "" = must verify
		wantCheck func(t *testing.T, rep *Report)
	}
	pinsOf := func(signers ...ssh.Signer) []string {
		var out []string
		for _, s := range signers {
			out = append(out, ssh.FingerprintSHA256(s.PublicKey()))
		}
		return out
	}
	// standardOpts verifies against the fixture's own root.
	standardOpts := func(f *fixture) Options { return Options{Pins: f.pins(), Threshold: 1} }
	// twoRoots is a fixture whose genesis bundle lists roots A and B with
	// the given threshold and is signed by signers.
	twoRoots := func(t *testing.T, threshold uint32, signers func(a, b ssh.Signer) []ssh.Signer) (*fixture, ssh.Signer, ssh.Signer) {
		f := newBareFixture(t, "ed25519")
		a, b := f.root, newSigner(t, "ed25519")
		g := f.genesis()
		g.Root = trust.RootSet{Keys: []trust.RootKey{
			{Key: trust.FormatKey(a.PublicKey()), Custody: "software"},
			{Key: trust.FormatKey(b.PublicKey()), Custody: "software"},
		}, Threshold: threshold}
		f.addBundle(f.signDocs(g, f.policy(), signers(a, b)...))
		f.addIssue()
		return f, a, b
	}
	cases := []tc{
		{"control_ok", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addIssue()
			return f, standardOpts(f)
		}, "", func(t *testing.T, rep *Report) {
			if rep.BundleVersion != 1 || rep.PolicyVersion != 1 || rep.IssuedByCA["user"] != 1 {
				t.Fatalf("report %+v", rep)
			}
		}},
		{"unpinned_root", func(t *testing.T) (*fixture, Options) {
			// The bundle lists and is signed by its own root; the operator
			// pinned another root.
			f := newFixture(t, "ed25519")
			f.addIssue()
			return f, Options{Pins: pinsOf(newSigner(t, "ed25519")), Threshold: 1}
		}, "not anchored in the pinned roots", nil},
		{"bundle_signed_by_unpinned_root", func(t *testing.T) (*fixture, Options) {
			// The bundle lists the pinned root but only another key signed it.
			f := newBareFixture(t, "ed25519")
			f.addBundle(f.signDocs(f.genesis(), f.policy(), newSigner(t, "ed25519")))
			f.addIssue()
			return f, standardOpts(f)
		}, "threshold not met", nil},
		{"pins_name_other_root", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addIssue()
			return f, Options{Pins: append(f.pins(), pinsOf(newSigner(t, "ed25519"))...), Threshold: 1}
		}, "not anchored in the pinned roots", nil},
		{"threshold_not_met", func(t *testing.T) (*fixture, Options) {
			// Roots A and B at threshold 2, but only A signed.
			f, a, b := twoRoots(t, 2, func(a, _ ssh.Signer) []ssh.Signer { return []ssh.Signer{a} })
			return f, Options{Pins: pinsOf(a, b), Threshold: 2}
		}, "threshold not met", nil},
		{"threshold_above_bundle", func(t *testing.T) (*fixture, Options) {
			// Both roots signed a threshold-1 bundle; the operator demands 2.
			f, a, b := twoRoots(t, 1, func(a, b ssh.Signer) []ssh.Signer { return []ssh.Signer{a, b} })
			return f, Options{Pins: pinsOf(a, b), Threshold: 2}
		}, "not anchored in the pinned roots", nil},
		{"two_roots_threshold_2_ok", func(t *testing.T) (*fixture, Options) {
			f, a, b := twoRoots(t, 2, func(a, b ssh.Signer) []ssh.Signer { return []ssh.Signer{a, b} })
			return f, Options{Pins: pinsOf(a, b), Threshold: 2}
		}, "", nil},
		{"threshold_zero", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addIssue()
			return f, Options{Pins: f.pins(), Threshold: 0}
		}, "threshold", nil},
		{"no_pins", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addIssue()
			return f, Options{Threshold: 1}
		}, "no pinned root", nil},
		{"host_ca_under_user_role", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleUser, f.hostCA, ssh.UserCert, 1, 1)
			return f, standardOpts(f)
		}, "not by the role's active CA", nil},
		{"machine_ca_under_user_role", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleUser, f.machineCA, ssh.UserCert, 1, 1)
			return f, standardOpts(f)
		}, "not by the role's active CA", nil},
		{"user_ca_under_host_role", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleHost, f.ca, ssh.HostCert, 1, 1)
			return f, standardOpts(f)
		}, "not by the role's active CA", nil},
		{"every_role_ok", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleUser, f.ca, ssh.UserCert, 1, 1)
			f.addRoleIssue(wire.CARoleHost, f.hostCA, ssh.HostCert, 1, 1)
			f.addRoleIssue(wire.CARoleMachine, f.machineCA, ssh.UserCert, 1, 1)
			return f, standardOpts(f)
		}, "", func(t *testing.T, rep *Report) {
			if rep.IssuedByCA["user"] != 1 || rep.IssuedByCA["host"] != 1 || rep.IssuedByCA["machine"] != 1 {
				t.Fatalf("issued by CA = %v, want one per role", rep.IssuedByCA)
			}
		}},
		{"user_cert_type_under_host_role", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleHost, f.hostCA, ssh.UserCert, 1, 1)
			return f, standardOpts(f)
		}, "certificate type", nil},
		{"host_cert_type_under_machine_role", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleMachine, f.machineCA, ssh.HostCert, 1, 1)
			return f, standardOpts(f)
		}, "certificate type", nil},
		{"issue_before_bundle", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			f.addIssue()
			f.addBundle(f.signDocs(f.genesis(), f.policy(), f.root))
			return f, standardOpts(f)
		}, "before the first bundle_install", nil},
		{"no_bundle", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			f.addRefusal()
			return f, standardOpts(f)
		}, "no bundle_install", nil},
		{"policy_version_mismatch", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleUser, f.ca, ssh.UserCert, 2, 2)
			return f, standardOpts(f)
		}, "pol=2", nil},
		{"leaf_policy_version_mismatch", func(t *testing.T) (*fixture, Options) {
			// The certificate says pol=1, the leaf records policy 2.
			f := newFixture(t, "ed25519")
			f.addRoleIssue(wire.CARoleUser, f.ca, ssh.UserCert, 1, 2)
			return f, standardOpts(f)
		}, "policy version", nil},
		{"bundle_version_field_mismatch", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			d := f.signDocs(f.genesis(), f.policy(), f.root)
			d.version = 7
			f.addBundle(d)
			f.addIssue()
			return f, standardOpts(f)
		}, "bundle version", nil},
		{"successor_same_log_key_ok", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), f.root)
			f.addBundle(g)
			f.addIssue()
			f.addBundle(f.signDocs(f.successor(g, nil), f.policy(), f.root))
			f.addIssue()
			return f, standardOpts(f)
		}, "", func(t *testing.T, rep *Report) {
			if rep.BundleVersion != 2 || rep.Counts[tlog.KindBundleInstall] != 2 || rep.Serials != 2 {
				t.Fatalf("report %+v, want bundle v2 after two installs and two issuances", rep)
			}
		}},
		{"successor_not_root_signed", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), f.root)
			f.addBundle(g)
			f.addBundle(f.signDocs(f.successor(g, nil), f.policy(), newSigner(t, "ed25519")))
			return f, standardOpts(f)
		}, "not a valid successor", nil},
		// A-WR-02, C-WR-05: a successor's policy chains like the bundle,
		// so pol=N names one policy.
		{"successor_policy_chained_ok", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), f.root)
			f.addBundle(g)
			pol := f.policy()
			pol.Version, pol.Prev = 2, trust.SHA256Hex(g.policy)
			pol.CAProfiles[0].MaxTTLSeconds = 3600
			f.addBundle(f.signDocs(f.successor(g, nil), pol, f.root))
			f.addRoleIssue(wire.CARoleUser, f.ca, ssh.UserCert, 2, 2)
			return f, standardOpts(f)
		}, "", func(t *testing.T, rep *Report) {
			if rep.PolicyVersion != 2 || rep.Serials != 1 {
				t.Fatalf("report %+v, want policy v2 and one issuance", rep)
			}
		}},
		{"successor_policy_same_version_refused", func(t *testing.T) (*fixture, Options) {
			// Another policy (other profile) under the version in force.
			f := newBareFixture(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), f.root)
			f.addBundle(g)
			pol := f.policy()
			pol.CAProfiles[0].MaxTTLSeconds = 3600
			f.addBundle(f.signDocs(f.successor(g, nil), pol, f.root))
			return f, standardOpts(f)
		}, "a changed policy must be version 2", nil},
		{"successor_policy_unchained_refused", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), f.root)
			f.addBundle(g)
			pol := f.policy()
			pol.Version, pol.Prev = 2, trust.SHA256Hex([]byte("another policy"))
			f.addBundle(f.signDocs(f.successor(g, nil), pol, f.root))
			return f, standardOpts(f)
		}, "a changed policy must be version 2", nil},
		{"log_key_change", func(t *testing.T) (*fixture, Options) {
			f := newBareFixture(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), f.root)
			f.addBundle(g)
			newLog := newSigner(t, "ed25519")
			f.addBundle(f.signDocs(f.successor(g, func(b *trust.Bundle) {
				b.Log = trust.LogEntry{Key: trust.FormatKey(newLog.PublicKey()), Alg: newLog.PublicKey().Type(), Custody: "agent", Origin: tlog.Origin(newLog.PublicKey())}
			}), f.policy(), f.root))
			return f, standardOpts(f)
		}, "log key change unsupported", nil},
		{"successor_ca_rotation_checked", func(t *testing.T) (*fixture, Options) {
			// A successor makes another key the active user CA: the old
			// CA's certificates no longer verify after it.
			f := newBareFixture(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), f.root)
			f.addBundle(g)
			f.addIssue()
			newUser := newSigner(t, "ed25519")
			f.addBundle(f.signDocs(f.successor(g, func(b *trust.Bundle) {
				b.CAs[0].Key = trust.FormatKey(newUser.PublicKey())
			}), f.policy(), f.root))
			f.addIssue() // still signed by the old user CA
			return f, standardOpts(f)
		}, "not by the role's active CA", nil},
		{"decoded_only_edit_still_ok", func(t *testing.T) (*fixture, Options) {
			f := newFixture(t, "ed25519")
			f.addIssue()
			return f, standardOpts(f)
		}, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, opts := c.build(t)
			lines := f.lines()
			if c.name == "decoded_only_edit_still_ok" {
				// The informational object of the bundle_install line names
				// another log key and root; Verify never reads it.
				var line ExportLine
				if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
					t.Fatal(err)
				}
				other := trust.FormatKey(newSigner(t, "ed25519").PublicKey())
				line.Decoded = json.RawMessage(fmt.Sprintf(`{"kind":"bundle_install","bundle_version":1,"log_key":%q,"root":%q}`, other, other))
				out, err := json.Marshal(line)
				if err != nil {
					t.Fatal(err)
				}
				lines[0] = string(out)
			}
			rep, err := Verify(strings.NewReader(join(lines)), opts)
			if c.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if c.wantCheck != nil {
					c.wantCheck(t, rep)
				}
				return
			}
			if err == nil {
				t.Fatalf("Verify accepted the export: %+v", rep)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Verify error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestVerifyRefusesRetiredRootAsAdmin (F-WR-02, KEY-07): a root stays a
// root after a rotation retires it. Root A signs genesis v1, v2 rotates to
// root B, and v3, signed by B, lists A as an admin. VerifySuccessor sees
// only v3's predecessor (root B), so Verify checks every policy against
// the roots of every bundle installed before it.
func TestVerifyRefusesRetiredRootAsAdmin(t *testing.T) {
	onlyRoot := func(s ssh.Signer) trust.RootSet {
		return trust.RootSet{Keys: []trust.RootKey{{Key: trust.FormatKey(s.PublicKey()), Custody: "software"}}, Threshold: 1}
	}
	chain := func(t *testing.T, admin func(a ssh.Signer) ssh.PublicKey) (*fixture, ssh.Signer) {
		f := newBareFixture(t, "ed25519")
		a, b := f.root, newSigner(t, "ed25519")
		g := f.signDocs(f.genesis(), f.policy(), a)
		f.addBundle(g)
		f.addIssue()
		v2 := f.signDocs(f.successor(g, func(bd *trust.Bundle) { bd.Root = onlyRoot(b) }), f.policy(), a, b)
		f.addBundle(v2)
		p1, err := f.policy().Canonical()
		if err != nil {
			t.Fatal(err)
		}
		pol := f.policy()
		pol.Version, pol.Prev = 2, trust.SHA256Hex(p1)
		pol.Admins = append(pol.Admins, trust.AdminKey{Name: "extra", Key: trust.FormatKey(admin(a))})
		v3 := f.successor(v2, func(bd *trust.Bundle) { bd.Root = onlyRoot(b) })
		v3.Version = 3
		f.addBundle(f.signDocs(v3, pol, b))
		return f, b
	}
	t.Run("retired_root_refused", func(t *testing.T) {
		f, b := chain(t, func(a ssh.Signer) ssh.PublicKey { return a.PublicKey() })
		_, err := Verify(strings.NewReader(join(f.lines())), Options{Pins: []string{ssh.FingerprintSHA256(b.PublicKey())}, Threshold: 1})
		if !errors.Is(err, trust.ErrKeyIsRoot) || !strings.Contains(err.Error(), "entry 3") {
			t.Fatalf("Verify = %v, want trust.ErrKeyIsRoot at entry 3 (the v3 bundle_install)", err)
		}
	})
	t.Run("control_fresh_admin_ok", func(t *testing.T) {
		f, b := chain(t, func(ssh.Signer) ssh.PublicKey { return newSigner(t, "ed25519").PublicKey() })
		rep, err := Verify(strings.NewReader(join(f.lines())), Options{Pins: []string{ssh.FingerprintSHA256(b.PublicKey())}, Threshold: 1})
		if err != nil || rep.BundleVersion != 3 || rep.PolicyVersion != 2 {
			t.Fatalf("Verify = %+v, %v; want bundle v3, policy v2", rep, err)
		}
	})
}

// TestVerifyBundleChainLinear: the retired-root check (KEY-07) costs each
// bundle_install entry work for its own roots and admins only, not for the
// roots of every earlier bundle, so verifying a hostile export of B
// successor bundles is linear in B, not quadratic. Allocations are
// deterministic where time is not: four times the bundles must cost about
// four times the allocations (quadratic growth gave about ten times).
func TestVerifyBundleChainLinear(t *testing.T) {
	allocs := func(bundles int) float64 {
		lf := newLoginFixture(t, false)
		for range bundles {
			lf.installPolicy(func(*trust.Policy) {})
		}
		export := join(lf.lines())
		return testing.AllocsPerRun(1, func() {
			if _, err := lf.verify(export, nil); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
	small, large := allocs(100), allocs(400)
	ratio := large / small
	if ratio > 6 {
		t.Fatalf("Verify of 400 successor bundles allocates %.0f times, of 100 %.0f times: ratio %.1f, want about 4 (linear)", large, small, ratio)
	}
	t.Logf("allocations: 100 bundles %.0f, 400 bundles %.0f, ratio %.1f", small, large, ratio)
}

// TestVerifyAnchorsOnLaterBundle (VIS-03, KEY-07): the pins may name the
// root set of any trust bundle in the log, not only the genesis bundle.
// The first bundle whose root set and threshold are exactly the pins is the
// anchor; the bundles before it are authenticated by the prev-hash chain,
// the ones after it by VerifySuccessor, and pins that match no bundle fail
// closed. This test goes red if anchoring becomes genesis-only again.
func TestVerifyAnchorsOnLaterBundle(t *testing.T) {
	// check is one Verify call over the case's log.
	type check struct {
		pins       []ssh.Signer
		threshold  int    // 0 = 1
		want       string // "" = must verify
		why        string // with want: the specific reason, also required
		wantAnchor uint64
	}
	pinsOf := func(signers ...ssh.Signer) []string {
		var out []string
		for _, s := range signers {
			out = append(out, ssh.FingerprintSHA256(s.PublicKey()))
		}
		return out
	}
	onlyRoot := func(s ssh.Signer) trust.RootSet {
		return trust.RootSet{Keys: []trust.RootKey{{Key: trust.FormatKey(s.PublicKey()), Custody: "software"}}, Threshold: 1}
	}
	// rootSet is the root set of roots at threshold.
	rootSet := func(threshold uint32, roots ...ssh.Signer) trust.RootSet {
		set := trust.RootSet{Threshold: threshold}
		for _, r := range roots {
			set.Keys = append(set.Keys, trust.RootKey{Key: trust.FormatKey(r.PublicKey()), Custody: "software"})
		}
		return set
	}
	// rotatedTo is genesis by root A (the fixture root) and an issuance,
	// then successor v2 with the root set and signers v2 returns for A, and
	// an issuance under v2.
	rotatedTo := func(t *testing.T, v2 func(a ssh.Signer) (trust.RootSet, []ssh.Signer)) (f *fixture, a ssh.Signer) {
		f = newBareFixture(t, "ed25519")
		a = f.root
		g := f.signDocs(f.genesis(), f.policy(), a)
		f.addBundle(g)
		f.addIssue()
		roots, signers := v2(a)
		f.addBundle(f.signDocs(f.successor(g, func(b *trust.Bundle) { b.Root = roots }), f.policy(), signers...))
		f.addIssue()
		return f, a
	}
	// rotated is the homelab rotation: genesis by root A (the fixture
	// root) and an issuance, then successor v2 naming root C, signed by
	// v2Signers, and an issuance under v2. edit changes v2 before signing.
	rotated := func(t *testing.T, edit func(*trust.Bundle), v2Signers func(a, c ssh.Signer) []ssh.Signer) (f *fixture, a, c ssh.Signer) {
		f = newBareFixture(t, "ed25519")
		a, c = f.root, newSigner(t, "ed25519")
		g := f.signDocs(f.genesis(), f.policy(), a)
		f.addBundle(g)
		f.addIssue()
		f.addBundle(f.signDocs(f.successor(g, func(b *trust.Bundle) {
			b.Root = onlyRoot(c)
			if edit != nil {
				edit(b)
			}
		}), f.policy(), v2Signers(a, c)...))
		f.addIssue()
		return f, a, c
	}
	both := func(a, c ssh.Signer) []ssh.Signer { return []ssh.Signer{a, c} }

	cases := []struct {
		name  string
		build func(t *testing.T) (*fixture, []check)
	}{
		{"rotation_new_pins_anchor_v2", func(t *testing.T) (*fixture, []check) {
			f, _, c := rotated(t, nil, both)
			return f, []check{{pins: []ssh.Signer{c}, wantAnchor: 2}}
		}},
		{"rotation_old_pins_anchor_v1", func(t *testing.T) (*fixture, []check) {
			f, a, _ := rotated(t, nil, both)
			return f, []check{{pins: []ssh.Signer{a}, wantAnchor: 1}}
		}},
		{"rotation_twice_pins_middle_anchor_v2", func(t *testing.T) (*fixture, []check) {
			// v3 rotates on from C to D: pins C anchor on v2, and v3 is
			// still checked as v2's successor.
			f := newBareFixture(t, "ed25519")
			a, c, d := f.root, newSigner(t, "ed25519"), newSigner(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), a)
			f.addBundle(g)
			v2 := f.signDocs(f.successor(g, func(b *trust.Bundle) { b.Root = onlyRoot(c) }), f.policy(), a, c)
			f.addBundle(v2)
			v3 := f.successor(v2, func(b *trust.Bundle) { b.Root = onlyRoot(d) })
			v3.Version = 3
			f.addBundle(f.signDocs(v3, f.policy(), c, d))
			f.addIssue()
			return f, []check{
				{pins: []ssh.Signer{a}, wantAnchor: 1},
				{pins: []ssh.Signer{c}, wantAnchor: 2},
				{pins: []ssh.Signer{d}, wantAnchor: 3},
			}
		}},
		{"fork_under_old_pins", func(t *testing.T) (*fixture, []check) {
			// Accepted property, not a bug: root A, exposed, signs a
			// separate genesis with its own log key and CAs. Pins of A
			// anchor whatever A signed, so the fork verifies under them;
			// pins of the new root C refuse it, because no bundle of the
			// fork has C's root set. After rotating away from exposed
			// roots, auditors pin the new roots (root-ceremony.md).
			_, a, c := rotated(t, nil, both)
			fork := newBareFixture(t, "ed25519")
			fork.root = a
			fork.addBundle(fork.signDocs(fork.genesis(), fork.policy(), a))
			fork.addIssue()
			return fork, []check{
				{pins: []ssh.Signer{a}, wantAnchor: 1},
				{pins: []ssh.Signer{c}, want: "not anchored in the pinned roots", why: "pinned root set at threshold 1"},
			}
		}},
		{"v2_not_signed_by_previous_root", func(t *testing.T) (*fixture, []check) {
			f, _, c := rotated(t, nil, func(_, c ssh.Signer) []ssh.Signer { return []ssh.Signer{c} })
			return f, []check{{pins: []ssh.Signer{c}, want: "not a valid successor", why: "(previous roots) signed by 0"}}
		}},
		{"v2_not_signed_by_new_root", func(t *testing.T) (*fixture, []check) {
			// The previous root alone cannot hand trust to a root set
			// that never signed.
			f, a, c := rotated(t, nil, func(a, _ ssh.Signer) []ssh.Signer { return []ssh.Signer{a} })
			return f, []check{
				{pins: []ssh.Signer{c}, want: "not a valid successor", why: "(new roots) signed by 0"},
				{pins: []ssh.Signer{a}, want: "not a valid successor", why: "(new roots) signed by 0"},
			}
		}},
		{"v2_prev_mismatch", func(t *testing.T) (*fixture, []check) {
			f, _, c := rotated(t, func(b *trust.Bundle) { b.Prev = trust.SHA256Hex([]byte("another bundle")) }, both)
			return f, []check{{pins: []ssh.Signer{c}, want: "not a valid successor", why: "is not the previous bundle's SHA-256"}}
		}},
		{"v1_tampered_anchor_v2", func(t *testing.T) (*fixture, []check) {
			// The v1 policy bytes are changed in the log: v1 no longer
			// matches its own policy_sha256.
			f := newBareFixture(t, "ed25519")
			a, c := f.root, newSigner(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), a)
			v2 := f.signDocs(f.successor(g, func(b *trust.Bundle) { b.Root = onlyRoot(c) }), f.policy(), a, c)
			pol := f.policy()
			pol.CAProfiles[0].MaxTTLSeconds = 3600
			tampered := g
			var err error
			if tampered.policy, err = pol.Canonical(); err != nil {
				t.Fatal(err)
			}
			f.addBundle(tampered)
			f.addBundle(v2)
			return f, []check{{pins: []ssh.Signer{c}, want: "not a valid genesis bundle", why: "policy_sha256 does not match"}}
		}},
		{"v1_replaced_and_resigned_anchor_v2", func(t *testing.T) (*fixture, []check) {
			// A holder of the old root A replaces v1 by another genesis
			// it signs (another policy, so other bundle bytes) and keeps
			// the real v2. v1 verifies on its own, but v2's prev names
			// the real v1, so the chain from the anchor breaks.
			f := newBareFixture(t, "ed25519")
			a, c := f.root, newSigner(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), a)
			v2 := f.signDocs(f.successor(g, func(b *trust.Bundle) { b.Root = onlyRoot(c) }), f.policy(), a, c)
			pol := f.policy()
			pol.CAProfiles[0].MaxTTLSeconds = 3600
			f.addBundle(f.signDocs(f.genesis(), pol, a))
			f.addIssue()
			f.addBundle(v2)
			return f, []check{{pins: []ssh.Signer{c}, want: "not a valid successor", why: "is not the previous bundle's SHA-256"}}
		}},
		{"pins_match_no_bundle", func(t *testing.T) (*fixture, []check) {
			f, _, c := rotated(t, nil, both)
			return f, []check{{pins: []ssh.Signer{c, newSigner(t, "ed25519")}, want: "not anchored in the pinned roots", why: "2 pins, 1 roots"}}
		}},
		// G-WR-03: multi-root sets, a root in both sets, duplicate
		// signatures, and a root set that recurs.
		{"two_new_roots_threshold_2_anchor_v2", func(t *testing.T) (*fixture, []check) {
			// v2 names C and D at threshold 2, signed by A, C and D. The
			// anchor must be the exact set at the exact threshold.
			c, d := newSigner(t, "ed25519"), newSigner(t, "ed25519")
			f, a := rotatedTo(t, func(a ssh.Signer) (trust.RootSet, []ssh.Signer) {
				return rootSet(2, c, d), []ssh.Signer{a, c, d}
			})
			return f, []check{
				{pins: []ssh.Signer{c, d}, threshold: 2, wantAnchor: 2},
				{pins: []ssh.Signer{d, c}, threshold: 2, wantAnchor: 2},
				{pins: []ssh.Signer{c, d}, threshold: 1, want: "not anchored in the pinned roots", why: "bundle threshold 2, pinned threshold 1"},
				{pins: []ssh.Signer{c}, threshold: 1, want: "not anchored in the pinned roots", why: "1 pins, 2 roots"},
				{pins: []ssh.Signer{a}, wantAnchor: 1},
			}
		}},
		{"two_new_roots_threshold_2_one_signed", func(t *testing.T) (*fixture, []check) {
			c, d := newSigner(t, "ed25519"), newSigner(t, "ed25519")
			f, _ := rotatedTo(t, func(a ssh.Signer) (trust.RootSet, []ssh.Signer) {
				return rootSet(2, c, d), []ssh.Signer{a, c}
			})
			return f, []check{{pins: []ssh.Signer{c, d}, threshold: 2, want: "not a valid successor", why: "(new roots) signed by 1 of 2 roots, need 2"}}
		}},
		{"duplicate_signature_toward_threshold_2", func(t *testing.T) (*fixture, []check) {
			// C's signature appears twice on both documents; it counts once.
			c, d := newSigner(t, "ed25519"), newSigner(t, "ed25519")
			f, _ := rotatedTo(t, func(a ssh.Signer) (trust.RootSet, []ssh.Signer) {
				return rootSet(2, c, d), []ssh.Signer{a, c, c}
			})
			return f, []check{{pins: []ssh.Signer{c, d}, threshold: 2, want: "not a valid successor", why: "(new roots) signed by 1 of 2 roots, need 2"}}
		}},
		{"root_in_both_sets_counts_toward_both", func(t *testing.T) (*fixture, []check) {
			// v2 keeps A and adds C at threshold 1. A's signature alone
			// meets the previous AND the new threshold (G-WR-02): C is
			// listed without ever signing.
			c := newSigner(t, "ed25519")
			f, a := rotatedTo(t, func(a ssh.Signer) (trust.RootSet, []ssh.Signer) {
				return rootSet(1, a, c), []ssh.Signer{a}
			})
			return f, []check{
				{pins: []ssh.Signer{a, c}, wantAnchor: 2},
				{pins: []ssh.Signer{a}, wantAnchor: 1},
			}
		}},
		{"root_in_both_sets_threshold_2", func(t *testing.T) (*fixture, []check) {
			// v2 keeps A and adds C at threshold 2: A alone meets the
			// previous threshold but not the new one.
			c := newSigner(t, "ed25519")
			alone, _ := rotatedTo(t, func(a ssh.Signer) (trust.RootSet, []ssh.Signer) {
				return rootSet(2, a, c), []ssh.Signer{a}
			})
			if _, err := Verify(strings.NewReader(join(alone.lines())), Options{Pins: []string{ssh.FingerprintSHA256(alone.root.PublicKey())}, Threshold: 1}); err == nil ||
				!strings.Contains(err.Error(), "(new roots) signed by 1 of 2 roots, need 2") {
				t.Fatalf("v2 {A, C} at threshold 2 signed by A alone: Verify error = %v, want the new roots' threshold refusal", err)
			}
			f, a := rotatedTo(t, func(a ssh.Signer) (trust.RootSet, []ssh.Signer) {
				return rootSet(2, a, c), []ssh.Signer{a, c}
			})
			return f, []check{
				{pins: []ssh.Signer{a, c}, threshold: 2, wantAnchor: 2},
				{pins: []ssh.Signer{a, c}, threshold: 1, want: "not anchored in the pinned roots", why: "bundle threshold 2, pinned threshold 1"},
			}
		}},
		{"root_set_recurs_first_match_anchors", func(t *testing.T) (*fixture, []check) {
			// v1 {A} -> v2 {C} -> v3 {A}: pins A anchor on the first bundle
			// with that root set, v1.
			f := newBareFixture(t, "ed25519")
			a, c := f.root, newSigner(t, "ed25519")
			g := f.signDocs(f.genesis(), f.policy(), a)
			f.addBundle(g)
			v2 := f.signDocs(f.successor(g, func(b *trust.Bundle) { b.Root = onlyRoot(c) }), f.policy(), a, c)
			f.addBundle(v2)
			v3 := f.successor(v2, func(b *trust.Bundle) { b.Root = onlyRoot(a) })
			v3.Version = 3
			f.addBundle(f.signDocs(v3, f.policy(), c, a))
			f.addIssue()
			return f, []check{
				{pins: []ssh.Signer{a}, wantAnchor: 1},
				{pins: []ssh.Signer{c}, wantAnchor: 2},
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, checks := tc.build(t)
			export := join(f.lines())
			for _, ch := range checks {
				threshold := ch.threshold
				if threshold == 0 {
					threshold = 1
				}
				rep, err := Verify(strings.NewReader(export), Options{Pins: pinsOf(ch.pins...), Threshold: threshold})
				if ch.want != "" {
					if err == nil {
						t.Fatalf("pins %v: Verify accepted the log, anchored on v%d", pinsOf(ch.pins...), rep.AnchorVersion)
					}
					for _, w := range []string{ch.want, ch.why} {
						if !strings.Contains(err.Error(), w) {
							t.Fatalf("pins %v: Verify error = %q, want it to mention %q", pinsOf(ch.pins...), err, w)
						}
					}
					continue
				}
				if err != nil {
					t.Fatalf("pins %v: Verify: %v", pinsOf(ch.pins...), err)
				}
				if rep.AnchorVersion != ch.wantAnchor {
					t.Fatalf("pins %v: anchored on trust bundle v%d, want v%d", pinsOf(ch.pins...), rep.AnchorVersion, ch.wantAnchor)
				}
			}
		})
	}
}

// TestVerifyKindsWithoutChecks: from plan 02-01 until 02-04, audit verify
// refused every directory_install and login_issue leaf with "not
// verifiable by this version" (T-02-115), and from 03-01 until 03-03 every
// revoke and krl_publish leaf (T-03-07). Plans 02-04 and 03-03 gave those
// kinds real checks; these cases keep the interim leaves, whose bodies
// only encode (the directory bytes are no directory, the request bytes
// prove nothing), and show that the interim refusal was replaced by a
// check, not by a pass:
// Verify still returns an error and no report, the error names the entry
// and its kind, and it is not the interim text. Each export carries a
// checkpoint correctly signed over all its leaves. The control shows every
// Phase 1 kind still verifies.
func TestVerifyKindsWithoutChecks(t *testing.T) {
	encode := func(t *testing.T, b interface{ Encode() ([]byte, error) }) []byte {
		t.Helper()
		out, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		kind tlog.Kind
		body func(t *testing.T) []byte
		want string // the check that must refuse it ("": any but the interim refusal)
	}{
		{"directory_install_unproven_refused", tlog.KindDirectoryInstall, func(t *testing.T) []byte {
			return encode(t, &tlog.DirectoryInstallBody{Version: 1, PolicyVersion: 1, Directory: []byte("not a directory"), Sigs: []byte("no signatures")})
		}, ""},
		{"login_issue_unproven_refused", tlog.KindLoginIssue, func(t *testing.T) []byte {
			return encode(t, &tlog.LoginIssueBody{Serial: 1 << 60, PolicyVersion: 1, DirectoryVersion: 1, Request: []byte("request"),
				Evidence: []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: []byte("assertion")}}, Cert: []byte("cert"), KeyID: "kr2"})
		}, "logged request: "},
		// From 03-01 until 03-03 the default branch refused these two kinds
		// (T-03-07); 03-03 gave them real checks.
		{"revoke_unproven_refused", tlog.KindRevoke, func(t *testing.T) []byte {
			return encode(t, &tlog.RevokeBody{PolicyVersion: 1, ResolvedAtSeconds: 1, Request: []byte("request"),
				Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sig")}},
				Entries:  []tlog.RevokedEntry{{Kind: tlog.RevokedSerial, CAKey: []byte("ca"), Serial: 1}}})
		}, "logged request: "},
		{"krl_publish_unproven_refused", tlog.KindKRLPublish, func(t *testing.T) []byte {
			return encode(t, &tlog.KRLPublishBody{KRLVersion: 1, BundleVersion: 1, Manifest: []byte("manifest"), Sig: []byte("sig")})
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := standard(t, "ed25519")
			idx := len(f.leaves)
			f.add(tc.kind, tc.body(t))
			rep, err := f.verify(join(f.lines()), nil)
			if err == nil || rep != nil {
				t.Fatalf("Verify = %+v, %v; want no report and the refusal of entry %d", rep, err, idx)
			}
			if prefix := fmt.Sprintf("audit: entry %d (%s): ", idx, tc.kind); !strings.HasPrefix(err.Error(), prefix) {
				t.Fatalf("error %q, want it to start with %q", err, prefix)
			}
			if strings.Contains(err.Error(), "not verifiable by this version") {
				t.Fatalf("error %q is the interim refusal, not a check of the %s entry", err, tc.kind)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, want the check %q", err, tc.want)
			}
			t.Logf("refused by its check: %v", err)
		})
	}
	t.Run("phase1_kinds_still_verify", func(t *testing.T) {
		f := standard(t, "ed25519")
		f.add(tlog.KindCAInit, encode(t, &tlog.CAInitBody{Keys: []tlog.CAInitKey{{Role: "log", PublicKey: []byte{1}, Alg: "ssh-ed25519", Custody: "agent"}}}))
		f.add(tlog.KindClockRegression, encode(t, &tlog.ClockRegressionBody{NowMicros: 1, HighWaterMicros: 2}))
		f.add(tlog.KindRefusalSummary, encode(t, &tlog.RefusalSummaryBody{WindowStartMicros: 1, WindowEndMicros: 2,
			Counts: []tlog.ReasonCount{{Reason: tlog.ReasonMalformed, Count: 3}}}))
		rep, err := f.verify(join(f.lines()), nil)
		if err != nil {
			t.Fatalf("Verify of a log of Phase 1 kinds: %v", err)
		}
		for _, k := range []tlog.Kind{tlog.KindIssue, tlog.KindRefusal, tlog.KindRefusalSummary, tlog.KindClockRegression, tlog.KindCAInit, tlog.KindBundleInstall} {
			if rep.Counts[k] < 1 {
				t.Fatalf("report counts no %s leaf: %+v", k, rep.Counts)
			}
		}
	})
}

// The relying party of the audit login fixtures.
const (
	auditRPID   = "keyroster.example.org"
	auditOrigin = "https://keyroster.example.org"
)

// loginFixture is a fixture whose log also holds directory_install and
// login_issue entries, built with the real directory, webauthn, wire, cert
// and certprofile packages the way the signer writes them (internal/signer
// InstallDirectory and LoginIssue). Like every fixture, its export carries
// a checkpoint signed with the test's own log key over all its leaves, so a
// tampered entry is caught only by the entry checks, never by the
// checkpoint: it models a compromised signer that holds the log key.
type loginFixture struct {
	*fixture
	docs       docs          // the bundle and policy in force
	pol        *trust.Policy // the policy in force
	alice, bob *webauthntest.Authenticator
	dirRaw     []byte // the directory in force
	dirVersion uint64
}

// loginPolicy is the fixture policy, with the WebAuthn RP when withRP and a
// user CA profile that also allows agent and port forwarding as extras and
// the source-address critical option, so cases can tamper with them.
func (f *fixture) loginPolicy(withRP bool) *trust.Policy {
	p := f.policy()
	p.CAProfiles[0].AllowedExtensions = []string{"permit-agent-forwarding", "permit-port-forwarding"}
	p.CAProfiles[0].AllowedCriticalOptions = []string{"source-address"}
	if withRP {
		p.WebAuthn = &trust.WebAuthnRP{RPID: auditRPID, Origins: []string{auditOrigin}}
	}
	return p
}

// newLoginFixture is a log that starts with the genesis bundle_install
// entry under loginPolicy(withRP), on a whole second, with soft
// authenticators for alice (EdDSA) and bob (ES256).
func newLoginFixture(t testing.TB, withRP bool) *loginFixture {
	t.Helper()
	return newLoginFixtureRoot(t, withRP, nil)
}

// newLoginFixtureRoot is newLoginFixture with root as the genesis root
// (nil: a new one).
func newLoginFixtureRoot(t testing.TB, withRP bool, root ssh.Signer) *loginFixture {
	t.Helper()
	f := newBareFixtureAt(t, "ed25519", time.Now().Truncate(time.Second))
	if root != nil {
		f.root = root
	}
	lf := &loginFixture{fixture: f, pol: f.loginPolicy(withRP)}
	lf.docs = f.signDocs(f.genesis(), lf.pol, f.root)
	f.addBundle(lf.docs)
	var err error
	if lf.alice, err = webauthntest.New(webauthn.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	if lf.bob, err = webauthntest.New(webauthn.AlgES256); err != nil {
		t.Fatal(err)
	}
	return lf
}

// installPolicy logs a successor bundle (the same roots, CAs and log key,
// signed by the fixture root) whose policy is the successor of the policy
// in force (version + 1, prev = its SHA-256), changed by edit.
func (lf *loginFixture) installPolicy(edit func(*trust.Policy)) {
	lf.t.Helper()
	prev, err := trust.ParseBundle(lf.docs.bundle)
	if err != nil {
		lf.t.Fatal(err)
	}
	next := *prev
	next.Version, next.Prev = prev.Version+1, trust.SHA256Hex(lf.docs.bundle)
	p := *lf.pol
	p.Version, p.Prev = lf.pol.Version+1, trust.SHA256Hex(lf.docs.policy)
	edit(&p)
	lf.docs = lf.signDocs(&next, &p, lf.root)
	lf.addBundle(lf.docs)
	lf.pol = &p
}

// directory returns the next directory version, chained to the directory
// in force: alice (her EdDSA credential) holds role ops (principal
// role:ops, 3600 s, extension permit-agent-forwarding), bob (his ES256
// credential) role dev (role:dev, 1800 s). edit changes it before Sort.
func (lf *loginFixture) directory(edit func(*directory.Directory)) *directory.Directory {
	prev := trust.GenesisPrev
	if lf.dirRaw != nil {
		prev = trust.SHA256Hex(lf.dirRaw)
	}
	cred := func(a *webauthntest.Authenticator) []directory.Credential {
		c := a.Credential()
		return []directory.Credential{{ID: base64.RawURLEncoding.EncodeToString(c.ID), Alg: c.Alg, SPKI: base64.StdEncoding.EncodeToString(c.SPKI)}}
	}
	d := &directory.Directory{
		Version: lf.dirVersion + 1,
		Prev:    prev,
		Users: []directory.User{
			{Name: "alice", Status: directory.StatusActive, Credentials: cred(lf.alice)},
			{Name: "bob", Status: directory.StatusActive, Credentials: cred(lf.bob)},
		},
		Roles: []directory.Role{
			{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600, Extensions: []string{"permit-agent-forwarding"}, Users: []string{"alice"}},
			{Name: "dev", Principals: []string{"role:dev"}, MaxTTLSeconds: 1800, Users: []string{"bob"}},
		},
	}
	if edit != nil {
		edit(d)
	}
	d.Sort()
	return d
}

// role returns d's role name, for edits.
func role(d *directory.Directory, name string) *directory.Role {
	for i := range d.Roles {
		if d.Roles[i].Name == name {
			return &d.Roles[i]
		}
	}
	panic("no role " + name)
}

// addDirectory logs a directory_install entry for d, signed by signers
// (default: the policy admin) under the policy in force, with the body
// changed by edit, and makes d the directory in force.
func (lf *loginFixture) addDirectory(d *directory.Directory, edit func(*tlog.DirectoryInstallBody), signers ...ssh.Signer) {
	lf.t.Helper()
	doc, err := d.Canonical()
	if err != nil {
		lf.t.Fatal(err)
	}
	if len(signers) == 0 {
		signers = []ssh.Signer{lf.admin}
	}
	var sigs []byte
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, directory.Namespace, doc)
		if err != nil {
			lf.t.Fatal(err)
		}
		sigs = append(sigs, sig...)
	}
	b := &tlog.DirectoryInstallBody{Version: d.Version, PolicyVersion: lf.pol.Version, Directory: doc, Sigs: sigs}
	if edit != nil {
		edit(b)
	}
	body, err := b.Encode()
	if err != nil {
		lf.t.Fatal(err)
	}
	lf.add(tlog.KindDirectoryInstall, body)
	lf.dirRaw, lf.dirVersion = doc, d.Version
}

// login is one login issuance as the fixture builds it, in the order of
// the signer's steps. A case changes it before the assertion (pre: what
// the user's passkey then approves) or after it (post: what a compromised
// signer logs on its own).
type login struct {
	req        *wire.LoginIssueRequest
	auth       *webauthntest.Authenticator // signs the assertion (default alice's)
	bob        *webauthntest.Authenticator // bob's, for cases that use it
	assertion  *wire.WebAuthnAssertion
	evidence   []wire.Evidence // nil: the assertion as the only item
	ca         ssh.Signer      // nil: the user CA
	certKey    ssh.PublicKey
	principals []string // the certificate's
	validFor   time.Duration
	keyID      cert.KeyID
	extra      map[string]string
	critical   map[string]string
	serial     uint64
	issued     time.Time // the certificate's issuance time (zero: issuedAt(serial))
	dirVersion uint64
	polVersion uint64
	// request is what the entry logs as the request (nil: the request's
	// SigningBytes, as the signer logs it).
	request []byte
}

// leafSecs is the whole-second time of the next leaf.
func (lf *loginFixture) leafSecs() uint64 { return (lf.micros + 1) / 1e6 }

// addLogin logs a login_issue entry: by default alice's request for all
// her roles (principals [role:ops], 600 s, created at the entry time)
// approved by her passkey, and the certificate cert.Build gives the user
// CA for it under the policy and directory in force, with the next serial.
// It returns the login as logged.
func (lf *loginFixture) addLogin(pre, post func(*login)) *login {
	lf.t.Helper()
	key := newSigner(lf.t, "ed25519").PublicKey()
	l := &login{
		req: &wire.LoginIssueRequest{SubjectKey: key.Marshal(), Subject: "alice", Principals: []string{"role:ops"},
			ValidForSeconds: 600, CreatedAt: lf.leafSecs()},
		auth: lf.alice, bob: lf.bob, certKey: key, serial: lf.serial + 1, dirVersion: lf.dirVersion, polVersion: lf.pol.Version,
	}
	if _, err := rand.Read(l.req.RequestID[:]); err != nil {
		lf.t.Fatal(err)
	}
	if pre != nil {
		pre(l)
	}
	a := l.auth.Assert(auditRPID, auditOrigin, l.req.Digest())
	l.assertion = &wire.WebAuthnAssertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}
	roles := []string{"ops"}
	if d, err := directory.Parse(lf.dirRaw); err == nil {
		if g, err := d.Authorize(l.req.Subject, l.req.Roles); err == nil {
			roles = g.Roles
		}
	}
	profile, err := certprofile.ForRole(trust.RoleUser, lf.pol)
	if err != nil {
		lf.t.Fatal(err)
	}
	l.principals = slices.Clone(l.req.Principals)
	l.validFor = time.Duration(l.req.ValidForSeconds) * time.Second
	l.keyID = cert.KeyID{CA: "user", Subject: l.req.Subject, Request: hex.EncodeToString(l.req.RequestID[:]),
		Policy: l.polVersion, Directory: l.dirVersion, Roles: roles}
	l.extra = map[string]string{}
	for _, e := range l.req.Extensions {
		if _, isDefault := profile.DefaultExtensions[e]; !isDefault {
			l.extra[e] = ""
		}
	}
	if post != nil {
		post(l)
	}
	l.keyID.Serial = l.serial
	ca := l.ca
	if ca == nil {
		ca = lf.ca
	}
	issued := l.issued
	if issued.IsZero() {
		issued = issuedAt(l.serial)
	}
	c, err := cert.Build(cert.Request{Profile: profile, Subject: l.certKey, Principals: l.principals, Now: issued,
		ValidFor: l.validFor, KeyID: l.keyID, Serial: l.serial, ExtraExtensions: l.extra, CriticalOptions: l.critical}, ca, rand.Reader)
	if err != nil {
		lf.t.Fatal(err)
	}
	evidence := l.evidence
	if evidence == nil {
		blob, err := l.assertion.Marshal()
		if err != nil {
			lf.t.Fatal(err)
		}
		evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}}
	}
	request := l.request
	if request == nil {
		request = l.req.SigningBytes()
	}
	body, err := (&tlog.LoginIssueBody{Serial: l.serial, PolicyVersion: l.polVersion, DirectoryVersion: l.dirVersion,
		Request: request, Evidence: evidence, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
	if err != nil {
		lf.t.Fatal(err)
	}
	lf.add(tlog.KindLoginIssue, body)
	lf.serial = max(lf.serial, l.serial)
	return l
}

// paddedKey is an ssh-rsa key blob that parses but is not canonical, and
// the key it denotes.
type paddedKey struct {
	blob []byte
	key  ssh.PublicKey
}

// nonCanonicalRSAKey returns a fresh 3072-bit ssh-rsa key whose exponent
// mpint carries a superfluous leading zero byte (00 01 00 01).
// ssh.ParsePublicKey accepts it and its Marshal is one byte shorter; both
// are checked, so a case that uses it cannot pass vacuously.
func nonCanonicalRSAKey(t testing.TB) paddedKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Name string
		E    []byte
		N    *big.Int
	}{ssh.KeyAlgoRSA, []byte{0, 1, 0, 1}, k.N})
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatalf("the padded RSA key does not parse: %v", err)
	}
	if bytes.Equal(pub.Marshal(), blob) || k.E != 65537 {
		t.Fatal("the padded RSA key is canonical")
	}
	return paddedKey{blob: blob, key: pub}
}

// addIssueWithRequest logs an admin issue entry under the policy in force
// whose kr1 key ID names request ID reqHex, with the next serial.
func (lf *loginFixture) addIssueWithRequest(reqHex string) {
	lf.t.Helper()
	lf.serial++
	keyID := cert.KeyID{CA: "user", Subject: "u:alice", Request: reqHex, Policy: lf.pol.Version, Serial: lf.serial}
	c, err := cert.Build(cert.Request{Profile: cert.DefaultUserProfile(), Subject: newSigner(lf.t, "ed25519").PublicKey(),
		Principals: []string{"alice"}, Now: issuedAt(lf.serial), ValidFor: time.Hour, KeyID: keyID, Serial: lf.serial}, lf.ca, rand.Reader)
	if err != nil {
		lf.t.Fatal(err)
	}
	body, err := (&tlog.IssueBody{CARole: uint8(wire.CARoleUser), Serial: lf.serial, PolicyVersion: lf.pol.Version, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
	if err != nil {
		lf.t.Fatal(err)
	}
	lf.add(tlog.KindIssue, body)
}

// TestVerifyLoginTampering (KEY-02, T-02-17, T-02-18, T-02-84): audit
// verify re-proves every directory_install and login_issue entry from the
// log. Each case builds a valid log in process with the real packages and
// then changes one thing as a compromised signer could: it holds the CA
// key and the log key, so every checkpoint is re-signed over the changed
// entries, and only the entry checks can catch it. Each tampered case must
// fail with its named check; the controls (want "") verify.
func TestVerifyLoginTampering(t *testing.T) {
	// base is a log with the RP policy and directory v1 installed.
	base := func(t *testing.T) *loginFixture {
		lf := newLoginFixture(t, true)
		lf.addDirectory(lf.directory(nil), nil)
		return lf
	}
	// oneLogin is base plus one login changed by pre and post.
	oneLogin := func(pre, post func(*login)) func(t *testing.T) *loginFixture {
		return func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addLogin(pre, post)
			return lf
		}
	}
	other := func(t *testing.T) ssh.Signer { return newSigner(t, "ed25519") }
	stranger := newSigner(t, "ed25519").PublicKey()
	rsaPadded := nonCanonicalRSAKey(t)
	widened := []string{"role:ops", "root"}
	cases := []struct {
		name  string
		build func(t *testing.T) *loginFixture
		want  string // "" = must verify
		check func(t *testing.T, rep *Report)
	}{
		// Controls.
		{name: "login_ok", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addLogin(nil, nil)
			lf.addLogin(nil, nil)
			return lf
		}, check: func(t *testing.T, rep *Report) {
			if rep.Counts[tlog.KindLoginIssue] != 2 || rep.Counts[tlog.KindDirectoryInstall] != 1 || rep.Serials != 0 || rep.IssuedByCA["user"] != 0 {
				t.Fatalf("report %+v: want 2 login certificates, 1 directory install, and no issue entries counted as issued", rep)
			}
		}},
		{name: "login_named_role_ok", build: oneLogin(func(l *login) { l.req.Roles = []string{"ops"} }, nil)},
		{name: "login_granted_extension_ok", build: oneLogin(func(l *login) { l.req.Extensions = []string{"permit-agent-forwarding"} }, nil)},
		{name: "login_bob_ok", build: oneLogin(func(l *login) {
			l.auth, l.req.Subject, l.req.Principals, l.req.ValidForSeconds = l.bob, "bob", []string{"role:dev"}, 1800
		}, nil)},
		{name: "login_created_300s_before_ok", build: oneLogin(func(l *login) { l.req.CreatedAt -= 300 }, nil)},
		{name: "login_created_300s_after_ok", build: oneLogin(func(l *login) { l.req.CreatedAt += 300 }, nil)},
		{name: "login_ttl_at_role_cap_ok", build: oneLogin(func(l *login) { l.req.ValidForSeconds = 3600 }, nil)},

		// The passkey authorization.
		{name: "login_assertion_bit_flip", build: oneLogin(nil, func(l *login) { l.assertion.Signature[7] ^= 0x10 }),
			want: `(login_issue): passkey assertion of user "alice" does not approve the logged request: webauthn: assertion signature does not verify`},
		{name: "login_principals_widened_after_approval", build: oneLogin(nil, func(l *login) { l.req.Principals, l.principals = widened, widened }),
			want: `(login_issue): passkey assertion of user "alice" does not approve the logged request: webauthn: challenge mismatch`},
		{name: "login_other_users_credential", build: oneLogin(func(l *login) { l.auth = l.bob }, nil), want: "(login_issue): directory v1 binds no credential"},
		{name: "login_two_evidence_items", build: oneLogin(nil, func(l *login) {
			blob, _ := l.assertion.Marshal()
			l.evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}, {Type: wire.EvidenceWebAuthnAssertion, Blob: blob}}
		}), want: "(login_issue): entry carries 2 evidence items, want exactly one webauthn-assertion/v1"},
		{name: "login_admin_evidence", build: oneLogin(nil, func(l *login) {
			l.evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sshsig")}}
		}), want: `(login_issue): evidence type "admin-sshsig/v1", want webauthn-assertion/v1`},
		{name: "login_assertion_unparseable", build: oneLogin(nil, func(l *login) {
			l.evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: []byte("not an assertion")}}
		}), want: "(login_issue): passkey assertion does not parse"},
		{name: "login_without_rp", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, false)
			lf.addDirectory(lf.directory(nil), nil)
			lf.addLogin(nil, nil)
			return lf
		}, want: "(login_issue): policy v1 has no WebAuthn relying party"},

		// The directory grant.
		{name: "login_principals_widened", build: oneLogin(func(l *login) { l.req.Principals = widened }, nil),
			want: `(login_issue): request principals ["role:ops" "root"] differ from what directory v1 grants for roles ["ops"]: ["role:ops"]`},
		{name: "login_unknown_user", build: oneLogin(func(l *login) { l.req.Subject = "mallory" }, nil),
			want: `(login_issue): directory v1 grants no login to user "mallory"`},
		{name: "login_disabled_user", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, true)
			lf.addDirectory(lf.directory(func(d *directory.Directory) { d.Users[0].Status = directory.StatusDisabled }), nil)
			lf.addLogin(nil, nil)
			return lf
		}, want: `(login_issue): directory v1 grants no login to user "alice"`},
		{name: "login_role_not_granted", build: oneLogin(func(l *login) { l.req.Roles = []string{"dev"} }, nil),
			want: `(login_issue): directory v1 grants no login to user "alice" for roles ["dev"]`},
		{name: "login_ttl_above_role", build: oneLogin(func(l *login) { l.req.ValidForSeconds = 3601 }, nil),
			want: "(login_issue): request TTL 3601 s is above the cap: role 3600 s, user CA profile 43200 s"},
		{name: "login_extension_not_granted", build: oneLogin(func(l *login) { l.req.Extensions = []string{"permit-port-forwarding"} }, nil),
			want: `(login_issue): request extension "permit-port-forwarding" is not granted by roles ["ops"]`},
		{name: "login_extension_twice", build: oneLogin(func(l *login) {
			l.req.Extensions = []string{"permit-agent-forwarding", "permit-agent-forwarding"}
		}, nil), want: `(login_issue): request names extension "permit-agent-forwarding" twice`},

		// The directory and policy in force.
		{name: "login_under_never_installed_directory", build: oneLogin(func(l *login) { l.dirVersion = 2 }, nil),
			want: "(login_issue): entry records directory version 2, but the directory in force is version 1"},
		{name: "login_before_any_directory", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, true)
			lf.addLogin(nil, nil)
			return lf
		}, want: "(login_issue): entry records directory version 0, but no directory is installed"},
		{name: "login_policy_version_wrong", build: oneLogin(func(l *login) { l.polVersion = 2 }, nil),
			want: "(login_issue): entry records policy version 2, but the policy in force is version 1"},
		{name: "login_under_unauthorized_directory", build: func(t *testing.T) *loginFixture {
			// Policy v2 replaces the admin who signed directory v1: v1
			// stays in force but is no longer authorized.
			lf := base(t)
			carol := other(t)
			lf.installPolicy(func(p *trust.Policy) {
				p.Admins = []trust.AdminKey{{Name: "carol", Key: trust.FormatKey(carol.PublicKey())}}
			})
			lf.addLogin(nil, nil)
			return lf
		}, want: "(login_issue): the directory in force (v1) is not authorized under the policy in force: directory v1 is not signed by the admin quorum of policy v2"},
		{name: "login_under_directory_above_new_cap", build: func(t *testing.T) *loginFixture {
			// Policy v2 lowers the user CA cap below role ops's 3600 s.
			lf := base(t)
			lf.installPolicy(func(p *trust.Policy) {
				p.CAProfiles = slices.Clone(p.CAProfiles)
				p.CAProfiles[0].MaxTTLSeconds = 1800
			})
			lf.addLogin(nil, nil)
			return lf
		}, want: "(login_issue): the directory in force (v1) is not authorized under the policy in force: directory v1 is outside the user CA profile of policy v2"},
		{name: "login_after_resigned_directory_ok", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			carol := other(t)
			lf.installPolicy(func(p *trust.Policy) {
				p.Admins = []trust.AdminKey{{Name: "carol", Key: trust.FormatKey(carol.PublicKey())}}
			})
			lf.addDirectory(lf.directory(nil), nil, carol)
			lf.addLogin(nil, nil)
			return lf
		}},
		{name: "login_directory_survives_rp_policy_change", build: func(t *testing.T) *loginFixture {
			// T-02-84 (02-04-F2): directory v1 installed under policy v1
			// without RP; policy v2 changes only the version, prev and
			// RP; a login under dir=1, pol=2; directory v2 under pol=2;
			// a login under dir=2, pol=2.
			lf := newLoginFixture(t, false)
			lf.addDirectory(lf.directory(nil), nil)
			lf.installPolicy(func(p *trust.Policy) {
				p.WebAuthn = &trust.WebAuthnRP{RPID: auditRPID, Origins: []string{auditOrigin}}
			})
			if l := lf.addLogin(nil, nil); l.dirVersion != 1 || l.polVersion != 2 {
				t.Fatalf("first login under dir=%d pol=%d, want dir=1 pol=2", l.dirVersion, l.polVersion)
			}
			lf.addDirectory(lf.directory(nil), nil)
			if l := lf.addLogin(nil, nil); l.dirVersion != 2 || l.polVersion != 2 {
				t.Fatalf("second login under dir=%d pol=%d, want dir=2 pol=2", l.dirVersion, l.polVersion)
			}
			return lf
		}, check: func(t *testing.T, rep *Report) {
			if rep.Counts[tlog.KindLoginIssue] != 2 || rep.Counts[tlog.KindDirectoryInstall] != 2 || rep.PolicyVersion != 2 || rep.BundleVersion != 2 {
				t.Fatalf("report %+v: want 2 login certificates and 2 directory installs under bundle v2, policy v2", rep)
			}
		}},

		// directory_install entries.
		{name: "directory_install_non_admin", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, true)
			lf.addDirectory(lf.directory(nil), nil, other(t))
			return lf
		}, want: "(directory_install): directory v1 is not signed by the admin quorum of policy v1"},
		{name: "directory_prev_wrong", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addDirectory(lf.directory(func(d *directory.Directory) { d.Prev = trust.SHA256Hex([]byte("not the directory in force")) }), nil)
			return lf
		}, want: "(directory_install): directory v2 is not the successor of the directory in force (v1)"},
		{name: "directory_version_skipped", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addDirectory(lf.directory(func(d *directory.Directory) { d.Version = 3 }), nil)
			return lf
		}, want: "(directory_install): directory v3 is not the successor of the directory in force (v1)"},
		{name: "directory_first_not_v1", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, true)
			lf.addDirectory(lf.directory(func(d *directory.Directory) { d.Version = 2 }), nil)
			return lf
		}, want: "(directory_install): directory v2 is not the successor of the directory in force (v0)"},
		{name: "directory_role_ttl_above_user_cap", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, true)
			lf.addDirectory(lf.directory(func(d *directory.Directory) { role(d, "ops").MaxTTLSeconds = 43201 }), nil)
			return lf
		}, want: "(directory_install): directory v1 is outside the user CA profile of policy v1"},
		{name: "directory_policy_version_wrong", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, true)
			lf.addDirectory(lf.directory(nil), func(b *tlog.DirectoryInstallBody) { b.PolicyVersion = 2 })
			return lf
		}, want: "(directory_install): entry records policy version 2, but the policy in force is version 1"},
		{name: "directory_version_mismatch", build: func(t *testing.T) *loginFixture {
			lf := newLoginFixture(t, true)
			lf.addDirectory(lf.directory(nil), func(b *tlog.DirectoryInstallBody) { b.Version = 2 })
			return lf
		}, want: "(directory_install): entry records directory version 2, but its document is version 1"},
		{name: "directory_before_bundle", build: func(t *testing.T) *loginFixture {
			f := newBareFixture(t, "ed25519")
			lf := &loginFixture{fixture: f, pol: f.loginPolicy(true)}
			var err error
			if lf.alice, err = webauthntest.New(webauthn.AlgEdDSA); err != nil {
				t.Fatal(err)
			}
			lf.bob = lf.alice
			lf.addDirectory(lf.directory(nil), nil)
			return lf
		}, want: "(directory_install): directory_install before the first bundle_install"},
		{name: "login_before_bundle", build: func(t *testing.T) *loginFixture {
			// A login_issue as the log's first entry: no root-signed
			// policy is in force to check it against.
			f := newBareFixture(t, "ed25519")
			lf := &loginFixture{fixture: f, pol: f.loginPolicy(true)}
			var err error
			if lf.alice, err = webauthntest.New(webauthn.AlgEdDSA); err != nil {
				t.Fatal(err)
			}
			lf.bob = lf.alice
			lf.addLogin(nil, nil)
			return lf
		}, want: "(login_issue): login_issue before the first bundle_install"},
		{name: "login_request_not_signing_bytes", build: oneLogin(nil, func(l *login) {
			// The wire body (fields and evidence, no domain tag) logged
			// instead of the signing bytes the passkey approved.
			body, err := l.req.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			l.request = body
		}), want: "(login_issue): logged request: "},

		// The certificate.
		{name: "login_cert_key_not_subject", build: oneLogin(nil, func(l *login) { l.certKey = stranger }),
			want: "(login_issue): certificate key SHA256:"},
		// A subject key that parses but is not canonically encoded denotes
		// exactly one key: the certificate carries that key's canonical
		// encoding, and the log verifies (an entry from a signer that did
		// not yet refuse such a key). A certificate for another key is
		// still refused.
		{name: "login_rsa_non_canonical_subject_key_ok", build: oneLogin(func(l *login) {
			l.req.SubjectKey, l.certKey = rsaPadded.blob, rsaPadded.key
		}, nil)},
		{name: "login_rsa_non_canonical_subject_key_cert_key_not_subject", build: oneLogin(func(l *login) {
			l.req.SubjectKey = rsaPadded.blob
		}, nil), want: "(login_issue): certificate key SHA256:"},
		{name: "login_subject_key_unparseable", build: oneLogin(func(l *login) { l.req.SubjectKey = []byte("not a key") }, nil),
			want: "(login_issue): request subject key does not parse:"},
		{name: "login_cert_principals_differ", build: oneLogin(nil, func(l *login) { l.principals = widened }),
			want: `(login_issue): certificate principals ["role:ops" "root"] differ from the request's ["role:ops"]`},
		{name: "login_cert_span_wrong", build: oneLogin(nil, func(l *login) { l.validFor = 3600 * time.Second }),
			want: "(login_issue): certificate spans 3900 s, but cert.Build gives 900 s for the requested 600 s"},
		{name: "login_cert_extra_extension", build: oneLogin(nil, func(l *login) { l.extra["permit-port-forwarding"] = "" }),
			want: "(login_issue): certificate extensions"},
		{name: "login_cert_critical_option", build: oneLogin(nil, func(l *login) { l.critical = map[string]string{"source-address": "192.0.2.0/24"} }),
			want: `(login_issue): certificate carries critical options ["source-address"]`},
		{name: "login_cert_by_host_ca", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addLogin(nil, func(l *login) { l.ca = lf.hostCA })
			return lf
		}, want: "(login_issue): certificate for CA role user signed by"},
		{name: "login_kr1_key_id", build: oneLogin(nil, func(l *login) { l.keyID.Roles, l.keyID.Directory = nil, 0 }),
			want: "(login_issue): a login_issue entry must carry a kr2 key ID, not kr1"},
		{name: "login_kr2_roles_not_grant", build: oneLogin(nil, func(l *login) { l.keyID.Roles = []string{"dev", "ops"} }),
			want: `(login_issue): key ID roles ["dev" "ops"] differ from the roles the directory grants ["ops"]`},
		{name: "login_kr2_subject_wrong", build: oneLogin(nil, func(l *login) { l.keyID.Subject = "bob" }),
			want: `(login_issue): key ID sub=bob, but the request's subject is "alice"`},
		{name: "login_kr2_request_wrong", build: oneLogin(nil, func(l *login) { l.keyID.Request = strings.Repeat("ab", 16) }),
			want: "(login_issue): key ID req=abababababababababababababababab, but the request ID is"},
		{name: "login_kr2_dir_wrong", build: oneLogin(nil, func(l *login) { l.keyID.Directory = 2 }),
			want: "(login_issue): key ID dir=2, but the entry records directory version 1"},
		{name: "login_kr2_pol_wrong", build: oneLogin(nil, func(l *login) { l.keyID.Policy = 2 }),
			want: "(login_issue): key ID pol=2, but the policy in force is version 1"},

		// Freshness.
		{name: "login_created_301s_before", build: oneLogin(func(l *login) { l.req.CreatedAt -= 301 }, nil),
			want: "(login_issue): request CreatedAt is 301 s from the serial's time"},
		{name: "login_created_301s_after", build: oneLogin(func(l *login) { l.req.CreatedAt += 301 }, nil),
			want: "(login_issue): request CreatedAt is 301 s from the serial's time"},
		// The signer logged a refusal while its clock ran 600 s ahead, then
		// the clock was stepped back and a login was issued on the
		// corrected clock: appendLocked raises the login's leaf time to the
		// refusal's, but its serial and CreatedAt are the real time.
		{name: "login_after_leaf_time_raised_ok", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.micros += 600e6
			lf.addRefusal()
			lf.addLogin(func(l *login) { l.req.CreatedAt = l.serial / 1e6 }, nil)
			return lf
		}},
		// The same raised leaf time cannot excuse a CreatedAt 600 s from
		// the serial: the signer checks CreatedAt against its clock, which
		// the serial is read from.
		{name: "login_created_at_raised_leaf_time", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.micros += 600e6
			lf.addRefusal()
			lf.addLogin(nil, nil) // CreatedAt = the raised leaf time
			return lf
		}, want: "(login_issue): request CreatedAt is 600 s from the serial's time"},
		// A compromised signer holds a passkey approval (CreatedAt = T) and
		// logs the login a week later: the serial right after T (no
		// certificate came in between), the leaf time T+7d and a
		// certificate issued at T+7d, inside [serial, leaf time]. The
		// serial agrees with CreatedAt, but the certificate was not issued
		// within the approval's freshness window.
		{name: "login_held_approval_refused", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.micros += uint64(7 * 24 * time.Hour / time.Microsecond)
			lf.addLogin(func(l *login) { l.req.CreatedAt = l.serial / 1e6 },
				func(l *login) { l.issued = issuedAt(lf.micros + 1) }) // the next leaf's time
			return lf
		}, want: "(login_issue): request CreatedAt is 6048"}, // 604800 s, or 604801 across a second boundary
		// The issuance-time bound at its edges, with the serial at
		// CreatedAt and the leaf time raised 600 s so the issuance range
		// allows both certificates.
		{name: "login_issued_300s_after_created_ok", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.micros += 600e6
			lf.addLogin(func(l *login) { l.req.CreatedAt = l.serial / 1e6 },
				func(l *login) { l.issued = time.Unix(int64(l.req.CreatedAt)+300, 0) }) //nolint:gosec // G115: test times are after 1970
			return lf
		}},
		{name: "login_issued_301s_after_created", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.micros += 600e6
			lf.addLogin(func(l *login) { l.req.CreatedAt = l.serial / 1e6 },
				func(l *login) { l.issued = time.Unix(int64(l.req.CreatedAt)+301, 0) }) //nolint:gosec // G115: test times are after 1970
			return lf
		}, want: "(login_issue): request CreatedAt is 301 s from the certificate's issuance time"},

		// Replay: request IDs are single-use for logins.
		{name: "login_request_replayed", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			first := lf.addLogin(nil, nil)
			lf.addLogin(func(l *login) { cp := *first.req; l.req, l.certKey = &cp, first.certKey }, nil)
			return lf
		}, want: "(login_issue): request ID "},
		{name: "login_reuses_issue_request_id", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addIssueWithRequest(strings.Repeat("cd", 16))
			lf.addLogin(func(l *login) { copy(l.req.RequestID[:], bytes.Repeat([]byte{0xcd}, 16)) }, nil)
			return lf
		}, want: "(login_issue): request ID cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd replayed: issue entry 2 already used it"},
		{name: "issue_reuses_login_request_id", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			first := lf.addLogin(nil, nil)
			lf.addIssueWithRequest(hex.EncodeToString(first.req.RequestID[:]))
			return lf
		}, want: "replayed: login_issue entry 2 already used it"},
		{name: "issue_request_ids_not_compared_with_each_other", build: func(t *testing.T) *loginFixture {
			// Phase 1 behaviour, unchanged: two issue entries are not
			// compared with each other (verify.go, issuance).
			lf := base(t)
			lf.addIssueWithRequest(strings.Repeat("ef", 16))
			lf.addIssueWithRequest(strings.Repeat("ef", 16))
			return lf
		}},

		// One serial sequence across issue and login_issue entries.
		{name: "login_after_issue_ascending_ok", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addIssue()
			lf.addLogin(nil, nil)
			lf.addIssue()
			return lf
		}},
		{name: "login_serial_not_above_issue", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addIssue()
			lf.addLogin(nil, func(l *login) { l.serial = lf.serial })
			return lf
		}, want: "(login_issue): serials not strictly increasing"},
		{name: "login_serial_below_issue", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addIssue()
			lf.addLogin(nil, func(l *login) { l.serial = lf.serial - 1 })
			return lf
		}, want: "(login_issue): serials not strictly increasing"},
		{name: "issue_after_login_ascending_ok", build: func(t *testing.T) *loginFixture {
			lf := base(t)
			lf.addLogin(nil, nil)
			lf.addIssue()
			return lf
		}},
		{name: "issue_serial_not_above_login", build: func(t *testing.T) *loginFixture {
			// The log's first certificate is a login; the next issue
			// entry reuses its serial.
			lf := base(t)
			lf.addLogin(nil, nil)
			lf.serial--
			lf.addIssue()
			return lf
		}, want: "serials not strictly increasing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lf := tc.build(t)
			rep, err := lf.verify(join(lf.lines()), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if tc.check != nil {
					tc.check(t, rep)
				}
				return
			}
			if err == nil || rep != nil {
				t.Fatalf("Verify accepted the tampered log: %+v", rep)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestVerifyReplayFields: a line that carries the directory or sigs key a
// restore replays from (03-02) verifies only as a directory_install line
// with each key once and the leaf's own bytes as its value, so the
// replayed bytes are the verified leaf's (03-02 pre-merge review). A line
// without them, as exports before 03-02 wrote, is not checked, and other
// decoded fields stay informational.
func TestVerifyReplayFields(t *testing.T) {
	lf := newLoginFixture(t, true)
	lf.addDirectory(lf.directory(nil), nil)
	all := lf.lines() // bundle_install, directory_install, checkpoint
	editDecoded := func(i int, edit func(m map[string]any)) []string {
		t.Helper()
		return editDecodedLine(t, all, i, edit)
	}
	other := base64.StdEncoding.EncodeToString([]byte(`{"version":1,"roles":[{"name":"evil"}]}`))
	const refused = "its directory or sigs field is not the document and signatures of its directory_install leaf"
	cases := []struct {
		name  string
		lines []string
		want  string // "" = must verify
	}{
		{"as_exported_ok", all, ""},
		{"reencoded_unchanged_ok", editDecoded(1, func(map[string]any) {}), ""},
		{"other_decoded_field_ok", editDecoded(1, func(m map[string]any) { m["note"] = "added by a later binary" }), ""},
		{"directory_swapped_refused", editDecoded(1, func(m map[string]any) { m["directory"] = other }), refused},
		{"sigs_swapped_refused", editDecoded(1, func(m map[string]any) { m["sigs"] = other }), refused},
		{"sigs_missing_refused", editDecoded(1, func(m map[string]any) { delete(m, "sigs") }), refused},
		{"nested_decoy_refused", editDecoded(1, func(m map[string]any) { m["x"] = map[string]any{"directory": other} }), refused},
		{"pre_03_02_line_ok", editDecoded(1, func(m map[string]any) { delete(m, "directory"); delete(m, "sigs") }), ""},
		{"decoy_on_other_kind_refused", editDecoded(0, func(m map[string]any) {
			m["kind"], m["version"], m["directory"], m["sigs"] = "directory_install", 1, other, other
		}), refused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := lf.verify(join(tc.lines), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify = %+v, %v; want an error with %q", rep, err, tc.want)
			}
		})
	}
}

// editDecodedLine returns a copy of lines with line i re-encoded, its
// decoded object changed by edit.
func editDecodedLine(t *testing.T, lines []string, i int, edit func(m map[string]any)) []string {
	t.Helper()
	l := append([]string(nil), lines...)
	var line ExportLine
	if err := json.Unmarshal([]byte(l[i]), &line); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(line.Decoded, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	dec, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	line.Decoded = dec
	out, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	l[i] = string(out)
	return l
}

// TestVerifyGrepFields: the decoded fields the restore runbook reads with
// grep to count, list and pick entries (signer-install.md steps 2 and 3)
// verify only as the leaf's own (03-02 pre-merge review, round 2): "kind"
// once on every leaf line, "bundle_version" once on every bundle_install
// line, and "version", where present, once on a directory_install line,
// each with the leaf's value and on no other line. hidden_final_install
// is the review's case: with v3 relabelled as a refusal, the runbook's
// grep would list only v1 and v2, and a replay would stop at v2.
func TestVerifyGrepFields(t *testing.T) {
	lf := newLoginFixture(t, true)
	for range 3 {
		lf.addDirectory(lf.directory(nil), nil)
	}
	lf.addLogin(nil, nil)
	all := lf.lines() // bundle_install v1, directory_install v1, v2, v3, login_issue, checkpoint
	edit := func(i int, f func(m map[string]any)) []string {
		t.Helper()
		return editDecodedLine(t, all, i, f)
	}
	raw := func(i int, old, repl string) []string {
		t.Helper()
		if !strings.Contains(all[i], old) {
			t.Fatalf("line %d has no %s", i, old)
		}
		l := append([]string(nil), all...)
		l[i] = strings.Replace(l[i], old, repl, 1)
		return l
	}
	const (
		kind          = "its decoded kind is not the kind of its leaf"
		version       = "its decoded version field is not the one of its"
		bundleVersion = "its decoded bundle_version field is not the one of its"
	)
	cases := []struct {
		name  string
		lines []string
		want  string // "" = must verify
	}{
		{"as_exported_ok", all, ""},
		{"other_decoded_field_ok", edit(2, func(m map[string]any) { m["note"] = "added by a later binary" }), ""},
		{"hidden_final_install_refused", edit(3, func(m map[string]any) { m["kind"] = "refusal" }), kind},
		{"kind_missing_refused", edit(2, func(m map[string]any) { delete(m, "kind") }), kind},
		{"kind_spaced_refused", raw(3, `"kind":"directory_install"`, `"kind" : "directory_install"`), kind},
		{"kind_decoy_nested_refused", edit(0, func(m map[string]any) { m["x"] = map[string]any{"kind": "directory_install"} }), kind},
		{"kind_decoy_escaped_key_refused", edit(0, func(m map[string]any) { m[`x"kind`] = "directory_install" }), kind},
		{"version_edited_refused", edit(2, func(m map[string]any) { m["version"] = 3 }), version},
		{"version_longer_number_refused", edit(2, func(m map[string]any) { m["version"] = 23 }), version},
		{"version_twice_refused", edit(2, func(m map[string]any) { m["x"] = map[string]any{"version": 2} }), version},
		{"version_missing_ok", edit(2, func(m map[string]any) { delete(m, "version") }), ""},
		{"version_on_other_kind_refused", edit(0, func(m map[string]any) { m["version"] = 2 }), version},
		{"bundle_version_edited_refused", edit(0, func(m map[string]any) { m["bundle_version"] = 2 }), bundleVersion},
		{"bundle_version_missing_refused", edit(0, func(m map[string]any) { delete(m, "bundle_version") }), bundleVersion},
		{"bundle_version_on_other_kind_refused", edit(3, func(m map[string]any) { m["bundle_version"] = 1 }), bundleVersion},
		// The other kind's key with the value the check computes for this
		// line (round 3): only the key compare refuses these.
		{"bundle_version_colliding_on_directory_refused", edit(3, func(m map[string]any) { m["bundle_version"] = 3 }), bundleVersion},
		{"version_colliding_on_bundle_refused", edit(0, func(m map[string]any) { m["version"] = 1 }), version},
		{"version_zero_on_login_refused", edit(4, func(m map[string]any) { m["version"] = 0 }), version},
		{"bundle_version_zero_on_login_refused", edit(4, func(m map[string]any) { m["bundle_version"] = 0 }), bundleVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := lf.verify(join(tc.lines), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify = %+v, %v; want an error with %q", rep, err, tc.want)
			}
		})
	}
}

// auditInstallationID is the installation ID of the revocation fixtures'
// genesis bundle.
const auditInstallationID = "00112233445566778899aabbccddeeff"

// revokeFixture is a fixture whose genesis bundle has an installation ID
// and whose log can hold revoke and krl_publish entries written the way the
// signer writes them: admin-signed requests, entries resolved from the
// logged certificates, and KRLs built with krl.PublishSet from every
// logged entry, signed by the bundle's ops key.
type revokeFixture struct {
	*fixture
	entries    []krl.Entry // every revoke entry logged so far
	krlVersion uint64
}

func newRevokeFixture(t testing.TB) *revokeFixture {
	t.Helper()
	f := newBareFixtureAt(t, "ed25519", time.Now())
	g := f.genesis()
	g.InstallationID = auditInstallationID
	f.addBundle(f.signDocs(g, f.policy(), f.root))
	return &revokeFixture{fixture: f}
}

// issue logs one certificate (kr1, subject u:alice, an hour) and returns
// it.
func (rf *revokeFixture) issue() *ssh.Certificate {
	rf.t.Helper()
	rf.serial++
	c := rf.newCert(rf.serial, issuedAt(rf.serial))
	rf.add(tlog.KindIssue, issueBody(rf.t, c, rf.serial))
	return c
}

// secs is the next leaf's time in whole seconds (add raises the leaf time
// by one microsecond first).
func (rf *revokeFixture) secs() uint64 { return (rf.micros + 1) / 1_000_000 }

// serialEntry is the serial entry of c as the signer writes it.
func serialEntry(c *ssh.Certificate) tlog.RevokedEntry {
	return tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, ValidBeforeSeconds: c.ValidBefore}
}

// revoke logs a revoke entry for req, resolved now (CreatedAt and
// ResolvedAtSeconds the next leaf's whole seconds), signed by the policy
// admin, listing entries; edit (optional) changes the body after signing.
func (rf *revokeFixture) revoke(req *wire.RevokeRequest, entries []tlog.RevokedEntry, edit func(*tlog.RevokeBody)) {
	rf.t.Helper()
	at := rf.secs()
	if req.CreatedAt == 0 {
		req.CreatedAt = at
	}
	if req.Reason == "" {
		req.Reason = "test"
	}
	if req.InstallationID == "" {
		req.InstallationID = auditInstallationID
	}
	if req.RequestID == ([16]byte{}) {
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			rf.t.Fatal(err)
		}
	}
	sig, err := sshsig.Sign(rand.Reader, rf.admin, wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		rf.t.Fatal(err)
	}
	b := &tlog.RevokeBody{PolicyVersion: 1, ResolvedAtSeconds: at, Request: req.SigningBytes(),
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}, Entries: entries}
	if edit != nil {
		edit(b)
	}
	body, err := b.Encode()
	if err != nil {
		rf.t.Fatal(err)
	}
	rf.add(tlog.KindRevoke, body)
	kinds := map[uint8]uint8{tlog.RevokedSerial: krl.EntrySerial, tlog.RevokedKeyID: krl.EntryKeyID, tlog.RevokedKey: krl.EntryKey}
	for _, e := range b.Entries {
		rf.entries = append(rf.entries, krl.Entry{Kind: kinds[e.Kind], CAKey: e.CAKey, Serial: e.Serial, KeyID: e.KeyID, Key: e.Key, ValidBefore: e.ValidBeforeSeconds})
	}
}

// publishOpts changes a krl_publish entry before it is signed: its
// version, issued_at (whole seconds), the entries the KRL is built from.
type publishOpts struct {
	version  uint64
	issuedAt uint64
	entries  []krl.Entry
	data     []byte // the KRL bytes, instead of the ones built
}

// publish logs a krl_publish entry as the signer writes one: issued at the
// next leaf's whole seconds, version max(prev + 1, issued_at), the KRL
// krl.PublishSet builds from every logged entry, its manifest signed by
// the ops key. edit (optional) changes the options first.
func (rf *revokeFixture) publish(edit func(*publishOpts)) {
	rf.t.Helper()
	o := &publishOpts{issuedAt: rf.secs(), entries: rf.entries}
	o.version = max(rf.krlVersion+1, o.issuedAt)
	if edit != nil {
		edit(o)
	}
	if o.data == nil {
		set, err := krl.PublishSet(o.entries, o.issuedAt)
		if err != nil {
			rf.t.Fatal(err)
		}
		if o.data, err = krl.Encode(set, o.version, time.Unix(int64(o.issuedAt), 0)); err != nil { //nolint:gosec // G115: a test time
			rf.t.Fatal(err)
		}
	}
	m := krl.Manifest{InstallationID: auditInstallationID, KRLVersion: o.version, KRLSHA256: krl.SHA256Hex(o.data),
		IssuedAt: time.Unix(int64(o.issuedAt), 0).UTC().Format(trust.TimeFormat), BundleVersion: 1, LogIndex: uint64(len(rf.leaves))} //nolint:gosec // G115: test values
	manifest, err := m.Canonical()
	if err != nil {
		rf.t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, rf.ops, krl.Namespace, manifest)
	if err != nil {
		rf.t.Fatal(err)
	}
	body, err := (&tlog.KRLPublishBody{KRLVersion: o.version, BundleVersion: 1, IssuedAtSeconds: o.issuedAt,
		SHA256: sha256.Sum256(o.data), Manifest: manifest, Sig: sig}).Encode()
	if err != nil {
		rf.t.Fatal(err)
	}
	rf.add(tlog.KindKRLPublish, body)
	rf.krlVersion = o.version
}

func (rf *revokeFixture) verifyAll() (*Report, error) {
	return rf.verify(join(rf.lines()), nil)
}

func subjectAlice() *wire.RevokeRequest {
	return &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "u:alice"}
}

// bigSKKey returns a fresh canonical sk-ssh-ed25519@openssh.com public key
// of exactly size bytes (at least 74), padded by its application string.
func bigSKKey(t testing.TB, size int) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, "ssh:" + strings.Repeat("x", size-74)})
	if p, err := ssh.ParsePublicKey(k); err != nil || len(k) != size || !bytes.Equal(p.Marshal(), k) {
		t.Fatalf("security-key key of %d bytes: %v", len(k), err)
	}
	return k
}

// fillKeyCap logs explicit-key revocations of 8000-byte keys, each
// followed by its KRL publish, up to krl.MaxRevokedKeyBytes, and returns
// the first key.
func (rf *revokeFixture) fillKeyCap() []byte {
	rf.t.Helper()
	var first []byte
	for range krl.MaxRevokedKeyBytes / 8004 {
		k := bigSKKey(rf.t, 8000)
		if first == nil {
			first = k
		}
		rf.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: k}, []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: k}}, nil)
		rf.publish(nil)
	}
	return first
}

// asV1 returns an edit that logs req as a 03-01 v1 request (no
// installation ID, keyroster/revoke-request/v1), signed by the admin under
// namespace.
func (rf *revokeFixture) asV1(req *wire.RevokeRequest, namespace string) func(*tlog.RevokeBody) {
	return func(b *tlog.RevokeBody) {
		v1 := *req
		v1.InstallationID = ""
		b.Request = v1.SigningBytes()
		sig, err := sshsig.Sign(rand.Reader, rf.admin, namespace, b.Request)
		if err != nil {
			rf.t.Fatal(err)
		}
		b.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	}
}

// TestVerifyRevocations (REVOKE-01..03, T-03-13, T-03-14, T-03-16, T-03-202):
// audit verify re-derives every revoke entry from the admin-signed request
// and the logged certificates, and every krl_publish entry from the logged
// revocations, and refuses every entry a signer could not have written.
func TestVerifyRevocations(t *testing.T) {
	type tc struct {
		name  string
		build func(rf *revokeFixture)
		want  string // "" accepted, otherwise a substring of the refusal
	}
	cases := []tc{
		{"revoke_subject_accepted", func(rf *revokeFixture) {
			c1, c2 := rf.issue(), rf.issue()
			rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c1), serialEntry(c2)}, nil)
			rf.publish(nil)
		}, ""},
		// Installation binding (pre-merge review of PR #61, owner decision
		// 2026-10-26): a v2 request names its installation; a 03-01 v1
		// request names none, revokes only by serial and is signed under
		// keyroster/revoke-request/v1.
		{"revoke_other_installation_refused", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{InstallationID: "ffffffffffffffffffffffffffffffff", Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial},
				[]tlog.RevokedEntry{serialEntry(c)}, nil)
		}, "revoke_installation_mismatch"},
		{"revoke_v1_serial_accepted", func(rf *revokeFixture) {
			c := rf.issue()
			req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}
			rf.revoke(req, []tlog.RevokedEntry{serialEntry(c)}, rf.asV1(req, wire.RevokeSSHSIGNamespaceV1))
			rf.publish(nil)
		}, ""},
		{"revoke_v1_under_v2_namespace_refused", func(rf *revokeFixture) {
			c := rf.issue()
			req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}
			rf.revoke(req, []tlog.RevokedEntry{serialEntry(c)}, rf.asV1(req, wire.RevokeSSHSIGNamespace))
		}, "does not approve the logged request under keyroster/revoke-request/v1"},
		{"revoke_v2_under_v1_namespace_refused", func(rf *revokeFixture) {
			c := rf.issue()
			req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}
			rf.revoke(req, []tlog.RevokedEntry{serialEntry(c)}, func(b *tlog.RevokeBody) {
				sig, err := sshsig.Sign(rand.Reader, rf.admin, wire.RevokeSSHSIGNamespaceV1, b.Request)
				if err != nil {
					rf.t.Fatal(err)
				}
				b.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
			})
		}, "does not approve the logged request under keyroster/revoke-request/v2"},
		{"revoke_v1_key_id_refused", func(rf *revokeFixture) {
			c := rf.issue()
			req := &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: c.KeyId}
			rf.revoke(req, []tlog.RevokedEntry{{Kind: tlog.RevokedKeyID, CAKey: rf.ca.PublicKey().Marshal(), KeyID: c.KeyId, ValidBeforeSeconds: c.ValidBefore}},
				rf.asV1(req, wire.RevokeSSHSIGNamespaceV1))
		}, "revokes only by serial"},
		{"revoke_entries_tampered", func(rf *revokeFixture) {
			c1, _ := rf.issue(), rf.issue()
			rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c1)}, nil) // omits the live c2
		}, "lists 1 entries, but the log shows 2"},
		{"revoke_entry_valid_before_tampered", func(rf *revokeFixture) {
			c := rf.issue()
			e := serialEntry(c)
			e.ValidBeforeSeconds -= 3600 // so it would be pruned early
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{e}, nil)
		}, "but the log shows serial"},
		{"revoke_entry_ca_key_tampered", func(rf *revokeFixture) {
			c := rf.issue()
			e := serialEntry(c)
			e.CAKey = rf.hostCA.PublicKey().Marshal()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{e}, nil)
		}, "but the log shows serial"},
		{"revoke_entry_other_target_refused_serial", func(rf *revokeFixture) {
			c1, c2 := rf.issue(), rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c1.Serial}, []tlog.RevokedEntry{serialEntry(c2)}, nil)
		}, "but the log shows serial"},
		{"revoke_entry_other_target_refused_key_id", func(rf *revokeFixture) {
			c1, c2 := rf.issue(), rf.issue()
			ca := rf.ca.PublicKey().Marshal()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: c1.KeyId},
				[]tlog.RevokedEntry{{Kind: tlog.RevokedKeyID, CAKey: ca, KeyID: c2.KeyId, ValidBeforeSeconds: c2.ValidBefore}}, nil)
		}, "but the log shows key ID"},
		{"revoke_entry_other_target_refused_key", func(rf *revokeFixture) {
			k1, k2 := newSigner(rf.t, "ed25519").PublicKey().Marshal(), newSigner(rf.t, "ed25519").PublicKey().Marshal()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: k1}, []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: k2}}, nil)
		}, "but the log shows key"},
		{"revoke_key_id_ca_set_mismatch_refused_missing", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: c.KeyId}, nil, nil)
		}, "lists 0 entries, but the log shows 1"},
		{"revoke_key_id_ca_set_mismatch_refused_foreign", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: c.KeyId}, []tlog.RevokedEntry{
				{Kind: tlog.RevokedKeyID, CAKey: rf.ca.PublicKey().Marshal(), KeyID: c.KeyId, ValidBeforeSeconds: c.ValidBefore},
				{Kind: tlog.RevokedKeyID, CAKey: rf.hostCA.PublicKey().Marshal(), KeyID: c.KeyId}}, nil)
		}, "lists 2 entries, but the log shows 1"},
		{"revoke_key_id_accepted", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: c.KeyId},
				[]tlog.RevokedEntry{{Kind: tlog.RevokedKeyID, CAKey: rf.ca.PublicKey().Marshal(), KeyID: c.KeyId, ValidBeforeSeconds: c.ValidBefore}}, nil)
			rf.publish(nil)
		}, ""},
		// Pre-merge review of PR #61 (owner decision 2026-10-26, T-03-211):
		// a key-ID entry the log's issuance does not support would never
		// leave the KRL, and the signer refuses it (key_id_not_issued).
		{"key_id_not_issued_refused", func(rf *revokeFixture) {
			id := "kr1/ca=user/sub=nobody/req=000102030405060708090a0b0c0d0e0f/pol=1/ser=1"
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: id},
				[]tlog.RevokedEntry{{Kind: tlog.RevokedKeyID, CAKey: rf.ca.PublicKey().Marshal(), KeyID: id}}, nil)
		}, "key_id_not_issued"},
		{"key_id_not_issued_empty_refused", func(rf *revokeFixture) {
			id := "kr1/ca=user/sub=nobody/req=000102030405060708090a0b0c0d0e0f/pol=1/ser=1"
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: id}, nil, nil)
		}, "key_id_not_issued"},
		{"key_id_of_other_role_refused", func(rf *revokeFixture) {
			c := rf.issue() // a user certificate
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleHost, KeyID: c.KeyId},
				[]tlog.RevokedEntry{{Kind: tlog.RevokedKeyID, CAKey: rf.hostCA.PublicKey().Marshal(), KeyID: c.KeyId}}, nil)
		}, "key_id_not_issued"},
		// The explicit-key cap (krl.CheckExplicitKeys): the byte cap is
		// reached with krl.MaxRevokedKeyBytes / 8004 keys of 8000 bytes; a
		// key already revoked is accepted again at the cap, a new one is
		// refused.
		{"explicit_key_cap_relist_accepted", func(rf *revokeFixture) {
			first := rf.fillKeyCap()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: first}, []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: first}}, nil)
			rf.publish(nil)
		}, ""},
		{"explicit_key_cap_refused", func(rf *revokeFixture) {
			rf.fillKeyCap()
			k := bigSKKey(rf.t, 8000)
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: k}, []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: k}}, nil)
		}, "explicit_key_cap_reached"},
		{"revoke_key_accepted", func(rf *revokeFixture) {
			k := newSigner(rf.t, "ed25519").PublicKey().Marshal()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: k}, []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: k}}, nil)
			rf.publish(nil)
		}, ""},
		{"revoke_key_of_installation_refused", func(rf *revokeFixture) {
			k := rf.ca.PublicKey().Marshal()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: k}, []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: k}}, nil)
		}, "key_is_ca_of_this_installation"},
		{"revoke_subject_kind_host_refused", func(rf *revokeFixture) {
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectHost, Subject: "web1"}, nil, nil)
		}, "does not resolve"},
		{"revoke_not_admin_refused", func(rf *revokeFixture) {
			c := rf.issue()
			req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}
			rf.revoke(req, []tlog.RevokedEntry{serialEntry(c)}, func(b *tlog.RevokeBody) {
				sig, err := sshsig.Sign(rand.Reader, newSigner(rf.t, "ed25519"), wire.RevokeSSHSIGNamespace, b.Request)
				if err != nil {
					rf.t.Fatal(err)
				}
				b.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
			})
		}, "not an admin"},
		{"revoke_wrong_namespace_refused", func(rf *revokeFixture) {
			c := rf.issue()
			req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}
			rf.revoke(req, []tlog.RevokedEntry{serialEntry(c)}, func(b *tlog.RevokeBody) {
				sig, err := sshsig.Sign(rand.Reader, rf.admin, wire.AdminSSHSIGNamespace, b.Request)
				if err != nil {
					rf.t.Fatal(err)
				}
				b.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
			})
		}, "does not approve the logged request"},
		{"revoke_resolved_after_leaf_refused", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)},
				func(b *tlog.RevokeBody) { b.ResolvedAtSeconds++ })
		}, "is after the leaf time"},
		{"revoke_resolved_far_from_created_refused", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial, CreatedAt: rf.secs() - 301},
				[]tlog.RevokedEntry{serialEntry(c)}, nil)
		}, "from the request's CreatedAt"},
		{"revoke_clock_rollback_accepted", func(rf *revokeFixture) {
			c := rf.issue()
			// Two hours on, the clock steps back one: the leaf time stays
			// (appendLocked raises it), the resolution time does not. c is
			// live at T and not at the leaf time.
			rf.micros += 2 * 3600 * 1_000_000
			back := rf.secs() - 3600
			if !krl.EntryLive(c.ValidBefore, back) || krl.EntryLive(c.ValidBefore, rf.secs()) {
				rf.t.Fatal("the case does not separate T from the leaf time")
			}
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "u:alice", CreatedAt: back},
				[]tlog.RevokedEntry{serialEntry(c)}, func(b *tlog.RevokeBody) { b.ResolvedAtSeconds = back })
			rf.publish(nil)
		}, ""},
		// Pre-merge review of PR #61: the signer writes the krl_publish
		// entry right after every revocation, in the same transaction, so
		// a revocation followed by another entry, or by none, is refused.
		{"revoke_unpublished_at_end_refused", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)}, nil)
		}, "is not followed by the krl_publish entry"},
		{"revoke_published_after_another_entry_refused", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)}, nil)
			rf.issue()
			rf.publish(nil)
		}, "is not followed by the krl_publish entry"},
		{"revoke_followed_by_revoke_refused", func(rf *revokeFixture) {
			c1, c2 := rf.issue(), rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c1.Serial}, []tlog.RevokedEntry{serialEntry(c1)}, nil)
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c2.Serial}, []tlog.RevokedEntry{serialEntry(c2)}, nil)
			rf.publish(nil)
		}, "is not followed by the krl_publish entry"},
		{"revoke_subject_relist_accepted", func(rf *revokeFixture) {
			c1, c2 := rf.issue(), rf.issue()
			rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c1), serialEntry(c2)}, nil)
			rf.publish(nil)
			rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c1), serialEntry(c2)}, nil)
			rf.publish(nil)
		}, ""},
		{"revoke_subject_excluding_revoked_refused", func(rf *revokeFixture) {
			c1, c2 := rf.issue(), rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c1.Serial}, []tlog.RevokedEntry{serialEntry(c1)}, nil)
			rf.publish(nil)
			// c1 is already revoked; a sweep that leaves it out is refused.
			rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c2)}, nil)
		}, "lists 1 entries, but the log shows 2"},
		{"revoke_request_replayed_refused", func(rf *revokeFixture) {
			c := rf.issue()
			req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}
			rf.revoke(req, []tlog.RevokedEntry{serialEntry(c)}, nil)
			rf.publish(nil)
			rf.revoke(req, []tlog.RevokedEntry{serialEntry(c)}, nil)
		}, "replayed"},
		{"krl_publish_digest_tampered", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)}, nil)
			rf.publish(func(o *publishOpts) { o.entries = nil }) // a KRL that omits the revocation, ops-signed
		}, "re-derived from the log's revocations"},
		{"krl_publish_early_prune_refused", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)}, nil)
			// Published while c is live, but pruned as if issued after E.
			rf.publish(func(o *publishOpts) {
				set, err := krl.PublishSet(rf.entries, c.ValidBefore+krl.PruneMargin)
				if err != nil {
					rf.t.Fatal(err)
				}
				if o.data, err = krl.Encode(set, o.version, time.Unix(int64(o.issuedAt), 0)); err != nil { //nolint:gosec // G115: a test time
					rf.t.Fatal(err)
				}
			})
		}, "re-derived from the log's revocations"},
		{"krl_publish_time_derived_accepted", func(rf *revokeFixture) {
			rf.publish(nil) // version = issued_at
			if rf.krlVersion != rf.secs() {
				rf.t.Fatalf("version %d, want issued_at %d", rf.krlVersion, rf.secs())
			}
		}, ""},
		{"krl_publish_same_second_plus_one_accepted", func(rf *revokeFixture) {
			rf.publish(nil)
			rf.publish(nil) // the same second: prev + 1, above issued_at
		}, ""},
		{"krl_publish_03_01_plus_one_accepted", func(rf *revokeFixture) {
			rf.publish(func(o *publishOpts) { o.version = 1 })
			rf.publish(func(o *publishOpts) { o.version = 2 })
		}, ""},
		{"krl_publish_version_not_above_prev_refused_equal", func(rf *revokeFixture) {
			rf.publish(nil)
			v := rf.krlVersion
			rf.publish(func(o *publishOpts) { o.version = v })
		}, "is not above the previous version"},
		{"krl_publish_version_not_above_prev_refused_below", func(rf *revokeFixture) {
			rf.publish(nil)
			v := rf.krlVersion
			rf.publish(func(o *publishOpts) { o.version = v - 1 })
		}, "is not above the previous version"},
		{"krl_publish_version_above_max_refused", func(rf *revokeFixture) {
			rf.publish(func(o *publishOpts) { o.version = max(1, o.issuedAt) + 1 })
		}, "is above max(previous + 1, issued_at)"},
		{"krl_publish_version_between_refused", func(rf *revokeFixture) {
			rf.publish(func(o *publishOpts) { o.version = 1 })
			rf.publish(func(o *publishOpts) { o.version = 5 }) // between 2 and issued_at
		}, "is neither the previous version + 1"},
		{"krl_publish_issued_after_leaf_refused", func(rf *revokeFixture) {
			rf.publish(func(o *publishOpts) { o.issuedAt++; o.version = o.issuedAt })
		}, "is after the leaf time"},
		{"krl_publish_log_index_refused", func(rf *revokeFixture) {
			// The manifest names the index the entry was built for; a refusal
			// inserted before it moves it one entry later.
			n := len(rf.leaves)
			rf.publish(nil)
			raw := rf.leaves[n]
			rf.leaves = rf.leaves[:n]
			rf.addRefusal()
			rf.add(tlog.KindKRLPublish, mustLeafBody(rf.t, raw))
		}, "manifest names log index"},
		{"republish_unchanged_set", func(rf *revokeFixture) {
			c := rf.issue()
			rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)}, nil)
			rf.publish(nil)
			rf.micros += 10 * 60 * 1_000_000
			rf.publish(nil)
			rf.micros += 3 * 3600 * 1_000_000 // past E: the next one prunes c
			rf.publish(nil)
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rf := newRevokeFixture(t)
			c.build(rf)
			rep, err := rf.verifyAll()
			if c.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				t.Logf("accepted: %d revocations, %d entries, %d KRL publishes", rep.Revocations, rep.RevokedEntries, rep.KRLPublishes)
				return
			}
			if err == nil || rep != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Verify = %+v, %v; want a refusal containing %q", rep, err, c.want)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// TestVerifyRevokeSplit (T-03-16): a subject revocation of more than
// tlog.MaxRevokedEntries certificates is accepted over adjacent revoke
// entries of one request (every one but the last full, ascending) and
// refused when its parts are not adjacent.
func TestVerifyRevokeSplit(t *testing.T) {
	build := func(t *testing.T, between func(rf *revokeFixture)) (*Report, error) {
		rf := newRevokeFixture(t)
		var entries []tlog.RevokedEntry
		for range tlog.MaxRevokedEntries + 1 {
			entries = append(entries, serialEntry(rf.issue()))
		}
		req := subjectAlice()
		rf.revoke(req, entries[:tlog.MaxRevokedEntries], nil)
		between(rf)
		rf.revoke(req, entries[tlog.MaxRevokedEntries:], nil)
		rf.publish(nil)
		return rf.verifyAll()
	}
	t.Run("revoke_subject_split_joined_accepted", func(t *testing.T) {
		rep, err := build(t, func(*revokeFixture) {})
		if err != nil || rep.Revocations != 1 || rep.RevokedEntries != tlog.MaxRevokedEntries+1 {
			t.Fatalf("Verify = %+v, %v; want one revocation of 4097 entries", rep, err)
		}
	})
	t.Run("revoke_subject_split_unpublished_refused", func(t *testing.T) {
		// The krl_publish entry follows the last part, not the first.
		rf := newRevokeFixture(t)
		var entries []tlog.RevokedEntry
		for range tlog.MaxRevokedEntries + 1 {
			entries = append(entries, serialEntry(rf.issue()))
		}
		req := subjectAlice()
		rf.revoke(req, entries[:tlog.MaxRevokedEntries], nil)
		rf.revoke(req, entries[tlog.MaxRevokedEntries:], nil)
		rf.issue()
		rf.publish(nil)
		if rep, err := rf.verifyAll(); err == nil || rep != nil || !strings.Contains(err.Error(), "is not followed by the krl_publish entry") {
			t.Fatalf("Verify = %+v, %v; want the unpublished split refused", rep, err)
		}
	})
	t.Run("revoke_subject_split_nonadjacent_refused", func(t *testing.T) {
		rep, err := build(t, func(rf *revokeFixture) { rf.addRefusal() })
		if err == nil || rep != nil || !strings.Contains(err.Error(), "does not continue it") {
			t.Fatalf("Verify = %+v, %v; want the split refused", rep, err)
		}
		t.Logf("refused: %v", err)
	})
}

// TestVerifyRevokeExportLines (PR #59 review, round 3): the as-exported
// lines of a revoke entry with two entries and of a krl_publish entry pass
// Verify: each entry's kind is rendered as entry_kind, and neither line
// carries a bundle_version or version key.
func TestVerifyRevokeExportLines(t *testing.T) {
	rf := newRevokeFixture(t)
	c1, c2 := rf.issue(), rf.issue()
	rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c1), serialEntry(c2)}, nil)
	rf.publish(nil)
	lines := rf.lines()
	if _, err := rf.verify(join(lines), nil); err != nil {
		t.Fatalf("Verify of the as-exported lines: %v", err)
	}
	rev, pub := lines[len(lines)-3], lines[len(lines)-2]
	for _, want := range []string{`"kind":"revoke"`, `"target":"subject"`, `"subject":"u:alice"`, `"entry_kind":"serial"`, `"admins":["SHA256:`} {
		if !strings.Contains(rev, want) {
			t.Errorf("revoke line lacks %s:\n%s", want, rev)
		}
	}
	if strings.Count(rev, `"entry_kind":`) != 2 || strings.Count(rev, `"kind":`) != 1 {
		t.Errorf("revoke line: %d entry_kind and %d kind keys, want 2 and 1:\n%s", strings.Count(rev, `"entry_kind":`), strings.Count(rev, `"kind":`), rev)
	}
	for _, want := range []string{`"kind":"krl_publish"`, `"krl_version":`, `"krl_sha256":`, `"issued_at":`} {
		if !strings.Contains(pub, want) {
			t.Errorf("krl_publish line lacks %s:\n%s", want, pub)
		}
	}
	for _, l := range []string{rev, pub} {
		if strings.Contains(l, `"bundle_version":`) || strings.Contains(l, `"version":`) {
			t.Errorf("a revoke or krl_publish line carries a bundle_version or version key:\n%s", l)
		}
	}
}

// TestVerifyKRLPublishBeyondRowRange (valid_before_beyond_row_range_kept,
// audit side): a revoke entry whose certificate is valid until
// ssh.CertTimeInfinity is stored in the signer's row as NULL (unknown);
// the KRL the signer builds from that row is the one audit verify
// re-derives from the leaf's ValidBefore, at any realistic time.
func TestVerifyKRLPublishBeyondRowRange(t *testing.T) {
	rf := newRevokeFixture(t)
	body, err := tlog.DecodeBundleInstallBody(mustLeafBody(t, rf.leaves[0]))
	if err != nil {
		t.Fatal(err)
	}
	var a anchor
	if err := a.install(body, Options{Pins: rf.pins(), Threshold: 1}); err != nil {
		t.Fatal(err)
	}
	ca := rf.ca.PublicKey().Marshal()
	for _, years := range []int64{0, 100} {
		rs := newRevocations()
		rs.add([]tlog.RevokedEntry{{Kind: tlog.RevokedSerial, CAKey: ca, Serial: 77, ValidBeforeSeconds: ssh.CertTimeInfinity}})
		rf.micros += uint64(years) * 365 * 24 * 3600 * 1_000_000 //nolint:gosec // G115: test values
		// The signer's view: the row's valid_before NULL, so 0.
		rf.entries = []krl.Entry{{Kind: krl.EntrySerial, CAKey: ca, Serial: 77}}
		rf.krlVersion = 0
		rf.publish(nil)
		l, err := tlog.DecodeLeaf(rf.leaves[len(rf.leaves)-1])
		if err != nil {
			t.Fatal(err)
		}
		pb, err := tlog.DecodeKRLPublishBody(l.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyKRLPublish(l.Index, pb, l.TimeMicros, &a, rs); err != nil {
			t.Fatalf("%d years on: verifyKRLPublish of the signer's KRL: %v", years, err)
		}
	}
}

func mustLeafBody(t testing.TB, raw []byte) []byte {
	t.Helper()
	l, err := tlog.DecodeLeaf(raw)
	if err != nil {
		t.Fatal(err)
	}
	return l.Body
}

// installSuccessor logs a successor bundle (version + 1, the same roots,
// CAs and log key, signed by the fixture root) changed by editBundle, with
// the policy in force unchanged.
func (lf *loginFixture) installSuccessor(editBundle func(*trust.Bundle)) {
	lf.t.Helper()
	prev, err := trust.ParseBundle(lf.docs.bundle)
	if err != nil {
		lf.t.Fatal(err)
	}
	next := *prev
	next.Version, next.Prev = prev.Version+1, trust.SHA256Hex(lf.docs.bundle)
	editBundle(&next)
	lf.docs = lf.signDocs(&next, lf.pol, lf.root)
	lf.addBundle(lf.docs)
}

// TestVerifyDirectoryInstallation (D-04, T-03-20, T-03-25): audit verify
// applies the signer's installation rules. A directory_install entry must
// name the installation of the bundle in force (none while it has none);
// an ID-less directory installed before the bundle gained an ID stays in
// force for logins (the lenient 03-01 answer), and the rebind's
// directory_install entry verifies.
func TestVerifyDirectoryInstallation(t *testing.T) {
	const other = "ffffffffffffffffffffffffffffffff"
	withID := func(id string) func(*directory.Directory) {
		return func(d *directory.Directory) { d.InstallationID = id }
	}
	refusedAt := func(t *testing.T, lf *loginFixture, want string) {
		t.Helper()
		entry := fmt.Sprintf("entry %d (directory_install)", len(lf.leaves)-1)
		_, err := lf.verify(join(lf.lines()), nil)
		if err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), want) {
			t.Fatalf("Verify = %v, want a refusal at %s naming %q", err, entry, want)
		}
	}
	bound := func(t *testing.T) *loginFixture {
		lf := newLoginFixture(t, true)
		lf.installSuccessor(func(b *trust.Bundle) { b.InstallationID = auditInstallationID })
		return lf
	}
	t.Run("other_installation_refused", func(t *testing.T) {
		lf := bound(t)
		lf.addDirectory(lf.directory(withID(other)), nil)
		refusedAt(t, lf, "names another installation")
	})
	t.Run("missing_installation_refused", func(t *testing.T) {
		lf := bound(t)
		lf.addDirectory(lf.directory(nil), nil)
		refusedAt(t, lf, "names no installation")
	})
	t.Run("unknown_installation_refused", func(t *testing.T) {
		lf := newLoginFixture(t, true)
		lf.addDirectory(lf.directory(withID(auditInstallationID)), nil)
		refusedAt(t, lf, "the trust bundle in force has none")
	})
	t.Run("matching_installation_accepted", func(t *testing.T) {
		lf := bound(t)
		lf.addDirectory(lf.directory(withID(auditInstallationID)), nil)
		lf.addLogin(nil, nil)
		if _, err := lf.verify(join(lf.lines()), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rebind_leaf_accepted", func(t *testing.T) {
		lf := newLoginFixture(t, true)
		lf.addDirectory(lf.directory(nil), nil)
		lf.addLogin(nil, nil)
		lf.installSuccessor(func(b *trust.Bundle) { b.InstallationID = auditInstallationID })
		// Lenient: the ID-less directory stays in force for logins.
		lf.addLogin(nil, nil)
		// The rebind: the next version, identical but for the ID.
		lf.addDirectory(lf.directory(withID(auditInstallationID)), nil)
		lf.addLogin(nil, nil)
		rep, err := lf.verify(join(lf.lines()), nil)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Counts[tlog.KindDirectoryInstall] != 2 || rep.Counts[tlog.KindLoginIssue] != 3 {
			t.Fatalf("report: %d directory installs, %d logins; want 2 and 3", rep.Counts[tlog.KindDirectoryInstall], rep.Counts[tlog.KindLoginIssue])
		}
	})
}

// TestVerifyBundlePoP (owner decision 2026-10-24, T-03-206): a
// bundle_install entry whose policy turns pop.hosts off fails at that
// entry; a successor that keeps it verifies.
func TestVerifyBundlePoP(t *testing.T) {
	t.Run("pop_hosts_removed_refused", func(t *testing.T) {
		lf := newLoginFixture(t, true)
		lf.installPolicy(func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: true} })
		lf.installPolicy(func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Machines: true} })
		entry := fmt.Sprintf("entry %d: bundle_install", len(lf.leaves)-1)
		_, err := lf.verify(join(lf.lines()), nil)
		if err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), "pop_hosts_removed") {
			t.Fatalf("Verify = %v, want pop_hosts_removed at %s", err, entry)
		}
	})
	t.Run("pop_hosts_kept_accepted", func(t *testing.T) {
		lf := newLoginFixture(t, true)
		lf.installPolicy(func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: true} })
		lf.installPolicy(func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: true, Machines: true} })
		if _, err := lf.verify(join(lf.lines()), nil); err != nil {
			t.Fatal(err)
		}
	})
}

// recoveryOpts changes a revocation_recovery entry the fixture logs: the
// request before it is signed (req), the signer of its evidence, the
// entries (nil: derived as the signer derives them), the resolution time,
// and the body after signing (body).
type recoveryOpts struct {
	req        func(*wire.RecoveryRequest)
	signer     ssh.Signer
	entries    func([]tlog.RevokedEntry) []tlog.RevokedEntry
	resolvedAt uint64
	body       func(*tlog.RecoveryBody)
}

// importKRL is a KRL version listing entries (nothing pruned), of version,
// for installation, its manifest signed by signer (the ops key when nil).
func (rf *revokeFixture) importKRL(entries []krl.Entry, version uint64, signer ssh.Signer, installation string) wire.RecoveryImport {
	rf.t.Helper()
	set, err := krl.PublishSet(entries, 0)
	if err != nil {
		rf.t.Fatal(err)
	}
	data, err := krl.Encode(set, version, time.Unix(1_700_000_000, 0))
	if err != nil {
		rf.t.Fatal(err)
	}
	return rf.signImport(data, version, signer, installation)
}

// signImport is importKRL over KRL bytes data.
func (rf *revokeFixture) signImport(data []byte, version uint64, signer ssh.Signer, installation string) wire.RecoveryImport {
	rf.t.Helper()
	if signer == nil {
		signer = rf.ops
	}
	m := krl.Manifest{InstallationID: installation, KRLVersion: version, KRLSHA256: krl.SHA256Hex(data),
		IssuedAt: time.Unix(1_700_000_000, 0).UTC().Format(trust.TimeFormat), BundleVersion: 1, LogIndex: 1}
	manifest, err := m.Canonical()
	if err != nil {
		rf.t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, signer, krl.Namespace, manifest)
	if err != nil {
		rf.t.Fatal(err)
	}
	return wire.RecoveryImport{KRL: data, Manifest: manifest, Sig: sig}
}

// issuedCerts are the certificates the fixture's issue and login_issue
// leaves logged, by serial.
func (rf *revokeFixture) issuedCerts() map[uint64]*ssh.Certificate {
	rf.t.Helper()
	out := map[uint64]*ssh.Certificate{}
	for _, raw := range rf.leaves {
		l, err := tlog.DecodeLeaf(raw)
		if err != nil {
			rf.t.Fatal(err)
		}
		var blob []byte
		switch l.Kind {
		case tlog.KindIssue:
			b, _ := tlog.DecodeIssueBody(l.Body)
			blob = b.Cert
		case tlog.KindLoginIssue:
			b, _ := tlog.DecodeLoginIssueBody(l.Body)
			blob = b.Cert
		default:
			continue
		}
		c, err := parseCert(blob)
		if err != nil {
			rf.t.Fatal(err)
		}
		out[c.Serial] = c
	}
	return out
}

// lostCert is a user certificate (u:alice, an hour from now) with a serial
// above every logged one, which the log never logs: a certificate a
// restore lost.
func (rf *revokeFixture) lostCert(serial uint64) *ssh.Certificate {
	rf.t.Helper()
	return rf.newCert(serial, time.UnixMicro(int64(rf.micros))) //nolint:gosec // G115: a test time
}

// treeRoot is the root of the fixture's leaves.
func (rf *revokeFixture) treeRoot() [32]byte {
	rf.t.Helper()
	var hashes [][]byte
	for _, l := range rf.leaves {
		hashes = append(hashes, tlog.HashLeaf(l))
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		rf.t.Fatal(err)
	}
	root, err := tree.Root()
	if err != nil {
		rf.t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], root)
	return out
}

// recover logs a revocation_recovery entry as the signer writes one: the
// request names this log's size and root and the installation, is signed
// by the policy admin, and its entries are krl.RecoveryEntries over the
// imports and certs with the logged certificates as the lookup. edit
// (optional) changes it.
func (rf *revokeFixture) recover(imports []wire.RecoveryImport, certs []wire.RecoveredCertificate, edit func(*recoveryOpts)) {
	rf.t.Helper()
	req := &wire.RecoveryRequest{InstallationID: auditInstallationID, CreatedAt: rf.secs(), RestoredSize: uint64(len(rf.leaves)), //nolint:gosec // G115: test size
		RestoredRoot: rf.treeRoot(), Imports: imports, Certificates: certs}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		rf.t.Fatal(err)
	}
	o := &recoveryOpts{signer: rf.admin, resolvedAt: rf.secs()}
	if edit != nil {
		edit(o)
	}
	if o.req != nil {
		o.req(req)
	}
	sb, err := req.SigningBytes()
	if err != nil {
		rf.t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, o.signer, wire.RecoverySSHSIGNamespace, sb)
	if err != nil {
		rf.t.Fatal(err)
	}
	var parsed []*krl.Parsed
	for _, im := range imports {
		p, err := krl.Parse(im.KRL)
		if err != nil {
			rf.t.Fatal(err)
		}
		parsed = append(parsed, p)
	}
	var rcs []krl.RecoveredCert
	for _, rc := range certs {
		c, err := parseCert(rc.Cert)
		if err != nil {
			rf.t.Fatal(err)
		}
		rcs = append(rcs, krl.RecoveredCert{CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, KeyID: c.KeyId, ValidBefore: c.ValidBefore, Revoke: rc.Revoke})
	}
	issued := rf.issuedCerts()
	derived, err := krl.RecoveryEntries(parsed, rcs, func(serial uint64) ([]byte, string, uint64, bool) {
		c, ok := issued[serial]
		if !ok {
			return nil, "", 0, false
		}
		return c.SignatureKey.Marshal(), c.KeyId, c.ValidBefore, true
	})
	if err != nil && o.entries == nil {
		rf.t.Fatal(err)
	}
	entries := revokedEntries(derived)
	if o.entries != nil {
		entries = o.entries(entries)
	}
	b := &tlog.RecoveryBody{PolicyVersion: 1, ResolvedAtSeconds: o.resolvedAt, Request: sb,
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}, Entries: entries}
	if o.body != nil {
		o.body(b)
	}
	body, err := b.Encode()
	if err != nil {
		rf.t.Fatal(err)
	}
	rf.add(tlog.KindRevocationRecovery, body)
	kinds := map[uint8]uint8{tlog.RevokedSerial: krl.EntrySerial, tlog.RevokedKeyID: krl.EntryKeyID, tlog.RevokedKey: krl.EntryKey}
	for _, e := range b.Entries {
		rf.entries = append(rf.entries, krl.Entry{Kind: kinds[e.Kind], CAKey: e.CAKey, Serial: e.Serial, KeyID: e.KeyID, Key: e.Key, ValidBefore: e.ValidBeforeSeconds})
	}
}

// sha256SectionKRL is a KRL of version whose only section is a SHA-256
// fingerprint section (type 5), which ssh-keygen may write and this
// installation never publishes.
func sha256SectionKRL(t testing.TB, version uint64) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddBytes([]byte(krl.Magic))
	b.AddUint32(krl.FormatVersion)
	b.AddUint64(version)
	b.AddUint64(0)
	b.AddUint64(0)
	b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {})
	b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {})
	b.AddUint8(5)
	b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestVerifyRecovery (03-06b): audit verify re-derives every
// revocation_recovery entry from its signed request, the trust state in
// force and the log before it, and refuses every entry a signer could not
// have written.
func TestVerifyRecovery(t *testing.T) {
	// base logs one certificate and a recovery that imports a KRL listing
	// it and a key, and carries a lost user certificate it revokes.
	base := func(rf *revokeFixture, edit func(*recoveryOpts)) (c *ssh.Certificate, im wire.RecoveryImport, lost *ssh.Certificate) {
		c = rf.issue()
		key := newSigner(rf.t, "ed25519").PublicKey().Marshal()
		im = rf.importKRL([]krl.Entry{{Kind: krl.EntrySerial, CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, ValidBefore: c.ValidBefore},
			{Kind: krl.EntryKey, Key: key}}, 7, nil, auditInstallationID)
		lost = rf.lostCert(rf.serial + 1000)
		rf.recover([]wire.RecoveryImport{im}, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, edit)
		return c, im, lost
	}
	type tc struct {
		name  string
		build func(rf *revokeFixture)
		want  string // "" accepted, otherwise a substring of the refusal
	}
	cases := []tc{
		{"recovery_accepted", func(rf *revokeFixture) { base(rf, nil); rf.publish(nil) }, ""},
		{"recovery_entries_tampered", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) { o.entries = func(es []tlog.RevokedEntry) []tlog.RevokedEntry { return es[1:] } })
			rf.publish(nil)
		}, "its entries are not those"},
		{"recovery_entry_vb_tampered", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) {
				o.entries = func(es []tlog.RevokedEntry) []tlog.RevokedEntry {
					for i := range es {
						if es[i].Kind == tlog.RevokedSerial && es[i].ValidBeforeSeconds > 0 {
							es[i].ValidBeforeSeconds--
							break
						}
					}
					return es
				}
			})
			rf.publish(nil)
		}, "its entries are not those"},
		{"recovery_entry_added_unbound", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) {
				o.entries = func(es []tlog.RevokedEntry) []tlog.RevokedEntry {
					return append(es, tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: rf.ca.PublicKey().Marshal(), Serial: 424242})
				}
			})
			rf.publish(nil)
		}, "its entries are not those"},
		{"recovery_restored_root_mismatch", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) { o.req = func(r *wire.RecoveryRequest) { r.RestoredRoot[0] ^= 1 } })
			rf.publish(nil)
		}, "restored root that is not the root"},
		{"recovery_restored_size_mismatch", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) { o.req = func(r *wire.RecoveryRequest) { r.RestoredSize-- } })
			rf.publish(nil)
		}, "names a restored log of"},
		{"recovery_not_admin", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) { o.signer = newSigner(rf.t, "ed25519") })
			rf.publish(nil)
		}, "not an admin of policy"},
		{"recovery_other_installation", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) {
				o.req = func(r *wire.RecoveryRequest) { r.InstallationID = "ffffffffffffffffffffffffffffffff" }
			})
			rf.publish(nil)
		}, "recovery_installation_mismatch"},
		{"recovery_import_unsigned", func(rf *revokeFixture) {
			c := rf.issue()
			im := rf.importKRL([]krl.Entry{{Kind: krl.EntrySerial, CAKey: c.SignatureKey.Marshal(), Serial: c.Serial}}, 7, newSigner(rf.t, "ed25519"), auditInstallationID)
			rf.recover([]wire.RecoveryImport{im}, nil, nil)
			rf.publish(nil)
		}, "recovery_import_invalid"},
		{"recovery_import_hash_section", func(rf *revokeFixture) {
			rf.issue()
			rf.recover([]wire.RecoveryImport{rf.signImport(sha256SectionKRL(rf.t, 7), 7, nil, auditInstallationID)}, nil, func(o *recoveryOpts) {
				o.entries = func([]tlog.RevokedEntry) []tlog.RevokedEntry { return nil }
			})
			rf.publish(nil)
		}, "fingerprint section"},
		{"recovery_certificate_forged", func(rf *revokeFixture) {
			rf.issue()
			lost := rf.lostCert(rf.serial + 1000)
			other := newSigner(rf.t, "ed25519")
			forged := forgeCert(rf.t.(*testing.T), lost, other, other.PublicKey())
			rf.recover(nil, []wire.RecoveredCertificate{{Cert: forged.Marshal(), Revoke: true}}, nil)
			rf.publish(nil)
		}, "recovery_certificate_invalid"},
		{"recovery_certificate_already_logged", func(rf *revokeFixture) {
			c := rf.issue()
			rf.recover(nil, []wire.RecoveredCertificate{{Cert: c.Marshal(), Revoke: true}}, nil)
			rf.publish(nil)
		}, "recovery_certificate_not_lost"},
		{"recovery_user_certificate_kept", func(rf *revokeFixture) {
			rf.issue()
			rf.recover(nil, []wire.RecoveredCertificate{{Cert: rf.lostCert(rf.serial + 1000).Marshal(), Revoke: false}}, nil)
			rf.publish(nil)
		}, "recovery_user_certificate_kept"},
		// A recovery carries only the lost certificates krl.CarriesLost
		// admits at its CreatedAt, as the signer requires (PR #69 review,
		// D-R2); the resolution time plays no part.
		{"recovery_certificate_expired", func(rf *revokeFixture) {
			rf.issue()
			lost := rf.lostCert(rf.serial + 1000)
			rf.recover(nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: false}}, func(o *recoveryOpts) {
				o.req = func(r *wire.RecoveryRequest) { r.CreatedAt = lost.ValidBefore + 600 }
			})
			rf.publish(nil)
		}, "(recovery_certificate_expired)"},
		{"recovery_expired_revoked_accepted", func(rf *revokeFixture) {
			rf.issue()
			lost := rf.lostCert(rf.serial + 1000)
			rf.recover(nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, func(o *recoveryOpts) {
				o.req = func(r *wire.RecoveryRequest) { r.CreatedAt = lost.ValidBefore + 600 }
			})
			rf.publish(nil)
		}, ""},
		{"recovery_prepared_live_applied_late_accepted", func(rf *revokeFixture) {
			rf.issue()
			// Valid until two hours ago; the request was prepared while it
			// was live and is resolved now, after it expired.
			lost := rf.newCert(rf.serial+1000, time.UnixMicro(int64(rf.micros)).Add(-3*time.Hour)) //nolint:gosec // G115: a test time
			rf.recover(nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: false}}, func(o *recoveryOpts) {
				o.req = func(r *wire.RecoveryRequest) { r.CreatedAt = lost.ValidBefore - 1000 }
			})
			rf.publish(nil)
		}, ""},
		{"recovery_unpublished_at_end", func(rf *revokeFixture) { base(rf, nil) }, "not followed by the krl_publish entry"},
		{"recovery_publish_not_above_import", func(rf *revokeFixture) {
			c := rf.issue()
			ahead := rf.secs() + 1000
			im := rf.importKRL([]krl.Entry{{Kind: krl.EntrySerial, CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, ValidBefore: c.ValidBefore}}, ahead, nil, auditInstallationID)
			rf.recover([]wire.RecoveryImport{im}, nil, nil)
			rf.publish(nil)
		}, "is not above the imported version"},
		{"recovery_resolved_after_leaf", func(rf *revokeFixture) {
			base(rf, func(o *recoveryOpts) { o.resolvedAt = rf.secs() + 10 })
			rf.publish(nil)
		}, "is after the leaf time"},

		// Successive recoveries (PR #66 review): a certificate that only a
		// recovery carried never joins the log's issuance, so a later
		// recovery's entry for it has ValidBefore 0, as on the signer.
		{"recovery_after_recovery_vb_zero_accepted", func(rf *revokeFixture) {
			_, _, lost := base(rf, nil)
			rf.publish(nil)
			im := rf.importKRL([]krl.Entry{{Kind: krl.EntrySerial, CAKey: lost.SignatureKey.Marshal(), Serial: lost.Serial}}, rf.krlVersion, nil, auditInstallationID)
			rf.recover([]wire.RecoveryImport{im}, nil, nil)
			if e := rf.entries[len(rf.entries)-1]; e.Serial != lost.Serial || e.ValidBefore != 0 {
				rf.t.Fatalf("the second recovery's entry %+v, want serial %d with ValidBefore 0", e, lost.Serial)
			}
			rf.publish(nil)
		}, ""},
		{"recovery_after_recovery_vb_from_leaf_refused", func(rf *revokeFixture) {
			_, _, lost := base(rf, nil)
			rf.publish(nil)
			im := rf.importKRL([]krl.Entry{{Kind: krl.EntrySerial, CAKey: lost.SignatureKey.Marshal(), Serial: lost.Serial}}, rf.krlVersion, nil, auditInstallationID)
			rf.recover([]wire.RecoveryImport{im}, nil, func(o *recoveryOpts) {
				o.entries = func(es []tlog.RevokedEntry) []tlog.RevokedEntry {
					es[0].ValidBeforeSeconds = lost.ValidBefore // from the first recovery's carried certificate
					return es
				}
			})
			rf.publish(nil)
		}, "its entries are not those"},
		{"recovery_carried_not_in_subject_revoke", func(rf *revokeFixture) {
			c, _, _ := base(rf, nil)
			rf.publish(nil)
			rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c)}, nil)
			rf.publish(nil)
		}, ""},
		{"recovery_carried_in_subject_revoke_refused", func(rf *revokeFixture) {
			c, _, lost := base(rf, nil)
			rf.publish(nil)
			rf.revoke(subjectAlice(), []tlog.RevokedEntry{serialEntry(c), serialEntry(lost)}, nil)
			rf.publish(nil)
		}, "lists 2 entries, but the log shows 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rf := newRevokeFixture(t)
			c.build(rf)
			rep, err := rf.verifyAll()
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("Verify: %v", err)
			case c.want == "" && rep.Recoveries == 0:
				t.Fatal("Verify counted no recovery")
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("Verify = %v, want a refusal containing %q", err, c.want)
			}
		})
	}
}

// TestVerifyRecoveryExportLines: the as-exported lines of a recovery
// verify, and its line carries counts only and none of the keys Verify
// binds to other kinds.
func TestVerifyRecoveryExportLines(t *testing.T) {
	rf := newRevokeFixture(t)
	c := rf.issue()
	im := rf.importKRL([]krl.Entry{{Kind: krl.EntrySerial, CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, ValidBefore: c.ValidBefore}}, 7, nil, auditInstallationID)
	rf.recover([]wire.RecoveryImport{im}, []wire.RecoveredCertificate{{Cert: rf.lostCert(rf.serial + 1000).Marshal(), Revoke: true}}, nil)
	rf.publish(nil)
	lines := rf.lines()
	rep, err := rf.verify(join(lines), nil)
	if err != nil || rep.Recoveries != 1 {
		t.Fatalf("Verify of the as-exported lines: %+v, %v", rep, err)
	}
	line := lines[len(lines)-3]
	for _, want := range []string{`"kind":"revocation_recovery"`, `"restored_size":2`, `"imports":1`, `"import_krl_versions":[7]`,
		`"certificates":1`, `"certificates_revoked":1`, `"entries":2`, `"admins":["SHA256:`} {
		if !strings.Contains(line, want) {
			t.Errorf("revocation_recovery line lacks %s:\n%s", want, line)
		}
	}
	for _, key := range []string{`"bundle_version":`, `"version":`, `"directory":`, `"sigs":`} {
		if strings.Contains(line, key) {
			t.Errorf("revocation_recovery line carries %s:\n%s", key, line)
		}
	}
	if strings.Count(line, `"kind":`) != 1 {
		t.Errorf("revocation_recovery line has %d kind keys, want 1", strings.Count(line, `"kind":`))
	}
	if strings.Contains(line, base64.StdEncoding.EncodeToString(im.KRL)) {
		t.Error("the revocation_recovery line renders the KRL bytes")
	}
}

// TestRecoveryLeafFitsExportLine: a revocation_recovery leaf with a body
// of exactly tlog.MaxRecoveryBody, written with Export's line encoder, is
// read back by Verify's line reader (maxLine) without "token too long".
func TestRecoveryLeafFitsExportLine(t *testing.T) {
	b := &tlog.RecoveryBody{PolicyVersion: 1, ResolvedAtSeconds: 1, Request: make([]byte, wire.MaxRecoveryRequest)}
	// 8+8+3+3+3 bytes of fixed fields; key entries take 23 bytes plus
	// their key.
	rest := tlog.MaxRecoveryBody - 25 - wire.MaxRecoveryRequest
	for rest > 0 {
		k := min(rest-23, wire.MaxSubjectKeyLen)
		b.Entries = append(b.Entries, tlog.RevokedEntry{Kind: tlog.RevokedKey, Key: bytes.Repeat([]byte{'k'}, k)})
		rest -= 23 + k
	}
	body, err := b.Encode()
	if err != nil || len(body) != tlog.MaxRecoveryBody {
		t.Fatalf("a body of %d bytes (%v), want exactly %d", len(body), err, tlog.MaxRecoveryBody)
	}
	leaf, err := tlog.MarshalLeaf(tlog.Leaf{Kind: tlog.KindRevocationRecovery, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Export(context.Background(), &buf, &memLog{leaves: [][]byte{leaf}, note: []byte("note")}); err != nil {
		t.Fatal(err)
	}
	if first := bytes.IndexByte(buf.Bytes(), '\n'); first < 14<<20 {
		t.Fatalf("the export line is %d bytes, want the largest body's (above 14 MiB)", first)
	}
	_, err = Verify(&buf, Options{Pins: []string{"SHA256:" + strings.Repeat("A", 43)}, Threshold: 1})
	if err == nil || strings.Contains(err.Error(), "too long") || !strings.Contains(err.Error(), "entry 0 (revocation_recovery)") {
		t.Fatalf("Verify = %v; want the line read and the entry checked (and refused: its request is zeros)", err)
	}
}

// TestVerifyCertificatesFrom: with Options.CertificatesFrom, the report
// lists exactly the certificates at or after that index, from the leaf
// bytes: those of issue and login_issue entries, and every certificate a
// revocation_recovery entry carries, each with its entry's index and kind.
func TestVerifyCertificatesFrom(t *testing.T) {
	t.Run("recovery_carried_listed", func(t *testing.T) {
		rf := newRevokeFixture(t)
		rf.issue()
		from := uint64(len(rf.leaves))
		c2 := rf.issue()
		lost := rf.lostCert(rf.serial + 1000)
		rf.recover(nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, nil)
		rf.publish(nil)
		rep, err := Verify(strings.NewReader(join(rf.lines())), Options{Pins: rf.pins(), Threshold: 1, CertificatesFrom: &from})
		if err != nil {
			t.Fatal(err)
		}
		want := []LoggedCertificate{{Index: from, Kind: tlog.KindIssue, Cert: c2.Marshal()}, {Index: from + 1, Kind: tlog.KindRevocationRecovery, Cert: lost.Marshal()}}
		if !slices.EqualFunc(rep.Certificates, want, func(a, b LoggedCertificate) bool {
			return a.Index == b.Index && a.Kind == b.Kind && bytes.Equal(a.Cert, b.Cert)
		}) {
			t.Fatalf("Certificates = %+v, want %+v", rep.Certificates, want)
		}
		if rep, err := rf.verifyAll(); err != nil || rep.Certificates != nil {
			t.Fatalf("without CertificatesFrom: %+v, %v; want no list", rep.Certificates, err)
		}
	})
	t.Run("login_issue_listed", func(t *testing.T) {
		lf := newLoginFixture(t, true)
		lf.addDirectory(lf.directory(nil), nil)
		lf.addLogin(nil, nil)
		body, err := tlog.DecodeLoginIssueBody(mustLeafBody(t, lf.leaves[len(lf.leaves)-1]))
		if err != nil {
			t.Fatal(err)
		}
		zero := uint64(0)
		rep, err := Verify(strings.NewReader(join(lf.lines())), Options{Pins: lf.pins(), Threshold: 1, CertificatesFrom: &zero})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Certificates) != 1 || rep.Certificates[0].Kind != tlog.KindLoginIssue || !bytes.Equal(rep.Certificates[0].Cert, body.Cert) {
			t.Fatalf("Certificates = %+v, want the login certificate", rep.Certificates)
		}
	})
}

// TestVerifyLastKRL: Report.LastKRL is the last published KRL, re-derived
// from the log: its SHA-256 is the manifest's, with the logged manifest
// and signature.
func TestVerifyLastKRL(t *testing.T) {
	rf := newRevokeFixture(t)
	c := rf.issue()
	rf.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)}, nil)
	rf.publish(nil)
	rep, err := rf.verifyAll()
	if err != nil {
		t.Fatal(err)
	}
	if rep.LastKRL == nil {
		t.Fatal("no LastKRL")
	}
	m, err := krl.VerifyManifest(rep.LastKRL.Manifest, rep.LastKRL.Sig, rep.LastKRL.KRL, rep.Bundle, auditInstallationID, 0)
	if err != nil || m.KRLVersion != rep.KRLVersion || m.KRLSHA256 != krl.SHA256Hex(rep.LastKRL.KRL) {
		t.Fatalf("LastKRL: %+v, %v", m, err)
	}
	p, err := krl.Parse(rep.LastKRL.KRL)
	if err != nil || !p.RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
		t.Fatalf("LastKRL does not list the revoked serial: %v", err)
	}
}
