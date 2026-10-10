package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
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
