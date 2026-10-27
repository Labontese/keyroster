package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// memSource is an in-memory audit.LogSource.
type memSource struct {
	leaves [][]byte
	note   []byte
}

func (m *memSource) ReadLog(_ context.Context, fn func(uint64, []byte) error) ([]byte, uint64, error) {
	for i, l := range m.leaves {
		if err := fn(uint64(i), l); err != nil { //nolint:gosec // G115: a test index
			return nil, 0, err
		}
	}
	return m.note, uint64(len(m.leaves)), nil
}

// logBuilder builds a signer log the way the signer writes one, under the
// trust bundle of a dirEnv (whose root the CLI config pins), so audit
// verify accepts its exports.
type logBuilder struct {
	t          *testing.T
	e          *dirEnv
	leaves     [][]byte
	micros     uint64
	logKey     ssh.Signer
	ops        ssh.Signer
	ca         map[string]ssh.Signer
	pol        *trust.Policy
	bundle     *trust.Bundle
	entries    []krl.Entry
	krlVersion uint64
	issued     map[uint64]*ssh.Certificate
	request    byte
}

// signerOf is the ssh.Signer of one of e's online keys.
func signerOf(t *testing.T, e *dirEnv, role string) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(e.caKeys[role])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// bundleDocs are the four documents of e's genesis bundle_install entry.
func bundleDocs(t *testing.T, e *dirEnv) *tlog.BundleInstallBody {
	t.Helper()
	var tr serverclient.TrustResponse
	if err := json.Unmarshal(e.trustDoc, &tr); err != nil {
		t.Fatal(err)
	}
	return &tlog.BundleInstallBody{BundleVersion: 1, Bundle: tr.Bundle, BundleSigs: tr.BundleSigs, Policy: tr.Policy, PolicySigs: tr.PolicySigs}
}

// newLogBuilder starts a log with install, half an hour ago (nil: e's
// genesis bundle), so its hour-long certificates are live.
func newLogBuilder(t *testing.T, e *dirEnv, install *tlog.BundleInstallBody) *logBuilder {
	t.Helper()
	return newLogBuilderAt(t, e, install, time.Now().Add(-30*time.Minute))
}

// newLogBuilderAt is newLogBuilder with a log that starts at start.
func newLogBuilderAt(t *testing.T, e *dirEnv, install *tlog.BundleInstallBody, start time.Time) *logBuilder {
	t.Helper()
	if install == nil {
		install = bundleDocs(t, e)
	}
	b := &logBuilder{t: t, e: e, micros: uint64(start.UnixMicro()), //nolint:gosec // G115: after 1970
		logKey: signerOf(t, e, "log"), ops: e.ops, ca: map[string]ssh.Signer{}, issued: map[uint64]*ssh.Certificate{}}
	for _, role := range []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine} {
		b.ca[role] = signerOf(t, e, role)
	}
	b.install(install)
	return b
}

// install logs a bundle_install entry.
func (b *logBuilder) install(body *tlog.BundleInstallBody) {
	b.t.Helper()
	var err error
	if b.bundle, err = trust.ParseBundle(body.Bundle); err != nil {
		b.t.Fatal(err)
	}
	if b.pol, err = trust.ParsePolicy(body.Policy); err != nil {
		b.t.Fatal(err)
	}
	enc, err := body.Encode()
	if err != nil {
		b.t.Fatal(err)
	}
	b.add(tlog.KindBundleInstall, enc)
}

// clone is a copy of b, to build a fork.
func (b *logBuilder) clone() *logBuilder {
	c := *b
	c.leaves = append([][]byte(nil), b.leaves...)
	c.entries = append([]krl.Entry(nil), b.entries...)
	c.issued = map[uint64]*ssh.Certificate{}
	for k, v := range b.issued {
		c.issued[k] = v
	}
	return &c
}

func (b *logBuilder) add(kind tlog.Kind, body []byte) {
	b.t.Helper()
	b.micros += 1000
	raw, err := tlog.MarshalLeaf(tlog.Leaf{Index: uint64(len(b.leaves)), TimeMicros: b.micros, Kind: kind, Body: body}) //nolint:gosec // G115: test size
	if err != nil {
		b.t.Fatal(err)
	}
	b.leaves = append(b.leaves, raw)
}

// secs is the next leaf's time in whole seconds.
func (b *logBuilder) secs() uint64 { return (b.micros + 1000) / 1_000_000 }

// cert is a certificate cert.Build gives role's CA for subject with
// serial, under the policy in force, an hour long.
func (b *logBuilder) cert(role, subject string, serial uint64) *ssh.Certificate {
	b.t.Helper()
	profile, err := certprofile.ForRole(role, b.pol)
	if err != nil {
		b.t.Fatal(err)
	}
	sub := newRevokeKey(b.t)
	b.request++
	kid := cert.KeyID{CA: role, Subject: subject, Request: strings.Repeat(strconv.FormatUint(uint64(b.request%10), 10), 32), Policy: b.pol.Version, Serial: serial}
	c, err := cert.Build(cert.Request{Profile: profile, Subject: sub, Principals: []string{"alice"}, Now: time.UnixMicro(int64(serial)), //nolint:gosec // G115: a test time
		ValidFor: time.Hour, KeyID: kid, Serial: serial}, b.ca[role], rand.Reader)
	if err != nil {
		b.t.Fatal(err)
	}
	return c
}

// issue logs an issue entry for a fresh certificate of role.
func (b *logBuilder) issue(role string) *ssh.Certificate {
	b.t.Helper()
	serial := b.micros + 1000
	c := b.cert(role, "u:alice", serial)
	roles := map[string]wire.CARole{trust.RoleUser: wire.CARoleUser, trust.RoleHost: wire.CARoleHost, trust.RoleMachine: wire.CARoleMachine}
	body, err := (&tlog.IssueBody{CARole: uint8(roles[role]), Serial: serial, PolicyVersion: b.pol.Version,
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sig")}}, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
	if err != nil {
		b.t.Fatal(err)
	}
	b.add(tlog.KindIssue, body)
	b.issued[serial] = c
	return c
}

// lost is a certificate of role that this log never issues, with a serial
// above every logged one: what a restore lost.
func (b *logBuilder) lost(role string) *ssh.Certificate {
	b.t.Helper()
	return b.cert(role, "u:alice", b.micros+500)
}

// revokeSerial logs a revocation of c by serial.
func (b *logBuilder) revokeSerial(c *ssh.Certificate) {
	b.t.Helper()
	req := &wire.RevokeRequest{InstallationID: b.bundle.InstallationID, Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial,
		CreatedAt: b.secs(), Reason: "test"}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		b.t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, b.e.signers[0], wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		b.t.Fatal(err)
	}
	e := tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, ValidBeforeSeconds: c.ValidBefore}
	body, err := (&tlog.RevokeBody{PolicyVersion: b.pol.Version, ResolvedAtSeconds: b.secs(), Request: req.SigningBytes(),
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}, Entries: []tlog.RevokedEntry{e}}).Encode()
	if err != nil {
		b.t.Fatal(err)
	}
	b.add(tlog.KindRevoke, body)
	b.entries = append(b.entries, krl.Entry{Kind: krl.EntrySerial, CAKey: e.CAKey, Serial: e.Serial, ValidBefore: e.ValidBeforeSeconds})
}

// publish logs a krl_publish entry as the signer writes one.
func (b *logBuilder) publish() {
	b.t.Helper()
	issuedAt := b.secs()
	version := max(b.krlVersion+1, issuedAt)
	set, err := krl.PublishSet(b.entries, issuedAt)
	if err != nil {
		b.t.Fatal(err)
	}
	data, err := krl.Encode(set, version, time.Unix(int64(issuedAt), 0)) //nolint:gosec // G115: a test time
	if err != nil {
		b.t.Fatal(err)
	}
	manifest, sig := b.manifest(data, version, issuedAt, uint64(len(b.leaves)), b.bundle.InstallationID, b.ops) //nolint:gosec // G115: test size
	body, err := (&tlog.KRLPublishBody{KRLVersion: version, BundleVersion: b.bundle.Version, IssuedAtSeconds: issuedAt,
		SHA256: sha256.Sum256(data), Manifest: manifest, Sig: sig}).Encode()
	if err != nil {
		b.t.Fatal(err)
	}
	b.add(tlog.KindKRLPublish, body)
	b.krlVersion = version
}

// manifest is the canonical manifest of a KRL version and its SSHSIG by
// signer.
func (b *logBuilder) manifest(data []byte, version, issuedAt, logIndex uint64, installation string, signer ssh.Signer) ([]byte, []byte) {
	b.t.Helper()
	m := krl.Manifest{InstallationID: installation, KRLVersion: version, KRLSHA256: krl.SHA256Hex(data),
		IssuedAt: time.Unix(int64(issuedAt), 0).UTC().Format(trust.TimeFormat), BundleVersion: b.bundle.Version, LogIndex: logIndex} //nolint:gosec // G115: a test time
	manifest, err := m.Canonical()
	if err != nil {
		b.t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, signer, krl.Namespace, manifest)
	if err != nil {
		b.t.Fatal(err)
	}
	return manifest, sig
}

// serverCopy writes a KRL document keyroster-server would keep: the KRL
// of every logged entry plus extra, as version, for installation, signed
// by signer (the ops key when nil). It returns the file.
func (b *logBuilder) serverCopy(extra []krl.Entry, version uint64, installation string, signer ssh.Signer) string {
	b.t.Helper()
	if signer == nil {
		signer = b.ops
	}
	set, err := krl.PublishSet(append(append([]krl.Entry(nil), b.entries...), extra...), 0)
	if err != nil {
		b.t.Fatal(err)
	}
	data, err := krl.Encode(set, version, time.Now())
	if err != nil {
		b.t.Fatal(err)
	}
	manifest, sig := b.manifest(data, version, uint64(time.Now().Unix()), 99, installation, signer) //nolint:gosec // G115: after 1970
	doc, err := json.Marshal(serverclient.KRLDocument{KRL: data, Manifest: manifest, Sig: sig})
	if err != nil {
		b.t.Fatal(err)
	}
	p := filepath.Join(b.t.TempDir(), "krl-served.json")
	writeTestFile(b.t, p, doc)
	return p
}

// root is the root of the log's leaves.
func (b *logBuilder) root() [32]byte {
	b.t.Helper()
	var hashes [][]byte
	for _, l := range b.leaves {
		hashes = append(hashes, tlog.HashLeaf(l))
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		b.t.Fatal(err)
	}
	root, err := tree.Root()
	if err != nil {
		b.t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], root)
	return out
}

// recover logs a revocation_recovery entry, as a recovered signer writes
// one, carrying certs and importing nothing.
func (b *logBuilder) recover(certs []wire.RecoveredCertificate) {
	b.t.Helper()
	req := &wire.RecoveryRequest{InstallationID: b.bundle.InstallationID, CreatedAt: b.secs(), RestoredSize: uint64(len(b.leaves)), //nolint:gosec // G115: test size
		RestoredRoot: b.root(), Certificates: certs}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		b.t.Fatal(err)
	}
	sb, err := req.SigningBytes()
	if err != nil {
		b.t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, b.e.signers[0], wire.RecoverySSHSIGNamespace, sb)
	if err != nil {
		b.t.Fatal(err)
	}
	var rcs []krl.RecoveredCert
	for _, rc := range certs {
		c, err := parseLostCert(rc.Cert)
		if err != nil {
			b.t.Fatal(err)
		}
		rcs = append(rcs, krl.RecoveredCert{CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, KeyID: c.KeyId, ValidBefore: c.ValidBefore, Revoke: rc.Revoke})
	}
	derived, err := krl.RecoveryEntries(nil, rcs, b.lookup)
	if err != nil {
		b.t.Fatal(err)
	}
	var entries []tlog.RevokedEntry
	for _, e := range derived {
		entries = append(entries, tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: e.CAKey, Serial: e.Serial, ValidBeforeSeconds: e.ValidBefore})
	}
	body, err := (&tlog.RecoveryBody{PolicyVersion: b.pol.Version, ResolvedAtSeconds: b.secs(), Request: sb,
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}, Entries: entries}).Encode()
	if err != nil {
		b.t.Fatal(err)
	}
	b.add(tlog.KindRevocationRecovery, body)
	b.entries = append(b.entries, derived...)
}

// lookup is the log's issuance, for krl.RecoveryEntries.
func (b *logBuilder) lookup(serial uint64) ([]byte, string, uint64, bool) {
	c, ok := b.issued[serial]
	if !ok {
		return nil, "", 0, false
	}
	return c.SignatureKey.Marshal(), c.KeyId, c.ValidBefore, true
}

// export writes the first n leaves (all when n < 0), checkpointed by the
// log key, as an export file.
func (b *logBuilder) export(n int) string {
	b.t.Helper()
	if n < 0 {
		n = len(b.leaves)
	}
	var hashes [][]byte
	for _, l := range b.leaves[:n] {
		hashes = append(hashes, tlog.HashLeaf(l))
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		b.t.Fatal(err)
	}
	root, err := tree.Root()
	if err != nil {
		b.t.Fatal(err)
	}
	origin := tlog.Origin(b.logKey.PublicKey())
	ns, err := tlog.NewNoteSigner(origin, b.logKey)
	if err != nil {
		b.t.Fatal(err)
	}
	note, err := tlog.SignCheckpoint(tlog.Checkpoint{Origin: origin, Size: uint64(n), Root: root}, ns) //nolint:gosec // G115: test size
	if err != nil {
		b.t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := audit.Export(context.Background(), &buf, &memSource{leaves: b.leaves[:n], note: note}); err != nil {
		b.t.Fatal(err)
	}
	p := filepath.Join(b.t.TempDir(), "export.jsonl")
	writeTestFile(b.t, p, buf.Bytes())
	return p
}

// recoverScenario is the common log: the genesis bundle, certificate c1,
// the start-up publish (the restored export ends here), then lost user
// certificate U, lost host certificate H, the revocation of c1 and its
// publish (the saved export).
type recoverScenario struct {
	e               *dirEnv
	b               *logBuilder
	c1, u, h        *ssh.Certificate
	restored, saved string
	restoredN       int
	out             string
}

func newRecoverScenario(t *testing.T) *recoverScenario {
	t.Helper()
	e := newDirEnv(t, 1, 1)
	b := newLogBuilder(t, e, nil)
	s := &recoverScenario{e: e, b: b}
	s.c1 = b.issue(trust.RoleUser)
	b.publish()
	s.restoredN = len(b.leaves)
	s.u = b.issue(trust.RoleUser)
	s.h = b.issue(trust.RoleHost)
	b.revokeSerial(s.c1)
	b.publish()
	s.restored, s.saved = b.export(s.restoredN), b.export(-1)
	s.out = filepath.Join(t.TempDir(), "recovery.req")
	return s
}

// run runs keyroster revoke recover with the scenario's exports, --out
// and extra.
func (s *recoverScenario) run(t *testing.T, extra ...string) (int, string, string) {
	t.Helper()
	return run(t, append([]string{"revoke", "recover", "--restored", s.restored, "--saved", s.saved, "--out", s.out, "--yes"}, extra...)...)
}

// request parses the written request.
func (s *recoverScenario) request(t *testing.T) *wire.RecoveryRequest {
	t.Helper()
	r, err := wire.ParseRecoveryRequest(readTestFile(t, s.out))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// carried maps the request's certificates by serial to their Revoke flag.
func carried(t *testing.T, r *wire.RecoveryRequest) map[uint64]bool {
	t.Helper()
	out := map[uint64]bool{}
	for _, rc := range r.Certificates {
		c, err := parseLostCert(rc.Cert)
		if err != nil {
			t.Fatal(err)
		}
		out[c.Serial] = rc.Revoke
	}
	return out
}

// noIDBundle is e's genesis bundle without an installation ID, re-signed
// by e's root, and a successor with one (version 2), for the installation
// ID cases.
func noIDBundles(t *testing.T, e *dirEnv) (genesis, successor *tlog.BundleInstallBody) {
	t.Helper()
	docs := bundleDocs(t, e)
	rootSigner, err := ssh.NewSignerFromKey(e.root)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(b *trust.Bundle) *tlog.BundleInstallBody {
		doc, err := b.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sshsig.Sign(rand.Reader, rootSigner, trust.NamespaceBundle, doc)
		if err != nil {
			t.Fatal(err)
		}
		return &tlog.BundleInstallBody{BundleVersion: b.Version, Bundle: doc, BundleSigs: sig, Policy: docs.Policy, PolicySigs: docs.PolicySigs}
	}
	g := *e.bundle
	g.InstallationID = ""
	genesis = sign(&g)
	next := g
	next.Version, next.Prev, next.InstallationID = 2, trust.SHA256Hex(genesis.Bundle), "fedcba9876543210fedcba9876543210"
	return genesis, sign(&next)
}

// TestRevokeRecover (03-06b): keyroster revoke recover reads every input
// first, verifies both exports on the saved trust pins, applies the prefix
// rule, the installation-ID rule and the owner's answer on lost
// certificates (revoke-users-list-others), and signs one recovery request
// offline.
func TestRevokeRecover(t *testing.T) {
	t.Run("saved_longer_collects_lost_certificates", func(t *testing.T) {
		s := newRecoverScenario(t)
		code, out, errOut := s.run(t)
		if code != 0 {
			t.Fatalf("exit %d:\n%s%s", code, out, errOut)
		}
		got := carried(t, s.request(t))
		if len(got) != 2 || !got[s.u.Serial] || got[s.h.Serial] {
			t.Fatalf("carried %v, want U revoked and H kept", got)
		}
		r := s.request(t)
		if len(r.Imports) != 1 || r.RestoredSize != uint64(s.restoredN) || r.InstallationID != s.e.bundle.InstallationID { //nolint:gosec // G115: test size
			t.Fatalf("request %+v", r)
		}
	})
	t.Run("restored_longer_no_lost_certificates", func(t *testing.T) {
		s := newRecoverScenario(t)
		s.restored, s.saved = s.saved, s.restored
		code, out, errOut := s.run(t)
		if code != 0 || !strings.Contains(out, "lost certificates: none\n") || len(s.request(t).Certificates) != 0 {
			t.Fatalf("exit %d:\n%s%s", code, out, errOut)
		}
	})
	t.Run("fork_refused", func(t *testing.T) {
		s := newRecoverScenario(t)
		fork := s.b.clone()
		fork.leaves = fork.leaves[:s.restoredN]
		fork.issue(trust.RoleMachine)
		s.restored = fork.export(-1)
		code, _, errOut := s.run(t)
		if code == 0 || !strings.Contains(errOut, "recovery_fork") || fileExists(s.out) {
			t.Fatalf("a fork: exit %d:\n%s", code, errOut)
		}
	})
	t.Run("export_not_verified_refused", func(t *testing.T) {
		s := newRecoverScenario(t)
		cfg := *s.e.cfg
		cfg.TrustPins = []string{ssh.FingerprintSHA256(newRevokeKey(t))}
		if _, err := saveConfig(&cfg, true); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := s.run(t)
		if code == 0 || !strings.Contains(errOut, "does not verify on your trust pins") || fileExists(s.out) {
			t.Fatalf("another trust pin: exit %d:\n%s", code, errOut)
		}
	})
	t.Run("server_copy_other_installation_refused", func(t *testing.T) {
		s := newRecoverScenario(t)
		doc := s.b.serverCopy(nil, s.b.krlVersion+1, "fedcba9876543210fedcba9876543210", nil)
		code, _, errOut := s.run(t, "--krl", doc)
		if code == 0 || !strings.Contains(errOut, "recovery_import_invalid") || fileExists(s.out) {
			t.Fatalf("a server copy of another installation: exit %d:\n%s", code, errOut)
		}
	})
	t.Run("user_live_revoked_by_default", func(t *testing.T) {
		s := newRecoverScenario(t)
		if code, out, errOut := s.run(t); code != 0 {
			t.Fatalf("exit %d:\n%s%s", code, out, errOut)
		}
		if !carried(t, s.request(t))[s.u.Serial] {
			t.Fatal("the lost live user certificate is not revoked")
		}
	})
	t.Run("revoke_lost_names_host", func(t *testing.T) {
		s := newRecoverScenario(t)
		if code, out, errOut := s.run(t, "--revoke-lost", strconv.FormatUint(s.h.Serial, 10)); code != 0 {
			t.Fatalf("exit %d:\n%s%s", code, out, errOut)
		}
		if got := carried(t, s.request(t)); !got[s.h.Serial] || !got[s.u.Serial] {
			t.Fatalf("carried %v, want H revoked as named", got)
		}
	})
	t.Run("revoke_lost_unknown_serial_refused", func(t *testing.T) {
		for _, serial := range []func(s *recoverScenario) uint64{
			func(*recoverScenario) uint64 { return 12345 },
			func(s *recoverScenario) uint64 { return s.u.Serial },  // a user certificate
			func(s *recoverScenario) uint64 { return s.c1.Serial }, // not lost
		} {
			s := newRecoverScenario(t)
			code, _, errOut := s.run(t, "--revoke-lost", strconv.FormatUint(serial(s), 10))
			if code == 0 || !strings.Contains(errOut, "recovery_revoke_lost_unknown") || fileExists(s.out) {
				t.Fatalf("--revoke-lost %d: exit %d:\n%s", serial(s), code, errOut)
			}
		}
	})
	t.Run("summary_lists_kept_with_key", func(t *testing.T) {
		s := newRecoverScenario(t)
		code, out, errOut := s.run(t)
		if code != 0 {
			t.Fatalf("exit %d:\n%s%s", code, out, errOut)
		}
		keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.h.Key)))
		for _, want := range []string{
			"installation: " + s.e.bundle.InstallationID + "\n",
			"lost certificate: serial " + strconv.FormatUint(s.u.Serial, 10) + ", user, subject u:alice, key " + ssh.FingerprintSHA256(s.u.Key) +
				", valid before " + strconv.FormatUint(s.u.ValidBefore, 10) + " (live): revoke\n",
			"lost certificate: serial " + strconv.FormatUint(s.h.Serial, 10) + ", host, subject u:alice, key " + ssh.FingerprintSHA256(s.h.Key) +
				", valid before " + strconv.FormatUint(s.h.ValidBefore, 10) + " (live): keep; public key " + keyLine +
				"; revoke later with: keyroster revoke key <file with this public key>\n",
			"import: saved export, log entry " + strconv.Itoa(len(s.b.leaves)-1) + ": KRL v" + strconv.FormatUint(s.b.krlVersion, 10),
			"entries: 2; the KRL the recovery publishes must be above v" + strconv.FormatUint(s.b.krlVersion, 10) + "\n",
			"wrote the signed recovery request to " + s.out,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the summary lacks %q:\n%s", want, out)
			}
		}
	})
	t.Run("offline_no_server_call", func(t *testing.T) {
		s := newRecoverScenario(t)
		cfg := *s.e.cfg
		cfg.Server = "https://127.0.0.1:1"
		if _, err := saveConfig(&cfg, true); err != nil {
			t.Fatal(err)
		}
		if code, out, errOut := s.run(t); code != 0 || !fileExists(s.out) {
			t.Fatalf("with the server URL at a closed port: exit %d:\n%s%s", code, out, errOut)
		}
		s.e.mu.Lock()
		calls := len(s.e.calls)
		s.e.mu.Unlock()
		if calls != 0 {
			t.Fatalf("%d calls reached the server", calls)
		}
	})
	t.Run("out_exists_refused", func(t *testing.T) {
		s := newRecoverScenario(t)
		writeTestFile(t, s.out, []byte("already here"))
		if code, _, errOut := s.run(t); code == 0 || !strings.Contains(errOut, "exists") || string(readTestFile(t, s.out)) != "already here" {
			t.Fatalf("an existing --out: exit %d:\n%s", code, errOut)
		}
	})
	t.Run("signed_bytes_verify", func(t *testing.T) {
		s := newRecoverScenario(t)
		if code, out, errOut := s.run(t); code != 0 {
			t.Fatalf("exit %d:\n%s%s", code, out, errOut)
		}
		r := s.request(t)
		sb, err := r.SigningBytes()
		if err != nil || len(r.Evidence) != 1 || r.Evidence[0].Type != wire.EvidenceAdminSSHSIG {
			t.Fatalf("request evidence %+v, %v", r.Evidence, err)
		}
		sig, err := sshsig.Parse(r.Evidence[0].Blob)
		if err != nil || sig.Verify(wire.RecoverySSHSIGNamespace, sb) != nil || ssh.FingerprintSHA256(sig.PublicKey()) != s.e.fps[0] {
			t.Fatalf("the evidence does not verify by the admin key under %s: %v", wire.RecoverySSHSIGNamespace, err)
		}
		if fi, err := os.Stat(s.out); err != nil || (fi.Mode().Perm() != 0o600 && runtime.GOOS != "windows") {
			t.Fatalf("--out: %v, %v; want mode 0600", fi, err)
		}
	})
	t.Run("installation_id_lost_refused", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		genesis, successor := noIDBundles(t, e)
		b := newLogBuilder(t, e, genesis)
		restored := b.export(-1)
		b.install(successor)
		saved := b.export(-1)
		out := filepath.Join(t.TempDir(), "recovery.req")
		code, stdout, errOut := run(t, "revoke", "recover", "--restored", restored, "--saved", saved, "--out", out, "--yes")
		if code == 0 || !strings.Contains(errOut, "recovery_installation_lost") || strings.Contains(stdout, "nothing to recover") || fileExists(out) {
			t.Fatalf("a lost installation ID: exit %d:\n%s%s", code, stdout, errOut)
		}
	})
	t.Run("krl_given_without_installation_id_refused", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		genesis, _ := noIDBundles(t, e)
		b := newLogBuilder(t, e, genesis)
		export := b.export(-1)
		// An ops-signed KRL document of a later bundle with an ID.
		doc := b.serverCopy(nil, 7, "fedcba9876543210fedcba9876543210", nil)
		out := filepath.Join(t.TempDir(), "recovery.req")
		code, stdout, errOut := run(t, "revoke", "recover", "--restored", export, "--saved", export, "--krl", doc, "--out", out, "--yes")
		if code == 0 || !strings.Contains(errOut, "recovery_installation_lost") || strings.Contains(stdout, "nothing to recover") || fileExists(out) {
			t.Fatalf("a --krl document under bundles without an installation ID: exit %d:\n%s%s", code, stdout, errOut)
		}
	})
	t.Run("krl_malformed_refused", func(t *testing.T) {
		for name, withID := range map[string]bool{"neither_bundle_has_an_id": false, "with_id": true} {
			t.Run(name, func(t *testing.T) {
				e := newDirEnv(t, 1, 1)
				var b *logBuilder
				if withID {
					b = newLogBuilder(t, e, nil)
				} else {
					genesis, _ := noIDBundles(t, e)
					b = newLogBuilder(t, e, genesis)
				}
				export := b.export(-1)
				bad := filepath.Join(t.TempDir(), "krl-served.json")
				writeTestFile(t, bad, []byte(`{"krl":"not base64"}`))
				out := filepath.Join(t.TempDir(), "recovery.req")
				code, stdout, errOut := run(t, "revoke", "recover", "--restored", export, "--saved", export, "--krl", bad, "--out", out, "--yes")
				if code == 0 || !strings.Contains(errOut, "recovery_import_invalid") || strings.Contains(stdout, "nothing to recover") || fileExists(out) {
					t.Fatalf("a --krl file that is not a KRL document: exit %d:\n%s%s", code, stdout, errOut)
				}
			})
		}
	})
	t.Run("no_installation_id_nothing_to_recover", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		genesis, _ := noIDBundles(t, e)
		b := newLogBuilder(t, e, genesis)
		b.issue(trust.RoleUser)
		export := b.export(-1)
		out := filepath.Join(t.TempDir(), "recovery.req")
		code, stdout, errOut := run(t, "revoke", "recover", "--restored", export, "--saved", export, "--out", out, "--yes")
		if code != 0 || stdout != nothingToRecover+"\n" || fileExists(out) {
			t.Fatalf("neither bundle with an installation ID: exit %d:\n%s%s", code, stdout, errOut)
		}
	})
	t.Run("restore_before_recovery_relists_carried", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		b := newLogBuilder(t, e, nil)
		b.issue(trust.RoleUser)
		b.publish()
		restoredN := len(b.leaves)
		u, h := b.lost(trust.RoleUser), b.lost(trust.RoleHost)
		if u.Serial == h.Serial {
			b.micros += 1000
			h = b.lost(trust.RoleHost)
		}
		certs := []wire.RecoveredCertificate{{Cert: u.Marshal(), Revoke: true}, {Cert: h.Marshal()}}
		if h.Serial < u.Serial {
			certs[0], certs[1] = certs[1], certs[0]
		}
		b.recover(certs)
		b.publish()
		out := filepath.Join(t.TempDir(), "recovery.req")
		code, stdout, errOut := run(t, "revoke", "recover", "--restored", b.export(restoredN), "--saved", b.export(-1), "--out", out, "--yes")
		if code != 0 {
			t.Fatalf("exit %d:\n%s%s", code, stdout, errOut)
		}
		for _, c := range []*ssh.Certificate{u, h} {
			if !strings.Contains(stdout, "lost certificate: serial "+strconv.FormatUint(c.Serial, 10)+",") {
				t.Errorf("the summary does not list serial %d again:\n%s", c.Serial, stdout)
			}
		}
		r, err := wire.ParseRecoveryRequest(readTestFile(t, out))
		if err != nil {
			t.Fatal(err)
		}
		if got := carried(t, r); len(got) != 2 || !got[u.Serial] || got[h.Serial] {
			t.Fatalf("carried %v, want U revoked and H kept again", got)
		}
		// The signer's derivation from this request gives U's entries
		// U's ValidBefore (its lookup, the restored issuance, has no U).
		var parsed []*krl.Parsed
		for _, im := range r.Imports {
			p, err := krl.Parse(im.KRL)
			if err != nil {
				t.Fatal(err)
			}
			parsed = append(parsed, p)
		}
		rcs := []krl.RecoveredCert{{CAKey: u.SignatureKey.Marshal(), Serial: u.Serial, KeyID: u.KeyId, ValidBefore: u.ValidBefore, Revoke: true},
			{CAKey: h.SignatureKey.Marshal(), Serial: h.Serial, KeyID: h.KeyId, ValidBefore: h.ValidBefore}}
		entries, err := krl.RecoveryEntries(parsed, rcs, nil)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, en := range entries {
			if en.Serial == u.Serial {
				found = en.ValidBefore == u.ValidBefore
			}
		}
		if !found {
			t.Fatalf("U's entry does not take U's ValidBefore: %+v", entries)
		}
	})
	// D-R2 (PR #69 review): a lost certificate that expired before the
	// request is not carried (and counted in the summary), unless
	// --revoke-lost names it; a live one is carried as before.
	t.Run("expired_lost_not_carried", func(t *testing.T) {
		for _, name := range []bool{false, true} {
			e := newDirEnv(t, 1, 1)
			b := newLogBuilderAt(t, e, nil, time.Now().Add(-3*time.Hour))
			b.issue(trust.RoleUser)
			b.publish()
			restoredN := len(b.leaves)
			uOld, hOld := b.issue(trust.RoleUser), b.issue(trust.RoleHost)   // valid until about two hours ago
			b.micros = uint64(time.Now().Add(-10 * time.Minute).UnixMicro()) //nolint:gosec // G115: after 1970
			uNew, hNew := b.issue(trust.RoleUser), b.issue(trust.RoleHost)
			b.publish()
			s := &recoverScenario{e: e, b: b, restored: b.export(restoredN), saved: b.export(-1), restoredN: restoredN,
				out: filepath.Join(t.TempDir(), "recovery.req")}
			var extra []string
			want := map[uint64]bool{uNew.Serial: true, hNew.Serial: false}
			wantLine := "lost certificates expired before this request, not carried: 2\n"
			if name {
				extra = []string{"--revoke-lost", strconv.FormatUint(hOld.Serial, 10)}
				want[hOld.Serial] = true
				wantLine = "lost certificates expired before this request, not carried: 1\n"
			}
			code, out, errOut := s.run(t, extra...)
			if code != 0 || !strings.Contains(out, wantLine) {
				t.Fatalf("--revoke-lost named %v: exit %d:\n%s%s", name, code, out, errOut)
			}
			if got := carried(t, s.request(t)); !maps.Equal(got, want) {
				t.Fatalf("--revoke-lost named %v: carried %v, want %v (expired user %d, host %d)", name, got, want, uOld.Serial, hOld.Serial)
			}
		}
	})
	// D-R1 (PR #69 review): a server copy near what the signer publishes,
	// 70,000 serials that are not adjacent, passes every limit of the CLI
	// and the request.
	t.Run("recovers_near_publishable_maximum", func(t *testing.T) {
		s := newRecoverScenario(t)
		caKey := s.b.ca[trust.RoleUser].PublicKey().Marshal()
		extra := make([]krl.Entry, 0, 70000)
		for i := range 70000 {
			extra = append(extra, krl.Entry{Kind: krl.EntrySerial, CAKey: caKey, Serial: 2*uint64(i) + 1}) //nolint:gosec // G115: a test index
		}
		doc := s.b.serverCopy(extra, s.b.krlVersion+1, s.e.bundle.InstallationID, nil)
		code, out, errOut := s.run(t, "--krl", doc)
		if code != 0 || !strings.Contains(out, "entries: 70002;") {
			t.Fatalf("a server copy of 70,000 serials: exit %d:\n%s%s", code, out, errOut)
		}
		if r := s.request(t); len(r.Imports) != 2 {
			t.Fatalf("the request imports %d KRL versions, want 2", len(r.Imports))
		}
	})
	t.Run("carried_serial_once", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		b := newLogBuilder(t, e, nil)
		b.issue(trust.RoleUser)
		b.publish()
		restoredN := len(b.leaves)
		u := b.lost(trust.RoleUser)
		for range 2 {
			b.recover([]wire.RecoveredCertificate{{Cert: u.Marshal(), Revoke: true}})
			b.publish()
		}
		out := filepath.Join(t.TempDir(), "recovery.req")
		code, stdout, errOut := run(t, "revoke", "recover", "--restored", b.export(restoredN), "--saved", b.export(-1), "--out", out, "--yes")
		if code != 0 {
			t.Fatalf("exit %d:\n%s%s", code, stdout, errOut)
		}
		r, err := wire.ParseRecoveryRequest(readTestFile(t, out))
		if err != nil || len(r.Certificates) != 1 {
			t.Fatalf("request %+v, %v; want U carried once", r, err)
		}
	})
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
