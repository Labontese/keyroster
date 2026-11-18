package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// tableCounts returns the row count of every table of the state database
// at path, read outside the signer (03-12e).
func tableCounts(t *testing.T, path string) map[string]int {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	counts := map[string]int{}
	for _, n := range names {
		var c int
		if err := raw.QueryRow(`SELECT count(*) FROM "` + n + `"`).Scan(&c); err != nil { //nolint:gosec // G202: a table name sqlite_master returned
			t.Fatal(err)
		}
		counts[n] = c
	}
	return counts
}

// sameCounts requires the table counts after to equal before.
func sameCounts(t *testing.T, before, after map[string]int) {
	t.Helper()
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("the table row counts changed:\nbefore %v\nafter  %v", before, after)
	}
}

// fixedClock is a clock that always reads t.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// roleMaxTTL is the max_ttl_seconds of role in p.
func roleMaxTTL(t *testing.T, p *trust.Policy, role string) uint64 {
	t.Helper()
	for _, prof := range p.CAProfiles {
		if prof.Role == role {
			return prof.MaxTTLSeconds
		}
	}
	t.Fatalf("the policy has no %s profile", role)
	return 0
}

// issueUser issues one user certificate through s valid for validFor
// seconds, created at now.
func issueUser(t *testing.T, e *genEnv, s *Signer, now time.Time, validFor uint64) *ssh.Certificate {
	t.Helper()
	req := &wire.IssueRequest{
		CARole: wire.CARoleUser, SubjectKey: newEd25519(t).PublicKey().Marshal(), Subject: "u:alice",
		Principals: []string{"alice"}, ValidForSeconds: uint32(validFor), CreatedAt: uint64(now.Unix()), //nolint:gosec // G115: a policy TTL and a time after 1970
		InstallationID: e.fx.InstallationID,
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	req.Evidence = SignRequest(t, req, e.fx.Admins...)
	resp, err := s.Issue(context.Background(), Peer{UID: 1000}, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pk, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatal("Issue returned no certificate")
	}
	return c
}

// switchDocs returns the root-signed successor of the bundle installed in
// e that switches role (its next entry becomes active and its active entry
// draining), built by trust.BuildSuccessor at issuedAt with allowance and
// the installed policy unchanged (03-12e).
func switchDocs(t *testing.T, e *genEnv, issuedAt time.Time, allowance time.Duration, roles ...string) [4][]byte {
	t.Helper()
	sb, err := e.db.LatestBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prev, err := trust.ParseBundle(sb.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	next, err := trust.BuildSuccessor(prev, sb.Bundle, sb.Policy, trust.SuccessorOptions{
		Roots: prev.Root.Keys, Threshold: prev.Root.Threshold, Policy: sb.Policy,
		IssuedAt: issuedAt.UTC().Format(trust.TimeFormat), InstallationID: prev.InstallationID,
		CASwitch: roles, DrainAllowance: allowance,
	})
	if err != nil {
		t.Fatalf("BuildSuccessor: %v", err)
	}
	pol, err := trust.ParsePolicy(sb.Policy)
	if err != nil {
		t.Fatal(err)
	}
	return docs4(t, next, pol, e.fx.Root)
}

// unixTime formats Unix seconds u in trust.TimeFormat.
func unixTime(u uint64) string {
	return time.Unix(int64(u), 0).UTC().Format(trust.TimeFormat) //nolint:gosec // G115: a test time
}

// TestSwitchTracer (03-12e, the tracer): one user CA switch end to end, in
// process. Ceremony 1 adds the prepared generation 2 as next; a certificate
// of generation 1 issued after the ceremony's clock is valid until V; a
// switch built by trust.BuildSuccessor whose trusted_until leaves that
// certificate live is refused with the certificate named and nothing
// written; with a longer allowance it installs behind the log's checkpoint,
// a restarted signer issues with generation 2, and audit verifies the
// export.
func TestSwitchTracer(t *testing.T) {
	ctx := context.Background()
	// t0 is the ceremony clock: a whole second, a minute ahead of the
	// real clock, so every fake signer clock below is after the leaves
	// written at bootstrap.
	t0 := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	e := newGenEnv(t)
	g2 := e.mustPrepare(t, keystore.RoleUser)
	if _, err := e.install(editedSuccessor(t, e.db, func(b *trust.Bundle) {
		insertCA(b, nextEntry(t, g2))
		b.IssuedAt = t0.Format(trust.TimeFormat)
	}, nil, e.fx.Root)); err != nil {
		t.Fatalf("ceremony 1: %v", err)
	}
	_, pol := installedDocs(t, e.db)
	m := roleMaxTTL(t, pol, trust.RoleUser)
	s, err := New(Config{Backend: e.be, DB: e.db, Clock: fixedClock(t0.Add(10 * time.Second)), AllowUIDs: []uint32{1000}})
	if err != nil {
		t.Fatalf("start after ceremony 1: %v", err)
	}
	c := issueUser(t, e, s, t0.Add(10*time.Second), m)
	v := uint64(t0.Unix()) + 10 + m //nolint:gosec // G115: after 1970
	if c.ValidBefore != v {
		t.Fatalf("the generation-1 certificate is valid until %d, want %d", c.ValidBefore, v)
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()) {
		t.Fatal("the certificate before the switch is not signed by generation 1")
	}
	installed := false
	t.Run("too_short_refused_writes_nothing", func(t *testing.T) {
		cp, _, err := e.db.LatestCheckpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		before, leaves := tableCounts(t, e.dbPath), e.leaves(t)
		d := switchDocs(t, e, t0, 0, trust.RoleUser)
		_, _, err = InstallBundleWithPrevious(ctx, e.db, e.be, nil, 0, d[0], d[1], d[2], d[3], fixedClock(t0.Add(20*time.Second)), cp)
		if !errors.Is(err, ErrDrainWindowTooShort) {
			t.Fatalf("the switch with allowance 0: %v, want drain_window_too_short", err)
		}
		t.Logf("refusal: %v", err)
		for _, want := range []string{
			fmt.Sprintf("serial %d", c.Serial), "key ID " + c.KeyId,
			"the earliest acceptable trusted_until is " + unixTime(v+300),
		} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal %q does not name %q", err, want)
			}
		}
		sameCounts(t, before, tableCounts(t, e.dbPath))
		if n := e.leaves(t); n != leaves {
			t.Fatalf("%d leaves after the refusal, want %d", n, leaves)
		}
	})
	t.Run("installed_and_issues_with_the_new_key", func(t *testing.T) {
		cp, _, err := e.db.LatestCheckpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		d := switchDocs(t, e, t0, 20*time.Second, trust.RoleUser)
		b, notes, err := InstallBundleWithPrevious(ctx, e.db, e.be, nil, 0, d[0], d[1], d[2], d[3], fixedClock(t0.Add(20*time.Second)), cp)
		if err != nil {
			t.Fatalf("the switch with allowance 20 s: %v", err)
		}
		if b.Version != 3 || trust.ActiveCA(b, trust.RoleUser).Generation != 2 {
			t.Fatalf("installed bundle v%d with active user generation %d, want v3 and generation 2", b.Version, trust.ActiveCA(b, trust.RoleUser).Generation)
		}
		if len(notes) != 1 || notes[0].Role != trust.RoleUser || notes[0].Generation != 1 || !notes[0].Recorded || notes[0].Max.Serial != c.Serial {
			t.Fatalf("drain notes %+v, want one for user generation 1 naming serial %d", notes, c.Serial)
		}
		installed = true
		dropDrained(t, e.be, notes)
		s2, err := New(Config{Backend: e.be, DB: e.db, Clock: fixedClock(t0.Add(30 * time.Second)), AllowUIDs: []uint32{1000}})
		if err != nil {
			t.Fatalf("restart after the switch: %v", err)
		}
		c2 := issueUser(t, e, s2, t0.Add(30*time.Second), 600)
		if !bytes.Equal(c2.SignatureKey.Marshal(), g2.PublicKey) {
			t.Fatalf("the certificate after the switch is signed by %s, want generation 2", ssh.FingerprintSHA256(c2.SignatureKey))
		}
	})
	t.Run("audit_verifies_the_switch", func(t *testing.T) {
		if !installed {
			t.Fatal("the switch was not installed")
		}
		var buf bytes.Buffer
		if _, err := audit.Export(ctx, &buf, e.db); err != nil {
			t.Fatal(err)
		}
		rep, err := audit.Verify(&buf, audit.Options{Pins: []string{e.fx.RootPin()}, Threshold: 1})
		if err != nil {
			t.Fatalf("audit.Verify: %v", err)
		}
		if rep.BundleVersion != 3 {
			t.Fatalf("audit reports bundle version %d, want 3", rep.BundleVersion)
		}
	})
}

// switchDocsDB returns the root-signed successor of the bundle installed
// in db that switches roles, built by trust.BuildSuccessor at issuedAt
// with allowance and the installed policy unchanged, signed by root
// (03-12e).
func switchDocsDB(t *testing.T, db *signerdb.DB, root ssh.Signer, issuedAt time.Time, allowance time.Duration, roles ...string) [4][]byte {
	t.Helper()
	sb, err := db.LatestBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prev, err := trust.ParseBundle(sb.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	next, err := trust.BuildSuccessor(prev, sb.Bundle, sb.Policy, trust.SuccessorOptions{
		Roots: prev.Root.Keys, Threshold: prev.Root.Threshold, Policy: sb.Policy,
		IssuedAt: issuedAt.UTC().Format(trust.TimeFormat), InstallationID: prev.InstallationID,
		CASwitch: roles, DrainAllowance: allowance,
	})
	if err != nil {
		t.Fatalf("BuildSuccessor: %v", err)
	}
	pol, err := trust.ParsePolicy(sb.Policy)
	if err != nil {
		t.Fatal(err)
	}
	return docs4(t, next, pol, root)
}

// swKit drives CA switches over the state of a revokeEnv-based fixture
// (03-12e): the env's memBackend wrapped as a genBackend, so that a
// generation can be prepared and opened while every key the env holds
// stays, and the env's clock, which the kit only moves forward. Every
// signer the kit starts after a switch runs on the genBackend.
type swKit struct {
	e   *logEnv
	clk *revokeClock
	gb  *genBackend
}

func newSwKit(e *revokeEnv) *swKit {
	return &swKit{e: e.logEnv, clk: e.clock, gb: &genBackend{memBackend: e.backend, fx: e.fx}}
}

// dropDrained removes from gb the key of every entry a successful switch
// install newly drains (03-12e): the stand-in for the runbook's removal
// step (ca-rotate retire-key), so that the signer started after the
// install serves, as it does once the old key is gone.
func dropDrained(t testing.TB, gb *genBackend, notes []DrainNote) {
	t.Helper()
	for _, n := range notes {
		gb.drop(t, keystore.Role(n.Role), n.Generation)
	}
}

func (k *swKit) now() time.Time { return k.clk.Now() }

// at moves the env's clock to at, never back.
func (k *swKit) at(t *testing.T, at time.Time) {
	t.Helper()
	if at.Before(k.clk.Now()) {
		t.Fatalf("the clock would move back from %s to %s", k.clk.Now(), at)
	}
	k.clk.set(at)
}

// reopen starts the env's signer, on the genBackend, as serve does after
// an install.
func (k *swKit) reopen(t *testing.T) {
	t.Helper()
	db, err := signerdb.Open(k.e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sdb, err := signerdb.OpenReadOnly(k.e.dbPath)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	s, err := New(Config{Backend: k.gb, Clock: k.clk.Now, DB: db, StatusDB: sdb, AllowUIDs: []uint32{1000}})
	if err != nil {
		_ = sdb.Close()
		_ = db.Close()
		t.Fatalf("start the signer on the generation backend: %v", err)
	}
	k.e.db, k.e.sdb, k.e.s = db, sdb, s
}

// stopped runs fn on one handle of the env's state database while the
// signer is stopped, then starts the signer again.
func (k *swKit) stopped(t *testing.T, fn func(db *signerdb.DB)) {
	t.Helper()
	k.e.close()
	db, err := signerdb.Open(k.e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	fn(db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	k.reopen(t)
}

// ceremonyTime moves the clock to the next whole second after both the
// clock and the installed bundle's issued_at, and returns it: the
// issued_at of a ceremony bundle, never after its install.
func (k *swKit) ceremonyTime(t *testing.T) time.Time {
	t.Helper()
	b, _ := installedDocs(t, k.e.db)
	at, err := time.Parse(trust.TimeFormat, b.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if now := k.now(); now.After(at) {
		at = now
	}
	at = at.Truncate(time.Second).Add(time.Second)
	k.at(t, at)
	return at
}

// ceremony1 prepares one generation of each role and installs, at the
// clock, the successor issued at issuedAt that adds them as next
// (ceremony 1, 03-12).
func (k *swKit) ceremony1(t *testing.T, issuedAt time.Time, roles ...keystore.Role) []signerdb.CAGeneration {
	t.Helper()
	var gens []signerdb.CAGeneration
	k.stopped(t, func(db *signerdb.DB) {
		for _, r := range roles {
			g, err := PrepareGeneration(context.Background(), db, k.gb, r, "", k.clk.Now)
			if err != nil {
				t.Fatalf("PrepareGeneration(%s): %v", r, err)
			}
			gens = append(gens, g)
		}
		d := editedSuccessor(t, db, func(b *trust.Bundle) {
			for _, g := range gens {
				insertCA(b, nextEntry(t, g))
			}
			b.IssuedAt = issuedAt.UTC().Format(trust.TimeFormat)
		}, nil, k.e.fx.Root)
		if _, err := InstallBundle(context.Background(), db, k.gb, nil, 0, d[0], d[1], d[2], d[3], k.clk.Now); err != nil {
			t.Fatalf("ceremony 1: %v", err)
		}
	})
	return gens
}

// maxTTL is the installed policy's max_ttl_seconds of role.
func (k *swKit) maxTTL(t *testing.T, role string) uint64 {
	t.Helper()
	_, pol := installedDocs(t, k.e.db)
	return roleMaxTTL(t, pol, role)
}

// allowance is the drain allowance that makes a switch of role issued at
// issuedAt end trust at tu under the installed policy.
func (k *swKit) allowance(t *testing.T, issuedAt time.Time, role string, tu uint64) time.Duration {
	t.Helper()
	ttl := k.maxTTL(t, role)
	floor, err := trust.DrainFloor(issuedAt.UTC().Format(trust.TimeFormat), ttl, ttl)
	if err != nil || tu < floor {
		t.Fatalf("trusted_until %d is below the floor %d of a %s switch (%v): the fixture's certificate does not outlive the floor", tu, floor, role, err)
	}
	return time.Duration(tu-floor) * time.Second //nolint:gosec // G115: a test allowance of a few seconds
}

// switchDocs builds the switch of roles, issued at issuedAt with
// allowance, over the env's installed bundle.
func (k *swKit) switchDocs(t *testing.T, issuedAt time.Time, allowance time.Duration, roles ...string) [4][]byte {
	t.Helper()
	return switchDocsDB(t, k.e.db, k.e.fx.Root, issuedAt, allowance, roles...)
}

// install installs d at the clock with the signer stopped, behind the
// log's latest checkpoint when withPrevious.
func (k *swKit) install(t *testing.T, d [4][]byte, withPrevious bool) ([]DrainNote, error) {
	t.Helper()
	var (
		notes []DrainNote
		err   error
	)
	k.stopped(t, func(db *signerdb.DB) {
		var cp []byte
		if withPrevious {
			var cerr error
			if cp, _, cerr = db.LatestCheckpoint(context.Background()); cerr != nil {
				t.Fatal(cerr)
			}
		}
		_, notes, err = InstallBundleWithPrevious(context.Background(), db, k.gb, nil, 0, d[0], d[1], d[2], d[3], k.clk.Now, cp)
		if err == nil {
			dropDrained(t, k.gb, notes)
		}
	})
	return notes, err
}

// issueAdmin issues, through the admin path at the clock (one millisecond
// on: serials come from the clock), a certificate of role valid for
// validFor seconds.
func (k *swKit) issueAdmin(t *testing.T, role wire.CARole, validFor uint64) *ssh.Certificate {
	t.Helper()
	k.at(t, k.now().Add(time.Millisecond))
	req := k.e.request()
	req.CARole, req.ValidForSeconds, req.CreatedAt = role, uint32(validFor), uint64(k.now().Unix()) //nolint:gosec // G115: a policy TTL and a time after 1970
	req.Evidence = SignRequest(t, req, k.e.fx.Admins...)
	resp, err := k.e.s.Issue(context.Background(), Peer{UID: 1000}, req)
	if err != nil {
		t.Fatalf("issue %s: %v", role, err)
	}
	return certOf(t, resp)
}

// audit is audit's verdict on the env's log.
func (k *swKit) audit(t *testing.T) error {
	t.Helper()
	return auditExport(t, k.e.fx, k.e.db)
}

// auditForced is audit's verdict on the env's log with the install leaf of
// d appended, although the signer refused d: on a copy of the state
// database, the leaf written by a plain log writer (03-12e).
func (k *swKit) auditForced(t *testing.T, d [4][]byte) error {
	t.Helper()
	k.e.close()
	path := copyState(t, k.e.dbPath)
	k.reopen(t)
	db, err := signerdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	b, err := trust.ParseBundle(d[0])
	if err != nil {
		t.Fatal(err)
	}
	enc, err := (&tlog.BundleInstallBody{BundleVersion: b.Version, Bundle: d[0], BundleSigs: d[1], Policy: d[2], PolicySigs: d[3]}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendRaw(db, k.e.fx, k.clk.Now, tlog.KindBundleInstall, enc); err != nil {
		t.Fatalf("append the refused switch's install leaf: %v", err)
	}
	return auditExport(t, k.e.fx, db)
}

// auditExport is audit's verdict on the export of db under fx's root pin.
func auditExport(t *testing.T, fx *Fixture, db *signerdb.DB) error {
	t.Helper()
	var buf bytes.Buffer
	if _, err := audit.Export(context.Background(), &buf, db); err != nil {
		t.Fatal(err)
	}
	_, err := audit.Verify(&buf, audit.Options{Pins: []string{fx.RootPin()}, Threshold: 1})
	return err
}

// copyState copies the state database at path, with its -wal and -shm
// files where present, into a new directory and returns the copy's path.
// No signer may have it open.
func copyState(t *testing.T, path string) string {
	t.Helper()
	dir := t.TempDir()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(path + suffix) //nolint:gosec // G304: the test's own database
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "signer.db"+suffix), data, 0o600); err != nil { //nolint:gosec // G703: a fixed name in the test's temporary directory
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "signer.db")
}

// appendRaw appends one leaf of kind with body to the log of db through a
// plain log writer, as the signer's own appends do, so its hash and the
// checkpoint follow; it returns the leaf's index. No signer may run on
// db. It is how a test writes a leaf the signer never would.
func appendRaw(db *signerdb.DB, fx *Fixture, clock func() time.Time, kind tlog.Kind, body []byte) (uint64, error) {
	ctx := context.Background()
	logKey, err := newMemBackend(fx).Key(keystore.RoleLog, ssh.FingerprintSHA256(fx.Roles[keystore.RoleLog].PublicKey()))
	if err != nil {
		return 0, err
	}
	lw, err := newLogWriter(ctx, db, logKey, clock)
	if err != nil {
		return 0, err
	}
	var idx uint64
	err = lw.logTx(ctx, func(tx *sql.Tx) error {
		var aerr error
		idx, aerr = lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(clock()), Kind: kind, Body: body})
		return aerr
	})
	return idx, err
}

// gen1Cert is a user or host certificate signed directly by the fixture's
// generation-1 key of role, with serial and ValidBefore validBefore: a
// certificate the signer did not issue (03-12e).
func gen1Cert(t *testing.T, fx *Fixture, role keystore.Role, serial, validBefore uint64) *ssh.Certificate {
	t.Helper()
	typ := uint32(ssh.UserCert)
	if role == keystore.RoleHost {
		typ = ssh.HostCert
	}
	return makeCert(t, fx.Roles[role], typ, string(role), "u:lost", serial, serial, validBefore, nil)
}

// truncated is blob without its last ten bytes: it no longer parses.
func truncated(blob []byte) []byte { return append([]byte(nil), blob[:len(blob)-10]...) }

// rawLoginBody is a login_issue body whose certificate bytes are blob.
func rawLoginBody(t *testing.T, serial uint64, blob []byte) []byte {
	t.Helper()
	enc, err := (&tlog.LoginIssueBody{Serial: serial, PolicyVersion: 1, DirectoryVersion: 1, Request: []byte("r"),
		Evidence: []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: []byte("assertion")}}, Cert: blob, KeyID: "kid"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// rawRecoveryBody is a revocation_recovery body whose request, for
// installation, carries the blobs (each revoked), written as a
// certificate list of length-prefixed blobs: Validate is not run on them.
func rawRecoveryBody(t *testing.T, installation string, blobs ...[]byte) []byte {
	t.Helper()
	r := &wire.RecoveryRequest{InstallationID: installation, CreatedAt: 1, RestoredSize: 1}
	sb, err := r.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	// The request with no certificate ends in its zero count; replace it
	// with the count and the blobs.
	if len(blobs) > 255 || sb[len(sb)-2] != 0 || sb[len(sb)-1] != 0 {
		t.Fatal("the recovery request does not end in its certificate count")
	}
	out := append(append([]byte(nil), sb[:len(sb)-2]...), 0, byte(len(blobs))) //nolint:gosec // G115: at most 255, checked above
	for _, b := range blobs {
		out = append(out, byte(len(b)>>16), byte(len(b)>>8), byte(len(b))) //nolint:gosec // G115: the bytes of a uint24 length; a test certificate is far shorter
		out = append(out, b...)
		out = append(out, 1)
	}
	enc, err := (&tlog.RecoveryBody{PolicyVersion: 1, ResolvedAtSeconds: 1, Request: out,
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sig")}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// nonCanonical returns the bytes of a certificate like gen1Cert's whose
// subject is an RSA key with its exponent written as the padded mpint 00
// 01 00 01: ssh.ParsePublicKey accepts it, and its Marshal differs.
func nonCanonical(t *testing.T, fx *Fixture, role keystore.Role, serial, validBefore uint64) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	typ := uint32(ssh.UserCert)
	if role == keystore.RoleHost {
		typ = ssh.HostCert
	}
	canon := makeCert(t, fx.Roles[role], typ, string(role), "u:lost", serial, serial, validBefore, sub).Marshal()
	out := bytes.Replace(canon, []byte{0, 0, 0, 3, 1, 0, 1}, []byte{0, 0, 0, 4, 0, 1, 0, 1}, 1)
	if len(out) != len(canon)+1 {
		t.Fatal("the RSA exponent is not where the certificate encodes it")
	}
	pub, err := ssh.ParsePublicKey(out)
	if err != nil || bytes.Equal(pub.Marshal(), out) {
		t.Fatalf("the padded certificate does not parse, or re-encodes identically (%v)", err)
	}
	return out
}

// drainEnv is a revokeEnv (one admin, the test installation) whose user
// and host CAs have a prepared generation 2 added as next by a ceremony
// issued at T, the returned time (03-12e).
func drainEnv(t *testing.T) (*swKit, time.Time) {
	t.Helper()
	k := newSwKit(newRevokeEnv(t, 1, 1, testInstallationID))
	at := k.ceremonyTime(t)
	k.ceremony1(t, at, keystore.RoleUser, keystore.RoleHost)
	return k, at
}

// TestDrainBoundary (03-12e): the one binding rule, which the signer's
// checkSwitchInstall and audit's install both call, is !krl.EntryLive at
// every row: trusted_until V + 299 leaves a certificate valid until V live
// and V + 300 does not; ssh.CertChecker refuses the certificate at its
// ValidBefore and accepts it one second before; a ValidBefore near 2^64
// is refused and never wraps.
func TestDrainBoundary(t *testing.T) {
	const v = 1_800_000_000
	for _, r := range []struct {
		vb, tu uint64
		holds  bool
	}{
		{v, v + 299, false}, {v, v + 300, true}, {v, v + 301, true}, {v, v, false}, {v, 0, false},
		{math.MaxUint64, math.MaxUint64, false}, {math.MaxUint64 - 300, math.MaxUint64, true}, {math.MaxUint64 - 299, math.MaxUint64, false},
	} {
		if got := krl.DrainBindingHolds(r.vb, r.tu); got != r.holds || got != !krl.EntryLive(r.vb, r.tu) {
			t.Fatalf("DrainBindingHolds(%d, %d) = %t, want %t (and !EntryLive = %t)", r.vb, r.tu, got, r.holds, !krl.EntryLive(r.vb, r.tu))
		}
	}
	if e := earliestTrustedUntil(math.MaxUint64); e != "none (that certificate never expires)" {
		t.Fatalf("the earliest trusted_until of a never-expiring certificate renders %q", e)
	}
	fx := NewFixture(t, 1, 1)
	c := gen1Cert(t, fx, keystore.RoleUser, 7, v)
	cc := &ssh.CertChecker{
		IsUserAuthority: func(a ssh.PublicKey) bool {
			return bytes.Equal(a.Marshal(), fx.Roles[keystore.RoleUser].PublicKey().Marshal())
		},
	}
	for _, r := range []struct {
		at uint64
		ok bool
	}{{v - 1, true}, {v, false}} {
		cc.Clock = func() time.Time { return time.Unix(int64(r.at), 0) } //nolint:gosec // G115: a test time
		err := cc.CheckCert("alice", c)
		if (err == nil) != r.ok {
			t.Fatalf("ssh.CertChecker at %d: %v, want accepted %t", r.at, err, r.ok)
		}
	}
}

// appendIssued is appendRaw for an issue or login_issue leaf of serial
// (above the high-water mark) and certificate bytes blob: in the same
// transaction it records the issuance row of role and raises the serial
// high-water mark, as an issuance does, so the start-up check that the
// log covers the issuance table still holds (03-12e).
func appendIssued(t *testing.T, db *signerdb.DB, fx *Fixture, clock func() time.Time, kind tlog.Kind, body []byte, serial uint64, role string, blob []byte) uint64 {
	t.Helper()
	ctx := context.Background()
	logKey, err := newMemBackend(fx).Key(keystore.RoleLog, ssh.FingerprintSHA256(fx.Roles[keystore.RoleLog].PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	lw, err := newLogWriter(ctx, db, logKey, clock)
	if err != nil {
		t.Fatal(err)
	}
	is := signerdb.Issuance{Serial: serial, CARole: role, KeyID: "kid", Cert: blob, IssuedAt: clock()}
	if _, err := rand.Read(is.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	var idx uint64
	err = lw.logTx(ctx, func(tx *sql.Tx) error {
		if err := db.InsertIssuance(tx, is); err != nil {
			return err
		}
		if err := db.SetLastSerial(tx, serial); err != nil {
			return err
		}
		var aerr error
		idx, aerr = lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(clock()), Kind: kind, Body: body})
		return aerr
	})
	if err != nil {
		t.Fatalf("append the %s leaf: %v", kind, err)
	}
	return idx
}

// nextSerial is one above the state's serial high-water mark.
func nextSerial(t *testing.T, db *signerdb.DB) uint64 {
	t.Helper()
	s, err := db.LastSerial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s + 1
}

// rawHostBody is a host_issue body whose certificate bytes are blob.
func rawHostBody(t *testing.T, serial uint64, blob []byte) []byte {
	t.Helper()
	enc, err := (&tlog.HostIssueBody{Serial: serial, PolicyVersion: 1, DirectoryVersion: 1, CapSeconds: 90, Request: []byte("r"),
		Evidence: []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: []byte("pop")}}, Cert: blob, KeyID: "kid"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// unchanged returns a check that nothing was written to the env's state
// since it was called: every table's row count and the leaf count.
func (k *swKit) unchanged(t *testing.T) func() {
	t.Helper()
	before, leaves := tableCounts(t, k.e.dbPath), leafCount(t, k.e.db)
	return func() {
		t.Helper()
		sameCounts(t, before, tableCounts(t, k.e.dbPath))
		if n := leafCount(t, k.e.db); n != leaves {
			t.Fatalf("%d leaves, want %d: the refused install wrote a leaf", n, leaves)
		}
	}
}

// drainRefusal requires err to be drain_window_too_short and to hold every
// one of want.
func drainRefusal(t *testing.T, err error, want ...string) {
	t.Helper()
	if !errors.Is(err, ErrDrainWindowTooShort) {
		t.Fatalf("the install: %v, want drain_window_too_short", err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("the refusal %q does not hold %q", err, w)
		}
	}
}

// TestDrainBinding (03-12e): the install binding, rows IB-01 to IB-13,
// IB-16 to IB-18 and IB-20 to IB-23 of the plan's fail-closed table.
// Environments: drainEnv (admin issue leaves of the user and host roles,
// and raw login_issue, issue, host_issue and revocation_recovery leaves),
// hostEnv (host_issue, and probe_issue under a lowered machine cap), and
// rc04State (issue leaves and a recovery that carries a certificate).
func TestDrainBinding(t *testing.T) {
	ctx := context.Background()
	user := func(k *swKit) uint64 { return k.maxTTL(t, trust.RoleUser) }
	t.Run("install_within_window_ok", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		c := k.issueAdmin(t, wire.CARoleUser, user(k))
		k.at(t, at.Add(10*time.Second))
		notes, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleUser, c.ValidBefore+360), trust.RoleUser), true)
		if err != nil {
			t.Fatalf("the switch within its window: %v", err)
		}
		if len(notes) != 1 || !notes[0].Recorded || notes[0].Max.Serial != c.Serial || notes[0].Max.ValidBefore != c.ValidBefore {
			t.Fatalf("drain notes %+v, want one naming serial %d", notes, c.Serial)
		}
	})
	t.Run("no_certificates_ok", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		notes, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleHost), true)
		if err != nil {
			t.Fatalf("a switch of a role that never issued: %v", err)
		}
		if len(notes) != 1 || notes[0].Recorded || notes[0].Role != trust.RoleHost {
			t.Fatalf("drain notes %+v, want one for host recording no certificate", notes)
		}
	})
	t.Run("install_delayed_refused", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		k.issueAdmin(t, wire.CARoleUser, user(k))
		k.at(t, at.Add(10*time.Second))
		done := k.unchanged(t)
		_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
		drainRefusal(t, err, "CA user")
		done()
	})
	t.Run("admin_host_cert_sets_maxvb", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		c := k.issueAdmin(t, wire.CARoleHost, k.maxTTL(t, trust.RoleHost))
		k.at(t, at.Add(10*time.Second))
		_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleHost), true)
		drainRefusal(t, err, "CA host", fmt.Sprintf("serial %d", c.Serial))
		notes, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleHost, c.ValidBefore+300), trust.RoleHost), true)
		if err != nil {
			t.Fatalf("the host switch at ValidBefore plus 300 s: %v", err)
		}
		if len(notes) != 1 || notes[0].Max.Serial != c.Serial {
			t.Fatalf("drain notes %+v, want the admin host certificate %d", notes, c.Serial)
		}
	})
	t.Run("refusal_names_certificate", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		leaf := leafCount(t, k.e.db)
		c := k.issueAdmin(t, wire.CARoleUser, user(k))
		k.at(t, at.Add(10*time.Second))
		tu := c.ValidBefore + 299
		_, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleUser, tu), trust.RoleUser), true)
		drainRefusal(t, err, "the switch of CA user ends trust at "+unixTime(tu),
			fmt.Sprintf("a certificate of generation 1 valid until %s (serial %d, key ID %s, leaf %d)", unixTime(c.ValidBefore), c.Serial, c.KeyId, leaf),
			"the earliest acceptable trusted_until is "+unixTime(c.ValidBefore+300))
	})
	t.Run("two_roles_both_bound", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		k.issueAdmin(t, wire.CARoleUser, 600)
		h := k.issueAdmin(t, wire.CARoleHost, k.maxTTL(t, trust.RoleHost))
		k.at(t, at.Add(10*time.Second))
		done := k.unchanged(t)
		_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser, trust.RoleHost), true)
		drainRefusal(t, err, "CA host", fmt.Sprintf("serial %d", h.Serial))
		done()
		notes, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleHost, h.ValidBefore+300), trust.RoleUser, trust.RoleHost), true)
		if err != nil || len(notes) != 2 {
			t.Fatalf("both roles within their windows: %d notes, %v; want two notes", len(notes), err)
		}
	})
	t.Run("scan_missing_refuses", func(t *testing.T) {
		k, at := drainEnv(t)
		installed, _ := installedDocs(t, k.e.db)
		b, err := trust.ParseBundle(k.switchDocs(t, at, 0, trust.RoleUser)[0])
		if err != nil {
			t.Fatal(err)
		}
		for name, lw := range map[string]*Signer{"no writer": nil, "a writer without a scan": {}} {
			if _, err := checkSwitchInstall(lw, installed, nil, b, nil, k.now(), true); !errors.Is(err, ErrDrainScanMissing) {
				t.Fatalf("%s: checkSwitchInstall = %v, want drain_scan_missing", name, err)
			}
		}
	})
	t.Run("unparsable_certificate_refuses", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		var idx uint64
		k.stopped(t, func(db *signerdb.DB) {
			s := nextSerial(t, db)
			blob := truncated(gen1Cert(t, k.e.fx, keystore.RoleUser, s, uint64(at.Unix())+60).Marshal()) //nolint:gosec // G115: after 1970
			idx = appendIssued(t, db, k.e.fx, k.clk.Now, tlog.KindLoginIssue, rawLoginBody(t, s, blob), s, "user", blob)
		})
		k.at(t, at.Add(10*time.Second))
		done := k.unchanged(t)
		_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
		if !errors.Is(err, errLogMismatch) || !strings.Contains(err.Error(), fmt.Sprintf("drain scan: leaf %d (login_issue)", idx)) {
			t.Fatalf("the install over a login certificate that does not parse: %v, want a log mismatch naming drain scan: leaf %d (login_issue)", err, idx)
		}
		done()
	})
	t.Run("unparsable_recovery_certificate_refuses", func(t *testing.T) {
		// The recovery-carried certificate that only the scan can refuse
		// is a non-canonical one: Validate, which the host and machine
		// indexes run on every recovery's request, already refuses one
		// that does not parse (the control below).
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		vb := uint64(at.Unix()) + 60 //nolint:gosec // G115: after 1970
		var idx uint64
		k.stopped(t, func(db *signerdb.DB) {
			ok := gen1Cert(t, k.e.fx, keystore.RoleUser, 1, vb).Marshal()
			var err error
			idx, err = appendRaw(db, k.e.fx, k.clk.Now, tlog.KindRevocationRecovery,
				rawRecoveryBody(t, k.e.fx.InstallationID, ok, nonCanonical(t, k.e.fx, keystore.RoleUser, 2, vb)))
			if err != nil {
				t.Fatalf("append the recovery leaf: %v", err)
			}
		})
		k.at(t, at.Add(10*time.Second))
		done := k.unchanged(t)
		_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
		if !errors.Is(err, errLogMismatch) || !strings.Contains(err.Error(), fmt.Sprintf("drain scan: leaf %d (revocation_recovery)", idx)) ||
			!strings.Contains(err.Error(), "certificate 1") {
			t.Fatalf("the install over a carried certificate that is not canonical: %v, want a log mismatch naming drain scan: leaf %d (revocation_recovery) and certificate 1", err, idx)
		}
		done()
	})
	// indexRefuses requires the leaf of kind with body to be refused by
	// the signer's own indexes, not by the drain scan: either its append
	// through the signer's writer (whose in-memory indexes apply each new
	// leaf) or the install's walk fails with a log mismatch that names no
	// drain scan. A labelled control: it does not bite M291.
	indexRefuses := func(t *testing.T, kind tlog.Kind, body func(k *swKit, db *signerdb.DB) []byte) {
		t.Helper()
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		var aerr error
		k.stopped(t, func(db *signerdb.DB) { _, aerr = appendRaw(db, k.e.fx, k.clk.Now, kind, body(k, db)) })
		err := aerr
		if err == nil {
			k.at(t, at.Add(10*time.Second))
			_, err = k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
			t.Logf("the append passed; the install: %v", err)
		} else {
			t.Logf("the append through the signer's writer: %v", err)
		}
		if !errors.Is(err, errLogMismatch) || strings.Contains(err.Error(), "drain scan") {
			t.Fatalf("a %s leaf whose certificate does not parse: %v, want a log mismatch from the index, not the drain scan", kind, err)
		}
	}
	t.Run("host_index_refuses_unparsable_host_certificate", func(t *testing.T) {
		indexRefuses(t, tlog.KindHostIssue, func(k *swKit, db *signerdb.DB) []byte {
			s := nextSerial(t, db)
			return rawHostBody(t, s, truncated(gen1Cert(t, k.e.fx, keystore.RoleHost, s, uint64(k.now().Unix())+60).Marshal())) //nolint:gosec // G115: after 1970
		})
	})
	t.Run("recovery_index_refuses_unparsable_carried_certificate", func(t *testing.T) {
		indexRefuses(t, tlog.KindRevocationRecovery, func(k *swKit, _ *signerdb.DB) []byte {
			return rawRecoveryBody(t, k.e.fx.InstallationID, truncated(gen1Cert(t, k.e.fx, keystore.RoleUser, 1, uint64(k.now().Unix())+60).Marshal())) //nolint:gosec // G115: after 1970
		})
	})
	t.Run("cancelled_scan_installs_nothing", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		d := k.switchDocs(t, at, 0, trust.RoleUser)
		done := k.unchanged(t)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		k.stopped(t, func(db *signerdb.DB) {
			pub := k.e.fx.Roles[keystore.RoleLog].PublicKey()
			v, err := tlog.NewNoteVerifier(tlog.Origin(pub), pub)
			if err != nil {
				t.Fatal(err)
			}
			_, _, inst, err := rebuildLogFromWith(cctx, db, v, rebuildOptions{drain: true})
			if !errors.Is(err, errLogMismatch) || inst.drain != nil {
				t.Fatalf("the rebuild under a cancelled context: %v (an accumulator returned: %t), want a log mismatch and none", err, inst.drain != nil)
			}
			cp, _, err := db.LatestCheckpoint(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := InstallBundleWithPrevious(cctx, db, k.gb, nil, 0, d[0], d[1], d[2], d[3], k.clk.Now, cp); err == nil {
				t.Fatal("the install under a cancelled context succeeded")
			}
		})
		done()
	})
	t.Run("trusted_until_before_epoch_refused", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		d := editedSuccessor(t, k.e.db, func(b *trust.Bundle) {
			for i := range b.CAs {
				switch ca := &b.CAs[i]; {
				case ca.Role == trust.RoleUser && ca.State == "next":
					ca.State = "active"
				case ca.Role == trust.RoleUser && ca.State == "active":
					ca.State, ca.TrustedUntil = "draining", "1969-12-31T00:00:00Z"
				}
			}
			b.IssuedAt = at.UTC().Format(trust.TimeFormat)
		}, nil, k.e.fx.Root)
		done := k.unchanged(t)
		_, err := k.install(t, d, true)
		if err == nil || !strings.Contains(err.Error(), "the switch floor cannot be computed") {
			t.Fatalf("a switch ending trust in 1969: %v, want the chain rule's refusal", err)
		}
		done()
	})
	t.Run("prepare_pays_no_scan", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		k.stopped(t, func(db *signerdb.DB) {
			s := nextSerial(t, db)
			blob := truncated(gen1Cert(t, k.e.fx, keystore.RoleUser, s, uint64(at.Unix())+60).Marshal()) //nolint:gosec // G115: after 1970
			appendIssued(t, db, k.e.fx, k.clk.Now, tlog.KindLoginIssue, rawLoginBody(t, s, blob), s, "user", blob)
			if _, err := PrepareGeneration(ctx, db, k.gb, keystore.RoleMachine, "", k.clk.Now); err != nil {
				t.Fatalf("prepare over a log with a login certificate that does not parse: %v", err)
			}
		})
	})
	t.Run("other_roles_certificates_ignored", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		h := k.issueAdmin(t, wire.CARoleHost, k.maxTTL(t, trust.RoleHost))
		k.at(t, at.Add(10*time.Second))
		// The env's only user certificate is the one its bootstrap issued,
		// valid for 600 s, so the user key's maximum is that one.
		notes, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
		if err != nil || len(notes) != 1 || notes[0].Max.Serial == h.Serial || notes[0].Max.ValidBefore >= h.ValidBefore {
			t.Fatalf("a user switch beside a long host certificate: %+v, %v; want one note whose maximum is not the host certificate %d", notes, err, h.Serial)
		}
	})
	t.Run("never_expires_names_no_acceptable_time", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		var serial uint64
		k.stopped(t, func(db *signerdb.DB) {
			serial = nextSerial(t, db)
			blob := gen1Cert(t, k.e.fx, keystore.RoleUser, serial, ssh.CertTimeInfinity).Marshal()
			enc, err := (&tlog.IssueBody{CARole: uint8(wire.CARoleUser), Serial: serial, PolicyVersion: 1, Cert: blob, KeyID: "kid"}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			appendIssued(t, db, k.e.fx, k.clk.Now, tlog.KindIssue, enc, serial, "user", blob)
		})
		k.at(t, at.Add(10*time.Second))
		_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
		drainRefusal(t, err, "valid until forever", fmt.Sprintf("serial %d", serial), "the earliest acceptable trusted_until is none (that certificate never expires)")
	})
	t.Run("stale_scan_cannot_commit", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		k.stopped(t, func(db *signerdb.DB) {
			logKey, err := k.gb.Key(keystore.RoleLog, ssh.FingerprintSHA256(k.e.fx.Roles[keystore.RoleLog].PublicKey()))
			if err != nil {
				t.Fatal(err)
			}
			lw, err := newLogWriterWith(ctx, db, logKey, k.clk.Now, rebuildOptions{drain: true})
			if err != nil || lw.loaded.drain == nil {
				t.Fatalf("the scanning writer: %v", err)
			}
			second, err := signerdb.Open(k.e.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = second.Close() }()
			body, err := (&tlog.ClockRegressionBody{NowMicros: 1, HighWaterMicros: 2}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := appendRaw(second, k.e.fx, k.clk.Now, tlog.KindClockRegression, body); err != nil {
				t.Fatalf("the append through the second handle: %v", err)
			}
			n := leafCount(t, db)
			err = lw.logTx(ctx, func(tx *sql.Tx) error {
				_, aerr := lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(k.now()), Kind: tlog.KindClockRegression, Body: body})
				return aerr
			})
			if err == nil {
				t.Fatal("the writer whose scan predates the second handle's leaf committed a leaf")
			}
			if got := leafCount(t, db); got != n {
				t.Fatalf("%d leaves after the stale commit, want %d", got, n)
			}
		})
	})
	drainBindingLater(t)
}

// addNextDocs prepares one generation of each role, with the signer
// stopped, and returns the successor issued at issuedAt that adds them as
// next (ceremony 1, 03-12), not yet installed.
func (k *swKit) addNextDocs(t *testing.T, issuedAt time.Time, roles ...keystore.Role) [4][]byte {
	t.Helper()
	var d [4][]byte
	k.stopped(t, func(db *signerdb.DB) {
		var gens []signerdb.CAGeneration
		for _, r := range roles {
			g, err := PrepareGeneration(context.Background(), db, k.gb, r, "", k.clk.Now)
			if err != nil {
				t.Fatalf("PrepareGeneration(%s): %v", r, err)
			}
			gens = append(gens, g)
		}
		d = editedSuccessor(t, db, func(b *trust.Bundle) {
			for _, g := range gens {
				insertCA(b, nextEntry(t, g))
			}
			b.IssuedAt = issuedAt.UTC().Format(trust.TimeFormat)
		}, nil, k.e.fx.Root)
	})
	return d
}

// policyDocs is the successor issued at issuedAt that changes the policy
// only (its version), so no CA entry changes.
func (k *swKit) policyDocs(t *testing.T, issuedAt time.Time) [4][]byte {
	t.Helper()
	return editedSuccessor(t, k.e.db, func(b *trust.Bundle) { b.IssuedAt = issuedAt.UTC().Format(trust.TimeFormat) }, func(*trust.Policy) {}, k.e.fx.Root)
}

// lostCert is a certificate of role signed directly by the fixture's
// generation-1 key of role, with a serial above every serial the log
// holds, valid until validBefore: a lost certificate that no issue leaf
// holds.
func (k *swKit) lostCert(t *testing.T, role keystore.Role, validBefore uint64) *ssh.Certificate {
	t.Helper()
	return gen1Cert(t, k.e.fx, role, nextSerial(t, k.e.db)+1000, validBefore)
}

// recoverCarrying applies, through RecoverRevocations at the clock, a
// recovery of the env's log as it is that carries certs.
func (k *swKit) recoverCarrying(t *testing.T, certs ...wire.RecoveredCertificate) {
	t.Helper()
	k.e.recover(t, k.e.recoveryRequest(t, nil, certs, nil))
}

// rc04 is the state of row RC-04 of the plan's table (03-12e): on
// drainEnv, the user switch installed (generation 1 draining until tu,
// which covers every certificate logged before it, generation 2 active),
// then a recovery whose request carries one revoked certificate of
// generation 1 that no issue leaf holds, with a serial above the log's
// last and a ValidBefore above tu minus 300. The signer and audit both
// accept the recovery: a carried certificate need only be signed by a CA
// key of its role in the bundle in force, a draining key included.
type rc04 struct {
	k    *swKit
	at   time.Time // the switch's issued_at
	tu   uint64    // generation 1's trusted_until
	lost *ssh.Certificate
	cp   []byte // the checkpoint after the recovery
}

func rc04State(t *testing.T) *rc04 {
	t.Helper()
	k, at := drainEnv(t)
	k.at(t, at.Add(10*time.Second))
	notes, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
	if err != nil || len(notes) != 1 {
		t.Fatalf("the user switch: %v", err)
	}
	tu, err := unixSeconds(notes[0].TrustedUntil)
	if err != nil {
		t.Fatal(err)
	}
	k.at(t, at.Add(20*time.Second))
	lost := k.lostCert(t, keystore.RoleUser, tu-300+100)
	k.recoverCarrying(t, wire.RecoveredCertificate{Cert: lost.Marshal(), Revoke: true})
	cp, _, err := k.e.db.LatestCheckpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &rc04{k: k, at: at, tu: tu, lost: lost, cp: cp}
}

// laterInstalls runs, on the RC-04 state, an add-next of user generation
// 3 and a policy-only install, each with no --previous and no drain note,
// then a second switch of user generation 2 with --previous and one note,
// for generation 2 only; check runs after each install (03-12e).
func (r *rc04) laterInstalls(t *testing.T, check func(step string)) {
	t.Helper()
	k := r.k
	at2 := k.ceremonyTime(t)
	notes, err := k.install(t, k.addNextDocs(t, at2, keystore.RoleUser), false)
	if err != nil || len(notes) != 0 {
		t.Fatalf("the add-next of generation 3 on the RC-04 state: %d notes, %v; want none and no error", len(notes), err)
	}
	check("add-next of generation 3")
	at3 := k.ceremonyTime(t)
	notes, err = k.install(t, k.policyDocs(t, at3), false)
	if err != nil || len(notes) != 0 {
		t.Fatalf("the policy-only install on the RC-04 state: %d notes, %v; want none and no error", len(notes), err)
	}
	check("policy-only install")
	k.at(t, at3.Add(10*time.Second))
	notes, err = k.install(t, k.switchDocs(t, at3, 0, trust.RoleUser), true)
	if err != nil || len(notes) != 1 || notes[0].Generation != 2 {
		t.Fatalf("the second switch on the RC-04 state: %+v, %v; want one note, for generation 2", notes, err)
	}
	check("second switch")
}

// drainBindingLater holds the leaves of TestDrainBinding that need the
// RC-04 state or a lowered policy; TestDrainBinding runs them.
func drainBindingLater(t *testing.T) {
	t.Run("already_draining_not_rebound", func(t *testing.T) {
		rc04State(t).laterInstalls(t, func(string) {})
	})
	t.Run("policy_lowered_ttl_refused", func(t *testing.T) {
		// A host certificate issued under a 30-day cap, the cap lowered to
		// one day, and the switch two bundles later: its floor covers one
		// day, the certificate 30, so the binding refuses until
		// trusted_until covers the certificate.
		e := newHostEnv(t, 30*86400)
		k := newSwKit(e.revokeEnv)
		c, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.setHostCap(t, 86400, nil)
		k.at(t, time.Unix(int64(c.ValidBefore)-86400-10, 0)) //nolint:gosec // G115: a test time
		at := k.ceremonyTime(t)
		k.ceremony1(t, at, keystore.RoleHost)
		k.at(t, at.Add(5*time.Second))
		_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleHost), true)
		drainRefusal(t, err, "CA host", fmt.Sprintf("serial %d", c.Serial))
		if _, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleHost, c.ValidBefore+300), trust.RoleHost), true); err != nil {
			t.Fatalf("the host switch at the certificate's ValidBefore plus 300 s: %v", err)
		}
		// A probe certificate under a machine cap below and above
		// 604800 s (its lifetime is the smaller of the two), the cap
		// then lowered to one day.
		for _, capSeconds := range []uint64{2 * 86400, 10 * 86400} {
			e := newHostEnv(t, 3600)
			k := newSwKit(e.revokeEnv)
			e.setMachineCap(t, capSeconds, nil)
			req, _ := e.probeReq(e.ed, "web1", false)
			p, _ := e.mustProbe(req)
			e.setMachineCap(t, 86400, nil)
			k.at(t, time.Unix(int64(p.ValidBefore)-86400-10, 0)) //nolint:gosec // G115: a test time
			at := k.ceremonyTime(t)
			k.ceremony1(t, at, keystore.RoleMachine)
			k.at(t, at.Add(5*time.Second))
			_, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleMachine), true)
			drainRefusal(t, err, "CA machine", fmt.Sprintf("serial %d", p.Serial))
			if _, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleMachine, p.ValidBefore+300), trust.RoleMachine), true); err != nil {
				t.Fatalf("the machine switch at the probe's ValidBefore plus 300 s (cap %d s): %v", capSeconds, err)
			}
		}
	})
}

// agree switches role at the boundary of vb, the largest ValidBefore of a
// certificate of the role's draining key that the test logged (the
// model): the signer and audit both refuse trusted_until vb + 299, and
// both accept vb + 300 (03-12e).
func (k *swKit) agree(t *testing.T, at time.Time, role string, vb uint64) {
	t.Helper()
	d := k.switchDocs(t, at, k.allowance(t, at, role, vb+299), role)
	aerr := k.auditForced(t, d) // first: audit's verdict owes nothing to the signer's
	_, err := k.install(t, d, true)
	if !errors.Is(err, ErrDrainWindowTooShort) || aerr == nil || !strings.Contains(aerr.Error(), "drain_window_too_short") {
		t.Fatalf("CA %s ending trust at ValidBefore %d plus 299 s: the signer %v, audit %v; want both drain_window_too_short", role, vb, err, aerr)
	}
	if _, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, role, vb+300), role), true); err != nil {
		t.Fatalf("CA %s ending trust at ValidBefore %d plus 300 s: the signer refused: %v", role, vb, err)
	}
	if err := k.audit(t); err != nil {
		t.Fatalf("CA %s ending trust at ValidBefore %d plus 300 s: audit refused: %v", role, vb, err)
	}
}

// loginSwEnv is a login environment (03-08) on a revokeClock whose
// policy's user cap is 3600 s, the ops role's limit in the login
// directory, which is installed.
func loginSwEnv(t *testing.T) (*swKit, *passkeys) {
	t.Helper()
	pk := newPasskeys(t)
	fx := NewFixture(t, 1, 1)
	fx.PolicyEdit = func(p *trust.Policy) {
		p.WebAuthn = &trust.WebAuthnRP{RPID: loginRP, Origins: []string{loginOrigin}}
		for i := range p.CAProfiles {
			if p.CAProfiles[i].Role == trust.RoleUser {
				p.CAProfiles[i].MaxTTLSeconds = 3600
			}
		}
	}
	clock := &revokeClock{now: time.Now().Truncate(time.Second).Add(500 * time.Millisecond)}
	e := &revokeEnv{logEnv: newLogEnvClock(t, fx, clock.Now), clock: clock}
	doc, sigs := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), fx.Admins[:fx.Quorum]...)
	e.installDirectory(t, doc, sigs)
	return newSwKit(e), pk
}

// TestDrainBindingCountsCarriedCertificates (03-12e, IB-03): a certificate
// that only a recovery carries, kept or revoked, counts in the binding, in
// the signer and in audit: trusted_until V + 299 is refused by both and V
// + 300 passes both.
func TestDrainBindingCountsCarriedCertificates(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		v := uint64(at.Unix()) + k.maxTTL(t, trust.RoleHost) + 100 //nolint:gosec // G115: after 1970
		c := k.lostCert(t, keystore.RoleHost, v)
		k.recoverCarrying(t, wire.RecoveredCertificate{Cert: c.Marshal(), Revoke: revoke})
		k.at(t, at.Add(10*time.Second))
		k.agree(t, at, trust.RoleHost, v)
	}
}

// TestDrainBindingSignerAuditAgree (03-12e): one corpus, the signer's
// install and audit.Verify of the export give the same verdict at the
// boundary of every environment's maximum; a tampered issuance row
// changes neither; on the RC-04 state the later installs pass both; and
// the signer's upper bound and audit's re-derivation of it, two copies of
// one formula, agree at the bound, one second above it and on its
// overflow edge.
func TestDrainBindingSignerAuditAgree(t *testing.T) {
	t.Run("corpus_around_the_boundary", func(t *testing.T) {
		// Admin issue leaves of the user and host roles, a refusal and a
		// clock_regression leaf, a recovery that carries a kept host and
		// a revoked user certificate, and two rotations of the user CA.
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		u := k.issueAdmin(t, wire.CARoleUser, k.maxTTL(t, trust.RoleUser))
		h := k.issueAdmin(t, wire.CARoleHost, k.maxTTL(t, trust.RoleHost))
		req := k.e.request()
		req.ValidForSeconds = uint32(k.maxTTL(t, trust.RoleUser) + 1) //nolint:gosec // G115: a policy TTL
		req.CreatedAt = uint64(k.now().Unix())                        //nolint:gosec // G115: after 1970
		req.Evidence = SignRequest(t, req, k.e.fx.Admins...)
		if _, err := k.e.s.Issue(context.Background(), Peer{UID: 1000}, req); err == nil {
			t.Fatal("an issue above the user cap was not refused")
		}
		k.clk.set(k.now().Add(-time.Minute))
		if _, err := k.e.s.Issue(context.Background(), Peer{UID: 1000}, k.e.request()); err == nil {
			t.Fatal("an issue under a clock that went back was not refused")
		}
		k.clk.set(at.Add(6 * time.Second))
		hv := h.ValidBefore + 50
		lostHost := k.lostCert(t, keystore.RoleHost, hv)
		lostUser := gen1Cert(t, k.e.fx, keystore.RoleUser, lostHost.Serial+1, uint64(at.Unix())+60) //nolint:gosec // G115: after 1970
		k.recoverCarrying(t, wire.RecoveredCertificate{Cert: lostHost.Marshal()}, wire.RecoveredCertificate{Cert: lostUser.Marshal(), Revoke: true})
		k.at(t, at.Add(10*time.Second))
		k.agree(t, at, trust.RoleUser, u.ValidBefore)
		k.agree(t, at, trust.RoleHost, hv)
		// The second rotation of the user CA: generation 3 added, a
		// certificate of generation 2 issued after the restart, and the
		// switch of generation 2.
		at2 := k.ceremonyTime(t)
		k.ceremony1(t, at2, keystore.RoleUser)
		k.at(t, at2.Add(5*time.Second))
		u2 := k.issueAdmin(t, wire.CARoleUser, k.maxTTL(t, trust.RoleUser))
		k.at(t, at2.Add(10*time.Second))
		k.agree(t, at2, trust.RoleUser, u2.ValidBefore)

		// host_issue, machine_issue and probe_issue (both polarities),
		// with refusal leaves; then a host and a machine switch.
		m := newMachineEnv(t)
		mk := newSwKit(m.revokeEnv)
		mat := mk.ceremonyTime(t)
		mk.ceremony1(t, mat, keystore.RoleHost, keystore.RoleMachine)
		mk.at(t, mat.Add(5*time.Second))
		hc, _ := m.mustHost(m.hostReq(m.ed, "web1"))
		mc, _ := m.mustMachine(t, m.machineReq(m.k1, "ci"))
		var pmax uint64
		for _, neg := range []bool{false, true} {
			preq, _ := m.probeReq(m.ed, "web1", neg)
			p, _ := m.mustProbe(preq)
			pmax = max(pmax, p.ValidBefore)
		}
		mk.at(t, mat.Add(10*time.Second))
		mk.agree(t, mat, trust.RoleHost, hc.ValidBefore)
		mk.agree(t, mat, trust.RoleMachine, max(pmax, mc.ValidBefore))

		// login_issue.
		lk, pk := loginSwEnv(t)
		lat := lk.ceremonyTime(t)
		lk.ceremony1(t, lat, keystore.RoleUser)
		lk.at(t, lat.Add(5*time.Second))
		lreq := lk.e.loginReq(t, "alice")
		lreq.ValidForSeconds = 3600
		lc := lk.e.mustLogin(t, approve(t, pk.eddsa, lreq, nil))
		lk.at(t, lat.Add(10*time.Second))
		lk.agree(t, lat, trust.RoleUser, lc.ValidBefore)
	})
	t.Run("row_tamper", func(t *testing.T) {
		e := newHostEnv(t, 3600)
		k := newSwKit(e.revokeEnv)
		at := k.ceremonyTime(t)
		k.ceremony1(t, at, keystore.RoleHost)
		k.at(t, at.Add(5*time.Second))
		c, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		short := gen1Cert(t, e.fx, keystore.RoleHost, c.Serial, uint64(at.Unix())+60) //nolint:gosec // G115: after 1970
		e.close()
		e.exec(t, `UPDATE issuance SET cert = ?, ca_role = 'user' WHERE serial = ?`, short.Marshal(), c.Serial)
		k.reopen(t)
		k.at(t, at.Add(10*time.Second))
		d := k.switchDocs(t, at, k.allowance(t, at, trust.RoleHost, c.ValidBefore+299), trust.RoleHost)
		_, err := k.install(t, d, true)
		drainRefusal(t, err, fmt.Sprintf("serial %d", c.Serial))
		if aerr := k.auditForced(t, d); aerr == nil || !strings.Contains(aerr.Error(), "drain_window_too_short") {
			t.Fatalf("audit of the switch over a tampered issuance row: %v, want drain_window_too_short", aerr)
		}
	})
	t.Run("rc04_state_later_installs_pass", func(t *testing.T) {
		r := rc04State(t)
		if err := r.k.audit(t); err != nil {
			t.Fatalf("audit of the RC-04 state: %v", err)
		}
		r.laterInstalls(t, func(step string) {
			if err := r.k.audit(t); err != nil {
				t.Fatalf("audit after the %s: %v", step, err)
			}
		})
	})
	t.Run("upper_bound_corpus", drainUpperBoundAgree)
}

// drainUpperBoundAgree (03-12e): the signer's drainUpperBound and audit's
// copy of it give the same verdict on one corpus of user switches edited
// by hand, each installed at a whole second of the clock, so the signer's
// clock reading and the install leaf's time that audit reads are the same
// second. Audit's verdict is taken first, on the install leaf forced into
// a copy of the log, so it owes nothing to the signer's. At the bound set
// by the clock and at the bound set by a logged certificate that outlives
// it, one second above the bound both refuse drain_window_too_long naming
// the same latest acceptable trusted_until, and the bound itself passes
// both. On the overflow edge (a logged ValidBefore at which the bound's
// sum just fits, and one second above it, where it overflows) both refuse
// with the same code, drain_window_too_short: the binding runs before the
// bound on both sides, and no trusted_until in TimeFormat reaches such a
// certificate, so neither copy's overflow check is reachable through an
// install or through Verify.
func drainUpperBoundAgree(t *testing.T) {
	const week = uint64(7 * 24 * 3600)
	// carryUser applies a recovery that carries, revoked (a recovery
	// revokes every lost user certificate), a user certificate of
	// generation 1 valid until vb that no issue leaf holds: the route by
	// which a ValidBefore far beyond the cap reaches a log that audit
	// verifies. The maximum is revocation-blind, so it counts.
	carryUser := func(t *testing.T, k *swKit, vb uint64) {
		t.Helper()
		k.recoverCarrying(t, wire.RecoveredCertificate{Cert: k.lostCert(t, keystore.RoleUser, vb).Marshal(), Revoke: true})
	}
	// clockBound is the bound of a user switch installed at the clock
	// when no logged certificate outlives the clock plus the cap.
	clockBound := func(t *testing.T, k *swKit) uint64 {
		t.Helper()
		return uint64(k.now().Unix()) + k.maxTTL(t, trust.RoleUser) + 600 + week //nolint:gosec // G115: after 1970
	}
	// atTheBound runs the pair of cases around bound b on k.
	atTheBound := func(t *testing.T, k *swKit, at time.Time, b uint64) {
		t.Helper()
		d := k.handSwitch(t, at, trust.RoleUser, b+1)
		aerr := k.auditForced(t, d)
		_, err := k.install(t, d, true)
		want := "the switch of CA user ends trust at " + unixTime(b+1) + ", above the latest acceptable " + unixTime(b)
		if !errors.Is(err, ErrDrainWindowTooLong) || !strings.Contains(err.Error(), want) ||
			aerr == nil || !strings.Contains(aerr.Error(), "drain_window_too_long: "+want) {
			t.Fatalf("a switch one second above the bound %d: the signer %v, audit %v; want both drain_window_too_long: %s", b, err, aerr, want)
		}
		d = k.handSwitch(t, at, trust.RoleUser, b)
		if aerr := k.auditForced(t, d); aerr != nil {
			t.Fatalf("a switch exactly at the bound %d: audit refused: %v", b, aerr)
		}
		if _, err := k.install(t, d, true); err != nil {
			t.Fatalf("a switch exactly at the bound %d: the signer refused: %v", b, err)
		}
		if err := k.audit(t); err != nil {
			t.Fatalf("a switch exactly at the bound %d: audit of the installed switch: %v", b, err)
		}
	}
	t.Run("clock_sets_the_bound", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		atTheBound(t, k, at, clockBound(t, k))
	})
	t.Run("logged_certificate_sets_the_bound", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		vb := uint64(at.Unix()) + 60*86400 //nolint:gosec // G115: after 1970
		carryUser(t, k, vb)
		k.at(t, at.Add(10*time.Second))
		if vb <= clockBound(t, k)-600-week {
			t.Fatal("the certificate does not outlive the clock plus the cap; the case proves nothing")
		}
		atTheBound(t, k, at, vb+600+week)
	})
	t.Run("overflow_edge", func(t *testing.T) {
		for _, vb := range []uint64{math.MaxUint64 - 600 - week, math.MaxUint64 - 600 - week + 1} {
			k, at := drainEnv(t)
			k.at(t, at.Add(5*time.Second))
			carryUser(t, k, vb)
			k.at(t, at.Add(10*time.Second))
			now := uint64(k.now().Unix()) //nolint:gosec // G115: after 1970
			ttl := k.maxTTL(t, trust.RoleUser)
			if _, oerr := drainUpperBound(now, ttl, ttl, vb); (oerr != nil) != (vb > math.MaxUint64-600-week) {
				t.Fatalf("ValidBefore %d is not on the side of the overflow edge the case expects: %v", vb, oerr)
			}
			if err := k.audit(t); err != nil {
				t.Fatalf("audit of the log before the switch, ValidBefore %d: %v", vb, err)
			}
			d := k.handSwitch(t, at, trust.RoleUser, clockBound(t, k))
			aerr := k.auditForced(t, d)
			_, err := k.install(t, d, true)
			if !errors.Is(err, ErrDrainWindowTooShort) || aerr == nil || !strings.Contains(aerr.Error(), "drain_window_too_short") {
				t.Fatalf("a switch over a certificate valid until %d: the signer %v, audit %v; want both drain_window_too_short", vb, err, aerr)
			}
		}
	})
}

// exec runs one SQL statement on a logEnv's state database (no signer may
// have it open).
func (e *logEnv) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	execSQL(t, e.dbPath, query, args...)
}

// TestDrainBindingIsClockFree (03-12e, IB-11): the verdict is the one
// krl.DrainBindingHolds gives for the certificate's ValidBefore, whatever
// the signer's clock read when it issued. Ahead: the certificate issued
// with the signer's clock 3 days ahead of the ceremony's, the switch
// refused at its ValidBefore plus 299 s and accepted at plus 300 s.
// Behind: the certificate issued with the signer's clock 3 days behind the
// ceremony's, so its ValidBefore plus 300 s is below the switch floor and
// every switch the chain rule admits passes, with that certificate named
// as the maximum. (A whole environment 3 days behind the real clock
// cannot be built: the fixture dates its genesis bundle by the real
// clock, which a signer 3 days behind refuses as issued in the future.)
func TestDrainBindingIsClockFree(t *testing.T) {
	t.Run("ahead", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(72*time.Hour))
		c := k.issueAdmin(t, wire.CARoleUser, k.maxTTL(t, trust.RoleUser))
		k.at(t, at.Add(72*time.Hour+10*time.Second))
		_, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleUser, c.ValidBefore+299), trust.RoleUser), true)
		drainRefusal(t, err, fmt.Sprintf("serial %d", c.Serial))
		if _, err := k.install(t, k.switchDocs(t, at, k.allowance(t, at, trust.RoleUser, c.ValidBefore+300), trust.RoleUser), true); err != nil {
			t.Fatalf("the switch at ValidBefore plus 300 s: %v", err)
		}
	})
	t.Run("behind", func(t *testing.T) {
		k := newSwKit(newRevokeEnv(t, 1, 1, testInstallationID))
		k.at(t, k.now().Add(time.Second))
		c := k.issueAdmin(t, wire.CARoleUser, k.maxTTL(t, trust.RoleUser))
		k.at(t, k.now().Add(72*time.Hour))
		at := k.ceremonyTime(t)
		k.ceremony1(t, at, keystore.RoleUser)
		k.at(t, at.Add(10*time.Second))
		notes, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
		if err != nil || len(notes) != 1 || notes[0].Max.Serial != c.Serial {
			t.Fatalf("the switch after a certificate issued 3 days before the ceremony: %+v, %v; want it named and the install passed", notes, err)
		}
		tu, err := unixSeconds(notes[0].TrustedUntil)
		if err != nil || !krl.DrainBindingHolds(c.ValidBefore, tu) {
			t.Fatalf("DrainBindingHolds(%d, %s) is false, but the install passed (%v)", c.ValidBefore, notes[0].TrustedUntil, err)
		}
	})
}

// TestRefusedSwitchWritesNothing (03-12e, IB-13): a refused switch install
// leaves every table's row count, the leaf count and the checkpoint as
// they were, and Status still reports the old bundle.
func TestRefusedSwitchWritesNothing(t *testing.T) {
	ctx := context.Background()
	k, at := drainEnv(t)
	k.at(t, at.Add(5*time.Second))
	k.issueAdmin(t, wire.CARoleUser, k.maxTTL(t, trust.RoleUser))
	k.at(t, at.Add(10*time.Second))
	cp, _, err := k.e.db.LatestCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st, err := k.e.s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := k.unchanged(t)
	_, err = k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true)
	drainRefusal(t, err)
	done()
	cp2, _, err := k.e.db.LatestCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cp, cp2) {
		t.Fatal("the checkpoint changed after the refused install")
	}
	st2, err := k.e.s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st2.BundleVersion != st.BundleVersion {
		t.Fatalf("Status reports bundle version %d after the refused install, want %d", st2.BundleVersion, st.BundleVersion)
	}
}

// drainFuzzPool is the certificate pool of FuzzDrainFeed: per CA key and
// lifetime choice a certificate, and per CA key a non-canonical one.
type drainFuzzPool struct {
	cas    []ssh.Signer
	certs  [][]*ssh.Certificate // [ca][lifetime]
	nonCan [][]byte             // [ca]
}

func newDrainFuzzPool(t *testing.T) *drainFuzzPool {
	t.Helper()
	fx := NewFixture(t, 1, 1)
	p := &drainFuzzPool{cas: []ssh.Signer{fx.Roles[keystore.RoleUser], fx.Roles[keystore.RoleHost], fx.Roles[keystore.RoleMachine]}}
	roles := []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine}
	for i, r := range roles {
		var row []*ssh.Certificate
		for j, vb := range []uint64{1_800_000_000, 1_800_003_600, 1_800_086_400, ssh.CertTimeInfinity} {
			row = append(row, gen1Cert(t, fx, r, uint64(100*i+j+1), vb)) //nolint:gosec // G115: small serials
		}
		p.certs = append(p.certs, row)
		p.nonCan = append(p.nonCan, nonCanonical(t, fx, r, uint64(100*i+50), 1_800_000_000)) //nolint:gosec // G115: a small serial
	}
	return p
}

// leaf builds the leaf of one fuzz op (kind, key, choice): kind
// 0 issue, 1 login_issue, 2 host_issue, 3 machine_issue, 4 and 5
// probe_issue (positive, negative), 6 a revocation_recovery that carries
// two certificates, 7 refusal, 8 clock_regression; choice's low two bits
// name a corruption of the (last) certificate (0 none, 1 a truncation, 2
// a plain key, 3 a non-canonical encoding) and the rest its lifetime. It
// returns the leaf, the certificate bytes it carries and whether it names
// a corruption.
func (p *drainFuzzPool) leaf(t *testing.T, kind, key, choice byte) (tlog.Leaf, [][]byte, bool) {
	t.Helper()
	ca := int(key) % len(p.cas)
	c := p.certs[ca][int(choice>>2)%len(p.certs[ca])]
	blob := c.Marshal()
	corrupt := choice & 3
	switch corrupt {
	case 1:
		blob = truncated(blob)
	case 2:
		blob = c.Key.Marshal()
	case 3:
		blob = p.nonCan[ca]
	}
	ev := func(typ string) wire.Evidence { return wire.Evidence{Type: typ, Blob: []byte("e")} }
	var (
		k     tlog.Kind
		enc   []byte
		err   error
		blobs = [][]byte{blob}
	)
	switch kind % 9 {
	case 0:
		k = tlog.KindIssue
		enc, err = (&tlog.IssueBody{CARole: 1, Serial: c.Serial, PolicyVersion: 1, Cert: blob, KeyID: "kid"}).Encode()
	case 1:
		k, enc = tlog.KindLoginIssue, rawLoginBody(t, c.Serial, blob)
	case 2:
		k, enc = tlog.KindHostIssue, rawHostBody(t, c.Serial, blob)
	case 3:
		k = tlog.KindMachineIssue
		enc, err = (&tlog.MachineIssueBody{Serial: c.Serial, PolicyVersion: 1, DirectoryVersion: 1, CapSeconds: 90, Request: []byte("r"),
			Evidence: []wire.Evidence{ev(wire.EvidenceMachinePoP)}, Cert: blob, KeyID: "kid"}).Encode()
	case 4, 5:
		k = tlog.KindProbeIssue
		enc, err = (&tlog.ProbeIssueBody{Serial: c.Serial, Negative: kind%9 == 5, PolicyVersion: 1, DirectoryVersion: 1, CapSeconds: 90, Request: []byte("r"),
			Evidence: []wire.Evidence{ev(wire.EvidenceHostPoP), ev(wire.EvidenceProbePoP)}, Cert: blob, KeyID: "kid"}).Encode()
	case 6:
		first := p.certs[(ca+1)%len(p.cas)][0].Marshal()
		k, blobs = tlog.KindRevocationRecovery, [][]byte{first, blob}
		enc = rawRecoveryBody(t, testInstallationID, first, blob)
	case 7:
		k, blobs, corrupt = tlog.KindRefusal, nil, 0
		enc, err = (&tlog.RefusalBody{PeerUID: 1000, Reason: tlog.ReasonBadPrincipal, Detail: "bad_principal"}).Encode()
	default:
		k, blobs, corrupt = tlog.KindClockRegression, nil, 0
		enc, err = (&tlog.ClockRegressionBody{NowMicros: 1, HighWaterMicros: 2}).Encode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return tlog.Leaf{Kind: k, Body: enc}, blobs, corrupt != 0
}

// FuzzDrainFeed (03-12e): leaves of every kind, built with the bodies'
// encoders from a fixed certificate pool in the order, kinds, keys,
// lifetimes and named corruptions the input chooses, fed through
// drainFeed. A named corruption must be an error; otherwise the result is
// an error or equals the model, which takes the largest ValidBefore per
// signature key (the earliest leaf on a tie) by parsing the very bytes the
// feed sees.
func FuzzDrainFeed(f *testing.F) {
	for k := range byte(9) {
		f.Add([]byte{k, k, k << 2}) // one leaf of every kind
	}
	for _, seed := range [][]byte{{0, 0, 1}, {1, 1, 2}, {2, 2, 3}, {6, 0, 5}} {
		f.Add(seed) // a truncation, a plain key, a non-canonical blob, a recovery's
	}
	f.Add([]byte{6, 0, 4})                                                                          // a recovery with two certificates
	f.Add([]byte{0, 0, 0, 1, 0, 4, 2, 1, 8, 4, 2, 12, 5, 2, 4, 6, 1, 8, 7, 0, 0, 8, 0, 0, 3, 2, 4}) // a mixed log
	var (
		once sync.Once
		pool *drainFuzzPool
	)
	f.Fuzz(func(t *testing.T, ops []byte) {
		once.Do(func() { pool = newDrainFuzzPool(t) })
		if len(ops) > 3*64 {
			ops = ops[:3*64]
		}
		acc := krl.NewDrainMax()
		model := map[string]krl.DrainEntry{}
		for i := 0; i+2 < len(ops); i += 3 {
			idx := uint64(i / 3) //nolint:gosec // G115: a small index
			l, blobs, corrupt := pool.leaf(t, ops[i], ops[i+1], ops[i+2])
			err := drainFeed(acc, idx, l)
			if corrupt {
				if err == nil {
					t.Fatalf("op %d: a %s leaf with a named corruption was fed without an error", i/3, l.Kind)
				}
				return
			}
			if err != nil {
				return
			}
			for _, b := range blobs {
				pub, perr := ssh.ParsePublicKey(b)
				if perr != nil {
					t.Fatalf("op %d: the model cannot parse a certificate the feed accepted: %v", i/3, perr)
				}
				c, ok := pub.(*ssh.Certificate)
				if !ok {
					t.Fatalf("op %d: the feed accepted a %s key", i/3, pub.Type())
				}
				key := string(c.SignatureKey.Marshal())
				if cur, ok := model[key]; !ok || c.ValidBefore > cur.ValidBefore {
					model[key] = krl.DrainEntry{ValidBefore: c.ValidBefore, Leaf: idx, Serial: c.Serial, KeyID: c.KeyId}
				}
			}
		}
		for _, ca := range pool.cas {
			key := ca.PublicKey().Marshal()
			got, ok := acc.For(key)
			want, wok := model[string(key)]
			if ok != wok || got != want {
				t.Fatalf("the accumulator holds %+v (%t) for %s, the model %+v (%t)", got, ok, ssh.FingerprintSHA256(ca.PublicKey()), want, wok)
			}
		}
	})
}

// installPrev installs d at the clock with the signer stopped, behind the
// checkpoint note previous (nil for none) (03-12e).
func (k *swKit) installPrev(t *testing.T, d [4][]byte, previous []byte) ([]DrainNote, error) {
	t.Helper()
	var (
		notes []DrainNote
		err   error
	)
	k.stopped(t, func(db *signerdb.DB) {
		_, notes, err = InstallBundleWithPrevious(context.Background(), db, k.gb, nil, 0, d[0], d[1], d[2], d[3], k.clk.Now, previous)
		if err == nil {
			dropDrained(t, k.gb, notes)
		}
	})
	return notes, err
}

// checkpoint is the env's latest checkpoint note.
func (k *swKit) checkpoint(t *testing.T) []byte {
	t.Helper()
	cp, _, err := k.e.db.LatestCheckpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// appendLeaves appends one clock_regression leaf per body seed to the
// state database at path through a plain log writer, with no signer
// running on it, and returns that database's latest checkpoint note.
func (k *swKit) appendLeaves(t *testing.T, path string, seeds ...uint64) []byte {
	t.Helper()
	db, err := signerdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, s := range seeds {
		body, err := (&tlog.ClockRegressionBody{NowMicros: s, HighWaterMicros: s + 1}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := appendRaw(db, k.e.fx, k.clk.Now, tlog.KindClockRegression, body); err != nil {
			t.Fatalf("append a leaf: %v", err)
		}
	}
	cp, _, err := db.LatestCheckpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

// fork returns a checkpoint of a copy of the env's state that holds one
// more leaf, after appending a different leaf to the env's own log: the
// two logs have the same size and different roots (03-12e).
func (k *swKit) fork(t *testing.T) []byte {
	t.Helper()
	var cp []byte
	k.stopped(t, func(*signerdb.DB) {
		cp = k.appendLeaves(t, copyState(t, k.e.dbPath), 7)
		k.appendLeaves(t, k.e.dbPath, 9)
	})
	return cp
}

// handSwitch is the root-signed switch of role issued at issuedAt with
// trusted_until tu, edited by hand (editedSuccessor), so that its end may
// lie further beyond the floor than BuildSuccessor's MaxDrainAllowance.
func (k *swKit) handSwitch(t *testing.T, issuedAt time.Time, role string, tu uint64) [4][]byte {
	t.Helper()
	return editedSuccessor(t, k.e.db, func(b *trust.Bundle) {
		for i := range b.CAs {
			switch ca := &b.CAs[i]; {
			case ca.Role == role && ca.State == "next":
				ca.State = "active"
			case ca.Role == role && ca.State == "active":
				ca.State, ca.TrustedUntil = "draining", unixTime(tu)
			}
		}
		b.IssuedAt = issuedAt.UTC().Format(trust.TimeFormat)
	}, nil, k.e.fx.Root)
}

// TestInstallUpperBound (03-12e, UB-01 to UB-04): the latest trusted_until
// a switch install accepts is max(signer-now + the larger TTL, maxVB) +
// 300 + MaxDrainAllowance + 300, it never falls below the binding, and an
// overflow is refused. The table is drainUpperBound's; the leaves install
// switches edited by hand, since BuildSuccessor caps the allowance.
func TestInstallUpperBound(t *testing.T) {
	const week = uint64(7 * 24 * 3600)
	for _, r := range []struct {
		name                     string
		now, prev, next, vb, out uint64
	}{
		{"normal", 1_800_000_000, 3600, 7200, 1_800_000_100, 1_800_000_000 + 7200 + 300 + week + 300},
		{"max_valid_before_above_now_plus_ttl", 1_800_000_000, 7200, 3600, 1_900_000_000, 1_900_000_000 + 300 + week + 300},
		{"equality_at_the_limit", 1_800_000_000, 3600, 3600, 1_800_003_600, 1_800_003_600 + 600 + week},
	} {
		if got, err := drainUpperBound(r.now, r.prev, r.next, r.vb); err != nil || got != r.out {
			t.Errorf("%s: drainUpperBound = %d, %v; want %d", r.name, got, err, r.out)
		}
	}
	// bound is the upper bound of a user switch installed at now over
	// drainEnv's log, whose user maximum is below now plus the TTL.
	bound := func(k *swKit, now time.Time) uint64 {
		return uint64(now.Unix()) + k.maxTTL(t, trust.RoleUser) + 600 + week //nolint:gosec // G115: after 1970
	}
	t.Run("drain_window_too_long_refused", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		b := bound(k, k.now())
		done := k.unchanged(t)
		_, err := k.install(t, k.handSwitch(t, at, trust.RoleUser, b+1), true)
		if !errors.Is(err, ErrDrainWindowTooLong) || !strings.Contains(err.Error(), "the switch of CA user ends trust at "+unixTime(b+1)+", above the latest acceptable "+unixTime(b)) {
			t.Fatalf("a switch one second above the bound: %v, want drain_window_too_long naming %s", err, unixTime(b))
		}
		done()
	})
	t.Run("upper_bound_at_limit_ok", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		if _, err := k.install(t, k.handSwitch(t, at, trust.RoleUser, bound(k, k.now())), true); err != nil {
			t.Fatalf("a switch exactly at the bound: %v", err)
		}
	})
	t.Run("upper_bound_never_below_binding", func(t *testing.T) {
		// A logged certificate valid for 60 days, beyond signer-now plus
		// the cap: the bound follows its ValidBefore, so the earliest
		// trusted_until the binding accepts passes.
		k, at := drainEnv(t)
		k.at(t, at.Add(5*time.Second))
		vb := uint64(at.Unix()) + 60*86400 //nolint:gosec // G115: after 1970
		k.stopped(t, func(db *signerdb.DB) {
			s := nextSerial(t, db)
			blob := gen1Cert(t, k.e.fx, keystore.RoleUser, s, vb).Marshal()
			enc, err := (&tlog.IssueBody{CARole: uint8(wire.CARoleUser), Serial: s, PolicyVersion: 1, Cert: blob, KeyID: "kid"}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			appendIssued(t, db, k.e.fx, k.clk.Now, tlog.KindIssue, enc, s, "user", blob)
		})
		k.at(t, at.Add(10*time.Second))
		if vb+300 <= bound(k, k.now()) {
			t.Fatal("the certificate does not outlive the clock-based bound; the case proves nothing")
		}
		if _, err := k.install(t, k.handSwitch(t, at, trust.RoleUser, vb+300), true); err != nil {
			t.Fatalf("a switch at the certificate's ValidBefore plus 300 s: %v", err)
		}
	})
	t.Run("overflow_refused", func(t *testing.T) {
		// Pure: an install cannot reach the overflow, because a maximum
		// near 2^64 makes the binding refuse first (no trusted_until in
		// TimeFormat reaches it).
		for _, vb := range []uint64{math.MaxUint64, math.MaxUint64 - 600 - week + 1} {
			if got, err := drainUpperBound(1_800_000_000, 3600, 3600, vb); err == nil {
				t.Fatalf("drainUpperBound with maxVB %d = %d, nil; want an overflow error", vb, got)
			}
		}
		if _, err := drainUpperBound(math.MaxUint64-100, 3600, 3600, 0); err == nil {
			t.Fatal("drainUpperBound with signer-now near 2^64 = nil error; want an overflow error")
		}
	})
	t.Run("clock_far_ahead_raises_the_bound", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		normal := bound(k, k.now())
		k.at(t, at.Add(30*24*time.Hour))
		if _, err := k.install(t, k.handSwitch(t, at, trust.RoleUser, normal+86400), true); err != nil {
			t.Fatalf("a switch a day above the bound of the earlier clock, installed 30 days later: %v", err)
		}
	})
}

// TestInstallPrevious (03-12e, PV-01 to PV-06 and IB-19): a switch
// install needs --previous; whenever it is given it must be a checkpoint
// of this log, signed by the log key, covering at least one entry, that
// the log extends (no larger size, the same root at its size); a
// non-switch install needs none.
func TestInstallPrevious(t *testing.T) {
	sw := func(k *swKit, at time.Time) [4][]byte { return k.switchDocs(t, at, 0, trust.RoleUser) }
	t.Run("switch_without_previous_refused", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		done := k.unchanged(t)
		if _, err := k.installPrev(t, sw(k, at), nil); !errors.Is(err, ErrInstallPreviousRequired) {
			t.Fatalf("a switch without --previous: %v, want install_previous_required", err)
		}
		done()
	})
	t.Run("previous_invalid_refused", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		other, _ := drainEnv(t)
		pub := k.e.fx.Roles[keystore.RoleLog].PublicKey()
		ns, err := tlog.NewNoteSigner(tlog.Origin(pub), k.e.fx.Roles[keystore.RoleLog])
		if err != nil {
			t.Fatal(err)
		}
		empty := sha256.Sum256(nil)
		zero, err := tlog.SignCheckpoint(tlog.Checkpoint{Origin: tlog.Origin(pub), Size: 0, Root: empty[:]}, ns)
		if err != nil {
			t.Fatal(err)
		}
		for name, cp := range map[string][]byte{"garbage": []byte("not a checkpoint"), "another log's key": other.checkpoint(t), "size 0": zero} {
			done := k.unchanged(t)
			if _, err := k.installPrev(t, sw(k, at), cp); !errors.Is(err, ErrInstallPreviousInvalid) {
				t.Fatalf("%s: %v, want install_previous_invalid", name, err)
			}
			done()
		}
	})
	t.Run("previous_larger_than_log_refused", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		var cp []byte
		k.stopped(t, func(*signerdb.DB) { cp = k.appendLeaves(t, copyState(t, k.e.dbPath), 1, 3) })
		done := k.unchanged(t)
		if _, err := k.installPrev(t, sw(k, at), cp); !errors.Is(err, ErrInstallPreviousNotExtended) {
			t.Fatalf("a checkpoint larger than the log: %v, want install_previous_not_extended", err)
		}
		done()
	})
	t.Run("previous_forked_refused", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		cp := k.fork(t)
		done := k.unchanged(t)
		if _, err := k.installPrev(t, sw(k, at), cp); !errors.Is(err, ErrInstallPreviousNotExtended) {
			t.Fatalf("a checkpoint of a fork of the same size: %v, want install_previous_not_extended", err)
		}
		done()
	})
	t.Run("previous_ok", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		if _, err := k.installPrev(t, sw(k, at), k.checkpoint(t)); err != nil {
			t.Fatalf("a switch behind the log's own checkpoint: %v", err)
		}
		k, at = drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		prefix := k.checkpoint(t)
		k.stopped(t, func(*signerdb.DB) { k.appendLeaves(t, k.e.dbPath, 5) })
		if _, err := k.installPrev(t, sw(k, at), prefix); err != nil {
			t.Fatalf("a switch behind a checkpoint of a prefix of the log: %v", err)
		}
	})
	t.Run("previous_checked_when_given", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		prefix := k.checkpoint(t)
		cp := k.fork(t)
		done := k.unchanged(t)
		if _, err := k.installPrev(t, k.policyDocs(t, at), cp); !errors.Is(err, ErrInstallPreviousNotExtended) {
			t.Fatalf("a policy-only install behind a forked checkpoint: %v, want install_previous_not_extended", err)
		}
		done()
		if _, err := k.installPrev(t, k.policyDocs(t, at), prefix); err != nil {
			t.Fatalf("a policy-only install behind a prefix: %v", err)
		}
	})
	t.Run("non_switch_needs_no_previous", func(t *testing.T) {
		r := rc04State(t)
		at2 := r.k.ceremonyTime(t)
		if notes, err := r.k.installPrev(t, r.k.addNextDocs(t, at2, keystore.RoleUser), nil); err != nil || len(notes) != 0 {
			t.Fatalf("an add-next on the RC-04 state with no --previous: %d notes, %v", len(notes), err)
		}
		at3 := r.k.ceremonyTime(t)
		if notes, err := r.k.installPrev(t, r.k.policyDocs(t, at3), nil); err != nil || len(notes) != 0 {
			t.Fatalf("a policy-only install on the RC-04 state with no --previous: %d notes, %v", len(notes), err)
		}
	})
}

// BenchmarkInstallBundleDrainScan (03-12e) times the scan a switch install
// performs (rebuildLogFromWith with the drain option) over a log of n
// certificate leaves: issue and login_issue leaves, each with its
// issuance row, from a pool of certificates reused under fresh serials
// and appended in batched transactions. It reports the heap in use after
// a forced collection, which must not grow with n beyond the hash list.
// It runs only with -bench; leaves=5000000 also needs
// KEYROSTER_BENCH_LARGE=1.
func BenchmarkInstallBundleDrainScan(b *testing.B) {
	for _, n := range []int{100_000, 1_000_000, 5_000_000} {
		b.Run(fmt.Sprintf("leaves=%d", n), func(b *testing.B) {
			if n > 1_000_000 && os.Getenv("KEYROSTER_BENCH_LARGE") != "1" {
				b.Skip("set KEYROSTER_BENCH_LARGE=1 to run leaves=5000000")
			}
			fx := NewFixture(b, 1, 1)
			path := filepath.Join(b.TempDir(), "signer.db")
			db, err := signerdb.Open(path)
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			be := newMemBackend(fx)
			fx.Bootstrap(b, db, be, nil)
			logKey, err := be.Key(keystore.RoleLog, ssh.FingerprintSHA256(fx.Roles[keystore.RoleLog].PublicKey()))
			if err != nil {
				b.Fatal(err)
			}
			ctx := context.Background()
			var pool [][]byte
			ca := fx.Roles[keystore.RoleUser]
			for i := range 64 {
				// Signed by hand, as signTestCert does (a benchmark has no
				// *testing.T for it).
				c := &ssh.Certificate{Key: fx.Roles[keystore.RoleHost].PublicKey(), Serial: uint64(i + 1), CertType: ssh.UserCert, KeyId: "kid", //nolint:gosec // G115: a small index
					ValidPrincipals: []string{"alice"}, ValidAfter: 1, ValidBefore: 1_900_000_000 + uint64(i), Nonce: make([]byte, 32), SignatureKey: ca.PublicKey()} //nolint:gosec // G115: a small index
				out := c.Marshal()
				sig, err := ca.Sign(rand.Reader, out[:len(out)-4])
				if err != nil {
					b.Fatal(err)
				}
				c.Signature = sig
				pool = append(pool, c.Marshal())
			}
			serial, err := db.LastSerial(ctx)
			if err != nil {
				b.Fatal(err)
			}
			for done := 0; done < n; {
				lw, err := newLogWriter(ctx, db, logKey, time.Now)
				if err != nil {
					b.Fatal(err)
				}
				err = lw.logTx(ctx, func(tx *sql.Tx) error {
					for j := 0; j < 5000 && done < n; j++ {
						serial++
						blob := pool[done%len(pool)]
						kind := tlog.KindIssue
						enc, err := (&tlog.IssueBody{CARole: uint8(wire.CARoleUser), Serial: serial, PolicyVersion: 1, Cert: blob, KeyID: "kid"}).Encode()
						if done%2 == 1 {
							kind = tlog.KindLoginIssue
							enc, err = (&tlog.LoginIssueBody{Serial: serial, PolicyVersion: 1, DirectoryVersion: 1, Request: []byte("r"),
								Evidence: []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: []byte("a")}}, Cert: blob, KeyID: "kid"}).Encode()
						}
						if err != nil {
							return err
						}
						is := signerdb.Issuance{Serial: serial, CARole: "user", KeyID: "kid", Cert: blob, IssuedAt: time.Now()}
						binary.BigEndian.PutUint64(is.RequestID[:8], serial)
						if err := db.InsertIssuance(tx, is); err != nil {
							return err
						}
						if err := db.SetLastSerial(tx, serial); err != nil {
							return err
						}
						if _, err := lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(time.Now()), Kind: kind, Body: enc}); err != nil {
							return err
						}
						done++
					}
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
			}
			pub := fx.Roles[keystore.RoleLog].PublicKey()
			v, err := tlog.NewNoteVerifier(tlog.Origin(pub), pub)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for range b.N {
				_, _, inst, err := rebuildLogFromWith(ctx, db, v, rebuildOptions{drain: true})
				if err != nil || inst.drain == nil {
					b.Fatalf("the scan: %v", err)
				}
			}
			b.StopTimer()
			runtime.GC()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			b.ReportMetric(float64(ms.HeapInuse), "heap-inuse-bytes")
		})
	}
}

// TestLogDrain (03-12e): LogDrain walks the verified log with the drain
// scan and returns its accumulator, which for every CA key holds the
// certificate with the largest ValidBefore that the leaves record (the
// earliest leaf on a tie), as a walk of tlog.LeafCertificates over the
// same leaves finds; a log that does not verify gives an error and no
// accumulator.
func TestLogDrain(t *testing.T) {
	ctx := context.Background()
	t.Run("returns_the_accumulator_of_a_verified_log", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		k.issueAdmin(t, wire.CARoleHost, 86400)
		k.stopped(t, func(db *signerdb.DB) {
			acc, err := LogDrain(ctx, db, k.e.fx.Roles[keystore.RoleLog].PublicKey())
			if err != nil || acc == nil {
				t.Fatalf("LogDrain = %v, %v; want an accumulator", acc, err)
			}
			want := map[string]krl.DrainEntry{}
			if err := db.ForEachLeaf(ctx, func(idx uint64, raw []byte) error {
				l, err := tlog.DecodeLeaf(raw)
				if err != nil {
					return err
				}
				certs, err := tlog.LeafCertificates(l)
				if err != nil {
					return err
				}
				for _, c := range certs {
					ca := string(c.SignatureKey.Marshal())
					if cur, ok := want[ca]; !ok || c.ValidBefore > cur.ValidBefore {
						want[ca] = krl.DrainEntry{ValidBefore: c.ValidBefore, Leaf: idx, Serial: c.Serial, KeyID: c.KeyId}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, role := range []keystore.Role{keystore.RoleUser, keystore.RoleHost} {
				ca := k.e.fx.Roles[role].PublicKey().Marshal()
				w, ok := want[string(ca)]
				if !ok {
					t.Fatalf("the log records no certificate of the %s CA; the fixture must issue one", role)
				}
				if got, ok := acc.For(ca); !ok || got != w {
					t.Fatalf("LogDrain's entry for the %s CA = %+v, %t; want %+v", role, got, ok, w)
				}
			}
			if got, ok := acc.For(k.e.fx.Roles[keystore.RoleMachine].PublicKey().Marshal()); ok {
				t.Fatalf("LogDrain holds %+v for the machine CA, which issued nothing", got)
			}
		})
	})
	t.Run("refuses_a_log_that_does_not_verify", func(t *testing.T) {
		k, _ := drainEnv(t)
		k.offline(t, func(db *signerdb.DB) {
			if acc, err := LogDrain(ctx, db, newEd25519(t).PublicKey()); err == nil || acc != nil {
				t.Fatalf("LogDrain under another log key = %v, %v; want an error and no accumulator", acc, err)
			}
		})
		k.e.exec(t, `UPDATE log_leaf SET leaf = leaf || x'00' WHERE idx = 1`)
		k.offline(t, func(db *signerdb.DB) {
			if acc, err := LogDrain(ctx, db, k.e.fx.Roles[keystore.RoleLog].PublicKey()); err == nil || acc != nil {
				t.Fatalf("LogDrain over an edited leaf = %v, %v; want an error and no accumulator", acc, err)
			}
		})
	})
}
