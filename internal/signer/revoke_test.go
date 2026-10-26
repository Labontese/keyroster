package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

const testInstallationID = "0123456789abcdef0123456789abcdef"

// bigSKKey returns a fresh canonical sk-ssh-ed25519@openssh.com public key
// of exactly size bytes (at least 74), padded by its application string:
// a revocable key near wire.MaxSubjectKeyLen for the explicit-key byte cap.
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

// revokeClock is a settable clock for the signer and the bootstrap.
type revokeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *revokeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *revokeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// revokeEnv is a logEnv whose bundle has an installation ID, with one
// issued user certificate to revoke.
type revokeEnv struct {
	*logEnv
	clock  *revokeClock
	serial uint64
}

func newRevokeEnv(t *testing.T, admins int, quorum uint32, installationID string) *revokeEnv {
	t.Helper()
	fx := NewFixture(t, admins, quorum)
	fx.InstallationID = installationID
	clock := &revokeClock{now: time.Now().Truncate(time.Second).Add(500 * time.Millisecond)}
	e := &revokeEnv{logEnv: newLogEnvClock(t, fx, clock.Now), clock: clock}
	resp, err := e.issue()
	if err != nil {
		t.Fatal(err)
	}
	e.serial = resp.Serial
	return e
}

// revokeRequest returns a revoke request for serial under role, created
// now by the env's clock, signed under ns by signers.
func (e *revokeEnv) revokeRequest(serial uint64, role wire.CARole, ns string, signers ...ssh.Signer) *wire.RevokeRequest {
	e.t.Helper()
	req := &wire.RevokeRequest{InstallationID: e.fx.InstallationID, Target: wire.TargetSerial, CARole: role, Serial: serial, CreatedAt: uint64(e.clock.Now().Unix()), Reason: "test"} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		e.t.Fatal(err)
	}
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, ns, req.SigningBytes())
		if err != nil {
			e.t.Fatal(err)
		}
		req.Evidence = append(req.Evidence, wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig})
	}
	return req
}

// bundle returns the installed trust bundle.
func (e *revokeEnv) bundle() *trust.Bundle {
	e.t.Helper()
	stored, err := e.db.LatestBundle(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	b, err := trust.ParseBundle(stored.Bundle)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// revoked runs req through revokeOrRefuse and requires success, exactly
// one new revoke and one new krl_publish leaf in that order, and a KRL
// that verifies against the bundle.
func (e *revokeEnv) revoked(req *wire.RevokeRequest, storedVersion uint64) (*wire.RevokeResponse, []tlog.Leaf) {
	e.t.Helper()
	before := len(e.leavesOf())
	resp, er := e.s.revokeOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		e.t.Fatalf("revoke refused: %s", er.Message)
	}
	leaves := e.leavesOf()[before:]
	if len(leaves) != 2 || leaves[0].Kind != tlog.KindRevoke || leaves[1].Kind != tlog.KindKRLPublish ||
		resp.RevokeLeaf != leaves[0].Index || resp.PublishLeaf != leaves[1].Index {
		e.t.Fatalf("leaves after the revoke: %+v (response %+v), want one revoke then one krl_publish", leaves, resp)
	}
	got := e.s.GetKRL()
	m, err := krl.VerifyManifest(got.Manifest, got.Sig, got.KRL, e.bundle(), e.fx.InstallationID, storedVersion)
	if err != nil || m.KRLVersion != resp.KRLVersion || m.LogIndex != resp.PublishLeaf {
		e.t.Fatalf("published KRL: %+v, %v (response %+v)", m, err, resp)
	}
	return resp, leaves
}

// refusedRevoke runs req through revokeOrRefuse and requires the refusal
// detail, exactly one new leaf (the refusal, with req's digest) and the
// revocation state unchanged.
func (e *revokeEnv) refusedRevoke(req *wire.RevokeRequest, detail string) {
	e.t.Helper()
	before := len(e.leavesOf())
	krlBefore := e.s.GetKRL()
	revsBefore := e.countRows("revocation")
	resp, er := e.s.revokeOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if resp != nil || er == nil || er.Message != detail {
		e.t.Fatalf("revoke: %+v, %+v; want the refusal %s", resp, er, detail)
	}
	leaves := e.leavesOf()[before:]
	if len(leaves) != 1 || leaves[0].Kind != tlog.KindRefusal {
		e.t.Fatalf("%d new leaves after the refusal %s, want exactly one refusal leaf", len(leaves), detail)
	}
	b, err := tlog.DecodeRefusalBody(leaves[0].Body)
	if err != nil || b.Detail != detail || b.RequestDigest != req.Digest() || b.Reason == tlog.ReasonInternal {
		e.t.Fatalf("refusal leaf %+v, %v", b, err)
	}
	if after := e.s.GetKRL(); !bytes.Equal(after.KRL, krlBefore.KRL) || e.countRows("revocation") != revsBefore {
		e.t.Fatalf("the revocation state changed after the refusal %s", detail)
	}
}

func (e *revokeEnv) countRows(table string) int {
	e.t.Helper()
	var n int
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n) //nolint:gosec // G202: a constant table name
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// TestRevoke (REVOKE-01, T-03-01, T-03-02): one admin of a quorum-2
// policy revokes; every other credential, a replay, an unknown serial, a
// role mismatch and a bundle without installation ID are refused with
// their detail and change nothing.
func TestRevoke(t *testing.T) {
	t.Run("one_admin_of_quorum_two_revokes", func(t *testing.T) {
		e := newRevokeEnv(t, 2, 2, testInstallationID)
		resp, leaves := e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
		// The first publish takes the clock's seconds (max(0 + 1,
		// issued_at), owner decision 2026-10-25, Q1).
		if want := uint64(e.clock.Now().Unix()); resp.KRLVersion != want { //nolint:gosec // G115: after 1970
			t.Fatalf("first KRL version %d, want the publish time in seconds %d", resp.KRLVersion, want)
		}
		body, err := tlog.DecodeRevokeBody(leaves[0].Body)
		if err != nil || len(body.Entries) != 1 || body.Entries[0].Serial != e.serial || body.Entries[0].Kind != tlog.RevokedSerial ||
			!bytes.Equal(body.Entries[0].CAKey, e.fx.Roles["user"].PublicKey().Marshal()) || body.Entries[0].ValidBeforeSeconds == 0 {
			t.Fatalf("revoke body %+v, %v", body, err)
		}
		// A second revocation publishes the next version over both
		// entries, strictly greater than the first. The serial is
		// time-based, so the frozen clock moves on first.
		e.clock.set(e.clock.Now().Add(time.Second))
		other, err := e.issue()
		if err != nil {
			t.Fatal(err)
		}
		if resp2, _ := e.revoked(e.revokeRequest(other.Serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[1]), resp.KRLVersion); resp2.KRLVersion <= resp.KRLVersion {
			t.Fatalf("second KRL version %d, want strictly greater than the previous %d", resp2.KRLVersion, resp.KRLVersion)
		}
	})
	e := newRevokeEnv(t, 1, 1, testInstallationID)
	nonAdmin := newEd25519(t)
	for _, tc := range []struct {
		name   string
		req    func() *wire.RevokeRequest
		detail string
	}{
		{"non_admin_refused", func() *wire.RevokeRequest {
			return e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, nonAdmin)
		}, "evidence_not_admin"},
		{"issue_namespace_refused", func() *wire.RevokeRequest {
			return e.revokeRequest(e.serial, wire.CARoleUser, wire.AdminSSHSIGNamespace, e.fx.Admins[0])
		}, "evidence_wrong_namespace"},
		{"no_evidence_refused", func() *wire.RevokeRequest {
			return e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace)
		}, "missing_evidence"},
		{"stale_request_refused", func() *wire.RevokeRequest {
			r := e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace)
			r.CreatedAt -= 301
			return e.signed(r, e.fx.Admins[0])
		}, "request_time_skew"},
		{"unknown_serial_refused", func() *wire.RevokeRequest {
			return e.revokeRequest(e.serial+1, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0])
		}, "unknown_serial"},
		{"ca_role_mismatch_refused", func() *wire.RevokeRequest {
			return e.revokeRequest(e.serial, wire.CARoleHost, wire.RevokeSSHSIGNamespace, e.fx.Admins[0])
		}, "ca_role_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer e.use(t)()
			e.refusedRevoke(tc.req(), tc.detail)
		})
	}
	t.Run("duplicate_request", func(t *testing.T) {
		defer e.use(t)()
		req := e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0])
		e.revoked(req, 0)
		revokes := 0
		e.refusedRevoke(req, "duplicate_request")
		for _, l := range e.leavesOf() {
			if l.Kind == tlog.KindRevoke {
				revokes++
			}
		}
		if revokes != 1 {
			t.Fatalf("%d revoke leaves after the replay, want 1", revokes)
		}
	})
	t.Run("no_installation_id_refused", func(t *testing.T) {
		e := newRevokeEnv(t, 1, 1, "")
		e.refusedRevoke(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), "krl_no_installation_id")
		if st, err := e.db.KRLState(context.Background()); err != nil || st != nil {
			t.Fatalf("KRL state after the refusal: %+v, %v", st, err)
		}
	})
	t.Run("installation_binding", func(t *testing.T) {
		// Pre-merge review of PR #61 (owner decision 2026-10-26): an
		// admin-signed request for another installation, and a 03-01 v1
		// request, which names none, are refused before the evidence is
		// checked; the request for this installation revokes.
		e := newRevokeEnv(t, 1, 1, testInstallationID)
		other := e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace)
		other.InstallationID = "ffffffffffffffffffffffffffffffff"
		e.refusedRevoke(e.signed(other, e.fx.Admins[0]), "revoke_installation_mismatch")
		v1 := e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace)
		v1.InstallationID = ""
		sig, err := sshsig.Sign(rand.Reader, e.fx.Admins[0], wire.RevokeSSHSIGNamespaceV1, v1.SigningBytes())
		if err != nil {
			t.Fatal(err)
		}
		v1.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
		e.refusedRevoke(v1, "revoke_installation_missing")
		e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
	})
}

// signed replaces req's evidence with signatures by signers over its
// current signing bytes.
func (e *revokeEnv) signed(req *wire.RevokeRequest, signers ...ssh.Signer) *wire.RevokeRequest {
	e.t.Helper()
	req.Evidence = nil
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, wire.RevokeSSHSIGNamespace, req.SigningBytes())
		if err != nil {
			e.t.Fatal(err)
		}
		req.Evidence = append(req.Evidence, wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig})
	}
	return req
}

// TestRevokeClock (F9): Revoke takes one clock reading for freshness,
// ResolvedAtSeconds, the manifest's issued_at, the krl_publish
// IssuedAtSeconds and both leaf times before the clamp; a clock stepped
// back is not refused, and the clamp raises only the leaf time.
func TestRevokeClock(t *testing.T) {
	t.Run("resolved_at_one_reading", func(t *testing.T) {
		e := newRevokeEnv(t, 1, 1, testInstallationID)
		at := e.clock.Now().Add(3*time.Second + 700*time.Millisecond)
		e.clock.set(at)
		_, leaves := e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
		rb, err := tlog.DecodeRevokeBody(leaves[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		pb, err := tlog.DecodeKRLPublishBody(leaves[1].Body)
		if err != nil {
			t.Fatal(err)
		}
		m, err := krl.ParseManifest(pb.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(at.Unix()) //nolint:gosec // G115: after 1970
		if rb.ResolvedAtSeconds != want || pb.IssuedAtSeconds != want || m.IssuedAt != at.UTC().Truncate(time.Second).Format(trust.TimeFormat) {
			t.Fatalf("ResolvedAtSeconds %d, IssuedAtSeconds %d, manifest issued_at %s; want all %d", rb.ResolvedAtSeconds, pb.IssuedAtSeconds, m.IssuedAt, want)
		}
		if leaves[0].TimeMicros != uint64(at.UnixMicro()) || leaves[1].TimeMicros != uint64(at.UnixMicro()) { //nolint:gosec // G115: after 1970
			t.Fatalf("leaf times %d, %d; want the one reading %d", leaves[0].TimeMicros, leaves[1].TimeMicros, at.UnixMicro())
		}
	})
	t.Run("clock_stepped_back", func(t *testing.T) {
		e := newRevokeEnv(t, 1, 1, testInstallationID)
		all := e.leavesOf()
		last := all[len(all)-1].TimeMicros                         // the issue leaf, at T
		back := time.UnixMicro(int64(last)).Add(-10 * time.Second) //nolint:gosec // G115: a test time
		e.clock.set(back)
		_, leaves := e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
		rb, err := tlog.DecodeRevokeBody(leaves[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		if leaves[0].TimeMicros != last || rb.ResolvedAtSeconds != uint64(back.Unix()) || rb.ResolvedAtSeconds*1_000_000 > leaves[0].TimeMicros { //nolint:gosec // G115: after 1970
			t.Fatalf("leaf time %d (want the clamp to %d), ResolvedAtSeconds %d (want %d)", leaves[0].TimeMicros, last, rb.ResolvedAtSeconds, back.Unix())
		}
	})
}

// TestRevokeKRLTooLarge (T-03-201): a revocation whose KRL would exceed
// MaxKRL is refused krl_too_large and rolled back: the revocation table
// keeps only the rows a published KRL could carry, the request ID is not
// recorded, and the only new leaf is the refusal.
func TestRevokeKRLTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 600 000 revocation rows")
	}
	e := newRevokeEnv(t, 1, 1, testInstallationID)
	ca := e.fx.Roles["user"].PublicKey().Marshal()
	// The 600 000 rows join the revocation table inside the revocation's
	// own transaction (a trigger on revoke_request), so they are rolled
	// back with it: rows written outside that transaction, with no revoke
	// leaf recording them, would be refused as revocations_not_logged
	// when the failed transaction reloads the log.
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE TABLE bulk (ca BLOB, serial INTEGER)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 600000)
			INSERT INTO bulk (ca, serial) SELECT ?, 2 * x FROM c`, ca); err != nil {
			return err
		}
		_, err := tx.Exec(`CREATE TRIGGER bulk_revoke AFTER INSERT ON revoke_request BEGIN
			INSERT INTO revocation (kind, ca_key, serial, request_id, leaf_index, revoked_at_us)
			SELECT 'serial', ca, serial, NEW.request_id, NEW.leaf_index, 1 FROM bulk; END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	req := e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0])
	e.refusedRevoke(req, "krl_too_large")
	if used, err := e.db.RevokeRequestUsed(context.Background(), req.RequestID); err != nil || used {
		t.Fatalf("the refused request ID is recorded: %v, %v", used, err)
	}
}

// TestRevokeRestart (T-03-06): a signer restarted on a state database
// holding revoke and krl_publish leaves starts and serves the same KRL;
// a KRL state the log does not record stops serve and doctor alike
// (krl_state_not_logged).
func TestRevokeRestart(t *testing.T) {
	e := newRevokeEnv(t, 1, 1, testInstallationID)
	e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
	before := e.s.GetKRL()
	e.close()
	if err := e.open(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	after := e.s.GetKRL()
	if !bytes.Equal(after.KRL, before.KRL) || !bytes.Equal(after.Manifest, before.Manifest) || !bytes.Equal(after.Sig, before.Sig) {
		t.Fatal("the restarted signer serves another KRL")
	}
	if err := CheckTrust(context.Background(), e.db); err != nil {
		t.Fatalf("CheckTrust of a healthy database: %v", err)
	}
	e.close()
	execSQL(t, e.dbPath, `UPDATE krl_state SET krl = ? WHERE id = 1`, []byte("SSHKRL\n\x00tampered"))
	err := e.open()
	if !errors.Is(err, errLogMismatch) || !strings.Contains(err.Error(), "krl_state_not_logged") {
		t.Fatalf("start with a tampered KRL state: %v, want krl_state_not_logged", err)
	}
	db := e.openDB()
	err = CheckTrust(context.Background(), db)
	_ = db.Close()
	if err == nil || !strings.Contains(err.Error(), "krl_state_not_logged") {
		t.Fatalf("CheckTrust with a tampered KRL state: %v, want krl_state_not_logged", err)
	}
	execSQL(t, e.dbPath, `DELETE FROM krl_state`)
	if err := e.open(); err == nil || !strings.Contains(err.Error(), "krl_state_not_logged") {
		t.Fatalf("start with the KRL state deleted: %v, want krl_state_not_logged", err)
	}
}

// TestRevocationsNotLogged (pre-merge review): the revocation table, from
// which every KRL is rebuilt, must be exactly the entries of the revoke
// leaves. A row deleted, written or changed outside the signer stops
// serve and doctor's log check alike (revocations_not_logged), so the
// next revocation cannot publish a signed KRL that un-revokes a
// certificate.
func TestRevocationsNotLogged(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		args        func(e *revokeEnv) []any
	}{
		{"row_deleted", `DELETE FROM revocation WHERE serial = ?`, func(e *revokeEnv) []any { return []any{int64(e.serial)} }}, //nolint:gosec // G115: a test serial
		{"row_inserted", `INSERT INTO revocation (kind, ca_key, serial, request_id, leaf_index, revoked_at_us)
			SELECT kind, ca_key, serial + 1, request_id, leaf_index, revoked_at_us FROM revocation`, func(*revokeEnv) []any { return nil }},
		{"row_changed", `UPDATE revocation SET serial = serial + 1`, func(*revokeEnv) []any { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRevokeEnv(t, 1, 1, testInstallationID)
			e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
			e.close()
			// Control: the untouched database starts and passes the check.
			db := e.openDB()
			err := CheckLog(context.Background(), db, e.fx.Roles[keystore.RoleLog].PublicKey())
			_ = db.Close()
			if err != nil {
				t.Fatalf("CheckLog of a healthy database: %v", err)
			}
			execSQL(t, e.dbPath, tc.query, tc.args(e)...)
			err = e.open()
			if !errors.Is(err, errLogMismatch) || !strings.Contains(err.Error(), "revocations_not_logged") {
				t.Fatalf("start: %v, want revocations_not_logged", err)
			}
			db = e.openDB()
			err = CheckLog(context.Background(), db, e.fx.Roles[keystore.RoleLog].PublicKey())
			_ = db.Close()
			if !errors.Is(err, errLogMismatch) || !strings.Contains(err.Error(), "revocations_not_logged") {
				t.Fatalf("CheckLog: %v, want revocations_not_logged", err)
			}
		})
	}
}

// TestRevocationsChangedWhileRunning (pre-merge review, round 2): the
// start-up check does not see a revocation row deleted, written or
// changed through another database handle while the signer runs. The
// next revocation must not publish a KRL built from such rows: it is
// refused revocations_not_logged before the ops key signs, nothing of it
// commits, and the signer stops (broken) as it would at start. The
// control revokes B on an untouched table, which needs the in-memory set
// to have taken A's entry when A committed.
func TestRevocationsChangedWhileRunning(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		args        func(e *revokeEnv) []any
	}{
		{"untouched", ``, nil},
		{"row_deleted", `DELETE FROM revocation WHERE serial = ?`, func(e *revokeEnv) []any { return []any{int64(e.serial)} }}, //nolint:gosec // G115: a test serial
		{"row_inserted", `INSERT INTO revocation (kind, ca_key, serial, request_id, leaf_index, revoked_at_us)
			SELECT kind, ca_key, serial + 1000, request_id, leaf_index, revoked_at_us FROM revocation`, func(*revokeEnv) []any { return nil }},
		{"row_changed", `UPDATE revocation SET serial = serial + 1000`, func(*revokeEnv) []any { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRevokeEnv(t, 1, 1, testInstallationID)
			first, _ := e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
			// The serial is time-based, so the frozen clock moves on first.
			e.clock.set(e.clock.Now().Add(time.Second))
			b, err := e.issue()
			if err != nil {
				t.Fatal(err)
			}
			reqB := e.revokeRequest(b.Serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0])
			if tc.query == "" {
				e.revoked(reqB, first.KRLVersion)
				return
			}
			// Through its own handle, while e.s stays open.
			execSQL(t, e.dbPath, tc.query, tc.args(e)...)
			before := e.s.GetKRL()
			rows := e.countRows("revocation")
			publishes := 0
			for _, l := range e.leavesOf() {
				if l.Kind == tlog.KindKRLPublish {
					publishes++
				}
			}
			resp, er := e.s.revokeOrRefuse(context.Background(), Peer{UID: 1000}, reqB)
			if resp != nil || er == nil || er.Message != "revocations_not_logged" || er.Code != wire.CodeUnavailable {
				t.Fatalf("revoke B: %+v, %+v; want the refusal revocations_not_logged", resp, er)
			}
			after := e.s.GetKRL()
			if !bytes.Equal(after.KRL, before.KRL) || !bytes.Equal(after.Manifest, before.Manifest) {
				t.Fatal("the signer serves another KRL after the refusal")
			}
			stored, err := e.db.KRLState(context.Background())
			if err != nil || stored == nil || stored.Version != first.KRLVersion {
				t.Fatalf("KRL state after the refusal: %+v, %v; want the first publish's version %d", stored, err, first.KRLVersion)
			}
			n := 0
			for _, l := range e.leavesOf() {
				if l.Kind == tlog.KindKRLPublish {
					n++
				}
			}
			if n != publishes || e.countRows("revocation") != rows {
				t.Fatalf("%d krl_publish leaves and %d revocation rows after the refusal, want %d and %d", n, e.countRows("revocation"), publishes, rows)
			}
			e.s.mu.Lock()
			broken := e.s.broken
			e.s.mu.Unlock()
			if !errors.Is(broken, errRevocationsNotLogged) {
				t.Fatalf("broken = %v, want revocations_not_logged", broken)
			}
			if _, err := e.issue(); err == nil {
				t.Fatal("the stopped signer still issues")
			}
		})
	}
}

// TestRevokeFailedTxDiscardsPendingEntries (pre-merge review, round 2):
// the entries of a revoke leaf join the in-memory set only when its
// transaction commits. A failed transaction leaves the set as the reloaded
// log records it, so the next legitimate revocation still publishes.
func TestRevokeFailedTxDiscardsPendingEntries(t *testing.T) {
	e := newRevokeEnv(t, 1, 1, testInstallationID)
	ctx := context.Background()
	body, err := (&tlog.RevokeBody{Request: []byte("r"), Entries: []tlog.RevokedEntry{
		{Kind: tlog.RevokedSerial, CAKey: e.fx.Roles["user"].PublicKey().Marshal(), Serial: 999},
	}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected failure after the append")
	e.s.mu.Lock()
	err = e.s.logTx(ctx, func(tx *sql.Tx) error {
		if _, err := e.s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(e.clock.Now()), Kind: tlog.KindRevoke, Body: body}); err != nil {
			return err
		}
		return injected
	})
	broken := e.s.broken
	e.s.mu.Unlock()
	if !errors.Is(err, injected) || broken != nil {
		t.Fatalf("logTx: %v (broken %v), want the injected error and a reloaded state", err, broken)
	}
	e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
}

// openDB opens the env's state database through its own handle.
func (e *revokeEnv) openDB() *signerdb.DB {
	e.t.Helper()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	return db
}

// use makes t the env's test while a subtest runs on the shared env, so
// its helpers fail the subtest; the returned function restores the
// previous one.
func (e *revokeEnv) use(t *testing.T) func() {
	prev := e.t
	e.t = t
	return func() { e.t = prev }
}

// TestRevokeFailedCommitReloadsKRL (pre-merge review): when a transaction
// that appended leaves fails, logTx reloads the log in case the COMMIT
// reached the disk anyway, and the published KRL the signer serves is
// reloaded with it. The cache is set back to "nothing published" to stand
// in for the version before a revocation whose COMMIT reported an error
// but was durable; after the failed transaction GetKRL must serve what
// krl_state holds.
func TestRevokeFailedCommitReloadsKRL(t *testing.T) {
	e := newRevokeEnv(t, 1, 1, testInstallationID)
	e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
	ctx := context.Background()
	stored, err := e.db.KRLState(ctx)
	if err != nil || stored == nil {
		t.Fatalf("KRL state: %+v, %v", stored, err)
	}
	body, err := (&tlog.RefusalBody{PeerUID: 1000, Reason: tlog.ReasonMalformed, Detail: "test"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected failure after the append")
	e.s.mu.Lock()
	e.s.krl.Store(nil)
	err = e.s.logTx(ctx, func(tx *sql.Tx) error {
		if _, err := e.s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(e.clock.Now()), Kind: tlog.KindRefusal, Body: body}); err != nil {
			return err
		}
		return injected
	})
	broken := e.s.broken
	e.s.mu.Unlock()
	if !errors.Is(err, injected) || broken != nil {
		t.Fatalf("logTx: %v (broken %v), want the injected error and a reloaded state", err, broken)
	}
	got := e.s.GetKRL()
	if !bytes.Equal(got.KRL, stored.KRL) || !bytes.Equal(got.Manifest, stored.Manifest) || !bytes.Equal(got.Sig, stored.Sig) {
		t.Fatal("after the failed transaction GetKRL does not serve the stored KRL state")
	}
}

// TestGetKRLDoesNotWaitForMu (pre-merge review): GET /api/v1/krl is
// unauthenticated and makes one signer call per request, so GetKRL must
// not wait for s.mu, which Issue, Login and Revoke hold across CA signing
// and their transaction; otherwise a burst of KRL reads holds every
// connection slot and the accept loop refuses the authenticated calls.
func TestGetKRLDoesNotWaitForMu(t *testing.T) {
	e := newRevokeEnv(t, 1, 1, testInstallationID)
	e.revoked(e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
	e.s.mu.Lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			unlocked = true
			e.s.mu.Unlock()
		}
	}
	defer unlock()
	done := make(chan *wire.GetKRLResponse, 1)
	go func() { done <- e.s.GetKRL() }()
	select {
	case got := <-done:
		if len(got.KRL) == 0 {
			t.Fatal("GetKRL served no KRL")
		}
	case <-time.After(5 * time.Second):
		unlock()
		<-done
		t.Fatal("GetKRL waited for s.mu")
	}
}

// tickingClock is a settable signer clock that, while tick is set, moves one
// microsecond per read, so serials (allocated from the clock) progress
// while the time stays where a test put it.
type tickingClock struct {
	mu   sync.Mutex
	now  time.Time
	tick bool
}

func (c *tickingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tick {
		c.now = c.now.Add(time.Microsecond)
	}
	return c.now
}

func (c *tickingClock) set(t time.Time, tick bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now, c.tick = t, tick
}

// subjectEnv is a signer whose genesis bundle has an installation ID and
// whose policy names the login RP, with a directory in which alice and bob
// are active, on a tickingClock.
type subjectEnv struct {
	*logEnv
	pk    *passkeys
	clock *tickingClock
}

// subjectDirectory is directory version with prev: alice and bob with the
// given statuses, role ops granting loginPrincipals to both for up to
// 3600 s, bound to testInstallationID (the bundle's, D-04).
func subjectDirectory(pk *passkeys, version uint64, prev, aliceStatus, bobStatus string) *directory.Directory {
	d := &directory.Directory{
		Version:        version,
		Prev:           prev,
		InstallationID: testInstallationID,
		Users: []directory.User{
			{Name: "alice", Status: aliceStatus, Credentials: []directory.Credential{boundCredential(pk.eddsa)}},
			{Name: "bob", Status: bobStatus, Credentials: []directory.Credential{boundCredential(pk.bob)}},
		},
		Roles: []directory.Role{{Name: "ops", Principals: loginPrincipals, MaxTTLSeconds: 3600, Extensions: []string{"permit-pty"},
			Users: []string{"alice", "bob"}}},
	}
	d.Sort()
	return d
}

func newSubjectEnv(t *testing.T) *subjectEnv {
	t.Helper()
	fx := NewFixture(t, 1, 1)
	fx.InstallationID = testInstallationID
	fx.PolicyEdit = func(p *trust.Policy) {
		p.WebAuthn = &trust.WebAuthnRP{RPID: loginRP, Origins: []string{loginOrigin}}
	}
	clock := &tickingClock{now: time.Unix(time.Now().Unix(), 0), tick: true}
	e := &subjectEnv{logEnv: newLogEnvClock(t, fx, clock.Now), pk: newPasskeys(t), clock: clock}
	doc, sigs := signDirectory(t, subjectDirectory(e.pk, 1, trust.GenesisPrev, directory.StatusActive, directory.StatusActive), fx.Admins[0])
	e.installDirectory(t, doc, sigs)
	return e
}

// login issues a login certificate to user (alice or bob) through
// LoginIssue.
func (e *subjectEnv) login(t *testing.T, user string) *ssh.Certificate {
	t.Helper()
	auth := e.pk.eddsa
	if user == "bob" {
		auth = e.pk.bob
	}
	return e.mustLogin(t, approve(t, auth, e.loginReq(t, user), nil))
}

// subjectRequest is a subject revocation of the user subject, created now
// on the signer's clock and signed by the fixture's admin.
func (e *subjectEnv) subjectRequest(t *testing.T, subject string) *wire.RevokeRequest {
	t.Helper()
	req := &wire.RevokeRequest{InstallationID: e.fx.InstallationID, Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: subject,
		CreatedAt: uint64(e.clock.Now().Unix()), Reason: "test"} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, e.fx.Admins[0], wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	return req
}

// revoke runs req through revokeOrRefuse and requires success.
func (e *subjectEnv) revoke(t *testing.T, req *wire.RevokeRequest) *wire.RevokeResponse {
	t.Helper()
	resp, er := e.s.revokeOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		t.Fatalf("revoke refused: %s", er.Message)
	}
	return resp
}

// keygenOracle returns ssh-keygen, the KRL oracle, as internal/krl's
// oracle tests find it: skipped when missing, unless
// KEYROSTER_REQUIRE_ORACLE=1, where a missing oracle fails.
func keygenOracle(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("KEYROSTER_REQUIRE_ORACLE") == "1" {
			t.Fatalf("ssh-keygen not found and KEYROSTER_REQUIRE_ORACLE=1: %v", err)
		}
		t.Skipf("ssh-keygen not found (set KEYROSTER_REQUIRE_ORACLE=1 to fail instead): %v", err)
	}
	return p
}

// keygenRevoked writes data as a KRL file and c as a certificate file and
// reports whether ssh-keygen -Q -f refuses c (a non-zero exit that says
// REVOKED).
func keygenRevoked(t *testing.T, keygen string, data []byte, c *ssh.Certificate) bool {
	t.Helper()
	dir := t.TempDir()
	krlFile, certFile := filepath.Join(dir, "revoked.krl"), filepath.Join(dir, "id-cert.pub")
	if err := os.WriteFile(krlFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, ssh.MarshalAuthorizedKey(c), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(keygen, "-Q", "-f", krlFile, certFile).CombinedOutput() //nolint:gosec // G204: test oracle
	if err == nil {
		t.Logf("ssh-keygen -Q, serial %d: %s", c.Serial, strings.TrimSpace(string(out)))
		return false
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || !strings.Contains(string(out), "REVOKED") {
		t.Fatalf("ssh-keygen -Q: %v\n%s", err, out)
	}
	t.Logf("ssh-keygen -Q, serial %d (exit %d): %s", c.Serial, ee.ExitCode(), strings.TrimSpace(string(out)))
	return true
}

// TestRevokeSubjectTracer (03-03 Task 1, D-09): on a real signer with a
// software CA, alice holds two login certificates and bob one. A subject
// revocation of alice resolves both of hers in the signer and answers
// their serials; the KRL it publishes makes ssh-keygen -Q refuse both of
// alice's certificates and accept bob's; and audit verify, re-deriving the
// revoke entry and the KRL from the exported log, passes and counts one
// revocation with two entries.
func TestRevokeSubjectTracer(t *testing.T) {
	keygen := keygenOracle(t)
	e := newSubjectEnv(t)
	a1, a2 := e.login(t, "alice"), e.login(t, "alice")
	b := e.login(t, "bob")
	before := len(e.leavesOf())
	resp := e.revoke(t, e.subjectRequest(t, "alice"))
	if resp.SerialCount != 2 || !slices.Equal(resp.Serials, []uint64{a1.Serial, a2.Serial}) {
		t.Fatalf("answer %+v, want SerialCount 2 and the serials of alice %d, %d", resp, a1.Serial, a2.Serial)
	}
	leaves := e.leavesOf()[before:]
	if len(leaves) != 2 || leaves[0].Kind != tlog.KindRevoke || leaves[1].Kind != tlog.KindKRLPublish ||
		resp.RevokeLeaf != leaves[0].Index || resp.PublishLeaf != leaves[1].Index {
		t.Fatalf("leaves after the subject revoke: %+v (answer %+v), want one revoke then one krl_publish", leaves, resp)
	}
	rb, err := tlog.DecodeRevokeBody(leaves[0].Body)
	if err != nil || len(rb.Entries) != 2 {
		t.Fatalf("revoke body: %+v, %v", rb, err)
	}
	userCA := e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()
	for i, c := range []*ssh.Certificate{a1, a2} {
		if en := rb.Entries[i]; en.Kind != tlog.RevokedSerial || en.Serial != c.Serial || !bytes.Equal(en.CAKey, userCA) || en.ValidBeforeSeconds != c.ValidBefore {
			t.Fatalf("entry %d: %+v, want serial %d under the user CA, valid before %d", i, en, c.Serial, c.ValidBefore)
		}
	}
	got := e.s.GetKRL()
	if _, err := krl.VerifyManifest(got.Manifest, got.Sig, got.KRL, e.bundleOf(t), testInstallationID, 0); err != nil {
		t.Fatalf("published KRL: %v", err)
	}
	for _, c := range []*ssh.Certificate{a1, a2} {
		if !keygenRevoked(t, keygen, got.KRL, c) {
			t.Errorf("ssh-keygen -Q accepts the certificate %d of alice", c.Serial)
		}
	}
	if keygenRevoked(t, keygen, got.KRL, b) {
		t.Errorf("ssh-keygen -Q refuses the certificate %d of bob", b.Serial)
	}
	// Read back with krl.Parse (Task 2): both of alice's serials under the
	// user CA key, none of bob's.
	p, err := krl.Parse(got.KRL)
	if err != nil {
		t.Fatalf("krl.Parse of the published KRL: %v", err)
	}
	if !p.RevokesSerial(userCA, a1.Serial) || !p.RevokesSerial(userCA, a2.Serial) || p.RevokesSerial(userCA, b.Serial) ||
		len(p.Certs) != 1 || !bytes.Equal(p.Certs[0].CAKey, userCA) {
		t.Fatalf("krl.Parse of the published KRL: %+v; want the two serials of alice under the user CA key and none of bob", p.Certs)
	}
	rep := e.verifyExport()
	if rep.Counts[tlog.KindRevoke] != 1 || rep.Revocations != 1 || rep.RevokedEntries != 2 ||
		uint64(rep.KRLPublishes) != rep.Counts[tlog.KindKRLPublish] || rep.KRLPublishes < 1 { //nolint:gosec // G115: a count
		t.Fatalf("audit report: %d revoke entries, %d revocations, %d revoked entries, %d KRL publishes (%d krl_publish entries); want 1, 1, 2 and at least 1",
			rep.Counts[tlog.KindRevoke], rep.Revocations, rep.RevokedEntries, rep.KRLPublishes, rep.Counts[tlog.KindKRLPublish])
	}
	t.Logf("audit verify: %d entries, %d revocation with %d entries, %d KRL publishes, KRL v%d", rep.Size, rep.Revocations, rep.RevokedEntries, rep.KRLPublishes, rep.KRLVersion)
}

// bundleOf returns the installed trust bundle.
func (e *logEnv) bundleOf(t *testing.T) *trust.Bundle {
	t.Helper()
	stored, err := e.db.LatestBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(stored.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signedRevoke completes req (CreatedAt now on the signer's clock, a fresh
// request ID) and signs it with the fixture's admin.
func (e *subjectEnv) signedRevoke(t *testing.T, req *wire.RevokeRequest) *wire.RevokeRequest {
	t.Helper()
	req.CreatedAt = uint64(e.clock.Now().Unix()) //nolint:gosec // G115: after 1970
	if req.InstallationID == "" {
		req.InstallationID = e.fx.InstallationID
	}
	if req.Reason == "" {
		req.Reason = "test"
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, e.fx.Admins[0], wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	return req
}

// refused runs req through revokeOrRefuse and requires the refusal
// detail, with one refusal leaf and no revocation row added.
func (e *subjectEnv) refused(t *testing.T, req *wire.RevokeRequest, detail string) {
	t.Helper()
	re := &revokeEnv{logEnv: e.logEnv}
	defer re.use(t)()
	re.refusedRevoke(req, detail)
}

// parsedKRL parses the KRL the signer serves.
func (e *logEnv) parsedKRL(t *testing.T) *krl.Parsed {
	t.Helper()
	p, err := krl.Parse(e.s.GetKRL().KRL)
	if err != nil {
		t.Fatalf("krl.Parse of the served KRL: %v", err)
	}
	return p
}

// revokeEntries returns the entries of the revoke leaf at index idx.
func (e *logEnv) revokeEntries(t *testing.T, idx uint64) []tlog.RevokedEntry {
	t.Helper()
	l := e.leavesOf()[idx]
	if l.Kind != tlog.KindRevoke {
		t.Fatalf("leaf %d is %s, want a revoke leaf", idx, l.Kind)
	}
	b, err := tlog.DecodeRevokeBody(l.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b.Entries
}

func serialsOf(entries []tlog.RevokedEntry) []uint64 {
	out := make([]uint64, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Serial)
	}
	return out
}

// TestSubjectResolutionTime (F9, T-03-202, T-03-203): a subject revocation
// resolves at T = the clock reading in whole seconds, and a certificate is
// live while ValidBefore + 300 > T, in whole seconds, on both sides of a
// sub-second boundary; after a clock step back the revoke leaf's time is
// clamped, T is not, and audit verify accepts it; and a certificate issued
// under an older policy with a longer TTL cap is found.
func TestSubjectResolutionTime(t *testing.T) {
	boundary := func(t *testing.T, offset time.Duration, wantRevoked bool) {
		e := newSubjectEnv(t)
		c := e.login(t, "alice")
		end := time.Unix(int64(c.ValidBefore)+krl.PruneMargin, 0) //nolint:gosec // G115: a test time
		e.clock.set(end.Add(offset), false)
		resp := e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "alice"}))
		entries := e.revokeEntries(t, resp.RevokeLeaf)
		rb, err := tlog.DecodeRevokeBody(e.leavesOf()[resp.RevokeLeaf].Body)
		if err != nil {
			t.Fatal(err)
		}
		if want := uint64(end.Add(offset).Unix()); rb.ResolvedAtSeconds != want { //nolint:gosec // G115: a test time
			t.Fatalf("ResolvedAtSeconds %d, want the reading's whole seconds %d", rb.ResolvedAtSeconds, want)
		}
		if got := len(entries) == 1 && entries[0].Serial == c.Serial; got != wantRevoked || len(entries) > 1 {
			t.Fatalf("at E%+v the subject revocation lists %v; want the certificate revoked=%v", offset, serialsOf(entries), wantRevoked)
		}
		e.verifyExport()
	}
	t.Run("subsecond_before_boundary_live", func(t *testing.T) { boundary(t, -time.Microsecond, true) })
	t.Run("at_boundary_excluded", func(t *testing.T) { boundary(t, 0, false) })
	t.Run("subsecond_after_boundary_excluded", func(t *testing.T) { boundary(t, 999_999*time.Microsecond, false) })
	t.Run("clock_rollback", func(t *testing.T) {
		e := newSubjectEnv(t)
		c := e.login(t, "alice")
		// A leaf at L, after the certificate's E = ValidBefore + 300.
		l := time.Unix(int64(c.ValidBefore)+krl.PruneMargin+100, 0) //nolint:gosec // G115: a test time
		e.clock.set(l, true)
		e.login(t, "bob")
		all := e.leavesOf()
		last := all[len(all)-1].TimeMicros
		// The clock steps back an hour: E lies inside (L - 3600 s, L].
		back := time.UnixMicro(int64(last)).Add(-time.Hour).Truncate(time.Second) //nolint:gosec // G115: a test time
		e.clock.set(back, false)
		resp := e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "alice"}))
		leaf := e.leavesOf()[resp.RevokeLeaf]
		rb, err := tlog.DecodeRevokeBody(leaf.Body)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.TimeMicros != last || rb.ResolvedAtSeconds != uint64(back.Unix()) || !slices.Equal(serialsOf(rb.Entries), []uint64{c.Serial}) { //nolint:gosec // G115: a test time
			t.Fatalf("leaf time %d (want clamped to %d), ResolvedAtSeconds %d (want %d), entries %v (want %d)",
				leaf.TimeMicros, last, rb.ResolvedAtSeconds, back.Unix(), serialsOf(rb.Entries), c.Serial)
		}
		if krl.EntryLive(c.ValidBefore, leaf.TimeMicros/1_000_000) {
			t.Fatal("the certificate is live at the clamped leaf time too, so the case would not catch an audit that reads it")
		}
		rep := e.verifyExport()
		t.Logf("audit verify accepts the revocation resolved at %d s under a leaf clamped to %d µs: %d revocation, %d entries", rb.ResolvedAtSeconds, leaf.TimeMicros, rep.Revocations, rep.RevokedEntries)
	})
	t.Run("older_longer_cap_found", func(t *testing.T) {
		fx := NewFixture(t, 1, 1)
		fx.InstallationID = testInstallationID
		fx.PolicyEdit = func(p *trust.Policy) { p.CAProfiles[0].MaxTTLSeconds = 24 * 3600 }
		clock := &tickingClock{now: time.Unix(time.Now().Unix(), 0), tick: true}
		e := &subjectEnv{logEnv: newLogEnvClock(t, fx, clock.Now), clock: clock}
		req := &wire.IssueRequest{CARole: wire.CARoleUser, SubjectKey: newEd25519(t).PublicKey().Marshal(), Subject: "alice",
			Principals: []string{"alice"}, ValidForSeconds: 24 * 3600, CreatedAt: uint64(clock.Now().Unix())} //nolint:gosec // G115: after 1970
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		req.Evidence = SignRequest(t, req, fx.Admins...)
		issued, err := e.s.Issue(context.Background(), Peer{UID: 1000}, req)
		if err != nil {
			t.Fatal(err)
		}
		// A successor policy cuts the user cap to 8 h.
		e.restartUnderPolicy(t, func(*trust.Policy) {})
		if e.s.profiles[wire.CARoleUser].MaxTTL != 8*time.Hour {
			t.Fatalf("user cap under the successor policy %v, want 8h", e.s.profiles[wire.CARoleUser].MaxTTL)
		}
		clock.set(clock.Now().Add(20*time.Hour), false)
		resp := e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "alice"}))
		if !slices.Equal(resp.Serials, []uint64{issued.Serial}) {
			t.Fatalf("20 h later the subject revocation lists %v, want the 24 h certificate %d", resp.Serials, issued.Serial)
		}
		e.verifyExport()
	})
}

// TestRevokeSubject (D-09, REVOKE-01): the subject, key-ID and key targets
// on a real signer, their refusals, the entry cap split, re-listing, and
// the second sweep after a login between the revoke and the disable.
func TestRevokeSubject(t *testing.T) {
	subject := func(name string) *wire.RevokeRequest {
		return &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: name}
	}
	t.Run("revoke_user_login_between_revoke_and_disable", func(t *testing.T) {
		e := newSubjectEnv(t)
		a1 := e.login(t, "alice")
		first := e.revoke(t, e.signedRevoke(t, subject("alice")))
		if !slices.Equal(first.Serials, []uint64{a1.Serial}) {
			t.Fatalf("first sweep %v, want %d", first.Serials, a1.Serial)
		}
		// The directory still has alice active: a login between the
		// revoke and the disable is issued.
		a2 := e.login(t, "alice")
		doc1, err := subjectDirectory(e.pk, 1, trust.GenesisPrev, directory.StatusActive, directory.StatusActive).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		doc, sigs := signDirectory(t, subjectDirectory(e.pk, 2, trust.SHA256Hex(doc1), directory.StatusDisabled, directory.StatusActive), e.fx.Admins[0])
		e.installDirectory(t, doc, sigs)
		e.refuseLogin(t, approve(t, e.pk.eddsa, e.loginReq(t, "alice"), nil), "user_disabled")
		second := e.revoke(t, e.signedRevoke(t, subject("alice")))
		if !slices.Equal(second.Serials, []uint64{a1.Serial, a2.Serial}) || second.SerialCount != 2 {
			t.Fatalf("second sweep %+v, want the first sweep's %d and the interleaved %d", second, a1.Serial, a2.Serial)
		}
		p := e.parsedKRL(t)
		userCA := e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()
		if len(p.Certs) != 1 || !slices.Equal(p.Certs[0].Serials, []krl.SerialRange{{Lo: a1.Serial, Hi: a1.Serial}, {Lo: a2.Serial, Hi: a2.Serial}}) || !bytes.Equal(p.Certs[0].CAKey, userCA) {
			t.Fatalf("KRL after the second sweep: %+v, want each serial once under the user CA", p.Certs)
		}
		rep := e.verifyExport()
		if rep.Revocations != 2 || rep.RevokedEntries != 3 {
			t.Fatalf("audit: %d revocations, %d entries; want 2 and 3", rep.Revocations, rep.RevokedEntries)
		}
	})
	t.Run("revoke_user_second_sweep_relists", func(t *testing.T) {
		e := newSubjectEnv(t)
		a1, a2 := e.login(t, "alice"), e.login(t, "alice")
		r1 := e.revoke(t, e.signedRevoke(t, subject("alice")))
		r2 := e.revoke(t, e.signedRevoke(t, subject("alice")))
		want := []uint64{a1.Serial, a2.Serial}
		if !slices.Equal(serialsOf(e.revokeEntries(t, r1.RevokeLeaf)), want) || !slices.Equal(serialsOf(e.revokeEntries(t, r2.RevokeLeaf)), want) {
			t.Fatal("the two sweeps do not both list both certificates")
		}
		if n := e.countRevocations(t); n != 4 {
			t.Fatalf("%d revocation rows, want 4 (one per entry of each sweep)", n)
		}
		p := e.parsedKRL(t)
		if len(p.Certs) != 1 || !slices.Equal(p.Certs[0].Serials, []krl.SerialRange{{Lo: a1.Serial, Hi: a1.Serial}, {Lo: a2.Serial, Hi: a2.Serial}}) {
			t.Fatalf("KRL: %+v, want each serial once", p.Certs)
		}
		e.verifyExport()
	})
	t.Run("subject_kind_unsupported", func(t *testing.T) {
		e := newSubjectEnv(t)
		for _, kind := range []wire.SubjectKind{wire.SubjectHost, wire.SubjectMachine} {
			e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: kind, Subject: "web1"}), "subject_kind_unsupported")
		}
	})
	t.Run("key_is_ca_of_this_installation", func(t *testing.T) {
		e := newSubjectEnv(t)
		for _, role := range []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog} {
			e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: e.fx.Roles[role].PublicKey().Marshal()}), "key_is_ca_of_this_installation")
		}
		e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: e.fx.Root.PublicKey().Marshal()}), "key_is_ca_of_this_installation")
	})
	t.Run("malformed_targets_refused", func(t *testing.T) {
		e := newSubjectEnv(t)
		c := e.login(t, "alice")
		for name, req := range map[string]*wire.RevokeRequest{
			"empty_key_id":       {Target: wire.TargetKeyID, CARole: wire.CARoleUser},
			"certificate_as_key": {Target: wire.TargetKey, Key: c.Marshal()},
			"unknown_target":     {Target: 9},
			"subject_with_slash": {Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "alice/x"},
		} {
			t.Run(name, func(t *testing.T) { e.refused(t, e.signedRevoke(t, req), "malformed_request") })
		}
	})
	t.Run("empty_live_set_recorded", func(t *testing.T) {
		e := newSubjectEnv(t)
		req := e.signedRevoke(t, subject("carol"))
		resp := e.revoke(t, req)
		if resp.SerialCount != 0 || len(resp.Serials) != 0 || len(e.revokeEntries(t, resp.RevokeLeaf)) != 0 {
			t.Fatalf("answer %+v, want a revoke leaf with no entries", resp)
		}
		if used, err := e.db.RevokeRequestUsed(context.Background(), req.RequestID); err != nil || !used {
			t.Fatalf("the request ID is not recorded: %v, %v", used, err)
		}
		e.refused(t, req, "duplicate_request")
		e.verifyExport()
	})
	t.Run("revoke_by_key_id", func(t *testing.T) {
		e := newSubjectEnv(t)
		c := e.login(t, "alice")
		resp := e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: c.KeyId}))
		entries := e.revokeEntries(t, resp.RevokeLeaf)
		userCA := e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()
		if len(entries) != 1 || entries[0].Kind != tlog.RevokedKeyID || entries[0].KeyID != c.KeyId || !bytes.Equal(entries[0].CAKey, userCA) ||
			entries[0].ValidBeforeSeconds != c.ValidBefore || resp.SerialCount != 0 {
			t.Fatalf("key-ID revoke entries %+v (answer %+v), want the key ID under the user CA with the certificate's ValidBefore", entries, resp)
		}
		if p := e.parsedKRL(t); !p.RevokesKeyID(userCA, c.KeyId) {
			t.Fatalf("the KRL does not revoke the key ID: %+v", p)
		}
		e.verifyExport()
	})
	t.Run("revoke_by_key", func(t *testing.T) {
		e := newSubjectEnv(t)
		key := newEd25519(t).PublicKey().Marshal()
		resp := e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: key}))
		if entries := e.revokeEntries(t, resp.RevokeLeaf); len(entries) != 1 || entries[0].Kind != tlog.RevokedKey || !bytes.Equal(entries[0].Key, key) {
			t.Fatalf("key revoke entries %+v", entries)
		}
		if p := e.parsedKRL(t); !p.RevokesKey(key) {
			t.Fatal("the KRL does not revoke the key")
		}
		e.verifyExport()
	})
	t.Run("key_id_not_issued_refused", func(t *testing.T) {
		// Pre-merge review of PR #61 (owner decision 2026-10-26): a key ID
		// this signer did not issue under the role's CA keys would be an
		// entry that never leaves the KRL, so it is refused; one it issued
		// under another role is refused too.
		e := newSubjectEnv(t)
		c := e.login(t, "alice")
		e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser,
			KeyID: "kr1/ca=user/sub=nobody/req=000102030405060708090a0b0c0d0e0f/pol=1/ser=1"}), "key_id_not_issued")
		e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleHost, KeyID: c.KeyId}), "key_id_not_issued")
		e.verifyExport()
	})
	t.Run("explicit_key_cap_reached", func(t *testing.T) {
		// T-03-211: explicit keys never leave the KRL, so at most
		// krl.MaxRevokedKeys distinct keys in krl.MaxRevokedKeyBytes. The
		// keys at the cap are written as rows directly: the cap is checked
		// against the rows before anything is logged or published.
		for name, keys := range map[string]func(t *testing.T) [][]byte{
			"count": func(t *testing.T) [][]byte {
				out := make([][]byte, krl.MaxRevokedKeys)
				for i := range out {
					out[i] = newEd25519(t).PublicKey().Marshal()
				}
				return out
			},
			"bytes": func(t *testing.T) [][]byte {
				out := make([][]byte, krl.MaxRevokedKeyBytes/8004)
				for i := range out {
					out[i] = bigSKKey(t, 8000)
				}
				return out
			},
		} {
			t.Run(name, func(t *testing.T) {
				e := newSubjectEnv(t)
				full := keys(t)
				if err := krl.CheckExplicitKeys(full); err != nil {
					t.Fatalf("the keys at the cap: %v", err)
				}
				if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
					for _, k := range full {
						if err := e.db.InsertRevocation(tx, signerdb.Revocation{Kind: signerdb.RevocationKey, Key: k, RevokedAt: time.Now()}); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				next := bigSKKey(t, 8000)
				if name == "count" {
					next = newEd25519(t).PublicKey().Marshal()
				}
				e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: next}), "explicit_key_cap_reached")
			})
		}
	})
	t.Run("explicit_key_cap_relist_accepted", func(t *testing.T) {
		// A key already revoked adds nothing to the cap, so revoking it
		// again at the cap is accepted and it stays listed (03-03b
		// carry-over from the PR #61 fix check). The keys at the cap are
		// logged in one revoke leaf with their rows and published, as
		// MaxRevokedKeys revocations would leave them: the publish check
		// refuses rows the log does not hold (revocations_not_logged).
		e := newSubjectEnv(t)
		ctx := context.Background()
		entries := make([]tlog.RevokedEntry, krl.MaxRevokedKeys)
		for i := range entries {
			entries[i] = tlog.RevokedEntry{Kind: tlog.RevokedKey, Key: newEd25519(t).PublicKey().Marshal()}
		}
		body, err := (&tlog.RevokeBody{Request: []byte("r"), Entries: entries}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		now := e.clock.Now()
		e.s.mu.Lock()
		err = e.s.logTx(ctx, func(tx *sql.Tx) error {
			idx, err := e.s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindRevoke, Body: body})
			if err != nil {
				return err
			}
			for _, en := range entries {
				if err := e.db.InsertRevocation(tx, revocationRow(en, [16]byte{2}, idx, now)); err != nil {
					return err
				}
			}
			st, _, err := e.s.publishKRLLocked(ctx, tx, now)
			if err == nil {
				e.s.krl.Store(st)
			}
			return err
		})
		e.s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: newEd25519(t).PublicKey().Marshal()}), "explicit_key_cap_reached")
		e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: entries[0].Key}))
		if p := e.parsedKRL(t); !p.RevokesKey(entries[0].Key) || len(p.Keys) != krl.MaxRevokedKeys {
			t.Fatalf("the KRL after revoking a revoked key again at the cap lists %d keys, want the %d with it", len(p.Keys), krl.MaxRevokedKeys)
		}
	})
	t.Run("valid_before_beyond_row_range_kept", func(t *testing.T) {
		// No signer issues a certificate valid until ssh.CertTimeInfinity,
		// so this logs one serial entry with that ValidBefore directly, as
		// a revocation would, and its row with valid_before NULL
		// (validBeforeMicros), then publishes.
		e := newSubjectEnv(t)
		ctx := context.Background()
		caKey := e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()
		entry := tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: caKey, Serial: 77, ValidBeforeSeconds: ssh.CertTimeInfinity}
		body, err := (&tlog.RevokeBody{Request: []byte("r"), Entries: []tlog.RevokedEntry{entry}}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		now := e.clock.Now()
		e.s.mu.Lock()
		err = e.s.logTx(ctx, func(tx *sql.Tx) error {
			idx, err := e.s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindRevoke, Body: body})
			if err != nil {
				return err
			}
			if err := e.db.InsertRevocation(tx, revocationRow(entry, [16]byte{1}, idx, now)); err != nil {
				return err
			}
			st, _, err := e.s.publishKRLLocked(ctx, tx, now)
			if err == nil {
				e.s.krl.Store(st)
			}
			return err
		})
		e.s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		revs := e.revocationRows(t)
		if len(revs) != 1 || revs[0].ValidBeforeMicros != 0 {
			t.Fatalf("revocation rows %+v, want one with valid_before NULL", revs)
		}
		for _, at := range []time.Time{now, now.Add(100 * 365 * 24 * time.Hour)} {
			e.clock.set(at, false)
			if !at.Equal(now) && !e.s.republishIfDue(ctx) {
				t.Fatal("no re-publish")
			}
			if p := e.parsedKRL(t); !p.RevokesSerial(caKey, 77) {
				t.Fatalf("the serial left the KRL at %v", at)
			}
			// Audit builds its set from the leaf's ValidBefore, the signer
			// from the row's NULL: the same KRL at any realistic time.
			issued := uint64(at.Unix()) //nolint:gosec // G115: a test time
			fromLeaf, err := krl.PublishSet([]krl.Entry{{Kind: krl.EntrySerial, CAKey: caKey, Serial: 77, ValidBefore: ssh.CertTimeInfinity}}, issued)
			if err != nil {
				t.Fatal(err)
			}
			fromRow, err := krl.PublishSet(revocationEntries(revs), issued)
			if err != nil {
				t.Fatal(err)
			}
			a, _ := krl.Encode(fromLeaf, 1, at)
			b, _ := krl.Encode(fromRow, 1, at)
			if !bytes.Equal(a, b) {
				t.Fatalf("the leaf (audit) and the row (signer) give different KRLs at %v", at)
			}
		}
	})
	t.Run("revoke_user_over_entry_cap", func(t *testing.T) {
		if testing.Short() {
			t.Skip("issues 4097 login certificates")
		}
		e := newSubjectEnv(t)
		var serials []uint64
		for range tlog.MaxRevokedEntries + 1 {
			serials = append(serials, e.login(t, "alice").Serial)
		}
		req := e.signedRevoke(t, subject("alice"))
		before := len(e.leavesOf())
		resp := e.revoke(t, req)
		leaves := e.leavesOf()[before:]
		if len(leaves) != 3 || leaves[0].Kind != tlog.KindRevoke || leaves[1].Kind != tlog.KindRevoke || leaves[2].Kind != tlog.KindKRLPublish ||
			resp.RevokeLeaf != leaves[1].Index || resp.PublishLeaf != leaves[2].Index {
			t.Fatalf("leaves %v (answer %+v), want two revoke leaves then one krl_publish", leaves, resp)
		}
		got := append(serialsOf(e.revokeEntries(t, leaves[0].Index)), serialsOf(e.revokeEntries(t, leaves[1].Index))...)
		if n := len(e.revokeEntries(t, leaves[0].Index)); n != tlog.MaxRevokedEntries || !slices.Equal(got, serials) {
			t.Fatalf("the first leaf lists %d entries and both %d, want %d and every serial ascending", n, len(got), tlog.MaxRevokedEntries)
		}
		if resp.SerialCount != tlog.MaxRevokedEntries+1 || !slices.Equal(resp.Serials, serials[:wire.MaxRevokeAnswerSerials]) {
			t.Fatalf("answer: SerialCount %d, %d serials; want 4097 and the first 4096", resp.SerialCount, len(resp.Serials))
		}
		e.refused(t, req, "duplicate_request")
		rep := e.verifyExport()
		if rep.Revocations != 1 || rep.RevokedEntries != tlog.MaxRevokedEntries+1 {
			t.Fatalf("audit: %d revocations, %d entries", rep.Revocations, rep.RevokedEntries)
		}
	})
}

func (e *logEnv) countRevocations(t *testing.T) int {
	t.Helper()
	return len(e.revocationRows(t))
}

func (e *logEnv) revocationRows(t *testing.T) []signerdb.Revocation {
	t.Helper()
	var revs []signerdb.Revocation
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		revs, err = e.db.RevocationsTx(context.Background(), tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return revs
}

// TestPublishNeverDropsLiveEntry (T-03-14, the shared contract with 03-05's
// KRL_M = KRL_B): over serial, key-ID (a key ID without an issuance row
// is refused, key_id_not_issued), key and subject revocations, forced
// re-publishes and clock steps forward and back, every entry missing from
// a published KRL version is prunable at that version's issued_at
// (krl.Prunable over every row of it), and no explicit key ever leaves.
func TestPublishNeverDropsLiveEntry(t *testing.T) {
	e := newSubjectEnv(t)
	ctx := context.Background()
	var versions []*krl.Parsed
	record := func() {
		t.Helper()
		p := e.parsedKRL(t)
		if n := len(versions); n == 0 || versions[n-1].Version != p.Version {
			versions = append(versions, p)
		}
	}
	unknownID := "kr1/ca=user/sub=nobody/req=000102030405060708090a0b0c0d0e0f/pol=1/ser=1"
	keyA, keyB := newEd25519(t).PublicKey().Marshal(), newEd25519(t).PublicKey().Marshal()
	a1, a2, b := e.login(t, "alice"), e.login(t, "alice"), e.login(t, "bob")
	steps := []func(){
		func() {
			e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: a1.Serial}))
		},
		func() {
			e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: a2.KeyId}))
		},
		func() {
			// Refused since the pre-merge review of PR #61: it would never leave.
			e.refused(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: unknownID}), "key_id_not_issued")
		},
		func() { e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: keyA})) },
		func() {
			e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "bob"}))
		},
		func() { e.clock.set(e.clock.Now().Add(30*time.Minute), false); e.s.republishIfDue(ctx) }, // under an hour: nothing
		func() { e.clock.set(e.clock.Now().Add(2*time.Hour), false); e.s.republishIfDue(ctx) },    // prunes the expired certificates
		func() {
			// The clock steps back three hours; a revocation then publishes
			// at the earlier issued_at.
			e.clock.set(e.clock.Now().Add(-3*time.Hour), false)
			e.revoke(t, e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: keyB}))
		},
		func() { e.clock.set(e.clock.Now().Add(5*time.Hour), false); e.s.republishIfDue(ctx) },
	}
	for _, step := range steps {
		step()
		record()
	}
	if len(versions) < 7 {
		t.Fatalf("%d KRL versions published, want at least 7", len(versions))
	}
	revs := e.revocationRows(t)
	userCA := e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()
	prunable := func(match func(r signerdb.Revocation) bool, at uint64) bool {
		n := 0
		for _, r := range revs {
			if match(r) {
				n++
				if !krl.Prunable(r.ValidBeforeMicros/1_000_000, at) {
					return false
				}
			}
		}
		return n > 0
	}
	for i := 1; i < len(versions); i++ {
		prev, next := versions[i-1], versions[i]
		at := next.GeneratedDate // issued_at in whole seconds
		for _, sec := range prev.Certs {
			for _, r := range sec.Serials {
				for s := r.Lo; s <= r.Hi; s++ {
					if next.RevokesSerial(sec.CAKey, s) {
						continue
					}
					if !prunable(func(row signerdb.Revocation) bool {
						return row.Kind == signerdb.RevocationSerial && row.Serial == s && bytes.Equal(row.CAKey, sec.CAKey)
					}, at) {
						t.Fatalf("version %d drops serial %d, which is not prunable at its issued_at %d", next.Version, s, at)
					}
				}
			}
			for _, id := range sec.KeyIDs {
				if next.RevokesKeyID(sec.CAKey, id) {
					continue
				}
				if !prunable(func(row signerdb.Revocation) bool {
					return row.Kind == signerdb.RevocationKeyID && row.KeyID == id && bytes.Equal(row.CAKey, sec.CAKey)
				}, at) {
					t.Fatalf("version %d drops key ID %q, which is not prunable at its issued_at %d", next.Version, id, at)
				}
			}
		}
		for _, k := range prev.Keys {
			if !next.RevokesKey(k) {
				t.Fatalf("version %d drops an explicit key", next.Version)
			}
		}
		if next.Version <= prev.Version {
			t.Fatalf("version %d after %d", next.Version, prev.Version)
		}
	}
	last := versions[len(versions)-1]
	if last.RevokesKeyID(userCA, unknownID) || !last.RevokesKey(keyA) || !last.RevokesKey(keyB) || last.RevokesSerial(userCA, b.Serial) {
		t.Fatalf("the last version: %+v; want both keys, no refused key ID, and the expired subject entry pruned", last)
	}
	pruned := false
	for i := 1; i < len(versions); i++ {
		if versions[i-1].RevokesSerial(userCA, a1.Serial) && !versions[i].RevokesSerial(userCA, a1.Serial) {
			pruned = true
		}
	}
	if !pruned {
		t.Fatal("no version pruned an expired entry, so the property was not exercised")
	}
	t.Logf("%d KRL versions checked pairwise", len(versions))
	e.verifyExport()
}
