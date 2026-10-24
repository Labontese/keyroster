package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

const testInstallationID = "0123456789abcdef0123456789abcdef"

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
	req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: role, Serial: serial, CreatedAt: uint64(e.clock.Now().Unix()), Reason: "test"} //nolint:gosec // G115: after 1970
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
		if resp.KRLVersion != 1 {
			t.Fatalf("KRL version %d, want 1", resp.KRLVersion)
		}
		body, err := tlog.DecodeRevokeBody(leaves[0].Body)
		if err != nil || len(body.Entries) != 1 || body.Entries[0].Serial != e.serial || body.Entries[0].Kind != tlog.RevokedSerial ||
			!bytes.Equal(body.Entries[0].CAKey, e.fx.Roles["user"].PublicKey().Marshal()) || body.Entries[0].ValidBeforeSeconds == 0 {
			t.Fatalf("revoke body %+v, %v", body, err)
		}
		// A second revocation publishes version 2 over both entries. The
		// serial is time-based, so the frozen clock moves on first.
		e.clock.set(e.clock.Now().Add(time.Second))
		other, err := e.issue()
		if err != nil {
			t.Fatal(err)
		}
		if resp2, _ := e.revoked(e.revokeRequest(other.Serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[1]), 1); resp2.KRLVersion != 2 {
			t.Fatalf("second KRL version %d, want 2", resp2.KRLVersion)
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
