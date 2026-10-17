package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// wantDirectory requires GetDirectory to report version with exactly doc
// and sigs, and authorized.
func (e *logEnv) wantDirectory(t *testing.T, version uint64, doc, sigs []byte, authorized bool) {
	t.Helper()
	got := e.s.GetDirectory()
	if got.Version != version || !bytes.Equal(got.Directory, doc) || !bytes.Equal(got.Sigs, sigs) || got.Authorized != authorized {
		t.Fatalf("GetDirectory = version %d, directory equal %v, signatures equal %v, authorized %v; want %d, true, true, %v",
			got.Version, bytes.Equal(got.Directory, doc), bytes.Equal(got.Sigs, sigs), got.Authorized, version, authorized)
	}
}

// refuseInstall runs req through the signer's dispatch path
// (installDirectoryOrRefuse) and requires the refusal detail, the
// installed directory unchanged (in memory and stored), and exactly one
// new leaf: a refusal with detail, its class (never internal) and the
// SHA-256 of the refused document, so no directory_install leaf.
func (e *logEnv) refuseInstall(t *testing.T, req *wire.InstallDirectoryRequest, detail string) {
	t.Helper()
	class := classify(detail)
	if class == tlog.ReasonInternal {
		t.Fatalf("classify(%q) is internal", detail)
	}
	before := e.s.GetDirectory()
	storedBefore, err := e.db.LatestDirectory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	leavesBefore := len(e.leavesOf())
	resp, er := e.s.installDirectoryOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if resp != nil || er == nil || er.Message != detail {
		t.Fatalf("install: %+v, %+v; want the refusal %s", resp, er, detail)
	}
	e.wantDirectory(t, before.Version, before.Directory, before.Sigs, before.Authorized)
	stored, err := e.db.LatestDirectory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if (stored == nil) != (storedBefore == nil) || stored != nil && (stored.Version != storedBefore.Version || !bytes.Equal(stored.Doc, storedBefore.Doc)) {
		t.Fatalf("the stored directory changed after the refusal %s", detail)
	}
	leaves := e.leavesOf()
	if len(leaves) != leavesBefore+1 || leaves[leavesBefore].Kind != tlog.KindRefusal {
		t.Fatalf("%d new leaves after the refusal, want exactly one refusal leaf", len(leaves)-leavesBefore)
	}
	b, err := tlog.DecodeRefusalBody(leaves[leavesBefore].Body)
	if err != nil {
		t.Fatal(err)
	}
	if b.Reason != class || b.Detail != detail || b.RequestDigest != sha256.Sum256(req.Directory) {
		t.Fatalf("refusal leaf %s/%s, want %s/%s with the document's SHA-256", tlog.ReasonName(b.Reason), b.Detail, tlog.ReasonName(class), detail)
	}
}

// execSQL runs query on the state database at path through its own
// handle, as another process would.
func execSQL(t *testing.T, path, query string, args ...any) {
	t.Helper()
	db, err := signerdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.WithTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestDirectoryInstallRefusals (D-01): InstallDirectory refuses a document
// that does not parse canonically, does not follow the installed version,
// lacks the admin quorum of the policy in force or exceeds it, or that
// would be logged under a superseded trust bundle. Nothing is stored, no
// directory_install leaf is written, and the refusal is logged. Control:
// a valid successor installs on the same signer afterwards.
func TestDirectoryInstallRefusals(t *testing.T) {
	pk := newPasskeys(t)
	cases := []struct {
		name, detail string
		admins       int
		quorum       uint32
		request      func(t *testing.T, e *logEnv, prev string) *wire.InstallDirectoryRequest
	}{
		{"directory_invalid/non_canonical_whitespace", "directory_invalid", 1, 1, func(t *testing.T, e *logEnv, prev string) *wire.InstallDirectoryRequest {
			doc, _ := signDirectory(t, loginDirectory(pk, 2, prev))
			doc = append([]byte("{ "), doc[1:]...)
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: signDoc(t, doc, e.fx.Admins[0])}
		}},
		{"directory_invalid/unknown_field", "directory_invalid", 1, 1, func(t *testing.T, e *logEnv, prev string) *wire.InstallDirectoryRequest {
			doc, _ := signDirectory(t, loginDirectory(pk, 2, prev))
			doc = append([]byte(`{"comment":"x",`), doc[1:]...)
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: signDoc(t, doc, e.fx.Admins[0])}
		}},
		{"directory_version_chain/v3_after_v1", "directory_version_chain", 1, 1, func(t *testing.T, e *logEnv, prev string) *wire.InstallDirectoryRequest {
			doc, sigs := signDirectory(t, loginDirectory(pk, 3, prev), e.fx.Admins[0])
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}
		}},
		{"directory_version_chain/wrong_prev", "directory_version_chain", 1, 1, func(t *testing.T, e *logEnv, _ string) *wire.InstallDirectoryRequest {
			doc, sigs := signDirectory(t, loginDirectory(pk, 2, trust.SHA256Hex([]byte("another directory"))), e.fx.Admins[0])
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}
		}},
		{"directory_version_chain/reinstall_v1", "directory_version_chain", 1, 1, func(_ *testing.T, e *logEnv, _ string) *wire.InstallDirectoryRequest {
			v1 := e.s.GetDirectory()
			return &wire.InstallDirectoryRequest{Directory: v1.Directory, Sigs: v1.Sigs}
		}},
		{"directory_quorum_not_met/non_admin_signer", "directory_quorum_not_met", 1, 1, func(t *testing.T, _ *logEnv, prev string) *wire.InstallDirectoryRequest {
			_, outsider := NewEd25519Key(t)
			doc, sigs := signDirectory(t, loginDirectory(pk, 2, prev), outsider)
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}
		}},
		// Signatures are checked before the document is parsed (T-02-12):
		// a document that does not parse, signed by a non-admin, is
		// refused for its signatures, so parsing never runs under s.mu
		// for a peer the admins did not authorize.
		{"directory_quorum_not_met/unparsable_signed_by_non_admin", "directory_quorum_not_met", 1, 1, func(t *testing.T, _ *logEnv, prev string) *wire.InstallDirectoryRequest {
			_, outsider := NewEd25519Key(t)
			doc, _ := signDirectory(t, loginDirectory(pk, 2, prev))
			doc = append([]byte(`{"comment":"x",`), doc[1:]...)
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: signDoc(t, doc, outsider)}
		}},
		{"directory_quorum_not_met/same_admin_twice", "directory_quorum_not_met", 2, 2, func(t *testing.T, e *logEnv, prev string) *wire.InstallDirectoryRequest {
			doc, sigs := signDirectory(t, loginDirectory(pk, 2, prev), e.fx.Admins[0], e.fx.Admins[0])
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}
		}},
		{"directory_exceeds_policy/role_ttl_above_user_cap", "directory_exceeds_policy", 1, 1, func(t *testing.T, e *logEnv, prev string) *wire.InstallDirectoryRequest {
			d := loginDirectory(pk, 2, prev)
			d.Roles[1].MaxTTLSeconds = 12*3600 + 1 // the fixture's user CA cap is 12 h
			doc, sigs := signDirectory(t, d, e.fx.Admins[0])
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}
		}},
		{"directory_exceeds_policy/extension_not_allowed", "directory_exceeds_policy", 1, 1, func(t *testing.T, e *logEnv, prev string) *wire.InstallDirectoryRequest {
			d := loginDirectory(pk, 2, prev)
			d.Roles[1].Extensions = []string{"permit-port-forwarding", "permit-pty"}
			doc, sigs := signDirectory(t, d, e.fx.Admins[0])
			return &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t, pk, NewFixture(t, tc.admins, tc.quorum), true, true)
			prev := trust.SHA256Hex(e.s.GetDirectory().Directory)
			e.refuseInstall(t, tc.request(t, e, prev), tc.detail)
			// Control: a valid successor installs.
			doc, sigs := signDirectory(t, loginDirectory(pk, 2, prev), e.fx.Admins[:tc.quorum]...)
			e.installDirectory(t, doc, sigs)
			e.wantDirectory(t, 2, doc, sigs, true)
		})
	}

	// 02-01 deviation 2: the install re-checks the trust bundle in force
	// inside its transaction.
	t.Run("trust_changed", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		prev := trust.SHA256Hex(e.s.GetDirectory().Directory)
		other, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		installSuccessor(t, e, other)
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
		doc, sigs := signDirectory(t, loginDirectory(pk, 2, prev), e.fx.Admins[0])
		before := e.s.GetDirectory()
		leaves := len(e.leavesOf())
		resp, er := e.s.installDirectoryOrRefuse(context.Background(), Peer{UID: 1000}, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs})
		if resp != nil || er == nil || er.Message != "trust_changed" {
			t.Fatalf("install under a superseded bundle: %+v, %+v; want trust_changed", resp, er)
		}
		e.wantDirectory(t, before.Version, before.Directory, before.Sigs, true)
		if n := len(e.leavesOf()); n != leaves {
			t.Fatalf("%d new leaves, want none (no directory_install entry)", n-leaves)
		}
		// The bundle_install entry written by the other process moved the
		// log on, so the refusal leaf could not be appended under the old
		// state; it is counted for the next refusal_summary (D-14).
		e.s.flushSummaries(context.Background())
		all := e.leavesOf()
		last := all[len(all)-1]
		sum, err := tlog.DecodeRefusalSummaryBody(last.Body)
		if last.Kind != tlog.KindRefusalSummary || err != nil || len(sum.Counts) != 1 ||
			sum.Counts[0] != (tlog.ReasonCount{Reason: classify("trust_changed"), Count: 1}) {
			t.Fatalf("last leaf %s (%v) %+v, want a refusal_summary counting the trust_changed refusal", last.Kind, err, sum)
		}
		// Control: after a restart under the new bundle, it installs.
		e.close()
		if err := e.open(); err != nil {
			t.Fatal(err)
		}
		e.installDirectory(t, doc, sigs)
		e.wantDirectory(t, 2, doc, sigs, true)
	})
}

// TestDirectoryRefusalLeaves (T-02-83): a refused install is logged with
// its exact detail and the SHA-256 of the refused document.
func TestDirectoryRefusalLeaves(t *testing.T) {
	pk := newPasskeys(t)
	t.Run("install_refusal_leaf_carries_digest", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, false)
		_, outsider := NewEd25519Key(t)
		doc, sigs := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), outsider)
		before := len(e.leavesOf())
		if resp, er := e.s.installDirectoryOrRefuse(context.Background(), Peer{UID: 1000}, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}); resp != nil || er == nil || er.Message != "directory_quorum_not_met" {
			t.Fatalf("install signed by a non-admin: %+v, %+v; want directory_quorum_not_met", resp, er)
		}
		leaves := e.leavesOf()
		if len(leaves) != before+1 || leaves[before].Kind != tlog.KindRefusal {
			t.Fatalf("%d new leaves, want exactly one refusal leaf", len(leaves)-before)
		}
		b, err := tlog.DecodeRefusalBody(leaves[before].Body)
		if err != nil {
			t.Fatal(err)
		}
		if want := sha256.Sum256(doc); b.Detail != "directory_quorum_not_met" || b.RequestDigest != want {
			t.Fatalf("refusal leaf %s digest %x, want directory_quorum_not_met with digest %x", b.Detail, b.RequestDigest, want)
		}
	})
}

// TestDirectoryRefusalBudget (D-14, T-02-83): a refused install draws on
// its own refusal-log bucket. A flood of cheap malformed frames that
// drains the shared bucket cannot hide a quorum-less install inside the
// next refusal_summary: it still gets its own refusal leaf with its detail
// and digest. Controls: the flood's last frames are counted, not logged,
// before and after the install, and the summary counts exactly them.
func TestDirectoryRefusalBudget(t *testing.T) {
	pk := newPasskeys(t)
	e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, false)
	ctx := context.Background()
	malformed := func() int {
		before := len(e.leavesOf())
		_ = e.s.refuse(ctx, Peer{UID: 1000}, [32]byte{}, tlog.ReasonMalformed, "malformed_frame")
		return len(e.leavesOf()) - before
	}
	for i := range DefaultRefusalLogBurst {
		if n := malformed(); n != 1 {
			t.Fatalf("malformed frame %d: %d new leaves, want its refusal leaf (the bucket is not drained yet)", i+1, n)
		}
	}
	if n := malformed(); n != 0 {
		t.Fatalf("malformed frame %d: %d new leaves, want none (the shared bucket is drained)", DefaultRefusalLogBurst+1, n)
	}
	_, outsider := NewEd25519Key(t)
	doc, sigs := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), outsider)
	e.refuseInstall(t, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}, "directory_quorum_not_met")
	if n := malformed(); n != 0 {
		t.Fatalf("malformed frame after the install: %d new leaves, want none (the shared bucket is still drained)", n)
	}
	e.s.flushSummaries(ctx)
	all := e.leavesOf()
	last := all[len(all)-1]
	sum, err := tlog.DecodeRefusalSummaryBody(last.Body)
	if last.Kind != tlog.KindRefusalSummary || err != nil || len(sum.Counts) != 1 ||
		sum.Counts[0] != (tlog.ReasonCount{Reason: tlog.ReasonMalformed, Count: 2}) {
		t.Fatalf("last leaf %s (%v) %+v, want a refusal_summary counting the 2 unlogged malformed frames", last.Kind, err, sum)
	}
}

// wantStartLog requires the operator log of a signer start to carry an
// error record with msg and policy_version 2, the version of the policy
// it was checked against.
func wantStartLog(t *testing.T, log, msg string) {
	t.Helper()
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "level=ERROR") && strings.Contains(line, msg) && strings.Contains(line, " policy_version=2 ") {
			return
		}
	}
	t.Fatalf("no error record %q with policy_version=2 in the start-up log:\n%s", msg, log)
}

// TestDirectoryRestart (T-02-15): the signer re-verifies the stored
// directory under the policy in force at start. After a restart under a
// successor policy whose admin set no longer meets the installed
// directory's quorum, or whose user CA cap is below a role's TTL, the
// signer starts, logs an error naming the policy version, refuses logins
// (directory_not_authorized) and still issues on the admin path; a
// directory that conforms to the new policy restores logins. GetDirectory
// reports the state at each point.
func TestDirectoryRestart(t *testing.T) {
	pk := newPasskeys(t)
	t.Run("restart_under_new_admins", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, false)
		var log bytes.Buffer
		e.logOut = &log
		doc1, sigs1 := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), e.fx.Admins[0])
		e.installDirectory(t, doc1, sigs1)
		// One login before the restart, so the start-up log check also
		// covers a login_issue leaf and its issuance row (T-02-116).
		e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil))
		e.wantDirectory(t, 1, doc1, sigs1, true)

		b := e.restartUnderNewAdmins(t)
		wantStartLog(t, log.String(), "installed directory is not signed by the admin quorum of the policy in force")
		e.wantDirectory(t, 1, doc1, sigs1, false)
		e.refuseLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil), "directory_not_authorized")
		admin := e.request()
		admin.Evidence = SignRequest(t, admin, b)
		if _, err := e.s.Issue(context.Background(), Peer{UID: 1000}, admin); err != nil {
			t.Fatalf("admin issuance by the new admin while logins are refused: %v", err)
		}

		doc2, sigs2 := signDirectory(t, loginDirectory(pk, 2, trust.SHA256Hex(doc1)), b)
		e.installDirectory(t, doc2, sigs2)
		e.wantDirectory(t, 2, doc2, sigs2, true)
		if c := e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil)); !strings.Contains(c.KeyId, "/pol=2/dir=2/") {
			t.Fatalf("key ID %q, want pol=2 and dir=2", c.KeyId)
		}
	})
	t.Run("restart_under_tighter_cap", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, false)
		var log bytes.Buffer
		e.logOut = &log
		doc1, sigs1 := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), e.fx.Admins[0])
		e.installDirectory(t, doc1, sigs1)
		e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil))

		// The same admins, but a user CA cap below the roles' 3600 s.
		const tighter = 1800
		e.restartUnderPolicy(t, func(p *trust.Policy) { p.CAProfiles[0].MaxTTLSeconds = tighter })
		wantStartLog(t, log.String(), "installed directory exceeds the policy in force")
		e.wantDirectory(t, 1, doc1, sigs1, false)
		e.refuseLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil), "directory_not_authorized")
		admin := e.request()
		admin.Evidence = SignRequest(t, admin, e.fx.Admins[0])
		if _, err := e.s.Issue(context.Background(), Peer{UID: 1000}, admin); err != nil {
			t.Fatalf("admin issuance while logins are refused: %v", err)
		}

		// Control: a v2 within the new cap, signed by the same admin.
		d2 := loginDirectory(pk, 2, trust.SHA256Hex(doc1))
		for i := range d2.Roles {
			d2.Roles[i].MaxTTLSeconds = tighter
		}
		doc2, sigs2 := signDirectory(t, d2, e.fx.Admins[0])
		e.installDirectory(t, doc2, sigs2)
		e.wantDirectory(t, 2, doc2, sigs2, true)
		if c := e.mustLogin(t, approve(t, pk.eddsa, e.loginReq(t, "alice"), nil)); !strings.Contains(c.KeyId, "/pol=2/dir=2/") {
			t.Fatalf("key ID %q, want pol=2 and dir=2", c.KeyId)
		}
	})
}

// checkTrustAt runs doctor's trust check (CheckTrust) on the state
// database at path, opened read-only as doctor opens it.
func checkTrustAt(t *testing.T, path string) error {
	t.Helper()
	ro, err := signerdb.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	return CheckTrust(context.Background(), ro)
}

// TestDirectoryLogConsistency (T-02-14): the signer takes its directory
// from the directory table only when the verified log's last
// directory_install entry records exactly that row (version, bytes and
// signatures). A row overwritten, deleted, wiped or written without a log
// entry stops the signer from starting, and doctor's trust check
// (CheckTrust) refuses the same state. Control: each state starts and
// passes CheckTrust before tampering, and a state with neither row nor
// entry starts.
func TestDirectoryLogConsistency(t *testing.T) {
	pk := newPasskeys(t)
	t.Run("fresh_state_starts", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, false)
		e.close()
		if err := e.open(); err != nil {
			t.Fatalf("restart with no directory and no directory_install entry: %v", err)
		}
		e.wantDirectory(t, 0, nil, nil, false)
	})
	cases := []struct {
		name     string
		versions int // directory versions installed before tampering
		tamper   func(t *testing.T, e *logEnv)
	}{
		// Another validly admin-signed version 1 written over the row.
		{"stored_directory_tampered", 1, func(t *testing.T, e *logEnv) {
			d := loginDirectory(pk, 1, trust.GenesisPrev)
			d.Roles[1].MaxTTLSeconds = 7200
			doc, sigs := signDirectory(t, d, e.fx.Admins[0])
			execSQL(t, e.dbPath, `UPDATE directory SET doc = ?, sigs = ? WHERE version = 1`, doc, sigs)
		}},
		// Each compared field alone: the document with the logged
		// signatures kept, and the version with everything else kept.
		{"doc_only_replaced", 1, func(t *testing.T, e *logEnv) {
			d := loginDirectory(pk, 1, trust.GenesisPrev)
			d.Roles[1].MaxTTLSeconds = 7200
			doc, _ := signDirectory(t, d)
			execSQL(t, e.dbPath, `UPDATE directory SET doc = ? WHERE version = 1`, doc)
		}},
		{"version_only_replaced", 1, func(t *testing.T, e *logEnv) {
			execSQL(t, e.dbPath, `UPDATE directory SET version = 5 WHERE version = 1`)
		}},
		{"signatures_replaced", 1, func(t *testing.T, e *logEnv) {
			execSQL(t, e.dbPath, `UPDATE directory SET sigs = 'x' WHERE version = 1`)
		}},
		{"policy_version_replaced", 1, func(t *testing.T, e *logEnv) {
			execSQL(t, e.dbPath, `UPDATE directory SET policy_version = 2 WHERE version = 1`)
		}},
		// The older, validly signed version 1 is left.
		{"newest_row_deleted", 2, func(t *testing.T, e *logEnv) {
			execSQL(t, e.dbPath, `DELETE FROM directory WHERE version = 2`)
		}},
		{"table_wiped", 1, func(t *testing.T, e *logEnv) {
			execSQL(t, e.dbPath, `DELETE FROM directory`)
		}},
		// A validly admin-signed version 1 that install never logged.
		{"unlogged_row", 0, func(t *testing.T, e *logEnv) {
			doc, sigs := signDirectory(t, loginDirectory(pk, 1, trust.GenesisPrev), e.fx.Admins[0])
			execSQL(t, e.dbPath, `INSERT INTO directory (version, doc, sigs, policy_version, installed_at_us) VALUES (1, ?, ?, 1, 1)`, doc, sigs)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, tc.versions >= 1)
			if tc.versions == 2 {
				doc, sigs := signDirectory(t, loginDirectory(pk, 2, trust.SHA256Hex(e.s.GetDirectory().Directory)), e.fx.Admins[0])
				e.installDirectory(t, doc, sigs)
			}
			e.close()
			if err := e.open(); err != nil {
				t.Fatalf("control: restart before tampering: %v", err)
			}
			e.close()
			if err := checkTrustAt(t, e.dbPath); err != nil {
				t.Fatalf("control: CheckTrust before tampering: %v", err)
			}
			tc.tamper(t, e)
			err := e.open()
			if !errors.Is(err, errLogMismatch) || !strings.Contains(err.Error(), "directory_install") {
				t.Fatalf("start with a directory table the log does not record = %v, want errLogMismatch naming the directory_install entry", err)
			}
			if err := checkTrustAt(t, e.dbPath); !errors.Is(err, errLogMismatch) || !strings.Contains(err.Error(), "directory_install") {
				t.Fatalf("CheckTrust (doctor) with a directory table the log does not record = %v, want errLogMismatch naming the directory_install entry", err)
			}
		})
	}
}

// TestDirectoryConcurrent (T-02-16): two different successors of the same
// version installed at once leave exactly one installed; the other is
// refused directory_version_chain.
func TestDirectoryConcurrent(t *testing.T) {
	pk := newPasskeys(t)
	t.Run("concurrent_successor_installs", func(t *testing.T) {
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, true)
		prev := trust.SHA256Hex(e.s.GetDirectory().Directory)
		reqs := make([]*wire.InstallDirectoryRequest, 2)
		for i, ttl := range []uint64{1800, 2400} {
			d := loginDirectory(pk, 2, prev)
			d.Roles[1].MaxTTLSeconds = ttl
			doc, sigs := signDirectory(t, d, e.fx.Admins[0])
			reqs[i] = &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}
		}
		var (
			wg       sync.WaitGroup
			resps    [2]*wire.InstallDirectoryResponse
			refusals [2]*wire.ErrorResponse
		)
		for i := range reqs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resps[i], refusals[i] = e.s.installDirectoryOrRefuse(context.Background(), Peer{UID: 1000}, reqs[i])
			}()
		}
		wg.Wait()
		won := -1
		for i := range reqs {
			switch {
			case resps[i] != nil && won < 0:
				won = i
			case resps[i] != nil:
				t.Fatal("both successors of version 1 installed")
			case refusals[i] == nil || refusals[i].Message != "directory_version_chain":
				t.Fatalf("losing install refused %+v, want directory_version_chain", refusals[i])
			}
		}
		if won < 0 {
			t.Fatalf("no successor installed: %+v", refusals)
		}
		e.wantDirectory(t, 2, reqs[won].Directory, reqs[won].Sigs, true)
		installs := 0
		for _, l := range e.leavesOf() {
			if l.Kind == tlog.KindDirectoryInstall {
				installs++
			}
		}
		if installs != 2 {
			t.Fatalf("%d directory_install leaves, want 2 (version 1 and the one successor)", installs)
		}
	})
}
