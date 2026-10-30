package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// forgetEnv is a revokeEnv (three admins, quorum 2, an installation ID)
// with two directory versions installed: v1 holds web1 (active, key
// removed) and web2 (disabled, key held); v2 holds web2 only. The agent a
// forget names is the one with host key removed, removed at v2 and
// confirmed at v2 with v2's document.
type forgetEnv struct {
	*revokeEnv
	removed, held ssh.PublicKey
	docs          [][]byte // the installed documents, by version - 1
}

func newForgetEnv(t *testing.T, quorum uint32, installationID string) *forgetEnv {
	t.Helper()
	e := &forgetEnv{revokeEnv: newRevokeEnv(t, 3, quorum, installationID)}
	_, removed := NewEd25519Key(t)
	_, held := NewEd25519Key(t)
	e.removed, e.held = removed.PublicKey(), held.PublicKey()
	web1 := directory.Host{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(e.removed)}, Principals: []string{"web1"}, Status: directory.StatusActive}
	web2 := directory.Host{Name: "web2", HostGroup: "lab", Keys: []string{trust.FormatKey(e.held)}, Principals: []string{"web2"}, Status: directory.StatusDisabled}
	prev := trust.GenesisPrev
	for v, hosts := range [][]directory.Host{{web1, web2}, {web2}} {
		d := &directory.Directory{
			Version: uint64(v + 1), Prev: prev, InstallationID: installationID,
			Roles:      []directory.Role{{Name: "ops", Principals: loginPrincipals, MaxTTLSeconds: 3600}},
			HostGroups: []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}},
			Hosts:      hosts,
		}
		d.Sort()
		doc, sigs := signDirectory(t, d, e.fx.Admins[0], e.fx.Admins[1])
		e.installDirectory(t, doc, sigs)
		e.docs = append(e.docs, doc)
		prev = trust.SHA256Hex(doc)
	}
	return e
}

// request is a forget of the agent with host key removed, approved once
// and confirmed at v2, created now on the env's clock, signed under the
// forget namespace by signers; the server's statement agrees.
func (e *forgetEnv) request(signers ...ssh.Signer) *wire.ForgetRequest {
	e.t.Helper()
	req := &wire.ForgetRequest{InstallationID: e.fx.InstallationID, ExpectedName: "web1", EnrolledAtMicros: 1_790_000_000_000_000,
		HostKeyFingerprints: [][32]byte{wire.HostKeyDigest(e.removed)}, ApprovedOnce: true, RemovalVersion: 2, ConfirmedVersion: 2,
		ConfirmedSHA256: sha256.Sum256(e.docs[1]), CreatedAt: uint64(e.clock.Now().Unix()), ServerApprovedOnce: true} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.AgentIdentity[:]); err != nil {
		e.t.Fatal(err)
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		e.t.Fatal(err)
	}
	return e.sign(req, wire.ForgetSSHSIGNamespace, signers...)
}

// neverApproved is request for an agent never approved: no removal, no
// confirmation, and the server's statement says so.
func (e *forgetEnv) neverApproved(signers ...ssh.Signer) *wire.ForgetRequest {
	e.t.Helper()
	req := e.request()
	req.ApprovedOnce, req.ServerApprovedOnce, req.RemovalVersion, req.ConfirmedVersion, req.ConfirmedSHA256 = false, false, 0, 0, [32]byte{}
	return e.sign(req, wire.ForgetSSHSIGNamespace, signers...)
}

// sign replaces req's evidence with signatures by signers over its signing
// bytes under ns.
func (e *forgetEnv) sign(req *wire.ForgetRequest, ns string, signers ...ssh.Signer) *wire.ForgetRequest {
	e.t.Helper()
	req.Evidence = nil
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, ns, req.SigningBytes())
		if err != nil {
			e.t.Fatal(err)
		}
		req.Evidence = append(req.Evidence, wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig})
	}
	return req
}

// forgets is the number of host_forget leaves.
func (e *forgetEnv) forgets() int {
	e.t.Helper()
	n := 0
	for _, l := range e.leavesOf() {
		if l.Kind == tlog.KindHostForget {
			n++
		}
	}
	return n
}

// accepted runs req through forgetOrRefuse and requires success: exactly
// one new leaf, the host_forget leaf the answer names, recording the
// policy and directory versions in force, the resolution time, req's
// signing bytes and evidence, and req's request ID recorded.
func (e *forgetEnv) accepted(req *wire.ForgetRequest) *tlog.HostForgetBody {
	e.t.Helper()
	before := len(e.leavesOf())
	resp, er := e.s.forgetOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		e.t.Fatalf("forget refused: %s", er.Message)
	}
	leaves := e.leavesOf()[before:]
	if len(leaves) != 1 || leaves[0].Kind != tlog.KindHostForget || leaves[0].Index != resp.Leaf {
		e.t.Fatalf("leaves after the forget: %+v (answer %+v), want one host_forget leaf", leaves, resp)
	}
	b, err := tlog.DecodeHostForgetBody(leaves[0].Body)
	if err != nil {
		e.t.Fatal(err)
	}
	if b.PolicyVersion != e.s.PolicyVersion() || b.DirectoryVersion != 2 || b.ResolvedAtSeconds != uint64(e.clock.Now().Unix()) || //nolint:gosec // G115: after 1970
		!bytes.Equal(b.Request, req.SigningBytes()) || len(b.Evidence) != len(req.Evidence) {
		e.t.Fatalf("host_forget body %+v", b)
	}
	if used, err := e.db.RevokeRequestUsed(context.Background(), req.RequestID); err != nil || !used {
		e.t.Fatalf("the request ID is not recorded: %t %v", used, err)
	}
	return b
}

// refused runs req through forgetOrRefuse and requires the refusal detail,
// no host_forget leaf and no request ID recorded (a refusal leaf may be
// appended, plan check item 5).
func (e *forgetEnv) refused(req *wire.ForgetRequest, detail string) {
	e.t.Helper()
	forgets, requests := e.forgets(), e.countRows("revoke_request")
	resp, er := e.s.forgetOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if resp != nil || er == nil || er.Message != detail {
		e.t.Fatalf("forget: %+v, %+v; want the refusal %s", resp, er, detail)
	}
	if e.forgets() != forgets || e.countRows("revoke_request") != requests {
		e.t.Fatalf("the refusal %s wrote a host_forget leaf or a request ID", detail)
	}
}

// TestForgetAgent (03-08c, owner decisions 03-08 D-1 and Q3): the signer
// logs a forget as one host_forget leaf only under its rule, one admin for
// an agent never approved and the policy's admin quorum for every other,
// with the signed approved_once equal to the server's statement, for its
// own installation, fresh, never replayed, of no host the directory holds
// and with a confirmation of a directory it installed.
func TestForgetAgent(t *testing.T) {
	t.Run("quorum_met_logs_one_leaf", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		e.accepted(e.request(e.fx.Admins[0], e.fx.Admins[1]))
	})
	t.Run("never_approved_one_admin_accepted", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		e.accepted(e.neverApproved(e.fx.Admins[2]))
	})
	t.Run("approved_once_one_admin_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		e.refused(e.request(e.fx.Admins[0]), "admin_quorum_not_met")
	})
	t.Run("same_admin_twice_counts_once", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		e.refused(e.request(e.fx.Admins[0], e.fx.Admins[0]), "admin_quorum_not_met")
	})
	t.Run("server_statement_mismatch_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		// Signed "never approved" by one admin, while the server's row was
		// approved once (T-03-293).
		req := e.neverApproved(e.fx.Admins[0])
		req.ServerApprovedOnce = true
		e.refused(req, "forget_facts_mismatch")
		// And the reverse: signed approved once, the server says never.
		req = e.request(e.fx.Admins[0], e.fx.Admins[1])
		req.ServerApprovedOnce = false
		e.refused(req, "forget_facts_mismatch")
	})
	t.Run("non_admin_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		_, outsider := NewEd25519Key(t)
		e.refused(e.request(e.fx.Admins[0], outsider), "evidence_not_admin")
	})
	t.Run("revoke_namespace_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.sign(e.request(), wire.RevokeSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1])
		e.refused(req, "evidence_wrong_namespace")
	})
	t.Run("installation_mismatch_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.request()
		req.InstallationID = "fedcba9876543210fedcba9876543210"
		e.refused(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "forget_installation_mismatch")
	})
	t.Run("stale_request_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		for _, d := range []time.Duration{-301 * time.Second, 301 * time.Second} {
			req := e.request()
			req.CreatedAt = uint64(e.clock.Now().Add(d).Unix()) //nolint:gosec // G115: after 1970
			e.refused(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "request_time_skew")
		}
		// The clock is half a second past a whole second, so CreatedAt 300 s
		// ahead, in whole seconds, is 299.5 s off: inside the window.
		req := e.request()
		req.CreatedAt = uint64(e.clock.Now().Add(300 * time.Second).Unix()) //nolint:gosec // G115: after 1970
		e.accepted(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]))
	})
	t.Run("duplicate_request_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.request(e.fx.Admins[0], e.fx.Admins[1])
		e.accepted(req)
		e.refused(req, "duplicate_request")
		// A request ID a revocation used.
		rev := e.revokeRequest(e.serial, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0])
		e.revoked(rev, 0)
		again := e.request()
		again.RequestID = rev.RequestID
		e.refused(e.sign(again, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "duplicate_request")
	})
	t.Run("host_in_directory_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.request()
		// The disabled entry web2 holds this key.
		req.HostKeyFingerprints = append(req.HostKeyFingerprints, wire.HostKeyDigest(e.held))
		slices.SortFunc(req.HostKeyFingerprints, func(x, y [32]byte) int { return bytes.Compare(x[:], y[:]) })
		e.refused(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "forget_host_in_directory")
	})
	t.Run("confirmation_above_current_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.request()
		req.ConfirmedVersion = 3
		e.refused(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "forget_confirmation_invalid")
	})
	t.Run("confirmation_sha_mismatch_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.request()
		req.ConfirmedSHA256 = sha256.Sum256(e.docs[0]) // v1's document at v2
		e.refused(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "forget_confirmation_invalid")
		req = e.request()
		req.RemovalVersion, req.ConfirmedVersion, req.ConfirmedSHA256 = 1, 1, sha256.Sum256(e.docs[1]) // v2's at v1
		e.refused(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "forget_confirmation_invalid")
		// v1's own document at v1, a version below the one in force, is
		// a directory the signer installed.
		req = e.request()
		req.RemovalVersion, req.ConfirmedVersion, req.ConfirmedSHA256 = 1, 1, sha256.Sum256(e.docs[0])
		e.accepted(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]))
	})
	t.Run("host_gone_logged", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.request()
		req.ConfirmedVersion, req.ConfirmedSHA256, req.HostGone = 0, [32]byte{}, true
		b := e.accepted(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]))
		if r, err := wire.ParseForgetSigningBytes(b.Request); err != nil || !r.HostGone {
			t.Fatalf("the logged request %+v, %v", r, err)
		}
	})
	t.Run("restart_after_forget", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		e.accepted(e.request(e.fx.Admins[0], e.fx.Admins[1]))
		e.close()
		if err := e.open(); err != nil {
			t.Fatalf("restart after a forget: %v", err)
		}
		if err := CheckTrust(context.Background(), e.db); err != nil {
			t.Fatalf("CheckTrust after a forget: %v", err)
		}
		var forget tlog.Leaf
		for _, l := range e.leavesOf() {
			if l.Kind == tlog.KindHostForget {
				forget = l
			}
		}
		e.close()
		// The leaf framed as before, with its body cut short by one byte:
		// the body no longer decodes.
		forget.Body = forget.Body[:len(forget.Body)-1]
		execSQL(t, e.dbPath, `UPDATE log_leaf SET leaf = ? WHERE idx = ?`, tlog.EncodeLeaf(forget), forget.Index)
		if err := e.open(); !errors.Is(err, errLogMismatch) {
			t.Fatalf("start with a host_forget body that does not decode: %v, want errLogMismatch", err)
		}
	})
	t.Run("policy_quorum_1_one_admin", func(t *testing.T) {
		e := newForgetEnv(t, 1, testInstallationID)
		e.accepted(e.request(e.fx.Admins[1]))
	})
	t.Run("no_installation_id_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, "")
		req := e.request()
		req.InstallationID = testInstallationID
		e.refused(e.sign(req, wire.ForgetSSHSIGNamespace, e.fx.Admins[0], e.fx.Admins[1]), "forget_no_installation_id")
	})
	t.Run("malformed_refused", func(t *testing.T) {
		e := newForgetEnv(t, 2, testInstallationID)
		req := e.request(e.fx.Admins[0], e.fx.Admins[1])
		req.HostKeyFingerprints = nil
		e.refused(req, "malformed_request")
	})
	if !strings.HasPrefix(wire.ForgetSSHSIGNamespace, "keyroster/host-forget-request/") {
		t.Fatal("the forget namespace changed")
	}
}
