//go:build linux

package signer

import (
	"context"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/wire"
)

// issueKR1 issues a kr1 certificate under role for subject through the
// admin path (keyroster ca issue --ca host --subject S builds the same),
// valid for validFor seconds.
func (e *hostEnv) issueKR1(t *testing.T, role wire.CARole, subject string, validFor uint32) *ssh.Certificate {
	t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	req := &wire.IssueRequest{CARole: role, SubjectKey: newEd25519(t).PublicKey().Marshal(), Subject: subject, Principals: []string{"web1"},
		ValidForSeconds: validFor, CreatedAt: uint64(e.clock.Now().Unix())} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	req.Evidence = SignRequest(t, req, e.fx.Admins...)
	resp, err := e.s.Issue(context.Background(), Peer{UID: 1000}, req)
	if err != nil {
		t.Fatalf("issue %s for %s: %v", role, subject, err)
	}
	return certOf(t, resp)
}

// revokeHostSubject revokes every live certificate of host name and
// returns the signer's answer.
func (e *hostEnv) revokeHostSubject(t *testing.T, name string) *wire.RevokeResponse {
	t.Helper()
	return e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectHost, Subject: name})
}

// TestRevokeHostSubject (03-09b, REVOKE-01's host subject): a subject
// revocation of a host resolves its kr3 certificates and the kr1
// certificates issued under the host CA with that exact subject, marks
// the host index so the key is held cert_revoked until a newer directory
// version is installed (Q-09-5, Q-09-9), and audit re-derives it.
func TestRevokeHostSubject(t *testing.T) {
	t.Run("subject_host_kr3_and_kr1", func(t *testing.T) {
		e := newHostEnv(t, 3600)
		k3, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		k1 := e.issueKR1(t, wire.CARoleHost, "web1", 600)
		u1 := e.issueKR1(t, wire.CARoleUser, "web1", 600)
		resp := e.revokeHostSubject(t, "web1")
		want := []uint64{k3.Serial, k1.Serial}
		slices.Sort(want)
		if !slices.Equal(resp.Serials, want) || slices.Contains(resp.Serials, u1.Serial) {
			t.Fatalf("host subject web1 revoked %v, want the kr3 and kr1 host certificates %v and not the user certificate %d", resp.Serials, want, u1.Serial)
		}
		p := e.parsedKRL(t)
		for _, c := range []*ssh.Certificate{k3, k1} {
			if !p.RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
				t.Fatalf("the KRL does not revoke serial %d under the host CA", c.Serial)
			}
		}
		if p.RevokesSerial(u1.SignatureKey.Marshal(), u1.Serial) {
			t.Fatal("the KRL revokes the user certificate with subject web1")
		}
	})
	t.Run("subject_host_prefix_exact", func(t *testing.T) {
		e := newHostEnv(t, 3600)
		k3, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		old := e.issueKR1(t, wire.CARoleHost, "web1-old", 600)
		if got := e.revokeHostSubject(t, "web1").Serials; !slices.Equal(got, []uint64{k3.Serial}) {
			t.Fatalf("web1 revoked %v, want only %d (not web1-old's %d)", got, k3.Serial, old.Serial)
		}
		if got := e.revokeHostSubject(t, "web1-old").Serials; !slices.Equal(got, []uint64{old.Serial}) {
			t.Fatalf("web1-old revoked %v, want only %d", got, old.Serial)
		}
		if got := e.revokeHostSubject(t, "web").Serials; len(got) != 0 {
			t.Fatalf("web revoked %v, want none", got)
		}
	})
	t.Run("subject_host_no_issue_time_cutoff", func(t *testing.T) {
		e := newHostEnv(t, 86400)
		long, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.setHostCap(t, 3600, nil)
		e.tickTo(issuedSecs(long) + 7200)
		if got := e.revokeHostSubject(t, "web1").Serials; !slices.Contains(got, long.Serial) {
			t.Fatalf("revoked %v, want the older, longer-lived %d under the shorter successor cap", got, long.Serial)
		}
	})
	t.Run("subject_host_live_boundary", func(t *testing.T) {
		for _, tc := range []struct {
			after uint64
			live  bool
		}{{299, true}, {300, false}} {
			e := newHostEnv(t, 90)
			c, _ := e.mustHost(e.hostReq(e.ed, "web1"))
			e.tickTo(c.ValidBefore + tc.after)
			if got := e.revokeHostSubject(t, "web1").Serials; slices.Contains(got, c.Serial) != tc.live {
				t.Fatalf("at ValidBefore + %d s revoked %v; want serial %d listed: %v", tc.after, got, c.Serial, tc.live)
			}
		}
	})
	t.Run("subject_host_marks_index_revoked", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.revokeHostSubject(t, "web1")
		e.tickTo(issuedSecs(c1) + 3600)
		e.refusedHost(t, e.hostReq(e.ed, "web1"), "cert_revoked", wire.CodeRefused)
		e.publish(t)
		if c2, _ := e.mustHost(e.hostReq(e.ed, "web1")); c2.Serial <= c1.Serial {
			t.Fatal("after a newer directory version the key was not issued")
		}
	})
	t.Run("loss_revoke_before_install_released_by_same_install", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		// Revoked at version 1, then version 2 (the entry kept) installed:
		// that same install releases the hold.
		e.revokeHostSubject(t, "web1")
		e.publish(t)
		e.tickTo(issuedSecs(c1) + 3600)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if c2.Serial <= c1.Serial {
			t.Fatal("the install after the revoke did not release the hold")
		}
		// Revoked after the install of version 2: held until version 3.
		e.revokeHostSubject(t, "web1")
		e.tickTo(issuedSecs(c2) + 3600)
		e.refusedHost(t, e.hostReq(e.ed, "web1"), "cert_revoked", wire.CodeRefused)
		e.publish(t)
		if c3, _ := e.mustHost(e.hostReq(e.ed, "web1")); c3.Serial <= c2.Serial {
			t.Fatal("version 3 did not release the hold recorded at version 2")
		}
	})
	t.Run("subject_machine_still_unsupported", func(t *testing.T) {
		e := newHostEnv(t, 90)
		req := &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectMachine, Subject: "web1", InstallationID: e.fx.InstallationID,
			CreatedAt: uint64(e.clock.Now().Unix()), Reason: "test"} //nolint:gosec // G115: after 1970
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		e.refusedRevoke(e.signed(req, e.fx.Admins[0]), "subject_kind_unsupported")
	})
	t.Run("audit_agrees", func(t *testing.T) {
		e := newHostEnv(t, 3600)
		e.mustHost(e.hostReq(e.ed, "web1"))
		e.mustHost(e.hostReq(e.ec, "web1"))
		e.issueKR1(t, wire.CARoleHost, "web1", 600)
		resp := e.revokeHostSubject(t, "web1")
		rep := e.verifyExport()
		if len(resp.Serials) != 3 || rep.Revocations != 1 || rep.RevokedEntries != 3 {
			t.Fatalf("signer revoked %v; audit: %d revocations, %d entries; want 3 serials, 1 and 3", resp.Serials, rep.Revocations, rep.RevokedEntries)
		}
	})
}
