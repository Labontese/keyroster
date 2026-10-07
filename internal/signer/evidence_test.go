package signer

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// leavesOf decodes every leaf in the environment's log.
func (e *logEnv) leavesOf() []tlog.Leaf {
	e.t.Helper()
	var out []tlog.Leaf
	err := e.db.ForEachLeaf(context.Background(), func(_ uint64, raw []byte) error {
		l, err := tlog.DecodeLeaf(raw)
		if err != nil {
			return err
		}
		out = append(out, l)
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

// refuseThroughSigner runs req through the signer's dispatch path
// (issueOrRefuse), as the socket server does, and requires a refusal with
// detail and one new refusal leaf carrying class reason, detail and the
// request digest (D-14). Nothing is issued.
func (e *logEnv) refuseThroughSigner(t *testing.T, req *wire.IssueRequest, reason uint8, detail string) {
	t.Helper()
	leavesBefore, issuedBefore, serialBefore := e.counts()
	resp, er := e.s.issueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if resp != nil || er == nil {
		t.Fatalf("request issued (%+v), want the refusal %s", resp, detail)
	}
	if er.Message != detail {
		t.Fatalf("refusal %s: %s, want %s", er.Code, er.Message, detail)
	}
	leaves, issued, serial := e.counts()
	if issued != issuedBefore || serial != serialBefore || leaves != leavesBefore+1 {
		t.Fatalf("after the refusal: %d leaves, %d issuances, serial %d; want %d, %d, %d",
			leaves, issued, serial, leavesBefore+1, issuedBefore, serialBefore)
	}
	all := e.leavesOf()
	last := all[len(all)-1]
	if last.Kind != tlog.KindRefusal {
		t.Fatalf("last leaf is %s, want a refusal", last.Kind)
	}
	b, err := tlog.DecodeRefusalBody(last.Body)
	if err != nil {
		t.Fatal(err)
	}
	if b.Reason != reason || b.Detail != detail || b.RequestDigest != req.Digest() {
		t.Fatalf("refusal leaf %s/%s, want %s/%s with the request digest", tlog.ReasonName(b.Reason), b.Detail, tlog.ReasonName(reason), detail)
	}
}

// sshsigEvidence signs msg with s under namespace as admin-sshsig/v1
// evidence.
func sshsigEvidence(t *testing.T, s ssh.Signer, namespace string, msg []byte) wire.Evidence {
	t.Helper()
	sig, err := sshsig.Sign(rand.Reader, s, namespace, msg)
	if err != nil {
		t.Fatal(err)
	}
	return wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig}
}

// TestEvidence pins D-13: every issue request needs admin-sshsig/v1
// evidence over its exact signing bytes, by at least the policy's quorum
// of distinct admins. Every refusal is logged.
func TestEvidence(t *testing.T) {
	_, outsider := NewEd25519Key(t)

	refusals := []struct {
		name   string
		quorum uint32 // admins in the fixture and the policy quorum
		edit   func(t *testing.T, e *logEnv, r *wire.IssueRequest)
		detail string
	}{
		{"missing_evidence", 1, func(_ *testing.T, _ *logEnv, r *wire.IssueRequest) { r.Evidence = nil }, "missing_evidence"},
		{"unknown_type", 1, func(_ *testing.T, _ *logEnv, r *wire.IssueRequest) {
			r.Evidence = []wire.Evidence{{Type: "webauthn/v1", Blob: r.Evidence[0].Blob}}
		}, "unknown_evidence_type"},
		{"unknown_type_next_to_valid_evidence", 1, func(_ *testing.T, _ *logEnv, r *wire.IssueRequest) {
			r.Evidence = append(r.Evidence, wire.Evidence{Type: "admin-sshsig/v2", Blob: r.Evidence[0].Blob})
		}, "unknown_evidence_type"},
		{"malformed_signature", 1, func(_ *testing.T, _ *logEnv, r *wire.IssueRequest) {
			r.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")}}
		}, "bad_evidence"},
		{"wrong_namespace", 1, func(t *testing.T, e *logEnv, r *wire.IssueRequest) {
			r.Evidence = []wire.Evidence{sshsigEvidence(t, e.fx.Admins[0], trust.NamespacePolicy, r.SigningBytes())}
		}, "evidence_wrong_namespace"},
		{"digest_mismatch", 1, func(_ *testing.T, _ *logEnv, r *wire.IssueRequest) {
			r.Principals = []string{"root"} // changed after the admin signed
		}, "evidence_digest_mismatch"},
		{"digest_mismatch_extension_added", 1, func(_ *testing.T, _ *logEnv, r *wire.IssueRequest) {
			r.Extensions = []string{"permit-port-forwarding"}
		}, "evidence_digest_mismatch"},
		{"non_admin", 1, func(t *testing.T, _ *logEnv, r *wire.IssueRequest) {
			r.Evidence = []wire.Evidence{sshsigEvidence(t, outsider, wire.AdminSSHSIGNamespace, r.SigningBytes())}
		}, "evidence_not_admin"},
		{"non_admin_next_to_valid_evidence", 1, func(t *testing.T, _ *logEnv, r *wire.IssueRequest) {
			r.Evidence = append(r.Evidence, sshsigEvidence(t, outsider, wire.AdminSSHSIGNamespace, r.SigningBytes()))
		}, "evidence_not_admin"},
		{"same_admin_twice_quorum_2", 2, func(t *testing.T, e *logEnv, r *wire.IssueRequest) {
			r.Evidence = SignRequest(t, r, e.fx.Admins[0], e.fx.Admins[0])
		}, "admin_quorum_not_met"},
		{"one_admin_quorum_2", 2, func(t *testing.T, e *logEnv, r *wire.IssueRequest) {
			r.Evidence = SignRequest(t, r, e.fx.Admins[1])
		}, "admin_quorum_not_met"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			e := newLogEnvFx(t, NewFixture(t, int(tc.quorum), tc.quorum))
			req := e.request() // signed by every fixture admin
			tc.edit(t, e, req)
			e.refuseThroughSigner(t, req, tlog.ReasonUnauthorized, tc.detail)
			// The signer still issues the next authorized request.
			if _, err := e.issue(); err != nil {
				t.Fatalf("authorized request after the refusal: %v", err)
			}
		})
	}

	t.Run("two_admins_quorum_2", func(t *testing.T) {
		e := newLogEnvFx(t, NewFixture(t, 2, 2))
		resp, err := e.s.Issue(context.Background(), Peer{UID: 1000}, e.request())
		if err != nil {
			t.Fatalf("two distinct admins with quorum 2: %v", err)
		}
		leaves := e.leavesOf()
		b, err := tlog.DecodeIssueBody(leaves[resp.LeafIndex].Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Evidence) != 2 || b.Evidence[0].Type != wire.EvidenceAdminSSHSIG {
			t.Fatalf("issue leaf records %d evidence items, want both admin signatures", len(b.Evidence))
		}
	})
	t.Run("replay_duplicate_request", func(t *testing.T) {
		e := newLogEnv(t)
		req := e.request()
		if _, err := e.s.Issue(context.Background(), Peer{UID: 1000}, req); err != nil {
			t.Fatal(err)
		}
		replay := *req // identical bytes, evidence included
		_, err := e.s.Issue(context.Background(), Peer{UID: 1000}, &replay)
		var r *refusal
		if !errors.As(err, &r) || r.reason != "duplicate_request" {
			t.Fatalf("replay = %v, want duplicate_request", err)
		}
	})
	for _, skew := range []int64{-301, 301} {
		t.Run("created_at_outside_skew_"+map[bool]string{true: "past", false: "future"}[skew < 0], func(t *testing.T) {
			// The signer is pinned to at, so the skew is exactly ±301 s
			// regardless of elapsed wall time.
			at := time.Now().Truncate(time.Second)
			e := newLogEnvClock(t, NewFixture(t, 1, 1), func() time.Time { return at })
			req := e.request()
			req.CreatedAt = uint64(at.Unix() + skew) //nolint:gosec // G115: a current timestamp
			req.Evidence = SignRequest(t, req, e.fx.Admins...)
			e.refuseThroughSigner(t, req, tlog.ReasonStaleRequest, "request_time_skew")
		})
	}
}

// TestAdminQuorumFitsEvidence (A-WR-03): the largest quorum a policy may
// require is exactly the evidence an issue request can carry, and a policy
// at that quorum can issue.
func TestAdminQuorumFitsEvidence(t *testing.T) {
	if trust.MaxAdminQuorum != wire.MaxEvidence {
		t.Fatalf("trust.MaxAdminQuorum = %d, wire.MaxEvidence = %d; they must be equal", trust.MaxAdminQuorum, wire.MaxEvidence)
	}
	e := newLogEnvFx(t, NewFixture(t, trust.MaxAdminQuorum, trust.MaxAdminQuorum))
	if _, err := e.issue(); err != nil {
		t.Fatalf("issue at the largest quorum, signed by every admin: %v", err)
	}
}
