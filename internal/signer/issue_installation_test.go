package signer

import (
	"bytes"
	"context"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// otherInstallationID is the installation ID of the second installation
// in TestIssueInstallation.
const otherInstallationID = "fedcba9876543210fedcba9876543210"

// issueFixture returns a fixture with one admin at quorum 1 for
// installation id ("" names none). With admins set, its policy lists
// those admin keys instead of its own (the same admin approves in two
// installations).
func issueFixture(t *testing.T, id string, admins *Fixture) *Fixture {
	t.Helper()
	fx := NewFixture(t, 1, 1)
	fx.InstallationID = id
	if admins != nil {
		fx.Admins, fx.AdminPriv = admins.Admins, admins.AdminPriv
	}
	return fx
}

// reframe marshals req and parses it back: what a signer reads from the
// socket for that frame.
func reframe(t *testing.T, req *wire.IssueRequest) *wire.IssueRequest {
	t.Helper()
	body, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.ParseIssueRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// issuesUnder requires req to issue through e's dispatch path, signed by
// the user CA of e's fixture.
func (e *logEnv) issuesUnder(t *testing.T, req *wire.IssueRequest) {
	t.Helper()
	resp, er := e.s.issueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		t.Fatalf("refused %s: %s, want it issued", er.Code, er.Message)
	}
	// Parsed here, not with recovery_test.go's certOf, which builds on
	// linux only (03-14d, F15).
	pub, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()) {
		t.Fatal("the certificate is not signed by this installation's user CA")
	}
}

// TestIssueInstallation (03-14d, F15): an admin issue request names the
// installation it is for (keyroster/issue-request/v2 signs the ID first).
// A signer whose bundle names an installation refuses a request without
// one (issue_installation_missing) or for another
// (issue_installation_mismatch), and one whose bundle names none refuses
// a request that names one (issue_installation_unknown), each before the
// admin evidence and before any CA key; a v1 request still issues where
// the bundle names none. An ID rewritten after signing, a v1 signature
// under a v2 request and a v2 frame stripped to v1 each fail the
// evidence check.
func TestIssueInstallation(t *testing.T) {
	t.Run("request_for_other_installation_refused", func(t *testing.T) {
		fxA := issueFixture(t, testInstallationID, nil)
		a, b := newLogEnvFx(t, fxA), newLogEnvFx(t, issueFixture(t, otherInstallationID, fxA))
		req := a.request()
		body, err := req.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		forA, err := wire.ParseIssueRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		forB, err := wire.ParseIssueRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		a.issuesUnder(t, forA)
		if forB.Digest() != req.Digest() {
			t.Fatal("the frame sent to B is not A's request")
		}
		b.refuseThroughSigner(t, forB, tlog.ReasonUnauthorized, "issue_installation_mismatch")
	})
	t.Run("id_rewritten_refused", func(t *testing.T) {
		fxA := issueFixture(t, testInstallationID, nil)
		b := newLogEnvFx(t, issueFixture(t, otherInstallationID, fxA))
		req := (&logEnv{t: t, fx: fxA}).request()
		req.InstallationID = otherInstallationID
		b.refuseThroughSigner(t, reframe(t, req), tlog.ReasonUnauthorized, "evidence_digest_mismatch")
	})
	t.Run("v1_refused_where_bundle_names_one", func(t *testing.T) {
		a := newLogEnvFx(t, issueFixture(t, testInstallationID, nil))
		req := a.request()
		req.InstallationID = ""
		req.Evidence = SignRequest(t, req, a.fx.Admins...)
		a.refuseThroughSigner(t, req, tlog.ReasonUnauthorized, "issue_installation_missing")
	})
	t.Run("v2_refused_where_bundle_names_none", func(t *testing.T) {
		n := newLogEnvFx(t, issueFixture(t, "", nil))
		req := n.request()
		req.InstallationID = testInstallationID
		req.Evidence = SignRequest(t, req, n.fx.Admins...)
		n.refuseThroughSigner(t, req, tlog.ReasonUnauthorized, "issue_installation_unknown")
	})
	t.Run("v1_issues_where_bundle_names_none", func(t *testing.T) {
		n := newLogEnvFx(t, issueFixture(t, "", nil))
		req := n.request()
		if req.InstallationID != "" || req.Namespace() != wire.AdminSSHSIGNamespace {
			t.Fatalf("the request names installation %q under %s, want a v1 request", req.InstallationID, req.Namespace())
		}
		n.issuesUnder(t, reframe(t, req))
	})
	t.Run("v2_issues_for_own_installation", func(t *testing.T) {
		a := newLogEnvFx(t, issueFixture(t, testInstallationID, nil))
		req := a.request()
		if req.InstallationID != testInstallationID {
			t.Fatalf("the request names installation %q, want %s", req.InstallationID, testInstallationID)
		}
		a.issuesUnder(t, reframe(t, req))
	})
	t.Run("v1_signature_refused_as_v2", func(t *testing.T) {
		a := newLogEnvFx(t, issueFixture(t, testInstallationID, nil))
		req := a.request()
		req.InstallationID = ""
		req.Evidence = SignRequest(t, req, a.fx.Admins...) // v1 bytes, v1 namespace
		req.InstallationID = testInstallationID
		a.refuseThroughSigner(t, reframe(t, req), tlog.ReasonUnauthorized, "evidence_wrong_namespace")
	})
	t.Run("v2_frame_stripped_to_v1_refused", func(t *testing.T) {
		fxA := issueFixture(t, testInstallationID, nil)
		n := newLogEnvFx(t, issueFixture(t, "", fxA))
		req := (&logEnv{t: t, fx: fxA}).request() // signed for A
		stripped := *req
		stripped.InstallationID = ""
		n.refuseThroughSigner(t, reframe(t, &stripped), tlog.ReasonUnauthorized, "evidence_wrong_namespace")
	})
	t.Run("installation_checked_before_evidence", func(t *testing.T) {
		fxA := issueFixture(t, testInstallationID, nil)
		b := newLogEnvFx(t, issueFixture(t, otherInstallationID, nil)) // lists another admin
		req := (&logEnv{t: t, fx: fxA}).request()
		b.refuseThroughSigner(t, reframe(t, req), tlog.ReasonUnauthorized, "issue_installation_mismatch")
	})
	t.Run("classified_unauthorized", func(t *testing.T) {
		for _, d := range []string{"issue_installation_missing", "issue_installation_mismatch", "issue_installation_unknown"} {
			if classify(d) != classify("revoke_installation_mismatch") || codeFor(classify(d)) != wire.CodeRefused {
				t.Errorf("%s classified %s (code %s), want %s like revoke_installation_mismatch",
					d, tlog.ReasonName(classify(d)), codeFor(classify(d)), tlog.ReasonName(classify("revoke_installation_mismatch")))
			}
		}
	})
}
