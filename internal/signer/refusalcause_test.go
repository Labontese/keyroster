package signer

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/wire"
)

// TestRefusalCauseLogged (A-WR-05): the operator log record of an internal
// or unavailable refusal says why it happened (the cause's type and text),
// while a refused request's cause is not logged, so peer-supplied text
// never reaches the log through it. Neither reaches the peer.
func TestRefusalCauseLogged(t *testing.T) {
	e := newLogEnv(t)
	var buf bytes.Buffer
	e.s.log = slog.New(slog.NewTextHandler(&buf, nil))
	ctx := context.Background()

	t.Run("state_unavailable_cause_logged", func(t *testing.T) {
		buf.Reset()
		e.s.mu.Lock()
		orig := e.s.cpSigner
		e.s.cpSigner = failingSigner{orig}
		e.s.mu.Unlock()
		defer func() {
			e.s.mu.Lock()
			e.s.cpSigner = orig
			e.s.mu.Unlock()
		}()
		_, refused := e.s.issueOrRefuse(ctx, Peer{UID: 1000}, e.request())
		if refused == nil || refused.Message != "state_unavailable" {
			t.Fatalf("refusal %+v, want state_unavailable", refused)
		}
		if strings.Contains(refused.Message, "injected") {
			t.Fatalf("the cause reached the peer: %q", refused.Message)
		}
		out := buf.String()
		if !strings.Contains(out, `msg=refused`) || !strings.Contains(out, "reason=state_unavailable") ||
			!strings.Contains(out, "cause_type=") || !strings.Contains(out, "injected checkpoint signing failure") {
			t.Fatalf("operator log lacks the cause of state_unavailable:\n%s", out)
		}
	})

	t.Run("refused_request_cause_type_only", func(t *testing.T) {
		buf.Reset()
		const peerText = "peer-chosen-algorithm-name"
		req := e.request()
		req.SubjectKey = ssh.Marshal(struct{ Name string }{peerText})
		req.Evidence = SignRequest(t, req, e.fx.Admins...)
		_, refused := e.s.issueOrRefuse(ctx, Peer{UID: 1000}, req)
		if refused == nil || refused.Message != "bad_subject_key" || refused.Code != wire.CodeRefused {
			t.Fatalf("refusal %+v, want bad_subject_key", refused)
		}
		out := buf.String()
		if !strings.Contains(out, `msg=refused`) || !strings.Contains(out, "reason=bad_subject_key") {
			t.Fatalf("operator log lacks the bad_subject_key refusal:\n%s", out)
		}
		if strings.Contains(out, peerText) || strings.Contains(out, "cause") {
			t.Fatalf("a refused request's cause reached the operator log:\n%s", out)
		}
	})
}
