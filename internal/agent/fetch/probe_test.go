//go:build linux

package fetch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/agent/probe"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// probeServer is a testServer whose probe certificate route answers
// through answer, called with the 1-based count of probe posts.
type probeServer struct {
	*testServer
	posts atomic.Int32
}

func newProbeServer(t *testing.T, answer func(n int, w http.ResponseWriter, r *http.Request)) *probeServer {
	t.Helper()
	ps := &probeServer{}
	ps.testServer = newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != serverclient.AgentProbeCertPath {
			http.NotFound(w, r)
			return
		}
		answer(int(ps.posts.Add(1)), w, r)
	})
	return ps
}

// outboxProbe writes a probe request of polarity pol into the outbox and
// returns its request ID.
func (s *probeServer) outboxProbe(t *testing.T, pol probe.Polarity) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := probe.BuildRequest(host, "0123456789abcdef0123456789abcdef", "web1", pol == probe.Negative, time.Now(), rand.Reader, ed25519.GenerateKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.CanonicalJSON(hostcert.OutboxRequest{Request: body})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.outbox, probe.RequestFileName(pol)), b, 0o640); err != nil { //nolint:gosec // G306: the outbox mode
		t.Fatal(err)
	}
	return hexID(req.RequestID[:])
}

// probeAnswerOf reads polarity pol's spool answer; nil when there is none.
func (s *probeServer) probeAnswerOf(t *testing.T, pol probe.Polarity) *hostcert.Answer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.spool, probe.AnswerFileName(pol)))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	a, err := hostcert.ParseAnswer(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (s *probeServer) post(t *testing.T) {
	t.Helper()
	if err := s.f.postProbeCerts(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func probeCertAnswer(cert []byte) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(serverclient.AgentProbeCertAnswer{Certificate: cert})
	}
}

// TestPostProbeCerts is the fetcher's half of probe certificates (03-10b):
// the shapes and status mapping of postHostCerts for probecert-<polarity>.
func TestPostProbeCerts(t *testing.T) {
	t.Run("posts_each_request_once", func(t *testing.T) {
		s := newProbeServer(t, probeCertAnswer(testHostCert(t)))
		s.outboxProbe(t, probe.Positive)
		s.outboxProbe(t, probe.Negative)
		s.post(t)
		s.post(t)
		if n := s.posts.Load(); n != 2 {
			t.Fatalf("%d posts, want one per outbox request", n)
		}
	})
	t.Run("200_writes_certificate_answer", func(t *testing.T) {
		cert := testHostCert(t)
		s := newProbeServer(t, probeCertAnswer(cert))
		id := s.outboxProbe(t, probe.Negative)
		s.post(t)
		if a := s.probeAnswerOf(t, probe.Negative); a == nil || a.RequestID != id || string(a.Certificate) != string(cert) || a.Refused != "" {
			t.Fatalf("answer %+v, want the certificate for request %s", a, id)
		}
	})
	t.Run("403_detail_is_refusal", func(t *testing.T) {
		s := newProbeServer(t, statusAnswer(http.StatusForbidden, "", "probe_cert_recent"))
		id := s.outboxProbe(t, probe.Positive)
		s.post(t)
		if a := s.probeAnswerOf(t, probe.Positive); a == nil || a.RequestID != id || a.Refused != "probe_cert_recent" {
			t.Fatalf("answer %+v, want the probe_cert_recent refusal", a)
		}
	})
	t.Run("429_ends_the_poll", func(t *testing.T) {
		s := newProbeServer(t, statusAnswer(http.StatusTooManyRequests, "30", "rate_limited"))
		s.outboxProbe(t, probe.Positive)
		s.outboxProbe(t, probe.Negative)
		s.post(t)
		if s.probeAnswerOf(t, probe.Positive) != nil || s.probeAnswerOf(t, probe.Negative) != nil || s.posts.Load() != 1 {
			t.Fatalf("after a 429: %d posts; want one post and nothing written", s.posts.Load())
		}
	})
	t.Run("5xx_writes_nothing", func(t *testing.T) {
		for _, code := range []int{500, 502, 503, 504} {
			s := newProbeServer(t, statusAnswer(code, "", "signer_unavailable"))
			s.outboxProbe(t, probe.Positive)
			s.post(t)
			if a := s.probeAnswerOf(t, probe.Positive); a != nil {
				t.Fatalf("answer %+v after a %d, want none", a, code)
			}
		}
	})
	t.Run("other_4xx_is_http_status", func(t *testing.T) {
		for code, d := range map[int]string{404: "not_found", 403: "Not A Detail!", 400: "bad"} {
			s := newProbeServer(t, statusAnswer(code, "", d))
			s.outboxProbe(t, probe.Positive)
			s.post(t)
			if a := s.probeAnswerOf(t, probe.Positive); code == 400 && (a == nil || a.Refused != "http_400") ||
				code == 404 && (a == nil || a.Refused != "http_404") || code == 403 && (a == nil || a.Refused != "http_403") {
				t.Fatalf("%d %q: answer %+v", code, d, a)
			}
		}
	})
	t.Run("answered_not_posted_again", func(t *testing.T) {
		s := newProbeServer(t, probeCertAnswer(testHostCert(t)))
		s.outboxProbe(t, probe.Negative)
		for range 3 {
			s.post(t)
		}
		if n := s.posts.Load(); n != 1 {
			t.Fatalf("%d posts of one answered request, want 1", n)
		}
		// A new request (another ID) for the same polarity is posted.
		s.outboxProbe(t, probe.Negative)
		s.post(t)
		if n := s.posts.Load(); n != 2 {
			t.Fatalf("%d posts after a new request, want 2", n)
		}
	})
	t.Run("answers_without_request_pruned", func(t *testing.T) {
		s := newProbeServer(t, probeCertAnswer(testHostCert(t)))
		s.outboxProbe(t, probe.Positive)
		s.post(t)
		if err := os.Remove(filepath.Join(s.outbox, probe.RequestFileName(probe.Positive))); err != nil {
			t.Fatal(err)
		}
		s.post(t)
		if a := s.probeAnswerOf(t, probe.Positive); a != nil {
			t.Fatalf("answer %+v kept although the outbox holds no request", a)
		}
	})
	t.Run("hostcert_answers_untouched", func(t *testing.T) {
		s := newProbeServer(t, probeCertAnswer(testHostCert(t)))
		name := hostcert.AnswerFileName("0000000000000000000000000000000000000000000000000000000000000000")
		if err := os.WriteFile(filepath.Join(s.spool, name), []byte("x"), 0o644); err != nil { //nolint:gosec // G306: the spool mode
			t.Fatal(err)
		}
		s.outboxProbe(t, probe.Positive)
		s.post(t)
		if _, err := os.Stat(filepath.Join(s.spool, name)); err != nil {
			t.Fatalf("a host certificate answer: %v", err)
		}
	})
	t.Run("answer_mode_0644", func(t *testing.T) {
		s := newProbeServer(t, probeCertAnswer(testHostCert(t)))
		s.outboxProbe(t, probe.Positive)
		s.post(t)
		fi, err := os.Stat(filepath.Join(s.spool, probe.AnswerFileName(probe.Positive)))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("mode %v, want 0644", fi.Mode().Perm())
		}
	})
	t.Run("oversize_answer_is_answer_too_large", func(t *testing.T) {
		s := newProbeServer(t, probeCertAnswer(make([]byte, hostcert.MaxAnswer)))
		id := s.outboxProbe(t, probe.Positive)
		s.post(t)
		if a := s.probeAnswerOf(t, probe.Positive); a == nil || a.RequestID != id || a.Refused != "answer_too_large" {
			t.Fatalf("answer %+v, want answer_too_large", a)
		}
	})
}
