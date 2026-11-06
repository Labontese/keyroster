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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// hostCertServer is a testServer whose host certificate route answers
// through answer, called with the 1-based count of host certificate posts.
type hostCertServer struct {
	*testServer
	posts atomic.Int32
}

func newHostCertServer(t *testing.T, answer func(n int, w http.ResponseWriter, r *http.Request)) *hostCertServer {
	t.Helper()
	hs := &hostCertServer{}
	hs.testServer = newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != serverclient.AgentHostCertPath {
			http.NotFound(w, r)
			return
		}
		answer(int(hs.posts.Add(1)), w, r)
	})
	return hs
}

// outboxRequest writes a host certificate request for a fresh Ed25519
// host key into the outbox and returns its key name and request ID.
func (s *hostCertServer) outboxRequest(t *testing.T) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := hostcert.BuildRequest(signer, "0123456789abcdef0123456789abcdef", "web1", time.Now(), rand.Reader)
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
	k := hostcert.KeySHA256(signer.PublicKey())
	if err := os.WriteFile(filepath.Join(s.outbox, hostcert.RequestFileName(k)), b, 0o640); err != nil { //nolint:gosec // G306: the outbox mode
		t.Fatal(err)
	}
	return k, hexID(req.RequestID[:])
}

func hexID(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// answerOf reads key k's spool answer; nil when there is none.
func (s *hostCertServer) answerOf(t *testing.T, k string) *hostcert.Answer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.spool, hostcert.AnswerFileName(k)))
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

func (s *hostCertServer) post(t *testing.T) {
	t.Helper()
	if err := s.f.postHostCerts(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// testHostCert stands for a certificate: the fetcher relays the bytes and
// never parses them (the applier verifies them).
func testHostCert(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func certAnswer(cert []byte) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(serverclient.AgentHostCertAnswer{Certificate: cert})
	}
}

func statusAnswer(code int, retryAfter, detail string) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": detail})
	}
}

// TestPostHostCerts is the fetcher's half of host certificates (03-09).
func TestPostHostCerts(t *testing.T) {
	t.Run("posts_each_request_once", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		s.outboxRequest(t)
		s.outboxRequest(t)
		s.post(t)
		s.post(t)
		if n := s.posts.Load(); n != 2 {
			t.Fatalf("%d posts, want one per outbox request", n)
		}
	})
	t.Run("writes_certificate_answer", func(t *testing.T) {
		cert := testHostCert(t)
		s := newHostCertServer(t, certAnswer(cert))
		k, id := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.RequestID != id || string(a.Certificate) != string(cert) || a.Refused != "" {
			t.Fatalf("answer %+v, want the certificate for request %s", a, id)
		}
	})
	t.Run("writes_refusal_answer", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusForbidden, "", "cert_revoked"))
		k, id := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.RequestID != id || a.Refused != "cert_revoked" {
			t.Fatalf("answer %+v, want the cert_revoked refusal", a)
		}
	})
	t.Run("rate_limited_writes_nothing", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusTooManyRequests, "30", "rate_limited"))
		k1, _ := s.outboxRequest(t)
		k2, _ := s.outboxRequest(t)
		s.post(t)
		if s.answerOf(t, k1) != nil || s.answerOf(t, k2) != nil || s.posts.Load() != 1 {
			t.Fatalf("after a 429: %d posts, answers %v %v; want one post and nothing written", s.posts.Load(), s.answerOf(t, k1), s.answerOf(t, k2))
		}
	})
	t.Run("rate_limited_without_retry_after_writes_nothing", func(t *testing.T) {
		for _, ra := range []string{"", "99999999999", "soon"} {
			s := newHostCertServer(t, statusAnswer(http.StatusTooManyRequests, ra, "rate_limited"))
			k, _ := s.outboxRequest(t)
			s.post(t)
			if a := s.answerOf(t, k); a != nil {
				t.Fatalf("Retry-After %q: answer %+v, want none", ra, a)
			}
		}
	})
	t.Run("old_server_404_backs_off", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusNotFound, "", "not_found"))
		k, _ := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.Refused != "http_404" {
			t.Fatalf("answer %+v, want http_404", a)
		}
	})
	t.Run("no_answer_on_503", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusServiceUnavailable, "", "signer_unavailable"))
		k, _ := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a != nil {
			t.Fatalf("answer %+v after a 503, want none", a)
		}
	})
	for name, code := range map[string]int{"internal_error_500_writes_nothing": 500, "bad_gateway_502_writes_nothing": 502, "gateway_timeout_504_writes_nothing": 504} {
		t.Run(name, func(t *testing.T) {
			s := newHostCertServer(t, statusAnswer(code, "", "internal"))
			k, _ := s.outboxRequest(t)
			s.post(t)
			if a := s.answerOf(t, k); a != nil {
				t.Fatalf("answer %+v after a %d, want none", a, code)
			}
		})
	}
	t.Run("forbidden_without_detail_is_http_403", func(t *testing.T) {
		for _, d := range []string{"", "Not A Detail!", "x:y:z"} {
			s := newHostCertServer(t, statusAnswer(http.StatusForbidden, "", d))
			k, _ := s.outboxRequest(t)
			s.post(t)
			if a := s.answerOf(t, k); a == nil || a.Refused != "http_403" {
				t.Fatalf("detail %q: answer %+v, want http_403", d, a)
			}
		}
	})
	t.Run("one_at_a_time", func(t *testing.T) {
		var mu sync.Mutex
		inFlight, peak := 0, 0
		cert := testHostCert(t)
		s := newHostCertServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			inFlight++
			peak = max(peak, inFlight)
			mu.Unlock()
			time.Sleep(20 * time.Millisecond) // overlap would show in peak
			certAnswer(cert)(n, w, r)
			mu.Lock()
			inFlight--
			mu.Unlock()
		})
		for range 3 {
			s.outboxRequest(t)
		}
		s.post(t)
		if peak != 1 || s.posts.Load() != 3 {
			t.Fatalf("peak %d in flight over %d posts, want one at a time", peak, s.posts.Load())
		}
	})
	t.Run("prunes_answers_without_outbox_request", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		k, _ := s.outboxRequest(t)
		gone := hostcert.KeySHA256(mustSSHPub(t))
		for key, id := range map[string]string{k: "0123456789abcdef0123456789abcdef", gone: "fedcba9876543210fedcba9876543210"} {
			if err := writeHostCertAnswer(s.spool, key, hostcert.Answer{RequestID: id, Refused: "cert_revoked"}); err != nil {
				t.Fatal(err)
			}
		}
		s.post(t)
		if a := s.answerOf(t, gone); a != nil {
			t.Fatalf("an answer for a key with no outbox request survives: %+v", a)
		}
		if a := s.answerOf(t, k); a == nil || a.Refused != "" {
			t.Fatalf("the stale answer for k was not replaced by the new one: %+v", a)
		}
	})
	t.Run("oversize_answer_healed", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		k, _ := s.outboxRequest(t)
		for _, n := range []int{spool.MaxHostCertAnswer, spool.MaxHostCertAnswer + 1} {
			p := filepath.Join(s.spool, hostcert.AnswerFileName(k))
			if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil { //nolint:gosec // G306: the answer mode
				t.Fatal(err)
			}
			if _, err := healSpool(s.spool); err != nil {
				t.Fatal(err)
			}
			_, err := os.Stat(p)
			if (n > spool.MaxHostCertAnswer) != os.IsNotExist(err) {
				t.Fatalf("an answer of %d bytes after the heal: %v", n, err)
			}
		}
	})
	t.Run("answer_mode_0644", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		k, _ := s.outboxRequest(t)
		s.post(t)
		fi, err := os.Stat(filepath.Join(s.spool, hostcert.AnswerFileName(k)))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("answer mode %v, %v; want 0644", fi.Mode(), err)
		}
	})
	t.Run("retry_after_lost_response_gets_certificate", func(t *testing.T) {
		cert := testHostCert(t)
		var bodies []string
		var mu sync.Mutex
		s := newHostCertServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
			var req serverclient.AgentHostCertRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			bodies = append(bodies, string(req.Request))
			mu.Unlock()
			if n == 1 {
				// The server committed, then the response was lost.
				statusAnswer(http.StatusServiceUnavailable, "", "signer_unavailable")(n, w, r)
				return
			}
			certAnswer(cert)(n, w, r)
		})
		k, id := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a != nil {
			t.Fatalf("answer %+v after the lost response", a)
		}
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.RequestID != id || string(a.Certificate) != string(cert) {
			t.Fatalf("the retry wrote %+v, want the certificate", a)
		}
		if len(bodies) != 2 || bodies[0] != bodies[1] {
			t.Fatal("the retry did not post the same request")
		}
	})
}

func mustSSHPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
