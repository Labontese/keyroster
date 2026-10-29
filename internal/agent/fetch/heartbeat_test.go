//go:build linux

package fetch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// validStatus is a status that passes heartbeat.Validate.
func validStatus(seq uint64) heartbeat.Status {
	return heartbeat.Status{AgentVersion: "keyroster-agent (devel)", Files: []heartbeat.File{}, Seq: seq}
}

// putStatus writes s as the applier's outbox/status.json.
func (s *testServer) putStatus(t *testing.T, st heartbeat.Status) []byte {
	t.Helper()
	b, err := trust.CanonicalJSON(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.outbox, heartbeat.StatusFile), b, 0o640); err != nil { //nolint:gosec // G306: the outbox file's mode
		t.Fatal(err)
	}
	return b
}

// TestStatus is the fetcher's side of status.json (03-08): its clock
// offset is whole seconds from the server's Date header.
func TestStatus(t *testing.T) {
	t.Run("clock_offset_whole_seconds", func(t *testing.T) {
		at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
		for _, c := range []struct {
			date, received time.Time
			want           int64
		}{
			{at, at.Add(900 * time.Millisecond), 0},
			{at.Add(time.Second), at.Add(999 * time.Millisecond), 1},
			{at.Add(301 * time.Second), at, 301},
			{at, at.Add(300*time.Second + 500*time.Millisecond), -300},
		} {
			if got := clockOffset(c.date, c.received); got != c.want {
				t.Errorf("clockOffset(%s, %s) = %d, want %d", c.date, c.received, got, c.want)
			}
		}
		// Through a poll: the server's Date is 400 s ahead.
		var mu sync.Mutex
		var posted []byte
		ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Date", time.Now().Add(400*time.Second).UTC().Format(http.TimeFormat))
			if r.URL.Path == serverclient.AgentHeartbeatPath {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				posted = b
				mu.Unlock()
				_, _ = w.Write([]byte(`{"seq":1}`))
				return
			}
			_, _ = w.Write([]byte(emptyState))
		})
		ts.putStatus(t, validStatus(1))
		var log bytes.Buffer
		ts.f.cfg.Log = &log
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		h, err := heartbeat.ParseHeartbeat(posted)
		if err != nil {
			t.Fatalf("the posted heartbeat: %v\n%s", err, posted)
		}
		if h.ClockOffsetS < 399 || h.ClockOffsetS > 401 {
			t.Fatalf("clock_offset_s %d, want 400 +- 1", h.ClockOffsetS)
		}
		if !strings.Contains(log.String(), "ERROR clock_skew") {
			t.Fatalf("no clock_skew line: %q", log.String())
		}
	})
}

// TestHeartbeatPost is the fetcher's heartbeat (03-08, AGENT-07): each
// poll the server answered posts status.json, read without following a
// link and checked as the server checks it; 409 stale_heartbeat is quiet
// (owner decision D-2).
func TestHeartbeatPost(t *testing.T) {
	type rec struct {
		mu    sync.Mutex
		posts [][]byte
	}
	server := func(t *testing.T, code int, body string) (*testServer, *rec) {
		t.Helper()
		r := &rec{}
		ts := newTestServer(t, func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == serverclient.AgentHeartbeatPath {
				b, _ := io.ReadAll(req.Body)
				r.mu.Lock()
				r.posts = append(r.posts, b)
				r.mu.Unlock()
				w.WriteHeader(code)
				_, _ = w.Write([]byte(body))
				return
			}
			_, _ = w.Write([]byte(emptyState))
		})
		return ts, r
	}
	t.Run("posted_every_poll", func(t *testing.T) {
		ts, r := server(t, http.StatusOK, `{"seq":5}`)
		want := ts.putStatus(t, validStatus(5))
		for range 2 {
			if err := ts.f.Once(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.posts) != 2 {
			t.Fatalf("%d heartbeats in two polls", len(r.posts))
		}
		var h struct {
			Status json.RawMessage `json:"status"`
		}
		if err := json.Unmarshal(r.posts[0], &h); err != nil || !bytes.Equal(append([]byte(h.Status), '\n'), want) {
			t.Fatalf("the posted status is not status.json: %s", r.posts[0])
		}
	})
	t.Run("stale_heartbeat_quiet", func(t *testing.T) {
		ts, _ := server(t, http.StatusConflict, `{"error":"stale_heartbeat"}`)
		ts.putStatus(t, validStatus(5))
		var log bytes.Buffer
		ts.f.cfg.Log = &log
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("409 stale_heartbeat: %v, want no error", err)
		}
		if log.Len() != 0 {
			t.Fatalf("409 stale_heartbeat logged %q", log.String())
		}
	})
	t.Run("field_refusal_is_an_error", func(t *testing.T) {
		ts, _ := server(t, http.StatusBadRequest, `{"error":"heartbeat_field_invalid","field":"seq"}`)
		ts.putStatus(t, validStatus(5))
		if err := ts.f.Once(t.Context()); err == nil || !strings.Contains(err.Error(), "heartbeat_field_invalid") {
			t.Fatalf("a refused heartbeat: %v", err)
		}
	})
	t.Run("no_status_no_heartbeat", func(t *testing.T) {
		ts, r := server(t, http.StatusOK, `{"seq":1}`)
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(r.posts) != 0 {
			t.Fatal("a heartbeat without status.json")
		}
	})
	t.Run("invalid_status_not_posted", func(t *testing.T) {
		ts, r := server(t, http.StatusOK, `{"seq":1}`)
		bad := validStatus(1)
		bad.SSHDVersion = "OpenSSH\x1b[2J"
		ts.putStatus(t, bad)
		if err := ts.f.Once(t.Context()); err == nil {
			t.Fatal("an invalid status.json was accepted")
		}
		if len(r.posts) != 0 {
			t.Fatal("an invalid status.json was posted")
		}
	})
	t.Run("status_symlink_not_followed", func(t *testing.T) {
		ts, r := server(t, http.StatusOK, `{"seq":1}`)
		target := filepath.Join(t.TempDir(), "status.json")
		b, _ := trust.CanonicalJSON(validStatus(1))
		if err := os.WriteFile(target, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(ts.outbox, heartbeat.StatusFile)); err != nil {
			t.Fatal(err)
		}
		if err := ts.f.Once(t.Context()); err == nil {
			t.Fatal("a symlinked status.json was read")
		}
		if len(r.posts) != 0 {
			t.Fatal("a symlinked status.json was posted")
		}
	})
	t.Run("not_approved_no_heartbeat", func(t *testing.T) {
		var mu sync.Mutex
		var paths []string
		ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"not_approved"}`))
		})
		ts.putStatus(t, validStatus(1))
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(paths) != 1 || paths[0] != serverclient.AgentStatePath {
			t.Fatalf("requests %q, want the state request only", paths)
		}
	})
}

// rotServer is a fake agent server that knows one identity at a time and
// switches it on a valid rotation (the server's own rules are
// internal/server's TestIdentityRotation).
type rotServer struct {
	mu       sync.Mutex
	current  string // hex SHA-256 of the known identity's SPKI
	dropNext bool   // commit the next rotation and drop its answer
	rotated  int
	refused  int // requests with an unknown identity
}

func spkiHash(spki []byte) string {
	s := sha256.Sum256(spki)
	return hex.EncodeToString(s[:])
}

func (s *rotServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer := r.TLS.PeerCertificates[0]
	if spkiHash(peer.RawSubjectPublicKeyInfo) != s.current {
		s.refused++
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"unknown_agent"}`))
		return
	}
	switch r.URL.Path {
	case serverclient.AgentIdentityPath:
		var req serverclient.AgentIdentityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		old, _ := peer.PublicKey.(ed25519.PublicKey)
		pub, err := x509.ParsePKIXPublicKey(req.NewSPKI)
		if _, ok := pub.(ed25519.PublicKey); err != nil || !ok || !ed25519.Verify(old, serverclient.AgentIdentityMessage(req.NewSPKI), req.Sig) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"identity_rotation_invalid"}`))
			return
		}
		s.current = spkiHash(req.NewSPKI)
		s.rotated++
		if s.dropNext {
			s.dropNext = false
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write([]byte(`{}`))
	case serverclient.AgentHeartbeatPath:
		_, _ = w.Write([]byte(`{"seq":1}`))
	default:
		_, _ = w.Write([]byte(emptyState))
	}
}

func keyFile(t *testing.T, ts *testServer, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ts.dir, name)) //nolint:gosec // test fixture
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

// TestIdentityRotation (03-08, AGENT-02, Codex 03-07 MEDIUM and
// suggestion): rotation survives a lost answer, a crash before the POST,
// and polls running at the same time.
func TestIdentityRotation(t *testing.T) {
	newRot := func(t *testing.T) (*testServer, *rotServer) {
		t.Helper()
		rs := &rotServer{}
		ts := newTestServer(t, rs.handler)
		rs.current = ts.f.spkiHex
		return ts, rs
	}
	t.Run("rotated", func(t *testing.T) {
		ts, rs := newRot(t)
		old := ts.f.spkiHex
		oldKey := keyFile(t, ts, IdentityKeyFile)
		if err := ts.f.RotateIdentity(t.Context()); err != nil {
			t.Fatal(err)
		}
		if ts.f.spkiHex == old || rs.current != ts.f.spkiHex || bytes.Equal(keyFile(t, ts, IdentityKeyFile), oldKey) || keyFile(t, ts, IdentityNextFile) != nil {
			t.Fatalf("after the rotation: identity %s (was %s), server %s, identity.next left: %v", ts.f.spkiHex, old, rs.current, keyFile(t, ts, IdentityNextFile) != nil)
		}
		if st, err := os.Stat(filepath.Join(ts.dir, IdentityKeyFile)); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("identity.key mode %v (%v)", st.Mode(), err)
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("a poll with the new identity: %v", err)
		}
	})
	t.Run("rotation_response_lost_recovers", func(t *testing.T) {
		ts, rs := newRot(t)
		rs.dropNext = true
		if err := ts.f.RotateIdentity(t.Context()); err == nil {
			t.Fatal("a dropped answer reported success")
		}
		next := keyFile(t, ts, IdentityNextFile)
		if next == nil || rs.rotated != 1 {
			t.Fatalf("identity.next %v, rotations %d", next != nil, rs.rotated)
		}
		// The old certificate is unknown now; the next poll tries
		// identity.next, gets 200 and promotes it.
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("the poll after a lost answer: %v", err)
		}
		if !bytes.Equal(keyFile(t, ts, IdentityKeyFile), next) || keyFile(t, ts, IdentityNextFile) != nil || ts.f.spkiHex != rs.current {
			t.Fatal("identity.next was not promoted")
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("a later poll: %v", err)
		}
	})
	t.Run("rotation_never_sent_old_still_works", func(t *testing.T) {
		ts, rs := newRot(t)
		old := keyFile(t, ts, IdentityKeyFile)
		ts.f.cfg.Fault = func(p string) error {
			if p == "rotate-before-post" {
				return errors.New("stopped before the POST")
			}
			return nil
		}
		if err := ts.f.RotateIdentity(t.Context()); err == nil {
			t.Fatal("a rotation stopped before the POST reported success")
		}
		ts.f.cfg.Fault = nil
		if keyFile(t, ts, IdentityNextFile) == nil {
			t.Fatal("no identity.next before the POST")
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("the old identity after a rotation that never reached the server: %v", err)
		}
		if !bytes.Equal(keyFile(t, ts, IdentityKeyFile), old) || keyFile(t, ts, IdentityNextFile) != nil || rs.refused != 0 {
			t.Fatalf("after the poll: key changed %v, identity.next left %v, refused %d", !bytes.Equal(keyFile(t, ts, IdentityKeyFile), old), keyFile(t, ts, IdentityNextFile) != nil, rs.refused)
		}
		if err := ts.f.RotateIdentity(t.Context()); err != nil {
			t.Fatalf("the next rotation: %v", err)
		}
		if rs.current != ts.f.spkiHex {
			t.Fatal("the next rotation did not take")
		}
	})
	t.Run("rotation_concurrent_with_poll", func(t *testing.T) {
		ts, rs := newRot(t)
		// A second fetcher on the same directories is the separate
		// --rotate-identity process.
		other, err := New(ts.f.cfg)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 20 {
				if err := ts.f.Once(t.Context()); err != nil {
					errs <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 5 {
				if err := other.RotateIdentity(t.Context()); err != nil {
					errs <- err
				}
			}
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent poll and rotation: %v", err)
		}
		rs.mu.Lock()
		defer rs.mu.Unlock()
		if rs.refused != 0 || rs.rotated != 5 {
			t.Fatalf("%d requests with an unknown identity, %d rotations", rs.refused, rs.rotated)
		}
	})
}

// TestUnknownAgentLoggedAtError is owner decision D-R1 (PR #72 review
// C12): when the server no longer knows the agent's identity (rotated
// away by whoever holds its key, or forgotten), the fetcher logs that at
// error level, journald priority 3, once, so the host's own journal shows
// that it has been cut off.
func TestUnknownAgentLoggedAtError(t *testing.T) {
	t.Setenv("JOURNAL_STREAM", "8:12345")
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"unknown_agent"}`))
	})
	var log bytes.Buffer
	ts.f.cfg.Log = &log
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	_ = ts.f.Run(ctx)
	out := log.String()
	if !strings.HasPrefix(out, "<3>keyroster-agent-fetch: ERROR unknown_agent: ") || strings.Count(out, "unknown_agent") != 1 {
		t.Fatalf("the fetcher's log for an unknown identity, want one <3> ERROR unknown_agent line:\n%s", out)
	}
}
