//go:build linux

package signer_test

import (
	"context"
	"database/sql"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// fakeClock is a settable signer clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Tick advances the clock by one microsecond and returns the new time. As
// a signer clock it moves only when read and never reads the wall clock:
// it is strictly increasing, so serial.Next always progresses, and a
// test's time checks no longer depend on how long the test takes.
func (c *fakeClock) Tick() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Microsecond)
	return c.t
}

// logLeaves reads every leaf of the signer's log. When the signer is
// stopped, it opens the database read-only.
func (ts *testSigner) logLeaves(t *testing.T) []tlog.Leaf {
	t.Helper()
	db := ts.DB
	if db == nil {
		ro, err := signerdb.OpenReadOnly(ts.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ro.Close() }()
		db = ro
	}
	var out []tlog.Leaf
	err := db.ForEachLeaf(context.Background(), func(_ uint64, raw []byte) error {
		l, err := tlog.DecodeLeaf(raw)
		if err != nil {
			return err
		}
		out = append(out, l)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// refusalTally counts the refusals recorded in leaves.
type refusalTally struct {
	individual []*tlog.RefusalBody
	summaries  int
	summarized uint64
	clockRegs  []*tlog.ClockRegressionBody
}

func tally(t *testing.T, leaves []tlog.Leaf) refusalTally {
	t.Helper()
	var r refusalTally
	for _, l := range leaves {
		switch l.Kind {
		case tlog.KindRefusal:
			b, err := tlog.DecodeRefusalBody(l.Body)
			if err != nil {
				t.Fatal(err)
			}
			r.individual = append(r.individual, b)
		case tlog.KindRefusalSummary:
			b, err := tlog.DecodeRefusalSummaryBody(l.Body)
			if err != nil {
				t.Fatal(err)
			}
			r.summaries++
			r.summarized += b.Total()
		case tlog.KindClockRegression:
			b, err := tlog.DecodeClockRegressionBody(l.Body)
			if err != nil {
				t.Fatal(err)
			}
			r.clockRegs = append(r.clockRegs, b)
		}
	}
	return r
}

// sendMalformed sends one frame with an unknown message type and waits for
// the signer's error response.
func (ts *testSigner) sendMalformed(t *testing.T) {
	t.Helper()
	conn, err := net.Dial("unix", ts.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(conn, wire.TypeError, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if typ, _, err := wire.ReadMessage(conn); err != nil || typ != wire.TypeError {
		t.Fatalf("response type %#x, %v; want an error response", typ, err)
	}
}

// TestRefusalFloodIsSummarized (D-14): with the default rate (10 per
// minute, burst 10), 1000 refusals inside one instant yield 10 individual
// refusal leaves; the other 990 are counted and written as one
// refusal_summary leaf when the signer shuts down. Every refusal also
// leaves one slog record with its reason and peer uid.
func TestRefusalFloodIsSummarized(t *testing.T) {
	clk := newFakeClock()
	ts := newTestSigner(t, signerOpts{clock: clk.Now})
	const total = 1000
	for range total {
		ts.sendMalformed(t)
	}
	ts.waitRefusalRecords(t, total)
	uid := strconv.Itoa(os.Getuid())
	for _, rec := range ts.reasonRecords() {
		if rec.Attrs["reason"] != "unknown_message_type" || rec.Attrs["uid"] != uid {
			t.Fatalf("refusal record %+v, want reason unknown_message_type and uid %s", rec.Attrs, uid)
		}
	}
	before := tally(t, ts.logLeaves(t))
	if before.summaries != 0 {
		t.Fatalf("%d summary leaves before the window was flushed", before.summaries)
	}

	ts.stop() // graceful shutdown flushes the pending counts
	got := tally(t, ts.logLeaves(t))
	if len(got.individual) != 10 || got.summaries != 1 {
		t.Fatalf("%d individual refusal leaves and %d summaries, want 10 and 1", len(got.individual), got.summaries)
	}
	if n := uint64(len(got.individual)) + got.summarized; n != total {
		t.Fatalf("individual %d + summarized %d = %d, want %d", len(got.individual), got.summarized, n, total)
	}
	for _, b := range got.individual {
		if b.Reason != tlog.ReasonMalformed || b.Detail != "unknown_message_type" ||
			b.RequestDigest != ([32]byte{}) || strconv.FormatUint(uint64(b.PeerUID), 10) != uid {
			t.Fatalf("refusal leaf %+v", b)
		}
	}
}

// TestRefusalRateRefills: one refusal every 60 ms of signer time for 60 s
// refills the bucket at 10 per minute: 10 (burst) + 9 refills are logged
// individually, and the rest are summarized.
func TestRefusalRateRefills(t *testing.T) {
	clk := newFakeClock()
	ts := newTestSigner(t, signerOpts{clock: clk.Now})
	const total = 1000
	for range total {
		ts.sendMalformed(t)
		clk.Add(60 * time.Millisecond)
	}
	ts.waitRefusalRecords(t, total)
	ts.stop()
	got := tally(t, ts.logLeaves(t))
	if len(got.individual) != 19 {
		t.Fatalf("%d individual refusal leaves, want 19", len(got.individual))
	}
	if n := uint64(len(got.individual)) + got.summarized; n != total {
		t.Fatalf("individual + summarized = %d, want %d", n, total)
	}
}

// TestRefusalLeavesCarryDigestAndPeer: a decoded request is logged with its
// digest; a peer-credential rejection with a zero digest and the peer uid.
func TestRefusalLeavesCarryDigestAndPeer(t *testing.T) {
	t.Run("bad_principal", func(t *testing.T) {
		ts := newTestSigner(t, signerOpts{})
		req := newRequest(t, "*")
		_, err := ts.issue(req)
		wantErrorResponse(t, err, wire.CodeRefused, "bad_principal")
		got := tally(t, ts.logLeaves(t))
		if len(got.individual) != 1 {
			t.Fatalf("%d refusal leaves, want 1", len(got.individual))
		}
		b := got.individual[0]
		if b.Reason != tlog.ReasonBadPrincipal || b.Detail != "bad_principal" || b.RequestDigest != req.Digest() {
			t.Fatalf("refusal leaf %+v, want bad_principal with the request digest", b)
		}
	})
	t.Run("peer_not_allowed", func(t *testing.T) {
		uid := uint32(os.Getuid()) //nolint:gosec // G115: a uid fits uint32
		ts := newTestSigner(t, signerOpts{allowSet: true, allowUIDs: []uint32{uid + 1}})
		conn, err := net.Dial("unix", ts.Socket)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		ts.waitRefusalRecords(t, 1)
		deadline := time.Now().Add(5 * time.Second)
		var got refusalTally
		for time.Now().Before(deadline) {
			if got = tally(t, ts.logLeaves(t)); len(got.individual) == 1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if len(got.individual) != 1 {
			t.Fatalf("%d refusal leaves, want 1", len(got.individual))
		}
		b := got.individual[0]
		if b.Reason != tlog.ReasonPeerNotAllowed || b.PeerUID != uid || b.RequestDigest != ([32]byte{}) {
			t.Fatalf("refusal leaf %+v, want peer_not_allowed for uid %d with a zero digest", b, uid)
		}
	})
}

// TestRefusalClockRegressionEpisodes (D-14, CA-03): a clock below the
// serial high-water mark refuses issuance; the first refusal of an episode
// also appends one clock_regression leaf, later ones in the same episode
// are ordinary refusals, and the next successful issuance ends the episode.
func TestRefusalClockRegressionEpisodes(t *testing.T) {
	clk := newFakeClock()
	start := clk.Now()
	ts := newTestSigner(t, signerOpts{clock: clk.Now})
	hwm := uint64(start.Add(time.Hour).UnixMicro()) //nolint:gosec // G115: after 1970
	if err := ts.DB.WithTx(context.Background(), func(tx *sql.Tx) error { return ts.DB.SetLastSerial(tx, hwm) }); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, err := ts.issue(requestAt(t, clk))
		wantErrorResponse(t, err, wire.CodeUnavailable, "clock_regression")
	}
	got := tally(t, ts.logLeaves(t))
	if len(got.clockRegs) != 1 {
		t.Fatalf("%d clock_regression leaves after one episode, want 1", len(got.clockRegs))
	}
	if b := got.clockRegs[0]; b.HighWaterMicros != hwm || b.NowMicros != uint64(start.UnixMicro()) { //nolint:gosec // G115: after 1970
		t.Fatalf("clock_regression leaf %+v, want now %d below high-water %d", b, start.UnixMicro(), hwm)
	}
	if len(got.individual) != 3 {
		t.Fatalf("%d refusal leaves, want 3 (every clock_regression refusal)", len(got.individual))
	}

	clk.Set(start.Add(2 * time.Hour)) // the clock recovers: the episode ends at this issuance
	if _, err := ts.issue(requestAt(t, clk)); err != nil {
		t.Fatalf("issuance after the clock recovered: %v", err)
	}
	clk.Set(start.Add(90 * time.Minute)) // and regresses again: a new episode
	_, err := ts.issue(requestAt(t, clk))
	wantErrorResponse(t, err, wire.CodeUnavailable, "clock_regression")
	if got := tally(t, ts.logLeaves(t)); len(got.clockRegs) != 2 {
		t.Fatalf("%d clock_regression leaves after two episodes, want 2", len(got.clockRegs))
	}
}

// TestRefusalReasonCodes: the reason classes D-14 names exist.
func TestRefusalReasonCodes(t *testing.T) {
	want := map[uint8]string{
		tlog.ReasonPeerNotAllowed:   "peer_not_allowed",
		tlog.ReasonMalformed:        "malformed",
		tlog.ReasonCANotConfigured:  "ca_not_configured",
		tlog.ReasonBadPrincipal:     "bad_principal",
		tlog.ReasonBadSubjectKey:    "bad_subject_key",
		tlog.ReasonTTLExceeded:      "ttl_exceeded",
		tlog.ReasonStaleRequest:     "stale_request",
		tlog.ReasonDuplicateRequest: "duplicate_request",
		tlog.ReasonClockRegression:  "clock_regression",
	}
	for code, name := range want {
		if got := tlog.ReasonName(code); got != name {
			t.Errorf("ReasonName(%d) = %q, want %q", code, got, name)
		}
	}
}

// requestAt is newRequest created at the fake clock's time.
func requestAt(t *testing.T, clk *fakeClock) *wire.IssueRequest {
	t.Helper()
	req := newRequest(t, "alice")
	req.CreatedAt = uint64(clk.Now().Unix()) //nolint:gosec // G115: after 1970
	return req
}
