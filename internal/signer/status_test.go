//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// serveStatusSigner opens its own handle on e's state database (the caller
// closes logEnv's own first), builds a Signer that allows the test's own
// uid, and serves it on a socket in a short temporary directory. stop
// cancels Serve, waits for it to return (which flushes the refusal
// counts) and requires a nil error; it leaves the database open.
func serveStatusSigner(t *testing.T, e *logEnv) (sock string, s *Signer, db *signerdb.DB, stop func()) {
	t.Helper()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err = New(Config{Backend: e.backend, DB: db, AllowUIDs: []uint32{uint32(os.Getuid())}, Logger: slog.New(slog.DiscardHandler)}) //nolint:gosec // G115: a uid fits uint32
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "krst")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = filepath.Join(dir, "s.sock")
	l, err := Listen(sock, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, l) }()
	stopped := false
	stop = func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-served; err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}
	t.Cleanup(stop)
	return sock, s, db, stop
}

// requireStatusOf requires a Status reply over sock that reports the keys
// ca-init recorded (in role order) and exactly the trust_bundle row of
// version want.
func requireStatusOf(t *testing.T, sock string, db *signerdb.DB, want uint64) {
	t.Helper()
	ctx := context.Background()
	st, err := signerclient.Status(ctx, sock)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	row, err := db.LatestBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.BundleVersion != want || row.Version != want || !bytes.Equal(st.Bundle, row.Bundle) || !bytes.Equal(st.Policy, row.Policy) ||
		!bytes.Equal(st.BundleSigs, row.BundleSigs) || !bytes.Equal(st.PolicySigs, row.PolicySigs) {
		t.Fatalf("Status reports bundle version %d (row %d), want %d with the row's bundle, policy and signatures", st.BundleVersion, row.Version, want)
	}
	caKeys, err := db.CAKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Keys) != len(initRoles) {
		t.Fatalf("Status reports %d keys, want %d", len(st.Keys), len(initRoles))
	}
	for i, role := range initRoles {
		k := st.Keys[i]
		for _, c := range caKeys {
			if c.Role != string(role) {
				continue
			}
			pub, err := ssh.ParsePublicKey(c.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if k.Role != c.Role || k.Alg != c.Alg || k.Custody != c.Custody || k.Fingerprint != ssh.FingerprintSHA256(pub) {
				t.Fatalf("Status key %d = %+v, want the ca-init record %s %s %s %s", i, k, c.Role, c.Alg, c.Custody, ssh.FingerprintSHA256(pub))
			}
		}
	}
	if st.DirectoryVersion != 0 || st.DirectorySHA256 != [32]byte{} || st.DirectoryAuthorized {
		t.Fatalf("Status reports directory %d %x %v, want none", st.DirectoryVersion, st.DirectorySHA256, st.DirectoryAuthorized)
	}
}

// TestStatusTrustChanged (02-05-R2-F10, T-02-120): after a bundle install
// under the running signer (by a process that bypassed the state-directory
// lock), Status refuses trust_changed through the real socket, handle and
// signerclient.Status, and records each refusal (D-14); after a restart it
// reports the new bundle.
func TestStatusTrustChanged(t *testing.T) {
	e := newLogEnv(t)
	e.close()
	ctx := context.Background()
	sock, s, db, stop := serveStatusSigner(t, e)

	// 1. Control: the bundle the signer loaded.
	requireStatusOf(t, sock, db, 1)

	// 2. A successor installed through a second handle.
	other, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	installSuccessor(t, e, other)

	// 3. Two Status requests over the socket are refused trust_changed.
	const refused = 2
	for i := range refused {
		st, err := signerclient.Status(ctx, sock)
		var er *wire.ErrorResponse
		if st != nil || !errors.As(err, &er) || er.Code != wire.CodeUnavailable || er.Message != "trust_changed" {
			t.Fatalf("Status %d after the install = %+v, %v; want no reply and the trust_changed ErrorResponse (unavailable)", i+1, st, err)
		}
	}
	if st, err := s.Status(ctx); st != nil || !errors.Is(err, errTrustChanged) {
		t.Fatalf("Signer.Status after the install = %+v, %v; want no reply and errTrustChanged", st, err)
	}

	// 4. The refusal record: refusal leaves plus summary counts.
	stop()
	var leaves, summarized uint64
	if err := db.ForEachLeaf(ctx, func(_ uint64, raw []byte) error {
		l, err := tlog.DecodeLeaf(raw)
		if err != nil {
			return err
		}
		switch l.Kind {
		case tlog.KindRefusal:
			b, err := tlog.DecodeRefusalBody(l.Body)
			if err != nil {
				return err
			}
			if b.Detail == "trust_changed" {
				if b.Reason != tlog.ReasonUnavailable || b.RequestDigest != [32]byte{} {
					t.Errorf("trust_changed refusal leaf: reason %d digest %x, want unavailable and a zero digest", b.Reason, b.RequestDigest)
				}
				leaves++
			}
		case tlog.KindRefusalSummary:
			b, err := tlog.DecodeRefusalSummaryBody(l.Body)
			if err != nil {
				return err
			}
			for _, c := range b.Counts {
				if c.Reason == tlog.ReasonUnavailable {
					summarized += c.Count
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if leaves+summarized != refused {
		t.Fatalf("refusal record: %d trust_changed leaves + %d unavailable summary counts, want %d", leaves, summarized, refused)
	}
	t.Logf("refusal record: %d leaves, %d summarized", leaves, summarized)

	// 5. Restart: the signer loads and reports version 2.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	sock2, _, db2, _ := serveStatusSigner(t, e)
	requireStatusOf(t, sock2, db2, 2)
}

// TestStatusOverSocket: a Status request must have an empty body; one with
// a body is refused malformed_request and logged, and the next empty
// request is answered.
func TestStatusOverSocket(t *testing.T) {
	e := newLogEnv(t)
	e.close()
	sock, _, db, stop := serveStatusSigner(t, e)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(conn, wire.TypeStatus, []byte{0}); err != nil {
		t.Fatal(err)
	}
	typ, body, err := wire.ReadMessage(conn, wire.ResponseCaps(wire.TypeStatusResponse))
	_ = conn.Close()
	if err != nil || typ != wire.TypeError {
		t.Fatalf("Status with a body: type %#x, %v; want an error response", typ, err)
	}
	er, err := wire.ParseErrorResponse(body)
	if err != nil || er.Code != wire.CodeMalformed || er.Message != "malformed_request" {
		t.Fatalf("Status with a body: %+v, %v; want malformed_request", er, err)
	}
	// Control: an empty Status request is answered.
	requireStatusOf(t, sock, db, 1)
	stop()
	var found bool
	if err := db.ForEachLeaf(context.Background(), func(_ uint64, raw []byte) error {
		l, err := tlog.DecodeLeaf(raw)
		if err != nil || l.Kind != tlog.KindRefusal {
			return err
		}
		b, err := tlog.DecodeRefusalBody(l.Body)
		if err == nil && b.Detail == "malformed_request" {
			found = true
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("the refused Status request left no malformed_request refusal leaf")
	}
}

// TestStatusReportsDirectory: Status carries the installed directory's
// version, the SHA-256 of its canonical bytes and its authorization, as
// GetDirectory reports them.
func TestStatusReportsDirectory(t *testing.T) {
	e := newLoginEnv(t, newPasskeys(t), NewFixture(t, 1, 1), true, true)
	st, err := e.s.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := e.s.GetDirectory()
	if d.Version == 0 || st.DirectoryVersion != d.Version || st.DirectorySHA256 != sha256.Sum256(d.Directory) || st.DirectoryAuthorized != d.Authorized || !d.Authorized {
		t.Fatalf("Status directory %d %x %v; GetDirectory %d %x %v", st.DirectoryVersion, st.DirectorySHA256, st.DirectoryAuthorized,
			d.Version, sha256.Sum256(d.Directory), d.Authorized)
	}
}
