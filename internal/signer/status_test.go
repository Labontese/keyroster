//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// serveStatusSigner opens its own handle on e's state database (the caller
// closes logEnv's own first) and a read-only one passed as StatusDB
// (03-08i), builds a Signer that allows the test's own uid, and serves it on a socket in a short temporary directory. stop
// cancels Serve, waits for it to return (which flushes the refusal
// counts) and requires a nil error; it leaves the database open.
func serveStatusSigner(t *testing.T, e *logEnv) (sock string, s *Signer, db *signerdb.DB, stop func()) {
	t.Helper()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sdb, err := signerdb.OpenReadOnly(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	s, err = New(Config{Backend: e.backend, DB: db, StatusDB: sdb, AllowUIDs: []uint32{uint32(os.Getuid())}, Logger: slog.New(slog.DiscardHandler)}) //nolint:gosec // G115: a uid fits uint32
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

// statusSigner is a Signer built by newStatusSigner, with its own handles
// on a logEnv's state database (03-08i).
type statusSigner struct {
	s    *Signer
	db   *signerdb.DB // the main handle
	sdb  *signerdb.DB // the read-only handle passed as StatusDB
	sock string       // "" when not served
}

// newStatusSigner (03-08i) builds a Signer on be over its own main handle
// of e's state database and a read-only handle on it (signerdb.OpenReadOnly,
// passed as Config.StatusDB), allowing the test's own uid, with Clock
// e.clock. The caller closes logEnv's own handle first; e.close() sets e.s
// to nil, so a test uses the returned Signer and its mu. With serve set,
// it serves the Signer on a socket in a short temporary directory, with a
// KRL ticker that never fires, and waits for one answered Status: Serve
// runs its first republishIfDue before it accepts a connection, so after
// that answer nothing but the call under test signs. Serve is stopped, and
// the handles closed (the read-only one first), at cleanup.
func newStatusSigner(t *testing.T, e *logEnv, be keystore.Backend, serve bool) *statusSigner {
	t.Helper()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sdb, err := signerdb.OpenReadOnly(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	s, err := New(Config{Backend: be, DB: db, StatusDB: sdb, Clock: e.clock,
		AllowUIDs: []uint32{uint32(os.Getuid())}, Logger: slog.New(slog.DiscardHandler)}) //nolint:gosec // G115: a uid fits uint32
	if err != nil {
		t.Fatal(err)
	}
	ss := &statusSigner{s: s, db: db, sdb: sdb}
	if !serve {
		return ss
	}
	s.newKRLTicker = func() (<-chan time.Time, func()) { return make(chan time.Time), func() {} }
	dir, err := os.MkdirTemp("", "krsl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ss.sock = filepath.Join(dir, "s.sock")
	l, err := Listen(ss.sock, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	if _, err := signerclient.Status(sctx, ss.sock); err != nil {
		t.Fatalf("the first Status of the served signer: %v", err)
	}
	return ss
}

// statusAnswer is one Status call's result.
type statusAnswer struct {
	st  *wire.StatusResponse
	err error
}

// goStatus runs call in a goroutine that reports only through the
// returned buffered channel.
func goStatus(call func() (*wire.StatusResponse, error)) <-chan statusAnswer {
	ch := make(chan statusAnswer, 1)
	go func() {
		st, err := call()
		ch <- statusAnswer{st, err}
	}()
	return ch
}

// awaitStatus waits for one answer of ch, failing the test after 10 s with
// a message naming what.
func awaitStatus(t *testing.T, ch <-chan statusAnswer, what string) statusAnswer {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no answer within 10 s (Status waits for the signer's lock or its main connection)", what)
		return statusAnswer{}
	}
}

// armGate arms a one-shot gate on be's key fp (03-08i): the first
// signature with that key signals entered and blocks until release is
// called. release is Once-guarded, so a test can defer it and call it.
func armGate(be *signHookBackend, fp string) (entered <-chan struct{}, release func()) {
	ent, rel := make(chan struct{}), make(chan struct{})
	var first, once sync.Once
	be.mu.Lock()
	be.hooks[fp] = func() {
		first.Do(func() {
			close(ent)
			<-rel
		})
	}
	be.mu.Unlock()
	return ent, func() { once.Do(func() { close(rel) }) }
}

// issueAnswer is one issueOrRefuse call's result.
type issueAnswer struct {
	resp    *wire.IssueResponse
	refused *wire.ErrorResponse
}

// goIssue runs an admin issue of req on s in a goroutine that reports only
// through the returned buffered channel. req is built by the caller, in
// the test goroutine (logEnv.request calls t.Fatal).
func goIssue(s *Signer, req *wire.IssueRequest) <-chan issueAnswer {
	ch := make(chan issueAnswer, 1)
	go func() {
		resp, refused := s.issueOrRefuse(context.Background(), Peer{UID: uint32(os.Getuid())}, req) //nolint:gosec // G115: a uid fits uint32
		ch <- issueAnswer{resp, refused}
	}()
	return ch
}

// awaitIssue waits for the issue's answer, failing after 10 s.
func awaitIssue(t *testing.T, ch <-chan issueAnswer, what string) issueAnswer {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: the issue never returned within 10 s", what)
		return issueAnswer{}
	}
}

// awaitEntered waits for a gate's first signature, failing after 10 s.
func awaitEntered(t *testing.T, entered <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: the issue never reached the gated signature within 10 s", what)
	}
}

// lockMu takes s.mu and returns a conditional unlock to defer and call.
func lockMu(s *Signer) func() {
	s.mu.Lock()
	locked := true
	return func() {
		if locked {
			locked = false
			s.mu.Unlock()
		}
	}
}

// statusSummary renders a Status reply for a failure message: its
// bundle and directory versions, the directory's SHA-256 and whether it is
// authorized, or "no reply".
func statusSummary(st *wire.StatusResponse) string {
	if st == nil {
		return "no reply"
	}
	return fmt.Sprintf("bundle %d, directory %d %x authorized %v", st.BundleVersion, st.DirectoryVersion, st.DirectorySHA256, st.DirectoryAuthorized)
}

// requireStateUnavailable requires err to be a state_unavailable refusal
// (CodeUnavailable) and st no reply.
func requireStateUnavailable(t *testing.T, what string, st *wire.StatusResponse, err error) {
	t.Helper()
	var r *refusal
	if st != nil || !errors.As(err, &r) || r.code != wire.CodeUnavailable || r.reason != "state_unavailable" {
		t.Fatalf("%s: Status = %s, %v; want no reply and a state_unavailable refusal (unavailable)", what, statusSummary(st), err)
	}
}

// TestStatusLockFree (03-08i): Signer.Status takes no lock and reads
// nothing through the signer's main database handle, so it answers at
// once from the snapshot published after COMMIT while a signature holds
// s.mu: the CA key's in cert.Build, outside the transaction, or the log
// key's checkpoint signature inside it. A bundle installed under the
// running signer is refused trust_changed at once through the read-only
// handle, also while s.mu is held, and a missing or failing handle
// refuses state_unavailable.
func TestStatusLockFree(t *testing.T) {
	ctx := context.Background()
	t.Run("answers_with_mu_held", func(t *testing.T) {
		e := newLoginEnv(t, newPasskeys(t), NewFixture(t, 1, 1), true, true)
		d := e.s.GetDirectory()
		unlock := lockMu(e.s)
		defer unlock()
		a := awaitStatus(t, goStatus(func() (*wire.StatusResponse, error) { return e.s.Status(ctx) }), "answers_with_mu_held")
		if a.err != nil || a.st.BundleVersion != 1 || a.st.DirectoryVersion != 1 || a.st.DirectorySHA256 != sha256.Sum256(d.Directory) || !a.st.DirectoryAuthorized {
			t.Fatalf("answers_with_mu_held: Status = %s, %v; want bundle 1, directory 1 with its SHA-256, authorized", statusSummary(a.st), a.err)
		}
	})
	for _, tc := range []struct {
		name string
		role keystore.Role
	}{
		{"answers_during_ca_signature", keystore.RoleUser},
		{"answers_during_log_key_signature", keystore.RoleLog},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLogEnv(t)
			e.close()
			be := newSignHookBackend(e.backend)
			ss := newStatusSigner(t, e, be, true)
			fp := ssh.FingerprintSHA256(e.fx.Roles[tc.role].PublicKey())
			before := be.count(fp)
			req := e.request()
			entered, release := armGate(be, fp)
			defer release()
			issued := goIssue(ss.s, req)
			awaitEntered(t, entered, tc.name)
			sock := goStatus(func() (*wire.StatusResponse, error) { return signerclient.Status(ctx, ss.sock) })
			direct := goStatus(func() (*wire.StatusResponse, error) { return ss.s.Status(ctx) })
			if a := awaitStatus(t, sock, tc.name+" over the socket"); a.err != nil || a.st.BundleVersion != 1 {
				t.Fatalf("%s: Status over the socket = %s, %v; want bundle 1", tc.name, statusSummary(a.st), a.err)
			}
			if a := awaitStatus(t, direct, tc.name+" direct"); a.err != nil || a.st.BundleVersion != 1 {
				t.Fatalf("%s: Signer.Status = %s, %v; want bundle 1", tc.name, statusSummary(a.st), a.err)
			}
			release()
			if a := awaitIssue(t, issued, tc.name); a.resp == nil || a.refused != nil {
				t.Fatalf("%s: the issue after release = %+v, %+v; want a certificate", tc.name, a.resp, a.refused)
			}
			if n := be.count(fp) - before; n != 1 {
				t.Fatalf("%s: the gated key signed %d times, want 1 (the issuance's)", tc.name, n)
			}
		})
	}
	t.Run("successor_refused_while_mu_held", func(t *testing.T) {
		e := newLogEnv(t)
		e.close()
		ss := newStatusSigner(t, e, e.backend, false)
		if st, err := ss.s.Status(ctx); err != nil || st.BundleVersion != 1 {
			t.Fatalf("Status before the install = %s, %v; want bundle 1", statusSummary(st), err)
		}
		other, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		installSuccessor(t, e, other)
		unlock := lockMu(ss.s)
		defer unlock()
		a := awaitStatus(t, goStatus(func() (*wire.StatusResponse, error) { return ss.s.Status(ctx) }), "successor_refused_while_mu_held")
		if a.st != nil || !errors.Is(a.err, errTrustChanged) {
			t.Fatalf("successor_refused_while_mu_held: Status = %s, %v; want no reply and errTrustChanged", statusSummary(a.st), a.err)
		}
	})
	t.Run("successor_refused_during_ca_signature", func(t *testing.T) {
		const what = "successor_refused_during_ca_signature"
		e := newLogEnv(t)
		e.close()
		be := newSignHookBackend(e.backend)
		ss := newStatusSigner(t, e, be, true)
		other, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		fp := ssh.FingerprintSHA256(e.fx.Roles[keystore.RoleUser].PublicKey())
		before := be.count(fp)
		req := e.request()
		entered, release := armGate(be, fp)
		defer release()
		issued := goIssue(ss.s, req)
		awaitEntered(t, entered, what)
		// The stalled issue holds s.mu but no transaction.
		installSuccessor(t, e, other)
		sock := goStatus(func() (*wire.StatusResponse, error) { return signerclient.Status(ctx, ss.sock) })
		direct := awaitStatus(t, goStatus(func() (*wire.StatusResponse, error) { return ss.s.Status(ctx) }), what+" direct")
		if direct.st != nil || !errors.Is(direct.err, errTrustChanged) {
			t.Fatalf("%s: Signer.Status before release = %s, %v; want no reply and errTrustChanged", what, statusSummary(direct.st), direct.err)
		}
		release()
		// The socket refusal is logged under s.mu, so it answers only now.
		a := awaitStatus(t, sock, what+" over the socket")
		var er *wire.ErrorResponse
		if a.st != nil || !errors.As(a.err, &er) || er.Code != wire.CodeUnavailable || er.Message != "trust_changed" {
			t.Fatalf("%s: Status over the socket = %s, %v; want the trust_changed ErrorResponse (unavailable)", what, statusSummary(a.st), a.err)
		}
		if i := awaitIssue(t, issued, what); i.resp != nil || i.refused == nil || i.refused.Message != "trust_changed" {
			t.Fatalf("%s: the issue after release = %+v, %+v; want trust_changed", what, i.resp, i.refused)
		}
		if n := be.count(fp) - before; n != 1 {
			t.Fatalf("%s: the user CA signed %d times, want 1 (the dropped certificate)", what, n)
		}
	})
	t.Run("status_db_missing_or_failing_refuses", func(t *testing.T) {
		e := newLogEnv(t)
		e.close()
		// No StatusDB.
		db, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		bare, err := New(Config{Backend: e.backend, DB: db, AllowUIDs: []uint32{1000}, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		st, err := bare.Status(ctx)
		requireStateUnavailable(t, "without StatusDB", st, err)
		// StatusDB equal to DB.
		if s, err := New(Config{Backend: e.backend, DB: db, StatusDB: db, AllowUIDs: []uint32{1000}, Logger: slog.New(slog.DiscardHandler)}); s != nil || err == nil {
			t.Fatalf("New with StatusDB equal to DB = a signer %v, %v; want no signer and an error", s != nil, err)
		}
		// A cancelled ctx, then a live one.
		ss := newStatusSigner(t, e, e.backend, false)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		st, err = ss.s.Status(cctx)
		requireStateUnavailable(t, "with a cancelled ctx", st, err)
		if st, err := ss.s.Status(ctx); err != nil || st.BundleVersion != 1 {
			t.Fatalf("Status with a live ctx after the cancelled one = %s, %v; want bundle 1", statusSummary(st), err)
		}
		// The read-only handle closed.
		if err := ss.sdb.Close(); err != nil {
			t.Fatal(err)
		}
		st, err = ss.s.Status(ctx)
		requireStateUnavailable(t, "with the read-only handle closed", st, err)
	})
	t.Run("emptied_bundle_table_refused", func(t *testing.T) {
		e := newLogEnv(t)
		execSQL(t, e.dbPath, "DELETE FROM trust_bundle")
		if st, err := e.s.Status(ctx); st != nil || !errors.Is(err, errTrustChanged) {
			t.Fatalf("Status with the trust_bundle table emptied = %s, %v; want no reply and errTrustChanged", statusSummary(st), err)
		}
	})
	t.Run("reply_carries_loaded_bundle", func(t *testing.T) {
		e := newLogEnv(t)
		row, err := e.db.LatestBundle(ctx)
		if err != nil {
			t.Fatal(err)
		}
		execSQL(t, e.dbPath, "UPDATE trust_bundle SET policy = ? WHERE version = 1", append(bytes.Clone(row.Policy), ' '))
		st, err := e.s.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.BundleVersion != row.Version || !bytes.Equal(st.Policy, row.Policy) || !bytes.Equal(st.Bundle, row.Bundle) ||
			!bytes.Equal(st.BundleSigs, row.BundleSigs) || !bytes.Equal(st.PolicySigs, row.PolicySigs) {
			t.Fatalf("Status after the policy was edited in place: version %d, policy equal to the loaded one %v; want the row the signer loaded",
				st.BundleVersion, bytes.Equal(st.Policy, row.Policy))
		}
	})
	t.Run("install_then_status_over_socket", func(t *testing.T) {
		pk := newPasskeys(t)
		fx := NewFixture(t, 1, 1)
		e := newLoginEnv(t, pk, fx, true, false)
		e.close()
		ss := newStatusSigner(t, e, e.backend, true)
		prev := trust.GenesisPrev
		for v := uint64(1); v <= 2; v++ {
			doc, sigs := signDirectory(t, loginDirectory(pk, v, prev), fx.Admins[:fx.Quorum]...)
			if _, err := signerclient.InstallDirectory(ctx, ss.sock, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}); err != nil {
				t.Fatalf("InstallDirectory of version %d: %v", v, err)
			}
			st, err := signerclient.Status(ctx, ss.sock)
			if err != nil || st.DirectoryVersion != v || st.DirectorySHA256 != sha256.Sum256(doc) || !st.DirectoryAuthorized {
				t.Fatalf("Status after the install of version %d = %s, %v; want that version with its SHA-256, authorized", v, statusSummary(st), err)
			}
			prev = trust.SHA256Hex(doc)
		}
	})
	t.Run("failed_transaction_keeps_snapshot", func(t *testing.T) {
		pk := newPasskeys(t)
		fx := NewFixture(t, 1, 1)
		e := newLoginEnv(t, pk, fx, true, true)
		v1 := e.s.GetDirectory()
		e.s.mu.Lock()
		orig := e.s.cpSigner
		e.s.cpSigner = failingSigner{orig}
		e.s.mu.Unlock()
		doc, sigs := signDirectory(t, loginDirectory(pk, 2, trust.SHA256Hex(v1.Directory)), fx.Admins[:fx.Quorum]...)
		resp, err := e.s.InstallDirectory(ctx, Peer{UID: 1000}, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs})
		var r *refusal
		if resp != nil || !errors.As(err, &r) || r.code != wire.CodeUnavailable {
			t.Fatalf("InstallDirectory with a failing checkpoint signer = %+v, %v; want an unavailable refusal", resp, err)
		}
		e.s.mu.Lock()
		e.s.cpSigner = orig
		e.s.mu.Unlock()
		st, err := e.s.Status(ctx)
		if err != nil || st.DirectoryVersion != 1 || st.DirectorySHA256 != sha256.Sum256(v1.Directory) || !st.DirectoryAuthorized {
			t.Fatalf("Status after the failed install = %s, %v; want version 1 with its SHA-256, authorized", statusSummary(st), err)
		}
	})
}
