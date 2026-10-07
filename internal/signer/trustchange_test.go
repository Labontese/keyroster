package signer

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
)

// signHookBackend is a memBackend whose keys call hooks[fingerprint] before
// every signature, and count their signatures.
type signHookBackend struct {
	*memBackend
	mu    sync.Mutex
	hooks map[string]func()
	signs map[string]int
}

func newSignHookBackend(inner *memBackend) *signHookBackend {
	return &signHookBackend{memBackend: inner, hooks: map[string]func(){}, signs: map[string]int{}}
}

type hookKey struct {
	keystore.CAKey
	b  *signHookBackend
	fp string
}

func (k hookKey) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	k.b.mu.Lock()
	hook := k.b.hooks[k.fp]
	k.b.signs[k.fp]++
	k.b.mu.Unlock()
	if hook != nil {
		hook()
	}
	return k.CAKey.Sign(r, data)
}

func (b *signHookBackend) Key(role keystore.Role, fp string) (keystore.CAKey, error) {
	k, err := b.memBackend.Key(role, fp)
	if err != nil {
		return nil, err
	}
	return hookKey{k, b, fp}, nil
}

func (b *signHookBackend) count(fp string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.signs[fp]
}

// installSuccessor installs version 2 of the bundle (policy version 2)
// through db, a second handle on the state database, as an install-bundle
// process would.
func installSuccessor(t *testing.T, e *logEnv, db *signerdb.DB) {
	t.Helper()
	sb, err := db.LatestBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ie := &installEnv{fx: e.fx, db: db, be: e.backend}
	prev := ie.genesis(t)
	if sb.Version != 1 || prev.Version != 1 {
		t.Fatalf("installed bundle version %d, want 1", sb.Version)
	}
	pol := policyV2(t, e.fx)
	if _, err := ie.install(nil, 0, docs4(t, successor(t, prev, pol), pol, e.fx.Root)); err != nil {
		t.Fatalf("install successor: %v", err)
	}
}

// issueLeavesAfterLastInstall returns the number of issue leaves logged
// after the last bundle_install entry.
func issueLeavesAfterLastInstall(t *testing.T, db *signerdb.DB) int {
	t.Helper()
	n := 0
	err := db.ForEachLeaf(context.Background(), func(_ uint64, raw []byte) error {
		l, err := tlog.DecodeLeaf(raw)
		if err != nil {
			return err
		}
		switch l.Kind {
		case tlog.KindBundleInstall:
			n = 0
		case tlog.KindIssue:
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestTrustChangedUnderLiveSigner (A-CR-01, C-CR-01): a successor bundle
// installed while a signer serves, bypassing the state directory lock,
// makes that signer refuse every request with trust_changed instead of
// issuing under the superseded policy. The log stays verifiable, and after
// a restart the signer issues under the new policy.
func TestTrustChangedUnderLiveSigner(t *testing.T) {
	e := newLogEnv(t)
	if _, err := e.issue(); err != nil {
		t.Fatal(err)
	}
	other, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	installSuccessor(t, e, other)
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		resp, refused := e.s.issueOrRefuse(context.Background(), Peer{UID: 1000}, e.request())
		if resp != nil || refused == nil || refused.Message != "trust_changed" {
			t.Fatalf("request %d after the live successor install: response %+v, refusal %+v; want trust_changed", i, resp, refused)
		}
	}
	if n := issueLeavesAfterLastInstall(t, e.db); n != 0 {
		t.Fatalf("%d issue leaves after the successor's bundle_install, want 0", n)
	}
	if rep := e.verifyExport(); rep.PolicyVersion != 2 || rep.Serials != 1 {
		t.Fatalf("export after the refused requests: %+v", rep)
	}

	e.close()
	if err := e.open(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if v := e.s.PolicyVersion(); v != 2 {
		t.Fatalf("policy version after restart %d, want 2", v)
	}
	resp, err := e.issue()
	if err != nil {
		t.Fatalf("issue after restart: %v", err)
	}
	c, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if kid := c.(*ssh.Certificate).KeyId; !strings.Contains(kid, "/pol=2/") {
		t.Fatalf("key ID %q after restart, want pol=2", kid)
	}
	if rep := e.verifyExport(); rep.PolicyVersion != 2 || rep.Serials != 2 {
		t.Fatalf("export after restart: %+v", rep)
	}
}

// TestTrustChangedDuringIssue (A-CR-01): the bundle check inside the
// issuance transaction holds until COMMIT. A successor installed while the
// CA key signs (after the pre-check) still refuses the request, and the
// signed certificate is dropped.
func TestTrustChangedDuringIssue(t *testing.T) {
	e := newLogEnv(t)
	e.close()
	be := newSignHookBackend(e.backend)
	userFP := ssh.FingerprintSHA256(e.fx.Roles[keystore.RoleUser].PublicKey())
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Config{Backend: be, DB: db, AllowUIDs: []uint32{1000}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	other, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	var once sync.Once
	be.hooks[userFP] = func() { once.Do(func() { installSuccessor(t, e, other) }) }

	resp, refused := s.issueOrRefuse(context.Background(), Peer{UID: 1000}, e.request())
	if resp != nil || refused == nil || refused.Message != "trust_changed" {
		t.Fatalf("request with a successor installed while signing: response %+v, refusal %+v; want trust_changed", resp, refused)
	}
	if be.count(userFP) != 1 {
		t.Fatalf("user CA signed %d times, want 1 (the dropped certificate)", be.count(userFP))
	}
	if n := issueLeavesAfterLastInstall(t, db); n != 0 {
		t.Fatalf("%d issue leaves after the successor's bundle_install, want 0", n)
	}
	var issued int
	if err := db.WithTx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM issuance`).Scan(&issued)
	}); err != nil || issued != 0 {
		t.Fatalf("%d issuance rows (%v), want 0", issued, err)
	}
}

// TestReplayRefusedBeforeSigning (A-WR-04): a replayed request (same
// request id, validly signed, within the freshness window) is refused as
// duplicate_request before a serial is allocated and before the CA key
// signs, so a replay costs no CA operation (and no PIV touch).
func TestReplayRefusedBeforeSigning(t *testing.T) {
	e := newLogEnv(t)
	e.close()
	be := newSignHookBackend(e.backend)
	userFP := ssh.FingerprintSHA256(e.fx.Roles[keystore.RoleUser].PublicKey())
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(Config{Backend: be, DB: db, AllowUIDs: []uint32{1000}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	req := e.request()
	if _, err := s.Issue(context.Background(), Peer{UID: 1000}, req); err != nil {
		t.Fatal(err)
	}
	if n := be.count(userFP); n != 1 {
		t.Fatalf("user CA signed %d times for one issuance, want 1", n)
	}
	last, err := db.LastSerial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		resp, refused := s.issueOrRefuse(context.Background(), Peer{UID: 1000}, req)
		if resp != nil || refused == nil || refused.Message != "duplicate_request" {
			t.Fatalf("replay: response %+v, refusal %+v; want duplicate_request", resp, refused)
		}
	}
	if n := be.count(userFP); n != 1 {
		t.Fatalf("user CA signed %d times after three replays, want 1 (no signature for a replay)", n)
	}
	if got, err := db.LastSerial(context.Background()); err != nil || got != last {
		t.Fatalf("serial high-water mark %d (%v) after the replays, want %d", got, err, last)
	}
}
