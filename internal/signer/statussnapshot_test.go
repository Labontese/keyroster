//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestStatusSnapshot (03-08i): readers see only whole snapshots, a reply
// shares nothing with the snapshot, the size verdict and a missing
// snapshot refuse, the setter publishes an unparsed directory state as it
// is, and a refused Status still waits for the lock to log its refusal.
func TestStatusSnapshot(t *testing.T) {
	ctx := context.Background()
	t.Run("no_torn_reply", func(t *testing.T) {
		pk := newPasskeys(t)
		fx := NewFixture(t, 1, 1)
		e := newLoginEnv(t, pk, fx, true, true)
		v1 := e.s.GetDirectory()
		type pair struct {
			version uint64
			sum     [32]byte
		}
		type doc struct{ doc, sigs []byte }
		valid := map[pair]bool{{1, sha256.Sum256(v1.Directory)}: true}
		var docs []doc
		prev := trust.SHA256Hex(v1.Directory)
		for v := uint64(2); v <= 9; v++ {
			d, sigs := signDirectory(t, loginDirectory(pk, v, prev), fx.Admins[:fx.Quorum]...)
			valid[pair{v, sha256.Sum256(d)}] = true
			docs = append(docs, doc{d, sigs})
			prev = trust.SHA256Hex(d)
		}
		const readers = 4
		var done atomic.Bool
		var wg sync.WaitGroup
		seen := make([][]pair, readers)
		errs := make([]error, readers)
		for r := range readers {
			wg.Go(func() {
				for !done.Load() {
					st, err := e.s.Status(ctx)
					if err != nil {
						errs[r] = err
						return
					}
					seen[r] = append(seen[r], pair{st.DirectoryVersion, st.DirectorySHA256})
				}
			})
		}
		for _, d := range docs {
			e.installDirectory(t, d.doc, d.sigs)
		}
		done.Store(true)
		wg.Wait()
		for r := range readers {
			if errs[r] != nil {
				t.Fatalf("reader %d: Status: %v", r, errs[r])
			}
			var last uint64
			for i, p := range seen[r] {
				if !valid[p] {
					t.Fatalf("reader %d observation %d: version %d with SHA-256 %x is not a pair of an installed version (a torn reply)", r, i, p.version, p.sum)
				}
				if p.version < last {
					t.Fatalf("reader %d observation %d: version %d after %d (a reply behind one already seen)", r, i, p.version, last)
				}
				last = p.version
			}
			t.Logf("reader %d: %d observations, last version %d", r, len(seen[r]), last)
		}
	})
	t.Run("reply_is_a_copy", func(t *testing.T) {
		e := newLogEnv(t)
		first, err := e.s.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		custody := first.Keys[0].Custody
		orig := map[string][]byte{
			"Bundle": bytes.Clone(first.Bundle), "BundleSigs": bytes.Clone(first.BundleSigs),
			"Policy": bytes.Clone(first.Policy), "PolicySigs": bytes.Clone(first.PolicySigs),
		}
		first.Keys[0].Custody = "changed by a caller"
		for _, b := range [][]byte{first.Bundle, first.BundleSigs, first.Policy, first.PolicySigs} {
			b[0] ^= 0xff
		}
		next, err := e.s.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if next.Keys[0].Custody != custody {
			t.Errorf("Keys[0].Custody = %q after a caller changed its reply, want %q", next.Keys[0].Custody, custody)
		}
		for name, got := range map[string][]byte{"Bundle": next.Bundle, "BundleSigs": next.BundleSigs, "Policy": next.Policy, "PolicySigs": next.PolicySigs} {
			if !bytes.Equal(got, orig[name]) {
				t.Errorf("%s changed in the next reply after a caller changed its own: the reply shares it with the snapshot", name)
			}
		}
	})
	t.Run("too_large_refused", func(t *testing.T) {
		e := newLogEnv(t)
		row, err := e.db.LatestBundle(ctx)
		if err != nil {
			t.Fatal(err)
		}
		big := *row
		big.Bundle = make([]byte, wire.MaxStatusFrame)
		snap := newStatusSnapshot(e.s.caKeys, &big, directoryState{})
		if !errors.Is(snap.err, wire.ErrStatusTooLarge) {
			t.Fatalf("snapshot err = %v, want wire.ErrStatusTooLarge", snap.err)
		}
		e.s.status.Store(snap)
		if st, err := e.s.Status(ctx); st != nil || !errors.Is(err, wire.ErrStatusTooLarge) {
			t.Fatalf("Status of an oversize snapshot = %+v, %v; want no reply and wire.ErrStatusTooLarge", st != nil, err)
		}
	})
	t.Run("nil_snapshot_refused", func(t *testing.T) {
		e := newLogEnv(t)
		e.s.status.Store(nil)
		st, err := e.s.Status(ctx)
		requireStateUnavailable(t, "with no snapshot", st, err)
	})
	t.Run("unparsed_state_published", func(t *testing.T) {
		e := newLogEnv(t)
		raw := []byte("a stored document that does not parse")
		unlock := lockMu(e.s)
		defer unlock()
		e.s.setDirectoryLocked(directoryState{directoryRaw: raw, directorySigs: []byte("signatures"), directoryVersion: 7})
		unlock()
		snap := e.s.status.Load()
		if snap == nil || snap.reply.DirectoryVersion != 7 || snap.reply.DirectorySHA256 != sha256.Sum256(raw) || snap.reply.DirectoryAuthorized {
			t.Fatalf("snapshot of the unparsed state = %+v; want version 7, the SHA-256 of the raw bytes, not authorized", snap)
		}
	})
	t.Run("refused_status_waits_for_refusal_log", func(t *testing.T) {
		e := newLogEnv(t)
		e.close()
		ss := newStatusSigner(t, e, e.backend, true)
		other, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		installSuccessor(t, e, other)
		unlock := lockMu(ss.s)
		defer unlock()
		ch := goStatus(func() (*wire.StatusResponse, error) { return signerclient.Status(ctx, ss.sock) })
		select {
		case a := <-ch:
			t.Fatalf("a refused Status answered within 200 ms while s.mu was held (%+v, %v): its refusal is logged under s.mu", a.st, a.err)
		case <-time.After(200 * time.Millisecond):
		}
		unlock()
		a := awaitStatus(t, ch, "refused_status_waits_for_refusal_log")
		var er *wire.ErrorResponse
		if a.st != nil || !errors.As(a.err, &er) || er.Code != wire.CodeUnavailable || er.Message != "trust_changed" {
			t.Fatalf("Status after the unlock = %+v, %v; want the trust_changed ErrorResponse (unavailable)", a.st, a.err)
		}
	})
}
