package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// publishKRLLocked rebuilds the KRL from the whole revocation table inside
// tx and publishes it as the next version. One clock reading, now, gives
// issued_at (now in whole seconds) and the KRL's generated_date. The set
// is built by krl.PublishSet from every revocation row, whichever CA keys
// the bundle in force trusts, so only entries no longer live at issued_at
// leave it, and a row whose valid_before is unknown never does. The
// version is max(prev + 1, issued_at), prev being the published version
// (0 before the first): a restored signer with a correct clock publishes
// above every version it lost (owner decision 2026-10-25, Q1). Then
// krl.Encode, a manifest {installation ID of the bundle in force, version,
// SHA-256, issued_at, bundle version, the index the krl_publish leaf
// takes} signed by the ops key under krl.Namespace, the KRL state row, and
// the krl_publish leaf. A KRL above krl.MaxKRL is refused krl_too_large
// (buildKRLLocked), which rolls the whole transaction back. Rows that are
// not exactly the logged revoke entries are refused revocations_not_logged
// before the ops key signs, and the signer stops. The caller holds s.mu
// and runs tx through logTx.
//
// The invariant kept (03-10): every transaction that writes a revocation
// row (Revoke, RecoverRevocations and a Negative ProbeIssue) encodes the
// whole publish set in that transaction, through buildKRLLocked here or
// checkKRLFitsLocked, so the committed row set always encodes within
// krl.MaxKRL at the commit's clock. A row that rides waits for the next
// publish, which carries it because expiry only shrinks the set (a clock
// that steps back can bring entries back: accepted, untested).
func (s *Signer) publishKRLLocked(ctx context.Context, tx *sql.Tx, now time.Time) (*signerdb.KRLState, uint64, error) {
	b, err := s.buildKRLLocked(ctx, tx, now)
	if err != nil {
		return nil, 0, err
	}
	revs, issued, issuedAt, version, data := b.revs, b.issued, b.issuedAt, b.version, b.data
	// The start-up check (loggedRevocations.check) does not cover a row
	// deleted, written or changed through another database handle while
	// the signer runs: the KRL built from such rows would un-revoke a
	// certificate or publish an unlogged entry under the ops key. So the
	// rows read in tx must be exactly the entries of the logged revoke
	// leaves, this transaction's included, before the ops key signs. It
	// runs after Encode so a KRL too large is still krl_too_large; Encode
	// signs nothing. logTx stops the signer on a mismatch.
	logged := s.pendingRevoked
	if logged == nil {
		logged = s.loaded.revoked
	}
	if err := logged.check(revs); err != nil {
		return nil, 0, refusalErr(wire.CodeUnavailable, "revocations_not_logged", err)
	}
	m := krl.Manifest{
		InstallationID: s.installationID,
		KRLVersion:     version,
		KRLSHA256:      krl.SHA256Hex(data),
		IssuedAt:       issued.Format(trust.TimeFormat),
		BundleVersion:  s.bundleVersion,
		LogIndex:       s.nextLeafIndexLocked(),
	}
	manifest, err := m.Canonical()
	if err != nil {
		return nil, 0, refusalErr(wire.CodeInternal, "krl_encoding", err)
	}
	sig, err := sshsig.Sign(rand.Reader, s.opsKey, krl.Namespace, manifest)
	if err != nil {
		return nil, 0, refusalErr(wire.CodeUnavailable, "ops_key_unavailable", err)
	}
	st := signerdb.KRLState{Version: version, KRL: data, Manifest: manifest, Sig: sig, PublishedAt: now}
	if err := s.db.PutKRLStateTx(tx, st); err != nil {
		return nil, 0, err
	}
	body, err := (&tlog.KRLPublishBody{
		KRLVersion:      version,
		BundleVersion:   s.bundleVersion,
		IssuedAtSeconds: issuedAt,
		SHA256:          sha256.Sum256(data),
		Manifest:        manifest,
		Sig:             sig,
	}).Encode()
	if err != nil {
		return nil, 0, refusalErr(wire.CodeInternal, "log_encoding", err)
	}
	idx, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindKRLPublish, Body: body})
	if err != nil {
		return nil, 0, err
	}
	if idx != m.LogIndex {
		return nil, 0, fmt.Errorf("signer: krl_publish leaf took index %d, the manifest names %d", idx, m.LogIndex)
	}
	return &st, idx, nil
}

// builtKRL is what buildKRLLocked encodes: the rows it read, the publish
// time in whole seconds (as a time and as Unix seconds), the version and
// the KRL bytes.
type builtKRL struct {
	revs     []signerdb.Revocation
	issued   time.Time
	issuedAt uint64
	version  uint64
	data     []byte
}

// buildKRLLocked is everything publishKRLLocked does before the
// logged-rows check (03-10): the krl_no_installation_id refusal, the rows
// read in tx, krl.PublishSet at now in whole seconds, the next version and
// krl.Encode, with krl.ErrTooLarge mapped to krl_too_large and any other
// encoding error to krl_encoding. It signs and writes nothing. It is the
// signer's one size rule: publishKRLLocked and checkKRLFitsLocked both
// call it. The caller holds s.mu.
func (s *Signer) buildKRLLocked(ctx context.Context, tx *sql.Tx, now time.Time) (*builtKRL, error) {
	if s.installationID == "" {
		return nil, refusalErr(wire.CodeUnavailable, "krl_no_installation_id", nil)
	}
	revs, err := s.db.RevocationsTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	issued := now.UTC().Truncate(time.Second)
	issuedAt := uint64(max(issued.Unix(), 0)) //nolint:gosec // G115: >= 0
	set, err := krl.PublishSet(revocationEntries(revs), issuedAt)
	if err != nil {
		return nil, refusalErr(wire.CodeInternal, "krl_encoding", err)
	}
	prev, err := s.db.KRLStateTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	var prevVersion uint64
	if prev != nil {
		prevVersion = prev.Version
	}
	version := max(prevVersion+1, issuedAt)
	data, err := krl.Encode(set, version, now)
	if err != nil {
		if errors.Is(err, krl.ErrTooLarge) {
			return nil, refusalErr(wire.CodeUnavailable, "krl_too_large", err)
		}
		return nil, refusalErr(wire.CodeInternal, "krl_encoding", err)
	}
	return &builtKRL{revs: revs, issued: issued, issuedAt: issuedAt, version: version, data: data}, nil
}

// checkKRLFitsLocked requires the whole publish set of tx to encode within
// krl.MaxKRL at now (krl_too_large otherwise), through buildKRLLocked, and
// discards the result: it signs and writes nothing (03-10). A Negative
// probe issuance whose row rides the hourly publish or waits for the
// prompt flag runs it in its own transaction. The caller holds s.mu.
func (s *Signer) checkKRLFitsLocked(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := s.buildKRLLocked(ctx, tx, now)
	return err
}

// revocationEntries maps the revocation rows to the entries krl.PublishSet
// builds a KRL from. A row's valid_before is in microseconds (0, from
// NULL, when not known); the entry takes it in whole seconds.
func revocationEntries(revs []signerdb.Revocation) []krl.Entry {
	kinds := map[string]uint8{
		signerdb.RevocationSerial: krl.EntrySerial,
		signerdb.RevocationKeyID:  krl.EntryKeyID,
		signerdb.RevocationKey:    krl.EntryKey,
	}
	out := make([]krl.Entry, 0, len(revs))
	for _, r := range revs {
		out = append(out, krl.Entry{
			Kind:        kinds[r.Kind], // an unknown kind maps to 0, which PublishSet refuses
			CAKey:       r.CAKey,
			Serial:      r.Serial,
			KeyID:       r.KeyID,
			Key:         r.Key,
			ValidBefore: r.ValidBeforeMicros / uint64(time.Second/time.Microsecond),
		})
	}
	return out
}

// D-10: the signer re-publishes the KRL by itself, so a frozen server
// shows through the KRL's signed issued_at.
const (
	// krlRepublishAfter is the age of the last publish at which the
	// signer publishes the next version with an unchanged set.
	krlRepublishAfter = time.Hour
	// krlCheckInterval is how often krlLoop checks that age.
	krlCheckInterval = time.Minute
)

// krlLoop runs republishIfDue on every tick of the KRL ticker (every
// krlCheckInterval unless a test set newKRLTicker) until ctx is done.
// Serve runs the first check itself, before it accepts any connection.
func (s *Signer) krlLoop(ctx context.Context) {
	newTicker := s.newKRLTicker
	if newTicker == nil {
		newTicker = func() (<-chan time.Time, func()) {
			t := time.NewTicker(krlCheckInterval)
			return t.C, t.Stop
		}
	}
	tick, stop := newTicker()
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			s.republishIfDue(ctx)
		}
	}
}

// republishIfDue publishes the next KRL version, by the rules of every
// publish and with the set otherwise unchanged, when the bundle in force
// has an installation ID and either no KRL is published or the last
// publish is at least krlRepublishAfter old on the signer's clock, or
// dated after it (D-10; pre-merge review of PR #61).
// It runs under s.mu in one logTx, with the trust check every request
// makes, so a signer still running after another bundle was installed
// publishes nothing. A failure is logged at error level and retried at the
// next check; it never stops the signer. It reports whether it published.
func (s *Signer) republishIfDue(ctx context.Context) bool {
	// installationID is fixed for the life of the process, so a signer
	// that publishes nothing never waits for s.mu here.
	if s.installationID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	// A negative age (the last publish is dated after the clock: it ran
	// ahead and was corrected) is due too: waiting until the clock passed
	// it would keep serving a KRL whose future issued_at looks fresh.
	// The probe prompt flag (03-10) skips the wait for a young publish
	// while a negative probe certificate is still unpublished and the last
	// probe-caused publish is at least krlCheckInterval old (a clock that
	// went back counts as old enough), so two probe-caused versions are
	// never closer than a minute. A flagged tick that is too early
	// publishes nothing and leaves the flag set.
	prompted := false
	if st := s.krl.Load(); st != nil {
		if age := now.Sub(st.PublishedAt); age >= 0 && age < krlRepublishAfter {
			if !s.probePrompt || !s.loaded.probes.hasUnpublishedNegative() || probePublishTooRecent(s.lastProbePublish, now) {
				return false
			}
			prompted = true
		}
	}
	var (
		published *signerdb.KRLState
		leaf      uint64
	)
	err := s.logTx(ctx, func(tx *sql.Tx) error {
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
		}
		var err error
		published, leaf, err = s.publishKRLLocked(ctx, tx, now)
		return err
	})
	if err != nil {
		s.log.Error("KRL publish failed; retrying at the next check", "error", err.Error())
		return false
	}
	s.publishedLocked(published)
	if prompted {
		s.lastProbePublish = now
	}
	s.log.Info("KRL published", "krl_version", published.Version, "publish_leaf", leaf, "probe_prompt", prompted)
	return true
}

// publishedLocked installs st, the KRL a committed publish wrote, as the
// one GetKRL serves, and clears the probe prompt flag: every publish
// encodes the whole revocation table, so it carries every negative row the
// flag was set for, whichever path published (pre-merge review of PR #90).
// It leaves lastProbePublish alone. The caller holds s.mu.
func (s *Signer) publishedLocked(st *signerdb.KRLState) {
	s.krl.Store(st)
	s.probePrompt = false
}

// probePublishTooRecent reports whether the last probe-caused publish at
// last is younger than krlCheckInterval at now; none (zero) and a clock
// that went back count as old enough (03-10).
func probePublishTooRecent(last, now time.Time) bool {
	if last.IsZero() {
		return false
	}
	age := now.Sub(last)
	return age >= 0 && age < krlCheckInterval
}

// nextLeafIndexLocked returns the index the next appended leaf takes in
// the open transaction (or in the committed log when nothing is pending).
// The caller holds s.mu.
func (s *Signer) nextLeafIndexLocked() uint64 {
	if s.pending != nil {
		return s.pending.Size()
	}
	return s.tree.Size()
}

// GetKRL returns the published KRL in force with its manifest and
// signature, or an empty response when none is published. It does not
// take s.mu (see Signer.krl).
func (s *Signer) GetKRL() *wire.GetKRLResponse {
	st := s.krl.Load()
	if st == nil {
		return &wire.GetKRLResponse{}
	}
	return &wire.GetKRLResponse{
		KRL:      bytes.Clone(st.KRL),
		Manifest: bytes.Clone(st.Manifest),
		Sig:      bytes.Clone(st.Sig),
	}
}

// loadKRL reads the published KRL at start. The stored state must be
// exactly what the verified log's last krl_publish entry records (the same
// version, KRL SHA-256, manifest and signature), or the signer refuses to
// start (krl_state_not_logged).
func (s *Signer) loadKRL(ctx context.Context) error {
	st, err := s.db.KRLState(ctx)
	if err != nil {
		return err
	}
	if err := checkKRLLogged(st, s.loaded.lastKRLPublish); err != nil {
		return err
	}
	s.krl.Store(st)
	if st != nil {
		s.log.Info("KRL loaded", "krl_version", st.Version, "sha256", krl.SHA256Hex(st.KRL))
	}
	return nil
}

// errKRLNotLogged is the krl_state_not_logged start-up refusal.
var errKRLNotLogged = fmt.Errorf("%w: krl_state_not_logged", errLogMismatch)

// checkKRLLogged requires the stored KRL state (nil when none is stored)
// to be exactly what publish, the body of the last krl_publish leaf of the
// verified log (nil when there is none), records.
func checkKRLLogged(st *signerdb.KRLState, publish []byte) error {
	switch {
	case st == nil && publish == nil:
		return nil
	case st == nil:
		return fmt.Errorf("%w: the log records a published KRL, but the state database holds none", errKRLNotLogged)
	case publish == nil:
		return fmt.Errorf("%w: KRL version %d is stored, but the log records no krl_publish entry", errKRLNotLogged, st.Version)
	}
	body, err := tlog.DecodeKRLPublishBody(publish)
	if err != nil {
		return fmt.Errorf("%w: last krl_publish entry: %w", errKRLNotLogged, err)
	}
	if body.KRLVersion != st.Version || body.SHA256 != sha256.Sum256(st.KRL) ||
		!bytes.Equal(body.Manifest, st.Manifest) || !bytes.Equal(body.Sig, st.Sig) {
		return fmt.Errorf("%w: the stored KRL (version %d) is not the one the last krl_publish entry records (version %d)",
			errKRLNotLogged, st.Version, body.KRLVersion)
	}
	return nil
}
