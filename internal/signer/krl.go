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

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// publishKRLLocked rebuilds the KRL from the whole revocation table inside
// tx and publishes it as the next version: krl.Encode with now as its
// generated_date, a manifest {installation ID of the bundle in force,
// version, SHA-256, issued_at = now in whole seconds, bundle version, the
// index the krl_publish leaf takes} signed by the ops key under
// krl.Namespace, the KRL state row, and the krl_publish leaf. A KRL above
// krl.MaxKRL is refused krl_too_large, which rolls the whole transaction
// back, so the revocation table never holds an entry no published KRL
// carries. The caller holds s.mu and runs tx through logTx.
func (s *Signer) publishKRLLocked(ctx context.Context, tx *sql.Tx, now time.Time) (*signerdb.KRLState, uint64, error) {
	if s.installationID == "" {
		return nil, 0, refusalErr(wire.CodeUnavailable, "krl_no_installation_id", nil)
	}
	revs, err := s.db.RevocationsTx(ctx, tx)
	if err != nil {
		return nil, 0, err
	}
	set, err := revocationSet(revs)
	if err != nil {
		return nil, 0, err
	}
	prev, err := s.db.KRLStateTx(ctx, tx)
	if err != nil {
		return nil, 0, err
	}
	version := uint64(1)
	if prev != nil {
		version = prev.Version + 1
	}
	data, err := krl.Encode(set, version, now)
	if err != nil {
		if errors.Is(err, krl.ErrTooLarge) {
			return nil, 0, refusalErr(wire.CodeUnavailable, "krl_too_large", err)
		}
		return nil, 0, refusalErr(wire.CodeInternal, "krl_encoding", err)
	}
	issued := now.UTC().Truncate(time.Second)
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
		IssuedAtSeconds: uint64(max(issued.Unix(), 0)), //nolint:gosec // G115: >= 0
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

// revocationSet groups the serial revocations by CA key.
func revocationSet(revs []signerdb.Revocation) (krl.Set, error) {
	var (
		set   krl.Set
		index = map[string]int{} // CA key wire bytes -> position in set.Certs
	)
	for _, r := range revs {
		if r.Kind != signerdb.RevocationSerial {
			// The key_id and key kinds arrive with 03-03; a row this
			// version cannot put into the KRL must not be dropped silently.
			return krl.Set{}, fmt.Errorf("signer: revocation %d has kind %q, which this version cannot publish", r.ID, r.Kind)
		}
		i, ok := index[string(r.CAKey)]
		if !ok {
			pub, err := ssh.ParsePublicKey(r.CAKey)
			if err != nil {
				return krl.Set{}, fmt.Errorf("signer: revocation %d: CA key: %w", r.ID, err)
			}
			i = len(set.Certs)
			index[string(r.CAKey)] = i
			set.Certs = append(set.Certs, krl.CertSerials{CAKey: pub})
		}
		set.Certs[i].Serials = append(set.Certs[i].Serials, r.Serial)
	}
	return set, nil
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
// signature, or an empty response when none is published.
func (s *Signer) GetKRL() *wire.GetKRLResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.krl == nil {
		return &wire.GetKRLResponse{}
	}
	return &wire.GetKRLResponse{
		KRL:      bytes.Clone(s.krl.KRL),
		Manifest: bytes.Clone(s.krl.Manifest),
		Sig:      bytes.Clone(s.krl.Sig),
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
	s.krl = st
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
