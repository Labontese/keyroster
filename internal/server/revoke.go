package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/wire"
)

const (
	// maxRevokeBody is the body limit of POST AdminRevokePath: a
	// RevokeRequest is at most a few hundred bytes plus MaxEvidence armored
	// signatures, far below 16 KiB in base64 and JSON.
	maxRevokeBody = 16 << 10

	// krlPerMinute and krlBurst are the per-client rate of GET KRLPath;
	// the global backstop is globalFactor times them.
	krlPerMinute = 60
	krlBurst     = 30

	// krlTTL is how long a KRL read from the signer is served from the
	// cache. A revocation through this server drops the entry before it
	// answers (dropKRL), unless the signer refused it as malformed or
	// refused, which publishes nothing; any other change, such as a
	// signer restarted on another state database, is served at most
	// krlTTL late.
	krlTTL = 5 * time.Second
)

// handleRevoke serves POST /api/v1/admin/revoke (03-01, REVOKE-01). The
// server holds no revocation authority: it parses the admin-signed
// RevokeRequest strictly (so a malformed one is 400, not a signer
// failure) and forwards it to the signer unchanged; the signer verifies
// the policy admin's SSHSIG and decides alone. A refusal is 400 for a
// malformed request or a serial the signer does not know, 403 for every
// other refusal, each with the signer's reason code, and 503 when the
// signer could not decide. Every answer but those 400 and 403 refusals
// drops the cached KRL, since the signer may have published.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body serverclient.RevokeBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() {
		s.writeAdminError(w, r, http.StatusBadRequest, "malformed request")
		return
	}
	req, err := wire.ParseRevokeRequest(body.Request)
	if err != nil {
		s.writeAdminError(w, r, http.StatusBadRequest, "malformed request")
		return
	}
	ctx := r.Context()
	admin := adminName(ctx)
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	defer cancel()
	resp, err := s.signer.Revoke(cctx, req)
	if err != nil {
		var refused *wire.ErrorResponse
		if errors.As(err, &refused) {
			s.log.Warn("revocation refused", "admin", admin, "serial", req.Serial, "reason", refused.Message)
			switch refused.Code {
			case wire.CodeMalformed:
				s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: refused.Message})
			case wire.CodeRefused:
				s.writeJSON(w, v, http.StatusForbidden, serverclient.APIError{Error: refused.Message})
			default:
				// A malformed or refused request was decided before
				// the transaction or rolled back inside it; any other
				// answer (state_unavailable after a failed COMMIT
				// that reached the disk, say) may follow a publish.
				s.dropKRL()
				s.signerUnavailable(w, false)
			}
			return
		}
		// The outcome is unknown: the signer may have revoked.
		s.log.Error("revocation: signer call failed, outcome unknown", "admin", admin, "serial", req.Serial, "err", err)
		s.dropKRL()
		s.signerUnavailable(w, false)
		return
	}
	// The signer published a new KRL version: the CLI reads it right
	// after this answer, so the cached older one must not be served.
	s.dropKRL()
	s.log.Info("revoked", "admin", admin, "serial", req.Serial, "ca", req.CARole.String(),
		"krl_version", resp.KRLVersion, "revoke_leaf", resp.RevokeLeaf, "publish_leaf", resp.PublishLeaf)
	s.writeJSON(w, v, http.StatusOK, serverclient.RevokeAnswer{
		KRLVersion: resp.KRLVersion, RevokeLeaf: resp.RevokeLeaf, PublishLeaf: resp.PublishLeaf,
	})
}

// handleKRL serves GET /api/v1/krl: the KRL the signer published, its
// manifest and the ops key's signature, or 404 no_krl before the first
// publish. Authority is the ops-key signature, which every reader checks
// against its root-pinned bundle (krl.VerifyManifest); the server only
// relays the bytes, unchanged. The route is unauthenticated, so the
// signer's answer is cached (currentKRL) rather than asked for on every
// request; HTTP clients are still told not to cache it.
func (s *Server) handleKRL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	resp, err := s.currentKRL(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if len(resp.KRL) == 0 {
		s.writeJSON(w, v, http.StatusNotFound, serverclient.APIError{Error: serverclient.KRLErrNone})
		return
	}
	s.writeJSON(w, v, http.StatusOK, serverclient.KRLDocument{KRL: resp.KRL, Manifest: resp.Manifest, Sig: resp.Sig})
}

// krlView is one GetKRL answer and when it was read. It is shared by
// every request served from it and never modified.
type krlView struct {
	resp    *wire.GetKRLResponse
	fetched time.Time
}

// krlRefresh is one GetKRL call in flight. done closes when it has
// ended; resp and err are its result, set before done closes.
type krlRefresh struct {
	done chan struct{}
	resp *wire.GetKRLResponse
	err  error
}

// currentKRL returns the published KRL as currentStatus returns the
// status: an entry younger than krlTTL comes from the cache; otherwise one
// refresh asks the signer, and every caller that arrives while it is in
// flight waits for it and takes its result, a failure included, so a
// burst of requests makes at most one signer call. A failed refresh is
// never cached.
func (s *Server) currentKRL(ctx context.Context) (*wire.GetKRLResponse, error) {
	s.mu.Lock()
	now := s.clock()
	if k := s.krl; k != nil {
		if age := now.Sub(k.fetched); age >= 0 && age < krlTTL {
			s.mu.Unlock()
			return k.resp, nil
		}
	}
	s.krl = nil
	r := s.krlInflight
	if r == nil {
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		r = &krlRefresh{done: make(chan struct{})}
		s.krlInflight = r
		// Detached, as for the status refresh.
		go s.refreshKRL(context.WithoutCancel(ctx), r, now)
	}
	s.mu.Unlock()
	select {
	case <-r.done:
		return r.resp, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// refreshKRL asks the signer for the published KRL, bounded by
// signerCallTimeout; ctx must carry no cancellation. It stores a good
// answer as the cache entry and hands the result to every caller waiting
// on r.
func (s *Server) refreshKRL(ctx context.Context, r *krlRefresh, now time.Time) {
	rctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	defer cancel()
	resp, err := s.signer.GetKRL(rctx)
	if err == nil && resp == nil {
		err = errors.New("empty signer KRL answer")
	}
	if err != nil {
		s.log.Warn("KRL read failed", "err", err)
		resp = nil
	}
	s.mu.Lock()
	if err == nil {
		s.krl = &krlView{resp: resp, fetched: now}
	}
	s.krlInflight = nil
	r.resp, r.err = resp, err
	s.mu.Unlock()
	close(r.done)
}

// dropKRL removes the cached KRL, so the next GET asks the signer again.
// Like dropStatus it first waits for the refresh in flight, if any, so a
// KRL read before a revocation can never be put back after the drop.
func (s *Server) dropKRL() {
	s.mu.Lock()
	r := s.krlInflight
	s.mu.Unlock()
	if r != nil {
		<-r.done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.krl = nil
}
