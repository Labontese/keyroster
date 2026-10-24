package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

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
)

// handleRevoke serves POST /api/v1/admin/revoke (03-01, REVOKE-01). The
// server holds no revocation authority: it parses the admin-signed
// RevokeRequest strictly (so a malformed one is 400, not a signer
// failure) and forwards it to the signer unchanged; the signer verifies
// the policy admin's SSHSIG and decides alone. A refusal is 400 for a
// malformed request or a serial the signer does not know, 403 for every
// other refusal, each with the signer's reason code, and 503 when the
// signer could not decide.
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
				s.signerUnavailable(w, false)
			}
			return
		}
		// The outcome is unknown: the signer may have revoked.
		s.log.Error("revocation: signer call failed, outcome unknown", "admin", admin, "serial", req.Serial, "err", err)
		s.signerUnavailable(w, false)
		return
	}
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
// relays. The answer is never cached.
func (s *Server) handleKRL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	defer cancel()
	resp, err := s.signer.GetKRL(cctx)
	if err != nil {
		s.log.Warn("KRL read failed", "err", err)
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
