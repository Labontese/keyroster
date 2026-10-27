package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
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
	// krlTTL late. The value is serverclient's, which the e2e suite
	// waits out.
	krlTTL = serverclient.KRLMaxStale
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
			s.log.Warn("revocation refused", append(append([]any{"admin", admin}, revokeTarget(req)...), "reason", refused.Message)...)
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
		s.log.Error("revocation: signer call failed, outcome unknown", append(append([]any{"admin", admin}, revokeTarget(req)...), "err", err)...)
		s.dropKRL()
		s.signerUnavailable(w, false)
		return
	}
	// The signer published a new KRL version: the CLI reads it right
	// after this answer, so the cached older one must not be served.
	s.dropKRL()
	s.log.Info("revoked", append(append([]any{"admin", admin}, revokeTarget(req)...),
		"krl_version", resp.KRLVersion, "revoke_leaf", resp.RevokeLeaf, "publish_leaf", resp.PublishLeaf, "serial_count", resp.SerialCount)...)
	// SerialCount and Serials pass through unchanged: the CLI prints them
	// and checks that the KRL it verified lists each serial (03-03b).
	s.writeJSON(w, v, http.StatusOK, serverclient.RevokeAnswer{
		KRLVersion: resp.KRLVersion, RevokeLeaf: resp.RevokeLeaf, PublishLeaf: resp.PublishLeaf,
		SerialCount: resp.SerialCount, Serials: resp.Serials,
	})
}

// revokeTarget is the log attributes naming a revocation's target: its
// kind, then the CA role and serial of a serial target, the CA role and
// key ID of a key ID target and the subject kind and subject of a subject
// target (a key target logs only its kind). Serial is 0 for every target
// but serial, so it is logged only there.
func revokeTarget(req *wire.RevokeRequest) []any {
	switch req.Target {
	case wire.TargetSerial:
		return []any{"target", "serial", "ca", req.CARole.String(), "serial", req.Serial}
	case wire.TargetKeyID:
		return []any{"target", "key_id", "ca", req.CARole.String(), "key_id", req.KeyID}
	case wire.TargetKey:
		return []any{"target", "key"}
	case wire.TargetSubject:
		return []any{"target", "subject", "subject_kind", req.SubjectKind.String(), "subject", req.Subject}
	}
	return []any{"target", "unknown"}
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
// signerCallTimeout; ctx must carry no cancellation. A published KRL is
// kept (keepKRL) before it is served. It stores a good answer as the cache
// entry and hands the result to every caller waiting on r; an answer it
// could not keep is never cached, and the route answers 503.
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
	} else if len(resp.KRL) > 0 && s.krlFile != "" {
		if err = s.keepKRL(rctx, resp); err != nil {
			s.log.Error(err.Error())
			resp = nil
		}
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

// servedKRL is the KRL document the server last kept and served: its
// version and the exact JSON handleKRL writes for it (without the final
// newline).
type servedKRL struct {
	version uint64
	doc     []byte
}

// loadServedKRL reads the durable copy at path at start: nil when there is
// none yet, an error when it does not parse (strict KRLDocument JSON, then
// krl.ParseManifest of its manifest), which stops keyroster-server.
func loadServedKRL(path string) (*servedKRL, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator's state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("server: read %s: %w", path, err)
	}
	refuse := func(err error) error {
		return fmt.Errorf("server: %s does not parse: %w. It is the last KRL this server served and the restore source for lost revocations: "+
			"keep it, do not delete it, and see docs/runbooks/server-install.md", path, err)
	}
	doc, err := serverclient.DecodeKRLDocument(data)
	if err != nil {
		return nil, refuse(err)
	}
	m, err := krl.ParseManifest(doc.Manifest)
	if err != nil {
		return nil, refuse(err)
	}
	enc, err := json.Marshal(doc)
	if err != nil {
		return nil, refuse(err)
	}
	return &servedKRL{version: m.KRLVersion, doc: enc}, nil
}

// keepKRL keeps resp, a published KRL the signer answered, before any
// route serves it (03-06b): it must verify (krl.VerifyManifest) against
// the trust bundle of the signer's status and that bundle's installation
// ID; then a version above the one this server served (or the first) is
// written to the durable copy, exactly the KRLDocument JSON handleKRL
// serves (keepKRLFile), and the same version with the same bytes writes
// nothing. A lower version, or the same version with other bytes, is
// refused: hosts keep their last KRL instead (D-10), and the log says why.
// The copy is never replaced by a lower or equal version.
func (s *Server) keepKRL(ctx context.Context, resp *wire.GetKRLResponse) error {
	v, err := s.currentStatus(ctx)
	if err != nil {
		return fmt.Errorf("KRL not served: it does not verify: the signer status is unavailable: %w", err)
	}
	b, err := trust.ParseBundle(v.raw.Bundle)
	if err != nil {
		return fmt.Errorf("KRL not served: it does not verify: the signer's trust bundle does not parse: %w", err)
	}
	m, err := krl.VerifyManifest(resp.Manifest, resp.Sig, resp.KRL, b, b.InstallationID, 0)
	if err != nil {
		return fmt.Errorf("KRL not served: it does not verify against the signer's trust bundle v%d: %w", b.Version, err)
	}
	doc, err := json.Marshal(serverclient.KRLDocument{KRL: resp.KRL, Manifest: resp.Manifest, Sig: resp.Sig})
	if err != nil {
		return fmt.Errorf("KRL not kept: %w", err)
	}
	s.mu.Lock()
	prev := s.served
	s.mu.Unlock()
	if prev != nil {
		switch {
		case m.KRLVersion == prev.version && bytes.Equal(doc, prev.doc):
			return nil
		case m.KRLVersion < prev.version:
			return fmt.Errorf("KRL not served: version %d is below version %d this server served (a signer restored without the recovery? signer-install.md)",
				m.KRLVersion, prev.version)
		case m.KRLVersion == prev.version:
			return fmt.Errorf("KRL not served: version %d has other bytes than the version %d this server served", m.KRLVersion, prev.version)
		}
	}
	if err := keepKRLFile(s.krlFile, append(doc, '\n')); err != nil {
		return fmt.Errorf("KRL not kept: %w", err)
	}
	s.mu.Lock()
	s.served = &servedKRL{version: m.KRLVersion, doc: doc}
	s.mu.Unlock()
	return nil
}

// keepKRLFile replaces path with data durably: a temporary file in the
// same directory (created with O_EXCL and mode 0600), written and synced,
// renamed over path, then the directory synced. Windows cannot sync a
// directory handle, so that step is skipped there: keyroster-server runs
// only on Linux, and this package's tests also run on Windows.
func keepKRLFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".krl-served-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	done := false
	defer func() {
		if !done {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	done = true
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the state directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
