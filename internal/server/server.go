// Package server is keyroster-server: the untrusted web front that
// proposes but never decides. It serves server-rendered pages and a small
// JSON API over HTTPS, and takes every fact about the signer (relying
// party, policy, custody, directory) from the signer's own Status, never
// from its own configuration (D-09, D-18).
package server

import (
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// Config configures a Server.
type Config struct {
	// SignerSocket is keyroster-signer's Unix socket.
	SignerSocket string
	// Clock is the time source of the status cache (nil: time.Now).
	Clock func() time.Time
	// Logger receives every log line of the Server and its handlers
	// (nil: discarded).
	Logger *slog.Logger
}

// Server serves keyroster's pages and API.
type Server struct {
	signer  signerAPI
	clock   func() time.Time
	log     *slog.Logger
	pages   map[string]*template.Template
	static  fs.FS
	handler http.Handler

	mu     sync.Mutex  // held for a whole status refresh
	status *statusView // nil when there is no current entry
}

// New builds a Server that reaches the signer at cfg.SignerSocket.
func New(cfg Config) (*Server, error) {
	if cfg.SignerSocket == "" {
		return nil, errors.New("server: no signer socket")
	}
	return newServer(cfg, socketSigner{socket: cfg.SignerSocket})
}

// newServer builds a Server on sg; tests pass fakeSigner.
func newServer(cfg Config, sg signerAPI) (*Server, error) {
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	static, err := staticFS()
	if err != nil {
		return nil, err
	}
	s := &Server{signer: sg, clock: cfg.Clock, log: cfg.Logger, pages: pages, static: static}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/", s.handleStatic)
	mux.HandleFunc("GET "+serverclient.TrustPath, s.handleTrust)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.handler = secure(mux)
	return s, nil
}

// Handler returns the Server's HTTP handler, with the security headers and
// cross-origin protection applied to every route.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	v, err := s.currentStatus(r.Context())
	if err != nil {
		s.signerUnavailable(w, true)
		return
	}
	d := statusPage(v, v.rp.RPID)
	d.RPID = v.rp.RPID
	d.BundleVersion = v.raw.BundleVersion
	d.PolicyVersion = v.policy.Version
	d.DirectoryVersion = v.raw.DirectoryVersion
	d.Keys = v.raw.Keys
	s.renderPage(w, v, http.StatusOK, "index", d)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	ctype, ok := staticTypes[path.Ext(name)]
	if !ok || !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(s.static, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(data) //nolint:gosec // G705: an embedded asset with an explicit type and nosniff, not request data

}

func (s *Server) handleTrust(w http.ResponseWriter, r *http.Request) {
	v, err := s.currentStatus(r.Context())
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	st := v.raw
	resp := serverclient.TrustResponse{
		Bundle:           st.Bundle,
		BundleSigs:       st.BundleSigs,
		Policy:           st.Policy,
		PolicySigs:       st.PolicySigs,
		BundleVersion:    st.BundleVersion,
		DirectoryVersion: st.DirectoryVersion,
		Custody:          make([]serverclient.KeyCustody, 0, len(st.Keys)),
	}
	for _, k := range st.Keys {
		resp.Custody = append(resp.Custody, serverclient.KeyCustody{Role: k.Role, Alg: k.Alg, Custody: k.Custody, Fingerprint: k.Fingerprint})
	}
	s.writeJSON(w, v, http.StatusOK, resp)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	v, err := s.currentStatus(r.Context())
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	s.writeJSON(w, v, http.StatusOK, map[string]string{"status": "ok"})
}
