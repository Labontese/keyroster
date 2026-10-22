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
	"github.com/Labontese/keyroster/internal/serverdb"
)

// Config configures a Server.
type Config struct {
	// SignerSocket is keyroster-signer's Unix socket.
	SignerSocket string
	// RPID is the WebAuthn RP ID the server started with, the one its TLS
	// certificate was checked against (required). A signer status whose
	// policy names another RP ID is refused until the server restarts.
	RPID string
	// Clock is the time source of the status cache (nil: time.Now).
	Clock func() time.Time
	// Logger receives every log line of the Server and its handlers
	// (nil: discarded).
	Logger *slog.Logger
	// DB is the server state database (required): pending accounts,
	// invites and used admin nonces. Nothing in it is authority.
	DB *serverdb.DB
	// Limits are the rate limits of the admin, invite and sign-in routes
	// (zero fields: the defaults).
	Limits Limits
}

// Server serves keyroster's pages and API.
type Server struct {
	signer  signerAPI
	rpID    string
	clock   func() time.Time
	log     *slog.Logger
	db      *serverdb.DB
	pages   map[string]*template.Template
	static  fs.FS
	handler http.Handler

	adminLimit      *limiter  // admin API routes
	inviteLimit     *limiter  // invite pages
	signInLimit     *limiter  // sign-in begin and finish, per client, with a global backstop
	signInUserLimit *limiter  // sign-in begin and finish, per user name
	mirror          dirMirror // the installed directory, as of the last Status that matched

	// pendingMu orders a directory install (its pending check, forward
	// and cleanup) against a reinvite (its lookups and write), so neither
	// runs inside the other (02-09-R2-F1). It is always the outermost
	// lock: a handler takes it after requireAdmin, and nothing that holds
	// mu or the mirror's lock takes it. It orders requests inside this
	// process only.
	pendingMu sync.Mutex

	mu       sync.Mutex  // guards status and inflight; never held across a signer call
	status   *statusView // nil when there is no current entry
	inflight *refresh    // the status refresh in flight, or nil
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
	if cfg.RPID == "" {
		return nil, errors.New("server: no RP ID")
	}
	if cfg.DB == nil {
		return nil, errors.New("server: no state database")
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	static, err := staticFS()
	if err != nil {
		return nil, err
	}
	lim := cfg.Limits.withDefaults()
	s := &Server{
		signer: sg, rpID: cfg.RPID, clock: cfg.Clock, log: cfg.Logger, db: cfg.DB, pages: pages, static: static,
		adminLimit:  newLimiter(lim.AdminPerMinute, lim.AdminBurst, 0, 0), // per client only (Limits)
		inviteLimit: newLimiter(lim.InvitePerMinute, lim.InviteBurst, globalFactor*lim.InvitePerMinute, globalFactor*lim.InviteBurst),
		// Sign-in is its own route class (02-10): per client with the
		// global backstop, and per user name with none.
		signInLimit:     newLimiter(lim.SignInPerMinute, lim.SignInBurst, globalFactor*lim.SignInPerMinute, globalFactor*lim.SignInBurst),
		signInUserLimit: newLimiter(lim.SignInUserPerMinute, lim.SignInUserBurst, 0, 0),
	}
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
	mux.Handle("POST "+serverclient.AdminUsersPath, s.rateLimited(s.adminLimit, false, s.requireAdmin(http.HandlerFunc(s.handleAddUser))))
	mux.Handle("GET "+serverclient.AdminUsersPath+"/{name}/pending", s.rateLimited(s.adminLimit, false, s.requireAdmin(http.HandlerFunc(s.handlePendingCredentials))))
	// The directory (02-09): the users list, the mirror, and the install,
	// the only route that names its own body limit.
	mux.Handle("GET "+serverclient.AdminUsersPath, s.rateLimited(s.adminLimit, false, s.requireAdmin(http.HandlerFunc(s.handleListUsers))))
	mux.Handle("GET "+serverclient.AdminDirectoryPath, s.rateLimited(s.adminLimit, false, s.requireAdmin(http.HandlerFunc(s.handleGetDirectory))))
	mux.Handle("POST "+serverclient.AdminDirectoryPath, s.rateLimited(s.adminLimit, false, s.requireAdminLimit(maxDirectoryInstallBody, http.HandlerFunc(s.handleInstallDirectory))))
	mux.Handle("GET /enroll/{token}", s.rateLimited(s.inviteLimit, true, http.HandlerFunc(s.handleEnroll)))
	// The registration ceremony of an invite (02-08): JSON routes in the
	// invite class, under the same limiter as the invite page.
	mux.Handle("POST "+enrollBeginPath, s.rateLimited(s.inviteLimit, false, http.HandlerFunc(s.handleEnrollBegin)))
	mux.Handle("POST "+enrollFinishPath, s.rateLimited(s.inviteLimit, false, http.HandlerFunc(s.handleEnrollFinish)))
	// Web sign-in (02-10): the passkey ceremony, the read-only account
	// page and logout. The two JSON routes apply the sign-in limiters
	// themselves, so their 429 is logged as a sign-in event. A session
	// authorizes nothing but GET /account.
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST "+signInBeginPath, s.handleSignInBegin)
	mux.HandleFunc("POST "+signInFinishPath, s.handleSignInFinish)
	mux.Handle("GET /account", s.withSession(s.handleAccount))
	mux.HandleFunc("POST /logout", s.handleLogout)
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
