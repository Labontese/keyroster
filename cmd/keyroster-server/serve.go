//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Labontese/keyroster/internal/server"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

const (
	// statusWait is how long start-up retries the signer's Status.
	statusWait = 30 * time.Second
	// statusRetry is the pause between two Status attempts.
	statusRetry = time.Second
	// statusAttempt bounds one Status attempt.
	statusAttempt = 3 * time.Second
	// shutdownGrace bounds a graceful shutdown.
	shutdownGrace = 5 * time.Second
	// certWatch is how often the certificate files are checked for a
	// change.
	certWatch = 60 * time.Second
)

func runServe(ctx context.Context, args []string, stderr io.Writer) error {
	// SIGHUP first (02-13-R2-F4). Until a Go program registers SIGHUP,
	// the signal ends it, and systemd does not restart a service ended by
	// SIGHUP under Restart=on-failure. The certificate unit's reload can
	// arrive while start-up still retries the signer (step 1); it waits
	// in this buffer and becomes one reload once Watch runs. Only the
	// moments before this statement are left unprotected.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":443", "TCP address to serve HTTPS on")
	certFile := fs.String("tls-cert", "", "TLS certificate chain file, leaf first (required)")
	keyFile := fs.String("tls-key", "", "TLS private key file (required)")
	socket := fs.String("signer-socket", "/run/keyroster-signer/signer.sock", "keyroster-signer Unix socket")
	stateDir := fs.String("state-dir", "/var/lib/keyroster-server", "directory of the server's state database (created 0700); nothing in it is authority")
	agentListen := fs.String("agent-listen", "", "TCP address of the agent listener (03-07): the agent routes only, a client certificate required; empty: no agent listener")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *certFile == "" || *keyFile == "" {
		_, _ = fmt.Fprintln(stderr, "serve: --tls-cert and --tls-key are required; no positional arguments")
		return errUsage
	}

	// Logger first: every line of every start-up step, the first
	// certificate load included, is one JSON object on stderr.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// 1. The signer's Status, retried for up to statusWait.
	st, err := probeStatus(ctx, *socket, logger)
	if err != nil {
		return err
	}
	// 2. The relying party comes only from the root-signed policy.
	policy, err := trust.ParsePolicy(st.Policy)
	if err != nil {
		return fmt.Errorf("the signer's policy: %w", err)
	}
	if policy.WebAuthn == nil {
		return errors.New("the installed policy has no WebAuthn RP; add it with keyroster root successor-policy (docs/runbooks/root-ceremony.md)")
	}
	rpID := policy.WebAuthn.RPID
	// 3. The certificate must cover the RP ID and be valid now.
	holder := server.NewCertHolder(server.CertConfig{CertFile: *certFile, KeyFile: *keyFile, RPID: rpID, Logger: logger})
	if err := holder.Reload("start"); err != nil {
		return err
	}

	db, err := openStateDB(*stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	// 4. The listeners: the main one for browsers and the CLI, and, with
	// --agent-listen, the agent listener (03-07), whose port minted join
	// tokens name. Both serve TLS 1.3 with the holder's certificate.
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	var al net.Listener
	agentPort := 0
	if *agentListen != "" {
		if al, err = net.Listen("tcp", *agentListen); err != nil {
			_ = l.Close()
			return err
		}
		agentPort = al.Addr().(*net.TCPAddr).Port
	}
	// krl-served.json is the last KRL document this server served, kept
	// before it is served: the restore source for lost revocations (03-06b,
	// docs/runbooks/server-install.md).
	srv, err := server.New(server.Config{SignerSocket: *socket, RPID: rpID, Logger: logger, DB: db,
		KRLFile: filepath.Join(*stateDir, "krl-served.json"), AgentPort: agentPort})
	if err != nil {
		return err
	}
	// 5. Bounded reads, writes and headers. The main listener's TLS
	// configuration asks for no client certificate (BrowserTLSConfig); the
	// agent listener's requires one and serves only the agent routes.
	servers := []*http.Server{newHTTPServer(srv.Handler(), server.BrowserTLSConfig(holder.GetCertificate), logger)}
	listeners := []net.Listener{l}
	if al != nil {
		servers = append(servers, newHTTPServer(srv.AgentHandler(), server.AgentTLSConfig(holder.GetCertificate), logger))
		listeners = append(listeners, al)
	}
	// Reload on a file change (checked every certWatch) and on SIGHUP.
	go holder.Watch(ctx, certWatch, hup)
	served := make(chan error, len(servers))
	for i, hs := range servers {
		go func() { served <- hs.ServeTLS(listeners[i], "", "") }()
	}
	agentAddr := ""
	if al != nil {
		agentAddr = al.Addr().String()
	}
	logger.Info("serving", "listen", l.Addr().String(), "agent_listen", agentAddr, "rp_id", rpID, "origins", policy.WebAuthn.Origins,
		"policy_version", policy.Version, "bundle_version", st.BundleVersion)

	var serveErr error
	select {
	case serveErr = <-served:
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, hs := range servers {
		if err := hs.Shutdown(sctx); err != nil && serveErr == nil {
			serveErr = err
		}
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	logger.Info("stopped")
	return nil
}

// newHTTPServer is one listener's http.Server: bounded reads, writes and
// headers, errors to the JSON log.
func newHTTPServer(h http.Handler, tlsCfg *tls.Config, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// openStateDB creates dir (0700) if needed and opens server.db in it.
func openStateDB(dir string) (*serverdb.DB, error) {
	if dir == "" {
		return nil, errors.New("--state-dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	return serverdb.Open(filepath.Join(dir, "server.db"))
}

// probeStatus asks the signer for its Status until it answers or
// statusWait has passed. It is the one signer call outside the server's
// signer seam: it runs before the Server exists.
func probeStatus(ctx context.Context, socket string, logger *slog.Logger) (*wire.StatusResponse, error) {
	deadline := time.Now().Add(statusWait)
	for {
		actx, cancel := context.WithTimeout(ctx, statusAttempt)
		st, err := signerclient.Status(actx, socket)
		cancel()
		if err == nil {
			return st, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the signer at %s did not answer Status within %s: %w", socket, statusWait, err)
		}
		logger.Warn("signer status unavailable; retrying", "socket", socket, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(statusRetry):
		}
	}
}
