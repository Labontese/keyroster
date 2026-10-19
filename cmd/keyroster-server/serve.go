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
	"os/signal"
	"syscall"
	"time"

	"github.com/Labontese/keyroster/internal/server"
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
)

func runServe(ctx context.Context, args []string, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":443", "TCP address to serve HTTPS on")
	certFile := fs.String("tls-cert", "", "TLS certificate chain file, leaf first (required)")
	keyFile := fs.String("tls-key", "", "TLS private key file (required)")
	socket := fs.String("signer-socket", "/run/keyroster-signer/signer.sock", "keyroster-signer Unix socket")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *certFile == "" || *keyFile == "" {
		_, _ = fmt.Fprintln(stderr, "serve: --tls-cert and --tls-key are required; no positional arguments")
		return errUsage
	}

	// Logger first: every line of every start-up step, the first
	// certificate load included, is one JSON object on stderr.
	logger := slog.New(slog.NewJSONHandler(stderr, nil))

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

	srv, err := server.New(server.Config{SignerSocket: *socket, Logger: logger})
	if err != nil {
		return err
	}
	// 4. TLS 1.3 only, certificate from the holder.
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	// 5. Bounded reads, writes and headers.
	hs := &http.Server{
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: holder.GetCertificate},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() { served <- hs.ServeTLS(l, "", "") }()
	logger.Info("serving", "listen", l.Addr().String(), "rp_id", rpID, "origins", policy.WebAuthn.Origins,
		"policy_version", policy.Version, "bundle_version", st.BundleVersion)

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		return err
	}
	logger.Info("stopped")
	return nil
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
