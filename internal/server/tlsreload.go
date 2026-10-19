package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// CertConfig configures a CertHolder.
type CertConfig struct {
	// CertFile is the certificate chain (leaf first) and KeyFile its key,
	// as the operator's TLS tooling writes them.
	CertFile, KeyFile string
	// RPID is the WebAuthn RP ID from the signer's policy; every
	// certificate must cover it.
	RPID string
	// Clock is the time source for validity checks (nil: time.Now).
	Clock func() time.Time
	// Logger receives the holder's log lines (nil: discarded).
	Logger *slog.Logger
}

// CertHolder serves the TLS certificate. It swaps in a new certificate
// only after validating it, and keeps the last good one otherwise.
type CertHolder struct {
	cfg CertConfig
	cur atomic.Pointer[tls.Certificate]
}

// NewCertHolder returns a holder with no certificate; call Reload("start")
// before serving.
func NewCertHolder(cfg CertConfig) *CertHolder {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &CertHolder{cfg: cfg}
}

// GetCertificate is the tls.Config callback.
func (h *CertHolder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := h.cur.Load()
	if c == nil {
		return nil, errors.New("no TLS certificate loaded")
	}
	return c, nil
}

// Reload loads the certificate and key files, validates them (a matching
// pair, a leaf that covers the RP ID and is within its validity period)
// and only then swaps them in. trigger names what started the load
// (start, file_change, sighup). A refused load returns its error and
// keeps the current certificate.
func (h *CertHolder) Reload(trigger string) error {
	c, err := h.load()
	if err != nil {
		h.cfg.Logger.Error("tls certificate reload refused", "trigger", trigger, "err", err)
		return err
	}
	h.cur.Store(c)
	return nil
}

// load reads and validates the files.
func (h *CertHolder) load() (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(h.cfg.CertFile, h.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load %s and %s: %w", h.cfg.CertFile, h.cfg.KeyFile, err)
	}
	leaf := c.Leaf
	if leaf == nil {
		return nil, errors.New("certificate file has no leaf")
	}
	if err := leaf.VerifyHostname(h.cfg.RPID); err != nil {
		return nil, fmt.Errorf("the certificate does not cover the RP ID %s: %w", h.cfg.RPID, err)
	}
	now := h.cfg.Clock()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate is valid from %s to %s, not now (%s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return &c, nil
}
