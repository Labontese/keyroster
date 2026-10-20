package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// expiryWarnBefore is the remaining validity below which the holder
	// warns, at most once per expiryWarnEvery.
	expiryWarnBefore = 14 * 24 * time.Hour
	expiryWarnEvery  = 24 * time.Hour
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
// only after validating it and keeps the last good one otherwise (D-10,
// RESEARCH Pitfall 7). Watch reloads it on a file change and on SIGHUP.
type CertHolder struct {
	cfg CertConfig
	cur atomic.Pointer[tls.Certificate]

	mu       sync.Mutex
	stamp    fileStamp // the files as last loaded
	lastWarn time.Time // last expiry warning
}

// fileStamp is the mtime and size of the certificate and key files; a
// missing file has a zero entry.
type fileStamp struct {
	certMod, keyMod   int64 // UnixNano
	certSize, keySize int64
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
// and only then swaps them in. trigger names what started the load:
// start, file_change or sighup. A successful load writes one info record
// "tls certificate loaded" with the leaf's fingerprint (lowercase hex
// SHA-256 of its DER), not_after (RFC 3339, UTC) and trigger. A refused
// load writes an error record, returns its error and keeps the current
// certificate. Only a successful load records the files' stamp, so Watch
// tries refused files again at every interval until they load: a fix such
// as chmod or chgrp on the key changes neither mtime nor size.
func (h *CertHolder) Reload(trigger string) error {
	st := h.statFiles()
	c, err := h.load()
	if err != nil {
		h.cfg.Logger.Error("tls certificate reload refused", "trigger", trigger, "err", err)
		return err
	}
	h.mu.Lock()
	h.stamp = st
	h.mu.Unlock()
	h.cur.Store(c)
	sum := sha256.Sum256(c.Leaf.Raw)
	h.cfg.Logger.Info("tls certificate loaded", "fingerprint", hex.EncodeToString(sum[:]),
		"not_after", c.Leaf.NotAfter.UTC().Format(time.RFC3339), "trigger", trigger)
	h.checkExpiry()
	return nil
}

// Watch reloads the certificate until ctx ends: on every interval when
// the files' mtime or size differ from the last successful load (so
// refused files are tried again at every interval), and on every
// signal from hup whether or not the files changed. A signal already
// waiting in hup (for example a SIGHUP that arrived during start-up) is
// handled as one reload. Each interval also repeats the expiry check.
func (h *CertHolder) Watch(ctx context.Context, interval time.Duration, hup <-chan os.Signal) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			_ = h.Reload("sighup") // a refusal is logged; the last good certificate stays
		case <-t.C:
			if h.changed() {
				_ = h.Reload("file_change")
			}
			h.checkExpiry()
		}
	}
}

// changed reports whether the files differ from the last successful load.
func (h *CertHolder) changed() bool {
	st := h.statFiles()
	h.mu.Lock()
	defer h.mu.Unlock()
	return st != h.stamp
}

func (h *CertHolder) statFiles() fileStamp {
	var st fileStamp
	if fi, err := os.Stat(h.cfg.CertFile); err == nil {
		st.certMod, st.certSize = fi.ModTime().UnixNano(), fi.Size()
	}
	if fi, err := os.Stat(h.cfg.KeyFile); err == nil {
		st.keyMod, st.keySize = fi.ModTime().UnixNano(), fi.Size()
	}
	return st
}

// checkExpiry logs the fixed expiry warning (WARN, with not_after)
// when the served certificate has less than expiryWarnBefore left, at most
// once per expiryWarnEvery.
func (h *CertHolder) checkExpiry() {
	c := h.cur.Load()
	if c == nil || c.Leaf == nil {
		return
	}
	now := h.cfg.Clock()
	if c.Leaf.NotAfter.Sub(now) >= expiryWarnBefore {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.lastWarn.IsZero() && now.Sub(h.lastWarn) < expiryWarnEvery {
		return
	}
	h.lastWarn = now
	h.cfg.Logger.Warn("tls certificate expires soon", "not_after", c.Leaf.NotAfter.UTC().Format(time.RFC3339))
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
