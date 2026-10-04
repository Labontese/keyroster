// Package signer is the core of keyroster-signer: it accepts framed requests
// on a Unix socket from allowlisted peers only, decides whether to issue, and
// issues every certificate through cert.Build with a serial from the state
// database. "The server proposes, the signer disposes."
//
// The package must stay network-less: depguard rule signer-no-network denies
// net/http, net/rpc, crypto/tls, os/exec, net/smtp and the template packages.
package signer

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
)

// Config configures a Signer.
type Config struct {
	Backend           keystore.Backend
	UserCAFingerprint string // SHA256:... of the user CA key
	DB                *signerdb.DB
	Clock             serial.Clock // defaults to time.Now
	AllowUIDs         []uint32
	AllowGIDs         []uint32
	Logger            *slog.Logger // defaults to slog.Default()
}

// Signer issues certificates.
type Signer struct {
	backend   keystore.Backend
	userCA    keystore.CAKey
	db        *signerdb.DB
	clock     serial.Clock
	allowUIDs []uint32
	allowGIDs []uint32
	log       *slog.Logger

	issueMu sync.Mutex // serializes issuance: serial allocation through commit
}

// New resolves the user CA key by its pinned fingerprint and fails if the
// backend does not hold it.
func New(cfg Config) (*Signer, error) {
	if cfg.Backend == nil || cfg.DB == nil {
		return nil, errors.New("signer: a keystore backend and a state database are required")
	}
	if cfg.UserCAFingerprint == "" {
		return nil, errors.New("signer: no pinned user CA fingerprint")
	}
	if len(cfg.AllowUIDs) == 0 && len(cfg.AllowGIDs) == 0 {
		return nil, errors.New("signer: the peer allowlist is empty, so every client would be refused")
	}
	key, err := cfg.Backend.Key(keystore.RoleUser, cfg.UserCAFingerprint)
	if err != nil {
		return nil, fmt.Errorf("signer: user CA: %w", err)
	}
	// Defence in depth: the backend promised a fingerprint match and a
	// valid CA key; check both again before trusting it.
	if got := ssh.FingerprintSHA256(key.PublicKey()); got != cfg.UserCAFingerprint {
		return nil, fmt.Errorf("signer: backend returned key %s, want %s", got, cfg.UserCAFingerprint)
	}
	if err := cert.CheckCAKey(key.PublicKey()); err != nil {
		return nil, fmt.Errorf("signer: user CA: %w", err)
	}
	s := &Signer{
		backend:   cfg.Backend,
		userCA:    key,
		db:        cfg.DB,
		clock:     cfg.Clock,
		allowUIDs: slices.Clone(cfg.AllowUIDs),
		allowGIDs: slices.Clone(cfg.AllowGIDs),
		log:       cfg.Logger,
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// UserCAPublicKey returns the user CA's public key.
func (s *Signer) UserCAPublicKey() ssh.PublicKey { return s.userCA.PublicKey() }

// allowed reports whether the peer's uid, or its primary or any
// supplementary gid, is on the allowlist. Default deny.
func (s *Signer) allowed(p Peer) bool {
	if slices.Contains(s.allowUIDs, p.UID) {
		return true
	}
	if slices.Contains(s.allowGIDs, p.GID) {
		return true
	}
	for _, g := range p.Groups {
		if slices.Contains(s.allowGIDs, g) {
			return true
		}
	}
	return false
}
