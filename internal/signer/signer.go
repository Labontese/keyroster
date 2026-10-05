// Package signer is the core of keyroster-signer: it accepts framed requests
// on a Unix socket from allowlisted peers only, decides whether to issue, and
// issues every certificate through cert.Build with a serial from the state
// database. "The server proposes, the signer disposes."
//
// Every issued certificate is appended to the Merkle audit log, with a new
// signed checkpoint, in the same transaction as the issuance row and the
// serial high-water mark; the certificate leaves the process only after
// that transaction committed (VIS-01).
//
// The package must stay network-less: depguard rule signer-no-network denies
// net/http, net/rpc, crypto/tls, os/exec, net/smtp and the template packages.
package signer

import (
	"context"
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
	LogKeyFingerprint string // SHA256:... of the audit-log checkpoint key
	DB                *signerdb.DB
	Clock             serial.Clock // defaults to time.Now
	AllowUIDs         []uint32
	AllowGIDs         []uint32
	Logger            *slog.Logger // defaults to slog.Default()
	// RefusalLogPerMinute and RefusalLogBurst rate-limit individual
	// refusal leaves (D-14); 0 means the default (10 and 10). Refusals
	// above the rate are counted in refusal_summary leaves.
	RefusalLogPerMinute int
	RefusalLogBurst     int
}

// Signer issues certificates.
type Signer struct {
	backend   keystore.Backend
	userCA    keystore.CAKey
	logKey    keystore.CAKey
	db        *signerdb.DB
	clock     serial.Clock
	allowUIDs []uint32
	allowGIDs []uint32
	log       *slog.Logger

	// mu serializes every state change: serial allocation, issuance and
	// log appends, each through its commit.
	mu sync.Mutex
	logState
	limiter *refusalLimiter // guarded by mu
	// clockEpisode is set while the clock is behind the serial high-water
	// mark and that episode's clock_regression leaf is logged; the next
	// successful issuance clears it. Guarded by mu.
	clockEpisode bool
}

// New resolves the user CA key and the log key by their pinned
// fingerprints, fails if the backend does not hold them, and rebuilds the
// audit log from the state database; a log whose leaves do not reproduce
// its latest signed checkpoint is refused.
func New(cfg Config) (*Signer, error) {
	if cfg.Backend == nil || cfg.DB == nil {
		return nil, errors.New("signer: a keystore backend and a state database are required")
	}
	if cfg.UserCAFingerprint == "" {
		return nil, errors.New("signer: no pinned user CA fingerprint")
	}
	if cfg.LogKeyFingerprint == "" {
		return nil, errors.New("signer: no pinned log key fingerprint")
	}
	if cfg.LogKeyFingerprint == cfg.UserCAFingerprint {
		return nil, errors.New("signer: the log key must not be the user CA key")
	}
	if len(cfg.AllowUIDs) == 0 && len(cfg.AllowGIDs) == 0 {
		return nil, errors.New("signer: the peer allowlist is empty, so every client would be refused")
	}
	if cfg.RefusalLogPerMinute < 0 || cfg.RefusalLogBurst < 0 {
		return nil, errors.New("signer: negative refusal log rate")
	}
	perMinute, burst := cfg.RefusalLogPerMinute, cfg.RefusalLogBurst
	if perMinute == 0 {
		perMinute = DefaultRefusalLogPerMinute
	}
	if burst == 0 {
		burst = DefaultRefusalLogBurst
	}
	key, err := pinnedKey(cfg.Backend, keystore.RoleUser, cfg.UserCAFingerprint)
	if err != nil {
		return nil, fmt.Errorf("signer: user CA: %w", err)
	}
	logKey, err := pinnedKey(cfg.Backend, keystore.RoleLog, cfg.LogKeyFingerprint)
	if err != nil {
		return nil, fmt.Errorf("signer: log key: %w", err)
	}
	s := &Signer{
		backend:   cfg.Backend,
		userCA:    key,
		logKey:    logKey,
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
	s.limiter = newRefusalLimiter(perMinute, burst, s.clock())
	if err := s.initLog(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

// pinnedKey fetches the key for role by fingerprint and checks, as defence
// in depth, the fingerprint and the key type the backend promised.
func pinnedKey(b keystore.Backend, role keystore.Role, fp string) (keystore.CAKey, error) {
	key, err := b.Key(role, fp)
	if err != nil {
		return nil, err
	}
	if got := ssh.FingerprintSHA256(key.PublicKey()); got != fp {
		return nil, fmt.Errorf("backend returned key %s, want %s", got, fp)
	}
	if err := cert.CheckCAKey(key.PublicKey()); err != nil {
		return nil, err
	}
	return key, nil
}

// UserCAPublicKey returns the user CA's public key.
func (s *Signer) UserCAPublicKey() ssh.PublicKey { return s.userCA.PublicKey() }

// LogPublicKey returns the audit-log checkpoint key.
func (s *Signer) LogPublicKey() ssh.PublicKey { return s.logKey.PublicKey() }

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
