// Package signer is the core of keyroster-signer: it accepts framed requests
// on a Unix socket from allowlisted peers only, decides whether to issue, and
// issues every certificate through cert.Build with a serial from the state
// database. "The server proposes, the signer disposes."
//
// The signer runs under a root-signed trust bundle (KEY-07): ca-init
// chooses its five keys, install-bundle verifies the bundle and policy
// against pinned roots, and serve takes every key and the issuance policy
// from the installed bundle. Every request must carry admin-sshsig/v1
// evidence from the policy's admins (D-13).
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
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// Config configures a Signer. The CA keys, the log key and the issuance
// policy are not configuration: they come from the root-signed trust
// bundle that install-bundle stored in DB, and the keys from Backend.
type Config struct {
	Backend   keystore.Backend
	DB        *signerdb.DB
	Clock     serial.Clock // defaults to time.Now
	AllowUIDs []uint32
	AllowGIDs []uint32
	Logger    *slog.Logger // defaults to slog.Default()
	// RefusalLogPerMinute and RefusalLogBurst rate-limit individual
	// refusal leaves (D-14); 0 means the default (10 and 10). Refusals
	// above the rate are counted in refusal_summary leaves.
	RefusalLogPerMinute int
	RefusalLogBurst     int
}

// Signer issues certificates.
type Signer struct {
	backend   keystore.Backend
	ca        map[wire.CARole]keystore.CAKey // one key per CA role, from the bundle
	profiles  map[wire.CARole]cert.Profile   // one profile per CA role, from the policy
	policy    *trust.Policy
	logKey    keystore.CAKey
	db        *signerdb.DB
	clock     serial.Clock
	allowUIDs []uint32
	allowGIDs []uint32
	log       *slog.Logger

	// bundleVersion is the version of the installed bundle that ca,
	// profiles and policy were loaded from. Issuance refuses once the
	// database holds another version (trust_changed).
	bundleVersion uint64

	// mu serializes every state change: serial allocation, issuance and
	// log appends, each through its commit.
	mu sync.Mutex
	logState
	limiter *refusalLimiter // guarded by mu
	// overloaded counts connections refused over capacity by the accept
	// loop, which never takes mu; flushSummaries moves it into the limiter.
	overloaded atomic.Uint64
	// clockEpisode is set while the clock is behind the serial high-water
	// mark and that episode's clock_regression leaf is logged; the next
	// successful issuance clears it. Guarded by mu.
	clockEpisode bool
}

// New loads the installed trust bundle and its policy, opens every bundle
// key (user, host and machine CA, ops and log key) in the backend, and
// rebuilds the audit log from the state database. It refuses to start
// without an installed bundle, when any bundle key is missing from the
// backend, when the stored leaves do not reproduce the latest signed
// checkpoint, and when the installed bundle record is not the one the last
// bundle_install entry of that log records. The trust state is loaded only here: once another bundle is
// installed, the signer refuses every request (trust_changed) until it is
// restarted and loads it.
func New(cfg Config) (*Signer, error) {
	if cfg.Backend == nil || cfg.DB == nil {
		return nil, errors.New("signer: a keystore backend and a state database are required")
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
	ts, err := loadTrust(context.Background(), cfg.DB, cfg.Backend)
	if err != nil {
		return nil, err
	}
	s := &Signer{
		backend:   cfg.Backend,
		ca:        ts.ca,
		profiles:  ts.profiles,
		policy:    ts.policy,
		logKey:    ts.logKey,
		db:        cfg.DB,
		clock:     cfg.Clock,
		allowUIDs: slices.Clone(cfg.AllowUIDs),
		allowGIDs: slices.Clone(cfg.AllowGIDs),
		log:       cfg.Logger,

		bundleVersion: ts.bundle.Version,
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
	// The trust state above came from the trust_bundle table; take it only
	// if the verified log's last bundle_install entry records exactly it.
	if err := checkBundleLogged(ts.stored, s.loadedInstall); err != nil {
		return nil, err
	}
	return s, nil
}

// pinnedKey fetches the key for role by fingerprint and checks, as defence
// in depth, the fingerprint and the key type the backend promised.
func pinnedKey(b keystore.Backend, role keystore.Role, fp string) (keystore.CAKey, error) {
	if fp == "" {
		return nil, fmt.Errorf("no fingerprint for role %s", role)
	}
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

// CAPublicKey returns the public key of the CA for role, or nil.
func (s *Signer) CAPublicKey(role wire.CARole) ssh.PublicKey {
	if k, ok := s.ca[role]; ok {
		return k.PublicKey()
	}
	return nil
}

// LogPublicKey returns the audit-log checkpoint key.
func (s *Signer) LogPublicKey() ssh.PublicKey { return s.logKey.PublicKey() }

// PolicyVersion returns the version of the installed policy.
func (s *Signer) PolicyVersion() uint64 { return s.policy.Version }

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
