package signer

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// Errors of CA initialization and bundle installation.
var (
	// ErrAlreadyInitialised means ca-init already ran on this state.
	ErrAlreadyInitialised = errors.New("signer: CA keys already initialised")
	// ErrNotInitialised means ca-init has not run.
	ErrNotInitialised = errors.New("signer: CA keys not initialised (run keyroster-signer ca-init)")
	// ErrNoTrustBundle means install-bundle has not run.
	ErrNoTrustBundle = errors.New("signer: no trust bundle installed (run keyroster-signer install-bundle)")
	// ErrKeySelection means the role keys are missing, repeated or not
	// usable as CA keys.
	ErrKeySelection = errors.New("signer: CA key selection refused")
	// ErrBundleKeys means a bundle's CA, ops or log keys differ from the
	// keys ca-init chose, or one of them is a root key.
	ErrBundleKeys = errors.New("signer: bundle keys do not match the CA keys")
	// ErrBundleInstall means a bundle cannot be installed on this state.
	ErrBundleInstall = errors.New("signer: bundle refused")
)

// initRoles is the fixed role order of ca-init, ca-pubkeys.json and the
// ca_init log entry.
var initRoles = []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog}

// caRoles maps the request's CA role to its key role.
var caRoles = map[wire.CARole]keystore.Role{
	wire.CARoleUser:    keystore.RoleUser,
	wire.CARoleHost:    keystore.RoleHost,
	wire.CARoleMachine: keystore.RoleMachine,
}

// InitCA selects (by pinned fingerprint per role, from selection) or, when
// selection is empty and the backend implements keystore.Provisioner,
// creates the five online keys: user, host and machine CA, ops key and
// log key (CA-01, D-09). It refuses certificate keys and every algorithm
// other than ssh-ed25519 and ecdsa-sha2-nistp256, requires five distinct
// keys, and in one transaction stores the backend configuration and the
// keys and appends a ca_init log entry recording every role's key,
// algorithm and custody, with a checkpoint signed by the new log key
// (VIS-01). On any refusal nothing is written. It returns the keys in the
// fixed role order user, host, machine, ops, log.
func InitCA(ctx context.Context, db *signerdb.DB, be keystore.Backend, backendName string, opts map[string]string,
	selection map[keystore.Role]string, clock serial.Clock) (*trust.CAPubKeys, error) {
	if db == nil || be == nil || backendName == "" {
		return nil, errors.New("signer: InitCA needs a state database and a named keystore backend")
	}
	if clock == nil {
		clock = time.Now
	}
	switch _, err := db.CAKeys(ctx); {
	case err == nil:
		return nil, ErrAlreadyInitialised
	case !errors.Is(err, signerdb.ErrNotInitialised):
		return nil, err
	}
	if hashes, err := db.LeafHashes(ctx); err != nil {
		return nil, err
	} else if len(hashes) != 0 {
		return nil, fmt.Errorf("%w: the audit log already has %d entries; ca-init needs a fresh state directory", ErrAlreadyInitialised, len(hashes))
	}
	for role := range selection {
		if !isInitRole(role) {
			return nil, fmt.Errorf("%w: unknown role %q", ErrKeySelection, role)
		}
	}
	if len(selection) == 0 {
		prov, ok := be.(keystore.Provisioner)
		if !ok {
			return nil, fmt.Errorf("%w: backend %s cannot create keys; select one key per role (user, host, machine, ops, log)", ErrKeySelection, backendName)
		}
		pubs, err := prov.Provision(initRoles)
		if err != nil {
			return nil, fmt.Errorf("signer: provision keys: %w", err)
		}
		selection = map[keystore.Role]string{}
		for _, role := range initRoles {
			pub := pubs[role]
			if pub == nil {
				return nil, fmt.Errorf("%w: backend %s created no key for role %s", ErrKeySelection, backendName, role)
			}
			selection[role] = ssh.FingerprintSHA256(pub)
		}
	}
	for _, role := range initRoles {
		if selection[role] == "" {
			return nil, fmt.Errorf("%w: no key selected for role %s", ErrKeySelection, role)
		}
	}

	keys := make(map[keystore.Role]keystore.CAKey, len(initRoles))
	seen := map[string]keystore.Role{}
	cas := &trust.CAPubKeys{Keys: make([]trust.CAPubKey, 0, len(initRoles))}
	body := &tlog.CAInitBody{}
	dbKeys := make([]signerdb.CAKey, 0, len(initRoles))
	for _, role := range initRoles {
		k, err := pinnedKey(be, role, selection[role])
		if err != nil {
			return nil, fmt.Errorf("%w: role %s: %w", ErrKeySelection, role, err)
		}
		pub := k.PublicKey()
		if k.Algorithm() != pub.Type() {
			return nil, fmt.Errorf("%w: role %s: backend reports algorithm %q for a %s key", ErrKeySelection, role, k.Algorithm(), pub.Type())
		}
		if prior, dup := seen[string(pub.Marshal())]; dup {
			return nil, fmt.Errorf("%w: the same key %s is selected for roles %s and %s", ErrKeySelection, ssh.FingerprintSHA256(pub), prior, role)
		}
		seen[string(pub.Marshal())] = role
		keys[role] = k
		cas.Keys = append(cas.Keys, trust.CAPubKey{Role: string(role), Key: trust.FormatKey(pub), Alg: pub.Type(), Custody: string(k.Custody())})
		body.Keys = append(body.Keys, tlog.CAInitKey{Role: string(role), PublicKey: pub.Marshal(), Alg: pub.Type(), Custody: string(k.Custody())})
		dbKeys = append(dbKeys, signerdb.CAKey{Role: string(role), PublicKey: pub.Marshal(), Alg: pub.Type(), Custody: string(k.Custody())})
	}
	if err := cas.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeySelection, err)
	}
	enc, err := body.Encode()
	if err != nil {
		return nil, err
	}
	lw, err := newLogWriter(ctx, db, keys[keystore.RoleLog], clock)
	if err != nil {
		return nil, err
	}
	err = lw.logTx(ctx, func(tx *sql.Tx) error {
		if err := db.SaveBackendConfig(tx, backendName, opts); err != nil {
			return err
		}
		if err := db.SaveCAKeys(tx, dbKeys); err != nil {
			return err
		}
		_, err := lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(clock()), Kind: tlog.KindCAInit, Body: enc})
		return err
	})
	if err != nil {
		return nil, err
	}
	return cas, nil
}

func isInitRole(r keystore.Role) bool {
	for _, x := range initRoles {
		if x == r {
			return true
		}
	}
	return false
}

// newLogWriter returns a Signer that only appends to the audit log of db
// with logKey, for ca-init and install-bundle; it rebuilds and checks the
// stored log first.
func newLogWriter(ctx context.Context, db *signerdb.DB, logKey keystore.CAKey, clock serial.Clock) (*Signer, error) {
	s := &Signer{db: db, logKey: logKey, clock: clock, log: slog.New(slog.DiscardHandler)}
	if err := s.initLog(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// InstallBundle verifies a trust bundle and its policy and installs them
// (KEY-07). A genesis bundle must be signed, bundle and policy alike, by at
// least threshold distinct roots among the operator's pins, and its root
// set must be exactly the pinned set (trust.VerifyGenesisBundle). A later
// bundle is verified against the installed one by the successor rule
// (trust.VerifySuccessor); pins and threshold must then be empty, and the
// installed record must be the one the log's last bundle_install entry
// records (none for a genesis install). In both
// cases the bundle's CA, ops and log keys, algorithms and custody must
// equal the keys ca-init chose, none of them may be a root key, and the
// log origin must be the log key's. The bundle, the policy and their
// signatures are stored with a bundle_install log entry carrying all four
// documents, in one transaction; on any refusal nothing is written.
func InstallBundle(ctx context.Context, db *signerdb.DB, be keystore.Backend, pins []string, threshold int,
	bundle, bundleSigs, policy, policySigs []byte, clock serial.Clock) (*trust.Bundle, error) {
	if db == nil || be == nil {
		return nil, errors.New("signer: InstallBundle needs a state database and a keystore backend")
	}
	if clock == nil {
		clock = time.Now
	}
	caKeys, err := db.CAKeys(ctx)
	if errors.Is(err, signerdb.ErrNotInitialised) {
		return nil, ErrNotInitialised
	}
	if err != nil {
		return nil, err
	}
	logKey, err := openRoleKey(be, caKeys, "log")
	if err != nil {
		return nil, err
	}
	lw, err := newLogWriter(ctx, db, logKey, clock)
	if err != nil {
		return nil, err
	}
	var (
		b *trust.Bundle
		p *trust.Policy
	)
	latest, err := db.LatestBundle(ctx)
	if err == nil || errors.Is(err, signerdb.ErrNoBundle) {
		// A successor is verified against the installed record, so that
		// record must be the one the verified log carries.
		if cerr := checkBundleLogged(latest, lw.loadedInstall); cerr != nil {
			return nil, cerr
		}
	}
	switch {
	case errors.Is(err, signerdb.ErrNoBundle):
		b, p, err = trust.VerifyGenesisBundle(bundle, bundleSigs, policy, policySigs, pins, threshold)
	case err != nil:
		return nil, err
	case len(pins) != 0 || threshold != 0:
		return nil, fmt.Errorf("%w: bundle version %d is installed; a successor is verified against it, so --pin and --threshold apply to the genesis bundle only", ErrBundleInstall, latest.Version)
	default:
		var prev *trust.Bundle
		prev, err = trust.ParseBundle(latest.Bundle)
		if err != nil {
			return nil, fmt.Errorf("installed bundle: %w", err)
		}
		b, p, err = trust.VerifySuccessor(prev, latest.Bundle, bundle, bundleSigs, policy, policySigs)
		if err == nil && b.Version <= latest.Version {
			err = fmt.Errorf("%w: version %d is not above the installed version %d", ErrBundleInstall, b.Version, latest.Version)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := checkBundleKeys(b, caKeys); err != nil {
		return nil, err
	}
	if err := checkPolicyAdmins(p, caKeys); err != nil {
		return nil, err
	}
	if b.Log.Origin != tlog.Origin(logKey.PublicKey()) {
		return nil, fmt.Errorf("%w: log origin %q is not the log key's %q", ErrBundleKeys, b.Log.Origin, tlog.Origin(logKey.PublicKey()))
	}
	enc, err := (&tlog.BundleInstallBody{
		BundleVersion: b.Version, Bundle: bundle, BundleSigs: bundleSigs, Policy: policy, PolicySigs: policySigs,
	}).Encode()
	if err != nil {
		return nil, err
	}
	now := clock()
	err = lw.logTx(ctx, func(tx *sql.Tx) error {
		if err := db.InsertBundle(tx, signerdb.StoredBundle{
			Version: b.Version, Bundle: bundle, BundleSigs: bundleSigs, Policy: policy, PolicySigs: policySigs, InstalledAt: now,
		}); err != nil {
			return err
		}
		_, err := lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindBundleInstall, Body: enc})
		return err
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// checkBundleKeys requires the bundle to list exactly the ca-init keys: one
// active CA entry each for user, host and machine, then the ops and log
// keys, each with the same key, algorithm and custody, and none equal to a
// root key.
func checkBundleKeys(b *trust.Bundle, caKeys []signerdb.CAKey) error {
	want := map[string]signerdb.CAKey{}
	for _, k := range caKeys {
		want[k.Role] = k
	}
	same := func(where, key, alg, custody string, k signerdb.CAKey) error {
		pub, err := ssh.ParsePublicKey(k.PublicKey)
		if err != nil {
			return fmt.Errorf("%w: stored %s key: %w", ErrBundleKeys, k.Role, err)
		}
		if key != trust.FormatKey(pub) || alg != k.Alg || custody != k.Custody {
			return fmt.Errorf("%w: %s is %s (%s, %s), ca-init chose %s (%s, %s)", ErrBundleKeys, where,
				fingerprintOf(key), alg, custody, ssh.FingerprintSHA256(pub), k.Alg, k.Custody)
		}
		return nil
	}
	if len(b.CAs) != len(caRoles) {
		return fmt.Errorf("%w: the bundle lists %d CA keys, want one each for user, host and machine", ErrBundleKeys, len(b.CAs))
	}
	for _, ca := range b.CAs {
		if ca.State != "active" {
			return fmt.Errorf("%w: CA %s is %s, want active", ErrBundleKeys, ca.Role, ca.State)
		}
		if err := same("CA "+ca.Role, ca.Key, ca.Alg, ca.Custody, want[ca.Role]); err != nil {
			return err
		}
	}
	if err := same("the ops key", b.OpsKey.Key, b.OpsKey.Alg, b.OpsKey.Custody, want["ops"]); err != nil {
		return err
	}
	if err := same("the log key", b.Log.Key, b.Log.Alg, b.Log.Custody, want["log"]); err != nil {
		return err
	}
	for _, rk := range b.Root.Keys {
		root, err := trust.ParseKey(rk.Key)
		if err != nil {
			return fmt.Errorf("%w: root key: %w", ErrBundleKeys, err)
		}
		for _, k := range caKeys {
			if bytes.Equal(root.Marshal(), k.PublicKey) {
				return fmt.Errorf("%w: the %s key %s is a root key", ErrBundleKeys, k.Role, ssh.FingerprintSHA256(root))
			}
		}
	}
	return nil
}

// checkPolicyAdmins refuses a policy that names one of the signer's own
// online keys (a CA, ops or log key) as an admin: the keys that sign
// certificates must never also authorize them (D-13).
func checkPolicyAdmins(p *trust.Policy, caKeys []signerdb.CAKey) error {
	for _, a := range p.Admins {
		pub, err := trust.ParseKey(a.Key)
		if err != nil {
			return fmt.Errorf("%w: admin %s: %w", ErrBundleKeys, a.Name, err)
		}
		for _, k := range caKeys {
			if bytes.Equal(pub.Marshal(), k.PublicKey) {
				return fmt.Errorf("%w: policy admin %s uses the %s key %s", ErrBundleKeys, a.Name, k.Role, ssh.FingerprintSHA256(pub))
			}
		}
	}
	return nil
}

// openRoleKey opens the ca-init key for role in the backend and requires
// the custody the backend reports to be the recorded one, so a changed
// backend option cannot present the same key under another custody.
func openRoleKey(be keystore.Backend, caKeys []signerdb.CAKey, role string) (keystore.CAKey, error) {
	for _, k := range caKeys {
		if k.Role != role {
			continue
		}
		key, err := pinnedKey(be, keystore.Role(role), keyFingerprint(caKeys, role))
		if err != nil {
			return nil, fmt.Errorf("signer: bundle key for role %s: %w", role, err)
		}
		if got := string(key.Custody()); got != k.Custody {
			return nil, fmt.Errorf("%w: the backend reports custody %s for the %s key, the bundle records %s", ErrBundleKeys, got, role, k.Custody)
		}
		return key, nil
	}
	return nil, fmt.Errorf("signer: no key for role %s", role)
}

func fingerprintOf(key string) string {
	pub, err := trust.ParseKey(key)
	if err != nil {
		return "an unparsable key"
	}
	return ssh.FingerprintSHA256(pub)
}

// keyFingerprint returns the SHA256 fingerprint of the stored key for role,
// or "" when it does not parse.
func keyFingerprint(caKeys []signerdb.CAKey, role string) string {
	for _, k := range caKeys {
		if k.Role == role {
			pub, err := ssh.ParsePublicKey(k.PublicKey)
			if err != nil {
				return ""
			}
			return ssh.FingerprintSHA256(pub)
		}
	}
	return ""
}

// trustState is what the signer takes from the installed bundle.
type trustState struct {
	stored   *signerdb.StoredBundle
	bundle   *trust.Bundle
	policy   *trust.Policy
	ca       map[wire.CARole]keystore.CAKey
	profiles map[wire.CARole]cert.Profile
	logKey   keystore.CAKey
}

// loadTrust reads the ca-init keys and the latest installed bundle and
// opens every bundle key in the backend. It refuses when ca-init or
// install-bundle has not run, when the stored bundle no longer matches the
// stored keys or its policy, and when any bundle key (CA, ops or log) is
// missing from the backend (KEY-01).
func loadTrust(ctx context.Context, db *signerdb.DB, be keystore.Backend) (*trustState, error) {
	caKeys, err := db.CAKeys(ctx)
	if errors.Is(err, signerdb.ErrNotInitialised) {
		return nil, ErrNotInitialised
	}
	if err != nil {
		return nil, err
	}
	stored, err := db.LatestBundle(ctx)
	if errors.Is(err, signerdb.ErrNoBundle) {
		return nil, ErrNoTrustBundle
	}
	if err != nil {
		return nil, err
	}
	b, err := trust.ParseBundle(stored.Bundle)
	if err != nil {
		return nil, fmt.Errorf("signer: installed bundle: %w", err)
	}
	p, err := trust.ParsePolicy(stored.Policy)
	if err != nil {
		return nil, fmt.Errorf("signer: installed policy: %w", err)
	}
	if b.Version != stored.Version || b.PolicySHA256 != trust.SHA256Hex(stored.Policy) {
		return nil, fmt.Errorf("signer: the installed bundle record is inconsistent (version or policy hash)")
	}
	if err := checkBundleKeys(b, caKeys); err != nil {
		return nil, err
	}
	if err := checkPolicyAdmins(p, caKeys); err != nil {
		return nil, err
	}
	ts := &trustState{stored: stored, bundle: b, policy: p, ca: map[wire.CARole]keystore.CAKey{}, profiles: map[wire.CARole]cert.Profile{}}
	keys := map[string]keystore.CAKey{}
	for _, k := range caKeys {
		key, err := openRoleKey(be, caKeys, k.Role)
		if err != nil {
			return nil, err
		}
		keys[k.Role] = key
	}
	for role, kr := range caRoles {
		ts.ca[role] = keys[string(kr)]
		prof, err := profileFor(string(kr), p)
		if err != nil {
			return nil, err
		}
		ts.profiles[role] = prof
	}
	ts.logKey = keys["log"]
	if b.Log.Origin != tlog.Origin(ts.logKey.PublicKey()) {
		return nil, fmt.Errorf("%w: log origin %q is not the log key's", ErrBundleKeys, b.Log.Origin)
	}
	return ts, nil
}
