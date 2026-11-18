package signer

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
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
// with logKey, for ca-init and ca-rotate prepare; it rebuilds and checks
// the stored log first. It asks for no drain scan (03-12e).
func newLogWriter(ctx context.Context, db *signerdb.DB, logKey keystore.CAKey, clock serial.Clock) (*Signer, error) {
	return newLogWriterWith(ctx, db, logKey, clock, rebuildOptions{})
}

// newLogWriterWith is newLogWriter whose log walk takes opts (03-12e):
// InstallBundleWithPrevious alone asks for the drain scan and the check of
// a previous checkpoint.
func newLogWriterWith(ctx context.Context, db *signerdb.DB, logKey keystore.CAKey, clock serial.Clock, opts rebuildOptions) (*Signer, error) {
	s := &Signer{db: db, logKey: logKey, clock: clock, log: slog.New(slog.DiscardHandler)}
	s.rebuildOpts = opts
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
// equal the keys ca-init chose, none of them may be a root key, no policy
// admin may be a root of this or of any bundle the log records, and the
// log origin must be the log key's. The bundle, the policy and their
// signatures are stored with a bundle_install log entry carrying all four
// documents, in one transaction; on any refusal nothing is written. Before
// any of that, it refuses a bundle and policy whose Status reply would
// exceed wire.MaxStatusFrame (wire.ErrStatusTooLarge), the limit Status
// itself enforces. It is InstallBundleWithPrevious without a previous
// checkpoint, so it refuses a switch (03-12e).
func InstallBundle(ctx context.Context, db *signerdb.DB, be keystore.Backend, pins []string, threshold int,
	bundle, bundleSigs, policy, policySigs []byte, clock serial.Clock) (*trust.Bundle, error) {
	b, _, err := InstallBundleWithPrevious(ctx, db, be, pins, threshold, bundle, bundleSigs, policy, policySigs, clock, nil)
	return b, err
}

// checkIssuedNotAhead refuses bundle_issued_in_future (03-12): a bundle,
// genesis or successor, whose issued_at is later than the signer's clock
// now plus krl.PruneMargin seconds, compared at full clock resolution, so
// that exactly the margin ahead is accepted. The ceremony machine's clock
// is offline and nothing else bounds it; a bundle dated far ahead would
// block every later successor.
func checkIssuedNotAhead(b *trust.Bundle, now time.Time) error {
	issued, err := time.Parse(trust.TimeFormat, b.IssuedAt)
	if err != nil {
		return fmt.Errorf("%w: issued_at %q: %w", ErrBundleInstall, b.IssuedAt, err)
	}
	if limit := now.Add(krl.PruneMargin * time.Second); issued.After(limit) {
		return fmt.Errorf("%w: bundle_issued_in_future: trust bundle v%d is issued at %s, the signer's clock reads %s, and the latest accepted issued_at is %s; the usual cause is a ceremony machine whose clock runs ahead",
			ErrBundleInstall, b.Version, b.IssuedAt, now.UTC().Format(time.RFC3339Nano), limit.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// checkBundleKeys requires, for each of user, host and machine, exactly one
// active CA entry, equal in key, algorithm and custody to the stored
// generation of its role whose key it carries and naming that
// generation's number, and accepts beside it a next, retired or draining
// entry only when it equals a stored generation of its role in generation
// number, key, algorithm and custody (03-12b, 03-12e), whatever the
// backend holds. Then the ops and log keys of ca_keys with the same key,
// algorithm and custody, and no root key equal to any stored key or
// generation of any role (03-12). Which stored generation is active is
// the chain rule's (trust.checkSuccessorChain): only the switch makes a
// later generation active (03-12e).
func checkBundleKeys(b *trust.Bundle, caKeys []signerdb.CAKey, gens []signerdb.CAGeneration) error {
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
	// stored reports whether ca equals a stored generation of its role in
	// generation number, key, algorithm and custody.
	stored := func(ca trust.CAEntry) bool {
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return false
		}
		for _, g := range gens {
			if g.Role == ca.Role && g.Generation == ca.Generation && bytes.Equal(g.PublicKey, pub.Marshal()) && g.Alg == ca.Alg && g.Custody == ca.Custody {
				return true
			}
		}
		return false
	}
	// byKey returns the stored generation of ca's role whose key is ca's.
	byKey := func(ca trust.CAEntry) (signerdb.CAGeneration, bool) {
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return signerdb.CAGeneration{}, false
		}
		for _, g := range gens {
			if g.Role == ca.Role && bytes.Equal(g.PublicKey, pub.Marshal()) {
				return g, true
			}
		}
		return signerdb.CAGeneration{}, false
	}
	roles := []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine}
	for _, ca := range b.CAs {
		if !slices.Contains(roles, ca.Role) {
			return fmt.Errorf("%w: the bundle lists a CA entry for role %q", ErrBundleKeys, ca.Role)
		}
	}
	for _, role := range roles {
		active := 0
		for _, ca := range b.CAs {
			if ca.Role != role {
				continue
			}
			switch ca.State {
			case "active":
				active++
				g, ok := byKey(ca)
				if !ok {
					return fmt.Errorf("%w: the active CA %s entry (generation %d, %s) is no stored generation of the role", ErrBundleKeys, ca.Role, ca.Generation, fingerprintOf(ca.Key))
				}
				if ca.Alg != g.Alg || ca.Custody != g.Custody {
					return fmt.Errorf("%w: the active CA %s entry is %s (%s, %s); stored generation %d of that key is (%s, %s)", ErrBundleKeys, ca.Role,
						fingerprintOf(ca.Key), ca.Alg, ca.Custody, g.Generation, g.Alg, g.Custody)
				}
				if ca.Generation != g.Generation {
					return fmt.Errorf("%w: the active CA %s entry carries generation %d; its key is stored generation %d", ErrBundleKeys, ca.Role, ca.Generation, g.Generation)
				}
			case "next", "retired", "draining":
				if !stored(ca) {
					return fmt.Errorf("%w: CA %s is %s but generation %d is no stored generation of that key", ErrBundleKeys, ca.Role, ca.State, ca.Generation)
				}
			default:
				return fmt.Errorf("%w: CA %s is %s, want active, next, draining or retired", ErrBundleKeys, ca.Role, ca.State)
			}
		}
		if active != 1 {
			return fmt.Errorf("%w: the bundle lists %d active CA %s entries, want one", ErrBundleKeys, active, role)
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
		for _, g := range gens {
			if bytes.Equal(root.Marshal(), g.PublicKey) {
				return fmt.Errorf("%w: the %s generation %d key %s is a root key", ErrBundleKeys, g.Role, g.Generation, ssh.FingerprintSHA256(root))
			}
		}
	}
	return nil
}

// checkPolicyAdmins refuses a policy that names one of the signer's own
// online keys as an admin: any stored generation of any role (a CA, ops or
// log key, prepared generations included, 03-12) or any key of the bundle
// in any state. The keys that sign certificates must never also authorize
// them (D-13). Nor may an admin be one of the bundle's roots (KEY-07,
// trust.CheckAdminsNotRoots); the trust.Verify* functions check that on
// install already, and this repeats it for a stored record loaded at
// start.
func checkPolicyAdmins(b *trust.Bundle, p *trust.Policy, gens []signerdb.CAGeneration) error {
	if err := trust.CheckAdminsNotRoots(p, b.Root.Keys); err != nil {
		return err
	}
	bundleKeys := []string{b.OpsKey.Key, b.Log.Key}
	for _, ca := range b.CAs {
		bundleKeys = append(bundleKeys, ca.Key)
	}
	for _, a := range p.Admins {
		pub, err := trust.ParseKey(a.Key)
		if err != nil {
			return fmt.Errorf("%w: admin %s: %w", ErrBundleKeys, a.Name, err)
		}
		for _, g := range gens {
			if bytes.Equal(pub.Marshal(), g.PublicKey) {
				return fmt.Errorf("%w: policy admin %s uses the %s generation %d key %s", ErrBundleKeys, a.Name, g.Role, g.Generation, ssh.FingerprintSHA256(pub))
			}
		}
		for _, key := range bundleKeys {
			if k, err := trust.ParseKey(key); err == nil && bytes.Equal(pub.Marshal(), k.Marshal()) {
				return fmt.Errorf("%w: policy admin %s uses a key of the bundle, %s", ErrBundleKeys, a.Name, ssh.FingerprintSHA256(pub))
			}
		}
	}
	return nil
}

// checkCAKeysGeneration1 requires each ca_keys row to equal the
// generation-1 row of its role on key, algorithm and custody (03-12):
// checkBundleKeys reads the CA keys from the generation rows, and doctor's
// custody results read ca_keys, so the two tables must agree.
func checkCAKeysGeneration1(caKeys []signerdb.CAKey, gens []signerdb.CAGeneration) error {
	for _, k := range caKeys {
		i := slices.IndexFunc(gens, func(g signerdb.CAGeneration) bool { return g.Role == k.Role && g.Generation == 1 })
		if i < 0 {
			return fmt.Errorf("%w: ca_keys %s has no generation-1 row", ErrBundleKeys, k.Role)
		}
		if g := gens[i]; !bytes.Equal(g.PublicKey, k.PublicKey) || g.Alg != k.Alg || g.Custody != k.Custody {
			return fmt.Errorf("%w: ca_keys %s (%s, %s, %s) differs from its generation-1 row (%s, %s, %s)", ErrBundleKeys, k.Role,
				fingerprintOfWire(k.PublicKey), k.Alg, k.Custody, fingerprintOfWire(g.PublicKey), g.Alg, g.Custody)
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

// isCARole reports whether role is a CA role (user, host or machine).
func isCARole(role string) bool {
	for _, kr := range caRoles {
		if string(kr) == role {
			return true
		}
	}
	return false
}

// activeGeneration returns the stored generation row that b's active entry
// for role names: the same role, generation number and key (03-12).
func activeGeneration(b *trust.Bundle, gens []signerdb.CAGeneration, role string) (signerdb.CAGeneration, error) {
	for _, ca := range b.CAs {
		if ca.Role != role || ca.State != "active" {
			continue
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return signerdb.CAGeneration{}, fmt.Errorf("%w: CA %s: %w", ErrBundleKeys, role, err)
		}
		for _, g := range gens {
			if g.Role == role && g.Generation == ca.Generation && bytes.Equal(g.PublicKey, pub.Marshal()) {
				return g, nil
			}
		}
		return signerdb.CAGeneration{}, fmt.Errorf("%w: the active CA %s entry (generation %d, %s) names no stored generation",
			ErrBundleKeys, role, ca.Generation, ssh.FingerprintSHA256(pub))
	}
	return signerdb.CAGeneration{}, fmt.Errorf("%w: the bundle has no active CA %s entry", ErrBundleKeys, role)
}

// openGenerationKey opens the key of generation row g through
// keystore.KeyFor, with the row's location, and requires the fingerprint,
// the custody the backend reports and the key type to be the recorded
// ones, as openRoleKey does for a ca-init key (03-12).
func openGenerationKey(be keystore.Backend, g signerdb.CAGeneration) (keystore.CAKey, error) {
	pub, err := ssh.ParsePublicKey(g.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: stored %s generation %d key: %w", ErrBundleKeys, g.Role, g.Generation, err)
	}
	key, err := pinnedKeyAt(be, keystore.Role(g.Role), g.Generation, ssh.FingerprintSHA256(pub), g.Location)
	if err != nil {
		return nil, fmt.Errorf("signer: bundle key for role %s (generation %d): %w", g.Role, g.Generation, err)
	}
	if got := string(key.Custody()); got != g.Custody {
		return nil, fmt.Errorf("%w: the backend reports custody %s for the %s generation %d key, the generation records %s",
			ErrBundleKeys, got, g.Role, g.Generation, g.Custody)
	}
	return key, nil
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
	// caKeys are the ca-init keys, each opened in the backend with its
	// recorded custody (openRoleKey) by loadTrust; Status reports them.
	caKeys   []signerdb.CAKey
	stored   *signerdb.StoredBundle
	bundle   *trust.Bundle
	policy   *trust.Policy
	ca       map[wire.CARole]keystore.CAKey
	profiles map[wire.CARole]cert.Profile
	logKey   keystore.CAKey
	opsKey   keystore.CAKey
}

// loadTrust reads the ca-init keys and the latest installed bundle,
// checks them (checkStoredTrust) and opens every bundle key in the
// backend. It refuses when ca-init or install-bundle has not run, when the
// stored bundle no longer matches the stored keys or its policy, when
// any bundle key (CA, ops or log) is missing from the backend (KEY-01),
// and, before it opens any key, when the backend still holds, or cannot
// say whether it holds, the key of a draining CA entry of the bundle
// (draining_key_still_usable, 03-12e). In the recovery configuration
// (recovery true, 03-12e) it keeps every check that needs no CA key, opens
// only the ops and log keys, leaves the CA key map empty, so every
// issuance path refuses ca_not_configured, and skips the draining-key
// refusal.
func loadTrust(ctx context.Context, db *signerdb.DB, be keystore.Backend, recovery bool) (*trustState, error) {
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
	gens, err := db.CAGenerations(ctx)
	if err != nil {
		return nil, err
	}
	ts, err := checkStoredTrust(caKeys, gens, stored)
	if err != nil {
		return nil, err
	}
	if !recovery {
		if err := checkDrainingNotHeld(be, ts.bundle, gens); err != nil {
			return nil, err
		}
	}
	// Each CA role's signing key is the generation the bundle names as
	// active, opened by generation through keystore.KeyFor with the
	// location its row records (03-12); ops and log are still the ca-init
	// keys. The rows the signer reports keep the fixed role order.
	keys := map[string]keystore.CAKey{}
	rows := make([]signerdb.CAKey, 0, len(caKeys))
	for _, k := range caKeys {
		var (
			key keystore.CAKey
			row = k
		)
		if isCARole(k.Role) {
			g, err := activeGeneration(ts.bundle, gens, k.Role)
			if err != nil {
				return nil, err
			}
			row = signerdb.CAKey{Role: g.Role, PublicKey: g.PublicKey, Alg: g.Alg, Custody: g.Custody}
			if recovery {
				rows = append(rows, row)
				continue
			}
			if key, err = openGenerationKey(be, g); err != nil {
				return nil, err
			}
		} else if key, err = openRoleKey(be, caKeys, k.Role); err != nil {
			return nil, err
		}
		keys[k.Role] = key
		rows = append(rows, row)
	}
	for role, kr := range caRoles {
		if key, ok := keys[string(kr)]; ok {
			ts.ca[role] = key
		}
	}
	ts.logKey = keys["log"]
	ts.opsKey = keys["ops"]
	ts.caKeys = rows
	if ts.bundle.Log.Origin != tlog.Origin(ts.logKey.PublicKey()) {
		return nil, fmt.Errorf("%w: log origin %q is not the log key's", ErrBundleKeys, ts.bundle.Log.Origin)
	}
	return ts, nil
}

// checkDrainingNotHeld refuses ErrDrainingKeyUsable when be still holds
// the key of any draining CA entry of b, in any role (03-12e): the old key
// must be gone (ca-rotate retire-key) before the signer serves. It asks
// keystore.Holds with the location of the entry's generation row (empty
// when no row matches; checkBundleKeys has already required one), and
// keystore.Holds fails closed: a backend that cannot say, or whose answer
// is an error, counts as holding the key. It opens no key.
func checkDrainingNotHeld(be keystore.Backend, b *trust.Bundle, gens []signerdb.CAGeneration) error {
	for _, ca := range b.CAs {
		if ca.State != "draining" {
			continue
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return fmt.Errorf("%w: CA %s generation %d: %w", ErrBundleKeys, ca.Role, ca.Generation, err)
		}
		fp, location := ssh.FingerprintSHA256(pub), ""
		for _, g := range gens {
			if g.Role == ca.Role && g.Generation == ca.Generation && bytes.Equal(g.PublicKey, pub.Marshal()) {
				location = g.Location
			}
		}
		held, err := keystore.Holds(be, keystore.Role(ca.Role), ca.Generation, fp, location)
		switch {
		case err != nil:
			return fmt.Errorf("%w: generation %d of the %s CA (%s), which the installed bundle drains: cannot tell whether the backend holds it: %w; run keyroster-signer ca-rotate retire-key",
				ErrDrainingKeyUsable, ca.Generation, ca.Role, fp, err)
		case held:
			return fmt.Errorf("%w: the backend still holds generation %d of the %s CA (%s), which the installed bundle drains; run keyroster-signer ca-rotate retire-key",
				ErrDrainingKeyUsable, ca.Generation, ca.Role, fp)
		}
	}
	return nil
}

// checkStoredTrust is the part of loadTrust that needs no backend, shared
// with CheckTrust (doctor): the stored bundle record must be consistent
// (version, policy hash), list only stored generations (checkBundleKeys),
// name no stored generation nor a root as a policy
// admin (checkPolicyAdmins), carry a profile for every CA role, and name
// the recorded log key's origin, and the ca_keys rows must equal the
// generation-1 rows (checkCAKeysGeneration1, 03-12). It returns the trust
// state without keys.
func checkStoredTrust(caKeys []signerdb.CAKey, gens []signerdb.CAGeneration, stored *signerdb.StoredBundle) (*trustState, error) {
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
	if err := checkBundleKeys(b, caKeys, gens); err != nil {
		return nil, err
	}
	if err := checkCAKeysGeneration1(caKeys, gens); err != nil {
		return nil, err
	}
	if err := checkPolicyAdmins(b, p, gens); err != nil {
		return nil, err
	}
	ts := &trustState{stored: stored, bundle: b, policy: p, ca: map[wire.CARole]keystore.CAKey{}, profiles: map[wire.CARole]cert.Profile{}}
	for role, kr := range caRoles {
		prof, err := certprofile.ForRole(string(kr), p)
		if err != nil {
			return nil, err
		}
		ts.profiles[role] = prof
	}
	for _, k := range caKeys {
		if k.Role != "log" {
			continue
		}
		pub, err := ssh.ParsePublicKey(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: stored log key: %w", ErrBundleKeys, err)
		}
		if b.Log.Origin != tlog.Origin(pub) {
			return nil, fmt.Errorf("%w: log origin %q is not the log key's", ErrBundleKeys, b.Log.Origin)
		}
	}
	return ts, nil
}
