package signer

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
)

// Refusals of ca-rotate prepare (03-12). Each message starts with the name
// the runbook and the operator search for.
var (
	// ErrRotationRole refuses a role whose generations are not supported:
	// ops and log keys rotate in 03-13.
	ErrRotationRole = errors.New("rotation_role_not_supported")
	// ErrRotationBackend refuses a backend whose generations are not
	// supported yet (tpm and piv) or that is not a registered backend.
	ErrRotationBackend = errors.New("rotation_not_supported_on_backend")
	// ErrRotationCustody refuses a new key whose custody is not the one
	// recorded for the role's generation 1: a rotation never changes
	// custody.
	ErrRotationCustody = errors.New("rotation_custody_mismatch")
)

// rotationBackends are the registered keystore backends (pkcs11-agent is a
// custody label of the agent backend, not a backend), and
// rotationNotYet those of them whose CA key generations arrive in 03-12f,
// which deletes both entries.
var (
	rotationBackends = map[string]bool{"agent": true, "software": true, "tpm": true, "piv": true}
	rotationNotYet   = map[string]bool{"tpm": true, "piv": true}
)

// CheckRotationBackend refuses, by the backend name ca-init stored and
// before any backend is opened, a backend that cannot hold a later CA key
// generation yet: agent and software can, tpm and piv cannot until 03-12f,
// and an unknown name is refused too (03-12).
func CheckRotationBackend(name string) error {
	switch {
	case rotationNotYet[name]:
		return fmt.Errorf("%w: backend %s: tpm and piv generations arrive in 03-12f", ErrRotationBackend, name)
	case !rotationBackends[name]:
		return fmt.Errorf("%w: unknown backend %q (tpm and piv generations arrive in 03-12f)", ErrRotationBackend, name)
	}
	return nil
}

// PrepareGeneration records the next CA key generation of role (user, host
// or machine) for a later rotation (03-12, D-14): with selectFP the backend
// key with that fingerprint, opened at the next generation through
// keystore.KeyFor, otherwise a key the backend creates
// (keystore.GenerationProvisioner). The new key must have the custody of
// the role's generation 1 and may equal no stored generation of any role,
// no root key of any trust bundle the log records (retired roots
// included), no key of the installed bundle in any state and no admin of
// the installed policy. The generation row and a ca_generation log entry
// are written in one transaction; on any refusal nothing is written. The
// log is checked (generations_not_logged included) before any key is
// created, so only a failed final commit or a fresh key that collides can
// leave a created key that no row records, and the error then says so.
// It changes nothing a host, a client or a trust bundle can see.
func PrepareGeneration(ctx context.Context, db *signerdb.DB, be keystore.Backend, role keystore.Role, selectFP string,
	clock serial.Clock) (signerdb.CAGeneration, error) {
	if db == nil || be == nil {
		return signerdb.CAGeneration{}, errors.New("signer: PrepareGeneration needs a state database and a keystore backend")
	}
	if err := checkRotationRole(role); err != nil {
		return signerdb.CAGeneration{}, err
	}
	if clock == nil {
		clock = time.Now
	}
	caKeys, err := db.CAKeys(ctx)
	if errors.Is(err, signerdb.ErrNotInitialised) {
		return signerdb.CAGeneration{}, ErrNotInitialised
	}
	if err != nil {
		return signerdb.CAGeneration{}, err
	}
	if _, err := db.LatestBundle(ctx); errors.Is(err, signerdb.ErrNoBundle) {
		return signerdb.CAGeneration{}, ErrNoTrustBundle
	} else if err != nil {
		return signerdb.CAGeneration{}, err
	}
	// The log key is still generation 1 (03-13 rotates it).
	logKey, err := openRoleKey(be, caKeys, "log")
	if err != nil {
		return signerdb.CAGeneration{}, err
	}
	lw, err := newLogWriter(ctx, db, logKey, clock)
	if err != nil {
		return signerdb.CAGeneration{}, err
	}
	return prepareGeneration(ctx, lw, db, be, role, selectFP, clock)
}

// checkRotationRole accepts the CA roles user, host and machine.
func checkRotationRole(role keystore.Role) error {
	switch role {
	case keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine:
		return nil
	case keystore.RoleOps, keystore.RoleLog:
		return fmt.Errorf("%w: role %s: ops and log key generations arrive in 03-13", ErrRotationRole, role)
	default:
		return fmt.Errorf("%w: unknown role %q (user, host or machine)", ErrRotationRole, role)
	}
}

// prepareGeneration is PrepareGeneration after the log writer lw exists
// (its log checks have run): it reads every distinctness input, then
// selects or creates the key, checks it, and writes the row and the
// ca_generation entry in one logTx.
func prepareGeneration(ctx context.Context, lw *Signer, db *signerdb.DB, be keystore.Backend, role keystore.Role, selectFP string,
	clock serial.Clock) (signerdb.CAGeneration, error) {
	if err := checkRotationRole(role); err != nil {
		return signerdb.CAGeneration{}, err
	}
	stored, err := db.LatestBundle(ctx)
	if errors.Is(err, signerdb.ErrNoBundle) {
		return signerdb.CAGeneration{}, ErrNoTrustBundle
	}
	if err != nil {
		return signerdb.CAGeneration{}, err
	}
	// The stored bundle and policy are the distinctness inputs below, so
	// the row must be the one the verified log's last bundle_install entry
	// records, as InstallBundle requires: an edited policy that no longer
	// names an admin key would otherwise let that key become a generation
	// (PR #102 review, I2).
	if err := checkBundleLogged(stored, lw.loaded.last); err != nil {
		return signerdb.CAGeneration{}, err
	}
	b, err := trust.ParseBundle(stored.Bundle)
	if err != nil {
		return signerdb.CAGeneration{}, fmt.Errorf("signer: installed bundle: %w", err)
	}
	p, err := trust.ParsePolicy(stored.Policy)
	if err != nil {
		return signerdb.CAGeneration{}, fmt.Errorf("signer: installed policy: %w", err)
	}
	gens, err := db.CAGenerations(ctx)
	if err != nil {
		return signerdb.CAGeneration{}, err
	}
	var (
		latest      uint32
		gen1Custody string
		used        []string
	)
	for _, g := range gens {
		if g.Role == string(role) {
			latest = max(latest, g.Generation)
			if g.Generation == 1 {
				gen1Custody = g.Custody
			}
		}
		if g.Location != "" {
			used = append(used, g.Location)
		}
	}
	if latest == 0 || gen1Custody == "" {
		return signerdb.CAGeneration{}, fmt.Errorf("%w: no stored generation 1 of role %s", ErrBundleKeys, role)
	}
	if latest == ^uint32(0) {
		return signerdb.CAGeneration{}, fmt.Errorf("%w: role %s has no generation number left", ErrKeySelection, role)
	}
	next := latest + 1
	// Every root of every trust bundle the log records, retired roots
	// included, as audit verify compares a ca_generation key with them.
	var roots []trust.RootKey
	for _, rs := range lw.loaded.roots {
		roots = append(roots, rs...)
	}

	g := signerdb.CAGeneration{Role: string(role), Generation: next}
	var created ssh.PublicKey // a key the backend created, which no row records yet
	if selectFP != "" {
		key, err := pinnedKeyAt(be, role, next, selectFP, "")
		if err != nil {
			return signerdb.CAGeneration{}, fmt.Errorf("%w: role %s generation %d: %w", ErrKeySelection, role, next, err)
		}
		pub := key.PublicKey()
		if key.Algorithm() != pub.Type() {
			return signerdb.CAGeneration{}, fmt.Errorf("%w: role %s: backend reports algorithm %q for a %s key", ErrKeySelection, role, key.Algorithm(), pub.Type())
		}
		if string(key.Custody()) != gen1Custody {
			return signerdb.CAGeneration{}, fmt.Errorf("%w: the key %s has custody %s, generation 1 of %s has %s", ErrRotationCustody,
				ssh.FingerprintSHA256(pub), key.Custody(), role, gen1Custody)
		}
		g.PublicKey, g.Alg, g.Custody = pub.Marshal(), pub.Type(), string(key.Custody())
	} else {
		prov, ok := be.(keystore.GenerationProvisioner)
		if !ok {
			return signerdb.CAGeneration{}, fmt.Errorf("%w: this backend cannot create a key; pass --key with the fingerprint of the new key", ErrKeySelection)
		}
		// A created key has the custody of the backend's keys, which the
		// opened log key reports.
		if custody := string(lw.logKey.Custody()); custody != gen1Custody {
			return signerdb.CAGeneration{}, fmt.Errorf("%w: the backend creates keys with custody %s, generation 1 of %s has %s", ErrRotationCustody,
				custody, role, gen1Custody)
		}
		pub, location, err := prov.ProvisionGeneration(role, next, used)
		if err != nil {
			return signerdb.CAGeneration{}, fmt.Errorf("signer: create generation %d of %s: %w", next, role, err)
		}
		created = pub
		g.PublicKey, g.Alg, g.Custody, g.Location = pub.Marshal(), pub.Type(), gen1Custody, location
		if err := cert.CheckCAKey(pub); err != nil {
			return signerdb.CAGeneration{}, orphaned(created, role, next, err)
		}
	}
	if err := checkGenerationDistinct(g.PublicKey, gens, roots, b, p); err != nil {
		return signerdb.CAGeneration{}, orphaned(created, role, next, err)
	}
	body, err := (&tlog.CAGenerationBody{Role: g.Role, Generation: g.Generation, PublicKey: g.PublicKey, Alg: g.Alg, Custody: g.Custody}).Encode()
	if err != nil {
		return signerdb.CAGeneration{}, orphaned(created, role, next, err)
	}
	now := clock()
	g.CreatedAtMicros = now.UnixMicro()
	err = lw.logTx(ctx, func(tx *sql.Tx) error {
		if err := db.InsertCAGenerationTx(tx, g); err != nil {
			return err
		}
		_, err := lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindCAGeneration, Body: body})
		return err
	})
	if err != nil {
		return signerdb.CAGeneration{}, orphaned(created, role, next, err)
	}
	return g, nil
}

// pinnedKeyAt is pinnedKey for generation of role (03-12): it opens the key
// through keystore.KeyFor with location, and checks, as defence in depth,
// the fingerprint and the key type the backend promised.
func pinnedKeyAt(b keystore.Backend, role keystore.Role, generation uint32, fp, location string) (keystore.CAKey, error) {
	if fp == "" {
		return nil, fmt.Errorf("no fingerprint for role %s", role)
	}
	key, err := keystore.KeyFor(b, role, generation, fp, location)
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

// orphaned names a key the backend created for generation of role that no
// row records, so the operator can remove it; err is returned unchanged
// when no key was created.
func orphaned(created ssh.PublicKey, role keystore.Role, generation uint32, err error) error {
	if created == nil {
		return err
	}
	return fmt.Errorf("%w (the backend created the key %s for generation %d of %s, which no generation row records: remove it; for the software backend it is {state-dir}/software/%s-g%d.age)",
		err, ssh.FingerprintSHA256(created), generation, role, role, generation)
}

// checkGenerationDistinct refuses a new generation key that equals a
// stored generation of any role, a root key of any bundle the log records,
// a key of the installed bundle in any state (ops and log included) or an
// admin of the installed policy, naming what it equals.
func checkGenerationDistinct(pub []byte, gens []signerdb.CAGeneration, roots []trust.RootKey, b *trust.Bundle, p *trust.Policy) error {
	fp := fingerprintOfWire(pub)
	for _, g := range gens {
		if bytes.Equal(g.PublicKey, pub) {
			return fmt.Errorf("%w: the key %s equals stored generation %d of %s", ErrKeySelection, fp, g.Generation, g.Role)
		}
	}
	equal := func(key string) bool {
		k, err := trust.ParseKey(key)
		return err == nil && bytes.Equal(k.Marshal(), pub)
	}
	for _, rk := range roots {
		if equal(rk.Key) {
			return fmt.Errorf("%w: the key %s is a root key of a trust bundle the log records", ErrBundleKeys, fp)
		}
	}
	for _, ca := range b.CAs {
		if equal(ca.Key) {
			return fmt.Errorf("%w: the key %s is the installed bundle's %s CA key (generation %d, %s)", ErrBundleKeys, fp, ca.Role, ca.Generation, ca.State)
		}
	}
	if equal(b.OpsKey.Key) {
		return fmt.Errorf("%w: the key %s is the installed bundle's ops key", ErrBundleKeys, fp)
	}
	if equal(b.Log.Key) {
		return fmt.Errorf("%w: the key %s is the installed bundle's log key", ErrBundleKeys, fp)
	}
	for _, a := range p.Admins {
		if equal(a.Key) {
			return fmt.Errorf("%w: the key %s is policy admin %s", ErrBundleKeys, fp, a.Name)
		}
	}
	return nil
}

func fingerprintOfWire(pub []byte) string {
	k, err := ssh.ParsePublicKey(pub)
	if err != nil {
		return "an unparsable key"
	}
	return ssh.FingerprintSHA256(k)
}
