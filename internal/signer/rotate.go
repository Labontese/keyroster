package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	// ErrRotationBackend refuses a stored backend name that is not a
	// registered keystore backend.
	ErrRotationBackend = errors.New("rotation_not_supported_on_backend")
	// ErrRotationCustody refuses a new key whose custody is not the one
	// recorded for the role's generation 1: a rotation never changes
	// custody.
	ErrRotationCustody = errors.New("rotation_custody_mismatch")
)

// rotationBackends are the registered keystore backends, each of which can
// hold a later CA key generation (pkcs11-agent is a custody label of the
// agent backend, not a backend).
var rotationBackends = map[string]bool{"agent": true, "software": true, "tpm": true, "piv": true}

// CheckRotationBackend refuses, by the backend name ca-init stored and
// before any backend is opened, a name that is not a registered keystore
// backend: agent, software, tpm and piv each hold later CA key
// generations.
func CheckRotationBackend(name string) error {
	if !rotationBackends[name] {
		return fmt.Errorf("%w: unknown backend %q", ErrRotationBackend, name)
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
			return signerdb.CAGeneration{}, orphaned(created, role, next, g.Location, err)
		}
	}
	if err := checkGenerationDistinct(g.PublicKey, gens, roots, b, p); err != nil {
		return signerdb.CAGeneration{}, orphaned(created, role, next, g.Location, err)
	}
	body, err := (&tlog.CAGenerationBody{Role: g.Role, Generation: g.Generation, PublicKey: g.PublicKey, Alg: g.Alg, Custody: g.Custody}).Encode()
	if err != nil {
		return signerdb.CAGeneration{}, orphaned(created, role, next, g.Location, err)
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
		return signerdb.CAGeneration{}, orphaned(created, role, next, g.Location, err)
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
// row records, so the operator can remove it: at the location the backend
// returned when there is one, otherwise by the software backend's file and
// the tpm backend's two files. err is returned unchanged when no key was
// created.
func orphaned(created ssh.PublicKey, role keystore.Role, generation uint32, location string, err error) error {
	if created == nil {
		return err
	}
	if location != "" {
		return fmt.Errorf("%w (the backend created the key %s for generation %d of %s at location %s, which no generation row records: remove it)",
			err, ssh.FingerprintSHA256(created), generation, role, location)
	}
	return fmt.Errorf("%w (the backend created the key %s for generation %d of %s, which no generation row records: remove it; for the software backend it is {state-dir}/software/%s-g%d.age, for the tpm backend {state-dir}/tpm/%s-g%d.tpmkey and %s-g%d.auth)",
		err, ssh.FingerprintSHA256(created), generation, role, role, generation, role, generation, role, generation)
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

// Refusals of ca-rotate retire-key (03-12e). Each message starts with the
// name the runbook and the operator search for.
var (
	// ErrNoDrainingEntry refuses a role whose installed bundle has no
	// draining entry: retire-key handles draining keys only.
	ErrNoDrainingEntry = errors.New("no_draining_entry")
	// ErrActiveKeyUnusable refuses, before anything is removed, when the
	// role's active key cannot be opened or does not sign.
	ErrActiveKeyUnusable = errors.New("active_key_unusable")
	// ErrDrainingGenerationUnknown refuses a draining entry that no stored
	// generation row of its role, number and key matches.
	ErrDrainingGenerationUnknown = errors.New("draining_generation_unknown")
	// ErrDrainingNamesActive refuses a draining entry whose generation
	// number is the role's active entry's.
	ErrDrainingNamesActive = errors.New("draining_names_the_active_generation")
	// ErrRetireIncomplete reports that a draining key of the role is
	// still held after retire-key ran.
	ErrRetireIncomplete = errors.New("retire_key_incomplete")
)

// The outcomes of one draining generation in a RetireResult (03-12e).
const (
	// RetireRemoved: the backend removed the key and no longer holds it.
	RetireRemoved = "removed"
	// RetireNotHeld: the backend did not hold the key.
	RetireNotHeld = "not held"
	// RetireNotRemoved: the backend's removal refused or failed (Detail
	// says why); the key counts as still held.
	RetireNotRemoved = "not removed"
	// RetireStillHeld: the backend cannot remove the key itself (the
	// agent), still holds it after the removal, or cannot say (Detail);
	// KeyLine and CertLines name what to remove.
	RetireStillHeld = "still held"
)

// RetireResult is what RetireKeys did for each draining generation of one
// role (03-12e). Socket is the stored agent backend's socket option ("" for
// another backend): the agent through which an operator removes a key the
// agent still holds.
type RetireResult struct {
	Role        string
	Socket      string
	Generations []RetiredGeneration
}

// RetiredGeneration is the outcome for one draining generation (03-12e):
// its number and fingerprint, the outcome, a reason for RetireNotRemoved
// or for an unknown answer, and, while it is RetireStillHeld, the draining
// entry's public key line and the public line of each certificate
// identity of that key that the backend lists.
type RetiredGeneration struct {
	Generation  uint32
	Fingerprint string
	Outcome     string
	Detail      string
	KeyLine     string
	CertLines   []string
}

// Held reports whether the key of g still counts as held.
func (g RetiredGeneration) Held() bool {
	return g.Outcome != RetireRemoved && g.Outcome != RetireNotHeld
}

// retireTarget is a draining CA entry of the installed bundle and the
// stored generation row it names (03-12e).
type retireTarget struct {
	Entry trust.CAEntry
	Gen   signerdb.CAGeneration
}

// retireTargets pairs each draining entry of role in b with its generation
// row in gens (03-12e): the row of the same role and number whose key is
// the entry's. It refuses an entry whose number is the role's active
// entry's (ErrDrainingNamesActive) and one that no row matches
// (ErrDrainingGenerationUnknown), because the removal acts on a generation
// number, which must name a stored key of that role and never the active
// one. It returns none when role has no draining entry.
func retireTargets(b *trust.Bundle, gens []signerdb.CAGeneration, role string) ([]retireTarget, error) {
	active, hasActive := uint32(0), false
	for _, ca := range b.CAs {
		if ca.Role == role && ca.State == "active" {
			active, hasActive = ca.Generation, true
		}
	}
	var out []retireTarget
	for _, ca := range b.CAs {
		if ca.Role != role || ca.State != "draining" {
			continue
		}
		if hasActive && ca.Generation == active {
			return nil, fmt.Errorf("%w: the draining CA %s entry names generation %d, the active entry's", ErrDrainingNamesActive, role, ca.Generation)
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: CA %s generation %d: %w", ErrBundleKeys, role, ca.Generation, err)
		}
		i := slices.IndexFunc(gens, func(g signerdb.CAGeneration) bool {
			return g.Role == role && g.Generation == ca.Generation && bytes.Equal(g.PublicKey, pub.Marshal())
		})
		if i < 0 {
			return nil, fmt.Errorf("%w: the draining CA %s entry (generation %d, %s) names no stored generation of that key",
				ErrDrainingGenerationUnknown, role, ca.Generation, ssh.FingerprintSHA256(pub))
		}
		out = append(out, retireTarget{Entry: ca, Gen: gens[i]})
	}
	return out, nil
}

// retireProof is the message RetireKeys has the active key sign.
var retireProof = []byte("keyroster-signer ca-rotate retire-key: the active key signs (03-12e)")

// RetireKeys removes the key of every draining generation of role (user,
// host or machine) that be still holds, after a switch install (03-12e).
// It first proves what it acts on: the stored bundle must pass
// checkStoredTrust and be the one the verified log's last bundle_install
// entry records (checkBundleLogged, as InstallBundle and New require); its
// draining entries of role must name stored generation rows other than the
// active one (retireTargets), and there must be at least one
// (ErrNoDrainingEntry); and the role's active generation must open and
// sign a test message (ErrActiveKeyUnusable). Only then, per draining
// generation, it asks keystore.Holds, removes the key through
// keystore.GenerationRemover when the backend has one, and asks again. A
// backend without a remover (the agent) keeps the key, and the result
// names the key and its certificate identities, with the stored socket,
// for the operator to remove. It returns the result, and with it
// ErrRetireIncomplete while any generation is still held. It writes no log
// leaf and no row.
func RetireKeys(ctx context.Context, db *signerdb.DB, be keystore.Backend, role keystore.Role) (*RetireResult, error) {
	if db == nil || be == nil {
		return nil, errors.New("signer: RetireKeys needs a state database and a keystore backend")
	}
	if err := checkRotationRole(role); err != nil {
		return nil, err
	}
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
	logKey, err := openRoleKey(be, caKeys, "log")
	if err != nil {
		return nil, err
	}
	lw, err := newLogWriter(ctx, db, logKey, time.Now)
	if err != nil {
		return nil, err
	}
	if err := checkBundleLogged(stored, lw.loaded.last); err != nil {
		return nil, err
	}
	targets, err := retireTargets(ts.bundle, gens, string(role))
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: the installed bundle has no draining CA %s entry", ErrNoDrainingEntry, role)
	}
	if err := proveActiveKey(be, ts.bundle, gens, string(role)); err != nil {
		return nil, err
	}
	res := &RetireResult{Role: string(role)}
	if name, opts, err := db.BackendConfig(ctx); err == nil && name == "agent" {
		res.Socket = opts["socket"]
	}
	held := 0
	for _, tg := range targets {
		g := retireOne(be, role, tg)
		if g.Held() {
			held++
		}
		res.Generations = append(res.Generations, g)
	}
	if held > 0 {
		return res, fmt.Errorf("%w: %d draining generation(s) of role %s are still held", ErrRetireIncomplete, held, role)
	}
	return res, nil
}

// proveActiveKey opens role's active generation and requires it to sign
// retireProof with a signature its public key verifies (03-12e).
func proveActiveKey(be keystore.Backend, b *trust.Bundle, gens []signerdb.CAGeneration, role string) error {
	g, err := activeGeneration(b, gens, role)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrActiveKeyUnusable, err)
	}
	key, err := openGenerationKey(be, g)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrActiveKeyUnusable, err)
	}
	sig, err := key.Sign(rand.Reader, retireProof)
	if err == nil {
		err = key.PublicKey().Verify(retireProof, sig)
	}
	if err != nil {
		return fmt.Errorf("%w: generation %d of the %s CA does not sign: %w", ErrActiveKeyUnusable, g.Generation, role, err)
	}
	return nil
}

// retireOne removes, where the backend can, the key of one draining
// generation and reports the outcome (03-12e).
func retireOne(be keystore.Backend, role keystore.Role, tg retireTarget) RetiredGeneration {
	fp := fingerprintOfWire(tg.Gen.PublicKey)
	out := RetiredGeneration{Generation: tg.Gen.Generation, Fingerprint: fp}
	held, err := keystore.Holds(be, role, tg.Gen.Generation, fp, tg.Gen.Location)
	if err == nil && !held {
		out.Outcome = RetireNotHeld
		return out
	}
	if rm, ok := be.(keystore.GenerationRemover); ok {
		if err := rm.RemoveGeneration(role, tg.Gen.Generation, fp, tg.Gen.Location); err != nil {
			out.Outcome, out.Detail = RetireNotRemoved, err.Error()
			return out
		}
		held, err = keystore.Holds(be, role, tg.Gen.Generation, fp, tg.Gen.Location)
		if err == nil && !held {
			out.Outcome = RetireRemoved
			return out
		}
	}
	out.Outcome, out.KeyLine = RetireStillHeld, tg.Entry.Key
	if err != nil {
		out.Detail = "cannot tell whether the backend holds it: " + err.Error()
	}
	if cl, ok := be.(keystore.CertificateLister); ok {
		certs, cerr := cl.Certificates(fp)
		if cerr != nil && out.Detail == "" {
			out.Detail = "cannot list its certificate identities: " + cerr.Error()
		}
		for _, c := range certs {
			out.CertLines = append(out.CertLines, strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(c)), "\n"))
		}
	}
	return out
}
