// Package keystore defines how keyroster-signer reaches its CA keys. Every
// backend (ssh-agent, TPM, PIV, ...) yields keys as ssh.Signer values plus
// custody metadata, and every key is selected by a pinned SHA-256
// fingerprint, never by position.
package keystore

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// ErrCredentialRefused means the key store refused the credential the
// signer presented (a PIV PIN, a TPM key's auth value), or that the backend
// refused to present one because the device has too few attempts left.
// Each further try uses up one of the device's limited attempts (the card's
// PIN retry counter, the TPM's dictionary-attack counter for keys without
// noDA), so keyroster-signer exits with a dedicated status that its systemd
// unit never restarts on: an operator must fix the secret first.
var ErrCredentialRefused = errors.New("keystore: the key store refused the credential (retrying uses up the device's limited attempts)")

// Custody records where a key lives. It is written into the trust bundle and
// the audit log, so the weaker custodies stay visible.
type Custody string

// Custody values.
const (
	CustodyAgent       Custody = "agent"
	CustodyPKCS11Agent Custody = "pkcs11-agent"
	CustodyTPM         Custody = "tpm"
	CustodyVTPM        Custody = "vtpm"
	CustodyPIV         Custody = "piv"
	CustodySoftware    Custody = "software"
)

// Role names what a key is used for.
type Role string

// Key roles.
const (
	RoleUser    Role = "user"
	RoleHost    Role = "host"
	RoleMachine Role = "machine"
	RoleOps     Role = "ops"
	RoleLog     Role = "log"
)

// CAKey is a signing key held by a backend. Its public key is never an
// *ssh.Certificate (CA-07), and its algorithm is ssh-ed25519 or
// ecdsa-sha2-nistp256 (D-09).
type CAKey interface {
	ssh.Signer
	Custody() Custody
	Algorithm() string
}

// Backend gives access to the keys of one key store.
type Backend interface {
	// Key returns the key for role whose SHA-256 fingerprint
	// (ssh.FingerprintSHA256 format) equals fingerprint. It never falls
	// back to another key.
	Key(role Role, fingerprint string) (CAKey, error)
	Close() error
}

// OptStateDir is the reserved backend option through which keyroster-signer
// (ca-init, install-bundle and serve) passes its state directory, for
// backends that keep files there (the TPM backend's key files). Operators
// cannot set it, it is never stored with the backend configuration, and
// CheckOptions accepts it for every backend.
const OptStateDir = "state-dir"

// Describer is implemented by backends that have a one-line description for
// the operator, for example the TPM manufacturer and the custody derived
// from it. ca-init prints it.
type Describer interface {
	Describe() string
}

// Provisioner is implemented by backends that can create keys in place (for
// example inside a TPM), returning the new public keys.
type Provisioner interface {
	Provision(roles []Role) (map[Role]ssh.PublicKey, error)
}

// GenerationProvisioner is implemented by backends that can create the key
// of a later CA key generation in place (03-12: the software backend). used
// holds the non-empty locations that every stored generation row of every
// role records, so that a backend with a handle to allocate (a PIV slot)
// can choose a free one. It returns the new public key and the location to
// record in the generation row; the software backend returns "".
type GenerationProvisioner interface {
	ProvisionGeneration(role Role, generation uint32, used []string) (pub ssh.PublicKey, location string, err error)
}

// GenerationBackend is implemented by backends that keep a separate key per
// CA key generation (03-12: the software backend, one file per
// generation). KeyAt returns the key of that generation of role whose
// SHA-256 fingerprint equals fingerprint, and never falls back to another
// key or generation. location is the generation row's location column, as
// ProvisionGeneration returned it; the software, agent and memory backends
// ignore it, and a backend with a handle to remember (a PIV slot) receives
// it here.
type GenerationBackend interface {
	KeyAt(role Role, generation uint32, fingerprint, location string) (CAKey, error)
}

// KeyFor opens the key of generation of role with fingerprint: through
// KeyAt when b is a GenerationBackend, otherwise through Key, which selects
// by fingerprint only and takes no location (03-12).
func KeyFor(b Backend, role Role, generation uint32, fingerprint, location string) (CAKey, error) {
	if g, ok := b.(GenerationBackend); ok {
		return g.KeyAt(role, generation, fingerprint, location)
	}
	return b.Key(role, fingerprint)
}
