//go:build linux

// Package tpm is the TPM 2.0 keystore backend, registered as "tpm" (KEY-04).
// The CA, ops and log keys are ECDSA P-256 keys created inside the TPM
// (D-09); the TPM never reveals them. On disk the signer keeps, per role,
// a TSS2 PEM key file ({state-dir}/tpm/{role}.tpmkey, the key wrapped by
// the TPM's storage root key) and a random 32-byte auth value
// ({role}.auth) that the TPM requires for every signature. Both are mode
// 0600 in a 0700 directory owned by the signer.
//
// The TPM is reached through the kernel resource manager (/dev/tpmrm0), or
// in tests through an swtpm socket. Pure Go, no cgo: go-tpm and
// go-tpm-keyfiles.
//
// Custody is derived from the TPM manufacturer: software and virtual TPMs
// (swtpm/libtpms, which Proxmox vTPM uses, Microsoft and Google vTPMs)
// are custody vtpm, every other manufacturer is custody tpm. A vTPM is only
// as safe as its hypervisor host.
//
// Options:
//
//	state-dir     the signer's state directory (set by keyroster-signer)
//	device        TPM resource-manager device (default /dev/tpmrm0)
//	swtpm-socket  test and development only: swtpm unixio socket path
//	custody       "vtpm" forces custody vtpm (for a virtual TPM with an
//	              unrecognised manufacturer); "tpm" is accepted only when
//	              the manufacturer already maps to tpm
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
)

// Errors of the TPM backend.
var (
	// ErrKeyNotPresent means the key file for a role holds another key
	// than the pinned one. The backend never falls back to another key.
	ErrKeyNotPresent = errors.New("keystore tpm: pinned CA key not present in the TPM key files")
	// ErrKeyFilesExist means Provision found key files from an earlier
	// run; it overwrites nothing.
	ErrKeyFilesExist = errors.New("keystore tpm: TPM key files already exist")
)

// tpmMu serialises every TPM command of this process: provisioning,
// capability queries and signatures, across all backends and keys.
var tpmMu sync.Mutex

func init() { keystore.Register("tpm", open) }

type backend struct {
	tpm          transport.TPMCloser // used only under tpmMu
	dir          string              // {state-dir}/tpm
	manufacturer string
	custody      keystore.Custody
}

func open(opts map[string]string) (keystore.Backend, error) {
	if err := keystore.CheckOptions(opts, "device", "swtpm-socket", "custody"); err != nil {
		return nil, err
	}
	stateDir := opts[keystore.OptStateDir]
	if stateDir == "" || !filepath.IsAbs(stateDir) {
		return nil, errors.New("keystore tpm: needs the signer's absolute state directory (option state-dir, set by keyroster-signer)")
	}
	override := keystore.Custody(opts["custody"])
	switch override {
	case "", keystore.CustodyTPM, keystore.CustodyVTPM:
	default:
		return nil, fmt.Errorf("keystore tpm: custody must be %q or %q", keystore.CustodyTPM, keystore.CustodyVTPM)
	}
	t, err := openTransport(opts)
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: open TPM: %w", err)
	}
	tpmMu.Lock()
	id, err := Manufacturer(t)
	tpmMu.Unlock()
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("keystore tpm: read the TPM manufacturer: %w", err)
	}
	custody := CustodyForManufacturer(id)
	switch {
	case override == keystore.CustodyVTPM:
		custody = keystore.CustodyVTPM
	case override == keystore.CustodyTPM && custody != keystore.CustodyTPM:
		_ = t.Close()
		return nil, fmt.Errorf("keystore tpm: custody tpm refused: TPM manufacturer %q is a software or virtual TPM (custody %s)", id, custody)
	}
	return &backend{tpm: t, dir: filepath.Join(stateDir, "tpm"), manufacturer: id, custody: custody}, nil
}

// Describe names the TPM manufacturer and the custody derived from it.
func (b *backend) Describe() string {
	return fmt.Sprintf("TPM manufacturer: %s → custody %s", b.manufacturer, b.custody)
}

// keyPaths returns the key file and auth file of role. Only the five known
// roles have files, so a role can never name a path outside the directory.
func (b *backend) keyPaths(role keystore.Role) (keyPath, authPath string, err error) {
	switch role {
	case keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog:
	default:
		return "", "", fmt.Errorf("keystore tpm: unknown role %q", role)
	}
	base := filepath.Join(b.dir, string(role))
	return base + ".tpmkey", base + ".auth", nil
}

// Key loads the key file of role, checks that its public key has the
// pinned fingerprint and is an ECDSA P-256 CA key, and returns a CAKey that
// signs inside the TPM with the role's auth value.
func (b *backend) Key(role keystore.Role, fingerprint string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore tpm: no pinned fingerprint for role %s", role)
	}
	keyPath, authPath, err := b.keyPaths(role)
	if err != nil {
		return nil, err
	}
	if err := checkPrivateDir(b.dir); err != nil {
		return nil, err
	}
	pem, err := readPrivateFile(keyPath)
	if err != nil {
		return nil, err
	}
	auth, err := readPrivateFile(authPath)
	if err != nil {
		return nil, err
	}
	k, err := keyfile.Decode(pem)
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: %s: %w", keyPath, err)
	}
	if !k.Keytype.Equal(keyfile.OIDLoadableKey) || k.KeyAlgo() != tpm2.TPMAlgECC {
		return nil, fmt.Errorf("keystore tpm: %s is not a loadable ECC key", keyPath)
	}
	cpub, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: %s: %w", keyPath, err)
	}
	ec, ok := cpub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("keystore tpm: %s does not hold an ECDSA P-256 key", keyPath)
	}
	pub, err := ssh.NewPublicKey(ec)
	if err != nil {
		return nil, err
	}
	if ssh.FingerprintSHA256(pub) != fingerprint {
		return nil, fmt.Errorf("%w (role %s)", ErrKeyNotPresent, role)
	}
	if err := cert.CheckCAKey(pub); err != nil {
		return nil, fmt.Errorf("keystore tpm: key for role %s: %w", role, err)
	}
	cs, err := k.Signer(b.tpm, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: key for role %s: %w", role, err)
	}
	s, err := ssh.NewSignerFromSigner(lockedSigner{cs})
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: key for role %s: %w", role, err)
	}
	return &caKey{Signer: s, custody: b.custody}, nil
}

func (b *backend) Close() error {
	tpmMu.Lock()
	defer tpmMu.Unlock()
	return b.tpm.Close()
}

// lockedSigner runs every TPM signature under tpmMu, so concurrent
// signatures never interleave on the transport.
type lockedSigner struct{ crypto.Signer }

func (l lockedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	tpmMu.Lock()
	defer tpmMu.Unlock()
	return l.Signer.Sign(rand, digest, opts)
}

// caKey is a TPM-held CA key. Its signatures are ASN.1 ECDSA from the TPM,
// converted to the SSH format by ssh.NewSignerFromSigner.
type caKey struct {
	ssh.Signer
	custody keystore.Custody
}

func (k *caKey) Custody() keystore.Custody { return k.custody }

func (k *caKey) Algorithm() string { return ssh.KeyAlgoECDSA256 }

// checkPrivateDir requires dir to be a directory, not a symlink, with no
// group or other permissions.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("keystore tpm: key directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("keystore tpm: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("keystore tpm: %s has mode %04o, want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// readPrivateFile reads a regular file that has no group or other
// permissions.
func readPrivateFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keystore tpm: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keystore tpm: %s has mode %04o, want 0600", path, fi.Mode().Perm())
	}
	return os.ReadFile(path) //nolint:gosec // G304: a fixed name inside the signer's own state directory
}
