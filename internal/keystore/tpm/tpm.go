//go:build linux

// Package tpm is the TPM 2.0 keystore backend, registered as "tpm" (KEY-04).
// The CA, ops and log keys are ECDSA P-256 keys created inside the TPM
// (D-09); the TPM never reveals them. Key refuses a key file whose key was
// imported into the TPM rather than generated in it. On disk the signer
// keeps, per role, a TSS2 PEM key file ({state-dir}/tpm/{role}.tpmkey, the
// key wrapped by the TPM's storage root key) and a random 32-byte auth
// value ({role}.auth) that the TPM requires for every signature. Both are
// mode 0600 in a 0700 directory owned by the signer.
//
// CA key generations (03-12f): generation N of at least 2 of a role is
// {state-dir}/tpm/{role}-g{N}.tpmkey and {role}-g{N}.auth, created inside
// the TPM with noDA like the genesis keys; generation 1 keeps the names
// above. KeyAt opens exactly the asked generation's two files, never falls
// back to another generation, and refuses a key of generation 2 or later
// without noDA. Holds and GenerationHeld look at the two names only (any
// directory entry at either counts) and send no TPM command.
// RemoveGeneration removes a generation's regular key file, together with
// its auth file, only after the key file's public key matched the draining
// fingerprint; a link or any other entry at the names opens no key and is
// unlinked unchecked. Removing the files deletes the key's wrapped blobs
// and destroys nothing inside the TPM: any earlier copy of both files
// still signs on the same TPM until its owner hierarchy is cleared.
//
// The TPM is reached through the kernel resource manager (/dev/tpmrm0), or
// in tests through an swtpm socket. Pure Go, no cgo: go-tpm and
// go-tpm-keyfiles.
//
// Custody is derived from the TPM manufacturer and fails closed: only an
// allowlist of physical and firmware TPM vendors (Intel, AMD, Infineon,
// Nuvoton, STMicroelectronics) is custody tpm; software and virtual TPMs
// (swtpm/libtpms, which Proxmox vTPM uses, Microsoft and Google vTPMs) and
// every unknown manufacturer are custody vtpm, and so is any TPM reached
// through swtpm-socket. A vTPM is only as safe as its hypervisor host. The
// manufacturer ID is self-reported and not authenticated (see vendor.go).
//
// Options:
//
//	state-dir     the signer's state directory (set by keyroster-signer)
//	device        TPM resource-manager device (default /dev/tpmrm0)
//	swtpm-socket  test and development only: swtpm unixio socket path;
//	              always custody vtpm
//	custody       "vtpm" forces custody vtpm; "tpm" is accepted only when
//	              the custody already is tpm
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	// ErrKeyFileUnreadable means RemoveGeneration found a regular file at
	// a generation's key name that cannot be read as a TPM key file, so it
	// is not shown to hold the draining key: nothing is removed (03-12f).
	ErrKeyFileUnreadable = errors.New("keystore tpm: the key file cannot be read as a TPM key")
)

// The TPM backend keeps one key per CA key generation, says whether a
// generation's files are still present and removes them (03-12f).
var (
	_ keystore.GenerationBackend     = (*backend)(nil)
	_ keystore.GenerationProvisioner = (*backend)(nil)
	_ keystore.GenerationHolder      = (*backend)(nil)
	_ keystore.GenerationRemover     = (*backend)(nil)
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
	custody := deriveCustody(id, opts)
	if override == keystore.CustodyTPM && custody != keystore.CustodyTPM {
		_ = t.Close()
		return nil, fmt.Errorf("keystore tpm: custody tpm refused: TPM manufacturer %q maps to custody %s (only a physical TPM vendor on the allowlist, reached through device, is custody tpm; swtpm-socket is always vtpm)", id, custody)
	}
	return &backend{tpm: t, dir: filepath.Join(stateDir, "tpm"), manufacturer: id, custody: custody}, nil
}

// Describe names the TPM manufacturer and the custody derived from it.
func (b *backend) Describe() string {
	return fmt.Sprintf("TPM manufacturer: %s → custody %s", b.manufacturer, b.custody)
}

// keyPaths returns the key file and auth file of role's generation 1.
func (b *backend) keyPaths(role keystore.Role) (keyPath, authPath string, err error) {
	return b.keyPathsAt(role, 1)
}

// keyPathsAt returns the key file and auth file of generation of role
// (03-12f): {role}.tpmkey and {role}.auth for generation 1 and
// {role}-g{N}.tpmkey and {role}-g{N}.auth from generation 2. Only the five
// known roles have files, so a role can never name a path outside the
// directory; generation 0 has none.
func (b *backend) keyPathsAt(role keystore.Role, generation uint32) (keyPath, authPath string, err error) {
	switch role {
	case keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog:
	default:
		return "", "", fmt.Errorf("keystore tpm: unknown role %q", role)
	}
	var base string
	switch generation {
	case 0:
		return "", "", fmt.Errorf("keystore tpm: no generation 0 of role %s", role)
	case 1:
		base = filepath.Join(b.dir, string(role))
	default:
		base = filepath.Join(b.dir, fmt.Sprintf("%s-g%d", role, generation))
	}
	return base + ".tpmkey", base + ".auth", nil
}

// Key is KeyAt generation 1: the ca-init key of role (03-12f).
func (b *backend) Key(role keystore.Role, fingerprint string) (keystore.CAKey, error) {
	return b.KeyAt(role, 1, fingerprint, "")
}

// KeyAt loads the key file of generation of role (exactly that
// generation's two files: no scanning and no fallback to another
// generation, 03-12f), checks that the key was generated inside the TPM
// and cannot leave it (checkGeneratedInTPM), that a key of generation 2 or
// later has noDA, and that its public key has the pinned fingerprint and
// is an ECDSA P-256 CA key, proves the auth value with one test signature
// (probe), and returns a CAKey that signs inside the TPM with that auth
// value. It ignores location: the file names derive from role and
// generation only.
func (b *backend) KeyAt(role keystore.Role, generation uint32, fingerprint, _ string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore tpm: no pinned fingerprint for role %s", role)
	}
	keyPath, authPath, err := b.keyPathsAt(role, generation)
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
	pubArea, err := k.Pubkey.Contents()
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: %s: %w", keyPath, err)
	}
	if err := checkGeneratedInTPM(pubArea); err != nil {
		return nil, fmt.Errorf("keystore tpm: %s: %w", keyPath, err)
	}
	// Every key this backend creates has noDA. A later generation's key
	// may be one the operator placed for prepare --key: without noDA its
	// failed authorisations would count toward the TPM-wide
	// dictionary-attack lockout, so it is refused before any TPM command
	// (03-12f). Generation 1 keys created before noDA was set still open.
	if generation >= 2 && !pubArea.ObjectAttributes.NoDA {
		return nil, fmt.Errorf("keystore tpm: %s: the key of generation %d lacks noDA", keyPath, generation)
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
		return nil, fmt.Errorf("%w (role %s generation %d)", ErrKeyNotPresent, role, generation)
	}
	if err := cert.CheckCAKey(pub); err != nil {
		return nil, fmt.Errorf("keystore tpm: key for role %s generation %d: %w", role, generation, err)
	}
	cs, err := k.Signer(b.tpm, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: key for role %s generation %d: %w", role, generation, err)
	}
	if err := probe(lockedSigner{cs}, ec); err != nil {
		return nil, fmt.Errorf("keystore tpm: key for role %s generation %d (%s): %w", role, generation, authPath, err)
	}
	s, err := ssh.NewSignerFromSigner(lockedSigner{cs})
	if err != nil {
		return nil, fmt.Errorf("keystore tpm: key for role %s generation %d: %w", role, generation, err)
	}
	return &caKey{Signer: s, custody: b.custody}, nil
}

// GenerationHeld reports whether a file of generation of role is present
// in stateDir's TPM key directory (03-12f): the key file or the auth file,
// and any directory entry at either name counts (a regular file, a damaged
// file, a link, dangling or not, or a directory). Only the absence of both
// is not held; any other lstat error is held, with the error. It sends no
// TPM command, so doctor can ask it without opening the TPM.
func GenerationHeld(stateDir string, role keystore.Role, generation uint32) (bool, error) {
	return (&backend{dir: filepath.Join(stateDir, "tpm")}).held(role, generation)
}

// held is GenerationHeld for b's key directory: os.Lstat of the two names,
// so a link is never followed.
func (b *backend) held(role keystore.Role, generation uint32) (bool, error) {
	keyPath, authPath, err := b.keyPathsAt(role, generation)
	if err != nil {
		return true, err
	}
	for _, p := range []string{keyPath, authPath} {
		switch _, err := os.Lstat(p); {
		case err == nil:
			return true, nil
		case !errors.Is(err, fs.ErrNotExist):
			return true, fmt.Errorf("keystore tpm: %w", err)
		}
	}
	return false, nil
}

// Holds reports whether a file of generation of role is still present
// (GenerationHeld); it ignores the fingerprint and the location and sends
// no TPM command (03-12f).
func (b *backend) Holds(role keystore.Role, generation uint32, _, _ string) (bool, error) {
	return b.held(role, generation)
}

// RemoveGeneration removes the key file and the auth file of generation
// (at least 1) of role, the auth file first, and then fsyncs the key
// directory once (03-12f). The directory must be private. Both files
// absent is done. A regular key file is removed only after its public key
// (the public area in the file, read with no TPM command and no auth
// value) has the SHA-256 fingerprint fingerprint: another key refuses with
// keystore.ErrGenerationFileMismatch, a file that cannot be read as a TPM
// key with ErrKeyFileUnreadable, and neither removes anything, because the
// generation number alone never decides which key is destroyed. A link at
// the key name is unlinked without being followed, and anything else there
// (a directory) is removed with os.Remove, which fails on a non-empty
// directory; no key can be opened at such a name, and neither can one from
// a lone auth file, which is removed unchecked. One fsync does not order
// the two unlinks: a crash between them leaves a file that Holds reports
// as held, and a rerun converges. It ignores location.
func (b *backend) RemoveGeneration(role keystore.Role, generation uint32, fingerprint, _ string) error {
	keyPath, authPath, err := b.keyPathsAt(role, generation)
	if err != nil {
		return err
	}
	if err := checkPrivateDir(b.dir); err != nil {
		return err
	}
	keyInfo, err := os.Lstat(keyPath)
	keyThere := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("keystore tpm: %w", err)
	}
	_, err = os.Lstat(authPath)
	authThere := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("keystore tpm: %w", err)
	}
	if !keyThere && !authThere {
		return nil
	}
	if keyThere && keyInfo.Mode().IsRegular() {
		if err := checkKeyFile(keyPath, fingerprint); err != nil {
			return err
		}
	}
	if authThere {
		if err := os.Remove(authPath); err != nil {
			return fmt.Errorf("keystore tpm: remove %s: %w", authPath, err)
		}
	}
	if keyThere {
		if err := os.Remove(keyPath); err != nil {
			return fmt.Errorf("keystore tpm: remove %s: %w", keyPath, err)
		}
	}
	if err := syncDir(b.dir); err != nil {
		return fmt.Errorf("keystore tpm: sync %s: %w", b.dir, err)
	}
	return nil
}

// checkKeyFile requires the TSS2 key file at path to hold the key whose
// SHA-256 fingerprint is fingerprint (03-12f). The public area is in the
// file, so the check sends no TPM command and needs no auth value.
func checkKeyFile(path, fingerprint string) error {
	pem, err := readPrivateFile(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyFileUnreadable, err)
	}
	k, err := keyfile.Decode(pem)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrKeyFileUnreadable, path, err)
	}
	cpub, err := k.PublicKey()
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrKeyFileUnreadable, path, err)
	}
	pub, err := ssh.NewPublicKey(cpub)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrKeyFileUnreadable, path, err)
	}
	if got := ssh.FingerprintSHA256(pub); got != fingerprint {
		return fmt.Errorf("%w (%s)", keystore.ErrGenerationFileMismatch, got)
	}
	return nil
}

// probeDigest is what probe signs: a fixed SHA-256 digest, never a
// certificate or log entry.
var probeDigest = sha256.Sum256([]byte("keyroster tpm key probe"))

// probe signs probeDigest once with cs and verifies the signature with
// pub, so a wrong auth value (a corrupt or truncated {role}.auth) stops the
// signer at start instead of failing, and costing a TPM authorisation
// failure, on every signing request. An authorisation failure, and a TPM
// already in dictionary-attack lockout, wrap keystore.ErrCredentialRefused:
// keyroster-signer then exits with a status systemd does not restart on.
// Keys from Provision and ProvisionGeneration have noDA, so their failures
// do not count toward lockout; generation 1 keys created before noDA was
// set still do, and for them this limits the cost to one failure per
// manual start (KeyAt refuses a later generation's key without noDA).
func probe(cs crypto.Signer, pub *ecdsa.PublicKey) error {
	sig, err := cs.Sign(rand.Reader, probeDigest[:], crypto.SHA256)
	switch {
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth), errors.Is(err, tpm2.TPMRCLockout):
		return fmt.Errorf("the TPM refused the auth value (%w): %w", err, keystore.ErrCredentialRefused)
	case err != nil:
		return fmt.Errorf("test signature: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, probeDigest[:], sig) {
		return errors.New("test signature does not verify with the key file's public key")
	}
	return nil
}

// checkGeneratedInTPM requires the object attributes of a key created
// inside a TPM and never allowed to leave it: fixedTPM and fixedParent (it
// cannot be duplicated) and sensitiveDataOrigin (the TPM generated the
// private key). A key created in software and brought in with TPM2_Import
// is still a valid loadable key, but it must be duplicable to be imported,
// so it has these clear, and whoever created it may keep a copy. The TPM
// enforces the attributes when it loads the key: they are part of the
// public area, which the object's name binds to the private blob.
func checkGeneratedInTPM(pub *tpm2.TPMTPublic) error {
	a := pub.ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return fmt.Errorf("the key was not generated inside this TPM, or may leave it (fixedTPM=%v fixedParent=%v sensitiveDataOrigin=%v), so a copy may exist outside the TPM",
			a.FixedTPM, a.FixedParent, a.SensitiveDataOrigin)
	}
	return nil
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
