//go:build linux

// Package software is the encrypted software keystore backend, registered
// as "software" (KEY-06). It holds the five online keys (user, host and
// machine CA, ops and log key) as Ed25519 keys in armored age files, one
// per role, each encrypted to one scrypt recipient at age's default work
// factor: {state-dir}/software/{role}.age, mode 0600 in a 0700 directory.
//
// This custody is for evaluation only. Whoever can read the key files and
// the passphrase can issue certificates, and the decrypted keys sit in the
// signer's memory while it runs: a compromised signer host can copy them.
// The signer reports custody software over its Status message, and the
// CLI and the server print an evaluation-only warning from it
// (docs/security/custody.md).
//
// The passphrase comes only from a file: the passphrase-file option, or
// else $CREDENTIALS_DIRECTORY/keyroster-software-passphrase (systemd
// LoadCredential= or LoadCredentialEncrypted=). It never comes from argv or
// the environment, is never logged, and is read again for every Provision
// and Key call; the backend keeps no copy of it.
//
// Options:
//
//	state-dir        the signer's state directory (set by keyroster-signer)
//	passphrase-file  absolute path of the file holding the passphrase (no
//	                 group or other permissions; one trailing newline is
//	                 ignored)
package software

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
)

// Errors of the software backend.
var (
	// ErrKeyNotPresent means the key file for a role holds another key
	// than the pinned one. The backend never falls back to another key.
	ErrKeyNotPresent = errors.New("keystore software: pinned CA key not present in the software key files")
	// ErrKeyFilesExist means Provision found key files from an earlier
	// run; it overwrites nothing.
	ErrKeyFilesExist = errors.New("keystore software: software key files already exist")
)

const (
	// optPassphraseFile names the passphrase file.
	optPassphraseFile = "passphrase-file"
	// credentialName is the systemd credential that holds the passphrase.
	credentialName = "keyroster-software-passphrase"
	// minPassphraseRunes is the shortest passphrase accepted (as for
	// software roots, STATE.md 01-09). It is a length floor, not a
	// strength check (docs/security/custody.md).
	minPassphraseRunes = 20
	// maxPassphraseFile bounds the passphrase file read.
	maxPassphraseFile = 4 << 10
	// maxKeyFile bounds an encrypted key file and maxKeyPlaintext its
	// decrypted contents: an OpenSSH Ed25519 private key in PEM form is
	// about 400 bytes.
	maxKeyFile      = 16 << 10
	maxKeyPlaintext = 16 << 10
	// keyComment is the comment stored inside each encrypted key.
	keyComment = "keyroster software CA key"
)

// scryptWorkFactor is the scrypt work factor (log2 N) Provision encrypts
// with; 0 means age's default (18). Only tests lower it, to keep
// provisioning fast; TestScryptWorkFactorIsAgeDefault pins the production
// value. Decryption accepts the work factor a file records, up to age's
// maximum.
var scryptWorkFactor = 0

func init() { keystore.Register("software", open) }

type backend struct {
	dir      string // {state-dir}/software
	passFile string // the passphrase-file option, "" for none

	mu    sync.Mutex
	privs []ed25519.PrivateKey // keys handed out by Key; zeroed by Close
}

func open(opts map[string]string) (keystore.Backend, error) {
	if err := keystore.CheckOptions(opts, optPassphraseFile); err != nil {
		return nil, err
	}
	stateDir := opts[keystore.OptStateDir]
	if stateDir == "" || !filepath.IsAbs(stateDir) {
		return nil, errors.New("keystore software: needs the signer's absolute state directory (option state-dir, set by keyroster-signer)")
	}
	passFile, set := opts[optPassphraseFile]
	if set && passFile == "" {
		return nil, errors.New("keystore software: option passphrase-file is empty")
	}
	// ca-init stores the option as given, and serve runs from another
	// working directory: only an absolute path names the same file.
	if set && !filepath.IsAbs(passFile) {
		return nil, errors.New("keystore software: option passphrase-file must be an absolute path")
	}
	b := &backend{dir: filepath.Join(stateDir, "software"), passFile: passFile}
	// Fail at open, not at the first key, when no passphrase is reachable.
	pass, err := b.readPassphrase()
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	return b, nil
}

// Describe says what this custody is.
func (b *backend) Describe() string {
	return "software keys: age-encrypted files in " + b.dir + " (custody software, evaluation only; docs/security/custody.md)"
}

// readPassphrase reads the passphrase from the passphrase-file option or,
// without it, from $CREDENTIALS_DIRECTORY/keyroster-software-passphrase.
// An operator's passphrase file must be a regular file without group or
// other permissions, the credential a regular file without other
// permissions. Exactly one trailing newline is removed, and the
// passphrase must be valid UTF-8 of at least 20 characters. Every caller
// clears the returned buffer (defer clear) right after a successful read;
// on an error nothing is returned and the buffer read so far is cleared.
// No error message carries the passphrase.
func (b *backend) readPassphrase() ([]byte, error) {
	path, operator := b.passFile, b.passFile != ""
	if !operator {
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return nil, fmt.Errorf("keystore software: no passphrase: set --backend-opt %s=FILE, or run under systemd with LoadCredential=%s (CREDENTIALS_DIRECTORY)", optPassphraseFile, credentialName)
		}
		if !filepath.IsAbs(dir) {
			return nil, errors.New("keystore software: CREDENTIALS_DIRECTORY is not an absolute path")
		}
		path = filepath.Join(dir, credentialName)
	}
	// O_NONBLOCK: opening a FIFO without a writer must not block before
	// the regular-file check below refuses it. It has no effect on reads
	// of a regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the operator's passphrase file or the systemd credential
	if err != nil {
		return nil, fmt.Errorf("keystore software: passphrase: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("keystore software: passphrase: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keystore software: passphrase file %s is not a regular file", path)
	}
	if operator && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keystore software: passphrase file %s has mode %04o, want no group or other permissions (0600 or 0400)", path, fi.Mode().Perm())
	}
	// systemd creates a credential 0400, or 0440 when it grants access
	// through an ACL (shown as group bits), never with other bits (not
	// run under a real systemd unit here, UNVERIFIED). Other bits mean a
	// CREDENTIALS_DIRECTORY set by hand to a file anyone can read.
	if !operator && fi.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("keystore software: credential %s has mode %04o, want no other permissions", path, fi.Mode().Perm())
	}
	pass, err := io.ReadAll(io.LimitReader(f, maxPassphraseFile+1))
	if err != nil {
		clear(pass)
		return nil, fmt.Errorf("keystore software: read passphrase file %s: %w", path, err)
	}
	if len(pass) > maxPassphraseFile {
		clear(pass)
		return nil, fmt.Errorf("keystore software: passphrase file %s is larger than %d bytes", path, maxPassphraseFile)
	}
	n := len(pass)
	if n > 0 && pass[n-1] == '\n' {
		pass[n-1] = 0
		pass = pass[:n-1]
	}
	if !utf8.Valid(pass) {
		clear(pass)
		return nil, fmt.Errorf("keystore software: the passphrase in %s is not valid UTF-8", path)
	}
	if r := utf8.RuneCount(pass); r < minPassphraseRunes {
		clear(pass)
		return nil, fmt.Errorf("keystore software: the passphrase in %s has %d characters; it needs at least %d (use a random one, docs/security/custody.md)", path, r, minPassphraseRunes)
	}
	return pass, nil
}

// keyPath returns the key file of role. Only the five known roles have
// files, so a role can never name a path outside the directory.
func (b *backend) keyPath(role keystore.Role) (string, error) {
	switch role {
	case keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog:
	default:
		return "", fmt.Errorf("keystore software: unknown role %q", role)
	}
	return filepath.Join(b.dir, string(role)+".age"), nil
}

// Provision creates one Ed25519 key per role and writes each, as an
// armored age file encrypted to the passphrase (one scrypt recipient at
// age's default work factor), to {state-dir}/software/{role}.age, mode
// 0600, in the 0700 directory {state-dir}/software, then fsyncs that
// directory (and the state directory when it created the key directory).
// It refuses, and writes nothing, when the directory is not private or is
// a symlink, already holds any .age file, or a role is given twice. It
// writes all files or none.
func (b *backend) Provision(roles []keystore.Role) (map[keystore.Role]ssh.PublicKey, error) {
	if len(roles) == 0 {
		return nil, errors.New("keystore software: no roles to provision")
	}
	pass, err := b.readPassphrase()
	if err != nil {
		return nil, err
	}
	defer clear(pass)

	createdDir := true
	if err := os.Mkdir(b.dir, 0o700); errors.Is(err, fs.ErrExist) {
		createdDir = false
	} else if err != nil {
		return nil, fmt.Errorf("keystore software: %w", err)
	}
	if err := checkPrivateDir(b.dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, fmt.Errorf("keystore software: %w", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".age") {
			return nil, fmt.Errorf("%w: %s (remove %s only if no trust bundle uses these keys)", ErrKeyFilesExist, filepath.Join(b.dir, e.Name()), b.dir)
		}
	}
	paths := make(map[keystore.Role]string, len(roles))
	for _, role := range roles {
		if _, dup := paths[role]; dup {
			return nil, fmt.Errorf("keystore software: role %s given twice", role)
		}
		p, err := b.keyPath(role)
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(p); err == nil {
			return nil, fmt.Errorf("%w: %s (remove %s only if no trust bundle uses these keys)", ErrKeyFilesExist, p, b.dir)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("keystore software: %w", err)
		}
		paths[role] = p
	}

	files := make(map[keystore.Role][]byte, len(roles))
	pubs := make(map[keystore.Role]ssh.PublicKey, len(roles))
	for _, role := range roles {
		enc, pub, err := newEncryptedKey(pass)
		if err != nil {
			return nil, fmt.Errorf("keystore software: create the %s key: %w", role, err)
		}
		files[role], pubs[role] = enc, pub
	}

	// The keys exist only in memory so far: write all files, or none.
	var written []string
	removeWritten := func() {
		for _, p := range written {
			_ = os.Remove(p)
		}
	}
	for _, role := range roles {
		if err := writeNew(paths[role], files[role]); err != nil {
			removeWritten()
			return nil, err
		}
		written = append(written, paths[role])
	}
	// The files are the only copy of these keys, and the caller (ca-init)
	// commits their fingerprints next: make the new directory entries
	// durable first. When this run created the key directory, its own
	// entry in the state directory needs the same.
	dirs := []string{b.dir}
	if createdDir {
		dirs = append(dirs, filepath.Dir(b.dir))
	}
	for _, d := range dirs {
		if err := syncDir(d); err != nil {
			removeWritten()
			return nil, fmt.Errorf("keystore software: sync %s: %w", d, err)
		}
	}
	return pubs, nil
}

// newEncryptedKey generates an Ed25519 key with crypto/rand and returns it
// as an OpenSSH private key in an armored age file encrypted to pass, and
// its public key. The plaintext is zeroed before it returns (best effort:
// age derives its key from a string copy of pass, which cannot be
// zeroed).
func newEncryptedKey(pass []byte) ([]byte, ssh.PublicKey, error) {
	edPub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	defer clear(priv)
	block, err := ssh.MarshalPrivateKey(priv, keyComment)
	if err != nil {
		return nil, nil, err
	}
	plain := pem.EncodeToMemory(block)
	clear(block.Bytes)
	defer clear(plain)

	recipient, err := age.NewScryptRecipient(string(pass))
	if err != nil {
		return nil, nil, err
	}
	if scryptWorkFactor != 0 {
		recipient.SetWorkFactor(scryptWorkFactor)
	}
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, nil, err
	}
	if err := w.Close(); err != nil {
		return nil, nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, nil, err
	}
	pub, err := ssh.NewPublicKey(edPub)
	if err != nil {
		return nil, nil, err
	}
	return out.Bytes(), pub, nil
}

// Key decrypts the key file of role with the passphrase, requires an
// Ed25519 key whose SHA-256 fingerprint is fingerprint, and returns it as a
// CAKey with custody software. The key file must be a private regular
// file in a private directory. A wrong passphrase, an edited or truncated
// file and another key are refused; no error carries the passphrase.
func (b *backend) Key(role keystore.Role, fingerprint string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore software: no pinned fingerprint for role %s", role)
	}
	path, err := b.keyPath(role)
	if err != nil {
		return nil, err
	}
	if err := checkPrivateDir(b.dir); err != nil {
		return nil, err
	}
	enc, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	pass, err := b.readPassphrase()
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	priv, err := decryptKey(enc, pass)
	if err != nil {
		return nil, fmt.Errorf("keystore software: %s: %w", path, err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		clear(priv)
		return nil, fmt.Errorf("keystore software: %s: %w", path, err)
	}
	pub := signer.PublicKey()
	if ssh.FingerprintSHA256(pub) != fingerprint {
		clear(priv)
		return nil, fmt.Errorf("%w (role %s, %s)", ErrKeyNotPresent, role, path)
	}
	if err := cert.CheckCAKey(pub); err != nil {
		clear(priv)
		return nil, fmt.Errorf("keystore software: key for role %s: %w", role, err)
	}
	b.mu.Lock()
	b.privs = append(b.privs, priv)
	b.mu.Unlock()
	return &caKey{Signer: signer}, nil
}

// decryptKey decrypts an armored age file with one scrypt recipient and
// returns the Ed25519 private key inside it. The plaintext is zeroed
// before it returns (best effort, as in newEncryptedKey).
func decryptKey(enc, pass []byte) (ed25519.PrivateKey, error) {
	identity, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(enc)), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt (wrong passphrase, or not a keyroster software key file): %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxKeyPlaintext+1))
	defer clear(plain)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	if len(plain) > maxKeyPlaintext {
		return nil, errors.New("decrypted key file is too large")
	}
	raw, err := ssh.ParseRawPrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		priv = *k
	case ed25519.PrivateKey:
		priv = k
	default:
		return nil, fmt.Errorf("refusing a %T key: software CA keys are Ed25519 only", raw)
	}
	if len(priv) != ed25519.PrivateKeySize {
		clear(priv)
		return nil, errors.New("malformed Ed25519 key")
	}
	return priv, nil
}

// Close zeroes the private keys Key handed out (best effort: the ssh
// signers built from them hold the same slices, so they stop working).
func (b *backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.privs {
		clear(p)
	}
	b.privs = nil
	return nil
}

// caKey is a software-held CA key.
type caKey struct{ ssh.Signer }

func (k *caKey) Custody() keystore.Custody { return keystore.CustodySoftware }

func (k *caKey) Algorithm() string { return ssh.KeyAlgoED25519 }

// checkPrivateDir requires dir to be a directory, not a symlink, with no
// group or other permissions (copied from package tpm, not imported).
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("keystore software: key directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("keystore software: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("keystore software: %s has mode %04o, want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// readPrivateFile reads a regular file that has no group or other
// permissions (copied from package tpm, not imported).
func readPrivateFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("keystore software: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keystore software: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keystore software: %s has mode %04o, want 0600", path, fi.Mode().Perm())
	}
	if fi.Size() > maxKeyFile {
		return nil, fmt.Errorf("keystore software: %s is larger than %d bytes", path, maxKeyFile)
	}
	return os.ReadFile(path) //nolint:gosec // G304: a fixed name inside the signer's own state directory
}

// writeNew creates path with mode 0600, failing if it exists, and syncs it
// (copied from package tpm, not imported).
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed name inside the signer's own state directory
	if err != nil {
		return fmt.Errorf("keystore software: %w", err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("keystore software: write %s: %w", path, err)
	}
	return nil
}

// syncDir fsyncs a directory. Tests replace it to see which directories
// Provision syncs and to inject a failure.
var syncDir = func(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the signer's own state and key directories
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
