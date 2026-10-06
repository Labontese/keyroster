//go:build linux

package tpm

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
)

// authSize is the length of each key's random auth value: the digest size
// of the key's SHA-256 name algorithm, the most a TPM accepts.
const authSize = 32

// Provision creates one ECDSA P-256 key per role inside the TPM (D-09),
// each under the owner hierarchy's storage root key with its own random
// 32-byte auth value, and writes {role}.tpmkey (TSS2 PEM) and {role}.auth,
// mode 0600, into the 0700 directory {state-dir}/tpm. It refuses, and
// writes nothing, when any key or auth file of the requested roles already
// exists. The custody of the new keys is the backend's (from the TPM
// manufacturer, see CustodyForManufacturer).
func (b *backend) Provision(roles []keystore.Role) (map[keystore.Role]ssh.PublicKey, error) {
	if len(roles) == 0 {
		return nil, errors.New("keystore tpm: no roles to provision")
	}
	if err := os.Mkdir(b.dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("keystore tpm: %w", err)
	}
	if err := checkPrivateDir(b.dir); err != nil {
		return nil, err
	}
	type created struct {
		keyPath, authPath string
		pem, auth         []byte
	}
	todo := make(map[keystore.Role]*created, len(roles))
	for _, role := range roles {
		if _, dup := todo[role]; dup {
			return nil, fmt.Errorf("keystore tpm: role %s given twice", role)
		}
		keyPath, authPath, err := b.keyPaths(role)
		if err != nil {
			return nil, err
		}
		for _, p := range []string{keyPath, authPath} {
			if _, err := os.Lstat(p); err == nil {
				return nil, fmt.Errorf("%w: %s (remove %s only if no trust bundle uses these keys)", ErrKeyFilesExist, p, b.dir)
			} else if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("keystore tpm: %w", err)
			}
		}
		todo[role] = &created{keyPath: keyPath, authPath: authPath}
	}

	pubs := make(map[keystore.Role]ssh.PublicKey, len(roles))
	for _, role := range roles {
		c := todo[role]
		c.auth = make([]byte, authSize)
		if _, err := rand.Read(c.auth); err != nil {
			return nil, err
		}
		tpmMu.Lock()
		k, err := keyfile.NewLoadableKey(b.tpm, tpm2.TPMAlgECC, 256, nil,
			keyfile.WithUserAuth(c.auth), keyfile.WithDescription("keyroster "+string(role)+" key"))
		tpmMu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("keystore tpm: create the %s key: %w", role, err)
		}
		cpub, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		ec, ok := cpub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("keystore tpm: the TPM created a %T for role %s", cpub, role)
		}
		pub, err := ssh.NewPublicKey(ec)
		if err != nil {
			return nil, err
		}
		if pub.Type() != ssh.KeyAlgoECDSA256 {
			return nil, fmt.Errorf("keystore tpm: the TPM created a %s key for role %s, want %s", pub.Type(), role, ssh.KeyAlgoECDSA256)
		}
		c.pem = k.Bytes()
		if len(c.pem) == 0 {
			return nil, fmt.Errorf("keystore tpm: encode the %s key file", role)
		}
		pubs[role] = pub
	}

	// The keys exist only as TPM-wrapped blobs so far: write all files, or none.
	var written []string
	for _, role := range roles {
		c := todo[role]
		for _, f := range []struct {
			path string
			data []byte
		}{{c.keyPath, c.pem}, {c.authPath, c.auth}} {
			if err := writeNew(f.path, f.data); err != nil {
				for _, p := range written {
					_ = os.Remove(p)
				}
				return nil, err
			}
			written = append(written, f.path)
		}
	}
	return pubs, nil
}

// writeNew creates path with mode 0600, failing if it exists, and syncs it.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed name inside the signer's own state directory
	if err != nil {
		return fmt.Errorf("keystore tpm: %w", err)
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
		return fmt.Errorf("keystore tpm: write %s: %w", path, err)
	}
	return nil
}
