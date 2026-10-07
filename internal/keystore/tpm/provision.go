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
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
)

// authSize is the length of each key's random auth value: the digest size
// of the key's SHA-256 name algorithm, the most a TPM accepts.
const authSize = 32

// Provision creates one ECDSA P-256 key per role inside the TPM (D-09),
// each under the owner hierarchy's storage root key with its own random
// 32-byte auth value and with noDA set (keyTemplate), and writes {role}.tpmkey (TSS2 PEM) and {role}.auth,
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
		k, err := createKey(b.tpm, c.auth, "keyroster "+string(role)+" key")
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

// keyTemplate is go-tpm-keyfiles' ECC P-256 key template (createECCKey)
// with noDA added: the TPM does not count a failed authorisation of these
// keys against its dictionary-attack counter. Their auth value is 32
// random bytes, so dictionary-attack protection adds nothing, while a
// corrupt auth file would otherwise push the whole TPM into lockout and
// break other users of it (for example TPM+PIN disk unlocking). fixedTPM,
// fixedParent and sensitiveDataOrigin are what Key requires
// (checkGeneratedInTPM).
func keyTemplate() tpm2.TPM2BPublic {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			SignEncrypt:         true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			},
		),
	})
}

// createKey creates a keyTemplate key with auth value auth under the owner
// hierarchy's storage root key, the way keyfile.NewLoadableKey does (same
// parent, same salted session), and returns it as a loadable TSS2 key. The
// caller holds tpmMu.
func createKey(t transport.TPMCloser, auth []byte, desc string) (*keyfile.TPMKey, error) {
	sess := keyfile.NewTPMSession(t)
	parent, err := keyfile.GetParentHandle(sess, tpm2.TPMRHOwner, nil)
	if err != nil {
		return nil, err
	}
	defer sess.FlushHandle()
	rsp, err := tpm2.Create{
		ParentHandle: *parent,
		InPublic:     keyTemplate(),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth}},
		},
	}.Execute(t, sess.GetHMAC())
	if err != nil {
		return nil, err
	}
	return keyfile.NewTPMKey(keyfile.OIDLoadableKey, rsp.OutPublic, rsp.OutPrivate,
		keyfile.WithUserAuth(auth), keyfile.WithDescription(desc)), nil
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
