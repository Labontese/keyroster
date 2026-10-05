package rootceremony

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
)

// rootKeyComment is the comment stored inside an encrypted root key.
const rootKeyComment = "keyroster root"

// maxRootPlaintext bounds the decrypted key file. An OpenSSH Ed25519
// private key in PEM form is about 400 bytes.
const maxRootPlaintext = 16 << 10

// errRootClosed reports use of a Root after Close.
var errRootClosed = errors.New("rootceremony: the root key is closed")

// GenerateRoot creates a software root key (D-10): a fresh Ed25519 key in
// OpenSSH private-key format, encrypted to passphrase with age's scrypt
// recipient at age's default work factor and armored. It returns the
// encrypted file and the public key. The plaintext key is zeroed before
// GenerateRoot returns (best effort: the passphrase string age derives
// its key from cannot be zeroed).
func GenerateRoot(rnd io.Reader, passphrase []byte) (encrypted []byte, pub ssh.PublicKey, err error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, nil, err
	}
	edPub, priv, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("rootceremony: generate root key: %w", err)
	}
	defer clear(priv)
	block, err := ssh.MarshalPrivateKey(priv, rootKeyComment)
	if err != nil {
		return nil, nil, fmt.Errorf("rootceremony: marshal root key: %w", err)
	}
	plain := pem.EncodeToMemory(block)
	clear(block.Bytes)
	defer clear(plain)

	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, nil, fmt.Errorf("rootceremony: %w", err)
	}
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return nil, nil, fmt.Errorf("rootceremony: encrypt root key: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return nil, nil, fmt.Errorf("rootceremony: encrypt root key: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, nil, fmt.Errorf("rootceremony: encrypt root key: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, nil, fmt.Errorf("rootceremony: armor root key: %w", err)
	}
	pub, err = ssh.NewPublicKey(edPub)
	if err != nil {
		return nil, nil, fmt.Errorf("rootceremony: %w", err)
	}
	return out.Bytes(), pub, nil
}

// Root is a software root key decrypted into memory. It signs only trust
// bundles and policies (SignBundle, SignPolicy); it never hands out its
// signer or private key (KEY-07). Close zeroes the key.
type Root struct {
	priv   ed25519.PrivateKey
	signer ssh.Signer
	pub    ssh.PublicKey
}

// OpenRoot decrypts a root key file written by GenerateRoot with
// passphrase and returns the root. It refuses a wrong passphrase, a file
// that is not armored age with a single scrypt recipient, and any key that
// is not Ed25519.
func OpenRoot(encrypted, passphrase []byte) (*Root, error) {
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("rootceremony: %w", err)
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(encrypted)), identity)
	if err != nil {
		return nil, fmt.Errorf("rootceremony: decrypt root key (wrong passphrase or not a root key file): %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxRootPlaintext+1))
	defer clear(plain)
	if err != nil {
		return nil, fmt.Errorf("rootceremony: decrypt root key: %w", err)
	}
	if len(plain) > maxRootPlaintext {
		return nil, errors.New("rootceremony: decrypted root key file is too large")
	}
	raw, err := ssh.ParseRawPrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("rootceremony: parse root key: %w", err)
	}
	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		priv = *k
	case ed25519.PrivateKey:
		priv = k
	default:
		return nil, fmt.Errorf("rootceremony: refusing a %T root key: software roots are Ed25519 only", raw)
	}
	if len(priv) != ed25519.PrivateKeySize {
		clear(priv)
		return nil, errors.New("rootceremony: malformed Ed25519 root key")
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		clear(priv)
		return nil, fmt.Errorf("rootceremony: %w", err)
	}
	return &Root{priv: priv, signer: signer, pub: signer.PublicKey()}, nil
}

// PublicKey returns the root's public key.
func (r *Root) PublicKey() ssh.PublicKey {
	return r.pub
}

// SignBundle signs a canonical trust bundle with the root (see the
// package-level SignBundle).
func (r *Root) SignBundle(rnd io.Reader, bundleJSON []byte) ([]byte, error) {
	if r.signer == nil {
		return nil, errRootClosed
	}
	return SignBundle(rnd, r.signer, bundleJSON)
}

// SignPolicy signs a canonical policy with the root (see the package-level
// SignPolicy).
func (r *Root) SignPolicy(rnd io.Reader, policyJSON []byte) ([]byte, error) {
	if r.signer == nil {
		return nil, errRootClosed
	}
	return SignPolicy(rnd, r.signer, policyJSON)
}

// Close zeroes the private key and drops the signer; the root cannot sign
// afterwards. The signer shares the key's memory, so zeroing priv also
// clears the signer's copy.
func (r *Root) Close() {
	clear(r.priv)
	r.priv = nil
	r.signer = nil
}
