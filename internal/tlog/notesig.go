package tlog

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"
)

// Signed-note signature type bytes (C2SP signed-note).
const (
	SigTypeEd25519 byte = 0x01
	SigTypeECDSA   byte = 0x02
)

// ErrUnsupportedKey reports a log key whose algorithm has no note
// signature type here.
var ErrUnsupportedKey = errors.New("tlog: unsupported log key algorithm")

// NewNoteSigner adapts an SSH signer (for example a key in ssh-agent or a
// TPM) to a note.Signer named name. Every signature is verified with the
// public key before it is returned, so a faulty signer cannot produce a
// checkpoint that fails later.
func NewNoteSigner(name string, s ssh.Signer) (note.Signer, error) {
	if s == nil {
		return nil, errors.New("tlog: nil signer")
	}
	v, err := NewNoteVerifier(name, s.PublicKey())
	if err != nil {
		return nil, err
	}
	return &noteSigner{noteVerifier: v.(*noteVerifier), s: s}, nil
}

// NewNoteVerifier returns the note.Verifier for an SSH public key named
// name.
//
// Ed25519 (type 0x01): key ID = first 4 bytes, big-endian, of
// SHA-256(name || 0x0A || 0x01 || 32-byte public key); the signature is the
// raw 64-byte Ed25519 signature over the note text.
//
// ECDSA P-256 (type 0x02, as github.com/transparency-dev/witness defines it
// and C2SP signed-note references): key ID = first 4 bytes, big-endian, of
// SHA-256 of the DER-encoded SubjectPublicKeyInfo (the key name is not
// hashed); the signature is an ASN.1 DER ECDSA-Sig-Value over SHA-256 of
// the note text.
func NewNoteVerifier(name string, pub ssh.PublicKey) (note.Verifier, error) {
	if !validName(name) {
		return nil, fmt.Errorf("tlog: invalid note key name %q", name)
	}
	if pub == nil {
		return nil, errors.New("tlog: nil public key")
	}
	// Re-parse: agent keys do not expose their crypto key.
	parsed, err := ssh.ParsePublicKey(pub.Marshal())
	if err != nil {
		return nil, fmt.Errorf("tlog: log key: %w", err)
	}
	cpk, ok := parsed.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, parsed.Type())
	}
	switch parsed.Type() {
	case ssh.KeyAlgoED25519:
		edPub, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
		if !ok || len(edPub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: malformed Ed25519 key", ErrUnsupportedKey)
		}
		h := sha256.New()
		h.Write([]byte(name))
		h.Write([]byte{'\n', SigTypeEd25519})
		h.Write(edPub)
		return &noteVerifier{
			name:    name,
			hash:    binary.BigEndian.Uint32(h.Sum(nil)),
			sshType: ssh.KeyAlgoED25519,
			verify: func(msg, sig []byte) bool {
				return len(sig) == ed25519.SignatureSize && ed25519.Verify(edPub, msg, sig)
			},
		}, nil
	case ssh.KeyAlgoECDSA256:
		ecPub, ok := cpk.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: malformed P-256 key", ErrUnsupportedKey)
		}
		der, err := x509.MarshalPKIXPublicKey(ecPub)
		if err != nil {
			return nil, fmt.Errorf("tlog: log key: %w", err)
		}
		sum := sha256.Sum256(der)
		return &noteVerifier{
			name:    name,
			hash:    binary.BigEndian.Uint32(sum[:4]),
			sshType: ssh.KeyAlgoECDSA256,
			verify: func(msg, sig []byte) bool {
				digest := sha256.Sum256(msg)
				return ecdsa.VerifyASN1(ecPub, digest[:], sig)
			},
			fromSSH: ecdsaBlobToDER,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, parsed.Type())
	}
}

// ecdsaBlobToDER converts an SSH ECDSA signature blob (mpint r, mpint s,
// RFC 5656 section 3.1.2) to the ASN.1 DER ECDSA-Sig-Value that C2SP type
// 0x02 signatures carry.
func ecdsaBlobToDER(blob []byte) ([]byte, error) {
	var sig struct {
		R *big.Int
		S *big.Int
	}
	if err := ssh.Unmarshal(blob, &sig); err != nil {
		return nil, fmt.Errorf("tlog: ECDSA signature blob: %w", err)
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("tlog: ECDSA signature with a non-positive r or s")
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(sig.R)
		b.AddASN1BigInt(sig.S)
	})
	return b.Bytes()
}

type noteVerifier struct {
	name    string
	hash    uint32
	sshType string
	verify  func(msg, sig []byte) bool
	// fromSSH converts an SSH signature blob to the note signature bytes.
	fromSSH func(blob []byte) ([]byte, error)
}

func (v *noteVerifier) Name() string                { return v.name }
func (v *noteVerifier) KeyHash() uint32             { return v.hash }
func (v *noteVerifier) Verify(msg, sig []byte) bool { return v.verify(msg, sig) }

type noteSigner struct {
	*noteVerifier
	s ssh.Signer
}

func (n *noteSigner) Sign(msg []byte) ([]byte, error) {
	sig, err := n.s.Sign(rand.Reader, msg)
	if err != nil {
		return nil, fmt.Errorf("tlog: sign checkpoint: %w", err)
	}
	if sig == nil || sig.Format != n.sshType {
		return nil, fmt.Errorf("tlog: log key returned a signature of another format")
	}
	raw := sig.Blob
	if n.fromSSH != nil {
		if raw, err = n.fromSSH(sig.Blob); err != nil {
			return nil, err
		}
	}
	if !n.verify(msg, raw) {
		return nil, errors.New("tlog: log key produced a signature that does not verify")
	}
	return raw, nil
}

// validName mirrors the signed-note key name rule: non-empty UTF-8 without
// Unicode spaces or '+'.
func validName(name string) bool {
	return name != "" && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}
