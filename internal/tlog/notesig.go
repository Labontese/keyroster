package tlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

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
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, parsed.Type())
	}
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
