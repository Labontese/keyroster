// Package sshsig signs and verifies detached OpenSSH signatures in the
// SSHSIG format (openssh-portable PROTOCOL.sshsig), the format of
// `ssh-keygen -Y sign` and `ssh-keygen -Y verify`.
//
// keyroster uses SSHSIG for every signature by a root or admin key: the
// trust bundle, the policy and (later) admin request authorizations. Each
// use has its own namespace, and the signed data starts with the raw bytes
// "SSHSIG", so a signature made for one purpose cannot be replayed as
// another, nor confused with a certificate's to-be-signed bytes (which
// start with a uint32 length).
//
// Only sha512 is emitted and accepted as the message hash. RSA keys and
// certificate keys are refused as signers: keyroster's root and admin keys
// are Ed25519 or ECDSA, optionally security-key (sk-*) backed (D-09, D-11).
package sshsig

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

const (
	magic         = "SSHSIG"
	sigVersion    = 1
	hashAlgorithm = "sha512"
	armorBegin    = "-----BEGIN SSH SIGNATURE-----"
	armorEnd      = "-----END SSH SIGNATURE-----"
	// lineLen is the base64 line length ssh-keygen writes (SSHSIG_LINE_LEN).
	lineLen = 70
	// skUserPresent is the FIDO user-presence flag of an sk-* signature.
	skUserPresent = 0x01
	// maxBlob bounds one decoded signature blob; real ones are < 300 bytes.
	maxBlob = 8 << 10
)

// signatureFormats maps each accepted key type to the one signature format
// it may carry.
var signatureFormats = map[string]string{
	ssh.KeyAlgoED25519:    ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256:   ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384:   ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521:   ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKED25519:  ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoSKECDSA256: ssh.KeyAlgoSKECDSA256,
}

var (
	// ErrMalformed reports an armored block or blob that is not a
	// well-formed SSHSIG signature.
	ErrMalformed = errors.New("sshsig: malformed signature")
	// ErrNamespace reports an empty namespace or one that differs from the
	// namespace the caller verifies under.
	ErrNamespace = errors.New("sshsig: namespace mismatch")
	// ErrHashAlgorithm reports a hash algorithm other than sha512.
	ErrHashAlgorithm = errors.New("sshsig: unsupported hash algorithm")
	// ErrKeyType reports a signer key keyroster does not accept (RSA,
	// certificates, unknown types).
	ErrKeyType = errors.New("sshsig: unsupported signer key type")
	// ErrUserPresence reports an sk-* signature without the user-presence
	// flag.
	ErrUserPresence = errors.New("sshsig: security-key signature without user presence")
)

// Signature is one parsed SSHSIG signature.
type Signature struct {
	pub       ssh.PublicKey
	namespace string
	hashAlg   string
	sig       *ssh.Signature
	blob      []byte
}

// PublicKey returns the key that made the signature. It is untrusted until
// the caller matches it against a pinned key.
func (s *Signature) PublicKey() ssh.PublicKey { return s.pub }

// Verify checks that s is a valid signature over msg under namespace, which
// must be non-empty and equal to the signed namespace. It does not decide
// whether the signer is trusted.
func (s *Signature) Verify(namespace string, msg []byte) error {
	if namespace == "" || s.namespace != namespace {
		return fmt.Errorf("%w: signed under %q, want %q", ErrNamespace, s.namespace, namespace)
	}
	if s.hashAlg != hashAlgorithm {
		return fmt.Errorf("%w: %q", ErrHashAlgorithm, s.hashAlg)
	}
	if err := checkFormat(s.pub, s.sig); err != nil {
		return err
	}
	if err := s.pub.Verify(signedData(namespace, msg), s.sig); err != nil {
		return fmt.Errorf("sshsig: invalid signature: %w", err)
	}
	return nil
}

// Sign makes a detached SSHSIG signature over msg under namespace with s and
// returns it as one armored block (ssh-keygen's 70-column base64), ending
// in a newline. The signature is verified before it is returned, so a
// misbehaving agent or token cannot produce an unusable signature file.
func Sign(rnd io.Reader, s ssh.Signer, namespace string, msg []byte) ([]byte, error) {
	if namespace == "" {
		return nil, fmt.Errorf("%w: empty namespace", ErrNamespace)
	}
	pub := s.PublicKey()
	if err := checkKeyType(pub); err != nil {
		return nil, err
	}
	data := signedData(namespace, msg)
	sig, err := s.Sign(rnd, data)
	if err != nil {
		return nil, fmt.Errorf("sshsig: sign: %w", err)
	}
	if err := checkFormat(pub, sig); err != nil {
		return nil, err
	}
	if err := pub.Verify(data, sig); err != nil {
		return nil, fmt.Errorf("sshsig: the signer returned an invalid signature: %w", err)
	}
	blob := marshalBlob(pub, namespace, hashAlgorithm, sig)
	return armor(blob), nil
}

// Parse parses exactly one armored SSHSIG block, optionally followed by one
// newline.
func Parse(armored []byte) (*Signature, error) {
	sig, rest, err := parseBlock(armored)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: data after the signature block", ErrMalformed)
	}
	return sig, nil
}

// ParseAll parses one or more concatenated armored blocks, separated by the
// newline that ends each block (the format of a .sigs file that signers
// append to). Any data that is not a well-formed block makes the whole input
// invalid: a verifier never guesses which part of a damaged file to trust.
func ParseAll(data []byte) ([]*Signature, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: no signature blocks", ErrMalformed)
	}
	var sigs []*Signature
	for len(data) > 0 {
		// parseBlock refuses anything but a newline right after the end
		// line, so blocks are always newline-separated.
		sig, rest, err := parseBlock(data)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", len(sigs)+1, err)
		}
		sigs = append(sigs, sig)
		data = rest
	}
	return sigs, nil
}

// signedData is the message the key signs (PROTOCOL.sshsig): the magic
// preamble, then namespace, reserved, hash algorithm and H(msg) as SSH
// strings.
func signedData(namespace string, msg []byte) []byte {
	h := sha512.Sum512(msg)
	var b cryptobyte.Builder
	b.AddBytes([]byte(magic))
	for _, f := range [][]byte{[]byte(namespace), nil, []byte(hashAlgorithm), h[:]} {
		b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(f) })
	}
	return b.BytesOrPanic()
}

func marshalBlob(pub ssh.PublicKey, namespace, hashAlg string, sig *ssh.Signature) []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(magic))
	b.AddUint32(sigVersion)
	for _, f := range [][]byte{pub.Marshal(), []byte(namespace), nil, []byte(hashAlg), ssh.Marshal(sig)} {
		b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(f) })
	}
	return b.BytesOrPanic()
}

// armor encodes blob the way ssh-keygen does.
func armor(blob []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(armorBegin + "\n")
	for len(enc) > lineLen {
		b.WriteString(enc[:lineLen] + "\n")
		enc = enc[lineLen:]
	}
	b.WriteString(enc + "\n")
	b.WriteString(armorEnd + "\n")
	return []byte(b.String())
}

// parseBlock parses the armored block at the start of data and returns the
// remainder after the end line and its newline, if any.
func parseBlock(data []byte) (*Signature, []byte, error) {
	begin := []byte(armorBegin + "\n")
	if !bytes.HasPrefix(data, begin) {
		return nil, nil, fmt.Errorf("%w: missing %s line", ErrMalformed, armorBegin)
	}
	body := data[len(begin):]
	end := bytes.Index(body, []byte(armorEnd))
	if end < 0 {
		return nil, nil, fmt.Errorf("%w: missing %s line", ErrMalformed, armorEnd)
	}
	rest := body[end+len(armorEnd):]
	body = body[:end]
	if len(rest) > 0 {
		if rest[0] != '\n' {
			return nil, nil, fmt.Errorf("%w: data after %s on the same line", ErrMalformed, armorEnd)
		}
		rest = rest[1:]
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return nil, nil, fmt.Errorf("%w: empty body or %s not on its own line", ErrMalformed, armorEnd)
	}
	var enc []byte
	for _, line := range bytes.Split(body[:len(body)-1], []byte("\n")) {
		if len(line) == 0 || len(line) > lineLen {
			return nil, nil, fmt.Errorf("%w: base64 line of length %d", ErrMalformed, len(line))
		}
		enc = append(enc, line...)
	}
	if base64.StdEncoding.DecodedLen(len(enc)) > maxBlob {
		return nil, nil, fmt.Errorf("%w: signature blob too large", ErrMalformed)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(string(enc))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: base64: %w", ErrMalformed, err)
	}
	sig, err := parseBlob(blob)
	if err != nil {
		return nil, nil, err
	}
	return sig, rest, nil
}

func parseBlob(blob []byte) (*Signature, error) {
	s := cryptobyte.String(blob)
	var (
		m                                     []byte
		version                               uint32
		pubBytes, ns, reserved, alg, sigBytes []byte
	)
	if !s.ReadBytes(&m, len(magic)) || string(m) != magic {
		return nil, fmt.Errorf("%w: bad magic", ErrMalformed)
	}
	if !s.ReadUint32(&version) || version != sigVersion {
		return nil, fmt.Errorf("%w: unsupported version", ErrMalformed)
	}
	if !readString(&s, &pubBytes) || !readString(&s, &ns) ||
		!readString(&s, &reserved) || !readString(&s, &alg) ||
		!readString(&s, &sigBytes) || !s.Empty() {
		return nil, fmt.Errorf("%w: truncated or trailing fields", ErrMalformed)
	}
	// The reserved field is part of the signed data; keyroster signs it
	// empty, so anything else could not verify. Refusing it here keeps one
	// blob per signature.
	if len(reserved) != 0 {
		return nil, fmt.Errorf("%w: non-empty reserved field", ErrMalformed)
	}
	if len(ns) == 0 {
		return nil, fmt.Errorf("%w: empty namespace", ErrNamespace)
	}
	pub, err := ssh.ParsePublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: public key: %w", ErrMalformed, err)
	}
	if err := checkKeyType(pub); err != nil {
		return nil, err
	}
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(sigBytes, sig); err != nil {
		return nil, fmt.Errorf("%w: signature: %w", ErrMalformed, err)
	}
	// Re-marshalling must reproduce the input, so one signature has exactly
	// one blob (no trailing bytes hidden in the signature field).
	if !bytes.Equal(marshalBlob(pub, string(ns), string(alg), sig), blob) {
		return nil, fmt.Errorf("%w: non-canonical encoding", ErrMalformed)
	}
	return &Signature{pub: pub, namespace: string(ns), hashAlg: string(alg), sig: sig, blob: blob}, nil
}

// checkKeyType refuses certificates, RSA and unknown key types.
func checkKeyType(pub ssh.PublicKey) error {
	if _, ok := pub.(*ssh.Certificate); ok {
		return fmt.Errorf("%w: certificate keys cannot sign", ErrKeyType)
	}
	if _, ok := signatureFormats[pub.Type()]; !ok {
		return fmt.Errorf("%w: %s", ErrKeyType, pub.Type())
	}
	return nil
}

// checkFormat requires the signature format that belongs to the key type
// and, for sk-* keys, the user-presence flag. x/crypto checks the flag too;
// the explicit check keeps the rule independent of library defaults.
func checkFormat(pub ssh.PublicKey, sig *ssh.Signature) error {
	want := signatureFormats[pub.Type()]
	if sig.Format != want {
		return fmt.Errorf("sshsig: signature format %q for key type %s", sig.Format, pub.Type())
	}
	if strings.HasPrefix(pub.Type(), "sk-") {
		var f struct {
			Flags   byte
			Counter uint32
		}
		if err := ssh.Unmarshal(sig.Rest, &f); err != nil {
			return fmt.Errorf("%w: sk signature flags: %w", ErrMalformed, err)
		}
		if f.Flags&skUserPresent == 0 {
			return ErrUserPresence
		}
	} else if len(sig.Rest) != 0 {
		return fmt.Errorf("%w: trailing signature data", ErrMalformed)
	}
	return nil
}

// readString reads one SSH string (uint32 length, then the bytes).
func readString(s *cryptobyte.String, out *[]byte) bool {
	var n uint32
	if !s.ReadUint32(&n) || uint64(n) > uint64(len(*s)) {
		return false
	}
	return s.ReadBytes(out, int(n))
}
