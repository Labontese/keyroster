// Package enroll is the agent's enrollment proof of possession (AGENT-01,
// T-03-45): every host key sshd serves signs one canonical statement that
// binds the one-time token, the agent's TLS identity, the installation,
// the host keys themselves and the host facts. The root applier signs it
// with the host private keys; keyroster-server verifies it before it
// records a pending host. Nothing an agent sends becomes a principal, a
// host group or a directory name: an admin types those at approval.
//
// This package imports no HTTP or TLS code: the root applier uses it.
package enroll

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// Namespace is the SSHSIG namespace of the proof, and Domain its first
// field, so a signature made for it means nothing anywhere else.
const (
	Namespace = "keyroster/agent-enroll/v1"
	Domain    = Namespace
)

// MaxFactLen bounds each Facts field.
const MaxFactLen = 255

// ErrInvalid is every refusal of Check and Verify.
var ErrInvalid = errors.New("enroll_pop_invalid")

// PoP is the statement each host key signs, as canonical JSON. The hashes
// are lowercase hex SHA-256: of the raw join token, of the agent's TLS
// identity SubjectPublicKeyInfo DER, and of the canonical JSON of the
// Facts. HostKeys are trust.FormatKey strings, sorted, each a type a
// directory host entry may name (directory.IsHostKeyType).
type PoP struct {
	Domain             string   `json:"domain"`
	InstallationID     string   `json:"installation_id"`
	TokenSHA256        string   `json:"token_sha256"`
	IdentitySPKISHA256 string   `json:"identity_spki_sha256"`
	HostKeys           []string `json:"host_keys"`
	FactsSHA256        string   `json:"facts_sha256"`
}

// Facts are what the host reports about itself, for the admin to compare
// out of band at approval. They are the host's word only: never authority,
// never a name in the directory. Each field is printable ASCII of at most
// MaxFactLen bytes (CheckFacts); "" means unknown.
type Facts struct {
	SSHDVersion string `json:"sshd_version"`
	OSID        string `json:"os_id"`
	OSVersionID string `json:"os_version_id"`
	Hostname    string `json:"hostname"`
}

// CheckFacts refuses a field longer than MaxFactLen or holding anything
// but printable ASCII, so facts are safe to print on a terminal.
func CheckFacts(f Facts) error {
	for _, v := range []string{f.SSHDVersion, f.OSID, f.OSVersionID, f.Hostname} {
		if len(v) > MaxFactLen {
			return fmt.Errorf("%w: a fact of %d bytes, above %d", ErrInvalid, len(v), MaxFactLen)
		}
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 || v[i] > 0x7e {
				return fmt.Errorf("%w: a fact holds a byte that is not printable ASCII", ErrInvalid)
			}
		}
	}
	return nil
}

// SanitizeFact makes s a valid fact: every byte that is not printable
// ASCII becomes '?', and it is cut to MaxFactLen bytes.
func SanitizeFact(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > MaxFactLen {
		b = b[:MaxFactLen]
	}
	return string(b)
}

// FactsSHA256 is the lowercase hex SHA-256 of f's canonical JSON.
func FactsSHA256(f Facts) (string, error) {
	b, err := trust.CanonicalJSON(f)
	if err != nil {
		return "", err
	}
	return trust.SHA256Hex(b), nil
}

// Canonical returns p's canonical JSON, the bytes each host key signs.
func (p *PoP) Canonical() ([]byte, error) { return trust.CanonicalJSON(p) }

// Check refuses a statement that is not well formed: another domain, an
// installation ID or hash that is not lowercase hex of its length, and
// host keys that are not 1 to directory.MaxHostKeys sorted, distinct
// trust.FormatKey strings of host key types.
func Check(p *PoP) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	if p.Domain != Domain {
		return bad("domain %q", p.Domain)
	}
	if !trust.IsInstallationID(p.InstallationID) {
		return bad("installation ID")
	}
	for name, h := range map[string]string{"token_sha256": p.TokenSHA256, "identity_spki_sha256": p.IdentitySPKISHA256, "facts_sha256": p.FactsSHA256} {
		if !IsSHA256Hex(h) {
			return bad("%s must be 64 lowercase hex digits", name)
		}
	}
	if len(p.HostKeys) == 0 || len(p.HostKeys) > directory.MaxHostKeys {
		return bad("needs 1 to %d host keys, has %d", directory.MaxHostKeys, len(p.HostKeys))
	}
	for i, k := range p.HostKeys {
		pub, err := trust.ParseKey(k)
		if err != nil || trust.FormatKey(pub) != k {
			return bad("host key %d is not a key in canonical form", i)
		}
		if !directory.IsHostKeyType(pub.Type()) {
			return bad("host key type %s (want ssh-ed25519 or ecdsa-sha2-nistp256/384/521)", pub.Type())
		}
		if i > 0 && p.HostKeys[i-1] >= k {
			return bad("host keys are not sorted and distinct")
		}
	}
	return nil
}

// IsSHA256Hex reports whether s is 64 lowercase hex digits.
func IsSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Sign signs p's canonical bytes with every signer under Namespace. The
// signers' public keys must be exactly p.HostKeys, in that order; the
// signatures come back in the same order (armored SSHSIG).
func Sign(p PoP, signers []ssh.Signer) ([][]byte, error) {
	if err := Check(&p); err != nil {
		return nil, err
	}
	if len(signers) != len(p.HostKeys) {
		return nil, fmt.Errorf("%w: %d signers for %d host keys", ErrInvalid, len(signers), len(p.HostKeys))
	}
	msg, err := p.Canonical()
	if err != nil {
		return nil, err
	}
	sigs := make([][]byte, 0, len(signers))
	for i, s := range signers {
		if trust.FormatKey(s.PublicKey()) != p.HostKeys[i] {
			return nil, fmt.Errorf("%w: signer %d is not host key %d", ErrInvalid, i, i)
		}
		sig, err := sshsig.Sign(rand.Reader, s, Namespace, msg)
		if err != nil {
			return nil, fmt.Errorf("sign the enrollment proof with host key %d: %w", i, err)
		}
		sigs = append(sigs, sig)
	}
	return sigs, nil
}

// Verify checks that sigs holds, for every key of p.HostKeys in order, one
// SSHSIG signature by exactly that key under Namespace over p's canonical
// bytes. hostKeys are p.HostKeys parsed (the caller may pass nil: they are
// parsed here). Any other key, namespace or statement is refused.
func Verify(p PoP, hostKeys []ssh.PublicKey, sigs [][]byte) error {
	if err := Check(&p); err != nil {
		return err
	}
	if hostKeys == nil {
		for _, k := range p.HostKeys {
			pub, err := trust.ParseKey(k)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrInvalid, err)
			}
			hostKeys = append(hostKeys, pub)
		}
	}
	if len(hostKeys) != len(p.HostKeys) || len(sigs) != len(p.HostKeys) {
		return fmt.Errorf("%w: %d host keys, %d keys given, %d signatures", ErrInvalid, len(p.HostKeys), len(hostKeys), len(sigs))
	}
	msg, err := p.Canonical()
	if err != nil {
		return err
	}
	for i, pub := range hostKeys {
		if trust.FormatKey(pub) != p.HostKeys[i] {
			return fmt.Errorf("%w: key %d is not host key %d", ErrInvalid, i, i)
		}
		s, err := sshsig.Parse(sigs[i])
		if err != nil {
			return fmt.Errorf("%w: signature %d: %w", ErrInvalid, i, err)
		}
		if !bytes.Equal(s.PublicKey().Marshal(), pub.Marshal()) {
			return fmt.Errorf("%w: signature %d is not by host key %d", ErrInvalid, i, i)
		}
		if err := s.Verify(Namespace, msg); err != nil {
			return fmt.Errorf("%w: signature %d: %w", ErrInvalid, i, err)
		}
	}
	return nil
}

// IdentityFingerprint is how an agent's TLS identity is shown for the
// approval comparison, by keyroster-agent identity, keyroster host
// approve and the server's log: "SHA256:" and the unpadded standard
// base64 of the SHA-256 of its SubjectPublicKeyInfo DER (spkiHash), the
// form of an OpenSSH key fingerprint.
func IdentityFingerprint(spkiHash []byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(spkiHash)
}

// SortHostKeys returns keys in trust.FormatKey form, sorted, with
// duplicates removed.
func SortHostKeys(keys []ssh.PublicKey) []string {
	var out []string
	for _, k := range keys {
		out = append(out, trust.FormatKey(k))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// The enrollment hand-over between the fetcher and the root applier, in
// files (03-07, F2). The fetcher writes RequestFile and IdentityFile into
// the spool; the applier answers with AnswerFile in the outbox, which only
// it can write and the fetcher can read (root:keyroster-agent 2750, files
// 0640). Both sides read each other's files through spool.ReadFileAt.
const (
	RequestFile = "enroll-request.json"
	AnswerFile  = "enroll-pop.json"
	// IdentityFile is the fetcher's TLS identity, a PEM PUBLIC KEY block
	// (its SPKI), for keyroster-agent identity.
	IdentityFile = "identity.pub"
	// MaxRequestFile bounds RequestFile and IdentityFile as the applier
	// reads them, and MaxAnswerFile AnswerFile as the fetcher reads it.
	MaxRequestFile = 4 << 10
	MaxAnswerFile  = 64 << 10
)

// AcceptedFile is the applier's accepted versions, canonical JSON of
// Accepted, in the outbox (0640), and MaxAcceptedFile its cap as the
// fetcher reads it. The fetcher starts every poll's state requests from
// these, never from the spool's newest file names alone, so a version a
// server spooled that the applier never accepted is asked for again
// (PR #71 review F3/F7).
const (
	AcceptedFile    = "accepted.json"
	MaxAcceptedFile = 4 << 10
)

// Accepted is AcceptedFile: per kind, the version the applier has
// accepted (0: none); KRL is the KRL version the host enforces.
type Accepted struct {
	Bundle    uint64 `json:"bundle"`
	Directory uint64 `json:"directory"`
	KRL       uint64 `json:"krl"`
}

// Request is RequestFile, the fetcher's request for a proof of
// possession, canonical JSON: the SHA-256 of its TLS identity's SPKI and
// of the raw join token (64 lowercase hex digits each), the host name the
// join string names and its installation ID. The applier signs only with
// the installation ID of its own pins.json, which must equal this one
// byte for byte.
type Request struct {
	IdentitySPKISHA256 string `json:"identity_spki_sha256"`
	TokenSHA256        string `json:"token_sha256"`
	ExpectedName       string `json:"expected_name"`
	InstallationID     string `json:"installation_id"`
}

// Answer is AnswerFile, canonical JSON: the proof the applier made, the
// facts it covers and one armored SSHSIG per host key, in PoP.HostKeys
// order.
type Answer struct {
	PoP   PoP      `json:"pop"`
	Facts Facts    `json:"facts"`
	Sigs  [][]byte `json:"sigs"`
}
