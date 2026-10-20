package wire

import (
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/cryptobyte"
)

// MaxStatusFrame is the largest frame length (header and body) of a
// StatusResponse: the signer's key report, the installed trust bundle and
// policy with their signatures, and the directory's fixed-size fields.
// InstallBundle refuses a bundle and policy whose Status reply would not
// fit, so every installed trust state can be reported.
const MaxStatusFrame = 256 << 10

// MaxStatusKeys bounds the key entries of a StatusResponse (the signer has
// five roles today).
const MaxStatusKeys = 8

// maxStatusString bounds each string field of a KeyStatus.
const maxStatusString = 255

// token is the form of a key's role and custody in a StatusResponse.
var token = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// IsToken reports whether s is a short lowercase token: 1 to 64 of a-z,
// 0-9 and '-', not starting with '-'. A StatusResponse's role and custody
// names must be tokens, so text that the CLI and keyroster-server print or
// put in a header from a signer report cannot carry control characters,
// spaces or padding.
func IsToken(s string) bool { return token.MatchString(s) }

// ErrStatusTooLarge means a StatusResponse body would exceed the
// MaxStatusFrame budget. The signer refuses to install a bundle and policy
// that would cause it, and Status reports it instead of truncating.
var ErrStatusTooLarge = errors.New("wire: status reply exceeds its frame budget")

// KeyStatus is one online key as the signer reports it: its role, its
// algorithm and custody as ca-init recorded them and the signer re-checked
// at start, and its SHA-256 fingerprint.
type KeyStatus struct {
	Role        string
	Alg         string
	Custody     string
	Fingerprint string
}

// StatusResponse is the signer's own report (D-18): every online key with
// its custody, the installed trust bundle and policy with their root
// signatures, exactly as the signer runs on them, and the installed
// directory's version, SHA-256 of its canonical bytes and whether it is
// authorized under the policy in force. Custody shown to users comes only
// from here. A Status request (TypeStatus) has an empty body.
//
// Encoding: a uint8 key count, each key's four strings uint16-length-
// prefixed; the bundle version as uint64; bundle, bundle signatures,
// policy and policy signatures uint24-length-prefixed; the directory
// version as uint64, its 32-byte SHA-256 and Authorized as one byte 0 or
// 1. Directory version 0 (none installed) has one encoding only: a zero
// hash and Authorized 0.
type StatusResponse struct {
	Keys                []KeyStatus
	BundleVersion       uint64
	Bundle              []byte
	BundleSigs          []byte
	Policy              []byte
	PolicySigs          []byte
	DirectoryVersion    uint64
	DirectorySHA256     [32]byte
	DirectoryAuthorized bool
}

func (r *StatusResponse) check() error {
	if len(r.Keys) == 0 || len(r.Keys) > MaxStatusKeys {
		return fmt.Errorf("%w: %d status keys", ErrMalformed, len(r.Keys))
	}
	for _, k := range r.Keys {
		for _, s := range []string{k.Role, k.Alg, k.Custody, k.Fingerprint} {
			if len(s) == 0 || len(s) > maxStatusString {
				return fmt.Errorf("%w: status key field length", ErrMalformed)
			}
		}
		if !IsToken(k.Role) || !IsToken(k.Custody) {
			return fmt.Errorf("%w: a status key's role or custody is not a lowercase token", ErrMalformed)
		}
	}
	if r.DirectoryVersion == 0 && (r.DirectorySHA256 != [32]byte{} || r.DirectoryAuthorized) {
		return fmt.Errorf("%w: a status without a directory carries a directory hash or authorization", ErrMalformed)
	}
	return nil
}

// maxStatusBody is the largest StatusResponse body: MaxStatusFrame minus
// the version and type header, the same limit maxBodyFor applies to the
// frame.
const maxStatusBody = MaxStatusFrame - headerLen

// Marshal encodes the response body. A body above MaxStatusFrame minus the
// 2-byte header is refused with ErrStatusTooLarge, never truncated.
func (r *StatusResponse) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8(uint8(len(r.Keys))) //nolint:gosec // G115: at most MaxStatusKeys, checked above
	for _, k := range r.Keys {
		for _, s := range []string{k.Role, k.Alg, k.Custody, k.Fingerprint} {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(s)) })
		}
	}
	b.AddUint64(r.BundleVersion)
	for _, d := range [][]byte{r.Bundle, r.BundleSigs, r.Policy, r.PolicySigs} {
		if len(d) > 1<<24-1 {
			return nil, fmt.Errorf("%w: a status document of %d bytes, above the %d-byte limit", ErrStatusTooLarge, len(d), maxStatusBody)
		}
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(d) })
	}
	b.AddUint64(r.DirectoryVersion)
	b.AddBytes(r.DirectorySHA256[:])
	var auth uint8
	if r.DirectoryAuthorized {
		auth = 1
	}
	b.AddUint8(auth)
	out, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if len(out) > maxStatusBody {
		return nil, fmt.Errorf("%w: a body of %d bytes, above the %d-byte limit (MaxStatusFrame minus the %d-byte header)", ErrStatusTooLarge, len(out), maxStatusBody, headerLen)
	}
	return out, nil
}

// ParseStatusResponse decodes a response body strictly: at most
// MaxStatusKeys keys with non-empty fields, each role and custody a token
// (IsToken), Authorized 0 or 1, nothing
// after it, and a status without a directory carrying no hash and no
// authorization.
func ParseStatusResponse(body []byte) (*StatusResponse, error) {
	if len(body) > maxStatusBody {
		return nil, ErrStatusTooLarge
	}
	s := cryptobyte.String(body)
	var (
		r     StatusResponse
		count uint8
	)
	if !s.ReadUint8(&count) || count == 0 || count > MaxStatusKeys {
		return nil, ErrMalformed
	}
	for range count {
		var f [4]cryptobyte.String
		for i := range f {
			if !s.ReadUint16LengthPrefixed(&f[i]) {
				return nil, ErrMalformed
			}
		}
		r.Keys = append(r.Keys, KeyStatus{Role: string(f[0]), Alg: string(f[1]), Custody: string(f[2]), Fingerprint: string(f[3])})
	}
	if !s.ReadUint64(&r.BundleVersion) {
		return nil, ErrMalformed
	}
	for _, d := range []*[]byte{&r.Bundle, &r.BundleSigs, &r.Policy, &r.PolicySigs} {
		var v cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&v) {
			return nil, ErrMalformed
		}
		*d = append([]byte(nil), v...)
	}
	var (
		sum  []byte
		auth uint8
	)
	if !s.ReadUint64(&r.DirectoryVersion) || !s.ReadBytes(&sum, 32) || !s.ReadUint8(&auth) || !s.Empty() || auth > 1 {
		return nil, ErrMalformed
	}
	copy(r.DirectorySHA256[:], sum)
	r.DirectoryAuthorized = auth == 1
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}
