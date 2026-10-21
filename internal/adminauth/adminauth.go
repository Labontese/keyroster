// Package adminauth authenticates keyroster-server's admin API (D-02).
// Every request to /api/v1/admin/ carries a detached SSHSIG made with an
// admin key from the root-signed policy, under the namespace
// keyroster/admin-api/v1, over Message, seven lines each ending in \n:
//
//	keyroster/admin-api/v1
//	<origin>          https://host[:port] of the server the request is for
//	<METHOD>
//	<request-target>  path and query, raw
//	<body SHA-256>    64 lowercase hex digits, also sent as HeaderBodySHA256
//	<Unix seconds>    decimal, also sent as HeaderTime
//	<nonce>           32 lowercase hex digits, also sent as HeaderNonce
//
// These are the same keys and the same SSHSIG machinery as the Phase 1
// admin evidence; the server has no admin password, token or other bypass.
//
// The origin binds a signature to one deployment. The client signs the
// canonical form of the server URL it talks to (serverclient's
// ParseServerURL: lowercase host, no trailing dot, no port 443), which is
// the serialization of the policy's webauthn origins. The server verifies
// only against a root-verified policy origin it matched exactly, so a
// request signed for one deployment does not verify at another one that
// trusts the same admin key.
//
// The body is covered through its digest, which travels in a header, so
// the server checks the signature before it reads any of the body. It
// reads the body of a verified request only, and then requires its
// SHA-256 to equal the signed digest (CheckBody).
//
// The signed request-target is the raw one, path and query exactly as
// sent on the wire, never normalised, cleaned or unescaped. The client
// signs the URL.RequestURI() of the request it actually sends, and the
// server verifies against r.RequestURI. Neither side uses the decoded path
// field of a parsed URL or its escaped-path method, so a percent-encoded
// variant of a signed path does not verify (02-07-F12).
//
// The package imports only the standard library, internal/sshsig and
// internal/trust; the signer never imports it.
package adminauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

const (
	// Namespace is the SSHSIG namespace of admin API signatures.
	Namespace = "keyroster/admin-api/v1"
	// HeaderTime carries the request's timestamp, decimal Unix seconds.
	HeaderTime = "Keyroster-Admin-Time"
	// HeaderNonce carries the request's nonce, 32 lowercase hex digits.
	HeaderNonce = "Keyroster-Admin-Nonce"
	// HeaderBodySHA256 carries the SHA-256 of the request body, of the
	// empty body when there is none: exactly 64 lowercase hex digits.
	HeaderBodySHA256 = "Keyroster-Admin-Body-SHA256"
	// HeaderSignature carries the standard base64 of the armored SSHSIG.
	HeaderSignature = "Keyroster-Admin-Signature"
	// MaxSkew is how far a request's timestamp may differ from the
	// server's clock, either way.
	MaxSkew = 120 * time.Second
)

// nonceLen is the length of a nonce: 16 random bytes as lowercase hex.
const nonceLen = 32

// maxSignatureHeader bounds the signature header before it is decoded. A
// real one is well under 1 KiB.
const maxSignatureHeader = 16 << 10

// Refusals. Verify and CheckBody return exactly one of these, wrapped with
// detail for the server log; the server answers every one with the same
// 401.
var (
	ErrMissingHeaders = errors.New("adminauth: missing admin headers")
	ErrBadTime        = errors.New("adminauth: malformed timestamp")
	ErrStale          = errors.New("adminauth: timestamp too old")
	ErrFuture         = errors.New("adminauth: timestamp in the future")
	ErrBadNonce       = errors.New("adminauth: malformed nonce")
	ErrBadDigest      = errors.New("adminauth: malformed body digest")
	ErrBadSignature   = errors.New("adminauth: malformed signature")
	ErrNotAdmin       = errors.New("adminauth: signer is not a policy admin")
	ErrNamespace      = errors.New("adminauth: wrong signature namespace")
	ErrMismatch       = errors.New("adminauth: signature does not match the request")
	ErrBadPolicy      = errors.New("adminauth: unusable admin key in the policy")
	ErrBodyMismatch   = errors.New("adminauth: body does not match the signed digest")
)

// Message returns the signed bytes of an admin request, laid out as in
// the package comment: origin is the canonical https://host[:port] the
// request is for and target the raw request-target.
func Message(origin, method, target string, bodySHA256 [32]byte, unix int64, nonce string) []byte {
	b := make([]byte, 0, len(Namespace)+len(origin)+len(method)+len(target)+64+20+nonceLen+7)
	b = append(b, Namespace...)
	b = append(b, '\n')
	b = append(b, origin...)
	b = append(b, '\n')
	b = append(b, method...)
	b = append(b, '\n')
	b = append(b, target...)
	b = append(b, '\n')
	b = hex.AppendEncode(b, bodySHA256[:])
	b = append(b, '\n')
	b = strconv.AppendInt(b, unix, 10)
	b = append(b, '\n')
	b = append(b, nonce...)
	b = append(b, '\n')
	return b
}

// Sign signs one admin request for origin, the canonical server URL it is
// sent to, with signer (an admin key, usually held in ssh-agent) at time
// now, and returns the four headers to send. Each call makes a new nonce:
// a failed request is retried only by signing it again.
func Sign(signer ssh.Signer, origin, method, target string, body []byte, now time.Time) (http.Header, error) {
	var raw [nonceLen / 2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(raw[:])
	unix := now.Unix()
	digest := sha256.Sum256(body)
	sig, err := sshsig.Sign(rand.Reader, signer, Namespace, Message(origin, method, target, digest, unix, nonce))
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set(HeaderTime, strconv.FormatInt(unix, 10))
	h.Set(HeaderNonce, nonce)
	h.Set(HeaderBodySHA256, hex.EncodeToString(digest[:]))
	h.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return h, nil
}

// Verify authenticates the headers h of one admin request for origin (a
// policy origin the server matched exactly), method and target (the raw
// request-target, r.RequestURI) at the server's time now, against the
// policy's admins. It reads no body. The timestamp must be within MaxSkew
// of now, the nonce and the body digest well-formed, and the signature an
// SSHSIG under Namespace over Message by a key that equals an admin's key.
// It returns the admin's name, the nonce and the signed body digest; the
// caller then reads the body, checks it with CheckBody and consumes the
// nonce exactly once, in that order. Every refusal wraps one of the Err
// values.
func Verify(h http.Header, origin, method, target string, now time.Time, admins []trust.AdminKey) (adminName, nonce string, bodySHA256 [32]byte, err error) {
	var none [32]byte
	ts, nonce, digestHex, sigB64 := h.Get(HeaderTime), h.Get(HeaderNonce), h.Get(HeaderBodySHA256), h.Get(HeaderSignature)
	if ts == "" || nonce == "" || digestHex == "" || sigB64 == "" {
		return "", "", none, ErrMissingHeaders
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || strconv.FormatInt(unix, 10) != ts {
		return "", "", none, ErrBadTime
	}
	// Compare in seconds: time.Unix of an extreme value would overflow a
	// Duration.
	diff := now.Unix() - unix
	skew := int64(MaxSkew / time.Second)
	switch {
	case diff > skew:
		return "", "", none, fmt.Errorf("%w: %d s old", ErrStale, diff)
	case diff < -skew:
		return "", "", none, fmt.Errorf("%w: %d s ahead", ErrFuture, -diff)
	}
	if !validNonce(nonce) {
		return "", "", none, ErrBadNonce
	}
	digest, ok := parseDigest(digestHex)
	if !ok {
		return "", "", none, ErrBadDigest
	}
	if len(sigB64) > maxSignatureHeader {
		return "", "", none, ErrBadSignature
	}
	armored, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", "", none, ErrBadSignature
	}
	sig, err := sshsig.Parse(armored)
	if err != nil {
		return "", "", none, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	pub := sig.PublicKey()
	fp := ssh.FingerprintSHA256(pub)
	name := ""
	for _, a := range admins {
		k, err := trust.ParseKey(a.Key)
		if err != nil {
			return "", "", none, fmt.Errorf("%w: %s: %w", ErrBadPolicy, a.Name, err)
		}
		if ssh.FingerprintSHA256(k) == fp && a.Key == trust.FormatKey(pub) {
			name = a.Name
			break
		}
	}
	if name == "" {
		return "", "", none, fmt.Errorf("%w: %s", ErrNotAdmin, fp)
	}
	if err := sig.Verify(Namespace, Message(origin, method, target, digest, unix, nonce)); err != nil {
		if errors.Is(err, sshsig.ErrNamespace) {
			return "", "", none, fmt.Errorf("%w: %w", ErrNamespace, err)
		}
		return "", "", none, fmt.Errorf("%w: %w", ErrMismatch, err)
	}
	return name, nonce, digest, nil
}

// CheckBody reports whether body is the body a verified request signed:
// its SHA-256 must equal bodySHA256, the digest Verify returned. A
// mismatch is ErrBodyMismatch.
func CheckBody(bodySHA256 [32]byte, body []byte) error {
	if sha256.Sum256(body) != bodySHA256 {
		return ErrBodyMismatch
	}
	return nil
}

// validNonce reports whether s is 32 lowercase hex digits.
func validNonce(s string) bool {
	return len(s) == nonceLen && lowerHex(s)
}

// parseDigest parses a body digest header: exactly 64 lowercase hex
// digits, the one form Sign writes.
func parseDigest(s string) ([32]byte, bool) {
	var d [32]byte
	if len(s) != 2*len(d) || !lowerHex(s) {
		return d, false
	}
	if _, err := hex.Decode(d[:], []byte(s)); err != nil {
		return d, false
	}
	return d, true
}

// lowerHex reports whether s holds only the digits 0-9 and a-f.
func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
