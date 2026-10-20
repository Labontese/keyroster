// Package adminauth authenticates keyroster-server's admin API (D-02).
// Every request to /api/v1/admin/ carries a detached SSHSIG made with an
// admin key from the root-signed policy, under the namespace
// keyroster/admin-api/v1, over Message: the method, the path, the SHA-256
// of the body, a timestamp and a single-use nonce. These are the same keys
// and the same SSHSIG machinery as the Phase 1 admin evidence; the server
// has no admin password, token or other bypass.
//
// The signed path is the raw request-target, path and query exactly as
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

// Refusals. Verify returns exactly one of these, wrapped with detail for
// the server log; the server answers every one with the same 401.
var (
	ErrMissingHeaders = errors.New("adminauth: missing admin headers")
	ErrBadTime        = errors.New("adminauth: malformed timestamp")
	ErrStale          = errors.New("adminauth: timestamp too old")
	ErrFuture         = errors.New("adminauth: timestamp in the future")
	ErrBadNonce       = errors.New("adminauth: malformed nonce")
	ErrBadSignature   = errors.New("adminauth: malformed signature")
	ErrNotAdmin       = errors.New("adminauth: signer is not a policy admin")
	ErrNamespace      = errors.New("adminauth: wrong signature namespace")
	ErrMismatch       = errors.New("adminauth: signature does not match the request")
	ErrBadPolicy      = errors.New("adminauth: unusable admin key in the policy")
)

// Message returns the signed bytes of an admin request:
//
//	keyroster/admin-api/v1\n<METHOD>\n<path incl. query>\n<hex sha256 of body>\n<decimal seconds>\n<nonce>\n
//
// path is the raw request-target (see the package comment).
func Message(method, path string, bodySHA256 [32]byte, unix int64, nonce string) []byte {
	b := make([]byte, 0, len(Namespace)+len(method)+len(path)+64+20+nonceLen+6)
	b = append(b, Namespace...)
	b = append(b, '\n')
	b = append(b, method...)
	b = append(b, '\n')
	b = append(b, path...)
	b = append(b, '\n')
	b = hex.AppendEncode(b, bodySHA256[:])
	b = append(b, '\n')
	b = strconv.AppendInt(b, unix, 10)
	b = append(b, '\n')
	b = append(b, nonce...)
	b = append(b, '\n')
	return b
}

// Sign signs one admin request with signer (an admin key, usually held in
// ssh-agent) at time now and returns the three headers to send. Each call
// makes a new nonce: a failed request is retried only by signing it again.
func Sign(signer ssh.Signer, method, path string, body []byte, now time.Time) (http.Header, error) {
	var raw [nonceLen / 2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(raw[:])
	unix := now.Unix()
	sig, err := sshsig.Sign(rand.Reader, signer, Namespace, Message(method, path, sha256.Sum256(body), unix, nonce))
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	h.Set(HeaderTime, strconv.FormatInt(unix, 10))
	h.Set(HeaderNonce, nonce)
	h.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return h, nil
}

// Verify authenticates one admin request: method, path (the raw
// request-target, r.RequestURI), body and headers h, at the server's time
// now, against the policy's admins. The timestamp must be within MaxSkew
// of now, the nonce well-formed, and the signature an SSHSIG under
// Namespace over Message by a key that equals an admin's key. It returns
// the admin's name and the nonce, which the caller must then consume
// exactly once. Every refusal wraps one of the Err values.
func Verify(h http.Header, method, path string, body []byte, now time.Time, admins []trust.AdminKey) (adminName, nonce string, err error) {
	ts, nonce, sigB64 := h.Get(HeaderTime), h.Get(HeaderNonce), h.Get(HeaderSignature)
	if ts == "" || nonce == "" || sigB64 == "" {
		return "", "", ErrMissingHeaders
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || strconv.FormatInt(unix, 10) != ts {
		return "", "", ErrBadTime
	}
	// Compare in seconds: time.Unix of an extreme value would overflow a
	// Duration.
	diff := now.Unix() - unix
	skew := int64(MaxSkew / time.Second)
	switch {
	case diff > skew:
		return "", "", fmt.Errorf("%w: %d s old", ErrStale, diff)
	case diff < -skew:
		return "", "", fmt.Errorf("%w: %d s ahead", ErrFuture, -diff)
	}
	if !validNonce(nonce) {
		return "", "", ErrBadNonce
	}
	if len(sigB64) > maxSignatureHeader {
		return "", "", ErrBadSignature
	}
	armored, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", "", ErrBadSignature
	}
	sig, err := sshsig.Parse(armored)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	pub := sig.PublicKey()
	fp := ssh.FingerprintSHA256(pub)
	name := ""
	for _, a := range admins {
		k, err := trust.ParseKey(a.Key)
		if err != nil {
			return "", "", fmt.Errorf("%w: %s: %w", ErrBadPolicy, a.Name, err)
		}
		if ssh.FingerprintSHA256(k) == fp && a.Key == trust.FormatKey(pub) {
			name = a.Name
			break
		}
	}
	if name == "" {
		return "", "", fmt.Errorf("%w: %s", ErrNotAdmin, fp)
	}
	msg := Message(method, path, sha256.Sum256(body), unix, nonce)
	if err := sig.Verify(Namespace, msg); err != nil {
		if errors.Is(err, sshsig.ErrNamespace) {
			return "", "", fmt.Errorf("%w: %w", ErrNamespace, err)
		}
		return "", "", fmt.Errorf("%w: %w", ErrMismatch, err)
	}
	return name, nonce, nil
}

// validNonce reports whether s is 32 lowercase hex digits.
func validNonce(s string) bool {
	if len(s) != nonceLen {
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
