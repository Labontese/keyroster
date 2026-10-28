// Package join is the agent's join string (AGENT-01, D-02): one opaque
// line an admin mints with keyroster host join-token and copies to the
// host, where keyroster-agent install reads it from a 0600 file. It
// carries the one-time enrollment token and everything the agent pins at
// enrollment, so its first contact is free of trust on first use: the
// agent server's URL, the TLS root certificates and their SPKI pins (the
// fetcher verifies the server like the CLI does: a pool of the pinned
// roots plus the host name, never the leaf), the trust-root fingerprints
// with their threshold and the installation ID (the applier's pins.json).
//
// The format is "kr-join-v1:" and the unpadded base64url of the canonical
// JSON of JoinToken. The string is a secret until its token is used or
// expires: it is never printed or logged (String redacts the token).
//
// This package imports no HTTP or TLS code: the root applier parses join
// strings (internal/tlspin holds the URL and pin rules).
package join

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/tlspin"
	"github.com/Labontese/keyroster/internal/trust"
)

// Prefix starts every join string.
const Prefix = "kr-join-v1:"

// Version is the JoinToken version this package reads and writes.
const Version = 1

// MaxString bounds a join string, the prefix included.
const MaxString = 64 << 10

// TokenBytes is the length of the raw enrollment token.
const TokenBytes = 32

// ErrInvalid is every refusal of Parse; its text names the rule.
var ErrInvalid = errors.New("join_string_invalid")

// JoinToken is the decoded join string. TLSPins and TrustPins are sets,
// kept sorted. Token is the unpadded base64url of TokenBytes random bytes.
// ExpiresAt is RFC 3339 in UTC with whole seconds; the server enforces it.
type JoinToken struct { //nolint:revive // the plan's name (03-07), used across the agent, the server and the CLI
	Version        int      `json:"version"`
	Server         string   `json:"server"`
	TLSRoots       []string `json:"tls_roots"`
	TLSPins        []string `json:"tls_pins"`
	TrustPins      []string `json:"trust_pins"`
	Threshold      int      `json:"threshold"`
	InstallationID string   `json:"installation_id"`
	Token          string   `json:"token"`
	ExpectedName   string   `json:"expected_name"`
	ExpiresAt      string   `json:"expires_at"`
}

// String describes j without its token, so a join token that reaches a
// log or an error message never leaks the secret (T-03-49).
func (j JoinToken) String() string {
	return fmt.Sprintf("join token for host %s at %s (expires %s, token redacted)", j.ExpectedName, j.Server, j.ExpiresAt)
}

// GoString is String, for %#v.
func (j JoinToken) GoString() string { return j.String() }

// Format sorts j's pin sets, checks it with Check and returns the join
// string.
func Format(j JoinToken) (string, error) {
	j.TLSPins = slices.Sorted(slices.Values(j.TLSPins))
	j.TrustPins = slices.Sorted(slices.Values(j.TrustPins))
	if err := Check(&j); err != nil {
		return "", err
	}
	b, err := trust.CanonicalJSON(j)
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Parse reads a join string: the prefix, at most MaxString bytes in all,
// unpadded base64url, canonical JSON of a JoinToken decoded strictly
// (trust.DecodeStrict: no unknown fields, no other spelling), then Check.
// Surrounding white space (the line end of a file) is ignored.
func Parse(s string) (*JoinToken, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxString {
		return nil, fmt.Errorf("%w: %d bytes, above %d", ErrInvalid, len(s), MaxString)
	}
	body, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return nil, fmt.Errorf("%w: it does not start with %s", ErrInvalid, Prefix)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("%w: not unpadded base64url", ErrInvalid)
	}
	var j JoinToken
	if err := trust.DecodeStrict(raw, &j); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := Check(&j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Check enforces every rule of a join token (AGENT-01 edges):
//   - version 1;
//   - the server URL is what tlspin.ParseServerURL returns for it (no
//     other spelling);
//   - at least one TLS root and one TLS pin, every root a CA certificate
//     whose pin is listed and every pin the pin of a listed root;
//   - the TLS and trust pins sorted with no duplicate, at least one trust
//     pin and a threshold from 1 to the number of trust pins
//     (trust.CheckPins);
//   - an installation ID of 32 lowercase hex digits, compared byte for
//     byte later (no case folding);
//   - a token that is the unpadded base64url of exactly TokenBytes bytes;
//   - an expected host name in the directory's host name grammar;
//   - expires_at in RFC 3339, UTC, whole seconds.
func Check(j *JoinToken) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	if j.Version != Version {
		return bad("version %d, want %d", j.Version, Version)
	}
	if err := checkServer(j.Server, j.TLSRoots, j.TLSPins); err != nil {
		return err
	}
	if len(j.TrustPins) == 0 {
		return bad("no trust pin")
	}
	if err := checkSet("trust pins", j.TrustPins); err != nil {
		return err
	}
	if err := trust.CheckPins(j.TrustPins, j.Threshold); err != nil {
		return bad("%v", err)
	}
	if j.InstallationID == "" {
		return bad("no installation ID")
	}
	if !trust.IsInstallationID(j.InstallationID) {
		return bad("the installation ID must be 32 lowercase hex digits")
	}
	if j.Token == "" {
		return bad("no token")
	}
	if _, err := DecodeToken(j.Token); err != nil {
		return err
	}
	if !directory.ValidUserName(j.ExpectedName) {
		return bad("expected host name %q is not a directory host name", j.ExpectedName)
	}
	if _, err := ParseExpiry(j.ExpiresAt); err != nil {
		return err
	}
	return nil
}

// checkServer is Check's rule for the server URL, the TLS roots and their
// pins: the URL in its normal form, at least one root and one pin, the
// pins a sorted set, every root one CA certificate whose pin is listed and
// every pin the pin of a listed root.
func checkServer(server string, roots, pins []string) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	if server == "" {
		return bad("no server")
	}
	u, err := tlspin.ParseServerURL(server)
	if err != nil {
		return bad("%v", err)
	}
	if u.String() != server {
		return bad("the server URL is not in its normal form %s", u.String())
	}
	if len(roots) == 0 {
		return bad("no TLS root certificate")
	}
	if len(pins) == 0 {
		return bad("no TLS pin")
	}
	if err := checkSet("TLS pins", pins); err != nil {
		return err
	}
	rootPins := map[string]bool{}
	for _, r := range roots {
		certs, err := tlspin.ParseRoots([]byte(r))
		if err != nil {
			return bad("%v", err)
		}
		if len(certs) != 1 {
			return bad("each TLS root entry must hold exactly one certificate")
		}
		rootPins[tlspin.PinOf(certs[0])] = true
	}
	for _, p := range pins {
		if err := tlspin.CheckPin(p); err != nil {
			return bad("%v", err)
		}
		if !rootPins[p] {
			return bad("TLS pin %s is not the pin of a listed root", p)
		}
	}
	for p := range rootPins {
		if !slices.Contains(pins, p) {
			return bad("a listed TLS root (%s) is not pinned", p)
		}
	}
	return nil
}

// checkSet refuses an unsorted list or one with a duplicate.
func checkSet(what string, s []string) error {
	for i := 1; i < len(s); i++ {
		switch {
		case s[i-1] == s[i]:
			return fmt.Errorf("%w: %s hold %s twice", ErrInvalid, what, s[i])
		case s[i-1] > s[i]:
			return fmt.Errorf("%w: %s are not sorted", ErrInvalid, what)
		}
	}
	return nil
}

// DecodeToken returns the raw token of its unpadded base64url form, which
// must decode to exactly TokenBytes bytes.
func DecodeToken(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != TokenBytes {
		return nil, fmt.Errorf("%w: the token must be the unpadded base64url of exactly %d bytes", ErrInvalid, TokenBytes)
	}
	return raw, nil
}

// EncodeToken is the unpadded base64url form of a raw token.
func EncodeToken(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// TokenSHA256 is the lowercase hex SHA-256 of the raw token: what the
// server stores, and what the enrollment proof of possession names.
func TokenSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ParseExpiry reads an expires_at value: RFC 3339 in UTC ("Z") with whole
// seconds, in exactly the form FormatExpiry writes.
func ParseExpiry(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Location() != time.UTC || t.Nanosecond() != 0 || FormatExpiry(t) != s {
		return time.Time{}, fmt.Errorf("%w: expires_at %q is not RFC 3339 UTC with whole seconds", ErrInvalid, s)
	}
	return t, nil
}

// FormatExpiry writes t as RFC 3339 UTC with whole seconds.
func FormatExpiry(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// FetchConfig is <root>/etc/keyroster-agent/fetch.json, written by
// keyroster-agent install from a join string (canonical JSON, root,
// group keyroster-agent, 0640): all the fetcher learns of the pins, the
// agent server's URL and its TLS roots with their pins. The trust pins and
// threshold stay in the applier's root-only pins.json (D-02).
type FetchConfig struct {
	Server   string   `json:"server"`
	TLSRoots []string `json:"tls_roots"`
	TLSPins  []string `json:"tls_pins"`
}

// FetcherToken is <root>/var/lib/keyroster-agent-fetch/join-token, written
// by install (canonical JSON, keyroster-agent, 0600) and removed by the
// fetcher once the server accepted its enrollment: the one-time token and
// what the fetcher's enrollment request names.
type FetcherToken struct {
	Token          string `json:"token"`
	ExpectedName   string `json:"expected_name"`
	InstallationID string `json:"installation_id"`
}

// String describes t without its token.
func (t FetcherToken) String() string {
	return fmt.Sprintf("join token for host %s (token redacted)", t.ExpectedName)
}

// GoString is String, for %#v.
func (t FetcherToken) GoString() string { return t.String() }

// FetchConfigOf is the fetcher's part of j.
func FetchConfigOf(j *JoinToken) FetchConfig {
	return FetchConfig{Server: j.Server, TLSRoots: slices.Clone(j.TLSRoots), TLSPins: slices.Clone(j.TLSPins)}
}

// FetcherTokenOf is the fetcher's token file of j.
func FetcherTokenOf(j *JoinToken) FetcherToken {
	return FetcherToken{Token: j.Token, ExpectedName: j.ExpectedName, InstallationID: j.InstallationID}
}

// CheckFetchConfig applies the server, root and pin rules of Check to c.
func CheckFetchConfig(c *FetchConfig) error { return checkServer(c.Server, c.TLSRoots, c.TLSPins) }

// CheckFetcherToken applies the token, name and installation rules of
// Check to t.
func CheckFetcherToken(t *FetcherToken) error {
	if _, err := DecodeToken(t.Token); err != nil {
		return err
	}
	if !directory.ValidUserName(t.ExpectedName) {
		return fmt.Errorf("%w: expected host name %q is not a directory host name", ErrInvalid, t.ExpectedName)
	}
	if !trust.IsInstallationID(t.InstallationID) {
		return fmt.Errorf("%w: the installation ID must be 32 lowercase hex digits", ErrInvalid)
	}
	return nil
}
