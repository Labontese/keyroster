// Package serverclient is the keyroster CLI's HTTPS client for
// keyroster-server. It trusts only the TLS root certificates the user
// pinned with keyroster init (never the system roots), requires every
// connection to chain to one of those pinned roots, verifies the served
// trust bundle against the user's root pins, and prints the evaluation-only
// banner once per Client when the server reports software custody (D-18).
//
// The /api/v1/trust document and the Keyroster-Custody header are defined
// here once; keyroster-server imports them, so the server and every CLI
// build agree on the wire shape.
package serverclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// CustodyHeader carries each online key's custody as the signer reported
// it: "user=<c>, host=<c>, machine=<c>, ops=<c>, log=<c>". keyroster-server
// sets it on every response built from a current signer status, and never
// on a 503 (custody unknown).
const CustodyHeader = "Keyroster-Custody"

// TrustPath is the server route that serves TrustResponse.
const TrustPath = "/api/v1/trust"

// TrustResponse is the /api/v1/trust document: the trust bundle and policy
// the signer runs on, with their root signatures (byte slices are standard
// base64 in JSON), the bundle and directory versions, and each online key's
// custody, all as the signer reported them. Nothing in it is trusted until
// Trust has verified the bundle against the user's root pins.
type TrustResponse struct {
	Bundle           []byte       `json:"bundle"`
	BundleSigs       []byte       `json:"bundle_sigs"`
	Policy           []byte       `json:"policy"`
	PolicySigs       []byte       `json:"policy_sigs"`
	BundleVersion    uint64       `json:"bundle_version"`
	DirectoryVersion uint64       `json:"directory_version"`
	Custody          []KeyCustody `json:"custody"`
}

// KeyCustody is one online key in TrustResponse.
type KeyCustody struct {
	Role        string `json:"role"`
	Alg         string `json:"alg"`
	Custody     string `json:"custody"`
	Fingerprint string `json:"fingerprint"`
}

// APIError is the JSON body of a server error response.
type APIError struct {
	Error string `json:"error"`
}

// CustodyHeaderValue formats keys as the CustodyHeader value, in the order
// given. It refuses a role or custody that is not a short lowercase token,
// so a signer report can never inject anything into a header.
func CustodyHeaderValue(keys []wire.KeyStatus) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("custody: no keys")
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if !wire.IsToken(k.Role) || !wire.IsToken(k.Custody) {
			return "", fmt.Errorf("custody: role %q or custody %q is not a lowercase token", k.Role, k.Custody)
		}
		parts = append(parts, k.Role+"="+k.Custody)
	}
	return strings.Join(parts, ", "), nil
}

// ParseCustodyHeader parses a CustodyHeader value into keys with Role and
// Custody set, in header order. It has at most wire.MaxStatusKeys entries,
// each role=custody with role one of the signer's roles (user, host,
// machine, ops, log) and custody a lowercase token, and no role may
// repeat. The header arrives before Trust has verified anything, so it
// cannot fill the evaluation-only banner with roles of its own.
func ParseCustodyHeader(v string) ([]wire.KeyStatus, error) {
	if strings.Count(v, ",") >= wire.MaxStatusKeys {
		return nil, fmt.Errorf("malformed %s header %s", CustodyHeader, peerExcerpt(v))
	}
	var out []wire.KeyStatus
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		role, custody, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !slices.Contains(trust.CAPubKeyRoles, role) || !wire.IsToken(custody) || seen[role] {
			return nil, fmt.Errorf("malformed %s header %s", CustodyHeader, peerExcerpt(v))
		}
		seen[role] = true
		out = append(out, wire.KeyStatus{Role: role, Custody: custody})
	}
	return out, nil
}

// ErrTLSRootNotPinned means the server's TLS chain does not end in a root
// the user pinned. It cannot name the new root: with only the pinned roots
// in the pool, chain building fails before the client sees it.
var ErrTLSRootNotPinned = errors.New("the server's TLS certificate does not chain to a root you pinned with keyroster init. " +
	"If its CA changed roots, run `keyroster init --server <URL>` without --tls-pin (add --tls-root-file <new root PEM> for a private CA) " +
	"to print the roots it now presents, compare the pins out of band (docs/runbooks/server-install.md \"TLS root changed\"), " +
	"then re-run init with --tls-pin and --force, plus your --root-pin, --threshold, --user and (for an admin) --admin-key, " +
	"since --force replaces the whole config. " +
	"The same error appears when the server is not sending its full chain (a missing intermediate certificate); " +
	"in that case fix the server's certificate file and do not re-pin")

// ErrTrustRootNotPinned means the served trust bundle verifies under its
// own roots but those are not the --root-pin set the user gave keyroster
// init, for example after a root rotation. The message never names the
// served roots, so a hostile server cannot hand the user pins to type.
var ErrTrustRootNotPinned = errors.New("the server's trust bundle is signed by roots that do not match the --root-pin set you gave keyroster init. " +
	"If the roots were rotated (docs/runbooks/root-ceremony.md \"Rotate the roots\"), get the new root fingerprints and threshold " +
	"out of band from the root holders' records, never from the server, and run " +
	"`keyroster init --force --server <URL> --tls-pin <pin> --root-pin <new fp> [--root-pin ...] --threshold <n> " +
	"--user <name> [--admin-key <your admin key>]` (--force replaces the whole config)")

// ErrSignerUnavailable is a 503 from the server: it cannot reach its
// signer, so it reports nothing about the signer's state, custody included.
var ErrSignerUnavailable = errors.New("the server cannot reach its signer (HTTP 503); try again later")

// ErrPolicyNotBundled means the served policy is not the policy the
// verified trust bundle names (its policy_sha256), for example an older
// policy signed by the same roots.
var ErrPolicyNotBundled = errors.New("the server's policy is not the policy its trust bundle names (policy_sha256 mismatch)")

// ErrNoCustody means a successful response carried no custody report.
var ErrNoCustody = errors.New("the server's response carries no " + CustodyHeader + " header, so the signer's key custody is unknown")

// errRootPinMismatch is VerifyConnection's refusal: a chain verified to a
// stored root whose pin is not in the pin set.
var errRootPinMismatch = errors.New("no verified chain ends in a pinned root")

const (
	// requestTimeout bounds every request, connection included.
	requestTimeout = 30 * time.Second
	// maxResponse bounds a response body.
	maxResponse = 4 << 20
)

// bannerFrame frames the custody banner on stderr, as keyroster ca issue
// does.
var bannerFrame = strings.Repeat("!", 76)

// Config configures a Client.
type Config struct {
	// Server is the server URL, https://HOST[:PORT] (ParseServerURL).
	Server string
	// RootsPEM are the pinned TLS root certificates (PEM). Only these
	// verify the server's chain; the system roots are never used.
	RootsPEM []string
	// Pins are the sha256/<base64> SPKI pins (PinOf) of the roots a chain
	// may end in.
	Pins []string
	// Stderr receives the custody banner (nil: io.Discard).
	Stderr io.Writer
}

// Client talks to one keyroster-server over pinned TLS.
type Client struct {
	base   *url.URL
	http   *http.Client
	stderr io.Writer

	mu          sync.Mutex
	bannerShown bool
}

// ParseServerURL validates a server URL: scheme https, a DNS host name
// (never an IP literal), an optional port, and no user info, path, query
// or fragment. It returns the URL normalized to https://host[:port], the
// serialization of the policy's webauthn origins: the host lowercased,
// one trailing dot removed and a port of 443 dropped. The admin API signs
// that origin (internal/adminauth), so every spelling of one server URL
// signs the same bytes.
func ParseServerURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("server URL %q: the scheme must be https", s)
	}
	if u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("server URL %q: no user info allowed", s)
	}
	if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("server URL %q: give only https://HOST[:PORT], with no path, query or fragment", s)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("server URL %q: no host", s)
	}
	if isIPLiteral(host) {
		return nil, fmt.Errorf("server URL %q: the host is an IP address; use the server's DNS name (the WebAuthn RP ID)", s)
	}
	if !isDNSName(host) {
		return nil, fmt.Errorf("server URL %q: the host must be a DNS name: dot-separated labels of letters, digits and inner hyphens", s)
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("server URL %q: empty port", s)
	}
	hostport := strings.ToLower(strings.TrimSuffix(host, "."))
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || p[0] == '0' {
			return nil, fmt.Errorf("server URL %q: bad port", s)
		}
		if n != 443 {
			hostport += ":" + p
		}
	}
	return &url.URL{Scheme: "https", Host: hostport}, nil
}

// numericLabel is a last host label that resolvers read as (part of) an
// IPv4 address: decimal, or hexadecimal with 0x. No DNS top-level domain
// has this form.
var numericLabel = regexp.MustCompile(`^([0-9]+|0x[0-9a-f]*)$`)

// isIPLiteral reports whether host (a URL's Hostname) is an IP address in
// any form: with ':' or an IPv6 zone ('%'), with a trailing dot, or with a
// numeric last label such as 127.1 or 2130706433.
func isIPLiteral(host string) bool {
	if strings.ContainsAny(host, ":%") {
		return true
	}
	h := strings.TrimSuffix(host, ".")
	if net.ParseIP(h) != nil {
		return true
	}
	return numericLabel.MatchString(strings.ToLower(h[strings.LastIndexByte(h, '.')+1:]))
}

// isDNSName reports whether host is a DNS name in letter-digit-hyphen
// form: at most 253 characters (one trailing dot allowed), labels of 1 to
// 63 letters, digits and hyphens, no label starting or ending with a
// hyphen. url.Parse also accepts RFC 3986 sub-delimiters such as '!', '$',
// '(' and ';' in a host; none of them is part of a DNS name, and a server
// URL keyroster prints (in an invite or a keyroster init line) must carry
// no shell metacharacter.
func isDNSName(host string) bool {
	h := strings.TrimSuffix(host, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// PinOf returns the pin of a certificate: "sha256/" and the standard
// base64 of the SHA-256 of its SubjectPublicKeyInfo.
func PinOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

// CheckPin reports whether pin has the form PinOf produces.
func CheckPin(pin string) error {
	b64, ok := strings.CutPrefix(pin, "sha256/")
	if !ok {
		return fmt.Errorf("TLS pin %q: want sha256/<base64 of the SPKI SHA-256>", pin)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("TLS pin %q: want sha256/<base64 of 32 bytes>", pin)
	}
	return nil
}

// ParseRoots parses PEM data that must hold at least one CA certificate
// and nothing but certificates.
func ParseRoots(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, errors.New("TLS roots: data after the last PEM block")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("TLS roots: unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("TLS roots: %w", err)
		}
		if !c.IsCA {
			return nil, fmt.Errorf("TLS roots: %q is not a CA certificate", c.Subject.String())
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("TLS roots: no certificate")
	}
	return out, nil
}

// New builds a Client for cfg. It refuses a bad server URL, no roots or
// pins, a malformed pin and a root that is not a CA certificate.
func New(cfg Config) (*Client, error) {
	base, err := ParseServerURL(cfg.Server)
	if err != nil {
		return nil, err
	}
	if len(cfg.RootsPEM) == 0 || len(cfg.Pins) == 0 {
		return nil, errors.New("serverclient: no pinned TLS roots; run keyroster init")
	}
	pool := x509.NewCertPool()
	for _, p := range cfg.RootsPEM {
		roots, err := ParseRoots([]byte(p))
		if err != nil {
			return nil, err
		}
		for _, r := range roots {
			pool.AddCert(r)
		}
	}
	pinned := map[string]bool{}
	for _, p := range cfg.Pins {
		if err := CheckPin(p); err != nil {
			return nil, err
		}
		pinned[p] = true
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: base.Hostname(),
		// Go has already verified the chain against the stored roots
		// and the host name; this requires its root to be pinned.
		VerifyConnection: func(cs tls.ConnectionState) error {
			for _, chain := range cs.VerifiedChains {
				if len(chain) > 0 && pinned[PinOf(chain[len(chain)-1])] {
					return nil
				}
			}
			return errRootPinMismatch
		},
	}
	tr := &http.Transport{
		Proxy:               nil,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		base: base,
		http: &http.Client{
			Transport: tr,
			Timeout:   requestTimeout,
			// No redirects: the server answers each route itself.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		stderr: stderr,
	}, nil
}

// Server returns the normalized server URL.
func (c *Client) Server() string { return c.base.String() }

// GetJSON GETs path and decodes a 2xx JSON body into out.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// PostJSON POSTs in as JSON to path and decodes a 2xx JSON body into out
// (out may be nil).
func (c *Client) PostJSON(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	return c.send(ctx, method, path, body, out, nil)
}

// send is do with a prepare step, which runs on the finished request just
// before it is sent (AdminJSON signs it there). A non-2xx answer other
// than 503 is an *HTTPError.
func (c *Client) send(ctx context.Context, method, path string, body []byte, out any, prepare func(*http.Request) error) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("serverclient: path %q must start with /", path)
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if prepare != nil {
		if err := prepare(req); err != nil {
			return err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return c.mapError(path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		// A transport failure, as for the request itself.
		return c.mapError(path, err)
	}
	if len(data) > maxResponse {
		return fmt.Errorf("%s%s: response larger than %d bytes", c.base, path, maxResponse)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		// Custody is unknown on a 503; nothing is parsed from it.
		return fmt.Errorf("%s: %w", c.base, ErrSignerUnavailable)
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if err := c.checkCustody(resp.Header, ok); err != nil {
		return fmt.Errorf("%s%s: %w", c.base, path, err)
	}
	if !ok {
		he := &HTTPError{Code: resp.StatusCode, date: resp.Header.Get("Date"), retryAfter: resp.Header.Get("Retry-After")}
		var apiErr APIError
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			// The server's own text, as a short delimited excerpt.
			he.api = apiErr.Error
			he.err = fmt.Errorf("%s%s: HTTP %d: %w", c.base, path, resp.StatusCode, PeerError(errors.New(apiErr.Error)))
		} else {
			he.err = fmt.Errorf("%s%s: HTTP %d", c.base, path, resp.StatusCode)
		}
		return he
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s%s: decode: %w", c.base, path, decodeError(err))
	}
	return nil
}

// decodeError states why a response did not decode, in the CLI's own
// words and from typed fields only: encoding/json's text can repeat what
// the peer sent (a number literal of any length, for one). Anything else
// is a PeerError. The cause stays reachable with errors.As.
func decodeError(err error) error {
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
		b64Err    base64.CorruptInputError
		msg       string
	)
	switch {
	case errors.As(err, &syntaxErr):
		msg = fmt.Sprintf("the response is not valid JSON (at byte %d)", syntaxErr.Offset)
	case errors.As(err, &typeErr):
		msg = fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d)", typeErr.Offset)
	case errors.As(err, &b64Err):
		msg = fmt.Sprintf("the response has a field that is not valid base64 (at byte %d of the field)", int64(b64Err))
	default:
		return PeerError(err)
	}
	return &connectFailure{msg: msg, errs: []error{err}}
}

// mapError states a failed request, or a failed read of its response
// body, through ConnectError: a chain that does not end in a pinned root
// is ErrTLSRootNotPinned, with nothing after it.
func (c *Client) mapError(path string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		// Its text repeats the URL; c.base and path say the same.
		err = ue.Err
	}
	return fmt.Errorf("%s%s: %w", c.base, path, ConnectError(c.base.Hostname(), err, ErrTLSRootNotPinned))
}

// tlsHandshakeTimeout is the text of net/http's error for a TLS handshake
// that exceeded the transport's TLSHandshakeTimeout. The type is
// unexported, so the fixed text identifies it; Go writes it, never the
// peer.
const tlsHandshakeTimeout = "net/http: TLS handshake timeout"

// connectFailure is a failed connection or request stated in the CLI's
// own words (a refused certificate, a timeout, a cancellation) or in the
// text Go wrote for one error in its cause (goText). Error never includes
// the whole cause's text, which can repeat names from the peer's
// certificates (host names, a candidate issuer's name) or embed text the
// peer sent; Unwrap returns the cause, and untrusted when it applies, for
// errors.Is and errors.As.
type connectFailure struct {
	msg  string
	errs []error
}

func (e *connectFailure) Error() string   { return e.msg }
func (e *connectFailure) Unwrap() []error { return e.errs }

// ConnectError states err, the failure of a TLS connection to host (the
// host name the user gave), without repeating anything the peer chose
// (T-02-93):
//
//   - a certificate the chain verification refused is described in the
//     CLI's own words, naming only host: a wrong host name, a chain that
//     does not end in a trusted root (untrusted's text, and errors.Is
//     finds untrusted), an expired certificate and the like;
//   - a timeout of a network operation (a *net.OpError whose Timeout is
//     true: a dial or a DNS lookup) is Go's own text, with the address
//     and the operation. Only synthetic errors test this; no real dial or
//     DNS timeout has been run (UNVERIFIED). A TLS handshake that stalls
//     ends in net/http's own timeout error instead, whose text is the
//     fixed "net/http: TLS handshake timeout": it is "the TLS handshake
//     with <host> timed out" (a real stalled server tests it). Any other
//     timeout is "timed out talking to <host>" and a cancellation "the
//     request to <host> was canceled": net/http's timeout error embeds the
//     inner error's text, which can be the peer's;
//   - a transport failure whose text Go wrote, not the peer, is printed
//     whole: a *net.OpError of any Op (the addresses it resolved and a
//     system error, or a TLS alert's name from a fixed table, as in
//     "remote error: tls: protocol version not supported"), a
//     tls.AlertError, a tls.RecordHeaderError (a fixed message with at
//     most a version or length number), http.ErrSchemeMismatch,
//     io.ErrUnexpectedEOF and io.EOF. Only the matched error's own text
//     is printed, never the errors wrapping it, which may carry received
//     bytes;
//   - anything else is a PeerError: a malformed header line or status
//     line, for example, repeats the bytes the peer sent.
//
// The cause stays reachable with errors.As in every case.
func ConnectError(host string, err, untrusted error) error {
	var (
		hostErr    x509.HostnameError
		unknownErr x509.UnknownAuthorityError
		invalidErr x509.CertificateInvalidError
		verifyErr  *tls.CertificateVerificationError
		opErr      *net.OpError
		netErr     net.Error
	)
	switch {
	case errors.As(err, &hostErr):
		return &connectFailure{msg: "the server's TLS certificate is not valid for " + host, errs: []error{err}}
	case errors.As(err, &unknownErr), errors.Is(err, errRootPinMismatch):
		return &connectFailure{msg: untrusted.Error(), errs: []error{untrusted, err}}
	case errors.As(err, &invalidErr):
		var leaf *x509.Certificate
		if errors.As(err, &verifyErr) && len(verifyErr.UnverifiedCertificates) > 0 {
			leaf = verifyErr.UnverifiedCertificates[0]
		}
		return &connectFailure{msg: "the server's TLS certificate for " + host + " is not valid: " + invalidReason(invalidErr, leaf, time.Now()), errs: []error{err}}
	case errors.As(err, &verifyErr):
		return &connectFailure{msg: "the server's TLS certificate for " + host + " does not verify", errs: []error{err}}
	case errors.As(err, &opErr) && opErr.Timeout():
		// Go's own text: the operation, the address it resolved and
		// "i/o timeout", so the user sees which address and phase.
		return &connectFailure{msg: opErr.Error(), errs: []error{err}}
	case errors.As(err, &netErr) && netErr.Timeout() && netErr.Error() == tlsHandshakeTimeout:
		return &connectFailure{msg: "the TLS handshake with " + host + " timed out", errs: []error{err}}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return &connectFailure{msg: "timed out talking to " + host, errs: []error{err}}
	case errors.Is(err, context.Canceled):
		return &connectFailure{msg: "the request to " + host + " was canceled", errs: []error{err}}
	}
	if text, ok := goText(err); ok {
		return &connectFailure{msg: text, errs: []error{err}}
	}
	return PeerError(err)
}

// goText returns the text of the first error in err's chain whose text Go
// wrote from fixed strings and values it resolved, never from bytes the
// peer sent (see ConnectError), and whether there is one.
func goText(err error) (string, bool) {
	var (
		opErr    *net.OpError
		alertErr tls.AlertError
		recErr   tls.RecordHeaderError
	)
	switch {
	case errors.As(err, &opErr):
		return opErr.Error(), true
	case errors.As(err, &alertErr):
		return alertErr.Error(), true
	case errors.As(err, &recErr):
		return recErr.Error(), true
	}
	for _, sentinel := range []error{http.ErrSchemeMismatch, io.ErrUnexpectedEOF, io.EOF} {
		if errors.Is(err, sentinel) {
			return sentinel.Error(), true
		}
	}
	return "", false
}

// invalidReason says why x509 refused a certificate, in the CLI's own
// words: CertificateInvalidError's Detail can name the peer's names. For a
// certificate outside its validity period it gives that period and now
// as fixed-format UTC times (validity fields, never free text), naming
// the certificate "it" when it is leaf, the server's own certificate.
func invalidReason(e x509.CertificateInvalidError, leaf *x509.Certificate, now time.Time) string {
	switch e.Reason {
	case x509.Expired:
		if e.Cert == nil {
			return "it or a certificate in its chain has expired or is not yet valid"
		}
		which := "a certificate in its chain"
		if leaf != nil && leaf.Equal(e.Cert) {
			which = "it"
		}
		return fmt.Sprintf("%s is valid from %s until %s, and the local time is %s (check the certificate and this computer's clock)",
			which, e.Cert.NotBefore.UTC().Format(time.RFC3339), e.Cert.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	case x509.NotAuthorizedToSign:
		return "a certificate in its chain is not allowed to sign certificates"
	case x509.IncompatibleUsage:
		return "its key usage does not allow a TLS server"
	case x509.TooManyIntermediates:
		return "its chain has too many intermediate certificates"
	case x509.CANotAuthorizedForThisName, x509.CANotAuthorizedForExtKeyUsage, x509.NameConstraintsWithoutSANs,
		x509.UnconstrainedName, x509.TooManyConstraints:
		return "a CA in its chain is not allowed to certify it (name or usage constraints)"
	default:
		return "its chain does not verify"
	}
}

// maxPeerExcerpt bounds the escaped peer text a PeerError shows, in
// bytes, delimiters not counted. It is below 43, the length of a SHA-256
// digest in unpadded base64, so no excerpt holds a whole TLS or root pin.
const maxPeerExcerpt = 40

// peerError is an error whose text the peer chose in part. Its Error is
// only a short excerpt of that text (peerExcerpt); Unwrap returns the
// original, so errors.Is and errors.As still see it.
type peerError struct{ err error }

func (e *peerError) Error() string { return peerExcerpt(e.err.Error()) }
func (e *peerError) Unwrap() error { return e.err }

// PeerError wraps err, whose text may come from the server or from a
// network-position attacker (a response body, a malformed document), so
// that its message is at most a short, escaped, delimited excerpt of that
// text: [peer text: "..."]. Every run of white space becomes one space,
// everything but printable ASCII is escaped (strconv.QuoteToASCII, so a
// quote cannot end the excerpt early), and the escaped text is cut at
// maxPeerExcerpt bytes, cut marked. What this holds, and no more: the
// excerpt is one line of at most maxPeerExcerpt printable ASCII bytes
// inside its delimiters, with no run of two spaces, so padding cannot
// push the CLI's message off the screen and no whole pin fits in it
// (T-02-93). The excerpt is still untrusted text: up to maxPeerExcerpt
// bytes of it are the peer's words. Callers keep the CLI's own advice
// out of any message that carries a PeerError. A nil err stays nil.
func PeerError(err error) error {
	if err == nil {
		return nil
	}
	return &peerError{err: err}
}

// peerExcerpt returns s as PeerError shows it.
func peerExcerpt(s string) string {
	var b strings.Builder
	space, cut := false, false
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		q := strconv.QuoteToASCII(string(r))
		piece := q[1 : len(q)-1]
		if space {
			piece = " " + piece
		}
		if b.Len()+len(piece) > maxPeerExcerpt {
			cut = true
			break
		}
		b.WriteString(piece)
		space = false
	}
	if cut {
		return fmt.Sprintf(`[peer text, cut to %d bytes: "%s"]`, maxPeerExcerpt, b.String())
	}
	return `[peer text: "` + b.String() + `"]`
}

// checkCustody parses the CustodyHeader of a response and prints the
// evaluation-only banner once per Client when any key's custody is
// software. A successful response (required) must carry the header.
func (c *Client) checkCustody(h http.Header, required bool) error {
	vals := h.Values(CustodyHeader)
	if len(vals) == 0 {
		if required {
			return ErrNoCustody
		}
		return nil
	}
	if len(vals) > 1 {
		return fmt.Errorf("more than one %s header", CustodyHeader)
	}
	keys, err := ParseCustodyHeader(vals[0])
	if err != nil {
		return err
	}
	roles := custodytext.SoftwareRoles(keys)
	if len(roles) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.bannerShown {
		c.bannerShown = true
		_, _ = fmt.Fprintf(c.stderr, "%s\n%s\n%s\n", bannerFrame, custodytext.SoftwareCABanner(roles), bannerFrame)
	}
	return nil
}

// Trust fetches /api/v1/trust and verifies it. First, before anything else
// in the documents is parsed, the bundle's root set must be exactly
// rootPins at exactly threshold (otherwise ErrTrustRootNotPinned, with no
// served text) and threshold of those roots must have signed bundle and
// policy. Then the bundle must pass trust.VerifySelfSigned and
// trust.MatchPins, the policy must be the one the bundle names
// (ErrPolicyNotBundled), and no policy admin may be a root. It returns the
// verified bundle and policy.
func (c *Client) Trust(ctx context.Context, rootPins []string, threshold int) (*trust.Bundle, *trust.Policy, error) {
	if err := trust.CheckPins(rootPins, threshold); err != nil {
		return nil, nil, err
	}
	var tr TrustResponse
	if err := c.GetJSON(ctx, TrustPath, &tr); err != nil {
		return nil, nil, err
	}
	// Authenticate before parsing (T-02-93): the served root set must be
	// exactly the pins, and those roots must have signed both documents,
	// before anything else in them is parsed or can appear in an error.
	roots, err := pinnedRoots(tr.Bundle, rootPins, threshold)
	if err != nil {
		return nil, nil, err
	}
	for _, d := range []struct {
		what, namespace string
		doc, sigs       []byte
	}{
		{"trust bundle", trust.NamespaceBundle, tr.Bundle, tr.BundleSigs},
		{"policy", trust.NamespacePolicy, tr.Policy, tr.PolicySigs},
	} {
		signed, err := trust.CountPinnedSigners(d.doc, d.sigs, d.namespace, roots)
		if err != nil {
			return nil, nil, fmt.Errorf("the server's %s signatures are malformed: %w", d.what, PeerError(err))
		}
		if len(signed) < threshold {
			return nil, nil, fmt.Errorf("the server's %s is signed by %d of your pinned roots, below your threshold of %d", d.what, len(signed), threshold)
		}
	}
	// From here on the documents are root-signed.
	b, err := trust.VerifySelfSigned(tr.Bundle, tr.BundleSigs, tr.Policy, tr.PolicySigs)
	if err != nil {
		return nil, nil, fmt.Errorf("the server's trust bundle does not verify under its own roots: %w", PeerError(err))
	}
	// MatchPins' own message names a served root; never show it.
	if err := trust.MatchPins(b, rootPins, threshold); err != nil {
		return nil, nil, ErrTrustRootNotPinned
	}
	if b.PolicySHA256 != trust.SHA256Hex(tr.Policy) {
		return nil, nil, ErrPolicyNotBundled
	}
	if tr.BundleVersion != b.Version {
		return nil, nil, fmt.Errorf("the server reports bundle version %d for a bundle of version %d", tr.BundleVersion, b.Version)
	}
	p, err := trust.ParsePolicy(tr.Policy)
	if err != nil {
		return nil, nil, fmt.Errorf("the server's policy: %w", PeerError(err))
	}
	if err := trust.CheckAdminsNotRoots(p, b.Root.Keys); err != nil {
		return nil, nil, PeerError(err)
	}
	return b, p, nil
}

// pinnedRoots reads only the root set of a served bundle and returns its
// keys by fingerprint when they are exactly pins at exactly threshold.
// Any other root set, none included, is ErrTrustRootNotPinned. The read
// is lenient on purpose: the roots sign only canonical bytes, so a
// document they signed reads the same here as in the strict parse that
// follows. No error repeats the bundle's text.
func pinnedRoots(bundle []byte, pins []string, threshold int) (map[string]ssh.PublicKey, error) {
	var doc struct {
		Root trust.RootSet `json:"root"`
	}
	if json.Unmarshal(bundle, &doc) != nil {
		return nil, errors.New("the server's trust bundle is not a JSON document")
	}
	if trust.MatchPins(&trust.Bundle{Root: doc.Root}, pins, threshold) != nil {
		// MatchPins' own message names a served root; never show it.
		return nil, ErrTrustRootNotPinned
	}
	roots := make(map[string]ssh.PublicKey, len(doc.Root.Keys))
	for _, rk := range doc.Root.Keys {
		pub, err := trust.ParseKey(rk.Key)
		if err != nil {
			return nil, ErrTrustRootNotPinned // unreachable: MatchPins parsed every key
		}
		roots[ssh.FingerprintSHA256(pub)] = pub
	}
	return roots, nil
}
