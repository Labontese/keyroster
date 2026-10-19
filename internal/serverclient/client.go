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
	"strconv"
	"strings"
	"sync"
	"time"

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

// custodyToken is the form of a role or custody name in CustodyHeader.
var custodyToken = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// CustodyHeaderValue formats keys as the CustodyHeader value, in the order
// given. It refuses a role or custody that is not a short lowercase token,
// so a signer report can never inject anything into a header.
func CustodyHeaderValue(keys []wire.KeyStatus) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("custody: no keys")
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if !custodyToken.MatchString(k.Role) || !custodyToken.MatchString(k.Custody) {
			return "", fmt.Errorf("custody: role %q or custody %q is not a lowercase token", k.Role, k.Custody)
		}
		parts = append(parts, k.Role+"="+k.Custody)
	}
	return strings.Join(parts, ", "), nil
}

// ParseCustodyHeader parses a CustodyHeader value into keys with Role and
// Custody set, in header order. Every entry must be role=custody with both
// a lowercase token, and no role may repeat.
func ParseCustodyHeader(v string) ([]wire.KeyStatus, error) {
	var out []wire.KeyStatus
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		role, custody, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !custodyToken.MatchString(role) || !custodyToken.MatchString(custody) || seen[role] {
			return nil, fmt.Errorf("malformed %s header %q", CustodyHeader, v)
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
	// maxAPIError bounds the server error text an error message quotes.
	maxAPIError = 200
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
// or fragment. It returns the URL normalized to https://host[:port].
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
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || p[0] == '0' {
			return nil, fmt.Errorf("server URL %q: bad port", s)
		}
	}
	return &url.URL{Scheme: "https", Host: u.Host}, nil
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
	resp, err := c.http.Do(req)
	if err != nil {
		return c.mapError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("%s%s: %w", c.base, path, err)
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
		var apiErr APIError
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			// The server's own text: quoted, so no control character
			// reaches the terminal, and capped.
			msg := apiErr.Error
			if len(msg) > maxAPIError {
				msg = msg[:maxAPIError] + "..."
			}
			return fmt.Errorf("%s%s: HTTP %d: server said: %q", c.base, path, resp.StatusCode, msg)
		}
		return fmt.Errorf("%s%s: HTTP %d", c.base, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s%s: decode: %w", c.base, path, err)
	}
	return nil
}

// mapError turns a pinned-root failure into ErrTLSRootNotPinned. Other
// failures (a wrong host name, an expired leaf, a network error) keep
// their own error and get no re-pin hint.
func (c *Client) mapError(err error) error {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) || errors.Is(err, errRootPinMismatch) {
		return fmt.Errorf("%s: %w (%w)", c.base, ErrTLSRootNotPinned, err)
	}
	return err
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

// Trust fetches /api/v1/trust and verifies it: the bundle must carry its
// own threshold of its own roots' signatures on bundle and policy
// (trust.VerifySelfSigned), its root set must be exactly rootPins at
// exactly threshold (trust.MatchPins; otherwise ErrTrustRootNotPinned),
// the policy must be the one the bundle names (ErrPolicyNotBundled), and
// no policy admin may be a root. It returns the verified bundle and policy.
func (c *Client) Trust(ctx context.Context, rootPins []string, threshold int) (*trust.Bundle, *trust.Policy, error) {
	if err := trust.CheckPins(rootPins, threshold); err != nil {
		return nil, nil, err
	}
	var tr TrustResponse
	if err := c.GetJSON(ctx, TrustPath, &tr); err != nil {
		return nil, nil, err
	}
	b, err := trust.VerifySelfSigned(tr.Bundle, tr.BundleSigs, tr.Policy, tr.PolicySigs)
	if err != nil {
		return nil, nil, fmt.Errorf("the server's trust bundle does not verify under its own roots: %w", err)
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
		return nil, nil, fmt.Errorf("the server's policy: %w", err)
	}
	if err := trust.CheckAdminsNotRoots(p, b.Root.Keys); err != nil {
		return nil, nil, err
	}
	return b, p, nil
}
