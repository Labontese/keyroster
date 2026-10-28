// Package tlspin holds the pure parts of keyroster's server pinning: the
// server URL rule, the TLS root SPKI pin and the PEM root parser. It
// imports neither net/http nor crypto/tls, so the root agent applier
// (keyroster-agent, whose graph has no HTTP or TLS code, D-05) can check a
// join string with the same rules the CLI and the fetcher connect with
// (03-07). serverclient re-exports every function here under its old name.
package tlspin

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

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
