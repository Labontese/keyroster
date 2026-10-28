package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
)

// BrowserTLSConfig is the TLS configuration of keyroster-server's main
// listener, the one browsers and the CLI use: TLS 1.3 with the
// certificate from getCert, and no client certificate asked for (03-07:
// the browser listener stays exactly as it was, so no browser ever shows
// a client-certificate picker).
func BrowserTLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: getCert}
}

// AgentTLSConfig is the TLS configuration of the agent listener
// (--agent-listen, 03-07, D-02): TLS 1.3, the same server certificate,
// and a client certificate required at the handshake
// (tls.RequireAnyClientCert). verifyAgentConn, which runs on every
// connection, resumed ones included, accepts exactly one certificate,
// with an Ed25519 key, whose signature verifies under its own key
// (self-signed): the agent's identity. There is no agent CA, and its
// validity dates are ignored: the server pins the SPKI (requireAgent).
// Whether that identity is enrolled, and approved, is decided per request
// from the SHA-256 of its SPKI (agentSPKI).
func AgentTLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		GetCertificate:   getCert,
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: verifyAgentConn,
	}
}

// errAgentCert is every refusal of an agent's client certificate.
var errAgentCert = errors.New("agent client certificate refused")

// verifyAgentConn is AgentTLSConfig's VerifyConnection, which crypto/tls
// calls for every handshake, a resumed one included (VerifyPeerCertificate
// is not called on resumption): exactly one certificate, an Ed25519 public
// key, and a signature by that same key (cert.CheckSignature over its own
// TBS bytes: CheckSignatureFrom would refuse a leaf that is not a CA).
func verifyAgentConn(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) != 1 {
		return fmt.Errorf("%w: %d certificates, want exactly one self-signed certificate", errAgentCert, len(cs.PeerCertificates))
	}
	cert := cs.PeerCertificates[0]
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return fmt.Errorf("%w: not an Ed25519 key", errAgentCert)
	}
	if cert.SignatureAlgorithm != x509.PureEd25519 {
		return fmt.Errorf("%w: not signed with Ed25519", errAgentCert)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("%w: not self-signed: %w", errAgentCert, err)
	}
	return nil
}

// agentSPKI returns the SHA-256 of the SubjectPublicKeyInfo of the client
// certificate r came with, which AgentTLSConfig verified at the handshake.
// A request without exactly one certificate (only possible on another
// listener) gives false.
func agentSPKI(r *http.Request) ([]byte, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		return nil, false
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return sum[:], true
}
