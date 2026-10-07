// Package agent is the ssh-agent keystore backend, registered as "agent".
// It talks to an OpenSSH ssh-agent over its Unix socket; with a PKCS#11
// provider loaded into that agent (ssh-add -s), the key stays in the token
// and the vendor module runs in OpenSSH's ssh-pkcs11-helper, not in the
// signer.
//
// Options:
//
//	socket   path of the agent socket (required)
//	custody  "agent" (default) or "pkcs11-agent"
//
// Custody pkcs11-agent is the operator's declaration. The agent protocol
// does not say where a key lives: a key from a PKCS#11 token, from a
// SoftHSM token, and a plain key added with ssh-add look the same, and the
// entry's comment is whatever the loader chose. So the backend cannot
// verify the claim; Describe (printed by ca-init) and keyroster-signer
// doctor say that it is declared, not verified (D-WR-03).
package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
)

// ErrKeyNotPresent means no non-certificate key in the agent has the pinned
// fingerprint. The backend never falls back to another key.
var ErrKeyNotPresent = errors.New("keystore: pinned CA key not present in agent")

func init() { keystore.Register("agent", open) }

// requestTimeout bounds each request to the agent (listing its keys, or
// one signature): an agent or ssh-pkcs11-helper that hangs must not block
// every signing request behind the backend's mutex. It is generous because
// a token such as a YubiHSM 2 behind yubihsm-connector may be slow. Tests
// shorten it.
var requestTimeout = 30 * time.Second

type backend struct {
	mu      sync.Mutex // guards conn and client and serialises every agent request
	sock    string
	conn    net.Conn // nil after a failed request, until the next request redials
	client  sshagent.ExtendedAgent
	custody keystore.Custody
}

func open(opts map[string]string) (keystore.Backend, error) {
	if err := keystore.CheckOptions(opts, "socket", "custody"); err != nil {
		return nil, err
	}
	sock := opts["socket"]
	if sock == "" {
		return nil, errors.New("keystore agent: option socket is required")
	}
	custody := keystore.CustodyAgent
	switch c := keystore.Custody(opts["custody"]); c {
	case "", keystore.CustodyAgent:
	case keystore.CustodyPKCS11Agent:
		custody = c
	default:
		return nil, fmt.Errorf("keystore agent: custody must be %q or %q", keystore.CustodyAgent, keystore.CustodyPKCS11Agent)
	}
	b := &backend{sock: sock, custody: custody}
	if err := b.connect(); err != nil {
		return nil, err
	}
	return b, nil
}

// connect dials the agent socket. The caller holds b.mu, or owns b.
func (b *backend) connect() error {
	conn, err := net.Dial("unix", b.sock)
	if err != nil {
		return fmt.Errorf("keystore agent: connect: %w", err)
	}
	b.conn, b.client = conn, sshagent.NewClient(conn)
	return nil
}

// drop closes and forgets the connection. The caller holds b.mu.
func (b *backend) drop() error {
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn, b.client = nil, nil
	return err
}

// request runs f against the agent under b.mu, with requestTimeout as the
// connection's deadline. Any failure discards the connection: after an I/O
// error or an expired deadline its state is unknown, and a late reply must
// never answer a later request. f is then tried once more on a new
// connection, so a restarted agent (keyroster-signer-agent.service, or its
// ssh-pkcs11-helper) does not leave a running signer unable to sign. The
// second error, if any, is returned. The caller's key is still chosen by
// its public key, so a new connection cannot substitute another key.
func (b *backend) request(f func(sshagent.ExtendedAgent) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	for range 2 {
		if b.conn == nil {
			if cerr := b.connect(); cerr != nil {
				if err != nil {
					return fmt.Errorf("%w; reconnecting: %w", err, cerr)
				}
				return cerr
			}
		}
		if err = b.call(f); err == nil {
			return nil
		}
		_ = b.drop()
	}
	return err
}

// call runs one request on the current connection within requestTimeout.
func (b *backend) call(f func(sshagent.ExtendedAgent) error) error {
	if err := b.conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	err := f(b.client)
	if derr := b.conn.SetDeadline(time.Time{}); err == nil {
		err = derr
	}
	return err
}

// Describe names the custody and, for pkcs11-agent, that it is declared.
func (b *backend) Describe() string {
	if b.custody == keystore.CustodyPKCS11Agent {
		return "ssh-agent: custody pkcs11-agent declared by the operator, not verified (the agent cannot show whether a key lives in a hardware token)"
	}
	return "ssh-agent: custody agent (plain keys in ssh-agent: test and development only)"
}

// Key returns the agent key whose SHA-256 fingerprint equals fingerprint.
// Certificate entries are skipped (CA-07) and the key must pass
// cert.CheckCAKey.
func (b *backend) Key(role keystore.Role, fingerprint string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore agent: no pinned fingerprint for role %s", role)
	}
	var keys []*sshagent.Key
	if err := b.request(func(c sshagent.ExtendedAgent) (err error) {
		keys, err = c.List()
		return err
	}); err != nil {
		return nil, fmt.Errorf("keystore agent: list keys: %w", err)
	}
	for _, pub := range keys {
		if isCertificate(pub) {
			continue
		}
		if ssh.FingerprintSHA256(pub) != fingerprint {
			continue
		}
		if err := cert.CheckCAKey(pub); err != nil {
			return nil, fmt.Errorf("keystore agent: pinned key for role %s: %w", role, err)
		}
		return &caKey{b: b, pub: pub}, nil
	}
	return nil, fmt.Errorf("%w (role %s)", ErrKeyNotPresent, role)
}

// isCertificate reports whether an agent entry is a certificate. The agent
// client returns every entry as an *agent.Key, never as *ssh.Certificate,
// so the wire key type is what identifies a certificate entry.
func isCertificate(pub ssh.PublicKey) bool {
	if _, ok := pub.(*ssh.Certificate); ok {
		return true
	}
	return strings.HasSuffix(pub.Type(), "-cert-v01@openssh.com")
}

func (b *backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.drop()
}

// caKey signs through the backend's request, so concurrent signatures
// never interleave on the agent connection, and a signature after an
// agent restart goes over a new connection. The agent picks the key by its
// public key blob, which for a plain key never matches a certificate entry.
type caKey struct {
	b   *backend
	pub *sshagent.Key
}

func (k *caKey) PublicKey() ssh.PublicKey { return k.pub }

// Sign asks the agent to sign data; the agent uses its own randomness.
func (k *caKey) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	var sig *ssh.Signature
	err := k.b.request(func(c sshagent.ExtendedAgent) (err error) {
		sig, err = c.Sign(k.pub, data)
		return err
	})
	return sig, err
}

func (k *caKey) Custody() keystore.Custody { return k.b.custody }

func (k *caKey) Algorithm() string { return k.pub.Type() }
