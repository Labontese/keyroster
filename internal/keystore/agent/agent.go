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
package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
)

// ErrKeyNotPresent means no non-certificate key in the agent has the pinned
// fingerprint. The backend never falls back to another key.
var ErrKeyNotPresent = errors.New("keystore: pinned CA key not present in agent")

func init() { keystore.Register("agent", open) }

type backend struct {
	mu      sync.Mutex // guards every use of conn and client
	conn    net.Conn
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
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("keystore agent: connect: %w", err)
	}
	return &backend{conn: conn, client: sshagent.NewClient(conn), custody: custody}, nil
}

// Key returns the agent key whose SHA-256 fingerprint equals fingerprint.
// Certificate entries are skipped (CA-07) and the key must pass
// cert.CheckCAKey.
func (b *backend) Key(role keystore.Role, fingerprint string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore agent: no pinned fingerprint for role %s", role)
	}
	b.mu.Lock()
	signers, err := b.client.Signers()
	b.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("keystore agent: list keys: %w", err)
	}
	for _, s := range signers {
		pub := s.PublicKey()
		if _, isCert := pub.(*ssh.Certificate); isCert {
			continue
		}
		if ssh.FingerprintSHA256(pub) != fingerprint {
			continue
		}
		if err := cert.CheckCAKey(pub); err != nil {
			return nil, fmt.Errorf("keystore agent: pinned key for role %s: %w", role, err)
		}
		return &caKey{b: b, s: s}, nil
	}
	return nil, fmt.Errorf("%w (role %s)", ErrKeyNotPresent, role)
}

func (b *backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn.Close()
}

// caKey signs through the backend's mutex, so concurrent signatures never
// interleave on the agent connection.
type caKey struct {
	b *backend
	s ssh.Signer
}

func (k *caKey) PublicKey() ssh.PublicKey { return k.s.PublicKey() }

func (k *caKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	k.b.mu.Lock()
	defer k.b.mu.Unlock()
	return k.s.Sign(rand, data)
}

func (k *caKey) Custody() keystore.Custody { return k.b.custody }

func (k *caKey) Algorithm() string { return k.s.PublicKey().Type() }
