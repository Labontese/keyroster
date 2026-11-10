package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/rootceremony"
)

// maxMachineKeyFileBytes bounds the private key file keyroster machine
// renew reads (03-11b): an OpenSSH private key file is a few KiB at most.
const maxMachineKeyFileBytes = 64 << 10

// readMachineKeyFile reads the machine's private key file at path: a
// regular file of at most maxMachineKeyFileBytes, refused as
// key_file_too_large before any byte of it is parsed. The caller clears
// the returned buffer when it is done with it. A FIFO swapped in between
// the Stat and the open can block the open; whoever can do that owns the
// key path anyway (stated, not defended).
func readMachineKeyFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("--key: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("--key %s is not a regular file", path)
	}
	f, err := os.Open(path) //nolint:gosec // G304: the key file the operator named
	if err != nil {
		return nil, fmt.Errorf("--key: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxMachineKeyFileBytes+1))
	if err != nil {
		clear(data)
		return nil, fmt.Errorf("--key: %w", err)
	}
	if len(data) > maxMachineKeyFileBytes {
		clear(data)
		return nil, fmt.Errorf("key_file_too_large: --key %s is larger than %d bytes, which no OpenSSH private key file is; nothing was sent", path, maxMachineKeyFileBytes)
	}
	return data, nil
}

// Test hooks, nil outside tests. machineKeyParseHook is called before the
// key file is parsed; machineKeyBufferHook is called once, at the caller's
// clear point after the signing, with the file buffer, the passphrase and
// the Ed25519 private key bytes, after they are cleared.
var (
	machineKeyParseHook  func()
	machineKeyBufferHook func(file, passphrase, ed25519Key []byte)
)

// opensshKeyMagic starts the body of an openssh-key-v1 private key file.
const opensshKeyMagic = "openssh-key-v1\x00"

// opensshKeyHeader mirrors the clear header of an openssh-key-v1 file, as
// x/crypto's openSSHEncryptedPrivateKey reads it: the public key blob is
// in the clear even when the private part is encrypted (PD6).
type opensshKeyHeader struct {
	CipherName string
	KdfName    string
	KdfOpts    string
	NumKeys    uint32
	PubKey     []byte
	Rest       []byte `ssh:"rest"`
}

// machineKeyHeaderPub returns the clear public key of an openssh-key-v1
// file, or nil for any other file (PKCS#8, EC PRIVATE KEY and the other
// PEM types carry no clear public key and are never sk). It reads the
// type from the header, never from an error text.
func machineKeyHeaderPub(raw []byte) ssh.PublicKey {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil
	}
	defer clear(block.Bytes)
	if block.Type != "OPENSSH PRIVATE KEY" || !bytes.HasPrefix(block.Bytes, []byte(opensshKeyMagic)) {
		return nil
	}
	var h opensshKeyHeader
	if err := ssh.Unmarshal(block.Bytes[len(opensshKeyMagic):], &h); err != nil || h.NumKeys != 1 {
		return nil
	}
	// A copy: ParsePublicKey keeps slices of its input, and block.Bytes is
	// cleared on return.
	pub, err := ssh.ParsePublicKey(bytes.Clone(h.PubKey))
	if err != nil {
		return nil
	}
	return pub
}

// refuseMachineKeyType refuses, before any passphrase prompt, a key that
// can never renew from a file: an sk key (a security key signs only
// through ssh-agent, OQ-2 of 03-11, T-03-406), then RSA.
func refuseMachineKeyType(pub ssh.PublicKey, path string) error {
	switch pub.Type() {
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return fmt.Errorf("--key %s is a security key (%s), which signs only through ssh-agent: load it with ssh-add, then run with --agent-key %s, "+
			"which asks for a touch at every renewal; unattended renewal needs an Ed25519 or ECDSA key; nothing was sent",
			path, pub.Type(), ssh.FingerprintSHA256(pub))
	case ssh.KeyAlgoRSA:
		return fmt.Errorf("--key %s: RSA keys are not machine keys; use an Ed25519 or ECDSA key; nothing was sent", path)
	}
	return nil
}

// machineKey is a parsed machine key file: its signer and the secrets the
// caller clears after signing.
type machineKey struct {
	signer ssh.Signer
	ed     ed25519.PrivateKey // nil for ECDSA, whose big integers Go cannot clear reliably
	pass   []byte
}

// wipe clears the file buffer raw, the passphrase and the Ed25519 private
// key, then calls machineKeyBufferHook.
func (k *machineKey) wipe(raw []byte) {
	clear(raw)
	clear(k.pass)
	clear(k.ed)
	if machineKeyBufferHook != nil {
		machineKeyBufferHook(raw, k.pass, k.ed)
	}
}

// errNotMachineKeyFile is a file that parses as no private key. It never
// echoes a byte of the file.
func errNotMachineKeyFile(path string) error {
	return fmt.Errorf("--key %s is not an OpenSSH or PEM private key; nothing was sent", path)
}

// parseMachineKey parses raw, the contents of the key file at path (03-11b,
// F11, T-03-74, T-03-244, PD6). The sk and RSA refusals come first, read
// from the clear header, so an encrypted sk file never prompts. A
// passphrase is read only when the file is encrypted: from fd when fd >= 0,
// otherwise from a terminal, and never from a stdin that is not one. It
// accepts Ed25519 and ECDSA keys only. No error carries key or passphrase
// bytes. The caller calls wipe after signing; on an error the secrets are
// already cleared.
func parseMachineKey(raw []byte, path string, fd int) (*machineKey, error) {
	if pub := machineKeyHeaderPub(raw); pub != nil {
		if err := refuseMachineKeyType(pub, path); err != nil {
			return nil, err
		}
	}
	if machineKeyParseHook != nil {
		machineKeyParseHook()
	}
	k := &machineKey{}
	key, err := ssh.ParseRawPrivateKey(raw)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if fd < 0 && !stdinIsTerminal() {
			return nil, fmt.Errorf("--key %s is encrypted and stdin is not a terminal: pass the passphrase on an inherited descriptor with --passphrase-fd N; nothing was sent", path)
		}
		k.pass, err = rootceremony.ReadPassphrase(fd, "Passphrase for "+path+": ", false)
		if err != nil {
			return nil, err
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(raw, k.pass)
		if errors.Is(err, x509.IncorrectPasswordError) {
			clear(k.pass)
			return nil, fmt.Errorf("the passphrase for %s is wrong; nothing was sent", path)
		}
	}
	if err != nil {
		clear(k.pass)
		return nil, errNotMachineKeyFile(path)
	}
	switch v := key.(type) {
	case *ed25519.PrivateKey:
		k.ed = *v
	case ed25519.PrivateKey:
		k.ed = v
	case *ecdsa.PrivateKey:
	case *rsa.PrivateKey:
		clear(k.pass)
		return nil, fmt.Errorf("--key %s: RSA keys are not machine keys; use an Ed25519 or ECDSA key; nothing was sent", path)
	default:
		clear(k.pass)
		return nil, fmt.Errorf("--key %s is not an Ed25519 or ECDSA private key; nothing was sent", path)
	}
	signerKey := key
	if k.ed != nil {
		signerKey = k.ed
	}
	if k.signer, err = ssh.NewSignerFromKey(signerKey); err != nil {
		clear(k.ed)
		clear(k.pass)
		return nil, errNotMachineKeyFile(path)
	}
	return k, nil
}
