package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
)

// maxMachineKeyFileBytes bounds the private key file keyroster machine
// renew reads (03-11b): an OpenSSH private key file is a few KiB at most.
const maxMachineKeyFileBytes = 64 << 10

// readMachineKeyFile reads the machine's private key file at path: a
// regular file of at most maxMachineKeyFileBytes, refused as
// key_file_too_large before any byte of it is parsed. The caller clears
// the returned buffer when it is done with it.
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

// errMachineKeyFile is a key file that is not an unencrypted Ed25519
// private key. It never echoes a byte of the file.
var errMachineKeyFile = errors.New("is not an unencrypted Ed25519 private key")

// machineFileSigner parses data, the contents of the key file at path, as
// an unencrypted Ed25519 private key and returns its signer and a function
// that clears the private key's bytes.
func machineFileSigner(path string, data []byte) (ssh.Signer, func(), error) {
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("--key %s %w; nothing was sent", path, errMachineKeyFile)
	}
	k, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("--key %s %w; nothing was sent", path, errMachineKeyFile)
	}
	s, err := ssh.NewSignerFromKey(*k)
	if err != nil {
		clear(*k)
		return nil, nil, fmt.Errorf("--key %s %w; nothing was sent", path, errMachineKeyFile)
	}
	return s, func() { clear(*k) }, nil
}
