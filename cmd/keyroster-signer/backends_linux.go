//go:build linux

package main

// Keystore backends linked into the signer. Each registers itself by name.
import (
	_ "github.com/Labontese/keyroster/internal/keystore/agent"
	_ "github.com/Labontese/keyroster/internal/keystore/tpm"
)
