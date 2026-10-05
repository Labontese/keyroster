// Package trust defines keyroster's root-signed trust anchor: the trust
// bundle (root set, CA keys, ops and log keys, policy hash) and the policy
// (admin keys, quorum, CA profiles), both canonical JSON with detached
// SSHSIG signatures by the root keys, and their verification against
// operator-pinned root fingerprints (KEY-07, D-01, D-09, D-13).
//
// Trust anchors never come from the document being verified: a genesis
// bundle is checked against the fingerprints the operator pins, and a
// successor against the previously accepted bundle (TUF rule).
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// NamespaceBundle is the SSHSIG namespace of root signatures over a trust
// bundle. A signature under one namespace never verifies under another
// (NamespacePolicy is in policy.go).
const NamespaceBundle = "keyroster/trust-bundle/v1"

// GenesisPrev is the prev hash of a version 1 bundle or policy.
const GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

// LogOriginPrefix starts every keyroster log origin (same rule as
// internal/tlog.Origin; the two are cross-checked by the signer in 01-07).
const LogOriginPrefix = "keyroster/log/"

// CA roles, in the fixed order the bundle lists them.
const (
	RoleUser    = "user"
	RoleHost    = "host"
	RoleMachine = "machine"
)

var caRoles = []string{RoleUser, RoleHost, RoleMachine}

// Validation errors. Each refusal class has its own error so tests and
// operators can tell them apart.
var (
	ErrInvalid      = errors.New("trust: invalid document")
	ErrKeyIsRoot    = errors.New("trust: a CA, ops or log key equals a root key")
	ErrDuplicateKey = errors.New("trust: the same key appears twice")
	ErrAlgorithm    = errors.New("trust: algorithm not allowed or not the key's type")
	ErrCustody      = errors.New("trust: custody value not allowed")
	ErrCARole       = errors.New("trust: CA roles missing or out of order")
	ErrActiveCA     = errors.New("trust: a CA role must have exactly one active key")
	ErrLogOrigin    = errors.New("trust: log origin does not match the log key")
)

// Bundle is the root-signed trust bundle.
type Bundle struct {
	Version      uint64    `json:"version"`
	Prev         string    `json:"prev"`
	IssuedAt     string    `json:"issued_at"`
	Root         RootSet   `json:"root"`
	CAs          []CAEntry `json:"cas"`
	OpsKey       KeyEntry  `json:"ops_key"`
	Log          LogEntry  `json:"log"`
	PolicySHA256 string    `json:"policy_sha256"`
}

// RootSet is the set of root keys and how many of them must sign.
type RootSet struct {
	Keys      []RootKey `json:"keys"`
	Threshold uint32    `json:"threshold"`
}

// RootKey is one root public key and where its private half lives.
type RootKey struct {
	Key     string `json:"key"`
	Custody string `json:"custody"`
}

// CAEntry is one CA key generation for a role.
type CAEntry struct {
	Role       string `json:"role"`
	Key        string `json:"key"`
	Alg        string `json:"alg"`
	Custody    string `json:"custody"`
	State      string `json:"state"`
	Generation uint32 `json:"generation"`
}

// KeyEntry is a non-CA online key (the ops key, the KRL authority used from
// Phase 3).
type KeyEntry struct {
	Key     string `json:"key"`
	Alg     string `json:"alg"`
	Custody string `json:"custody"`
}

// LogEntry is the audit-log checkpoint key and its log origin.
type LogEntry struct {
	Key     string `json:"key"`
	Alg     string `json:"alg"`
	Custody string `json:"custody"`
	Origin  string `json:"origin"`
}

// Allowed values (D-09, D-11).
var (
	onlineAlgs    = set(ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256)
	rootKeyTypes  = set(ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoSKECDSA256)
	rootCustody   = set("software", "fido", "piv", "pkcs11")
	onlineCustody = set("agent", "pkcs11-agent", "tpm", "vtpm", "piv", "software")
	caStates      = set("active", "next", "retired")
)

func set(vs ...string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

// ParseBundle decodes a canonical bundle and validates it.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := decodeStrict(data, &b); err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Canonical returns the canonical encoding of b (the bytes roots sign).
func (b *Bundle) Canonical() ([]byte, error) { return canonical(b) }

// Validate checks every structural rule of a bundle. It does not check
// signatures, pins or the policy hash against a policy document.
func (b *Bundle) Validate() error {
	if b.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", ErrInvalid)
	}
	if !isHash(b.Prev) {
		return fmt.Errorf("%w: prev must be 64 lowercase hex digits", ErrInvalid)
	}
	if b.Version == 1 && b.Prev != GenesisPrev {
		return fmt.Errorf("%w: a version 1 bundle must have an all-zero prev", ErrInvalid)
	}
	if err := checkTimestamp(b.IssuedAt); err != nil {
		return err
	}
	if !isHash(b.PolicySHA256) {
		return fmt.Errorf("%w: policy_sha256 must be 64 lowercase hex digits", ErrInvalid)
	}
	rootKeys, err := b.Root.validate()
	if err != nil {
		return err
	}
	seen := map[string]string{} // wire encoding -> where it was used
	for _, k := range rootKeys {
		seen[string(k.Marshal())] = "root"
	}
	use := func(where string, pub ssh.PublicKey) error {
		if prior, ok := seen[string(pub.Marshal())]; ok {
			if prior == "root" {
				return fmt.Errorf("%w: %s (%s)", ErrKeyIsRoot, where, ssh.FingerprintSHA256(pub))
			}
			return fmt.Errorf("%w: %s and %s (%s)", ErrDuplicateKey, prior, where, ssh.FingerprintSHA256(pub))
		}
		seen[string(pub.Marshal())] = where
		return nil
	}

	if b.CAs == nil {
		return fmt.Errorf("%w: cas must be an array", ErrCARole)
	}
	roleIdx := -1
	var lastGen uint32
	active := map[string]int{}
	for i, ca := range b.CAs {
		where := fmt.Sprintf("cas[%d] (%s)", i, ca.Role)
		idx := indexOf(caRoles, ca.Role)
		if idx < 0 {
			return fmt.Errorf("%w: %s: unknown role %q", ErrCARole, where, ca.Role)
		}
		if idx < roleIdx || (idx == roleIdx && ca.Generation <= lastGen) {
			return fmt.Errorf("%w: %s: entries must be ordered user, host, machine, then by increasing generation", ErrCARole, where)
		}
		roleIdx, lastGen = idx, ca.Generation
		if ca.Generation < 1 {
			return fmt.Errorf("%w: %s: generation must be >= 1", ErrInvalid, where)
		}
		if !caStates[ca.State] {
			return fmt.Errorf("%w: %s: state %q (want active, next or retired)", ErrInvalid, where, ca.State)
		}
		if ca.State == "active" {
			active[ca.Role]++
		}
		pub, err := checkOnlineKey(where, ca.Key, ca.Alg, ca.Custody)
		if err != nil {
			return err
		}
		if err := use(where, pub); err != nil {
			return err
		}
	}
	for _, role := range caRoles {
		if active[role] != 1 {
			if active[role] == 0 && !hasRole(b.CAs, role) {
				return fmt.Errorf("%w: no CA for role %s", ErrCARole, role)
			}
			return fmt.Errorf("%w: role %s has %d active keys", ErrActiveCA, role, active[role])
		}
	}

	ops, err := checkOnlineKey("ops_key", b.OpsKey.Key, b.OpsKey.Alg, b.OpsKey.Custody)
	if err != nil {
		return err
	}
	if err := use("ops_key", ops); err != nil {
		return err
	}
	logKey, err := checkOnlineKey("log", b.Log.Key, b.Log.Alg, b.Log.Custody)
	if err != nil {
		return err
	}
	if err := use("log", logKey); err != nil {
		return err
	}
	if b.Log.Origin != LogOrigin(logKey) {
		return fmt.Errorf("%w: %q, want %q", ErrLogOrigin, b.Log.Origin, LogOrigin(logKey))
	}
	return nil
}

// validate checks the root set and returns the parsed root keys.
func (r *RootSet) validate() ([]ssh.PublicKey, error) {
	if len(r.Keys) == 0 {
		return nil, fmt.Errorf("%w: the root set is empty", ErrInvalid)
	}
	if r.Threshold < 1 || int(r.Threshold) > len(r.Keys) {
		return nil, fmt.Errorf("%w: root threshold %d with %d root keys", ErrInvalid, r.Threshold, len(r.Keys))
	}
	keys := make([]ssh.PublicKey, 0, len(r.Keys))
	seen := map[string]bool{}
	for i, rk := range r.Keys {
		where := fmt.Sprintf("root.keys[%d]", i)
		pub, err := ParseKey(rk.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalid, where, err)
		}
		if !rootKeyTypes[pub.Type()] {
			return nil, fmt.Errorf("%w: %s: root key type %s", ErrAlgorithm, where, pub.Type())
		}
		if err := checkRootCustody(pub, rk.Custody); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if seen[string(pub.Marshal())] {
			return nil, fmt.Errorf("%w: %s repeats a root key", ErrDuplicateKey, where)
		}
		seen[string(pub.Marshal())] = true
		keys = append(keys, pub)
	}
	return keys, nil
}

// checkRootCustody requires custody fido exactly for security-key (sk-*)
// root keys.
func checkRootCustody(pub ssh.PublicKey, custody string) error {
	if !rootCustody[custody] {
		return fmt.Errorf("%w: root custody %q (want software, fido, piv or pkcs11)", ErrCustody, custody)
	}
	isSK := strings.HasPrefix(pub.Type(), "sk-")
	if isSK != (custody == "fido") {
		return fmt.Errorf("%w: custody fido is for sk-* keys only, and sk-* keys are custody fido (%s, %s)", ErrCustody, pub.Type(), custody)
	}
	return nil
}

// checkOnlineKey checks a CA, ops or log key entry (D-09).
func checkOnlineKey(where, key, alg, custody string) (ssh.PublicKey, error) {
	pub, err := ParseKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalid, where, err)
	}
	if !onlineAlgs[alg] || alg != pub.Type() {
		return nil, fmt.Errorf("%w: %s: alg %q for a %s key (want ssh-ed25519 or ecdsa-sha2-nistp256, matching the key)", ErrAlgorithm, where, alg, pub.Type())
	}
	if !onlineCustody[custody] {
		return nil, fmt.Errorf("%w: %s: custody %q", ErrCustody, where, custody)
	}
	return pub, nil
}

// LogOrigin returns the log origin for a log key: "keyroster/log/" plus the
// first 16 hex digits of the SHA-256 of the key's SSH wire encoding.
func LogOrigin(logKey ssh.PublicKey) string {
	sum := sha256.Sum256(logKey.Marshal())
	return LogOriginPrefix + hex.EncodeToString(sum[:8])
}

// FormatKey returns pub in authorized_keys format without a comment, the
// only key encoding the documents accept.
func FormatKey(pub ssh.PublicKey) string {
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
}

// ParseKey parses a key in the exact form FormatKey writes: no options, no
// comment, no certificate.
func ParseKey(s string) (ssh.PublicKey, error) {
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, err
	}
	if comment != "" || len(options) != 0 || len(rest) != 0 {
		return nil, errors.New("key must be \"<type> <base64>\" without options or comment")
	}
	if _, ok := pub.(*ssh.Certificate); ok {
		return nil, errors.New("certificates are not allowed as keys")
	}
	if FormatKey(pub) != s {
		return nil, errors.New("key is not in canonical \"<type> <base64>\" form")
	}
	return pub, nil
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// checkTimestamp requires RFC 3339 UTC with whole seconds, e.g.
// 2026-10-05T07:00:00Z.
func checkTimestamp(s string) error {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.UTC().Format(TimeFormat) != s {
		return fmt.Errorf("%w: issued_at %q must be RFC 3339 UTC with whole seconds (%s)", ErrInvalid, s, TimeFormat)
	}
	return nil
}

// TimeFormat is the layout of issued_at.
const TimeFormat = "2006-01-02T15:04:05Z"

func indexOf(list []string, v string) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return -1
}

func hasRole(cas []CAEntry, role string) bool {
	for _, ca := range cas {
		if ca.Role == role {
			return true
		}
	}
	return false
}
