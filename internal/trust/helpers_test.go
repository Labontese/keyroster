package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Fixed test keys: deterministic, so the golden vectors are reproducible.
// They are test fixtures only and never trusted outside tests.

// edKey returns the Ed25519 signer with seed byte n repeated.
func edKey(t testing.TB, n byte) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// p256Key returns the ECDSA P-256 signer whose scalar is
// SHA-256("keyroster-test-p256" || n).
func p256Key(t testing.TB, n byte) ssh.Signer {
	t.Helper()
	d := sha256.Sum256(append([]byte("keyroster-test-p256"), n))
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keyOf(s ssh.Signer) string { return FormatKey(s.PublicKey()) }

// Seeds of the golden fixture keys.
const (
	seedRootA   = 1
	seedRootB   = 2
	seedUserCA  = 10
	seedHostCA  = 11
	seedMachCA  = 12
	seedOps     = 13
	seedLog     = 14
	seedAdmin   = 20
	goldenIssue = "2026-10-05T00:00:00Z"
)

// goldenPolicy is the genesis policy of test/vectors/policy_genesis_v1.json.
func goldenPolicy(t testing.TB) *Policy {
	t.Helper()
	return &Policy{
		Version:     1,
		Prev:        GenesisPrev,
		AdminQuorum: 1,
		Admins:      []AdminKey{{Name: "alice", Key: keyOf(edKey(t, seedAdmin))}},
		CAProfiles: []CAProfile{
			{Role: RoleUser, MaxTTLSeconds: 43200, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: RoleHost, MaxTTLSeconds: 2592000, DefaultExtensions: []string{}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
		},
		TimelockSeconds: 0,
	}
}

// goldenBundle is the genesis bundle of test/vectors/bundle_genesis_v1.json
// for the given policy bytes: two roots (Ed25519 software, P-256 PIV),
// threshold 1, P-256 CAs, ops and log keys in vTPM custody (D-09).
func goldenBundle(t testing.TB, policy []byte) *Bundle {
	t.Helper()
	logKey := p256Key(t, seedLog)
	ca := func(role string, seed byte) CAEntry {
		return CAEntry{Role: role, Key: keyOf(p256Key(t, seed)), Alg: ssh.KeyAlgoECDSA256, Custody: "vtpm", State: "active", Generation: 1}
	}
	return &Bundle{
		Version:  1,
		Prev:     GenesisPrev,
		IssuedAt: goldenIssue,
		Root: RootSet{
			Keys: []RootKey{
				{Key: keyOf(edKey(t, seedRootA)), Custody: "software"},
				{Key: keyOf(p256Key(t, seedRootB)), Custody: "piv"},
			},
			Threshold: 1,
		},
		CAs:          []CAEntry{ca(RoleUser, seedUserCA), ca(RoleHost, seedHostCA), ca(RoleMachine, seedMachCA)},
		OpsKey:       KeyEntry{Key: keyOf(p256Key(t, seedOps)), Alg: ssh.KeyAlgoECDSA256, Custody: "vtpm"},
		Log:          LogEntry{Key: keyOf(logKey), Alg: ssh.KeyAlgoECDSA256, Custody: "vtpm", Origin: LogOrigin(logKey.PublicKey())},
		PolicySHA256: SHA256Hex(policy),
	}
}

// mustCanonical returns v's canonical bytes.
func mustCanonical(t testing.TB, v any) []byte {
	t.Helper()
	b, err := canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
