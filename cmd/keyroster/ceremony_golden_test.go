package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// updateGolden rewrites the ceremony golden files from the current output
// (03-14b). It is for a deliberate output change only, never with a mutant
// applied: a regenerated golden must show only added lines in its diff.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/ceremony/*.golden from the current output (a deliberate output change only, never with a mutant applied)")

// The fixed installation ID of the fixture's bundle in force, which every
// successor carries (03-14b).
const goldenInstallationID = "00112233445566778899aabbccddeeff"

// seedKey returns the Ed25519 key with seed byte n repeated, as
// internal/trust's edKey does (03-14b).
func seedKey(n byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
}

// seedPub returns seedKey(n)'s public key in canonical form.
func seedPub(t *testing.T, n byte) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(seedKey(n).Public())
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(pub)
}

// goldenFixture is a fixed, seeded ceremony (03-14b): roots A (seed 1,
// software) and B (seed 2, piv) at threshold 2, the public CA, ops and log
// keys of test/vectors/bundle_genesis_v1.json, and a bundle in force in
// prev/ that A and B signed, with policy_genesis_v1.json as its policy.
type goldenFixture struct {
	dir, prev, prevSHA, roots, caPubkeys string
	fpA, fpB                             string
	genesisPolicy                        []byte
}

func readGoldenVector(t *testing.T, name string) []byte {
	t.Helper()
	return readTestFile(t, filepath.Join("..", "..", "test", "vectors", name))
}

func newGoldenFixture(t *testing.T) *goldenFixture {
	t.Helper()
	rootA, rootB := seedKey(1), seedKey(2)
	useKeyring(t, rootA, rootB)
	f := &goldenFixture{dir: t.TempDir(), fpA: keyFingerprint(t, rootA), fpB: keyFingerprint(t, rootB)}
	f.genesisPolicy = readGoldenVector(t, "policy_genesis_v1.json")
	vector, err := trust.ParseBundle(readGoldenVector(t, "bundle_genesis_v1.json"))
	if err != nil {
		t.Fatal(err)
	}

	// ca-pubkeys.json: the vector's online public keys, in CAPubKeyRoles order.
	cas := &trust.CAPubKeys{}
	for _, ca := range vector.CAs {
		cas.Keys = append(cas.Keys, trust.CAPubKey{Role: ca.Role, Key: ca.Key, Alg: ca.Alg, Custody: ca.Custody})
	}
	cas.Keys = append(cas.Keys,
		trust.CAPubKey{Role: "ops", Key: vector.OpsKey.Key, Alg: vector.OpsKey.Alg, Custody: vector.OpsKey.Custody},
		trust.CAPubKey{Role: "log", Key: vector.Log.Key, Alg: vector.Log.Alg, Custody: vector.Log.Custody})
	casData, err := cas.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	f.caPubkeys = filepath.Join(f.dir, "ca-pubkeys.json")
	writeTestFile(t, f.caPubkeys, casData)

	pubA, pubB := seedPub(t, 1), seedPub(t, 2)
	f.roots = filepath.Join(f.dir, "roots.pub")
	writeTestFile(t, f.roots, []byte(pubA+" custody=software\n"+pubB+" custody=piv\n"))

	// The bundle in force, signed by A and B.
	prev := *vector
	prev.Version = 1
	prev.Prev = trust.GenesisPrev
	prev.IssuedAt = "2026-10-05T00:00:00Z"
	prev.Root = trust.RootSet{Keys: []trust.RootKey{{Key: pubA, Custody: "software"}, {Key: pubB, Custody: "piv"}}, Threshold: 2}
	prev.PolicySHA256 = trust.SHA256Hex(f.genesisPolicy)
	prev.InstallationID = goldenInstallationID
	if err := prev.Validate(); err != nil {
		t.Fatal(err)
	}
	prevData, err := prev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	f.prev = filepath.Join(f.dir, "prev")
	if err := os.MkdirAll(f.prev, 0o750); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(f.prev, "bundle.json"), prevData)
	writeTestFile(t, filepath.Join(f.prev, "policy.json"), f.genesisPolicy)
	signGoldenDocs(t, f.prev, rootA, rootB)
	f.prevSHA = trust.SHA256Hex(prevData)
	return f
}

// signGoldenDocs signs dir's bundle.json and policy.json with each key and
// appends the signatures to their .sigs files.
func signGoldenDocs(t *testing.T, dir string, keys ...ed25519.PrivateKey) {
	t.Helper()
	for _, doc := range []struct{ file, ns string }{{"bundle.json", trust.NamespaceBundle}, {"policy.json", trust.NamespacePolicy}} {
		msg := readTestFile(t, filepath.Join(dir, doc.file))
		for _, k := range keys {
			s, err := ssh.NewSignerFromKey(k)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := sshsig.Sign(rand.Reader, s, doc.ns, msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := appendSignature(filepath.Join(dir, doc.file+".sigs"), sig); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// writePolicy writes, from policy_genesis_v1.json, a canonical policy edited
// by edit, and returns its path. successor makes it version 2 chained to the
// policy in force; otherwise it stays a genesis policy (version 1).
func (f *goldenFixture) writePolicy(t *testing.T, name string, successor bool, edit func(p *trust.Policy)) string {
	t.Helper()
	p, err := trust.ParsePolicy(f.genesisPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if successor {
		p.Version = 2
		p.Prev = trust.SHA256Hex(f.genesisPolicy)
	}
	if edit != nil {
		edit(p)
	}
	data, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.ParsePolicy(data); err != nil {
		t.Fatalf("policy %s: %v", name, err)
	}
	path := filepath.Join(f.dir, name+".json")
	writeTestFile(t, path, data)
	return path
}

// display runs root sign --prev with a wrong confirmation: it requires exit
// 1 with "nothing was signed" and returns stdout, the display a custodian
// reads before confirming.
func (f *goldenFixture) display(t *testing.T, policy, out, fp string) string {
	t.Helper()
	code, stdout, stderr := run(t, "root", "sign", "--prev", f.prev, "--prev-sha256", f.prevSHA, "--roots", f.roots, "--threshold", "2",
		"--policy", policy, "--out-dir", out, "--agent-key", fp, "--confirm", "00000000")
	if code != 1 || !strings.Contains(stderr, "nothing was signed") {
		t.Fatalf("root sign --prev with a wrong confirmation: exit %d: %s", code, stderr)
	}
	return stdout
}

// signWith runs root sign --prev confirmed with the prefix of out's
// bundle.json, and requires exit 0.
func (f *goldenFixture) signWith(t *testing.T, policy, out, fp string) {
	t.Helper()
	confirm := fileSHA256(t, filepath.Join(out, "bundle.json"))[:8]
	code, _, stderr := run(t, "root", "sign", "--prev", f.prev, "--prev-sha256", f.prevSHA, "--roots", f.roots, "--threshold", "2",
		"--policy", policy, "--out-dir", out, "--agent-key", fp, "--confirm", confirm)
	if code != 0 {
		t.Fatalf("root sign --prev by %s: exit %d: %s", fp, code, stderr)
	}
}

// verifyPrev runs trust verify --prev on out, requires exit 0 and returns
// stdout.
func (f *goldenFixture) verifyPrev(t *testing.T, out string) string {
	t.Helper()
	code, stdout, stderr := run(t, "trust", "verify", "--prev", f.prev, "--prev-sha256", f.prevSHA, "--pin", f.fpA, "--pin", f.fpB, "--threshold", "2",
		"--bundle", filepath.Join(out, "bundle.json"), "--policy", filepath.Join(out, "policy.json"))
	if code != 0 {
		t.Fatalf("trust verify --prev: exit %d: %s", code, stderr)
	}
	return stdout
}

// checkGolden compares got with testdata/ceremony/<name>.golden byte for
// byte. With -update-golden and write set, it rewrites the file instead.
func checkGolden(t *testing.T, name, got string, write bool) {
	t.Helper()
	path := filepath.Join("testdata", "ceremony", name+".golden")
	if *updateGolden && write {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, path, []byte(got))
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed test file
	if err != nil {
		t.Errorf("golden %s.golden: %v", name, err)
		return
	}
	if string(want) == got {
		return
	}
	wl, gl := strings.Split(string(want), "\n"), strings.Split(got, "\n")
	n := 0
	for n < len(wl) && n < len(gl) && wl[n] == gl[n] {
		n++
	}
	line := func(l []string) string {
		if n < len(l) {
			return l[n]
		}
		return "<end of output>"
	}
	t.Errorf("golden %s.golden: first difference at line %d\nwant: %q\ngot:  %q\nwhole output:\n%s", name, n+1, line(wl), line(gl), got)
}

// The kinds of output checkInvariants knows.
const (
	kindSuccessorRootSign    = "successor root_sign"
	kindSuccessorTrustVerify = "successor trust_verify"
	kindGenesis              = "genesis"
)

// checkInvariants checks the display's structure without reading any golden
// (03-14b), so a regenerated golden cannot confirm a broken layout. Each
// broken rule is a t.Errorf starting "invariant:".
func checkInvariants(t *testing.T, kind, got string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	first := func(prefix string) int {
		for i, l := range lines {
			if strings.HasPrefix(l, prefix) {
				return i
			}
		}
		return -1
	}
	count := func(prefix string) int {
		n := 0
		for _, l := range lines {
			if strings.HasPrefix(l, prefix) {
				n++
			}
		}
		return n
	}

	// Exactly one summary pop line, between the summary's webauthn line and
	// its timelock line. The block's own "  webauthn:" field line comes
	// later, so the first webauthn line is the summary's.
	pops, pop := 0, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "  pop: none (") || strings.HasPrefix(l, "  pop hosts=") {
			pops++
			pop = i
		}
	}
	webauthn, timelock := first("  webauthn"), first("  timelock ")
	if pops != 1 {
		t.Errorf("invariant: %d summary pop lines, want exactly 1", pops)
	} else if webauthn < 0 || timelock < 0 || pop < webauthn || pop > timelock {
		t.Errorf("invariant: the summary pop line (line %d) is not between the first webauthn line (%d) and the first timelock line (%d)", pop+1, webauthn+1, timelock+1)
	}

	// Exactly one installation id line (03-14c, render-05): root sign's and
	// trust verify's alike, after the Bundle SHA-256 line, and before the
	// policy block and the first signer line where the output has them.
	inst, sha, signedBy, policyAt := first("installation id: "), first("Bundle SHA-256:"), first("signed by "), first("Policy in force:")
	switch {
	case count("installation id: ") != 1:
		t.Errorf("invariant: %d \"installation id: \" lines, want exactly 1", count("installation id: "))
	case sha < 0 || inst < sha:
		t.Errorf("invariant: the installation id line (line %d) does not follow the Bundle SHA-256 line (%d)", inst+1, sha+1)
	case policyAt >= 0 && inst > policyAt, signedBy >= 0 && inst > signedBy:
		t.Errorf("invariant: the installation id line (line %d) is not before the policy block (%d) and the first signer line (%d)", inst+1, policyAt+1, signedBy+1)
	}

	block := first("Policy in force:")
	switch kind {
	case kindSuccessorRootSign:
		if n := count("Policy in force:"); n != 1 {
			t.Errorf("invariant: %d \"Policy in force:\" lines, want exactly 1", n)
			return
		}
		if inst := first("installation id:"); inst < 0 || block < inst {
			t.Errorf("invariant: the policy block (line %d) does not follow the installation id line (%d)", block+1, inst+1)
		}
		for i := block; i < len(lines); i++ {
			l := lines[i]
			if !strings.HasPrefix(l, "Policy in force:") && !strings.HasPrefix(l, "Successor policy:") &&
				!strings.HasPrefix(l, "WARNING:") && !strings.HasPrefix(l, "  ") {
				t.Errorf("invariant: line %d %q after the policy block's start is not a block line; the block must be the last thing before the prompt", i+1, l)
			}
		}
	case kindSuccessorTrustVerify:
		if n := count("Policy in force:"); n != 1 {
			t.Errorf("invariant: %d \"Policy in force:\" lines, want exactly 1", n)
			return
		}
		sha, signed := first("Bundle SHA-256:"), first("signed by ")
		if sha < 0 || signed < 0 || block < sha || block > signed {
			t.Errorf("invariant: the policy block (line %d) is not between the Bundle SHA-256 line (%d) and the first signer line (%d)", block+1, sha+1, signed+1)
		}
	case kindGenesis:
		if n := count("Policy in force:"); n != 0 {
			t.Errorf("invariant: a genesis output has %d \"Policy in force:\" lines, want none", n)
		}
	default:
		t.Fatalf("checkInvariants: unknown kind %q", kind)
	}
}

// checkCeremony is every TestCeremonyGolden leaf: the invariants, then always
// the golden.
func checkCeremony(t *testing.T, kind, golden, got string, write bool) {
	t.Helper()
	checkInvariants(t, kind, got)
	checkGolden(t, golden, got, write)
}

// TestCeremonyGolden pins, byte for byte, what root sign and trust verify
// print on a fixed, seeded ceremony (03-14b, F04, F14): the summary with its
// pop line, and for a successor the policy block, the last thing before root
// sign's prompt and after trust verify's summary. Each group's body runs its
// commands in order; its leaves only assert, so each runs alone under -run.
// The subtests are not parallel: they share the ceremony clock and agent.
func TestCeremonyGolden(t *testing.T) {
	rp := func(p *trust.Policy) {
		p.WebAuthn = &trust.WebAuthnRP{RPID: "keyroster.example.org", Origins: []string{"https://keyroster.example.org"}}
	}

	t.Run("successor_unchanged", func(t *testing.T) {
		f := newGoldenFixture(t)
		setCeremonyNow(t, "2026-10-06T00:00:00Z")
		pol, out := filepath.Join(f.prev, "policy.json"), filepath.Join(f.dir, "out")
		rs := f.display(t, pol, out, f.fpA)
		f.signWith(t, pol, out, f.fpA)
		f.signWith(t, pol, out, f.fpB)
		tv := f.verifyPrev(t, out)
		t.Run("root_sign", func(t *testing.T) {
			checkCeremony(t, kindSuccessorRootSign, "successor_unchanged.root_sign", rs, true)
		})
		t.Run("trust_verify", func(t *testing.T) {
			checkCeremony(t, kindSuccessorTrustVerify, "successor_unchanged.trust_verify", tv, true)
		})
	})

	t.Run("successor_rp_only", func(t *testing.T) {
		f := newGoldenFixture(t)
		setCeremonyNow(t, "2026-10-06T00:00:00Z")
		pol, out := f.writePolicy(t, "rp_only", true, rp), filepath.Join(f.dir, "out")
		rs := f.display(t, pol, out, f.fpA)
		t.Run("root_sign", func(t *testing.T) {
			checkCeremony(t, kindSuccessorRootSign, "successor_rp_only.root_sign", rs, true)
		})
	})

	t.Run("successor_added_admin", func(t *testing.T) {
		f := newGoldenFixture(t)
		setCeremonyNow(t, "2026-10-06T00:00:00Z")
		pol := f.writePolicy(t, "added_admin", true, func(p *trust.Policy) {
			rp(p)
			p.Admins = append(p.Admins, trust.AdminKey{Name: "mallory", Key: seedPub(t, 21)})
			p.CAProfiles[0].MaxTTLSeconds = 2592000
		})
		out := filepath.Join(f.dir, "out")
		rs := f.display(t, pol, out, f.fpA)
		f.signWith(t, pol, out, f.fpA)
		// A co-signer in the out-dir that now holds the bundle and A's
		// signatures (prepareBundle's existing-bundle branch).
		co := f.display(t, pol, out, f.fpB)
		f.signWith(t, pol, out, f.fpB)
		tv := f.verifyPrev(t, out)
		t.Run("root_sign", func(t *testing.T) {
			checkCeremony(t, kindSuccessorRootSign, "successor_added_admin.root_sign", rs, true)
		})
		t.Run("cosigner", func(t *testing.T) {
			checkCeremony(t, kindSuccessorRootSign, "successor_added_admin.root_sign", co, false)
		})
		t.Run("trust_verify", func(t *testing.T) {
			checkCeremony(t, kindSuccessorTrustVerify, "successor_added_admin.trust_verify", tv, true)
		})
	})

	t.Run("successor_every_field", func(t *testing.T) {
		f := newGoldenFixture(t)
		setCeremonyNow(t, "2026-10-06T00:00:00Z")
		pol := f.writePolicy(t, "every_field", true, func(p *trust.Policy) {
			p.AdminQuorum = 2
			p.Admins = []trust.AdminKey{
				{Name: "carol", Key: seedPub(t, 20)},
				{Name: "mallory", Key: seedPub(t, 21)},
				{Name: "bob", Key: seedPub(t, 22)},
			}
			p.CAProfiles[0].MaxTTLSeconds = 3600
			p.CAProfiles[0].AllowedExtensions = []string{"permit-agent-forwarding"}
			p.CAProfiles[0].AllowedCriticalOptions = []string{"force-command"}
			p.CAProfiles[1].MaxTTLSeconds = 604800
			p.CAProfiles[2].DefaultExtensions = []string{}
			p.TimelockSeconds = 3600
			rp(p)
			p.PoP = &trust.PoPPolicy{Hosts: true, Machines: false}
		})
		rs := f.display(t, pol, filepath.Join(f.dir, "out"), f.fpA)
		t.Run("root_sign", func(t *testing.T) {
			checkCeremony(t, kindSuccessorRootSign, "successor_every_field.root_sign", rs, true)
		})
	})

	t.Run("successor_pop", func(t *testing.T) {
		f := newGoldenFixture(t)
		setCeremonyNow(t, "2026-10-06T00:00:00Z")
		pol := f.writePolicy(t, "pop", true, func(p *trust.Policy) {
			p.PoP = &trust.PoPPolicy{Hosts: true, Machines: true}
		})
		out := filepath.Join(f.dir, "out")
		rs := f.display(t, pol, out, f.fpA)
		f.signWith(t, pol, out, f.fpA)
		f.signWith(t, pol, out, f.fpB)
		tv := f.verifyPrev(t, out)
		t.Run("root_sign", func(t *testing.T) {
			checkCeremony(t, kindSuccessorRootSign, "successor_pop.root_sign", rs, true)
		})
		t.Run("trust_verify", func(t *testing.T) {
			checkCeremony(t, kindSuccessorTrustVerify, "successor_pop.trust_verify", tv, true)
		})
	})

	t.Run("genesis_pop", func(t *testing.T) {
		f := newGoldenFixture(t)
		setCeremonyNow(t, "2026-10-05T00:00:00Z")
		pol := f.writePolicy(t, "genesis_pop", false, func(p *trust.Policy) {
			p.PoP = &trust.PoPPolicy{Hosts: true, Machines: false}
		})
		out := filepath.Join(f.dir, "out")
		gsign := func(fp, confirm string) (int, string, string) {
			return run(t, "root", "sign", "--ca-pubkeys", f.caPubkeys, "--policy", pol, "--roots", f.roots, "--threshold", "2",
				"--out-dir", out, "--agent-key", fp, "--confirm", confirm)
		}
		code, rs, stderr := gsign(f.fpA, "00000000")
		if code != 1 || !strings.Contains(stderr, "nothing was signed") {
			t.Fatalf("genesis root sign with a wrong confirmation: exit %d: %s", code, stderr)
		}
		bundlePath := filepath.Join(out, "bundle.json")
		confirm := fileSHA256(t, bundlePath)[:8]
		for _, fp := range []string{f.fpA, f.fpB} {
			if code, _, stderr := gsign(fp, confirm); code != 0 {
				t.Fatalf("genesis root sign by %s: exit %d: %s", fp, code, stderr)
			}
		}
		code, tv, stderr := run(t, "trust", "verify", "--pin", f.fpA, "--pin", f.fpB, "--threshold", "2",
			"--bundle", bundlePath, "--policy", filepath.Join(out, "policy.json"))
		if code != 0 {
			t.Fatalf("trust verify: exit %d: %s", code, stderr)
		}
		// The fresh installation ID and so the bundle hash differ per run.
		b, err := trust.ParseBundle(readTestFile(t, bundlePath))
		if err != nil {
			t.Fatal(err)
		}
		norm := strings.NewReplacer(fileSHA256(t, bundlePath), "<BUNDLE_SHA256>", b.InstallationID, "<INSTALLATION_ID>")
		rs, tv = norm.Replace(rs), norm.Replace(tv)
		t.Run("root_sign", func(t *testing.T) {
			checkCeremony(t, kindGenesis, "genesis_pop.root_sign", rs, true)
		})
		t.Run("trust_verify", func(t *testing.T) {
			checkCeremony(t, kindGenesis, "genesis_pop.trust_verify", tv, true)
		})
	})
}
