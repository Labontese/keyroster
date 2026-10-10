package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestTrustVerifySuccessor (KEY-07) runs trust verify --prev in the homelab
// rotation shape: a genesis bundle by software roots A and B at threshold 1,
// signed by A, and a successor from root sign --prev naming software roots
// C and D at threshold 1. The successor must be a valid successor of the
// bundle in --prev (previous AND new roots' thresholds on both documents),
// and its new root set must be exactly the pins, so the new roots' paper
// fingerprints are checked before the install. The roots are held in an
// in-memory agent (custody=software), so no scrypt run is needed.
func TestTrustVerifySuccessor(t *testing.T) {
	g := newCeremony(t, 2) // roots A, B
	keyC, keyD := newEd25519Key(t), newEd25519Key(t)
	useKeyring(t, append(append([]ed25519.PrivateKey{}, g.rootKeys...), keyC, keyD)...)
	typeHashPrefix(t, g.out)
	if code, _, stderr := g.sign(t, "1", 0); code != 0 {
		t.Fatalf("genesis root sign: exit %d: %s", code, stderr)
	}
	genesis, err := os.ReadFile(filepath.Join(g.out, "bundle.json")) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}

	// The successor documents, unsigned: a wrong confirmation writes them
	// and signs nothing.
	newRoots := filepath.Join(g.dir, "new-roots.pub")
	writeTestFile(t, newRoots, []byte(rootLine(t, keyC)+rootLine(t, keyD)))
	succ := filepath.Join(g.dir, "succ")
	if code, _, stderr := run(t, "root", "sign", "--prev", g.out, "--prev-sha256", trust.SHA256Hex(genesis), "--roots", newRoots, "--threshold", "1",
		"--policy", filepath.Join(g.out, "policy.json"), "--out-dir", succ, "--agent-key", keyFingerprint(t, keyC),
		"--confirm", "00000000"); code != 1 || !strings.Contains(stderr, "nothing was signed") {
		t.Fatalf("root sign --prev with a wrong confirmation: exit %d: %s", code, stderr)
	}

	a, b := g.rootKeys[0], g.rootKeys[1]
	fpA, fpB, fpC, fpD := keyFingerprint(t, a), keyFingerprint(t, b), keyFingerprint(t, keyC), keyFingerprint(t, keyD)
	foreign := newEd25519Key(t)

	// signed copies the successor into a fresh directory signed by signers.
	signed := func(t *testing.T, signers ...ed25519.PrivateKey) string {
		t.Helper()
		dir := t.TempDir()
		for _, doc := range []struct{ file, ns string }{{"bundle.json", trust.NamespaceBundle}, {"policy.json", trust.NamespacePolicy}} {
			msg, err := os.ReadFile(filepath.Join(succ, doc.file)) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(dir, doc.file), msg)
			for _, k := range signers {
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
		return dir
	}
	// verify runs trust verify on dir. With prev, it passes --prev and
	// --prev-sha256 prevSHA; prevSHA "" means the SHA-256 of prev's own
	// bundle.json, and noPrevSHA omits the flag.
	verify := func(t *testing.T, prev, prevSHA, dir, threshold string, pins ...string) (int, string, string) {
		t.Helper()
		args := []string{"trust", "verify", "--threshold", threshold,
			"--bundle", filepath.Join(dir, "bundle.json"), "--policy", filepath.Join(dir, "policy.json")}
		if prev != "" {
			args = append(args, "--prev", prev)
			if prevSHA == "" {
				prevSHA = fileSHA256(t, filepath.Join(prev, "bundle.json"))
			}
			if prevSHA != noPrevSHA {
				args = append(args, "--prev-sha256", prevSHA)
			}
		}
		for _, p := range pins {
			args = append(args, "--pin", p)
		}
		return run(t, args...)
	}

	t.Run("previous_and_new_root_signed_ok", func(t *testing.T) {
		// A foreign key's signature is reported as ignored; the roots of
		// either set are not.
		code, stdout, stderr := verify(t, g.out, "", signed(t, a, keyC, foreign), "1", fpC, fpD)
		if code != 0 {
			t.Fatalf("trust verify --prev: exit %d: %s", code, stderr)
		}
		for _, want := range []string{
			"Successor of trust bundle v1, sha256 " + trust.SHA256Hex(genesis) + "\n",
			"Trust bundle version 2",
			"signed by previous root " + fpA + "\n",
			"signed by new root " + fpC + "\n",
			"ignored: bundle signature by non-pinned key " + keyFingerprint(t, foreign) + "\n",
			"OK: successor of trust bundle v1: previous roots 1 of 2 signed both documents (threshold 1); new roots 1 of 2 signed both documents (threshold 1, pinned)\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("trust verify --prev output lacks %q:\n%s", want, stdout)
			}
		}
		for _, fp := range []string{fpA, fpC} {
			if strings.Contains(stdout, "ignored: bundle signature by non-pinned key "+fp) {
				t.Fatalf("trust verify --prev reports root %s as ignored:\n%s", fp, stdout)
			}
		}
	})
	// unsigned holds the genesis bundle.json and policy.json, byte for
	// byte, without their .sigs files.
	unsigned := t.TempDir()
	for _, f := range []string{"bundle.json", "policy.json"} {
		writeTestFile(t, filepath.Join(unsigned, f), readTestFile(t, filepath.Join(g.out, f)))
	}
	other := otherGenesis(t, g)
	refusals := []struct {
		name      string
		prev      string
		prevSHA   string // "" = the SHA-256 of prev's bundle.json
		signers   []ed25519.PrivateKey
		threshold string
		pins      []string
		want      []string
	}{
		{"new_root_only_refused", g.out, "", []ed25519.PrivateKey{keyC}, "1", []string{fpC, fpD},
			[]string{"threshold not met", "previous roots"}},
		{"previous_root_only_refused", g.out, "", []ed25519.PrivateKey{a}, "1", []string{fpC, fpD},
			[]string{"threshold not met", "new roots"}},
		{"pins_name_previous_roots_refused", g.out, "", []ed25519.PrivateKey{a, keyC}, "1", []string{fpA, fpB},
			[]string{"not the pinned roots", "is not pinned"}},
		{"pins_one_new_root_refused", g.out, "", []ed25519.PrivateKey{a, keyC}, "1", []string{fpC},
			[]string{"not the pinned roots", "1 pins, 2 roots"}},
		{"pinned_threshold_differs_refused", g.out, "", []ed25519.PrivateKey{a, keyC, keyD}, "2", []string{fpC, fpD},
			[]string{"not the pinned roots", "bundle threshold 1, pinned threshold 2"}},
		// other is a real genesis, pinned by its own SHA-256, so the
		// refusal is the successor's prev hash.
		{"prev_other_genesis_refused", other, "", []ed25519.PrivateKey{a, keyC}, "1", []string{fpC, fpD},
			[]string{"not a valid successor", "prev", "is not the previous bundle's SHA-256"}},
		{"without_prev_successor_is_not_genesis", "", "", []ed25519.PrivateKey{a, keyC}, "1", []string{fpC, fpD},
			[]string{"a genesis bundle is version 1"}},
		// G-CR-01: the bundle in --prev must be the one recorded at its
		// install, and signed by its own roots.
		{"prev_sha256_mismatch_refused", g.out, fileSHA256(t, filepath.Join(other, "bundle.json")), []ed25519.PrivateKey{a, keyC}, "1", []string{fpC, fpD},
			[]string{"not the recorded --prev-sha256"}},
		{"prev_without_sigs_refused", unsigned, "", []ed25519.PrivateKey{a, keyC}, "1", []string{fpC, fpD},
			[]string{"--prev", "bundle.json.sigs"}},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := verify(t, tc.prev, tc.prevSHA, signed(t, tc.signers...), tc.threshold, tc.pins...)
			if code != 1 {
				t.Fatalf("trust verify accepted: exit %d:\n%s%s", code, stdout, stderr)
			}
			if strings.Contains(stdout, "OK:") {
				t.Fatalf("a refusal printed an OK line:\n%s", stdout)
			}
			for _, want := range tc.want {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr lacks %q:\n%s", want, stderr)
				}
			}
		})
	}

	// G-CR-01 regression: a compromised CA host hands the ceremony a
	// foreign genesis in place of the bundle in force (another root Z, and
	// the attacker's CA, ops and log keys), correctly signed by Z, and a
	// successor of it that names the honest new roots C and D and is signed
	// by Z and C. Its chain and its new-root pins are sound, so only the
	// SHA-256 recorded when the real bundle was installed tells it apart.
	// Both commands must refuse it, and must refuse to run without that
	// SHA-256.
	t.Run("foreign_prev_refused_by_both_commands", func(t *testing.T) {
		z := newCeremony(t, 1)
		useKeyring(t, z.rootKeys[0], keyC)
		typeHashPrefix(t, z.out)
		if code, _, stderr := z.sign(t, "1", 0); code != 0 {
			t.Fatalf("foreign genesis root sign: exit %d: %s", code, stderr)
		}
		foreignSHA := fileSHA256(t, filepath.Join(z.out, "bundle.json"))
		recorded := trust.SHA256Hex(genesis)
		rootSign := func(t *testing.T, out string, prevSHA []string, fp string) (int, string, string) {
			t.Helper()
			typeHashPrefix(t, out)
			args := append([]string{"root", "sign", "--prev", z.out}, prevSHA...)
			return run(t, append(args, "--roots", newRoots, "--threshold", "1",
				"--policy", filepath.Join(z.out, "policy.json"), "--out-dir", out, "--agent-key", fp)...)
		}
		mustNotExist := func(t *testing.T, path string) {
			t.Helper()
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("%s exists after a refusal (stat error %v)", path, err)
			}
		}

		// root sign: without the recorded SHA-256 it is a usage error, and
		// with it the foreign prev is refused; both write nothing.
		out := filepath.Join(z.dir, "refused")
		if code, stdout, stderr := rootSign(t, out, nil, fpC); code != 2 || !strings.Contains(stderr, "--prev-sha256") {
			t.Fatalf("root sign --prev without --prev-sha256: exit %d:\n%s%s", code, stdout, stderr)
		}
		mustNotExist(t, out)
		if code, stdout, stderr := rootSign(t, out, []string{"--prev-sha256", recorded}, fpC); code != 1 ||
			!strings.Contains(stderr, "not the recorded --prev-sha256") || !strings.Contains(stderr, "nothing was written or signed") {
			t.Fatalf("root sign with a foreign --prev: exit %d:\n%s%s", code, stdout, stderr)
		}
		mustNotExist(t, out)

		// The forged successor, built and signed as the attacker would by
		// pinning the foreign genesis's own SHA-256.
		forged := filepath.Join(z.dir, "forged")
		for _, fp := range []string{keyFingerprint(t, z.rootKeys[0]), fpC} {
			if code, _, stderr := rootSign(t, forged, []string{"--prev-sha256", foreignSHA}, fp); code != 0 {
				t.Fatalf("forged successor root sign by %s: exit %d: %s", fp, code, stderr)
			}
		}

		// trust verify: without the recorded SHA-256 it is a usage error;
		// with it the foreign prev is refused. Pinned to the foreign
		// genesis's own SHA-256 it verifies, which shows the forged
		// successor is otherwise sound: the hash pin is what refuses it.
		if code, stdout, stderr := verify(t, z.out, noPrevSHA, forged, "1", fpC, fpD); code != 2 || strings.Contains(stdout, "OK:") {
			t.Fatalf("trust verify --prev without --prev-sha256: exit %d:\n%s%s", code, stdout, stderr)
		}
		if code, stdout, stderr := verify(t, z.out, recorded, forged, "1", fpC, fpD); code != 1 ||
			strings.Contains(stdout, "OK:") || !strings.Contains(stderr, "not the recorded --prev-sha256") {
			t.Fatalf("trust verify with a foreign --prev and the recorded SHA-256: exit %d:\n%s%s", code, stdout, stderr)
		}
		if code, stdout, stderr := verify(t, z.out, foreignSHA, forged, "1", fpC, fpD); code != 0 || !strings.Contains(stdout, "OK: successor of trust bundle v1") {
			t.Fatalf("trust verify of the forged successor against its own prev: exit %d:\n%s%s", code, stdout, stderr)
		}
	})
}

// noPrevSHA tells TestTrustVerifySuccessor's verify to omit --prev-sha256.
const noPrevSHA = "omit"

// readTestFile returns the contents of path.
func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fileSHA256 returns the lowercase hex SHA-256 of the file at path.
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	return trust.SHA256Hex(readTestFile(t, path))
}

// otherGenesis signs a second genesis bundle with g's roots and root A but
// other CA keys and another admin, and returns its out directory.
func otherGenesis(t *testing.T, g *ceremony) string {
	t.Helper()
	other := newCeremonyInputs(t)
	other.rootKeys = g.rootKeys
	roots, err := os.ReadFile(g.roots) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, other.roots, roots)
	typeHashPrefix(t, other.out)
	if code, _, stderr := other.sign(t, "1", 0); code != 0 {
		t.Fatalf("second genesis root sign: exit %d: %s", code, stderr)
	}
	return other.out
}

func newEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func keyFingerprint(t *testing.T, k ed25519.PrivateKey) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(pub)
}

// rootLine is k's roots.pub line, labelled custody=software.
func rootLine(t *testing.T, k ed25519.PrivateKey) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(pub) + " custody=software\n"
}
