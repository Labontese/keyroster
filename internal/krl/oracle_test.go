package krl

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// oracleKeygen returns the path of ssh-keygen, the KRL oracle. It skips
// the test when ssh-keygen is missing, unless KEYROSTER_REQUIRE_ORACLE=1
// (set in CI's build-test job), where a missing oracle is a failure.
func oracleKeygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("KEYROSTER_REQUIRE_ORACLE") == "1" {
			t.Fatalf("ssh-keygen not found and KEYROSTER_REQUIRE_ORACLE=1: %v", err)
		}
		t.Skipf("ssh-keygen not found (set KEYROSTER_REQUIRE_ORACLE=1 to fail instead): %v", err)
	}
	return p
}

// oracleCert is one certificate ssh-keygen -s issued for the oracle.
type oracleCert struct {
	ca     int
	serial uint64
	path   string
}

// oracleCA writes the CA key with seed first as an OpenSSH private key
// file (0600) and returns its path and public key.
func oracleCA(t *testing.T, dir string, first byte) (string, ssh.PublicKey) {
	t.Helper()
	priv, pub := seedKey(t, first)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca"+strconv.Itoa(int(first)))
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

// issueOracleCert has ssh-keygen -s sign a fresh user key with caFile at
// serial and returns the certificate file.
func issueOracleCert(t *testing.T, keygen, dir, caFile string, serial uint64, n int) string {
	t.Helper()
	key := filepath.Join(dir, "user"+strconv.Itoa(n))
	run(t, keygen, "-q", "-t", "ed25519", "-N", "", "-f", key)
	run(t, keygen, "-q", "-s", caFile, "-I", "oracle", "-n", "u", "-z", strconv.FormatUint(serial, 10), "-V", "-5m:+1h", key+".pub")
	return key + "-cert.pub"
}

func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput() //nolint:gosec // G204: test oracle
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", filepath.Base(bin), args, err, out)
	}
	return string(out)
}

// queryRevoked runs ssh-keygen -Q -f krl cert and reports whether the
// oracle says the certificate is revoked (non-zero exit).
func queryRevoked(t *testing.T, keygen, krlFile, cert string) bool {
	t.Helper()
	out, err := exec.Command(keygen, "-Q", "-f", krlFile, cert).CombinedOutput() //nolint:gosec // G204: test oracle
	if err == nil {
		return false
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("ssh-keygen -Q: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "REVOKED") {
		t.Fatalf("ssh-keygen -Q exited %d without reporting REVOKED:\n%s", ee.ExitCode(), out)
	}
	return true
}

// TestOracleSSHKeygenKRL (REVOKE-02): for a random set of revoked serials
// over two CA keys, ssh-keygen -Q -f krl reports exactly the revoked
// certificates as revoked, and ssh-keygen -Q -l lists every revoked
// serial. Controls: an unrevoked serial adjacent to a range, and the same
// serial under the other CA, are not revoked; the empty KRL revokes
// nothing.
func TestOracleSSHKeygenKRL(t *testing.T) {
	keygen := oracleKeygen(t)
	dir := t.TempDir()
	caFiles := make([]string, 2)
	caPubs := make([]ssh.PublicKey, 2)
	caFiles[0], caPubs[0] = oracleCA(t, dir, 0x10)
	caFiles[1], caPubs[1] = oracleCA(t, dir, 0x30)

	// A random revoked set under CA 0 plus a fixed range 20..22 with the
	// adjacent 23 left unrevoked; serial 7 under CA 1 only.
	revoked := [2]map[uint64]bool{{20: true, 21: true, 22: true}, {7: true}}
	for range 6 {
		n, err := rand.Int(rand.Reader, big.NewInt(16))
		if err != nil {
			t.Fatal(err)
		}
		revoked[0][n.Uint64()+1] = true
	}
	var set Set
	for ca := range 2 {
		cs := CertSerials{CAKey: caPubs[ca]}
		for s := range revoked[ca] {
			cs.Serials = append(cs.Serials, s)
		}
		set.Certs = append(set.Certs, cs)
	}
	data, err := Encode(set, 1, testTime)
	if err != nil {
		t.Fatal(err)
	}
	krlFile := filepath.Join(dir, "revoked.krl")
	if err := os.WriteFile(krlFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	emptyData, err := Encode(Set{}, 1, testTime)
	if err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(dir, "empty.krl")
	if err := os.WriteFile(emptyFile, emptyData, 0o600); err != nil {
		t.Fatal(err)
	}

	var certs []oracleCert
	for ca := range 2 {
		for s := uint64(1); s <= 24; s++ {
			if ca == 1 && s != 7 && s != 20 && s != 23 {
				continue // CA 1: its revoked serial and two controls
			}
			certs = append(certs, oracleCert{ca: ca, serial: s, path: issueOracleCert(t, keygen, dir, caFiles[ca], s, len(certs))})
		}
	}
	controls := 0
	for _, c := range certs {
		want := revoked[c.ca][c.serial]
		if got := queryRevoked(t, keygen, krlFile, c.path); got != want {
			t.Errorf("CA %d serial %d: ssh-keygen -Q says revoked=%v, want %v", c.ca, c.serial, got, want)
		}
		if !want {
			controls++
		}
		if queryRevoked(t, keygen, emptyFile, c.path) {
			t.Errorf("CA %d serial %d: the empty KRL revokes it", c.ca, c.serial)
		}
	}
	if controls == 0 || revoked[0][23] {
		t.Fatal("no unrevoked control certificate")
	}

	// ssh-keygen -Q -l lists the KRL: every revoked serial, as a single
	// serial or inside a range, under its CA.
	listed := map[uint64]int{}
	for _, line := range strings.Split(run(t, keygen, "-Q", "-l", "-f", krlFile), "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "serial: ")
		if !ok {
			continue
		}
		lo, hi, isRange := strings.Cut(v, "-")
		a, err := strconv.ParseUint(lo, 10, 64)
		if err != nil {
			t.Fatalf("ssh-keygen -Q -l line %q", line)
		}
		b := a
		if isRange {
			if b, err = strconv.ParseUint(hi, 10, 64); err != nil {
				t.Fatalf("ssh-keygen -Q -l line %q", line)
			}
		}
		for s := a; s <= b; s++ {
			listed[s]++
		}
	}
	for ca := range 2 {
		for s := range revoked[ca] {
			if listed[s] == 0 {
				t.Errorf("ssh-keygen -Q -l does not list serial %d (CA %d)", s, ca)
			}
		}
	}
	if listed[23] != 0 {
		t.Error("ssh-keygen -Q -l lists the unrevoked serial 23")
	}
}
