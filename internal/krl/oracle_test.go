package krl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
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
		cs := CertSection{CAKey: caPubs[ca]}
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

// oracleSigner is the CA key with seed first as an ssh.Signer.
func oracleSigner(t *testing.T, first byte) ssh.Signer {
	t.Helper()
	priv, _ := seedKey(t, first)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// buildCert issues a user certificate for subject with serial and the kr1
// key ID of request req through cert.Build, signed by ca.
func buildCert(t *testing.T, ca ssh.Signer, subject ssh.PublicKey, serial uint64, req byte) *ssh.Certificate {
	t.Helper()
	kid := cert.KeyID{CA: "user", Subject: "alice", Request: strings.Repeat(fmt.Sprintf("%02x", req), 16), Policy: 1, Serial: serial}
	c, err := cert.Build(cert.Request{Profile: cert.DefaultUserProfile(), Subject: subject, Principals: []string{"alice"},
		Now: time.Now(), ValidFor: time.Hour, KeyID: kid, Serial: serial}, ca, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// queryMany runs ssh-keygen -Q -f krl on every file at once and returns,
// per file, whether the oracle reports it revoked. ssh-keygen prints one
// line per file ("<path> (<comment>): ok" or "...: REVOKED").
func queryMany(t *testing.T, keygen, krlFile string, files []string) map[string]bool {
	t.Helper()
	out, err := exec.Command(keygen, append([]string{"-Q", "-f", krlFile}, files...)...).CombinedOutput() //nolint:gosec // G204: test oracle
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("ssh-keygen -Q: %v\n%s", err, out)
	}
	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		for _, f := range files {
			if !strings.HasPrefix(line, f+" ") && !strings.HasPrefix(line, f+":") {
				continue
			}
			switch {
			case strings.HasSuffix(line, ": REVOKED"):
				got[f] = true
			case strings.HasSuffix(line, ": ok"):
				got[f] = false
			}
		}
	}
	for _, f := range files {
		if _, ok := got[f]; !ok {
			t.Fatalf("ssh-keygen -Q printed no verdict for %s:\n%s", f, out)
		}
	}
	return got
}

// TestOracleForward (REVOKE-02): for random sets of up to 200 entries over
// two CA keys (serials with runs, key IDs and explicit keys),
// ssh-keygen -Q -f refuses every certificate the set revokes and accepts
// the controls: a serial next to each run, an unrevoked key ID, and a key
// ID revoked under CA A on a certificate of CA B (key_id_scoped_to_ca); an
// explicit key refuses the plain key and every certificate for it; and
// ssh-keygen -Q -l lists every entry.
func TestOracleForward(t *testing.T) {
	keygen := oracleKeygen(t)
	cas := []ssh.Signer{oracleSigner(t, 0x10), oracleSigner(t, 0x30)}
	for round := range 3 {
		t.Run(fmt.Sprintf("set_%d", round), func(t *testing.T) {
			dir := t.TempDir()
			n := 0
			write := func(name string, data []byte) string {
				n++
				p := filepath.Join(dir, fmt.Sprintf("%03d-%s", n, name))
				if err := os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			r := func(m int64) uint64 {
				v, err := rand.Int(rand.Reader, big.NewInt(m))
				if err != nil {
					t.Fatal(err)
				}
				return v.Uint64()
			}
			// Up to 200 entries: serials under both CAs (runs from the
			// small range), key IDs under CA 0, two explicit keys.
			revoked := [2]map[uint64]bool{{}, {}}
			var set Set
			for range 50 + r(100) {
				ca := r(2)
				s := 1 + r(150)
				revoked[ca][s] = true
				set.Certs = append(set.Certs, CertSection{CAKey: cas[ca].PublicKey(), Serials: []uint64{s}})
			}
			subject := newOracleKey(t)
			idCert := buildCert(t, cas[0], subject, 1000, 1)
			idOther := buildCert(t, cas[0], subject, 1001, 2) // an unrevoked key ID
			idUnderB := buildCert(t, cas[1], subject, 1000, 1)
			set.Certs = append(set.Certs, CertSection{CAKey: cas[0].PublicKey(), KeyIDs: []string{idCert.KeyId}})
			explicit := []ssh.PublicKey{newOracleKey(t), newOracleKey(t)}
			set.Keys = explicit
			data, err := Encode(set, 7, testTime)
			if err != nil {
				t.Fatal(err)
			}
			krlFile := write("revoked.krl", data)

			want := map[string]bool{}
			var files []string
			add := func(name string, data []byte, revoked bool) {
				f := write(name, data)
				want[f] = revoked
				files = append(files, f)
			}
			controls := 0
			for ca := range 2 {
				for s := uint64(1); s <= 152; s++ {
					next := revoked[ca][s-1] || revoked[ca][s+1]
					if !revoked[ca][s] && !next {
						continue // neither revoked nor adjacent to a revoked serial
					}
					if !revoked[ca][s] {
						controls++
					}
					add(fmt.Sprintf("ca%d-serial-%d-cert.pub", ca, s), ssh.MarshalAuthorizedKey(buildCert(t, cas[ca], subject, s, byte(s))), revoked[ca][s])
				}
			}
			add("keyid-cert.pub", ssh.MarshalAuthorizedKey(idCert), true)
			add("keyid-other-cert.pub", ssh.MarshalAuthorizedKey(idOther), false)
			add("key_id_scoped_to_ca-cert.pub", ssh.MarshalAuthorizedKey(idUnderB), revoked[1][1000])
			for i, k := range explicit {
				add(fmt.Sprintf("explicit-%d.pub", i), ssh.MarshalAuthorizedKey(k), true)
				add(fmt.Sprintf("explicit-%d-cert.pub", i), ssh.MarshalAuthorizedKey(buildCert(t, cas[1], k, 2000+uint64(i), 9)), true) //nolint:gosec // G115: small
			}
			if controls == 0 {
				t.Fatal("no control serial next to a run")
			}
			got := queryMany(t, keygen, krlFile, files)
			for _, f := range files {
				if got[f] != want[f] {
					t.Errorf("%s: ssh-keygen -Q says revoked=%v, want %v", filepath.Base(f), got[f], want[f])
				}
			}

			// ssh-keygen -Q -l lists every serial, the key ID and both keys.
			listing := run(t, keygen, "-Q", "-l", "-f", krlFile)
			listed := map[uint64]int{}
			for _, line := range strings.Split(listing, "\n") {
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
			if !strings.Contains(listing, "id: "+idCert.KeyId) {
				t.Errorf("ssh-keygen -Q -l does not list the key ID %s:\n%s", idCert.KeyId, listing)
			}
			for _, k := range explicit {
				if !strings.Contains(listing, ssh.FingerprintSHA256(k)) {
					t.Errorf("ssh-keygen -Q -l does not list the explicit key %s:\n%s", ssh.FingerprintSHA256(k), listing)
				}
			}
			t.Logf("%d files checked against a KRL of %d bytes (%d controls next to a run)", len(files), len(data), controls)
		})
	}
}

// newOracleKey is a fresh Ed25519 public key.
func newOracleKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// bitmapSeed is the FuzzParseKRL seed file that holds the bitmap-bearing
// KRL TestOracleReverse has ssh-keygen -k write (rewritten with -update).
var bitmapSeed = filepath.Join("testdata", "fuzz", "FuzzParseKRL", "sshkeygen_bitmap")

// hasSubsection reports whether data, a KRL, has a certificate subsection
// of type typ (the bytes are walked, not parsed by Parse).
func hasSubsection(t *testing.T, data []byte, typ byte) bool {
	t.Helper()
	s := cryptobyte.String(data[8+4+8+8+8:])
	var reserved, comment cryptobyte.String
	if !readString(&s, &reserved) || !readString(&s, &comment) {
		t.Fatal("bad KRL header")
	}
	for !s.Empty() {
		var (
			st   byte
			body cryptobyte.String
		)
		if !s.ReadUint8(&st) || !readString(&s, &body) {
			t.Fatal("bad section")
		}
		if st != sectionCertificates {
			continue
		}
		var ca, res cryptobyte.String
		if !readString(&body, &ca) || !readString(&body, &res) {
			t.Fatal("bad certificate section")
		}
		for !body.Empty() {
			var (
				sub  byte
				data cryptobyte.String
			)
			if !body.ReadUint8(&sub) || !readString(&body, &data) {
				t.Fatal("bad subsection")
			}
			if sub == typ {
				return true
			}
		}
	}
	return false
}

// TestOracleReverse (REVOKE-02, REVOKE-03): KRLs that ssh-keygen -k writes
// from serial:, id:, key: and hash: spec lines parse with Parse to the
// same semantic set, including a dense run of serials for which
// ssh-keygen writes a bitmap subsection (0x22), and the SHA-256 section
// of a hash: line. The bitmap KRL is a FuzzParseKRL seed.
func TestOracleReverse(t *testing.T) {
	keygen := oracleKeygen(t)
	dir := t.TempDir()
	_, caPub := oracleCA(t, dir, 0x10)
	caPubFile := filepath.Join(dir, "ca.pub")
	if err := os.WriteFile(caPubFile, ssh.MarshalAuthorizedKey(caPub), 0o600); err != nil {
		t.Fatal(err)
	}
	_, explicit := seedKey(t, 0x50)
	_, hashed := seedKey(t, 0x51)
	keyID := "kr1/ca=user/sub=alice/req=000102030405060708090a0b0c0d0e0f/pol=1/ser=7"
	for _, tc := range []struct {
		name   string
		spec   []string
		want   func() *Parsed
		bitmap bool
	}{
		{"serials_ids_keys", []string{"serial: 5", "serial: 7-9", "serial: 20", "id: " + keyID, "key: " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(explicit)))},
			func() *Parsed {
				return (Set{Certs: []CertSection{{CAKey: caPub, Serials: []uint64{5, 7, 8, 9, 20}, KeyIDs: []string{keyID}}}, Keys: []ssh.PublicKey{explicit}}).Normalize()
			}, false},
		{"dense_run_bitmap", func() []string {
			var spec []string
			for s := 1000; s <= 1400; s += 2 {
				spec = append(spec, fmt.Sprintf("serial: %d", s))
			}
			return spec
		}(), func() *Parsed {
			var serials []uint64
			for s := uint64(1000); s <= 1400; s += 2 {
				serials = append(serials, s)
			}
			return (Set{Certs: []CertSection{{CAKey: caPub, Serials: serials}}}).Normalize()
		}, true},
		{"hash_line_sha256", []string{"hash: " + ssh.FingerprintSHA256(hashed)}, func() *Parsed {
			h := sha256.Sum256(hashed.Marshal())
			return &Parsed{SHA256: [][]byte{h[:]}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := filepath.Join(dir, tc.name+".spec")
			if err := os.WriteFile(spec, []byte(strings.Join(tc.spec, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, tc.name+".krl")
			run(t, keygen, "-k", "-s", caPubFile, "-z", "3", "-f", out, spec)
			data, err := os.ReadFile(out) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			p, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse of the KRL ssh-keygen -k wrote: %v", err)
			}
			if want := tc.want(); p.Version != 3 || !p.SameContent(want) {
				t.Fatalf("Parse = %+v, want the content of %+v", p, want)
			}
			if tc.name == "hash_line_sha256" && !p.RevokesKey(hashed.Marshal()) {
				t.Fatal("RevokesKey misses the key of the hash: line")
			}
			if !tc.bitmap {
				return
			}
			if !hasSubsection(t, data, subSerialBitmap) {
				t.Fatal("ssh-keygen wrote no bitmap subsection (0x22) for the dense run")
			}
			t.Logf("ssh-keygen -k wrote a bitmap subsection (%d bytes for %d serials)", len(data), len(tc.spec))
			if *update {
				if err := os.MkdirAll(filepath.Dir(bitmapSeed), 0o750); err != nil {
					t.Fatal(err)
				}
				seed := "go test fuzz v1\n[]byte(" + strconv.Quote(string(data)) + ")\n"
				if err := os.WriteFile(bitmapSeed, []byte(seed), 0o644); err != nil { //nolint:gosec // G306: public fuzz seed
					t.Fatal(err)
				}
			}
			seed, err := readFuzzSeed(bitmapSeed)
			if err != nil {
				t.Fatalf("the bitmap seed %s (write it with -update): %v", bitmapSeed, err)
			}
			if !hasSubsection(t, seed, subSerialBitmap) {
				t.Fatalf("the seed %s holds no bitmap subsection", bitmapSeed)
			}
			if sp, err := Parse(seed); err != nil || !sp.SameContent(tc.want()) {
				t.Fatalf("the seed %s parses to %+v, %v", bitmapSeed, sp, err)
			}
		})
	}
}

// readFuzzSeed reads the []byte of a one-value Go fuzz corpus file.
func readFuzzSeed(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: fixed seed path
	if err != nil {
		return nil, err
	}
	body, ok := strings.CutPrefix(string(raw), "go test fuzz v1\n[]byte(")
	if !ok {
		return nil, errors.New("not a go test fuzz v1 []byte file")
	}
	body, ok = strings.CutSuffix(strings.TrimSpace(body), ")")
	if !ok {
		return nil, errors.New("not a go test fuzz v1 []byte file")
	}
	s, err := strconv.Unquote(body)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}
