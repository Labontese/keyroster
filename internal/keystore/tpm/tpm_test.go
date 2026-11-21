//go:build linux

package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
)

// These tests need swtpm: KEYROSTER_SWTPM names the binary, otherwise
// swtpm is looked up on PATH. Without it they skip, unless
// KEYROSTER_TPM_REQUIRE=1 (set by the e2e-tpm workflow, which runs them
// under -race), when a missing swtpm fails them.

var allRoles = []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog}

// startSWTPM runs a private swtpm with a unixio socket and returns the
// socket path. The swtpm is stopped at cleanup.
func startSWTPM(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("KEYROSTER_SWTPM")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("swtpm"); err != nil {
			if os.Getenv("KEYROSTER_TPM_REQUIRE") == "1" {
				t.Fatal("swtpm not found and KEYROSTER_TPM_REQUIRE=1")
			}
			t.Skip("swtpm not installed; the e2e-tpm workflow runs these tests")
		}
	}
	dir, err := os.MkdirTemp("", "swtpm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "swtpm.sock")
	cmd := exec.Command(bin, "socket", "--tpm2", //nolint:gosec // G204: the swtpm under test
		"--server", "type=unixio,path="+sock,
		"--ctrl", "type=unixio,path="+filepath.Join(dir, "swtpm.ctrl"),
		"--tpmstate", "dir="+state,
		"--flags", "not-need-init,startup-clear")
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			return sock
		}
		select {
		case <-done:
			t.Fatalf("swtpm exited early:\n%s", log.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("swtpm socket did not appear")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// newStateDir returns a fresh 0700 state directory.
func newStateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func openBackend(t *testing.T, opts map[string]string) *backend {
	t.Helper()
	be, err := keystore.Open("tpm", opts)
	if err != nil {
		t.Fatalf("keystore.Open(tpm): %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	return be.(*backend)
}

func provision(t *testing.T, b *backend) map[keystore.Role]ssh.PublicKey {
	t.Helper()
	pubs, err := b.Provision(allRoles)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return pubs
}

// signAndVerify signs a random message with role's key and verifies it with
// the provisioned public key.
func signAndVerify(b *backend, role keystore.Role, pub ssh.PublicKey) error {
	k, err := b.Key(role, ssh.FingerprintSHA256(pub))
	if err != nil {
		return err
	}
	msg := make([]byte, 64)
	if _, err := rand.Read(msg); err != nil {
		return err
	}
	sig, err := k.Sign(rand.Reader, msg)
	if err != nil {
		return err
	}
	return pub.Verify(msg, sig)
}

// TestProvisionSignReopen: five P-256 keys are created in the TPM, their
// files are 0600 in a 0700 directory, each key signs, and after the
// backend is closed and reopened the same keys load and sign again.
func TestProvisionSignReopen(t *testing.T) {
	sock := startSWTPM(t)
	state := newStateDir(t)
	opts := map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock}
	b := openBackend(t, opts)
	pubs := provision(t, b)

	dir := filepath.Join(state, "tpm")
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("key directory %s: mode %v, err %v; want 0700", dir, fi.Mode().Perm(), err)
	}
	seen := map[string]bool{}
	for _, role := range allRoles {
		pub := pubs[role]
		if pub == nil || pub.Type() != ssh.KeyAlgoECDSA256 {
			t.Fatalf("role %s: provisioned key %v, want %s", role, pub, ssh.KeyAlgoECDSA256)
		}
		if seen[ssh.FingerprintSHA256(pub)] {
			t.Fatalf("role %s: duplicate key", role)
		}
		seen[ssh.FingerprintSHA256(pub)] = true
		for _, ext := range []string{".tpmkey", ".auth"} {
			fi, err := os.Stat(filepath.Join(dir, string(role)+ext))
			if err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s%s: mode %v, err %v; want 0600", role, ext, fi.Mode().Perm(), err)
			}
		}
		auth, err := os.ReadFile(filepath.Join(dir, string(role)+".auth")) //nolint:gosec // test fixture
		if err != nil || len(auth) != authSize {
			t.Fatalf("%s.auth: %d bytes, err %v; want %d", role, len(auth), err, authSize)
		}
		k, err := b.Key(role, ssh.FingerprintSHA256(pub))
		if err != nil {
			t.Fatalf("Key(%s): %v", role, err)
		}
		if k.Algorithm() != ssh.KeyAlgoECDSA256 || k.Custody() != keystore.CustodyVTPM {
			t.Fatalf("Key(%s): algorithm %s custody %s, want %s vtpm (swtpm)", role, k.Algorithm(), k.Custody(), ssh.KeyAlgoECDSA256)
		}
		if err := signAndVerify(b, role, pub); err != nil {
			t.Fatalf("role %s: %v", role, err)
		}
	}
	if !strings.Contains(b.Describe(), "TPM manufacturer: IBM") || !strings.Contains(b.Describe(), "custody vtpm") {
		t.Fatalf("Describe() = %q", b.Describe())
	}

	// Persistence: a new backend on the same TPM and state loads the keys.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b2 := openBackend(t, opts)
	for _, role := range allRoles {
		if err := signAndVerify(b2, role, pubs[role]); err != nil {
			t.Fatalf("after reopen, role %s: %v", role, err)
		}
	}
}

// TestKeyRefusals: a wrong fingerprint, an unknown role, a key file
// readable by others and a wrong auth value are all refused.
func TestKeyRefusals(t *testing.T) {
	sock := startSWTPM(t)
	state := newStateDir(t)
	b := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock})
	pubs := provision(t, b)
	userFP := ssh.FingerprintSHA256(pubs[keystore.RoleUser])

	if _, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); !errors.Is(err, ErrKeyNotPresent) {
		t.Fatalf("Key with the host fingerprint for role user: %v, want ErrKeyNotPresent", err)
	}
	if _, err := b.Key(keystore.RoleUser, ""); err == nil {
		t.Fatal("Key with an empty fingerprint succeeded")
	}
	if _, err := b.Key("../user", userFP); err == nil || !strings.Contains(err.Error(), "unknown role") {
		t.Fatalf("Key with role ../user: %v, want an unknown-role refusal", err)
	}

	auth := filepath.Join(state, "tpm", "user.auth")
	if err := os.Chmod(auth, 0o644); err != nil { //nolint:gosec // G302: the test makes the file too open on purpose
		t.Fatal(err)
	}
	if _, err := b.Key(keystore.RoleUser, userFP); err == nil || !strings.Contains(err.Error(), "want 0600") {
		t.Fatalf("Key with a 0644 auth file: %v, want a mode refusal", err)
	}
	// A wrong auth value: the TPM refuses the signature.
	if err := os.Chmod(auth, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auth, bytes.Repeat([]byte{1}, authSize), 0o600); err != nil {
		t.Fatal(err)
	}
	// D-WR-01: Key proves the auth value with one signature, so a wrong
	// one stops the signer at start (keystore.ErrCredentialRefused, a
	// non-restartable exit) instead of failing every signing request.
	if _, err := b.Key(keystore.RoleUser, userFP); !errors.Is(err, keystore.ErrCredentialRefused) {
		t.Fatalf("Key with a wrong auth value: %v, want keystore.ErrCredentialRefused", err)
	}
}

// lockoutCounter reads the TPM's dictionary-attack failure counter
// (TPM_PT_LOCKOUT_COUNTER).
func lockoutCounter(t *testing.T, b *backend) uint32 {
	t.Helper()
	tpmMu.Lock()
	defer tpmMu.Unlock()
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTLockoutCounter),
		PropertyCount: 1,
	}.Execute(b.tpm)
	if err != nil {
		t.Fatal(err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range props.TPMProperty {
		if p.Property == tpm2.TPMPTLockoutCounter {
			return p.Value
		}
	}
	t.Fatal("the TPM did not report TPM_PT_LOCKOUT_COUNTER")
	return 0
}

// TestProvisionNoDA (D-WR-01): Provision creates every key with noDA, so a
// wrong auth value (refused by Key's start-up signature) does not count
// against the TPM-wide dictionary-attack counter that also guards other
// users of the TPM. The control: a key from go-tpm-keyfiles' default
// template (without noDA) does raise the counter on the same TPM.
func TestProvisionNoDA(t *testing.T) {
	sock := startSWTPM(t)
	state := newStateDir(t)
	b := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock})
	pubs := provision(t, b)
	dir := filepath.Join(state, "tpm")
	for _, role := range allRoles {
		raw, err := os.ReadFile(filepath.Join(dir, string(role)+".tpmkey")) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		k, err := keyfile.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := k.Pubkey.Contents()
		if err != nil {
			t.Fatal(err)
		}
		a := pub.ObjectAttributes
		if !a.NoDA || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.UserWithAuth || !a.SignEncrypt {
			t.Fatalf("role %s: attributes %+v, want noDA, fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, sign", role, a)
		}
	}

	before := lockoutCounter(t, b)
	if err := os.WriteFile(filepath.Join(dir, "user.auth"), bytes.Repeat([]byte{1}, authSize), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleUser]))
	if !errors.Is(err, keystore.ErrCredentialRefused) || !errors.Is(err, tpm2.TPMRCBadAuth) {
		t.Fatalf("Key with a wrong auth value: %v, want TPM_RC_BAD_AUTH (a noDA key) wrapped in keystore.ErrCredentialRefused", err)
	}
	if after := lockoutCounter(t, b); after != before {
		t.Fatalf("a wrong auth value on a provisioned key moved the lockout counter from %d to %d", before, after)
	}

	// Control: a DA-protected key raises the counter on a wrong auth value.
	tpmMu.Lock()
	da, err := keyfile.NewLoadableKey(b.tpm, tpm2.TPMAlgECC, 256, nil, keyfile.WithUserAuth(bytes.Repeat([]byte{2}, authSize)))
	tpmMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("control"))
	tpmMu.Lock()
	cs, err := da.Signer(b.tpm, nil, bytes.Repeat([]byte{3}, authSize))
	if err == nil {
		_, err = cs.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	tpmMu.Unlock()
	if !errors.Is(err, tpm2.TPMRCAuthFail) {
		t.Fatalf("control: signing with a wrong auth value: %v, want TPM_RC_AUTH_FAIL (a DA-protected key)", err)
	}
	if after := lockoutCounter(t, b); after != before+1 {
		t.Fatalf("control: a wrong auth value on a DA-protected key moved the lockout counter from %d to %d, want +1", before, after)
	}
}

// TestOpenOptions: unknown options, two transports, a missing state
// directory, an invalid custody and custody tpm on a software TPM are
// refused; custody vtpm is accepted.
func TestOpenOptions(t *testing.T) {
	sock := startSWTPM(t)
	state := newStateDir(t)
	for _, tc := range []struct {
		name string
		opts map[string]string
		want string
	}{
		{"unknown option", map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock, "pin": "1"}, "unknown backend option"},
		{"two transports", map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock, "device": "/dev/tpmrm0"}, "mutually exclusive"},
		{"no state dir", map[string]string{"swtpm-socket": sock}, "state directory"},
		{"relative state dir", map[string]string{keystore.OptStateDir: "state", "swtpm-socket": sock}, "state directory"},
		{"bad custody", map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock, "custody": "software"}, "custody must be"},
		{"tpm custody on swtpm", map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock, "custody": "tpm"}, "custody tpm refused"},
		{"missing device", map[string]string{keystore.OptStateDir: state, "device": filepath.Join(state, "nope")}, "open TPM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be, err := keystore.Open("tpm", tc.opts)
			if err == nil {
				_ = be.Close()
				t.Fatalf("keystore.Open succeeded, want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("keystore.Open: %v, want %q", err, tc.want)
			}
		})
	}
	b := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock, "custody": "vtpm"})
	if b.custody != keystore.CustodyVTPM {
		t.Fatalf("custody %s, want vtpm", b.custody)
	}
}

// TestProvisionTwiceRefused: a second Provision on the same state is
// refused and leaves every key and auth file byte-identical (KEY-04
// idempotency), including when only one role's file is left over.
func TestProvisionTwiceRefused(t *testing.T) {
	sock := startSWTPM(t)
	state := newStateDir(t)
	b := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock})
	provision(t, b)
	dir := filepath.Join(state, "tpm")
	snapshot := func() map[string][]byte {
		t.Helper()
		out := map[string][]byte{}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // test fixture
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = data
		}
		return out
	}
	before := snapshot()
	if len(before) != 2*len(allRoles) {
		t.Fatalf("%d files after provisioning, want %d", len(before), 2*len(allRoles))
	}
	if _, err := b.Provision(allRoles); !errors.Is(err, ErrKeyFilesExist) {
		t.Fatalf("second Provision: %v, want ErrKeyFilesExist", err)
	}
	// Only the log key's auth file left over: still refused, nothing new.
	for name := range before {
		if name != "log.auth" {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := b.Provision(allRoles); !errors.Is(err, ErrKeyFilesExist) {
		t.Fatalf("Provision with log.auth left over: %v, want ErrKeyFilesExist", err)
	}
	after := snapshot()
	if len(after) != 1 || !bytes.Equal(after["log.auth"], before["log.auth"]) {
		t.Fatalf("refused Provision changed the key directory: %d files", len(after))
	}
}

// TestConcurrentSign: eight goroutines sign through one backend at once;
// every signature verifies (KEY-04 concurrency; run under -race).
func TestConcurrentSign(t *testing.T) {
	const n = 8
	sock := startSWTPM(t)
	b := openBackend(t, map[string]string{keystore.OptStateDir: newStateDir(t), "swtpm-socket": sock})
	pubs := provision(t, b)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			role := allRoles[i%len(allRoles)]
			errs[i] = signAndVerify(b, role, pubs[role])
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("signature %d: %v", i, err)
		}
	}
}

// TestImportedKeyRefused (D-CR-02): a key created in software and imported
// into the TPM (TPM2_Import) is a valid loadable key that this TPM signs
// with, but its owner kept a copy, so Key refuses it rather than report it
// as TPM custody.
func TestImportedKeyRefused(t *testing.T) {
	sock := startSWTPM(t)
	state := newStateDir(t)
	b := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock})
	provision(t, b) // creates {state}/tpm with the backend's own keys

	soft, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := bytes.Repeat([]byte{7}, authSize)
	tpmMu.Lock()
	sess := keyfile.NewTPMSession(b.tpm)
	srk, srkPub, err := keyfile.CreateSRK(sess, tpm2.TPMRHOwner, nil)
	if err == nil {
		keyfile.FlushHandle(b.tpm, srk)
	}
	tpmMu.Unlock()
	if err != nil {
		t.Fatalf("CreateSRK: %v", err)
	}
	importable, err := keyfile.NewImportablekey(srkPub, *soft, keyfile.WithUserAuth(auth))
	if err != nil {
		t.Fatalf("NewImportablekey: %v", err)
	}
	tpmMu.Lock()
	loadable, err := keyfile.ImportTPMKey(b.tpm, importable, nil)
	tpmMu.Unlock()
	if err != nil {
		t.Fatalf("ImportTPMKey: %v", err)
	}

	// The imported key really works in this TPM: only the attribute check
	// stands between it and TPM custody.
	digest := sha256.Sum256([]byte("imported"))
	tpmMu.Lock()
	cs, err := loadable.Signer(b.tpm, nil, auth)
	var sig []byte
	if err == nil {
		sig, err = cs.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	tpmMu.Unlock()
	if err != nil {
		t.Fatalf("the imported key does not sign in the TPM: %v", err)
	}
	if !ecdsa.VerifyASN1(&soft.PublicKey, digest[:], sig) {
		t.Fatal("the TPM signature of the imported key does not verify")
	}

	dir := filepath.Join(state, "tpm")
	if err := os.WriteFile(filepath.Join(dir, "user.tpmkey"), loadable.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "user.auth"), auth, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&soft.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pub))
	if err == nil {
		t.Fatalf("Key accepted an imported key and reports custody %s", k.Custody())
	}
	if !strings.Contains(err.Error(), "not generated inside this TPM") {
		t.Fatalf("Key on an imported key: %v, want the generated-inside refusal", err)
	}
}

// TestCheckGeneratedInTPM (D-CR-02): each of fixedTPM, fixedParent and
// sensitiveDataOrigin is required; the backend's own template has all three.
func TestCheckGeneratedInTPM(t *testing.T) {
	ok := tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true}
	if err := checkGeneratedInTPM(&tpm2.TPMTPublic{ObjectAttributes: ok}); err != nil {
		t.Fatalf("generated key refused: %v", err)
	}
	for name, clear := range map[string]func(*tpm2.TPMAObject){
		"fixedTPM":            func(a *tpm2.TPMAObject) { a.FixedTPM = false },
		"fixedParent":         func(a *tpm2.TPMAObject) { a.FixedParent = false },
		"sensitiveDataOrigin": func(a *tpm2.TPMAObject) { a.SensitiveDataOrigin = false },
	} {
		a := ok
		clear(&a)
		if err := checkGeneratedInTPM(&tpm2.TPMTPublic{ObjectAttributes: a}); err == nil || !strings.Contains(err.Error(), name+"=false") {
			t.Errorf("%s clear: %v, want a refusal naming it", name, err)
		}
	}
}

// TestProvisionSyncsDirectories (D-WR-05): after writing the key files,
// Provision fsyncs the key directory, and the state directory too when it
// created the key directory, so the new entries survive a crash right
// after ca-init commits. A failed sync removes the files and fails.
func TestProvisionSyncsDirectories(t *testing.T) {
	sock := startSWTPM(t)
	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	var synced []string
	syncDir = func(dir string) error {
		synced = append(synced, dir)
		return orig(dir)
	}

	state := newStateDir(t)
	b := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock})
	provision(t, b)
	dir := filepath.Join(state, "tpm")
	if len(synced) != 2 || synced[0] != dir || synced[1] != state {
		t.Fatalf("synced %v, want [%s %s]", synced, dir, state)
	}

	// The key directory exists already: only it is synced.
	synced = nil
	state2 := newStateDir(t)
	if err := os.Mkdir(filepath.Join(state2, "tpm"), 0o700); err != nil {
		t.Fatal(err)
	}
	b2 := openBackend(t, map[string]string{keystore.OptStateDir: state2, "swtpm-socket": sock})
	provision(t, b2)
	if len(synced) != 1 || synced[0] != filepath.Join(state2, "tpm") {
		t.Fatalf("synced %v, want only %s", synced, filepath.Join(state2, "tpm"))
	}

	// A failed sync: Provision fails and leaves no key files behind.
	syncDir = func(string) error { return errors.New("injected fsync failure") }
	state3 := newStateDir(t)
	b3 := openBackend(t, map[string]string{keystore.OptStateDir: state3, "swtpm-socket": sock})
	if _, err := b3.Provision(allRoles); err == nil || !strings.Contains(err.Error(), "injected fsync failure") {
		t.Fatalf("Provision with a failing directory sync: %v, want the sync error", err)
	}
	entries, err := os.ReadDir(filepath.Join(state3, "tpm"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed Provision left %d files in the key directory", len(entries))
	}
}

// The tests below pin CA key generations on the TPM backend (03-12f). Each
// top-level test starts its own swtpm and opens no backend itself; each
// leaf makes its own state directory, opens one backend, provisions the
// five genesis keys, and closes every backend before it opens the next.
// go-tpm's socket transport connects for each command and disconnects
// after the answer, so swtpm does not keep a second backend out. Every
// refusal leaf also runs its legitimate case, which must succeed.

// genSetup opens a backend on sock over a fresh state directory and
// provisions the five genesis keys. The backend is closed when t ends.
func genSetup(t *testing.T, sock string) (*backend, string, map[keystore.Role]ssh.PublicKey) {
	t.Helper()
	state := newStateDir(t)
	b := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock})
	return b, state, provision(t, b)
}

// closeBackend closes b before the leaf opens another backend on the same
// swtpm.
func closeBackend(t *testing.T, b *backend) {
	t.Helper()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

// provisionGen creates generation of role and requires the empty location
// and an ECDSA P-256 key.
func provisionGen(t *testing.T, b *backend, role keystore.Role, generation uint32) ssh.PublicKey {
	t.Helper()
	pub, location, err := b.ProvisionGeneration(role, generation, nil)
	if err != nil {
		t.Fatalf("ProvisionGeneration(%s, %d): %v", role, generation, err)
	}
	if location != "" || pub == nil || pub.Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("ProvisionGeneration(%s, %d): location %q key %v, want \"\" and an %s key", role, generation, location, pub, ssh.KeyAlgoECDSA256)
	}
	return pub
}

// regularFiles returns the bytes of every regular file in dir by name.
func regularFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = data
	}
	return out
}

// sameFiles requires every file of before to be in dir, byte-identical.
func sameFiles(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := regularFiles(t, dir)
	for name, data := range before {
		if !bytes.Equal(after[name], data) {
			t.Fatalf("%s changed or is gone", name)
		}
	}
}

// absent requires that nothing is at any of names in dir.
func absent(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := os.Lstat(filepath.Join(dir, n)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: %v, want absent", n, err)
		}
	}
}

// present requires an entry at each of names in dir.
func present(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("%s: %v, want present", n, err)
		}
	}
}

// signAt opens generation of role with KeyAt and proves one signature
// with pub.
func signAt(b *backend, role keystore.Role, generation uint32, pub ssh.PublicKey, location string) error {
	k, err := b.KeyAt(role, generation, ssh.FingerprintSHA256(pub), location)
	if err != nil {
		return err
	}
	msg := make([]byte, 64)
	if _, err := rand.Read(msg); err != nil {
		return err
	}
	sig, err := k.Sign(rand.Reader, msg)
	if err != nil {
		return err
	}
	return pub.Verify(msg, sig)
}

// keyFileAttributes decodes the key file at path and returns its object
// attributes.
func keyFileAttributes(t *testing.T, path string) tpm2.TPMAObject {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	k, err := keyfile.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.Pubkey.Contents()
	if err != nil {
		t.Fatal(err)
	}
	return pub.ObjectAttributes
}

// wantHeld requires Holds(role, generation) to answer held, with a nil
// error when wantErr is false and a non-nil one when it is true.
func wantHeld(t *testing.T, b *backend, role keystore.Role, generation uint32, held, wantErr bool) {
	t.Helper()
	got, err := b.Holds(role, generation, "", "")
	if got != held || (err != nil) != wantErr {
		t.Fatalf("Holds(%s, %d) = %v, %v; want %v with error %v", role, generation, got, err, held, wantErr)
	}
}

// TestTPMGenerationFiles: generation 2 of a role is created as
// {role}-g2.tpmkey and {role}-g2.auth beside generation 1, whose files and
// every other role's stay byte-identical, and its key carries noDA and
// the attributes Key requires.
func TestTPMGenerationFiles(t *testing.T) {
	sock := startSWTPM(t)
	t.Run("names_and_modes", func(t *testing.T) {
		b, state, pubs := genSetup(t, sock)
		dir := filepath.Join(state, "tpm")
		before := regularFiles(t, dir)
		for _, role := range []keystore.Role{keystore.RoleUser, keystore.RoleOps} {
			pub := provisionGen(t, b, role, 2)
			if ssh.FingerprintSHA256(pub) == ssh.FingerprintSHA256(pubs[role]) {
				t.Fatalf("generation 2 of %s is generation 1's key", role)
			}
			for _, ext := range []string{".tpmkey", ".auth"} {
				name := string(role) + "-g2" + ext
				fi, err := os.Lstat(filepath.Join(dir, name))
				if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
					t.Fatalf("%s: %v, err %v; want a regular file with mode 0600", name, fi, err)
				}
			}
			auth, err := os.ReadFile(filepath.Join(dir, string(role)+"-g2.auth")) //nolint:gosec // test fixture
			if err != nil || len(auth) != authSize {
				t.Fatalf("%s-g2.auth: %d bytes, err %v; want %d", role, len(auth), err, authSize)
			}
		}
		if after := regularFiles(t, dir); len(after) != len(before)+4 {
			t.Fatalf("%d files after two generations, want %d", len(after), len(before)+4)
		}
		sameFiles(t, dir, before)
	})
	t.Run("noda_on_generation_key", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		provisionGen(t, b, keystore.RoleUser, 2)
		a := keyFileAttributes(t, filepath.Join(state, "tpm", "user-g2.tpmkey"))
		if !a.NoDA || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.UserWithAuth || !a.SignEncrypt {
			t.Fatalf("user-g2.tpmkey: attributes %+v, want noDA, fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, sign", a)
		}
	})
}

// TestTPMProvisionGenerationRefusals: generation 0 and 1, an existing key
// or auth file, a key directory that is not private or is a link, and a
// failed directory sync are refused, and nothing is left behind.
func TestTPMProvisionGenerationRefusals(t *testing.T) {
	sock := startSWTPM(t)
	t.Run("generation_below_2_refused", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		provisionGen(t, b, keystore.RoleUser, 2)
		dir := filepath.Join(state, "tpm")
		before := regularFiles(t, dir)
		for _, g := range []uint32{0, 1} {
			if _, _, err := b.ProvisionGeneration(keystore.RoleUser, g, nil); err == nil || !strings.Contains(err.Error(), "generation 1 is ca-init's") {
				t.Fatalf("ProvisionGeneration(user, %d): %v, want a refusal naming generation 1 is ca-init's", g, err)
			}
		}
		if after := regularFiles(t, dir); len(after) != len(before) {
			t.Fatalf("a refused ProvisionGeneration wrote: %d files, want %d", len(after), len(before))
		}
		sameFiles(t, dir, before)
	})
	for _, tc := range []struct{ leaf, existing, other string }{
		{"existing_key_file_refused", "user-g2.tpmkey", "user-g2.auth"},
		{"existing_auth_file_refused", "user-g2.auth", "user-g2.tpmkey"},
	} {
		t.Run(tc.leaf, func(t *testing.T) {
			b, state, _ := genSetup(t, sock)
			provisionGen(t, b, keystore.RoleUser, 3)
			dir := filepath.Join(state, "tpm")
			placed := []byte("a file from a lost prepare")
			if err := os.WriteFile(filepath.Join(dir, tc.existing), placed, 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil)
			if !errors.Is(err, ErrKeyFilesExist) || !strings.Contains(err.Error(), tc.existing) ||
				!strings.Contains(err.Error(), "is a key from a lost prepare") ||
				!strings.Contains(err.Error(), "docs/runbooks/signer-install.md has run to its end") {
				t.Fatalf("ProvisionGeneration over %s: %v, want ErrKeyFilesExist with the lost-prepare hint", tc.existing, err)
			}
			got, err := os.ReadFile(filepath.Join(dir, tc.existing)) //nolint:gosec // test fixture
			if err != nil || !bytes.Equal(got, placed) {
				t.Fatalf("%s changed: %q, err %v", tc.existing, got, err)
			}
			absent(t, dir, tc.other)
		})
	}
	t.Run("key_dir_not_private_refused", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		dir := filepath.Join(state, "tpm")
		if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: the test opens the directory on purpose
			t.Fatal(err)
		}
		if _, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil); err == nil || !strings.Contains(err.Error(), "want 0700") {
			t.Fatalf("ProvisionGeneration in a 0750 key directory: %v, want a refusal naming want 0700", err)
		}
		absent(t, dir, "user-g2.tpmkey", "user-g2.auth")
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the key directory's own mode, restored
			t.Fatal(err)
		}
		provisionGen(t, b, keystore.RoleUser, 2)
	})
	t.Run("symlinked_key_dir_refused", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		dir := filepath.Join(state, "tpm")
		aside := filepath.Join(state, "tpm-aside")
		other := filepath.Join(state, "other")
		if err := os.Rename(dir, aside); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, dir); err != nil {
			t.Fatal(err)
		}
		if _, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil); err == nil || !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("ProvisionGeneration through a linked key directory: %v, want a refusal naming is not a directory", err)
		}
		absent(t, aside, "user-g2.tpmkey", "user-g2.auth")
		absent(t, other, "user-g2.tpmkey", "user-g2.auth")
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(aside, dir); err != nil {
			t.Fatal(err)
		}
		provisionGen(t, b, keystore.RoleUser, 2)
	})
	t.Run("sync_failure_leaves_nothing", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		dir := filepath.Join(state, "tpm")
		orig := syncDir
		t.Cleanup(func() { syncDir = orig })
		syncDir = func(d string) error {
			if d == dir {
				return errors.New("injected fsync failure")
			}
			return orig(d)
		}
		if _, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil); err == nil || !strings.Contains(err.Error(), "sync") || !strings.Contains(err.Error(), "injected fsync failure") {
			t.Fatalf("ProvisionGeneration with a failing directory sync: %v, want the sync error", err)
		}
		absent(t, dir, "user-g2.tpmkey", "user-g2.auth")
		syncDir = orig
		provisionGen(t, b, keystore.RoleUser, 2)
	})
}

// createKeyWithoutNoDA creates, inside the TPM, a key with keyTemplate's
// attributes minus noDA and auth value auth, as an operator could place
// one for prepare --key.
func createKeyWithoutNoDA(t *testing.T, b *backend, auth []byte) *keyfile.TPMKey {
	t.Helper()
	tmpl := keyTemplate()
	pub, err := tmpl.Contents()
	if err != nil {
		t.Fatal(err)
	}
	pub.ObjectAttributes.NoDA = false
	tpmMu.Lock()
	defer tpmMu.Unlock()
	sess := keyfile.NewTPMSession(b.tpm)
	parent, err := keyfile.GetParentHandle(sess, tpm2.TPMRHOwner, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.FlushHandle()
	rsp, err := tpm2.Create{
		ParentHandle: *parent,
		InPublic:     tpm2.New2B(*pub),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth}},
		},
	}.Execute(b.tpm, sess.GetHMAC())
	if err != nil {
		t.Fatal(err)
	}
	return keyfile.NewTPMKey(keyfile.OIDLoadableKey, rsp.OutPublic, rsp.OutPrivate, keyfile.WithUserAuth(auth))
}

// TestTPMKeyAtExact: KeyAt opens exactly the asked generation's files and
// key, never falls back to another generation, requires noDA from
// generation 2, ignores the location and works after a reopen and with
// generation 1 removed.
func TestTPMKeyAtExact(t *testing.T) {
	sock := startSWTPM(t)
	setup := func(t *testing.T) (*backend, string, ssh.PublicKey, ssh.PublicKey) {
		t.Helper()
		b, state, pubs := genSetup(t, sock)
		return b, state, pubs[keystore.RoleUser], provisionGen(t, b, keystore.RoleUser, 2)
	}
	t.Run("generation_2_signs", func(t *testing.T) {
		b, _, _, pub2 := setup(t)
		k, err := b.KeyAt(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), "")
		if err != nil {
			t.Fatalf("KeyAt(user, 2): %v", err)
		}
		if k.Algorithm() != ssh.KeyAlgoECDSA256 || k.Custody() != keystore.CustodyVTPM {
			t.Fatalf("KeyAt(user, 2): algorithm %s custody %s, want %s vtpm (swtpm)", k.Algorithm(), k.Custody(), ssh.KeyAlgoECDSA256)
		}
		if err := signAt(b, keystore.RoleUser, 2, pub2, ""); err != nil {
			t.Fatalf("generation 2: %v", err)
		}
	})
	t.Run("generation_2_refuses_generation_1_fingerprint", func(t *testing.T) {
		b, _, pub1, pub2 := setup(t)
		if err := signAt(b, keystore.RoleUser, 2, pub2, ""); err != nil {
			t.Fatalf("KeyAt(user, 2) with generation 2's fingerprint: %v", err)
		}
		// user.tpmkey holds fp1: only the file name decides the generation.
		if _, err := b.KeyAt(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub1), ""); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("KeyAt(user, 2) with generation 1's fingerprint: %v, want ErrKeyNotPresent", err)
		}
	})
	t.Run("generation_1_refuses_generation_2_fingerprint", func(t *testing.T) {
		b, _, pub1, pub2 := setup(t)
		if err := signAt(b, keystore.RoleUser, 1, pub1, ""); err != nil {
			t.Fatalf("KeyAt(user, 1) with generation 1's fingerprint: %v", err)
		}
		if _, err := b.KeyAt(keystore.RoleUser, 1, ssh.FingerprintSHA256(pub2), ""); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("KeyAt(user, 1) with generation 2's fingerprint: %v, want ErrKeyNotPresent", err)
		}
	})
	t.Run("works_with_generation_1_removed", func(t *testing.T) {
		b, state, _, pub2 := setup(t)
		for _, name := range []string{"user.tpmkey", "user.auth"} {
			if err := os.Remove(filepath.Join(state, "tpm", name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := signAt(b, keystore.RoleUser, 2, pub2, ""); err != nil {
			t.Fatalf("generation 2 with generation 1's files removed: %v", err)
		}
	})
	t.Run("after_reopen", func(t *testing.T) {
		b, state, pub1, pub2 := setup(t)
		closeBackend(t, b)
		b2 := openBackend(t, map[string]string{keystore.OptStateDir: state, "swtpm-socket": sock})
		for g, pub := range map[uint32]ssh.PublicKey{1: pub1, 2: pub2} {
			if err := signAt(b2, keystore.RoleUser, g, pub, ""); err != nil {
				t.Fatalf("after reopen, generation %d: %v", g, err)
			}
		}
	})
	t.Run("missing_generation_no_fallback", func(t *testing.T) {
		b, _, pub1, pub2 := setup(t)
		if err := signAt(b, keystore.RoleUser, 2, pub2, ""); err != nil {
			t.Fatalf("KeyAt(user, 2): %v", err)
		}
		// No generation 3 files exist; generation 1's are never tried.
		if k, err := b.KeyAt(keystore.RoleUser, 3, ssh.FingerprintSHA256(pub1), ""); err == nil {
			t.Fatalf("KeyAt(user, 3) with no generation 3 files returned a key (custody %s)", k.Custody())
		}
	})
	t.Run("noda_required_for_generation_n", func(t *testing.T) {
		b, state, _, pub2 := setup(t)
		if err := signAt(b, keystore.RoleUser, 2, pub2, ""); err != nil {
			t.Fatalf("the noDA key of generation 2: %v", err)
		}
		auth := bytes.Repeat([]byte{5}, authSize)
		k := createKeyWithoutNoDA(t, b, auth)
		cpub, err := k.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		pub3, err := ssh.NewPublicKey(cpub)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(state, "tpm")
		if err := os.WriteFile(filepath.Join(dir, "user-g3.tpmkey"), k.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "user-g3.auth"), auth, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := b.KeyAt(keystore.RoleUser, 3, ssh.FingerprintSHA256(pub3), ""); err == nil || !strings.Contains(err.Error(), "lacks noDA") {
			t.Fatalf("KeyAt(user, 3) on a key without noDA: %v, want a refusal naming lacks noDA", err)
		}
	})
	t.Run("noda_refused_before_any_tpm_command", func(t *testing.T) {
		// A key without noDA whose auth file holds a wrong value: the
		// refusal comes before the test signature, so the wrong value never
		// reaches the TPM and its dictionary-attack counter stays (03-12f).
		b, state, _, pub2 := setup(t)
		k := createKeyWithoutNoDA(t, b, bytes.Repeat([]byte{5}, authSize))
		cpub, err := k.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		pub3, err := ssh.NewPublicKey(cpub)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(state, "tpm")
		if err := os.WriteFile(filepath.Join(dir, "user-g3.tpmkey"), k.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "user-g3.auth"), bytes.Repeat([]byte{6}, authSize), 0o600); err != nil {
			t.Fatal(err)
		}
		before := lockoutCounter(t, b)
		_, err = b.KeyAt(keystore.RoleUser, 3, ssh.FingerprintSHA256(pub3), "")
		if err == nil || !strings.Contains(err.Error(), "lacks noDA") || errors.Is(err, keystore.ErrCredentialRefused) {
			t.Fatalf("KeyAt(user, 3) on a key without noDA and a wrong auth value: %v, want a refusal naming lacks noDA and not ErrCredentialRefused", err)
		}
		if after := lockoutCounter(t, b); after != before {
			t.Fatalf("the lockout counter went from %d to %d, want no change", before, after)
		}
		if err := signAt(b, keystore.RoleUser, 2, pub2, ""); err != nil {
			t.Fatalf("the noDA key of generation 2: %v", err)
		}
	})
	t.Run("location_ignored", func(t *testing.T) {
		b, _, _, pub2 := setup(t)
		k1, err := b.KeyAt(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), "87")
		if err != nil {
			t.Fatalf("KeyAt(user, 2, \"87\"): %v", err)
		}
		k2, err := b.KeyAt(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), "")
		if err != nil {
			t.Fatalf("KeyAt(user, 2, \"\"): %v", err)
		}
		if !bytes.Equal(k1.PublicKey().Marshal(), k2.PublicKey().Marshal()) {
			t.Fatal("KeyAt with a location opened another key than without")
		}
		if err := signAt(b, keystore.RoleUser, 2, pub2, "87"); err != nil {
			t.Fatalf("KeyAt(user, 2, \"87\"): %v", err)
		}
	})
}

// TestTPMHolds: a generation is held while either of its two files has
// any directory entry, not held only when both are absent, and held with
// an error on any other lstat error, a generation 0 or an unknown role;
// GenerationHeld answers what Holds answers, without a TPM.
func TestTPMHolds(t *testing.T) {
	sock := startSWTPM(t)
	t.Run("absent_not_held", func(t *testing.T) {
		b, _, _ := genSetup(t, sock)
		wantHeld(t, b, keystore.RoleUser, 3, false, false)
	})
	t.Run("regular_file_held", func(t *testing.T) {
		b, _, _ := genSetup(t, sock)
		provisionGen(t, b, keystore.RoleUser, 2)
		wantHeld(t, b, keystore.RoleUser, 2, true, false)
	})
	t.Run("dangling_link_held", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		if err := os.Symlink(filepath.Join(state, "nowhere"), filepath.Join(state, "tpm", "user-g2.tpmkey")); err != nil {
			t.Fatal(err)
		}
		wantHeld(t, b, keystore.RoleUser, 2, true, false)
	})
	t.Run("link_held", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		target := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.WriteFile(target, []byte("another file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(state, "tpm", "user-g2.tpmkey")); err != nil {
			t.Fatal(err)
		}
		wantHeld(t, b, keystore.RoleUser, 2, true, false)
	})
	t.Run("directory_held", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		if err := os.Mkdir(filepath.Join(state, "tpm", "user-g2.tpmkey"), 0o700); err != nil {
			t.Fatal(err)
		}
		wantHeld(t, b, keystore.RoleUser, 2, true, false)
	})
	t.Run("only_auth_held", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		provisionGen(t, b, keystore.RoleUser, 2)
		if err := os.Remove(filepath.Join(state, "tpm", "user-g2.tpmkey")); err != nil {
			t.Fatal(err)
		}
		wantHeld(t, b, keystore.RoleUser, 2, true, false)
	})
	t.Run("only_tpmkey_held", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		provisionGen(t, b, keystore.RoleUser, 2)
		if err := os.Remove(filepath.Join(state, "tpm", "user-g2.auth")); err != nil {
			t.Fatal(err)
		}
		wantHeld(t, b, keystore.RoleUser, 2, true, false)
	})
	t.Run("lstat_error_held", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		wantHeld(t, b, keystore.RoleUser, 3, false, false)
		dir := filepath.Join(state, "tpm")
		if err := os.Rename(dir, filepath.Join(state, "tpm-aside")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		wantHeld(t, b, keystore.RoleUser, 3, true, true)
	})
	t.Run("bad_generation_or_role_held", func(t *testing.T) {
		b, _, _ := genSetup(t, sock)
		wantHeld(t, b, keystore.RoleUser, 3, false, false)
		wantHeld(t, b, keystore.RoleUser, 0, true, true)
		wantHeld(t, b, keystore.Role("foo"), 2, true, true)
	})
	t.Run("generation_held_matches_holds", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		check := func(what string, wantAbsent bool) {
			t.Helper()
			held, err := b.Holds(keystore.RoleUser, 2, "", "")
			gHeld, gErr := GenerationHeld(state, keystore.RoleUser, 2)
			if held != gHeld || (err != nil) != (gErr != nil) {
				t.Fatalf("%s: Holds = %v, %v but GenerationHeld = %v, %v", what, held, err, gHeld, gErr)
			}
			if wantAbsent && (held || err != nil) {
				t.Fatalf("%s: Holds = %v, %v, want false, nil", what, held, err)
			}
			if !wantAbsent && (!held || err != nil) {
				t.Fatalf("%s: Holds = %v, %v, want true, nil", what, held, err)
			}
		}
		check("absent", true)
		provisionGen(t, b, keystore.RoleUser, 2)
		check("present", false)
		if err := os.Remove(filepath.Join(state, "tpm", "user-g2.tpmkey")); err != nil {
			t.Fatal(err)
		}
		check("only the auth file", false)
	})
}

// TestTPMRemoveGeneration: a generation's regular key file goes, together
// with its auth file and one fsync of the key directory, only after its
// public key matched the fingerprint; another key or a file that does not
// decode refuses and removes nothing; a link is unlinked and its target
// never touched; the crash states between the two unlinks converge.
func TestTPMRemoveGeneration(t *testing.T) {
	sock := startSWTPM(t)
	t.Run("tpm_retire_removes_both_files", func(t *testing.T) {
		b, state, pubs := genSetup(t, sock)
		provisionGen(t, b, keystore.RoleUser, 2)
		dir := filepath.Join(state, "tpm")
		before := regularFiles(t, dir)
		delete(before, "user.tpmkey")
		delete(before, "user.auth")
		orig := syncDir
		t.Cleanup(func() { syncDir = orig })
		var synced []string
		syncDir = func(d string) error {
			synced = append(synced, d)
			return orig(d)
		}
		fp1 := ssh.FingerprintSHA256(pubs[keystore.RoleUser])
		if err := b.RemoveGeneration(keystore.RoleUser, 1, fp1, ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 1): %v", err)
		}
		absent(t, dir, "user.tpmkey", "user.auth")
		if len(synced) != 1 || synced[0] != dir {
			t.Fatalf("synced %v, want only %s", synced, dir)
		}
		wantHeld(t, b, keystore.RoleUser, 1, false, false)
		sameFiles(t, dir, before)
		if err := b.RemoveGeneration(keystore.RoleUser, 1, fp1, ""); err != nil {
			t.Fatalf("a second RemoveGeneration(user, 1): %v", err)
		}
	})
	t.Run("other_key_refused", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		pub2 := provisionGen(t, b, keystore.RoleUser, 2)
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 2) with its own fingerprint: %v", err)
		}
		absent(t, filepath.Join(state, "tpm"), "user-g2.tpmkey", "user-g2.auth")
		closeBackend(t, b)

		b, state, _ = genSetup(t, sock)
		pub2 = provisionGen(t, b, keystore.RoleUser, 2)
		pub3 := provisionGen(t, b, keystore.RoleUser, 3)
		dir := filepath.Join(state, "tpm")
		for _, ext := range []string{".tpmkey", ".auth"} {
			if err := os.Rename(filepath.Join(dir, "user-g3"+ext), filepath.Join(dir, "user-g2"+ext)); err != nil {
				t.Fatal(err)
			}
		}
		before := regularFiles(t, dir)
		err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), "")
		if !errors.Is(err, keystore.ErrGenerationFileMismatch) || !strings.Contains(err.Error(), ssh.FingerprintSHA256(pub3)) {
			t.Fatalf("RemoveGeneration(user, 2) over generation 3's key: %v, want ErrGenerationFileMismatch naming %s", err, ssh.FingerprintSHA256(pub3))
		}
		present(t, dir, "user-g2.tpmkey", "user-g2.auth")
		sameFiles(t, dir, before)
	})
	t.Run("unparsable_key_file_refused", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		pub3 := provisionGen(t, b, keystore.RoleUser, 3)
		if err := b.RemoveGeneration(keystore.RoleUser, 3, ssh.FingerprintSHA256(pub3), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 3) of a key file that decodes: %v", err)
		}
		pub2 := provisionGen(t, b, keystore.RoleUser, 2)
		dir := filepath.Join(state, "tpm")
		if err := os.WriteFile(filepath.Join(dir, "user-g2.tpmkey"), []byte("not a TSS2 key file"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := regularFiles(t, dir)
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); !errors.Is(err, ErrKeyFileUnreadable) {
			t.Fatalf("RemoveGeneration(user, 2) of garbage: %v, want ErrKeyFileUnreadable", err)
		}
		present(t, dir, "user-g2.tpmkey", "user-g2.auth")
		sameFiles(t, dir, before)
	})
	t.Run("link_unlinked_target_intact", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		pub2 := provisionGen(t, b, keystore.RoleUser, 2)
		dir := filepath.Join(state, "tpm")
		target := filepath.Join(t.TempDir(), "elsewhere")
		garbage := []byte("not a key, and never read")
		if err := os.WriteFile(target, garbage, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "user-g2.tpmkey")
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 2) with a link at the key name: %v", err)
		}
		absent(t, dir, "user-g2.tpmkey", "user-g2.auth")
		if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, garbage) { //nolint:gosec // test fixture
			t.Fatalf("the link's target changed: %q, err %v", got, err)
		}
		closeBackend(t, b)

		// An empty directory at the key name is removed with the auth file.
		b, state, _ = genSetup(t, sock)
		pub2 = provisionGen(t, b, keystore.RoleUser, 2)
		dir = filepath.Join(state, "tpm")
		if err := os.Remove(filepath.Join(dir, "user-g2.tpmkey")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "user-g2.tpmkey"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 2) with an empty directory at the key name: %v", err)
		}
		absent(t, dir, "user-g2.tpmkey", "user-g2.auth")
		wantHeld(t, b, keystore.RoleUser, 2, false, false)
		closeBackend(t, b)

		// A directory holding a file is not removed, and stays held.
		b, state, _ = genSetup(t, sock)
		pub2 = provisionGen(t, b, keystore.RoleUser, 2)
		dir = filepath.Join(state, "tpm")
		sub := filepath.Join(dir, "user-g2.tpmkey")
		if err := os.Remove(sub); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "inside"), []byte("kept"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err == nil {
			t.Fatal("RemoveGeneration(user, 2) removed a non-empty directory at the key name")
		}
		present(t, dir, "user-g2.tpmkey", filepath.Join("user-g2.tpmkey", "inside"))
		wantHeld(t, b, keystore.RoleUser, 2, true, false)
	})
	t.Run("crash_states_converge", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		dir := filepath.Join(state, "tpm")
		// Only the auth file left: removed unchecked.
		pub2 := provisionGen(t, b, keystore.RoleUser, 2)
		if err := os.Remove(filepath.Join(dir, "user-g2.tpmkey")); err != nil {
			t.Fatal(err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 2) with only the auth file left: %v", err)
		}
		absent(t, dir, "user-g2.tpmkey", "user-g2.auth")
		wantHeld(t, b, keystore.RoleUser, 2, false, false)
		// Only the key file left: checked, then removed.
		pub2 = provisionGen(t, b, keystore.RoleUser, 2)
		if err := os.Remove(filepath.Join(dir, "user-g2.auth")); err != nil {
			t.Fatal(err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 2) with only the key file left: %v", err)
		}
		absent(t, dir, "user-g2.tpmkey", "user-g2.auth")
		wantHeld(t, b, keystore.RoleUser, 2, false, false)
		// A lone key file that holds another key: refused, and it stays.
		pub3 := provisionGen(t, b, keystore.RoleUser, 3)
		if err := os.Rename(filepath.Join(dir, "user-g3.tpmkey"), filepath.Join(dir, "user-g2.tpmkey")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "user-g3.auth")); err != nil {
			t.Fatal(err)
		}
		err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), "")
		if !errors.Is(err, keystore.ErrGenerationFileMismatch) || !strings.Contains(err.Error(), ssh.FingerprintSHA256(pub3)) {
			t.Fatalf("RemoveGeneration(user, 2) of a lone key file holding generation 3's key: %v, want ErrGenerationFileMismatch", err)
		}
		present(t, dir, "user-g2.tpmkey")
	})
	t.Run("sync_failure_returned", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		pub3 := provisionGen(t, b, keystore.RoleUser, 3)
		if err := b.RemoveGeneration(keystore.RoleUser, 3, ssh.FingerprintSHA256(pub3), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 3) with a working sync: %v", err)
		}
		pub2 := provisionGen(t, b, keystore.RoleUser, 2)
		dir := filepath.Join(state, "tpm")
		orig := syncDir
		t.Cleanup(func() { syncDir = orig })
		syncDir = func(d string) error {
			if d == dir {
				return errors.New("injected fsync failure")
			}
			return orig(d)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err == nil || !strings.Contains(err.Error(), "sync") || !strings.Contains(err.Error(), "injected fsync failure") {
			t.Fatalf("RemoveGeneration(user, 2) with a failing directory sync: %v, want the sync error", err)
		}
	})
	t.Run("key_directory_mode_refused", func(t *testing.T) {
		b, state, _ := genSetup(t, sock)
		pub2 := provisionGen(t, b, keystore.RoleUser, 2)
		dir := filepath.Join(state, "tpm")
		before := regularFiles(t, dir)
		if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: the test opens the directory on purpose
			t.Fatal(err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err == nil || !strings.Contains(err.Error(), "want 0700") {
			t.Fatalf("RemoveGeneration(user, 2) in a 0750 key directory: %v, want a refusal naming want 0700", err)
		}
		present(t, dir, "user-g2.tpmkey", "user-g2.auth")
		sameFiles(t, dir, before)
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the key directory's own mode, restored
			t.Fatal(err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 2) in the 0700 key directory: %v", err)
		}
		absent(t, dir, "user-g2.tpmkey", "user-g2.auth")
	})
}
