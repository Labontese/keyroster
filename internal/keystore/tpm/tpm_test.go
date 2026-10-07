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
