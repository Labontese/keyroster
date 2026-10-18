//go:build linux

package software

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
)

var allRoles = []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog}

// testPassphrase is 32 characters.
const testPassphrase = "correct horse battery staple 1234"

// fastScrypt lowers the work factor Provision encrypts with for one test,
// so the suite stays fast under -race. Key decrypts whatever work factor a
// file records.
func fastScrypt(t *testing.T) {
	t.Helper()
	scryptWorkFactor = 10
	t.Cleanup(func() { scryptWorkFactor = 0 })
}

// writePassFile writes content to a new file with mode and returns its
// path.
func writePassFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
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

func openWith(t *testing.T, stateDir, passFile string) (keystore.Backend, error) {
	t.Helper()
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	opts := map[string]string{keystore.OptStateDir: stateDir}
	if passFile != "" {
		opts[optPassphraseFile] = passFile
	}
	return keystore.Open("software", opts)
}

func mustOpen(t *testing.T, stateDir, passFile string) keystore.Backend {
	t.Helper()
	be, err := openWith(t, stateDir, passFile)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	return be
}

func provision(t *testing.T, be keystore.Backend) map[keystore.Role]ssh.PublicKey {
	t.Helper()
	pubs, err := be.(keystore.Provisioner).Provision(allRoles)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return pubs
}

func ageFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*.age"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestScryptWorkFactorIsAgeDefault pins the production work factor: 0, so
// age's default (2^18) applies. Only fastScrypt lowers it, inside a test.
func TestScryptWorkFactorIsAgeDefault(t *testing.T) {
	if scryptWorkFactor != 0 {
		t.Fatalf("scryptWorkFactor = %d, want 0 (age's default) outside tests that lower it", scryptWorkFactor)
	}
}

func TestSoftwareBackend(t *testing.T) {
	t.Run("provision_and_sign", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		var synced []string
		orig := syncDir
		syncDir = func(d string) error { synced = append(synced, d); return orig(d) }
		t.Cleanup(func() { syncDir = orig })
		be := mustOpen(t, state, writePassFile(t, testPassphrase+"\n", 0o600))
		pubs := provision(t, be)
		keyDir := filepath.Join(state, "software")
		if len(synced) != 2 || synced[0] != keyDir || synced[1] != state {
			t.Fatalf("Provision synced %v, want the key directory then the state directory", synced)
		}
		fi, err := os.Lstat(keyDir)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Fatalf("key directory: %v %v, want 0700", fi.Mode(), err)
		}
		seen := map[string]bool{}
		for _, role := range allRoles {
			p := filepath.Join(keyDir, string(role)+".age")
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v %v, want a 0600 regular file", p, fi.Mode(), err)
			}
			data, err := os.ReadFile(p) //nolint:gosec // test fixture
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(data, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) || bytes.Contains(data, []byte(testPassphrase)) {
				t.Fatalf("%s is not an armored age file, or holds the passphrase", p)
			}
			pub := pubs[role]
			if pub == nil || pub.Type() != ssh.KeyAlgoED25519 || seen[string(pub.Marshal())] {
				t.Fatalf("role %s: public key %v (duplicate %v)", role, pub, seen[string(pub.Marshal())])
			}
			seen[string(pub.Marshal())] = true
		}
		// A new backend on the same files, with the passphrase file
		// without its newline: the same passphrase.
		be2 := mustOpen(t, state, writePassFile(t, testPassphrase, 0o400))
		for _, role := range allRoles {
			k, err := be2.Key(role, ssh.FingerprintSHA256(pubs[role]))
			if err != nil {
				t.Fatalf("Key(%s): %v", role, err)
			}
			if k.Custody() != keystore.CustodySoftware || k.Algorithm() != ssh.KeyAlgoED25519 {
				t.Fatalf("Key(%s): custody %s alg %s", role, k.Custody(), k.Algorithm())
			}
			msg := []byte("keyroster software key test " + string(role))
			sig, err := k.Sign(rand.Reader, msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := pubs[role].Verify(msg, sig); err != nil {
				t.Fatalf("signature of the %s key does not verify with its provisioned public key: %v", role, err)
			}
		}
	})
	t.Run("credentials_directory_source", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		creds := t.TempDir()
		if err := os.WriteFile(filepath.Join(creds, credentialName), []byte(testPassphrase+"\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CREDENTIALS_DIRECTORY", creds)
		be, err := keystore.Open("software", map[string]string{keystore.OptStateDir: state})
		if err != nil {
			t.Fatalf("open with CREDENTIALS_DIRECTORY: %v", err)
		}
		t.Cleanup(func() { _ = be.Close() })
		pubs := provision(t, be)
		k, err := be.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleUser]))
		if err != nil || k.Custody() != keystore.CustodySoftware {
			t.Fatalf("Key with the credential passphrase: %v", err)
		}
		// The operator file takes precedence and must hold the same passphrase.
		other := writePassFile(t, "another passphrase of enough length", 0o600)
		be2, err := keystore.Open("software", map[string]string{keystore.OptStateDir: state, optPassphraseFile: other})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := be2.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleUser])); err == nil {
			t.Fatal("Key with the passphrase-file option ignored it and used the credential")
		}
	})
	t.Run("passphrase_file_world_readable", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
			_, err := openWith(t, newStateDir(t), writePassFile(t, testPassphrase, mode))
			if err == nil || !strings.Contains(err.Error(), "mode") {
				t.Fatalf("passphrase file mode %04o: %v, want a mode refusal", mode, err)
			}
		}
	})
	t.Run("passphrase_too_short", func(t *testing.T) {
		// 19 two-byte characters (38 bytes) are refused: the floor counts
		// characters, not bytes. 20 are accepted.
		short := strings.Repeat("ä", 19)
		_, err := openWith(t, newStateDir(t), writePassFile(t, short+"\n", 0o600))
		if err == nil || !strings.Contains(err.Error(), "19 characters") || strings.Contains(err.Error(), short) {
			t.Fatalf("19-character passphrase: %v, want a length refusal that does not echo it", err)
		}
		if _, err := openWith(t, newStateDir(t), writePassFile(t, short+"ä\n", 0o600)); err != nil {
			t.Fatalf("20-character passphrase: %v", err)
		}
		// Exactly one trailing newline is removed: the second is part of
		// the passphrase, which then is 20 characters.
		if _, err := openWith(t, newStateDir(t), writePassFile(t, short+"\n\n", 0o600)); err != nil {
			t.Fatalf("19 characters and two newlines: %v", err)
		}
		if _, err := openWith(t, newStateDir(t), writePassFile(t, "\xff"+strings.Repeat("a", 30), 0o600)); err == nil {
			t.Fatal("a passphrase that is not UTF-8 was accepted")
		}
	})
	t.Run("no_passphrase_source", func(t *testing.T) {
		_, err := openWith(t, newStateDir(t), "")
		if err == nil || !strings.Contains(err.Error(), optPassphraseFile) || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
			t.Fatalf("no passphrase source: %v, want an error naming both ways", err)
		}
		t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
		if _, err := keystore.Open("software", map[string]string{keystore.OptStateDir: newStateDir(t)}); err == nil {
			t.Fatal("a credentials directory without the credential was accepted")
		}
	})
	t.Run("wrong_passphrase_not_echoed", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		pubs := provision(t, mustOpen(t, state, writePassFile(t, testPassphrase, 0o600)))
		wrong := "a wrong passphrase of enough length"
		be := mustOpen(t, state, writePassFile(t, wrong, 0o600))
		_, err := be.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleUser]))
		if err == nil {
			t.Fatal("Key with a wrong passphrase succeeded")
		}
		if strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), testPassphrase) {
			t.Fatalf("the error echoes a passphrase: %v", err)
		}
		if !strings.Contains(err.Error(), "wrong passphrase") {
			t.Fatalf("error %v does not say wrong passphrase", err)
		}
	})
	t.Run("key_file_tampered", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		pass := writePassFile(t, testPassphrase, 0o600)
		pubs := provision(t, mustOpen(t, state, pass))
		be := mustOpen(t, state, pass)
		keyDir := filepath.Join(state, "software")
		read := func(role keystore.Role) []byte {
			b, err := os.ReadFile(filepath.Join(keyDir, string(role)+".age")) //nolint:gosec // test fixture
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		write := func(role keystore.Role, b []byte) {
			if err := os.WriteFile(filepath.Join(keyDir, string(role)+".age"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		orig := read(keystore.RoleHost)
		write(keystore.RoleHost, orig[:len(orig)/2])
		if _, err := be.Key(keystore.RoleHost, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); err == nil {
			t.Fatal("a truncated key file was accepted")
		}
		edited := append([]byte(nil), orig...)
		i := bytes.LastIndex(edited, []byte("-----END")) - 10
		if edited[i] == 'A' {
			edited[i] = 'B'
		} else {
			edited[i] = 'A'
		}
		write(keystore.RoleHost, edited)
		if _, err := be.Key(keystore.RoleHost, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); err == nil {
			t.Fatal("an edited key file was accepted")
		}
		write(keystore.RoleHost, orig)
		if _, err := be.Key(keystore.RoleHost, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); err != nil {
			t.Fatalf("control: the restored key file: %v", err)
		}
		// Another role's file in this role's place: a fingerprint mismatch.
		write(keystore.RoleHost, read(keystore.RoleOps))
		if _, err := be.Key(keystore.RoleHost, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("the ops key file in the host key's place: %v, want ErrKeyNotPresent", err)
		}
	})
	t.Run("fingerprint_mismatch", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		pass := writePassFile(t, testPassphrase, 0o600)
		pubs := provision(t, mustOpen(t, state, pass))
		be := mustOpen(t, state, pass)
		if _, err := be.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("Key(user, host fingerprint) = %v, want ErrKeyNotPresent", err)
		}
		if _, err := be.Key(keystore.RoleUser, ""); err == nil {
			t.Fatal("Key without a fingerprint succeeded")
		}
		if _, err := be.Key("root", ssh.FingerprintSHA256(pubs[keystore.RoleUser])); err == nil {
			t.Fatal("Key of an unknown role succeeded")
		}
	})
	t.Run("provision_refuses_existing", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		be := mustOpen(t, state, writePassFile(t, testPassphrase, 0o600))
		provision(t, be)
		keyDir := filepath.Join(state, "software")
		before := map[string][]byte{}
		for _, f := range ageFiles(t, keyDir) {
			before[f], _ = os.ReadFile(f) //nolint:gosec // test fixture
		}
		if _, err := be.(keystore.Provisioner).Provision(allRoles); !errors.Is(err, ErrKeyFilesExist) {
			t.Fatalf("second Provision = %v, want ErrKeyFilesExist", err)
		}
		// Any .age file in the directory refuses provisioning, even for
		// other roles.
		if _, err := be.(keystore.Provisioner).Provision([]keystore.Role{"user"}); !errors.Is(err, ErrKeyFilesExist) {
			t.Fatalf("Provision of one role over existing files = %v, want ErrKeyFilesExist", err)
		}
		after := ageFiles(t, keyDir)
		if len(after) != len(before) {
			t.Fatalf("%d key files after the refusal, want %d", len(after), len(before))
		}
		for _, f := range after {
			b, _ := os.ReadFile(f) //nolint:gosec // test fixture
			if !bytes.Equal(b, before[f]) {
				t.Fatalf("%s changed", f)
			}
		}
	})
	t.Run("provision_refuses_permissive_dir", func(t *testing.T) {
		state := newStateDir(t)
		keyDir := filepath.Join(state, "software")
		if err := os.Mkdir(keyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyDir, 0o750); err != nil {
			t.Fatal(err)
		}
		be := mustOpen(t, state, writePassFile(t, testPassphrase, 0o600))
		if _, err := be.(keystore.Provisioner).Provision(allRoles); err == nil || !strings.Contains(err.Error(), "0750") {
			t.Fatalf("Provision into a 0750 directory = %v, want a mode refusal", err)
		}
		if f := ageFiles(t, keyDir); len(f) != 0 {
			t.Fatalf("Provision wrote %v into a permissive directory", f)
		}
	})
	t.Run("provision_refuses_symlinked_dir", func(t *testing.T) {
		state := newStateDir(t)
		target := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(state, "software")); err != nil {
			t.Fatal(err)
		}
		be := mustOpen(t, state, writePassFile(t, testPassphrase, 0o600))
		if _, err := be.(keystore.Provisioner).Provision(allRoles); err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("Provision through a symlinked directory = %v, want a refusal", err)
		}
		if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
			t.Fatalf("Provision wrote through the symlink: %v %v", entries, err)
		}
	})
	t.Run("provision_cleans_up_on_failure", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		orig := syncDir
		syncDir = func(string) error { return errors.New("injected sync failure") }
		t.Cleanup(func() { syncDir = orig })
		be := mustOpen(t, state, writePassFile(t, testPassphrase, 0o600))
		if _, err := be.(keystore.Provisioner).Provision(allRoles); err == nil || !strings.Contains(err.Error(), "injected sync failure") {
			t.Fatalf("Provision with a failing directory sync = %v, want that error", err)
		}
		if f := ageFiles(t, filepath.Join(state, "software")); len(f) != 0 {
			t.Fatalf("Provision left %v after a failure", f)
		}
		// Control: with the sync restored, the same state provisions.
		syncDir = orig
		provision(t, be)
	})
	t.Run("provision_refuses_bad_roles", func(t *testing.T) {
		be := mustOpen(t, newStateDir(t), writePassFile(t, testPassphrase, 0o600))
		p := be.(keystore.Provisioner)
		if _, err := p.Provision([]keystore.Role{"user", "user"}); err == nil {
			t.Fatal("a role given twice was accepted")
		}
		if _, err := p.Provision([]keystore.Role{"../user"}); err == nil {
			t.Fatal("an unknown role was accepted")
		}
		if _, err := p.Provision(nil); err == nil {
			t.Fatal("no roles was accepted")
		}
	})
	t.Run("key_file_not_private_refused", func(t *testing.T) {
		fastScrypt(t)
		state := newStateDir(t)
		pass := writePassFile(t, testPassphrase, 0o600)
		pubs := provision(t, mustOpen(t, state, pass))
		be := mustOpen(t, state, pass)
		keyDir := filepath.Join(state, "software")
		userFile := filepath.Join(keyDir, "user.age")
		fp := ssh.FingerprintSHA256(pubs[keystore.RoleUser])
		if err := os.Chmod(userFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := be.Key(keystore.RoleUser, fp); err == nil || !strings.Contains(err.Error(), "0644") {
			t.Fatalf("Key with a 0644 key file = %v, want a mode refusal", err)
		}
		if err := os.Chmod(userFile, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := be.Key(keystore.RoleUser, fp); err != nil {
			t.Fatalf("control: Key with the 0600 key file: %v", err)
		}
		// A symlink to a valid key file is refused.
		moved := filepath.Join(t.TempDir(), "user.age")
		if err := os.Rename(userFile, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, userFile); err != nil {
			t.Fatal(err)
		}
		if _, err := be.Key(keystore.RoleUser, fp); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Key through a symlinked key file = %v, want a refusal", err)
		}
		// A key directory that became permissive is refused too.
		if err := os.Chmod(keyDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := be.Key(keystore.RoleHost, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); err == nil {
			t.Fatal("Key in a 0755 key directory succeeded")
		}
	})
	t.Run("unknown_option", func(t *testing.T) {
		_, err := keystore.Open("software", map[string]string{keystore.OptStateDir: newStateDir(t), "passphrase": testPassphrase})
		if err == nil || !strings.Contains(err.Error(), "unknown backend option") || strings.Contains(err.Error(), testPassphrase) {
			t.Fatalf("an unknown option: %v", err)
		}
		if _, err := keystore.Open("software", map[string]string{optPassphraseFile: writePassFile(t, testPassphrase, 0o600)}); err == nil {
			t.Fatal("open without the state directory succeeded")
		}
		if _, err := keystore.Open("software", map[string]string{keystore.OptStateDir: newStateDir(t), optPassphraseFile: ""}); err == nil {
			t.Fatal("an empty passphrase-file option was accepted")
		}
	})
}
