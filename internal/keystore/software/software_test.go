//go:build linux

package software

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
	t.Run("credential_world_readable_refused", func(t *testing.T) {
		// The credential file must have no other bits. Group bits are
		// allowed: systemd may grant the service user access through an
		// ACL, which shows as group bits.
		creds := t.TempDir()
		cred := filepath.Join(creds, credentialName)
		if err := os.WriteFile(cred, []byte(testPassphrase), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CREDENTIALS_DIRECTORY", creds)
		for _, tc := range []struct {
			mode os.FileMode
			ok   bool
		}{{0o644, false}, {0o666, false}, {0o604, false}, {0o400, true}, {0o440, true}} {
			if err := os.Chmod(cred, tc.mode); err != nil {
				t.Fatal(err)
			}
			be, err := keystore.Open("software", map[string]string{keystore.OptStateDir: newStateDir(t)})
			if err == nil {
				_ = be.Close()
			}
			if tc.ok && err != nil {
				t.Fatalf("credential mode %04o: %v, want it accepted", tc.mode, err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "mode")) {
				t.Fatalf("credential mode %04o: %v, want a mode refusal", tc.mode, err)
			}
		}
	})
	t.Run("passphrase_fifo_refused_without_blocking", func(t *testing.T) {
		// A FIFO without a writer would block a plain open forever, before
		// the regular-file check (and serve would hang holding the state
		// directory lock). The open must not wait for a writer.
		openTimed := func(t *testing.T, opts map[string]string) error {
			t.Helper()
			done := make(chan error, 1)
			go func() {
				be, err := keystore.Open("software", opts)
				if err == nil {
					_ = be.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				return err
			case <-time.After(2 * time.Second):
				t.Fatal("open blocked on a FIFO passphrase file")
				return nil
			}
		}
		mkfifo := func(t *testing.T, p string) {
			t.Helper()
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		fifo := filepath.Join(t.TempDir(), "passphrase")
		mkfifo(t, fifo)
		link := filepath.Join(t.TempDir(), "passphrase-link")
		if err := os.Symlink(fifo, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CREDENTIALS_DIRECTORY", "")
		for name, p := range map[string]string{"fifo": fifo, "symlink_to_fifo": link} {
			err := openTimed(t, map[string]string{keystore.OptStateDir: newStateDir(t), optPassphraseFile: p})
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("%s: %v, want a not-a-regular-file refusal", name, err)
			}
		}
		creds := t.TempDir()
		mkfifo(t, filepath.Join(creds, credentialName))
		t.Setenv("CREDENTIALS_DIRECTORY", creds)
		if err := openTimed(t, map[string]string{keystore.OptStateDir: newStateDir(t)}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("credential FIFO: %v, want a not-a-regular-file refusal", err)
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
		// The same role again is refused by its own file.
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
	t.Run("provision_refuses_any_age_file", func(t *testing.T) {
		// Any .age file in the key directory refuses provisioning, even
		// one that is no role's file: here no role being provisioned has
		// a file yet.
		fastScrypt(t)
		state := newStateDir(t)
		keyDir := filepath.Join(state, "software")
		if err := os.Mkdir(keyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		stray := filepath.Join(keyDir, "stray.age")
		if err := os.WriteFile(stray, []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}
		be := mustOpen(t, state, writePassFile(t, testPassphrase, 0o600))
		if _, err := be.(keystore.Provisioner).Provision([]keystore.Role{"user"}); !errors.Is(err, ErrKeyFilesExist) || !strings.Contains(err.Error(), "stray.age") {
			t.Fatalf("Provision beside stray.age = %v, want ErrKeyFilesExist naming it", err)
		}
		if f := ageFiles(t, keyDir); len(f) != 1 || f[0] != stray {
			t.Fatalf("key directory after the refusal: %v, want only %s", f, stray)
		}
	})
	t.Run("provision_refuses_permissive_dir", func(t *testing.T) {
		state := newStateDir(t)
		keyDir := filepath.Join(state, "software")
		if err := os.Mkdir(keyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyDir, 0o750); err != nil { //nolint:gosec // G302: a permissive mode on purpose, to see it refused
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
		// Refused before any key is written: without the check, the
		// second exclusive write of user.age would still fail, but only
		// after the first one.
		if _, err := p.Provision([]keystore.Role{"user", "user"}); err == nil || !strings.Contains(err.Error(), "given twice") {
			t.Fatalf("a role given twice: %v, want a given-twice refusal", err)
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
		if err := os.Chmod(userFile, 0o644); err != nil { //nolint:gosec // G302: a permissive mode on purpose, to see it refused
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
		if err := os.Chmod(keyDir, 0o755); err != nil { //nolint:gosec // G302: a permissive mode on purpose, to see it refused
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
	t.Run("relative_passphrase_file_refused", func(t *testing.T) {
		// ca-init stores the option verbatim and serve runs from another
		// working directory, so a relative path would resolve elsewhere
		// later. It is refused even when it resolves here.
		state := newStateDir(t)
		abs := writePassFile(t, testPassphrase, 0o600)
		t.Chdir(filepath.Dir(abs))
		_, err := openWith(t, state, filepath.Base(abs))
		if err == nil || !strings.Contains(err.Error(), optPassphraseFile) || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("a relative passphrase-file that resolves in the working directory: %v, want a refusal naming the option", err)
		}
		if _, err := openWith(t, state, abs); err != nil {
			t.Fatalf("control: the same file by its absolute path: %v", err)
		}
	})
}

// TestProvisionGeneration (03-12): a later CA key generation is its own
// file, {role}-g{N}.age, written next to the genesis files and opened only
// by KeyAt with its own number.
func TestProvisionGeneration(t *testing.T) {
	fastScrypt(t)
	setup := func(t *testing.T) (string, keystore.Backend, map[keystore.Role]ssh.PublicKey) {
		t.Helper()
		dir := newStateDir(t)
		be := mustOpen(t, dir, writePassFile(t, testPassphrase, 0o600))
		return dir, be, provision(t, be)
	}
	gp := func(t *testing.T, be keystore.Backend) keystore.GenerationProvisioner {
		t.Helper()
		p, ok := be.(keystore.GenerationProvisioner)
		if !ok {
			t.Fatal("the software backend is not a GenerationProvisioner")
		}
		return p
	}
	gb := func(t *testing.T, be keystore.Backend) keystore.GenerationBackend {
		t.Helper()
		g, ok := be.(keystore.GenerationBackend)
		if !ok {
			t.Fatal("the software backend is not a GenerationBackend")
		}
		return g
	}
	t.Run("writes_generation_file", func(t *testing.T) {
		dir, be, _ := setup(t)
		pub, _, err := gp(t, be).ProvisionGeneration(keystore.RoleUser, 2, nil)
		if err != nil || pub == nil {
			t.Fatalf("ProvisionGeneration = %v, %v", pub, err)
		}
		fi, err := os.Lstat(filepath.Join(dir, "software", "user-g2.age"))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("user-g2.age: %v, %v; want a regular 0600 file", fi, err)
		}
	})
	t.Run("genesis_files_untouched", func(t *testing.T) {
		dir, be, _ := setup(t)
		before := map[string][]byte{}
		for _, role := range allRoles {
			p := filepath.Join(dir, "software", string(role)+".age")
			data, err := os.ReadFile(p) //nolint:gosec // G304: a file of the test's own state directory
			if err != nil {
				t.Fatal(err)
			}
			before[p] = data
		}
		if _, _, err := gp(t, be).ProvisionGeneration(keystore.RoleUser, 2, nil); err != nil {
			t.Fatal(err)
		}
		for p, data := range before {
			if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, data) { //nolint:gosec // G304: a file of the test's own state directory
				t.Fatalf("%s changed (%v)", p, err)
			}
		}
		if got := ageFiles(t, filepath.Join(dir, "software")); len(got) != len(allRoles)+1 {
			t.Fatalf("software directory holds %v", got)
		}
	})
	t.Run("refuses_existing_file", func(t *testing.T) {
		dir, be, _ := setup(t)
		p := filepath.Join(dir, "software", "host-g3.age")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := gp(t, be).ProvisionGeneration(keystore.RoleHost, 3, nil)
		if !errors.Is(err, ErrKeyFilesExist) || !strings.Contains(err.Error(), p) {
			t.Fatalf("ProvisionGeneration over an existing file = %v, want ErrKeyFilesExist naming %s", err, p)
		}
		for _, want := range []string{
			"is a key from a lost prepare",
			"once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it",
			"where that section stops on a lost generation, keep it",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ProvisionGeneration over an existing file: %v, want the lost-prepare hint with %q", err, want)
			}
		}
		if data, _ := os.ReadFile(p); string(data) != "x" { //nolint:gosec // G304: a file of the test's own state directory
			t.Fatal("ProvisionGeneration overwrote the existing file")
		}
	})
	t.Run("refuses_generation_below_2", func(t *testing.T) {
		dir, be, _ := setup(t)
		for _, gen := range []uint32{0, 1} {
			if _, _, err := gp(t, be).ProvisionGeneration(keystore.RoleUser, gen, nil); err == nil {
				t.Fatalf("ProvisionGeneration accepted generation %d", gen)
			}
		}
		if got := ageFiles(t, filepath.Join(dir, "software")); len(got) != len(allRoles) {
			t.Fatalf("software directory holds %v", got)
		}
	})
	t.Run("private_directory_required", func(t *testing.T) {
		dir, be, _ := setup(t)
		if err := os.Chmod(filepath.Join(dir, "software"), 0o750); err != nil { //nolint:gosec // G302: the test widens the mode on purpose
			t.Fatal(err)
		}
		if _, _, err := gp(t, be).ProvisionGeneration(keystore.RoleUser, 2, nil); err == nil {
			t.Fatal("ProvisionGeneration wrote into a directory with group permissions")
		}
		if _, err := os.Lstat(filepath.Join(dir, "software", "user-g2.age")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("user-g2.age exists after the refusal (%v)", err)
		}
	})
	t.Run("key_is_generation_1", func(t *testing.T) {
		_, be, pubs := setup(t)
		fp := ssh.FingerprintSHA256(pubs[keystore.RoleUser])
		k1, err := be.Key(keystore.RoleUser, fp)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := gb(t, be).KeyAt(keystore.RoleUser, 1, fp, "")
		if err != nil || !bytes.Equal(k1.PublicKey().Marshal(), k2.PublicKey().Marshal()) {
			t.Fatalf("KeyAt generation 1 = %v, want Key's key", err)
		}
	})
	t.Run("keyat_opens_own_file_only", func(t *testing.T) {
		dir, be, pubs := setup(t)
		pub2, _, err := gp(t, be).ProvisionGeneration(keystore.RoleUser, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		fp1, fp2 := ssh.FingerprintSHA256(pubs[keystore.RoleUser]), ssh.FingerprintSHA256(pub2)
		g := gb(t, be)
		if _, err := g.KeyAt(keystore.RoleUser, 2, fp1, ""); err == nil {
			t.Fatal("generation 2 opened generation 1's key")
		}
		if _, err := g.KeyAt(keystore.RoleUser, 1, fp2, ""); err == nil {
			t.Fatal("generation 1 opened generation 2's key")
		}
		if _, err := g.KeyAt(keystore.RoleUser, 3, fp2, ""); err == nil {
			t.Fatal("generation 3 opened generation 2's key")
		}
		g1, g2 := filepath.Join(dir, "software", "user.age"), filepath.Join(dir, "software", "user-g2.age")
		d1, err := os.ReadFile(g1) //nolint:gosec // G304: a file of the test's own state directory
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(g1); err != nil {
			t.Fatal(err)
		}
		if k, err := g.KeyAt(keystore.RoleUser, 2, fp2, ""); err != nil || ssh.FingerprintSHA256(k.PublicKey()) != fp2 {
			t.Fatalf("generation 2 without user.age: %v", err)
		}
		if err := os.WriteFile(g1, d1, 0o600); err != nil { //nolint:gosec // G703: a file of the test's own state directory
			t.Fatal(err)
		}
		if err := os.Remove(g2); err != nil {
			t.Fatal(err)
		}
		if k, err := g.KeyAt(keystore.RoleUser, 1, fp1, ""); err != nil || ssh.FingerprintSHA256(k.PublicKey()) != fp1 {
			t.Fatalf("generation 1 without user-g2.age: %v", err)
		}
		if _, err := g.KeyAt(keystore.RoleUser, 2, fp2, ""); err == nil {
			t.Fatal("generation 2 opened without its file")
		}
	})
	t.Run("keyat_wrong_fingerprint_refused", func(t *testing.T) {
		_, be, pubs := setup(t)
		if _, _, err := gp(t, be).ProvisionGeneration(keystore.RoleUser, 2, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := gb(t, be).KeyAt(keystore.RoleUser, 2, ssh.FingerprintSHA256(pubs[keystore.RoleHost]), ""); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("KeyAt with another fingerprint = %v, want ErrKeyNotPresent", err)
		}
	})
	t.Run("keyat_ignores_location", func(t *testing.T) {
		_, be, _ := setup(t)
		pub2, _, err := gp(t, be).ProvisionGeneration(keystore.RoleUser, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		fp2 := ssh.FingerprintSHA256(pub2)
		for _, loc := range []string{"", "slot-9a", "../../etc/passwd"} {
			k, err := gb(t, be).KeyAt(keystore.RoleUser, 2, fp2, loc)
			if err != nil || ssh.FingerprintSHA256(k.PublicKey()) != fp2 {
				t.Fatalf("KeyAt with location %q = %v", loc, err)
			}
		}
	})
	t.Run("provision_returns_empty_location", func(t *testing.T) {
		_, be, _ := setup(t)
		_, loc, err := gp(t, be).ProvisionGeneration(keystore.RoleMachine, 2, []string{"slot-9a"})
		if err != nil || loc != "" {
			t.Fatalf("ProvisionGeneration location = %q, %v; want empty", loc, err)
		}
	})
}

// holder is be as a keystore.GenerationHolder.
func holder(t *testing.T, be keystore.Backend) keystore.GenerationHolder {
	t.Helper()
	h, ok := be.(keystore.GenerationHolder)
	if !ok {
		t.Fatal("the software backend is not a GenerationHolder")
	}
	return h
}

// remover is be as a keystore.GenerationRemover.
func remover(t *testing.T, be keystore.Backend) keystore.GenerationRemover {
	t.Helper()
	r, ok := be.(keystore.GenerationRemover)
	if !ok {
		t.Fatal("the software backend is not a GenerationRemover")
	}
	return r
}

// TestHoldsSoftware (03-12e, SR-01): a generation is held while any
// directory entry sits at its file name (a regular file, a dangling link,
// a directory), as the backend's Holds and GenerationHeld, which doctor
// asks without the passphrase, both report; only absence is not held.
func TestHoldsSoftware(t *testing.T) {
	// both asks the backend and GenerationHeld and requires them to agree.
	both := func(t *testing.T, dir string, be keystore.Backend, role keystore.Role, gen uint32) bool {
		t.Helper()
		h1, err1 := holder(t, be).Holds(role, gen, "SHA256:ignored", "ignored")
		h2, err2 := GenerationHeld(dir, role, gen)
		if err1 != nil || err2 != nil || h1 != h2 {
			t.Fatalf("Holds = %v, %v; GenerationHeld = %v, %v; want the same answer without an error", h1, err1, h2, err2)
		}
		return h1
	}
	setup := func(t *testing.T) (string, string, keystore.Backend) {
		t.Helper()
		dir := newStateDir(t)
		if err := os.Mkdir(filepath.Join(dir, "software"), 0o700); err != nil {
			t.Fatal(err)
		}
		return dir, filepath.Join(dir, "software"), mustOpen(t, dir, writePassFile(t, testPassphrase, 0o600))
	}
	t.Run("regular_file_is_held", func(t *testing.T) {
		dir, kd, be := setup(t)
		if err := os.WriteFile(filepath.Join(kd, "user-g2.age"), []byte("not even a key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !both(t, dir, be, keystore.RoleUser, 2) {
			t.Fatal("a file at user-g2.age is not held")
		}
	})
	t.Run("dangling_symlink_is_held", func(t *testing.T) {
		dir, kd, be := setup(t)
		if err := os.Symlink(filepath.Join(kd, "nowhere.age"), filepath.Join(kd, "host-g3.age")); err != nil {
			t.Fatal(err)
		}
		if !both(t, dir, be, keystore.RoleHost, 3) {
			t.Fatal("a dangling link at host-g3.age is not held")
		}
	})
	t.Run("directory_at_the_name_is_held", func(t *testing.T) {
		dir, kd, be := setup(t)
		if err := os.Mkdir(filepath.Join(kd, "machine-g2.age"), 0o700); err != nil {
			t.Fatal(err)
		}
		if !both(t, dir, be, keystore.RoleMachine, 2) {
			t.Fatal("a directory at machine-g2.age is not held")
		}
	})
	t.Run("generation_1_name_is_the_role_file", func(t *testing.T) {
		dir, kd, be := setup(t)
		if err := os.WriteFile(filepath.Join(kd, "user-g1.age"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if both(t, dir, be, keystore.RoleUser, 1) {
			t.Fatal("generation 1 is held by a user-g1.age file; its file is user.age")
		}
		if err := os.WriteFile(filepath.Join(kd, "user.age"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !both(t, dir, be, keystore.RoleUser, 1) {
			t.Fatal("a file at user.age does not hold generation 1")
		}
	})
	t.Run("missing_is_not_held", func(t *testing.T) {
		dir, _, be := setup(t)
		if both(t, dir, be, keystore.RoleUser, 2) {
			t.Fatal("a generation with no file is held")
		}
	})
}

// TestRemoveGeneration (03-12e, RK-04, RK-05 and RK-11): RemoveGeneration
// unlinks exactly the file of one generation, after it decrypts to the
// generation's key, and fsyncs the directory; a link goes without its
// target, a non-empty directory stays and fails, another key or a file it
// cannot decrypt is refused with nothing removed, and a missing file is
// done.
func TestRemoveGeneration(t *testing.T) {
	fastScrypt(t)
	setup := func(t *testing.T) (string, keystore.Backend, map[keystore.Role]ssh.PublicKey, ssh.PublicKey) {
		t.Helper()
		dir := newStateDir(t)
		be := mustOpen(t, dir, writePassFile(t, testPassphrase, 0o600))
		pubs := provision(t, be)
		pub2, _, err := be.(keystore.GenerationProvisioner).ProvisionGeneration(keystore.RoleUser, 2, nil)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Join(dir, "software"), be, pubs, pub2
	}
	exists := func(t *testing.T, path string) bool {
		t.Helper()
		_, err := os.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return err == nil
	}
	t.Run("removes_only_that_generation", func(t *testing.T) {
		kd, be, _, pub2 := setup(t)
		if err := remover(t, be).RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatalf("RemoveGeneration: %v", err)
		}
		if exists(t, filepath.Join(kd, "user-g2.age")) {
			t.Fatal("user-g2.age is still there")
		}
		for _, role := range allRoles {
			if !exists(t, filepath.Join(kd, string(role)+".age")) {
				t.Fatalf("%s.age was removed", role)
			}
		}
	})
	t.Run("symlink_removed_not_followed", func(t *testing.T) {
		kd, be, _, _ := setup(t)
		target := filepath.Join(t.TempDir(), "target.age")
		if err := os.WriteFile(target, []byte("the target of the link"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(kd, "host-g2.age")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := remover(t, be).RemoveGeneration(keystore.RoleHost, 2, "SHA256:any", ""); err != nil {
			t.Fatalf("RemoveGeneration of a link: %v", err)
		}
		if exists(t, link) {
			t.Fatal("the link is still there")
		}
		if !exists(t, target) {
			t.Fatal("the target of the link was removed")
		}
	})
	t.Run("directory_stays_held", func(t *testing.T) {
		kd, be, _, _ := setup(t)
		d := filepath.Join(kd, "host-g2.age")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "inside"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := remover(t, be).RemoveGeneration(keystore.RoleHost, 2, "SHA256:any", ""); err == nil {
			t.Fatal("RemoveGeneration of a non-empty directory succeeded")
		}
		if held, err := holder(t, be).Holds(keystore.RoleHost, 2, "", ""); err != nil || !held {
			t.Fatalf("the directory after the failed removal: held %v, %v; want held", held, err)
		}
	})
	t.Run("refuses_generation_0", func(t *testing.T) {
		_, be, _, _ := setup(t)
		if err := remover(t, be).RemoveGeneration(keystore.RoleUser, 0, "SHA256:any", ""); err == nil {
			t.Fatal("RemoveGeneration accepted generation 0")
		}
	})
	t.Run("fsyncs_the_directory", func(t *testing.T) {
		kd, be, _, pub2 := setup(t)
		var synced []string
		orig := syncDir
		syncDir = func(d string) error { synced = append(synced, d); return orig(d) }
		t.Cleanup(func() { syncDir = orig })
		if err := remover(t, be).RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err != nil {
			t.Fatal(err)
		}
		if len(synced) != 1 || synced[0] != kd {
			t.Fatalf("synced %v, want exactly %s", synced, kd)
		}
	})
	t.Run("missing_file_is_ok", func(t *testing.T) {
		_, be, _, _ := setup(t)
		if err := remover(t, be).RemoveGeneration(keystore.RoleMachine, 5, "SHA256:any", ""); err != nil {
			t.Fatalf("RemoveGeneration of a generation with no file: %v", err)
		}
	})
	t.Run("private_dir_required", func(t *testing.T) {
		kd, be, _, pub2 := setup(t)
		if err := os.Chmod(kd, 0o750); err != nil { //nolint:gosec // G302: the test widens the mode on purpose
			t.Fatal(err)
		}
		if err := remover(t, be).RemoveGeneration(keystore.RoleUser, 2, ssh.FingerprintSHA256(pub2), ""); err == nil {
			t.Fatal("RemoveGeneration removed from a directory with group permissions")
		}
		if !exists(t, filepath.Join(kd, "user-g2.age")) {
			t.Fatal("user-g2.age was removed")
		}
	})
	t.Run("fingerprint_mismatch_refused_nothing_removed", func(t *testing.T) {
		kd, be, pubs, pub2 := setup(t)
		fp1 := ssh.FingerprintSHA256(pubs[keystore.RoleUser])
		err := remover(t, be).RemoveGeneration(keystore.RoleUser, 2, fp1, "")
		if !errors.Is(err, keystore.ErrGenerationFileMismatch) || !strings.Contains(err.Error(), "the file holds another key ("+ssh.FingerprintSHA256(pub2)+")") {
			t.Fatalf("RemoveGeneration with the fingerprint of generation 1 = %v, want ErrGenerationFileMismatch naming the key of the file", err)
		}
		if !exists(t, filepath.Join(kd, "user-g2.age")) {
			t.Fatal("user-g2.age was removed")
		}
	})
	t.Run("undecryptable_file_refused_nothing_removed", func(t *testing.T) {
		kd, be, _, pub2 := setup(t)
		fp2 := ssh.FingerprintSHA256(pub2)
		// A wrong passphrase: another backend over the same directory.
		other := mustOpen(t, filepath.Dir(kd), writePassFile(t, "another passphrase of 33 characters", 0o600))
		err := remover(t, other).RemoveGeneration(keystore.RoleUser, 2, fp2, "")
		if !errors.Is(err, keystore.ErrGenerationFileUndecryptable) || !strings.Contains(err.Error(), "the file cannot be decrypted: ") {
			t.Fatalf("RemoveGeneration under a wrong passphrase = %v, want ErrGenerationFileUndecryptable", err)
		}
		if !exists(t, filepath.Join(kd, "user-g2.age")) {
			t.Fatal("user-g2.age was removed under a wrong passphrase")
		}
		// A damaged file.
		damaged := filepath.Join(kd, "host-g2.age")
		if err := os.WriteFile(damaged, []byte("-----BEGIN AGE ENCRYPTED FILE-----\ngarbage\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := remover(t, be).RemoveGeneration(keystore.RoleHost, 2, fp2, ""); !errors.Is(err, keystore.ErrGenerationFileUndecryptable) {
			t.Fatalf("RemoveGeneration of a damaged file = %v, want ErrGenerationFileUndecryptable", err)
		}
		if !exists(t, damaged) {
			t.Fatal("the damaged file was removed")
		}
	})
}
