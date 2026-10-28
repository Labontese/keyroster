//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/tlspin"
)

// joinFile writes a valid join string to a 0600 file and returns it.
func joinFile(t *testing.T) (string, *join.JoinToken) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	rpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, _ := ssh.NewPublicKey(rpub)
	j := join.JoinToken{Version: join.Version, Server: "https://keyroster.example:8443", TLSRoots: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))},
		TLSPins: []string{tlspin.PinOf(c)}, TrustPins: []string{ssh.FingerprintSHA256(rk)}, Threshold: 1, InstallationID: "0123456789abcdef0123456789abcdef",
		Token: join.EncodeToken(make([]byte, join.TokenBytes)), ExpectedName: "web1", ExpiresAt: "2026-10-28T12:30:00Z"}
	s, err := join.Format(j)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "join.txt")
	if err := os.WriteFile(p, []byte(s+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, &j
}

// installRoot is a host root with /etc and /var/lib, and a state
// directory path whose parent exists.
func installRoot(t *testing.T) (root, state string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	for _, d := range []string{"etc", "var/lib"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil { //nolint:gosec // G301: a host's /etc and /var/lib
			t.Fatal(err)
		}
	}
	return root, filepath.Join(base, "state")
}

func currentUserName(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := dispatch(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestInstallLayout (F2, T-03-225): install lays out every path with its
// mode, the spool is the only path under the state directory the fetch
// user owns, and a pre-existing symlink or a group-writable directory is
// refused install_path_unsafe with nothing written. The owners here are
// the test's uid (root's own run is 03-08's agent-smoke.sh).
func TestInstallLayout(t *testing.T) {
	who := currentUserName(t)
	modes := func(root, state string) map[string]uint32 {
		return map[string]uint32{
			state:                                                           0o755,
			filepath.Join(state, "accepted"):                                0o700,
			filepath.Join(state, "pins.json"):                               0o600,
			filepath.Join(state, "spool"):                                   0o750,
			filepath.Join(state, "outbox"):                                  0o2750,
			filepath.Join(root, "etc/keyroster-agent"):                      0o755,
			filepath.Join(root, "etc/keyroster-agent/fetch.json"):           0o640,
			filepath.Join(root, "var/lib/keyroster-agent-fetch"):            0o700,
			filepath.Join(root, "var/lib/keyroster-agent-fetch/join-token"): 0o600,
		}
	}
	t.Run("layout", func(t *testing.T) {
		root, state := installRoot(t)
		jf, j := joinFile(t)
		if code, out, errOut := runCmd(t, "install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", who); code != 0 {
			t.Fatalf("install exited %d:\n%s%s", code, out, errOut)
		}
		for p, want := range modes(root, state) {
			var st unix.Stat_t
			if err := unix.Lstat(p, &st); err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			if got := uint32(st.Mode) & 0o7777; got != want {
				t.Errorf("%s: mode %04o, want %04o", p, got, want)
			}
		}
		entries, err := os.ReadDir(state)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 4 {
			t.Errorf("the state directory holds %d entries, want accepted, outbox, pins.json and spool", len(entries))
		}
		b, err := os.ReadFile(filepath.Join(root, "etc/keyroster-agent/fetch.json")) //nolint:gosec // G304: the test's own file
		if err != nil || strings.Contains(string(b), j.TrustPins[0]) || strings.Contains(string(b), j.Token) || !strings.Contains(string(b), j.Server) {
			t.Fatalf("fetch.json %s (%v): the server and TLS pins only", b, err)
		}
		tok, err := os.ReadFile(filepath.Join(root, "var/lib/keyroster-agent-fetch/join-token")) //nolint:gosec // G304: the test's own file
		if err != nil || !strings.Contains(string(tok), j.Token) {
			t.Fatalf("join-token: %v", err)
		}
		// Running install again with the same join string is a no-op.
		if code, out, errOut := runCmd(t, "install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", who); code != 0 {
			t.Fatalf("install again exited %d:\n%s%s", code, out, errOut)
		}
	})
	t.Run("outbox_symlink_refused", func(t *testing.T) {
		root, state := installRoot(t)
		if err := os.Mkdir(state, 0o755); err != nil { //nolint:gosec // G301: the state directory's mode
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(state, "outbox")); err != nil {
			t.Fatal(err)
		}
		jf, _ := joinFile(t)
		code, _, errOut := runCmd(t, "install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", who)
		if code == 0 || !strings.Contains(errOut, "install_path_unsafe") {
			t.Fatalf("a symlinked outbox: exit %d: %s", code, errOut)
		}
		requireNothingWritten(t, root, state, "outbox")
	})
	t.Run("group_writable_state_refused", func(t *testing.T) {
		root, state := installRoot(t)
		if err := os.Mkdir(state, 0o755); err != nil { //nolint:gosec // G301: the state directory's mode
			t.Fatal(err)
		}
		if err := os.Chmod(state, 0o775); err != nil { //nolint:gosec // the mode under test
			t.Fatal(err)
		}
		jf, _ := joinFile(t)
		code, _, errOut := runCmd(t, "install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", who)
		if code == 0 || !strings.Contains(errOut, "install_path_unsafe") {
			t.Fatalf("a group-writable state directory: exit %d: %s", code, errOut)
		}
		requireNothingWritten(t, root, state)
	})
	t.Run("fetch_dir_wrong_type_refused", func(t *testing.T) {
		root, state := installRoot(t)
		if err := os.WriteFile(filepath.Join(root, "var/lib/keyroster-agent-fetch"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		jf, _ := joinFile(t)
		if code, _, errOut := runCmd(t, "install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", who); code == 0 || !strings.Contains(errOut, "install_path_unsafe") {
			t.Fatalf("a file where the fetcher's directory goes: exit %d: %s", code, errOut)
		}
		if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the state directory was created")
		}
	})
	t.Run("pins_differ_refused", func(t *testing.T) {
		root, state := installRoot(t)
		jf, _ := joinFile(t)
		if code, _, errOut := runCmd(t, "install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", who); code != 0 {
			t.Fatalf("install: %s", errOut)
		}
		other, _ := joinFile(t)
		if code, _, errOut := runCmd(t, "install", "--root", root, "--state-dir", state, "--join-file", other, "--fetch-user", who); code == 0 || !strings.Contains(errOut, "install_pins_differ") {
			t.Fatalf("install over other pins: exit %d: %s", code, errOut)
		}
	})
	t.Run("refused_before_writing", func(t *testing.T) {
		root, state := installRoot(t)
		jf, _ := joinFile(t)
		bad := filepath.Join(t.TempDir(), "bad.txt")
		if err := os.WriteFile(bad, []byte("kr-join-v1:e30\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"install", "--root", root, "--state-dir", state, "--join-file", bad, "--fetch-user", who},
			{"install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", "keyroster-agent-no-such-user"},
		} {
			if code, _, _ := runCmd(t, args...); code == 0 {
				t.Fatalf("%v succeeded", args)
			}
			if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%v wrote the state directory", args)
			}
		}
	})
}

// requireNothingWritten fails when install created anything: the state
// directory holds at most keep, and the fetcher's paths do not exist.
func requireNothingWritten(t *testing.T, root, state string, keep ...string) {
	t.Helper()
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.Contains(strings.Join(keep, " "), e.Name()) {
			t.Errorf("install wrote %s", e.Name())
		}
	}
	for _, p := range []string{"etc/keyroster-agent", "var/lib/keyroster-agent-fetch"} {
		if _, err := os.Lstat(filepath.Join(root, p)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("install created %s", p)
		}
	}
}

// TestIdentityCommand: keyroster-agent identity prints the fetcher's
// identity and every Ed25519 or ECDSA host key sshd -T names, as the
// lines keyroster host pending and host approve print ("agent identity:
// SHA256:..." and "host key: SHA256:... ssh-ed25519"). sshd is a script
// that prints a dump naming the test's host key.
func TestIdentityCommand(t *testing.T) {
	dir := t.TempDir()
	_, hpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := ssh.NewSignerFromKey(hpriv)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "ssh_host_ed25519_key")
	block, _ := ssh.MarshalPrivateKey(hpriv, "")
	if err := os.WriteFile(key, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key+".pub", ssh.MarshalAuthorizedKey(hs.PublicKey()), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	sshd := filepath.Join(dir, "sshd")
	script := "#!/bin/sh\nprintf 'port 22\\nlistenaddress 127.0.0.1:22\\nhostkey " + key + "\\nlogingracetime 120\\n'\n"
	if err := os.WriteFile(sshd, []byte(script), 0o755); err != nil { //nolint:gosec // the fake sshd must run
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfg, nil, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	spool := filepath.Join(dir, "spool")
	if err := os.Mkdir(spool, 0o750); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, enroll.IdentityFile), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	code, out, errOut := runCmd(t, "identity", "--state-dir", dir, "--spool", spool, "--sshd", sshd, "--sshd-config", cfg)
	if code != 0 {
		t.Fatalf("identity exited %d: %s", code, errOut)
	}
	sum := sha256.Sum256(spki)
	want := "agent identity: " + enroll.IdentityFingerprint(sum[:]) + "\nhost key: " + ssh.FingerprintSHA256(hs.PublicKey()) + " ssh-ed25519\n"
	if out != want {
		t.Fatalf("identity printed\n%s\nwant\n%s", out, want)
	}
}
