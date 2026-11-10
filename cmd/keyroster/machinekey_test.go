package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const machineKeyPass = "correct horse battery staple machine"

// writeKeyPEM writes the private key k as an OpenSSH private key file,
// encrypted with pass when pass is set, and returns its path and bytes.
func writeKeyPEM(t *testing.T, k crypto.PrivateKey, pass string) (string, []byte) {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if pass == "" {
		block, err = ssh.MarshalPrivateKey(k, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(k, "", []byte(pass))
	}
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "id_machine")
	writeTestFile(t, path, data)
	return path, data
}

// skKeyFile writes an openssh-key-v1 file whose clear public key is an
// sk-ssh-ed25519@openssh.com key, encrypted (cipher and KDF named, the
// private block random) or not, as ssh-keygen -t ed25519-sk writes one.
func skKeyFile(t *testing.T, encrypted bool) (string, ssh.PublicKey) {
	t.Helper()
	pubEd, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pubEd, "ssh:"})
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	cipher, kdf, opts := "none", "none", ""
	if encrypted {
		cipher, kdf = "aes256-ctr", "bcrypt"
		opts = string(ssh.Marshal(struct {
			Salt   []byte
			Rounds uint32
		}{bytes.Repeat([]byte{1}, 16), 16}))
	}
	priv := make([]byte, 160)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	body := append([]byte(opensshKeyMagic), ssh.Marshal(struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}{cipher, kdf, opts, 1, blob, priv})...)
	path := filepath.Join(t.TempDir(), "id_ed25519_sk")
	writeTestFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body}))
	return path, pub
}

// passPipe is an inherited descriptor holding pass and a newline, with the
// read end kept so a test can see whether it was read.
func passPipe(t *testing.T, pass string) (int, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err := w.WriteString(pass + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	fd, err := strconv.Atoi(strconv.FormatUint(uint64(r.Fd()), 10))
	if err != nil {
		t.Fatal(err)
	}
	return fd, r
}

// unread reports whether the pipe still holds pass.
func unread(t *testing.T, r *os.File, pass string) bool {
	t.Helper()
	rest, _ := io.ReadAll(r)
	return string(rest) == pass+"\n"
}

// loadKey reads and parses the key file at path as machine renew does.
func loadKey(path string, fd int) (*machineKey, []byte, error) {
	data, err := readMachineKeyFile(path)
	if err != nil {
		return nil, nil, err
	}
	k, err := parseMachineKey(data, path, fd)
	return k, data, err
}

// newEd is a fresh Ed25519 private key.
func newEd(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestMachineKeyInput pins the key input of machine renew (03-11b, F11,
// T-03-74, T-03-244, OQ-2, PD6): a bounded regular file, sk and RSA
// refused by type before any prompt, a passphrase only from a descriptor
// or a terminal, Ed25519 and ECDSA keys, and no secret in any error.
func TestMachineKeyInput(t *testing.T) {
	useTerminal(t, false, "typed on stdin\n")
	padded := func(t *testing.T, n int) string {
		t.Helper()
		_, data := writeKeyPEM(t, newEd(t), "")
		data = append(data, bytes.Repeat([]byte{'\n'}, n-len(data))...)
		p := filepath.Join(t.TempDir(), "id_padded")
		writeTestFile(t, p, data)
		return p
	}
	t.Run("max_size_read", func(t *testing.T) {
		if _, _, err := loadKey(padded(t, maxMachineKeyFileBytes), -1); err != nil {
			t.Fatalf("a 64 KiB key file: %v", err)
		}
	})
	t.Run("over_max_refused_before_parse", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		parsed := 0
		prev := machineKeyParseHook
		machineKeyParseHook = func() { parsed++ }
		t.Cleanup(func() { machineKeyParseHook = prev })
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", padded(t, maxMachineKeyFileBytes+1), "--out", filepath.Join(t.TempDir(), "c.pub"))
		if code != 1 || !strings.Contains(stderr, "key_file_too_large") || parsed != 0 || e.renewCount() != 0 {
			t.Fatalf("exit %d, %d parses, %d sent: %s; want 1, key_file_too_large, none parsed or sent", code, parsed, e.renewCount(), stderr)
		}
	})
	t.Run("non_regular_refused", func(t *testing.T) {
		dir := t.TempDir()
		if _, _, err := loadKey(dir, -1); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("a directory: %v", err)
		}
	})
	t.Run("encrypted_no_terminal_refused_immediately", func(t *testing.T) {
		path, _ := writeKeyPEM(t, newEd(t), machineKeyPass)
		_, _, err := loadKey(path, -1)
		want := "is encrypted and stdin is not a terminal: pass the passphrase on an inherited descriptor with --passphrase-fd N; nothing was sent"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("an encrypted key without a terminal: %v; want %q", err, want)
		}
		if rest, _ := io.ReadAll(ceremonyInput); string(rest) != "typed on stdin\n" {
			t.Fatalf("stdin was read: %q left", rest)
		}
	})
	t.Run("encrypted_passphrase_fd_ok", func(t *testing.T) {
		path, _ := writeKeyPEM(t, newEd(t), machineKeyPass)
		fd, _ := passPipe(t, machineKeyPass)
		k, data, err := loadKey(path, fd)
		if err != nil {
			t.Fatalf("the passphrase on a descriptor: %v", err)
		}
		defer k.wipe(data)
		if _, err := k.signer.Sign(rand.Reader, []byte("message")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wrong_passphrase_no_secret_in_output", func(t *testing.T) {
		path, data := writeKeyPEM(t, newEd(t), machineKeyPass)
		fd, _ := passPipe(t, "the wrong passphrase here")
		_, _, err := loadKey(path, fd)
		if err == nil || !strings.Contains(err.Error(), "the passphrase for "+path+" is wrong") {
			t.Fatalf("a wrong passphrase: %v", err)
		}
		requireNoSecret(t, err.Error(), data, "the wrong passphrase here", machineKeyPass)
	})
	t.Run("parse_clears_buffers", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		path, _ := writeKeyPEM(t, newEd(t), machineKeyPass)
		fd, _ := passPipe(t, machineKeyPass)
		calls := 0
		prev := machineKeyBufferHook
		machineKeyBufferHook = func(file, pass, ed []byte) {
			calls++
			// The clear point is right after the signing, before the
			// request leaves (pre-merge review 1, 03-11b).
			if n := e.renewCount(); n != 0 {
				t.Errorf("the buffers were cleared after the stub received %d request(s); want before the request is sent", n)
			}
			for name, b := range map[string][]byte{"file buffer": file, "passphrase": pass, "Ed25519 key": ed} {
				if len(b) == 0 || bytes.Count(b, []byte{0}) != len(b) {
					t.Errorf("the %s (%d bytes) is not cleared", name, len(b))
				}
			}
		}
		t.Cleanup(func() { machineKeyBufferHook = prev })
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", path, "--passphrase-fd", strconv.Itoa(fd), "--out", filepath.Join(t.TempDir(), "c.pub"))
		if code != 0 || calls != 1 {
			t.Fatalf("exit %d, %d hook calls: %s; want 0 and 1", code, calls, stderr)
		}
	})
	t.Run("sk_key_file_named_error", func(t *testing.T) {
		for _, encrypted := range []bool{false, true} {
			name := map[bool]string{false: "unencrypted", true: "encrypted"}[encrypted]
			t.Run(name, func(t *testing.T) {
				path, pub := skKeyFile(t, encrypted)
				fd, r := passPipe(t, machineKeyPass)
				_, _, err := loadKey(path, fd)
				if err == nil {
					t.Fatal("an sk key file was accepted")
				}
				for _, want := range []string{"is a security key (" + ssh.KeyAlgoSKED25519 + ")", "signs only through ssh-agent", "ssh-add",
					"--agent-key " + ssh.FingerprintSHA256(pub), "asks for a touch at every renewal", "unattended renewal needs an Ed25519 or ECDSA key"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("the sk refusal lacks %q: %v", want, err)
					}
				}
				if !unread(t, r, machineKeyPass) {
					t.Fatal("a passphrase was read for an sk key file")
				}
			})
		}
	})
	t.Run("rsa_key_refused", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		path, _ := writeKeyPEM(t, k, "")
		if _, _, err := loadKey(path, -1); err == nil || !strings.Contains(err.Error(), "RSA keys are not machine keys") {
			t.Fatalf("an RSA key: %v", err)
		}
	})
	t.Run("ecdsa_keys_sign", func(t *testing.T) {
		for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
			k, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			path, _ := writeKeyPEM(t, k, "")
			mk, data, err := loadKey(path, -1)
			if err != nil {
				t.Fatalf("%s: %v", c.Params().Name, err)
			}
			if _, err := mk.signer.Sign(rand.Reader, []byte("message")); err != nil {
				t.Fatalf("%s: %v", c.Params().Name, err)
			}
			mk.wipe(data)
		}
	})
	t.Run("not_a_private_key_refused", func(t *testing.T) {
		s, err := ssh.NewSignerFromKey(newEd(t))
		if err != nil {
			t.Fatal(err)
		}
		junk := make([]byte, 300)
		if _, err := rand.Read(junk); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"public key": ssh.MarshalAuthorizedKey(s.PublicKey()), "random bytes": junk} {
			path := filepath.Join(t.TempDir(), "id_x")
			writeTestFile(t, path, data)
			_, _, err := loadKey(path, -1)
			if err == nil || !strings.Contains(err.Error(), path+" is not an OpenSSH or PEM private key") {
				t.Fatalf("%s: %v", name, err)
			}
			requireNoSecret(t, err.Error(), data)
		}
	})
	t.Run("no_secret_in_any_error", func(t *testing.T) {
		ed := newEd(t)
		encPath, encData := writeKeyPEM(t, ed, machineKeyPass)
		skPath, _ := skKeyFile(t, true)
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaPath, rsaData := writeKeyPEM(t, rk, "")
		var texts []string
		for _, tc := range []struct {
			path string
			pass string
		}{{encPath, ""}, {encPath, "a wrong passphrase value"}, {skPath, machineKeyPass}, {rsaPath, ""}} {
			fd := -1
			if tc.pass != "" {
				fd, _ = passPipe(t, tc.pass)
			}
			if _, _, err := loadKey(tc.path, fd); err != nil {
				texts = append(texts, err.Error())
			} else {
				t.Fatalf("%s was accepted", tc.path)
			}
		}
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		fd, _ := passPipe(t, "a wrong passphrase value")
		_, stdout, stderr := run(t, "machine", "renew", "ci", "--key", encPath, "--passphrase-fd", strconv.Itoa(fd), "--out", filepath.Join(t.TempDir(), "c.pub"))
		texts = append(texts, stdout, stderr)
		for _, s := range texts {
			requireNoSecret(t, s, encData, rsaData, ed.Seed(), machineKeyPass, "a wrong passphrase value")
		}
	})
}

// requireNoSecret fails when s holds any of the secrets (bytes or text),
// or a 16-byte run of a byte secret.
func requireNoSecret(t *testing.T, s string, secrets ...any) {
	t.Helper()
	for _, sec := range secrets {
		var b []byte
		switch v := sec.(type) {
		case string:
			b = []byte(v)
		case []byte:
			b = v
		}
		for i := 0; i+16 <= len(b); i += 16 {
			if strings.Contains(s, string(b[i:i+16])) {
				t.Fatalf("the output holds secret bytes: %q", s)
			}
		}
		if len(b) < 16 && len(b) > 0 && strings.Contains(s, string(b)) {
			t.Fatalf("the output holds a secret: %q", s)
		}
	}
}

// FuzzMachineKeyFile: parseMachineKey never panics, never returns a signer
// for a file whose clear header is an sk key, and never reads a passphrase
// when fd is -1 and stdin is not a terminal; readMachineKeyFile never
// returns more than 64 KiB.
func FuzzMachineKeyFile(f *testing.F) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pem.EncodeToMemory(block))
	if block, err = ssh.MarshalPrivateKeyWithPassphrase(k, "", []byte(machineKeyPass)); err != nil {
		f.Fatal(err)
	}
	f.Add(pem.EncodeToMemory(block))
	// A header with nothing after the magic.
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte(opensshKeyMagic)}))
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	f.Cleanup(func() { stdinIsTerminal = prev })
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxMachineKeyFileBytes {
			p := filepath.Join(t.TempDir(), "k")
			writeTestFile(t, p, data)
			if got, err := readMachineKeyFile(p); err == nil || got != nil {
				t.Fatalf("a %d-byte file was read", len(data))
			}
			return
		}
		raw := bytes.Clone(data)
		k, err := parseMachineKey(raw, "k", -1)
		if pub := machineKeyHeaderPub(data); pub != nil && (pub.Type() == ssh.KeyAlgoSKED25519 || pub.Type() == ssh.KeyAlgoSKECDSA256) && err == nil {
			t.Fatal("a signer for an sk key file")
		}
		if err == nil {
			if k.signer == nil {
				t.Fatal("no signer and no error")
			}
			k.wipe(raw)
		} else if strings.Contains(err.Error(), "rootceremony") {
			t.Fatalf("a passphrase was asked for: %v", err)
		}
	})
}
