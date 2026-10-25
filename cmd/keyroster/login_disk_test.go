package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestLoginNeverWritesKey: keyroster login never writes its ephemeral
// private key to disk (the 02-12 prohibition, disk half; 03-02). A complete
// login runs with HOME, the user config directory, the temporary directory
// and the working directory all pointed at fresh empty directories (the
// config is copied in first). Afterwards no file under them holds the
// key's 32-byte seed raw, as lowercase hex, as standard base64 or as
// base64url, its PKCS#8 or OpenSSH encoding, or the text "PRIVATE KEY".
// The key is taken from the agent add, the one place it is meant to go.
func TestLoginNeverWritesKey(t *testing.T) {
	e := newLoginServer(t)
	a := useRecordingAgent(t)
	cfgPath, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg := readTestFile(t, cfgPath)

	// Fresh directories for everything the CLI could write to, and the
	// real os.UserConfigDir, so the config is found where the platform puts
	// it under them.
	home, xdg, appData, tmp, cwd := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	dirs := []string{home, xdg, appData, tmp, cwd}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("APPDATA", appData)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	t.Chdir(cwd)
	prev := userConfigDir
	userConfigDir = os.UserConfigDir
	t.Cleanup(func() { userConfigDir = prev })
	cfgPath, err = configPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, cfgPath, cfg)

	stderr, wait := e.start(t)
	e.drive(t, stderr)
	if r := wait(); r.code != 0 {
		t.Fatalf("keyroster login exit %d:\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	adds := a.added()
	if len(adds) != 1 {
		t.Fatalf("agent adds = %d, want 1", len(adds))
	}
	var priv ed25519.PrivateKey
	switch k := adds[0].PrivateKey.(type) {
	case ed25519.PrivateKey:
		priv = k
	case *ed25519.PrivateKey:
		priv = *k
	default:
		t.Fatalf("the agent got a %T, want an Ed25519 private key", adds[0].PrivateKey)
	}
	seed := priv.Seed()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	openssh, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	forms := map[string][]byte{
		"raw seed":       seed,
		"hex seed":       []byte(hex.EncodeToString(seed)),
		"base64 seed":    []byte(base64.RawStdEncoding.EncodeToString(seed)), // the padded form contains it
		"base64url seed": []byte(base64.RawURLEncoding.EncodeToString(seed)),
		"PKCS#8 DER":     pkcs8,
		// An Ed25519 PKCS#8 key is 48 bytes, so its whole base64 is the
		// first PEM body line.
		"PKCS#8 PEM body":  []byte(base64.StdEncoding.EncodeToString(pkcs8)),
		"OpenSSH key blob": openssh.Bytes,
		// The first PEM body line of an unencrypted OpenSSH Ed25519 key is
		// the same for every such key, so this matches any of them.
		"OpenSSH PEM body (any Ed25519 key)": []byte(base64.StdEncoding.EncodeToString(openssh.Bytes)[:64]),
		"PRIVATE KEY header":                 []byte("PRIVATE KEY"),
	}
	if !bytes.Contains(pem.EncodeToMemory(openssh), []byte("PRIVATE KEY")) {
		t.Fatal("the OpenSSH PEM form lacks its header; the header check would prove nothing")
	}
	scanned := 0
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, de os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				return nil
			}
			scanned++
			data, err := os.ReadFile(p) //nolint:gosec // G304: a file under the test's own directories
			if err != nil {
				return err
			}
			for name, f := range forms {
				if bytes.Contains(data, f) {
					t.Errorf("%s holds the login key (%s)", p, name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned == 0 {
		t.Fatal("no file was scanned; the copied config should be one")
	}
}
