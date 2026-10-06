//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// doctorState is a state directory initialised by ca-init with the agent
// backend, its five role keys held by an in-process ssh-agent.
type doctorState struct {
	dir string
	db  string
}

// newDoctorState runs ca-init (in process, through dispatch) against an
// in-process ssh-agent with five generated Ed25519 keys. No bundle is
// installed.
func newDoctorState(t *testing.T) doctorState {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("doctor refuses to run as root; run the tests as a normal user")
	}
	// Unix socket paths are limited to 108 bytes; t.TempDir() can be longer.
	sockDir, err := os.MkdirTemp("", "krdoc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	keyring := agent.NewKeyring()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = agent.ServeAgent(keyring, c)
			}()
		}
	}()

	args := []string{"ca-init", "--backend", "agent", "--backend-opt", "socket=" + sock}
	for _, role := range []string{"user", "host", "machine", "ops", "log"} {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: role}); err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "--key", role+"="+ssh.FingerprintSHA256(signer.PublicKey()))
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	args = append(args, "--state-dir", dir)
	if code, out := runSigner(t, args...); code != 0 {
		t.Fatalf("ca-init exited %d:\n%s", code, out)
	}
	return doctorState{dir: dir, db: filepath.Join(dir, "signer.db")}
}

// runSigner runs a keyroster-signer command in process and returns its exit
// status and combined output.
func runSigner(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := dispatch(context.Background(), args, &out, &out)
	return code, out.String()
}

func (s doctorState) doctor(t *testing.T) (int, string) {
	t.Helper()
	return runSigner(t, "doctor", "--state-dir", s.dir)
}

// exec runs one SQL statement on the state database, as tampering outside
// the signer would.
func (s doctorState) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", s.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

var doctorLine = regexp.MustCompile(`^(OK|INFO|WARN|FAIL) [a-z0-9_]+: \S.*$`)

func requireLine(t *testing.T, out, prefix string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return
		}
	}
	t.Fatalf("no line starting with %q in doctor output:\n%s", prefix, out)
}

func TestDoctorAfterCAInit(t *testing.T) {
	s := newDoctorState(t)
	code, out := s.doctor(t)
	if code != 0 {
		t.Fatalf("doctor exited %d, want 0:\n%s", code, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for _, line := range lines {
		if !doctorLine.MatchString(line) {
			t.Errorf("line %q is not LEVEL code: message", line)
		}
	}
	requireLine(t, out, "OK db_integrity:")
	requireLine(t, out, "OK log:")
	requireLine(t, out, "OK clock:")
	requireLine(t, out, "WARN no_bundle:")
	requireLine(t, out, "WARN software_key_in_agent:")
	if strings.Contains(out, "FAIL ") {
		t.Fatalf("unexpected FAIL:\n%s", out)
	}
}

func TestDoctorFailures(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, s doctorState)
		want   string
	}{
		{"state dir 0750", func(t *testing.T, s doctorState) {
			if err := os.Chmod(s.dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}, "FAIL state_dir_permissions:"},
		{"db 0644", func(t *testing.T, s doctorState) {
			if err := os.Chmod(s.db, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "FAIL db_permissions:"},
		{"leaf modified", func(t *testing.T, s doctorState) {
			s.exec(t, `UPDATE log_leaf SET leaf = leaf || x'00' WHERE idx = 0`)
		}, "FAIL log_mismatch:"},
		{"leaf deleted", func(t *testing.T, s doctorState) {
			s.exec(t, `DELETE FROM log_leaf WHERE idx = 0`)
		}, "FAIL log_mismatch:"},
		{"serial high-water an hour ahead of the clock", func(t *testing.T, s doctorState) {
			s.exec(t, `UPDATE serial_state SET last_serial = ? WHERE id = 1`, time.Now().Add(time.Hour).UnixMicro())
		}, "FAIL clock_regression:"},
		{"database missing", func(t *testing.T, s doctorState) {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if err := os.Remove(s.db + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
		}, "FAIL db_integrity:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newDoctorState(t)
			tc.tamper(t, s)
			code, out := s.doctor(t)
			if code != 1 {
				t.Fatalf("doctor exited %d, want 1:\n%s", code, out)
			}
			requireLine(t, out, tc.want)
		})
	}
}

func TestDoctorDoesNotCreateADatabase(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("doctor refuses to run as root")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out := runSigner(t, "doctor", "--state-dir", dir)
	if code != 1 {
		t.Fatalf("doctor on an empty state dir exited %d, want 1:\n%s", code, out)
	}
	requireLine(t, out, "FAIL db_integrity:")
	if _, err := os.Stat(filepath.Join(dir, "signer.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor created signer.db (stat err %v); it must only read", err)
	}
}

func TestDoctorUsage(t *testing.T) {
	for _, args := range [][]string{{"doctor"}, {"doctor", "--state-dir", t.TempDir(), "extra"}} {
		if code, out := runSigner(t, args...); code != 2 {
			t.Fatalf("%v exited %d, want 2:\n%s", args, code, out)
		}
	}
}

// TestDoctorImports pins that doctor opens no network connection and runs
// no program: doctor.go imports neither os/exec nor any net package.
func TestDoctorImports(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "doctor.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if path == "os/exec" || path == "net" || strings.HasPrefix(path, "net/") {
			t.Errorf("doctor.go imports %s", path)
		}
	}
}
