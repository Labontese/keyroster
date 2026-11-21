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

	"github.com/Labontese/keyroster/internal/doctor"
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
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
			if err := os.Chmod(s.dir, 0o750); err != nil { //nolint:gosec // G302: the test widens the mode on purpose
				t.Fatal(err)
			}
		}, "FAIL state_dir_permissions:"},
		{"db 0644", func(t *testing.T, s doctorState) {
			if err := os.Chmod(s.db, 0o644); err != nil { //nolint:gosec // G302: the test widens the mode on purpose
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
		// C-WR-01: the same edit without an issue entry for that serial
		// contradicts the log.
		{"serial high-water raised outside the signer", func(t *testing.T, s doctorState) {
			s.exec(t, `UPDATE serial_state SET last_serial = ? WHERE id = 1`, time.Now().Add(time.Hour).UnixMicro())
		}, "FAIL log_mismatch:"},
		// T-02-14: a directory row the log records no directory_install
		// entry for, which serve refuses to start on.
		{"directory row without a log entry", func(t *testing.T, s doctorState) {
			s.exec(t, `INSERT INTO directory (version, doc, sigs, policy_version, installed_at_us) VALUES (1, 'x', 'x', 1, 1)`)
		}, "FAIL trust_mismatch:"},
		{"log wiped", func(t *testing.T, s doctorState) {
			s.exec(t, `DELETE FROM log_leaf`)
			s.exec(t, `DELETE FROM checkpoint`)
		}, "FAIL log_mismatch:"},
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

// TestDoctorGenerationsAndMarker (03-12): after a prepare, doctor lists the
// user role's generations, the new one as prepared.
func TestDoctorGenerationsAndMarker(t *testing.T) {
	st, _ := bootstrapped(t)
	if code, out := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", st.addKey(t),
		"--out", filepath.Join(t.TempDir(), "g2.json")); code != 0 {
		t.Fatalf("prepare exited %d:\n%s", code, out)
	}
	code, out := runSigner(t, "doctor", "--state-dir", st.dir)
	if code != 0 {
		t.Fatalf("doctor exited %d:\n%s", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "OK generations: ") {
			if !strings.Contains(line, "prepared g2") || !strings.Contains(line, "active g1") {
				t.Fatalf("the generations line does not list the user role's generations: %s", line)
			}
			return
		}
	}
	t.Fatalf("doctor printed no OK generations line:\n%s", out)
}

// TestDoctorUnrecordedGenerationFile (03-12): a {state-dir}/software
// <role>-g<N>.age file that no generation row names is a WARN naming it;
// a recorded one, or no software directory, gives none. doctor lists names
// only, so the files may be empty.
func TestDoctorUnrecordedGenerationFile(t *testing.T) {
	soft := func(t *testing.T, dir string, names ...string) {
		t.Helper()
		d := filepath.Join(dir, "software")
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(d, n), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("stray_file_warns", func(t *testing.T) {
		st, _ := bootstrapped(t)
		soft(t, st.dir, "user-g3.age")
		code, out := runSigner(t, "doctor", "--state-dir", st.dir)
		if code != 0 {
			t.Fatalf("doctor exited %d:\n%s", code, out)
		}
		requireLine(t, out, "WARN unrecorded_generation_file: ")
		if !strings.Contains(out, filepath.Join(st.dir, "software", "user-g3.age")) {
			t.Fatalf("the warning does not name the file:\n%s", out)
		}
	})
	t.Run("recorded_file_no_warn", func(t *testing.T) {
		st, _ := bootstrapped(t)
		if code, out := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", st.addKey(t),
			"--out", filepath.Join(t.TempDir(), "g2.json")); code != 0 {
			t.Fatalf("prepare exited %d:\n%s", code, out)
		}
		soft(t, st.dir, "user-g2.age")
		code, out := runSigner(t, "doctor", "--state-dir", st.dir)
		if code != 0 || strings.Contains(out, "unrecorded_generation_file") {
			t.Fatalf("doctor exited %d:\n%s", code, out)
		}
	})
	t.Run("tpm_stray_files_warn", func(t *testing.T) {
		// 03-12f: {state-dir}/tpm <role>-g<N>.tpmkey and .auth files with
		// N of at least 2 are read the same way: recorded ones give no
		// warning, unrecorded ones are named.
		st, _ := bootstrapped(t)
		if code, out := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", st.addKey(t),
			"--out", filepath.Join(t.TempDir(), "g2.json")); code != 0 {
			t.Fatalf("prepare exited %d:\n%s", code, out)
		}
		d := filepath.Join(st.dir, "tpm")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		put := func(t *testing.T, names ...string) {
			t.Helper()
			for _, n := range names {
				if err := os.WriteFile(filepath.Join(d, n), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		put(t, "user-g2.tpmkey", "user-g2.auth")
		if code, out := runSigner(t, "doctor", "--state-dir", st.dir); code != 0 || strings.Contains(out, "unrecorded_generation_file") {
			t.Fatalf("doctor with the recorded generation's TPM files exited %d:\n%s", code, out)
		}
		put(t, "user-g3.tpmkey", "user-g3.auth")
		code, out := runSigner(t, "doctor", "--state-dir", st.dir)
		if code != 0 {
			t.Fatalf("doctor exited %d:\n%s", code, out)
		}
		requireLine(t, out, "WARN unrecorded_generation_file: ")
		for _, n := range []string{"user-g3.tpmkey", "user-g3.auth"} {
			if !strings.Contains(out, filepath.Join(d, n)) {
				t.Fatalf("the warning does not name %s:\n%s", n, out)
			}
		}
	})
	t.Run("no_software_dir_no_warning", func(t *testing.T) {
		st, _ := bootstrapped(t)
		code, out := runSigner(t, "doctor", "--state-dir", st.dir)
		if code != 0 || strings.Contains(out, "unrecorded_generation_file") || strings.Contains(out, "FAIL ") {
			t.Fatalf("doctor exited %d:\n%s", code, out)
		}
	})
}

// TestDoctorDrainingTrustedUntil (03-12c): a stored generation whose key
// the installed bundle lists as draining shows the entry's trusted_until
// on the OK generations line. The signer refuses to install a draining
// bundle until 03-12e, so the bundle is built by hand and goes through
// generationFacts and doctor.Run directly.
func TestDoctorDrainingTrustedUntil(t *testing.T) {
	key := func() ssh.PublicKey {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return s.PublicKey()
	}
	k1, k2 := key(), key()
	const end = "2026-10-20T00:00:00Z"
	b := &trust.Bundle{CAs: []trust.CAEntry{
		{Role: trust.RoleUser, Key: trust.FormatKey(k1), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "draining", Generation: 1, TrustedUntil: end},
		{Role: trust.RoleUser, Key: trust.FormatKey(k2), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "active", Generation: 2},
	}}
	gens := []signerdb.CAGeneration{
		{Role: trust.RoleUser, Generation: 1, PublicKey: k1.Marshal(), Alg: ssh.KeyAlgoED25519, Custody: "software"},
		{Role: trust.RoleUser, Generation: 2, PublicKey: k2.Marshal(), Alg: ssh.KeyAlgoED25519, Custody: "software"},
	}
	var line string
	for _, r := range doctor.Run(doctor.Facts{Generations: generationFacts(gens, b)}) {
		if r.Code == "generations" {
			line = r.Line()
		}
	}
	for _, want := range []string{"OK", "draining g1 " + ssh.FingerprintSHA256(k1) + " until " + end, "active g2 " + ssh.FingerprintSHA256(k2)} {
		if !strings.Contains(line, want) {
			t.Fatalf("the generations line %q lacks %q", line, want)
		}
	}
}

// issueUserCert issues one user certificate through s, signed by g's
// admin, and returns it (03-12e).
func issueUserCert(t *testing.T, s *signer.Signer, g genesisDocs) *ssh.Certificate {
	t.Helper()
	req := &wire.IssueRequest{CARole: wire.CARoleUser, SubjectKey: newTestSigner(t).PublicKey().Marshal(), Subject: "u:alice", Principals: []string{"alice"},
		ValidForSeconds: 600, CreatedAt: uint64(time.Now().Unix()), InstallationID: g.b.InstallationID} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, g.admin, req.Namespace(), req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	resp, err := s.Issue(context.Background(), signer.Peer{UID: uint32(os.Getuid())}, req) //nolint:gosec // G115: a uid
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	pub, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("the response holds a %T, not a certificate", pub)
	}
	return c
}

// TestDoctorSwitch (03-12e, SR-08 and SR-09, the command): after a switch
// install doctor fails draining_key_still_usable while the backend holds
// the draining key, the software backend by its file (no passphrase) and
// the agent backend through the stored socket; it warns
// draining_key_unchecked when the agent cannot be reached; after
// retire-key, or with an agent that no longer lists the key, it gives no
// such line and exits 0. Per CA role with an active key, gatherFacts reads
// from the verified log the certificate that sets the earliest
// trusted_until a switch could carry, which doctor prints.
func TestDoctorSwitch(t *testing.T) {
	held := func(fp string) string {
		return "FAIL draining_key_still_usable: user generation 1 " + fp + " is still held by the backend\n"
	}
	doctorRun := func(t *testing.T, st *rotateState) (int, string) {
		t.Helper()
		return runSigner(t, "doctor", "--state-dir", st.dir)
	}
	t.Run("held_software_key_fails", func(t *testing.T) {
		st, fp1, _ := softwareSwitchState(t)
		if code, out := doctorRun(t, st); code == 0 || !strings.Contains(out, held(fp1)) {
			t.Fatalf("doctor with the draining key file present exited %d, want 1 with\n%s\ngot:\n%s", code, held(fp1), out)
		}
	})
	t.Run("agent_backend_held_fails", func(t *testing.T) {
		st, fp1 := agentSwitchState(t)
		if code, out := doctorRun(t, st); code == 0 || !strings.Contains(out, held(fp1)) {
			t.Fatalf("doctor while the agent lists the draining key exited %d, want 1 with\n%s\ngot:\n%s", code, held(fp1), out)
		}
	})
	// asTPM rewrites st's stored backend name to tpm, as
	// TestRetireKey/unsupported_backend_refused rewrites it, and makes a
	// private tpm key directory holding the given empty files (03-12f).
	// doctor checks a TPM generation by its files and opens no TPM for it;
	// its TPM inspection then fails on the agent options, which these
	// cases do not assert.
	asTPM := func(t *testing.T, st *rotateState, names ...string) {
		t.Helper()
		db, err := sql.Open("sqlite", st.db)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`UPDATE backend_config SET name = ? WHERE id = 1`, "tpm")
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(st.dir, "tpm")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(d, n), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("tpm_held_fails", func(t *testing.T) {
		st, fp1 := agentSwitchState(t)
		asTPM(t, st, "user.auth")
		if code, out := doctorRun(t, st); code == 0 || !strings.Contains(out, held(fp1)) {
			t.Fatalf("doctor with generation 1's TPM auth file present exited %d, want 1 with\n%s\ngot:\n%s", code, held(fp1), out)
		}
	})
	t.Run("tpm_removed_clean", func(t *testing.T) {
		st, _ := agentSwitchState(t)
		asTPM(t, st)
		if _, out := doctorRun(t, st); strings.Contains(out, "draining_key_") {
			t.Fatalf("doctor with generation 1's TPM files gone reports a draining key:\n%s", out)
		}
	})
	t.Run("agent_unreachable_warns", func(t *testing.T) {
		st, fp1 := agentSwitchState(t)
		if err := os.Remove(st.sock); err != nil {
			t.Fatal(err)
		}
		_, out := doctorRun(t, st)
		requireLine(t, out, "WARN draining_key_unchecked: user generation 1 "+fp1+": ")
		if strings.Contains(out, "draining_key_still_usable") {
			t.Fatalf("doctor reports the unreachable agent's key as held:\n%s", out)
		}
	})
	t.Run("floor_line_names_the_certificate", func(t *testing.T) {
		st := newRotateState(t)
		g := genesisFiles(t, st)
		install(t, st, g)
		c := issueUserCert(t, startSigner(t, st), g)
		f := gatherFacts(context.Background(), st.dir, nil)
		var user, host *doctor.SwitchFloor
		for i := range f.SwitchFloors {
			switch f.SwitchFloors[i].Role {
			case trust.RoleUser:
				user = &f.SwitchFloors[i]
			case trust.RoleHost:
				host = &f.SwitchFloors[i]
			}
		}
		want := doctor.SwitchFloor{Role: trust.RoleUser, Generation: 1, HasCertificate: true, Serial: c.Serial, KeyID: c.KeyId, ValidBefore: c.ValidBefore}
		if user == nil || *user != want {
			t.Fatalf("the user CA's switch floor is %+v, want %+v (facts %+v)", user, want, f.SwitchFloors)
		}
		if host == nil || host.HasCertificate || host.Generation != 1 {
			t.Fatalf("the host CA's switch floor is %+v, want generation 1 with no certificate", host)
		}
		_, out := doctorRun(t, st)
		line := "OK switch_floor: user generation 1: the certificate that sets the earliest trusted_until a switch could carry is serial " +
			strconv.FormatUint(c.Serial, 10) + " (key ID " + c.KeyId + ", valid until " + time.Unix(int64(c.ValidBefore), 0).UTC().Format(trust.TimeFormat) + //nolint:gosec // G115: a ValidBefore of this test
			"); the earliest is " + time.Unix(int64(c.ValidBefore)+300, 0).UTC().Format(trust.TimeFormat) + "\n" //nolint:gosec // G115: a ValidBefore of this test
		if !strings.Contains(out, line) {
			t.Fatalf("doctor does not print\n%s\ngot:\n%s", line, out)
		}
	})
	t.Run("draining_not_held_ok", func(t *testing.T) {
		st, _, _ := softwareSwitchState(t)
		if code, out := retireKey(t, st, "user"); code != 0 {
			t.Fatalf("retire-key exited %d:\n%s", code, out)
		}
		if code, out := doctorRun(t, st); code != 0 || strings.Contains(out, "draining_key_still_usable") {
			t.Fatalf("doctor after retire-key exited %d:\n%s", code, out)
		}
	})
	t.Run("agent_backend_not_held_ok", func(t *testing.T) {
		st, fp1 := agentSwitchState(t)
		user, _ := st.caPubKeys(t).Key(trust.RoleUser)
		pub1, err := trust.ParseKey(user.Key)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.keyring.Remove(pub1); err != nil {
			t.Fatal(err)
		}
		code, out := doctorRun(t, st)
		if code != 0 || strings.Contains(out, "draining_key_still_usable") || strings.Contains(out, "draining_key_unchecked") {
			t.Fatalf("doctor with an agent that no longer lists %s exited %d:\n%s", fp1, code, out)
		}
	})
}
