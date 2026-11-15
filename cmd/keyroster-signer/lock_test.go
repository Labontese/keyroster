//go:build linux

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/signer"
)

// TestStateDirLock (A-CR-01, C-CR-01): serve, ca-init and install-bundle
// share one exclusive lock on the state directory, so install-bundle and
// ca-init refuse while the service runs, and a second serve refuses too.
func TestStateDirLock(t *testing.T) {
	st := newDoctorState(t)
	unlock, err := lockStateDir(st.dir)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := lockStateDir(st.dir); !errors.Is(err, errStateLocked) {
		if again != nil {
			again()
		}
		t.Fatalf("second lock = %v, want errStateLocked", err)
	}

	// install-bundle reads its documents first; the lock refusal comes
	// before any of them is parsed and before the backend is opened.
	docs := t.TempDir()
	for _, name := range []string{"bundle.json", "bundle.json.sigs", "policy.json", "policy.json.sigs"} {
		if err := os.WriteFile(filepath.Join(docs, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, args := range map[string][]string{
		"install-bundle": {"install-bundle", "--state-dir", st.dir,
			"--bundle", filepath.Join(docs, "bundle.json"), "--policy", filepath.Join(docs, "policy.json")},
		"ca-init": {"ca-init", "--state-dir", st.dir, "--backend", "agent", "--out", filepath.Join(docs, "ca-pubkeys.json")},
		"serve":   {"serve", "--state-dir", st.dir, "--socket", filepath.Join(docs, "s.sock"), "--allow-uid", "1"},
	} {
		code, out := runSigner(t, args...)
		if code != 1 || !strings.Contains(out, errStateLocked.Error()) || !strings.Contains(out, "stop the service first") {
			t.Fatalf("%s with the state directory locked exited %d, want 1 and the lock refusal:\n%s", name, code, out)
		}
	}
	if _, err := os.Stat(filepath.Join(docs, "ca-pubkeys.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ca-init wrote its output although the state directory was locked: %v", err)
	}

	unlock()
	relock, err := lockStateDir(st.dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	relock()
}

// bootstrapped returns a state initialised with the agent backend and the
// genesis bundle installed (03-12).
func bootstrapped(t *testing.T) (*rotateState, genesisDocs) {
	t.Helper()
	st := newRotateState(t)
	g := genesisFiles(t, st)
	install(t, st, g)
	return st, g
}

func writeMarker(t *testing.T, dir string) string {
	t.Helper()
	m := filepath.Join(dir, restoreMarkerName)
	if err := os.WriteFile(m, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

func markerExists(t *testing.T, m string) bool {
	t.Helper()
	_, err := os.Lstat(m)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// listenJournal points journalSocketPath at a unixgram listener in a short
// temporary directory and returns a function that drains the datagrams it
// received so far.
func listenJournal(t *testing.T) func() []string {
	t.Helper()
	dir, err := os.MkdirTemp("", "krj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "j.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	old := journalSocketPath
	journalSocketPath = path
	t.Cleanup(func() { journalSocketPath = old })
	return func() []string {
		var out []string
		buf := make([]byte, 64<<10)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			n, err := conn.Read(buf)
			if err != nil {
				return out
			}
			out = append(out, string(buf[:n]))
		}
	}
}

// fakeRecovery replaces applyRecovery for one test.
func fakeRecovery(t *testing.T, res *signer.RecoveryResult, err error) {
	t.Helper()
	old := applyRecovery
	applyRecovery = func(context.Context, *signer.Signer, []byte) (*signer.RecoveryResult, error) { return res, err }
	t.Cleanup(func() { applyRecovery = old })
}

// recoverIn runs the recovery in process with in as standard input.
func recoverIn(t *testing.T, dir, in string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := recoverRevocations(context.Background(), strings.NewReader(in), dir, nil, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

// withBlockedStdin makes os.Stdin a pipe that never delivers data, so a
// command that reads it would block, and returns a function that runs a
// command with a deadline.
func withBlockedStdin(t *testing.T) func(args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; _ = w.Close(); _ = r.Close() })
	return func(args ...string) (int, string) {
		type result struct {
			code int
			out  string
		}
		done := make(chan result, 1)
		go func() {
			code, out := runSigner(t, args...)
			done <- result{code, out}
		}()
		select {
		case res := <-done:
			return res.code, res.out
		case <-time.After(20 * time.Second):
			t.Fatalf("%v blocked: it reads standard input", args)
			return 0, ""
		}
	}
}

// freshStateDir is an empty 0700 state directory.
func freshStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// tableCounts returns the row count of every table of the database.
func tableCounts(t *testing.T, path string) map[string]int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	out := map[string]int{}
	for _, n := range names {
		var c int
		if err := db.QueryRow(`SELECT count(*) FROM "` + n + `"`).Scan(&c); err != nil { //nolint:gosec // G202: a table name from sqlite_master
			t.Fatal(err)
		}
		out[n] = c
	}
	return out
}

func dirNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		out[e.Name()] = true
	}
	return out
}

func exportBytes(t *testing.T, st *rotateState) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "export.jsonl")
	if code, msg := runSigner(t, "export-log", "--state-dir", st.dir, "--out", out); code != 0 {
		t.Fatalf("export-log exited %d:\n%s", code, msg)
	}
	data, err := os.ReadFile(out) //nolint:gosec // G304: the test's own export file
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestRestoreMarker (03-12): with restore-recovery-pending in the state
// directory, every writer of the state refuses restore_recovery_pending
// (the gate is in lockStateDir), recover-revocations runs under it and
// removes it after a successful recovery, --no-recovery-needed removes it
// explicitly, --migrate-only migrates signer.db under it and keeps it,
// doctor fails and export-log still works.
func TestRestoreMarker(t *testing.T) {
	ctx := context.Background()
	refused := func(t *testing.T, code int, out string) {
		t.Helper()
		if code != 1 || !strings.Contains(out, "restore_recovery_pending") || !strings.Contains(out, "recover-revocations") {
			t.Fatalf("exit %d, want 1 and the restore_recovery_pending refusal:\n%s", code, out)
		}
	}
	t.Run("install_refused_under_restore_marker", func(t *testing.T) {
		st, g := bootstrapped(t)
		writeMarker(t, st.dir)
		leaves := st.count(t, "SELECT count(*) FROM log_leaf")
		code, out := runSigner(t, "install-bundle", "--state-dir", st.dir, "--bundle", g.bundle, "--policy", g.policy)
		refused(t, code, out)
		if n := st.count(t, "SELECT count(*) FROM log_leaf"); n != leaves {
			t.Fatalf("%d leaves after the refusal, want %d", n, leaves)
		}
	})
	t.Run("serve_refused_under_restore_marker", func(t *testing.T) {
		st, _ := bootstrapped(t)
		writeMarker(t, st.dir)
		if unlock, err := lockStateDir(st.dir); !errors.Is(err, errRestorePending) {
			if unlock != nil {
				unlock()
			}
			t.Fatalf("lockStateDir under the marker = %v, want restore_recovery_pending", err)
		}
		sockDir, err := os.MkdirTemp("", "krsv")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var out bytes.Buffer
		code := dispatch(sctx, []string{"serve", "--state-dir", st.dir, "--socket", filepath.Join(sockDir, "s.sock"),
			"--allow-uid", strconv.Itoa(os.Getuid())}, &out, &out)
		refused(t, code, out.String())
	})
	t.Run("prepare_refused_under_restore_marker", func(t *testing.T) {
		st, _ := bootstrapped(t)
		writeMarker(t, st.dir)
		outFile := filepath.Join(t.TempDir(), "g2.json")
		code, out := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", st.addKey(t), "--out", outFile)
		refused(t, code, out)
		if _, err := os.Lstat(outFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("prepare left %s after the refusal (%v)", outFile, err)
		}
		if n := st.count(t, "SELECT count(*) FROM ca_key_generations"); n != 5 {
			t.Fatalf("%d generation rows after the refusal, want 5", n)
		}
	})
	t.Run("cainit_refused_under_restore_marker", func(t *testing.T) {
		dir := freshStateDir(t)
		writeMarker(t, dir)
		sock, _ := startTestAgent(t)
		code, out := runSigner(t, "ca-init", "--backend", "agent", "--backend-opt", "socket="+sock, "--state-dir", dir)
		refused(t, code, out)
		for _, name := range []string{"ca-pubkeys.json", "signer.db"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ca-init wrote %s under the marker (%v)", name, err)
			}
		}
	})
	t.Run("refused_lock_is_released", func(t *testing.T) {
		dir := freshStateDir(t)
		m := writeMarker(t, dir)
		if unlock, err := lockStateDir(dir); err == nil {
			unlock()
			t.Fatal("lockStateDir under the marker succeeded")
		}
		if err := os.Remove(m); err != nil {
			t.Fatal(err)
		}
		unlock, err := lockStateDir(dir)
		if err != nil {
			t.Fatalf("lockStateDir after the marker was removed: %v", err)
		}
		unlock()
	})
	t.Run("marker_symlink_counts", func(t *testing.T) {
		dir := freshStateDir(t)
		if err := os.Symlink(filepath.Join(dir, "no-such-target"), filepath.Join(dir, restoreMarkerName)); err != nil {
			t.Fatal(err)
		}
		if unlock, err := lockStateDir(dir); !errors.Is(err, errRestorePending) {
			if unlock != nil {
				unlock()
			}
			t.Fatalf("lockStateDir with a dangling symlink marker = %v, want restore_recovery_pending", err)
		}
	})
	t.Run("marker_is_directory_counts", func(t *testing.T) {
		dir := freshStateDir(t)
		if err := os.Mkdir(filepath.Join(dir, restoreMarkerName), 0o700); err != nil {
			t.Fatal(err)
		}
		if unlock, err := lockStateDir(dir); !errors.Is(err, errRestorePending) {
			if unlock != nil {
				unlock()
			}
			t.Fatalf("lockStateDir with a directory marker = %v, want restore_recovery_pending", err)
		}
	})
	t.Run("nonempty_directory_marker_says_remove_by_hand", func(t *testing.T) {
		st, _ := bootstrapped(t)
		m := filepath.Join(st.dir, restoreMarkerName)
		if err := os.Mkdir(m, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m, "x"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		fakeRecovery(t, &signer.RecoveryResult{}, nil)
		_, _, err := recoverIn(t, st.dir, "request")
		if err == nil || !strings.Contains(err.Error(), "remove "+m+" by hand") || !strings.Contains(err.Error(), "applied") ||
			strings.Contains(err.Error(), "--no-recovery-needed") {
			t.Fatalf("recovery under a non-empty directory marker = %v, want the applied recovery and remove-by-hand text", err)
		}
		code, out := runSigner(t, "recover-revocations", "--state-dir", st.dir, "--no-recovery-needed")
		if code != 1 || !strings.Contains(out, "remove "+m+" by hand") {
			t.Fatalf("--no-recovery-needed on a non-empty directory marker exited %d:\n%s", code, out)
		}
	})
	t.Run("recover_allowed_and_clears_marker", func(t *testing.T) {
		st, _ := bootstrapped(t)
		m := writeMarker(t, st.dir)
		journal := listenJournal(t)
		fakeRecovery(t, &signer.RecoveryResult{Entries: 1}, nil)
		stdout, stderr, err := recoverIn(t, st.dir, "request")
		if err != nil {
			t.Fatalf("recovery under the marker: %v", err)
		}
		if markerExists(t, m) {
			t.Fatal("the marker is still there after a successful recovery")
		}
		want := "restore-recovery-pending removed: " + m
		if !strings.Contains(stdout, "recovered: ") || !strings.Contains(stderr, want) {
			t.Fatalf("stdout %q, stderr %q; want the recovered line and %q", stdout, stderr, want)
		}
		if got := journal(); len(got) != 1 || !strings.Contains(got[0], "MESSAGE="+want) {
			t.Fatalf("journal datagrams %q, want one with MESSAGE=%s", got, want)
		}
	})
	t.Run("recover_refused_keeps_marker", func(t *testing.T) {
		st, _ := bootstrapped(t)
		m := writeMarker(t, st.dir)
		if _, _, err := recoverIn(t, st.dir, "not a recovery request"); err == nil || !strings.Contains(err.Error(), "recovery_malformed") {
			t.Fatalf("a malformed request = %v, want recovery_malformed", err)
		}
		if !markerExists(t, m) {
			t.Fatal("a refused recovery removed the marker")
		}
	})
	t.Run("recover_apply_error_keeps_marker", func(t *testing.T) {
		st, _ := bootstrapped(t)
		m := writeMarker(t, st.dir)
		fakeRecovery(t, nil, errors.New("injected recovery failure"))
		if _, _, err := recoverIn(t, st.dir, "request"); err == nil {
			t.Fatal("the failed recovery returned no error")
		}
		if !markerExists(t, m) {
			t.Fatal("a failed recovery removed the marker")
		}
	})
	t.Run("no_recovery_needed_clears_marker", func(t *testing.T) {
		dir := freshStateDir(t)
		m := writeMarker(t, dir)
		journal := listenJournal(t)
		run := withBlockedStdin(t)
		code, out := run("recover-revocations", "--state-dir", dir, "--no-recovery-needed")
		want := "restore-recovery-pending removed: " + m
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("--no-recovery-needed exited %d:\n%s", code, out)
		}
		if markerExists(t, m) {
			t.Fatal("--no-recovery-needed left the marker")
		}
		if _, err := os.Lstat(filepath.Join(dir, "signer.db")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("--no-recovery-needed opened a database (%v)", err)
		}
		if got := journal(); len(got) != 1 || !strings.Contains(got[0], "MESSAGE="+want) {
			t.Fatalf("journal datagrams %q, want one with MESSAGE=%s", got, want)
		}
	})
	t.Run("no_recovery_needed_without_marker_is_noop", func(t *testing.T) {
		dir := freshStateDir(t)
		journal := listenJournal(t)
		code, out := runSigner(t, "recover-revocations", "--state-dir", dir, "--no-recovery-needed")
		if code != 0 || !strings.Contains(out, "no restore-recovery-pending marker in "+dir) {
			t.Fatalf("--no-recovery-needed without a marker exited %d:\n%s", code, out)
		}
		if got := journal(); len(got) != 0 {
			t.Fatalf("journal datagrams %q, want none", got)
		}
	})
	t.Run("release_is_journaled", func(t *testing.T) {
		st, _ := bootstrapped(t)
		journal := listenJournal(t)
		check := func(t *testing.T, m string) {
			t.Helper()
			got := journal()
			if len(got) != 1 {
				t.Fatalf("journal datagrams %q, want one", got)
			}
			lines := strings.Split(got[0], "\n")
			if !slices.Contains(lines, "SYSLOG_IDENTIFIER=keyroster-signer") || !slices.Contains(lines, "PRIORITY=4") ||
				!slices.Contains(lines, "MESSAGE=restore-recovery-pending removed: "+m) {
				t.Fatalf("journal datagram %q", got[0])
			}
		}
		m := writeMarker(t, st.dir)
		fakeRecovery(t, &signer.RecoveryResult{}, nil)
		if _, _, err := recoverIn(t, st.dir, "request"); err != nil {
			t.Fatal(err)
		}
		check(t, m)
		m = writeMarker(t, st.dir)
		if code, out := runSigner(t, "recover-revocations", "--state-dir", st.dir, "--no-recovery-needed"); code != 0 {
			t.Fatalf("--no-recovery-needed exited %d:\n%s", code, out)
		}
		check(t, m)
		writeMarker(t, st.dir)
		applyRecovery = func(ctx context.Context, s *signer.Signer, data []byte) (*signer.RecoveryResult, error) {
			return s.RecoverRevocations(ctx, data)
		}
		if _, _, err := recoverIn(t, st.dir, "not a recovery request"); err == nil {
			t.Fatal("a malformed request was applied")
		}
		if got := journal(); len(got) != 0 {
			t.Fatalf("a refused recovery wrote journal datagrams %q", got)
		}
	})
	t.Run("journal_unavailable_is_not_an_error", func(t *testing.T) {
		dir := freshStateDir(t)
		m := writeMarker(t, dir)
		old := journalSocketPath
		journalSocketPath = filepath.Join(t.TempDir(), "no-journal.sock")
		t.Cleanup(func() { journalSocketPath = old })
		code, out := runSigner(t, "recover-revocations", "--state-dir", dir, "--no-recovery-needed")
		if code != 0 || markerExists(t, m) {
			t.Fatalf("--no-recovery-needed without a journal exited %d (marker left: %t):\n%s", code, markerExists(t, m), out)
		}
	})
	// PR #102 review (I3): a marker that was removed is recorded on stderr
	// and in the journal even when the fsync of the state directory then
	// fails, and the error names the fsync instead of sending the operator
	// to --no-recovery-needed, which would answer that there is no marker.
	t.Run("release_recorded_when_sync_fails", func(t *testing.T) {
		old := syncStateDir
		syncStateDir = func(string) error { return errors.New("injected fsync failure") }
		t.Cleanup(func() { syncStateDir = old })
		check := func(t *testing.T, m, out, errText string, journal func() []string) {
			t.Helper()
			if markerExists(t, m) {
				t.Fatal("the marker is still there")
			}
			want := "restore-recovery-pending removed: " + m
			if !strings.Contains(out, want) {
				t.Fatalf("stderr %q does not record the release %q", out, want)
			}
			if got := journal(); len(got) != 1 || !strings.Contains(got[0], "MESSAGE="+want) {
				t.Fatalf("journal datagrams %q, want one with MESSAGE=%s", got, want)
			}
			if !strings.Contains(errText, "injected fsync failure") || !strings.Contains(errText, "syncing") || strings.Contains(errText, "--no-recovery-needed") {
				t.Fatalf("the error %q does not name the failed fsync, or sends the operator to --no-recovery-needed", errText)
			}
		}
		t.Run("recovery", func(t *testing.T) {
			st, _ := bootstrapped(t)
			m := writeMarker(t, st.dir)
			journal := listenJournal(t)
			fakeRecovery(t, &signer.RecoveryResult{Entries: 1}, nil)
			_, stderr, err := recoverIn(t, st.dir, "request")
			if err == nil {
				t.Fatal("the recovery reported no error although the fsync failed")
			}
			check(t, m, stderr, err.Error(), journal)
		})
		t.Run("no_recovery_needed", func(t *testing.T) {
			dir := freshStateDir(t)
			m := writeMarker(t, dir)
			journal := listenJournal(t)
			code, out := runSigner(t, "recover-revocations", "--state-dir", dir, "--no-recovery-needed")
			if code == 0 {
				t.Fatalf("--no-recovery-needed exited 0 although the fsync failed:\n%s", out)
			}
			check(t, m, out, out, journal)
		})
	})
	t.Run("schema5_restore_migrates_under_marker", func(t *testing.T) {
		st, g := bootstrapped(t)
		// The backup of a build before 03-12: schema 5.
		raw, err := sql.Open("sqlite", st.db)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{`DROP TABLE ca_key_generations`, `PRAGMA user_version = 5`} {
			if _, err := raw.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}
		m := writeMarker(t, st.dir)
		for _, args := range [][]string{{"export-log", "--state-dir", st.dir, "--out", filepath.Join(t.TempDir(), "x.jsonl")}, {"doctor", "--state-dir", st.dir}} {
			if code, out := runSigner(t, args...); code != 1 || !strings.Contains(out, "has schema version 5, this binary reads 6") {
				t.Fatalf("%s on a schema-5 database exited %d:\n%s", args[0], code, out)
			}
		}
		code, out := runSigner(t, "install-bundle", "--state-dir", st.dir, "--bundle", g.bundle, "--policy", g.policy)
		refused(t, code, out)
		code, out = runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", st.addKey(t), "--out", filepath.Join(t.TempDir(), "g2.json"))
		refused(t, code, out)
		if unlock, err := lockStateDir(st.dir); !errors.Is(err, errRestorePending) {
			if unlock != nil {
				unlock()
			}
			t.Fatalf("serve's lock under the marker = %v", err)
		}
		run := withBlockedStdin(t)
		code, out = run("recover-revocations", "--state-dir", st.dir, "--migrate-only")
		if code != 0 || !strings.Contains(out, "restore-recovery-pending kept: "+m) {
			t.Fatalf("--migrate-only exited %d:\n%s", code, out)
		}
		if !markerExists(t, m) {
			t.Fatal("--migrate-only removed the marker")
		}
		if v := st.count(t, "PRAGMA user_version"); v != 6 {
			t.Fatalf("user_version %d after --migrate-only, want 6", v)
		}
		if n := st.count(t, "SELECT count(*) FROM ca_key_generations g JOIN ca_keys k ON k.role = g.role AND k.pubkey = g.pubkey AND k.alg = g.alg AND k.custody = g.custody WHERE g.generation = 1"); n != 5 {
			t.Fatalf("%d generation-1 rows equal to ca_keys after --migrate-only, want 5", n)
		}
		if _, _, err := exportAndVerify(t, st, g.rootFP); err != nil {
			t.Fatalf("audit verify of the migrated export: %v", err)
		}
		if code, out := runSigner(t, "recover-revocations", "--state-dir", st.dir, "--no-recovery-needed"); code != 0 || markerExists(t, m) {
			t.Fatalf("--no-recovery-needed exited %d:\n%s", code, out)
		}
		startSigner(t, st)
	})
	t.Run("migrate_only_writes_nothing_else", func(t *testing.T) {
		st, _ := bootstrapped(t)
		m := writeMarker(t, st.dir)
		export, counts, names := exportBytes(t, st), tableCounts(t, st.db), dirNames(t, st.dir)
		code, out := runSigner(t, "recover-revocations", "--state-dir", st.dir, "--migrate-only")
		if code != 0 || !strings.Contains(out, "migrate-only: signer.db is at the schema this binary reads; restore-recovery-pending kept: "+m) {
			t.Fatalf("--migrate-only exited %d:\n%s", code, out)
		}
		if !markerExists(t, m) {
			t.Fatal("--migrate-only removed the marker")
		}
		if !bytes.Equal(exportBytes(t, st), export) {
			t.Fatal("--migrate-only changed the export")
		}
		if got := tableCounts(t, st.db); !maps.Equal(got, counts) {
			t.Fatalf("table row counts %v after --migrate-only, want %v", got, counts)
		}
		for name := range dirNames(t, st.dir) {
			if !names[name] && name != "signer.db-wal" && name != "signer.db-shm" {
				t.Fatalf("--migrate-only created %s in the state directory", name)
			}
		}
	})
	t.Run("migrate_only_requires_existing_db", func(t *testing.T) {
		dir := freshStateDir(t)
		writeMarker(t, dir)
		if code, out := runSigner(t, "recover-revocations", "--state-dir", dir, "--migrate-only"); code != 1 {
			t.Fatalf("--migrate-only without signer.db exited %d:\n%s", code, out)
		}
		if _, err := os.Lstat(filepath.Join(dir, "signer.db")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("--migrate-only created signer.db (%v)", err)
		}
	})
	t.Run("migrate_only_refuses_symlink_signer_db", func(t *testing.T) {
		dir := freshStateDir(t)
		writeMarker(t, dir)
		target := filepath.Join(t.TempDir(), "elsewhere.db")
		if err := os.Symlink(target, filepath.Join(dir, "signer.db")); err != nil {
			t.Fatal(err)
		}
		if code, out := runSigner(t, "recover-revocations", "--state-dir", dir, "--migrate-only"); code != 1 || !strings.Contains(out, "not a regular file") {
			t.Fatalf("--migrate-only on a symlinked signer.db exited %d:\n%s", code, out)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("--migrate-only created the symlink's target (%v)", err)
		}
		dir2 := freshStateDir(t)
		writeMarker(t, dir2)
		if err := os.Mkdir(filepath.Join(dir2, "signer.db"), 0o700); err != nil {
			t.Fatal(err)
		}
		if code, out := runSigner(t, "recover-revocations", "--state-dir", dir2, "--migrate-only"); code != 1 || !strings.Contains(out, "not a regular file") {
			t.Fatalf("--migrate-only on a directory signer.db exited %d:\n%s", code, out)
		}
	})
	t.Run("migrate_only_excludes_no_recovery_needed", func(t *testing.T) {
		dir := freshStateDir(t)
		m := writeMarker(t, dir)
		code, out := runSigner(t, "recover-revocations", "--state-dir", dir, "--migrate-only", "--no-recovery-needed")
		if code != 2 || !strings.Contains(out, "--migrate-only and --no-recovery-needed exclude each other") {
			t.Fatalf("both flags exited %d:\n%s", code, out)
		}
		if !markerExists(t, m) {
			t.Fatal("the marker is gone after the usage error")
		}
	})
	t.Run("doctor_reports_marker", func(t *testing.T) {
		st, _ := bootstrapped(t)
		writeMarker(t, st.dir)
		code, out := runSigner(t, "doctor", "--state-dir", st.dir)
		if code != 1 {
			t.Fatalf("doctor under the marker exited %d:\n%s", code, out)
		}
		requireLine(t, out, "FAIL restore_recovery_pending")
	})
	t.Run("export_allowed_under_marker", func(t *testing.T) {
		st, _ := bootstrapped(t)
		writeMarker(t, st.dir)
		exportBytes(t, st)
	})
}
