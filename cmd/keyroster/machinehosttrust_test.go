package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// mhtNames are the host names of the CA lines TestMachineHostTrust plants
// (03-12g).
var mhtNames = []string{"web1", "web2"}

// mhtEntries returns g1, g2 and g3 of TestAddHostCALines and
// FuzzAddHostCALines (03-12g): nkSeedKey keys 1, 2 and 3 as host entries
// of generations 1, 2 and 3 in the states s1, s2 and s3.
func mhtEntries(t testing.TB, s1, s2, s3 string) (g1, g2, g3 trust.CAEntry) {
	t.Helper()
	e := func(seed byte, state string) trust.CAEntry {
		return trust.CAEntry{Role: trust.RoleHost, Key: nkSeedKey(t, seed), Alg: ssh.KeyAlgoED25519, State: state, Generation: uint32(seed)}
	}
	return e(1, s1), e(2, s2), e(3, s3)
}

// mhtSourceKeys returns the keys of the CA lines of data whose key is the
// key of an entry of cas (03-12g): a line whose first field, split on
// spaces and tabs after its \n and \r are cut, is @cert-authority in any
// case, with at least four fields, fields three and four joined by one
// space being the key.
func mhtSourceKeys(data []byte, cas []trust.CAEntry) map[string]bool {
	keys := map[string]bool{}
	for _, line := range strings.SplitAfter(string(data), "\n") {
		s := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		f := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
		if len(f) < 4 || !strings.EqualFold(f[0], "@cert-authority") {
			continue
		}
		if k := f[2] + " " + f[3]; slices.ContainsFunc(cas, func(e trust.CAEntry) bool { return e.Key == k }) {
			keys[k] = true
		}
	}
	return keys
}

// TestAddHostCALines pins the line reader of keyroster machine renew's host
// trust step (03-12g, T-03-465): it adds the line of each active or next
// host CA the file lacks, over the names of the file's own lines of trusted
// host CAs, never a draining or retired one, never over the names of an
// untrusted line, and refuses lines that disagree or are not in the form
// keyroster writes.
func TestAddHostCALines(t *testing.T) {
	L := hostCALine
	errForm := "a CA line of a host CA the trust bundle trusts is not in the form keyroster writes"
	errDisagree := "its CA lines of the host CAs the trust bundle trusts name different hosts"
	st := &hostTrustState{BundleVersion: 2, KRLVersion: 1}
	// adds fails unless addHostCALines returns want, the entries added and
	// no error.
	adds := func(t *testing.T, in string, trusted, issuing []trust.CAEntry, want string, added ...trust.CAEntry) {
		t.Helper()
		out, got, err := addHostCALines([]byte(in), trusted, issuing)
		if err != nil {
			t.Fatalf("addHostCALines(%q): %v", in, err)
		}
		if string(out) != want {
			t.Fatalf("addHostCALines(%q) =\n%q\nwant\n%q", in, out, want)
		}
		if !slices.Equal(got, added) {
			t.Fatalf("addHostCALines(%q) added %v, want %v", in, got, added)
		}
	}
	// refused fails unless addHostCALines returns the error want and
	// nothing else.
	refused := func(t *testing.T, in string, trusted, issuing []trust.CAEntry, want string) {
		t.Helper()
		out, got, err := addHostCALines([]byte(in), trusted, issuing)
		if err == nil || err.Error() != want {
			t.Fatalf("addHostCALines(%q): error %v, want %q", in, err, want)
		}
		if out != nil || got != nil {
			t.Fatalf("addHostCALines(%q) returned %q and %v with its error, want nil", in, out, got)
		}
	}
	t.Run("appends_each_missing_issuing_line", func(t *testing.T) {
		g1, g2, _ := mhtEntries(t, "active", "next", "retired")
		in := string(knownHostsFile([]trust.CAEntry{g1}, []string{"web1", "web2"}, st))
		cas := []trust.CAEntry{g1, g2}
		adds(t, in, cas, cas, in+L("web1,web2", g2), g2)
	})
	t.Run("adds_the_active_line_beside_a_draining_one", func(t *testing.T) {
		g1, g2, _ := mhtEntries(t, "draining", "active", "retired")
		in := L("web1", g1)
		adds(t, in, []trust.CAEntry{g1, g2}, []trust.CAEntry{g2}, in+L("web1", g2), g2)
	})
	t.Run("never_adds_a_draining_or_retired_key", func(t *testing.T) {
		g1, g2, _ := mhtEntries(t, "draining", "active", "retired")
		in := L("web1", g2)
		adds(t, in, []trust.CAEntry{g1, g2}, []trust.CAEntry{g2}, in)
	})
	t.Run("nothing_to_add_returns_the_input", func(t *testing.T) {
		g1, g2, _ := mhtEntries(t, "active", "next", "retired")
		in := L("web1", g1) + L("web1", g2)
		cas := []trust.CAEntry{g1, g2}
		adds(t, in, cas, cas, in)
	})
	t.Run("no_trusted_line_adds_nothing", func(t *testing.T) {
		g1, g2, g3 := mhtEntries(t, "active", "next", "retired")
		cas := []trust.CAEntry{g1, g2}
		for _, in := range []string{hostTrustHeader, L("web1", g3)} {
			adds(t, in, cas, cas, in)
		}
	})
	t.Run("untrusted_lines_give_no_names", func(t *testing.T) {
		g1, g2, g3 := mhtEntries(t, "active", "next", "retired")
		in := L("evil", g3) + L("web1", g1)
		cas := []trust.CAEntry{g1, g2}
		adds(t, in, cas, cas, in+L("web1", g2), g2)
	})
	t.Run("disagreeing_lines_refused", func(t *testing.T) {
		g1, g2, g3 := mhtEntries(t, "draining", "active", "next")
		refused(t, L("web1", g1)+L("web1,web2", g2), []trust.CAEntry{g1, g2, g3}, []trust.CAEntry{g2, g3}, errDisagree)
	})
	t.Run("not_writer_form_refused", func(t *testing.T) {
		g1, g2, _ := mhtEntries(t, "active", "next", "retired")
		cas := []trust.CAEntry{g1, g2}
		line := L("web1", g1)
		for _, c := range []struct{ name, in string }{
			{"tab_separated", strings.ReplaceAll(line, " ", "\t")},
			{"upper_case_marker", strings.Replace(line, "@cert-authority", "@CERT-AUTHORITY", 1)},
			{"wrong_generation", strings.Replace(line, "generation 1\n", "generation 7\n", 1)},
			{"crlf", strings.TrimSuffix(line, "\n") + "\r\n"},
			{"extra_field", strings.TrimSuffix(line, "\n") + " extra\n"},
			{"no_comment", "@cert-authority web1 " + g1.Key + "\n"},
			{"unsorted_names", L("web2,web1", g1)},
			{"duplicate_name", L("web1,web1", g1)},
			{"wildcard_name", L("*", g1)},
			{"negated_name", L("!web1", g1)},
			{"hashed_name", L("|1|abc=|def=", g1)},
			{"empty_name", L("web1,,web2", g1)},
			{"no_final_newline", hostTrustHeader + strings.TrimSuffix(line, "\n")},
		} {
			t.Run(c.name, func(t *testing.T) {
				refused(t, c.in, cas, cas, errForm)
			})
		}
	})
	t.Run("missing_final_newline_gets_one", func(t *testing.T) {
		g1, g2, _ := mhtEntries(t, "active", "next", "retired")
		in := L("web1", g1) + "# a comment without a newline"
		cas := []trust.CAEntry{g1, g2}
		adds(t, in, cas, cas, in+"\n"+L("web1", g2), g2)
	})
	t.Run("added_line_is_the_writers_line", func(t *testing.T) {
		g1, g2, _ := mhtEntries(t, "active", "next", "retired")
		names := []string{"web1", "web2"}
		var writer string
		for _, line := range strings.SplitAfter(string(knownHostsFile([]trust.CAEntry{g2}, names, st)), "\n") {
			if strings.Contains(line, g2.Key) {
				writer = line
			}
		}
		if writer == "" {
			t.Fatal("knownHostsFile wrote no line of g2")
		}
		in := string(knownHostsFile([]trust.CAEntry{g1}, names, st))
		cas := []trust.CAEntry{g1, g2}
		out, _, err := addHostCALines([]byte(in), cas, cas)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimPrefix(string(out), in); got != writer {
			t.Fatalf("the added line is %q, want the writer's %q", got, writer)
		}
	})
}

// FuzzAddHostCALines (03-12g, T-03-465): over any bytes, an output without
// error is the input, at most one newline, and whole lines in the writer's
// form, each of an issuing entry over names hostTrustName accepts, no entry
// twice; reading it again adds nothing; and an input with a line of a
// trusted host CA gets a line of every issuing entry. An error returns no
// output.
func FuzzAddHostCALines(f *testing.F) {
	g1, g2, _ := mhtEntries(f, "active", "next", "retired")
	cas := []trust.CAEntry{g1, g2}
	st := &hostTrustState{BundleVersion: 2, KRLVersion: 1}
	f.Add(knownHostsFile([]trust.CAEntry{g1}, []string{"web1", "web2"}, st))
	f.Add([]byte(hostCALine("web1", g1) + hostCALine("web1,web2", g2)))
	f.Add([]byte(strings.ReplaceAll(hostCALine("web1", g1), " ", "\t")))
	f.Add([]byte(hostCALine("web1", g1) + "# a comment without a newline"))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, _, err := addHostCALines(data, cas, cas)
		if err != nil {
			if out != nil {
				t.Fatalf("addHostCALines(%q) returned %q with its error %v", data, out, err)
			}
			return
		}
		if !bytes.HasPrefix(out, data) {
			t.Fatalf("addHostCALines(%q) = %q, which does not start with its input", data, out)
		}
		rest := out[len(data):]
		if len(rest) > 0 && rest[0] == '\n' {
			rest = rest[1:]
		}
		seen := map[string]bool{}
		for len(rest) > 0 {
			end := bytes.IndexByte(rest, '\n') + 1
			if end == 0 {
				t.Fatalf("addHostCALines(%q) = %q: the added bytes are not whole lines", data, out)
			}
			line := string(rest[:end])
			rest = rest[end:]
			fl := strings.Fields(line)
			ok := len(fl) >= 4 && fl[0] == "@cert-authority"
			if ok {
				for _, n := range strings.Split(fl[1], ",") {
					ok = ok && hostTrustName(n)
				}
			}
			match := false
			for _, e := range cas {
				if ok && line == hostCALine(fl[1], e) && !seen[e.Key] {
					seen[e.Key], match = true, true
				}
			}
			if !match {
				t.Fatalf("addHostCALines(%q) added %q, which is not the writer's line of an issuing entry not added before", data, line)
			}
		}
		again, added, err := addHostCALines(out, cas, cas)
		if err != nil || !bytes.Equal(again, out) || len(added) != 0 {
			t.Fatalf("addHostCALines(%q) again = %q, %v, %v; want it unchanged", out, again, added, err)
		}
		if len(mhtSourceKeys(data, cas)) > 0 {
			have := mhtSourceKeys(out, cas)
			for _, e := range cas {
				if !have[e.Key] {
					t.Fatalf("addHostCALines(%q) = %q, which holds no line of issuing generation %d", data, out, e.Generation)
				}
			}
		}
	})
}

// mhtEnv is a fixture of TestMachineHostTrust (03-12g): a renew env whose
// stub answers every renewal, a machine key, the certificate's path, the
// env's own host CA g1, and the planted files and their bytes.
type mhtEnv struct {
	e      *dirEnv
	key    string
	priv   ed25519.PrivateKey
	out    string
	g1     trust.CAEntry
	sshDir string
	before map[string]string
	// hookState is the state a hook of the test wrote.
	hookState string
}

// newMHTEnv returns an mhtEnv with nothing served beyond the genesis
// bundle and nothing planted.
func newMHTEnv(t *testing.T) *mhtEnv {
	t.Helper()
	e := newRenewEnv(t)
	renewAnswer(t, e, renewOpts{})
	key, priv := machineKeyFile(t)
	return &mhtEnv{e: e, key: key, priv: priv, out: filepath.Join(t.TempDir(), "ci-cert.pub"), g1: hostCAsOf(e.bundle)[0]}
}

// mhtNextOf returns a fresh next host entry one generation above g.
func mhtNextOf(t *testing.T, g trust.CAEntry) trust.CAEntry {
	t.Helper()
	n := g
	n.Key, n.State, n.Generation, n.TrustedUntil = rotatedCAKey(t, g.Alg), "next", g.Generation+1, ""
	return n
}

// serve serves version v of the env's bundle with exactly the host entries
// hosts, in their order; the other roles stay.
func (m *mhtEnv) serve(t *testing.T, v uint64, hosts ...trust.CAEntry) {
	t.Helper()
	m.e.serveRotated(t, v, func(b *trust.Bundle) {
		var cas []trust.CAEntry
		placed := false
		for _, ca := range b.CAs {
			if ca.Role != trust.RoleHost {
				cas = append(cas, ca)
				continue
			}
			if !placed {
				cas, placed = append(cas, hosts...), true
			}
		}
		b.CAs = cas
	})
}

// plant plants the files of bundle version v with the lines of cas over
// mhtNames and records their bytes.
func (m *mhtEnv) plant(t *testing.T, v uint64, cas ...trust.CAEntry) {
	t.Helper()
	m.sshDir = plantHostTrust(t, m.e, v, cas, mhtNames)
	m.before = mhtFiles(t, m.sshDir)
}

// mhtFirst is the fixture of the first leaf: version served of the env's
// bundle with g1 active and a fresh g2 next, and the files of version
// planted with g1's line over web1,web2. It returns g2.
func mhtFirst(t *testing.T, served, planted uint64) (*mhtEnv, trust.CAEntry) {
	t.Helper()
	m := newMHTEnv(t)
	g2 := mhtNextOf(t, m.g1)
	m.serve(t, served, m.g1, g2)
	m.plant(t, planted, m.g1)
	return m, g2
}

// run runs keyroster machine renew ci with the fixture's key and --out,
// then args.
func (m *mhtEnv) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return run(t, append([]string{"machine", "renew", "ci", "--key", m.key, "--out", m.out}, args...)...)
}

// khPath is the managed keyroster_known_hosts.
func (m *mhtEnv) khPath() string { return filepath.Join(m.sshDir, hostTrustKnownHosts) }

// statePath is host-trust.json.
func (m *mhtEnv) statePath(t *testing.T) string {
	t.Helper()
	p, err := hostTrustStatePath()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// stateAt returns the planted state's bytes with bundle_version v and
// nothing else changed.
func (m *mhtEnv) stateAt(t *testing.T, v uint64) string {
	t.Helper()
	st, err := parseHostTrustState([]byte(m.before[hostTrustStateFile]))
	if err != nil {
		t.Fatal(err)
	}
	st.BundleVersion = v
	data, err := st.encode()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// editState rewrites the state on disk changed by edit and returns its
// bytes.
func (m *mhtEnv) editState(t *testing.T, edit func(st *hostTrustState)) string {
	t.Helper()
	p := m.statePath(t)
	_, st, err := readHostTrustStateBytes(p)
	if err != nil || st == nil {
		t.Fatalf("the state: %v", err)
	}
	edit(st)
	data, err := st.encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStateFile(p, data); err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// added is the step's stderr line for an added line of generation gen
// over n names.
func (m *mhtEnv) added(gen uint32, n int) string {
	return fmt.Sprintf("Host trust: added the CA line of host CA generation %d to %s for the %d host name(s) its lines already trust.\n", gen, m.khPath(), n)
}

// narrowed is the narrowing's stderr line for one removed line.
func (m *mhtEnv) narrowed() string {
	return fmt.Sprintf("Host trust narrowed: removed 1 CA line(s) of host CAs the trust bundle no longer trusts from %s.\n", m.khPath())
}

// mhtFiles returns the bytes of the state and the three managed files
// under sshDir, by name: "" when absent, "<a directory>" for a directory.
func mhtFiles(t *testing.T, sshDir string) map[string]string {
	t.Helper()
	statePath, err := hostTrustStatePath()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for name, p := range map[string]string{
		hostTrustStateFile:  statePath,
		hostTrustKnownHosts: filepath.Join(sshDir, hostTrustKnownHosts),
		hostTrustKRLFile:    filepath.Join(sshDir, hostTrustKRLFile),
		hostTrustSSHConfig:  filepath.Join(sshDir, hostTrustSSHConfig),
	} {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			out[name] = ""
		case err != nil:
			t.Fatal(err)
		case fi.IsDir():
			out[name] = "<a directory>"
		default:
			out[name] = string(readTestFile(t, p))
		}
	}
	return out
}

// requireFiles fails unless each of the four files holds want's bytes, or
// the planted bytes when want does not name it.
func (m *mhtEnv) requireFiles(t *testing.T, want map[string]string, stderr string) {
	t.Helper()
	got := mhtFiles(t, m.sshDir)
	for _, n := range []string{hostTrustStateFile, hostTrustKnownHosts, hostTrustKRLFile, hostTrustSSHConfig} {
		w, ok := want[n]
		if !ok {
			w = m.before[n]
		}
		if got[n] != w {
			t.Fatalf("%s:\n%s\nwant:\n%s\nstderr:\n%s", n, got[n], w, stderr)
		}
	}
}

// requireRenewed fails unless stdout is the renewed summary.
func (m *mhtEnv) requireRenewed(t *testing.T, stdout, stderr string) {
	t.Helper()
	if !strings.HasPrefix(stdout, "machine certificate for ci written to "+m.out+"\n") {
		t.Fatalf("stdout:\n%s\nwant the renewed summary; stderr:\n%s", stdout, stderr)
	}
}

// requireNoStepLine fails when stderr holds a line of the step.
func requireNoStepLine(t *testing.T, stderr string) {
	t.Helper()
	if strings.Contains(stderr, "Host trust: ") || strings.Contains(stderr, "Warning: host trust not refreshed") {
		t.Fatalf("stderr:\n%s\nwant no line of the host trust step", stderr)
	}
}

// writeCurrentCert writes a current certificate of the fixture's key by
// the machine CA, issued now for 24 h, to --out.
func (m *mhtEnv) writeCurrentCert(t *testing.T) {
	t.Helper()
	pub, err := ssh.NewPublicKey(m.priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	c := buildMachineCert(t, machineCASigner(t, m.e), pub, "ci", time.Now().Truncate(time.Second), 24*time.Hour, rand.Reader)
	writeTestFile(t, m.out, ssh.MarshalAuthorizedKey(c))
}

// mhtUseAccountHome makes accountHome return home and err for the test.
func mhtUseAccountHome(t *testing.T, home string, err error) {
	t.Helper()
	prev := accountHome
	accountHome = func() (string, error) { return home, err }
	t.Cleanup(func() { accountHome = prev })
}

// mhtUseSSHDir makes userSSHDir return dir and err for the test.
func mhtUseSSHDir(t *testing.T, dir string, err error) {
	t.Helper()
	prev := userSSHDir
	userSSHDir = func() (string, error) { return dir, err }
	t.Cleanup(func() { userSSHDir = prev })
}

// mhtFailing makes machineTrustReplace fail for the file name and write
// every other file as replaceManagedFile does.
func mhtFailing(t *testing.T, name string) {
	t.Helper()
	prev := machineTrustReplace
	machineTrustReplace = func(dir, n string, data []byte, mode fs.FileMode, check func() error) error {
		if n == name {
			return errors.New("injected write failure")
		}
		return replaceManagedFile(dir, n, data, mode, check)
	}
	t.Cleanup(func() { machineTrustReplace = prev })
}

// mhtHook sets machineTrustHook for the test.
func mhtHook(t *testing.T, hook func()) {
	t.Helper()
	prev := machineTrustHook
	machineTrustHook = hook
	t.Cleanup(func() { machineTrustHook = prev })
}

// TestMachineHostTrust pins keyroster machine renew's host trust step at
// the command level (03-12g, D-14, T-03-465 to T-03-471): it adds the line
// of each active or next host CA the managed known_hosts lacks over the
// names its trusted lines carry, moves the bundle floor before it writes
// the file, on a renewed, not-due or refused run, unless --no-known-hosts
// is given; it never creates a file and never writes the KRL or the ssh
// config; and it exits 4 when the certificate is in place but host trust
// was not refreshed, 1 for a refused renewal whatever it did. Every test
// that makes userSSHDir return an error other than errNoHomeDir also
// replaces accountHome with a temporary directory, so no test looks at the
// real home's .ssh.
func TestMachineHostTrust(t *testing.T) {
	warnPrefix := "Warning: host trust not refreshed in "
	exitLine := "keyroster machine: the machine certificate is in place, but host trust was not refreshed, as reported above"
	t.Run("adds_the_next_line_and_moves_the_floor", func(t *testing.T) {
		m, g2 := mhtFirst(t, 3, 2)
		code, stdout, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireRenewed(t, stdout, stderr)
		if strings.Count(stderr, m.added(g2.Generation, 2)) != 1 || strings.Contains(stderr, "Warning:") {
			t.Fatalf("stderr:\n%s\nwant %q once and no warning", stderr, m.added(g2.Generation, 2))
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	t.Run("adds_the_active_line_beside_a_draining_one", func(t *testing.T) {
		m := newMHTEnv(t)
		m.e.serveRotated(t, 3, rotatedHostCAs(t, time.Now().Add(time.Hour), false))
		cas := hostCAsOf(m.e.bundle)
		m.plant(t, 2, cas[0])
		code, stdout, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireRenewed(t, stdout, stderr)
		if strings.Count(stderr, m.added(cas[1].Generation, 2)) != 1 {
			t.Fatalf("stderr:\n%s\nwant %q once", stderr, m.added(cas[1].Generation, 2))
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", cas[1]),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	t.Run("never_adds_a_draining_line", func(t *testing.T) {
		m := newMHTEnv(t)
		m.e.serveRotated(t, 3, rotatedHostCAs(t, time.Now().Add(time.Hour), false))
		cas := hostCAsOf(m.e.bundle)
		m.plant(t, 2, cas[1])
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		requireNoStepLine(t, stderr)
		m.requireFiles(t, map[string]string{hostTrustStateFile: m.stateAt(t, 3)}, stderr)
	})
	t.Run("narrows_and_moves_the_floor", func(t *testing.T) {
		m := newMHTEnv(t)
		m.e.serveRotated(t, 3, rotatedHostCAs(t, time.Now().Add(-time.Hour), true))
		cas := hostCAsOf(m.e.bundle)
		m.plant(t, 2, cas...)
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		if strings.Count(stderr, m.narrowed()) != 1 {
			t.Fatalf("stderr:\n%s\nwant the narrowing line once", stderr)
		}
		requireNoStepLine(t, stderr)
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: strings.Replace(m.before[hostTrustKnownHosts], hostCALine("web1,web2", cas[0]), "", 1),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	t.Run("not_due_adds_the_line", func(t *testing.T) {
		m, g2 := mhtFirst(t, 3, 2)
		m.writeCurrentCert(t)
		code, stdout, stderr := m.run(t, "--if-due")
		if code != 0 || !strings.HasPrefix(stdout, "not due: ") || !strings.Contains(stdout, "; nothing was sent") || m.e.renewCount() != 0 {
			t.Fatalf("exit %d, %d sent, stdout:\n%s\nstderr:\n%s\nwant exit 0, not due and nothing sent", code, m.e.renewCount(), stdout, stderr)
		}
		if strings.Count(stderr, m.added(g2.Generation, 2)) != 1 {
			t.Fatalf("stderr:\n%s\nwant %q once", stderr, m.added(g2.Generation, 2))
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	t.Run("renewal_refused_still_adds_and_exits_1", func(t *testing.T) {
		m, g2 := mhtFirst(t, 3, 2)
		m.e.mu.Lock()
		m.e.override["POST "+serverclient.MachineRenewPath] = func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }
		m.e.mu.Unlock()
		code, _, stderr := m.run(t)
		if code != 1 {
			t.Fatalf("exit %d, want 1; stderr:\n%s", code, stderr)
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	t.Run("no_known_hosts_adds_nothing", func(t *testing.T) {
		m, _ := mhtFirst(t, 3, 2)
		code, _, stderr := m.run(t, "--no-known-hosts")
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		requireNoStepLine(t, stderr)
		m.requireFiles(t, nil, stderr)
	})
	t.Run("no_managed_file_is_silent", func(t *testing.T) {
		m := newMHTEnv(t)
		m.serve(t, 3, m.g1, mhtNextOf(t, m.g1))
		dir := useSSHDir(t)
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("~/.ssh after the run: %v, want it not created", err)
		}
		if _, err := os.Lstat(m.statePath(t)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the state after the run: %v, want it not created", err)
		}
		if strings.Contains(stderr, "host trust") || strings.Contains(stderr, "Host trust") {
			t.Fatalf("stderr:\n%s\nwant nothing about host trust", stderr)
		}
	})
	t.Run("unchanged_is_silent", func(t *testing.T) {
		m := newMHTEnv(t)
		g2 := mhtNextOf(t, m.g1)
		m.serve(t, 2, m.g1, g2)
		m.plant(t, 2, m.g1, g2)
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		requireNoStepLine(t, stderr)
		m.requireFiles(t, nil, stderr)
	})
	t.Run("failures_exit_4", func(t *testing.T) {
		for _, c := range []struct {
			name            string
			served, planted uint64
			// set breaks one thing after the plant and returns the path
			// and the reason of the warning line.
			set func(t *testing.T, m *mhtEnv, g2 trust.CAEntry) (string, string)
			// want is the files the run leaves, by name, where they differ
			// from the plant.
			want func(t *testing.T, m *mhtEnv) map[string]string
		}{
			{"damaged_state", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				writeTestFile(t, m.statePath(t), []byte("{"))
				_, err := parseHostTrustState([]byte("{"))
				if err == nil {
					t.Fatal("a state of { parses")
				}
				return m.khPath(), fmt.Sprintf("the host trust state is damaged (%s)", strings.TrimPrefix(err.Error(), errStateCorrupt.Error()+": "))
			}, nil},
			{"missing_state", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				if err := os.Remove(m.statePath(t)); err != nil {
					t.Fatal(err)
				}
				return m.khPath(), "the host trust state is missing"
			}, nil},
			{"other_installation", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				other := "0123456789abcdef0123456789abcdef"
				m.editState(t, func(st *hostTrustState) { st.InstallationID = other })
				return m.khPath(), fmt.Sprintf("the host trust state belongs to installation %s, not to %s", other, m.e.bundle.InstallationID)
			}, nil},
			{"older_bundle", 3, 5, func(_ *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				return m.khPath(), "the server serves trust bundle version 3, older than version 5, which this client verified before"
			}, nil},
			{"equal_version_other_ops_key", 3, 3, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				m.editState(t, func(st *hostTrustState) { st.OpsKey = nkSeedKey(t, 9) })
				return m.khPath(), "trust bundle version 3 names another ops key than the version this client verified before"
			}, nil},
			{"lines_disagree", 3, 2, func(t *testing.T, m *mhtEnv, g2 trust.CAEntry) (string, string) {
				writeTestFile(t, m.khPath(), []byte(m.before[hostTrustKnownHosts]+hostCALine("web1", g2)))
				return m.khPath(), "its CA lines of the host CAs the trust bundle trusts name different hosts"
			}, nil},
			{"not_writer_form", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				writeTestFile(t, m.khPath(), []byte(strings.Replace(m.before[hostTrustKnownHosts], "@cert-authority", "@CERT-AUTHORITY", 1)))
				return m.khPath(), "a CA line of a host CA the trust bundle trusts is not in the form keyroster writes"
			}, nil},
			{"not_a_regular_file", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				if err := os.Remove(m.khPath()); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(m.khPath(), 0o700); err != nil {
					t.Fatal(err)
				}
				return m.khPath(), "it is not a regular file"
			}, nil},
			{"too_large", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				prev := maxNarrowFile
				maxNarrowFile = 10
				t.Cleanup(func() { maxNarrowFile = prev })
				return m.khPath(), "it is larger than 10 bytes"
			}, nil},
			{"file_write_failure", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				mhtFailing(t, hostTrustKnownHosts)
				return m.khPath(), "writing it failed: injected write failure"
			}, func(t *testing.T, m *mhtEnv) map[string]string {
				return map[string]string{hostTrustStateFile: m.stateAt(t, 3)}
			}},
			{"state_write_failure", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				mhtFailing(t, hostTrustStateFile)
				return m.khPath(), "writing the host trust state failed: injected write failure"
			}, nil},
			{"file_changed_meanwhile", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				mhtHook(t, func() {
					writeTestFile(t, m.khPath(), append(readTestFile(t, m.khPath()), "# changed meanwhile\n"...))
				})
				return m.khPath(), "the file changed while it was read"
			}, func(t *testing.T, m *mhtEnv) map[string]string {
				return map[string]string{
					hostTrustKnownHosts: m.before[hostTrustKnownHosts] + "# changed meanwhile\n",
					hostTrustStateFile:  m.stateAt(t, 3),
				}
			}},
			{"state_changed_meanwhile", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				mhtHook(t, func() {
					m.hookState = m.editState(t, func(st *hostTrustState) { st.KRLVersion++ })
				})
				return m.khPath(), "another run recorded a newer host trust state meanwhile"
			}, func(_ *testing.T, m *mhtEnv) map[string]string {
				return map[string]string{hostTrustStateFile: m.hookState}
			}},
			{"home_mismatch_with_file", 3, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				home := t.TempDir()
				if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(home, ".ssh", hostTrustKnownHosts)
				writeTestFile(t, p, []byte(m.before[hostTrustKnownHosts]))
				reason := "$HOME is not your account home, which ssh reads (a test)"
				mhtUseSSHDir(t, "", errors.New(reason))
				mhtUseAccountHome(t, home, nil)
				return p, reason
			}, nil},
			{"state_changed_at_equal_floor", 2, 2, func(t *testing.T, m *mhtEnv, _ trust.CAEntry) (string, string) {
				mhtHook(t, func() {
					m.hookState = m.editState(t, func(st *hostTrustState) { st.KRLVersion++ })
				})
				return m.khPath(), "another run recorded a newer host trust state meanwhile"
			}, func(_ *testing.T, m *mhtEnv) map[string]string {
				return map[string]string{hostTrustStateFile: m.hookState}
			}},
		} {
			t.Run(c.name, func(t *testing.T) {
				m, g2 := mhtFirst(t, c.served, c.planted)
				path, reason := c.set(t, m, g2)
				m.before = mhtFiles(t, m.sshDir)
				code, stdout, stderr := m.run(t)
				if code != 4 {
					t.Fatalf("exit %d, want 4; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
				}
				m.requireRenewed(t, stdout, stderr)
				warn := fmt.Sprintf("Warning: host trust not refreshed in %s: %s.\n", path, reason)
				if strings.Count(stderr, warn) != 1 || strings.Count(stderr, warnPrefix) != 1 {
					t.Fatalf("stderr:\n%s\nwant one warning of the step: %q", stderr, warn)
				}
				if !strings.Contains(stderr, exitLine) {
					t.Fatalf("stderr:\n%s\nwant %q", stderr, exitLine)
				}
				var want map[string]string
				if c.want != nil {
					want = c.want(t, m)
				}
				m.requireFiles(t, want, stderr)
			})
		}
	})
	t.Run("not_due_failure_exits_4", func(t *testing.T) {
		m, _ := mhtFirst(t, 3, 2)
		writeTestFile(t, m.statePath(t), []byte("{"))
		m.writeCurrentCert(t)
		code, stdout, stderr := m.run(t, "--if-due")
		if code != 4 || !strings.HasPrefix(stdout, "not due: ") || m.e.renewCount() != 0 {
			t.Fatalf("exit %d, %d sent, stdout:\n%s\nstderr:\n%s\nwant exit 4, not due and nothing sent", code, m.e.renewCount(), stdout, stderr)
		}
		if strings.Count(stderr, warnPrefix+m.khPath()+": the host trust state is damaged (") != 1 || !strings.Contains(stderr, exitLine) {
			t.Fatalf("stderr:\n%s\nwant the step's warning once and %q", stderr, exitLine)
		}
	})
	t.Run("home_lookup_warning_uses_its_dir", func(t *testing.T) {
		m, g2 := mhtFirst(t, 3, 2)
		mhtUseSSHDir(t, m.sshDir, &homeLookupWarning{dir: m.sshDir, err: errors.New("no account of this uid (a test)")})
		mhtUseAccountHome(t, t.TempDir(), nil)
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	t.Run("adds_the_line_from_a_config_without_a_user", func(t *testing.T) {
		m, g2 := mhtFirst(t, 3, 2)
		m.e.cfg.User, m.e.cfg.AdminKey = "", ""
		if _, err := saveConfig(m.e.cfg, true); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	t.Run("home_mismatch_without_file_is_0", func(t *testing.T) {
		m, _ := mhtFirst(t, 3, 2)
		mhtUseSSHDir(t, "", errors.New("$HOME is not your account home, which ssh reads (a test)"))
		mhtUseAccountHome(t, t.TempDir(), nil)
		if code, _, stderr := m.run(t); code != 0 || strings.Contains(stderr, "Warning: host trust") {
			t.Fatalf("an account home without the file: exit %d, stderr:\n%s\nwant 0 and no warning of the step", code, stderr)
		}
		mhtUseAccountHome(t, "", errors.New("no account of this uid (a test)"))
		if code, _, stderr := m.run(t); code != 0 || strings.Contains(stderr, "Warning: host trust") {
			t.Fatalf("a failed account lookup: exit %d, stderr:\n%s\nwant 0 and no warning of the step", code, stderr)
		}
	})
	t.Run("stale_bundle_after_the_floor_moved_adds_nothing", func(t *testing.T) {
		m := newMHTEnv(t)
		g2 := mhtNextOf(t, m.g1)
		m.serve(t, 3, m.g1, g2)
		m.plant(t, 2, m.g1)
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("run 1: exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
		m.e.mu.Lock()
		doc1, bundle1 := m.e.trustDoc, m.e.bundle
		m.e.mu.Unlock()
		// Run 2: g2 aborted (retired).
		retired := g2
		retired.State = "retired"
		m.serve(t, 4, m.g1, retired)
		code, _, stderr = m.run(t)
		if code != 0 {
			t.Fatalf("run 2: exit %d, want 0; stderr:\n%s", code, stderr)
		}
		if strings.Count(stderr, m.narrowed()) != 1 || strings.Contains(stderr, "Host trust: ") {
			t.Fatalf("run 2: stderr:\n%s\nwant the narrowing line once and nothing added", stderr)
		}
		m.requireFiles(t, map[string]string{hostTrustStateFile: m.stateAt(t, 4)}, stderr)
		// Run 3: run 1's signed bundle again.
		m.e.mu.Lock()
		m.e.trustDoc, m.e.bundle = doc1, bundle1
		m.e.mu.Unlock()
		code, _, stderr = m.run(t)
		warn := fmt.Sprintf("Warning: host trust not refreshed in %s: the server serves trust bundle version 3, older than version 4, which this client verified before.\n", m.khPath())
		if code != 4 || strings.Count(stderr, warn) != 1 {
			t.Fatalf("run 3: exit %d, stderr:\n%s\nwant 4 and %q", code, stderr, warn)
		}
		if got := mhtFiles(t, m.sshDir)[hostTrustKnownHosts]; strings.Contains(got, g2.Key) {
			t.Fatalf("run 3: known_hosts holds the aborted key's line:\n%s", got)
		}
	})
	// The floor records the bundle's ops key with its version, as the
	// writer does (03-12g, "The step", item 6; pre-merge review).
	t.Run("floor_records_the_new_ops_key", func(t *testing.T) {
		m, g2 := mhtFirst(t, 3, 2)
		newOps := freshKeyLike(t, m.e.bundle.OpsKey.Alg)
		if newOps == m.e.bundle.OpsKey.Key {
			t.Fatal("the fresh ops key equals the planted one")
		}
		m.e.serveRotated(t, 3, func(b *trust.Bundle) { b.OpsKey.Key = newOps })
		code, stdout, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("run 1: exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireRenewed(t, stdout, stderr)
		st, err := parseHostTrustState([]byte(m.before[hostTrustStateFile]))
		if err != nil {
			t.Fatal(err)
		}
		st.BundleVersion, st.OpsKey = 3, newOps
		wantState, err := st.encode()
		if err != nil {
			t.Fatal(err)
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  string(wantState),
		}, stderr)
		m.before = mhtFiles(t, m.sshDir)
		code, _, stderr = m.run(t)
		if code != 0 {
			t.Fatalf("run 2: exit %d, want 0; stderr:\n%s", code, stderr)
		}
		requireNoStepLine(t, stderr)
		m.requireFiles(t, nil, stderr)
	})
	// The step writes the file 0644 and the state 0600, as the writer
	// does, whatever modes the files had (03-12g, "The step", items 6 and
	// 7; pre-merge review).
	t.Run("writes_use_the_writers_modes", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Unix mode bits")
		}
		m, g2 := mhtFirst(t, 3, 2)
		if err := os.Chmod(m.khPath(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(m.statePath(t), 0o644); err != nil { //nolint:gosec // a wider mode on purpose, so the step's write must narrow it
			t.Fatal(err)
		}
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: m.before[hostTrustKnownHosts] + hostCALine("web1,web2", g2),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
		for p, want := range map[string]fs.FileMode{m.khPath(): 0o644, m.statePath(t): 0o600} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := fi.Mode().Perm(); got != want {
				t.Fatalf("%s: mode %v after the step's write, want %v", p, got, want)
			}
		}
	})
	// Without $HOME the step does not look at the account's home (03-12g,
	// "The step", item 1, and the outcome table's column "no home"): the
	// run changes nothing and prints nothing of the step, even though the
	// account's home holds the file.
	t.Run("no_home_changes_nothing", func(t *testing.T) {
		m, _ := mhtFirst(t, 3, 2)
		mhtUseAccountHome(t, filepath.Dir(m.sshDir), nil)
		mhtUseSSHDir(t, "", fmt.Errorf("%w: %w", errNoHomeDir, errors.New("$HOME is not defined (a test)")))
		code, stdout, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		m.requireRenewed(t, stdout, stderr)
		requireNoStepLine(t, stderr)
		if strings.Contains(stderr, "Host trust narrowed") {
			t.Fatalf("stderr:\n%s\nwant no narrowing line", stderr)
		}
		m.requireFiles(t, nil, stderr)
	})
	// A file with no line of a host CA the bundle trusts gets no line and
	// exits 0 when nothing else is wrong (03-12g, B11; pre-merge review).
	t.Run("no_trusted_line_exits_0_and_adds_nothing", func(t *testing.T) {
		m := newMHTEnv(t)
		g2 := mhtNextOf(t, m.g1)
		m.serve(t, 3, m.g1, g2)
		stranger := mhtNextOf(t, g2)
		m.plant(t, 2, stranger)
		code, _, stderr := m.run(t)
		if code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", code, stderr)
		}
		if strings.Count(stderr, m.narrowed()) != 1 {
			t.Fatalf("stderr:\n%s\nwant the narrowing line once", stderr)
		}
		requireNoStepLine(t, stderr)
		got := mhtFiles(t, m.sshDir)[hostTrustKnownHosts]
		for _, g := range []trust.CAEntry{m.g1, g2} {
			if strings.Contains(got, g.Key) {
				t.Fatalf("known_hosts holds a CA line of generation %d:\n%s", g.Generation, got)
			}
		}
		m.requireFiles(t, map[string]string{
			hostTrustKnownHosts: strings.Replace(m.before[hostTrustKnownHosts], hostCALine("web1,web2", stranger), "", 1),
			hostTrustStateFile:  m.stateAt(t, 3),
		}, stderr)
	})
	// The same file with a missing state exits 4: the step reads the
	// state whether or not a line is missing (03-12g, "The step", item 4;
	// pre-merge review).
	t.Run("no_trusted_line_with_a_missing_state_exits_4", func(t *testing.T) {
		m := newMHTEnv(t)
		g2 := mhtNextOf(t, m.g1)
		m.serve(t, 3, m.g1, g2)
		m.plant(t, 2, mhtNextOf(t, g2))
		if err := os.Remove(m.statePath(t)); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := m.run(t)
		warn := fmt.Sprintf("Warning: host trust not refreshed in %s: the host trust state is missing.\n", m.khPath())
		if code != 4 || strings.Count(stderr, warn) != 1 || strings.Count(stderr, warnPrefix) != 1 {
			t.Fatalf("exit %d, stderr:\n%s\nwant 4 and %q once", code, stderr, warn)
		}
	})
}

// TestMachineHostTrustCaller pins the step's one call site (03-12g, as
// TestTrustCallersUseWrapper pins the narrowing's): over every non-test
// .go file of the package, whatever its build constraints, machineHostTrust
// is referenced, outside its declaration, exactly once, in
// runMachineRenew, after that function's verifiedTrust call.
func TestMachineHostTrustCaller(t *testing.T) {
	t.Run("only_machine_renew_calls_it_after_verified_trust", func(t *testing.T) {
		files, err := filepath.Glob("*.go")
		if err != nil {
			t.Fatal(err)
		}
		type ref struct {
			fn, at string
			pos    token.Pos
		}
		var refs []ref
		var verified token.Pos
		fset := token.NewFileSet()
		parsed := 0
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			parsed++
			for _, d := range af.Decls {
				fd, isFunc := d.(*ast.FuncDecl)
				fn := ""
				if isFunc {
					fn = fd.Name.Name
				}
				ast.Inspect(d, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.Ident:
						if x.Name == "machineHostTrust" && (!isFunc || x != fd.Name) {
							refs = append(refs, ref{fn, fset.Position(x.Pos()).String(), x.Pos()})
						}
					case *ast.CallExpr:
						if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "verifiedTrust" && fn == "runMachineRenew" {
							verified = x.Pos()
						}
					}
					return true
				})
			}
		}
		if parsed < 10 {
			t.Fatalf("parsed %d non-test files of the package, want the whole package", parsed)
		}
		if verified == token.NoPos {
			t.Fatal("runMachineRenew has no verifiedTrust call")
		}
		if len(refs) != 1 {
			t.Fatalf("machineHostTrust is referenced %d times outside its declaration (%v), want once, in runMachineRenew", len(refs), refs)
		}
		if refs[0].fn != "runMachineRenew" || refs[0].pos <= verified {
			t.Fatalf("%s: machineHostTrust is referenced in %q, want runMachineRenew after its verifiedTrust call", refs[0].at, refs[0].fn)
		}
	})
}
