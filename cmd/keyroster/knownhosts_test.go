package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestMain points ~/.ssh at an error for every test of this package
// (03-09b), so no test, a TestLoginFlowFakeServer case included, can
// touch a real home: a test that writes the host trust files installs a
// temporary directory with useSSHDir.
func TestMain(m *testing.M) {
	userSSHDir = func() (string, error) {
		return "", errors.New("no ~/.ssh in this test (useSSHDir installs one)")
	}
	os.Exit(m.Run())
}

// useSSHDir points ~/.ssh at a fresh, not yet existing directory under a
// temporary directory and returns it.
func useSSHDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".ssh")
	prev := userSSHDir
	userSSHDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { userSSHDir = prev })
	return dir
}

// htFix is the writer's test fixture: a stub root-verified bundle and
// policy, the admin, ops and CA keys behind them, a temporary ~/.ssh and
// config directory.
type htFix struct {
	install   string
	admins    []ssh.Signer
	pol       *trust.Policy
	ops       ssh.Signer
	bundle    *trust.Bundle
	hostCA    ssh.Signer
	sshDir    string
	statePath string
}

func htSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func htInstall(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

// newHTFix builds a fixture with admins policy admins at quorum quorum, a
// bundle of version 1 with an active user and host CA, and fresh
// directories.
func newHTFix(t *testing.T, admins, quorum int) *htFix {
	t.Helper()
	f := &htFix{install: htInstall(t), ops: htSigner(t), hostCA: htSigner(t)}
	f.pol = &trust.Policy{Version: 1, AdminQuorum: uint32(quorum)} //nolint:gosec // G115: a small test count
	for i := range admins {
		s := htSigner(t)
		f.admins = append(f.admins, s)
		f.pol.Admins = append(f.pol.Admins, trust.AdminKey{Name: fmt.Sprintf("admin%d", i), Key: trust.FormatKey(s.PublicKey())})
	}
	f.bundle = &trust.Bundle{Version: 1, InstallationID: f.install, OpsKey: trust.KeyEntry{Key: trust.FormatKey(f.ops.PublicKey())},
		CAs: []trust.CAEntry{
			{Role: trust.RoleUser, Key: trust.FormatKey(htSigner(t).PublicKey()), State: "active", Generation: 1},
			{Role: trust.RoleHost, Key: trust.FormatKey(f.hostCA.PublicKey()), State: "active", Generation: 1},
		}}
	f.sshDir = useSSHDir(t)
	f.statePath = filepath.Join(filepath.Dir(useConfigDir(t)), hostTrustStateFile)
	return f
}

// host is an active host entry in host group web with a fresh key.
func htHost(t *testing.T, name, status string, principals ...string) directory.Host {
	t.Helper()
	ps := slices.Clone(principals)
	slices.Sort(ps)
	return directory.Host{Name: name, HostGroup: "web", Keys: []string{trust.FormatKey(htSigner(t).PublicKey())}, Principals: ps, Status: status}
}

// dirDoc is directory version v, bound to installation (f.install when
// ""; "-" for none), with hosts.
func (f *htFix) dirDoc(t *testing.T, v uint64, installation string, hosts ...directory.Host) []byte {
	t.Helper()
	d := &directory.Directory{Version: v, Prev: trust.GenesisPrev, InstallationID: f.install,
		HostGroups: []directory.HostGroup{{Name: "web", Accounts: []directory.AccountMap{}}}}
	if v > 1 {
		d.Prev = strings.Repeat("ab", 32)
	}
	switch installation {
	case "":
	case "-":
		d.InstallationID = ""
	default:
		d.InstallationID = installation
	}
	if len(hosts) > 0 {
		d.Hosts = hosts
	}
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		t.Fatalf("test directory does not parse: %v", err)
	}
	return doc
}

// sign returns the armored signatures of signers over doc.
func htSign(t *testing.T, doc []byte, signers ...ssh.Signer) []byte {
	t.Helper()
	var out []byte
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, directory.Namespace, doc)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sig...)
	}
	return out
}

// htKRLDoc is a KRL document of version v issued at issued, for
// installation, signed by signer, listing set.
func htKRLDoc(t *testing.T, v uint64, issued time.Time, installation string, signer ssh.Signer, set krl.Set) *serverclient.KRLDocument {
	t.Helper()
	data, err := krl.Encode(set, v, issued)
	if err != nil {
		t.Fatal(err)
	}
	m := krl.Manifest{InstallationID: installation, KRLVersion: v, KRLSHA256: krl.SHA256Hex(data),
		IssuedAt: issued.UTC().Truncate(time.Second).Format(trust.TimeFormat), BundleVersion: 1, LogIndex: v}
	manifest, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, signer, krl.Namespace, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return &serverclient.KRLDocument{KRL: data, Manifest: manifest, Sig: sig}
}

// krlV is an empty KRL of version v by the fixture's ops key, issued now.
func (f *htFix) krlV(t *testing.T, v uint64) *serverclient.KRLDocument {
	t.Helper()
	return htKRLDoc(t, v, time.Now(), f.install, f.ops, krl.Set{})
}

// in is the writer's input: f's bundle and policy, its host CAs, doc
// signed by the first quorum admins (nil doc: no directory) and k.
func (f *htFix) in(t *testing.T, doc []byte, k *serverclient.KRLDocument) hostTrustInput {
	t.Helper()
	var sigs []byte
	if doc != nil {
		sigs = htSign(t, doc, f.admins[:f.pol.AdminQuorum]...)
	}
	return hostTrustInput{Bundle: f.bundle, Policy: f.pol, CAs: hostTrustCAs(f.bundle, time.Now()), Dir: doc, DirSigs: sigs, KRL: k, Now: time.Now()}
}

// write runs the writer and returns its result, stdout and stderr.
func htWrite(in hostTrustInput) (hostTrustResult, string, string) {
	var stdout, stderr strings.Builder
	res := writeHostTrust(in, &stdout, &stderr)
	return res, stdout.String(), stderr.String()
}

// file returns the bytes of a managed file ("" when absent).
func (f *htFix) file(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(f.sshDir, name)
	if name == hostTrustStateFile {
		p = f.statePath
	}
	data, err := os.ReadFile(p) //nolint:gosec // a test path
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// files returns the four files' bytes.
func (f *htFix) files(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range []string{hostTrustStateFile, hostTrustKRLFile, hostTrustKnownHosts, hostTrustSSHConfig} {
		out[n] = f.file(t, n)
	}
	return out
}

// requireNothingWritten fails when any of the four files exists.
func (f *htFix) requireNothingWritten(t *testing.T) {
	t.Helper()
	for n, data := range f.files(t) {
		if data != "" {
			t.Fatalf("%s was written:\n%s", n, data)
		}
	}
}

// state reads the state file.
func (f *htFix) state(t *testing.T) *hostTrustState {
	t.Helper()
	st, err := parseHostTrustState([]byte(f.file(t, hostTrustStateFile)))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// mustRun runs the writer and requires want.
func mustRun(t *testing.T, in hostTrustInput, want hostTrustResult) (string, string) {
	t.Helper()
	res, stdout, stderr := htWrite(in)
	if res != want {
		t.Fatalf("writer result %d, want %d\nstdout: %s\nstderr: %s", res, want, stdout, stderr)
	}
	return stdout, stderr
}

const htKnownHostsHead = "# keyroster: managed file, rewritten by keyroster login and keyroster known-hosts sync. Do not edit.\n"

// htConfig is the exact keyroster_ssh_config over names.
func htConfig(names ...string) string {
	s := htKnownHostsHead + "# Include it from ~/.ssh/config before the first Host or Match line.\n"
	if len(names) == 0 {
		return s
	}
	return s + "Host " + strings.Join(names, " ") + "\n" +
		"\tUserKnownHostsFile ~/.ssh/keyroster_known_hosts\n" +
		"\tGlobalKnownHostsFile ~/.ssh/keyroster_known_hosts\n" +
		"\tStrictHostKeyChecking yes\n" +
		"\tUpdateHostKeys no\n" +
		"\tVerifyHostKeyDNS no\n" +
		"\tRevokedHostKeys ~/.ssh/keyroster_revoked_hosts.krl\n"
}

// htCALines returns the names of the @cert-authority lines of a
// keyroster_known_hosts, by CA key.
func htCALines(t *testing.T, kh string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, l := range strings.Split(kh, "\n") {
		if !strings.HasPrefix(l, "@cert-authority ") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 4 {
			t.Fatalf("CA line %q", l)
		}
		out[f[2]+" "+f[3]] = strings.Split(f[1], ",")
	}
	return out
}

// htHostLine returns the names of the Host line of a keyroster_ssh_config.
func htHostLine(cfg string) []string {
	for _, l := range strings.Split(cfg, "\n") {
		if rest, ok := strings.CutPrefix(l, "Host "); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

// TestHostTrustName (03-09b, T-03-59): the one name rule of the managed
// files, independent of the directory's grammar.
func TestHostTrustName(t *testing.T) {
	t.Run("accepts_valid", func(t *testing.T) {
		for _, s := range []string{"web1", "web1.lab.example", "127.0.0.1", "2001:db8::1", strings.Repeat("a", 253)} {
			if !hostTrustName(s) {
				t.Fatalf("%q refused", s)
			}
		}
	})
	t.Run("rejects_pattern_bytes", func(t *testing.T) {
		for _, c := range []string{"*", "?", ",", "!", "#", `"`, "'", "=", "[", "]", `\`, "%", "/", "@"} {
			for _, s := range []string{c, "web" + c, c + "web", "w" + c + "b"} {
				if hostTrustName(s) {
					t.Fatalf("%q accepted", s)
				}
			}
		}
	})
	t.Run("rejects_space_control_and_high_bytes", func(t *testing.T) {
		for _, s := range []string{"web 1", "web\t1", "web\n1", "web\x001", "web\x7f1", "wéb1"} {
			if hostTrustName(s) {
				t.Fatalf("%q accepted", s)
			}
		}
	})
	t.Run("rejects_uppercase_and_underscore", func(t *testing.T) {
		for _, s := range []string{"Web1", "WEB1", "web_1", "_web1"} {
			if hostTrustName(s) {
				t.Fatalf("%q accepted", s)
			}
		}
	})
	t.Run("rejects_empty_leading_dash_and_over_253", func(t *testing.T) {
		for _, s := range []string{"", "-web1", "-", strings.Repeat("a", 254)} {
			if hostTrustName(s) {
				t.Fatalf("%q accepted", s)
			}
		}
	})
}

// TestHostTrustCAs (03-09b): the host CAs clients trust.
func TestHostTrustCAs(t *testing.T) {
	key := func() string { return trust.FormatKey(htSigner(t).PublicKey()) }
	t.Run("active_and_next_sorted_by_generation_then_key", func(t *testing.T) {
		k1, k2, k3 := key(), key(), key()
		hi, lo := max(k2, k3), min(k2, k3)
		b := &trust.Bundle{CAs: []trust.CAEntry{
			{Role: trust.RoleHost, Key: hi, State: "next", Generation: 2},
			{Role: trust.RoleHost, Key: k1, State: "active", Generation: 1},
			{Role: trust.RoleHost, Key: lo, State: "next", Generation: 2},
		}}
		got := hostTrustCAs(b, time.Now())
		if len(got) != 3 || got[0].Key != k1 || got[1].Key != lo || got[2].Key != hi {
			t.Fatalf("hostTrustCAs = %+v", got)
		}
	})
	t.Run("retired_excluded", func(t *testing.T) {
		k := key()
		b := &trust.Bundle{CAs: []trust.CAEntry{{Role: trust.RoleHost, Key: key(), State: "retired", Generation: 1}, {Role: trust.RoleHost, Key: k, State: "active", Generation: 2}}}
		if got := hostTrustCAs(b, time.Now()); len(got) != 1 || got[0].Key != k {
			t.Fatalf("hostTrustCAs = %+v", got)
		}
	})
	t.Run("other_roles_excluded", func(t *testing.T) {
		b := &trust.Bundle{CAs: []trust.CAEntry{{Role: trust.RoleUser, Key: key(), State: "active", Generation: 1}, {Role: trust.RoleMachine, Key: key(), State: "active", Generation: 1}}}
		if got := hostTrustCAs(b, time.Now()); len(got) != 0 {
			t.Fatalf("hostTrustCAs = %+v", got)
		}
	})
	t.Run("empty_bundle_none", func(t *testing.T) {
		if got := hostTrustCAs(&trust.Bundle{}, time.Now()); len(got) != 0 {
			t.Fatalf("hostTrustCAs = %+v", got)
		}
	})
}

// TestKnownHosts (03-09b, D2, T-03-59 to T-03-61, T-03-241, T-03-347):
// the writer on stub inputs.
func TestKnownHosts(t *testing.T) {
	t.Run("writes_three_files_and_state", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		doc := f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1", "web1.lab.example"))
		k := f.krlV(t, 1)
		stdout, _ := mustRun(t, f.in(t, doc, k), hostTrustFull)
		if stdout != "Host trust refreshed (directory v1, KRL v1, 2 names).\n" {
			t.Fatalf("stdout %q", stdout)
		}
		sha := trust.SHA256Hex(doc)
		want := fmt.Sprintf(`{"format":1,"installation_id":"%s","bundle_version":1,"ops_key":"%s","directory_version":1,"directory_sha256":"%s","krl_version":1,"names":["web1","web1.lab.example"]}`+"\n",
			f.install, trust.FormatKey(f.ops.PublicKey()), sha)
		if got := f.file(t, hostTrustStateFile); got != want {
			t.Fatalf("state\n%s\nwant\n%s", got, want)
		}
		if got := f.file(t, hostTrustKRLFile); got != string(k.KRL) {
			t.Fatal("the KRL file is not the verified KRL bytes")
		}
		wantKH := htKnownHostsHead + fmt.Sprintf("# directory version 1 (sha256 %s), trust bundle version 1, KRL version 1 (informational; never read back)\n", sha) +
			"@cert-authority web1,web1.lab.example " + trust.FormatKey(f.hostCA.PublicKey()) + " keyroster host CA generation 1\n"
		if got := f.file(t, hostTrustKnownHosts); got != wantKH {
			t.Fatalf("known_hosts\n%s\nwant\n%s", got, wantKH)
		}
		if got := f.file(t, hostTrustSSHConfig); got != htConfig("web1", "web1.lab.example") {
			t.Fatalf("config\n%s", got)
		}
	})
	t.Run("ca_line_format_exact", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		next := htSigner(t)
		f.bundle.CAs = append(f.bundle.CAs, trust.CAEntry{Role: trust.RoleHost, Key: trust.FormatKey(next.PublicKey()), State: "next", Generation: 2})
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustFull)
		lines := strings.Split(strings.TrimSuffix(f.file(t, hostTrustKnownHosts), "\n"), "\n")
		want := []string{
			"@cert-authority web1 " + trust.FormatKey(f.hostCA.PublicKey()) + " keyroster host CA generation 1",
			"@cert-authority web1 " + trust.FormatKey(next.PublicKey()) + " keyroster host CA generation 2",
		}
		if len(lines) != 4 || !slices.Equal(lines[2:], want) {
			t.Fatalf("known_hosts lines %q, want the two comments and %q", lines, want)
		}
	})
	t.Run("ssh_config_keywords_exact", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustFull)
		cfg := f.file(t, hostTrustSSHConfig)
		lines := strings.Split(strings.TrimSuffix(cfg, "\n"), "\n")
		want := []string{"Host web1", "\tUserKnownHostsFile ~/.ssh/keyroster_known_hosts", "\tGlobalKnownHostsFile ~/.ssh/keyroster_known_hosts",
			"\tStrictHostKeyChecking yes", "\tUpdateHostKeys no", "\tVerifyHostKeyDNS no", "\tRevokedHostKeys ~/.ssh/keyroster_revoked_hosts.krl"}
		if len(lines) != 9 || !slices.Equal(lines[2:], want) {
			t.Fatalf("config lines %q", lines)
		}
		for _, no := range []string{"HostKeyAlias", "CheckHostIP"} {
			if strings.Contains(cfg, no) {
				t.Fatalf("config sets %s", no)
			}
		}
	})
	t.Run("no_active_names_header_only", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		k := f.krlV(t, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, ""), k), hostTrustFull)
		kh := strings.Split(strings.TrimSuffix(f.file(t, hostTrustKnownHosts), "\n"), "\n")
		if len(kh) != 2 || !strings.HasPrefix(kh[0], "# ") || !strings.HasPrefix(kh[1], "# ") {
			t.Fatalf("known_hosts %q, want two comment lines", kh)
		}
		if f.file(t, hostTrustSSHConfig) != htConfig() {
			t.Fatalf("config %q, want the two comment lines", f.file(t, hostTrustSSHConfig))
		}
		if f.file(t, hostTrustKRLFile) != string(k.KRL) {
			t.Fatal("the KRL was not written")
		}
	})
	t.Run("prefix_names_exact", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1"), htHost(t, "web1-old", directory.StatusActive, "web1-old")), f.krlV(t, 1)), hostTrustFull)
		if got := htHostLine(f.file(t, hostTrustSSHConfig)); !slices.Equal(got, []string{"web1", "web1-old"}) {
			t.Fatalf("Host line %q", got)
		}
		for _, names := range htCALines(t, f.file(t, hostTrustKnownHosts)) {
			if !slices.Equal(names, []string{"web1", "web1-old"}) {
				t.Fatalf("CA line names %q", names)
			}
		}
		for _, file := range []string{hostTrustKnownHosts, hostTrustSSHConfig} {
			if strings.ContainsAny(f.file(t, file), "*?!") {
				t.Fatalf("%s holds a pattern byte", file)
			}
		}
	})
	t.Run("names_are_principals_not_entry_names", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "srv1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustFull)
		if got := htHostLine(f.file(t, hostTrustSSHConfig)); !slices.Equal(got, []string{"web1"}) {
			t.Fatalf("Host line %q, want the principal web1 only", got)
		}
		if strings.Contains(f.file(t, hostTrustKnownHosts), "srv1") {
			t.Fatal("the entry name reached known_hosts")
		}
	})
	t.Run("names_sorted_unique_across_entries", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "a", directory.StatusActive, "zz", "mm"), htHost(t, "b", directory.StatusActive, "aa")), f.krlV(t, 1)), hostTrustFull)
		if got := htHostLine(f.file(t, hostTrustSSHConfig)); !slices.Equal(got, []string{"aa", "mm", "zz"}) {
			t.Fatalf("Host line %q", got)
		}
		for _, names := range htCALines(t, f.file(t, hostTrustKnownHosts)) {
			if !slices.Equal(names, []string{"aa", "mm", "zz"}) {
				t.Fatalf("CA names %q", names)
			}
		}
	})

	// Trust semantics.
	t.Run("disabled_name_stays_in_block_without_ca_line", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1"), htHost(t, "web2", directory.StatusDisabled, "web2")), f.krlV(t, 1)), hostTrustFull)
		if got := htHostLine(f.file(t, hostTrustSSHConfig)); !slices.Equal(got, []string{"web1", "web2"}) {
			t.Fatalf("Host line %q", got)
		}
		for _, names := range htCALines(t, f.file(t, hostTrustKnownHosts)) {
			if !slices.Equal(names, []string{"web1"}) {
				t.Fatalf("CA line names %q, want web1 only", names)
			}
		}
	})
	t.Run("removed_name_stays_in_block", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1"), htHost(t, "web2", directory.StatusActive, "web2")), f.krlV(t, 1)), hostTrustFull)
		mustRun(t, f.in(t, f.dirDoc(t, 2, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 2)), hostTrustFull)
		if got := htHostLine(f.file(t, hostTrustSSHConfig)); !slices.Equal(got, []string{"web1", "web2"}) {
			t.Fatalf("Host line %q, want web2 kept from the state", got)
		}
		for _, names := range htCALines(t, f.file(t, hostTrustKnownHosts)) {
			if !slices.Equal(names, []string{"web1"}) {
				t.Fatalf("CA names %q", names)
			}
		}
	})
	t.Run("ca_set_is_an_input", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		other := trust.FormatKey(htSigner(t).PublicKey())
		in := f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1))
		in.CAs = []trust.CAEntry{{Role: trust.RoleHost, Key: other, State: "retired", Generation: 7}}
		mustRun(t, in, hostTrustFull)
		lines := htCALines(t, f.file(t, hostTrustKnownHosts))
		if len(lines) != 1 || lines[other] == nil || !strings.Contains(f.file(t, hostTrustKnownHosts), "generation 7\n") {
			t.Fatalf("known_hosts does not use the CA list given:\n%s", f.file(t, hostTrustKnownHosts))
		}
	})
	t.Run("retired_ca_gets_no_line", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		active := htSigner(t)
		f.bundle.CAs[1].State = "retired"
		f.bundle.CAs = append(f.bundle.CAs, trust.CAEntry{Role: trust.RoleHost, Key: trust.FormatKey(active.PublicKey()), State: "active", Generation: 2})
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustFull)
		lines := htCALines(t, f.file(t, hostTrustKnownHosts))
		if len(lines) != 1 || lines[trust.FormatKey(active.PublicKey())] == nil {
			t.Fatalf("CA lines %v, want the active generation 2 only", lines)
		}
	})
	t.Run("next_ca_gets_a_line", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		next := htSigner(t)
		f.bundle.CAs = append(f.bundle.CAs, trust.CAEntry{Role: trust.RoleHost, Key: trust.FormatKey(next.PublicKey()), State: "next", Generation: 2})
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustFull)
		if lines := htCALines(t, f.file(t, hostTrustKnownHosts)); len(lines) != 2 || lines[trust.FormatKey(next.PublicKey())] == nil {
			t.Fatalf("CA lines %v, want the active and the next CA", lines)
		}
	})
	t.Run("names_outside_charset_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustFull)
		before := f.files(t)
		// A directory value outside [a-z0-9.:-], built without Parse
		// (which refuses it first).
		bad := &directory.Directory{Version: 2, Prev: strings.Repeat("ab", 32), InstallationID: f.install, Users: []directory.User{}, Groups: []directory.Group{}, Roles: []directory.Role{},
			HostGroups: []directory.HostGroup{{Name: "web", Accounts: []directory.AccountMap{}}},
			Hosts:      []directory.Host{{Name: "web9", HostGroup: "web", Keys: []string{trust.FormatKey(htSigner(t).PublicKey())}, Principals: []string{"Web9"}, Status: directory.StatusActive}}}
		if _, _, err := hostTrustNames(bad); err == nil {
			t.Fatal("hostTrustNames accepted Web9")
		}
		doc, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		prev := parseHostTrustDirectory
		parseHostTrustDirectory = func(data []byte) (*directory.Directory, error) {
			var d directory.Directory
			return &d, json.Unmarshal(data, &d)
		}
		t.Cleanup(func() { parseHostTrustDirectory = prev })
		k := f.krlV(t, 2)
		stdout, _ := mustRun(t, f.in(t, doc, k), hostTrustPartial)
		if !strings.Contains(stdout, "revocations only") || !strings.Contains(stdout, `"Web9"`) {
			t.Fatalf("stdout %q", stdout)
		}
		after := f.files(t)
		if after[hostTrustKnownHosts] != before[hostTrustKnownHosts] || after[hostTrustSSHConfig] != before[hostTrustSSHConfig] || after[hostTrustKRLFile] != string(k.KRL) {
			t.Fatal("the names were refreshed, or the KRL was not written")
		}
	})

	// Verification.
	web1 := func(t *testing.T, f *htFix, v uint64) []byte {
		return f.dirDoc(t, v, "", htHost(t, "web1", directory.StatusActive, "web1"))
	}
	t.Run("forged_directory_runs_krl_only", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		before := f.files(t)
		doc := f.dirDoc(t, 2, "", htHost(t, "web2", directory.StatusActive, "web2"))
		in := f.in(t, doc, f.krlV(t, 2))
		in.DirSigs = htSign(t, doc, htSigner(t))
		stdout, _ := mustRun(t, in, hostTrustPartial)
		if !strings.HasPrefix(stdout, "Host trust partly refreshed: revocations only (the directory the server sent is not signed by the policy admins") {
			t.Fatalf("stdout %q", stdout)
		}
		after := f.files(t)
		if after[hostTrustKnownHosts] != before[hostTrustKnownHosts] || after[hostTrustSSHConfig] != before[hostTrustSSHConfig] {
			t.Fatal("known_hosts or the config changed")
		}
		if after[hostTrustKRLFile] != string(in.KRL.KRL) || f.state(t).KRLVersion != 2 || f.state(t).DirectoryVersion != 1 {
			t.Fatalf("the KRL or the state's KRL version was not written: state %+v", f.state(t))
		}
	})
	t.Run("forged_directory_without_state_writes_nothing", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		doc := web1(t, f, 1)
		in := f.in(t, doc, f.krlV(t, 1))
		in.DirSigs = htSign(t, doc, htSigner(t))
		mustRun(t, in, hostTrustNone)
		f.requireNothingWritten(t)
	})
	t.Run("directory_below_quorum_refused", func(t *testing.T) {
		f := newHTFix(t, 2, 2)
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		before := f.files(t)
		doc := web1(t, f, 2)
		in := f.in(t, doc, f.krlV(t, 2))
		in.DirSigs = htSign(t, doc, f.admins[0])
		mustRun(t, in, hostTrustPartial)
		if after := f.files(t); after[hostTrustKnownHosts] != before[hostTrustKnownHosts] || f.state(t).DirectoryVersion != 1 {
			t.Fatal("a directory below the quorum was used")
		}
	})
	t.Run("directory_without_installation_id_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		stdout, _ := mustRun(t, f.in(t, f.dirDoc(t, 1, "-", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustNone)
		if !strings.Contains(stdout, "is bound to installation none") {
			t.Fatalf("stdout %q", stdout)
		}
		f.requireNothingWritten(t)
	})
	t.Run("directory_other_installation_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, f.dirDoc(t, 1, htInstall(t), htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1)), hostTrustNone)
		f.requireNothingWritten(t)
	})
	t.Run("no_krl_writes_nothing", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		stdout, _ := mustRun(t, f.in(t, web1(t, f, 1), nil), hostTrustNone)
		if stdout != "Host trust not refreshed: the server serves no KRL.\n" {
			t.Fatalf("stdout %q", stdout)
		}
		f.requireNothingWritten(t)
		if _, err := os.Lstat(f.sshDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("~/.ssh was created: %v", err)
		}
	})
	t.Run("krl_without_installation_id_writes_nothing", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		in := f.in(t, web1(t, f, 1), f.krlV(t, 1))
		b := *f.bundle
		b.InstallationID = ""
		in.Bundle = &b
		mustRun(t, in, hostTrustNone)
		f.requireNothingWritten(t)
	})
	t.Run("krl_other_installation_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, web1(t, f, 1), htKRLDoc(t, 1, time.Now(), htInstall(t), f.ops, krl.Set{})), hostTrustNone)
		f.requireNothingWritten(t)
	})
	t.Run("krl_other_signer_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, web1(t, f, 1), htKRLDoc(t, 1, time.Now(), f.install, htSigner(t), krl.Set{})), hostTrustNone)
		f.requireNothingWritten(t)
	})

	// Rollback and freshness.
	t.Run("older_krl_refused_equal_accepted", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		k5, d1 := f.krlV(t, 5), web1(t, f, 1)
		mustRun(t, f.in(t, d1, k5), hostTrustFull)
		before := f.files(t)
		mustRun(t, f.in(t, d1, f.krlV(t, 4)), hostTrustNone)
		if after := f.files(t); !mapsEqual(before, after) {
			t.Fatal("an older KRL changed a file")
		}
		mustRun(t, f.in(t, d1, k5), hostTrustFull)
	})
	t.Run("krl_floor_has_no_underflow", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		st := &hostTrustState{Format: 1, InstallationID: f.install, BundleVersion: 1, OpsKey: f.bundle.OpsKey.Key, Names: []string{}}
		data, err := st.encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(f.statePath), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, f.statePath, data)
		d1 := web1(t, f, 1)
		mustRun(t, f.in(t, d1, f.krlV(t, 1)), hostTrustFull) // stored 0
		mustRun(t, f.in(t, d1, f.krlV(t, 1)), hostTrustFull) // stored 1, equal
		if f.state(t).KRLVersion != 1 {
			t.Fatalf("state %+v", f.state(t))
		}
	})
	t.Run("older_bundle_freezes_ca_lines_krl_still_written", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		f.bundle.Version = 2
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		before, stBefore := f.files(t), f.state(t)
		// A restore brings back bundle version 1 with another ops key and
		// another host CA; its KRL is signed by the STORED ops key.
		oldOps := htSigner(t)
		old := &trust.Bundle{Version: 1, InstallationID: f.install, OpsKey: trust.KeyEntry{Key: trust.FormatKey(oldOps.PublicKey())},
			CAs: []trust.CAEntry{{Role: trust.RoleHost, Key: trust.FormatKey(htSigner(t).PublicKey()), State: "active", Generation: 1}}}
		in := f.in(t, f.dirDoc(t, 2, "", htHost(t, "web2", directory.StatusActive, "web2")), f.krlV(t, 2))
		in.Bundle, in.CAs = old, hostTrustCAs(old, time.Now())
		res, stdout, stderr := htWrite(in)
		if res != hostTrustPartial || !strings.HasPrefix(stdout, "Host trust partly refreshed: revocations only (") {
			t.Fatalf("result %d, stdout %q, stderr %q", res, stdout, stderr)
		}
		if !strings.Contains(stderr, "trust bundle version 1, older than version 2") {
			t.Fatalf("stderr %q does not name both versions", stderr)
		}
		var ee *exitError
		if err := hostTrustExit(res); !errors.As(err, &ee) || ee.code != 3 {
			t.Fatalf("known-hosts sync's exit for this outcome: %v, want 3", err)
		}
		after, stAfter := f.files(t), f.state(t)
		if after[hostTrustKnownHosts] != before[hostTrustKnownHosts] || after[hostTrustSSHConfig] != before[hostTrustSSHConfig] {
			t.Fatal("an older bundle changed the CA lines or the Host block")
		}
		if after[hostTrustKRLFile] != string(in.KRL.KRL) || stAfter.KRLVersion != 2 {
			t.Fatal("the KRL signed by the stored ops key was not written")
		}
		stBefore.KRLVersion = 2
		if !slices.Equal(stAfter.Names, stBefore.Names) || stAfter.BundleVersion != 2 || stAfter.OpsKey != stBefore.OpsKey || stAfter.DirectoryVersion != 1 || stAfter.DirectorySHA256 != stBefore.DirectorySHA256 {
			t.Fatalf("state %+v, want %+v", stAfter, stBefore)
		}
		// An equal version with the stored key is a normal run.
		mustRun(t, f.in(t, f.dirDoc(t, 2, "", htHost(t, "web2", directory.StatusActive, "web2")), f.krlV(t, 3)), hostTrustFull)
	})
	t.Run("equal_bundle_other_ops_key_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		before := f.files(t)
		other := htSigner(t)
		b := *f.bundle
		b.OpsKey.Key = trust.FormatKey(other.PublicKey())
		in := f.in(t, web1(t, f, 2), htKRLDoc(t, 2, time.Now(), f.install, other, krl.Set{}))
		in.Bundle = &b
		mustRun(t, in, hostTrustNone)
		if !mapsEqual(before, f.files(t)) {
			t.Fatal("an equal bundle with another ops key changed a file")
		}
	})
	t.Run("older_bundle_krl_by_retired_key_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		f.bundle.Version = 2
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		before := f.files(t)
		oldOps := htSigner(t)
		old := &trust.Bundle{Version: 1, InstallationID: f.install, OpsKey: trust.KeyEntry{Key: trust.FormatKey(oldOps.PublicKey())}, CAs: f.bundle.CAs}
		in := f.in(t, web1(t, f, 2), htKRLDoc(t, 2, time.Now(), f.install, oldOps, krl.Set{}))
		in.Bundle = old
		mustRun(t, in, hostTrustNone)
		if !mapsEqual(before, f.files(t)) {
			t.Fatal("a KRL signed by the older bundle's own ops key was written")
		}
	})
	t.Run("first_run_records_ops_key", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		f.bundle.Version = 3
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		if st := f.state(t); st.OpsKey != trust.FormatKey(f.ops.PublicKey()) || st.BundleVersion != 3 {
			t.Fatalf("state %+v", st)
		}
	})
	t.Run("newer_bundle_rotates_stored_ops_key", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		other := htSigner(t)
		b := *f.bundle
		b.Version, b.OpsKey.Key = 2, trust.FormatKey(other.PublicKey())
		in := f.in(t, web1(t, f, 2), htKRLDoc(t, 2, time.Now(), f.install, other, krl.Set{}))
		in.Bundle = &b
		mustRun(t, in, hostTrustFull)
		if st := f.state(t); st.OpsKey != b.OpsKey.Key || st.BundleVersion != 2 {
			t.Fatalf("state %+v", st)
		}
	})
	t.Run("older_directory_refused_equal_accepted", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		d3 := web1(t, f, 3)
		mustRun(t, f.in(t, d3, f.krlV(t, 1)), hostTrustFull)
		stdout, _ := mustRun(t, f.in(t, web1(t, f, 2), f.krlV(t, 2)), hostTrustPartial)
		if !strings.Contains(stdout, "directory version 2, older than version 3") {
			t.Fatalf("stdout %q", stdout)
		}
		mustRun(t, f.in(t, d3, f.krlV(t, 2)), hostTrustFull)
	})
	t.Run("equal_version_other_sha_refused", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, f.in(t, web1(t, f, 3), f.krlV(t, 1)), hostTrustFull)
		before := f.files(t)
		other := f.dirDoc(t, 3, "", htHost(t, "web2", directory.StatusActive, "web2"))
		stdout, _ := mustRun(t, f.in(t, other, f.krlV(t, 2)), hostTrustPartial)
		if !strings.Contains(stdout, "with another SHA-256") || f.files(t)[hostTrustKnownHosts] != before[hostTrustKnownHosts] {
			t.Fatalf("stdout %q", stdout)
		}
	})
	t.Run("stale_manifest_warned_still_written", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		issued := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
		k := htKRLDoc(t, 1, issued, f.install, f.ops, krl.Set{})
		in := f.in(t, web1(t, f, 1), k)
		in.Now = issued.Add(24*time.Hour - time.Second)
		if _, stderr := mustRun(t, in, hostTrustFull); stderr != "" {
			t.Fatalf("a manifest 24 h minus 1 s old warned: %q", stderr)
		}
		in.Now = issued.Add(24*time.Hour + time.Second)
		_, stderr := mustRun(t, in, hostTrustFull)
		if !strings.Contains(stderr, "24h0m1s ago") {
			t.Fatalf("stderr %q, want a warning naming the age", stderr)
		}
		if f.file(t, hostTrustKRLFile) != string(k.KRL) {
			t.Fatal("a stale KRL was not written")
		}
	})

	// Order and rewrites.
	t.Run("state_written_first", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		useFault(t, func(step string) error { return errors.New("stop after " + step) })
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustNone)
		files := f.files(t)
		if files[hostTrustStateFile] == "" || files[hostTrustKRLFile] != "" || files[hostTrustKnownHosts] != "" || files[hostTrustSSHConfig] != "" {
			t.Fatal("the state is not written first")
		}
	})
	t.Run("krl_known_hosts_config_in_order", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		var steps []string
		useFault(t, func(step string) error { steps = append(steps, step); return nil })
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		if !slices.Equal(steps, []string{"state", "krl", "known_hosts", "config"}) {
			t.Fatalf("steps %q", steps)
		}
		steps = nil
		in := f.in(t, nil, f.krlV(t, 2))
		mustRun(t, in, hostTrustPartial)
		if !slices.Equal(steps, []string{"state", "krl"}) {
			t.Fatalf("revocations-only steps %q", steps)
		}
	})
	t.Run("unchanged_not_rewritten", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		in := f.in(t, web1(t, f, 1), f.krlV(t, 1))
		mustRun(t, in, hostTrustFull)
		old := time.Now().Add(-time.Hour).Truncate(time.Second)
		paths := []string{f.statePath}
		for _, n := range []string{hostTrustKRLFile, hostTrustKnownHosts, hostTrustSSHConfig} {
			paths = append(paths, filepath.Join(f.sshDir, n))
		}
		for _, p := range paths {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
		mustRun(t, in, hostTrustFull)
		for _, p := range paths {
			fi, err := os.Stat(p)
			if err != nil || !fi.ModTime().Equal(old) {
				t.Fatalf("%s was rewritten (%v)", p, err)
			}
		}
	})
	t.Run("byte_identical_resync", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		in := f.in(t, web1(t, f, 1), f.krlV(t, 1))
		mustRun(t, in, hostTrustFull)
		before := f.files(t)
		mustRun(t, in, hostTrustFull)
		if !mapsEqual(before, f.files(t)) {
			t.Fatal("a resync changed a file")
		}
	})
	t.Run("ssh_config_and_known_hosts_never_written", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		if err := os.Mkdir(f.sshDir, 0o700); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Hour).Truncate(time.Second)
		for _, n := range []string{"config", "known_hosts"} {
			p := filepath.Join(f.sshDir, n)
			writeTestFile(t, p, []byte("user's own "+n+"\n"))
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
		mustRun(t, f.in(t, web1(t, f, 1), f.krlV(t, 1)), hostTrustFull)
		for _, n := range []string{"config", "known_hosts"} {
			p := filepath.Join(f.sshDir, n)
			fi, err := os.Stat(p)
			if err != nil || !fi.ModTime().Equal(old) || string(readTestFile(t, p)) != "user's own "+n+"\n" {
				t.Fatalf("~/.ssh/%s was written (%v)", n, err)
			}
		}
	})

	// Interruption.
	t.Run("interrupted_write_never_widens_trust", func(t *testing.T) {
		testInterruptedWrite(t)
	})
}

// mapsEqual reports whether two file maps are equal.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// useFault installs hook as hostTrustFault for the test.
func useFault(t *testing.T, hook func(step string) error) {
	t.Helper()
	prev := hostTrustFault
	hostTrustFault = hook
	t.Cleanup(func() { hostTrustFault = prev })
}

// htAccepts is a model of ssh's rule for a name in the managed block: the
// name is in the Host line, a CA line lists it under ca, and the KRL does
// not revoke serial under ca. Missing files accept nothing.
func htAccepts(t *testing.T, f *htFix, name string, ca ssh.PublicKey, serial uint64) bool {
	t.Helper()
	if !slices.Contains(htHostLine(f.file(t, hostTrustSSHConfig)), name) {
		return false
	}
	if !slices.Contains(htCALines(t, f.file(t, hostTrustKnownHosts))[trust.FormatKey(ca)], name) {
		return false
	}
	data := f.file(t, hostTrustKRLFile)
	if data == "" {
		return false // RevokedHostKeys names a missing file: ssh refuses
	}
	p, err := krl.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return !p.RevokesSerial(ca.Marshal(), serial)
}

// testInterruptedWrite (T-03-241, T-03-346): from state S to S', with a
// name disabled and one added, a CA retired and one added, a serial added
// to the KRL, and a disabled name re-enabled while one of its
// certificates is revoked in the same refresh, a run that stops after any
// of the four steps accepts no (name, CA, serial) that neither S nor S'
// accepts, and the next uninterrupted run converges to S' byte for byte.
func testInterruptedWrite(t *testing.T) {
	c1, c2, c3 := htSigner(t), htSigner(t), htSigner(t)
	type world struct {
		bundle *trust.Bundle
		doc    []byte
		k      *serverclient.KRLDocument
	}
	build := func(t *testing.T, f *htFix) (s, s2 world) {
		ca := func(k ssh.Signer, state string, gen uint32) trust.CAEntry {
			return trust.CAEntry{Role: trust.RoleHost, Key: trust.FormatKey(k.PublicKey()), State: state, Generation: gen}
		}
		ops := trust.KeyEntry{Key: trust.FormatKey(f.ops.PublicKey())}
		s.bundle = &trust.Bundle{Version: 1, InstallationID: f.install, OpsKey: ops, CAs: []trust.CAEntry{ca(c1, "active", 1), ca(c2, "next", 2)}}
		s2.bundle = &trust.Bundle{Version: 2, InstallationID: f.install, OpsKey: ops, CAs: []trust.CAEntry{ca(c1, "retired", 1), ca(c2, "active", 2), ca(c3, "next", 3)}}
		keep, gone, back := htHost(t, "a", directory.StatusActive, "n-a"), htHost(t, "d", directory.StatusActive, "n-d"), htHost(t, "r", directory.StatusDisabled, "n-r")
		s.doc = f.dirDoc(t, 1, "", keep, gone, back)
		gone.Status, back.Status = directory.StatusDisabled, directory.StatusActive
		s2.doc = f.dirDoc(t, 2, "", keep, gone, back, htHost(t, "e", directory.StatusActive, "n-e"))
		s.k = htKRLDoc(t, 1, time.Now(), f.install, f.ops, krl.Set{Certs: []krl.CertSection{{CAKey: c1.PublicKey(), Serials: []uint64{1}}}})
		s2.k = htKRLDoc(t, 2, time.Now(), f.install, f.ops, krl.Set{Certs: []krl.CertSection{
			{CAKey: c1.PublicKey(), Serials: []uint64{1, 5}}, {CAKey: c2.PublicKey(), Serials: []uint64{7}}}})
		return s, s2
	}
	input := func(t *testing.T, f *htFix, w world) hostTrustInput {
		in := f.in(t, w.doc, w.k)
		in.Bundle, in.CAs = w.bundle, hostTrustCAs(w.bundle, time.Now())
		return in
	}
	names := []string{"n-a", "n-d", "n-e", "n-r", "n-x"}
	cas := []ssh.PublicKey{c1.PublicKey(), c2.PublicKey(), c3.PublicKey()}
	serials := []uint64{1, 5, 7, 9}
	accepted := func(t *testing.T, f *htFix) map[string]bool {
		out := map[string]bool{}
		for _, n := range names {
			for i, ca := range cas {
				for _, s := range serials {
					if htAccepts(t, f, n, ca, s) {
						out[fmt.Sprintf("%s/c%d/%d", n, i+1, s)] = true
					}
				}
			}
		}
		return out
	}

	// The reference: S, then S' uninterrupted.
	ref := newHTFix(t, 1, 1)
	s, s2 := build(t, ref)
	mustRun(t, input(t, ref, s), hostTrustFull)
	accS := accepted(t, ref)
	mustRun(t, input(t, ref, s2), hostTrustFull)
	accS2 := accepted(t, ref)
	want := ref.files(t)
	if !accS["n-a/c1/9"] || accS["n-r/c2/7"] || accS2["n-r/c2/7"] || !accS2["n-r/c2/9"] {
		t.Fatalf("the scenario does not exercise the re-enable with a revoked serial: S %v, S' %v", accS, accS2)
	}
	for _, step := range []string{"state", "krl", "known_hosts", "config"} {
		f := newHTFix(t, 1, 1)
		f.install, f.ops, f.admins, f.pol = ref.install, ref.ops, ref.admins, ref.pol
		mustRun(t, input(t, f, s), hostTrustFull)
		stop := step
		useFault(t, func(got string) error {
			if got == stop {
				return errors.New("interrupted after " + got)
			}
			return nil
		})
		htWrite(input(t, f, s2))
		for k := range accepted(t, f) {
			if !accS[k] && !accS2[k] {
				t.Fatalf("interrupted after %s: %s is accepted, which neither S nor S' accepts", step, k)
			}
		}
		hostTrustFault = nil
		mustRun(t, input(t, f, s2), hostTrustFull)
		if got := f.files(t); !mapsEqual(got, want) {
			t.Fatalf("after the interruption at %s, the next run does not converge to S'", step)
		}
	}
}

// TestKnownHostsSync (03-09b): keyroster known-hosts sync against the
// stub server.
func TestKnownHostsSync(t *testing.T) {
	serveKRL := func(t *testing.T, e *dirEnv, v uint64) {
		doc := e.krlDoc(t, v, v, e.bundle.InstallationID, e.ops)
		e.mu.Lock()
		defer e.mu.Unlock()
		e.override["GET "+serverclient.KRLPath] = func(w http.ResponseWriter) { _, _ = w.Write(doc) }
	}
	t.Run("sync_writes_from_admin_routes", func(t *testing.T) {
		e, _ := hostEnv(t)
		serveKRL(t, e, 1)
		sshDir := useSSHDir(t)
		code, stdout, stderr := run(t, "known-hosts", "sync")
		if code != 0 || stdout != "Host trust refreshed (directory v2, KRL v1, 2 names).\n" {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		cfg := string(readTestFile(t, filepath.Join(sshDir, hostTrustSSHConfig)))
		if !strings.Contains(cfg, "Host web1 web1.lab.example\n") {
			t.Fatalf("config %q", cfg)
		}
	})
	t.Run("sync_needs_an_admin_key", func(t *testing.T) {
		e, _ := hostEnv(t)
		serveKRL(t, e, 1)
		useSSHDir(t)
		e.cfg.AdminKey = ""
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := run(t, "known-hosts", "sync")
		if code != 1 || !strings.Contains(stderr, "no admin key") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("sync_exit_0_when_refreshed_and_when_unchanged", func(t *testing.T) {
		e, _ := hostEnv(t)
		serveKRL(t, e, 1)
		useSSHDir(t)
		for i := range 2 {
			if code, stdout, stderr := run(t, "known-hosts", "sync"); code != 0 || !strings.HasPrefix(stdout, "Host trust refreshed (") {
				t.Fatalf("run %d: exit %d, stdout %q, stderr %q", i, code, stdout, stderr)
			}
		}
	})
	t.Run("sync_exit_1_when_nothing_written", func(t *testing.T) {
		hostEnv(t)
		sshDir := useSSHDir(t)
		code, stdout, _ := run(t, "known-hosts", "sync")
		if code != 1 || stdout != "Host trust not refreshed: the server serves no KRL.\n" {
			t.Fatalf("exit %d, stdout %q", code, stdout)
		}
		if _, err := os.Lstat(sshDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("~/.ssh was created: %v", err)
		}
	})
	t.Run("usage_errors", func(t *testing.T) {
		for _, args := range [][]string{{"known-hosts"}, {"known-hosts", "frob"}, {"known-hosts", "sync", "extra"}, {"known-hosts", "sync", "--bogus"}} {
			if code, _, _ := run(t, args...); code != 2 {
				t.Fatalf("%q: exit %d, want 2", args, code)
			}
		}
	})
}
