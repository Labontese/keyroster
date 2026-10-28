package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// resignBundle serves e's genesis bundle changed by edit, re-signed by
// the root, as the bundle in force.
func (e *dirEnv) resignBundle(t *testing.T, edit func(b *trust.Bundle)) {
	t.Helper()
	b := *e.bundle
	edit(&b)
	doc, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	root, err := ssh.NewSignerFromKey(e.root)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, root, trust.NamespaceBundle, doc)
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var tr serverclient.TrustResponse
	if err := json.Unmarshal(e.trustDoc, &tr); err != nil {
		t.Fatal(err)
	}
	tr.Bundle, tr.BundleSigs = doc, sig
	if e.trustDoc, err = json.Marshal(tr); err != nil {
		t.Fatal(err)
	}
	e.bundle = &b
}

// writeEntryKey writes a fresh Ed25519 public key file (with a comment,
// as ssh-keygen writes one) and returns its path and the key's
// trust.FormatKey form.
func writeEntryKey(t *testing.T, name string) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name+".pub")
	writeTestFile(t, path, []byte(trust.FormatKey(pub)+" root@"+name+"\n"))
	return path, trust.FormatKey(pub)
}

// hostEnv is roleEnv with host web1 (host group web, principals web1 and
// web1.lab.example) added through keyroster host add, so the installed
// directory is version 2, bound to the bundle's installation.
func hostEnv(t *testing.T) (*dirEnv, string) {
	t.Helper()
	e := roleEnv(t, nil)
	keyFile, key := writeEntryKey(t, "web1")
	if code, stdout, stderr := run(t, "host", "add", "web1", "--group", "web", "--key", keyFile, "--principal", "web1.lab.example", "--principal", "web1", "--yes"); code != 0 {
		t.Fatalf("host add web1: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	return e, key
}

// TestHostCommands covers keyroster host add, remove, list and principals
// --host against the fake server.
func TestHostCommands(t *testing.T) {
	t.Run("host_add_copies_installation_id", func(t *testing.T) {
		e := roleEnv(t, nil)
		if e.bundle.InstallationID == "" {
			t.Fatal("the fixture bundle has no installation ID")
		}
		keyFile, key := writeEntryKey(t, "web1")
		code, stdout, stderr := run(t, "host", "add", "web1", "--group", "web", "--key", keyFile, "--principal", "web1.lab.example", "--principal", "web1", "--yes")
		if code != 0 {
			t.Fatalf("host add: exit %d, stderr %s", code, stderr)
		}
		for _, want := range []string{"+ installation_id " + e.bundle.InstallationID, "+ host web1 host_group=web status=active principals=[web1 web1.lab.example] keys=[ssh-ed25519 SHA256:"} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("host add diff lacks %q:\n%s", want, stdout)
			}
		}
		d := installedDir(t, e)
		h, ok := d.HostByName("web1")
		if d.InstallationID != e.bundle.InstallationID || !ok || len(h.Keys) != 1 || h.Keys[0] != key {
			t.Fatalf("installed: installation %q, host %+v; want %s and the key without its comment", d.InstallationID, h, e.bundle.InstallationID)
		}
	})
	t.Run("host_add_refusals", func(t *testing.T) {
		e := roleEnv(t, nil)
		keyFile, _ := writeEntryKey(t, "web1")
		privFile := filepath.Join(t.TempDir(), "id_web1")
		writeTestFile(t, privFile, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
		for _, tc := range []struct {
			name string
			args []string
			want string
		}{
			{"unknown_group", []string{"--group", "db", "--key", keyFile, "--principal", "web1"}, "there is no host group db"},
			{"uppercase_principal", []string{"--group", "web", "--key", keyFile, "--principal", "Web1"}, "as web1"},
			{"ipv6_uncompressed_principal", []string{"--group", "web", "--key", keyFile, "--principal", "2001:db8:0:0::1"}, "write 2001:db8::1"},
			{"wildcard_principal", []string{"--group", "web", "--key", keyFile, "--principal", "*.lab.example"}, "no wildcard"},
			{"private_key_file", []string{"--group", "web", "--key", privFile, "--principal", "web1"}, "contains a private key"},
			{"missing_group", []string{"--key", keyFile, "--principal", "web1"}, "--group is required"},
			{"missing_principal", []string{"--group", "web", "--key", keyFile}, "at least one --key and one --principal"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				check := unchanged(t, e)
				code, _, stderr := run(t, append([]string{"host", "add", "web1", "--yes"}, tc.args...)...)
				if code == 0 || !strings.Contains(stderr, tc.want) {
					t.Fatalf("host add %v: exit %d, stderr %q; want a refusal naming %q", tc.args, code, stderr, tc.want)
				}
				check()
			})
		}
	})
	t.Run("host_add_duplicate_refused", func(t *testing.T) {
		e, _ := hostEnv(t)
		keyFile, _ := writeEntryKey(t, "web1b")
		check := unchanged(t, e)
		code, _, stderr := run(t, "host", "add", "web1", "--group", "web", "--key", keyFile, "--principal", "web1b", "--yes")
		if code == 0 || !strings.Contains(stderr, "host web1 is already in the directory") {
			t.Fatalf("host add web1 again: exit %d, stderr %q", code, stderr)
		}
		check()
	})
	t.Run("host_principal_on_two_hosts_refused", func(t *testing.T) {
		e, _ := hostEnv(t)
		keyFile, _ := writeEntryKey(t, "web2")
		check := unchanged(t, e)
		code, _, stderr := run(t, "host", "add", "web2", "--group", "web", "--key", keyFile, "--principal", "web1", "--yes")
		if code == 0 || !strings.Contains(stderr, "host principal web1 is on hosts web1 and web2") {
			t.Fatalf("host add web2 with web1's name: exit %d, stderr %q", code, stderr)
		}
		check()
	})
	t.Run("host_list_and_remove", func(t *testing.T) {
		e, _ := hostEnv(t)
		code, stdout, stderr := run(t, "host", "list")
		if code != 0 || !strings.Contains(stdout, "web1 host_group=web status=active principals=[web1 web1.lab.example]") || !strings.Contains(stdout, "installation "+e.bundle.InstallationID) {
			t.Fatalf("host list: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr := run(t, "host", "remove", "web1", "--yes"); code != 0 || !strings.Contains(stdout, "- host web1 ") {
			t.Fatalf("host remove: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if _, ok := installedDir(t, e).HostByName("web1"); ok {
			t.Fatal("web1 is still in the installed directory")
		}
		if code, _, stderr := run(t, "host", "remove", "web1", "--yes"); code == 0 || !strings.Contains(stderr, "there is no host web1") {
			t.Fatalf("host remove of a removed host: exit %d, stderr %q", code, stderr)
		}
	})
	t.Run("host_principals_by_host", func(t *testing.T) {
		e, _ := hostEnv(t)
		code, stdout, stderr := run(t, "host", "principals", "--host", "web1", "root")
		want, err := directory.RenderPrincipalsFile(installedDir(t, e), "web", "root")
		if err != nil {
			t.Fatal(err)
		}
		if code != 0 || stdout != string(want) || !strings.HasSuffix(stdout, "\nrole:ops\n") {
			t.Fatalf("host principals --host web1 root: exit %d, stderr %q, stdout %q; want %q", code, stderr, stdout, want)
		}
	})
	t.Run("host_principals_unknown_host_refused", func(t *testing.T) {
		hostEnv(t)
		code, stdout, stderr := run(t, "host", "principals", "--host", "web2", "root")
		if code == 0 || stdout != "" || !strings.Contains(stderr, "directory version 2 has no active host web2") {
			t.Fatalf("host principals --host web2: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
	t.Run("host_group_remove_refused_while_used", func(t *testing.T) {
		e, _ := hostEnv(t)
		run(t, "host-group", "unmap", "web", "root", "--yes")
		check := unchanged(t, e)
		code, _, stderr := run(t, "host-group", "remove", "web", "--yes")
		if code == 0 || !strings.Contains(stderr, "host group web is the host group of host(s) web1") {
			t.Fatalf("host-group remove web while web1 names it: exit %d, stderr %q", code, stderr)
		}
		check()
	})
}

// TestDirectoryRebind covers keyroster directory rebind: the next version,
// identical but for the bundle's installation ID, and its three refusals.
func TestDirectoryRebind(t *testing.T) {
	t.Run("rebind_writes_only_installation_id", func(t *testing.T) {
		e := roleEnv(t, nil)
		v1, _ := e.installed()
		code, stdout, stderr := run(t, "directory", "rebind", "--yes")
		if code != 0 {
			t.Fatalf("directory rebind: exit %d, stderr %s", code, stderr)
		}
		v2, _ := e.installed()
		before, after := installedDirOf(t, v1), installedDirOf(t, v2)
		if after.Version != 2 || after.Prev != trust.SHA256Hex(v1) || after.InstallationID != e.bundle.InstallationID {
			t.Fatalf("rebind installed version %d prev %s installation %q", after.Version, after.Prev, after.InstallationID)
		}
		if got := directory.Diff(before, after); len(got) != 1 || got[0] != "+ installation_id "+e.bundle.InstallationID {
			t.Fatalf("the rebind changed more than the installation ID: %q", got)
		}
		after.Version, after.Prev, after.InstallationID = before.Version, before.Prev, ""
		if a, b := mustJSON(t, after), mustJSON(t, before); a != b {
			t.Fatalf("the rebind changed the lists:\n%s\nwant\n%s", a, b)
		}
		if !strings.Contains(stdout, "+ installation_id "+e.bundle.InstallationID) {
			t.Fatalf("the rebind diff does not show the ID:\n%s", stdout)
		}
	})
	t.Run("rebind_refused_when_already_bound", func(t *testing.T) {
		e := roleEnv(t, nil)
		if code, _, stderr := run(t, "directory", "rebind", "--yes"); code != 0 {
			t.Fatalf("first rebind: %s", stderr)
		}
		check := unchanged(t, e)
		code, _, stderr := run(t, "directory", "rebind", "--yes")
		if code == 0 || !strings.Contains(stderr, "already bound to installation "+e.bundle.InstallationID) {
			t.Fatalf("second rebind: exit %d, stderr %q", code, stderr)
		}
		check()
	})
	t.Run("rebind_refused_other_installation", func(t *testing.T) {
		const other = "ffffffffffffffffffffffffffffffff"
		e := newDirEnv(t, 1, 1)
		e.installDirect(t, buildDir(t, nil, func(d *directory.Directory) {
			roleBase(t, nil)(d)
			d.InstallationID = other
		}))
		check := unchanged(t, e)
		code, _, stderr := run(t, "directory", "rebind", "--yes")
		if code == 0 || !strings.Contains(stderr, "bound to installation "+other) || !strings.Contains(stderr, "names "+e.bundle.InstallationID) {
			t.Fatalf("rebind of another installation's directory: exit %d, stderr %q; want both IDs", code, stderr)
		}
		check()
		// Every other edit refuses that base too.
		code, _, stderr = run(t, "role", "add", "deploy", "--max-ttl", "1h", "--yes")
		if code == 0 || !strings.Contains(stderr, "bound to installation "+other) {
			t.Fatalf("role add on another installation's directory: exit %d, stderr %q", code, stderr)
		}
		check()
	})
	t.Run("rebind_refused_without_bundle_id", func(t *testing.T) {
		e := roleEnv(t, nil)
		e.resignBundle(t, func(b *trust.Bundle) { b.InstallationID = "" })
		check := unchanged(t, e)
		code, _, stderr := run(t, "directory", "rebind", "--yes")
		if code == 0 || !strings.Contains(stderr, "has no installation ID, so there is nothing to bind the directory to") {
			t.Fatalf("rebind under a bundle without an ID: exit %d, stderr %q", code, stderr)
		}
		check()
	})
}

// unchanged records the agent's directory signatures and the install
// posts so far; its result fails unless neither grew (a refusal before
// signing).
func unchanged(t *testing.T, e *dirEnv) func() {
	t.Helper()
	signs := e.agent.dirSigns()
	_, posts := e.installed()
	return func() {
		t.Helper()
		if n := e.agent.dirSigns(); n != signs {
			t.Fatalf("the agent got %d new directory sign requests, want 0", n-signs)
		}
		if _, p := e.installed(); p != posts {
			t.Fatalf("%d new install posts, want 0", p-posts)
		}
	}
}

// installedDirOf parses doc.
func installedDirOf(t *testing.T, doc []byte) *directory.Directory {
	t.Helper()
	d, err := directory.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestReadCommandsCheckInstallation (pre-merge review, 03-04): every
// command that reads the served directory applies the signer's
// installation rule for an installed directory (fetchVerifiedDirectory,
// directory.CheckStoredInstallation). A directory bound to another
// installation, or to one under a bundle without an ID, is refused with
// nothing printed; an ID-less directory under a bundle with an ID is read.
// directory sign and directory install read it too, as the base of a
// proposal (PR #65 fix check): each gets a proposal bound to the bundle's
// own installation, so the only refusal left is the served directory's,
// and neither asks the agent nor posts anything.
func TestReadCommandsCheckInstallation(t *testing.T) {
	const other = "ffffffffffffffffffffffffffffffff"
	reads := [][]string{
		{"directory", "show"},
		{"user", "list"},
		{"host", "list"},
		{"machine", "list"},
		{"host", "principals", "web", "root"},
	}
	// proposalReads are directory sign and directory install of a proposal
	// that follows the served directory and names the bundle's ID.
	proposalReads := func(t *testing.T, e *dirEnv) [][]string {
		t.Helper()
		served, _ := e.installed()
		doc := buildDir(t, served, boundTo(e.bundle.InstallationID, func(d *directory.Directory) {
			d.Groups = append(d.Groups, directory.Group{Name: "zed", Members: []string{}})
		}))
		dir := writeProposalDir(t, doc, e.sign(t, doc, 0))
		return [][]string{{"directory", "sign", dir, "--yes"}, {"directory", "install", dir}}
	}
	bound := func(t *testing.T, e *dirEnv, id string) {
		t.Helper()
		e.installDirect(t, buildDir(t, nil, func(d *directory.Directory) {
			roleBase(t, nil)(d)
			d.InstallationID = id
		}))
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) *dirEnv
		want  string
	}{
		{"other_installation", func(t *testing.T) *dirEnv {
			e := newDirEnv(t, 1, 1)
			bound(t, e, other)
			return e
		}, "bound to installation " + other + ", but the root-verified trust bundle names "},
		{"bundle_without_id", func(t *testing.T) *dirEnv {
			e := newDirEnv(t, 1, 1)
			bound(t, e, e.bundle.InstallationID)
			e.resignBundle(t, func(b *trust.Bundle) { b.InstallationID = "" })
			return e
		}, "but the root-verified trust bundle names none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.setup(t)
			for _, args := range append(slices.Clone(reads), proposalReads(t, e)...) {
				code, stdout, stderr := run(t, args...)
				if code == 0 || stdout != "" || !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "Refusing to use it") {
					t.Errorf("%s: exit %d, stdout %q, stderr %q; want a refusal naming the installations and nothing printed", strings.Join(args, " "), code, stdout, stderr)
				}
			}
			requireNotSigned(t, e, 0)
		})
	}
	t.Run("id_less_directory_read", func(t *testing.T) {
		e := roleEnv(t, nil) // no installation ID, under a bundle with one
		for _, args := range reads {
			if code, stdout, stderr := run(t, args...); code != 0 || stdout == "" {
				t.Fatalf("%s: exit %d, stdout %q, stderr %q; want the lenient D-04 answer (read)", strings.Join(args, " "), code, stdout, stderr)
			}
		}
		// The proposal commands get past the base check; whatever they
		// answer afterwards is not this test's concern.
		for _, args := range proposalReads(t, e) {
			if _, _, stderr := run(t, args...); strings.Contains(stderr, "Refusing to use it") {
				t.Fatalf("%s: stderr %q; want the lenient D-04 answer (the served base is read)", strings.Join(args, " "), stderr)
			}
		}
	})
}

// popHostsEnv is roleEnv on a genesis policy that sets pop.hosts.
func popHostsEnv(t *testing.T) *dirEnv {
	t.Helper()
	e := newDirEnvPolicy(t, 1, 1, func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: true} })
	e.installDirect(t, buildDir(t, nil, roleBase(t, nil)))
	return e
}

// recordCall marks path's override as called, under e.mu.
func (e *dirEnv) recordCall(method, path string, called *bool, answer string, code int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.override[method+" "+path] = func(w http.ResponseWriter) {
		*called = true
		w.WriteHeader(code)
		_, _ = io.WriteString(w, answer)
	}
}

func (e *dirEnv) wasCalled(called *bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return *called
}

// TestHostApprovePoPRequired (owner decision 2026-10-24, REVIEWS L1488):
// host approve and host join-token refuse host_pop_not_enabled on the
// policy the CLI verified itself, before any admin request; with
// pop.hosts, approve signs the enrolled keys and join-token writes the
// join string to a 0600 file only.
func TestHostApprovePoPRequired(t *testing.T) {
	t.Run("approve_refused_locally", func(t *testing.T) {
		e := roleEnv(t, nil)
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminPendingHostsPath, &called, `{"hosts":[]}`, http.StatusOK)
		code, _, stderr := run(t, "host", "approve", "web1", "--group", "web", "--principal", "web1", "--host-key", "SHA256:"+strings.Repeat("A", 43), "--yes")
		if code == 0 || !strings.Contains(stderr, "host_pop_not_enabled") {
			t.Fatalf("host approve without pop.hosts: exit %d: %s", code, stderr)
		}
		if e.wasCalled(&called) || len(e.calls) != 0 || e.agent.dirSigns() != 0 {
			t.Fatalf("host approve made a call (pending %t, posts %q, directory signatures %d)", e.wasCalled(&called), e.calls, e.agent.dirSigns())
		}
	})
	t.Run("join_token_refused_locally", func(t *testing.T) {
		e := roleEnv(t, nil)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminJoinTokensPath, &called, `{}`, http.StatusCreated)
		out := filepath.Join(t.TempDir(), "join.txt")
		code, _, stderr := run(t, "host", "join-token", "web1", "--out", out)
		if code == 0 || !strings.Contains(stderr, "host_pop_not_enabled") {
			t.Fatalf("host join-token without pop.hosts: exit %d: %s", code, stderr)
		}
		if e.wasCalled(&called) || len(e.calls) != 0 {
			t.Fatalf("host join-token made a call (mint %t, posts %q)", e.wasCalled(&called), e.calls)
		}
		if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("host join-token wrote the file")
		}
	})
	t.Run("approve_signs_enrolled_keys", func(t *testing.T) {
		e := popHostsEnv(t)
		_, key := writeEntryKey(t, "web1")
		pub, err := trust.ParseKey(key)
		if err != nil {
			t.Fatal(err)
		}
		ans, err := json.Marshal(serverclient.PendingHostsAnswer{Hosts: []serverclient.PendingHost{{ExpectedName: "web1", IdentitySPKISHA256: strings.Repeat("00", 32),
			HostKeys: []string{key}, Facts: enroll.Facts{OSID: "debian", Hostname: "web1"}, EnrolledAt: "2026-10-28T12:00:00Z"}}})
		if err != nil {
			t.Fatal(err)
		}
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminPendingHostsPath, &called, string(ans), http.StatusOK)
		code, stdout, stderr := run(t, "host", "approve", "web1", "--group", "web", "--principal", "web1", "--host-key", ssh.FingerprintSHA256(pub), "--yes")
		if code != 0 {
			t.Fatalf("host approve: exit %d: %s", code, stderr)
		}
		if !strings.Contains(stdout, "agent identity: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n") || !strings.Contains(stdout, "host key: "+ssh.FingerprintSHA256(pub)+" ssh-ed25519\n") {
			t.Fatalf("host approve does not show the fingerprints:\n%s", stdout)
		}
		h, ok := installedDir(t, e).HostByName("web1")
		if !ok || !slices.Equal(h.Keys, []string{key}) || h.HostGroup != "web" || !slices.Equal(h.Principals, []string{"web1"}) {
			t.Fatalf("installed host %+v, %v", h, ok)
		}
	})
	t.Run("approve_refuses_bad_pending_answer", func(t *testing.T) {
		e := popHostsEnv(t)
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminPendingHostsPath, &called,
			`{"hosts":[{"expected_name":"web1","identity_spki_sha256":"00","host_keys":["ssh-rsa AAAA"],"facts":{"sshd_version":"","os_id":"","os_version_id":"","hostname":"\u001b[31m"},"enrolled_at":"x"}]}`, http.StatusOK)
		if code, _, stderr := run(t, "host", "approve", "web1", "--group", "web", "--principal", "web1", "--host-key", "SHA256:"+strings.Repeat("A", 43), "--yes"); code == 0 || !strings.Contains(stderr, "does not check out") {
			t.Fatalf("a pending answer that does not check out: exit %d: %s", code, stderr)
		}
		if e.agent.dirSigns() != 0 {
			t.Fatal("a directory version was signed")
		}
	})
	t.Run("join_token_writes_file", func(t *testing.T) {
		e := popHostsEnv(t)
		token := strings.Repeat("A", 43)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminJoinTokensPath, &called,
			`{"expected_name":"web1","token":"`+token+`","expires_at":"2026-10-28T12:30:00Z","agent_port":8443}`, http.StatusCreated)
		out := filepath.Join(t.TempDir(), "join.txt")
		code, stdout, stderr := run(t, "host", "join-token", "web1", "--out", out)
		if code != 0 {
			t.Fatalf("host join-token: exit %d: %s", code, stderr)
		}
		if strings.Contains(stdout+stderr, token) {
			t.Fatal("host join-token printed the token")
		}
		b, err := os.ReadFile(out) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		j, err := join.Parse(string(b))
		if err != nil {
			t.Fatal(err)
		}
		u, _ := serverclient.ParseServerURL(e.cfg.Server)
		if j.Token != token || j.ExpectedName != "web1" || j.Server != "https://"+u.Hostname()+":8443" || j.InstallationID != e.bundle.InstallationID ||
			!slices.Equal(j.TLSPins, e.cfg.TLSPins) || j.Threshold != 1 {
			t.Fatalf("join string %v", j)
		}
		if runtime.GOOS != "windows" {
			if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("join file mode %v (%v), want 0600", st.Mode(), err)
			}
		}
		if code, _, stderr := run(t, "host", "join-token", "web1", "--out", out); code == 0 || !strings.Contains(stderr, "exists") {
			t.Fatalf("an existing --out: exit %d: %s", code, stderr)
		}
		if code, _, _ := run(t, "host", "join-token", "web1", "--out", out+".2", "--ttl", "61m"); code == 0 {
			t.Fatal("--ttl 61m was accepted")
		}
	})
}

// TestHostForget (PR #71 review D-R1): host forget prints every agent the
// server forgot, with its re-derived fingerprints, and turns the server's
// host_in_directory refusal into the runbook order.
func TestHostForget(t *testing.T) {
	_, key := writeEntryKey(t, "web1")
	pub, err := trust.ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	forgotten, err := json.Marshal(serverclient.ForgetHostAnswer{Forgotten: []serverclient.PendingHost{{ExpectedName: "web1", IdentitySPKISHA256: strings.Repeat("00", 32),
		HostKeys: []string{key}, Facts: enroll.Facts{OSID: "debian", Hostname: "web1"}, EnrolledAt: "2026-10-28T12:00:00Z"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("prints_the_forgotten_agent", func(t *testing.T) {
		e := popHostsEnv(t)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, string(forgotten), http.StatusOK)
		code, stdout, stderr := run(t, "host", "forget", "web1")
		if code != 0 || !e.wasCalled(&called) {
			t.Fatalf("host forget: exit %d: %s", code, stderr)
		}
		if !strings.Contains(stdout, "agent identity: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n") || !strings.Contains(stdout, "host key: "+ssh.FingerprintSHA256(pub)+" ssh-ed25519\n") {
			t.Fatalf("host forget output:\n%s", stdout)
		}
	})
	t.Run("in_directory_refused_with_the_runbook_order", func(t *testing.T) {
		e := popHostsEnv(t)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, `{"error":"host_in_directory"}`, http.StatusConflict)
		if code, _, stderr := run(t, "host", "forget", "web1"); code == 0 || !strings.Contains(stderr, "keyroster host remove") {
			t.Fatalf("host forget of a host still in the directory: exit %d: %s", code, stderr)
		}
	})
	t.Run("answer_for_another_name_refused", func(t *testing.T) {
		e := popHostsEnv(t)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, strings.Replace(string(forgotten), `"web1"`, `"web2"`, 1), http.StatusOK)
		if code, _, stderr := run(t, "host", "forget", "web1"); code == 0 || !strings.Contains(stderr, "does not check out") {
			t.Fatalf("an answer for another name: exit %d: %s", code, stderr)
		}
	})
}

// TestHostApproveHostKeys is owner decision D-R4 (PR #71 review F13):
// host approve with --yes needs --host-key for every host key the admin
// compared on the host, and signs only when the pending host the CLI
// fetched again has exactly that set: a swapped key, a missing one or an
// extra one is refused and nothing is signed.
func TestHostApproveHostKeys(t *testing.T) {
	keyOf := func(t *testing.T, name string) (string, string) {
		t.Helper()
		_, key := writeEntryKey(t, name)
		pub, err := trust.ParseKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return key, ssh.FingerprintSHA256(pub)
	}
	k1, fp1 := keyOf(t, "a")
	k2, fp2 := keyOf(t, "b")
	_, fpOther := keyOf(t, "c")
	pendingWith := func(t *testing.T, keys ...string) *dirEnv {
		t.Helper()
		e := popHostsEnv(t)
		slices.Sort(keys)
		ans, err := json.Marshal(serverclient.PendingHostsAnswer{Hosts: []serverclient.PendingHost{{ExpectedName: "web1", IdentitySPKISHA256: strings.Repeat("00", 32),
			HostKeys: keys, Facts: enroll.Facts{OSID: "debian", Hostname: "web1"}, EnrolledAt: "2026-10-28T12:00:00Z"}}})
		if err != nil {
			t.Fatal(err)
		}
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminPendingHostsPath, &called, string(ans), http.StatusOK)
		return e
	}
	approve := func(fps ...string) []string {
		args := []string{"host", "approve", "web1", "--group", "web", "--principal", "web1", "--yes"}
		for _, fp := range fps {
			args = append(args, "--host-key", fp)
		}
		return args
	}
	for _, tc := range []struct {
		name    string
		pending []string
		given   []string
	}{
		{"yes_without_host_key_refused", []string{k1}, nil},
		{"swapped_key_refused", []string{k1, k2}, []string{fp1, fpOther}},
		{"missing_key_refused", []string{k1, k2}, []string{fp1}},
		{"extra_key_refused", []string{k1}, []string{fp1, fp2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := pendingWith(t, tc.pending...)
			if code, _, stderr := run(t, approve(tc.given...)...); code == 0 || !strings.Contains(stderr, "host-key") {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			if e.agent.dirSigns() != 0 {
				t.Fatal("a directory version was signed")
			}
		})
	}
	t.Run("exact_set_in_any_order_signs", func(t *testing.T) {
		e := pendingWith(t, k1, k2)
		if code, _, stderr := run(t, approve(fp2, fp1)...); code != 0 || e.agent.dirSigns() != 1 {
			t.Fatalf("exit %d, %d signatures: %s", code, e.agent.dirSigns(), stderr)
		}
	})
}
