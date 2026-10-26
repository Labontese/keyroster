package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

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
