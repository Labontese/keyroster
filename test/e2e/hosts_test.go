//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestDirectoryHostsEndToEnd (D-04, D-11, D-15, D-16, AUTHZ-02): on a
// signer whose genesis bundle carries an installation ID, admin-signed
// directory versions made with the CLI carry that ID without the admin
// typing it, and add host group lab, host web1 in it (a generated host
// key, two typed principals) and machine ci with role ops, which no user
// or group grants, at 24 h: above the 12 h user CA cap, within the 24 h
// machine CA cap. keyroster host principals --host web1 renders exactly
// the file RenderPrincipalsFile gives for lab. A directory signed by the
// same admin key for another installation is refused
// (directory_installation_mismatch), one that names none is refused
// (directory_installation_missing), and keyroster audit verify passes the
// exported log.
func TestDirectoryHostsEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{})
	if env.Signer.InstallationID == "" {
		t.Fatal("the bootstrap bundle carries no installation ID")
	}
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	// kr runs one CLI command and requires exit 0, running it again when
	// the server rate-limited it (nothing was installed then).
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			time.Sleep(2 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}

	// 1. The first version binds the installation; the diff shows it.
	if out := kr("role", "add", "ops", "--max-ttl", "1h", "--yes"); !strings.Contains(out, "+ installation_id "+env.Signer.InstallationID) {
		t.Fatalf("role add ops: the diff does not show the installation ID %s:\n%s", env.Signer.InstallationID, out)
	}
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", "deploy", "ops", "--yes")

	// 2. Host web1 in lab, with a generated host key and typed names.
	hostKey := newUserKey(t, "ssh_host_ed25519_key")
	if out := kr("host", "add", "web1", "--group", "lab", "--key", hostKey+".pub", "--principal", "web1", "--principal", "web1.lab.example", "--yes"); !strings.Contains(out, "+ host web1 host_group=lab status=active principals=[web1 web1.lab.example]") {
		t.Fatalf("host add web1: the diff does not add the host:\n%s", out)
	}

	// 3. Machine ci with role ops at 24 h.
	machineKey := newUserKey(t, "id_ci")
	if out := kr("machine", "add", "ci", "--key", machineKey+".pub", "--role", "ops", "--max-ttl", "24h", "--yes"); !strings.Contains(out, "roles=[ops] max_ttl_seconds=86400") {
		t.Fatalf("machine add ci: the diff does not add the machine:\n%s", out)
	}

	// 4. The signer holds version 5, bound to the installation, with the
	// host and the machine.
	resp, d := signerDirectory(t, env)
	if resp.Version != 5 || !resp.Authorized || d.InstallationID != env.Signer.InstallationID {
		t.Fatalf("signer directory = version %d, authorized %v, installation %q; want 5, true, %s", resp.Version, resp.Authorized, d.InstallationID, env.Signer.InstallationID)
	}
	h, ok := d.HostByName("web1")
	if !ok || h.HostGroup != "lab" || len(h.Keys) != 1 || h.Keys[0] != strings.Join(strings.Fields(readPub(t, hostKey+".pub"))[:2], " ") {
		t.Fatalf("host web1 = %+v, %v; want host group lab with the generated host key", h, ok)
	}
	if m, ok := d.MachineByName("ci"); !ok || m.MaxTTLSeconds != 86400 || len(m.Roles) != 1 || m.Roles[0] != "ops" {
		t.Fatalf("machine ci = %+v, %v; want role ops at 86400 s", m, ok)
	}

	// 5. host principals --host renders through the one renderer.
	want, err := directory.RenderPrincipalsFile(d, "lab", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if got := kr("host", "principals", "--host", "web1", "deploy"); got != string(want) || !strings.HasSuffix(got, "\nrole:ops\n") {
		t.Fatalf("host principals --host web1 deploy = %q, want %q", got, want)
	}
	if code, _, errOut := env.keyroster(t, admin, "", "host", "principals", "--host", "web2", "deploy"); code == 0 || !strings.Contains(errOut, "no active host web2") {
		t.Fatalf("host principals --host web2: exit %d, stderr %q; want the unknown-host refusal", code, errOut)
	}

	// 6. Signed by the same admin key, but for another installation or for
	// none: the signer refuses both, and the directory stays at version 5.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, c := range []struct{ id, detail string }{
		{strings.Repeat("ab", 16), "directory_installation_mismatch"},
		{"", "directory_installation_missing"},
	} {
		next := &directory.Directory{}
		if err := json.Unmarshal(resp.Directory, next); err != nil {
			t.Fatal(err)
		}
		next.Version, next.Prev, next.InstallationID = resp.Version+1, trust.SHA256Hex(resp.Directory), c.id
		next.Sort()
		doc, err := next.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		_, err = signerclient.InstallDirectory(ctx, env.Signer.Socket, &wire.InstallDirectoryRequest{Directory: doc, Sigs: adminSign(t, env.Signer, directory.Namespace, doc)})
		if !isRefusal(err, c.detail) {
			t.Fatalf("install of a version for installation %q: %v, want %s", c.id, err, c.detail)
		}
	}
	if after, _ := signerDirectory(t, env); after.Version != 5 || !bytes.Equal(after.Directory, resp.Directory) {
		t.Fatalf("after the refused installs the signer holds version %d, want version 5 unchanged", after.Version)
	}

	// 7. The exported log verifies, with every directory install.
	export := env.Signer.exportLog(t)
	if code, out := auditVerify(t, env.Signer, export); code != 0 || !strings.Contains(out, "directory installs 5") {
		t.Fatalf("audit verify exited %d (want 0 and 5 directory installs):\n%s", code, out)
	}
}
