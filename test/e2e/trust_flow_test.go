//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/trust"
)

// TestTrustFlowEndToEnd is the trust tracer: ca-init selects five distinct
// keys, the offline root signs the genesis bundle and policy, install-bundle
// verifies them against the pinned root, serve takes every key from the
// bundle, an admin-signed keyroster ca issue yields a certificate that real
// sshd accepts, and the exported log verifies against the pinned root alone
// (audit verify --pin takes the log key from the root-signed bundle_install
// entry) and starts with the ca_init and bundle_install entries.
func TestTrustFlowEndToEnd(t *testing.T) {
	login := currentUser(t)
	env := bootstrapSigner(t, bootstrapOpts{})

	// ca-pubkeys.json lists the five roles in the fixed order with five
	// distinct keys.
	data, err := os.ReadFile(env.CAPubkeys)
	if err != nil {
		t.Fatal(err)
	}
	cas, err := trust.ParseCAPubKeys(data)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, k := range cas.Keys {
		if k.Role != roleNames[i] || seen[k.Key] {
			t.Fatalf("ca-pubkeys.json entry %d: role %s (want %s), key repeated: %v", i, k.Role, roleNames[i], seen[k.Key])
		}
		seen[k.Key] = true
	}

	key := newUserKey(t, "id_trust")
	out := env.issue(t, "--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	if want := "log leaf: " + strconv.Itoa(bootstrapLeaves); !strings.Contains(out, want) {
		t.Fatalf("ca issue output lacks %q:\n%s", want, out)
	}
	info := parseCertInfo(t, sshKeygen(t, "-L", "-f", key+"-cert.pub"))
	if info.signingCAFP != fingerprint(t, env.UserCAPub) {
		t.Fatalf("certificate signed by %s, want the bundle's user CA %s", info.signingCAFP, fingerprint(t, env.UserCAPub))
	}
	if !strings.Contains(info.keyID, "/pol=1/") {
		t.Fatalf("key ID %q, want the installed policy version pol=1", info.keyID)
	}

	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {login}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: key, Cert: key + "-cert.pub", User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the admin-authorized certificate exited %d:\n%s", code, out)
	}

	export := env.exportLog(t)
	code, out := auditVerify(t, env, export)
	if code != 0 || !strings.HasPrefix(out, "OK: 3 entries,") || !strings.Contains(out, "issued 1") {
		t.Fatalf("audit verify exited %d, want OK with 3 entries and 1 issued:\n%s", code, out)
	}
	raw, err := os.ReadFile(export) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	for i, want := range []string{"ca_init", "bundle_install", "issue"} {
		var line struct {
			Decoded struct {
				Kind          string           `json:"kind"`
				Keys          []map[string]any `json:"keys"`
				BundleVersion uint64           `json:"bundle_version"`
			} `json:"decoded"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &line); err != nil {
			t.Fatal(err)
		}
		if line.Decoded.Kind != want {
			t.Fatalf("export entry %d is %q, want %q", i, line.Decoded.Kind, want)
		}
		if want == "ca_init" && len(line.Decoded.Keys) != len(roleNames) {
			t.Fatalf("ca_init entry records %d keys, want %d", len(line.Decoded.Keys), len(roleNames))
		}
		if want == "bundle_install" && line.Decoded.BundleVersion != 1 {
			t.Fatalf("bundle_install entry records version %d, want 1", line.Decoded.BundleVersion)
		}
	}
}

// TestServeRefusesWithoutBundle (KEY-01, KEY-07): after ca-init but before
// install-bundle, serve exits non-zero with "no trust bundle installed" and
// creates no socket.
func TestServeRefusesWithoutBundle(t *testing.T) {
	env := initSigner(t, bootstrapOpts{})
	code, out := env.signerCmd(t, "serve", "--state-dir", env.StateDir, "--socket", env.Socket, "--allow-uid", strconv.Itoa(os.Getuid()))
	if code == 0 || !strings.Contains(out, "no trust bundle installed") {
		t.Fatalf("serve without a bundle exited %d, want the \"no trust bundle installed\" refusal:\n%s", code, out)
	}
	if isSocket(env.Socket) {
		t.Errorf("serve created %s although it refused to start", env.Socket)
	}
	if _, err := os.Stat(filepath.Join(env.StateDir, "signer.db")); err != nil {
		t.Fatalf("ca-init left no state database: %v", err)
	}
}
