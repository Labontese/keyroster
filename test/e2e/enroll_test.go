//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/signerclient"
)

// runCLIIn runs the keyroster binary bin with c's config directories,
// SSH_AUTH_SOCK set to agentSock ("" for none) and working directory dir
// ("" for the test's), and returns its exit code, stdout and stderr.
func runCLIIn(t *testing.T, c *cliEnv, agentSock, dir, bin string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: the binary under test
	cmd.Env = append(envWithout("SSH_AUTH_SOCK", "XDG_CONFIG_HOME", "HOME"), "XDG_CONFIG_HOME="+c.configHome, "HOME="+c.home)
	if agentSock != "" {
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+agentSock)
	}
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("%s %v: %v", filepath.Base(bin), args, err)
		}
		return ee.ExitCode(), stdout.String(), stderr.String()
	}
	return 0, stdout.String(), stderr.String()
}

// clientConfig is the part of a saved CLI config the test compares.
type clientConfig struct {
	Server   string   `json:"server"`
	TLSPins  []string `json:"tls_pins"`
	User     string   `json:"user"`
	AdminKey string   `json:"admin_key"`
}

func readClientConfig(t *testing.T, c *cliEnv) clientConfig {
	t.Helper()
	var cfg clientConfig
	if err := json.Unmarshal(mustRead(t, c.configFile()), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestUserAddInvite: an admin runs keyroster user add through the
// SSHSIG-authenticated admin API. The server keeps a pending account and
// an invite, the invite page greets the user, and the signer's directory
// stays at version 0: the pending account grants nothing (D-03, AUTH-01).
// The printed keyroster init line, with the printed TLS root saved under
// the name it reads, runs unchanged for the user (02-07-F9). A second add
// is refused, and so is an add signed by a key that is not a policy admin
// (control: the admin's add of the same name succeeds).
func TestUserAddInvite(t *testing.T) {
	env := startServerEnv(t, serverOpts{})
	admin := newCLIEnv(t)
	initArgs := []string{"init", "--server", env.URL, "--tls-root-file", env.CA.RootPEM, "--tls-pin", env.CA.RootPin,
		"--root-pin", env.Signer.RootFingerprints[0], "--threshold", "1", "--user", "admin", "--admin-key", env.Signer.AdminFingerprint}
	if code, stdout, stderr := runCLIIn(t, admin, env.Signer.AdminAgent, "", keyrosterBin, initArgs...); code != 0 {
		t.Fatalf("admin keyroster init exited %d:\n%s\n%s", code, stdout, stderr)
	}

	code, stdout, stderr := runCLIIn(t, admin, env.Signer.AdminAgent, "", keyrosterBin, "user", "add", "alice")
	if code != 0 {
		t.Fatalf("keyroster user add alice exited %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, stdout, stderr, env.Stderr.String())
	}
	t.Logf("keyroster user add alice:\n%s", stdout)
	for _, want := range []string{"/enroll/", "--user alice", "--tls-root-file keyroster-tls-root.pem"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("user add output lacks %q:\n%s", want, stdout)
		}
	}
	var inviteURL, initLine string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(l, "Invite for alice: ") {
			inviteURL = strings.TrimPrefix(l, "Invite for alice: ")
		}
		if strings.HasPrefix(l, "keyroster init ") {
			if initLine != "" {
				t.Fatalf("more than one keyroster init line:\n%s", stdout)
			}
			initLine = l
		}
	}
	if !strings.HasPrefix(inviteURL, env.URL+"/enroll/") || initLine == "" {
		t.Fatalf("no invite URL under %s or no init line:\n%s", env.URL, stdout)
	}
	token := strings.TrimPrefix(inviteURL, env.URL+"/enroll/")

	t.Run("init_line_round_trip", func(t *testing.T) {
		work := t.TempDir()
		var roots bytes.Buffer
		for rest := []byte(stdout); ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if err := pem.Encode(&roots, block); err != nil {
				t.Fatal(err)
			}
		}
		if roots.Len() == 0 {
			t.Fatalf("no PEM block in the user add output:\n%s", stdout)
		}
		if err := os.WriteFile(filepath.Join(work, "keyroster-tls-root.pem"), roots.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(initLine)
		user := newCLIEnv(t)
		code, out, errOut := runCLIIn(t, user, "", work, keyrosterBin, fields[1:]...)
		if code != 0 {
			t.Fatalf("the printed line %q exited %d:\nstdout:\n%s\nstderr:\n%s", initLine, code, out, errOut)
		}
		got, want := readClientConfig(t, user), readClientConfig(t, admin)
		if got.User != "alice" || got.AdminKey != "" || got.Server != want.Server || !slices.Equal(got.TLSPins, want.TLSPins) {
			t.Fatalf("user config %+v, want user alice with the admin's server and TLS pins %+v", got, want)
		}
	})

	t.Run("invite_page", func(t *testing.T) {
		r := env.mustGet(t, "/enroll/"+token)
		if r.code != http.StatusOK || !strings.Contains(r.body, "alice") || !strings.Contains(r.body, serverRPID) {
			t.Fatalf("GET invite = %d:\n%s", r.code, r.body)
		}
		requireSecurityHeaders(t, "invite page", r)
		bad := env.mustGet(t, "/enroll/"+strings.Repeat("A", 43))
		if bad.code != http.StatusNotFound || !strings.Contains(bad.body, "Invite not valid") || strings.Contains(bad.body, "alice") {
			t.Fatalf("GET unknown invite = %d:\n%s", bad.code, bad.body)
		}
	})

	t.Run("signer_directory_unchanged", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d, err := signerclient.GetDirectory(ctx, env.Signer.Socket)
		if err != nil {
			t.Fatal(err)
		}
		if d.Version != 0 || d.Authorized {
			t.Fatalf("signer directory version %d (authorized %v) after user add, want 0", d.Version, d.Authorized)
		}
	})

	t.Run("second_add_refused", func(t *testing.T) {
		code, out, errOut := runCLIIn(t, admin, env.Signer.AdminAgent, "", keyrosterBin, "user", "add", "alice")
		if code == 0 || !strings.Contains(errOut, "already pending") {
			t.Fatalf("second user add alice: exit %d, want non-zero with \"already pending\":\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
	})

	t.Run("non_admin_refused_admin_accepted", func(t *testing.T) {
		agentSock := startAgent(t)
		key := filepath.Join(t.TempDir(), "notadmin")
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "not-an-admin", "-f", key)
		sshAdd(t, agentSock, key)
		code, out, errOut := runCLIIn(t, admin, agentSock, "", keyrosterBin, "user", "add", "bob", "--admin-key", fingerprint(t, key+".pub"))
		if code == 0 || !strings.Contains(errOut, "admin authentication failed") {
			t.Fatalf("user add bob with a non-admin key: exit %d, want non-zero with \"admin authentication failed\":\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		if !strings.Contains(env.Stderr.String(), "signer is not a policy admin") {
			t.Fatalf("the server log does not name the refusal:\n%s", env.Stderr.String())
		}
		code, out, errOut = runCLIIn(t, admin, env.Signer.AdminAgent, "", keyrosterBin, "user", "add", "bob")
		if code != 0 || !strings.Contains(out, "--user bob") {
			t.Fatalf("control: the admin's user add bob exited %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
	})

	t.Run("token_never_logged", func(t *testing.T) {
		if strings.Contains(env.Stderr.String(), token) {
			t.Fatalf("the server log carries the invite token:\n%s", env.Stderr.String())
		}
	})
}
