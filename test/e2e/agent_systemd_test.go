//go:build e2e && systemdsmoke

package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// The paths test/systemd/agent-smoke.sh sets up before it runs this test
// as root on a throwaway systemd host (03-08).
const (
	smokeAgent = "/usr/local/bin/keyroster-agent"
	smokeState = "/var/lib/keyroster-agent"
)

// systemctl runs systemctl with args and fails the test on an error.
func systemctl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("systemctl", args...).CombinedOutput() //nolint:gosec // test-only, fixed binary
	if err != nil {
		t.Fatalf("systemctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// journal is the units' journal since the test began.
func journal(t *testing.T, since time.Time) string {
	t.Helper()
	out, _ := exec.Command("journalctl", "--no-pager", "-o", "cat", "--since", since.Format("2006-01-02 15:04:05"), //nolint:gosec // test-only, fixed binary
		"-u", "keyroster-agent", "-u", "keyroster-agent-fetch").CombinedOutput()
	return string(out)
}

// TestAgentSystemdSmoke runs both agent units under real systemd against
// the runner's own ssh.service (03-08, PLAT-01): keyroster-agent install
// writes the units, systemd starts them, the host enrolls and is
// approved, the first apply reloads sshd through systemd, a certificate
// logs in to 127.0.0.1 as the probe-free account, and the heartbeat
// shows the host on the current KRL. agent-smoke.sh then checks the
// cross-user writes and systemd-analyze security. Run only by that
// script (build tag systemdsmoke), as root, with KEYROSTER_OPENSSH_PREFIX
// set to the system's (/usr) and KEYROSTER_SMOKE_ACCOUNT naming the
// account to log in as.
func TestAgentSystemdSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("run by test/systemd/agent-smoke.sh as root")
	}
	account := os.Getenv("KEYROSTER_SMOKE_ACCOUNT")
	if account == "" {
		t.Fatal("KEYROSTER_SMOKE_ACCOUNT is not set")
	}
	since := time.Now()
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\n%s\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", account, "ops", "--yes")
	joinFile := filepath.Join(t.TempDir(), "join.txt")
	kr("host", "join-token", "runner", "--out", joinFile)

	code, out := runBin(t, smokeAgent, "", "install", "--join-file", joinFile)
	if code != 0 {
		t.Fatalf("keyroster-agent install exited %d:\n%s", code, out)
	}
	t.Logf("keyroster-agent install:\n%s", out)
	systemctl(t, "daemon-reload")
	systemctl(t, "start", "keyroster-agent.service", "keyroster-agent-fetch.service")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("unit journals:\n%s", journal(t, since))
		}
	})

	var pending string
	for deadline := time.Now().Add(180 * time.Second); !strings.Contains(pending, "Pending host runner"); time.Sleep(5 * time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("host pending never listed the runner:\n%s\njournal:\n%s", pending, journal(t, since))
		}
		pending = kr("host", "pending")
	}
	code, ident := runBin(t, smokeAgent, "", "identity")
	if code != 0 {
		t.Fatalf("keyroster-agent identity exited %d:\n%s", code, ident)
	}
	args := []string{"host", "approve", "runner", "--group", "lab", "--principal", "runner", "--yes"}
	for _, l := range strings.Split(strings.TrimSpace(ident), "\n") {
		if fp, ok := strings.CutPrefix(l, "host key: "); ok {
			args = append(args, "--host-key", strings.Fields(fp)[0])
		}
	}
	kr(args...)

	// The first apply, under the unit: through systemctl (reload, or
	// try-reload-or-restart for a socket-activated sshd).
	var last struct {
		LastApply struct {
			Generation    uint64   `json:"generation"`
			SelfTest      string   `json:"self_test"`
			ReloadActions []string `json:"reload_actions"`
			Errors        []string `json:"errors"`
		} `json:"last_apply"`
	}
	for deadline := time.Now().Add(150 * time.Second); ; time.Sleep(time.Second) {
		b, err := os.ReadFile(filepath.Join(smokeState, "status.json"))
		if err == nil && json.Unmarshal(b, &last) == nil && last.LastApply.Generation > 0 && last.LastApply.SelfTest == "pass" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no first apply under the unit within 150 s (last %+v)\njournal:\n%s", last.LastApply, journal(t, since))
		}
	}
	if len(last.LastApply.Errors) != 0 {
		t.Fatalf("the first apply: errors %q", last.LastApply.Errors)
	}
	reload := strings.Join(last.LastApply.ReloadActions, "; ")
	switch {
	case strings.Contains(reload, "systemctl reload "):
		t.Logf("the first apply reloaded sshd with %q (no socket activation)", reload)
	case strings.Contains(reload, "systemctl try-reload-or-restart "):
		t.Logf("the first apply reloaded sshd with %q (socket activation)", reload)
	default:
		t.Fatalf("the first apply's reload actions %q: neither systemctl reload nor try-reload-or-restart", reload)
	}

	c := issueAgentCert(t, env.Signer, "smoke", "role:ops")
	code, lout := sshLogin(t, loginOptions{Port: 22, Key: c.key, Cert: c.cert, User: account, Command: "true"})
	if code != 0 {
		t.Fatalf("certificate login as %s to 127.0.0.1:22 exited %d:\n%s\njournal:\n%s", account, code, lout, journal(t, since))
	}
	t.Logf("certificate %s (serial %s, role:ops) logs in as %s to the runner's ssh.service on 127.0.0.1:22", c.cert, c.serial, account)

	var a serverclient.HostsStatusAnswer
	for deadline := time.Now().Add(150 * time.Second); ; time.Sleep(5 * time.Second) {
		if err := json.Unmarshal([]byte(kr("host", "status", "--json")), &a); err != nil {
			t.Fatal(err)
		}
		if len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.Committed(a.Current.Bundle, a.Current.Directory, a.Current.KRL) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no heartbeat on the current versions within 150 s: %+v\njournal:\n%s", a, journal(t, since))
		}
	}
	text := kr("host", "status")
	if !strings.Contains(text, "KRL v"+strconv.FormatUint(a.Current.KRL, 10)+" on 1/1 hosts\n") {
		t.Fatalf("host status:\n%s", text)
	}
	t.Logf("keyroster host status under systemd:\n%s", text)
	// Identity rotation with the real users, while the unit polls: root
	// is refused (it would leave keys the service cannot read), the
	// keyroster-agent user rotates, and the running fetcher's next poll
	// uses the new identity (it reloads it under the shared flock).
	if out, err := exec.Command("/usr/local/bin/keyroster-agent-fetch", "--rotate-identity").CombinedOutput(); err == nil || !strings.Contains(string(out), "fetch_dir_not_owned") {
		t.Fatalf("--rotate-identity as root: %v\n%s", err, out)
	} else {
		t.Logf("--rotate-identity as root refused: %s", strings.TrimSpace(string(out)))
	}
	oldID := a.Hosts[0].IdentitySPKISHA256
	rot, err := exec.Command("runuser", "-u", "keyroster-agent", "--", "/usr/local/bin/keyroster-agent-fetch", "--rotate-identity").CombinedOutput()
	if err != nil {
		t.Fatalf("--rotate-identity as keyroster-agent: %v\n%s", err, rot)
	}
	t.Logf("--rotate-identity as keyroster-agent: %s", strings.TrimSpace(string(rot)))
	rotatedAt := time.Now()
	for deadline := time.Now().Add(150 * time.Second); ; time.Sleep(5 * time.Second) {
		if err := json.Unmarshal([]byte(kr("host", "status", "--json")), &a); err != nil {
			t.Fatal(err)
		}
		if seen, err := time.Parse(time.RFC3339, a.Hosts[0].LastSeen); err == nil && a.Hosts[0].IdentitySPKISHA256 != oldID && seen.After(rotatedAt) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the service never polled with the rotated identity: %+v\njournal:\n%s", a.Hosts[0], journal(t, since))
		}
	}
	t.Logf("the running fetcher polled with the rotated identity %s (was %s)", a.Hosts[0].IdentitySPKISHA256, oldID)

	if j := journal(t, since); strings.Contains(j, "phase2_adoption_pending") {
		t.Logf("the applier reported phase2_adoption_pending (a Phase 2 layout on the runner)")
	}
}
