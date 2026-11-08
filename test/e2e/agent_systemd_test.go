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

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
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

	// 03-10b: a probe negative's first publish can move the KRL between
	// the JSON read and the text read, so each iteration reads both again
	// and accepts only a text that names the fresh JSON's KRL version; a
	// disagreement that lasts past the deadline still fails.
	var a serverclient.HostsStatusAnswer
	var text string
	// 270 s: the probe negative's first KRL commits about one fetch poll
	// after the first install, and that poll's heartbeat precedes the apply.
	for deadline := time.Now().Add(270 * time.Second); ; time.Sleep(5 * time.Second) {
		if err := json.Unmarshal([]byte(kr("host", "status", "--json")), &a); err != nil {
			t.Fatal(err)
		}
		if len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.Committed(a.Current.Docs()) {
			text = kr("host", "status")
			if strings.Contains(text, "KRL v"+strconv.FormatUint(a.Current.KRL, 10)+" on 1/1 hosts\n") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no heartbeat on the current versions, with the text status naming them, within 270 s: %+v\nhost status:\n%s\njournal:\n%s", a, text, journal(t, since))
		}
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

	// 03-10c: with the probe account that agent-smoke.sh created through
	// the runbook's script, a revocation lands at once, and a role addition
	// waits for a probe pair and passes both probes under the real units
	// (the applier's IPAddressAllow=localhost must admit the probe source
	// 127.0.0.2, T-03-381).
	if !t.Run("revocation_lands", func(t *testing.T) {
		// A fresh certificate that logs in first, so that the refused login
		// after the revocation cannot be an expired certificate.
		rc := issueAgentCert(t, env.Signer, "smoke-revoked", "role:ops")
		if code, out := sshLogin(t, loginOptions{Port: 22, Key: rc.key, Cert: rc.cert, User: account, Command: "true"}); code != 0 {
			t.Fatalf("the certificate to revoke does not log in: exit %d:\n%s", code, out)
		}
		serial, err := strconv.ParseUint(rc.serial, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(rc.cert)
		if err != nil {
			t.Fatal(err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			t.Fatal("not a certificate")
		}
		ca := cert.SignatureKey.Marshal()
		start := time.Now()
		revokeSerial(t, env.Signer, rc.serial)
		for deadline := time.Now().Add(240 * time.Second); ; time.Sleep(5 * time.Second) {
			if b, err := os.ReadFile("/etc/ssh/keyroster/current/revoked.krl"); err == nil {
				if k, err := krl.Parse(b); err == nil && k.RevokesSerial(ca, serial) {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("current/revoked.krl does not list serial %d of the user CA within 240 s\njournal:\n%s", serial, journal(t, since))
			}
		}
		t.Logf("the revocation of serial %d landed in %s", serial, time.Since(start).Round(time.Second))
		if code, out := sshLogin(t, loginOptions{Port: 22, Key: rc.key, Cert: rc.cert, User: account, Command: "true"}); code == 0 {
			t.Fatalf("the revoked certificate still logs in:\n%s", out)
		}
	}) {
		t.FailNow()
	}
	if !t.Run("probe_pair_ready", func(t *testing.T) {
		var rec struct {
			Committed struct {
				Positive, Negative *json.RawMessage
			} `json:"committed"`
		}
		for deadline := time.Now().Add(300 * time.Second); ; time.Sleep(5 * time.Second) {
			if b, err := os.ReadFile(filepath.Join(smokeState, "probe.json")); err == nil && json.Unmarshal(b, &rec) == nil &&
				rec.Committed.Positive != nil && rec.Committed.Negative != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("probe.json holds no committed probe pair within 300 s\njournal:\n%s", journal(t, since))
			}
		}
	}) {
		t.FailNow()
	}
	t.Run("role_addition_passes_probes", func(t *testing.T) {
		var st struct {
			LastApply struct {
				SelfTest      string   `json:"self_test"`
				Rollback      bool     `json:"rollback"`
				Detail        string   `json:"detail"`
				ProbePositive string   `json:"probe_positive"`
				ProbeNegative string   `json:"probe_negative"`
				Errors        []string `json:"errors"`
			} `json:"last_apply"`
		}
		start := time.Now()
		kr("role", "update", "ops", "--principal", "role:ops", "--principal", "role:smoke2", "--yes")
		for deadline := time.Now().Add(420 * time.Second); ; time.Sleep(5 * time.Second) {
			b, err := os.ReadFile(filepath.Join(smokeState, "status.json"))
			p, perr := os.ReadFile("/etc/ssh/keyroster/current/principals/" + account) //nolint:gosec // G304: the generation under test
			la := &st.LastApply
			if err == nil && perr == nil && json.Unmarshal(b, &st) == nil && la.ProbePositive == "pass" && la.ProbeNegative == "pass" &&
				la.Detail == "" && len(la.Errors) == 0 && !la.Rollback && strings.Contains(string(p), "\nrole:smoke2\n") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the role addition did not land with both probes passing within 420 s (last %+v)\njournal:\n%s", st.LastApply, journal(t, since))
			}
		}
		t.Logf("the role addition landed with both probes passing in %s", time.Since(start).Round(time.Second))
		if text := kr("host", "status"); strings.Contains(text, "probe: ") {
			t.Fatalf("keyroster host status shows a probe alert:\n%s", text)
		}
	})
}
