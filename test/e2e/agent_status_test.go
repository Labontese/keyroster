//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// enrollApproved enrolls and approves host name as TestAgentEnrollEndToEnd
// steps 1 to 6 do, and waits for its first apply.
func enrollApproved(t *testing.T, env *serverEnv, kr func(args ...string) string, name string) *enrolledHost {
	t.Helper()
	login := currentUser(t)
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", login, "ops", "--yes")
	joinFile := filepath.Join(t.TempDir(), "join.txt")
	kr("host", "join-token", name, "--out", joinFile)
	h := newEnrolledHostLayout(t, env.Signer)
	if code, out := runBin(t, agentBin(t), "", "install", "--root", h.root, "--state-dir", h.state, "--join-file", joinFile, "--fetch-user", login); code != 0 {
		t.Fatalf("keyroster-agent install exited %d:\n%s", code, out)
	}
	eh := startEnrolled(t, h)
	for deadline := time.Now().Add(30 * time.Second); !strings.Contains(kr("host", "pending"), "Pending host "+name); time.Sleep(500 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("host pending never listed %s\nfetch log:\n%s", name, eh.fetch.String())
		}
	}
	prefix := opensshPrefix(t)
	code, ident := runBin(t, agentBin(t), "", "identity", "--state-dir", h.state, "--root", h.root,
		"--sshd", filepath.Join(prefix, "sbin", "sshd"), "--sshd-config", h.sshd.cfg)
	if code != 0 {
		t.Fatalf("keyroster-agent identity exited %d:\n%s", code, ident)
	}
	args := []string{"host", "approve", name, "--group", "lab", "--principal", name, "--yes"}
	for _, l := range strings.Split(strings.TrimSpace(ident), "\n") {
		if fp, ok := strings.CutPrefix(l, "host key: "); ok {
			args = append(args, "--host-key", strings.Fields(fp)[0])
		}
	}
	kr(args...)
	waitFor(t, "the first apply", eh.runDone, eh.run, func() bool {
		r := h.lastApply(t)
		return r != nil && r.Generation > 0 && r.SelfTest == "pass" && len(r.Errors) == 0
	})
	return eh
}

// hostsStatusJSON is keyroster host status --json.
func hostsStatusJSON(t *testing.T, kr func(args ...string) string) serverclient.HostsStatusAnswer {
	t.Helper()
	var a serverclient.HostsStatusAnswer
	if err := json.Unmarshal([]byte(kr("host", "status", "--json")), &a); err != nil {
		t.Fatalf("host status --json: %v", err)
	}
	return a
}

// waitStatus polls host status --json until cond holds (30 s).
func waitStatus(t *testing.T, what string, eh *enrolledHost, kr func(args ...string) string, cond func(a serverclient.HostsStatusAnswer) bool) serverclient.HostsStatusAnswer {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		a := hostsStatusJSON(t, kr)
		if cond(a) {
			return a
		}
		if time.Now().After(deadline) {
			b, _ := json.MarshalIndent(a, "", "  ")
			t.Fatalf("%s: not within 30 s; host status:\n%s\nfetch log:\n%s\nrun log:\n%s", what, b, eh.fetch.String(), eh.run.String())
		}
	}
}

// staleKRL spools a KRL version v that revokes serials of the user CA,
// with a manifest copied from the KRL the host holds now (its
// installation, bundle version and log index) whose issued_at is
// issuedAt, signed by the bundle's ops key: a KRL the server never
// published, as a frozen or late server's would look.
func staleKRL(t *testing.T, env *signerEnv, h *agentHost, cur, v uint64, issuedAt time.Time, serials []uint64) {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(h.state, "spool", fmt.Sprintf("krl-%d.manifest.json", cur))) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("the current KRL's manifest in the spool: %v", err)
	}
	m, err := krl.ParseManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := os.ReadFile(env.UserCAPub)
	if err != nil {
		t.Fatal(err)
	}
	userCA, _, _, _, err := ssh.ParseAuthorizedKey(ub)
	if err != nil {
		t.Fatal(err)
	}
	k, err := krl.Encode(krl.Set{Certs: []krl.CertSection{{CAKey: userCA, Serials: serials}}}, v, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	m.KRLVersion, m.KRLSHA256, m.IssuedAt = v, krl.SHA256Hex(k), issuedAt.UTC().Format(trust.TimeFormat)
	doc, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", env.RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ob, err := os.ReadFile(env.OpsPub)
	if err != nil {
		t.Fatal(err)
	}
	opsPub, _, _, _, err := ssh.ParseAuthorizedKey(ob)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		t.Fatal(err)
	}
	var sig []byte
	for _, s := range signers {
		if trust.FormatKey(s.PublicKey()) == trust.FormatKey(opsPub) {
			if sig, err = sshsig.Sign(rand.Reader, s, krl.Namespace, doc); err != nil {
				t.Fatal(err)
			}
		}
	}
	if sig == nil {
		t.Fatal("the ops key is not in the role agent")
	}
	if err := spool.Write(h.spoolDr, spool.State{KRLs: map[uint64]spool.KRLFiles{v: {KRL: k, Manifest: doc, Sig: sig}}}); err != nil {
		t.Fatal(err)
	}
}

// outboxStatus reads the applier's outbox/status.json.
func (h *agentHost) outboxStatus(t *testing.T) *heartbeat.Status {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "outbox", heartbeat.StatusFile)) //nolint:gosec // test fixture
	if err != nil {
		return nil
	}
	s, err := heartbeat.ParseStatus(b)
	if err != nil {
		t.Fatalf("outbox/status.json does not pass the server's checks: %v", err)
	}
	return s
}

// TestAgentStatusEndToEnd is 03-08's tracer (AGENT-07, D-10): the applier
// writes its status, the fetcher heartbeats it, the server stores it by
// seq and keyroster host status shows the host on the current KRL; a
// revocation shows up after one poll; a KRL 24 h old raises krl_stale in
// the applier's log and the heartbeat while a certificate still logs in;
// a stopped fetcher becomes silent after 180 s on the server's clock.
func TestAgentStatusEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true})
	login := currentUser(t)
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
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
	eh := enrollApproved(t, env, kr, "web1")
	h := eh.agentHost

	// 1. After the first apply: the host on the current versions.
	a := waitStatus(t, "the first heartbeat", eh, kr, func(a serverclient.HostsStatusAnswer) bool {
		return len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.Committed(a.Current.Docs())
	})
	if a.Hosts[0].Silent || a.Hosts[0].NeverApplied || a.Hosts[0].Name != "web1" || a.Hosts[0].State != serverclient.HostStateActive {
		t.Fatalf("the first heartbeat: %+v", a.Hosts[0])
	}
	text := kr("host", "status")
	if want := "KRL v" + strconv.FormatUint(a.Current.KRL, 10) + " on 1/1 hosts\n"; !strings.Contains(text, want) {
		t.Fatalf("host status lacks %q:\n%s", want, text)
	}
	t.Logf("keyroster host status after the first apply:\n%s", text)

	// 2. A revocation, then one poll: the new KRL version on 1/1.
	c1 := issueAgentCert(t, env.Signer, "c1", "role:ops")
	c2 := issueAgentCert(t, env.Signer, "c2", "role:ops")
	before := a.Current.KRL
	kr("revoke", "serial", c1.serial, "--reason", "e2e agent status")
	a = waitStatus(t, "the revocation's KRL in host status", eh, kr, func(a serverclient.HostsStatusAnswer) bool {
		return a.Current.KRL > before && len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.KRL.Version == a.Current.KRL
	})
	text = kr("host", "status")
	if want := "KRL v" + strconv.FormatUint(a.Current.KRL, 10) + " on 1/1 hosts\n"; !strings.Contains(text, want) {
		t.Fatalf("host status lacks %q:\n%s", want, text)
	}
	t.Logf("keyroster host status after the revocation:\n%s", text)

	// 3. A KRL whose manifest is 24 h old (D-10): with the fetcher stopped
	// (it would remove a spool file above the server's version), a KRL
	// signed by the ops key, issued 24 h and a minute ago, is applied. The
	// applier logs the error line, the status says krl_stale, and a
	// certificate still logs in.
	eh.stopFetch(t)
	serial, err := strconv.ParseUint(c1.serial, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	staleV := a.Current.KRL + 1
	staleKRL(t, env.Signer, h, a.Current.KRL, staleV, time.Now().Add(-24*time.Hour-time.Minute), []uint64{serial})
	waitFor(t, "the stale KRL's apply", eh.runDone, eh.run, func() bool {
		r := h.lastApply(t)
		return r != nil && r.KRLVersion == staleV && r.SelfTest == "pass"
	})
	waitFor(t, "the krl_stale error line", eh.runDone, eh.run, func() bool {
		return strings.Contains(eh.run.String(), "ERROR krl_stale: the installed KRL version "+strconv.FormatUint(staleV, 10))
	})
	if s := h.outboxStatus(t); s == nil || !s.KRLStale || s.KRL.Version != staleV {
		t.Fatalf("outbox status after the stale KRL: %+v", s)
	}
	for _, l := range strings.Split(eh.run.String(), "\n") {
		if strings.Contains(l, "ERROR krl_stale") {
			t.Logf("the applier's log: %s", l)
			break
		}
	}
	h.wantAccepted(t, "c2 with a stale KRL", c2, login)
	t.Logf("certificate c2 (serial %s) logs in as %s while krl_stale is set", c2.serial, login)
	h.wantRefused(t, "c1 under the stale KRL", c1, login, "127.0.0.4", logRevoked)

	// The fetcher again: the heartbeat carries krl_stale.
	eh.startFetch(t)
	a = waitStatus(t, "krl_stale in host status", eh, kr, func(a serverclient.HostsStatusAnswer) bool {
		return len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.KRLStale
	})
	text = kr("host", "status")
	if !strings.Contains(text, "krl_stale") {
		t.Fatalf("host status does not show krl_stale:\n%s", text)
	}
	t.Logf("keyroster host status with the stale KRL:\n%s", text)

	// 4. Silence (D-10): with the fetcher stopped, the host is silent only
	// once its last request is more than 180 s old on the server's clock.
	eh.stopFetch(t)
	var lastQuiet, firstSilent time.Duration
	for deadline := time.Now().Add(240 * time.Second); ; time.Sleep(4 * time.Second) {
		a := hostsStatusJSON(t, kr)
		seen, err := time.Parse(time.RFC3339, a.Hosts[0].LastSeen)
		if err != nil {
			t.Fatal(err)
		}
		age := time.Since(seen) // last_seen is whole seconds, so this is up to 1 s above the true age
		if !a.Hosts[0].Silent {
			lastQuiet = age
			if age > 182*time.Second {
				t.Fatalf("not silent at %s after the last request", age)
			}
		} else {
			firstSilent = age
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the host never became silent")
		}
	}
	if lastQuiet == 0 || lastQuiet > 181*time.Second || firstSilent < 180*time.Second {
		t.Fatalf("silent boundary: last not silent at %s, first silent at %s; want silent only above 180 s", lastQuiet, firstSilent)
	}
	t.Logf("not silent %s after the last request, silent at %s (D-10 bound 180 s; the exact 180/181 s edge is TestHeartbeat/silent_boundary_180_not_181)", lastQuiet.Round(time.Second), firstSilent.Round(time.Second))
	t.Logf("keyroster host status while silent:\n%s", kr("host", "status"))
}
